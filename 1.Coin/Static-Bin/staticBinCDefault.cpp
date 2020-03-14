#include <iostream>
#include <thread>
#include "Util/Timer.cpp"
#include "Contract/Coin.cpp"
#include "Util/FILEOPR.cpp"
#include <unistd.h>
#include <list>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <set>
#include <algorithm>

#define MAX_THREADS 128
#define M_SharedObj 5000
#define FUN_IN_CONT 3
#define pl "=================================================================\n"
#define MValidation true   //! true or false
#define numValidator 50
#define InitBalance 1000
#define NumBlock 26        //! at least two blocks, the first run is warmup run.
#define malMiner true      //! set the flag to make miner malicious.
#define NumOfDoubleSTx 2   //! # double-spending Tx for malicious final state by Miner, multiple of 2.



using namespace std;
using namespace std::chrono;

int    SObj    = 2;        //! SObj: number of shared objects; at least 2, to send & recive.
int    nThread = 1;        //! nThread: total number of concurrent threads; default is 1.
int    numAUs;             //! numAUs: total number of Atomic Unites to be executed.
double lemda;              //! % of edges to be removed from BG by malicious Miner.
double tTime[2];           //! total time taken by miner and validator algorithm.
Coin   *coin;              //! smart contract.
int    *aCount;            //! aborted transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs (Transactions).
float_t*vTTime;            //! time taken by each validator Thread to execute AUs (Transactions).
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
vector<string>seqBin;      //! holds sequential Bin AUs.
vector<string>concBin;     //! holds concurrent Bin AUs.
vector<int>ccSet;          //! Set holds the IDs of the shared objects accessed by concurrent Bin Tx.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>vCount;    //! # of valid AU.
std::atomic<int>eAUCount;  //! used by validator threads to keep track of how many valid AUs executed by validator threads.
mutex concLock, seqLock;   //! Lock used to access seq and conc bin.
float_t seqTime[3];        //! Used to store seq exe time.
int MinerState[M_SharedObj];
int ValidatorState[M_SharedObj];





/*************************Barrier code begins**********************************/
std::mutex mtx;
std::mutex pmtx; // to print in concurrent scene
std::condition_variable cv;
bool launch = false;

void wait_for_launch()
{
	std::unique_lock<std::mutex> lck(mtx);
	while (!launch) cv.wait(lck);
}

void shoot()
{
	std::unique_lock<std::mutex> lck(mtx);
	launch = true;
	cv.notify_all();
}
/*************************Barrier code ends************************************/





/*************************Miner code begins************************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "n" miner-THREAD CONCURRENTLY           !
!"concMiner()" CALLED BY miner-THREAD TO PERFROM oprs of RESPECTIVE AUs !
! THREAD 0 IS CONSIDERED AS MINTER-THREAD (SMART CONTRACT DEPLOYER)     !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int minter_id)
	{
		vCount     = 0;
		currAU     = 0;
		mTTime     = new float_t [nThread];//! array index -> respective tid.
		aCount     = new int [nThread];
		for( int i = 0; i < nThread; i++ ) {
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		//! id of the contract creater is "minter_id".
		coin = new Coin(SObj, minter_id);
	}


	//!---------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER THREADS !!!!!!!!!!
	//!----------------------------------------------------
	void mainMiner()
	{

		thread T[nThread];
		int bal = InitBalance;

		//! initialization of account with fixed
		//! ammount; mint() is assume to be serial.
		for(int sid = 1; sid <= SObj; sid++)
			coin->mint(0, sid, bal); //! 0 is contract deployer.


		seqTime[0] = 0;
		Timer staticTimer;
		//! start timer to get time taken by static analysis.
		auto start = staticTimer._timeStart();
		staticAnalysis();
		seqTime[0] = staticTimer._timeStop( start );
		
//		printBin(concBin);
//		printBin(seqBin);


		//!---------------------------------------------------------
		//!!!!!!!!!!          Concurrent Phase            !!!!!!!!!!
		//!!!!!!!!!!    Create 'nThread' Miner threads    !!!!!!!!!!
		//!---------------------------------------------------------
		for( int i = 0; i < nThread; i++ )
			T[i] = thread(concMiner, i, numAUs);
		for( auto &th : T) th.join ( );

		//!------------------------------------------
		//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
		//!------------------------------------------
		seqTime[1] = 0;
		Timer SeqTimer;
		//! start timer to get time taken by this thread.
		start = SeqTimer._timeStart();
		seqBinExe();
		seqTime[1] = SeqTimer._timeStop( start );

		//! print the final state of the shared objects.
		finalState();
	}
	

	//! returns the sObj accessed by AU.
	void getSobjId(vector<int> &sObj, string AU) {
		istringstream ss(AU);
		string tmp;
		ss >> tmp; //! AU_ID to Execute.
		ss >> tmp; //! Function Name (smart contract).
		if(tmp.compare("get_bal") == 0) {
			ss >> tmp; //! get balance of SObj/id.
			int s_id = stoi(tmp);
			sObj.push_back(s_id);
			return;
		}
		if(tmp.compare("send") == 0) {
			ss >> tmp; //! Sender ID.
			int s_id  = stoi(tmp);
			sObj.push_back(s_id);
			ss >> tmp; //! Reciver ID.
			int r_id  = stoi(tmp);
			sObj.push_back(r_id);
			return;
		}
	}


	//!-----------------------------------------------------------
	//! Performs the static analysis based on set Operations.    !
	//!-----------------------------------------------------------
	void staticAnalysis() {
		vector<int> sObj; //! holds the IDs of the shared object accessed by an AU.
		if(numAUs != 0) {
			//! Add first AU to concBin and Add Sobj accessed by it to ccSet.
			concBin.push_back(listAUs[0]);
			getSobjId(sObj, listAUs[0]);
			auto it = sObj.begin();
			for( ; it != sObj.end(); ++it) {
				ccSet.push_back(*it);
			}
		}
		int index = 1;
		while( index < numAUs ) {
			sObj.clear();

			getSobjId(sObj, listAUs[index]);
			sort (ccSet.begin(), ccSet.end());
			sort (sObj.begin(), sObj.end());

			vector<int> intersect(ccSet.size() + sObj.size());
			vector<int>:: iterator it;
			it = set_intersection( ccSet.begin(), ccSet.end(),
			                       sObj.begin(), sObj.end(),
			                       intersect.begin());

			intersect.resize(it-intersect.begin());
			if(intersect.size() == 0 ) {
				auto it = sObj.begin();
				for(; it != sObj.end(); ++it) ccSet.push_back(*it);
				concBin.push_back(listAUs[index]);
			}
			else {
				seqBin.push_back(listAUs[index]);
			}
			index++;
		}
	}

	//!-----------------------------------------------------------------
	//!!!!!!!!!!               Concurrent Phase               !!!!!!!!!!
	//! The function to be executed by all the miner threads. Thread   !
	//! executes the transaction concurrently from Concurrent Bin      !
	//!-----------------------------------------------------------------
	static void concMiner(int t_ID, int numAUs)
	{
		//! statrt clock to get time taken by this transaction.
		Timer Ttimer;
		int  curInd = currAU++;
		auto start  = Ttimer._timeStart();
		while(curInd < concBin.size())
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(concBin[curInd]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("get_bal") == 0)
			{
				ss >> tmp; //! get balance of SObj/id.
				int s_id = stoi(tmp);
				int bal  = 0;
				//! call get_bal() of smart contract.
				int v = coin->get_bal(s_id, &bal);
				if(v == 0){
					//cout<<"Account "<<s_id<<" not found\n";
				}
			}
			if(tmp.compare("send") == 0)
			{
				ss >> tmp; //! Sender ID.
				int s_id  = stoi(tmp);
				ss >> tmp; //! Reciver ID.
				int r_id  = stoi(tmp);
				ss >> tmp; //! Ammount to send.
				int amt   = stoi(tmp);
				int v = coin->send(s_id, r_id, amt);
				if(v == 0) {
					//! invalid AU: sender does't 
					//! have sufficent balance to send.
//					cout<<"\nConcBIn:Sender don't have sufficent balance to send.\n";
				}
			}
			curInd = currAU++;
		}
		mTTime[t_ID] = mTTime[t_ID] + Ttimer._timeStop( start );
	}

	//!------------------------------------------
	//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
	//!------------------------------------------
	void seqBinExe( )
	{
		int t_ID  = 0;
		int count = 0;
		while(count < seqBin.size())
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(seqBin[count]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("get_bal") == 0)
			{
				ss >> tmp; //! get balance of SObj/id.
				int s_id = stoi(tmp);
				int bal  = 0;
				//! call get_bal() of smart contract.
				bool v = coin->get_bal(s_id, &bal);
			}
			if(tmp.compare("send") == 0)
			{
				ss >> tmp; //! Sender ID.
				int s_id  = stoi(tmp);
				ss >> tmp; //! Reciver ID.
				int r_id  = stoi(tmp);
				ss >> tmp; //! Ammount to send.
				int amt   = stoi(tmp);
				int v = coin->send(s_id, r_id, amt);
				if(v == false) {
					//! invalid AU: sender does't 
					//! have sufficent balance to send.
//					cout<<"\nSeqBIn: Sender don't have sufficent balance to send.\n";
				}
			}
			count++;
		}
	}


	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using get_bel()|
	//!-------------------------------------------------
	void finalState()
	{
		for(int sid = 1; sid <= SObj; sid++) {
			int bal = 0;
			bool v = coin->get_bal(sid, &bal);
			if(v != false) MinerState[sid] = bal;
		}
	}
	~Miner() { };
};
/*************************Miner code ends**************************************/







/*************************Validator code begins********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "n" validator-THREAD   !
! CONCURRENTLY BASED ON CONC and SEQ BIN GIVEN BY MINER !
! OPERATIONS of RESPECTIVE AUs. THREAD 0 IS CONSIDERED  !
! AS MINTER-THREAD (SMART CONTRACT DEPLOYER)            !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

class Validator
{
public:
	Validator()
	{
		//! array index location represents respective thread id.
		eAUCount = 0;
		vTTime   = new float_t[nThread];
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
	};

	//!----------------------------------------
	//! create n concurrent validator threads | 
	//! to execute valid AUs.                 |
	//!----------------------------------------
	void mainValidator()
	{
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
		eAUCount = 0;
		int bal  = InitBalance;
		thread T[nThread];
		//! initialization of account with fixed ammount;
		//! mint() function is assume to be serial.
		for(int sid = 1; sid <= SObj; sid++) 
			bool r = coin->mint(0, sid, bal); //! 0 is contract deployer.

		//!---------------------------------------------------------
		//!!!!!!!!!!          Concurrent Phase            !!!!!!!!!!
		//!!!!!!!!!!  Create 'nThread' Validator threads  !!!!!!!!!!
		//!---------------------------------------------------------
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concValidator, i);
		shoot(); //notify all threads to begin the worker();
		for(auto& th : T) th.join ( );

		//!------------------------------------------
		//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
		//!------------------------------------------
		seqTime[2] = 0;
		Timer SeqTimer;
		//! start timer to get time taken by this thread.
		auto start = SeqTimer._timeStart();
		seqBinExe();
		seqTime[2] = SeqTimer._timeStop( start );

		finalState(); //! print the final state of the SObjs by validator.
	}

	//!------------------------------------------------------------
	//!!!!!!!          Concurrent Phase                    !!!!!!!!
	//!!!!!!  'nThread' Validator threads Executes this Fun !!!!!!!
	//!------------------------------------------------------------
	static void concValidator( int t_ID )
	{
		//barrier to synchronise all threads for a coherent launch
		wait_for_launch();
		Timer Ttimer;
		//! start timer to get time taken by this thread.
		auto start = Ttimer._timeStart();
		int curInd = eAUCount++;
		while( curInd < concBin.size() )
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(concBin[curInd]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("get_bal") == 0)
			{
				ss >> tmp; //! get balance of SObj/id.
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coin->get_bal(s_id, &bal);
			}
			if( tmp.compare("send") == 0 )
			{
				ss >> tmp; //! Sender ID.
				int s_id = stoi(tmp);
				ss >> tmp; //! Reciver ID.
				int r_id = stoi(tmp);
				ss >> tmp; //! Ammount to send.
				int amt  = stoi(tmp);
				bool v   = coin->send(s_id, r_id, amt);
			//	if(v == false)
			//	cout<<"\nConcBin:Sender don't have sufficent balance to send.\n";
			}
			curInd = eAUCount++;
		}
		//!stop timer to get time taken by this thread
		vTTime[t_ID] = vTTime[t_ID] + Ttimer._timeStop( start );
	}

	//!------------------------------------------
	//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
	//!------------------------------------------
	void seqBinExe( )
	{
		int t_ID = 0;
		int count = 0;
		while(count < seqBin.size())
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(seqBin[count]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("get_bal") == 0)
			{
				ss >> tmp; //! get balance of SObj/id.
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coin->get_bal(s_id, &bal);
			}
			if( tmp.compare("send") == 0 )
			{
				ss >> tmp; //! Sender ID.
				int s_id = stoi(tmp);
				ss >> tmp; //! Reciver ID.
				int r_id = stoi(tmp);
				ss >> tmp; //! Ammount to send.
				int amt  = stoi(tmp);
				bool v   = coin->send(s_id, r_id, amt);
	//			if(v == false)
	//			cout<<"\nSeqBin:Sender don't have sufficent balance to send.\n";
			}
			count++;
		}
	}

	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. Geting this using get_bel()       |
	//!-------------------------------------------------
	void finalState()
	{
		for(int sid = 1; sid <= SObj; sid++) {
			int bal = 0, ts;
			bool v  = coin->get_bal(sid, &bal);
			ValidatorState[sid] = bal;
		}
	}

	~Validator() { };
};

/*************************Validator code ends**********************************/



//!--------------------------------------------------------------------------
//! atPoss:: from which double-spending Tx to be stored at end of the list. !
//! add malicious final state with double-spending Tx                       !
//!--------------------------------------------------------------------------
bool addMFS(int atPoss)
{
	istringstream ss(listAUs[atPoss-2]);
	string trns1;
	string trns2;
	ss >> trns1; //! AU_ID to Execute.
	int AU_ID1 = stoi(trns1);
	ss >> trns1;//function name
	ss >> trns1; //! Sender ID.
	int s_id = stoi(trns1);
	ss >> trns1; //! Reciver ID.
	int r_id = stoi(trns1);
	ss >> trns1; //! Ammount to send.
	int amtAB  = stoi(trns1);

	istringstream ss1(listAUs[atPoss-1]);
	ss1 >> trns2; //! AU_ID to Execute.
	int AU_ID2 = stoi(trns2);
	ss1 >> trns2;//function name
	ss1 >> trns2; //! Sender ID.
	int s_id1 = stoi(trns2);
	ss1 >> trns2; //! Reciver ID.
	int r_id1 = stoi(trns2);
	ss1 >> trns2; //! Ammount to send.
	int amtAC  = stoi(trns2);

	MinerState[s_id]  = 1000;
	MinerState[r_id]  = 1000;
	MinerState[r_id1] = 1000;

	amtAB = 950;
	trns1 = to_string(AU_ID1)+" send "+to_string(s_id)+" "
			+to_string(r_id)+" "+to_string(amtAB);
	listAUs[AU_ID1-1] =  trns1;
	amtAC = 100;
	trns2 = to_string(AU_ID2)+" send "+to_string(s_id)+" "
			+to_string(r_id1)+" "+to_string(amtAC);
	listAUs[AU_ID2-1] =  trns2;

	MinerState[s_id]  -= amtAB;
	MinerState[r_id]  += amtAB;
	MinerState[r_id1] += amtAC;
	
	//! add the confliciting AUs in conc bin and remove them from seq bin. Add
	//! one of the AU from seq bin to conc Bin and remove that AU from seq bin.
	auto it = concBin.begin();
	concBin.erase(it);
	concBin.insert(concBin.begin(), listAUs[atPoss-2]);
	concBin.insert(concBin.begin()+1, listAUs[atPoss-1]);
	it = seqBin.begin();
	seqBin.erase(it);
	return true;
}


void printBins( )
{
	int concCount = 0, seqCount = 0;
	cout<<endl<<"=====================\n"
		<<"Concurrent Bin AUs\n=====================";
	for(int i = 0; i < concBin.size(); i++) {
		cout<<"\n"<<concBin[i];
		concCount++;
	}
	cout<<endl;
	cout<<endl<<"=====================\n"
		<<"Sequential Bin AUs\n=====================";
	for(int i = 0; i < seqBin.size(); i++) {
		cout<<"\n"<<seqBin[i];
		seqCount++;
	}
	cout<<"\n=====================\n"
		<<"Conc AU Count "<< concCount 
		<<"\nSeq AU Count "<<seqCount
		<<"\n=====================\n";
}




bool stateVal() {
	//State Validation
	bool flag = false;
//	cout<<"\n"<<pl<<"SObject \tMiner \t\tValidator"<<endl;
	for(int sid = 1; sid <= SObj; sid++) {
//		cout<<sid<<" \t \t"<<MinerState[sid]
//			<<" \t\t"<<ValidatorState[sid]<<endl;
		if(MinerState[sid] != ValidatorState[sid]) flag = true;
	}
	return flag;
}





/*************************Main Fun code begins*********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!          main()         !!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"Bin Based Static Miner and Concurrent Validator\n";
	cout<<"--------------------------------\n";
	//! list holds the avg time taken by miner and 
	//! Validator thread s for multiple consecutive runs.
	list<double>mItrT;
	list<double>vItrT;
	int totalDepInG  = 0; //to get total number of dependencies in graph;
	int totalRejCont = 0; //number of validator rejected the blocks;
	int maxAccepted  = 0;
	int totalRun     = NumBlock; //at least 2

	FILEOPR file_opr;

	//! read from input file:: SObj = #SObj; nThread = #threads;
	//! numAUs = #AUs; λ =  % of edges to be removed from BG by malicious Miner.
	file_opr.getInp(&SObj, &nThread, &numAUs, &lemda);
	//! max shared object error handling.
	if(SObj > M_SharedObj) {
		SObj = M_SharedObj;
		cout<<"Max number of Shared Object can be "<<M_SharedObj<<"\n";
	}

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		//! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, SObj, FUN_IN_CONT, listAUs);
		tTime[0] = 0;
		tTime[1] = 0;

		Timer mTimer;
		mTimer.start();

		//MINER
		Miner *miner = new Miner(0);
		miner ->mainMiner();

//		printBins();
		if(lemda != 0) bool rv = addMFS(NumOfDoubleSTx);

		//VALIDATOR
		if(MValidation == true)
		{
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++)
			{
				Validator *validator = new Validator();
				validator ->mainValidator();
				//State Validation
				bool flag = stateVal();
				if(flag == true) rejectCount++;
				else acceptCount++;
			}
			if(numItr > 0 && malMiner == true) {
				totalRejCont += rejectCount;
				if(maxAccepted < acceptCount ) maxAccepted = acceptCount;
			}
			for(int i = 1; i <= SObj; i++) ValidatorState[i] = 0;
		}
		else
		{
			Validator *validator = new Validator();
			validator ->mainValidator();
			//State Validation
			bool flag = stateVal();
			if(flag == true) cout<<"\nBlock Rejected by Validator";
		}
	
		mTimer.stop();

		//total valid AUs among total AUs executed
		//by miner and varified by Validator.
		int vAUs = seqBin.size() + concBin.size();
		if(numItr > 0)//skip first run
			file_opr.writeOpt(SObj, nThread, numAUs, tTime, mTTime,
			                        vTTime, aCount, vAUs, mItrT, vItrT);

		for(int i = 1; i <= SObj; i++) {
			MinerState[i]     = 0;
			ValidatorState[i] = 0;
		}
		ccSet.clear();
		concBin.clear();
		seqBin.clear();
		listAUs.clear();
		delete miner;
		miner = NULL;

	}

	//to get total avg miner and validator
	//time after number of totalRun runs.
	double tAvgMinerT = 0, tAvgValidT = 0;
	auto mit = mItrT.begin();
	auto vit = vItrT.begin();
	for(int j = 1; j < totalRun; j++) {
		tAvgMinerT = tAvgMinerT + *mit;
		tAvgValidT = tAvgValidT + *vit;
		mit++;
		vit++;
	}
	tAvgMinerT = tAvgMinerT/(totalRun-1);
	tAvgValidT = tAvgValidT/(totalRun-1);
	cout<<"    Total Avg Miner  = "
			<<tAvgMinerT+seqTime[1]+seqTime[0]<<" microseconds";
	cout<<"\nTotal Avg Validator  = "<<tAvgValidT+seqTime[2]
		<<" microseconds\n-----------------------------";
	cout<<"\nStaic Analysis Time  = "<<seqTime[0]<<" microseconds";
	cout<<"\nMiner Seq Time       = "<<seqTime[1]<<" microseconds"
		<< "\nValidator Seq Time   = "<< seqTime[2]<<" microseconds";
	cout<<endl<<"-----------------------------";
	cout<<"\nAvg Number of Validator Accepted the Block = "
		<<(numValidator-(totalRejCont/(totalRun-1)));
	cout<<"\nAvg Number of Validator Rejcted the Block = "
		<<totalRejCont/(totalRun-1);
	cout<<"\nMax Validator Accepted any Block = "<<maxAccepted;
	cout<<"\n"<<endl;

	mItrT.clear();
	vItrT.clear();
	delete mTTime;
	delete vTTime;
	delete aCount;
	return 0;
}
/*************************Main Fun code ends***********************************/
