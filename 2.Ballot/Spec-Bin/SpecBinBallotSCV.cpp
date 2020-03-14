#include <iostream>
#include <thread>
#include "Util/Timer.cpp"
#include "Contract/BallotSCV.cpp"
#include "Util/FILEOPR.cpp"
#include <unistd.h>
#include <list>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <set>
#include <algorithm>


#define maxThreads 128
#define maxPObj 1000
#define maxVObj 40000
#define funInContract 5
#define pl "=================================================================\n"
#define MValidation true //! true or false
#define numValidator 50
#define NumBlock 26      //! at least two blocks, the first run is warmup run.
#define malMiner true    //! set the flag to make miner malicious.
#define NumOfDoubleSTx 2 //! # double-spending Tx for malicious final state by Miner, multiple of 2.

using namespace std;
using namespace std::chrono;
int    nProposal = 2;     //! nProposal: number of proposal shared objects; default is 1.
int    nVoter    = 1;     //! nVoter: number of voter shared objects; default is 1.
int    nThread   = 1;     //! nThread: total number of concurrent threads; default is 1.
int    numAUs;            //! numAUs: total number of Atomic Unites to be executed.
double lemda;             //! λ: random delay seed.
double totalTime[2];      //! total time taken by miner and validator algorithm.
Ballot *ballot;           //! smart contract.
int    *aCount;            //! aborted transaction count.
float_t *mTTime;          //! time taken by each miner Thread to execute AUs (Transactions).
float_t *vTTime;          //! time taken by each validator Thread to execute AUs (Transactions).
float_t *gTtime;          //! time taken by each miner Thread to add edges and nodes in the conflict graph.
vector<string>listAUs;    //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
vector<string>seqBin;     //! holds sequential Bin AUs.
vector<string>concBin;    //! holds concurrent Bin AUs.
std::atomic<int>currAU;   //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>vCount;   //! # of valid AU node added in graph (invalid AUs will not be part of the graph & conflict list).
std::atomic<int>eAUCount; //! used by validator threads to keep track of how many valid AUs executed by validator threads.
mutex concLock, seqLock;   //! Lock used to access seq and conc bin.
float_t seqTime[2];        //! Used to store seq exe time.
std::atomic<bool>mm;       //! miner is malicious, this is used by validators.
int *mProposalState;
int *vProposalState;
int *mVoterState;
int *vVoterState;
string *proposalNames;



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
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int chairperson)
	{
		//! initialize the counter used to execute the numAUs
		currAU = 0;
		vCount = 0;
		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		gTtime = new float_t [nThread];
		proposalNames = new string[nProposal+1];
		for(int x = 0; x <= nProposal; x++)
			proposalNames[x]="X"+to_string(x+1);
		for(int i = 0; i < nThread; i++) {
			mTTime[i] = 0;
			gTtime[i] = 0;
		}
		//! Id of the contract creater is \chairperson = 0\.
		ballot = new Ballot( proposalNames, chairperson, nVoter, nProposal);
	}


	//!---------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER THREADS !!!!!!!!!!
	//!----------------------------------------------------
	void mainMiner()
	{
		Timer mTimer;
		thread T[nThread];
		ballot->reset_m();
		//! Give \`voter\` the right to vote on this ballot.
		//! giveRightToVote is serial.
		for(int voter = 1; voter <= nVoter; voter++)			
			ballot->giveRightToVote_m(0, voter);//! 0 is chairperson.

		//!---------------------------------------------------------
		//!!!!!!!!!!          Concurrent Phase            !!!!!!!!!!
		//!!!!!!!!!!    Create 'nThread' Miner threads    !!!!!!!!!!
		//!---------------------------------------------------------
		double s = mTimer.timeReq();
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concMiner, i, numAUs);
		for(auto& th : T) th.join();//! miner thread join
		totalTime[0] = mTimer.timeReq() - s;

		//!------------------------------------------
		//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
		//!------------------------------------------
		seqTime[0] = 0;
		Timer SeqTimer;
//		ballot->allUnlock();
		auto start = SeqTimer._timeStart();
		seqBinExe();
		seqTime[0] = SeqTimer._timeStop( start );
//		ballot->allUnlock();

		//! print the final state of the shared objects.
		finalState();
	}

	
	//!-----------------------------------------------------------------
	//!!!!!!!!!!               Concurrent Phase               !!!!!!!!!!
	//! The function to be executed by all the miner threads. Thread   !
	//! executes the transaction concurrently from Concurrent Bin      !
	//!-----------------------------------------------------------------
	static void concMiner( int t_ID, int numAUs)
	{
		Timer thTimer;
		//! get the current index, and increment it.
		int curInd = currAU++;
		auto start = thTimer._timeStart();
		while(curInd < numAUs)
		{
			istringstream ss(listAUs[curInd]);
			string tmp;
			ss >> tmp;
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote_m(vID, PID, true);
				//! if fun retrun -1 add the AU to seq Bin.
				if(v == -1) {
					vCount++;
					seqLock.lock();
					seqBin.push_back(listAUs[curInd]);
					seqLock.unlock();
				}
				else if(v == 0){
//					cout<<"Error!!! Invalid AU\n";
				}
				else {
					concLock.lock();
					concBin.push_back(listAUs[curInd]);
					concLock.unlock();
				}			
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate_m(sID, rID, true);
				//! if fun retrun -1 add the AU to seq Bin.
				if(v == -1) {
					vCount++;
					seqLock.lock();
					seqBin.push_back(listAUs[curInd]);
					seqLock.unlock();
				}
				else if(v == 0){
					//cout<<"Error!!! Invalid AU\n";
				}
				else {
					concLock.lock();
					concBin.push_back(listAUs[curInd]);
					concLock.unlock();
				}
			}
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		mTTime[t_ID] = mTTime[t_ID] + thTimer._timeStop(start);
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
			ss >> tmp;
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote_m(vID, PID, false);
				if(v == 0){
//					seqBin.erase(seqBin.begin()+count);
//					cout<<"Error!!! Invalid AU:: "<< seqBin[count]<<endl;
				}				
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate_m(sID, rID, false);
				if(v == 0){
//					seqBin.erase(seqBin.begin()+count);
//					cout<<"Error!!! Invalid AU:: "<< seqBin[count]<<endl;
				}				
			}
			count++;
		}
	}


	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using state()|
	//!-------------------------------------------------
	void finalState()
	{
		for(int id = 1; id <= nVoter; id++) 
			ballot->state_m(id, true, mVoterState);//for voter state

		for(int id = 1; id <= nProposal; id++) 
			ballot->state_m(id, false, mProposalState);//for Proposal state
	}
	~Miner() { };
};
/*************************Miner code ends**************************************/







/*************************Validator code begins********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "n" validator-THREAD   !
! CONCURRENTLY BASED ON CONC and SEQ BIN GIVEN BY MINER !
! OPERATIONS of RESPECTIVE AUs. THREAD 0 IS CONSIDERED  !
! AS chairperson-THREAD (SMART CONTRACT DEPLOYER)       !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Validator
{
public:
	Validator()
	{
		//! int the execution counter used by validator threads.
		eAUCount = 0;
		//! array index location represents respective thread id.
		vTTime = new float_t [nThread];
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
		Timer vTimer;
		thread T[nThread];
		ballot->reset();
		//! giveRightToVote() function is serial. Id 0 is chairperson.
		for(int voter = 1; voter <= nVoter; voter++)
			ballot->giveRightToVote(0, voter);

		//!---------------------------------------------------------
		//!!!!!!!!!!          Concurrent Phase            !!!!!!!!!!
		//!!!!!!!!!!  Create 'nThread' Validator threads  !!!!!!!!!!
		//!---------------------------------------------------------
		double s = vTimer.timeReq();
		for(int i = 0; i<nThread; i++)	T[i] = thread(concValidator, i);
		shoot(); //notify all threads to begin the worker();
		for(auto& th : T) th.join( );
		totalTime[1] = vTimer.timeReq() - s;


		//!------------------------------------------
		//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
		//!------------------------------------------
		seqTime[1] = 0;
		Timer SeqTimer;
		//! start timer to get time taken by this thread.
		auto start = SeqTimer._timeStart();
			seqBinExe();
		seqTime[1] = SeqTimer._timeStop( start );


		//!print the final state of the shared objects by validator.
		finalState();
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
		while(curInd < concBin.size()  && mm == false)
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(concBin[curInd]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote(vID, PID);
				if(v == -1)	mm = true;
//				else if(v == 0) cout<<"Error!!! Invalid AU\n";
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
				if(v == -1)	mm = true;
//				else if(v == 0) cout<<"Error!!! Invalid AU\n";
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
//		cout<<"\nSequential Bin Execution::\n";
		int t_ID = 0;
		int count = 0;
		while(count < seqBin.size() && mm == false)
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(seqBin[count]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote(vID, PID);
				if(v == -1)	mm = true;
//				else if(v == 0) cout<<"Error!!! Invalid AU\n";
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
				if(v == -1)	mm = true;
//				else if(v == 0) cout<<"Error!!! Invalid AU\n";
			}
			count++;
		}
	}

	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using state()  |
	//!-------------------------------------------------
	void finalState()
	{
		for(int id = 1; id <= nVoter; id++) 
			ballot->state(id, true, vVoterState);//for voter state

		for(int id = 1; id <= nProposal; id++) 
			ballot->state(id, false, vProposalState);//for Proposal state
	}

	~Validator() { };
};
/*************************Validator code ends**********************************/



void eraseAUID(int id, bool Bin) {
	if(Bin == true){
		for(auto its = seqBin.begin(); its < seqBin.end(); its++) {
			istringstream ss(*its);
			string auid;
			ss >> auid;
			int A_ID = stoi(auid);
			if(A_ID == id){
				seqBin.erase(its);
				return;
			}
		}
	}
	else {
		for(auto it = concBin.begin(); it < concBin.end(); it++) {
			istringstream ss(*it);
			string auid;
			ss >> auid;
			int A_ID = stoi(auid);
			if(A_ID == id){
				concBin.erase(it);
				return;
			}
		}
	}
}


//!--------------------------------------------------------------------------
//! atPoss:: from which double-spending Tx to be stored at end of the list. !
//! add malicious final state with double-spending Tx                       !
//!--------------------------------------------------------------------------
bool addMFS(int atPoss)
{
	istringstream ss(listAUs[atPoss-2]);
	string trns1;
	ss >> trns1; //! AU_ID to Execute.
	int AU_ID1 = stoi(trns1);
	ss >> trns1;//function name
	ss >> trns1; //! Voter ID.
	int s_id = stoi(trns1);
	ss >> trns1; //! Proposal ID.
	int r_id = - stoi(trns1);

	istringstream ss1(listAUs[atPoss-1]);
	string trns2;
	ss1 >> trns2; //! AU_ID to Execute.
	int AU_ID2 = stoi(trns2);
	ss1 >> trns2;//function name
	ss1 >> trns2; //! Voter ID.
	int s_id1 = stoi(trns2);
	ss1 >> trns2; //! Proposal ID.
	int r_id1 = - stoi(trns2);

	mProposalState[r_id-1]  = 1;
	mProposalState[r_id1-1] = 1;
	mVoterState[s_id1-1]    = 1;


	trns1 = listAUs[atPoss-2];
	trns2 = listAUs[atPoss-1];

	//! add the confliciting AUs in conc bin and remove them from seq bin.
	//! Add one of the AU from seq bin to conc Bin and remove that AU from seq bin.
	eraseAUID(AU_ID1, true);
	eraseAUID(AU_ID2, true);
	eraseAUID(AU_ID1, false);
	eraseAUID(AU_ID2, false);
	concBin.insert(concBin.begin(), trns1);
	concBin.insert(concBin.begin()+1, trns2);
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
//	cout<<"\n"<<pl<<"Proposal \tMiner \t\tValidator"<<endl;
	for(int pid = 0; pid < nProposal; pid++) {
//		cout<<pid+1<<" \t \t"<<mProposalState[pid]
//			<<" \t\t"<<vProposalState[pid]<<endl;
		if(mProposalState[pid] != vProposalState[pid])
			flag = true;
	}
//	cout<<"\n"<<pl<<"Voter ID \tMiner \t\tValidator"<<endl;
	for(int vid = 0; vid < nVoter; vid++) {
//		cout<<vid+1<<" \t \t"<<mVoterState[vid]
//			<<" \t\t"<<vVoterState[vid]<<endl;
		if(mVoterState[vid] != vVoterState[vid])
			flag = true;
	}
	return flag;
}





/*************************Main Fun code begins*********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!          main()         !!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"Bin Based TryLock Miner and SCV\n";
	cout<<"--------------------------------\n";
	//! list holds the avg time taken by miner and Validator
	//! thread s for multiple consecutive runs.
	list<double>mItrT;
	list<double>vItrT;
	int totalDepInG  = 0; //to get total number of dependencies in graph;
	int totalRejCont = 0; //number of validator rejected the blocks;
	int mWiningPro   = 0;
	int vWiningPro   = 0;
	int maxAccepted  = 0;
	int totalRun     = NumBlock; //at least 2

	FILEOPR file_opr;

	//! read from input file:: nProposal = #numProposal; nThread = #threads;
	//! numAUs = #AUs; λ = random delay seed.
	file_opr.getInp(&nProposal, &nVoter, &nThread, &numAUs, &lemda);
	if(nProposal > maxPObj) {
		nProposal = maxPObj;
		cout<<"Max number of Proposals can be "<<maxPObj<<"\n";
	}
	if(nVoter > maxVObj) {
		nVoter = maxVObj;
		cout<<"Max number of Voters can be "<<maxVObj<<"\n";
	}

	mProposalState   = new int [nProposal];
	vProposalState   = new int [nProposal];
	mVoterState      = new int [nVoter];
	vVoterState      = new int [nVoter];

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		mm = new std::atomic<bool>;
		mm = false;
		//! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, nVoter, nProposal, funInContract, listAUs);
		for(int pid = 0; pid < nProposal; pid++) mProposalState[pid] = 0;
		for(int vid = 0; vid < nVoter; vid++) mVoterState[vid] = 0;
		Timer mTimer;
		mTimer.start();

		//MINER
		Miner *miner = new Miner(0);//0 is contract deployer id
		miner ->mainMiner();

		//! Add malicious AUs.
		if(lemda != 0) bool rv = addMFS(NumOfDoubleSTx);

//		printBins();

		//VALIDATOR
		if(MValidation == true)
		{
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++)
			{
				for(int p = 0; p < nProposal; p++) vProposalState[p] = 0;
				for(int v = 0; v < nVoter; v++) vVoterState[v] = 0;

				Validator *validator = new Validator();
				validator ->mainValidator();

				//State Validation
				bool flag = stateVal();
				if(flag == true) rejectCount++;
				else acceptCount++;
				mm = false;
			}
			if(numItr > 0 && malMiner == true) {
				totalRejCont += rejectCount;
				if(maxAccepted < acceptCount ) maxAccepted = acceptCount;
			}
		}
		else {
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
		if(numItr > 0)
		file_opr.writeOpt(nProposal, nVoter, nThread, numAUs, totalTime,
		                  mTTime, vTTime, aCount, vAUs, mItrT, vItrT);

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
			<<tAvgMinerT+seqTime[0]<<" microseconds";
	cout<<"\nTotal Avg Validator  = "<<tAvgValidT+seqTime[1]
		<<" microseconds\n-----------------------------";
	cout<<"\nMiner Seq Time       = "<<seqTime[0]<<" microseconds"
		<< "\nValidator Seq Time   = "<< seqTime[1]<<" microseconds";
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
