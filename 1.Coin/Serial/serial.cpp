#include <iostream>
#include <thread>
#include <atomic>
#include <list>
#include "Util/Timer.cpp"
#include "Contract/Coin.cpp"
#include "Util/FILEOPR.cpp"

#define MAX_THREADS 1
#define M_SharedObj 5000
#define FUN_IN_CONT 3
#define pl "=================================================================\n"
#define MValidation true   //! true or false
#define numValidator 10
#define InitBalance 1000
#define NumBlock 201         //! at least two blocks, the first run is warmup run.

using namespace std;
using namespace std::chrono;

int    SObj    = 2;        //! SObj: number of shared objects; at least 2, to send & recive.
int    nThread = 1;        //! nThread: total number of concurrent threads; default is 1.
int    numAUs;             //! numAUs: total number of Atomic Unites to be executed.
double lemda;              //! λ:  % of edges to be removed from BG by malicious Miner.
double tTime[2];           //! total time taken by miner and validator algorithm.
Coin   *coin;              //! smart contract miner.
Coin   *coinV;              //! smart contract validator.
int    *aCount;            //! Invalid transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs (Transactions).
float_t*vTTime;            //! time taken by each validator Thread to execute AUs (Transactions).
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.
int MinerState[M_SharedObj];
int ValidatorState[M_SharedObj];




/*************************Miner code begins************************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "1" miner-THREAD                        !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int minter_id)
	{
		//! initialize the counter.
		currAU = 0;
		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		aCount = new int [nThread];
		for(int i = 0; i < nThread; i++) {
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		//! id of the contract creater is "minter_id".
		coin = new Coin( SObj, minter_id );
	}

	//!------------------------------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER + GRAPH CONSTRUCTION THREADS !!!!!!!!!!
	//!-------------------------------------------------------------------------
	void mainMiner()
	{
		Timer lTimer;
		thread T[nThread];
		//! initialization of account with fixed ammount;
		//! mint() function is serial.
		int bal = InitBalance, total = 0;
		for(int sid = 1; sid <= SObj; sid++) {
			//! 0 is contract deployer.
			bool v = coin->mint(0, sid, bal);
			total  = total + bal;
		}

		//!---------------------------------------------------
		//!!!!!!!!!!    CREATE 1 MINER THREADS      !!!!!!!!!!
		//!---------------------------------------------------
		double start = lTimer.timeReq();
		for(int i = 0; i < nThread; i++) T[i] = thread(concMiner, i, numAUs);
		for(auto& th : T) th.join();
		tTime[0] = lTimer.timeReq() - start;

		//! print the final state of the shared objects.
		finalState();
	}

	//!--------------------------------------------------
	//! The function to be executed by a miner threads. !
	//!--------------------------------------------------
	static void concMiner( int t_ID, int numAUs)
	{
		Timer thTimer;
		//! get the current index, and increment it.
		int curInd = currAU++;
		//! statrt clock to get time taken by this.AU
		auto start = thTimer._timeStart();
		while( curInd < numAUs )
		{
			//!get the AU to execute, which is of string type.
			istringstream ss(listAUs[curInd]);
			string tmp;
			ss >> tmp;
			int AU_ID = stoi(tmp);
			//! Function Name (smart contract).
			ss >> tmp;
			if( tmp.compare("get_bal") == 0 )
			{
				ss >> tmp;
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coin->get_bal(s_id, &bal);
			}
			if( tmp.compare("send") == 0 )
			{
				ss >> tmp;
				int s_id = stoi(tmp);
				ss >> tmp;
				int r_id = stoi(tmp);
				ss >> tmp;
				int amt = stoi(tmp);
				bool v  = coin->send(s_id, r_id, amt);
				if(v == false) aCount[t_ID]++;
			}
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		mTTime[t_ID] = mTTime[t_ID] + thTimer._timeStop(start);
	}

	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. Geting this using get_bel_val()   |
	//!-------------------------------------------------
	void finalState()
	{
		for(int sid = 1; sid <= SObj; sid++) {
			int bal = 0;
			//! get_bal() of smart contract.
			bool v = coin->get_bal(sid, &bal);
			MinerState[sid] = bal;
		}
	}

	~Miner() { };
};
/*************************Miner code ends**************************************/







/*************************Validator code begins********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "1" validator-THREAD          !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Validator
{
public:

	Validator(int minter_id)
	{
		//! initialize the counter to 0.
		currAU = 0;
		//! index location represents respective thread id.
		vTTime = new float_t [nThread];
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
		//! id of the contract creater is "minter_id".
		coinV = new Coin( SObj, minter_id );
	}

	//!-------------------------------------------------------- 
	//!! MAIN Validator:: CREATE ONE VALIDATOR THREADS !!!!!!!!
	//!--------------------------------------------------------
	void mainValidator()
	{
		Timer lTimer;
		thread T[nThread];
		//! initialization of account with fixed ammount;
		//! mint() function is serial.
		int bal = InitBalance, total = 0;
		for(int sid = 1; sid <= SObj; sid++) {
			//! 0 is contract deployer.
			bool v = coinV->mint(0, sid, bal);
			total  = total + bal;
		}

		//!-----------------------------------------------------
		//!!!!!!!!!!    CREATE 1 VALIDATOR THREADS      !!!!!!!!
		//!-----------------------------------------------------
		double start = lTimer.timeReq();
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concValidator, i, numAUs);
		for(auto& th : T) th.join();
		tTime[1] = lTimer.timeReq() - start;
	
		//! print the final state of the shared objects.
		finalState();
	}

	//!------------------------------------------------------
	//! THE FUNCTION TO BE EXECUTED BY A VALIDATOR THREADS. !
	//!------------------------------------------------------
	static void concValidator( int t_ID, int numAUs)
	{
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
		currAU = 0;
		Timer tTimer;
		//! get the current index, and increment it.
		int curInd = currAU++;

		//! statrt clock to get time taken by this.AU
		auto start = tTimer._timeStart();
		while( curInd < numAUs )
		{
			//!get the AU to execute, which is of string type.
			istringstream ss(listAUs[curInd]);
			string tmp;
			ss >> tmp;//! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp;//! Function Name (smart contract).
			if( tmp.compare("get_bal") == 0 )
			{
				ss >> tmp;//! get balance of SObj/id.
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coinV->get_bal(s_id, &bal);
			}
			if( tmp.compare("send") == 0 )
			{
				ss >> tmp;
				int s_id = stoi(tmp);
				ss >> tmp;
				int r_id = stoi(tmp);
				ss >> tmp;
				int amt = stoi(tmp);
				bool v  = coinV->send(s_id, r_id, amt);
			}			
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		vTTime[t_ID] = vTTime[t_ID] + tTimer._timeStop(start);
	}

	//!-------------------------------------------------
	//! FINAL STATE OF ALL THE SHARED OBJECT. ONCE ALL |
	//! AUS EXECUTED. GETING THIS USING get_bel.       |
	//!-------------------------------------------------
	void finalState()
	{
		for(int sid = 1; sid <= SObj; sid++) {
			int bal = 0;
			//! get_bal() of smart contract.
			bool v = coinV->get_bal(sid, &bal);
			ValidatorState[sid] = bal;
		}
	}

	~Validator() { };
};
/*************************Validator code ends**********************************/



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
/*!!!!!!!!!!!!!!!   main() !!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"Serial Miner and Serial Validator\n";
	cout<<"--------------------------------\n";
	//! list holds the avg time taken by miner and validator
	//!  threads for multiple consecutive runs of the algorithm.
	list<double>mItrT;         
	list<double>vItrT;	
	int totalRun = NumBlock; //at least 2
	int maxAccepted  = 0;
	int totalDepInG  = 0; //to get total number of dependencies in graph;
	int totalRejCont = 0; //number of validator rejected the blocks;

	FILEOPR file_opr;

	//! read from input file:: SObj = #SObj; nThread = #threads;
	//! numAUs = #AUs; λ =  % of edges to be removed from BG by malicious Miner.
	file_opr.getInp(&SObj, &nThread, &numAUs, &lemda);

	//!------------------------------------------------------------------
	//! Num of threads should be 1 for serial so we are fixing it to 1, !
	//! Whatever be # of threads in inputfile, it will be always one.   !
	//!------------------------------------------------------------------
	nThread = 1;
	if(SObj > M_SharedObj) {
		SObj = M_SharedObj;
		cout<<"Max number of Shared Object can be "<<M_SharedObj<<"\n";
	}

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		 //! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, SObj, FUN_IN_CONT, listAUs);
		Timer mTimer;
		mTimer.start();

		//MINER
		Miner *miner = new Miner(0);
		miner ->mainMiner();

		//VALIDATOR
		if(MValidation == true)
		{
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++)
			{
				Validator *validator = new Validator(0);
				validator ->mainValidator();

				//State Validation
				bool flag = stateVal();
				if(flag == true) rejectCount++;
				else acceptCount++;
			}
			if(numItr > 0) {
				totalRejCont += rejectCount;
				if(maxAccepted < acceptCount ) maxAccepted = acceptCount;
			}
			for(int i = 1; i <= SObj; i++) ValidatorState[i] = 0;
		}
		else
		{
			Validator *validator = new Validator(0);
			//State Validation
			bool flag = stateVal();
			if(flag == true) cout<<"\nBlock Rejected by Validator";
		}

		mTimer.stop();

		//total valid AUs among List-AUs executed
		//by Miner & varified by Validator.
		int vAUs = numAUs - aCount[0];
		if(numItr > 0)
			file_opr.writeOpt(SObj, nThread, numAUs, tTime, mTTime,
			                        vTTime, aCount, vAUs, mItrT, vItrT);

		for(int i = 1; i <= SObj; i++) {
			MinerState[i]     = 0;
			ValidatorState[i] = 0;
		}
		listAUs.clear();
		delete miner;
		miner = NULL;
	}
	
	// to get total avg miner and validator
	// time after number of totalRun runs.
	double tAvgMinerT = 0;
	double tAvgValidT = 0;
	auto mit          = mItrT.begin();
	auto vit          = vItrT.begin();
	for(int j = 0; j < totalRun; j++) {
		tAvgMinerT = tAvgMinerT + *mit;
		tAvgValidT = tAvgValidT + *vit;
		mit++;
		vit++;
	}
	tAvgMinerT = tAvgMinerT/(totalRun-1);
	tAvgValidT = tAvgValidT/(totalRun-1);
	cout<<"    Total Avg Miner = "<<tAvgMinerT<<" microseconds";
	cout<<"\nTotal Avg Validator = "<<tAvgValidT<<" microseconds";
	cout<<endl<<"-----------------------------";
	cout<<"\nAvg Number of Validator Accepted the Block = "
		<<(numValidator-(totalRejCont/(totalRun-1)));
	cout<<"\nAvg Number of Validator Rejcted the Block = "
		<<totalRejCont/(totalRun-1);
	cout<<"\nMax Validator Accepted any Block = "<<maxAccepted;
	cout<<"\n"<<pl<<endl;
	return 0;
}
