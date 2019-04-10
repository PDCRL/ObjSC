#include <iostream>
#include <thread>
#include <list>
#include <atomic>
#include "Util/Timer.cpp"
#include "Contract/Ballot.cpp"
#include "Util/FILEOPR.cpp"

#define maxThreads 128
#define maxPObj 1000
#define maxVObj 5000
#define funInContract 5
#define pl "=============================\n"

using namespace std;
using namespace std::chrono;

int    nProposal = 2;      //! nProposal: number of proposal shared objects;
int    nVoter    = 1;      //! nVoter: number of voter shared objects;
int    nThread   = 1;      //! nThread: total number of concurrent threads; default is 1.
int    numAUs;             //! numAUs: total number of Atomic Unites to be executed.
double lemda;              //! λ: random delay seed.

double totalTime[2];       //! total time taken by miner and validator algorithm.
Ballot *ballot;            //! smart contract for miner.
Ballot *ballot_v;          //! smart contract for validator.
int    *aCount;            //! aborted transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs (Transactions).
float_t*vTTime;            //! time taken by each validator Thread to execute AUs (Transactions).
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>eAUCount;  //! used by validator threads to keep track of how many valid AUs executed by validator threads.

string *proposalNames;

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "n" miner-THREAD CONCURRENTLY           !
!"concMiner()" CALLED BY miner-THREAD TO PERFROM oprs of RESPECTIVE AUs !
! THREAD 0 IS CONSIDERED AS MINTER-THREAD (SMART CONTRACT DEPLOYER)     !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int chairperson)
	{
		//! initialize the counter used to execute the numAUs to
		//! 0, and graph node counter to 0 (number of AUs added
		//! in graph, invalid AUs will not be part of the grpah).
		currAU     = 0;

		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		aCount = new int [nThread];

		proposalNames = new string[nProposal+1];
		for(int x = 0; x <= nProposal; x++)
		{
			proposalNames[x] = "X"+to_string(x+1);
		}		
		for(int i = 0; i < nThread; i++) 
		{
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		
		//! Id of the contract creater is \chairperson = 0\.
		ballot = new Ballot( proposalNames, chairperson, nVoter, nProposal);
	}

	//!------------------------------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER + GRAPH CONSTRUCTION THREADS !!!!!!!!!!
	//!-------------------------------------------------------------------------
	void mainMiner()
	{
		Timer mTimer;
		thread T[nThread];

		//! Give \`voter\` the right to vote on this ballot.
		//! giveRightToVote_m() is serial.
		for(int voter = 1; voter <= nVoter; voter++) 
		{
			//! 0 is chairperson.
			ballot->giveRightToVote(0, voter);
		}

		//!-----------------------------------------------------
		//!!!!!!!!!!    Create one Miner threads      !!!!!!!!!!
		//!-----------------------------------------------------
//		cout<<"!!!!!!!   Serial Miner Thread Started         !!!!!!\n";
		//! Start clock to get time taken by miner algorithm.
		double start = mTimer.timeReq();
		for(int i = 0; i < nThread; i++)
		{
			T[i] = thread(concMiner, i, numAUs);
		}
		//! miner thread join
		for(auto& th : T)
		{
			th.join();
		}
		//! Stop clock
		totalTime[0] = mTimer.timeReq() - start;
//		cout<<"!!!!!!!   Serial Miner Thread Join            !!!!!!\n";
	

		//! print the final state of the shared objects.
//		finalState();
//		ballot->winningProposal_m();
//		string winner;
//		ballot->winnerName(&winner);
//		cout<<"\n Number of Valid   AUs = "+to_string(numAUs-aCount[0])
//				+" (AUs Executed Successfully)\n";
//		cout<<" Number of Invalid AUs = "+to_string(aCount[0])+"\n";
	}


	//!--------------------------------------------------------
	//! The function to be executed by all the miner threads. !
	//!--------------------------------------------------------
	static void concMiner( int t_ID, int numAUs)
	{
		Timer thTimer;
		//! statrt clock to get time taken by this.AU
		auto start = thTimer._timeStart();

		//! get the current index, and increment it.
		int curInd = currAU++;

		while( curInd < numAUs )
		{

			//!get the AU to execute, which is of string type.
			istringstream ss(listAUs[curInd]);

			string tmp;
			//! AU_ID to Execute.
			ss >> tmp;

			int AU_ID = stoi(tmp);

			//! Function Name (smart contract).
			ss >> tmp;

			if(tmp.compare("vote") == 0)
			{
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int v = ballot->vote(vID, pID);
				if(v != 1)
				{
					aCount[0]++;
				}
			}
			if(tmp.compare("delegate") == 0)
			{
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
				if(v != 1)
				{
					aCount[0]++;
				}
			}
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		mTTime[t_ID] = mTTime[t_ID] + thTimer._timeStop(start);
	}


	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using state_m()|
	//!-------------------------------------------------
	void finalState()
	{
		for(int id = 1; id <= nVoter; id++) 
		{
			ballot->state(id, true);//for voter state
		}
		for(int id = 1; id <= nProposal; id++) 
		{
			ballot->state(id, false);//for voter state
		}
//		cout<<"\n Number of Valid   AUs = "+to_string(numAUs - aCount[0])
//				+" (AUs Executed Successfully)\n";
//		cout<<" Number of Invalid AUs = "+to_string(aCount[0])+"\n";
	}

	~Miner() { };
};



/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "1" validator-THREAD CONCURRENTLY BASED ON CONFLICT GRPAH!
! GIVEN BY MINER. "concValidator()" CALLED BY validator-THREAD TO PERFROM OPERATIONS of   !
! RESPECTIVE AUs. THREAD 0 IS CONSIDERED AS MINTER-THREAD (SMART CONTRACT DEPLOYER)       !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Validator
{
public:

	Validator(int chairperson)
	{
		//! initialize the counter used to execute the numAUs to
		//! 0, and graph node counter to 0 (number of AUs added
		//! in graph, invalid AUs will not be part of the grpah).
		currAU     = 0;

		//! index location represents respective thread id.
		vTTime = new float_t [nThread];
		aCount = new int [nThread];
		
		for(int i = 0; i < nThread; i++) 
		{
			vTTime[i] = 0;
			aCount[i] = 0;
		}
		
		//! Id of the contract creater is \chairperson = 0\.
		ballot_v = new Ballot( proposalNames, chairperson, nVoter, nProposal);
	}

	/*!---------------------------------------
	| create n concurrent validator threads  |
	| to execute valid AUs in conflict graph.|
	----------------------------------------*/
	void mainValidator()
	{
		Timer vTimer;
		thread T[nThread];

		//! giveRightToVote() function is serial.
		for(int voter = 1; voter <= nVoter; voter++) 
		{
			//! 0 is chairperson.
			ballot_v->giveRightToVote(0, voter);
		}

		//!--------------------------_-----------
		//!!!!! Create one Validator threads !!!!
		//!--------------------------------------
//		cout<<"!!!!!!!   Serial Validator Thread Started     !!!!!!\n";
		//!Start clock
		double start = vTimer.timeReq();
		for(int i = 0; i<nThread; i++)
		{
			T[i] = thread(concValidator, i);
		}
		//!validator thread join.
		for(auto& th : T)
		{
			th.join( );
		}
		//!Stop clock
		totalTime[1] = vTimer.timeReq() - start;
//		cout<<"!!!!!!!   Serial Validator Thread Join        !!!!!!\n\n";

		//!print the final state of the shared objects by validator.
//		finalState();
//		ballot->winningProposal();
//		string winner;
//		ballot->winnerName(&winner);
	}

	//!-------------------------------------------------------
	//! Function to be executed by all the validator threads.!
	//!-------------------------------------------------------
	static void concValidator( int t_ID )
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
			//! AU_ID to Execute.
			ss >> tmp;

			int AU_ID = stoi(tmp);

			//! Function Name (smart contract).
			ss >> tmp;

			if(tmp.compare("vote") == 0)
			{
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int v = ballot_v->vote(vID, pID);
				if(v != 1)
				{
					aCount[0]++;
				}
			}
			if(tmp.compare("delegate") == 0)
			{
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot_v->delegate(sID, rID);
				if(v != 1)
				{
					aCount[0]++;
				}
			}
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		vTTime[t_ID] = vTTime[t_ID] + thTimer._timeStop(start);
	}


	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using get_bel()|
	//!-------------------------------------------------
	void finalState()
	{
		for(int id = 1; id <= nVoter; id++) 
		{
			ballot_v->state(id, true);//for voter state
		}
		for(int id = 1; id <= nProposal; id++) 
		{
			ballot_v->state(id, false);//for voter state
		}
	}
	~Validator() { };
};




/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!   main() !!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	//! list holds the avg time taken by miner and Validator
	//! thread s for multiple consecutive runs.
	list<double>mItrT;
	list<double>vItrT;
	double avgMiner = 0;
	double avgValidator = 0;


	cout<<pl<<" Serial Algorithm \n"<<pl;
	int totalRun = 1;
	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		FILEOPR file_opr;

		//! read from input file:: nProposal = #numProposal; nThread = #threads;
		//! numAUs = #AUs; λ = random delay seed.
		file_opr.getInp(&nProposal, &nVoter, &nThread, &numAUs, &lemda);
		
		//!------------------------------------------------------------------
		//! Num of threads should be 1 for serial so we are fixing it to 1, !
		//! Whatever be # of threads in inputfile, it will be always one.   !
		//!------------------------------------------------------------------
		nThread = 1;

		//! max Proposal shared object error handling.
		if(nProposal > maxPObj) 
		{
			nProposal = maxPObj;
			cout<<"Max number of Proposal Shared Object can be "<<maxPObj<<"\n";
		}
		
		//! max Voter shared object error handling.
		if(nVoter > maxVObj) 
		{
			nVoter = maxVObj;
			cout<<"Max number of Proposal Shared Object can be "<<maxVObj<<"\n";
		}
		 //! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, nVoter, nProposal, funInContract, listAUs);
		
		Timer mTimer;
		mTimer.start();

		//MINER
		Miner *miner = new Miner(0);
		std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
		miner ->mainMiner();
		std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
//		cout << "\nSerial-Miner Algorithm computation took " 
//			 << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//			 << " microseconds" << std::endl;
 		avgMiner += std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

		//VALIDATOR
		Validator *validator = new Validator(0);
		begin = std::chrono::steady_clock::now();
		validator ->mainValidator();
		end = std::chrono::steady_clock::now();
//		cout << "Serial-Validator Algorithm computation took " 
//			 << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//			 << " microseconds" << std::endl;
 		avgValidator += std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

		mTimer.stop();

		//! total valid AUs among total AUs executed 
		//! by miner and varified by Validator.
		int vAUs = numAUs-aCount[0];
		file_opr.writeOpt(nProposal, nVoter, nThread, numAUs, totalTime, mTTime, vTTime, aCount, vAUs, mItrT, vItrT);

//		cout<<"\n\nc CPU time:  " << main_timer->cpu_ms_total() <<" ms \n";
//		cout<<"c Real time: "    << main_timer->real_ms_total()<<" ms \n";
//		cout<<"\n===================== Execution "<<numItr+1<<" Over =====================\n"<<endl;

		listAUs.clear();
		delete miner;
		miner = NULL;
		delete validator;
		validator = NULL;
	}
	
	double tAvgMinerT = 0, tAvgValidT = 0;//to get total avg miner and validator time after number of totalRun runs.
	auto mit = mItrT.begin();
	auto vit = vItrT.begin();
	for(int j = 0; j < totalRun; j++)
	{
		tAvgMinerT = tAvgMinerT + *mit;
//		cout<<"\n    Avg Miner = "<<*mit;
		tAvgValidT = tAvgValidT + *vit;
//		cout<<"\nAvg Validator = "<<*vit;
		mit++;
		vit++;
	}
	tAvgMinerT = tAvgMinerT/totalRun;
	tAvgValidT = tAvgValidT/totalRun;
	cout<<"\n    Total Avg Miner = "<<tAvgMinerT<<" microseconds";
	cout<<"\nTotal Avg Validator = "<<tAvgValidT<<" microseconds";
//	cout<<"\n  Total Avg (M + V) = "<<tAvgMinerT+tAvgValidT<<" microseconds";
	cout<<"\n"<<pl;

	mItrT.clear();
	vItrT.clear();

	delete mTTime;
	delete vTTime;
	delete aCount;

return 0;
}
