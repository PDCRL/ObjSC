#include <iostream>
#include <thread>
#include <list>
#include <atomic>
#include "Util/Timer.cpp"
#include "Contract/SimpleAuction.cpp"
#include "Util/FILEOPR.cpp"

#define maxThreads 128
#define maxBObj 5000
#define maxbEndT 5000 //millseconds
#define funInContract 6
#define pl "=================================================================\n"
#define MValidation true  //! true or false
#define numValidator 50
#define NumBlock 26      //! at least two blocks, the first run is warmup run.

using namespace std;
using namespace std::chrono;

int beneficiary = 0;       //! fixed beneficiary id to 0, it can be any unique address/id.
int    nBidder  = 2;       //! nBidder: number of bidder shared objects.
int    nThread  = 1;       //! nThread: total number of concurrent threads; default is 1.
int    numAUs;             //! numAUs: total number of Atomic Unites to be executed.
double lemda;              //! λ: random delay seed.
int    bidEndT;            //! time duration for auction.
double tTime[2];          //! total time taken by miner and validator algorithm respectively.
SimpleAuction *auction;    //! smart contract for miner.
SimpleAuction *auctionV;   //! smart contract for Validator.
int    *aCount;            //! aborted transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs (Transactions).
float_t*vTTime;            //! time taken by each validator Thread to execute AUs (Transactions).
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>eAUCount;  //! used by validator threads to keep track of how many valid AUs executed by validator threads.


// state
int mHBidder;
int mHBid;
int vHBidder;
int vHBid;
int *mPendingRet;
int *vPendingRet;




/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "n" miner-THREAD CONCURRENTLY           !
!"concMiner()" CALLED BY miner-THREAD TO PERFROM oprs of RESPECTIVE AUs !
! THREAD 0 IS CONSIDERED AS MINTER-THREAD (SMART CONTRACT DEPLOYER)     !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner( )
	{
		//! initialize the counter used to execute the numAUs to
		//! 0, and graph node counter to 0 (number of AUs added
		//! in graph, invalid AUs will not be part of the grpah).
		currAU = 0;
		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		aCount = new int [nThread];
		for(int i = 0; i < nThread; i++) {
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		auction = new SimpleAuction(bidEndT, beneficiary, nBidder);
	}

	//!-------------------------------------------- 
	//!!!!!! MAIN MINER:: CREATE MINER THREADS !!!!
	//!--------------------------------------------
	void mainMiner()
	{
		Timer mTimer;
		thread T[nThread];

		//!-------------------------------------
		//!!!!!! Create one Miner threads  !!!!!
		//!-------------------------------------
		double start = mTimer.timeReq();
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concMiner, i, numAUs);
		for(auto& th : T) th.join();
		tTime[0] = mTimer.timeReq() - start;

		//! print the final state of the shared objects.
		finalState();
//		 auction->AuctionEnded( );
	}


	//!--------------------------------------------------------
	//! The function to be executed by all the miner threads. !
	//!--------------------------------------------------------
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
			ss >> tmp;
			if(tmp.compare("bid") == 0)
			{
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				bool v = auction->bid(payable, bID, bAmt);
				if(v != true) aCount[0]++;
			}
			if(tmp.compare("withdraw") == 0)
			{
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID

				bool v = auction->withdraw(bID);
				if(v != true) aCount[0]++;
			}
			if(tmp.compare("auction_end") == 0)
			{
				bool v = auction->auction_end( );
				if(v != true) aCount[0]++;
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
		for(int id = 1; id <= nBidder; id++) {
			auction->state(&mHBidder, &mHBid, mPendingRet);
		}
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
		currAU = 0;
		//! index location represents respective thread id.
		vTTime = new float_t [nThread];
		aCount = new int [nThread];
		for(int i = 0; i < nThread; i++) {
			vTTime[i] = 0;
			aCount[i] = 0;
		}
		auctionV = new SimpleAuction(bidEndT, beneficiary, nBidder);
	}

	/*!---------------------------------------
	| create n concurrent validator threads  |
	| to execute valid AUs in conflict graph.|
	----------------------------------------*/
	void mainValidator()
	{
		Timer vTimer;
		thread T[nThread];
		auction->reset(bidEndT);

		//!--------------------------_-----------
		//!!!!! Create one Validator threads !!!!
		//!--------------------------------------
		double start = vTimer.timeReq();
		for(int i = 0; i<nThread; i++)
			T[i] = thread(concValidator, i);
		for(auto& th : T) th.join( );
		tTime[1] = vTimer.timeReq() - start;

		//!print the final state of the shared objects by validator.
		finalState();
//		auctionV->AuctionEnded( );
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
			ss >> tmp;
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if(tmp.compare("bid") == 0)
			{
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				bool v = auctionV->bid(payable, bID, bAmt);
				if(v != true) aCount[0]++;
			}
			if(tmp.compare("withdraw") == 0)
			{
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID

				bool v = auctionV->withdraw(bID);
				if(v != true) aCount[0]++;
			}
			if(tmp.compare("auction_end") == 0)
			{
				bool v = auctionV->auction_end( );
				if(v != true) aCount[0]++;
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
		for(int id = 1; id <= nBidder; id++) {
			auction->state(&vHBidder, &vHBid, vPendingRet);
		}
	}
	~Validator() { };
};



bool stateVal() {
	//State Validation
	bool flag = false;
	if(mHBidder != vHBidder || mHBid != vHBid) flag = true;
//	cout<<"\n============================================"
//	    <<"\n     Miner Auction Winer "<<mHBidder
//	    <<" |  Amount "<<mHBid;
//	cout<<"\n Validator Auction Winer "<<to_string(vHBidder)
//	    <<" |  Amount "<<to_string(vHBid);
//	cout<<"\n============================================\n";
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
	//! list holds the avg time taken by miner and Validator
	//! thread s for multiple consecutive runs.
	list<double>mItrT;
	list<double>vItrT;
	int totalRejCont = 0; //number of validator rejected the blocks;
	int maxAccepted  = 0;
	int totalRun     = NumBlock;

	FILEOPR file_opr;

	//! read from input file:: nBidder = #numProposal; nThread = #threads;
	//! numAUs = #AUs; λ = random delay seed.
	file_opr.getInp(&nBidder, &bidEndT, &nThread, &numAUs, &lemda);

	//!------------------------------------------------------------------
	//! Num of threads should be 1 for serial so we are fixing it to 1, !
	//! Whatever be # of threads in inputfile, it will be always one.   !
	//!------------------------------------------------------------------
	nThread = 1;

	//! max Proposal shared object error handling.
	if(nBidder > maxBObj) {
		nBidder = maxBObj;
		cout<<"Max number of Proposal Shared Object can be "<<maxBObj<<"\n";
	}

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		 //! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, nBidder, funInContract, listAUs);
		tTime[0]    = 0;
		tTime[1]    = 0;
		mPendingRet = new int [nBidder+1];
		vPendingRet = new int [nBidder+1];
		Timer mTimer;
		mTimer.start();

		//MINER
		Miner *miner = new Miner();
		miner ->mainMiner();

		//VALIDATOR
		if(MValidation == true) {
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++) {

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
		}
		else {
			Validator *validator = new Validator(0);
			validator ->mainValidator();

			//State Validation
			bool flag = stateVal();
			if(flag == true) cout<<"\nBlock Rejected by Validator";
		}
		mTimer.stop();

		//! total valid AUs among total AUs executed 
		//! by miner and varified by Validator.
		int vAUs = numAUs-aCount[0];
		if(numItr > 0)
			file_opr.writeOpt(nBidder, nThread, numAUs, tTime,
			                  mTTime, vTTime, aCount, vAUs, mItrT, vItrT);

		listAUs.clear();
		delete miner;
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

	cout<<"    Total Avg Miner       = "<<tAvgMinerT<<" microseconds";
	cout<<"\nTotal Avg Validator       = "<<tAvgValidT<<" microseconds";
	cout<<"\n--------------------------------\n";
	cout<<"Avg Number of Validator Accepted the Block = "
		<<(numValidator-(totalRejCont/(totalRun-1)));
	cout<<"\nAvg Number of Validator Rejcted the Block = "
		<<totalRejCont/(totalRun-1);
	cout<<"\nMax Validator Accepted any Block = "<<maxAccepted;
	cout<<"\n"<<endl;

	mItrT.clear();
	vItrT.clear();
	delete mTTime;
	delete vTTime;
	return 0;
}
/*************************Main Fun code ends***********************************/
