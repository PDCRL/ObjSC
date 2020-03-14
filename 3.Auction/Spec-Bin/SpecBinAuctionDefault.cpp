#include <iostream>
#include <thread>
#include "Util/Timer.cpp"
#include "Contract/SimpleAuction.cpp"
#include "Util/FILEOPR.cpp"
#include <unistd.h>
#include <list>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <set>
#include <algorithm>


#define maxThreads 128
#define maxBObj 5000
#define maxbEndT 5000 //millseconds
#define funInContract 6
#define pl "=================================================================\n"
#define MValidation true //! true or false
#define numValidator 50
#define NumBlock 26     //! at least two blocks, the first run is warmup run.
#define malMiner true    //! set the flag to make miner malicious.
#define NumOfDoubleSTx 2 //! # double-spending Tx for malicious final state by Miner, multiple of 2.

using namespace std;
using namespace std::chrono;


int beneficiary = 0;      //! fixed beneficiary id to 0, it can be any unique address/id.
int    nBidder  = 2;      //! nBidder: number of bidder shared objects. default is 2.
int    nThread  = 1;      //! nThread: total number of concurrent threads; default is 1.
int    numAUs;            //! numAUs: total number of Atomic Unites to be executed.
double lemda;             //! λ: random delay seed.
int    bidEndT;           //! time duration for auction.
double tTime[2];          //! total time taken by miner and validator algorithm respectively.
SimpleAuction *auction;   //! smart contract for miner.
int    *aCount  = NULL;   //! aborted transaction count.
float_t *mTTime = NULL;   //! time taken by each miner Thread to execute AUs (Transactions).
float_t *vTTime = NULL;   //! time taken by each validator Thread to execute AUs (Transactions).
float_t *gTtime = NULL;   //! time taken by each miner Thread to add edges and nodes in the conflict graph.
vector<string>listAUs;    //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
vector<string>seqBin;     //! holds sequential Bin AUs.
vector<string>concBin;    //! holds concurrent Bin AUs.
std::atomic<int>currAU;   //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>vCount;   //! # of valid AU node added in graph (invalid AUs will not be part of the graph & conflict list).
std::atomic<int>eAUCount; //! used by validator threads to keep track of how many valid AUs executed by validator threads.
mutex concLock, seqLock;  //! Lock used to access seq and conc bin.
float_t seqTime[2];       //! Used to store seq exe time.

// state
int mHBidder;
int mHBid;
int vHBidder;
int vHBid;
int *mPendingRet;
int *vPendingRet;



/*************************Barrier code begins**********************************/
std::mutex mtx;
std::mutex pmtx; // to print in concurrent scene
std::condition_variable cv;
bool launch = false;

void wait_for_launch() {
	std::unique_lock<std::mutex> lck(mtx);
	while (!launch) cv.wait(lck);
}

void shoot() {
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
	Miner( )
	{
		//! initialize the counter used to execute the numAUs
		currAU = 0;
		vCount = 0;
		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		gTtime = new float_t [nThread];
		aCount = new int [nThread];
		for(int i = 0; i < nThread; i++)  {
			mTTime[i] = 0;
			gTtime[i] = 0;
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

		//!---------------------------------------------------------
		//!!!!!!!!!!          Concurrent Phase            !!!!!!!!!!
		//!!!!!!!!!!    Create 'nThread' Miner threads    !!!!!!!!!!
		//!---------------------------------------------------------
		double s = mTimer.timeReq();
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concMiner, i, numAUs);
		for(auto& th : T) th.join();
		tTime[0] = mTimer.timeReq() - s;

		//!------------------------------------------
		//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
		//!------------------------------------------
		seqTime[0] = 0;
		Timer SeqTimer;
//		auction->allUnlock();
		auto start = SeqTimer._timeStart();
		seqBinExe();
		seqTime[0] = SeqTimer._timeStop( start );
//		auction->allUnlock();
		//! print the final state of the shared objects.
		finalState();
	}

	//!--------------------------------------------------------
	//! THE FUNCTION TO BE EXECUTED BY ALL THE MINER THREADS. !
	//!--------------------------------------------------------
	static void concMiner( int t_ID, int numAUs)
	{
		Timer thTimer;
		//! get the current index, and increment it.
		int curInd = currAU++;
		//! statrt clock to get time taken by this.AU
		auto start = thTimer._timeStart();
		while(curInd < numAUs)
		{
			//!get the AU to execute, which is of string type.
			istringstream ss(listAUs[curInd]);
			string tmp;
			ss >> tmp;
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if(tmp.compare("bid") == 0) {
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid_m(payable, bID, bAmt, true);
				//! if fun retrun -1 add the AU to seq Bin.
				if(v == -1) {
					vCount++;
					seqLock.lock();
					seqBin.push_back(listAUs[curInd]);
					seqLock.unlock();
				}
				else if(v == 1) {
					concLock.lock();
					concBin.push_back(listAUs[curInd]);
					concLock.unlock();
				}
				else {
					vCount++;
					seqLock.lock();
					seqBin.push_back(listAUs[curInd]);
					seqLock.unlock();
				}
			}
			if(tmp.compare("withdraw") == 0) {
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw_m(bID, true);
				//! if fun retrun -1 add the AU to seq Bin.
				if(v == -1) {
					vCount++;
					seqLock.lock();
					seqBin.push_back(listAUs[curInd]);
					seqLock.unlock();
				}
				else if(v == 1) {
					concLock.lock();
					concBin.push_back(listAUs[curInd]);
					concLock.unlock();
				}
				else {
					vCount++;
					seqLock.lock();
					seqBin.push_back(listAUs[curInd]);
					seqLock.unlock();
				}
			}
			if(tmp.compare("auction_end") == 0) {
				int v = auction->auction_end_m( );
				seqLock.lock();
				seqBin.push_back(listAUs[curInd]);
				seqLock.unlock();
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
			if(tmp.compare("bid") == 0) {
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid_m(payable, bID, bAmt, false);
			}
			if(tmp.compare("withdraw") == 0) {
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw_m(bID, false);
			}
			if(tmp.compare("auction_end") == 0) {
				int v = auction->auction_end_m( );
			}
			count++;
		}
	}


	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using state()  |
	//!-------------------------------------------------
	void finalState() {	
		auction->state_m(&mHBidder, &mHBid, mPendingRet);//Entire state
	}
	~Miner() { };
};
/*************************Miner code ends**************************************/







/*************************Validator code begins********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "n" validator-THREAD   !
! CONCURRENTLY BASED ON CONC and SEQ BIN GIVEN BY MINER !
! OPERATIONS of RESPECTIVE AUs.                         !
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

		auction->reset(bidEndT);

		//!---------------------------------------------------------
		//!!!!!!!!!!          Concurrent Phase            !!!!!!!!!!
		//!!!!!!!!!!  Create 'nThread' Validator threads  !!!!!!!!!!
		//!---------------------------------------------------------
		//!Start clock
		double s = vTimer.timeReq();
		for(int i = 0; i<nThread; i++)
			T[i] = thread(concValidator, i);
		shoot(); //notify all threads to begin the worker();
		for(auto& th : T) th.join( );
		tTime[1] = vTimer.timeReq() - s;

		//!------------------------------------------
		//!!!!!!!!!   Sequential Phase     !!!!!!!!!!
		//!------------------------------------------
		seqTime[1] = 0;
		Timer SeqTimer;
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
		auto start = Ttimer._timeStart();
		int curInd = eAUCount++;
		while( curInd< concBin.size() )
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(concBin[curInd]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if(tmp.compare("bid") == 0) {
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid(payable, bID, bAmt);
			}
			if(tmp.compare("withdraw") == 0) {
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw(bID);
			}
			if(tmp.compare("auction_end") == 0) {
				int v = auction->auction_end( );
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
			ss >> tmp;
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if(tmp.compare("bid") == 0) {
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid(payable, bID, bAmt);
			}
			if(tmp.compare("withdraw") == 0) {
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw(bID);
			}
			if(tmp.compare("auction_end") == 0) {
				int v = auction->auction_end( );
			}
			count++;
		}
	}

	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. ONCE ALL  |
	//!AUS EXECUTED. WE ARE GETING THIS USING state()  |
	//!-------------------------------------------------
	void finalState() {
		auction->state(&vHBidder, &vHBid, vPendingRet);
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
	ss >> trns1; //! payable.
	int payable = stoi(trns1);
	ss >> trns1; //! bidder ID.
	int bidderID = stoi(trns1);
	ss >> trns1; //! Ammount to bid.
	int bidValue  = stoi(trns1);

	istringstream ss1(listAUs[atPoss-1]);
	string trns2;
	ss1 >> trns1; //! AU_ID to Execute.
	int AU_ID2 = stoi(trns1);
	ss1 >> trns1;//function name
	ss1 >> trns1; //! payable.
	int payable1 = stoi(trns1);
	ss1 >> trns1; //! bidderID.
	int bidderID1 = stoi(trns1);
	ss1 >> trns1; //! Ammount to bid.
	int bidValue1  = stoi(trns1);


	bidValue = 999;
	trns1 = to_string(AU_ID1)+" bid "+to_string(payable)+" "
			+to_string(bidderID)+" "+to_string(bidValue);
	listAUs[AU_ID1-1] =  trns1;

	bidValue1 = 1000;
	trns2 = to_string(AU_ID2)+" bid "+to_string(payable1)+" "
			+to_string(bidderID1)+" "+to_string(bidValue1);
	listAUs[AU_ID2-1] =  trns1;

	mHBidder = bidderID1;
	mHBid    = bidValue;


	//! add the confliciting AUs in conc bin and remove them from seq bin. Add
	//! one of the AU from seq bin to conc Bin and remove that AU from seq bin.
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
/*!!!!!!!!          main()         !!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"Bin Based tryLock Miner and Concurrent Validator\n";
	cout<<"--------------------------------\n";
	//! list holds the avg time taken by miner and Validator
	//! thread s for multiple consecutive runs.
	list<double>mItrT;
	list<double>vItrT;
	int totalDepInG  = 0; //to get total number of dependencies in graph;
	int totalRejCont = 0; //number of validator rejected the blocks;
	int maxAccepted  = 0;
	int totalRun     = NumBlock; //at least 2

	FILEOPR file_opr;

	//! read from input file:: nBidder = #nBidder; nThread = #threads;
	//! numAUs = #AUs; λ = random delay seed.
	file_opr.getInp(&nBidder, &bidEndT, &nThread, &numAUs, &lemda);

	if(nBidder > maxBObj) {
		nBidder = maxBObj;
		cout<<"Max number Bidder Shared Object can be "<<maxBObj<<"\n";
	}

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
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

		if(lemda != 0) bool rv = addMFS(NumOfDoubleSTx);

//		printBins();

		//VALIDATOR
		if(MValidation == true)
		{
				
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++)
			{
				Validator *validator = new Validator();
				validator ->mainValidator();

				bool flag = stateVal();
				if(flag == true) rejectCount++;
				else acceptCount++;
			}
			if(numItr > 0 && malMiner == true) {
				totalRejCont += rejectCount;
				if(maxAccepted < acceptCount ) maxAccepted = acceptCount;
			}
		}
		else
		{
			Validator *validator = new Validator();
			validator ->mainValidator();
			//State Validation
			bool flag = stateVal();
			if(flag == true) cout<<"\nBlock Rejected by Validator";
		}

	
		//! total valid AUs among total AUs executed 
		//! by miner and varified by Validator.
		int vAUs =  seqBin.size() + concBin.size();
		if(numItr > 0)
			file_opr.writeOpt(nBidder, nThread, numAUs, tTime,
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
			<<tAvgMinerT+seqTime[1]+seqTime[0]<<" microseconds";
	cout<<"\nTotal Avg Validator  = "<<tAvgValidT+seqTime[1]
		<<" microseconds\n-----------------------------";
	cout<<"\nMiner Seq Time       = "<<seqTime[0]<<" microseconds"
		<< "\nValidator Seq Time   = "<< seqTime[1]<<" microseconds";
	cout<<"\n-----------------------------";
	cout<<"\nAvg Number of Validator Accepted the Block = "
		<<(numValidator-(totalRejCont/(totalRun-1)));
	cout<<"\nAvg Number of Validator Rejcted  the Block = "
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
