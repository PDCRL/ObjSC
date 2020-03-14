#include <iostream>
#include <thread>
#include <atomic>
#include <list>
#include "Util/Timer.cpp"
#include "Util/FILEOPR.cpp"
#include "Contract/Mix.cpp"
#include <unistd.h>
#include <list>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <set>
#include <algorithm>

#define CoinIdStart 5000
#define VoterIdStart 10000 //Proposal Id is -Ve in I/P file
#define AuctionIdStart 1


#define MAX_THREADS 128
#define maxCoinAObj 5000  //maximum coin contract \account\ object.
#define CFCount 3         //# methods in coin contract.

#define maxPropObj 1000   //maximum ballot contract \proposal\ shared object.
#define maxVoterObj 40000 //maximum ballot contract \voter\ shared object.
#define BFCount 5         //# methods in ballot contract.

#define maxBidrObj 5000   //maximum simple auction contract \bidder\ shared object.
#define maxbEndT 600      //maximum simple auction contract \bidding time out\ duration.
#define AFConut 6         //# methods in simple auction contract.
#define pl "=================================================================\n"
#define MValidation true   //! true or false
#define numValidator 50
#define InitBalance 1000
#define NumBlock 26       //! at least two blocks, the first run is warmup run.
#define malMiner true      //! set the flag to make miner malicious.
#define NumOfDoubleSTx 2   //! # double-spending Tx for malicious final state by Miner, multiple of 2.


using namespace std;
using namespace std::chrono;

//! INPUT FROM INPUT FILE.
int nThread;    //! # of concurrent threads;
int numAUs;     //! # Atomic Unites to be executed.
int CoinSObj;   //! # Coin Shared Object.
int nProposal;  //! # Ballot Proposal Shared Object.
int nVoter;     //! # Ballot Voter Shared Object.
int nBidder;    //! # Ballot Voter Shared Object.
int bidEndT;    //! time duration for auction.
int lemda;      //!  % of edges to be removed from BG by malicious Miner.

double tTime[2];           //! total time taken by miner & validator.
int    *aCount;            //! Invalid transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs.
float_t*vTTime;            //! time taken by each validator Thread to execute AUs.
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
vector<string>seqBin;      //! holds sequential Bin AUs.
vector<string>concBin;     //! holds concurrent Bin AUs.
vector<int>ccSet;          //! Set holds the IDs of the shared objects accessed by concurrent Bin Tx.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>vCount;    //! # of valid AU.
std::atomic<int>eAUCount;  //! used by validator threads to keep track of how many valid AUs executed by validator threads.
mutex concLock, seqLock;
float_t seqTime[3];
string *proposalNames;     //! proposal names for ballot contract.

//! CONTRACT OBJECTS;
Coin   *coin;            //! coin contract miner object.
Ballot *ballot;          //! ballot contract for miner object.
SimpleAuction *auction;  //! simple auction contract for miner object.

int *mCoinState;
int *vCoinState;
int *mBallotProState;
int *vBallotProState;
int *mBallotVotState;
int *vBallotVotState;
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
	Miner(int contDeployer)
	{
		//! initialize the counter used to execute the numAUs
		currAU = 0;
		vCount = 0;

		proposalNames = new string[nProposal+1];
		for(int x = 0; x <= nProposal; x++)
			proposalNames[x] = "X"+to_string(x+1);

		
		
		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		aCount = new int [nThread];
		
		for(int i = 0; i < nThread; i++) 
		{
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		//! id of the contract creater is "minter_id = 5000".
		coin = new Coin( CoinSObj, 5000 );
		
		//! Id of the contract creater is \chairperson = 10000\.
		ballot = new Ballot( proposalNames, 10000, nVoter, nProposal);
		
		//! fixed beneficiary id to 0, it can be any unique address/id.
		auction = new SimpleAuction(bidEndT, 0, nBidder);
	}

	//!---------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER THREADS !!!!!!!!!!
	//!----------------------------------------------------
	void mainMiner()
	{
		Timer mTimer;
		thread T[nThread];

		//! initialization of account with
		//! fixed ammount; mint() is serial.
		int bal = InitBalance;
		for(int sid = 1; sid <= CoinSObj; sid++) {
			//! 5000 is contract deployer.
			coin->mint(5000, CoinIdStart+sid, bal);
		}

		//! Give \`voter\` the right to vote on this ballot.
		//! giveRightToVote_m() is serial.
		for(int voter = 1; voter <= nVoter; voter++) {
			//! 10000 is chairperson.
			ballot->giveRightToVote(10000, VoterIdStart+voter);
		}


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
		//! Start clock to get time taken by miner algorithm.
		double s = mTimer.timeReq();
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concMiner, i, concBin.size());
		for(auto& th : T) th.join();
		tTime[0] = mTimer.timeReq() - s;


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

	void printBin(vector<string> &Bin) {
		cout<<endl<<"====================="
			<<"\nBin AUs\n=====================";
		for(int i = 0; i < Bin.size(); i++) {
			cout<<"\n"<<Bin[i];
		}
		cout<<endl;
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
		if(tmp.compare("bid") == 0) {
			ss >> tmp;
			int payable = stoi(tmp);//! payable
			ss >> tmp;
			int bID = stoi(tmp);//! Bidder ID
			sObj.push_back(bID);
			return;
		}
		if(tmp.compare("withdraw") == 0) {
			ss >> tmp;
			int bID = stoi(tmp);//! Bidder ID
			sObj.push_back(bID);
			return;
		}
		if(tmp.compare("vote") == 0) {
			ss >> tmp;
			int vID = stoi(tmp);//! voter ID
			ss >> tmp;
			int pID = stoi(tmp);//! proposal ID
			sObj.push_back(vID);
			sObj.push_back(pID);
			return;
		}
		if(tmp.compare("delegate") == 0) {
			ss >> tmp;
			int sID = stoi(tmp);//! Sender ID
			ss >> tmp;
			int rID = stoi(tmp);//! Reciver ID
			sObj.push_back(sID);
			sObj.push_back(rID);
			return;
		}
		
	}


	//!-----------------------------------------------------------
	//! Performs the static analysis based on set Operations.    !
	//!-----------------------------------------------------------
	void staticAnalysis() {

		//holds the IDs of the shared object accessed by an AU.
		vector<int> sObj;
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


	//!--------------------------------------------------------
	//! THE FUNCTION TO BE EXECUTED BY ALL THE MINER THREADS. !
	//!--------------------------------------------------------
	static void concMiner( int t_ID, int numAUs)
	{
		shoot();

		Timer thTimer;

		//! flag is used to add valid AUs in Graph.
		//! (invalid AU: senders doesn't
		//! have sufficient balance to send).
		bool flag = true;

		//! get the current index, and increment it.
		int curInd = currAU++;

		//! statrt clock to get time taken by this.AU
		auto start = thTimer._timeStart();

		while(curInd < concBin.size())
		{
			//!get the AU to execute, which is of string type.
			istringstream ss(concBin[curInd]);

			string tmp;
			//! AU_ID to Execute.
			ss >> tmp;

			int AU_ID = stoi(tmp);

			//! Function Name (smart contract).
			ss >> tmp;
			if(tmp.compare("bid") == 0)
			{
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid(payable, bID, bAmt);
			}
			if(tmp.compare("withdraw") == 0)
			{
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw(bID);
			}
			if(tmp.compare("auction_end") == 0)
			{
				int v = auction->auction_end( );
			}

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
				if(v == 0)
				{
					//! invalid AU: sender does't 
					//! have sufficent balance to send.
//					cout<<"\nConcBIn:Sender don't have sufficent balance to send.\n";
				}
			}
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote(vID, PID);					
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
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
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("bid") == 0)
			{
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid(payable, bID, bAmt);
			}
			if(tmp.compare("withdraw") == 0)
			{
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw(bID);
			}
			if(tmp.compare("auction_end") == 0)
			{
				int v = auction->auction_end( );
			}
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
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote(vID, PID);				
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
			}
			count++;
		}
	}

	//!-------------------------------
	//!FINAL STATE OF ALL THE SHARED |
	//!OBJECT. Once all AUs executed.|
	//!-------------------------------
	void finalState()
	{
		//coin state
		for(int sid = 1; sid <= CoinSObj; sid++) 
		{
			int bal = 0, ts;
			coin->get_bal(CoinIdStart+sid, &bal);
			mCoinState[sid] = bal;
		}

		for(int id = 1; id <= nVoter; id++) 
			ballot->state(VoterIdStart+id, true, mBallotVotState);//for voter state

		for(int id = 1; id <= nProposal; id++) 
			ballot->state(id, false, mBallotProState);//for Proposal state

		auction->state(&mHBidder, &mHBid, mPendingRet);//Auction state
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
	Validator() {
		//! int the execution counter used by validator threads.
		eAUCount = 0;
		
		//! array index location => thread id.
		vTTime   = new float_t[nThread];
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
		ballot->reset();
		
		//! initialization of account with fixed ammount;
		//! mint_val() function is serial.
		int bal = InitBalance;
		for(int sid = 1; sid <= CoinSObj; sid++) 
		{
			//! 5000 is contract deployer.
			bool v = coin->mint(5000, CoinIdStart+sid, bal);
		}

		//! giveRightToVote() function is serial.
		for(int voter = 1; voter <= nVoter; voter++) 
		{
			//! 10000 is chairperson.
			ballot->giveRightToVote(10000, VoterIdStart+voter);
		}

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
		seqTime[2] = 0;
		Timer SeqTimer;
		//! start timer to get time taken by this thread.
		auto start = SeqTimer._timeStart();
			seqBinExe();
		seqTime[2] = SeqTimer._timeStop( start );



		//! print the final state of the shared objects by validator.
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

		//!statrt clock to get time taken by this thread.
		auto start = Ttimer._timeStart();
		int curInd = eAUCount++;
		while( curInd< concBin.size() )
		{
			//! get the AU to execute, which is of string type.
			istringstream ss(concBin[curInd]);
			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("bid") == 0)
			{
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid(payable, bID, bAmt);
			}
			if(tmp.compare("withdraw") == 0)
			{
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw(bID);
			}
			if(tmp.compare("auction_end") == 0)
			{
				int v = auction->auction_end( );
			}
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
			//		cout<<"\nConcBin:Sender don't have sufficent balance to send.\n";
			}
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote(vID, PID);
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
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
			if(tmp.compare("bid") == 0)
			{
				ss >> tmp;
				int payable = stoi(tmp);//! payable
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				ss >> tmp;
				int bAmt = stoi(tmp);//! Bidder value
				int v = auction->bid(payable, bID, bAmt);
			}
			if(tmp.compare("withdraw") == 0)
			{
				ss >> tmp;
				int bID = stoi(tmp);//! Bidder ID
				int v = auction->withdraw(bID);
			}
			if(tmp.compare("auction_end") == 0)
			{
				int v = auction->auction_end( );
			}
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
			//		cout<<"\nConcBin:Sender don't have sufficent balance to send.\n";
			}
			if(tmp.compare("vote") == 0) {
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int PID = -pID; 
				int v = ballot->vote(vID, PID);
			}
			if(tmp.compare("delegate") == 0) {
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
			}
			count++;
		}
	}

	//!-------------------------------
	//!FINAL STATE OF ALL THE SHARED |
	//!OBJECT. Once all AUs executed.|
	//!-------------------------------
	void finalState()
	{
		//coin state
		for(int sid = 1; sid <= CoinSObj; sid++) {
			int bal = 0;
			bool v  = coin->get_bal(CoinIdStart+sid, &bal);
			vCoinState[sid] = bal;
		}

		for(int id = 1; id <= nVoter; id++) 
			ballot->state(VoterIdStart+id, true, vBallotVotState);

		for(int id = 1; id <= nProposal; id++) 
			ballot->state(id, false, vBallotProState);//for Proposal state
		
		auction->state(&vHBidder, &vHBid, vPendingRet); //auction state
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


	mCoinState[s_id-CoinIdStart]  = 1000;
	mCoinState[r_id-CoinIdStart]  = 1000;
	mCoinState[r_id1-CoinIdStart] = 1000;

	amtAB = 950;
	trns1 = to_string(AU_ID1)+" send "+to_string(s_id)+" "
			+to_string(r_id)+" "+to_string(amtAB);

	listAUs[AU_ID1-1] =  trns1;
	
	amtAC = 100;
	trns2 = to_string(AU_ID2)+" send "+to_string(s_id)+" "
			+to_string(r_id1)+" "+to_string(amtAC);

	listAUs[AU_ID2-1] =  trns2;

	mCoinState[s_id-CoinIdStart]  -= amtAB;
	mCoinState[r_id-CoinIdStart]  += amtAB;
	mCoinState[r_id1-CoinIdStart] += amtAC;
	
	//! add the confliciting AUs in conc bin and remove them from seq bin. Add
	//! one of the AU from seq bin to conc Bin and remove that AU from seq bin.
	auto it = concBin.begin();
	concBin.erase(it);
	concBin.insert(concBin.begin(), trns1);
	concBin.insert(concBin.begin()+1, trns2);
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
	bool flag = false;
//	cout<<"\n"<<pl<<"Object \tMiner \t\tValidator"<<endl;
	for(int sid = 1; sid <= CoinSObj; sid++) {
//		cout<<sid<<" \t \t"<<mCoinState[sid]
//			<<" \t\t"<<vCoinState[sid]<<endl;
		if(mCoinState[sid] != vCoinState[sid]) flag = true;
	}
//	cout<<"\n"<<pl<<"Prop ID \tMiner \t\tValidator"<<endl;
	for(int pid = 0; pid < nProposal; pid++) {
//		cout<<pid+1<<" \t \t"<<mBallotProState[pid]
//			<<" \t\t"<<vBallotProState[pid]<<endl;
		if(mBallotProState[pid] != vBallotProState[pid]) flag = true;
	}
//	cout<<"\n"<<pl<<"Voter ID \tMiner \t\tValidator"<<endl;
	for(int vid = 0; vid < nVoter; vid++) {
//		cout<<vid+1<<" \t \t"<<mBallotVotState[vid]
//			<<" \t\t"<<vBallotVotState[vid]<<endl;
		if(mBallotVotState[vid] != vBallotVotState[vid]) flag = true;
	}
	
	if(mHBidder != vHBidder || mHBid != vHBid) flag = true;
//	cout<<pl<<"     Miner Auction Winer "+to_string(mHBidder)
//			+" |  Amount "+to_string(mHBid);
//	cout<<"\n Validator Auction Winer "+to_string(vHBidder)
//			+" |  Amount "+to_string(vHBid);
//	cout<<"\n"<<pl;
	return flag;
}



/*************************Main Fun code begins*********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!   main() !!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"Bin Based Static Miner and Decentralized Validator\n";
	cout<<"-----------------------------\n";

	//! list holds the avg time taken by miner and validator
	//!  threads for multiple consecutive runs of the algorithm.
	list<double>mItrT;         
	list<double>vItrT;	
	int totalDepInG  = 0; //to get total number of dependencies in graph;
	int totalRejCont = 0; //number of validator rejected the blocks;
	int maxAccepted  = 0;
	int totalRun     = NumBlock; //at least 2
	FILEOPR file_opr;
	
	//! read from input file::
	int input[8] = {0};
	file_opr.getInp(input);
	nThread   = input[0]; // # of threads; should be one for serial;
	numAUs    = input[1]; // # of AUs or Transactions;
	CoinSObj  = input[2]; // # Coin Account Shared Object.
	nProposal = input[3]; // # Ballot Proposal Shared Object.
	nVoter    = input[4]; // # Ballot Voter Shared Object.
	nBidder   = input[5]; // # Auction Bidder Shared Object.
	bidEndT   = input[6]; // # Auction Bid End Time.
	lemda     = input[7];

	if(CoinSObj > maxCoinAObj) {
		CoinSObj = maxCoinAObj;
		cout<<"Max number of Coin Shared Object can be "<<maxCoinAObj<<"\n";
	}
	if(nProposal > maxPropObj) {
		nProposal = maxPropObj;
		cout<<"Max number of Proposal Shared Object can be "<<maxPropObj<<"\n";
	}	
	if(nVoter > maxVoterObj) {
		nVoter = maxVoterObj;
		cout<<"Max number of Voter Shared Object can be "<<maxVoterObj<<"\n";
	}
	if(nBidder > maxBidrObj) {
		nBidder = maxBidrObj;
		cout<<"Max number of Bid Shared Object can be "<<maxBidrObj<<"\n";
	}
	if(bidEndT > maxbEndT) {
		bidEndT = maxbEndT;
		cout<<"Max Bid End Time can be "<<maxbEndT<<"\n";
	}

	//used for state validation
	mCoinState      = new int [CoinSObj];
	vCoinState      = new int [CoinSObj];
	mBallotProState = new int [nProposal];
	vBallotProState = new int [nProposal];
	mBallotVotState = new int [nVoter];
	vBallotVotState = new int [nVoter];
	mPendingRet     = new int [nBidder+1];
	vPendingRet     = new int [nBidder+1];
	
	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		
 		//! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(input, CFCount, BFCount, AFConut, listAUs);

		//MINER
		Miner *miner = new Miner(0);
		miner ->mainMiner();

		if(lemda != 0) bool rv = addMFS(NumOfDoubleSTx);
//		printBins();

		//VALIDATOR
		if(MValidation == true)
		{
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++)
			{
				for(int p = 0; p < nProposal; p++)vBallotProState[p]= 0;
				for(int v = 0; v < nVoter; v++)   vBallotVotState[v]= 0;
				for(int c = 0; c < CoinSObj; c++) vCoinState[c]     = 0;

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
		}
		else
		{
			Validator *validator = new Validator();
			validator ->mainValidator();

			//State Validation
			bool flag = stateVal();
			if(flag == true) cout<<"\nBlock Rejected by Validator";
		}
		
		//! total valid AUs among List-AUs executed 
		//! by Miner & varified by Validator.
		int vAUs =  seqBin.size() + concBin.size();
		if(numItr > 0)
			file_opr.writeOpt(nThread, numAUs, tTime, mTTime,
			                  vTTime, aCount, vAUs, mItrT, vItrT);

//		for(int pid = 0; pid < nProposal; pid++) mBallotProState[pid] = 0;
//		for(int vid = 0; vid < nVoter; vid++)    mBallotVotState[vid] = 0;
//		for(int cid = 0; cid < CoinSObj; cid++)  mCoinState[cid]      = 0;
		ccSet.clear();
		concBin.clear();
		seqBin.clear();
		listAUs.clear();
		delete miner;
		miner = NULL;
	}
	//! to get total avg miner and validator
	//! time after number of totalRun runs.
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
/*************************Main Fun code ends***********************************/
