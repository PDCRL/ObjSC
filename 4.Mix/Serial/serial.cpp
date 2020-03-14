#include <iostream>
#include <thread>
#include <atomic>
#include <list>
#include "Util/Timer.cpp"
#include "Contract/Coin.cpp"
#include "Contract/Ballot.cpp"
#include "Contract/SimpleAuction.cpp"
#include "Util/FILEOPR.cpp"

#define MAX_THREADS 128
#define maxCoinAObj 5000  //maximum coin contract \account\ object.
#define CFCount 3         //# methods in coin contract.

#define maxPropObj 1000   //maximum ballot contract \proposal\ shared object.
#define maxVoterObj 5000  //maximum ballot contract \voter\ shared object.
#define BFCount 5         //# methods in ballot contract.

#define maxBidrObj 5000   //maximum simple auction contract \bidder\ shared object.
#define maxbEndT 6000      //maximum simple auction contract \bidding time out\ duration.
#define AFConut 6         //# methods in simple auction contract.
#define pl "=================================================================\n"
#define MValidation true   //! true or false
#define numValidator 50
#define InitBalance 1000
#define NumBlock 26        //! at least two blocks, the first run is warmup run.



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

double tTime[2];         //! total time taken by miner & validator.
int    *aCount;          //! Invalid transaction count.
float_t*mTTime;          //! time taken by each miner Thread to execute AUs.
float_t*vTTime;          //! time taken by each validator Thread to execute AUs.
vector<string>listAUs;   //! AUs to be executed on contracts: index+1 => AU_ID.
std::atomic<int>currAU;  //! used by miner-thread to get index of AU to execute.
//! CONTRACT OBJECTS;
Coin   *coin;            //! coin contract miner object.
Coin   *coinV;           //! coin contract validator object.
Ballot *ballot;          //! ballot contract for miner object.
Ballot *ballot_v;        //! ballot contract for validator object.
SimpleAuction *auction;  //! simple auction contract for miner object.
SimpleAuction *auctionV; //! simple auction contract for validator object.
string *proposalNames;   //! proposal names for ballot contract.

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


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "1" miner-THREAD                        !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int contDeployer )
	{
		//! initialize the counter.
		currAU = 0;
		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		aCount = new int [nThread];
		for(int i = 0; i < nThread; i++){
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		proposalNames = new string[nProposal+1];
		for(int x = 0; x <= nProposal; x++)
			proposalNames[x] = "X"+to_string(x+1);
		//! id of the contract creater is "minter_id = contDeployer".
		coin = new Coin( CoinSObj, contDeployer );
		//! Id of the contract creater is \chairperson = contDeployer\.
		ballot = new Ballot( proposalNames, contDeployer, nVoter, nProposal);
		//! fixed beneficiary id to 0, it can be any unique address/id.
		auction = new SimpleAuction(bidEndT, 0, nBidder);
	}

	//!--------------------------------------
	//!!!!!!!! MAIN MINER:: CREATE MINER !!!!
	//!--------------------------------------
	void mainMiner()
	{
		Timer lTimer;
		thread T[nThread];
		//! initialization of account with fixed ammount;
		//! mint() function is serial.
		int bal = 1000;
		for(int sid = 1; sid <= CoinSObj; sid++) {
			//! 0 is contract deployer.
			bool v = coin->mint(0, sid, bal);
		}
		
		//! Give \`voter\` the right to vote on this ballot.
		//! giveRightToVote_m() is serial.
		for(int voter = 1; voter <= nVoter; voter++) {
			//! 0 is chairperson.
			ballot->giveRightToVote(0, voter);
		}

		//!---------------------------------------------------------
		//!!!!!!!!!!    CREATE NTHREAD MINER THREADS      !!!!!!!!!!
		//!---------------------------------------------------------
		double start = lTimer.timeReq();
		for(int i = 0; i < nThread; i++) 
			T[i] = thread(concMiner, i, numAUs);
		for(auto& th : T) th.join();
		tTime[0] = lTimer.timeReq() - start;

		//! print the final state of all contract shared objects.
		finalState();
//		string winner;
//		ballot->winnerName(&winner);
//		auction->AuctionEnded( );
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
			if( tmp.compare("get_bal") == 0 )
			{
				ss >> tmp;
				int s_id = stoi(tmp);
				int bal  = 0;
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
			if(tmp.compare("vote") == 0)
			{
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int v = ballot->vote(vID, pID);
				if(v != true) aCount[0]++;
			}
			if(tmp.compare("delegate") == 0)
			{
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot->delegate(sID, rID);
				if(v != true) aCount[0]++;
			}
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
	//!AUs executed. Geting this using get_bel_val()   |
	//!-------------------------------------------------
	void finalState()
	{
		//coin state
		for(int sid = 1; sid <= CoinSObj; sid++) {
			int bal = 0, ts;
			coin->get_bal(sid, &bal);
			mCoinState[sid] = bal;
		}

		for(int id = 1; id <= nVoter; id++) 
			ballot->state(id, true, mBallotVotState);//for voter state

		for(int id = 1; id <= nProposal; id++) 
			ballot->state(id, false, mBallotProState);//for Proposal state

		auction->state(&mHBidder, &mHBid, mPendingRet);//Auction state
	}

	~Miner() { };
};


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "1" validator-THREAD          !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Validator
{
public:

	Validator(int contDeployer)
	{
		//! initialize the counter to 0.
		currAU = 0;
		//! index location represents respective thread id.
		vTTime = new float_t [nThread];
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
		//! id of the contract creater is "minter_id = contDeployer".
		coinV = new Coin( CoinSObj, contDeployer );
		//! Id of the contract creater is \chairperson = contDeployer\.
		ballot_v = new Ballot( proposalNames, contDeployer, nVoter, nProposal);
		auctionV = new SimpleAuction(bidEndT, 0, nBidder);
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
		int bal = 1000;
		for(int sid = 1; sid <= CoinSObj; sid++)  {
			//! 0 is contract deployer.
			bool v = coinV->mint(0, sid, bal);
		}
		
		//! giveRightToVote() function is serial.
		for(int voter = 1; voter <= nVoter; voter++) {
			//! 0 is chairperson.
			ballot_v->giveRightToVote(0, voter);
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
//		string winner;
//		ballot->winnerName(&winner);
//		auctionV->AuctionEnded( );
	}

	//!------------------------------------------------------------
	//! THE FUNCTION TO BE EXECUTED BY ALL THE VALIDATOR THREADS. !
	//!------------------------------------------------------------
	static void concValidator( int t_ID, int numAUs)
	{
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
			ss >> tmp;
			int AU_ID = stoi(tmp);
			ss >> tmp;
			if( tmp.compare("get_bal") == 0 )
			{
				ss >> tmp;
				int s_id = stoi(tmp);
				int bal  = 0;
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
			if(tmp.compare("vote") == 0)
			{
				ss >> tmp;
				int vID = stoi(tmp);//! voter ID
				ss >> tmp;
				int pID = stoi(tmp);//! proposal ID
				int v = ballot_v->vote(vID, pID);
				if(v != 1) aCount[0]++;
			}
			if(tmp.compare("delegate") == 0)
			{
				ss >> tmp;
				int sID = stoi(tmp);//! Sender ID
				ss >> tmp;
				int rID = stoi(tmp);//! Reciver ID
				int v = ballot_v->delegate(sID, rID);
				if(v != 1) aCount[0]++;
			}
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
		vTTime[t_ID] = vTTime[t_ID] + tTimer._timeStop(start);
	}

	//!-------------------------------------------------
	//! FINAL STATE OF ALL THE SHARED OBJECT. ONCE ALL |
	//! AUS EXECUTED. GETING THIS USING get_bel.       |
	//!-------------------------------------------------
	void finalState()
	{
		//coin state
		for(int sid = 1; sid <= CoinSObj; sid++) {
			int bal = 0;
			bool v  = coin->get_bal(sid, &bal);
			vCoinState[sid] = bal;
		}
		
		for(int id = 1; id <= nVoter; id++) 
			ballot->state(id, true, vBallotVotState);

		for(int id = 1; id <= nProposal; id++) 
			ballot->state(id, false, vBallotProState);//for Proposal state
		
		auction->state(&vHBidder, &vHBid, vPendingRet); //auction state
	}

	~Validator() { };
};



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



/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!   main() !!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"Serial Miner and Serial Validator\n";
	cout<<"-----------------------------\n";

	//! list holds the avg time taken by miner and validator
	//!  threads for multiple consecutive runs of the algorithm.
	list<double>mItrT;         
	list<double>vItrT;
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

	//!------------------------------------------------------------------
	//! Num of threads should be 1 for serial so we are fixing it to 1, !
	//! Whatever be # of threads in inputfile, it will be always one.   !
	//!------------------------------------------------------------------
	nThread = 1;

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		 //! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(input, CFCount, BFCount, AFConut, listAUs);

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
				for(int p = 0; p < nProposal; p++)vBallotProState[p]= 0;
				for(int v = 0; v < nVoter; v++)   vBallotVotState[v]= 0;
				for(int c = 0; c < CoinSObj; c++) vCoinState[c]     = 0;
				
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

		//total valid AUs among List-AUs executed by Miner & varified by Validator.
		int vAUs = numAUs;
		if(numItr > 0)
			file_opr.writeOpt(nThread, numAUs, tTime, mTTime,
			                  vTTime, aCount, vAUs, mItrT, vItrT);

//		for(int pid = 0; pid < nProposal; pid++) mBallotProState[pid] = 0;
//		for(int vid = 0; vid < nVoter; vid++)    mBallotVotState[vid] = 0;
//		for(int cid = 0; cid < CoinSObj; cid++)  mCoinState[cid]      = 0;
		listAUs.clear();
		delete miner;
		miner = NULL;
	}
	// to get total avg miner and validator
	// time after number of totalRun runs.
	double tAvgMinerT = 0;
	double tAvgValidT = 0;
	auto mit = mItrT.begin();
	auto vit = vItrT.begin();
	for(int j = 1; j < totalRun; j++)
	{
		tAvgMinerT = tAvgMinerT + *mit;
		tAvgValidT = tAvgValidT + *vit;
		mit++;
		vit++;
	}
	tAvgMinerT = tAvgMinerT/(totalRun-1);
	tAvgValidT = tAvgValidT/(totalRun-1);
	cout<<"\n    Total Avg Miner = "<<tAvgMinerT<<" microseconds";
	cout<<"\nTotal Avg Validator = "<<tAvgValidT<<" microseconds";
	cout<<endl<<"-----------------------------";
	cout<<"\nAvg Number of Validator Accepted the Block = "
		<<(numValidator-(totalRejCont/(totalRun-1)));
	cout<<"\nAvg Number of Validator Rejcted the Block = "
		<<totalRejCont/(totalRun-1);
	cout<<"\nMax Validator Accepted any Block = "<<maxAccepted;
	cout<<"\n"<<endl;
return 0;
}
