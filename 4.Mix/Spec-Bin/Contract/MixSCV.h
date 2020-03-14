#pragma once
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <list>
#include <sys/time.h>
#include <shared_mutex>

#define CoinIdStart 5000
#define VoterIdStart 10000 //Proposal Id is -Ve in I/P file
#define AuctionIdStart 1

using namespace std;



class SimpleAuction
{
	public:
		// Parameters of the auction. Times are either absolute unix time-
		// -stamps (seconds since 1970-01-01) or time periods in seconds.
		std::chrono::time_point<std::chrono::system_clock> now, start;

		int nBidder;
		// beneficiary of the auction.
		int beneficiary;
		int beneficiaryAmount = 0;
		std::atomic<int> auctionEnd;
		// Current state of the auction.
		std::atomic<int> highestBidder;
		std::atomic<int> highestBid;
		struct PendReturn {
			int ID;
			int value;
		};
		// Allowed withdrawals of previous bids.
		list<PendReturn>pendingReturns;
		list<PendReturn>pendingReturnsM;

		std::shared_mutex tLock[5000];
		// Set to true at the end, disallows any change.
		std::atomic<bool> ended;
		SimpleAuction( int _biddingTime, int _beneficiary, int numBidder) {
			nBidder        = numBidder;
			beneficiary    = _beneficiary;
			highestBidder  = 0;
			highestBid     = 0;
			ended          = false;
			for(int b = 0; b <= numBidder; b++) {
				PendReturn pret;
				pret.ID    = b;
				pret.value = 0;
				pendingReturns.push_back(pret);
				pendingReturnsM.push_back(pret);
			}
			start = std::chrono::system_clock::now();
			auctionEnd = _biddingTime;
		};



		//! STANDERED COIN CONTRACT FROM SOLIDITY CONVERTED IN C++ for validator
		// Bid on the auction with the value sent together with transaction.
		// The value will only be refunded if the auction is not won.
		bool bid( int payable, int bidderID, int bidValue );
		bool withdraw(int bidderID);// Withdraw a bid that was overbid.
		// End the auction and send the highest bid to the beneficiary.
		bool auction_end();
		void AuctionEnded( );
		int send(int bidderID, int amount);
		void reset(int _biddingTime);
		void state(int *hBidder, int *hBid, int *vPendingRet);
		
		
		//! CONTRACT miner functions return TRUE/1 if Try_Commit returns true
		int bid_m( int payable, int bidderID, int bidValue, bool binFlag);
		int withdraw_m(int bidderID, bool binFlag);// Withdraw a bid that was overbid.
		void state_m(int *hBidder, int *hBid, int *mPendingRet);
		bool auction_end_m();
		void allUnlock();

		~SimpleAuction() { };//destructor
};


class Coin
{
	private:
		struct accNode {
			int ID;
			int bal;
			int rCount;//increase count by transaction that is reading dataitem.
			int wCount;//increase count by transaction that is writing to dataitem.
			pthread_mutex_t accLock;// lock with each account id used at validator.
		};
		list<accNode>listAccount;
		list<accNode>listAccountMiner;
		std::atomic<bool> useCounter;
		std::shared_mutex tLock[5000];
		std::atomic<int> minter; //! contract creator

	public:
		Coin(int m, int minter_id) //! constructor (m: num of sharedObj)
		{
			minter  = minter_id;   //! minter is contract creator
			for(int i = 1; i <= m; i++) {
				accNode acc;
				acc.ID      = CoinIdStart+i;
				acc.bal     = 0;
				acc.rCount  = 0;
				acc.wCount  = 0;
				acc.accLock = PTHREAD_MUTEX_INITIALIZER;//initialize the lock with each account id.
				listAccount.push_back(acc);
				listAccountMiner.push_back(acc);
			}
		};

		void reset();
		void setCounterFlag(bool cFlag);

		//! STANDERED COIN CONTRACT FROM SOLIDITY CONVERTED IN C++ for validator
		bool mint(int t_ID, int receiver_iD, int amount);
		int send(int sender_iD, int receiver_iD, int amount);
		int get_bal(int account_iD, int *bal);


		//! CONTRACT miner functions return TRUE/1 if Try_Commit returns true
		bool mint_m(int t_ID, int receiver_iD, int amount);
		int send_m(int t_ID,int sender_iD,int receiver_iD,int amount,bool binFlag);
		int get_bal_m(int account_iD, int *bal, int t_ID, bool binFlag);
		void allUnlock();

		~Coin() { };
};

class Ballot
{

	public:
		int numProposal;
		std::atomic<int> numPropsals;
		std::atomic<int> numVoters;

		struct Voter {
			int ID;
			int weight;  // weight is accumulated by delegation
			bool voted;  // if true, that person already voted
			int delegate;// person delegated to
			int vote;    // index of the voted proposal
		};
		//! this is voter shared object used by validator.
		list<Voter>voters;
		list<Voter>votersM;
		
		struct Proposal {
			int ID;
			string *name;
			int voteCount;//! number of accumulated votes
		};
		list<Proposal>proposals;
		list<Proposal>proposalsM;

		std::atomic<int> chairperson;
		std::shared_mutex ptLock[1001];  //Proposal Try Locks
		std::shared_mutex vtLock[40001]; //Voters Try Locks

		//! constructor:: create a new ballot to choose one of `proposalNames`.
		Ballot(string proposalNames[], int sender, int numVoter, int nPropsal)
		{
			numProposal = nPropsal;
			numPropsals = nPropsal;
			numVoters   = numVoter;

			//! sid is chairperson of the contract
			chairperson = sender;

			// This declares a state variable that
			// stores a \`Voter\` struct for each possible address.
			// mapping(address => Voter) public voters;
			for(int v = 0; v <= numVoter; v++) {
				//! Initializing shared objects used by validator.
				Voter votr;
				votr.ID       = VoterIdStart+v;
				votr.voted    = false;
				votr.delegate = 0;
				votr.vote     = 0;
				if(v==chairperson) votr.weight = 1;//if senderid is chairperson;
				voters.push_back(votr);
				votersM.push_back(votr);

			}
		
			// A dynamically-sized array of \`Proposal\` structs.
			/*! Proposal[] public proposals;*/
			// \`Proposal({...})\` creates a temporary
			// Proposal object and \`proposals.push(...)\`
			// appends it to the end of \`proposals\`.
			//! For each of the provided proposal names,
			//! create, initilize and add new proposal 
			//! shared object to STM shared memory.
			for(int p = 0; p <= numProposal; p++) {
				//! Initializing Proposals used by validator.
				Proposal prop;
				prop.ID        = p;
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-1];
				proposals.push_back(prop);
				proposalsM.push_back(prop);
			}
		};

	//! STANDERED CONTRACT FUN FROM SOLIDITY CONVERTED IN C++ for validator.
	void giveRightToVote(int senderID, int voter);
	int delegate(int senderID, int to);
	int vote(int senderID, int proposal);
	int winningProposal( );
	void winnerName(string *winnerName);

	void state(int ID, bool sFlag, int *State);
	void reset();


	//! CONTRACT miner functions return TRUE/1 if Try_Commit returns true
	void giveRightToVote_m(int senderID, int voter);
	int delegate_m(int senderID, int to, bool binFlag);
	int vote_m(int senderID, int proposal, bool binFlag);
	int winningProposal_m( );
	void winnerName_m(string *winnerName);
	void allUnlock();
	void state_m(int ID, bool sFlag, int *State);
	void reset_m();
	~Ballot(){ };//destructor
};

