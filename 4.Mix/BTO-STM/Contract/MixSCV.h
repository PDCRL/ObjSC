#pragma once
#include <chrono>
#define CIDStart 5000  //Coin shared objects ids from 5000-10000.
#define BIDStart 10000 //Ballot contract shared objects ids from 10000 onwords.

#include "stmBTO-lib/stm_BTO.cpp"
using namespace std;

voidVal* structVal = new voidVal( sizeof(int) );
LinkedHashNode* tb = new LinkedHashNode(0, 0, structVal);
BTO* lib           = new BTO(tb);//! using OSTM library.


class SimpleAuction
{
	public:
		// Parameters of the auction. Times are either absolute unix time-
		// -stamps (seconds since 1970-01-01) or time periods in seconds.
		std::chrono::time_point<std::chrono::system_clock> now, start;

		// beneficiary of the auction.
		int beneficiary;
		int beneficiaryAmount = 0;

		std::atomic<int> maxBiderID;
		std::atomic<int> auctionEnd;

		// Current state of the auction (USED BY VALIDATOR).
		std::atomic<int> highestBidder;
		int rCountHBidder = 0;
		int wCountHBidder = 0;

		std::atomic<int> highestBid;
		int rCountHBid    = 0;
		int wCountHBid    = 0;

		struct PendReturn
		{
			int ID;
			int value;
			int rCount;   //increase count by tx that is reading dataitem.
			int wCount;   //increase count by tx that is writing to dataitem.
		};
		// Allowed withdrawals of previous bids.
		// mapping(address => uint) pendingReturns;
		list<PendReturn>pendingReturns;

		// Set to true at the end, disallows any change (USED BY VALIDATOR).
		std::atomic<bool> ended;

		// The following is a so-called natspec comment,recognizable by the 3
		// slashes. It will be shown when the user is asked to confirm a trans.
		/// Create a simple auction with \`_biddingTime`\, seconds bidding
		/// time on behalf of the beneficiary address \`_beneficiary`\.

		// CONSTRUCTOR.
		SimpleAuction(int _biddingTime, int _beneficiary, int numBidder)
		{
			maxBiderID = numBidder;

			//! USED BY VALIDATOR ONLY.
			beneficiary   = _beneficiary;
			highestBidder = 0;
			highestBid    = 0;
			ended         = false;

			list<int> conf_list;
			trans_log* txlog;
			STATUS ops, txs;
			txlog = lib->begin();

			//! \'end'\ in STM memory, USED BY MINERS.
			lib->t_write(txlog, 0, maxBiderID+1, 0, tb);//end

			//! \'highestBidder'\ in STM memory, USED BY MINERS.
			lib->t_write(txlog, 0, maxBiderID+2, 0, tb);//highestBidder

			//! \'highestBid'\ in STM memory, USED BY MINERS.
			lib->t_write(txlog, 0, maxBiderID+3, 0, tb);//highestBid

			for(int b = 1; b <= numBidder; b++)
			{
				//! USED BY VALIDATORS.
				PendReturn pret;
				pret.ID       = b;
				pret.value    = 0;
				pret.rCount   = 0;
				pret.wCount   = 0;
				pendingReturns.push_back(pret);

				//! initilize bidder pendingReturns[] value = 0 in STM Memory;
				//! \'pendingReturns[]'\ memory in STM memory, USED BY MINERS.
				lib->t_write(txlog, 0, b, 0, tb);//highestBid
			}

			txs = lib->bto_TryComit(txlog, conf_list, tb);
			if(ABORT == txs) cout<<"\nError!!Failed to create Shared Object\n";

			start = std::chrono::system_clock::now();
//			cout<<"AUCTION [Start Time = "<<0;
			auctionEnd = _biddingTime;
//			cout<<"] [End Time = "<<auctionEnd<<"] milliseconds";
		};


		/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
		/*!   FUNCTION FOR VALIDATOR   !*/
		/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
		// Bid on the auction with the value sent together with transaction.
		// The value will only be refunded if the auction is not won.
		int bid( int payable, int bidderID, int bidValue );

		// Withdraw a bid that was overbid.
		int withdraw(int bidderID);

		// End the auction and send the highest bid to the beneficiary.
		bool auction_end();
		void AuctionEnded( );
		int send(int bidderID, int amount);
		void reset();
		void state(int *hBidder, int *hBid);

		/*~~~~~~~~~~~~~~~~~~~~~~*/
		/*! FUNCTION FOR MINER.!*/
		/*~~~~~~~~~~~~~~~~~~~~~~*/
		int bid_m( int payable, int bidderID, int bidValue, 
					int *ts, list<int> &cList);
		int withdraw_m(int bidderID, int *ts, list<int> &cList);
		int auction_end_m(int *ts, list<int> &cList);
		bool AuctionEnded_m( );
		int send_m(int bidderID, int amount);
		void state_m(int *hBidder, int *hBid);

	~SimpleAuction() { };//destructor
};



class Coin
{
	private:
		struct accNode
		{
			int ID;
			int bal;
		};

		struct accNodeV
		{
			int ID;
			int bal;
			pthread_mutex_t accLock;// lock with each account id used at validator.
			int rCount;//increase count by tx that is reading dataitem.
			int wCount;//increase count by tx that is writing to dataitem.
		};
		list<accNodeV>listAccount;
		std::atomic<int> minter;         //! contract creator

	public:
		Coin(int m, int minter_id)       //! constructor
		{
			minter = minter_id;          //! minter is contract creator

			voidVal* structVal = new voidVal( sizeof(accNode) );
			LinkedHashNode* tb = new LinkedHashNode(0, 0, structVal);
			list<int> conf_list;
			trans_log* txlog;
			STATUS ops, txs;
			txlog = lib->begin();

			for(int i = CIDStart+1; i <= CIDStart+m; i++)
			{
				accNodeV acc;
				acc.ID  	= i-CIDStart;
				acc.bal 	= 0;
				acc.rCount  = 0;
				acc.wCount  = 0;
				acc.accLock = PTHREAD_MUTEX_INITIALIZER;//initialize the lock with each account id.
				listAccount.push_back(acc);

				(*(accNode*)tb->val).ID  = i;
				(*(accNode*)tb->val).bal = 0;
				lib->t_write(txlog, 0, i, 0, tb);
			}
			txs = lib->bto_TryComit(txlog, conf_list, tb);
			if(ABORT == txs)
				cout<<"\nError!!Failed to create Shared Object\n";
		};

		/*!!! STANDERED COIN CONTRACT FUNCTION FROM 
		SOLIDITY CONVERTED IN C++ USED BY validator !!!*/

		 //! serial function1 for validator.
		bool mint(int t_ID, int receiver_iD, int amount);
		//! concurrent function1 for validator.
		int send(int sender_iD, int receiver_iD, int amount);
		//! concurrent function2 for validator.
		int get_bal(int account_iD, int *bal);
		//! used for malicious miner.
		void reset();

		/*!!! CONTRACT with 3 functions for miner
		return TRUE/1 if Try_Commit SUCCESS !!!*/
		bool mint_m(int t_ID, int receiver_iD, int amount, int *time_stamp);
		int send_m(int t_ID, int sender_iD, int receiver_iD, 
						int amount, int *time_stamp, list<int>&conf_list);
		bool get_bal_m(int account_iD, int *bal, int t_ID,
							int *time_stamp, list<int>&conf_list);

		~Coin() { };//destructor
};


class Ballot
{
	public:
		std::atomic<int> numPropsals;
		std::atomic<int> numVoters;
		std::atomic<int> chairperson;

		struct Voter
		{
			int ID;
			int weight;  // weight is accumulated by delegation
			bool voted;  // if true, that person already voted
			int delegate;// person delegated to
			int vote;    // index of the voted proposal
		};
		struct Proposal
		{
			int ID;
			string *name; //! short name (<=32 bytes) data type.
			int voteCount;//! number of accumulated votes
		};



		struct VoterV
		{
			int ID;
			int weight;  // weight is accumulated by delegation
			bool voted;  // if true, that person already voted
			int delegate;// person delegated to
			int vote;    // index of the voted proposal
			int rCount;  //increase count by tx that is reading dataitem.
			int wCount;  //increase count by tx that is writing to dataitem.
			pthread_mutex_t accLock;// lock with each account id used at validator.
		};
		//! this is voter shared object used by validator.
		list<VoterV>voters;


		struct ProposalV
		{
			int ID;
			string *name; //! short name (<=32 bytes) data type.
			int voteCount;//! number of accumulated votes
			int rCount;   //increase count by tx that is reading dataitem.
			int wCount;   //increase count by tx that is writing to dataitem.
			pthread_mutex_t accLock;// lock with each account id used at validator.
		};
		list<ProposalV>proposals;

		

		//! constructor:: create a new ballot to choose one of `proposalNames`.
		Ballot(string proposalNames[], int sender, int numVoter, int nPropsal)
		{
			numPropsals = nPropsal;
			numVoters   = numVoter;
			//! sender is chairperson of the contract
			chairperson = sender;


			voidVal* structValp   = new voidVal( sizeof(Proposal) );
			voidVal* structValV   = new voidVal( sizeof(Voter) );
			LinkedHashNode* pObj  = new LinkedHashNode(0, 0, structValp);
			LinkedHashNode* vObj  = new LinkedHashNode(0, 0, structValV);


			// This declares a state variable that stores a
			// \`Voter\` struct for each possible address.
			// mapping(address => Voter) public voters;
			for(int v = BIDStart; v <= BIDStart+numVoters; v++)
			{
				list<int> conf_list;
				trans_log* txlog;
				STATUS txs;
				txlog = lib->begin();

				(*(Voter*)vObj->val).ID = v;
				//if senderid is chairperson
				if( v == chairperson) (*(Voter*)vObj->val).weight = 1;
				else
				{
					//! '0' indicates that doesn't have right to vote
					//! 'false' indicates that it hasn't vote yet.
					//! denotes to whom voter is going select to vote on
					//! behalf of this voter && '0' indicates that it 
					//! hasn't delegate yet.
					(*(Voter*)vObj->val).weight   = 0;
					(*(Voter*)vObj->val).voted    = false;
					(*(Voter*)vObj->val).delegate = 0;
					(*(Voter*)vObj->val).vote     = 0; 
				}
				lib->t_write(txlog, 0, v, 0, vObj);
				txs = lib->bto_TryComit(txlog, conf_list, vObj);
				if(ABORT == txs)
					cout<<"\nError!!Failed to create Shared Voter Object\n";

				//! Initializing shared objects used by validator.
				VoterV votr;
				votr.ID       = v-BIDStart;
				votr.voted    = false;
				votr.delegate = 0;
				votr.vote     = 0;
				votr.rCount   = 0;
				votr.wCount   = 0;
				votr.accLock  = PTHREAD_MUTEX_INITIALIZER;//initialize the lock with each account id.

				if(v == chairperson) votr.weight = 1; //if sender is chairperson
				voters.push_back(votr);
			}

			// A dynamically-sized array of \`Proposal\` structs.
			/*! Proposal[] public proposals;*/
			// \`Proposal({...})\` creates a temporary
			// Proposal object and \`proposals.push(...)\`
			// appends it to the end of \`proposals\`.
			//! For each of the provided proposal names,
			//! create, initilize and add new proposal 
			//! shared object to STM shared memory.
			for(int p = BIDStart+numVoters+1; p <= (BIDStart+numVoters+numPropsals); p++)
			{
				list<int> conf_list;
				trans_log* txlog;
				STATUS txs;
				txlog = lib->begin();

				(*(Proposal*)pObj->val).ID        = p;
				(*(Proposal*)pObj->val).name      = &proposalNames[p-(BIDStart+numVoters+1)];
				(*(Proposal*)pObj->val).voteCount = 0; //! Denotes voteCount of candidate.

				lib->t_write(txlog, 0, p, 0, pObj);
				txs = lib->bto_TryComit(txlog, conf_list, pObj);
				if(ABORT == txs) cout<<"\nError!!Failed to create Shared Proposal Object\n";

				//! Initializing Proposals used by validator.
//				cout<<"P = "<<p<<" p-(BIDStart+numVoters+1) = "<<p-(BIDStart+numVoters)<<"\n";
				ProposalV prop;
				prop.ID        = p-(BIDStart+numVoters);
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-(BIDStart+numVoters+1)];
				prop.rCount    = 0;
				prop.wCount    = 0;
				prop.accLock   = PTHREAD_MUTEX_INITIALIZER;//initialize the lock with each account id.
				proposals.push_back(prop);
			}
		};

	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	//! fun called by the validator threads.
	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	// Give \`voter\` the right to vote on this ballot.
	// May only be called by \`chairperson\`.
	int giveRightToVote(int senderID, int voter);

	// Delegate your vote to the voter \`to\`.
	int delegate(int senderID, int to);

	// Give your vote (including votes delegated to you)
	// to proposal \`proposals[proposal].name\`.
	int vote(int senderID, int proposal);

	// @dev Computes the winning proposal taking all
	// previous votes into account.
	int winningProposal( );

	// Calls winningProposal() function to get the 
	// index of the winner contained in the proposals
	// array and then returns the name of the winner.
	void winnerName(string *winnerName);

	void state(int ID, bool sFlag, int *ValidatorState);
	void reset();

	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	//! fun called by the miner threads.
	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	int giveRightToVote_m(int senderID, int voter);
	int delegate_m(int senderID, int to, int *ts, list<int>&cList);
	int vote_m( int senderID, int proposal, int *ts, list<int>&cList);
	int winningProposal_m( );
	void winnerName_m(string *winnerName);
	void state_m(int ID, bool sFlag, int *MinerState);

	~Ballot(){ };//destructor
};
