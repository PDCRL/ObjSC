#pragma once
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <list>
#include <sys/time.h>


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

		// beneficiary of the auction.
		int beneficiary;
		int beneficiaryAmount = 0;


		std::atomic<int> auctionEnd;
		// Current state of the auction (USED BY VALIDATOR).
		std::atomic<int> highestBidder;
		std::atomic<int> highestBid;

		struct PendReturn
		{
			int ID;
			int value;
		};
		// Allowed withdrawals of previous bids.
		// mapping(address => uint) pendingReturns;
		list<PendReturn>pendingReturns;

		// Set to true at the end, disallows any change (USED BY VALIDATOR).
		std::atomic<bool> ended;

		// The following is a so-called natspec comment,recognizable by the 3
		// slashes. It will be shown when the user is asked to confirm a trans.
		// Create a simple auction with \`_biddingTime`\, seconds bidding
		// time on behalf of the beneficiary address \`_beneficiary`\.


		// CONSTRUCTOR.
		SimpleAuction( int _biddingTime, int _beneficiary, int numBidder)
		{
			beneficiary    = _beneficiary;
			highestBidder  = 0;
			highestBid     = 0;
			ended          = false;

			for(int b = 0; b <= numBidder; b++)
			{
				PendReturn pret;
				pret.ID    = b;
				pret.value = 0;
				pendingReturns.push_back(pret);

			}
			start = std::chrono::system_clock::now();
//			cout<<"AUCTION [Start Time = "<<0;
			auctionEnd = _biddingTime;
//			cout<<"] [End Time = "<<auctionEnd<<"] milliseconds";
		};



		// Bid on the auction with the value sent together with transaction.
		// The value will only be refunded if the auction is not won.
		bool bid( int payable, int bidderID, int bidValue );

		// Withdraw a bid that was overbid.
		bool withdraw(int bidderID);
		
		// End the auction and send the highest bid to the beneficiary.
		bool auction_end();
		void AuctionEnded( );
		int send(int bidderID, int amount);
		void reset(int _biddingTime);
		void state(int *hBidder, int *hBid, int *vPendingRet);

	~SimpleAuction()
	{

	};//destructor
};




class Coin
{
	private:
		struct accNode
		{
			int ID;
			int bal;
		};
		list<accNode>listAccount;
		list<accNode>listAccountMiner;

		std::atomic<int> minter;         //! contract creator

	public:

		Coin(int m, int minter_id)      //! constructor (m: num of sharedObj)
		{
			minter  = minter_id;        //! minter is contract creator

			for(int i = 1; i <= m; i++)
			{
				accNode acc;
				acc.ID  = CoinIdStart+i;
				acc.bal = 0;
				listAccount.push_back(acc);
				listAccountMiner.push_back(acc);
			}
		};


		/*!!! STANDERED COIN CONTRACT FUNCTION FROM SOLIDITY CONVERTED IN C++ USED BY validator !!!*/
		bool mint(int t_ID, int receiver_iD, int amount);     //! serial function1 for validator.
		bool send(int sender_iD, int receiver_iD, int amount);//! concurrent function1 for validator.
		bool get_bal(int account_iD, int *bal);               //! concurrent function2 for validator.

		~Coin()
		{

		};//destructor
};




class Ballot
{

	public:
		int numProposal;
		std::atomic<int> numPropsals;
		std::atomic<int> numVoters;

		struct Voter
		{
			int ID;
			int weight;  // weight is accumulated by delegation
			bool voted;  // if true, that person already voted
			int delegate;// person delegated to
			int vote;    // index of the voted proposal
		};

		//! this is voter shared object used by validator.
		list<Voter>voters;

		//! This is a type for a single proposal.
		struct Proposal
		{
			int ID;
			//! short name (<=32 bytes) data
			//! type only avail in solidity.
			string *name;
			//! number of accumulated votes
			int voteCount;
		};

		list<Proposal>proposals;

		std::atomic<int> chairperson;


		//! constructor:: create a new ballot to choose one of `proposalNames`.
		Ballot(string proposalNames[], int sender, int numVoter, int nPropsal)
		{
			numProposal = nPropsal;
			numPropsals = nPropsal;
			numVoters   = numVoter;
//			cout<<"\n==================================";
//			cout<<"\n     Number of Proposal = "<<numProposal;
//			cout<<"\n==================================\n";

			//! sid is chairperson of the contract
			chairperson = sender;

			// This declares a state variable that
			// stores a \`Voter\` struct for each possible address.
			// mapping(address => Voter) public voters;
			for(int v = 0; v <= numVoter; v++)
			{
				//! Initializing shared objects used by validator.
				Voter votr;
				votr.ID       = VoterIdStart+v;
				votr.voted    = false;
				votr.delegate = 0;
				votr.vote     = 0;
				if(v == chairperson) votr.weight = 1; //if senderid is chairperson;
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
			
			for(int p = 0; p <= numProposal; p++)
			{
				//! Initializing Proposals used by validator.
				Proposal prop;
				prop.ID        = p;
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-1];
				proposals.push_back(prop);		
			}
		};

		//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		//! fun called by the validator threads.
		//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		// Give \`voter\` the right to vote on this ballot.
		// May only be called by \`chairperson\`.
		void giveRightToVote(int senderID, int voter);
	
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

	~Ballot(){ };//destructor
};
