#pragma once
#include "mvtoSTM-lib/MVTO.cpp"

using namespace std;

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

		voidVal* tb  = new voidVal( sizeof(Voter) );
		MVTO* lib    = new MVTO(tb);

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
				votr.ID       = v;
				votr.voted    = false;
				votr.delegate = 0;
				votr.vote     = 0;
				if(v == chairperson)
				{
					votr.weight = 1; //if senderid is chairperson;
				}
				voters.push_back(votr);

				voidVal* vObj = new voidVal( sizeof(Voter) );
				list<int> conf_list;
				L_txlog* txlog;
				OPN_STATUS ops, txs;
				txlog = lib->begin();

				(*(Voter*)vObj->val)    = votr;
				(*(Voter*)vObj->val).ID = v;

				if(v == chairperson)
				{
					(*(Voter*)vObj->val).weight   = 1; //if senderid is chairperson
				}
				else
				{
					(*(Voter*)vObj->val).weight   = 0;      //! '0' indicates that it doesn't have right to vote
					(*(Voter*)vObj->val).voted    = false;  //! 'false' indicates that it hasn't vote yet
					(*(Voter*)vObj->val).delegate = 0;      //! denotes to whom voter is going select to vote on behalf of this voter && '0' indicates that it hasn't delegate yet
					(*(Voter*)vObj->val).vote     = 0; 
				}

				ops = lib->tx_write(txlog, v, 0, vObj);

				if(ABORT != ops) txs = lib->tryCommit(txlog, conf_list, vObj);

				if(ABORT == txs) cout<<"\nError!!Failed to create Shared Voter Object\n";
			}
		
			// A dynamically-sized array of \`Proposal\` structs.
			/*! Proposal[] public proposals;*/
			
			// \`Proposal({...})\` creates a temporary
			// Proposal object and \`proposals.push(...)\`
			// appends it to the end of \`proposals\`.
			//! For each of the provided proposal names,
			//! create, initilize and add new proposal 
			//! shared object to STM shared memory.
			
			for(int p = numVoter+1; p <= (numVoter+numProposal); p++)
			{
				//! Initializing Proposals used by validator.
				Proposal prop;
				prop.ID        = p-numVoter;
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-(numVoter+1)];
				proposals.push_back(prop);
				
				voidVal* pObj = new voidVal( sizeof(Proposal) );
				list<int> conf_list;
				L_txlog* txlog;
				OPN_STATUS ops, txs;
				txlog = lib->begin();
				
				(*(Proposal*)pObj->val) = prop;

				(*(Proposal*)pObj->val).ID        = p;
				(*(Proposal*)pObj->val).name      = &proposalNames[p-(numVoter+1)];
				(*(Proposal*)pObj->val).voteCount = 0;	//! Denotes voteCount of candidate.

				ops = lib->tx_write(txlog, p, 0, pObj);

				if(ABORT != ops) txs = lib->tryCommit(txlog, conf_list, pObj);

				if(ABORT == txs) cout<<"\nError!!Failed to create Shared Voter Object\n";

//				cout<<"Proposal ID \t= "<<p-numVoter<<endl;
//				cout<<"Name \t\t= " <<*(*(Proposal *)pObj->val).name<<endl;
//				cout<<"Vote Count \t= "<<(*(Proposal *)pObj->val).voteCount;
//				cout<<"\n==========================\n";
				
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
	
	void state(int ID, bool sFlag);
	
	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	//! fun called by the miner threads.
	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	int giveRightToVote_m(int senderID, int voter);
	int delegate_m(int senderID, int to, int *ts, list<int>&cList);
	int vote_m( int senderID, int proposal, int *ts, list<int>&cList);
	int winningProposal_m( );
	void winnerName_m(string *winnerName);
	void state_m(int ID, bool sFlag);
	~Ballot(){ };//destructor
};
