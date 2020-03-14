#pragma once
#include "stmBTO-lib/stm_BTO.cpp"

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


		std::atomic<int> chairperson;

		voidVal* structVal = new voidVal( sizeof(Voter) );
		LinkedHashNode* tb = new LinkedHashNode(0, 0, structVal);
		BTO* lib           = new BTO(tb);

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
				LinkedHashNode* vObj = new LinkedHashNode(0, 0, structVal);
				list<int> conf_list;
				trans_log* txlog;
				STATUS ops, txs;
				txlog = lib->begin();
				
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

				ops = lib->t_write(txlog, 0, v, 0, vObj);
				if(ABORT != ops) txs = lib->bto_TryComit(txlog, conf_list, vObj);
				if(ABORT == txs) cout<<"\nError!!Failed to create Shared Voter Object\n";
				
				//! Initializing shared objects used by validator.
				VoterV votr;
				votr.ID       = v;
				votr.voted    = false;
				votr.delegate = 0;
				votr.vote     = 0;
				votr.rCount   = 0;
				votr.wCount   = 0;
				votr.accLock = PTHREAD_MUTEX_INITIALIZER;//initialize the lock with each account id.

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
			
			for(int p = numVoter+1; p <= (numVoter+numProposal); p++)
			{	
				voidVal* structVal   = new voidVal( sizeof(Proposal) );
				LinkedHashNode* pObj = new LinkedHashNode(0, 0, structVal);

				/*! proposals.push(Proposal({name: propName[i], voteCount: 0}));*/
				list<int> conf_list;
				trans_log* txlog;
				STATUS ops, txs;
				txlog = lib->begin();
				
				(*(Proposal*)pObj->val).ID = p;
				
				(*(Proposal *)pObj->val).name      = &proposalNames[p-(numVoter+1)];
				(*(Proposal *)pObj->val).voteCount = 0;	//! Denotes voteCount of candidate.
				
				ops = lib->t_write(txlog, 0, p, 0, pObj);

				if(ABORT != ops) txs = lib->bto_TryComit(txlog, conf_list, pObj);

				if(ABORT == txs) cout<<"\nError!!Failed to create Shared Voter Object\n";

//				cout<<"Proposal ID \t= "<<p-numVoter<<endl;
//				cout<<"Name \t\t= " <<*(*(Proposal *)pObj->val).name<<endl;
//				cout<<"Vote Count \t= "<<(*(Proposal *)pObj->val).voteCount;
//				cout<<"\n==========================\n";
				
				//! Initializing Proposals used by validator.
				ProposalV prop;
				prop.ID        = p-numVoter;
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-(numVoter+1)];
				prop.rCount    = 0;
				prop.wCount    = 0;
				prop.accLock = PTHREAD_MUTEX_INITIALIZER;//initialize the lock with each account id.
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
