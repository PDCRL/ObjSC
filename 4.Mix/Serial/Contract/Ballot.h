#pragma once

using namespace std;
class Ballot
{

public:
		int numProposal;

		struct Voter
		{
			int ID;
			int weight;  // weight is accumulated by delegation
			bool voted;  // if true, that person already voted
			int delegate;// person delegated to
			int vote;    // index of the voted proposal
		};
		
		list<Voter>voters;//! list of voters.
		
///		This is a type for a single proposal.
		struct Proposal
		{
			int ID;
			string *name;   //! short name (<=32 bytes) data type only avail in solidity
			int voteCount; //! number of accumulated votes
		};
		
		list<Proposal>proposals;

		std::atomic<int> chairperson;
		
		//! constructor:: create a new ballot to choose one of `proposalNames`.
		Ballot(string proposalNames[], int sender, int numVoter, int nPropsal)
		{
			long long error;
			
			numProposal = nPropsal;
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
			}
		
			// A dynamically-sized array of \`Proposal\` structs.
			/*! Proposal[] public proposals;*/
			
			// \`Proposal({...})\` creates a temporary
			// Proposal object and \`proposals.push(...)\`
			// appends it to the end of \`proposals\`.
			//! For each of the provided proposal names,
			//! create, initilize and add new proposal 
			//! shared object to STM shared memory.
			
			//proposals = new Proposal[numProposal+1];
			for(int p = 1; p <= numProposal; p++)
			{	
				/*! proposals.push(Proposal({name: propName[i], voteCount: 0}));*/				
				//! Initializing Proposals used by validator.
				Proposal prop;
				prop.ID        = p;
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-1];
				proposals.push_back(prop);
///				(proposals[p]).name = &proposalNames[p-1];
///				proposals[p].voteCount = 0;
			}
		};
		

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
	
	void state(int ID, bool sFlag, int *State);
	
	~Ballot(){ };//destructor
};
