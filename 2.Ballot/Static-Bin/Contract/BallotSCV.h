#pragma once
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <list>
#include <shared_mutex>
#include <sys/time.h>
#include <random>

using namespace std;

class Ballot
{

public:
		int numProposal;
		std::atomic<int> numPropsals;
		std::atomic<int> numVoters;

		struct VoterV
		{
			int ID;
			int weight;  // weight is accumulated by delegation
			bool voted;  // if true, that person already voted
			int delegate;// person delegated to
			int vote;    // index of the voted proposal
			int rCount;  //increase count by tx that is reading dataitem.
			int wCount;  //increase count by tx that is writing to dataitem.
			pthread_mutex_t accLock;//lock with each account id used at validator.
		};

		//! this is voter shared object used by validator.
		list<VoterV>voters;

		//! This is a type for a single proposal.
		struct ProposalV
		{
			int ID;
			string *name; //! short name (<=32 bytes) data type.
			int voteCount;//! number of accumulated votes
			int rCount;   //increase count by tx that is reading dataitem.
			int wCount;   //increase count by tx that is writing to dataitem.
			pthread_mutex_t accLock;//lock with each account id used at validator.
		};

		list<ProposalV>proposals;

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
			
			for(int p = 0; p <= numProposal; p++)
			{
				//! Initializing Proposals used by validator.
				ProposalV prop;
				prop.ID        = p;
				prop.voteCount = 0;
				prop.name      = &proposalNames[p-1];
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

	~Ballot(){ };//destructor
};
