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
				votr.ID       = v;
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
