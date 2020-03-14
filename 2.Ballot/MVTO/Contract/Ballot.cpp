#include "Ballot.h"

	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	//! fun called by the validator threads.
	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*----------------------------------------------------
! Validator::Give \`voter\` the right to vote on     !
! this ballot. May only be called by \`chairperson\`.!
*---------------------------------------------------*/
void Ballot::reset()
{
	list<Voter>::iterator votr = voters.begin();
	for(; votr != voters.end(); votr++)
	{
		votr->voted    = false;
		votr->delegate = 0;
		votr->vote     = 0;
	}
	list<Proposal>::iterator prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
	prop->voteCount = 0;

}


void Ballot::giveRightToVote(int senderID, int voter)
{
	/*! Ballot::Voter voter[Voter_Count+1];*/

	// If 'sender' is not a chairperson, return,
	// as only chairperson can give rights to vote.
	// \`throw\` terminates & reverts all changes to
	// the state and to Ether balances. It is often
	// a good idea to use this if functions are
	// called incorrectly. But watch out, this
	// will also consume all provided gas.
	list<Voter>::iterator it = voters.begin();
	for(; it != voters.end(); it++)
	{
		if( it->ID == voter) break;
	}
	if(it == voters.end() && it->ID != voter)
	{
		cout<<"\nError:: voter "+to_string(voter)+" not found.\n";
	}

	if(senderID != chairperson || it->voted == true)
	{
		if(senderID != chairperson)
			cout<< "Error: Only chairperson can give right.\n";
		else
//			cout<< "Error: Already Voted.\n";
		return;
	}
	it->weight = 1;
}

/*-----------------------------------------------------
! Validator:: Delegate your vote to the voter \`to\`. !
*----------------------------------------------------*/
int Ballot::delegate(int senderID, int to)
{
	// assigns reference.
	list<Voter>::iterator sender = voters.begin();
	for(; sender != voters.end(); sender++)
	{
		if( sender->ID == senderID)
			break;
	}
	if(sender == voters.end() && sender->ID != senderID)
	{
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
	}
        
	if(sender->voted)
	{
		//cout<<"\nVoter "+to_string(senderID)+" already voted!\n";
		return 0;//already voted.
	}
	// Forward the delegation as long as \`to\` also delegated.
	// In general, such loops are very dangerous, because if 
	// they run too long, they might need more gas than is 
	// available in a block. In this case, delegation will 
	// not be executed, but in other situations, such loops 
	// might cause a contract to get "stuck" completely.
	
	list<Voter>::iterator Ito = voters.begin();
	for(; Ito != voters.end(); Ito++)
	{
		if( Ito->ID == to)
			break;
	}
	if(Ito == voters.end() && Ito->ID != to)
	{
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
	}

	while ( Ito->delegate != 0 && Ito->delegate != senderID ) 
	{
		to = Ito->delegate;
		for(Ito = voters.begin(); Ito != voters.end(); Ito++)
		{
			if( Ito->ID == to)
				break;
		}
		if(Ito == voters.end() && Ito->ID != to)
		{
			cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
		}	
	}
	// We found a loop in the delegation, not allowed.
	if (to == senderID)
	{
		return -1;
	}
	// Since \`sender\` is a reference, this
	// modifies \`voters[msg.sender].voted\`
	sender->voted    = true;
	sender->delegate = to;
	
	list<Voter>::iterator delegate = voters.begin();
	for(; delegate != voters.end(); delegate++)
	{
		if( delegate->ID == to)
			break;
	}
	if(delegate == voters.end() && delegate->ID != to)
	{
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
	}
	if (delegate->voted) 
	{
		list<Proposal>::iterator prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
		{
			if( prop->ID == delegate->vote)
				break;
		}
		if(prop == proposals.end() && prop->ID != delegate->vote)
		{
//			cout<<"\nError:: Proposal "+to_string(delegate->vote)+" not found.\n";
		}	
		// If the delegate already voted,
		// directly add to the number of votes
		prop->voteCount = prop->voteCount + sender->weight;
		sender->weight = 0;
		return 1;
	}
	else
	{
		// If the delegate did not voted yet,
		// add to her weight.
		delegate->weight = delegate->weight + sender->weight;
		return 1;
	}
}

/*-------------------------------------------------------
! Validator:: Give your vote (including votes delegated !
! to you) to proposal \`proposals[proposal].name\`     .!
-------------------------------------------------------*/
int Ballot::vote(int senderID, int proposal)
{
	list<Voter>::iterator sender = voters.begin();
	for(; sender != voters.end(); sender++)
	{
		if( sender->ID == senderID)
			break;
	}
	if(sender == voters.end() && sender->ID != senderID)
	{
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
	}

	if (sender->voted) return 0;//already voted

	sender->voted = true;
	sender->vote  = proposal;

	// If \`proposal\` is out of the range of the array,
	// this will throw automatically and revert all changes.
	list<Proposal>::iterator prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
	{
		if( prop->ID == proposal)
			break;
	}
	if(prop == proposals.end() && prop->ID != proposal)
	{
//		cout<<"\nError:: Proposal "+to_string(proposal)+" not found.\n";
	}			
	prop->voteCount += sender->weight;
	return 1;
}

/*-------------------------------------------------
! Validator:: @dev Computes the winning proposal  !
! taking all previous votes into account.        .!
-------------------------------------------------*/
int Ballot::winningProposal( )
{
	int winningProposal  = 0;
	int winningVoteCount = 0;
	for (int p = 1; p <= numProposal; p++)//numProposal = proposals.length.
	{
		//Proposal *prop = &proposals[p];
		list<Proposal>::iterator prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
		{
			if( prop->ID == p)
				break;
		}
		if(prop == proposals.end() && prop->ID != p)
		{
//			cout<<"\nError:: Proposal "+to_string(p)+" not found.\n";
		}		
		if (prop->voteCount > winningVoteCount)
		{
			winningVoteCount = prop->voteCount;
			winningProposal = p;
		}
	}
	cout<<"\n=======================================================\n";
	cout<<"Winning Proposal = " <<winningProposal<< 
			" | Vote Count = "<<winningVoteCount;
	return winningProposal;
}

/*-----------------------------------------------------
! Validator:: Calls winningProposal() function to get !
! the index of the winner contained in the proposals  !
! array and then returns the name of the winner.      !
-----------------------------------------------------*/
void Ballot::winnerName(string *winnerName)
{
	int winnerID = winningProposal();
	list<Proposal>::iterator prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
	{
		if( prop->ID == winnerID)
			break;
	}
	if(prop == proposals.end() && prop->ID != winnerID)
	{
//		cout<<"\nError:: Proposal "+to_string(winnerID)+" not found.\n";
	}

	//winnerName = &(prop)->name;
	cout<<" | Name = " <<*(prop->name) << " |";
	cout<<"\n=======================================================\n";
}

void Ballot::state(int ID, bool sFlag, int *ValidatorState)
{
//	cout<<"==========================\n";
	if(sFlag == false)//Proposal
	{
		list<Proposal>::iterator prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
		{
			if( prop->ID == ID)
				break;
		}
		if(prop == proposals.end() && prop->ID != ID)
		{
			cout<<"\nError:: Proposal "+to_string(ID)+" not found.\n";
		}
//		cout<<"Proposal ID \t= "  << prop->ID  <<endl;
//		cout<<"Proposal Name \t= "<< *(prop->name) <<endl;
//		cout<<"Vote Count \t= "  << prop->voteCount <<endl;
		ValidatorState[ID-1] = prop->voteCount;
//		cout<<"================================\n";
	}
	if(sFlag == true)
	{
		list<Voter>::iterator it = voters.begin();
		for(; it != voters.end(); it++)
		{
			if( it->ID == ID)
				break;
		}
		if(it == voters.end() && it->ID != ID)
		{
			cout<<"\nError:: voter "+to_string(ID)+" not found.\n";
		}	
		ValidatorState[ID-1] = it->voted;
//		cout<<"Voter ID \t= "  <<it->ID<<endl;
//		cout<<"weight \t\t= "  <<it->weight<<endl;
//		cout<<"Voted \t\t= "   <<it->voted<<endl;
//		cout<<"Delegate \t= "  <<it->delegate<<endl;
//		cout<<"Vote Index -\t= "<<it->vote<<endl;
//		cout<<"================================\n";
	}
}


		//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		//! fun called by the miner threads.
		//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*----------------------------------------------------
! Miner::Give \`voter\` the right to vote on         !
! this ballot. May only be called by \`chairperson\`.!
*---------------------------------------------------*/
int Ballot::giveRightToVote_m(int senderID, int voter)
{
	voidVal *cObj = new voidVal( sizeof(Voter) );
	int* val      = new int;

	(*(Voter*)cObj->val).ID = voter;
	
	list<int> conf_list;
	L_txlog* txlog;
	OPN_STATUS ops, txs;
	txlog = lib->begin();

	ops = lib->tx_read(txlog, voter, val, cObj);

	if(ABORT == ops) return 0; // AU transaction aborted.
	
	if(senderID != chairperson || (*(Voter*)cObj->val).voted)
	{
		cout<<"\nVoter "+to_string(senderID)+" already voted or your not chairperson!\n";
//		lib->try_abort( );
		return -1; //invalid AU.
	}

	(*(Voter*)cObj->val).weight = 1;

	ops = lib->tx_write(txlog, voter, *val, cObj);

	if(ABORT != ops) txs = lib->tryCommit(txlog, conf_list, cObj);

	if(ABORT == txs) return 0; //AU transaction aborted.

	else return 1;//valid AU: executed successfully.
}


/*-------------------------------------------------
! Miner:: Delegate your vote to the voter \`to\`. !
*------------------------------------------------*/
int Ballot::delegate_m(int senderID, int to, int *ts, list<int>&cList)
{
	voidVal* sObj  = new voidVal( sizeof(Voter) );
	voidVal* toObj = new voidVal( sizeof(Voter) );
	int* val       = new int;
	L_txlog* txlog;
	OPN_STATUS Sops, Tops, txs;
	txlog = lib->begin();
	*ts   = txlog->L_tx_id;;

	Sops = lib->tx_read(txlog, senderID, val, sObj);
	if(ABORT == Sops) return 0; // AU transaction aborted.

	Tops = lib->tx_read(txlog, to, val, toObj);
	if(ABORT == Tops) return 0; // AU transaction aborted.

	if( (*(Voter*)sObj->val).voted )
	{
//		lib->try_abort(T);
		return -1;//AU is invalid
	}
	
	int delegateTO = (*(Voter*)toObj->val).delegate;
	while( delegateTO != 0 )
	{
		if(delegateTO == (*(Voter*)toObj->val).ID)
		{
			break;
		}
		
		(*(Voter*)toObj->val).ID = (*(Voter*)toObj->val).delegate;
		
		Tops = lib->tx_read(txlog, (*(Voter*)toObj->val).ID, val, toObj);
		if(ABORT == Tops) return 0; // AU transaction aborted.

		delegateTO = (*(Voter*)toObj->val).delegate;
	}

	//! We found a loop in the delegation, not allowed. 
	//! Prev while may cause loop.
	if( (*(Voter*)toObj->val).ID == (*(Voter*)sObj->val).ID) 
	{
//		lib->try_abort(T);
		return -1;//AU is invalid
	}

	(*(Voter*)sObj->val).voted    = true;
	(*(Voter*)sObj->val).delegate = (*(Voter*)toObj->val).ID;

	// If the delegate already voted, directly add to the number of votes.
	if( (*(Voter*)toObj->val).voted ) 
	{
		int votedPropsal = (*(Voter*)toObj->val).vote;

		voidVal* pObj    = new voidVal( sizeof(Proposal) );
		
		OPN_STATUS Pops = lib->tx_read(txlog, numVoters+votedPropsal, val, pObj);
		if(ABORT == Pops) return 0; // AU transaction aborted.
						
		(*(Proposal*)pObj->val).voteCount += (*(Voter*)sObj->val).weight;
				
		(*(Voter*)sObj->val).weight = 0;
		
		lib->tx_write(txlog, numVoters+votedPropsal, *val, pObj);
	}
	else // If the delegate did not vote yet, add to weight.
	{
		(*(Voter*)toObj->val).weight += (*(Voter*)sObj->val).weight;
	}

	lib->tx_write(txlog, senderID, *val, sObj);
	lib->tx_write(txlog, (*(Voter*)toObj->val).ID, *val, toObj);

	
	txs = lib->tryCommit(txlog, cList, sObj);

	if(ABORT == txs) return 0; //AU transaction aborted.

	else return 1;//valid AU: executed successfully.
}


/*---------------------------------------------------
! Miner:: Give your vote (including votes delegated !
! to you) to proposal \`proposals[proposal].name\  .!
---------------------------------------------------*/
int Ballot::vote_m( int senderID, int proposal, int *ts, list<int>&cList)
{
	voidVal* vObj = new voidVal( sizeof(Voter) );
	voidVal* pObj = new voidVal( sizeof(Proposal) );
	int* val      = new int;

	L_txlog* txlog;
	OPN_STATUS Vops, Pops, txs;

	txlog = lib->begin();
	*ts   = txlog->L_tx_id;

	Vops = lib->tx_read(txlog, senderID, val, vObj);
	if(ABORT == Vops) return 0; // AU transaction aborted.

	if( (*(Voter*)vObj->val).voted )
	{
//		lib->try_abort(T);
		return -1;// AU is invalid.
	}

	Pops = lib->tx_read(txlog, numVoters+proposal, val, pObj);
	if(ABORT == Pops) return 0; // AU transaction aborted.
	
	(*(Voter*)vObj->val).voted = true;
	(*(Voter*)vObj->val).vote  = proposal;
	(*(Proposal*)pObj->val).voteCount += (*(Voter*)vObj->val).weight;
	
//	cout<<" new vote count is "+to_string((*(Proposal*)pObj->value).voteCount);
	lib->tx_write(txlog, senderID, *val, vObj);
	lib->tx_write(txlog, numVoters+proposal, *val, pObj);

	txs = lib->tryCommit(txlog, cList, vObj);

	if(ABORT == txs) return 0; //AU transaction aborted.

	else return 1;//valid AU: executed successfully.
}


/*---------------------------------------------
! Miner:: @dev Computes the winning proposal  !
! taking all previous votes into account.    .!
---------------------------------------------*/
int Ballot::winningProposal_m()
{
	voidVal* pObj = new voidVal( sizeof(Proposal) );
	int* val      = new int;

	list<int> conf_list;
	L_txlog* txlog;
	OPN_STATUS Pops, txs;
	txlog = lib->begin();


	int winningProposal  = 0;
	int winningVoteCount = 0;
	for(int p = numVoters+1 ; p <= numVoters+numProposal ; p++)//numProposal = proposals.length.
	{
		Pops = lib->tx_read(txlog, p, val, pObj);
		if(ABORT == Pops)
		{
			return 0; // AU transaction aborted.
			cout<<"\nError in reading Proposal "+to_string(p-numVoters)+"  State.\n";
		}
		if(winningVoteCount < (*(Proposal*)pObj->val).voteCount)
		{
			winningProposal  = p;
			winningVoteCount = (*(Proposal*)pObj->val).voteCount;
		}
	}
	txs = lib->tryCommit(txlog, conf_list, pObj);
	if(txs == ABORT)cout<<"\nError in reading Winner\n";
	cout<<"\n=======================================================\n";
	cout<<"Winning Proposal = " <<winningProposal-numVoters<< " | Vote Count = "<<winningVoteCount;
	return winningProposal;
}



/*-----------------------------------------------------
! Miner:: Calls winningProposal() function to get     !
! the index of the winner contained in the proposals  !
! array and then returns the name of the winner.      !
-----------------------------------------------------*/
void Ballot::winnerName_m(string *winnerName)
{
	voidVal* pObj = new voidVal( sizeof(Proposal) );
	int* val      = new int;

	int winningP = winningProposal_m();	

	list<int> conf_list;
	L_txlog* txlog;
	OPN_STATUS Pops, txs;

	txlog = lib->begin();
	Pops = lib->tx_read(txlog, winningP, val, pObj);
	if(ABORT == Pops) cout<<"\nError in reading Winning Proposal "+to_string(winningP-numVoters)+"  State.\n";

	winnerName      = (*(Proposal*)pObj->val).name;
	
	cout<<" | Name = " <<*(*(Proposal*)pObj->val).name << " |";
	cout<<"\n=======================================================\n";
	txs = lib->tryCommit(txlog, conf_list, pObj);
}

void Ballot::state_m(int ID, bool sFlag, int *MinerState)
{
	list<int> conf_list;
	L_txlog* txlog;
	OPN_STATUS Pops, txs;
	txlog = lib->begin();

//	cout<<"==========================\n";
	if(sFlag == false)//Proposal
	{
		voidVal* Obj = new voidVal( sizeof(Proposal) );
		int* val     = new int;

		Pops = lib->tx_read(txlog, numVoters+ID, val, Obj);
		if(ABORT == Pops)
		{
			cout<<"\nError in reading Winning Proposal "+to_string(ID)+"  State.\n";
			return;
		}
//		cout<<"Proposal ID \t= "  << ID <<endl;
//		cout<<"Proposal Name \t= "<< *(*(Proposal*)Obj->val).name <<endl;
//		cout<<"Vote Count \t= "  << (*(Proposal*)Obj->val).voteCount <<endl;	
		MinerState[ID-1] =(*(Proposal*)Obj->val).voteCount;
//		cout<<"================================\n";
	}
	if(sFlag == true)
	{
		voidVal* Obj = new voidVal( sizeof(Voter) );
		int* val     = new int;

		Pops = lib->tx_read(txlog, ID, val, Obj);
		if(ABORT == Pops)
		{
			cout<<"\nError in reading Voter "+to_string(ID)+"  State.\n";
			return;
		}
		MinerState[ID-1] = (*(Voter*)Obj->val).voted;
//		cout<<"Voter ID : "  <<ID<<endl;
//		cout<<"weight : "    <<(*(Voter*)Obj->val).weight <<endl;
//		cout<<"Voted : "     <<(*(Voter*)Obj->val).voted <<endl;
//		cout<<"Delegate : "  <<(*(Voter*)Obj->val).delegate <<endl;
//		cout<<"Vote Index : "<<(*(Voter*)Obj->val).vote <<endl;
//		cout<<"================================\n";
	}
	voidVal* Obj = new voidVal( sizeof(Voter) );
	txs = lib->tryCommit(txlog, conf_list, Obj);
}
