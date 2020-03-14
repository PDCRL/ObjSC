#include "Ballot.h"

//==============================================================================
//===============================Validator SC Fun===============================
//==============================================================================
void Ballot::giveRightToVote(int senderID, int voter)
{
	auto it = voters.begin();
	for(; it != voters.end(); it++)
		if( it->ID == voter) break;

	if(it == voters.end() && it->ID != voter)
		cout<<"\nError:: voter "+to_string(voter)+" not found.\n";


	if(senderID != chairperson || it->voted == true)
	{
		if(senderID != chairperson)
			cout<< "Error: Only chairperson can give right.\n";
		else
			cout<< "Error: Already Voted.\n";
		return;
	}
	it->weight = 1;
	return;
}

/*-----------------------------------------------------
!        Delegate your vote to the voter \`to\`.      !
*----------------------------------------------------*/
int Ballot::delegate(int senderID, int to)
{
	// assigns reference.
	auto sender = voters.begin();
	for(; sender != voters.end(); sender++)
		if( sender->ID == senderID) break;

	if(sender == voters.end() && sender->ID != senderID) {
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
		return 0;
	}
	if(sender->voted)
		//cout<<"\nVoter "+to_string(senderID)+" already voted!\n";
		return 0;//already voted.

	// Forward the delegation as long as \`to\` also delegated.
	// In general, such loops are very dangerous, because if 
	// they run too long, they might need more gas than is 
	// available in a block. In this case, delegation will 
	// not be executed, but in other situations, such loops 
	// might cause a contract to get "stuck" completely.
	
	auto Ito = voters.begin();
	for(; Ito != voters.end(); Ito++)
		if( Ito->ID == to) break;

	if(Ito == voters.end() && Ito->ID != to)
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";

	while ( Ito->delegate != 0 && Ito->delegate != senderID ) 
	{
		to = Ito->delegate;
		for(Ito = voters.begin(); Ito != voters.end(); Ito++)
			if( Ito->ID == to) break;

		if(Ito == voters.end() && Ito->ID != to) {
			cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
			return 0;
		}
	}
	// We found a loop in the delegation, not allowed.
	if (to == senderID) return 0;

	// Since \`sender\` is a reference, this
	// modifies \`voters[msg.sender].voted\`
	sender->voted    = true;
	sender->delegate = to;
	
	auto delegate = voters.begin();
	for(; delegate != voters.end(); delegate++)
		if( delegate->ID == to) break;

	if(delegate == voters.end() && delegate->ID != to) {
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
		return 0;
	}
	if (delegate->voted) 
	{
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
			if( prop->ID == delegate->vote) break;

		if(prop == proposals.end() && prop->ID != delegate->vote) {
			cout<<"\nError:: Proposal "+to_string(delegate->vote)+" not found.\n";
			return 0;
		}

		// If the delegate already voted,
		// directly add to the number of votes to voted proposal
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
!       Give your vote (including votes delegated       !
! to you) to proposal \`proposals[proposal].name\`     .!
-------------------------------------------------------*/
int Ballot::vote(int senderID, int proposal)
{
	auto sender = voters.begin();
	for(; sender != voters.end(); sender++) 
		if( sender->ID == senderID) break;

	if(sender == voters.end() && sender->ID != senderID) {
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
		return 0;
	}
	if (sender->voted) return 0;//already voted

	sender->voted = true;
	sender->vote  = proposal;

	// If \`proposal\` is out of the range of the array,
	// this will throw automatically and revert all changes.
	auto prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
		if( prop->ID == proposal) break;

	if(prop == proposals.end() && prop->ID != proposal) {
		cout<<"\nError:: Proposal "+to_string(proposal)+" not found.\n";
		return 0;
	}
	prop->voteCount += sender->weight;
	return 1;
}

/*-------------------------------------------------
!        @dev Computes the winning proposal       !
! taking all previous votes into account.        .!
-------------------------------------------------*/
int Ballot::winningProposal( )
{
	int winningProposal  = 0;
	int winningVoteCount = 0;
	for (int p = 1; p <= numProposal; p++)//numProposal = proposals.length.
	{
		//Proposal *prop = &proposals[p];
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
			if( prop->ID == p) break;

		if(prop == proposals.end() && prop->ID != p)
			cout<<"\nError:: Proposal "+to_string(p)+" not found.\n";

		if (prop->voteCount > winningVoteCount)
		{
			winningVoteCount = prop->voteCount;
			winningProposal = p;
		}
	}
//	cout<<"\n=======================================================\n";
//	cout<<"Winning Proposal = " <<winningProposal<< 
//			" | Vote Count = "<<winningVoteCount;
	return winningProposal;
}

/*------------------------------------------------
! Calls winningProposal() function to get the    !
! index of the winner contained in the proposals !
! array and then returns the name of the winner. !
------------------------------------------------*/
void Ballot::winnerName(string *winnerName)
{
	int winnerID = winningProposal();

	auto prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
		if( prop->ID == winnerID) break;

	if(prop == proposals.end() && prop->ID != winnerID)
		cout<<"\nError:: Proposal "+to_string(winnerID)+" not found.\n";


	//winnerName = &(prop)->name;
	cout<<"\n==================================================\n";
	cout<<"Winning Proposal = " <<winnerID;
	cout<<" | Name = " <<*(prop->name) << " |";
	cout<<"\n===================================";
}

void Ballot::state(int ID, bool sFlag, int *State)
{
	if(sFlag == false) {//Proposal
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++) if( prop->ID == ID) break;
		if(prop != proposals.end())
			State[ID-1] = prop->voteCount;
	}
	if(sFlag == true) {
		auto it = voters.begin();
		for(; it != voters.end(); it++) if( it->ID == ID) break;
		if(it != voters.end() )
			State[ID-1] = it->voted;
	}
}


void Ballot::reset() {
	for(auto votr = voters.begin() ; votr != voters.end(); votr++) {
		votr->voted    = false;
		votr->delegate = 0;
		votr->vote     = 0;
	}
	for(auto prop = proposals.begin(); prop != proposals.end(); prop++)
		prop->voteCount = 0;
}

//==============================================================================
//===============================Miner SC Fun===================================
//==============================================================================
/*----------------------------------------------------
!        Give \`voter\` the right to vote on         !
! this ballot. May only be called by \`chairperson\`.!
*---------------------------------------------------*/
void Ballot::giveRightToVote_m(int senderID, int voter) {
	auto it = votersM.begin();
	for(; it != votersM.end(); it++) if( it->ID == voter) break;
	if(it == votersM.end() && it->ID != voter)
		cout<<"\nError:: voter "+to_string(voter)+" not found.\n";

	if(senderID != chairperson || it->voted == true) {
		if(senderID != chairperson)
			cout<< "Error: Only chairperson can give right.\n";
		else cout<< "Error: Already Voted.\n";
		return;
	}
	it->weight = 1;
	return;
}

/*-----------------------------------------------------
!        Delegate your vote to the voter \`to\`.      !
*----------------------------------------------------*/
int Ballot::delegate_m(int senderID, int to, bool binFlag)
{
	auto sender = votersM.begin();
	for(; sender != votersM.end(); sender++)
		if(sender->ID == senderID)
			break;

	if( sender != votersM.end())
	{
		if(binFlag == true) 
		{
			bool x = vtLock[senderID].try_lock();
			if(x == false) {
				if(sender->voted)
					return 0;//already voted.
				else
					return -1;// Some other Tx has done update already.
			}
			else { 
				if(sender->voted)
					return 0;//already voted.
			}
		}
		if(sender->voted) return 0;//already voted.
		
	}
	else {
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
		return 0;//AU execution fail;
	}

	auto Ito = votersM.begin();
	for(; Ito != votersM.end(); Ito++) if( Ito->ID == to) break;

	if( Ito != voters.end())
	{
		if(binFlag == true)
		{
			bool x = vtLock[to].try_lock();
			if(x == false)
				return -1;// Some other Tx has done update already.
		}
	}
	else {
		cout<<"\nError:: voter to"+to_string(to)+" not found.\n";
		return 0;//AU execution fail;
	}

	while(Ito->delegate != 0 && Ito->delegate != senderID )
	{
		to = Ito->delegate;

		for(Ito = votersM.begin(); Ito != votersM.end(); Ito++)
			if( Ito->ID == to) break;

		if( Ito != votersM.end())
		{
			if(binFlag == true)
			{
				bool x = vtLock[to].try_lock();
				if(x==false) {
					return -1;// Some other Tx has done update already.
				}
			}
		}
		else {
			cout<<"\nError:: voter to"+to_string(to)+" not found.\n";
			return 0;//AU execution fail;
		}
	}
	// We found a loop in the delegation, not allowed.
	if(to == senderID) return 0;


	sender->voted    = true;
	sender->delegate = to;
	
	auto delegate = votersM.begin();
	for(; delegate != votersM.end(); delegate++)
		if( delegate->ID == to)
			break;

	if(delegate->voted)
	{
		auto prop = proposalsM.begin();
		for(; prop != proposalsM.end(); prop++)
			if(prop->ID == delegate->vote)
				break;

		if(prop != proposalsM.end() ) {
			if(binFlag == true) {
				bool x = ptLock[prop->ID].try_lock();
				if(x == false)
				{
					sender->voted    = false;
					sender->delegate = 0;
					return -1;// Some other Tx has done update already.
				}
				else {
					prop->voteCount += sender->weight;
					sender->weight = 0;
					return 1;
				}
			}
			else {
				prop->voteCount += sender->weight;
				sender->weight = 0;
				return 1;
			}
		}
		else {
			cout<<"\nError:: Proposal "+to_string(delegate->vote)+" not found\n";
			return 0;//AU execution fail;
		}
	}
	else {
		// If the delegate did not voted yet,
		// add to her weight.
		delegate->weight += sender->weight;
		return 1;
	}
}

/*-------------------------------------------------------
!       Give your vote (including votes delegated       !
! to you) to proposal \`proposals[proposal].name\`     .!
-------------------------------------------------------*/
int Ballot::vote_m(int senderID, int proposal, bool binFlag)
{
	auto sender = votersM.begin();
	for(; sender != votersM.end(); sender++) 
		if(sender->ID == senderID)
			break;

	if(sender != votersM.end()) 
	{
		if(binFlag == true)
		{
			bool x = vtLock[senderID].try_lock();
			if(x == false) {
				if(sender->voted)
					return 0;//already voted.
				else
					return -1;// Some other Tx has done update already.
			}
			else {
				if(sender->voted)
					return 0;//already voted.
			}
		}
		else {
			if(sender->voted)
				return 0;//already voted.
		}
	}
	else {
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
		return 0;//AU execution fail;
	}

	sender->voted = true;
	sender->vote  = proposal;

	auto prop = proposalsM.begin();
	for(; prop != proposalsM.end(); prop++)
		if(prop->ID == proposal)
			break;

	if( prop != proposalsM.end() ) {
		if(binFlag == true)
		{
			bool x = ptLock[prop->ID].try_lock();
			if(x == false) {
				sender->voted = false;
				sender->vote  = 0;
				return -1;// Some other Tx has done update already.
			}
			else {
				prop->voteCount += sender->weight;
				return 1;
			}
		}
		prop->voteCount += sender->weight;
		return 1;
	}
	else {
		cout<<"\nError:: Proposal "+to_string(proposal)+" not found\n";
		return 0;//AU execution fail;
	}
	prop->voteCount += sender->weight;
	return 1;
}

/*-------------------------------------------------
!        @dev Computes the winning proposal       !
! taking all previous votes into account.        .!
-------------------------------------------------*/
int Ballot::winningProposal_m( )
{
	int winningProposal  = 0;
	int winningVoteCount = 0;
	for (int p = 1; p <= numProposal; p++) {
		//Proposal *prop = &proposals[p];
		auto prop = proposalsM.begin();
		for(; prop != proposalsM.end(); prop++) if( prop->ID == p) break;
		if(prop == proposalsM.end() && prop->ID != p)
			cout<<"\nError:: Proposal "+to_string(p)+" not found.\n";

		if (prop->voteCount > winningVoteCount) {
			winningVoteCount = prop->voteCount;
			winningProposal = p;
		}
	}
return winningProposal;
}

/*------------------------------------------------
! Calls winningProposal() function to get the    !
! index of the winner contained in the proposals !
! array and then returns the name of the winner. !
------------------------------------------------*/
void Ballot::winnerName_m(string *winnerName)
{
	int winnerID = winningProposal_m();
	auto prop = proposalsM.begin();
	for(; prop != proposalsM.end(); prop++) if( prop->ID == winnerID) break;
	if(prop == proposalsM.end() && prop->ID != winnerID)
		cout<<"\nError:: Proposal "+to_string(winnerID)+" not found.\n";
	cout<<"\n==================================================\n";
	cout<<"Winning Proposal = " <<winnerID;
	cout<<" | Name = " <<*(prop->name) << " |";
	cout<<"\n===================================";
}


//==============================================================================
//==============================================================================
//==============================================================================


void Ballot::state_m(int ID, bool sFlag, int *State)
{
	if(sFlag == false) {//Proposal
		auto prop = proposalsM.begin();
		for(; prop != proposalsM.end(); prop++) if( prop->ID == ID) break;
		if(prop != proposalsM.end())
			State[ID-1] = prop->voteCount;
	}
	if(sFlag == true) {
		auto it = votersM.begin();
		for(; it != votersM.end(); it++) if( it->ID == ID) break;
		if(it != votersM.end() )
			State[ID-1] = it->voted;
	}
}

void Ballot::reset_m() {
	for(auto votr = votersM.begin(); votr != votersM.end(); votr++) {
		votr->voted    = false;
		votr->delegate = 0;
		votr->vote     = 0;
	}
	for(auto prop = proposalsM.begin(); prop != proposalsM.end(); prop++)
		prop->voteCount = 0;
}


void Ballot::allUnlock() {
	for(int i = 0; i <= numPropsals; i++) ptLock[i].unlock();
	for(int i = 0; i <= numVoters; i++) vtLock[i].unlock();
}
