#include "Ballot.h"

/*----------------------------------------------------
! Give \`voter\` the right to vote on                !
! this ballot. May only be called by \`chairperson\`.!
*---------------------------------------------------*/
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
		if( it->ID == voter)
			break;
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
			cout<< "Error: Already Voted.\n";
		return;
	}
	it->weight = 1;
}

/*-----------------------------------------
! Delegate your vote to the voter \`to\`. !
*----------------------------------------*/
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
///		Proposal *prop = &proposals[delegate->vote];
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

/*-----------------------------------------------------
! Give your vote (including votes delegated           !
! to you) to proposal \`proposals[proposal].name\`   .!
-----------------------------------------------------*/
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
	// this will throw automatically and revert all
	// changes.
///	Proposal *prop = &proposals[proposal];
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
! @dev Computes the winning proposal              !
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
! Calls winningProposal() function to get             !
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
