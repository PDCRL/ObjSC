#include "BallotSCV.h"

	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	//! fun called by the validator threads.
	//!~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*----------------------------------------------------
! Validator::Give \`voter\` the right to vote on     !
! this ballot. May only be called by \`chairperson\`.!
*---------------------------------------------------*/
void Ballot::reset()
{
	auto votr = voters.begin();
	for(; votr != voters.end(); votr++)
	{
		votr->voted    = false;
		votr->delegate = 0;
		votr->vote     = 0;
	}
	auto prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
	prop->voteCount = 0;

}



int Ballot::giveRightToVote(int senderID, int voter)
{
	/*! Ballot::Voter voter[Voter_Count+1];*/

	// If 'sender' is not a chairperson, return,
	// as only chairperson can give rights to vote.
	// \`throw\` terminates & reverts all changes to
	// the state and to Ether balances. It is often
	// a good idea to use this if functions are
	// called incorrectly. But watch out, this
	// will also consume all provided gas.
	auto it = voters.begin();
	for(; it != voters.end(); it++)
	{
		if( it->ID == voter)
		{
			pthread_mutex_lock(&(it->accLock));
			if(it->rCount == 0 && it->wCount == 0)
			{
				it->wCount = 1;
				pthread_mutex_unlock(&(it->accLock));
				break;
			}
			else
			{
				pthread_mutex_unlock(&(it->accLock));
				return -1;//miner is malicious not given proper dependencies.
			}
		}
	}
	if(it == voters.end() && it->ID != voter)
	{
		cout<<"\nError:: voter "+to_string(voter)+" not found.\n";
	}

	if(senderID != chairperson || it->voted == true)
	{
		if(senderID != chairperson)
			cout<< "Error: Only chairperson can give right.\n";
		
		pthread_mutex_lock(&(it->accLock));
		it->wCount = 0;
		pthread_mutex_unlock(&(it->accLock));
		return 0;
	}
	pthread_mutex_lock(&(it->accLock));
	it->weight = 1;
	it->wCount = 0;
	pthread_mutex_unlock(&(it->accLock));
	return 1;
}

/*-----------------------------------------------------
! Validator:: Delegate your vote to the voter \`to\`. !
*----------------------------------------------------*/
int Ballot::delegate(int senderID, int to)
{
	// assigns reference.
	auto sender = voters.begin();
	for(; sender != voters.end(); sender++)
	{
		if(sender->ID == senderID)
		{
			pthread_mutex_lock(&(sender->accLock));
			if(sender->rCount == 0 && sender->wCount == 0)
			{
				sender->wCount = 1;
				pthread_mutex_unlock(&(sender->accLock));
				break;
			}
			else
			{
				pthread_mutex_unlock(&(sender->accLock));
				return -1;//miner is malicious not given proper dependencies.
			}
		}
	}
	if(sender == voters.end() && sender->ID != senderID)
	{
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
	}
        
	if(sender->voted)
	{
		//cout<<"\nVoter "+to_string(senderID)+" already voted!\n";
		pthread_mutex_lock(&(sender->accLock));
		sender->wCount = 0;
		pthread_mutex_unlock(&(sender->accLock));
		return 0;//already voted.
	}
	// Forward the delegation as long as \`to\` also delegated.
	// In general, such loops are very dangerous, because if 
	// they run too long, they might need more gas than is 
	// available in a block. In this case, delegation will 
	// not be executed, but in other situations, such loops 
	// might cause a contract to get "stuck" completely.

	auto Ito = voters.begin();
	for(; Ito != voters.end(); Ito++)
	{
		if( Ito->ID == to)
		{
			pthread_mutex_lock(&(Ito->accLock));
			if(Ito->wCount == 0)
			{
				Ito->rCount = 1;
				pthread_mutex_unlock(&(Ito->accLock));
				break;
			}
			else
			{
				pthread_mutex_unlock(&(Ito->accLock));
				return -1;//miner is malicious not given proper dependencies.
			}
		}
	}

	if(Ito == voters.end() && Ito->ID != to)
	{
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
	}

	while( Ito->delegate != 0 && Ito->delegate != senderID ) 
	{
		pthread_mutex_lock(&(Ito->accLock));
		Ito->rCount = 0;
		pthread_mutex_unlock(&(Ito->accLock));

		to = Ito->delegate;
		for(Ito = voters.begin(); Ito != voters.end(); Ito++)
		{
			if( Ito->ID == to)
			{
				pthread_mutex_lock(&(Ito->accLock));
				if(Ito->wCount == 0)
				{
					Ito->rCount = 1;
					pthread_mutex_unlock(&(Ito->accLock));
					break;
				}
				else
				{
					pthread_mutex_unlock(&(Ito->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
		}
		if(Ito == voters.end() && Ito->ID != to)
		{
			cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
		}	
	}
	// We found a loop in the delegation, not allowed.
	if (to == senderID)
	{
		pthread_mutex_lock(&(sender->accLock));
		sender->wCount = 0;
		pthread_mutex_unlock(&(sender->accLock));
		
		pthread_mutex_lock(&(Ito->accLock));
		Ito->rCount    = 0;
		pthread_mutex_unlock(&(Ito->accLock));

		return -2;
	}

	// Since \`sender\` is a reference, this
	// modifies \`voters[msg.sender].voted\`
	sender->voted    = true;
	sender->delegate = to;
	
	auto delegate = voters.begin();
	for(; delegate != voters.end(); delegate++)
	{
		if( delegate->ID == to)
		{
			pthread_mutex_lock(&(delegate->accLock));
			if(delegate->wCount == 0)
			{
				delegate->rCount = 1;
				pthread_mutex_unlock(&(delegate->accLock));
				break;
			}
			else
			{
				pthread_mutex_unlock(&(delegate->accLock));
				return -1;//miner is malicious not given proper dependencies.
			}
		}
	}
	if(delegate == voters.end() && delegate->ID != to)
	{
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
	}
	if (delegate->voted) 
	{
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
		{
			if( prop->ID == delegate->vote)
			{
				pthread_mutex_lock(&(prop->accLock));
				if(prop->rCount == 0 && prop->wCount == 0)
				{
					prop->wCount = 1;
					pthread_mutex_unlock(&(prop->accLock));
					break;
				}
				else
				{
					pthread_mutex_unlock(&(prop->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
		}
		if(prop == proposals.end() && prop->ID != delegate->vote)
		{
			cout<<"\nError:: Proposal "+to_string(delegate->vote)+" not found.\n";
		}	
		// If the delegate already voted,
		// directly add to the number of votes
		prop->voteCount = prop->voteCount + sender->weight;
		sender->weight = 0;

		pthread_mutex_lock(&(sender->accLock));
		sender->wCount   = 0;
		pthread_mutex_unlock(&(sender->accLock));
		
		pthread_mutex_lock(&(Ito->accLock));
		Ito->rCount      = 0;
		pthread_mutex_unlock(&(Ito->accLock));

		pthread_mutex_lock(&(delegate->accLock));
		delegate->rCount = 0;
		pthread_mutex_unlock(&(delegate->accLock));

		pthread_mutex_lock(&(prop->accLock));
		prop->wCount     = 0;		
		pthread_mutex_unlock(&(prop->accLock));

		return 1;
	}
	else
	{
		// If the delegate did not voted yet,
		// add to her weight.
		delegate->weight = delegate->weight + sender->weight;

		pthread_mutex_lock(&(sender->accLock));
		sender->wCount   = 0;
		pthread_mutex_unlock(&(sender->accLock));
		
		pthread_mutex_lock(&(Ito->accLock));
		Ito->rCount      = 0;
		pthread_mutex_unlock(&(Ito->accLock));

		pthread_mutex_lock(&(delegate->accLock));
		delegate->rCount = 0;
		pthread_mutex_unlock(&(delegate->accLock));


		return 1;
	}
}

/*-------------------------------------------------------
! Validator:: Give your vote (including votes delegated !
! to you) to proposal \`proposals[proposal].name\`     .!
-------------------------------------------------------*/
int Ballot::vote(int senderID, int proposal)
{
	auto sender = voters.begin();
	for(; sender != voters.end(); sender++)
	{
		if( sender->ID == senderID)
		{
			pthread_mutex_lock(&(sender->accLock));
			if(sender->rCount == 0 && sender->wCount == 0)
			{
				sender->wCount = 1;
				pthread_mutex_unlock(&(sender->accLock));
				break;
			}
			else
			{
				pthread_mutex_unlock(&(sender->accLock));
				return -1;//miner is malicious not given proper dependencies.
			}
		}
	}
	if(sender == voters.end() && sender->ID != senderID)
	{
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";
	}

	if (sender->voted)
	{
		pthread_mutex_lock(&(sender->accLock));
		sender->wCount = 0;
		pthread_mutex_unlock(&(sender->accLock));
		return 0;//already voted
	}
	sender->voted = true;
	sender->vote  = proposal;

	// If \`proposal\` is out of the range of the array,
	// this will throw automatically and revert all changes.
	auto prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
	{
		if( prop->ID == proposal)
		{
			pthread_mutex_lock(&(prop->accLock));
			if(prop->rCount == 0 && prop->wCount == 0)
			{
				prop->wCount = 1;
				pthread_mutex_unlock(&(prop->accLock));
				break;
			}
			else
			{
				pthread_mutex_unlock(&(prop->accLock));
				return -1;//miner is malicious not given proper dependencies.
			}
		}
	}
	if(prop == proposals.end() && prop->ID != proposal)
	{
		cout<<"\nError:: Proposal "+to_string(proposal)+" not found.\n";
	}
	prop->voteCount += sender->weight;
	
	pthread_mutex_lock(&(sender->accLock));
	sender->wCount = 0;
	pthread_mutex_unlock(&(sender->accLock));
	
	pthread_mutex_lock(&(prop->accLock));
	prop->wCount   = 0;
	pthread_mutex_unlock(&(prop->accLock));

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
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
		{
			if( prop->ID == p)
				break;
		}
		if(prop == proposals.end() && prop->ID != p)
		{
			cout<<"\nError:: Proposal "+to_string(p)+" not found.\n";
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
	auto prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
	{
		if( prop->ID == winnerID)
			break;
	}
	if(prop == proposals.end() && prop->ID != winnerID)
	{
		cout<<"\nError:: Proposal "+to_string(winnerID)+" not found.\n";
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
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
		{
			if( prop->ID == ID)
				break;
		}
		if(prop == proposals.end() && prop->ID != ID)
		{
			cout<<"\nError:: Proposal "+to_string(ID)+" not found.\n";
		}
		ValidatorState[ID-1] = prop->voteCount;
	}
	if(sFlag == true)
	{
		auto it = voters.begin();
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
	}
}
