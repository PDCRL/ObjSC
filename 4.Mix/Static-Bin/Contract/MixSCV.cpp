#include "MixSCV.h"

//! RESETING TIMEPOIN FOR VALIDATOR.
void SimpleAuction::reset(int _biddingTime)
{
	beneficiaryAmount = 0;
	start = std::chrono::system_clock::now();
	auctionEnd = _biddingTime;
	
	auto pr = pendingReturns.begin();
	for(; pr != pendingReturns.end(); pr++)
		pr->value = 0;
}


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!        Bid on the auction with the value sent together with this       !*/
/*! transaction. The value will only be refunded if the auction is not won.!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool SimpleAuction::bid( int payable, int bidderID, int bidValue )
{
	// No arguments are necessary, all information is already part of trans
	// -action. The keyword payable is required for the function to be able
	// to receive Ether. Revert the call if the bidding period is over.
	
	auto end     = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();

	if( now > auctionEnd)
	{
//		cout<<"\nAuction already ended.";
		return false;
	}
	// If the bid is not higher, send the money back.
	if( bidValue <= highestBid)
	{
//		cout<<"\nThere already is a higher bid.";
		return false;
	}
	if (highestBid != 0) 
	{
		// Sending back the money by simply using highestBidder.send(highestBid)
		// is a security risk because it could execute an untrusted contract.
		// It is always safer to let recipients withdraw their money themselves.
		//pendingReturns[highestBidder] += highestBid;
		
		auto pr = pendingReturns.begin();
		for(; pr != pendingReturns.end(); pr++)
			if( pr->ID == highestBidder) break;

//		if(pr == pendingReturns.end() && pr->ID != highestBidder)
//			cout<<"\nError:: Bidder "+to_string(highestBidder)+" not found.\n";

		pr->value = highestBid;
	}
	//HighestBidIncreased(bidderID, bidValue);
	highestBidder = bidderID;
	highestBid    = bidValue;

	return true;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!       Withdraw a bid that was overbid.       !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool SimpleAuction::withdraw(int bidderID)
{
	auto pr = pendingReturns.begin();
	for(; pr != pendingReturns.end(); pr++)
		if( pr->ID == bidderID) break;

//	if(pr == pendingReturns.end() && pr->ID != bidderID)
//		cout<<"\nError:: Bidder "+to_string(bidderID)+" not found.\n";

///	int amount = pendingReturns[bidderID];
	int amount = pr->value;
	if (amount > 0) 
	{
		// It is important to set this to zero because the recipient
		// can call this function again as part of the receiving call
		// before `send` returns.
		pr->value = 0;
		if ( !send(bidderID, amount) )
		{
			// No need to call throw here, just reset the amount owing.
			pr->value = amount;
			return false;
		}
	}
	return true;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*       This fun can also be impelemted       !*/
/* as method call to other smart contract. we  !*/
/* assume this fun always successful in send.  !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::send(int bidderID, int amount)
{
//	bidderAcount[bidderID] += amount;
	return 1;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*        End the auction and send the highest bid to the beneficiary.      !*/
/*!-------------------------------------------------------------------------!*/
/*! It's good guideline to structure fun that interact with other contracts !*/
/*! (i.e. they call functions or send Ether) into three phases: 1.checking  !*/
/*! conditions, 2.performing actions (potentially changing conditions), 3.  !*/
/*! interacting with other contracts. If these phases mixed up, other cont- !*/
/*! -ract could call back into current contract & modify state or cause     !*/
/*! effects (ether payout) to be performed multiple times. If fun called    !*/
/*! internally include interaction with external contracts, they also have  !*/ 
/*! to be considered interaction with external contracts.                   !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool SimpleAuction::auction_end()
{
	// 1. Conditions
	auto end     = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();

	if(now < auctionEnd) return false;

	if(!ended)
	{
//		cout<<"\nAuctionEnd has already been called.";
		return true;
	}
	// 2. Effects
	ended = true;

	// 3. Interaction
	///beneficiary.transfer(highestBid);
	beneficiaryAmount = highestBid;
	return true;
}


void SimpleAuction::AuctionEnded( )
{
	cout<<"\n======================================";
	cout<<"\n| Auction Winer ID "+to_string(highestBidder)
			+" |  Amount "+to_string(highestBid);
	cout<<"\n======================================\n";	
}



void SimpleAuction::state(int* hBidder, int *hBid, int *vPendingRet)
{
	*hBidder = highestBidder;
	*hBid    = highestBid;
	auto pr  = pendingReturns.begin();
	for(; pr != pendingReturns.end(); pr++)
	{
		vPendingRet[pr->ID] = pr->value;
//		cout<<"Bidder ID "<<pr->ID<<" value to return "
//			<<vPendingRet[pr->ID]<<endl;
	}
}




/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!            mint() called by minter thread.               !!!*/
/*!!!    initially credit some num of coins to each account    !!!*/
/*!!! (can be called by anyone but only minter can do changes) !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int Coin::mint(int t_ID, int receiver_iD, int amount)
{
	if(t_ID != minter) 
	{
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) can initialize the Accounts (Shared Objects)\n";
		return 0; //false not a minter.
	}
	auto it = listAccount.begin();
	for(; it != listAccount.end(); it++)
	{
		if(it->ID == receiver_iD) break;
	}
	it->bal = amount;
	return 1;      //AU execution successful.
}


void Coin::setCounterFlag(bool cFlag)
{
	useCounter = cFlag;
}

void Coin::reset()
{
	auto it = listAccount.begin();
	for(; it != listAccount.end(); it++){
		it->wCount = 0;
		it->rCount = 0;
	}
}



/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!       send() called by account holder thread.            !!!*/
/*!!!   To send some coin from his account to another account  !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int Coin::send(int sender_iD, int receiver_iD, int amount)
{
	auto sender = listAccount.begin();
	for(; sender != listAccount.end(); sender++)
	{
		if( sender->ID == sender_iD)
		{
			if(useCounter == true)
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
			else break;
		}
	}

//	if(amount > account[sender_iD]) return false; //not sufficent balance to send; AU is invalid.
	if( sender != listAccount.end() )
	{
		if(amount > sender->bal)
		{
			pthread_mutex_lock(&(sender->accLock));
			sender->wCount = 0;
			pthread_mutex_unlock(&(sender->accLock));
			return -2; //not sufficent balance to send; AU is invalid.
		}
	}
	else
	{
		cout<<"Sender ID" << sender_iD<<" not found\n";
		return 0;//AU execution fail;
	}
	
	auto reciver = listAccount.begin();
	for(; reciver != listAccount.end(); reciver++)
	{
		if( reciver->ID == receiver_iD)
		{
			if(useCounter == true)
			{
				pthread_mutex_lock(&(reciver->accLock));
				if(reciver->rCount == 0 && reciver->wCount == 0)
				{
					reciver->wCount = 1;
					pthread_mutex_unlock(&(reciver->accLock));
					break;
				}
				else
				{
					sender->wCount = 0;
					pthread_mutex_unlock(&(reciver->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
			else
				break;
		}
	}
	if( reciver != listAccount.end() )
	{
		sender->bal  -= amount;
		reciver->bal += amount;
		
		pthread_mutex_lock(&(sender->accLock));
		pthread_mutex_lock(&(reciver->accLock));
		sender->wCount  = 0;
		reciver->wCount = 0;
		pthread_mutex_unlock(&(reciver->accLock));
		pthread_mutex_unlock(&(sender->accLock));
		return 1; //AU execution successful.
	}
	else
	{
		pthread_mutex_lock(&(sender->accLock));
		sender->wCount = 0;
		pthread_mutex_unlock(&(sender->accLock));
		cout<<"Reciver ID" << receiver_iD<<" not found\n";
		return 0;// when id not found
	}
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!    get_balance() called by account holder thread.        !!!*/
/*!!!       To view number of coins in his account             !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int Coin::get_bal(int account_iD, int *bal)
{	
	auto acc = listAccount.begin();
	for(; acc != listAccount.end(); acc++)
	{
		if( acc->ID == account_iD)
		{
			if(useCounter == true)
			{
				pthread_mutex_lock(&(acc->accLock));
				if(acc->wCount == 0)
				{
					acc->rCount = 1;
					pthread_mutex_unlock(&(acc->accLock));
					break;
				}
				else
				{
					pthread_mutex_unlock(&(acc->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
			else
				break;
		}
	}
	if( acc != listAccount.end() )
	{
		*bal = acc->bal;
		pthread_mutex_lock(&(acc->accLock));
		acc->rCount = 0;
		pthread_mutex_unlock(&(acc->accLock));
		return 1; //AU execution successful.
	}
	else
	{
		cout<<"Account ID" << account_iD<<" not found\n";
		return 0;//AU execution fail.
	}
}



/*----------------------------------------------------
!        Give \`voter\` the right to vote on         !
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
//			cout<< "Error: Already Voted.\n";
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

	if(sender == voters.end() && sender->ID != senderID)
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";

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

		if(Ito == voters.end() && Ito->ID != to)
			cout<<"\nError:: voter to "+to_string(to)+" not found.\n";
	}
	// We found a loop in the delegation, not allowed.
	if (to == senderID) return -1;

	// Since \`sender\` is a reference, this
	// modifies \`voters[msg.sender].voted\`
	sender->voted    = true;
	sender->delegate = to;
	
	auto delegate = voters.begin();
	for(; delegate != voters.end(); delegate++)
		if( delegate->ID == to) break;

	if(delegate == voters.end() && delegate->ID != to)
		cout<<"\nError:: voter to "+to_string(to)+" not found.\n";

	if (delegate->voted) 
	{
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
			if( prop->ID == delegate->vote) break;

		if(prop == proposals.end() && prop->ID != delegate->vote)
			cout<<"\nError:: Proposal "+to_string(delegate->vote)+" not found.\n";


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

	if(sender == voters.end() && sender->ID != senderID)
		cout<<"\nError:: voter "+to_string(senderID)+" not found.\n";

	if (sender->voted) return 0;//already voted

	sender->voted = true;
	sender->vote  = proposal;

	// If \`proposal\` is out of the range of the array,
	// this will throw automatically and revert all changes.
	auto prop = proposals.begin();
	for(; prop != proposals.end(); prop++)
		if( prop->ID == proposal) break;

	if(prop == proposals.end() && prop->ID != proposal)
		cout<<"\nError:: Proposal "+to_string(proposal)+" not found.\n";

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

void Ballot::state(int ID, bool sFlag, int *ValidatorState)
{
//	cout<<"==========================\n";
	if(sFlag == false)//Proposal
	{
		auto prop = proposals.begin();
		for(; prop != proposals.end(); prop++)
			if( prop->ID == ID) break;

		if(prop == proposals.end() && prop->ID != ID)
			cout<<"\nError:: Proposal "+to_string(ID)+" not found.\n";

//		cout<<"Proposal ID \t= "  << prop->ID  <<endl;
//		cout<<"Proposal Name \t= "<< *(prop->name) <<endl;
//		cout<<"Vote Count \t= "  << prop->voteCount <<endl;
		ValidatorState[ID-1] = prop->voteCount;
//		cout<<"================================\n";
	}
	if(sFlag == true)
	{
		auto it = voters.begin();
		for(; it != voters.end(); it++)
			if( it->ID == ID) break;

		if(it == voters.end() && it->ID != ID)
			cout<<"\nError:: voter "+to_string(ID)+" not found.\n";

		ValidatorState[ID-VoterIdStart-1] = it->voted;
//		cout<<"Voter ID \t= "  <<it->ID<<endl;
//		cout<<"weight \t\t= "  <<it->weight<<endl;
//		cout<<"Voted \t\t= "   <<it->voted<<endl;
//		cout<<"Delegate \t= "  <<it->delegate<<endl;
//		cout<<"Vote Index -\t= "<<it->vote<<endl;
//		cout<<"================================\n";
	}
}
