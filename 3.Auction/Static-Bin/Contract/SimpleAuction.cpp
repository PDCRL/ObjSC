#include "SimpleAuction.h"


//! RESETING TIME
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
	auto pr = pendingReturns.begin();
	for(; pr != pendingReturns.end(); pr++)
	{
		vPendingRet[pr->ID] = pr->value;
//		cout<<"Bidder ID "<<pr->ID<<" value to return "
//			<<vPendingRet[pr->ID]<<endl;
	}
}


