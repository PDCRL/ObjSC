#include "SimpleAuction.h"

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!!!FUNCTIONS FOR VALIDATOR !!!*/
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
//! RESETING TIMEPOIN FOR VALIDATOR.
void SimpleAuction::reset()
{
	beneficiaryAmount = 0;
	start = std::chrono::system_clock::now();
//	cout<<"\nAUCTION [Start Time = "<<0;
//	cout<<"] [End Time = "<<auctionEnd<<"] milliseconds\n";
}


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*! VALIDATOR:: Bid on the auction with the value sent together with this  !*/
/*! transaction. The value will only be refunded if the auction is not won.!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool SimpleAuction::bid( int payable, int bidderID, int bidValue )
{
	// No arguments are necessary, all information is already part of trans
	// -action. The keyword payable is required for the function to be able
	// to receive Ether. Revert the call if the bidding period is over.
	
	auto end = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();

	if( now > auctionEnd)
	{
//		cout<<"\nAuction already ended.";
		return false;
	}
	// If the bid is not higher, send the
	// money back.
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
		
		list<PendReturn>::iterator pr = pendingReturns.begin();
		for(; pr != pendingReturns.end(); pr++)
		{
			if( pr->ID == highestBidder)
				break;
		}
		if(pr == pendingReturns.end() && pr->ID != highestBidder)
		{
			cout<<"\nError:: Bidder "+to_string(highestBidder)+" not found.\n";
		}
		pr->value = highestBid;
	}
	//HighestBidIncreased(bidderID, bidValue);
	highestBidder = bidderID;
	highestBid    = bidValue;

	return true;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*! VALIDATOR:: Withdraw a bid that was overbid. !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool SimpleAuction::withdraw(int bidderID)
{
	list<PendReturn>::iterator pr = pendingReturns.begin();
	for(; pr != pendingReturns.end(); pr++)
	{
		if( pr->ID == bidderID)
			break;
	}
	if(pr == pendingReturns.end() && pr->ID != bidderID)
	{
		cout<<"\nError:: Bidder "+to_string(bidderID)+" not found.\n";
	}

///	int amount = pendingReturns[bidderID];
	int amount = pr->value;
	if (amount > 0) 
	{
		// It is important to set this to zero because the recipient
		// can call this function again as part of the receiving call
		// before `send` returns.
///		pendingReturns[bidderID] = 0;
		pr->value = 0;
		if ( !send(bidderID, amount) )
		{
			// No need to call throw here, just reset the amount owing.
///			pendingReturns[bidderID] = amount;
			pr->value = amount;
			return false;
		}
	}
	return true;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* VALIDATOR:: this fun can also be impelemted !*/
/* as method call to other smart contract. we  !*/
/* assume this fun always successful in send.  !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::send(int bidderID, int amount)
{
//	bidderAcount[bidderID] += amount;
	return 1;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* VALIDATOR:: End the auction and send the highest bid to the beneficiary. !*/
/*!_________________________________________________________________________!*/
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

	if(now < auctionEnd)
    {
//    	cout<< "\nAuction not yet ended.";
    	return false;
    }
	if(!ended)
    {
//    	AuctionEnded(highestBidder, highestBid);
//		cout<<"\nAuctionEnd has already been called.";
    	return true;
	}
	// 2. Effects
	ended = true;
//	AuctionEnded( );

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


/*~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!! FUNCTIONS FOR MINER !!!*/
/*~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*! MINER:: Bid on the auction with the value sent together with this      !*/
/*! transaction. The value will only be refunded if the auction is not won.!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::bid_m( int payable, int bidderID, int bidValue, 
							int *ts, list<int> &cList)
{
	auto end     = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();

	if( now > auctionEnd)
	{
		return -1;//! invalid AUs: Auction already ended.
	}
	
	voidVal* structTB        = new voidVal( sizeof(int) );
	LinkedHashNode* tbBid    = new LinkedHashNode(0, 0, structTB);
	LinkedHashNode* tbBidder = new LinkedHashNode(0, 0, structTB);
	LinkedHashNode* tbBidNew = new LinkedHashNode(0, 0, structTB);
	
	trans_log* txlog;
	STATUS ops;
	STATUS txs         = ABORT;
	int* highestBid    = new int;
	int* highestBidder = new int;
	*highestBid        = 0;
	*highestBidder     = 0;
	txlog              = lib->begin();
	*ts                = txlog->tid; //return time_stamp to caller.
	
	//! highestBid SObj id is maxBiderID+3.
	(*(int*)tbBid->val) = 0;
	ops = lib->t_read(txlog, 0, maxBiderID+3, highestBid, tbBid);
	*highestBid = (*(int*)tbBid->val);

	if(ABORT == ops) return 0;//AU aborted.

	//! highestBidder SObj id is maxBiderID+2.
	(*(int*)tbBidder->val) = 0;
	ops = lib->t_read(txlog, 0, maxBiderID+2, highestBidder, tbBidder);
	*highestBidder = (*(int*)tbBidder->val);

	if(ABORT == ops) return 0;//AU aborted.

	//! invalid AUs: There already is a higher bid.
	if( bidValue <= *highestBid ) return -1;

	// If the bid is no longer higher, send the money back to old bidder.
	if (*highestBid != 0)
		lib->t_write(txlog, 0, *highestBidder, *highestBid, tbBid);//highestBidder

	// increase the highest bid.
	(*(int*)tbBidNew->val) = bidderID;
	lib->t_write(txlog, 0, maxBiderID+2, bidderID, tbBidNew);//new highestBidder

	(*(int*)tbBidNew->val) = bidValue;
	lib->t_write(txlog, 0, maxBiderID+3, bidValue, tbBidNew);//new highestBid

	(*(int*)tbBidNew->val) = 0;
	txs = lib->bto_TryComit(txlog, cList, tbBidNew);

	if(ABORT == txs) return 0;//AU aborted.

	else return 1;//bid successfully done; AU execution successful.
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*! MINER:: Withdraw a bid that was overbid. !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::withdraw_m(int bidderID, int *ts, list<int> &cList)
{
	voidVal* structTB      = new voidVal( sizeof(int) );
	LinkedHashNode* tbBval = new LinkedHashNode(0, 0, structTB);


	trans_log* txlog;
	STATUS ops;
	STATUS txs         = ABORT;
	int* bidderVal     = new int;
	*bidderVal         = 0;
	txlog              = lib->begin();
	*ts                = txlog->tid; //return time_stamp to caller.
	
	(*(int*)tbBval->val) = 0;
	ops = lib->t_read(txlog, 0, bidderID, bidderVal, tbBval);
	*bidderVal = (*(int*)tbBval->val);
	
	if(ABORT == ops) return 0;//AU aborted.
		
	//int amount = pendingReturns[bidderID];
	int amount = *bidderVal;
	if(amount > 0) 
	{
		//pendingReturns[bidderID] = 0;
		bidderVal = 0;
		(*(int*)tbBval->val) = 0;
		lib->t_write(txlog, 0, bidderID, 0, tbBval);
		
		if(!send(bidderID, amount))
		{
			// No need to call throw here, just reset the amount owing.
			*bidderVal = amount;
			(*(int*)tbBval->val) = amount;
			lib->t_write(txlog, 0, bidderID, *bidderVal, tbBval);

			txs = lib->bto_TryComit(txlog, cList, tbBval);
			if(ABORT == txs) return 0;//AU aborted.
			else return -1;//AU invalid.
		}
	}
	txs = lib->bto_TryComit(txlog, cList, tbBval);
	if(ABORT == txs) return 0;//AU aborted.
	else return 1;//withdraw successfully done; AU execution successful.
}


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* MINER:: End the auction and send the highest bid to the beneficiary. !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::auction_end_m(int *ts, list<int> &cList)
{
	auto end     = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();

	if(now < auctionEnd)
    {
    	//! Auction not yet ended.
    	return -1;
    }

	voidVal* structTB      = new voidVal( sizeof(int) );
	LinkedHashNode* tbEnd  = new LinkedHashNode(0, 0, structTB);
	LinkedHashNode* tbHBid = new LinkedHashNode(0, 0, structTB);
	(*(int*)tbEnd->val)    = 0;
	(*(int*)tbHBid->val)   = 0;

	trans_log* txlog;
	STATUS ops;
	STATUS txs   = ABORT;
	int* endFlag = new int;
	*endFlag     = 0;
	txlog        = lib->begin();
	*ts          = txlog->tid; //return time_stamp to caller.

	ops = lib->t_read(txlog, 0, maxBiderID+1, endFlag, tbEnd);
	if(ABORT == ops) return 0;//AU aborted.

//	int ended = *endFlag;
	int ended = (*(int*)tbEnd->val);
	if( !ended )
    {
		//! AuctionEnd has already been called.
    	return 1;
	}
//	ended = yes;
	(*(int*)tbEnd->val) = 0;
	lib->t_write(txlog, 0, maxBiderID+1, 0, tbEnd);

	int* hBidder = new int;
	int* hBid    = new int;

	ops = lib->t_read(txlog, 0, maxBiderID+2, hBidder, tbHBid);
	if(ABORT == ops) return 0;//AU aborted.

	*hBidder = (*(int*)tbHBid->val);
	
	(*(int*)tbHBid->val) = 0;
	ops = lib->t_read(txlog, 0, maxBiderID+3, hBid, tbHBid);
	if(ABORT == ops) return 0;//AU aborted.

	*hBid = (*(int*)tbHBid->val);

	beneficiaryAmount = *hBid;

	txs = lib->bto_TryComit(txlog, cList, tbHBid);
	if(ABORT == txs) return 0;//AU aborted.
	else return 1;//withdraw successfully done; AU execution successful.
}

bool SimpleAuction::AuctionEnded_m( )
{
	voidVal* structTB       = new voidVal( sizeof(int) );
	LinkedHashNode* tbHBid  = new LinkedHashNode(0, 0, structTB);
	LinkedHashNode* tbHBidr = new LinkedHashNode(0, 0, structTB);
	(*(int*)tbHBid->val)    = 0;
	(*(int*)tbHBidr->val)   = 0;
	
	trans_log* txlog;
	STATUS ops;
	STATUS txs   = ABORT;
	int* hBid    = new int;
	int* hBider  = new int;
	*hBid        = 0;
	*hBider      = 0;
	txlog        = lib->begin();

	ops = lib->t_read(txlog, 0, maxBiderID+3, hBid, tbHBid);//! highestBid SObj
	if(ABORT == ops) return false;//AU aborted.
	
	ops = lib->t_read(txlog, 0, maxBiderID+2, hBider, tbHBidr);//! highestBidder SObj
	if(ABORT == ops) return false;//AU aborted.
	

	cout<<"\n======================================";
	cout<<"\n| Auction Winer ID "+to_string((*(int*)tbHBidr->val))
			+" |  Amount "+to_string((*(int*)tbHBid->val));
	cout<<"\n======================================\n";	
	list<int> cList;
	(*(int*)tbHBidr->val) = 0;
	txs = lib->bto_TryComit(txlog, cList, tbHBidr);
	if(ABORT == txs) return false;//AU aborted.
	else return true;//auction_end successfully done; AU execution successful.
}
