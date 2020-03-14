#include "Mix.h"


//==============================================================================
//==============================Validator SC Fun================================
//==============================================================================
//! RESETING State
void SimpleAuction::reset(int _biddingTime)
{
	beneficiaryAmount = 0;
	start = std::chrono::system_clock::now();
	auctionEnd = _biddingTime;
	auto pr = pendingReturns.begin();
	for(; pr != pendingReturns.end(); pr++) pr->value = 0;
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
	if( now > auctionEnd) return false;

	// If the bid is not higher, send the money back.
	if( bidValue <= highestBid) return false;

	if (highestBid != 0) 
	{
		// Sending back the money by simply using highestBidder.send(highestBid)
		// is a security risk because it could execute an untrusted contract.
		// It is always safer to let recipients withdraw their money themselves.
		//pendingReturns[highestBidder] += highestBid;
		
		auto pr = pendingReturns.begin();
		for(; pr != pendingReturns.end(); pr++)
			if( pr->ID == highestBidder) break;

	//	if(pr == pendingReturns.end() && pr->ID != bidderID)
	//		cout<<"\nError:: Bidder "+to_string(bidderID)+" not found.\n";

		pr->value = highestBid;
	}
	if( bidValue > highestBid) {
		highestBidder = bidderID;
		highestBid    = bidValue;
	}
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


	int amount = pr->value;
	if (amount > 0) {
		// It is important to set this to zero because the recipient
		// can call this function again as part of the receiving call
		// before `send` returns.
		pr->value = 0;
		if ( !send(bidderID, amount) ) {
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
	if(!ended) return true;

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
		vPendingRet[pr->ID] = pr->value;
}




//==============================================================================
//===============================Miner SC Fun===================================
//==============================================================================
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!        Bid on the auction with the value sent together with this       !*/
/*! transaction. The value will only be refunded if the auction is not won.!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::bid_m( int payable, int bidderID, int bidValue, bool binFlag)
{
	// No arguments are necessary, all information is already part of trans
	// -action. The keyword payable is required for the function to be able
	// to receive Ether. Revert the call if the bidding period is over.
	auto end     = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();
	if( now > auctionEnd) return false;

	// If the bid is not higher, send the money back.
	if( bidValue <= highestBid) return false;

	if (highestBid != 0) 
	{
		// Sending back the money by simply using highestBidder.send(highestBid)
		// is a security risk because it could execute an untrusted contract.
		// It is always safer to let recipients withdraw their money themselves.
		//pendingReturns[highestBidder] += highestBid;
		
		auto pr = pendingReturnsM.begin();
		for(; pr != pendingReturnsM.end(); pr++)
			if( pr->ID == highestBidder) break;

		if( pr != pendingReturnsM.end() ) {
			if(binFlag == true) {
				bool x = tLock[highestBidder].try_lock();
				if(x == false) return -1;
			}
		}
		else {
//			cout<<"Account ID" << highestBidder<<" not found\n";
			return 0;//AU execution fail.
		}
		pr->value = highestBid;
	}
	if( bidValue > highestBid) {
		highestBidder = bidderID;
		highestBid    = bidValue;
	}
	return 1;
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!       Withdraw a bid that was overbid.       !*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int SimpleAuction::withdraw_m(int bidderID, bool binFlag)
{
	auto pr = pendingReturnsM.begin();
	for(; pr != pendingReturnsM.end(); pr++)
		if( pr->ID == bidderID) break;

	if( pr != pendingReturnsM.end() ) {
		if(binFlag == true) {
			bool x = tLock[bidderID].try_lock();
			if(x == false) return -1;
		}
	}
	else {
		cout<<"Account ID" << bidderID<<" not found\n";
		return 0;//AU execution fail.
	}

	int amount = pr->value;
	if (amount > 0) {
		// It is important to set this to zero because the recipient
		// can call this function again as part of the receiving call
		// before `send` returns.
		pr->value = 0;
		if ( !send(bidderID, amount) ) {
			// No need to call throw here, just reset the amount owing.
			pr->value = amount;
			return 0;
		}
	}
	return 1;
}


bool SimpleAuction::auction_end_m()
{
	// 1. Conditions
	auto end     = high_resolution_clock::now();
	double_t now = duration_cast<milliseconds>( end - start ).count();
	if(now < auctionEnd) return false;
	if(!ended) return true;

	// 2. Effects
	ended = true;

	// 3. Interaction
	///beneficiary.transfer(highestBid);
	beneficiaryAmount = highestBid;
	return true;
}

void SimpleAuction::state_m(int* hBidder, int *hBid, int *mPendingRet)
{
	*hBidder = highestBidder;
	*hBid    = highestBid;
	auto pr  = pendingReturnsM.begin();
	for(; pr != pendingReturnsM.end(); pr++)
		mPendingRet[pr->ID] = pr->value;
}

void SimpleAuction::allUnlock() {
	for(int i = 0; i <= nBidder; i++)
		tLock[i].unlock();
}





//==============================================================================
//===============================Validator SC Fun===============================
//==============================================================================
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!            mint() called by minter thread.               !!!*/
/*!!!    initially credit some num of coins to each account    !!!*/
/*!!! (can be called by anyone but only minter can do changes) !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool Coin::mint(int t_ID, int receiver_iD, int amount)
{
	if(t_ID != minter) {
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) "
			<<" can initialize the Accounts (Shared Objects)\n";
		return false; //false not a minter.
	}
	auto it = listAccount.begin();
	for(; it != listAccount.end(); it++) {
		if( (it)->ID == receiver_iD) (it)->bal = amount;
	}

//	account[receiver_iD] = account[receiver_iD] + amount;
	return true;      //AU execution successful.
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!       send() called by account holder thread.            !!!*/
/*!!!   To send some coin from his account to another account  !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool Coin::send(int sender_iD, int receiver_iD, int amount)
{
	auto sender = listAccount.begin();
	for(; sender != listAccount.end(); sender++)
		if( sender->ID == sender_iD) break;

	if( sender != listAccount.end() ) {
		//not sufficent balance to send; AU is invalid.
		if(amount > sender->bal) return false;
	}
	else {
		cout<<"Sender ID" << sender_iD<<" not found\n";
		return false;//AU execution fail;
	}

	auto reciver = listAccount.begin();
	for(; reciver != listAccount.end(); reciver++) {
		if( reciver->ID == receiver_iD) break;
	}

	if( reciver != listAccount.end() ) {
		sender->bal  -= amount;
		reciver->bal += amount;
		return true; //AU execution successful.
	}
	else {
		cout<<"Reciver ID" << receiver_iD<<" not found\n";
		return false;// when id not found
	}
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!    get_balance() called by account holder thread.        !!!*/
/*!!!       To view number of coins in his account             !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool Coin::get_bal(int account_iD, int *bal)
{
	auto acc = listAccount.begin();
	for(; acc != listAccount.end(); acc++)
		if( acc->ID == account_iD) break;

	if( acc != listAccount.end() ) {
		*bal = acc->bal;
		return true; //AU execution successful.
	}
	else {
		cout<<"Account ID" << account_iD<<" not found\n";
		return false;//AU execution fail.
	}
}



//==============================================================================
//===============================Miner SC Fun===================================
//==============================================================================
bool Coin::mint_m(int t_ID, int receiver_iD, int amount) 
{
	if(t_ID != minter) 
	{
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) "
			<<"can initialize the Accounts (Shared Objects)\n";
		return false; //false not a minter.
	}
	auto it = listAccountMiner.begin();
	for(; it != listAccountMiner.end(); it++)
		if( (it)->ID == receiver_iD) (it)->bal = amount;

	return true; //AU execution successful.
}


int Coin::send_m(int t_ID,int sender_iD,int receiver_iD,int amount,bool binFlag)
{
	auto sender = listAccountMiner.begin();
	for(; sender != listAccountMiner.end(); sender++) {
		if( sender->ID == sender_iD) break;
	}

	if( sender != listAccountMiner.end() ) {
		if(binFlag == true) {
			bool x = tLock[sender_iD-CoinIdStart].try_lock();
			if(x == false) {
				//not sufficent balance to send; AU is invalid.
				if(amount > sender->bal) 
					return 0; // AU is inavlid.
				else return -1; // Some other Tx has done update already.
			}
			//not sufficent balance to send; AU is invalid.
			else 
				if(amount > sender->bal) return 0;
		}
		else {
			//not sufficent balance to send; AU is invalid.
			if(amount > sender->bal) return 0;
		}
	}
	else {
		cout<<"Sender ID" << sender_iD<<" not found\n";
		return 0;//AU execution fail;
	}

	auto reciver = listAccountMiner.begin();
	for(; reciver != listAccountMiner.end(); reciver++)
		if( reciver->ID == receiver_iD) break;

	if( reciver != listAccountMiner.end() ) {
		if(binFlag == true) {
			bool x = tLock[receiver_iD-CoinIdStart].try_lock();
			if(x == false) return -1;
		}
		sender->bal  -= amount;
		reciver->bal += amount;
		return 1; //AU execution successful.
	}
	else {
		cout<<"Reciver ID" << receiver_iD<<" not found\n";
		return 0;// when id not found
	}
}


int Coin::get_bal_m(int account_iD, int *bal, int t_ID, bool binFlag) {
	auto acc = listAccountMiner.begin();
	for(; acc != listAccountMiner.end(); acc++)
		if( acc->ID == account_iD) break;

	if( acc != listAccountMiner.end() ) {
		if(binFlag == true) {
			bool x = tLock[account_iD-CoinIdStart].try_lock_shared();
			if(x == false) return -1;
		}
		*bal = acc->bal;
		return 1; //AU execution successful.
	}
	else {
		cout<<"Account ID" << account_iD<<" not found\n";
		return 0;//AU execution fail.
	}
	*bal = acc->bal;
	return 1; //AU execution successful.
}

void Coin::allUnlock() {
	for(int i = 0; i <= nAccount; i++)
		tLock[i].unlock();
}


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
			State[ID-VoterIdStart-1] = it->voted;
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
			bool x = vtLock[senderID-VoterIdStart].try_lock();
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
			bool x = vtLock[to-VoterIdStart].try_lock();
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
				bool x = vtLock[to-VoterIdStart].try_lock();
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
			bool x = vtLock[senderID-VoterIdStart].try_lock();
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
			State[ID-VoterIdStart-1] = it->voted;
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
