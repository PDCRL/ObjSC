#pragma once
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <list>
#include <sys/time.h>
#include <shared_mutex>

using namespace std;


class SimpleAuction
{
	public:
		// Parameters of the auction. Times are either absolute unix time-
		// -stamps (seconds since 1970-01-01) or time periods in seconds.
		std::chrono::time_point<std::chrono::system_clock> now, start;

		int nBidder;
		// beneficiary of the auction.
		int beneficiary;
		int beneficiaryAmount = 0;
		std::atomic<int> auctionEnd;
		// Current state of the auction.
		std::atomic<int> highestBidder;
		std::atomic<int> highestBid;
		struct PendReturn {
			int ID;
			int value;
		};
		// Allowed withdrawals of previous bids.
		list<PendReturn>pendingReturns;
		list<PendReturn>pendingReturnsM;

		std::shared_mutex tLock[5000];
		// Set to true at the end, disallows any change.
		std::atomic<bool> ended;
		SimpleAuction( int _biddingTime, int _beneficiary, int numBidder) {
			nBidder        = numBidder;
			beneficiary    = _beneficiary;
			highestBidder  = 0;
			highestBid     = 0;
			ended          = false;
			for(int b = 0; b <= numBidder; b++) {
				PendReturn pret;
				pret.ID    = b;
				pret.value = 0;
				pendingReturns.push_back(pret);
				pendingReturnsM.push_back(pret);
			}
			start = std::chrono::system_clock::now();
			auctionEnd = _biddingTime;
		};



		//! STANDERED COIN CONTRACT FROM SOLIDITY CONVERTED IN C++ for validator
		// Bid on the auction with the value sent together with transaction.
		// The value will only be refunded if the auction is not won.
		bool bid( int payable, int bidderID, int bidValue );
		bool withdraw(int bidderID);// Withdraw a bid that was overbid.
		// End the auction and send the highest bid to the beneficiary.
		bool auction_end();
		void AuctionEnded( );
		int send(int bidderID, int amount);
		void reset(int _biddingTime);
		void state(int *hBidder, int *hBid, int *vPendingRet);
		
		
		//! CONTRACT miner functions return TRUE/1 if Try_Commit returns true
		int bid_m( int payable, int bidderID, int bidValue, bool binFlag);
		int withdraw_m(int bidderID, bool binFlag);// Withdraw a bid that was overbid.
		void state_m(int *hBidder, int *hBid, int *mPendingRet);
		bool auction_end_m();
		void allUnlock();

		~SimpleAuction() { };//destructor
};
