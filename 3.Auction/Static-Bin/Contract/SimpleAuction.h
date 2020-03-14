#pragma once
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <list>
#include <sys/time.h>

using namespace std;


class SimpleAuction
{
	public:
		// Parameters of the auction. Times are either absolute unix time-
		// -stamps (seconds since 1970-01-01) or time periods in seconds.
		std::chrono::time_point<std::chrono::system_clock> now, start;

		// beneficiary of the auction.
		int beneficiary;
		int beneficiaryAmount = 0;


		std::atomic<int> auctionEnd;
		// Current state of the auction (USED BY VALIDATOR).
		std::atomic<int> highestBidder;
		std::atomic<int> highestBid;

		struct PendReturn
		{
			int ID;
			int value;
		};
		// Allowed withdrawals of previous bids.
		// mapping(address => uint) pendingReturns;
		list<PendReturn>pendingReturns;

		// Set to true at the end, disallows any change (USED BY VALIDATOR).
		std::atomic<bool> ended;

		// The following is a so-called natspec comment,recognizable by the 3
		// slashes. It will be shown when the user is asked to confirm a trans.
		// Create a simple auction with \`_biddingTime`\, seconds bidding
		// time on behalf of the beneficiary address \`_beneficiary`\.


		// CONSTRUCTOR.
		SimpleAuction( int _biddingTime, int _beneficiary, int numBidder)
		{
			beneficiary    = _beneficiary;
			highestBidder  = 0;
			highestBid     = 0;
			ended          = false;

			for(int b = 0; b <= numBidder; b++)
			{
				PendReturn pret;
				pret.ID    = b;
				pret.value = 0;
				pendingReturns.push_back(pret);

			}
			start = std::chrono::system_clock::now();
//			cout<<"AUCTION [Start Time = "<<0;
			auctionEnd = _biddingTime;
//			cout<<"] [End Time = "<<auctionEnd<<"] milliseconds";
		};



		// Bid on the auction with the value sent together with transaction.
		// The value will only be refunded if the auction is not won.
		bool bid( int payable, int bidderID, int bidValue );

		// Withdraw a bid that was overbid.
		bool withdraw(int bidderID);
		
		// End the auction and send the highest bid to the beneficiary.
		bool auction_end();
		void AuctionEnded( );
		int send(int bidderID, int amount);
		void reset(int _biddingTime);
		void state(int *hBidder, int *hBid, int *vPendingRet);

	~SimpleAuction()
	{

	};//destructor
};
