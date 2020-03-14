#pragma once
#include <iostream>
#include <thread> 
#include <mutex> 
#include <atomic>
#include <list>
#include <shared_mutex>

using namespace std;

class Coin
{
	private:
		struct accNode
		{
			int ID;
			int bal;
		};
		list<accNode>listAccount;
		list<accNode>listAccountMiner;

		std::atomic<int> minter;         //! contract creator

	public:

		Coin(int m, int minter_id)      //! constructor (m: num of sharedObj)
		{
			minter  = minter_id;        //! minter is contract creator

			for(int i = 1; i <= m; i++)
			{
				accNode acc;
				acc.ID  = i;
				acc.bal = 0;
				listAccount.push_back(acc);
				listAccountMiner.push_back(acc);
			}
		};


		/*!!! STANDERED COIN CONTRACT FUNCTION FROM SOLIDITY CONVERTED IN C++ USED BY validator !!!*/
		bool mint(int t_ID, int receiver_iD, int amount);     //! serial function1 for validator.
		bool send(int sender_iD, int receiver_iD, int amount);//! concurrent function1 for validator.
		bool get_bal(int account_iD, int *bal);               //! concurrent function2 for validator.

		~Coin()
		{

		};//destructor
};
