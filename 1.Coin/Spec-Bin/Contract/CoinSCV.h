#pragma once
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <list>
#include <thread>
#include <shared_mutex>

using namespace std;

class Coin
{
	private:
		struct accNode {
			int ID;
			int bal;
			int rCount;//increase count by transaction that is reading dataitem.
			int wCount;//increase count by transaction that is writing to dataitem.
			pthread_mutex_t accLock;// lock with each account id used at validator.
		};
		
		std::atomic<bool> useCounter;		
		list<accNode>listAccount;
		list<accNode>listAccountMiner;
		std::shared_mutex tLock[5000];
		std::atomic<int> minter; //! contract creator

	public:
		Coin(int m, int minter_id) //! constructor (m: num of sharedObj)
		{
			minter  = minter_id;   //! minter is contract creator
			for(int i = 1; i <= m; i++) {

				accNode acc;
				acc.ID  = i;
				acc.bal = 0;
				acc.rCount  = 0;
				acc.wCount  = 0;
				acc.accLock = PTHREAD_MUTEX_INITIALIZER;//init lock for each id.
				listAccountMiner.push_back(acc);
				listAccount.push_back(acc);
			}
		};


		//used for malicious miner
		void reset();
		void setCounterFlag(bool cFlag);

		//! STANDERED COIN CONTRACT FUNCTION FROM SOLIDITY CONVERTED IN C++.
		int mint(int t_ID, int receiver_iD, int amount);
		int send(int sender_iD, int receiver_iD, int amount);
		int get_bal(int account_iD, int *bal);


		//! CONTRACT miner functions return TRUE/1 if Try_Commit returns true.
		bool mint_m(int t_ID, int receiver_iD, int amount);
		int send_m(int t_ID,int sender_iD,int receiver_iD,int amount,bool binFlag);
		int get_bal_m(int account_iD, int *bal, int t_ID, bool binFlag);
		void allUnlock();

		~Coin() { };
};
