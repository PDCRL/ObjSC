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
		//	std::shared_mutex tLock;
		};
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
			//	std::shared_lock lk1(&(acc.tLock).mutex, std::defer_lock);
			//	acc.tLock = PTHREAD_MUTEX_INITIALIZER;//initialize the lock.
			//	std::unique_lock<std::mutex> lck(acc.tLock,std::defer_lock);
				listAccount.push_back(acc);
				listAccountMiner.push_back(acc);
			}
		};


		//! STANDERED COIN CONTRACT FROM SOLIDITY CONVERTED IN C++ for validator
		bool mint(int t_ID, int receiver_iD, int amount);
		bool send(int sender_iD, int receiver_iD, int amount);
		bool get_bal(int account_iD, int *bal);


		//! CONTRACT miner functions return TRUE/1 if Try_Commit returns true
		bool mint_m(int t_ID, int receiver_iD, int amount);
		int send_m(int t_ID,int sender_iD,int receiver_iD,int amount,bool binFlag);
		int get_bal_m(int account_iD, int *bal, int t_ID, bool binFlag);
		void allUnlock();

		~Coin() { };
};
