#pragma once
#include "ostm-lib/ostm.cpp"

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

		std::atomic<int> minter;         //! contract creator

	public:

		voidVal* structVal = new voidVal( sizeof(accNode) );
		LinkedHashNode* tb = new LinkedHashNode(0, 0, structVal);
		OSTM* lib          = new OSTM(tb);

		HashMap* hasht = lib->hash_table;

		Coin(int m, int minter_id)      //! constructor (m: num of sharedObj)
		{
			minter  = minter_id;        //! minter is contract creator

			for(int i = 1; i <= m; i++)
			{
				accNode acc;
				acc.ID = i;
				acc.bal = 0;
				listAccount.push_back(acc);

				(*(accNode*)tb->val).ID  = i;
				(*(accNode*)tb->val).bal = 0;

				list<int> conf_list;
				trans_log* txlog;
				STATUS ops, txs;
				txlog = lib->begin();

				ops = lib->t_insert(txlog, 0, i, 0, tb);
				if(ABORT != ops)
					txs = lib->tryCommit(txlog, conf_list, tb);
				if(ABORT == txs)
					cout<<"\nError!!Failed to create Shared Object\n";
			}
		};


		/*!!! STANDERED COIN CONTRACT FUNCTION FROM SOLIDITY CONVERTED IN C++ USED BY validator !!!*/
		bool mint(int t_ID, int receiver_iD, int amount);     //! serial function1 for validator.
		bool send(int sender_iD, int receiver_iD, int amount);//! concurrent function1 for validator.
		bool get_bal(int account_iD, int *bal);               //! concurrent function2 for validator.


		/*!!! CONTRACT with 3 functions for miner return TRUE/1 if Try_Commit SUCCESS !!!*/
		bool mint_m(int t_ID, int receiver_iD, int amount, int *time_stamp);                                    //! serial function1 for miner.
		int send_m(int t_ID, int sender_iD, int receiver_iD, int amount, int *time_stamp, list<int>&conf_list); //! concurrent function1 for miner.
		bool get_bal_m(int account_iD, int *bal, int t_ID, int *time_stamp, list<int>&conf_list);               //! concurrent function2 for miner.


		~Coin()
		{
			delete lib;
		};//destructor
};
