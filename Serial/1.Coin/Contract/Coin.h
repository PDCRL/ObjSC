#pragma once
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
		Coin(int m, int minter_id)       //! constructor
		{
			long long error_id;
			minter  = minter_id;         //! minter is contract creator

			for(int i = 1; i <= m; i++)
			{				
				accNode acc;
				acc.ID = i;
				acc.bal = 0;				
				listAccount.push_back(acc);
			}
		};

		bool mint(int t_ID, int receiver_iD, int amount);
		bool send(int sender_iD, int receiver_iD, int amount);
		bool get_bal(int account_iD, int *bal);
		
		~Coin()
		{

		};//destructor
};
