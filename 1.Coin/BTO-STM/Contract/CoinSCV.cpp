#include "CoinSCV.h"


/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!!!functions for validator !!!*/
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
void Coin::setCounterFlag(bool cFlag)
{
	useCounter = cFlag;
}

void Coin::reset()
{
	list<accNode>::iterator it = listAccount.begin();
	for(; it != listAccount.end(); it++){
		it->wCount = 0;
		it->rCount = 0;
	}
}



/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!            mint() called by minter thread.               !!!*/
/*!!!    initially credit some num of coins to each account    !!!*/
/*!!! (can be called by anyone but only minter can do changes) !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int Coin::mint(int t_ID, int receiver_iD, int amount)
{
	if(t_ID != minter) 
	{
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) can initialize the Accounts (Shared Objects)\n";
		return 0; //false not a minter.
	}
	list<accNode>::iterator it = listAccount.begin();
	for(; it != listAccount.end(); it++)
	{
		if(it->ID == receiver_iD) break;
	}
	it->bal = amount;
	return 1;      //AU execution successful.
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!       send() called by account holder thread.            !!!*/
/*!!!   To send some coin from his account to another account  !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int Coin::send(int sender_iD, int receiver_iD, int amount)
{
	list<accNode>::iterator sender = listAccount.begin();
	for(; sender != listAccount.end(); sender++)
	{
		if( sender->ID == sender_iD)
		{
			if(useCounter == true)
			{
				pthread_mutex_lock(&(sender->accLock));
				if(sender->rCount == 0 && sender->wCount == 0)
				{
					sender->wCount = 1;
					pthread_mutex_unlock(&(sender->accLock));
					break;
				}
				else
				{
					pthread_mutex_unlock(&(sender->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
			else break;
		}
	}

//	if(amount > account[sender_iD]) return false; //not sufficent balance to send; AU is invalid.
	if( sender != listAccount.end() )
	{
		if(amount > sender->bal)
		{
			pthread_mutex_lock(&(sender->accLock));
			sender->wCount = 0;
			pthread_mutex_unlock(&(sender->accLock));
			return -2; //not sufficent balance to send; AU is invalid.
		}
	}
	else
	{
		cout<<"Sender ID" << sender_iD<<" not found\n";
		return 0;//AU execution fail;
	}
	
	list<accNode>::iterator reciver = listAccount.begin();
	for(; reciver != listAccount.end(); reciver++)
	{
		if( reciver->ID == receiver_iD)
		{
			if(useCounter == true)
			{
				pthread_mutex_lock(&(reciver->accLock));
				if(reciver->rCount == 0 && reciver->wCount == 0)
				{
					reciver->wCount = 1;
					pthread_mutex_unlock(&(reciver->accLock));
					break;
				}
				else
				{
					sender->wCount = 0;
					pthread_mutex_unlock(&(reciver->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
			else
				break;
		}
	}
	if( reciver != listAccount.end() )
	{
		sender->bal  -= amount;
		reciver->bal += amount;
		
		pthread_mutex_lock(&(sender->accLock));
		pthread_mutex_lock(&(reciver->accLock));
		sender->wCount  = 0;
		reciver->wCount = 0;
		pthread_mutex_unlock(&(reciver->accLock));
		pthread_mutex_unlock(&(sender->accLock));
		return 1; //AU execution successful.
	}
	else
	{
		pthread_mutex_lock(&(sender->accLock));
		sender->wCount = 0;
		pthread_mutex_unlock(&(sender->accLock));
		cout<<"Reciver ID" << receiver_iD<<" not found\n";
		return 0;// when id not found
	}
}

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!    get_balance() called by account holder thread.        !!!*/
/*!!!       To view number of coins in his account             !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int Coin::get_bal(int account_iD, int *bal)
{	
	list<accNode>::iterator acc = listAccount.begin();
	for(; acc != listAccount.end(); acc++)
	{
		if( acc->ID == account_iD)
		{
			if(useCounter == true)
			{
				pthread_mutex_lock(&(acc->accLock));
				if(acc->wCount == 0)
				{
					acc->rCount = 1;
					pthread_mutex_unlock(&(acc->accLock));
					break;
				}
				else
				{
					pthread_mutex_unlock(&(acc->accLock));
					return -1;//miner is malicious not given proper dependencies.
				}
			}
			else
				break;
		}
	}
	if( acc != listAccount.end() )
	{
		*bal = acc->bal;
		pthread_mutex_lock(&(acc->accLock));
		acc->rCount = 0;
		pthread_mutex_unlock(&(acc->accLock));
		return 1; //AU execution successful.
	}
	else
	{
		cout<<"Account ID" << account_iD<<" not found\n";
		return 0;//AU execution fail.
	}
}




/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!!!  functions for miner   !!!*/
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
bool Coin::mint_m(int t_ID, int receiver_iD, int amount, int* time_stamp) 
{
	if(t_ID != minter)
	{
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) can initialize the Accounts (Shared Objects)\n";
		return false;//false not a minter.
	}

	voidVal* tb1       = new voidVal( sizeof(int) );
	LinkedHashNode* tb = new LinkedHashNode(0, 0, tb1);

	list<int> conf_list;
	trans_log* txlog;
	STATUS txs  = ABORT;
	STATUS ops  = ABORT;
	int* val    = new int;
	txlog       = lib->begin();
	*time_stamp = txlog->tid; //return time_stamp to user.
	
	ops = lib->t_read(txlog, 0, receiver_iD, val, tb);
	if(ABORT != ops)
	{
		*val += amount;
		(*(int*)tb->val) = amount;
		ops = lib->t_write(txlog, 0, receiver_iD, *val, tb);
		txs = lib->bto_TryComit(txlog, conf_list, tb);
	}
	if(ABORT == txs)
	{
//		cout<<"mint() account init Aborted.\n";
		return false;//AU aborted.
	}
	else
		return true;//AU execution successful.
}


int Coin::send_m(int t_ID, int sender_iD, int receiver_iD, int amount, int *time_stamp, list<int>&conf_list) 
{
	voidVal* tb1   = new voidVal( sizeof(int) );
	LinkedHashNode* tb    = new LinkedHashNode(0, 0, tb1);
	
	trans_log* txlog;
	STATUS txs  = ABORT;
	STATUS ops1 , ops2;
	int* Sval   = new int;
	int* Rval   = new int;
	*Sval = 0;
	*Rval = 0;
	txlog       = lib->begin();
	*time_stamp = txlog->tid; //return time_stamp to caller.
	
	ops1 = lib->t_read(txlog, 0, sender_iD, Sval, tb);
	
	if(ABORT == ops1) return 0;//AU aborted.

	//not sufficent balance to send;
	//AU is invalid, Trans aborted.
	if(amount > *Sval)	return -1;
	
	ops2 = lib->t_read(txlog, 0, receiver_iD, Rval, tb);

	if(ABORT == ops2) return 0;//AU aborted.

	*Sval = *Sval - amount;
	*Rval = *Rval + amount;
	
	(*(int*)tb->val) = *Sval;
	ops1  = lib->t_write(txlog, 0, sender_iD, *Sval, tb);
	
	(*(int*)tb->val) = *Rval;
	ops2  = lib->t_write(txlog, 0, receiver_iD, *Rval, tb);

	txs   = lib->bto_TryComit( txlog, conf_list, tb);

	if(ABORT == txs) return 0;//AU aborted.
	else return 1;//AU execution successful.
}
	

bool Coin::get_bal_m(int account_iD, int *bal, int t_ID, int *time_stamp, list<int>&conf_list) 
{
	voidVal* tb1   = new voidVal( sizeof(int) );
	LinkedHashNode* tb    = new LinkedHashNode(0, 0, tb1);

	trans_log* txlog;
	STATUS txs  = ABORT;
	STATUS ops  = ABORT;
	int* val    = new int;
	txlog       = lib->begin();
	*time_stamp = txlog->tid; //return time_stamp to user.
	
	ops = lib->t_read(txlog, 0, account_iD, val, tb);
	if(ABORT != ops) txs = lib->bto_TryComit( txlog, conf_list, tb);
	if(ABORT == txs) return false;//AU aborted.
	else
	{
//		cout<<"\nTrnsID "+to_string(txlog->tid)+" Key = "+to_string(account_iD)+" void value "+to_string((*(int*)tb->val));
//		*bal = *val;
		*bal = *(int*)tb->val;
		return true;//AU execution successful.	
	}
}

