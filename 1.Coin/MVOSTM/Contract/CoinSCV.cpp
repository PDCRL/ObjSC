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
			else
				break;
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

	accNode acc;
	acc.ID  = 0;
	acc.bal = 0;
	voidVal* tb = new voidVal( sizeof(accNode) );
//	(*(accNode*)tb->val) = acc;

	list<int> conf_list;
	L_txlog* txlog;
	OPN_STATUS txs  = ABORT;
	OPN_STATUS ops  = ABORT;
	int* val    = new int;
	txlog       = lib->begin( );
	*time_stamp = txlog->L_tx_id; //return time_stamp to user.
	
	ops = lib->tx_lookup(txlog, receiver_iD, val, tb);
	if(ABORT != ops)
	{
		string str = "\nAccount "+to_string(receiver_iD)+" Old value "+to_string((*(accNode*)tb->val).bal);
		*val += amount;
		(*(accNode*)tb->val).bal += amount;
		ops = lib->tx_insert(txlog, receiver_iD, *val, tb);
		txs = lib->tryCommit(txlog, conf_list, tb);
//		cout<<str+" New value "+to_string((*(accNode*)tb->val).bal)+"\n";
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
	accNode acc;
	acc.ID  = sender_iD;
	acc.bal = 0;
	voidVal* tb = new voidVal( sizeof(accNode) );
	(*(accNode*)tb->val) = acc;
	
	acc.ID  = receiver_iD;
	voidVal* tbR = new voidVal( sizeof(accNode) );
	(*(accNode*)tbR->val) = acc;

	L_txlog* txlog;
	OPN_STATUS txs;
	OPN_STATUS ops1 , ops2;
	int* Sval   = new int;
	int* Rval   = new int;
	*Sval = 0;
	*Rval = 0;
	txlog       = lib->begin( );
	*time_stamp = txlog->L_tx_id; //return time_stamp to caller.
	
	ops1 = lib->tx_lookup(txlog, sender_iD, Sval, tb);
	ops2 = lib->tx_lookup(txlog, receiver_iD, Rval, tbR);
	string str = "\nTrans "+to_string(txlog->L_tx_id) +" Sender "+to_string(sender_iD)+" balance "+to_string((*(accNode*)tb->val).bal);

	if(ABORT == ops1)
	{
//		cout<<"ops1 OPN_STATUS == abort\n";
		return 0;//AU aborted.
	}
	*Sval = (*(accNode*)tb->val).bal;
	*Rval = (*(accNode*)tbR->val).bal;
	if(amount > *Sval)
	{
		
		str = str + " < amount ="+to_string(amount)+"\n";
//		cout<<str;
		return -1;//not sufficent balance to send; AU is invalid, Trans aborted.
	}
	
	if(ABORT == ops2)
	{
//		cout<<"ops2 OPN_STATUS == abort\n";
		return 0;//AU aborted.
	}
	else
	{
		str = str +" Reciver-"
				  +to_string(receiver_iD)+" amount to send "+to_string(amount);
		str = str + "\n old-bal <send, rev> <"+ to_string(*Sval)
				  +" , "+to_string(*Rval)+">";
		
		(*(accNode*)tb->val).bal  -= amount;
		(*(accNode*)tbR->val).bal += amount;
		*Sval = (*(accNode*)tb->val).bal - amount;
		*Rval = (*(accNode*)tb->val).bal + amount;
		lib->tx_insert(txlog, sender_iD, *Sval, tb);
		lib->tx_insert(txlog, receiver_iD, *Rval, tbR);

		txs   = lib->tryCommit( txlog, conf_list, tbR);
		str = str + "\n new-bal <send, rev> <"+ to_string((*(accNode*)tb->val).bal)+" , "+to_string((*(accNode*)tbR->val).bal)+">\n";
	
		if(ABORT == txs)
		{
//			cout<<"sent() tryComit failed.\n";
			return 0;//AU aborted.
		}
		else
		{
//			cout<<str;
			return 1;//AU execution successful.
		}
	}
}
	

bool Coin::get_bal_m(int account_iD, int *bal, int t_ID, int *time_stamp, list<int>&conf_list) 
{
	accNode acc;
	acc.ID      = 0;
	acc.bal     = 0;
	voidVal* tb = new voidVal( sizeof(accNode) );
	//(*(accNode*)tb->val) = acc;

	L_txlog* txlog;
	OPN_STATUS txs  = ABORT;
	OPN_STATUS ops  = ABORT;
	int* val        = new int;
	txlog           = lib->begin( );
	*time_stamp     = txlog->L_tx_id; //return time_stamp to user.
	
	ops = lib->tx_lookup(txlog, account_iD, val, tb);
	if(ABORT != ops) txs = lib->tryCommit( txlog, conf_list, tb);
	if(ABORT == txs)
	{
//		cout<<"get_bal() Aborted.\n";
		return false;//AU aborted.
	}
	else
	{
//		*bal = *val;
		*bal = (*(accNode*)tb->val).bal;
		return true;//AU execution successful.	
	}
}

