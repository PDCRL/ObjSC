#include "Coin.h"



/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!!!functions for validator !!!*/
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!            mint() called by minter thread.               !!!*/
/*!!!    initially credit some num of coins to each account    !!!*/
/*!!! (can be called by anyone but only minter can do changes) !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool Coin::mint(int t_ID, int receiver_iD, int amount)
{
	if(t_ID != minter) 
	{
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) can initialize the Accounts (Shared Objects)\n";
		return false; //false not a minter.
	}
	list<accNode>::iterator it = listAccount.begin();
	for(; it != listAccount.end(); it++)
	{
		if( (it)->ID == receiver_iD)
			(it)->bal = amount;
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
	list<accNode>::iterator sender = listAccount.begin();
	for(; sender != listAccount.end(); sender++)
	{
		if( sender->ID == sender_iD) break;
	}

//	if(amount > account[sender_iD]) return false; //not sufficent balance to send; AU is invalid.
	if( sender != listAccount.end() )
	{
		//not sufficent balance to send; AU is invalid.
		if(amount > sender->bal) return false;
	}
	else
	{
		cout<<"Sender ID" << sender_iD<<" not found\n";
		return false;//AU execution fail;
	}

	list<accNode>::iterator reciver = listAccount.begin();
	for(; reciver != listAccount.end(); reciver++)
	{
		if( reciver->ID == receiver_iD) break;
	}
//	account[sender_iD]   = account[sender_iD]   - amount;
//	account[receiver_iD] = account[receiver_iD] + amount;
	if( reciver != listAccount.end() )
	{
		sender->bal  -= amount;
		reciver->bal += amount;
		return true; //AU execution successful.
	}
	else
	{
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
	list<accNode>::iterator acc = listAccount.begin();
	for(; acc != listAccount.end(); acc++)
	{
		if( acc->ID == account_iD) break;
	}
//	*bal = account[account_iD];
	if( acc != listAccount.end() )
	{
		*bal = acc->bal;
		return true; //AU execution successful.
	}
	else
	{
		cout<<"Account ID" << account_iD<<" not found\n";
		return false;//AU execution fail.
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
	voidVal* structVal = new voidVal( sizeof(accNode) );
	LinkedHashNode* tb = new LinkedHashNode(0, 0, structVal);
	list<int> conf_list;
	trans_log* txlog;
	STATUS txs  = ABORT;
	STATUS ops  = ABORT;
	int* val    = new int;

	txlog       = lib->begin();
	*time_stamp = txlog->tid; //return time_stamp to user.

	ops = lib->t_lookup(txlog, 0, receiver_iD, val, tb);
	if(ABORT != ops)
	{
		*val += amount;
		(*(accNode*)tb->val).ID  = receiver_iD;
		(*(accNode*)tb->val).bal = amount;
		lib->t_insert(txlog, 0, receiver_iD, *val, tb);
		txs = lib->tryCommit(txlog, conf_list, tb);
	}
	if(ABORT == txs) return false;//AU aborted.
	else return true;//AU execution successful.
}


int Coin::send_m(int t_ID, int sender_iD, int receiver_iD, int amount, int *time_stamp, list<int>&conf_list) 
{
	voidVal* structVal = new voidVal( sizeof(accNode) );
	LinkedHashNode* tb = new LinkedHashNode(0, 0, structVal);

	trans_log* txlog;
	STATUS txs  = ABORT;
	STATUS ops1 , ops2;
	int* Sval   = new int;
	int* Rval   = new int;
	*Sval = 0;
	*Rval = 0;
	txlog       = lib->begin();
	*time_stamp = txlog->tid; //return time_stamp to caller.

	(*(accNode*)tb->val).ID  = sender_iD;
	(*(accNode*)tb->val).bal = 0;

	ops1 = lib->t_lookup(txlog, 0, sender_iD, Sval, tb);
	if(ABORT == ops1) return 0;//AU aborted.
	*Sval = (*(accNode*)tb->val).bal;
	if(amount > *Sval) return -1;//not sufficent balance to send; AU is invalid, Trans aborted.

	(*(accNode*)tb->val).ID  = receiver_iD;
	(*(accNode*)tb->val).bal = 0;
	ops2 = lib->t_lookup(txlog, 0, receiver_iD, Rval, tb);
	*Rval = (*(accNode*)tb->val).bal;
	if(ABORT == ops2) return 0;//AU aborted.
  
	*Sval = *Sval - amount;
	*Rval = *Rval + amount;

	(*(accNode*)tb->val).ID  = sender_iD;
	(*(accNode*)tb->val).bal = *Sval;
	lib->t_insert(txlog, 0, sender_iD, *Sval, tb);

	(*(accNode*)tb->val).ID  = receiver_iD;
	(*(accNode*)tb->val).bal = *Rval;
	lib->t_insert(txlog, 0, receiver_iD, *Rval, tb);
	txs   = lib->tryCommit( txlog, conf_list, tb);
	if(ABORT == txs) return 0;//AU aborted.
	else return 1;//AU execution successful.
}


bool Coin::get_bal_m(int account_iD, int *bal, int t_ID, int *time_stamp, list<int>&conf_list) 
{
	voidVal* tb1       = new voidVal( sizeof(accNode) );
	LinkedHashNode* tb = new LinkedHashNode(0, 0, tb1);

	trans_log* txlog;
	STATUS txs  = ABORT;
	STATUS ops  = ABORT;
	int* val    = new int;
	txlog       = lib->begin();
	*time_stamp = txlog->tid; //return time_stamp to user.

	(*(accNode*)tb->val).ID  = account_iD;
	(*(accNode*)tb->val).bal = 0;

	ops = lib->t_lookup(txlog, 0, account_iD, val, tb);

	if(ABORT != ops) txs = lib->tryCommit( txlog, conf_list, tb);

	if(ABORT == txs) return false;//AU aborted.
	else
	{
		*bal = *val;
		*bal = (*(accNode*)tb->val).bal;
		return true;//AU execution successful.	
	}
}
