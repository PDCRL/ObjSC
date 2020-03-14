#include "Coin.h"


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!            mint() called by minter thread.               !!!*/
/*!!!    initially credit some num of coins to each account    !!!*/
/*!!! (can be called by anyone but only minter can do changes) !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
bool Coin::mint(int t_ID, int receiver_iD, int amount)
{
	if(t_ID != minter) {
		cout<<"\nERROR:: Only ''MINTER'' (Contract Creator) can initialize the Accounts (Shared Objects)\n";
		return false; //false not a minter.
	}
	list<accNode>::iterator it = listAccount.begin();
	for(; it != listAccount.end(); it++) {
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
		if( sender->ID == sender_iD) break;

	if( sender != listAccount.end() ) {
		//not sufficent balance to send; AU is invalid.
		if(amount > sender->bal) return false;
	}
	else {
		cout<<"Sender ID" << sender_iD<<" not found\n";
		return false;//AU execution fail;
	}

	list<accNode>::iterator reciver = listAccount.begin();
	for(; reciver != listAccount.end(); reciver++) {
		if( reciver->ID == receiver_iD) break;
	}

	if( reciver != listAccount.end() ) {
		sender->bal  -= amount;
		reciver->bal += amount;
		return true; //AU execution successful.
	}
	else {
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
		if( acc->ID == account_iD) break;

	if( acc != listAccount.end() ) {
		*bal = acc->bal;
		return true; //AU execution successful.
	}
	else {
		cout<<"Account ID" << account_iD<<" not found\n";
		return false;//AU execution fail.
	}
}
