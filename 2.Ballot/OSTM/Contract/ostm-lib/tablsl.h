#ifndef TABLSL_H
#define TABLSL_H
#include <pthread.h>
#include "common.h"
#include <climits>
#include <assert.h>
#include <list>
#include <string>
#include <cstring>

using namespace std;

/*!=============================
 * LINK LIST CLASS DECLARATION !
 * ===========================*/
class LinkedHashNode
{
	public:
		int obj_id;
		int key, value;
		bool marked;

		struct
		{
			int look_ts;
			int ins_ts;
			int del_ts;
		}max_ts; //max_ts DS
		
		//!give user flexabaility to store value of 
		//!his wish (e.g., int/bool/float/struct...)
		void *val;
		int  size;     //!size of data object

		//#return value ( lookup + delete(!ok) ) list
		//#with each dataitem:: stores Tid's
		list<int> *rv_list;
		
		//#tryCommit ( insert + delete(ok) ) list
		//#with each dataitem:: stores Tid's
		list<int> *tc_list;

		pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER; //LOCK
		std::recursive_mutex lmutex;
		int lock_count;

		LinkedHashNode(int size)
		{
			this->size    = size;
			this->val     = operator new(size);
			memset((char*)(this->val), 0, size);
		}

		//NEXT RED NODE
		LinkedHashNode *red_next;
		//NEXT BLUE NODE
		LinkedHashNode *blue_next;

		//INIT THE NODE WITH KEY, VALUE
		LinkedHashNode(int key, int value, voidVal* tb);
};

/*!===========================
 * HashMap CLASS DECLARATION !
 * =========================*/
class HashMap
{
	private:
		LinkedHashNode **htable;
	public:
		HashMap(voidVal* tb);
		~HashMap();

		//HASH FUNCTION
		int HashFunc(int key);

		//INSERT ELEMENT AT A KEY
		void lslIns(int key, int value, LinkedHashNode** preds, LinkedHashNode** currs, LIST_TYPE lst_type, LinkedHashNode* tb);

		//SEARCH ELEMENT AT A KEY
		STATUS lslSch(int obj_id, int key, int* value, LinkedHashNode** preds, LinkedHashNode** currs, VALIDATION_TYPE val_type, int tid);

		//DELETE ELEMENT AT A KEY
		void lslDel(LinkedHashNode** preds, LinkedHashNode** currs);

		void printTable();
		void printBlueTable();

		//FUNCTIONS TO TEST THE LIST FUNCTIONALITY SERIALLY
		void lslInsert(int key, int value, LinkedHashNode* tb);
		int lslSearch(int key);
		void lslDelete(int key);
};


//interference validation: to validate pred and curr.
STATUS interferenceValidation(LinkedHashNode** preds, LinkedHashNode** currs);

//time stamp validation
STATUS toValidation(int key, LinkedHashNode** currs, VALIDATION_TYPE val_type, int tid);

//intra trans validation i.e., within same tran bcz of one
//operation other opr curr and pred may change, so validate.
STATUS validation(int key, LinkedHashNode** preds, LinkedHashNode** currs, VALIDATION_TYPE val_type, int tid);


#endif //TABLSL_H
