#ifndef OSTM_H
#define OSTM_H

//#include "common.h"
#include "tablsl.cpp"
#include <vector>
#include <atomic>
#include <algorithm>

struct ll_entry
{
	int obj_id, bucketId;
	int key;
	int value;
	
	//!give user flexabaility to store value of 
	//!his wish (e.g., int/bool/float/struct...)
	void *val;
	int  size;     //!size of data object

	LinkedHashNode** preds; //alloc dynamically these arrays preds[]
	LinkedHashNode** currs;
	LinkedHashNode*  node;  //for the inserted single node in BL
	OPN_NAME opn;
	STATUS op_status;

	~ll_entry()
	{
		delete[] preds;
		delete[] currs;
		preds = NULL;
		currs = NULL;
	}
};


/*!==========================================================
 * Local buffer associated with each transaction - release  !
 * the memory in commit* --> its key, ll_entry pair. key IS !
 * bucket id and ll_entry is respective local log entry.    !
 *=========================================================*/
typedef std::vector < std::pair< int, ll_entry*> > ll_list;


/*!===================
 * TRANSACTION CLASS !
 *==================*/
class trans_log
{
	public:
		//UNIQUE ID
		int tid;

		//TRANSACTION STATUS:
		//retry, commit, fail, abort
		STATUS tx_status;

		//local buffer - release the memory in commit
		ll_list ll;

		//transaction object constructor:
		//input as transaction id
		trans_log( int );
		
		//trans_state destructor frees
		//memory allocated to write buffer
		~trans_log();
		
		/*!==========================================
		* operations supported for each transaction !
		* =========================================*/
		
		//1. Find specific key in local log (buffer)
		int  findinLL(int key);
		
		//2. Create new entry in local log (sorted order)
		int  createLLentry(int key, LinkedHashNode* tb);
		
		//3. set pred and curr at given pos (vector index).
		void setPredsnCurrs(int pos, LinkedHashNode** preds, LinkedHashNode** currs);
		
		//4. 
		void setOpnName(int pos, OPN_NAME opn);
		
		//5.
		void setOpStatus(int pos, STATUS op_status);

		//6.
		void setValue(int pos, int value, LinkedHashNode* tb);

		//7.
		void setKey(int pos, int key);

		//8.
		void setbucketId(int pos, int bid);


		OPN_NAME getOpn(int ll_pos);
		STATUS getOpStatus(int ll_pos);
		int getValue(int ll_pos);
		int getKey(int ll_pos);
		int getbucketId(int ll_pos);

};

class OSTM 
{
	public:
		//keeps count of transactions for
		//allocating new transaction IDs
		std::atomic<int> tid_counter;
		
		//std::atomic<int> abort_count;

		//shared memory: will init
		//hashtablle as in main.cpp
		HashMap* hash_table; 
		//txlog;

		//OSTM class
		//object constructor
		OSTM(LinkedHashNode* tb);

		//OSTM class
		//object destructor
		~OSTM();

		//starts a transaction by initing
		//a log of it as well to record.
		//So whenever it is called a new 
		//trans structure will be created.
		//returns a unique trans id.
		trans_log* begin();

		//given trans structure (tid), object id, and key it 
		//returns/stores the value at given pass by refrence.
		STATUS t_lookup(trans_log* txlog, int obj_id, int key, int* value, LinkedHashNode* tb);

		//given trans structure (tid), object id, and key it 
		//returns status (abort/ok/fails).
		//TODO:why returns the value at given pass by refrence?
		STATUS t_delete(trans_log* txlog, int obj_id, int key, int* value, LinkedHashNode* tb);
		
		
		STATUS t_insert(trans_log* txlog, int obj_id, int key, int value, LinkedHashNode* tb);
		
		STATUS tryCommit(trans_log* txlog, list<int> &conf_list, LinkedHashNode* tb);
		
		STATUS tryAbort(trans_log* txlog);
};

#endif //OSTM_H
