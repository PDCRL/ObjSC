#ifndef MVTO_
#define MVTO_

//#include "common.h"
#include "dataStructure.cpp"
#include <vector>
#include <atomic>
#include <algorithm>

/** 
 * L_rec class is a class to create and maintain arecord withing the local log/buffer. 
 **/
class L_rec
{
	public:
		/*To keep track of bucket ID.*/
		int L_bucket_id;
		/*To keep track of Key-Node.*/
		int L_key;
		/*To keep track of Key-Node-Version that this trans lookup.*/
		int L_kVers;
		/*To keep track of value.*/
		int L_value;
		/*To keep track of preds and curs of blue and red list.*/
		G_node **L_preds = new G_node*[2];
		G_node **L_currs = new G_node*[2];
		/*To keep track of operataion status.*/
		OPN_STATUS L_opn_status;
		/*To keep track of operation.*/
		OPN_NAME L_opn;

		//!give user flexabaility to store value of 
		//!his wish (e.g., int/bool/float/struct...)
		void *val;
		int  size;     //!size of data object

		/*Setter methods of the class.*/
		void setBucketId(int bucketId);
		void setKey(int key);
		void setVal(int value, voidVal* tb);
		void setPredsnCurrs(G_node** preds, G_node** currs);
		void setOpnStatus(OPN_STATUS op_status);
		void setOpn(OPN_NAME opn);        

		/* Getter methods of the class.*/
		int getBucketId();
		int getKey();
		int getVal(voidVal* tb);
		void getPredsnCurrs(G_node** preds, G_node** currs);
		OPN_STATUS getOpnStatus();
		OPN_NAME getOpn();
		/*Destructor of the class.*/
		//~L_rec();
};

/**
 * This class define the structure of the log/buffer loacl to each transaction.
 **/
class L_txlog{
	public:
		/*Transaction Id.*/
		int L_tx_id;
		/*Transaction status.*/
		OPN_STATUS L_tx_status;
		/*Vector to store all the operations performed by the transaction.*/
		vector<L_rec*> *L_list;
		/*Array of all the G_Nodes that are locked by current transaction.*/
		vector<G_node*> lockedNodes;
		/*Constructor of the class.*/
		L_txlog(int L_tx_id);
		/*Funtion to find an entry in vector L_list for a specific key.*/
		L_rec* L_find(L_txlog* txlog, int L_bucket_id, int L_key);
		/*Method described to do the Intra transaction validations.*/
		void intraTransValidation(L_rec* record_i, L_rec* record_k, G_node** G_preds, G_node** G_currs);
		/*Destructor of the class.*/
		~L_txlog();
};

/**
 * This class define the structure of main MV-OSTM.
 **/
class MVTO
{
	public:
		/*keeps count of transactions for allocating new transaction IDs.*/
		std::atomic<int> G_cnt;
		/*shared memory -> will initialize hashtable as in main.cpp.*/
		HashMap* hash_table;
		/*Constructor of the class.*/
		MVTO(voidVal *tb);
		/*Destructor of the class.*/
		~MVTO();
		/*Initializes the global counter.*/
		void init();
		/*starts a transaction by initing a log of it as well to record.*/
		L_txlog* begin();
		/*Method to perform the read operation.*/
		OPN_STATUS tx_read(L_txlog* txlog, int L_key, int* value, voidVal* tb);
		/*Method to perform the write operation.*/
		OPN_STATUS tx_write(L_txlog* txlog, int L_key, int L_val, voidVal* tb);
		/*Method to commit the changes to the shared memory - the hash table.*/
		OPN_STATUS tryCommit(L_txlog* txlog, list<int>&conf_list, voidVal* tb);
		/*Metho that is invoked by a transaction when is about to abort.*/
		OPN_STATUS tryAbort(L_txlog* txlog);
};

#endif //MVTO_
