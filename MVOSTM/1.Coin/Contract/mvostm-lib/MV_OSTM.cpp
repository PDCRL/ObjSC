
#include "MV_OSTM.hpp"

/*************************************
 *Constructor to the class L_txlog.
 ************************************/
L_txlog:: L_txlog(int L_tx_id)
{
	//Initialize the transaction ID.
	this->L_tx_id     = L_tx_id;
	this->L_tx_status = OK;
	this->L_list = new vector<L_rec*>;
}

/*************************************
 * Funtion to find an entry in 
 * vector L_list for a specific key.
 ************************************/
L_rec* L_txlog::L_find(L_txlog* txlog, int L_bucket_id, int L_key)
{
	L_rec *record = NULL;
	//Get the local log list corresponding to each
	//trans which is in increasing order of keys.
	vector<L_rec*> *L_list;
	L_list = txlog->L_list;

	//Every method first identify the node 
	//corresponding to the key into local log.
	for(int i=0;i<L_list->size();i++)
	{
		if((L_list->at(i)->getKey() == L_key) && (L_list->at(i)->getBucketId() == L_bucket_id))
		{
			record = L_list->at(i);
			break;
		}
	}
	return record;
}

/********************************
 * Method described to do the
 * Intra trans validations.
 *******************************/
void L_txlog::intraTransValidation(L_rec* record_i, L_rec* record_k, G_node** G_preds, G_node** G_currs)
{
	if((G_preds[0]->G_mark) || (G_preds[0]->blue_next != G_currs[1]))
	{
		if(record_k->getOpn() == INSERT)
		{
			//G_preds[0]->lmutex.unlock();
			G_preds[0] = record_k->L_preds[0]->blue_next;
			G_preds[0]->lmutex.lock();
			this->lockedNodes.push_back(G_preds[0]);
		}
		else
		{
			//G_preds[0]->lmutex.unlock();
			G_preds[0] = record_k->L_preds[0];
			G_preds[0]->lmutex.lock();
			this->lockedNodes.push_back(G_preds[0]);
		}
	}
	//If G_currs[0] and G_preds[1] is modified
	//by prev operation then update them also.
	if(G_preds[1]->red_next != G_currs[0])
	{
		//G_preds[1]->lmutex.unlock();
		G_preds[1] = record_k->L_preds[1]->red_next;
		G_preds[1]->lmutex.lock();
		this->lockedNodes.push_back(G_preds[1]);
	}
}

/************************************
 * Destructor to the class L_txlog.
 ***********************************/
L_txlog::~L_txlog()
{
	for(int i = 0; i < this->L_list->size(); i++)
	{
		L_list->at(i)->~L_rec();
	}
	delete[] this->L_list;
}

/*============================================================================*/

/*****************************************************
 * Set location of G_pred and G_curr acording to the
 * node corrsponding to the key into trans local log.
 ****************************************************/
void L_rec::setPredsnCurrs(G_node** preds, G_node** currs)
{
	this->L_preds[0] = preds[0];
	this->L_preds[1] = preds[1];
	this->L_currs[0] = currs[0];
	this->L_currs[1] = currs[1];   
}

/****************************************
 * Set method name into trans local log.
 ***************************************/
void L_rec::setOpn(OPN_NAME opn)
{
	this->L_opn = opn;
}

/*********************************************
 * Set status of method into trans local log.
 ********************************************/
void L_rec::setOpnStatus(OPN_STATUS op_status)
{
	this->L_opn_status = op_status;
}

/*********************************************
 * Set value of the key into trans local log.
 *********************************************/
void L_rec::setVal(int value, voidVal* tb)
{
	this->L_value = value;
//	copyBytes(this->val, tb->val, tb->size);
	this->val = tb->val;
}

/*********************************
 * Set key corresponding to the 
 * method from trans local log.
 ********************************/
void L_rec::setKey(int key)
{
	this->L_key = key;
}

/************************************
 * Set bucket Id corresponding to
 * the method from trans local log.
 ***********************************/
void L_rec::setBucketId(int bucketId)
{
	this->L_bucket_id = bucketId;
}

/*************************************************************
 * Get location of G_preds and G_currs according to the node
 * corresponding to the key from the transaction local log.
 ************************************************************/
void L_rec::getPredsnCurrs(G_node** preds, G_node** currs)
{
	preds[0] = this->L_preds[0];
	preds[1] = this->L_preds[1];
	currs[0] = this->L_currs[0];
	currs[1] = this->L_currs[1];
}

/********************************************
 * Get method name from the trans local log.
 *******************************************/
OPN_NAME L_rec::getOpn()
{
	return this->L_opn;
}

/*************************************************
 * Get status of the method from trans local log.
 ************************************************/
OPN_STATUS L_rec::getOpnStatus()
{
	return this->L_opn_status;
}

/*********************************************
 * Get value of the key from trans local log.
 ********************************************/
int L_rec::getVal(voidVal* tb)
{
	copyBytes(tb->val, this->val, this->size);
	return this->L_value;
	
}

/*********************************
 * Get key corresponding to the 
 * method from trans local log.
 ********************************/
int L_rec::getKey()
{
	return this->L_key;
}

/*****************************************
 * Get L_bucket_id corresponding to the 
 * method from transaction local log.
 ****************************************/
int L_rec::getBucketId()
{
	return this->L_bucket_id;
}

/*============================================================================*/
/*============= MV_OSTM class operations are defined here. ===================*/
/*============================================================================*/

/************************************
 * Constructor to the class MV-OSTM.
 ***********************************/
MV_OSTM::MV_OSTM(voidVal *tb)
{
	voidVal* temp   = new voidVal( sizeof(tb->size) );
	init();
	//shared memory-will init hashtablle as in main.cpp
	hash_table = new HashMap(temp);
}

/************************************
 * Destructor of the class MV_OSTM.
 ***********************************/
MV_OSTM::~MV_OSTM()
{
	free(this);
}

/***********************************************************
 * This method is invoked at the start of the STM system.
 * Initializes the global counter(G_cnt).
 **********************************************************/
void MV_OSTM::init()
{
	//Initiazation of global counter to 0.
	G_cnt.store(1);
}
/***********************************************************
 * It is invoked by a thread to being a new transaction Ti.
 * It creates transactional log and allocate unique id.
 **********************************************************/
L_txlog* MV_OSTM::begin()
{
	//Get the transaction Id.
	int tx_id       = G_cnt++;
	L_txlog* tx_log = new L_txlog(tx_id);
	return tx_log;
}

/**********************************************************
 * This method looks up for a key-Node first in 
 * local log if not found then in the shared memory.
 *********************************************************/
OPN_STATUS MV_OSTM::tx_lookup(L_txlog* txlog, int L_key, int* value, voidVal* tb)
{
	//Operation status to be returned.
	OPN_STATUS L_opn_status;
	//Value to be returned.
	int L_val;
	//The bucket id for the corresponding key is.
	int L_bucket_id = hash_table->HashFunc(L_key);
	//first identify the node corresponding to the key in the local log.
	L_rec *record = txlog->L_find(txlog, L_bucket_id, L_key);

	if(record != NULL)
	{
		//Getting the previous operation's name.
		OPN_NAME L_opn = record->getOpn();
		
		//If previous operation is insert/lookup then get the value/opn_status
		//based on the previous operations value/op_status.
		if((INSERT == L_opn)||(LOOKUP == L_opn))
		{
//			copyBytes(tb->val, record->val, record->size);
//			tb->val = record->val;
			*value = record->getVal(tb);
			L_opn_status = record->getOpnStatus();
		}
		else
		{
			//If the previous operation is delete then set the value as NULL
			*value = 0;
			L_opn_status = FAIL;
		}
	}
	else
	{
		G_node *G_preds[2];
		G_node *G_currs[2];
		//If node corresponding to the key is not a part of local log.
		L_opn_status = hash_table->commonLuNDel(txlog->L_tx_id,L_bucket_id,L_key,value,G_preds,G_currs, tb);
		//Create local log record and append it into increasing order of keys.
		record = new L_rec();
		record->setBucketId(L_bucket_id);
		record->setKey(L_key);
		if(value != 0)
		{
//			copyBytes(tb->val, record->val, tb->size);
//			tb->val = record->val;
			record->setVal(*value, tb);
		}
		else
		{
			record->setVal(0, tb);
		}
		record->setPredsnCurrs(G_preds, G_currs);
	
		bool flag = false;
		if(txlog->L_list->size() != 0)
		{
			for(int i = 0; i<txlog->L_list->size(); i++)
			{
				//Insert the record in the sorted order.
				if(txlog->L_list->at(i)->L_key > L_key)
				{
					txlog->L_list->insert(txlog->L_list->begin()+i, record);
					flag = true;
					break;
				}
			}
		}
		else //if(flag == false)
		{
			txlog->L_list->push_back(record);
		}

	}
	//Update the local log.
	record->setOpn(LOOKUP);
	record->setOpnStatus(L_opn_status);
	//Return the operation status.
	return L_opn_status;
}


/*****************************************************
 * This method deletes up for a key-Node first in
 * local logif not found then in the shared memory.
 ****************************************************/
OPN_STATUS MV_OSTM::tx_delete(L_txlog* txlog, int L_key, int* value, voidVal* tb)
{
	//Operation status to be returned.
	OPN_STATUS L_opn_status;
	//Value to be returned.
	int L_val;
	value = &L_val;
	//The bucket id for the corresponding key is.
	int L_bucket_id = hash_table->HashFunc(L_key);
	//first identify the node corresponding to the key in the local log.
	L_rec *record   = txlog->L_find(txlog,L_bucket_id,L_key);

	if(record != NULL)
	{
		//Getting the previous operation's name.
		OPN_NAME L_opn = record->getOpn();
		
//		copyBytes(tb->val, record->val, record->size);
		//If previous operation is insert then get the value based on the previous
		//operations value and set the value as NULL and operation name as DELETE.
		if(INSERT == L_opn)
		{
			*value       = record->getVal(tb);
			L_opn_status = OK;
		} 
		else if(DELETE == L_opn)
		{
			//If the previous operation is delete then set the value as NULL
			*value       = 0;
			L_opn_status = FAIL;
		}
		else 
		{
			// If previous operation is lookup then get the value based on the previous
			// operations value and set the value as NULL and operation name as DELETE.
			*value       = record->getVal(tb);
			L_opn_status = record->getOpnStatus();
		}
	} 
	else
	{
		G_node *G_preds[2];
		G_node *G_currs[2];
		//If node corresponding to the key is not a part of local log.
		L_opn_status = hash_table->commonLuNDel(txlog->L_tx_id, L_bucket_id, L_key, value, G_preds, G_currs, tb);
		//Create local log record and append it into increasing order of keys.
		record = new L_rec();
		record->setBucketId(L_bucket_id);
		record->setKey(L_key);
		if(value != 0)
		{
//			copyBytes(record->val, tb->val, tb->size);
//			tb->val = record->val;
			record->setVal(*value, tb);
		}
		else
		{
			record->setVal(-1, tb);
		}
		record->setPredsnCurrs(G_preds, G_currs);
	}
	//Update the local log.
	record->setOpn(DELETE);
	record->setOpnStatus(L_opn_status);
	//Return the operation status.
	return L_opn_status;
}

/**********************************************************************
 * This method inserts a key-Node in local log and optimistically,
 * the actual insertion happens optimistically in tryCommit() method.
 *********************************************************************/
OPN_STATUS MV_OSTM::tx_insert(L_txlog* txlog, int L_key, int L_val, voidVal* tb)
{
	//To keep track of the position at which
	//the record to be inserted in the tx log.
	bool flag = false;
	//The bucket id for the corresponding key is.
	int L_bucket_id = hash_table->HashFunc(L_key);
	
	//first identify the node corresponding to the key in the local log.
	L_rec *record = txlog->L_find(txlog, L_bucket_id, L_key);
	
	if(record == NULL)
	{
		//Create local log record and append
		//it into increasing order of keys.
		record = new L_rec();
		record->setBucketId(L_bucket_id);
		record->setKey(L_key);
		for(int i = 0; i < txlog->L_list->size(); i++)
		{
			//Insert the record in the sorted order.
			if(txlog->L_list->at(i)->L_key > L_key)
			{
				txlog->L_list->insert(txlog->L_list->begin()+i, record);
				flag = true;
				break;
			}
		}
		if(flag == false)
		{
			txlog->L_list->push_back(record);
		}
	}
	//Updating the local log.
	record->setVal(L_val, tb);
	record->setOpn(INSERT);
	record->setOpnStatus(OK);
	return OK;
}

/***************************************************
 * This method is used to commit the transactions.
 **************************************************/
OPN_STATUS MV_OSTM::tryCommit(L_txlog* txlog, list<int>&conf_list, voidVal* tb)
{
	//Get the local log list corresponding to each
	//trans which is in increasing order of keys.
	vector<L_rec*> *L_list = new vector<L_rec*>;

	//Sort the records in the txlog of the
	//transaction in order of bucket_id.
	for(int i = 0; i < TABLE_SIZE; i++)
	{
		for(int j = 0; j < txlog->L_list->size(); j++)
		{
			if(txlog->L_list->at(j)->getBucketId() == i)
				L_list->push_back(txlog->L_list->at(j));
		}
	}

	//Identify the new G_preds[] and G_currs[] for all
	//update methods of a transaction and validate it.
	for(int i = 0; i < L_list->size() ; i++)
	{
		//Identify the new G_pred and G_curr
		//location with the help of listLookUp()
		G_node *G_preds[2];
		G_node *G_currs[2];

		L_rec* record_i = L_list->at(i);
		int L_key       = L_list->at(i)->getKey();
		OPN_NAME L_opn  = record_i->getOpn();
		if(L_opn == INSERT || L_opn == DELETE)
		{
			//method velidation
			hash_table->list_LookUp(L_list->at(i)->getBucketId(), L_list->at(i)->getKey(), G_preds, G_currs);
			
			//To keep track of the G_nodes that are locked by this transaction.
			txlog->lockedNodes.push_back(G_preds[0]);
			txlog->lockedNodes.push_back(G_preds[1]);
			txlog->lockedNodes.push_back(G_currs[0]);
			txlog->lockedNodes.push_back(G_currs[1]);

			//time stamp validation for INSERT/DELETE operation
			if(L_opn == INSERT || L_opn == DELETE)
			{
				//timestamp validation
				if((G_currs[1]->G_key == L_key) && (hash_table->check_version(txlog->L_tx_id, G_currs[1] ) == false))
				{
					//Unlock all the variables.
					for(int i = 0; i < txlog->lockedNodes.size(); i++)
						txlog->lockedNodes.at(i)->lmutex.unlock();

					return ABORT;
				}
				else if((G_currs[0]->G_key == L_key)&&(hash_table->check_version(txlog->L_tx_id,G_currs[0]) == false))
				{
					//Unlock all the variables.
					for(int i = 0; i < txlog->lockedNodes.size(); i++)
						txlog->lockedNodes.at(i)->lmutex.unlock();

					return ABORT;
				}
				//Update local log entry.
				L_list->at(i)->setPredsnCurrs(G_preds, G_currs);
			}
		}
	}

	//Get each update method one by one & take
	//effect in underlying datastructure.
	for(int i = 0; i < L_list->size(); i++)
	{
		G_node *G_preds[2];
		G_node *G_currs[2];
		L_rec* record_i = L_list->at(i);
		L_rec* record_k = L_list->at(i);
		if( i != 0 )
			record_k = L_list->at(i-1);

		voidVal *temp  = new voidVal(tb->size);
		OPN_NAME L_opn = record_i->getOpn();
		int L_key      = record_i->getKey();
		int val        = record_i->getVal(temp);
		int L_tx_id    = txlog->L_tx_id;
		copyBytes(temp->val, record_i->val, tb->size);
		record_i->getPredsnCurrs(G_preds, G_currs);

		//Modify the G_preds[] and G_currs[] for the consecutive update
		//methods which are working on overlapping zone in lazy-list.
		txlog->intraTransValidation(record_i, record_k, G_preds, G_currs);

		//If operation is insert then after successfull completion of
		//its node corresponding to the key should be part of BL.
		if(L_opn == INSERT)
		{
			if(G_currs[1]->G_key == L_key)
			{
				//Add a new version to the respective G_node.
				hash_table->insertVersion(L_tx_id, val, G_currs[1], conf_list, temp); 
			}
			else if(G_currs[0]->G_key == L_key) 
			{
//				cout<<"\nHELLO Insert from tid ="+to_string(L_tx_id)+"\n";
				hash_table->list_Ins(L_key, &val, G_preds, G_currs, RL_BL, L_tx_id, temp);
				hash_table->insertVersion(L_tx_id, val, G_currs[0], conf_list, temp);
			} 
			else 
			{
				hash_table->list_Ins(L_key, &val, G_preds, G_currs, BL, L_tx_id, temp); 
				txlog->lockedNodes.push_back(G_preds[0]->blue_next);
				hash_table->insertVersion(L_tx_id, val, G_currs[1], conf_list, temp);
			}
		} 
		else if(L_opn == DELETE && record_i->getOpnStatus() == OK)
		{
			//If node corresponding to the key is part of BL.
			if(G_currs[1]->G_key == L_key)
			{
				G_currs[1]->G_mark = true;
				hash_table->insertVersion(L_tx_id, -1, G_currs[1], conf_list, temp);
				hash_table->list_Del(G_preds, G_currs);
			}
		}
	}
	//Unlock all the variables locked for update opr in the increasing order.
	for(int i=0;i<txlog->lockedNodes.size();i++)
		txlog->lockedNodes.at(i)->lmutex.unlock();

	txlog->lockedNodes.clear();

	//get lock, update lookup trs id, add conflict in conflist, release lock.
	for(int i = 0; i < L_list->size() ; i++)
	{
		//Identify the G_pred and G_curr location with the help of listLookUp()
		G_node *G_preds[2];
		G_node *G_currs[2];
		L_rec* record_i  = L_list->at(i);
		int L_tx_id      = txlog->L_tx_id;
		int L_key        = L_list->at(i)->getKey();
		OPN_NAME L_opn   = record_i->getOpn();
		record_i->getPredsnCurrs(G_preds, G_currs);

		if(L_opn == LOOKUP)
		{
			//get global pread and curr and hold the lock
//			hash_table->list_LookUp(L_list->at(i)->getBucketId(), L_list->at(i)->getKey(), G_preds, G_currs);
			acquirePredCurrLocks(G_preds, G_currs);
			
			G_node* key_Node = G_currs[1];

			int i = 0;
			for(i = 0; i < key_Node->G_vl->size(); i++)
			{
				//Look for an appropriate place.
				if(key_Node->G_vl->at(i)->G_ts > L_tx_id)
				{
					//add conflicts
					//just before version (version smaller then itself).
					conf_list.push_back(key_Node->G_vl->at(i)->G_ts);
					int j = i-1;//largest time stamp smaller then L_tx_id.
					if( j > -1 )//with in range
					{
						conf_list.push_back(key_Node->G_vl->at(j)->G_ts);//lookup vers ts as conf
					}
					key_Node->G_vl->at(j)->rList->push_back(L_tx_id);
				}
			}
			releasePredCurrLocks(G_preds, G_currs);
		}
	}

	conf_list.sort ();
	conf_list.unique();
	conf_list.remove(txlog->L_tx_id);
	return OK;
}

/*************************************************
 * This method is used to abort the transactions.
 ************************************************/
OPN_STATUS MV_OSTM::tryAbort(L_txlog* txlog)
{
	return OK;
}

