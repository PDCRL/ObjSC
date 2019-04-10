#include "tablsl.h"
using namespace std; //for cout

/*!========================================================================
* DESCP: hash table list node (table being closed addressed has rb-list). !
* =======================================================================*/
LinkedHashNode::LinkedHashNode(int key, int value, voidVal* tb)
{
	this->obj_id         = 0;
	this->key            = key;
	this->value          = value;
	this->lock_count     = 0;
	this->red_next       = NULL;
	this->blue_next      = NULL;
	this->marked         = DEFAULT_MARKED;
	this->max_ts.look_ts = DEFAULT_TS; //use thread ID ot TX id
	this->max_ts.ins_ts  = DEFAULT_TS; //use thread ID ot TX id
	this->max_ts.del_ts  = DEFAULT_TS; //use thread ID ot TX id
	
	this->rv_list        = new list<int>;
	this->tc_list        = new list<int>;
	
	this->size           = tb->size;
	this->val            = operator new(tb->size);
//	memset((char*)(this->val), 0, tb->size);
	copyBytes(this->val, tb->val, tb->size);
}

/*!===================================================
* DESCP: hash table constructor init resources here. !
*===================================================*/
HashMap::HashMap(voidVal* tb)
{
	//creates the actual hash table which consist
	//of TABLE_SIZE buckets/contaner. Each container
	//consist of read and blue list pointers.
	//I.e. table of pointers
	htable = new LinkedHashNode* [TABLE_SIZE];

	
	//init hash-tab with head and tail
	for (int i = 0; i < TABLE_SIZE; i++)
	{
		//note here this and next line making
		//changes at htable[i] possition.
		//last two lines making chnages at read and 
		//blue pointer at htable[i]th address.
		htable[i]            = NULL;
		htable[i]            = new LinkedHashNode(INT_MIN, INT_MIN, tb);
		htable[i]->red_next  = new LinkedHashNode(INT_MAX, INT_MAX, tb);
		htable[i]->blue_next = htable[i]->red_next;
	}
}

/*!==========================================================
* DESCP: hash table destructor free dynamic resources here. !
* =========================================================*/
HashMap::~HashMap()
{
	for (int i = 0; i < TABLE_SIZE; i++)
	{
		if (htable[i] != NULL)
		{
			LinkedHashNode *prev = NULL;
			LinkedHashNode *entry = htable[i];
			while (entry != NULL)
			{
				prev = entry;
				entry = entry->red_next;
				delete prev;
			}
		}
		delete[] htable;
	}
}

/*!========================
* DESCP: cal table index. !
* =======================*/
int HashMap::HashFunc(int key)
{
	return key % TABLE_SIZE;
}

/*!=========================================================
* DESCP: inserts a node into the rblist of the hash table. !
*        at given possition i.e. between preds and currs  .!
* ========================================================*/
void HashMap::lslIns(int key, int value, LinkedHashNode** preds, LinkedHashNode** currs, LIST_TYPE lst_type, LinkedHashNode* tb)
{
	voidVal* tb1   = new voidVal( sizeof(tb->size) );
	copyBytes(tb1->val, tb->val, tb->size);
	//if lst_type == RL_BL then move the node from read list to blue list.
	if(RL_BL == lst_type)
	{
		currs[0]->blue_next = currs[1];
		preds[0]->blue_next = currs[0];
		currs[0]->marked    = false;
		assert(key == currs[0]->key);
	}
	
	//if lst_type == RL then create and insert
	//node between red pred and curr.
	else if(RL == lst_type)
	{
		// TODO: locked, but where? preds, AND currs?
		//node inited and locked
		LinkedHashNode *node = new LinkedHashNode(key, value, tb1);
		node->marked         = true;

		//lock(node->mtx);
		//lock needed so that other might not travel this node
		//and lockremeber to unlock in major mthod \& deadlock
		//may occur if locked while creating the node if head
		//is already locked it might request lock again.
		node->red_next     = currs[0];
		preds[1]->red_next = node;
	}
	//if lst_type == BL then create and insert node 
	//between both red and blue pred and curr.
	else
	{
		LinkedHashNode *node = new LinkedHashNode(key, value, tb1);
		copyBytes(node->val, tb->val, tb->size);

		// lock(node->mtx); no need to take lock on
		// node bcs no othe tx will be able to change
		// it unless it takes lock obn both pred n curr.

		//lock the node before inserting to the ds
		node->lmutex.lock();
		node->red_next      = currs[0];
		node->blue_next     = currs[1];
		preds[1]->red_next  = node;
		preds[0]->blue_next = node;
	}
}


/*!=======================================================
* DESCP: Search Element at a key. Key must strictly lie  !
*        b\w head and tail that is INT_MIN and INT_MAX.  !
* preds and currs are arrays of size two with pointers   !
* to object LinkedHashNode inside func we can access as  !
* Foo* fooPtr = fooPtrArray[i]; and declare as in t_     !
* lookup, insert Foo* fooPtrArray[4];                    !
* ======================================================*/
STATUS HashMap::lslSch(int obj_id, int key, int* value, LinkedHashNode** preds, 
					LinkedHashNode** currs, VALIDATION_TYPE val_type, int tid)
{
	STATUS op_status     = RETRY;
	LinkedHashNode *head = NULL;

	//right now one has tab so this
	//version of hasfunc is enough.
	int bucket_num = HashFunc(key);

	//if bucket is empty
	if(htable[bucket_num] == NULL)
	{
		elog("bucket is empty \n");
		//verify probab if enum can
		//take negative int????????
		return BUCKET_EMPTY;
	}
	else
	{
		head = htable[bucket_num];
	}

	if(preds == NULL || currs == NULL)
	{
		elog("preds and currs is NULL \n");
		return VARIABLE_NULL;
	}

	if((key <= INT_MIN) && (key >= INT_MAX))
	{
		assert((key > INT_MIN) && (key < INT_MAX));
	}

	while(RETRY == op_status)
	{
		preds[0] = head;
		currs[1] = preds[0]->blue_next;

		//search blue pred and curr
		while(currs[1]->key < key)
		{
			preds[0] = currs[1];
			currs[1] = currs[1]->blue_next;
		}

		if(value)
		{
			*value = currs[1]->value;
		}

		preds[1] = preds[0];
		currs[0] = preds[0]->red_next;

		//search red pred and curr
		while(currs[0]->key < key)
		{
			preds[1] = currs[0];
			currs[0] = currs[0]->red_next;
		}

		preds[0]->lmutex.lock();
		preds[1]->lmutex.lock();

		currs[0]->lmutex.lock();
		currs[1]->lmutex.lock();


		preds[0]->lock_count++;
		preds[1]->lock_count++;
		currs[0]->lock_count++;
		currs[1]->lock_count++;

		//validation
		op_status = validation(key, preds, currs, val_type, tid);
		if(value) *value = currs[1]->value;

		// NOTE: Release lock for abort here only no 
		// need to do that seperately in lookup or delete.
		if(RETRY == op_status)
		{
			preds[0]->lock_count--;
			preds[1]->lock_count--;
			currs[0]->lock_count--;
			currs[1]->lock_count--;

			preds[0]->lmutex.unlock();
			preds[1]->lmutex.unlock();

			currs[0]->lmutex.unlock();
			currs[1]->lmutex.unlock();
		}

	}
	return op_status;
}


/*!===============================================
* DESCP: Prints table with red & blue nodes both !
* ==============================================*/
void HashMap::printTable()
{
	int bucket_num      = 0; //HashFunc(key);
	int red_node_count  = 0; //count total red nodes in hashtable
	int blue_node_count = 0; //count total blue nodes in hashtable

	for(bucket_num = 0; bucket_num < TABLE_SIZE; bucket_num++)
	{
		if (htable[bucket_num] == NULL)
			return ;
		else
		{
			LinkedHashNode *entry = htable[bucket_num];
			while (entry != NULL)
			{
				int k1 = entry->key;
				std::stringstream msg;
				msg<<"\n\nKey Val : <"<<entry->key<<" "<<entry->value/*entry */<<">";
				cout<<msg.str();
				
				entry->tc_list->sort ();
				entry->tc_list->unique();
				entry->rv_list->sort ();
				entry->rv_list->unique();
				
				list<int>::iterator it;
				cout<<"\nTC_LIST = {";
				for(it = entry->tc_list->begin(); it != entry->tc_list->end();it++)
				{
					cout << to_string(*it) + " ";
				}
				cout<<"}";
						
				cout<<"\nRV_LIST = {";
				for(it = entry->rv_list->begin(); it != entry->rv_list->end();it++)
				{
					cout << to_string(*it) + " ";
				}
				cout<<"}";
				
				//if marked then read node so increase 
				//red count else increase blue count.
				(entry->marked)?red_node_count++: blue_node_count++;
				
				entry = entry->red_next;

				if (entry == NULL)
				{
					//to reduce the count for head &
					//tail node as they are unmarked
					blue_node_count -= 2;
					cout<< endl <<endl;
					break;
				}
				else
				{
					int k2 = entry->key;
					assert(k1<k2);
				}
			}
		}
	}
	std::stringstream msg;
	msg <<"!!!!!!!!!!!!!!!!!!!!red node count : " <<red_node_count <<endl;
	msg <<"!!!!!!!!!!!!!!!!!!!!blue node count : " <<blue_node_count <<endl;
	cout<<msg.str();
}


/*!=========================================
* DESCP: Prints table with blue list alone !
* ========================================*/
void HashMap::printBlueTable()
{
	int bucket_num = 0;//HashFunc(key);
	int node_count = 0;
	cout<<"\n=======================\n\tHash Table\n=======================\n";
	for(bucket_num = 0; bucket_num < TABLE_SIZE; bucket_num++)
	{
		cout<< "\n| Bucket "<< bucket_num<<" |===>";
		if (htable[bucket_num] == NULL)
			return ;
		else
		{
			LinkedHashNode *entry = htable[bucket_num];
			while (entry != NULL)
			{
				cout<< "|K " << entry->key<<", V "<< entry->value <<"|-->";
				node_count++;

				if(entry->marked)
					//check if any blue node is not marked
					assert(!entry->marked);

				entry = entry->blue_next;

				if (entry == NULL)
				{
					//to reduce the count for head & tail node
					node_count -= 2;
					cout<<"\n\n------------------------------------------\n" <<endl;
				}
			}
		}
	}
	cout<<"============================\n"
		<<"Blue Node Count = " <<node_count
		<<"\n============================\n\n"<<endl;
}

/*!===========================================================
* DESCP: Delete Element at a key. In paper renamed to rblDel !
* ==========================================================*/
void HashMap::lslDel(LinkedHashNode** preds, LinkedHashNode** currs)
{
	currs[1]->marked = true;
	preds[0]->blue_next = currs[1]->blue_next;
}


/*!=========================================================================
* DESCP: Method to identify any concurrent and conflicting modification.   !
*        This method was later renamed to methodValidation() in the paper. !
* ========================================================================*/
STATUS interferenceValidation(LinkedHashNode** preds, LinkedHashNode** currs)
{
	if((preds[0]->marked) || (currs[1]->marked) || (preds[0]->blue_next != currs[1]) || (preds[1]->red_next != currs[0]))
	{
		return RETRY;
	}
	else
		return OK;
}

/*!=======================================================================
* DESCP: Method to identify any time order violation to enusre opacity.  !
*        This method was later renamed to transValidation() in the paper.!
* ======================================================================*/
STATUS toValidation(int key, LinkedHashNode** currs, VALIDATION_TYPE val_type, int tid)
{
	STATUS op_status = OK;

	LinkedHashNode* curr = NULL;

	//getaptCurr
	if(key == currs[1]->key)
		curr = currs[1];

	else if(key == currs[0]->key)
		curr = currs[0];
	
	// NOTE: Sanity check for Default Time stamp of the
	//       node. Check if TS of node is not default.
	if((NULL != curr) && (key == curr->key))
	{
		if((RV == val_type) && ((tid < curr->max_ts.ins_ts) || (tid < curr->max_ts.del_ts) ) )
		{
			op_status = ABORT;
		}
		else if((tid < curr->max_ts.ins_ts) || (tid < curr->max_ts.del_ts) || (tid < curr->max_ts.look_ts) )
		{
			op_status = ABORT;
		}
		else
		{
			op_status = OK;
		}
	}
	return op_status;
}

/*!=============================================
* DESCP: Method to to invoke 2way validations. !
* ============================================*/
STATUS validation(int key, LinkedHashNode** preds, LinkedHashNode** currs, VALIDATION_TYPE val_type, int tid)
{
	STATUS op_status = interferenceValidation(preds, currs);

	if(RETRY != op_status)
	{
		op_status = toValidation(key, currs, val_type, tid);
	}
	return op_status;
}

/*!=================================================
 * TEST functionality of regular Hash Map serially !
 * ===============================================*/
int HashMap::lslSearch(int key)
{
	int bucket_num = HashFunc(key);
	if (htable[bucket_num] == NULL)
		return -1;
	else
	{
		LinkedHashNode *entry = htable[bucket_num];
		while (entry != NULL && entry->key != key)
			entry = entry->red_next;
		if (entry == NULL)
			return -1;
		else
			return entry->value;
	}
}

/*!=======================
* DESCP: serial utility. !
* ======================*/
void HashMap::lslInsert(int key, int value, LinkedHashNode* tb)
{
	voidVal* tb1   = new voidVal( sizeof(tb->size) );
	copyBytes(tb1->val, tb->val, tb->size);
	int bucket_num = HashFunc(key);

	if (htable[bucket_num] == NULL)
		htable[bucket_num] = new LinkedHashNode(key, value, tb1);
	else
	{
		LinkedHashNode *entry = htable[bucket_num];
		while (entry->red_next != NULL)
			entry = entry->red_next;
		if (entry->key == key)
		{
			entry->value = value;
			copyBytes(tb->val, entry->val, tb->size);
		}
		else
			entry->red_next = new LinkedHashNode(key, value, tb1);
	}
}

/*!=======================
* DESCP: serial utility. !
* ======================*/
void HashMap::lslDelete(int key)
{
	int bucket_num = HashFunc(key);

	if (htable[bucket_num] != NULL)
	{
		LinkedHashNode *entry = htable[bucket_num];
		LinkedHashNode *prev  = NULL;

		while (entry->red_next != NULL && entry->key != key)
		{
			prev  = entry;
			entry = entry->red_next;
		}
		if (entry->key == key)
		{
			if (prev == NULL)
			{
				LinkedHashNode *red_next = entry->red_next;
				delete entry;
				htable[bucket_num] = red_next;
			}
			else
			{
				LinkedHashNode *red_next = entry->red_next;
				delete entry;
				prev->red_next = red_next;
			}
		}
	}
}
