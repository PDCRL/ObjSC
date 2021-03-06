#include <iostream>
#include <thread>
#include "Util/Timer.cpp"
#include "Contract/CoinSCV.cpp"
#include "Graph/Lockfree/Graph.cpp"
#include "Util/FILEOPR.cpp"
#include <unistd.h>

#define MAX_THREADS 128
#define M_SharedObj 5000
#define FUN_IN_CONT 3
#define pl "=================================================================\n"
#define MValidation true   //! true or false
#define numValidator 50
#define InitBalance 1000
#define NumBlock 26        //! at least two blocks, the first run is warmup run.
#define malMiner true      //! set the flag to make miner malicious.
#define NumOfDoubleSTx 2   //! # double-spending Tx for malicious final state by Miner, multiple of 2.

using namespace std;
using namespace std::chrono;

int    SObj    = 2;        //! SObj: number of shared objects; at least 2, to send & recive.
int    nThread = 1;        //! nThread: total number of concurrent threads; default is 1.
int    numAUs;             //! numAUs: total number of Atomic Unites to be executed.
double lemda;              //!  % of edges to be removed from BG by malicious Miner.
double tTime[2];           //! total time taken by miner and validator algorithm.
Coin   *coin;              //! smart contract.
Graph  *cGraph;            //! conflict graph generated by miner to be given to validator.
int    *aCount;            //! aborted transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs (Transactions).
float_t*vTTime;            //! time taken by each validator Thread to execute AUs (Transactions).
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.
std::atomic<int>gNodeCount;//! # of valid AU node added in graph (invalid AUs will not be part of the graph & conflict list).
std::atomic<int>eAUCount;  //! used by validator threads to keep track of how many valid AUs executed by validator threads.
std::atomic<int>*mAUT;     //! array to map AUs to Trans id (time stamp); mAUT[index] = TransID, index+1 = AU_ID.
Graph  *nValBG;            //! used to store graph of respective n validators.
int MinerState[M_SharedObj];
int ValidatorState[M_SharedObj];
std::atomic<bool>mm;       //! miner is malicious, this is used by validators.


/*************************Barrier code begins**********************************/
std::mutex mtx;
std::mutex pmtx; // to print in concurrent scene
std::condition_variable cv;
bool launch = false;

void wait_for_launch() {
	std::unique_lock<std::mutex> lck(mtx);
	while (!launch) cv.wait(lck);
}

void shoot() {
	std::unique_lock<std::mutex> lck(mtx);
	launch = true;
	cv.notify_all();
}
/*************************Barrier code ends************************************/



/*************************Miner code begins************************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "n" miner-THREAD CONCURRENTLY           !
!"concMiner()" CALLED BY miner-THREAD TO PERFROM oprs of RESPECTIVE AUs !
! THREAD 0 IS CONSIDERED AS MINTER-THREAD (SMART CONTRACT DEPLOYER)     !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int minter_id)
	{
		//! init counter used to execute the numAUs to 0.
		//! init graph node counter to 0 (number of AUs 
		//! added in graph, invalid AUs are not part of the grpah).
		cGraph     = new Graph();
		currAU     = 0;
		gNodeCount = 0;
		mTTime     = new float_t [nThread];//! array index -> respective tid.
		aCount     = new int [nThread];
		for( int i = 0; i < nThread; i++ ) {
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		//! id of the contract creater is "minter_id".
		coin = new Coin(SObj, minter_id);
	}

	//!------------------------------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER + GRAPH CONSTRUCTION THREADS !!!!!!!!!!
	//!-------------------------------------------------------------------------
	void mainMiner()
	{
		Timer Ltimer;
		thread T[nThread];
		int ts, bal = InitBalance;
		//! initialization of account with fixed
		//! ammount; mint() is assume to be serial.
		for(int sid = 1; sid <= SObj; sid++) {
			//! 0 is contract deployer.
			coin->mint_m(0, sid, bal, &ts);
		}

		//!!!!!!!!!!    Create nThread Miner threads      !!!!!!!!!!
		double start = Ltimer.timeReq();//! start timer.
		for( int i = 0; i < nThread; i++ ) 
			T[i] = thread(concMiner, i, numAUs, cGraph);
		for( auto &th : T) th.join ( );
		tTime[0] = Ltimer.timeReq() - start;

//		cGraph->print_grpah(); //! print conflict grpah generated by miner.
//		FILEOPR file_opr;
//		file_opr.pAUTrns(mAUT, numAUs); //! print AU_ID and Timestamp.
		finalState(); //! print the final state of the shared objects.
	}


	//!--------------------------------------------------------
	//! The function to be executed by all the miner threads. !
	//!--------------------------------------------------------
	static void concMiner( int t_ID, int numAUs, Graph *cGraph)
	{
		//! flag is used to add valid AUs in Graph (invalid AU: 
		//! senders does't have sufficent balance to send).
		//! get the current index, and increment it.
		//! statrt clock to get time taken by this transaction.
		Timer Ttimer;
		bool flag   = true;
		int  curInd = currAU++;
		auto start  = Ttimer._timeStart();
		while(curInd < numAUs)
		{
			//!tid of STM_OSTM_transaction that successfully executed this AU.
			//! trans_ids with which this AU.trans_id is conflicting.
			//! get the AU to execute, which is of string type.
			int t_stamp;
			list<int>conf_list;
			istringstream ss(listAUs[curInd]);

			string tmp;
			ss >> tmp; //! AU_ID to Execute.
			int AU_ID = stoi(tmp);
			ss >> tmp; //! Function Name (smart contract).
			if(tmp.compare("get_bal") == 0)
			{
				ss >> tmp; //! get balance of SObj/id.
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coin->get_bal_m(s_id, &bal, t_ID, &t_stamp, conf_list);
				while(v == false) //! execute again if tryCommit fails.
				{
					aCount[t_ID]++;
					v = coin->get_bal_m(s_id, &bal, t_ID, &t_stamp, conf_list);
				}
				mAUT[AU_ID-1] = t_stamp;
			}

			if(tmp.compare("send") == 0)
			{
				ss >> tmp; //! Sender ID.
				int s_id  = stoi(tmp);
				ss >> tmp; //! Reciver ID.
				int r_id  = stoi(tmp);
				ss >> tmp; //! Ammount to send.
				int amt   = stoi(tmp);
				int v =coin->send_m(t_ID, s_id, r_id, amt, &t_stamp, conf_list);
				while(v != 1 ) //! execute again if tryCommit fails.
				{
					aCount[t_ID]++;
					v =coin->send_m(t_ID, s_id, r_id, amt, &t_stamp, conf_list);
					if(v == -1) {
						//! invalid AU: sender does't 
						//! have sufficent balance to send.
						flag = false;
						break;                                    
					}
				}
				mAUT[AU_ID-1] = t_stamp;
			}
			//! graph construction for committed AUs.
			if (flag == true)
			{
				//! increase graph node counter (Valid AU executed).
				gNodeCount++;

				//! get respective tran conflict list using lib fun.
				//list<int>conf_list = lib->get_conf(t_stamp);
				
				//! IMP::delete time stamps in conflict list, which are added
				//! because of initilization of SObj by mnit() trycommit.
				for(int y = 0; y <= 2*SObj; y++) conf_list.remove(y);

				//!------------------------------------------
				//! conf_list come from contract fun using  !
				//! pass by argument of get_bel() and send()!
				//!------------------------------------------
				//!when conflist is empty.
				if(conf_list.begin() == conf_list.end()) {
					Graph:: Graph_Node *tempRef;
					cGraph->add_node(AU_ID, t_stamp, &tempRef);
				}

				for(auto it = conf_list.begin(); it != conf_list.end(); it++)
				{
					int i = 0;
					//! find the conf_AU_ID in map table
					//! given conflicting time-stamp.
					while(*it != mAUT[i]) i = (i+1)%numAUs; 
					//! because array index start with 0
					//! and index+1 respresent AU_ID.
					int cAUID   = i+1;
					//! conflicting AU_ID with this.AU_ID.
					int cTstamp = mAUT[i];
					//! edge from conf_AU_ID to AU_ID.
					if(cTstamp  < t_stamp)
						cGraph->add_edge(cAUID, AU_ID, cTstamp, t_stamp);
					
					//! edge from AU_ID to conf_AU_ID.
					if(cTstamp > t_stamp)
						cGraph->add_edge(AU_ID, cAUID, t_stamp, cTstamp);
				}
			}
			//! reset flag for next AU.
			//! get the current index to execute, and increment it.
			flag   = true;
			curInd = currAU++;
		}
		mTTime[t_ID] = mTTime[t_ID] + Ttimer._timeStop( start );
	}

	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. we are geting this using get_bel()|
	//!-------------------------------------------------
	void finalState()
	{
		list<int>cList;
		for(int sid = 1; sid <= SObj; sid++) {
			int bal = 0, ts;
			//! get_bal() of smart contract, execute again if tryCommit fails.
			coin->get_bal_m(sid, &bal, 0, &ts, cList);
			MinerState[sid] = bal;
		}
	}
	~Miner() { };
};
/*************************Miner code ends**************************************/



/*************************Validator code begins********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "n" validator-THREAD   !
! CONCURRENTLY BASED ON CONFLICT GRPAH! GIVEN BY MINER. !
! concValidator() CALLED BY validator-THREAD TO PERFROM !
! OPERATIONS of RESPECTIVE AUs. THREAD 0 IS CONSIDERED  !
! AS MINTER-THREAD (SMART CONTRACT DEPLOYER)            !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Validator
{
public:
	Validator()
	{
		//! array index location represents respective thread id.
		eAUCount = 0;
		vTTime   = new float_t[nThread];
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
	};

	/*!--------------------------------------
	| create n concurrent validator threads | 
	| to execute valid AUs in conf graph.   |
	---------------------------------------*/
	void mainValidator( )
	{
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
		eAUCount = 0;

		coin->reset();

		Timer Ttimer;
		int bal = InitBalance, total = 0;
		thread T[nThread];
		//! initialization of account with fixed ammount;
		//! mint() function is assume to be serial.
		for(int sid = 1; sid <= SObj; sid++) {
			bool r = coin->mint(0, sid, bal); //! 0 is contract deployer.
			total  = total + bal;
		}

		//!Create "nThread" threads
		double start = Ttimer.timeReq(); //! start timer.
		for(int i = 0; i < nThread; i++)
			T[i] = thread(concValidator, i);
		shoot(); //notify all threads to begin the worker();
		for(auto& th : T) th.join ( );
		tTime[1] = Ttimer.timeReq() - start; //! stop timer
		finalState(); //! print the final state of the SObjs by validator.
	}

	//!--------------------------------------------------------
	//! The function to be executed by all Validator threads. !
	//!--------------------------------------------------------
	static void concValidator( int t_ID )
	{
		//barrier to synchronise all threads for a coherent launch
		wait_for_launch();
		Timer Ttimer;
		//! start timer to get time taken by this thread.
		auto start = Ttimer._timeStart();
		list<Graph::Graph_Node*>buffer;
		auto itr = buffer.begin();
		Graph:: Graph_Node *verTemp;
		while( mm == false )
		{
			//!uncomment this to remove the effect of local buffer optimization.
//			buffer.clear();

			//! all Graph Nodes (Valid AUs executed).
			if(eAUCount == gNodeCount) break;

			//!------------------------------------------
			//!!!<< AU execution from local buffer. >>!!!
			//!------------------------------------------
			for(itr = buffer.begin(); itr != buffer.end(); itr++)
			{
				Graph::Graph_Node* temp = *itr;
				if(temp->in_count == 0 )
				{
					//! expected in_degree is 0 then vertex can
					//! be executed if not claimed by other thread
					int expected = 0;
					if(atomic_compare_exchange_strong(
									&(temp->in_count), &expected, -1 ) == true)
					{
						eAUCount++; //! num of Valid AUs executed is eAUCount+1

						//! get the AU to execute, which is of
						//! string type; listAUs index statrt with 0
						istringstream ss(listAUs[(temp->AU_ID)-1]);
						string tmp;
						ss >> tmp; //! AU_ID to Execute.
						int AU_ID = stoi(tmp);
						ss >> tmp; //! Function Name (smart contract).
						if(tmp.compare("get_bal") == 0)
						{
							ss >> tmp;//! get balance of SObj/id.
							int s_id = stoi(tmp);
							int bal  = 0;

							//! get_bal() of smart contract.
							int v = coin->get_bal(s_id, &bal);
							if(v == -1)	mm = true;
						}
						if( tmp.compare("send") == 0 )
						{
							ss >> tmp; //! Sender ID.
							int s_id = stoi(tmp);
							ss >> tmp; //! Reciver ID.
							int r_id = stoi(tmp);
							ss >> tmp; //! Ammount to send.
							int amt  = stoi(tmp);
							int v   = coin->send(s_id, r_id, amt);
							if(v == -1)	mm = true;
						}
						
						//!-----------------------------------------
						//!change indegree of out edge nodes (node !
						//! having incomming edge from this node). !
						//!-----------------------------------------						
						Graph::EdgeNode *e_temp = temp->edgeHead->next;
						while( e_temp != temp->edgeTail) {
							Graph::Graph_Node* refVN =
									(Graph::Graph_Node*)e_temp->ref;
							refVN->in_count--;

							if(refVN->in_count == 0 )
							buffer.push_back(refVN);//! insert into local buffer.
							e_temp = e_temp->next;
						}
					}
				}
			}
			buffer.clear();//! reached to end of local buffer; clear the buffer.

			//!-----------------------------------------------------
			//!!!<< AU execution by traversing conflict grpah  >>!!!
			//!-----------------------------------------------------
			verTemp = nValBG->verHead->next;
			while(verTemp != nValBG->verTail)
			{
				if(verTemp->in_count == 0)
				{
					//! expected in_degree is 0 then vertex can be
					//! executed if not claimed by other thread
					int expected = 0;
					if(atomic_compare_exchange_strong(
							 &(verTemp->in_count), &expected, -1 ) == true)
					{
						eAUCount++; //! num of Valid AUs executed is eAUCount+1

						//get the AU to execute, which is of string
						//type; listAUs index statrt with 0
						istringstream ss( listAUs[(verTemp->AU_ID) -1 ]);
						string tmp;
						ss >> tmp; //! AU_ID to Execute.
						int AU_ID = stoi(tmp);
						ss >> tmp; //! Function Name (smart contract).
						if(tmp.compare("get_bal") == 0)
						{
							ss >> tmp; //! get balance of SObj/id.
							int s_id = stoi(tmp);
							int bal  = 0;
							//! get_bal() of smart contract.
							int v = coin->get_bal(s_id, &bal);
							if(v == -1)	mm = true;
						}
						if( tmp.compare("send") == 0 )
						{
							ss >> tmp; //! Sender ID.
							int s_id = stoi(tmp);
							ss >> tmp; //! Reciver ID.
							int r_id = stoi(tmp);
							ss >> tmp; //! Ammount to send.
							int amt  = stoi(tmp);
							int v   = coin->send(s_id, r_id, amt);
							if(v == -1)	mm = true;
						}
						
						//!-----------------------------------------
						//!change indegree of out edge nodes (node !
						//! having incomming edge from this node). !
						//!-----------------------------------------
						Graph::EdgeNode *e_temp = verTemp->edgeHead->next;
						while(e_temp != verTemp->edgeTail) {
							Graph::Graph_Node* refVN = 
											(Graph::Graph_Node*)e_temp->ref;
							refVN->in_count--;
							//! insert into local buffer.
							if(refVN->in_count == 0 ) buffer.push_back(refVN);
							e_temp = e_temp->next;
						}
					}
				}
				verTemp = verTemp->next;
				
			}
//			sleep(1);
		}
		//!stop timer to get time taken by this thread
		vTTime[t_ID] = vTTime[t_ID] + Ttimer._timeStop( start );
	}


	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. Geting this using get_bel_val()   |
	//!-------------------------------------------------
	void finalState()
	{
		for(int sid = 1; sid <= SObj; sid++) {
			int bal = 0, ts;
			bool v  = coin->get_bal(sid, &bal);
			ValidatorState[sid] = bal;
		}
	}

	~Validator() { };
};
/*************************Validator code ends**********************************/







//atPoss:: from which double-spending Tx to be stored at end of the list.
bool addMFS(int atPoss)//add malicious final state with double-spending Tx
{

	istringstream ss(listAUs[atPoss-2]);
	string trns1;
	ss >> trns1; //! AU_ID to Execute.
	int AU_ID1 = stoi(trns1);
	ss >> trns1;//function name
	ss >> trns1; //! Sender ID.
	int s_id = stoi(trns1);
	ss >> trns1; //! Reciver ID.
	int r_id = stoi(trns1);
	ss >> trns1; //! Ammount to send.
	int amtAB  = stoi(trns1);

	istringstream ss1(listAUs[atPoss-1]);
	ss1 >> trns1; //! AU_ID to Execute.
	int AU_ID2 = stoi(trns1);
	ss1 >> trns1;//function name
	ss1 >> trns1; //! Sender ID.
	int s_id1 = stoi(trns1);
	ss1 >> trns1; //! Reciver ID.
	int r_id1 = stoi(trns1);
	ss1 >> trns1; //! Ammount to send.
	int amtAC  = stoi(trns1);

	cGraph->remove_AU_Edge(cGraph, AU_ID1);
	cGraph->remove_AU_Edge(cGraph, AU_ID2);
	MinerState[s_id]  = 1000;
	MinerState[r_id]  = 1000;
	MinerState[r_id1] = 1000;

	amtAB = 950;
	trns1 = to_string(AU_ID1)+" send "+to_string(s_id)+" "
	       +to_string(r_id)+" "+to_string(amtAB)+"\n";
	listAUs[AU_ID1-1] =  trns1;

	amtAC = 100;
	trns1 = to_string(AU_ID2)+" send "+to_string(s_id)+" "
	       +to_string(r_id1)+" "+to_string(amtAC)+"\n";
	listAUs[AU_ID2-1] =  trns1;

	MinerState[s_id]  -= amtAB;
	MinerState[r_id]  += amtAB;
	MinerState[r_id1] += amtAC;
	return true;
}


bool stateVal() {
	//State Validation
	bool flag = false;
//	cout<<"\n"<<pl<<"SObject \tMiner \t\tValidator"<<endl;
	for(int sid = 1; sid <= SObj; sid++) {
//		cout<<sid<<" \t \t"<<MinerState[sid]
//			<<" \t\t"<<ValidatorState[sid]<<endl;
		if(MinerState[sid] != ValidatorState[sid]) flag = true;
	}
	return flag;
}






/*************************Main Fun code begins*********************************/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!          main()         !!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	cout<<pl<<"BTO Miner and Decentralized SCV\n";
	cout<<"--------------------------------\n";
	//! list holds the avg time taken by miner and 
	//! Validator thread s for multiple consecutive runs.
	list<double>mItrT;
	list<double>vItrT;
	int totalDepInG  = 0; //to get total number of dependencies in graph;
	int totalRejCont = 0; //number of validator rejected the blocks;
	int maxAccepted  = 0;
	int totalRun     = NumBlock; //at least 2

	FILEOPR file_opr;

	//! read from input file:: SObj = #SObj; nThread = #threads;
	//! numAUs = #AUs; λ =  % of edges to be removed from BG by malicious Miner.
	file_opr.getInp(&SObj, &nThread, &numAUs, &lemda);

	if(SObj > M_SharedObj) {
		SObj = M_SharedObj;
		cout<<"Max number of Shared Object can be "<<M_SharedObj<<"\n";
	}

	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		 //! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, SObj, FUN_IN_CONT, listAUs);
		mm = new std::atomic<bool>;
		mm = false;
		//! index+1 represents respective AU id, and
		//! mAUT[index] represents "time stamp (commited trans)".
		mAUT = new std::atomic<int>[numAUs];
		for(int i = 0; i< numAUs; i++) mAUT[i] = 0;
		tTime[0] = 0;
		tTime[1] = 0;
		Timer mTimer;
		mTimer.start();

		//MINER
		Miner *miner = new Miner(0);
		miner ->mainMiner();

		if(lemda != 0) bool rv = addMFS(NumOfDoubleSTx);

		int totalEdginBG = cGraph->print_grpah();
		//give dependenices in the graph.
		if(numItr>0) totalDepInG += totalEdginBG;

		//VALIDATOR
		if(MValidation == true)
		{
			//Set Counter for malicious miner detection.
			coin->setCounterFlag(true);
				
			int acceptCount = 0, rejectCount = 0;
			for(int nval = 0; nval < numValidator; nval++)
			{
				Validator *validator = new Validator();
				nValBG = NULL;
				nValBG = new Graph;
				cGraph->copy_graph(nValBG);
				//If the miner is malicious this
				//fun remove an edge from graph.
				if(malMiner == true) {
					int eTR = ceil((totalEdginBG * lemda)/100);
					for(int r = 1; r <= eTR; r++)
						nValBG->remove_Edge(nValBG);
				}

				validator ->mainValidator();

				//State Validation
				bool flag = stateVal();
				if(flag == true) rejectCount++;
				else acceptCount++;
				mm = false;
			}
			if(numItr > 0 && malMiner == true) {
				totalRejCont += rejectCount;
				if(maxAccepted < acceptCount ) maxAccepted = acceptCount;
			}
			for(int i = 1; i <= SObj; i++) ValidatorState[i] = 0;
		}
		else
		{
			Validator *validator = new Validator();
			nValBG = new Graph;
			cGraph->copy_graph(nValBG);
			validator ->mainValidator();
			//State Validation
			bool flag = stateVal();
			if(flag == true) cout<<"\nBlock Rejected by Validator";
		}
		int abortCnt = 0;
		for( int iii = 0; iii < nThread; iii++ ) {
			abortCnt = abortCnt + aCount[iii];
		}

		mTimer.stop();

		//total valid AUs among total AUs executed
		//by miner and varified by Validator.
		int vAUs = gNodeCount;
		if(numItr > 0)//skip first run
			file_opr.writeOpt(SObj, nThread, numAUs, tTime, mTTime,
			                        vTTime, aCount, vAUs, mItrT, vItrT);

		for(int i = 1; i <= SObj; i++) {
			MinerState[i]     = 0;
			ValidatorState[i] = 0;
		}
		listAUs.clear();
		delete miner;
		miner = NULL;
		delete cGraph;
		cGraph = NULL;
	}

	//! to get total avg miner and validator
	//! time after number of totalRun runs.
	double tAvgMinerT = 0, tAvgValidT = 0;
	auto mit = mItrT.begin();
	auto vit = vItrT.begin();
	for(int j = 1; j < totalRun; j++){
		tAvgMinerT = tAvgMinerT + *mit;
		tAvgValidT = tAvgValidT + *vit;mit++;
		vit++;
	}
	tAvgMinerT = tAvgMinerT/(totalRun-1);
	tAvgValidT = tAvgValidT/(totalRun-1);
	
	cout<<"    Total Avg Miner       = "<<tAvgMinerT<<" microseconds";
	cout<<"\nTotal Avg Validator       = "<<tAvgValidT<<" microseconds";
	cout<<"\n--------------------------------";
	cout<<"\nAvg Dependencies in Graph = "<<totalDepInG/(totalRun-1);
	cout<<"\n--------------------------------";
	cout<<"\nAvg Number of Validator Accepted the Block = "
		<<(numValidator-(totalRejCont/(totalRun-1)));
	cout<<"\nAvg Number of Validator Rejcted the Block  = "
		<<totalRejCont/(totalRun-1);
	cout<<"\nMax Validator Accepted any Block = "<<maxAccepted;
	cout<<"\n"<<endl;

	mItrT.clear();
	vItrT.clear();
	delete mTTime;
	delete vTTime;
	delete aCount;
	return 0;
}
/*************************Main Fun code ends***********************************/
