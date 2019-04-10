#include <iostream>
#include <thread>
#include <atomic>
#include <list>
#include "Util/Timer.cpp"
#include "Contract/Coin.cpp"
#include "Util/FILEOPR.cpp"

#define MAX_THREADS 1
#define M_SharedObj 5000
#define FUN_IN_CONT 3
#define pl "=============================\n"

using namespace std;
using namespace std::chrono;

int    SObj    = 2;        //! SObj: number of shared objects; at least 2, to send & recive.
int    nThread = 1;        //! nThread: total number of concurrent threads; default is 1.
int    numAUs;             //! numAUs: total number of Atomic Unites to be executed.
double lemda;              //! λ: random delay seed.
double tTime[2];           //! total time taken by miner and validator algorithm.
Coin   *coin;              //! smart contract miner.
Coin   *coinV;              //! smart contract validator.
int    *aCount;            //! Invalid transaction count.
float_t*mTTime;            //! time taken by each miner Thread to execute AUs (Transactions).
float_t*vTTime;            //! time taken by each validator Thread to execute AUs (Transactions).
vector<string>listAUs;     //! holds AUs to be executed on smart contract: "listAUs" index+1 represents AU_ID.
std::atomic<int>currAU;    //! used by miner-thread to get index of Atomic Unit to execute.



/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!    Class "Miner" CREATE & RUN "1" miner-THREAD                        !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Miner
{
	public:
	Miner(int minter_id)
	{
		//! initialize the counter.
		currAU = 0;

		//! index location represents respective thread id.
		mTTime = new float_t [nThread];
		aCount = new int [nThread];
		
		for(int i = 0; i < nThread; i++) 
		{
			mTTime[i] = 0;
			aCount[i] = 0;
		}
		//! id of the contract creater is "minter_id".
		coin = new Coin( SObj, minter_id );
	}

	//!------------------------------------------------------------------------- 
	//!!!!!!!! MAIN MINER:: CREATE MINER + GRAPH CONSTRUCTION THREADS !!!!!!!!!!
	//!-------------------------------------------------------------------------
	void mainMiner()
	{
		Timer lTimer;
		thread T[nThread];

		//! initialization of account with fixed ammount;
		//! mint() function is serial.
		int bal = 1000, total = 0;
		for(int sid = 1; sid <= SObj; sid++) 
		{
			//! 0 is contract deployer.
			bool v = coin->mint(0, sid, bal);
			total  = total + bal;
		}

		//!---------------------------------------------------------
		//!!!!!!!!!!    CREATE NTHREAD MINER THREADS      !!!!!!!!!!
		//!---------------------------------------------------------
//		cout<<"!!!!!!!   Serial Miner Thread Started         !!!!!!\n";
		//! Start clock.
		double start = lTimer.timeReq();
		
		T[0] = thread(concMiner, 0, numAUs);
		
		//! miner thread join
		for(auto& th : T) th.join();
		
		//! Stop clock
		tTime[0] += lTimer.timeReq() - start;
//		cout<<"!!!!!!!   Serial Miner Thread Join            !!!!!!\n";

		//! print the final state of the shared objects.
//		finalState();
	}

	//!--------------------------------------------------------
	//! The function to be executed by all the miner threads. !
	//!--------------------------------------------------------
	static void concMiner( int t_ID, int numAUs)
	{
		Timer thTimer;
		//! statrt clock to get time taken by this.AU
		auto start = thTimer._timeStart();
		//! get the current index, and increment it.
		int curInd = currAU++;

		while( curInd < numAUs )
		{
			//!get the AU to execute, which is of string type.
			istringstream ss(listAUs[curInd]);

			string tmp;
			//! AU_ID to Execute.
			ss >> tmp;
			int AU_ID = stoi(tmp);

			//! Function Name (smart contract).
			ss >> tmp;
			if( tmp.compare("get_bal") == 0 )
			{
			//! get balance of SObj/id.
				ss >> tmp;
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coin->get_bal(s_id, &bal);
			}
			if( tmp.compare("send") == 0 )
			{
				//! Sender ID.
				ss >> tmp;
				int s_id = stoi(tmp);
				//! Reciver ID.
				ss >> tmp;
				int r_id = stoi(tmp);
				//! Ammount to Send.
				ss >> tmp;
				int amt = stoi(tmp);
				bool v  = coin->send(s_id, r_id, amt);
				if(v == false) aCount[t_ID]++;
			}
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		mTTime[t_ID] = mTTime[t_ID] + thTimer._timeStop(start);
	}

	//!-------------------------------------------------
	//!FINAL STATE OF ALL THE SHARED OBJECT. Once all  |
	//!AUs executed. Geting this using get_bel_val()   |
	//!-------------------------------------------------
	void finalState()
	{
		int total = 0;
		cout<<pl<<"SHARED OBJECTS FINAL STATE\n"<<pl<<"SObj ID | FINAL STATE\n"<<pl;
		for(int sid = 1; sid <= SObj; sid++) 
		{
			int bal = 0;
			//! get_bal() of smart contract.
			bool v = coin->get_bal(sid, &bal);
			total  = total + bal;
			cout<<"  "+to_string(sid)+"  \t|  "+to_string(bal)+"\n";
		}
		cout<<pl<<"  SUM   |  "<<total<<"\n"<<pl;
	}

	~Miner() { };
};


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
! Class "Validator" CREATE & RUN "1" validator-THREAD          !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
class Validator
{
public:

	Validator(int minter_id)
	{
		//! initialize the counter to 0.
		currAU = 0;

		//! index location represents respective thread id.
		vTTime = new float_t [nThread];
		
		for(int i = 0; i < nThread; i++) vTTime[i] = 0;
		
		//! id of the contract creater is "minter_id".
		coinV = new Coin( SObj, minter_id );
	}

	//!-------------------------------------------------------- 
	//!! MAIN Validator:: CREATE ONE VALIDATOR THREADS !!!!!!!!
	//!--------------------------------------------------------
	void mainValidator()
	{
		Timer lTimer;
		thread T[nThread];

		//! initialization of account with fixed ammount;
		//! mint() function is serial.
		int bal = 1000, total = 0;
		for(int sid = 1; sid <= SObj; sid++) 
		{
			//! 0 is contract deployer.
			bool v = coinV->mint(0, sid, bal);
			total  = total + bal;
		}

		//!-----------------------------------------------------
		//!!!!!!!!!!    CREATE 1 VALIDATOR THREADS      !!!!!!!!
		//!-----------------------------------------------------
//		cout<<"!!!!!!!   Serial Validator Thread Started      !!!!\n";
		//! Start clock.
		double start = lTimer.timeReq();
		
		T[0] = thread(concValidator, 0, numAUs);
		
		//! validator thread join
		for(auto& th : T) th.join();
		//! Stop clock
		tTime[1] += lTimer.timeReq() - start;
//		cout<<"!!!!!!!   Serial Validator Thread Join            !!!!!!\n";
	
		//! print the final state of the shared objects.
//		finalState();
	}

	//!------------------------------------------------------------
	//! THE FUNCTION TO BE EXECUTED BY ALL THE VALIDATOR THREADS. !
	//!------------------------------------------------------------
	static void concValidator( int t_ID, int numAUs)
	{
		Timer tTimer;
	
		//! get the current index, and increment it.
		int curInd = currAU++;

		//! statrt clock to get time taken by this.AU
		auto start = tTimer._timeStart();
		while( curInd < numAUs )
		{
			//!get the AU to execute, which is of string type.
			istringstream ss(listAUs[curInd]);

			string tmp;
			//! AU_ID to Execute.
			ss >> tmp;
			int AU_ID = stoi(tmp);

			//! Function Name (smart contract).
			ss >> tmp;
			if( tmp.compare("get_bal") == 0 )
			{
			//! get balance of SObj/id.
				ss >> tmp;
				int s_id = stoi(tmp);
				int bal  = 0;
				//! get_bal() of smart contract.
				bool v = coinV->get_bal(s_id, &bal);
			}
			if( tmp.compare("send") == 0 )
			{
				//! Sender ID.
				ss >> tmp;
				int s_id = stoi(tmp);
				//! Reciver ID.
				ss >> tmp;
				int r_id = stoi(tmp);
				//! Ammount to Send.
				ss >> tmp;
				int amt = stoi(tmp);
				bool v  = coinV->send(s_id, r_id, amt);
			}			
			//! get the current index to execute, and increment it.
			curInd = currAU++;
		}
		vTTime[t_ID] = vTTime[t_ID] + tTimer._timeStop(start);
	}

	//!-------------------------------------------------
	//! FINAL STATE OF ALL THE SHARED OBJECT. ONCE ALL |
	//! AUS EXECUTED. GETING THIS USING get_bel.       |
	//!-------------------------------------------------
	void finalState()
	{
		int total = 0;
		cout<<pl<<"SHARED OBJECTS FINAL STATE\n"<<pl<<"SObj ID | FINAL STATE\n"<<pl;
		for(int sid = 1; sid <= SObj; sid++) 
		{
			int bal = 0;
			//! get_bal() of smart contract.
			bool v = coinV->get_bal(sid, &bal);
			total  = total + bal;
			cout<<"  "+to_string(sid)+"  \t|  "+to_string(bal)+"\n";
		}
		cout<<pl<<"  SUM   |  "<<total<<"\n"<<pl;
	}

	~Validator() { };
};




/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!   main() !!!!!!!!!!!!!!!!!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int main( )
{
	//! list holds the avg time taken by miner and validator
	//!  threads for multiple consecutive runs of the algorithm.
	list<double>mItrT;         
	list<double>vItrT;	
	double avgMiner = 0;
	double avgValidator = 0;
	tTime[0] = 0;
	tTime[1] = 0;

	FILEOPR file_opr;

	//! read from input file:: SObj = #SObj; nThread = #threads;
	//! numAUs = #AUs; λ = random delay seed.
	file_opr.getInp(&SObj, &nThread, &numAUs, &lemda);

	//!------------------------------------------------------------------
	//! Num of threads should be 1 for serial so we are fixing it to 1, !
	//! Whatever be # of threads in inputfile, it will be always one.   !
	//!------------------------------------------------------------------
	nThread = 1;

	//! max shared object error handling.
	if(SObj > M_SharedObj) 
	{
		SObj = M_SharedObj;
		cout<<"Max number of Shared Object can be "<<M_SharedObj<<"\n";
	}

	cout<<pl<<"   Serial  Algorithm  \n"<<pl;
	int totalRun = 1;
	for(int numItr = 0; numItr < totalRun; numItr++)
	{
		 //! generates AUs (i.e. trans to be executed by miner & validator).
		file_opr.genAUs(numAUs, SObj, FUN_IN_CONT, listAUs);


		//MINER
		Miner *miner = new Miner(0);

		std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
		miner ->mainMiner();
		std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
//		cout << "\nSerial-Miner Algorithm computation took " 
//			 << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//			 << " microseconds" << std::endl;
 		avgMiner += std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
 		
		//VALIDATOR
		Validator *validator = new Validator(0);	
		begin = std::chrono::steady_clock::now();
		validator ->mainValidator();
		end = std::chrono::steady_clock::now();
//		cout << "Serial-Validator Algorithm computation took " 
//			 << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
//			 << " microseconds" << std::endl;
 		avgValidator += std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();


		//total valid AUs among List-AUs executed by Miner & varified by Validator.
		int vAUs = numAUs - aCount[0];
		nThread = 1;
		file_opr.writeOpt(SObj, nThread, numAUs, tTime, mTTime, vTTime, aCount, vAUs, mItrT, vItrT);

		listAUs.clear();
		delete miner;
		miner = NULL;
		delete validator;
		validator = NULL;
	}
	
	// to get total avg miner and validator
	// time after number of totalRun runs.
	double tAvgMinerT = 0;
	double tAvgValidT = 0;
	auto mit          = mItrT.begin();
	auto vit          = vItrT.begin();

	for(int j = 0; j < totalRun; j++)
	{
		tAvgMinerT = tAvgMinerT + *mit;
		tAvgValidT = tAvgValidT + *vit;
		mit++;
		vit++;
	}
//	tTime[0] = tTime[0]/totalRun*1000000;
//	tTime[1] = tTime[1]/totalRun*1000000;
	tAvgMinerT = tAvgMinerT/totalRun;
	tAvgValidT = tAvgValidT/totalRun;

	cout<<"\n    Total Avg Miner = "<<tAvgMinerT<<" microseconds";
	cout<<"\nTotal Avg Validator = "<<tAvgValidT<<" microseconds";
	cout<<"\n"<<pl;
	
	
	mItrT.clear();
	vItrT.clear();

	delete mTTime;
	delete vTTime;
	delete aCount;	
return 0;
}
