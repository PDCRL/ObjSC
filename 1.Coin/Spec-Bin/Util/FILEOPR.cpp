#include "FILEOPR.h"

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!! RANDOM NUMBER GENERATER FOR ACCOUNT BALANCE !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
float FILEOPR::getRBal( ) 
{
	random_device rd;    //Random seed
	mt19937 gen(rd());  //Init Mersenne Twister pseudo-random number generator
	uniform_int_distribution<> dis( 1, 1000 ); //Uniformly distributed in range
	int num = dis(gen);
	return num;
}
	
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!! RANDOM NUMBER GENERATER FOR ID !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int FILEOPR::getRId( int numSObj) 
{
	random_device rd; 
	mt19937 gen(rd());
	uniform_int_distribution<> dis(1, numSObj); 
	int num = dis(gen);
	return num;
}
	
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!! RANDOM NUMBER GENERATER FOR FUNCTION CALL !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int FILEOPR::getRFunC( int nCFun ) 
{
	random_device rd;          
	mt19937 gen(rd());        
	uniform_int_distribution<> dis(1, nCFun);
	int num = dis(gen);
	return num;
}


//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//! getInp() reads #Shared Objects, #Threads, #AUs,  !
//! & random delay seed "Lemda" from input file      !
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
void FILEOPR::getInp(int* m, int* n, int* K, double* lemda ) 
{
	string ipBuffer[4]; //stores input from file
	ifstream inputFile;
	inputFile.open ( "inp-output/inp-params.txt" );
	while(!inputFile) {
		cerr << "Error!! Unable to open inputfile <inp-params.txt>\n\n";
		exit(1); //call system to stop
	}
	int i = 0;
	while( !inputFile.eof( ) ) {
		inputFile >> ipBuffer[i];
		i++;
	}
	*m     = stoi(ipBuffer[0]);     // m: # of SObj;
	*n     = stoi(ipBuffer[1]);     // n: # of threads
	*K     = stoi(ipBuffer[2]);     // K: Total # of AUs or Transactions;
	*lemda = stof(ipBuffer[3]);     // λ: random delay
	inputFile.close( );
	return;
}


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! writeOpt() stores the Time taken by algorithm in output file "Time.txt"  !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
void FILEOPR::writeOpt(int m,int n,int K,double total_time[],float_t mTTime[],
						float_t vTTime[],int aCount[],int validAUs,
						list<double>&mIT,list<double>&vIT)
{
	ofstream out;
	
	out.open("inp-output/Time.txt");
	
	float_t t_Time[2];
	t_Time[0] = 0;//total time miner thread
	t_Time[1] = 0;//total time validator thred
	out <<"\nTime Taken By Miner Threads:\n";
	for(int i = 0; i < n; i++) {
		out <<"THREAD "<< i << " = "<< mTTime[i] <<" microseconds\n";
		t_Time[0] = t_Time[0] + mTTime[i];
	}

	out <<"\nTime Taken By Validator Threads:\n";
	for(int i = 0; i < n; i++) {
		out <<"THREAD "<< i << " = "<< vTTime[i] <<" microseconds\n";
		t_Time[1] = t_Time[1] + vTTime[i];
	}
	out <<"\n[ # Shared Objects = "<< m <<" ]\n[ # Threads = "<< n 
		<< " ]\n[ # Total AUs = " << K << " ]\n";
	out <<"\n\nAverage Time Taken by a Miner     Thread        = "
		<<t_Time[0]/n << " microseconds\n";
	mIT.push_back(t_Time[0]/n);

	out <<"Average Time Taken by a Validator Thread        = "
		<<t_Time[1]/n << " microseconds\n";
	vIT.push_back(t_Time[1]/n);
	out <<"\nTotal Average Time (Miner + Validator)  = "
		<<(t_Time[0]/n + t_Time[1]/n)<<" microseconds\n";
	out.close( );
	return;
}
	
	

void FILEOPR::genAUs(int numAUs, int SObj, int nFunC, vector<string>& ListAUs)
{
	std::ifstream input( "inp-output/listAUs.txt" );
	int count = 0;
	while(count < numAUs) {
		std::string trns; getline( input, trns );
		ListAUs.push_back(trns);
		count++;
	}
	input.close();
}
