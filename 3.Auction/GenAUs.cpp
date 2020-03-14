/*
* Compile:: g++ -std=c++17 GenAUs.cpp -o genAUs -O3 -g
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <random>
#include <vector>
#include <sstream>
#include <list>

#define funInContract 6
#define bidPer 20
#define withdrawPer 20

using namespace std;

int text[200]; //! for input
bool cmdLineArg = true;
int lemda       = 0;



/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!! RANDOM NUMBER GENERATER FOR ACCOUNT BALANCE !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
float getRBal( ) 
{
	//Random seed
	random_device rd;
	//Initialize Mersenne Twister pseudo-random number generator
	mt19937 gen(rd());
	//Uniformly distributed in range (1, 1000)
	uniform_int_distribution<> dis( 1, 1000 );
	int num = dis(gen);
	return num;
}
	
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!! RANDOM NUMBER GENERATER FOR ID !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
int getRId( int numSObj) 
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
int getRFunC( int nCFun ) 
{
	random_device rd;          
	mt19937 gen(rd());        
	uniform_int_distribution<> dis(1, nCFun);
	int num = dis(gen);
	return num;
}


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! genAUs() generate and store the Atomic Unites    ! 
!!! (transactions to be executed by miner/validator) !
!!! in a list & file, nFunC: parallel fun's (AUs)    !
!!! in smart contract, numAUs: number of AUs         !
!!! to be requested by client to execute.            !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
void genAUs(int numAUs, int nBidder, int nFunC, int nThreads)
{
	fstream f_smpBto, f_smpMvto, f_smpOstm, f_smpMvos, f_serial;
	fstream f_smpSta, f_smpStm,  f_smpTry,  file_log;

	f_smpBto.open ("BTO-STM/inp-output/inp-params.txt",    ios::out);
	f_smpMvto.open("MVTO/inp-output/inp-params.txt",       ios::out);
	f_smpOstm.open("OSTM/inp-output/inp-params.txt",       ios::out);
	f_smpMvos.open("MVOSTM/inp-output/inp-params.txt",     ios::out);
	f_serial.open ("Serial/inp-output/inp-params.txt",     ios::out);
	f_smpSta.open ("Static-Bin/inp-output/inp-params.txt", ios::out);
	f_smpStm.open ("STM-Bin/inp-output/inp-params.txt",    ios::out);
	f_smpTry.open ("Spec-Bin/inp-output/inp-params.txt",ios::out);

	int bidC = ceil((numAUs * (bidPer)) /100);
	int withdrawC = ceil((numAUs * (withdrawPer)) /100);
	int endC = numAUs - (bidC + withdrawC);

	int local_bidC = 1, local_withdrawC = 1, local_endC = 1;
	int auCount = 1;
	
	while(auCount <= numAUs)
	{
		// Gives Smart contract func: 
		// 1 = "bid()"
		// 2 = "withdraw()"
		// 3 = "auction_end()"
		int funName;
		if(lemda != 0 && auCount < 3) funName = 1;		
		else funName = getRFunC( nFunC );
		if(funName == 1)
		{
			if(local_bidC <= bidC)
			{
				int payable  = getRBal( );
				int bidderID = getRId(nBidder);
				int bidValue = getRBal( );
				
				string trns;
				if(lemda != 0 && auCount < 3) {
					trns = to_string(1)+" bid "+to_string(payable)+" "
					      +to_string(nBidder+1)+" "+to_string(0)+"\n";

					trns = trns + to_string(2)+" bid "+to_string(payable)+" "
					            + to_string(nBidder+2)+" "+to_string(0)+"\n";

					auCount++;
					local_bidC++;
				}
				else
					trns = to_string(auCount)+" bid "+to_string(payable)+" "
							 +to_string(bidderID)+" "+to_string(bidValue)+"\n";

				f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
				f_smpMvos << trns;
				f_serial  << trns;
				f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
				file_log  << trns;
				auCount++;
				local_bidC++;
			}
		}
		else if (funName == 2)
		{
			if(local_withdrawC <= withdrawC)
			{
				int bidderID = getRId(nBidder);
				string trns = to_string(auCount)+" withdraw "+to_string(bidderID)+"\n";

				f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
				f_smpMvos << trns;
				f_serial  << trns;
				f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
				file_log  << trns;
				auCount++;
				local_withdrawC++;
			}
		}
		else if (funName == 3)
		{
			if(local_endC <= endC)
			{
				string trns = to_string(auCount)+" auction_end\n";
			
				f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
				f_smpMvos << trns;
				f_serial  << trns;
				f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
				file_log  << trns;
				auCount++;
				local_endC++;
			}
		}
	}

	//closing the file
	f_smpBto.close(); f_smpMvto.close(); f_smpOstm.close(); f_smpMvos.close();
	f_serial.close();
	f_smpSta.close(); f_smpStm.close();  f_smpTry.close();
}

void printAUl()
{
	std::ifstream input( "BTO-STM/inp-output/listAUs.txt" );
	for( std::string line; getline( input, line ); )
	{
		cout<<line<<"\n";
	}
	input.close();
}



int main(int argc, char *argv[])
{
	fstream f_smpBto, f_smpMvto, f_smpOstm, f_smpMvos, f_serial;
	fstream f_smpSta, f_smpStm,  f_smpTry,  file_log;
	f_smpBto.open ("BTO-STM/inp-output/inp-params.txt",    ios::out);
	f_smpMvto.open("MVTO/inp-output/inp-params.txt",       ios::out);
	f_smpOstm.open("OSTM/inp-output/inp-params.txt",       ios::out);
	f_smpMvos.open("MVOSTM/inp-output/inp-params.txt",     ios::out);
	f_serial.open ("Serial/inp-output/inp-params.txt",     ios::out);
	f_smpSta.open ("Static-Bin/inp-output/inp-params.txt", ios::out);
	f_smpStm.open ("STM-Bin/inp-output/inp-params.txt",    ios::out);
	f_smpTry.open ("Spec-Bin/inp-output/inp-params.txt",   ios::out);

	cout << "\n===============================================================";
	cout << "\nEnter the values of the input for Auction Contract.";
	cout << "\nPLEASE FOLLOW THE INSTRUCTIONS::";
	cout << "\n===============================================================";
	cout << "\nInput will be updated in <Algo Name>/inp-output/inp-params.txt";
	cout << "\nInput should be a line space seprated 5 values as given below::";
	cout << "\n---------------------------------------------------------------";
	cout << "\n500 2 10 500 1\n";
	cout << "\tWhere:\n";
	cout << "\t1. nBidder: # of Bidder <Range: 2 to 2000>\n";
	cout << "\t2. bidEndTime: Time in milliseconds <Range: 1 to - >\n";
	cout << "\t3. n: # of Threads <Range: 1 to maximum available H/W threads>\n"; 
	cout << "\t4. K: # of Total AUs or Transactions <Range:"
	     << " integer >= # Threads>\n";
	cout << "\t5. λ: if Miner is Maliciois then 1 else 0";
	cout << "\n------------------------------------------------------------------\n";



	if(cmdLineArg) {
		text[0] = atoi(argv[1]);
		text[1] = atoi(argv[2]);
		text[2] = atoi(argv[3]);
		text[3] = atoi(argv[4]);
		text[4] = atoi(argv[5]);

		string input = to_string(text[0])+" "+to_string(text[1])+" "
              +to_string(text[2])+" "+to_string(text[3])+" "
              +to_string(text[4]);

		cout << input << endl;
		cout << "\n======================================"
			 << "============================================\n";

		if(text[0] < 2 || text[0] > 5000)
			cout<<"\n\tError!!! # of Bidder should be from Range [2, 2000]\n";

		if(text[1] < 1)
			cout<<"\n\tError!!! bidEndTime should be in milliseconds > 1\n";

		if(text[2] <= 0)
			cout<<"\n\tError!!! # of Threads should be "
			    <<"from Range [1, max available]\n";

		if(text[3] < text[2])
			cout<<"\n\tError!!! # of AUs should be an integer >= # Threads\n";

	}
	else {
		cout << "\tPlease Enter # of Bidder <Range: 2 to 5000> :: ";
		cin>>text[0];
		while(text[0] < 2 || text[0] > 5000)
		{
			cout<<"\n\tError!!! Please Enter # of Bidder "
			    <<"from <Range: 2 to 5000> :: ";
			cin>>text[0];
			if(text[0] > 0  && text[0] < 5000 ) break;
		}


		cout << "\n\tPlease Enter bidEndTime: Time in milliseconds"
		     << " <Range: 1 to - > :: ";
		cin>>text[1];
		while(text[1] < 1)
		{
			cout<<"\n\tError!!! Please Enter bidEndTime in "
			    <<"milliseconds from <Range: 1 to - >  :: ";
			cin>>text[1];
			if(text[1] > 0 ) break;
		}


		cout << "\n\tPlease Enter # of Threads <Range: 1 to max available> :: ";
		cin>>text[2];
		while(text[2] <= 0)
		{
			cout<<"\n\tError!!! Please Enter # of Threads "
			    <<"from <Range: from 1 to max available> :: ";
			cin>>text[2];
			if(text[2] > 0) break;
		}


		cout << "\n\tPlease Enter # of AUs   <Range: integer >= # Threads> :: ";
		cin>>text[3];
		while(text[3] < text[2])
		{
			cout<<"\n\tError!!! Please Enter # of AUs    "
			    <<" <Range: integer >= # Threads> :: ";
			cin>>text[3];
			if(text[3] >= text[2]) break;
		}


		cout << "\n\tPlease Enter value for λ  (Range: any integer number) :: ";
		cin>>text[4];
	}

	string input = to_string(text[0])+" "+to_string(text[1])+" "
	              +to_string(text[2])+" "+to_string(text[3])+" "
	              +to_string(text[4]);

	// Writing on file_bto
	f_smpBto  << input << endl; f_smpMvto << input << endl;
	f_smpOstm << input << endl; f_smpMvos << input << endl;
	f_serial  << input << endl;
	f_smpSta  << input << endl; f_smpStm  << input << endl;
	f_smpTry  << input << endl;
	file_log  << input << endl;

	// Reding from file
	cout<<"\nCONGRATULATIONS!!!!\nEntered Input Is Updated In\n"
	    <<"\tAll Directories For Auction\n\n";
	f_smpBto >> input;
	cout << input << endl;
	cout <<"\n==============================================================\n";
	//closing the file
	f_smpBto.close();
	f_smpMvto.close();
	f_smpOstm.close();
	f_smpMvos.close();
	f_serial.close();
	f_smpSta.close();
	f_smpStm.close();
	f_smpTry.close();
	file_log.close();

	lemda = text[4]; //! if lemda is 0 miner is non-malicious else malicious.
	int Sobj = text[0];

	if(lemda != 0 && text[0] > 3 && text[3] > 2) {
		Sobj -= 2;
	}
	genAUs(text[3], Sobj, funInContract, text[2]);

//	printAUl();
	return 0;
}
