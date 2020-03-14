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

#define funInContract 5
#define delegatePer 10

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




void genAUs(int numAUs, int numVoter, int numProposal, int nFunC, int nThreads)
{
	int SObj = text[0] + text[1];
	fstream f_smpBto, f_smpMvto, f_smpOstm, f_smpMvos, f_serial;
	fstream f_smpSta, f_smpStm,  f_smpTry,  file_log;

	f_smpBto.open  ("BTO-STM/inp-output/listAUs.txt",    ios::out);
	f_smpMvto.open ("MVTO/inp-output/listAUs.txt",       ios::out);
	f_smpOstm.open ("OSTM/inp-output/listAUs.txt",       ios::out);
	f_smpMvos.open ("MVOSTM/inp-output/listAUs.txt",     ios::out);
	f_serial.open  ("Serial/inp-output/listAUs.txt",     ios::out);
	f_smpSta.open  ("Static-Bin/inp-output/listAUs.txt", ios::out);
	f_smpTry.open  ("Spec-Bin/inp-output/listAUs.txt",   ios::out);



	int delgC = ceil((numAUs * (delegatePer)) /100);
	int voterC = numAUs - delgC;

	int local_delgC = 1, local_voterC = 1;

	int auCount = 1;
	//cout<<"\n---------------------";
	//cout<<"\nAU | Operations\n";
	//cout<<"---------------------\n";
	while(auCount <= numAUs)
	{
		//gives contract func: 1 = "delegate()" and 2 = "vote()"
		int funName;
		if(lemda != 0 && auCount < 3) funName = 2;		
		else funName = getRFunC( nFunC );
		if(funName == 1)
		{
			if(local_delgC <= delgC)
			{
				int from = getRId(numVoter);
				int to   = getRId(numVoter);
				while (from == to) to = getRId(numVoter);

				string trns = to_string(auCount)+" delegate "
				             +to_string(from)+" "+to_string(to)+"\n";
				//cout<<" "+trns;
				f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
				f_smpMvos << trns;
				f_serial  << trns;
				f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
				file_log  << trns;
				auCount++;
				local_delgC++;
			}
		}
		else if (funName == 2)
		{
			if(local_voterC <= voterC)
			{
				int vID = getRId(numVoter);   //voter ID
				int pID = getRId(numProposal);//proposalID
				string trns;
				if(lemda != 0 && auCount < 3) {
					trns = to_string(auCount)+" vote "
						  +to_string(numVoter+1)+" "
						  +to_string(numProposal+1)+"\n";

					trns = trns + to_string(auCount+1)+" vote "
								+to_string(numVoter+1)+" "
								+to_string(numProposal+2)+"\n";
				}
				else
					trns = to_string(auCount)+" vote "
					      +to_string(vID)+" "+to_string(pID)+"\n";

				f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
				f_smpMvos << trns;
				f_serial  << trns;
				file_log  << trns;

				if(lemda != 0 && auCount < 3) {
					trns = to_string(auCount)+" vote "
					      +to_string(numVoter+1)+" "
					      +to_string(-(numProposal+1))+"\n";

					trns = trns + to_string(auCount+1)+" vote "
					            +to_string(numVoter+1)+" "
					            +to_string(-(numProposal+2))+"\n";
					auCount++;
					local_voterC++;
				}
				else
					trns = to_string(auCount)+" vote "
					      +to_string(vID)+" "+to_string(-pID)+"\n";

				f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
				//cout<<" "+trns;
				auCount++;
				local_voterC++;
			}
		}
	}
	//cout<<"---------------------\n";
	//closing the file
	f_smpBto.close(); f_smpMvto.close(); f_smpOstm.close(); f_smpMvos.close();
	f_serial.close();
	f_smpSta.close(); f_smpStm.close();  f_smpTry.close();
	file_log.close();
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
	f_smpTry.open ("Spec-Bin/inp-output/inp-params.txt",ios::out);

	cout << "\n===============================================================";
	cout << "\nEnter the values of the input for Ballot Contract";
	cout << "\nPLEASE FOLLOW THE INSTRUCTIONS::";
	cout << "\n===============================================================";
	cout << "\nInput will be updated in <Algo Name>/inp-output/inp-params.txt";
	cout << "\nInput should be a line space seprated 5 values as given below::";
	cout << "\n---------------------------------------------------------------";
	cout << "\n5 1000 10 500 5\n";
	cout << "\tWhere:\n";
	cout << "\t1. nProposal: # of Proposals <Range: 1 to 1000>\n";
	cout << "\t2. nVoter: # of Voters <Range: 1 to 3000>\n";
	cout << "\t3. n: # of Threads <Range:1 to maximum available H/W threads>\n"; 
	cout << "\t4. K: # of Total AUs or Transactions"
	     << " <Range: integer >= # Threads>\n";
	cout << "\t5. λ: if Miner is Maliciois then 1 else 0";
	cout << "\n-------------------------------------------------------------\n";

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
			 << "======================================\n";

		if(text[0] < 1 || text[0] > 5000) {
			cout<<"\n\tError!!! # of Proposals in Ballot should"
			    <<" be from the Range [1, 5000]\n";
		}
		if(text[1] < 1 || text[1] > 40000) {
			cout<<"\n\tError!!! # of Voters in Ballot should"
			    <<" be from the Range [1, 10000]\n";
		}
		
		if(text[2] <= 0) {
			cout<<"\n\tError!!! # of Threads should"
			    <<" be from the Range [1, max available]\n";
		}

		if(text[3] < text[2]) {
			cout<<"\n\t# of AUs should be an integer >= # Threads\n";
		}
	}
	else {
		cout<< "\tPlease Enter # of Proposal <Range: 1 to 1000> :: ";
		cin>>text[0];
		while(text[0] < 1 || text[0] > 5000)
		{
			cout<<"\n\tError!!! Please Enter # of Proposals"
			    <<" from <Range: 1 to 1000> :: ";
			cin>>text[0];
			if(text[0] > 0  && text[0] < 5000 ) break;
		}


		cout<< "\n\tPlease Enter # of Voters <Range: 1 to 3000> :: ";
		cin>>text[1];
		while(text[1] < 1 || text[1] > 10000)
		{
			cout<<"\n\tError!!! Please Enter # of Voters <Range: 1 to 3000> :: ";
			cin>>text[1];
			if(text[1] > 0  && text[1] < 10000 ) break;
		}


		cout<< "\n\tPlease Enter # of Threads <Range: 1 to max available> :: ";
		cin>>text[2];
		while(text[2] <= 0)
		{
			cout<<"\n\tError!!! Please Enter # of Threads <Range: "
			    <<"from 1 to max available> :: ";
			cin>>text[2];
			if(text[2] > 0) break;
		}


		cout<< "\n\tPlease Enter # of AUs     <Range: "
		    <<"integer >= # Threads> :: ";
		cin>>text[3];
		while(text[3] < text[2])
		{
			cout<<"\n\tError!!! Please Enter # of AUs     "
			    <<"<Range: integer >= # Threads> :: ";
			cin>>text[3];
			if(text[3] >= text[2]) break;
		}


		cout << "\n\tPlease Enter value of λ 0/1 :: ";
		cin>>text[4];
		while(text[4] < 0 || text[4] > 100)
		{
			cout<<"\n\tError!!! Please Enter value of λ 0/1 :: ";
			cin>>text[4];
			if(text[4] >= 0  && text[4] <= 100 ) break;
		}
	}
	int SObj = text[0] + text[1];

	string input = to_string(text[0])+" "+to_string(text[1])+" "
	              +to_string(text[2])+" "+to_string(text[3])+" "
	              +to_string(text[4]);

	// Writing on file_bto
	f_smpBto  << input << endl;
	f_smpMvto << input << endl;
	f_smpOstm << input << endl;
	f_smpMvos << input << endl;
	f_serial  << input << endl;
	f_smpSta  << input << endl;
	f_smpStm  << input << endl;
	f_smpTry  << input << endl;
	file_log  << input << endl;

	// Reding from file
	cout<<"\nCONGRATULATIONS!!!!\nEntered input is updated in all"
	    <<" Directory for Ballot Contract\n\n";
	f_smpBto >> input;
	cout << input << endl;
		cout << "\n======================================"
			 << "======================================\n";


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
	int nProposals = text[0];
	int nVoters    = text[1];

	if(lemda != 0 && nProposals >= 3 && nVoters >= 2 && text[3] > 2) {
		nProposals -= 2;
		nVoters    -= 1;
	}


	genAUs(text[3], nVoters, nProposals, funInContract, text[2]);

//	printAUl();
	return 0;
}
