/*
* Compile:: g++ -std=c++17 GenAUs.cpp -o genAUs -O3
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <random>
#include <vector>
#include <sstream>
#include <list>

#define CFCount 3//# methods in coin contract.
#define BFCount 5//# methods in ballot contract.
#define AFConut 6//# methods in simple auction contract.

//Out of coin AUs, what % will be get_Balance()?
#define LOOKUPPer 90

//Out of Ballot AUs, what % will be delegate()?
#define delegatePer 1

//Out of Auction AUs, what % will be bid() and withdraw()?
#define bidPer 10
#define withdrawPer 10


#define CoinIdStart 5000
#define VoterIdStart 10000 //Proposal Id is -Ve in I/P file for Bin approach


using namespace std;


int  text[200]; //! for input
bool cmdLineArg = true;
int  lemda       = 0;

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

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! genAUs() generate and store the Atomic Unites     !!!
!!! (transactions to be executed by miner/validator)  !!!
!!! in a list & file, nFunC: parallel fun's (AUs) in  !!!
!!! smart contract, numAUs: number of AUs to be       !!!
!!! requested by client to execute                    !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
void genAUs(int input[], int nCF, int nBF, int nAF)
{
	fstream f_smpBto, f_smpMvto, f_smpOstm, f_smpMvos, f_serial;
	fstream f_smpSta, f_smpStm,  f_smpTry,  file_log;

	
	f_smpBto.open ("BTO-STM/inp-output/listAUs.txt",    ios::out);
	f_smpMvto.open("MVTO/inp-output/listAUs.txt",       ios::out);
	f_smpOstm.open("OSTM/inp-output/listAUs.txt",       ios::out);
	f_smpMvos.open("MVOSTM/inp-output/listAUs.txt",     ios::out);
	f_serial.open ("Serial/inp-output/listAUs.txt",     ios::out);
	f_smpSta.open ("Static-Bin/inp-output/listAUs.txt", ios::out);
	f_smpStm.open ("STM-Bin/inp-output/listAUs.txt",    ios::out);
	f_smpTry.open ("Spec-Bin/inp-output/listAUs.txt",   ios::out);


	int Sobj = text[2]+text[3]+text[4]+text[5];


	int numAUs     = input[1]; // # of AUs or Transactions;
	int CoinSObj   = input[2]; // # Coin Account Shared Object.
	int BalPrObj   = input[3]; // # Ballot Proposal Shared Object.
	int BalVotObj  = input[4]; // # Ballot Voter Shared Object.
	int AuctBidObj = input[5]; // # Auction Bidder Shared Object.

	if(lemda != 0 && CoinSObj > 4 && numAUs > 2) {
		CoinSObj -= 3;
	}

	//Respective Contract AUs %.
	int coinAU = ceil(numAUs*.34);
	int ballAU = ceil(numAUs*.33);
	int auctAU = ceil(numAUs*.33);


	int getBal = ceil((coinAU * (LOOKUPPer)) /100);
	int sendAB = coinAU - getBal;
	int cgetBalCount = 1, SendABCount = 1;

	int delgC = ceil((ballAU * (delegatePer)) /100);
	int voterC = ballAU - delgC;
	int local_delgC = 1, local_voterC = 1;

	int bidC = ceil((auctAU * (bidPer)) /100);
	int withdrawC = ceil((auctAU * (withdrawPer)) /100);
	int endC = auctAU - (bidC + withdrawC);
	int local_bidC = 1, local_withdrawC = 1, local_endC = 1;


	int auCount = 1;
	int cCount = 1, bCount = 1, aCount = 1;
	while(auCount <= numAUs)
	{	
		if(cCount <= coinAU)//Coin contract
		{
			int funName;
			if(lemda != 0 && auCount < 3) funName = 1;
			else funName = getRFunC( nCF );
			if(funName == 1 )
			{
				if(SendABCount <= sendAB)
				{
					int from = getRId(CoinSObj);
					int to   = getRId(CoinSObj);
				
					while (from == to) to = getRId(CoinSObj);

					int ammount = getRBal( );

					string trns;
					if(lemda != 0 && auCount < 3) {
						trns = to_string(1)+" send "
						      +to_string(CoinSObj+1)+" "
						      +to_string(CoinSObj+2)+" "
						      +to_string(0)+"\n";

						trns = trns + to_string(2)+" send "
						      +to_string(CoinSObj+1)+" "
						      +to_string(CoinSObj+3)+" "
						      +to_string(0)+"\n";
					}
					else {
						trns = to_string(auCount)+" send "
						      +to_string(from)+" "
						      +to_string(to)+" "
						      +to_string(ammount)+"\n";
					}

					f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
					f_smpMvos << trns;
					f_serial  << trns;
					f_smpStm  << trns;
					file_log  << trns;



					if(lemda != 0 && auCount < 3) {
						trns = to_string(1)+" send "
						      +to_string(CoinSObj+1+CoinIdStart)+" "
						      +to_string(CoinSObj+2+CoinIdStart)+" "
						      +to_string(0)+"\n";

						trns = trns + to_string(2)+" send "
						            + to_string(CoinSObj+1+CoinIdStart)+" "
						            + to_string(CoinSObj+3+CoinIdStart)+" "
						            + to_string(0)+"\n";
						auCount++;
						cCount++;
						SendABCount++;
					}
					else {
						trns = to_string(auCount)+" send "
							  +to_string(from+CoinIdStart)+" "
							  +to_string(to+CoinIdStart)
							  +" "+to_string(ammount)+"\n";
					}

					f_smpSta  << trns;
					f_smpTry  << trns;

					auCount++;
					cCount++;
					SendABCount++;
				}
			}
			else if (funName == 2)
			{
				if(cgetBalCount <= getBal)
				{
					int id      = getRId(CoinSObj);
					string trns = to_string(auCount)+" get_bal "
					             +to_string(id)+"\n";
				
					f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
					f_smpMvos << trns;
					f_serial  << trns;
					f_smpStm  << trns;
					file_log  << trns;


					trns = to_string(auCount) +" get_bal "
					      +to_string(id+CoinIdStart)+"\n";

					f_smpSta  << trns;
					f_smpTry  << trns;

					auCount++;
					cCount++;
					cgetBalCount++;
				}
			}
		}
		if(bCount <= ballAU)//Ballot Contract
		{
			//gives contract func: 1 = "delegate()" and 2 = "vote()"
			int funName = getRFunC( nBF );
			if(funName == 1)
			{
				if(local_delgC <= delgC)
				{
					int from = getRId(BalVotObj);
					int to   = getRId(BalVotObj);
			
					while (from == to) to = getRId(BalVotObj);

					string trns = to_string(auCount)+" delegate "+
								to_string(from)+" "+to_string(to)+"\n";
				
					f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
					f_smpMvos << trns;
					f_serial  << trns;
					f_smpStm  << trns;
					file_log  << trns;


					trns = to_string(auCount)+" delegate "+
								to_string(from+VoterIdStart)+" "
								+to_string(to+VoterIdStart)+"\n";

					f_smpSta  << trns;
					f_smpTry  << trns;

					auCount++;
					bCount++;
					local_delgC++;
				}
			}
			else if (funName == 2)
			{
				if(local_voterC <= voterC)
				{
					int vID  = getRId(BalVotObj);//voter ID
					int pID  = getRId(BalPrObj);//proposalID
					string trns = to_string(auCount)+" vote "+
									to_string(vID)+" "+to_string(pID)+"\n";

					f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
					f_smpMvos << trns;
					f_serial  << trns;
					file_log  << trns;


					trns = to_string(auCount)+" vote "+
					       to_string(vID)+" "+
					       to_string(-pID)+"\n";

					f_smpStm  << trns;


					trns = to_string(auCount)+" vote "+
					       to_string(vID+VoterIdStart)+" "+
					       to_string(-pID)+"\n";

					f_smpSta  << trns;
					f_smpTry  << trns;

					auCount++;
					bCount++;
					local_voterC++;
				}
			}
		}
		if(aCount <= auctAU)//Auction Contract
		{
			// Gives Smart contract func: 
			// 1 = "bid()"
			// 2 = "withdraw()"
			// 3 = "auction_end()"
			int funName = getRFunC( nAF );
			if(funName == 1)
			{
				if(local_bidC <= bidC)
				{
					int payable  = getRBal( );
					int bidderID = getRId(AuctBidObj);
					int bidValue = getRBal( );
					string trns = to_string(auCount)+" bid "
					             +to_string(payable)+" "
					             +to_string(bidderID)+" "
					             +to_string(bidValue)+"\n";

					f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
					f_smpMvos << trns;
					f_serial  << trns;
					f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
					file_log  << trns;

					auCount++;
					aCount++;
					local_bidC++;
				}
			}
			else if (funName == 2)
			{
				if(local_withdrawC <= withdrawC)
				{
					int bidderID = getRId(AuctBidObj);
					string trns  = to_string(auCount)+" withdraw "
					              +to_string(bidderID)+"\n";

					f_smpBto  << trns; f_smpMvto << trns; f_smpOstm << trns;
					f_smpMvos << trns;
					f_serial  << trns;
					f_smpSta  << trns; f_smpStm << trns;  f_smpTry  << trns;
					file_log  << trns;

					auCount++;
					aCount++;
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
					aCount++;
					local_endC++;
				}
			}
		}
	}
	//closing the file
	f_smpBto.close(); f_smpMvto.close(); f_smpOstm.close(); f_smpMvos.close();
	f_serial.close();
	f_smpSta.close(); f_smpStm.close();  f_smpTry.close();
	file_log.close();
	return;
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
	cout << "\nEnter the values of the input for Mix Contract";
	cout << "\nPLEASE FOLLOW THE INSTRUCTIONS::";
	cout << "\n===============================================================";
	cout << "\nInput will be updated in <Algo Name>/inp-output/inp-params.txt";
	cout << "\nInput should be:\n"
		 << "Line-1 space seprated 2 values \t<# of threads, # of AUs>\n"
		 << "Line-2 1 values \t\t<# Account in Coin Contract>\n"
		 << "Line-3 space seprated 2 values  <# Proposal, # Voter"
		 << " in Ballot Contract>\n"
		 << "Line-4 space seprated 2 values  <# Bidder, Bid End Time"
		 << " in Auction Contract>\n"
		 << "Line-5 1 values \t\t<Positive Integer λ 0/1>\n";
	cout << "\n--------------------------------------------------------------\n"
		 << "Sample Input File:";
	cout << "\n50 250\n50\n5 250\n200 200\n5\n";
	cout << "\tWhere:\n";
	cout << "\t1. n: # of Threads <Range: 1 to maximum available H/W threads>\n"; 
	cout << "\t2. K: # of Total AUs or Trans <Range: integer >= # Threads>\n";
	cout << "\t3. nAccounts: # of Account in Coin Contract <Range: 2 to 2000>\n";
	cout << "\t4. nProposal: # of Proposal <Range: 1 to 1000>\n";
	cout << "\t5. nVoter: # of Voters <Range: 1 to 3000>\n";
	cout << "\t6. nBidder: # of Bidder <Range: 2 to 2000>\n";
	cout << "\t7. bidEndTime: Time in milliseconds <Range: 1 to - >\n";
	cout << "\t8. λ: if Miner is Maliciois then 1 else 0";
	cout << "\n-------------------------------------------------------------\n";

	if(cmdLineArg) {
		text[0] = atoi(argv[1]);
		text[1] = atoi(argv[2]);
		text[2] = atoi(argv[3]);
		text[3] = atoi(argv[4]);
		text[4] = atoi(argv[5]);
		text[5] = atoi(argv[6]);
		text[6] = atoi(argv[7]);
		text[7] = atoi(argv[8]);

		string input = to_string(text[0])+" "+to_string(text[1])+"\n"
              +to_string(text[2])+"\n"+to_string(text[3])+" "
              +to_string(text[4])+"\n"+to_string(text[5])+" "
              +to_string(text[6])+"\n"+to_string(text[7]);

		cout << input << endl;
		cout << "\n======================================"
			 << "======================================\n";
	}
	else {
		cout << "\n\tPlease Enter # of Threads <Range: 1 to max available> :: ";
		cin>>text[0];
		while(text[0] <= 0)
		{
			cout<<"\n\tError!!! Please Enter # of Threads from"
				<<" <Range: from 1 to max available> :: ";
			cin>>text[0];
			if(text[0] > 0) break;
		}

		cout<<"\n\tPlease Enter # of AUs    <Range: integer >= # Threads> :: ";
		cin>>text[1];
		while(text[1] < text[0])
		{
			cout<<"\n\tError!!! Please Enter # of AUs "
				<<"    <Range: integer >= # Threads> :: ";
			cin>>text[1];
			if(text[1] >= text[1]) break;
		}

		cout << "\n\tPlease Enter # of Accounts in "
			 << "Coin Contract <Range: 2 to 5000> :: ";
		cin>>text[2];
		while(text[2] < 2 || text[2] > 5000)
		{
			cout<<"\n\tError!!! Please Enter # of Accounts in"
				<<" Coin Contract from <Range: 2 to 5000> :: ";
			cin>>text[2];
			if(text[2] > 2  && text[2] < 5000 ) break;
		}


		cout << "\n\tPlease Enter # of Proposals in Ballot"
			 << " Contract <Range: 1 to 1000> :: ";
		cin>>text[3];
		while(text[3] < 1 || text[3] > 1000)
		{
			cout<<"\n\tError!!! Please Enter # of Proposals"
				<<" in Ballot Contract from <Range: 1 to 1000> :: ";
			cin>>text[3];
			if(text[3] > 0  && text[3] < 1000 ) break;
		}


		cout << "\n\tPlease Enter # of Voters in Ballot "
			 << "Contract <Range: 1 to 5000> :: ";
		cin>>text[4];
		while(text[4] < 1 || text[4] > 5000)
		{
			cout<<"\n\tError!!! Please Enter # of Voters in "
				<<"Ballot Contract <Range: 1 to 5000> :: ";
			cin>>text[4];
			if(text[4] > 0  && text[4] < 5000 ) break;
		}


		cout << "\n\tPlease Enter # of Bidders in Auction "
			 <<"Contract <Range: 2 to 5000> :: ";
		cin>>text[5];
		while(text[5] < 2 || text[5] > 5000)
		{
			cout<<"\n\tError!!! Please Enter # of Bidders in"
				<<" Auction Contract from <Range: 2 to 5000> :: ";
			cin>>text[5];
			if(text[5] > 0  && text[5] < 5000 ) break;
		}


		cout << "\n\tPlease Enter bidEndTime: Time in milliseconds"
			 <<" in Auction Contract<Range: 1 to - > :: ";
		cin>>text[6];
		while(text[6] < 1)
		{
			cout<<"\n\tError!!! Please Enter bidEndTime in milliseconds"
				<<" in Auction Contract from <Range: 1 to - >  :: ";
			cin>>text[6];
			if(text[6] > 0 ) break;
		}

		cout << "\n\tPlease Enter value of λ 0/1 :: ";
		cin>>text[7];
		while(text[7] < 0 || text[7] > 1)
		{
			cout<<"\n\tError!!! Please Enter value of λ 0/1 :: ";
			cin>>text[7];
			if(text[7] >= 0  && text[7] <= 1 ) break;
		}
	}


	string input = to_string(text[0])+" "+to_string(text[1])+"\n"
	              +to_string(text[2])+"\n"
	              +to_string(text[3])+" "+to_string(text[4])+"\n"
	              +to_string(text[5])+" "+to_string(text[6])+"\n"
	              +to_string(text[7]);


	int Sobj = text[2]+text[3]+text[4]+text[5];

	// Writing on file_bto
	f_smpBto  << input << endl; f_smpMvto << input << endl;
	f_smpOstm << input << endl; f_smpMvos << input << endl;
	f_serial  << input << endl;
	f_smpSta  << input << endl; f_smpStm  << input << endl;
	f_smpTry  << input << endl;
	f_scvTry  << input << endl;
	file_log  << input << endl;

	// Reding from file
	cout<<"\nCONGRATULATIONS!!!!\nEntered input is updated."
		<<"\nin all the directories for Mixed Contract\n\n";
	f_smpBto >> input;
	cout << input << endl;
	cout <<"\n=============================================================\n";


	//closing the file
	f_smpBto.close(); f_smpMvto.close(); f_smpOstm.close(); f_smpMvos.close();
	f_serial.close();
	f_smpSta.close(); f_smpStm.close();  f_smpTry.close();
	file_log.close();

	lemda = text[7]; //! if lemda is 0 miner is non-malicious else malicious.

	genAUs(text, CFCount, BFCount, AFConut);

//	printAUl();
	return 0;
}
