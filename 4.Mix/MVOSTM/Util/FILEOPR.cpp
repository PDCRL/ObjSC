#include "FILEOPR.h"

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/*!!! RANDOM NUMBER GENERATER FOR ACCOUNT BALANCE !!!*/
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
float FILEOPR::getRBal( ) 
{
	//Random seed.
	random_device rd;
	// Initialize Mersenne Twister 
	// pseudo-random number generator.
	mt19937 gen(rd());
	
	//Uniformly distributed in range (1, 1000)
	uniform_int_distribution<> dis( 1, 1000 );
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


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! getInp() reads #Shared Objects, #Threads, #AUs,  !
!!! & random delay seed "Lemda" from input file.     !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
void FILEOPR::getInp( int input[] ) 
{
	string ipBuffer[8]; //stores input from file
	
	ifstream inputFile;
	inputFile.open ( "inp-output/inp-params.txt" );
	while(!inputFile)
	{
		cerr << "Use!! Unable to open inputfile <inp-params.txt>\n\n";
		exit(1); //call system to stop
	}
	int i = 0;
	while( !inputFile.eof( ) )
	{
		inputFile >> ipBuffer[i];
		i++;
	}
	input[0] = stoi(ipBuffer[0]);
	input[1] = stoi(ipBuffer[1]);
	input[2] = stoi(ipBuffer[2]);
	input[3] = stoi(ipBuffer[3]);
	input[4] = stoi(ipBuffer[4]);
	input[5] = stoi(ipBuffer[5]);
	input[6] = stoi(ipBuffer[6]);
	input[7] = stoi(ipBuffer[7]);
	inputFile.close( );
	return;
}


/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! Time taken by algorithm  !
!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
void FILEOPR::writeOpt( int n, int K, 
						double total_time[],
						float_t mTTime[],
						float_t vTTime[],
						int aCount[],
						int validAUs,
						list<double>&mIT,
						list<double>&vIT)
{
	float_t minTime = 0;//total time miner thread
	float_t valTime = 0;//total time validator thred
	
	for(int i = 0; i < n; i++) minTime = minTime + mTTime[i];

	for(int i = 0; i < n; i++) valTime = valTime + vTTime[i];

	int total_Abort = 0;	
	for(int i = 0; i < n; i++)
	{
		total_Abort = total_Abort + aCount[i];
	}

	//Average Time Taken by one Miner Thread = Total Time/# Threads
//	cout<<"\n    Avg Miner = "<<minTime/n<<" microseconds\n";
	mIT.push_back(minTime/n);

	//Average Time Taken by one Validator Thread = Total Time/# Threads
//	cout<<"Avg Validator = "<<valTime/n<<" microseconds\n";
	vIT.push_back(valTime/n);
	
	//Total Avg Time Taken by Both Algorithm Threads
//	cout<<"Total (M + V) = "<<(minTime/n + valTime/n)<<" microseconds\n";
	return;
}
	
	
	
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! genAUs() generate and store the Atomic Unites     !!!
!!! (transactions to be executed by miner/validator)  !!!
!!! in a list & file, nFunC: parallel fun's (AUs) in  !!!
!!! smart contract, numAUs: number of AUs to be       !!!
!!! requested by client to execute                    !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
void FILEOPR::genAUs(int input[], int nCF, int nBF, 
						int nAF, vector<string>& ListAUs)
{
	std::ifstream in( "inp-output/listAUs.txt" );
	for( std::string trns; getline( in, trns ); )
	{
//		cout<<trns<<"\n";
		ListAUs.push_back(trns);
	}
	in.close();
/*
	int numAUs     = input[1]; // # of AUs or Transactions;
	int CoinSObj   = input[2]; // # Coin Account Shared Object.
	int BalPrObj   = input[3]; // # Ballot Proposal Shared Object.
	int BalVotObj  = input[4]; // # Ballot Voter Shared Object.
	int AuctBidObj = input[5]; // # Auction Bidder Shared Object.
	
	//Random_gen r_val;
	int auCount = 1;
	ofstream out_file;
	out_file.open("inp-output/listAUs.txt");
	ListAUs.clear();

	int coinAU = ceil(numAUs*.34);
	int ballAU = ceil(numAUs*.33);
	int auctAU = ceil(numAUs*.33);

	int cCount = 1, bCount = 1, aCount = 1;
	while(auCount <= numAUs)
	{
		if(cCount <= coinAU)//Coin contract
		{
			//gives contract func: 1 = "send()" and 2 = "get_bal()"
			int funName = getRFunC( nCF );
			if(funName == 1 )
			{
					int from = getRId(CoinSObj);
					int to   = getRId(CoinSObj);
				
					while (from == to)
					{
						to = getRId(CoinSObj);
					}
					int ammount = getRBal( );
				
					string trns = to_string(auCount)+" send "
									+to_string(from)+" "+to_string(to)
									+" "+to_string(ammount)+"\n";
					out_file << trns;
					ListAUs.push_back(trns);
					auCount++;
					cCount++;
			}
			else if (funName == 2)
			{
					int id      = getRId(CoinSObj);
					string trns = to_string(auCount)
									+" get_bal "+to_string(id)+"\n";
				
					out_file << trns;
					ListAUs.push_back(trns);
					auCount++;
					cCount++;
			}
		}
		if(bCount <= ballAU)//Ballot Contract
		{
			//gives contract func: 1 = "delegate()" and 2 = "vote()"
			int funName = getRFunC( nBF );
			if(funName == 1)
			{
				int from = getRId(BalVotObj);
				int to   = getRId(BalVotObj);
			
				while (from == to)
				{
					to = getRId(BalVotObj);
				}
				string t = to_string(auCount)+" delegate "+
							to_string(from)+" "+to_string(to)+"\n";
				out_file << t;
				ListAUs.push_back(t);
				auCount++;
				bCount++;
			}
			else if (funName == 2)
			{
				int vID  = getRId(BalVotObj);//voter ID
				int pID  = getRId(BalPrObj);//proposalID
				string t = to_string(auCount)+" vote "+
								to_string(vID)+" "+to_string(pID)+"\n";
				out_file << t;
				ListAUs.push_back(t);
				auCount++;
				bCount++;
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
				int payable  = getRBal( );
				int bidderID = getRId(AuctBidObj);
				int bidValue = getRBal( );
				string t = to_string(auCount)+" bid "
							+to_string(payable)+" "
							+to_string(bidderID)+" "
							+to_string(bidValue)+"\n";
				out_file << t;
				ListAUs.push_back(t);
				auCount++;
				aCount++;
			}
			else if (funName == 2)
			{
				int bidderID = getRId(AuctBidObj);
				string t = to_string(auCount)+" withdraw "
							+to_string(bidderID)+"\n";
				out_file << t;
				ListAUs.push_back(t);
				auCount++;
				aCount++;
			}
			else if (funName == 3)
			{
				string t = to_string(auCount)+" auction_end\n";
			
				out_file << t;
				ListAUs.push_back(t);
				auCount++;
				aCount++;
			}
		}
	}
	out_file.close ( );
	return;
*/
}

/*------------------------------------------
! Print Conflict List of given Atomic Unit.!
------------------------------------------*/
void FILEOPR::printCList(int AU_ID, list<int>&CList)
{
	string str;
	for(auto it = CList.begin(); it != CList.end(); it++)
		str  = str + to_string(*it)+" ";
	
	cout<< " AU_ID- "+to_string(AU_ID)
			+" Conf_list (time-stamp) [ "+str+"]\n";
	return;
}


/*----------------------------------------------
! Print Table used for Mapping AUs with        !
! Committed Transaction (that has executed AU) !
----------------------------------------------*/
void FILEOPR::pAUTrns(std::atomic<int> *mAUTrns, int numAUs)
{
	cout<<"\n========================\n";
	cout << "  AU_ID |  Timestamp";
	cout<<"\n========================\n";
	for (int i = 0; i < numAUs; i++)
		cout  <<  "   " << i+1 <<  "\t|    " << mAUTrns[i] << "\n";
	cout<<"========================\n";	
	return;
}
