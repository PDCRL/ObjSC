//#pragma once
#ifndef _FILEOPR_h
#define _FILEOPR_h
 

#include <fstream>
#include <cstring>
#include <random>
#include <vector>
#include <sstream>

#define LOOKUPPer 90

using namespace std;
class FILEOPR
{
	public: 
	FILEOPR(){};//constructor
	
	float getRBal( );
	int getRId( int numSObj );
	int getRFunC( int nCFun );
		
	
	void getInp(int* m, int* n, int* K, double* lemda );
	void writeOpt(int m,int n,int K,double total_time[],float_t mTTime[],float_t vTTime[],int aCount[],int validAUs,list<double>&mIT,list<double>&vIT);
	void genAUs(int numAUs, int SObj, int nFunC, vector<string>& ListAUs);
	
	void printCList(int AU_ID, list<int>&CList);
	void pAUTrns(std::atomic<int> *mAUTrns, int numAUs);
	
	~FILEOPR() { };//destructor
};
#endif