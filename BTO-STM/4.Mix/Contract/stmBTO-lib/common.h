#ifndef COMMON_H
#define COMMON_H


#include <iostream>
#include <thread>
#include <mutex>              // std::mutex, std::unique_lock
#include <condition_variable> // std::condition_variable
#include <sys/time.h>
#include <math.h>
#include <sstream>
#include <assert.h>
#include <cstring>

typedef uint64_t uint_t;
#define DEBUG_LOGS 0


//!TABLE_SIZE is fixed to 1 for STM
//!BTO/MVTO so it work as a linked list.
const int TABLE_SIZE = 30;

/*!====================================================
 * TYPE OF OPERATION TO BE PERFORMED BY A TRANSACTION !
 *===================================================*/
enum OPN_NAME
{
	WRITE  = 5,//write
	DELETE = 6,
	READ   = 7,//read
	//ERROR
	WRONG_OPN        = 8, //PROGRAM SHALL NOT PROCEED
	DEFAULT_OPN_NAME = 111
};


/*!==================================
 * TRANSACTION AND OPERATION STATUS !
 *=================================*/
enum STATUS
{
	ABORT             = 10,
	OK                = 11,
	FAIL              = 12,
	COMMIT            = 13,
	RETRY             = 14,
	//error
	BUCKET_EMPTY      = 100,
	VARIABLE_NULL     = 101,
	WRONG_STATUS      = 102, //PROGRAM SHALL NOT PROCEED
	DEFAULT_OP_STATUS = 222
};

/*!===========================================================================
 * THREE TYPE OF VALIDATION::                                                !
 * V1: return value validation (inter transaction i.e. pred curr validation).!
 * V2: time-stamp validation (inter trans: for abort and retry based on TS). !
 * V3: intera-transaction validation (oper validation with in trans.         !
 *==========================================================================*/
enum VALIDATION_TYPE
{
	RV,
	TRYCOMMIT
};


#define status(x) ((x==10)? ("**ABORT**"):((x==11)?("OK"):((x==12)?("FAIL"):((x==13)?("COMMIT"):((x==14)?("RETRY"):((x==102)?("WRONG_STATUS"):((x==222)?("DEFAULT_OP_STATUS!!!"):("***SCREW"))))))))
#define opname(x) ((x==5)?("WRITE"):((x==6)?("DELETE"):((x==7)?("READ"):((x==8)?("WRONG_OPN**"):("DEFAULT_OPN_NAME")))))


/*!=================================================================
 * RL_BL list: INSERTING THE NODE WHICH IS IN RED LIST TO BLUELIST !
 * RL        : INSERTING THE NODE INTO RED LIST ONLY               !
 * BL        : INSERTING THE NODE INTO RED AS WELL AS BLUE LIST.   !
 *================================================================*/
enum LIST_TYPE
{
	RL_BL,
	RL,
	BL
};

//INT_MAX IS A MACRO THAT SPECIFIES THAT AN INTEGER
//VARIABLE CANNOT STORE ANY VALUE BEYOND THIS LIMIT.
#define BAD_INDEX INT_MAX

//INT_MIN SPECIFIES THAT AN INTEGER VARIABLE CANNOT
//STORE ANY VALUE BELOW THIS LIMIT.
#define BAD_VALUE INT_MIN

#define MAX_KEY 50000

/*!=============
 * INIT VALUES !
 *============*/
#define DEFAULT_KEY    INT_MIN
#define DEFAULT_VALUE  INT_MIN
#define DEFAULT_TS     0
#define DEFAULT_MARKED 0

#define elog(_message_)  do {fprintf(stderr, "%s():%s:%u: %s\n", __FUNCTION__, __FILE__, __LINE__,_message_); fflush(stderr);}while(0);




//mutex copyBytes_lock;
void copyBytes( void *a, void *b, int howMany )
{
	int i;
	char* x = (char*) a;
	char* y = (char*) b;
	for( i  = 0; i<howMany; i++)
	{
		*(x+i) = *(y+i);
	}
};

class voidVal
{
  public:
	int size;
	void *val;
	voidVal(int size)
	{
		this->size = size;
		this->val     = operator new(size);
		memset((char*)(this->val), 0, size);
	}
	~voidVal()
	{
	
	}
};


#endif //#define COMMON_H
