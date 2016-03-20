#ifndef __SRV_SRVSVC_H__
#define __SRV_SRVSVC_H__
//****************************************************************************
//**
//**    SrvSrvc.H
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvssn.h"

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define TRANS_TRANSACT_NMPIPE   0x26  // See section 2.2.2.2 - TRANS_TRANSACT_NMPIPE is all that's supported, provides enough to enumerate shares.


//============================================================================
//    INTERFACE STRUCTURES / UTILITY CLASSES
//============================================================================
//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
// Interface between stream and SrvSrvc
typedef struct StreamtoSrvSrvc_s {
 word  reply_data_count;
 void *reply_heap_data;
 void *reply_response_data;
 BBOOL in_use;
} StreamtoSrvSrvc;

//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================

int SRVSVC_ProcTransaction (PSMB_SESSIONCTX pCtx,
	PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
	PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left);

int SMBU_StreamWriteToSrvcSrvc (void *pIndata, rtsmb_size size_left,StreamtoSrvSrvc *pReturn);


//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================



//****************************************************************************
//**
//**    END HEADER SrvSrvc.H
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_SRVSVC_H__ */
