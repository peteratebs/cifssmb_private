#ifndef __SMB2_SRV_ASSERT__
#define __SMB2_SRV_ASSERT__


//****************************************************************************
//**
//**    SMB2_SRV_ASSERT.H
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================

#include "com_smb2.h"
#include "com_smb2_ssn.h"
#include "com_smb2_wiredefs.h"

BBOOL assert_smb2_uid(smb2_stream  *pStream);
BBOOL assert_smb2_tid(smb2_stream  *pStream);
BBOOL assert_smb2_permission(smb2_stream  *pStream,byte permission);
BBOOL assert_smb2_Fid (smb2_stream  *pStream, word external, word flag);


#define ASSERT_SMB2_UID(S) if(assert_smb2_uid(S)) return TRUE;   //
#define ASSERT_SMB2_TID(S) if(assert_smb2_tid(S)) return TRUE;  //
#define ASSERT_SMB2_PERMISSION(S,P) if(assert_smb2_permission(S,P)) return TRUE;  //  // Checks permission on pCtx->tid
#define ASSERT_SMB2_FID(S,E,F) if(assert_smb2_Fid(S,E,F)) return TRUE;  //  // Checks permission on pCtx->fid



#endif /* __SMB2_SRV_ASSERT__ */
