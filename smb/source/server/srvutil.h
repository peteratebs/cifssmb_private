#ifndef __SRV_UTIL_H__
#define __SRV_UTIL_H__
//****************************************************************************
//**
//**    SRVUTIL.H
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "smbdefs.h"
#include "srvnet.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvssn.h"
#include "smbobjs.h"

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define ANY_FID -1
#define ANY_TID -1

//============================================================================
//    INTERFACE STRUCTURES / UTILITY CLASSES
//============================================================================
//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================


dword SMBU_MakeError (PSMB_SESSIONCTX pCtx, byte errorClass, word errorCode);
void SMBU_FillNtError (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pOutHdr, dword errorCode);
void SMBU_FillError (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pOutHdr, byte errorClass, word errorCode);
void SMBU_AddError (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pHdr, PFVOID buf, byte errorClass, word errorCode);



void SMBU_DOSifyName (PFRTCHAR name, PFRTCHAR buf, char pad);
PFRTCHAR SMBU_DOSifyPath (PFRTCHAR name, PFRTCHAR dest, rtsmb_size size);

PFRTCHAR SMBU_GetFilename (PFRTCHAR filename);
PFRTCHAR SMBU_GetPath (PFRTCHAR filename, PFRTCHAR dest);
PFRTCHAR SMBU_FitWildcards (PFRTCHAR pattern, PFRTCHAR solution, PFRTCHAR destPattern, PFRTCHAR dest);
PFRTCHAR SMBU_ShortenSMBPath (PFRTCHAR path);

word SMBU_WriteToFile (PSMB_SESSIONCTX pCtx, int fid, PFBYTE source, word count, BBOOL append, dword offset);
int SMBU_TemporaryFileName (PSMB_SESSIONCTX pCtx, PFRTCHAR dir, PFRTCHAR fullname);

rtsmb_size SMBU_GetSize (PFVOID buf);

BBOOL SMBU_DoesContain (PFRTCHAR src, PFRTCHAR s);

PFRTCHAR SMBU_NormalizeFileName (PSMB_SESSIONCTX pCtx, PFRTCHAR string);
void SMBU_MakePath (PSMB_SESSIONCTX pCtx, PFRTCHAR filepath);

PUSER SMBU_GetUser (PSMB_SESSIONCTX pCtx, word uid);
PTREE SMBU_GetTree (PSMB_SESSIONCTX pCtx, int tid);

int SMBU_SetFidError (PSMB_SESSIONCTX pCtx, word external, byte ec, word error );
void SMBU_SetFidSmb2Flags (PSMB_SESSIONCTX pCtx, word external,   dword smb2flags );
int SMBU_GetFidError (PSMB_SESSIONCTX pCtx, word external, byte *ec, word *error);
int SMBU_GetInternalFid (PSMB_SESSIONCTX pCtx, word external, word flag_mask, word *rflags, dword *rsmb2flags);
int SMBU_SetInternalFid (PSMB_SESSIONCTX pCtx, int internal, PFRTCHAR name, word flags, dword smb2flags, byte *unique_fileid);
void SMBU_SetOplockLevel (PTREE tree, word uid, word externalfid, int oplocklevel);
PFID  SMBU_CheckOplockLevel (PTREE tree, word uid, byte *unique_fileid, int *pCurrentOplockLevel);
void SMBU_ClearInternalFid (PSMB_SESSIONCTX pCtx, word external);
PFRTCHAR SMBU_GetFileNameFromFid (PSMB_SESSIONCTX pCtx, word external);
int SMBU_GetInternalFidFromName (PSMB_SESSIONCTX pCtx, PFRTCHAR name);
int SMBU_PrintFile (PSMB_SESSIONCTX pCtx, int fid);
typedef int(*enumFidFnType)(PFID fid, PNET_SESSIONCTX pnCtx, PSMB_SESSIONCTX pCtx, void *pargs);
int SMBU_EnumerateFids(enumFidFnType fn, void *enumargs);
extern PNET_SESSIONCTX SMBU_Fid2Session(PFID pfid);



void *ptralign(void *ptr, int a);
dword dwordalign(dword original, int a);


//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================

//****************************************************************************
//**
//**    END HEADER SRVUTIL.H
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_UTIL_H__ */
