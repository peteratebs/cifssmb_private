#ifndef __SMB2_YIELD_H__
#define __SMB2_YIELD_H__

//****************************************************************************
//**
//**    Header - Description
//**    Definitions for stream cooms for SMB2 server and client.
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
void RtsmbYieldPushFrame(smb2_stream *pStream);
void RtsmbYieldPopFrame(smb2_stream *pStream);
void RtsmbYieldYield(smb2_stream *pStream, dword yield_duration);
void RtsmbYieldSignal(smb2_stream *pStream);
BBOOL RtsmbYieldCheckSignalled(PSMB_SESSIONCTX pSctx);
BBOOL RtsmbYieldCheckTimeOut(PSMB_SESSIONCTX pSctx);
BBOOL RtsmbYieldCheckBlocked(PSMB_SESSIONCTX pSctx);
void RtsmbYieldSetTimeOut(PSMB_SESSIONCTX pSctx,dword yieldTimeout);


#endif // #define __SMB2_YILED_H__
