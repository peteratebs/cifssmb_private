//
// SRV_SMB2_SSN.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles most of the actual processing of packets for the RTSMB server.
//

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "rtpmem.h"
#include "rtptime.h"
#include "srvssn.h"
#include "srv_smb2_yield.h"

void RtsmbYieldYield(smb2_stream *pStream, dword yield_duration)
{
    pStream->doSessionYield = TRUE;
    pStream->yield_duration = yield_duration;

}
extern void RtsmbYieldFreeBodyContext(pSmb2SrvModel_Session pSession)
{
  if (pSession->SMB2_BodyContext) rtp_free(pSession->SMB2_BodyContext);
  pSession->SMB2_BodyContext = 0;
//  Smb2Sessions[i].SMB2_BodyContext=(void *)rtp_malloc(sizeof(ProcSMB2_BodyContext));
}
extern void RtsmbYieldAllocBodyContext(pSmb2SrvModel_Session pSession)
{
  RtsmbYieldFreeBodyContext(pSession); // Does nothing if already free
  pSession->SMB2_BodyContext=             (void *)rtp_malloc(sizeof(ProcSMB2_BodyContext));
}

// These two routines save the necessary pointers in the stream structure
// So that SMB2 create and write commands can exit and leave the stream strcuture usable in a replay
void RtsmbYieldPushFrame(smb2_stream *pStream)
{
  pStream->StreamInputPointerState.pInBuf = pStream->pInBuf;
  pStream->StreamInputPointerState.read_buffer_remaining = pStream->read_buffer_remaining;
}
void RtsmbYieldPopFrame(smb2_stream *pStream)
{
  pStream->pInBuf = pStream->StreamInputPointerState.pInBuf;
  pStream->read_buffer_remaining = pStream->StreamInputPointerState.read_buffer_remaining;
}

BBOOL RtsmbYieldCheckSignalled(PSMB_SESSIONCTX pSctx)
{
  return (pSctx->yieldFlags & YIELDSIGNALLED) == YIELDSIGNALLED;
}
void RtsmbYieldSetTimeOut(PSMB_SESSIONCTX pSctx,dword yieldTimeout)
{
 pSctx->yieldTimeout = yieldTimeout;

}
BBOOL RtsmbYieldCheckTimeOut(PSMB_SESSIONCTX pSctx)
{
 if (rtp_get_system_msec() > pSctx->yieldTimeout)
 {
    pSctx->yieldFlags |= YIELDTIMEDOUT;
 }
 return (pSctx->yieldFlags & YIELDTIMEDOUT) == YIELDTIMEDOUT;
}
BBOOL RtsmbYieldCheckBlocked(PSMB_SESSIONCTX pSctx)
{
  return pSctx->yieldTimeout != 0;
}

#endif
#endif
