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
#include "srvnet.h"

static const byte local_ip_address[] = {0x7f,0,0,1};
static const byte local_ip_mask[] = {0xff,0,0,0};


BBOOL RtsmbYieldBindSignalSocket(NET_THREAD_T  * pThread)
{
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD: RtsmbYieldBindSignalSocket: calling socket on portnumber: %u\n",pThread->yield_sock_portnumber);
  rtsmb_net_socket_new (&pThread->yield_sock, pThread->yield_sock_portnumber, FALSE);
//    int rtsmb_net_socket_new (RTP_SOCKET* sock_ptr, int port, BBOOL reliable)
  return TRUE;
}
// HEREHERE
void RtsmbYieldSendSignalSocketSession(PNET_SESSIONCTX pNctxt)
{
  pNctxt->smbCtx.yieldFlags |= YIELDSIGNALLED;
  int r = rtsmb_net_write_datagram (pNctxt->pThread->yield_sock, local_ip_address, pNctxt->pThread->yield_sock_portnumber, "SIG", 4);  // Four is the minimum size might as well send something
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: r:%d sock[%d] RtsmbYieldSendSignalSocketTest %X -> %X\n", r, pNctxt->pThread->yield_sock,&pNctxt->smbCtx,pNctxt->smbCtx.yieldFlags);
}

void RtsmbYieldSendSignalSocket(smb2_stream  *pStream)
{
  PNET_SESSIONCTX pNctxt = findSessionByContext(pStream->psmb2Session->pSmbCtx);
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldSendSignalSocket to %X\n", pStream->psmb2Session->pSmbCtx);
  if (pNctxt)
  {
    RtsmbYieldSendSignalSocketSession(pNctxt);
  }
}

void RtsmbYieldRecvSignalSocket(RTP_SOCKET sock)
{
  byte remote_ip[4];
  byte messagebuffer[5];
  int  size, remote_port;

  size = rtsmb_net_read_datagram (sock, messagebuffer, 4, remote_ip, &remote_port);
  messagebuffer[4]=0;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldRecvSignalSocket recved %s\n", (char *)messagebuffer);
}

int rtsmb_net_read_datagram (RTP_SOCKET sock, PFVOID pData, int size, PFBYTE remoteAddr, PFINT remotePort);


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
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldCheckSignalled %X -> %X\n", pSctx,pSctx->yieldFlags);
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldCheckSignalled == %d\n", (pSctx->yieldFlags & YIELDSIGNALLED) == YIELDSIGNALLED);
  BBOOL r = (pSctx->yieldFlags & YIELDSIGNALLED) == YIELDSIGNALLED;
  if (r)
        pSctx->yieldFlags &=  ~YIELDSIGNALLED;
  return r;
}
void RtsmbYieldSetTimeOut(PSMB_SESSIONCTX pSctx,dword yieldTimeout)
{
 pSctx->yieldTimeout = yieldTimeout;

}
BBOOL RtsmbYieldCheckTimeOut(PSMB_SESSIONCTX pSctx)
{
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldCheckTimeOut Check %lu > %lu\n", rtp_get_system_msec(), pSctx->yieldTimeout);
 if (rtp_get_system_msec() > pSctx->yieldTimeout)
 {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldCheckTimeOut TRUE\n");
    pSctx->yieldFlags |= YIELDTIMEDOUT;
 }
 else
    pSctx->yieldFlags &= ~YIELDTIMEDOUT;
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: RtsmbYieldCheckTimeOut == %d\n", (pSctx->yieldFlags & YIELDTIMEDOUT) == YIELDTIMEDOUT);
 return (pSctx->yieldFlags & YIELDTIMEDOUT) == YIELDTIMEDOUT;
}
BBOOL RtsmbYieldCheckBlocked(PSMB_SESSIONCTX pSctx)
{
  return pSctx->yieldTimeout != 0;
}

#endif
#endif
