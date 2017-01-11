//
// SRV_SMB2_PROC_NOTIFY.C -
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

#define SMB2_OPLOCK_MAX_WAIT_MILLIS          20000 // Don't know what this shold be


#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */
#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "srvcfg.h"
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "rtptime.h"
#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"
#include "rtpmem.h"
#include "srv_smb2_proc_fileio.h"
#include "remotediags.h"
#include "srvoplocks.h"
#include "smbnet.h"
#include "srvnotify.h"
#include "srvsmbssn.h"   // YIELD_BASE_PORTNUMBER

#warning duplicate define
#define MAX_PENDING_NOTIFIES 256
typedef struct notify_request_s {
 BBOOL in_use;
 uint64_t MessageId;                   // Message ID from the header so we can find it to cancel it
 rtplatform_notify_request_args args;
 RTSMB2_CHANGE_NOTIFY_C command;
} notify_request_t;

#define MAX_PENDING_NOTIFIES 256
notify_request_t notify_requests[MAX_PENDING_NOTIFIES];
int notify_requests_in_use;

// Return the index of a usable request struture else -i
static int allocate_notify_request(void) {
  int i;
  for (i=0; i < MAX_PENDING_NOTIFIES;i++)
  {  if (!notify_requests[i].in_use) { notify_requests[i].in_use=TRUE;notify_requests_in_use+=1;return i;}}
  return -1;
}
// Return the index of a request structure with tid:fileid
static int find_notify_request(uint16_t tid, uint8_t *file_id) {
int checked = 0;
int i;
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < notify_requests_in_use;i++)
  {
    if (notify_requests[i].in_use)
    {
      checked += 1;
      if (notify_requests[i].args.tid == tid && tc_memcmp(notify_requests[i].command.FileId,file_id, 16)==0)
      {
        return i;
      }
    }
  }
  return -1;
}

void rtplatform_notify_request(rtplatform_notify_request_args *prequest)
{
    ;
}

static void call_rtplatform_notify_cancel(int notify_index)
{
  notify_requests[notify_index].args.completion_filter = 0;
  rtplatform_notify_request(&notify_requests[notify_index].args);
}
static void call_rtplatform_notify_queue(int notify_index)
{
  void rtplatform_notify_request(rtplatform_notify_request_args *prequest);
}

BBOOL cancel_notify_request(smb2_stream  *pStream)
{
  int closed = 0;
  int checked=0;
  int i;
  PNET_SESSIONCTX pCtx = SMBU_SmbSessionToNetSession(pStream->pSmbCtx);
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < notify_requests_in_use;i++) {
    if (notify_requests[i].in_use)  {
      checked += 1;
      if (notify_requests[i].args.tid == pCtx->netsessiont_smbCtx.tid && notify_requests[i].MessageId == pStream->InHdr.MessageId)  {
        call_rtplatform_notify_cancel(i);
        notify_requests[i].in_use=FALSE;
        notify_requests_in_use -= 1;
        closed += 1;
        break;
      }
    }
  }
  if (closed)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: cancel_notify_request: nfree:%d \n", MAX_PENDING_NOTIFIES-notify_requests_in_use);
  }
}

// Called when a session is closing, release all notify requests
void close_session_notify_requests(PNET_SESSIONCTX pCtx)
{
  int i;
  int session_index      = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
  int checked = 0;
  int closed = 0;
  int _notify_requests_in_use= notify_requests_in_use;
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < _notify_requests_in_use;i++) {
    if (notify_requests[i].in_use)  {
      checked += 1;
      if (notify_requests[i].args.tid == pCtx->netsessiont_smbCtx.tid)  {
        call_rtplatform_notify_cancel(i);
        notify_requests[i].in_use=FALSE;
        notify_requests_in_use -= 1;
        closed += 1;
      }
    }
  }
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_session_notify_requests: nfree:%d \n", MAX_PENDING_NOTIFIES-notify_requests_in_use);
}

// Called when file is closing, or canceled
void close_fileid_notify_requests(smb2_stream  *pStream, uint8_t *fileid)
{
  int closed = 0;
  PNET_SESSIONCTX pCtx = SMBU_SmbSessionToNetSession(pStream->pSmbCtx);
  int notify_index = find_notify_request(pStream->pSmbCtx->tid, fileid);
  if (notify_index >= 0)
  {
    call_rtplatform_notify_cancel(notify_index);
    notify_requests[notify_index].in_use = FALSE;
    notify_requests_in_use -= 1;
    closed += 1;
  }
  if (closed)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_fileid_notify_requests: nfree:%d \n", MAX_PENDING_NOTIFIES-notify_requests_in_use);
  }
}

BBOOL Proc_smb2_ChangeNotify(smb2_stream  *pStream)
{
 rtplatform_notify_request_args args;
 RTSMB2_CHANGE_NOTIFY_C command;
 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 if (!pStream->Success)
 {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_ChangeNotify:  RtsmbStreamDecodeCommand failed...\n");
    return FALSE;
 }
 PNET_SESSIONCTX pCtx = SMBU_SmbSessionToNetSession(pStream->pSmbCtx);

 int notify_index = allocate_notify_request();
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_ChangeNotify: allocated notify index: %d nfree:%d \n",notify_index, MAX_PENDING_NOTIFIES-notify_requests_in_use);

 args.session_index      = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
 args.signal_port_number = YIELD_BASE_PORTNUMBER+args.session_index;
 args.notify_index       = notify_index;
 args.smb_protocol       = 2;
 args.tid                = pStream->pSmbCtx->tid;                          //
 tc_memcpy(args.file_id, &command.FileId, 16);
 args.max_notify_message_size = command.OutputBufferLength;           // Maximum payload size to embed in notify messages
 args.completion_filter = command.CompletionFilter;                                               // 0 means clear or others below.
 args.Flags             = command.Flags;
 notify_requests[notify_index].MessageId = pStream->InHdr.MessageId; // Save the messageID in case we're asked need to cancel
 tc_memcpy(&notify_requests[notify_index].command, &command, sizeof(command));
 tc_memcpy(&notify_requests[notify_index].args, &args, sizeof(args));
 rtplatform_notify_request(&args);
 // Now pass args to the OS
 // rtplatform_notify_request(&args);
 return FALSE;
}

#endif
#endif
