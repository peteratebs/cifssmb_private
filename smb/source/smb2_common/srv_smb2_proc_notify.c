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

// #define USE_DEEP_DIAGS

#define USE_NON_ASYNC_REPLY 0 // Set to 1 to use experimental queue events between notifies. 1

// API for rtsmb send a notify queue request or cancelation to the OS.
static int rtplatform_notify_request(smb2_stream  *pStream, rtplatform_notify_request_args *prequest);

#warning duplicate define
#define MAX_PENDING_NOTIFIES 256
typedef struct notify_request_s {

 BBOOL in_use;
 uint64_t MessageId;                                 // Message ID from the header so we can find it to cancel it
 uint64_t AsyncId;                                   // We have to remember the async id of our reply for when we send an unsoliceted notices
 int     notify_cancelled;                           // Set to 1 if we were canceled.
 rtplatform_notify_control_object notify_control;    // For queueing and sending outgoing notify alerts
 int  rtplatform_notify_request;
 rtplatform_notify_request_args args;
 RTSMB2_CHANGE_NOTIFY_C command;
} notify_request_t;

#define MAX_PENDING_NOTIFIES 256
notify_request_t notify_requests[MAX_PENDING_NOTIFIES];
int notify_requests_in_use;


typedef struct s_RTSMB2_ASYNC_CHANGE_NOTIFY_R
{
  byte nbss_header_type;
  byte nbss_size[3];
  RTSMB2_ASYNC_HEADER    header;
  RTSMB2_CHANGE_NOTIFY_R response;
} PACK_ATTRIBUTE RTSMB2_ASYNC_CHANGE_NOTIFY_R;

// Append a notify alert to the rtplatform_notify_control_object that resides in the session content block
// The session cycling routine will picks these up and sends them out.
#warning - This needs semaphore protection
static int notify_message_append(rtplatform_notify_control_object *phandle, uint16_t notify_index,  uint32_t change_alert_type,  size_t utf_string_size,  uint16_t *utf_16_string)
{
uint32_t next_location = phandle->formatted_content_size;
uint32_t new_next_location;
uint32_t zero=0;
int remainder =  utf_string_size%4;

  if (!phandle->message_buffer)
  {
    int maximimumsize = notify_requests[notify_index].args.max_notify_message_size;
    tc_memset(phandle,0,sizeof(*phandle));
   // Allocate message buffer for udp send
    phandle->message_buffer = rtp_malloc(sizeof(RTSMB2_ASYNC_CHANGE_NOTIFY_R) + maximimumsize);
//     phandle->message_buffer = rtp_malloc(sizeof(rtsmbNotifyMessage) + maximimumsize);
   // Alias it to pmessage and copy in facts that we'll route back to the server from the passed in arguments.
//    phandle->pmessage = (rtsmbNotifyMessage *)phandle->message_buffer;
//    phandle->pmessage->session_index = notify_requests[notify_index].args.session_index;
//    phandle->pmessage->notify_index  = notify_requests[notify_index].args.notify_index;
//    tc_memcpy(&phandle->pmessage->file_id, notify_requests[notify_index].args.file_id, sizeof(phandle->pmessage->file_id));
//    phandle->pmessage->payloadsize = 0;
    // Subtract one from the size of the structure so we put the out pointer on the buffer field
    phandle->format_buffer = phandle->message_buffer+sizeof(RTSMB2_ASYNC_CHANGE_NOTIFY_R)-1;
    phandle->format_buffer_size = maximimumsize;
#ifdef USE_DEEP_DIAGS
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: notify_message_append: alloc base: %X format:%X\n", phandle->message_buffer,  phandle->format_buffer);
#endif
  }
  if (!phandle->message_buffer)
    return -1;

  new_next_location = phandle->formatted_content_size;
  new_next_location += (12+utf_string_size);
  if (remainder)
    new_next_location += (4-remainder);
  if (new_next_location >=  phandle->format_buffer_size)
  { // If there is already a pachet
    if (phandle->formatted_content_size)
    {
      tc_memcpy(&phandle->format_buffer[phandle->next_location_offset],&zero, 4);
    }
    else
      phandle->format_buffer_full = 1;
#ifdef USE_DEEP_DIAGS
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: notify_message_append truncate_or_full: size: %d full:%d\n", phandle->formatted_content_size,  phandle->format_buffer_full);
#endif
    return 0;
  }
  // Link us to the previous name in the list
  if (phandle->formatted_content_size)
  {
    uint32_t offset_from_last =  phandle->formatted_content_size - phandle->next_location_offset;
    tc_memcpy(&phandle->format_buffer[phandle->next_location_offset],&offset_from_last, 4);
  }
  uint32_t utf_string_size32 = (uint32_t)utf_string_size;
  // Remembmber our offset in the list for linked the next item
  tc_memcpy(&phandle->format_buffer[phandle->formatted_content_size],&zero, 4);
  tc_memcpy(&phandle->format_buffer[phandle->formatted_content_size+4],&change_alert_type, 4);
  tc_memcpy(&phandle->format_buffer[phandle->formatted_content_size+8],&utf_string_size32, 4);
  tc_memcpy(&phandle->format_buffer[phandle->formatted_content_size+12],utf_16_string, utf_string_size);
#ifdef USE_DEEP_DIAGS
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: notify_message_append: base:%X toaddress:%X count:%d \n",phandle->message_buffer,&phandle->format_buffer[phandle->formatted_content_size],utf_string_size32+12);
#endif
  phandle->next_location_offset = phandle->formatted_content_size;
  phandle->formatted_content_size = new_next_location;
#ifdef USE_DEEP_DIAGS
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: notify_message_append: phandle->formatted_content_size:%d \n",phandle->formatted_content_size);
#endif
  return 0;
}


// Return the index of a usable request struture else -i
static int allocate_notify_request(void) {
  int i;
  for (i=0; i < MAX_PENDING_NOTIFIES;i++)
  {  if (!notify_requests[i].in_use) { notify_requests[i].in_use=TRUE;notify_requests_in_use+=1;return i;}}
  return -1;
}
// Return the index of a usable request struture else -i
static void free_notify_request(int i) {
  if (notify_requests[i].in_use)
  {
#ifdef USE_DEEP_DIAGS
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: freeing #:%d Asyncmssgmid: %lu syncmid: %lu \n",  i,  (dword)notify_requests[i].AsyncId,(dword)notify_requests[i].MessageId);
#endif
    notify_requests[i].in_use=FALSE;
    if (notify_requests[i].notify_control.message_buffer)
      RTP_FREE(notify_requests[i].notify_control.message_buffer);
    notify_requests[i].notify_control.message_buffer = 0;
    if(notify_requests_in_use)notify_requests_in_use-=1;
  }
}

// Return the index of a request structure with tid:fileid
static void display_notify_requests(char *prompt) {
int checked = 0;
int i;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: inuse: %d   XXXX %s XXXX \n",  notify_requests_in_use, prompt);
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < notify_requests_in_use;i++)
  {
    if (notify_requests[i].in_use)
    {
      checked += 1;
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: index :%d  Async: %lu mssgmid: %lu wd:%d\n",  i,  (dword)notify_requests[i].AsyncId, (dword)notify_requests[i].MessageId, notify_requests[i].rtplatform_notify_request);
    }
  }
}

// Return the index of a request structure with tid:inode portion of fileid
static int find_notify_request_by_inode(uint16_t tid, uint8_t *file_id) {
int checked = 0;
int i;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Search  by inode inuse: %d \n",  notify_requests_in_use);
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < notify_requests_in_use;i++)
  {
    if (notify_requests[i].in_use)
    {
      checked += 1;
      if (notify_requests[i].args.tid == tid && tc_memcmp(notify_requests[i].command.FileId,file_id, 4)==0)
      {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Found by inode index :%d \n",  i);
        return i;
      }
    }
  }
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


int linux_inotify_add_watch(const char *pathname, uint32_t mask);

static int _rtplatform_notify_request(smb2_stream  *pStream, rtplatform_notify_request_args *prequest, uint32_t mask)
{
PFRTCHAR FileName = SMBU_UniqueIdToFileName(prequest->file_id);
int wd = -1;
  if (!(mask && FileName))
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: add_watch nothing to do: mask:%X FileName :%X\n", mask, FileName);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Null filename is share root, bug to fix\n");
  }
  if (mask && FileName)
  {
    rtsmb_char utemp[512];
    char temp[512];
    if (SMBFIO_ExpandName (pStream->pSmbCtx, pStream->pSmbCtx->tid, FileName, utemp, 512))
    {
      rtsmb_util_rtsmb_to_ascii (utemp, temp, CFG_RTSMB_USER_CODEPAGE);
      wd = linux_inotify_add_watch((const char *)temp, mask);
    }
  }
  return wd;
}

// Arm a notify request that was just received to be watched
static int rtplatform_notify_request(smb2_stream  *pStream, rtplatform_notify_request_args *prequest)
{
uint32_t mask = 1;
int wd = _rtplatform_notify_request(pStream, prequest, mask);
  return wd;
}


void linux_inotify_cancel_watch(int w);

static void call_rtplatform_notify_cancel(int notify_index)
{
uint32_t mask = 0;
   linux_inotify_cancel_watch(notify_requests[notify_index].rtplatform_notify_request);
  //  _rtplatform_notify_request(pStream, prequest, mask);
}

// Called when a cancel is received
BBOOL cancel_notify_request(smb2_stream  *pStream)
{
  BBOOL closed = FALSE;
  int checked=0;
  int i;

  if (!prtsmb_srv_ctx->enable_notify) return FALSE;  // If notify disabled just ignore it we shouldn't respond anyway

  display_notify_requests("cancel_notify_request top");

  PNET_SESSIONCTX pCtx = SMBU_SmbSessionToNetSession(pStream->pSmbCtx);
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < notify_requests_in_use;i++)
  {
    if (notify_requests[i].in_use)
    {
      ddword mid;
      checked += 1;
      int matched = 0;
#ifdef USE_DEEP_DIAGS
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: outside :%d checked:%d inuse:%d Async: %lu mssgmid: %lu wd:%d asyncheader:%lu\n",  i,checked , notify_requests_in_use , (dword)notify_requests[i].AsyncId, (dword)notify_requests[i].MessageId, notify_requests[i].rtplatform_notify_request,(dword)((RTSMB2_ASYNC_HEADER *) &pStream->InHdr)->AsyncId);
#endif
      if (pStream->InHdr.Flags & 2)
      {
        mid = ((RTSMB2_ASYNC_HEADER *) &pStream->InHdr)->AsyncId;
        matched = (notify_requests[i].AsyncId == mid);
#ifdef USE_DEEP_DIAGS
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: async cancel_notify_request for :%d mssgmid: %lu savedMesagemid: %lu wd:%d\n",  i,  mid,  (dword)notify_requests[i].MessageId, notify_requests[i].rtplatform_notify_request);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: async cancel_notify_request for :%d mssgmid: %lu savedAsyncmid: %lu \n",  i,  mid,  (dword)notify_requests[i].AsyncId);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: async cancel_notify_request for :%d mssgmid: %lu savedArgAsyncmid: %lu \n",  i,  mid,  (dword)notify_requests[i].args.AsyncId);
#endif
      }
      else
      {
        mid = pStream->InHdr.MessageId;
        matched =  notify_requests[i].args.tid == pCtx->netsessiont_smbCtx.tid && notify_requests[i].MessageId == mid;
#ifdef USE_DEEP_DIAGS
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: sync cancel_notify_request for :%d tids: [%d %d] mssgmid: %lu savedmid: %lu savemidargs: %lu\n",  i, notify_requests[i].args.tid, pCtx->netsessiont_smbCtx.tid ,mid,  (dword)notify_requests[i].MessageId,      notify_requests[i].args.MessageId);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: sync cancel_notify_request for :%d mssgmid: %lu Asyncmid: %lu \n",  i,  mid,  (dword)notify_requests[i].AsyncId);
#endif
      }
      if (matched) { // pStream->InHdr.MessageId)  {
        notify_requests[i].notify_cancelled = 1;
        pCtx->netsessiont_smbCtx.queued_notify_sends += 1;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: cancel_notify_request succeeded for :%d new:queued_notify_sends: %d\n", i, pCtx->netsessiont_smbCtx.queued_notify_sends);
        closed = TRUE;
        break;
      }
    }
  }
  if (closed)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: cancel_notify_request: notify_requests_in_use: %d \n", notify_requests_in_use);
  }
#ifdef USE_DEEP_DIAGS
  display_notify_requests("cancel_notify_request bottom");
#endif
  return closed;
}



// Called when file object is released
void close_pfid_notify_requests(PNET_SESSIONCTX pCtx, PFID pfid)
{
  if (!prtsmb_srv_ctx->enable_notify) return;  // If notify disabled return

  int closed = 0;
  int notify_index = find_notify_request(pCtx->netsessiont_smbCtx.tid, SMBU_Fidobject(pfid)->unique_fileid);
  if (notify_index >= 0)
  {
    call_rtplatform_notify_cancel(notify_index);
    {
    int i = notify_index;
#ifdef USE_DEEP_DIAGS
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_pfid_notify_requests freeing #:%d Asyncmssgmid: %lu syncmid: %lu \n",  i,  (dword)notify_requests[i].AsyncId,(dword)notify_requests[i].MessageId);
#endif
    }
    free_notify_request(notify_index);
    closed += 1;
  }
#ifdef USE_DEEP_DIAGS
  if (closed)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_fileid_notify_requests: nfree:%d \n", MAX_PENDING_NOTIFIES-notify_requests_in_use);
  }
#endif
}

// Called when a session is closing, release all notify requests
void close_session_notify_requests(PNET_SESSIONCTX pCtx)
{
  int i;

  if (!prtsmb_srv_ctx->enable_notify) return;  // If notify disabled return

  int session_index      = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
  int checked = 0;
  int closed = 0;
  int _notify_requests_in_use= notify_requests_in_use;
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < _notify_requests_in_use;i++) {
    if (notify_requests[i].in_use)  {
      checked += 1;
      if (notify_requests[i].args.tid == pCtx->netsessiont_smbCtx.tid)  {
        call_rtplatform_notify_cancel(i);
#ifdef USE_DEEP_DIAGS
    {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_session_notify_requests freeing #:%d Asyncmssgmid: %lu syncmid: %lu \n",  i,  (dword)notify_requests[i].AsyncId,(dword)notify_requests[i].MessageId);
    }
#endif

        free_notify_request(i);
        closed += 1;
      }
    }
  }
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_session_notify_requests: inuse:%d \n", notify_requests_in_use);
}

// Called when file is closing, or canceled
void close_fileid_notify_requests(smb2_stream  *pStream, uint8_t *fileid)
{
  if (!prtsmb_srv_ctx->enable_notify) return;  // If notify disabled return

  int closed = 0;
  PNET_SESSIONCTX pCtx = SMBU_SmbSessionToNetSession(pStream->pSmbCtx);
  int notify_index = find_notify_request(pStream->pSmbCtx->tid, fileid);
  if (notify_index >= 0)
  {
    call_rtplatform_notify_cancel(notify_index);
#ifdef USE_DEEP_DIAGS
    {
    int i = notify_index;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_fileid_notify_requests freeing #:%d Asyncmssgmid: %lu syncmid: %lu \n",  i,  (dword)notify_requests[i].AsyncId,(dword)notify_requests[i].MessageId);
    }
#endif
    free_notify_request(notify_index);
    closed += 1;
  }
#ifdef USE_DEEP_DIAGS
  if (closed)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: close_fileid_notify_requests: nfree:%d \n", MAX_PENDING_NOTIFIES-notify_requests_in_use);
  }
#endif
}

extern ddword CurrentAsyncId;



BBOOL Proc_smb2_ChangeNotify(smb2_stream  *pStream)
{
 rtplatform_notify_request_args args;
 RTSMB2_CHANGE_NOTIFY_C command;
 RTSMB2_CHANGE_NOTIFY_R response;
 int notify_index_found;
 int notify_index;
 uint16_t CurrentStatus = 0;        // 0 means, send a reply synchronously SMB_NT_STATUS_PENDING means send async
 PNET_SESSIONCTX pCtx = SMBU_SmbSessionToNetSession(pStream->pSmbCtx);


 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 if (!pStream->Success)
 {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_ChangeNotify:  RtsmbStreamDecodeCommand failed...\n");
    return FALSE;
 }
 // If notify disabled just ignore it we shouldn't respond anyway
 if (!prtsmb_srv_ctx->enable_notify)
   return FALSE;

 display_notify_requests("Proc_smb2_ChangeNotify top");
 // Compound requests send 0xffff ffff ffff ffff to mean the last file if returned by create
 // Map if neccessary
 byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
#if (USE_NON_ASYNC_REPLY==0)
 // Force allocate of a new request every time and send and async reply
 notify_index_found = notify_index = -1;
#else
 notify_index_found = notify_index = find_notify_request(pStream->pSmbCtx->tid, pFileId);
 if (notify_index_found < 0)
   notify_index_found = notify_index = find_notify_request_by_inode(pStream->pSmbCtx->tid, pFileId);
#endif
 if (notify_index_found >= 0)
 {
  if (notify_requests[notify_index].notify_control.notify_reply_data_present)
  {  // Need to send reply synchronousy
    notify_requests[notify_index].notify_control.notify_reply_data_present = 0;
    notify_requests[notify_index].notify_control.client_notify_request_is_pending = 0;
    CurrentStatus = 0;
  }
  else
  {  // Need to reply asynchronously
    notify_requests[notify_index].notify_control.notify_reply_data_present = 0;
    notify_requests[notify_index].notify_control.client_notify_request_is_pending = 1;
    CurrentStatus = SMB_NT_STATUS_PENDING;
  }
  }
  else
  {   // No event already queued
    CurrentStatus = SMB_NT_STATUS_PENDING;
    notify_index = allocate_notify_request();
    notify_requests[notify_index].args.session_index      = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
    notify_requests[notify_index].args.signal_port_number = YIELD_BASE_PORTNUMBER+args.session_index;
    notify_requests[notify_index].args.notify_index       = notify_index;
    notify_requests[notify_index].args.smb_protocol       = 2;
    notify_requests[notify_index].args.tid                = pStream->pSmbCtx->tid;                          //
    tc_memcpy(notify_requests[notify_index].args.file_id, pFileId, 16);
    notify_requests[notify_index].args.SessionId         = pStream->InHdr.SessionId; // Save the SessionId for send;;
  }
  // Fall through for existing and new watches
  notify_requests[notify_index].args.max_notify_message_size = command.OutputBufferLength;           // Maximum payload size to embed in notify messages
  notify_requests[notify_index].args.completion_filter = command.CompletionFilter;                                               // 0 means clear or others below.
  notify_requests[notify_index].args.Flags             = command.Flags;
  notify_requests[notify_index].args.MessageId         = pStream->InHdr.MessageId; // Save the messageID for send;
  notify_requests[notify_index].args.AsyncId           = CurrentAsyncId;           // Diagnostic , we are stomping it for some reason.
  notify_requests[notify_index].MessageId = pStream->InHdr.MessageId; // Save the messageID in case we're asked need to cancel
  tc_memcpy(&notify_requests[notify_index].command, &command, sizeof(command));

  if (notify_index_found < 0)
  { // Fire up a new watcher request if we need to
    int wd = rtplatform_notify_request(pStream, &notify_requests[notify_index].args);
    if (wd < 0)
    {
      { int i = notify_index; RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_ChangeNotify:  rtplatform_notify_request failed:  freeing #:%d Asyncmssgmid: %lu syncmid: %lu \n",  i,  (dword)notify_requests[i].AsyncId,(dword)notify_requests[i].MessageId); }
      display_notify_requests("Proc_smb2_ChangeNotify exit");
      free_notify_request(notify_index);
      return FALSE;
    }
    notify_requests[notify_index].rtplatform_notify_request = wd;
  }
#ifdef USE_DEEP_DIAGS
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_ChangeNotify:XXX alloc notify. index: %d messageID:%lu location :%X  \n", notify_index,(dword) notify_requests[notify_index].args.MessageId, &notify_requests[notify_index]);
#endif
#ifdef USE_DEEP_DIAGS
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG:XXX Proc_smb2_ChangeNotify: set(%d) async id to: %lu\n",notify_index,CurrentAsyncId);
#endif
 notify_requests[notify_index].AsyncId = 0; // Remember the async id for when we send an unsolicted notice
 pStream->OutHdr.Status_ChannelSequenceReserved =  CurrentStatus;  // Status pending or success
 if (CurrentStatus == SMB_NT_STATUS_PENDING)
 {
   notify_requests[notify_index].AsyncId = CurrentAsyncId; // Remember the async id for when we send an unsolicted notice
   // Set the status to pending
   response.StructureSize = 9;
   response.OutputBufferOffset = 0;
   response.OutputBufferLength = 0;
   response.Buffer             = 0x21;                            // Sapture value from samba <-> OSX
   // RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_ChangeNotify: Size before async: %d\n",response.StructureSize);
   // Modify header to async
   RTSMB2_ASYNC_HEADER *pAsyncOut =  (RTSMB2_ASYNC_HEADER *) &pStream->OutHdr;
   pAsyncOut->AsyncId = CurrentAsyncId;
   pAsyncOut->Flags = 3;                             // ASYNC|RESPONSE
   CurrentAsyncId += 1;
 }
 else
 {
   pStream->OutHdr.Status_ChannelSequenceReserved =  SMB2_STATUS_NOTIFY_ENUM_DIR;  // Status pending or success
   pStream->OutHdr.Flags = 1;
   response.StructureSize = 9;
   response.OutputBufferOffset = 0;
   response.OutputBufferLength = 0;
   response.Buffer             = 0x21;
 }

// RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_ChangeNotify: Size before RtsmbStreamEncodeResponse: %d\n",response.StructureSize);
 RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
 display_notify_requests("Proc_smb2_ChangeNotify bottom");

 return TRUE;
}

// Return the index of a request waiting for an alert on wd
int find_notify_request_from_alert(int wd) {
 if (!prtsmb_srv_ctx->enable_notify) return -1;  // If notify disabled return
 int checked = 0;
 int i;
  for (i=0; i < MAX_PENDING_NOTIFIES && checked < notify_requests_in_use;i++)
  {
    if (notify_requests[i].in_use)
    {
      checked += 1;
      if (notify_requests[i].rtplatform_notify_request == wd)
      {
        return i;
      }
    }
  }
  return -1;
}

void send_notify_request_from_alert(int wd,char *name, uint32_t mapped_alert)
{
 if (!prtsmb_srv_ctx->enable_notify) return;  // If notify disabled return
 int notify_index = find_notify_request_from_alert(wd);
 if (notify_index >= 0)
 {
   size_t utf_string_size=0;
   uint16_t utf_16_string[512];
   utf_string_size = tc_strlen(name) * 2;
   rtsmb_util_ascii_to_unicode (name, utf_16_string, CFG_RTSMB_USER_CODEPAGE);
#ifdef USE_DEEP_DIAGS
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_notify_request_from_alert: name:%s size:%d \n",name, utf_string_size);
#endif
   prtsmb_srv_ctx->sessions[notify_requests[notify_index].args.session_index].netsessiont_smbCtx.queued_notify_sends += 1;
#ifdef USE_DEEP_DIAGS
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_notify_request_from_alert:XXX add notify index: %d messageID:%lu location :%X  \n", notify_index,(dword) notify_requests[notify_index].args.MessageId, &notify_requests[notify_index]);
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_notify_request_from_alert:XXX session_queued: %d \n", prtsmb_srv_ctx->sessions[notify_requests[notify_index].args.session_index].netsessiont_smbCtx.queued_notify_sends);
#endif
   // Find the session and then call; notify_message_append()
   notify_message_append( &notify_requests[notify_index].notify_control,notify_index,mapped_alert, utf_string_size, utf_16_string);
 }
}

static int send_notify_message(PNET_SESSIONCTX pCtx, int notify_cancelled, rtplatform_notify_request_args *pArgs, rtplatform_notify_control_object *phandle);

int send_session_notify_messages(PNET_SESSIONCTX pCtx)
{
int r=0;

  if (!prtsmb_srv_ctx->enable_notify) return 0;  // If notify disabled return

  int session_index      = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
  if (pCtx->netsessiont_smbCtx.queued_notify_sends)
  {
#ifdef USE_DEEP_DIAGS
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:send_session_notify_messages sendount: inuse:%d %d\n", notify_requests_in_use, pCtx->netsessiont_smbCtx.queued_notify_sends);
#endif
   int checked = 0;
   int i;
   int _notify_requests_in_use = notify_requests_in_use;
    for (i=0; i < MAX_PENDING_NOTIFIES && checked < _notify_requests_in_use;i++)
    {
#ifdef USE_DEEP_DIAGS
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:send_session_notify_messages i: %d isinuse:%d \n", i, notify_requests[i].in_use);
#endif
      if (notify_requests[i].in_use)
      {
        checked += 1;
#ifdef USE_DEEP_DIAGS
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:2 send_session_notify_messages cancelled: %lu\n", notify_requests[i].notify_cancelled);
#endif
      if (notify_requests[i].args.session_index == session_index)
      {
        rtplatform_notify_control_object *phandle = &notify_requests[i].notify_control;
        if (notify_requests[i].notify_cancelled || (phandle->message_buffer && (phandle->formatted_content_size||phandle->format_buffer_full)))
        {
           r = send_notify_message(pCtx, notify_requests[i].notify_cancelled, &notify_requests[i].args ,phandle);
           notify_requests[i].notify_cancelled = 0;
//         call_rtplatform_notify_cancel(i);
#ifdef USE_DEEP_DIAGS
    {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_session_notify_messages freeing #:%d Asyncmssgmid: %lu syncmid: %lu \n",  i,  (dword)notify_requests[i].AsyncId,(dword)notify_requests[i].MessageId);
    }
#endif
#if (USE_NON_ASYNC_REPLY==0)
// If we are not queueing between notify alerts so release it
           call_rtplatform_notify_cancel(i);
           free_notify_request(i);
#endif
        }
      }
      }
    }
    pCtx->netsessiont_smbCtx.queued_notify_sends = 0;
  }
  // Not reporting send errors yet to shut session down, could be useful
  return 0;
}

// Append a notify alert to the rtplatform_notify_control_object that resides in the session content block
// The session cycling routine will picks these up and sends them out.
#warning - This needs semaphore protection
// rtplatform_notify_control_object *phandle, uint16_t notify_index,  uint32_t change_alert_type,  size_t utf_string_size,  uint16_t *utf_16_string)

static int send_notify_message(PNET_SESSIONCTX pCtx, int notify_cancelled, rtplatform_notify_request_args *pArgs, rtplatform_notify_control_object *phandle)
{
  byte temp_message_buffer[512];
  RTSMB2_ASYNC_CHANGE_NOTIFY_R *p = (RTSMB2_ASYNC_CHANGE_NOTIFY_R *)phandle->message_buffer;
  int base_size = sizeof(RTSMB2_ASYNC_CHANGE_NOTIFY_R)-1;
  dword nbssize;
  if (p==0)
  {
    if (notify_cancelled)
     p = (RTSMB2_ASYNC_CHANGE_NOTIFY_R *)temp_message_buffer;
    else
    {
      srvsmboo_panic("send_notify_message no buffer");
      return -1;
    }
  }
  // Windows returns status 0x0000010c and zero data when size is larger than allocated, which is always 32 on Win10 ?
  if (phandle->format_buffer_full||notify_cancelled)
    nbssize = (dword) sizeof(RTSMB2_ASYNC_CHANGE_NOTIFY_R) - RTSMB_NBSS_HEADER_SIZE;
  else
    nbssize = (dword) base_size+phandle->formatted_content_size - RTSMB_NBSS_HEADER_SIZE;
  // Message size is the SMB content plust the HNBS header
  int messagesize = (int)(nbssize + RTSMB_NBSS_HEADER_SIZE);

#ifdef USE_DEEP_DIAGS
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_notify_message: phandle->formatted_content_size:%d messagesize:%d full: %d CANCELED:%d  \n",phandle->formatted_content_size,messagesize,phandle->format_buffer_full,notify_cancelled);
#endif
  tc_memset (p, 0,base_size);
  p->nbss_header_type = 0;
  p->nbss_size[0] =  (byte) (nbssize>>16 & 0xFF);
  p->nbss_size[1] =  (byte) (nbssize>>8 & 0xFF);
  p->nbss_size[2] =  (byte) (nbssize & 0xFF);
  p->header.ProtocolId[0] = 0xFE;  p->header.ProtocolId[1] = 'S';   p->header.ProtocolId[2] = 'M';   p->header.ProtocolId[3] = 'B';
  p->header.StructureSize = 64;
  p->header.CreditCharge  = 0; /* SAMBA uses 0 (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
//  p->header.CreditCharge  = 0; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
  if (notify_cancelled)
    p->header.Status_ChannelSequenceReserved = SMB2_STATUS_CANCELLED;
  else if (phandle->format_buffer_full)
    p->header.Status_ChannelSequenceReserved = SMB2_STATUS_NOTIFY_ENUM_DIR; /*  ?? (4 bytes): */
  else
    p->header.Status_ChannelSequenceReserved = 0; /*  (4 bytes): */

  p->header.Command = SMB2_CHANGE_NOTIFY;
  p->header.CreditRequest_CreditResponse = 1;    // Samba uses 1
// HEREHERE - Have to probe connection
  p->header.Flags = 0x3;  // Windows uses 0x33
  p->header.NextCommand = 0;
  p->header.MessageId   = pArgs->MessageId;
//  phandle->MessageId; //  notify_requests[notify_index].MessageId
  p->header.AsyncId     = CurrentAsyncId;
  CurrentAsyncId += 1;

  p->header.SessionId   = pArgs->SessionId; // From  pStream->psmb2Session->SessionId;
//  header.Signature[16] = {0};

  p->response.StructureSize = 9;
  p->response.OutputBufferOffset = base_size- RTSMB_NBSS_HEADER_SIZE; // Should be 72

  if (phandle->format_buffer_full||notify_cancelled)
  {
    p->response.OutputBufferLength=0;
    p->response.OutputBufferOffset = 0;
    p->response.Buffer = 0x21;
  }
  else
    p->response.OutputBufferLength=phandle->formatted_content_size;

  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_notify_message: address:%X size:%d \n", phandle->message_buffer,messagesize);
  if (rtsmb_net_write (pCtx->netsessiont_smbCtx.sock,(PFVOID) p,messagesize) < 0)
  {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: send_notify_message to socket: %d rtsmb_net_write failed\n",pCtx->netsessiont_smbCtx.sock);
     return -1;
  }
  else
  {
     return 0;
  }
}



#endif
#endif
