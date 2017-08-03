//
// CLI_SMB2_PROC.C -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2013
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//
#include <map>
#include <algorithm>
#include <iostream>
using std::cout;
using std::endl;
#include "smb2utils.hpp"

#include "smbdefs.h"
#include <netstreambuffer.hpp>

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)


extern "C" {

// #include "com_smb2.h"
#include "rtpmem.h"

#include "clissn.h"
#include "smbutil.h"
#include "clians.h"
#include "clicmds.h"
#include "smbnbns.h"
#include "smbnbds.h"
#include "smbnet.h"
#include "smbpack.h"
#include "smbnb.h"
#include "clicfg.h"
#include "smbbrcfg.h"
#include "smbglue.h"
#include "smbdebug.h"
#include "smbconf.h"

#include "rtptime.h"
#include "rtpnet.h"
#include "rtpthrd.h"
#include "rtpwcs.h"
#include "smbobjs.h"
#include <assert.h>


extern void rtsmb_cli_session_job_cleanup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, int r);
extern void rtsmb_cli_session_user_close (PRTSMB_CLI_SESSION_USER pUser);
extern PRTSMB_CLI_SESSION_SEARCH rtsmb_cli_session_get_search (PRTSMB_CLI_SESSION pSession, int sid);
extern PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_free_buffer (PRTSMB_CLI_WIRE_SESSION pSession);
extern void  smb2_iostream_start_encryption(smb2_iostream *pStream);
int rtsmb_cli_wire_smb2_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);
void rtsmb_cli_session_search_close (PRTSMB_CLI_SESSION_SEARCH pSearch);

int rtsmb_cli_wire_smb2_iostream_flush(PRTSMB_CLI_WIRE_SESSION pSession, smb2_iostream  *pStream);
smb2_iostream  *rtsmb_cli_wire_smb2_iostream_construct (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
smb2_iostream  *rtsmb_cli_wire_smb2_iostream_get(PRTSMB_CLI_WIRE_SESSION pSession, word mid);
smb2_iostream  *rtsmb_cli_wire_smb2_iostream_attach (PRTSMB_CLI_WIRE_SESSION pSession, word mid, int header_length, RTSMB2_HEADER *pheader_smb2);
int RtsmbStreamEncodeCommand(smb2_iostream *pStream, PFVOID pItem);
int RtsmbStreamDecodeResponse(smb2_iostream *pStream, PFVOID pItem);

int rtsmb_nbss_fill_header_cpp (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct);
void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession);

} // extern C

#include <smb2wireobjects.hpp>

typedef int (* pVarEncodeFn_t) (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);



//static void rtsmb2_cli_session_free_dir_query_buffer (smb2_iostream  *pStream);

/* Called when a new_session is created sepcifying an SMBV2 dialect.
   Currently holds SessionId, building it up. */
void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession)
{
    pSession->server_info.smb2_session_id = 0;  // New session sends zero in the header
}

void rtsmb_cli_smb2_session_release (PRTSMB_CLI_SESSION pSession)
{
}

smb2_iostream  *rtsmb_cli_wire_smb2_iostream_construct (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    BBOOL EncryptMessage = FALSE;
    int v1_mid;

    /* Attach a buffer to the wire session */
    v1_mid = rtsmb_cli_wire_smb2_add_start (&pSession->wire, pJob->mid);
    if (v1_mid<0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_iostream_construct: rtsmb_cli_wire_smb2_add_start Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        return 0;
    }

    pJob->mid = (word)v1_mid;
    pBuffer = rtsmb_cli_wire_get_buffer (&pSession->wire, (word) v1_mid);
    if (!pBuffer)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_iostream_construct: rtsmb_cli_wire_get_buffer Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        return 0;
    }

    /* Initialize stream structure from V1 buffer structure */
    tc_memset(&pBuffer->smb2stream, 0, sizeof(pBuffer->smb2stream));

    /* Reads and writes don't interleave so the streams are initialized the same */

    /* Reads will be performed starting form the session buffer origin using size values and offset from the session buffer */
    pBuffer->smb2stream.Success=TRUE;
    pBuffer->smb2stream.read_origin             = pBuffer->buffer;
    pBuffer->smb2stream.pInBuf                  = pBuffer->buffer_end;
    pBuffer->smb2stream.read_buffer_size        = pBuffer->allocated_buffer_size;                               /* read buffer_size is the buffer size minus NBSS header */
    pBuffer->smb2stream.read_buffer_remaining   = pBuffer->smb2stream.read_buffer_size-(rtsmb_size)PDIFF(pBuffer->smb2stream.pInBuf,pBuffer->smb2stream.read_origin); // RTSMB_NBSS_HEADER_SIZE;

    /* Writes will be performed starting form the session buffer origin using size values and offset from the session buffer */
    pBuffer->smb2stream.OutHdr.StructureSize    = 64;
    pBuffer->smb2stream.write_origin            = pBuffer->smb2stream.read_origin;                  /* write_buffer_size is the buffer size minus NBSS header */
    pBuffer->smb2stream.write_buffer_size       = pBuffer->smb2stream.read_buffer_size;
    pBuffer->smb2stream.pOutBuf                 = pBuffer->smb2stream.pInBuf;
    pBuffer->smb2stream.write_buffer_remaining  = pBuffer->smb2stream.read_buffer_remaining;
    pBuffer->smb2stream.OutBodySize = 0;

    pBuffer->smb2stream.pBuffer = pBuffer;
    pBuffer->smb2stream.pSession = pSession;
    pBuffer->smb2stream.pJob     = pJob;
    if (EncryptMessage)
        smb2_iostream_start_encryption(&pBuffer->smb2stream);
    return &pBuffer->smb2stream;
}

smb2_iostream  *rtsmb_cli_wire_smb2_iostream_get(PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);
    if (pBuffer)
    {
        return &pBuffer->smb2stream;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_iostream_get: rtsmb_cli_wire_get_buffer Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    return 0;
}

smb2_iostream  *rtsmb_cli_wire_smb2_iostream_attach (PRTSMB_CLI_WIRE_SESSION pSession, word mid, int header_length, RTSMB2_HEADER *pheader_smb2)
{
    smb2_iostream  *pStream = rtsmb_cli_wire_smb2_iostream_get(pSession, mid);

    if (pStream )
    {
        pStream->InHdr     = *pheader_smb2;
        pStream->pInBuf    = PADD(pStream->pInBuf,header_length);
        pStream->read_buffer_remaining -= (rtsmb_size)header_length;
    }
   return pStream;
}

// This is not used, see rtsmb_cli_wire_smb2_iostream_flush_sendbuffer()
int rtsmb_cli_wire_smb2_iostream_flush_raw(PRTSMB_CLI_WIRE_SESSION pSession, smb2_iostream  *pStream)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    pBuffer = pStream->pBuffer;

    pBuffer->buffer_size = pStream->write_buffer_size-pStream->write_buffer_remaining;

    TURN_ON (pBuffer->flags, INFO_CAN_TIMEOUT);

    if (pSession->state == CONNECTED)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Set state Waiting on us\n");
        pBuffer->state = WAITING_ON_US;
    }
    else
    {
        pBuffer->end_time_base = rtp_get_system_msec ();
        if (rtsmb_net_write (pSession->socket, pBuffer->buffer, (int)pBuffer->buffer_size)<0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Error writing %d bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->buffer_size);
            return -2;
        }

        pBuffer->state = WAITING_ON_SERVER;
    }
    return 0;
}

int rtsmb_cli_wire_smb2_iostream_flush(PRTSMB_CLI_WIRE_SESSION pSession, smb2_iostream  *pStream)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    RTSMB_NBSS_HEADER header;
    pBuffer = pStream->pBuffer;

    pBuffer->buffer_size = pStream->write_buffer_size-pStream->write_buffer_remaining;

    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = (word) (pBuffer->buffer_size - RTSMB_NBSS_HEADER_SIZE);

  #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
    if (pBuffer->attached_data)
    {
        header.size += pBuffer->attached_size;
    }
  #endif
    rtsmb_nbss_fill_header_cpp (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE, &header);

    TURN_ON (pBuffer->flags, INFO_CAN_TIMEOUT);

    if (pSession->state == CONNECTED)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Set state Waiting on us\n");
        pBuffer->state = WAITING_ON_US;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_US);
#endif
    }
    else
    {
        pBuffer->end_time_base = rtp_get_system_msec ();
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Writing %d bytes\n",(int)pBuffer->buffer_size);
        if (rtsmb_net_write (pSession->socket, pBuffer->buffer, (int)pBuffer->buffer_size)<0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Error writing %d bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->buffer_size);
            return -2;
        }

      #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
        if (pBuffer->attached_data)
        {
            if (rtsmb_net_write (pSession->socket, pBuffer->attached_data, (int)pBuffer->attached_size)<0)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Error writing %d attached bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->attached_size);
                return -2;
            }
        }
      #endif
        pBuffer->state = WAITING_ON_SERVER;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_iostream_flush: Set state Waiting on server\n");
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_SERVER);
#endif
    }
    return 0;
}



extern void rtsmb2_cli_session_init_header(smb2_iostream  *pStream, word command, ddword mid64, ddword SessionId); // This is now implemented in the cpp code base.




int rtsmb2_cli_session_send_find_first (smb2_iostream  *pStream)
{
    RTSMB2_QUERY_DIRECTORY_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));

cout << "Top Send Find first !!!!!" << endl;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: Session == %X \n",(int)pStream->pSession);

    rtsmb2_cli_session_init_header (pStream, SMB2_QUERY_DIRECTORY, (ddword) pStream->pBuffer->mid,pStream->pSession->server_info.smb2_session_id);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob == %X \n",(int)pStream->pJob);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob->data.findfirst.search_struct == %X \n",(int)pStream->pJob->data.findfirst.search_struct);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob->data.findfirst.search_struct->share_struct == %X \n",(int)pStream->pJob->data.findfirst.search_struct->share_struct);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: pStream->pJob->data.findfirst.search_struct->share_struct->tid == %X \n",(int)pStream->pJob->data.findfirst.search_struct->share_struct->tid);

    pStream->OutHdr.TreeId = (ddword) pStream->pJob->data.findfirst.search_struct->share_struct->tid;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: TreeId == %X \n",(int)pStream->OutHdr.TreeId);

    command_pkt.StructureSize   = 33;

	command_pkt.FileInformationClass    = SMB2_QUERY_FileIdBothDirectoryInformation; // SMB2_QUERY_FileNamesInformation;
	command_pkt.FileIndex               = 0;

//  MISSING , defaulting to 0 foer now and working.
//  command_pkt.FileId[16];

    command_pkt.Flags                   = 0; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;
    // restart scans unless it is a continue
    if (pStream->pJob->data.findsmb2.search_struct->has_continue==FALSE)
      command_pkt.Flags                   |= SMB2_QUERY_RESTART_SCANS; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

//    command_pkt.Flags                   |= SMB2_QUERY_RESTART_SCANS; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

    // continue will be set by the recieve if needed
    pStream->pJob->data.findsmb2.search_struct->has_continue = FALSE;

    /* The File Id was filled in by a call to SMB2_Create_Request and then pmaced in the SMB2FileId filed */
	tc_memcpy(command_pkt.FileId, pStream->pJob->data.findfirst.search_struct->SMB2FileId, 16);
    command_pkt.FileNameOffset          = (word) (pStream->OutHdr.StructureSize+command_pkt.StructureSize-1);

    if (pStream->pJob->data.findfirst.pattern)
    {
        pStream->WriteBufferParms[0].pBuffer = pStream->pJob->data.findfirst.pattern;
        pStream->WriteBufferParms[0].byte_count = rtsmb_len (pStream->pJob->data.findfirst.pattern)*sizeof(rtsmb_char);
        command_pkt.FileNameLength   = (word)pStream->WriteBufferParms[0].byte_count;
    }

    /* Tell the server that the maximum we can accept is what remains in our read buffer */
	command_pkt.OutputBufferLength      = (word)pStream->read_buffer_remaining;



    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: Call encode \n");

    /* Packs the SMB2 header and tree connect command/blob into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: back encode \n");
    return send_status;
}



// See SMB2_FILLFileIdBothDirectoryInformation and  rtsmb_cli_session_receive_find_first

// Returned structures Borrowed from server code for now, need to fix
PACK_PRAGMA_ONE
typedef struct s_FILE_DIRECTORY_INFORMATION_BASE
{
	dword NextEntryOffset;
	dword FileIndex;
	FILETIME_T CreationTime;
	FILETIME_T LastAccessTime;
	FILETIME_T LastWriteTime;
	FILETIME_T ChangeTime;
	ddword EndofFile;
	ddword AllocationSize;
	dword FileAttributes;
	dword FileNameLength;
} PACK_ATTRIBUTE FILE_DIRECTORY_INFORMATION_BASE;
PACK_PRAGMA_POP
PACK_PRAGMA_ONE
typedef struct s_FILE_ID_BOTH_DIR_INFORMATION
{
    FILE_DIRECTORY_INFORMATION_BASE directory_information_base;
	dword EaSize;
	byte  ShortNameLength;
	byte  Reserved1;
	byte  ShortName[24];
	word  Reserved2;
	ddword FileId;
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_ID_BOTH_DIR_INFORMATION;
PACK_PRAGMA_POP


static int BufferedDirscanToDstat(PRTSMB_CLI_SESSION_SEARCH pSearch)
{
int nConverted = 0;
     pSearch->index = 0;
     pSearch->num_stats = 0;
    // Convert entries to internal type if we got new
if (!pSearch->pBufferedIterator)
  rtp_printf("BufferedDirscanToDstat called with null iteratorat on pSearch == %X Iterator:%\n", pSearch,pSearch->pBufferedIterator);
  if (pSearch->pBufferedResponse&&pSearch->pBufferedIterator&&pSearch->pBufferedIterator < pSearch->pBufferedIteratorEnd)
  {
    int i;
    FILE_ID_BOTH_DIR_INFORMATION *BothDirInfoIterator;
    BothDirInfoIterator = (FILE_ID_BOTH_DIR_INFORMATION *) pSearch->pBufferedIterator;

    rtp_printf("BufferedDirscanToDstat called on pSearch == %X Iterator:%X\n", pSearch,pSearch->pBufferedIterator);

    // use prtsmb_cli_ctx->max_files_per_search-1 because algorith is different from v1, 2 levels of buffering
    //      for (i = 0; i < prtsmb_cli_ctx->max_files_per_search-1; i++)
    for (i = 0; i < 1; i++)
    {
      rtsmb_char dot[2] = {'.', '\0'};
      rtsmb_char dotdot[3] = {'.', '.', '\0'};
      if (0 && (rtsmb_cmp ((rtsmb_char *)BothDirInfoIterator->FileName, dot) == 0 || rtsmb_cmp ((rtsmb_char *)BothDirInfoIterator->FileName, dotdot) == 0))
      {   // Don't Ignore . and .. for now
          i--;
      }
      else
      {   // Consume these
         #define FILETIMETOTIME(T) *((TIME *)&T)
         tc_memcpy (pSearch->dstats[i].filename,BothDirInfoIterator->FileName,BothDirInfoIterator->directory_information_base.FileNameLength);
         // null terminate
         * ((char *) (&pSearch->dstats[i].filename)+BothDirInfoIterator->directory_information_base.FileNameLength) = 0;
         * ((char *) (&pSearch->dstats[i].filename)+BothDirInfoIterator->directory_information_base.FileNameLength+1) = 0;
         pSearch->dstats[i].unicode = 1;           //    char unicode;   /* will be zero if filename is ascii, non-zero if unicode */
         pSearch->dstats[i].fattributes =
           (unsigned short) BothDirInfoIterator->directory_information_base.FileAttributes;    //    unsigned short fattributes;
         pSearch->dstats[i].fatime64=FILETIMETOTIME(BothDirInfoIterator->directory_information_base.LastAccessTime);              //    TIME           fatime64; /* last access time */
         pSearch->dstats[i].fatime64= *((TIME *)(&BothDirInfoIterator->directory_information_base.LastAccessTime));              //    TIME           fatime64; /* last access time */
         pSearch->dstats[i].fwtime64=FILETIMETOTIME(BothDirInfoIterator->directory_information_base.LastWriteTime);              //    TIME           fwtime64; /* last write time */
         pSearch->dstats[i].fctime64=FILETIMETOTIME(BothDirInfoIterator->directory_information_base.CreationTime);              //    TIME           fctime64; /* last create time */
         pSearch->dstats[i].fhtime64=FILETIMETOTIME(BothDirInfoIterator->directory_information_base.ChangeTime);              //    TIME           fhtime64; /* last change time */
         pSearch->dstats[i].fsize =
           (dword) BothDirInfoIterator->directory_information_base.EndofFile;                 //    unsigned long fsize;
         pSearch->dstats[i].fsizehi;               //    unsigned long fsizehi;
           (dword) (BothDirInfoIterator->directory_information_base.EndofFile>>32);                 //    unsigned long fsize;
         pSearch->dstats[i].sid =  pSearch->sid;                   //    int sid;
      }
      nConverted += 1;
      dword nextOffset  = BothDirInfoIterator->directory_information_base.NextEntryOffset;
      if (nextOffset)
        BothDirInfoIterator = (FILE_ID_BOTH_DIR_INFORMATION *)PADD(BothDirInfoIterator,nextOffset);
      else
         BothDirInfoIterator = (FILE_ID_BOTH_DIR_INFORMATION *) pSearch->pBufferedIteratorEnd;
      pSearch->pBufferedIterator = BothDirInfoIterator;
      if (pSearch->pBufferedIterator >= pSearch->pBufferedIteratorEnd)
      {
         break; // we are done
      }
    }
  }
  pSearch->num_stats = nConverted;
  return nConverted;
}


// SMB2 only return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY if we still have content buffered
// Return RTSMB_CLI_SSN_RV_OK to force a gnext call
// SMB1 always returns RTSMB_CLI_SSN_RV_OK to force a gnext call
extern "C" int rtsmb2_cli_session_find_buffered_rt (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat)
{
 PRTSMB_CLI_SESSION pSession;
 PRTSMB_CLI_SESSION_JOB pJob;
 PRTSMB_CLI_SESSION_SEARCH pSearch;

 pSession = rtsmb_cli_session_get_session (sid);
 ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
 ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);

  pSearch = rtsmb_cli_session_get_search (pSession, pdstat->sid);
  ASSURE (pSearch, RTSMB_CLI_SSN_RV_BAD_SEARCH);

  pJob = &pSession->jobs[pSearch->job_number];

   // prefetching more than one into pSearch->dstats[pSearch->index] is not usednow so this should always run
   // and pull one from the smb2 buffer layer if there are any lft.
  if (pSearch->index >= pSearch->num_stats)
  {
rtp_printf("rtsmb2_cli_session_find_buffered_rt calling BufferedDirscanToDstat on pSearch == %X\n", pSearch);
      BufferedDirscanToDstat(pSearch);
  }
  // Check if we have anything after calling BufferedDirscanToDstat(pSearch);
  if (pSearch->index < pSearch->num_stats)
  {
     *pdstat = pSearch->dstats[pSearch->index];
    {
       char temp[200];
       rtsmb_util_rtsmb_to_ascii ((PFRTCHAR) pdstat->filename, temp, 0);
       rtp_printf("rtsmb_cli_session_find_buffered_rt: TOP:index %d name: %s\n", pSearch->index, temp);
    }
    pSearch->index += 1;
    return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY; // RTSMB_CLI_SSN_RV_OK;
  }
  // See if we need to start another scan to get more data
  if (pJob->data.findsmb2.search_struct->has_continue)
  {
      pJob->data.findsmb2.search_struct->has_continue = FALSE;
      return RTSMB_CLI_SSN_SMB2_QUERY_IN_PROGRESS; // Tell the top layer to start another scan without setting the restart bit
  }
  else
  {
     return RTSMB_CLI_SSN_RV_OK;
  }
}

static void rtsmb2_cli_session_free_dir_query_buffer (smb2_iostream  *pStream);


int rtsmb2_cli_session_receive_find_first (smb2_iostream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
int rv;
RTSMB2_QUERY_DIRECTORY_R response_pkt;
FILE_ID_BOTH_DIR_INFORMATION *BothDirInfoIterator;
PRTSMB_CLI_SESSION_JOB pJob = pStream->pJob;
int i;

  if (pStream->InHdr.Status_ChannelSequenceReserved == SMB2_STATUS_INFO_LENGTH_MISMATCH)
  { // Means more to come if we send another find to this handle
    pStream->pJob->data.findsmb2.search_struct->has_continue = TRUE;
    // Clear the error so we don't abort the job
    pStream->InHdr.Status_ChannelSequenceReserved = 0;
    // This came in a compund frame after a busrt, we have data buffered
rtp_printf("rtsmb2_cli_session_receive_find_first RTSMB_CLI_SSN_RV_SEARCH_DATA_READY\n");
    return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY;
//    return RTSMB_CLI_SSN_SMB2_QUERY_IN_PROGRESS;
  }


  // let the protocol handler allocate space needed for the buffer and tell us how much is there
  pStream->ReadBufferParms[0].pBuffer  = 0;
  pStream->ReadBufferParms[0].byte_count = 0;
  pJob->data.findsmb2.search_struct->index = 0;
  pJob->data.findsmb2.search_struct->num_stats = 0;

  // Make sure any buffered search replied are released.
  rtsmb2_cli_session_free_dir_query_buffer (pStream);

  rtp_printf("rtsmb2_cli_session_receive_find_first pulling data \n");
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_find_first: called with error == %X\n", (int)pStream->InHdr.Status_ChannelSequenceReserved);

  // Allow the decoder to allocate and copy to our buffer
  pStream->ReadBufferParms[0].pBuffer = 0;
  pStream->ReadBufferParms[0].byte_count=0;
  if ((rv=RtsmbStreamDecodeResponse(pStream, &response_pkt)) < 0)
  {   // The decode failed, but free memory if it allocated it before failing.
      if (pStream->ReadBufferParms[0].pBuffer)
        rtp_free(pStream->ReadBufferParms[0].pBuffer);
      pStream->ReadBufferParms[0].pBuffer = 0;
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_find_first: RtsmbStreamDecodeResponse failed with error == %X\n", rv);
      return RTSMB_CLI_SSN_RV_MALFORMED;
  }
  pJob->data.findsmb2.search_struct->pBufferedIterator =
  pJob->data.findsmb2.search_struct->pBufferedResponse = pStream->ReadBufferParms[0].pBuffer;
  pJob->data.findsmb2.search_struct->pBufferedIteratorEnd = PADD(pJob->data.findsmb2.search_struct->pBufferedIterator,pStream->ReadBufferParms[0].byte_count);
  // Populate dstas in search structure
  pJob->data.findsmb2.search_struct->num_stats = 0;
rtp_printf("rtsmb2_cli_session_receive_find_first calling BufferedDirscanToDstat on pSearch == %X\n", pJob->data.findsmb2.search_struct);
  BufferedDirscanToDstat(pJob->data.findsmb2.search_struct);
  // Check if we ran off the end or if we never got any
  if (!pJob->data.findsmb2.search_struct->num_stats)
  {
    pJob->data.findsmb2.search_struct->end_of_search = 1;
    return RTSMB_CLI_SSN_RV_END_OF_SEARCH;
  }
  else
  {   // Return one
      *pJob->data.findsmb2.answering_dstat = pJob->data.findsmb2.search_struct->dstats[pJob->data.findsmb2.search_struct->index];
{
      char temp[200];
      rtsmb_util_rtsmb_to_ascii ((PFRTCHAR) pJob->data.findsmb2.answering_dstat->filename, temp, 0);
      rtp_printf("rtsmb2_cli_session_receive_find_first: index %d name: %s\n", pJob->data.findsmb2.search_struct->index, temp);
}
      pJob->data.findsmb2.search_struct->index+=1;
      return RTSMB_CLI_SSN_RV_SEARCH_DATA_READY; // RTSMB_CLI_SSN_RV_OK;
  }
}

static void rtsmb2_cli_session_free_dir_query_buffer (smb2_iostream  *pStream)
{
  if (pStream->pJob->data.findsmb2.search_struct->pBufferedResponse)
  {
    rtp_free(pStream->pJob->data.findsmb2.search_struct->pBufferedResponse);
    pStream->pJob->data.findsmb2.search_struct->pBufferedResponse = 0;
    pStream->pJob->data.findsmb2.search_struct->pBufferedIteratorEnd =
    pStream->pJob->data.findsmb2.search_struct->pBufferedResponse = 0;

  }
}

int rtsmb2_cli_session_send_find_close (smb2_iostream  *pStream)
{
//   pStream->pSession;       // For a client. points to the controlling SMBV1 session structure.
//   pStream->pJob;
cout << "Top Send Find close !!!!!" << endl;


   /*Make sure we free any buffering we left */
   rtsmb2_cli_session_free_dir_query_buffer (pStream);
    /*  Release the buffer we used for this job */

   /* we also want to close everything up here -- useless to wait for response */
   rtsmb_cli_session_search_close (pStream->pJob->data.findsmb2.search_struct);
   return RTSMB_CLI_SSN_RV_OK;
}

typedef struct c_jobobject_t
{
  int (*new_send_handler_smb2)(NetStreamBuffer &SendBuffer);
  int (*send_handler_smb2)    (smb2_iostream  *psmb2stream);
  int (*new_error_handler_smb2) (NetStreamBuffer &SendBuffer);
  int (*error_handler_smb2)   (smb2_iostream  *psmb2stream);
  int (*new_receive_handler_smb2) (NetStreamBuffer &SendBuffer);
  int (*receive_handler_smb2) (smb2_iostream  *psmb2stream);
} c_jobobject;

typedef std::map <jobTsmb2 , c_jobobject *> CmdToJobObject_t;
CmdToJobObject_t glCmdToJobObject;

struct c_jobobject_table_t
{
  jobTsmb2    command;
  c_jobobject cobject;
};


static int rtsmb2_cli_session_error_handler_base (smb2_iostream  *pStream)
{
  return RTSMB_CLI_SSN_RV_INVALID_RV;

}

int rtsmb2_cli_session_send_read (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_read (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_write (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_write (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_open (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_open (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_close (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_close (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_seek (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_seek (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_truncate (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_truncate (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_flush (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_flush (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_rename (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_rename (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_delete (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_delete (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_mkdir (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_mkdir (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_rmdir (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_rmdir (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}

int rtsmb2_cli_session_send_find_first_error_handler (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_find_close (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_stat (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_stat (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_chmode (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_chmode (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_full_server_enum (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_full_server_enum (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_get_free (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_get_free (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_share_find_first (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_share_find_first (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_server_enum (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_server_enum (smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}



#define default_error_handler(FUNCNAME) static int FUNCNAME (smb2_iostream  *pStream) {return rtsmb2_cli_session_error_handler_base(pStream);}
// static int rtsmb2_cli_session_send_negotiate_error_handler (smb2_iostream  *pStream) {  return rtsmb2_cli_session_error_handler_base(pStream);}
default_error_handler(rtsmb2_cli_session_send_logoff_error_handler)
default_error_handler(rtsmb2_cli_session_send_error_handler)
default_error_handler(rtsmb2_cli_session_send_find_close_error_handler)

#if (0)
default_error_handler(rtsmb2_cli_session_send_read_error_handler)
default_error_handler(rtsmb2_cli_session_send_write_error_handler)
default_error_handler(rtsmb2_cli_session_send_error_handler)
default_error_handler(rtsmb2_cli_session_send_close_error_handler)
default_error_handler(rtsmb2_cli_session_send_seek_error_handler)
default_error_handler(rtsmb2_cli_session_send_truncate_error_handler)
default_error_handler(rtsmb2_cli_session_send_flush_error_handler)
default_error_handler(rtsmb2_cli_session_send_rename_error_handler)
default_error_handler(rtsmb2_cli_session_send_delete_error_handler)
default_error_handler(rtsmb2_cli_session_send_mkdir_error_handler)
default_error_handler(rtsmb2_cli_session_send_rmdir_error_handler)
// default_error_handler(rtsmb2_cli_session_send_error_handler)
default_error_handler(rtsmb2_cli_session_send_stat_error_handler)
default_error_handler(rtsmb2_cli_session_send_chmode_error_handler)
default_error_handler(rtsmb2_cli_session_send_full_server_enum_error_handler)
default_error_handler(rtsmb2_cli_session_send_get_free_error_handler)
default_error_handler(rtsmb2_cli_session_send_share_find_first_error_handler)
default_error_handler(rtsmb2_cli_session_send_server_enum_error_handler)
#endif


// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.

static  struct c_jobobject_table_t CmdToJobObjectTable[] =
{
// See SmbCmdToCmdObjectTable for commands that are succesfully converted to CPP. These are routed through SmbCmdToCmdObjectTable instead of CmdToJobObjectTable.
//  {jobTsmb2_negotiate,{ rtsmb2_cli_session_send_negotiate, rtsmb2_cli_session_send_negotiate_error_handler,rtsmb2_cli_session_receive_negotiate}},
//  {jobTsmb2_tree_connect,     0, rtsmb2_cli_session_send_tree_connect    , 0,rtsmb2_cli_session_send_tree_connect_error_handler    ,0,rtsmb2_cli_session_receive_tree_connect},
//  {jobTsmb2_session_setup,    0, rtsmb2_cli_session_send_session_setup   , 0,rtsmb2_cli_session_send_session_setup_error_handler   ,0,rtsmb2_cli_session_receive_session_setup},
//  {jobTsmb2_logoff,           0, rtsmb2_cli_session_send_logoff          , 0,rtsmb2_cli_session_send_logoff_error_handler          ,0,rtsmb2_cli_session_receive_logoff,},
//  {jobTsmb2_disconnect,  0, rtsmb2_cli_session_send_tree_disconnect , 0,rtsmb2_cli_session_send_tree_disconnect_error_handler ,0,rtsmb2_cli_session_receive_tree_disconnect},

//  {jobTsmb2_read, rtsmb2_cli_session_send_read, rtsmb2_cli_session_send_read_error_handler,rtsmb2_cli_session_receive_read,},
//  {jobTsmb2_write, rtsmb2_cli_session_send_write, rtsmb2_cli_session_send_write_error_handler,rtsmb2_cli_session_receive_write,},
//  {jobTsmb2_open, rtsmb2_cli_session_send_open, rtsmb2_cli_session_send_error_handler,rtsmb2_cli_session_receive_open,},
//  {jobTsmb2_close, rtsmb2_cli_session_send_close, rtsmb2_cli_session_send_close_error_handler,rtsmb2_cli_session_receive_close,},
//  {jobTsmb2_seek, rtsmb2_cli_session_send_seek, rtsmb2_cli_session_send_seek_error_handler,rtsmb2_cli_session_receive_seek},
//  {jobTsmb2_truncate, rtsmb2_cli_session_send_truncate, rtsmb2_cli_session_send_truncate_error_handler,rtsmb2_cli_session_receive_truncate,},
//  {jobTsmb2_flush, rtsmb2_cli_session_send_flush, rtsmb2_cli_session_send_flush_error_handler,rtsmb2_cli_session_receive_flush,},
//  {jobTsmb2_rename, rtsmb2_cli_session_send_rename, rtsmb2_cli_session_send_rename_error_handler,rtsmb2_cli_session_receive_rename,},
//  {jobTsmb2_delete, rtsmb2_cli_session_send_delete, rtsmb2_cli_session_send_delete_error_handler,rtsmb2_cli_session_receive_delete,},
//  {jobTsmb2_mkdir, rtsmb2_cli_session_send_mkdir, rtsmb2_cli_session_send_mkdir_error_handler,rtsmb2_cli_session_receive_mkdir,},
//  {jobTsmb2_rmdir, rtsmb2_cli_session_send_rmdir, rtsmb2_cli_session_send_rmdir_error_handler,rtsmb2_cli_session_receive_rmdir,},

  {jobTsmb2_find_first,       0, rtsmb2_cli_session_send_find_first      , 0, rtsmb2_cli_session_send_error_handler                ,0,rtsmb2_cli_session_receive_find_first,},
  {jobTsmb2_find_close,       0, rtsmb2_cli_session_send_find_close      , 0, rtsmb2_cli_session_send_find_close_error_handler     ,0,rtsmb2_cli_session_receive_find_close,},
//  {jobTsmb2_stat, rtsmb2_cli_session_send_stat, rtsmb2_cli_session_send_stat_error_handler,rtsmb2_cli_session_receive_stat,},
//  {jobTsmb2_chmode, rtsmb2_cli_session_send_chmode, rtsmb2_cli_session_send_chmode_error_handler,rtsmb2_cli_session_receive_chmode,},
//  {jobTsmb2_full_server_enum, rtsmb2_cli_session_send_full_server_enum, rtsmb2_cli_session_send_full_server_enum_error_handler,rtsmb2_cli_session_receive_full_server_enum,},
//  {jobTsmb2_get_free, rtsmb2_cli_session_send_get_free, rtsmb2_cli_session_send_get_free_error_handler,rtsmb2_cli_session_receive_get_free,},
//  {jobTsmb2_share_find_first, rtsmb2_cli_session_send_share_find_first, rtsmb2_cli_session_send_share_find_first_error_handler,rtsmb2_cli_session_receive_share_find_first,},
//  {jobTsmb2_server_enum, rtsmb2_cli_session_send_server_enum, rtsmb2_cli_session_send_server_enum_error_handler,rtsmb2_cli_session_receive_server_enum,},

};

extern void include_wiretests();
void InitSmbCmdToCmdObjectTable();


// Use static initializer constructor to intitialize run time table
class InitializeSmb2Tables {
    public:
     InitializeSmb2Tables()
     {
      cout << "*** Initializing SMB2 client runtime proccessing variables *** " << endl;
      cout << "***                                                        ***" << endl;
      for (int i = 0; i < TABLEEXTENT(CmdToJobObjectTable);i++)
        glCmdToJobObject[CmdToJobObjectTable[i].command] = &CmdToJobObjectTable[i].cobject;
      InitSmbCmdToCmdObjectTable();

//       AssureCmdToJobObjectInstance();
//      Smb2ClientNegotiateMessageExchange NegotiateObject((smb2_iostream *) 0);
//       Smb2ClientUnNegotiateMessageExchange UnNegotiateObject((smb2_iostream *) 0);
//        cout << "Name 1: " << NegotiateObject.get_command_name() << endl;
//       cout << "Name 2: " << UnNegotiateObject.get_command_name() << endl;
      cout << "*** Done Initializing SMB2 client runtime proccessing variables *** " << endl;
      include_wiretests();
    }
};
InitializeSmb2Tables PerformInitializeSmb2Tables;


#endif /* INCLUDE_RTSMB_CLIENT */
#endif
