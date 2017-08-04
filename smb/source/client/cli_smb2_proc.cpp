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

#endif /* INCLUDE_RTSMB_CLIENT */
#endif
