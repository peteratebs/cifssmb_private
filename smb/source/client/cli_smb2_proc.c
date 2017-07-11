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

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include "com_smb2.h"
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

static Rtsmb2ClientSession Rtsmb2ClientSessionArray[32];
static void rtsmb2_cli_session_free_dir_query_buffer (smb2_stream  *pStream);

extern PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_free_buffer (PRTSMB_CLI_WIRE_SESSION pSession);

int rtsmb_cli_wire_smb2_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

static Rtsmb2ClientSession *NewRtsmb2ClientSession(void);

/* Called when a new_session is created sepcifying an SMBV2 dialect. Calls NewRtsmb2ClientSession() to allocate a new V2 session..
   Currently holds SessionId, building it up. */
void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession)
{
    pSession->psmb2Session = NewRtsmb2ClientSession();
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb_cli_smb2_session_init called: Session == %X  pSession->psmb2Session == %X\n",(int)pSession, (int) pSession->psmb2Session);
}

void rtsmb_cli_smb2_session_release (PRTSMB_CLI_SESSION pSession)
{
    if (pSession->psmb2Session)
    {
        pSession->psmb2Session->inUse = FALSE;
        pSession->psmb2Session = 0;
    }
}


static Rtsmb2ClientSession *NewRtsmb2ClientSession(void)
{
int i;
    for (i = 0; i < 32; i++)
    {
        if (!Rtsmb2ClientSessionArray[i].inUse)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session number %d of %d just allocated\n", i,TABLE_SIZE(Rtsmb2ClientSessionArray) );
            Rtsmb2ClientSessionArray[i].inUse = TRUE;
            return &Rtsmb2ClientSessionArray[i];
        }
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "No client sessions available\n");
    return 0;
}

smb2_stream  *rtsmb_cli_wire_smb2_stream_construct (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    BBOOL EncryptMessage = FALSE; // HEREHERE
    int v1_mid;

    /* Attach a buffer to the wire session */
    v1_mid = rtsmb_cli_wire_smb2_add_start (&pSession->wire, pJob->mid);
    if (v1_mid<0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: rtsmb_cli_wire_smb2_add_start Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        return 0;
    }

    pJob->mid = (word)v1_mid;
    pBuffer = rtsmb_cli_wire_get_buffer (&pSession->wire, (word) v1_mid);
    if (!pBuffer)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: rtsmb_cli_wire_get_buffer Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
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
    if (!(pBuffer->smb2stream.pSession && pBuffer->smb2stream.pSession->psmb2Session))
    {
        if (!pSession)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: NewRtsmb2ClientSession Failed no PRTSMB_CLI_SESSION !!!!!!!!!\n");
        }
        else
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_construct: NewRtsmb2ClientSession Failed no psmb2Session !!!!!!!!!!!!!!!!!\n");
        }
        return 0;
    }
    pBuffer->smb2stream.pJob     = pJob;
    if (EncryptMessage)
        smb2_stream_start_encryption(&pBuffer->smb2stream);
    return &pBuffer->smb2stream;
}

smb2_stream  *rtsmb_cli_wire_smb2_stream_get(PRTSMB_CLI_WIRE_SESSION pSession, word mid)
{
    PRTSMB_CLI_WIRE_BUFFER pBuffer;
    pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);
    if (pBuffer)
    {
        return &pBuffer->smb2stream;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_get: rtsmb_cli_wire_get_buffer Failed !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    return 0;
}


smb2_stream  *rtsmb_cli_wire_smb2_stream_attach (PRTSMB_CLI_WIRE_SESSION pSession, word mid, int header_length, RTSMB2_HEADER *pheader_smb2)
{
    smb2_stream  *pStream = rtsmb_cli_wire_smb2_stream_get(pSession, mid);

    if (pStream )
    {
        pStream->InHdr     = *pheader_smb2;
        pStream->pInBuf    = PADD(pStream->pInBuf,header_length);
        pStream->read_buffer_remaining -= (rtsmb_size)header_length;
    }
   return pStream;
}

int rtsmb_cli_wire_smb2_stream_flush(PRTSMB_CLI_WIRE_SESSION pSession, smb2_stream  *pStream)
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
    rtsmb_nbss_fill_header (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE, &header);

    TURN_ON (pBuffer->flags, INFO_CAN_TIMEOUT);

    if (pSession->state == CONNECTED)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_stream_flush: Set state Waiting on us\n");
        pBuffer->state = WAITING_ON_US;
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_US);
#endif
    }
    else
    {
        pBuffer->end_time_base = rtp_get_system_msec ();
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_stream_flush: Writing %d bytes\n",(int)pBuffer->buffer_size);
        if (rtsmb_net_write (pSession->socket, pBuffer->buffer, (int)pBuffer->buffer_size)<0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_flush: Error writing %d bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->buffer_size);
            return -2;
        }

      #ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
        if (pBuffer->attached_data)
        {
            if (rtsmb_net_write (pSession->socket, pBuffer->attached_data, (int)pBuffer->attached_size)<0)
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_cli_wire_smb2_stream_flush: Error writing %d attached bytes !!!!!!!!!!!!!!!!!\n",(int)pBuffer->attached_size);
                return -2;
            }
        }
      #endif
        pBuffer->state = WAITING_ON_SERVER;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb_cli_wire_smb2_stream_flush: Set state Waiting on server\n");
#ifdef STATE_DIAGNOSTICS
Get_Wire_Buffer_State(WAITING_ON_SERVER);
#endif
    }
    return 0;
}


static void rtsmb2_cli_session_init_header(smb2_stream  *pStream, word command, ddword mid64, ddword SessionId)
{

    tc_memset(&pStream->OutHdr, 0, sizeof(pStream->OutHdr));
    tc_memcpy(pStream->OutHdr.ProtocolId,"\xfeSMB",4);
    pStream->OutHdr.StructureSize=64;
    pStream->OutHdr.CreditCharge = 0;
    pStream->OutHdr.Status_ChannelSequenceReserved=0; /*  (4 bytes): */
    pStream->OutHdr.Command = command;
    pStream->OutHdr.CreditRequest_CreditResponse = 0;
    pStream->OutHdr.Flags = 0;
    pStream->OutHdr.NextCommand = 0;
    pStream->OutHdr.MessageId = mid64;
    pStream->OutHdr.SessionId = SessionId;
    pStream->OutHdr.Reserved=0;
    pStream->OutHdr.TreeId=0;
    tc_strcpy((char *)pStream->OutHdr.Signature,"IAMTHESIGNATURE");

}

int RtsmbStreamEncodeCommand(smb2_stream *pStream, PFVOID pItem);
int RtsmbStreamDecodeResponse(smb2_stream *pStream, PFVOID pItem);


/* Encode with RtsmbStreamEncodeCommand */
int rtsmb2_cli_session_send_negotiate (smb2_stream  *pStream)
{
    RTSMB2_NEGOTIATE_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_NEGOTIATE, (ddword) pStream->pBuffer->mid, 0);

    command_pkt.StructureSize = 36;
    command_pkt.DialectCount=2;
    command_pkt.SecurityMode  = SMB2_NEGOTIATE_SIGNING_ENABLED;
    command_pkt.Reserved=0;
    command_pkt.Capabilities = 0; // SMB2_GLOBAL_CAP_DFS  et al
    tc_strcpy((char *)command_pkt.guid, "IAMTHEGUID     ");
    command_pkt.ClientStartTime = 0; // rtsmb_util_get_current_filetime();  // ???  TBD
    /* GUID is zero for SMB2002 */
    // tc_memset(command_pkt.ClientGuid, 0, 16);
    command_pkt.Dialects[0] = SMB2_DIALECT_2002;
    command_pkt.Dialects[1] = SMB2_DIALECT_2100;

    /* Packs the SMB2 header and negotiate command into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}


int rtsmb2_cli_session_receive_negotiate (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_NEGOTIATE_R response_pkt;
byte securiy_buffer[255];

    pStream->ReadBufferParms[0].byte_count = sizeof(securiy_buffer);
    pStream->ReadBufferParms[0].pBuffer = securiy_buffer;
    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;
    pStream->pSession->server_info.dialect =  response_pkt.DialectRevision;
/*

Indented means accounted for

    word SecurityMode;
  word DialectRevision;
    byte  ServerGuid[16];
    dword Capabilities;
  dword MaxTransactSize;
  dword MaxReadSize;
  dword MaxWriteSize;
    ddword SystemTime;
    ddword ServerStartTime;
  word SecurityBufferOffset;
  word SecurityBufferLength;
  dword Reserved2;
  byte  SecurityBuffer;
*/

   // Get the maximum buffer size we can ever want to allocate and store it in buffer_size
   {
    dword maxsize =  response_pkt.MaxReadSize;
    if (response_pkt.MaxWriteSize >  maxsize)
      maxsize = response_pkt.MaxWriteSize;
    if (response_pkt.MaxTransactSize >  maxsize)
      maxsize = response_pkt.MaxTransactSize;
    pStream->pSession->server_info.buffer_size =  maxsize;
    pStream->pSession->server_info.raw_size   =   maxsize;
   }

#if (0)

##    pSession->server_info.dialect = 0;
##    if (nr.DialectRevision == SMB2_DIALECT_2002)
##        pSession->server_info.dialect = CSSN_DIALECT_SMB2_2002;
##    ASSURE (pSession->server_info.dialect != 0, RTSMB_CLI_SSN_RV_MALFORMED);
##
##//    pSession->server_info.user_mode = ON (nr.security_mode, 0x1);
##    pSession->server_info.capabilities = nr.Capabilities;
##//    pSession->server_info.encrypted = ON (nr.security_mode, 0x2);
##    pSession->server_info.buffer_size = nr.MaxReadSize;
##    pSession->server_info.raw_size = nr.MaxTransactSize;
##//    pSession->server_info.vcs = nr.max_vcs;
##//    pSession->server_info.session_id = nr.session_id;
##//    pSession->server_info.mpx_count = (word) MIN (nr.max_mpx_count, prtsmb_cli_ctx->max_jobs_per_session);
##
##HEREHERE - Do the session
##    int r = 0;
##
##    nr.challenge_size = 8;
##    nr.challenge = pSession->server_info.challenge;
##    nr.domain = 0;
##    nr.dialect_index = 0;
##    nr.security_mode = 0;
##    nr.capabilities = 0;
##    nr.max_buffer_size = 0;
##    nr.max_raw_size = 0;
##    nr.max_vcs = 0;
##    nr.session_id = 0;
##    nr.max_mpx_count = 0;
##
#####    rtsmb_cli_wire_smb2_read (&pSession->wire, pHeader->mid, cmd_read_negotiate_smb2, &nr, r);
##    ASSURE (r == 0, RTSMB_CLI_SSN_RV_MALFORMED);
##
##    /* make sure we have a valid dialect */
##    ASSURE (nr.dialect_index != 0xFF, RTSMB_CLI_SSN_RV_DEAD);
##    ASSURE (nr.dialect_index < NUM_SPOKEN_DIALECTS, RTSMB_CLI_SSN_RV_MALICE);
##
##    pSession->server_info.dialect = dialect_types[nr.dialect_index];
##    pSession->server_info.user_mode = ON (nr.security_mode, 0x1);
##    pSession->server_info.capabilities = nr.capabilities;
##    pSession->server_info.encrypted = ON (nr.security_mode, 0x2);
##    pSession->server_info.buffer_size = nr.max_buffer_size;
##    pSession->server_info.raw_size = nr.max_raw_size;
##    pSession->server_info.vcs = nr.max_vcs;
##    pSession->server_info.session_id = nr.session_id;
##    pSession->server_info.mpx_count = (word) MIN (nr.max_mpx_count, prtsmb_cli_ctx->max_jobs_per_session);
##
##    if (pSession->server_info.encrypted)
##    {
##        /* we currently only support 8-bytes */
##        ASSURE (nr.challenge_size == 8, RTSMB_CLI_SSN_RV_DEAD);
##    }
#endif
    return recv_status;
}


// Captured init blob from windows
static byte spnego_init_blob[] = {
  0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,
  0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0x39,0x38,0x00,0x00,0x00,0x0f};

int spnego_encode_NegTokenInit_packet(smb2_stream  *pStream, int *spnego_blob_size_to_server, byte **spnego_blob_to_server)
{
    *spnego_blob_to_server = (PFBYTE)spnego_init_blob;
    *spnego_blob_size_to_server = sizeof(spnego_init_blob);
    return *spnego_blob_size_to_server;
}
#if (0)
static int ntlmssp_encode_ntlm2_init_packet(smb2_stream  *pStream, int *spnego_blob_size_to_server, byte **spnego_blob_to_server)
{
  // NTLMSSP signature
  // Should be NTLM Message Type: NTLMSSP_NEGOTIATE (0x00000001)
  //    Flags: 0xa0080205
    *spnego_blob_to_server = (PFBYTE)"Hello from the blob";
    *spnego_blob_size_to_server = sizeof("Hello from the blob");
    return *spnego_blob_size_to_server;
}
#endif
int rtsmb2_cli_session_send_session_setup (smb2_stream  *pStream)
{
    RTSMB2_SESSION_SETUP_C command_pkt;
    int send_status;
    int spnego_blob_size_to_server;
    byte *spnego_blob_to_server;
        /* Hard wiring SNGEGO blob   */
    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_SESSION_SETUP, (ddword) pStream->pBuffer->mid,0);

    command_pkt.StructureSize = 25;
    command_pkt.Flags = 0;
    command_pkt.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED;
    command_pkt.Capabilities = 0;
    command_pkt.Channel = 0;

//   ntlmssp_encode_ntlm2_init_packet(pStream, &spnego_blob_size_to_server, &spnego_blob_to_server);
    spnego_encode_NegTokenInit_packet(pStream, &spnego_blob_size_to_server, &spnego_blob_to_server);

    command_pkt.SecurityBufferOffset = (word)(pStream->OutHdr.StructureSize+command_pkt.StructureSize-1);
    command_pkt.SecurityBufferLength = (word)spnego_blob_size_to_server;
    pStream->WriteBufferParms[0].byte_count = spnego_blob_size_to_server;
    pStream->WriteBufferParms[0].pBuffer = spnego_blob_to_server;

    /* Packs the SMB2 header and setup command/blob into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}

// Captured challenge response token blob from windows
static byte spnego_chalenge_response_blob[] = {
0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x03,0x00,0x00,0x00,0x18,0x00,0x18,0x00,0xa0,0x00,0x00,0x00,0x20,0x01,0x20,0x01,0xb8,0x00,0x00,0x00,0x1e,0x00,0x1e,0x00,0x58,0x00,0x00,0x00,0x0c,
0x00,0x0c,0x00,0x76,0x00,0x00,0x00,0x1e,0x00,0x1e,0x00,0x82,0x00,0x00,0x00,0x10,0x00,0x10,0x00,0xd8,0x01,0x00,0x00,0x15,0x02,0x88,0xe2,0x0a,0x00,0x39,0x38,0x00,0x00,0x00,0x0f,0x09,0x56,
0xe4,0x6d,0x66,0x1a,0x10,0xc0,0x96,0xef,0xa9,0x29,0x35,0xaa,0xbd,0x3e,0x4c,0x00,0x41,0x00,0x50,0x00,0x54,0x00,0x4f,0x00,0x50,0x00,0x2d,0x00,0x52,0x00,0x4f,0x00,0x51,0x00,0x50,0x00,0x4f,
0x00,0x30,0x00,0x50,0x00,0x42,0x00,0x6e,0x00,0x6f,0x00,0x74,0x00,0x65,0x00,0x62,0x00,0x73,0x00,0x4c,0x00,0x41,0x00,0x50,0x00,0x54,0x00,0x4f,0x00,0x50,0x00,0x2d,0x00,0x52,0x00,0x4f,0x00,
0x51,0x00,0x50,0x00,0x4f,0x00,0x30,0x00,0x50,0x00,0x42,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc7,
0xc7,0x8e,0xf2,0xac,0xd4,0x4b,0xa8,0x3c,0xe8,0x5f,0x1c,0x3a,0x6d,0xea,0x85,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x89,0x67,0x34,0x53,0x52,0xf7,0xd2,0x01,0x92,0xe8,0xaa,0x28,0x3c,0xc5,
0x44,0x03,0x00,0x00,0x00,0x00,0x02,0x00,0x0e,0x00,0x44,0x00,0x4f,0x00,0x4d,0x00,0x41,0x00,0x49,0x00,0x4e,0x00,0x00,0x00,0x01,0x00,0x26,0x00,0x4e,0x00,0x45,0x00,0x54,0x00,0x42,0x00,0x49,
0x00,0x4f,0x00,0x53,0x00,0x43,0x00,0x4f,0x00,0x4d,0x00,0x50,0x00,0x55,0x00,0x54,0x00,0x45,0x00,0x52,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x00,0x00,0x04,0x00,0x1c,0x00,0x44,0x00,0x4e,0x00,
0x53,0x00,0x44,0x00,0x4f,0x00,0x4d,0x00,0x41,0x00,0x49,0x00,0x4e,0x00,0x4e,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x00,0x00,0x03,0x00,0x1e,0x00,0x44,0x00,0x4e,0x00,0x53,0x00,0x43,0x00,0x4f,
0x00,0x4d,0x00,0x50,0x00,0x55,0x00,0x54,0x00,0x45,0x00,0x52,0x00,0x41,0x00,0x4d,0x00,0x45,0x00,0x00,0x00,0x08,0x00,0x30,0x00,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
0x00,0x20,0x00,0x00,0xe6,0x1c,0x6c,0x9c,0x22,0xdd,0xfd,0xaa,0x13,0xa1,0x7e,0x97,0x7b,0x50,0xc2,0xcc,0xe6,0x42,0x9d,0x81,0xdc,0xd9,0x08,0x34,0xdf,0xbd,0xf2,0x2a,0xc8,0x60,0xef,0xfc,0x0a,
0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,0x00,0x22,0x00,0x63,0x00,0x69,0x00,0x66,0x00,0x73,0x00,0x2f,0x00,0x31,0x00,0x39,0x00,
0x32,0x00,0x2e,0x00,0x31,0x00,0x36,0x00,0x38,0x00,0x2e,0x00,0x31,0x00,0x2e,0x00,0x31,0x00,0x37,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4f,0x4c,0x7e,0x18,0x87,0x19,0x2b,0x2f,0x45,
0xb9,0x1f,0x0e,0x62,0xba,0x0a,0x5d };


int rtsmb2_cli_session_receive_session_setup (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_SESSION_SETUP_R response_pkt;
byte securiy_buffer[255];

    pStream->ReadBufferParms[0].byte_count = sizeof(securiy_buffer);
    pStream->ReadBufferParms[0].pBuffer = securiy_buffer;

//    recv_status = cmd_read_header_smb2 (pStream);
//    ASSURE (recv_status > 0, RTSMB_CLI_SSN_RV_MALFORMED);
    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;

    pStream->pSession->psmb2Session->SessionId = pStream->InHdr.SessionId;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_session_setup: Set stream's session id to %X\n", (int)pStream->pSession->psmb2Session->SessionId);

	/* make sure we have a valid user */
	if (pStream->pJob->data.session_setup.user_struct->state != CSSN_USER_STATE_LOGGING_ON)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb2_cli_session_receive_session_setup: %s\n", "pStream->pJob->data.session_setup.user_struct->state != CSSN_USER_STATE_LOGGING_ON");
	    return RTSMB_CLI_SSN_RV_BAD_UID;
    }

//	pStream->pJob->data.session_setup.user_struct->uid = pHeader->uid;
	pStream->pJob->data.session_setup.user_struct->state = CSSN_USER_STATE_LOGGED_ON;


#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_USER_STATE_LOGGED_ON);
#endif
	rtsmb_cpy (pStream->pJob->data.session_setup.user_struct->name, pStream->pJob->data.session_setup.account_name);
	tc_strcpy (pStream->pJob->data.session_setup.user_struct->password, pStream->pJob->data.session_setup.password);
	rtsmb_cpy (pStream->pJob->data.session_setup.user_struct->domain_name, pStream->pJob->data.session_setup.domain_name);

    return recv_status;
}

int rtsmb2_cli_session_send_tree_connect (smb2_stream  *pStream)
{
    RTSMB2_TREE_CONNECT_C command_pkt;
    rtsmb_char share_name [RTSMB_NB_NAME_SIZE + RTSMB_MAX_SHARENAME_SIZE + 4]; /* 3 for '\\'s and 1 for null */
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));

    rtsmb2_cli_session_init_header (pStream, SMB2_TREE_CONNECT, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);

    tc_memset (share_name, 0, sizeof (share_name));
    if (tc_strcmp (pStream->pSession->server_name, "") != 0)
    {
        share_name[0] = '\\';
        share_name[1] = '\\';
        rtsmb_util_ascii_to_rtsmb (pStream->pSession->server_name, &share_name[2], CFG_RTSMB_USER_CODEPAGE);
        share_name [rtsmb_len (share_name)] = '\\';
    }
    rtsmb_util_ascii_to_rtsmb (pStream->pJob->data.tree_connect.share_name, &share_name [rtsmb_len (share_name)], CFG_RTSMB_USER_CODEPAGE);
    rtsmb_util_string_to_upper (share_name, CFG_RTSMB_USER_CODEPAGE);
    pStream->WriteBufferParms[0].pBuffer = share_name;
    pStream->WriteBufferParms[0].byte_count = (rtsmb_len (share_name)+1)*sizeof(rtsmb_char);

    command_pkt.StructureSize   = 9;
    command_pkt.Reserved        = 0;
    command_pkt.PathOffset      = (word) (pStream->OutHdr.StructureSize+command_pkt.StructureSize-1);
    command_pkt.PathLength      = (word)pStream->WriteBufferParms[0].byte_count;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_tree_connect called: Sharename == %s\n",share_name);
    /* Save the message ID in the share sructure */
	pStream->pJob->data.tree_connect.share_struct->connect_mid = pStream->pJob->mid;


//=====
//	r = rtsmb_cli_wire_smb_add_start (&pSession->wire, pJob->mid);
//	ASSURE (r >= 0, RTSMB_CLI_SSN_RV_LATER);
//	pJob->mid = (word) r;
//	pJob->data.tree_connect.share_struct->connect_mid = pJob->mid;
//	rtsmb_cli_wire_smb_add_header (&pSession->wire, pJob->mid, &h);
//	rtsmb_cli_wire_smb_add (&pSession->wire, pJob->mid, cli_cmd_fill_tree_connect_and_x, &t, r);
//	rtsmb_cli_wire_smb_add_end (&pSession->wire, pJob->mid);
// ================
    /* Packs the SMB2 header and tree connect command/blob into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}


int rtsmb2_cli_session_receive_tree_connect (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_TREE_CONNECT_R response_pkt;

    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;

// ====================================
//int rtsmb_cli_session_receive_tree_connect (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader)
{
    PRTSMB_CLI_SESSION pSession;
	PRTSMB_CLI_SESSION_SHARE pShare;
	int r = 0;

	pShare = 0;
    pSession  = pStream->pSession;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_tree_connect called\n");
    if(!pSession)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect: No sesion info !!!! \n");
    }
    if(pSession)
    {
	    for (r = 0; r < prtsmb_cli_ctx->max_shares_per_session; r++)
    	{
      		if (pSession->shares[r].state != CSSN_SHARE_STATE_UNUSED &&
    		    pSession->shares[r].connect_mid == (word) pStream->InHdr.MessageId)
    		{
    			pShare = &pSession->shares[r];
    		    break;
    		}
    	}
    }
   	if (!pShare)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_connect: No Share found !!!!!!! \n");
        return RTSMB_CLI_SSN_RV_MALFORMED;
    }

	pShare->tid = (word)pStream->InHdr.TreeId;
	pShare->state = CSSN_SHARE_STATE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SHARE_STATE (CSSN_SHARE_STATE_CONNECTED);
#endif
	tc_strcpy (pShare->share_name, pStream->pJob->data.tree_connect.share_name);
	tc_strcpy (pShare->password, pStream->pJob->data.tree_connect.password);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_tree_connect: Share found: Names == %s\n",pShare->share_name);

	/* We special-case a situation where we have just connected to the IPC$ share.  This
	   means that we are now a fully-negotiated session and should alert our consumer. */
	if (tc_strcmp (pShare->share_name, "IPC$") == 0)
	{
		/* To denote this, we find the pseudo-job that was waiting on this and finish it. */
		for (r = 0; r < prtsmb_cli_ctx->max_jobs_per_session; r++)
		{
			if (pSession->jobs[r].state == CSSN_JOB_STATE_FAKE)
			{
			    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_tree_connect IPC$: Finish logon by calling rtsmb_cli_session_job_cleanup\n");
				rtsmb_cli_session_job_cleanup (pSession, &pSession->jobs[r], RTSMB_CLI_SSN_RV_OK);
			}
		}
	}

	if (pSession->state == CSSN_STATE_RECOVERY_TREE_CONNECTING)
	{
		pSession->state = CSSN_STATE_RECOVERY_TREE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_USER_STATE (CSSN_STATE_RECOVERY_TREE_CONNECTED);
#endif
	}

    recv_status = RTSMB_CLI_SSN_RV_OK;
}
// ====================================
/*
    response_pkt.StructureSize;
    response_pkt.ShareType;
    response_pkt.Reserved;
    response_pkt.ShareFlags;
    response_pkt.Capabilities;
    response_pkt.MaximalAccess;
*/
    return recv_status;
}
int rtsmb2_cli_session_send_tree_connect_error_handler (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_session_setup_error_handler (smb2_stream  *pStream)
{
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb2_cli_session_send_session_setup_error_handler: called with error == %X\n", (int)pStream->InHdr.Status_ChannelSequenceReserved);
    return RTSMB_CLI_SSN_RV_INVALID_RV;  /* Don't intercept the message */
}

int rtsmb2_cli_session_send_logoff (smb2_stream  *pStream)
{
    RTSMB2_LOGOFF_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_LOGOFF, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);
    command_pkt.StructureSize   = 4;
    command_pkt.Reserved        = 0;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_logoff called:\n");
    /* Packs the SMB2 header and tree disconnect into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}
int rtsmb2_cli_session_receive_logoff (smb2_stream  *pStream)
{
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_logoff called for session (%d):\n",(int)pStream->InHdr.SessionId);
 	/* make sure we have a valid user */
	if (pStream->pSession->user.state != CSSN_USER_STATE_LOGGED_ON)
	{
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_logoff: error: (pStream->pSession->user.state != CSSN_USER_STATE_LOGGED_ON) \n");
	    return RTSMB_CLI_SSN_RV_BAD_UID;
    }

//	ASSURE (pSession->user.uid == pHeader->uid, RTSMB_CLI_SSN_RV_BAD_UID);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_logoff: calling: rtsmb_cli_session_user_close \n");
	rtsmb_cli_session_user_close (&pStream->pSession->user);


    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb2_cli_session_send_tree_disconnect (smb2_stream  *pStream)
{
    RTSMB2_TREE_DISCONNECT_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));


    rtsmb2_cli_session_init_header (pStream, SMB2_TREE_DISCONNECT, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);

    pStream->OutHdr.TreeId = (ddword) pStream->pJob->data.tree_disconnect.tid;
    command_pkt.StructureSize   = 4;
    command_pkt.Reserved        = 0;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_tree_disconnect called:\n");
    /* Packs the SMB2 header and tree disconnect into the stream buffer and sets send_status to OK or and ERROR */
    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;
    return send_status;
}
int rtsmb2_cli_session_receive_tree_disconnect (smb2_stream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
int rv;
RTSMB2_TREE_DISCONNECT_R response_pkt;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_disconnect: called with error == %X\n", (int)pStream->InHdr.Status_ChannelSequenceReserved);
    if ((rv=RtsmbStreamDecodeResponse(pStream, &response_pkt)) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_disconnect: RtsmbStreamDecodeResponse failed with error == %X\n", rv);
        return RTSMB_CLI_SSN_RV_MALFORMED;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "rtsmb2_cli_session_receive_tree_disconnect: RtsmbStreamDecodeResponse success on treeId == %d\n", (int) pStream->InHdr.TreeId);
    return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb2_cli_session_send_read (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_read (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}

int rtsmb2_cli_session_send_write (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_write (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_open (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_open (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_close (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_close (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_seek (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_seek (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_truncate (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_truncate (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_flush (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_rename (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_delete (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_mkdir (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_rmdir (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}


int rtsmb2_cli_session_send_find_first (smb2_stream  *pStream)
{
    RTSMB2_QUERY_DIRECTORY_C command_pkt;
    int send_status;
    tc_memset(&command_pkt, 0, sizeof(command_pkt));


    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: Session == %X \n",(int)pStream->pSession);

    rtsmb2_cli_session_init_header (pStream, SMB2_QUERY_DIRECTORY, (ddword) pStream->pBuffer->mid,pStream->pSession->psmb2Session->SessionId);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: pStream->pSession->psmb2Session == %X \n",(int)pStream->pSession->psmb2Session);

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

int rtsmb2_cli_session_send_find_first_error_handler (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}

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
      if (0 && (rtsmb_cmp (BothDirInfoIterator->FileName, dot) == 0 || rtsmb_cmp (BothDirInfoIterator->FileName, dotdot) == 0))
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
int rtsmb2_cli_session_find_buffered_rt (int sid, PRTSMB_CLI_SESSION_DSTAT pdstat)
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


int rtsmb2_cli_session_receive_find_first (smb2_stream  *pStream)
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

static void rtsmb2_cli_session_free_dir_query_buffer (smb2_stream  *pStream)
{
  if (pStream->pJob->data.findsmb2.search_struct->pBufferedResponse)
  {
    rtp_free(pStream->pJob->data.findsmb2.search_struct->pBufferedResponse);
    pStream->pJob->data.findsmb2.search_struct->pBufferedResponse = 0;
    pStream->pJob->data.findsmb2.search_struct->pBufferedIteratorEnd =
    pStream->pJob->data.findsmb2.search_struct->pBufferedResponse = 0;

  }
}

int rtsmb2_cli_session_send_find_close (smb2_stream  *pStream)
{
//   pStream->pSession;       // For a client. points to the controlling SMBV1 session structure.
//   pStream->pJob;

   /*Make sure we free any buffering we left */
   rtsmb2_cli_session_free_dir_query_buffer (pStream);
    /*  Release the buffer we used for this job */

   /* we also want to close everything up here -- useless to wait for response */
   rtsmb_cli_session_search_close (pStream->pJob->data.findsmb2.search_struct);
   return RTSMB_CLI_SSN_RV_OK;
}

int rtsmb2_cli_session_send_stat (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_stat (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_chmode (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_full_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_full_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_get_free (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_get_free (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_share_find_first (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_share_find_first (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_send_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}
int rtsmb2_cli_session_receive_server_enum (smb2_stream  *pStream) {return RTSMB_CLI_SSN_RV_OK;}


#endif /* INCLUDE_RTSMB_CLIENT */
#endif