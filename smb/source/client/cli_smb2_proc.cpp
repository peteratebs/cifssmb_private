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

//  {jobTsmb2_find_first,       0, rtsmb2_cli_session_send_find_first      , 0, rtsmb2_cli_session_send_error_handler                ,0,rtsmb2_cli_session_receive_find_first,},
//  {jobTsmb2_find_close,       0, rtsmb2_cli_session_send_find_close      , 0, rtsmb2_cli_session_send_find_close_error_handler     ,0,rtsmb2_cli_session_receive_find_close,},
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
