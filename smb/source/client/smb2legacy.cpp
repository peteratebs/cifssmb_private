//
// smb2legacy.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  Populate SmbCmdToCmdObjectTable[] as commands are moved to a stream interface for the commands
//  and accessed through glSmbCmdToCmdObject
//

//
#include "smb2utils.hpp"
#include <smb2wireobjects.hpp>




// SmbCmdToCmdObjectTable[] has links to functions that load stream interfaces for the commands.
extern c_smb2cmdobject *get_negotiateobject();            // smblogon.cpp
extern c_smb2cmdobject *get_setupobject();
extern c_smb2cmdobject *get_setupphase_2object();
extern c_smb2cmdobject *get_treeconnectobject();
extern c_smb2cmdobject *get_logoffobject();
extern c_smb2cmdobject *get_disconnectobject();
extern c_smb2cmdobject *get_querydirectoryobject();

// Need one of each of these
extern c_smb2cmdobject *get_readobject();
extern c_smb2cmdobject *get_writeobject();
extern c_smb2cmdobject *get_openobject();
extern c_smb2cmdobject *get_closeobject();
extern c_smb2cmdobject *get_seekobject();
extern c_smb2cmdobject *get_truncateobject();
extern c_smb2cmdobject *get_flushobject();
extern c_smb2cmdobject *get_renameobject();
extern c_smb2cmdobject *get_deleteobject();
extern c_smb2cmdobject *get_mkdirobject();
extern c_smb2cmdobject *get_rmdirobject();
extern c_smb2cmdobject *get_find_firstobject();
extern c_smb2cmdobject *get_find_closeobject();
extern c_smb2cmdobject *get_statobject();
extern c_smb2cmdobject *get_chmodeobject();
extern c_smb2cmdobject *get_full_server_enumobject();
extern c_smb2cmdobject *get_get_freeobject();
extern c_smb2cmdobject *get_share_find_firstobject();
extern c_smb2cmdobject *get_server_enumobject();



// ===============================
// Use static initializer constructor to intitialize run time table

typedef struct smb2cmdobject_table_t
{
  jobTsmb2            command;
  c_smb2cmdobject *(* cobject_fetch)();
  c_smb2cmdobject *cobject;
} smb2cmdobject_table;

typedef std::map <word , struct c_smb2cmdobject_t *> SmbCmdToCmdObject_t;
SmbCmdToCmdObject_t glSmbCmdToCmdObject;

typedef std::map <jobTsmb2 , c_smb2cmdobject *> CmdToJobObject_t;

static struct smb2cmdobject_table_t SmbCmdToCmdObjectTable[] =
{
 {jobTsmb2_negotiate              ,  get_negotiateobject, 0},
 {jobTsmb2_session_setup          ,  get_setupobject, 0},
 {jobTsmb2_session_setup_phase_2  ,  get_setupphase_2object, 0},
 {jobTsmb2_tree_connect           ,  get_treeconnectobject, 0},
 {jobTsmb2_logoff                 ,  get_logoffobject, 0},
 {jobTsmb2_disconnect             ,  get_disconnectobject, 0},
 {jobTsmb2_find_first             ,  get_querydirectoryobject, 0},
};

void InitSmbCmdToCmdObjectTable()
{
  cout_log(LL_INIT) << "*** Initializing SMB2 SmbCmdToCmdObjectTable  *** " << endl;
  for (int i = 0; i < TABLEEXTENT(SmbCmdToCmdObjectTable);i++)
     glSmbCmdToCmdObject[SmbCmdToCmdObjectTable[i].command] = SmbCmdToCmdObjectTable[i].cobject_fetch();
}

extern void include_wiretests();
void InitSmbCmdToCmdObjectTable();

// Use static initializer constructor to intitialize run time table
class InitializeSmb2Tables {
    public:
     InitializeSmb2Tables()
     {
      cout_log(LL_INIT) << "*** Initializing SMB2 client runtime proccessing variables *** " << endl;
      cout_log(LL_INIT) << "***                                                        ***" << endl;
      InitSmbCmdToCmdObjectTable();
      cout_log(LL_INIT) << "*** Done Initializing SMB2 client runtime proccessing variables *** " << endl;
      include_wiretests();
    }
};
InitializeSmb2Tables PerformInitializeSmb2Tables;
// end static initializer constructor to intitialize run time tables
// ===============================

/// Bind a buffer and tcpip socket for sending
///   attaches a socket and a legacy smb2_iostream structure which references MID mapped buffer pools, NetStreamBuffer
void rtsmb2_smb2_iostream_to_streambuffer (smb2_iostream  *pStream,NetStreamBuffer &SendBuffer, struct SocketContext &sockContext, DataSinkDevtype &SocketSink)
{
  SendBuffer.session_pStream(pStream);
  sockContext.socket = pStream->pSession->wire.socket;

  SendBuffer.attach_buffer((byte *)pStream->write_origin, pStream->write_buffer_size);
  SendBuffer.attach_sink(&SocketSink);
}

/// Bind a buffer for receiving.
///   attaches structure which references MID mapped buffer pools to NetStreamBuffer
///   For receive sockets are bound in seperate step
void rtsmb2_smb2_iostream_to_input_streambuffer (smb2_iostream  *pStream,NetStreamBuffer &ReplyBuffer)
{
  ReplyBuffer.session_pStream(pStream);
  ReplyBuffer.attach_buffer((byte *)pStream->read_origin, pStream->read_buffer_size,pStream->pSession->wire.total_read);
}

extern "C" int rtsmb_cli_wire_smb2_send_handler(smb2_iostream  *pStream)        //  Called from rtsmb_cli_session_send_job  if pJob->smb2_jobtype
{
int r = RTSMB_CLI_SSN_RV_OK;

  if (glSmbCmdToCmdObject.find(pStream->pJob->smb2_jobtype) != glSmbCmdToCmdObject.end() )
  {
     NetStreamBuffer    SendBuffer;
     struct             SocketContext sockContext;
     DataSinkDevtype SocketSink(socket_sink_function, (void *)&sockContext);
     rtsmb2_smb2_iostream_to_streambuffer(pStream, SendBuffer, sockContext, SocketSink);

     if (glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->new_send_handler_smb2)
       r = glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->new_send_handler_smb2(SendBuffer);
     else
       ; // r = glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->send_handler_smb2(pStream);
  }
  return r;
}

extern "C" int rtsmb_cli_wire_receive_handler_smb2(smb2_iostream  *pStream)     //  Called from rtsmb_cli_session_handle_job_smb2
{
int r = RTSMB_CLI_SSN_RV_OK;

  if (glSmbCmdToCmdObject.find(pStream->pJob->smb2_jobtype) != glSmbCmdToCmdObject.end() )
  {
    NetStreamBuffer    SendBuffer;
    struct             SocketContext sockContext;
//    DataSinkDevtype SocketSource(socket_sink_function, (void *)&sockContext);
    rtsmb2_smb2_iostream_to_input_streambuffer(pStream, SendBuffer);

    if (glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->new_receive_handler_smb2)
      r = glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->new_receive_handler_smb2(SendBuffer);
    else
      ; // r = glSmbCmdToCmdObject[pStream->InHdr.Command]->receive_handler_smb2(pStream);
  }
  return r;
}

extern "C" int rtsmb_cli_wire_error_handler_smb2(smb2_iostream  *pStream)       // Called from rtsmb_cli_session_handle_job_smb2
{
int r = RTSMB_CLI_SSN_RV_OK;
  if (glSmbCmdToCmdObject.find(pStream->pJob->smb2_jobtype) != glSmbCmdToCmdObject.end() )
  {
   NetStreamBuffer    SendBuffer;
   struct             SocketContext sockContext;
   DataSinkDevtype SocketSink(socket_sink_function, (void *)&sockContext);
   rtsmb2_smb2_iostream_to_streambuffer(pStream, SendBuffer, sockContext, SocketSink);

   if (glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->new_error_handler_smb2)
      r = glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->new_error_handler_smb2(SendBuffer);
   else if (glSmbCmdToCmdObject.find(pStream->InHdr.Command) != glSmbCmdToCmdObject.end() )
     ; // r = glSmbCmdToCmdObject[pStream->InHdr.Command]->error_handler_smb2(pStream);
  }
  return r;
}

// Init header function using bytes order alignment friendly factory object replaces C version of same name.
extern "C" int rtsmb_nbss_fill_header_cpp (PFVOID buf, rtsmb_size size, PRTSMB_NBSS_HEADER pStruct)
{
NetNbssHeader NbssHeader;
  if (size < NbssHeader.FixedStructureSize())
    return -1;
  NbssHeader.bindpointers((byte *)buf);
  NbssHeader.nbss_packet_type =  pStruct->type;
  NbssHeader.nbss_packet_size =  pStruct->size;
  return NbssHeader.FixedStructureSize(); // RTSMB_NBSS_HEADER_SIZE;
}
#ifdef __notused__
// Init header function using bytes order?alignment friendly factory object replaces C version of same.
extern void rtsmb2_cli_session_init_header(smb2_iostream  *pStream, word command, ddword mid64, ddword SessionId)
{
NetSmb2Header Smb2Header;
    tc_memset(&pStream->OutHdr, 0, sizeof(pStream->OutHdr));

    Smb2Header.bindpointers((byte *)&pStream->OutHdr);

    Smb2Header.ProtocolId    =     (byte *)"\xfeSMB";
    Smb2Header.StructureSize =     64       ; // 64
    Smb2Header.CreditCharge =      0; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
    Smb2Header.Status_ChannelSequenceReserved = 0; /*  (4 bytes): */
    Smb2Header.Command = command;
    Smb2Header.CreditRequest_CreditResponse = 0;
    Smb2Header.Flags = 0;
    Smb2Header.NextCommand = 0;
    Smb2Header.MessageId = mid64;
    Smb2Header.Reserved = 0;
    Smb2Header.TreeId =  0;
    Smb2Header.SessionId = SessionId;
    Smb2Header.Signature = (byte *)"IAMTHESIGNATURE";
}

extern "C" BBOOL rtsmb2_smb2_check_response_status_valid (smb2_iostream  *pStream)
{
  if (pStream->InHdr.Status_ChannelSequenceReserved==0)
    return TRUE;
  else if (pStream->InHdr.Status_ChannelSequenceReserved == SMB_NT_STATUS_MORE_PROCESSING_REQUIRED)
    return TRUE;
  else
    return FALSE;
}

#endif

extern "C" {

smb2_iostream  *rtsmb_cli_wire_smb2_iostream_construct (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
smb2_iostream  *rtsmb_cli_wire_smb2_iostream_get(PRTSMB_CLI_WIRE_SESSION pSession, word mid);
smb2_iostream  *rtsmb_cli_wire_smb2_iostream_attach (PRTSMB_CLI_WIRE_SESSION pSession, word mid, int header_length, RTSMB2_HEADER *pheader_smb2);

void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession);

int rtsmb_cli_wire_smb2_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);
extern void  smb2_iostream_start_encryption(smb2_iostream *pStream);

} // extern C


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

