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
//  The glCmdToJobObject interface has legacy implementations of several commands that will be replaced one at a time.

//
#include "smb2utils.hpp"
#include <smb2wireobjects.hpp>




// SmbCmdToCmdObjectTable[] has links to functions that load stream interfaces for the commands.
extern c_smb2cmdobject *get_negotiateobject();            // smblogon.cpp
extern c_smb2cmdobject *get_setupobject();
extern c_smb2cmdobject *get_setupphase_2object();
extern c_smb2cmdobject *get_treeconnectobject();

// Need one of each of these
extern c_smb2cmdobject *get_session_setupobject();
extern c_smb2cmdobject *get_logoffobject();
extern c_smb2cmdobject *get_tree_disconnectobject();
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


extern "C" BBOOL rtsmb2_smb2_check_response_status_valid (smb2_iostream  *pStream)
{
  if (pStream->InHdr.Status_ChannelSequenceReserved==0)
    return TRUE;
  else if (pStream->InHdr.Status_ChannelSequenceReserved == SMB_NT_STATUS_MORE_PROCESSING_REQUIRED)
    return TRUE;
  else
    return FALSE;
}



/// ===============================


typedef struct smb2cmdobject_table_t
{
  word            command;
  c_smb2cmdobject *(* cobject_fetch)();
  c_smb2cmdobject *cobject;
} smb2cmdobject_table;

typedef std::map <word , struct c_smb2cmdobject_t *> SmbCmdToCmdObject_t;
SmbCmdToCmdObject_t glSmbCmdToCmdObject;

typedef std::map <jobTsmb2 , c_smb2cmdobject *> CmdToJobObject_t;
extern CmdToJobObject_t glCmdToJobObject;


static struct smb2cmdobject_table_t SmbCmdToCmdObjectTable[] =
{
 {jobTsmb2_negotiate              ,  get_negotiateobject, 0},
 {jobTsmb2_session_setup          ,  get_setupobject, 0},
 {jobTsmb2_session_setup_phase_2  ,  get_setupphase_2object, 0},
 {jobTsmb2_tree_connect           ,  get_treeconnectobject, 0},
};
void InitSmbCmdToCmdObjectTable()
{
      cout << "*** Initializing SMB2 SmbCmdToCmdObjectTable  *** " << endl;
  for (int i = 0; i < TABLEEXTENT(SmbCmdToCmdObjectTable);i++)
    glSmbCmdToCmdObject[SmbCmdToCmdObjectTable[i].command] = SmbCmdToCmdObjectTable[i].cobject_fetch();
}

void rtsmb2_smb2_iostream_to_streambuffer (smb2_iostream  *pStream,NetStreamBuffer &SendBuffer, struct SocketContext &sockContext, DataSinkDevtype &SocketSink)
{
  SendBuffer.pStream = pStream;

  sockContext.socket = pStream->pSession->wire.socket;

  SendBuffer.attach_buffer((byte *)pStream->write_origin, pStream->write_buffer_size);
  SendBuffer.attach_sink(&SocketSink);
}

void rtsmb2_smb2_iostream_to_input_streambuffer (smb2_iostream  *pStream,NetStreamBuffer &ReplyBuffer)
{
  ReplyBuffer.pStream = pStream;
//  sockContext.socket = pStream->pSession->wire.socket;
  ReplyBuffer.attach_buffer((byte *)pStream->read_origin, pStream->read_buffer_size);
  //ReplyBuffer.attach_source(&SocketSource);
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
       r = glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->send_handler_smb2(pStream);
  }
  else if ( glCmdToJobObject.find(pStream->pJob->smb2_jobtype) != glCmdToJobObject.end() )
    r = glCmdToJobObject[pStream->pJob->smb2_jobtype]->send_handler_smb2(pStream);
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
      r = glSmbCmdToCmdObject[pStream->InHdr.Command]->receive_handler_smb2(pStream);
  }
  else if ( glCmdToJobObject.find(pStream->pJob->smb2_jobtype) != glCmdToJobObject.end() )
  {
    r = glCmdToJobObject[pStream->pJob->smb2_jobtype]->receive_handler_smb2(pStream);
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
     r = glSmbCmdToCmdObject[pStream->InHdr.Command]->error_handler_smb2(pStream);
  } else if ( glCmdToJobObject.find(pStream->pJob->smb2_jobtype) != glCmdToJobObject.end() )
    r = glCmdToJobObject[pStream->pJob->smb2_jobtype]->error_handler_smb2(pStream);
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
