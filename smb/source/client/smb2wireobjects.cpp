//
// smb2wireobjects.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
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
#include <string>
using std::cout;
using std::endl;

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
//#include "client.h"
#include <wireobjects.hpp>
#include <smb2wireobjects.hpp>
#include <netstreambuffer.hpp>

extern "C" int RtsmbStreamEncodeCommand(smb2_iostream *pStream, PFVOID pItem);

void rtsmb2_cli_session_init_header(smb2_iostream  *pStream, word command, ddword mid64, ddword SessionId);
/// ===============================



typedef struct c_smb2cmdobject_t
{
  const char *command_name;
  int   command_size;
  pVarEncodeFn_t pVarEncodeFn;
  int   reply_size;
  pVarDecodeFn_t pVarDecodeFn;
  int (*send_handler_smb2)    (smb2_iostream  *psmb2stream);
  int (*error_handler_smb2)   (smb2_iostream  *psmb2stream);
  int (*receive_handler_smb2) (smb2_iostream  *psmb2stream);
} c_smb2cmdobject;

typedef struct smb2cmdobject_table_t
{
  word            command;
  c_smb2cmdobject cobject;
} smb2cmdobject_table;

typedef std::map <word , struct c_smb2cmdobject_t *> SmbCmdToCmdObject_t;
SmbCmdToCmdObject_t glSmbCmdToCmdObject;

static bool cpp_handler_dispatch_send(smb2_iostream  *pStream, int &status)
{
  if (glSmbCmdToCmdObject.find(pStream->pJob->smb2_jobtype) != glSmbCmdToCmdObject.end() )
  {    // ???
     status = glSmbCmdToCmdObject[pStream->pJob->smb2_jobtype]->send_handler_smb2(pStream);
     return true;
  }
  return false;
}
static bool cpp_handler_dispatch_recv(smb2_iostream  *pStream, int &status)
{
  if (glSmbCmdToCmdObject.find(pStream->InHdr.Command) != glSmbCmdToCmdObject.end() )
  {    // ???
     status = glSmbCmdToCmdObject[pStream->InHdr.Command]->receive_handler_smb2(pStream);
     return true;
  }
  return false;
}

static bool cpp_handler_dispatch_error(smb2_iostream  *pStream, int &status)
{
  if (glSmbCmdToCmdObject.find(pStream->InHdr.Command) != glSmbCmdToCmdObject.end() )
  {
     printf("Yo executing error from glSmbCmdToCmdObjectb: %d \n", pStream->pJob->smb2_jobtype);
     status = glSmbCmdToCmdObject[pStream->InHdr.Command]->error_handler_smb2(pStream);
     return true;
  }
  return false;
}

// duplicated for now

typedef struct c_jobobject_t
{
    int (*send_handler_smb2)    (smb2_iostream  *psmb2stream);
    int (*error_handler_smb2)   (smb2_iostream  *psmb2stream);
    int (*receive_handler_smb2) (smb2_iostream  *psmb2stream);
} c_jobobject;

typedef std::map <jobTsmb2 , c_jobobject *> CmdToJobObject_t;
extern CmdToJobObject_t glCmdToJobObject;
// ================

extern "C" int rtsmb_cli_wire_smb2_send_handler(smb2_iostream  *pStream)        //  rtsmb_cli_session_send_job
{
int r = RTSMB_CLI_SSN_RV_OK;
  if (cpp_handler_dispatch_send(pStream, r))
    ;
  else if ( glCmdToJobObject.find(pStream->pJob->smb2_jobtype) != glCmdToJobObject.end() )
    r = glCmdToJobObject[pStream->pJob->smb2_jobtype]->send_handler_smb2(pStream);
  return r;
}

extern "C" int rtsmb_cli_wire_receive_handler_smb2(smb2_iostream  *pStream)
{
int r = RTSMB_CLI_SSN_RV_OK;

  printf("Yo search job: %d \n", pStream->pJob->smb2_jobtype);
  if (cpp_handler_dispatch_recv(pStream, r))
  {
     printf("Yo executed rev from cpp_handler_dispatch_recv: \n");
  }
  else if ( glCmdToJobObject.find(pStream->pJob->smb2_jobtype) != glCmdToJobObject.end() )
  {
     r = glCmdToJobObject[pStream->pJob->smb2_jobtype]->receive_handler_smb2(pStream);
  }
  return r;
}
extern "C" int rtsmb_cli_wire_error_handler_smb2(smb2_iostream  *pStream)
{
int r = RTSMB_CLI_SSN_RV_OK;
  if (cpp_handler_dispatch_error (pStream, r))
  {
     printf("Yo executed error from cpp_handler_dispatch_recv: \n");
  }
  else if ( glCmdToJobObject.find(pStream->pJob->smb2_jobtype) != glCmdToJobObject.end() )
    r = glCmdToJobObject[pStream->pJob->smb2_jobtype]->error_handler_smb2(pStream);
  return r;
}
// Messy for now but our goal is to replace CmdToJobObjectTable

extern int rtsmb2_cli_session_send_negotiate_error_handler(smb2_iostream  *pStream); // handled in cpp layer
extern int rtsmb2_cli_session_send_negotiate(smb2_iostream  *pStream);
extern "C" int rtsmb2_cli_session_receive_negotiate (smb2_iostream  *pStream); // This is now implemented in the cpp code base.
extern "C" int RtsmbWireVarDecodeNegotiateResponseCb(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
static struct smb2cmdobject_table_t SmbCmdToCmdObjectTable[] =
{
// command_name, send_fixed_size, VarEncodeCb,  rcv_fixed_size, VarDecodeCb
//  see also {jobTsmb2_negotiate,{                                                        rtsmb2_cli_session_send_negotiate, rtsmb2_cli_session_send_negotiate_error_handler,rtsmb2_cli_session_receive_negotiate}},
 {SMB2_NEGOTIATE, {"NEGOTIATE", 36, 0, 64, RtsmbWireVarDecodeNegotiateResponseCb, rtsmb2_cli_session_send_negotiate,rtsmb2_cli_session_send_negotiate_error_handler,rtsmb2_cli_session_receive_negotiate},},
};
void InitSmbCmdToCmdObjectTable()
{
      cout << "*** Initializing SMB2 SmbCmdToCmdObjectTable  *** " << endl;
  for (int i = 0; i < TABLEEXTENT(SmbCmdToCmdObjectTable);i++)
    glSmbCmdToCmdObject[SmbCmdToCmdObjectTable[i].command] = &SmbCmdToCmdObjectTable[i].cobject;
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

//    PACK_BYTE (buf, &size, pStruct->type, -1);
//    PACK_BYTE (buf, &size, (byte) (pStruct->size>>16 & 0xFF), -1);
//    PACK_BYTE (buf, &size, (byte) (pStruct->size>>8 & 0xFF), -1);
//    PACK_BYTE (buf, &size, (byte) (pStruct->size & 0xFF), -1);

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

//    tc_memcpy(pStream->OutHdr.ProtocolId,"\xfeSMB",4);
//    pStream->OutHdr.StructureSize=64;
//    pStream->OutHdr.CreditCharge = 0;
//    pStream->OutHdr.Status_ChannelSequenceReserved=0; /*  (4 bytes): */
//    pStream->OutHdr.Command = command;
//    pStream->OutHdr.CreditRequest_CreditResponse = 0;
//    pStream->OutHdr.Flags = 0;
//    pStream->OutHdr.NextCommand = 0;
//    pStream->OutHdr.MessageId = mid64;
//    pStream->OutHdr.SessionId = SessionId;
//    pStream->OutHdr.Reserved=0;
//    pStream->OutHdr.TreeId=0;
}


void NetNbssHeader::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(nbss_packet_type);
  BINDPOINTERS(nbss_packet_size);
}

void NetSmb2Header::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(ProtocolId);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(CreditCharge);
  BINDPOINTERS(Status_ChannelSequenceReserved);
  BINDPOINTERS(Command);
  BINDPOINTERS(CreditRequest_CreditResponse);
  BINDPOINTERS(Flags);
  BINDPOINTERS(NextCommand);
  BINDPOINTERS(MessageId);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(TreeId);
  BINDPOINTERS(SessionId);
  BINDPOINTERS(Signature);
}

void NetSmb2NegotiateCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 36
  BINDPOINTERS(DialectCount);
  BINDPOINTERS(SecurityMode);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(Capabilities);
  BINDPOINTERS(guid);
  BINDPOINTERS(ClientStartTime);
  // Variable number of arguments right after the fixed section behaves the same as fixed
  BINDPOINTERS(Dialect0);
  BINDPOINTERS(Dialect1);
  BINDPOINTERS(Dialect2);
  BINDPOINTERS(Dialect3);
}




#endif /* INCLUDE_RTSMB_CLIENT */
#endif
