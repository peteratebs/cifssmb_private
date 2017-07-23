//
// smb2logon.cpp -
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



void show_cpp_rtsmb2_cli_session_recv_negotiate(smb2_iostream  *pStream)
{
NetNbssHeader NbssHeader;
NetSmb2Header Smb2Header;
   cout << "Parsing live input  !!" << endl;
//   byte *pSmb2Raw = NbssHeader.bindpointers((byte *)pStream->read_origin);
//   cout << "(NBSS Size :)" << NbssHeader.nbss_packet_size.get() << endl;
   byte *pSmb2Raw =(byte *)pStream->read_origin;
   pSmb2Raw = Smb2Header.bindpointers(pSmb2Raw);
   cout << "(SMB2 Size :)" << Smb2Header.StructureSize.get() << endl;

}


extern "C" int RtsmbWireEncodeSmb2(smb2_iostream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarEncodeFn_t pVarEncodeFn);


extern int rtsmb2_cli_session_send_negotiate_error_handler(smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_INVALID_RV;}


// part of this chain.
// do_logon_server_worker()
//   >> int rtsmb_cli_session_logon_user (int sid, PFCHAR user, PFCHAR password, PFCHAR domain) >>
//       >>int rtsmb_cli_session_logon_user_rt (int sid, PFRTCHAR user, PFCHAR password, PFRTCHAR domain)    >> rtsmb2_cli_session_send_negotiate()
//  r = wait_on_job(sid, r);
//   >> rtsmb_cli_session_ntlm_auth
//       rtsmb_cli_session_send_session_extended_logon
//  r = send_stalled_jobs(sid, r);
//       recv extended logon finishes it

extern int rtsmb2_cli_session_send_negotiate (smb2_iostream  *pStream)
{
//    RTSMB2_NEGOTIATE_C command_pkt;
    byte  command_pkt[44];                  // Max size is 36 * 4 * sizeof(word) == 44 bytes
    NetSmb2NegotiateCmd Smb2NegotiateCmd;
    int send_status;

    tc_memset(&command_pkt, 0, sizeof(command_pkt));
    rtsmb2_cli_session_init_header (pStream, SMB2_NEGOTIATE, (ddword) pStream->pBuffer->mid, 0);

    Smb2NegotiateCmd.bindpointers((byte *)command_pkt);
    Smb2NegotiateCmd.StructureSize=   Smb2NegotiateCmd.FixedStructureSize();
    Smb2NegotiateCmd.DialectCount =   2;
    Smb2NegotiateCmd.SecurityMode =   SMB2_NEGOTIATE_SIGNING_ENABLED;
    Smb2NegotiateCmd.Reserved     =   0;
    Smb2NegotiateCmd.Capabilities =   0; // SMB2_GLOBAL_CAP_DFS  et al
    Smb2NegotiateCmd.guid        =    (byte *) "IAMTHEGUID     ";
    Smb2NegotiateCmd.ClientStartTime = 0; // rtsmb_util_get_current_filetime();  // ???  TBD
    Smb2NegotiateCmd.Dialect0 =SMB2_DIALECT_2002;
    Smb2NegotiateCmd.Dialect1 =SMB2_DIALECT_2100;
//    Smb2NegotiateCmd.Dialect2 =
//    Smb2NegotiateCmd.Dialect3 =


//    command_pkt.StructureSize = 36;
//    command_pkt.DialectCount=2;
//    command_pkt.SecurityMode  = SMB2_NEGOTIATE_SIGNING_ENABLED;
//    command_pkt.Reserved=0;
//    command_pkt.Capabilities = 0; // SMB2_GLOBAL_CAP_DFS  et al
//    tc_strcpy((char *)command_pkt.guid, "IAMTHEGUID     ");
//    command_pkt.ClientStartTime = 0; // rtsmb_util_get_current_filetime();  // ???  TBD
//    /* GUID is zero for SMB2002 */
//    // tc_memset(command_pkt.ClientGuid, 0, 16);
//    command_pkt.Dialects[0] = SMB2_DIALECT_2002;
//    command_pkt.Dialects[1] = SMB2_DIALECT_2100;

    /* Packs the SMB2 header and negotiate command into the stream buffer and sets send_status to OK or and ERROR */
//    if (RtsmbStreamEncodeCommand(pStream,&command_pkt) < 0)
     if (RtsmbWireEncodeSmb2(pStream,  command_pkt, 40, 0) < 0)
        send_status=RTSMB_CLI_SSN_RV_TOO_MUCH_DATA;
    else
       send_status=RTSMB_CLI_SSN_RV_OK;


    return send_status;
}

extern "C" int RtsmbStreamDecodeResponse(smb2_iostream *pStream, PFVOID pItem);
extern "C" int RtsmbWireVarDecode (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize);

extern "C" int myRtsmbWireVarDecodeNegotiateResponseCb(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_NEGOTIATE_R pResponse = (PRTSMB2_NEGOTIATE_R) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pResponse->SecurityBufferOffset, pResponse->SecurityBufferLength, pResponse->StructureSize);
}


extern "C" int rtsmb2_cli_session_receive_negotiate (smb2_iostream  *pStream);
int rtsmb2_cli_session_receive_negotiate (smb2_iostream  *pStream)
{
int recv_status = RTSMB_CLI_SSN_RV_OK;
RTSMB2_NEGOTIATE_R response_pkt;
byte securiy_buffer[255];

    pStream->ReadBufferParms[0].byte_count = sizeof(securiy_buffer);
    pStream->ReadBufferParms[0].pBuffer = securiy_buffer;
    if (RtsmbStreamDecodeResponse(pStream, &response_pkt) < 0)
        return RTSMB_CLI_SSN_RV_MALFORMED;
   show_cpp_rtsmb2_cli_session_recv_negotiate(pStream);
    pStream->pSession->server_info.dialect =  (RTSMB_CLI_SESSION_DIALECT)response_pkt.DialectRevision;
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
#endif /* INCLUDE_RTSMB_CLIENT */
#endif
