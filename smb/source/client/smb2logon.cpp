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
#include <memory>
#include "smb2utils.hpp"

using std::cout;
using std::endl;

#include "smbdefs.h"


#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include <wireobjects.hpp>
#include <smb2wireobjects.hpp>
#include <netstreambuffer.hpp>
extern "C" {
#include "smbspnego.h" // void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
int rtsmb_cli_session_ntlm_auth (int sid, byte * user, byte * password, byte *domain, byte * serverChallenge, byte *serverInfoblock, int serverInfoblock_length);
int rtsmb_cli_session_receive_session_setup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
int rtsmb_cli_session_send_session_setup_nt (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid);
int rtsmb_cli_session_send_session_setup_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
int RtsmbStreamEncodeCommand(smb2_iostream *pStream, PFVOID pItem);
}

void rtsmb2_cli_session_init_header(smb2_iostream  *pStream, word command, ddword mid64, ddword SessionId);


// --------------------------------------------------------
extern "C" void mark_rv_cpp (int job, int rv, void *data)
{
    int *idata = (int *)data;

    *idata = rv;
    if (rv == -RTSMB_CLI_WIRE_BAD_MID)
        cout << "Bad Permissions, Marked" << *idata << endl;
}

static int wait_on_job_cpp(int sid, int job)
{
    int rv = RTSMB_CLI_SSN_RV_INVALID_RV;
    rtsmb_cli_session_set_job_callback(sid, job, mark_rv_cpp, &rv);

    while(rv == RTSMB_CLI_SSN_RV_INVALID_RV )
    {
        int r = rtsmb_cli_session_cycle(sid, 10);
        if (r < 0)
        {
//            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "\n wait_on_job: rtsmb_cli_session_cycle returned error == %d\n",r);
            return r;
        }
    }
    return rv;
}



static int rtsmb_cli_session_logon_user_rt_cpp (int sid, byte * user, byte * password, byte *domain)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;
//    dualstring user_string;
//    std::auto_ptr<dualstring> user_string(new(dualstring));
//    dualstring user_string(3);
    dualstringdecl(user_string);
    dualstringdecl(password_string);
    dualstringdecl(domain_string);
    dualstringdecl(show_user_string);

    *user_string = user;
    *password_string = password;
    *domain_string = domain;
//    *password_string = (byte *)password;


    if (user_string->input_length() > (CFG_RTSMB_MAX_USERNAME_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;

    if (password_string->input_length() > (CFG_RTSMB_MAX_PASSWORD_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;

    if (domain_string->input_length() > (CFG_RTSMB_MAX_DOMAIN_NAME_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    ASSURE (pSession->user.state == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);
    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pSession->user.uid = 0;
    pJob->data.session_setup.user_struct = &pSession->user;
    rtsmb_cpy (pJob->data.session_setup.account_name, user_string->utf16());
    tc_strcpy (pJob->data.session_setup.password, (char *) password_string->ascii());
    rtsmb_cpy (pJob->data.session_setup.domain_name, domain_string->utf16());

    pJob->error_handler = rtsmb_cli_session_send_session_setup_error_handler;
    pJob->receive_handler = rtsmb_cli_session_receive_session_setup;

    switch (pSession->server_info.dialect)
    {
//    case CSSN_DIALECT_PRE_NT:
//        pJob->send_handler = rtsmb_cli_session_send_session_setup_pre_nt;
//        break;

    case CSSN_DIALECT_NT:
        if (ON (pSession->server_info.capabilities, CAP_EXTENDED_SECURITY))
        {
            pJob->send_handler = rtsmb_cli_session_send_session_setup_nt;
        }
        else
        {
            pJob->send_handler = rtsmb_cli_session_send_session_setup_nt;
        }
        break;
    case CSSN_DIALECT_SMB2_2002:
        break;
    }

    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
    {
        pJob->smb2_jobtype = jobTsmb2_session_setup;
    }
    rtsmb_cli_session_user_new (&pSession->user, 1);

    rtsmb_cli_session_send_stalled_jobs (pSession);

    return INDEX_OF (pSession->jobs, pJob);
}

class SmbLogonWorker {
public:
//  SmbLogonWorker(int _sid,  byte *_user_name=(byte *)"", byte *_password=(byte *)"", byte *_domain=(byte *)"")
  SmbLogonWorker(int _sid,  byte *_user_name, byte *_password, byte *_domain)
  {
   ENSURECSTRINGSAFETY(_user_name); ENSURECSTRINGSAFETY(_password); ENSURECSTRINGSAFETY(_domain);
   sid=_sid;user_name=_user_name;password=_password;domain=_domain;
  };
  int go()
  {
      int r = rtsmb_cli_session_logon_user_rt_cpp (sid, user_name, password, domain);

      if(r < 0) return 0;
      r = wait_on_job_cpp(sid, r);
      if(r < 0) return 0;
      if (prtsmb_cli_ctx->sessions[sid].user.state == CSSN_USER_STATE_CHALLENGED)
      {
         decoded_NegTokenTarg_challenge_t decoded_targ_token;
         r = spnego_decode_NegTokenTarg_challenge(&decoded_targ_token, prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server, prtsmb_cli_ctx->sessions[sid].user.spnego_blob_size_from_server);
         if (r == 0)
         {
             r = rtsmb_cli_session_ntlm_auth (sid, user_name, password, domain, // Does a send/wait
                 decoded_targ_token.ntlmserverchallenge,
                 decoded_targ_token.target_info->value_at_offset,
                 decoded_targ_token.target_info->size);
         }
         rtp_free(prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server);
         spnego_decoded_NegTokenTarg_challenge_destructor(&decoded_targ_token);
         if(r < 0) return 0;
         r = wait_on_job_cpp(sid, r);
         if(r < 0) return 0;
      }
    return(1);
  }

private:
  int sid;
  byte *user_name;
  byte *password;
  byte *domain;

};

extern "C" int do_logon_server_worker(int sid,  byte *user_name, byte *password, byte *domain)
{
  SmbLogonWorker LogonWorker(sid, user_name, password, domain);
  return LogonWorker.go();
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
