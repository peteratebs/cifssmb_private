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
#include "smb2utils.hpp"
#include <smb2wireobjects.hpp>

extern "C" {
#include "smbspnego.h" // void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
int rtsmb_cli_session_ntlm_auth (int sid, byte * user, byte * password, byte *domain, byte * serverChallenge, byte *serverInfoblock, int serverInfoblock_length);
int rtsmb_cli_session_receive_session_setup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
int rtsmb_cli_session_send_session_setup_nt (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob);
void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid);
int rtsmb_cli_session_send_session_setup_error_handler (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, PRTSMB_HEADER pHeader);
}

static int rtsmb_cli_session_logon_user_rt_cpp (int sid, byte * user, byte * password, byte *domain);
extern void rtsmb2_smb2_iostream_to_streambuffer (smb2_iostream  *pStream,NetStreamBuffer &SendBuffer, struct SocketContext &sockContext, DataSinkDevtype &SocketSink);


class SmbLogonWorker {
public:
  SmbLogonWorker(int _sid,  byte *_user_name, byte *_password, byte *_domain)
  {
   ENSURECSTRINGSAFETY(_user_name); ENSURECSTRINGSAFETY(_password); ENSURECSTRINGSAFETY(_domain);
   sid=_sid;user_name=_user_name;password=_password;domain=_domain;
  };
  int go()
  {
      if (prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server)
      {
        rtp_free(prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server); // boiler plate, ignore not_defined_in_RFC4178@please_ignore
        prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server = 0;
      }

      int r = rtsmb_cli_session_logon_user_rt_cpp (sid, user_name, password, domain);

      if(r < 0) return 0;
      cout << "SmbLogonWorker waiting for setup " << r << endl;
      r = wait_on_job_cpp(sid, r);
      if(r < 0) return 0;
      if (prtsmb_cli_ctx->sessions[sid].user.state == CSSN_USER_STATE_CHALLENGED)
      {
         decoded_NegTokenTarg_challenge_t decoded_targ_token;
         int r = spnego_decode_NegTokenTarg_challenge(&decoded_targ_token, prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server, prtsmb_cli_ctx->sessions[sid].user.spnego_blob_size_from_server);

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


static int rtsmb2_cli_session_send_negotiate_error_handler(smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_negotiate (NetStreamBuffer &SendBuffer)
{
    int send_status;
    dword variable_content_size = (dword)2*sizeof(word);
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2NegotiateCmd Smb2NegotiateCmd;
    NetSmb2NBSSCmd<NetSmb2NegotiateCmd> Smb2NBSSCmd(SMB2_NEGOTIATE, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2NegotiateCmd, variable_content_size);
    if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
    {
      Smb2NegotiateCmd.StructureSize=   Smb2NegotiateCmd.FixedStructureSize();
      Smb2NegotiateCmd.DialectCount =   2;
      Smb2NegotiateCmd.SecurityMode =   SMB2_NEGOTIATE_SIGNING_ENABLED;
      Smb2NegotiateCmd.Reserved     =   0;
      Smb2NegotiateCmd.Capabilities =   0; // SMB2_GLOBAL_CAP_DFS  et al
      Smb2NegotiateCmd.guid        =    (byte *) "IAMTHEGUID     ";
      Smb2NegotiateCmd.ClientStartTime = rtsmb_util_get_current_filetime();  // ???  TBD
      Smb2NegotiateCmd.Dialect0 =SMB2_DIALECT_2002;
      Smb2NegotiateCmd.Dialect1 =SMB2_DIALECT_2100;
      Smb2NegotiateCmd.addto_variable_content(4);
      if (Smb2NegotiateCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
    }
    SendBuffer.pStream->pJob->data.session_setup.user_struct = &SendBuffer.pStream->pSession->user;  // gross.
    Smb2NBSSCmd.flush();
    return Smb2NBSSCmd.status;
}
static int rtsmb2_cli_session_receive_negotiate (NetStreamBuffer &ReplyBuffer)
{
//    int send_status;
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2NegotiateReply Smb2NegotiateReply;
  NetSmb2NBSSReply<NetSmb2NegotiateReply> Smb2NBSSReply(SMB2_NEGOTIATE, ReplyBuffer,                InNbssHeader,InSmb2Header, Smb2NegotiateReply);

  if (Smb2NegotiateReply.SecurityBufferLength.get()&&Smb2NegotiateReply.SecurityBufferLength.get() < 255)
  {
    PRTSMB_CLI_SESSION_JOB pJob=ReplyBuffer.pStream->pJob;

    // Hack it isn't set up yet
    ReplyBuffer.pStream->pSession->user.uid = 0;

   pJob->data.session_setup.user_struct->spnego_blob_size_from_server = Smb2NegotiateReply.SecurityBufferLength.get();
   pJob->data.session_setup.user_struct->spnego_blob_from_server = (byte *)rtp_malloc(Smb2NegotiateReply.SecurityBufferLength.get());
   pJob->data.session_setup.user_struct->state = CSSN_USER_STATE_CHALLENGED;
   tc_memcpy( pJob->data.session_setup.user_struct->spnego_blob_from_server, InSmb2Header.FixedStructureAddress()+Smb2NegotiateReply.SecurityBufferOffset.get(), Smb2NegotiateReply.SecurityBufferLength.get());

  }

  cout << ">>>>> Security Offset: " << Smb2NegotiateReply.SecurityBufferOffset.get() << "Length: " << Smb2NegotiateReply.SecurityBufferLength.get() << endl;

   ReplyBuffer.pStream->pSession->server_info.dialect =  (RTSMB_CLI_SESSION_DIALECT)Smb2NegotiateReply.DialectRevision.get();

   // Get the maximum buffer size we can ever want to allocate and store it in buffer_size
   {
    dword maxsize =  Smb2NegotiateReply.MaxReadSize.get();
    if (Smb2NegotiateReply.MaxWriteSize.get() >  maxsize)
      maxsize = Smb2NegotiateReply.MaxWriteSize.get();
    if (Smb2NegotiateReply.MaxTransactSize.get() >  maxsize)
      maxsize = Smb2NegotiateReply.MaxTransactSize.get();
    ReplyBuffer.pStream->pSession->server_info.buffer_size =  maxsize;
    ReplyBuffer.pStream->pSession->server_info.raw_size   =   maxsize;
   }
   ReplyBuffer.pStream->read_buffer_remaining = 0;   // Fore the top layer to stop.
   return RTSMB_CLI_SSN_RV_OK;
}





static int rtsmb2_cli_session_send_setup_with_blob (NetStreamBuffer &SendBuffer, byte *variable_content, dword variable_content_size)
{
    int send_status;
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2SetupCmd     Smb2SetupCmd;
    NetSmb2NBSSCmd<NetSmb2SetupCmd> Smb2NBSSCmd(SMB2_SESSION_SETUP, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2SetupCmd, variable_content_size);
    if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
    {
      Smb2SetupCmd.StructureSize        =  Smb2SetupCmd.FixedStructureSize();
      Smb2SetupCmd.Flags                =  0x0;
      Smb2SetupCmd.SecurityMode         =  0x01;
      Smb2SetupCmd.Capabilities         =  0;
      Smb2SetupCmd.Channel              =  0;
      Smb2SetupCmd.SecurityBufferOffset =  0x58;
      Smb2SetupCmd.SecurityBufferLength =  variable_content_size;
      Smb2SetupCmd.PreviousSessionId    =  0;
      Smb2SetupCmd.addto_variable_content(Smb2SetupCmd.SecurityBufferLength.get());
      if (Smb2SetupCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
      tc_memcpy(OutSmb2Header.FixedStructureAddress()+Smb2SetupCmd.SecurityBufferOffset.get(), variable_content, variable_content_size);
    }
    Smb2NBSSCmd.flush();
    return Smb2NBSSCmd.status;
}

// This is fixed negTokeninit, mechType1 ... see wireshark for decode
static const byte setup_blob[] = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,
0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0xd7,0x3a,0x00,0x00,0x00,0x0f};

static int rtsmb2_cli_session_send_setup (NetStreamBuffer &SendBuffer)
{
  return rtsmb2_cli_session_send_setup_with_blob (SendBuffer,(byte *)setup_blob, sizeof(setup_blob));
#if (0)
    int send_status;
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2SetupCmd     Smb2SetupCmd;
    dword variable_content_size = 74;
    NetSmb2NBSSCmd<NetSmb2SetupCmd> Smb2NBSSCmd(SMB2_SESSION_SETUP, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2SetupCmd, variable_content_size);
    if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
    {
      Smb2SetupCmd.StructureSize        =  Smb2SetupCmd.FixedStructureSize();
      Smb2SetupCmd.Flags                =  0x0;
      Smb2SetupCmd.SecurityMode         =  0x01;
      Smb2SetupCmd.Capabilities         =  0;
      Smb2SetupCmd.Channel              =  0;
      Smb2SetupCmd.SecurityBufferOffset =  0x58;
      Smb2SetupCmd.SecurityBufferLength =  sizeof(setup_blob); // 74;
      Smb2SetupCmd.PreviousSessionId    =  0;
      Smb2SetupCmd.addto_variable_content(Smb2SetupCmd.SecurityBufferLength.get());
      if (Smb2SetupCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
      tc_memcpy(OutSmb2Header.FixedStructureAddress()+Smb2SetupCmd.SecurityBufferOffset.get(), setup_blob, sizeof(setup_blob));
    }
    Smb2NBSSCmd.flush();
    return Smb2NBSSCmd.status;
#endif
}

static int rtsmb2_cli_session_receive_setup (NetStreamBuffer &ReplyBuffer)
{
//    int send_status;
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2SetupReply Smb2SetupReply;
  NetSmb2NBSSReply<NetSmb2SetupReply> Smb2NBSSReply(SMB2_SESSION_SETUP, ReplyBuffer,                InNbssHeader,InSmb2Header, Smb2SetupReply);

  cout << "session_receive_setup received packet" << endl;

  if (InSmb2Header.Status_ChannelSequenceReserved.get() !=  SMB_NT_STATUS_MORE_PROCESSING_REQUIRED)
  {
    cout << "didnt get SMB_NT_STATUS_MORE_PROCESSING_REQUIRED" << endl;
  }
  if (Smb2SetupReply.SecurityBufferLength.get()&&Smb2SetupReply.SecurityBufferLength.get() < 2048)
  {
    PRTSMB_CLI_SESSION_USER user_struct = &ReplyBuffer.pStream->pSession->user;
    PRTSMB_CLI_SESSION_JOB pJob=ReplyBuffer.pStream->pJob;
    user_struct->spnego_blob_size_from_server = Smb2SetupReply.SecurityBufferLength.get();
    user_struct->spnego_blob_from_server = (byte *)rtp_malloc(Smb2SetupReply.SecurityBufferLength.get());
    user_struct->state = CSSN_USER_STATE_CHALLENGED;
    tc_memcpy( user_struct->spnego_blob_from_server, InSmb2Header.FixedStructureAddress()+Smb2SetupReply.SecurityBufferOffset.get(), Smb2SetupReply.SecurityBufferLength.get());
    pJob->data.session_setup.user_struct = user_struct;
  }
  cout << ">>>>> Security Offset: " << Smb2SetupReply.SecurityBufferOffset.get() << "Length: " << Smb2SetupReply.SecurityBufferLength.get() << endl;
  return RTSMB_CLI_SSN_RV_OK;
}
static int rtsmb2_cli_session_send_setup_error_handler(smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_INVALID_RV;}


//  static /*const*/ char ntlmssp_str[] = "NTLMSSP";
//  dword ntlmssp_type = 0x1;
static /*const*/ char setup2_blob[] = "NTLMSSPYEAHBABYNOWWEARETALKING";

static int rtsmb2_cli_session_receive_setupphase_2 (NetStreamBuffer &ReplyBuffer)
{
//    int send_status;
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2SetupReply Smb2SetupReply;
  NetSmb2NBSSReply<NetSmb2SetupReply> Smb2NBSSReply(SMB2_SESSION_SETUP, ReplyBuffer,                InNbssHeader,InSmb2Header, Smb2SetupReply);

  cout << "session_receive_setup received packet" << endl;

  if (InSmb2Header.Status_ChannelSequenceReserved.get() !=  SMB_NT_STATUS_SUCCESS)
  {
    cout << "setup_phase2 didnt get SMB_NT_STATUS_SUCCESS" << endl;
  }
  // Spnego should be a negTokenTarg completed status but ignore it
  // should be 9 bytes: this sequence a1073005a0030a0100
  cout << "setup_phase2 spnego reply size is:  " << Smb2SetupReply.SecurityBufferLength.get() << endl;
  PRTSMB_CLI_SESSION_USER user_struct = &ReplyBuffer.pStream->pSession->user;
  user_struct->state = CSSN_USER_STATE_LOGGED_ON;
  return RTSMB_CLI_SSN_RV_OK;
}




static int rtsmb2_cli_session_send_setupphase_2 (NetStreamBuffer &SendBuffer)
{
PRTSMB_CLI_SESSION_JOB pJob=SendBuffer.pStream->pJob;
  // ntlm_response_blob was set up by rtsmb_cli_session_ntlm_auth which was called by dologonworker after recving the challenge
  return rtsmb2_cli_session_send_setup_with_blob (SendBuffer,(byte *)pJob->data.ntlm_auth.ntlm_response_blob, pJob->data.ntlm_auth.ntlm_response_blob_size);
}

static int rtsmb2_cli_session_send_setupphase_2_error_handler(smb2_iostream  *pStream) {return RTSMB_CLI_SSN_RV_INVALID_RV;}
// --------------------------------------------------------

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

    // Allow CSSN_USER_STATE_CHALLENGED through as a legal state. it will be cleared later.
    if (pSession->user.state != CSSN_USER_STATE_CHALLENGED)
    {
      ASSURE (pSession->user.state == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);
    }
    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pSession->user.uid = 0;
    pJob->data.session_setup.user_struct = &pSession->user;
    rtsmb_cpy (pJob->data.session_setup.account_name, user_string->utf16());
    tc_strcpy (pJob->data.session_setup.password, (char *) password_string->ascii());
    rtsmb_cpy (pJob->data.session_setup.domain_name, domain_string->utf16());

   // note:  rtsmb2_cli_session_receive_negotiate is incomplete wrt processing capabities.


    //
//    pJob->smb2_jobtype = jobTsmb2_setup;    // Setting this makes us pull from the smb2 dispatch table see get_setupobject() below.
    pJob->error_handler    =   0;
    pJob->receive_handler =    0;
    pJob->send_handler    =    0;
    pJob->smb2_jobtype = jobTsmb2_session_setup;

    rtsmb_cli_session_user_new (&pSession->user, 1);

    cout << "rtsmb_cli_session_logon_user_rt_cpp sending setup " << endl;
    rtsmb_cli_session_send_stalled_jobs (pSession);


    int r =  INDEX_OF (pSession->jobs, pJob);
    cout << "rtsmb_cli_session_logon_user_rt_cpp returnig r " << r << endl;
    return r;
}



extern "C" int RtsmbStreamDecodeResponse(smb2_iostream *pStream, PFVOID pItem);
extern "C" int RtsmbWireVarDecode (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize);

extern "C" int myRtsmbWireVarDecodeNegotiateResponseCb(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem)
{
PRTSMB2_NEGOTIATE_R pResponse = (PRTSMB2_NEGOTIATE_R) pItem;
    return RtsmbWireVarDecode (pStream, origin, buf, size, pResponse->SecurityBufferOffset, pResponse->SecurityBufferLength, pResponse->StructureSize);
}




// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.
c_smb2cmdobject negotiateobject = { rtsmb2_cli_session_send_negotiate,0, 0,rtsmb2_cli_session_send_negotiate_error_handler, rtsmb2_cli_session_receive_negotiate, };
c_smb2cmdobject *get_negotiateobject() { return &negotiateobject;};

c_smb2cmdobject setupobject =     { rtsmb2_cli_session_send_setup,    0, 0,rtsmb2_cli_session_send_setup_error_handler,     rtsmb2_cli_session_receive_setup, };
// c_smb2cmdobject negotiateobject = { rtsmb2_cli_session_send_negotiate,0, 0,rtsmb2_cli_session_send_negotiate_error_handler, rtsmb2_cli_session_receive_negotiate, };
c_smb2cmdobject *get_setupobject() { return &setupobject;};



c_smb2cmdobject setupphase_2object =     { rtsmb2_cli_session_send_setupphase_2,    0, 0,rtsmb2_cli_session_send_setupphase_2_error_handler,     rtsmb2_cli_session_receive_setupphase_2, };
// c_smb2cmdobject negotiateobject = { rtsmb2_cli_session_send_negotiate,0, 0,rtsmb2_cli_session_send_negotiate_error_handler, rtsmb2_cli_session_receive_negotiate, };
c_smb2cmdobject *get_setupphase_2object() { return &setupphase_2object;};

#if (0)

// note on negotiate
static int rtsmb2_cli_session_receive_negotiate (smb2_iostream  *pStream)
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
