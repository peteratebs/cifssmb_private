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
#include "smb2wireobjects.hpp"

// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()


extern "C" {
#include "smbspnego.h" // void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
int rtsmb_cli_session_ntlm_auth (int sid, byte * user, byte * password, byte *domain, byte * serverChallenge, byte *serverInfoblock, int serverInfoblock_length);
void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid);
}
// static int rtsmb_cli_session_logon_user_rt_cpp (int sid, byte * user, byte * password, byte *domain);

#include "smb2session.hpp"

class SmbLogonWorker {
public:
  SmbLogonWorker(Smb2Session &Session)
  {  // Constructor that takes a sesstion
    _SmbLogonWorker(Session.sid(), Session.user_name(), Session.password(), Session.domain());
  }
  SmbLogonWorker(int _sid,  byte *_user_name, byte *_password, byte *_domain)
  {
   _SmbLogonWorker(_sid, _user_name, _password, _domain);
  };
  int rtsmb_cli_session_logon_user_rt_cpp (int sid, byte * user, byte * password, byte *domain)
  {
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;
    dualstringdecl(user_string);                   //    dualstring user_string;
    dualstringdecl(password_string);               //    std::auto_ptr<dualstring> user_string(new(dualstring));
    dualstringdecl(domain_string);                 //    dualstring user_string(3);
    dualstringdecl(show_user_string);

    *user_string = user;
    *password_string = password;
    *domain_string = domain;

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

    // State must be CSSN_USER_STATE_UNUSED otherwise only CSSN_USER_STATE_CHALLENGED allowed through as a legal state. it will be cleared later.
    if (pSession->user.state != CSSN_USER_STATE_CHALLENGED)
    { ASSURE (pSession->user.state == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);  }
    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

    pSession->user.uid = 0;
    pJob->data.session_setup.user_struct = &pSession->user;
    rtsmb_cpy (pJob->data.session_setup.account_name, user_string->utf16());
    tc_strcpy (pJob->data.session_setup.password, (char *) password_string->ascii());
    rtsmb_cpy (pJob->data.session_setup.domain_name, domain_string->utf16());
    rtsmb_cli_session_user_new (&pSession->user, 1);

    pJob->error_handler    =   0;   pJob->receive_handler =    0;   pJob->send_handler    =    0;
    pJob->smb2_jobtype = jobTsmb2_session_setup;

    rtsmb_cli_session_send_stalled_jobs (pSession);
    int r =  INDEX_OF (pSession->jobs, pJob);
    if(r < 0) return r;
    return wait_on_job_cpp(sid, r);
  }
  int go()
  {
      // Send setup and wait for the response which will have a challenge blob
      int r = rtsmb_cli_session_logon_user_rt_cpp (sid, user_name, password, domain);
      if(r < 0) return 0;
      if (prtsmb_cli_ctx->sessions[sid].user.state == CSSN_USER_STATE_CHALLENGED)
      {
         decoded_NegTokenTarg_challenge_t decoded_targ_token;
         int r = spnego_decode_NegTokenTarg_challenge(&decoded_targ_token, prtsmb_cli_ctx->sessions[sid].user.spnego_blob_from_server, prtsmb_cli_ctx->sessions[sid].user.spnego_blob_size_from_server);
         if (r == 0)
         {  // Ssends of the hashed challenge and waits for status
            r = rtsmb_cli_session_ntlm_auth (sid, user_name, password, domain,
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
  void _SmbLogonWorker(int _sid,  byte *_user_name, byte *_password, byte *_domain)
  {
   ENSURECSTRINGSAFETY(_user_name); ENSURECSTRINGSAFETY(_password); ENSURECSTRINGSAFETY(_domain);
   sid=_sid;user_name=_user_name;password=_password;domain=_domain;
  };
  int sid;
  byte *user_name;
  byte *password;
  byte *domain;

};


extern int do_smb2_logon_server_worker(Smb2Session &Session)
{
  SmbLogonWorker LogonWorker(Session);
  return LogonWorker.go();
}

//extern "C" int do_smb2_logon_server_worker(int sid,  byte *user_name, byte *password, byte *domain)
//{
//  SmbLogonWorker LogonWorker(sid, user_name, password, domain);
//  return LogonWorker.go();
//}


static int rtsmb2_cli_session_send_negotiate_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_negotiate (NetStreamBuffer &SendBuffer)
{
    int send_status;
    dword variable_content_size = (dword)2*sizeof(word);  // Needs to be known before Smb2NBSSCmd is instantiated
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
      Smb2NegotiateCmd.addto_variable_content(variable_content_size);  // Odd but this is not the same as Smb2NBSSCmd's variable content
      if (Smb2NegotiateCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
    }
    SendBuffer.job_data()->session_setup.user_struct = SendBuffer.session_user();  // gross.
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
  NetSmb2NBSSReply<NetSmb2NegotiateReply> Smb2NBSSReply(SMB2_NEGOTIATE, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2NegotiateReply);

  if (Smb2NegotiateReply.SecurityBufferLength())
  {
    // Hack it isn't set up yet
    ReplyBuffer.session_user()->uid = 0;
   // This is the ignore rfc xx comment, no need to save it
   ReplyBuffer.job_data()->session_setup.user_struct->state = CSSN_USER_STATE_CHALLENGED;
  }
  ReplyBuffer.session_server_info()->dialect =  (RTSMB_CLI_SESSION_DIALECT)Smb2NegotiateReply.DialectRevision();

  // Get the maximum buffer size we can ever want to allocate and store it in buffer_size
  {
    dword maxsize =  Smb2NegotiateReply.MaxReadSize();
    if (Smb2NegotiateReply.MaxWriteSize() >  maxsize)
      maxsize = Smb2NegotiateReply.MaxWriteSize();
    if (Smb2NegotiateReply.MaxTransactSize() >  maxsize)
      maxsize = Smb2NegotiateReply.MaxTransactSize();
    ReplyBuffer.session_server_info()->buffer_size =  maxsize;
    ReplyBuffer.session_server_info()->raw_size   =   maxsize;
    // HEREHERE -  ReplyBuffer.session_server_info()->smb2_session_id = InSmb2Header->Smb2NegotiateReply???
   }
   ReplyBuffer.session_pStream()->read_buffer_remaining = 0;   // Fore the top layer to stop.
   return RTSMB_CLI_SSN_RV_OK;
}


class SmbNegotiateWorker {
public:
  SmbNegotiateWorker(int _sid, PRTSMB_CLI_SESSION _pSession)
  {
    sid      = _sid;
    pSession = _pSession;
  }
  int rtsmb_cli_session_negotiate ()
  {
      PRTSMB_CLI_SESSION_JOB pJob;

      pJob = rtsmb_cli_session_get_free_job (pSession);
      ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

      pJob->smb2_jobtype = jobTsmb2_negotiate;

#if (INCLUDE_ANON_AUTOMATIC)
      /* We set up a chain of actions here.  First is negotiate, then
       we connect an anonymous user.  Then, we connect to the IPC. */
    pJob->callback = rtsmb_cli_session_negotiate_helper;
    pJob->callback_data = pSession;
#endif

    rtsmb_cli_session_send_stalled_jobs (pSession);
    pSession->state = CSSN_STATE_NEGOTIATED;
    return INDEX_OF (pSession->jobs, pJob);
  }
  int go()
  {
      // Send setup and wait for the response which will have a challenge blob
      int r = rtsmb_cli_session_negotiate();
      // Return to the to, do_smb2_connect_server_worker() needs rework to run to completion
      return r;

      if(r < 0) return 0;
      r = wait_on_job_cpp(sid, r);
      if(r < 0) return 0;
      return(1);
  }

private:
  int sid;
  PRTSMB_CLI_SESSION pSession;
};


extern int do_smb2_negotiate_worker(Smb2Session &Session)
{
  PRTSMB_CLI_SESSION pSession = Session.pSession();
  SmbNegotiateWorker NegotiateWorker(INDEX_OF (prtsmb_cli_ctx->sessions, pSession), pSession);
  return NegotiateWorker.go();
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
      Smb2SetupCmd.addto_variable_content(Smb2SetupCmd.SecurityBufferLength());
      if (Smb2SetupCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
      tc_memcpy(OutSmb2Header.FixedStructureAddress()+Smb2SetupCmd.SecurityBufferOffset(), variable_content, variable_content_size);
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
}

static int rtsmb2_cli_session_receive_setup (NetStreamBuffer &ReplyBuffer)
{
//    int send_status;
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2SetupReply Smb2SetupReply;
  NetSmb2NBSSReply<NetSmb2SetupReply> Smb2NBSSReply(SMB2_SESSION_SETUP, ReplyBuffer,                InNbssHeader,InSmb2Header, Smb2SetupReply);

   cout_log(LL_JUNK)  << "session_receive_setup received packet" << endl;

  if (InSmb2Header.Status_ChannelSequenceReserved() !=  SMB_NT_STATUS_MORE_PROCESSING_REQUIRED)
  {
    cout_log(LL_JUNK) << "didnt get SMB_NT_STATUS_MORE_PROCESSING_REQUIRED" << endl;
  }
  if (Smb2SetupReply.SecurityBufferLength()&&Smb2SetupReply.SecurityBufferLength() < 2048)
  {
    ReplyBuffer.session_user()->spnego_blob_size_from_server = Smb2SetupReply.SecurityBufferLength();
    ReplyBuffer.session_user()->spnego_blob_from_server = (byte *)rtp_malloc(Smb2SetupReply.SecurityBufferLength());
    ReplyBuffer.session_user()->state = CSSN_USER_STATE_CHALLENGED;
    tc_memcpy( ReplyBuffer.session_user()->spnego_blob_from_server, InSmb2Header.FixedStructureAddress()+Smb2SetupReply.SecurityBufferOffset(), Smb2SetupReply.SecurityBufferLength());
    ReplyBuffer.job_data()->session_setup.user_struct = ReplyBuffer.session_user();
  }
  return RTSMB_CLI_SSN_RV_OK;
}
static int rtsmb2_cli_session_send_setup_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}


static int rtsmb2_cli_session_receive_setupphase_2 (NetStreamBuffer &ReplyBuffer)
{
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2SetupReply Smb2SetupReply;
  NetSmb2NBSSReply<NetSmb2SetupReply> Smb2NBSSReply(SMB2_SESSION_SETUP, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2SetupReply);

  if (InSmb2Header.Status_ChannelSequenceReserved() !=  SMB_NT_STATUS_SUCCESS)
    cout_log(LL_JUNK) << "setup_phase2 didnt get SMB_NT_STATUS_SUCCESS" << endl;
  // Spnego should be a negTokenTarg completed status but ignore it
  // should be 9 bytes: this sequence a1073005a0030a0100
  // cout << "setup_phase2 spnego reply size is:  " << Smb2SetupReply.SecurityBufferLength() << endl;
  ReplyBuffer.session_user()->state = CSSN_USER_STATE_LOGGED_ON;
  return RTSMB_CLI_SSN_RV_OK;
}


static int rtsmb2_cli_session_send_setupphase_2 (NetStreamBuffer &SendBuffer)
{  // ntlm_response_blob was set up by rtsmb_cli_session_ntlm_auth which was called by dologonworker after recving the challenge
  return rtsmb2_cli_session_send_setup_with_blob (SendBuffer,(byte *)SendBuffer.job_data()->ntlm_auth.ntlm_response_blob, SendBuffer.job_data()->ntlm_auth.ntlm_response_blob_size);
}

static int rtsmb2_cli_session_send_setupphase_2_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}
// --------------------------------------------------------


// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.
c_smb2cmdobject negotiateobject = { rtsmb2_cli_session_send_negotiate,rtsmb2_cli_session_send_negotiate_error_handler, rtsmb2_cli_session_receive_negotiate, };
c_smb2cmdobject *get_negotiateobject() { return &negotiateobject;};
c_smb2cmdobject setupobject =     { rtsmb2_cli_session_send_setup,   rtsmb2_cli_session_send_setup_error_handler,     rtsmb2_cli_session_receive_setup, };
c_smb2cmdobject *get_setupobject() { return &setupobject;};
c_smb2cmdobject setupphase_2object =     { rtsmb2_cli_session_send_setupphase_2,rtsmb2_cli_session_send_setupphase_2_error_handler, rtsmb2_cli_session_receive_setupphase_2, };
c_smb2cmdobject *get_setupphase_2object() { return &setupphase_2object;};

