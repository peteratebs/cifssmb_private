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
void rtsmb_cli_session_job_cleanup (PRTSMB_CLI_SESSION pSession, PRTSMB_CLI_SESSION_JOB pJob, int r);
}
// static int rtsmb_cli_session_logon_user_rt_cpp (int sid, byte * user, byte * password, byte *domain);

#include "smb2session.hpp"


RTSMB_STATIC rtsmb_char wildcard_type[]        = {'?', '?', '?', '?', '?', '\0'};

class SmbTreeConnectWorker {
public:
  SmbTreeConnectWorker(int _sid,  byte *_sharename, byte *_password)  // ascii
  {
   ENSURECSTRINGSAFETY(_sharename); ENSURECSTRINGSAFETY(_password);
   sid=_sid;sharename=_sharename;password=_password;
  };
  int go()
  {
  cout_log(LL_JUNK)  << "YOYO !!! GOGOGO !!" << endl;
     int r = rtsmb_cli_session_connect_share (sid, (PFCHAR)sharename, (PFCHAR)password);
     if(r < 0) return 0;
     r = wait_on_job_cpp(sid, r);
     if(r < 0) return 0;
    return(1);
  }

private:
  int rtsmb_cli_session_connect_share (int sid, PFCHAR share, PFCHAR password)
  {
      PRTSMB_CLI_SESSION_JOB pJob;
      PRTSMB_CLI_SESSION_SHARE pShare;
      PRTSMB_CLI_SESSION pSession;

      pSession = rtsmb_cli_session_get_session (sid);
      ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
      ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
      rtsmb_cli_session_update_timestamp (pSession);

      ASSURE (share, RTSMB_CLI_SSN_RV_BAD_SHARE);

      /* First, see if we alread are connected */
      pShare = rtsmb_cli_session_get_share (pSession, share);
      if (pShare && pShare->state != CSSN_SHARE_STATE_DIRTY)
      {
          return RTSMB_CLI_SSN_RV_ALREADY_CONNECTED;
      }

      if (!pShare)
      {
          /* find free share */
          pShare = rtsmb_cli_session_get_free_share (pSession);
          ASSURE (pShare, RTSMB_CLI_SSN_RV_TOO_MANY_SHARES);
      }
      else
      {
          pShare->state = CSSN_SHARE_STATE_CONNECTING;
  #ifdef STATE_DIAGNOSTICS
  RTSMB_GET_SESSION_STATE (CSSN_SHARE_STATE_CONNECTING);
  #endif
      }

      pJob = rtsmb_cli_session_get_free_job (pSession);
      if (!pJob)
          rtsmb_cli_session_share_close (pShare);
      ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

      pJob->data.tree_connect.share_type = wildcard_type; // disk_type;
      pJob->data.tree_connect.share_struct = pShare;
      tc_strcpy (pJob->data.tree_connect.share_name, share);
      if (password)
          tc_strcpy (pJob->data.tree_connect.password, password);
      else
          tc_memset (pJob->data.tree_connect.password, 0, 2);

      pJob->smb2_jobtype = jobTsmb2_tree_connect;

      rtsmb_cli_session_send_stalled_jobs (pSession);

      if (pSession->blocking_mode)
      {
          int r;
          r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
          return(r);
      }
      else
      {
          return INDEX_OF (pSession->jobs, pJob);
      }
  }
  int sid;
  byte *sharename;
  byte *password;

};

extern int do_smb2_tree_connect_worker(Smb2Session &Session)
{
  SmbTreeConnectWorker TreeConnectWorker( Session.sid(), Session.sharename(), Session.sharepassword());
  return TreeConnectWorker.go();
}


static int rtsmb2_cli_session_send_treeconnect_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_treeconnect (NetStreamBuffer &SendBuffer)
{
  int send_status;
  byte *path=0;
  rtsmb_char lshare_name [RTSMB_NB_NAME_SIZE + RTSMB_MAX_SHARENAME_SIZE + 4]; /* 3 for '\\'s and 1 for null */

  tc_memset (lshare_name, 0, sizeof (lshare_name));
//  if (tc_strcmp (SendBuffer.session_server_name(), (byte *) "") != 0)


  if (tc_strcmp (SendBuffer.session_pStream()->pSession->server_name, "") != 0)
  {
      lshare_name[0] = '\\';
      lshare_name[1] = '\\';
      rtsmb_util_ascii_to_rtsmb (
//        SendBuffer.session_server_name(),
        SendBuffer.session_pStream()->pSession->server_name,
        &lshare_name[2],
        CFG_RTSMB_USER_CODEPAGE);

      lshare_name [rtsmb_len (lshare_name)] = '\\';
  }
  rtsmb_util_ascii_to_rtsmb (SendBuffer.job_data()->tree_connect.share_name, &lshare_name[rtsmb_len (lshare_name)], CFG_RTSMB_USER_CODEPAGE);

  rtsmb_util_string_to_upper (lshare_name, CFG_RTSMB_USER_CODEPAGE);
  dword pathlen = (rtsmb_len(lshare_name)+1)*sizeof(rtsmb_char);
  dword variable_content_size = pathlen;  // Needs to be known before Smb2NBSSCmd is instantiated
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2TreeconnectCmd Smb2TreeconnectCmd;

  NetSmb2NBSSCmd<NetSmb2TreeconnectCmd> Smb2NBSSCmd(SMB2_TREE_CONNECT, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2TreeconnectCmd, variable_content_size);
  if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
  {
    Smb2TreeconnectCmd.StructureSize=   Smb2TreeconnectCmd.FixedStructureSize();
    Smb2TreeconnectCmd.Reserved = 0;
    Smb2TreeconnectCmd.PathOffset = (word) (OutSmb2Header.StructureSize()+Smb2TreeconnectCmd.StructureSize()-1);
    Smb2TreeconnectCmd.PathLength = pathlen;
    Smb2TreeconnectCmd.addto_variable_content(variable_content_size);  // we have to do this

    SendBuffer.job_data()->tree_connect.share_struct->connect_mid = (word) OutSmb2Header.MessageId();

    tc_memcpy(Smb2TreeconnectCmd.FixedStructureAddress()+Smb2TreeconnectCmd.FixedStructureSize()-1,lshare_name, Smb2TreeconnectCmd.PathLength());
    if (Smb2TreeconnectCmd.push_output(SendBuffer) != NetStatusOk)
       return RTSMB_CLI_SSN_RV_DEAD;


    Smb2NBSSCmd.flush();
  }
  return Smb2NBSSCmd.status;
}
static int rtsmb2_cli_session_receive_treeconnect (NetStreamBuffer &ReplyBuffer)
{
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2TreeconnectReply Smb2TreeconnectReply;
  NetSmb2NBSSReply<NetSmb2TreeconnectReply> Smb2NBSSReply(SMB2_TREE_CONNECT, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2TreeconnectReply);

//  NetWireword  Smb2TreeconnectReply.StructureSize;
//  NetWirebyte  Smb2TreeconnectReply.ShareType;
//  NetWirebyte  Smb2TreeconnectReply.Reserved;
//  NetWiredword Smb2TreeconnectReply.ShareFlags;
//  NetWiredword Smb2TreeconnectReply.Capabilities;
//  NetWiredword Smb2TreeconnectReply.MaximalAccess;

  PRTSMB_CLI_SESSION pSession ;
  PRTSMB_CLI_SESSION_SHARE pShare;
  int r = 0;

    for (r = 0; r < prtsmb_cli_ctx->max_shares_per_session; r++)
    {
      if (ReplyBuffer.session_shares()[r].state != CSSN_SHARE_STATE_UNUSED &&
       ReplyBuffer.session_shares()[r].connect_mid == (word) InSmb2Header.MessageId())
      {
        pShare = &ReplyBuffer.session_shares()[r];
        break;
      }
    }
   	if (!pShare)
    {
        return RTSMB_CLI_SSN_RV_MALFORMED;
    }

    pShare->tid = (word)InSmb2Header.TreeId();
    pShare->state = CSSN_SHARE_STATE_CONNECTED;
#ifdef STATE_DIAGNOSTICS
RTSMB_GET_SESSION_SHARE_STATE (CSSN_SHARE_STATE_CONNECTED);
#endif
    tc_strcpy (pShare->share_name, ReplyBuffer.job_data()->tree_connect.share_name);
    tc_strcpy (pShare->password, ReplyBuffer.job_data()->tree_connect.password);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_receive_tree_connect: Share found: Names == %s\n",pShare->share_name);

     /* We special-case a situation where we have just connected to the IPC$ share.  This
     means that we are now a fully-negotiated session and should alert our consumer. */
    if (tc_strcmp (pShare->share_name, "IPC$") == 0)
    {
      /* To denote this, we find the pseudo-job that was waiting on this and finish it. */
      for (r = 0; r < prtsmb_cli_ctx->max_jobs_per_session; r++)
      {
        if (ReplyBuffer.session_jobs()[r].state == CSSN_JOB_STATE_FAKE)
          rtsmb_cli_session_job_cleanup (ReplyBuffer.session_pSession(), &ReplyBuffer.session_jobs()[r], RTSMB_CLI_SSN_RV_OK);
      }
    }

    if (pSession->state == CSSN_STATE_RECOVERY_TREE_CONNECTING)
    {
     ReplyBuffer.session_pSession()->state = CSSN_STATE_RECOVERY_TREE_CONNECTED;
    }

    return  RTSMB_CLI_SSN_RV_OK;
}


// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.
c_smb2cmdobject treeconnectobject = { rtsmb2_cli_session_send_treeconnect,rtsmb2_cli_session_send_treeconnect_error_handler, rtsmb2_cli_session_receive_treeconnect, };
c_smb2cmdobject *get_treeconnectobject() { return &treeconnectobject;};

static int rtsmb2_cli_session_send_logoff_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_logoff (NetStreamBuffer &SendBuffer)
{
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2LogoffCmd    Smb2LogoffCmd;

  NetSmb2NBSSCmd<NetSmb2LogoffCmd> Smb2NBSSCmd(SMB2_LOGOFF, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2LogoffCmd, 0);
  OutSmb2Header.TreeId =  (ddword)SendBuffer.job_data()->tree_disconnect.tid;

  if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
  {
    if (Smb2LogoffCmd.push_output(SendBuffer) != NetStatusOk)
       return RTSMB_CLI_SSN_RV_DEAD;
    Smb2NBSSCmd.flush();
  }
  return Smb2NBSSCmd.status;
}
static int rtsmb2_cli_session_receive_logoff (NetStreamBuffer &ReplyBuffer)
{
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2LogoffReply  Smb2LogoffReply;
  NetSmb2NBSSReply<NetSmb2LogoffReply> Smb2NBSSReply(SMB2_LOGOFF, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2LogoffReply);
  return  RTSMB_CLI_SSN_RV_OK;
}

// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.
c_smb2cmdobject logoffobject = { rtsmb2_cli_session_send_logoff,rtsmb2_cli_session_send_logoff_error_handler, rtsmb2_cli_session_receive_logoff, };
c_smb2cmdobject *get_logoffobject() { return &logoffobject;};


static int rtsmb2_cli_session_send_disconnect_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_disconnect (NetStreamBuffer &SendBuffer)
{
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2DisconnectCmd    Smb2DisconnectCmd;
  NetSmb2NBSSCmd<NetSmb2DisconnectCmd> Smb2NBSSCmd(SMB2_TREE_DISCONNECT, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2DisconnectCmd, 0);

  OutSmb2Header.TreeId = (ddword) SendBuffer.job_data()->tree_disconnect.tid;

  if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
  {
    if (Smb2DisconnectCmd.push_output(SendBuffer) != NetStatusOk)
       return RTSMB_CLI_SSN_RV_DEAD;
    Smb2NBSSCmd.flush();
  }
  return Smb2NBSSCmd.status;
}
static int rtsmb2_cli_session_receive_disconnect (NetStreamBuffer &ReplyBuffer)
{
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2DisconnectReply  Smb2DisconnectReply;
  NetSmb2NBSSReply<NetSmb2DisconnectReply> Smb2NBSSReply(SMB2_TREE_DISCONNECT, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2DisconnectReply);
  return  RTSMB_CLI_SSN_RV_OK;
}

class SmbTreeDisconnectWorker {
public:
  SmbTreeDisconnectWorker(int _sid) { sid=_sid; };
  int go()
  {
     int r = rtsmb_cli_session_logoff_user(sid);
     if(r < 0) return 0;
     r = wait_on_job_cpp(sid, r);
     if(r < 0) return 0;
    return(1);
  }

private:
  int rtsmb_cli_session_logoff_user (int sid)
  {
      PRTSMB_CLI_SESSION_JOB pJob;
      PRTSMB_CLI_SESSION pSession;

      pSession = rtsmb_cli_session_get_session (sid);
      ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
      ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
      rtsmb_cli_session_update_timestamp (pSession);

      if (!(RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect)))
      {
          ASSURE (pSession->user.state == CSSN_USER_STATE_LOGGED_ON, RTSMB_CLI_SSN_RV_NO_USER);
      }
      pJob = rtsmb_cli_session_get_free_job (pSession);
      ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);

      pJob->smb2_jobtype = jobTsmb2_logoff;

      rtsmb_cli_session_send_stalled_jobs (pSession);

      if (pSession->blocking_mode)
      {
          int r;
          r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
          return(r);
      }
      else
      {
          return INDEX_OF (pSession->jobs, pJob);
    }
  }
  int sid;
};
extern int do_smb2_tree_disconnect_worker(Smb2Session &Session)
{
  SmbTreeDisconnectWorker TreeDisconnectWorker(Session.sid());
  return TreeDisconnectWorker.go();
}




// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.
c_smb2cmdobject disconnectobject = { rtsmb2_cli_session_send_disconnect,rtsmb2_cli_session_send_disconnect_error_handler, rtsmb2_cli_session_receive_disconnect, };
c_smb2cmdobject *get_disconnectobject() { return &disconnectobject;};
