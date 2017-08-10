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

// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()


#include "smb2defs.hpp"
#include "smb2socks.hpp"
#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "smb2wireobjects.hpp"
#include "mswireobjects.hpp"
#include "session.hpp"
#include "smb2socks.hpp"


// Can't embedd this in smb2session.hpp

static const word wildcard_type[]        = {'?', '?', '?', '?', '?', '\0'};

class SmbTreeConnectWorker {
public:
  SmbTreeConnectWorker(NewSmb2Session &_pSmb2Session)
  {
    pSmb2Session = &_pSmb2Session;
  }
  int go()
  {
    int r = rtsmb_cli_session_connect_share ();
    if(r < 0) return 0;
    return(1);
  }

private:
  NewSmb2Session *pSmb2Session;
  int share_number;
  int rtsmb_cli_session_connect_share (int _share_number=0)
  {

      share_number=_share_number;

      ASSURE (pSmb2Session->session_state() > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
      pSmb2Session->update_timestamp ();

      if (pSmb2Session->Shares[share_number].share_state != CSSN_SHARE_STATE_DIRTY)
          return RTSMB_CLI_SSN_RV_ALREADY_CONNECTED;

      pSmb2Session->Shares[share_number].share_state = CSSN_SHARE_STATE_CONNECTING;
      pSmb2Session->Shares[share_number].share_type = (const word *)wildcard_type; // disk_type;
//      pSmb2Session->Share[share_number].share_name was set by session.

      int r = rtsmb2_cli_session_send_treeconnect ();

      if (r == RTSMB_CLI_SSN_RV_OK)
        r = rtsmb2_cli_session_receive_treeconnect();

      return r;
  }

  int rtsmb2_cli_session_send_treeconnect ()
  {
    int send_status;
    byte *path=0;

    dword pathlen = (rtp_wcslen(pSmb2Session->Shares[share_number].share_name)+1)*sizeof(word);
    dword variable_content_size = pathlen;  // Needs to be known before Smb2NBSSCmd is instantiated
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2TreeconnectCmd Smb2TreeconnectCmd;

    NetSmb2NBSSCmd<NetSmb2TreeconnectCmd> Smb2NBSSCmd(SMB2_TREE_CONNECT, pSmb2Session->SendBuffer,OutNbssHeader,OutSmb2Header, Smb2TreeconnectCmd, variable_content_size);
    if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
    {
      Smb2TreeconnectCmd.StructureSize=   Smb2TreeconnectCmd.FixedStructureSize();
      Smb2TreeconnectCmd.Reserved = 0;
      Smb2TreeconnectCmd.PathOffset = (word) (OutSmb2Header.StructureSize()+Smb2TreeconnectCmd.StructureSize()-1);
      Smb2TreeconnectCmd.PathLength = pathlen;
      Smb2TreeconnectCmd.addto_variable_content(variable_content_size);  // we have to do this

      pSmb2Session->Shares[share_number].connect_mid =  OutSmb2Header.MessageId();

      memcpy(Smb2TreeconnectCmd.FixedStructureAddress()+Smb2TreeconnectCmd.FixedStructureSize()-1, pSmb2Session->Shares[share_number].share_name, Smb2TreeconnectCmd.PathLength());
      if (Smb2TreeconnectCmd.push_output(pSmb2Session->SendBuffer) != NetStatusOk)
        return RTSMB_CLI_SSN_RV_DEAD;
      Smb2NBSSCmd.flush();
    }
    return Smb2NBSSCmd.status;
  }
  int rtsmb2_cli_session_receive_treeconnect ()
  {
    dword in_variable_content_size = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2TreeconnectReply Smb2TreeconnectReply;
    NetSmb2NBSSReply<NetSmb2TreeconnectReply> Smb2NBSSReply(SMB2_TREE_CONNECT, pSmb2Session->ReplyBuffer, InNbssHeader,InSmb2Header, Smb2TreeconnectReply);

     int r = 0;
// HAVE TO PULL OR TIMEOUT
//    pShare = find_connecting_share(pSmb2Session, InSmb2Header.MessageId());
  //    for (r = 0; r < prtsmb_cli_ctx->max_shares_per_session; r++)
  //    {
  //      if (pSmb2Session->pSession()->shares[r].state != CSSN_SHARE_STATE_UNUSED &&
  //       pSmb2Session->pSession()->shares[r].connect_mid == (word) InSmb2Header.MessageId())
  //      {
  //        pShare = &pSmb2Session->pSession()->shares[r];
  //        break;
  //      }
  //    }

      pSmb2Session->Shares[share_number].tid =   InSmb2Header.TreeId();
      pSmb2Session->Shares[share_number].share_state = CSSN_SHARE_STATE_CONNECTED;

      if (pSmb2Session->session_state() == CSSN_STATE_RECOVERY_TREE_CONNECTING)
      {
        pSmb2Session->session_state(CSSN_STATE_RECOVERY_TREE_CONNECTED);
      }

      return  RTSMB_CLI_SSN_RV_OK;
  }

};

#if(0) // Need to adapt the code below for logoff support

static int rtsmb2_cli_session_send_logoff_error_handler(NetStreamBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_logoff (NetStreamBuffer &SendBuffer)
{
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2LogoffCmd    Smb2LogoffCmd;
  Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(SendBuffer);

  NetSmb2NBSSCmd<NetSmb2LogoffCmd> Smb2NBSSCmd(SMB2_LOGOFF, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2LogoffCmd, 0);

  OutSmb2Header.TreeId =  (ddword)pSmb2Session->job_data()->tree_disconnect.tid;

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

  Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(SendBuffer);

  OutSmb2Header.TreeId = (ddword) pSmb2Session->job_data()->tree_disconnect.tid;

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

#endif
