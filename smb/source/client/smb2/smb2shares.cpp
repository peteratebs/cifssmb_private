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


#include "smb2clientincludes.hpp"


// Can't embedd this in smb2session.hpp

static const word wildcard_type[]        = {'?', '?', '?', '?', '?', '\0'};

class SmbTreeConnectWorker: private smb_diagnostics {
public:
  SmbTreeConnectWorker(Smb2Session &_pSmb2Session,int _sharenumber)
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
    pSmb2Session = &_pSmb2Session;
    share_number = _sharenumber;
  }
  int go()
  {
    int r = rtsmb_cli_session_connect_share ();
    if(r < 0) return 0;
    return(1);
  }

private:
  Smb2Session *pSmb2Session;
  int share_number;
  bool rtsmb_cli_session_connect_share()
  {
    if (pSmb2Session->session_state() <=  CSSN_STATE_DEAD)
    {
      pSmb2Session->diag_text_warning("connect_share command called but session is dead");
      return false;
    }
     if (pSmb2Session->Shares[share_number].share_state != CSSN_SHARE_STATE_DIRTY)
    {
      pSmb2Session->diag_text_warning("connect_share command called share is already connected");
      return false;
    }

     pSmb2Session->Shares[share_number].share_state = CSSN_SHARE_STATE_CONNECTING;
     pSmb2Session->Shares[share_number].share_type = (const word *)wildcard_type; // disk_type;
//      pSmb2Session->Share[share_number].share_name was set by session.

     bool r = rtsmb2_cli_session_send_treeconnect ();

     if (r)
       r = rtsmb2_cli_session_receive_treeconnect();

      return r;
  }

  bool rtsmb2_cli_session_send_treeconnect ()
  {
    int send_status;
    byte *path=0;

    setSessionSigned(false);      // Should enable signing here and everythng should work, but signing is broken

    dword variable_content_size = (rtp_wcslen(pSmb2Session->Shares[share_number].share_name))*sizeof(word);
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2TreeconnectCmd Smb2TreeconnectCmd;

    NetSmb2NBSSCmd<NetSmb2TreeconnectCmd> Smb2NBSSCmd(SMB2_TREE_CONNECT, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2TreeconnectCmd, variable_content_size);

    Smb2TreeconnectCmd.StructureSize=   Smb2TreeconnectCmd.FixedStructureSize();
    Smb2TreeconnectCmd.Reserved = 0;
    Smb2TreeconnectCmd.PathOffset = (word) (OutSmb2Header.StructureSize()+Smb2TreeconnectCmd.StructureSize()-1);
    Smb2TreeconnectCmd.PathLength = variable_content_size;

    pSmb2Session->Shares[share_number].connect_mid =  OutSmb2Header.MessageId();

    Smb2TreeconnectCmd.copyto_variable_content(pSmb2Session->Shares[share_number].share_name, variable_content_size);  // we have to do this


    return Smb2NBSSCmd.flush();
  }
  bool rtsmb2_cli_session_receive_treeconnect ()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2TreeconnectReply Smb2TreeconnectReply;

     // Pull enough for the fixed part and then map pointers toi input buffer
//    NetStatus r = pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2TreeconnectReply.PackedStructureSize(), bytes_pulled);
    NetStatus r = pSmb2Session->ReplyBuffer.pull_nbss_frame_checked("TREECONNECT", Smb2TreeconnectReply.FixedStructureSize(), bytes_pulled);
    if (r != NetStatusOk)
    {
      pSmb2Session->diag_text_warning("receive_treeconnect command failed pulling from the socket");
      return false;
    }

    NetSmb2NBSSReply<NetSmb2TreeconnectReply> Smb2NBSSReply(SMB2_TREE_CONNECT, pSmb2Session, InNbssHeader,InSmb2Header, Smb2TreeconnectReply);

    InNbssHeader.show_contents();
    InSmb2Header.show_contents();

    pSmb2Session->Shares[share_number].tid =   InSmb2Header.TreeId();
    pSmb2Session->Shares[share_number].share_state = CSSN_SHARE_STATE_CONNECTED;

    if (pSmb2Session->session_state() == CSSN_STATE_RECOVERY_TREE_CONNECTING)
    {
      pSmb2Session->session_state(CSSN_STATE_RECOVERY_TREE_CONNECTED);
    }
    return true;
  }

};

extern int do_smb2_tree_connect_worker(Smb2Session &Session,int sharenumber)
{
  SmbTreeConnectWorker TreeConnectWorker(Session,sharenumber);
  return TreeConnectWorker.go();
}

#if(0) // Need to adapt the code below for logoff support

static int rtsmb2_cli_session_send_logoff_error_handler(NetStreamInputBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_logoff (NetStreamInputBuffer &SendBuffer)
{
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2LogoffCmd    Smb2LogoffCmd;
  Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(SendBuffer);

  NetSmb2NBSSCmd<NetSmb2LogoffCmd> Smb2NBSSCmd(SMB2_LOGOFF, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2LogoffCmd, 0);

  OutSmb2Header.TreeId =  (ddword)pSmb2Session->job_data()->tree_disconnect.tid;
  Smb2NBSSCmd.flush();
  return Smb2NBSSCmd.status;
}
static bool rtsmb2_cli_session_receive_logoff (NetStreamInputBuffer &ReplyBuffer)
{
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2LogoffReply  Smb2LogoffReply;
  NetSmb2NBSSReply<NetSmb2LogoffReply> Smb2NBSSReply(SMB2_LOGOFF, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2LogoffReply);
  return  true;
}

// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.
c_smb2cmdobject logoffobject = { rtsmb2_cli_session_send_logoff,rtsmb2_cli_session_send_logoff_error_handler, rtsmb2_cli_session_receive_logoff, };
c_smb2cmdobject *get_logoffobject() { return &logoffobject;};


static int rtsmb2_cli_session_send_disconnect_error_handler(NetStreamInputBuffer &Buffer) {return RTSMB_CLI_SSN_RV_INVALID_RV;}

static int rtsmb2_cli_session_send_disconnect (NetStreamInputBuffer &SendBuffer)
{
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2DisconnectCmd    Smb2DisconnectCmd;
  NetSmb2NBSSCmd<NetSmb2DisconnectCmd> Smb2NBSSCmd(SMB2_TREE_DISCONNECT, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2DisconnectCmd, 0);

  Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(SendBuffer);

  OutSmb2Header.TreeId = (ddword) pSmb2Session->job_data()->tree_disconnect.tid;

  Smb2NBSSCmd.flush();
  return Smb2NBSSCmd.status;
}
static int rtsmb2_cli_session_receive_disconnect (NetStreamInputBuffer &ReplyBuffer)
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
