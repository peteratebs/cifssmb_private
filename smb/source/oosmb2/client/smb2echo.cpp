//
// smb2echo.cpp -
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

#include "smb2clientincludes.hpp"

class SmbEchoWorker: private smb_diagnostics {
public:
  SmbEchoWorker(Smb2Session &_pSmb2Session)
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
    pSmb2Session = &_pSmb2Session;
  }
  bool go()
  {
    return rtsmb_cli_session_echo();
  }

private:
  Smb2Session *pSmb2Session;

  bool rtsmb_cli_session_echo()
  {
    if (pSmb2Session->session_state() <=  CSSN_STATE_DEAD)
    {
      pSmb2Session->diag_text_warning("echo command called but session is dead");
      return false;
    }
     bool r = rtsmb2_cli_session_send_echo();
     if (r)
       r = rtsmb2_cli_session_receive_echo();
      return r;
  }

  bool rtsmb2_cli_session_send_echo ()
  {
    int send_status;
    dword variable_content_size = 0;
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2EchoCmd Smb2EchoCmd;

    NetSmb2NBSSSendCmd<NetSmb2EchoCmd> Smb2NBSSCmd(SMB2_ECHO, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2EchoCmd, variable_content_size);
    Smb2EchoCmd.StructureSize = Smb2EchoCmd.FixedStructureSize();
    return Smb2NBSSCmd.flush();
  }
  bool rtsmb2_cli_session_receive_echo()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2EchoReply  Smb2EchoReply;
    bool rv = false;
     // Pull  the fixed part
    NetStatus r = pSmb2Session->RecvBuffer.pull_nbss_frame_checked("ECHO", Smb2EchoReply.PackedStructureSize(), bytes_pulled);
    if (r == NetStatusOk)
      rv = true;
    return rv;
  }
};
extern  bool do_smb2_echo_worker(Smb2Session &Session)
{
  SmbEchoWorker EchoWorker(Session);
  bool r = EchoWorker.go();
  return r;
}
