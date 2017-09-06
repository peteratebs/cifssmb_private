
//
// smb2dirents.cpp -
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

Smb2Session *smb2_reply_buffer_to_session(NetStreamInputBuffer &RecvBuffer);
extern int PassDirscanToShell(void *pBuffer);


// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()



//int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);


static const byte zero16[16] = {0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0,0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0};         // zeros

class SmbQuerydirectoryWorker {
public:
  SmbQuerydirectoryWorker(Smb2Session &_pSmb2Session,int _sharenumber, int _filenumber, word *_pattern)
  {
    pSmb2Session = &_pSmb2Session;
    share_number = _sharenumber;
    file_number  = _filenumber;
    pattern = _pattern;
    has_continue          = false;
  };
  bool go()
  {
    return do_ls_command_worker();
  }


private:
  Smb2Session *pSmb2Session;
  int share_number;
  int file_number;
  word *pattern;
  bool has_continue;
  bool rtsmb2_cli_session_recv_querydirectory ()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled = 0;
    dword bytes_consumed = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2QuerydirectoryReply Smb2QuerydirectoryReply;
    NetStatus r;

    r = pSmb2Session->RecvBuffer.pull_nbss_frame_checked("QUERY", Smb2QuerydirectoryReply.PackedStructureSize(), bytes_pulled);
    if (r != NetStatusOk && r != NetStatusServerErrorStatus)
    {
      return false;
    }
    NetSmb2NBSSRecvReply<NetSmb2QuerydirectoryReply> Smb2NBSSReply(SMB2_QUERY_DIRECTORY, pSmb2Session, InNbssHeader,InSmb2Header, Smb2QuerydirectoryReply);

    if (r == NetStatusServerErrorStatus)
    {
      bool rv = false;
      has_continue = false;
      if (InSmb2Header.Status_ChannelSequenceReserved() == SMB2_STATUS_NO_MORE_FILES)
        rv = true;
      return rv;
    }

    pSmb2Session->RecvBuffer.consume_bytes(bytes_pulled);
    if (InSmb2Header.Status_ChannelSequenceReserved() == SMB2_STATUS_NO_MORE_FILES)
    {
      has_continue = false;
    }
    else
     has_continue = true;

    dword total_bytes_left     = 0;  // bytes left in the buffer
    dword payload_bytes_left   = 0;  // iterator for the directory content

    if (Smb2QuerydirectoryReply.OutputBufferOffset()!=0)  // If zero it means we are empty. Confused why recv hangs when I try to read all bytes on last message (including the 1 byte buff that is zero filled by the server)
    { // Skip to the content if we have to
      int t = (Smb2QuerydirectoryReply.OutputBufferOffset()+InNbssHeader.FixedStructureSize())-bytes_pulled;  // Advance to the variable part if needed
      if (t>0)
      {
        pSmb2Session->diag_text_warning("receive_querydirectory content was offset ??");
        pSmb2Session->RecvBuffer.consume_bytes(t);
        bytes_pulled += t;
      }
      // read in the content which will fit in our buffer if the server obneyed our max transaction size
      dword payload_bytes_pulled = 0;
      total_bytes_left = (InNbssHeader.nbss_packet_size()+4)-bytes_pulled;
      if (pSmb2Session->RecvBuffer.pull_nbss_data(total_bytes_left,payload_bytes_pulled)!=NetStatusOk)
      {
        pSmb2Session->diag_text_warning("receive_querydirectory command failed pulling variable part from the socket");
        return false;
      }
      bytes_pulled         += payload_bytes_pulled;
      payload_bytes_left   = Smb2QuerydirectoryReply.OutputBufferLength();
    }
    if (payload_bytes_left > total_bytes_left)
    {
      pSmb2Session->diag_text_warning("receive_querydirectory SMB2_QUERY_DIRECTORY Truncated payload from %d to %d", payload_bytes_left, total_bytes_left);
      payload_bytes_left = total_bytes_left;
    }
    // call back to the application layer with each item
    if (payload_bytes_left)
    {
      dword bytes_ready;
      byte *pdata = pSmb2Session->RecvBuffer.buffered_data_pointer(bytes_ready);
      while (bytes_ready)
      {
        int next_offset;
        next_offset = PassDirscanToShell(pdata);
        if (next_offset>0 && next_offset <= bytes_ready)
        {
          pSmb2Session->RecvBuffer.consume_bytes(next_offset);
          pdata = pSmb2Session->RecvBuffer.buffered_data_pointer(bytes_ready);
        }
        else
        {
          if (next_offset < 0) // zero is end, < 0 is canceled the request
            has_continue = false;
          break;
        }
      }
    }
    return true;
  }

  bool rtsmb2_cli_session_send_querydirectory ()
  {
    dword variable_content_size = 0;  // Needs to be known before Smb2NBSSCmd is instantiated
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2QuerydirectoryCmd Smb2QuerydirectoryCmd;
    if (pattern)
      variable_content_size   = (word)rtp_wcslen_bytes (pattern);
    else
      variable_content_size  = 0;

    NetSmb2NBSSSendCmd<NetSmb2QuerydirectoryCmd> Smb2NBSSCmd(SMB2_QUERY_DIRECTORY, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2QuerydirectoryCmd, variable_content_size);
    OutSmb2Header.TreeId = pSmb2Session->Shares[share_number].tid;
    Smb2QuerydirectoryCmd.StructureSize        =  Smb2QuerydirectoryCmd.FixedStructureSize();
    Smb2QuerydirectoryCmd.FileInformationClass    = SMB2_QUERY_FileIdBothDirectoryInformation; // SMB2_QUERY_FileNamesInformation;
    Smb2QuerydirectoryCmd.FileIndex               = 0;
    if (has_continue)
      Smb2QuerydirectoryCmd.Flags                   = 0; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;
    else
      Smb2QuerydirectoryCmd.Flags                    = (byte)Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS;
//    Smb2QuerydirectoryCmd.Flags                    = Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

    Smb2QuerydirectoryCmd.FileId                  = pSmb2Session->Files[file_number].get_file_id();
    Smb2QuerydirectoryCmd.FileNameOffset          = (word) (OutSmb2Header.StructureSize()+Smb2QuerydirectoryCmd.VariableContentOffset());

    if (pattern)
      Smb2QuerydirectoryCmd.FileNameLength   = (word)rtp_wcslen_bytes(pattern);
    else
      Smb2QuerydirectoryCmd.FileNameLength   = 0;

    Smb2QuerydirectoryCmd.OutputBufferLength      = RTSMB_CFG_MAX_CLIENT_TRANSACTION_SIZE;

    if (Smb2QuerydirectoryCmd.FileNameLength() != 0)
    {
      Smb2QuerydirectoryCmd.copyto_variable_content( pattern, Smb2QuerydirectoryCmd.FileNameLength());
      return Smb2NBSSCmd.flush();
    }
    return false;
  }

  bool do_ls_command_worker()
  {
    int smb2_ls_context;  // not used yet
    bool doLoop = false;
    bool r = false;
    do
    {
        r = rtsmb2_cli_session_send_querydirectory();
        if (r)
          r = rtsmb2_cli_session_recv_querydirectory ();

    } while(r && has_continue);
    return r;
  }
};

extern bool do_smb2_cli_querydirectory_worker(Smb2Session &Session,int sharenumber, int filenumber, word *pattern);
extern bool do_smb2_cli_querydirectory_worker(Smb2Session &Session,int sharenumber, int filenumber, word *pattern)
{
  SmbQuerydirectoryWorker QuerydirectoryWorker(Session, sharenumber, filenumber, pattern);
  return QuerydirectoryWorker.go();
}
