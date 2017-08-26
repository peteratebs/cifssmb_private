
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

Smb2Session *smb2_reply_buffer_to_session(NetStreamInputBuffer &ReplyBuffer);
extern int FormatDirscanToDstat(void *pBuffer);


// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()




static inline int smb2_ls_function(void *devContext, byte *pData, int size)
{
  int esize;
  esize = FormatDirscanToDstat(pData);
  cout << " We got ls function with size" << endl;
  return esize>0?esize:size;
}

//int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);


static const byte zero16[16] = {0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0,0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0};         // zeros

class SmbQuerydirectoryWorker {
public:
  SmbQuerydirectoryWorker(Smb2Session &_pSmb2Session,int _sharenumber, word *_pattern)
  {
    pSmb2Session = &_pSmb2Session;
    share_number = _sharenumber;
    pattern = _pattern;
    has_continue          = false;
//    sink_Fn               = smb2_ls_function; // HEREHERE NOT DONE
//    sink_parameters       = 0;  // HEREHERE NOT DONE
//    wire_socket           = 0; // HEREHERE NOT DONE
  };
  int go()
  {
    return do_ls_command_worker();
  }

private:
  Smb2Session *pSmb2Session;
  int share_number;
  word *pattern;
  bool has_continue;
  int rtsmb2_cli_session_send_querydirectory ()
  {
    dword variable_content_size = 0;  // Needs to be known before Smb2NBSSCmd is instantiated
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2QuerydirectoryCmd Smb2QuerydirectoryCmd;

    setSessionSigned(true);

    if (pattern)
      variable_content_size   = (word)rtp_wcslen_bytes (pattern);
    else
      variable_content_size  = 0;

    pSmb2Session->SendBuffer.stream_buffer_mid = pSmb2Session->next_message_id();
    NetSmb2NBSSCmd<NetSmb2QuerydirectoryCmd> Smb2NBSSCmd(SMB2_QUERY_DIRECTORY, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2QuerydirectoryCmd, variable_content_size);
    if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
    {
      OutSmb2Header.TreeId = pSmb2Session->Shares[share_number].tid;
      Smb2QuerydirectoryCmd.StructureSize        =  Smb2QuerydirectoryCmd.FixedStructureSize();
      Smb2QuerydirectoryCmd.FileInformationClass    = SMB2_QUERY_FileIdBothDirectoryInformation; // SMB2_QUERY_FileNamesInformation;
      Smb2QuerydirectoryCmd.FileIndex               = 0;
      if (has_continue)
        Smb2QuerydirectoryCmd.Flags                   = 0; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;
      else
        Smb2QuerydirectoryCmd.Flags                    = (byte)Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS;
  //    Smb2QuerydirectoryCmd.Flags                    = Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

      cout_log(LL_JUNK)  << "YOYO Flags1: " << (int)Smb2QuerydirectoryCmd.Flags() << "Flags2: " << (int)Smb2QuerydirectoryCmd.Flags() << endl;

      Smb2QuerydirectoryCmd.FileId                  = (byte*)zero16; // SMB2FileId;
      Smb2QuerydirectoryCmd.FileNameOffset          = (word) (OutSmb2Header.StructureSize()+Smb2QuerydirectoryCmd.StructureSize()-1);

      if (pattern)
        Smb2QuerydirectoryCmd.FileNameLength   = (word)rtp_wcslen_bytes(pattern);
      else
        Smb2QuerydirectoryCmd.FileNameLength   = 0;
     /* Tell the server that the maximum we can accept is what remains in our read buffer */
     // Wrong
      Smb2QuerydirectoryCmd.OutputBufferLength      = (word)1400;

      if (Smb2QuerydirectoryCmd.FileNameLength() != 0)
      {
        tc_memcpy(Smb2QuerydirectoryCmd.FixedStructureAddress()+Smb2QuerydirectoryCmd.FixedStructureSize()-1, pattern, Smb2QuerydirectoryCmd.FileNameLength());
        Smb2QuerydirectoryCmd.addto_variable_content(Smb2QuerydirectoryCmd.FileNameLength());
        byte signature[16];
        // Clear the signaturte for calculating over or if it's disabled
        memset (signature, 0 , 16);
        OutSmb2Header.Signature = signature;
        if (checkSessionSigned())
        {
          size_t length=0;
          byte *signme = Smb2NBSSCmd.RangeRequiringSigning(length);
diag_printf_fn(DIAG_INFORMATIONAL, "XXXXX Signing nbytes: %d\n", length);
diag_dump_bin_fn(DIAG_INFORMATIONAL,"session key is: ", pSmb2Session->session_key(), 16);
          calculate_smb2_signing_key((void *)pSmb2Session->session_key(), (void *)signme, length, (unsigned char *)signature);
          OutSmb2Header.Signature = signature;
        }
        if (Smb2QuerydirectoryCmd.push_output(pSmb2Session->SendBuffer) != NetStatusOk)
          return RTSMB_CLI_SSN_RV_DEAD;
        Smb2NBSSCmd.flush();
      }
    }
    return Smb2NBSSCmd.status;
  }

  int do_ls_command_worker()
  {
    int smb2_ls_context;  // not used yet
    bool doLoop = false;
    do
    {
        NEWRTSMB_CLI_SESSION_DSTAT dstat1;
        // pass callbacks to smb2 stream layer through the stat structure
        dstat1.sink_Fn         = smb2_ls_function;
        dstat1.sink_parameters = (void *) &smb2_ls_context;
        int r1;
        r1 = rtsmb2_cli_session_send_querydirectory ();
//        r1 = rtsmb_cli_session_find_first(sid, (char * ) sharename, (char *) pattern, &dstat1);
        if(r1 < 0)
        {
          return 1;
        }
#if (0)
        // This is the SMB2 flavor of search continue
// Cheating, using RTSMB_CLI_SSN_SMB2_COMPUND_INPUT to assume he wants another
// Should really be RTSMB_CLI_SSN_SMB2_QUERY_MORE
//        while (r1 == RTSMB_CLI_SSN_SMB2_QUERY_MORE)
        while (r1 == RTSMB_CLI_SSN_SMB2_COMPUND_INPUT)
        {
            r1 = rtsmb_cli_session_find_next(sid, &dstat1);
            if(r1 < 0)
            {
              return 1;
            }
        }
        rtsmb_cli_session_find_close(sid, &dstat1);
#endif
    } while(doLoop);
    return 0;
  }
};

extern int do_smb2_cli_querydirectory_worker(Smb2Session &Session,int share_number, word *pattern);
extern int do_smb2_cli_querydirectory_worker(Smb2Session &Session,int sharenumber, word *pattern)
{
  SmbQuerydirectoryWorker QuerydirectoryWorker(Session, sharenumber, pattern);
  return QuerydirectoryWorker.go();
}

#if(0)

int rtsmb2_cli_session_send_querydirectory_method (NetStreamOutputBuffer &SendBuffer)
{
  dword variable_content_size = 0;  // Needs to be known before Smb2NBSSCmd is instantiated
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2QuerydirectoryCmd Smb2QuerydirectoryCmd;

  Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(SendBuffer);

  if (pattern)
    variable_content_size   = (word)rtp_wcslen_bytes (pattern);
  else
    variable_content_size  = 0;


  NetSmb2NBSSCmd<NetSmb2QuerydirectoryCmd> Smb2NBSSCmd(SMB2_QUERY_DIRECTORY, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2QuerydirectoryCmd, variable_content_size);

  if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
  {
    OutSmb2Header.TreeId = tid(); // (ddword) pSmb2Session->job_data()->findsmb2.search_struct->share_struct->tid;
    Smb2QuerydirectoryCmd.StructureSize        =  Smb2QuerydirectoryCmd.FixedStructureSize();
    Smb2QuerydirectoryCmd.FileInformationClass    = SMB2_QUERY_FileIdBothDirectoryInformation; // SMB2_QUERY_FileNamesInformation;
    Smb2QuerydirectoryCmd.FileIndex               = 0;
    Smb2QuerydirectoryCmd.Flags                   = 0; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

    if (!has_continue)
      Smb2QuerydirectoryCmd.Flags                    = (byte)Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS;
//    Smb2QuerydirectoryCmd.Flags                    = Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

    cout_log(LL_JUNK)  << "YOYO Flags1: " << (int)Smb2QuerydirectoryCmd.Flags() << "Flags2: " << (int)Smb2QuerydirectoryCmd.Flags() << endl;

    Smb2QuerydirectoryCmd.FileId =  SMB2FileId;
    Smb2QuerydirectoryCmd.FileNameOffset          = (word) (OutSmb2Header.StructureSize()+Smb2QuerydirectoryCmd.StructureSize()-1);

    if (pattern)
      Smb2QuerydirectoryCmd.FileNameLength   = (word)rtp_wcslen_bytes(pattern);
    else
      Smb2QuerydirectoryCmd.FileNameLength   = 0;
   /* Tell the server that the maximum we can accept is what remains in our read buffer */
   // Wrong
    Smb2QuerydirectoryCmd.OutputBufferLength      = (word)1400;

    if (Smb2QuerydirectoryCmd.FileNameLength() != 0)
    {
      tc_memcpy(Smb2QuerydirectoryCmd.FixedStructureAddress()+Smb2QuerydirectoryCmd.FixedStructureSize()-1, pattern, Smb2QuerydirectoryCmd.FileNameLength());
      Smb2QuerydirectoryCmd.addto_variable_content(Smb2QuerydirectoryCmd.FileNameLength());
      if (Smb2QuerydirectoryCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
      Smb2NBSSCmd.flush();
    }
  }
  return Smb2NBSSCmd.status;
}

int rtsmb2_cli_session_receive_querydirectory (NetStreamInputBuffer &ReplyBuffer)
{
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2QuerydirectoryReply Smb2QuerydirectoryReply;
  NetStatus s = NetStatusOk;

  // The headers are actually in memory already but this should go before instantiate in case we
  NetSmb2NBSSReply<NetSmb2QuerydirectoryReply> Smb2NBSSReply(SMB2_QUERY_DIRECTORY, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2QuerydirectoryReply);

  Smb2Session *pSmb2Session = smb2_reply_buffer_to_session(ReplyBuffer);

  if (InSmb2Header.Status_ChannelSequenceReserved() == SMB2_STATUS_INFO_LENGTH_MISMATCH)
  {
     cout_log(LL_JUNK)  << "qeply status1 got missmatch: " << endl;

  }
  if (InSmb2Header.Status_ChannelSequenceReserved() == SMB2_STATUS_NO_MORE_FILES)
  {
     cout_log(LL_JUNK)  << "qeply status1 got no more files: " << endl;
     return RTSMB_CLI_SSN_SMB2_QUERY_FINISHED;
  }


  cout_log(LL_JUNK)  << "YOYO Qreply status1: " << std::hex << (dword)InSmb2Header.Status_ChannelSequenceReserved() << "no more :" << std::hex << (dword) SMB2_STATUS_NO_MORE_FILES << endl;
  cout_log(LL_JUNK)  << "YOYO mismatch==: " << std::hex << (dword)SMB2_STATUS_INFO_LENGTH_MISMATCH << endl;

  // bind to the socket and toss the buffer content we already used.
  StreamBufferDataSource SocketSource;
  struct SocketContext sockContext;
  sockContext.socket = wire_socket;
  SocketSource.SourceFromDevice (socket_source_function, (void *)&sockContext);
  ReplyBuffer.attach_source(SocketSource);
  // pull the bytes we processed already .
  // easier to do outside the template for now.
//  s = ReplyBuffer.toss_input(InSmb2Header.FixedStructureSize()+Smb2QuerydirectoryReply.FixedStructureSize()-1);
  if (s != NetStatusOk)
  {
    return RTSMB_CLI_SSN_RV_DEAD;
  }

  // Now sink the rest to to the shell callback
  DataSinkDevtype ShellCallbackSink(
     sink_Fn,
     sink_parameters);
  ReplyBuffer.attach_sink(&ShellCallbackSink);

  dword bytes_pulled=0;
  dword byte_count = Smb2QuerydirectoryReply.OutputBufferLength();
//  ReplyBuffer.attach_sink(&ShellCallbackSink);
  while (bytes_pulled < byte_count && s==NetStatusOk)
  {
    dword _bytes_pulled;
// XX    s = ReplyBuffer.pull_input(byte_count,_bytes_pulled);
    if (s==NetStatusOk)
      bytes_pulled += _bytes_pulled;
  }
  // Remember the search ID
//  pSmb2Session->job_data()->findsmb2.answering_dstat->sid = pSmb2Session->job_data()->findsmb2.search_struct->sid;
  if (InSmb2Header.NextCommand())
  {
    return RTSMB_CLI_SSN_SMB2_QUERY_MORE;
  }
  return  RTSMB_CLI_SSN_RV_OK;
}
};


extern int do_smb2_querydirectory_worker(int sid,  byte *share_name, word *pattern)
{
  SmbQuerydirectoryWorker QuerydirectoryWorker(sid, share_name, pattern);
  return QuerydirectoryWorker.go();
}

#endif
