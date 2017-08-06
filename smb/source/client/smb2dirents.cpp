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
#include "smb2utils.hpp"
#include "smb2wireobjects.hpp"
#include "smb2session.hpp"
#include "mswireobjects.hpp"


// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()



extern "C" void rtsmb_cli_session_job_close (PRTSMB_CLI_SESSION_JOB pJob);
extern "C" int FormatDirscanToDstat(void *pBuffer);
extern "C" int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);

static inline int smb2_ls_function(void *devContext, byte *pData, int size)
{
  int esize;
  esize = FormatDirscanToDstat(pData);
  cout << " We got ls function with size" << endl;
  return esize>0?esize:size;
}

//int  rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);


class SmbQuerydirectoryWorker {
public:
  SmbQuerydirectoryWorker(int _sid,  byte *_sharename, byte *_pattern)
  {
   ENSURECSTRINGSAFETY(_sharename); ENSURECSTRINGSAFETY(_pattern);
   sid=_sid;sharename=_sharename;pattern=_pattern;
  };
  int go()
  {
    return do_ls_command_worker();
  }

private:
  int sid;
  byte *sharename;
  byte *pattern;
  int do_ls_command_worker()
  {
    RTSMB_CLI_SESSION_DSTAT dstat1;
    int smb2_ls_context;  // not used yet
    bool doLoop = false;
    do
    {
        // pass callbacks to smb2 stream layer through the stat structure
        dstat1.sink_function = (void *) smb2_ls_function;
        dstat1.sink_parameters = (void *) &smb2_ls_context;
        int r1;
        r1 = rtsmb_cli_session_find_first(sid, (PFCHAR) sharename, (PFCHAR)pattern, &dstat1);
        if(r1 < 0)
        {
          return 1;
        }
        r1 = wait_on_job_cpp(sid, r1);
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
            r1 = wait_on_job_cpp(sid, r1);
        }

        rtsmb_cli_session_find_close(sid, &dstat1);
    } while(doLoop);
    return 0;
}


};


extern int do_smb2_cli_query_worker(Smb2Session &Session)
{
  SmbQuerydirectoryWorker QuerydirectoryWorker(Session.sid(), Session.sharename(), Session.searchpattern());
  return QuerydirectoryWorker.go();
}


extern "C" int do_smb2_querydirectory_worker(int sid,  byte *share_name, byte *pattern)
{
  SmbQuerydirectoryWorker QuerydirectoryWorker(sid, share_name, pattern);
  return QuerydirectoryWorker.go();
}

static int rtsmb2_cli_session_send_querydirectory_error_handler(NetStreamBuffer &Buffer) {
    cout_log(LL_JUNK)  << "Yo got error :" << endl;
    return RTSMB_CLI_SSN_RV_INVALID_RV;
}


static int rtsmb2_cli_session_send_querydirectory (NetStreamBuffer &SendBuffer)
{
  dword variable_content_size = 0;  // Needs to be known before Smb2NBSSCmd is instantiated
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;
  NetSmb2QuerydirectoryCmd Smb2QuerydirectoryCmd;
  if (SendBuffer.job_data()->findsmb2.pattern)
    variable_content_size   = (word)rtsmb_len (SendBuffer.job_data()->findsmb2.pattern)*sizeof(rtsmb_char);
  else
    variable_content_size  = 0;


  NetSmb2NBSSCmd<NetSmb2QuerydirectoryCmd> Smb2NBSSCmd(SMB2_QUERY_DIRECTORY, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2QuerydirectoryCmd, variable_content_size);

  if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
  {
    OutSmb2Header.TreeId = (ddword) SendBuffer.job_data()->findsmb2.search_struct->share_struct->tid;
    Smb2QuerydirectoryCmd.StructureSize        =  Smb2QuerydirectoryCmd.FixedStructureSize();
    Smb2QuerydirectoryCmd.FileInformationClass    = SMB2_QUERY_FileIdBothDirectoryInformation; // SMB2_QUERY_FileNamesInformation;
    Smb2QuerydirectoryCmd.FileIndex               = 0;
    Smb2QuerydirectoryCmd.Flags                   = 0; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

    if (SendBuffer.job_data()->findsmb2.search_struct->has_continue==FALSE)
      Smb2QuerydirectoryCmd.Flags                    = (byte)Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS;
//    Smb2QuerydirectoryCmd.Flags                    = Smb2QuerydirectoryCmd.Flags()|SMB2_QUERY_RESTART_SCANS; // SMB2_QUERY_SMB2_INDEX_SPECIFIED;

    cout_log(LL_JUNK)  << "YOYO Flags1: " << (int)Smb2QuerydirectoryCmd.Flags() << "Flags2: " << (int)Smb2QuerydirectoryCmd.Flags() << endl;

    Smb2QuerydirectoryCmd.FileId =  SendBuffer.job_data()->findsmb2.search_struct->SMB2FileId;
    Smb2QuerydirectoryCmd.FileNameOffset          = (word) (OutSmb2Header.StructureSize()+Smb2QuerydirectoryCmd.StructureSize()-1);

    if (SendBuffer.job_data()->findsmb2.pattern)
      Smb2QuerydirectoryCmd.FileNameLength   = (word)rtsmb_len (SendBuffer.job_data()->findsmb2.pattern)*sizeof(rtsmb_char);
    else
      Smb2QuerydirectoryCmd.FileNameLength   = 0;
   /* Tell the server that the maximum we can accept is what remains in our read buffer */
   // Wrong
    Smb2QuerydirectoryCmd.OutputBufferLength      = (word)1400;

    if (Smb2QuerydirectoryCmd.FileNameLength() != 0)
    {
      tc_memcpy(Smb2QuerydirectoryCmd.FixedStructureAddress()+Smb2QuerydirectoryCmd.FixedStructureSize()-1, SendBuffer.job_data()->findsmb2.pattern, Smb2QuerydirectoryCmd.FileNameLength());
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "rtsmb2_cli_session_send_find_first: Call encode \n");
      Smb2QuerydirectoryCmd.addto_variable_content(Smb2QuerydirectoryCmd.FileNameLength());
      if (Smb2QuerydirectoryCmd.push_output(SendBuffer) != NetStatusOk)
         return RTSMB_CLI_SSN_RV_DEAD;
      Smb2NBSSCmd.flush();
    }
  }
  return Smb2NBSSCmd.status;
}



static int rtsmb2_cli_session_receive_querydirectory (NetStreamBuffer &ReplyBuffer)
{
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2QuerydirectoryReply Smb2QuerydirectoryReply;
  NetStatus s = NetStatusOk;

  // The headers are actually in memory already but this should go before instantiate in case we
  NetSmb2NBSSReply<NetSmb2QuerydirectoryReply> Smb2NBSSReply(SMB2_QUERY_DIRECTORY, ReplyBuffer, InNbssHeader,InSmb2Header, Smb2QuerydirectoryReply);

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
  sockContext.socket = ReplyBuffer.session_pStream()->pSession->wire.socket;
  SocketSource.SourceFromDevice (socket_source_function, (void *)&sockContext);
  ReplyBuffer.attach_source(SocketSource);
  // pull the bytes we processed already .
  // easier to do outside the template for now.
  s = ReplyBuffer.toss_input(InSmb2Header.FixedStructureSize()+Smb2QuerydirectoryReply.FixedStructureSize()-1);
  if (s != NetStatusOk)
  {
    return RTSMB_CLI_SSN_RV_DEAD;
  }

  // Now sink the rest to to the shell callback
  DataSinkDevtype ShellCallbackSink(
     (pDeviceSendFn_t)ReplyBuffer.job_data()->findsmb2.answering_dstat->sink_function,
     ReplyBuffer.job_data()->findsmb2.answering_dstat->sink_parameters);
  ReplyBuffer.attach_sink(&ShellCallbackSink);

  dword bytes_pulled=0;
  dword byte_count = Smb2QuerydirectoryReply.OutputBufferLength();
//  ReplyBuffer.attach_sink(&ShellCallbackSink);
  while (bytes_pulled < byte_count && s==NetStatusOk)
  {
    dword _bytes_pulled;
    s = ReplyBuffer.pull_input(byte_count,_bytes_pulled);
    if (s==NetStatusOk)
      bytes_pulled += _bytes_pulled;
  }
  // Remember the search ID
  ReplyBuffer.job_data()->findsmb2.answering_dstat->sid = ReplyBuffer.job_data()->findsmb2.search_struct->sid;
  if (InSmb2Header.NextCommand())
  {
    cout_log(LL_JUNK)  << "Yo next :" << InSmb2Header.NextCommand() << "Stream view: " << ReplyBuffer.get_smb2_read_pointer() << endl;
    return RTSMB_CLI_SSN_SMB2_QUERY_MORE;
  }
  return  RTSMB_CLI_SSN_RV_OK;
}

// Table needs entries for smb2io as well as Streambuffers for now until all legacys are removed.


c_smb2cmdobject querydirectoryobject = { rtsmb2_cli_session_send_querydirectory,rtsmb2_cli_session_send_querydirectory_error_handler, rtsmb2_cli_session_receive_querydirectory, };
c_smb2cmdobject *get_querydirectoryobject() { return &querydirectoryobject;};
