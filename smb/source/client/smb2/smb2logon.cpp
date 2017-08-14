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
#include "smb2defs.hpp"
#include "smb2socks.hpp"
#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "smb2wireobjects.hpp"
#include "mswireobjects.hpp"
#include "session.hpp"
#include "smb2socks.hpp"


// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()



static int do_smb2_extended_setup_server_worker(NewSmb2Session *Session, decoded_NegTokenTarg_challenge_t *decoded_targ_token);


// This is fixed negTokeninit, mechType1 ... see wireshark for decode
static const byte setup_blob[] = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,
0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0xd7,0x3a,0x00,0x00,0x00,0x0f};


class SmbLogonWorker {
public:
  SmbLogonWorker(NewSmb2Session &_Session)
  {  // Constructor that takes a sesstion
    pSmb2Session = &_Session;
    _SmbLogonWorker();
  }
  int rtsmb_cli_session_logon_user_rt_cpp ()
  {
//    PRTSMB_CLI_SESSION_JOB pJob;
    dualstringdecl(user_string);                   //    dualstring user_string;
    dualstringdecl(password_string);               //    std::auto_ptr<dualstring> user_string(new(dualstring));
    dualstringdecl(domain_string);                 //    dualstring user_string(3);

    *user_string     = pSmb2Session->user_name();
    *password_string = pSmb2Session->password() ;
    *domain_string    =pSmb2Session->domain()   ;

    if (user_string->input_length() > (RTSMB_CFG_MAX_USERNAME_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;
    if (password_string->input_length() > (RTSMB_CFG_MAX_PASSWORD_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;
    if (domain_string->input_length() > (RTSMB_CFG_MAX_DOMAIN_NAME_SIZE - 1))
        return RTSMB_CLI_SSN_RV_BAD_ARGS;
    ASSURE (pSmb2Session->session_state() > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);

    pSmb2Session->update_timestamp();


    if (pSmb2Session->user_state() != CSSN_USER_STATE_CHALLENGED)
    { ASSURE (pSmb2Session->user_state() == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);  }


// These fileds are now in this Session class.

// ??    pJob->data.session_setup.user_struct = pSmb2Session->user_structure();
//    rtp_wcscpy (pJob->data.session_setup.account_name, user_string->utf16());
//    strcpy (pJob->data.session_setup.password, (char *) password_string->ascii());
//    rtp_wcscpy (pJob->data.session_setup.domain_name, domain_string->utf16());

//    rtsmb_cli_session_user_new (( RTSMB_CLI_SESSION_USER*)pSmb2Session->user_structure(), 1);
    pSmb2Session->user_state(CSSN_USER_STATE_LOGGING_ON);
    pSmb2Session->user_uid(1);

    int r = rtsmb2_cli_session_send_setup (); // (NetStreamBuffer &SendBuffer);
    if (r== RTSMB_CLI_SSN_RV_OK)
    {
      r = pSmb2Session->wait_on_job();
      if (r==0)
        r = rtsmb2_cli_session_receive_setup (); // (NetStreamBuffer &ReplyBuffer);
    }
    return r;
  }
  int go()
  {
      int r = rtsmb2_cli_session_send_negotiate ();
      if(r < 0)
      {
        cout_log(LL_JUNK) << "rtsmb2_cli_session_send_negotiate failed r==: " << r << endl;
        return 0;
      }
      r = rtsmb2_cli_session_receive_negotiate ();
      if(r < 0) return 0;

      // Send setup and wait for the response which will have a challenge blob
      r = rtsmb_cli_session_logon_user_rt_cpp ();
      if(r < 0) return 0;
      if (pSmb2Session->user_state() == CSSN_USER_STATE_CHALLENGED)
      {
         decoded_NegTokenTarg_challenge_t decoded_targ_token;
         int r = spnego_decode_NegTokenTarg_challenge(&decoded_targ_token,
                     pSmb2Session->spnego_blob_from_server(),
                     pSmb2Session->spnego_blob_size_from_server());
         if (r == 0)
         {  // Ssends of the hashed challenge and waits for status
            r =  do_smb2_extended_setup_server_worker(pSmb2Session, &decoded_targ_token);
         }
         rtp_free(pSmb2Session->spnego_blob_from_server());
         spnego_decoded_NegTokenTarg_challenge_destructor(&decoded_targ_token);
         if(r < 0) return 0;
         r = pSmb2Session->wait_on_job();
         if(r < 0) return 0;
      }
    return(1);
  }


  // Phase 1 sends sNegTokenInit, Expects SMB_NT_STATUS_MORE_PROCESSING_REQUIRED and a server challenge
  // Phase 2 sends sNegTokenInit   ntlmssp_encode_ntlm2_type2_response_packet (spnego_encode_ntlm2_type3_packet)

//  int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key)

  int rtsmb2_cli_session_send_setup()
  {
      int send_status;
      NetNbssHeader       OutNbssHeader;
      NetSmb2Header       OutSmb2Header;
      NetSmb2SetupCmd     Smb2SetupCmd;
  //    NetStreamBuffer SendBuffer;

      byte *variable_content = (byte *) setup_blob;
      dword variable_content_size = sizeof(setup_blob);

      pSmb2Session->SendBuffer.stream_buffer_mid = pSmb2Session->unconnected_message_id();

      NetSmb2NBSSCmd<NetSmb2SetupCmd> Smb2NBSSCmd(SMB2_SESSION_SETUP, pSmb2Session->SendBuffer,OutNbssHeader,OutSmb2Header, Smb2SetupCmd, variable_content_size);
      if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
      {
  //      Smb2SetupCmd.SecurityBufferLength =  Smb2SetupCmd.SecurityBufferLength();
        dword in_variable_content_size    =  Smb2SetupCmd.SecurityBufferLength();    // not sure if this is right
        Smb2SetupCmd.StructureSize        =  Smb2SetupCmd.FixedStructureSize();
        Smb2SetupCmd.Flags                =  0x0;
        Smb2SetupCmd.SecurityMode         =  0x01;
        Smb2SetupCmd.Capabilities         =  0;
        Smb2SetupCmd.Channel              =  0;
        Smb2SetupCmd.SecurityBufferOffset =  0x58;
        Smb2SetupCmd.SecurityBufferLength =  variable_content_size;
        Smb2SetupCmd.PreviousSessionId    =  0;
        Smb2SetupCmd.addto_variable_content(variable_content_size); // (Smb2SetupCmd.SecurityBufferLength());
        if (Smb2SetupCmd.push_output(pSmb2Session->SendBuffer) != NetStatusOk)
           return RTSMB_CLI_SSN_RV_DEAD;

        memcpy(OutSmb2Header.FixedStructureAddress()+Smb2SetupCmd.SecurityBufferOffset(), variable_content, variable_content_size);
      }
      Smb2NBSSCmd.flush();
      return RTSMB_CLI_SSN_RV_OK;
//      return Smb2NBSSCmd.status;
  }

  int rtsmb2_cli_session_receive_setup()
  {
  //    int send_status;
    dword in_variable_content_size = 0;
    dword bytes_pulled;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2SetupReply Smb2SetupReply;


    pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2SetupReply.FixedStructureSize() ,bytes_pulled);
    cout_log(LL_JUNK)  << "rtsmb2_cli_session_receive_setup received packet pulled #: " << bytes_pulled << endl;
    dword bytes_ready;
    byte *message_base = pSmb2Session->ReplyBuffer.buffered_data_pointer(bytes_ready);

    NetSmb2NBSSReply<NetSmb2SetupReply>  Smb2NBSSReply(SMB2_SESSION_SETUP, pSmb2Session->ReplyBuffer, InNbssHeader,InSmb2Header, Smb2SetupReply);
    cout_log(LL_JUNK)  << "session_receive_setup received packet :" << endl;

  cout_log(LL_JUNK) << " Smb2SetupReply InNbssHeader size: " << (int) InNbssHeader.nbss_packet_size() << endl;
  cout_log(LL_JUNK) << " SMB StructureSize 65 ???: " << (int) InSmb2Header.StructureSize() << endl;
  cout_log(LL_JUNK) << " Reply StructureSize 65 ???: " << (int) Smb2SetupReply.StructureSize() << endl;


    if (InSmb2Header.Status_ChannelSequenceReserved() !=  SMB_NT_STATUS_MORE_PROCESSING_REQUIRED)
    {
      dword ssstatus =  InSmb2Header.Status_ChannelSequenceReserved();
//      cout_log(LL_JUNK) << "didnt get SMB_NT_STATUS_MORE_PROCESSING_REQUIRED :" << std::hex << ssstatus << endl;
      cout_log(LL_JUNK) << "didnt get SMB_NT_STATUS_MORE_PROCESSING_REQUIRED :" << std::hex << ssstatus << endl;
    }
    if (Smb2SetupReply.SecurityBufferLength()&&Smb2SetupReply.SecurityBufferLength() < 2048)
    {
      pSmb2Session->spnego_blob_size_from_server(Smb2SetupReply.SecurityBufferLength());
      pSmb2Session->spnego_blob_from_server((byte *)rtp_malloc(Smb2SetupReply.SecurityBufferLength()));
      pSmb2Session->user_state(CSSN_USER_STATE_CHALLENGED);
      memcpy( pSmb2Session->spnego_blob_from_server(), InSmb2Header.FixedStructureAddress()+Smb2SetupReply.SecurityBufferOffset(), Smb2SetupReply.SecurityBufferLength());
      // ??    ReplyBuffer.job_data()->session_setup.user_struct = ReplyBuffer.session_user();
    }
    return RTSMB_CLI_SSN_RV_OK;
  }

  int rtsmb2_cli_session_send_negotiate ()
  {
      int send_status;
      dword variable_content_size = (dword)2*sizeof(word);  // Needs to be known before Smb2NBSSCmd is instantiated
      NetNbssHeader       OutNbssHeader;
      NetSmb2Header       OutSmb2Header;
      NetSmb2NegotiateCmd Smb2NegotiateCmd;
      pSmb2Session->SendBuffer.stream_buffer_mid = pSmb2Session->unconnected_message_id();
      NetSmb2NBSSCmd<NetSmb2NegotiateCmd> Smb2NBSSCmd(SMB2_NEGOTIATE, pSmb2Session->SendBuffer,OutNbssHeader,OutSmb2Header, Smb2NegotiateCmd, variable_content_size);
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
        if (Smb2NegotiateCmd.push_output(pSmb2Session->SendBuffer) != NetStatusOk)
           return RTSMB_CLI_SSN_RV_DEAD;
      }
  // ??   SendBuffer.job_data()->session_setup.user_struct = SendBuffer.session_user();  // gross.
  //    SendBuffer.job_data()->session_setup.user_struct = SendBuffer.session_user();  // gross.
      Smb2NBSSCmd.flush();
      return Smb2NBSSCmd.status;
  }
int rtsmb2_cli_session_receive_negotiate ()
{
//    int send_status;
  dword in_variable_content_size = 0;
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2NegotiateReply Smb2NegotiateReply;
  dword start_count = pSmb2Session->ReplyBuffer.get_smb2_read_pointer();
  dword bytes_pulled;

  pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2NegotiateReply.FixedStructureSize() ,bytes_pulled);
  cout_log(LL_JUNK)  << "rtsmb2_cli_session_receive_negotiate received packet pulled #: " << bytes_pulled << endl;
  dword bytes_ready;
  byte *message_base = pSmb2Session->ReplyBuffer.buffered_data_pointer(bytes_ready);
  cout_log(LL_JUNK)  << "rtsmb2_cli_session_receive_negotiate received packet pulled #: " << bytes_pulled << endl;
  NetSmb2NBSSReply<NetSmb2NegotiateReply> Smb2NBSSReply(SMB2_NEGOTIATE, pSmb2Session->ReplyBuffer, InNbssHeader,InSmb2Header, Smb2NegotiateReply);

  cout_log(LL_JUNK) << " Negotiate InNbssHeader size: " << (int) InNbssHeader.nbss_packet_size() << endl;
  cout_log(LL_JUNK) << " SMB StructureSize 65 ???: " << (int) InSmb2Header.StructureSize() << endl;
  cout_log(LL_JUNK) << " Reply StructureSize 65 ???: " << (int) Smb2NegotiateReply.StructureSize() << endl;

  cout_log(LL_JUNK) << " Need to purge:  " << InNbssHeader.nbss_packet_size() - bytes_pulled << endl;


  pSmb2Session->ReplyBuffer.purge_socket_input((InNbssHeader.nbss_packet_size()+4) - bytes_pulled);


  if (Smb2NegotiateReply.SecurityBufferLength())
  {
   pSmb2Session->user_uid(0);   // Hack it isn't set up yet
   // This is the ignore rfc xx comment, no need to save it
   pSmb2Session->user_state(CSSN_USER_STATE_CHALLENGED);
  }
  pSmb2Session->session_server_info_dialect =  (RTSMB_CLI_SESSION_DIALECT)Smb2NegotiateReply.DialectRevision();

  // Get the maximum buffer size we can ever want to allocate and store it in buffer_size
  {
    dword maxsize =  Smb2NegotiateReply.MaxReadSize();
    if (Smb2NegotiateReply.MaxWriteSize() >  maxsize)
      maxsize = Smb2NegotiateReply.MaxWriteSize();
    if (Smb2NegotiateReply.MaxTransactSize() >  maxsize)
      maxsize = Smb2NegotiateReply.MaxTransactSize();
    pSmb2Session->session_server_info_buffer_size =  maxsize;
    pSmb2Session->session_server_info_raw_size   =   maxsize;
    // HEREHERE -  ReplyBuffer.session_server_info()->smb2_session_id = InSmb2Header->Smb2NegotiateReply???
   }
//   ReplyBuffer.session_pStream()->read_buffer_remaining = 0;   // Fore the top layer to stop.
   return RTSMB_CLI_SSN_RV_OK;
}

private:
  void _SmbLogonWorker()
  {
  };
  NewSmb2Session *pSmb2Session;

};


extern int do_smb2_logon_server_worker(NewSmb2Session &Session)
{
  SmbLogonWorker LogonWorker(Session);
  return LogonWorker.go();
}

// The server sent a setup reply with a challenge, we create a security blob from the challagne and reply with another setup request
static int do_smb2_extended_setup_server_worker(NewSmb2Session *Session, decoded_NegTokenTarg_challenge_t *decoded_targ_token)
{
   return -1;
//   decoded_targ_token.ntlmserverchallenge,
//   decoded_targ_token.target_info->value_at_offset,
//   decoded_targ_token.target_info->size
}
