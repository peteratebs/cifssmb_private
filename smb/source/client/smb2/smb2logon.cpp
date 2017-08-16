//
// smb2logon.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2017
//   All rights reserved.
//    This code may not be redistributed in source or linkable object form
//    without the consent of its author.
//
//  Module description:
//    Process client negotiate and setup commands and perfrom a log in.
//
#include "smb2clientincludes.hpp"
#include "smb2spnego.hpp"

static int do_smb2_extended_setup_server_worker(NewSmb2Session *Session, decoded_NegTokenTarg_challenge_t *decoded_targ_token);
// This is fixed negTokeninit, mechType1 ... see wireshark for decode
static const byte setup_blob_phase_one[] = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,
0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0xd7,0x3a,0x00,0x00,0x00,0x0f};


static const byte setup_blob_phase_two[] = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,
0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0xd7,0x3a,0x00,0x00,0x00,0x0f};

static byte * cli_util_client_encrypt_password_ntlmv2 (word * name, char * password, word * domainname, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, char * output);
static int rtsmb_cli_session_ntlm_auth ( char * user, char * password, char * domain, byte * serverChallenge, byte * serverInfoblock, int serverInfoblock_length);

static byte ntlm_response_buffer_ram[1024];

class SmbLogonWorker {
public:
  SmbLogonWorker(NewSmb2Session &_Session)        {     pSmb2Session = &_Session; do_setup_phase_two=false;  }
  int do_logon_commands()
  {
    // Send negotiate and wait for the response which will have a server challenge
    int r = do_negotiate_command();
    if(r < 0) return 0;

    // Send setup and wait for the response which will have a challenge blob
    r = do_setup_command();
    if(r < 0) return 0;
    if (pSmb2Session->user_state() != CSSN_USER_STATE_CHALLENGED)
    {
       cout_log(LL_JUNK) << "didnt get to CSSN_USER_STATE_CHALLENGED state" << endl;
       return 0;
    }
    // Send hashed user, password, domain, server challenge blob and wait for okay from teh server
    r = do_extended_setup_command();
    if(r < 0) return 0;
    return(1);
  }
  int do_negotiate_command ()
  {
    int r = send_negotiate ();
    if (r >= 0)
      r = receive_negotiate ();
    return r;
  }

  int send_negotiate ()
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
  int receive_negotiate ()
  {
  //    int send_status;
    dword in_variable_content_size = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2NegotiateReply Smb2NegotiateReply;
    dword bytes_pulled;

    pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2NegotiateReply.FixedStructureSize() ,bytes_pulled);
    cout_log(LL_JUNK)  << "rtsmb2_cli_session_receive_negotiate received packet pulled #: " << bytes_pulled << endl;
    dword bytes_ready;
    byte *message_base = pSmb2Session->ReplyBuffer.buffered_data_pointer(bytes_ready);
    cout_log(LL_JUNK)  << "rtsmb2_cli_session_receive_negotiate received packet pulled #: " << bytes_pulled << endl;
    NetSmb2NBSSReply<NetSmb2NegotiateReply> Smb2NBSSReply(SMB2_NEGOTIATE, pSmb2Session->ReplyBuffer, InNbssHeader,InSmb2Header, Smb2NegotiateReply);

    InNbssHeader.show_contents();
    InSmb2Header.show_contents();

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

  // Phase 1 sends sNegTokenInit, Expects SMB_NT_STATUS_MORE_PROCESSING_REQUIRED and a server challenge
  // Phase 2 sends sNegTokenInit   ntlmssp_encode_ntlm2_type2_response_packet (spnego_encode_ntlm2_type3_packet)

//  int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key)
  int do_setup_command ()
  {
    dualstringdecl(user_string)    ;*user_string     = pSmb2Session->user_name();
    dualstringdecl(password_string);*password_string = pSmb2Session->password() ;
    dualstringdecl(domain_string)  ;*domain_string    =pSmb2Session->domain()   ;

    if (user_string->input_length() > (RTSMB_CFG_MAX_USERNAME_SIZE - 1))  return RTSMB_CLI_SSN_RV_BAD_ARGS;
    if (password_string->input_length() > (RTSMB_CFG_MAX_PASSWORD_SIZE - 1)) return RTSMB_CLI_SSN_RV_BAD_ARGS;
    if (domain_string->input_length() > (RTSMB_CFG_MAX_DOMAIN_NAME_SIZE - 1)) return RTSMB_CLI_SSN_RV_BAD_ARGS;
    ASSURE (pSmb2Session->session_state() > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    if (pSmb2Session->user_state() != CSSN_USER_STATE_CHALLENGED) { ASSURE (pSmb2Session->user_state() == CSSN_USER_STATE_UNUSED, RTSMB_CLI_SSN_RV_TOO_MANY_USERS);  }

    pSmb2Session->update_timestamp();
    pSmb2Session->user_state(CSSN_USER_STATE_LOGGING_ON);
    pSmb2Session->user_uid(1);

    setup_blob = (byte *) setup_blob_phase_one;
    setup_blob_size = sizeof(setup_blob_phase_one);

    int r = send_setup (); // (NetStreamInputBuffer &SendBuffer);
    if (r==RTSMB_CLI_SSN_RV_OK)
        r = receive_setup(); // (NetStreamInputBuffer &ReplyBuffer);
    return r;
  }

  int send_setup()
  {
      int send_status;
      NetNbssHeader       OutNbssHeader;
      NetSmb2Header       OutSmb2Header;
      NetSmb2SetupCmd     Smb2SetupCmd;

      byte *variable_content = (byte *) setup_blob;
      dword variable_content_size = setup_blob_size;

      pSmb2Session->SendBuffer.stream_buffer_mid = pSmb2Session->unconnected_message_id();
      NetSmb2NBSSCmd<NetSmb2SetupCmd> Smb2NBSSCmd(SMB2_SESSION_SETUP, pSmb2Session->SendBuffer,OutNbssHeader,OutSmb2Header, Smb2SetupCmd, variable_content_size);
      if (Smb2NBSSCmd.status == RTSMB_CLI_SSN_RV_OK)
      {
        dword in_variable_content_size    =  Smb2SetupCmd.SecurityBufferLength();    // not sure if this is right
        Smb2SetupCmd.StructureSize        =  Smb2SetupCmd.FixedStructureSize();
        Smb2SetupCmd.Flags                =  0x0;
        Smb2SetupCmd.SecurityMode         =  0x01;
        Smb2SetupCmd.Capabilities         =  0;
        Smb2SetupCmd.Channel              =  0;
        Smb2SetupCmd.SecurityBufferOffset =  0x58;
        Smb2SetupCmd.SecurityBufferLength =  variable_content_size;
        Smb2SetupCmd.PreviousSessionId    =  0;
        memcpy(OutSmb2Header.FixedStructureAddress()+Smb2SetupCmd.SecurityBufferOffset(), variable_content, variable_content_size);
        Smb2SetupCmd.addto_variable_content(variable_content_size);
        if (Smb2SetupCmd.push_output(pSmb2Session->SendBuffer) != NetStatusOk)
           return RTSMB_CLI_SSN_RV_DEAD;
      }
      Smb2NBSSCmd.flush();
      return RTSMB_CLI_SSN_RV_OK;
  }

  int receive_setup()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2SetupReply Smb2SetupReply;

    // Pull enough for the fixed part and then map pointers toi input buffer
    int r = pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2SetupReply.FixedStructureSize()-1, bytes_pulled);
    if (r != NetStatusOk)
      return RTSMB_CLI_SSN_RV_DEAD;
    NetSmb2NBSSReply<NetSmb2SetupReply>  Smb2NBSSReply(SMB2_SESSION_SETUP, pSmb2Session->ReplyBuffer, InNbssHeader,InSmb2Header, Smb2SetupReply);

    InNbssHeader.show_contents();
    InSmb2Header.show_contents();

    if (InSmb2Header.Status_ChannelSequenceReserved() !=  SMB_NT_STATUS_MORE_PROCESSING_REQUIRED)
    {
      dword ssstatus =  InSmb2Header.Status_ChannelSequenceReserved();
      cout_log(LL_JUNK) << "didnt get SMB_NT_STATUS_MORE_PROCESSING_REQUIRED got:" << std::hex << ssstatus << endl;
      return RTSMB_CLI_SSN_RV_DEAD;
    }

    if (Smb2SetupReply.SecurityBufferLength()&&Smb2SetupReply.SecurityBufferLength() < 2048)
    {
      dword security_bytes_pulled;
      r = pSmb2Session->ReplyBuffer.pull_nbss_data(Smb2SetupReply.SecurityBufferLength(), security_bytes_pulled);
      if (r != NetStatusOk)
        return RTSMB_CLI_SSN_RV_DEAD;
      if (Smb2SetupReply.SecurityBufferLength() != security_bytes_pulled)
        return RTSMB_CLI_SSN_RV_DEAD;
      pSmb2Session->spnego_blob_size_from_server(Smb2SetupReply.SecurityBufferLength());
      pSmb2Session->spnego_blob_from_server((byte *)rtp_malloc(Smb2SetupReply.SecurityBufferLength()));
      pSmb2Session->user_state(CSSN_USER_STATE_CHALLENGED);
      memcpy( pSmb2Session->spnego_blob_from_server(), InSmb2Header.FixedStructureAddress()+Smb2SetupReply.SecurityBufferOffset(), Smb2SetupReply.SecurityBufferLength());
    }
    return RTSMB_CLI_SSN_RV_OK;
  }
  int do_extended_setup_command()
  {
    do_setup_phase_two=true;
    decoded_NegTokenTarg_challenge_t decoded_targ_token;
    int r = spnego_decode_NegTokenTarg_challenge(&decoded_targ_token,
                 pSmb2Session->spnego_blob_from_server(),
                 pSmb2Session->spnego_blob_size_from_server());

//    decoded_targ_token.Flags;
//    decoded_targ_token.ntlmserverchallenge[8];
//typedef struct SecurityBuffer_s {  dword size;  word  offset;  byte  *value_at_offset;
//    decoded_targ_token.target_name;
//    decoded_targ_tokentarget_info;

//typedef struct SecurityBuffer_s {  dword size;  word  offset;  byte  *value_at_offset;


 int blob_length = rtsmb_cli_session_ntlm_auth (
    pSmb2Session->user_name(),
    pSmb2Session->password(),
    pSmb2Session->domain(),
    decoded_targ_token.ntlmserverchallenge,
    decoded_targ_token.target_info->value_at_offset,
    decoded_targ_token.target_info->size);

    setup_blob = (byte *) ntlm_response_buffer_ram; // setup_blob_phase_two;
    setup_blob_size = blob_length;

    r = send_setup (); // (NetStreamInputBuffer &SendBuffer);
    if (r==RTSMB_CLI_SSN_RV_OK)
        r = receive_setup(); // (NetStreamInputBuffer &ReplyBuffer);
    return r;

     rtp_free(pSmb2Session->spnego_blob_from_server());
     spnego_decoded_NegTokenTarg_challenge_destructor(&decoded_targ_token);
     return r;
  }

  private:
    bool do_setup_phase_two;
    byte *setup_blob;
    dword setup_blob_size;
    NewSmb2Session *pSmb2Session;

};


extern int do_smb2_logon_server_worker(NewSmb2Session &Session)
{
  SmbLogonWorker LogonWorker(Session);
  return LogonWorker.do_logon_commands();
}

// The server sent a setup reply with a challenge, we create a security blob from the challagne and reply with another setup request
static int do_smb2_extended_setup_server_worker(NewSmb2Session *Session, decoded_NegTokenTarg_challenge_t *decoded_targ_token)
{
   return -1;
//   decoded_targ_token.ntlmserverchallenge,
//   decoded_targ_token.target_info->value_at_offset,
//   decoded_targ_token.target_info->size
}

byte ntlm_response_buffer[] = {0xbc,0xd3,0x40,0x6e,0x8f,0x2e,0x83,0x5f,0xc2,0xd2,0x35,0xe1,0x1d,0xeb,0x06,0x37,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0b,0xf4,0xcb,0xd2,0x34,0xd1,0x01,0x36,0xc3,0x0c,0x2d,0xfc,0x9b,0x47,0xe5,0x00,0x00,0x00,0x00,0x01,0x00,
0x26,0x00,0x55,0x00,0x42,0x00,0x55,0x00,0x4e,0x00,0x54,0x00,0x55,0x00,0x31,0x00,0x34,0x00,0x2d,0x00,0x56,0x00,0x49,0x00,0x52,0x00,0x54,0x00,0x55,0x00,0x41,0x00,0x4c,0x00,0x42,0x00,0x4f,0x00,0x58,0x00,0x02,0x00,0x26,0x00,0x55,0x00,
0x42,0x00,0x55,0x00,0x4e,0x00,0x54,0x00,0x55,0x00,0x31,0x00,0x34,0x00,0x2d,0x00,0x56,0x00,0x49,0x00,0x52,0x00,0x54,0x00,0x55,0x00,0x41,0x00,0x4c,0x00,0x42,0x00,0x4f,0x00,0x58,0x00,0x03,0x00,0x26,0x00,0x75,0x00,0x62,0x00,0x75,0x00,
0x6e,0x00,0x74,0x00,0x75,0x00,0x31,0x00,0x34,0x00,0x2d,0x00,0x76,0x00,0x69,0x00,0x72,0x00,0x74,0x00,0x75,0x00,0x61,0x00,0x6c,0x00,0x62,0x00,0x6f,0x00,0x78,0x00,0x04,0x00,0x00,0x00,0x06,0x00,0x04,0x00,0x02,0x00,0x00,0x00,0x09,0x00,
0x20,0x00,0x63,0x00,0x69,0x00,0x66,0x00,0x73,0x00,0x2f,0x00,0x31,0x00,0x39,0x00,0x32,0x00,0x2e,0x00,0x31,0x00,0x36,0x00,0x38,0x00,0x2e,0x00,0x31,0x00,0x2e,0x00,0x37,0x00,0x0a,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

static const byte zero[8] = {0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0};         // zeros


int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key);

int rtsmb_cli_session_ntlm_auth ( char * user, char * password, char * domain, byte * serverChallenge, byte * serverInfoblock, int serverInfoblock_length)
{
    byte session_key[16];
    rtsmb_util_guid(&session_key[0]);
    rtsmb_util_guid(&session_key[8]);
    word workstation_name[32];
    rtsmb_util_ascii_to_unicode ("workstation" ,workstation_name, (strlen("workstation")+1)*2 );
    word user_name[32];
    rtsmb_util_ascii_to_unicode (user, user_name, 2*(strlen(user)+1));
    word domain_name[32];
    rtsmb_util_ascii_to_unicode (domain, domain_name, 2*(strlen(domain)+1));
    byte *pclient_blob;

    pclient_blob = &ntlm_response_buffer_ram[8];

    // The structure is 8 bytes unused, 8 bytes server challenge, followed by the blob which contains the signature, timestamp, and nonce
    // Prepend the 8 byte server challenge
    memcpy(pclient_blob, serverChallenge,8);
    pclient_blob += 8;
    // Append the 28 byte blob containing the client nonce
    spnego_get_client_ntlmv2_response_blob(pclient_blob);
    pclient_blob += 28;
    // Append the target information block pqassed from the server
    memcpy(pclient_blob, serverInfoblock,serverInfoblock_length);

    pclient_blob += serverInfoblock_length;

    memcpy(pclient_blob,zero,4);
    pclient_blob += 4;

    pclient_blob = &ntlm_response_buffer_ram[8];
    // The size of the blob to run the digest on
    int client_blob_size = 8 + 28 + serverInfoblock_length + 4;
    // The size of the blob plus digest
    int ntlm_response_buffer_size = 16 + 28 + serverInfoblock_length + 4;
    byte output[16];

    cli_util_client_encrypt_password_ntlmv2 (
      (word *) user_name,
      (char *) password,
      (word *) domain_name,
      (byte *)serverChallenge,
      (byte *)pclient_blob,
      (size_t) client_blob_size,
      (char *) output);
    memcpy(&ntlm_response_buffer_ram[0],output,16);

    byte *ntlm_response_blob=(byte *)rtp_malloc(2048);;

    size_t ntlm_response_blob_size=
            spnego_encode_ntlm2_type3_packet(
              (byte *)ntlm_response_blob,
              (size_t)2048, // ntlm_response_blob_size,
              (byte *)ntlm_response_buffer_ram,
              (int)ntlm_response_buffer_size,
              (byte *)domain_name, (byte *)user_name, (byte *)workstation_name, (byte *)session_key);
    return ntlm_response_blob_size;
}

// PFCHAR password, byte * serverChallenge, PFRTCHAR domainname, byte * ntlm_response_blob, size_t ntlm_response_blob_length, PFRTCHAR name, char * output)
//
extern unsigned char *RTSMB_MD4(const unsigned char *d, unsigned long n, unsigned char *md); //   { return 0; }
extern void hmac_md5( unsigned char*  text, int text_len, unsigned char*  key,int  key_len, unsigned char *digest); //  {}


static byte * cli_util_client_encrypt_password_ntlmv2 (word * name, char * password, word * domainname, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, char * output)
{
  byte nameDomainname[(RTSMB_CFG_MAX_USERNAME_SIZE + 1) * 4];
  byte p21 [21];
  byte NTLMv2_Hash[16];
  int dst, src;
  size_t ndLen;

  // The NTLM password hash is obtained, this is the MD4 digest of the Unicode mixed-case password).
  // Convert the password to unicode
  std::string s_password;
  s_password = password;
  // Store it in upper case
  std::transform(s_password.begin(), s_password.end(), s_password.begin(), toupper);
  std::string s_password2 = s_password;  // Copy to make sure c_str is contiguous
  dualstringdecl(upassword);   //   use a dualstring to convert the password to unicode
  *upassword = (char *)s_password2.c_str();

   // p21 is actually p16 with 5 null bytes appended.  we just null it now
   // and fill it as if it were p16
   memset (&p21[16], 0, 5);
   // get md4 of password.  This is the 16-byte NTLM hash
   RTSMB_MD4 ((const unsigned char *)upassword->utf16(), (dword)dst, p21);

   dualstringdecl(udomain);   //   use a dualstring to convert the domain to upper
   *udomain = domainname;
   std::string s_domain;
   s_domain = (char *)udomain->ascii();
   std::transform(s_domain.begin(), s_domain.end(), s_domain.begin(), toupper);
   std::string s_domain2 = s_domain;  // Copy to make sure c_str is contiguous
   dualstringdecl(udomain_upper);   //   use a dualstring to convert the domain to upper
   *udomain_upper = (char *)s_domain2.c_str();

   dualstringdecl(uname);   //   use a dualstring to convert the name to a string
   *uname = name;
   std::string s_name;
   s_name = (char *)uname->ascii();

    // The Unicode uppercase username is concatenated with the Unicode authentication target
    // (the domain or server name specified in the Target Name field of the Type 3 message).
    // Note that this calculation always uses the Unicode representation, even if OEM encoding
    // has been negotiated; also note that the username is converted to uppercase,
    // while the authentication target is case-sensitive and must match the case presented in the Target Name field.
//   ndLen = 2*rtsmb_util_wlen((PFWCS)name) + 2*rtsmb_util_wlen((PFWCS)domainname);
    ndLen = 2 * (s_name.length() + s_domain.length());
   // concatenate the uppercase username with the domainname
    memcpy((char *) nameDomainname, uname->utf16(), 2*s_name.length() );
    memcpy((char *) &nameDomainname[2*s_name.length()], udomain_upper->utf16(), 2*s_domain.length() );

   // The HMAC-MD5 message authentication code algorithm is applied to
   // the unicode (username,domainname) using the 16-byte NTLM hash as the key.
   // This results in a 16-byte value - the NTLMv2 hash.
   hmac_md5(nameDomainname,    /* pointer to data stream */
               ndLen,				/* length of data stream */
               p21,             /* pointer to remote authentication key */
               16,              /* length of authentication key */
               NTLMv2_Hash);    /* caller digest to be filled in */
    byte concatChallenge[1024];
    byte output_value[16];
    // The HMAC-MD5 message authentication code algorithm is applied to this value using the 16-byte NTLMv2 hash
    // (calculated in step 2) as the key. This results in a 16-byte output value.
    // pntlmv2_blob = (ntlmv2_blob_t *) ntlm_response_blob;

    memcpy(concatChallenge, serverChallenge, 8);
    memcpy(&concatChallenge[8], ntlm_response_blob, ntlm_response_blob_length);
    hmac_md5(concatChallenge+8,	/* pointer to data stream */
               ntlm_response_blob_length,		/* length of data stream */
               NTLMv2_Hash,		/* pointer to remote authentication key */
               16,				/* length of authentication key */
               (byte * ) output);
    return (byte * )output;
}
