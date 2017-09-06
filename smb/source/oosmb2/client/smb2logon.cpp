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

// This is fixed negTokeninit, mechType1 sent by setup to evoke a challenge from the server ... see wireshark for decode
static const byte setup_blob_phase_one[] = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,
0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0xd7,0x3a,0x00,0x00,0x00,0x0f};

#define MAXBLOB 4096

#define DIAG_LOGON_LEVEL DIAG_DEBUG // DIAG_DISABLED,DIAG_DEBUG


class SmbLogonWorker : private local_allocator,private smb_diagnostics {
public:
  SmbLogonWorker(Smb2Session &_Session)
  {
    set_diag_level(DIAG_LOGON_LEVEL);
    pSmb2Session = &_Session; do_extended_setup_phase=false;
    spnego_blob_from_server = response_to_challenge=0;
    spnego_blob_from_server = (byte *)local_rtp_malloc(MAXBLOB);
    response_to_challenge=(byte *)local_rtp_malloc(MAXBLOB);
    ntlm_response_buffer_ram=(byte *)local_rtp_malloc(MAXBLOB);
    concatChallenge =(byte *)local_rtp_malloc(MAXBLOB);
    if (pSmb2Session->user_state() != CSSN_USER_STATE_UNUSED)
    {
      pSmb2Session->diag_text_warning("Logon called but user_state() != CSSN_USER_STATE_UNUSED %d",pSmb2Session->user_state());
//      return false;
    }

  }
  ~SmbLogonWorker()
  {
  }
  /// Send negotiate and wait for the response which will have dialect, capabilities and buffer sizes and a generic security blob
  /// Send setup and wait for the response which will have a challenge blob
  /// Encode the ntlm security blob from the callenge plus name, domain and UIDand send another setup
  /// Set tate to logged in.
  bool do_logon_commands()
  {
    // Send negotiate and wait for the response which will have a server challenge
    bool r = do_negotiate_command();
    if(r)
    {
      // Send setup and wait for the response which will have a challenge blob
      r = do_setup_command();
      if(r)
      {
       if (pSmb2Session->user_state() != CSSN_USER_STATE_CHALLENGED)
       {
         pSmb2Session->diag_text_warning("didnt get to CSSN_USER_STATE_CHALLENGED state");
         return false;
       }
       else    // Send hashed user, password, domain, server challenge blob and wait for okay from teh server
          r = do_extended_setup_command();
      }
    }
    return(r);
  }
  bool do_negotiate_command ()
  {
    bool r = send_negotiate();
    if (r)
      r = receive_negotiate();
    return r;
  }
private:
    int rtsmb_cli_session_ntlm_auth ( char * user, char * password, char * domain, byte * serverChallenge, byte * serverInfoblock, int serverInfoblock_length, byte *session_key);
    byte *cli_util_client_encrypt_password_ntlmv2 (word * name, char * password, word * domainname, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, char * output);
    byte *ntlm_response_buffer_ram;
    byte *response_to_challenge;
    byte *concatChallenge;

    bool do_extended_setup_phase;
    byte *setup_blob;
    dword setup_blob_size;
    byte   *spnego_blob_from_server;
    int    spnego_blob_size_from_server;

    Smb2Session *pSmb2Session;

  bool send_negotiate ()
  {
      int send_status;
      dword variable_content_size = (dword)2*sizeof(word);  // Needs to be known before Smb2NBSSCmd is instantiated
      NetNbssHeader       OutNbssHeader;
      NetSmb2Header       OutSmb2Header;
      NetSmb2NegotiateCmd Smb2NegotiateCmd;

      NetSmb2NBSSSendCmd<NetSmb2NegotiateCmd> Smb2NBSSCmd(SMB2_NEGOTIATE, pSmb2Session, OutNbssHeader,OutSmb2Header, Smb2NegotiateCmd, variable_content_size);
      Smb2NegotiateCmd.StructureSize=   Smb2NegotiateCmd.FixedStructureSize();
      Smb2NegotiateCmd.DialectCount =   2;
      Smb2NegotiateCmd.SecurityMode =   SMB2_NEGOTIATE_SIGNING_ENABLED;
      Smb2NegotiateCmd.Reserved     =   0;
      Smb2NegotiateCmd.Capabilities =   0; // SMB2_GLOBAL_CAP_DFS  et al
      Smb2NegotiateCmd.guid        =    (byte *) "IAMTHEGUID     ";
      Smb2NegotiateCmd.ClientStartTime = rtsmb_util_get_current_filetime();  // ???  TBD
      Smb2NegotiateCmd.Dialect0 =SMB2_DIALECT_2002;
      Smb2NegotiateCmd.Dialect1 =SMB2_DIALECT_2100;
      Smb2NegotiateCmd.addto_variable_content(variable_content_size);  // not using copy2 but we could

      return Smb2NBSSCmd.flush();
  }
  bool receive_negotiate ()
  {
    dword in_variable_content_size = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2NegotiateReply Smb2NegotiateReply;
    dword bytes_pulled;

    NetStatus r = pSmb2Session->RecvBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2NegotiateReply.PackedStructureSize() ,bytes_pulled);
    if (r != NetStatusOk)
    {
       pSmb2Session->diag_text_warning("Socket error pulling receive_negotiate message status:%d",r);
       return false;
    }
    dword bytes_ready;
    byte *message_base = pSmb2Session->RecvBuffer.buffered_data_pointer(bytes_ready);
    NetSmb2NBSSRecvReply<NetSmb2NegotiateReply> Smb2NBSSReply(SMB2_NEGOTIATE, pSmb2Session, InNbssHeader,InSmb2Header, Smb2NegotiateReply);


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
      pSmb2Session->diag_text_warning("receive_negotiate max size:%d",maxsize);
     }
     return true;
  }

  // Phase 1 sends sNegTokenInit, Expects SMB_NT_STATUS_MORE_PROCESSING_REQUIRED and a server challenge
  // Phase 2 sends sNegTokenInit   ntlmssp_encode_ntlm2_type2_response_packet (spnego_encode_ntlm2_type3_packet)

//  int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key)
  bool do_setup_command ()
  {
    dualstringdecl(user_string)    ;*user_string     = pSmb2Session->user_name();
    dualstringdecl(password_string);*password_string = pSmb2Session->password() ;
    dualstringdecl(domain_string)  ;*domain_string    =pSmb2Session->domain()   ;


    if ( (user_string->ascii_length() > (RTSMB_CFG_MAX_USERNAME_SIZE - 1))   ||
       (password_string->ascii_length() > (RTSMB_CFG_MAX_PASSWORD_SIZE - 1)) ||
       (domain_string->ascii_length() > (RTSMB_CFG_MAX_DOMAIN_NAME_SIZE - 1)) )
    {
      pSmb2Session->diag_text_warning("bad arguments to setup command");
      return false;
    }
    if (pSmb2Session->session_state() <=  CSSN_STATE_DEAD)
    {
      pSmb2Session->diag_text_warning("setup command called but session is dead");
      return false;
    }
    if (pSmb2Session->user_state() != CSSN_USER_STATE_CHALLENGED)
    {
      pSmb2Session->diag_text_warning  ( "do_setup_command state != CSSN_USER_STATE_CHALLENGED state:%d", pSmb2Session->user_state());
      return false;
    }
    pSmb2Session->user_state(CSSN_USER_STATE_LOGGING_ON);
    pSmb2Session->user_uid(1);

    setup_blob = (byte *) setup_blob_phase_one;
    setup_blob_size = sizeof(setup_blob_phase_one);

    bool r = send_setup (); // (NetStreamInputBuffer &SendBuffer);
    if (r)
        r = receive_setup(); // (NetStreamInputBuffer &RecvBuffer);
    return r;
  }

  bool send_setup()
  {
      int send_status;
      NetNbssHeader       OutNbssHeader;
      NetSmb2Header       OutSmb2Header;
      NetSmb2SetupCmd     Smb2SetupCmd;

      byte *variable_content = (byte *) setup_blob;
      dword variable_content_size = setup_blob_size;

      NetSmb2NBSSSendCmd<NetSmb2SetupCmd> Smb2NBSSCmd(SMB2_SESSION_SETUP, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2SetupCmd, variable_content_size);
      dword in_variable_content_size    =  Smb2SetupCmd.SecurityBufferLength();    // not sure if this is right
      Smb2SetupCmd.StructureSize        =  Smb2SetupCmd.FixedStructureSize();
      Smb2SetupCmd.Flags                =  0x0;
      Smb2SetupCmd.SecurityMode         =  0x01;
      Smb2SetupCmd.Capabilities         =  0;
      Smb2SetupCmd.Channel              =  0;
      Smb2SetupCmd.SecurityBufferOffset =  0x58;
      Smb2SetupCmd.SecurityBufferLength =  variable_content_size;
      Smb2SetupCmd.PreviousSessionId    =  0;

      memcpy(OutSmb2Header.FixedStructureAddress()+Smb2SetupCmd.VariableContentOffset(), variable_content, variable_content_size);
      Smb2SetupCmd.addto_variable_content(variable_content_size); // can't use copyto because the offset if from base of message

      return Smb2NBSSCmd.flush();
  }

  bool receive_setup()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled;
    dword total_security_bytes_pulled=0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2SetupReply Smb2SetupReply;

    // Pull enough for the fixed part and then map pointers toi input buffer
    NetStatus r = pSmb2Session->RecvBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2SetupReply.PackedStructureSize(), bytes_pulled);
    if (r != NetStatusOk)
    {
      pSmb2Session->diag_text_warning("Socket error pulling recieve_setup message status:%d",r);
      return false;
    }
    NetSmb2NBSSRecvReply<NetSmb2SetupReply>  Smb2NBSSReply(SMB2_SESSION_SETUP, pSmb2Session, InNbssHeader,InSmb2Header, Smb2SetupReply);


    if (InSmb2Header.Status_ChannelSequenceReserved() !=  SMB_NT_STATUS_MORE_PROCESSING_REQUIRED && !do_extended_setup_phase)
    {
      pSmb2Session->diag_text_warning("receive_setup missing: SMB_NT_STATUS_MORE_PROCESSING_REQUIRED status:%x",InSmb2Header.Status_ChannelSequenceReserved());
      dword ssstatus =  InSmb2Header.Status_ChannelSequenceReserved();
      return false;
    }

    pSmb2Session->session_server_info_smb2_session_id = InSmb2Header.SessionId();
    if (Smb2SetupReply.SecurityBufferLength()&&Smb2SetupReply.SecurityBufferLength() < 2048)
    {
      dword security_bytes_pulled;
      r = pSmb2Session->RecvBuffer.pull_nbss_data(Smb2SetupReply.SecurityBufferLength(), security_bytes_pulled);
      if (r != NetStatusOk)
      {
        pSmb2Session->diag_text_warning("receive_setup recv  error pulling security buffer");
        return false;
      }
      if (Smb2SetupReply.SecurityBufferLength() != security_bytes_pulled)
      {
        pSmb2Session->diag_text_warning("receive_setup length error pulling security buffer");
        return false;
      }
      total_security_bytes_pulled += security_bytes_pulled;
      spnego_blob_size_from_server = std::max(Smb2SetupReply.SecurityBufferLength(),(word)MAXBLOB);
      pSmb2Session->user_state(CSSN_USER_STATE_CHALLENGED);
      memcpy( spnego_blob_from_server, InSmb2Header.FixedStructureAddress()+Smb2SetupReply.SecurityBufferOffset(), spnego_blob_size_from_server);
    }
    return true;
  }
  bool do_extended_setup_command()
  {
    class SpnegoClient spnegoWorker;
    do_extended_setup_phase=true;
    decoded_NegTokenTarg_challenge_t decoded_targ_token;
    bool r = spnegoWorker.spnego_decode_NegTokenTarg_challenge(&decoded_targ_token,
                 spnego_blob_from_server,
                 spnego_blob_size_from_server);
diag_dump_bin_fn(DIAG_INFORMATIONAL,"server challenge is: ", decoded_targ_token.ntlmserverchallenge,8);

//    decoded_targ_token.Flags;
//    decoded_targ_token.ntlmserverchallenge[8];
//typedef struct SecurityBuffer_s {  dword size;  word  offset;  byte  *value_at_offset;
//    decoded_targ_token.target_name;
//    decoded_targ_tokentarget_info;

//typedef struct SecurityBuffer_s {  dword size;  word  offset;  byte  *value_at_offset;
    byte session_key[16];
 int blob_length = rtsmb_cli_session_ntlm_auth (
    pSmb2Session->user_name(),
    pSmb2Session->password(),
    pSmb2Session->domain(),
    decoded_targ_token.ntlmserverchallenge,
    decoded_targ_token.target_info->value_at_offset,
    decoded_targ_token.target_info->size, session_key);

 diag_printf_fn(DIAG_INFORMATIONAL,"blob length is: %d", blob_length);

    if (blob_length && response_to_challenge)
    {
      pSmb2Session->session_key(session_key);     // Save the session key
diag_dump_bin_fn(DIAG_INFORMATIONAL,"calculated session key is: ", pSmb2Session->session_key(), 16);
      setup_blob = (byte *) response_to_challenge;
      setup_blob_size = blob_length;
      r = send_setup (); // (NetStreamInputBuffer &SendBuffer);
    }
    else
    {
      pSmb2Session->diag_text_warning("do_extended_setup_command error creating challenge" );
      r= false;
    }
    if (r)
      r = receive_setup(); // (NetStreamInputBuffer &RecvBuffer);
    return r;
  }
};


extern bool do_smb2_logon_server_worker(Smb2Session &Session)
{
  SmbLogonWorker LogonWorker(Session);
  return LogonWorker.do_logon_commands();
}


static const byte zero[8] = {0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0};         // zeros
char *myworkstation = "VBOXUNBUNTU";
// char *myworkstation = "VBOXUNBUNTU";

int SmbLogonWorker::rtsmb_cli_session_ntlm_auth ( char * user, char * password, char * domain, byte * serverChallenge, byte * serverInfoblock, int serverInfoblock_length,byte *session_key)
{

    rtsmb_util_guid(&session_key[0]);
//    rtsmb_util_guid(&session_key[8]);
    word workstation_name[32];
    rtsmb_util_ascii_to_unicode (myworkstation ,workstation_name, std::max((size_t)32,(strlen(myworkstation)+1)*2) );
    word user_name[32];
    rtsmb_util_ascii_to_unicode (user, user_name, std::max((size_t)32,2*(strlen(user)+1)));
    word domain_name[32];
    rtsmb_util_ascii_to_unicode (domain, domain_name, std::max((size_t)32,2*(strlen(domain)+1)));
    byte *pclient_blob;

    pclient_blob = &ntlm_response_buffer_ram[8];

    // The structure is 8 bytes unused, 8 bytes server challenge, followed by the blob which contains the signature, timestamp, and nonce
    // Prepend the 8 byte server challenge
    memcpy(pclient_blob, serverChallenge,8);
    pclient_blob += 8;
    class SpnegoClient spnegoWorker;
    // Append the 28 byte blob containing the client nonce
    spnegoWorker.spnego_get_client_ntlmv2_response_blob(pclient_blob);
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

    cli_util_client_encrypt_password_ntlmv2 (user_name, password, domain_name, serverChallenge, pclient_blob, client_blob_size, (char *) output);

    memcpy(&ntlm_response_buffer_ram[0],output,16);

    size_t ntlm_response_blob_size=
            spnegoWorker.spnego_encode_ntlm2_type3_packet(
              (byte *)response_to_challenge,
              (size_t)MAXBLOB, // ntlm_response_blob_size,
              (byte *)ntlm_response_buffer_ram,
              (int)ntlm_response_buffer_size,
              (byte *)domain_name, (byte *)user_name, (byte *)workstation_name, (byte *) session_key);

    return ntlm_response_blob_size;
}

// PFCHAR password, byte * serverChallenge, PFRTCHAR domainname, byte * ntlm_response_blob, size_t ntlm_response_blob_length, PFRTCHAR name, char * output)
//
extern unsigned char *RTSMB_MD4(const unsigned char *d, unsigned long n, unsigned char *md); //   { return 0; }
extern void hmac_md5( unsigned char*  text, int text_len, unsigned char*  key,int  key_len, unsigned char *digest); //  {}

byte * SmbLogonWorker::cli_util_client_encrypt_password_ntlmv2 (word * name, char * password, word * domainname, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, char * output)
{
  byte nameDomainname[(RTSMB_CFG_MAX_USERNAME_SIZE + 1) * 4];
  byte p21 [21];
  byte NTLMv2_Hash[16];
  int dst, src;
  size_t ndLen;

  // The NTLM password hash is obtained, this is the MD4 digest of the Unicode mixed-case password).
  // Convert the password to unicode
  dualstringdecl(upassword);   //   use a dualstring to convert the password to unicode
  *upassword = (char *)password;


   // p21 is actually p16 with 5 null bytes appended.  we just null it now
   // and fill it as if it were p16
   memset (&p21[16], 0, 5);
  // Convert the password to unicode
   // get md4 of password.  This is the 16-byte NTLM hash
   dst = upassword->utf16_length();
   diag_dump_unicode(DIAG_DEBUG,"cli_util_client_encrypt_password_ntlmv2 fixed passwd: ", (byte*)upassword->utf16(), dst);
   diag_dump_bin(DIAG_DEBUG,"cli_util_client_encrypt_password_ntlmv2 fixed passwd: ", upassword->utf16(), dst);
   RTSMB_MD4 ((const unsigned char *)upassword->utf16(), (dword)dst, p21);
   diag_dump_bin(DIAG_DEBUG,"cli_util_client_encrypt_password_ntlmv2 fixed pwhash: ", p21, 16);

    // The Unicode uppercase username is concatenated with the Unicode authentication target
    // (the domain or server name specified in the Target Name field of the Type 3 message).
    // Note that this calculation always uses the Unicode representation, even if OEM encoding
    // has been negotiated; also note that the username is converted to uppercase,
    // while the authentication target is case-sensitive and must match the case presented in the Target Name field.
   dualstringdecl(aname);   //   use a dualstring to convert the name to uppercase
   *aname = name;
   std::string s_name;
   s_name = (char *)aname->ascii();
   std::transform(s_name.begin(), s_name.end(), s_name.begin(), toupper);
   dualstringdecl(uname);   //   use a dualstring to convert the name to a string
   *uname = (char *)s_name.c_str();
   diag_dump_unicode(DIAG_DEBUG,"cli_util_client_encrypt_password_ntlmv2 fixed name: ", (byte*)uname->utf16(), uname->utf16_length());

   dualstringdecl(udomain);   //   use a dualstring to convert the domain to upper
   *udomain = domainname;
   diag_dump_unicode(DIAG_DEBUG,"cli_util_client_encrypt_password_ntlmv2 fixed domain: ", (byte*)udomain->utf16(), udomain->utf16_length());

    // The Unicode uppercase username is concatenated with the Unicode authentication target
    // (the domain or server name specified in the Target Name field of the Type 3 message).
    // Note that this calculation always uses the Unicode representation, even if OEM encoding
    // has been negotiated; also note that the username is converted to uppercase,
    // while the authentication target is case-sensitive and must match the case presented in the Target Name field.
//   ndLen = 2*rtsmb_util_wlen((PFWCS)name) + 2*rtsmb_util_wlen((PFWCS)domainname);
    ndLen = (uname->utf16_length() + udomain->utf16_length());
   // concatenate the uppercase username with the domainname
    memcpy((char *) nameDomainname, uname->utf16(), uname->utf16_length() );
    memcpy((char *) &nameDomainname[uname->utf16_length()], udomain->utf16(), udomain->utf16_length() );
   diag_dump_unicode(DIAG_DEBUG,"cli_util_encrypt_password_ntlmv2 fixed namedomain: ", nameDomainname, ndLen);
    diag_dump_bin(DIAG_DEBUG,"cli_util_encrypt_password_ntlmv2 fixed namedomain: ", nameDomainname, ndLen);

   // The HMAC-MD5 message authentication code algorithm is applied to
   // the unicode (username,domainname) using the 16-byte NTLM hash as the key.
   // This results in a 16-byte value - the NTLMv2 hash.
   hmac_md5(nameDomainname,    /* pointer to data stream */
               ndLen,        /* length of data stream */
               p21,             /* pointer to remote authentication key */
               16,              /* length of authentication key */
               NTLMv2_Hash);    /* caller digest to be filled in */
    byte output_value[16];
    // The HMAC-MD5 message authentication code algorithm is applied to this value using the 16-byte NTLMv2 hash
    // (calculated in step 2) as the key. This results in a 16-byte output value.
    // pntlmv2_blob = (ntlmv2_blob_t *) ntlm_response_blob;
    diag_dump_bin(DIAG_DEBUG,"cli_util_encrypt_password_ntlmv2 v2 hash: ", NTLMv2_Hash, 16);

    memcpy(concatChallenge, serverChallenge, 8);
    memcpy(&concatChallenge[8], ntlm_response_blob, ntlm_response_blob_length);
    diag_dump_bin(DIAG_DEBUG,"NTLMv2 concatChallenge: ", concatChallenge+8, ntlm_response_blob_length);
    hmac_md5(concatChallenge+8,  /* pointer to data stream */
               ntlm_response_blob_length,    /* length of data stream */
               NTLMv2_Hash,    /* pointer to remote authentication key */
               16,        /* length of authentication key */
               (byte * ) output);

    diag_dump_bin(DIAG_DEBUG,"cli_util_encrypt_password_ntlmv2 fixed md5hash: ", output, 16);
    return (byte * )output;
}
