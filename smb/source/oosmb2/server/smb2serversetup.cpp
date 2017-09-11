//
// smbservernegotiate.pp -
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

#include "smb2serverincludes.hpp"
#include "smb2spnego.hpp"

static void calculate_ntlmv2_signing_key(
  byte *encrypted_key,
  byte *security_blob,
  int blob_size,
  byte *user_name,
  int user_name_size,
  byte *domain_name,
  int domain_name_size,
  byte *password,
  int password_size,
  byte *session_key,
  int session_key_size,
  byte *signing_key_result);

static byte * cli_util_encrypt_password_ntlmv2 (char *password, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, word * name, word * domainname,byte * output);

static bool gl_display_login_info = true;
// session id seed for sessions we create
ddword  server_next_sessionid = 0;

static /*const*/ char ntlmssp_str[] = "NTLMSSP";

int Smb2ServerSession::ProcessSetup()
{
    byte *nbss_read_origin= (byte *) read_origin;
    nbss_read_origin-=4;
    NetNbssHeader            InNbssHeader;
    NetSmb2Header            InSmb2Header;
    NetSmb2SetupCmd          Smb2SetupCmd;

    InNbssHeader.bindpointers(nbss_read_origin);
    InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());
    Smb2SetupCmd.        bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());

    NetNbssHeader            OutNbssHeader;
    NetSmb2Header            OutSmb2Header;
    NetSmb2SetupReply        Smb2SetupReply;
    byte *nbss_write_origin= (byte *) write_origin;
    nbss_write_origin-=4;
    memset(nbss_write_origin, 0,OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2SetupReply.FixedStructureSize());
    OutNbssHeader.bindpointers(nbss_write_origin);
    OutSmb2Header.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize());
    Smb2SetupReply.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize());

    OutSmb2Header.InitializeReply(InSmb2Header);
    OutNbssHeader.nbss_packet_size = OutSmb2Header.FixedStructureSize()+ Smb2SetupReply.FixedStructureSize();
    Smb2SetupReply.StructureSize = Smb2SetupReply.FixedStructureSize();
    Smb2SetupReply.SecurityBufferOffset = OutSmb2Header.FixedStructureSize()+ Smb2SetupReply.PackedStructureSize();
    /* Pg 260 3. If SessionId in the SMB2 header of the request is non-zero reconnect otherwise the server MUST process the authentication request as specified in section 3.3.5.5.1. */
    if (InSmb2Header.SessionId()!=0)
    {  // Match it to a session ID. For now just fail
       OutSmb2Header.Status_ChannelSequenceReserved = SMB2_STATUS_INVALID_SMB;
    }

    server_next_sessionid += 1;   // create a unique session id.
    OutSmb2Header.SessionId = server_next_sessionid;


    session_state        = Session_State_InProgress;
    session_create_time  = rtsmb_util_get_current_filetime();

    session_idle_timebase   = rtp_get_system_msec();
    client_capabilities     = Smb2SetupCmd.Capabilities();

    byte *psecurityblob =      InSmb2Header.FixedStructureAddress()+Smb2SetupCmd.SecurityBufferOffset();
    dword spnego_blob_size   = Smb2SetupCmd.SecurityBufferLength();

    diag_dump_bin_fn(DIAG_INFORMATIONAL,"Setup blob:", psecurityblob, Smb2SetupCmd.SecurityBufferLength());

    dword ntlmssp_type = 0;
    if (memcmp(psecurityblob,ntlmssp_str, sizeof(ntlmssp_str))==0)
    {
      NetWiredword NtlmType;
      NtlmType.bindaddress(psecurityblob + sizeof(ntlmssp_str));
      ntlmssp_type = NtlmType();
    }

//    SpnegoClient spnegoWorker;
    decoded_NegTokenInit_t decoded_init_token;

    int isNegTokenInitNOT=1;
    if (ntlmssp_type == 0x1)  // ntlmssp is missing still
      isNegTokenInitNOT = 1; // spnegoWorker.process_ntlmssp_request(&decoded_targ_token, psecurityblob, Smb2SetupCmd.SecurityBufferLength());
    else
    {
      isNegTokenInitNOT = /* spnegoWorker. */spnego_decode_NegTokenInit_packet(&decoded_init_token, psecurityblob, (size_t ) Smb2SetupCmd.SecurityBufferLength());
      /* spnegoWorker. */spnego_decoded_NegTokenInit_destructor(&decoded_init_token);
    }
    if (isNegTokenInitNOT == 0)
    { // We got neg token init packet, send a challenge
#define HARDWIRED_DEBUG_ENCRYPTION_KEY 1
#if (HARDWIRED_DEBUG_ENCRYPTION_KEY==1)
        static byte b[8] = {0x01,0x23,0x45,0x67,0x89,0xab, 0xcd, 0xef};
  //           memcpy (&(pCtx->encryptionKey[0]), b, 8);
        memcpy (session_encryption_key, b, 8);
#else
        for (int i = 0; i < 4; i++)
        {
         word randnum = (word) std::rand();
         memcpy (&session_encryption_key[i * 2], &randnum, 2);
        }
#endif
        dword spnego_blob_output_size = 0;
        byte *spnego_blob_out_buffer = nbss_write_origin+OutNbssHeader.FixedStructureSize()+Smb2SetupReply.SecurityBufferOffset();
        if (ntlmssp_type == 0x1)
        {
          ;
//            spnego_blob_output_size =  ntlmssp_encode_ntlm2_type2_response_packet(spnego_blob_buffer, sizeof(spnego_blob_buffer),
//              decoded_targ_token.domain_name?decoded_targ_token.domain_name->value_at_offset:0,
//              decoded_targ_token.user_name?decoded_targ_token.user_name->value_at_offset:0,
//              decoded_targ_token.host_name?decoded_targ_token.host_name->value_at_offset:0,
//              pStream->pSmbCtx->encryptionKey);
         }
         else
         { // Plenty of space in the buffer so use 2048 as a max2048
           spnego_blob_output_size=/*spnegoWorker.*/spnego_encode_ntlm2_type2_response_packet(spnego_blob_out_buffer, 2048,session_encryption_key);
         }
         OutSmb2Header.Status_ChannelSequenceReserved = SMB2_STATUS_MORE_PROCESSING_REQUIRED;

         Smb2SetupReply.SecurityBufferLength = spnego_blob_output_size;
         diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO plobsize:%d setup packet size:%d \n",  OutNbssHeader.nbss_packet_size());

diag_dump_bin_fn(DIAG_INFORMATIONAL,"Output Setup blob:", spnego_blob_out_buffer, Smb2SetupReply.SecurityBufferLength());


         OutNbssHeader.nbss_packet_size =
         OutSmb2Header.FixedStructureSize()+Smb2SetupReply.PackedStructureSize()+Smb2SetupReply.SecurityBufferLength() - 4;
//         +Smb2SetupReply.SecurityBufferOffset()+Smb2SetupReply.SecurityBufferLength();
         diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO plobsize:%d setup packet size:%d \n", spnego_blob_output_size,  OutNbssHeader.nbss_packet_size());

         //pStream->WriteBufferParms[0].byte_count = spnego_blob_size;
         //pStream->WriteBufferParms[0].pBuffer = spnego_blob_buffer;
        // Spnego_isLast_token = 0;
    }
    else
    {
        int status = check_login_credentials(ntlmssp_type,psecurityblob, spnego_blob_size);
        diag_printf_fn(DIAG_INFORMATIONAL,"FuckWithSmb2OO status %d \n", status);
        OutNbssHeader.nbss_packet_size =
         OutSmb2Header.FixedStructureSize()+Smb2SetupReply.FixedStructureSize();
        if (status == 0)
          OutSmb2Header.Status_ChannelSequenceReserved = SMB2_NT_STATUS_SUCCESS;
        else
          OutSmb2Header.Status_ChannelSequenceReserved = SMB2_STATUS_ACCESS_DENIED;

    }
    return OutNbssHeader.nbss_packet_size()+4;
}

int Smb2ServerSession::check_login_credentials(dword ntlmssp_type,byte *psecurityblob, dword SecurityBufferLength)
{ // Check log- in credentials
  word  extended_authId=0;
  word  extended_access=AUTH_NOACCESS;
  word password_buffer[CFG_RTSMB_MAX_PASSWORD_SIZE+1];
  int  password_size = 0;
  int  status;
  byte *password;
  word *username=0;
  int NegTokenTargDecodeResult =-1;
//  decoded_NegTokenTarg_challenge_t decoded_targ_token;
  decoded_NegTokenTarg_t decoded_targ_token;
  int spnego_blob_size=0;

  // we have to send these
  byte  *pBuffer   = 0;
  dword byte_count = 0;

  if (ntlmssp_type == 0x3)
    ; // ; NegTokenTargDecodeResult = ntlmssp_decode_type2_response_packet(&decoded_targ_token, pStream->ReadBufferParms[0].pBuffer,pStream->ReadBufferParms[0].byte_count);
  else
  {
    NegTokenTargDecodeResult =
      spnego_decode_NegTokenTarg_packet(&decoded_targ_token, psecurityblob, SecurityBufferLength);
  }
  if (NegTokenTargDecodeResult == 0)
  {
    extended_access = spnego_AuthenticateUser (&decoded_targ_token, &extended_authId);
  }
  if (extended_access != AUTH_NOACCESS)
  {
    // The login succeeded now retrieve the password and calculate the signing key.
    // Some redundancy because the login looks up the password too.
    if (decoded_targ_token.user_name && decoded_targ_token.user_name->value_at_offset)
    {
      username = (word *)decoded_targ_token.user_name->value_at_offset;
      // Get password and convert the unicode string length to byte size
//      password_size =  2 * Auth_GetPasswordFromUserName((word *)decoded_targ_token.user_name->value_at_offset, password_buffer);
      const word *p = get_password_from_user_name((word *)decoded_targ_token.user_name->value_at_offset, password_size);
      if (p)
        memcpy(password_buffer, p, password_size);

      diag_dump_unicode_fn(DIAG_INFORMATIONAL,"Log in using db Password", password_buffer, password_size);
      password = (byte *)password_buffer;
    }
    if (!password_size)
    {
      diag_dump_unicode_fn(DIAG_INFORMATIONAL,"display_login_info: user not found:", decoded_targ_token.user_name->value_at_offset, decoded_targ_token.user_name->size);
    //              // Force it to "password"
    //              static byte glpassword[] = {'p',0,'a',0,'s',0,'s',0,'w',0,'o',0,'r',0,'d',0,0,0};
    //              diag_dump_bin_fn(DIAG_INFORMATIONAL,"DB lookup failed use global password", glpassword, sizeof(glpassword), DUMPUNICODE);
    //              password = (byte *) glpassword;
    //              password_size = sizeof(glpassword)-2;
    }
  }
  if (extended_access==AUTH_NOACCESS)
  {
    // Force the buffer to zero this will close the session and shut down the socket
    // Okay for both spnego and NTLMSSP
    spnego_decoded_NegTokenTarg_destructor(&decoded_targ_token);
    diag_printf_fn(DIAG_INFORMATIONAL,"!!!! spnego Auth failed, No access !!!! \n");
    pBuffer = 0;
    status=SMB2_STATUS_ACCESS_DENIED;
  }
  else
  {
    // If spnego encode
    if (ntlmssp_type == 0)
    {
      byte_count = spnego_encode_ntlm2_type3_response_packet(psecurityblob, SecurityBufferLength);
    }
    else
    {
      byte_count = 0;
    }
    // Calculate the session signing key
    if (decoded_targ_token.ntlm_response && decoded_targ_token.ntlm_response->size>16)
    {
         // Look up the password by user. Fail if not found.
         calculate_ntlmv2_signing_key(session_encryption_key,
           &decoded_targ_token.ntlm_response->value_at_offset[16],
           decoded_targ_token.ntlm_response->size-16,
           decoded_targ_token.user_name?decoded_targ_token.user_name->value_at_offset:0,
           decoded_targ_token.user_name?(int) decoded_targ_token.user_name->size:0,
           decoded_targ_token.domain_name?decoded_targ_token.domain_name->value_at_offset:0,
           decoded_targ_token.domain_name?(int) decoded_targ_token.domain_name->size:0,
           password,
           password_size,
           decoded_targ_token.session_key?decoded_targ_token.session_key->value_at_offset:0,
           decoded_targ_token.session_key?(int) decoded_targ_token.session_key->size:0,
           session_signing_key);
    }
    // Save off
//    pStream->psmb2Session->UserName = (byte *) rtsmb_util_wstrmalloc(decoded_targ_token.user_name?(word *)decoded_targ_token.user_name->value_at_offset:(word *)"U\0N\0K\0N\0O\0W\0N\0\0\0");
//    pStream->psmb2Session->DomainName = (byte *) rtsmb_util_wstrmalloc(decoded_targ_token.domain_name?(word *)decoded_targ_token.domain_name->value_at_offset:(word *)"U\0N\0K\0N\0O\0W\0N\0\0\0");
    spnego_decoded_NegTokenTarg_destructor(&decoded_targ_token);
    status = SMB2_NT_STATUS_SUCCESS;
  }
  return status;
}

static const byte zeros24[24]={};


word Smb2ServerSession::spnego_AuthenticateUser (void *_decoded_targ_token, word *extended_authId)
{
bool has_lm_field=false;
bool display_login_info=true;
decoded_NegTokenTarg_t *decoded_targ_token = (decoded_NegTokenTarg_t *) _decoded_targ_token;
    // decoded_targ_token is taken from the NTLM Type 3 message sent from the client
    // Note: pCtx->encryptionKey[] holds the key we sent
     //decoded_targ_token->Flags;              // Not used in non data gram connection scheme
// access = decode (pCtx, username, domainname, (PFCHAR)password_buf, (PFCHAR) password_buf2, &authId);

    if (display_login_info)
    {
      diag_printf_fn(DIAG_INFORMATIONAL, "\ndisplay_login_info: Authenticating user from SPNEGO PACCKET\n");
      if (decoded_targ_token->lm_response)       //
      {
          diag_dump_bin_fn(DIAG_INFORMATIONAL,"LMRESPONSE", decoded_targ_token->lm_response->value_at_offset, decoded_targ_token->lm_response->size);
          ;
      }
      if (decoded_targ_token->ntlm_response)
      {
          diag_dump_bin_fn(DIAG_INFORMATIONAL,"display_login_info: NTLMRESPONSE", decoded_targ_token->ntlm_response->value_at_offset, decoded_targ_token->ntlm_response->size);
      }
      if (decoded_targ_token->user_name)
      {
          diag_dump_unicode_fn(DIAG_INFORMATIONAL,"display_login_info: USER NAME", decoded_targ_token->user_name->value_at_offset, decoded_targ_token->user_name->size);
      }
      if (decoded_targ_token->domain_name)
      {
          diag_dump_unicode_fn(DIAG_INFORMATIONAL,"display_login_info: DOMAIN NAME", decoded_targ_token->domain_name->value_at_offset, decoded_targ_token->domain_name->size);
          ;
      }
      if (decoded_targ_token->host_name)
      {
          diag_dump_unicode_fn(DIAG_INFORMATIONAL,"display_login_info: HOST NAME", decoded_targ_token->host_name->value_at_offset, decoded_targ_token->host_name->size);
          ;
      }
      if (decoded_targ_token->session_key)
      {
          diag_dump_unicode_fn(DIAG_INFORMATIONAL,"display_login_info: SESSION KEY", decoded_targ_token->session_key->value_at_offset, decoded_targ_token->session_key->size);
          ;
      }
    }
    word Access=AUTH_NOACCESS;

    // Think of what security to use
    if (decoded_targ_token->lm_response && decoded_targ_token->lm_response->value_at_offset && memcmp(decoded_targ_token->lm_response->value_at_offset,zeros24,8)!=0)
       has_lm_field=true;

    // Make sure we have an nulled domain name buffer if none was passed.
    byte default_domainname_buffer[256];
    byte username_buffer[256];
    word * domainname = 0;
    word * username  = 0;
    if (decoded_targ_token->domain_name)
    {
      if (display_login_info) {diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: decoded_targ_token->domain_name->size:%d\n", decoded_targ_token->domain_name->size);}
      domainname = (word *) decoded_targ_token->domain_name->value_at_offset;
      memcpy(default_domainname_buffer,decoded_targ_token->domain_name->value_at_offset,decoded_targ_token->domain_name->size);
      default_domainname_buffer[decoded_targ_token->domain_name->size]=0;
      default_domainname_buffer[decoded_targ_token->domain_name->size+1]=0;
      domainname = (word *)default_domainname_buffer;
    }
    else
    {
      default_domainname_buffer[0] = 0;
      default_domainname_buffer[1] = 0;
      domainname = (word *)default_domainname_buffer;
    }
    if (decoded_targ_token->user_name)
    {
      if (display_login_info) {diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: decoded_targ_token->user_name->size:%d\n", decoded_targ_token->user_name->size);}
      memcpy(username_buffer,decoded_targ_token->user_name->value_at_offset,decoded_targ_token->user_name->size);
      username_buffer[decoded_targ_token->user_name->size]=0;
      username_buffer[decoded_targ_token->user_name->size+1]=0;
      username = (word *)username_buffer;
    }
    else
    {
      if (display_login_info) { diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: No domain\n");}
      default_domainname_buffer[0] = 0;
      default_domainname_buffer[1] = 0;
      domainname = (word *)default_domainname_buffer;
    }

    // Try ntlmv2
    if (decoded_targ_token->ntlm_response)
    {
      Access = Auth_AuthenticateUser_ntlmv2 (decoded_targ_token->ntlm_response->value_at_offset, (size_t) decoded_targ_token->ntlm_response->size,username, domainname);
      if (display_login_info) { diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: Auth_AuthenticateUser_ntlmv2 returned %X\n", Access);   }
      diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: Auth_AuthenticateUser_ntlmv2 returned %X\n", Access);
    }
    if (Access == AUTH_NOACCESS)
    {
      diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: Not authenticated after User_ntlmv2. Give up %X\n", Access);
    }
// Jump past all but ntlmv2. The rest are not supported and may be buggy
resume_with_access:
    if (display_login_info) {diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: Auth_AuthenticateUser should be removed \n");}
    diag_printf_fn(DIAG_INFORMATIONAL,"Log in worked, stiill need to set up session\n");
#if(0)
    {
    int i;
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
    {
        if (pCtx->uids[i].uid == pCtx->uid)
        {
          if (display_login_info) { diag_printf_fn(DIAG_INFORMATIONAL,"display_login_info: Auth_AuthenticateUser did removed %d \n", i);}
          pCtx->uids[i].inUse = false;
          break;
        }
    }
    }
#endif
    // See if it impacts client first
//    if (Access == AUTH_NOACCESS)
//    {
//     Access=Auth_AuthenticateUser (pCtx, decoded_targ_token->user_name->value_at_offset, 0, decoded_targ_token->lm_response->value_at_offset, 0,  extended_authId);
//    }
#if (HARDWIRED_FORCE_EXTENDED_SECURITY_OK)
    if (Access == AUTH_NOACCESS)
    {
      diag_printf_fn(DIAG_INFORMATIONAL,"Fake success by returning %X\n",AUTH_USER_MODE);     // #if (HARDWIRED_FORCE_EXTENDED_SECURITY_OK)
      Access = AUTH_USER_MODE;
    }
#endif
    if (display_login_info)  {diag_printf_fn(DIAG_INFORMATIONAL,"\nprtsmb_srv_ctx->display_login_info: Authenticate user from SPNEGO PACCKET v=%d \n", Access);}
    diag_printf_fn(DIAG_INFORMATIONAL,"\ndAuthenticate user (0==OK) result: %d \n", Access);
    return Access;
}


word Smb2ServerSession::Auth_AuthenticateUser_ntlmv2 (byte *ntlm_response_blob, size_t ntlm_response_blob_length, word *name, word *domainname)
{
    word rv = AUTH_NOACCESS;
    byte *output = (byte *)smb_rtp_malloc(1024);
    dualstringdecl(ascii_name_factory);      // autoptr releases itself
    *ascii_name_factory = name;               // assign as utf16 and derefence as acscii
    char *ascii_name = ascii_name_factory->ascii();
    const char *user_password = 0;

    if (resistered_users.find(ascii_name)!=resistered_users.end())
      user_password = resistered_users[ascii_name].c_str();

    // This is the wild west so chak all args that we use.
    if (user_password)
    {
// see byte * SmbLogonWorker::cli_util_client_encrypt_password_ntlmv2 (word * name, char * password, word * domainname, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, char * output)
        cli_util_encrypt_password_ntlmv2 ((char *)user_password, session_encryption_key, ntlm_response_blob, ntlm_response_blob_length, name, domainname,output);
        if (memcmp(ntlm_response_blob, output, 16) == 0)
        {
           rv = 0;
        }
    }
    smb_rtp_free(output);
    return rv;
}

#include "smb_md4.hpp"
#include "hmac_md5.hpp"
#include "rc4.hpp"
extern void hmac_md5( unsigned char*  text, int text_len, unsigned char*  key,int  key_len, unsigned char *digest);

static int trim_right_null(byte *string_name, int string_size)
{
  if (string_size >= 2 && string_name[string_size-2]==0&&string_name[string_size-1]==0)
    return string_size - 2;
  else
    return string_size;
}
static void cli_util_nt_password_hash(byte *password, int password_l, byte *output)
{
  RTSMB_MD4(password, password_l, output);
}
static void cli_util_encrypt_signing_key_response (byte * owf, byte * user, int user_l, byte * domain, int domain_l,byte output[16])
{
  byte concatChallenge[1024];
  byte output_value[16];
  memcpy(concatChallenge, user, user_l);
  if (domain)
    memcpy(concatChallenge+user_l, domain, domain_l);
    hmac_md5(concatChallenge,    /* pointer to data stream */
               user_l+domain_l,  /* length of data stream */
               &owf[0],          /*  */
               16,               /* length of authentication key */
               (byte * ) output_value);
    if (gl_display_login_info) {rtsmb_dump_bytes("cli_util_encrypt_signing_key_response output: ", output_value, 16, DUMPBIN);}
    memcpy(&output[0], output_value, 16);

}



static void cli_util_encrypt_signing_key_ntlmv2 (byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, byte *kr, char * output)
{
    // The HMAC-MD5 message authentication code algorithm is applied to
    // the unicode (username,domainname) using the 16-byte NTLM hash as the key.
    // This results in a 16-byte value - the NTLMv2 hash.
    byte concatChallenge[1024];
    byte output_value[16];
   // The HMAC-MD5 message authentication code algorithm is applied to this value using the 16-byte NTLMv2 hash
   // Passed in blob length
   // (calculated in step 2) as the key. This results in a 16-byte output value.
   memcpy(concatChallenge, serverChallenge, 8);
   memcpy(&concatChallenge[8], ntlm_response_blob, ntlm_response_blob_length);
//    rtsmb_dump_bytes("NTLMv2 hash: ", NTLMv2_Hash, 16, DUMPBIN);
//    rtsmb_dump_bytes("NTLMv2 concatChallenge: ", concatChallenge, ntlm_response_blob_length+8, DUMPBIN);
    hmac_md5(concatChallenge,    /* pointer to data stream */
               ntlm_response_blob_length+8,        /* length of data stream */
               &kr[0],             /*  */
               16,                /* length of authentication key */
               (byte * ) output_value);

    memcpy(&output[0], output_value, 16);

}


static void calculate_ntlmv2_signing_key(
  byte *encrypted_key,
  byte *security_blob,
  int blob_size,
  byte *user_name,
  int user_name_size,
  byte *domain_name,
  int domain_name_size,
  byte *password,
  int password_size,
  byte *session_key,
  int session_key_size,
  byte *signing_key_result)
{
byte encsignkey[16];
byte kr[16];
byte outowf[16];
RC4_KEY rc4_key;
byte sess_key[16];
byte user_domain[512];
  if (gl_display_login_info)
  {
    diag_dump_bin_fn(DIAG_INFORMATIONAL, "server challenge was:  ", encrypted_key, 8);
    diag_dump_bin_fn(DIAG_INFORMATIONAL, "blob:  ", security_blob, blob_size);
  }
  // Hash the password
  cli_util_nt_password_hash(password, password_size, outowf);
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "NTLMv2 owf nt hash: ", outowf, 16);}
  rtsmb_util_string_to_upper ((char *) user_name);
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "User", user_name,user_name_size);}
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "Domain", domain_name,domain_name_size);}

  user_name_size = trim_right_null(user_name,user_name_size);
  if (user_name_size > 0)
    memcpy(user_domain,user_name,user_name_size);

  domain_name_size = trim_right_null(domain_name,domain_name_size);
  if (domain_name_size > 0)
    memcpy(&user_domain[user_name_size],domain_name,domain_name_size);

  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "User_Domain", user_domain, user_name_size+domain_name_size);}
  // Encrypt the user and domain. (not doing domain now)
  cli_util_encrypt_signing_key_response (outowf, user_domain, user_name_size+domain_name_size, 0, 0,kr);
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "NTLMv2 enrypted key calculated output: ", kr, 16);}

   // Comes from  pStream->psmb2Session->pSmbCtx->encryptionKey, the encrypted key send by the client.
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "Security blob: ", security_blob, blob_size);}


  cli_util_encrypt_signing_key_ntlmv2 ((byte *)encrypted_key, (byte *)security_blob, (size_t) blob_size, (byte *) kr, (char *)encsignkey);

  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "NTLMv2 key_ntlmv2 encsignkey: ", encsignkey, 16);}

//  SMBsesskeygen_ntv2(const uint8_t kr[16], const uint8_t * nt_resp, uint8_t sess_key[16])
// output from cli_util_encrypt_signing_key_ntlmv2  == CE 98 06 7A BA 98 03 80   AF 1C 6C 04 A9 95 87 38
  // hash the encrypted user name with the signing
  hmac_md5(encsignkey ,16,  kr, 16,sess_key);
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "SMBsesskeygen_ntv2: ", sess_key, 16);}
  // should be  0x63, 0xA2, 0x4F, 0xB3, 0x81, 0x6B, 0x85, 0x99, 0xEC, 0xBA, 0x0D, 0x04, 0xB0, 0x8A, 0xC7, 0xCC};          // Output of SMBsesskeygen_ntv2

  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "session_key: ", session_key, session_key_size);}

  RC4_set_key(&rc4_key, 16, sess_key);
  RC4(&rc4_key, session_key_size, session_key, signing_key_result);    // Session key sent from client in setup request 2
  // RC4(&rc4_key, sizeof(glencsessionkey), glencsessionkey, signing_key_result);    - PETERPETER HEREHERE -     // Session key sent from client in setup request 2
  if (gl_display_login_info) {diag_dump_bin_fn(DIAG_INFORMATIONAL, "signing_key_result: ", signing_key_result, 16);}
}

static byte * cli_util_encrypt_password_ntlmv2 (char *password, byte * serverChallenge, byte * ntlm_response_blob, size_t ntlm_response_blob_length, word * name, word * domainname,byte * output)
{
  byte unicode_lendian[(RTSMB_CFG_MAX_PASSWORD_SIZE + 1) * 2];
  byte nameDomainname[(RTSMB_CFG_MAX_USERNAME_SIZE + 1) * 4];
  byte p21 [21];
  byte NTLMv2_Hash[16];
  int dst, src, ndLen, ndLenFirstHalf;
  memset (nameDomainname, 0, sizeof(nameDomainname)); // should not be needed but do anyway

  // p21 is actually p16 with 5 null bytes appended.  we just null it now
  // and fill it as if it were p16
  memset (&p21[16], 0, 5);
    // The NTLM password hash is obtained (as discussed previously, this is the MD4 digest of the Unicode mixed-case password).
  // Convert the password to unicode
  for (src=0, dst=0; src<=CFG_RTSMB_MAX_PASSWORD_SIZE && password[src]; src++)
  {
    unicode_lendian[dst++] = (byte)password[src];
    unicode_lendian[dst++] = 0;
  }
diag_dump_bin_fn(DIAG_INFORMATIONAL,"new: unicode_lendian passwd: ", unicode_lendian, dst);
  // get md4 of password.  This is the 16-byte NTLM hash
  RTSMB_MD4 (unicode_lendian, (dword)dst, p21);
diag_dump_bin_fn(DIAG_INFORMATIONAL,"new: p21: ", p21, 21);

    // The Unicode uppercase username is concatenated with the Unicode authentication target
    // (the domain or server name specified in the Target Name field of the Type 3 message).
    // Note that this calculation always uses the Unicode representation, even if OEM encoding
    // has been negotiated; also note that the username is converted to uppercase,
    // while the authentication target is case-sensitive and must match the case presented in the Target Name field.
  for (src=0, ndLenFirstHalf=0; src<=RTSMB_CFG_MAX_USERNAME_SIZE && name[src]; src++)
  {
    nameDomainname[ndLenFirstHalf++] = (byte)std::toupper ( (int) name[src] );
    nameDomainname[ndLenFirstHalf++] = (byte) 0;
  }
  dualstringdecl(name_len_factory);           // autoptr releases itself
  dualstringdecl(domain_len_factory);      // autoptr releases itself

  *name_len_factory = (word *)name;
  *domain_len_factory = (word *)domainname;

  ndLen = name_len_factory->utf16_length()+domain_len_factory->utf16_length();
  // concatenate the uppercase username with the domainname

  memcpy(&nameDomainname[ndLenFirstHalf], domainname, domain_len_factory->utf16_length());
diag_dump_bin_fn(DIAG_INFORMATIONAL,"new: nameDomainname: ", nameDomainname, ndLen);

//  memcpy(&nameDomainname[name_len_factory.utf16_length()], domainname, domain_len_factory.utf16_length());

  // The HMAC-MD5 message authentication code algorithm is applied to
  // the unicode (username,domainname) using the 16-byte NTLM hash as the key.
  // This results in a 16-byte value - the NTLMv2 hash.
  hmac_md5(nameDomainname,    /* pointer to data stream */
               ndLen,        /* length of data stream */
               p21,             /* pointer to remote authentication key */
               16,              /* length of authentication key */
               NTLMv2_Hash);    /* caller digest to be filled in */
    byte concatChallenge[1024];
    byte output_value[16];
diag_dump_bin_fn(DIAG_INFORMATIONAL,"old: NTLMv2_Hash: ", NTLMv2_Hash, 16);
    // The HMAC-MD5 message authentication code algorithm is applied to this value using the 16-byte NTLMv2 hash
    // Passed in blob length
    // (calculated in step 2) as the key. This results in a 16-byte output value.
    ntlm_response_blob_length = ntlm_response_blob_length-16;

    memcpy(concatChallenge, serverChallenge, 8);
    memcpy(&concatChallenge[8], ntlm_response_blob+16, ntlm_response_blob_length);
diag_dump_bin_fn(DIAG_INFORMATIONAL, "new: concatChallenge: ", concatChallenge, ntlm_response_blob_length+8);

//    rtsmb_dump_bytes("NTLMv2 hash: ", NTLMv2_Hash, 16, DUMPBIN);
//    rtsmb_dump_bytes("NTLMv2 concatChallenge: ", concatChallenge, ntlm_response_blob_length+8, DUMPBIN);
    hmac_md5(concatChallenge,  /* pointer to data stream */
               (int)ntlm_response_blob_length+8,    /* length of data stream */
               NTLMv2_Hash,    /* pointer to remote authentication key */
               16,        /* length of authentication key */
               (byte * ) output_value);
//    rtsmb_dump_bytes("NTLMv2 real concatChallenge output: ", output_value, 16, DUMPBIN);
diag_dump_bin_fn(DIAG_INFORMATIONAL, "new: NTLMv2 real concatChallenge output:: ", output_value, 16);

    // This value is concatenated with the blob to form the NTLMv2 response.
  memcpy(&output[0], output_value, 16);
  memcpy(&output[16], ntlm_response_blob+16, ntlm_response_blob_length-16);

  return (byte * )output;
}
