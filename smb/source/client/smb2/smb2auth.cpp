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



extern int do_smb2_extended_setup_server_worker(NewSmb2Session &Session,byte * serverChallenge, byte * serverInfoblock, int serverInfoblock_length);


// This is fixed negTokeninit, mechType1 ... see wireshark for decode
static const byte setup_blob[] = {0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04,0x28,0x4e,0x54,0x4c,0x4d,0x53,
0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x97,0x82,0x08,0xe2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0xd7,0x3a,0x00,0x00,0x00,0x0f};


class SmbExtendedSetupWorker {
public:
  SmbExtendedSetupWorker(NewSmb2Session &_Session)
  {  // Constructor that takes a sesstion
    pSmb2Session = &_Session;
    _SmbExtendedSetupWorker();
  }
  int go()   { return  _SmbExtendedSetupWorker(); };
  byte * serverChallenge; byte * serverInfoblock; int serverInfoblock_length;
private:
  NewSmb2Session *pSmb2Session;
  int _SmbExtendedSetupWorker() {return -1;};
};


extern int do_smb2_extended_setup_server_worker(NewSmb2Session &Session,byte * serverChallenge, byte * serverInfoblock, int serverInfoblock_length)
{
SmbExtendedSetupWorker Worker(Session);
    Worker.serverChallenge=serverChallenge; Worker.serverInfoblock=serverInfoblock;  Worker.serverInfoblock_length=serverInfoblock_length;;
    return 0;
//    r = rtsmb2_cli_session_ntlm_auth (0,pSmb2Session->user_name(), pSmb2Session->password(), pSmb2Session->domain(), serverChallenge, serverInfoblock,  serverInfoblock_length);
//  SmbLogonWorker LogonWorker(Session);
//  return LogonWorker.go();
}

#if(0)
int rtsmb_cli_session_ntlm_auth (int sid, PFCHAR user, PFCHAR password, PFCHAR domain, PFBYTE serverChallenge, PFBYTE serverInfoblock, int serverInfoblock_length)
{
    PRTSMB_CLI_SESSION_JOB pJob;
    PRTSMB_CLI_SESSION pSession;

    byte ntlm_response_buffer_ram[1024];

#if (DEBUG_LOGON)
    rtp_printf("PVO - rtsmb_cli_session_ntlm_auth \n");
#endif

    pSession = rtsmb_cli_session_get_session (sid);
    ASSURE (pSession, RTSMB_CLI_SSN_RV_BAD_SID);
    ASSURE (pSession->state > CSSN_STATE_DEAD, RTSMB_CLI_SSN_RV_DEAD);
    rtsmb_cli_session_update_timestamp (pSession);

    pJob = rtsmb_cli_session_get_free_job (pSession);
    ASSURE (pJob, RTSMB_CLI_SSN_RV_TOO_MANY_JOBS);
    pJob->data.ntlm_auth.user_struct = &pSession->user;

    byte session_key[16];
    rtsmb_util_guid(&session_key[0]);
    rtsmb_util_guid(&session_key[8]);
    byte workstation_name[32];
    rtsmb_util_ascii_to_unicode ("workstation" ,workstation_name , CFG_RTSMB_USER_CODEPAGE);
    byte user_name[32];
    rtsmb_util_ascii_to_unicode (user, user_name, CFG_RTSMB_USER_CODEPAGE);
    byte domain_name[32];
    rtsmb_util_ascii_to_unicode (domain, domain_name, CFG_RTSMB_USER_CODEPAGE);
    byte *pclient_blob;

    pclient_blob = &ntlm_response_buffer_ram[8];

    // The structure is 8 bytes unused, 8 bytes server challenge, followed by the blob which contains the signature, timestamp, and nonce
    // Prepend the 8 byte server challenge
    tc_memcpy(pclient_blob, serverChallenge,8);
    pclient_blob += 8;
    // Append the 28 byte blob containing the client nonce
    spnego_get_client_ntlmv2_response_blob(pclient_blob);
    pclient_blob += 28;
    // Append the target information block pqassed from the server
    tc_memcpy(pclient_blob, serverInfoblock,serverInfoblock_length);

    pclient_blob += serverInfoblock_length;

    tc_memcpy(pclient_blob,zero,4);
    pclient_blob += 4;

    pclient_blob = &ntlm_response_buffer_ram[8];
    // The size of the blob to run the digest on
    int client_blob_size = 8 + 28 + serverInfoblock_length + 4;
    // The size of the blob plus digest
    int ntlm_response_buffer_size = 16 + 28 + serverInfoblock_length + 4;
#if (DEBUG_LOGON)
    rtp_printf("PVO - call cli_util_client_encrypt_password_ntlmv2 !! \n");
#endif
    byte output[16];
    cli_util_client_encrypt_password_ntlmv2 (user_name, password, domain_name, serverChallenge, pclient_blob, client_blob_size, output);
    tc_memcpy(&ntlm_response_buffer_ram[0],output,16);
#if (DEBUG_LOGON)
    rtsmb_dump_bytes("cli_util_client_encrypt_password_ntlmv2: ", output, 16, DUMPBIN);
#endif

    pJob->data.ntlm_auth.ntlm_response_blob_size = spnego_encode_ntlm2_type3_packet(&pJob->data.ntlm_auth.ntlm_response_blob[0], sizeof(pJob->data.ntlm_auth.ntlm_response_blob), ntlm_response_buffer_ram, ntlm_response_buffer_size, domain_name, user_name, workstation_name, session_key);

    rtsmb_dump_bytes("spnego_encode_ntlm2_type3_packet output: ", pJob->data.ntlm_auth.ntlm_response_blob, pJob->data.ntlm_auth.ntlm_response_blob_size, DUMPBIN);

#if 0
    //0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00}; // 0x0101000 00000000
    //rtsmb_util_get_current_filetime();       // timestamp
    //spnego_get_Guid(response.guid);          // 8 bytes random
    //0000000                                  // zero

    int ntlm_response_blob_length = spnego_get_client_ntlmv2_response_blob(&pJob->data.ntlm_auth.ntlm_response_blob[16]);

    // Concatenate the target information block from the server.
    tc_memcpy(&pJob->data.ntlm_auth.ntlm_response_blob[16+ntlm_response_blob_length],serverInfoblock,serverInfoblock_length);
    // 4 bytes zeros at the end
    tc_memcpy(&pJob->data.ntlm_auth.ntlm_response_blob[16+ntlm_response_blob_length+serverInfoblock_length],zero,4);
    // We then concatenate the Type 2 challenge with our blob (in front)
    tc_memcpy(&pJob->data.ntlm_auth.ntlm_response_blob[8],serverChallenge,8);

    PFBYTE pblob = &pJob->data.ntlm_auth.ntlm_response_blob[8];
    size_t blob_length = ntlm_response_blob_length+8+serverInfoblock_length;
    // Applying HMAC-MD5 to this value using the NTLMv2 hash from step 2 as the key gives us the 16-byte value "0xcbabbca713eb795d04c97abc01ee4983".
    byte output[16];
    cli_util_client_encrypt_password_ntlmv2 (user, password, domain, serverChallenge, pblob, blob_length, output);


    // This value is concatenated with the blob to obtain the NTLMv2 response
    tc_memcpy(&pJob->data.ntlm_auth.ntlm_response_blob[0],output,16);
    blob_length = ntlm_response_blob_length+8+serverInfoblock_length;
// BUG !!!    pJob->data.ntlm_auth.ntlm_response_blob_size = ntlm_response_blob_length+16;
    pJob->data.ntlm_auth.ntlm_response_blob_size = blob_length+16;
#endif

#if (DEBUG_LOGON)
    rtp_printf("PVO - rtsmb_cli_session_ntlm_auth go !! \n");
#endif


    if (RTSMB_ISSMB2_DIALECT(pSession->server_info.dialect))
      pJob->smb2_jobtype = jobTsmb2_session_setup_phase_2;

    pJob->error_handler    = rtsmb_cli_session_send_session_extended_setup_error_handler;
    pJob->receive_handler  = rtsmb_cli_session_receive_session_extended_logon;
    pJob->send_handler     = rtsmb_cli_session_send_session_extended_setup;

    rtsmb_cli_session_send_stalled_jobs (pSession);

    if (pSession->blocking_mode)
    {
        int r;
rtp_printf("USER LOGON: WAIT\n");
        r = rtsmb_cli_session_wait_for_job (pSession, INDEX_OF (pSession->jobs, pJob));
rtp_printf("USER LOGON: DONE WAIT returned %d\n", r);
        return(r);
    }
    else
    {
        return INDEX_OF (pSession->jobs, pJob);
    }
}
#endif
