//
// smb2session.cpp -
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



extern "C" {
#include "smbspnego.h" // void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
#include "rtpthrd.h" // void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
//int rtsmb_cli_session_ntlm_auth (int sid, byte * user, byte * password, byte *domain, byte * serverChallenge, byte *serverInfoblock, int serverInfoblock_length);
//void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid);
int rtsmb_cli_session_get_free_session (void);
void rtsmb_cli_session_memclear (PRTSMB_CLI_SESSION pSession);
void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession);

}

extern int do_smb2_logon_server_worker(Smb2Session &Session);
extern int do_smb2_tree_connect_worker(Smb2Session &Session);
extern int do_smb2_tree_disconnect_worker(Smb2Session &Session);
extern int do_smb2_negotiate_worker(Smb2Session &Session);
extern int do_smb2_cli_query_worker(Smb2Session &Session);


Smb2Session Smb2Sessions[1];



extern "C" int do_smb2_negotiate_worker(PRTSMB_CLI_SESSION pSession)
{
  return Smb2Sessions[0].smb2_negotiate_worker();
}
int Smb2Session::smb2_negotiate_worker()
{
  return do_smb2_negotiate_worker(*this);
}

extern "C" int rtsmb2_cli_session_new_with_ip (PFBYTE ip, PFBYTE broadcast_ip, BBOOL blocking, PFINT psid)
{

    Smb2Sessions[0].rtsmb2_cli_session_new_with_ip (ip, broadcast_ip);
    return Smb2Sessions[0].go(psid);
}
extern "C" int do_smb2_logon_server_worker(int sid,  byte *user_name, byte *password, byte *domain)
{
  Smb2Sessions[0].rtsmb2_cli_negotiate_params(user_name, password, domain,CSSN_DIALECT_SMB2_2002);
  return Smb2Sessions[0].smb2_session_logon_server_worker();
}
extern "C" int do_smb2_tree_connect_worker(int sid,  byte *share_name, byte *password)
{
  Smb2Sessions[0].rtsmb2_cli_share_parms (share_name, password);
  return Smb2Sessions[0].smb2_tree_connect_worker();
}
extern "C" int do_smb2_tree_disconnect_worker(int sid)
{
  return Smb2Sessions[0].smb2_tree_disconnect_worker();
}
int Smb2Session::smb2_tree_disconnect_worker()
{
  return do_smb2_tree_disconnect_worker(*this);
}
int Smb2Session::smb2_tree_connect_worker()
{
  return do_smb2_tree_connect_worker(*this);
}

int Smb2Session::smb2_session_logon_server_worker()
{
  return do_smb2_logon_server_worker(*this);
}

extern "C" int do_smb2_cli_query_worker(int doLoop,int sid, char *sharename,char *pattern)
{
  Smb2Sessions[0].rtsmb2_cli_query_parms ((byte*)sharename, (byte*)pattern);
  return Smb2Sessions[0].smb2_cli_query_worker();
}
int Smb2Session::smb2_cli_query_worker()
{
  return do_smb2_cli_query_worker(*this);
}
int Smb2Session::do_rtsmb2_cli_session_new_with_ip (BBOOL blocking, PFINT psid)
{
  int job_off;
  int r;

  cout_log(LL_JUNK) << "Yo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << endl;

  _p_sid = rtsmb_cli_session_get_free_session ();
  _p_pSession = rtsmb_cli_session_get_session (_p_sid);

  ASSURE (_p_pSession, RTSMB_CLI_SSN_RV_NOT_ENOUGH_RESOURCES);

  rtsmb_cli_session_update_timestamp (_p_pSession);

  rtsmb_cli_session_memclear (_p_pSession);

  _p_pSession->blocking_mode = blocking;

/* Force speaking over this dialect   */
  _p_pSession->server_info.dialect = CSSN_DIALECT_SMB2_2002;

  rtp_thread_handle((RTP_HANDLE *) &_p_pSession->owning_thread);

  if (broadcast_ip)
  {
      tc_memcpy (_p_pSession->broadcast_ip, broadcast_ip, 4);
  }
  else
  {
      tc_memcpy (_p_pSession->broadcast_ip, rtsmb_net_get_broadcast_ip (),4);
  }
  /* Attach an SMB2 session structure since that is our prefered dialect   */
  rtsmb_cli_smb2_session_init (_p_pSession);
  /* -------------------------- */
  /* start Negotiate Protocol - also setups callbacks for
   fake job to logon as anonymous */
  // job_off = rtsmb_cli_session_init (pSession, 0, ip);

  rtsmb_cli_wire_session_new (&_p_pSession->wire, 0, ip, 1);
  tc_strcpy (_p_pSession->server_name, "");

  tc_memcpy (_p_pSession->server_ip, ip, 4);
  job_off = do_smb2_negotiate_worker(_p_pSession);


  if (job_off < 0)
  {
      rtsmb_cli_session_close_session (_p_sid);
    return RTSMB_CLI_SSN_RV_DEAD;
  }

/* -------------------------- */
  if (psid) *psid = _p_sid;

  /* -------------------------- */
  if (_p_pSession->blocking_mode)
  {
      /* anonymous login not tried */
      /* wait for Negotiate Protocol to complete */
      r = rtsmb_cli_session_wait_for_job (_p_pSession, job_off);
      return(r);
  }
  else
  {
    return job_off;
  }
}
