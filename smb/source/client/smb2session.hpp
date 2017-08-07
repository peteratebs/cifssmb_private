//
// smb2session.hpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
//

#ifndef include_smb2session
#define include_smb2session



class Smb2Session {
public:
  Smb2Session() {};

  void rtsmb2_cli_session_new_with_ip (PFBYTE _ip, PFBYTE _broadcast_ip) { ip=_ip; broadcast_ip=_broadcast_ip;}

  int smb2_session_logon_server_worker();

  void rtsmb2_cli_negotiate_params(byte *_user_name, byte *_password, byte *_domain,RTSMB_CLI_SESSION_DIALECT _dialect=CSSN_DIALECT_SMB2_2002)
  { _p_user_name  = _user_name; _p_password   = _password ; _p_domain     = _domain   ; _p_dialect    = _dialect  ;    }

  int smb2_negotiate_worker();

  void rtsmb2_cli_share_parms(byte *sharename, byte *password)       {_p_sharename=sharename;_p_password=password;}

  int smb2_tree_connect_worker();

  int smb2_tree_disconnect_worker();
  // ignoring sharename for now, only one share at a time

  void rtsmb2_cli_query_parms (byte *_sharename, byte *pattern)     { _p_searchpattern = pattern;};

  int smb2_cli_query_worker ();


  int go(PFINT psid)
  {
     return do_rtsmb2_cli_session_new_with_ip (FALSE, psid);
  }


  RTSMB_CLI_SESSION_STATE session_state()    { return _p_pSession->state; }
  RTSMB_CLI_SESSION_USER_STATE user_state()  { return _p_pSession->user.state; }


  void update_timestamp()                    { rtsmb_cli_session_update_timestamp(_p_pSession); }
  void send_stalled_jobs()                   { rtsmb_cli_session_send_stalled_jobs (_p_pSession);  }
  int wait_on_job(PRTSMB_CLI_SESSION_JOB pJob)
  {
    int r =  INDEX_OF (_p_pSession->jobs, pJob);
    if(r < 0) return r;
    return wait_on_job_cpp(_p_sid, r);
  }
  PRTSMB_CLI_SESSION_JOB get_free_job ()
  {
    _p_pJob = rtsmb_cli_session_get_free_job(_p_pSession);
    return _p_pJob;
  }
  PRTSMB_CLI_SESSION_JOB pJob() { return _p_pJob; }


  int  sid()           {return _p_sid;       }
  byte *user_name()    {return _p_user_name; }


  byte *password()     {return _p_password;  }
  byte *domain()       {return _p_domain;    }
  byte *sharename()    {return _p_sharename;    }
  byte *sharepassword(){return _p_sharepassword;    }
  byte *searchpattern(){return _p_searchpattern;    }
  PRTSMB_CLI_SESSION pSession() {return _p_pSession; }
private:
  PFBYTE ip;
  PFBYTE broadcast_ip;
  PRTSMB_CLI_SESSION _p_pSession;
  RTSMB_CLI_SESSION_DIALECT _p_dialect;
  PRTSMB_CLI_SESSION_JOB    _p_pJob;
  int   _p_sid;
  byte *_p_user_name;
  byte *_p_password;
  byte *_p_domain;
  byte *_p_sharename;
  byte *_p_sharepassword;
  byte *_p_searchpattern;
  int do_rtsmb2_cli_session_new_with_ip (BBOOL blocking, PFINT psid);
};

#endif // include_smb2session
