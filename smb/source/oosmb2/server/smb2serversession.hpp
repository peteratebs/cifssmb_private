//
// smbserversession.hpp -
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

#ifndef include_smbserversession
#define include_smbserversession


#define RTSMB_CFG_MAX_SHARES_PER_SERVER_SESSION 2

typedef struct session_file_instance_t {
  bool  in_use;
  int   session_file_id;    // index in the session file table
  int   int_file_id;        // index in the server file table
} session_file_instance;


class Smb2ServerSession : public smb_diagnostics {
public:

// - Use these istead of smb1 structures
//  RTSMB2_CLI_SESSION_USER  user;
//  RTSMB2_CLI_SESSION_SHARE share;
//  Smb2ServerSession() ;
  Smb2ServerSession();
  void AttachLegacyBuffers(byte *_read_origin, dword _read_size, byte *_write_origin, dword _write_size);

  int SessionIndex();

  int ProcessNegotiate();
  int ProcessSetup();
  int ProcessTreeconnect();
  int ProcessCreate();
  int ProcessEcho();
  int ProcessQueryDirectory();

  int check_login_credentials(dword ntlmssp_type,byte *psecurityblob, dword SecurityBufferLength);
  word spnego_AuthenticateUser (/* decoded_NegTokenTarg_t*/ void *decoded_targ_token, word *extended_authId);
  const word *get_password_from_user_name( word *username, int &return_pwd_width_bytes);
  word Auth_AuthenticateUser_ntlmv2 (byte *ntlm_response_blob, size_t ntlm_response_blob_length, word *name, word *domainname);

  session_file_instance *allocate_session_file();
  void release_session_file(session_file_instance *pFileInstance);

  NetStreamOutputBuffer     SendBuffer;
  NetStreamInputBuffer      RecvBuffer;
private:
#define Session_State_Idle        0
#define Session_State_InProgress  1
#define Session_State_Valid       2
#define Session_State_Expired     3
  /* The current activity state of this session. This value MUST be either InProgress, Valid, or Expired. */
  byte     session_state;
  ddword   session_create_time;
  dword    session_idle_timebase;
  byte     session_encryption_key[8];
  byte     session_signing_key[16];
  ddword   sessionid;                 /* For selecting this session by id sent from the client. Copied in by us from ddword  server_next_sessionid */

  byte    *UserName;                  /* The name of the user who established the session. */
  byte    *DomainName;                /* The domain of the user who established the session. */

  int  _p_sessionindex;
  int _p_reply_buffer_size;
  int _p_send_buffer_size;
  byte *_p_send_buffer_raw;
  byte *_p_reply_buffer_raw;
  SmbSocket_c        SmbSocket;
  StreamBufferDataSource SocketSource;
  struct SocketContext sourcesockContext;
  DataSinkDevtype     SocketSink;
  struct SocketContext sinksockContext;
  bool connect_buffers() ;
  bool disconnect_buffers() ;

  // properties recieved from the client
  dword  client_capabilities;

  // properties inhereted from the environment.
  byte server_guid[16];
  dword  server_max_transaction_size;
  dword  server_global_caps;
  bool   server_require_signing;

  std::map<std::string, std::string> resistered_users;

  // link external FID to internal fid
  session_file_instance session_file_table[RTSMB_CFG_MAX_FILES_PER_SESSION];

  // temporary stealing from old stream stuff
  byte *read_origin;
  dword read_size;
  byte *write_origin;
  dword write_size;


};


#if(0)

class Smb2File {
public:
  Smb2File()  { memset(file_id,0,16); file_name="";file_name_unicode = 0; }
  ~Smb2File() { set_file_free();}
  void set_filename(char *filename)
  {
    size_t w;
    file_name = filename;
    w=rtp_strlen(filename)*2+2;
    file_name_unicode=(word*)smb_rtp_malloc(w);
    rtsmb_util_ascii_to_unicode (filename ,file_name_unicode, w);
  }
  const char *get_filename_ascii()  { return file_name.c_str(); }
  word *get_filename_utf16()  { return file_name_unicode;  };
  byte *get_file_id()    { return file_id;  };
  void set_fileid(byte *fileid)  { allocated=true;memcpy(file_id, fileid,16);  };
  void set_file_free() {file_name = ""; if(file_name_unicode) smb_rtp_free(file_name_unicode);memset(file_id,0,16);}
  bool  allocated;
private:
  byte  file_id[16];
  std::string file_name;
  word   *file_name_unicode;
};


bool checkSessionSigned();
void setCurrentActiveSession(Smb2ServerSession *CurrentActiveSession);
extern Smb2ServerSession *getCurrentActiveSession();
// calling this from a static funtion rather than a class method of session, not sure why for now
void setSessionSocketError(Smb2ServerSession *pSmb2ServerSession, bool isSendError, NetStatus SmbStatus);

Smb2ServerSession *FileIdToSession(dword Fileid);
inline int   FileIdToSharenumber(dword Fileid)     {return (int)(Fileid>>16)&0xff;}
inline int   FileIdToFilenumber(dword Fileid)      {return (int)(Fileid&0xffff);}


#endif // 0
#endif // include_smb2session
