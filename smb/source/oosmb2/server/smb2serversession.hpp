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

class Smb2ServerSession : public smb_diagnostics {
public:

// - Use these istead of smb1 structures
//  RTSMB2_CLI_SESSION_USER  user;
//  RTSMB2_CLI_SESSION_SHARE share;
//  Smb2ServerSession() ;
  Smb2ServerSession()
  {
  }
  NetStreamOutputBuffer     SendBuffer;
  NetStreamInputBuffer      RecvBuffer;
private:
//  int                _p_session_number;
//  int                _p_session_state;
//  int                _p_sid;
//  dword              _p_timestamp;
//  ddword              _p_session_mid;  // Smb legacy should be
//  word               _p_uid;        // A little confused abiut this one still
//  byte               _p_session_key[16];
//  bool               _p_session_key_valid;
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


//  const char *current_command_name;
//  int current_command_id;

};
#if(0)
typedef enum
{
    CSSN_SHARE_STATE_UNUSED,    /* no user */
    CSSN_SHARE_STATE_CONNECTING,    /* trying to connect */
    CSSN_SHARE_STATE_CONNECTED, /* share is connected */
    CSSN_SHARE_STATE_DIRTY      /* share needs to be reconnected */
} RTSMB_CLI_SESSION_SHARE_STATE;



class Smb2File {
public:
  Smb2File()  { memset(file_id,0,16); file_name="";file_name_unicode = 0; }
  ~Smb2File() { set_file_free();}
  void set_filename(char *filename)
  {
    size_t w;
    file_name = filename;
    w=rtp_strlen(filename)*2+2;
    file_name_unicode=(word*)rtp_malloc(w);
    rtsmb_util_ascii_to_unicode (filename ,file_name_unicode, w);
  }
  const char *get_filename_ascii()  { return file_name.c_str(); }
  word *get_filename_utf16()  { return file_name_unicode;  };
  byte *get_file_id()    { return file_id;  };
  void set_fileid(byte *fileid)  { allocated=true;memcpy(file_id, fileid,16);  };
  void set_file_free() {file_name = ""; if(file_name_unicode) rtp_free(file_name_unicode);memset(file_id,0,16);}
  bool  allocated;
private:
  byte  file_id[16];
  std::string file_name;
  word   *file_name_unicode;
};

class Smb2Share {
public:
  Smb2Share() {share_state = CSSN_SHARE_STATE_DIRTY;}
  int share_state;
  word connect_mid;
  const word * share_type;
  word share_name [RTSMB_CFG_MAX_SHARENAME_SIZE + 1];
  dword tid;
  // retained from reply but not used yet.
  byte  ShareType;
  dword ShareFlags;
  dword Capabilities;
  dword MaximalAccess;
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
