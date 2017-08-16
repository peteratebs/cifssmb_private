//
// smbsession.hpp -
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

#ifndef include_smbsession
#define include_smbsession

typedef enum
{
    CSSN_SHARE_STATE_UNUSED,    /* no user */
    CSSN_SHARE_STATE_CONNECTING,    /* trying to connect */
    CSSN_SHARE_STATE_CONNECTED, /* share is connected */
    CSSN_SHARE_STATE_DIRTY      /* share needs to be reconnected */
} RTSMB_CLI_SESSION_SHARE_STATE;


class NewSmb2Share {
public:
  NewSmb2Share() {};
  int share_state;
  word connect_mid;
  dword tid;
  const word * share_type;
  word share_name [RTSMB_CFG_MAX_SHARENAME_SIZE + 1];
};



class NewSmb2Session {
public:

// - Use these istead of smb1 structures
//  RTSMB2_CLI_SESSION_USER  user;
//  RTSMB2_CLI_SESSION_SHARE share;
//  NewSmb2Session() ;
  NewSmb2Session()
  {
    _p_sid = 0;
    session_state(CSSN_STATE_DEAD);
    user_state(CSSN_USER_STATE_UNUSED);
  }

  void set_connection_parameters(const char *ip, byte *mask, int port);
  void set_user_parameters(char *_username, char *_password, char *_domain) ;
  void set_share_parameters(char *share_name, int sharenumber=0) ;

  bool connect_socket();
  void disconnect_socket();

  bool connect_buffers() ;
  bool disconnect_buffers() ;

  bool connect_server() ;
  bool disconnect_server() ;

  bool connect_user() ;
  bool disconnect_user(int sharenumber=0) ;

  bool connect_share(int sharenumber=0) ;
  bool disconnect_share(int sharenumber=0) ;

  void  session_state(int state) { _p_session_state = state;_p_session_mid=0;}
  int  session_state() { return _p_session_state;}
  int  sid()           {return _p_sid;       }
  char *user_name()    {return _p_username; }
  char *password()     {return _p_password;  }
  char *domain()       {return _p_domain;    }
  char *workstation()       {return (char *)"workstation";    }
  void user_uid(ddword uid) { _p_uid = uid; }
  void update_timestamp()   { _p_timestamp = rtp_get_system_msec (); };
  ddword unconnected_message_id() { _p_session_mid=0; return _p_session_mid;}
  ddword next_message_id() { return ++_p_session_mid; }

  void user_state(RTSMB_CLI_SESSION_USER_STATE user_state) { _p_user_state=user_state; }
  RTSMB_CLI_SESSION_USER_STATE user_state() { return _p_user_state; }
  void spnego_blob_from_server(byte *s)     { _p_spnego_blob_from_server = s;     }
  byte * spnego_blob_from_server()     { return _p_spnego_blob_from_server;       }
  int  spnego_blob_size_from_server()  { return _p_spnego_blob_size_from_server ; }
  void spnego_blob_size_from_server(int size)  { _p_spnego_blob_size_from_server =size; }

  NetStreamOutputBuffer    SendBuffer;
  NetStreamInputBuffer          ReplyBuffer;

  NewSmb2Share       Shares    [RTSMB_CFG_MAX_SHARESPERSESSION];


  RTSMB_CLI_SESSION_DIALECT session_server_info_dialect;
  dword session_server_info_capabilities;
  dword session_server_info_buffer_size;
  dword session_server_info_raw_size;
  ddword session_server_info_smb2_session_id;
  byte   session_server_info_challenge [8];


private:
  int                _p_session_state;
  int                _p_sid;
  byte             * _p_spnego_blob_from_server;
  int                _p_spnego_blob_size_from_server;
  dword              _p_timestamp;
  ddword              _p_session_mid;  // Smb legacy should be
  word               _p_uid;        // A little confused abiut this one still

  int _p_reply_buffer_size;
  int _p_send_buffer_size;
  byte *_p_send_buffer_raw;
  byte *_p_reply_buffer_raw;

  RTSMB_CLI_SESSION_USER_STATE _p_user_state;
  char               _p_groupname [RTSMB_CFG_MAX_GROUPNAME_SIZE  ];
  char               _p_username  [RTSMB_CFG_MAX_USERNAME_SIZE   ];
  char               _p_password  [RTSMB_CFG_MAX_PASSWORD_SIZE   ];
  char               _p_domain    [RTSMB_CFG_MAX_DOMAIN_NAME_SIZE];
  SmbSocket_c        SmbSocket;
  StreamBufferDataSource SocketSource;
  struct SocketContext sourcesockContext;
  DataSinkDevtype     SocketSink;
  struct SocketContext sinksockContext;

//  byte host_ip [4];
//  byte ip_mask [4];
//  int  portnumber;
//  RTP_SOCKET socket;

  //dialect
  //connection_state
  //shares[] sharename, sharestate, current_directory
  //current_share
};


#endif // include_smb2session
