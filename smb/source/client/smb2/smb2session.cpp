//
// session.cpp -
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

#include "smb2clientincludes.hpp"


extern bool do_smb2_logon_server_worker(Smb2Session &Session);
extern int do_smb2_tree_connect_worker(Smb2Session &Session,int sharenumber);
extern int do_smb2_cli_querydirectory_worker(Smb2Session &Session,int share_number, int filenumber, word *pattern);
extern bool do_smb2_directory_open_worker(Smb2Session &Session,int sharenumber,int filenumber,char *dirname, bool writeable);
extern bool do_smb2_file_open_worker(Smb2Session &Session,int sharenumber,int filenumber,char *dirname, bool writeable);
extern bool do_smb2_directory_create_worker(Smb2Session &Session,int sharenumber,int filenumber,char *dirname);
extern bool do_smb2_dirent_close_worker(Smb2Session &Session,int sharenumber,int filenumber);
extern bool do_smb2_dirent_delete_worker(Smb2Session &Session,int sharenumber,char *name, bool isdir);
extern bool do_smb2_dirent_rename_worker(Smb2Session &Session,int sharenumber, char *oldname, char *newname, bool isdir);


/// Api method sets ip address, mask and port (445 | 139) to connect to
void Smb2Session::set_connection_parameters(const char *ip, byte *mask, int port)
{
  SmbSocket.set_client_parameters(ip, mask, port);
}

/// Api method sets username, passsword and domain for the next connect
void Smb2Session::set_user_parameters(char *_username, char *_password, char *_domain) {
  strncpy(_p_username,_username, sizeof(_p_username));
  strncpy(_p_password,_password, sizeof(_p_password));
  strncpy(_p_domain,  _domain  , sizeof(_p_domain));
}

/// Api method sets sharename for share indexed by share number when we next connect
void Smb2Session::set_share_parameters(char *_share_name, int sharenumber)
{
  dualstringdecl(share_name);   //   use a dualstring to convert the share to unicode
  std::string s;
  std::string s2;
  if (_share_name[0] != '\\')     s = "\\";
  if (_share_name[1] != '\\')     s += "\\";
  s += _share_name;
  // Store it in upper case
//  std::transform(s.begin(), s.end(), s.begin(), toupper);
  *share_name = (char *)s.c_str();
  memcpy(
    Shares[sharenumber].share_name,
    share_name->utf16(),
    std::max((size_t)RTSMB_CFG_MAX_SHARENAME_SIZE, 2*(1+strlen((char *)share_name->ascii()) )));
}

/// Api method establishes a socket connection to the server and assigns buffering and stream handlers
bool Smb2Session::connect_socket()
{
  session_state(CSSN_STATE_CONNECTING);
  if (SmbSocket.connect() == 0)
  {
    diag_printf_fn(DIAG_JUNK, "Socket connect worked\n");
    session_state(CSSN_STATE_CONNECTED);
    return Smb2Session::connect_buffers();
  }
  else
  {
    diag_text_warning("Socket connect failed, reverting back to dead");
    session_state(CSSN_STATE_DEAD);
    setSessionSocketError(this, true, NetStatusConnectFailed);
    return false;
  }
  return true;
}
/// Api method establishes a logged in SMB connection to the server and updates session state information.
bool Smb2Session::connect_server()
{
  return do_smb2_logon_server_worker(*this);
};

void Smb2Session::disconnect_socket()
{
  SmbSocket.close();
}

bool Smb2Session::connect_buffers() // private
{
  _p_send_buffer_size  = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_reply_buffer_size = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_send_buffer_raw = (byte *)rtp_malloc(_p_send_buffer_size);
  _p_reply_buffer_raw = (byte *)rtp_malloc(_p_reply_buffer_size);

  SendBuffer.attach_buffer(_p_send_buffer_raw, _p_send_buffer_size);
  ReplyBuffer.attach_buffer(_p_reply_buffer_raw, _p_reply_buffer_size);

  sourcesockContext.socket = SmbSocket.socket();
  SocketSource.SourceFromDevice (socket_source_function, socket_drain_function, (void *)&sourcesockContext);
  ReplyBuffer.attach_source(SocketSource);

  sinksockContext.socket = SmbSocket.socket();
  SocketSink.AssignSendFunction(socket_sink_function, (void *)&sinksockContext);
  SendBuffer.attach_socket(SmbSocket);
  return true;
}

bool Smb2Session::connect_share(int sharenumber)
{
  return (bool) do_smb2_tree_connect_worker(*this,sharenumber);
};

bool Smb2Session::list_share(int sharenumber, int filenumber, word *_pattern)
{
  return (bool) do_smb2_cli_querydirectory_worker(*this,sharenumber,filenumber,_pattern);
}

bool Smb2Session::open_dir(int sharenumber, int filenumber, char *filename, bool forwrite)
{
  return do_smb2_directory_open_worker(*this,sharenumber, filenumber, filename, forwrite);
}

bool Smb2Session::open_file(int sharenumber, int filenumber, const char *filename, bool forwrite)
{
  return do_smb2_directory_open_worker(*this,sharenumber, filenumber, (char *)filename, forwrite);
}
int Smb2Session::write_to_file(int sharenumber, int filenumber, byte *buffer, int count)
{
  return -1;
}
int Smb2Session::read_from_file(int sharenumber, int filenumber, byte *buffer, int count)
{
  return -1;
}


bool Smb2Session::close_dirent(int sharenumber, int filenumber)
{
  return do_smb2_dirent_close_worker(*this,sharenumber, filenumber);
}

bool Smb2Session::make_dir(int sharenumber, int filenumber, char *filename)
{
  return do_smb2_directory_create_worker(*this,sharenumber, filenumber, filename);
}
bool Smb2Session::delete_dir(int sharenumber, char *filename)
{
  return do_smb2_dirent_delete_worker(*this,sharenumber, filename, true);
}
bool Smb2Session::delete_file(int sharenumber,char *filename)
{
  return do_smb2_dirent_delete_worker(*this,sharenumber, filename, false);
}
bool Smb2Session::rename_dir(int sharenumber, char *fromname , char *toname)
{
  return do_smb2_dirent_rename_worker(*this,sharenumber,  fromname , toname, true);
}
bool Smb2Session::rename_file(int sharenumber, char *fromname, char *toname)
{
  return do_smb2_dirent_rename_worker(*this,sharenumber, fromname , toname, false);
}


bool Smb2Session::disconnect_server()                {return false;};
bool Smb2Session::disconnect_user(int sharenumber)   {return false;};
bool Smb2Session::disconnect_share(int sharenumber)  {return false;};

static Smb2Session *glCurrentActiveSession=0;
void setCurrentActiveSession(Smb2Session *CurrentActiveSession) {glCurrentActiveSession=CurrentActiveSession;}
ddword getCurrentActiveSession_session_id() { return glCurrentActiveSession->session_server_info_smb2_session_id;}
Smb2Session *getCurrentActiveSession() {return glCurrentActiveSession;}
//bool checkSessionSigned( ) { return glCurrentActiveSession && glCurrentActiveSession->session_key_valid(); };
bool force_signing_on = false;
bool checkSessionSigned() { return force_signing_on; }// glCurrentActiveSession && glCurrentActiveSession->session_key_valid(); };
void setSessionSigned(bool isSigned) { force_signing_on=isSigned; }// glCurrentActiveSession && glCurrentActiveSession->session_key_valid(); };

void setSessionSocketError(Smb2Session *pSmb2Session, bool isSendError, NetStatus SmbStatus)
{ // calling this from a static funtion rather than a class method of session, not sure why for now
  int util_errno;
  const char *util_errstr = rtsmb_util_errstr(util_errno);
  pSmb2Session->set_socket_error(isSendError, SmbStatus, util_errno, util_errstr );
}
