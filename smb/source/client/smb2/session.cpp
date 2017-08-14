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
#include "smb2defs.hpp"
#include "smb2socks.hpp"
#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "mswireobjects.hpp"
#include "session.hpp"


void NewSmb2Session::set_connection_parameters(const char *ip, byte *mask, int port)
{
  SmbSocket.set_client_parameters(ip, mask, port);
}

void NewSmb2Session::set_user_parameters(char *_username, char *_password, char *_domain) {
  strncpy(_p_username,_username, sizeof(_p_username));
  strncpy(_p_password,_password, sizeof(_p_password));
  strncpy(_p_domain,  _domain  , sizeof(_p_domain));
}


bool NewSmb2Session::connect_buffers()
{
  _p_send_buffer_size  = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_reply_buffer_size = RTSMB_CFG_MAX_BUFFER_SIZE;
  _p_send_buffer_raw = (byte *)rtp_malloc(_p_send_buffer_size);
  _p_reply_buffer_raw = (byte *)rtp_malloc(_p_reply_buffer_size);

  SendBuffer.attach_buffer(_p_send_buffer_raw, _p_send_buffer_size);
  ReplyBuffer.attach_buffer(_p_reply_buffer_raw, _p_reply_buffer_size);

  sourcesockContext.socket = SmbSocket.socket();
  SocketSource.SourceFromDevice (socket_source_function, (void *)&sourcesockContext);
  ReplyBuffer.attach_source(SocketSource);

  sinksockContext.socket = SmbSocket.socket();
  SocketSink.AssignSendFunction(socket_sink_function, (void *)&sinksockContext);
  SendBuffer.attach_socket(SmbSocket);
  return true;
}

void NewSmb2Session::set_share_parameters(char *_share_name, int sharenumber)
{
  dualstringdecl(share_name);   //   use a dualstring to convert the share to unicode
  std::string s;
  if (_share_name[0] != '\\');
    s = "\\";
  if (_share_name[1] != '\\');
    s += "\\";
  s += *_share_name;
  // Store it in upper case
  std::transform(s.begin(), s.end(), s.begin(), toupper);

  if (s[0] != '\\')
   s = "\\" + s;
  if (s[0] != '\\')
   s = "\\" + s;
  *share_name = (char *)s.c_str();
  memcpy(
    Shares[sharenumber].share_name,
    share_name->utf16(),
    std::max((size_t)RTSMB_CFG_MAX_SHARENAME_SIZE, 2*(1+strlen((char *)share_name->ascii()) )));
}

extern int do_smb2_logon_server_worker(NewSmb2Session &Session);

// Basically need to poll the socket for input here and then call the recv handler
int NewSmb2Session::wait_on_job()
{
  return RTSMB_CLI_SSN_RV_OK;

}
bool NewSmb2Session::connect_socket()
{
  session_state(CSSN_STATE_CONNECTING);
  if (SmbSocket.connect() == 0)
  {
    cout_log(LL_JUNK)  << "Socket connect worked" << endl;
    session_state(CSSN_STATE_CONNECTED);
  }
  else
  {
    cout_log(LL_JUNK)  << "Socket connect failed, back to dead" << endl;
    session_state(CSSN_STATE_DEAD);
  }
  return true;
}
void NewSmb2Session::disconnect_socket()
{
  SmbSocket.close();
}

bool NewSmb2Session::connect_server()
{
  int r = do_smb2_logon_server_worker(*this);
  if (r < 0)
   return false;
  else
   return true;
};
bool NewSmb2Session::disconnect_server()                {return false;};
bool NewSmb2Session::connect_user()                     {return false;};
bool NewSmb2Session::disconnect_user(int sharenumber)   {return false;};
bool NewSmb2Session::connect_share(int sharenumber)     {return false;};
bool NewSmb2Session::disconnect_share(int sharenumber)  {return false;};
