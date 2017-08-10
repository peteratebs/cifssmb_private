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


void NewSmb2Session::set_connection_parameters(byte *ip, byte *mask, int port)
{
  memcpy(host_ip, ip, 4);
  memcpy(ip_mask, mask, 4);
  portnumber  = port;
};

void NewSmb2Session::set_user_parameters(char *_username, char *_password, char *_domain) {
  strncpy(_p_username,_username, sizeof(_p_username));
  strncpy(_p_password,_password, sizeof(_p_password));
  strncpy(_p_domain,  _domain  , sizeof(_p_domain));
};


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
bool NewSmb2Session::connect_server()                   {return false;};
bool NewSmb2Session::disconnect_server()                {return false;};
bool NewSmb2Session::connect_user()                     {return false;};
bool NewSmb2Session::disconnect_user(int sharenumber)   {return false;};
bool NewSmb2Session::connect_share(int sharenumber)     {return false;};
bool NewSmb2Session::disconnect_share(int sharenumber)  {return false;};
