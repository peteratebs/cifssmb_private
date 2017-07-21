//
// smb2connection.hpp -
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
#ifndef include_smb2connection
#define include_smb2connection

#include <algorithm>
#include <climits>

#if (0)
class TcpConnection :    {
public:
   TcpConnection()  {};
   ~Tcp4Connection(){};
   NetStatus bind_endpoint(byte *ipaddress, word port);
   NetStatus connect(int timeout);
   NetStatus disconnect();
   NetStatus send(Netistream & pStream);
   NetStatus recieve_exactly(Netistream & pStream,int timeout=-1);
   NetStatus recieve_at_most(Netitream & pStream,int timeout=-1);
private:

private:
   byte ip4_address[4];
   word ip4portnumer;
   current_state;
   socket;

}
class SmbSession  :    {
public:
  SmbSession()                                         {};

  TcpConnection    tcp_connection;

  SmbConfiguration smb_configuration;      //  smb_bind(char *user, char *password, char *domain)      {};
  SmbConnection    smb_connection;         //  connect/recover/disconnect


  SmbTransaction   smb_transaction;        //  currently executing client request

  SmbSlotsSignals  smb_slots;             //  completions.

private:
};
#endif // include_0

#endif // include_smb2connection
