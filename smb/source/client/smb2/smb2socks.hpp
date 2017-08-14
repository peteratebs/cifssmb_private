/*
|  SMBSOCK.H -
|
|  EBS -
|
|
|  Copyright EBS Inc. , 2004
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/

#ifndef __SMBSOCK_H__
#define __SMBSOCK_H__

#include "rtpnet.h"




#define SMB_POLL_READ  0
#define SMB_POLL_WRITE 1

#define SMB_POLL_RESULT_READY     1
#define SMB_POLL_RESULT_TIMEOUT   0
#define SMB_POLL_RESULT_SOCKERR  -1
#define SMB_POLL_RESULT_ABORTED  -2

#ifdef __cplusplus
//extern "C" {
#endif

int rtsmb2_net_write(RTP_SOCKET sd, byte *pData, int size);

int rtsmb2_net_read(RTP_SOCKET sd, byte *pData, int size, int minsize);


typedef int (* smbIdleFn) (byte *idleContext);

int         smb_network_init            (void);

int         smb_network_close           (void);

int         smb_socket                  (RTP_SOCKET *psd);

int         smb_closesocket             (RTP_SOCKET sd);

int	        smb_connect                 (RTP_SOCKET sd,
                                          byte* ip_addr,
                                          word port);

long         smb_send                    (RTP_SOCKET sd,
                                          byte* buffer,
                                          long size,
                                          smbIdleFn idle_func,
                                          byte* idle_data);

int         smb_gethostipaddr           (unsigned char* ipaddr,
                                          const char* name);

char*       smb_ip_to_str               (char* ipstr,
                                          unsigned char* ipaddr);

byte* smb_str_to_ip               (unsigned char* ipaddr,
                                          const char* ipstr);

int         smb_socket_is_connected     (RTP_SOCKET sd);

long         smb_recv_at_least           (RTP_SOCKET sd,
                                          byte * buffer,
                                          long min_bytes,
                                          long max_bytes,
                                          smbIdleFn idle_func,
                                          byte* idle_data);

int         smb_socket_has_data_to_read (RTP_SOCKET sd,
                                          long usec_tmo);

int         smb_poll_socket             (RTP_SOCKET sd,
                                          smbIdleFn idle_func,
                                          byte * idle_data,
                                          dword untilMsec,
                                          int pollMode);


#ifdef __cplusplus
//}
#endif


class SmbSocket_c {
private:
typedef enum
{
 NoSocket,
 Closed,
 Connecting,
 Connected,
 Closing,
} ConnectionState_t;

public:
  SmbSocket_c()                         {_p_ipvalid=false; connection_state=NoSocket; idle_func = 0;}
  int connect()
  {
    int r = -1;
    if (connection_state==NoSocket)
    {
      if (smb_socket(&sd)==0)
        connection_state=Closed;
      else
        return -1;
    }
    if (!_p_ipvalid || connection_state != Closed)
      return -1;
    int cv= smb_connect(sd,_p_ipv4address, _p_ipv4port);
    if (cv == 0)
    {
      r = 0;
      connection_state = Connected;
    }
    else if (cv == -2)
    {
      connection_state = Connecting;
      dword untilMsec = rtp_get_system_msec() + SMB_TIMEOUT_SEC*1000;
      r = smb_poll_socket ( sd, idle_func,idle_data,untilMsec, SMB_POLL_WRITE);
      if (r == 0)
        connection_state = Connected;
      else
        connection_state = Closed;
    }
    return r;
  }
  long send(byte* buffer, long size)
  {
    if (connection_state!=Connected)
      return -1;
    long r= smb_send (sd,buffer, size, idle_func,idle_data);
    if (r<0)
      close();
    return r;
  }
  long recieve_at_least(byte* buffer, long minimum, long maximum)
  {
    if (connection_state!=Connected)
      return -1;
    long r= smb_recv_at_least(sd, buffer, minimum, maximum, idle_func,idle_data);
    if (r<0)
      close();
    return r;
  }
  void close()
  {
    // connection_state=Closing;
    if (connection_state!=Connected)
      return;
    int r= smb_closesocket(sd);
    connection_state=Closed;
  }
//  int set_parameters(char * ip_string, char * ip_mask, word port)
  // -1 on error
  // ip is a char *, could be a dns name, mask is a byte array
  int set_client_parameters(const char *ip, byte *mask, int port)
  {
    memcpy(_p_ipv4mask, mask, sizeof(_p_ipv4mask));
    _p_ipv4port=port;
    int r = smb_gethostipaddr (_p_ipv4address, ip);
    if (r == 0)
      _p_ipvalid=true;
    return r;
  }
  RTP_SOCKET socket()          {return sd;}

private:
  bool _p_ipvalid;
  byte _p_ipv4address[4];
  byte _p_ipv4mask[4];
  int  _p_ipv4port;
  RTP_SOCKET sd;
  smbIdleFn idle_func;
  byte * idle_data;
  ConnectionState_t connection_state;    // Notconnected, Connecting, Connected, Closing
  int run_state;           // Idle, WaitSend, WaitRecv
};



#endif /* __SMBSOCK_H__ */
