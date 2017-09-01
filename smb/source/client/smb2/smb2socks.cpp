/*
|  SMBSOCK.C - WebC sockets porting layer
|
|  EBS -
|
|
|  Copyright EBS Inc. , 2017
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/

/*****************************************************************************/
/* Header files
 *****************************************************************************/

#include "smb2clientincludes.hpp"
#include "rtptime.h"
//#include "rtpprint.h"

/*****************************************************************************/
/* Macros
 *****************************************************************************/

#define SMB2_SOCKET_NONBLOCK 1

#define SELECT_MSEC             20000     // number of msec to block in
#define DO_IDLE_FUNCTION        1        // 0 to disable, 1 to enable

/*****************************************************************************/
/* Types
 *****************************************************************************/

/*****************************************************************************/
/* Function Prototypes
 *****************************************************************************/

/*****************************************************************************/
/* Data
 *****************************************************************************/

static bool gWebcNetworkInitialized = false;

/*****************************************************************************/
/* Function Definitions
 *****************************************************************************/

/*************************************************************************
 smb_network_init() - Initialize TCP/IP Networking

 Returns: 0 on success, -1 otherwise.
*************************************************************************/




void SmbSocket_c::show_socket_errors(bool clear_error_state)
{
  if (has_error)
  {
   diag_printf_fn(DIAG_CONSOLE, "%s Smb Error Level: %d\n",(char *) (isSendError?"Send Error ":"Recv Error "),SmbNetStatus);
   diag_printf_fn(DIAG_CONSOLE, " errno value : %d\n", errno_val);
   diag_printf_fn(DIAG_CONSOLE, " errno string: %s\n", errno_string);
  }
  else
    diag_printf_fn(DIAG_CONSOLE, " no socket errors\n");
  if (clear_error_state) has_error = false;
}

int smb_network_init (void)
{
  if (!gWebcNetworkInitialized)
  {
    if (rtp_net_init() < 0)
    {
      return (-1);
    }
    gWebcNetworkInitialized = true;
  }

  return (0);
}


/*************************************************************************
 smb_network_close() - Do any TCP/IP related cleanup

 Returns: 0 on success, -1 otherwise.
*************************************************************************/

int smb_network_close (void)
{
  if (gWebcNetworkInitialized)
  {
    gWebcNetworkInitialized = false;
    rtp_net_exit();
  }
  return (0);
}



/*************************************************************************
 smb_socket() - Allocate a socket, set to non-blocking

 psd - pointer to RTP_SOCKET to be initialized

 Returns: 0 on success, -1 otherwise.
*************************************************************************/

int smb_socket (RTP_SOCKET *psd)
{
  if (rtp_net_socket_stream(psd) >= 0)
  {
    /* set the socket to hard-close (linger on, timeout 0) */
    if (rtp_net_setlinger(*psd, 1, 0) >= 0)
    {
      /* turn off nagle's delayed-send algorithm; this is sometimes
         called TCP_NODELAY */
      rtp_net_setnagle(*psd, 0);

      /* set the socket to use non-blocking I/O */
      if (rtp_net_setblocking(*psd, 0) >= 0)
      {
        return (0);
      }
    }

    rtp_net_closesocket(*psd);
  }
  return (-1);
}


/*************************************************************************
 smb_closesocket() - Terminate a socket connection

 sd - socket to close

 Returns: 0 on success, -1 otherwise.
*************************************************************************/

int smb_closesocket (RTP_SOCKET sd)
{
  return (rtp_net_closesocket(sd));
}


/*************************************************************************
 smb_connect() - Establish a TCP connection to a particular ip/port

 sd - socket to use for this connection
 ip_addr - 4 byte_ array containing IP address to connect to
 port - port number to connect to

 Returns: 0 on success, -1 otherwise.
*************************************************************************/

int smb_connect (RTP_SOCKET sd, byte* ip_addr, word port)
{
int result;
  result = rtp_net_connect(sd, ip_addr, port, 4);
  if (result < 0)
  {
    if (result == -2)
    {
      return (0);
    }
    return (-1);
  }

  return (0);
}


/*************************************************************************
 smb_recv() - receive data over a socket
 smb_s_recv() - receive data over a secure socket

 sd - socket to receive data over
 buffer - buffer to place data into
 size - the size of the buffer (max bytes to read)

 Returns: number of bytes received on success, < 0 on error
*************************************************************************/
int  WebCReadData(char *p, int buffersize);

long smb_recv_at_least (RTP_SOCKET sd, byte * buffer, long min_bytes, long max_bytes, smbIdleFn idle_func, byte * idle_data)
{

  RTP_FD_SET f_read;
  RTP_FD_SET f_error;
  byte* pkt_data;
  long  pkt_len;
  long  bytes_received;
  dword start_time, elapsed_time_msec;
  int select_val;

  bytes_received = 0;
  start_time = rtp_get_system_msec();

  while (bytes_received < min_bytes)
  {
    while (1)
    {

      rtp_fd_zero(&f_read);
      rtp_fd_set(&f_read, sd);

      rtp_fd_zero(&f_error);
      rtp_fd_set(&f_error, sd);

      select_val = rtp_net_select(&f_read, 0, &f_error, SELECT_MSEC);

      if (rtp_fd_isset(&f_error, sd))
      {
        diag_printf_fn(DIAG_JUNK,"rtsmb2_net_read Read select error\n");
        return (-1);
      }

      /* return value of 0 indicates no sockets selected this time */
      if (select_val > 0)
      {
        break;
      }

      elapsed_time_msec = rtp_get_system_msec() - start_time;
      if (elapsed_time_msec > SMB_TIMEOUT_SEC * 1000)
      {
        diag_printf_fn(DIAG_JUNK,"rtsmb2_net_read Read timed out elapsed:%d min:%d recvd:%d \n", elapsed_time_msec,min_bytes,bytes_received);
        return (-1);
      }
      if (idle_func)
      {
        unsigned long intoidle =  rtp_get_system_msec();
        if (idle_func(idle_data) < 0)
        {
          diag_printf_fn(DIAG_JUNK,"rtsmb2_net_read idle timed out elapsed:%d min:%d recvd:%d \n", elapsed_time_msec,min_bytes,bytes_received);
          return (-1);
        }
      }
    } /* while (1) */

    pkt_data = (unsigned char *) &(buffer[bytes_received]);
    pkt_len = rtp_net_recv(sd, pkt_data, max_bytes - bytes_received);
    if (pkt_len == -2)
    {
      continue;
    }
    if (pkt_len == 0 || pkt_len == -2)
    {
      break;
    }

    if (pkt_len < 0)
    {
      return (pkt_len);
    }
    bytes_received += pkt_len;
  }
  return (bytes_received);
}

int rtsmb2_net_read(RTP_SOCKET sd, byte *pData, int size, int minsize)
{
smbIdleFn idle_func=0; byte * idle_data=0;
   int r = smb_recv_at_least (sd, pData, minsize, size, idle_func, idle_data);
   return r;
}

void rtsmb2_net_drain(RTP_SOCKET sd)
{
  RTP_FD_SET f_read;
  RTP_FD_SET f_error;
  int ndrained = 0;
  int select_val;

  rtp_fd_zero(&f_read);
  rtp_fd_set(&f_read, sd);

  rtp_fd_zero(&f_error);
  rtp_fd_set(&f_error, sd);

  select_val = rtp_net_select(&f_read, 0, &f_error, 0);

 if (rtp_fd_isset(&f_error, sd))
 {
    diag_printf_fn(DIAG_JUNK,"rtsmb2_net_drain Read select error\n");
 }

  if (select_val > 0)
  {
    byte junk[32];
    long pkt_len;
    do {
     pkt_len = rtp_net_recv(sd, junk, 32);
     if (pkt_len > 0) ndrained += pkt_len;
    } while(pkt_len>0);
  }
  if (ndrained)
    diag_printf_fn(DIAG_JUNK,"rtsmb2_net_dran: drained bytes: %d \n", ndrained);
}

/*************************************************************************
 smb_send() - send data over a socket
 smb_s_send() - send data over a secure socket

 sd - socket to send data over
 buffer - data to send
 size - the size of the buffer (max bytes to send)

 Returns: number of bytes sent on success, < 0 on error
*************************************************************************/
long smb_send (RTP_SOCKET sd, byte * buffer, long size, smbIdleFn idle_func, byte * idle_data)
{

  RTP_FD_SET f_write;
  RTP_FD_SET f_error;
  byte* pkt_data;
  long  pkt_len;
  long  bytes_sent;
  dword start_time, elap_time_msec;
  int select_val;

  bytes_sent = 0;
  start_time = rtp_get_system_msec();

  while (bytes_sent < size)
  {
    while (1)
    {
      if (idle_func)
      {
        if (idle_func(idle_data) < 0)
        {
          return (-1);
        }
      }

      rtp_fd_zero(&f_write);
      rtp_fd_set(&f_write, sd);

      rtp_fd_zero(&f_error);
      rtp_fd_set(&f_error, sd);

      select_val = rtp_net_select(0, &f_write, &f_error, SELECT_MSEC);

      if (rtp_fd_isset(&f_error, sd))
      {
        return (-1);
      }

      /* return value of 0 indicates no sockets selected this time */
      if (select_val > 0)
      {
        break;
      }

      elap_time_msec = rtp_get_system_msec() - start_time;
      if (elap_time_msec > SMB_TIMEOUT_SEC * 1000)
      {
        return (-1);
      }
    } /* while (1) */

    pkt_data = (unsigned char *) &(buffer[bytes_sent]);


     pkt_len = rtp_net_send(sd, pkt_data, size - bytes_sent);
     if (pkt_len == 0 || pkt_len == -2)
     {
       break;
     }

     if (pkt_len < 0)
     {
      return (pkt_len);
    }

     bytes_sent += pkt_len;
  }

  if (idle_func)
  {
    if (idle_func(idle_data) < 0)
    {
      return (-1);
    }
  }

  return (bytes_sent);

}

/// device for sinking bytes to tcp stream.
int rtsmb2_net_write(RTP_SOCKET sd, byte *pData, int size)
{
byte * idle_data =0; smbIdleFn idle_fn = 0;
   return smb_send (sd, pData, size, idle_fn, idle_data);
}


/*************************************************************************
 smb_gethostipaddr() - Convert a host name into an IP address

 ipaddr - 4 byte_ array to fill with the IP address
 name - host name to look up

 Returns: 0 on success, SMB_EDNSFAILED (<0) on error
*************************************************************************/
int smb_gethostipaddr (byte * ipaddr, const char * name)
{
  int type;

  // first try the name as a numbered IP address
  if (name[0]>='0'&& name[0]<='9')
  {
    char testStr[16];

    smb_str_to_ip(ipaddr, name);

    // do a check to make sure we translated an IP address
    smb_ip_to_str(testStr, ipaddr);
    if (!strcmp(name, testStr))
    {
      // if we go from string to ip addr and back, without
      //  changing the host name, this is success.
      return (0);
    }
  }
  return (rtp_net_gethostbyname(ipaddr, &type, (char *)name));
}


/*************************************************************************
 smb_ip_to_str() - Convert 4 byte ip address to dotted string

 ipstr - 13 char array : the buffer to fill with dotted string
 ipaddr - 4 byte_ array : the ip address to convert

 Returns: ipstr
*************************************************************************/

char * smb_ip_to_str(char * ipstr, byte * ipaddr)
{
int n;

  ipstr[0] = '\0';

  for (n=0; n<4; n++)
  {
    rtp_itoa(ipaddr[n], &(ipstr[strlen(ipstr)]), 10);
    if (n<3)
    {
      strcat(ipstr, ".");
    }
  }

  return (ipstr);
}


/*************************************************************************
 smb_str_to_ip() - Convert dotted string to 4 byte ip address

 ipaddr -  a 4-byte_ buffer to fill with the ip address
 ipstr -   the dotted string to convert

 Notes:
   "111.111.111.111" converts to {111,111,111,111}
   "111.111.111"     converts to {111,111,111,0}
   "111.111"         converts to {111,111,0,0}
   "111"             converts to {111,0,0,0}

 Returns: ipaddr
*************************************************************************/

byte * smb_str_to_ip(byte * ipaddr, const char * _ipstr)
{
char * ptr;
char savech;
int n;
char ncipstr[32];   // non-const

  strncpy(ncipstr,_ipstr,sizeof(ncipstr));
  char *ipstr = ncipstr;
  memset(ipaddr, 0, 4);

  for (n=0; n<4; n++)
  {
    ptr = ipstr; // ipstr;
    while (*ptr != '.' && *ptr != '\0')
    {
      ptr++;
    }

    savech = *ptr;
    *ptr = '\0';
    ipaddr[n] =  atoi(ipstr);
    if (savech == '\0')
    {
      break;
    }
    *ptr = savech;

    ipstr = ptr + 1;
  }

  return (ipaddr);
}


/*************************************************************************
 smb_socket_is_connected() - Check whether a connection is still active

 sd - the socket to check

 Returns: non zero for true, 0 for false
*************************************************************************/

int smb_socket_is_connected (RTP_SOCKET sd)
{
  return (rtp_net_is_connected(sd));
}


/*************************************************************************
 smb_socket_has_data_to_read() - Check whether a connection has data ready

 sd - the socket to check
 usec_tmo - microsecond timeout

 Returns: non zero for true, 0 for false
*************************************************************************/

int smb_socket_has_data_to_read (RTP_SOCKET sd, long usec_tmo)
{
  return (rtp_net_read_select(sd, usec_tmo / 1000) >= 0);
}

/*
   1 - ready to read
   0 - timed out
  -1 - error on socket
  -2 - abort command received
*/

int smb_poll_socket (
    RTP_SOCKET sd,
    smbIdleFn idle_func,
    byte * idle_data,
    dword untilMsec,
    int pollMode)
{
  RTP_FD_SET f_test;
  RTP_FD_SET* f_read;
  RTP_FD_SET* f_write;
  RTP_FD_SET f_error;
  int select_val;
  long timeToWait;
  long timeRemaining;

  while (1)
  {
    timeRemaining = (long) ((long) untilMsec - (long) rtp_get_system_msec());

    if (timeRemaining <= 0)
    {
      return SMB_POLL_RESULT_TIMEOUT;
    }

    if (idle_func)
    {
      if (idle_func(idle_data) < 0)
      {
        return SMB_POLL_RESULT_ABORTED;
      }
    }

    timeToWait = std::min((long)SELECT_MSEC, timeRemaining);

    rtp_fd_zero(&f_test);
    rtp_fd_set(&f_test, sd);

    if (pollMode == SMB_POLL_READ)
    {
      f_read = &f_test;
      f_write = 0;
    }
    else
    {
      f_write = &f_test;
      f_read = 0;
    }

    rtp_fd_zero(&f_error);
    rtp_fd_set(&f_error, sd);

    select_val = rtp_net_select(f_read, f_write, &f_error, timeToWait);

    if (rtp_fd_isset(&f_error, sd))
    {
      return SMB_POLL_RESULT_SOCKERR;
    }

    /* return value of 0 indicates no sockets selected this time */
    if (select_val > 0)
    {
      break;
    }
  } /* while (1) */

  return SMB_POLL_RESULT_READY;
}
