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


typedef int (* webcIdleFn) (byte *idleContext);

int         smb_network_init            (void);

int         smb_network_close           (void);

int         smb_socket                  (RTP_SOCKET *psd);

int         smb_closesocket             (RTP_SOCKET sd);

int	        smb_connect                 (RTP_SOCKET sd,
                                          byte* ip_addr,
                                          word port);

int         smb_send                    (RTP_SOCKET sd,
                                          byte* buffer,
                                          long size,
                                          webcIdleFn idle_func,
                                          byte* idle_data);

int         smb_gethostipaddr           (unsigned char* ipaddr,
                                          char* name);

char*       smb_ip_to_str               (char* ipstr,
                                          unsigned char* ipaddr);

byte* smb_str_to_ip               (unsigned char* ipaddr,
                                          char* ipstr);

int         smb_socket_is_connected     (RTP_SOCKET sd);

int         smb_recv_at_least           (RTP_SOCKET sd,
                                          byte * buffer,
                                          long min_bytes,
                                          long max_bytes,
                                          webcIdleFn idle_func,
                                          byte* idle_data);

int         smb_socket_has_data_to_read (RTP_SOCKET sd,
                                          long usec_tmo);

int         smb_poll_socket             (RTP_SOCKET sd,
                                          webcIdleFn idle_func,
                                          byte * idle_data,
                                          dword untilMsec,
                                          int pollMode);


#ifdef __cplusplus
//}
#endif

#endif /* __SMBSOCK_H__ */
