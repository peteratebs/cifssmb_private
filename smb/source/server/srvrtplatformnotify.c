/*                                                                        */
/* SRVRTPLATFORMNOTIFY.CPP -                                                      */
/*                                                                        */
/* EBSnet - RTSMB                                                         */
/*                                                                        */
/* Copyright EBS Inc. , 2016                                             */
/* All rights reserved.                                                   */
/* This code may not be redistributed in source or linkable object form   */
/* without the consent of its author.                                     */
/*                                                                        */
/* Module description:                                                    */

#include "srvnotify.h"
#include "rtpmem.h"
#include "rtpfile.h"
#include "rtprand.h"
#include "rtpwcs.h"
#include "smbdebug.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "srvcfg.h"
#include "smbnet.h"
#include "wchar.h"
#include "remotediags.h"
#include "srvnotify.h"


void notify_message_discard(rtplatform_notify_control_object *phandle)
{
  if (phandle->message_buffer)
    RTP_FREE(phandle->message_buffer);
  phandle->message_buffer = 0;
}


#include "rtpnet.h"

extern int rtsmb_net_write_datagram (RTP_SOCKET socket, uint8_t *remote, int port, void *buf, int size);

static const uint8_t local_ip_address[] = {0x7f,0,0,1};
void notify_message_send_and_release(rtplatform_notify_control_object *phandle)
{
#if (0)
static RTP_SOCKET notify_send_socket;
static int notify_send_is_open;
  if (!notify_send_is_open)
  {
    if (rtp_net_socket_datagram(&notify_send_socket) < 0)
    {
        return -1;
    }
    notify_send_is_open = 1;
  }
  uint32_t zero = 0;
  tc_memcpy(&phandle->format_buffer[phandle->next_location_offset],&zero, 4);
  phandle->pmessage->payloadsize = phandle->formatted_content_size;
  int r = 0; // rtsmb_net_write_datagram (notify_send_socket, (uint8_t *)local_ip_address, phandle->signal_port_number,  phandle->message_buffer, phandle->formatted_content_size+sizeof(rtsmbNotifyMessage));
  notify_message_discard(phandle);
#endif
}

int rtsmb_net_read_datagram (RTP_SOCKET sock, void *pData, int size, uint8_t * remoteAddr, int * remotePort);
// Retrieve a formatted message from the udp channel
uint8_t *notify_retreive_message(RTP_SOCKET sock, uint32_t *pmessage_size)
{
#if (0)
rtsmbNotifyMessage inComing;
uint8_t remoteAddr[8];
int remotePort;
uint8_t *r=0;

  *pmessage_size = 0;
  if (rtsmb_net_read_datagram (sock, (void *) &inComing, sizeof(inComing), remoteAddr, &remotePort)!= sizeof(inComing))
    return 0;
  *pmessage_size = sizeof(inComing)+inComing.payloadsize;
  r = rtp_malloc(*pmessage_size);

  if (r)
  {
    if (rtsmb_net_read_datagram (sock, r, (int)*pmessage_size, remoteAddr, &remotePort)!= (int)*pmessage_size)
    {
        RTP_FREE(r);
        r=0;
    }
  }
  return r;
#endif
  return 0;
}
