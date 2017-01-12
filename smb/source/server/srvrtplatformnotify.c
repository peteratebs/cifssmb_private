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

int notify_message_open(rtplatform_notify_control_object *phandle, rtplatform_notify_request_args *pargs, size_t maximimumsize)
{
  tc_memset(phandle,0,sizeof(*phandle));

  // Allocate message buffer for udp send
  phandle->message_buffer = rtp_malloc(sizeof(rtsmbNotifyMessage) + maximimumsize);
  // Alias it to pmessage and copy in facts that we'll route back to the server from the passed in arguments.
  phandle->pmessage = (rtsmbNotifyMessage *)phandle->message_buffer;
  phandle->pmessage->session_index = pargs->session_index;
  phandle->pmessage->notify_index  = pargs->notify_index;
  tc_memcpy(&phandle->pmessage->file_id, pargs->file_id, sizeof(phandle->pmessage->file_id));
  phandle->pmessage->payloadsize = 0;
  phandle->format_buffer = phandle->message_buffer+sizeof(rtsmbNotifyMessage);
  phandle->format_buffer_size = maximimumsize;
  if (!phandle->format_buffer)
    return -1;
  tc_memcpy(&phandle->args, pargs, sizeof(phandle->args));
  return 0;
}

int notify_message_append(rtplatform_notify_control_object *phandle, uint32_t change_alert_type, size_t utf_string_size, uint16_t *utf_16_string) // Null terminated UTF16 strings probably, returns -1 if message is too large
{
uint32_t next_location = phandle->formatted_content_size;
uint32_t new_next_location;
uint32_t zero=0;
int remainder =  utf_string_size%4;

  new_next_location = phandle->formatted_content_size;
  new_next_location += (8+utf_string_size);
  if (remainder)
    new_next_location += (4-remainder);
  if (new_next_location >=  phandle->format_buffer_size)
    return -1;

  // Link us to the previous name in the list
  if (phandle->formatted_content_size)
    tc_memcpy(&phandle->format_buffer[phandle->next_location_offset],&zero, 4);

  // Rembmber our offset in the list for linked the next item
  phandle->next_location_offset = next_location;
  tc_memcpy(&phandle->format_buffer[next_location],&zero, 4);
  tc_memcpy(&phandle->format_buffer[next_location+4],&change_alert_type, 4);
  tc_memcpy(&phandle->format_buffer[next_location+8],utf_16_string, utf_string_size);
  phandle->formatted_content_size = new_next_location;

  return 0;
}
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
  int r = rtsmb_net_write_datagram (notify_send_socket, (uint8_t *)local_ip_address, phandle->args.signal_port_number,  phandle->message_buffer, phandle->formatted_content_size+sizeof(rtsmbNotifyMessage));
  notify_message_discard(phandle);
  return r;
}

int rtsmb_net_read_datagram (RTP_SOCKET sock, void *pData, int size, uint8_t * remoteAddr, int * remotePort);
// Retrieve a formatted message from the udp channel
uint8_t *notify_retreive_message(RTP_SOCKET sock, uint32_t *pmessage_size)
{
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
}
