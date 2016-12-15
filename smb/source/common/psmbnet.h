#ifndef __PSMBNET_H__
#define __PSMBNET_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "rtpnet.h"

/* psmbnet.h - SMB Network Interface Layer with RTPlatform */

int  rtsmb_netport_select_n_for_read (RTP_SOCKET *socketList, int listSize, long timeoutMsec);
#ifdef __cplusplus
}
#endif

#endif /* __PSMBNET_H__ */
