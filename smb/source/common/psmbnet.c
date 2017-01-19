//
// PSMBNET.C - RTSMB Network Interface Layer for RTPlatform
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc., 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Function to select on all sockets in socketList

#include "psmbnet.h"
#include "rtpnet.h"
#include "smbdefs.h"
#include "errno.h"
#include "string.h"
#include "srvutil.h"
#include "rtptime.h"


extern RTP_SOCKET diag_socket;

// select failed check one at a time for bad sockets
static void rtsmb_netport_select_n_diag(RTP_SOCKET *socketList, int listSize, int listIndex)
{
    int n;
    int result;
    RTP_FD_SET readList;
    RTP_FD_SET errorList;
    //Clear readList
    rtp_fd_zero (&readList);
    rtp_fd_zero (&errorList);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu Select: NSOCKS:%d [%d,%d,%d,%d,%d]\n", rtp_get_system_msec(), listSize, socketList[0],socketList[1],socketList[2],socketList[3],socketList[3]);
    rtp_fd_set(&readList, socketList[listIndex]);
    rtp_fd_set(&errorList, socketList[listIndex]);
    result = rtp_net_select (&readList, (RTP_FD_SET*)0, &errorList, 100);
    if (result < 0)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu socket index : %d  rtp_net_select error errno string: %s\n", rtp_get_system_msec(), listIndex, strerror(errno));
    }
    else
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu socket index : %d  rtp_net_select succeeded\n", rtp_get_system_msec(),listIndex);
    }
}

extern volatile int keyboard_break_pressed_count;
int rtsmb_netport_select_n_for_read (RTP_SOCKET *socketList, int listSize, long timeoutMsec)
{

    int c;
    int n;
    int result;
    RTP_FD_SET readList;
    RTP_FD_SET errorList;
    RTP_SOCKET tempList[256];

    for(n=0; n<listSize; n++)
    {
        tempList[n] = socketList[n];
    }

    if (listSize == 0)
    {
        return (0);
    }

    //Clear readList
    rtp_fd_zero (&readList);
    rtp_fd_zero (&errorList);
    for (n=0; n<listSize; n++)
    {
        rtp_fd_set(&readList, socketList[n]);
        rtp_fd_set(&errorList, socketList[n]);
#if 0
        readList.fdArray[n] = socketList[n];
        readList.fdCount++;
#endif
    }

    if (timeoutMsec < 0)
    {
        result = rtp_net_select (&readList, (RTP_FD_SET*)0, &errorList, -1);
    }
    else
    {
        result = rtp_net_select (&readList, (RTP_FD_SET*)0, &errorList, timeoutMsec);
    }
    if (diag_socket!=tempList[0])    // display socks unless it's diag
    {
      if (result < 0)
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu:  rtp_net_select error errno string: %s\n", rtp_get_system_msec(), strerror(errno));
    }
    if (result < 0)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: rtsmb_netport_select_n_for_read: listSize: %d  rtp_net_select error returned : %d errno string: %s\n", listSize, result, strerror(errno));
       for (n=0; n<listSize; n++)    // which socket
         rtsmb_netport_select_n_diag(tempList, listSize, n);
       srvsmboo_panic("Select error");
    }
    if (result <= 0)
    {
        return (0);
    }

    c = 0;

    for (n=0; n<listSize; n++)
    {
        if (rtp_fd_isset(&errorList, tempList[n]))
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: rtsmb_netport_select_n_for_read: socket error on : %d\n",c);
           if (keyboard_break_pressed_count)
           {
             RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_netport_select_n_for_read: ketboard break on : %d\n",c);
             keyboard_break_pressed_count =0;
             continue;
           }
           else
           {
             RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_netport_select_n_for_read: socket error on : %d\n",c);
             socketList[c++] = tempList[n];
           }
        }
        if (rtp_fd_isset(&readList, tempList[n]))
        {
           socketList[c++] = tempList[n];
        }
    }
    return(c);

#if 0 /* _YI_ */
    n = 0;
    while (n < listSize)
    {
        if (!rtp_fd_isset(&readList, socketList[n]))
        {
            socketList[n] = socketList[--listSize];
        }
        else
        {
            n++;
        }
    }

    return (listSize);
#endif
}
