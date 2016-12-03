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


extern volatile int keyboard_break_pressed_count;
int rtsmb_netport_select_n_for_read (RTP_SOCKET *socketList, int listSize, long timeoutMsec)
{

    int c;
    int n;
    int result;
    RTP_FD_SET readList;
    RTP_FD_SET errorList;
    int tempList[256];

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

    if (result <= 0)
    {
        return (0);
    }

    c = 0;

    for (n=0; n<listSize; n++)
    {
        if (rtp_fd_isset(&errorList, tempList[n]))
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_netport_select_n_for_read: socket error on : %d\n",c);
           if (keyboard_break_pressed_count)
           {
             RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_netport_select_n_for_read: ketboard breakr on : %d\n",c);
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
