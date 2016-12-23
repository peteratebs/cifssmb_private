/*                                                                                       */
/* SRVNET.C -                                                                            */
/*                                                                                       */
/* EBSnet - RTSMB                                                                        */
/*                                                                                       */
/* Copyright EBSnet Inc. , 2003                                                          */
/* All rights reserved.                                                                  */
/* This code may not be redistributed in source or linkable object form                  */
/* without the consent of its author.                                                    */
/*                                                                                       */
/* Module description:                                                                   */
/* This file contains the network loop for the RTSMB server.  Here is where all incoming */
/* traffic is analyzed and shipped off to appropriate layers.  Also, this is where the   */
/* threading support is handled.                                                         */
/*                                                                                       */


#include "smbdefs.h"
#include "rtprand.h" /* _YI_ 9/24/2004 */
#include "smbdebug.h"
#if (INCLUDE_RTSMB_SERVER)

#include "srvnet.h"
#include "srvrsrcs.h"
#include "psmbnet.h"
#include "smbnbns.h"
#include "smbnbss.h"
#include "smbnbds.h"
#include "srvnbss.h"
#include "srvnbns.h"
#include "smbnet.h"
#include "srvrap.h"
#include "srvbrbak.h"
#include "smbutil.h"


#include "rtptime.h"
#include "rtpnet.h"
#include "rtpthrd.h"
#include "rtpprint.h"
#ifdef SUPPORT_SMB2
#include "srv_smb2_model.h"
#include "com_smb2_wiredefs.h"
#endif
#include "remotediags.h"



#if INCLUDE_RTSMB_DC
RTSMB_STATIC int numPDCQueries = 0;
RTSMB_STATIC unsigned long next_pdc_find;
#endif

byte net_lastRemoteHost_ip[4];
int net_lastRemoteHost_port;

RTP_SOCKET net_nsSock;
RTP_SOCKET net_ssnSock;


// BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx)   move to srvsmbssn.cpp



void rtsmb_srv_netinfo_set_ip (PFBYTE host_ip, PFBYTE mask_ip)
{
    byte old_broadcast_ip [4];

    /* We want to reset our broadcasting if we are changing subnets.
       So, we save our current broadcast ip. */
    tc_memcpy (old_broadcast_ip, rtsmb_srv_netinfo_get_broadcast_ip (), 4);

    rtsmb_net_set_ip (host_ip, mask_ip);

    /* If they're different, restart broadcasting */
    if (tc_memcmp (old_broadcast_ip, rtsmb_srv_netinfo_get_broadcast_ip (), 4))
    {
        rtsmb_srv_nbns_restart ();
    }
}


PFBYTE rtsmb_srv_netinfo_get_host_ip (void)
{
    return rtsmb_net_get_host_ip ();
}

PFBYTE rtsmb_srv_netinfo_get_broadcast_ip (void)
{
    return rtsmb_net_get_broadcast_ip ();
}


RTP_SOCKET rtsmb_srv_netinfo_get_nbns_socket (void)
{
    return net_nsSock;
}
RTP_SOCKET rtsmb_srv_netinfo_get_nbss_socket (void)
{
    return net_ssnSock;
}
PFBYTE rtsmb_srv_netinfo_get_last_remote_ip (void)
{
    return net_lastRemoteHost_ip;
}
int rtsmb_srv_netinfo_get_last_remote_port (void)
{
    return net_lastRemoteHost_port;
}

#if INCLUDE_RTSMB_DC
RTSMB_STATIC void rtsmb_srv_netssn_pdc_reset_interval (void)
{
    numPDCQueries = 0;
}

RTSMB_STATIC dword rtsmb_srv_netssn_pdc_next_interval (void)
{
    dword rv;

    switch (numPDCQueries)
    {
    case 0:     rv = 0; break;
    case 1:     rv = 500; break;
    case 2:     rv = 2000; break;
    case 3:     rv = 8000; break;
    case 4:     rv = 60000; break;
    case 5:     rv = 120000; break;
    case 6:     rv = 180000; break;
    case 7:     rv = 240000; break;
    case 8:
    default:    rv = 300000; break;
    }

    numPDCQueries ++;

    return rv;
}

void rtsmb_srv_netssn_pdc_invalidate (void)
{
    rtsmb_srv_netssn_pdc_reset_interval ();

    MS_ClearPDCName ();
}
#endif





#endif /* INCLUDE_RTSMB_SERVER */
