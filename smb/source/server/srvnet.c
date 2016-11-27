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
#include "srv_smb2_yield.h"
#endif

RTSMB_STATIC PNET_THREAD mainThread;


#if INCLUDE_RTSMB_DC
RTSMB_STATIC int numPDCQueries = 0;
RTSMB_STATIC unsigned long next_pdc_find;
#endif

byte net_lastRemoteHost_ip[4];
int net_lastRemoteHost_port;

RTP_SOCKET net_nsSock;
RTP_SOCKET net_ssnSock;


RTSMB_STATIC void rtsmb_srv_net_thread_init (PNET_THREAD p, dword numSessions);
RTSMB_STATIC BBOOL rtsmb_srv_net_thread_cycle (PNET_THREAD pThread, RTP_SOCKET *readList, int readListSize);

extern BBOOL SMBS_ProcSMBBodyPacketExecute (PSMB_SESSIONCTX pSctx, dword *yieldTimeout);
extern BBOOL SMBS_ProcSMBBodyPacketEpilog (PSMB_SESSIONCTX pSctx, BBOOL doSend);
extern BBOOL  SMBS_ProcSMBBodyPacketReplay (PSMB_SESSIONCTX pSctx);

RTP_SOCKET rtsmb_srv_net_get_nbns_socket (void)
{
    return net_nsSock;
}
RTP_SOCKET rtsmb_srv_net_get_nbss_socket (void)
{
    return net_ssnSock;
}
PFBYTE rtsmb_srv_net_get_last_remote_ip (void)
{
    return net_lastRemoteHost_ip;
}
int rtsmb_srv_net_get_last_remote_port (void)
{
    return net_lastRemoteHost_port;
}

RTSMB_STATIC PNET_THREAD rtsmb_srv_net_thread_new (void)
{
    word i;
    PNET_THREAD rv = (PNET_THREAD)0;

    CLAIM_NET ();
    for (i = 0; i < prtsmb_srv_ctx->max_threads + 1; i++)
    {
        if (!prtsmb_srv_ctx->threadsInUse[i])
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"Allocating thread %d \n",i);
            prtsmb_srv_ctx->threadsInUse[i] = 1;
            rv = &prtsmb_srv_ctx->threads[i];
            break;
        }
    }
    RELEASE_NET ();

    return rv;
}

void rtsmb_srv_net_thread_close (PNET_THREAD p)
{
    int location = INDEX_OF (prtsmb_srv_ctx->threads, p);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"rtsmb_srv_net_thread_close: freeing thread %i \n", location);

    CLAIM_NET ();
    prtsmb_srv_ctx->threadsInUse[location] = 0;
    RELEASE_NET ();
}



RTSMB_STATIC PNET_SESSIONCTX rtsmb_srv_net_connection_open (PNET_THREAD pThread)
{
    PNET_SESSIONCTX pNetCtx;
    RTP_SOCKET      sock;
    unsigned char clientAddr[4];
    int clientPort;
    int ipVersion;
    /**
     * Move connection to a shiny new port and socket.
     */
    if (rtp_net_accept ((RTP_SOCKET *) &sock,(RTP_SOCKET) net_ssnSock, clientAddr, &clientPort, &ipVersion) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_srv_net_connection_open: accept error\n");
        return (PNET_SESSIONCTX)0;
    }

    pNetCtx = allocateSession();

    if(pNetCtx)
    {
        pNetCtx->sock = sock;

        pNetCtx->lastActivity = rtp_get_system_msec ();
        SMBS_InitSessionCtx(&(pNetCtx->smbCtx), pNetCtx->sock);

        SMBS_SetBuffers (&pNetCtx->smbCtx, pThread->inBuffer, prtsmb_srv_ctx->in_buffer_size, pThread->outBuffer, prtsmb_srv_ctx->out_buffer_size, pThread->tmpBuffer, prtsmb_srv_ctx->temp_buffer_size);

        return pNetCtx;
    }
    else
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_srv_net_connection_open:  No free sessions\n");

        /* let them know we are rejecting their request */
        rtsmb_srv_nbss_send_session_response (sock, FALSE);

        if (rtp_net_closesocket((RTP_SOCKET) sock))
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "ERROR IN CLOSESOCKET\n");
        }

        return (PNET_SESSIONCTX)0;
    }
}

// Close the session out but don't close the socket.
// Used when an SMB2 session tries to reconnect the session withiut closing the socket
void rtsmb_srv_net_connection_close_session(PNET_SESSIONCTX pSCtx )
{
#ifdef SUPPORT_SMB2
   if (pSCtx->smbCtx.pCtxtsmb2Session)
     RTSmb2_SessionShutDown(pSCtx->smbCtx.pCtxtsmb2Session);
#endif
   SMBS_CloseSession( &(pSCtx->smbCtx) );
   pSCtx->smbCtx.state = NOTCONNECTED;

}



RTSMB_STATIC void rtsmb_srv_net_connection_close (PNET_SESSIONCTX pSCtx )
{

//    RTSMB_DEBUG_OUTPUT_STR ("CloseConnection: socket ");
//    RTSMB_DEBUG_OUTPUT_DINT (pSCtx->sock);
//    RTSMB_DEBUG_OUTPUT_STR (" closed\n");
    rtsmb_srv_net_connection_close_session(pSCtx);

    /* kill conection */
    if (rtp_net_closesocket((RTP_SOCKET) pSCtx->sock))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"ERROR IN CLOSESOCKET\n");
    }

    freeSession (pSCtx);
}

#if INCLUDE_RTSMB_DC
RTSMB_STATIC void rtsmb_srv_net_pdc_reset_interval (void)
{
    numPDCQueries = 0;
}

RTSMB_STATIC dword rtsmb_srv_net_pdc_next_interval (void)
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

void rtsmb_srv_net_pdc_invalidate (void)
{
    rtsmb_srv_net_pdc_reset_interval ();

    MS_ClearPDCName ();
}
#endif


/*============================================================================   */
/*    INTERFACE FUNCTIONS                                                        */
/*============================================================================   */

/*
==============

==============
*/
void rtsmb_srv_net_init (void)
{
RTSMB_STATIC PNET_THREAD tempThread;


#if INCLUDE_RTSMB_DC
    next_pdc_find = rtp_get_system_msec () + rtsmb_srv_net_pdc_next_interval ();
#endif

    /**
     * You will note that we consistently use the term 'thread' to refer to the 'mainThread.'
     * In fact, it is not a full blown thread, but is only treated the same, for coding simplicity
     * purposes.  This first thread always runs in the same thread/process as the caller of our API
     * functions.  If CFG_RTSMB_MAX_THREADS is 0, no threads will ever be created.
     */
    tempThread = rtsmb_srv_net_thread_new ();   /* this will succeed because there is at least one thread free at start */

    if (!tempThread)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_net_init: Error -- could not allocate main pseudo-thread.\n");
        return;
    }

    mainThread = tempThread;
    rtsmb_srv_net_thread_init (mainThread, 0);

    /* -------------------- */
    /* get the three major sockets */
    /* Name Service Datagram Socket */
    if (rtsmb_net_socket_new (&net_nsSock, rtsmb_nbns_port, FALSE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"Could not allocate Name & Datagram service socket\n");
    }

    /* SSN Reliable Socket */
  #ifdef RTSMB_ALLOW_SMB_OVER_TCP
    if (rtsmb_net_socket_new (&net_ssnSock, rtsmb_nbss_direct_port, TRUE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Master Socket allocation failed Name & Datagram service socke\n");
    }
  #else
    if (rtsmb_net_socket_new (&net_ssnSock, rtsmb_nbss_port, TRUE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Master Socket allocation failed\n");
    }
  #endif
    if (rtp_net_listen ((RTP_SOCKET) net_ssnSock, prtsmb_srv_ctx->max_sessions) != 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Error occurred while trying to listen on SSN Reliable socket.\n");
    }

    if (rtp_net_setbroadcast((RTP_SOCKET) net_nsSock, 1) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Error occurred while trying to set broadcast on Name & Datagram service socket\n");
    }
}


RTSMB_STATIC void rtsmb_srv_net_thread_condense_sessions (PNET_THREAD pThread)
{
    dword i;
    /* condense list */
    for (i = 0; i < pThread->numSessions; i++)
    {
        if (pThread->sessionList[i] == (PNET_SESSIONCTX)0)
        {
            do
            {
                pThread->numSessions--;
                if (pThread->sessionList[pThread->numSessions] != (PNET_SESSIONCTX)0)
                {
                    pThread->sessionList[i] = pThread->sessionList[pThread->numSessions];
                    pThread->sessionList[pThread->numSessions] = (PNET_SESSIONCTX)0;
                    break;
                }
            }
            while (pThread->numSessions > i);
        }
    }
}

RTSMB_STATIC void rtsmb_srv_net_thread_main (PNET_THREAD pThread)
{
    dword i;
    RTP_SOCKET readList[256];
    int len;

    do
    {
        len = 0;

        /* build list */
        for(i = 0; i < pThread->numSessions && len < 256; i++)
        {
            if (pThread->sessionList[i]->smbCtx.yieldTimeout==0)
              readList[len++] = pThread->sessionList[i]->sock;
        }

        /**
         * Block on input.
         */
        // HEREHERE - We need to reduce timeout and send alerts from thread cycle.
        len = rtsmb_netport_select_n_for_read (readList, len, RTSMB_NBNS_KEEP_ALIVE_TIMEOUT_YIELD);
    }
    while (rtsmb_srv_net_thread_cycle (pThread, readList, len));

    rtsmb_srv_net_thread_close (pThread);

}


RTSMB_STATIC void rtsmb_srv_net_thread_init (PNET_THREAD p, dword numSessions)
{
    dword i;

    for (i = numSessions; i < prtsmb_srv_ctx->max_sessions; i++)
    {
        p->sessionList[i] = (PNET_SESSIONCTX)0;
    }

    p->index = 0;
    p->blocking_session = -1;
    p->numSessions = numSessions;
    p->srand_is_initialized = FALSE;
}

RTSMB_STATIC void rtsmb_srv_net_thread_split (PNET_THREAD pMaster, PNET_THREAD pThread)
{
    int numSessions = (int)pMaster->numSessions;
    int i, k = 0;
    int end = numSessions / 2;
    RTP_HANDLE newThread;
    /**
     * Set up thread, giving it half our sessions.
     */
    for (i =  numSessions - 1; i >= end; i--)
    {
        pThread->sessionList[k] = pMaster->sessionList[i];

        /**
         * We must also switch buffer pointers to correct place.
         */
        SMBS_SetBuffers (&pThread->sessionList[k]->smbCtx, pThread->inBuffer,
            prtsmb_srv_ctx->in_buffer_size, pThread->outBuffer, prtsmb_srv_ctx->out_buffer_size,
            pThread->tmpBuffer, prtsmb_srv_ctx->temp_buffer_size);

        k++;

        pMaster->sessionList[i] = (PNET_SESSIONCTX)0;
        pMaster->numSessions --;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_net_thread_split: Giving %d", (int) (numSessions - end));
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL," session %s to a thread.\n", (numSessions - end == 1 ? "" : "s"));

    rtsmb_srv_net_thread_init (pThread, (dword) (numSessions - end));

    if (rtp_thread_spawn(&newThread, (RTP_ENTRY_POINT_FN) rtsmb_srv_net_thread_main, "SMBTHREAD", 0, 0, pThread))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_net_thread_split: Couldn't start thread!\n");
    }
}

/**
 * Allocates space for a new session, if available; else
 */
RTSMB_STATIC BBOOL rtsmb_srv_net_thread_new_session (PNET_THREAD pMaster)
{
    /*new session */
    PNET_SESSIONCTX pSCtx = rtsmb_srv_net_connection_open (pMaster);
    PNET_THREAD pThread;

    if (pSCtx)
    {
        /**
         * Add new session to our list.
         */
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL,"rtsmb_srv_net_thread_new_session: adding session at place %d\n", (int) pMaster->numSessions);
        pMaster->sessionList[pMaster->numSessions] = pSCtx;
        pMaster->numSessions++;

        /**
         * See if we have a free thread.
         */
        pThread = rtsmb_srv_net_thread_new ();
        if (pThread)
        {
            /**
             * Give half our sessions to the new thread.
             */
            rtsmb_srv_net_thread_split (pMaster, pThread);
        }
        return TRUE;
    }
    else
        return FALSE;
}



RTSMB_STATIC BBOOL rtsmb_srv_net_session_yield_cycle (PNET_SESSIONCTX *session)
{
BBOOL doCB=FALSE;
BBOOL dosend = TRUE;

    if ((*session)->smbCtx.isSMB2)
    {

       if (RtsmbYieldCheckSignalled(&(*session)->smbCtx))
          doCB=TRUE;
       else
       {
         if(RtsmbYieldCheckTimeOut(&(*session)->smbCtx))
         {
          doCB=TRUE;
         }
      }
    }

    if (doCB)
      dosend = SMBS_ProcSMBBodyPacketReplay(&(*session)->smbCtx);
    return dosend;
}

RTSMB_STATIC BBOOL rtsmb_srv_net_session_cycle (PNET_SESSIONCTX *session, int ready)
{
    BBOOL isDead = FALSE;
    BBOOL rv = TRUE;

    claimSession (*session);

    /* keep session alive while we do stuff */
    switch ((*session)->smbCtx.state)
    {
    case BROWSE_MUTEX:
    case BROWSE_SENT:
    case WAIT_ON_PDC_NAME:
    case WAIT_ON_PDC_IP:
    case FINISH_NEGOTIATE:
    case FAIL_NEGOTIATE:
        (*session)->lastActivity = rtp_get_system_msec ();
        break;
    default:
        break;
    }

    /* handle special state cases here, potentially skipping netbios layer */
    switch ((*session)->smbCtx.state)
    {
#if (INCLUDE_RTSMB_DC)
    case WAIT_ON_PDC_NAME:
        SMBS_StateWaitOnPDCName (&(*session)->smbCtx);
        break;
    case WAIT_ON_PDC_IP:
        SMBS_StateWaitOnPDCIP (&(*session)->smbCtx);
        break;
    case FINISH_NEGOTIATE:
    case FAIL_NEGOTIATE:
        SMBS_StateContinueNegotiate (&(*session)->smbCtx);
        break;
#endif

    case BROWSE_MUTEX:
    case BROWSE_SENT:
    case BROWSE_FINISH:
    case BROWSE_FAIL:
        rtsmb_srv_browse_finish_server_enum (&(*session)->smbCtx);
        break;

    case READING:
    case WRITING_RAW_READING:
    {
        int pcktsize = (int) ((*session)->smbCtx.in_packet_size - (*session)->smbCtx.current_body_size);
        if (pcktsize == 0)
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Warning: rtsmb_srv_nbss_process_packet ignoring 0-length packet: %d \n", pcktsize);
        } else
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_nbss_process_packet process packetsize : %d \n", pcktsize);
           SMBS_ProcSMBPacket (&(*session)->smbCtx, pcktsize);/* rtsmb_srv_net_session_cycle finish reading what we started. */
        }
        break;
    }
    default:
        if (ready)
        {
            (*session)->lastActivity = rtp_get_system_msec ();

            if (rtsmb_srv_nbss_process_packet (&(*session)->smbCtx) == FALSE)
            {
                isDead = TRUE;
            }
        }
        else
        {
            /*check for time out */
            if(IS_PAST ((*session)->lastActivity, RTSMB_NBNS_KEEP_ALIVE_TIMEOUT))
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_srv_net_session_cycle: Connection timed out on socket %ld ",(*session)->sock);
                (*session)->lastActivity = rtp_get_system_msec ();
                isDead = TRUE;
            }
        }
        break;
    }

    if (isDead)
    {
        rtsmb_srv_net_connection_close (*session);
        rv = FALSE;
        // Set to not connected so we allow reception of SMB2 negotiate packets.
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session closed\n");
        (*session)->smbCtx.state = NOTCONNECTED;
    }
    else
    {
       if ((*session)->smbCtx.sendOplockBreakCount)
       {
          // HEREHERE -  send any oplock break alerts
          (*session)->smbCtx.sendOplockBreakCount = 0;
       }
       if ((*session)->smbCtx.sendNotifyCount)
       {
           // HEREHERE -  send any notify alerts
          (*session)->smbCtx.sendNotifyCount = 0;
       }
    }
    releaseSession (*session);

    if (isDead)
    {
        *session = (PNET_SESSIONCTX)0;
    }

    return rv;
}

RTSMB_STATIC BBOOL rtsmb_srv_net_thread_cycle (PNET_THREAD pThread, RTP_SOCKET *readList, int readListSize)
{
    PNET_SESSIONCTX *session;
    int i,n;

    /**
     * The reason we wait here to seed tc_rand() is so that the seed value has
     * some degree of randomness to it.  This gets called the first time there
     * is network traffic on this thread's sockets, so the network is our
     * only source of randomness.  Not very good, but its the best we have.
     *
     * We could use time (), and you are welcome to use that instead, but I
     * am under the impression that not all embedded compilers support time.h.
     */
    if (!pThread->srand_is_initialized)
    {
        tc_srand ((unsigned int) rtp_get_system_msec ());
        pThread->srand_is_initialized = TRUE;
    }

    /**
     * Now we run the sessions we are responsible for.
     */
    for(i = 0; i < (int)pThread->numSessions; i++)
    {
        int current_session_index = (i + (int)pThread->index) % (int)pThread->numSessions;
        SMBS_SESSION_STATE starting_state;

        /* Shouldn't run if a blocking session exists and we aren't it. */
        if (pThread->blocking_session != -1 &&
            pThread->blocking_session != current_session_index)
        {
            continue;
        }

        /* session can be null here */
        session = &pThread->sessionList[current_session_index];
        if (!*session)
          continue;

        starting_state = (*session)->smbCtx.state;
        for (n = 0; n < readListSize; n++)
        {
            if (readList[n] == (*session)->sock)
            {
                rtsmb_srv_net_session_cycle (session, TRUE);
                break;
            }
        }
        /* session can be null here */
        if (!*session)
          continue;

        // A yielded session's socket won't be in the socket list so check
        // if it is yielded and then check the countdown and wakup triggers
        if (RtsmbYieldCheckBlocked(&(*session)->smbCtx))
        {
          rtsmb_srv_net_session_yield_cycle (session);
        }
        else if (n == readListSize)
        { // A non yielded session timeded out, check for KEEPALIVES
            rtsmb_srv_net_session_cycle (session, FALSE);
        }

        /* Warning: at this point, (*session) may be NULL */

        /* if we changed states, and we are changing away from idle,
           we should block on this session.  If we are changing to idle,
           we should stop blocking on this session */
        if ((*session) && starting_state != (*session)->smbCtx.state)
        {
            if (starting_state == IDLE)
            {
                pThread->blocking_session = current_session_index;
            }
            else if ((*session)->smbCtx.state == IDLE)
            {
                pThread->blocking_session = -1;
            }
        }
        else if (!(*session))
        {
            /* dead session.  clear block if this held it */
            if (pThread->blocking_session == current_session_index)
            {
                pThread->blocking_session = -1;
            }
        }
    }

    rtsmb_srv_net_thread_condense_sessions (pThread);

    if (pThread->numSessions)
    {
        /* mix it up a bit, in case a session at the front is hogging time */
        pThread->index = ((dword) tc_rand () % pThread->numSessions);
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/*
==============
 poll to see if any of the  sockets belonging to a handler
 has something to be read.
==============
*/

void rtsmb_srv_net_cycle (long timeout)
{
    RTP_SOCKET readList[256];
    int len;
    word i;

    if (!mainThread)
    {
        return;
    }

    /**
     * Build the list of sockets to poll, consisting of the
     * name service socket, session service socket, and
     * sessions' sockets we are handling.
     */
    len = 0;
    readList[len++] = net_nsSock;  /* Name Service Socket */
    readList[len++] = rtsmb_nbds_get_socket (); /* Datagram Service Socket */
    readList[len++] = net_ssnSock; /* Session Service Socket */

    for (i = 0; i < mainThread->numSessions && len < 256; i++)
    {
        if (!RtsmbYieldCheckBlocked(&mainThread->sessionList[i]->smbCtx) )
          readList[len++] = mainThread->sessionList[i]->sock;
    }

    len = rtsmb_netport_select_n_for_read (readList, len, timeout);

    /**
     * Handle name requests, etc.
     */

    for (i = 0; i < len; i++)
    {
        if (readList[i] == net_nsSock)
        {
            byte datagram[RTSMB_NB_MAX_DATAGRAM_SIZE];

            /*process datagram */
            rtsmb_net_read_datagram (net_nsSock, datagram, RTSMB_NB_MAX_DATAGRAM_SIZE, net_lastRemoteHost_ip, &net_lastRemoteHost_port);

            /* only handle datagrams that don't originate from us */
            if (tc_memcmp (net_lastRemoteHost_ip, rtsmb_srv_net_get_host_ip (), 4) != 0)
            {
                rtsmb_srv_nbns_process_packet (datagram, RTSMB_NB_MAX_DATAGRAM_SIZE);
            }
        }
        /**
         * If a new session has arrived and we have free threads, give half our
         * sessions to them.
         */
        else if (readList[i] == net_ssnSock)
        {
            rtsmb_srv_net_thread_new_session (mainThread);
        }
    }

    /* handle sessions we own */
    rtsmb_srv_net_thread_cycle (mainThread, readList, len);

#if INCLUDE_RTSMB_DC
    /* now see if we need to query for the pdc again */
    if (!MS_IsKnownPDCName () && next_pdc_find <= rtp_get_system_msec ())
    {
        MS_SendPDCQuery ();

        next_pdc_find = next_pdc_find + rtsmb_srv_net_pdc_next_interval ();
    }
#endif
}

void rtsmb_srv_net_shutdown (void)
{
    if (rtp_net_closesocket((RTP_SOCKET) net_nsSock))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"ERROR IN CLOSESOCKET\n");
    }
    if (rtp_net_closesocket((RTP_SOCKET) net_ssnSock))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"ERROR IN CLOSESOCKET\n");
    }

    rtsmb_srv_net_thread_close (mainThread);
}


void rtsmb_srv_net_set_ip (PFBYTE host_ip, PFBYTE mask_ip)
{
    byte old_broadcast_ip [4];

    /* We want to reset our broadcasting if we are changing subnets.
       So, we save our current broadcast ip. */
    tc_memcpy (old_broadcast_ip, rtsmb_srv_net_get_broadcast_ip (), 4);

    rtsmb_net_set_ip (host_ip, mask_ip);

    /* If they're different, restart broadcasting */
    if (tc_memcmp (old_broadcast_ip, rtsmb_srv_net_get_broadcast_ip (), 4))
    {
        rtsmb_srv_nbns_restart ();
    }
}


PFBYTE rtsmb_srv_net_get_host_ip (void)
{
    return rtsmb_net_get_host_ip ();
}

PFBYTE rtsmb_srv_net_get_broadcast_ip (void)
{
    return rtsmb_net_get_broadcast_ip ();
}

#endif /* INCLUDE_RTSMB_SERVER */
