/*                                                                        */
/* SRVSMBSSNOO.CPP -                                                      */
/*                                                                        */
/* EBSnet - RTSMB                                                         */
/*                                                                        */
/* Copyright EBS Inc. , 2016                                             */
/* All rights reserved.                                                   */
/* This code may not be redistributed in source or linkable object form   */
/* without the consent of its author.                                     */
/*                                                                        */
/* Module description:                                                    */

#warning duplicate define
#define CFG_RTSMB_MAX_SESSIONS              8

#pragma GCC diagnostic ignored "-Wwrite-strings"


#include "smbdefs.h"

#include "rtpfile.h"
#include "srvnotify.h"
#include "rtprand.h"
#include "rtpwcs.h"
#include "smbdebug.h"
#include "rtpscnv.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvtran2.h"
#include "srvssn.h"
#include "srvrap.h"
#include "srvshare.h"
#include "srvrsrcs.h"
#include "srvfio.h"
#include "srvassrt.h"
#include "srvauth.h"
#include "srvutil.h"
#include "smbnb.h"
#include "srvnbns.h"
#include "srvans.h"
#include "srvcmds.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "srvcfg.h"
#include "smbnet.h"
#include "smbspnego.h"
#include "rtpmem.h"

#include "rtptime.h"
#include "remotediags.h"
#include "srvsmbssn.h"
#include "srvoplocks.h"
#include "srvnbns.h"






EXTERN_C void rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive);
EXTERN_C void srvsmboo_panic(char *panic_string);
EXTERN_C void Smb2SrvModel_New_Session(struct smb_sessionCtx_s *pSmbCtx);
EXTERN_C void Smb2SrvModel_Free_Session(pSmb2SrvModel_Session pSession);
EXTERN_C void rtsmb_srv_browse_finish_server_enum (PSMB_SESSIONCTX pCtx);

EXTERN_C uint8_t *notify_retreive_message(RTP_SOCKET sock, uint32_t *pmessage_size);
EXTERN_C void close_session_notify_requests(PNET_SESSIONCTX pCtx);

static void freeSession (PNET_SESSIONCTX p);




#define NOSOCKET 0xffff

static RTP_SOCKET diag_accept_socket_history[256];
static int diag_accept_socket_history_count;
static RTP_SOCKET diag_close_socket_history[256];
static int diag_close_socket_history_count;

static int   current_net_thread_signal_socketnumber = YIELD_BASE_PORTNUMBER;
static const byte local_ip_address[] = {0x7f,0,0,1};
static const byte local_ip_mask[] = {0xff,0,0,0};
#define MASTER_SOCKET_INDEX 0
#define SIGNAL_SOCKET_INDEX  1
#define FIRST_SESSION_SOCKET_INDEX  2
RTP_SOCKET  master_socket;
RTP_SOCKET  nameserver_socket;
RTP_SOCKET  signal_socket;
int         signal_socket_portnumber;

static dword socket_timeout_shutdowns;
static    dword socket_requested_shutdowns;

// Sends an rtsmbSigStruct message to the session
//static void send_signal(rtsmbSigStruct *psig)
//{
//    rtsmb_net_write_datagram ( signal_socket, (byte *)local_ip_address, signal_socket_portnumber, (void *)psig, psig->payloadsize);
//}

// Returns a rtsmbSigStruct if one is pending (should be because select was called) on the UDP port else null
//static void recv_signal(void)
//{
//static rtsmbSigStruct return_sig;
//  byte remote_ip[4];
//  int  size, remote_port;
//  size = rtsmb_net_read_datagram (signal_socket, &return_sig, sizeof(return_sig), remote_ip, &remote_port);
//  if (size == sizeof(return_sig))  {
//    { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: _net_thread_signal_c recved a signal of size %d\n", size);}
//    return &return_sig;
//  }
//  else if (size != 0) { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: _net_thread_signal_c recved invalid message size %d\n", size);}
//  return 0;
//}


void srvsmboo_init(PNET_THREAD pThread)
{

   signal_socket_portnumber = current_net_thread_signal_socketnumber++;
   if (rtsmb_net_socket_new (&signal_socket, signal_socket_portnumber, FALSE) < 0)
   {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"DIAG: Failed to create Datagram signalling socket\n");
     srvsmboo_panic("Socket error");
//     return -1; // YIKES
   }
    /* -------------------- */
    /* get the three major sockets */
    /* Name Service Datagram Socket */
    if (rtsmb_net_socket_new (&nameserver_socket, rtsmb_nbns_port, FALSE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"Could not allocate Name & Datagram service socket\n");
    }
    if (rtp_net_setbroadcast((RTP_SOCKET) nameserver_socket, 1) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Error occurred while trying to set broadcast on Name & Datagram service socket\n");
    }

    /* SSN Reliable Socket */
    if (rtsmb_net_socket_new (&master_socket, rtsmb_nbss_direct_port, TRUE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Master Socket allocation failed Name & Datagram service socket\n");
        srvsmboo_panic("Socket error");
       // return -1; // not good
    }
    if (rtp_net_listen (master_socket, prtsmb_srv_ctx->max_sessions) != 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Error occurred while trying to listen on SSN Reliable socket.\n");
        srvsmboo_panic("Socket error");
//        return -1; // not good
    }
//    return 0;
}

//extern BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock);
static BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock);





void srvsmboo_netssn_shutdown(void)
{
 // #warning implement
}
EXTERN_C void srvsmboo_panic(char *panic_string)
{
#warning Need panic strategy

   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: Looping Panic abort called :%s\n",panic_string);
   for (;;) { }
   rtp_printf("\nPanic abort called: \n");
   rtp_printf("panic: %s \r",panic_string);
   int iCrash = 13 / 0;      // trap to the debugger
}



/*
================
 This function intializes the session context portions that are shared by SMBV1 and SMBV2.

    @pSmbCtx: This is the session context to initialize.
    @sock: This is the sock we are connected to.

    return: Nothing.
================
*/
static void SMBS_InitSessionCtx (PSMB_SESSIONCTX pSmbCtx, RTP_SOCKET sock)
{

    pSmbCtx->sock = sock;
    pSmbCtx->dialect = DIALECT_NONE;
    pSmbCtx->isSMB2 = FALSE;

    pSmbCtx->accessMode = Auth_GetMode ();

#ifdef SUPPORT_SMB2
    SMBS_Setsession_state(pSmbCtx, NOTCONNECTED);
#else  /* SUPPORT_SMB2 */
    SMBS_Setsession_state(pSmbCtx, IDLE);
    /* Initialize uids, tid, and fid buckets for the new session if it's version 2 also initialize v2 context block in pSmbCtx Sets pSctx->isSMB2 = FALSE*/
    SMBS_InitSessionCtx_smb(pSmbCtx,1);
#endif
    /**
     * See srvssn.h for a more detailed description of what these do.
     */
    pSmbCtx->writeRawInfo.amWritingRaw = FALSE;

/*  pSmbCtx->num = num++;  */
}


/**
 * Allocates space for a new session, if available; else
 */

static PNET_SESSIONCTX allocateSession (void)
{
	word i;
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;

	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (!prtsmb_srv_ctx->sessionsInUse[i])
		{
			prtsmb_srv_ctx->sessionsInUse[i] = 1;
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();
    // zero the oplock control stuff so we don;t have any surprises
    if (rv)
      tc_memset(&rv->netsessiont_smbCtx.sessionoplock_control, 0, sizeof(rv->netsessiont_smbCtx.sessionoplock_control));
	return rv;
}

static BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock)
{
    //PNET_SESSIONCTX pSCtx = rtsmb_srv_netssn_connection_open (pMaster, sock);
    // RTSMB_STATIC PNET_SESSIONCTX rtsmb_srv_netssn_connection_open (PNET_THREAD pThread, RTP_SOCKET  sock)
    PNET_SESSIONCTX pCtx;


    pCtx = allocateSession();
    if(pCtx)
    {
        pCtx->netsessiont_sock = sock;

        pCtx->netsessiont_lastActivity = rtp_get_system_msec ();
        SMBS_InitSessionCtx(&(pCtx->netsessiont_smbCtx), pCtx->netsessiont_sock);
//        SMBS_PointSmbBuffersAtNetThreadBuffers (&pNetCtx->netsessiont_smbCtx, pThread);
        PSMB_SESSIONCTX pSCtx = &pCtx->netsessiont_smbCtx;

        int session_index = SMBU_SessionToIndex(pSCtx);
        pSCtx->readBuffer              = prtsmb_srv_ctx->unshared_read_buffers [session_index];
        pSCtx->smallReadBuffer         = prtsmb_srv_ctx->unshared_read_buffers [session_index];
        pSCtx->smallWriteBuffer        = prtsmb_srv_ctx->unshared_write_buffers[session_index];
        pSCtx->writeBuffer             = prtsmb_srv_ctx->unshared_write_buffers[session_index];
        pSCtx->tmpBuffer               = prtsmb_srv_ctx->unshared_temp_buffers [session_index];
        pSCtx->readBufferSize          = prtsmb_srv_ctx->out_buffer_size; // They are the same
        pSCtx->writeBufferSize         = prtsmb_srv_ctx->out_buffer_size;
        pSCtx->tmpSize                 = prtsmb_srv_ctx->temp_buffer_size;

        /**
         * Add new session to our list.
         */
        pMaster->sessionList[pMaster->numSessions] = pCtx;
        pMaster->numSessions++;
        return TRUE;
    }
    else
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_srv_netssn_connection_open:  No free sessions\n");
        rtsmb_srv_nbss_send_session_response (sock, FALSE);
        return FALSE;
    }
}

/*
================
 This function intializes the session SMB context portions for SMBV1 and V2.

 This is performed when the server state goes from NOTCONNECTED to IDLE after accepting it's fir bytes and identifying smbv1

    @pSmbCtx: This is the session context to initialize.

    return: Nothing.
================
*/
/* Initialize uids, tid, and fid buckets for the new session if it's version 2 also initialize v2 context block in pSmbCtx */
void SMBS_InitSessionCtx_smb(PSMB_SESSIONCTX pSmbCtx, int protocol_version)
{
    word i;

    /**
     * Outsource our user initialization.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
    {
        SMBS_User_Init  (&pSmbCtx->uids[i]);
        pSmbCtx->uids[i].inUse = FALSE;
    }

    /**
     * Outsource our tree initialization.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
    {
        SMBS_Tree_Init (&pSmbCtx->trees[i]);
        pSmbCtx->trees[i].inUse = FALSE;
    }

    /**
     * Clear fids.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_session; i++)
    {
        pSmbCtx->fids[i].internal_fid = -1;
    }

    pSmbCtx->isSMB2 =  (protocol_version == 2);
    if (pSmbCtx->isSMB2)
    {
        /* Allocate the smb2 session stuff it is embedded in pSmbCtx so it can't fail */
        Smb2SrvModel_New_Session(pSmbCtx);
    }
}



/*
==============

==============
*/
RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions);

void SMBS_srv_netssn_init (void)      // called once from rtsmb_srv_init or rtsmb_srv_enable
{
RTSMB_STATIC PNET_THREAD tempThread;
//void srvsmboo_get_legacy_c_thread_structure(void)

#if INCLUDE_RTSMB_DC
    next_pdc_find = rtp_get_system_msec () + rtsmb_srv_netssn_pdc_next_interval ();
#endif
    /**
     * You will note that we consistently use the term 'thread' to refer to the 'mainThread.'
     * In fact, it is not a full blown thread, but is only treated the same, for coding simplicity
     * purposes.  This first thread always runs in the same thread/process as the caller of our API
     * functions.  If CFG_RTSMB_MAX_THREADS is 0, no threads will ever be created.
     */
    // rtsmb_srv_netssn_thread_new is obsolete but estill using thread from cfg
    prtsmb_srv_ctx->threadsInUse[0] = 1;
    prtsmb_srv_ctx->mainThread = &prtsmb_srv_ctx->threads[0]; // rtsmb_srv_netssn_thread_new ();   /* this will succeed because there is at least one thread free at start */
    // We do something strage here and discard thread 0 swap it with temp thread, so save off and restore what we did with thread[0]
    rtsmb_srv_netssn_thread_init (prtsmb_srv_ctx->mainThread, 0);
    srvsmboo_init(prtsmb_srv_ctx->mainThread);
}

/*
==============
 poll to see if any of the  sockets belonging to a handler
 has something to be read.
==============
*/

RTSMB_STATIC void rtsmb_srv_netssn_session_cycle (PNET_SESSIONCTX *session, int ready);
RTSMB_STATIC void rtsmb_srv_netssn_session_yield_cycle (PNET_SESSIONCTX *session);



static void rtsmb_srv_pdc_session_cycle (PNET_SESSIONCTX *session);
static void _srv_netssn_pdc_cycle(void);
static void SMBS_claimSession (PNET_SESSIONCTX pCtx);
static void SMBS_releaseSession (PNET_SESSIONCTX pCtx);
RTSMB_STATIC void rtsmb_srv_netssn_thread_condense_sessions (PNET_THREAD pThread);
BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize, BBOOL pull_nbss, BBOOL replay);
BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx);    // Called from rtsmb_srv_netssn_session_cycle



int diagreadListSize;
RTP_SOCKET diagreadList[256];


static RTP_SOCKET  get_master_socket(void)     { return master_socket;};
extern "C" RTP_SOCKET  get_signalling_socket(void) { return signal_socket;};
void SMBS_srv_netssn_cycle (long timeout)          // Top level API call to cycle based on select and timeouts
{
    if (!prtsmb_srv_ctx->mainThread)
    {
        srvsmboo_panic("rtsmb_srv_netssn_cycle sock: lost mainTread");
        return;
    }
    PNET_THREAD pThread = prtsmb_srv_ctx->mainThread;
    //
//    rtsmb_srv_netssn_thread_cycle (prtsmb_srv_ctx->mainThread, timeout);
// ===================================
//RTSMB_STATIC void rtsmb_srv_netssn_thread_cycle (PNET_THREAD pThread,long timeout)
    if (!pThread->srand_is_initialized)    /* Seed rend here for no big reason */
    {
        tc_srand ((unsigned int) rtp_get_system_msec ());
        pThread->srand_is_initialized = TRUE;
    }

    PNET_SESSIONCTX *session;
    int i,n;
    int readListSize;
    RTP_SOCKET readList[256];
    int master_signal_active = 0;
    int signalling_signal_active = 0;

//    readList[len++] = net_nsSock;  /* Name Service Socket */
//    readList[len++] = rtsmb_nbds_get_socket (); /* Datagram Service Socket */
    readList[SIGNAL_SOCKET_INDEX] = signal_socket;
    readList[MASTER_SOCKET_INDEX] = master_socket;
    readListSize = 2;

    for (int i = 0; i < prtsmb_srv_ctx->mainThread->numSessions && readListSize < 256; i++)
    {
       // Don't queue yielded sockets
      if (!prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx.sessionoplock_control._yieldSession)
        readList[readListSize++] = prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx.sock;
    }

    int len = rtsmb_netport_select_n_for_read (readList, readListSize, timeout);
    int active_list_size = len>=0?len:0;

    // Remember if we have activity on the signal slot or on master
    for (int socket_index = 0; socket_index<active_list_size;socket_index++) {
      if (readList[socket_index] == master_socket) master_signal_active = 1;
      else if (readList[socket_index] == signal_socket) signalling_signal_active = 1;
    }
    if (master_signal_active)
    {
      RTP_SOCKET      sock;
      unsigned char clientAddr[4]; int clientPort; int ipVersion;
      if (rtp_net_accept ((RTP_SOCKET *) &sock,(RTP_SOCKET) get_master_socket(), clientAddr, &clientPort, &ipVersion) < 0)
      {  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, (char *) "DIAG: net_thread_c::perform_session_cycle: accept error\n");  }
      else
      {
        if (diag_accept_socket_history_count < 256)
          diag_accept_socket_history[diag_accept_socket_history_count++] = sock;

        if (!rtsmb_srv_netssn_thread_new_session(prtsmb_srv_ctx->mainThread,sock))
        {
//        pMaster->sessionList[pMaster->numSessions] = pCtx;
          srvsmboo_panic("oo and non oo sessions out of sync");
        }
      }
    }
    if (signalling_signal_active)
    {
       uint32_t message_size;
       uint8_t *message_data;
       message_data = notify_retreive_message(signal_socket, &message_size);
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, (char *) "DIAG: net_thread_c::perform_session_cycle: notify signal buffer size id %d\n",message_size);
       if (message_data)
         RTP_FREE(message_data);
//       rtsmbSigStruct *recvSig = recv_signal(); // Must copy to use
       // Make sure we
    }

    diagreadListSize = readListSize;
    tc_memcpy(diagreadList, readList, sizeof(diagreadList));

    if (readListSize > 0)
    {
        // Fall through an allow old school processing to run

        /**
         * Now we run the sessions we are responsible for.
         */
        for(i = 0; i < (int)pThread->numSessions; i++)
        {
            int current_session_index = (i + (int)pThread->index) % (int)pThread->numSessions;
            SMBS_SESSION_STATE starting_state;

            /* session can be null here */
            session = &pThread->sessionList[current_session_index];
            if (!*session)
              continue;

            /* Shouldn't run if a blocking session exists and we aren't it. */
            if (pThread->blocking_session != -1 &&
                pThread->blocking_session != current_session_index)
            {
                continue;
            }

            /* make sure we bind the thread to the net session context */
           (*session)->netsessiont_pThread = pThread;
            starting_state = (*session)->netsessiont_smbCtx.session_state;
            for (n = 0; n < active_list_size; n++)
            {
                if (readList[n] == (*session)->netsessiont_sock)
                {
                    rtsmb_srv_pdc_session_cycle (session);
                    rtsmb_srv_netssn_session_cycle (session, TRUE);
                    break;
                }
            }
            /* session can be null here */
            if (!*session)
              continue;

            // A yielded session's socket won't be in the socket list so check
            // if it is yielded and then check the countdown and wakeup triggers
            //RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_yield_cycle in\n", rtp_get_system_msec());
            rtsmb_srv_netssn_session_yield_cycle (session);
            //RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_yield_cycle out\n", rtp_get_system_msec());

            // May have been a wakeup for a yield or just a timeout, process timers either way
            if (n == readListSize)
            { // A non yielded session timeded out, check for KEEPALIVES
                 rtsmb_srv_pdc_session_cycle (session);
                //RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_yield_cycle done in\n", rtp_get_system_msec());
                rtsmb_srv_netssn_session_cycle (session, FALSE);
                //RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_yield_cycle done out\n", rtp_get_system_msec());
            }

            /* Warning: at this point, (*session) may be NULL */

            /* if we changed states, and we are changing away from idle,
               we should block on this session.  If we are changing to idle,
               we should stop blocking on this session */
            if ((*session) && starting_state != (*session)->netsessiont_smbCtx.session_state)
            {
                if (starting_state == IDLE)
                {
                    pThread->blocking_session = current_session_index;
                    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_cycle set blocking:%d \n", rtp_get_system_msec());
                }
                else if ((*session)->netsessiont_smbCtx.session_state == IDLE)
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

        rtsmb_srv_netssn_thread_condense_sessions (pThread);

        if (pThread->numSessions)
        {
            /* mix it up a bit, in case a session at the front is hogging time */
            pThread->index = ((dword) tc_rand () % pThread->numSessions);
        }
    }
// ==================================
    _srv_netssn_pdc_cycle();
}

extern void SMBS_ProcSMBReplay(PSMB_SESSIONCTX pSctx);

RTSMB_STATIC void rtsmb_srv_netssn_session_yield_cycle (PNET_SESSIONCTX *session) // Call from top level SMBS_srv_netssn_cycle() to test if a session is yielded and if it should execute
{
BBOOL doCB=FALSE;
BBOOL dosend = TRUE;
    if (!prtsmb_srv_ctx->enable_oplocks)
      return;
    if (!(*session)->netsessiont_smbCtx.isSMB2)
      return;
    if (!(*session)->netsessiont_smbCtx.sessionoplock_control._yieldSession)
      return;
    if ((*session)->netsessiont_smbCtx.sessionoplock_control._wakeSession)
    {
       OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_SIGNAL
       rtp_printf("Replay from SIGNAL\n");
       doCB=TRUE;
    }
    else if (rtp_get_system_msec() > (*session)->netsessiont_smbCtx.sessionoplock_control._yieldTimeout);
    { // Clear it so it doesn't fire right away
      OPLOCK_DIAG_YIELD_SESSION_SEND_TIMEOUT
       (*session)->netsessiont_smbCtx.sessionoplock_control._yieldSession = FALSE;
      rtp_printf("Replay from TMO\n");
      doCB=TRUE;
      OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_TIMEOUT
    }
    if (doCB)
    {
       (*session)->netsessiont_smbCtx.sessionoplock_control._yieldSession = FALSE;
       (*session)->netsessiont_smbCtx.sessionoplock_control._wakeSession = FALSE;
       (*session)->netsessiont_smbCtx.sessionoplock_control._yieldTimeout = 0;
       SMBS_ProcSMBReplay(&(*session)->netsessiont_smbCtx);
    }
}




RTSMB_STATIC void rtsmb_srv_netssn_session_cycle (PNET_SESSIONCTX *session, int ready) // Called when a packet is present for the socket or when 1 second expires with no traffic
{
    BBOOL isDead = FALSE;
    BBOOL rv = TRUE;
    PSMB_SESSIONCTX pSCtx = &(*session)->netsessiont_smbCtx;
    PNET_SESSIONCTX pNetCtxt = *session;
    RTP_SOCKET sock = pNetCtxt->netsessiont_sock;

    // Give replay a chance to execute
    // rtsmb_srv_netssn_session_yield_cycle(session);

    SMBS_claimSession (pNetCtxt);

    oplock_c_break_clear_pending_break_send_queue();  // Processing may queue up oplock breaks to send, requires breaks (see: oplock_c_break_send_pending_breaks()) below

    /* handle special state cases here, potentially skipping netbios layer */
    switch (pSCtx->session_state)
    {
    case READING:
    case WRITING_RAW_READING:
    {
        int pcktsize = (int) (pSCtx->in_packet_size - pSCtx->current_body_size);
        if (pcktsize == 0)
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Warning: rtsmb_srv_netssn_session_cycle ignoring 0-length packet: %d \n", pcktsize);
        } else
        {
           SMBS_ProcSMBPacket (pSCtx, pcktsize, FALSE /* dont pull*/, FALSE /* replay*/);/* rtsmb_srv_netssn_session_cycle finish reading what we started. */
        }
        break;
    }
    default:
        if (ready)
        {
            (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
            if (SMBS_ProcSMBPacket (pSCtx, 0, TRUE, FALSE)== FALSE) /* pull a new nbss packet and process it */
            {
              RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"DIAG: rtsmb_srv_netssn_session_cycle: SMBS_ProcSMBPacket failed on %ld \n",sock);
              socket_requested_shutdowns += 1;
              isDead = TRUE;
            }
        }
        else
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_cycle not ready  in\n", rtp_get_system_msec());
            /*check for time out */
//            #define RTSMB_NBNS_KEEP_ALIVE_TIMEOUT     30000
//            if (((long) (rtp_get_system_msec () - ((unsigned long)(*session)->netsessiont_lastActivity))) >= (long) (RTSMB_NBNS_KEEP_ALIVE_TIMEOUT))
            if(IS_PAST ((*session)->netsessiont_lastActivity, RTSMB_NBNS_KEEP_ALIVE_TIMEOUT))
//            if(IS_PAST ((*session)->netsessiont_lastActivity, RTSMB_NBNS_KEEP_ALIVE_TIMEOUT*4))
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"DIAG: rtsmb_srv_netssn_session_cycle: Connection timed out on socket %ld \n",(*session)->netsessiont_sock);
                // (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
                socket_timeout_shutdowns+=1;
                isDead = TRUE;
            }
            // run down any oplock timers
            oplock_c_break_check_waiting_break_requests();
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_netssn_session_cycle not ready  out\n", rtp_get_system_msec());
        }
        break;
    }
    SMBS_releaseSession (pNetCtxt);

    // Send breaks to any other sessions
    oplock_c_break_send_pending_breaks();

    if (isDead)
    {
      // RTSmb2_SessionShutDown(&pSCtx->netsessiont_smbCtx.Smb2SessionInstance);    // Shuts down SMB2 session, not much relevent but user name, securty nonces, SessionId most is done in the SMB1 framework
      //SMBS_CloseSession( &(pSCtx->netsessiont_smbCtx) );
       // Finds the smbs_session_c object assoicated with the session and remove it from the active read select group.
       // Shuts down user structures        - closes files, clears oplocks and clears entries in tree too.
       // Shuts down tree structures
       // Reverts to SMB1 buffer sizes and assumed protocol
       // Sets session state to NOTCONNECTED
      // Free the session if it wasn't already.
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: Close dead session close SOCK:%d \n",sock);
      if (diag_close_socket_history_count < 256)
          diag_close_socket_history[diag_close_socket_history_count++] = sock;
      if (rtp_net_closesocket(sock))
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: rtsmb_srv_netssn_connection_close: Error in closesocket\n");

      if (*session)
      { // Closes the session and returns to notInUse state, the socket is closed later
        SMBS_srv_netssn_connection_close_session(*session);
      }
      rv = FALSE;
      // Set to not connected so we allow reception of SMB2 negotiate packets.
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session closed\n");
        // SMBS_CloseSession( pSCtx );                  --- Already done by SMBS_srv_netssn_connection_close_session
        // SMBS_Setsession_state(pSCtx, NOTCONNECTED);  --- Already done by SMBS_srv_netssn_connection_close_session
      *session = (PNET_SESSIONCTX)0;
    }
}

RTSMB_STATIC void rtsmb_srv_netssn_thread_condense_sessions (PNET_THREAD pThread)   // Called from top level polling routine SMBS_srv_netssn_cycle
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



RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions) // called from SMBS_srv_netssn_init() called once from rtsmb_srv_init or rtsmb_srv_enable

{
    dword i;
    for (i = numSessions; i < prtsmb_srv_ctx->max_sessions; i++)
        p->sessionList[i] = (PNET_SESSIONCTX)0;
    p->index = 0;
    p->blocking_session = -1;
    p->numSessions = numSessions;
    p->srand_is_initialized = FALSE;
    // p->yield_sock; A udp socket dedicated to signalling yield sessions was initialized at startup
}

static void freeSession (PNET_SESSIONCTX p)  // Called from rtsmb_srv_netssn_session_cycle when a dead socket is encountered
{
  int location;
  location = INDEX_OF (prtsmb_srv_ctx->sessions, p);
  CLAIM_NET ();
  prtsmb_srv_ctx->sessionsInUse[location] = 0;
  RELEASE_NET ();
}


// Remove the session from the list of sessions polloing for input.
static void srvsmboo_close_session(RTP_SOCKET sock)
{
  for (int i = 0; i < prtsmb_srv_ctx->mainThread->numSessions; i++)
  {
    if (sock == prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx.sock)
    {
       freeSession (prtsmb_srv_ctx->mainThread->sessionList[i]);  // Called from rtsmb_srv_netssn_session_cycle when a dead socket is encountered
       prtsmb_srv_ctx->mainThread->sessionList[i] = (PNET_SESSIONCTX)0;
       break;
    }
  }
}

// Finds the smbs_session_c object assoicated with the session and remove it from the active read select group.
// Shuts down user structures        - closes files, clears oplocks and clears entries in tree too.
// Shuts down tree structures
// Reverts to SMB1 buffer sizes and assumed protocol
static void SMBS_CloseSession(PSMB_SESSIONCTX pSmbCtx)
{
    word i;

    srvsmboo_close_session((RTP_SOCKET) pSmbCtx->sock);           // Finds the smbs_session_c object assoicated with the session and remove it from the active read select group.
    /**
     * Only data worth freeing is in user data and trees.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
        if (pSmbCtx->uids[i].inUse)
            SMBS_User_Shutdown (pSmbCtx, &pSmbCtx->uids[i]);

    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
        if (pSmbCtx->trees[i].inUse)
            SMBS_Tree_Shutdown (pSmbCtx, &pSmbCtx->trees[i]);
    // Revert to smbv1 defaults
    pSmbCtx->readBufferSize   = prtsmb_srv_ctx->out_buffer_size;
    pSmbCtx->writeBufferSize  = prtsmb_srv_ctx->out_buffer_size;
    pSmbCtx->protocol_version = 1;
}


void SMBS_srv_netssn_connection_close_session(PNET_SESSIONCTX pCtx ) // Close the session out but don't close the socket. Used when an SMB2 session tries to reconnect the session without closing the socket
{
  close_session_notify_requests(pCtx);
#ifdef SUPPORT_SMB2
   if (pCtx->netsessiont_smbCtx.isSMB2)

// if (pSCtx->netsessiont_smbCtx.pCtxtsmb2Session)
     RTSmb2_SessionShutDown(&pCtx->netsessiont_smbCtx.Smb2SessionInstance);
#endif

   SMBS_Setsession_state(&pCtx->netsessiont_smbCtx,NOTCONNECTED);
   SMBS_CloseSession( &(pCtx->netsessiont_smbCtx) );

}
void SMBS_Setsession_state(PSMB_SESSIONCTX pSctxt, SMBS_SESSION_STATE new_session_state)      // Set the state of a session for strategy of what to do in session cycle NOTCONNECTED, READING IDLE etc.
{
   pSctxt->session_state = new_session_state;
}

BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate) // Fill the nbss session header and send contents of pCtx->writeBuffer
{
    RTSMB_NBSS_HEADER header;
    int r;

    size = MIN (size, pCtx->writeBufferSize);

    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = size;

    r = rtsmb_nbss_fill_header (pCtx->writeBuffer, RTSMB_NBSS_HEADER_SIZE, &header);
    if (r < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_SendMessage: Error writing netbios header!\n");
        return FALSE;
    }
    else
    {
        r =  rtsmb_net_write (pCtx->sock, pCtx->writeBuffer, (int)(RTSMB_NBSS_HEADER_SIZE + size));
        if (r < 0)
            return FALSE;
    }
    return TRUE;
}


PNET_SESSIONCTX SMBS_findSessionByContext (PSMB_SESSIONCTX pSctxt)   // Called when the smb session is known but the net session is not, these are one to one.
{
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;
	word i;
	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
//		if (prtsmb_srv_ctx->sessionsInUse[i] && &(prtsmb_srv_ctx->sessions[i].netsessiont_smbCtx) == pSctxt)
		if (&(prtsmb_srv_ctx->sessions[i].netsessiont_smbCtx) == pSctxt)
		{
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();

	return rv;
}

void SMBS_closeAllShares(PSR_RESOURCE pResource)  // Top level api legacy implementaion, close this share in all sessions.
{
PNET_SESSIONCTX pCtx = &prtsmb_srv_ctx->sessions[0];
   /**
    * We have the session right where we want it.  It is not doing anything,
    * so we can close the tree itself and all the files it has open on this session.
    */
   SMBS_claimSession (pCtx);
   SMBS_CloseShare (&pCtx->netsessiont_smbCtx, (word) INDEX_OF (prtsmb_srv_ctx->shareTable, pResource));
   SMBS_releaseSession (pCtx);
}

void SMBS_srv_netssn_shutdown (void)       // Top level shutdown before exit
{
    srvsmboo_netssn_shutdown();
    // Legacy code
    CLAIM_NET ();
    prtsmb_srv_ctx->threadsInUse[0] = 0;
    RELEASE_NET ();
}

static void SMBS_claimSession (PNET_SESSIONCTX pCtx)
{
	int i;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);

	rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->activeSessions[i]);
}

static void SMBS_releaseSession (PNET_SESSIONCTX pCtx)
{
	int i;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
	rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->activeSessions[i]);

}


static void _srv_netssn_pdc_cycle(void)
{
#if INCLUDE_RTSMB_DC
    /* now see if we need to query for the pdc again */
    if (!MS_IsKnownPDCName () && next_pdc_find <= rtp_get_system_msec ())
    {
        MS_SendPDCQuery ();

        next_pdc_find = next_pdc_find + rtsmb_srv_netssn_pdc_next_interval ();
    }
#endif
}
#if (INCLUDE_RTSMB_DC)
static BBOOL SMBS_StateWaitOnPDCName (PSMB_SESSIONCTX pCtx)
{
    if (pCtx->session_state != WAIT_ON_PDC_NAME)
        return TRUE;

    if (MS_IsKnownPDCName ())
    {
        pCtx->session_state = FINISH_NEGOTIATE;
    }
    else if (pCtx->end_time <= rtp_get_system_msec() ())
    {
        pCtx->session_state = FAIL_NEGOTIATE;
    }

    return TRUE;
}

static BBOOL SMBS_StateWaitOnPDCIP (PSMB_SESSIONCTX pCtx)
{
    char pdc [RTSMB_NB_NAME_SIZE + 1];

    if (pCtx->session_state != WAIT_ON_PDC_IP)
        return TRUE;

    if (!MS_GetPDCName (pdc))
    {
        /* we've should've already alotted time and sent out a query.   */
        /* let's not do it again                                        */
        pCtx->session_state = WAIT_ON_PDC_NAME;
        return TRUE;
    }

    if (rtsmb_srv_nbns_is_in_name_cache (pdc, RTSMB_NB_NAME_TYPE_SERVER))
    {
        pCtx->session_state = FINISH_NEGOTIATE;
    }
    else if (pCtx->end_time <= rtp_get_system_msec())
    {
        pCtx->session_state = FAIL_NEGOTIATE;
    }

    return TRUE;
}

static BBOOL SMBS_StateContinueNegotiate (PSMB_SESSIONCTX pCtx)
{
    PFBYTE pInBuf;
    PFVOID pOutBuf;

    /**
     * Set up incoming and outgoing header.
     */
    pInBuf = (PFBYTE) SMB_INBUF (pCtx);
    pOutBuf = SMB_OUTBUF (pCtx);

    /* since we are coming here from a pdc discovery, restore state   */
    pInBuf[0] = 0xFF;
    pInBuf[1] = 'S';
    pInBuf[2] = 'M';
    pInBuf[3] = 'B';
    pInBuf[4] = SMB_COM_NEGOTIATE;

    SMBS_ProcSMBBody (pCtx);
    pCtx->session_state = IDLE;

    return SMBS_SendMessage (pCtx, pCtx->outBodySize, TRUE);
}
#endif

static void rtsmb_srv_pdc_session_cycle (PNET_SESSIONCTX *session)
{
    BBOOL isDead = FALSE;
    BBOOL rv = TRUE;
    PSMB_SESSIONCTX pSCtx = &(*session)->netsessiont_smbCtx;

    SMBS_claimSession (*session);

    /* keep session alive while we do stuff */
    switch (pSCtx->session_state)
    {
    case BROWSE_MUTEX:
    case BROWSE_SENT:
    case WAIT_ON_PDC_NAME:
    case WAIT_ON_PDC_IP:
    case FINISH_NEGOTIATE:
    case FAIL_NEGOTIATE:
        (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
        break;
    default:
        break;
    }
    /* handle special state cases here, potentially skipping netbios layer */
    switch (pSCtx->session_state)
    {
#if (INCLUDE_RTSMB_DC)
    case WAIT_ON_PDC_NAME:
        SMBS_StateWaitOnPDCName (pSCtx);
        break;
    case WAIT_ON_PDC_IP:
        SMBS_StateWaitOnPDCIP (pSCtx);
        break;
    case FINISH_NEGOTIATE:
    case FAIL_NEGOTIATE:
        SMBS_StateContinueNegotiate (pSCtx);
        break;
#endif
    case BROWSE_MUTEX:
    case BROWSE_SENT:
    case BROWSE_FINISH:
    case BROWSE_FAIL:
        rtsmb_srv_browse_finish_server_enum (pSCtx);
        break;
    default:
        break;
    }
    SMBS_releaseSession (*session);
}



static char NetStatsBuffer[40960];
#define highwater 40000
static int  NetStatsBufferLength = 0;

EXTERN_C void SMBU_DiagNetStatsAppend(char *buffer)
{
int  _NetStatsBufferLength = NetStatsBufferLength ;
 _NetStatsBufferLength += tc_strlen(buffer);
 if (_NetStatsBufferLength > highwater)
 {
   _NetStatsBufferLength =   NetStatsBufferLength = 0;
 }
 tc_strcpy(&NetStatsBuffer[NetStatsBufferLength],buffer);
 NetStatsBufferLength = _NetStatsBufferLength;

}

EXTERN_C char *SMBU_DiagFormatNetStats(char *buffer)
{
   buffer += tc_sprintf(buffer, (char *)"Master socket: %d Signalling socket: %d\n", get_master_socket(), get_signalling_socket());
   buffer += tc_sprintf(buffer, (char *)"Socket timeouts:  %d Sokcet session shutdowns: %d\n", socket_timeout_shutdowns, socket_requested_shutdowns);

//   for (int i = 0; i < CFG_RTSMB_MAX_SESSIONS; i++)
//   {
//      buffer += tc_sprintf(buffer, (char *)"  %d %10.10s %d\n", i, state_names[(int)all_sessions[i].get_session_state()], all_sessions[i].get_session_socket());
//   }
  buffer += tc_sprintf(buffer, (char *)"  Last select list size: %d\n", diagreadListSize);
  for (int i = 0; i < diagreadListSize; i++)
  {
     buffer += tc_sprintf(buffer, (char *)"  %d: SOCK: %d\n", i, diagreadList[i]);
  }
  buffer += tc_sprintf(buffer, (char *)"  Accept History: [");
  for (int i = 0; i < diag_accept_socket_history_count; i++)
    buffer += tc_sprintf(buffer, (char *)"%d,", diag_accept_socket_history[i]);
  buffer += tc_sprintf(buffer, (char *)"]\n");
  buffer += tc_sprintf(buffer, (char *)"  Close History: [");
  for (int i = 0; i < diag_close_socket_history_count; i++)
    buffer += tc_sprintf(buffer, (char *)"%d,", diag_close_socket_history[i]);
  buffer += tc_sprintf(buffer, (char *)"]\n");


//   pnCtx->netsessiont_lastActivity,
//   pnCtx->netsessiont_smbCtx._yieldTimeout,
//   pnCtx->netsessiont_smbCtx._yieldFlags,
//   pnCtx->netsessiont_smbCtx.session_state);


  buffer += tc_sprintf(buffer, (char *)"  Sessions:\n");
  for (int i = 0; i < prtsmb_srv_ctx->mainThread->numSessions; i++)
  {
    if (!prtsmb_srv_ctx->mainThread->sessionList[i])
    {
      buffer += tc_sprintf(buffer, (char *)"%d:session:NULL\n", i, prtsmb_srv_ctx->mainThread->sessionList[i]);
    }
    else
    {
      int index = INDEX_OF(prtsmb_srv_ctx->sessions, prtsmb_srv_ctx->mainThread->sessionList[i]);
      buffer += tc_sprintf(buffer, (char *)"%d: session:%X index:%d sock:%d active:%lu ", i, prtsmb_srv_ctx->mainThread->sessionList[i], index ,prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx.sock,prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_lastActivity);
//      buffer += tc_sprintf(buffer, (char *)"%d: session:%X index:%d sock:%d active:%lu ", i, prtsmb_srv_ctx->mainThread->sessionList[i], index ,prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx.sock,prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx->netsessiont_lastActivity);
      if (prtsmb_srv_ctx->mainThread->sessionList[i]->netsessiont_smbCtx.sessionoplock_control._yieldSession)
        buffer += tc_sprintf(buffer, (char *)"YIELD \n");
      else
        buffer += tc_sprintf(buffer, (char *)"RUN\n");
    }
  }
  buffer += tc_sprintf(buffer, (char *)"  Lock Break History:\n");
  buffer += tc_sprintf(buffer, "%s", NetStatsBuffer);
  return buffer;
}



#endif /* INCLUDE_RTSMB_SERVER */
