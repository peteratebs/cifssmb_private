/*                                                                        */
/* SRVPROCSMB.C -                                                             */
/*                                                                        */
/* EBSnet - RTSMB                                                         */
/*                                                                        */
/* Copyright EBS Inc. , 2016                                             */
/* All rights reserved.                                                   */
/* This code may not be redistributed in source or linkable object form   */
/* without the consent of its author.                                     */
/*                                                                        */
/* Module description:                                                    */
/* Handles most of the actual processing of packets for the RTSMB server. */
// BBOOL SMBS_ProcNegotiateProtocol  // Strange one, shared by both SMB1 and 2
// BBOOL SMBS_SendMessage            // Used by smb2 fi\or echo and read raw
// void SMBS_CloseSession
// void SMBS_CloseShare
// void SMBS_InitSessionCtx_smb
// void SMBS_srv_netssn_connection_close_session
// void SMBS_srv_netssn_cycle
// void SMBS_srv_netssn_init
// void SMBS_Tree_Init
// void SMBS_Tree_Shutdown
// void SMBS_User_Init
// void SMBS_User_Shutdown  // Friend with smb1 shutdown
//
/*                                                                        */

#warning duplicate define
#define CFG_RTSMB_MAX_SESSIONS              8

#pragma GCC diagnostic ignored "-Wwrite-strings"


#include "smbdefs.h"

#include "rtpfile.h"
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

#include "srvsmbssn.h"
#include "srvnbns.h"

#define DOPUSH 1

#ifdef SUPPORT_SMB2
#include "com_smb2.h"
#include "com_smb2_ssn.h"
#include "srv_smb2_model.h"
EXTERN_C BBOOL SMBS_proc_RTSMB2_NEGOTIATE_R_from_SMB (PSMB_SESSIONCTX pSctx);
EXTERN_C int SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx);

#include "srvyield.h"
#endif


void srvsmboo_init(PNET_THREAD pThread);
void srvsmboo_cycle(int timeout);
int srvsmboo_get_new_session_socket(RTP_SOCKET  *psock);
void srvsmboo_check_for_new_sessions(void);
int srvsmboo_new_session_socket(RTP_SOCKET  *psock);
int srvsmboo_get_session_read_list(RTP_SOCKET *readList);
void srvsmboo_close_session(RTP_SOCKET sock);
void srvsmboo_close_socket(RTP_SOCKET sock);
void srvsmboo_netssn_shutdown(void);
void srvsmboo_get_legacy_c_thread_structure(void);
EXTERN_C void srvsmboo_panic(char *panic_string);

static void SMBS_ProcSMBBody (PSMB_SESSIONCTX pSctx);
static void SMBS_ProcSMBBodyPacketReplay (PSMB_SESSIONCTX pSctx);
static void SMBS_PopContextBuffers (PSMB_SESSIONCTX pCtx);
static void SMBS_InitSessionCtx (PSMB_SESSIONCTX pSmbCtx, RTP_SOCKET sock);
static void SMBS_PointSmbBuffersAtNetThreadBuffers (PSMB_SESSIONCTX pCtx, PNET_THREAD pThread);
static BBOOL SMBS_StateWaitOnPDCName (PSMB_SESSIONCTX pCtx);
static BBOOL SMBS_StateWaitOnPDCIP (PSMB_SESSIONCTX pCtx);
static BBOOL SMBS_StateContinueNegotiate (PSMB_SESSIONCTX pCtx);
static PNET_SESSIONCTX allocateSession (void);
static void freeSession (PNET_SESSIONCTX p);
static void SMBS_claimSession (PNET_SESSIONCTX pCtx);
static void SMBS_releaseSession (PNET_SESSIONCTX pCtx);
EXTERN_C void SMBS_InitSessionCtx_smb(PSMB_SESSIONCTX pSmbCtx, int protocol_version);


EXTERN_C BBOOL ProcSMB1NegotiateProtocol (PSMB_SESSIONCTX pCtx, SMB_DIALECT_T dialect, int priority, int bestEntry, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf);
EXTERN_C BBOOL SMBS_ProcSMB1PacketExecute (PSMB_SESSIONCTX pSctx,RTSMB_HEADER *pinCliHdr,PFBYTE pInBuf, RTSMB_HEADER *poutCliHdr, PFVOID pOutBuf);
EXTERN_C BBOOL ProcWriteRaw2 (PSMB_SESSIONCTX pCtx, PFBYTE data, PFVOID pOutBuf, word bytesRead);

EXTERN_C void rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive);
EXTERN_C  void rtsmb_srv_browse_finish_server_enum (PSMB_SESSIONCTX pCtx);

EXTERN_C RTP_SOCKET rtsmb_nbds_get_socket (void);

static BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx);    // Called from rtsmb_srv_netssn_session_cycle
#define SEND_NO_REPLY   0
#define SEND_REPLY      1
#define OPLOCK_YIELD    2
#define EXECUTE_PACKET  3
#define SMB2PROCBODYACTION int
static SMB2PROCBODYACTION SMBS_ProcSMB1BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay);
static SMB2PROCBODYACTION SMBS_ProcSMB2BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay);
BBOOL gl_disablesmb2 = FALSE;

static BBOOL SMBS_ProcSMBBodyPacketEpilog (PSMB_SESSIONCTX pSctx, BBOOL doSend);
static BBOOL SMBS_PushContextBuffers (PSMB_SESSIONCTX pCtx);



static BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize);


/*
================
This function processes one smb packet.

    @packetSize: This is the declared size of the incoming packet.

    return: If an error occurs which is a breach of client trust, we return FALSE,
        indicating that the connection to the client should be shut off.  This happens
        if the client sends more data than we negotiated or if the client is not sending
        valid smbs, for example.
================
*/


static void SMBS_ProcSMBBodyPacketReplay (PSMB_SESSIONCTX pSctx)
{  // We either timed out or we got signalled so clear the timeout,
  // The command processor can query the flags (SMB2TIMEDOUT|SMB2SIGNALED) to see what happened
  yield_c_clear_timeout(pSctx);
  int pcktsize = (int) (pSctx->in_packet_size - pSctx->current_body_size);
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"YIELD:: SMBS_ProcSMBBodyPacketReplay: in_size:%d body_size:%d pcktsize:%d \n",pSctx->in_packet_size , pSctx->current_body_size,pcktsize);
  SMB2PROCBODYACTION r;
    if (pSctx->isSMB2)
      r = SMBS_ProcSMB2BodyPacketExecute(pSctx, TRUE);   // Is a replay
    else
      r = SMBS_ProcSMB1BodyPacketExecute (pSctx, TRUE);  // V1 Replay shouldn't occur

  BBOOL dosend = (r== SEND_REPLY);
  if (r==OPLOCK_YIELD)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"YIELD:: SMBS_ProcSMBBodyPacketReplay yield: \n");
    yield_c_set_timeout(pSctx);
    dosend = FALSE;
  }
  // Send output if there is any or process socket closures ok whetehr yielding or ruynning
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketReplay call Epilog with SendRequest %d: CloseRequest:%d\n", dosend, pSctx->doSessionClose);
  BBOOL rr=SMBS_ProcSMBBodyPacketEpilog (pSctx, dosend);
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketReplay returned from Epilog r: %d\n",rr);
}

static BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize)
{
    PFBYTE pInBuf,pSavedreadBuffer;
    PFVOID pOutBuf;
    BBOOL doSend = FALSE;
    BBOOL doSocketClose = FALSE;
    int length;
    int protocol_version = 0;
    BBOOL returnVal  = TRUE;
    rtsmb_size saved_body_size,saved_in_packet_size;

    pSctx->doSocketClose = FALSE;
    pSctx->doSessionClose = FALSE;

    // The command processor can query the flags (SMB2TIMEDOUT|SMB2SIGNALED) to see what happened
    yield_c_clear_timeout(pSctx);

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: NBSS Packet rcved: of size %lu\n",packetSize);
    if (packetSize > CFG_RTSMB_SMALL_BUFFER_SIZE)
//    if (packetSize > pSctx->readBufferSize)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBPacket:  Packet of size %d too big for buffer of size %d, Tossing packet.\n ", packetSize, (int)pSctx->readBufferSize);
        return TRUE; /* eat the packet */
    }

    /**
     * We need to make sure we are making some progress (i.e. packetSize != 0)
     */
    if (packetSize < 1)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"Warning: enlargening 0-length packet\n");
        packetSize = 1;
    }

    /**
     * Set up incoming and outgoing header.
     */


    pInBuf = (PFBYTE) SMB_INBUF (pSctx);
    pOutBuf = SMB_OUTBUF (pSctx);
    pSavedreadBuffer =  pInBuf;
    pSavedreadBuffer -= RTSMB_NBSS_HEADER_SIZE;
    saved_body_size = pSctx->current_body_size - RTSMB_NBSS_HEADER_SIZE;
    saved_in_packet_size = pSctx->in_packet_size;


    switch (pSctx->session_state)
    {
    case WRITING_RAW:

        pSctx->in_packet_size =  packetSize;
        pSctx->current_body_size = 0;
        pSctx->in_packet_timeout_base = rtp_get_system_msec();

    case WRITING_RAW_READING:
        /**
         * Read bytes from wire.
         */
        if ((length = rtsmb_net_read (pSctx->sock, pInBuf + pSctx->current_body_size,
            pSctx->readBufferSize - pSctx->current_body_size, packetSize - pSctx->current_body_size)) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBPacket:  Error on read.  Ending session.\n");
            return FALSE;
        }
        pSctx->current_body_size += (dword)length;

        if (pSctx->current_body_size < pSctx->in_packet_size)
        {
            /* We didn't get it all.  We'll have to stop and try again.   */
            /* are we out of time?                                        */
            if (IS_PAST (pSctx->in_packet_timeout_base, RTSMB_NB_UCAST_RETRY_TIMEOUT))
            {
                SMBS_Setsession_state(pSctx, IDLE);
            }
            else
            {
                SMBS_Setsession_state(pSctx, WRITING_RAW_READING);
            }
            return TRUE;
        }

        /**
         * If we are writing raw data from net to disk, don't try to interpret
         * header and rather just call ProcWriteRaw2.
         *
         * pInSmbHdr will contain raw data, pOutSmbHdr will be the same as the
         * WriteRaw call immediately prior, since we haven't emptied the writeBuffer.
         */
        doSend = ProcWriteRaw2 (pSctx, pInBuf, pOutBuf, (word) length);
        freeBigBuffer (pSctx->readBuffer);  /* safe to release, since all write raws are only one packet large */
        pSctx->readBuffer = pSctx->smallReadBuffer;
        pSctx->readBufferSize = (dword)SMB_BUFFER_SIZE;
        pSctx->writeRawInfo.amWritingRaw = FALSE;
        SMBS_Setsession_state(pSctx, IDLE);
        break;
#ifdef SUPPORT_SMB2
    case NOTCONNECTED:
#endif
#define SMBSIGSIZE 4
    case IDLE:
    {
        /**
         * Read starting bytes from the wire.
         */
        if ((length = rtsmb_net_read (pSctx->sock, pInBuf, pSctx->readBufferSize, SMBSIGSIZE)) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBPacket:  Error on read.  Ending session.\n");
            return FALSE;
        }
        if ((pInBuf[0] == 0xFF) && (pInBuf[1] == 'S') && (pInBuf[2] == 'M')  && (pInBuf[3] == 'B')) protocol_version = 1;
        else if ((pInBuf[0] == 0xFE) && (pInBuf[1] == 'S') && (pInBuf[2] == 'M')  && (pInBuf[3] == 'B')) protocol_version = 2;
        else protocol_version = 0;


        /**
         * If the packet is not an SMB, end connection.
         */
        if (protocol_version == 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBPacket: Not SMB or SMB2 packet\n");
            /* If we were nice, we'd send a message saying we don't understand.            */
            /* But, we don't know any values to fill it with (like tid, uid) or whatever,  */
            /* so the client won't know which message was bad.  Plus, if they are          */
            /* sending bad messages, they're up to no good, so we should just end contact. */
/*          SMBU_CreateDummySmb (pOutSmbHdr);                                              */
/*          SMBU_FillError (pOutSmbHdr, SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD);                 */
/*          return SMBS_SendMessage (pSctx, SMBU_GetSize (pOutSmbHdr), TRUE);              */
            return FALSE;
        }
        // If
#ifdef SUPPORT_SMB2
        if (!pSctx->protocol_version)
           pSctx->protocol_version=1;
        if (protocol_version == 2 && gl_disablesmb2)
          return FALSE;
        if (pSctx->protocol_version != protocol_version)
        {
#if (DOPUSH)
          if (protocol_version == 2)
          {
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBPacket:  call SMBS_PushContextBuffers.\n");
            if (!SMBS_PushContextBuffers (pSctx))
                return FALSE;
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // If using private session buffers
             // Copy the start of the frame to to smb2 buffer we hjust allocated
             tc_memcpy(pSctx->readBuffer, pSavedreadBuffer,SMBSIGSIZE+RTSMB_NBSS_HEADER_SIZE);
#endif
          }
          else
          {  // Copy the smb2 buffer to the originginla buffer before we release the smb2 buffer
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // If using private session buffers
             tc_memcpy(pSctx->CtxSave.readBuffer, pSavedreadBuffer,SMBSIGSIZE+RTSMB_NBSS_HEADER_SIZE);
#endif
             SMBS_PopContextBuffers (pSctx);
          }
#endif
        }
        pSctx->protocol_version = protocol_version;
        // Start a new session if we are connected and the current protocol doesn't match the incoming packet
        if (pSctx->session_state == IDLE)
        {
           if ((protocol_version == 2 && !pSctx->isSMB2) || (protocol_version == 1 && pSctx->isSMB2))
           {
             PNET_SESSIONCTX pNctxt = SMBS_findSessionByContext(pSctx);
             if (pNctxt)
             {
               SMBS_srv_netssn_connection_close_session(pNctxt);
             }
             SMBS_Setsession_state(pSctx, NOTCONNECTED);
             RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBPacket:  Protocol switch detected resetting session.\n");
             // We'll fall into the not connected handler and initialize based on the header
           }
        }

        if (pSctx->session_state == NOTCONNECTED)
        {
            /* Initialize uids, tid, and fid buckets for the new session if it's version 2 also initialize v2 context block in pSmbCtx Sets pSctx->isSMB2 = TRUE/FALSE*/
            SMBS_InitSessionCtx_smb(pSctx, protocol_version);
            // Okay we have a protocol
            SMBS_Setsession_state(pSctx, IDLE);
        }
#endif
        pSctx->in_packet_size = packetSize;
        pSctx->current_body_size = SMBSIGSIZE;
        pSctx->in_packet_timeout_base = rtp_get_system_msec();
    }
    case READING:
    {
        SMB2PROCBODYACTION bodyR;
        dword current_body_size = pSctx->current_body_size;
        if (pSctx->isSMB2)
        {
           bodyR = SMBS_ProcSMB2BodyPacketExecute(pSctx, FALSE);
        }
        else
        {
           bodyR = SMBS_ProcSMB1BodyPacketExecute (pSctx, FALSE);
        }

        doSend = (bodyR == SEND_REPLY);
        if (bodyR == OPLOCK_YIELD)
        {
          // Clear the yield status bits and set the yield timeout fence
          yield_c_set_timeout(pSctx);
          pSctx->in_packet_size = saved_in_packet_size;
          pSctx->readBuffer = pSavedreadBuffer;
          pSctx->current_body_size = saved_body_size;
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket yielded\n");
        }
        if (pSctx->session_state == NOTCONNECTED)
        {
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, (char *)"DIAG:Returned to not-connected stated\n");
        }
        break;
    }
    default:
        return TRUE;
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket call Epilog with SendRequest %d: CloseRequest:%d\n", doSend, pSctx->doSessionClose);
    return SMBS_ProcSMBBodyPacketEpilog (pSctx, doSend);
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, (char *)"DIAG: SMBS_ProcSMBPacket back from Epilog with SendRequest %d: CloseRequest:%d\n", doSend, pSctx->doSessionClose);
}

static BBOOL SMBS_ProcSMBBodyPacketEpilog (PSMB_SESSIONCTX pSctx, BBOOL doSend)
{
    BBOOL returnVal  = TRUE;
    /**
     * We clear the incoming buffer as a precaution, because we don't want
     * malicious clients somehow tricking us into accepting bad data if we
     * see an old packet or random data here.
     */
    /* It's not clear we need this, and not doing it let's us interrupt ourselves   */
    /* in the middle of a packet and reprocess it later.                            */
    /*tc_memset (pInBuf, 0, pSctx->readBufferSize);                                 */

    if (doSend)
    {
       if (oplock_diagnotics.performing_replay) { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"YIELD:: SMBS_ProcSMBBodyPacketEpilog from replay seending bytes: %d\n", pSctx->outBodySize); }
        returnVal = SMBS_SendMessage (pSctx, pSctx->outBodySize, TRUE);
       { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketEpilog sent %lu returned: %d\n",pSctx->outBodySize, returnVal); }
    }
    else {  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketEpilog called with no send request\n"); }
    if (pSctx->doSessionClose)
    { // Do it if a session close is requested and return false so we close the socket
       if (oplock_diagnotics.performing_replay)
        { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketEpilog closing from replay\n"); }
       else
        { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketEpilog closing from NBSS layer\n"); }
       pSctx->doSessionClose = FALSE;
       PNET_SESSIONCTX pNctxt = SMBS_findSessionByContext(pSctx);
       if (pNctxt)
          SMBS_srv_netssn_connection_close_session(pNctxt);
       returnVal = FALSE;    // So we return to close the socket
    }
    if (pSctx->doSocketClose)
        return FALSE;
    else
        return returnVal;
}



static void SMBS_ProcSMBBody (PSMB_SESSIONCTX pSctx)
{
SMB2PROCBODYACTION r;
   if (pSctx->isSMB2)
   {
     r = SMBS_ProcSMB2BodyPacketExecute(pSctx, FALSE);
   }
   else
   {
     r = SMBS_ProcSMB1BodyPacketExecute (pSctx, FALSE);
   }
}

// return SEND_NO_REPLY or EXECUTE_PACKET
// sets session_state to WAIT_ON_PDC_NAME,WAIT_ON_PDC_IP,IDLE,READINS
static SMB2PROCBODYACTION SMBS_ReadNbssPacketToSessionCtxt (PSMB_SESSIONCTX pSctx)
{
    PFBYTE pInBuf;
    PFVOID pOutBuf;
    int header_size;
    int length;
    BBOOL doSend = FALSE;

    /**
     * Set up incoming and outgoing packet header.
     */
    pInBuf = (PFBYTE) SMB_INBUF (pSctx);
    pOutBuf = SMB_OUTBUF (pSctx);
#if (INCLUDE_RTSMB_DC)
    if (pInBuf[4] == SMB_COM_NEGOTIATE &&
        pSctx->accessMode == AUTH_USER_MODE && pSctx->session_state == IDLE)
    {
        char pdc [RTSMB_NB_NAME_SIZE + 1];

        /* we must connect with the dc first   */
        if (!MS_GetPDCName (pdc))
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBBody:  NEGOTIATE being processed, must find PDC name.\n");

            /* change our state to waiting on pdc name   */
            SMBS_Setsession_state(pSctx, WAIT_ON_PDC_NAME);

            MS_SendPDCQuery (); /* jump start the search */

            pSctx->end_time = rtp_get_system_msec() + RTSMB_NBNS_KEEP_ALIVE_TIMEOUT;
            return SEND_NO_REPLY;
        }

        if (!rtsmb_srv_nbns_is_in_name_cache (pdc, RTSMB_NB_NAME_TYPE_SERVER))
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMBBody:  NEGOTIATE being processed, must find PDC ip.\n");

            /* change our state to waiting on pdc ip   */
            SMBS_Setsession_state(pSctx, WAIT_ON_PDC_IP);

            rtsmb_srv_nbns_start_query_for_name (pdc, RTSMB_NB_NAME_TYPE_SERVER);

            pSctx->end_time = rtp_get_system_msec() + RTSMB_NBNS_KEEP_ALIVE_TIMEOUT;

            return SEND_NO_REPLY;
        }

        /* ok, we can continue   */
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMBBody:  NEGOTIATE being processed, we've got all the information we need.\n");
    }
#endif
    /**
     * Read remaining bytes from wire (there should be a header there already).
     */

    if ((length = rtsmb_net_read (pSctx->sock, (PFBYTE) PADD (pInBuf, pSctx->current_body_size),
        pSctx->readBufferSize - pSctx->current_body_size, pSctx->in_packet_size - pSctx->current_body_size)) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMBBody:  Error on read.\n");
        return SEND_NO_REPLY;
    }
    pSctx->current_body_size += (dword)length;

    if (pSctx->current_body_size < pSctx->in_packet_size)
    {
        /* We didn't get it all.  We'll have to stop and try again.   */
        /* are we out of time?   */
        if (IS_PAST (pSctx->in_packet_timeout_base, RTSMB_NB_UCAST_RETRY_TIMEOUT))
        {
            SMBS_Setsession_state(pSctx, IDLE);
        }
        else
        {
            SMBS_Setsession_state(pSctx, READING);
        }
        return SEND_NO_REPLY;
    }
    SMBS_Setsession_state(pSctx, IDLE);
    return EXECUTE_PACKET;
}



static SMB2PROCBODYACTION SMBS_ProcSMB2BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay)
{
    SMB2PROCBODYACTION r;
    if (!isReplay)
    { // Pull the remainder of the NBSS packet from the stream if it is not a replay. SMB1 PDC support is inside SMBS_ReadNbssPacketToSessionCtxt as well.
      r=SMBS_ReadNbssPacketToSessionCtxt (pSctx);   // Sets state to WAIT_ON_PDC_NAME,WAIT_ON_PDC_IP,IDLE,READINS
      if (r!=EXECUTE_PACKET)
        return r;
    }
    r = SEND_NO_REPLY;
    // Keep all moving parts (pointers, indeces etc) and manage a state machine trhrough the context structure.
    // State machine which may reenter and restart in phase 2
    //                  phase 1                  |        phase 2
    // ST_INIT -> (ST_INPROCESS|ST_FALSE|ST_TRUE)->(ST_INPROCESS|ST_TRUE|ST_YIELD)->->(ST_INPROCESS|ST_TRUE|ST_YIELD)
    // SMBS_ReadNbssPacketToSessionCtxt() can return and reenter from phase II
    // Proc_smb2_Create() and Proc_smb2_Write() use this to wait for an oplock/record lock releases
    // A timeout is allocated when it exits so it can be cleared if a reply is not recieved.

    int stackcontext_state = SMBS_ProcSMB2_Body (pSctx);
    if (stackcontext_state == ST_FALSE)
      r = SEND_NO_REPLY;
    else if (stackcontext_state == ST_TRUE)
    {
      r = SEND_REPLY;
    }
    else if (stackcontext_state == ST_YIELD)
    {
      r = OPLOCK_YIELD;
    }
    // Hold onto the context in a suspended state if we're yielding
    // Otherwise we can free the context and grab another one when we enter again
    if (r != OPLOCK_YIELD)
    {
      yield_c_drop_yield_point(pSctx->current_yield_Cptr);
      pSctx->current_yield_Cptr=0;
    }
    return r;
}

static SMB2PROCBODYACTION SMBS_ProcSMB1BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay)
{
    if (!isReplay)
    { // Pull from the stream if it is not a replays shouldn't occur in V1
      SMB2PROCBODYACTION r;
      r=SMBS_ReadNbssPacketToSessionCtxt (pSctx);   // Sets state to WAIT_ON_PDC_NAME,WAIT_ON_PDC_IP,IDLE,READINS
      if (r!=EXECUTE_PACKET)
        return r;
    }
    RTSMB_HEADER inCliHdr;
    RTSMB_HEADER outCliHdr;
    PFBYTE pInBuf;
    PFVOID pOutBuf;
    int header_size;
    int length;
    BBOOL doSend = FALSE;

    pInBuf = (PFBYTE) SMB_INBUF (pSctx);
    pOutBuf = SMB_OUTBUF (pSctx);

    /* read header   */
    if ((header_size = srv_cmd_read_header (pInBuf,
        pInBuf, pSctx->current_body_size, &inCliHdr)) == -1)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMBBody: Badly formed header");
        return SEND_NO_REPLY;
    }

    /**
     * Clear the write buffer.  Proc* functions assume that all unused bytes of
     * the buffer are zero.  (This shouldn't be true anymore, but can't hurt as
     * a precaution either.)
     */
    tc_memset (pOutBuf, 0, pSctx->writeBufferSize);

    pSctx->read_origin = pInBuf;
    PFBYTE pheader_size = (PFBYTE) header_size;
    pInBuf = (PFBYTE) PADD(pInBuf, pheader_size);

    /**
     * Set up outgoing header.
     */
    outCliHdr = inCliHdr;
    outCliHdr.flags |= SMB_FLG_RESPONSE;
    outCliHdr.flags &= NOT_FLAG(byte, SMB_FLG_CASELESSPATH);  /* ~SMB_FLG_CASELESSPATH;  we always send case sensitive */
    outCliHdr.flags &= NOT_FLAG(byte, SMB_FLG_CANONICALIZED); /* ~SMB_FLG_CANONICALIZED; nor do we canonicalize file names */
    outCliHdr.flags2 = 0;

    if (ON (inCliHdr.flags2, SMB_FLG2_UNICODESTR))
    {
        outCliHdr.flags2 |= SMB_FLG2_UNICODESTR;
    }

    pSctx->write_origin = (PFBYTE) pOutBuf;
    pSctx->pInHeader = &inCliHdr;
    pSctx->pOutHeader = &outCliHdr;

    /* fill it in once, just so we have something reasonable in place   */
    srv_cmd_fill_header (pSctx->write_origin, pSctx->write_origin, prtsmb_srv_ctx->small_buffer_size,
        &outCliHdr);

    pSctx->outBodySize = 0;

    /**
     * Set up some helper variables.
     */
    if (pSctx->accessMode == AUTH_SHARE_MODE)
    {
        pSctx->uid = 0;
    }
    else
    {
        pSctx->uid = outCliHdr.uid;
    }
    pSctx->pid = outCliHdr.pid;
    pSctx->tid = outCliHdr.tid;

    /**
     * Do a quick check here that the first command we receive is a negotiate.
     */
    if (pSctx->dialect == DIALECT_NONE && inCliHdr.command != SMB_COM_NEGOTIATE)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMBBody:  Bad first packet -- was not a NEGOTIATE.\n");
        SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
        doSend = TRUE;
    }
    else if (pSctx->session_state == FAIL_NEGOTIATE)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMBBody:  Failing pending negotiation.\n");
        SMBU_FillError (pSctx, &outCliHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
        doSend = TRUE;
    }
    else
    {
      doSend = SMBS_ProcSMB1PacketExecute (pSctx, &inCliHdr, pInBuf, &outCliHdr, pOutBuf);
    }
    if (doSend)
       return SEND_REPLY;
    else
       return SEND_NO_REPLY;
}

/* this changes the permenant buffers used by this session   */
static BBOOL SMBS_PushContextBuffers (PSMB_SESSIONCTX pCtx)
{
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // Don't swap pointers if we are using exclusive buffers
PSMB_SESSIONCTX_SAVE pCtxSave = &pCtx->CtxSave;
    pCtxSave->smallReadBuffer = pCtx->smallReadBuffer;
    pCtxSave->smallWriteBuffer = pCtx->smallWriteBuffer;
    pCtxSave->readBuffer = pCtx->readBuffer;
    pCtxSave->writeBuffer = pCtx->writeBuffer;
    pCtx->readBuffer  = rtp_malloc(HARDWIRED_SMB2_MAX_NBSS_FRAME_SIZE);
    pCtx->writeBuffer = rtp_malloc(HARDWIRED_SMB2_MAX_NBSS_FRAME_SIZE);
    if (!pCtx->readBuffer || !pCtx->writeBuffer)
    {
     SMBS_PopContextBuffers(pCtx);
      return FALSE;
    }
    pCtx->smallReadBuffer = pCtx->readBuffer;
    pCtx->smallWriteBuffer =  pCtx->writeBuffer;
    pCtxSave->readBufferSize = pCtx->readBufferSize;
    pCtxSave->writeBufferSize = pCtx->writeBufferSize;
#endif
    pCtx->readBufferSize  = prtsmb_srv_ctx->max_smb2_frame_size;
    pCtx->writeBufferSize = prtsmb_srv_ctx->max_smb2_frame_size;
    return TRUE;
}

/* this changes the permanent buffers used by this session   */
static void SMBS_PopContextBuffers (PSMB_SESSIONCTX pCtx)
{
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // Don't swap pointers if we are using exclusive buffers
PSMB_SESSIONCTX_SAVE pCtxSave = &pCtx->CtxSave;
    if (pCtx->readBuffer)  rtp_free(pCtx->readBuffer);
    if (pCtx->writeBuffer)  rtp_free(pCtx->writeBuffer);
    pCtx->smallReadBuffer  = pCtxSave->smallReadBuffer;
    pCtx->smallWriteBuffer = pCtxSave->smallWriteBuffer;
    pCtx->readBuffer       = pCtxSave->readBuffer;
    pCtx->writeBuffer      = pCtxSave->writeBuffer;
    pCtx->readBufferSize   = pCtxSave->readBufferSize;
    pCtx->writeBufferSize  = pCtxSave->writeBufferSize;
#endif
    pCtx->readBufferSize   = prtsmb_srv_ctx->out_buffer_size;
    pCtx->writeBufferSize  = prtsmb_srv_ctx->out_buffer_size;

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

EXTERN_C void Smb2SrvModel_New_Session(struct smb_sessionCtx_s *pSmbCtx);
EXTERN_C void Smb2SrvModel_Free_Session(pSmb2SrvModel_Session pSession);

/* this changes the permenant buffers used by this session   */
static void SMBS_PointSmbBuffersAtNetThreadBuffers (PSMB_SESSIONCTX pCtx, PNET_THREAD pThread)
{
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 1) // Swap if we are using exclusive buffers
int session_index = SMBU_SessionToIndex(pCtx);
    pCtx->readBuffer              = prtsmb_srv_ctx->unshared_read_buffers [session_index];
    pCtx->smallReadBuffer         = prtsmb_srv_ctx->unshared_read_buffers [session_index];
    pCtx->smallWriteBuffer        = prtsmb_srv_ctx->unshared_write_buffers[session_index];
    pCtx->writeBuffer             = prtsmb_srv_ctx->unshared_write_buffers[session_index];
    pCtx->tmpBuffer               = prtsmb_srv_ctx->unshared_temp_buffers [session_index];
    pCtx->readBufferSize          = prtsmb_srv_ctx->out_buffer_size; // They are the same
    pCtx->writeBufferSize         = prtsmb_srv_ctx->out_buffer_size;
    pCtx->tmpSize                 = prtsmb_srv_ctx->temp_buffer_size;
#else
    pCtx->smallReadBuffer = pThread->_inBuffer;
    pCtx->smallWriteBuffer = pThread->_outBuffer;
    pCtx->tmpBuffer = pThread->tmpBuffer;
    pCtx->readBuffer = pThread->_inBuffer;
    pCtx->writeBuffer = pThread->_outBuffer;
    pCtx->readBufferSize  = prtsmb_srv_ctx->out_buffer_size;
    pCtx->writeBufferSize = prtsmb_srv_ctx->out_buffer_size;
    pCtx->tmpSize         = prtsmb_srv_ctx->temp_buffer_size;
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


BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock);



RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions);
RTSMB_STATIC void rtsmb_srv_netssn_connection_close (PNET_SESSIONCTX pSCtx );
RTSMB_STATIC void rtsmb_srv_netssn_thread_condense_sessions (PNET_THREAD pThread);
RTSMB_STATIC void rtsmb_srv_netssn_thread_main (PNET_THREAD pThread);
RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions);
RTSMB_STATIC void rtsmb_srv_netssn_session_yield_cycle (PNET_SESSIONCTX *session);
RTSMB_STATIC void rtsmb_srv_netssn_session_cycle (PNET_SESSIONCTX *session, int ready);


RTSMB_STATIC void rtsmb_srv_netssn_thread_cycle (PNET_THREAD pThread,long timeout)
{
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

    PNET_SESSIONCTX *session;
    int i,n;
    int readListSize;
    RTP_SOCKET readList[256];

    srvsmboo_cycle(timeout);
    srvsmboo_check_for_new_sessions();
    readListSize = srvsmboo_get_session_read_list(readList);
    if (readListSize == 0)
      return;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"srvsmboo_get_session_read_list: returned %d", readListSize);
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
//            srvobject_session_blocked(pThread,session); // marks an ended session
            continue;
        }

        /* make sure we bind the thread to the net session context */
       (*session)->netsessiont_pThread = pThread;

//        srvobject_session_enter(pThread,session);
        starting_state = (*session)->netsessiont_smbCtx.session_state;
        for (n = 0; n < readListSize; n++)
        {
            if (readList[n] == (*session)->netsessiont_sock)
            {
                rtsmb_srv_netssn_session_cycle (session, TRUE);
                break;
            }
        }
        /* session can be null here */
//        if (!*session)
//           srvobject_session_enter(pThread,session); // marks an ended session
        if (!*session)
          continue;

        // A yielded session's socket won't be in the socket list so check
        // if it is yielded and then check the countdown and wakup triggers
        if (yield_c_is_session_blocked(&(*session)->netsessiont_smbCtx))
//        if (yield_c_recieve_blocked(pThread->signal_object))
        {
          rtsmb_srv_netssn_session_yield_cycle (session);
        }
        else if (n == readListSize)
        { // A non yielded session timeded out, check for KEEPALIVES
            rtsmb_srv_netssn_session_cycle (session, FALSE);
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
//    srvobject_session_exit(pThread,session);

    rtsmb_srv_netssn_thread_condense_sessions (pThread);

    if (pThread->numSessions)
    {
        /* mix it up a bit, in case a session at the front is hogging time */
        pThread->index = ((dword) tc_rand () % pThread->numSessions);
    }
}




RTSMB_STATIC PNET_SESSIONCTX rtsmb_srv_netssn_connection_open (PNET_THREAD pThread, RTP_SOCKET  sock)
{
    PNET_SESSIONCTX pNetCtx;

    pNetCtx = allocateSession();
    if(pNetCtx)
    {
        pNetCtx->netsessiont_sock = sock;
        yield_c_new_session(pNetCtx);

        pNetCtx->netsessiont_lastActivity = rtp_get_system_msec ();
        SMBS_InitSessionCtx(&(pNetCtx->netsessiont_smbCtx), pNetCtx->netsessiont_sock);
        SMBS_PointSmbBuffersAtNetThreadBuffers (&pNetCtx->netsessiont_smbCtx, pThread);
        return pNetCtx;
    }
    else
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_srv_netssn_connection_open:  No free sessions\n");
        /* let them know we are rejecting their request */
        rtsmb_srv_nbss_send_session_response (sock, FALSE);
        return (PNET_SESSIONCTX)0;
    }
}


//
RTSMB_STATIC void rtsmb_srv_netssn_connection_close (PNET_SESSIONCTX pSCtx )
{

    SMBS_srv_netssn_connection_close_session(pSCtx);
    srvsmboo_close_socket((RTP_SOCKET) pSCtx->netsessiont_sock);
    freeSession (pSCtx);
}

//
RTSMB_STATIC void rtsmb_srv_netssn_thread_condense_sessions (PNET_THREAD pThread)
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

RTSMB_STATIC void rtsmb_srv_netssn_session_yield_cycle (PNET_SESSIONCTX *session)
{
BBOOL doCB=FALSE;
BBOOL dosend = TRUE;

    if ((*session)->netsessiont_smbCtx.isSMB2)
    {
        if (yield_c_check_signal(&(*session)->netsessiont_smbCtx))
       {
          OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_SIGNAL
          doCB=TRUE;
       }
       else
       {
         if(yield_c_check_timeout(&(*session)->netsessiont_smbCtx))
         { // Clear it so it doesn't fire right away
           yield_c_clear_timeout(&(*session)->netsessiont_smbCtx);
           doCB=TRUE;
           OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_TIMEOUT
         }
       }
    }

    if (doCB)
    {
       OPLOCK_DIAG_ENTER_REPLAY
       SMBS_ProcSMBBodyPacketReplay(&(*session)->netsessiont_smbCtx);
       OPLOCK_DIAG_EXIT_REPLAY
    }
}


static BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx)    // Called from rtsmb_srv_netssn_session_cycle
{
  BBOOL isDead = FALSE;
  RTSMB_NBSS_HEADER header;
  byte header_bytes[4];
  if (rtsmb_net_read (pSCtx->sock, pSCtx->readBuffer, pSCtx->readBufferSize, RTSMB_NBSS_HEADER_SIZE) == -1)
  {
    isDead = TRUE;
  }
  else if (rtsmb_nbss_read_header (pSCtx->readBuffer, RTSMB_NBSS_HEADER_SIZE, &header) < 0)
  {
    isDead = TRUE;
  }
  else
    {
      switch (header.type)
      {
        case RTSMB_NBSS_COM_MESSAGE:  /* Session Message */
          if (!header.size)
          {
             RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG:: rtsmb_srv_nbss_process_packet ignoring 0-length packet\n");
          }
          else
          {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG: rtsmb_srv_nbss_process_packet call SMBS_ProcSMBPacket\n");
            if (!SMBS_ProcSMBPacket (pSCtx, header.size))   //rtsmb_srv_nbss_process_packet stubs ?
            {
              RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG: rtsmb_srv_nbss_process_packet returned SMBS_ProcSMBPacket failure\n");
              isDead = TRUE;
            }
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG: rtsmb_srv_nbss_process_packet returned SMBS_ProcSMBPacket success\n");
          }
          break;
        case RTSMB_NBSS_COM_REQUEST:  /* Session Request */
            //      if (!rtsmb_srv_nbss_process_request (pSCtx->sock, &header))
            //      {
            //   isDead = TRUE;
            //        return FALSE;
            //      }
          break;
        default:
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_nbss_process_packet: Unhandled packet type %X\n", header.type);
        break;
      }
  }

  return !isDead;
}

RTSMB_STATIC void rtsmb_srv_netssn_session_cycle (PNET_SESSIONCTX *session, int ready)
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

    case READING:
    case WRITING_RAW_READING:
    {
        int pcktsize = (int) (pSCtx->in_packet_size - pSCtx->current_body_size);
        if (pcktsize == 0)
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Warning: rtsmb_srv_netssn_session_cycle ignoring 0-length packet: %d \n", pcktsize);
        } else
        {
           SMBS_ProcSMBPacket (pSCtx, pcktsize);/* rtsmb_srv_netssn_session_cycle finish reading what we started. */
        }
        break;
    }
    default:
        if (ready)
        {
            (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
            if (rtsmb_srv_nbss_process_packet (pSCtx) == FALSE)
            {
                isDead = TRUE;
            }
        }
        else
        {
            /*check for time out */
            if(IS_PAST ((*session)->netsessiont_lastActivity, RTSMB_NBNS_KEEP_ALIVE_TIMEOUT*4))
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_srv_netssn_session_cycle: Connection timed out on socket %ld ",(*session)->netsessiont_sock);
                (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
                isDead = TRUE;
            }
            else if (prtsmb_srv_ctx->enable_oplocks) // run down any oplock timers
            {
               oplock_c_break_check_wating_break_requests();
            }
        }
        break;
    }

    if (isDead)
    {
        rtsmb_srv_netssn_connection_close (*session);
        rv = FALSE;
        // Set to not connected so we allow reception of SMB2 negotiate packets.
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session closed\n");
        SMBS_Setsession_state(pSCtx, NOTCONNECTED);

    }
    else
    {
       // Send any oplock break alerts
       oplock_c_break_send_pending_breaks();
       // HEREHERE -  send any notify alerts
    }
    SMBS_releaseSession (*session);

    if (isDead)
    {
        *session = (PNET_SESSIONCTX)0;
    }
}


RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions)
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
    // p->yield_sock; A udp socket dedicated to signalling yield sessions was initialized at startup
}




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

	return rv;
}

static void freeSession (PNET_SESSIONCTX p)
{
	int location;
	location = INDEX_OF (prtsmb_srv_ctx->sessions, p);


	CLAIM_NET ();
	prtsmb_srv_ctx->sessionsInUse[location] = 0;
	RELEASE_NET ();
}

/**
 * At this point in the packet's life, only the first few bytes will be
 * read, in order to get the NetBios header.  This gives us the length
 * of the message, which we will then pull from the socket.
 *
 * Returns FALSE if we should end the session.
 */


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




/**
 * Allocates space for a new session, if available; else
 */
BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock)
{
    /*new session */
    PNET_SESSIONCTX pSCtx = rtsmb_srv_netssn_connection_open (pMaster, sock);
    PNET_THREAD pThread;

    if (pSCtx)
    {
        /**
         * Add new session to our list.
         */
        pMaster->sessionList[pMaster->numSessions] = pSCtx;
        pMaster->numSessions++;
        return TRUE;
    }
    else
        return FALSE;
}



/*
================
Proccess Negotiate protocol requests.  This function
  figures out what the highest supported dialog on both machines can be used for the
  remainder of the session.

================
*/


/*============================================================================   */
/*    IMPLEMENTATION PRIVATE STRUCTURES                                          */
/*============================================================================   */

#define DIALECT_TYPE rtsmb_char


RTSMB_STATIC DIALECT_TYPE srv_dialect_core[] = {'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ',
'P', 'R', 'O', 'G', 'R', 'A', 'M', ' ', '1', '.', '0', '\0'};
RTSMB_STATIC DIALECT_TYPE srv_dialect_lanman[] = {'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', '\0'};
RTSMB_STATIC DIALECT_TYPE srv_dialect_lm1_2x[] = {'L', 'M', '1', '.', '2', 'X', '0', '0', '2', '\0'};
RTSMB_STATIC DIALECT_TYPE srv_dialect_lanman2[] = {'L', 'A', 'N', 'M', 'A', 'N', '2', '.', '1', '\0'};
RTSMB_STATIC DIALECT_TYPE srv_dialect_ntlm[] = {'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', '\0'};
#ifdef SUPPORT_SMB2    /* Some branching to SMB2 from this file, no major processing */
RTSMB_STATIC DIALECT_TYPE srv_dialect_smb2002[] = {'S', 'M', 'B',' ', '2', '.', '0', '0', '2', '\0'};
RTSMB_STATIC DIALECT_TYPE srv_dialect_smb2xxx[] = {'S', 'M', 'B',' ', '2', '.', '?', '?', '?', '\0'};
// Use these instead as poor man's way to disable smb2002 need to implement max protocol
// RTSMB_STATIC DIALECT_TYPE srv_dialect_smb2002[] = {'N', 'O', 'N', 'E', '\0'};
// RTSMB_STATIC DIALECT_TYPE srv_dialect_smb2xxx[] = {'N', 'O', 'N', 'E', '\0'};
#endif


struct dialect_entry_s
{
    SMB_DIALECT_T dialect;
    DIALECT_TYPE * name;
    int priority;
}
 dialectList[] =
{
    {PC_NETWORK, srv_dialect_core, 0},
    {LANMAN_1_0, srv_dialect_lanman, 1},
    {LM1_2X002, srv_dialect_lm1_2x, 2},
    {LANMAN_2_1, srv_dialect_lanman2, 4},
    {NT_LM, srv_dialect_ntlm, 5},
#ifdef SUPPORT_SMB2
    {SMB2_2002, srv_dialect_smb2002, 6},
    {SMB2_2xxx, srv_dialect_smb2xxx, 7}
#endif
};
SMB_DIALECT_T max_dialect = SMB2_2xxx; // NT_LM;

// INTERFACE
/*============================================================================   */
/*    INTERFACE FUNCTIONS                                                        */
/*============================================================================   */

// Called from SMBS_ProcSMB1PacketExecute

BBOOL SMBS_ProcNegotiateProtocol (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID pInBuf, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf)
{
    int i, entry, bestEntry;
    SMB_DIALECT_T dialect = DIALECT_NONE;
    DIALECT_TYPE dialect_bufs[32][21];
    DIALECT_TYPE *dialects[32];
    RTSMB_NEGOTIATE command;



    for (i = 0; i < 32; i++)
    {
        dialects[i] = dialect_bufs[i];
        *dialects[i]=0;
    }

    command.num_dialects = 32;
    command.string_size = 20;
    command.dialects = dialects;
    READ_SMB (srv_cmd_read_negotiate);

    /**
     * Sending more than one negotiate is an error, cannot renegotiate
     * the dialect
     */
    if (pCtx->dialect != DIALECT_NONE)
    {
        SMBU_FillError (pCtx, pOutHdr, SMB_EC_ERRSRV, SMB_ERRSRV_ERROR);
        return TRUE;
    }

    for (entry = 0; entry < command.num_dialects; entry++)
    {
        /*check dialect field against dialect list   */
        for (i = PC_NETWORK; i < NUM_DIALECTS; i++)
        {
            if (dialectList[i].dialect > max_dialect)
              continue;
#ifdef SUPPORT_SMB2
            if (dialectList[i].name == srv_dialect_smb2002 || dialectList[i].name == srv_dialect_smb2xxx)
            {
               if (SMBU_DoesContain (dialects[entry], dialectList[i].name) == TRUE)
               {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "ProcNegotiateProtocol:  Responding to 2.002 option. !!!!!!!!!!!!!!\n");
                dialect = dialectList[i].dialect;
                bestEntry = entry;
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Responding to 2.002 option:  dialect == %d Best entry == %X\n",(int)dialect,(int)bestEntry );
            }
            } else
#endif
            {
            if (SMBU_DoesContain (dialects[entry], dialectList[i].name) == TRUE)
            {
                if ((dialect == DIALECT_NONE)
                    || (dialectList[dialect].priority < dialectList[i].priority))
                {
                    dialect = dialectList[i].dialect;
                    bestEntry = entry;
                }
            }
            }
        }
    }
#ifdef SUPPORT_SMB2
    if (dialect >= SMB2_2002) /* PVO */
    {
        return SMBS_proc_RTSMB2_NEGOTIATE_R_from_SMB (pCtx);
    }
#endif
    return ProcSMB1NegotiateProtocol(pCtx,dialect, dialectList[dialect].priority,bestEntry, pInHdr, pInBuf, pOutHdr, pOutBuf);
}

BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate)
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
================
This function frees resources held by an SMB session context.

    @pSmbCtx: This is the session context to free.

    return: Nothing.
================
*/
void SMBS_CloseSession(PSMB_SESSIONCTX pSmbCtx)
{
    word i;

    srvsmboo_close_session((RTP_SOCKET) pSmbCtx->sock);

    /**
     * Only data worth freeing is in user data and trees.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
        if (pSmbCtx->uids[i].inUse)
            SMBS_User_Shutdown (pSmbCtx, &pSmbCtx->uids[i]);

    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
        if (pSmbCtx->trees[i].inUse)
            SMBS_Tree_Shutdown (pSmbCtx, &pSmbCtx->trees[i]);
#if (DOPUSH)
    if (pSmbCtx->protocol_version == 2)
    {
       SMBS_PopContextBuffers (pSmbCtx);
       pSmbCtx->protocol_version = 1;
    }
#endif
}

/*
==============

==============
*/
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
    signalobject_Cptr saved_signal_object = prtsmb_srv_ctx->mainThread->signal_object;
    rtsmb_srv_netssn_thread_init (prtsmb_srv_ctx->mainThread, 0);
    prtsmb_srv_ctx->mainThread->signal_object = saved_signal_object;
    srvsmboo_init(prtsmb_srv_ctx->mainThread);
}

/*
==============
 poll to see if any of the  sockets belonging to a handler
 has something to be read.
==============
*/

void SMBS_srv_netssn_cycle (long timeout)
{
    if (!prtsmb_srv_ctx->mainThread)
    {
    word i;
        for (i=0;i<10;i++) { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_netssn_cycle sock: crashing lost mainTread %x \n",prtsmb_srv_ctx->mainThread);}
        int iCrash = 13 / 0;      // trap to the debugger
        return;
    }

    rtsmb_srv_netssn_thread_cycle (prtsmb_srv_ctx->mainThread, timeout);
#if INCLUDE_RTSMB_DC
    /* now see if we need to query for the pdc again */
    if (!MS_IsKnownPDCName () && next_pdc_find <= rtp_get_system_msec ())
    {
        MS_SendPDCQuery ();

        next_pdc_find = next_pdc_find + rtsmb_srv_netssn_pdc_next_interval ();
    }
#endif
}
// Close the session out but don't close the socket.
// Used when an SMB2 session tries to reconnect the session withiut closing the socket
void SMBS_srv_netssn_connection_close_session(PNET_SESSIONCTX pSCtx )
{
#ifdef SUPPORT_SMB2

   if (pSCtx->netsessiont_smbCtx.isSMB2)
// if (pSCtx->netsessiont_smbCtx.pCtxtsmb2Session)
     RTSmb2_SessionShutDown(&pSCtx->netsessiont_smbCtx.Smb2SessionInstance);
#endif

   SMBS_CloseSession( &(pSCtx->netsessiont_smbCtx) );
   SMBS_Setsession_state(&pSCtx->netsessiont_smbCtx,NOTCONNECTED);

}
void SMBS_Setsession_state(PSMB_SESSIONCTX pSctxt, SMBS_SESSION_STATE new_session_state)
{
   pSctxt->session_state = new_session_state;
}

PNET_SESSIONCTX SMBS_findSessionByContext (PSMB_SESSIONCTX pSctxt)
{
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;
	word i;
	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (prtsmb_srv_ctx->sessionsInUse[i] && &(prtsmb_srv_ctx->sessions[i].netsessiont_smbCtx) == pSctxt)
		{
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();

	return rv;
}

// Legacy implementaion, close this share in all sessions.
void SMBS_closeAllShares(PSR_RESOURCE pResource)
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
void SMBS_srv_netssn_shutdown (void)
{
    srvsmboo_netssn_shutdown();
    // Legacy code
    CLAIM_NET ();
    prtsmb_srv_ctx->threadsInUse[0] = 0;
    RELEASE_NET ();
}



#endif /* INCLUDE_RTSMB_SERVER */

