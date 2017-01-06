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


#include "com_smb2.h"
#include "com_smb2_ssn.h"
#include "srv_smb2_model.h"
#include "remotediags.h"




EXTERN_C BBOOL SMBS_ProcSMB1PacketExecute (PSMB_SESSIONCTX pSctx,RTSMB_HEADER *pinCliHdr,PFBYTE pInBuf, RTSMB_HEADER *poutCliHdr, PFVOID pOutBuf);
EXTERN_C BBOOL ProcWriteRaw2 (PSMB_SESSIONCTX pCtx, PFBYTE data, PFVOID pOutBuf, word bytesRead);
#define SEND_NO_REPLY   0
#define SEND_REPLY      1
#define OPLOCK_YIELD    2
#define EXECUTE_PACKET  3
#define SMB2PROCBODYACTION int
static SMB2PROCBODYACTION SMBS_ProcSMB1BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay);
SMB2PROCBODYACTION SMBS_ProcSMB2BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay);



BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize, BBOOL pull_nbss, BBOOL replay);

extern BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate);
EXTERN_C int SMBS_ProccessCompoundFrame (PSMB_SESSIONCTX pSctx, BBOOL replay);


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



static BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx)    // Called from rtsmb_srv_netssn_session_cycle
{
  BBOOL isDead = FALSE;
  RTSMB_NBSS_HEADER header;
  byte header_bytes[4];

  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_nbss_process_packet pull RTSMB_NBSS_HEADER_SIZE\n", rtp_get_system_msec());
  if (rtsmb_net_read (pSCtx->sock, pSCtx->readBuffer, pSCtx->readBufferSize, RTSMB_NBSS_HEADER_SIZE) == -1)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_nbss_process_packet pull RTSMB_NBSS_HEADER_SIZE failed\n", rtp_get_system_msec());
    isDead = TRUE;
  }
  if (!isDead)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_nbss_process_packet call rtsmb_nbss_read_header\n", rtp_get_system_msec());
    if (rtsmb_nbss_read_header (pSCtx->readBuffer, RTSMB_NBSS_HEADER_SIZE, &header) < 0)
    {
      isDead = TRUE;
    }
  }
  if (!isDead)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_nbss_process_packet Top content\n", rtp_get_system_msec());
    switch (header.type)
    {
      case RTSMB_NBSS_COM_MESSAGE:  /* Session Message */
        if (!header.size)
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG:: rtsmb_srv_nbss_process_packet ignoring 0-length packet\n");
        }
        else
        {
//          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG: rtsmb_srv_nbss_process_packet call SMBS_ProcSMBPacket\n");
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_nbss_process_packet call SMBS_ProcSMBPacket\n", rtp_get_system_msec());
          if (!SMBS_ProcSMBPacket (pSCtx, header.size, FALSE, FALSE))   //rtsmb_srv_nbss_process_packet stubs ?
          {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG: rtsmb_srv_nbss_process_packet returned SMBS_ProcSMBPacket failure\n");
            isDead = TRUE;
          }
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  rtsmb_srv_nbss_process_packet back SMBS_ProcSMBPacket\n", rtp_get_system_msec());
//          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"DIAG: rtsmb_srv_nbss_process_packet returned SMBS_ProcSMBPacket success\n");
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


BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize, BBOOL pull_nbss, BBOOL replay)
{
    // This calls us right away with pull_nbss = FALSE if it has a packet
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket in\n", rtp_get_system_msec());
    if (pull_nbss)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket pull\n", rtp_get_system_msec());
      return rtsmb_srv_nbss_process_packet(pSctx);
    }
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket in 2\n", rtp_get_system_msec());

    PFBYTE pInBuf,pSavedreadBuffer;
    PFVOID pOutBuf;
    BBOOL doSend = FALSE;
    int length;
    int protocol_version = 0;
    rtsmb_size saved_body_size,saved_in_packet_size;

    pSctx->doSocketClose = FALSE;
    pSctx->doSessionClose = FALSE;

//    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: NBSS Packet rcved: of size %lu\n",packetSize);
    if (packetSize > CFG_RTSMB_SMALL_BUFFER_SIZE)
//    if (packetSize > pSctx->readBufferSize)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket:  Packet of size %d too big for buffer of size %d, Tossing packet.\n ", packetSize, (int)pSctx->readBufferSize);
        return TRUE; /* eat the packet */
    }

    /**
     * We need to make sure we are making some progress (i.e. packetSize != 0)
     */
    if (!replay && packetSize < 1)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"Warning: enlargening 0-length packet\n");
        packetSize = 1;
    }

    /**
     * Set up incoming and outgoing header.
     */

    if (replay)   {    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: Replaying state == %d\n", pSctx->session_state);    }
    if (replay)   {   OPLOCK_DIAG_YIELD_SESSION_RUN }
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
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket:  Error on read.  Ending session.\n");
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
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket read\n", rtp_get_system_msec());
        if ((length = rtsmb_net_read (pSctx->sock, pInBuf, pSctx->readBufferSize, SMBSIGSIZE)) < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket:  Error on read.  Ending session.\n");
            return FALSE;
        }
        if ((pInBuf[0] == 0xFF) && (pInBuf[1] == 'S') && (pInBuf[2] == 'M')  && (pInBuf[3] == 'B')) protocol_version = 1;
        else if ((pInBuf[0] == 0xFE) && (pInBuf[1] == 'S') && (pInBuf[2] == 'M')  && (pInBuf[3] == 'B')) protocol_version = 2;
        else protocol_version = 0;

        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket process\n", rtp_get_system_msec());
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
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket:  no SMB or SMB2 signature.  Ending session.\n");
            return FALSE;
        }
        // If
#ifdef SUPPORT_SMB2
        if (!pSctx->protocol_version)
           pSctx->protocol_version=1;

        if (protocol_version == 2 && prtsmb_srv_ctx->max_protocol < 2002)
        {
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket:  SMB2 disabled.\n");
          return FALSE;
        }
        if (protocol_version == 2)
        {
           pSctx->readBufferSize  = prtsmb_srv_ctx->max_smb2_frame_size;
           pSctx->writeBufferSize = prtsmb_srv_ctx->max_smb2_frame_size;
        }
        else
        {
            pSctx->readBufferSize  = prtsmb_srv_ctx->out_buffer_size;
            pSctx->writeBufferSize = prtsmb_srv_ctx->out_buffer_size;
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
    case OPLOCK_SIGNALLED:
    {
        SMB2PROCBODYACTION bodyR;
        dword current_body_size = pSctx->current_body_size;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket execute in\n", rtp_get_system_msec());
        if (pSctx->isSMB2)
        {
   if (replay)   {    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: call SMBS_ProcSMB2BodyPacketExecute state == %d\n", pSctx->session_state);    }

           bodyR = SMBS_ProcSMB2BodyPacketExecute(pSctx, replay);
   if (replay)   {    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: back SMBS_ProcSMB2BodyPacketExecute r==  == %d\n", bodyR);    }
        }
        else
        {
           bodyR = SMBS_ProcSMB1BodyPacketExecute (pSctx, FALSE);
        }
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket execute out\n", rtp_get_system_msec());

        doSend = (bodyR == SEND_REPLY);
        if (bodyR == OPLOCK_YIELD)
        {
          // Clear the yield status bits and set the yield timeout fence
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
    BBOOL returnVal  = TRUE;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket call Epilog with SendRequest %d: CloseRequest:%d\n", doSend, pSctx->doSessionClose);
    if (doSend)
    {
       if (oplock_diagnotics.performing_replay)  { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"YIELD:: SMBS_ProcSMBBodyPacketEpilog from replay sending bytes ctxt: %lu stream: %lu\n", pSctx->outBodySize, pSctx->SMB2_FrameState.smb2stream.OutBodySize); }
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket send in\n", rtp_get_system_msec());
       returnVal = SMBS_SendMessage (pSctx, pSctx->outBodySize, TRUE);
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: T:%lu  SMBS_ProcSMBPacket send out\n", rtp_get_system_msec());

       if (!returnVal) { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket SMBS_SendMessage failed\n"); }
//       { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketEpilog sent %lu returned: %d\n",pSctx->outBodySize, returnVal); }
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
       { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBBodyPacketEpilog closed session from NBSS layer\n"); }
       returnVal = FALSE;    // So we return to close the socket
    }
    if (pSctx->doSocketClose)
    {
       { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: doSocketClose is set closing from NBSS layer\n"); }
        returnVal = FALSE;
    }

     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, (char *)"DIAG: SMBS_ProcSMBPacket back from Epilog with SendRequest %d: CloseRequest:%d\n", doSend, pSctx->doSessionClose);
     if (!returnVal)
     { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket returning FALSE\n"); }
     else
     { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: SMBS_ProcSMBPacket returning TRUE\n"); }
     return returnVal;
}

// Session packet replay was called because SMBS_is_yield_signal_blocked() is true for thuis session
//
// Call back into SMBS_ProcSMBPacket() to replay the packet and send replies, process shutdowns etc.
//
void SMBS_ProcSMBReplay(PSMB_SESSIONCTX pSctx)
{
SMB2PROCBODYACTION bodyR;
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBReplay:  111\n");
   SMBS_SESSION_STATE saved_session_state = pSctx->session_state;
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBReplay:  222\n");
   OPLOCK_DIAG_ENTER_REPLAY
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBReplay:  333\n");
   pSctx->session_state = OPLOCK_SIGNALLED;
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBReplay:  call SMBS_ProcSMBPacket\n");
   SMBS_ProcSMBPacket (pSctx, 0, FALSE, TRUE);
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"SMBS_ProcSMBReplay:  back SMBS_ProcSMBPacket\n");
   if (pSctx->session_state == OPLOCK_SIGNALLED)
   {
     pSctx->session_state = saved_session_state;
   }
   OPLOCK_DIAG_EXIT_REPLAY
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


SMB2PROCBODYACTION SMBS_ProcSMB2BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay)
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

    int stackcontext_state = SMBS_ProccessCompoundFrame (pSctx,isReplay);
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
    return r;
}

static SMB2PROCBODYACTION SMBS_ProcSMB1BodyPacketExecute (PSMB_SESSIONCTX pSctx, BBOOL isReplay)
{
    // Replay option is temporarilly disabled, will refactor
    // if (!isReplay)
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







// rtsmb_srv_netssn_thread_cycle() Went away it is now embedded in SMBS_srv_netssn_cycle
// RTSMB_STATIC void rtsmb_srv_netssn_thread_cycle (PNET_THREAD pThread,long timeout)







#endif /* INCLUDE_RTSMB_SERVER */
