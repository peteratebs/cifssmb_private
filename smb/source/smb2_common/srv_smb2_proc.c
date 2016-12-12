//
// SRV_SMB2_SSN.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles most of the actual processing of packets for the RTSMB server.
//

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "com_smb2.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"

#include "rtpfile.h"
#include "rtprand.h"
#include "rtpwcs.h"
#include "smbdebug.h"
#include "rtpscnv.h"


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
#include "sha256.h"

#include "wchar.h"
#include "srvyield.h"


extern word spnego_AuthenticateUser (PSMB_SESSIONCTX pCtx, decoded_NegTokenTarg_t *decoded_targ_token, word *extended_authId);
void calculate_smb2_signing_key(void *signing_key, void *data, size_t data_len, unsigned char *result);


#include "rtptime.h"




extern int RtsmbStreamDecodeCommand(smb2_stream *pStream, PFVOID pItem);
extern int RtsmbStreamEncodeResponse(smb2_stream *pStream, PFVOID pItem);
extern int RtsmbWriteSrvStatus(smb2_stream *pStream, dword statusCode);
extern pSmb2SrvModel_Global pSmb2SrvGlobal;

extern BBOOL Proc_smb2_Ioctl(smb2_stream  *pStream);
extern BBOOL Proc_smb2_Create(smb2_stream  *pStream);
extern BBOOL Proc_smb2_SessionSetup (smb2_stream  *pStream);
extern BBOOL Proc_smb2_Close(smb2_stream  *pStream);
extern BBOOL Proc_smb2_QueryInfo(smb2_stream  *pStream);
extern BBOOL Proc_smb2_QueryDirectory(smb2_stream  *pStream);
extern BBOOL Proc_smb2_Flush(smb2_stream  *pStream);
extern BBOOL Proc_smb2_Read(smb2_stream  *pStream);
extern BBOOL Proc_smb2_Write(smb2_stream  *pStream);
extern BBOOL Proc_smb2_Lock(smb2_stream  *pStream);
extern BBOOL Proc_smb2_OplockBreak(smb2_stream  *pStream);
extern BBOOL Proc_smb2_Cancel(smb2_stream  *pStream);
extern BBOOL Proc_smb2_SetInfo(smb2_stream  *pStream);



static struct smb2_dialect_entry_s *RTSMB_FindBestDialect(int inDialectCount, word inDialects[]);


static BBOOL Proc_smb2_NegotiateProtocol (smb2_stream  *pStream);
static BBOOL Proc_smb2_LogOff(smb2_stream  *pStream);

static BBOOL Proc_smb2_TreeConnect(smb2_stream  *pStream);
static BBOOL Proc_smb2_TreeDisConnect(smb2_stream  *pStream);
static BBOOL Proc_smb2_ChangeNotify(smb2_stream  *pStream);


static void DebugOutputSMB2Command(int command);

static BBOOL Proc_smb2_Echo(smb2_stream  *pStream);

static void Smb1SrvCtxtToStream(smb2_stream * pStream, PSMB_SESSIONCTX pSctx)
{
    tc_memset(pStream, 0, sizeof(*pStream));
    pStream->doSessionClose         =  FALSE;
    pStream->doSocketClose          =  FALSE;
	pStream->Success                =  TRUE;
	pStream->read_origin            = (PFVOID) SMB_INBUF (pSctx);
	pStream->pInBuf                 =  pStream->read_origin;

	pStream->InBodySize             =  pSctx->current_body_size;
	pStream->read_buffer_size       =  pSctx->readBufferSize;                /* read buffer_size is the buffer size minus NBSS header */
	pStream->read_buffer_remaining  = (pStream->read_buffer_size - pStream->InBodySize);

    pStream->write_origin = (PFVOID) SMB_OUTBUF (pSctx);                      /* write_buffer_size is the buffer size minus NBSS header */
    pStream->write_buffer_size = pSctx->writeBufferSize;
	pStream->pOutBuf = pStream->write_origin;
	pStream->write_buffer_remaining = pStream->write_buffer_size;
    pStream->OutBodySize = 0;
    pStream->psmb2Session = pSctx->pCtxtsmb2Session;
}

// shared with srv_smb2_proc_setup.c
void RTSmb2_SessionShutDown(struct s_Smb2SrvModel_Session  *pStreamSession)
{
    /* The server MUST remove the session object from GlobalSessionTable and Connection.SessionTable */
    Smb2SrvModel_Global_Remove_SessionFromSessionList(pStreamSession);
    /*  3.3.4.12 ?? */
    /* The server MUST close every Open in Session.OpenTable as specified in section 3.3.4.17. */
    /* The server MUST deregister every TreeConnect in Session.TreeConnectTable by providing
       the tuple <TreeConnect.Share.ServerName, TreeConnect.Share.Name> and TreeConnect.TreeGlobalId as the input parameters
       and invoking the event specified in [MS-SRVS] section 3.1.6.7. */
    /* For each deregistered TreeConnect, TreeConnect.Share.CurrentUses MUST be decreased by 1. */
    /* All the tree connects in Session.TreeConnectTable MUST be removed and freed. */
    Smb2SrvModel_Free_Session(pStreamSession);
}

static void Smb1SrvCtxtFromStream(PSMB_SESSIONCTX pSctx,smb2_stream * pStream)
{
    pSctx->outBodySize      = pStream->OutBodySize;
    pSctx->pCtxtsmb2Session = pStream->psmb2Session;
    pSctx->doSocketClose    = pStream->doSocketClose;
    pSctx->doSessionClose   = pStream->doSessionClose;
}

/**
    Called from SMBS_ProcSMBPacket when it receives an SMB2 packet.

    Dispatches to the appropriate SMB2 handler and returns TRUE if a response must be sent back over the NBSS link.

    Response information is placed in the buffer at pCtx->write_origin, and the length is placed in pCtx->outBodySize.


*/

static BBOOL SMBS_ProcSMB2_Packet (smb2_stream * pStream);
static BBOOL SMBS_Frame_Compound_Output(smb2_stream * pStream, PFVOID pOutBufStart);

void SMBS_ProcSMB2_BodyPhaseOne (PSMB_SESSIONCTX pSctx);
static void SMBS_ProcSMB2_BodyPhaseLoop(PSMB_SESSIONCTX pSctx);
static void _SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx);


BBOOL SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx)
{
  BBOOL r=FALSE;
  ProcSMB2_BodyContext *pstackcontext = pSctx->pCtxtsmb2Session->SMB2_BodyContext;

  // Initialize the handling of a compound packet containing one or more SMB2 commands
  if (pstackcontext->stackcontext_state == ST_INIT)
  {
    _SMBS_ProcSMB2_Body (pSctx);
   }

  while (pstackcontext->stackcontext_state == ST_INPROCESS)
    _SMBS_ProcSMB2_Body (pSctx);

  if (pstackcontext->stackcontext_state == ST_YIELD)
  {
    r = FALSE;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBS_ProcSMB2_Body: YIELDED:: r=:%d", r);
  }
  else if (pstackcontext->stackcontext_state == ST_FALSE)
    r = FALSE;
  else if (pstackcontext->stackcontext_state == ST_TRUE)
  {
    Smb1SrvCtxtFromStream(pSctx, &pstackcontext->smb2stream);
    r = TRUE;
  }
  return r;
}

static void _SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx)
{
    ProcSMB2_BodyContext *pstackcontext = pSctx->pCtxtsmb2Session->SMB2_BodyContext;
    // SMBS_ProcSMB2_BodyPhaseOne sets
    //  pstackcontext->stackcontext_state:
    //    ST_INPROCESS - Still looping proccessing compund input or output
    //    ST_TRUE      - Done parameter error or failure of somekind return TRUE to send the buffered reply.
    //    ST_FALSE     - Failed pqrsing input, send no reply.
    if (pstackcontext->stackcontext_state == ST_INIT)
    {  // This is the beginning of a compound packet containing one or more SMB2 commands
       SMBS_ProcSMB2_BodyPhaseOne (pSctx);
       // SMBS_ProcSMB2_BodyPhaseOne setting these states indicate we it wants to return and on true/false send/notsend the output buffer
       if (pstackcontext->stackcontext_state == ST_FALSE)
         return;
       else if (pstackcontext->stackcontext_state == ST_TRUE)
          return;
//       else if (pstackcontext->stackcontext_state = ST_INPROCESS)
          ;
       // Fall through and execute the first command in the compound statement
    }
    // SMBS_ProcSMB2_BodyPhaseLoop sets
    //    ST_INPROCESS - Keep looping proccessing compund input or output
    //    ST_YIELD     - ?? not sure if needed. We have to yield and wait for an external event to continue.
    //    ST_TRUE      - Done parameter success or failure it returns TRUE to send the buffered reply.
    SMBS_ProcSMB2_BodyPhaseLoop(pSctx);
}


void SMBS_ProcSMB2_BodyPhaseOne (PSMB_SESSIONCTX pSctx)
{
    ProcSMB2_BodyContext *pstackcontext = pSctx->pCtxtsmb2Session->SMB2_BodyContext;
	pstackcontext->doFirstPacket = TRUE;
    pstackcontext->pPreviousNextOutCommand = 0;
    pstackcontext->isCompoundReply=FALSE;
    pstackcontext->NextCommandOffset=0;
    pstackcontext->pInBufStart=0;
    pstackcontext->pOutBufStart=0;
    pstackcontext->sign_packet = FALSE;
    pstackcontext->stackcontext_state = ST_INPROCESS;

    /* Initialize memory stream pointers from the v1 contect structure
       set pStream->psmb2Session from the smb2 value saved in the session context structure  */
    if (pSctx->current_yield_Cptr)
    {
       yield_c_resume_yield_point(&pstackcontext->smb2stream, pSctx->current_yield_Cptr);
    }
    else
    {
      Smb1SrvCtxtToStream(&pstackcontext->smb2stream, pSctx);
      /* Save the stream state so we can replay it if we need to*/
      pSctx->current_yield_Cptr = yield_c_new_yield_point(&pstackcontext->smb2stream);
    }

	/* read header and advance the stream pointer */
	if (cmd_read_header_raw_smb2 (pstackcontext->smb2stream.read_origin, pstackcontext->smb2stream.read_origin, pstackcontext->smb2stream.InBodySize, &pstackcontext->smb2stream.InHdr) == -1)
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBS_ProcSMB2_Body: Badly formed header");
		rtsmb_dump_bytes("RAWH",  pstackcontext->smb2stream.read_origin, pstackcontext->smb2stream.InBodySize,  DUMPBIN);
        pstackcontext->stackcontext_state = ST_FALSE;
		return;
	}
    // These lines were done in Smb1SrvCtxtToStream, should remove
	pstackcontext->smb2stream.pOutBuf = pstackcontext->smb2stream.write_origin;
	pstackcontext->smb2stream.write_buffer_remaining = pstackcontext->smb2stream.write_buffer_size;
	pstackcontext->smb2stream.OutBodySize = 0;

	/**  Do a quick check here that the first command we receive is a negotiate.*/
	if (!pstackcontext->smb2stream.psmb2Session)
    {
	    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "SMBS_ProcSMB2_Body:  No Session structures available !!!!!.\n");
        RtsmbWriteSrvStatus(&pstackcontext->smb2stream,SMB2_STATUS_NETWORK_SESSION_EXPIRED);
        pstackcontext->stackcontext_state = ST_TRUE;
		return;
    }
	else if (pstackcontext->smb2stream.psmb2Session->Connection->NegotiateDialect == 0 && pstackcontext->smb2stream.InHdr.Command != SMB2_NEGOTIATE)
	{
	   if (pstackcontext->smb2stream.InHdr.Command == SMB2_ECHO)
       {
		  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBS_ProcSMB2_Body:  Allow SMB2_ECHO with no dialect.\n");
       }
       else
       {
		  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBS_ProcSMB2_Body:  Bad first packet -- was not a NEGOTIATE.\n");
          RtsmbWriteSrvStatus(&pstackcontext->smb2stream,SMB2_STATUS_INVALID_PARAMETER);
          pstackcontext->stackcontext_state = ST_TRUE;
       }
	}
    // Fill in by create so we can replace 0xffffff with the last created FD.
    // Cleared before processing a packet (compound request)
    tc_memset(pstackcontext->smb2stream.LastFileId,0, sizeof( pstackcontext->smb2stream.LastFileId));
    // Process one or more SMB2 packets
    pstackcontext->smb2stream.compound_output_index = 0;
    return;
}

static void SMBS_ProcSMB2_BodyPhaseTwo (PSMB_SESSIONCTX pSctx);

static void SMBS_ProcSMB2_BodyPhaseLoop(PSMB_SESSIONCTX pSctx)
{
    ProcSMB2_BodyContext *pstackcontext = pSctx->pCtxtsmb2Session->SMB2_BodyContext;

    // do
    {
      pstackcontext->sign_packet = FALSE;
      pstackcontext->NextCommandOffset = 0;

       pstackcontext->pInBufStart = pstackcontext->smb2stream.pInBuf;
       pstackcontext->pOutBufStart = pstackcontext->smb2stream.pOutBuf;

       if (pstackcontext->smb2stream.compound_output_index == 0)
       {
           // Read the header into smb2stream.inHdr
           if (cmd_read_header_smb2(&pstackcontext->smb2stream) != 64)
           { // Not quite sure why returning TRUE here, if there's anything to send, from previous calls, then send
             pstackcontext->stackcontext_state = ST_TRUE;
             return;
//              RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMB2_Body: cmd_read_header_smb2 failed\n");
//             return TRUE;
           }
       }
       // Why do we do this I wonder
       pstackcontext->smb2stream.psmb2Session->pSmbCtx->tid = (word)pstackcontext->smb2stream.InHdr.TreeId;

       // Set up outgoing header.
       pstackcontext->smb2stream.OutHdr = pstackcontext->smb2stream.InHdr;
//       smb2stream.OutHdr.Flags &= ~SMB2_FLAGS_SIGNED; // XXX - disable signing in header here

       pstackcontext->smb2stream.OutHdr.NextCommand = 0;
       // Check if it's a compound field
       pstackcontext->isCompoundReply = FALSE; // Process this packet and then drop out of the do loop.
	   if (pstackcontext->doFirstPacket)
       {
          pstackcontext->NextCommandOffset = 0;
          pstackcontext->doFirstPacket = FALSE;
       }
       else if (pstackcontext->smb2stream.compound_output_index!=0)
       {
          pstackcontext->isCompoundReply = TRUE; // Process this packet and then drop out of the do loop.
          pstackcontext->NextCommandOffset = 0;
       }
       else
       {
         if (pstackcontext->smb2stream.InHdr.NextCommand == 0)
         {
            pstackcontext->NextCommandOffset = 0;
         }
         else
         {
           pstackcontext->NextCommandOffset = pstackcontext->smb2stream.InHdr.NextCommand;
         }
       }
       //=====================================
       // Process this one smb packet
       // Make sure yield state is cleared. The command processor may set it
       pstackcontext->smb2stream.doSessionYield=FALSE;
       BBOOL SendCommandResponse = SMBS_ProcSMB2_Packet (&pstackcontext->smb2stream);
       // If the command process requested a yield.
       // rewind the stream and return with pstackcontext->stackcontext_state == ST_INPROCESS; to start the yield
       if (pstackcontext->smb2stream.doSessionYield)
       {
         pstackcontext->stackcontext_state = ST_YIELD;
         return;
       }

       // Must be a compound input to a command that does not respond, we'll null it out so the frame isn't bad
       if (!SendCommandResponse && pstackcontext->pPreviousNextOutCommand)
       {
         *pstackcontext->pPreviousNextOutCommand = 0;
       }
       // See if there are more input commands to process if the packet doesn't require compound_output_index
       if (!pstackcontext->smb2stream.compound_output_index)
         pstackcontext->NextCommandOffset = pstackcontext->smb2stream.InHdr.NextCommand;


       SMBS_ProcSMB2_BodyPhaseTwo (pSctx);
       if (pstackcontext->isCompoundReply)
         pstackcontext->stackcontext_state = ST_INPROCESS;
       else
         pstackcontext->stackcontext_state = ST_TRUE;
    } //  while (pstackcontext->isCompoundReply);
}

static void SMBS_ProcSMB2_BodyPhaseTwo (PSMB_SESSIONCTX pSctx)
{
    ProcSMB2_BodyContext *pstackcontext = pSctx->pCtxtsmb2Session->SMB2_BodyContext;
       PRTSMB2_HEADER pOutHeader  = (PRTSMB2_HEADER) pstackcontext->pOutBufStart;
       // Set out process id to input \n");
       pOutHeader->Reserved = pstackcontext->smb2stream.InHdr.Reserved;
       pOutHeader->NextCommand = 0; // We'll override this if needed
       pstackcontext->pPreviousNextOutCommand     =   &pOutHeader->NextCommand; // Remember it. If we have a compound input to a command that does not respond, then we'll null it out so the frame isn't bad.
       if (pstackcontext->NextCommandOffset == 0)
       {
          // Negotiate requires 1 Credit
          // Otherwise give 1 credit if the client request > 0
          // give zero if it requests 0
          if (pOutHeader->Command == SMB2_NEGOTIATE)
            pOutHeader->CreditRequest_CreditResponse = 1;
          else if (pstackcontext->smb2stream.InHdr.CreditRequest_CreditResponse==0)
            pOutHeader->CreditRequest_CreditResponse = 0;
          else
            pOutHeader->CreditRequest_CreditResponse = pstackcontext->smb2stream.InHdr.CreditRequest_CreditResponse;
       }
       // Advance the buffer pointers to 8 byte boundaries if this is a compound request
       if (pstackcontext->smb2stream.compound_output_index!=0 || pstackcontext->NextCommandOffset != 0)
       {
          unsigned int SkipCount = 0;
          // First advance the input request
          if (pstackcontext->smb2stream.compound_output_index!=0)
            SkipCount = 0;
          else
          {
            unsigned int consumed = (unsigned int) PDIFF (pstackcontext->smb2stream.pInBuf, pstackcontext->pInBufStart);
            if (pstackcontext->NextCommandOffset > consumed)
              SkipCount = pstackcontext->NextCommandOffset - consumed;
          }
          if (SkipCount > pstackcontext->smb2stream.read_buffer_remaining)
          {
              RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMB2_Body: Bad Compound request:\n");
             pstackcontext->isCompoundReply = FALSE;
          }
          else
          {
             pOutHeader->CreditRequest_CreditResponse = 0;
             pstackcontext->smb2stream.pInBuf+=SkipCount;
             pstackcontext->smb2stream.read_buffer_remaining-=SkipCount;
             pstackcontext->isCompoundReply = TRUE;
             // Now see if we have to pad the output to get to an 8 byte boundary
             if (!SMBS_Frame_Compound_Output(&pstackcontext->smb2stream, pstackcontext->pOutBufStart))
               pstackcontext->isCompoundReply = FALSE;
          }
       }
       // sign
#if (1)


        PRTSMB2_HEADER pOutHdr = (PRTSMB2_HEADER)pstackcontext->pOutBufStart;
        pOutHdr->Flags &= ~SMB2_FLAGS_SIGNED;
        tc_memset(pOutHdr->Signature, 0, 16);

#if (HARDWIRED_DISABLE_SIGNING)
        pstackcontext->sign_packet = FALSE;
#else
       // Always sign if signing is required.
       if (pstackcontext->smb2stream.psmb2Session->SigningRequired)
         pstackcontext->sign_packet = TRUE;
#warning Note that we are overriding and always signing.
       pstackcontext->sign_packet = TRUE;
       // Sign outgoing if incoming was signed basically
       if (pstackcontext->smb2stream.InHdr.Flags&SMB2_FLAGS_SIGNED && pstackcontext->smb2stream.psmb2Session && pstackcontext->smb2stream.psmb2Session->Connection->Dialect != SMB2_DIALECT_2002)
         pstackcontext->sign_packet = TRUE;
       if (pstackcontext->smb2stream.InHdr.Command == SMB2_SESSION_SETUP && pstackcontext->smb2stream.OutHdr.Status_ChannelSequenceReserved != SMB2_STATUS_MORE_PROCESSING_REQUIRED)
       {
         pstackcontext->sign_packet = TRUE;
       }
#endif
       if (pstackcontext->sign_packet)
       { // sign if dialact == 2100 and session id != 0
            if (pstackcontext->smb2stream.psmb2Session->SessionId != 0)
            {
               unsigned int PrevLength;
               unsigned int SkipCount;
               // Now see if we have to pad the output to get to an 8 byte boundary
               PrevLength = (unsigned int) PDIFF (pstackcontext->smb2stream.pOutBuf, pstackcontext->pOutBufStart);
               SkipCount = ((PrevLength+7)&~((unsigned int)0x7))-PrevLength;
               if (SkipCount && SkipCount < (rtsmb_size)pstackcontext->smb2stream.write_buffer_remaining)
               {
                  tc_memset(pstackcontext->smb2stream.pOutBuf,0,SkipCount);
                  pstackcontext->smb2stream.write_buffer_remaining -= SkipCount;
                  pstackcontext->smb2stream.pOutBuf = PADD (pstackcontext->smb2stream.pOutBuf, SkipCount);
                  pstackcontext->smb2stream.OutBodySize += SkipCount;
               }
               pOutHdr->Flags |= SMB2_FLAGS_SIGNED;

               {
                void *data = pstackcontext->pOutBufStart;
                size_t  data_len =  PDIFF(pstackcontext->smb2stream.pOutBuf,pstackcontext->pOutBufStart);
                calculate_smb2_signing_key(pstackcontext->smb2stream.psmb2Session->SigningKey, data, data_len, pOutHdr->Signature);
               }
            }
        }
#endif
}

static BBOOL SMBS_Frame_Compound_Output(smb2_stream * pStream, PFVOID pOutBufStart)
{
unsigned int PrevLength;
unsigned int SkipCount;
    // Now see if we have to pad the output to get to an 8 byte boundary
    PrevLength = (unsigned int) PDIFF (pStream->pOutBuf, pOutBufStart);
    SkipCount = ((PrevLength+7)&~((unsigned int)0x7))-PrevLength;
    if (SkipCount > (rtsmb_size)pStream->write_buffer_remaining)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_ProcSMB2_Body: Compound request: write buffer full\n");
      return FALSE;
    }
    else
    {
      PRTSMB2_HEADER pOutHeader  = (PRTSMB2_HEADER) pOutBufStart;
      // Now insert the offset to the next command into the prior header
      // This is only used for input ????
      pOutHeader->NextCommand = (dword)PDIFF (pStream->pOutBuf, pOutBufStart)+SkipCount;
      if (SkipCount)
      {
        tc_memset(pStream->pOutBuf,0,SkipCount);
        pStream->write_buffer_remaining -= SkipCount;
        pStream->pOutBuf = PADD (pStream->pOutBuf, SkipCount);
        pStream->OutBodySize += SkipCount;
      }
    }
    return TRUE;
}



static BBOOL SMBS_ProcSMB2_Packet (smb2_stream * pStream)
{
	int header_size;
	int length;
	BBOOL doSend = FALSE;
	BBOOL doFinalize = FALSE;
    PRTSMB2_HEADER pHeaderInBuffer;
    PFVOID   pOutBufStart;


    tc_memset(pStream->OutHdr.Signature,0, sizeof(pStream->OutHdr.Signature));

    pStream->OutHdr.Flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    pStream->OutHdr.StructureSize = 64;

	/* Save the location of the header in the output buffer, we will copy over this with contents from smb2stream.OutHdr that is built up by the procs. */
    pHeaderInBuffer = (PRTSMB2_HEADER) pStream->pOutBuf;
	/* fill it in once, just so we have something reasonable in place */
	header_size = cmd_fill_header_smb2 (pStream, &pStream->OutHdr);

	if (header_size >= 0)
    {
      /* Reset the stream */
	  pStream->pOutBuf = pHeaderInBuffer;
	  pStream->write_buffer_remaining += header_size;
	  pStream->OutBodySize -= header_size;
    }
	{
        if ( pStream->InHdr.Command != SMB2_ECHO)
	      DebugOutputSMB2Command(pStream->InHdr.Command);

        doFinalize = TRUE;
        if (pStream->InHdr.Command != SMB2_NEGOTIATE)
        {
            /* Decide here if we should encrypt  */
            BBOOL EncryptMessage = FALSE;
            if (EncryptMessage)
                smb2_stream_start_encryption(pStream);
        }


		/**
		 * Ok, we now see what kind of command has been requested, and
		 * call an appropriate helper function to fill out details of
		 * pOutSmbHdr.  Most return a BBOOL, indicating whether we should
		 * send a response or not.
		 */
		switch (pStream->InHdr.Command)
		{
            case SMB2_NEGOTIATE:
    			doSend = Proc_smb2_NegotiateProtocol (pStream);
    			break;
            case SMB2_SESSION_SETUP  :
    			doSend = Proc_smb2_SessionSetup(pStream);
    			break;
            case SMB2_LOGOFF         :
    			doSend = Proc_smb2_LogOff(pStream);
    			break;
            case SMB2_TREE_CONNECT   :
    			doSend = Proc_smb2_TreeConnect(pStream);
    			break;
            case SMB2_TREE_DISCONNECT:
    			doSend = Proc_smb2_TreeDisConnect(pStream);
    			break;
            case SMB2_CREATE         :
                if (oplock_diagnotics.performing_replay)   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: Proc_smb2_Create: replay enter\n");
    			doSend = Proc_smb2_Create(pStream);
                if (oplock_diagnotics.performing_replay)
                  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: Proc_smb2_Create:  replay complete dosend:%d\n",doSend);
    			break;
            case SMB2_CLOSE          :
    			doSend = Proc_smb2_Close(pStream);
    			break;
            case SMB2_FLUSH          :
    			doSend = Proc_smb2_Flush(pStream);
    			break;
            case SMB2_READ           :
    			doSend = Proc_smb2_Read(pStream);
    			break;
            case SMB2_WRITE          :
    			doSend = Proc_smb2_Write(pStream);
    			break;
            case SMB2_LOCK           :
    			doSend = Proc_smb2_Lock(pStream);
    			break;
            case SMB2_IOCTL          :
    			doSend = Proc_smb2_Ioctl(pStream);
    			break;
            case SMB2_CANCEL         :
    			doSend = Proc_smb2_Cancel(pStream);
    			break;
            case SMB2_ECHO           :
    			doSend = Proc_smb2_Echo(pStream);
    			break;
            case SMB2_QUERY_DIRECTORY:
    			doSend = Proc_smb2_QueryDirectory(pStream);
    			break;
            case SMB2_CHANGE_NOTIFY  :
    			doSend = Proc_smb2_ChangeNotify(pStream);
    			break;
            case SMB2_QUERY_INFO     :
    			doSend = Proc_smb2_QueryInfo(pStream);
    			break;
            case SMB2_SET_INFO       :
    			doSend = Proc_smb2_SetInfo(pStream);
    			break;
            case SMB2_OPLOCK_BREAK   :
    			doSend = Proc_smb2_OplockBreak(pStream);
    			break;
    		default:
                RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
    		    doFinalize = FALSE;
    		    doSend = TRUE;
    		break;
		}
	}
    if (doSend)
    {
        // Set CreditCharge=0 assume 2.02\n");
#warning Force charge credit charge 1
        pStream->OutHdr.CreditCharge=1;
        tc_memcpy(pHeaderInBuffer,&pStream->OutHdr,sizeof(pStream->OutHdr));
	    if (doFinalize)
        {
            if (RtsmbWriteFinalizeSmb2(pStream, pStream->InHdr.MessageId)<0)
            {
                RtsmbWriteSrvStatus (pStream, SMB2_STATUS_BUFFER_OVERFLOW);
            }
        }
        Smb2SrvModel_Global_Stats_Send_Update(pStream->OutBodySize);
    }

	return doSend;
}



/* Called from ProcNegotiateProtocol when a V1 protocol negotiate request is recieved with an SMB2002 protocol option */
BBOOL SMBS_proc_RTSMB2_NEGOTIATE_R_from_SMB (PSMB_SESSIONCTX pSctx)
{
    int header_size;
    int length;
    BBOOL doSend = FALSE;
    BBOOL doFinalize = FALSE;
    smb2_stream  smb2stream;
    smb2_stream * pStream;

    SMBS_InitSessionCtx_smb2(pSctx);

    pStream = &smb2stream;


    /* Initialize memory stream pointers and set pStream->psmb2Session from value saved in the session context structure  */
    Smb1SrvCtxtToStream(pStream, pSctx);

    pStream->psmb2Session->Connection->ShouldSign = FALSE;

    pStream->psmb2Session->Connection->Dialect = SMB2_DIALECT_WILD;
    pStream->psmb2Session->Connection->NegotiateDialect = SMB2_DIALECT_WILD;

// XXX    pStream->psmb2Session->Connection->Dialect = SMB2_DIALECT_2002;
// XXX   pStream->psmb2Session->Connection->NegotiateDialect = SMB2_DIALECT_2002;
    pStream->psmb2Session->Connection->MaxTransactSize = pSctx->readBufferSize;
    pStream->psmb2Session->Connection->MaxWriteSize = pSctx->writeBufferSize;
    pStream->psmb2Session->Connection->MaxReadSize = pSctx->readBufferSize;

    pStream->psmb2Session->Connection->MaxTransactSize =
    pStream->psmb2Session->Connection->MaxWriteSize =
    pStream->psmb2Session->Connection->MaxReadSize = prtsmb_srv_ctx->max_smb2_transaction_size;
	/**
	 * Set up outgoing header.
	 */
    tc_memset(&smb2stream.OutHdr,0, sizeof(smb2stream.OutHdr));
//    tc_memset(smb2stream.OutHdr.Signature,0, sizeof(smb2stream.OutHdr.Signature));


    smb2stream.OutHdr.Flags |= SMB2_FLAGS_SERVER_TO_REDIR;
    smb2stream.OutHdr.StructureSize = 64;
    smb2stream.OutHdr.CreditRequest_CreditResponse=1;

	/* fill it in once, just so we have something reasonable in place */
	cmd_fill_header_smb2 (&smb2stream, &smb2stream.OutHdr);

    /* Reset the stream */
	smb2stream.pOutBuf = smb2stream.write_origin;
	smb2stream.write_buffer_remaining = smb2stream.write_buffer_size;
	smb2stream.OutBodySize = 0;

    RTSMB2_NEGOTIATE_R response;
    MEMCLEAROBJ(response);
    response.StructureSize      = 65;
    /* SecurityMode MUST have the SMB2_NEGOTIATE_SIGNING_ENABLED bit set. */
    response.SecurityMode       = SMB2_NEGOTIATE_SIGNING_ENABLED;
    /* If RequireMessageSigning is TRUE, the server MUST also set SMB2_NEGOTIATE_SIGNING_REQUIRED in the SecurityMode field. */
    if (pSmb2SrvGlobal->RequireMessageSigning)
    {
        response.SecurityMode   |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
        pStream->psmb2Session->SigningRequired = TRUE;
    }
    /* DialectRevision MUST be set to the common dialect. */
    response.DialectRevision    = pStream->psmb2Session->Connection->Dialect;
    response.Reserved = 0;
    /* ServerGuid is set to the global ServerGuid value. */
    tc_memcpy(response.ServerGuid,pSmb2SrvGlobal->ServerGuid,16);

    printf("Forcing mutil credit in smbv1 reply\n");
    pStream->psmb2Session->Connection->SupportsMultiCredit = TRUE;
    /* The Capabilities field MUST be set to a combination of zero or more of the following bit values, as specified in section 2.2.4 */
    response.Capabilities       = Smb2_util_get_global_caps(pStream->psmb2Session->Connection, 0); // command==0 , no SMB3

    /* MaxTransactSize is set to the maximum buffer size<221>,in bytes, that the server will accept on this connection for QUERY_INFO,
       QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations. */
    response.MaxTransactSize    =  pStream->psmb2Session->Connection->MaxTransactSize;
    /* MaxReadSize is set to the maximum size,<222> in bytes, of the Length in an SMB2 READ Request */
    response.MaxReadSize        =  pStream->psmb2Session->Connection->MaxReadSize;

    /* MaxWriteSize is set to the maximum size,<223> in bytes, of the Length in an SMB2 WRITE Request */
    response.MaxWriteSize       =  pStream->psmb2Session->Connection->MaxWriteSize;

    /* SystemTime is set to the current time */
    response.SystemTime         =  rtsmb_util_get_current_filetime();
    /* ServerStartTime is set to the global ServerStartTime value */
    response.ServerStartTime    =  pSmb2SrvGlobal->ServerStartTime;

    /* SecurityBufferOffset is set to the offset to the Buffer field in the response, in bytes, from the beginning of the SMB2 header.
        SecurityBufferLength is set to the length of the data being returned in the Buffer field. */
    response.SecurityBufferLength = 0;
    pStream->WriteBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_Default(&pStream->WriteBufferParms[0].byte_count);
    response.SecurityBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.SecurityBufferLength)
    {
        response.SecurityBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
    }
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    if (response.SecurityBufferLength)
        RTSmb2_Encryption_Release_Spnego_Default(pStream->WriteBufferParms[0].pBuffer);
    Smb1SrvCtxtFromStream(pSctx, &smb2stream);
    return TRUE;
} // End ProcNegotiateProtocol


/*
Proccess Negotiate protocol requests.  This function figures out what the highest supported dialog on both machines can be used for the remainder of the session.

    3.3.5.4 Receiving an SMB2 NEGOTIATE Request   ................ 258

    pStream->psmb2Session and pStream->psmb2Session->Connection are already partially initialized.

    Process the incoming negotiate command and complete setup commands.

*/

static BBOOL Proc_smb2_NegotiateProtocol (smb2_stream  *pStream)
{
	RTSMB2_NEGOTIATE_C command;
	RTSMB2_NEGOTIATE_R response;
    BBOOL select_3x_only  = FALSE;
    struct smb2_dialect_entry_s *pEntry=0;

    if (pSmb2SrvGlobal->EncryptData && pSmb2SrvGlobal->RejectUnencryptedAccess)
    {
        select_3x_only = TRUE;
    }

    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
        return TRUE;
    /*
        If Connection.NegotiateDialect is 0x0202, 0x0210, 0x0300, or 0x0302 the server MUST disconnect the connection,
        as specified in section 3.3.7.1, and not reply.
    */
    if (pStream->psmb2Session->Connection->NegotiateDialect && pStream->psmb2Session->Connection->NegotiateDialect!=SMB2_DIALECT_WILD)
    {
        pStream->doSocketClose = TRUE;
		return FALSE;
    }
    pStream->psmb2Session->Connection->MaxTransactSize = pStream->psmb2Session->pSmbCtx->readBufferSize;
    pStream->psmb2Session->Connection->MaxWriteSize    = pStream->psmb2Session->pSmbCtx->writeBufferSize;
    pStream->psmb2Session->Connection->MaxReadSize     = pStream->psmb2Session->pSmbCtx->readBufferSize;

    /* The server MUST set Connection.ClientCapabilities to the capabilities received in the SMB2 NEGOTIATE request. */
    pStream->psmb2Session->Connection->ClientCapabilities = command.Capabilities;

    /* If the server implements the SMB 3.x dialect family, the server MUST set Connection.ClientSecurityMode to the SecurityMode field of the SMB2 NEGOTIATE Request. */
    pStream->psmb2Session->Connection->ClientSecurityMode = command.SecurityMode;

    /* If the server implements the SMB2.1 or 3.x dialect family, the server MUST set Connection.ClientGuid to the ClientGuid field of the SMB2 NEGOTIATE Request. */
    tc_memcpy(pStream->psmb2Session->Connection->ClientGuid, command.guid, 16);

    /* If SMB2_NEGOTIATE_SIGNING_REQUIRED is set in SecurityMode, the server MUST set Connection.ShouldSign to TRUE. */
    if (command.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
        pStream->psmb2Session->Connection->ShouldSign = TRUE;

    /*  If the DialectCount of the SMB2 NEGOTIATE Request is 0, the server MUST fail the request with STATUS_INVALID_PARAMETER. */
    if (command.DialectCount == 0)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
		return TRUE;
    }
    pEntry = RTSMB_FindBestDialect(command.DialectCount, command.Dialects);
    /* If a common dialect is not found, the server MUST fail the request with STATUS_NOT_SUPPORTED. */
    if (pEntry == 0)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_NOT_SUPPORTED);
		return TRUE;
    }
    /*
        If a common dialect is found, the server MUST set Connection.Dialect to "2.002", "2.100", "3.000", or "3.002", and Connection.NegotiateDialect to
        0x0202, 0x0210, 0x0300, or 0x0302 accordingly, to reflect the dialect selected.
    */
    pStream->psmb2Session->Connection->NegotiateDialect = pEntry->dialect;
    pStream->psmb2Session->Connection->Dialect = pEntry->dialect;

    if (select_3x_only && !SMB2IS3XXDIALECT(pEntry->dialect))
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
		return TRUE;
    }

    /* If the common dialect is SMB 2.1 or 3.x dialect family and the underlying connection is either TCP port 445 or RDMA,
       Connection.SupportsMultiCredit MUST be set to TRUE; otherwise, it MUST be set to FALSE.
    */
    if (pStream->psmb2Session->Connection->Dialect != SMB2_DIALECT_2002)
    {
        if (1 || pStream->psmb2Session->Connection->TransportName & (RTSMB2_TRANSPORT_SMB_OVER_RDMA|RTSMB2_TRANSPORT_SMB_OVER_TCP) ) // This is true
            pStream->psmb2Session->Connection->SupportsMultiCredit = TRUE;
    }
    MEMCLEAROBJ(response);
    response.StructureSize      = 65;
    /* SecurityMode MUST have the SMB2_NEGOTIATE_SIGNING_ENABLED bit set. */
    response.SecurityMode       = SMB2_NEGOTIATE_SIGNING_ENABLED;
    /* If RequireMessageSigning is TRUE, the server MUST also set SMB2_NEGOTIATE_SIGNING_REQUIRED in the SecurityMode field. */
    if (pSmb2SrvGlobal->RequireMessageSigning)
    {
        response.SecurityMode   |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
        pStream->psmb2Session->SigningRequired = TRUE;
    }
    /* DialectRevision MUST be set to the common dialect. */
// XXXX    response.DialectRevision    = pStream->psmb2Session->Connection->Dialect;
    response.DialectRevision    = SMB2_DIALECT_2100;
    response.Reserved = 0;
    /* ServerGuid is set to the global ServerGuid value. */
    tc_memcpy(response.ServerGuid,pSmb2SrvGlobal->ServerGuid,16);
    /* The Capabilities field MUST be set to a combination of zero or more of the following bit values, as specified in section 2.2.4 */
//    response.Capabilities       = Smb2_util_get_global_caps(pStream->psmb2Session->Connection, &command);
    response.Capabilities       = Smb2_util_get_global_caps(pStream->psmb2Session->Connection, 0); // command==0 , no SMB3
//    response.Capabilities       = 0x4;


    /* MaxTransactSize is set to the maximum buffer size<221>,in bytes, that the server will accept on this connection for QUERY_INFO,
       QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations. */
    response.MaxTransactSize    =  pStream->psmb2Session->Connection->MaxTransactSize;
    /* MaxReadSize is set to the maximum size,<222> in bytes, of the Length in an SMB2 READ Request */
    response.MaxReadSize        =  pStream->psmb2Session->Connection->MaxReadSize;
    /* MaxWriteSize is set to the maximum size,<223> in bytes, of the Length in an SMB2 WRITE Request */
    response.MaxWriteSize       =  pStream->psmb2Session->Connection->MaxWriteSize;
    response.MaxTransactSize    =
    response.MaxReadSize        =
    response.MaxWriteSize       =  prtsmb_srv_ctx->max_smb2_transaction_size;
    /* SystemTime is set to the current time */
    response.SystemTime         =  rtsmb_util_get_current_filetime();
    /* ServerStartTime is set to the global ServerStartTime value */
//    response.ServerStartTime    =  pSmb2SrvGlobal->ServerStartTime;
    response.ServerStartTime    =  0; // pSmb2SrvGlobal->ServerStartTime;

    /* SecurityBufferOffset is set to the offset to the Buffer field in the response, in bytes, from the beginning of the SMB2 header.
        SecurityBufferLength is set to the length of the data being returned in the Buffer field. */
    pStream->WriteBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_Default(&pStream->WriteBufferParms[0].byte_count);
    response.SecurityBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.SecurityBufferLength)
    {
        response.SecurityBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
    }
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
} // End ProcNegotiateProtocol


/* --------------------------------------------------- /
 * Proc_smb2_LogOff command			           /
 *	                                                   /
 *                                                     /
 * smb2_stream  *pStream                               /
 *  Has inbuffer and outbuffer stream pointers         /
 *  Has links to SMB2 session and SMB1 session info    /
 *  PSMB_HEADER InHdr - the incoming smb header        /
 *  PSMB_HEADER OutHdr - the outgoing smb header       /
 *													   /
 * This command logs the user off, and frees resource   /
 *                                                     /
 * Returns: TRUE if there is data to write.            /
 *          FALSE otherwise.                           /
 *          If a communication error occurs the command/
 *          The may instruct the session to shut down  /
 *          and/or the socket to be closed.            /
 * -------------------------------------------------- */
static BBOOL Proc_smb2_LogOff(smb2_stream  *pStream)
{
	RTSMB2_LOGOFF_C command;
	RTSMB2_LOGOFF_R response;
	dword error_status = 0;
	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    /* Read into command */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    response.StructureSize          = 4;
    response.Reserved               = 0;
    pStream->OutHdr.SessionId       = pStream->psmb2Session->SessionId;
    /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    // Close out the session after sending the response
    // The client will be able to start another SMB2 or SMB1 session
    pStream->doSessionClose = TRUE;
    return TRUE;

}

/* --------------------------------------------------- /
 * Proc_smb2_TreeConnect command			           /
 *	                                                   /
 *                                                     /
 * smb2_stream  *pStream                               /
 *  Has inbuffer and outbuffer stream pointers         /
 *  Has links to SMB2 session and SMB1 session info    /
 *  PSMB_HEADER InHdr - the incoming smb header        /
 *  PSMB_HEADER OutHdr - the outgoing smb header       /
 *													   /
 * This command connects the client to a given share.  /
 * The spec says that every Session Setup command      /
 * must be followed by a tree connect, but that rule   /
 * is sometimes broken.                                /
 *
 * Formats the output buffer with either a positive or /
 * response message.                                   /
 *                                                     /
 * Returns: TRUE if there is data to write.            /
 *          FALSE otherwise.                           /
 *          If a communication error occurs the command/
 *          The may instruct the session to shut down  /
 *          and/or the socket to be closed.            /
 * -------------------------------------------------- */

static byte MapRTSMB_To_Smb2_ShareType(enum RTSMB_SHARE_TYPE inType)
{
byte b=0;
 switch (inType){
 case RTSMB_SHARE_TYPE_DISK:
     b = 1;
     break;
 case RTSMB_SHARE_TYPE_PRINTER:
     b = 3;
     break;
 case RTSMB_SHARE_TYPE_DEVICE:
 case RTSMB_SHARE_TYPE_IPC:
     b = 2;
     break;
 }
 return b;
};

static BBOOL Proc_smb2_TreeConnect(smb2_stream  *pStream)
{
	RTSMB2_TREE_CONNECT_C command;
	RTSMB2_TREE_CONNECT_R response;
	rtsmb_char share_name [RTSMB_NB_NAME_SIZE + RTSMB_MAX_SHARENAME_SIZE + 4]; /* 3 for '\\'s and 1 for null */
	dword error_status = 0;
	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(share_name,0, sizeof(share_name));
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

     /* Set up a temporary buffer to hold incoming share name */
    pStream->ReadBufferParms[0].pBuffer = share_name;
    pStream->ReadBufferParms[0].byte_count = sizeof(share_name);
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    pSmb2Session = Smb2SrvModel_Global_Get_SessionById(pStream->InHdr.SessionId);

    /* Tie into the V1 share mechanism for now */
    {
        int tid;

        CLAIM_SHARE ();
        tid = SR_GetTreeIdFromName ( share_name );
        if (tid <0)
        {
           error_status = SMB2_STATUS_BAD_NETWORK_NAME;
        }
        else
        {
			byte access;
			PSR_RESOURCE pResource;

			pResource = SR_ResourceById ((word) tid);

#if (1)
printf("TBD: Hardwiring TREE security to SECURITY_READWRITE\n");

            access = SECURITY_READWRITE;
#else
			/**
			 * We first see what mode the server was in when the user logged in.
			 * This will let us know how to get access info.
			 */
			switch (pCtx->accessMode)
			{
				case AUTH_SHARE_MODE:
// Auth_AuthenticateUser and DoPasswordsMatch() are really ugly, should be able to remove but not just yet
					if (Auth_DoPasswordsMatch (pCtx, 0, 0, pResource->password, (PFBYTE) password, (PFBYTE) password) == TRUE)
						access = pResource->permission;
					else
					{
						pOutHdr->status = SMBU_MakeError (pCtx, SMB_EC_ERRSRV, SMB_ERRSRV_BADPW);   // Commented out
					}
					break;
				case AUTH_USER_MODE:
				default:
					access = Auth_BestAccess (pCtx, (word) tid);
					break;
			}
#endif
			/**
			 * If they have *some* access, let them connect and browse the share.
			 */
			if (access != SECURITY_NONE)
			{
				PTREE tree;

                // Allocates a free tree structure from the context
				tree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, -1);

				if (!tree)
				{
					/* no free tree structs */
					error_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
				}
                else
                {
				word externaltid;

				    error_status = 0;

				    response.StructureSize = 16;
				    response.ShareType              = MapRTSMB_To_Smb2_ShareType(pResource->stype);
				    response.ShareFlags             = 0; // SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK These are okay SMB2_SHAREFLAG_NO_CACHING|SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS;
				    response.Capabilities           = 0; // SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;
				    if (access == SECURITY_READ)
				        response.MaximalAccess          = SMB2_FPP_ACCESS_MASK_FILE_READ_DATA;
				    else
                    {
				        response.MaximalAccess          =   SMB2_FPP_ACCESS_MASK_FILE_READ_DATA|
				                                            SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA|
				                                            SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA;
                    }
				    externaltid = (word) (((int) (tree)) & 0xFFFF);
				    pStream->OutHdr.TreeId = (dword) externaltid;

				    tree->external = externaltid;
				    tree->internal = (word) tid;
                    // Zero the file id structures
				    Tree_Init (tree);
				    tree->access = access;
				    tree->type = pResource->stype;
                    pStream->psmb2Session->pSmbCtx->tid = externaltid;
				}
			}
			else
			{
				error_status = SMB2_STATUS_ACCESS_DENIED;
			}
       }
       RELEASE_SHARE ();
    }


    if (error_status)
    {
		RtsmbWriteSrvStatus (pStream, error_status);
    }
    else
    {
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
    return TRUE;
} // Proc_smb2_TreeConnect


/*
================
	PSMB_SESSIONCTX pSmbCtx - x
	PSMB_HEADER1 pInHdr1 - x
	PSMB_HEADER2 pInHdr2 - x
================
*/
static BBOOL Proc_smb2_TreeDisConnect(smb2_stream  *pStream)
{
	RTSMB2_TREE_DISCONNECT_C command;
	RTSMB2_TREE_DISCONNECT_R response;
	dword error_status = 0;

	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  RtsmbStreamDecodeCommand failed...\n");
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    else
    {
        PTREE tree;
        tree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, (word) pStream->InHdr.TreeId);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  SMBU_GetTree returned %X\n",(int)tree);
        if (tree)
        {
            Tree_Shutdown (pStream->psmb2Session->pSmbCtx, tree);
        }
    }
	response.StructureSize = 4;
    if (error_status)
    {
		RtsmbWriteSrvStatus (pStream, error_status);
    }
    else
    {
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
    return TRUE;
} // Proc_smb2_TreeDisConnect


static BBOOL Proc_smb2_Echo(smb2_stream  *pStream)
{
	RTSMB2_ECHO_C command;
	RTSMB2_ECHO_R response;

	pSmb2SrvModel_Session pSmb2Session;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Echo:  RtsmbStreamDecodeCommand failed...\n");
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
	response.StructureSize = 4;
     /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;

}

static BBOOL Proc_smb2_ChangeNotify(smb2_stream  *pStream)
{
 RTSMB2_CHANGE_NOTIFY_C command;
 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 return FALSE;
}

static  rtsmb_char srv_dialect_smb2002[] = {'S', 'M', 'B', '2', '.', '0', '0', '2', '\0'};
static  rtsmb_char srv_dialect_smb2100[] = {'S', 'M', 'B', '2', '.', '1', '0', '0', '\0'};
static struct smb2_dialect_entry_s smb2_dialectList[] =
{
	{SMB2_DIALECT_2002, srv_dialect_smb2002, 1},
	{SMB2_DIALECT_2100, srv_dialect_smb2100, 2},
};
#define NUM_SMB2_DIALECTS (int)(sizeof(smb2_dialectList)/sizeof(smb2_dialectList[0]))
static struct smb2_dialect_entry_s *RTSMB_FindBestDialect(int inDialectCount, word inDialects[])
{
int i,entry;
word dialect = 0;
struct smb2_dialect_entry_s *pEntry = 0;

   for (entry = 0; entry < inDialectCount; entry++)
   {//check dialect field against dialect list
        for (i = 0; i < NUM_SMB2_DIALECTS; i++)
        {
	        if (inDialects[entry] == smb2_dialectList[i].dialect)
	        {
	            if ((dialect == 0)	|| (smb2_dialectList[dialect].priority < smb2_dialectList[i].priority))
	            {
				    dialect = i;
				    pEntry = &smb2_dialectList[i];
	            }
	        }
        }
   }
   return pEntry;
}



const char *DebugSMB2CommandToString(int command);

//
static void DebugOutputSMB2Command(int command)
{
#ifdef RTSMB_DEBUG
//    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_TRACE_LVL, "SMBS_ProcSMB2_Body:  Processing a packet with command: %s \n", (char *)DebugSMB2CommandToString(command));
#endif // RTSMB_DEBUG
}


#endif /* INCLUDE_RTSMB_SERVER */
#endif
