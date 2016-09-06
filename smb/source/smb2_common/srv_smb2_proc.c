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


extern word spnego_AuthenticateUser (PSMB_SESSIONCTX pCtx, decoded_NegTokenTarg_t *decoded_targ_token, word *extended_authId);


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
extern BBOOL Proc_smb2_SetInfo(smb2_stream  *pStream);



static struct smb2_dialect_entry_s *RTSMB_FindBestDialect(int inDialectCount, word inDialects[]);


static BBOOL Proc_smb2_NegotiateProtocol (smb2_stream  *pStream);
static BBOOL Proc_smb2_LogOff(smb2_stream  *pStream);

static BBOOL Proc_smb2_TreeConnect(smb2_stream  *pStream);
static BBOOL Proc_smb2_TreeDisConnect(smb2_stream  *pStream);

static BBOOL Proc_smb2_Cancel(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_ChangeNotify(smb2_stream  *pStream){return FALSE;}
static BBOOL Proc_smb2_OplockBreak(smb2_stream  *pStream){return FALSE;}
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
//    RTSmb2_SessionShutDown(pStreamSession);
    Smb2SrvModel_Free_Session(pStreamSession);
}
static void Smb1SrvCtxtFromStream(PSMB_SESSIONCTX pSctx,smb2_stream * pStream)
{
    pSctx->outBodySize      = pStream->OutBodySize;
    pSctx->pCtxtsmb2Session = pStream->psmb2Session;
    pSctx->doSocketClose    = pStream->doSocketClose;
    if (pStream->doSessionClose && pStream->psmb2Session)
    {
        RTSmb2_SessionShutDown(pStream->psmb2Session);
        pStream->psmb2Session = 0;
        pStream->doSessionClose = FALSE;
    }
}

/**
    Called from SMBS_ProcSMBPacket when it receives an SMB2 packet.

    Dispatches to the appropriate SMB2 handler and returns TRUE if a response must be sent back over the NBSS link.

    Response information is placed in the buffer at pCtx->write_origin, and the length is placed in pCtx->outBodySize.


*/

static BBOOL SMBS_ProcSMB2_Packet (smb2_stream * pStream);
static BBOOL SMBS_Frame_Compound_Output(smb2_stream * pStream, PFVOID pOutBufStart);

extern BYTE spnego_session_key[16];

BBOOL SMBS_ProcSMB2_Body (PSMB_SESSIONCTX pSctx)
{
	int header_size;
	int length;
	BBOOL doSend = FALSE;
	BBOOL doFinalize = FALSE;
	BBOOL doFirstPacket = TRUE;
    smb2_stream  smb2stream;
    smb2_stream * pStream;
    PRTSMB2_HEADER pHeaderInBuffer;
    BBOOL isCompoundReply=FALSE;
    pStream = &smb2stream;
    word AddtoFinalCreditRequest_CreditResponse = 0;
    /* Initialize memory stream pointers from the v1 contect structure
       set pStream->psmb2Session from the smb2 value saved in the session context structure  */
    Smb1SrvCtxtToStream(&smb2stream, pSctx);

	/* read header and advance the stream pointer */
	if ((header_size = cmd_read_header_raw_smb2 (smb2stream.read_origin, smb2stream.read_origin, smb2stream.InBodySize, &smb2stream.InHdr)) == -1)
	{
		RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body: Badly formed header", RTSMB_DEBUG_TYPE_ASCII);
		return FALSE;
	}
	smb2stream.pOutBuf = smb2stream.write_origin;
	smb2stream.write_buffer_remaining = smb2stream.write_buffer_size;
	smb2stream.OutBodySize = 0;
	/**
	 * Do a quick check here that the first command we receive is a negotiate.
	 */


	if (!smb2stream.psmb2Session)
    {
	    RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body:  No Session structures available !!!!!.\n", RTSMB_DEBUG_TYPE_ASCII);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_NETWORK_SESSION_EXPIRED);
		return TRUE;
    }
	else if (smb2stream.psmb2Session->Connection->NegotiateDialect == 0 && smb2stream.InHdr.Command != SMB2_NEGOTIATE)
	{
		RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body:  Bad first packet -- was not a NEGOTIATE.\n", RTSMB_DEBUG_TYPE_ASCII);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
		return TRUE;
	}

    // Process one or more SMB2 packets
    smb2stream.compound_output_index = 0;
    do
    {
      PFVOID   pInBufStart;
      PFVOID   pOutBufStart;
      dword NextCommandOffset = 0;

       pInBufStart = smb2stream.pInBuf;
       pOutBufStart = smb2stream.pOutBuf;

       if (smb2stream.compound_output_index == 0)
       {
           // Read the header into smb2stream.inHdr
           if (cmd_read_header_smb2(&smb2stream) != 64)
           {
             break;
//              RTSMB_DEBUG_OUTPUT_STR("SMBS_ProcSMB2_Body: cmd_read_header_smb2 failed\n", RTSMB_DEBUG_TYPE_ASCII);
//             return TRUE;
           }
       }
       // Why do we do this I wonder
       smb2stream.psmb2Session->pSmbCtx->tid = (word)smb2stream.InHdr.TreeId;

       // Set up outgoing header.
       smb2stream.OutHdr = smb2stream.InHdr;
//       smb2stream.OutHdr.Flags &= ~SMB2_FLAGS_SIGNED; // XXX - disable signing in header here

       smb2stream.OutHdr.NextCommand = 0;
       // Check if it's a compound field
       isCompoundReply = FALSE; // Process this packet and then drop out of the do loop.
	   if (doFirstPacket)
       {
          NextCommandOffset = 0;
          doFirstPacket = FALSE;
       }
       else if (smb2stream.compound_output_index!=0)
       {
          isCompoundReply = TRUE; // Process this packet and then drop out of the do loop.
          NextCommandOffset = 0;
       }
       else
       {
         if (smb2stream.InHdr.NextCommand == 0)
         {
            NextCommandOffset = 0;
         }
         else
         {
           NextCommandOffset = smb2stream.InHdr.NextCommand;
         }
       }
       // Process this one smb packet
       doSend |= SMBS_ProcSMB2_Packet (&smb2stream);
       // See if there are more input commands to process if the packet doesn't require compound_output_index
       if (!smb2stream.compound_output_index)
         NextCommandOffset = smb2stream.InHdr.NextCommand;

       PRTSMB2_HEADER pOutHeader  = (PRTSMB2_HEADER) pOutBufStart;
       // Set out process id to input \n");
       pOutHeader->Reserved = smb2stream.InHdr.Reserved;
       pOutHeader->NextCommand = 0; // We'll override this if needed
       if (NextCommandOffset == 0)
//          pOutHeader->CreditRequest_CreditResponse = 1 + AddtoFinalCreditRequest_CreditResponse;
          pOutHeader->CreditRequest_CreditResponse = 32 + AddtoFinalCreditRequest_CreditResponse;
//          pOutHeader->CreditRequest_CreditResponse = pOutHeader->CreditRequest_CreditResponse + AddtoFinalCreditRequest_CreditResponse;

       // Advance the buffer pointers to 8 byte boundaries if this is a compound request
       if (smb2stream.compound_output_index!=0 || NextCommandOffset != 0)
       {
          unsigned int SkipCount = 0;
          // First advance the input request
          if (smb2stream.compound_output_index!=0)
            SkipCount = 0;
          else
          {
            unsigned int consumed = (unsigned int) PDIFF (smb2stream.pInBuf, pInBufStart);
            if (NextCommandOffset > consumed)
              SkipCount = NextCommandOffset - consumed;
          }
          if (SkipCount > smb2stream.read_buffer_remaining)
          {
             rtp_printf("SMBS_ProcSMB2_Body: Bad Compound request:\n");
          }
          else
          {
//             AddtoFinalCreditRequest_CreditResponse += pOutHeader->CreditRequest_CreditResponse;
             AddtoFinalCreditRequest_CreditResponse += 1; // pOutHeader->CreditRequest_CreditResponse;
             pOutHeader->CreditRequest_CreditResponse = 0;
             pStream->pInBuf+=SkipCount;
             pStream->read_buffer_remaining-=SkipCount;
             isCompoundReply = TRUE;
             // Now see if we have to pad the output to get to an 8 byte boundary
             if (!SMBS_Frame_Compound_Output(pStream, pOutBufStart))
               isCompoundReply = FALSE;
          }
       }
       // sign
#if (1)
       // Sign outgoing if incoming was signed basically
       if (pStream->InHdr.Flags&SMB2_FLAGS_SIGNED && pStream->psmb2Session && pStream->psmb2Session->Connection->Dialect != SMB2_DIALECT_2002)
       { // sign if dialact == 2100 and session id != 0
            uint8_t digest[SHA256_DIGEST_LENGTH];
printf("Okay sign2\n");
            if (pStream->psmb2Session->SessionId != 0)
            {
               unsigned int PrevLength;
               unsigned int SkipCount;
               int i;
               SHA256_CTX ctx;
               SHA256_CTX ctx_o;
               uint8_t ipad[65];
               uint8_t opad[65];

               MEMCLEAROBJ(ctx);
               MEMCLEAROBJ(ctx_o);

               // Now see if we have to pad the output to get to an 8 byte boundary
               PrevLength = (unsigned int) PDIFF (pStream->pOutBuf, pOutBufStart);
               SkipCount = ((PrevLength+7)&~((unsigned int)0x7))-PrevLength;
printf("Okay skip before calc signature l=%d\n",SkipCount);
               if (SkipCount && SkipCount < (rtsmb_size)pStream->write_buffer_remaining)
               {
                  tc_memset(pStream->pOutBuf,0,SkipCount);
                  pStream->write_buffer_remaining -= SkipCount;
                  pStream->pOutBuf = PADD (pStream->pOutBuf, SkipCount);
                  pStream->OutBodySize += SkipCount;
               }
printf("Okay sign3\n");
               PRTSMB2_HEADER pOutHdr = (PRTSMB2_HEADER)pOutBufStart;
               pOutHdr->Flags |= SMB2_FLAGS_SIGNED;
               tc_memset(pOutHdr->Signature, 0, 16);
               tc_memset(ipad, 0, sizeof(ipad));
               tc_memset(opad, 0, sizeof(opad));
//	if (session_key.length == 0) {
//		DEBUG(2,("Wrong session key length %u for SMB2 signing\n",
//			 (unsigned)session_key.length));
//		return NT_STATUS_ACCESS_DENIED;
//	}

//               tc_memcpy( ipad, pStream->psmb2Session->pSmbCtx->encryptionKey, 8);
//               tc_memcpy( opad, pStream->psmb2Session->pSmbCtx->encryptionKey, 8);

rtsmb_dump_bytes("encryptionKey", pStream->psmb2Session->pSmbCtx->encryptionKey, 16,  DUMPBIN);

               tc_memcpy( ipad, spnego_session_key, 16);
               tc_memcpy( opad, spnego_session_key, 16);
rtsmb_dump_bytes("spnego_session_key", spnego_session_key, 16,  DUMPBIN);

               /* XOR key with ipad and opad values */
               for (i=0; i<64; i++)
	           {
                ipad[i] ^= 0x36;
                opad[i] ^= 0x5c;
               }
               SHA256_Init(&ctx);
               SHA256_Update(&ctx, ipad, 64);

               //=====
               // SHA256_Update (SHA256_CTX *m, const void *v, size_t len)]
               {
                void *data = pOutBufStart;
                size_t  data_len =  PDIFF(pStream->pOutBuf,pOutBufStart);
printf("Okay calc signature l=%d\n",data_len);
                SHA256_Update(&ctx, data, data_len); /* then text of datagram */
               }
               SHA256_Final(digest, &ctx);
               SHA256_Init(&ctx_o);
               SHA256_Update(&ctx_o, opad, 64);
               SHA256_Update(&ctx_o, digest, SHA256_DIGEST_LENGTH);
               SHA256_Final(digest, &ctx_o);
               tc_memcpy(pOutHdr->Signature, digest, 16);
               // tc_memset(&pOutHdr->Signature[8], 0x12, 4);
printf("Okay sign3\n");
            }
        }
#endif
    }  while (isCompoundReply);
    Smb1SrvCtxtFromStream(pSctx, pStream);

    return TRUE;
//    return doSend;
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
      rtp_printf("SMBS_ProcSMB2_Body: Compound request: write buffer full\n");
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
    			doSend = Proc_smb2_Create(pStream);
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
        printf("Force charge 1\n");
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

printf("Not doing session shutdown in logoff\n");
    RTSmb2_SessionShutDown(pStream->psmb2Session);

    response.StructureSize          = 4;
    response.Reserved               = 0;
    pStream->OutHdr.SessionId       = pStream->psmb2Session->SessionId;
    /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
printf("Not clearing session pointer in logoff\n");
//    pStream->psmb2Session = 0;

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
    /* Read into command, share name will be placed in command_args.pBuffer which came from RTSmb2_Encryption_Get_Spnego_InBuffer */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    RTSMB_DEBUG_OUTPUT_STR ("\nShare name:", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (share_name, RTSMB_DEBUG_TYPE_SYS_DEFINED);
    RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);

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
#if (0&&HARDWIRED_INCLUDE_DCE)    // HEREHERE not sure what the issue is. comment i "We need to get IPC out of string"
       if (command.flags & 0x08)
       {
          response.optional_support = 1;
          WRITE_SMB_AND_X (srv_cmd_fill_tree_connect_options_and_x_lanman);
       }
       else
       {
          RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
       }

#endif
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

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  called\n",0);
    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  RtsmbStreamDecodeCommand failed...\n",0);
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    else
    {
        PTREE tree;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  RtsmbStreamDecodeCommand succeded Tree = %d\n",(int)pStream->InHdr.TreeId);
        tree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, (word) pStream->InHdr.TreeId);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  SMBU_GetTree returned %X\n",(int)tree);
        if (tree)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  call Tree_Shutdown session == %X\n",(int)pStream->psmb2Session);
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  call Tree_Shutdown session->pSmbCtx == %X\n",(int)pStream->psmb2Session->pSmbCtx);
            Tree_Shutdown (pStream->psmb2Session->pSmbCtx, tree);
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_TreeDisConnect:  back Tree_Shutdown X\n",0);
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
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Echo:  RtsmbStreamDecodeCommand failed...\n",0);
		RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
	response.StructureSize = 4;
     /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;

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
    return;
#ifdef RTSMB_DEBUG
char tmpBuffer[32];
    char* buffer = tmpBuffer;
    tmpBuffer[0] = '\0';
    RTSMB_DEBUG_OUTPUT_STR ("SMBS_ProcSMB2_Body:  Processing a packet with command: ", RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR((char *)DebugSMB2CommandToString(command), RTSMB_DEBUG_TYPE_ASCII);
    RTSMB_DEBUG_OUTPUT_STR (".\n", RTSMB_DEBUG_TYPE_ASCII);

#endif // RTSMB_DEBUG
}


#endif /* INCLUDE_RTSMB_SERVER */
#endif
