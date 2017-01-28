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
#include "wchar.h"
#include "rtptime.h"
#include "rtpmem.h"
#include "srvsmbssn.h"

extern word spnego_AuthenticateUser (PSMB_SESSIONCTX pCtx, decoded_NegTokenTarg_t *decoded_targ_token, word *extended_authId);
extern pSmb2SrvModel_Global pSmb2SrvGlobal;
extern word NewUID(const PUSER u, int Max);
static BBOOL Smb1SrvUidForStream (smb2_stream  *pStream);
static byte *RTSmb2_Encryption_Get_Spnego_InBuffer(rtsmb_size *buffer_size);
static void RTSmb2_Encryption_Release_Spnego_InBuffer(byte *buffer);
extern int spnego_encode_ntlm2_type3_response_packet(unsigned char *outbuffer, size_t buffer_length);

/*
Proccess SESSION_SETUP requests.


3.3.5.5 Receiving an SMB2 SESSION_SETUP Request .................... 260


*/

void calculate_ntlmv2_signing_key(
  BYTE *encrypted_key,
  BYTE *security_blob,
  int blob_size,
  BYTE *user_name,
  int user_name_size,
  BYTE *domain_name,
  int domain_name_size,
  BYTE *password,
  int password_size,
  BYTE *session_key,
  int session_key_size,
  BYTE *signing_key_result);

BBOOL Proc_smb2_SessionSetup (smb2_stream  *pStream)
{
	int i;
	RTSMB2_SESSION_SETUP_C command;
	RTSMB2_SESSION_SETUP_R response;
	BBOOL  Connection3XXDIALECT = (BBOOL)SMB2IS3XXDIALECT(pStream->psmb2Session->Connection->NegotiateDialect);
    BBOOL  freesession=FALSE;
    BBOOL  reject=FALSE;
    BBOOL  finish=FALSE;
    BBOOL  send_next_token=FALSE;
    BBOOL  more_processing_required = FALSE;
    dword  reject_status=SMB2_STATUS_ACCESS_DENIED;
    struct s_Smb2SrvModel_Session  *pStreamSession;

    pSmb2SrvModel_Channel pChannel = 0;

    ////// pStream->EncryptMessage = TRUE;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    response.StructureSize          = 9;

    /* Get a temporary buffer for holding the incoming security token, released upon exit */
    pStream->ReadBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_InBuffer(&pStream->ReadBufferParms[0].byte_count);

    /* Read into command, if a security token is passed it will be placed in command_args.pBuffer which came from RTSmb2_Encryption_Get_Spnego_InBuffer */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
        goto release_and_return_TRUE;

    /* Pg 260 3. If SessionId in the SMB2 header of the request is zero, the server MUST process the authentication request as specified in section 3.3.5.5.1. */
    pStreamSession = pStream->psmb2Session;
    if (pStream->InHdr.SessionId!=0)
    { // We have a sessionid retrieve the session and go to process the next GSSAPI token
	  pSmb2SrvModel_Session pSmb2Session;
      pSmb2Session = Smb2SrvModel_Global_Get_SessionById(pStream->InHdr.SessionId);
      if (!pSmb2Session)
      {
        reject_status = SMB2_STATUS_INVALID_SMB;
        reject=TRUE;
      }
      else
      {
        pStreamSession = pStream->psmb2Session = pSmb2Session;
        finish=send_next_token=TRUE;
      }
    }
    if (pSmb2SrvGlobal->EncryptData && pSmb2SrvGlobal->RejectUnencryptedAccess)
    {
        /* 1. If the server implements the SMB 3.x dialect family, Connection.Dialect does not belong to the SMB 3.x dialect
           family, EncryptData is TRUE, and RejectUnencryptedAccess is TRUE, the server MUST fail the request with STATUS_ACCESS_DENIED.  */
        if (!Connection3XXDIALECT)
            reject=TRUE;
        else
        {
            /* 2. If Connection.Dialect belongs to the SMB 3.x dialect family, EncryptData is TRUE, RejectUnencryptedAccess is TRUE, and Connection.ClientCapabilities
               does not include the SMB2_GLOBAL_CAP_ENCRYPTION bit, the server MUST fail the request with STATUS_ACCESS_DENIED. */
            if ((pStreamSession->Connection->ClientCapabilities & SMB2_GLOBAL_CAP_ENCRYPTION)==0)
                reject=TRUE;
        }
    }
    finish=reject;
#define USE_HALF_DONE_SMB3_RECONNECT 0
#if (USE_HALF_DONE_SMB3_RECONNECT)
// This reconnects but looks only at the session ID. Check of UID is missing.
// Page 268   SMB3 only, this is incomplete more or less just a reminder for now.
// If Connection.Dialect belongs to the SMB 3.x dialect
// If a session is found with Session.SessionId equal to PreviousSessionId,
// the server MUST determine if the old session and the newly established session
// are created by the same user by comparing the user identifiers obtained from the Session.
// SecurityContext on the new and old session
    if (!finish && command.PreviousSessionId)
    {
        struct s_Smb2SrvModel_Session  *pCurrSession;   // For a server. points to the session
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_SessionSetup restoring a from session %d\n",(int)command.PreviousSessionId);
        pCurrSession = Smb2SrvModel_Global_Get_SessionById(command.PreviousSessionId);
        if (pCurrSession == pStreamSession)
        {
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_SessionSetup binding session:  pStreamSession == %X pStreamSession == %d\n",(int)pStreamSession, (int) pStreamSession->SessionId);
          RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
          goto release_and_return_TRUE;
        }
    }
#endif
    if (!finish && pStream->InHdr.SessionId==0)
    {
        /* Section 3.3.5.5.1 .. pg 262 */
	    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_SessionSetup binding session:  pStreamSession == %X pStreamSession == %d\n",(int)pStreamSession, (int) pStreamSession->SessionId);

        /* A session object MUST be allocated for this request. The session MUST be inserted into the GlobalSessionTable and a unique Session.SessionId is assigned to serve as a lookup key
           in the table. The session MUST be inserted into Connection.SessionTable. The server MUST register the session by invoking the event specified in [MS-SRVS] section 3.1.6.2 and
           assign the return value to Session.SessionGlobalId. ServerStatistics.sts0_sopens MUST be increased by 1. The SMB2 server MUST reserve -1 as an invalid SessionId and 0 as a S
           essionId for which no session exists. The other values MUST be initialized as follows:
        */
        Smb2SrvModel_Global_Stats_Open_Update(1);
        /* Session.Connection is set to the connection on which the request was received. (already done) */
        /* Session.State is set to InProgress */
        pStreamSession->State = Smb2SrvModel_Session_State_InProgress;
        /*  Already Done by New.
            Session.SecurityContext is set to NULL.
            Session.SessionKey is set to NULL, indicating that it is uninitialized.
            Session.SigningRequired is set to FALSE.
            Session.OpenTable is set to an empty table.
            Session.TreeConnectTable is set to an empty table.
            Session.IsAnonymous is set to FALSE.
        */

        /*  Session.CreationTime is set to the current time. */
        pStreamSession->CreationTime = rtsmb_util_get_current_filetime();
        /*    Session.IdleTime is set to the current time. */
        pStreamSession->IdleTime = rtp_get_system_msec();
        /*  If Connection.Dialect belongs to the SMB 3.x dialect family, Session.EncryptData is set to global EncryptData. */
        if (Connection3XXDIALECT)
        {
           pStream->EncryptMessage = pStreamSession->EncryptData = pSmb2SrvGlobal->EncryptData;
            /* If Connection.Dialect belongs to the SMB 3.x dialect family, Session.ChannelList MUST be set to an empty list. */
        }
        /* Using this session, authentication is continued as specified in section 3.3.5.5.3 */
        pStreamSession->SessionGlobalId = RTSmb2_Encryption_Get_Spnego_New_SessionGlobalId();

        if (!Smb2SrvModel_Global_Set_SessionInSessionList(pStreamSession))
        {
            reject_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
            finish=reject=TRUE;
        }
        else
        {
            finish=send_next_token=TRUE;
        }
    }

    /* 4. If Connection.Dialect belongs to the SMB 3.x dialect family, IsMultiChannelCapable is TRUE, and the SMB2_SESSION_FLAG_BINDING bit is set in the
          Flags field of the request, the server MUST perform the following:
    */
    if (Connection3XXDIALECT&&finish==FALSE&&pStream->InHdr.SessionId!=0&&pSmb2SrvGlobal->IsMultiChannelCapable && (command.Flags & SMB2_SESSION_FLAG_BINDING)!=0)
    {
        /* The server MUST look up the session in GlobalSessionTable using the SessionId from the SMB2 header. If the session is not found, the server MUST
           fail the session setup request with STATUS_USER_SESSION_DELETED. */
        struct s_Smb2SrvModel_Session  *pCurrSession;   // For a server. points to the session

        pCurrSession = Smb2SrvModel_Global_Get_SessionById(pStream->InHdr.SessionId);
        if (!pCurrSession)
        {
            reject_status = SMB2_STATUS_USER_SESSION_DELETED;
            finish=reject=TRUE;
        }
        else
        {
            /* If a session is found, the server MUST do the following */
            /* If Connection.Dialect is not the same as Session.Connection.Dialect, the server MUST fail the request with STATUS_INVALID_PARAMETER. */
            if (pStreamSession->Connection->NegotiateDialect != pCurrSession->Connection->NegotiateDialect)
            {
                reject_status = SMB2_STATUS_INVALID_PARAMETER;
                finish=reject=TRUE;
            }
           /* If the SMB2_FLAGS_SIGNED bit is not set in the Flags field in the header, the server MUST fail the request with error STATUS_INVALID_PARAMETER. */
            if (finish==FALSE && (pStream->InHdr.Flags & SMB2_FLAGS_SIGNED)== 0)
            {
                reject_status = SMB2_STATUS_INVALID_PARAMETER;
                finish=reject=TRUE;
            }
           /* If Session.State is InProgress, the server MUST fail the request with STATUS_REQUEST_NOT_ACCEPTED. */
            if (finish==FALSE && (pCurrSession->State == Smb2SrvModel_Session_State_InProgress))
            {
                reject_status = SMB2_STATUS_REQUEST_NOT_ACCEPTED;
                finish=reject=TRUE;
            }
           /* If Session.State is Expired, the server MUST fail the request with STATUS_NETWORK_SESSION_EXPIRED. */
            if (finish==FALSE && (pCurrSession->State == Smb2SrvModel_Session_State_Expired))
            {
                reject_status = SMB2_STATUS_NETWORK_SESSION_EXPIRED;
                finish=reject=TRUE;
            }
           /* If Session.IsAnonymous or Session.IsGuest is TRUE, the server MUST fail the request with STATUS_NOT_SUPPORTED. */
            if (finish==FALSE && (pCurrSession->IsAnonymous||pCurrSession->IsGuest))
            {
                reject_status = SMB2_STATUS_NOT_SUPPORTED;
                finish=reject=TRUE;
            }

           /* If there is a session in Connection.SessionTable identified by the SessionId in the request, the server MUST fail
              the request with STATUS_REQUEST_NOT_ACCEPTED. */
            if (finish==FALSE)
            {
                if (Smb2SrvModel_Global_Get_SessionByConnectionAndId(pStreamSession->Connection,pStream->InHdr.SessionId))
                {
                    reject_status = SMB2_STATUS_REQUEST_NOT_ACCEPTED;
                    finish=reject=TRUE;
                }
            }

           /* The server MUST verify the signature as specified in section 3.3.5.2.4, using the Session.SessionKey.*/
            if (finish==FALSE)
            {
                if (!RTSmb2_Encryption_SignatureVerify(pCurrSession->SessionGlobalId, pCurrSession->SecurityContext, pCurrSession->SessionKey,pStream->InHdr.Signature))
                {
                    reject_status = SMB2_STATUS_ACCESS_DENIED;
                    finish=reject=TRUE;
                }
            }
           /* The server MUST obtain the security context from the GSS authentication subsystem, and it MUST invoke the GSS_Inquire_context call as specified in [RFC2743]
              section 2.2.6, passing the security context as the input parameter. If the returned "src_name" does not match with the Session.Username, the server MUST fail
              the request with error code STATUS_NOT_SUPPORTED. */
            if (finish==FALSE)
            {
                pCurrSession->SecurityContext = RTSmb2_Encryption_GetSecurityContext(pCurrSession->SessionGlobalId);
                if (RTSmb2_Encryption_ValidateNameWithSecurityContext(pCurrSession->SessionGlobalId, pCurrSession->SecurityContext, pCurrSession->UserName)==FALSE)
                {
                    reject_status = SMB2_STATUS_NOT_SUPPORTED;
                    finish=reject=TRUE;
                }
            }
            /*If a session is found, proceed with the following steps. */
            if (finish==FALSE)
            {
                /* Free the session we came in with and use the one we just found */
                if (pStreamSession != pCurrSession)
                {
                  PNET_SESSIONCTX pNctxt = SMBS_findSessionByContext(pStream->pSmbCtx);
                    if (pNctxt)
                      SMBS_srv_netssn_connection_close_session(pNctxt);
                    pStream->psmb2Session = pCurrSession;
                    pStreamSession = pCurrSession;
                }
                /* If Session.State is Expired, the server MUST process the session setup request as specified in section 3.3.5.5.2. */
                /*  If Session.State is Valid, the server SHOULD<225> process the session setup request as specified in section 3.3.5.5.2. */
                if (pCurrSession->State == Smb2SrvModel_Session_State_Expired || pCurrSession->State == Smb2SrvModel_Session_State_Valid)
                {
                    /* 3.3.5.5.2 Reauthenticating an Existing Session
                    Session.State MUST be set to InProgress, and Session.SecurityContext set to NULL. Authentication is continued as specified in section 3.3.5.5.3.
                    Note that the existing Session.SessionKey will be retained.
                    */
                    /* 7. The server MUST continue processing the request as specified in section 3.3.5.5.3. */
                    pCurrSession->State = Smb2SrvModel_Session_State_InProgress;
                    finish=send_next_token=TRUE;
                }
            }
        }
    }
    if (send_next_token==TRUE)
    {
        dword status = 0;
        int Spnego_isLast_token = 1;
        decoded_NegTokenInit_t decoded_init_token;
        decoded_NegTokenTarg_t decoded_targ_token;
        int isNegTokenInitNOT;
int spnego_blob_size;
static byte spnego_blob_buffer[512];

        finish=FALSE; /* We may have set finished up above, so clear it now */
        /* Pg 262 - 3.3.5.5.3 Handling GSS-API Authentication */
        /* The server SHOULD use the configured authentication protocol to obtain the next GSS output token for the authentication exchange.<226> */
        isNegTokenInitNOT = spnego_decode_NegTokenInit_packet(&decoded_init_token, pStream->ReadBufferParms[0].pBuffer,pStream->ReadBufferParms[0].byte_count);
        spnego_decoded_NegTokenInit_destructor(&decoded_init_token);

        if (isNegTokenInitNOT == 0)
        { // We got neg token init packet, send a challenge
#if (HARDWIRED_DEBUG_ENCRYPTION_KEY==1)
            static byte b[8] = {0x01,0x23,0x45,0x67,0x89,0xab, 0xcd, 0xef};
//           tc_memcpy (&(pCtx->encryptionKey[0]), b, 8);
            rtp_printf("Sending hardwired type 2 key \n");
            tc_memcpy (&pStream->pSmbCtx->encryptionKey[0], b, 8);
#else
            for (i = 0; i < 4; i++)
            {
             word randnum = (word) tc_rand();    /* returns 15 bits of random data */
             tc_memcpy (&(pStream->pSmbCtx->encryptionKey[i * 2]), &randnum, 2);
            }
#endif
            spnego_blob_size=spnego_encode_ntlm2_type2_response_packet(spnego_blob_buffer, sizeof(spnego_blob_buffer),pStream->pSmbCtx->encryptionKey);
            pStream->WriteBufferParms[0].byte_count = spnego_blob_size;
            pStream->WriteBufferParms[0].pBuffer = spnego_blob_buffer;
            Spnego_isLast_token = 0;
        }
        else
        { // Check log- in credentials
          word  extended_authId=0;
          word  extended_access=AUTH_NOACCESS;
          rtsmb_char password_buffer[CFG_RTSMB_MAX_PASSWORD_SIZE+1];
          int  password_size = 0;
          BYTE *password;
          PFRTCHAR username=0;

          int NegTokenTargDecodeResult =  spnego_decode_NegTokenTarg_packet(&decoded_targ_token, pStream->ReadBufferParms[0].pBuffer,pStream->ReadBufferParms[0].byte_count);
          if (NegTokenTargDecodeResult == 0)
          {
            extended_access = spnego_AuthenticateUser (pStream->pSmbCtx, &decoded_targ_token, &extended_authId);
          }
          if (extended_access != AUTH_NOACCESS)
          {
            // Try the login if we have a password, otherwise fall trough and return status SMB2_STATUS_ACCESS_DENIED
            if (decoded_targ_token.user_name && decoded_targ_token.user_name->value_at_offset)
            {
              username = (PFRTCHAR)decoded_targ_token.user_name->value_at_offset;
              // Get password and convert the unicode string length to byte size
              password_size =  2 * Auth_GetPasswordFromUserName((PFRTCHAR)decoded_targ_token.user_name->value_at_offset,password_buffer);
              rtsmb_dump_bytes("Log in using db Password", password_buffer, password_size, DUMPUNICODE);
              password = (BYTE *)password_buffer;
            }
            if (!password_size)
            {
              RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Login error: user not found: %s\n", username?rtsmb_ascii_of((PFRTCHAR)username,0):"NOUSERNAME");
//              // Force it to "password"
//              static BYTE glpassword[] = {'p',0,'a',0,'s',0,'s',0,'w',0,'o',0,'r',0,'d',0,0,0};
//              rtsmb_dump_bytes("DB lookup failed use global password", glpassword, sizeof(glpassword), DUMPUNICODE);
//              password = (BYTE *) glpassword;
//              password_size = sizeof(glpassword)-2;
            }
          }
          if (extended_access==AUTH_NOACCESS)
          {
            // Force the buffer to zero this will close the session and shut down the socket
            spnego_decoded_NegTokenTarg_destructor(&decoded_targ_token);
            rtp_printf("!!!! spnego Auth failed, No access !!!! \n");
            pStream->WriteBufferParms[0].pBuffer = 0;
            status=SMB2_STATUS_ACCESS_DENIED;
          }
          else
          {
            spnego_blob_size=spnego_encode_ntlm2_type3_response_packet(spnego_blob_buffer, sizeof(spnego_blob_buffer));
            pStream->WriteBufferParms[0].byte_count = spnego_blob_size;
            pStream->WriteBufferParms[0].pBuffer = spnego_blob_buffer;
            Spnego_isLast_token = 1;
            // Calculate the session signing key
            if (decoded_targ_token.ntlm_response && decoded_targ_token.ntlm_response->size>16)
            {
                 // Look up the password by user. Fail if not found.
                 calculate_ntlmv2_signing_key(pStream->pSmbCtx->encryptionKey,
                   &decoded_targ_token.ntlm_response->value_at_offset[16],
                   decoded_targ_token.ntlm_response->size-16,
                   decoded_targ_token.user_name?decoded_targ_token.user_name->value_at_offset:0,
                   decoded_targ_token.user_name?(int) decoded_targ_token.user_name->size:0,
                   decoded_targ_token.domain_name?decoded_targ_token.domain_name->value_at_offset:0,
                   decoded_targ_token.domain_name?(int) decoded_targ_token.domain_name->size:0,
                   password,
                   password_size,
                   decoded_targ_token.session_key?decoded_targ_token.session_key->value_at_offset:0,
                   decoded_targ_token.session_key?(int) decoded_targ_token.session_key->size:0,
                   pStream->psmb2Session->SigningKey);
            }
            // Save off
            pStream->psmb2Session->UserName = (byte *) rtsmb_util_wstrmalloc(decoded_targ_token.user_name?(PFWCS)decoded_targ_token.user_name->value_at_offset:(PFWCS)"U\0N\0K\0N\0O\0W\0N\0\0\0");
            pStream->psmb2Session->DomainName = (byte *) rtsmb_util_wstrmalloc(decoded_targ_token.domain_name?(PFWCS)decoded_targ_token.domain_name->value_at_offset:(PFWCS)"U\0N\0K\0N\0O\0W\0N\0\0\0");
            spnego_decoded_NegTokenTarg_destructor(&decoded_targ_token);
          }
        }
//        pStream->WriteBufferParms[0].pBuffer = RTSmb2_Encryption_Get_Spnego_Next_token(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext, &pStream->WriteBufferParms[0].byte_count, &Spnego_isLast_token, &status, pStream->ReadBufferParms[0].pBuffer, command.SecurityBufferLength);
        if (!pStream->WriteBufferParms[0].pBuffer)
        {
           /* If the authentication protocol indicates an error, the server MUST fail the session setup request with the error received by placing the 32-bit NTSTATUS code received into the
              Status field of the SMB2 header. */
           /* and deregister the session by invoking the event
              specified in [MS-SRVS] section 3.1.6.3, providing Session.SessionGlobalId as an input parameter.*/
            RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(pStreamSession->SessionGlobalId);

           /* ServerStatistics.sts0_sopens MUST be decreased by 1. */
           Smb2SrvModel_Global_Stats_Open_Update(-1);

           /* set pStream->doSessionClose to instruct Smb1SrvCtxtFromStream to Unlink the session from all lists,
              free connections associated with the session and free the session */
           pStream->doSessionClose = TRUE;

            /* ServerStatistics.sts0_pwerrors MUST be increased by 1. */
            Smb2SrvModel_Global_Stats_Error_Update();

            /* The session object MUST also be freed, and the error response MUST be sent to the client. */
            reject_status = status;
            finish=reject=TRUE;

        }
        else
        {
            if (!Spnego_isLast_token)
                more_processing_required = TRUE; // Force more processing required status so we send more processing to get the client to authenticate
            /*
                The output token received from the GSS mechanism MUST be returned in the response. SecurityBufferLength indicates the length of the output token,
                and SecurityBufferOffset indicates its offset, in bytes, from the beginning of the SMB2 header.
            */
            if (pStream->WriteBufferParms[0].byte_count)
            {
                response.SecurityBufferOffset = (word)(pStream->OutHdr.StructureSize + response.StructureSize-1);
                response.SecurityBufferLength = (word)(pStream->WriteBufferParms[0].byte_count);
           }

            /* Session.SessionId MUST be placed in the SessionId field of the SMB2 header. */
            pStream->OutHdr.SessionId = pStreamSession->SessionId;
            /* Return the security tokens to the client and wait for another response packet */
            finish=TRUE;

            /* But first - If the GSS mechanism indicates that this is the final message in the authentication exchange, the server MUST verify the dialect as follows: */
            if (more_processing_required == FALSE)
            {
                pSmb2SrvModel_Connection Connection=pStreamSession->Connection;
                /* The server MUST look up all existing connections from the client in the global ConnectionList
                   where Connection.ClientGuid matches Session.Connection.ClientGuid. */
                CLAIM_SEMAPHORE    // TBD
                for (i=0; i < RTSMB2_CFG_MAX_CONNECTIONS; i++)
                {
                    pSmb2SrvModel_Connection p=pSmb2SrvGlobal->ConnectionList[i];
                    if (p && tc_memcmp(p->ClientGuid, Connection->ClientGuid, 16)==0)
                    {
                        if (p->NegotiateDialect != Connection->NegotiateDialect)
                        {
                        /* For any matching Connection, if Connection.Dialect is not the same as Session.Connection.Dialect,
                            the server SHOULD<227> close the newly created Session, as specified in section 3.3.4.12,
                            by providing Session.SessionGlobalId as the input parameter, and fail the session setup
                            request with STATUS_USER_SESSION_DELETED. */
                            reject_status = SMB2_STATUS_USER_SESSION_DELETED;
                            finish=reject=TRUE;
                            break;
                        }
                    }
                }
                RELEASE_SEMAPHORE
#ifdef SUPPORT_SMB3
                /* If Connection.Dialect belongs to the SMB 3.x dialect family */
                if (Connection3XXDIALECT)
                {
                    /* the server MUST insert the Session into Connection.SessionTable. */
                    if (!Smb2SrvModel_Connection_Set_SessionInSessionList(Connection, pStreamSession))
                    {

                        reject_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
                        finish=reject=TRUE;
                    }

                    if (finish==FALSE)
                    {
                        /* If Session.ChannelList does not have a channel entry for which Channel.Connection matches the connection on which this request is received,
                           the server MUST allocate a new Channel object with the following values and insert it into
                           Session.ChannelList:
                            Channel.SigningKey is set to NULL.
                            Channel.Connection is set to the connection on which this request is received.
                        */
                        pChannel = Smb2SrvModel_Session_Get_ChannelInChannelList(pStreamSession, Connection);

                        if (pChannel==0)
                        {
                            pChannel = Smb2SrvModel_New_Channel(Connection);
                            if (!pChannel || !Smb2SrvModel_Session_Set_ChannelInChannelList(pStreamSession, pChannel))
                            {
                                reject_status = SMB2_STATUS_INSUFFICIENT_RESOURCES;
                                finish=reject=TRUE;
                            }
                        }
                    }
                }
#endif
                /* 2. If Connection.ClientCapabilities is 0, the server MUST set Connection.ClientCapabilities to the capabilities received in the
                   SMB2 SESSION_SETUP Request. */
                if (Connection->ClientCapabilities == 0)
                {
                    Connection->ClientCapabilities = command.Capabilities;
                }
                /* 3. If Session.SecurityContext is NULL, it MUST be set to a value representing the user which successfully authenticated this connection.
                   The security context MUST be obtained from the GSS authentication subsystem.
                */
                if (!pStreamSession->SecurityContext)
                {
                    pStreamSession->SecurityContext = RTSmb2_Encryption_GetSecurityContext(pStreamSession->SessionGlobalId);
                }
                else
                {
                    /*  If it is not NULL, no changes are necessary. The server MUST invoke the GSS_Inquire_context call as specified in [RFC2743] section 2.2.6,
                        passing the Session.SecurityContext as the input parameter, and set Session.UserName to the returned "src_name".   */
                    RTSmb2_Encryption_SetNameFromSecurityContext(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->UserName);
                }
                /* 4. The server MUST invoke the GSS_Inquire_context call as specified in [RFC2743] section 2.2.6, passing the Session.SecurityContext as the
                      context_handle parameter. */
                if (RTSmb2_Encryption_InquireContextAnon(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext))
                {
                    /* If the returned anon_state is TRUE, the server MUST set Session.IsAnonymous to TRUE and the server MAY set the
                       SMB2_SESSION_FLAG_IS_NULL flag in the SessionFlags field of the SMB2 SESSION_SETUP Response.*/
                    pStreamSession->IsAnonymous = TRUE;
                    response.SessionFlags |= SMB2_SESSION_FLAG_IS_NULL;
                }
                else if (RTSmb2_Encryption_InquireContextGuest(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext))
                {
                  /* Otherwise, if the returned src_name corresponds to an implementation-specific guest user,<228> the server MUST set the SMB2_SESSION_FLAG_
                     IS_GUEST in the SessionFlags field of the SMB2 SESSION_SETUP Response and MUST set Session.IsGuest to TRUE. */
                     response.SessionFlags |= SMB2_SESSION_FLAG_IS_GUEST;
                     pStreamSession->IsGuest = TRUE;
                }
                /* 5. Session.SigningRequired MUST be set to TRUE under the following conditions:
                     If the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set in the SecurityMode field of the client request.
                     If the SMB2_SESSION_FLAG_IS_GUEST bit is not set in the SessionFlags field and Session.IsAnonymous
                     is FALSE and either Connection.ShouldSign or global RequireMessageSigning is TRUE. */
                if (
                       (command.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)!=0 &&
                       (response.SessionFlags&SMB2_SESSION_FLAG_IS_GUEST)==0 &&
                       !pStreamSession->IsAnonymous &&
                       (Connection->ShouldSign||pSmb2SrvGlobal->RequireMessageSigning)
                   )
                       pStreamSession->SigningRequired = TRUE;
                /* 6. The server MUST query the session key for this authentication from the underlying authentication protocol and store
                      the session key in Session.SessionKey, if Session.SessionKey is NULL. Session.SessionKey MUST be set as specified in
                      section 3.3.1.8, using the value queried from the GSS protocol.
                      For how this value is calculated for Kerberos authentication via GSS-API, see [MS-KILE] section 3.1.1.2.
                      When NTLM authentication via GSS-API is used, Session.SessionKey MUST be set to ExportedSessionKey,
                      see [MS-NLMP] section 3.1.5.1. The server SHOULD choose an authentication mechanism that provides unique and
                      randomly generated session keys in order to secure the integrity of the signing key, encryption key, and decryption key,
                      which are derived using the session key. */
//                if (pStreamSession->SessionKey == 0)
//                {
//                    RTSmb2_Encryption_SetSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SessionKey);
//                }
#ifdef SUPPORT_SMB3
                /*  7. If Connection.Dialect belongs to the SMB 3.x dialect family,
                       the server MUST generate Session.SigningKey as specified in section 3.1.4.2 by providing the following inputs:
                       Session.SessionKey as the key derivation key.
                       The case-sensitive ASCII string "SMB2AESCMAC" as the label.
                       The label buffer size in bytes, including the terminating null character. The size of "SMB2AESCMAC" is 12.
                       The case-sensitive ASCII string "SmbSign" as context for the algorithm.
                       The context buffer size in bytes, including the terminating null character. The size of "SmbSign" is 8.
                */
                if (Connection3XXDIALECT)
                {
                    byte RTSMB_FAR *pKey;
                    RTSmb2_Encryption_Get_Session_SigningKeyFromSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SigningKey,pStreamSession->SessionKey);
                /* 8. If Connection.Dialect belongs to the SMB 3.x dialect family, Session.ApplicationKey MUST be generated as specified in section 3.1.4.2 and passing the
                    following inputs:
                        Session.SessionKey as the key derivation key.
                        The case-sensitive ASCII string "SMB2APP" as the label.
                        The label buffer size in bytes, including the terminating null character. The size of "SMB2APP" is 8.
                        The case-sensitive ASCII string "SmbRpc" as context for the algorithm.
                            The context buffer size in bytes, including the terminating null character. The size of "SmbRpc" is 7.
                */
                    RTSmb2_Encryption_Get_Session_ApplicationKeyFromSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->ApplicationKey,pStreamSession->SessionKey);

                /*
                    9. If Connection.Dialect belongs to the SMB 3.x dialect family, the server MUST generate Channel.SigningKey by providing the following input values:
                        If SMB2_SESSION_FLAG_BINDING is not set in the Flags field of the request,
                            Session.SessionKey as the key derivation key;
                        otherwise,
                            the session key returned by the authentication protocol (in step 6) as the key derivation key.
                        The case-sensitive ASCII string "SMB2AESCMAC" as the label.
                        The label buffer size in bytes, including the terminating null character. The size of "SMB2AESCMAC" is 12.
                        The case-sensitive ASCII string "SmbSign" as context for the algorithm.
                        The context buffer size in bytes, including the terminating null character. The size of "SmbSign" is 8.
                */
                    if ((command.Flags & SMB2_SESSION_FLAG_BINDING)==0)
                        pKey = pStreamSession->SessionKey;
                    else
                        pKey = pStreamSession->SessionKey;  // TBD - Not sure about this

                    RTSmb2_Encryption_Get_Session_ChannelKeyFromSessionKey(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SigningKey,pKey);
                /* 10.If Connection.Dialect belongs to the SMB 3.x dialect family, global EncryptData is TRUE, and Connection.ClientCapabilities includes
                   the SMB2_GLOBAL_CAP_ENCRYPTION bit, the server MUST do the following:
                   Set the SMB2_SESSION_FLAG_ENCRYPT_DATA flag in the SessionFlags field of the SMB2 SESSION_SETUP Response.
                   Set Session.SigningRequired to FALSE.
                   Generate Session.EncryptionKey and Session.DecryptionKey as specified in section 3.1.4.2 by providing the following inputs:
                      Session.SessionKey as the key derivation key.
                      The case-sensitive ASCII string "SMB2AESCCM" as the label.
                      The label buffer length in bytes, including the terminating null character. The size of "SMB2AESCCM" is 11.
                      The case-sensitive ASCII string as key derivation context. For generating the encryption key, this MUST be "ServerOut".
                      For generating the decryption key, this MUST be "ServerIn "; note the blank space at the end.
                      The context buffer size in bytes, including the terminating null character. For generating both the encryption key and decryption key,
                      the string size is 10.
                */
                    if (pSmb2SrvGlobal->EncryptData && (Connection->ClientCapabilities&SMB2_GLOBAL_CAP_ENCRYPTION)!=0)
                    {
                        response.SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA;
                        pStreamSession->SigningRequired = FALSE;
                        RTSmb2_Encryption_Get_Session_EncryptionKeyFromSessionKey( pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->EncryptionKey, pStreamSession->SessionKey);
                        RTSmb2_Encryption_Get_Session_DecryptionKeyFromSessionKey( pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->DecryptionKey, pStreamSession->SessionKey);
                    }
                } // if (Connection3XXDIALECT)
#endif  // SUPPORT_SMB3

                /*
                    11.If Session.SigningRequired is TRUE, the server MUST sign the final session setup response before sending it to the client.
                    Otherwise, if Connection.Dialect belongs to the SMB 3.x dialect family, and if the SMB2_SESSION_FLAG_BINDING is set in the Flags
                    field of the request, the server MUST sign the response using Channel.SigningKey.
                */
                if (!more_processing_required && pStreamSession->SigningRequired)
                {
                    pStream->SigningKey = pStreamSession->SigningKey;
                    if (Connection3XXDIALECT)
                        pStream->SigningRule = SIGN_AES_CMAC_128;
                    else
                        pStream->SigningRule = SIGN_HMAC_SHA256;
                }
#ifdef SUPPORT_SMB3
                else if (!more_processing_required && Connection3XXDIALECT  && (command.Flags & SMB2_SESSION_FLAG_BINDING)!=0)
                {
                    RTSMB_ASSERT(pChannel)
                    pStream->SigningKey = pChannel->SigningKey;
                    pStream->SigningRule = SIGN_AES_CMAC_128;
                }
#endif
                /*
                      HEREHERE  - Session restore/Expiration time are not working properly
                       2.If the PreviousSessionId field of the request is not equal to zero, the server MUST take the following actions:
                        1. The server MUST look up the old session in GlobalSessionTable, where Session.SessionId matches PreviousSessionId. If no session is found,
                           no other processing is necessary.
                        2. If a session is found with Session.SessionId equal to PreviousSessionId, the server MUST determine if the old session and the newly established
                           session are created by the same user by comparing the user identifiers obtained from the Session.SecurityContext on the new and old session.
                            1. If the PreviousSessionId and SessionId values in the SMB2 header of the request are equal, the server SHOULD<229> ignore PreviousSessionId
                               and no other processing is required.
                            2. Otherwise, if the server determines the authentications were for the same user, the server MUST remove the old session from the GlobalSessionTable
                               and also from the Connection.SessionTable, as specified in section 3.3.7.1.
                            3. Otherwise, if the server determines that the authentications were for different users, the server MUST ignore the PreviousSessionId value.

                */
                /* 13.Session.State MUST be set to Valid */
                pStreamSession->State = Smb2SrvModel_Session_State_Valid;

                /* 14.Session.ExpirationTime MUST be set to the expiration time returned by the GSS authentication subsystem. If the GSS authentication subsystem does not
                   return an expiration time, the Session.ExpirationTime should be set to infinity.
                */
            }
            /*
                The GSS-API can indicate that this is not the final message in authentication exchange using the GSS_S_CONTINUE_NEEDED semantics as specified in
                [MS-SPNG] section 3.3.1. If the GSS mechanism indicates that this is not the final message of the authentication exchange, the following additional
                step MUST be taken:
                    The status code in the SMB2 header of the response MUST be set to STATUS_MORE_PROCESSING_REQUIRED.
                    If Connection.Dialect belongs to the SMB 3.x dialect family, and if the SMB2_SESSION_FLAG_BINDING is set in the Flags field of the request,
                    the server MUST sign the response by using Session.SessionKey
            */
            if (more_processing_required)
            {
                pStream->OutHdr.Status_ChannelSequenceReserved = SMB2_STATUS_MORE_PROCESSING_REQUIRED;
#ifdef SUPPORT_SMB3
                if (Connection3XXDIALECT)
                {
                    RTSmb2_Encryption_SignMessage(pStreamSession->SessionGlobalId,pStreamSession->SecurityContext,pStreamSession->SessionKey,pStream->InHdr.Signature);
                }
#endif
            }
        } // if (!pStream->WriteBufferParms[0].pBuffer) else ..
    } // if (send_next_token==TRUE)
    if (reject)
    {
        rtp_printf("!!!! Auth setting reject status !!!! \n");
		RtsmbWriteSrvStatus (pStream, reject_status);
        pStream->doSessionClose = TRUE;
    }
    else
    {
        pStream->OutHdr.SessionId       = pStreamSession->SessionId;
        // Allocate a UID structure for this session and populate pStream->pSmbCtx->uid
        if (!Smb1SrvUidForStream (pStream))
        {
           pStream->doSessionClose = TRUE;
        }
        else
        {
          /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
          RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
        }
    }
release_and_return_TRUE:
    if (pStream->WriteBufferParms[0].pBuffer)
        RTSmb2_Encryption_Release_Spnego_Next_token(pStream->WriteBufferParms[0].pBuffer);
    if (pStream->ReadBufferParms[0].pBuffer)
        RTSmb2_Encryption_Release_Spnego_InBuffer(pStream->ReadBufferParms[0].pBuffer);
    return TRUE;
} // End Proc_smb2_SessionSetup

static byte *RTSmb2_Encryption_Get_Spnego_InBuffer(rtsmb_size *buffer_size)
{
    *buffer_size=1024;
    return (byte *)rtp_malloc(1024);
}

static void RTSmb2_Encryption_Release_Spnego_InBuffer(byte *buffer)
{
    RTP_FREE(buffer);
}


static BBOOL Smb1SrvUidForStream (smb2_stream  *pStream)
{
  PSMB_SESSIONCTX pCtx =  pStream->pSmbCtx;
    pCtx->uid = 0;
    pCtx->accessMode = AUTH_USER_MODE;
    if (pCtx->accessMode == AUTH_USER_MODE)
    {
        int i;
        word authId;
        PUSER user = (PUSER)0;

       authId = 0;
//       word access access = AUTH_USER_MODE;
       {
           /* if this is a guest loging, reuse old guests   */
           if ((user == (PUSER)0) && (authId == 0))
           {
               for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
               {
                   if (pCtx->uids[i].inUse && (authId == pCtx->uids[i].authId))
                   {
                       user = &pCtx->uids[i];
                       break;
                   }
               }
           }
           /* allocate a new UID   */
           if (user == (PUSER)0)
           {
               for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
               {
                   if (pCtx->uids[i].inUse == FALSE)
                   {
                       user = &pCtx->uids[i];
                       SMBS_User_Init(user);
                       user->uid    = (word) NewUID(pCtx->uids, prtsmb_srv_ctx->max_uids_per_session);
                       user->authId = user->uid; // Not sure
                       user->canonicalized = (BBOOL) FALSE; // Not sure
                       break;
                   }
               }
           }

           if (user == (PUSER)0)
           {
               RtsmbWriteSrvStatus(pStream,SMB2_STATUS_SMB_TOO_MANY_GUIDS_REQUESTED);
               return FALSE;
           }
           else
           {
               pCtx->uid    = user->uid;

           }
       }
    }
    return TRUE;
}
#endif /* INCLUDE_RTSMB_SERVER */
#endif /* #ifdef SUPPORT_SMB2   exclude rest of file */
