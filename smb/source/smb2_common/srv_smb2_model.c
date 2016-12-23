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
#include "rtpmem.h"
#include "rtptime.h"

extern void Smb2SrvModel_New_Session(struct smb_sessionCtx_s *pSmbCtx);

pSmb2SrvModel_Session Smb2SrvModel_Global_Get_SessionById(ddword SessionId);
pSmb2SrvModel_Session Smb2SrvModel_Global_Get_SessionByConnectionAndId(pSmb2SrvModel_Connection Connection,ddword SessionId);

/*
================
Initialize Smb2 server model global structure.

  This function initializes the model to default values and calls the control initializer to initialize implemetation details.

================
*/

static struct s_Smb2SrvModel_Global RTSMB_FAR _Smb2SrvGlobal;
pSmb2SrvModel_Global pSmb2SrvGlobal = &_Smb2SrvGlobal;

/* MS-SMB2::3.3.3 Initialization */
void Smb2SrvModel_Global_Init(void)
{
    /*
        All the members in ServerStatistics MUST be set to zero.
        RequireMessageSigning MUST be set to Default value.
        ServerEnabled MUST be set to FALSE.
        GlobalOpenTable MUST be set to an empty table.
        GlobalSessionTable MUST be set to an empty table.
    ServerGuid MUST be set to a newly generated GUID.
        ConnectionList MUST be set to an empty list.
    ServerStartTime MUST be set to the time at which the SMB2 server was started.
        IsDfsCapable MUST be set to FALSE.
    RTSMBIsLeaseCapable set to configuration
    RTSMBIsPersistentHandlesCapable set to configuration
    RTSMBIsLeaseDirectoriesCapable set to configuration
    RTSMBIsEncryptionCapable set to configuration

    ServerSideCopyMaxNumberofChunks MUST be set to an implementation-specific<172> default value.
    ServerSideCopyMaxChunkSize MUST be set to an implementation-specific<173> default value.
    ServerSideCopyMaxDataSize MUST be set to an implementation-specific<174> default value.
        ShareList MUST be set to an empty list.
            If the server implements the SMB 2.1 or SMB 3.x dialect family, it MUST initialize the following:
    ServerHashLevel MUST be set to an implementation-specific<175> default value.
        If the server implements the SMB 2.1 or 3.x dialect family and supports leasing, the server MUST implement the following:
            GlobalLeaseTableList MUST be set to an empty list.
    MaxResiliencyTimeout SHOULD<176> be set to an implementation-specific default value.
        If the server implements the SMB 3.x dialect family, the server MUST implement the following:
    EncryptionAlgorithmList MUST be initialized with an implementation-specific<177> list of encryption algorithms supported by the server.
    EncryptData MUST be set in an implementation-specific manner.<178>
    RejectUnencryptedAccess MUST be set in an implementation-specific manner.<179>
    IsMultiChannelCapable MUST be set in an implementation-specific manner.<180>
        IsSharedVHDSupported: MUST be set to FALSE.
    */

    pSmb2SrvGlobal = &_Smb2SrvGlobal;
    /* Zero the global object, this does most of the work */
   	MEMCLEARPOBJ(pSmb2SrvGlobal);

    pSmb2SrvGlobal->RTSMBNetSessionId                   = 1;  /* Every new SETUP request sends a response with a new session ID */

    pSmb2SrvGlobal->RequireMessageSigning               = RTSMB2_CFG_REQUIRE_MESSAGE_SIGNING;
    pSmb2SrvGlobal->RTSMBIsLeaseCapable                 = RTSMB2_CFG_LEASE_CAPABLE;
    pSmb2SrvGlobal->RTSMBIsPersistentHandlesCapable     = RTSMB2_CFG_PERSISTENT_HANDLE_CAPABLE;
    pSmb2SrvGlobal->RTSMBIsLeaseDirectoriesCapable      = RTSMB2_CFG_LEASE_DIRECTORIES_CAPABLE;
    pSmb2SrvGlobal->RTSMBIsEncryptionCapable            = RTSMB2_CFG_ENCRYPTION_CAPABLE;

    rtsmb_util_get_new_Guid(pSmb2SrvGlobal->ServerGuid);

    pSmb2SrvGlobal->ServerStartTime                    = rtsmb_util_get_current_filetime();
    pSmb2SrvGlobal->ServerSideCopyMaxNumberofChunks    = RTSMB2_CFG_COPY_MAX_CHUNKS;
    pSmb2SrvGlobal->ServerSideCopyMaxChunkSize         = RTSMB2_CFG_COPY_MAX_CHUNK_SIZE;
    pSmb2SrvGlobal->ServerSideCopyMaxDataSize          = RTSMB2_CFG_COPY_MAX_DATA_SIZE;
    pSmb2SrvGlobal->ServerHashLevel                    = RTSMB2_CFG_SERVER_HASH_LEVEL;
    pSmb2SrvGlobal->MaxResiliencyTimeout               = RTSMB2_CFG_MAX_RESILIENCY_TIMEOUT;
static char *algs[] = {"Algorithm1", "Algorith2","Algorithm3", 0};
    pSmb2SrvGlobal->EncryptionAlgorithmList            = (byte  **)algs;
    pSmb2SrvGlobal->EncryptData                        = RTSMB2_CFG_ENCRYPT_DATA;
    pSmb2SrvGlobal->RejectUnencryptedAccess            = RTSMB2_CFG_REJECT_UNENCRYPTED_ACCESS;
    pSmb2SrvGlobal->IsMultiChannelCapable              = RTSMB2_CFG_MULTI_CHANNEL_CAPABLE;
}

/* Find a session in the global table based on Session ID */
pSmb2SrvModel_Session Smb2SrvModel_Global_Get_SessionById(ddword SessionId)
{
int i;
pSmb2SrvModel_Session r=0;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_SESSIONS; i++)
    {
        if (pSmb2SrvGlobal->SessionTable[i]&& pSmb2SrvGlobal->SessionTable[i]->SessionId==SessionId)
        {
            r=pSmb2SrvGlobal->SessionTable[i];
            break;
        }
    }
    RELEASE_SEMAPHORE
    return r;
}


/* Add a session to the global session table. */
BBOOL Smb2SrvModel_Global_Set_SessionInSessionList(pSmb2SrvModel_Session pSession)
{
int i;
BBOOL r=FALSE;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_SESSIONS; i++)
    {
        if (!pSmb2SrvGlobal->SessionTable[i])
        {
            pSmb2SrvGlobal->SessionTable[i]=pSession;
            r=TRUE;
            break;
        }
    }
    RELEASE_SEMAPHORE
    return r;
}

/* Remove a sesion from the global session table. */
void Smb2SrvModel_Global_Remove_SessionFromSessionList(pSmb2SrvModel_Session pSession)
{
int i;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_SESSIONS; i++)
    {
        if (pSmb2SrvGlobal->SessionTable[i]==pSession)
        {
            pSmb2SrvGlobal->SessionTable[i]=0;
            break;
        }
    }
    RELEASE_SEMAPHORE
}

/* Find a session in the global table based on Session ID and release it */
void  RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(dword SessionId)
{
pSmb2SrvModel_Session p;
   do
   {
      p = Smb2SrvModel_Global_Get_SessionById(SessionId);
      if (p)
      {
         Smb2SrvModel_Global_Remove_SessionFromSessionList(p);
      }
   }  while (p);
}

/* Find a session in the global table based on connection and Session ID */
pSmb2SrvModel_Session Smb2SrvModel_Global_Get_SessionByConnectionAndId(pSmb2SrvModel_Connection Connection,ddword SessionId)
{
int i;
pSmb2SrvModel_Session r=0;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_SESSIONS; i++)
    {
        if (pSmb2SrvGlobal->SessionTable[i]&&pSmb2SrvGlobal->SessionTable[i]->SessionId==SessionId&&pSmb2SrvGlobal->SessionTable[i]->Connection==Connection)
        {
            r=pSmb2SrvGlobal->SessionTable[i];
            break;
        }
    }
    RELEASE_SEMAPHORE
    return r;
}


/* Helper function for security code to access the user name from the smb2 session structure. */
PFWCS  RTSmb2_get_stream_username(void *pSmb2Stream)
{
  if (pSmb2Stream && ((smb2_stream  *)pSmb2Stream)->psmb2Session &&((smb2_stream  *)pSmb2Stream)->psmb2Session->UserName)
    return (PFWCS) ((smb2_stream  *)pSmb2Stream)->psmb2Session->UserName;
  else
    return (PFWCS) "U\0N\0K\0N\0O\0W\0N\0\0"; // "UTF16 UNKOWN"
}
/* Helper function for security code to access the domain name from the smb2 session structure. */
PFWCS  RTSmb2_get_stream_authority_name(void *pSmb2Stream)
{
  if (pSmb2Stream && ((smb2_stream  *)pSmb2Stream)->psmb2Session &&((smb2_stream  *)pSmb2Stream)->psmb2Session->DomainName)
    return (PFWCS)((smb2_stream  *)pSmb2Stream)->psmb2Session->DomainName;
  else
    return (PFWCS)"U\0N\0K\0N\0O\0W\0N\0\0"; // "UTF16 UNKOWN"
}



/* Format the global caps field for Proc_smb2_NegotiateProtocol. Values derived from fields in the global object */
dword Smb2_util_get_global_caps(pSmb2SrvModel_Connection pConnection,PRTSMB2_NEGOTIATE_C pRequest)
{
dword global_caps = 0;
BBOOL is3XXDIALECT = (BBOOL)SMB2IS3XXDIALECT(pConnection->NegotiateDialect);
    if (pSmb2SrvGlobal->IsDfsCapable)
        global_caps |= SMB2_GLOBAL_CAP_DFS;
    if (pSmb2SrvGlobal->RTSMBIsLeaseCapable)
        global_caps |= SMB2_GLOBAL_CAP_LEASING;
    if (pConnection->SupportsMultiCredit)
        global_caps |= SMB2_GLOBAL_CAP_LARGE_MTU;
    if (pRequest)
    {
      if (pSmb2SrvGlobal->IsMultiChannelCapable && is3XXDIALECT && (pRequest->Capabilities & SMB2_GLOBAL_CAP_MULTI_CHANNEL)!=0 )
          global_caps |= SMB2_GLOBAL_CAP_MULTI_CHANNEL;
      if (pSmb2SrvGlobal->RTSMBIsLeaseDirectoriesCapable && is3XXDIALECT && (pRequest->Capabilities & SMB2_GLOBAL_CAP_DIRECTORY_LEASING)!=0)
          global_caps |= SMB2_GLOBAL_CAP_DIRECTORY_LEASING;
      if (pSmb2SrvGlobal->RTSMBIsPersistentHandlesCapable && is3XXDIALECT && (pRequest->Capabilities & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES)!=0)
          global_caps |= SMB2_GLOBAL_CAP_PERSISTENT_HANDLES;
      if (pSmb2SrvGlobal->RTSMBIsEncryptionCapable && is3XXDIALECT && (pRequest->Capabilities & SMB2_GLOBAL_CAP_ENCRYPTION)!=0)
          global_caps |= SMB2_GLOBAL_CAP_ENCRYPTION;
    }
    return global_caps;
}

/* Find a session in the global table based on Session ID */
BBOOL Smb2SrvModel_Connection_Set_SessionInSessionList(pSmb2SrvModel_Connection Connection, pSmb2SrvModel_Session pSession)
{
int i;
BBOOL r=FALSE;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_SESSIONS; i++)
    {
        if (!Connection->SessionTable[i])
        {
            Connection->SessionTable[i]=pSession;
            r=TRUE;
            break;
        }
    }
    RELEASE_SEMAPHORE
    return r;
}

#ifdef SUPPORT_SMB3
/* See if Session.ChannelList has a channel entry for which Channel.Connection matches the connection on which this request is received */
pSmb2SrvModel_Channel Smb2SrvModel_Session_Get_ChannelInChannelList(pSmb2SrvModel_Session pSession, pSmb2SrvModel_Connection Connection)
{
pSmb2SrvModel_Channel r=0;
int i;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_CHANNELS_PER_SESSION; i++)
    {
        if (pSession->ChannelList[i]&&pSession->ChannelList[i]->Connection==Connection)
        {
            r=pSession->ChannelList[i];
            break;
        }
    }
    RELEASE_SEMAPHORE
    return r;
}

/* Add a channel to Session.ChannelList */
BBOOL Smb2SrvModel_Session_Set_ChannelInChannelList(pSmb2SrvModel_Session pSession, pSmb2SrvModel_Channel pChannel)
{
int i;
BBOOL r=FALSE;
    CLAIM_SEMAPHORE
    for (i=0; i < RTSMB2_CFG_MAX_CHANNELS_PER_SESSION; i++)
    {
        if (!pSession->ChannelList[i])
        {
            pSession->ChannelList[i]=pChannel;
            r=TRUE;
            break;
        }
    }
    RELEASE_SEMAPHORE
    return r;
}
#endif // #ifdef SUPPORT_SMB3

/* MS-SMB2::3.3.4.0 Sending Any Outgoing Message

*/
/* Called to update byte send count */
void Smb2SrvModel_Global_Stats_Send_Update(dword body_size)
{
    ddword prev = pSmb2SrvGlobal->ServerStatistics.sts0_bytessent_low;
    pSmb2SrvGlobal->ServerStatistics.sts0_bytessent_low  += body_size;
    if (pSmb2SrvGlobal->ServerStatistics.sts0_bytessent_low<prev)
        pSmb2SrvGlobal->ServerStatistics.sts0_bytessent_high += 1;
}
/* Called to update open count */
void Smb2SrvModel_Global_Stats_Open_Update(int change)
{
   pSmb2SrvGlobal->ServerStatistics.sts0_sopens += (dword)change;
}
/* Called to update password error count */
void Smb2SrvModel_Global_Stats_Error_Update(void)
{
   pSmb2SrvGlobal->ServerStatistics.sts0_pwerrors += 1;
}

extern void Smb2SrvModel_New_Session(PSMB_SESSIONCTX pSmbCtx)
{
    MEMCLEAROBJ(pSmbCtx->Smb2SessionInstance);
    pSmbCtx->Smb2SessionInstance.SessionId = pSmb2SrvGlobal->RTSMBNetSessionId++;
    pSmbCtx->Smb2SessionInstance.RTSMBisAllocated=TRUE;
    pSmbCtx->Smb2SessionInstance.Connection = &pSmbCtx->Smb2ConnectionInstance;
    MEMCLEAROBJ(pSmbCtx->Smb2ConnectionInstance);
    pSmbCtx->Smb2SessionInstance.Connection->RTSMBisAllocated = TRUE;
    /* The current activity state of this session. This value MUST be either InProgress, Valid, or Expired. */
    pSmbCtx->Smb2SessionInstance.State = Smb2SrvModel_Session_State_InProgress;
    pSmbCtx->isSMB2 = TRUE;
}


void Smb2SrvModel_Free_Session(pSmb2SrvModel_Session pSession)
{
    if (pSession->Connection) pSession->Connection->RTSMBisAllocated = FALSE;
    pSession->RTSMBisAllocated=FALSE;
}

#ifdef SUPPORT_SMB3
pSmb2SrvModel_Channel Smb2SrvModel_New_Channel(pSmb2SrvModel_Connection Connection)
{
    // TBD
    static Smb2SrvModel_Channel TestChannel;
    MEMCLEAROBJ(TestChannel);
    TestChannel.Connection = Connection;
    return &TestChannel;
}
#endif


#endif /* INCLUDE_RTSMB_SERVER */
#endif
