#ifndef __SMB2_H__
#define __SMB2_H__

#include <stdio.h>

#include "com_smb2_wiredefs.h"




//****************************************************************************
//**
//**    smb2.h
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================
#include "com_smb2_ssn.h"
//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================



extern void Smb2SrvModel_Global_Init(void);


#define RTSMB2_NBSS_TRANSFORM_HEADER_SIZE 52


//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================


#define TYPELESS int /* Types currently unresolved design */
#define CLAIM_SEMAPHORE
#define RELEASE_SEMAPHORE


//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================

/*  Returns a list of supported Encryption algorithms */
extern void RTSmb2_Encryption_Release_Spnego_Default(byte *pBuffer);
extern byte *RTSmb2_Encryption_Get_Spnego_Next_token(dword SessionGlobalId,TYPELESS SecurityContext,rtsmb_size *buffer_size,int *isLast_token,dword *status, byte *InToken, int InTokenLength);
extern dword RTSmb2_Encryption_Get_Spnego_New_SessionGlobalId(void);
extern void  RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(dword SessionId);
extern byte *RTSmb2_Encryption_Get_Spnego_Default(rtsmb_size *buffer_size);
extern BBOOL RTSmb2_Encryption_SignatureVerify(dword SessionGlobalId,TYPELESS SecurityContext,byte *Key, byte *Signature);
extern void  RTSmb2_Encryption_Sign_message(byte *Signature,byte *Key,byte SigningRule, byte *Message, rtsmb_size messageLength);
extern TYPELESS RTSmb2_Encryption_GetSecurityContext(dword SessionGlobalId);
extern BBOOL RTSmb2_Encryption_ValidateNameWithSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName);
extern BBOOL RTSmb2_Encryption_SetNameFromSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName);
extern BBOOL RTSmb2_Encryption_InquireContextAnon(dword SessionGlobalId,TYPELESS SecurityContext);
extern BBOOL RTSmb2_Encryption_InquireContextGuest(dword SessionGlobalId,TYPELESS SecurityContext);

extern void RTSmb2_Encryption_Release_Spnego_Next_token(byte *Buffer);

extern void  RTSmb2_Encryption_SetSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey);
extern void  RTSmb2_Encryption_Get_Session_SigningKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *pSigningKey, byte *pSessionKey);
extern void  RTSmb2_Encryption_Get_Session_ApplicationKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *ApplicationKey,byte *SessionKey);
extern void  RTSmb2_Encryption_Get_Session_ChannelKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SigningKey,byte *pKey);
extern void  RTSmb2_Encryption_Get_Session_EncryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *EncryptionKey, byte *SessionKey);
extern void  RTSmb2_Encryption_Get_Session_DecryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext, byte *DecryptionKey, byte *SessionKey);
extern void  RTSmb2_Encryption_SignMessage(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey, byte *Signature);

extern const char *DebugSMB2CommandToString(int command);

extern byte *RTSmb2_mapWildFileId(smb2_stream  *pStream, byte * pFileId);
extern word RTSmb2_get_externalFid(byte *smb2_file_handle);



//****************************************************************************
//**
//**    END HEADER smb2.h
//**
//****************************************************************************
#endif // __SMB2_H__
