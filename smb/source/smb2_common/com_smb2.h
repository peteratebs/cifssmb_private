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



EXTERN_C void Smb2SrvModel_Global_Init(void);


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
EXTERN_C void RTSmb2_Encryption_Release_Spnego_Default(byte *pBuffer);
EXTERN_C byte *RTSmb2_Encryption_Get_Spnego_Next_token(dword SessionGlobalId,TYPELESS SecurityContext,rtsmb_size *buffer_size,int *isLast_token,dword *status, byte *InToken, int InTokenLength);
EXTERN_C dword RTSmb2_Encryption_Get_Spnego_New_SessionGlobalId(void);
EXTERN_C void  RTSmb2_Encryption_Spnego_Clear_SessionGlobalId(dword SessionId);
EXTERN_C byte *RTSmb2_Encryption_Get_Spnego_Default(rtsmb_size *buffer_size);
EXTERN_C BBOOL RTSmb2_Encryption_SignatureVerify(dword SessionGlobalId,TYPELESS SecurityContext,byte *Key, byte *Signature);
EXTERN_C void  RTSmb2_Encryption_Sign_message(byte *Signature,byte *Key,byte SigningRule, byte *Message, rtsmb_size messageLength);
EXTERN_C TYPELESS RTSmb2_Encryption_GetSecurityContext(dword SessionGlobalId);
EXTERN_C BBOOL RTSmb2_Encryption_ValidateNameWithSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName);
EXTERN_C BBOOL RTSmb2_Encryption_SetNameFromSecurityContext(dword SessionGlobalId,TYPELESS SecurityContext,byte *UserName);
EXTERN_C BBOOL RTSmb2_Encryption_InquireContextAnon(dword SessionGlobalId,TYPELESS SecurityContext);
EXTERN_C BBOOL RTSmb2_Encryption_InquireContextGuest(dword SessionGlobalId,TYPELESS SecurityContext);

EXTERN_C void RTSmb2_Encryption_Release_Spnego_Next_token(byte *Buffer);

EXTERN_C void  RTSmb2_Encryption_SetSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey);
EXTERN_C void  RTSmb2_Encryption_Get_Session_SigningKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *pSigningKey, byte *pSessionKey);
EXTERN_C void  RTSmb2_Encryption_Get_Session_ApplicationKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *ApplicationKey,byte *SessionKey);
EXTERN_C void  RTSmb2_Encryption_Get_Session_ChannelKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *SigningKey,byte *pKey);
EXTERN_C void  RTSmb2_Encryption_Get_Session_EncryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext,byte *EncryptionKey, byte *SessionKey);
EXTERN_C void  RTSmb2_Encryption_Get_Session_DecryptionKeyFromSessionKey(dword SessionGlobalId,TYPELESS SecurityContext, byte *DecryptionKey, byte *SessionKey);
EXTERN_C void  RTSmb2_Encryption_SignMessage(dword SessionGlobalId,TYPELESS SecurityContext,byte *SessionKey, byte *Signature);

EXTERN_C const char *DebugSMB2CommandToString(int command);




//****************************************************************************
//**
//**    END HEADER smb2.h
//**
//****************************************************************************
#endif // __SMB2_H__
