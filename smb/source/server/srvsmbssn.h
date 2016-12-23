/*                                                                        */
/* SRVSMBSSN.H -                                                             */
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
/*                                                                        */
#ifndef __SRV_SMBSSN_H__
#define __SRV_SMBSSN_H__


#define YIELD_BASE_PORTNUMBER   9999
#define YIELD_DEFAULT_DURATION 3000                 // for testing


EXTERN_C BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate);
EXTERN_C void SMBS_InitSessionCtx_smb(PSMB_SESSIONCTX pSmbCtx, int protocol_version);

EXTERN_C void SMBS_Tree_Init (PTREE tree);
EXTERN_C void SMBS_Tree_Shutdown (PSMB_SESSIONCTX pCtx, PTREE tree);
EXTERN_C void SMBS_User_Init (PUSER user);
EXTERN_C void SMBS_User_Shutdown (PSMB_SESSIONCTX pCtx, PUSER user);
EXTERN_C void SMBS_CloseShare ( PSMB_SESSIONCTX pCtx, word handle);
EXTERN_C void SMBS_CloseSession(PSMB_SESSIONCTX pSmbCtx);


EXTERN_C void SMBS_new_session_yield_signal(PNET_SESSIONCTX pNetCtx);
EXTERN_C int  SMBS_check_yield_signal(PSMB_SESSIONCTX pSctx);
EXTERN_C void SMBS_set_yield_signal(PSMB_SESSIONCTX pSctx);        // Not called ???
EXTERN_C void SMBS_set_yield_timeout(PSMB_SESSIONCTX pSctx);
EXTERN_C void SMBS_clear_yield_timeout(PSMB_SESSIONCTX pSctx);
EXTERN_C int  SMBS_check_yield_timeout(PSMB_SESSIONCTX pSctx);           // Returns true if timedout
EXTERN_C void SMBS_wake_session_from_yield(PNET_SESSIONCTX pnCtx);
EXTERN_C void SMBS_bind_yield_signal(yield_signal_t *yield_signal_instance, int thread_index);
EXTERN_C int SMBS_is_yield_signal_blocked(PSMB_SESSIONCTX pSctx);






EXTERN_C void SMBS_srv_netssn_init (void);
EXTERN_C void SMBS_srv_netssn_cycle (long timeout);
EXTERN_C void SMBS_srv_netssn_shutdown (void);
EXTERN_C void SMBS_srv_netssn_connection_close_session(PNET_SESSIONCTX pSCtx );

EXTERN_C void SMBS_Setsession_state(PSMB_SESSIONCTX pSctxt, SMBS_SESSION_STATE new_session_state);
EXTERN_C PNET_SESSIONCTX SMBS_firstSession (void);
EXTERN_C PNET_SESSIONCTX SMBS_nextSession (PNET_SESSIONCTX pCtx);
EXTERN_C PNET_SESSIONCTX SMBS_findSessionByContext (PSMB_SESSIONCTX pSctxt);
EXTERN_C void SMBS_closeAllShares(PSR_RESOURCE pResource);

#endif // __SRV_SMBSSN_H__
/* INCLUDE_RTSMB_SERVER */
