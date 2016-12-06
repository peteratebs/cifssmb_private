#ifndef __SRVOBJECTSC_H__
#define __SRVOBJECTSC_H__

#include "smbdefs.h"
#include "srvssn.h"
#include "srvssn.h"
#include "srvnet.h"

#define INCLUDE_SRVOBJ_REMOTE_DIAGS 1
#ifdef INCLUDE_SRVOBJ_REMOTE_DIAGS

#define REMOTE_DEBUG_TO_PROXY_PORTNUMBER 9988
#define REMOTE_DEBUG_FROM_PROXY_PORTNUMBER 9989

#endif

#ifdef __cplusplus
extern "C" {
#endif

extern void srvobject_add_fid(FID_T *pfid);
extern void srvobject_tag_oplock(FID_T *pfid, char *tagstring); // Create check oplevel
extern void srvobject_session_blocked(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_session_enter(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_session_exit(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_tagalloc_oplock(FID_T *pfid, char *tagstring);
extern int srvobject_get_currentsession_index(void);
extern char *SMBU_format_fileid(byte *unique_fileid, int size, char *temp);
extern void SMBU_DisplayFidInfo(void);
extern BBOOL srvobject_bind_diag_socket(void);
extern int srvobject_process_diag_request(void);
extern RTP_SOCKET *srvobject_get_diag_socket(void);
extern void srvobject_write_diag_socket(byte *p, int len);

#ifdef __cplusplus
}
#endif

#endif

