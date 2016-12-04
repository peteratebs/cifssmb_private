#ifndef __SRVOBJECTSC_H__
#define __SRVOBJECTSC_H__

#include "smbdefs.h"
#include "srvssn.h"
#include "srvssn.h"
#include "srvnet.h"

extern void srvobject_add_fid(FID_T *pfid);
extern void srvobject_tag_oplock(FID_T *pfid, char *tagstring); // Create check oplevel
extern void srvobject_session_blocked(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_session_enter(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_session_exit(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_tagalloc_oplock(FID_T *pfid, char *tagstring);
extern int srvobject_get_currentsession_index(void);
extern char *SMBU_format_fileid(byte *unique_fileid, int size, char *temp);
extern void SMBU_DisplayFidInfo(void);

#endif
