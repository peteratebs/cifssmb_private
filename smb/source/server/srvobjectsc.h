#ifndef __SRVOBJECTSC_H__
#define __SRVOBJECTSC_H__

#include "smbdefs.h"
#include "srvssn.h"
#include "srvssn.h"

extern void srvobject_add_fid(FID_T *pfid);
extern void srvobject_tag_oplock(FID_T *pfid, char *tagstring); // Create check oplevel
extern void srvobject_session_blocked(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_session_enter(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_session_exit(struct net_thread_s *pThread, struct net_sessionctxt **psession);
extern void srvobject_display_diags(void);

#endif
