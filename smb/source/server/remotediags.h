#ifndef __REMOTEDIAGS_H__
#define __REMOTEDIAGS_H__

#include "smbdefs.h"
#include "srvssn.h"
#include "srvssn.h"
#include "srvnet.h"

#define INCLUDE_SRVOBJ_REMOTE_DIAGS 1
#define INCLUDE_SRVOBJ_REMOTE_DIAGS_THREAD 1

#if (INCLUDE_SRVOBJ_REMOTE_DIAGS)
#define REMOTE_DEBUG_TO_PROXY_PORTNUMBER 9988
#define REMOTE_DEBUG_FROM_PROXY_PORTNUMBER 9989
#endif

#ifdef __cplusplus
extern "C" {
#endif

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
