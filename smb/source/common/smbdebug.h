#ifndef __SMB_DEBUG_H__
#define __SMB_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "smbdefs.h"
#include "smbutil.h"

void _rtsmb_debug_output_str(void* msg, int type);
void _rtsmb_debug_output_int(long val);

#define DUMPBIN     0
#define DUMPASCII   1
#define DUMPUNICODE 2
extern void rtsmb_dump_bytes(char *prompt, void *pbytes, int length, int format);

//#define RTSMB_DEBUG_TYPE_ASCII       0
//#define RTSMB_DEBUG_TYPE_UNICODE     1
//#define RTSMB_DEBUG_TYPE_SYS_DEFINED 2

#ifndef RTSMB_DEBUG
#define RTSMB_DEBUG 1
#endif

#ifdef RTSMB_DEBUG
#ifndef RTP_DEBUG
#define RTP_DEBUG
#endif

#endif /* RTSMB_DEBUG */

#ifdef __cplusplus
}
#endif


#endif /* __SMB_DEBUG_H__ */
