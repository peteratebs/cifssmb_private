 /*
 | RTPDEBUG.H - Runtime Platform Debug Services
 |
 |   UNIVERSAL CODE - DO NOT CHANGE
 |
 | EBS - RT-Platform
 |
 |  $Author: vmalaiya $
 |  $Date: 2006/07/17 15:29:00 $
 |  $Name:  $
 |  $Revision: 1.3 $
 |
 | Copyright EBS Inc. , 2006
 | All rights reserved.
 | This code may not be redistributed in source or linkable object form
 | without the consent of its author.
 |
 | Module description:
 |  [tbd]
*/

#ifndef __RTPDEBUG_H__
#define __RTPDEBUG_H__

#include "rtp.h"
#include <stdarg.h>

/************************************************************************
 * If RTP_DEBUG is defined, the debug implementaion of the macro        *
 * will be implemented.  This provides debug information otherwise not  *
 * available.                                                           *
 ************************************************************************/

/* Uncomment the below code to enable debug information **/
#ifndef RTP_DEBUG
// #define RTP_DEBUG 1
#endif

/************************************************************************
 * Debug System API
 ************************************************************************/

/************************************************************************
 * Debug System API which should be
 * used via the macros indicated below.
 ************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

void _rtp_debug_output_str (
	char* msg,
	const char *file,
	long line_num
	);
void _rtp_debug_output_errno (
	char* msg,
	const char *file,
	long line_num
	);
void _rtp_debug_output_neterrno (
	char* msg,
	long err,
	const char *file,
	long line_num
	);
void _rtp_debug_output_int (
	long val
	);
void _rtp_debug_syslog_printf(int dbg_lvl, char *fmt, ...);
void _rtp_debug_syslog_open(char *name, unsigned long level_mask);
typedef int (*rtpsyslogFilterType)(char *str_buffer);
void _rtp_debug_syslog_filter(rtpsyslogFilterType pfilter);
#define SYSLOG_TRACE_LVL  1
#define SYSLOG_INFO_LVL   2
#define SYSLOG_ERROR_LVL   4


#ifdef __cplusplus
}
#endif

// Syslog is available in DEBUG or non DEBUG
#define RTP_DEBUG_OPEN_SYSLOG  _rtp_debug_syslog_open
#define RTP_DEBUG_OUTPUT_SYSLOG  _rtp_debug_syslog_printf
#define RTP_DEBUG_FILTER_SYSLOG  _rtp_debug_syslog_filter


#ifdef RTP_DEBUG
#define RTP_DEBUG_OUTPUT_NETERRNO(msg,err) _rtp_debug_output_neterrno(msg,err,__FILE__, __LINE__)
#define RTP_DEBUG_OUTPUT_ERRNO(msg) _rtp_debug_output_errno(msg, __FILE__, __LINE__)
#define RTP_DEBUG_OUTPUT_STR(msg)  _rtp_debug_output_str(msg, __FILE__, __LINE__)
#define RTP_DEBUG_OUTPUT_INT(val)  _rtp_debug_output_int(val)
/* variable arguements in macros are not supported by all compilers..MSVC started supporting with 2005 */
#else
#define RTP_DEBUG_OUTPUT_NETERRNO(msg,err)
#define RTP_DEBUG_OUTPUT_ERRNO(msg)
#define RTP_DEBUG_OUTPUT_STR(msg)
#define RTP_DEBUG_OUTPUT_INT(msg)
#endif /* RTP_DEBUG */


#endif /* __RTPDEBUG_H__ */

/* ----------------------------------- */
/*             END OF FILE             */
/* ----------------------------------- */
