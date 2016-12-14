#ifndef __SRV_NET_H__
#define __SRV_NET_H__


#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)
#ifdef __cplusplus
extern "C" {
#endif
#include "srvssn.h"

/*============================================================================   */
/*    INTERFACE STRUCTURES / UTILITY CLASSES                                     */
/*============================================================================   */
typedef struct net_sessionctxt
{
	int           heap_index;
	RTP_SOCKET    sock;
	unsigned long lastActivity;
	SMB_SESSIONCTX_T smbCtx;
    struct net_thread_s *pThread;   // The parent that cyckles between threads
} NET_SESSIONCTX_T;
typedef NET_SESSIONCTX_T RTSMB_FAR *PNET_SESSIONCTX;


typedef struct net_thread_s
{
	/**
	 * This list points to all the sessions this thread manages.
	 */
	PNET_SESSIONCTX *sessionList;
	dword numSessions;

	/**
	 * This indicates a session that we need to service, and
	 * no others.  Usually, that means it is holding on to data
	 * in the buffer that shouldn't be overwritten.
	 *
	 * A value of -1 means no session is blocking.
	 */
	int blocking_session;

	signalobject_Cptr signal_object;

	/**
	 * Index stores the index of the last session we serviced.
	 * This helps us avoid always servicing one session first.
	 */
	dword index;
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // These are shared if not using private session buffers
	/**
	 * These buffers hold the incoming data and the outgoing data for the current
	 * session being processed.
	 */
	byte *_inBuffer;        // 1 MB..
	byte *_outBuffer;       //
	byte *tmpBuffer;        // used for transactions 64 K
#endif
	/**
	 * This is FALSE if we have not yet initialized our random number
	 * generator, TRUE if we have.
	 */
	BBOOL srand_is_initialized;

} NET_THREAD_T;
typedef NET_THREAD_T RTSMB_FAR *PNET_THREAD;

/*============================================================================   */
/*    INTERFACE FUNCTION PROTOTYPES                                              */
/*============================================================================   */
void rtsmb_srv_net_init (void);
void rtsmb_srv_net_cycle (long timeout);
void rtsmb_srv_net_shutdown (void);
void rtsmb_srv_net_connection_close_session(PNET_SESSIONCTX pSCtx );
PNET_SESSIONCTX findSessionByContext (PSMB_SESSIONCTX pSctxt);
void SMBS_PointSmbBuffersAtNetThreadBuffers (PSMB_SESSIONCTX pCtx, PNET_THREAD pThread);

#if INCLUDE_RTSMB_DC
void rtsmb_srv_net_pdc_invalidate (void);
#endif


RTP_SOCKET rtsmb_srv_net_get_nbns_socket (void);
RTP_SOCKET rtsmb_srv_net_get_nbss_socket (void);

PFBYTE rtsmb_srv_net_get_last_remote_ip (void);
int rtsmb_srv_net_get_last_remote_port (void);

void rtsmb_srv_net_set_ip (PFBYTE host_ip, PFBYTE mask_ip);
PFBYTE rtsmb_srv_net_get_host_ip (void);
PFBYTE rtsmb_srv_net_get_broadcast_ip (void);

#endif /* INCLUDE_RTSMB_SERVER */

#ifdef __cplusplus
}
#endif

#endif /* __SRV_NET_H__ */
