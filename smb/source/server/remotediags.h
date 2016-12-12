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
extern BBOOL srvobject_bind_diag_socket(void);
extern int srvobject_process_diag_request(void);
extern RTP_SOCKET *srvobject_get_diag_socket(void);
extern void srvobject_write_diag_socket(byte *p, int len);

typedef struct oplock_diagnotics_s {
    int   performing_replay;
    void  *yielded_pfid;
    void  *yielded_signal_object;
    dword session_replays;
    dword session_yields;
    dword session_wakeups;
    dword session_wake_signalled;
    dword session_sent_signals;
    dword session_sent_timeouts;
    dword session_wake_timedout;
    dword session_sent_breaks;
} oplock_diagnotics_t;

extern oplock_diagnotics_t oplock_diagnotics;
#define OPLOCK_DIAG_YIELD_SESSION_YIELD             {oplock_diagnotics.session_yields += 1;oplock_diagnotics.yielded_pfid=pfid;oplock_diagnotics.yielded_signal_object=pnCtx->pThread->signal_object;}
#define OPLOCK_DIAG_YIELD_SESSION_RUN               oplock_diagnotics.session_wakeups += 1;
#define OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_SIGNAL   oplock_diagnotics.session_wake_signalled += 1;
#define OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_TIMEOUT  oplock_diagnotics.session_wake_timedout += 1;
#define OPLOCK_DIAG_YIELD_SESSION_SEND_SIGNAL       oplock_diagnotics.session_sent_signals += 1;
#define OPLOCK_DIAG_YIELD_SESSION_SEND_TIMEOUT      oplock_diagnotics.session_sent_timeouts += 1;
#define OPLOCK_DIAG_SEND_BREAK                      oplock_diagnotics.session_sent_breaks += 1;
#define OPLOCK_DIAG_ENTER_REPLAY                    {oplock_diagnotics.performing_replay = 1;oplock_diagnotics.session_replays += 1;}
#define OPLOCK_DIAG_EXIT_REPLAY                     oplock_diagnotics.performing_replay = 0;

#define OPLOCK_DIAG_DO_SIGNAL_TIMEOUT_TEST          0
#define OPLOCK_DIAG_DO_SIGNAL_SETTING_TEST          0
#define OPLOCK_DIAG_DO_SIGNAL_REPLAY_TEST (OPLOCK_DIAG_DO_SIGNAL_TIMEOUT_TEST||OPLOCK_DIAG_DO_SIGNAL_SETTING_TEST)

// Called from one spot only
#define OPLOCK_DIAG_TEST_REPLAY                     {if (OPLOCK_DIAG_DO_SIGNAL_REPLAY_TEST&&!oplock_diagnotics.performing_replay) return oplock_c_create_yield;}

#define OPLOCK_DIAG_TEST_SEND_SIGNAL {if (OPLOCK_DIAG_DO_SIGNAL_SETTING_TEST&&!oplock_diagnotics.performing_replay&&oplock_diagnotics.yielded_pfid) { oplock_c_wake_waiting_fid(oplock_diagnotics.yielded_pfid, oplock_diagnotics.signal_object);})





#ifdef __cplusplus
}
#endif

#endif
