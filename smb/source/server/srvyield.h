#ifndef __SRVYIELD__
#define __SRVYIELD__
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#include "smbdefs.h"
#include "srvcfg.h"
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "srvyield.h"
#include "remotediags.h"
#include "srvoplocks.h"


yield_Cptr yield_c_new_yield_point(smb2_stream *pStream);
void yield_c_drop_yield_point(yield_Cptr p);
void yield_c_retain_yield_point(yield_Cptr p);


signalobject_Cptr yield_c_bind_signal(int i);

signalobject_Cptr yield_c_stream_to_signal_object(smb2_stream  *pStream);

RTP_SOCKET  yield_c_get_signal_sock(signalobject_Cptr);

void yield_c_signal_to_session(signalobject_Cptr);           // Send a wakeup
void yield_c_signal_to_stream(smb2_stream  *pStream);        // Send a wakeup when you know the srtream
void yield_c_recieve_signal(signalobject_Cptr);              // Consume a signals associates UDP message doesn't change signal state
int yield_c_recieve_blocked(signalobject_Cptr signal_object);          // Returns true if it was blocked (it may nw be signalled)
int yield_c_is_session_blocked(PSMB_SESSIONCTX pSctx);                 // Returns true if session is block and shouldn;t be in select list

void yield_c_set_signal(PSMB_SESSIONCTX pSctx);
int  yield_c_check_signal(PSMB_SESSIONCTX pSctx);
void yield_c_set_timeout(PSMB_SESSIONCTX pSctx);
void yield_c_clear_timeout(PSMB_SESSIONCTX pSctx);
int  yield_c_check_timeout(PSMB_SESSIONCTX pSctx);           // Returns true if timedout

void yield_c_push_stream_inpstate(smb2_stream *pStream);
void yield_c_pop_stream_inpstate(smb2_stream *pStream);
void yield_c_execute_yield(smb2_stream *pStream);
extern void yield_c_body_context(pSmb2SrvModel_Session pSession);
extern void yield_c_free_body_context(pSmb2SrvModel_Session pSession);

void yield_c_new_session(PNET_SESSIONCTX pNetCtx);

#define YIELD_BASE_PORTNUMBER   9999
#define YIELD_DEFAULT_DURATION 3000                 // for testing



#ifdef __cplusplus
}
#endif

#endif //  #ifndef __SRVYIELD__
