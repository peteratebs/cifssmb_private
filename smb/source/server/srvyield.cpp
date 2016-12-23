#include "srvcfg.h"
#include "srvssn.h"
#include "rtpstr.h"
#include "rtptime.h"
#include "rtpmem.h"
#include "srv_smb2_model.h"
#include "com_smb2_ssn.h"
#include "srvutil.h"
#include "remotediags.h"
#include "srvoplocks.h"
#include "srvyield.h"
#include "rtpnet.h"
#include "smbnet.h"
#include "srvsmbssn.h"

#warning duplicate define
#define CFG_RTSMB_MAX_SESSIONS              8

static int yield_manager_c_current_yield_socketnumber;
static const byte local_ip_address[] = {0x7f,0,0,1};
static const byte local_ip_mask[] = {0xff,0,0,0};


class yield_manager_c {
  public:
     yield_manager_c(void) {
       yield_manager_c_current_yield_socketnumber = YIELD_BASE_PORTNUMBER;
     }
     ~yield_manager_c() {};
     int get_next_socket_number() {return yield_manager_c_current_yield_socketnumber++;};
//    private:
};

class yield_manager_c yield_manager;

class yield_signal_c {
public:
  yield_signal_c(void) {
   _yield_socket_portnumber=-1;
   signal_set_count=0;
   signal_rcv_count=0;
  };
  ~yield_signal_c(void) {_yield_socket_portnumber=-1;signal_set_count=0;signal_rcv_count=0;};
  class yield_signal_c * bind_signal(void);
  RTP_SOCKET yield_sock(void) {return _yield_socket;};
  int yield_sock_portnumber(void) {return _yield_socket_portnumber;};
  void send_signal(void) {
      signal_set_count += 1;
      rtsmb_net_write_datagram ( _yield_socket, (byte *)local_ip_address, _yield_socket_portnumber, (void *)"SIG", 4);  // Four is the minimum size might as well send something
  };
  int check_signal_count(void) {  return (signal_rcv_count<signal_set_count); };
  void clear_signal_count(void) { signal_rcv_count=signal_set_count=0;}
  void recieve_signal(void)
  {
    byte remote_ip[4];
    byte messagebuffer[5];
    int  size, remote_port;
    size = rtsmb_net_read_datagram (_yield_socket, messagebuffer, 4, remote_ip, &remote_port);
    messagebuffer[4]=0;
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: yield_c_recieve_signal recved %s\n", (char *)messagebuffer);
  }
private:
 RTP_SOCKET  _yield_socket;
 int _yield_socket_portnumber;
 uint32_t signal_set_count;
 uint32_t signal_rcv_count;
};

class yield_signal_c * yield_signal_c::bind_signal(void)
{
  _yield_socket_portnumber = yield_manager.get_next_socket_number();
  int r = rtsmb_net_socket_new (&this->_yield_socket, _yield_socket_portnumber, FALSE);
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: new sig sock sock:%d r:%d\n", _yield_socket_portnumber, r);
  return this;
}
class yield_signal_c yield_signals[CFG_RTSMB_MAX_SESSIONS];

// Called at initialization time
signalobject_Cptr yield_c_bind_signal(int i)
{
  return yield_signals[i].bind_signal();
}
void yield_c_recieve_signal(signalobject_Cptr signal_object)
{
  class yield_signal_c *p  = (class yield_signal_c *) signal_object;
  p->recieve_signal();
}

void yield_c_signal_to_session(signalobject_Cptr signal_object)
{
  class yield_signal_c *p  = (class yield_signal_c *) signal_object;
  p->send_signal();
}
RTP_SOCKET  yield_c_get_signal_sock(signalobject_Cptr signal_object)
{
  class yield_signal_c *p  = (class yield_signal_c *) signal_object;
  return p->yield_sock();

}
void yield_c_new_session(PNET_SESSIONCTX pNetCtx)
{
// Initialize state variable for a new connection
//void RtsmbYieldNetSessionInit(PNET_SESSIONCTX pNetCtx)
}

#define YIELDSIGNALLED         0x01   /* if a yielded event was signaled */

// BBOOL RtsmbYieldCheckSignalled(PSMB_SESSIONCTX pSctx)
int yield_c_check_signal(PSMB_SESSIONCTX pSctx)
{
  int r = ((pSctx->_yieldFlags & YIELDSIGNALLED)!=0);
  pSctx->_yieldFlags &=~YIELDSIGNALLED;
  return r;
}

void yield_c_set_signal(PSMB_SESSIONCTX pSctx)
{
  pSctx->_yieldFlags |= YIELDSIGNALLED;
}

int  yield_c_check_timeout(PSMB_SESSIONCTX pSctx)
{
  return (rtp_get_system_msec() > pSctx->_yieldTimeout);

}
void yield_c_clear_timeout(PSMB_SESSIONCTX pSctx)
{
    pSctx->_yieldTimeout = 0;

}

int yield_c_recieve_blocked(signalobject_Cptr signal_object)
{
  class yield_signal_c *p  = (class yield_signal_c *) signal_object;
  return p->check_signal_count();
}

int yield_c_is_session_blocked(PSMB_SESSIONCTX pSctx)
{
  return pSctx->_yieldTimeout != 0;
}


signalobject_Cptr yield_c_stream_to_signal_object(smb2_stream  *pStream)
{
  PNET_SESSIONCTX pNctxt = SMBS_findSessionByContext(pStream->pSmbCtx);
  if (pNctxt)
  {
    return (pNctxt->netsessiont_pThread->signal_object);
  }
  return 0;
}



// void RtsmbYieldSendSignalSocket(smb2_stream  *pStream)
void yield_c_signal_to_stream(smb2_stream  *pStream)
{
  PNET_SESSIONCTX pNctxt = SMBS_findSessionByContext(pStream->pSmbCtx);
  if (pNctxt)
  {
    yield_c_signal_to_session(pNctxt->netsessiont_pThread->signal_object);
  }
}



void yield_c_set_timeout(PSMB_SESSIONCTX pSctx)
{
 pSctx->_yieldTimeout = YIELD_DEFAULT_DURATION;

}
