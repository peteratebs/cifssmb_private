/*                                                                        */
/* SRVSMBSSNOO.CPP -                                                      */
/*                                                                        */
/* EBSnet - RTSMB                                                         */
/*                                                                        */
/* Copyright EBS Inc. , 2016                                             */
/* All rights reserved.                                                   */
/* This code may not be redistributed in source or linkable object form   */
/* without the consent of its author.                                     */
/*                                                                        */
/* Module description:                                                    */
/* 888888888888888888888888888888888888888888888888888888888888888888888888888888
  _net_session_list_c        - A list/queue mechanism for sorting and managing sessions
                                Methods
                                  empty_list()
                                  zero_enumerator()
                                  get_next_session
                                  add_session_to_list()
                                  remove_session_from_list()

  _net_thread_signal_c       - Manages select, spawns new sessions, queuses activated sessions by state and note receipt of internal smb signals
                                Methods
                                  net_thread_signal_initialize()
                                  net_thread_signal_select()
                                  send_signal()
                                  recv_signal()
                                  get_master_socket()
                                  get_signalling_socket()
                                  check_master_socket_signal()
                                  check_signalling_socket_signal()
                                  add_to_active_sessions()
                                  remove_from_active_sessions()
                                  add_to_establishing_sessions()
                                  clear_session_list_for_select()
                                  get_free_session()
                                  get_next_activesession()
                                  get_next_active_estabished_session()
                                  get_next_active_estabishing_session()
                                  socket_to_session()


  net_thread_c               - Provides external API perform_session_cycle() to invoke _net_thread_signal_c, then processes
                                 Dispatches control to sessions that own the sockets and signals with activity
                                  process_establishing_session(void);
                                  process_established_session(void);
                                  process_yielded_session(void);
                                  process_closing_session(void);
                                  process_dead_session(void);
  smbs_session_c             - Manages individual sessions
                                 Implement states in sessions that own the sockets and signals with activity
                                  process_establishing_session(void);
                                  process_established_session(void);
                                  process_yielded_session(void);
                                  process_closing_session(void);
                                  process_dead_session(void);
888888888888888888888888888888888888888888888888888888888888888888888888888888 */

#warning duplicate define
#define CFG_RTSMB_MAX_SESSIONS              8

#pragma GCC diagnostic ignored "-Wwrite-strings"


#include "smbdefs.h"

#include "rtpfile.h"
#include "rtprand.h"
#include "rtpwcs.h"
#include "smbdebug.h"
#include "rtpscnv.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvtran2.h"
#include "srvssn.h"
#include "srvrap.h"
#include "srvshare.h"
#include "srvrsrcs.h"
#include "srvfio.h"
#include "srvassrt.h"
#include "srvauth.h"
#include "srvutil.h"
#include "smbnb.h"
#include "srvnbns.h"
#include "srvans.h"
#include "srvcmds.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "srvcfg.h"
#include "smbnet.h"
#include "smbspnego.h"
#include "rtpmem.h"

#include "rtptime.h"

#include "srvsmbssn.h"
#include "srvnbns.h"
#include "srvyield.h"





static void srvsmboo_remember_session_socket(RTP_SOCKET  sock);
static void srvsmboo_remember_established_socket(RTP_SOCKET  sock);

EXTERN_C void rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive);
EXTERN_C void srvsmboo_panic(char *panic_string);
EXTERN_C void Smb2SrvModel_New_Session(struct smb_sessionCtx_s *pSmbCtx);
EXTERN_C void Smb2SrvModel_Free_Session(pSmb2SrvModel_Session pSession);
EXTERN_C void rtsmb_srv_browse_finish_server_enum (PSMB_SESSIONCTX pCtx);


#define PACK_ATTRIBUTE  __attribute__((packed))

typedef struct rtsmbSigStruct_s {
  word signame;
  word payloadsize;
// Payload
}  PACK_ATTRIBUTE rtsmbSigStruct;

typedef struct rtsmbSigOplockStruct_s {
  word signame;
  word payloadsize;
  dword inodenumber;
}  PACK_ATTRIBUTE rtsmbSigOplockStruct;

#define SMBS_SIGOPLOCK_NAME 0
#define SMBS_SIGOPLOCK_SIZE 4
#define SMBS_SIGOPLOCK(INODENUMBER) rtsmbSigOplockStruct = {SMBS_SIGOPLOCK_NAME,SMBS_SIGOPLOCK_SIZE,INODENUMBER};
#define SMBS_SIGONOTIFY_NAME 0
#define SMBS_SIGONOTIFY_SIZE 4
#define SMBS_SIGNOTIFY(INODENUMBER) rtsmbSigNotifyStruct = {SMBS_SIGONOTIFY_NAME,SMBS_SIGONOTIFY_SIZE,INODENUMBER};

typedef enum {listening,establishing,established,yielded, closing, dead,} smbs_session_session_state_e;


// list structure for segregating to sessions by the state they are in sessions with empty, zero, add_to, get_next, remove_from
class _net_session_list_c {
public:
  _net_session_list_c(void)          { empty_list(); }
  ~_net_session_list_c(void)         {};
  void empty_list(void)             { list_size = 0; next_return_index = 0;};
  void zero_enumerator (void)       { next_return_index = 0;};
  class smbs_session_c  * get_next_session(void) {
   return (next_return_index < list_size)?session_list[next_return_index++]:0;
  };
  void add_session_to_list(class smbs_session_c  *pSession) { if (pSession) session_list[list_size++]=pSession;};
  void remove_session_from_list(class smbs_session_c  *pSession)
  {
    for (int i=0;i<list_size;i++)
    {
      if (session_list[i]==pSession) {
        for (int j=i;j<list_size;j++) session_list[j]= session_list[j+1]; // Runs off the end
        list_size -= 1;
        if (list_size && (next_return_index >= list_size || session_list[next_return_index]==0)) // Messy, fix the qeueu logic
        {
           next_return_index = 0;
           for (int i=0;i<list_size;i++) if (session_list[i]) {next_return_index = i; break;}
        }
        if (list_size && session_list[next_return_index]==0) // Messy, fix the qeueu logic
        {
#warning Need panic strategy
            srvsmboo_panic("Session freelist error");
        }
        break;
      }
    }
  }
private:
  int list_size;
  int next_return_index;
  class smbs_session_c  *session_list[CFG_RTSMB_MAX_SESSIONS];
};


// Cheating now using active_either_session_list for all sessions, others are zeroed,

static _net_session_list_c active_either_session_list; // temp

class _net_thread_signal_c {
public:
  _net_thread_signal_c(void)  {};
  ~_net_thread_signal_c(void) {};
  int  net_thread_signal_initialize(class net_thread_c *net_thread_iam_partof);   // done
  int  net_thread_signal_select(int timeout);                               // done
  void send_signal(rtsmbSigStruct *psig);                                   // done
  rtsmbSigStruct *recv_signal(void);                                        // done

  RTP_SOCKET  get_master_socket(void)     { return master_socket;};
  RTP_SOCKET  get_signalling_socket(void) { return signal_socket;};                                      // done

  int  check_master_socket_signal(void)     { int r=master_signal_active;master_signal_active=0;return r;};
  int  check_signalling_socket_signal(void) { int r=signalling_signal_active; signalling_signal_active=0; return r;};                                      // done

  void add_to_active_sessions(class smbs_session_c  *new_session) {active_session_list.add_session_to_list(new_session);active_either_session_list.add_session_to_list(new_session);};
  void remove_from_active_sessions(class smbs_session_c  *del_session)
  {
    active_session_list.remove_session_from_list(del_session);
    active_either_session_list.remove_session_from_list(del_session);
    free_session_list.add_session_to_list(del_session);
  };
  void add_to_establishing_sessions(class smbs_session_c  *new_session)  {active_establishing_session_list.add_session_to_list(new_session);};

  void clear_session_list_for_select(void)
  { // Clear dispatch queues prior to a select.
    active_either_session_list.empty_list();
    active_establishing_session_list.empty_list();
    active_established_session_list.empty_list();
    closing_session_list.empty_list();
    dead_session_list.empty_list();
  }

  class smbs_session_c  * get_free_session(void) {
     class smbs_session_c  *pSession= free_session_list.get_next_session();


     if (pSession) free_session_list.remove_session_from_list(pSession);
     return pSession;
  }
  class smbs_session_c  * get_next_activesession(void);
  class smbs_session_c  * get_next_active_estabished_session()    { /* return */ active_established_session_list.get_next_session(); active_either_session_list.get_next_session(); };
  class smbs_session_c  * get_next_active_estabishing_session()   { /* return  */ active_establishing_session_list.get_next_session(); return 0; };
  class smbs_session_c  * socket_to_session(RTP_SOCKET sock);



private:
#define MASTER_SOCKET_INDEX 0
#define SIGNAL_SOCKET_INDEX  1
#define FIRST_SESSION_SOCKET_INDEX  2
  RTP_SOCKET  master_socket;
  RTP_SOCKET  nameserver_socket;
  RTP_SOCKET  signal_socket;   int         signal_socket_portnumber;


  int signalling_signal_active;
  int master_signal_active;

  int session_socket_list_size;
  RTP_SOCKET  session_socket_list[CFG_RTSMB_MAX_SESSIONS];

  _net_session_list_c free_session_list;

  _net_session_list_c active_session_list;                      // All sessions that can handle network input now


  _net_session_list_c active_establishing_session_list;

  _net_session_list_c active_established_session_list;

  _net_session_list_c yielded_session_list;

  _net_session_list_c closing_session_list;

  _net_session_list_c dead_session_list;


};


class net_thread_c : private _net_thread_signal_c {
public:
  net_thread_c(void)  {};
  ~net_thread_c(void) {};
  int net_thread_initialize(PNET_THREAD tempThread);                                          // done
  class smbs_session_c  *thread_socket_to_session(RTP_SOCKET sock) { return socket_to_session(sock);};
  void perform_session_cycle(int timeout);                                         //
  void remove_from_active_sessions(class smbs_session_c  *del_session) { _net_thread_signal_c:: remove_from_active_sessions(del_session);};
  void process_established_session(void);
  void process_establishing_session(void);
  void process_yielded_session(void);
  void process_closing_session(void);
  void process_dead_session(void);
  void send_signal(rtsmbSigStruct *psig)
    {_net_thread_signal_c::send_signal(psig);};                             // done
  PNET_THREAD pThread;       // Pointer to the old c thread context
//private:
};

class smbs_session_c  {
public:
  smbs_session_c(void);
  ~smbs_session_c(void);                                                    // done
  RTP_SOCKET get_session_socket(void) { return session_socket;};
  void set_session_socket(RTP_SOCKET _session_socket) { session_socket=_session_socket;};
  void session_init(class net_thread_c *parent_net_thread);
  void set_session_state(smbs_session_session_state_e s) { current_session_state=s; };
  smbs_session_session_state_e get_session_state(void)   { return current_session_state; };
  void process_established_session(void);
  void process_establishing_session(void);
  void process_yielded_session(void);
  void process_closing_session(void);
  void process_dead_session(void);
  void send_signal(rtsmbSigStruct *psig)
    {parent_net_thread->send_signal(psig);};                                // done

private:
 class net_thread_c *parent_net_thread;
 RTP_SOCKET  session_socket;

 smbs_session_session_state_e current_session_state;

};
static class smbs_session_c  all_sessions[CFG_RTSMB_MAX_SESSIONS];




static int   current_net_thread_signal_socketnumber = YIELD_BASE_PORTNUMBER;
static const byte local_ip_address[] = {0x7f,0,0,1};
static const byte local_ip_mask[] = {0xff,0,0,0};
// Initialises the UDP signaling thread, also initializes and puts the master socket on the listen list.
int  _net_thread_signal_c::net_thread_signal_initialize(class net_thread_c *net_thread_iam_partof)
{
  signal_socket_portnumber = current_net_thread_signal_socketnumber++;
  if (rtsmb_net_socket_new (&signal_socket, signal_socket_portnumber, FALSE) < 0)
    return -1; // YIKES

    /* -------------------- */
    /* get the three major sockets */
    /* Name Service Datagram Socket */
    if (rtsmb_net_socket_new (&nameserver_socket, rtsmb_nbns_port, FALSE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"Could not allocate Name & Datagram service socket\n");
    }
    if (rtp_net_setbroadcast((RTP_SOCKET) nameserver_socket, 1) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Error occurred while trying to set broadcast on Name & Datagram service socket\n");
    }

    /* SSN Reliable Socket */
    if (rtsmb_net_socket_new (&master_socket, rtsmb_nbss_direct_port, TRUE) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Master Socket allocation failed Name & Datagram service socket\n");
        return -1; // not good
    }
    if (rtp_net_listen (master_socket, prtsmb_srv_ctx->max_sessions) != 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Error occurred while trying to listen on SSN Reliable socket.\n");
        return -1; // not good
    }
    // Create sessions in the listening state
    for (int i=0; i <  prtsmb_srv_ctx->max_sessions; i++)
    {
      all_sessions[i].session_init(net_thread_iam_partof);
      all_sessions[i].set_session_state(listening);
      free_session_list.add_session_to_list(&all_sessions[i]);
    }

    return 0;
}

// Performs a select on the signal, listening and active session sockets,
// and returns the number of active sockets, or 0, -1
//  sets socket_signal_active and master_signal_active if a signal was sent or a listen was granted
//   Puts estabished sessions with incomming traffic on active_established_session_list
//   Puts estabishing sessions with incomming traffic on active_establishing_session_list
int _net_thread_signal_c::net_thread_signal_select(int timeout)
{
    int read_list_size=0;


    RTP_SOCKET  read_return_list[CFG_RTSMB_MAX_SESSIONS+FIRST_SESSION_SOCKET_INDEX];
    read_return_list[SIGNAL_SOCKET_INDEX] = signal_socket;
    read_return_list[MASTER_SOCKET_INDEX] = master_socket;
    read_list_size = 2;

    clear_session_list_for_select();
    active_session_list.zero_enumerator();
    class smbs_session_c  *pSession;
    do {
     pSession = active_session_list.get_next_session();
     if (pSession)
       read_return_list[read_list_size++] = pSession->get_session_socket();
    } while (pSession);

    int len = rtsmb_netport_select_n_for_read (read_return_list, read_list_size, timeout);
    int active_list_size = len>=0?len:0;
    master_signal_active =
    signalling_signal_active = 0;
    if (active_list_size)
    {
      for (int socket_index = 0; socket_index<active_list_size;socket_index++)
      {
        if (read_return_list[socket_index] == master_socket)
        {
          master_signal_active = 1;
        }
        else if (read_return_list[socket_index] == signal_socket)
        {
          signalling_signal_active = 1;
        }
        else
        {
          class smbs_session_c *pSession = socket_to_session(read_return_list[socket_index]);
          // save it away
          if (pSession) active_either_session_list.add_session_to_list(pSession);
          if (pSession && pSession->get_session_state() == established)
           active_established_session_list.add_session_to_list(pSession);
          else if (pSession && pSession->get_session_state() == establishing)
           active_establishing_session_list.add_session_to_list(pSession);
        }
      }
    }
}

// Sends an rtsmbSigStruct message to the session
void _net_thread_signal_c::send_signal(rtsmbSigStruct *psig)
{
    rtsmb_net_write_datagram ( signal_socket, (byte *)local_ip_address, signal_socket_portnumber, (void *)psig, psig->payloadsize);
}

// Returns a rtsmbSigStruct if one is pending (should be because select was called) on the UDP port else null
rtsmbSigStruct * _net_thread_signal_c::recv_signal(void)
{
static rtsmbSigStruct return_sig;
  byte remote_ip[4];
  int  size, remote_port;
  size = rtsmb_net_read_datagram (signal_socket, &return_sig, sizeof(return_sig), remote_ip, &remote_port);
  if (size == sizeof(return_sig))  {  return &return_sig;   }
    else if (size != 0) { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: _net_thread_signal_c recved invalid message size %d\n", size);}
  return 0;
}

class smbs_session_c  * _net_thread_signal_c::socket_to_session(RTP_SOCKET sock)
{
  class smbs_session_c  *pSession;
  active_session_list.zero_enumerator();
  do {
     pSession = active_session_list.get_next_session();
     if (pSession && pSession->get_session_socket() == sock)
      return pSession;
  } while (pSession);
  return 0;
};



void net_thread_c::perform_session_cycle(int timeout)
{
  int  active_signal_count = net_thread_signal_select(timeout);
  if (active_signal_count > 0)
  {
    // Process establishedsessions as requested
    int stay_in_session = 0;
    do
    {
      stay_in_session = 0;
      smbs_session_c  *psession;
      // Cheating for now and returning all
      psession = get_next_active_estabished_session();
      if (psession)
      {
        stay_in_session = 1;
        psession->process_established_session();
      }
    } while(stay_in_session);
    int stay_in_signals;
    do
    {
      stay_in_signals = 0;
      // Establish new sessions as requested
      if (check_master_socket_signal())
      {
        stay_in_signals = 1;
        RTP_SOCKET      sock;
        unsigned char clientAddr[4]; int clientPort; int ipVersion;
        if (rtp_net_accept ((RTP_SOCKET *) &sock,(RTP_SOCKET) get_master_socket(), clientAddr, &clientPort, &ipVersion) < 0)
        {  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, (char *) "net_thread_c::perform_session_cycle: accept error\n");  }
        else
        {
          smbs_session_c  *new_session = get_free_session();
          if (new_session)
          { // Set the socket number, set the state to establishing
            // See RTSMB_STATIC PNET_SESSIONCTX rtsmb_srv_netssn_connection_open (PNET_THREAD pThread) if we need more
            srvsmboo_remember_session_socket(sock);
            new_session->set_session_socket(sock);
            new_session->set_session_state(establishing);
            // Add it to the active(fed to seleect) and establishing sessions lists
            add_to_active_sessions(new_session);
            add_to_establishing_sessions(new_session);
          }
          else
          {
             RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "perform_session_cycle:  No free sessions\n");
             /* let them know we are rejecting their request */
             rtsmb_srv_nbss_send_session_response (sock, FALSE);
             rtp_net_closesocket(sock);
          }
        }
      }
      if (check_signalling_socket_signal())
      {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, (char *) "net_thread_c::perform_session_cycle: signal ? not expected\n");
        stay_in_signals = 1;
        rtsmbSigStruct *recvSig = recv_signal(); // Must copy to use
      }
    } while(stay_in_signals);
  }
}


int net_thread_c::net_thread_initialize(PNET_THREAD tempThread)
{
  // Open the udp signaling port, make sure it's flushed out
  // Also opens the master port and establishes those positions in the select read list
  int r = net_thread_signal_initialize(this);
  pThread = tempThread;                                                     // Remember a pointer to the C thread
  if (r < 0) return r; // not good
  return r;
};


void net_thread_c::process_established_session(void)
{
}

void net_thread_c::process_establishing_session(void)
{
}

void net_thread_c::process_yielded_session(void)
{
}

void net_thread_c::process_closing_session(void)
{
}

void net_thread_c::process_dead_session(void)
{

}

smbs_session_c::smbs_session_c(void) {}
smbs_session_c::~smbs_session_c(void){}
void smbs_session_c::session_init(class net_thread_c *_parent_net_thread)
{
  parent_net_thread=_parent_net_thread;
  current_session_state=listening;
}
void smbs_session_c::process_established_session(void)
{
  srvsmboo_remember_established_socket(get_session_socket());
}

void smbs_session_c::process_establishing_session(void) {}
void smbs_session_c::process_yielded_session(void) {}
void smbs_session_c::process_closing_session(void) {}
void smbs_session_c::process_dead_session(void) {}


class net_thread_c master_thread;
static RTP_SOCKET remembered_established_sockets[8];
static int remembered_established_socket_count;
static RTP_SOCKET remembered_socket;

void srvsmboo_init(PNET_THREAD pThread)
{
  master_thread.net_thread_initialize(pThread);
}
void srvsmboo_cycle(int timeout)
{
  remembered_established_socket_count = 0;
  master_thread.perform_session_cycle(timeout);
}


static void srvsmboo_remember_session_socket(RTP_SOCKET  sock)
{
  remembered_socket=sock;
}

static void srvsmboo_remember_established_socket(RTP_SOCKET  sock)
{
  remembered_established_sockets[remembered_established_socket_count++]=sock;
}
int srvsmboo_get_session_read_list(RTP_SOCKET *readList)
{
int readListSize=0;
   for (int i=0; i < remembered_established_socket_count; i++)
      readList[readListSize++] = remembered_established_sockets[i];
  remembered_established_socket_count = 0;
  return readListSize;
}


//extern BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock);
static BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock);

void srvsmboo_check_for_new_sessions(void)
{
  RTP_SOCKET sock = remembered_socket;
  remembered_socket = 0;
  if (sock)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"srvsmboo_get_new_session_socket: returned %lu", sock);
    if (!rtsmb_srv_netssn_thread_new_session(prtsmb_srv_ctx->mainThread,sock))
    {
      srvsmboo_panic("oo and non oo sessions out of sync");
    }
  }
}


void srvsmboo_close_session(RTP_SOCKET sock)
{
class smbs_session_c *pSession = master_thread.thread_socket_to_session(sock);
  if (pSession)
  {
    pSession->set_session_state(listening);
    master_thread.remove_from_active_sessions(pSession);
  }
}


void srvsmboo_close_socket(RTP_SOCKET sock)
{
  /* kill conection */
  if (rtp_net_closesocket(sock))
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_srv_netssn_connection_close: Error in closesocket\n");
  }
}

void srvsmboo_netssn_shutdown(void)
{
#warning implement
}
EXTERN_C void srvsmboo_panic(char *panic_string)
{
#warning Need panic strategy
   rtp_printf("\nPanic abort called: \n");
   rtp_printf("panic: %s \r",panic_string);
   int iCrash = 13 / 0;      // trap to the debugger
}



/*
================
 This function intializes the session context portions that are shared by SMBV1 and SMBV2.

    @pSmbCtx: This is the session context to initialize.
    @sock: This is the sock we are connected to.

    return: Nothing.
================
*/
static void SMBS_InitSessionCtx (PSMB_SESSIONCTX pSmbCtx, RTP_SOCKET sock)
{

    pSmbCtx->sock = sock;
    pSmbCtx->dialect = DIALECT_NONE;
    pSmbCtx->isSMB2 = FALSE;

    pSmbCtx->accessMode = Auth_GetMode ();

#ifdef SUPPORT_SMB2
    SMBS_Setsession_state(pSmbCtx, NOTCONNECTED);
#else  /* SUPPORT_SMB2 */
    SMBS_Setsession_state(pSmbCtx, IDLE);
    /* Initialize uids, tid, and fid buckets for the new session if it's version 2 also initialize v2 context block in pSmbCtx Sets pSctx->isSMB2 = FALSE*/
    SMBS_InitSessionCtx_smb(pSmbCtx,1);
#endif
    /**
     * See srvssn.h for a more detailed description of what these do.
     */
    pSmbCtx->writeRawInfo.amWritingRaw = FALSE;

/*  pSmbCtx->num = num++;  */
}


/**
 * Allocates space for a new session, if available; else
 */

static PNET_SESSIONCTX allocateSession (void)
{
	word i;
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;

	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (!prtsmb_srv_ctx->sessionsInUse[i])
		{
			prtsmb_srv_ctx->sessionsInUse[i] = 1;
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();

	return rv;
}

static BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock)
{
    //PNET_SESSIONCTX pSCtx = rtsmb_srv_netssn_connection_open (pMaster, sock);
    // RTSMB_STATIC PNET_SESSIONCTX rtsmb_srv_netssn_connection_open (PNET_THREAD pThread, RTP_SOCKET  sock)
    PNET_SESSIONCTX pCtx;


    pCtx = allocateSession();
    if(pCtx)
    {
        pCtx->netsessiont_sock = sock;
        yield_c_new_session(pCtx);

        pCtx->netsessiont_lastActivity = rtp_get_system_msec ();
        SMBS_InitSessionCtx(&(pCtx->netsessiont_smbCtx), pCtx->netsessiont_sock);
//        SMBS_PointSmbBuffersAtNetThreadBuffers (&pNetCtx->netsessiont_smbCtx, pThread);
        PSMB_SESSIONCTX pSCtx = &pCtx->netsessiont_smbCtx;

        int session_index = SMBU_SessionToIndex(pSCtx);
        pSCtx->readBuffer              = prtsmb_srv_ctx->unshared_read_buffers [session_index];
        pSCtx->smallReadBuffer         = prtsmb_srv_ctx->unshared_read_buffers [session_index];
        pSCtx->smallWriteBuffer        = prtsmb_srv_ctx->unshared_write_buffers[session_index];
        pSCtx->writeBuffer             = prtsmb_srv_ctx->unshared_write_buffers[session_index];
        pSCtx->tmpBuffer               = prtsmb_srv_ctx->unshared_temp_buffers [session_index];
        pSCtx->readBufferSize          = prtsmb_srv_ctx->out_buffer_size; // They are the same
        pSCtx->writeBufferSize         = prtsmb_srv_ctx->out_buffer_size;
        pSCtx->tmpSize                 = prtsmb_srv_ctx->temp_buffer_size;

        /**
         * Add new session to our list.
         */
        pMaster->sessionList[pMaster->numSessions] = pCtx;
        pMaster->numSessions++;
        return TRUE;
    }
    else
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "rtsmb_srv_netssn_connection_open:  No free sessions\n");
        rtsmb_srv_nbss_send_session_response (sock, FALSE);
        return FALSE;
    }
}

/*
================
 This function intializes the session SMB context portions for SMBV1 and V2.

 This is performed when the server state goes from NOTCONNECTED to IDLE after accepting it's fir bytes and identifying smbv1

    @pSmbCtx: This is the session context to initialize.

    return: Nothing.
================
*/
/* Initialize uids, tid, and fid buckets for the new session if it's version 2 also initialize v2 context block in pSmbCtx */
void SMBS_InitSessionCtx_smb(PSMB_SESSIONCTX pSmbCtx, int protocol_version)
{
    word i;

    /**
     * Outsource our user initialization.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
    {
        SMBS_User_Init  (&pSmbCtx->uids[i]);
        pSmbCtx->uids[i].inUse = FALSE;
    }

    /**
     * Outsource our tree initialization.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
    {
        SMBS_Tree_Init (&pSmbCtx->trees[i]);
        pSmbCtx->trees[i].inUse = FALSE;
    }

    /**
     * Clear fids.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_fids_per_session; i++)
    {
        pSmbCtx->fids[i].internal_fid = -1;
    }

    pSmbCtx->isSMB2 =  (protocol_version == 2);
    if (pSmbCtx->isSMB2)
    {
        /* Allocate the smb2 session stuff it is embedded in pSmbCtx so it can't fail */
        Smb2SrvModel_New_Session(pSmbCtx);
    }

}


/*
================
This function frees resources held by an SMB session context.

    @pSmbCtx: This is the session context to free.

    return: Nothing.
================
*/
void SMBS_CloseSession(PSMB_SESSIONCTX pSmbCtx)
{
    word i;

    srvsmboo_close_session((RTP_SOCKET) pSmbCtx->sock);

    /**
     * Only data worth freeing is in user data and trees.
     */
    for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
        if (pSmbCtx->uids[i].inUse)
            SMBS_User_Shutdown (pSmbCtx, &pSmbCtx->uids[i]);

    for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
        if (pSmbCtx->trees[i].inUse)
            SMBS_Tree_Shutdown (pSmbCtx, &pSmbCtx->trees[i]);
    // Revert to smbv1 defaults
    pSmbCtx->readBufferSize   = prtsmb_srv_ctx->out_buffer_size;
    pSmbCtx->writeBufferSize  = prtsmb_srv_ctx->out_buffer_size;
    pSmbCtx->protocol_version = 1;
}


/*
==============

==============
*/
RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions);

void SMBS_srv_netssn_init (void)      // called once from rtsmb_srv_init or rtsmb_srv_enable
{
RTSMB_STATIC PNET_THREAD tempThread;
//void srvsmboo_get_legacy_c_thread_structure(void)

#if INCLUDE_RTSMB_DC
    next_pdc_find = rtp_get_system_msec () + rtsmb_srv_netssn_pdc_next_interval ();
#endif
    /**
     * You will note that we consistently use the term 'thread' to refer to the 'mainThread.'
     * In fact, it is not a full blown thread, but is only treated the same, for coding simplicity
     * purposes.  This first thread always runs in the same thread/process as the caller of our API
     * functions.  If CFG_RTSMB_MAX_THREADS is 0, no threads will ever be created.
     */
    // rtsmb_srv_netssn_thread_new is obsolete but estill using thread from cfg
    prtsmb_srv_ctx->threadsInUse[0] = 1;
    prtsmb_srv_ctx->mainThread = &prtsmb_srv_ctx->threads[0]; // rtsmb_srv_netssn_thread_new ();   /* this will succeed because there is at least one thread free at start */
    // We do something strage here and discard thread 0 swap it with temp thread, so save off and restore what we did with thread[0]
    signalobject_Cptr saved_signal_object = prtsmb_srv_ctx->mainThread->signal_object;
    rtsmb_srv_netssn_thread_init (prtsmb_srv_ctx->mainThread, 0);
    prtsmb_srv_ctx->mainThread->signal_object = saved_signal_object;
    srvsmboo_init(prtsmb_srv_ctx->mainThread);
}

/*
==============
 poll to see if any of the  sockets belonging to a handler
 has something to be read.
==============
*/
// SMBS_srv_netssn_cycle ->  isDead
//   isDead ->  srvsmboo_cycle() -> srvsmboo_check_for_new_sessions() -> srvsmboo_get_session_read_list -> rtsmb_srv_netssn_session_cycle or rtsmb_srv_netssn_session_yield_cycle -> condense
//   -> rtsmb_srv_netssn_session_cycle -> SMBS_ProcSMBPacket (pSCtx, pcktsize);  -> rtsmb_srv_nbss_process_packet  or rtsmb_srv_nbss_process_packet
//   rtsmb_srv_nbss_process_packet -> read header and calls SMBS_ProcSMBPacket (pSCtx, header.size)
//     SMBS_ProcSMBPacket (pSCtx, header.size) calls
//           bodyR = SMBS_ProcSMB2BodyPacketExecute(pSctx, FALSE);
//     SMBS_ProcSMB2BodyPacketExecute ->   SMBS_ReadNbssPacketToSessionCtxt   -> SMBS_ProcSMB2_Body

//           bodyR = SMBS_ProcSMB1BodyPacketExecute (pSctx, FALSE); ->  SMBS_ProcSMB1PacketExecute


RTSMB_STATIC void rtsmb_srv_netssn_session_cycle (PNET_SESSIONCTX *session, int ready);
RTSMB_STATIC void rtsmb_srv_netssn_session_yield_cycle (PNET_SESSIONCTX *session);



static void rtsmb_srv_pdc_session_cycle (PNET_SESSIONCTX *session);
static void _srv_netssn_pdc_cycle(void);
static void SMBS_claimSession (PNET_SESSIONCTX pCtx);
static void SMBS_releaseSession (PNET_SESSIONCTX pCtx);
RTSMB_STATIC void rtsmb_srv_netssn_thread_condense_sessions (PNET_THREAD pThread);
RTSMB_STATIC void rtsmb_srv_netssn_connection_close (PNET_SESSIONCTX pSCtx );
BBOOL SMBS_ProcSMBPacket (PSMB_SESSIONCTX pSctx, dword packetSize, BBOOL pull_nbss);
BBOOL rtsmb_srv_nbss_process_packet (PSMB_SESSIONCTX pSCtx);    // Called from rtsmb_srv_netssn_session_cycle



void SMBS_srv_netssn_cycle (long timeout)
{
    if (!prtsmb_srv_ctx->mainThread)
    {
        srvsmboo_panic("rtsmb_srv_netssn_cycle sock: lost mainTread");
        return;
    }
    PNET_THREAD pThread = prtsmb_srv_ctx->mainThread;
    //
//    rtsmb_srv_netssn_thread_cycle (prtsmb_srv_ctx->mainThread, timeout);
// ===================================
//RTSMB_STATIC void rtsmb_srv_netssn_thread_cycle (PNET_THREAD pThread,long timeout)
    if (!pThread->srand_is_initialized)    /* Seed rend here for no big reason */
    {
        tc_srand ((unsigned int) rtp_get_system_msec ());
        pThread->srand_is_initialized = TRUE;
    }

    PNET_SESSIONCTX *session;
    int i,n;
    int readListSize;
    RTP_SOCKET readList[256];

    srvsmboo_cycle(timeout);                                               // call select and match up accepts, and incoming packet recieves
    srvsmboo_check_for_new_sessions();                                     // calls rtsmb_srv_netssn_thread_new_session if a new session request was recieved.
    readListSize = srvsmboo_get_session_read_list(readList);               // list of sockets with traffic
    if (readListSize > 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"srvsmboo_get_session_read_list: returned %d", readListSize);
        // Fall through an allow old school processing to run

        /**
         * Now we run the sessions we are responsible for.
         */
        for(i = 0; i < (int)pThread->numSessions; i++)
        {
            int current_session_index = (i + (int)pThread->index) % (int)pThread->numSessions;
            SMBS_SESSION_STATE starting_state;

            /* session can be null here */
            session = &pThread->sessionList[current_session_index];
            if (!*session)
              continue;

            /* Shouldn't run if a blocking session exists and we aren't it. */
            if (pThread->blocking_session != -1 &&
                pThread->blocking_session != current_session_index)
            {
                continue;
            }

            /* make sure we bind the thread to the net session context */
           (*session)->netsessiont_pThread = pThread;

            starting_state = (*session)->netsessiont_smbCtx.session_state;
            for (n = 0; n < readListSize; n++)
            {
                if (readList[n] == (*session)->netsessiont_sock)
                {
                    rtsmb_srv_pdc_session_cycle (session);
                    rtsmb_srv_netssn_session_cycle (session, TRUE);
                    break;
                }
            }
            /* session can be null here */
            if (!*session)
              continue;

            // A yielded session's socket won't be in the socket list so check
            // if it is yielded and then check the countdown and wakup triggers
            if (yield_c_is_session_blocked(&(*session)->netsessiont_smbCtx))
            {
              rtsmb_srv_netssn_session_yield_cycle (session);
            }
            else if (n == readListSize)
            { // A non yielded session timeded out, check for KEEPALIVES
                 rtsmb_srv_pdc_session_cycle (session);
                rtsmb_srv_netssn_session_cycle (session, FALSE);
            }

            /* Warning: at this point, (*session) may be NULL */

            /* if we changed states, and we are changing away from idle,
               we should block on this session.  If we are changing to idle,
               we should stop blocking on this session */
            if ((*session) && starting_state != (*session)->netsessiont_smbCtx.session_state)
            {
                if (starting_state == IDLE)
                {
                    pThread->blocking_session = current_session_index;
                }
                else if ((*session)->netsessiont_smbCtx.session_state == IDLE)
                {
                    pThread->blocking_session = -1;
                }
            }
            else if (!(*session))
            {
                /* dead session.  clear block if this held it */
                if (pThread->blocking_session == current_session_index)
                {
                    pThread->blocking_session = -1;
                }
            }
        }

        rtsmb_srv_netssn_thread_condense_sessions (pThread);

        if (pThread->numSessions)
        {
            /* mix it up a bit, in case a session at the front is hogging time */
            pThread->index = ((dword) tc_rand () % pThread->numSessions);
        }
    }
// ==================================
    _srv_netssn_pdc_cycle();
}

RTSMB_STATIC void rtsmb_srv_netssn_session_yield_cycle (PNET_SESSIONCTX *session)
{
BBOOL doCB=FALSE;
BBOOL dosend = TRUE;

    if ((*session)->netsessiont_smbCtx.isSMB2)
    {
        if (yield_c_check_signal(&(*session)->netsessiont_smbCtx))
       {
          OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_SIGNAL
          doCB=TRUE;
       }
       else
       {
         if(yield_c_check_timeout(&(*session)->netsessiont_smbCtx))
         { // Clear it so it doesn't fire right away
           yield_c_clear_timeout(&(*session)->netsessiont_smbCtx);
           doCB=TRUE;
           OPLOCK_DIAG_YIELD_SESSION_RUN_FROM_TIMEOUT
         }
       }
    }

    if (doCB)
    {
       OPLOCK_DIAG_ENTER_REPLAY
       ; // SMBS_ProcSMBBodyPacketReplay(&(*session)->netsessiont_smbCtx);
       OPLOCK_DIAG_EXIT_REPLAY
    }
}

RTSMB_STATIC void rtsmb_srv_netssn_session_cycle (PNET_SESSIONCTX *session, int ready)
{
    BBOOL isDead = FALSE;
    BBOOL rv = TRUE;
    PSMB_SESSIONCTX pSCtx = &(*session)->netsessiont_smbCtx;

    SMBS_claimSession (*session);

    /* handle special state cases here, potentially skipping netbios layer */
    switch (pSCtx->session_state)
    {
    case READING:
    case WRITING_RAW_READING:
    {
        int pcktsize = (int) (pSCtx->in_packet_size - pSCtx->current_body_size);
        if (pcktsize == 0)
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"Warning: rtsmb_srv_netssn_session_cycle ignoring 0-length packet: %d \n", pcktsize);
        } else
        {
           SMBS_ProcSMBPacket (pSCtx, pcktsize, FALSE /* dont pull*/);/* rtsmb_srv_netssn_session_cycle finish reading what we started. */
        }
        break;
    }
    default:
        if (ready)
        {
            (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
            if (SMBS_ProcSMBPacket (pSCtx, 0, TRUE)== FALSE) /* pull a new nbss packet and process it */
                isDead = TRUE;
        }
        else
        {
            /*check for time out */
            if(IS_PAST ((*session)->netsessiont_lastActivity, RTSMB_NBNS_KEEP_ALIVE_TIMEOUT*4))
            {
                RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_srv_netssn_session_cycle: Connection timed out on socket %ld ",(*session)->netsessiont_sock);
                (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
                isDead = TRUE;
            }
            else if (prtsmb_srv_ctx->enable_oplocks) // run down any oplock timers
            {
               oplock_c_break_check_wating_break_requests();
            }
        }
        break;
    }

    if (isDead)
    {
        rtsmb_srv_netssn_connection_close (*session);
        rv = FALSE;
        // Set to not connected so we allow reception of SMB2 negotiate packets.
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session closed\n");
        SMBS_Setsession_state(pSCtx, NOTCONNECTED);

    }
    else
    {
       // Send any oplock break alerts
       oplock_c_break_send_pending_breaks();
       // HEREHERE -  send any notify alerts
    }
    SMBS_releaseSession (*session);
    if (isDead)
    {
        *session = (PNET_SESSIONCTX)0;
    }
}
static void freeSession (PNET_SESSIONCTX p)
{
	int location;
	location = INDEX_OF (prtsmb_srv_ctx->sessions, p);


	CLAIM_NET ();
	prtsmb_srv_ctx->sessionsInUse[location] = 0;
	RELEASE_NET ();
}


RTSMB_STATIC void rtsmb_srv_netssn_connection_close (PNET_SESSIONCTX pSCtx )
{

    SMBS_srv_netssn_connection_close_session(pSCtx);
    srvsmboo_close_socket((RTP_SOCKET) pSCtx->netsessiont_sock);
    freeSession (pSCtx);
}



//
RTSMB_STATIC void rtsmb_srv_netssn_thread_condense_sessions (PNET_THREAD pThread)
{
    dword i;
    /* condense list */
    for (i = 0; i < pThread->numSessions; i++)
    {
        if (pThread->sessionList[i] == (PNET_SESSIONCTX)0)
        {
            do
            {
                pThread->numSessions--;
                if (pThread->sessionList[pThread->numSessions] != (PNET_SESSIONCTX)0)
                {
                    pThread->sessionList[i] = pThread->sessionList[pThread->numSessions];
                    pThread->sessionList[pThread->numSessions] = (PNET_SESSIONCTX)0;
                    break;
                }
            }
            while (pThread->numSessions > i);
        }
    }
}



RTSMB_STATIC void rtsmb_srv_netssn_thread_init (PNET_THREAD p, dword numSessions)
{
    dword i;

    for (i = numSessions; i < prtsmb_srv_ctx->max_sessions; i++)
    {
        p->sessionList[i] = (PNET_SESSIONCTX)0;
    }

    p->index = 0;
    p->blocking_session = -1;
    p->numSessions = numSessions;
    p->srand_is_initialized = FALSE;
    // p->yield_sock; A udp socket dedicated to signalling yield sessions was initialized at startup
}



// Close the session out but don't close the socket.
// Used when an SMB2 session tries to reconnect the session withiut closing the socket
void SMBS_srv_netssn_connection_close_session(PNET_SESSIONCTX pSCtx )
{
#ifdef SUPPORT_SMB2

   if (pSCtx->netsessiont_smbCtx.isSMB2)
// if (pSCtx->netsessiont_smbCtx.pCtxtsmb2Session)
     RTSmb2_SessionShutDown(&pSCtx->netsessiont_smbCtx.Smb2SessionInstance);
#endif

   SMBS_CloseSession( &(pSCtx->netsessiont_smbCtx) );
   SMBS_Setsession_state(&pSCtx->netsessiont_smbCtx,NOTCONNECTED);

}
void SMBS_Setsession_state(PSMB_SESSIONCTX pSctxt, SMBS_SESSION_STATE new_session_state)
{
   pSctxt->session_state = new_session_state;
}

BBOOL SMBS_SendMessage (PSMB_SESSIONCTX pCtx, dword size, BBOOL translate)
{
    RTSMB_NBSS_HEADER header;
    int r;

    size = MIN (size, pCtx->writeBufferSize);

    header.type = RTSMB_NBSS_COM_MESSAGE;
    header.size = size;

    r = rtsmb_nbss_fill_header (pCtx->writeBuffer, RTSMB_NBSS_HEADER_SIZE, &header);
    if (r < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBS_SendMessage: Error writing netbios header!\n");
        return FALSE;
    }
    else
    {
        r =  rtsmb_net_write (pCtx->sock, pCtx->writeBuffer, (int)(RTSMB_NBSS_HEADER_SIZE + size));
        if (r < 0)
            return FALSE;
    }
    return TRUE;
}


PNET_SESSIONCTX SMBS_findSessionByContext (PSMB_SESSIONCTX pSctxt)
{
	PNET_SESSIONCTX rv = (PNET_SESSIONCTX)0;
	word i;
	CLAIM_NET ();
	for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
	{
		if (prtsmb_srv_ctx->sessionsInUse[i] && &(prtsmb_srv_ctx->sessions[i].netsessiont_smbCtx) == pSctxt)
		{
			rv = &prtsmb_srv_ctx->sessions[i];
			break;
		}
	}
	RELEASE_NET ();

	return rv;
}

// Legacy implementaion, close this share in all sessions.
void SMBS_closeAllShares(PSR_RESOURCE pResource)
{
PNET_SESSIONCTX pCtx = &prtsmb_srv_ctx->sessions[0];
   /**
    * We have the session right where we want it.  It is not doing anything,
    * so we can close the tree itself and all the files it has open on this session.
    */
   SMBS_claimSession (pCtx);
   SMBS_CloseShare (&pCtx->netsessiont_smbCtx, (word) INDEX_OF (prtsmb_srv_ctx->shareTable, pResource));
   SMBS_releaseSession (pCtx);
}
void SMBS_srv_netssn_shutdown (void)
{
    srvsmboo_netssn_shutdown();
    // Legacy code
    CLAIM_NET ();
    prtsmb_srv_ctx->threadsInUse[0] = 0;
    RELEASE_NET ();
}

static void SMBS_claimSession (PNET_SESSIONCTX pCtx)
{
	int i;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);

	rtp_sig_mutex_claim((RTP_MUTEX) prtsmb_srv_ctx->activeSessions[i]);
}

static void SMBS_releaseSession (PNET_SESSIONCTX pCtx)
{
	int i;
	i = INDEX_OF (prtsmb_srv_ctx->sessions, pCtx);
	rtp_sig_mutex_release((RTP_MUTEX) prtsmb_srv_ctx->activeSessions[i]);

}


static void _srv_netssn_pdc_cycle(void)
{
#if INCLUDE_RTSMB_DC
    /* now see if we need to query for the pdc again */
    if (!MS_IsKnownPDCName () && next_pdc_find <= rtp_get_system_msec ())
    {
        MS_SendPDCQuery ();

        next_pdc_find = next_pdc_find + rtsmb_srv_netssn_pdc_next_interval ();
    }
#endif
}
#if (INCLUDE_RTSMB_DC)
static BBOOL SMBS_StateWaitOnPDCName (PSMB_SESSIONCTX pCtx)
{
    if (pCtx->session_state != WAIT_ON_PDC_NAME)
        return TRUE;

    if (MS_IsKnownPDCName ())
    {
        pCtx->session_state = FINISH_NEGOTIATE;
    }
    else if (pCtx->end_time <= rtp_get_system_msec() ())
    {
        pCtx->session_state = FAIL_NEGOTIATE;
    }

    return TRUE;
}

static BBOOL SMBS_StateWaitOnPDCIP (PSMB_SESSIONCTX pCtx)
{
    char pdc [RTSMB_NB_NAME_SIZE + 1];

    if (pCtx->session_state != WAIT_ON_PDC_IP)
        return TRUE;

    if (!MS_GetPDCName (pdc))
    {
        /* we've should've already alotted time and sent out a query.   */
        /* let's not do it again                                        */
        pCtx->session_state = WAIT_ON_PDC_NAME;
        return TRUE;
    }

    if (rtsmb_srv_nbns_is_in_name_cache (pdc, RTSMB_NB_NAME_TYPE_SERVER))
    {
        pCtx->session_state = FINISH_NEGOTIATE;
    }
    else if (pCtx->end_time <= rtp_get_system_msec())
    {
        pCtx->session_state = FAIL_NEGOTIATE;
    }

    return TRUE;
}

static BBOOL SMBS_StateContinueNegotiate (PSMB_SESSIONCTX pCtx)
{
    PFBYTE pInBuf;
    PFVOID pOutBuf;

    /**
     * Set up incoming and outgoing header.
     */
    pInBuf = (PFBYTE) SMB_INBUF (pCtx);
    pOutBuf = SMB_OUTBUF (pCtx);

    /* since we are coming here from a pdc discovery, restore state   */
    pInBuf[0] = 0xFF;
    pInBuf[1] = 'S';
    pInBuf[2] = 'M';
    pInBuf[3] = 'B';
    pInBuf[4] = SMB_COM_NEGOTIATE;

    SMBS_ProcSMBBody (pCtx);
    pCtx->session_state = IDLE;

    return SMBS_SendMessage (pCtx, pCtx->outBodySize, TRUE);
}
#endif

static void rtsmb_srv_pdc_session_cycle (PNET_SESSIONCTX *session)
{
    BBOOL isDead = FALSE;
    BBOOL rv = TRUE;
    PSMB_SESSIONCTX pSCtx = &(*session)->netsessiont_smbCtx;

    SMBS_claimSession (*session);

    /* keep session alive while we do stuff */
    switch (pSCtx->session_state)
    {
    case BROWSE_MUTEX:
    case BROWSE_SENT:
    case WAIT_ON_PDC_NAME:
    case WAIT_ON_PDC_IP:
    case FINISH_NEGOTIATE:
    case FAIL_NEGOTIATE:
        (*session)->netsessiont_lastActivity = rtp_get_system_msec ();
        break;
    default:
        break;
    }
    /* handle special state cases here, potentially skipping netbios layer */
    switch (pSCtx->session_state)
    {
#if (INCLUDE_RTSMB_DC)
    case WAIT_ON_PDC_NAME:
        SMBS_StateWaitOnPDCName (pSCtx);
        break;
    case WAIT_ON_PDC_IP:
        SMBS_StateWaitOnPDCIP (pSCtx);
        break;
    case FINISH_NEGOTIATE:
    case FAIL_NEGOTIATE:
        SMBS_StateContinueNegotiate (pSCtx);
        break;
#endif
    case BROWSE_MUTEX:
    case BROWSE_SENT:
    case BROWSE_FINISH:
    case BROWSE_FAIL:
        rtsmb_srv_browse_finish_server_enum (pSCtx);
        break;
    default:
        break;
    }
    SMBS_releaseSession (*session);
}




#endif /* INCLUDE_RTSMB_SERVER */
