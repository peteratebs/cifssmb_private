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


extern BBOOL rtsmb_srv_netssn_thread_new_session (PNET_THREAD pMaster, RTP_SOCKET  sock);



static void srvsmboo_remember_session_socket(RTP_SOCKET  sock);
static void srvsmboo_remember_established_socket(RTP_SOCKET  sock);

EXTERN_C void rtsmb_srv_nbss_send_session_response (RTP_SOCKET sock, BBOOL positive);
EXTERN_C void srvsmboo_panic(char *panic_string);

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
   while (1) rtp_printf("panic: %s \r",panic_string);
}


#endif /* INCLUDE_RTSMB_SERVER */
