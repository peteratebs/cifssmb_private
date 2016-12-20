#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"
#include "rtpthrd.h"
#include "srvobjectsc.h"
#include "remotediags.h"
#include "srvcfg.h"
#include "srvutil.h"
#include "rtpmem.h"

oplock_diagnotics_t oplock_diagnotics;

extern volatile int go; /* Variable loop on.. Note: Linux version needs sigkill support to clean up */

RTSMB_STATIC void rtsmb_srv_diag_main (void);



static char *syslogname = "RTSMBS";
static unsigned long level_mask = (SYSLOG_TRACE_LVL|SYSLOG_INFO_LVL|SYSLOG_ERROR_LVL);
static void SendDiagMessage(void);

static int DiagMessageFilter(char *str);

void rtsmb_srv_syslog_config(void)
{
  RTP_DEBUG_FILTER_SYSLOG(DiagMessageFilter);
  RTP_DEBUG_OPEN_SYSLOG(syslogname, level_mask);
}
void rtsmb_srv_diag_config(void)
{
   prtsmb_srv_ctx->display_login_info    = FALSE;
   prtsmb_srv_ctx->display_config_info    = FALSE;
}


void rtsmb_thread_diag (void *p)
{
  if (!srvobject_bind_diag_socket())
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Error occurred while trying to open diag socket\n");
  }
  else
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "diag socket is open\n");
      while (go)
      {
        rtsmb_srv_diag_main();
     }
  }
}


RTSMB_STATIC void rtsmb_srv_diag_main (void)
{
    dword i;
    RTP_SOCKET readList[2];
    int j,len,in_len;

    readList[0] = *srvobject_get_diag_socket();
    len = 1;
    len = rtsmb_netport_select_n_for_read (readList, len, 1000);
    if (len && go)
    {
      srvobject_process_diag_request();
    }
}
#define EXTERN_C
// #define EXTERNC extern "C"

#if(INCLUDE_SRVOBJ_REMOTE_DIAGS)

// extern "C" fixme first
static char *SMBU_format_filename(word *filename, size_t size, char *temp){  int i=0;  do   {     temp[i] = (char)filename[i]; }  while (filename[i++]);return temp;}

EXTERN_C  char *SMBU_format_fileid(byte *unique_fileid, int size, char *temp)
{
dword *p = (dword *)unique_fileid;
     sprintf(temp, "%7lu", *p);
     return temp;
}
 // 7 digits 4 000 000
//
//int i;
//     for (i = 0; i < size;i++) {tp += sprintf(&temp[tp], "%X,", unique_fileid[i]); } return temp;}
//     int i,tp;  tp = 0; tp &temp[0];
//     for (i = 0; i < size;i++) {tp += sprintf(&temp[tp], "%X,", unique_fileid[i]); } return temp;}


// Scans all in use fid objects
struct FidObjectReferencesCB_t {
    void *fidobject_address;
    int fid_count;
};

typedef int(*enumSessionFnType)(PNET_SESSIONCTX pnCtx, void *pargs);

// Scans all active sessions used in remote diags and in
static int SMBU_EnumerateSessions(enumSessionFnType fn, void *enumargs)
{
    word i;
    for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
    {
        if (prtsmb_srv_ctx->sessionsInUse[i])
        {
          int r = fn(&prtsmb_srv_ctx->sessions[i], enumargs);
          if (r != 0)
            return r;
        }
    }
    return 0;
}
struct mapPidToSessionNumberCB_t { FID_T *pfid;    int answer;    int index;};
static int mapPidToSessionNumberCB (PNET_SESSIONCTX pnCtx, void *pargs)
{
int i;
 for (i=0; i < prtsmb_srv_ctx->max_fids_per_session;i++)
 {
  if (&pnCtx->netsessiont_smbCtx.fids[i] == ((struct mapPidToSessionNumberCB_t *)pargs)->pfid)
  {
    ((struct mapPidToSessionNumberCB_t *)pargs)->answer =   ((struct mapPidToSessionNumberCB_t *)pargs)->index;
    return 1;
  }
 }
 ((struct mapPidToSessionNumberCB_t *)pargs)->index += 1;
 return 0;
}
//
static int SMBU_FidToSessionNumber (FID_T *pfid)
{
struct mapPidToSessionNumberCB_t args = {
        pfid: pfid,
        answer: -1,
        index:   0
    };
    SMBU_EnumerateSessions(mapPidToSessionNumberCB, (void *) &args);
    return args.answer;
}

static int countFidObjectReferencesCB(PFID fid, PNET_SESSIONCTX pnCtx, PSMB_SESSIONCTX pCtx, void *pargs)
{
    if (SMBU_Fidobject(fid)== ((struct FidObjectReferencesCB_t*)pargs)->fidobject_address)
      ((struct FidObjectReferencesCB_t*)pargs)->fid_count += 1;
    return 0;
}
// scan the open fid and count the number of FID that refernce this fidobject
static int SMBU_CountFidObjectReferences(void *fidobject_address)
{
  struct FidObjectReferencesCB_t  args;
  args.fid_count = 0;
  args.fidobject_address = fidobject_address;
  SMBU_EnumerateFids(countFidObjectReferencesCB, &args);
  return args.fid_count;
}

struct DiagFormatSessionsCB_t { char *buffer;; int numSessions; int doCount;};
static int DiagFormatSessionsCB (PNET_SESSIONCTX pnCtx, void *pargs)
{
 if ( ((struct  DiagFormatSessionsCB_t*)pargs)->doCount)
   ((struct  DiagFormatSessionsCB_t*)pargs)->numSessions+=1;
 else
   ((struct  DiagFormatSessionsCB_t*)pargs)->buffer +=  tc_sprintf(((struct DiagFormatSessionsCB_t *)pargs)->buffer, "  Last activity: %lu\n", pnCtx->netsessiont_lastActivity);
 return 0;
}

//
static char * SMBU_DiagFormatSessions(char *buffer)
{
struct DiagFormatSessionsCB_t args = {
        buffer: buffer,
        numSessions: 0,
        doCount: 1,
    };
    SMBU_EnumerateSessions(DiagFormatSessionsCB, (void *) &args);
    buffer +=  tc_sprintf(buffer, "  Num Sessions : %lu\n", args.numSessions);
    args.doCount = 0; args.buffer = buffer;
    SMBU_EnumerateSessions(DiagFormatSessionsCB, (void *) &args);
    return args.buffer;
}

static int SMBU_DiagFormatFidList(char *buffer)
{
char *start=buffer;
PFIDOBJECT pNewfidObject = 0;  // result

 buffer += tc_sprintf(buffer, (char *)"====================== FID STATISTICS  ==========================================\n");
 buffer += tc_sprintf(buffer, (char *)"### OBJADDR     REFS   FIDADDR OPENS FLGS  LCK  TID    UID SES#   INODE   FILENAME\n");
 int  i;
 for (i = 0; i < ((int)prtsmb_srv_ctx->max_fids_per_session*(int)prtsmb_srv_ctx->max_sessions); i++)
 {
 char temp0[32];
 char temp1[256];
 // struct SMBU_enumFidSearchUniqueidType_s matchedfids;
 int reference_count = 0;
 dword objaddress;

    if (prtsmb_srv_ctx->fidBuffers[i].internal_fid >= 0)
    {
      FID_T *p = &(prtsmb_srv_ctx->fidBuffers[i]);
      if (p->_pfidobject)
      {
        reference_count = SMBU_Fidobject(p)->reference_count;
        objaddress = (dword) SMBU_Fidobject(p);
        int fidcount = SMBU_CountFidObjectReferences(SMBU_Fidobject(p));
//        SMBU_SearchFidsByUniqueId (SMBU_Fidobject(p)->unique_fileid, &matchedfids);
                                           // i  obj  ref   p   fdcnt  flg lv    tid  uid  sess id nm
        buffer += tc_sprintf(buffer,  (char *)"%3d %8x  %5d  %8x   %5d  %2x  %2d  %4u %4u  %4d  %8s %s \n",
        i,
        objaddress,
        reference_count,
        p,fidcount, p->smb2flags,SMBU_Fidobject(p)->held_oplock_level,p->tid,p->uid, SMBU_FidToSessionNumber(p),SMBU_format_fileid(SMBU_Fidobject(p)->unique_fileid, SMB_UNIQUE_FILEID_SIZE, temp0),SMBU_format_filename(SMBU_Fidobject(p)->name,sizeof(temp1),temp1));
      }
    }
  }
  buffer += tc_sprintf(buffer, (char *)"====#======#====#=====#=====#====#====#=======#=== \n");

  buffer += tc_sprintf(buffer, (char *)"====================== OPLOCK STATISTICS  ==========================================\n");
  if (!prtsmb_srv_ctx->enable_oplocks)
     buffer += tc_sprintf(buffer, (char *)"Oplocks are disabled:\n");
  else
  {
    buffer += tc_sprintf(buffer, (char *)"Oplocks are enabled:\n");
    buffer += tc_sprintf(buffer, (char *)"  session_replays               :  %lu \n", oplock_diagnotics.session_replays               );
    buffer += tc_sprintf(buffer, (char *)"  session_yields                :  %lu \n", oplock_diagnotics.session_yields                );
    buffer += tc_sprintf(buffer, (char *)"  session_wakeups               :  %lu \n", oplock_diagnotics.session_wakeups               );
    buffer += tc_sprintf(buffer, (char *)"  session_wake_signalled        :  %lu \n", oplock_diagnotics.session_wake_signalled        );
    buffer += tc_sprintf(buffer, (char *)"  session_sent_signals          :  %lu \n", oplock_diagnotics.session_sent_signals          );
    buffer += tc_sprintf(buffer, (char *)"  session_sent_timeouts         :  %lu \n", oplock_diagnotics.session_sent_timeouts         );
    buffer += tc_sprintf(buffer, (char *)"  session_wake_timedout         :  %lu \n", oplock_diagnotics.session_wake_timedout         );
    buffer += tc_sprintf(buffer, (char *)"  session_sent_breaks           :  %lu \n", oplock_diagnotics.session_sent_breaks           );
  }
  buffer += tc_sprintf(buffer, (char *)"====================== SESSION STATISTICS  ==========================================\n");
  buffer = SMBU_DiagFormatSessions(buffer);
  return (int) (buffer - start);
}

static int diag_remote_portnumber = -1;
static RTP_SOCKET diag_socket = -1;
static const byte local_ip_address[] = {0x7f,0,0,1};
// Request come in here. replies go out.
static int  remote_port=-1;
static byte remote_ip[4];

EXTERN_C int rtsmb_net_read_datagram (RTP_SOCKET sock, PFVOID pData, int size, PFBYTE remoteAddr, PFINT remotePort);
EXTERN_C int rtsmb_net_write_datagram (RTP_SOCKET socket, PFBYTE remote, int port, PFVOID buf, int size);



EXTERN_C RTP_SOCKET *srvobject_get_diag_socket(void)
{
 if (diag_socket < 0)
   return 0;
 else
   return &diag_socket;

}
EXTERN_C BBOOL srvobject_bind_diag_socket(void)
{
    if (rtp_net_socket_datagram(&diag_socket) < 0)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "srvobject_bind_diag_socket: Unable to get new socket\n");
        return FALSE;
    }
    if (rtp_net_bind(diag_socket, (unsigned char*)0, REMOTE_DEBUG_FROM_PROXY_PORTNUMBER, 4))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "srvobject_bind_diag_socket: bind to port %d failed\n",REMOTE_DEBUG_FROM_PROXY_PORTNUMBER);
        return FALSE;
  }
  return TRUE;
}


EXTERN_C void srvobject_write_diag_socket(byte *p, int len)
{
  if (diag_remote_portnumber!=-1)
  {
  int r =
  rtsmb_net_write_datagram (
    diag_socket,
    (byte *) remote_ip, // local_ip_address,
    REMOTE_DEBUG_TO_PROXY_PORTNUMBER,
    p,
    len);  // Four is the minimum size might as well send something
  }

}

EXTERN_C int srvobject_process_diag_request(void)
{
  int  size, remote_port;
  byte p[80];
  size = rtsmb_net_read_datagram (diag_socket, p, 80, remote_ip, &remote_port);
  if (size >= 0)
  {
    diag_remote_portnumber = remote_port;
//    srvobject_write_diag_socket(p, size);
    if (tc_strstr((char *)p, "SMB FIDS"))
    {
      char * p = (char *) rtp_malloc(1024*512);
      int len = SMBU_DiagFormatFidList(p);
      srvobject_write_diag_socket((byte *)p, len);
      RTP_FREE(p);
    }
    if (tc_strstr((char *)p, "SMB MSSGS"))
    {
      SendDiagMessage();
    }
  }
  return size;
}


static int   queuedmessagelength=0;
static char  queuedmessageBuffer[1024*64];
static void QueueDiagMessage(char *str)
{
int l;
  l = tc_strlen(str);
  if ((l+queuedmessagelength) < sizeof(queuedmessageBuffer))
  {
    tc_strcpy(&queuedmessageBuffer[queuedmessagelength], str);
    queuedmessagelength += l;
  }
}
static void SendDiagMessage(void)
{
 if (queuedmessagelength>0)
 {
   srvobject_write_diag_socket(queuedmessageBuffer, queuedmessagelength+1);
   queuedmessagelength = 0;
 }
 else
   srvobject_write_diag_socket("NOPE:", 6);
}
static int DiagMessageFilter(char *str)
{
  if (tc_memcmp(str, "DIAG:",5) == 0)
  {
   int l;
//    if (queuedmessagelength!=0)
//       str += 5; // skip DIAG:
    l = tc_strlen(str);
    if ((l+queuedmessagelength) < sizeof(queuedmessageBuffer))
    {
      tc_strcpy(&queuedmessageBuffer[queuedmessagelength], str);
      queuedmessagelength += l;
    }
    printf("%s", str);
    return 1;
  }
  else
  {
    return 0;
  }
}

#endif
