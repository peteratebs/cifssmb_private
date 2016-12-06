#include <stdint.h>
#include "srvcfg.h"
#include "srvssn.h"
#include "rtpstr.h"
#include "rtptime.h"
#include "rtpmem.h"
#include "srv_smb2_model.h"
#include "com_smb2_ssn.h"
#include "srvobjectsc.h"

#include "rtpnet.h"
#include "rtpnet.h"

#define COPYCITEM(CPTR,FIELDNAME)   tc_memcpy(this->FIELDNAME, CPTR->FIELDNAME, sizeof(this->FIELDNAME))

#define mystdbool int

#define CFG_RTSMB_MAX_SESSIONS              8
#define CFG_RTSMB_MAX_USERS                 8
#define CFG_RTSMB_MAX_UIDS_PER_SESSION      3
#define CFG_RTSMB_MAX_TREES_PER_SESSION     10
#define CFG_RTSMB_MAX_FIDS_PER_SESSION      16

#if (0)

EnumerateTreads
  EnumerateSession
    EnumerateUids  one per session usually
    EnumerateFid
    EnumerateTrees


  EnumerateFids and keep a history
    UUID OPLOCKSTATE SESIONID:UID           NAME
    XXX              DEAD



 To do:.
  Given  prtsmb_srv_ctx:
   for each threads: in  mainThread,threads[]    - mainThread should be the only one
       dword numSessions;
       int blocking_session;
       int yield_sock_portnumber;
       RTP_SOCKET yield_sock;
       dword index;
     for each session in thread:
      sessions[]  CFG_RTSMB_MAX_SESSIONS
           sockinfo
           lastActivity
           duration
           could add bytes sent & recvd
         smb_sessionCtx_c
           current state
           could also log transaction history;
           uids[CFG_RTSMB_MAX_UIDS_PER_SESSION]
               uint8_t   inUse;
               uint16_t  uid;
               uint16_t  authId;
               mystdbool canonicalized;
               SEARCH_T *searches;
               PFID     *fids;
           trees [CFG_RTSMB_MAX_TREES_PER_SESSION];
               mystdbool inUse;
               uint8_t access;
               uint8_t type;      /* type of tree */
               uint16_t external;  /* public tid */
               uint16_t internal;  /* private tid */
               PFID *fids;
           fids  [CFG_RTSMB_MAX_FIDS_PER_SESSION]
               int internal_fid;   /* -1 means not in use */
               uint16_t external;
               uint16_t flags;
               uint32_t smb2flags;
               uint8_t held_oplock_level;         /* current level if (smb2flags&SMB2OPLOCKHELD) */
               uint16_t held_oplock_uid;
               uint8_t requested_oplock_level;    /* requested level if (smb2flags&SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY)  */
               uint32_t smb2waitexpiresat;        /* Timer expires if !0 and SMB2WAITOPLOCKREPLY|SMB2WAITLOCKREGION */
               uint16_t tid;       /* owning tree tree == prtsmb_srv_ctx->shareTable[tid]
               uint16_t uid;       /* owning user between 0 and prtsmb_srv_ctx->max_uids_per_session))*/
               uint32_t pid;      /* owning process */
               uint32_t error;    /* delayed error */
               uint8_t  unique_fileid[8];        /* The on-disk inode that identifies it uniquely on the volume. */
               uint16_t name[SMBF_FILENAMESIZE + 1];
#endif
class srvobjectglobals_c {
  public:
    srvobjectglobals_c() {
      session_number = -1;
    };
    int session_number;
};

class srvobjectglobals_c srvobjectglobals;

class hist_item_c {
  public:
    hist_item_c(){};
    class hist_item_c *nextitem(void) {return this->pnextitemc;};
    void append(class hist_item_c *listhead, void *contents)
    {
        this->contents = contents;
        this->pnextitemc=0;
        this->item_time = rtp_get_system_msec();

        if (listhead)
        {
            while (listhead->pnextitemc)
            {
              listhead = listhead->pnextitemc;
            }
            listhead->pnextitemc = this;
        }
    };
    ~hist_item_c(){};
  private:
    class hist_item_c *pnextitemc;
    uint32_t item_time;
    void *contents;
};

class hist_item_c *hist_item_get_item(class hist_item_c *listhead, int index)
{
  while (listhead) { if (index--==0)  return listhead; listhead=listhead->nextitem(); }
  return 0;
}

class hist_container_c {
  public:
    hist_container_c (void)
    {
      this->item_list = 0;
      this->itemcount = 0;
    };
    ~hist_container_c () {};
    void append_item (void *contents)
    {
      hist_item_c *p = new hist_item_c();
      p->append(this->item_list, contents);
      if (!this->item_list)
        this->item_list = p;
      this->itemcount += 1;
      itemcount;
    }
    hist_item_c *get_item(int index) { return hist_item_get_item(this->item_list,index); };
    void iterate(void *args);
  private:
    int itemcount;   /* -1 means not in use */
    hist_item_c *item_list;
};


// Each .seq file and the .bmp files it references creates one one_instance of an animation_sequence
class fid_c {
  public:
    fid_c (PFID pfid);
    ~fid_c ();
  private:
    int internal_fid;   /* -1 means not in use */
    uint16_t external;
    uint16_t flags;
    uint32_t smb2flags;
    uint8_t held_oplock_level;         /* current level if (smb2flags&SMB2OPLOCKHELD) */
    uint16_t held_oplock_uid;
    uint8_t requested_oplock_level;    /* requested level if (smb2flags&SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY)  */
    uint32_t smb2waitexpiresat;        /* Timer expires if !0 and SMB2WAITOPLOCKREPLY|SMB2WAITLOCKREGION */
    uint16_t tid;       /* owning tree */
    uint16_t uid;       /* owning user */
    uint32_t pid;      /* owning process */
    uint32_t error;    /* delayed error */
    uint8_t  unique_fileid[8];        /* The on-disk inode that identifies it uniquely on the volume. */
    uint16_t name[SMBF_FILENAMESIZE + 1];

};

fid_c::fid_c (PFID pfid)
{
  this->internal_fid           = pfid->internal_fid          ;   /* -1 means not in use */
  this->external               = pfid->external              ;
  this->flags                  = pfid->flags                 ;
  this->smb2flags              = pfid->smb2flags             ;
  this->held_oplock_level      = pfid->held_oplock_level     ;         /* current level if (smb2flags&SMB2OPLOCKHELD) */
  this->held_oplock_uid        = pfid->held_oplock_uid       ;
  this->requested_oplock_level = pfid->requested_oplock_level;    /* requested level if (smb2flags&SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY)  */
  this->smb2waitexpiresat      = pfid->smb2waitexpiresat     ;        /* Timer expires if !0 and SMB2WAITOPLOCKREPLY|SMB2WAITLOCKREGION */
  this->tid                    = pfid->tid                   ;       /* owning tree */
  this->uid                    = pfid->uid                   ;       /* owning user */
  this->pid                    = pfid->pid                   ;      /* owning process */
  this->error                  = pfid->error                 ;    /* delayed error */
  COPYCITEM(pfid,unique_fileid);
  COPYCITEM(pfid,name);
//  tc_memcpy(this->unique_fileid, pfid->unique_fileid, sizeof(this->unique_fileid));   /* The on-disk inode that identifies it uniquely on the volume. */
//  tc_memcpy(this->name, pfid->name,sizeof(this->name));
}

fid_c::~fid_c()
{

}

class tag_string_c {
  public:
    tag_string_c(class tag_string_c *pPrev, char *tagstring)
     {
     _tagstring = tagstring;
     pNext = (class tag_string_c *)0;
     tag_time=rtp_get_system_msec();
     sessionnumber=srvobjectglobals.session_number;
     if (pPrev) pPrev->pNext = this;
     };
    ~tag_string_c() {};
    class tag_string_c *get_next(void) { return pNext;};
    char *get_string(void) {return _tagstring;};
    int  get_sessionnumber(void) {return sessionnumber;};
    uint32_t get_time(void) {return tag_time;};
  private:
   char *_tagstring;
   uint32_t tag_time;
   int sessionnumber;
   class tag_string_c *pNext;
};

class fidhist_container_c : public hist_container_c
{
  public:
    fidhist_container_c(FID_T *pfid) { starttag=endtag=0;this->item_count=0; epoch_item_time = rtp_get_system_msec(); tc_memcpy(this->unique_fileid,pfid->unique_fileid,sizeof(this->unique_fileid)); };
    ~fidhist_container_c() {};
    void append(FID_T *pfid) {
      this->item_count += 1;
      append_item ((void *)pfid);
    }
    int equal(FID_T *pfid)  { return (tc_memcmp(pfid->unique_fileid,this->unique_fileid,sizeof(this->unique_fileid))==0);};
    void add_tag(char *newtagstring)
    {
       tag_string_c *ptagstring = new tag_string_c(endtag, newtagstring);
       if (!starttag)
         starttag = ptagstring;
       endtag = ptagstring;
    }
    void print(void)
    {
        printf("UID:[");
        for (int i = 0; i < 7; i++)  printf("%X,", unique_fileid[i]);
        printf("%2.2X] item_count:%d \n", unique_fileid[7],item_count);
        tag_string_c *tag = starttag;
        while (tag)
        {
           printf("   %8lu %6lu:(%3d): %s\n", tag->get_time() ,tag->get_time()-epoch_item_time, tag->get_sessionnumber(), tag->get_string());
           tag = tag->get_next();
        }

    }
  protected:
    uint8_t  unique_fileid[8];        /* The on-disk inode that identifies it uniquely on the volume. */
    uint32_t epoch_item_time;
    int item_count;
    tag_string_c *starttag;
    tag_string_c *endtag;

};

class fidhist_history_c
{
#define MAXFIDHISCONTAINERS 100
  public:
    fidhist_history_c(void) { fid_container_count = 0; };
    ~fidhist_history_c() {};
    void add_fid(FID_T *pfid) {
      int i = find_fid_bucket(pfid);
      if (i >= 0)
      {
        fid_containers[i]->append(pfid);
      }
      else
      {
        fid_containers[fid_container_count] = new fidhist_container_c(pfid);
        fid_containers[fid_container_count]->append(pfid);
        fid_container_count+= 1;
      }
    };
    void add_tag(FID_T *pfid,char *tagstring)
    {
      int i = find_fid_bucket(pfid);
      if (i < 0)
         add_fid(pfid);
      i = find_fid_bucket(pfid);
      if (i >= 0)
        fid_containers[i]->add_tag(tagstring);
    };
    void add_tagalloc(FID_T *pfid,char *tagstring)
    {
#warning LEAK
      char *p = (char *) rtp_malloc(tc_strlen(tagstring)+1);
      tc_strcpy(p, tagstring);
      add_tag(pfid,p);
    };
    void print_fids(void) {
      for (int i = 0; i < fid_container_count; i++)
      {
        fid_containers[i]->print();
      }
    };
  private:
    int find_fid_bucket(FID_T *pfid) {
      for (int i = 0; i < fid_container_count; i++)
        if (fid_containers[i]->equal(pfid))
        {
          return i;
        }
        return -1;
    }
    int     fid_container_count;
    fidhist_container_c *fid_containers[MAXFIDHISCONTAINERS];
};

static fidhist_history_c *fid_history = new fidhist_history_c();



extern "C" void srvobject_session_blocked(struct net_thread_s *pThread,struct net_sessionctxt **psession)
{
  printf("Blocked wtf ??\n");
}


extern "C" void srvobject_session_enter(struct net_thread_s *pThread,struct net_sessionctxt **psession)
{
  if (!*psession)
    srvobjectglobals.session_number = -2;
  else
  {
    srvobjectglobals.session_number = (*psession)->heap_index;
    if (srvobjectglobals.session_number > 2)
    {
       printf("Why %d\n", srvobjectglobals.session_number);
    }

  }
}

// extern "C" fixme first
static char *SMBU_format_filename(word *filename, size_t size, char *temp){  int i=0;  do   {     temp[i] = (char)filename[i]; }  while (filename[i++]);return temp;}
extern "C" char *SMBU_format_fileid(byte *unique_fileid, int size, char *temp){ int i,tp;  tp = 0; tp &temp[0];  for (i = 0; i < size;i++) {tp += sprintf(&temp[tp], "%X,", unique_fileid[i]); } return temp;}

extern "C" void SMBU_DisplayFidInfo(void)
{
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, (char *)"### ADDRESS FLGS   LCK  TID   UID  PID  INODE<br>");
 int  i;
 for (i = 0; i < ((int)prtsmb_srv_ctx->max_fids_per_session*(int)prtsmb_srv_ctx->max_sessions); i++)
 {
 char temp0[32];
 char temp1[256];
    if (prtsmb_srv_ctx->fids[i].internal_fid >= 0)
    {
      FID_T *p = &(prtsmb_srv_ctx->fids[i]);
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, (char *)"%3d %8x %2x    %2d  %4u %4u %8s %s<br>",i,p,p->smb2flags,p->held_oplock_level,p->tid,p->uid,SMBU_format_fileid(p->unique_fileid, 8, temp0),SMBU_format_filename(p->name,sizeof(temp1),temp1));
    }
 }
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, (char *)"====#===#====#====#=======#===#====#===#===<br>");
}

static int SMBU_DiagFormatFidList(char *buffer)
{
 char *start=buffer;

 buffer += tc_sprintf(buffer, (char *)"### ADDRESS FLGS   LCK  TID   UID  PID  INODE\n");
 int  i;
 for (i = 0; i < ((int)prtsmb_srv_ctx->max_fids_per_session*(int)prtsmb_srv_ctx->max_sessions); i++)
 {
 char temp0[32];
 char temp1[256];
    if (prtsmb_srv_ctx->fids[i].internal_fid >= 0)
    {
      FID_T *p = &(prtsmb_srv_ctx->fids[i]);
      buffer += tc_sprintf(buffer,  (char *)"%3d %8x %2x    %2d  %4u %4u %8s %s\n",i,p,p->smb2flags,p->held_oplock_level,p->tid,p->uid,SMBU_format_fileid(p->unique_fileid, 8, temp0),SMBU_format_filename(p->name,sizeof(temp1),temp1));
    }
 }
 buffer += tc_sprintf(buffer, (char *)"====#===#====#====#=======#===#====#===#===\n");

 return (int) (buffer - start);
}

extern "C" void srvobject_session_exit(struct net_thread_s *pThread,struct net_sessionctxt **psession)
{
    srvobjectglobals.session_number = -1;
}
extern "C" int srvobject_get_currentsession_index(void)
{
    return srvobjectglobals.session_number;

}

extern "C"  void srvobject_add_fid(FID_T *pfid)
{
  fid_history->add_fid(pfid);
}
extern "C"  void srvobject_display_fids(void)
{
  fid_history->print_fids();
}

extern "C" void srvobject_tag_oplock(FID_T *pfid, char *tagstring)
{
  fid_history->add_tag(pfid,tagstring);
}

extern "C" void srvobject_tagalloc_oplock(FID_T *pfid, char *tagstring)
{
  fid_history->add_tagalloc(pfid,tagstring);
}

extern "C"  void srvobject_display_diags(void)
{
  srvobject_display_fids();
  SMBU_DisplayFidInfo();
}

#if(INCLUDE_SRVOBJ_REMOTE_DIAGS)

static int diag_remote_portnumber = -1;
static RTP_SOCKET diag_socket = -1;
static const byte local_ip_address[] = {0x7f,0,0,1};
// Request come in here. replies go out.
static int  remote_port=-1;
static byte remote_ip[4];

extern "C" int rtsmb_net_read_datagram (RTP_SOCKET sock, PFVOID pData, int size, PFBYTE remoteAddr, PFINT remotePort);
extern "C" int rtsmb_net_write_datagram (RTP_SOCKET socket, PFBYTE remote, int port, PFVOID buf, int size);



extern "C" RTP_SOCKET *srvobject_get_diag_socket(void)
{
 if (diag_socket < 0)
   return 0;
 else
   return &diag_socket;

}
extern "C" BBOOL srvobject_bind_diag_socket(void)
{
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "srvobject_bind_diag_socket called\n");
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


extern "C" void srvobject_write_diag_socket(byte *p, int len)
{
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: srvobject_write_diag_socket sending %s\n", (char *)p);
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

extern "C" int srvobject_process_diag_request(void)
{
  int  size, remote_port;
  byte p[80];
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: srvobject_recv_diag_socket\n");
  size = rtsmb_net_read_datagram (diag_socket, p, 80, remote_ip, &remote_port);
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "YIELD:: srvobject_recv_diag_socket recved %s\n", (char *)p);
  if (size >= 0)
  {
    diag_remote_portnumber = remote_port;
//    srvobject_write_diag_socket(p, size);
    if (tc_strstr((char *)p, "SMB FIDS"))
    {
      char * p = (char *) rtp_malloc(1024*512);
      int len = SMBU_DiagFormatFidList(p);
      srvobject_write_diag_socket((byte *)p, len);
      srvobject_display_diags();
      RTP_FREE(p);
    }

  }
  return size;
}
#endif


// Each .seq file and the .bmp files it references creates one one_instance of an animation_sequence
class user_c {
  public:
    user_c (PUSER puser);
    ~user_c ();
  private:
    uint8_t   inUse;
    uint16_t  uid;
    uint16_t  authId;
    mystdbool canonicalized;
    SEARCH_T *searches;
    /* nulls can be interspersed in this array   */
    PFID     *fids;
};

user_c::user_c (PUSER puser)
{
  this->inUse              = puser->inUse              ;
  this->uid                = puser->uid                ;
  this->authId             = puser->authId             ;
  this->canonicalized      = puser->canonicalized      ;
  this->searches           = puser->searches           ;   //  - pointers to C structs
  this->fids               = puser->fids               ;   //
}

user_c::~user_c()
{

}

class smb_sessionCtx_c
{
  public:
    smb_sessionCtx_c (void) {};
    ~smb_sessionCtx_c ();
    void smb_sessionCtx_from_c (PSMB_SESSIONCTX pctxt);
  private:
    RTP_SOCKET sock;
    SMB_DIALECT_T dialect;      /* dialect we are speaking */
    mystdbool isSMB2;               /* Set true when SMB2 negotiated */
    mystdbool doSocketClose;        /* Set true when SMB command handler wants the network layer code to close the socket when it is convenient. */
    mystdbool doSessionClose;       /* Set true when SMB2 command handler wants the network layer code the session after the stream is flushed. */
	uint16_t  yieldFlags;
	uint32_t yieldTimeout;   // If not zero the session is yielding
    SMBS_SESSION_STATE state;   /* are we idle or waiting on something? */
    uint8_t * readBuffer;
    uint8_t * writeBuffer;
    uint32_t readBufferSize;
    uint32_t writeBufferSize;
    uint8_t * smallReadBuffer;
    uint8_t * smallWriteBuffer;
    uint8_t * read_origin;
    uint8_t * write_origin;
    uint32_t useableBufferSize;
    uint32_t current_body_size;
    uint32_t in_packet_size;
    uint32_t in_packet_timeout_base;
    uint32_t outBodySize;
    uint8_t * tmpBuffer;
    uint32_t tmpSize;
    WRITE_RAW_INFO_T writeRawInfo;
    struct s_Smb2SrvModel_Session  *pCtxtsmb2Session;
    PRTSMB_HEADER pInHeader;
    PRTSMB_HEADER pOutHeader;
    uint8_t encryptionKey [8]; /* encryptionKey used for password encryption */
    uint8_t accessMode;        /* access mode of server when session is set up */
    uint16_t sessionId;         /* this keeps value across session closes/opens */
    uint16_t uid;
    uint32_t pid;
    uint16_t tid;
    char  server_enum_domain [RTSMB_NB_NAME_SIZE + 1];
    uint32_t server_enum_type;
    USER_T *uids;
    TREE_T *trees;
    FID_T  *fids;
    int sendOplockBreakCount;
    int waitOplockAckCount;
    int sendNotifyCount;
    int protocol_version;
    SMB_SESSIONCTX_SAVE_T CtxSave;
};


void smb_sessionCtx_c::smb_sessionCtx_from_c (PSMB_SESSIONCTX pctxt)
{
    this->sock                             = pctxt->sock;
    this->dialect                          = pctxt->dialect;
    this->isSMB2                           = pctxt->isSMB2;
    this->doSocketClose                    = pctxt->doSocketClose;
    this->doSessionClose                   = pctxt->doSessionClose;
    this->yieldFlags                       = pctxt->yieldFlags;
    this->yieldTimeout                     = pctxt->yieldTimeout;
    this->state                            = pctxt->state;
    this->readBuffer                       = pctxt->readBuffer;
    this->writeBuffer                      = pctxt->writeBuffer;
    this->readBufferSize                   = pctxt->readBufferSize;
    this->writeBufferSize                  = pctxt->writeBufferSize;
    this->smallReadBuffer                  = pctxt->smallReadBuffer;
    this->smallWriteBuffer                 = pctxt->smallWriteBuffer;
    this->read_origin                      = pctxt->read_origin;
    this->write_origin                     = pctxt->write_origin;
    this->useableBufferSize                = pctxt->useableBufferSize;
    this->current_body_size                = pctxt->current_body_size;
    this->in_packet_size                   = pctxt->in_packet_size;
    this->in_packet_timeout_base           = pctxt->in_packet_timeout_base;
    this->outBodySize                      = pctxt->outBodySize;
    this->tmpBuffer                        = pctxt->tmpBuffer;
    this->tmpSize                          = pctxt->tmpSize;
    this->writeRawInfo                     = pctxt->writeRawInfo;
    this->pCtxtsmb2Session                 = pctxt->pCtxtsmb2Session;
    this->pInHeader                        = pctxt->pInHeader;
    this->pOutHeader                       = pctxt->pOutHeader;
    this->encryptionKey[0]                 = pctxt->encryptionKey[0];
    this->accessMode                       = pctxt->accessMode;
    this->sessionId                        = pctxt->sessionId;
    this->uid                              = pctxt->uid;
    this->pid                              = pctxt->pid;
    this->tid                              = pctxt->tid;
    COPYCITEM(pctxt,server_enum_domain);
// server_enum_domain               = pctxt->server_enum_domain;
    this->server_enum_type                 = pctxt->server_enum_type;
    this->uids                             = pctxt->uids;
    this->trees                            = pctxt->trees;
    this->fids                             = pctxt->fids;
    this->sendOplockBreakCount             = pctxt->sendOplockBreakCount;
    this->waitOplockAckCount               = pctxt->waitOplockAckCount;
    this->sendNotifyCount                  = pctxt->sendNotifyCount;
    this->protocol_version                 = pctxt->protocol_version;
    this->CtxSave                          = pctxt->CtxSave;
}

smb_sessionCtx_c::~smb_sessionCtx_c ()
{

}


class  net_session_c
{
public:
    net_session_c(void);
    void net_session_from_c(PNET_SESSIONCTX psession);
    ~net_session_c();
private:
   RTP_SOCKET    sock;
   uint32_t      lastActivity;
   smb_sessionCtx_c  smbCtx;
   struct net_thread_s *pThread;
};

net_session_c::net_session_c(void)
{
}

void net_session_c::net_session_from_c(PNET_SESSIONCTX psession)
{
    this->sock                     = psession-> sock         ;
    this->lastActivity             = psession-> lastActivity ;
    this->smbCtx.smb_sessionCtx_from_c(&psession-> smbCtx);
    this->pThread                  = psession-> pThread;
}

net_session_c::~net_session_c()
{

}

class  net_thread_c
{
public:
    net_thread_c(PNET_THREAD pThread);
    ~net_thread_c();
private:
    PNET_SESSIONCTX *sessionList;
    uint32_t numSessions;
    net_session_c sessionArray[CFG_RTSMB_MAX_SESSIONS];
    int blocking_session;
    int yield_sock_portnumber;
    RTP_SOCKET yield_sock;
    uint32_t index;
    uint8_t *inBuffer;
    uint8_t *outBuffer;
    uint8_t *tmpBuffer;
    mystdbool srand_is_initialized;
};

net_thread_c::net_thread_c(PNET_THREAD pThread)
{
    this->sessionList              = pThread->sessionList;
    this->numSessions              = pThread->numSessions;
    //
    for (int i=0;i<(int)pThread->numSessions;i++)  this->sessionArray[i].net_session_from_c(pThread->sessionList[i]);
    this->blocking_session         = pThread->blocking_session;
    this->yield_sock_portnumber    = pThread->yield_sock_portnumber;
    this->yield_sock               = pThread->yield_sock;
    this->index                    = pThread->index;
    this->inBuffer                 = pThread->inBuffer;
    this->outBuffer                = pThread->outBuffer;
    this->tmpBuffer                = pThread->tmpBuffer;
    this->srand_is_initialized     = pThread->srand_is_initialized;
}

net_thread_c::~net_thread_c()
{

}


class tree_c
{
public:
    tree_c(PTREE ptree);
    ~tree_c();
private:
    mystdbool inUse;
    uint8_t access;
    uint8_t type;      /* type of tree */
    uint16_t external;  /* public tid */
    uint16_t internal;  /* private tid */
    PFID *fids;
};

tree_c::tree_c(PTREE ptree)
{
  this->inUse    =   ptree->inUse   ;
  this->access   =   ptree->access  ;
  this->type     =   ptree->type    ;
  this->external =   ptree->external;
  this->internal =   ptree->internal;
  this->fids     =   ptree->fids;
}

tree_c::~tree_c()
{

}

/* 3.3.1.8 Per Session ............................................................................................. 226 */
class Smb2SrvModel_Session_c
{
public:
    Smb2SrvModel_Session_c(pSmb2SrvModel_Session psession);
    ~Smb2SrvModel_Session_c();
private:
    uint64_t                        SessionId;
    mystdbool                     RTSMBisAllocated;
    struct smb_sessionCtx_s       *pSmbCtx;
    void                          *SMB2_BodyContext;
    uint8_t                       State;
    TYPELESS                      SecurityContext;
    mystdbool                     IsAnonymous;
    mystdbool                     IsGuest;
    uint8_t                       SessionKey[16];
    mystdbool                     SigningRequired;
    uint64_t                        ExpirationTime;
    pSmb2SrvModel_Connection      Connection;
    uint32_t                      SessionGlobalId;
    FILETIME_T                    CreationTime;
    uint64_t                        IdleTime;
    uint8_t                       *UserName;
    uint8_t                       *DomainName;
    mystdbool                     EncryptData;
    uint8_t                       EncryptionKey[16];
    uint8_t                       DecryptionKey[16];
    uint8_t                       SigningKey[16];
};

Smb2SrvModel_Session_c::Smb2SrvModel_Session_c(pSmb2SrvModel_Session psession)
{
    this->SessionId              = psession->SessionId;
    this->RTSMBisAllocated       = psession->RTSMBisAllocated;
    this->pSmbCtx                = psession->pSmbCtx;
    this->SMB2_BodyContext       = psession->SMB2_BodyContext;
    this->State                  = psession->State;
    this->SecurityContext        = psession->SecurityContext;
    this->IsAnonymous            = psession->IsAnonymous;
    this->IsGuest                = psession->IsGuest;
    this->SessionKey[16]         = psession->SessionKey[16];
    this->SigningRequired        = psession->SigningRequired;
    this->ExpirationTime         = psession->ExpirationTime;
    this->Connection             = psession->Connection;
    this->SessionGlobalId        = psession->SessionGlobalId;
    this->CreationTime           = psession->CreationTime;
    this->IdleTime               = psession->IdleTime;
    this->UserName               = psession->UserName;
    this->DomainName             = psession->DomainName;
    this->EncryptData            = psession->EncryptData;
    COPYCITEM(psession,EncryptionKey);
    COPYCITEM(psession,DecryptionKey);
    COPYCITEM(psession,SigningKey);
}

Smb2SrvModel_Session_c::~Smb2SrvModel_Session_c()
{
}


class Smb2SrvModel_Connection_c {
public:
   Smb2SrvModel_Connection_c(Smb2SrvModel_Connection *pconnection);
   ~Smb2SrvModel_Connection_c();
private:
    mystdbool              RTSMBisAllocated;
    uint32_t               ClientCapabilities;
    uint16_t               NegotiateDialect;
    uint16_t               Dialect;
    mystdbool              ShouldSign;
    uint32_t               MaxTransactSize;
    uint32_t               MaxWriteSize;
    uint32_t               MaxReadSize;
    mystdbool              SupportsMultiCredit;
    uint8_t                TransportName;
    pSmb2SrvModel_Session  SessionTable[RTSMB2_CFG_MAX_SESSIONS];
    FILETIME_T             CreationTime;
    uint8_t                ClientGuid[16];
    uint32_t               ServerCapabilities;
    uint16_t               ClientSecurityMode;
    uint16_t               ServerSecurityMode;
};

Smb2SrvModel_Connection_c:: Smb2SrvModel_Connection_c(Smb2SrvModel_Connection *pconnection)
{
    this->RTSMBisAllocated          = pconnection->RTSMBisAllocated;
    this->ClientCapabilities        = pconnection->ClientCapabilities;
    this->NegotiateDialect          = pconnection->NegotiateDialect;
    this->Dialect                   = pconnection->Dialect;
    this->ShouldSign                = pconnection->ShouldSign;
    this->MaxTransactSize           = pconnection->MaxTransactSize;
    this->MaxWriteSize              = pconnection->MaxWriteSize;
    this->MaxReadSize               = pconnection->MaxReadSize;
    this->SupportsMultiCredit       = pconnection->SupportsMultiCredit;
    this->TransportName             = pconnection->TransportName;
    COPYCITEM(pconnection,SessionTable);
    this->CreationTime              = pconnection->CreationTime;
    COPYCITEM(pconnection,ClientGuid);
    this->ServerCapabilities        = pconnection->ServerCapabilities;
    this->ClientSecurityMode        = pconnection->ClientSecurityMode;
    this->ServerSecurityMode        = pconnection->ServerSecurityMode;
}
Smb2SrvModel_Connection_c:: ~Smb2SrvModel_Connection_c()
{

}

class Smb2SrvModel_Global_c {
  public:
    Smb2SrvModel_Global_c(Smb2SrvModel_Global *pglobal);
    ~Smb2SrvModel_Global_c();
  private:
    uint64_t                              RTSMBNetSessionId;
    mystdbool                           RequireMessageSigning;
    STAT_SERVER_0                       ServerStatistics;
    mystdbool                           ServerEnabled;
    pSmb2SrvModel_Session               SessionTable[RTSMB2_CFG_MAX_SESSIONS];
    pSmb2SrvModel_Connection            ConnectionList[RTSMB2_CFG_MAX_CONNECTIONS];
    uint8_t                             ServerGuid[16];
    FILETIME_T                          ServerStartTime;
    mystdbool                           IsDfsCapable;
    mystdbool                           RTSMBIsLeaseCapable;
    mystdbool                           RTSMBIsPersistentHandlesCapable;
    mystdbool                           RTSMBIsLeaseDirectoriesCapable;
    mystdbool                           RTSMBIsEncryptionCapable;
    uint32_t                            ServerSideCopyMaxNumberofChunks;
    uint32_t                            ServerSideCopyMaxChunkSize;
    uint32_t                            ServerSideCopyMaxDataSize;
    uint8_t                             ServerHashLevel;
    uint32_t                            MaxResiliencyTimeout;
    uint64_t                              ResilientOpenScavengerExpiryTime;
    uint8_t                             **EncryptionAlgorithmList;
    mystdbool                           EncryptData;
    mystdbool                           RejectUnencryptedAccess;
    mystdbool                           IsMultiChannelCapable;
    mystdbool                           IsSharedVHDSupported;
};

Smb2SrvModel_Global_c::Smb2SrvModel_Global_c(Smb2SrvModel_Global *pglobal)
{
    this->RTSMBNetSessionId = pglobal->RTSMBNetSessionId;
    this->RequireMessageSigning = pglobal->RequireMessageSigning;
    this->ServerStatistics = pglobal->ServerStatistics;
    this->ServerEnabled = pglobal->ServerEnabled;
    COPYCITEM(pglobal,SessionTable);
    COPYCITEM(pglobal,ConnectionList);
    COPYCITEM(pglobal,ServerGuid);
    this->ServerStartTime = pglobal->ServerStartTime;
    this->IsDfsCapable = pglobal->IsDfsCapable;
    this->RTSMBIsLeaseCapable = pglobal->RTSMBIsLeaseCapable;
    this->RTSMBIsPersistentHandlesCapable = pglobal->RTSMBIsPersistentHandlesCapable;
    this->RTSMBIsLeaseDirectoriesCapable = pglobal->RTSMBIsLeaseDirectoriesCapable;
    this->RTSMBIsEncryptionCapable = pglobal->RTSMBIsEncryptionCapable;
    this->ServerSideCopyMaxNumberofChunks = pglobal->ServerSideCopyMaxNumberofChunks;
    this->ServerSideCopyMaxChunkSize = pglobal->ServerSideCopyMaxChunkSize;
    this->ServerSideCopyMaxDataSize = pglobal->ServerSideCopyMaxDataSize;
    this->ServerHashLevel = pglobal->ServerHashLevel;
    this->MaxResiliencyTimeout = pglobal->MaxResiliencyTimeout;
    this->ResilientOpenScavengerExpiryTime = pglobal->ResilientOpenScavengerExpiryTime;
    this->EncryptionAlgorithmList = pglobal->EncryptionAlgorithmList;
    this->EncryptData = pglobal->EncryptData;
    this->RejectUnencryptedAccess = pglobal->RejectUnencryptedAccess;
    this->IsMultiChannelCapable = pglobal->IsMultiChannelCapable;
    this->IsSharedVHDSupported = pglobal->IsSharedVHDSupported;
}
Smb2SrvModel_Global_c::~Smb2SrvModel_Global_c()
{
}


class smb2_stream_c {
  public:
   smb2_stream_c(smb2_stream *pstream);
   ~smb2_stream_c();
  private:
    uint8_t                        *SigningKey;                           // For writes, the key for signing, For reads the key for checking the signature
    uint8_t                        SigningRule;
    struct s_Smb2SrvModel_Session  *psmb2Session;   // For a server. points to the session
    struct RTSMB_CLI_WIRE_BUFFER_s *pBuffer;        // For a client. points to the controlling SMBV1 buffer structure.
    struct RTSMB_CLI_SESSION_T     *pSession;       // For a client. points to the controlling SMBV1 session structure.
    struct RTSMB_CLI_SESSION_JOB_T *pJob;           // For a client points to the controlling SMBV1 job structure.
    int                            PadValue;                              // If the stream contains a compound message, set to the proper pad value between commands.
    int                            compound_output_index;                 // Set by output routines if the response should be sent and the processing routine called again.
    mystdbool                      EncryptMessage;                        // For write operations, encryption is required. For reads decryption is required.
    mystdbool                      Success;                               // Indicates the current state of read or write operation is succesful.
    mystdbool                      doSocketClose;                         // Indicates that the processing layer detected or enacted a session close and the socket should be closed.
    mystdbool                      doSessionClose;                        // Indicates that the processing layer is requesting a session close.
    mystdbool                      doSessionYield;                        // Indicates that the session should yield until sigalled or a timeout.
    uint32_t                       yield_duration;                         // If doSessionYield, this is the duration to wait for a signal before timing out
    RTSMB2_HEADER                  OutHdr;                                // Buffer control and header for response
    RTSMB2_BUFFER_PARM             WriteBufferParms[2];         // For writes, points to data source for data. Second slot is used in rare cases where 2 variable length parameters are present.
    PFVOID                         write_origin;                          // Points to the beginning of the buffer, the NBSS header.
    PFVOID                         saved_write_origin;                    // Original origin if the packet is beign encrypted
    PFVOID                         pOutBuf;                               // Current position in the output stream buffer.
    rtsmb_size                     write_buffer_size;
    rtsmb_size                     write_buffer_remaining;
    rtsmb_size                     OutBodySize;
    RTSMB2_HEADER                  InHdr;                            // Buffer control and header from command
    RTSMB2_BUFFER_PARM             ReadBufferParms[2];          // For reads points to sink for extra data.  Second slot is used in rare cases where 2 variable length parameters are present.
    PFVOID                         read_origin;
    rtsmb_size                     read_buffer_size;
    rtsmb_size                     read_buffer_remaining;
    rtsmb_size                     InBodySize;
    uint8_t                        LastFileId[16];                        // Filled in by create so we can replace 0xffffff with the last created FD.
    PFVOID                         saved_read_origin;
    PFVOID                         pInBuf;
    StreamInputPointerState_t      StreamInputPointerState;
};

smb2_stream_c::smb2_stream_c(smb2_stream *pstream)
{
    this->SigningKey            = pstream->SigningKey;
    this->SigningRule           = pstream->SigningRule;
    this->psmb2Session          = pstream->psmb2Session;
    this->pBuffer               = pstream->pBuffer;
    this->pSession              = pstream->pSession;
    this->pJob                  = pstream->pJob;
    this->PadValue              = pstream->PadValue;
    this->compound_output_index = pstream->compound_output_index;
    this->EncryptMessage        = pstream->EncryptMessage;
    this->Success               = pstream->Success;
    this->doSocketClose         = pstream->doSocketClose;
    this->doSessionClose        = pstream->doSessionClose;
    this->doSessionYield        = pstream->doSessionYield;
    this->yield_duration        = pstream->yield_duration;
    this->OutHdr                 = pstream->OutHdr;
    COPYCITEM(pstream,WriteBufferParms);
    this->write_origin          = pstream->write_origin;
    this->saved_write_origin    = pstream->saved_write_origin;
    this->pOutBuf               = pstream->pOutBuf;
    this->write_buffer_size     = pstream->write_buffer_size;
    this->write_buffer_remaining= pstream->write_buffer_remaining;
    this->OutBodySize           = pstream->OutBodySize;
    this->InHdr                 = pstream->InHdr;
    COPYCITEM(pstream,ReadBufferParms);
    this->read_origin            = pstream->read_origin;
    this->read_buffer_size       = pstream->read_buffer_size;
    this->read_buffer_remaining  = pstream->read_buffer_remaining;
    this->InBodySize             = pstream->InBodySize;
    COPYCITEM(pstream,LastFileId);
    this->saved_read_origin      = pstream->saved_read_origin;
    this->pInBuf                 = pstream->pInBuf;
    this->StreamInputPointerState= pstream->StreamInputPointerState;
}
smb2_stream_c::~smb2_stream_c()
{
}


#if(0)

typedef struct _RTSMB_SERVER_CONTEXT
{
	/* CONFIGURATION PARAMETERS */
	unsigned short    max_threads;
	unsigned short    max_sessions;
	unsigned short    max_uids_per_session;
	unsigned short    max_fids_per_tree;
	unsigned short    max_fids_per_uid;
	unsigned short    max_fids_per_session;
	unsigned short    max_trees_per_session;
	unsigned short    max_searches_per_uid;
	unsigned short    max_shares;
	unsigned short    max_users;
	unsigned short    max_groups;
    unsigned long     max_smb2_transaction_size;
    unsigned short    max_smb1_transaction_size;
	unsigned long     small_buffer_size;
	unsigned long     temp_buffer_size;
	unsigned long     in_buffer_size;
	unsigned long     out_buffer_size;
	unsigned long     big_buffer_size;
	unsigned short    num_big_buffers;
	int               enum_results_size;
	mystdbool         enum_results_in_use;
	int               server_table_size;
	int               domain_table_size;
    mystdbool             enable_oplocks;

	/* MUTEX HANDLES */
	unsigned long     bufsem;
	unsigned long     authsem;
	unsigned long     sharesem;
	unsigned long     printersem;
	unsigned long     cachesem;
	unsigned long     mailPDCNameSem;
	unsigned long     netsem;
	unsigned long    *activeSessions;
	unsigned long     enum_results_mutex;

	/* BUFFER POOLS */
	uint8_t *                   bigBuffers;
	PFCHAR                      bigBufferInUse;
	PNET_THREAD                 threads;
	PFCHAR                      threadsInUse;
	PNET_SESSIONCTX             sessions;
	PFCHAR                      sessionsInUse;
	uint8_t *                   namesrvBuffer;
	uint8_t *                   client_buffer;
	PSR_RESOURCE                shareTable;
	PRTSMB_BROWSE_SERVER_INFO   enum_results;
	PRTSMB_BROWSE_SERVER_INFO   server_table;
	PRTSMB_BROWSE_SERVER_INFO   domain_table;

	/* OTHER STUFF */
	uint8_t           shareMode;
	short             guestAccount;
	GROUPS_T          groupList;
	USERLIST_T        userList;
	PFCHAR            local_master;
    PNET_THREAD       mainThread;
}



typedef struct net_thread_s
{
	/**
	 * This list points to all the sessions this thread manages.
	 */
	PNET_SESSIONCTX *sessionList;
	uint32_t numSessions;

	/**
	 * This indicates a session that we need to service, and
	 * no others.  Usually, that means it is holding on to data
	 * in the buffer that shouldn't be overwritten.
	 *
	 * A value of -1 means no session is blocking.
	 */
	int blocking_session;

	int yield_sock_portnumber;
    RTP_SOCKET yield_sock;

	/**
	 * Index stores the index of the last session we serviced.
	 * This helps us avoid always servicing one session first.
	 */
	uint32_t index;

	/**
	 * These buffers hold the incoming data and the outgoing data for the current
	 * session being processed.
	 */
	uint8_t *inBuffer;
	uint8_t *outBuffer;
	uint8_t *tmpBuffer;

	/**
	 * This is FALSE if we have not yet initialized our random number
	 * generator, TRUE if we have.
	 */
	mystdbool srand_is_initialized;

} NET_THREAD_T;
typedef NET_THREAD_T RTSMB_FAR *PNET_THREAD;


typedef struct
{
	RTP_SOCKET    sock;
	unsigned long lastActivity;
	SMB_SESSIONCTX_T smbCtx;
    struct net_thread_s *pThread;
} NET_SESSIONCTX_T;
typedef NET_SESSIONCTX_T RTSMB_FAR *PNET_SESSIONCTX;

typedef struct user_s
{
    uint8_t inUse;
    uint16_t uid;
    uint16_t authId;
    mystdbool canonicalized;

    SEARCH_T *searches;

    /* nulls can be interspersed in this array   */
    PFID *fids;

} USER_T;

typedef struct search_s
{
    mystdbool inUse;

    unsigned long lastUse;
    uint16_t tid; /* tid this belongs to.  struct maybe should be put in TREE_T */
#ifdef SUPPORT_SMB2
    rtsmb_char name[SMBF_FILENAMESIZE + 1]; // SMB2 may restart the search with the original pattern
    uint8_t    FileId[16];                     // There's no sid instead use file id
    uint64_t pid64; /* pid this belongs to. */
#else
    uint64_t pid; /* pid this belongs to. */
#endif
    SMBDSTAT stat;
} SEARCH_T;
typedef SEARCH_T RTSMB_FAR *PSEARCH;

#define FID_FLAG_DIRECTORY      0x0001
#define FID_FLAG_ALL            0xFFFF
typedef struct fid_s
{
    int internal_fid;   /* -1 means not in use */
    uint16_t external;

    uint16_t flags;
#define SMB2FIDSIG 0x11000000
#define SMB2DELONCLOSE SMB2FIDSIG|0x01
#define SMB2SENDOPLOCKBREAK  0x02
#define SMB2WAITOPLOCKREPLY  0x04
#define SMB2OPLOCKHELD       0x08
#define SMB2WAITLOCKREGION   0x10   /* not used yet */
    uint32_t smb2flags;
    uint8_t held_oplock_level;         /* current level if (smb2flags&SMB2OPLOCKHELD) */
    uint16_t held_oplock_uid;
    uint8_t requested_oplock_level;    /* requested level if (smb2flags&SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY)  */
    uint32_t smb2waitexpiresat;        /* Timer expires if !0 and SMB2WAITOPLOCKREPLY|SMB2WAITLOCKREGION */
    uint16_t tid;       /* owning tree */
    uint16_t uid;       /* owning user */
    uint32_t pid;      /* owning process */
    uint32_t error;    /* delayed error */
    unsigned char  unique_fileid[8];        /* The on-disk inode that identifies it uniquely on the volume. */
    rtsmb_char name[SMBF_FILENAMESIZE + 1];
} FID_T;
typedef FID_T RTSMB_FAR *PFID;

typedef struct tree_s
{
    mystdbool inUse;
    uint8_t access;

    uint8_t type;      /* type of tree */

    uint16_t external;  /* public tid */
    uint16_t internal;  /* private tid */

    /* nulls can be interspersed in this array   */
    PFID *fids;

} TREE_T;
typedef TREE_T RTSMB_FAR *PTREE;

typedef struct sr_resource_s
{
	mystdbool inUse;		// does this resource contain valid data?

	SHARE_T stype;		// the type of shared resource
	rtsmb_char name[RTSMB_MAX_SHARENAME_SIZE + 1];	// the name of the shared resources
	rtsmb_char comment[RTSMB_MAX_COMMENT_SIZE + 1];	// comment about shared resource
	uint8_t permission;	// what permissions the password for this share gives
	PFCHAR password;	// pointer to passwordBuf or NULL if we don't need it
	char passwordBuf[CFG_RTSMB_MAX_PASSWORD_SIZE + 1];

	// FIXME: code in expandName (in smbfio.c) requires that
	// disktree and printer share their similar info both at the
	// beginning of structs (it refers to u.disktree even for a printer)
	union {
		struct {
			rtsmb_char path[MAX_PATH_PREFIX_SIZE + 1];	// path to local resource
			PSMBFILEAPI api;	// API for accessing files on this share
			int flags;
			rtsmb_char separator;

		} disktree;

		struct {
			rtsmb_char path[MAX_PATH_PREFIX_SIZE + 1];	// path to local resource
			PSMBFILEAPI api;	// API for accessing files on this share
			int flags;
			rtsmb_char separator;
		} ipctree;
		struct {
			rtsmb_char path[MAX_PATH_PREFIX_SIZE + 1];	// path to local resource
			PSMBFILEAPI api;	// API for accessing files on this share
			int flags;
			rtsmb_char separator;
			int num;

			/* printer file is used right now to store the driver name for the printer */
			PFRTCHAR printerfile;
			rtsmb_char printerfileBuf [SMBF_FILENAMESIZE + 1];

		} printer;
	} u;

} SR_RESOURCE_T;
typedef SR_RESOURCE_T RTSMB_FAR *PSR_RESOURCE;

typedef struct access_table_s
{
	rtsmb_char name [CFG_RTSMB_MAX_GROUPNAME_SIZE + 1];
	uint8_t *table;

} ACCESS_TABLE_T;
typedef ACCESS_TABLE_T RTSMB_FAR *PACCESS_TABLE;

typedef struct groups_s
{
	uint8_t numGroups;

	ACCESS_TABLE_T *groups;

} GROUPS_T;
typedef GROUPS_T RTSMB_FAR *PGROUPS;


typedef struct user_data_s
{
	mystdbool inUse;
	rtsmb_char name[CFG_RTSMB_MAX_USERNAME_SIZE + 1];		// username
	PFCHAR password;
	char password_buf[CFG_RTSMB_MAX_PASSWORD_SIZE + 1];	// password for user
	mystdbool *groups; 	// whether this user is in each group
					// using a whole uint8_t for each group is a little wasteful,
					// but there shouldn't be many groups, and overhead for groups is large
					// This way we don't want to require a multiple of 4 number of groups

} USERDATA_T;
typedef USERDATA_T RTSMB_FAR *PUSERDATA;

// These two routines save the necessary pointers in the stream structure
// So that SMB2 create and write commands can exit and leave the stream strcuture usable in a replay
typedef struct StreamInputPointerState_s
{
  void *pInBuf;
  rtsmb_size read_buffer_remaining;
} StreamInputPointerState_t;


typedef struct smb2_stream_s {
     // Signing rules. Set by calling smb2_stream_set_signing_rule
    uint8_t     *SigningKey;                           // For writes, the key for signing, For reads the key for checking the signature
#define SIGN_NONE         0                         // - Used for 3.x. Generates 16 uint8_t hash over entire message including Header and padding.
#define SIGN_AES_CMAC_128 1                         // - Used for 3.x. Generates 16 uint8_t hash over entire message including Header and padding.
#define SIGN_HMAC_SHA256  2                         // - Used for 2.002 and 2.100 generates 32 uint8_t hash over entire message including Header and padding. Copy low 16 bytes into the keyfield
    uint8_t     SigningRule;
    struct s_Smb2SrvModel_Session  *psmb2Session;   // For a server. points to the session
    struct RTSMB_CLI_WIRE_BUFFER_s *pBuffer;        // For a client. points to the controlling SMBV1 buffer structure.
    struct RTSMB_CLI_SESSION_T     *pSession;       // For a client. points to the controlling SMBV1 session structure.
//    struct Rtsmb2ClientSession_s   *psmb2Session;   // For a client. points to smb2 session structure
    struct RTSMB_CLI_SESSION_JOB_T *pJob;           // For a client points to the controlling SMBV1 job structure.

    int      PadValue;                              // If the stream contains a compound message, set to the proper pad value between commands.
    int      compound_output_index;                 // Set by output routines if the response should be sent and the processing routine called again.
    mystdbool    EncryptMessage;                        // For write operations, encryption is required. For reads decryption is required.
    mystdbool    Success;                               // Indicates the current state of read or write operation is succesful.
    mystdbool    doSocketClose;                         // Indicates that the processing layer detected or enacted a session close and the socket should be closed.
    mystdbool    doSessionClose;                        // Indicates that the processing layer is requesting a session close.
    mystdbool    doSessionYield;                        // Indicates that the session should yield until sigalled or a timeout.
    uint32_t    yield_duration;                         // If doSessionYield, this is the duration to wait for a signal before timing out
    RTSMB2_HEADER OutHdr;                           // Buffer control and header for response
	RTSMB2_BUFFER_PARM WriteBufferParms[2];         // For writes, points to data source for data. Second slot is used in rare cases where 2 variable length parameters are present.
	PFVOID   write_origin;                          // Points to the beginning of the buffer, the NBSS header.
	PFVOID   saved_write_origin;                    // Original origin if the packet is beign encrypted
    PFVOID   pOutBuf;                               // Current position in the output stream buffer.
    rtsmb_size write_buffer_size;
    rtsmb_size write_buffer_remaining;
    rtsmb_size OutBodySize;
    RTSMB2_HEADER InHdr;                            // Buffer control and header from command
	RTSMB2_BUFFER_PARM ReadBufferParms[2];          // For reads points to sink for extra data.  Second slot is used in rare cases where 2 variable length parameters are present.
	PFVOID   read_origin;
    rtsmb_size read_buffer_size;
    rtsmb_size read_buffer_remaining;
    rtsmb_size InBodySize;
    uint8_t     LastFileId[16];                        // Filled in by create so we can replace 0xffffff with the last created FD.
                                                    // Cleared before processing a packet (compound request)
	PFVOID   saved_read_origin;
    PFVOID   pInBuf;
    StreamInputPointerState_t StreamInputPointerState;

} smb2_stream;

typedef struct ProcSMB2_BodyContext_s {
  uint32_t *pPreviousNextOutCommand;
  mystdbool isCompoundReply;
  mystdbool doFirstPacket;
  uint32_t NextCommandOffset;
  smb2_stream  smb2stream;
  PFVOID   pInBufStart;
  PFVOID   pOutBufStart;
  mystdbool    sign_packet;
#define ST_INIT        0
#define ST_INPROCESS   1
#define ST_FALSE       2
#define ST_TRUE        3
#define ST_YIELD       4
  int      stackcontext_state;
  uint32_t  yield_duration; // Timneout in milliseconds if ST_YIELD is requested
} ProcSMB2_BodyContext;


/* MS-SRVS 2.2.4.39 .................................................................. 56*/
typedef struct _STAT_SERVER_0 {
    uint32_t sts0_start;
    uint32_t sts0_fopens;
    uint32_t sts0_devopens;
    uint32_t sts0_jobsqueued;
    uint32_t sts0_sopens;
    uint32_t sts0_stimedout;
    uint32_t sts0_serrorout;
    uint32_t sts0_pwerrors;
    uint32_t sts0_permerrors;
    uint32_t sts0_syserrors;
    uint32_t sts0_bytessent_low;
    uint32_t sts0_bytessent_high;
    uint32_t sts0_bytesrcvd_low;
    uint32_t sts0_bytesrcvd_high;
    uint32_t sts0_avresponse;
    uint32_t sts0_reqbufneed;
    uint32_t sts0_bigbufneed;
} STAT_SERVER_0;

/* 3.3.1.5 Global .................................................................................................... 223 */
typedef struct s_Smb2SrvModel_Global {
    ddword     RTSMBNetSessionId;           /*  Session ID, increased by one every time a session is created */
    mystdbool RequireMessageSigning;            /*  A Boolean that, if set, indicates that this node requires that messages MUST be signed if the message is sent
                                                with a user security context that is neither anonymous nor guest. If not set, this node does not require that
                                                any messages be signed, but can still choose to do so if the other node requires it. */
    STAT_SERVER_0 ServerStatistics;         /*  Server statistical information. This contains all the members of STAT_SRV_0 structure as specified
                                                in [MS-SRVS] section 2.2.4.39. */
    mystdbool ServerEnabled;                    /*  Indicates whether the SMB2 server is accepting incoming connections or requests. */
        /*  A list of available shares for the system. The structure of a share is as specified in
            section 3.3.1.6 and is uniquely indexed by the tuple <Share.ServerName, Share.Name>. */
// UNUSED    pSmb2SrvModel_Share ShareList[RTSMB2_CFG_MAX_SHARES];
        /*  A table containing all the files opened by remote clients on the server, indexed by Open.DurableFileId. The structure of
            an open is as specified in section 3.3.1.10. The table MUST support enumeration of all entries in the table. */
// UNUSED    pSmb2SrvModel_Open OpenTable[RTSMB2_CFG_MAX_OPENS];
        /*  A list of all the active sessions established to this server, indexed by the Session.SessionId. */
    pSmb2SrvModel_Session  SessionTable[RTSMB2_CFG_MAX_SESSIONS];   // See: Smb2Sessions
        /*  A list of all open connections on the server, indexed by the connection endpoint addresses. */
    pSmb2SrvModel_Connection ConnectionList[RTSMB2_CFG_MAX_CONNECTIONS];
    /* Examle uuid value {f81d4fae-7dec-11d0-a765-00a0c91e6bf6} - RFC4122*/
    uint8_t ServerGuid[16];                    /*  A global identifier for this server. [MS-DTYP] section 2.3.4 */
    FILETIME_T ServerStartTime;             /*  The start time of the SMB2 server, in FILETIME format as specified in [MS-DTYP] section 2.3.3. */
    mystdbool IsDfsCapable;                     /*  Indicates that the server supports the Distributed File System. */
    mystdbool RTSMBIsLeaseCapable;              /*  Indicates that the server supports leasing. */
    mystdbool RTSMBIsPersistentHandlesCapable;  /*  Indicates that the server supports persistent handles. */
    mystdbool RTSMBIsLeaseDirectoriesCapable;   /*  Indicates that the server supports leasing directories. */
    mystdbool RTSMBIsEncryptionCapable;         /*  Indicates that the server supports encryption. */

    uint32_t ServerSideCopyMaxNumberofChunks;  /*  The maximum number of chunks the server will accept in a server side copy operation. */
    uint32_t ServerSideCopyMaxChunkSize;       /*  The maximum number of bytes the server will accept in a single chunk for a server side copy operation. */
    uint32_t ServerSideCopyMaxDataSize;        /*  The maximum total number of bytes the server will accept for a server side copy operation. */
    /* If the server implements the SMB 2.1 or SMB 3.x dialect family, it MUST implement the following; */
#define HashEnableAll   1       /*  Indicates that caching is enabled for all shares on the server. */
#define HashDisableAll  2       /*  Indicates that caching is disabled for all shares on the server. */
#define HashEnableShare 3       /*  Indicates that caching is enabled or disabled on a per-share basis */
    uint8_t ServerHashLevel;       /*  A state that indicates the caching level configured on the server. It takes any of the following three values: */
// UNUSED    pSmb2SrvModel_LeaseTable GlobalLeaseTableList[RTSMB2_CFG_MAX_CONNECTIONS]; /*  A list of all the lease tables as described in 3.3.1.11, indexed by the ClientGuid. */
    uint32_t MaxResiliencyTimeout;             /*  The maximum resiliency time-out in milliseconds, for the TimeOut field of NETWORK_RESILIENCY_REQUEST Request as specified in section 2.2.31.3. */
    ddword ResilientOpenScavengerExpiryTime;/*  The time at which the Resilient Open Scavenger Timer, as specified in section 3.3.2.4, is currently set to expire. */
    /* If the server implements the SMB 3.x dialect family, it MUST implement the following; */
    uint8_t  **EncryptionAlgorithmList;        /*  A list of strings containing the encryption algorithms supported by the server. */
    mystdbool EncryptData;                      /*  Indicates that the server requires messages to be encrypted after session establishment, per the conditions specified in section 3.3.5.2.9. */
    mystdbool RejectUnencryptedAccess;          /*  Indicates that the server will reject any unencrypted messages. This flag is applicable only if EncryptData is TRUE or if Share.EncryptData (as defined in section 3.3.1.6) is TRUE. */
    mystdbool IsMultiChannelCapable;            /*  Indicates that the server supports the multichannel capability. */
/* If the server implements the SMB 3.02 dialect, it MUST implement the following; */
    mystdbool IsSharedVHDSupported;             /*  Indicates that the server supports shared virtual disks. */
} Smb2SrvModel_Global;


/* 3.3.1.6 Per Share ............................................................................................... 224 */



/* 3.3.1.7 Per Transport Connection ......................................................................... 225 */
typedef struct s_Smb2SrvModel_Connection
{
    mystdbool  RTSMBisAllocated;
// UNUSED    ddword CommandSequenceWindow[2];    /*  A list of the sequence numbers that is valid to receive from the client at this time.
//                                            For more information, see section 3.3.1.1. */
// UNUSED    pSmb2SrvModel_Request RequestList;     /*  A list of requests, as specified in section 3.3.1.13, that are currently
//                                            being processed by the server. This list is indexed by the MessageId field. */
    uint32_t   ClientCapabilities;        /*  The capabilities of the client of this connection in a form that MUST
                                             follow the syntax as specified in section 2.2.3. */
    uint16_t    NegotiateDialect;          /*  A numeric value representing the current state of dialect negotiation
                                            between the client and server on this transport connection. */
    uint16_t Dialect;                      /*    The dialect of SMB2 negotiated with the client. This value MUST be either
                                            "2002", "2.100", "3.000", "3.002" or "Unknown". For the purpose of
                                            These are defined symbolically in SMB2_DIALECT_2002 et al in smb2_wiredefs.h
                                            generalization in the server processing rules, the condition that
                                            Connection.Dialect is equal to "3.000" or "3.002" is referred to as
                                            Connection.Dialect belongs to the SMB 3.x dialect family¡¨. */
// UNUSED    pSmb2SrvModel_Request AsyncCommandList;/*  A list of client requests being handled asynchronously. Each request MUST
//                                            have been assigned an AsyncId. */
    mystdbool ShouldSign;                   /*  Indicates that all sessions on this connection (with the exception of
                                            anonymous and guest sessions) MUST have signing enabled. */
                            /*  A null-terminated Unicode UTF-16 IP address string, or NetBIOS host name of the client machine. */
// UNUSED    uint8_t ClientName[RTSMB2_MAX_QUALIFIED_CLIENTNAME_SIZE];
    uint32_t MaxTransactSize;              /*  The maximum buffer size, in bytes, that the server allows on the transport
                                            that established this connection for QUERY_INFO, QUERY_DIRECTORY, SET_INFO
                                            and CHANGE_NOTIFY operations. This field is applicable only for buffers sent
                                            by the client in SET_INFO requests, or returned from the server in QUERY_INFO,
                                            QUERY_DIRECTORY, and CHANGE_NOTIFY responses. */
    uint32_t MaxWriteSize;                 /*  The maximum buffer size, in bytes, that the server allows to be written on
                                            the connection using the SMB2 WRITE Request. */
    uint32_t MaxReadSize;                  /*  The maximum buffer size, in bytes, that the server allows to be read on the
                                            connection using the SMB2 READ Request. */

    mystdbool SupportsMultiCredit;          /*  Indicates whether the connection supports multi-credit operations. */

    uint8_t TransportName;                 /*  UNUSED (RTSMB2_TRANSPORT_SMB_OVER_RDMA|RTSMB2_TRANSPORT_SMB_OVER_TCP) An implementation-specific name of the transport used by this connection. */
                                        /*  A table of authenticated sessions, as specified in section 3.3.1.8,
                                            established on this SMB2 transport connection. The table MUST allow lookup
                                            by both Session.SessionId and by the security context of the user that
                                            established the connection. */
    pSmb2SrvModel_Session SessionTable[RTSMB2_CFG_MAX_SESSIONS];
    FILETIME_T CreationTime;            /*  The time when the connection was established. */
       /* If the server implements the SMB 2.1 or 3.x dialect family, it MUST implement the following;  */
    uint8_t ClientGuid[16];                /*  An identifier for the client machine. */
       /* If the server implements the SMB 3.x dialect family, it MUST implement the following;  */
    uint32_t ServerCapabilities;           /*  The capabilities sent by the server in the SMB2 NEGOTIATE Response on this
                                            connection, in a form that MUST follow the syntax as specified in section 2.2.4. */
    uint16_t ClientSecurityMode;            /*  The security mode sent by the client in the SMB2 NEGOTIATE request on this
                                            connection, in a form that MUST follow the syntax as specified in section 2.2.3. */
    uint16_t ServerSecurityMode;            /*  The security mode received from the server in the SMB2 NEGOTIATE response
                                            on this connection, in a form that MUST follow the syntax as specified in
                                            section 2.2.4. */
} Smb2SrvModel_Connection;

typedef struct smb_sessionCtx_sessionCtxSave_s
{
    uint8_t * readBuffer;
    uint8_t * writeBuffer;
    uint32_t readBufferSize;
    uint32_t writeBufferSize;
    uint8_t * smallReadBuffer;
    uint8_t * smallWriteBuffer;
} SMB_SESSIONCTX_SAVE_T;
typedef SMB_SESSIONCTX_SAVE_T RTSMB_FAR *PSMB_SESSIONCTX_SAVE;


typedef struct smb_sessionCtx_s
{
    RTP_SOCKET sock;

    SMB_DIALECT_T dialect;      /* dialect we are speaking */
    mystdbool isSMB2;               /* Set true when SMB2 negotiated */
    mystdbool doSocketClose;        /* Set true when SMB command handler wants the network layer code to close the socket when it is convenient. */
    mystdbool doSessionClose;       /* Set true when SMB2 command handler wants the network layer code the session after the stream is flushed. */

#define YIELDSIGNALLED         0x01   /* if a yielded event was signaled */
#define YIELDTIMEDOUT          0x02   /* if a yielded event timed out without being signaled */
	uint16_t  yieldFlags;
	uint32_t yieldTimeout;   // If not zero the session is yielding

    SMBS_SESSION_STATE state;   /* are we idle or waiting on something? */

    /**
     * Pointers to the buffers we are currently using for reading or writing.
     */
    uint8_t * readBuffer;
    uint8_t * writeBuffer;

    /**
     * We list the size of the current read/write buffers so that we know
     * what is safe to read from wire.
     */
    uint32_t readBufferSize;
    uint32_t writeBufferSize;

    /**
     * Here we house default reading/writing buffers that can handle everyday
     * messaging needs.
     */
    uint8_t * smallReadBuffer;
    uint8_t * smallWriteBuffer;

    /**
     * Points to beginning of SMB.
     */
    uint8_t * read_origin;
    uint8_t * write_origin;


    /**
     * We also need to keep track of the size we are willing to use from small
     * buffers, since client's buffer may be smaller than ours.
     */
    uint32_t useableBufferSize;

    /**
     * Used to record how large the body of our currently-being-procesed
     * incoming SMB is.
     */
    uint32_t current_body_size;

    /**
     * Used to record how big the current incoming packet is.
     */
    uint32_t in_packet_size;

    /**
     * Used to record when we will stop trying to complete the current packet.
     */
    uint32_t in_packet_timeout_base;

    /**
     * Size of our current outgoing packet.
     */
    uint32_t outBodySize;

    /**
     * Holds temporary read and write data.
     */
    uint8_t * tmpBuffer;
    uint32_t tmpSize;


    /**
     * A helper variable to hold on raw writes.
     */
    WRITE_RAW_INFO_T writeRawInfo;

#ifdef SUPPORT_SMB2
    struct s_Smb2SrvModel_Session  *pCtxtsmb2Session;
#endif
    /* Below here is all smbv1 and should be in a seperate union.   */
    /**
     * headers
     */
    PRTSMB_HEADER pInHeader;
    PRTSMB_HEADER pOutHeader;



    uint8_t encryptionKey [8]; /* encryptionKey used for password encryption */

    uint8_t accessMode;        /* access mode of server when session is set up */

    uint16_t sessionId;         /* this keeps value across session closes/opens */

    /**
     * Set some flags to let processing functions know what's going on without
     * having to pass a lot of info on around on the stack.
     *
     * These are the values for the smb being processed.
     */
    uint16_t uid;
    uint32_t pid;
    uint16_t tid;

    /**
     * Some helper data we keep around to answer net_server_enum's.
     */
    char  server_enum_domain [RTSMB_NB_NAME_SIZE + 1];
    uint32_t server_enum_type;


    /**
     * This array holds all the information on
     * all the users logged in over this session.
     */
    /* list of users for this session   */
    USER_T *uids;

    /* holds tree data   */
    TREE_T *trees;

    /* fids for this session   */
    FID_T  *fids;

    /* number of fids currently queued for oplock break send */
    int sendOplockBreakCount;

    /* number of fids currently blocked waiting for oplock break ack */
    int waitOplockAckCount;

    /* number of fids currently queued for sending a notify request */
    int sendNotifyCount;

    /* session defaults to smb1 but we push saved buffers here when we assing and SMB2 seesion */
    int protocol_version;
    SMB_SESSIONCTX_SAVE_T CtxSave;

} SMB_SESSIONCTX_T;
typedef SMB_SESSIONCTX_T RTSMB_FAR *PSMB_SESSIONCTX;


/* 3.3.1.8 Per Session ............................................................................................. 226 */
typedef struct s_Smb2SrvModel_Session
{
    ddword  SessionId;                  /* A numeric value that is used as an index in GlobalSessionTable, and (transformed into a 64-bit number)
                                           is sent to clients as the SessionId in the SMB2 header. */
    mystdbool   RTSMBisAllocated;
    struct smb_sessionCtx_s *pSmbCtx;   /* Temporary - Point back to the SMB1 session that links to this session */
    void *SMB2_BodyContext;             /* Dynamically allocated saved cmntext if the session is preempted so it can wait for a client to  clear an oplock and reply */

#define Smb2SrvModel_Session_State_InProgress  1
#define Smb2SrvModel_Session_State_Valid       2
#define Smb2SrvModel_Session_State_Expired     3
        /* The current activity state of this session. This value MUST be either InProgress, Valid, or Expired. */
    uint8_t     State;
    TYPELESS SecurityContext;           /* The security context of the user that authenticated this session. This value MUST be in
                                           a form that allows for evaluating security descriptors within the server, as well as
                                           being passed to the underlying object store to handle security evaluation that may
                                           happen there. */
    mystdbool IsAnonymous;                  /* Indicates that the session is for an anonymous user. */
    mystdbool IsGuest;                      /* Indicates that the session is for a guest user. */
    uint8_t SessionKey[16];                /* The first 16 bytes of the cryptographic key for this authenticated context. If the cryptographic key is less than
                                           16 bytes, it is right-padded with zero bytes. */
    mystdbool SigningRequired;              /* Indicates that all of the messages for this session MUST be signed. */
// UNUSED    pSmb2SrvModel_Open OpenTable;          /* A table of opens of files or named pipes, as specified in section 3.3.1.10, that have been opened by this
//                                           authenticated session and indexed by Open.FileId. The server MUST support enumeration of all entries in the table. */
// UNUSED    pSmb2SrvModel_TreeConnect TreeConnectTable; /* A table of tree connects that have been established by this authenticated session to
//                                                shares on this server, indexed by TreeConnect.TreeId. The server MUST allow enumeration of all entries in the table. */
    ddword   ExpirationTime;            /* A value that specifies the time after which the client must reauthenticate with the server.*/
    pSmb2SrvModel_Connection Connection;   /* The connection on which this session was established (see also section 3.3.5.5.1). */
    uint32_t    SessionGlobalId;           /* A numeric 32-bit value obtained via registration with [MS-SRVS], as specified in [MS-SRVS] section 3.1.6.2. */
    FILETIME_T CreationTime;            /* The time the session was established. */
    ddword   IdleTime;                  /* The time the session processed its most recent request. */
    uint8_t    *UserName;                  /* The name of the user who established the session. */
    uint8_t    *DomainName;                /* The domain of the user who established the session. */
        /* If the server implements the SMB 3.x dialect family, it MUST implement the following  */
// UNUSED    pSmb2SrvModel_Channel ChannelList[RTSMB2_CFG_MAX_CHANNELS_PER_SESSION];/* A list of channels that have been established on this authenticated session, as specified in section 3.3.1.14. */
    mystdbool EncryptData;                  /* Indicates that the messages on this session SHOULD be encrypted. */
    uint8_t EncryptionKey[16];             /* A 128-bit key used for encrypting the messages sent by the server. */
    uint8_t DecryptionKey[16];             /* A 128-bit key used for decrypting the messages received from the client. */
    uint8_t SigningKey[16];                /* A 128 bit key used for signing the SMB2 messages. */
// UNUSED    uint8_t ApplicationKey[16];            /* A 128-bit key, for the authenticated context, that is queried by the higher-layer applications. */
} Smb2SrvModel_Session;



#endif
