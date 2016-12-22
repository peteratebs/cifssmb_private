#ifndef __SRV_SSN_H__
#define __SRV_SSN_H__
/*****************************************************************************   */
/***                                                                             */
/***    SRVSSN.H                                                                 */
/***    Header - Description                                                     */
/***                                                                             */
/***                                                                             */
/*****************************************************************************   */
/*============================================================================   */
/*    INTERFACE REQUIRED HEADERS                                                 */
/*============================================================================   */
#include "smbdefs.h"
#if (INCLUDE_RTSMB_SERVER)

#include "psmbfile.h"
#include "srvshare.h"
#include "smb.h"
#include "smbobjs.h"
#include "smbnb.h"
#include "smbnbss.h"
#include "com_smb2_ssn.h"
#include "srv_smb2_model.h"

/*============================================================================   */
/*    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS                     */
/*============================================================================   */

#define SMB_BUFFER_SIZE     (prtsmb_srv_ctx->small_buffer_size - RTSMB_NBSS_HEADER_SIZE)
#define SMB_BIG_BUFFER_SIZE (prtsmb_srv_ctx->big_buffer_size - RTSMB_NBSS_HEADER_SIZE)

/* A is a smb context   */
#define SMB_INBUF(A)    (&A->readBuffer[RTSMB_NBSS_HEADER_SIZE])
#define SMB_OUTBUF(A)   (&A->writeBuffer[RTSMB_NBSS_HEADER_SIZE])

/* A is a smb header   */
#define SMB_PID(A)      ((((dword) A->extra.pidHigh) << 16) | A->pid)

typedef enum // smbs_session_state
{
#ifdef SUPPORT_SMB2
    NOTCONNECTED,       /* -> IDLE                             - ready and waiting for input, protocol V1 or V2 not yet identified */
    OPLOCK_WAITING,       /* -> OPLOCK_SIGNALLED,IDLE                                          */
    OPLOCK_SIGNALLED,     /* -> anything                         - ready and waiting for input */
#endif
    IDLE,               /* -> anything                         - ready and waiting for input */
    READING,            /* -> IDLE                             - in the middle of reading a packet */
    BROWSE_MUTEX,       /* -> BROWSE_SENT, BROWSE_FAIL         - waiting for resources to clear so we can netenum2 */
    BROWSE_SENT,        /* -> BROWSE_FINISH, BROWSE_FAIL       - waiting on response to our netenum2 */
    BROWSE_FINISH,      /* -> IDLE                             - data is here (or error occured), send answer to netenum2 */
    BROWSE_FAIL,        /* -> IDLE                             - something bad happened during enum (no domain) */
    WAIT_ON_PDC_NAME,   /* -> FINISH_NEGOTIATE, FAIL_NEGOTIATE - waiting to discover primary domain controller's name */
    WAIT_ON_PDC_IP,     /* -> FINISH_NEGOTIATE, FAIL_NEGOTIATE - waiting to discover primary domain controller's ip */
    FAIL_NEGOTIATE,     /* -> IDLE                             - negotiation failed -- send error message back */
    FINISH_NEGOTIATE,   /* -> IDLE                             - authentication succeeded, continue with negotiate */
    WRITING_RAW,        /* -> IDLE, WRITING_RAW_READING        - awaiting a large packet as part of a write raw request */
    WRITING_RAW_READING /* -> IDLE                             - in the middle of reading a large packet for write raw */
} SMBS_SESSION_STATE;

/*============================================================================   */
/*    INTERFACE STRUCTURES / UTILITY CLASSES                                     */
/*============================================================================   */

/**
 * Here's the deal with trees, fids, and users.
 *
 * A session can hold any number of user ids, trees and fids.
 * Trees can be accessed by any user.  Fids can only be accessed by
 * the creating user.  When a tree is disconnected (by any user), all
 * files it held are closed.  When a user logs off, all files he/she owned
 * are closed.
 */

#define FID_FLAG_DIRECTORY      0x0001
#define FID_FLAG_ALL            0xFFFF

typedef struct fidobject_s
{
  int die;                                // For testing, poke this every time we access it
  int reference_count;
   byte held_oplock_level;         /* current level if (smb2flags&SMB2OPLOCKFLAGHELD) */
   word held_oplock_uid;

  dword inode_number;                     // Numeric
  unsigned char  unique_fileid[SMB_UNIQUE_FILEID_SIZE];        /* The on-disk inode that identifies it uniquely on the volume. */
  rtsmb_char name[SMBF_FILENAMESIZE + 1];
} FIDOBJECT_T;
typedef FIDOBJECT_T RTSMB_FAR *PFIDOBJECT;


typedef struct fid_s
{
    int internal_fid;   /* -1 means not in use */
    word external;

    word flags;
#define SMB2FIDSIG 0x11000000
#define SMB2DELONCLOSE SMB2FIDSIG|0x01
    dword smb2flags;
    dword OplockFlags;       //  =   SMB2_OPLOCK_LEVEL_NONE;
    int   OplockLevel;       //  =   SMB2_OPLOCK_LEVEL_NONE;
    int   OplockState;       //  =   OplockStateNone; // OplockStateNone; OplockStateBreaking;
    dword OplockTimeout;     //  =     0;
   // These can go soon
    byte requested_oplock_level;    /* requested level if (smb2flags&SMB2SENDOPLOCKFLAGBREAK|SMB2WAITOPLOCKFLAGREPLY)  */






    word tid;       /* owning tree */
    word uid;       /* owning user */
    dword pid;      /* owning process */
    dword error;    /* delayed error */
//    FIDOBJECT_T      _empfidobject;               // Read only acces through SMBU_Fidobject()
    PFIDOBJECT      _pfidobject;               // Read only acces through SMBU_Fidobject()
} FID_T;
typedef FID_T RTSMB_FAR *PFID;

typedef struct tree_s
{
    BBOOL inUse;
    byte access;

    byte type;      /* type of tree */

    word external;  /* public tid */
    word internal;  /* private tid */

    /* nulls can be interspersed in this array   */
    PFID *fids;

} TREE_T;
typedef TREE_T RTSMB_FAR *PTREE;

typedef struct search_s
{
    BBOOL inUse;

    unsigned long lastUse;
    word tid; /* tid this belongs to.  struct maybe should be put in TREE_T */
#ifdef SUPPORT_SMB2
    rtsmb_char name[SMBF_FILENAMESIZE + 1]; // SMB2 may restart the search with the original pattern
    byte    FileId[16];                     // There's no sid instead use file id
    ddword pid64; /* pid this belongs to. */
#else
    ddword pid; /* pid this belongs to. */
#endif
    SMBDSTAT stat;
} SEARCH_T;
typedef SEARCH_T RTSMB_FAR *PSEARCH;

typedef struct user_s
{
    byte inUse;
    word uid;
    word authId;
    BBOOL canonicalized;

    SEARCH_T *searches;

    /* nulls can be interspersed in this array   */
    PFID *fids;

} USER_T;
typedef USER_T RTSMB_FAR *PUSER;

/**
 * This holds data for raw writing operations.
 * This could be cleaned up.
 */
typedef struct write_raw_info
{
    BBOOL amWritingRaw;
    BBOOL writeThrough;
    int internal;
    word external;
    RTSMB_HEADER hdr;
    word maxCount;

} WRITE_RAW_INFO_T;



#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // Don't swap pointers if we are using exclusive buffers
typedef struct smb_sessionCtx_sessionCtxSave_s
{
    PFBYTE readBuffer;
    PFBYTE writeBuffer;
    PFBYTE smallReadBuffer;
    PFBYTE smallWriteBuffer;
    dword readBufferSize;
    dword writeBufferSize;
} SMB_SESSIONCTX_SAVE_T;
typedef SMB_SESSIONCTX_SAVE_T RTSMB_FAR *PSMB_SESSIONCTX_SAVE;
#endif

typedef struct ProcSMB2_BodyContext_s {
  dword *pPreviousNextOutCommand;
  BBOOL isCompoundReply;
  dword NextCommandOffset;
  PFVOID   pInBufStart;
  PFVOID   pOutBufStart;
  BBOOL    sign_packet;
  smb2_stream  smb2stream;
#define ST_INIT        0
#define ST_INPROCESS   1
#define ST_FALSE       2
#define ST_TRUE        3
#define ST_YIELD       4
  int      stackcontext_state;
} SMB2_BODYCONTEXT_T;

typedef struct smb_sessionCtx_s
{
    RTP_SOCKET sock;

    SMB_DIALECT_T dialect;      /* dialect we are speaking */
    BBOOL isSMB2;               /* Set true when SMB2 negotiated */
    BBOOL doSocketClose;        /* Set true when SMB command handler wants the network layer code to close the socket when it is convenient. */
    BBOOL doSessionClose;       /* Set true when SMB2 command handler wants the network layer code the session after the stream is flushed. */


	word  _yieldFlags;          // Private for use only by srvyield.cpp
	dword _yieldTimeout;        // Private for use only by srvyield.cpp
    void  *current_yield_Cptr;   // Stores the resore point from srvyield.cpp


    SMBS_SESSION_STATE session_state;   /* are we idle or waiting on something? */

    /**
     * Pointers to the buffers we are currently using for reading or writing.
     */
    PFBYTE readBuffer;
    PFBYTE writeBuffer;

    /**
     * We list the size of the current read/write buffers so that we know
     * what is safe to read from wire.
     */
    dword readBufferSize;
    dword writeBufferSize;

    /**
     * Here we house default reading/writing buffers that can handle everyday
     * messaging needs.
     */
    PFBYTE smallReadBuffer;
    PFBYTE smallWriteBuffer;

    /**
     * Points to beginning of SMB.
     */
    PFBYTE read_origin;
    PFBYTE write_origin;


    /**
     * We also need to keep track of the size we are willing to use from small
     * buffers, since client's buffer may be smaller than ours.
     */
    dword useableBufferSize;

    /**
     * Used to record how large the body of our currently-being-procesed
     * incoming SMB is.
     */
    dword current_body_size;

    /**
     * Used to record how big the current incoming packet is.
     */
    dword in_packet_size;

    /**
     * Used to record when we will stop trying to complete the current packet.
     */
    dword in_packet_timeout_base;

    /**
     * Size of our current outgoing packet.
     */
    dword outBodySize;

    /**
     * Holds temporary read and write data.
     */
    PFBYTE tmpBuffer;
    dword tmpSize;


    /**
     * A helper variable to hold on raw writes.
     */
    WRITE_RAW_INFO_T writeRawInfo;

#ifdef SUPPORT_SMB2
    Smb2SrvModel_Session         Smb2SessionInstance;
    Smb2SrvModel_Connection      Smb2ConnectionInstance;
    SMB2_BODYCONTEXT_T           SMB2_FrameState;
#endif

    /* Below here is all smbv1 and should be in a seperate union.   */
    /**
     * headers
     */
    PRTSMB_HEADER pInHeader;
    PRTSMB_HEADER pOutHeader;



    byte encryptionKey [8]; /* encryptionKey used for password encryption */

    byte accessMode;        /* access mode of server when session is set up */

    word sessionId;         /* this keeps value across session closes/opens */

    /**
     * Set some flags to let processing functions know what's going on without
     * having to pass a lot of info on around on the stack.
     *
     * These are the values for the smb being processed.
     */
    word uid;
    dword pid;
    word tid;

    /**
     * Some helper data we keep around to answer net_server_enum's.
     */
    char  server_enum_domain [RTSMB_NB_NAME_SIZE + 1];
    dword server_enum_type;


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

    /* session defaults to smb1 but we push saved buffers here when we assing and SMB2 seesion */
    int protocol_version;
#if (HARDWIRE_NO_SHARED_SESSION_BUFFERS == 0) // Don't swap pointers if we are using exclusive buffers
    SMB_SESSIONCTX_SAVE_T CtxSave;
#endif

} SMB_SESSIONCTX_T;
typedef SMB_SESSIONCTX_T RTSMB_FAR *PSMB_SESSIONCTX;



#define READ_SMB(A) \
{\
    if (A (pCtx->read_origin, pInBuf, (rtsmb_size) (pCtx->current_body_size - (rtsmb_size)PDIFF (pInBuf, pCtx->read_origin)), pInHdr, &command) == -1)\
    {\
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);\
        return TRUE;\
    }\
}


#define WRITE_SMB(A) \
{\
    PFVOID buf;\
    int tmp_size = srv_cmd_fill_header (pCtx->write_origin, pOutBuf,\
        (rtsmb_size)SMB_BUFFER_SIZE, pOutHdr);\
    if (tmp_size == -1)\
    {\
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);\
        return TRUE;\
    }\
    buf = PADD (pOutBuf, tmp_size);\
    pCtx->outBodySize = (rtsmb_size)tmp_size;\
    if ((tmp_size = A (pCtx->write_origin, buf, (rtsmb_size)(SMB_BUFFER_SIZE - tmp_size), \
        pOutHdr, &response)) == -1)\
    {\
        SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_SRVERROR);\
        return TRUE;\
    }\
    pCtx->outBodySize += (rtsmb_size)tmp_size;\
}


/*============================================================================   */
/*    INTERFACE DATA DECLARATIONS                                                */
/*============================================================================   */

/*============================================================================   */
/*    INTERFACE FUNCTION PROTOTYPES                                              */
/*============================================================================   */




/*============================================================================   */
/*    INTERFACE TRAILING HEADERS                                                 */
/*============================================================================   */


/*****************************************************************************   */
/***                                                                             */
/***    END HEADER SRVSSN.H                                                      */
/***                                                                             */
/*****************************************************************************   */

#endif /* INCLUDE_RTSMB_SERVER */

#endif /* __SRV_SSN_H__ */
