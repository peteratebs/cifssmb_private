#include "srvcfg.h"
#include "srvssn.h"
#include "rtpstr.h"
#include "rtptime.h"
#include "rtpmem.h"
#include "srv_smb2_model.h"
#include "com_smb2_ssn.h"
#include "srvutil.h"
#include "remotediags.h"
#include "srvsmbssn.h"
#include "srvoplocks.h"
#include "rtpnet.h"
#include "rtpnet.h"

const char * format_uid(uint8_t *fileid){ static char buffer[80];tc_sprintf(buffer,"%x,%x,%x,%x,%x,%x,%x,%x",  fileid[0],  fileid[1],  fileid[2],  fileid[3],  fileid[4],  fileid[5],  fileid[6],  fileid[7]);  return (const char *) buffer;}

#define ITERATEOPLOCKHEAP for(int i=0; i < CFG_RTSMB_MAX_OPLOCKS; i++)

static int   oplocks_in_use;

// Queue of unsolicited oplock breaks to send. Cleared before each packet is processessed and dequeued and sent after completion.
static int   oplocks_break_sends_queued;

typedef struct oplock_s {
    int                  in_use;
    PFIDOBJECT           pfidobject;                                     /* file object owned by the oplock */
    PFID pfid;
    uint8_t              unique_fileid[SMB_UNIQUE_FILEID_SIZE];        /* The on-disk inode that identifies it uniquely on the volume. */
    uint8_t              held_lock_level;    // obolete maybe
    unique_userid_t      unique_userid_of_owner;
} oplock_t;
static oplock_t oplock_core[CFG_RTSMB_MAX_OPLOCKS];

static void free_oplock_structure(oplock_t *pOplock)
{
  oplocks_in_use -= 1;
  pOplock->in_use = 0;
  pOplock->pfid   = 0;
}
static oplock_t *_allocate_oplock(void)
{
  ITERATEOPLOCKHEAP {if (!oplock_core[i].in_use) {oplock_core[i].in_use=1; oplocks_in_use++; return &oplock_core[i]; } }
  return 0;
}
static oplock_t *allocate_oplock_structure(void)
{
oplock_t *r = _allocate_oplock();
  if (r)
  {
    tc_memset(r, 0, sizeof(*r));
    r->in_use = 1;
  }
  return r;
}

static oplock_t *find_oplock_structure(uint8_t *unique_fileid)
{
  for(int i=0; i < CFG_RTSMB_MAX_OPLOCKS; i++)
  {
    if (oplock_core[i].in_use)
      if (tc_memcmp(oplock_core[i].unique_fileid, unique_fileid, SMB_UNIQUE_FILEID_SIZE)==0)
        return &oplock_core[i];
  }
  return 0;
}


// Called from create
// A stat identified that a file exists and it want access at this lock level
//    Returns
//      oplock_c_create_continue
//      oplock_c_create_yield
//         The owner was queued a break request
//         The session is set to yiled until a replu comes back

oplock_c_create_return_e oplock_c_check_create_path(struct net_sessionctxt *current_session, uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t requested_lock_level)
{
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_check_create_path \n");
  if (!prtsmb_srv_ctx->enable_oplocks)
    return oplock_c_create_continue;

oplock_t *pOplock = find_oplock_structure(unique_fileid);

  // If no one owns the file there is nothing to do prior to opening
  if (!pOplock)
    return oplock_c_create_continue;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_check_create_path two\n");


  // If we currently own the file there is nothing to do prior to opening
  if (pOplock->pfidobject->fidoplock_control.owning_session == current_session)
    return oplock_c_create_continue;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_check_create_path three\n");

  //  If someone else owns the lock in >= SMB2_OPLOCK_LEVEL_BATCH mode already we must yield
  if (pOplock->pfidobject->fidoplock_control.held_oplock_level > SMB2_OPLOCK_LEVEL_II)
  {
    // We want to run at requested_lock_level and we can't so queue a send
    // So we don't send a break to ourselves
    pOplock->pfidobject->fidoplock_control.send_break_level = requested_lock_level;
    pOplock->pfidobject->fidoplock_control.break_send_requesting_session = current_session;
    oplocks_break_sends_queued += 1;

    current_session->netsessiont_smbCtx.sessionoplock_control._wakeSession =  false;
    current_session->netsessiont_smbCtx.sessionoplock_control._yieldSession = true;
    current_session->netsessiont_smbCtx.sessionoplock_control._yieldTimeout = YIELD_DEFAULT_DURATION;
    current_session->netsessiont_smbCtx.sessionoplock_control.requested_lock_level = requested_lock_level;
    tc_memcpy(current_session->netsessiont_smbCtx.sessionoplock_control.unique_fileid,unique_fileid, SMB_UNIQUE_FILEID_SIZE);
    OPLOCK_DIAG_YIELD_SESSION_YIELD
    return oplock_c_create_yield;
  }
  else
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_check_create_path yield\n");
    return oplock_c_create_continue;
  }
}

// Called from create after we succesfully open a FID

void oplock_c_create(struct net_sessionctxt *current_session, PFID pfid,unique_userid_t unique_userid, uint8_t requested_lock_level)
{
  if (!prtsmb_srv_ctx->enable_oplocks)
    return;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_create \n");
PFIDOBJECT pFidObject = SMBU_Fidobject(pfid);
oplock_t *pOplock = find_oplock_structure(pFidObject->unique_fileid);
bool send_breaks = FALSE;
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_create call allocat\n");
  if (!pOplock)
  { // If no oplock just claim one and set up a new state in the fidobject
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_create allocated\n");
    pOplock= allocate_oplock_structure();     // zero and allocate an oplock
    if (pOplock)
    {
      pOplock->pfidobject = pFidObject;
      tc_memset(&pOplock->pfidobject->fidoplock_control, 0, sizeof(pOplock->pfidobject->fidoplock_control));
      tc_memcpy(pOplock->unique_fileid, pFidObject->unique_fileid, SMB_UNIQUE_FILEID_SIZE);
      pOplock->pfidobject->fidoplock_control.owning_session    = current_session;
      pOplock->pfidobject->fidoplock_control.held_oplock_level = requested_lock_level;
      pOplock->pfidobject->fidoplock_control.held_oplock_uid   = unique_userid;
      oplock_t *pOplock2 = find_oplock_structure(pFidObject->unique_fileid);
      if (pOplock2 == pOplock)
      {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,(char *)"DIAG: oplock_c_create msatch\n");
      }
      return;
    }
  }
  //
  if (pOplock->pfidobject->fidoplock_control.owning_session == current_session)
  {
    // Check if we aren't changing anything
    if (pOplock->pfidobject->fidoplock_control.held_oplock_level == requested_lock_level)
      return;
    // Check if we are lowering it.
    if (pOplock->pfidobject->fidoplock_control.held_oplock_level > requested_lock_level)
      send_breaks = TRUE;
  }
  else
  {
    //  I now own the lock
    // Check if we are lowering it.
    if (pOplock->pfidobject->fidoplock_control.held_oplock_level > requested_lock_level)
      send_breaks = TRUE;

    pOplock->pfidobject->fidoplock_control.owning_session     = current_session;
    pOplock->pfidobject->fidoplock_control.held_oplock_level  = requested_lock_level;
    pOplock->pfidobject->fidoplock_control.held_oplock_uid    = unique_userid;
  }

  if (send_breaks)
  {
    oplocks_break_sends_queued += 1;
    // queue a sends to all fids that reference pOplock->pfidobject
    pOplock->pfidobject->fidoplock_control.send_break_level = requested_lock_level;
    pOplock->pfidobject->fidoplock_control.break_send_requesting_session = current_session;
    // We will enumerate all sessions with session != pOplock->pfidobject->fidoplock_control.break_send_requesting_session
    // and send a break if they reference pfidoject
  }

}

// Callback from the session layer to see if any blocked sessions timed out
void oplock_c_break_check_waiting_break_requests(void)
{
  if (!prtsmb_srv_ctx->enable_oplocks)
    return;
  for (int sessionindex = 0; sessionindex < prtsmb_srv_ctx->max_sessions; sessionindex++)
  { // Scan all in use sessions for fids that reference the fidobject reference by the oplock
    if (prtsmb_srv_ctx->sessionsInUse[sessionindex])
    {
      if (prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._yieldSession && rtp_get_system_msec() > prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._yieldTimeout)
      {
        oplock_t *pOplock = find_oplock_structure(prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control.unique_fileid);
        if (pOplock)
          pOplock->pfidobject->fidoplock_control.held_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._wakeSession  =  true;
        prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._yieldTimeout =  0;
      }
    }
  }
}


void oplock_c_break_clear_pending_break_send_queue(void)
{
  oplocks_break_sends_queued = 0;
}

// Called from the session layer after processing a packet.
// Send any breaks that may be queued to fids that own oplocks
void oplock_c_break_send_pending_breaks(void)
{
  if (!prtsmb_srv_ctx->enable_oplocks)
    return;
  if (!oplocks_break_sends_queued)
    return;
  // Scan all in use oplocks that need to send
  for(int lockindex=0; lockindex < CFG_RTSMB_MAX_OPLOCKS; lockindex++)
  {
     if (oplock_core[lockindex].in_use && oplock_core[lockindex].pfidobject->fidoplock_control.break_send_requesting_session)
     {
       for (int sessionindex = 0; sessionindex < prtsmb_srv_ctx->max_sessions; sessionindex++)
       { // Scan all in use sessions for fids that reference the fidobject reference by the oplock
         if (prtsmb_srv_ctx->sessionsInUse[sessionindex] && oplock_core[lockindex].pfidobject->fidoplock_control.break_send_requesting_session != &prtsmb_srv_ctx->sessions[sessionindex])
         {
           for (int fidindex = 0; fidindex < prtsmb_srv_ctx->max_fids_per_session; fidindex++)
           {
              if (prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.fids[fidindex].internal_fid >= 0 &&
                  SMBU_Fidobject(&prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.fids[fidindex]) == oplock_core[lockindex].pfidobject)
              {
                SendOplockBreak(prtsmb_srv_ctx->sessions[sessionindex].netsessiont_sock, oplock_core[lockindex].unique_fileid,oplock_core[lockindex].pfidobject->fidoplock_control.send_break_level);
              }
           }
         }
       }
       oplock_core[lockindex].pfidobject->fidoplock_control.break_send_requesting_session = 0; // clear for next time
     }
  }
  oplocks_break_sends_queued = 0;
}


// A break acknowledge was sent from a client in reponse to our request
//
// Possible outcomes:
//    returns
//      oplock_c__break_acknowledge_error
//            Abort and reply with *pstatus   - not returning now. need to review
//      oplock_c_create_continue
//            Reply with new opcode level



// Ack was recieved
//  Search all oplocks .
//    this a session should wake as a result, wake it up
//    if none found return not found status
oplock_c_break_acknowledge_return_e oplock_c_break_acknowledge(PNET_SESSIONCTX pnCtx, uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t granted_lock_level,uint32_t *pstatus)
{
  if (!prtsmb_srv_ctx->enable_oplocks)
    return oplock_c_create_continue;
  oplock_t *pOplock = find_oplock_structure(unique_fileid);
  if (!pOplock)
  {
    *pstatus = SMB2_STATUS_FILE_CLOSED;
    return oplock_c_create_continue;
  }

  // Found a lock, now wake anyone up that can run again
  *pstatus = 0;
  for(int lockindex=0; lockindex < CFG_RTSMB_MAX_OPLOCKS; lockindex++)
  {
    if (oplock_core[lockindex].in_use)
    {
      if (tc_memcmp(oplock_core[lockindex].unique_fileid, unique_fileid, SMB_UNIQUE_FILEID_SIZE)==0)
      {
        for (int sessionindex = 0; sessionindex < prtsmb_srv_ctx->max_sessions; sessionindex++)
        { // Scan all in use sessions for fids that reference the fidobject reference by the oplock
          if (prtsmb_srv_ctx->sessionsInUse[sessionindex] && pnCtx != &prtsmb_srv_ctx->sessions[sessionindex])
          {
            if (prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._yieldSession)
            { // Wake it up if granted_lock_level > wait_level ??
              if (granted_lock_level >= prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control.requested_lock_level)
              {
                OPLOCK_DIAG_YIELD_SESSION_SEND_SIGNAL
                prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._wakeSession  =  true;
                prtsmb_srv_ctx->sessions[sessionindex].netsessiont_smbCtx.sessionoplock_control._yieldTimeout =  0;
              }
            }
          }
        }
      }
    }
  }
  pOplock->pfidobject->fidoplock_control.held_oplock_level = granted_lock_level;             //
  return oplock_c_create_continue;
}



// A file or directory is being closed.
//
// Possible outcomes:
//   1. Delete the oplock if it is owned by this fid
//

void oplock_c_close(PNET_SESSIONCTX pnCtx, PFID pFid)
{
  if (!prtsmb_srv_ctx->enable_oplocks)
    return;
oplock_t *pOplock = find_oplock_structure(SMBU_Fidobject(pFid)->unique_fileid);
  if (!pOplock)
    return;
  // Release the oplock if we are the last user
  if (SMBU_Fidobject(pFid)->reference_count == 1)
  {
    free_oplock_structure(pOplock);
    return;
  }
  // reduce the level if we own it
  if (pOplock->pfidobject->fidoplock_control.owning_session == pnCtx)
  {
    pOplock->pfidobject->fidoplock_control.owning_session = 0;
    pOplock->pfidobject->fidoplock_control.held_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
    pOplock->pfidobject->fidoplock_control.held_oplock_uid = 0;
    // Now force sends to anyone waiting on this lock
    pOplock->pfidobject->fidoplock_control.break_send_requesting_session = pnCtx;
    pOplock->pfidobject->fidoplock_control.send_break_level = SMB2_OPLOCK_LEVEL_NONE;
    oplocks_break_sends_queued = 1;
  }
}

EXTERN_C char *SMBU_DiagFormatOplocks(char *buffer)
 {
  if (!prtsmb_srv_ctx->enable_oplocks)
  {
     buffer += tc_sprintf(buffer, (char *)"Oplocks are not enabled:\n");
     return buffer;
  }
   buffer += tc_sprintf(buffer, (char *)"Oplocks are enabled:\n");
   for (int i = 0; i < CFG_RTSMB_MAX_OPLOCKS; i++)
   {
     if (oplock_core[i].in_use)
     {
        char flagsstring[80];
        char temp0[80];
        tc_strcpy(flagsstring,"F:");
        buffer += tc_sprintf(buffer, (char *)" LOCK #: %d FID: [%X] heldlevel:%d UID:[%s] OWNER[%X][%X]  FLAGS:%s\n", i, oplock_core[i].pfid, oplock_core[i].held_lock_level, SMBU_format_fileid(oplock_core[i].unique_fileid, SMB_UNIQUE_FILEID_SIZE, temp0),(dword)(oplock_core[i].unique_userid_of_owner>>32), (dword)oplock_core[i].unique_userid_of_owner, flagsstring);
    }
   }
   buffer += tc_sprintf(buffer, (char *)"  session_replays               :  %lu \n", oplock_diagnotics.session_replays               );
   buffer += tc_sprintf(buffer, (char *)"  session_yields                :  %lu \n", oplock_diagnotics.session_yields                );
   buffer += tc_sprintf(buffer, (char *)"  session_wakeups               :  %lu \n", oplock_diagnotics.session_wakeups               );
   buffer += tc_sprintf(buffer, (char *)"  session_wake_signalled        :  %lu \n", oplock_diagnotics.session_wake_signalled        );
   buffer += tc_sprintf(buffer, (char *)"  session_sent_signals          :  %lu \n", oplock_diagnotics.session_sent_signals          );
   buffer += tc_sprintf(buffer, (char *)"  session_sent_timeouts         :  %lu \n", oplock_diagnotics.session_sent_timeouts         );
   buffer += tc_sprintf(buffer, (char *)"  session_wake_timedout         :  %lu \n", oplock_diagnotics.session_wake_timedout         );
   buffer += tc_sprintf(buffer, (char *)"  session_sent_breaks           :  %lu \n", oplock_diagnotics.session_sent_breaks           );
   buffer += tc_sprintf(buffer, (char *)"  session_received_breaks       :  %lu \n", oplock_diagnotics.session_received_breaks       );

   return buffer;
}
