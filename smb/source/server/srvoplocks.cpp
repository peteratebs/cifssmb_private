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
#include "rtpnet.h"



// Each .seq file and the .bmp files it references creates one one_instance of an animation_sequence
class oplock_c {
  public:
    oplock_c ();
    ~oplock_c ();
    void oplock_setvals(PFID pfid,unique_userid_t unique_userid_of_owner,uint8_t held_lock_level);
    static class oplock_c *allocate_oplock(void)
    {
      ITERATEOPLOCKHEAP {if (!oplock_core[i].in_use) {oplock_core[i].in_use=1; oplocks_in_use++; return &oplock_core[i];} }
      return 0;
    }
    static class oplock_c *find_oplock(uint8_t *unique_fileid)
    {
      ITERATEOPLOCKHEAP {if (oplock_core[i].in_use) { if (tc_memcmp(oplock_core[i].unique_fileid, unique_fileid, SMB_UNIQUE_FILEID_SIZE)==0) return &oplock_core[i];}}
      return 0;
    }
    static class oplock_c *new_fid_oplock(PFID pfid, unique_userid_t unique_userid_of_owner,uint8_t held_lock_level)
    {
      allocate_oplock()->oplock_setvals(pfid, unique_userid_of_owner, held_lock_level);
    };
  private:
    static int   oplocks_in_use;
    static class oplock_c oplock_core[CFG_RTSMB_MAX_OPLOCKS];
    int    in_use;
    uint8_t              unique_fileid[SMB_UNIQUE_FILEID_SIZE];        /* The on-disk inode that identifies it uniquely on the volume. */
    unique_userid_t      unique_userid_of_owner;
    uint8_t              held_lock_level;
};

oplock_c::oplock_c (void)
{

}


void oplock_c::oplock_setvals(PFID pfid,unique_userid_t unique_userid_of_owner,uint8_t held_lock_level)
{
  tc_memcpy(this->unique_fileid, SMBU_Fidobject(pfid)->unique_fileid, SMB_UNIQUE_FILEID_SIZE);
  this->unique_userid_of_owner = unique_userid_of_owner;
  this->held_lock_level = held_lock_level;
}

oplock_c::~oplock_c()
{

}


opploc_Cptr oplock_c_find_oplock(uint8_t *unique_fileid)
{
opploc_Cptr r = 0;
//  return (opploc_Cptr) oplock_c::find_oplock(unique_fileid);
  return r;
}

opploc_Cptr oplock_c_new_fid_oplock(PFID pfid, unique_userid_t unique_userid_of_owner,uint8_t held_lock_level)
{
opploc_Cptr r = 0;
  pfid->OplockLevel   =   SMB2_OPLOCK_LEVEL_NONE;
  pfid->OplockState   =   OplockStateNone; // OplockStateNone; OplockStateBreaking;
  pfid->OplockTimeout = 0;
//  r = (opploc_Cptr)oplock_c::map_fid_oplock(pfid, unique_userid_of_owner,held_lock_level);
  return r;
}

// A stat identified that a file exists and it want access at this lock level
//
// Possible outcomes:
//   1. If no one owns it:  assign this level and continues
//   2. Someone else owns it: queue a break send and yield
//   3. This unique_userid owns it but this instance of the FID does not own it (always true): don't change the level but continue.
//
//    returns
//      oplock_c_create_continue
//          - If true
//      oplock_c_create_yield
//          - If true
//              The owner was sent a break request
//              The session context was pushed and a signal for when a break ack(unique_fileid,requested_lock_level) comes back

oplock_c_create_return_e oplock_c_check_create_path(uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t requested_lock_level)
{
  return oplock_c_create_continue;
  return oplock_c_create_yield;


}

void oplock_c_new_unlocked_fid(PFID pfid)
{
  pfid->OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
  pfid->OplockTimeout = 0;
  pfid->OplockState =   OplockStateNone;;       //  =   OplockStateNone; // OplockStateNone; OplockStateBreaking;

//    SMBU_FidobjectSetheld_oplock_level(&pCtx->fids[k],0);
//    SMBU_Fidobject(&pCtx->fids[k])->held_oplock_uid = 0;
}

// A file or directory is being closed.
//
// Possible outcomes:
//   1. If oplock count is one, free the oplock and continue.
//   2. If this unique_userid owns it but this instance of the FID does not own it, decrement and continue.
//   3. This unique_userid owns it and this instance of the does own it: decrement, reduce level to next highest request, send any pending break responses.
//     recheck if we send alerts
//

#warning writeme
void oplock_c_close(PFID Fid)
{
#if (0)
// oplock_c_close  -- void RtsmbYieldOplockCloseFile(PSMB_SESSIONCTX pCtx, PFID pfid)
// oplock_c_close  -- {
// oplock_c_close  -- #warning RtsmbYieldOplockCloseFile rundown of is needed
// oplock_c_close  --   if (pfid->OplockFlags & SMB2WAITOPLOCKFLAGREPLY)
// oplock_c_close  --   {
// oplock_c_close  --     srvobject_tag_oplock(pfid,"Closed file waiting for reply"); // Closed file waiting for reply
// oplock_c_close  --   }
// oplock_c_close  --   else
// oplock_c_close  --   {
// oplock_c_close  --     srvobject_tag_oplock(pfid,"Closed file not waiting for reply"); // Closed file not waiting for reply
// oplock_c_close  --   }
// oplock_c_close  -- }
#endif
}
void oplock_c_delete(PFID Fid)
{

}

// A break acknowledge was sent from a client in reponse to our request
//
// Possible outcomes:
//
//    returns
//      oplock_c__break_acknowledge_error
//            Abort and reply with *pstatus
//      oplock_c_create_continue
//            Reply with new opcode level

#warning Write us
oplock_c_break_acknowledge_return_e oplock_c_break_acknowledge(uint8_t *unique_fileid, unique_userid_t unique_userid, uint8_t requested_lock_level,uint32_t *pstatus)
{
oplock_c_break_acknowledge_return_e r;
  r = oplock_c_break_acknowledge_continue;
  r = oplock_c_break_acknowledge_continue;
  *pstatus = 0;
  if (r == oplock_c_break_acknowledge_error)
    *pstatus = 0;
  else
    *pstatus = 0;
  return r;
}


#if 0
// oplock_c_break_update_pending_locks  -- //   -- /* =======================================================*/
// oplock_c_break_update_pending_locks  -- /* void Proc_smb2_OplockBreak(smb2_stream  *pStream)*/
// oplock_c_break_update_pending_locks  -- /* An oplock break ACK was recved
// oplock_c_break_update_pending_locks  --     Scan all LOCK
// oplock_c_break_update_pending_locks  --      If a lock is waiting for a break and it matches the uniqueid
// oplock_c_break_update_pending_locks  --        Set its oplock level
// oplock_c_break_update_pending_locks  --        Turn off pending.
// oplock_c_break_update_pending_locks  --        Signal the session layer to run and let the socket run.
// oplock_c_break_update_pending_locks  -- */
// oplock_c_break_update_pending_locks  -- /* =======================================================*/
// oplock_c_break_update_pending_locks  -- static int RtsmbYieldProcOplockBreaksCB (PFID fid, PNET_SESSIONCTX pnCtx,PSMB_SESSIONCTX pCtx, void *pargs)
// oplock_c_break_update_pending_locks  -- {
// oplock_c_break_update_pending_locks  --   if (fid->OplockFlags & SMB2WAITOPLOCKFLAGREPLY)
// oplock_c_break_update_pending_locks  --   {
// oplock_c_break_update_pending_locks  --      if (tc_memcmp (((struct RtsmbProcOplockBreaks_s *)pargs)->unique_fileid, SMBU_Fidobject(fid)->unique_fileid ,SMB_UNIQUE_FILEID_SIZE)==0)
// oplock_c_break_update_pending_locks  --      {
// oplock_c_break_update_pending_locks  --         if (fid->requested_oplock_level <= ((struct RtsmbProcOplockBreaks_s *)pargs)->incoming_oplock_level)
// oplock_c_break_update_pending_locks  --         { // Request succeeded
// oplock_c_break_update_pending_locks  --           SMBU_FidobjectSetheld_oplock_level(fid, fid->requested_oplock_level);
// oplock_c_break_update_pending_locks  --           srvobject_tag_oplock(fid,"RtsmbYieldProcOplockBreaksCB granted"); // RtsmbYieldProcOplockBreaksCB granted
// oplock_c_break_update_pending_locks  --           yield_c_signal_to_stream(((struct RtsmbProcOplockBreaks_s *)pargs)->pStream);
// oplock_c_break_update_pending_locks  --           fid->OplockFlags &= ~SMB2WAITOPLOCKFLAGREPLY;      // RtsmbYieldProcOplockBreaksCB granted
// oplock_c_break_update_pending_locks  --           fid->OplockTimeout = 0;
// oplock_c_break_update_pending_locks  --         }
// oplock_c_break_update_pending_locks  --         else
// oplock_c_break_update_pending_locks  --         {
// oplock_c_break_update_pending_locks  -- #warning OPLOCK break request failed what to do
// oplock_c_break_update_pending_locks  --           srvobject_tag_oplock(fid,"RtsmbYieldProcOplockBreaksCB not granted");// RtsmbYieldProcOplockBreaksCB not granted
// oplock_c_break_update_pending_locks  --         }
// oplock_c_break_update_pending_locks  --      }
// oplock_c_break_update_pending_locks  --   }
// oplock_c_break_update_pending_locks  --   return 0;
}

#endif
struct oplock_c_break_update_pending_locks_s { uint8_t *unique_fileid; uint8_t oplock_level;};
static int oplock_c_break_update_pending_locksCB (PFID fid, PNET_SESSIONCTX pnCtx,PSMB_SESSIONCTX pCtx, void *pargs)
{
#warning wrong

  if (fid->OplockFlags & SMB2SENDOPLOCKFLAGBREAK)
  {
     fid->OplockFlags &= ~SMB2SENDOPLOCKFLAGBREAK;
     SendOplockBreak(fid);
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD:  oplock_c_break_update_pending_locksCB sending break\n");
  }
  return 0;
}

void oplock_c_break_update_pending_locks(uint8_t *unique_fileid, uint8_t oplock_level)
{
 /* enumerate FIDs and signal lock release if we have a match. Send a response if  required */
 struct oplock_c_break_update_pending_locks_s args;
 args.unique_fileid          = unique_fileid;
 args.oplock_level           = oplock_level;
 SMBU_EnumerateFids(oplock_c_break_update_pending_locksCB, (void *) &args);
}

static int oplock_c_break_send_pending_breaksCB (PFID fid, PNET_SESSIONCTX pnCtx,PSMB_SESSIONCTX pCtx, void *pargs)
{
  if (fid->OplockFlags & SMB2SENDOPLOCKFLAGBREAK)
  {
     fid->OplockFlags &= ~SMB2SENDOPLOCKFLAGBREAK;
     SendOplockBreak (fid);
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD:  RtsmbYieldSendOplockBreaks sending break\n");
  }
  return 0;
}
void oplock_c_break_send_pending_breaks(void)
{
  SMBU_EnumerateFids(oplock_c_break_send_pending_breaksCB, (void *) 0);
}

/* =======================================================*/
/* void oplock_c_break_check_wating_break_requests(PNET_SESSIONCTX session)*/
/* Scan all active oplocks

     When the oplock break acknowledgment timer expires, the server MUST scan for oplock breaks that have not been acknowledged by the client within the configured time.
     It does this by enumerating all opens in the GlobalOpenTable. For each open, if Open.OplockState is Breaking and Open.OplockTimeout is earlier than the current time,
     the server MUST acknowledge the oplock break to the underlying object store represented by Open.LocalOpen, set Open.OplockLevel to SMB2_OPLOCK_LEVEL_NONE, and set
     Open.OplockState to None.

*/

/* =======================================================*/
struct oplock_c_break_check_wating_break_requests_s {  word timenow;};
static int oplock_c_break_check_wating_break_requestsCB (PFID fid, PNET_SESSIONCTX pNctxt,PSMB_SESSIONCTX pCtx, void *pargs)
{
  if (fid->OplockFlags & SMB2WAITOPLOCKFLAGREPLY)
  {
     if ( ((struct oplock_c_break_check_wating_break_requests_s *)pargs)->timenow > fid->OplockTimeout)
     {
       fid->OplockTimeout = 0;
       SMBU_FidobjectSetheld_oplock_level(fid, SMB2_OPLOCK_LEVEL_NONE);
       yield_c_signal_to_session(pNctxt->pThread->signal_object);
     }
  }
  return 0;
}
void oplock_c_break_check_wating_break_requests()
{
 struct oplock_c_break_check_wating_break_requests_s args;
 /* enumerate FIDs and signal lock release if we have a match. Send a response if  required */
 args.timenow  = rtp_get_system_msec ();
 SMBU_EnumerateFids(oplock_c_break_check_wating_break_requestsCB, (void *) &args);
}

#warning  WRITE ME
void oplock_c_create(PFID pfid,uint8_t requested_lock_level)
{
#if (0)
// oplock_c_create
// Change the break level of a local file
// oplock_c_create void RtsmbYieldChangeOplockBreakLevel(PSMB_SESSIONCTX pCtx, PFID pfid,int oplocklevel)
// oplock_c_create {
// oplock_c_create   // Set it and forget it
// oplock_c_create   SMBU_FidobjectSetheld_oplock_level(pfid, oplocklevel);
// oplock_c_create   pfid->OplockFlags &= ~(SMB2SENDOPLOCKFLAGBREAK|SMB2WAITOPLOCKFLAGREPLY);
// oplock_c_create   if (oplocklevel > 0)
// oplock_c_create   {
// oplock_c_create    printf("Ok look l:%d :%d\n",oplocklevel,SMBU_Fidobject(pfid)->held_oplock_level);
// oplock_c_create    sleep(1);
// oplock_c_create    printf("Ok back\n");
// oplock_c_create   }
// oplock_c_create }
// oplock_c_create
// oplock_c_create
#endif
}
#if (0)
// oplock_c_create // From create -
// oplock_c_create
#warning this is all junk now
// oplock_c_create        // Force a test of restarting from an oplock if the file exists
// oplock_c_create       if (SMBFIO_Stat (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, file_name, &stat))
// oplock_c_create       {
// oplock_c_create         int i,tp;
// oplock_c_create         tp = 0;
// oplock_c_create         // if (testingYield != 3)
// oplock_c_create         {
// oplock_c_create         int CurrentOplockLevel;
// oplock_c_create         pfidExisting =  SMBU_CheckOplockLevel (pTree, pStream->psmb2Session->pSmbCtx->uid, stat.unique_fileid, &CurrentOplockLevel);
// oplock_c_create
// oplock_c_create //        command.RequestedOplockLevel &&
// oplock_c_create         // If testing force a send
// oplock_c_create         if (pfidExisting)
// oplock_c_create         {
// oplock_c_create           if (reentering)
// oplock_c_create           {
// oplock_c_create             if (signalled)
// oplock_c_create               srvobject_tag_oplock(pfidExisting, "Create re enter check oplevel signalled");
// oplock_c_create             else
// oplock_c_create               srvobject_tag_oplock(pfidExisting, "Create re enter check oplevel timed out");
// oplock_c_create           }
// oplock_c_create           else
// oplock_c_create           {
// oplock_c_create             srvobject_tag_oplock(pfidExisting, "Create enter check oplevel");
// oplock_c_create           }
// oplock_c_create           if (timedout)
// oplock_c_create           {
// oplock_c_create             srvobject_tag_oplock(pfidExisting,"Create force accept after timeout"); // Create Force tids the same
// oplock_c_create             pfidExisting->tid =  pStream->psmb2Session->pSmbCtx->tid;
// oplock_c_create             RtsmbYieldChangeOplockBreakLevel (pStream->psmb2Session->pSmbCtx, pfidExisting,(int) command.RequestedOplockLevel);
// oplock_c_create             CurrentOplockLevel = command.RequestedOplockLevel;
// oplock_c_create           }
// oplock_c_create
// oplock_c_create           if (CurrentOplockLevel != (int) command.RequestedOplockLevel)
// oplock_c_create           { // Don't send any breaks if we already own the file.
// oplock_c_create             if (pfidExisting->tid ==  pStream->psmb2Session->pSmbCtx->tid)
// oplock_c_create             {
// oplock_c_create                srvobject_tag_oplock(pfidExisting,"Create Force tids the same"); // Create Force tids the same
// oplock_c_create                RtsmbYieldChangeOplockBreakLevel (pStream->psmb2Session->pSmbCtx, pfidExisting,(int) command.RequestedOplockLevel);
// oplock_c_create             }
// oplock_c_create             else
// oplock_c_create             {
// oplock_c_create               srvobject_tag_oplock(pfidExisting,"Create check lock status"); // Create check lock status
// oplock_c_create               RtsmbYieldQueueOplockBreakSend (pStream->psmb2Session->pSmbCtx, pfidExisting,(int) command.RequestedOplockLevel);
// oplock_c_create
// oplock_c_create               if (pfidExisting->OplockFlags & SMB2SENDOPLOCKFLAGBREAK)
// oplock_c_create                 srvobject_tag_oplock(pfidExisting,"Create send break queued"); // Create send break queued
// oplock_c_create               // We may have set SMB2SENDOPLOCKFLAGBREAK and possibly SMB2WAITOPLOCKFLAGREPLY
// oplock_c_create               // If we set SMB2WAITOPLOCKFLAGREPLY we should return to wait for a break response, otherwise contnue
// oplock_c_create               // If we have to send a break we'll send it after current packet is processed
// oplock_c_create               if (pfidExisting->OplockFlags & SMB2WAITOPLOCKFLAGREPLY)
// oplock_c_create               {
// oplock_c_create                 testingYield = 1;
// oplock_c_create                 yield_c_pop_stream_inpstate(pStream);
// oplock_c_create                 srvobject_tag_oplock(pfidExisting,"Create yield to wait for response"); // Create yield to wait for response
// oplock_c_create                 yield_c_execute_yield(pStream);
// oplock_c_create                 return FALSE;
// oplock_c_create               }
// oplock_c_create             }
// oplock_c_create           }
// oplock_c_create         }
// oplock_c_create         }
// oplock_c_create       }
// oplock_c_create =============
// oplock_c_create
// oplock_c_create void RtsmbYieldQueueOplockBreakSend (PSMB_SESSIONCTX pCtx, PFID pfid,int oplocklevel)
// oplock_c_create {
// oplock_c_create 	pfid->requested_oplock_level = oplocklevel;
// oplock_c_create 	switch (SMBU_Fidobject(pfid)->held_oplock_level) {
// oplock_c_create 	    case SMB2_OPLOCK_LEVEL_NONE     :
// oplock_c_create           // Set it and forget it
// oplock_c_create 	      SMBU_FidobjectSetheld_oplock_level(pfid,oplocklevel);
// oplock_c_create           pfid->OplockFlags &= ~(SMB2SENDOPLOCKFLAGBREAK|SMB2WAITOPLOCKFLAGREPLY);
// oplock_c_create           srvobject_tag_oplock(pfid,"Level Changed from none"); // Level Changed from none
// oplock_c_create 	      break;
// oplock_c_create 	    case SMB2_OPLOCK_LEVEL_II       :
// oplock_c_create           // Stepping from level II. Just send requested_oplock_level in a break message but don't wait
// oplock_c_create           pfid->OplockFlags &= ~SMB2WAITOPLOCKFLAGREPLY;
// oplock_c_create           pfid->OplockFlags |= SMB2SENDOPLOCKFLAGBREAK;
// oplock_c_create           pfid->OplockTimeout = 0;
// oplock_c_create           pCtx->sendOplockBreakCount += 1;
// oplock_c_create 	      SMBU_FidobjectSetheld_oplock_level(pfid,oplocklevel);
// oplock_c_create     	  pfid->requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
// oplock_c_create           srvobject_tag_oplock(pfid,"Level Changed from two"); // Level Changed from two
// oplock_c_create 	      break;
// oplock_c_create 	    case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
// oplock_c_create 	    case SMB2_OPLOCK_LEVEL_BATCH    :
// oplock_c_create          // Send requested_oplock_level in a break message.
// oplock_c_create          // Queue up a wait for reponse.
// oplock_c_create           pfid->OplockFlags |= (SMB2SENDOPLOCKFLAGBREAK|SMB2WAITOPLOCKFLAGREPLY);
// oplock_c_create           pfid->OplockTimeout = rtp_get_system_msec()+SMB2_OPLOCK_MAX_WAIT_MILLIS;
// oplock_c_create           pCtx->sendOplockBreakCount += 1;
// oplock_c_create           pCtx->waitOplockAckCount += 1;
// oplock_c_create     	  pfid->requested_oplock_level = SMB2_OPLOCK_LEVEL_II;
// oplock_c_create           PNET_SESSIONCTX pfilesession = SMBU_Fid2Session(pfid);
// oplock_c_create           if (!pfilesession)
// oplock_c_create           {
// oplock_c_create              srvobject_tag_oplock(pfid,"Level Changed to two but prevfid failed"); // rtsmb_net_write failed no session
// oplock_c_create           }
// oplock_c_create           else
// oplock_c_create           {
// oplock_c_create              PNET_SESSIONCTX myfilesession = SMBU_Fid2Session(pfid);
// oplock_c_create              char buff[80];
// oplock_c_create              sprintf(buff, "Level Changed to two ownsession == %d , thissession==%d", pfilesession->heap_index,srvobject_get_currentsession_index());
// oplock_c_create              srvobject_tagalloc_oplock(pfid,buff); // Level Changed to two
// oplock_c_create          }
// oplock_c_create 	     break;
// oplock_c_create 	    case SMB2_OPLOCK_LEVEL_LEASE    :
// oplock_c_create 	      break;
// oplock_c_create     }
// oplock_c_create }
// oplock_c_create
// oplock_c_create
// oplock_c_create
#endif




#if (0)

If Open.OplockLevel is SMB2_OPLOCK_LEVEL_EXCLUSIVE or SMB2_OPLOCK_LEVEL_BATCH, and if OplockLevel is not
SMB2_OPLOCK_LEVEL_II or SMB2_OPLOCK_LEVEL_NONE, the server MUST do the following:

  If Open.OplockState is not Breaking, stop processing the acknowledgment, and send an error response with
  STATUS_INVALID_OPLOCK_PROTOCOL.

  If Open.OplockState is Breaking, complete the oplock break request received from the object store, as
  described in section 3.3.4.6, with a new level SMB2_OPLOCK_LEVEL_NONE in an implementation-specific manner
  ,<365> and set Open.OplockLevel to SMB2_OPLOCK_LEVEL_NONE and Open.OplockState to None.

If Open.OplockLevel is SMB2_OPLOCK_LEVEL_II, and if OplockLevel is not SMB2_OPLOCK_LEVEL_NONE, the server
MUST do the following:
  If Open.OplockState is not Breaking, stop processing the acknowledgment, and send an error response with
  STATUS_INVALID_OPLOCK_PROTOCOL.
  If Open.OplockState is Breaking, complete the oplock break request received from the object store,
  as described in section 3.3.4.6, with a new level SMB2_OPLOCK_LEVEL_NONE in an implementation-specific
  manner,<366> and set Open.OplockLevel to SMB2_OPLOCK_LEVEL_NONE and Open.OplockState to None.

If OplockLevel is SMB2_OPLOCK_LEVEL_II or SMB2_OPLOCK_LEVEL_NONE, the server MUST do the following:
  If Open.OplockState is not Breaking, stop processing the acknowledgment, and send an error response
  with STATUS_INVALID_DEVICE_STATE.
  If Open.OplockState is Breaking, complete the oplock break request received from the object store as
  described in section 3.3.4.6, with a new level received in OplockLevel in an implementation-specific manner.
  <367>

  If the object store indicates an error, set the Open.OplockLevel to SMB2_OPLOCK_LEVEL_NONE, the
  Open.OplockState to None, and send the error response with the error code received.
  If the object store indicates success, update Open.OplockLevel and Open.OplockState as follows:
    If OplockLevel is SMB2_OPLOCK_LEVEL_II, set Open.OplockLevel to SMB2_OPLOCK_LEVEL_II and Open.OplockState
    to Held.
    If OplockLevel is SMB2_OPLOCK_LEVEL_NONE, set Open.OplockLevel to SMB2_OPLOCK_LEVEL_NONE and the
    Open.OplockState to None.

  The server then MUST construct an oplock break response using the syntax specified in section 2.2.25 with the
  following value:


#endif
