//
// SRV_SMB2_SSN.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles most of the actual processing of packets for the RTSMB server.
//


// A level 1 opportunistic lock on a file allows a client to read ahead in the file and cache both read-ahead and write data from the file locally. As long as the client has sole access to a file,
// there is no danger to data coherency in providing a level 1 opportunistic lock.

// A level 2 opportunistic lock informs a client that there are multiple concurrent clients of a file and that none has yet modified it. This lock allows the client to perform read operations and
// obtain file attributes using cached or read-ahead local information, but the client must send all other requests (such as for write operations) to the server. Your application should use the level 2
// opportunistic lock when you expect other applications to write to the file at random or read the file at random or sequentially.

// A batch opportunistic lock manipulates file openings and closings. For example, in the execution of a batch file, the batch file may be opened and closed once for each line of the file.
// A batch opportunistic lock opens the batch file on the server and keeps it open. As the command processor "opens" and "closes" the batch file, the network redirector intercepts the open and close commands.
// All the server receives are the seek and read commands. If the client is also reading ahead, the server receives a particular read request at most one time.


// Breaking an opportunistic lock is the process of degrading the lock that one client has on a file so that another client can open the file, with or without an opportunistic lock. When the other client requests the
// open operation, the server delays the open operation and notifies the client holding the opportunistic lock.
// The client holding the lock then takes actions appropriate to the type of lock, for example abandoning read buffers, closing the file, and so on. Only when the client holding the opportunistic lock notifies the
// server that it is done does the server open the file for the client requesting the open operation. However, when a level 2 lock is broken, the server reports to the client that it has been broken but does not wait
// for any acknowledgment, as there is no cached data to be flushed to the server.
// In acknowledging a break of any exclusive lock (filter, level 1, or batch), the holder of a broken lock cannot request another exclusive lock. It can degrade an exclusive lock to a level 2 lock or no lock at all.
// The holder typically releases the lock and closes the file when it is about to close the file anyway.

//  EXISTING LEVEL                                    NEW FILE OPEN LEVEL            RESULT
// SMB2_OPLOCK_LEVEL_EXCLUSIVE                       SMB2_OPLOCK_LEVEL_NONE          SEND BREAK&WAIT (SMB2_OPLOCK_LEVEL_II||SMB2_OPLOCK_LEVEL_NONE)  - fid.uid, session et al find the socket to send to and wait on
// SMB2_OPLOCK_LEVEL_EXCLUSIVE                       SMB2_OPLOCK_BATCH               SEND BREAK&WAIT (SMB2_OPLOCK_LEVEL_II||SMB2_OPLOCK_LEVEL_NONE)
// SMB2_OPLOCK_LEVEL_EXCLUSIVE                       SMB2_OPLOCK_LEVEL_II            SEND BREAK&WAIT (SMB2_OPLOCK_LEVEL_II)
// SMB2_OPLOCK_LEVEL_EXCLUSIVE                       SMB2_OPLOCK_LEVEL_LEASE         NOT SURE.
//
// SMB2_OPLOCK_LEVEL_BATCH                           SMB2_OPLOCK_LEVEL_NONE          SEND BREAK&WAIT
// SMB2_OPLOCK_LEVEL_BATCH                           SMB2_OPLOCK_BATCH               SEND BREAK&WAIT
// SMB2_OPLOCK_LEVEL_BATCH                           SMB2_OPLOCK_LEVEL_II            SEND BREAK&WAIT
// SMB2_OPLOCK_LEVEL_BATCH                           SMB2_OPLOCK_LEVEL_LEASE         NOT SURE.
//
// SMB2_OPLOCK_LEVEL_II                              SMB2_OPLOCK_LEVEL_NONE          SEND BREAK but dont WAIT
// SMB2_OPLOCK_LEVEL_II                              SMB2_OPLOCK_BATCH               SEND BREAK but dont WAIT
// SMB2_OPLOCK_LEVEL_II                              SMB2_OPLOCK_LEVEL_II            Do Nothing
// SMB2_OPLOCK_LEVEL_II                              SMB2_OPLOCK_LEVEL_LEASE         NOT SURE.
//
// SMB2_OPLOCK_LEVEL_NONE                            SMB2_OPLOCK_LEVEL_NONE          Do Nothing
// SMB2_OPLOCK_LEVEL_NONE                            SMB2_OPLOCK_BATCH               SEND BREAK&WAIT
// SMB2_OPLOCK_LEVEL_NONE                            SMB2_OPLOCK_LEVEL_II            SEND BREAK&WAIT
// SMB2_OPLOCK_LEVEL_NONE                            SMB2_OPLOCK_LEVEL_LEASE         NOT SURE.
//
//
#define SMB2_OPLOCK_LEVEL_NONE              0x00 //No oplock is requested.
#define SMB2_OPLOCK_LEVEL_II                0x01 // A level II oplock is requested.
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE         0x08 // An exclusive oplock is requested.
#define SMB2_OPLOCK_LEVEL_BATCH             0x09   // A batch oplock is requested.
#define SMB2_OPLOCK_LEVEL_LEASE             0xFF   // A lease is requested. If set, the request packet MUST contain an SMB2_CREATE_REQUEST_LEASE (section 2.2.13.2.8) create context. This value is not valid for the SMB 2.0.2 dialect.


#define SMB2_OPLOCK_MAX_WAIT_MILLIS          20000 // Don't know what this shold be



#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */
#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "srvcfg.h"
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "rtptime.h"
#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"
#include "rtpmem.h"
#include "srv_smb2_proc_fileio.h"

BBOOL Proc_smb2_Lock(smb2_stream  *pStream)
{
RTSMB2_LOCK_REQUEST_C command;
RTSMB2_LOCK_REQUEST_R response;
RTSMB2_FILEIOARGS fileioargs;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));


    if (Process_smb2_fileio_prolog(&fileioargs, pStream, (PFVOID) &command, (PFVOID) (&command.FileId[0]),&command.StructureSize ,49))
    {
      return TRUE;
    }
    // HEREHERE Proc_smb2_Lock - todo
    rtp_printf("Num Lock regions: %d\n", command.LockCount);
    {
      RTSMB2_LOCK_ELEMENT *pLock;
      int i;

      pLock = &command.Locks;
      for (i=0; i < command.LockCount;i++, pLock++)
      {
        rtp_printf(" Offset: %ld Length: %ld\n", (dword) pLock->Offset, (dword)pLock->Length);
      }
    }
    // Set the status to success
    // pStream->OutHdr.Status_ChannelSequenceReserved = 0;
    response.StructureSize = 4;
    /* Success - see above if the client asked for stats */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
}


BBOOL Proc_smb2_OplockBreak(smb2_stream  *pStream)
{
 RTSMB2_OPLOCK_BREAK_C command;
 RTSMB2_OPLOCK_BREAK_R response;

 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 return FALSE;
}

BBOOL Proc_smb2_Cancel(smb2_stream  *pStream)
{
 RTSMB2_CANCEL_C command;
 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 if (pStream->Success)
 {
// HEREHERE Cancel these guys
    pStream->InHdr.MessageId; // ddword
    pStream->InHdr.TreeId;    // dword
    pStream->InHdr.SessionId; // ddword
 }
  return FALSE;
}
void RtsmbYieldSendOplockBreaks (PSMB_SESSIONCTX pCtx)
{
  PFID pfid;
  PTREE tree;
  PUSER user;

  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: RtsmbYieldSendOplockBreaks\n");

  tree = SMBU_GetTree (pCtx, pCtx->tid);
  if (!tree)
  {
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"RtsmbYieldSendOplockBreaks: tree is not valid.\n");
	return;
  }
// user has space for fid, but does tree?
  int j;
  for (j = 0; j < prtsmb_srv_ctx->max_fids_per_tree; j++)
  {
	if (tree->fids[j] && tree->fids[j]->internal != -1)
	{
      if (tree->fids[j]->smb2flags & SMB2SENDOPLOCKBREAK)
      {
        tree->fids[j]->smb2flags &= ~SMB2SENDOPLOCKBREAK;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD:  RtsmbYieldSendOplockBreaks sending: %d\n", j);
      }
      else
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD:  RtsmbYieldSendOplockBreaks not sending: %d\n", j);

	}
  }
}

void RtsmbYieldQueueOplockBreakSend (PSMB_SESSIONCTX pCtx, PFID pfid,int oplocklevel)
{
	pfid->requested_oplock_level = oplocklevel;
	switch (pfid->held_oplock_level) {
	    case SMB2_OPLOCK_LEVEL_NONE     :
          // Set it and forget it
	      pfid->held_oplock_level = pfid->requested_oplock_level;
pfid->smb2flags |= SMB2SENDOPLOCKBREAK;
pCtx->sendOplockBreakCount += 1;
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD:  RtsmbYieldQueueOplockBreakSend hack:\n");
	      break;
	    case SMB2_OPLOCK_LEVEL_II       :
          // Stepping from level II. Just send requested_oplock_level in a break message but don't wait
          pfid->smb2flags |= SMB2SENDOPLOCKBREAK;
          pCtx->sendOplockBreakCount += 1;
	      break;
	    case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
	    case SMB2_OPLOCK_LEVEL_BATCH    :
         // Send requested_oplock_level in a break message.
         // Queue up a wait for reponse.
          pfid->smb2flags |= (SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY);
          pfid->smb2waitexpiresat = rtp_get_system_msec()+SMB2_OPLOCK_MAX_WAIT_MILLIS;
          pCtx->sendOplockBreakCount += 1;
	      break;
	    case SMB2_OPLOCK_LEVEL_LEASE    :
	      break;
    }
}


#endif
#endif
