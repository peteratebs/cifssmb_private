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
#include "srvobjectsc.h"


// Initialize state variable foer a new connection
void RtsmbYieldNetSessionInit(PNET_SESSIONCTX pNetCtx)
{
  pNetCtx->smbCtx.waitOplockAckCount =
  pNetCtx->smbCtx.sendOplockBreakCount =
  pNetCtx->smbCtx.sendNotifyCount = 0;
}

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



PACK_PRAGMA_ONE
struct s_RTSMB2_HPLUS_OPLOCK_BREAK_C
{
  byte nbss_header_type;
  byte nbss_size[3];
  RTSMB2_HEADER header;
  RTSMB2_OPLOCK_BREAK_C command;
};
PACK_PRAGMA_POP


static BBOOL SendOplockBreak(PNET_SESSIONCTX psession, PFID pfid)
{
struct s_RTSMB2_HPLUS_OPLOCK_BREAK_C p;
dword mysize = (dword) sizeof(p) - RTSMB_NBSS_HEADER_SIZE;

   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SendOplockBreak: top.\n");

  tc_memset (&p, 0,sizeof(p));

  p.nbss_header_type = 0;
  p.nbss_size[0] =  (byte) (mysize>>16 & 0xFF);
  p.nbss_size[1] =  (byte) (mysize>>8 & 0xFF);
  p.nbss_size[2] =  (byte) (mysize & 0xFF);
  p.header.ProtocolId[0] = 0xFE;  p.header.ProtocolId[1] = 'S';   p.header.ProtocolId[2] = 'M';   p.header.ProtocolId[3] = 'B';
  p.header.StructureSize = 64;
  p.header.CreditCharge  = 0; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
  p.header.Status_ChannelSequenceReserved = 0; /*  (4 bytes): */
  p.header.Command = SMB2_OPLOCK_BREAK;
  p.header.CreditRequest_CreditResponse = 0;
  p.header.Flags = 1;
  p.header.NextCommand = 0;
  p.header.MessageId   = 0xffffffffffffffffULL;
  p.header.Reserved    = 0;
  p.header.TreeId      = 0;
  p.header.SessionId   = 0;
//  header.Signature[16] = {0};

  p.command.StructureSize = 24;
  p.command.OplockLevel =  pfid->requested_oplock_level;
  p.command.Reserved = 0;
  p.command.Reserved2 = 0;
  tc_memcpy (p.command.FileId,pfid->unique_fileid ,8);

  // Send the oplock break over the socket
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: SendOplockBreak call rtsmb_net_write sock: %d\n",psession->sock);

  PNET_SESSIONCTX pfilesession = SMBU_Fid2Session(pfid);
  if (!pfilesession)
  {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: SendOplockBreak SMBU_Fid2Session() failed \n");
     srvobject_tag_oplock(pfid,"rtsmb_net_write failed no session"); // rtsmb_net_write failed no session

  }
  else if (rtsmb_net_write (pfilesession->sock, &p,sizeof(p)) < 0)
  {
     char buff[80];
     sprintf(buff, "rtsmb_net_write failed send failure to [%d]", pfilesession->heap_index);
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: SendOplockBreak rtsmb_net_write failed\n");
     srvobject_tagalloc_oplock(pfid,buff); // rtsmb_net_write failed send failure
  }
  else
  {
     srvobject_tag_oplock(pfid,"rtsmb_net_write succeeded"); // rtsmb_net_write succeeded
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: SendOplockBreak fake rtsmb_net_write succeeded \n");
     return FALSE;
  }
 /* Read into command to pull it from the input queue */
 // RtsmbStreamEncodeAlert(psession, (PFVOID ) &command);
 return FALSE;
}

struct RtsmbYieldProcOplockTimers_s {
  word timenow;
  PNET_SESSIONCTX session;
};



static int RtsmbYieldProcOplockTimersCB (PFID fid, PNET_SESSIONCTX pNctxt,PSMB_SESSIONCTX pCtx, void *pargs)
{
  if (fid->smb2flags & SMB2WAITOPLOCKREPLY)
  {
     if ( ((struct RtsmbYieldProcOplockTimers_s *)pargs)->timenow > fid->smb2waitexpiresat)
     {
       if (pCtx->waitOplockAckCount)
         pCtx->waitOplockAckCount -= 1;
       fid->smb2waitexpiresat = 0;
       srvobject_tag_oplock(fid,"RtsmbYieldProcOplockTimersCB timed out"); // RtsmbYieldProcOplockTimersCB timed out
       fid->held_oplock_level = fid->requested_oplock_level;
       RtsmbYieldSendSignalSocketSession(pNctxt);
       if (pCtx->waitOplockAckCount == 0)
         return 1;
     }
  }
  return 0;
}


void RtsmbYieldProcOplockTimers(PNET_SESSIONCTX session)
{
 struct RtsmbYieldProcOplockTimers_s args;
 /* enumerate FIDs and signal lock release if we have a match. Send a response if  required */
 args.session  = session;
 args.timenow  = rtp_get_system_msec ();
 SMBU_EnumerateFids(RtsmbYieldProcOplockTimersCB, (void *) &args);
}

struct RtsmbProcOplockBreaks_s {
  byte  *unique_fileid;
  byte   incoming_oplock_level;
  byte   send_oplock_level;
  smb2_stream  *pStream;
};


static int RtsmbYieldProcOplockBreaksCB (PFID fid, PNET_SESSIONCTX pnCtx,PSMB_SESSIONCTX pCtx, void *pargs)
{
  if (fid->smb2flags & SMB2WAITOPLOCKREPLY)
  {
     if (tc_memcmp (((struct RtsmbProcOplockBreaks_s *)pargs)->unique_fileid, fid->unique_fileid ,8)==0)
     {
        if (fid->requested_oplock_level <= ((struct RtsmbProcOplockBreaks_s *)pargs)->incoming_oplock_level)
        { // Request succeeded
          fid->held_oplock_level = fid->requested_oplock_level;
          srvobject_tag_oplock(fid,"RtsmbYieldProcOplockBreaksCB granted"); // RtsmbYieldProcOplockBreaksCB granted
          RtsmbYieldSendSignalSocket(((struct RtsmbProcOplockBreaks_s *)pargs)->pStream);
          fid->smb2flags &= ~SMB2WAITOPLOCKREPLY;      // RtsmbYieldProcOplockBreaksCB granted
          fid->smb2waitexpiresat = 0;
        }
        else
        {
#warning OPLOCK break request failed what to do
          srvobject_tag_oplock(fid,"RtsmbYieldProcOplockBreaksCB not granted");// RtsmbYieldProcOplockBreaksCB not granted
        }
        return 1; // There's only one that can macth, so quit.
     }
  }
  return 0;
}


BBOOL Proc_smb2_OplockBreak(smb2_stream  *pStream)
{
 struct RtsmbProcOplockBreaks_s args;
 RTSMB2_OPLOCK_BREAK_C command;
 RTSMB2_OPLOCK_BREAK_R response;

 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 if (!pStream->Success)
 {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_OplockBreak:  RtsmbStreamDecodeCommand failed...\n");
     RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
     return TRUE;
 }

 /* enumerate FIDs and signal lock release if we have a match. Send a response if  required */
 args.unique_fileid          = command.FileId;
 args.incoming_oplock_level  = command.OplockLevel;
 args.send_oplock_level      = command.OplockLevel;     // Respond with this if we don't have anything pending
 args.pStream                = pStream;
 SMBU_EnumerateFids(RtsmbYieldProcOplockBreaksCB, (void *) &args);

 tc_memset(&response,0, sizeof(response));
 response.StructureSize = 24;
 response.OplockLevel = args.send_oplock_level;
 tc_memcpy(response.FileId,command.FileId, sizeof(response.FileId));
 return TRUE;
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


struct RtsmbYieldSendOplockBreaks_s {
  PNET_SESSIONCTX session;
};

static int RtsmbYieldSendOplockBreaksCB (PFID fid, PNET_SESSIONCTX pnCtx,PSMB_SESSIONCTX pCtx, void *pargs)
{
  if (fid->smb2flags & SMB2SENDOPLOCKBREAK)
  {
     fid->smb2flags &= ~SMB2SENDOPLOCKBREAK;
     SendOplockBreak (((struct RtsmbYieldSendOplockBreaks_s*)pargs)->session,fid);
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD:  RtsmbYieldSendOplockBreaks sending break\n");
  }
  return 0;
}


void RtsmbYieldSendOplockBreaks (PNET_SESSIONCTX session)
{
  PTREE tree;
  PUSER user;
  PSMB_SESSIONCTX pCtx = &session->smbCtx;
  struct RtsmbYieldSendOplockBreaks_s args;
  args.session = session;
  SMBU_EnumerateFids(RtsmbYieldSendOplockBreaksCB, (void *) &args);
}

void RtsmbYieldOplockCloseFile(PSMB_SESSIONCTX pCtx, PFID pfid)
{
#warning RtsmbYieldOplockCloseFile rundown of is needed
  if (pfid->smb2flags & SMB2WAITOPLOCKREPLY)
  {
    srvobject_tag_oplock(pfid,"Closed file waiting for reply"); // Closed file waiting for reply
  }
  else
  {
    srvobject_tag_oplock(pfid,"Closed file not waiting for reply"); // Closed file not waiting for reply
  }
}

// Change the break level of a local file
void RtsmbYieldChangeOplockBreakLevel(PSMB_SESSIONCTX pCtx, PFID pfid,int oplocklevel)
{
  // Set it and forget it
  pfid->held_oplock_level = oplocklevel;
  pfid->smb2flags &= ~(SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY);
}
void RtsmbYieldQueueOplockBreakSend (PSMB_SESSIONCTX pCtx, PFID pfid,int oplocklevel)
{
	pfid->requested_oplock_level = oplocklevel;
	switch (pfid->held_oplock_level) {
	    case SMB2_OPLOCK_LEVEL_NONE     :
          // Set it and forget it
	      pfid->held_oplock_level = oplocklevel;
          pfid->smb2flags &= ~(SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY);
          srvobject_tag_oplock(pfid,"Level Changed from none"); // Level Changed from none
	      break;
	    case SMB2_OPLOCK_LEVEL_II       :
          // Stepping from level II. Just send requested_oplock_level in a break message but don't wait
          pfid->smb2flags &= ~SMB2WAITOPLOCKREPLY;
          pfid->smb2flags |= SMB2SENDOPLOCKBREAK;
          pfid->smb2waitexpiresat = 0;
          pCtx->sendOplockBreakCount += 1;
	      pfid->held_oplock_level = oplocklevel;
    	  pfid->requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
          srvobject_tag_oplock(pfid,"Level Changed from two"); // Level Changed from two
	      break;
	    case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
	    case SMB2_OPLOCK_LEVEL_BATCH    :
         // Send requested_oplock_level in a break message.
         // Queue up a wait for reponse.
          pfid->smb2flags |= (SMB2SENDOPLOCKBREAK|SMB2WAITOPLOCKREPLY);
          pfid->smb2waitexpiresat = rtp_get_system_msec()+SMB2_OPLOCK_MAX_WAIT_MILLIS;
          pCtx->sendOplockBreakCount += 1;
          pCtx->waitOplockAckCount += 1;
    	  pfid->requested_oplock_level = SMB2_OPLOCK_LEVEL_II;
          PNET_SESSIONCTX pfilesession = SMBU_Fid2Session(pfid);
          if (!pfilesession)
          {
             srvobject_tag_oplock(pfid,"Level Changed to two but prevfid failed"); // rtsmb_net_write failed no session
          }
          else
          {
             PNET_SESSIONCTX myfilesession = SMBU_Fid2Session(pfid);
             char buff[80];
             sprintf(buff, "Level Changed to two ownsession == %d , thissession==%d", pfilesession->heap_index,srvobject_get_currentsession_index());
             srvobject_tagalloc_oplock(pfid,buff); // Level Changed to two
         }
	      break;
	    case SMB2_OPLOCK_LEVEL_LEASE    :
	      break;
    }
}


#endif
#endif
