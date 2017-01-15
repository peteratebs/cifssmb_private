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
#include "remotediags.h"
#include "srvoplocks.h"
#include "smbnet.h"

extern BBOOL cancel_notify_request(smb2_stream  *pStream);

// Still experimental for now
extern ddword smb2_stream_to_unique_userid(smb2_stream  *pStream)
{
 ddword unique_userid;
 unique_userid = SMBU_UniqueUserId(pStream->InHdr.SessionId, pStream->InHdr.TreeId, pStream->InHdr.ProcessidH);
 return unique_userid;
}


BBOOL Proc_smb2_Cancel(smb2_stream  *pStream)
{
 RTSMB2_CANCEL_C command;
 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 if (pStream->Success)
 {
    // Queue matching pending notify replies to reply with canceled status to their original command
    // Oplock cancel needs to be supported similarly.
    if (cancel_notify_request(pStream))
    {
      return TRUE;
    }
    // Cancel oplocks here probably

//    pStream->InHdr.MessageId; // ddword
//    pStream->InHdr.TreeId;    // dword
//    pStream->InHdr.SessionId; // ddword
 }
  return FALSE;
}

BBOOL Proc_smb2_OplockBreak(smb2_stream  *pStream)
{
 RTSMB2_OPLOCK_BREAK_C command;
 RTSMB2_OPLOCK_BREAK_R response;

 OPLOCK_DIAG_RECV_BREAK
 /* Read into command to pull it from the input queue */
 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_OplockBreak:  recved...\n");
 if (!pStream->Success)
 {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_OplockBreak:  RtsmbStreamDecodeCommand failed...\n");
     RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
     return TRUE;
 }
 ddword unique_userid = smb2_stream_to_unique_userid(pStream);
 oplock_c_break_acknowledge_return_e r;
 dword status_toreturn = 0;

  r = oplock_c_break_acknowledge(SMBU_SmbSessionToNetSession(pStream->pSmbCtx), command.FileId, unique_userid, command.OplockLevel,&status_toreturn);
  if (r == oplock_c_break_acknowledge_error)
  {  // Send corect status with response
     RtsmbWriteSrvStatus(pStream, status_toreturn);
     return TRUE;
  }
  // Set the status to success
  pStream->OutHdr.Status_ChannelSequenceReserved = 0;
  /* Format the response to the break ack */
  tc_memset(&response,0, sizeof(response));
  response.StructureSize = 24;
  response.OplockLevel = command.OplockLevel;
  tc_memcpy(response.FileId,command.FileId, sizeof(response.FileId));
  RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
  return TRUE;
}

PACK_PRAGMA_ONE
struct PACK_ATTRIBUTE s_RTSMB2_HPLUS_OPLOCK_BREAK_C
{
  byte nbss_header_type;
  byte nbss_size[3];
  RTSMB2_HEADER header;
  RTSMB2_OPLOCK_BREAK_C command;
};
PACK_PRAGMA_POP


void SendOplockBreak(RTP_SOCKET sock, byte *unique_fileid,uint8_t requested_oplock_level)
{
struct s_RTSMB2_HPLUS_OPLOCK_BREAK_C p;
dword mysize = (dword) sizeof(p) - RTSMB_NBSS_HEADER_SIZE;

   OPLOCK_DIAG_SEND_BREAK;

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
  p.command.OplockLevel =  requested_oplock_level;
  p.command.Reserved = 0;
  p.command.Reserved2 = 0;
  tc_memcpy (p.command.FileId, unique_fileid ,SMB_UNIQUE_FILEID_SIZE);

  if (rtsmb_net_write (sock, &p,sizeof(p)) < 0)
  {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: SendOplockBreak to socket: %d rtsmb_net_write failed\n",sock);
  }
  else
  {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: SendOplockBreak rtsmb_net_write succeeded \n");
  }
 /* Read into command to pull it from the input queue */
 // RtsmbStreamEncodeAlert(psession, (PFVOID ) &command);
 return;
}


BBOOL Proc_smb2_Lock(smb2_stream  *pStream)
{
RTSMB2_LOCK_REQUEST_C command;
RTSMB2_LOCK_REQUEST_R response;
RTSMB2_FILEIOARGS fileioargs;

 tc_memset(&response,0, sizeof(response));
 tc_memset(&command,0, sizeof(command));

 RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
 RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_OplockBreak:  recved...\n");
 if (!pStream->Success)
 {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_Lock:  RtsmbStreamDecodeCommand failed...\n");
     RtsmbWriteSrvStatus (pStream, SMB2_STATUS_INVALID_PARAMETER);
     return TRUE;
 }
#if (0)
  int i;
  RTSMB2_LOCK_ELEMENT *pLock;
  // Set the status to success
  // pStream->OutHdr.Status_ChannelSequenceReserved = 0;
  pLock = &command.Locks;
  for (i=0; i < command.LockCount;i++, pLock++)
  {
    rtp_printf(" Offset: %ld Length: %ld\n", (dword) pLock->Offset, (dword)pLock->Length);
  }
#endif
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: Proc_smb2_Lock:  fake success...\n");
  response.StructureSize = 4;
  /* Success - see above if the client asked for stats */
  RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
  return TRUE;
}

#endif
#endif
