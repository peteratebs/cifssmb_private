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

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "srvcfg.h"
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "srv_smb2_proc_fileio.h"


#include "rtptime.h"

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"
#include "rtpmem.h"



BBOOL Process_smb2_fileio_prolog(RTSMB2_FILEIOARGS *pargs, smb2_stream  *pStream, PFVOID command, PFVOID pcommand_structure_Fileid,word *pcommand_structure_size, word command_size)
{
    tc_memset(pargs, 0, sizeof(*pargs));
    ASSERT_SMB2_UID(pStream)   // Returns TRUE if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns TRUE if the TID is not valid

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_filieio:  RtsmbStreamDecodeCommand failed...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    if (*pcommand_structure_size != command_size)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_filieio:  StructureSize invalid...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    pargs->pTree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid);
    tc_memcpy(pargs->externalFidRaw,pcommand_structure_Fileid, 16);
    pargs->externalFid = RTSmb2_get_externalFid(pargs->externalFidRaw);

    if (pargs->externalFid == 0xffff)
    {
      printf("Close, exfd == 0xffff why ?\n");
      pargs->fidflags = FID_FLAG_DIRECTORY; // Fake this so it doesn't close
      pargs->fid = -1;
    }
    else
    {
      // Set the status to success
      ASSERT_SMB2_FID(pStream,pargs->externalFid,FID_FLAG_ALL);     // Returns if the externalFid is not valid
      pargs->fid = SMBU_GetInternalFid (pStream->psmb2Session->pSmbCtx, pargs->externalFid, FID_FLAG_ALL, &pargs->fidflags,0);
    }
    return FALSE;
}



BBOOL Proc_smb2_Flush(smb2_stream  *pStream)
{
RTSMB2_FLUSH_C command;   //  StructureSize;  24
RTSMB2_FLUSH_R response;   //  StructureSize;  4
RTSMB2_FILEIOARGS fileioargs;

  tc_memset(&response,0, sizeof(response));
  tc_memset(&command,0, sizeof(command));
  if (Process_smb2_fileio_prolog(&fileioargs, pStream, (PFVOID) &command, (PFVOID) (&command.FileId[0]),&command.StructureSize ,24))
  {
    return TRUE;
  }
  SMBFIO_Flush (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileioargs.fid);
  // Set the status to success
  pStream->OutHdr.Status_ChannelSequenceReserved = 0;
  response.StructureSize = 4;
  /* Success */
  RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
  return TRUE;
}
BBOOL Proc_smb2_Read(smb2_stream  *pStream)
{
RTSMB2_READ_C command;        //  StructureSize; 49
RTSMB2_READ_R response;       //  17
RTSMB2_FILEIOARGS fileioargs;
dword toRead;
long bytesRead;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    if (Process_smb2_fileio_prolog(&fileioargs, pStream, (PFVOID) &command, (PFVOID) (&command.FileId[0]),&command.StructureSize ,49))
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Read !! prolog Failed\n");
      return TRUE;
    }
    pStream->WriteBufferParms[0].byte_count = pStream->psmb2Session->Connection->MaxReadSize;
    pStream->WriteBufferParms[0].pBuffer = rtp_malloc(pStream->psmb2Session->Connection->MaxReadSize);

    if (pStream->write_buffer_remaining <= 512)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Read !! buffer full\n");
       goto unsuccessful;
    }
     // Clip it to the maximum we allocated to read to
     toRead = (dword) MIN(pStream->WriteBufferParms[0].byte_count,command.Length);
     // Clip it to the maximum size we have for sending data
     toRead = (dword) MIN (toRead,(pStream->write_buffer_remaining-512));

    // note: command.Flags &0x01 == unbuffered;
    if (SMBFIO_Seeku64 (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileioargs.fid, command.Offset) == -1LL)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Read !! seek failed\n");
       goto unsuccessful;
    }
    else if ((bytesRead = SMBFIO_Read (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileioargs.fid, pStream->WriteBufferParms[0].pBuffer, toRead)) < 0)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Read !! read failedd\n");
       goto unsuccessful;
    }
	if ((dword)bytesRead < command.MinimumCount)
    {
unsuccessful:
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Proc_smb2_Read failed\n");
       RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
       pStream->OutHdr.Status_ChannelSequenceReserved = SMB2_STATUS_UNSUCCESSFUL;
       return TRUE;
    }
    pStream->OutHdr.Status_ChannelSequenceReserved = 0;
    response.StructureSize  = 17;
	response.DataOffset     = sizeof(RTSMB2_HEADER) + 16;
	response.DataLength     = bytesRead;
	response.DataRemaining  = bytesRead;

    pStream->WriteBufferParms[0].byte_count = bytesRead;
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
free_and_out:
    RTP_FREE(pStream->WriteBufferParms[0].pBuffer);
    return TRUE;
}

BBOOL Proc_smb2_Write(smb2_stream  *pStream)
{
RTSMB2_WRITE_C command;
RTSMB2_WRITE_R response;
RTSMB2_FILEIOARGS fileioargs;
long bytesWritten;

#define SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    pStream->ReadBufferParms[0].byte_count = pStream->psmb2Session->Connection->MaxWriteSize;
    pStream->ReadBufferParms[0].pBuffer = rtp_malloc(pStream->psmb2Session->Connection->MaxWriteSize);


    if (Process_smb2_fileio_prolog(&fileioargs, pStream, (PFVOID) &command, (PFVOID) (&command.FileId[0]),&command.StructureSize ,49))
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Write !! prolog Failed with maxB %ld \n",  pStream->ReadBufferParms[0].byte_count);
      goto free_and_out;
    }

    if (SMBFIO_Seeku64 (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileioargs.fid, command.Offset) == -1LL)
    {
       RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
       pStream->OutHdr.Status_ChannelSequenceReserved = SMB2_STATUS_UNSUCCESSFUL;
       goto free_and_out;
    }
    else if ((bytesWritten = SMBFIO_Write(pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileioargs.fid, pStream->ReadBufferParms[0].pBuffer, pStream->ReadBufferParms[0].byte_count)) < 0)
    {
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "Proc_smb2_Write failed\n");
       RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
       pStream->OutHdr.Status_ChannelSequenceReserved = SMB2_STATUS_UNSUCCESSFUL;
       goto free_and_out;
    }
    pStream->OutHdr.Status_ChannelSequenceReserved = 0;
    response.StructureSize = 17;
	response.Count = bytesWritten;
    /* Success - see above if the client asked for stats */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
free_and_out:
    RTP_FREE(pStream->ReadBufferParms[0].pBuffer);
    return TRUE;
}

#endif
#endif
