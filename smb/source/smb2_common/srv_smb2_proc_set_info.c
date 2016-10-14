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
#include "rtpmem.h"

#define FAKE_ALLOCATION_UNITS               0x10000000
#define FAKE_AVAILABLE_UNITS                0x01000000
#define FAKE_SECTORS_PER_ALLOCATION_UNIT    2
#define FAKE_BYTES_PER_SECTOR               512

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"


#include "rtptime.h"

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"


BBOOL Proc_smb2_SetInfo(smb2_stream  *pStream)
{
RTSMB2_SET_INFO_C command;
RTSMB2_SET_INFO_R response;

  tc_memset(&response,0, sizeof(response));
  tc_memset(&command,0, sizeof(command));

  pStream->ReadBufferParms[0].pBuffer = rtp_malloc(1024);
  pStream->ReadBufferParms[0].byte_count = 1024;

  RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

  if (!pStream->Success)
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_SetInfo:  RtsmbStreamDecodeCommand failed...\n");
      RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
      return TRUE;
  }

  if (command.StructureSize != 33)
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_SetInfo:  StructureSize invalid...\n");
      RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
      return TRUE;
  }


//  command.InfoType;
//  command.FileInfoClass;
//  command.BufferLength;
//  command.BufferOffset;
//  command.Reserved;
//  command.AdditionalInformation;
//  command.FileId[16];
//  command.Buffer;
  switch (command.InfoType) {
    case SMB2_0_INFO_FILE:
    if (command.FileInfoClass== SMB2_0_FileRenameInformation)
    {
        word externalFid;
        int i;
        byte *b;
        FILE_RENAME_INFORMATION_TYPE_2 *pRenameInfo = (FILE_RENAME_INFORMATION_TYPE_2 *)pStream->ReadBufferParms[0].pBuffer;
        externalFid = *((word *) &command.FileId[0]);
        b = &pRenameInfo->Buffer[0];
        b[pRenameInfo->FileNameLength] =0;
        b[pRenameInfo->FileNameLength+1] =0;
        for(i=0; i < 2; i++)
        { // Loop twice, in case we fail but ReplaceIfExists is rue
          if (SMBFIO_Rename(pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, SMBU_GetFileNameFromFid (pStream->psmb2Session->pSmbCtx, externalFid), pRenameInfo->Buffer))
            break;
          if (pRenameInfo->ReplaceIfExists)
          {
             pRenameInfo->ReplaceIfExists=0;
             if (SMBFIO_Delete(pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid,pRenameInfo->Buffer))
                continue;
          }
          RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
          goto free_bail;
        }
        break;
    }
    // Fall through
    case SMB2_0_INFO_FILESYSTEM:
    case SMB2_0_INFO_SECURITY  :
    case SMB2_0_INFO_QUOTA     :
    default:
     RtsmbWriteSrvStatus(pStream,SMB2_STATUS_NOT_IMPLEMENTED);
     goto free_bail;
    break;
  }

  pStream->OutHdr.Status_ChannelSequenceReserved = 0;
  response.StructureSize = 2;
  RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
free_bail:
  RTP_FREE(pStream->ReadBufferParms[0].pBuffer);
//  RTP_FREE(pStream->WriteBufferParms[0].pBuffer);
  return TRUE;
}

#endif
#endif
