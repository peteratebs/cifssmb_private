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
#include "srvfio.h"


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
        int i;
        byte *b;
        FILE_RENAME_INFORMATION_TYPE_2 *pRenameInfo = (FILE_RENAME_INFORMATION_TYPE_2 *)pStream->ReadBufferParms[0].pBuffer;
        byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
        word externalFid = RTSmb2_get_externalFid(pFileId);
        b = &pRenameInfo->Buffer[0];
        b[pRenameInfo->FileNameLength] =0;
        b[pRenameInfo->FileNameLength+1] =0;
        for(i=0; i < 2; i++)
        { // Loop twice, in case we fail but ReplaceIfExists is rue
          if (SMBFIO_Rename(pStream->pSmbCtx, pStream->pSmbCtx->tid, SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid), (PFRTCHAR)pRenameInfo->Buffer))
            break;
          if (pRenameInfo->ReplaceIfExists)
          {
             pRenameInfo->ReplaceIfExists=0;
             if (SMBFIO_Delete(pStream->pSmbCtx, pStream->pSmbCtx->tid,(PFRTCHAR) pRenameInfo->Buffer))
                continue;
          }
          RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
          goto free_bail;
        }
        break;
    }
    else if (command.FileInfoClass==SMB2_0_FileSetDisposition)
    {
        int i;
        byte *b;
        dword smb2flags=0;
        word fidflags=0;
        FILE_DISPOSITION_INFO *pInfo = (FILE_DISPOSITION_INFO *)pStream->ReadBufferParms[0].pBuffer;
        byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
        word externalFid = RTSmb2_get_externalFid(pFileId);
       // Set the status to success
        int fid = SMBU_GetInternalFid (pStream->pSmbCtx, externalFid, FID_FLAG_ALL, &fidflags, &smb2flags);
        if (fid >= 0)
        {
          if (pInfo->DeletePending)
          {
            // Check if we are a non-empty directory
            if (fidflags == FID_FLAG_DIRECTORY && SMBFIO_DirentCount(pStream->pSmbCtx, pStream->pSmbCtx->tid, SMBU_GetFileNameFromFid(pStream->pSmbCtx, externalFid),2)!=2)
            {
               RtsmbWriteSrvStatus(pStream,SMB2_STATUS_DIRECTORY_NOT_EMPTY);
               goto free_bail;
            }
            smb2flags |= (SMB2FIDSIG|SMB2DELONCLOSE);
          }
          else
            smb2flags&=~(SMB2FIDSIG|SMB2DELONCLOSE);
          SMBU_SetFidSmb2Flags (pStream->pSmbCtx,externalFid ,smb2flags );
          break;
        }
        else
        {
          RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
          goto free_bail;
        }
        break;
    }
    else if (command.FileInfoClass==SMB2_0_FileEndofFile)
    {
        int i;
        byte *b;
        dword smb2status = 0;
        dword smb2flags = 0;
        word fidflags=0;
        ddword *pInfo = (ddword *)pStream->ReadBufferParms[0].pBuffer;
        byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
        word externalFid = RTSmb2_get_externalFid(pFileId);
       // Set the status to success
        int fid = SMBU_GetInternalFid (pStream->pSmbCtx, externalFid, FID_FLAG_ALL, &fidflags, &smb2flags);
//        smb2status = SMB2_STATUS_INVALID_PARAMETER;
//        smb2status = SMB2_STATUS_DISK_FULL;
//        smb2status = SMB2_STATUS_INFO_LENGTH_MISMATCH;

        if (fid >= 0)
        {
           if (!SMBFIO_Truncate64 (pStream->pSmbCtx, pStream->pSmbCtx->tid, fid, *pInfo))
           {
             RtsmbWriteSrvStatus(pStream,SMB2_STATUS_ACCESS_DENIED);
             goto free_bail;
           }
        }
        else
        {
          RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
          goto free_bail;
        }
        break; // Success
    }
    else
    {
       // Fake success for other operations.
       RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_SetInfo: SMB2_0_INFO_FILE: Infoclass not supported: %d\n", command.FileInfoClass);
       break;
    }
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
