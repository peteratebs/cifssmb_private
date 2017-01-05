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
#include "com_smb2.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "rtptime.h"
#include "rtpmem.h"
#include "srvssn.h"
#include "smbdebug.h"
#include "srvutil.h"
#include "srvfio.h"

static BBOOL isAnInvalidFSCTLRequest(dword requestid)
{
  switch (requestid) {
    case FSCTL_DELETE_OBJECT_ID:
    case FSCTL_DELETE_REPARSE_POINT:
    case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
    case FSCTL_FILE_LEVEL_TRIM:
    case FSCTL_FILESYSTEM_GET_STATISTICS:
    case FSCTL_FIND_FILES_BY_SID:
    case FSCTL_GET_COMPRESSION:
    case FSCTL_GET_INTEGRITY_INFORMATION:
    case FSCTL_GET_NTFS_VOLUME_DATA:
    case FSCTL_GET_REFS_VOLUME_DATA:
    case FSCTL_GET_REPARSE_POINT:
    case FSCTL_LMR_SET_LINK_TRACKING_INFORMATION:
    case FSCTL_OFFLOAD_READ:
    case FSCTL_OFFLOAD_WRITE:
    case FSCTL_PIPE_PEEK:
    case FSCTL_PIPE_WAIT:
    case FSCTL_QUERY_ALLOCATED_RANGES:
    case FSCTL_QUERY_FAT_BPB:
    case FSCTL_QUERY_FILE_REGIONS:
    case FSCTL_QUERY_ON_DISK_VOLUME_INFO:
    case FSCTL_QUERY_SPARING_INFO:
    case FSCTL_READ_FILE_USN_DATA:
    case FSCTL_RECALL_FILE:
    case FSCTL_SET_COMPRESSION:
    case FSCTL_SET_DEFECT_MANAGEMENT:
    case FSCTL_SET_ENCRYPTION:
    case FSCTL_SET_INTEGRITY_INFORMATION:
    case FSCTL_SET_OBJECT_ID:
    case FSCTL_SET_OBJECT_ID_EXTENDED:
    case FSCTL_SET_REPARSE_POINT:
    case FSCTL_SET_SPARSE:
    case FSCTL_SET_ZERO_DATA:
    case FSCTL_SET_ZERO_ON_DEALLOCATION:
    case FSCTL_SIS_COPYFILE:
    case FSCTL_WRITE_USN_CLOSE_RECORD:
     return TRUE;
     break;
    default:
     break;
  }
  return FALSE;
}

extern void rtsmb_ipcrpc_bind_stream_pointer(int fd, void *stream_pointer);

extern pSmb2SrvModel_Global pSmb2SrvGlobal;

PACK_PRAGMA_ONE
typedef struct s_VALIDATE_NEGOTIATE_INFO_R
{
    dword Capabilities;
    byte  guid[16];
    word  SecurityMode;
    word  Dialect;
} PACK_ATTRIBUTE VALIDATE_NEGOTIATE_INFO_R;
PACK_PRAGMA_POP

BBOOL Proc_smb2_Ioctl(smb2_stream  *pStream)
{
	RTSMB2_IOCTL_C command;
	RTSMB2_IOCTL_R response;
	dword error_status = 0;
    int fileid;
    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    pStream->ReadBufferParms[0].pBuffer = rtp_malloc(1024);
    pStream->ReadBufferParms[0].byte_count = 1024;
    pStream->WriteBufferParms[0].pBuffer = rtp_malloc(1024);
    pStream->WriteBufferParms[0].byte_count = 1024;


    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Ioctl:  RtsmbStreamDecodeCommand failed...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        goto free_bail;
    }

//    if (command.StructureSize != 39) //was 39 wtf
    if (command.StructureSize != 57)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Ioctl:  StructureSize invalid...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        goto free_bail;
    }

    fileid = (int) RTSmb2_get_externalFid(command.FileId);

    if (isAnInvalidFSCTLRequest(command.CtlCode))
      error_status = SMB2_STATUS_INVALID_DEVICE_REQUEST;  // Return this to continue mounting
    else if (command.CtlCode == FSCTL_DFS_GET_REFERRALS)
      error_status = SMB2_STATUS_NOT_FOUND;  // Return this to continue mounting
    else if (command.CtlCode == FSCTL_GET_OBJECT_ID || command.CtlCode == FSCTL_CREATE_OR_GET_OBJECT_ID)
    {
      BBOOL worked = FALSE;
      SMBFSTAT stat;
      PFRTCHAR filepath;
      byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
      word externalFid = RTSmb2_get_externalFid(pFileId);
      filepath = SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid);
      if (filepath && SMBFIO_Stat (pStream->pSmbCtx, pStream->pSmbCtx->tid, filepath, &stat))
         worked = TRUE;
      if(worked == FALSE)
      {
        if (command.CtlCode == FSCTL_CREATE_OR_GET_OBJECT_ID)
          RtsmbWriteSrvStatus(pStream,SMB2_STATUS_DUPLICATE_NAME);
        else // if (command.CtlCode == FSCTL_CREATE_OR_GET_OBJECT_ID)
          RtsmbWriteSrvStatus(pStream,SMB2_STATUS_OBJECTID_NOT_FOUND);
        return TRUE;
      }
      unsigned char *p = (unsigned char *) pStream->WriteBufferParms[0].pBuffer;
      // Memset so uninitialized fields are zeros
      tc_memset(p, 0, 64);
//      ObjectId (16 bytes)
      tc_memcpy(&p[0], stat.unique_fileid, sizeof(stat.unique_fileid));
//      BirthVolumeId (16 bytes)  // 0
//      BirthObjectId (16 bytes)
      tc_memcpy(&p[32], stat.unique_fileid, sizeof(stat.unique_fileid));
//      DomainId (16 bytes)       // 0
      response.OutputCount = 64;
      // The extended type is this..
//      ObjectId (16 bytes)
//      ExtendedInfo (48 bytes)

    }
    else if (command.CtlCode == FSCTL_VALIDATE_NEGOTIATE_INFO) //         0x00140204
    {
      VALIDATE_NEGOTIATE_INFO_R *answer = (VALIDATE_NEGOTIATE_INFO_R *) pStream->WriteBufferParms[0].pBuffer;
      answer->Capabilities = Smb2_util_get_global_caps(pStream->psmb2Session->Connection, 0);
      tc_memcpy(answer->guid,pSmb2SrvGlobal->ServerGuid,16);
      answer->SecurityMode =  SMB2_NEGOTIATE_SIGNING_ENABLED;
      if (pSmb2SrvGlobal->RequireMessageSigning)
         answer->SecurityMode |=  SMB2_NEGOTIATE_SIGNING_REQUIRED;
#if (HARDWIRED_DISABLE_SIGNING)
      answer->SecurityMode =  0;
#endif
      answer->Dialect      =  pStream->psmb2Session->Connection->Dialect;
      response.OutputCount = sizeof(VALIDATE_NEGOTIATE_INFO_R);
    }
    else if (command.CtlCode == FSCTL_PIPE_TRANSCEIVE) //    0x0011c017
    {
       if (command.InputCount)
       {
         long l;
         // srvsvc layer will need the stream pointer to get to session info like user name and domain so pass it through the FD
         rtsmb_ipcrpc_bind_stream_pointer(fileid, (void *)pStream);
         l = SMBFIO_Write (pStream->pSmbCtx,
              pStream->pSmbCtx->tid,
              fileid,
              pStream->ReadBufferParms[0].pBuffer,
              command.InputCount);

         if (l==-2 ) // l == -2 means, read 4 bytes and you'll get the status code to return
         {
            l = SMBFIO_Read (pStream->pSmbCtx, pStream->pSmbCtx->tid, fileid, &error_status, 4);
            response.OutputCount = (unsigned long) 0;
         }
         else
         {
            l = SMBFIO_Read  (pStream->pSmbCtx, pStream->pSmbCtx->tid, fileid, pStream->WriteBufferParms[0].pBuffer, 1024);
            if (l > 0)
              response.OutputCount = (unsigned long) l;
          }
       }
    }
    else
      error_status = SMB2_STATUS_NOT_FOUND;
    if (error_status)
    {
        RtsmbWriteSrvStatus(pStream, error_status);
    }
    else
    {
        response.StructureSize = 49;
        response.CtlCode = command.CtlCode;
        rtp_memcpy(response.FileId,  command.FileId, 16);
        response.InputOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
        response.OutputOffset = response.InputOffset+response.InputCount;
        pStream->WriteBufferParms[0].byte_count = response.InputCount+response.OutputCount;
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
free_bail:
    RTP_FREE(pStream->ReadBufferParms[0].pBuffer);
    RTP_FREE(pStream->WriteBufferParms[0].pBuffer);
    return TRUE;
} // Proc_smb2_Ioctl

#endif
#endif
