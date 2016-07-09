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
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Ioctl:  RtsmbStreamDecodeCommand failed...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        goto free_bail;
    }

     printf("StructureSize = %d\n",command.StructureSize);
    if (command.StructureSize != 49)
    {
       printf("StructureSize Bad: %d\n",command.StructureSize);
    }

    fileid = *((int *) &command.FileId[0]);


    if (command.CtlCode == FSCTL_DFS_GET_REFERRALS)
      error_status = SMB2_STATUS_NOT_FOUND;  // Return this to continue mounting
    else if (command.CtlCode == FSCTL_PIPE_TRANSCEIVE) //    0x0011c017
    {
printf("FSCTL_PIPE_TRANSCEIVE inp == %ld\n",command.InputCount);
       if (command.InputCount)
       {
         long l;

// HEREHERE - The write and read are not getting into the svsvc layer
         l = SMBFIO_Write (pStream->psmb2Session->pSmbCtx,
              pStream->psmb2Session->pSmbCtx->tid,
              fileid,
              pStream->ReadBufferParms[0].pBuffer,
              command.InputCount);
printf("FSCTL_PIPE_TRANSCEIVE write: %ld\n", l);

         if (l==-2 ) // l == -2 means, read 4 bytes and you'll get the status code to return
         {
            l = SMBFIO_Read (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileid, &error_status, 4);
            response.OutputCount = (unsigned long) 0;
         }
         else
         {
printf("FSCTL_PIPE_TRANSCEIVE read: %ld\n", l);
            l = SMBFIO_Read  (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fileid, pStream->WriteBufferParms[0].pBuffer, 1024);
            if (l > 0)
              response.OutputCount = (unsigned long) l;
          }
       }
printf("FSCTL_PIPE_TRANSCEIVE inp == %ld\n",command.InputCount);
printf("FSCTL_PIPE_TRANSCEIVE out == %ld\n",response.OutputCount);
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
    rtp_free(pStream->ReadBufferParms[0].pBuffer);
    rtp_free(pStream->WriteBufferParms[0].pBuffer);
    return TRUE;
} // Proc_smb2_Ioctl

#endif
#endif
