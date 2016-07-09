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
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"


#include "rtptime.h"

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"



BBOOL Proc_smb2_Close(smb2_stream  *pStream)
{
	RTSMB2_CLOSE_C command;
	RTSMB2_CLOSE_R response;
    SMBFSTAT stat;
    word fidflags=0;
    int fid;
    dword r;
    word externalFid;
	PTREE pTree;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Close:  RtsmbStreamDecodeCommand failed...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    if (command.StructureSize != 24)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  StructureSize invalid...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    // What to do with these fields
	//  command.Flags;
	// command.Reserved;
	//  command.FileId[16];

    pTree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid);

    externalFid = *((word *) &command.FileId[1]);

    if (externalFid == 0xffff)
    {
      printf("Close, exfd == 0xffff why ?\n");
      fidflags = FID_FLAG_DIRECTORY; // Fake this so it doesn't close
      fid = -1;
    }
    else
    {

      // Set the status to success
      ASSERT_SMB2_FID(pStream,externalFid,FID_FLAG_ALL);     // Returns if the externalFid is not valid
      fid = SMBU_GetInternalFid (pStream->psmb2Session->pSmbCtx, externalFid, FID_FLAG_ALL, &fidflags);
    }
    /**
     * If we are closing a print file, print it before exit and delete it afterwards.
     */
    if (pTree->type == ST_PRINTQ)
    {
        if (SMBU_PrintFile (pStream->psmb2Session->pSmbCtx, fid))
            RTSMB_DEBUG_OUTPUT_STR("ProcClose: Printing file on close failed.\n", RTSMB_DEBUG_TYPE_ASCII);
        SMBFIO_Close (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fid);
        SMBFIO_Delete (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, SMBU_GetFileNameFromFid (pStream->psmb2Session->pSmbCtx, externalFid));
    }
    else
    {
        if (fidflags != FID_FLAG_DIRECTORY)
        {
            if (command.Flags & 0x01) // Asking for stats
            {
// We either need to implement SMBFIO_Fstat or cheat and add a file name store to SMBFIO_OpenInternal and use that in stat, being sure to delete it in SMBFIO_Close()
printf("Close asked for stat but we can not give them yet\n");
#ifdef TBD
                SMBFIO_Stat (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, file_name, &stat);
                response.Flags          = 0; // ??? SMB3 only
                response.Reserved       = 0; // ??? SMB3 only
                response.CreationTime   =  *((ddword *) &stat.f_ctime64);
                response.LastAccessTime =  *((ddword *) &stat.f_atime64);
                response.LastWriteTime  =  *((ddword *) &stat.f_wtime64);
                response.ChangeTime     =  *((ddword *) &stat.f_htime64);
                response.AllocationSize  = stat.f_size;
                response.EndofFile       = stat.f_size;
                response.FileAttributes  = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
#endif
           }
           SMBFIO_Close (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, fid);
        }
    }
    SMBU_ClearInternalFid (pStream->psmb2Session->pSmbCtx, externalFid);

        // Set the status to success
    pStream->OutHdr.Status_ChannelSequenceReserved = 0;
    response.StructureSize = 60;
    /* Success - see above if the client asked for stats */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
} // Proc_smb2_Ioctl

#endif
#endif
