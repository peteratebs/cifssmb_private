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


#include "rtptime.h"

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"

extern BBOOL RTSmb2_get_stat_from_fid(smb2_stream  *pStream, PTREE pTree, word externalFid, PSMBFSTAT pstat);


BBOOL RTSmb2_get_stat_from_fid(smb2_stream  *pStream, PTREE pTree, word externalFid, PSMBFSTAT pstat)
{
  BBOOL r=FALSE;
  PFRTCHAR file_name = SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid);
  if (file_name&&pTree->type == ST_DISKTREE)
  {
    if (SMBFIO_Stat (pStream->pSmbCtx, pStream->pSmbCtx->tid, file_name, pstat))
    r = TRUE;
  }
  if (!r)
    tc_memset(pstat, 0, sizeof(*pstat));
  return r;
}


BBOOL Proc_smb2_Close(smb2_stream  *pStream)
{
	RTSMB2_CLOSE_C command;
	RTSMB2_CLOSE_R response;
    word fidflags=0;
    int fid;
    dword r;
    word externalFid;
    dword smb2flags;
	PTREE pTree;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Close:  RtsmbStreamDecodeCommand failed...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    if (command.StructureSize != 24)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Close:  StructureSize invalid...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
    // What to do with these fields
	//  command.Flags;
	// command.Reserved;
	//  command.FileId[16];

    pTree = SMBU_GetTree (pStream->pSmbCtx, pStream->pSmbCtx->tid);

    byte *MappedFileId =  RTSmb2_mapWildFileId(pStream, command.FileId);
    externalFid = RTSmb2_get_externalFid(MappedFileId);

//    else
    {
      // Set the status to success
      ASSERT_SMB2_FID(pStream,externalFid,FID_FLAG_ALL);     // Returns if the externalFid is not valid
      fid = SMBU_GetInternalFid (pStream->pSmbCtx, externalFid, FID_FLAG_ALL, &fidflags, &smb2flags);
    }
    /**
     * If we are closing a print file, print it before exit and delete it afterwards.
     */
    if (pTree->type == ST_PRINTQ)
    {
        if (SMBU_PrintFile (pStream->pSmbCtx, fid))
        { RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"ProcClose: Printing file on close failed.\n"); }
        SMBFIO_Close (pStream->pSmbCtx, pStream->pSmbCtx->tid, fid);
        SMBFIO_Delete (pStream->pSmbCtx, pStream->pSmbCtx->tid, SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid));
    }
    else
    {
    // == Borrowed from srvtrans2 ==
        /**
         * If we are closing a diskfile make sure directory enum streams is closed..
        */
        if (pTree->type == ST_DISKTREE)// Close any directory scans associated with this file
        {
		PUSER user;
            int _sid;
            user = SMBU_GetUser (pStream->pSmbCtx, pStream->pSmbCtx->uid);
            for (_sid = 0; _sid < prtsmb_srv_ctx->max_searches_per_uid; _sid++)
            {
              if (user->searches[_sid].inUse && tc_memcmp(user->searches[_sid].FileId, MappedFileId, sizeof(command.FileId))==0)
              {
                SMBFIO_GDone (pStream->pSmbCtx, user->searches[_sid].tid, &user->searches[_sid].stat);
                user->searches[_sid].inUse=FALSE;
                break;
              }
            }
        }

        if (command.Flags & 0x01) // Asking for stats
        {
        // We either need to implement SMBFIO_Fstat or cheat and add a file name store to SMBFIO_OpenInternal and use that in stat, being sure to delete it in SMBFIO_Close()
          SMBFSTAT stat;
          RTSmb2_get_stat_from_fid(pStream,pTree, externalFid, &stat);
          response.Flags          = 0x01; // ??? SMB3 only
          response.Reserved       = 0; // ??? SMB3 only
          response.CreationTime   =  *((ddword *) &stat.f_ctime64);
          response.LastAccessTime =  *((ddword *) &stat.f_atime64);
          response.LastWriteTime  =  *((ddword *) &stat.f_wtime64);
          response.ChangeTime     =  *((ddword *) &stat.f_htime64);
          response.AllocationSize  = stat.f_size;
          response.EndofFile       = stat.f_size;
          response.FileAttributes  = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
        }
        if (fidflags != FID_FLAG_DIRECTORY)
            SMBFIO_Close (pStream->pSmbCtx, pStream->pSmbCtx->tid, fid);
        // 0xffff is not real resource so don't do any file ops.
        if (pTree->type == ST_DISKTREE)// Close any directory scans associated with this file
        {
          // Call opclock_close in case we are releasing a locked fid
          PFID pfid = SMBU_GetInternalFidPtr (pStream->pSmbCtx, externalFid);


          if ((smb2flags&SMB2FIDSIG)==SMB2FIDSIG && (smb2flags&SMB2DELONCLOSE))
          {
            BBOOL ok=FALSE;
            if (fidflags != FID_FLAG_DIRECTORY)
              ok=SMBFIO_Delete (pStream->pSmbCtx, pStream->pSmbCtx->tid, SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid));
            else
              ok=SMBFIO_Rmdir(pStream->pSmbCtx, pStream->pSmbCtx->tid, SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid));
             if ( prtsmb_srv_ctx->enable_oplocks&&ok)
               oplock_c_delete(pfid);
          }
          else
          {
             if (prtsmb_srv_ctx->enable_oplocks)
               oplock_c_close(pfid);
          }
        }
    }

    SMBU_ClearInternalFid (pStream->pSmbCtx, externalFid);

        // Set the status to success
    pStream->OutHdr.Status_ChannelSequenceReserved = 0;
    response.StructureSize = 60;
    /* Success - see above if the client asked for stats */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
} // Proc_smb2_Ioctl

#endif
#endif
