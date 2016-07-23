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


typedef struct s_RTSMB2_FILEIOARGS_C
{
PTREE pTree;
int fid;
word fidflags=0;
byte externalFidRaw[16];
word externalFid;
} RTSMB2_FILEIOARGS;


BBOOL Proc_smb2_Close(RTSMB2_FILEIOARGS *pargs, smb2_stream  *pStream, PFVOID command, PFVOID Fileid,int command_size)
{
    ASSERT_SMB2_UID(pStream)   // Returns TRUE if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns TRUE if the TID is not valid

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_filieio:  RtsmbStreamDecodeCommand failed...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    if (command.StructureSize != command_size)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_filieio:  StructureSize invalid...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    pargs->pTree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid);
    tc_memcpy(pargs->externalFidRaw,FileId, 16);
    pargs->externalFid = *((word *) &pargs->externalFidRaw[0]);

    if (pargs->externalFid == 0xffff)
    {
      printf("Close, exfd == 0xffff why ?\n");
      fidflags = FID_FLAG_DIRECTORY; // Fake this so it doesn't close
      pargs->fid = -1;
    }
    else
    {
printf("Call assert ex: %X \n",externalFid);
      // Set the status to success
      ASSERT_SMB2_FID(pStream,pargs->externalFid,FID_FLAG_ALL);     // Returns if the externalFid is not valid
printf("Back assert\n");
      pargs->fid = SMBU_GetInternalFid (pStream->psmb2Session->pSmbCtx, pargs->externalFid, FID_FLAG_ALL, &fidflags);
    }
    return false;
}



BBOOL Proc_smb2_Flush(smb2_stream  *pStream)
{
RTSMB2_FLUSH_C command;
RTSMB2_FLUSH_R response;

typedef struct s_RTSMB2_FLUSH_C
{
    word  StructureSize; // 24
	word  Reserved1;
	dword Reserved2;
	byte  FileId[16];
} PACK_ATTRIBUTE RTSMB2_FLUSH_C;
PACK_PRAGMA_POP
typedef RTSMB2_FLUSH_C RTSMB_FAR *PRTSMB2_FLUSH_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_FLUSH_R
{
    word  StructureSize; // 4
	word  Reserved;
} PACK_ATTRIBUTE RTSMB2_FLUSH_R;
PACK_PRAGMA_POP
typedef RTSMB2_FLUSH_R RTSMB_FAR *PRTSMB2_FLUSH_R;


return FALSE;
}
BBOOL Proc_smb2_Read(smb2_stream  *pStream)
{
RTSMB2_READ_C command;
RTSMB2_READ_R response;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_READ_C
{
    word    StructureSize; // 49
	byte    Padding;
	byte    Flags;
	dword   Length;
	ddword  Offset;
	byte    FileId[16];
	dword   MinimumCount;
	dword   Channel;
	dword   RemainingBytes;
	word    ReadChannelInfoOffset;
	word    ReadChannelInfoLength;
	byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_READ_C;
PACK_PRAGMA_POP
typedef RTSMB2_READ_C RTSMB_FAR *PRTSMB2_READ_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_READ_R
{
    word  StructureSize; // 17
	byte  DataOffset;
	byte  Reserved;
	dword DataLength;
	dword DataRemaining;
	dword Reserved2;
	byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_READ_R;
PACK_PRAGMA_POP
typedef RTSMB2_READ_R RTSMB_FAR *PRTSMB2_READ_R;



return FALSE;
}
BBOOL Proc_smb2_Write(smb2_stream  *pStream)
{
RTSMB2_WRITE_C command;
RTSMB2_WRITE_R response;
#define SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_WRITE_C
{
    word    StructureSize; // 49
	dword   DataOffset;
	dword   Length;
	ddword  Offset;
	byte    FileId[16];
	dword   Channel;
	dword   RemainingBytes;
	word    WriteChannelInfoOffset;
	word    WriteChannelInfoLength;
	dword   Flags;
	byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_WRITE_C;
PACK_PRAGMA_POP
typedef RTSMB2_WRITE_C RTSMB_FAR *PRTSMB2_WRITE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_WRITE_R
{
    word  StructureSize; // 17
	word  Reserved;
	dword Count;
	dword Remaining;
	word  WriteChannelInfoOffset;
	word  WriteChannelInfoLength;
} PACK_ATTRIBUTE RTSMB2_WRITE_R;
PACK_PRAGMA_POP
typedef RTSMB2_WRITE_R RTSMB_FAR *PRTSMB2_WRITE_R;
return FALSE;
}
BBOOL Proc_smb2_Lock(smb2_stream  *pStream)
{
//RTSMB2_READ_C command;
//RTSMB2_READ_R response;
return FALSE;
}
#if (0)

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

    externalFid = *((word *) &command.FileId[0]);
#if (HARDWIRED_INCLUDE_DCE)
    if (pTree->type == ST_IPC)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Close:  YA YA 6 IPC!!...\n",0);
    }
#endif


    if (externalFid == 0xffff)
    {
      printf("Close, exfd == 0xffff why ?\n");
      fidflags = FID_FLAG_DIRECTORY; // Fake this so it doesn't close
      fid = -1;
    }
    else
    {
printf("Call assert ex: %X \n",externalFid);

      // Set the status to success
      ASSERT_SMB2_FID(pStream,externalFid,FID_FLAG_ALL);     // Returns if the externalFid is not valid
printf("Back assert\n");
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
    // == Borrowed from srvtrans2 ==


        /**
         * If we are closing a diskfile make sure directory enum streams is closed..
        */
        if (pTree->type == ST_DISKTREE)// Close any directory scans associated with this file
        {
		PUSER user;
            int _sid;
            user = SMBU_GetUser (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->uid);
            for (_sid = 0; _sid < prtsmb_srv_ctx->max_searches_per_uid; _sid++)
            {
              if (user->searches[_sid].inUse && tc_memcmp(user->searches[_sid].FileId, command.FileId, sizeof(command.FileId))==0)
              {
                printf("File close, releaseing stat\n");
                SMBFIO_GDone (pStream->psmb2Session->pSmbCtx, user->searches[_sid].tid, &user->searches[_sid].stat);
                user->searches[_sid].inUse=FALSE;
                break;
              }
            }
        }

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
#endif // #if (0)

#endif
#endif


