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
#include "rtpmem.h"

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"
#include "srvcfg.h"

// FileInformationClass
#define FileDirectoryInformation        0x01
#define FileFullDirectoryInformation    0x02
#define FileIdFullDirectoryInformation  0x26
#define FileBothDirectoryInformation    0x03
#define FileIdBothDirectoryInformation  0x25
#define FileNamesInformation            0x0C

// Flags
#define SMB2_RESTART_SCANS              0x01
#define SMB2_RETURN_SINGLE_ENTRY        0x02
#define SMB2_INDEX_SPECIFIED            0x04
#define SMB2_REOPEN                     0x10



static int SMB2_FILLFileDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat);
static int SMB2_FILLFileFullDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat);
static int SMB2_FILLFileIdFullDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat);
static int SMB2_FILLFileBothDirectoryInformation(void *byte_pointer,  rtsmb_size bytes_remaining, SMBDSTAT *pstat);
static int SMB2_FILLFileIdBothDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat);
static int SMB2_FILLFileNamesInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat);




PACK_PRAGMA_ONE
typedef struct s_FILE_DIRECTORY_INFORMATION_BASE
{
	dword NextEntryOffset;
	dword FileIndex;
	FILETIME_T CreationTime;
	FILETIME_T LastAccessTime;
	FILETIME_T LastWriteTime;
	FILETIME_T ChangeTime;
	ddword EndofFile;
	ddword AllocationSize;
	dword FileAttributes;
	dword FileNameLength;
} PACK_ATTRIBUTE FILE_DIRECTORY_INFORMATION_BASE;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_FILE_DIRECTORY_INFORMATION
{
    FILE_DIRECTORY_INFORMATION_BASE directory_information_base;
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_DIRECTORY_INFORMATION;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_FILE_BOTH_DIR_INFORMATION
{
    FILE_DIRECTORY_INFORMATION_BASE directory_information_base;
	dword EaSize;
	byte  ShortNameLength;
	byte  Reserved;
	byte  ShortName[24];
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_BOTH_DIR_INFORMATION;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_FILE_FULL_DIR_INFORMATION
{
    FILE_DIRECTORY_INFORMATION_BASE directory_information_base;
	dword EaSize;
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_FILE_FULL_DIR_INFORMATION;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_FILE_ID_BOTH_DIR_INFORMATION
{
    FILE_DIRECTORY_INFORMATION_BASE directory_information_base;
	dword EaSize;
	byte  ShortNameLength;
	byte  Reserved1;
	byte  ShortName[24];
	word  Reserved2;
	ddword FileId;
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_ID_BOTH_DIR_INFORMATION;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_FILE_ID_FULL_DIR_INFORMATION
{
    FILE_DIRECTORY_INFORMATION_BASE directory_information_base;
	dword EaSize;
	dword Reserved;
	ddword FileId;
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_ID_FULL_DIR_INFORMATION;
PACK_PRAGMA_POP


PACK_PRAGMA_ONE
typedef struct s_FILE_NAMES_INFORMATION
{
	dword NextEntryOffset;
	dword FileIndex;
	byte  ShortNameLength;
	byte  FileName[1];
} PACK_ATTRIBUTE FILE_FILE_NAMES_INFORMATION;
PACK_PRAGMA_POP


extern const byte zeros24[24];

BBOOL Proc_smb2_QueryDirectory(smb2_stream  *pStream)
{
	RTSMB2_QUERY_DIRECTORY_C command;
	RTSMB2_QUERY_DIRECTORY_R response;
    byte file_name[RTSMB2_MAX_FILENAME_SIZE];
    SMBFSTAT stat;
    dword r;
	PUSER user;
	word sid;
    BBOOL searchFound=FALSE;
    BBOOL isFound;
    BBOOL isEof=FALSE;
    rtsmb_size bytes_remaining = 0;
    void *byte_pointer = 0;
    void *Saved_Inbuf;
    rtsmb_size Saved_read_buffer_remaining;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryDirectory:\n",0);


    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid

    pStream->ReadBufferParms[0].pBuffer = file_name;
    pStream->ReadBufferParms[0].byte_count = sizeof(file_name);

    // Save the input position
    Saved_Inbuf = pStream->pInBuf;
    Saved_read_buffer_remaining = pStream->read_buffer_remaining;

    /* Read into command, TreeId will be present in the input header */
    command.StructureSize = 33;
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);
    if (!pStream->Success)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  RtsmbStreamDecodeCommand failed...\n",0);
 		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
      return TRUE;
    }
    if (command.StructureSize != 33)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryDirectory:  StructureSize invalid...\n",0);
 		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
      return TRUE;
    }

    // == Borrowed from srvtrans2 ==

    user = SMBU_GetUser (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->uid);

    if (pStream->compound_output == TRUE || (command.Flags & (SMB2_RESTART_SCANS|SMB2_REOPEN))==0)
    {
        int _sid;
        sid = 0;
        for (_sid = 0; _sid < prtsmb_srv_ctx->max_searches_per_uid; _sid++)
        {
          if (tc_memcmp(user->searches[_sid].FileId, command.FileId, sizeof(command.FileId))==0)
          {
            searchFound=TRUE;
            sid = _sid;
            break;
          }
        }
    }
    if (!searchFound)
    {
    	for (sid = 0; sid < prtsmb_srv_ctx->max_searches_per_uid; sid++)
    		if (!user->searches[sid].inUse)
    			break;
    	if (sid == prtsmb_srv_ctx->max_searches_per_uid) // no free searches
    	{
    		word i;
    		sid = 0;
    		// find oldest search, kill it.
    		for (i = 1; i < prtsmb_srv_ctx->max_searches_per_uid; i++)
    			if (user->searches[sid].lastUse < user->searches[i].lastUse)
    				sid = i;
    		SMBFIO_GDone (pStream->psmb2Session->pSmbCtx, user->searches[sid].tid, &user->searches[sid].stat);
    	}
        tc_memcpy(user->searches[sid].FileId, command.FileId, sizeof(command.FileId));
	}

//	stat = &user->searches[sid].stat;
	user->searches[sid].lastUse = rtp_get_system_msec ();
	user->searches[sid].inUse = TRUE;
	user->searches[sid].tid = pStream->psmb2Session->pSmbCtx->tid;
	user->searches[sid].pid64 = pStream->InHdr.SessionId;


    // == Done Borrowed from srvtrans2 ==
    if (command.FileNameLength > sizeof(user->searches[sid].name))
    {
        user->searches[sid].inUse = FALSE;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryDirectory:  Search string too large\n",0);
        RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }
    else
        tc_memcpy(user->searches[sid].name,file_name,command.FileNameLength);

    printf("Proc_smb2_QueryDirectory: Maximum output length == %lu\n", command.OutputBufferLength);
    printf("Proc_smb2_QueryDirectory: command.FileInformationClass == %d\n", command.FileInformationClass);
    printf("Proc_smb2_QueryDirectory Search pattern:");
    {int i;
    for (i = 0;i<command.FileNameLength; i+= 2)
      printf("%c", (char )file_name[i]);
    rtp_printf(":\n");
    }

  // SMBFIO_GFirst (PSMB_SESSIONCTX pCtx, word tid, PSMBDSTAT dirobj, PFRTCHAR name)


    if (pStream->compound_output == FALSE && (command.Flags & (SMB2_RESTART_SCANS|SMB2_REOPEN)))
    {
       isFound = SMBFIO_GFirst( (PSMB_SESSIONCTX) pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, &user->searches[sid].stat, user->searches[sid].name);
       printf("==== TOP: Gfirst\n");
    }
    else
    {
	   isFound = SMBFIO_GNext (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, &user->searches[sid].stat);
       printf("==== TOP: Gnext\n");
    }

    if (!isFound)
    {
      pStream->WriteBufferParms[0].pBuffer    = 0;
      pStream->WriteBufferParms[0].byte_count = 0;
      isEof=TRUE;
    }
    else
    { // Prepare to accumulate as much as the space we have left in the output.
      bytes_remaining = pStream->write_buffer_remaining-(pStream->OutHdr.StructureSize + 8);
      byte_pointer = rtp_malloc(bytes_remaining);
      pStream->WriteBufferParms[0].pBuffer    = byte_pointer;
      pStream->WriteBufferParms[0].byte_count = 0;
    }

    while (isFound)
    {
        rtsmb_size bytes_consumed = 0;

        switch (command.FileInformationClass) {
        // FileInformationClass
           case FileDirectoryInformation        : // 0x01
           bytes_consumed = SMB2_FILLFileDirectoryInformation(byte_pointer, bytes_remaining, &user->searches[sid].stat);
           break;
           case FileFullDirectoryInformation    : // 0x02
           bytes_consumed = SMB2_FILLFileFullDirectoryInformation(byte_pointer, bytes_remaining, &user->searches[sid].stat);
           break;
           case FileIdFullDirectoryInformation  : // 0x26
           bytes_consumed = SMB2_FILLFileIdFullDirectoryInformation(byte_pointer, bytes_remaining, &user->searches[sid].stat);
           break;
           case FileBothDirectoryInformation    : // 0x03
           bytes_consumed = SMB2_FILLFileBothDirectoryInformation(byte_pointer, bytes_remaining, &user->searches[sid].stat);
           break;
           case FileIdBothDirectoryInformation  : // 0x25
           bytes_consumed = SMB2_FILLFileIdBothDirectoryInformation(byte_pointer, bytes_remaining, &user->searches[sid].stat);
           break;
           case FileNamesInformation            : // 0x0C
           bytes_consumed = SMB2_FILLFileNamesInformation(byte_pointer, bytes_remaining, &user->searches[sid].stat);
           break;
        }
        if (byte_pointer)
          *((dword *) byte_pointer) = 0;              // Start with next offset pointer zero
        printf("Bytes consumed :%d\n",bytes_consumed);



        if (bytes_consumed == 0)
           break;
        else
        {
            pStream->WriteBufferParms[0].byte_count += bytes_consumed;
            bytes_remaining -= bytes_consumed;
            if (command.Flags & SMB2_RETURN_SINGLE_ENTRY)
            {
                printf("==== SMB2_RETURN_SINGLE_ENTRY break\n");
                break;
            }
            // If not a single entry look for more matches
            isFound = SMBFIO_GNext(pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, &user->searches[sid].stat);
            if (isFound)
            {
               printf("==== Found more stay in\n");
                *((dword *) byte_pointer) = bytes_consumed;           // Next offset pointer
                byte_pointer = PADD(byte_pointer, bytes_consumed);
            }
            else
            {
              printf("==== Found no more get out\n");
             isEof=TRUE;
            }
        }
    }
    //command.FileNameOffset;
    //command.FileNameLength;

    response.StructureSize = 9; // 9
    response.OutputBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.OutputBufferLength)
    { // We''l come back at least one more time so be sure we can reread the input header again
      response.OutputBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
      pStream->compound_output = TRUE;
      pStream->pInBuf = Saved_Inbuf;
      pStream->read_buffer_remaining = Saved_read_buffer_remaining;
    }
    else
    {
      byte_pointer = rtp_malloc(4);           // send a zero in the payload, sending only one byte but work here by 4s.
      *((dword *) byte_pointer) = 0;
      pStream->WriteBufferParms[0].pBuffer    = byte_pointer;
      pStream->WriteBufferParms[0].byte_count = 1;
      response.OutputBufferLength = 0;
      response.OutputBufferOffset = 0;
      pStream->compound_output = FALSE;
    }
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    if (pStream->WriteBufferParms[0].pBuffer)
        rtp_free(pStream->WriteBufferParms[0].pBuffer);
    pStream->WriteBufferParms[0].pBuffer = 0;
    //
    if (isEof && response.OutputBufferLength==0)
    {
      // - Pack a header and response packet set status in header to STATUS_NO_MORE_FILES (0x80000006)
      pStream->OutHdr.Status_ChannelSequenceReserved = SMB2_STATUS_NO_MORE_FILES;
    }
    return TRUE;
} // Proc_smb2_QueryDirectory


static int SMB2_FILLFileDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat)
{
    return 0;
}

// See MS-FSCC - 2.4.14 FileFullDirectoryInformation
PACK_PRAGMA_ONE
typedef struct
{
	dword next_entry_offset;
	dword file_index;
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_end_of_file;
	dword high_end_of_file;
	dword low_allocation_size;
	dword high_allocation_size;

	dword extended_file_attributes;
	dword filename_size;
	dword ea_size;
//	PFRTCHAR filename;

} RTSMB2_FILE_FULL_DIRECTORY_INFO;
PACK_PRAGMA_POP
static int SMB2_FILLFileBaseDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *stat)
{
	RTSMB2_FILE_FULL_DIRECTORY_INFO *pinfo = (RTSMB2_FILE_FULL_DIRECTORY_INFO *) byte_pointer;
	rtsmb_size filename_size = (rtsmb_size) rtsmb_len(stat->filename) * sizeof (rtsmb_char);

    if (sizeof(RTSMB2_FILE_FULL_DIRECTORY_INFO) + filename_size > (rtsmb_size) bytes_remaining)
       return 0;;

	pinfo->low_last_access_time = stat->fatime64.low_time;
	pinfo->high_last_access_time = stat->fatime64.high_time;
	pinfo->low_creation_time = stat->fctime64.low_time;
	pinfo->high_creation_time = stat->fctime64.high_time;
	pinfo->low_last_write_time = stat->fwtime64.low_time;
	pinfo->high_last_write_time = stat->fwtime64.high_time;
	pinfo->low_change_time = stat->fhtime64.low_time;
	pinfo->high_change_time = stat->fhtime64.high_time;
	pinfo->low_end_of_file = stat->fsize;
	pinfo->high_end_of_file = 0;
	pinfo->low_allocation_size = stat->fsize;
	pinfo->high_allocation_size = 0;
	pinfo->extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat->fattributes);
	pinfo->filename_size = 0;
	pinfo->file_index = 0;
	pinfo->ea_size = 0;
    return (int) sizeof(RTSMB2_FILE_FULL_DIRECTORY_INFO);
}


PACK_PRAGMA_ONE
typedef struct
{
	byte short_name_length;
	byte reserved;
	byte short_name[24];
} RTSMB2_FILE_SHORT_DIRECTORY_INFO;
PACK_PRAGMA_POP

static int SMB2_FILLFileFullDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *stat)
{
    RTSMB2_FILE_FULL_DIRECTORY_INFO *pinfo = (RTSMB2_FILE_FULL_DIRECTORY_INFO *) byte_pointer;
    int base_size;
    rtsmb_size filename_size = (rtsmb_size) rtsmb_len(stat->filename) * sizeof (rtsmb_char);

    if (sizeof(RTSMB2_FILE_FULL_DIRECTORY_INFO) + filename_size > (rtsmb_size) bytes_remaining)
       return 0;

    base_size=SMB2_FILLFileBaseDirectoryInformation(byte_pointer, bytes_remaining, stat);
    if (base_size ==0)
        return 0;
    byte_pointer = PADD(byte_pointer,base_size);
    // Copy the filename just after the size
    pinfo->filename_size = filename_size;
    tc_memcpy(byte_pointer, stat->filename, filename_size);
    rtsmb_dump_bytes("FILENAME", byte_pointer, filename_size, DUMPUNICODE);



    return (int) (sizeof(RTSMB2_FILE_FULL_DIRECTORY_INFO) + pinfo->filename_size);
}
static int SMB2_FILLFileIdFullDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat)
{
    return 0;
}

static int SMB2_FILLFileBothDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *stat)
{
    RTSMB2_FILE_FULL_DIRECTORY_INFO *pinfo = (RTSMB2_FILE_FULL_DIRECTORY_INFO *) byte_pointer;
    RTSMB2_FILE_SHORT_DIRECTORY_INFO *pshortinfo;
    int base_size;
    rtsmb_size filename_size = (rtsmb_size) rtsmb_len(stat->filename) * sizeof (rtsmb_char);

    if (sizeof(RTSMB2_FILE_FULL_DIRECTORY_INFO)+sizeof(RTSMB2_FILE_SHORT_DIRECTORY_INFO)+filename_size > (rtsmb_size) bytes_remaining)
       return 0;
    base_size=SMB2_FILLFileBaseDirectoryInformation(byte_pointer, bytes_remaining, stat);
    if (base_size ==0)
       return 0;
    byte_pointer = PADD(byte_pointer,base_size);
    pshortinfo = (RTSMB2_FILE_SHORT_DIRECTORY_INFO *) byte_pointer;
	pshortinfo->short_name_length =   (rtsmb_size) rtsmb_len(stat->short_filename) * sizeof (rtsmb_char);
	pshortinfo->reserved           =  0;
	tc_memcpy(pshortinfo->short_name, stat->short_filename, sizeof(pshortinfo->short_name));
    byte_pointer = PADD(byte_pointer,sizeof(RTSMB2_FILE_SHORT_DIRECTORY_INFO));
    // Copy the filename just after the small file info
    pinfo->filename_size = filename_size;
    tc_memcpy(byte_pointer, stat->filename, filename_size);
    return (int) (sizeof(RTSMB2_FILE_FULL_DIRECTORY_INFO) + sizeof(pshortinfo->short_name) + pinfo->filename_size);
}
static int SMB2_FILLFileIdBothDirectoryInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat)
{
    return -1;
}
static int SMB2_FILLFileNamesInformation(void *byte_pointer, rtsmb_size bytes_remaining, SMBDSTAT *pstat)
{
    return 0;
}





#endif
#endif
