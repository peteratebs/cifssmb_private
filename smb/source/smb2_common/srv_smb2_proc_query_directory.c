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



BBOOL Proc_smb2_QueryDirectory(smb2_stream  *pStream)
{
	RTSMB2_QUERY_DIRECTORY_C command;
	RTSMB2_QUERY_DIRECTORY_R response;
    byte file_name[RTSMB2_MAX_FILENAME_SIZE];

    SMBFSTAT stat;
    word fidflags=0;
    int fid;
    dword r;
    word externalFid;
	PTREE pTree;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryDirectory:\n",0);

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid

    pStream->ReadBufferParms[0].pBuffer = file_name;
    pStream->ReadBufferParms[0].byte_count = sizeof(file_name);

    /* Read into command, TreeId will be present in the input header */
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

    switch (command.FileInformationClass) {
    // FileInformationClass
       case FileDirectoryInformation        : // 0x01
       break;
       case FileFullDirectoryInformation    : // 0x02
       break;
       case FileIdFullDirectoryInformation  : // 0x26
       break;
       case FileBothDirectoryInformation    : // 0x03
       break;
       case FileIdBothDirectoryInformation  : // 0x25
       break;
       case FileNamesInformation            : // 0x0C
       break;
    }
    switch (command.Flags) {
       case SMB2_RESTART_SCANS              : // 0x01
       break;
       case SMB2_RETURN_SINGLE_ENTRY        : // 0x02
       break;
       case SMB2_INDEX_SPECIFIED            : // 0x04
       break;
       case SMB2_REOPEN                     : // 0x10
       break;
    }
    //command.FileNameOffset;
    //command.FileNameLength;

    printf("Proc_smb2_QueryDirectory: Maximum output length == %d\n", command.OutputBufferLength);
    printf("Proc_smb2_QueryDirectory Search pattern:");
    {int i;
    for (i=0;i<command.FileNameLength; i+= 2)
      printf("%c", (char )file_name[i]);
    rtp_printf(":\n");
    }

    response.StructureSize = 9; // 9
    response.OutputBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.OutputBufferLength)
      response.OutputBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
} // Proc_smb2_QueryDirectory

#endif
#endif
