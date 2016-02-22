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



// Created: No time specified (0)    // 8
// Volume Serial Number: 0xe78d0889  // 4
// Label Length: 10                  // 4
// Reserved: 0000                    // 2
// Label: peter                      // Unicode

const byte fs_info_01_array[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x89,0x08,0x8d,0xe7,0x0a,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x65,0x00,0x74,0x00,0x65,0x00,0x72,0x00};

//    FS Attributes: 0x0001002f  dw
//    FS Attributes: 0x00000007  dw   - 7 is basic version
//    Max name length: 255       dw
//    Label Length: 8            w
//    FS Name: NTFS              4e00540046005300

const byte fs_info_05_array[] = {0x07,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x54,0x00,0x46,0x00,0x53,0x00};



BBOOL Proc_smb2_QueryInfo(smb2_stream  *pStream)
{
	RTSMB2_QUERY_INFO_C command;
	RTSMB2_QUERY_INFO_R response;

    SMBFSTAT stat;
    word fidflags=0;
    int fid;
    dword r;
    word externalFid;
	PTREE pTree;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  YA YA !!...\n",0);

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  RtsmbStreamDecodeCommand failed...\n",0);
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }

    if (command.StructureSize != 41)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  StructureSize invalid...\n",0);
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }

#define SMB2_0_INFO_FILE       0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY   0x03
#define SMB2_0_INFO_QUOTA      0x04

#define SMB2_FS_INFO_01        0x01
#define SMB2_FS_INFO_05        0x05

    pStream->WriteBufferParms[0].byte_count = 0;
    printf("Proc_smb2_QueryInfo: Got infotyp == %X\n", command.InfoType);
    if (command.InfoType == SMB2_0_INFO_FILESYSTEM)
      printf("Proc_smb2_QueryInfo: Got SMB2_0_INFO_FILESYSTEM == %X\n", command.InfoType);
    else
      printf("Proc_smb2_QueryInfo: Got other infotyp == %X\n", command.InfoType);
    if (command.InfoType == SMB2_0_INFO_FILESYSTEM && command.FileInfoClass == SMB2_FS_INFO_01)
    {
    printf("Proc_smb2_QueryInfo: Got SMB2_FS_INFO_01\n");
      pStream->WriteBufferParms[0].byte_count = sizeof(fs_info_01_array);
      pStream->WriteBufferParms[0].pBuffer = fs_info_01_array;
    }
    else if (command.InfoType == SMB2_0_INFO_FILESYSTEM && command.FileInfoClass == SMB2_FS_INFO_05)
    {
    printf("Proc_smb2_QueryInfo: Got SMB2_FS_INFO_05\n");
      pStream->WriteBufferParms[0].byte_count = sizeof(fs_info_05_array);
      pStream->WriteBufferParms[0].pBuffer = fs_info_05_array;
    }
    else
      printf("Proc_smb2_QueryInfo: Got unkown file class == %X\n", command.FileInfoClass);


    response.StructureSize = 9; // 9
    response.OutputBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.OutputBufferLength)
      response.OutputBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);

    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
} // Proc_smb2_QueryInfo

#endif
#endif
