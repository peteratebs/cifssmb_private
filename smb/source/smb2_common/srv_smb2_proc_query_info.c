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
    rtsmb_char file_name [SMBF_FILENAMESIZE + 1];
    word fidflags=0;
    int fid;
    dword r;
    word externalFid;
    PTREE pTree;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  YA YA !!...\n",0);

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    pStream->WriteBufferParms[0].pBuffer = 0;
    pStream->WriteBufferParms[1].pBuffer = 0;


    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid

    file_name[0]=0;
    pStream->ReadBufferParms[0].pBuffer = file_name;
    pStream->ReadBufferParms[0].byte_count = sizeof(file_name);

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  RtsmbStreamDecodeCommand failed...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    if (command.StructureSize != 41)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  StructureSize invalid...\n",0);
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

#define SMB2_0_INFO_FILE       0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY   0x03
#define SMB2_0_INFO_QUOTA      0x04

#define SMB2_FS_INFO_01        0x01
#define SMB2_FS_INFO_FSIZE     0x03  // Size
#define SMB2_FS_INFO_05        0x05

    pStream->WriteBufferParms[0].byte_count = 0;
    printf("Proc_smb2_QueryInfo: Got infotyp == %X\n", command.InfoType);
    if (command.InfoType == SMB2_0_INFO_FILESYSTEM)
    {
       BBOOL isFound; // did we find a file?
      SMBFSTAT stat;

      printf("Proc_smb2_QueryInfo: Processing SMB2_0_INFO_FILESYSTEM == %X\n", command.InfoType);

      isFound = SMBFIO_GFirst (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, stat, file_name);

      printf("Proc_smb2_QueryInfo: SMBFIO_GFirst returned %d\n", isFound);

      switch (command.FileInfoClass) {
        case SMB2_FS_INFO_01:
        {
          pStream->WriteBufferParms[0].byte_count = sizeof(fs_info_01_array);
          pStream->WriteBufferParms[0].pBuffer = rtp_malloc(sizeof(fs_info_01_array));
          memcpy(pStream->WriteBufferParms[0].pBuffer, fs_info_01_array,pStream->WriteBufferParms[0].byte_count);
        }
        break;
        case SMB2_FS_INFO_05:
        {
          pStream->WriteBufferParms[0].byte_count = sizeof(fs_info_05_array);
          pStream->WriteBufferParms[0].pBuffer = rtp_malloc(sizeof(fs_info_05_array));
          memcpy(pStream->WriteBufferParms[0].pBuffer, fs_info_05_array,pStream->WriteBufferParms[0].byte_count);
        }
       break;
       case SMB2_FS_INFO_FSIZE: // 03
       {
         MSFSCC_FILE_FS_SIZE_INFO *pInfo = rtp_malloc(sizeof(MSFSCC_FILE_FS_SIZE_INFO));
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_FILE_FS_SIZE_INFO);
         pStream->WriteBufferParms[0].pBuffer = pInfo;
         pInfo->TotalAllocationUnits      =  FAKE_ALLOCATION_UNITS;
         pInfo->AvailableAllocationUnits  =  FAKE_AVAILABLE_UNITS;
         pInfo->SectorsPerAllocationUnit  =  FAKE_SECTORS_PER_ALLOCATION_UNIT ;
         pInfo->BytesPerSector            =  FAKE_BYTES_PER_SECTOR;
       }
       break;
       default:
          printf("Proc_smb2_QueryInfo: Got unkown file class == %X\n", command.FileInfoClass);
      }
    }
    else
    {
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_NOT_IMPLEMENTED);
        return TRUE;
     }
      printf("Proc_smb2_QueryInfo: Got other infotyp == %X\n", command.InfoType);

    response.StructureSize = 9; // 9
    response.OutputBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.OutputBufferLength)
      response.OutputBufferOffset = (word) (pStream->OutHdr.StructureSize + response.StructureSize-1);
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);

    if (pStream->WriteBufferParms[0].pBuffer)
      rtp_free(pStream->WriteBufferParms[0].pBuffer);
    if (pStream->WriteBufferParms[1].pBuffer)
      rtp_free(pStream->WriteBufferParms[1].pBuffer);

    return TRUE;
} // Proc_smb2_QueryInfo

#if(0)
int fillSMB_FIND_FILE_BOTH_DIRECTORY_INFO (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PRTSMB_HEADER pOutHdr, PFVOID pOutBuf, rtsmb_size size, PSMBDSTAT stat)
{
    MSFSCC_BOTH_DIRECTORY_INFO *pinfo;
    rtsmb_char dosname [CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE];

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
    // pinfo->filename = (PFRTCHAR) stat->filename;
    SMBU_DOSifyName (pinfo->filename, dosname, '\0');
    pinfo->short_name_size = (byte)rtsmb_len ((PFRTCHAR) stat->short_filename);
    rtsmb_cpy (pinfo->short_name, (PFRTCHAR) stat->short_filename);

    pinfo->file_index = 0;
    pinfo->ea_size = 0;
}
#endif  // if 0


#endif
#endif
