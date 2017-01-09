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
#include "srvfio.h"


// Filesystem                1K-blocks      Used Available Use% Mounted on
// 0a_share_with_virtual_box 249068540 112020068 137048472  45% /media/sf_0a_share_with_virtual_box

#define FAKE_ALLOCATION_UNITS               249068540
#define FAKE_AVAILABLE_UNITS                137048472

// #define FAKE_ALLOCATION_UNITS               0x10000000
// #define FAKE_AVAILABLE_UNITS                0x01000000
#define FAKE_SECTORS_PER_ALLOCATION_UNIT    2
#define FAKE_BYTES_PER_SECTOR               512

unsigned char FAKE_VOLUME_LABEL[] = "I\0A\0M\0A\0F\0A\0K\0E\0L\0A\0B\0E\0L\0\0\0";
unsigned char FAKE_VOLUME_CREATION_TIME[] = {0x00, 0x78, 0x6b, 0x02, 0xbf, 0x27, 0xd2, 0x12};
#define FAKE_VOLUME_SERIAL_NUMBER 0x1234


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


static PFRTCHAR RTSmb2_get_path_and_stat_from_fid(smb2_stream  *pStream, word externalFid, PSMBFSTAT pstat)
{
PFRTCHAR filepath=0;
PTREE pTree =  SMBU_GetTree (pStream->pSmbCtx, pStream->pSmbCtx->tid);
  if (pTree)
  {
    filepath = SMBU_GetFileNameFromFid (pStream->pSmbCtx, externalFid);
    if (filepath && SMBFIO_Stat (pStream->pSmbCtx, pStream->pSmbCtx->tid, filepath, pstat))
      return filepath;
    else
      filepath=0;
  }
  return filepath;
}


BBOOL Proc_smb2_QueryInfo(smb2_stream  *pStream)
{
    RTSMB2_QUERY_INFO_C command;
    RTSMB2_QUERY_INFO_R response;
    rtsmb_char file_name [SMBF_FILENAMESIZE + 1];
    word fidflags=0;
    int fid;
    dword r;
    word externalFid;
    BBOOL not_implemented=TRUE;

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
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  RtsmbStreamDecodeCommand failed...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }

    if (command.StructureSize != 41)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo:  StructureSize invalid...\n");
        RtsmbWriteSrvStatus(pStream,SMB2_STATUS_INVALID_PARAMETER);
        return TRUE;
    }
//  see ms-fscc section 2.5
#define SMB2_FS_INFO_01          0x01
#define SMB2_FS_INFO_FSIZE       0x03  // Size
#define SMB2_FS_INFO_05          0x05
#define SMB2_FS_INFO_SIZE_7      0x07
#define SMB2_FS_INFO_VOLUME      0x2d  // 45
#define SMB2_FS_OBJECT_ID_INFO   0x08
#define SMB2_FILE_INFO_ALL       0x12
#define SMB2_FILE_INFO_FULL      0x2  // not sure if right.
#define SMB2_FILE_INFO_STANDARD      0x5
#define SMB2_FILE_NETWORK_OPEN_INFO  0x22

    pStream->WriteBufferParms[0].byte_count = 0;
    if (command.InfoType == SMB2_0_INFO_FILE)
    {
      not_implemented=FALSE;
      switch (command.FileInfoClass) {
       case SMB2_FILE_NETWORK_OPEN_INFO: //     0x22  .
       {
         MSFSCC_FILE_NETWORK_OPEN_INFORMATION *pInfo;
         SMBFSTAT stat;
         PFRTCHAR filepath;

//         word externalFid = *((word *) &command.FileId[0]);
          // Compound requests send 0xffff ffff ffff ffff to mean the last file if returned by create
          // Map if neccessary
         byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
         word externalFid = RTSmb2_get_externalFid(pFileId);

         filepath = RTSmb2_get_path_and_stat_from_fid(pStream, externalFid, &stat);
         if(!filepath)
         {
           RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
           return TRUE;
         }
         pInfo = rtp_malloc(sizeof(*pInfo));
         pStream->WriteBufferParms[0].byte_count = sizeof(*pInfo);
         pStream->WriteBufferParms[0].pBuffer = pInfo;


         pInfo->low_last_access_time = stat.f_atime64.low_time;
         pInfo->high_last_access_time = stat.f_atime64.high_time;
         pInfo->low_creation_time = stat.f_ctime64.low_time;
         pInfo->high_creation_time = stat.f_ctime64.high_time;
         pInfo->low_last_write_time = stat.f_wtime64.low_time;
         pInfo->high_last_write_time = stat.f_wtime64.high_time;
         pInfo->low_change_time = stat.f_htime64.low_time;
         pInfo->high_change_time = stat.f_htime64.high_time;
         pInfo->low_end_of_file = stat.fsize;
         pInfo->high_end_of_file = stat.fsize_hi;
         pInfo->low_allocation_size = stat.fsize;
         pInfo->high_allocation_size = stat.fsize_hi;
         pInfo->extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
         pInfo->reserved = 0;
         break;
       }
       case SMB2_FILE_INFO_ALL: // 0x12
       {
         int file_name_len_bytes;
         MSFSCC_ALL_DIRECTORY_INFO *pInfo;
         BBOOL worked;
         SMBFSTAT stat;
         PFRTCHAR filepath;
         PFRTCHAR filename;

//         word externalFid = *((word *) &command.FileId[0]);
          // Compound requests send 0xffff ffff ffff ffff to mean the last file if returned by create
          // Map if neccessary

         byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
         word externalFid = RTSmb2_get_externalFid(pFileId);
         filepath = RTSmb2_get_path_and_stat_from_fid(pStream, externalFid, &stat);
         if(!filepath)
         {
           RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
           return TRUE;
         }
         filename = SMBU_GetFilename (filepath);
         file_name_len_bytes = (rtsmb_len (filename)+1)*sizeof(rtsmb_char);

         pInfo = rtp_malloc(sizeof(*pInfo)+file_name_len_bytes);
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_ALL_DIRECTORY_INFO)+file_name_len_bytes;
         pStream->WriteBufferParms[0].pBuffer = pInfo;


         pInfo->low_last_access_time = stat.f_atime64.low_time;
         pInfo->high_last_access_time = stat.f_atime64.high_time;
         pInfo->low_creation_time = stat.f_ctime64.low_time;
         pInfo->high_creation_time = stat.f_ctime64.high_time;
         pInfo->low_last_write_time = stat.f_wtime64.low_time;
         pInfo->high_last_write_time = stat.f_wtime64.high_time;
         pInfo->low_change_time = stat.f_htime64.low_time;
         pInfo->high_change_time = stat.f_htime64.high_time;
         pInfo->low_end_of_file = stat.fsize;
         pInfo->high_end_of_file = stat.fsize_hi;
         pInfo->low_allocation_size = stat.fsize;
         pInfo->high_allocation_size = stat.fsize_hi;
         pInfo->extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
//         pInfo->filename_size = file_name_len_bytes/sizeof(rtsmb_char);       // dword filename_size;
//         pInfo->ea_size = 0;       // dword ea_size;
         pInfo->number_of_links = 0;
         pInfo->delete_pending = 0;
         pInfo->is_directory = 0;
         pInfo->IndexNumber = 0;
         pInfo->EaSize = 0;
         pInfo->is_directory =  pInfo->extended_file_attributes&SMB_FA_D?1:0;
//         pInfo->is_directory =  |= SMB_FA_D; (stat.fattributes & RTP_FILE_ATTRIB_ISDIR)?1:0;
         if (pInfo->is_directory)
            pInfo->AccessFlags =             // AccessInformation (4 bytes): A FILE_ACCESS_INFORMATION structure specified in section 2.4.1.
              SMB2_DIR_ACCESS_MASK_FILE_LIST_DIRECTORY|
              SMB2_DIR_ACCESS_MASK_FILE_ADD_FILE|
              SMB2_DIR_ACCESS_MASK_FILE_ADD_SUBDIRECTORY|
              SMB2_DIR_ACCESS_MASK_FILE_TRAVERSE|
              SMB2_DIR_ACCESS_MASK_FILE_DELETE_CHILD|
              SMB2_DIR_ACCESS_MASK_FILE_READ_ATTRIBUTES|
              SMB2_DIR_ACCESS_MASK_FILE_WRITE_ATTRIBUTES|
              SMB2_DIR_ACCESS_MASK_DELETE;
         else
            pInfo->AccessFlags =             // AccessInformation (4 bytes): A FILE_ACCESS_INFORMATION structure specified in section 2.4.1.
              SMB2_DIR_ACCESS_MASK_FILE_READ_ATTRIBUTES|
              SMB2_DIR_ACCESS_MASK_FILE_WRITE_ATTRIBUTES|
              SMB2_DIR_ACCESS_MASK_DELETE|
              SMB2_DIR_ACCESS_MASK_GENERIC_EXECUTE|
              SMB2_DIR_ACCESS_MASK_GENERIC_WRITE|
              SMB2_DIR_ACCESS_MASK_GENERIC_READ;

         pInfo->CurrentByteOffset = 0;      //
         pInfo->Mode = 0;      //
         pInfo->AlignmentRequirement = 0;            //
         pInfo->FileNameLength = file_name_len_bytes;
         pInfo += 1;
         tc_memcpy(pInfo, filename, file_name_len_bytes);
       }
       break;
       case SMB2_FILE_INFO_FULL: // Does not exist
       {
         int file_name_len_bytes;
         MSFSCC_FULL_DIRECTORY_INFO *pInfo;
         BBOOL worked;
         SMBFSTAT stat;

         byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
         word externalFid = RTSmb2_get_externalFid(pFileId);
         PFRTCHAR filepath = RTSmb2_get_path_and_stat_from_fid(pStream, externalFid, &stat);
         if(!filepath)
         {
           RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
           return TRUE;
         }
         PFRTCHAR filename =  SMBU_GetFilename (filepath);
         file_name_len_bytes = (rtsmb_len (filename)+1)*sizeof(rtsmb_char);
         pInfo = rtp_malloc(sizeof(MSFSCC_FULL_DIRECTORY_INFO)+file_name_len_bytes);
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_FULL_DIRECTORY_INFO)+file_name_len_bytes;
         pStream->WriteBufferParms[0].pBuffer = pInfo;

         pInfo->file_index = 0;       // dword file_index;
         pInfo->low_last_access_time = stat.f_atime64.low_time;
         pInfo->high_last_access_time = stat.f_atime64.high_time;
         pInfo->low_creation_time = stat.f_ctime64.low_time;
         pInfo->high_creation_time = stat.f_ctime64.high_time;
         pInfo->low_last_write_time = stat.f_wtime64.low_time;
         pInfo->high_last_write_time = stat.f_wtime64.high_time;
         pInfo->low_change_time = stat.f_htime64.low_time;
         pInfo->high_change_time = stat.f_htime64.high_time;
         pInfo->low_end_of_file = stat.fsize;
         pInfo->high_end_of_file = stat.fsize_hi;
         pInfo->low_allocation_size = stat.fsize;
         pInfo->high_allocation_size = stat.fsize_hi;
         pInfo->extended_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
         pInfo->filename_size = file_name_len_bytes/sizeof(rtsmb_char);       // dword filename_size;
         pInfo->ea_size = 0;       // dword ea_size;
         pInfo += 1;
         tc_memcpy(pInfo, filename, file_name_len_bytes);
       }
       break;
       case SMB2_FILE_INFO_STANDARD:
       {
         int file_name_len_bytes;
         MSFSCC_STANDARD_DIRECTORY_INFO *pInfo;
         BBOOL worked;
         SMBFSTAT stat;

         byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
         word externalFid = RTSmb2_get_externalFid(pFileId);
         PFRTCHAR filepath = RTSmb2_get_path_and_stat_from_fid(pStream, externalFid, &stat);
         if(!filepath)
         {
           RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
           return TRUE;
         }
         pInfo = rtp_malloc(sizeof(MSFSCC_STANDARD_DIRECTORY_INFO));
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_STANDARD_DIRECTORY_INFO);
         pStream->WriteBufferParms[0].pBuffer = pInfo;

         pInfo->low_end_of_file = stat.fsize;
         pInfo->high_end_of_file = stat.fsize_hi;
         pInfo->low_allocation_size = stat.fsize;
         pInfo->high_allocation_size = stat.fsize_hi;
         pInfo->number_of_links=1;
         pInfo->delete_pending=0;

         pInfo->directory =  rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes)&SMB_FA_D?1:0;
         pInfo->reserved=0;
         pInfo += 1;
       }
       break;
       default:
          not_implemented=TRUE;
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo SMB2_0_INFO_FILE: Got unknown file class == %X\n", command.FileInfoClass);
         break;
      }
    }
    else if (command.InfoType == SMB2_0_INFO_FILESYSTEM)
    {
      not_implemented=FALSE;

      switch (command.FileInfoClass) {
        case SMB2_FS_INFO_01:
        {
          pStream->WriteBufferParms[0].byte_count = sizeof(fs_info_01_array);
          pStream->WriteBufferParms[0].pBuffer = rtp_malloc(sizeof(fs_info_01_array));
          tc_memcpy(pStream->WriteBufferParms[0].pBuffer, fs_info_01_array,pStream->WriteBufferParms[0].byte_count);
        }
        break;
        case SMB2_FS_INFO_05:
        {
          pStream->WriteBufferParms[0].byte_count = sizeof(fs_info_05_array);
          pStream->WriteBufferParms[0].pBuffer = rtp_malloc(sizeof(fs_info_05_array));
          tc_memcpy(pStream->WriteBufferParms[0].pBuffer, fs_info_05_array,pStream->WriteBufferParms[0].byte_count);
        }
       break;
       case SMB2_FS_INFO_FSIZE: // 03
       {
         dword blocks, bfree, sectors, bytes;
         MSFSCC_FILE_FS_SIZE_INFO *pInfo = rtp_malloc(sizeof(MSFSCC_FILE_FS_SIZE_INFO));
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_FILE_FS_SIZE_INFO);
         pStream->WriteBufferParms[0].pBuffer = pInfo;
         PTREE pTree = SMBU_GetTree (pStream->pSmbCtx, pStream->pSmbCtx->tid);
         if (!pTree || pTree->type != ST_DISKTREE || SMBFIO_GetFree (pStream->pSmbCtx, pStream->pSmbCtx->tid, &blocks, &bfree, &sectors, &bytes) == FALSE)
         {
           pInfo->TotalAllocationUnits      =  0;
           pInfo->AvailableAllocationUnits  =  0;
           pInfo->SectorsPerAllocationUnit  =  1;
           pInfo->BytesPerSector            =  512;
         }
         else
         {
           pInfo->TotalAllocationUnits      =  blocks;
           pInfo->AvailableAllocationUnits  =  bfree;
           pInfo->SectorsPerAllocationUnit  =  sectors;
           pInfo->BytesPerSector            =  bytes;
         }
       }
       break;
       case SMB2_FS_INFO_SIZE_7: // 07
       {
         dword blocks, bfree, sectors, bytes;
         MSFSCC_FILE_FS_FULL_SIZE_INFO *pInfo = rtp_malloc(sizeof(MSFSCC_FILE_FS_FULL_SIZE_INFO));
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_FILE_FS_FULL_SIZE_INFO);
         pStream->WriteBufferParms[0].pBuffer = pInfo;
         PTREE pTree = SMBU_GetTree (pStream->pSmbCtx, pStream->pSmbCtx->tid);
         if (!pTree || pTree->type != ST_DISKTREE || SMBFIO_GetFree (pStream->pSmbCtx, pStream->pSmbCtx->tid, &blocks, &bfree, &sectors, &bytes) == FALSE)
         {
           pInfo->TotalAllocationUnits      =  0;
           pInfo->CallerAvailableAllocationUnits  =  0;
           pInfo->ActualAvailableAllocationUnits  =  0;
           pInfo->SectorsPerAllocationUnit  =  1;
           pInfo->BytesPerSector            =  512;

         }
         else
         {
           pInfo->TotalAllocationUnits      =  blocks;
           pInfo->CallerAvailableAllocationUnits  =  bfree;
           pInfo->ActualAvailableAllocationUnits  =  bfree;
           pInfo->SectorsPerAllocationUnit  =  sectors;
           pInfo->BytesPerSector            =  bytes;
         }
       }
       break;

       case SMB2_FS_OBJECT_ID_INFO: // 08
       {
          SMBFSTAT stat;
          byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);
          word externalFid = RTSmb2_get_externalFid(pFileId);
          PFRTCHAR filepath = RTSmb2_get_path_and_stat_from_fid(pStream, externalFid, &stat);

          if (!filepath)
          {
            RtsmbWriteSrvStatus(pStream,SMB2_STATUS_UNSUCCESSFUL);
            return TRUE;
          }
          else
          {
            unsigned char *p = (unsigned char *) rtp_malloc(64);
            pStream->WriteBufferParms[0].byte_count = 64;
            pStream->WriteBufferParms[0].pBuffer = p;
            // Memset so uninitialized fields are zeros
            tc_memset(p, 0, 64);
    //      ObjectId (16 bytes)
             tc_memcpy(&p[0], stat.unique_fileid, sizeof(stat.unique_fileid));
    //      BirthVolumeId (16 bytes)  // 0
    //      BirthObjectId (16 bytes)
              tc_memcpy(&p[32], stat.unique_fileid, sizeof(stat.unique_fileid));
    //      DomainId (16 bytes)       // 0
          }
       }
       break;
       case SMB2_FS_INFO_VOLUME: // 45
       {
         int volume_label_bytes = 2+ (2*rtsmb_len(FAKE_VOLUME_LABEL));
         MSFSCC_FILE_FS_VOLUME_INFO *pInfo = rtp_malloc(sizeof(MSFSCC_FILE_FS_VOLUME_INFO)+volume_label_bytes);
         pStream->WriteBufferParms[0].byte_count = sizeof(MSFSCC_FILE_FS_VOLUME_INFO)+volume_label_bytes;
         pStream->WriteBufferParms[0].pBuffer = pInfo;
         tc_memcpy((void *)&pInfo->VolumeCreationTime, FAKE_VOLUME_CREATION_TIME, sizeof(pInfo->VolumeCreationTime));
         pInfo->VolumeSerialNumber            =  FAKE_VOLUME_SERIAL_NUMBER;
         pInfo->VolumeLabelLength             =  volume_label_bytes;
         pInfo->SupportsObjects               =  0;
         pInfo->Reserved                      =  0;
         pInfo++;
         tc_memcpy((void *) pInfo, FAKE_VOLUME_LABEL, volume_label_bytes);
       }
       break;

       default:
          not_implemented=TRUE;
          RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_QueryInfo SMB2_0_INFO_FILESYSTEM: Got unknown file class == %X\n", command.FileInfoClass);
         break;
      }
    }

    if (not_implemented)
    {
      RtsmbWriteSrvStatus(pStream, SMB2_STATUS_NOT_IMPLEMENTED);
      return TRUE;
    }
    response.StructureSize = 9; // 9
    response.OutputBufferLength = (word) pStream->WriteBufferParms[0].byte_count;
    if (response.OutputBufferLength)
    {
      word w  = (word) dwordalign((pStream->OutHdr.StructureSize + response.StructureSize-1), 8);
      response.OutputBufferOffset = w;
    }
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);

    if (pStream->WriteBufferParms[0].pBuffer)
      RTP_FREE(pStream->WriteBufferParms[0].pBuffer);
    if (pStream->WriteBufferParms[1].pBuffer)
      RTP_FREE(pStream->WriteBufferParms[1].pBuffer);

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
    pinfo->high_end_of_file = stat->fsize_hi;
    pinfo->low_allocation_size = stat->fsize;
    pinfo->high_allocation_size = stat->fsize_hi;

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
