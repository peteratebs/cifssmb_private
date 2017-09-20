//
// smb2servercreate.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//

#include "smb2serverincludes.hpp"
#include "rtpfile.h"
#include "smb2fileio.hpp"


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


static int SMB2_FILLFileIdBothDirectoryInformation(byte *byte_pointer, int bytes_remaining, struct smb2fstat *dirobjstat,dword &File_index);

extern int decode_create_context_request_values( byte * pcreate_context_buffer, int create_context_buffer_length);

    // pull
    // Return INVALID_PARAMETER If the first character is a path separator.
    // set up flags,read;wants_write;wants_attr_write;
    // Make sure we have write permission if we are deleting
    // Checks permission
    // calculate mode
    // fail if sharetype !DISK OR IPC SMB2_STATUS_NOT_SUPPORTED
    // Decode CreateContexts into decoded_create_context structure
    // Massage the file name to \\ if length == 0, create a null terminated file name
    // Check if  the file is locked by an oplock and needs to send an async response

    // if disk
    //    if its the root make sure perms are correct.
    //    if its not the root stat it
    //      if it exists already
    //        check if creating exclusivly && fail if so.
    //        check if dirent type and permission or fail
    //      else
    //        create directory or file  or fail
    //    find out if delete on close is set
    // if ipc
    //    if opening the IPC root include extra_pXX info
    // check  wants_extra_DHnQ_info is always false
    // check  wants_extra_pMxAc_info,wants_extra_pQfid_info
    // this step may or may not be different for IPC root versus ohers
    // this step may or may not be different for IPC root versus ohers
    // encode the results



int  Smb2ServerSession::ProcessQueryDirectory()
{
  byte *nbss_read_origin= (byte *) read_origin;
  nbss_read_origin -= 4; // Look at the NBSS header
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  InNbssHeader.bindpointers(nbss_read_origin);
  InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());
  NetSmb2QuerydirectoryCmd Smb2QuerydirectoryCmd;
  Smb2QuerydirectoryCmd.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
  local_allocator temp_heap;      //  it's destructor cleans up our temorary allocations
  dword rstatus = SMB2_NT_STATUS_SUCCESS;
  word *TempFileName;

  NetNbssHeader               OutNbssHeader;
  NetSmb2Header               OutSmb2Header;
  NetSmb2QuerydirectoryReply  Smb2QuerydirectoryReply;
  byte *nbss_write_origin= (byte *) write_origin;
  nbss_write_origin-=4;
  memset(nbss_write_origin, 0,OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2QuerydirectoryReply.FixedStructureSize());
  OutNbssHeader.bindpointers(nbss_write_origin);
  OutSmb2Header.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize());
  Smb2QuerydirectoryReply.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize());
  OutSmb2Header.InitializeReply(InSmb2Header);

  Smb2QuerydirectoryReply.StructureSize      = Smb2QuerydirectoryReply.FixedStructureSize();
  Smb2QuerydirectoryReply.OutputBufferOffset = OutSmb2Header.FixedStructureSize()+Smb2QuerydirectoryReply.PackedStructureSize();

  dword search_result_size = 0;

  byte *byte_pointer = nbss_write_origin + OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2QuerydirectoryReply.PackedStructureSize();

  struct smb2fstat dirobjstat;  // Note change this to be part of the search context
  Smb2ServerFileStruct *pFile;

  // cant use Smb2FioCtxtDecl() here
  Smb2FioCtxt Smb2FioCtxt;
//  Smb2FioCtxtDecl(Smb2FioCtxt,this,pShare);   // Fio context for this share

  Smb2ServerShareStruct *pShare = map_shareid_to_sharehandle(InSmb2Header.TreeId());


  // Check the share and a file structure from the session, check the filename parameter and make a copy of it.
  if (!pShare)
    rstatus = SMB2_STATUS_OBJECT_PATH_NOT_FOUND;
  else
  {
    //Smb2QuerydirectoryCmd.FileInformationClass() ;    // FileIdBothDirectoryInformation
//#define SMB2_RESTART_SCANS              0x01
//#define SMB2_RETURN_SINGLE_ENTRY        0x02
//#define SMB2_INDEX_SPECIFIED            0x04
//#define SMB2_REOPEN                     0x10
     Smb2FioCtxt.pServerSession = this;
     Smb2FioCtxt.pShare          = pShare;

//    Smb2QuerydirectoryCmd.FileIndex;
    // HEREHERE - note if file is ffff's it needs to map to grab the handle
     pFile = map_fileid_to_serverfile((byte *)Smb2QuerydirectoryCmd.FileId());

     if (!pFile)
       rstatus = SMB2_STATUS_NO_MORE_FILES;

     if (Smb2QuerydirectoryCmd.Flags()&(SMB2_RESTART_SCANS|SMB2_REOPEN))
     { // Start a scan
       word *TempFileName = (word *) temp_heap.local_rtp_malloc(RTSMB_CFG_MAX_FILENAME_SIZE*2);
       memcpy(TempFileName,InSmb2Header.FixedStructureAddress()+Smb2QuerydirectoryCmd.FileNameOffset(),Smb2QuerydirectoryCmd.FileNameLength());
       TempFileName[(Smb2QuerydirectoryCmd.FileNameLength()/2)] = 0;
       if (!SMB2FIO_GFirst (&Smb2FioCtxt, &dirobjstat, TempFileName))
         rstatus = SMB2_STATUS_NO_MORE_FILES;
     }
     else
     { // For now. need to map the fid to the stat and continue
       rstatus = SMB2_STATUS_NO_MORE_FILES;
     }
  }

  dword File_index = 0;  // This has to accumulate across runs
  dword search_size_total = 0;


  if (rstatus == SMB2_NT_STATUS_SUCCESS)
  {
    dword bytes_remaining = Smb2QuerydirectoryCmd.OutputBufferLength();
   for(;;)
   {
     // Remember the next link so we can update
     NetWiredword NextEntryOffset;
     NextEntryOffset.bindaddress(byte_pointer);

     switch (Smb2QuerydirectoryCmd.FileInformationClass()) {
         case FileIdBothDirectoryInformation:
          search_result_size = SMB2_FILLFileIdBothDirectoryInformation(byte_pointer, bytes_remaining, &dirobjstat, File_index);
          bytes_remaining -= search_result_size;
          search_size_total += search_result_size;
          byte_pointer  += search_result_size;
          break;
         case FileDirectoryInformation      :
         case FileFullDirectoryInformation  :
         case FileIdFullDirectoryInformation:
         case FileBothDirectoryInformation  :
         case FileNamesInformation          :
         default:
            search_result_size = 0;
         break;
     }
     if (bytes_remaining < 1024)
     {
       break;
     }
     if (search_result_size == 0)
     {
       rstatus = SMB2_STATUS_NO_MORE_FILES;
       break;
     }
     if (!SMB2FIO_GNext(&Smb2FioCtxt,&dirobjstat))
     {
       // rstatus = SMB2_NT_STATUS_SUCCESS;
       break;
     }
     NextEntryOffset = search_result_size;
   }
  }

#if (0)
=====
    byte * pFileId = RTSmb2_mapWildFileId(pStream, command.FileId);

    // See if we have a match for this file id
    sid = 0;
    searchFound = find_smb2_sid_from_fid(&sid, pFileId, user, sizeof(command.FileId));
    if (searchFound)
    {
      if ((command.Flags&(SMB2_RESTART_SCANS|SMB2_REOPEN)) )
      {   // Make sure to start over if we found an open directory on a rescan
//RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: Gdone called on flags %X\n", command.Flags);
          SMBFIO_GDone (pStream->pSmbCtx, user->searches[sid].tid, &user->searches[sid].stat);
          user->searches[sid].File_index = 0;
          user->searches[sid].inUse=FALSE;
          searchFound=FALSE;
      }
    }
=====
#endif

    OutSmb2Header.Status_ChannelSequenceReserved = rstatus; // SMB2_NT_STATUS_SUCCESS;
    bool found=false;
   // Check if the file/dir should/should not exist
    if (pShare->share_type == ST_DISKTREE)
    {
    }

    if (rstatus == SMB2_NT_STATUS_SUCCESS)
    {
      Smb2QuerydirectoryReply.OutputBufferLength = search_size_total;
    }

   OutNbssHeader.nbss_packet_size =
      OutSmb2Header.FixedStructureSize()+
      Smb2QuerydirectoryReply.PackedStructureSize() + search_size_total;

    return OutNbssHeader.nbss_packet_size() + 4;
}

//
static int SMB2_FILLFileIdBothDirectoryInformation(byte *byte_pointer, int bytes_remaining, struct smb2fstat *dirobjstat,dword &File_index)
{
    ms_FILE_ID_BOTH_DIR_INFORMATION  BothDirInfo;
    memset(byte_pointer, 0, BothDirInfo.FixedStructureSize());
    BothDirInfo.bindpointers(byte_pointer);
    word *unicode_long_filename;
    word *unicode_short_filename;



    dword LongFileNameLength = (dword) 2*(strnlen(dirobjstat->filename, RTSMB_CFG_MAX_FILENAME_SIZE));
    unicode_long_filename = rtsmb_util_malloc_ascii_to_unicode (dirobjstat->filename);

    dword ShortFileNameLength = 0;

    // Add the null term if the string has length
    LongFileNameLength = LongFileNameLength  ? (LongFileNameLength +2):0;
    ShortFileNameLength = ShortFileNameLength? (ShortFileNameLength+2):0;

    BothDirInfo.FileIndex       =  File_index;                // NetWiredword    FileIndex;
    BothDirInfo.CreationTime    =  dirobjstat->f_ctime64;     // NetWireFileTime CreationTime;
    BothDirInfo.LastAccessTime  =  dirobjstat->f_atime64;     // NetWireFileTime LastAccessTime;
    BothDirInfo.LastWriteTime   =  dirobjstat->f_wtime64;     // NetWireFileTime LastWriteTime;
    BothDirInfo.ChangeTime      =  dirobjstat->f_htime64;     // NetWireFileTime ChangeTime;
    BothDirInfo.EndofFile       =  dirobjstat->fsize64;       // NetWireddword   EndofFile;
    BothDirInfo.AllocationSize  =  dirobjstat->fsize64;       // NetWireddword   AllocationSize;
    BothDirInfo.FileAttributes  =  rtsmb_util_rtsmb_to_smb_attributes(dirobjstat->fattributes);   // NetWiredword    FileAttributes;
    BothDirInfo.FileNameLength  =  LongFileNameLength;        // NetWiredword    FileNameLength;
    BothDirInfo.EaSize          =  0;                          // NetWiredword    EaSize;
    BothDirInfo.ShortNameLength =  0;                         // NetWirebyte     ShortNameLength;
    BothDirInfo.FileId          =  dirobjstat->unique_fileid;  // NetWireddword   FileId;


    memcpy(byte_pointer+BothDirInfo.PackedStructureSize(), unicode_long_filename,LongFileNameLength );
    File_index = File_index + 1;

    smb_rtp_free(unicode_long_filename);

    return (int) BothDirInfo.PackedStructureSize()+LongFileNameLength+1;
}
