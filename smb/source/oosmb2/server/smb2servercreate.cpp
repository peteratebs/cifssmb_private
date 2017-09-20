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



int  Smb2ServerSession::ProcessCreate()
{
  byte *nbss_read_origin= (byte *) read_origin;
  nbss_read_origin -= 4; // Look at the NBSS header
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  InNbssHeader.bindpointers(nbss_read_origin);
  InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());
  NetSmb2CreateCmd Smb2CreateCmd;
  Smb2CreateCmd.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
  local_allocator temp_heap;      //  it's destructor cleans up our temorary allocations

  dword CreateAction = 1; // 1== FILE_OPEN, 0 = SUPER_SEDED, 2=CREATED, 3=OVERWRITTEN
  bool wants_extra_pMxAc_info = false;
  bool wants_extra_pQfid_info = false;
  bool delete_on_close=false;
  word *TempFileName;     // Alloced/freed via temp_heap
  Smb2ServerFileStruct *pFile = 0;
  session_file_instance *pFileInstance=0;
  dword rstatus = SMB2_NT_STATUS_SUCCESS;

  Smb2ServerShareStruct *pShare = map_shareid_to_sharehandle(InSmb2Header.TreeId());

  // Check the share and a file structure from the session, check the filename parameter and make a copy of it.
  if (!pShare)
    rstatus = SMB2_STATUS_OBJECT_PATH_NOT_FOUND;
  else
  {
    pFile = allocate_server_file_struct();
    pFileInstance = allocate_session_file();

    TempFileName = (word *) temp_heap.local_rtp_malloc(RTSMB_CFG_MAX_FILENAME_SIZE*2);
    if (!pFile || !pFileInstance || !TempFileName)
      rstatus = SMB2_STATUS_INSUFFICIENT_RESOURCES;
    else
    {
      TempFileName[0] = '\\'; TempFileName[1] = '.';TempFileName[2] = 0; // if filename from the client is empty use "\." to stat the root
      if (Smb2CreateCmd.NameLength())               // otherwise copy and be sure it's null termed
      {
        memcpy(TempFileName,InSmb2Header.FixedStructureAddress()+Smb2CreateCmd.NameOffset(),Smb2CreateCmd.NameLength());
        TempFileName[(Smb2CreateCmd.NameLength()/2)+1] = 0;
      }
      // Return INVALID_PARAMETER If the first character is not path separator.
      if (TempFileName[0] != '\\')
        rstatus = SMB2_STATUS_INVALID_PARAMETER;
    }
  }

  //   These are global to the if (rstatus == SMB2_NT_STATUS_SUCCESS) clause that follow
  //   if (rstatus == SMB2_NT_STATUS_SUCCESS)

  Smb2FioCtxtDecl(Smb2FioCtxt,this,pShare);   // Fio context for this share
  int flags=0;int mode=0;

  if (rstatus == SMB2_NT_STATUS_SUCCESS)
  {
    bool wants_read,wants_write,wants_attr_write;
    byte permissions = 5; // SET IT TO A USELESS VALUE ?
    wants_read=wants_write=wants_attr_write=false;

    if (Smb2CreateCmd.DesiredAccess()&(0x80000000|0x20000000|0x10000000|0x20000|0x20|0x1))  wants_read = true;
    if (Smb2CreateCmd.DesiredAccess()&(0x2|0x4|0x40|0x10000|0x10000000|0x40000000))         wants_write = true;
    if (Smb2CreateCmd.DesiredAccess()&(0x10|0x100|0x4000|0x8000|0x2000000))                 wants_attr_write = true;
    switch (Smb2CreateCmd.CreateDisposition())  {
        default:
        case 0: {                                                   wants_read = true;   break;}  //SUPERSEDE
        case 1: {                                                   wants_read = true;   break;}  //NT_OPEN_EXISTING:
        case 2: { flags |= RTP_FILE_O_CREAT | RTP_FILE_O_EXCL;      wants_write = true;  break;}//.. NT_CREATE_NEW
        case 3: {    flags |= RTP_FILE_O_CREAT;                     wants_write = true; break;}   //NT_OPEN_ALWAYS:
        case 4: {   flags |= RTP_FILE_O_TRUNC;                       wants_write = true; break; }  //NT_TRUNCATE:
        case 5: {    flags |= RTP_FILE_O_CREAT | RTP_FILE_O_TRUNC;  wants_write = true; break; }// NT_CREATE_ALWAYS:
    }
    // Make sure we have write permission if we are deleting
    if (Smb2CreateCmd.CreateOptions()&FILE_DELETE_ON_CLOSE)  wants_write = true;
    if (wants_read && wants_write)  { flags |= RTP_FILE_O_RDWR;permissions = SECURITY_READWRITE;}  /* reading and writing */
    else if (wants_read) { flags |= RTP_FILE_O_RDONLY;  permissions = SECURITY_READ; }            /* reading only   */
    else if (wants_write){ flags |= RTP_FILE_O_WRONLY;  permissions = SECURITY_WRITE;  }          /* writing only   */
    if (wants_attr_write) { permissions = SECURITY_READWRITE;  }
    if (Smb2CreateCmd.FileAttributes() & 0x80)  {  mode = RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD|RTP_FILE_ATTRIB_ARCHIVE; /* VM */ }
    else
    {
      mode =  Smb2CreateCmd.FileAttributes() & 0x01 ? RTP_FILE_S_IREAD   : 0;
      mode |= Smb2CreateCmd.FileAttributes() & 0x02 ? RTP_FILE_S_HIDDEN  : 0;
      mode |= Smb2CreateCmd.FileAttributes() & 0x04 ? RTP_FILE_S_SYSTEM  : 0;
      mode |= Smb2CreateCmd.FileAttributes() & 0x20 ? RTP_FILE_S_ARCHIVE : 0;
    }
    if (pShare->is_readonly && ((permissions == SECURITY_READWRITE)||(permissions == SECURITY_WRITE)))
      rstatus = SMB2_STATUS_ACCESS_DENIED;
    if ((Smb2CreateCmd.CreateOptions() & (0x01|0x40)) == 0)   // Can't be both file and directory
      rstatus = SMB2_STATUS_INVALID_PARAMETER;
  }
  bool found=false;
  // Check if the file/dir should/should not exist
  if (pShare->share_type == ST_DISKTREE)
  {
     bool okay;
     dword ifbad =  SMB2_NT_STATUS_SUCCESS;
     found = SMB2FIO_Stat(&Smb2FioCtxt, TempFileName, pFile->pstat);
     switch (Smb2CreateCmd.CreateDisposition())  {
      default:
      case 0: { okay = true;   break;}   //SUPERSEDE
      case 1: { okay = found; ifbad = SMB2_STATUS_NO_SUCH_FILE; break;}   //NT_OPEN_EXISTING:
      case 2: { okay = !found;ifbad = SMB2_STATUS_OBJECT_NAME_COLLISION; break;}  //.. NT_CREATE_NEW
      case 3: { okay = true;  break;}  //NT_OPEN_ALWAYS:
      case 4: { okay = found; ifbad = SMB2_STATUS_NO_SUCH_FILE;  break; } //NT_TRUNCATE:
      case 5: { okay = true;   break; } // NT_CREATE_ALWAYS:
     }
     if (!okay)
       rstatus = ifbad;
     else if (found)
     {  // check the found file type against the request
        if (!(pFile->pstat->fattributes & RTP_FILE_ATTRIB_ISDIR)&&(Smb2CreateCmd.CreateOptions()&0x1))  // should be a directory
          rstatus = SMB2_STATUS_ACCESS_DENIED;
        if ( (pFile->pstat->fattributes & RTP_FILE_ATTRIB_ISDIR)&&(Smb2CreateCmd.CreateOptions()&0x4))  // should be a file
          rstatus = SMB2_STATUS_FILE_IS_A_DIRECTORY;
     }
     // HEREHERE check if we need oplock pending
  }

  if (rstatus == SMB2_NT_STATUS_SUCCESS)
  {
    if (Smb2CreateCmd.CreateOptions()&FILE_DELETE_ON_CLOSE)
      pFile->delete_on_close=true;
    // Decode CreateContexts into decoded_create_context structure
    if (Smb2CreateCmd.CreateContextsOffset())
       decode_create_context_request_values(InSmb2Header.FixedStructureAddress()+Smb2CreateCmd.CreateContextsOffset(), Smb2CreateCmd.CreateContextsLength());
    if (Smb2CreateCmd.NameLength()==0 && pShare->share_type != ST_DISKTREE)
    {  //  Fake an open for zero length filenames unless it's a
       // disktree which ends up opening the directory that is root of the share of a disk tree
      ;  //
    }
    if (pShare->share_type == ST_DISKTREE)
    {
       if (Smb2CreateCmd.CreateOptions() & 0x01)  // Create or open a directory
       {
         if (!found)
         { // Create it then stat it
           if ((SMB2FIO_Mkdir(&Smb2FioCtxt, TempFileName)&&SMB2FIO_Stat(&Smb2FioCtxt, TempFileName, pFile->pstat))==false)
             rstatus = SMB2_STATUS_UNSUCCESSFUL; // mkdir
         }
       }
       // Stat the filename Don't succeed if they are requesting a non-directory but the object is one
       else /* if (Smb2CreateCmd.CreateOptions() & 0x40) Create or open a FILE_NON_DIRECTORY_FILE */
       {
         if (!found)
         { // Create it then stat it
           fdhandle fd;
           if ( (SMB2FIO_Open(&Smb2FioCtxt, fd, TempFileName, flags, mode)&&SMB2FIO_Stat(&Smb2FioCtxt, TempFileName, pFile->pstat)) == false)
             rstatus = SMB2_STATUS_UNSUCCESSFUL; // mkdir

         }
        // open or create the file  r = OpenOrCreate (pStream->pSmbCtx, pTree, (word *) file_name, (word)flags, (word)mode, smb2flags, &externalFid, &fid);
        // if (statthefilefails)
        //   SMB2_STATUS_OBJECT_NAME_NOT_FOUND;
       }
    }
    else // IPC
    {
       // Set the stat struct to all zeros
    }

#if(0 && TEST_REPLAY_EVERY_TIME)
    if (pShare->share_type == ST_DISKTREE)
    {
        if (!replay)
        {
          if (SMBFIO_Stat (pStream->pSmbCtx, pStream->pSmbCtx->tid, (word *) file_name, &stat))
          {
            pStream->doSessionYield=TRUE;
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: Proc_smb2_Create:  yield while openings %s\n",rtsmb_ascii_of ((word *)file_name,0));
            return FALSE;
          }
        }
    }
#endif
#if (0)
    if (prtsmb_srv_ctx->enable_oplocks && pTree->type == ST_DISKTREE)
    {
      if (replay)  {  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "YIELD: Proc_smb2_Create:  replay openings %s\n",rtsmb_ascii_of ((word *)file_name,0));}

      if (SMBFIO_Stat (pStream->pSmbCtx, pStream->pSmbCtx->tid, (word *) file_name, &stat))
      {
        ddword unique_userid = smb2_stream_to_unique_userid(pStream);
       // Pass the socket down to the oplock test in case we need to yield and queue a break request
        oplock_c_create_return_e result;
        result = oplock_c_check_create_path(pNetctxt, pFile->unique_fileid, unique_userid, command.RequestedOplockLevel);
        if (result == oplock_c_create_yield)
        { // Send an asynchonrous interim response
          SendPendingCreate(pStream,pNetctxt, &command);
          pStream->doSessionYield=TRUE;
          return FALSE;
        }
      }
    }
//  Fake an open for zero length filenames unless it's a disktree which ends up opening the directory that is root of the share of a disk tree
    if (command.NameLength==0  && pTree->type != ST_DISKTREE)
    { // opening the root of the share
      flags = RTP_FILE_O_RDONLY;
      TURN_ON(command.FileAttributes, 0x80);
      // Hack, include extra info in stream if no file
      if (decoded_create_context.pMxAc)
        wants_extra_pMxAc_info = TRUE;
      if (decoded_create_context.pQFid)
        wants_extra_pQfid_info = TRUE;

      r = OpenOrCreate (pStream->pSmbCtx, pTree, (word *)file_name, (word)0/*flags*/, (word)0/*mode*/, smb2flags, &externalFid, &fid);

      tc_memset(&stat, 0, sizeof(stat));
      pFile->f_attributes = RTP_FILE_ATTRIB_ISDIR;
    }
    else
    {
      file_name[command.NameLength] = 0;
      file_name[command.NameLength+1] = 0;
      if (pTree->type == ST_DISKTREE)
      { /* If we have a normal disk filename. check if the client is trying to make a directory.  If so, make it Logic is the same for smb2  */
      /* We check if the client is trying to make a directory.  If so, make it   */
        if (/*ON (command.FileAttributes, 0x80) |*/ ON (command.CreateOptions, 0x1))
        {
            if (ON (flags, RTP_FILE_O_CREAT))
            {
                ASSERT_SMB2_PERMISSION (pStream, SECURITY_READWRITE);
                SMBFIO_Mkdir (pStream->pSmbCtx, pStream->pSmbCtx->tid, (word *)file_name);
                TURN_OFF (flags, RTP_FILE_O_EXCL);
                CreateAction = 2; // File created
            }
        }
        if (SMBFIO_Stat (pStream->pSmbCtx, pStream->pSmbCtx->tid, (word *)file_name, pFile->pstat))
        {
          if (!(pFile->pstat->f_attributes & RTP_FILE_ATTRIB_ISDIR) && ON (command.CreateOptions, 0x1))
          { // Don't succeed if they are requesting a directory but the object is not one
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  error: requesting a directory but the object is not one.\n%s\n", command.NameLength?rtsmb_ascii_of((word *)file_name,0):"NONAME");
            RtsmbWriteSrvStatus(pStream, SMB2_STATUS_ACCESS_DENIED);
            return TRUE;
          }
          if ((pFile->pstat->f_attributes & RTP_FILE_ATTRIB_ISDIR) && ON(command.CreateOptions, 0x40))
          { // Don't succeed if they are requesting a non-directory but the object is one
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  error: create request but file is a directory\n%s\n", command.NameLength?rtsmb_ascii_of((word *)file_name,0):"NONAME");
            RtsmbWriteSrvStatus(pStream, SMB2_STATUS_FILE_IS_A_DIRECTORY);
            return TRUE;
          }
        }
        if (ON(command.CreateOptions,FILE_DELETE_ON_CLOSE))
        {
           smb2flags = SMB2DELONCLOSE;
           //         SMBFIO_Rmdir(pStream->pSmbCtx, pStream->pSmbCtx->tid, file_name);
           //        SMBFIO_Delete (pStream->pSmbCtx, pStream->pSmbCtx->tid, file_name);
        }
      }
      r = OpenOrCreate (pStream->pSmbCtx, pTree, (word *) file_name, (word)flags, (word)mode, smb2flags, &externalFid, &fid);
      if (pTree->type == ST_DISKTREE)
      {
        // Stat the file
        if (!SMBFIO_Stat(pStream->pSmbCtx, pStream->pSmbCtx->tid, (word *) file_name, &stat))
        {
          RtsmbWriteSrvStatus(pStream, SMB2_STATUS_OBJECT_NAME_NOT_FOUND);
          return TRUE;
        }
      }
      else // IPC
      { // Call stat, it should work but if it doesn't just zero
        if (!SMBFIO_Stat(pStream->pSmbCtx, pStream->pSmbCtx->tid, (word *) file_name, &stat))
        {
          tc_memset(&stat, 0, sizeof(stat));
        }
        // stat.f_attributes = RTP_FILE_ATTRIB_ISDIR;
      }
    }

// ....    if (r != 0)




#endif
    }
//    }

    // Now reply
    NetNbssHeader            OutNbssHeader;
    NetSmb2Header            OutSmb2Header;
    NetSmb2CreateReply       Smb2CreateReply;
    byte *nbss_write_origin= (byte *) write_origin;
    nbss_write_origin-=4;
    memset(nbss_write_origin, 0,OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2CreateReply.FixedStructureSize());
    OutNbssHeader.bindpointers(nbss_write_origin);
    OutSmb2Header.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize());
    Smb2CreateReply.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize());

    OutSmb2Header.InitializeReply(InSmb2Header);
    Smb2CreateReply.StructureSize               = Smb2CreateReply.FixedStructureSize();


    OutSmb2Header.Status_ChannelSequenceReserved = rstatus; // SMB2_NT_STATUS_SUCCESS;

    byte *CreateContextsContent;
    dword CreateContextsLength=0;

    byte oplock_level;
    bool oplocks_enabled = false;
    if (oplocks_enabled)
      oplock_level = Smb2CreateCmd.RequestedOplockLevel();      // if oplocks are enabled
    else
      oplock_level = 0;                                         // override with zero
    if (rstatus == SMB2_NT_STATUS_SUCCESS)
    {
      pFile->session_number             = SessionIndex();         // Offset in the session table
      pFile->share_number               = pShare->share_handle;   // Offset in the share table
      if ((Smb2CreateCmd.CreateOptions() & 0x01))
        pFile->is_a_directory=true;
      else
        pFile->is_a_directory=false;
      pFileInstance->int_file_id  = pFile->file_number;        // index in the server file table
      pFile->external_fileid[0] = pFile->file_number&0xff;
      pFile->external_fileid[1] = ((pFile->file_number)>>8)&0xff;
      pFile->external_fileid[2] = pFile->share_number;
      pFile->external_fileid[3] = pFile->session_number;


      Smb2CreateReply.OplockLevel                  = oplock_level;
      Smb2CreateReply.Flags                        = 0;             // 3.0 only
      Smb2CreateReply.CreateAction                 = CreateAction;

      Smb2CreateReply.CreationTime                 = pFile->pstat->f_ctime64;
      Smb2CreateReply.LastAccessTime               = pFile->pstat->f_atime64;
      Smb2CreateReply.LastWriteTime                = pFile->pstat->f_wtime64;
      Smb2CreateReply.ChangeTime                   = pFile->pstat->f_htime64;
      Smb2CreateReply.AllocationSize               = pFile->pstat->fsize64;
      Smb2CreateReply.EndofFile                    = pFile->pstat->fsize64;
      Smb2CreateReply.FileAttributes               = rtsmb_util_rtsmb_to_smb_attributes(pFile->pstat->fattributes);
      Smb2CreateReply.FileId                       = pFile->external_fileid; // pFile->pstat->unique_fileid;
      if (CreateContextsLength)
      {
        Smb2CreateReply.CreateContextsOffset         = OutSmb2Header.FixedStructureSize()+Smb2CreateReply.PackedStructureSize();
        Smb2CreateReply.CreateContextsLength         = CreateContextsLength;
        memcpy(OutSmb2Header.FixedStructureAddress()+Smb2CreateReply.PackedStructureSize(), CreateContextsContent,CreateContextsLength);
      }
    }
    else
    {
      if (pFileInstance) release_session_file(pFileInstance);
      if (pFile) release_server_file_struct(pFile);
    }
    OutNbssHeader.nbss_packet_size =
      OutSmb2Header.FixedStructureSize()+
      Smb2CreateReply.PackedStructureSize() + (CreateContextsLength?CreateContextsLength:1);


    return OutNbssHeader.nbss_packet_size()+4;
}
