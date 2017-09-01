//
// smb2file.cpp -
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

// Classes and methods for negotiate and setup commands.
//
// public functions
// do_smb2_logon_server_worker()
//  get_negotiateobject()
//  get_setupobject()
//  get_setupphase_2object()


#include "smb2clientincludes.hpp"


#define SMB2_OPLOCK_LEVEL_NONE 0x00
#define SMB2_OPLOCK_LEVEL_II 0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH 0x09
#define SMB2_OPLOCK_LEVEL_LEASE 0xFF

#define SMB2_ImpersonationLevel_Anonymous           0x00000000
#define SMB2_ImpersonationLevel_Identification      0x00000001
#define SMB2_ImpersonationLevel_Impersonation       0x00000002
#define SMB2_ImpersonationLevel_Delegate            0x00000003

/* RTSMB2_CREATE_C::ShareAccess */
#define SMB2_FILE_SHARE_READ                        0x00000001
#define SMB2_FILE_SHARE_WRITE                       0x00000002
#define SMB2_FILE_SHARE_DELETE                      0x00000004

/* RTSMB2_CREATE_C::CreateDisposition */
#define SMB2_FILE_SUPERSEDE                         0x00000000
#define SMB2_FILE_OPEN                              0x00000001
#define SMB2_FILE_CREATE                            0x00000002
#define SMB2_FILE_OPEN_IF                           0x00000003
#define SMB2_FILE_OVERWRITE                         0x00000004
#define SMB2_FILE_OVERWRITE_IF                      0x00000005



#define SMB2_FPP_ACCESS_MASK_FILE_READ_DATA         0x00000001   /* ** This value indicates the right to read data from the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA        0x00000002   /* ** This value indicates the right to write data into the file or named pipe beyond the end of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA       0x00000004   /* ** This value indicates the right to append data into the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_EA           0x00000008   /* ** This value indicates the right to read the extended attributes of the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_EA          0x00000010   /* ** This value indicates the right to write or change the extended attributes to the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_DELETE_CHILD      0x00000040   /* ** This value indicates the right to delete entries within a directory. */
#define SMB2_FPP_ACCESS_MASK_FILE_EXECUTE           0x00000020   /* ** This value indicates the right to execute the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_ATTRIBUTES   0x00000080   /* ** This value indicates the right to read the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_ATTRIBUTES  0x00000100   /* ** This value indicates the right to change the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_DELETE                 0x00010000   /* ** This value indicates the right to delete the file. */
#define SMB2_FPP_ACCESS_MASK_READ_CONTROL           0x00020000   /* ** This value indicates the right to read the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_WRITE_DAC              0x00040000   /* ** This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP]. */
#define SMB2_FPP_ACCESS_MASK_WRITE_OWNER            0x00080000   /* ** This value indicates the right to change the owner in the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_SYNCHRONIZE            0x00100000   /* ** SMB2 clients set this flag to any value. SMB2 servers SHOULD ignore this flag. */
#define SMB2_FPP_ACCESS_MASK_ACCESS_SYSTEM_SECURITY 0x01000000   /* ** This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42> */
#define SMB2_FPP_ACCESS_MASK_MAXIMUM_ALLOWED        0x02000000   /* ** This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_ALL            0x10000000   /* ** This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_EXECUTE        0x20000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_WRITE          0x40000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_READ           0x80000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL. */



/* RTSMB2_CREATE_C::CreateOptions */
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000
#define FILE_OPEN_REMOTE_INSTANCE 0x00000400
#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000
#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000


// Can't embedd this in smb2session.hpp

static const word wildcard_type[]        = {'?', '?', '?', '?', '?', '\0'};

class SmbFileCreateWorker: private smb_diagnostics {
public:
  byte file_id[16];
  SmbFileCreateWorker(Smb2Session &_pSmb2Session)
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
    pSmb2Session = &_pSmb2Session;
    isadiropen =
    isreadonly =
    iscreate   =
    isexclusive = false;
  }
  void set_permissions(bool _create, bool _write) {
     iscreate = _create;
     isreadonly  = !_write;
  }
  void set_parameters(int _sharenumber, int _filenumber, char *filename, bool isdir)
  {
    share_number = _sharenumber;
    filenumber   = _filenumber;
    pSmb2Session->Files[_filenumber].set_filename(filename);
    isadiropen = isdir;
    isreadonly = true;
  }
  bool go()
  {
    return rtsmb_cli_session_create_file();
  }

private:
  Smb2Session *pSmb2Session;
  int share_number;
  int filenumber;
  bool isadiropen;
  bool isreadonly;
  bool iscreate;
  bool isexclusive;

  int rtsmb_cli_session_create_file()
  {
    if (pSmb2Session->session_state() <=  CSSN_STATE_DEAD)
    {
      pSmb2Session->diag_text_warning("create_file command called but session is dead");
      return false;
    }
    if (pSmb2Session->Shares[share_number].share_state != CSSN_SHARE_STATE_CONNECTED)
    {
      pSmb2Session->diag_text_warning("create_file command called share to closed share");
      return false;
    }

     bool r = rtsmb2_cli_session_send_createfile();
     if (r)
       r = rtsmb2_cli_session_receive_createfile();
      return r;
  }

  bool rtsmb2_cli_session_send_createfile ()
  {
    int send_status;
    byte *path=0;

    setSessionSigned(false);      // Should enable signing here and everythng should work, but signing is broken

    (char *)pSmb2Session->Files[filenumber].get_filename_ascii();
    dword variable_content_size = strlen((char *)pSmb2Session->Files[filenumber].get_filename_ascii())*sizeof(word);
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2CreateCmd Smb2CreateCmd;

    NetSmb2NBSSCmd<NetSmb2CreateCmd> Smb2NBSSCmd(SMB2_CREATE, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2CreateCmd, variable_content_size);

    OutSmb2Header.TreeId = pSmb2Session->Shares[share_number].tid;



   Smb2CreateCmd.StructureSize = Smb2CreateCmd.FixedStructureSize();
   Smb2CreateCmd.SecurityFlags         = 0;
   Smb2CreateCmd.RequestedOplockLevel  = 0;
   Smb2CreateCmd.ImpersonationLevel    = SMB2_ImpersonationLevel_Impersonation;
   Smb2CreateCmd.SmbCreateFlags        = 0;        // must be zero

   dword access = SMB2_FPP_ACCESS_MASK_FILE_READ_DATA|SMB2_FPP_ACCESS_MASK_FILE_READ_ATTRIBUTES;
   if (!isreadonly)
     access |= (SMB2_FPP_ACCESS_MASK_DELETE|SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA|SMB2_FPP_ACCESS_MASK_FILE_WRITE_ATTRIBUTES);
   Smb2CreateCmd.DesiredAccess         = access;
   if (isadiropen)
     Smb2CreateCmd.FileAttributes        = 0x10;
   Smb2CreateCmd.ShareAccess             = 0x7; // fixed per spec at RDWREXE;
#define SMB2_FILE_OPEN                              0x00000001
#define SMB2_FILE_CREATE                            0x00000002
#define SMB2_FILE_OPEN_IF                           0x00000003
#define SMB2_FILE_OVERWRITE                         0x00000004
#define SMB2_FILE_OVERWRITE_IF                      0x00000005

   dword disposition = 0;
   if (iscreate)
     disposition = SMB2_FILE_CREATE;
   else
     disposition = SMB2_FILE_OPEN;
//    if (isexclusive)
//     displosition = SMB2_FILE_OPEN_IF;  // ??

   Smb2CreateCmd.CreateDisposition     = disposition;
   if (isadiropen)
     Smb2CreateCmd.CreateOptions         = 1;
   Smb2CreateCmd.NameOffset            = 0x78;
   Smb2CreateCmd.NameLength            = variable_content_size; // strlen(filename);
   Smb2CreateCmd.CreateContextsOffset  = 0;
   Smb2CreateCmd.CreateContextsLength  = 0;
/// Smb2CreateCmd.Buffer;

    if (Smb2CreateCmd.NameLength())
      Smb2CreateCmd.copyto_variable_content((word *)pSmb2Session->Files[filenumber].get_filename_utf16(), variable_content_size);  // we have to do this
    return Smb2NBSSCmd.flush();
  }
  bool rtsmb2_cli_session_receive_createfile ()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2CreateReply  Smb2CreateReply;
    bool rv = false;

     // Pull enough for the fixed part and then map pointers to input buffer
//    NetStatus r = pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2CreateReply.PackedStructureSize(), bytes_pulled);
    NetStatus r = pSmb2Session->ReplyBuffer.pull_nbss_frame_checked("CREATE", Smb2CreateReply.PackedStructureSize(), bytes_pulled);

    if (r == NetStatusOk)
    {
      NetSmb2NBSSReply<NetSmb2CreateReply> Smb2NBSSReply(SMB2_CREATE, pSmb2Session, InNbssHeader,InSmb2Header, Smb2CreateReply);
      Smb2CreateReply.FileId.get(file_id);
      rv = true;
    }
    else
      pSmb2Session->diag_text_warning("receive_create command failed pulling from the socket");
    return rv;
  }
};
static bool do_smb2_dirent_open_worker(Smb2Session &Session,int sharenumber,int filenumber,char *name, bool isdir ,bool writeable, bool creatable)
{
  SmbFileCreateWorker FileCreateWorker(Session);
  FileCreateWorker.set_parameters(sharenumber, filenumber, name, isdir);
  FileCreateWorker.set_permissions(creatable, writeable);
  bool r = FileCreateWorker.go();
  if (r)
  {
    Session.Files[filenumber].set_fileid(FileCreateWorker.file_id);
    diag_dump_bin_fn(DIAG_DEBUG,"do_smb2_dirent_open_worker returned filedid: ", FileCreateWorker.file_id, 16);
  }
  return r;
}

extern bool do_smb2_file_open_worker(Smb2Session &Session,int sharenumber,int filenumber,char *filename, bool writeable)
{
  return do_smb2_dirent_open_worker(Session,sharenumber, filenumber, filename, false, writeable, writeable);
}

extern bool do_smb2_directory_open_worker(Smb2Session &Session,int sharenumber,int filenumber,char *dirname, bool writeable)
{
  return do_smb2_dirent_open_worker(Session,sharenumber, filenumber, dirname, true, writeable, false);
}
extern bool do_smb2_directory_create_worker(Smb2Session &Session,int sharenumber,int filenumber,char *dirname)
{
  return do_smb2_dirent_open_worker(Session,sharenumber, filenumber, dirname, true, true, true);
}


class SmbFileCloseWorker: private smb_diagnostics {
public:
  byte file_id[16];
  SmbFileCloseWorker(Smb2Session &_pSmb2Session, int _sharenumber, int _filenumber)
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
    pSmb2Session = &_pSmb2Session;
    ispostquery = false;
    share_number = _sharenumber;
    filenumber  = _filenumber;
  }
  void set_postquery() { ispostquery = true;  }
  bool go()
  {
    set_postquery();
    return rtsmb_cli_session_close_file();
  }

private:
  Smb2Session *pSmb2Session;
  int share_number;
  int filenumber;
  bool ispostquery;

  int rtsmb_cli_session_close_file()
  {
    if (pSmb2Session->session_state() <=  CSSN_STATE_DEAD)
    {
      pSmb2Session->diag_text_warning("close_file command called but session is dead");
      return false;
    }
    if (pSmb2Session->Shares[share_number].share_state != CSSN_SHARE_STATE_CONNECTED)
    {
      pSmb2Session->diag_text_warning("close_file command called share to closed share");
      return false;
    }

     bool r = rtsmb2_cli_session_send_closefile();
     if (r)
       r = rtsmb2_cli_session_receive_closefile();
      return r;
  }

  bool rtsmb2_cli_session_send_closefile ()
  {
    int send_status;
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2CloseCmd Smb2CloseCmd;

    NetSmb2NBSSCmd<NetSmb2CloseCmd> Smb2NBSSCmd(SMB2_CLOSE, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2CloseCmd, 0);


    OutSmb2Header.TreeId = pSmb2Session->Shares[share_number].tid;

    Smb2CloseCmd.StructureSize = Smb2CloseCmd.FixedStructureSize();
    if (ispostquery)
      Smb2CloseCmd.Flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;

    Smb2CloseCmd.FileId = pSmb2Session->Files[filenumber].get_file_id();
    return Smb2NBSSCmd.flush();
  }
  bool rtsmb2_cli_session_receive_closefile ()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2CloseReply  Smb2CloseReply;

#if(0)
    NetSmb2MinimumReply  Smb2MinimumReply;
    NetSmb2CloseReply &T = Smb2CloseReply;
    dword min_packet_bytes_pulled,more_bytes_pulled;
    size_t min_reply_size = InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2MinimumReply.PackedStructureSize();
    size_t good_reply_size = InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+T.PackedStructureSize();
    byte *pBase = pSmb2Session->ReplyBuffer.input_buffer_pointer();
     // Pull enough for the fixed part and then map pointers to input buffer
    NetStatus r = pSmb2Session->ReplyBuffer.pull_new_nbss_frame(min_reply_size, min_packet_bytes_pulled);
    if (r != NetStatusOk || min_packet_bytes_pulled != min_reply_size)
    {
      pSmb2Session->diag_text_warning("receive_close command failed pulling SMB2 header from the socket");
      return false;
    }
    // look at the headers for status
    InNbssHeader.bindpointers(pBase);
    InSmb2Header.bindpointers(pBase+InNbssHeader.FixedStructureSize());
    Smb2MinimumReply.bindpointers(pBase+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
    more_bytes_pulled = 0;


    if (InSmb2Header.Status_ChannelSequenceReserved() != SMB2_NT_STATUS_SUCCESS)
    {
      pSmb2Session->diag_text_warning("receive_close command failed pulling SMB2 header from the socket");
      r = NetStatusServerErrorStatus;
    }
    else
    {
      if (min_packet_bytes_pulled < good_reply_size)
      {
         r = pSmb2Session->ReplyBuffer.pull_nbss_data(good_reply_size-min_packet_bytes_pulled, more_bytes_pulled);
         if (r != NetStatusOk || more_bytes_pulled != good_reply_size-min_packet_bytes_pulled)
         {
           pSmb2Session->diag_text_warning("receive_close command failed pulling CMD header from the socket");
           r = NetStatusDeviceRecvBadLength;
         }
       }
       else
          r = NetStatusServerErrorStatus;
    }
    bytes_pulled = more_bytes_pulled + min_packet_bytes_pulled;
    if (bytes_pulled != good_reply_size)
    {
        pSmb2Session->diag_text_warning("receive_close not expected  command bytes_pulled != good_reply_size");
    }
#else
    NetStatus r = pSmb2Session->ReplyBuffer.pull_nbss_frame_checked("CLOSE", Smb2CloseReply.PackedStructureSize(), bytes_pulled);
#endif

    if (r == NetStatusOk)
    {
      NetSmb2NBSSReply<NetSmb2CloseReply> Smb2NBSSReply(SMB2_CLOSE, pSmb2Session, InNbssHeader,InSmb2Header, Smb2CloseReply);
    }
    return true;
  }
}
;
extern bool do_smb2_dirent_close_worker(Smb2Session &Session,int sharenumber,int filenumber)
{
  SmbFileCloseWorker FileCloseWorker(Session, sharenumber, filenumber);
  bool r = FileCloseWorker.go();
  if (r)
  {
    Session.Files[filenumber].set_file_free();
  }
  return r;
}



// GET/SET INFO
#define SMB2_0_INFO_FILE       0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY   0x03
#define SMB2_0_INFO_QUOTA      0x04


#define SMB2_0_FileRenameInformation       0x0a
#define SMB2_0_FileBasicInformation        0x04
#define SMB2_0_FileSetDisposition          0x0d
#define SMB2_0_FileEndofFile               0x14

class SmbFileSetinfoWorker: private smb_diagnostics {
public:
  byte file_id[16];
  SmbFileSetinfoWorker(Smb2Session &_pSmb2Session, int _share_number, int _filenumber, bool _isdelete=false)
  {
    set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
    pSmb2Session = &_pSmb2Session;
    share_number = _share_number;
    filenumber   = _filenumber;
    isdelete = _isdelete;
    isrename = false;
  }
  void set_new_name(char *_newname)
  {
    isrename = true;
    newname = _newname;
  }
  bool go()
  {
    return rtsmb_cli_session_setinfo();
  }

private:
  Smb2Session *pSmb2Session;
  int share_number;
  int filenumber;
  bool isdelete;
  bool isrename;
  char *newname;

  int rtsmb_cli_session_setinfo()
  {
    if (pSmb2Session->session_state() <=  CSSN_STATE_DEAD)
    {
      pSmb2Session->diag_text_warning("setinfo command called but session is dead");
      return false;
    }
    if (pSmb2Session->Shares[share_number].share_state != CSSN_SHARE_STATE_CONNECTED)
    {
      pSmb2Session->diag_text_warning("setinfo command called share to closed share");
      return false;
    }

     bool r = rtsmb2_cli_session_send_setinfo();
     if (r)
       r = rtsmb2_cli_session_receive_setinfo();
      return r;
  }

  bool rtsmb2_cli_session_send_setinfo ()
  {
    dword variable_content_size=0;
    NetNbssHeader       OutNbssHeader;
    NetSmb2Header       OutSmb2Header;
    NetSmb2SetinfoCmd   Smb2SetinfoCmd;
    NetSmb2RenameInfoType2 Smb2RenameInfoType2;
    dualstringdecl(converted_string);                   //    dualstring name_string;
    if (isdelete)
      variable_content_size=1;
    else if (isrename)
    {
      *converted_string     =  newname;
      variable_content_size= Smb2RenameInfoType2.PackedStructureSize()+ converted_string->utf16_length();
    }
    NetSmb2NBSSCmd<NetSmb2SetinfoCmd> Smb2NBSSCmd(SMB2_SET_INFO, pSmb2Session,OutNbssHeader,OutSmb2Header, Smb2SetinfoCmd, variable_content_size);

    OutSmb2Header.TreeId = pSmb2Session->Shares[share_number].tid;
    Smb2SetinfoCmd.StructureSize = Smb2SetinfoCmd.FixedStructureSize();

    Smb2SetinfoCmd.InfoType      = SMB2_0_INFO_FILE;
    Smb2SetinfoCmd.BufferOffset = OutSmb2Header.FixedStructureSize()+Smb2SetinfoCmd.PackedStructureSize();
    if (isdelete)
    {
      Smb2SetinfoCmd.BufferLength = 1;
      Smb2SetinfoCmd.Buffer = 1;       // Single byte set the buffer
    }

//    Smb2SetinfoCmd.AdditionalInformation = ;

    diag_dump_bin_fn(DIAG_DEBUG,"Smb2SetinfoCmd send filedid: ", pSmb2Session->Files[filenumber].get_file_id(), 16);
    Smb2SetinfoCmd.FileId = pSmb2Session->Files[filenumber].get_file_id();
//    Smb2SetinfoCmd.Buffer = ;
    if (isdelete)
    {
      byte one[1]; one[0]=1;
      Smb2SetinfoCmd.copyto_variable_content(one, 1);  // we have to do this
      Smb2SetinfoCmd.FileInfoClass = SMB2_0_FileSetDisposition;
    }
    else if (isrename)
    { // Map a renameinfo object onto the buffer
      // Zero the buffer otherwise fileds aren't initialized to zero
      memset(Smb2SetinfoCmd.VariableContentAddress(), 0, Smb2RenameInfoType2.PackedStructureSize()+converted_string->utf16_length());
      Smb2RenameInfoType2.bindpointers(Smb2SetinfoCmd.VariableContentAddress());
      Smb2RenameInfoType2.ReplaceIfExists = 0;
      Smb2RenameInfoType2.RootDirectory   = 0;

      Smb2RenameInfoType2.FileNameLength = converted_string->utf16_length();
      // Copy file new filename to the end
      Smb2SetinfoCmd.BufferLength = Smb2RenameInfoType2.PackedStructureSize()+converted_string->utf16_length();
      memcpy(Smb2RenameInfoType2.VariableContentAddress(),converted_string->utf16(),converted_string->utf16_length());
      // Add in the new content to the buffer
      Smb2SetinfoCmd.addto_variable_content(Smb2RenameInfoType2.PackedStructureSize()+converted_string->utf16_length());
      Smb2SetinfoCmd.FileInfoClass = SMB2_0_FileRenameInformation;
    }


    return Smb2NBSSCmd.flush();
  }
  bool rtsmb2_cli_session_receive_setinfo ()
  {
    dword in_variable_content_size = 0;
    dword bytes_pulled = 0;
    NetNbssHeader       InNbssHeader;
    NetSmb2Header       InSmb2Header;
    NetSmb2SetinfoReply Smb2SetinfoReply;
//    NetStatus r = pSmb2Session->ReplyBuffer.pull_new_nbss_frame(InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2SetinfoReply.PackedStructureSize(), bytes_pulled);
    NetStatus r = pSmb2Session->ReplyBuffer.pull_nbss_frame_checked("SETINFO", Smb2SetinfoReply.PackedStructureSize(), bytes_pulled);

    if (r != NetStatusOk)
    {
      pSmb2Session->diag_text_warning("receive_setinfo command failed pulling from the socket");
      return false;
    }
    NetSmb2NBSSReply<NetSmb2SetinfoReply> Smb2NBSSReply(SMB2_SET_INFO, pSmb2Session, InNbssHeader,InSmb2Header, Smb2SetinfoReply);

    return true;
  }
};

static bool do_smb2_dirent_setinfo_deleted_worker(Smb2Session &Session,int sharenumber,int filenumber)
{
  SmbFileSetinfoWorker FileSetinfoWorker(Session, sharenumber, filenumber, true);
  return FileSetinfoWorker.go();
}


bool do_smb2_dirent_delete_worker(Smb2Session &Session,int sharenumber,char *name, bool isdir)
{
  bool r;
  int filenumber = 0;
  r = do_smb2_dirent_open_worker(Session, sharenumber, filenumber,name, isdir, true, false);
  if (r)
  {
    r = do_smb2_dirent_setinfo_deleted_worker(Session, sharenumber, filenumber);
    if (r)
    {
       r = do_smb2_dirent_close_worker(Session,sharenumber,filenumber);
    }
    Session.Files[filenumber].set_file_free();
  }
  return r;
}

static bool do_smb2_dirent_setinfo_rename_worker(Smb2Session &Session,int sharenumber,int filenumber, bool isdir, char *newname)
{
  SmbFileSetinfoWorker FileSetinfoWorker(Session, sharenumber, filenumber, false);
  FileSetinfoWorker.set_new_name(newname);
  return FileSetinfoWorker.go();
}

bool do_smb2_dirent_rename_worker(Smb2Session &Session,int sharenumber, char *oldname, char *newname, bool isdir)
{
  bool r;
  int filenumber = 0;

  r = do_smb2_dirent_open_worker(Session, sharenumber, filenumber,oldname, isdir, true, false);
  if (r)
  {
    r = do_smb2_dirent_setinfo_rename_worker(Session, sharenumber, filenumber, isdir, newname);
    if (r)
    {
      r = do_smb2_dirent_close_worker(Session,sharenumber,filenumber);
    }
    Session.Files[filenumber].set_file_free();
  }
  return r;
}
