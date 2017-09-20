//
// smbserverfile.hpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2017
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
//

#ifndef include_smbserverfile
#define include_smbserverfile

//File
//  fd     - session<<24|share<<16|fileindex
//  Type   - directory or file
//  filepointer
//  path   - canonical path
//  stat     permissions etc



typedef struct Smb2ServerFileStruct_s {
  int   file_number;          // Offset in the file table
  int   session_number;       // Offset in the session table
  int   share_number;         // Offset in the share table
  int   reference_count;      //
  byte  external_fileid[16];
  bool  delete_on_close;
  bool  is_a_directory;      // Also buried in dstat but this is convenient
  fdhandle fd;                // The file handle if this is a file
  struct smb2fstat   *pstat;  // Allocated upon opening of the file freed upon close
} Smb2ServerFileStruct;


extern       void initialize_filetable();
extern       int  allocate_server_file();
extern       void release_server_file(int id);
extern       Smb2ServerFileStruct *fidto_server_file(int fid);
extern       Smb2ServerFileStruct *allocate_server_file_struct();
extern       void release_server_file_struct(Smb2ServerFileStruct *pFile,bool ignore_refcount=false);
extern       Smb2ServerFileStruct *map_fileid_to_serverfile(byte *external_fileid);

#endif // include_smbserverfile
