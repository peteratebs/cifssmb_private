//
// smb2api.hpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
//

#ifndef include_smb2api
#define include_smb2api

bool smb2_file_open (dword &smbclientFile, const char *filename, bool iswrite, int sharenumber=0);
bool smb2_file_close(dword smbclientFile);
int smb2_file_read(dword smbclientFile, byte *buffer, int n_bytes);
int smb2_file_write(dword smbclientFile, byte *buffer, int n_bytes);


#endif // include_smb2defs
