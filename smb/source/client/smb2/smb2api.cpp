/*
|  SMB2API.C - WebC sockets porting layer
|
|  EBS -
|
|
|  Copyright EBS Inc. , 2017
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/

/*****************************************************************************/
/* Header files
 *****************************************************************************/

#include "smb2clientincludes.hpp"
#include "smb2api.hpp"

bool smb2_file_open (dword &smbclientFile, const char *filename, bool iswrite, int sharenumber)
{
  dword fileid;
  if (getCurrentActiveSession()->allocate_fileid(fileid, sharenumber))
  {
    getCurrentActiveSession()->open_file(getCurrentActiveSession()->fileid_to_sharenumber(fileid), getCurrentActiveSession()->fileid_to_filenumber(fileid), filename, iswrite);
    smbclientFile = fileid;
    return true;
  }
  return false;
};
bool smb2_file_close(dword fileid)
{
  getCurrentActiveSession()->close_dirent(getCurrentActiveSession()->fileid_to_sharenumber(fileid),getCurrentActiveSession()->fileid_to_filenumber(fileid));
  return true;
};
int smb2_file_read(dword fileid, byte *buffer, int n_bytes)
{
  return  getCurrentActiveSession()->read_from_file(getCurrentActiveSession()->fileid_to_sharenumber(fileid),getCurrentActiveSession()->fileid_to_filenumber(fileid), buffer, n_bytes);
}

int smb2_file_write(dword fileid, byte *buffer, int n_bytes)
{
  return  getCurrentActiveSession()->write_to_file(getCurrentActiveSession()->fileid_to_sharenumber(fileid),getCurrentActiveSession()->fileid_to_filenumber(fileid), buffer, n_bytes);
}
