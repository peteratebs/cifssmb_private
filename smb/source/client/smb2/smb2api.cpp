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

extern bool do_smb2_write_to_file(Smb2Session *Session,int sharenumber, int filenumber, byte *buffer, int count, bool flush);
extern bool do_smb2_read_from_file(Smb2Session *Session,int sharenumber, int filenumber, byte *buffer, ddword offset, int count);

bool smb2_file_open (dword &smbclientFile, const char *filename, bool iswrite, int sharenumber)
{
  dword fileid;
  Smb2Session *pSession=getCurrentActiveSession();
  if (pSession->allocate_fileid(fileid, sharenumber))
  {
    pSession->open_file(pSession->fileid_to_sharenumber(fileid), pSession->fileid_to_filenumber(fileid), filename, iswrite);
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

//int smb2_file_read(dword fileid, byte *buffer, int n_bytes)
//{
//  return do_smb2_read_from_file(getCurrentActiveSession(),getCurrentActiveSession()->fileid_to_sharenumber(fileid),getCurrentActiveSession()->fileid_to_filenumber(fileid), buffer, n_bytes);
//}

int smb2_file_write(dword fileid, byte *buffer, int n_bytes)
{
  return do_smb2_write_to_file(getCurrentActiveSession(),getCurrentActiveSession()->fileid_to_sharenumber(fileid),getCurrentActiveSession()->fileid_to_filenumber(fileid), buffer, n_bytes, true);
}
