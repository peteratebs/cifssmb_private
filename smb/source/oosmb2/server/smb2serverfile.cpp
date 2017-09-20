//
// smbservershare.pp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2017
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//

#include "smb2serverincludes.hpp"
#include "smb2serverfile.hpp"


static Smb2ServerFileStruct filetable[RTSMB_CFG_MAX_FILES];


extern void initialize_filetable()
{
  memset(filetable,0,sizeof(filetable));
}

extern  Smb2ServerFileStruct *map_fileid_to_serverfile(byte *external_fileid)
{
  for (int i=0; i < RTSMB_CFG_MAX_FILES; i++)
  {
    if (filetable[i].reference_count)
    {
      if (memcmp(filetable[i].external_fileid,external_fileid, 16)==0)
        return &filetable[i];
    }
  }
  return 0;
}

extern  Smb2ServerFileStruct *allocate_server_file_struct()
{
  for (int i=0; i < RTSMB_CFG_MAX_FILES; i++)
  if (filetable[i].reference_count==0)
  {
    struct smb2fstat *pstat = (struct smb2fstat *)smb_rtp_malloc(sizeof(struct smb2fstat));
    if (pstat)
    {
      memset(&filetable[i],0,sizeof(filetable[0]));
      filetable[i].reference_count = 1;
      filetable[i].pstat           = pstat;
      filetable[i].file_number     = i;
      return &filetable[i];
    }
  }
  return 0;
}
extern void release_server_file_struct(Smb2ServerFileStruct *pFile, bool ignore_refcount)
{
  if (ignore_refcount || pFile->reference_count <= 1)
  {
     if (pFile->pstat) smb_rtp_free(pFile->pstat);
      memset(pFile,0,sizeof(*pFile));
  }
  else
   pFile->reference_count -= 1;
}
