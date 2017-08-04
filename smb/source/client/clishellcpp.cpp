//
// clishellcpp.cpp -
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
#include "smb2utils.hpp"
#include <smb2wireobjects.hpp>
#include <mswireobjects.hpp>

static TIME FILETIMETOTIME(ddword T)
{
  return *((TIME *)&T);
}

extern "C" {
  void DisplayDirscan(PRTSMB_CLI_SESSION_DSTAT pstat);
}

// Format the dstat in C++ with alignment independent classes and call back to the shell to display
extern "C" int FormatDirscanToDstat(void *pBuffer)
{
  ms_FILE_ID_BOTH_DIR_INFORMATION  BothDirInfoIterator;

  BothDirInfoIterator.bindpointers((byte *)pBuffer);

  RTSMB_CLI_SESSION_DSTAT mystat;
  PRTSMB_CLI_SESSION_DSTAT pstat = &mystat;
  tc_memcpy (pstat->filename,
    BothDirInfoIterator.FixedStructureAddress()+BothDirInfoIterator.FixedStructureSize()-1,
    BothDirInfoIterator.FileNameLength.get());
//  tc_memcpy (pstat->filename,BothDirInfoIterator->FileName,BothDirInfoIterator->directory_information_base.FileNameLength);
//   * ((char *) (&pstat->filename)+BothDirInfoIterator->directory_information_base.FileNameLength) = 0;
//   * ((char *) (&pstat->filename)+BothDirInfoIterator->directory_information_base.FileNameLength+1) = 0;
   pstat->unicode = 1;           //    char unicode;   /* will be zero if filename is ascii, non-zero if unicode */
   pstat->fattributes = (unsigned short) BothDirInfoIterator.FileAttributes.get();    //    unsigned short fattributes;
   pstat->fatime64=FILETIMETOTIME(BothDirInfoIterator.LastAccessTime.get());              //    TIME           fatime64; /* last access time */
   pstat->fatime64= FILETIMETOTIME(BothDirInfoIterator.LastAccessTime.get());              //    TIME           fatime64; /* last access time */
   pstat->fwtime64=FILETIMETOTIME(BothDirInfoIterator.LastWriteTime.get());              //    TIME           fwtime64; /* last write time */
   pstat->fctime64=FILETIMETOTIME(BothDirInfoIterator.CreationTime.get());              //    TIME           fctime64; /* last create time */
   pstat->fhtime64=FILETIMETOTIME(BothDirInfoIterator.ChangeTime.get());              //    TIME           fhtime64; /* last change time */
   pstat->fsize = (dword) BothDirInfoIterator.EndofFile.get();                 //    unsigned long fsize;
   pstat->fsizehi; (dword) (BothDirInfoIterator.EndofFile.get()>>32);                 //    unsigned long fsize;
//   pstat->sid =  pSearch->sid;
                  //    int sid;
   DisplayDirscan(pstat);
   return BothDirInfoIterator.NextEntryOffset.get();
}

