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

// Clean up what we can after completing a command
extern "C" void cpp_cleanup_after_command()
{
  int job; int session=0;
  for (job = 0; job < prtsmb_cli_ctx->max_jobs_per_session; job++)  prtsmb_cli_ctx->sessions[session].jobs[job].state = CSSN_JOB_STATE_UNUSED;
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
    BothDirInfoIterator.FileNameLength());
//  tc_memcpy (pstat->filename,BothDirInfoIterator->FileName,BothDirInfoIterator->directory_information_base.FileNameLength);
//   * ((char *) (&pstat->filename)+BothDirInfoIterator->directory_information_base.FileNameLength) = 0;
//   * ((char *) (&pstat->filename)+BothDirInfoIterator->directory_information_base.FileNameLength+1) = 0;
   pstat->unicode = 1;           //    char unicode;   /* will be zero if filename is ascii, non-zero if unicode */
   pstat->fattributes = (unsigned short) BothDirInfoIterator.FileAttributes();    //    unsigned short fattributes;
   pstat->fatime64=FILETIMETOTIME(BothDirInfoIterator.LastAccessTime());              //    TIME           fatime64; /* last access time */
   pstat->fatime64= FILETIMETOTIME(BothDirInfoIterator.LastAccessTime());              //    TIME           fatime64; /* last access time */
   pstat->fwtime64=FILETIMETOTIME(BothDirInfoIterator.LastWriteTime());              //    TIME           fwtime64; /* last write time */
   pstat->fctime64=FILETIMETOTIME(BothDirInfoIterator.CreationTime());              //    TIME           fctime64; /* last create time */
   pstat->fhtime64=FILETIMETOTIME(BothDirInfoIterator.ChangeTime());              //    TIME           fhtime64; /* last change time */
   pstat->fsize = (dword) BothDirInfoIterator.EndofFile();                 //    unsigned long fsize;
   pstat->fsizehi; (dword) (BothDirInfoIterator.EndofFile()>>32);                 //    unsigned long fsize;
//   pstat->sid =  pSearch->sid;
                  //    int sid;
   DisplayDirscan(pstat);
   return BothDirInfoIterator.NextEntryOffset();
}
