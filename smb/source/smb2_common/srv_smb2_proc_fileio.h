//
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles most of the actual processing of packets for the RTSMB server.
//


#ifndef _SRV_SMB2_PROC_FILEIO_
#define _SRV_SMB2_PROC_FILEIO_

typedef struct s_RTSMB2_FILEIOARGS_C
{
  PTREE pTree;
  int fid;
  word fidflags;
  byte externalFidRaw[16];
  word externalFid;
} RTSMB2_FILEIOARGS;


extern BBOOL Process_smb2_fileio_prolog(RTSMB2_FILEIOARGS *pargs, smb2_stream  *pStream, PFVOID command, PFVOID pcommand_structure_Fileid,word *pcommand_structure_size, word command_size);
#endif
