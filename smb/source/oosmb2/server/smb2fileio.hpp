//
// smb2fileio.hpp -
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

#ifndef include_smb2fileio
#define include_smb2fileio

struct smb2fstat
{
  char filename  [RTSMB_CFG_MAX_FILENAME_SIZE+1];  // need to allocate thios as an optimization
  unsigned char  fattributes;
  ddword         fsize64;         /* file size, in bytes */
  ddword         f_atime64;        /* last access time */
  ddword         f_wtime64;        /* last write time */
  ddword         f_ctime64;        /* last create time */
  ddword         f_htime64;        /* last change time */
  void           * rtp_dirobj;
  unsigned char  unique_fileid[8]; /* Passed back in Fileid field in SMB2  */
};

typedef struct Smb2FioCtxt_t
{
  Smb2ServerShareStruct *pShare;
  Smb2ServerSession     *pServerSession;
} Smb2FioCtxt;
typedef Smb2FioCtxt *pSmb2FioCtxt;

#define Smb2FioCtxtDecl(CTXT,pSESSION,pSHARE)  Smb2FioCtxt CTXT; CTXT.pServerSession = pSESSION; CTXT.pShare = pSHARE;



bool SMB2FIO_Open      (pSmb2FioCtxt pCtx,  fdhandle &fd,word * name, word flags, word mode);
long SMB2FIO_Read      (pSmb2FioCtxt pCtx,  fdhandle &fd, byte * buf, dword count);
long SMB2FIO_Write     (pSmb2FioCtxt pCtx,  fdhandle &fd, byte * buf, dword count);
long SMB2FIO_Seek      (pSmb2FioCtxt pCtx,  fdhandle &fd, long offset, int origin);
long long  SMB2FIO_Seek (pSmb2FioCtxt pCtx,  fdhandle &_fd, long long offset, int origin);
bool SMB2FIO_Truncate  (pSmb2FioCtxt pCtx,  fdhandle &fd, ddword offset);
bool SMB2FIO_Flush     (pSmb2FioCtxt pCtx,  fdhandle &fd);
bool SMB2FIO_Close      (pSmb2FioCtxt pCtx,  fdhandle &fd);
bool SMB2FIO_Rename    (pSmb2FioCtxt pCtx,  word * oldname, word * newname);
int SMB2FIO_DirentCount(pSmb2FioCtxt pCtx,  word * dirname,int max_count);
bool SMB2FIO_Delete    (pSmb2FioCtxt pCtx,  word * name);
bool SMB2FIO_Mkdir     (pSmb2FioCtxt pCtx,  word * name);
bool SMB2FIO_Rmdir     (pSmb2FioCtxt pCtx,  word * name);
bool SMB2FIO_SetCwd    (pSmb2FioCtxt pCtx,  word * name);
bool SMB2FIO_Pwd       (pSmb2FioCtxt pCtx,  word * name);
bool SMB2FIO_GFirst    (pSmb2FioCtxt pCtx,  struct smb2fstat *dirobj, word * name);
bool SMB2FIO_GNext     (pSmb2FioCtxt pCtx,  struct smb2fstat *dirobj);
void SMB2FIO_GDone     (pSmb2FioCtxt pCtx,  struct smb2fstat * dirobj);
bool SMB2FIO_Stat      (pSmb2FioCtxt pCtx,  word * name, struct smb2fstat *stat);
bool SMB2FIO_Chmode    (pSmb2FioCtxt pCtx,  word * name, byte attributes);
bool SMB2FIO_GetFree   (pSmb2FioCtxt pCtx,  dword * blocks, dword * bfree, dword * sectors, word * bytes);
bool SMB2FIO_SetTime   (pSmb2FioCtxt pCtx,  fdhandle &fd,  ddword * atime,  ddword * wtime,  ddword * ctime,  ddword * htime);
bool SMB2FIO_GetVolumeIdInternal(word tid, byte * volume);
#endif // include_smb2fileio
