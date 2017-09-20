//
// smb2fileio.cpp -
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

#include "smb2serverincludes.hpp"
#include "rtpfile.h"
#include "rtpdobj.h"
#include "smb2fileio.hpp"

extern TIME_MS rtsmb_util_time_rtp_date_to_ms (RTP_DATE rtp_date);
extern RTP_DATE rtsmb_util_time_unix_to_rtp_date (dword unix_time);
extern dword rtsmb_util_time_ms_to_unix (TIME_MS ms_time);

void rtplatform_translate_dstat (struct smb2fstat *dstat, void * rtp_dirobj);

static RTP_DATE rtsmb_util_time_ms_to_rtp_date (TIME_MS time)
{
  return rtsmb_util_time_unix_to_rtp_date(rtsmb_util_time_ms_to_unix(time));
}

// ST_DISKTREE 1

static bool rtp_file_stub() {return false;}



#define IS_ADISK pCtx->pShare->share_type==1

bool  SMB2FIO_Open(pSmb2FioCtxt pCtx, fdhandle &fd, word * name, word flags, word mode)
{
  if (IS_ADISK)
  {
    int _fd, rv;
//    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    char *ascii_name = rtsmb_util_malloc_fullpath_ascii(pCtx->pShare->alloced_sharepath_ascii,name);

    rv = rtp_file_open ((RTP_FILE *) &_fd, ascii_name, flags, mode);
    smb_rtp_free(ascii_name);

    if (rv >= 0)
    {
      fd = _fd;
      return true;
    }
  }
  return false;
}
long SMB2FIO_Read      (pSmb2FioCtxt pCtx,  fdhandle &_fd, byte * buf, dword count)
{
  long rv=-1;
  if (IS_ADISK)
  {
    int fd=_fd;
    rv = rtp_file_read ((RTP_HANDLE) fd, buf, count);
  }
  return rv;
}
long SMB2FIO_Write     (pSmb2FioCtxt pCtx,  fdhandle &_fd, byte * buf, dword count)
{
  long rv=-1;
  if (IS_ADISK)
  {
    int fd=_fd;
    rv = rtp_file_write ((RTP_HANDLE) fd, buf, count);
  }
  return rv;
}

long long  SMB2FIO_Seek (pSmb2FioCtxt pCtx,  fdhandle &_fd, long long offset, int origin)
{
  long long rv=-1;
  if (IS_ADISK)
  {
    int fd=_fd;
    rv = rtp_file_llseek (fd, offset, origin);
  }
  return rv;
}


bool SMB2FIO_Truncate  (pSmb2FioCtxt pCtx,  fdhandle &_fd, ddword offset)
{
  bool rv = false;
  if (IS_ADISK)
  {
    int fd=_fd;
    if (rtp_file_truncate64 ((RTP_HANDLE) fd, offset)>=0)
     rv = true;
  }
  return rv;
}
bool SMB2FIO_Flush (pSmb2FioCtxt pCtx,  fdhandle &_fd)
{
  bool rv = false;
  if (IS_ADISK)
  {
    int fd=_fd;
    if (rtp_file_flush((RTP_HANDLE) fd)==0)
      rv = true;
  }
  return rv;
}
bool SMB2FIO_Close      (pSmb2FioCtxt pCtx,  fdhandle &_fd)
{
  bool rv = false;
  if (IS_ADISK)
  {
    int fd=_fd;
    if (rtp_file_close ((RTP_FILE) fd) >= 0)
      rv = true;
  }
  return rv;
}
bool SMB2FIO_Rename    (pSmb2FioCtxt pCtx,  word * oldname, word * newname)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_oldname = rtsmb_util_malloc_unicodeto_ascii(oldname);
    char *ascii_newname = rtsmb_util_malloc_unicodeto_ascii(newname);
    if (rtp_file_rename (ascii_oldname, ascii_newname) >= 0)
      rv=true;
    smb_rtp_free(ascii_oldname);
    smb_rtp_free(ascii_newname);
  }
  return rv;
}
int SMB2FIO_DirentCount(pSmb2FioCtxt pCtx,  word * dirname,int max_count)
{
  return 0;
}
bool SMB2FIO_Delete    (pSmb2FioCtxt pCtx,  word * name)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    if (rtp_file_delete(ascii_name) >=0)
      rv = true;
    smb_rtp_free(ascii_name);
  }
  return rv;
}
bool SMB2FIO_Mkdir     (pSmb2FioCtxt pCtx,  word * name)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    if (rtp_file_mkdir(ascii_name) >=0)
      rv = true;
    smb_rtp_free(ascii_name);
  }
  return rv;
}
bool SMB2FIO_Rmdir     (pSmb2FioCtxt pCtx,  word * name)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    if (rtp_file_rmdir(ascii_name) >=0)
      rv = true;
    smb_rtp_free(ascii_name);
  }
  return rv;
}
bool SMB2FIO_SetCwd    (pSmb2FioCtxt pCtx,  word * name)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    if (rtp_file_setcwd(ascii_name) >=0)
      rv = true;
    smb_rtp_free(ascii_name);
  }
  return rv;
}

bool SMB2FIO_Pwd (pSmb2FioCtxt pCtx,  word * name)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_name = (char *)smb_rtp_malloc(RTSMB_CFG_MAX_FILENAME_SIZE);

    if (rtp_file_pwd(ascii_name, RTSMB_CFG_MAX_FILENAME_SIZE) >= 0)
    {
        rtsmb_util_ascii_to_unicode (ascii_name,name, std::max((size_t)((RTSMB_CFG_MAX_FILENAME_SIZE-1)*2),(strlen(ascii_name)+1)*2));
        rv = true;
    }
    smb_rtp_free(ascii_name);
  }
  return rv;
}

bool SMB2FIO_GFirst    (pSmb2FioCtxt pCtx,  struct smb2fstat *dirobj, word * name)
{
  bool rv = false;
  dirobj->rtp_dirobj = (void*)0;
  if (IS_ADISK)
  {
    int len;

    char *ascii_name = rtsmb_util_malloc_fullpath_ascii(pCtx->pShare->alloced_sharepath_ascii,name,16);// Add a little extra space

std::cout << "AAA:" <<  ascii_name << ":AAA" << std::endl;
    len = strlen(ascii_name);
    /* translate "\\*" to "\\*.*" becaues some file systems don't like "*" */
    if (len > 1 && ascii_name[len-1]=='*' && ascii_name[len-2]=='\\')
    {
        ascii_name[len]='.';ascii_name[len+1]='*'; ascii_name[len+2]=0;
    }
std::cout << "BBB:" <<  ascii_name << ":BBB" << std::endl;
    void * rtp_dirobj;
    if (rtp_file_gfirst_smb(&rtp_dirobj, ascii_name) >= 0)
    {
      rtp_file_get_name(rtp_dirobj, dirobj->filename, RTSMB_CFG_MAX_FILENAME_SIZE);
      dirobj->filename[RTSMB_CFG_MAX_FILENAME_SIZE-1] = '\0';
      /* translate rtplatform dstat to smb2fstat */
      rtplatform_translate_dstat (dirobj, rtp_dirobj);
      rv = true;
    }
    smb_rtp_free(ascii_name);
  }
  return rv;
}
bool SMB2FIO_GNext     (pSmb2FioCtxt pCtx,  struct smb2fstat *dirobj)
{
  bool rv = false;
  if ((IS_ADISK) && dirobj && dirobj->rtp_dirobj)
  {
    if (rtp_file_gnext(dirobj->rtp_dirobj)>=0)
    {
      rtp_file_get_name(dirobj->rtp_dirobj, dirobj->filename, RTSMB_CFG_MAX_FILENAME_SIZE);
//      rtp_file_get_name(rtp_dirobj, dirobj->filename, RTSMB_CFG_MAX_FILENAME_SIZE);
      dirobj->filename[RTSMB_CFG_MAX_FILENAME_SIZE-1] = '\0';
      /* translate rtplatform dstat to smb2fstat */
      rtplatform_translate_dstat (dirobj, dirobj->rtp_dirobj);
      rv = true;
    }
  }
  return rv;
}
void SMB2FIO_GDone     (pSmb2FioCtxt pCtx,  struct smb2fstat * dirobj)
{
  if (IS_ADISK)
  {
    /* make sure it hasn't already been freed */
    if (dirobj->rtp_dirobj != (void*)0)
    {
        rtp_file_gdone(dirobj->rtp_dirobj);
        dirobj->rtp_dirobj=0;
    }
  }
}

bool SMB2FIO_Stat      (pSmb2FioCtxt pCtx,  word * name, struct smb2fstat *stat)
{
  bool rv = false;
  if (IS_ADISK)
  {
    rv = SMB2FIO_GFirst(pCtx,  stat, name);
    if (rv)
     SMB2FIO_GDone(pCtx,stat);
  }
  return rv;
}

bool SMB2FIO_Chmode    (pSmb2FioCtxt pCtx, word * name, byte attributes)
{
  bool rv = false;
  if (IS_ADISK)
  {
    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    if (rtp_file_chmode (ascii_name, attributes) > 0)
      rv = true;
    smb_rtp_free(ascii_name);
  }
  return rv;
}
bool SMB2FIO_GetFree   (pSmb2FioCtxt pCtx,  dword * blocks, dword * bfree, dword * sectors, word * bytes_per_sector)
{
#warning SMB2FIO_GetFree is broken
  bool rv = false;
  if (IS_ADISK)
  {
//    char *ascii_name = rtsmb_util_malloc_unicodeto_ascii(name);
    char *ascii_name = "DEAD";
    unsigned long  sectors_per_unit;
    if (rtp_file_get_free (ascii_name, blocks, bfree, &sectors_per_unit, bytes_per_sector) < 0)
     rv = true;
//    smb_rtp_free(ascii_name);
  }
  return rv;
}

static TIME_MS *ddtotime(ddword t,TIME_MS *tm)
{
 tm->high_time = (dword)(t>>32);
 tm->low_time  = (dword)(t&0xffffffff);
 return tm;
}
bool SMB2FIO_SetTime(pSmb2FioCtxt pCtx,  fdhandle &_fd,  ddword * atime,  ddword * wtime,  ddword * ctime,  ddword * htime)
{
  bool rv = false;
  if (IS_ADISK)
  {
    int fd=_fd;
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
    TIME_MS tm;
    ddtotime(*atime,&tm);adate = rtsmb_util_time_ms_to_rtp_date(tm);
    ddtotime(*wtime,&tm);wdate = rtsmb_util_time_ms_to_rtp_date(tm);
    ddtotime(*ctime,&tm);cdate = rtsmb_util_time_ms_to_rtp_date(tm);
    ddtotime(*htime,&tm);hdate = rtsmb_util_time_ms_to_rtp_date(tm);
    if (rtp_file_set_time (fd, &adate, &wdate, &cdate, &hdate) >= 0)
      rv = true;
  }
  return rv;
}
bool SMB2FIO_GetVolumeIdInternal(pSmb2FioCtxt pCtx, byte * volume)
{
  bool rv = false;
  if (IS_ADISK)
  {
    rv =  rtp_file_stub();  // SMB2FIO_GetVolumeIdInternal
  }
  return rv;
}

void rtplatform_translate_dstat (struct smb2fstat *dstat, void * rtp_dirobj)
{
  RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
  RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
  RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
  RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
  TIME_MS atime = {0,0};
  TIME_MS wtime = {0,0};
  TIME_MS ctime = {0,0};
  TIME_MS htime = {0,0};

  rtp_file_get_attrib(rtp_dirobj, &dstat->fattributes);

  rtp_file_get_time(rtp_dirobj, &adate, &wdate, &cdate, &hdate );

  if (adate.year != 0) atime = rtsmb_util_time_rtp_date_to_ms(adate);
  if (wdate.year != 0) wtime = rtsmb_util_time_rtp_date_to_ms(wdate);
  if (cdate.year != 0) ctime = rtsmb_util_time_rtp_date_to_ms(cdate);
  if (hdate.year != 0) htime = rtsmb_util_time_rtp_date_to_ms(hdate);

#define  DDWCONV(HI, LO) ( (ddword)HI<<32|(ddword)LO)
#define  TIMECONV(X) ( (ddword)X.high_time<<32|(ddword)X.high_time)

  dstat->f_ctime64 = TIMECONV(ctime);
  dstat->f_wtime64 = TIMECONV(wtime);
  dstat->f_atime64 = TIMECONV(atime);
  dstat->f_htime64 = TIMECONV(htime);

  //    rtp_file_get_size(rtp_dirobj, &dstat->fsize);
  dword hi, lo;
  rtp_file_get_size64(rtp_dirobj, &hi, &lo);

  dstat->fsize64 = DDWCONV(hi, lo);
  rtp_file_get_unique_id(rtp_dirobj, dstat->unique_fileid);
  dstat->rtp_dirobj = rtp_dirobj;
}


#if (0)

int  rtplatform_direntcount(char RTSMB_FAR * name, int max_count)
{
  return rtp_file_direntcount(name,max_count);
}

void rtplatform_translate_fstat (PSMBFSTAT fstat, void * rtp_dirobj)
{
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
    TIME atime = {0,0};
    TIME wtime = {0,0};
    TIME ctime = {0,0};
    TIME htime = {0,0};

    rtp_file_get_time(rtp_dirobj, &adate, &wdate, &cdate, &hdate);

    if (adate.year != 0) atime = rtsmb_util_time_rtp_date_to_ms(adate);
    if (wdate.year != 0) wtime = rtsmb_util_time_rtp_date_to_ms(wdate);
    if (cdate.year != 0) ctime = rtsmb_util_time_rtp_date_to_ms(cdate);
    if (hdate.year != 0) htime = rtsmb_util_time_rtp_date_to_ms(hdate);

//    rtp_file_get_size(rtp_dirobj, &fstat->f_size);   /* file size, in bytes */
    rtp_file_get_size64(rtp_dirobj, &fstat->fsize_hi,&fstat->fsize);

    fstat->f_atime64 = atime;
    fstat->f_ctime64 = ctime;
    fstat->f_wtime64 = wtime;
    fstat->f_htime64 = htime;


    rtp_file_get_attrib(rtp_dirobj, &fstat->f_attributes);
	rtp_file_get_unique_id(rtp_dirobj, fstat->unique_fileid);
}
#endif
