//
// SRVIPCFILE.C - RTSMB File System Interface for IPC$ interface
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2016
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
// File abstraction layer for IPC$ operations.
//
// Currently supporting up to 10 simultaneous internal handles. 0xDCE0 - 0xDCE9
// Writes execute DCE commands that queue data onto the stream or the pipe.
// Reads pull data from the stream.
// Close frees any unpulled data.
//

#include "rtpfile.h"
#include "rtpwfile.h"
#include "rtpdutil.h"
#include "rtpmem.h"
#include "rtpdobj.h"
#include "rtpwcs.h"
#include "smbdebug.h"

#include "srvipcfile.h"
#include "srvsrvsvc.h"
#include "smbutil.h"

#define HARDWIRED_SRVSVC_FID                              0xDCE0  // 0xDCE0 uniquely ID /srvsvc named pipe
#define IS_SRVSVC_FID(FD) ((FD&0xfff0) == HARDWIRED_SRVSVC_FID)

// ********************************************************************
static int  ipcrpc_open(char RTSMB_FAR * name, unsigned short flag, unsigned short mode);
static long ipcrpc_read(int fd,  unsigned char RTSMB_FAR * buf, long count);
static long ipcrpc_write(int fd,  unsigned char RTSMB_FAR * buf, long count);
static int  ipcrpc_close(int fd);
static long ipcrpc_lseek(int fd, long offset, int origin);
static BBOOL ipcrpc_truncate(int fd, long offset);
static BBOOL ipcrpc_flush(int fd);
static BBOOL ipcrpc_pwd(char RTSMB_FAR * to, long size);
static BBOOL ipcrpc_rename(char RTSMB_FAR * from, char RTSMB_FAR * to);
static BBOOL ipcrpc_delete(char RTSMB_FAR * to);
static BBOOL ipcrpc_mkdir(char RTSMB_FAR * to);
static BBOOL ipcrpc_setcwd(char RTSMB_FAR * to);
static BBOOL ipcrpc_rmdir(char RTSMB_FAR * to);
static BBOOL ipcrpc_gfirst(PSMBDSTAT dirobj, char RTSMB_FAR * name);
static BBOOL ipcrpc_gnext(PSMBDSTAT dirobj);
static void ipcrpc_gdone(PSMBDSTAT dirobj);
static BBOOL ipcrpc_stat(char RTSMB_FAR * name, PSMBFSTAT vstat);
static BBOOL ipcrpc_chmode(char RTSMB_FAR * name, unsigned char attributes);
static BBOOL ipcrpc_get_free(char RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector);
static BBOOL ipcrpc_set_time(int fd, TIME atime, TIME wtime, TIME ctime, TIME htime);

static int  ipcrpc_wopen(unsigned short RTSMB_FAR * name, unsigned short flag, unsigned short mode);
static BBOOL ipcrpc_wrename(unsigned short RTSMB_FAR * from, unsigned short RTSMB_FAR * to);
static BBOOL ipcrpc_wdelete(unsigned short RTSMB_FAR * to);
static BBOOL ipcrpc_wmkdir(unsigned short RTSMB_FAR * to);
static BBOOL ipcrpc_wrmdir(unsigned short RTSMB_FAR * to);
static BBOOL ipcrpc_wsetcwd(unsigned short RTSMB_FAR * to);
static BBOOL ipcrpc_wpwd(unsigned short RTSMB_FAR * to, long size);
static BBOOL ipcrpc_wgfirst(PSMBDSTAT dirobj, unsigned short RTSMB_FAR * name);
static BBOOL ipcrpc_wgnext (PSMBDSTAT dirobj);
static BBOOL ipcrpc_wstat(unsigned short RTSMB_FAR * name, PSMBFSTAT vstat);
static BBOOL ipcrpc_wchmode(unsigned short RTSMB_FAR * name, unsigned char attributes);
static BBOOL ipcrpc_wget_free(unsigned short RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector);

static void ipcrpc_translate_dstat (PSMBDSTAT dstat);
static void ipcrpc_translate_fstat (PSMBFSTAT fstat);

static SMBFILEAPI _rtsmb_filesys_ipcrpc;
PSMBFILEAPI prtsmb_ipcrpc_filesys = 0;


/******************************************************************************

 rtsmb_ipcrpc_filesys_init - Initialize the RTSMB file system for PIPEs

 Description

    The interface between RTSMB and underlying file system routines is the
    SMBFILEAPI struct, which contains a set of function pointers to the various
    file system routines needed by RTSMB. These functions are called when IO
    is perfromed on a pipe.

 See Also

 Returns

    0
******************************************************************************/

#define FS_NOT_SUPPORTED(FNAME) {rtp_printf("IPC function not supported: %s\n", FNAME); return FALSE;}
int rtsmb_ipcrpc_filesys_init(void)
{

    prtsmb_ipcrpc_filesys = &_rtsmb_filesys_ipcrpc;


    prtsmb_ipcrpc_filesys->fs_open         =   (RTSMB_FS_OPENFN)        ipcrpc_open;
    prtsmb_ipcrpc_filesys->fs_read         =   (RTSMB_FS_READFN)        ipcrpc_read;
    prtsmb_ipcrpc_filesys->fs_write        =   (RTSMB_FS_WRITEFN)       ipcrpc_write;
    prtsmb_ipcrpc_filesys->fs_lseek        =   (RTSMB_FS_LSEEKFN)       ipcrpc_lseek;
    prtsmb_ipcrpc_filesys->fs_truncate     =   (RTSMB_FS_TRUNCATEFN)    ipcrpc_truncate;
    prtsmb_ipcrpc_filesys->fs_flush        =   (RTSMB_FS_FLUSHFN)       ipcrpc_flush;
    prtsmb_ipcrpc_filesys->fs_close        =   (RTSMB_FS_CLOSEFN)       ipcrpc_close;
    prtsmb_ipcrpc_filesys->fs_rename       =   (RTSMB_FS_RENAMEFN)      ipcrpc_rename;
    prtsmb_ipcrpc_filesys->fs_delete       =   (RTSMB_FS_DELETEFN)      ipcrpc_delete;
    prtsmb_ipcrpc_filesys->fs_mkdir        =   (RTSMB_FS_MKDIRFN)       ipcrpc_mkdir;
    prtsmb_ipcrpc_filesys->fs_rmdir        =   (RTSMB_FS_RMDIRFN)       ipcrpc_rmdir;
    prtsmb_ipcrpc_filesys->fs_set_cwd       =  (RTSMB_FS_SETCWDFN)      ipcrpc_setcwd;
    prtsmb_ipcrpc_filesys->fs_pwd          =   (RTSMB_FS_PWDFN)         ipcrpc_pwd;
    prtsmb_ipcrpc_filesys->fs_gfirst       =   (RTSMB_FS_GFIRSTFN)      ipcrpc_gfirst;
    prtsmb_ipcrpc_filesys->fs_gnext        =   (RTSMB_FS_GNEXTFN)       ipcrpc_gnext;
    prtsmb_ipcrpc_filesys->fs_gdone        =   (RTSMB_FS_GDONEFN)       ipcrpc_gdone;
    prtsmb_ipcrpc_filesys->fs_stat         =   (RTSMB_FS_STATFN)        ipcrpc_stat;
    prtsmb_ipcrpc_filesys->fs_chmode       =   (RTSMB_FS_CHMODEFN)      ipcrpc_chmode;
    prtsmb_ipcrpc_filesys->fs_get_free     =   (RTSMB_FS_GET_FREEFN)    ipcrpc_get_free;
    prtsmb_ipcrpc_filesys->fs_set_time     =   (RTSMB_FS_SET_TIMEFN)    ipcrpc_set_time;

    prtsmb_ipcrpc_filesys->fs_wopen        =   (RTSMB_FS_WOPENFN)       ipcrpc_wopen;
    prtsmb_ipcrpc_filesys->fs_wrename      =   (RTSMB_FS_WRENAMEFN)     ipcrpc_wrename;
    prtsmb_ipcrpc_filesys->fs_wdelete      =   (RTSMB_FS_WDELETEFN)     ipcrpc_wdelete;
    prtsmb_ipcrpc_filesys->fs_wmkdir       =   (RTSMB_FS_WMKDIRFN)      ipcrpc_wmkdir;
    prtsmb_ipcrpc_filesys->fs_wrmdir       =   (RTSMB_FS_WRMDIRFN)      ipcrpc_wrmdir;
    prtsmb_ipcrpc_filesys->fs_wset_cwd     =   (RTSMB_FS_WSETCWDFN)     ipcrpc_wsetcwd;
    prtsmb_ipcrpc_filesys->fs_wpwd         =   (RTSMB_FS_WPWDFN)        ipcrpc_wpwd;
    prtsmb_ipcrpc_filesys->fs_wgfirst      =   (RTSMB_FS_WGFIRSTFN)     ipcrpc_wgfirst;
    prtsmb_ipcrpc_filesys->fs_wgnext       =   (RTSMB_FS_WGNEXTFN)      ipcrpc_wgnext;
    prtsmb_ipcrpc_filesys->fs_wstat        =   (RTSMB_FS_WSTATFN)       ipcrpc_wstat;
    prtsmb_ipcrpc_filesys->fs_wchmode      =   (RTSMB_FS_WCHMODEFN)     ipcrpc_wchmode;
    prtsmb_ipcrpc_filesys->fs_wget_free    =   (RTSMB_FS_WGET_FREEFN)   ipcrpc_wget_free;

    return (0);
}

// Simple stream model for write command /read result IPC inerface
static StreamtoSrvSrvc SrvSrvcStreams[10];

static int AllocSrvSrvcStreamFid(void)
{
int i;

   for (i = 0; i < 10; i++)
   {
     if (!SrvSrvcStreams[i].in_use)
     {
      SrvSrvcStreams[i].in_use = TRUE;
      printf("AllocSrvSrvcStreamFid returning FD: %X\n", i|HARDWIRED_SRVSVC_FID);
      return i|HARDWIRED_SRVSVC_FID;
     }
   }
   return -1;
}

static void FreeSrvSrvcStream(StreamtoSrvSrvc *pStreamtoSrvSrvc)
{
   if (pStreamtoSrvSrvc->reply_heap_data)
   {
     rtp_free(pStreamtoSrvSrvc->reply_heap_data);
     pStreamtoSrvSrvc->reply_heap_data = 0;
     pStreamtoSrvSrvc->reply_data_count = 0;
   }

}
static StreamtoSrvSrvc *FdToSrvSrvcStream(int fd)
{
   return &SrvSrvcStreams[fd&0xf];
}


static BBOOL ipcrpc_is_srvsvc(char RTSMB_FAR * name)
{
  return (rtsmb_casecmp (name, _rtsmb_srvsvc_pipe_name, CFG_RTSMB_USER_CODEPAGE) == 0);
}
static int ipcrpc_open(char RTSMB_FAR * name, unsigned short flag, unsigned short mode)
{
    int fd = -1;

    if (ipcrpc_is_srvsvc(name))
    {
       fd = AllocSrvSrvcStreamFid();
    }
    else
    {
      rtsmb_dump_bytes("IPC$ open unknown file name", name, rtsmb_len(name)*2, DUMPUNICODE);
    }
    return fd;
}

static int ipcrpc_wopen(unsigned short RTSMB_FAR * name, unsigned short flag, unsigned short mode)
{
  return ipcrpc_open(name, flag, mode);
}


static long ipcrpc_read(int fd,  unsigned char RTSMB_FAR * buf, long count)
{
    long rv = -1;

    if (IS_SRVSVC_FID(fd))
    {  // This is hacky, call the srvsrvc call
      StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
      if (pStreamtoSrvSrvc->reply_data_count <= count)
      {
        tc_memcpy(buf, pStreamtoSrvSrvc->reply_response_data, pStreamtoSrvSrvc->reply_data_count);
        rv = pStreamtoSrvSrvc->reply_data_count;
      }
      FreeSrvSrvcStream(pStreamtoSrvSrvc);
    }
    return rv;
}



static long ipcrpc_write(int fd,  unsigned char RTSMB_FAR * buf, long count)
{
    long rv = -1;

    if (IS_SRVSVC_FID(fd))
    {  // This is hacky, call the srvsrvc call
       StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
       FreeSrvSrvcStream(pStreamtoSrvSrvc); // If we didn't recv, clear the pending recv.
       if (SMBU_StreamWriteToSrvcSrvc ( buf, count,pStreamtoSrvSrvc) == 0)
       {
           rv = count;
       }
       else
          FreeSrvSrvcStream(pStreamtoSrvSrvc); // If we didn't recv, clear the pending recv.
    }
    return rv;
}


static int ipcrpc_close(int fd)
{
    int rv = -1;
    if (IS_SRVSVC_FID(fd))
    {
      StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
      FreeSrvSrvcStream(pStreamtoSrvSrvc); // If we didn't recv, clear the pending recv.
      pStreamtoSrvSrvc->in_use=FALSE;
      rv = 0;
    }
}

static long ipcrpc_lseek(int fd, long offset, int origin)
{
    long rv = -1;
    if (IS_SRVSVC_FID(fd))
      rv = 0;
    return rv;

}
static BBOOL ipcrpc_srvsvc_stub(int fd)
{
  if (IS_SRVSVC_FID(fd))
     return TRUE;
  else
     return FALSE;
}

static BBOOL ipcrpc_truncate(int fd, long offset)
{
  return ipcrpc_srvsvc_stub(fd);
}


static BBOOL ipcrpc_flush(int fd)
{
  return ipcrpc_srvsvc_stub(fd);
}


static BBOOL ipcrpc_rename(char RTSMB_FAR * from, char RTSMB_FAR * to)
{
    FS_NOT_SUPPORTED("ipcrpc_rename")
}
static BBOOL ipcrpc_wrename(unsigned short RTSMB_FAR * from, unsigned short RTSMB_FAR * to)
{
    FS_NOT_SUPPORTED("ipcrpc_wrename")
}

static BBOOL ipcrpc_delete(char RTSMB_FAR * d)
{
    FS_NOT_SUPPORTED("ipcrpc_delete")
}

static BBOOL ipcrpc_wdelete(unsigned short RTSMB_FAR * d)
{
    FS_NOT_SUPPORTED("ipcrpc_wdelete")
}

static BBOOL ipcrpc_mkdir(char RTSMB_FAR * d)
{
    FS_NOT_SUPPORTED("ipcrpc_mkdir")
}

static BBOOL ipcrpc_wmkdir(unsigned short RTSMB_FAR * d)
{
    FS_NOT_SUPPORTED("ipcrpc_wmkdir")
}

static BBOOL ipcrpc_rmdir(char RTSMB_FAR * d)
{
    FS_NOT_SUPPORTED("ipcrpc_rmdir")
}

static BBOOL ipcrpc_wrmdir(unsigned short RTSMB_FAR * d)
{
    FS_NOT_SUPPORTED("ipcrpc_wrmdir")
}

static BBOOL ipcrpc_setcwd(char RTSMB_FAR * to)
{
    FS_NOT_SUPPORTED("ipcrpc_setcwd")
}

static BBOOL ipcrpc_wsetcwd(unsigned short RTSMB_FAR * to)
{
    FS_NOT_SUPPORTED("ipcrpc_wsetcwd")
}

static BBOOL ipcrpc_pwd(char RTSMB_FAR * to, long size)
{
    FS_NOT_SUPPORTED("ipcrpc_pwd")
}

static BBOOL ipcrpc_wpwd(unsigned short RTSMB_FAR * to, long size)
{
    FS_NOT_SUPPORTED("ipcrpc_wpwd")
}

static BBOOL ipcrpc_gfirst(PSMBDSTAT dirobj, char RTSMB_FAR * name_in)
{
    FS_NOT_SUPPORTED("ipcrpc_gfirst")
}
static BBOOL ipcrpc_wgfirst(PSMBDSTAT dirobj, unsigned short RTSMB_FAR * name_in)
{
    FS_NOT_SUPPORTED("ipcrpc_wgfirst")
}

static BBOOL ipcrpc_gnext(PSMBDSTAT dirobj)
{
    FS_NOT_SUPPORTED("ipcrpc_gnext")
}

static BBOOL ipcrpc_wgnext(PSMBDSTAT dirobj)
{
    FS_NOT_SUPPORTED("ipcrpc_wgnext")
}



static void ipcrpc_gdone(PSMBDSTAT dirobj)
{
}


static BBOOL ipcrpc_stat(char RTSMB_FAR * name, PSMBFSTAT vstat)
{
    if (ipcrpc_is_srvsvc(name))
    {
      ipcrpc_translate_fstat(vstat);
      return TRUE;
    }
    else
    {
      return FALSE;
    }
}

static BBOOL ipcrpc_wstat(unsigned short RTSMB_FAR * name, PSMBFSTAT vstat)
{
    return ipcrpc_stat(name, vstat);
}

static BBOOL ipcrpc_chmode(char RTSMB_FAR * name, unsigned char attributes)
{
    FS_NOT_SUPPORTED("ipcrpc_chmode")
}

static BBOOL ipcrpc_wchmode(unsigned short RTSMB_FAR * name, unsigned char attributes)
{
    FS_NOT_SUPPORTED("ipcrpc_wchmode")
}

static BBOOL ipcrpc_get_free (char RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector)
{
    *total = 0;
    *free = 0;
    *sectors_per_unit = 1;
    *bytes_per_sector = 512;
    return TRUE;

}

static BBOOL ipcrpc_wget_free (unsigned short RTSMB_FAR * name, unsigned long *total, unsigned long *free, unsigned long *sectors_per_unit, unsigned short *bytes_per_sector)
{
    *total = 0;
    *free = 0;
    *sectors_per_unit = 1;
    *bytes_per_sector = 512;
    return TRUE;

}


static BBOOL ipcrpc_set_time(int fd, TIME atime, TIME wtime, TIME ctime, TIME htime)
{
    FS_NOT_SUPPORTED("ipcrpc_set_time")
}

static void ipcrpc_translate_dstat (PSMBDSTAT dstat)
{
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
    TIME atime = {0,0};
    TIME wtime = {0,0};
    TIME ctime = {0,0};
    TIME htime = {0,0};

    dstat->fs_api = prtsmb_ipcrpc_filesys;

    dstat->fattributes = 0;

    dstat->fctime64.low_time = ctime.low_time;
    dstat->fctime64.high_time = ctime.high_time;
    dstat->fwtime64.low_time = wtime.low_time;
    dstat->fwtime64.high_time = wtime.high_time;
    dstat->fatime64.low_time = atime.low_time;
    dstat->fatime64.high_time = atime.high_time;
    dstat->fhtime64.low_time = htime.low_time;
    dstat->fhtime64.high_time = htime.high_time;

    dstat->fsize = 0;

    dstat->rtp_dirobj = 0;

}

static void ipcrpc_translate_fstat (PSMBFSTAT fstat)
{
    RTP_DATE adate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE wdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE cdate = {0,0,0,0,0,0,0,0,0};
    RTP_DATE hdate = {0,0,0,0,0,0,0,0,0};
    TIME atime = {0,0};
    TIME wtime = {0,0};
    TIME ctime = {0,0};
    TIME htime = {0,0};

    fstat->f_atime64 = atime;
    fstat->f_ctime64 = ctime;
    fstat->f_wtime64 = wtime;
    fstat->f_htime64 = htime;

    fstat->f_attributes = 0;

}
