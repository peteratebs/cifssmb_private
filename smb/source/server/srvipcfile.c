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

#define NUMSRVCSTREAMFILES 10
// Simple stream model for write command /read result IPC inerface
static StreamtoSrvSrvc SrvSrvcStreams[NUMSRVCSTREAMFILES];

static void FreeSrvSrvcStream(StreamtoSrvSrvc *pStreamtoSrvSrvc);
static int AllocSrvSrvcStreamFid(void)
{
int i;

   for (i = 0; i < NUMSRVCSTREAMFILES; i++)
   {
     if (!SrvSrvcStreams[i].in_use)
     {
      SrvSrvcStreams[i].in_use = TRUE;
      SrvSrvcStreams[i].bound_stream_pointer = 0;
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"AllocSrvSrvcStreamFid:  Allocated FID[%d].\n", i);
      return i|HARDWIRED_SRVSVC_FID;
     }
   }
   // Oops Out of these, probably because they weren't closed
   // This should not happen so recycle one now and alert
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"AllocSrvSrvcStreamFid:  Force to reuse FID[0].\n");
   FreeSrvSrvcStream(&SrvSrvcStreams[0]);
   SrvSrvcStreams[0].in_use = FALSE;
   return AllocSrvSrvcStreamFid();
//   return -1;
}


static void FreeSrvSrvcStream(StreamtoSrvSrvc *pStreamtoSrvSrvc)
{
   if (pStreamtoSrvSrvc->reply_heap_data)
   {
     RTP_FREE(pStreamtoSrvSrvc->reply_heap_data);
     pStreamtoSrvSrvc->reply_heap_data = 0;
     pStreamtoSrvSrvc->reply_data_count = 0;
   }

}


static StreamtoSrvSrvc *FdToSrvSrvcStream(int fd)
{
int ifd = fd&0xf;
   if (ifd >= NUMSRVCSTREAMFILES)
   {
     RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"FdToSrvSrvcStream: invalid fileid: %d\n", fd);
     return 0;
   }
   return &SrvSrvcStreams[ifd];
}

// Bind SMB2 stream pointer to fd file descriptor so we can get to context items from IOCTL calls that are accessed through the file system
void rtsmb_ipcrpc_bind_stream_pointer(int fd, void *stream_pointer)
{
  StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
  if (pStreamtoSrvSrvc)
    pStreamtoSrvSrvc->bound_stream_pointer = stream_pointer;
}
static BBOOL ipcrpc_is_srvsvc(PFRTCHAR name)
{
  return ( rtsmb_casecmp ((PFRTCHAR)name, _rtsmb2_srvsvc_pipe_name, CFG_RTSMB_USER_CODEPAGE) == 0 );
}
static BBOOL ipcrpc_is_lsarpc(PFRTCHAR name)
{
  return (rtsmb_casecmp ((PFRTCHAR)name, _rtsmb2_larpc_pipe_name, CFG_RTSMB_USER_CODEPAGE) == 0 );
}

static int ipcrpc_open(char RTSMB_FAR * name, unsigned short flag, unsigned short mode)
{
  return -1; // Do these in unicode
}

static int ipcrpc_wopen(unsigned short RTSMB_FAR * name, unsigned short flag, unsigned short mode)
{
    int fd = -1;
    // lsarpc
    if (ipcrpc_is_lsarpc(name))
    {
       fd = AllocSrvSrvcStreamFid();
    } else
    if (ipcrpc_is_srvsvc(name))
    {
       fd = AllocSrvSrvcStreamFid();
    }
    else
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "ipcrpc unkown file name");
    }
    return fd;
}


// Read the results of a write command that actually went to the dce layer.
// If reply_status_code is non zero, then no return data was stored, just return the 4 byte status.
// otherwise return the amount that was buffered.
static long ipcrpc_read(int fd,  unsigned char RTSMB_FAR * buf, long count)
{
    long rv = -1;

    {  // We are reading the results of a write command that actuall went to the dce layer.
       // If reply_status_code id non zero, then no return data was buffered, just return the 4 byte ststu.
      StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
      if (pStreamtoSrvSrvc)
      {
        if (pStreamtoSrvSrvc->reply_status_code!=0)
        {
          tc_memcpy(buf, &pStreamtoSrvSrvc->reply_status_code, 4);
          rv = 4;
        }
        else if (pStreamtoSrvSrvc->reply_data_count <= count)
        {
          tc_memcpy(buf, pStreamtoSrvSrvc->reply_response_data, pStreamtoSrvSrvc->reply_data_count);
          rv = pStreamtoSrvSrvc->reply_data_count;
        }
        FreeSrvSrvcStream(pStreamtoSrvSrvc);
      }
    }
    return rv;
}


// return xount if success
// return -2 if it failed but read 4 bytes will
// return -1 if it failed
static long ipcrpc_write(int fd,  unsigned char RTSMB_FAR * buf, long count)
{
    int r;
    long rv = -1;
    {  // This is hacky, call the srvsrvc call
       StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
       if (!pStreamtoSrvSrvc)
         return -1;
       FreeSrvSrvcStream(pStreamtoSrvSrvc); // If we didn't recv, clear the pending recv.
       pStreamtoSrvSrvc->reply_status_code=0;
       r = SMBU_StreamWriteToSrvcSrvc ( buf, count,pStreamtoSrvSrvc);
       if (r == 0 || pStreamtoSrvSrvc->reply_status_code!=0)
       {
           if (pStreamtoSrvSrvc->reply_status_code!=0)
             rv = -2;
           else
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
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"SrvSrvcStreamFid:ipcrpc_close  Freeing %d : FID[%d].\n", fd, fd&0xf);
      StreamtoSrvSrvc *pStreamtoSrvSrvc = FdToSrvSrvcStream(fd);
      if (pStreamtoSrvSrvc)
      {
        FreeSrvSrvcStream(pStreamtoSrvSrvc); // If we didn't recv, clear the pending recv.
        pStreamtoSrvSrvc->in_use=FALSE;
        rv = 0;
      }
    }
}

static long ipcrpc_lseek(int fd, long offset, int origin)
{
    long rv = 0;
    return rv;

}
static BBOOL ipcrpc_srvsvc_stub(int fd)
{
  return TRUE;
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


static BBOOL ipcrpc_wstat(unsigned short RTSMB_FAR * name, PSMBFSTAT vstat)
{
  tc_memset(vstat, 0, sizeof (*vstat));
  if (ipcrpc_is_srvsvc(name)||ipcrpc_is_lsarpc(name))
  {
    ipcrpc_translate_fstat(vstat);
    tc_memcpy(vstat->unique_fileid,name,8);
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

static BBOOL ipcrpc_stat(char RTSMB_FAR * name, PSMBFSTAT vstat)
{
  return FALSE;
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
