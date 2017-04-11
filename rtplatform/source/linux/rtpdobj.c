/*
|  RTPDOBJ.C -
|
|  EBS -
|
|   $Author: vmalaiya $
|   $Date: 2006/07/17 15:29:01 $
|   $Name:  $
|   $Revision: 1.3 $
|
|  Copyright EBS Inc. , 2006
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/

/*****************************************************************************/
/* Header files
 *****************************************************************************/
#include "rtpdobj.h"
#include "rtpdebug.h"
#include "rtpchar.h"




#include <errno.h>
#include <glob.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
// #define READDIR_BUFFERING
#ifdef READDIR_BUFFERING
#define _GNU_SOURCE
// #include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
struct linux_dirent {
   unsigned long long  d_ino;
   long long         d_off;
   unsigned short d_reclen;
   unsigned char   d_type;
   char           d_name[];
};
#endif
#include <sys/stat.h>
#include <dirent.h>
//Try again: Expected 16384 files but only got 9214
//Try again: Expected 16384 files but only got 12811
//Try again: Expected 16384 files but only got 12805
//Try again: Expected 16384 files but only got 16376




/*****************************************************************************/
/* Macros
 *****************************************************************************/

/*****************************************************************************/
/* Types
 *****************************************************************************/

#define GNSTYLE_GLOB  1
#define GNSTYLE_WILD  2
#define GNSTYLE_MATCH 3


#define SMB_MAX_NAME_SIZE 255
typedef struct NativeFileSystemObj
{
#define GNSTYLE_GLOB  1
#define GNSTYLE_WILD  2
#define GNSTYLE_MATCH 3
    int   gnstyle;
    DIR   *dirreadObj;                        // handle from opendir() if not gnstyle != GNSTYLE_GLOB
    char  dirmatchBase[SMB_MAX_NAME_SIZE];    // Base when we stat using the full path the whole
    int dirmatchBaseEnd;                      // Offset into dirmatchBase we copy to before stat
    char  dirmatchPattern[SMB_MAX_NAME_SIZE]; // pattern if gnstyle == GNSTYLE_MATCH
    char  dirmatchCurrent[SMB_MAX_NAME_SIZE]; // pattern if gnstyle == GNSTYLE_MATCH
    int currentPath;        // scheme if gnstyle == GNSTYLE_GLOB
    int glob_data_valid;
	glob_t globdata;
    struct stat statdata;
    struct stat dot_statdata;
    struct stat dot_dot_statdata;
    int    dot_count;

// Without COUNT_DIRENTS_AT_OPEN
//Try again: Expected 16384 files but only got 9214
//Try again: Expected 16384 files but only got 12811
//Try again: Expected 16384 files but only got 12805
//Try again: Expected 16384 files but only got 16376
// #define COUNT_DIRENTS_AT_OPEN
#ifdef COUNT_DIRENTS_AT_OPEN
    char   dirmatchBaseCopy[512];
    int    dirent_count_total;
    int    dirent_count_used;
#endif

// see above #define READDIR_BUFFERING   // Doesn't completely fix it
#ifdef READDIR_BUFFERING   // Doesn't completely fix it
#define READDIR_BUF_SIZE (32768*4)
    int readdir_fd;
    int readdir_bpos;
    int readdir_nread;
    int readdir_eof;
    unsigned char readdir_buf[READDIR_BUF_SIZE];
#endif

//#define READAHEAD_BUFFERING
#ifdef READAHEAD_BUFFERING
#define READAHEAD_SIZE    128
    int buffered_dirent_count;
    int output_page;
    int output_page_count;
    int output_page_offset;
    struct dirent *buffered_dirents[2][READAHEAD_SIZE];
    int input_page;
    int input_page_count;
    int at_eof;
#endif
//#define TEST_BUFFERING  // This methodology does fix premature eof on readdir when deleting too.
#ifdef TEST_BUFFERING
    int buffered_dirent_count;
    struct dirent *buffered_dirents[2048];
    int buffered_dirent_offset;
#endif

} FSOBJ;

#ifdef TEST_BUFFERING
static void  free_buffered_entries(struct dirent **buffered_dirents);
#endif

#ifdef READDIR_BUFFERING
static void  refresh_readdir_buffers(FSOBJ *linDirObj);
#endif

#ifdef READAHEAD_BUFFERING
static void  refresh_read_ahead_buffers(FSOBJ *linDirObj);
static void  free_read_ahead_buffered_entries(FSOBJ *linDirObj,int output_page);
#endif


/*****************************************************************************/
/* Function Prototypes
 *****************************************************************************/
static int _rtp_lindate_to_date (time_t * lindate, RTP_DATE * rtpdate);

/*****************************************************************************/
/* Data
 *****************************************************************************/

/*****************************************************************************/
/* Function Definitions
 *****************************************************************************/

/*----------------------------------------------------------------------*
                             rtp_file_gfirst
 *----------------------------------------------------------------------*/
static void bracify(char *bracified_name,char lower_c)
{
  bracified_name[0]='{';
  bracified_name[1]=lower_c;
  bracified_name[2]=',';
  bracified_name[3]= (char) rtp_toupper((char)lower_c);
  bracified_name[4]='}';
  bracified_name[5]=0;
}


static int check_if_dot(char *pc)
{
 if ( *pc == '.' && *(pc+1) == 0 )
   return 1;
 return 0;
}

static int check_if_dot_dot(char *pc)
{
 if ( *pc == (char) '.' && *(pc+1) == (char) '.' && *(pc+2) == (char)0 )
   return 1;
 return 0;
}


static int doReadirAndStat(FSOBJ *linDirObj)
{
char *matched_filename = 0;

    do
    {
     struct dirent *direntp;
#ifdef READAHEAD_BUFFERING
     struct dirent currdirent;
#endif
     char *current_filename = 0;
#if (defined(TEST_BUFFERING))
      if (linDirObj->gnstyle == GNSTYLE_WILD)
      {
       if (linDirObj->buffered_dirent_count > linDirObj->buffered_dirent_offset)
       {
         direntp = linDirObj->buffered_dirents[linDirObj->buffered_dirent_offset++];
         current_filename = direntp->f_name;
       }
       else
         return -1;
      }
      else
#elif (defined(READDIR_BUFFERING))
      if (linDirObj->gnstyle == GNSTYLE_WILD || linDirObj->gnstyle == GNSTYLE_MATCH)
      {
        if (linDirObj->readdir_bpos >= linDirObj->readdir_nread)
        {
          linDirObj->readdir_nread=0;
          if (!linDirObj->readdir_eof)
            refresh_readdir_buffers(linDirObj);
          if (linDirObj->readdir_nread==0)
            return -1;
        }
        {
          struct linux_dirent *d = (struct linux_dirent *) (linDirObj->readdir_buf + linDirObj->readdir_bpos);
          current_filename = d->d_name;
          if (d->d_reclen == 0)
            return -1;
          linDirObj->readdir_bpos += d->d_reclen;
//RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, ": doReadirAndStat pos:%d name: : %s\n",linDirObj->readdir_bpos,current_filename);
        }
      }
      else
#elif (defined(READAHEAD_BUFFERING))
      if (linDirObj->gnstyle == GNSTYLE_WILD)
      {
         if (linDirObj->output_page_count > linDirObj->output_page_offset)
         {
           currdirent = *linDirObj->buffered_dirents[linDirObj->output_page][linDirObj->output_page_offset];
           direntp = &currdirent;
           current_filename = direntp->f_name;
           linDirObj->output_page_offset += 1;
           if (linDirObj->output_page_count == linDirObj->output_page_offset)
           {
             linDirObj->output_page = linDirObj->output_page?0:1;
             linDirObj->input_page = linDirObj->input_page?0:1;
             linDirObj->output_page_offset = 0;
             linDirObj->output_page_count = linDirObj->input_page_count;
             linDirObj->input_page_count = 0;
             if (!linDirObj->at_eof)
                refresh_read_ahead_buffers(linDirObj);
           }
         }
         else
           return -1;
      }
      else
#else // not (defined(TEST_BUFFERING)||defined(READAHEAD_BUFFERING))
      {
        direntp = readdir(linDirObj->dirreadObj);
#ifdef COUNT_DIRENTS_AT_OPEN
        if (direntp)
          linDirObj->dirent_count_used += 1;
        else
        {
          if (linDirObj->dirent_count_total && linDirObj->dirent_count_used < linDirObj->dirent_count_total)
          {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG:\n");
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG:\n");
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: rewind used:%d of total %d\n",linDirObj->dirent_count_used,linDirObj->dirent_count_total);
            closedir(linDirObj->dirreadObj);
            linDirObj->dirreadObj = opendir(linDirObj->dirmatchBaseCopy);
            if (linDirObj->dirreadObj)
              direntp = readdir(linDirObj->dirreadObj);
            if (direntp)
            {
              RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: rewind reopen and read okay\n");
            }
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG:\n");
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG:\n");
          }
        }
#endif
        if (direntp)
          current_filename = direntp->d_name;
      }
#endif
      if (!current_filename)
        return -1;
      if (linDirObj->gnstyle == GNSTYLE_WILD)
      {
        // Skip inline dot and dot dot in GNSTYLE_WILD mode
        if (check_if_dot(current_filename) || check_if_dot_dot(current_filename))
          ;
        else
          matched_filename = current_filename;
      }
      else
      {
        if (strncasecmp(current_filename,linDirObj->dirmatchPattern,SMB_MAX_NAME_SIZE) == 0)
        {
          matched_filename = current_filename;
        }
      }
      if (matched_filename)
      {
        if (strlen(matched_filename) + linDirObj->dirmatchBaseEnd >= SMB_MAX_NAME_SIZE)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: stat path too long base: %s\nfilename: %s\n",linDirObj->dirmatchBase,matched_filename);
            return -1;
        }
        // Put the filename after the last slash in base and stat
       //    strncpy(linDirObj->dirmatchCurrent,matched_filename,SMB_MAX_NAME_SIZE);
        strcpy(linDirObj->dirmatchCurrent,matched_filename);
        strcpy(linDirObj->dirmatchBase+linDirObj->dirmatchBaseEnd,matched_filename);
       //    strncpy(linDirObj->dirmatchBase+linDirObj->dirmatchBaseEnd,matched_filename,SMB_MAX_NAME_SIZE);
        if (stat (linDirObj->dirmatchBase, &linDirObj->statdata) == -1)
        {
           RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: skip stat failed filename: %s\n",linDirObj->dirmatchBase,matched_filename);
//           stat (linDirObj->dirmatchBase, &linDirObj->statdata);
           matched_filename = 0;
//           return (-1);
        }
      }
    } while (!matched_filename);
    if (!matched_filename)
    {
        return -1;
    }
    return (0);
}


static void doFreeDirReadobj(FSOBJ *linDirObj)
{
#ifdef READDIR_BUFFERING
  if ((linDirObj->gnstyle == GNSTYLE_WILD || linDirObj->gnstyle == GNSTYLE_MATCH))
  {
    close(linDirObj->readdir_fd);
  }
#else
  if ((linDirObj->gnstyle == GNSTYLE_WILD || linDirObj->gnstyle == GNSTYLE_MATCH) && linDirObj->dirreadObj)
  {
//    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: GDONE Closedir on : %X\n",linDirObj);
    closedir(linDirObj->dirreadObj);

#ifdef TEST_BUFFERING
    if (linDirObj->gnstyle == GNSTYLE_WILD)
      free_buffered_entries(linDirObj->buffered_dirents);
#endif
#ifdef READAHEAD_BUFFERING
    if (linDirObj->gnstyle == GNSTYLE_WILD)
    {
      free_read_ahead_buffered_entries(linDirObj,0);
      free_read_ahead_buffered_entries(linDirObj,1);
    }
#endif
  }
#endif
  free (linDirObj);
}


#ifdef READDIR_BUFFERING
static void  refresh_readdir_buffers(FSOBJ *linDirObj)
{
  if (linDirObj->readdir_eof==0)
  {
    int nread;
    int n_to_read = READDIR_BUF_SIZE;
    linDirObj->readdir_bpos = 0;
    linDirObj->readdir_nread = 0;
    while (n_to_read > 1024 && !linDirObj->readdir_eof)
    {
      nread = syscall(SYS_getdents64, linDirObj->readdir_fd, linDirObj->readdir_buf+linDirObj->readdir_nread, 1024);
//      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: inner_readdir: n==:%d max:%d\n",nread,n_to_read);
      if (nread == -1)
      { // error but fake done
        nread = 0;
      }
      linDirObj->readdir_nread += nread;
      n_to_read -= nread;
      if (nread == 0)
      {
        linDirObj->readdir_eof = 1;
      }
    }
  }
  else
   linDirObj->readdir_nread = 0;
//   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: out_readdir: n==:%d\n", linDirObj->readdir_nread);
}
#endif

#ifdef READAHEAD_BUFFERING
static void  free_read_ahead_buffered_entries(FSOBJ *linDirObj,int output_page)
{
int output_page_offset;
     for (output_page_offset=0; output_page_offset<READAHEAD_SIZE;output_page_offset++)
     {
      if (linDirObj->buffered_dirents[output_page][output_page_offset])
        free(linDirObj->buffered_dirents[output_page][output_page_offset]);
      linDirObj->buffered_dirents[output_page][output_page_offset]=0;
     }
}


static void  refresh_read_ahead_buffers(FSOBJ *linDirObj)
{
   linDirObj->input_page_count = 0;
   free_read_ahead_buffered_entries(linDirObj,linDirObj->input_page);
   while (linDirObj->at_eof==0 && linDirObj->input_page_count <  READAHEAD_SIZE)
   {
      struct dirent *direntp = readdir(linDirObj->dirreadObj);
      if (!direntp)
      {
        linDirObj->at_eof             = 1;
        break;
      }
      else if (check_if_dot(direntp->d_name))
       ;
      else if (check_if_dot_dot(direntp->d_name))
       ;
      else
      {
       linDirObj->buffered_dirents[linDirObj->input_page][linDirObj->input_page_count] = malloc(sizeof(struct dirent));
       *linDirObj->buffered_dirents[linDirObj->input_page][linDirObj->input_page_count] = *direntp;
       linDirObj->input_page_count += 1;
      }
   }
}
#endif





#ifdef TEST_BUFFERING
static void  free_buffered_entries(struct dirent **buffered_dirents)
{
  while(*buffered_dirents)
  {
     free(*buffered_dirents++);
  }
}
static int  buffer_entries(char *dirBase, struct dirent **buffered_dirents)
{
struct dirent *direntp;
int count = 0;
DIR   *dirreadObj;                        // handle from opendir() if not gnstyle != GNSTYLE_GLOB

  *buffered_dirents = 0;
  dirreadObj = opendir(dirBase);
  if (!dirreadObj)
     return (-1);
  while (1)
  {
    direntp = readdir(dirreadObj);
    if (!direntp)
      break;
    if (check_if_dot(direntp->d_name))
     ;
    else if (check_if_dot_dot(direntp->d_name))
     ;
    else
    {
     buffered_dirents[count] = malloc(sizeof(struct dirent));
     *buffered_dirents[count] = *direntp;
     count++;
     buffered_dirents[count] = 0;
    }
  }
  closedir(dirreadObj);
  return count;

}
#endif

// Populate dot and dot dot and return 0 or return -1
static int retrieve_dot_entries(FSOBJ *linDirObj, struct stat *dot_statdata, struct stat *dot_dot_statdata)
{
struct dirent *direntp;
struct stat *statdata=0;
char full_name[SMB_MAX_NAME_SIZE];
int stat_dot = 0;
int stat_dot_dot = 0;
int counting_entries = 0;
int r = -1;
char *dirBase = linDirObj->dirmatchBase;
DIR   *dirreadObj;                        // handle from opendir() if not gnstyle != GNSTYLE_GLOB
#ifdef COUNT_DIRENTS_AT_OPEN
    linDirObj->dirent_count_total = 0;
    linDirObj->dirent_count_used = 0;
    counting_entries = 1;
    strcpy(linDirObj->dirmatchBaseCopy,dirBase);
#endif

  dirreadObj = opendir(dirBase);
  if (!dirreadObj)
     return (-1);
  strcpy(full_name,dirBase);
  while (counting_entries || !(stat_dot && stat_dot_dot))
  {
    direntp = readdir(dirreadObj);
    if (!direntp)
      break;
#ifdef COUNT_DIRENTS_AT_OPEN  // Doesn't completely fix it
    linDirObj->dirent_count_total += 1;
#endif

    if (check_if_dot(direntp->d_name))
    {
      stat_dot = 1;
      statdata = dot_statdata;
      strcat(full_name,"/.");
    }
    else if (check_if_dot_dot(direntp->d_name))
    {
      stat_dot_dot = 1;
      statdata = dot_dot_statdata;
      strcat(full_name,"/..");
    }
    else
    {
     continue;
    }
    if (stat (full_name, statdata) == -1)
      break;
  }
  if (stat_dot && stat_dot_dot)
    r = 0;
  closedir(dirreadObj);
  return r;
}

// Special case insensitive gfiirst command for smb server.
// If there is a wildcard after the final slash, then all non wildcard characters in that final section are globbed case insensitive.
int rtp_file_gfirst_smb(void ** dirobj, char * name)
{
FSOBJ *linDirObj;
int result;
int hung_up = 512;
char escaped_name[SMB_MAX_NAME_SIZE*2];
int gnstyle;

    *dirobj = (void*) 0;

    // Try a little precaution, make sure the string is <=512 bytes and null termintate.
    if (strnlen(name, SMB_MAX_NAME_SIZE) == SMB_MAX_NAME_SIZE)
      return -1;
    int i,j;
    j=0;

    // Use GLOB with embedded *'s or ?'s otherwise use readdir with either a true match or match all
    if (0)
      gnstyle = GNSTYLE_GLOB;
    else if (strstr(name, "?"))
      gnstyle = GNSTYLE_GLOB;
    else
    {
      char *p=strstr(name, "*");
      if (p && *(p+1) == 0)   gnstyle = GNSTYLE_WILD;
      else if (p)
        gnstyle = GNSTYLE_GLOB;
      else
        gnstyle = GNSTYLE_MATCH;
    }

    escaped_name[0]= 0;
    for (i = 0; i < SMB_MAX_NAME_SIZE; i++)
    {
        if (name[i] == 0)
          break;
        if (name[i] == '\\')
           escaped_name[j++]= '/';
        else
        {
         if (gnstyle == GNSTYLE_GLOB && (name[i] == '[' || name[i] == ']'))
           escaped_name[j++]= '\\';
          escaped_name[j++]= name[i];
        }
        escaped_name[j]= 0;
    }
    name = escaped_name;

    linDirObj = (FSOBJ*) malloc(sizeof(FSOBJ));
    memset(linDirObj, 0, sizeof(FSOBJ));
    linDirObj->gnstyle = gnstyle;


    char *slash = 0;
    char *nextslash=strstr(name, "/");
    while (nextslash && hung_up!=0)
    {
      slash = nextslash;
      nextslash = strstr(slash+1, "/");
      hung_up--;
    }
    if (hung_up==0) return -1;

    if (linDirObj->gnstyle != GNSTYLE_GLOB)
    {
      if (!slash)
      {
       return (-1);
      }
      char *string_after_slash;
      string_after_slash = slash + 1;
      if (slash > name && *(slash-1)=='/')
        slash-=1;
      memcpy(linDirObj->dirmatchBase,name,(slash-name));
      linDirObj->dirmatchBase[(slash-name)]=0;

      // Remember . and .., we will put them in fron and ignore them if we see them again
      linDirObj->dot_count = 0;
      if (gnstyle == GNSTYLE_WILD)
      {
         if (retrieve_dot_entries(linDirObj, &linDirObj->dot_statdata, &linDirObj->dot_dot_statdata)==0)
         {
            linDirObj->dot_count = 2;
         }
#ifdef TEST_BUFFERING
         linDirObj->buffered_dirent_count =
            buffer_entries(linDirObj->dirmatchBase,linDirObj->buffered_dirents);
         linDirObj->buffered_dirent_offset = 0;
#endif
      }
      else
      {
        ; // RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "DIAG: SMB_GFIRST MATCH on : %X\n",linDirObj);
      }

#ifdef READDIR_BUFFERING
      if (gnstyle == GNSTYLE_WILD || gnstyle == GNSTYLE_MATCH)
      {
        linDirObj->readdir_fd = open(linDirObj->dirmatchBase, O_RDONLY | O_DIRECTORY);
        if (linDirObj->readdir_fd  == -1)
          return (-1);
        linDirObj->readdir_eof = 0;
//        linDirObj->char readdir_buf[READDIR_BUF_SIZE];
        refresh_readdir_buffers(linDirObj);
      }
      else
#endif
      {

        linDirObj->dirreadObj = opendir(linDirObj->dirmatchBase);
        if (!linDirObj->dirreadObj)
        {
         return (-1);
        }
      }
#ifdef READAHEAD_BUFFERING
      if (gnstyle == GNSTYLE_WILD)
      {
         memset(linDirObj->buffered_dirents, 0, sizeof(linDirObj->buffered_dirents));
         linDirObj->input_page         = 0;
         linDirObj->input_page_count   = 0;
         linDirObj->at_eof             = 0;
         refresh_read_ahead_buffers(linDirObj);
         linDirObj->output_page_count  = linDirObj->input_page_count;
         linDirObj->output_page_offset = 0;
         linDirObj->output_page        = 0;
         linDirObj->input_page_count   = 0;
         linDirObj->input_page         = 1;
         if (!linDirObj->at_eof)
         {
           refresh_read_ahead_buffers(linDirObj);
         }
      }
#endif
      linDirObj->dirmatchBase[(slash-name)]='/';
      linDirObj->dirmatchBase[(slash-name)+1]=0;
      linDirObj->dirmatchBaseEnd = (slash-name)+1;
      int r = 0;

      if (linDirObj->gnstyle == GNSTYLE_MATCH)
        strcpy(linDirObj->dirmatchPattern,string_after_slash);
      if (gnstyle == GNSTYLE_WILD && linDirObj->dot_count==2)
      {
          linDirObj->statdata = linDirObj->dot_statdata;
          linDirObj->dot_count = 1;
          strcpy(linDirObj->dirmatchCurrent,".");
          r = 0;
      }
      else
        r = doReadirAndStat(linDirObj);
      if (r < 0)
      {
         doFreeDirReadobj(linDirObj);
         return -1;
      }
      else
      {
        linDirObj->glob_data_valid = 1;
        *dirobj = (void*) linDirObj;
        return 0;
      }
    }

    // Fall through for glob style
    if (!slash)   // If no / check if the base contains a wildcard
       slash = name;
    if (slash && (strstr(slash, "*") || strstr(slash, "?")))
    {
       int i;
       char *bracified_name = malloc(strlen(name)+1 + strlen(slash)*5);
       size_t l;
       if (slash == name)
           l=0;
       else
       {
           l = (size_t) (slash-name); // up to but not including the brace
           memcpy(bracified_name, name, l);
       }
       bracified_name[l] = 0;

       for (i=0; slash[i] && hung_up>0;i++,hung_up--)
       {
         if (slash[i]>='a'&&slash[i]<='z')
         {
           bracify(&bracified_name[l],slash[i]);
           l += 5;
         }
         else if (slash[i]>='A'&&slash[i]<='Z')
         {
           bracify(&bracified_name[l],(char)rtp_tolower((int)slash[i]));
           l += 5;
         }
         else
         {
           bracified_name[l] = slash[i];
           bracified_name[l+1] = 0;
           l+= 1;
         }
       }
       if (hung_up==0) return -1;
       result = glob((const char *) bracified_name, GLOB_BRACE|GLOB_PERIOD, NULL, &(linDirObj->globdata));
       free(bracified_name);
    }
    else
    {
        result = glob((const char *) name, GLOB_PERIOD, NULL, &(linDirObj->globdata));
    }
    if (result != 0)
    {
        free (linDirObj);
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_gfirst: error returned ");
        RTP_DEBUG_OUTPUT_INT(result);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
         return (-1);
    }

    linDirObj->currentPath = 0;
    if (stat (linDirObj->globdata.gl_pathv[linDirObj->currentPath], &linDirObj->statdata) == -1)
    {
        globfree(&linDirObj->globdata);
        free (linDirObj);
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_gfirst: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    linDirObj->glob_data_valid = 1;
    *dirobj = (void*) linDirObj;
    return (0);
}



/*----------------------------------------------------------------------*
                             rtp_file_gnext
 *----------------------------------------------------------------------*/
int rtp_file_gnext (void * dirobj)
{
    int r;
    if (!dirobj)
      return -1;
FSOBJ *linDirObj = (FSOBJ *) dirobj;
    if (((FSOBJ *)dirobj)->gnstyle != GNSTYLE_GLOB)
    {
      if (((FSOBJ *)dirobj)->gnstyle == GNSTYLE_WILD && linDirObj->dot_count)
      {
          linDirObj->statdata = linDirObj->dot_dot_statdata;
          linDirObj->dot_count = 0;
          strcpy(linDirObj->dirmatchCurrent,"..");
          r = 0;
      }
      else
      {
        r = doReadirAndStat((FSOBJ *)dirobj);
      }
      return r;
    }
    // else GLOB

do
{
    ((FSOBJ *)dirobj)->currentPath++;
    if (((FSOBJ *)dirobj)->currentPath >= (int)((FSOBJ *)dirobj)->globdata.gl_pathc)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_gnext: error no more files.\n");
#endif
        return (-1);
    }

    if (stat (((FSOBJ *)dirobj)->globdata.gl_pathv[((FSOBJ *)dirobj)->currentPath], &((FSOBJ *)dirobj)->statdata) == -1)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("Ignoring rtp_file_gnext: error returned ");
        RTP_DEBUG_OUTPUT_INT(errno);
        RTP_DEBUG_OUTPUT_STR(".\n");
#endif
        return (-1);
    }
    else
    {
       break;
    }
} while (1);
    return (0);
}


/*----------------------------------------------------------------------*
                             rtp_file_gdone
 *----------------------------------------------------------------------*/
void rtp_file_gdone (void * dirobj)
{
    if (((FSOBJ *)dirobj)->gnstyle == GNSTYLE_GLOB)
    {
       if (((FSOBJ *)dirobj)->glob_data_valid)
       {
         globfree(&((FSOBJ *)dirobj)->globdata);
         ((FSOBJ *)dirobj)->glob_data_valid=0;
       }
	   free(dirobj);
    }
    else
    {
       doFreeDirReadobj((FSOBJ *)dirobj);
    }
}



void rtp_file_get_unique_id(void * dirobj, unsigned char *unique_fileid)
{
    memset (unique_fileid,0,8);
    if (!dirobj ||
       ( ((FSOBJ *)dirobj)->gnstyle == GNSTYLE_GLOB &&
         ((FSOBJ *)dirobj)->currentPath >= (int)((FSOBJ *)dirobj)->globdata.gl_pathc )
       )
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_get_unique_id: error invalid dirobj.\n");
#endif
    }
    else
    {

      memcpy (unique_fileid,&((FSOBJ *)dirobj)->statdata.st_ino,sizeof(((FSOBJ *)dirobj)->statdata.st_ino));
    }

}

/*----------------------------------------------------------------------*
                            rtp_file_get_size
 *----------------------------------------------------------------------*/
int rtp_file_get_size64 (void * dirobj, unsigned long * size_hi,unsigned long * size)
{
    if (!dirobj ||
       ( ((FSOBJ *)dirobj)->gnstyle == GNSTYLE_GLOB &&
         ((FSOBJ *)dirobj)->currentPath >= (int)((FSOBJ *)dirobj)->globdata.gl_pathc )
       )
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_get_size: error invalid dirobj.\n");
#endif
        return (-1);
    }

	if (size)
	{
		*size = (unsigned long) ((((FSOBJ *)dirobj)->statdata.st_size)&0xffffffff);
	}
	if (size_hi)
    {
		*size_hi = (unsigned long) ((((FSOBJ *)dirobj)->statdata.st_size>>32)&0xffffffff);
    }
#ifdef RTP_DEBUG
	else
	{
        RTP_DEBUG_OUTPUT_STR("rtp_file_get_size: error no storage location.\n");
	}
#endif
    return (0);

}


int rtp_file_get_size (void * dirobj, unsigned long * size)
{
  return rtp_file_get_size64 (dirobj, 0, size);
}


/*----------------------------------------------------------------------*
                           rtp_file_get_attrib
 *----------------------------------------------------------------------*/
int rtp_file_get_attrib (void * dirobj, unsigned char * attributes)
{
    int readable, writable;

    if (!dirobj ||
       ( ((FSOBJ *)dirobj)->gnstyle == GNSTYLE_GLOB &&
         ((FSOBJ *)dirobj)->currentPath >= (int)((FSOBJ *)dirobj)->globdata.gl_pathc )
       )
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_get_size: error invalid dirobj.\n");
#endif
        return (-1);
    }

	*attributes  = S_ISDIR (((FSOBJ *)dirobj)->statdata.st_mode) ? RTP_FILE_ATTRIB_ISDIR : 0;
    // This wasn't right, causing problems
//    *attributes  = *attributes | S_ISBLK (((FSOBJ *)dirobj)->statdata.st_mode) ? RTP_FILE_ATTRIB_ISVOL : 0;

    readable = ((FSOBJ *)dirobj)->statdata.st_mode & S_IRUSR;
    writable = ((FSOBJ *)dirobj)->statdata.st_mode & S_IWUSR;

    if (readable && writable)
        *attributes |= RTP_FILE_ATTRIB_RDWR;
    else if (readable)
        *attributes |= RTP_FILE_ATTRIB_RDONLY;
    else if (writable)
        *attributes |= RTP_FILE_ATTRIB_WRONLY;

    return (0);
}


/*----------------------------------------------------------------------*
                           rtp_file_get_name
 *----------------------------------------------------------------------*/
int rtp_file_get_name (void * dirobj, char * name, int size)
{
unsigned int sizelimit;
const char *end;
    if (!dirobj)
      return (-1);

    if ( ((FSOBJ *)dirobj)->gnstyle != GNSTYLE_GLOB)
    {
      strcpy(name, ((FSOBJ *)dirobj)->dirmatchCurrent);
//      strncpy(name, ((FSOBJ *)dirobj)->dirmatchCurrent,size);
      return (0);
    }

    if (((FSOBJ *)dirobj)->currentPath >= (int)((FSOBJ *)dirobj)->globdata.gl_pathc )
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_get_name: error invalid dirobj.\n");
#endif
        return (-1);
    }

    if (size < 1)
    {
        return (0);
    }

    end = strrchr(((FSOBJ *)dirobj)->globdata.gl_pathv[((FSOBJ *)dirobj)->currentPath], '/');
    if (end)
    {
        end++;
        sizelimit = strlen(end);
        if (sizelimit > (unsigned int)(size - 1))
        {
            sizelimit = (unsigned int)size - 1;
        }
        strncpy(name, end, sizelimit);
    	name[sizelimit] = '\0';
    }
    else
        name[0] = '\0';
    return (0);
}



/*----------------------------------------------------------------------*
                           rtp_file_get_time
 *----------------------------------------------------------------------*/
int rtp_file_get_time (void * dirobj, RTP_DATE * adate, RTP_DATE * wdate, RTP_DATE * cdate, RTP_DATE * hdate)
{
    if (!dirobj ||
       ( ((FSOBJ *)dirobj)->gnstyle == GNSTYLE_GLOB &&
         ((FSOBJ *)dirobj)->currentPath >= (int)((FSOBJ *)dirobj)->globdata.gl_pathc )
       )
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("rtp_file_get_name: error invalid dirobj.\n");
#endif
        return (-1);
    }

    if (adate)
    {
        if (_rtp_lindate_to_date(&((FSOBJ *)dirobj)->statdata.st_atime, adate) != 0)
        {
            return (-1);
        }
    }
    if (wdate)
    {
        if (_rtp_lindate_to_date(&((FSOBJ *)dirobj)->statdata.st_mtime, wdate) != 0)
        {
            return (-1);
        }
    }
    if (cdate)
    {
        /* ----------------------------------- */
        /*  Not supported by the Linux fs.     */
        /*  Use write date to avoid bogus      */
        /*  data.                              */
        /* ----------------------------------- */
        if (_rtp_lindate_to_date(&((FSOBJ *)dirobj)->statdata.st_mtime, cdate) != 0)
        {
            return (-1);
        }
    }
    if (hdate)
    {
        if (_rtp_lindate_to_date(&((FSOBJ *)dirobj)->statdata.st_ctime, hdate) != 0)
        {
            return (-1);
        }
    }
    return (0);
}

/************************************************************************
* Utility Function Bodies
************************************************************************/

/*----------------------------------------------------------------------
----------------------------------------------------------------------*/
static int _rtp_lindate_to_date (time_t * lindate, RTP_DATE * rtpdate)
{
struct tm * ptime;
time_t utclindate = *lindate;
    // Subtract the tzoffset from the linux epoch date and convert to local time
    // Similar to how make_dos_date() works in smaba
    utclindate -= timezone;
    ptime = gmtime((const time_t *)&utclindate);
#if(0)
    // this is basically the same thsing.
    ptime = localtime((const time_t *)lindate);
#endif
    // Fall through using localtime((const time_t *)lindate);
    if (!ptime)
    {
#ifdef RTP_DEBUG
        RTP_DEBUG_OUTPUT_STR("_rtp_lindate_to_date: error returned.\n");
#endif
        return (-1);
    }

    (*rtpdate).year   = (unsigned int) ptime->tm_year + 1900;
    (*rtpdate).month  = (unsigned int) ptime->tm_mon + 1;
    (*rtpdate).day    = (unsigned int) ptime->tm_mday;
    (*rtpdate).hour   = (unsigned int) ptime->tm_hour;
    (*rtpdate).minute = (unsigned int) ptime->tm_min;
    (*rtpdate).second = (unsigned int) ptime->tm_sec;
	(*rtpdate).msec   = 0;

    (*rtpdate).dlsTime  = (unsigned int) ptime->tm_isdst;    /* always 0 for gmtime */
    (*rtpdate).tzOffset = timezone;

    return (0);
}
