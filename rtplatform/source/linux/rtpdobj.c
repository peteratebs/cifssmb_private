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
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>

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
} FSOBJ;


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



static int doReadirAndStat(FSOBJ *linDirObj)
{
struct dirent *direntp;
char *matched_filename = 0;

    do
    {
      direntp = readdir(linDirObj->dirreadObj);
      if (!direntp)
        return -1;
      if (linDirObj->gnstyle == GNSTYLE_WILD)
      {
        matched_filename = direntp->d_name;
      }
      else
      {
        if (strncasecmp(direntp->d_name,linDirObj->dirmatchPattern,SMB_MAX_NAME_SIZE) == 0)
        {
          matched_filename = direntp->d_name;
        }
      }
    } while (!matched_filename);
    if (!matched_filename)
    {
        return -1;
    }
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
       return (-1);
    }
    return (0);
}

static void doFreeDirReadobj(FSOBJ *linDirObj)
{
  if ((linDirObj->gnstyle == GNSTYLE_WILD || linDirObj->gnstyle == GNSTYLE_MATCH) && linDirObj->dirreadObj)
    closedir(linDirObj->dirreadObj);
  free (linDirObj);
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
      linDirObj->dirreadObj = opendir(linDirObj->dirmatchBase);
      if (!linDirObj->dirreadObj)
      {
       return (-1);
      }
      linDirObj->dirmatchBase[(slash-name)]='/';
      linDirObj->dirmatchBase[(slash-name)+1]=0;
      linDirObj->dirmatchBaseEnd = (slash-name)+1;

      if (linDirObj->gnstyle == GNSTYLE_MATCH)
        strcpy(linDirObj->dirmatchPattern,string_after_slash);
      int r = doReadirAndStat(linDirObj);
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
    if (!dirobj)
      return -1;
FSOBJ *linDirObj = (FSOBJ *) dirobj;
    if (((FSOBJ *)dirobj)->gnstyle != GNSTYLE_GLOB)
    {
      int r = doReadirAndStat((FSOBJ *)dirobj);
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
       doFreeDirReadobj((FSOBJ *)dirobj);
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
