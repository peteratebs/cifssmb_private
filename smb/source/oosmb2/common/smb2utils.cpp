//
// smb2util.cpp -
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

#include "smb2commonincludes.hpp"
#include "rtpdate.h"
#include "rtpfile.h"

// We need to port the whole smbutil file.


#define SECS_IN_A_DAY           86400
#define DAYS_IN_FOUR_YEARS      1461

/* This records how many days are in each month. */
static const int month_days [12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

#define SECS_BETWEEN_EPOCHS         0xB6109100
#define LOW_100NS_BETWEEN_EPOCHS    0xD53E8000
#define HIGH_100NS_BETWEEN_EPOCHS   0x019DB1DE
#define SECS_TO_100NS               10000000L     /* 10^7 */


word rtsmb_util_rtsmb_to_smb_attributes (byte rtsmb_attributes)
{
  word smb_attributes = 0;

  if (rtsmb_attributes & RTP_FILE_ATTRIB_ISDIR)   smb_attributes |= SMB_FA_D;
  if (rtsmb_attributes & RTP_FILE_ATTRIB_ISVOL)   smb_attributes |= SMB_FA_V;
  if (rtsmb_attributes & RTP_FILE_ATTRIB_RDONLY)  smb_attributes |= SMB_FA_RO;
  if (rtsmb_attributes & RTP_FILE_ATTRIB_HIDDEN)  smb_attributes |= SMB_FA_H;
  if (rtsmb_attributes & RTP_FILE_ATTRIB_SYSTEM)  smb_attributes |= SMB_FA_S;
  if (rtsmb_attributes & RTP_FILE_ATTRIB_ARCHIVE) smb_attributes |= SMB_FA_A;
  if (smb_attributes == 0)                        smb_attributes = SMB_FA_N;

return smb_attributes;
}


RTP_DATE rtsmb_util_time_unix_to_rtp_date (dword unix_time)
{
  RTP_DATE date;
  dword day_time;
  dword tmp;

  int i;
  bool leap = false;

  day_time = unix_time % SECS_IN_A_DAY;

  date.year = 0;
  date.msec = 0;
  date.dlsTime = 0;
  date.tzOffset = 0;

  date.hour = (day_time / 3600) - 4; //hours
  date.minute = ((((day_time / 60) % 60))); //minutes
  date.second = (((day_time % 60))); //seconds, might be (day_time %60) / 2


  /* Now, we are only concerned with the time span 1980 - 2099.  So, the only century year
     is also a 400-year.  Thus, every four years in this span there is one leap year.  Thus,
     a 4-year span has a constant amount of days. */
  day_time = unix_time / SECS_IN_A_DAY;

  /* adjust unix time to 1980-based time */
  day_time -= (DAYS_IN_FOUR_YEARS * 2 + 730);


  tmp = day_time / DAYS_IN_FOUR_YEARS;
  tmp *= 4;
  day_time = day_time % DAYS_IN_FOUR_YEARS;

  if (day_time < 366)
  {
    leap = true;
    tmp += 0;
  }
  else if (day_time < 731)
  {
    day_time -= 366;
    tmp += 1;
  }
  else if (day_time < 1096)
  {
    day_time -= 731;
    tmp += 2;
  }
  else
  {
    day_time -= 1096;
    tmp += 3;
  }

  /* year */
  date.year = (tmp);
  date.year += 1980;

  //deal with month
  for (i = 0, tmp = 0; i < 12; i++)
  {
    tmp += (dword)month_days [i];
    if (leap && i == 1)
    {
      tmp ++;
    }

    if (day_time < tmp)
    {
      /* month */
      date.month = (unsigned)(i + 1);
      break;
    }
  }

  tmp -= (dword)month_days [i];
  if (leap && i == 1)
  {
    tmp --;
  }

  /* day */
  date.day = ((day_time - tmp + 1));

  return date;
}

static void rtmsb_util_time_put_digit_at_offset (int digit, int offset, TIME_MS *ms_time)
{
dword *t;
dword temp;
  t = offset < 8 ? &ms_time->low_time : (offset -= 8, &ms_time->high_time);
  temp = (*t) & (0xFFFFFFFF << ((offset + 1) * 4));
  temp |= (*t) & (0xFFFFFFFF >> ((8 - offset) * 4));
  temp |= (dword)((digit & 0xF) << (offset * 4));
  *t = temp;
}
static dword rtmsb_util_time_get_dividend (int prior, int offset, TIME_MS *ms_time)
{
  dword *t;
  dword temp;
  t = offset < 8 ? &ms_time->low_time : (offset -= 8, &ms_time->high_time);
  temp = (dword)prior << 4;
  temp |=  (  ((*t) & (dword)(0xF << (offset * 4)))  >> (offset * 4));
  return temp;
}

dword rtsmb_util_time_ms_to_unix (TIME_MS ms_time)
{
int offset;
int remainder, window;
TIME_MS answer;

  answer.low_time = 0;
  answer.high_time = 0;

  /* get rid of uppermost bit, since that is the sign bit */
  ms_time.high_time = ms_time.high_time & 0x7FFFFFFF;

  for (offset = 14, remainder = 0; offset >= 0; offset --)
  {
    window = (int)rtmsb_util_time_get_dividend (remainder, offset, &ms_time);
    rtmsb_util_time_put_digit_at_offset (window / SECS_TO_100NS, offset, &answer);
    remainder = window % SECS_TO_100NS;
  }

  answer.low_time -= SECS_BETWEEN_EPOCHS;

  return answer.low_time;
}


static TIME_MS rtsmb_util_time_unix_to_ms (dword unix_time)
{
  TIME_MS answer;
  dword tmp1, tmp2, tmp3, tmp4, before;

  answer.low_time = 0;
  answer.high_time = 0;

  tmp1 = ((unix_time & 0x000000FF) >> 0)  * SECS_TO_100NS;
  tmp2 = ((unix_time & 0x0000FF00) >> 8)  * SECS_TO_100NS;
  tmp3 = ((unix_time & 0x00FF0000) >> 16) * SECS_TO_100NS;
  tmp4 = ((unix_time & 0xFF000000) >> 24) * SECS_TO_100NS;

  answer.low_time = tmp1;
  answer.high_time = 0;

  before = answer.low_time;
  answer.low_time += (tmp2 & 0xFFFFFF) << 8;
  answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
  answer.high_time += (tmp2 & 0xFF000000) >> 24;

  before = answer.low_time;
  answer.low_time += (tmp3 & 0xFFFF) << 16;
  answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
  answer.high_time += (tmp3 & 0xFFFF0000) >> 16;

  before = answer.low_time;
  answer.low_time += (tmp4 & 0xFF) << 24;
  answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
  answer.high_time += (tmp4 & 0xFFFFFF00) >> 8;

  /* now we have the right amount of 100-ns intervals */

  /* add the difference in epochs */
  before = answer.low_time;
  answer.low_time += LOW_100NS_BETWEEN_EPOCHS;
  answer.high_time += answer.low_time < before ? 1 : 0; /* did we carry? */
  answer.high_time += HIGH_100NS_BETWEEN_EPOCHS;

  return answer;
}

dword rtsmb_util_time_rtp_date_to_unix (RTP_DATE rtp_date)
{
  dword unix_time;
  bool leap = false;
  unsigned int i;

  unix_time = 0;
  unix_time += (rtp_date.second);  //seconds
  unix_time += (rtp_date.minute) * 60;  //minutes -> seconds
  unix_time += (rtp_date.hour + 4) * 3600;  //hours -> seconds

  unix_time += (rtp_date.day -1) * SECS_IN_A_DAY;

  unix_time += ((rtp_date.year - 1980) / 4) * DAYS_IN_FOUR_YEARS * SECS_IN_A_DAY;

  switch (rtp_date.year % 4)
  {
    case 0:
      leap = true;
      break;
    case 1:
      unix_time += 366 * SECS_IN_A_DAY;
      break;
    case 2:
      unix_time += 731 * SECS_IN_A_DAY;
      break;
    case 3:
      unix_time += 1096 * SECS_IN_A_DAY;
      break;
  }

  for (i = 0; i < rtp_date.month - 1; i++)
  {
    if (leap && i == 1)
    {
      unix_time += SECS_IN_A_DAY;
    }

    unix_time += (dword) (month_days [i] * SECS_IN_A_DAY);
  }

  /* adjust time to 1970-based time */
  unix_time += (DAYS_IN_FOUR_YEARS * 2 + 730) * SECS_IN_A_DAY;

  return unix_time;
}

TIME_MS rtsmb_util_time_rtp_date_to_ms (RTP_DATE rtp_date)
{
  return rtsmb_util_time_unix_to_ms(rtsmb_util_time_rtp_date_to_unix(rtp_date));
}

int rtsmb_util_unicode_strlen(word *str)
{
word l=0;
  while (str[l]) l++;
  return l;
}

ddword rtsmb_util_get_current_filetime(void)
{
RTP_DATE date;
TIME_MS t;
ddword r;
    rtp_get_date (&date);
    t = rtsmb_util_time_rtp_date_to_ms(date);
    r = (ddword)t.high_time<<32|t.low_time;
    return r;
}
void rtsmb_util_ascii_to_unicode (char *ascii_string ,word *unicode_string, size_t w)
{
  dualstringdecl(converted_string);                   //    dualstring user_string;
  *converted_string     =  ascii_string;
  if (w !=  converted_string->utf16_length())
    diag_printf_fn(DIAG_JUNK,"spego::: oops (w != 2*converted_string->utf16_length() w: \n");
  memcpy(unicode_string,converted_string->utf16(), w);
}
void rtsmb_util_unicode_to_ascii (word *unicode_string, char *ascii_string)
{
  dualstringdecl(converted_string);                   //    dualstring user_string;
  *converted_string     =  unicode_string;
  strcpy(ascii_string, converted_string->ascii());
}
/* See RFC4122 */
void rtsmb_util_guid(byte *_pGuid)
{
ddword t;
dword *pdw;
word  *pw;
byte   *pb;
byte node_address[6];
word clock_seq;

static byte lguid[16];
static byte *pGuid=0;

  if (!pGuid)
  {
    pGuid = lguid;
    std::srand(rtsmb_util_get_current_filetime()); // use current time as seed for random generator
    int random_variable = std::rand();
    clock_seq = (word) random_variable;

    rtp_net_get_node_address (node_address);
    pdw = (dword *) pGuid;
    t = rtsmb_util_get_current_filetime();
    *pdw++ = (dword) t;     /* [32] Time low */
    pw = (word *) pdw;                     /* [16] Time hi & version */
    *pw++ = (word) (t>>32) & 0xFFFF;       /* [16] Time mid */
    *pw  = (word) (t>>48) & 0x0FFF;        /* [16] Time hi & version */
    *pw++  |= (1<<12);
    pb  =  (byte *) pw;                     /* [16] clock_seq_hi & reserved */
    *pb =  (byte) ((clock_seq & 0x3F00) >> 8);
    *pb++ |= 0x80;
    memcpy(pb, node_address, sizeof (node_address) );
  }
    memcpy(_pGuid, pGuid, 16);
}

// Diag output funtions not attached to a class
void diag_dump_unicode_fn(smb_diaglevel at_diaglayer,  const char *prompt, void *buffer, int size)
{
  smb_diagnostics d;
  d.set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
  d.diag_dump_unicode(at_diaglayer, prompt, (byte *)buffer, size);
}


// Diag output funtions not attached to a class
void diag_dump_bin_fn(smb_diaglevel at_diaglayer,  const char *prompt, void *buffer, int size)
{
  smb_diagnostics d;
  d.set_diag_level(DIAG_DEBUG); //(DIAG_INFORMATIONAL); // DIAG_DEBUG);
  d.diag_dump_bin(at_diaglayer, prompt, buffer, size);
}

void diag_printf_fn(smb_diaglevel at_diaglayer, const char* fmt...)
{
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    vsprintf (buffer,fmt, args);
    cout << buffer;
}
char *rtsmb_strmalloc(char *str) { char *p = (char *)smb_rtp_malloc(rtp_strlen(str)+1); if (p) strcpy(p, str); return p;}
char *rtsmb_strmalloc_to_unicode(char *str) { char *p = (char *)smb_rtp_malloc(rtp_strlen(str)+1); if (p) strcpy(p, str); return p;}


#include <cerrno>

extern const char *rtsmb_util_errstr(int &util_errno)
{
  util_errno = errno;
  return strerror(util_errno);
//  return rtsmb_strmalloc(strerror(util_errno));
}


#include "rtpprint.h"

void rtsmb_dump_bytes(const char *prompt, void *_pbytes, int length, int format)
{
int i;
int charno = 0;
byte *pbytes = (byte *) _pbytes;
    rtp_printf("%-40s:(%4d) bytes:\n", prompt, length);
    for (i=0; i<length; i++)
      if (format==DUMPBIN)
      {
          rtp_printf("%2.2X ", pbytes[i]);
          if (++charno == 16)
          {
            charno = 0;
            rtp_printf("\n");
          }
      }
      else
      {
        rtp_printf("%c", (char) pbytes[i]);
        if (format==DUMPUNICODE)
          i++;
      }
      rtp_printf("\n===\n");
}

static bool initted=false;
void *alloc_pointers[10000];
size_t alloc_sizes[10000];

static void init_memtracker()
{
  initted=true;
  memset(alloc_pointers, 0,sizeof(alloc_pointers));
  memset(alloc_sizes, 0,sizeof(alloc_sizes));
}
int used_already=0;
void check_track_mem()
{
  for (int i = 0; i < 1000; i++)
  {
    if (alloc_pointers[i] && alloc_pointers[i]!=(void*)&used_already)
    {
      if (  ((byte *)alloc_pointers[i])[alloc_sizes[i]] != 'A')
      {
        rtp_printf("\noverrun at pointer: %X sized: %d \n", alloc_pointers[i], alloc_sizes[i]);
      }
    }
  }
}


static void track_mem(void *b, size_t s)
{
  check_track_mem();
  for (int i = 0; i < 10000; i++)
  {
    if (alloc_pointers[i]==0)
    {
      alloc_pointers[i] = b;
      alloc_sizes[i] = s;
      rtp_printf("\ntrack pointer#:%d at:%X sized: %d\n", i, alloc_pointers[i], alloc_sizes[i]);
      if (s==80)
      {
        rtp_printf("\nYo allocated 80 track pointer#:%d at:%X sized: %d\n", i, alloc_pointers[i], alloc_sizes[i]);
      }
      break;
    }
  }
}
static void untrack_mem(void *b)
{
  check_track_mem();
  for (int i = 0; i < 10000; i++)
  {
    if (alloc_pointers[i]==b)
    {
      rtp_printf("\n untrack pointer#:%d at:%X sized: %d\n", i, alloc_pointers[i], alloc_sizes[i]);
      if (alloc_sizes[i]==80)
      {
        rtp_printf("\nYo free 80 track feeded 80 #:%d at:%X sized: %d\n", i, alloc_pointers[i], alloc_sizes[i]);
      }
//      alloc_pointers[i] = (void *)&used_already;
//      alloc_sizes[i] = 0;
      alloc_pointers[i] = 0;
      alloc_sizes[i] = 0;
      return;
    }
  }
  rtp_printf("untracked lost pointer: %X\n", b);
}

void *smb_rtp_malloc(size_t s)
{
   if (!initted) init_memtracker();
   byte *b = (byte *) rtp_malloc(s+4);
   memcpy(b+s, "ABCD", 4);
   track_mem(b, s);
   return (void *) b;
}
void smb_rtp_free(void *s)
{
  untrack_mem(s);
  rtp_free(s);  // inside smb_rtp_free
}

char *rtsmb_util_string_to_upper (char *cstring)
{
  for (int i = 0; i < 256 && cstring[i]; i++)
    cstring[i]= (char) std::toupper ( (int) cstring[i] );
  return cstring;
}

word *rtsmb_util_string_to_upper (word *cstring)
{
  for (int i = 0; i < 256 && cstring[i]; i++)
  {
    if (cstring[i] >= 'a' && cstring[i] <= 'z')
      cstring[i]=(word) std::toupper ( (int) cstring[i] );
  }
  return cstring;
}

#define CFG_RTSMB_USER_CODEPAGE 0

word *rtsmb_util_malloc_ascii_to_unicode (char *ascii_string, int extra_bytes)
{
word *p;
size_t w;
  w=rtp_strlen(ascii_string)*2+2;
  p=(word *)smb_rtp_malloc(w+extra_bytes);
  rtsmb_util_ascii_to_unicode (ascii_string ,p , w);
  return (p);
}

char *rtsmb_util_malloc_ascii_to_ascii (char *ascii_string)
{
char *p;
size_t w;
  w=rtp_strlen(ascii_string)+1;
  p=(char *)smb_rtp_malloc(w);
  memcpy(p,ascii_string, w);
  return (p);
}


char *rtsmb_util_malloc_fullpath_ascii (char *ascii_path, word *unicode_filename, int extra_bytes)
{
char *p;
  int pathlen         = strlen(ascii_path);
  char *ascii_filename = rtsmb_util_malloc_unicodeto_ascii (unicode_filename);
  int filename_length = strlen(ascii_filename)+1;
  p=(char *)smb_rtp_malloc(pathlen+1+filename_length+extra_bytes);
  strcpy(p, ascii_path);
  strcat(p, "\\");
  strcat(p, ascii_filename);
  smb_rtp_free(ascii_filename);
  return p;
}

char *rtsmb_util_malloc_unicodeto_ascii (word *unicode_string, int extra_bytes)
{
char *p;
int w = rtsmb_util_unicode_strlen(unicode_string)+1;
  p=(char *)smb_rtp_malloc(w+extra_bytes);
  rtsmb_util_unicode_to_ascii(unicode_string,p);
  return (p);
}

char *rtsmb_util_malloc_unicodeto_xxascii (word *unicode_string)
{
char *p;
int w = rtsmb_util_unicode_strlen(unicode_string)+1;
  p=(char *)smb_rtp_malloc(w);
  rtsmb_util_unicode_to_ascii(unicode_string,p);
  return (p);
}

int rtsmb_util_unicode_strnicmp(word * ch1, word * ch2, int n)
{
  /* simplistic version that only case neutralizes ascii stuff.  How to
  better? */
  int i;

  for (i = 0; i < n && ch1[i] && ch2[i]; i++)
  {
    word c1, c2;

    c1 = (word)std::toupper(ch1[i]);
    c2 = (word)std::toupper(ch2[i]);

    if (c1 < c2)
    {
      return -1;
    }
    else if (c1 > c2)
    {
      return 1;
    }
  }
  if (i == n)
  {
    return 0;
  }
  if (!ch1[i] && !ch2[i])
  {
    return 0;
  }
  else if (!ch1[i])
  {
    return -1;
  }
  else if (!ch2[i])
  {
    return 1;
  }
  return 0;
}
