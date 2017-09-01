//
// smb2logon.cpp -
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

#include "smb2clientincludes.hpp"
#include "rtpdate.h"

// We need to port the whole smbutil file.

/* This is a time-since-microsoft-epoch struct.  That means it records
   how many 100-nanoseconds have passed since Jan. 1, 1601. */
typedef struct {
    dword low_time;
    dword high_time;
} TIME;

#define SECS_IN_A_DAY           86400
#define DAYS_IN_FOUR_YEARS      1461

/* This records how many days are in each month. */
static const int month_days [12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

#define SECS_BETWEEN_EPOCHS         0xB6109100
#define LOW_100NS_BETWEEN_EPOCHS    0xD53E8000
#define HIGH_100NS_BETWEEN_EPOCHS   0x019DB1DE
#define SECS_TO_100NS               10000000L     /* 10^7 */

static TIME rtsmb_util_time_unix_to_ms (dword unix_time)
{
	TIME answer;
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

static TIME rtsmb_util_time_rtp_date_to_ms (RTP_DATE rtp_date)
{
	return rtsmb_util_time_unix_to_ms(rtsmb_util_time_rtp_date_to_unix(rtp_date));
}

ddword rtsmb_util_get_current_filetime(void)
{
RTP_DATE date;
TIME t;
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
char *rtsmb_strmalloc(char *str) { char *p = (char *)rtp_malloc(rtp_strlen(str)+1); if (p) strcpy(p, str); return p;}


#include <cerrno>

extern const char *rtsmb_util_errstr(int &util_errno)
{
  util_errno = errno;
  return strerror(util_errno);
//  return rtsmb_strmalloc(strerror(util_errno));
}
extern Smb2Session *getCurrentActiveSession();

NetStatus NetStreamInputBuffer::pull_nbss_frame_checked(const char *arg_command_name, size_t arg_packed_structure_size, dword &bytes_pulled)
{
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2MinimumReply  Smb2MinimumReply;
  NetStatus           r = NetStatusOk;
  dword min_packet_bytes_pulled,more_bytes_pulled;
  size_t min_reply_size = InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2MinimumReply.PackedStructureSize();
  size_t good_reply_size = InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+arg_packed_structure_size;

  bytes_pulled = 0;

  byte *pBase = input_buffer_pointer();
  diag_printf_fn(DIAG_INFORMATIONAL, "XXXXX %s pulling minimum: %d \n", arg_command_name, min_reply_size);
   // Pull enough for the fixed part and then map pointers to input buffer
  r = pull_new_nbss_frame(min_reply_size, min_packet_bytes_pulled);
  if (r != NetStatusOk) return r;
  if (min_packet_bytes_pulled != min_reply_size)
  {
    getCurrentActiveSession()->diag_text_warning("receive_close command failed pulling SMB2 header from the socket");
    return NetStatusDeviceRecvUnderflow;
  }
  // look at the headers for status
  InNbssHeader.bindpointers(pBase);
  InSmb2Header.bindpointers(pBase+InNbssHeader.FixedStructureSize());
  Smb2MinimumReply.bindpointers(pBase+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
  more_bytes_pulled = 0;

  diag_printf_fn(DIAG_INFORMATIONAL, "XXXXX %s status == %0X \n", arg_command_name, InSmb2Header.Status_ChannelSequenceReserved());

  if (InSmb2Header.Status_ChannelSequenceReserved() != SMB2_NT_STATUS_SUCCESS)
  {
    getCurrentActiveSession()->diag_text_warning("receive_close command failed pulling SMB2 header from the socket");
    r = NetStatusServerErrorStatus;
  }
  else
  {
    if (min_packet_bytes_pulled < good_reply_size)
    {
       r = pull_nbss_data(good_reply_size-min_packet_bytes_pulled, more_bytes_pulled);
       if (r != NetStatusOk) return r;
       if (more_bytes_pulled != good_reply_size-min_packet_bytes_pulled)
       {
         getCurrentActiveSession()->diag_text_warning("receive_close command failed pulling CMD header from the socket");
         r = NetStatusDeviceRecvBadLength;
       }
     }
  }

  bytes_pulled = more_bytes_pulled + min_packet_bytes_pulled;
  if (r == NetStatusOk && bytes_pulled != good_reply_size)
  {
     getCurrentActiveSession()->diag_text_warning("receive_close not expected  command bytes_pulled != good_reply_size");
     r = NetStatusDeviceRecvBadLength;
  }

  return r;
}

