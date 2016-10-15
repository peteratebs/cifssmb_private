//
// SMBDEBUG.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2004
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Functions for Outputing unicode/Ascii debug information

#include "smbdebug.h"
#include "rtpdebug.h"

void rtsmb_dump_bytes(char *prompt, void *_pbytes, int length, int format)
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

#if (0)

char cnv_msg[100];
void _rtsmb_debug_output_str(void* msg, int type)
{

	switch (type)
	{
		case RTSMB_DEBUG_TYPE_ASCII:
        	rtp_printf("%s", msg);
			break;

		case RTSMB_DEBUG_TYPE_UNICODE:
		case RTSMB_DEBUG_TYPE_SYS_DEFINED:
			#if (INCLUDE_RTSMB_UNICODE)
				rtsmb_util_unicode_to_ascii (msg, (PFCHAR) cnv_msg, CFG_RTSMB_USER_CODEPAGE);
                rtp_printf("%s", cnv_msg);
			#else
                rtp_printf("%s", msg);
			#endif
			break;
	}
}

void _rtsmb_debug_output_int(long val)
{
    rtp_printf("%d", val);
}
void _rtsmb_debug_output_dint(unsigned long val)
{
    rtp_printf("%lu", val);
}
#endif
