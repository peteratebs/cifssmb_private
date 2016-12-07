#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"
#include "rtpthrd.h"
#include "srvobjectsc.h"
#include "srvcfg.h"

extern volatile int go; /* Variable loop on.. Note: Linux version needs sigkill support to clean up */

RTSMB_STATIC void rtsmb_srv_diag_main (void);

static char *syslogname = "RTSMBS";
static unsigned long level_mask = (SYSLOG_TRACE_LVL|SYSLOG_INFO_LVL|SYSLOG_ERROR_LVL);
void rtsmb_srv_syslog_config(void)
{
    RTP_DEBUG_OPEN_SYSLOG(syslogname, level_mask);
}
void rtsmb_srv_diag_config(void)
{
   prtsmb_srv_ctx->display_login_info    = FALSE;
   prtsmb_srv_ctx->display_config_info    = FALSE;
}


void rtsmb_thread_diag (void *p)
{
  if (!srvobject_bind_diag_socket())
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Error occurred while trying to open diag socket\n");
  }
  else
  {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "diag socket is open\n");
      while (go)
      {
        rtsmb_srv_diag_main();
     }
  }
}

RTSMB_STATIC void rtsmb_srv_diag_main (void)
{
    dword i;
    RTP_SOCKET readList[2];
    int j,len,in_len;

    readList[0] = *srvobject_get_diag_socket();
    len = 1;
    len = rtsmb_netport_select_n_for_read (readList, len, 1000);
    if (len && go)
    {
      srvobject_process_diag_request();
    }
}
