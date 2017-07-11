/* EBS SMB Client Application entery point.
    This module initializes TCP networking and then calls an interactive test shell
    that demonstrates SMB client commands

    Note: using a fixed ip address, recompile with
*/
#if defined(_WIN32)||defined(_WIN64)
#define RTSMB_WINDOWS 1
#define RTSMB_LINUX  0
#elif defined(__linux)
#define RTSMB_WINDOWS   0
#define RTSMB_LINUX     1
#else
#error Unsupported OS......
#endif

#define CALL_SHELL 1        /* If 1 call the interactive shell, otherwise call (archane) test routines. */

#if (RTSMB_WINDOWS)
#include <windows.h>
#endif
#include "cliapi.h"
#include "smbutil.h"
#include "rtpnet.h"
#include "rtpprint.h"
#include "clirpc.h"
#include "clsrvsvc.h"


/* Instructions..
    EBS CIFS SMB Client shell and tests

    To build ..
    Select
    CALL_SHELL or
    CALL_TESTS

    Initialize the following variables

        my_ip[]  - The IP address of the machine where the client test is running
        my_mask[] - The network mask for the lan (usually {255, 255, 255, 0} }

        The default configuration is:

            The IP address is: {192,168,1,3};
            The lan mask is {255, 255, 255, 0};


    To run the shell or test..

    If running on Windows - Setting up the client (where the test will be executed)

    Disable SMB and NetBios support on the client machine where the tests will
    be built and executed from:

    To do this select:

        control panel|network connections

        Right click on Active Lan connection

        Properties:

              File and Printer Sharing For Microsoft Network - Un-check this box
              Click on  Internet Protocol (TCP/IP)
              Click the "Advanced" button
              Select the WINS tab
              click on Disable Netbios over TCP-IP

*/



#if (RTSMB_WINDOWS)
static void socket_init ();
#endif
#if (CALL_SHELL)
int smb_test_main(int argc, char *argv[]);
int smb_cli_shell(void);
#endif
int smbclientmain(int argc, char *argv[])
{
#if (RTSMB_WINDOWS)
    socket_init ();
#endif
#if (CALL_SHELL)
    return(smb_cli_shell());
#else
    return(smb_test_main(argc, argv));
#endif
}

#if (RTSMB_WINDOWS)
static void socket_init ()
{
    #define WINSOCK_VER 0x0101
    int result;

    RTSMB_STATIC struct WSAData wsa_data;

    result = WSAStartup (WINSOCK_VER, &wsa_data);

    if (result)
    {
        rtp_printf(("init: Winsock start up failed\n"));
    }
}
#endif

/* Helpers, see shel and test */
void mark_rv (int job, int rv, void *data)
{
    int *idata = (int *)data;
    *idata = rv;
    if (rv==-52)
        rtp_printf("Bad Permissions, Marked = %d\n",*idata);
}

int wait_on_job(int sid, int job)
{
    int rv = RTSMB_CLI_SSN_RV_INVALID_RV;
    int r;
    rtsmb_cli_session_set_job_callback(sid, job, mark_rv, &rv);

    while(rv == RTSMB_CLI_SSN_RV_INVALID_RV)
    {
        r = rtsmb_cli_session_cycle(sid, 10);
        if (r < 0)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "\n wait_on_job: rtsmb_cli_session_cycle returned error == %d\n",r);
            return r;
        }
        if (rv == RTSMB_CLI_SSN_RV_INVALID_RV)
        {
            //rtp_printf("\n In the middle of cycling");
        }
    }
    return rv;
}

void srvsmboo_panic(const char *panic_string)
{
   RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "DIAG: Looping Panic abort called :%s\n",panic_string);
   for (;;) { }
   rtp_printf("\nPanic abort called: \n");
   rtp_printf("panic: %s \r",panic_string);
   int iZero  = 0;      // trap to the debugger
   int iCrash = 13 / iZero;      // trap to the debugger
}

RTP_SOCKET diag_socket = -1;




#ifdef __linux
#include <stdio.h>
#include <unistd.h>
#include <string.h> /* for strncpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

static int select_linux_interface(unsigned char *pip, unsigned char *pmask_ip)
{
 int fd;
 struct ifreq ifr;
 unsigned char *p;
 char *interface_name = "eth0";
// char *interface_name = "enp0s3";


 fd = socket(AF_INET, SOCK_DGRAM, 0);
 if (fd < 0)
 {
   printf("select_linux_interface: Failed error opening a socket\n");
   return -1;
 }
 /* I want to get an IPv4 IP address */
 ifr.ifr_addr.sa_family = AF_INET;

 /* I want IP address attached to "eth0" */
 strncpy(ifr.ifr_name, interface_name, IFNAMSIZ-1);

 int r = ioctl(fd, SIOCGIFADDR, &ifr);
 if (r < 0)
 {
ioctl_error:
   printf("select_linux_interface: Error performing ioctl() on a socket\n");
   close(fd);
   return -1;
 }
 p = (unsigned char *) &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
// printf("ip address: %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
 pip[0]=p[0]; pip[1]=p[1]; pip[2]=p[2]; pip[3]=p[3];

 ioctl(fd, SIOCGIFNETMASK, &ifr);
 if (r < 0)
  goto ioctl_error;
 p = (unsigned char *)&((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
// printf("mask:%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr));
 pmask_ip[0]=p[0]; pmask_ip[1]=p[1]; pmask_ip[2]=p[2]; pmask_ip[3]=p[3];

 printf("select_linux_interface\n  Success:\n  Using device %s ip address: %s net mask: %s\n", interface_name,  inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr) ,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr));
 close(fd);
 return 0;
}

#endif

