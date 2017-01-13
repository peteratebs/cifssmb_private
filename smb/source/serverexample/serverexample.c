/*
  srvmain.c - Sample server program for windows or linux, that should port relatively easilly to most run time environments



  This file is a sample main loop that is used for testing.
  It is not part of RT-SMB proper and need not be included in your code.
  If you want to use parts of this for your main loop, please do.

  If the line #define USE_CONFIG_FILE is TRUE then the share names and access control is provided by the confirguration file.

  The sample configuration file contains documentation for the file.

  srvmain.c is duplicated in the linux and windows projects.

  The only differences are:
  For windows,
  #define RTSMB_WIN is enabled
  For linux
  #ifdef RTSMB_LINUX is enabled

*/

/* Guess linux or windows based on compiler.. if this is wrong it's easy to fix */
#if (defined( _WIN32)||defined(_WIN64))
#define RTSMB_WIN
#endif

#ifdef __linux
#define RTSMB_LINUX
static int select_linux_interface(unsigned char *pip, unsigned char *pmask_ip);
#endif

#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"
#include "rtpthrd.h"
#include "remotediags.h"

volatile int go = 1; /* Variable loop on.. Note: Linux version needs sigkill support to clean up */
volatile quit_sig_pressed = 0;
volatile int keyboard_break_pressed_count;

extern void rtsmb_thread_iwatch (void *p);

extern void rtsmb_srv_syslog_config(void);

#if (INCLUDE_SRVOBJ_REMOTE_DIAGS_THREAD)
RTP_HANDLE mainThread;
RTP_HANDLE diagThread;
RTP_HANDLE watcherThread;
static int _smbservermain (void);
RTSMB_STATIC void rtsmb_thread_main (void *p)
{
   _smbservermain ();
}

extern void rtsmb_thread_diag (void *p);
void rtsmb_srv_fork_main(void)
{
    void *pArgs = 0;
    if (rtp_thread_spawn(&mainThread, (RTP_ENTRY_POINT_FN) rtsmb_thread_main, "MAINTHREAD", 0, 0, pArgs))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_fork_main: Couldn't start thread!\n");
    }
    if (rtp_thread_spawn(&diagThread, (RTP_ENTRY_POINT_FN) rtsmb_thread_diag, "DIAGTHREAD", 0, 0, pArgs))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_fork_main: Couldn't start thread!\n");
    }
    if (rtp_thread_spawn(&diagThread, (RTP_ENTRY_POINT_FN) rtsmb_thread_iwatch, "DIAGTHREAD", 0, 0, pArgs))
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"rtsmb_srv_fork_main: Couldn't start thread!\n");
    }
}
#endif

int smbservermain (int argc, char **argv)
{
  // Set up syslog early in the process
  rtsmb_srv_syslog_config();

#if (INCLUDE_SRVOBJ_REMOTE_DIAGS_THREAD)
  rtsmb_srv_fork_main();
  while (go)
  {
    rtp_thread_sleep_seconds(10);
  }
#else
  _smbservermain ();
#endif
 return 0;
}

RTSMB_STATIC char spinner[4] = {'\\', '-', '/', '|'};
RTSMB_STATIC int spinState = 0;

RTSMB_STATIC byte ip[4] = {192, 168, 1, 2};
RTSMB_STATIC byte mask_ip[4] = {255, 255, 255, 0};

byte security_mode;      // shared with serverinteractive.c
int pollforcommands = 1; // shared with serverinteractive.c


////////////////////////////////////////////////////

#if (HARDWIRE_SERVER_SETTINGS==0)
int rtsmb_server_interactive (void);
void in_ipaddress(byte *pip, byte *pmask_ip);
int in_printer(char *printerName,char *driverName,char *tempPath,char *prnFile);
byte in_loginmode(void);
int in_share(byte security_code, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode);
int in_user(char * userName, char *userPass, char *userPerm);
int in_guestaccount(void);
void in_name(char *network_name, char *network_group);
int in_pollforcommands(void);
int smbserver_runtimecommand(void);
int smbserver_runtimeadduser(void);
int smbserver_runtimeaddshare(void);
int smbserver_runtimeaddprinter(void);
#endif
static void rtsmb_srv_non_file_config(void);



void rtsmb_main (void)
{
	//spinState += 1;
	//spinState = spinState%4;
	//rtp_printf("\b%c",spinner[spinState]);
	rtsmb_srv_cycle (1000);
}




#include<signal.h>
// #include <unistd.h>

void sig_quit_handler(int signo)
{
  if (signo == SIGQUIT)
  {
    quit_sig_pressed = 1;
    keyboard_break_pressed_count = 1;
  }
}
void sig_handler(int signo)
{
  if (signo == SIGINT)
  {
    go = 0;
  }
}



static int _smbservermain (void)
{
	go = 1;
    //test_challenge();
    //return -1;

    // Control C handler for setting go = 0
    signal(SIGINT, sig_handler);
    // Control \ prints diags
    signal(SIGQUIT, sig_quit_handler);

 	if (rtp_net_init () < 0)
	{
       fprintf(stderr, "rtp_net_init failed\n");
       return -1;
	}

#if (HARDWIRED_EXTENDED_SECURITY)
    spnego_init_extended_security();
#endif
#ifdef RTSMB_LINUX
    if (select_linux_interface(ip, mask_ip) < 0)
    { // Resort to selecting he address by hand if linux retrieve address failed
       fprintf(stderr, "select interface failed\n");
       return -1;
    }
#else
    { // Resort to selecting he address by hand if linux retrieve address failed
	  /* Retrieve ip address and mask from console and initialize server */
	  in_ipaddress(ip, mask_ip);
    }
#endif

//    rtp_printf("Using PORT numbers (137 and 138),SMB/SAMBA should not also be running on this device.\n");
//    rtp_printf("type: sudo service stop smbd\n");
    rtsmb_init_port_well_know();
    // See also: rtsmb_init_port_alt();

	/* Retrieve the name and workgroup */
	{
	char network_name[32];
	char network_group[32];

		rtp_strcpy(network_name, HARDWIRED_HOST_NAME);
		rtp_strcpy(network_group, HARDWIRED_GROUP_NAME);
#if (HARDWIRE_SERVER_SETTINGS==0&&HARDWIRE_USE_CONFIG_FILE==0)
        // Override defaults interactiveky
        in_name(network_name, network_group);
#endif
		rtsmb_srv_init (ip, mask_ip, network_name , network_group);
	}


#if (HARDWIRE_USE_CONFIG_FILE==1)
    rtsmb_srv_share_add_ipc ((PFCHAR)0);
    rtsmb_srv_read_config ("smb_config.txt");
#else
    rtsmb_srv_non_file_config();
#endif //USE_CONFIG_FILE
#if (HARDWIRE_SERVER_SETTINGS==0)
#ifdef RTSMB_LINUX
	pollforcommands = in_pollforcommands();
#else
	pollforcommands = 1;
#endif
	if (pollforcommands)
	{
		rtp_printf("\n\n\n\n\n\n");
		rtp_printf("Server is running... Press return to enter a command or to quit\n");
	}
	else
	{
		rtp_printf("\n The Server is running.. Press control C to exit\n");
	}
#else
		rtp_printf("\n The Server is running.. Press control C to exit\n");
#endif

	//Inside smbservermain
	/*************************************************************************************/
	while(go){
		rtsmb_main ();
        if (quit_sig_pressed)
        {
// Do some diags herething here          srvobject_display_diags();
          rtp_printf("main: ctrl \\\\ pressed use for diagnostics\n");
          quit_sig_pressed = 0;
        }

#if (HARDWIRE_SERVER_SETTINGS==0)
		if (rtsmb_server_interactive () < 0)
          break;
#endif
	} // while (go)
	/************************************************************************************/


	rtp_printf("main: shutting down\n");
#if (HARDWIRED_EXTENDED_SECURITY)
    spnego_free_extended_security();
#endif

	rtsmb_srv_shutdown ();
	rtp_net_exit ();

	return(0);
}//smbservermain


#if (HARDWIRE_USE_CONFIG_FILE==0)
static void rtsmb_srv_non_file_config(void)
{

#if (HARDWIRE_SERVER_SETTINGS)
	rtp_printf("\nConfigure Rtsmb server with hard wired values...\n");
	rtp_printf("Note: The default values can be changed by editing smbdefs.h and rebuilding.\n");
    rtp_printf("=========================================================\n\n ");
	rtp_printf("User name   : %s\n", HARDWIRED_USER_NAME  );
	rtp_printf("Password    : %s\n", HARDWIRED_PASSWORD   );
	rtp_printf("Share name  : %s\n", HARDWIRED_SHARE_NAME  );
	rtp_printf("Share path  : %s\n", HARDWIRED_SHARE_PATH );
	rtp_printf("Host    name: %s\n", HARDWIRED_HOST_NAME  );
	rtp_printf("Group   name: %s\n", HARDWIRED_GROUP_NAME );
#endif


#if (HARDWIRE_SERVER_SETTINGS==0)
	/* Prompt for printers. */
	smbserver_runtimeaddprinter();
#endif
	rtsmb_srv_share_add_ipc ((PFCHAR)0);

#if (HARDWIRE_SERVER_SETTINGS)
	security_mode =	AUTH_USER_MODE;
#else
	/* Ask for user or share based security */
	security_mode =	in_loginmode();
#endif
	rtsmb_srv_set_mode (security_mode);

	/* Register names used by Rtsmb to control read write permissions */
	rtsmb_srv_register_group ("rw_access");
	rtsmb_srv_register_group ("rd_access");

#if (HARDWIRE_SERVER_SETTINGS==0)
	/* Prompt for shares. */
	smbserver_runtimeaddshare();
#else
char shareName[32];
char sharePath[32];
char shareDesc[32];
char sharePass[32];
char secCode[32];


	rtp_strcpy(shareName, HARDWIRED_SHARE_NAME);
	rtp_strcpy(shareDesc, "Rtsmbshare");
	rtp_strcpy(sharePath, HARDWIRED_SHARE_PATH);
	rtp_strcpy(sharePass, "");
	rtp_strcpy(secCode,"2");
	{
	byte security_mode; /* Defult is 2  SECURITY_READWRITE */
	char *psharePass;
		if (sharePass[0])
			psharePass = &sharePass[0];
		else
			psharePass = 0;
		security_mode = (byte)(secCode[0] -'0');
	 	if (rtsmb_srv_share_add_tree (shareName, shareDesc, 0, sharePath, SHARE_FLAGS_CREATE, security_mode, (PFCHAR)psharePass) == 0)
			rtp_printf("Share added.\n");
		else
			rtp_printf("Share add failed\n");
	 	if (!rtsmb_srv_set_group_permissions ("rw_access", shareName, SECURITY_READWRITE))
			rtp_printf("Set rw_access group permissions failed\n");
	 	if (!rtsmb_srv_set_group_permissions ("rd_access", shareName, SECURITY_READ))
			rtp_printf("Set rd_access group permissions failed\n");
	}
#endif
	/* Everyone must be able to read and write the IPC pipe */
	rtsmb_srv_set_group_permissions ("rw_access", "IPC$", SECURITY_READWRITE);
	rtsmb_srv_set_group_permissions ("rd_access", "IPC$", SECURITY_READWRITE);

	/* Old cruft, demonstrates some other security */

	//rtsmb_srv_register_group ("ro_access");
	//rtsmb_srv_set_group_permissions ("ro_access", SHARE_NAME, SECURITY_READ);
	//rtsmb_srv_set_group_permissions ("ro_access", "IPC$", SECURITY_READWRITE);

	//rtsmb_srv_register_group ("wo_access");
	//rtsmb_srv_set_group_permissions ("wo_access", SHARE_NAME, SECURITY_WRITE);
	//rtsmb_srv_set_group_permissions ("wo_access", "IPC$", SECURITY_READWRITE);

    /* No access */
    //rtsmb_srv_register_group ("nonebs");
	//rtsmb_srv_set_group_permissions ("nonebs", SHARE_NAME, SECURITY_NONE);
	//rtsmb_srv_set_group_permissions ("nonebs", "IPC$", SECURITY_NONE);

	//rtsmb_srv_register_user (SMB_GUESTNAME, (PFCHAR)0);
    //rtsmb_srv_register_user (SMB_GUESTNAME, "ebs");
	//rtsmb_srv_add_user_to_group (SMB_GUESTNAME, "rw_access");

	/* Prompt for user name and passwords */

	if (security_mode == AUTH_USER_MODE)
	{
	//char userName[32];
	//char userPass[32];
	//char userPerm[32];


#if (HARDWIRE_SERVER_SETTINGS==0)
		if (in_guestaccount())
		{
			rtsmb_srv_register_user (SMB_GUESTNAME, SMB_GUESTPASSWORD);
			rtsmb_srv_add_user_to_group (SMB_GUESTNAME, "rd_access");
		}
		rtp_printf("Add users, enter a blank user name to stop adding .. \n");
		rtp_printf("To stop adding users press BACKSPACE until the input field is empty followed by <return>.. \n");
		while (smbserver_runtimeadduser() == 1)
        {
			;
        }
#else
	char userName[32];
	char userPass[32];
	char userPerm[32];
        rtp_strcpy(userName, HARDWIRED_USER_NAME);
        rtp_strcpy(userPass, HARDWIRED_PASSWORD);
        rtp_strcpy(userPerm, "rw");
	    rtp_printf("User perm  : %s",userPerm);
		{
			if (!rtsmb_srv_register_user (userName, userPass))
			{
				rtp_printf("rtsmb_srv_register_user() failed. check configuration\n");
			}
			else
			{
				rtp_printf("rtsmb_srv_register_user() succeeded.\n");

				if (rtp_strcmp(userPerm, "rw") == 0 && !rtsmb_srv_add_user_to_group (userName, "rw_access"))
				{
					rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
				}
				else if (/* rtp_strcmp(userPerm, "r") == 0 && */!rtsmb_srv_add_user_to_group (userName, "rd_access"))
				{
					rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
				}
			}
		}
#endif
	}
}
#endif

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
