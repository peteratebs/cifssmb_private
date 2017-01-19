#if (0)
//
// Not used. but creates warnings.
//
//
//
/*
  srvinteractive.c - Provides an interactive console for the server when HARDWIRE_SERVER_SETTINGS is false



*/

/* Guess linux or windows based on compiler.. if this is wrong it's easy to fix */
#if (defined( _WIN32)||defined(_WIN64))
#define RTSMB_WIN
#endif


#include "srvapi.h"
#include "smbdebug.h"
#include "rtpprint.h"
#include "rtpterm.h"
#include "psmbfile.h"
#include "rtpscnv.h"
#include "rtpthrd.h"

#define SRVGETCHAR() rtp_term_getch()
#define SRVKBHIT() rtp_term_kbhit()
#define SRVPROMPT(A,B)  rtp_term_promptstring (A, B)

////////////////////////////////////////////////////

int smbserver_runtimecommand(void);
int smbserver_runtimeadduser(void);
int smbserver_runtimeaddshare(void);
int smbserver_runtimemodifyuser(void);
int smbserver_runtimemodifyshare(void);
int smbserver_runtimeaddprinter(void);
static int smbserver_runtimemodifyprinter(void);
static int smbserver_serverenable(void);


static int in_bool(char *prompt, char defaultC);
static void in_ipaddress(byte *pip, byte *pmask_ip);
static int in_printer(char *printerName,char *driverName,char *tempPath,char *prnFile);
byte in_loginmode(void);
static int in_share(byte security_code, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode);
static int in_user(char * userName, char *userPass, char *userPerm);
int in_guestaccount(void);
void in_name(char *network_name, char *network_group);
int in_pollforcommands(void);


#if (HARDWIRE_SERVER_SETTINGS==0)
extern int pollforcommands; // shared with serverexample.c
extern byte security_mode;

int rtsmb_server_interactive (void)
{
#if (HARDWIRE_SERVER_SETTINGS==0)
		if(pollforcommands && SRVKBHIT())
		{
#ifdef RTSMB_WIN
			SRVGETCHAR();
#endif //RTSMB_WIN
			if (smbserver_runtimecommand() == -1)
				return -1;
			else
				rtp_printf("Server is running... Press return to enter a command or to quit\n");
		}
#endif
  return 0;
}


int smbserver_runtimeadduser(void)
{
	/* Prompt for user name and passwords */
	if (security_mode == AUTH_USER_MODE)
	{
	char userName[32];
	char userPass[32];
	char userPerm[32];


		rtp_strcpy(userName, "");
		rtp_strcpy(userPass, "");
		rtp_printf("Add a new user .. \n");
		if (in_user(userName, userPass, userPerm))
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
			return(1);
		}
	}
	return(0);
}//smbserver_runtimeadduser

int smbserver_runtimemodifyuser (void)
{
	char userName[32]="";
	char *puserName;
	int newsecCode;

	if (security_mode == AUTH_USER_MODE)
	{
		rtp_printf("User to modify  : ");
		SRVPROMPT (userName, 0);
		rtp_printf("\nEnter new access rights");
		rtp_printf("\n0==READONLY, 1==READWRITE");
		rtp_printf("\nUser access-rights 0,1: ");
		rtp_scanf ("%d",&newsecCode);

		if (userName[0])
			puserName = &userName[0];
		else
			puserName = 0;

		if(puserName != 0)
		{
			switch(newsecCode)
			{
				case 0:
				{
					rtsmb_srv_remove_user_from_group (puserName, "rw_access");
					rtsmb_srv_remove_user_from_group (puserName, "rd_access");
					if(!rtsmb_srv_add_user_to_group (puserName, "rd_access"))
						rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
					break;
				}
				case 1:
				{
					rtsmb_srv_remove_user_from_group (puserName, "rw_access");
					rtsmb_srv_remove_user_from_group (puserName, "rd_access");
					if(!rtsmb_srv_add_user_to_group (puserName, "rw_access"))
						rtp_printf("rtsmb_srv_add_user_to_group() failed. check configuration\n");
					break;
				}
				default:
					rtp_printf("\nInvalid User access\n");
			}
		}
		else
			rtp_printf("\nUsername invalid\n");
		return(1);
	}
	return(0);
}//smbserver_runtimemodifyuser

int smbserver_runtimeaddshare(void)
{
char shareName[32];
char sharePath[32];
char shareDesc[32];
char sharePass[32];
char secCode[32];


// 	rtp_strcpy(shareName, "share0");
	rtp_strcpy(shareName, HARDWIRED_SHARE_NAME);
	rtp_strcpy(shareDesc, "Rtsmbshare");
	rtp_strcpy(sharePath, HARDWIRED_SHARE_PATH);
	rtp_strcpy(sharePass, "");
	rtp_strcpy(secCode,"2");
	if (in_share(security_mode, shareName, sharePath, shareDesc, sharePass, secCode))
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
	return(0);
}//smbserver_runtimeaddshare

int smbserver_runtimemodifyshare (void)
{
	char cur_share_name[32]="";
	char new_share_name[32]="";
	char newsecCode[32]="";
	byte newpermissions;
	char *pcur_share_name;

	rtp_printf("\nShare to modify:");
	SRVPROMPT (cur_share_name, 0);
	rtp_printf("\nEnter new share name or press enter to keep the current name: ");
	SRVPROMPT (new_share_name, 0);
	rtp_printf("\nEnter new access rights or press enter to keep the current access rights");
	rtp_printf("\n0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECRITY");
	rtp_printf("\nShare Security 0,1,2,3,4: ");
	SRVPROMPT (newsecCode, 0);

	if (newsecCode[0])
		newpermissions = (byte)(newsecCode[0] -'0');
	else
		newpermissions = 99;// If not changing, assign any value <0 or >4

	if (cur_share_name[0])
		pcur_share_name = &cur_share_name[0];
	else
		pcur_share_name = 0;

	if(pcur_share_name != 0)
	{
        if(rtsmb_srv_share_modify (cur_share_name, new_share_name, newpermissions) == 0)
		{
			rtp_printf("Share Modified.\n");
		}
        else
		{
            rtp_printf("Share Modify failed.\n");
		}
	}
	else
		rtp_printf("Share to Modify name Invalid\n");

	return(0);
}//smbserver_runtimemodifyshare

int smbserver_runtimeaddprinter(void)
{
	/* Prompt to add a printer */
	char printerName[32];
	char driverName[32];
	char tempPath[32];
	char prnFile[32];
	int  have_printer;

		rtp_strcpy(printerName, "SmbPrinter");
		rtp_strcpy(driverName, "HP LaserJet 1100");
		rtp_strcpy(tempPath, HARDWIRED_TEMP_PATH);
		rtp_strcpy(prnFile, "SmbPrintData.prn");

    have_printer = in_printer(printerName,driverName, tempPath, prnFile);
	if (have_printer)
		rtsmb_srv_share_add_printer (printerName, driverName, 1, (PSMBFILEAPI)0, tempPath, SHARE_FLAGS_CREATE, (PFCHAR)0, prnFile);

	return(0);
}//smbserver_runtimeaddprinter

static int smbserver_runtimemodifyprinter(void)
{
	char cur_printer_name[32]="";
	char new_printer_name[32]="";
	char *pcur_printer_name;

	rtp_printf("\nPrinter to modify:");
	SRVPROMPT (cur_printer_name, 0);
	rtp_printf("\nEnter new printer name or press enter to keep the current name: ");
	SRVPROMPT (new_printer_name, 0);

	if (cur_printer_name[0])
		pcur_printer_name = &cur_printer_name[0];
	else
		pcur_printer_name = 0;

	if(pcur_printer_name != 0)
	{
        if(rtsmb_srv_printer_modify (cur_printer_name, new_printer_name))
		{
			rtp_printf("Printer name Modified.\n");
		}
        else
		{
            rtp_printf("Printer name modification failed.\n");
		}
	}
	else
		rtp_printf("Printer to Modify name Invalid\n");

	return(0);
}//EOF smbserver_runtimemodifyprinter

static int smbserver_serverdisable(void)
{
	rtsmb_srv_disable ();
	rtp_printf("Server Disabled\n");

	for(;;)
	{
		if(in_bool("Enable? (y/n) : ", 'Y'))
		{
			smbserver_serverenable();
			break;
		}
	}

	return (0);
}//EOF smbserver_serverdisable

static int smbserver_serverenable(void)
{
	char network_name[32];
	char network_group[32];

		rtp_strcpy(network_name, "EBSRTSMB");
		rtp_strcpy(network_group, "MSHOME");

	rtp_printf("Enter server name or press return for the default : ");
	SRVPROMPT (network_name, 0);
	rtp_printf("Enter group name or press return for the default : ");
	SRVPROMPT (network_group, 0);
	rtp_printf("\n");

	rtsmb_srv_enable (network_name, network_group);
	return (0);
}//smbserver_serverenable

int smbserver_runtimecommand(void)
{
	char which_command[32];
	char which_name[32];

	for (;;)
	{
		rtp_printf("\nPress 'S' to add a file share.\n");
		rtp_printf("Press 's' to remove a file share or a print share.\n");
		rtp_printf("Press 'M' to modify a file share.\n");
		rtp_printf("***********************\n");
		rtp_printf("Press 'P' to add a printer.\n");
		rtp_printf("Press 'p' to modify printer name\n");
		rtp_printf("***********************\n");
		if (security_mode == AUTH_USER_MODE)
		{
			rtp_printf("Press 'U' to add an user.\n");
			rtp_printf("Press 'u' to remove an user.\n");
			rtp_printf("Press 'm' to modify an user.\n");
			rtp_printf("***********************\n");
		}
		rtp_printf("\nPress 'D' to disable the server\n");
		rtp_printf("Press 'q' to quit.\n");
		rtp_printf("\nCommand : ");
		rtp_strcpy(which_command, "");
		SRVPROMPT (which_command, 0);

		switch (which_command[0])
		{
		case 'P':
			{
				smbserver_runtimeaddprinter();
				return(0);
				break;
			}
		case 'p':
			{
				smbserver_runtimemodifyprinter();
				return(0);
				break;
			}
		case 'U':
			{
				smbserver_runtimeadduser();
				return(0);
				break;
			}
		case 'u':
			{
				if (security_mode == AUTH_USER_MODE)
				{
					rtp_strcpy(which_name, "user");
					rtp_printf("User to remove  : ");
					SRVPROMPT (which_name, 0);
					if (rtsmb_srv_delete_user(which_name))
						rtp_printf("Removed\n");
					else
						rtp_printf("Failed\n");
				return(0);
					return(0);
				}
				break;
			}
		case 'm':
			{
				smbserver_runtimemodifyuser ();
				return(0);
				break;
			}
		case 'S':
			{
				smbserver_runtimeaddshare();
				return(0);
				break;
			}
		case 's':
			{
				rtp_strcpy(which_name, "share0");
				rtp_printf("Share to remove  : ");
				SRVPROMPT (which_name, 0);
				if (rtsmb_srv_share_remove(which_name) == 0)
					rtp_printf("Removed\n");
				else
					rtp_printf("Failed\n");
				return(0);
				break;
			}
		case 'M':
			{
				smbserver_runtimemodifyshare ();
				return(0);
				break;
			}
		case 'q':
			{
				return(-1);
				break;
			}
		case 'D':
			{
				smbserver_serverdisable ();
				return(0);
				break;
			}
		}
	}
}//smbserver_runtimecommand


static void help_security_mode(void)
{
	rtp_printf("Sorry no help for you . \n");
}//help_security_mode


static int in_bool(char *prompt, char defaultC)
{
	char allow[32];
	allow[0] = defaultC;
	allow[1] = 0;
	rtp_printf("%s", prompt);
	SRVPROMPT (allow, 0);
	if (allow[0] == 'Y' || allow[0] == 'y')
		return(1);
	else
		return(0);
}//in_bool

static void in_ipaddress(byte *pip, byte *pmask_ip)
{
	byte counter;
/******** Not sure this works try on Linux***********/
/*
#ifdef RTSMB_LINUX
	rtp_in_addr_t my_ip = get_my_IP();
	if (my_ip != 0)
	{
		struct rtp_in_addr temp;
		temp.s_addr = my_ip;
		rtp_printf("%s\n", rtp_inet_ntoa(temp));
	}
#endif
*/
/********************/
	for (counter=0;counter<4;counter++)
	{
	char inbuffer[32];
        rtp_itoa(pip[counter], inbuffer, 10);
		rtp_printf("Byte %d IP Address: ",counter);
		SRVPROMPT (inbuffer, 0);
		pip[counter] = (unsigned char)rtp_atoi(inbuffer);
	}
	for (counter=0; counter<4; counter++)
	{
	char inbuffer[32];
        rtp_itoa(pmask_ip[counter], inbuffer, 10);
		rtp_printf("Byte %d IP Mask: ",counter);
		SRVPROMPT (inbuffer, 0);
		pmask_ip[counter] = (unsigned char)rtp_atoi(inbuffer);
	}
	rtp_printf("IP Address: %d.%d.%d.%d\n",pip[0],pip[1],pip[2],pip[3]);
	rtp_printf("IP Mask   : %d.%d.%d.%d\n",pmask_ip[0],pmask_ip[1],pmask_ip[2],pmask_ip[3]);

}//in_ipaddress

int in_printer(
	char *printerName,
	char *driverName,
	char *tempPath,
	char *prnFile)
{
int have_printer;
	rtp_printf("Note: The demo does not actually print data, it just captures print data to a temporary file.\n\n");

	have_printer = in_bool("Add a printer (y/n) ? ", 'Y');
	rtp_printf("\n");

	if (have_printer)
	{
		rtp_printf("Set up printer. press enter to keep defaults. \n");
		rtp_printf("Printer name : ");
		SRVPROMPT (printerName, 0);
		rtp_printf("Driver name : ");
		SRVPROMPT (driverName, 0);
		rtp_printf("Print Capture Path : ");
		SRVPROMPT (tempPath, 0);
		rtp_printf("Print Capture File : ");
		SRVPROMPT (prnFile, 0);
		rtp_printf("\n");
		return(1);
	}
	return(0);
}//in_printer

byte in_loginmode(void)
{
	byte security_mode;
	char which_share_mode[32];
	do {
		rtp_strcpy(which_share_mode, "s");
		rtp_printf("press '?' for help or ..\n");
		rtp_printf("Press 's' for share based passwords, 'u' for user passwords: ");
		SRVPROMPT (which_share_mode, 0);
		if (which_share_mode[0] == '?')
			help_security_mode();
	} while (which_share_mode[0] != 's' && which_share_mode[0] != 'u');
	if (which_share_mode[0] == 's')
		security_mode = AUTH_SHARE_MODE;
	else
		security_mode = AUTH_USER_MODE;
	rtp_printf("\n");
	return(security_mode);
}//in_loginmode

int in_share(byte security_mode, char *shareName,char *sharePath,char *shareDesc,char *sharePass, char *secCode)
{
		rtp_printf("Set up shares press enter to keep defaults. \n");
		rtp_printf("Share name : ");
		SRVPROMPT (shareName, 0);
		if (!shareName[0])
			return(0);
		rtp_printf("Share Path : ");
		SRVPROMPT (sharePath, 0);
		rtp_printf("Share Description : ");
		SRVPROMPT (shareDesc, 0);

		if (security_mode == AUTH_SHARE_MODE)
		{
			rtp_printf("Share Password (leave empty for no passwords): ");
			SRVPROMPT (sharePass, 0);
			rtp_printf("0==READONLY, 1==WRITEONLY, 2==READWRITE, 3==NOACCES, 4==NO SECURITY\n");
			rtp_printf("Share Security 0,1,2,3,4: ");
			SRVPROMPT (secCode, 0);
		 }
		rtp_printf("\n");
		return(1);

}// in_share

int in_user(char * userName, char *userPass, char *userPerm)
{
	rtp_printf("User Name  : ");
	SRVPROMPT (userName, 0);
	if (userName[0])
	{
		rtp_printf("Password  : ");
		SRVPROMPT (userPass, 0);
		rtsmb_srv_register_user (userName, userPass);
		for(;;)
		{
			rtp_strcpy(userPerm, "rw");
			rtp_printf("Select access rights , 'r'ead or 'rw' read-write  : ");
			SRVPROMPT (userPerm, 0);
			if (rtp_strcmp(userPerm, "rw") == 0)
				break;
			else if (rtp_strcmp(userPerm, "r") == 0)
				break;
		}
		rtp_printf("\n");
		return(1);
	}
	rtp_printf("\n");
	return(0);
}//in_user

int in_guestaccount(void)
{
	return(in_bool("Allow Guest login (y/n) : ", 'N'));
}//in_guestaccount

void in_name(char *network_name, char *network_group)
{
	rtp_printf("Enter server name and group name. \n");
	rtp_printf("Note: Change the name if more than one Rtsmb server is running on the network. \n\n");

	rtp_printf("Enter server name or press return for the default : ");
	SRVPROMPT (network_name, 0);
	rtp_printf("Enter group name or press return for the default : ");
	SRVPROMPT (network_group, 0);
	rtp_printf("\n");
}//in_name

int in_pollforcommands(void)
{
	rtp_printf("Type N or n to disable keyboard polling while the server is executing \n");
	rtp_printf(" If keyboard polling is enabled you may add and remove shares, add and remove users and display statistics\n");
	rtp_printf(" from the console while the server is running.\n");
	rtp_printf(" Note: Linux users should disable keyboard polling if polling appears to interfere with socket IO\n");

	return(in_bool("Poll keyboard for commands (y/n) : ", 'N'));
}//in_pollforcommands




#endif // (HARDWIRE_SERVER_SETTINGS==0)

#endif
