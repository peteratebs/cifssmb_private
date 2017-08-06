#ifdef __linux
static int select_linux_interface(unsigned char *pip, unsigned char *pmask_ip);
#endif


// --------------------------------------------------------
#include "cliapi.h"
#include "smbutil.h"
#include "rtpnet.h"
#include "rtpterm.h"
#include "rtpprint.h"
#include "rtpstr.h"
#include "clirpc.h"
#include "clsrvsvc.h"
#include "rtpscnv.h"
#include "rtpprint.h"
#include "rtpexit.h"
#include "rtpchar.h"
#include "wchar.h"
#include "smbdebug.h"
#include "smbspnego.h"
#include "rtpmem.h"
#include <stdarg.h>
#include "clicfg.h"

extern char *CommandProcessorGets(char *to, int max_count);
extern void CommandProcessorPuts(char *buffer);
extern void cpp_cleanup_after_command();

// --------------------------------------------------------
#define HISTORY_MODE 1 /* Set to one, to remember parts of Url zero to prompt for all elements of URL */
#define COMMAND_BUFFER_SIZE 80

#define CLI_DEBUG  1
#define CLI_PROMPT 2
#define CLI_ALERT  3

#define DEL_COMMAND   1
#define MKDIR_COMMAND 2
#define RMDIR_COMMAND 3
#define READ_COMMAND  1
#define WRITE_COMMAND 2
#define CAT_COMMAND   3

// --------------------------------------------------------
extern int http_advanced_server_demo(void);

char shell_buffer[2048];

// --------------------------------------------------------
int wait_on_job(int sid, int job);

static int do_connect_share(int sid, char *sharename);
static char *do_getserver_name(char *pnewservername);
static RTSMB_CLI_SESSION_DIALECT do_get_session_dialect(char *pnewdialect);

static int do_setserver_command(void);
static char *do_getuser_name(void);
static int do_setuser_command(void);
static char *do_getpassword(void);
static int do_setpassword_command(void);
static char *do_getdomain_name(void);
static int do_setdomain_command(void);
static char *do_getshare_name(void);
static int do_setshare_command(void);
static int do_net_command(char *command);
static int do_cli_info (void);
static void in_ipaddress(byte *pip, byte *pmask_ip);
unsigned char my_ip[] = {192,168,1,6};
unsigned char my_mask[] = {255, 255, 255, 0};

static int do_fhandle_open_command(char *command);
static int do_fhandle_close_command(char *command);
static int do_fhandle_aread_command(char *command);
static int do_fhandle_awrite_command(char *command);
static int do_fhandle_read_command(char *command);
static int do_fhandle_write_command(char *command);
static int do_fhandle_seek_command(char *command);
static int do_fhandle_stat_command(char *command);

// --------------------------------------------------------
char *enum_cmd   = "ENUMSRV";
char *lookup_cmd = "LOOKUPSRV";
char *shares_cmd = "LISTSHARES";
char *ls_cmd     = "LS";
char *cat_cmd    = "CAT";
char *read_cmd   = "READFILE";
char *fill_cmd   = "FILLFILE";
char *setserver_cmd   = "SETSERVER";
char *setshare_cmd    = "SETSHARE";
char *setuser_cmd     = "SETUSER";
char *setpassword_cmd = "SETPASSWORD";
//char *cre8_cmd      = "CRE8";
char *del_cmd         = "DEL";
char *mkdir_cmd       = "MKDIR";
char *rmdir_cmd       = "RMDIR";
char *loop_cmd        = "LOOP";
char *quit_cmd        = "QUIT";
char *net_cmd         = "NET";
char *logoff_cmd      = "LOGOFF";
char *dump_cmd        = "SHOWSTATE";
char *help_cmd        = "HELP";
char *alt_help_cmd        = "?";

static char *file_cmds[][2] = {
    {"FOPEN", "FOPEN filename {W|T|E}       ((W)rite,(T)runcate,(E)xclusive - select one or more.)"},
    {"FCLOSE","FCLOSE  fd#"},
    {"FAREAD", "FAREAD  fd# #nLines            (-1 lines == read to end) "},
    {"FAWRITE","FAWRITE fd#                    (reads text from stdin and writes to file)"},
    {"FREAD", "FREAD   fd# #nBytes            (-1 == read to end) "},
    {"FWRITE","FWRITE  fd# #nBytes            (Write byte pattern to the current file location)"},
    {"FSEEK", "FSEEK   fd# [S|C|E] #Offset    ( seek (S)et|(C)ur|(E)nd OFFSET )"},
    {"FSTAT", "FSTAT   fd#"},
    {0,0}
 };

typedef int (do_file_function_t)(char *p);
static do_file_function_t *file_functions[] =
{
 do_fhandle_open_command,
 do_fhandle_close_command,
 do_fhandle_aread_command,
 do_fhandle_awrite_command,
 do_fhandle_read_command,
 do_fhandle_write_command,
 do_fhandle_seek_command,
 do_fhandle_stat_command
};



static int do_enum_command(void);
static int do_lookup_command(char *nbsname);
static int do_enum_shares_command(void);
static int do_connect_server(int *sid);
static int do_logon_server(int sid);
static int do_prompt_ls_command(int doLoop);
static int do_quit_command(void);


static int do_file_command(int which_command, char *command);
static int do_dir_command(int which_command, char *command);
static int do_logoff_command(char *command);

static int do_connect_server_worker(int *sid,char *server_name, RTSMB_CLI_SESSION_DIALECT dialect);

// done in cpp now
extern  int do_smb2_logon_server_worker(int sid,  char *user_name, char *password, char *domain);
extern  int do_smb2_tree_disconnect_worker(int sid);
extern int do_smb2_querydirectory_worker(int sid,  byte *share_name, byte *pattern);
extern int do_smb2_tree_connect_worker(int sid,  byte *share_name, byte *password);


// static int do_logon_server_worker(int sid,  char *user_name, char *password, char *domain);
static int do_ls_command_worker(int doLoop,int sid, char *sharename,char *pattern);
static int do_ls_command(char *command);

static int do_loop_command();


// --------------------------------------------------------
void smb_cli_term_printf(int dbg_lvl, char *fmt, ...)
{
static char buffer[1024];

 va_list argptr=0;
 va_start(argptr,fmt);
 rtp_vsprintf(buffer, fmt, argptr);
 va_end(argptr);
 CommandProcessorPuts(buffer);
 return;
 if (dbg_lvl==CLI_DEBUG)
    rtp_printf("??? %s",buffer);
 else if (dbg_lvl==CLI_ALERT)
    rtp_printf("!!!! %s",buffer);
 else
 {
    rtp_printf("rtprintf_>>>   %s",buffer);
 }
}


static void smbcli_prompt(char *promptstr, char *buffer, int length)
{
//  rtp_term_c
    int i;
    smb_cli_term_printf(CLI_PROMPT,promptstr);
    //gets (buffer);
//        rtp_term_gets(buffer);
//        fgets(buffer, 80, stdin);
        CommandProcessorGets(buffer, 80);

     /* strip trailing newline */
        for (i = 0; i < (int)rtp_strlen(buffer); i++)
        {
            if ( buffer[i] == '\n' || buffer[i] == '\r' )
                buffer[i] = '\0';
        }
}
static int exit_shell;


static int do_help_command(void)
{
#if (HISTORY_MODE)
    smb_cli_term_printf(CLI_PROMPT,"%s\n","History mode is on you will be prompted for server, login  and  share names");
    smb_cli_term_printf(CLI_PROMPT,"%s\n","When none are stored from previous commands ");
    smb_cli_term_printf(CLI_PROMPT,"%s\n","To overide the history variables use SETSXXXX commands ");
#else
    smb_cli_term_printf(CLI_PROMPT,"%s\n","History mode is off, you will be prompted for server, login  and  share names");
    smb_cli_term_printf(CLI_PROMPT,"%s\n","For each command you execute");
#endif
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    smb_cli_term_printf(CLI_PROMPT,"%s\n"," ");
    smb_cli_term_printf(CLI_PROMPT,"%s\n",enum_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",lookup_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",shares_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",ls_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",cat_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",read_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",fill_cmd);
    //   rtp_term_puts(cre8_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",del_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",mkdir_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    smb_cli_term_printf(CLI_PROMPT,"%s\n",rmdir_cmd);
#if (HISTORY_MODE)
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setserver_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setshare_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setuser_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",setpassword_cmd);
#endif
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    smb_cli_term_printf(CLI_PROMPT,"%s\n",net_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",logoff_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",dump_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n","                  =======");
    {
        int i;
        for (i =0; file_cmds[i][0]; i++)
            smb_cli_term_printf(CLI_PROMPT,"%s\n",file_cmds[i][1]);
    }
    smb_cli_term_printf(CLI_PROMPT,"%s\n",help_cmd);
    smb_cli_term_printf(CLI_PROMPT,"%s\n",quit_cmd);
}

// --------------------------------------------------------
void smb_cli_term_get_command(char *command_buffer)
{
    smbcli_prompt("CMD>: ", command_buffer, COMMAND_BUFFER_SIZE);
}




static int do_fhandle_open_command(char *command);
static int do_fhandle_close_command(char *command);
static int do_fhandle_aread_command(char *command);
static int do_fhandle_awrite_command(char *command);
static int do_fhandle_read_command(char *command);
static int do_fhandle_write_command(char *command);
static int do_fhandle_seek_command(char *command);
static int do_fhandle_stat_command(char *command);



static void smb_cli_shell_proc(char *command_buffer);

#ifdef __linux

#include <unistd.h>
#include <time.h>

static int DiagMessageFilter(char *str)
{

  if (tc_memcmp(str, "DIAG:",5) == 0)
  {
   int l;
//    if (queuedmessagelength!=0)
//       str += 5; // skip DIAG:
    l = tc_strlen(str);
    {
      char timebuff[255];
      time_t now;
       struct tm *tm;

       now = time(0);
       if ((tm = gmtime (&now))) {
        tc_sprintf (timebuff,"%04d-%02d-%02d %02d:%02d:%02d : SMB",
        tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec);
       }
      rtp_printf("%s: %s", timebuff, str);
    }
    return 1;
  }
  else
  {
    rtp_printf("%s:", str);
    return 0;
  }
}
static char *syslogname = (char *) "RTSMBS";
static unsigned long level_mask = (SYSLOG_TRACE_LVL|SYSLOG_INFO_LVL|SYSLOG_ERROR_LVL);

void rtsmb_srv_syslog_config(void)
{
  RTP_DEBUG_FILTER_SYSLOG(DiagMessageFilter);
  RTP_DEBUG_OPEN_SYSLOG(syslogname, level_mask);
}


#endif
// --------------------------------------------------------
/* ENTRY POINT */
// --------------------------------------------------------
void smb_cli_shell(void)
{
char command_buffer[COMMAND_BUFFER_SIZE];
#ifdef __linux
    if (select_linux_interface(my_ip, my_mask) < 0)
    { // Resort to selecting he address by hand if linux retrieve address failed
       fprintf(stderr, "select interface failed\n");
       return -1;
    }
    rtsmb_srv_syslog_config();
#else
    { // Resort to selecting he address by hand if linux retrieve address failed
	  /* Retrieve ip address and mask from console and initialize server */
	  in_ipaddress(my_ip, my_mask);
    }
#endif
    smb_cli_term_printf(CLI_PROMPT,"Using IP address %d,%d,%d,%d\n", my_ip[0],my_ip[1],my_ip[2],my_ip[3]);
    smb_cli_term_printf(CLI_PROMPT,"Using IP mask    %d,%d,%d,%d\n", my_mask[0],my_mask[1],my_mask[2],my_mask[3]);

    smbcli_prompt("Type (A cr) to use alternate PORT numbers that don't clash with SMB" , command_buffer, COMMAND_BUFFER_SIZE);
    if (command_buffer[0] == 'A' || command_buffer[0] == 'a')
    {
        smb_cli_term_printf(CLI_PROMPT,"Using alternate PORT numbers (9137 and 9138)\n");
        rtsmb_init_port_alt();
    }
    else
    {
        smb_cli_term_printf(CLI_PROMPT,"Using PORT numbers (137 and 138),SMB/SAMBA should not also be running on this device.\n");
        rtsmb_init_port_well_know();
    }
    while (!exit_shell)
    {
        smb_cli_term_get_command(command_buffer);
        smb_cli_shell_proc(command_buffer);
    }
}

// --------------------------------------------------------
static void smb_cli_shell_proc(char *command_buffer)
{
   int Done=0;

   {
       int i;
       for (i =0; file_cmds[i][0]; i++)
       {
           if (rtp_strnicmp(command_buffer, file_cmds[i][0], rtp_strlen(file_cmds[i][0])) == 0)
           {
               file_functions[i](command_buffer+rtp_strlen(file_cmds[i][0])+1);
               Done=1;
               break;
           }
       }
   }
   if(Done)
       ;
   else if (rtp_strcmp(command_buffer, alt_help_cmd) == 0)
        do_help_command();
   else if (rtp_strcmp(command_buffer, help_cmd) == 0)
        do_help_command();
   else if (rtp_strcmp(command_buffer, quit_cmd) == 0)
        do_quit_command();
   else if (rtp_strcmp(command_buffer, enum_cmd) == 0)
    do_enum_command();
#if(INCLUDE_RTSMB_CLIENT_NBNS)
   else if (rtp_strcmp(command_buffer, lookup_cmd) == 0)
   {
    smbcli_prompt("Type name to look up : ", command_buffer, COMMAND_BUFFER_SIZE);
    do_lookup_command(command_buffer);
   }
#endif
   else if (rtp_strcmp(command_buffer, shares_cmd) == 0)
   {
    do_enum_shares_command();
   }
   else if (rtp_strnicmp(command_buffer, ls_cmd, rtp_strlen(ls_cmd)) == 0)
       do_ls_command(command_buffer+rtp_strlen(ls_cmd)+1);
   else if (rtp_strnicmp(command_buffer, cat_cmd,rtp_strlen(cat_cmd)) == 0)
    do_file_command(CAT_COMMAND,command_buffer+rtp_strlen(cat_cmd)+1);
   else if (rtp_strnicmp(command_buffer, read_cmd,rtp_strlen(read_cmd)) == 0)
    do_file_command(READ_COMMAND,command_buffer+rtp_strlen(read_cmd)+1);
   else if (rtp_strnicmp(command_buffer, fill_cmd,rtp_strlen(fill_cmd)) == 0)
    do_file_command(WRITE_COMMAND,command_buffer+rtp_strlen(fill_cmd)+1);
   else if (rtp_strnicmp(command_buffer, mkdir_cmd,rtp_strlen(mkdir_cmd)) == 0)
    do_dir_command(MKDIR_COMMAND,command_buffer+rtp_strlen(mkdir_cmd)+1);
   else if (rtp_strnicmp(command_buffer, rmdir_cmd,rtp_strlen(rmdir_cmd)) == 0)
    do_dir_command(RMDIR_COMMAND,command_buffer+rtp_strlen(rmdir_cmd)+1);
   else if (rtp_strnicmp(command_buffer, del_cmd,rtp_strlen(del_cmd)) == 0)
    do_dir_command(DEL_COMMAND,command_buffer+rtp_strlen(del_cmd)+1);
   else if (rtp_strnicmp(command_buffer, logoff_cmd,rtp_strlen(logoff_cmd)) == 0)
    do_logoff_command(command_buffer+rtp_strlen(logoff_cmd)+1);
   else if (rtp_strnicmp(command_buffer, net_cmd,3) == 0)
    do_net_command(command_buffer+rtp_strlen(net_cmd)+1);
   else if(rtp_stricmp(command_buffer, dump_cmd) == 0)
       do_cli_info ();
   else if (rtp_strcmp(command_buffer, loop_cmd) == 0)
    do_loop_command();
   else if (rtp_strcmp(command_buffer, setserver_cmd) == 0)
    do_setserver_command();
   else if (rtp_strcmp(command_buffer, setshare_cmd) == 0)
    do_setshare_command();
   else if (rtp_strcmp(command_buffer, setuser_cmd) == 0)
    do_setuser_command();
   else if (rtp_strcmp(command_buffer, setpassword_cmd) == 0)
    do_setpassword_command();
   cpp_cleanup_after_command();

}


// --------------------------------------------------------
static int do_quit_command(void)
{
    smb_cli_term_printf(CLI_PROMPT,"Quitting ...................................");
    exit_shell = 1;
    return 0;
}

#define STRCONSTLENGTH(S) sizeof(S)-1

typedef struct RtsmbCliFile_s {
    int fid;
    int session_fid;
    int session_id;
} RtsmbCliFile;

struct CliShellShare_s {
    int  ConnectionNo;
    char shareString[32];
};
struct CliShellConnection_s {
    int sid;
    RTSMB_CLI_SESSION_DIALECT dialect;
    char server_name[80];
    char userString[80];
    char passwordString[80];
};
#define MAX_FILES  8
#define MAX_SHARES 4
#define MAX_CONNECTIONS 2
struct CliShell_s {
    struct RtsmbCliFile_s ClishellFiles[MAX_FILES];
    struct CliShellConnection_s ClishellConnections[MAX_CONNECTIONS];
    struct CliShellShare_s ClishellShares[MAX_SHARES];
};
static struct CliShell_s Clishell;


// --------------------------------------------------------
static int CmdToFdno(char *command)
{
int v = -1;
    while (rtp_isdigit(*command))
    {
        if (v==-1) v = 0;
        v *= 10;
        v += (int)(*command-'0');
        command++;
    }
    return v;
}


// --------------------------------------------------------
static int CmdToDrvId(char *command)
{
int idNo=-1;
  if (command[1]==':')
  {
      idNo = (int)command[0]-'A';
      if (idNo>25)
          idNo = (int)command[0]-'a';
      if (idNo >= TABLE_SIZE(Clishell.ClishellShares))
      {
          smb_cli_term_printf(CLI_ALERT,"As configured the maximum Drive Id is: %c\n", (char) ('a' + TABLE_SIZE(Clishell.ClishellShares)-1));
          return -1;
      }
  }
  else
        smb_cli_term_printf(CLI_ALERT,"Bad arguments\n");
  return idNo;
}

// --------------------------------------------------------
// NET USE d: \\192.168.1.7\share0 /user:ebs /password:password /dialect:1
static int do_net_command(char *command)
{
int doHelp=0;
int idNo = 0;
int ConnectionNo=0;
BBOOL DoOpenConnection=FALSE;
char dialectString[20];
dialectString[0]=0;


    strcpy(command, "USE d: \\\\192.168.1.2\\share0 /user:notebs /password:notpassword /dialect:2");
    smb_cli_term_printf(CLI_ALERT,"Inside with command == %s\n", command);
//    command += STRCONSTLENGTH("NET ");
    smb_cli_term_printf(CLI_ALERT,"Inside 2 with command == %s STRCONSTLENGTH{\"USE\") == %d\n", command,(int)STRCONSTLENGTH("USE"));

    if (rtp_strnicmp(command,"USE", STRCONSTLENGTH("USE"))==0)
    {
        command += STRCONSTLENGTH("USE");
        smb_cli_term_printf(CLI_ALERT,"Inside 3 with command == %s \n", command);
        if (command[0] == 0)
        {
            /* net use - List all connections */
            smb_cli_term_printf(CLI_ALERT,"%s\n", "List all connections");
        }
        else if (command[0]==' ')
        {
            command++;
            smb_cli_term_printf(CLI_ALERT,"Inside 4 with command == %s \n", command);
            idNo=CmdToDrvId(command);
            if (idNo<0)
                return 0;
            command += 2;
            if (*command != ' ')
                doHelp = 1;
            else
            {
                command++;
                /* Check if /delete */
                if (rtp_strnicmp(command,"/delete", STRCONSTLENGTH("/delete"))==0)
                {
                    if (rtsmb_cli_session_disconnect_share (Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid, Clishell.ClishellShares[idNo].shareString)<0)
                    {
                        smb_cli_term_printf(CLI_ALERT,"Share disconnect failed\n");
                    }
                    else
                        smb_cli_term_printf(CLI_ALERT,"Share Deleted \n");
                    return 0;

                }
                else if (rtp_strnicmp(command,"\\\\", STRCONSTLENGTH("\\\\"))==0)
                {
                    char *nextSpace, *nextSlash;
                    unsigned len;
                    char server_name[80];
                    char userString[80];
                    char passwordString[80];
                    char shareString[80];

                    doHelp = 1; /* Assume it's wrong */

                    /* Parse url strng and optional user and password */

                    command += STRCONSTLENGTH("\\\\");
                    smb_cli_term_printf(CLI_ALERT,"Inside 5 with command == %s \n", command);
                    nextSlash=rtp_strstr(command,"\\");
                    nextSpace=rtp_strstr(command," ");

                    // Clishell.ClishellConnections[ConnectionNo].server_name[0]=Clishell.ClishellConnections[ConnectionNo].passwordString[0]=Clishell.ClishellConnections[ConnectionNo].userString[0] = Clishell.ClishellShares[idNo].shareString[0] = 0;
                    server_name[0]=passwordString[0]=userString[0] = shareString[0] = 0;

                    /* set length of the host name */
                    if ((nextSlash && !nextSpace) || nextSpace > nextSlash)
                        len = (unsigned) (nextSlash - command);
                    else if (nextSpace)
                        len = (unsigned) (nextSpace - command);
                    else
                        len = rtp_strlen(command);
                    rtp_memcpy(server_name, command, len);
                    server_name[len]=0;
                    smb_cli_term_printf(CLI_ALERT,"Url:%s \n",server_name);
                    do_getserver_name(server_name);

                    doHelp = 0;
                    command += len;
                    if (command == nextSlash)
                    {
                        command += 1;
                        /* get the share name */
                        if (nextSpace)
                            len = (unsigned) (nextSpace - command);
                        else
                            len = rtp_strlen(command);
                        rtp_memcpy(shareString, command, len);
                        command += len;
                        shareString[len]=0;
                        smb_cli_term_printf(CLI_ALERT,"Share:%s \n",shareString);
                        rtp_strcpy(Clishell.ClishellShares[idNo].shareString, shareString);
                    }
                    if (nextSpace)
                    {
                        /* Now check for user */
                        command = nextSpace+1;
                        if (rtp_strnicmp(command,"/user:", STRCONSTLENGTH("/user:"))==0)
                        {
                            command += STRCONSTLENGTH("/user:");
                            nextSpace=rtp_strstr(command," ");
                            len = nextSpace?(unsigned) (nextSpace - command): rtp_strlen(command);
                            rtp_memcpy(userString, command, len);
                            userString[len]=0;
                            smb_cli_term_printf(CLI_ALERT,"User:%s \n",userString);
                            nextSpace=rtp_strstr(command," ");
                        }
                    }
                    if (nextSpace)
                    {
                        /* Now check for password */
                        command = nextSpace+1;
                        if (rtp_strnicmp(command,"/password:", STRCONSTLENGTH("/password:"))==0)
                        {
                            command += STRCONSTLENGTH("/password:");
                            nextSpace=rtp_strstr(command," ");
                            len = nextSpace?(unsigned) (nextSpace - command): rtp_strlen(command);
                            rtp_memcpy(passwordString, command, len);
                            passwordString[len]=0;
                            smb_cli_term_printf(CLI_ALERT,"Password:%s \n",passwordString);
                            nextSpace=rtp_strstr(command," ");
                        }
                    }
                    if (nextSpace)
                    {
                        /* Now check for dialect */
                        command = nextSpace+1;
                        if (rtp_strnicmp(command,"/dialect:", STRCONSTLENGTH("/dialect:"))==0)
                        {
                            command += STRCONSTLENGTH("/dialect:");
                            nextSpace=rtp_strstr(command," ");
                            len = nextSpace?(unsigned) (nextSpace - command): rtp_strlen(command);
                            rtp_memcpy(dialectString, command, len);
                            dialectString[len]=0;
                            smb_cli_term_printf(CLI_ALERT,"Dialect:%s \n",dialectString);
                            do_get_session_dialect(dialectString);
                            nextSpace=rtp_strstr(command," ");
                        }
                    }
                    /* Test if it's already connected. */
                    if (server_name[0])
                    {
                        int i;
                        int freeConnection=-1;

                        ConnectionNo = -1;
                        for (i =0; i < MAX_CONNECTIONS; i++)
                        {
                            if (Clishell.ClishellConnections[i].server_name[0]==0)
                            {
                                if (freeConnection<0) freeConnection=i;
                            }
                            else if (rtp_strcmp(Clishell.ClishellConnections[i].server_name,server_name)==0)
                            {
                                ConnectionNo = i;
                            }
                        }
                        if (ConnectionNo < 0)
                        {
                            ConnectionNo = freeConnection;
                            rtp_strcpy(Clishell.ClishellConnections[ConnectionNo].server_name,server_name);
                            rtp_strcpy(Clishell.ClishellConnections[ConnectionNo].passwordString,passwordString);
                            rtp_strcpy(Clishell.ClishellConnections[ConnectionNo].userString,userString);
                            DoOpenConnection = TRUE;
                        }
                        if (ConnectionNo < 0)
                        {
                            smb_cli_term_printf(CLI_ALERT,"No connections are available \n");
                            return -1;
                        }

                    }
                }
            }
        }
        else
            doHelp = 1;
    }
    else if (1 || rtp_strnicmp(command,"HELP", 4)==0)
        doHelp = 1;
    if (doHelp)
    {
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use D: \\\\url [/user:name] [/password:password] [/dialect:{0,1,2}]");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use D: (displays info)");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use D: /delete (closes connection)");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net use (lists all connections)");
        smb_cli_term_printf(CLI_PROMPT,"%s\n","net help");
        return 0;
    }

    if (DoOpenConnection)
    {
        //  0==CSSN_DIALECT_PRE_NT, 1==CSSN_DIALECT_NT, 2==CSSN_DIALECT_SMB2_2002:
        //  Fix this later, for now default to /NT dialect
        if (dialectString[0]==0)
            Clishell.ClishellConnections[ConnectionNo].dialect = 1;
        else
            Clishell.ClishellConnections[ConnectionNo].dialect=(int)(dialectString[0]-'0');

        smb_cli_term_printf(CLI_ALERT,"Connecting to %s\n",Clishell.ClishellConnections[ConnectionNo].server_name);
        if (do_connect_server_worker(&Clishell.ClishellConnections[ConnectionNo].sid, Clishell.ClishellConnections[ConnectionNo].server_name, Clishell.ClishellConnections[ConnectionNo].dialect)!=1)
        {
            smb_cli_term_printf(CLI_ALERT,"Failed Connecting to %s\n",Clishell.ClishellConnections[ConnectionNo].server_name);
            return -1;
        }
        smb_cli_term_printf(CLI_ALERT,"Logging on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
        if (do_smb2_logon_server_worker(Clishell.ClishellConnections[ConnectionNo].sid,  Clishell.ClishellConnections[ConnectionNo].userString, Clishell.ClishellConnections[ConnectionNo].passwordString, "domain") < 0)
        {
            smb_cli_term_printf(CLI_ALERT,"Failed Logging on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
            return -1;
        }
    }
    else
    {
        smb_cli_term_printf(CLI_ALERT,"Using existing Log on with username: %s password: %s \n",Clishell.ClishellConnections[ConnectionNo].userString,Clishell.ClishellConnections[ConnectionNo].passwordString);
    }
    if (Clishell.ClishellShares[idNo].shareString[0])
    {
        int sh_val=0;

        Clishell.ClishellShares[idNo].ConnectionNo=ConnectionNo;
        smb_cli_term_printf(CLI_ALERT,"Connecting to sharename : %s \n",Clishell.ClishellShares[idNo].shareString);
        while(!sh_val)
        {
            sh_val = do_connect_share(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid, Clishell.ClishellShares[idNo].shareString);
            if(!sh_val)
            {
                smb_cli_term_printf(CLI_ALERT,"Unknown logon or share. Use SETUSER, SETPASSWORD, SETSHARE for changing values.\n\n");
                return -1;
            }
        }
        smb_cli_term_printf(CLI_ALERT,"Succesfully connected to sharename : %s \n",Clishell.ClishellShares[idNo].shareString);
    }

    return 0;

    /* USE ID \\url:\path /user:name /password:password */
    /* USE ID */
    /* USE ID /delete */
}

// --------------------------------------------------------
/* Helpers, see shel and test */
void mark_rv (int job, int rv, void *data)
{
    int *idata = (int *)data;

    *idata = rv;
    if (rv == -52)
        smb_cli_term_printf("Bad Permissions, Marked = %d\n",*idata);
}

int wait_on_job(int sid, int job)
{
    int rv = RTSMB_CLI_SSN_RV_INVALID_RV;
    int r;

    rtsmb_cli_session_set_job_callback(sid, job, mark_rv, &rv);

    while(rv == RTSMB_CLI_SSN_RV_INVALID_RV )
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

// --------------------------------------------------------
static int do_enum_command(void)
{
  RTSMB_CLI_SESSION_SRVSTAT srvstat;
  char srvname[32];
  int r;
  rtsmb_cli_init( my_ip, (PFBYTE)&my_mask[0]);
  r = rtsmb_cli_session_server_enum_start(&srvstat, NULL, NULL);
  if(r < 0)
  {
    smb_cli_term_printf(CLI_ALERT,"\n could not start the enumeration");
    return 1;
  }
  do
  {
    do
    {
      r = rtsmb_cli_session_server_enum_cycle(&srvstat, 10);
      if(r == 0)
      {
//        smb_cli_term_printf(CLI_PROMPT,"\n In middle of cycling");
      }
    }while(r == 0);
    if(r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
      break;
    }
    else if(r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
       smb_cli_term_printf(CLI_ALERT,"\n Error in cycling");
       return 1;
    }
    do
    {
        r = rtsmb_cli_session_server_enum_next_name_uc(&srvstat, (PFWCS)&srvname[0]);
        if(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
          smb_cli_term_printf(CLI_PROMPT,"Unicode [%ls]\n", (wchar_t *) srvname);
        }
        r = rtsmb_cli_session_server_enum_next_name(&srvstat, srvname);
        if(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
          smb_cli_term_printf(CLI_PROMPT,"[%s]\n", srvname);
        }
    }while(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY);
    if(r != RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        smb_cli_term_printf(CLI_ALERT, "Error getting names");
        return 1;
    }
  }while(1);
  rtsmb_cli_session_server_enum_close(&srvstat);
  rtsmb_cli_shutdown();
  return 0;
}

#if(INCLUDE_RTSMB_CLIENT_NBNS)
// --------------------------------------------------------
static int do_lookup_command(char *nbsname)
{
    RTSMB_NBNS_NAME_QUERY list[20];
    int argc;
    char *argv[2];
    int i;
    int done = 0;

    rtsmb_cli_init(my_ip, (PFBYTE)&my_mask[0]);
    /* Cahnge to multi format soi we don't have to recode */
    argc = 2;
    argv[0] = "unused";
    argv[1] = nbsname;


    for (i=1; i<argc; i++)
    {
        rtsmb_nbns_query_name(&list[i-1], argv[i]);
    }

    smb_cli_term_printf(CLI_PROMPT,"Resolving NetBIOS names...");
    while (!done)
    {
        smb_cli_term_printf(CLI_PROMPT,".");
        rtsmb_nbns_query_cycle(list, argc-1, 1);
//      rtsmb_nbns_query_cycle(list, argc-1, 1000);

        done = 1;
        for (i=0; i<argc-1; i++)
        {
            RTSMB_NBNS_NAME_INFO info[5];
            int num_addrs;

            switch (list[i].status)
            {
            case RTSMB_NBNS_QUERY_STATUS_RESOLVED:
                smb_cli_term_printf(CLI_PROMPT,"\nHost %s resolved: ", list[i].name);
                num_addrs = rtsmb_nbns_get_name_query_response(&list[i], info, 5);
                for (;num_addrs > 0; num_addrs--)
                {
                    smb_cli_term_printf(CLI_PROMPT,"%d.%d.%d.%d \n",
                            info[num_addrs-1].ip_addr[0],
                            info[num_addrs-1].ip_addr[1],
                            info[num_addrs-1].ip_addr[2],
                            info[num_addrs-1].ip_addr[3]);
                }

            case RTSMB_NBNS_QUERY_STATUS_ERROR:
                rtsmb_nbns_close_query(&list[i]);
                break;

            case RTSMB_NBNS_QUERY_STATUS_TIMEOUT:
                smb_cli_term_printf (CLI_ALERT,"\nQuery: %s timed out \n", list[i].name);
                rtsmb_nbns_close_query(&list[i]);
                break;

            case RTSMB_NBNS_QUERY_STATUS_PENDING:
                done = 0;
                break;
            }
        }
    }

    rtsmb_cli_shutdown();
    return 0;
}
#endif
// --------------------------------------------------------
static int do_enum_shares_command(void)
{
    int r, sid;
    RTSMB_CLI_SESSION_SSTAT sstat;

    rtsmb_cli_init(my_ip, (PFBYTE)&my_mask[0]);

    if (!do_connect_server(&sid))
        return(0);
    if (!do_logon_server(sid))
        return(0);

    /* now enumerate the shares on this server */
    r = rtsmb_cli_session_share_find_first(sid, &sstat);
    if (r < 0)
    {
        smb_cli_term_printf (CLI_ALERT,"Share enumeration failed!\n");
        return 1;
    }
    r = wait_on_job(sid, r);
    while (r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
        //char temp[200];
        //rtsmb_util_rtsmb_to_ascii (sstat.name, temp, 0);
        smb_cli_term_printf(CLI_PROMPT,"Found share: %s\n", sstat.name);
        r = rtsmb_cli_session_share_find_next(sid, &sstat);
        if (r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
            if (r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
                break;
            if (r < 0)
            {
                smb_cli_term_printf (CLI_ALERT,"Share enumeration failed!\n");
                return 1;
            }
            r = wait_on_job(sid, r);
        }
    }
    rtsmb_cli_session_share_find_close(sid, &sstat);
    rtsmb_cli_shutdown();
    return(0);
}

// --------------------------------------------------------
static const char *month_names[] =
{
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};


static int do_logoff_command(char *command)
{
    if (*command==0)
    {
        smb_cli_term_printf(CLI_PROMPT,"%s \n", "usage: LOGOFF a:");
        return 0;
    }
    else
    {
        int idNo;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].server_name[0]=0;
        if (do_get_session_dialect(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid) >= CSSN_DIALECT_SMB2_2002)
          return do_smb2_tree_disconnect_worker(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid);
        else
          return rtsmb_cli_session_logoff_user(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid);
    }
}

// FormatDirscanToDstat) is in cpp with aligned data but it calls this function
extern int FormatDirscanToDstat(void *pBuffer);
void DisplayDirscan(PRTSMB_CLI_SESSION_DSTAT pstat)
{
  char temp[300];
  rtsmb_util_rtsmb_to_ascii ((PFRTCHAR) pstat->filename, temp, 0);
  {
     DATE_STR d;
     RTP_DATE rtpDateStruct;
     dword  unix_time = rtsmb_util_time_date_to_unix (rtsmb_util_time_ms_to_date (/*(TIME)*/pstat->fctime64));
     char attrib_string[8];
     byte fattributes = (byte)pstat->fattributes;

     if (fattributes & RTP_FILE_ATTRIB_ISDIR) // RTP_FILE_ATTRIB_ISDIR)
         attrib_string[0] = 'd';
     else
         attrib_string[0] = '_';
     attrib_string[1] = 'r';
     if ((fattributes & RTP_FILE_ATTRIB_RDONLY)==0) // RTP_FILE_ATTRIB_ISDIR)
       attrib_string[2] = 'w';
     else
       attrib_string[2] = '_';
     attrib_string[3] = 0;

     rtpDateStruct =  rtsmb_util_time_unix_to_rtp_date (unix_time);

     smb_cli_term_printf(CLI_PROMPT,"%s %s %2d %4d, %8d %s\n", attrib_string,month_names[(rtpDateStruct.month-1)%12], (int)rtpDateStruct.day, (int)rtpDateStruct.year,  (int)pstat->fsize, temp);
  }
}



/// Protototype "device for sinking bytes from a stream.
/// This memcopies to a location stored in device context.
int ls_sink_function(void *devContext, byte *pData, int size)
{
//  tc_memcpy( ((struct memcpydevContext *)devContext)->pData, pData,size);
//  ((struct memcpydevContext *)devContext)->pData += size;
//  ((struct memcpydevContext *)devContext)->bytes_left -= size;

  rtp_printf("ls_sink_function size = %d\n", size);
  int fmt_size = FormatDirscanToDstat(pData);
  rtp_printf("ls_sink_function size = %d %d \n", size, fmt_size);
  return fmt_size;
}


static int _do_ls_command_worker(int doLoop,int sid, char *sharename,char *pattern);

static int do_ls_command_worker(int doLoop,int sid, char *sharename,char *pattern)
{
  if (do_get_session_dialect(sid) >= CSSN_DIALECT_SMB2_2002)
    return do_smb2_querydirectory_worker(sid,  sharename, pattern);
  else
    return _do_ls_command_worker(doLoop, sid,  sharename, pattern);
}
static int _do_ls_command_worker(int doLoop,int sid, char *sharename,char *pattern)
{

    RTSMB_CLI_SESSION_DSTAT dstat1;
    smb_cli_term_printf(CLI_ALERT,"performing LS on %s\\%s \n", sharename, pattern);
    do
    {
        // pass callbacks to smb2 stream layer through the stat structure
        int r1;
        r1 = rtsmb_cli_session_find_first(sid, sharename, pattern, &dstat1);
        if(r1 < 0)
        {
          smb_cli_term_printf(CLI_ALERT,"\n Error getting files\n");
          return 1;
        }
        r1 = wait_on_job(sid, r1);
        while(r1 == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {  // SMB1 stuff
            char temp[200];

            rtsmb_util_rtsmb_to_ascii ((PFRTCHAR) dstat1.filename, temp, 0);
            {
                DATE_STR d;
                RTP_DATE rtpDateStruct;
                dword  unix_time = rtsmb_util_time_date_to_unix (rtsmb_util_time_ms_to_date (/*(TIME)*/dstat1.fctime64));
                char attrib_string[8];
                byte fattributes = (byte)dstat1.fattributes;

                if (fattributes & RTP_FILE_ATTRIB_ISDIR) // RTP_FILE_ATTRIB_ISDIR)
                    attrib_string[0] = 'd';
                else
                    attrib_string[0] = '_';
                attrib_string[1] = 'r';
                if ((fattributes & RTP_FILE_ATTRIB_RDONLY)==0) // RTP_FILE_ATTRIB_ISDIR)
                  attrib_string[2] = 'w';
                else
                  attrib_string[2] = '_';
                attrib_string[3] = 0;


                rtpDateStruct =  rtsmb_util_time_unix_to_rtp_date (unix_time);

                smb_cli_term_printf(CLI_PROMPT,"%s %s %2d %4d, %8d %s\n", attrib_string,month_names[(rtpDateStruct.month-1)%12], (int)rtpDateStruct.day, (int)rtpDateStruct.year,  (int)dstat1.fsize, temp);
            }
        } r1 = rtsmb_cli_session_find_next(sid, &dstat1);
        rtsmb_cli_session_find_close(sid, &dstat1);
    } while(doLoop);
    return 0;
}

static int do_prompt_ls_command(int doLoop)
{
    RTSMB_CLI_SESSION_DSTAT dstat1;
    int sid;
    char *sharename;
    char pattern[256];
    int srv_val = 0;
    int log_val = 0;
    int sh_val = 0;

    while(!srv_val)
    {
        srv_val = do_connect_server(&sid);
        smb_cli_term_printf(CLI_ALERT,"\ndo_connect_server returns %d\n ",srv_val);
        if(!srv_val)
        {
            smb_cli_term_printf(CLI_ALERT,"\nUnknown Server. Use SETSERVER for changing the value.\n ");
            return 0;
        }
    }

    while(!log_val)
    {
        log_val = do_logon_server(sid);
        if(!log_val)
        {
            smb_cli_term_printf(CLI_ALERT,"\nUnknown user or wrong password. Please check.\n");
            return 0;
        }
    }

    sharename = do_getshare_name();
    while(!sh_val)
    {
        sh_val = do_connect_share(sid, sharename);
        if(!sh_val)
        {
            smb_cli_term_printf(CLI_ALERT,"Unknown logon or share. Use SETUSER, SETPASSWORD, SETSHARE for changing values.\n\n");
            return 0;
        }
    }
    smbcli_prompt("Pattern (* always works):  ", pattern, 256);

    do_ls_command_worker(doLoop,sid,sharename,pattern);
    rtsmb_cli_shutdown();
    return 0;
}




static int do_ls_command(char *command)
{
     printf("Yo 0 |%s|\n", command);
    if (*command==0)
    {
        printf("Yo 1\n");
        return do_prompt_ls_command(FALSE);
    }
    else
    {
        int idNo;
        printf("Yo 2\n");
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        // if there's a pattern use it, otherwise use '*'
        if (command[2])
          return do_ls_command_worker(FALSE,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,&command[2]);
        else
          return do_ls_command_worker(FALSE,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,"*");
    }
}

static int do_file_command_worker_complete(RtsmbCliFile *pFile, int r, char *Operation)
{
    if(r >= 0)
        r = wait_on_job(pFile->session_id, r);
    if(r < 0)
        smb_cli_term_printf(CLI_ALERT,"\n Error: %s\n", Operation);
    return r;
}
static int do_file_command_open_worker(int SessionId,RtsmbCliFile *pFile,char *sharename, char *filename, word options,word flags)
{
int r;
    pFile->session_id      = SessionId;
printf("OPening share==%s file==%s\n", sharename, filename);
    r = rtsmb_cli_session_open(pFile->session_id,  sharename, filename, options, flags, &pFile->session_fid);
    r = do_file_command_worker_complete(pFile, r, "Opening file");
    if(r < 0)
    {
        pFile->session_id      = 0;
        pFile->session_fid      = -1;
    }
   return r;

}
static int do_file_command_close_worker(RtsmbCliFile *pFile)
{
int r;
    r = rtsmb_cli_session_close(pFile->session_id, pFile->session_fid);
    r = do_file_command_worker_complete(pFile, r, "Close file");
    return r;
}
static int do_file_command_io_worker(RtsmbCliFile *pFile,void *buffer, int count, BBOOL isRead)
{
int r,transferred;
    if (isRead)
    {
        r = rtsmb_cli_session_read(pFile->session_id, pFile->session_fid, buffer, count, &transferred);
        r = do_file_command_worker_complete(pFile, r, "Reading");
    }
    else
    {
        r = rtsmb_cli_session_write(pFile->session_id, pFile->session_fid, buffer, count, &transferred);
        r = do_file_command_worker_complete(pFile, r, "Writing");
    }
    if(r < 0)
        transferred=-1;
    return transferred;
}


static int do_file_command_worker(int which_command,int sid, char *sharename, char *filename)
{
/*  RTSMB_CLI_SESSION_DSTAT dstat1; */
    int transferred;
    long total_transferred =0;
    int r,fd,l;
    RtsmbCliFile MyFile;
    RtsmbCliFile *pFile=&MyFile;
    if (which_command == WRITE_COMMAND)
    {
        r = do_file_command_open_worker(sid,pFile,sharename, filename,RTP_FILE_O_CREAT|RTP_FILE_O_RDWR|RTP_FILE_O_TRUNC,RTP_FILE_S_IWRITE|RTP_FILE_S_IREAD);
    }
    else
    {
        r = do_file_command_open_worker(sid,pFile,sharename, filename,RTP_FILE_O_RDONLY,RTP_FILE_S_IREAD);
    }
    if(r < 0)
        return 1;
    if (which_command == WRITE_COMMAND)
    {
        smb_cli_term_printf(CLI_ALERT,"Filling a file with hello world \n");
    }
    l = 0;
    for(;;)
    {
        transferred = 0;
        if (which_command == WRITE_COMMAND)
        {
            rtp_sprintf(shell_buffer, "(%d) - Hello again world from %s\n",l++, filename);
            r = do_file_command_io_worker(pFile,shell_buffer, (int)rtp_strlen(shell_buffer), FALSE);
        }
        else if (which_command == READ_COMMAND)
            r = do_file_command_io_worker(pFile,shell_buffer, 512, TRUE);
        else if (which_command == CAT_COMMAND)
            r = do_file_command_io_worker(pFile,shell_buffer, 80, TRUE);
        if(r < 0)
        {
            smb_cli_term_printf(CLI_ALERT,"\n Error transferring data");
            transferred=0;
            break;
        }
        else
           transferred=r;
        if (transferred <= 0)
            break;
        if (which_command == CAT_COMMAND)
            smb_cli_term_printf(CLI_PROMPT,"%s", shell_buffer);
        total_transferred += transferred;
        /* Th write just does writes 100 times, read stops at eof */
        if (which_command == WRITE_COMMAND && l > 100)
            break;
    }
    smb_cli_term_printf(CLI_PROMPT,"\n numbytes transfered is %ld\n", total_transferred);
    if (do_file_command_close_worker(pFile) < 0)
        return 0;
    return 0;
}

static int do_prompt_file_command(int which_command)
{
/*  RTSMB_CLI_SESSION_DSTAT dstat1; */
    long total_transferred =0;
    int sid;
    int r;
    char *sharename;
    char filename[256];

    if (!do_connect_server(&sid))
        return(0);
    if (!do_logon_server(sid))
        return(0);

    sharename = do_getshare_name();
    if (!do_connect_share(sid, sharename))
        return(0);

    smbcli_prompt("Filename :  ", filename, 256);

    r = do_file_command_worker(which_command, sid, sharename, filename);
    rtsmb_cli_shutdown();
    return r;
}

static int do_file_command(int which_command, char *command)
{
  if (*command==0)
  {
    return do_prompt_file_command(which_command);
  }
  else
      {
        int idNo;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        command += 3;
        return do_file_command_worker(which_command,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,command);
    }
}
static int do_fhandle_open_command(char *command)
{
char *command_start = command;
char *filename_start = command;
char *mode_start = 0,*q=0;
word mode, flags;
int r;
int idNo, fdno;

    idNo=CmdToDrvId(command);
    if (idNo<0)
    {
        return -1;
    }
    command += 2;

    q = rtp_strstr(command,"\"");
    if (q)
    {
        command++;
        filename_start = command;
        q = rtp_strstr(command,"\"");
        if (!q)
        {
            smb_cli_term_printf(CLI_ALERT,"do_fhandle_open_command: Bad arguments\n");
            return -1;
        }
        *q = '0';
        mode_start = rtp_strstr(q+1," ");
    }
    else
    {
        command = rtp_strstr(command," ");
        if (!command)
        {
            smb_cli_term_printf(CLI_ALERT,"do_fhandle_open_command: Bad arguments\n");
            return -1;
        }
        command++;
        filename_start = command;
        mode_start = rtp_strstr(command," ");
    }

    if (!mode_start)
    {
        mode = RTP_FILE_O_RDONLY;
        flags = RTP_FILE_S_IREAD;
    }
    else
    {
        *mode_start++ = 0; /* Null trerminate file */
        mode = (word)RTP_FILE_O_CREAT|RTP_FILE_O_RDONLY;
        flags = RTP_FILE_S_IREAD;
        while(*mode_start)
        {
            if (*mode_start=='W' || *mode_start=='w')
            {
                mode &= (word)(~RTP_FILE_O_RDONLY);
                mode |= (word)RTP_FILE_O_RDWR;
                flags |= (word)RTP_FILE_S_IWRITE;
            }
            if (*mode_start=='T' || *mode_start=='t')
                mode |= (word)RTP_FILE_O_TRUNC;
            if (*mode_start=='E' || *mode_start=='e')
                mode &= (word)(~RTP_FILE_O_CREAT);
            mode_start++;
        }
        if ((mode & RTP_FILE_O_RDWR)!=RTP_FILE_O_RDWR)
            mode &= (word)(~RTP_FILE_O_CREAT);
    }

//TABLE_SIZE(Clishell.ClishellFiles

//    Clishell.ClishellFiles[fdno].fid;
//    Clishell.ClishellFiles[fdno].session_fid;
//    Clishell.ClishellFiles[fdno].session_id;

printf("FH OPening share==%s file==%s\n", Clishell.ClishellShares[idNo].shareString,filename_start);

    for (fdno=0; fdno< MAX_FILES; fdno++)
    {
        if (Clishell.ClishellFiles[fdno].session_id==0)
            break;
    }
    if (fdno == MAX_FILES)
    {
        smb_cli_term_printf(CLI_PROMPT,"do_fhandle_open_command: Out of files\n");
        return -1;
    }
    r = do_file_command_open_worker(Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,&Clishell.ClishellFiles[fdno],
                                        Clishell.ClishellShares[idNo].shareString,  filename_start, mode,flags);
    if (q)
        *q = '\"';
    if (r >= 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"do_fhandle_open_command: File succesfully opened with fdno == %d\n", fdno);
    }
    else
        smb_cli_term_printf(CLI_PROMPT,"do_fhandle_open_command: File opened failed\n");
    return r;
}

static int do_fhandle_close_command(char *command)
{
int fdno;
    fdno=CmdToFdno(command);
    if (fdno<0)
        return -1;
    return do_file_command_close_worker(&Clishell.ClishellFiles[fdno]);
}
/* read fdno count */
static int do_fhandle_aread_command(char *command)
{
int r,fdno,lines;
    fdno=CmdToFdno(command);
    if (fdno<0)
        return -1;
    command += 2;
    if (fdno>9) command++;
    lines = (int)rtp_atol(command);
    if (lines < 0)
        lines = 32765;
    do {
        int i;
        r = do_file_command_io_worker(&Clishell.ClishellFiles[fdno],shell_buffer, 80, TRUE);
        if (r <= 0)
            break;
        shell_buffer[r]=0;
        for (i =0; i < r; i++)
            if (shell_buffer[i] == '\n')
                lines -= 1;
        smb_cli_term_printf(CLI_PROMPT,"%s",shell_buffer);
    } while (r>0 && lines > 0);
    return 0;
}

/* read fdno count */
static int do_fhandle_read_command(char *command)
{
    return 0;
}
static int do_fhandle_awrite_command(char *command)
{
    int r=0,lines =0,nbytes=0,prev=0;
    int fdno=CmdToFdno(command);
    if (fdno<0)
        return -1;

    smb_cli_term_printf(CLI_PROMPT,"Type in lines into the file. Type 2 empty lines to stop.\n");
    smb_cli_term_printf(CLI_PROMPT,"Preceed a line with !### to repeat the line ### times.\n");
    prev=0;
    do {
        int prev,l,repeat;
        char *p=shell_buffer;

        repeat = 1;
        smbcli_prompt("> ", shell_buffer, sizeof(shell_buffer));
        if (*p=='!')
        {
            p = rtp_strstr(shell_buffer," ");
            if (p)
            {
                *p=0;
                repeat = (int)rtp_atol(shell_buffer+1);
                p+=1;
            }
            else
                p = shell_buffer;
        }
        l = (int)rtp_strlen(p);
        shell_buffer[l++] = '\n';
        shell_buffer[l] = 0;
        if (l == 1 && prev==1)
            break;
        prev=l;
        while(repeat--)
        {
            r = do_file_command_io_worker(&Clishell.ClishellFiles[fdno],shell_buffer, l, FALSE);
            if (r <= 0)
                break;
            lines++;
            nbytes+=r;
        }
    } while (r>0);
    smb_cli_term_printf(CLI_PROMPT,"lines/bytes sent = %d %d\n", lines, nbytes);
    return 0;
}

static int do_fhandle_write_command(char *command)
{
    smb_cli_term_printf(CLI_PROMPT,"do_fhandle_write_command: %s\n", command);
    return 0;
}
static int do_fhandle_seek_command(char *command)
{
    smb_cli_term_printf(CLI_PROMPT,"do_fhandle_seek_command: %s\n", command);
    return 0;
}
static int do_fhandle_stat_command(char *command)
{
    smb_cli_term_printf(CLI_PROMPT,"do_fhandle_stat_command: %s\n", command);
    return 0;
}

static int do_dir_command_worker(int which_command,int sid,char *sharename,char *filename)
{
    int r;
    switch(which_command) {
        case DEL_COMMAND:
            r = rtsmb_cli_session_delete(sid, sharename, filename);
            break;
        case MKDIR_COMMAND:
            r = rtsmb_cli_session_mkdir(sid, sharename, filename);
            break;
        case RMDIR_COMMAND:
            r = rtsmb_cli_session_rmdir(sid, sharename, filename);
            break;
    }
    if(r < 0)
    {
failed:
        smb_cli_term_printf(CLI_ALERT,"Error executing command \n");
        return 0;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
        goto failed;
    return 0;
}

static int do_prompt_dir_command(int which_command)
{
    int sid;
    int r;
    char *sharename;
    char filename[256];

    if (!do_connect_server(&sid))
        return(0);
    if (!do_logon_server(sid))
        return(0);

    sharename = do_getshare_name();
    if (!do_connect_share(sid, sharename))
        return(0);

    smbcli_prompt("Name :  ", filename, 256);

    r = do_dir_command_worker(which_command,sid, sharename,filename);
    if(r < 0)
    {
        return 0;
    }
    rtsmb_cli_shutdown();
    return 0;
}

static int do_dir_command(int which_command, char *command)
{
  if (*command==0)
  {
    return do_prompt_dir_command(which_command);
  }
  else
      {
        int idNo;
        idNo =CmdToDrvId(command);
        if (idNo < 0)
            return 0;
        command += 3;
        return do_dir_command_worker(which_command,Clishell.ClishellConnections[Clishell.ClishellShares[idNo].ConnectionNo].sid,Clishell.ClishellShares[idNo].shareString,command);
    }
}



static int do_loop_command()
{
    do_prompt_ls_command(TRUE);

    return 0;
}

int looks_like_ip_addr(char *server_name)
{
    char *cur = server_name;
    int numPeriods=0;
    while('\0' != *cur)
    {
        if('.' == *cur)
            numPeriods++;

        cur++;
    }

    return (3 == numPeriods);
}

static int do_connect_server_worker(int *sid,char *server_name, RTSMB_CLI_SESSION_DIALECT dialect)
{
    int r;
    int i;

    smb_cli_term_printf(CLI_ALERT,"Connecting to server: %s\n",server_name);

    rtsmb_cli_init(my_ip, (PFBYTE)&my_mask[0]);
    if(looks_like_ip_addr(server_name))
    {
        int scanVals[4];
        BYTE ip[4];
        sscanf(server_name, "%d.%d.%d.%d", scanVals, scanVals+1, scanVals+2, scanVals+3);
        for(i=0; i<4; i++)
            ip[i] = (BYTE)scanVals[i];
        r = rtsmb_cli_session_new_with_ip (ip, NULL, FALSE, sid, dialect);
    }
    else
    {
        r = -1;
#if (INCLUDE_RTSMB_CLIENT_NBNS)
        r = rtsmb_cli_session_new_with_name(server_name, FALSE, NULL, sid, dialect);
#endif
    }

    if(r < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\n rtsmb_cli_session_new: Error starting session with server %s", server_name);
    }
    r = wait_on_job(*sid, r);
    if(r < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\nError Creating Session with server %s", server_name);
        return 0;
    }
    //if(r < 0)
    //{
    //  smb_cli_term_printf(CLI_PROMPT,"\n Error during session create ??");
    //  return 0;
    //}
    return(1);
}

static int do_connect_server(int *sid)
{
    char *server_name;
    RTSMB_CLI_SESSION_DIALECT dialect;

    //smbcli_prompt("Server: ", gl_server_name);
    server_name = do_getserver_name(0);
    dialect = do_get_session_dialect(0);

    smb_cli_term_printf(CLI_ALERT,"server = %s\n",server_name);

    return do_connect_server_worker(sid, server_name, dialect);
}

#include "clicfg.h"
#include "clissn.h"

// static int do_logon_server_worker(int sid,  char *user_name, char *password, char *domain); // done in cpp now
static int do_logon_server(int sid)
{
    char *user_name;
    char *password;
    char *domain;
    RTSMB_CLI_SESSION_DIALECT dialect;
    user_name = do_getuser_name();
    password = do_getpassword();
    domain = do_getdomain_name();

    dialect = do_get_session_dialect(sid);
    if (dialect >= CSSN_DIALECT_SMB2_2002)
      return do_smb2_logon_server_worker(sid,  user_name, password, domain);
    else
    // SMB1 is broken, TBD
     return do_smb2_logon_server_worker(sid,  user_name, password, domain);

}


static int do_connect_share(int sid, char *sharename)
{
    int r1;

    if ( do_get_session_dialect(sid) >= CSSN_DIALECT_SMB2_2002)
      return do_smb2_tree_connect_worker(sid,  sharename, "");
    // else use smb1
    r1 = rtsmb_cli_session_connect_share(sid, sharename, "");
    if (r1 < 0)
    {

        smb_cli_term_printf(CLI_PROMPT,"\n Error connecting to share\n");
        return 0;
    }
    r1 = wait_on_job(sid, r1);

    if(r1 < 0)// || r2 < 0)
    {
        smb_cli_term_printf(CLI_PROMPT,"\n Error during connect to share response\n");
        return 0;
    }
    return 1;
}

/* Tools for inputting server, share, user password.. these save a lot of typing */
char gl_server_name[128]= {'1','9','2','.','1','6','8','.','1','.','6',0};
static int  server_name_is_set=1;
static char *do_getserver_name(char *pnewservername)
{
    if (pnewservername)
    {
      tc_strcpy(gl_server_name, pnewservername);
      server_name_is_set=1;
    }
    else if (!server_name_is_set)
        do_setserver_command();
    return(&gl_server_name[0]);
}
static RTSMB_CLI_SESSION_DIALECT do_get_session_dialect(char *pnewdialect)
{
static int  dialog_is_set;
static char gl_dialog_string[32];
    if (pnewdialect)
    {
       tc_strcpy(gl_dialog_string, pnewdialect);
       dialog_is_set=1;
    }
    while (!dialog_is_set)
    {
        smbcli_prompt("Select dialect: 0==CSSN_DIALECT_PRE_NT, 1==CSSN_DIALECT_NT, 2==CSSN_DIALECT_SMB2_2002: ", gl_dialog_string, 32);
        if (gl_dialog_string[0]>='0'&&gl_dialog_string[0]<='2')
            dialog_is_set=1;

    }
    return((RTSMB_CLI_SESSION_DIALECT)(gl_dialog_string[0]-'0'));
}


static int do_setserver_command(void)
{
#if (HISTORY_MODE)
    server_name_is_set = 1;
#endif
    smbcli_prompt("Server: ", gl_server_name, 128);
    return(1);
}
char gl_user_name[128];
int  user_name_is_set;
static char *do_getuser_name(void)
{
    if (!user_name_is_set)
        do_setuser_command();
    return(&gl_user_name[0]);
}

char gl_domain_name[128];
int  domain_name_is_set;
static char *do_getdomain_name(void)
{
    if (!domain_name_is_set)
        do_setdomain_command();
    return(&gl_domain_name[0]);
}

static int do_setuser_command(void)
{
#if (HISTORY_MODE)
    user_name_is_set = 1;
#endif
    smbcli_prompt("user: ", gl_user_name, 128);
    if (!gl_user_name[0])
    { /* Does not like an ampty string.. investigate */
        gl_user_name[0] = ' ';
        gl_user_name[1] = 0;
    }
    return(1);
}
static int do_setdomain_command(void)
{
#if (HISTORY_MODE)
    domain_name_is_set = 1;
#endif
    smbcli_prompt("domain: ", gl_domain_name, 128);
    return(1);
}

char gl_password[128];
int  password_name_is_set;
static char *do_getpassword(void)
{
    if (!password_name_is_set)
        do_setpassword_command();
    return(&gl_password[0]);
}
static int do_setpassword_command(void)
{
#if (HISTORY_MODE)
    password_name_is_set = 1;
#endif
    smbcli_prompt("password: ", gl_password, 128);
    return(1);
}
char gl_share_name[128];
int  share_name_is_set;
static char *do_getshare_name(void)
{
    if (!share_name_is_set)
        do_setshare_command();
    return(&gl_share_name[0]);
}
static int do_setshare_command(void)
{
#if (HISTORY_MODE)
    share_name_is_set = 1;
#endif
    smbcli_prompt("share: ", gl_share_name, 128);
    return(1);
}
static void in_ipaddress(byte *pip, byte *pmask_ip)
{
    byte counter;
    for (counter=0;counter<4;counter++)
    {
    char inbuffer[32];
    char inbuffer2[32];
        rtp_itoa(pip[counter], inbuffer, 10);
        smb_cli_term_printf(CLI_PROMPT,"Byte %d IP Address %s :",counter,inbuffer);
        smbcli_prompt("return to keep or new value:", inbuffer2, 0);
//        rtp_term_promptstring (inbuffer, 0);
        if (inbuffer2[0])
         pip[counter] = (unsigned char)rtp_atoi(inbuffer2);
        else
         pip[counter] = (unsigned char)rtp_atoi(inbuffer);
    }
    for (counter=0; counter<4; counter++)
    {
    char inbuffer[32];
    char inbuffer2[32];
        rtp_itoa(pmask_ip[counter], inbuffer, 10);
        smb_cli_term_printf(CLI_PROMPT,"Byte %d IP Mask %s :",counter,inbuffer);
//        rtp_term_promptstring (inbuffer, 0);
        smbcli_prompt("return to keep or new value:", inbuffer2, 0);
        if (inbuffer2[0])
         pmask_ip[counter] = (unsigned char)rtp_atoi(inbuffer2);
        else
         pmask_ip[counter] = (unsigned char)rtp_atoi(inbuffer);
    }
    smb_cli_term_printf(CLI_PROMPT,"IP Address: %d.%d.%d.%d\n",pip[0],pip[1],pip[2],pip[3]);
    smb_cli_term_printf(CLI_PROMPT,"IP Mask   : %d.%d.%d.%d\n",pmask_ip[0],pmask_ip[1],pmask_ip[2],pmask_ip[3]);

}

#include "clicfg.h"

static const char *SessionStateName[] = {"UNUSED", "DEAD  ", "QUERYING", "CONNECTING", "UNCONNECTED",
                                  "NEGOTIATED", "RECOVERY_QUERYING", "RECOVERY_NEGOTIATING",
                                  "RECOVERY_NEGOTIATED", "RECOVERY_LOGGING_ON",
                                  "RECOVERY_LOGGED_ON", "RECOVERY_TREE_CONNECTING",
                                  "RECOVERY_TREE_CONNECTED", "RECOVERY_FILE_OPENING",
                                  "RECOVERY_FILE_OPENED"};

//const char *UserStateName[] = {"UNUSED", "LOGGING ON", "LOGGED ON", "DIRTY"};
static const char *ShareStateName[] = {"UNUSED", "CONNECTING", "CONNECTED", "DIRTY"};
static const char *JobStateName[] = {"UNUSED", "FAKE  ", "STALLED", "WAITING", "DIRTY"};
//const char *ServerSearchStateName[] = {"UNUSED", "BACK UP", "LOGGING ON", "REQUESTING", "DATA READY",
//                                       "BACKUP AGAIN", "DONE LOCAL", "FINISH"};



static int do_cli_info (void)
{
    int session, job, share,fid,search_sid;
//  PRTSMB_CLI_SESSION_SHARE pShare;
//  PRTSMB_CLI_SESSION_JOB pJob;
//  PRTSMB_CLI_SESSION pSession;

    for (session = 0; session < prtsmb_cli_ctx->max_sessions; session++)
    {

        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Session %d: %s. \n",session, SessionStateName[prtsmb_cli_ctx->sessions[session].state]);
        if (prtsmb_cli_ctx->sessions[session].state == CSSN_STATE_UNUSED)
            continue;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "    Server Name:      %s \n", prtsmb_cli_ctx->sessions[session].server_name);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "    Current Job Queue For Session\n", 0);
        for (job = 0; job < prtsmb_cli_ctx->max_jobs_per_session; job++)
        {
            if (prtsmb_cli_ctx->sessions[session].jobs[job].state == CSSN_JOB_STATE_UNUSED)
                continue;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Job State:            %s \n", JobStateName[prtsmb_cli_ctx->sessions[session].jobs[job].state]);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Request Message Id:   %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].mid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Send  Retry count:    %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].send_count);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Reconnect Count:      %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].die_count);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Reconnect Count:      %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].die_count);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        response Value:       %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].response);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        error    Value:       %d \n", prtsmb_cli_ctx->sessions[session].jobs[job].error);
        }
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "    Current Shares For The Session\n", 0);
        for (share = 0; share < prtsmb_cli_ctx->max_shares_per_session; share++)
        {
            if (prtsmb_cli_ctx->sessions[session].shares[share].state == CSSN_SHARE_STATE_UNUSED)
                continue;
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Share Name:           %s \n", prtsmb_cli_ctx->sessions[session].shares[share].share_name);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Password  :           %s \n", prtsmb_cli_ctx->sessions[session].shares[share].password);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Tree Id   :           %d \n", (int)prtsmb_cli_ctx->sessions[session].shares[share].tid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Connect Mid :         %d \n", (int)prtsmb_cli_ctx->sessions[session].shares[share].connect_mid);
        }
        for (fid = 0; fid < prtsmb_cli_ctx->max_fids_per_session; fid++)
        {
            if (prtsmb_cli_ctx->sessions[session].fids[fid].real_fid == CSSN_FID_STATE_UNUSED)
            {
                continue;
            }
            if (prtsmb_cli_ctx->sessions[session].fids[fid].real_fid == CSSN_FID_STATE_DIRTY)
            {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Real FileId:           %s \n", "Dirty. Must be reopened");
            }
            else
            {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        File Name:                %s \n", (int)prtsmb_cli_ctx->sessions[session].fids[fid].name);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Real FileId:              %d \n", prtsmb_cli_ctx->sessions[session].fids[fid].real_fid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Smb  FileId:              %d \n", (int)prtsmb_cli_ctx->sessions[session].fids[fid].smb_fid);
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Cached Offset:            %d \n", (int)prtsmb_cli_ctx->sessions[session].fids[fid].offset);
                if (prtsmb_cli_ctx->sessions[session].fids[fid].owning_share && prtsmb_cli_ctx->sessions[session].fids[fid].owning_share->share_name)
                {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Owning Share :            %s \n", prtsmb_cli_ctx->sessions[session].fids[fid].owning_share->share_name);
                }
                else
                {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "        Owning Share :            %s \n", "Lost");
                }
            }
//      prtsmb_cli_ctx->sessions[session].fids[fid].flags;
//      prtsmb_cli_ctx->sessions[session].fids[fid].mode;
        }

        for (search_sid = 0; search_sid < prtsmb_cli_ctx->max_searches_per_session; search_sid++)
        {
            if (prtsmb_cli_ctx->sessions[session].searches[search_sid].sid == -1)
                continue;
        }
//      pSession->user.state = CSSN_USER_STATE_UNUSED;
//      pSession->anon.state = CSSN_USER_STATE_UNUSED;

//      prtsmb_cli_ctx->sessions[i].share_search
//      prtsmb_cli_ctx->sessions[i].psmb2Session
//      prtsmb_cli_ctx->sessions[i].timestamp; /* tells how long it's been since the session has been used */

//      prtsmb_cli_ctx->sessions[i].wire;

//      prtsmb_cli_ctx->sessions[i].state;

//      prtsmb_cli_ctx->sessions[i].server_info;

//      prtsmb_cli_ctx->sessions[i].user;
//      prtsmb_cli_ctx->sessions[i].anon;   /* an anonymous user we have as a fallback */

    }
    return 0;
}


/*---------------------------------------------------------------------------*/



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
