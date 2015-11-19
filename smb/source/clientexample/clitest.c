#include "cliapi.h"
#include "smbutil.h"
#include "rtpnet.h"
#include "rtpstr.h"
#include "rtpprint.h"
#include "clirpc.h"
#include "clsrvsvc.h"
#include "wchar.h"

extern unsigned char my_ip[];
extern unsigned char my_mask[];

#define TEST_BUFFER_SIZE 163850 // a really big buffer
char buffer[TEST_BUFFER_SIZE];
void smb_cli_shell(void);


#define TEST_DIALECT CSSN_DIALECT_NT


/* Instructions..

EBS CIFS SMB Client exerciser test,,


    This test is designed to run with a specific configuration (see below)
    The command shell provides a simpler interactive way to exersize the SMB
    client library. And we recommend you use it if possible


To run the test..

    Setting up the server:

        First make sure that these are both enabled:

            "File and Printer Sharing For Microsoft Network"
            Enable Netbios over TCP-IP

        The server must have a share named "testfolder" with read/write permission for the user

        create the share on the server named "testfolder"

        Do this by creating a subdirectory named "testfolder"

        then from explorer:

            right click on "testfolder"
            select sharing and security
            click on Share this folder
            click on Allow users to change files

        Place a file in "testfolder" named "cifs_download.dat". Any file will do, but its
        presence is required for the tests to proceed.

    Modify configuration constants in this file (climain.c)

        TEST_SERVER_NAME        - The name of the server described above
        TEST_USER_NAME          - User Name for logging in to server
        TEST_USER_PASSWORD      - Password for user, or "" if no password required

    Initialize the following variables


        The default configuration is:
           The user id and password are:
                username rachel
                password nonerequired
           To determine your user name on the server see:
            control panel/system properties/computer name
           To find user names
            control panel/user accounts

           To start, use a user account with no password.


*/

/* Change these four lines for your environment */
#define TEST_SERVER_NAME    "peter"
#define TEST_USER_NAME      "smbtestuser"
#define TEST_USER_PASSWORD  ""
#define TEST_DOMAIN_NAME    "MSHOME"

#define TEST_SHARE_1        "testfolder"
char* writeTestArgs[]    = {"unused", TEST_SERVER_NAME, TEST_SHARE_1, "dump2.txt"};
char* downloadTestArgs[] = {"unused", TEST_SERVER_NAME, TEST_SHARE_1, "cifs_download.dat"};
char* uploadTestArgs2[]   = {"unused", TEST_SERVER_NAME, TEST_SHARE_1, "cifs_upload.dat"};
char* rpcTestArgs[]   = {"unused", TEST_SERVER_NAME};
char* nameTestArgs[]   = {"unused", TEST_SERVER_NAME};

int server_enum_test_1 ();
int nb_name_query_test_1 (int argc, char *argv[]);
int write_test_1(int argc, char *argv[]);
int download_file_test(int argc, char *argv[]);
int upload_file_test(int argc, char *argv[]);
int rpc_test_1(int argc, char* argv[]);
int file_enum_test_1(int argc, char* argv[]);

int wait_on_job(int sid, int job);

int smb_test_main(int argc, char *argv[])
{

    rtp_printf("Call name test\n");
    if (nb_name_query_test_1 (2, nameTestArgs) != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }
    rtp_printf("Call write test\n");
    if (write_test_1(4, writeTestArgs) != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }

    rtp_printf("Call server enum test\n");
    if (server_enum_test_1() != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }

    rtp_printf("Call download test\n");
    if (download_file_test(4, downloadTestArgs) != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }
    rtp_printf("Call upload test\n");
    if (upload_file_test(4, uploadTestArgs2) != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }
    rtp_printf("Call rpc test\n");
    if (rpc_test_1(2, rpcTestArgs) != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }
    rtp_printf("Call enum test\n");
    if (file_enum_test_1(0,0) != 0)
    {
        rtp_printf("Test failed\n");
        return(-1);
    }
    rtp_printf("========= All test succeed ========= \n");
    return 0;
}

int server_enum_test_1 ()
{
  RTSMB_CLI_SESSION_SRVSTAT srvstat;
  char srvname[16];
  int r;
  rtsmb_cli_init(my_ip, my_mask);
  r = rtsmb_cli_session_server_enum_start(&srvstat, NULL, NULL);
  if(r < 0)
  {
    rtp_printf("\n could not start the enumeration");
    return 1;
  }
  do
  {
    do
    {
      r = rtsmb_cli_session_server_enum_cycle(&srvstat, 10);
      if(r == 0)
      {
        rtp_printf("\n In middle of cycling");
      }
    }while(r == 0);
    if(r == RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
      break;
    }
    else if(r != RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
       rtp_printf("\n Error in cycling");
       return 1;
    }
    do
    {
        r = rtsmb_cli_session_server_enum_next_name(&srvstat, srvname);
        if(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
        {
          rtp_printf("\n server name is %s", srvname);
        }
    }while(r == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY);
    if(r != RTSMB_CLI_SSN_RV_END_OF_SEARCH)
    {
        rtp_printf("\n error getting names");
        return 1;
    }
  }while(1);
  rtsmb_cli_session_server_enum_close(&srvstat);
  rtsmb_cli_shutdown();
  return 0;
}





char testString [] = "Network Working Group       K. Egevang"
    "Request for Comments: 1631                           Cray Communications"
    "Category: Informational                                       P. Francis"
    "                                                                   NTT"
    "                                                               May 1994"
    "               The IP Network Address Translator (NAT)"
    "Status of this Memo"
    "This memo provides information for the Internet community.  This memo"
    "does not specify an Internet standard of any kind.  Distribution of"
    "this memo is unlimited."
    "Abstract"
    "The two most compelling problems facing the IP Internet are IP"
    "address depletion and scaling in routing. Long-term and short-term"
    "solutions to these problems are being developed. The short-term"
    "solution is CIDR (Classless InterDomain Routing). The long-term"
    "solutions consist of various proposals for new internet protocols"
    "with larger addresses."
    "It is possible that CIDR will not be adequate to maintain the IP"
    "Internet until the long-term solutions are in place. This memo"
    "proposes another short-term solution, address reuse, that complements"
    "CIDR or even makes it unnecessary. The address reuse solution is to"
    "place Network Address Translators (NAT) at the borders of stub"
    "domains. Each NAT box has a table consisting of pairs of local IP"
    "addresses and globally unique addresses. The IP addresses inside the"
    "stub domain are not globally unique. They are reused in other"
    "domains, thus solving the address depletion problem. The globally"
    "unique IP addresses are assigned according to current CIDR address"
    "allocation schemes. CIDR solves the scaling problem. The main"
    "advantage of NAT is that it can be installed without changes to"
    "routers or hosts. This memo presents a preliminary design for NAT,"
    "and discusses its pros and cons."
    "Acknowledgments"
    "This memo is based on a paper by Paul Francis (formerly Tsuchiya) and"
    "Tony Eng, published in Computer Communication Review, January 1993."
    "Paul had the concept of address reuse from Van Jacobson."
    "Kjeld Borch Egevang edited the paper to produce this memo and"
    "introduced adjustment of sequence-numbers for FTP. Thanks to Jacob"
    "Michael Christensen for his comments on the idea and text (we thought"
    "Egevang & Francis                                               [Page 1]"
    "RFC 1631               Network Address Translator               May 1994"
    "for a long time, we were the only ones who had had the idea)."
    "1. Introduction"
    "The two most compelling problems facing the IP Internet are IP"
    "address depletion and scaling in routing. Long-term and short-term"
    "solutions to these problems are being developed. The short-term"
    "solution is CIDR (Classless InterDomain Routing) [2]. The long-term"
    "solutions consist of various proposals for new internet protocols"
    "with larger addresses."
    "Until the long-term solutions are ready an easy way to hold down the"
    "demand for IP addresses is through address reuse. This solution takes"
    "advantage of the fact that a very small percentage of hosts in a stub"
    "domain are communicating outside of the domain at any given time. (A"
    "stub domain is a domain, such as a corporate network, that only"
    "handles traffic originated or destined to hosts in the domain)."
    "Indeed, many (if not most) hosts never communicate outside of their"
    "stub domain. Because of this, only a subset of the IP addresses"
    "inside a stub domain, need be translated into IP addresses that are"
    "globally unique when outside communications is required."
    "This solution has the disadvantage of taking away the end-to-end"
    "significance of an IP address, and making up for it with increased"
    "state in the network. There are various work-arounds that minimize"
    "the potential pitfalls of this. Indeed, connection-oriented protocols"
    "are essentially doing address reuse at every hop."
    "The huge advantage of this approach is that it can be installed"
    "incrementally, without changes to either hosts or routers. (A few"
    "unusual applications may require changes). As such, this solution can"
    "be implemented and experimented with quickly. If nothing else, this"
    "solution can serve to provide temporarily relief while other, more"
    "complex and far-reaching solutions are worked out."
    "2. Overview of NAT"
    "The design presented in this memo is called NAT, for Network Address"
    "Translator. NAT is a router function that can be configured as shown"
    "in figure 1. Only the stub border router requires modifications."
    "NAT's basic operation is as follows. The addresses inside a stub"
    "domain can be reused by any other stub domain. For instance, a single"
    "Class A address could be used by many stub domains. At each exit"
    "point between a stub domain and backbone, NAT is installed. If there"
    "is more than one exit point it is of great importance that each NAT"
    "has the same translation table."
    "Egevang & Francis                                               [Page 2]"
    "RFC 1631               Network Address Translator               May 1994"
    "+---------------+  WAN     .           +-----------------+/"
    "|Regional Router|----------------------|Stub Router w/NAT|---"
    "+---------------+          .           +-----------------+"
    "                           .                      |  LAN"
    "                           .               --------------"
    "                       Stub border"
    "                   Figure 1: NAT Configuration"
    "For instance, in the example of figure 2, both stubs A and B"
    "internally use class A address 10.0.0.0. Stub A's NAT is assigned the"
    "class C address 198.76.29.0, and Stub B's NAT is assigned the class C"
    "address 198.76.28.0. The class C addresses are globally unique no"
    "other NAT boxes can use them."
    "                                   +---------------+"
    "                                   |Regional Router|"
    "                                   +---------------+"
    "                               WAN |           | WAN"
    "                                   |           |"
    "               Stub A .............|....   ....|............ Stub B"
    "                                   |           |"
    "                   {s=198.76.29.7,^  |           |  v{s=198.76.29.7,"
    "                   d=198.76.28.4}^  |           |  v d=198.76.28.4}"
    "                   +-----------------+       +-----------------+"
    "                   |Stub Router w/NAT|       |Stub Router w/NAT|"
    "                   +-----------------+       +-----------------+"
    "                           |                         |"
    "                           |  LAN               LAN  |"
    "                   -------------             -------------"
    "                               |                 |"
    "           {s=10.33.96.5, ^  |                 |  v{s=198.76.29.7,"
    "               d=198.76.28.4}^ +--+             +--+ v d=10.81.13.22}"
    "                               |--|             |--|"
    "                           10.33.96.5       10.81.13.22"
    "                   Figure 2: Basic NAT Operation"
    "When stub A host 10.33.96.5 wishes to send a packet to stub B host"
    "10.81.13.22, it uses the globally unique address 198.76.28.4 as"
    "destination, and sends the packet to it's primary router. The stub"
    "router has a static route for net 198.76.0.0 so the packet is"
    "forwarded to the WAN-link. However, NAT translates the source address"
    "10.33.96.5 of the IP header with the globally unique 198.76.29.7";

int write_test_1(int argc, char *argv[])
{
    int written;
    int fd;
    int sid;
    int r;

    rtp_strcpy(buffer, testString);

    rtsmb_cli_init(my_ip, my_mask);

    if(argc != 4)
    {
        rtp_printf("\n please provide one server name and share name, path and data string as input");
        return 1;
    }

    r = rtsmb_cli_session_new_with_name(argv[1], FALSE, NULL, &sid,TEST_DIALECT);
    if(r < 0)
    {
        rtp_printf("\n Error Creating Session with server %s", argv[1]);
        return 1;
    }

    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during session create");
        return 1;
    }

    r = rtsmb_cli_session_logon_user(sid, TEST_USER_NAME, TEST_USER_PASSWORD, TEST_DOMAIN_NAME);
    if(r < 0)
    {
        rtp_printf("\n Error during user logon");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during logon response");
        return 1;
    }
    r = rtsmb_cli_session_connect_share(sid, argv[2], "");
    if(r < 0)
    {
        rtp_printf("\n Error connecting to share %s", argv[2]);
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during connect to share response");
        return 1;
    }
    r = rtsmb_cli_session_open(sid, argv[2], argv[3], RTP_FILE_O_CREAT|RTP_FILE_O_RDWR|RTP_FILE_O_TRUNC,
                       RTP_FILE_S_IWRITE|RTP_FILE_S_IREAD, &fd);
    if(r < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }
    r = rtsmb_cli_session_write(sid, fd, (PFBYTE) buffer, /*strlen(buffer)*/ 2048 /* 5300*/ , &written); // too big: 4308, small enough: 4300
    if(r < 0)
    {
        rtp_printf("\n Error writing file");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error in write response");
        return 1;
    }
    rtp_printf("\n numbytes written is %d", written);
    rtsmb_cli_shutdown();
    return 0;
}


int download_file_test(int argc, char *argv[])
{
    int bytesRead;
    int fd;
    int sid;
    int r;
    long copySize = 2048;
    FILE* localFile;

    rtsmb_cli_init(my_ip, my_mask);


    if(argc != 4)
    {
        rtp_printf("\n please provide one server name and share name, path and data string as input");
        return 1;
    }

    r = rtsmb_cli_session_new_with_name(argv[1], FALSE, NULL, &sid, TEST_DIALECT);
    if(r < 0)
    {
        rtp_printf("\n Error Creating Session with server %s", argv[1]);
        return 1;
    }

    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during session create");
        return 1;
    }

    r = rtsmb_cli_session_logon_user(sid, TEST_USER_NAME, TEST_USER_PASSWORD, TEST_DOMAIN_NAME);
    if(r < 0)
    {
        rtp_printf("\n Error during user logon");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during logon response");
        return 1;
    }
    r = rtsmb_cli_session_connect_share(sid, argv[2], "");
    if(r < 0)
    {
        rtp_printf("\n Error connecting to share %s", argv[2]);
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during connect to share response");
        return 1;
    }

    localFile = fopen(argv[3], "wb+");
    if (!localFile)
    {
        rtp_printf("\nError opening local file.");
        return 1;
    }

    r = rtsmb_cli_session_open (sid, argv[2], argv[3], RTP_FILE_O_RDWR,
                       RTP_FILE_S_IWRITE|RTP_FILE_S_IREAD, &fd);
    if(r < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }

    do
    {
        bytesRead = -1;
        r = rtsmb_cli_session_read(sid, fd, (PFBYTE) buffer, copySize, &bytesRead);
        if(r < 0)
        {
            rtp_printf("\n Error writing file");
            return 1;
        }
        r = wait_on_job(sid, r);

        if (bytesRead > 0)
        {
            fwrite(buffer, 1, (size_t)bytesRead, localFile);
        }
    }
    while (r >= 0 && bytesRead > 0);

    fclose(localFile);

    if(r < 0)
    {
        rtp_printf("\n Error in write response");
        return 1;
    }
    localFile = fopen(argv[3], "rb+");

    rtsmb_cli_shutdown();

    return 0;
}


int upload_file_test(int argc, char *argv[])
{
    int written, bytesRead;
    int fd;
    int sid;
    int r;
    long copySize = TEST_BUFFER_SIZE;
    FILE* localFile;

    rtsmb_cli_init(my_ip, my_mask);

    if(argc != 4)
    {
        rtp_printf("\n please provide one server name and share name, path and data string as input");
        return 1;
    }

    r = rtsmb_cli_session_new_with_name(argv[1], FALSE, NULL, &sid, TEST_DIALECT);
    if(r < 0)
    {
        rtp_printf("\n Error Creating Session with server %s", argv[1]);
        return 1;
    }

    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during session create");
        return 1;
    }

    r = rtsmb_cli_session_logon_user(sid, TEST_USER_NAME, TEST_USER_PASSWORD, TEST_DOMAIN_NAME);
    if(r < 0)
    {
        rtp_printf("\n Error during user logon");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during logon response");
        return 1;
    }
    r = rtsmb_cli_session_connect_share(sid, argv[2], "");
    if(r < 0)
    {
        rtp_printf("\n Error connecting to share %s", argv[2]);
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during connect to share response");
        return 1;
    }

    localFile = fopen(argv[3], "rb+");
    if (!localFile)
    {
        rtp_printf("\nError opening local file.");
        return 1;
    }

    r = rtsmb_cli_session_open (sid, argv[2], argv[3], RTP_FILE_O_CREAT|RTP_FILE_O_RDWR|RTP_FILE_O_TRUNC,
                       RTP_FILE_S_IWRITE|RTP_FILE_S_IREAD, &fd);
    if(r < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }

    do
    {
        written = -1;
        bytesRead = (int)fread(buffer,
            1,
            (size_t)copySize,
            localFile);
        if (bytesRead > 0)
        {
            r = rtsmb_cli_session_write(sid, fd, (PFBYTE) buffer, bytesRead, &written);
            if(r < 0)
            {
                rtp_printf("\n Error writing file");
                return 1;
            }
            r = wait_on_job(sid, r);
        }
        else
        {
            // file done.
            break;
        }
    }
    while (r >= 0 && written > 0);

    fclose(localFile);

    if(r < 0)
    {
        rtp_printf("\n Error in write response");
        return 1;
    }

    r = rtsmb_cli_session_close(sid, fd);
    if (r < 0)
    {
        rtp_printf ("\n Error closing file.");
        return 1;
    }
    r = wait_on_job(sid, r);

    rtsmb_cli_shutdown();

    return 0;
}

int rpc_test_1(int argc, char* argv[])
{
    int fd;
    int sid;
    int r;
    unsigned char buffer[RTSMB_RPC_INIT_BUFFER_SIZE];
    RTSMB_RPC_SHARE_INFO_LEVEL_1 shareInfoArray[128];
    RTSMB_RPC_NETR_SHARE_ENUM_REQUEST request;
    RTSMB_RPC_NETR_SHARE_ENUM_RESPONSE response;

    rtsmb_cli_init(my_ip, my_mask);

    if(argc != 2)
    {
        rtp_printf("\n please provide one server name as input");
        return 1;
    }

    r = rtsmb_cli_session_new_with_name(argv[1], FALSE, NULL, &sid, TEST_DIALECT);
    if(r < 0)
    {
        rtp_printf("\n Error Creating Session with server %s", argv[1]);
        return 1;
    }

    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during session create");
        return 1;
    }

    r = rtsmb_cli_session_logon_user(sid, TEST_USER_NAME, TEST_USER_PASSWORD, TEST_DOMAIN_NAME);
    if(r < 0)
    {
        rtp_printf("\n Error during user logon");
        return 1;
    }

    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during logon response");
        return 1;
    }

    r = rtsmb_cli_rpc_open_interface(sid, prtsmb_srvsvc_pipe_name, prtsmb_srvsvc_info, &fd, buffer);
    if (r < 0)
    {
        rtp_printf("\n Error starting open RPC pipe job");
        return 1;
    }

    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error opening RPC interface");
        return 1;
    }

    // initialize the request parameters
    wcscpy((wchar_t *)request.server_name_uc, L"\\\\thinkpad");

    // initialize the response parameters
    response.max_shares = 128;
    response.share_info = shareInfoArray;

    rtsmb_cli_rpc_NetrShareEnum_init(&request, &response);

    r = rtsmb_cli_rpc_invoke(sid, fd, RTSMB_RPC_SRVSVC_NETR_SHARE_ENUM,
                            rtsmb_cli_rpc_NetrShareEnum_request, &request,
                            rtsmb_cli_rpc_NetrShareEnum_response, &response);

    if (wait_on_job(sid, r) < 0)
    {
        // handle error case here
        rtp_printf("\n Error invoking RPC");
        return 1;
    }
    else
    {
        // the operation was successful; read the collected share data

        unsigned int i;

        rtp_printf("Shares found:\n");

        for (i = 0; i < response.num_shares; i++)
        {
            rtp_printf("%ls  %10s  %ls\n",
                    (wchar_t *)shareInfoArray[i].share_name_uc,
                    (shareInfoArray[i].share_type == 0)? "<folder>" : "<printer>",
                    (wchar_t *)shareInfoArray[i].share_comment_uc);
        }
    }

    rtsmb_cli_shutdown();

    return 0;
}

int file_enum_test_1(int argc, char* argv[])
{
    RTSMB_CLI_SESSION_DSTAT dstat1;
    int sid;
    int r;
    int r1;

    rtsmb_cli_init(my_ip, my_mask);

    r = rtsmb_cli_session_new_with_name(TEST_SERVER_NAME, FALSE, NULL, &sid, TEST_DIALECT);

    if(r < 0)
    {
        rtp_printf("\n Error Creating Session with server %s", argv[1]);
        return 1;
    }

    r = wait_on_job(sid, r);

    r = rtsmb_cli_session_logon_user(sid, TEST_USER_NAME, TEST_USER_PASSWORD, TEST_DOMAIN_NAME);
    if(r < 0)
    {
        rtp_printf("\n Error during user logon");
        return 1;
    }
    r = wait_on_job(sid, r);
    if(r < 0)
    {
        rtp_printf("\n Error during logon response");
        return 1;
    }

    r1 = rtsmb_cli_session_connect_share(sid, TEST_SHARE_1, "");

    rtp_printf("Existing Job ID's are %x\n",r1);
    if (r1 < 0)
    {
        rtp_printf("\n Error connecting to share");
        return 1;
    }

    r1 = wait_on_job(sid, r1);

    if(r1 < 0)// || r2 < 0)
    {
        rtp_printf("\n Error during connect to share response");
        return 1;
    }
    r1 = rtsmb_cli_session_find_first(sid, TEST_SHARE_1, "*", &dstat1);

    if(r1 < 0)
    {
        rtp_printf("\n Error getting files");
        return 1;
    }
    r1 = wait_on_job(sid, r1);

    while(r1 == RTSMB_CLI_SSN_RV_SEARCH_DATA_READY)
    {
        char temp[200];

        rtsmb_util_rtsmb_to_ascii ((PFRTCHAR) dstat1.filename, temp, 0);

        rtp_printf("Search data name is %s\n", temp);
                r1 = rtsmb_cli_session_find_next(sid, &dstat1);
        if(r1 >= 0)
        {
            r1 = wait_on_job(sid, r1);
        }
    }
    r1 = rtsmb_cli_session_find_next(sid, &dstat1);
    rtsmb_cli_session_find_close(sid, &dstat1);

    rtsmb_cli_shutdown();
    return 0;
}

int nb_name_query_test_1 (int argc, char *argv[])
{
    RTSMB_NBNS_NAME_QUERY list[20];
    int i;
    int done = 0;

    rtsmb_cli_init(my_ip, my_mask);

    if (argc > 20)
    {
        rtsmb_cli_shutdown();
        return -1;
    }

    for (i=1; i<argc; i++)
    {
        rtsmb_nbns_query_name(&list[i-1], argv[i]);
    }

    rtp_printf("Resolving NetBIOS names...");
    while (!done)
    {
        rtp_printf(".");
        rtsmb_nbns_query_cycle(list, argc-1, 1000);

        done = 1;
        for (i=0; i<argc-1; i++)
        {
            RTSMB_NBNS_NAME_INFO info[5];
            int num_addrs;

            switch (list[i].status)
            {
            case RTSMB_NBNS_QUERY_STATUS_RESOLVED:
                rtp_printf("\nHost %s resolved: ", list[i].name);
                num_addrs = rtsmb_nbns_get_name_query_response(&list[i], info, 5);
                for (;num_addrs > 0; num_addrs--)
                {
                    rtp_printf("%d.%d.%d.%d ",
                            info[num_addrs-1].ip_addr[0],
                            info[num_addrs-1].ip_addr[1],
                            info[num_addrs-1].ip_addr[2],
                            info[num_addrs-1].ip_addr[3]);
                }

            case RTSMB_NBNS_QUERY_STATUS_ERROR:
                rtsmb_nbns_close_query(&list[i]);
                break;

            case RTSMB_NBNS_QUERY_STATUS_TIMEOUT:
                rtp_printf ("\nQuery: %s timed out", list[i].name);
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
