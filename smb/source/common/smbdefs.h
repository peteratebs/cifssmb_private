#ifndef __SMB_DEFS_H__
#define __SMB_DEFS_H__

#ifdef __cplusplus
   #define EXTERN_C extern "C"
#else
   #define EXTERN_C
#endif

#define TESTING_OO 1

//****************************************************************************
//**
//**    SMBDEFS.H
//**    Header - This sets up cross-platform code and includes the correct
//**             network stack.  It also defines various constants needed by
//**             the code.
//****************************************************************************


#define HARDWIRE_NO_SHARED_SESSION_BUFFERS             1  // Set to zero to prompt for settings and allow more flexibility like run-time add of shares

// Definitions for development
// See https://msdn.microsoft.com/en-us/library/cc236699.aspx for good NTLM reference
#define HARDWIRE_SERVER_SETTINGS           1  // Set to zero to prompt for settings and allow more flexibility like run-time add of shares
#define HARDWIRED_USER_NAME  "ebs"
#define HARDWIRED_PASSWORD   "password" // "SecREt01" // "password"
#define HARDWIRED_SHARE_NAME  "share0"
#define HARDWIRED_SHARE_PATH "/media"
#define HARDWIRED_TEMP_PATH "/tmp"
#define HARDWIRED_HOST_NAME  "EBSRTSMB"
#define HARDWIRED_GROUP_NAME "WORKGROUP"
#define HARDWIRED_EXTENDED_SECURITY           1  // Use extended security (SPNEO_) if true and client supports it. Set to zero to authenticate through the NTLM1 method, where the clint sends LM or NTLM1
                                                 // credentials in the setup request
#define HARDWIRED_INCLUDE_NTLM2_IN_CHALLENGE  1  // Set to zero to force the client to reply with NTLM1 resonse not NTLM2 (not ntlmv2, that's different) response. If HARDWIRED_EXTENDED_SECURITY and client requests exended security.
#define HARDWIRED_DEBUG_ENCRYPTION_KEY        1  // send 0123456789abcde for an encrypion key for easier debugging of hash functions
#define HARDWIRED_FORCE_EXTENDED_SECURITY_OK  0  // If one force a successful login even though the password checker failed
#define HARDWIRED_ENCRYPION_KEY_HACK          1  // Must be fixed. Use a global to pass the encryption key between levels in trans.


#define HARDWIRED_OVERRIDE_CLIENT_EXT_FILE_ALL_INFO_DEF    1  // FILE ALL INFO structure okay for server, seems wrong in client, needs investigation.
#define HARDWIRED_FAKED_ZERO_VALUE                         0  // Search around for these, must be updated with real values.
#define HARDWIRED_NTLM_EXTENSIONS                          1  // Fixes for missing extensions, may cause mal;formed issues for earlier than NTLM1.2.
#define HARDWIRED_NEGOTIATE_CHALLENGE_SIZE                 0  // TBD: MAC does not respond to protocol reponse unless this is 0,
                                                              // for mac based client, 8 for windows client
// #define HARDWIRED_MAX_SMALL_BUFFER_SIZE                    16384 // Improves performance. tried (32768-512) but this breaks DIR *.* on very large directories, that specific procedure should be debugged with a larger buffer.
// At least 64K required for SMB2
// #define HARDWIRED_MAX_SMALL_BUFFER_SIZE                    ((32768*2)+512) // Set this large enough to hold a 64 K Read or Write transaction + header size
#define HARDWIRED_MAX_SMALL_BUFFER_SIZE                    ((32768*2)+512) // Set this large enough to hold a 64 K Read or Write transaction + header size
#define CFG_RTSMB_SMALL_BUFFER_SIZE        HARDWIRED_MAX_SMALL_BUFFER_SIZE // 4096 // (32768-512) // 2924
#define CFG_RTSMB_SMALL_BUFFER_SIZE_VETTED  ((32768*2)+512)
#define CFG_RTSMB_IN_BUFFER_SIZE_VETTED  ((32768*2)+4)
#define CFG_RTSMB_OUT_BUFFER_SIZE_VETTED  ((32768*2)+4)

#define CFG_RTSMB_TEMP_BUFFER_SIZE  ((32768*2)+4)

#define HARDWIRED_SMB2_MAX_NBSS_FRAME_SIZE                (32768*16)      // 512 K for now


#define HARDWIRED_SMB2_MAX_TRANSACTION_SIZE                (32768*2)       // Advertize this as maximum transaction size
#define HARDWIRED_SMB1_MAX_TRANSACTION_SIZE                0xffff     //   HARDWIRED_SMB1_MAX_TRANSACTION_SIZE-RTSMB_NBSS_HEADER_SIZE Advertize this as maximum transaction size
#define HARDWIRE_USE_CONFIG_FILE                           1  // 1 to read user and share info from "smb_config.txt" in the launch directory.
                                                              // These values are then used instead of HARDWIRED_USER_NAME, HARDWIRED_PASSWORD, HARDWIRED_SHARE_NAME, HARDWIRED_SHARE_PATH
                                                              // Note: Should add EXTENDED security, min-dialect, max-dialect, others.
#ifdef donbserver                                             // Add stubs neede to run without any nbns support functions. depends on the makefile state. see donbserver = "Y" im mkgnu.inc
#define HARDWIRE_EXCLUDE_NBNS                              0
#else
#define HARDWIRE_EXCLUDE_NBNS                              1  // exclude NBNS functionality like group join announcements and responding to NBNS queries.
                                                              // If this feature is enabled the makefile should be edited to exclude the /servernb and /commonnb directories
#endif

// Passed with the extended security client challenge. Target configuration strings.
// #define HARDWIRED_TARGET_NAME       "TARGETNAME"
#define HARDWIRED_TARGET_NAME       "VBOXUNBUNTU"
#define HARDWIRED_NBDOMAIN_NAME     "DOMAIN"
#define HARDWIRED_NBCOMPUTER_NAME   "NETBIOSCOMPUTERAME"
#define HARDWIRED_DNSDOMAIN_NAME    "DNSDOMAINNAME"
#define HARDWIRED_DNSCOMPUTER_NAME  "DNSCOMPUTERAME"


#define HARDWIRED_CLIENT_EXTENDED_SECURITY 1                  // Client side Spnego
#define HARDWIRED_INCLUDE_DCE                             1       // Experimental DCE support for NetShareEnumAll

#define HARDWIRED_DISABLE_SIGNING 0                           // Disables signing

#define SMB_UNIQUE_FILEID_SIZE 8    // How much we store in UID field

//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================


//common program headers
#include "rtptypes.h"
#include "rtpdebug.h"
#include "rtpstr.h"
#include "rtptotc.h"
#include "smbconf.h"
#include "smb.h"

#if (1)
#include "rtpprint.h"
#define SMB_ERROR rtp_printf
#else
#define SMB_ERROR
#endif
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#define MAX(A, B) (((A) > (B)) ? (A) : (B))

#define RTSMB_MIN MIN
#define RTSMB_MAX MAX

#ifdef WIN32
#include <assert.h>
#define RTSMB_ASSERT(X) assert(X)
#else
#define RTSMB_ASSERT(X)
#endif /* WIN32 */

// #define RTP_FREE(B) {printf("call freeon %X:  %s:%ld\n", B, __FILE__, __LINE__); rtp_free(B); }
#define RTP_FREE(B) {rtp_free(B);}

#define PADD(p, n) ((PFVOID) (((RTP_ADDR) (p)) + ((RTP_ADDR) (n))))
#define PDIFF(p, q) (RTP_ADDR)((RTP_ADDR) (p) - (RTP_ADDR) (q))

// gets the index of item B in array A.  A must have at least one element
// this is very unsafe if you are not sure that B is in A and both pointers
// are valid
#define INDEX_OF(A, B)  ((int)(((RTP_ADDR) B - (RTP_ADDR) A) / (int)sizeof (A[0])))

// gets the size (number of indeces) in an array.
#define TABLE_SIZE(A)   (int) (sizeof (A) / sizeof (A[0]))


// for testing/measurement purposes, I find it convenient to disable static/const variables temporarily
#define RTSMB_STATIC static
#define RTSMB_CONST  const

#define BBOOL byte

#define RTSMB_TIME_INFINITE     0xFFFFFFFF


#if (INCLUDE_RTSMB_UNICODE)
typedef unsigned short  rtsmb_char;
#define RTSMB_STR_TOK   "%S"    /* rtp_printf argument for unicode string */
#else
typedef char            rtsmb_char;
#define RTSMB_STR_TOK   "%s"    /* rtp_printf argument for ascii string */
#endif

typedef unsigned char   byte;   //8-bit
typedef unsigned short  word;   //16-bit
typedef unsigned long   dword;  //32-bit
typedef unsigned long long ddword;  //32-bit
typedef unsigned long   rtsmb_size;

typedef byte              RTSMB_FAR * PFBYTE;
typedef word              RTSMB_FAR * PFWORD;
typedef dword             RTSMB_FAR * PFDWORD;
typedef ddword            RTSMB_FAR * PFDDWORD;
typedef unsigned short    RTSMB_FAR * PFWCS;
typedef rtsmb_char        RTSMB_FAR * PFRTCHAR;
typedef rtsmb_size        RTSMB_FAR * PFSIZE;
typedef char              RTSMB_FAR * PFCHAR;
typedef int               RTSMB_FAR * PFINT;
typedef long              RTSMB_FAR * PFLONG;
typedef void              RTSMB_FAR * PFVOID;
typedef BBOOL             RTSMB_FAR * PFBBOOL;


typedef unsigned short    RTSMB_CHAR16;
typedef char              RTSMB_CHAR8;
typedef unsigned char     RTSMB_UINT8;
typedef unsigned short    RTSMB_UINT16;
typedef unsigned long     RTSMB_UINT32;
typedef char              RTSMB_INT8;
typedef short             RTSMB_INT16;
typedef long              RTSMB_INT32;
typedef int               RTSMB_BOOL;

#define RTSMB_TRUE        1
#define RTSMB_FALSE       0

typedef unsigned short    SMB_DATE;
typedef unsigned short    SMB_TIME;

typedef void * signalobject_Cptr;
typedef void * yield_Cptr;


/* This is a time-since-microsoft-epoch struct.  That means it records
   how many 100-nanoseconds have passed since Jan. 1, 1601. */
typedef struct {
    dword low_time;
    dword high_time;
} TIME;

/* This is a time-since-microsoft-epoch struct as a 64 bit ddword.
   Same as TIME, it records how many 100-nanoseconds have passed since Jan. 1, 1601. */
typedef ddword FILETIME_T;

typedef struct {
    SMB_DATE date;
    SMB_TIME time;
} DATE_STR;


#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/*
//This causes some compilers to complain
#if INCLUDE_RTSMB_PRINTF
#define PRINTF rtp_printf
#else
#define PRINTF
#endif
*/
#if INCLUDE_RTSMB_PRINTF
    #define PRINTF(p) rtp_printf p
#else
    #define PRINTF(p)
#endif

PFRTCHAR rtsmb_get_comment (void);

// some macros to change from our host byte ordering to intel byte ordering
// this is because all smb's are sent using intel byte ordering
// 'w' refers to word or short, 'd' refers to a dword or int

/*
#define SMB_SWAP_BYTES_W(A) ((word) (A >> 8 | A << 8))
#define SMB_SWAP_BYTES_D(A) ((dword) ((A >> 24) | (A << 24) | ((A >> 8) & 0x0000FF00) | ((A << 8) & 0x00FF0000)))
*/
#define SMB_SWAP_BYTES_W(A) (word) ((((A) >> 8) & 0x00ff) | (((A) << 8) & 0xff00))
#define SMB_SWAP_BYTES_D(A) (dword) ((((A) >> 8) & 0x0000ff00) | (((A) << 8) & 0x00ff0000) | (((A) >> 24) & 0x000000ff) | (((A) << 24) & 0xff000000))

#ifdef SUPPORT_SMB2
extern ddword swapdword(const ddword i);
#define SMB_SWAP_BYTES_DD(A) (ddword) swapdword(A)
#endif

#if RTSMB_INTEL_ORDER
    #define SMB_HTOIW(A)  A
    #define SMB_HTOID(A)  A
    #define SMB_HTOIDD(A) A
    #define SMB_ITOHW(A)  A
    #define SMB_ITOHD(A)  A
    #define SMB_ITOHDD(A) A
    #define SMB_HTONW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_HTOND(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_HTONDD(A) SMB_SWAP_BYTES_DD(A)
    #define SMB_NTOHW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_NTOHD(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_NTOHDD(A) SMB_SWAP_BYTES_DD(A)
#else
    #define SMB_HTOIW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_HTOID(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_HTOIDD(A) SMB_SWAP_BYTES_D(A)
    #define SMB_ITOHW(A)  SMB_SWAP_BYTES_W(A)
    #define SMB_ITOHD(A)  SMB_SWAP_BYTES_D(A)
    #define SMB_ITOHDD(A) SMB_SWAP_BYTES_DD(A)
    #define SMB_HTONW(A)  A
    #define SMB_HTOND(A)  A
    #define SMB_HTONDD(A) A
    #define SMB_NTOHW(A)  A
    #define SMB_NTOHD(A)  A
    #define SMB_NTOHDD(A) A
#endif

#define MEMCLEAROBJ(S) tc_memset(&S,0,sizeof(S))
#define MEMCLEARPOBJ(S) tc_memset(S,0,sizeof(*S))

#include "psmbos.h"
#include "psmbnet.h"
#include "psmbfile.h"

#include "rtpsignl.h"
#include "rtpfile.h"
//****************************************************************************
//**
//**    END HEADER SMBDEFS.H
//**
//****************************************************************************
#if (HARDWIRED_INCLUDE_DCE)
extern rtsmb_char _rtsmb_srvsvc_pipe_name[8];  // '\\','s','r','v','s','v','c',0 File name HARDWIRED_SRVSVC_FID maps to this name
extern rtsmb_char pipe_protocol[7];            // '\\','P','I','P','E','\\','\0'
#ifdef SUPPORT_SMB2
extern rtsmb_char _rtsmb2_srvsvc_pipe_name[8]; //  = {'\\','s','r','v','s','v','c',0};
extern rtsmb_char _rtsmb2_larpc_pipe_name[7];  //  = {'l','s','a','r','p','c',0};
#endif
#endif
#endif /* __SMB_DEFS_H__ */
