//
// smb2defs.hpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//
//

#ifndef include_smb2defs
#define include_smb2defs

#include <algorithm>
#include <climits>
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
#include <memory>
#include <cstddef>
#include <cstring>
#include <vector>
#include "rtpstr.h"  // rtp_memcpy
#include "rtptime.h"  // rtp_get_system_msec ();
#include "rtpwcs.h"  // rtp_wcslen
#include "rtpmem.h"  // rtp_get_system_msec ();
#include "rtpnet.h"
#include "rtpscnv.h" // itoa

#define tc_memcpy rtp_memcpy
#define STUB(X) 0
#define SMB_TIMEOUT_SEC 30  // TBD general timeout failure on a socket

#define SMB_HTOIW(A)  A     // Usage of this mean it should be using a smart field.
#define SMB_HTOID(A)  A
#define SMB_HTOIDD(A) A
#define SMB_ITOHW(A)  A
#define SMB_ITOHD(A)  A
#define SMB_ITOHDD(A) A


void *smb_rtp_malloc(size_t s);
void smb_rtp_free(void *s);


#define rtp_malloc_auto_freed smb_rtp_malloc
#define rtp_free_auto_free smb_rtp_free
#define rtp_freed_from_object             // does nothing just a marker where rtp_free is replaced by the localallocator destructor.

#define rtp_wcslen_bytes(S) (rtp_wcslen((S))*2)

using std::cout;
using std::endl;

// Log levels for further processing by cout_log()
#define LL_JUNK  0
#define LL_TESTS 1
#define LL_INIT  2
// Macro for now but convert to a class for a better outcome
#define cout_log(level) cout

// Legacy code for dumping buffers doesn't work standalone for now, requires SMB1 package.
#define DUMPBIN     0
#define DUMPASCII   1
#define DUMPUNICODE 2
extern void rtsmb_dump_bytes(const char *prompt, void *pbytes, int length, int format);



typedef unsigned char   byte;   //8-bit
typedef unsigned short  word;   //16-bit
typedef unsigned long   dword;  //32-bit
typedef unsigned long long ddword;  //32-bit
typedef ptrdiff_t RTP_ADDR;

#define LARGEST_STRING 255
#define dualstringdecl(STRINGNAME) std::auto_ptr<dualstring> STRINGNAME(new(dualstring))
/// dualstring string container can be intialized with ascii or utf16 and then be dereferenced by either type utf16() or the ascii() methods.
/// Uses dynamic memory that is freed by its destructror.
/// For extra safety use the dualstringdecl(stringname) to ensure that the destuctor is called to free memory.
class dualstring {
public:
  dualstring() {utf16view=0; asciiview=0;empty();};
  ~dualstring() { empty(); }
  void empty() { if (utf16view) smb_rtp_free(utf16view); if (asciiview) smb_rtp_free(asciiview);maxlen=LARGEST_STRING; utf16view=0; asciiview=0;strlen=0; };
  char *ascii()  { return asciiview;}
  word  *utf16() { return utf16view;}
  int   utf16_length() { return strlen*2; }
  int   ascii_length() { return strlen; }
  bool  istoolong() {return (strlen > maxlen);}
  void operator =(char *s)
  {
    int l=arglen(s);
    utf16view = (word *)rtp_malloc_auto_freed(2*(l+1));
    asciiview = (char *)rtp_malloc_auto_freed(l+1);
    asciiview[l]=0;
    utf16view[l]=0;
    for (int i=0;i<l; i++)
    {
     asciiview[i]=(byte)s[i];
     utf16view[i]=(word)s[i];
    }
  }
  void operator =(word *s)
  {
    int l=arglen(s);
    utf16view = (word *)rtp_malloc_auto_freed(2*(l+1));
    asciiview = (char *)rtp_malloc_auto_freed(l+1);
    for (int i=0;i<l; i++)
    {
     asciiview[i]=(byte)s[i];
     utf16view[i]=(word)s[i];
    }
    asciiview[l]=0;
    utf16view[l]=0;
   }
private:
  int maxlen;
  int strlen;
  int arglen(char *s)
    {
      strlen=0;
      while(s[strlen])
        strlen++;
      strlen = std::min(strlen,maxlen);
      return strlen;
  }
  int arglen(word *s)
   { strlen=0;
     while(s[strlen])
      strlen++;
     strlen = std::min(strlen,maxlen);
     return strlen;
   }
  word *utf16view;
  char *asciiview;
};



#define TURN_ON(A, B)	{(A) |= (B);}
/* if A is false, return B */
#define ASSURE(A, B)    {if (!(A))	return B;}
/* if A is false, return */
// #define ASSURE_V(A)     {if (!(A))	return;}


#define RTSMB_CFG_MAX_SESSIONS                      1
#define RTSMB_CFG_MAX_SHARESPERSESSION              1

#define RTSMB_CFG_MAX_FILESPERSESSION               8

#define RTSMB_CFG_MAX_SHARENAME_SIZE               80

#define HARDWIRED_TARGET_NAME       "VBOXUNBUNTU"
#define HARDWIRED_NBDOMAIN_NAME     "DOMAIN"
#define HARDWIRED_NBCOMPUTER_NAME   "NETBIOSCOMPUTERAME"
#define HARDWIRED_DNSDOMAIN_NAME    "DNSDOMAINNAME"
#define HARDWIRED_DNSCOMPUTER_NAME  "DNSCOMPUTERAME"

#define RTSMB_CFG_MAX_GROUPNAME_SIZE   10   // the maximum size of group names
#define RTSMB_CFG_MAX_USERNAME_SIZE    128  // the maximum size of account names
#define RTSMB_CFG_MAX_PASSWORD_SIZE    128  // the maximum size of passwords (must be at least 24 when using encryption)
#define RTSMB_CFG_MAX_DOMAIN_NAME_SIZE 128  // the maximum size of domain names


#define RTSMB_CFG_MAX_BUFFER_SIZE     32768    // The physical buffer size we stream through
  // Maximum read/write/trasnaction size we'll ever use so we know that we have space in the buffer for it.
#define RTSMB_CFG_MAX_CLIENT_TRANSACTION_SIZE     (RTSMB_CFG_MAX_BUFFER_SIZE-2048)

#define RTSMB_CFG_MAX_FILENAME_SIZE    255   // the maximum size of file name in utf16



typedef enum
{
    CSSN_STATE_UNUSED,                   /* absolutely free to be used by someone */
    CSSN_STATE_DEAD,                     /* untenable, but needs to be free'd */
//    CSSN_STATE_QUERYING,                 /* in the process of finding server by name */
    CSSN_STATE_CONNECTING,               /* we know the name/address mapping, and are connecting */
    CSSN_STATE_CONNECTED,                /* conneted but haven't yet formed a session */
    CSSN_STATE_NEGOTIATED,               /* we've started a full session and are go */
//    CSSN_STATE_RECOVERY_QUERYING,        /* we're trying to recover from a bad connection */
//    CSSN_STATE_RECOVERY_NEGOTIATING,     /* we're trying to recover from a bad connection */
//    CSSN_STATE_RECOVERY_NEGOTIATED,      /* we're trying to recover from a bad connection */
//    CSSN_STATE_RECOVERY_LOGGING_ON,      /* we're trying to recover from a bad connection */
//    CSSN_STATE_RECOVERY_LOGGED_ON,       /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_TREE_CONNECTING, /* we're trying to recover from a bad connection */
    CSSN_STATE_RECOVERY_TREE_CONNECTED,  /* we're trying to recover from a bad connection */
//    CSSN_STATE_RECOVERY_FILE_OPENING,    /* we're trying to recover from a bad connection */
//    CSSN_STATE_RECOVERY_FILE_OPENED      /* we're trying to recover from a bad connection */
} RTSMB_CLI_SESSION_STATE;

typedef enum
{
    CSSN_USER_STATE_UNUSED, /* no user */
    CSSN_USER_STATE_LOGGING_ON, /* user is trying to log on */
    CSSN_USER_STATE_CHALLENGED, /* user is trying to log on but recieved a challenge */
    CSSN_USER_STATE_LOGGED_ON,  /* user is logged on */
    CSSN_USER_STATE_DIRTY       /* user needs to be reconnected */
} RTSMB_CLI_SESSION_USER_STATE;

typedef enum
{
    CSSN_JOB_STATE_UNUSED,  /* no job */
    CSSN_JOB_STATE_FAKE,    /* not a real job, just for internal use */
    CSSN_JOB_STATE_STALLED, /* job is waiting for wire to clear */
    CSSN_JOB_STATE_WAITING, /* job is waiting on SMB server response */
    CSSN_JOB_STATE_DIRTY    /* job is waiting to be restarted */
} RTSMB_CLI_SESSION_JOB_STATE;




typedef enum		//Possible SMB Dialects
{
	DIALECT_NONE=-1,
	PC_NETWORK=0,	// PC NETWORK PROGRAM 1.0
	LANMAN_1_0,		// LANMAN 1.0
	LM1_2X002,		// LM1.2X002
	LANMAN_2_1,		// LANMAN 2.1
	NT_LM,			// NT LM 0.12
    SMB2_2002,       // "SMB 2.002"
    SMB2_2xxx,       //  "SMB 2.???"
	NUM_DIALECTS
} SMB_DIALECT_T;

typedef enum
{
    CSSN_DIALECT_PRE_NT,
    CSSN_DIALECT_NT,
    CSSN_DIALECT_SMB2_2002,
} RTSMB_CLI_SESSION_DIALECT;


/// Propogate status conditions up from the lowest failure level with these constants
enum NetStatus {
    NetStatusnbsseof           = 2,
    NetStatusNextsmb2Message   = 1,
    NetStatusOk                = 0,
    NetStatusFailed            = -1,
    NetStatusFull              = -2,
    NetStatusEmpty             = -3,
    NetStatusDeviceRecvFailed  = -4,
    NetStatusDeviceSendFailed  = -5,
    NetStatusBadCallParms      = -6,
    NetStatusConnectFailed     = -7,
    NetStatusDeviceRecvBadLength  = -8,
    NetStatusServerErrorStatus    = -9,
    NetStatusDeviceRecvUnderflow  = -10,
};

typedef struct SecurityBuffer_s {
  dword size;
  word  offset;
  byte  *value_at_offset;
} SecurityBuffer_t;


typedef struct decoded_NegTokenTarg_challenge_s {
    dword Flags;
    byte ntlmserverchallenge[8];
    SecurityBuffer_t *target_name;
    SecurityBuffer_t *target_info;
} decoded_NegTokenTarg_challenge_t;

#define AUTH_GUEST          1
#define AUTH_NOACCESS       2
#define AUTH_USER_MODE      0
#define AUTH_SHARE_MODE     1

/* It is not recommended that you change these */
//#define CFG_RTSMB_MAX_GROUPNAME_SIZE   10   // the maximum size of group names
//#define CFG_RTSMB_MAX_USERNAME_SIZE    128  // the maximum size of account names
#define CFG_RTSMB_MAX_PASSWORD_SIZE    128  // the maximum size of passwords (must be at least 24 when using encryption)
//#define CFG_RTSMB_MAX_DOMAIN_NAME_SIZE 128  // the maximum size of domain names
//#define CFG_RTSMB_MAX_HOSTNAME_NAME_SIZE 128  // the maximum size of host name (rcved from client)
//#define CFG_RTSMB_MAX_SECURITYBLOB_SIZE 512 // the maximum size of spnego security blob



// void spnego_decoded_NegTokenInit_destructor(decoded_NegTokenInit_t *decoded_token);
void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
void calculate_smb2_signing_key(void *signing_key, void *data, size_t data_len, unsigned char *result);

typedef int (* lssinkFn_t) (void *devContext, byte *pData, int size);

typedef struct
{
    word             filename [RTSMB_CFG_MAX_FILENAME_SIZE + 1];   /* big enough for unicode with null term */
    word             fattributes;

    ddword           fatime64; /* last access time */
    ddword           fwtime64; /* last write time */
    ddword           fctime64; /* last create time */
    ddword           fhtime64; /* last change time */

    ddword           fsize;

    lssinkFn_t       sink_Fn;
    void             *sink_parameters;

} NEWRTSMB_CLI_SESSION_DSTAT;

#define RTSMB_NBSS_COM_MESSAGE            0x00
#define PDIFF(p, q) (std::ptrdiff_t)((std::ptrdiff_t) (p) - (std::ptrdiff_t) (q))


int rtsmb_cli_session_find_first(int sid, char *sharename, char *pattern, NEWRTSMB_CLI_SESSION_DSTAT *pstat1);
int rtsmb_cli_session_find_next(int sid,  NEWRTSMB_CLI_SESSION_DSTAT *pstat1);
void rtsmb_cli_session_find_close(int sid,  NEWRTSMB_CLI_SESSION_DSTAT *pstat1);


extern void rtsmb_util_guid(byte *_pGuid);
extern ddword rtsmb_util_get_current_filetime(void);
extern void rtsmb_util_ascii_to_unicode (char *ascii_string ,word *unicode_string, size_t w);
extern void rtsmb_util_unicode_to_ascii (word *unicode_string, char *ascii_string);
int rtsmb_util_unicode_strlen(word *str);
word *rtsmb_util_string_to_upper (word *string);
char *rtsmb_util_string_to_upper (char *cstring);
word *rtsmb_util_malloc_ascii_to_unicode (char *ascii_string);


typedef enum smb_diaglevel_e {
    DIAG_DISABLED      =0,
    DIAG_CONSOLE       =1,
    DIAG_JUNK          =1,             // Handy for bumping diagnostics.
    DIAG_INFORMATIONAL =2,
    DIAG_DEBUG         =3,
} smb_diaglevel;
extern void diag_dump_bin_fn(smb_diaglevel at_diaglayer,  const char *prompt, void *buffer, int size);
extern void diag_dump_unicode_fn(smb_diaglevel at_diaglayer,  const char *prompt, void *buffer, int size);
extern void diag_printf_fn(smb_diaglevel at_diaglayer, const char* fmt...);

extern char *rtsmb_strmalloc(char *str);


bool checkSessionSigned();
void setSessionSigned(bool isSigned);
extern const char *rtsmb_util_errstr(int &util_errno);

typedef struct {void *ptr; size_t size;} allocated_item_t;
inline void free_item(allocated_item_t &item)
 {
 if (item.ptr)
      {   void *p = item.ptr;
          diag_printf_fn(DIAG_INFORMATIONAL,"Free size:%d addr:%X\n", item.size, item.ptr);
          rtp_free_auto_free(p);
      }
}

/// Inheret this class to auto free heap data allocated with local_rtp_malloc(size_t nbytes) when the object's destructor runs
class local_allocator {
public:
  local_allocator() {};
  ~local_allocator() { std::for_each (allocated_items.begin(), allocated_items.end(), free_item);}
  void *local_rtp_malloc(size_t nbytes)
  {
     allocated_item_t r;
     r.size=nbytes;
     r.ptr = rtp_malloc_auto_freed(nbytes);
diag_printf_fn(DIAG_INFORMATIONAL,"Localalloc size:%d addr:%X\n", nbytes, r.ptr);
     allocated_items.push_back(r);
     return r.ptr;
  }
private:
  std::vector<allocated_item_t> allocated_items;
};

#endif // include_smb2defs
