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


#define rtp_malloc_auto_freed rtp_malloc
#define rtp_free_auto_free rtp_free

#define rtp_wcslen_bytes(S) (rtp_wcslen((S))*2)

using std::cout;
using std::endl;

// Log levels for further processing by cout_log()
#define LL_JUNK  0
#define LL_TESTS 1
#define LL_INIT  2
// Macro for now but convert to a class for a better outcome
#define cout_log(level) cout


typedef unsigned char   byte;   //8-bit
typedef unsigned short  word;   //16-bit
typedef unsigned long   dword;  //32-bit
typedef unsigned long long ddword;  //32-bit


#define LARGEST_STRING 255

#define dualstringdecl(STRINGNAME) std::auto_ptr<dualstring> STRINGNAME(new(dualstring))
/// dualstring string container can be intialized with ascii or utf16 and then be dereferenced by either type utf16() or the ascii() methods.
/// Uses dynamic memory so use dualstringdecl(stringname) to ensure that the destrcutor is called to free memory.
class dualstring {
public:
  dualstring(int _maxlen=LARGEST_STRING) {buflen=0;maxlen=_maxlen; utf16view=0; asciiview=0;};
  ~dualstring() { if (utf16view) rtp_free_auto_free(utf16view); if (asciiview) rtp_free_auto_free(asciiview); };
//  word *utf16() { return (word *)((wchar_t *)utf16view.c_str()); }
  byte *ascii()  { return (byte *) asciiview;}
  word  *utf16() { return utf16view;}
  int   input_length() { return inlen; }
  bool  istoolong() {return (inlen > maxlen);}
  void operator =(char *s)  {utf16view = (word *)rtp_malloc_auto_freed(2*(arglen(s)+1)); asciiview = (byte *)rtp_malloc_auto_freed(buflen+1); asciiview[buflen]=0; utf16view[buflen]=0; for (int i=0;i<buflen; i++) {asciiview[i]=(byte)s[i];utf16view[i]=(word)s[i];utf16view[i+1]=0;asciiview[i+1]=0;}}
  void operator =(word *s)  {utf16view = (word *)rtp_malloc_auto_freed(2*(arglen(s)+1)); asciiview = (byte *)rtp_malloc_auto_freed(buflen+1); asciiview[buflen]=0; utf16view[buflen]=0; for (int i=0;i<buflen; i++) {asciiview[i]=(byte)s[i];utf16view[i]=(word)s[i];utf16view[i+1]=0;asciiview[i+1]=0;}}
private:
  int maxlen;
  int buflen;
  int inlen;
  int arglen(char *s)  { inlen=0; buflen=0; while(s[inlen++]);  buflen = std::min(inlen,maxlen); return buflen; }
  int arglen(word *s)  { inlen=0; buflen=0; while(s[inlen++]); buflen = std::min(inlen,maxlen); return buflen;}
  word *utf16view;
  byte *asciiview;
};



#define TURN_ON(A, B)	{(A) |= (B);}
/* if A is false, return B */
#define ASSURE(A, B)    {if (!(A))	return B;}
/* if A is false, return */
// #define ASSURE_V(A)     {if (!(A))	return;}


#define RTSMB_CFG_MAX_SESSIONS                      1
#define RTSMB_CFG_MAX_SHARESPERSESSION               1
#define RTSMB_CFG_MAX_SHARENAME_SIZE               80


#define RTSMB_CFG_MAX_GROUPNAME_SIZE   10   // the maximum size of group names
#define RTSMB_CFG_MAX_USERNAME_SIZE    128  // the maximum size of account names
#define RTSMB_CFG_MAX_PASSWORD_SIZE    128  // the maximum size of passwords (must be at least 24 when using encryption)
#define RTSMB_CFG_MAX_DOMAIN_NAME_SIZE 128  // the maximum size of domain names


#define RTSMB_CFG_MAX_BUFFER_SIZE     32768    // The physical buffer size we stream through

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
    NetStatusBadCallParms      = -6
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


// void spnego_decoded_NegTokenInit_destructor(decoded_NegTokenInit_t *decoded_token);
int spnego_decode_NegTokenTarg_challenge(decoded_NegTokenTarg_challenge_t *decoded_targ_token, unsigned char *pinbuffer, size_t buffer_length);
void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);


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


#define RTSMB_CLI_SSN_RV_OK                    0    /* everything is good */
#define RTSMB_CLI_SSN_RV_SENT                  1    /* The callback sends this when the packet was send internally and doesn't need to be sent from the top */
#define RTSMB_CLI_SSN_RV_DEAD                 -3   /* session is untenable and should be closed */
#define RTSMB_CLI_SSN_RV_BAD_ARGS             -6   /* argument to function is out of range */
#define RTSMB_CLI_SSN_RV_TOO_MANY_JOBS        -7   /* too many jobs waiting */
#define RTSMB_CLI_SSN_RV_TOO_MANY_USERS       -8   /* too many users logged on */

#define RTSMB_CLI_SSN_RV_ALREADY_CONNECTED    -20  /* already connected to a share */

#define RTSMB_CLI_SSN_SMB2_QUERY_MORE         -102 /* the SMB2 retrieve is still in progress, display current results */
#define RTSMB_CLI_SSN_SMB2_QUERY_FINISHED     -103 /* the SMB2 retrieve is complte. Send a search close */
#define RTSMB_CLI_SSN_SMB2_COMPUND_INPUT      -104 /* the SMB2 packet indicates moree data */
#define RTSMB_CLI_SSN_RV_INVALID_RV           -100 /* this is guaranteed to never be used as an rv value */

#define RTSMB_NBSS_COM_MESSAGE            0x00
#define PDIFF(p, q) (std::ptrdiff_t)((std::ptrdiff_t) (p) - (std::ptrdiff_t) (q))



int rtsmb_cli_session_find_first(int sid, char *sharename, char *pattern, NEWRTSMB_CLI_SESSION_DSTAT *pstat1);
int rtsmb_cli_session_find_next(int sid,  NEWRTSMB_CLI_SESSION_DSTAT *pstat1);
void rtsmb_cli_session_find_close(int sid,  NEWRTSMB_CLI_SESSION_DSTAT *pstat1);
int wait_on_job_cpp(int sid, int job);

class Smb2Session {
public:
  Smb2Session() {}
#define CONNECTED 1
  int session_wire_state;
};

typedef struct smb2_iostream_s {
  int xx;
#define INFO_CAN_TIMEOUT 1
  dword buffer_flags;
  ddword buffer_mid;
#define WAITING_ON_US 1
#define WAITING_ON_SERVER 2
  int  buffer_state;
  dword buffer_end_time_base;
  int session_wire_state;     // There are two instances, tbd
  byte *session_wire_incoming_nbss_header;
} smb2_iostream;

void rtsmb_util_guid(byte *_pGuid);
extern ddword rtsmb_util_get_current_filetime(void);
void rtsmb_util_ascii_to_unicode (char *ascii_string ,word *unicode_string, size_t w);
void rtsmb_util_guid(byte *_pGuid);


#endif // include_smb2defs
