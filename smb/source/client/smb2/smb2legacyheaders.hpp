//
// smb2legacyheaders.hpp -
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
#ifndef include_smb2legacyheaders
#define include_smb2legacyheaders
extern "C" {
#include "smbdefs.h"
#include "smbutil.h"
#include "smbnet.h"
#include "smbspnego.h"

#include "rtpnet.h"
#include "rtpmem.h"
#include "rtpwcs.h"
#include "rtptime.h"
#include "rtpthrd.h"

#include "clissn.h"



extern "C" void rtsmb_cli_smb2_session_init (PRTSMB_CLI_SESSION pSession);
extern "C" int rtsmb_cli_wire_smb2_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);
extern "C" void rtsmb_cli_session_memclear (PRTSMB_CLI_SESSION pSession);
extern "C" void rtsmb_cli_session_user_new (PRTSMB_CLI_SESSION_USER pUser, word uid);


// DSTAT is a basic type that can be extracted easily from clissn.h
extern "C" void DisplayDirscan(PRTSMB_CLI_SESSION_DSTAT pstat);
extern "C" int FormatDirscanToDstat(void *pBuffer);
extern "C" int rtsmb_cli_session_find_first (int sid, PFCHAR share, PFCHAR pattern, PRTSMB_CLI_SESSION_DSTAT pdstat);

extern "C" int rtsmb_cli_session_get_free_session (void);
extern "C" int rtsmb_cli_session_ntlm_auth (int sid, byte * user, byte * password, byte *domain, byte * serverChallenge, byte *serverInfoblock, int serverInfoblock_length);
extern "C" int rtsmb_cli_session_translate_error32 (dword status);


}

#endif // include_smb2legacyheaders
