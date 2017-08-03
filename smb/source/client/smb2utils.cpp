//
// smb2logon.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
#include <memory>
#include "smb2utils.hpp"

using std::cout;
using std::endl;

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include <wireobjects.hpp>
#include <smb2wireobjects.hpp>
#include <netstreambuffer.hpp>

// --------------------------------------------------------
// extern "C" void mark_rv_cpp (int job, int rv, void *data)
extern "C" {
static void mark_rv_cpp (int job, int rv, void *data)
{
    int *idata = (int *)data;

    *idata = rv;
    if (rv == -RTSMB_CLI_WIRE_BAD_MID)
        cout << "Bad Permissions, Marked" << *idata << endl;
}
}
int wait_on_job_cpp(int sid, int job)
{
    int rv = RTSMB_CLI_SSN_RV_INVALID_RV;
    rtsmb_cli_session_set_job_callback(sid, job, mark_rv_cpp, &rv);
    while(rv == RTSMB_CLI_SSN_RV_INVALID_RV )
    {
        int r = rtsmb_cli_session_cycle(sid, 10);
        if (r < 0)
        {
//            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "\n wait_on_job: rtsmb_cli_session_cycle returned error == %d\n",r);
            return r;
        }
    }
    return rv;
}


#endif /* INCLUDE_RTSMB_CLIENT */
#endif