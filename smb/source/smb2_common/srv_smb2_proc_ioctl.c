//
// SRV_SMB2_SSN.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles most of the actual processing of packets for the RTSMB server.
//

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include <stdio.h>
#if (INCLUDE_RTSMB_SERVER)
#include "com_smb2.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"


#include "rtptime.h"

BBOOL Proc_smb2_Ioctl(smb2_stream  *pStream)
{
	RTSMB2_IOCTL_C command;
	RTSMB2_IOCTL_R response;
	dword error_status = 0;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Ioctl:  RtsmbStreamDecodeCommand failed...\n",0);
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }
    if (command.CtlCode == FSCTL_DFS_GET_REFERRALS)
      error_status = SMB2_STATUS_NOT_FOUND;  // Return this to continue mounting
    else
      error_status = SMB2_STATUS_NOT_FOUND;
    if (error_status)
    {
        RtsmbWriteSrvStatus(pStream, error_status);
    }
    else
    {
        /* Passes cmd_fill_negotiate_response_smb2 pOutHdr, and &response */
        RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    }
    return TRUE;
} // Proc_smb2_Ioctl

#endif
#endif
