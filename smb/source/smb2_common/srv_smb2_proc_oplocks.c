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
#include "srvcfg.h"
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"
#include "rtptime.h"
#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"
#include "rtpmem.h"
#include "srv_smb2_proc_fileio.h"

BBOOL Proc_smb2_Lock(smb2_stream  *pStream)
{
RTSMB2_LOCK_REQUEST_C command;
RTSMB2_LOCK_REQUEST_R response;
RTSMB2_FILEIOARGS fileioargs;

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));


    if (Process_smb2_fileio_prolog(&fileioargs, pStream, (PFVOID) &command, (PFVOID) (&command.FileId[0]),&command.StructureSize ,49))
    {
      return TRUE;
    }
    // HEREHERE Proc_smb2_Lock - todo
    rtp_printf("Num Lock regions: %d\n", command.LockCount);
    {
      RTSMB2_LOCK_ELEMENT *pLock;
      int i;

      pLock = &command.Locks;
      for (i=0; i < command.LockCount;i++, pLock++)
      {
        rtp_printf(" Offset: %ld Length: %ld\n", (dword) pLock->Offset, (dword)pLock->Length);
      }
    }
    // Set the status to success
    // pStream->OutHdr.Status_ChannelSequenceReserved = 0;
    response.StructureSize = 4;
    /* Success - see above if the client asked for stats */
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
}

#endif
#endif
