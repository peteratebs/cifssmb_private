//
// SRV_SMB2_ASSERT.C -
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


#include <stdio.h>
#include "com_smb2.h"
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"


#include "rtptime.h"

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"


BBOOL assert_smb2_uid(smb2_stream  *pStream)
{
	PUSER user;

	// no need to authenticate when in share mode
	if (pStream->psmb2Session->pSmbCtx->accessMode == AUTH_SHARE_MODE)
	{
		return FALSE;
	}
	user = SMBU_GetUser (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->uid);

	if (user == (PUSER)0)
	{
        RtsmbWriteSrvStatus(pStream, SMB2_STATUS_SMB_BAD_UID);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
    return TRUE;   //
}
// undefined behavior if uid doesn't exist
BBOOL assertThissmb2Tid (smb2_stream  *pStream)
{
	if (SMBU_GetTree (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid))
	{  // Ok the tree exists
		return FALSE;
	}

    RtsmbWriteSrvStatus(pStream, SMB2_STATUS_SMB_BAD_TID);
	return TRUE;
}
BBOOL assert_smb2_tid(smb2_stream  *pStream)
{
  return assertThissmb2Tid (pStream);
}

BBOOL assert_smb2_permission(smb2_stream  *pStream,byte permission)
{
	PTREE tree;

	tree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid);

	if (!tree || tree->access == SECURITY_NONE ||
		(tree->access != SECURITY_READWRITE && tree->access != permission))
	{
		RTSMB_DEBUG_OUTPUT_STR ("failed permissions check with permission of ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (permission);
		RTSMB_DEBUG_OUTPUT_STR (" against permission of ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (tree->access);
		RTSMB_DEBUG_OUTPUT_STR (" on tid ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (pStream->psmb2Session->pSmbCtx->tid);
		RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
        RtsmbWriteSrvStatus(pStream, SMB2_STATUS_ACCESS_DENIED);
		return TRUE;
	}

	return FALSE;
}
// undefined behavior if uid or tid isn't valid
// or if user doesn't have access permissions
// this also checks for old errors on this fid
BBOOL assert_smb2_Fid (smb2_stream  *pStream, word external, word flag)
{
	int fid;
	byte ec = 0;
	word error = 0;
    PSMB_SESSIONCTX pCtx = pStream->psmb2Session->pSmbCtx;
	if ((fid = SMBU_GetInternalFid (pCtx, external, flag,0)) == -2)
	{
        RtsmbWriteSrvStatus(pStream, SMBU_MakeError(SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS));
		return TRUE;
	}
	else if (fid < 0)
	{
        RtsmbWriteSrvStatus(pStream, SMBU_MakeError(SMB_EC_ERRDOS, SMB_ERRDOS_BADFID));
		return TRUE;
	}

	// check if an error is waiting for us
	SMBU_GetFidError (pCtx, external, &ec, &error);

	if (error > 0)
	{
		SMBU_SetFidError (pCtx, external, SMB_EC_SUCCESS, 0);
        RtsmbWriteSrvStatus(pStream, SMBU_MakeError(ec, error));
		return TRUE;
	}

	return FALSE;
}
