//
// SRVRSRCS.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles NETBIOS Session Layer including claiming and freeing sessions
//

#include "smbdefs.h"

#if (INCLUDE_RTSMB_SERVER)

#include "srvrsrcs.h"
#include "srvcfg.h"
#include "rtpsignl.h"
#include "smbdebug.h"




PFBYTE allocateBigBuffer (void)
{
	word i;
	PFBYTE rv = (PFBYTE)0;

	CLAIM_BUF ();
	for (i = 0; i < prtsmb_srv_ctx->num_big_buffers; i++)
	{
		if (!prtsmb_srv_ctx->bigBufferInUse[i])
		{
			prtsmb_srv_ctx->bigBufferInUse[i] = 1;
			rv = &prtsmb_srv_ctx->bigBuffers[i * prtsmb_srv_ctx->big_buffer_size];
			break;
		}
	}
	RELEASE_BUF ();

	return rv;
}

void freeBigBuffer (PFBYTE p)
{
	int location;
	location = INDEX_OF (prtsmb_srv_ctx->bigBuffers, p);

	CLAIM_BUF ();
	prtsmb_srv_ctx->bigBufferInUse[location] = 0;
	RELEASE_BUF ();
}

#endif /* INCLUDE_RTSMB_SERVER */
