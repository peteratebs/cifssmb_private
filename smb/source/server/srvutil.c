//
// SRVUTIL.C -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  [tbd]
//

//============================================================================
//    IMPLEMENTATION HEADERS
//============================================================================
#include "smbdefs.h"
#include "rtpstr.h"   /* _YI_ 9/24/2004 */
#include "rtpwcs.h"   /* _YI_ 9/24/2004 */
#include "rtpwchar.h" /* _YI_ 9/24/2004 */
#include "rtpchar.h"  /* _YI_ 9/27/2004 */
#include "smbdebug.h" /* _VM_ 12/23/2004 */
#include "rtpprint.h"
#include "srvobjectsc.h"

#if (INCLUDE_RTSMB_SERVER)
#define PRINT_VIA_CUPS 0//enable this only if you want to print via CUPS

#include "srvutil.h"
#include "srvssn.h"
#include "srvfio.h"
#include "srvshare.h"
#include "srvrsrcs.h"
#include "srvans.h"
#include "smbutil.h"
#include "smbpack.h"
#include "srvipcfile.h"
#ifdef SUPPORT_SMB2
#include "com_smb2_wiredefs.h"
#endif
#include "srvobjectsc.h"


#if (INCLUDE_RTSMB_ENCRYPTION)
#include "smb_md4.h"
#endif


//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================
#define WRITE_TO_FILE_BUFFER_SIZE	1024

//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================
//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================
//============================================================================
//    INTERFACE DATA
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================
//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================



dword dwordalign(dword original, int a)
{
  dword dd = (dword) original;
  dword s = (dword)(a-1);
  dd=(dd+s)&~s;
  return  dd;
}

void *ptralign(void *ptr, int a)
{
#ifdef BUILD_SMB_64BIT
  ddword dd = (ddword) ptr;
  ddword s = (ddword)(a-1);
  dd=(dd+s)&~s;
  return (void *) dd;
#else
  dword dd = (dword) ptr;
  dword s = (dword)(a-1);
  dd=(dd+s)&~s;
  return (void *) dd;
#endif
}


PFRTCHAR SMBU_ShortenSMBPath (PFRTCHAR path)
{
	int i;

	for(i=0; i < 3; path = &(path[1]))
		if(path[0] == '\\') i++;

	return path;
}

void SMBU_FillNtError (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pOutHdr, dword errorCode)
{
	int size;

	pOutHdr->status = errorCode;

	size = srv_cmd_fill_header (pCtx->write_origin, pCtx->write_origin,
		prtsmb_srv_ctx->small_buffer_size, pOutHdr);
	if (size != -1)
	{
		tc_memset (PADD (pCtx->write_origin, size), 0, 3);
		pCtx->outBodySize = (rtsmb_size) (size + 3);
	}
}

dword SMBU_MakeError (PSMB_SESSIONCTX pCtx, byte errorClass, word errorCode)
{
  dword error = 0;
#ifdef SUPPORT_SMB2
  if (pCtx && pCtx->pCtxtsmb2Session)
  {
    if (errorClass == SMB_EC_ERRDOS)
    {
      switch (errorCode) {
       case SMB_ERRDOS_BADACCESS:
         return SMB2_STATUS_UNSUCCESSFUL;
       case SMB_ERRDOS_BADFID:
         return SMB2_STATUS_INVALID_HANDLE;
       case SMB_ERRDOS_BADFILE:
         return SMB2_STATUS_OBJECT_NAME_NOT_FOUND;
       case SMB_ERRDOS_BADPATH:
         return SMB2_STATUS_OBJECT_PATH_NOT_FOUND;
       case SMB_ERRDOS_DIFFDEVICE:
         return SMB2_STATUS_UNSUCCESSFUL;
       case SMB_ERRDOS_FILEEXISTS:
         return SMB2_STATUS_OBJECT_NAME_COLLISION;
       case SMB_ERRDOS_NOACCESS:
         return SMB2_STATUS_ACCESS_DENIED;
       case SMB_ERRDOS_NOFIDS:
         return SMB2_STATUS_UNSUCCESSFUL;
       case SMB_ERRDOS_REMCD:
         return SMB2_STATUS_UNSUCCESSFUL;
       }
    }
    else if (errorClass == SMB_EC_ERRSRV)
    {
      switch (errorCode) {
       case SMB_ERRSRV_ACCESS:
       case SMB_ERRSRV_BADPW:
       case SMB_ERRSRV_BADUID:
           return SMB2_STATUS_ACCESS_DENIED;
       case SMB_ERRSRV_ERROR:
       case SMB_ERRSRV_INVDEVICE:
       case SMB_ERRSRV_INVNETNAME:
       case SMB_ERRSRV_INVNID:
       case SMB_ERRSRV_NOSUPPORT:
       case SMB_ERRSRV_SMBCMD:
       case SMB_ERRSRV_SRVERROR:
         return SMB2_STATUS_UNSUCCESSFUL;
       case SMB_ERRSRV_TOOMANYUIDS:
         return SMB2_STATUS_SMB_TOO_MANY_GUIDS_REQUESTED;
       case SMB_ERRSRV_USESTD:
         return SMB2_STATUS_UNSUCCESSFUL;
       }
     }
     else if (errorClass == SMB_EC_ERRHRD)
     {
       switch (errorCode) {
        case SMB_ERRHRD_GENERAL:
        case SMB_ERRHRD_READ:
        case SMB_ERRHRD_SEEK:
        case SMB_ERRHRD_WRITE:
          return SMB2_STATUS_UNSUCCESSFUL;
       }
      }
      else
      {
         return SMB2_STATUS_UNSUCCESSFUL;
      }
  }
  else
#endif
  {
    error |= ((dword)errorCode) << 16;
    error |= ((dword)errorClass);
  }
  return error;
}
void SMBU_FillError (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pOutHdr, byte errorClass, word errorCode)
{
	int size;

	pOutHdr->status = SMBU_MakeError (pCtx ,errorClass, errorCode);

	size = srv_cmd_fill_header (pCtx->write_origin, pCtx->write_origin,
		prtsmb_srv_ctx->small_buffer_size, pOutHdr);
	if (size != -1)
	{
		tc_memset (PADD (pCtx->write_origin, size), 0, 3);
		pCtx->outBodySize = (rtsmb_size) (size + 3);
	}
}

void SMBU_AddError (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pHdr, PFVOID buf, byte errorClass, word errorCode)
{
	pHdr->status = SMBU_MakeError (pCtx, errorClass, errorCode);
	tc_memset (buf, 0, 3);	/* pretty unsafe, but it is only 3 bytes */
}

PUSER SMBU_GetUser (PSMB_SESSIONCTX pCtx, word uid)
{
	word i;

	for (i = 0; i < prtsmb_srv_ctx->max_uids_per_session; i++)
	{
		if (pCtx->uids[i].inUse && pCtx->uids[i].uid == uid)
		{
			return &pCtx->uids[i];
		}
	}

	return (PUSER)0;
}


// returns -1 if not found
// returns -2 if found, but not valid
// flag_mask is a set of bits that the flag value *can* have
int SMBU_GetInternalFid (PSMB_SESSIONCTX pCtx, word external, word flag_mask, word *rflags, dword *rsmb2flags)
{
	PUSER user;

	user = SMBU_GetUser (pCtx, pCtx->uid);

	if (user == (PUSER)0)
		return -1;
    if (rsmb2flags)
     *rsmb2flags = 0;

	if (external >= prtsmb_srv_ctx->max_fids_per_uid)
		return -1;
	if (user->fids[external] && user->fids[external]->internal_fid != -1 &&
		user->fids[external]->tid == pCtx->tid)
	{
		if (OFF (user->fids[external]->flags, ~flag_mask))
		{
			if (rflags) /* IF flags passed retuern the flags value */
				*rflags = user->fids[external]->flags;
           if (rsmb2flags)
             *rsmb2flags = user->fids[external]->smb2flags;

			return user->fids[external]->internal_fid;
		}
		else
		{
			return -2;
		}
	}
	return -1; // not found
}

/* performs a caseless lookup on 'name'.  returns -1 if not found */
int SMBU_GetInternalFidFromName (PSMB_SESSIONCTX pCtx, PFRTCHAR name)
{
	PUSER user;
	int i;

	user = SMBU_GetUser (pCtx, pCtx->uid);

	if (user == (PUSER)0)
		return -1;

	for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
	{
		if (user->fids[i] && user->fids[i]->internal_fid != -1 &&
			user->fids[i]->tid == pCtx->tid &&
			rtsmb_casecmp (name, user->fids[i]->name, CFG_RTSMB_USER_CODEPAGE) == 0)
		{
			return user->fids[i]->internal_fid;
		}
	}

	return -1; // not found
}

int SMBU_GetFidError (PSMB_SESSIONCTX pCtx, word external, byte *ec, word *error)
{
	int i;
	PUSER user;

	user = SMBU_GetUser (pCtx, pCtx->uid);

	if (user == (PUSER)0)
		return -1;

	for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
		if (user->fids[i] && user->fids[i]->internal_fid >= 0 &&
			user->fids[i]->external == external)
		{
			*ec = (byte) (user->fids[i]->error >> 16);
			*error = (word) (user->fids[i]->error & 0xFFFF);
			return 0;
		}

	return -1; // not found
}


void SMBU_SetFidSmb2Flags (PSMB_SESSIONCTX pCtx, word external,   dword smb2flags )
{
	int i;
	PUSER user;
	user = SMBU_GetUser (pCtx, pCtx->uid);
	if (user == (PUSER)0)
		return;

	for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
		if (user->fids[i] && user->fids[i]->internal_fid >= 0 &&
			user->fids[i]->external == external)
		{
            user->fids[i]->smb2flags = smb2flags;
            return;
		}
}

// returns 0 on success
int SMBU_SetFidError (PSMB_SESSIONCTX pCtx, word external, byte ec, word error )
{
	int i;
	PUSER user;

	user = SMBU_GetUser (pCtx, pCtx->uid);
	if (user == (PUSER)0)
		return -1;

	for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
		if (user->fids[i] && user->fids[i]->internal_fid >= 0 &&
			user->fids[i]->external == external)
		{
			user->fids[i]->error = ((dword)ec << 16) | (dword)error;
			return 0;
		}

	return -1; // bad external
}



// Scans all open FIDS
int SMBU_EnumerateFids(enumFidFnType fn, void *enumargs)
{
    word i, j;
    PSMB_SESSIONCTX pCtx;
    /* find all resources claimed by us and free them   */
    for (i = 0; i < prtsmb_srv_ctx->max_sessions; i++)
    {
        pCtx = &prtsmb_srv_ctx->sessions[i].smbCtx;
        for (j = 0; j < prtsmb_srv_ctx->max_fids_per_session; j++)
        {
            if (pCtx->fids[j].internal_fid >= 0 && pCtx->fids[j].pid == pCtx->pid)
            {
               int r = fn(&pCtx->fids[j], &prtsmb_srv_ctx->sessions[i], pCtx,enumargs);
               if (r != 0)
                 return r;
            }
        }
    }
    return 0;
}
struct enumFidArgsType_s {
  PTREE tree; word uid; word externalfid; int oplocklevel;
};
static int SMBU_SetOplockLevelCB (PFID fid, PNET_SESSIONCTX pnCtx, PSMB_SESSIONCTX pCtx, void *pargs)
{
  struct enumFidArgsType_s * pArgs = (struct enumFidArgsType_s *) pargs;
  if (fid->external == pArgs->externalfid)
  {
     fid->held_oplock_level = pArgs->oplocklevel;
     fid->held_oplock_uid = pArgs->uid;
     return 1;
  }
  return 1;
}

void SMBU_SetOplockLevel (PTREE tree, word uid, word externalfid, int oplocklevel)
{
int j;
struct enumFidArgsType_s args;
    args.tree = tree;
    args.uid  = uid;
    args.externalfid = externalfid;
    args.oplocklevel = oplocklevel;
    SMBU_EnumerateFids(SMBU_SetOplockLevelCB, (void *) &args);
	return;
}


struct SMBU_Fid2Session_s {
PNET_SESSIONCTX netsession;
PFID pfid;
};
static int SMBU_Fid2SessionCB (PFID fid, PNET_SESSIONCTX pnCtx, PSMB_SESSIONCTX pCtx, void *pargs)
{
  if ( ((struct SMBU_Fid2Session_s*)pargs)->pfid == fid )
  {
    ((struct SMBU_Fid2Session_s*)pargs)->netsession = pnCtx;
    return 1;
  }
  return 0;
}
PNET_SESSIONCTX SMBU_Fid2Session(PFID pfid)
{
  struct SMBU_Fid2Session_s args;
  args.netsession = 0;
  args.pfid = pfid;
  SMBU_EnumerateFids(SMBU_Fid2SessionCB, (void *) &args);
  return args.netsession;
}



BBOOL SMBU_CheckMyInode(byte *this_uid)
{
static byte break_uid[] = {0x72, 0x08, 0x07, 0,0,0,0,0};  // "demo_pages"
  return (tc_memcmp (this_uid ,break_uid,8)==0);
}

struct enumFidSearchUniqueidType_s {
  byte *unique_fileid;
  PFID result;
};

static int _SMBU_SearchUniqueidCB (PFID fid, PNET_SESSIONCTX pnCtx, PSMB_SESSIONCTX pCtx, void *pargs)
{
  struct enumFidSearchUniqueidType_s * pArgs = (struct enumFidSearchUniqueidType_s *) pargs;
  if (tc_memcmp(fid->unique_fileid,pArgs->unique_fileid,sizeof(fid->unique_fileid)) == 0)
  {
    pArgs->result = fid;
    return 1;
  }
  return 0;
}
static PFID SMBU_SearchFidByUniqueId (byte *unique_fileid)
{

 struct enumFidSearchUniqueidType_s args;
   args.result = 0;
   args.unique_fileid = unique_fileid;
  char temp0[80];
  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBU_SeardFidByUniqueId %d files for %s\n", prtsmb_srv_ctx->max_fids_per_tree, SMBU_format_fileid(unique_fileid, 8, temp0));
  args.result = 0;
  if (SMBU_EnumerateFids(_SMBU_SearchUniqueidCB, (void *) &args))
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBU_SeardFidByUniqueId yes matched for %s\n", SMBU_format_fileid(unique_fileid, 8, temp0));
  else
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBU_SeardFidByUniqueId no match for %s\n", SMBU_format_fileid(unique_fileid, 8, temp0));

  return args.result;
}

PFID  SMBU_CheckOplockLevel (PTREE tree, word uid, byte *unique_fileid, int *pCurrentOplockLevel)
{
PFID pfid = SMBU_SearchFidByUniqueId (unique_fileid);
  if (pfid)
  {
    char temp0[80];
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBU_CheckOplockLevel fake return for %s\n", SMBU_format_fileid(unique_fileid, 8, temp0));
    *pCurrentOplockLevel = pfid->held_oplock_level;
     return pfid;
  }
  return 0;
}

// uid, tid must be valid
// finds free slot and
// returns external fid associated with this internal one
// returns -1 if not found
int SMBU_SetInternalFid (PSMB_SESSIONCTX pCtx, int internal_fid, PFRTCHAR name, word flags, dword smb2flags, byte *unique_fileid)
{
	PTREE tree;
	PUSER user;
	word i, j, k;

	tree = SMBU_GetTree (pCtx, pCtx->tid);
	user = SMBU_GetUser (pCtx, pCtx->uid);


	if (!user || !tree)
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"SMBU_SetInternalFid: user or tree is not valid.\n");
		return -1;
	}
	/**
	 * The user has requested a new fid, so we try to find a slot for it
	 */

	for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
	{
		if (!user->fids[i])
		{
			break;
		}
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"FID: SMBU_SetInternalFid: list xfid: %u \n",user->fids[i]->external);
        rtsmb_dump_bytes("FID: list file name", user->fids[i]->name, 80, DUMPUNICODE);
	}

	if (i == prtsmb_srv_ctx->max_fids_per_uid) // no space found
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"FID: SMBU_SetInternalFid: Not enough space for new file in user data.\n");
		return -1;
	}

	// user has space for fid, but does tree?
	for (j = 0; j < prtsmb_srv_ctx->max_fids_per_tree; j++)
	{
		if (!tree->fids[j])
		{
			break;
		}
	}

	if (j == prtsmb_srv_ctx->max_fids_per_tree)	// no space on tree
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"FID: SMBU_SetInternalFid: Not enough space for new file in tree data.\n");
		return -1;
	}

	// at this point, we know both the user and the tree have space for
	// the fid.  but, does the session?
	for (k = 0; k < prtsmb_srv_ctx->max_fids_per_session && pCtx->fids[k].internal_fid != -1; k++);

	if (k == prtsmb_srv_ctx->max_fids_per_session)	// no space on session
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"FID: SMBU_SetInternalFid: Not enough space for new file in session data.\n");
		return -1;
	}

	// setup the fid for user and tree
	user->fids[i] = &pCtx->fids[k];
	tree->fids[j] = &pCtx->fids[k];
	// setup the fid values in master list
	pCtx->fids[k].internal_fid = internal_fid;
#warning FID allocatin scheme need fix for oplocks
	pCtx->fids[k].external = k;
	pCtx->fids[k].pid = pCtx->pid;
	pCtx->fids[k].tid = pCtx->tid;
	pCtx->fids[k].uid = pCtx->uid;
	pCtx->fids[k].error = 0;
	pCtx->fids[k].flags = flags;
	pCtx->fids[k].smb2flags = smb2flags;
	pCtx->fids[k].held_oplock_level = 0;
    pCtx->fids[k].held_oplock_uid = 0;
	pCtx->fids[k].requested_oplock_level = 0;
    pCtx->fids[k].smb2waitexpiresat = 0;
	tc_memcpy(pCtx->fids[k].unique_fileid,unique_fileid,sizeof(pCtx->fids[k].unique_fileid));
    srvobject_add_fid(&pCtx->fids[k]);

	// here we assume name is not too long (should be true b/c of reading-from-wire methods)
	rtsmb_cpy (pCtx->fids[k].name, name);
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"FID: SMBU_SetInternalFid: set xfid: %u tid:%u\n",pCtx->fids[k].external, pCtx->tid);
    rtsmb_dump_bytes("FID: set file name", pCtx->fids[k].name, 80, DUMPUNICODE);

	return k;
}


// returns a pointer to fid or null
PFID SMBU_GetInternalFidPtr (PSMB_SESSIONCTX pCtx,  word external)
{
	int k;
	// find fid in master list
	for (k = 0; k < prtsmb_srv_ctx->max_fids_per_session; k++)
	{
		if (pCtx->fids[k].internal_fid != -1 &&
			pCtx->fids[k].external == external)
		{
            return &pCtx->fids[k];
			break;
		}
	}
	return 0; // not found
}

// uid, tid, external must be valid
// sets the internal fid for this external to unused
void SMBU_ClearInternalFid (PSMB_SESSIONCTX pCtx, word external)
{
	PTREE tree;
	PUSER user;
	word i, j, k;
    PFID pFid = 0;

	RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "FID: SMBU_ClearInternalFid: clear fids:%u\n",external);

#if (0 && HARDWIRED_INCLUDE_DCE)
    {
      tree = SMBU_GetTree( pCtx, pCtx->tid);
      // Special case of ipc just determine that it is a valid handle
      if (tree && tree->type == ST_IPC)
        return;
    }
#endif

	// find fid in master list
	for (k = 0; k < prtsmb_srv_ctx->max_fids_per_session; k++)
	{
		if (pCtx->fids[k].internal_fid != -1 &&
			pCtx->fids[k].external == external)
		{
            pFid = &pCtx->fids[k];
			break;
		}
	}

	if (k == prtsmb_srv_ctx->max_fids_per_session)	// bad external
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "FID: SMBU_ClearInternalFid: Bad external fid: %d\n",external);
		return;
	}

	tree = SMBU_GetTree (pCtx, pCtx->fids[k].tid);
	user = SMBU_GetUser (pCtx, pCtx->fids[k].uid);

	/**
	 * Here, the user wants to get rid of this fid.
	 * We need to find the fid in the tree and user and
	 * nullify them
	 */

	if (!user)
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "FID: SMBU_ClearInternalFid: No user for fid:%d\n",external);

	if (user)
	{
		// find fid in user list and nullify
		for (i = 0; i < prtsmb_srv_ctx->max_fids_per_uid; i++)
		{
			if (user->fids[i] == &pCtx->fids[k])
			{
				break;
			}
		}

		if (i < prtsmb_srv_ctx->max_fids_per_uid) // if we found it...
		{
			user->fids[i] = (PFID)0;
		}
        else
        {
		  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "FID: SMBU_ClearInternalFid: Not in user list of fids:%d\n",external);
        }
	}

	if (!tree)
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "FID: SMBU_ClearInternalFid: No user for fid:%d\n",external);
	if (tree)
	{
		// find fid in tree list and nullify
		for (j = 0; j < prtsmb_srv_ctx->max_fids_per_tree; j++)
		{
			if (tree->fids[j] == &pCtx->fids[k])
			{
				break;
			}
		}

		if (j < prtsmb_srv_ctx->max_fids_per_tree)	// if we found it...
		{
			tree->fids[j] = (PFID)0;
		}
        else
        {
		  RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "FID: SMBU_ClearInternalFid: Not in tree  of fids:%d\n",external);
        }
	}

	// clear the fid in master list
#warning SMBU_ClearInternalFid needs to call void RtsmbYieldOplockCloseFile(PSMB_SESSIONCTX pCtx, PFID pfid)

    if (pCtx->fids[k].smb2flags & SMB2WAITOPLOCKREPLY)
      srvobject_tag_oplock(&pCtx->fids[k],"SMBU_ClearInternalFid freed waiting"); // Level Changed from two
    if (pCtx->fids[k].smb2flags & SMB2SENDOPLOCKBREAK)
      srvobject_tag_oplock(&pCtx->fids[k],"SMBU_ClearInternalFid freed bfor send"); // Level Changed from two
    // NULL everything except internal (-1 == free)
    tc_memset(&pCtx->fids[k], 0, sizeof(FID_T));
    pCtx->fids[k].internal_fid = -1;
RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "SMBU_ClearInternalFid: fID: %X pfid->internal_fid after should be -1:%d \n", &pCtx->fids[k], pCtx->fids[k].internal_fid);

}


// assumes valid uid/tid
// if tid == -1, return a free tree
// tid is external tid
PTREE SMBU_GetTree (PSMB_SESSIONCTX pCtx, int tid)
{
	/**
	 * Get the current info from the context.
	 */
	word i;
	PTREE rv = (PTREE)0;

	for (i = 0; i < prtsmb_srv_ctx->max_trees_per_session; i++)
	{
		if (tid < 0)
		{
			if (!pCtx->trees[i].inUse)
			{
				rv = &pCtx->trees[i];
				break;
			}
		}
		else
		{
			if (pCtx->trees[i].external == tid && pCtx->trees[i].inUse)
			{
				rv = &pCtx->trees[i];
				break;
			}
		}
	}

	// for testing purposes
	if (!rv)
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL, "BAD TREE with external id of %d \n");
	}

	return rv;
}


PFRTCHAR SMBU_GetFileNameFromFid (PSMB_SESSIONCTX pCtx, word external)
{
	int i;
	for (i = 0; i < prtsmb_srv_ctx->max_fids_per_session; i++)
	{
		if (pCtx->fids[i].internal_fid != -1 &&
			pCtx->fids[i].external == external)
		{
			return pCtx->fids[i].name;
		}
	}
	return (PFRTCHAR)0;
}




// returns true if s is a substring of src, false else
BBOOL SMBU_DoesContain (PFRTCHAR src, PFRTCHAR s)
{
	int i;
	int size;
	int ssize;


	size = (int)rtsmb_len (src);
	ssize = (int)rtsmb_len (s);


	for (i = 0; i <= size - ssize; i++)
	{
		if (rtsmb_ncmp (src, s, (rtsmb_size)ssize) == 0)
		{
			return TRUE;
		}

		src++;
	}
	return FALSE;
}


// returns smb path of filename without trailing '\\'
// dest and filename can overlap
// dest is expected to be SMBF_FILENAMESIZE
PFRTCHAR SMBU_GetPath (PFRTCHAR filename, PFRTCHAR dest)
{
	PFRTCHAR temp;
	rtsmb_char buf [SMBF_FILENAMESIZE + 1];

	rtsmb_ncpy (buf, filename, SMBF_FILENAMESIZE);
	buf[SMBF_FILENAMESIZE] = '\0';

	for (temp = &buf[rtsmb_len (buf)]; temp [0] != '\\' && temp != buf; temp --);
	temp[0] = '\0';

	rtsmb_cpy (dest, buf);

	return dest;
}

PFRTCHAR SMBU_GetFilename (PFRTCHAR filename)
{
	PFRTCHAR temp;
	temp = &filename[rtsmb_len (filename) - 1];
	while (temp[0] != '\\')
	{
		if (temp == filename)
		{
			return temp;
		}
		else
		{
			temp--;
		}
	}

	return ++temp;
}

/*************************************************************************
 * smbu_patcmp - Compare a string against a pattern using wildcards
 *
 * Parameters:
 *		pat - the pattern to match the string against
 *		name - the string to match
 * 	dowildcard - if set to 0, disables the use of wildcards in doing
 *			the comparison
 *
 * Returns:
 *		1 if the string matches
 *		0 otherwise
 *
 * Examples:
 *		smbu_patcmp("he*, w*", "hello, world", 1) returns 1
 *		smbu_patcmp("*z*", "hello, world", 1) returns 0
 *		smbu_patcmp("he?lo, world", "hello, world", 1) returns 1
 *		smbu_patcmp("he?lo, world", "hello, world", 0) returns 0
 *
 *************************************************************************/

int smbu_patcmp(PFRTCHAR pat, PFRTCHAR name, int dowildcard)
{
	int p,n,i;
	int res = 0;
	rtsmb_char stardotstar[] = {'*', '.', '*', '\0'};
	rtsmb_char dot[] = {'.', '\0'};

	if (!rtsmb_cmp(pat, stardotstar))
	{
		pat[1] = 0;
	}
	if (!rtsmb_cmp(pat, dot))
	{
		pat[0] = '*';
		pat[1] = 0;
	}

	for(p=0,n=0; pat[p]!=0; p++,n++)
	{
		if (pat[p]=='*' && dowildcard)
		{
			for(i=n; name[i]!=0; i++)
                res |= smbu_patcmp(&(pat[p+1]),&(name[i]),dowildcard);
			res |= smbu_patcmp(&(pat[p+1]),&(name[i]),dowildcard);
			return(res);
		}

		if (name[n] == 0)
		{
			/* Match * with end of string */
			if (pat[p]=='*' && pat[p+1] == 0 && dowildcard)
				return(1);
			else
				return(0);
		}

		if ((pat[p]!='?' || !dowildcard) && rtsmb_toupper (pat[p]) != rtsmb_toupper (name[n]))
				return(0);

	}
	if (name[n]==0)
		return(1);
	else
		return(0);
}

/**
 * This takes a pattern, a 'solution' for that pattern (a string that matches
 * the pattern), and two pointers to character pointers.
 *
 * When done, the two character pointers will point to two buffers holding
 * null-delimited strings representing what each wildcard in the pattern was
 * matched to in the solution.
 *
 * q will hold the parts matched by a '?' wildcard, while a will hold those
 * matched by a '*' wildcard.
 */
int whatWasMatched (PFRTCHAR pattern, PFRTCHAR solution, PFRTCHAR q, PFRTCHAR a)
{
	PFRTCHAR Qplace;	// question mark place
	PFRTCHAR Aplace;	// asterisk place
	word i;

	// can't work with the strings if they don't actually matched
	if (smbu_patcmp (pattern, solution, 1) == FALSE)
		return -1;

	Qplace = q;
	Aplace = a;

	for (i = 0; i < rtsmb_len (pattern); i++)
	{
		if (pattern[i] != '?' && pattern[i] != '*')
		{
			solution ++;
		}
		else
		{
			int size;
			PFRTCHAR RTSMB_FAR *place;
			PFRTCHAR beginning = solution;

			place = pattern[i] == '?' ? &Qplace : &Aplace;

			if (pattern[i] == '*') solution --; // '*' can match nothing

			// keep on testing end of string until we find a match
			while (smbu_patcmp (&pattern[i + 1], ++ solution, 1) == FALSE);
			// now, solution points to beginning of rest of string

            size = PDIFF(solution , beginning);

			rtsmb_ncpy (*place, beginning, (rtsmb_size)size);

			(*place) = &(*place)[size + 1];
		}
	}

	return 0;
}

/**
 * This returns a string representing 'destPattern', but with all the wildcards
 * pulled out and replaced by the strings in 'solution' that were matched by
 * 'pattern'.
 *
 * 'pattern' and 'destPattern' MUST have same numbers and types of wildcards
 */
PFRTCHAR SMBU_FitWildcards (PFRTCHAR pattern, PFRTCHAR solution, PFRTCHAR destPattern, PFRTCHAR dest)
{
	word i;
	PFRTCHAR place;
	rtsmb_char Qpieces[SMBF_FILENAMESIZE * 2];	/* doubled to reserve spaces for interspersed null chars */
	rtsmb_char Apieces[SMBF_FILENAMESIZE * 2];
	PFRTCHAR q, a;
	PFRTCHAR RTSMB_FAR *pieces;

	place = dest;
	tc_memset (Qpieces, 0, sizeof (Qpieces));
	tc_memset (Apieces, 0, sizeof (Apieces));

	if (whatWasMatched (pattern, solution, Qpieces, Apieces) != 0)
	{
		return (PFRTCHAR)0;
	}

	q = Qpieces;
	a = Apieces;

	for (i = 0; i < rtsmb_len (destPattern); i++)
	{
		if (destPattern[i] == '?' || destPattern[i] == '*')
		{
			pieces = destPattern[i] == '?' ? &q : &a;

			rtsmb_cpy (place, *pieces);
			place = &place[rtsmb_len (*pieces)];
			(*pieces) = &(*pieces)[rtsmb_len (*pieces) + 1]; // skip null char
		}
		else
		{
			place[0] = destPattern[i];
			place ++;
		}
	}

	place[0] = '\0';

	return dest;
}


// Takes a filename and makes it a 8.3 compliant.
// 'name' and 'buf' can overlap.
// 'buf' is a string of at least CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE char's,
//   that will be 'pad'-padded at the end of this call
//   with a null byte at the end
void SMBU_DOSifyName (PFRTCHAR name, PFRTCHAR buf, char pad)
{
	rtsmb_char result [CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE];
	rtsmb_char normalized_name [SMBF_FILENAMESIZE];
	int counter = 0;
	int dot = 0;
	BBOOL dotExists = TRUE;
	BBOOL mangled = FALSE;
	rtsmb_size name_size;
	rtsmb_char empty[] = {'\0'};
	rtsmb_char dotstr[] = {'.', '\0'};
	rtsmb_char dotdotstr[] = {'.', '.', '\0'};
	int i;

	/* Other illegal chars are ", <, >, ?, and *.  But, those are valid
	   wildcards, so we don't strip them here. */
#define RTSMB_DOSIFY_CHARS " ./\\[]:+|=;,"

	tc_memset (result, pad, sizeof (result));
	result [CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE - 1] = '\0';

	name_size = rtsmb_len (name);
	if (name_size < CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE)
	{
		result [name_size] = '\0';
	}

	/**
	 * Special cases for empty strings, ".", and ".."
	 */
	if (!name_size)
	{
		rtsmb_cpy (buf, empty);
		return;
	}
	else if (!rtsmb_cmp (name, dotstr))
	{
		rtsmb_cpy (buf, dotstr);
		return;
	}
	else if (!rtsmb_cmp (name, dotdotstr))
	{
		rtsmb_cpy (buf, dotdotstr);
		return;
	}

	// find out where the dot is
	for (i = (int)name_size - 1; i >= 0; i--)
	{
		if (name[i] == '.')
		{
			dot = i;
			break;
		}

		if (!i)
		{
			// if no dot, make note of it, and pretend there is one at the end
			dotExists = FALSE;
			dot = (int)rtsmb_len (name);
			break;
		}
	}

	// put char's into result, skipping invalid characters, ending at the 8th char
	for (i = 0; i < dot; i++)
	{
		if (counter == 8)
		{
			mangled = TRUE;
			break;
		}

		if (!tc_strchr (RTSMB_DOSIFY_CHARS, name[i]))
		{
			result[counter++] = name[i];
		}
		else
		{
			mangled = TRUE;
		}
	}

	// if a dot is there, we must add the extension
	if (dotExists == TRUE)
	{
		result[counter++] = '.';

		for (i = 1; i < 4 && name[dot + i] != '\0'; i++)
		{
			if (tc_strchr (RTSMB_DOSIFY_CHARS, name[dot + i]))
			{
				mangled = TRUE;
				result[counter++] = '_';
			}
			else
			{
				result[counter++] = name[dot + i];
			}
		}

		if (name[dot + i] != '\0')
		{
			mangled = TRUE;
		}

		dot = counter - i;
	}
	else
	{
		dot = counter;
	}

	// we had to mangle it
	// add a "~#" to the filename,
	// where '#' is a number
	if (mangled == TRUE)
	{
		int extra = 8 - dot;
		int loc;
		byte p16 [16];

		if (extra >= 3)
		{
			extra = 3;
		}

		if (extra > 0)
		{
			counter = dot + (int)rtsmb_len (&result[dot]) + extra;

			for (i = counter - extra - 1; i >= dot; i --)
			{
				result[i + extra] = result[i];
			}
		}

		loc = dot - (3 - extra);

		result[loc] = '~';

#if (INCLUDE_RTSMB_ENCRYPTION)
		/**
		 * Now, we md4 the filename.  This gives us a 16-byte hash.
		 * We use 1 of those bytes and add it on the end of our
		 * file name.  This is done to help reduce the chances of collisions.
		 */
		rtsmb_cpy (normalized_name, name);
		rtsmb_util_string_to_upper (normalized_name, CFG_RTSMB_USER_CODEPAGE);
		RTSMB_MD4 ((const unsigned char *) normalized_name, name_size * sizeof (rtsmb_char), p16);
		result[loc + 1] = p16[0];
		result[loc + 2] = p16[1];
#else
		result[loc + 1] = '0';
		result[loc + 2] = '1';
#endif
	}

	rtsmb_ncpy (buf, result, CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE);

	return;
}

/**
 * DOSify's a whole path (see above)
 */
PFRTCHAR SMBU_DOSifyPath (PFRTCHAR name, PFRTCHAR dest, rtsmb_size size)
{
	rtsmb_size nameSize;
	rtsmb_char old;
	PFRTCHAR tmp;
	PFRTCHAR tmp2;
	PFRTCHAR place;
	PFRTCHAR end;

	nameSize = rtsmb_len (name);
	tmp2 = name;
	place = &(dest [rtsmb_len (dest)]); // where we are currently writing to
	end = &name[nameSize];

	// pass by leading slash
	if (name[0] == '\\')
	{
		name ++;
		nameSize --;
		place[0] = '\\';
		place++;
	}

	// for each directory in name, you must DOSIFY.  Come on, just DOSIFY!
	// tmp points to end of segment we are dosifying, tmp2 points to start
	while (1)
	{
		for (tmp = tmp2; tmp[0] != '\\' && tmp != end; tmp ++);

		// the following will yield some false positives
		// to prevent this, we should dosify into a temporary buffer,
		// and check the size of that instead of CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE.
		// Then, copy the temp buffer onto place
		if (rtsmb_len (dest) + CFG_RTSMB_EIGHT_THREE_BUFFER_SIZE >= size)
		{
			return (PFRTCHAR)0;
		}

		old = tmp[0];
		tmp[0] = '\0';
		SMBU_DOSifyName (tmp2, place, '\0');
		tmp[0] = old;

		if (tmp == end) break;
		tmp2 = tmp + 1;
		place = &place[rtsmb_len (place)];
		place[0] = '\\';
		place++;
	}

	return dest;
}


/**
 * This is used to pretty-ify any outgoing filenames.
 * We currently do not need to do this.
 *
 * Possible uses in the future would be capitalizing or converting to unicode.
 */
PFRTCHAR SMBU_NormalizeFileName (PSMB_SESSIONCTX pCtx, PFRTCHAR string)
{
	return string;
}

// Used for SMB_COM_WRITE_PRINT_FILE, SMB_COM_WRITE and SMB_COM_WRITE_AND_CLOSE
// If append is TRUE, just append to the file.  If FALSE, go offset into file.
// If offset is out of range, extends the file! -- so make sure you want that behavior
// before using this.
word SMBU_WriteToFile (PSMB_SESSIONCTX pCtx, int fid, PFBYTE source, word count, BBOOL append, dword offset)
{
	int size;
	long loc;
	int written=0; /* _YI_ */
	byte buf [WRITE_TO_FILE_BUFFER_SIZE];

	// get size
	if ((size = SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_END)) < 0)
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_SEEK);
	else
	{
#if 0
		dword zeroes;
#endif
		loc = size;

		if (append)
			offset = (dword)loc;

		if (loc <= (int)offset)
		{
            ;
#if 0
			// we don't need to seek to offset, since we're already at end of file
			zeroes = offset - loc;
#endif

		}
		else
		{
			/* testing */
			// we must seek to offset, since we are at end of file, and don't want to be.
			SMBFIO_Seek (pCtx, pCtx->tid, fid, (long)offset, RTSMB_SEEK_SET);
#if 0
			zeroes = 0;
#endif
		}

		tc_memset (buf, 0, WRITE_TO_FILE_BUFFER_SIZE);

		/**
		 * If the offset is beyond end of file, all bytes between previous end of file
		 * and new end of file are supposed to be initialized to 0.  Since VFile does not
		 * make any guarantees about what happens to those bytes when a seek beyond eof is
		 * performed, we only seek to end of file but start writing 0's.
		 */
#if 0
		while (zeroes != 0)
		{
			word num;

			if (zeroes >= WRITE_TO_FILE_BUFFER_SIZE)
				num = WRITE_TO_FILE_BUFFER_SIZE;
			else
				num = (word) (zeroes & 0xFFFF);	/* since WRITE_TO_FILE_BUFFER_SIZE < max word, we're fine */

			zeroes -= num;

			if (SMBFIO_Write (pCtx, pCtx->tid, fid, buf, num) < 0) {
				SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_WRITE); return 0; }
		}
#endif

		if ((written = SMBFIO_Write (pCtx, pCtx->tid, fid, source, count)) < 0) {
			SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRHRD, SMB_ERRHRD_WRITE); return 0; }

		if (count == 0)
		{
			// if count is 0, we are supposed to truncate the file
			SMBFIO_Truncate (pCtx, pCtx->tid, fid, offset);
		}
	}

	return (word)written;
}

// returns 0 if success, else failure
// fullname points to a buffer that will contain the full name of the file
//   relative to tid after this call.
// fullname must be at least SMBF_FILENAMESIZE + ! size
// dir and fullname can overlap
int SMBU_TemporaryFileName (PSMB_SESSIONCTX pCtx, PFRTCHAR dir, PFRTCHAR fullname)
{
	PFRTCHAR filename;
	SMBFSTAT stat;
	rtsmb_char buf [SMBF_FILENAMESIZE + 1];
	rtsmb_char empty[1] = {'\0'};
	rtsmb_char separator[2] = {'\\', '\0'};
	rtsmb_char starting_name[] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', '.', 't', 'x', 't', '\0'};
	short index = 7; // last 'A'

	if (rtsmb_cmp (empty, dir) == 0 || dir == (PFRTCHAR)0)
	{
		rtsmb_cpy (buf, starting_name);
	}
	else
	{
		rtsmb_cpy (buf, dir);
		rtsmb_cat (buf, separator);
		rtsmb_cat (buf, starting_name);
	}

	filename = &buf [rtsmb_len (buf) - 12]; // points at first 'A'
	filename[index] --;

	do {
		if (filename[index] == 'Z')
		{
			filename[index] = 'a';
		}
		else
		{
			if (filename[index] == 'z')
			{
				index --;
			}

			if (index == -1)
			{
				// Say What?  This shouldn't happen in a kind world
				return -1;
			}

			filename[index] ++;
		}
	} while (SMBFIO_Stat (pCtx, pCtx->tid, buf, &stat));

	rtsmb_cpy (fullname, buf);

	return 0;
}


void SMBU_MakePath (PSMB_SESSIONCTX pCtx, PFRTCHAR filepath)
{
	rtsmb_char string [SMBF_FILENAMESIZE + 1];
	PFRTCHAR end;
	rtsmb_char old;

	SMBU_GetPath (filepath, string);

	end = string;
	if (end[0] == '\\')	// skip leading backslash
		end++;

	do
	{
		for (; end[0] != '\0' && end[0] != '\\'; end++);

		old = end[0];

		end[0] = '\0';
		SMBFIO_Mkdir (pCtx, pCtx->tid, string);
		end[0] = old;

		if (old != '\0')
			end++;
	}
	while (old != '\0');
}

// Returns 0 on success, -1 on error.
int SMBU_PrintFile (PSMB_SESSIONCTX pCtx, int fid)
{
	byte buffer [WRITE_TO_FILE_BUFFER_SIZE];
	long bytesRead;
	PTREE tree;
	PSR_RESOURCE pResource;
	int n, rv = 0;

	tree = SMBU_GetTree (pCtx, pCtx->tid);
	if (!tree)
	{
		return -1;
	}
	CLAIM_SHARE ();
	pResource = SR_ResourceById (tree->internal);

	switch (pResource->stype)
	{
	case ST_PRINTQ:
		n = pResource->u.printer.num;
		break;
	default:
		rv = -1;
		break;
	}
	RELEASE_SHARE ();
	if (rv == -1)
	{
		return -1;
	}

	if (SMBFIO_Seek (pCtx, pCtx->tid, fid, 0, RTSMB_SEEK_SET) < 0)
	{
		return -1;
	}

	/**
	 * Claim the printers mutex as a clumsy way of making sure
	 * no one else prints to the same printer while this thread
	 * is trying to print.
	 */
	CLAIM_PRINTERS ();
//#define PRINT_VIA_CUPS
	if(rtsmb_osport_printer_open (n) < 1)
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_osport_printer_open failed");
	}

	do
	{
		bytesRead = SMBFIO_Read (pCtx, pCtx->tid, fid, buffer, WRITE_TO_FILE_BUFFER_SIZE);

		if (bytesRead < 0)
		{
			rv = -1;
			break;
		}

		if(rtsmb_osport_printer_write (n, buffer, bytesRead) < 0)
		{
			RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_osport_printer_write failed");
		}
	}
	while (bytesRead == WRITE_TO_FILE_BUFFER_SIZE);

	if (!rv)
	{
		byte eof = (byte) (-1); /* EOF */
		rtsmb_osport_printer_write (n, &eof, 1);
	}

#if (PRINT_VIA_CUPS)
	if(rtsmb_osport_file_send_n_delete (n) < 1)
	{
		RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL,"rtsmb_osport_file_send_n_delete failed");
	}
#else
	rtsmb_osport_printer_close (n);
#endif
	RELEASE_PRINTERS ();

	return rv;
}




//****************************************************************************
//**
//**    END MODULE SRVUTIL.C
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */
