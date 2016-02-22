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
#include "srv_smb2_assert.h"
#include "com_smb2_wiredefs.h"
#include "srv_smb2_model.h"


const unsigned char extra_info_response[] = {0x20,0x00,0x00,0x00,0x10,0x00,0x04,0x00,0x00,0x00,0x18,0x00,0x08,0x00,0x00,0x00,0x4d,0x78,0x41,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x01,
0x1f,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x04,0x00,0x00,0x00,0x18,0x00,0x20,0x00,0x00,0x00,0x51,0x46,0x69,0x64,0x00,0x00,0x00,0x00,0x9e,0x3b,0x06,0x00
,0x00,0x00,0x00,0x00,0x00,0xfc,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};



#include "rtptime.h"

#define CRDISP_FILE_SUPERSEDE    0x00000000 // If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object.<32>
#define CRDISP_FILE_OPEN         0x00000001 // If the file already exists, return success; otherwise, fail the operation. MUST NOT be used for a printer object.
#define CRDISP_FILE_CREATE       0x00000002 // If the file already exists, fail the operation; otherwise, create the file.
#define CRDISP_FILE_OPEN_IF      0x00000003 // Open the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.<33>
#define CRDISP_FILE_OVERWRITE    0x00000004 // Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be used for a printer object.
#define CRDISP_FILE_OVERWRITE_IF 0x00000005 //

#include "srvssn.h"
#include "srvutil.h"
#include "srvauth.h"
#include "smbdebug.h"

extern dword OpenOrCreate (PSMB_SESSIONCTX pCtx, PTREE pTree, PFRTCHAR filename, word flags, word mode, PFWORD answer_external_fid, PFINT answer_fid);


#define MAX_CREATE_CONTEXT_LENGTH_TOTAL 64 // Don't need much, mostly 4 byte values
BBOOL Proc_smb2_Create(smb2_stream  *pStream)
{
	RTSMB2_CREATE_C command;
	RTSMB2_CREATE_R response;
    byte file_name[RTSMB2_MAX_FILENAME_SIZE+MAX_CREATE_CONTEXT_LENGTH_TOTAL];
    int fid;
    dword r;
    word externalFid;
    BBOOL wants_read = FALSE, wants_write = FALSE, wants_attr_write = FALSE;
    BBOOL wants_extra_info = FALSE;
    dword CreateAction = 1; // 1== FILE_OPEN, 0 = SUPER_SEDED, 2=CREATED, 3=OVERWRITTEN
    int flags = 0, mode;
    SMBFSTAT stat;
    byte permissions = 5; /* HAD TO SET IT TO A USELESS VALUE _YI_ */
	PTREE pTree;

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA !!...\n",0);

    tc_memset(&response,0, sizeof(response));
    tc_memset(&command,0, sizeof(command));

    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA 1!!...\n",0);
    ASSERT_SMB2_UID(pStream)   // Returns if the UID is not valid
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA 2!!...\n",0);
    ASSERT_SMB2_TID (pStream)  // Returns if the TID is not valid
    RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA 3!!...\n",0);

     /* Set up a temporary buffer to hold incoming share name */
    pStream->ReadBufferParms[0].pBuffer = file_name;
    pStream->ReadBufferParms[0].byte_count = sizeof(file_name);

    /* Read into command, TreeId will be present in the input header */
    RtsmbStreamDecodeCommand(pStream, (PFVOID) &command);

    if (!pStream->Success)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  RtsmbStreamDecodeCommand failed...\n",0);
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }

    if (command.StructureSize != 57)
    {
        RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  StructureSize invalid...\n",0);
   		RtsmbWriteSrvError(pStream,SMB_EC_ERRSRV, SMB_ERRSRV_SMBCMD,0,0);
        return TRUE;
    }
    if (ON (command.DesiredAccess, 0x1) ||
        ON (command.DesiredAccess, 0x20) ||
        ON (command.DesiredAccess, 0x20000) ||
        ON (command.DesiredAccess, 0x10000000) ||
        ON (command.DesiredAccess, 0x20000000) ||
        ON (command.DesiredAccess, 0x80000000))
    {
        wants_read = TRUE;
    }
    if (ON (command.DesiredAccess, 0x2) ||
        ON (command.DesiredAccess, 0x4) ||
        ON (command.DesiredAccess, 0x40) ||
        ON (command.DesiredAccess, 0x10000) ||
        ON (command.DesiredAccess, 0x10000000) ||
        ON (command.DesiredAccess, 0x40000000))
    {
        wants_write = TRUE;
    }
    if (ON (command.DesiredAccess, 0x10) ||
        ON (command.DesiredAccess, 0x100) ||
        ON (command.DesiredAccess, 0x4000) ||
        ON (command.DesiredAccess, 0x8000) ||
        ON (command.DesiredAccess, 0x2000000))
    {
        wants_attr_write = TRUE;
    }

//=====
    /* do we make the file if it doesn't exist?   */
    switch (command.CreateDisposition)
    {
        case NT_CREATE_NEW:
            flags |= RTP_FILE_O_CREAT | RTP_FILE_O_EXCL;
            wants_write = TRUE;
            break;
        case NT_CREATE_ALWAYS:
            flags |= RTP_FILE_O_CREAT | RTP_FILE_O_TRUNC;
            wants_write = TRUE;
            break;
        default:
        case NT_OPEN_EXISTING:
            wants_read = TRUE;
            break;
        case NT_OPEN_ALWAYS:
            flags |= RTP_FILE_O_CREAT;
            wants_write = TRUE;
            break;
        case NT_TRUNCATE:
            flags |= RTP_FILE_O_TRUNC;
            wants_write = TRUE;
            break;
    }

    if (wants_read && wants_write)
    {
        /* reading and writing   */
        flags |= RTP_FILE_O_RDWR;
        permissions = SECURITY_READWRITE;
    }
    else if (wants_read)
    {
        /* reading only   */
        flags |= RTP_FILE_O_RDONLY;
        permissions = SECURITY_READ;
    }
    else if (wants_write)
    {
        /* writing only   */
        flags |= RTP_FILE_O_WRONLY; /* was RTP_FILE_O_RDWR _YI_ */
        permissions = SECURITY_WRITE;
    }

    if (wants_attr_write)
    {
        permissions = SECURITY_READWRITE;
    }

    ASSERT_SMB2_PERMISSION(pStream, permissions);  // Checks permission on pCtx->tid

    // If no name length then it's requesting persistent handles et al via CREATE_CONTEXT requests.
    // Return SMB2_STATUS_OBJECT_NAME_NOT_FOUND and the client continues
    if (command.NameLength==0)
    { // An error if trying to create the root
      if (flags & RTP_FILE_O_CREAT)
      {
       printf("call RtsmbWriteSrvStatus(SMB2_STATUS_OBJECT_NAME_NOT_FOUND)== %X\n", SMB2_STATUS_OBJECT_NAME_NOT_FOUND);
         RtsmbWriteSrvStatus(pStream, SMB2_STATUS_OBJECT_NAME_NOT_FOUND);
         return TRUE;
      }
    }


    if (command.FileAttributes & 0x80)
    {
            mode = RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD |
                   RTP_FILE_ATTRIB_ARCHIVE; /* VM */
    }
    else
    {
        mode =  command.FileAttributes & 0x01 ? RTP_FILE_S_IREAD   : 0;
        mode |= command.FileAttributes & 0x02 ? RTP_FILE_S_HIDDEN  : 0;
        mode |= command.FileAttributes & 0x04 ? RTP_FILE_S_SYSTEM  : 0;
        mode |= command.FileAttributes & 0x20 ? RTP_FILE_S_ARCHIVE : 0;
    }

    pTree = SMBU_GetTree (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid);

    // NULL terminate the file name, this clobbers the CREATE_CONTEXTs if there are any
    if (command.NameLength==0)
    {
      PFRTCHAR p = (PFRTCHAR) file_name;
      rtsmb_char s = '\\';     // pass file_name[0] = \. so it stats the root.
      rtsmb_char d = '.';     // pass file_name[0] = \\ so it stats the root.
      *p++ = s; *p++ = d; *p = 0;
      flags = RTP_FILE_O_RDONLY;
      TURN_ON(command.FileAttributes, 0x80);
      // This will fall through and stat the root
      if (pTree->type == ST_IPC || pTree->type == ST_PRINTQ)
      {
      /* The correct behavior for non-supported pipe files is that they      */
      /* are not-found files.  However, 2K at least, will die if we do that. */
      /* This way (denying access) makes them think we support it, but they  */
      /* just don't have the right priviledges, and they fall back to normal */
      /* packets.                                                            */
         r = SMBU_MakeError (SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
      }
      else
      {
       // Hack, include extra info in stream if no file
       wants_extra_info = TRUE;
       printf ("Creae options == %X\n", command.CreateOptions);
       if (!(ON(command.CreateOptions, 0x1)))
       {
         r = OpenOrCreate (pStream->psmb2Session->pSmbCtx, pTree, file_name, (word)flags, (word)mode, &externalFid, &fid);
         printf ("Open on root no create options returned : %x\n", r);
//         r = SMB2_STATUS_FILE_IS_A_DIRECTORY;
//         printf ("Set is directory error %x\n", r);
       }
       else
       {
         r = OpenOrCreate (pStream->psmb2Session->pSmbCtx, pTree, file_name, (word)flags, (word)mode, &externalFid, &fid);
         printf ("Open on root returned : %x\n", r);
       }
      }
    }
    else
    {
      file_name[command.NameLength] = 0;
      file_name[command.NameLength+1] = 0;
      /* If we have a normal filename. check if the client is trying to make a directory.  If so, make it Logic is the same for smb2  */
      if (ON (command.FileAttributes, 0x80) && ON (command.CreateOptions, 0x1))
      {
          if (ON (flags, RTP_FILE_O_CREAT))
          {
              ASSERT_SMB2_PERMISSION (pStream, SECURITY_READWRITE);
              SMBFIO_Mkdir (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, file_name);
              TURN_OFF (flags, RTP_FILE_O_EXCL);
              CreateAction = 2; // File created
          }
         r = OpenOrCreate (pStream->psmb2Session->pSmbCtx, pTree, file_name, (word)flags, (word)mode, &externalFid, &fid);
      }
    }
    if (r != 0)
    {
//        printf("OpenOrCreate failed r == %x fixed r == %x\n", r, SMB_NT_STATUS_NO_SUCH_FILE);
//        r = SMB_NT_STATUS_NO_SUCH_FILE;
        RtsmbWriteSrvStatus(pStream, r);
        return TRUE;
    }

    SMBFIO_Stat (pStream->psmb2Session->pSmbCtx, pStream->psmb2Session->pSmbCtx->tid, file_name, &stat);
//=====

	// byte  SecurityFlags;              // reserved
	// command.RequestedOplockLevel;
	printf("Oplock level %d \n", command.RequestedOplockLevel);
	printf("ImpersonationLevel %d \n", command.ImpersonationLevel);
	// byte  SmbCreateFlags[8]; reserved
	// byte  Reserved[8];
	printf("DesiredAccess %X\n", command.DesiredAccess);
	printf("FileAttributes %X\n", command.FileAttributes);
	printf("ShareAccess %X\n", command.ShareAccess);
	printf("CreateDisposition %X\n", command.CreateDisposition);
	printf("CreateOptions %X\n", command.CreateOptions);
    printf("NameOffset %d\n", command.NameOffset);
    printf("NameLength %d\n", command.NameLength);
    printf("CreateContextsOffset %d\n", command.CreateContextsOffset);
    printf("CreateContextsLength %d\n", command.CreateContextsLength);
    printf("Filename: :");
    {int i;
    for (i=0;i<command.NameLength; i+= 2)
      printf("%c", (char )file_name[i]);
    rtp_printf(":\n");
    }

    printf("Input Tree Id = %ld\n", pStream->InHdr.TreeId);

    response.StructureSize = 89;
    response.OplockLevel = 0; // command.RequestedOplockLevel;
    response.Flags = 0; // SMB3 only
    response.CreateAction = CreateAction;

    response.CreationTime   =  *((ddword *) &stat.f_ctime64);
    response.LastAccessTime =  *((ddword *) &stat.f_atime64);
    response.LastWriteTime  =  *((ddword *) &stat.f_wtime64);
    response.ChangeTime     =  *((ddword *) &stat.f_htime64);
    response.AllocationSize  = stat.f_size;
    response.EndofFile       = stat.f_size;
    response.FileAttributes  = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);
    // response.FileId[0] = 1; response.FileId[1] = 2; response.FileId[2] = 3; response.FileId[3] = 4; response.FileId[4] = 5;
    *((word *) &response.FileId[0]) = (word) externalFid;
    response.CreateContextsOffset = 0;
    response.CreateContextsLength = 0;

    if (wants_extra_info)
    {
      pStream->WriteBufferParms[0].byte_count = sizeof(extra_info_response);
      pStream->WriteBufferParms[0].pBuffer = extra_info_response;
      response.CreateContextsOffset = (pStream->OutHdr.StructureSize+response.StructureSize-1);
      response.CreateContextsLength = pStream->WriteBufferParms[0].byte_count;
    }
    RtsmbStreamEncodeResponse(pStream, (PFVOID ) &response);
    return TRUE;
} // Proc_smb2_Ioctl

#endif
#endif

#if (0)

BBOOL assertUid (PSMB_SESSIONCTX pCtx)
{
	PUSER user;

	// no need to authenticate when in share mode
	if (pCtx->accessMode == AUTH_SHARE_MODE)
	{
		return FALSE;
	}
	user = SMBU_GetUser (pCtx, pCtx->uid);

	if (user == (PUSER)0)
	{
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_BADUID);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// undefined behavior if uid doesn't exist
BBOOL assertTid (PSMB_SESSIONCTX pCtx)
{
	return assertThisTid (pCtx, pCtx->tid);
}

// undefined behavior if uid doesn't exist
BBOOL assertThisTid (PSMB_SESSIONCTX pCtx, word tid)
{
	if (SMBU_GetTree (pCtx, tid))
	{
		return FALSE;
	}

	SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_INVNID);
	return TRUE;
}
// undefined behavior if uid or tid isn't valid
BBOOL assertPermission (PSMB_SESSIONCTX pCtx, byte permission)
{
	return assertPermissionForTid (pCtx, permission, pCtx->tid);
}

// undefined behavior if uid or tid isn't valid
BBOOL assertPermissionForTid (PSMB_SESSIONCTX pCtx, byte permission, word tid)
{
	PTREE tree;

	tree = SMBU_GetTree (pCtx, pCtx->tid);

	if (tree->access == SECURITY_NONE ||
		(tree->access != SECURITY_READWRITE && tree->access != permission))
	{
		RTSMB_DEBUG_OUTPUT_STR ("failed permissions check with permission of ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (permission);
		RTSMB_DEBUG_OUTPUT_STR (" against permission of ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (tree->access);
		RTSMB_DEBUG_OUTPUT_STR (" on tid ", RTSMB_DEBUG_TYPE_ASCII);
		RTSMB_DEBUG_OUTPUT_INT (tid);
		RTSMB_DEBUG_OUTPUT_STR ("\n", RTSMB_DEBUG_TYPE_ASCII);
		SMBU_FillError (pCtx, pCtx->pOutHeader, SMB_EC_ERRSRV, SMB_ERRSRV_ACCESS);
		return TRUE;
	}

	return FALSE;
}


int ProcNTCreateAndx (PSMB_SESSIONCTX pCtx, PRTSMB_HEADER pInHdr, PFVOID *pInBuf, PRTSMB_HEADER pOutHdr, PFVOID *pOutBuf)
{
    RTSMB_NT_CREATE_AND_X command;
    PTREE pTree;
    int flags = 0, mode;
    byte permissions = 5; /* HAD TO SET IT TO A USELESS VALUE _YI_ */
    int fid;
    dword r;
    word externalFid;
    RTSMB_NT_CREATE_AND_X_R response;
    SMBFSTAT stat;
    BBOOL wants_read = FALSE, wants_write = FALSE, wants_attr_write = FALSE;


    ASSERT_UID (pCtx);  // see above pCtx->uid
    ASSERT_TID (pCtx);  // see above pCtx->tid

    command.filename_size = (word) (pCtx->tmpSize & 0xFFFF);
    command.filename = (PFRTCHAR) pCtx->tmpBuffer;
    READ_SMB_AND_X (srv_cmd_read_nt_create_and_x);


    if (ON (command.desired_access, 0x1) ||
        ON (command.desired_access, 0x20) ||
        ON (command.desired_access, 0x20000) ||
        ON (command.desired_access, 0x10000000) ||
        ON (command.desired_access, 0x20000000) ||
        ON (command.desired_access, 0x80000000))
    {
        wants_read = TRUE;
    }
    if (ON (command.desired_access, 0x2) ||
        ON (command.desired_access, 0x4) ||
        ON (command.desired_access, 0x40) ||
        ON (command.desired_access, 0x10000) ||
        ON (command.desired_access, 0x10000000) ||
        ON (command.desired_access, 0x40000000))
    {
        wants_write = TRUE;
    }
    if (ON (command.desired_access, 0x10) ||
        ON (command.desired_access, 0x100) ||
        ON (command.desired_access, 0x4000) ||
        ON (command.desired_access, 0x8000) ||
        ON (command.desired_access, 0x2000000))
    {
        wants_attr_write = TRUE;
    }
    if (wants_read && wants_write)
    {
        /* reading and writing   */
        flags |= RTP_FILE_O_RDWR;
        permissions = SECURITY_READWRITE;
    }
    else if (wants_read)
    {
        /* reading only   */
        flags |= RTP_FILE_O_RDONLY;
        permissions = SECURITY_READ;
    }
    else if (wants_write)
    {
        /* writing only   */
        flags |= RTP_FILE_O_WRONLY; /* was RTP_FILE_O_RDWR _YI_ */
        permissions = SECURITY_WRITE;
    }

    if (wants_attr_write)
    {
        permissions = SECURITY_READWRITE;
    }

    ASSERT_PERMISSION (pCtx, permissions);  // Checks permission on pCtx->tid

    /* do we make the file if it doesn't exist?   */
    switch (command.create_disposition)
    {
        case NT_CREATE_NEW:
            flags |= RTP_FILE_O_CREAT | RTP_FILE_O_EXCL;
            break;
        case NT_CREATE_ALWAYS:
            flags |= RTP_FILE_O_CREAT | RTP_FILE_O_TRUNC;
            break;
        default:
        case NT_OPEN_EXISTING:
            break;
        case NT_OPEN_ALWAYS:
            flags |= RTP_FILE_O_CREAT;
            break;
        case NT_TRUNCATE:
            flags |= RTP_FILE_O_TRUNC;
            break;
    }

    if (command.ext_file_attributes & 0x80)
    {
            mode = RTP_FILE_S_IWRITE | RTP_FILE_S_IREAD |
                   RTP_FILE_ATTRIB_ARCHIVE; /* VM */
    }
    else
    {
        mode =  command.ext_file_attributes & 0x01 ? RTP_FILE_S_IREAD   : 0;
        mode |= command.ext_file_attributes & 0x02 ? RTP_FILE_S_HIDDEN  : 0;
        mode |= command.ext_file_attributes & 0x04 ? RTP_FILE_S_SYSTEM  : 0;
        mode |= command.ext_file_attributes & 0x20 ? RTP_FILE_S_ARCHIVE : 0;
    }

    pTree = SMBU_GetTree (pCtx, pCtx->tid);

    /* We check if the client is trying to make a directory.  If so, make it   */
    if (ON (command.flags, 0x80) | ON (command.create_options, 0x1))
    {
        if (ON (flags, RTP_FILE_O_CREAT))
        {
            ASSERT_PERMISSION (pCtx, SECURITY_READWRITE);
            SMBFIO_Mkdir (pCtx, pCtx->tid, command.filename);
            TURN_OFF (flags, RTP_FILE_O_EXCL);
        }
        response.directory = TRUE;
    }
    else
    {
        response.directory = FALSE;
    }
    r = OpenOrCreate (pCtx, pTree, command.filename, (word)flags, (word)mode, &externalFid, &fid);
    if (r != 0)
    {
        pOutHdr->status = r;
        return 0;
    }

    SMBFIO_Stat (pCtx, pCtx->tid, command.filename, &stat);

    response.next_command = command.next_command;
    response.oplock_level = 0;
    response.fid = (word) externalFid;

    response.create_action = (byte) command.create_disposition;

    response.device_state = 0;
    response.file_type = pTree->type == ST_PRINTQ ? SMB_FILE_TYPE_PRINTER : SMB_FILE_TYPE_DISK;
    response.creation_time_high = stat.f_ctime64.high_time;
    response.creation_time_low = stat.f_ctime64.low_time;
    response.allocation_size_high = 0;
    response.allocation_size_low = stat.f_size;
    response.end_of_file_high = 0;
    response.end_of_file_low = stat.f_size;
    response.change_time_high = stat.f_htime64.high_time;
    response.change_time_low = stat.f_htime64.low_time;
    response.last_access_time_high = stat.f_atime64.high_time;
    response.last_access_time_low = stat.f_atime64.low_time;
    response.last_write_time_high = stat.f_wtime64.high_time;
    response.last_write_time_low = stat.f_wtime64.low_time;
    response.ext_file_attributes = rtsmb_util_rtsmb_to_smb_attributes (stat.f_attributes);

#if (HARDWIRED_NTLM_EXTENSIONS)
    tc_memset (response.guid, 0, 16);
    response.fileid_high = 0;
    response.fileid_low = 0;
    response.maximal_access_rights = 0;
    response.guest_maximal_access_rights = 0;
    if (response.file_type==SMB_FILE_TYPE_DISK)
    {
       if ((stat.f_attributes & RTP_FILE_ATTRIB_RDONLY)==0)
       {
          response.maximal_access_rights |= SMB_DIR_ACCESS_MASK_DELETE;
       }
      if (response.directory)
      {
        response.maximal_access_rights |=
         (SMB_DIR_ACCESS_MASK_FILE_LIST_DIRECTORY  \
         |SMB_DIR_ACCESS_MASK_FILE_TRAVERSE);
        if ((stat.f_attributes & RTP_FILE_ATTRIB_RDONLY)==0)
        {
          response.maximal_access_rights |=
           (SMB_DIR_ACCESS_MASK_FILE_ADD_FILE        \
           |SMB_DIR_ACCESS_MASK_FILE_ADD_SUBDIRECTORY\
           |SMB_DIR_ACCESS_MASK_FILE_DELETE_CHILD);
        }
      }
      else
      { // A File, not a directory
        response.maximal_access_rights |= SMB_FPP_ACCESS_MASK_GENERIC_READ|SMB_FPP_ACCESS_MASK_GENERIC_EXECUTE;
        if ((stat.f_attributes & RTP_FILE_ATTRIB_RDONLY)==0)
          response.maximal_access_rights |= SMB_FPP_ACCESS_MASK_GENERIC_WRITE;
      }
    }
    else
    { // Printer
      response.maximal_access_rights = SMB_FPP_ACCESS_MASK_GENERIC_WRITE;
      response.guest_maximal_access_rights = SMB_FPP_ACCESS_MASK_GENERIC_WRITE;
    }
#endif // if (HARDWIRED_NTLM_EXTENSIONS)

    WRITE_SMB_AND_X (srv_cmd_fill_nt_create_and_x);

    return command.next_command;
} /* End ProcTreeConAndx */

#endif
