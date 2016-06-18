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


const unsigned char extra_info_response[] = {0x20,0x00,0x00,0x00,0x10,0x00,0x04,0x00,0x00,0x00,0x18,0x00,0x08,0x00,0x00,0x00,0x4d,0x78,0x41,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0xff,0x01,0x1f, // Access mask
0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x04,0x00,0x00,0x00,0x18,0x00,0x20,0x00,0x00,0x00,0x51,0x46,0x69,0x64,0x00,0x00,0x00,0x00,0x9e,0x3b,0x06,0x00
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


#define MAX_CREATE_CONTEXT_LENGTH_TOTAL 512 // Don't need much, mostly 4 byte values
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CREATE_CONTEXT_WIRE {
  dword Next;
  word NameOffset;
  dword NameLength;
  word  DataOffset;
  dword DataLength;
  byte Buffer[1];
} PACK_ATTRIBUTE RTSMB2_CREATE_CONTEXT_WIRE;
PACK_PRAGMA_POP

typedef RTSMB2_CREATE_CONTEXT_WIRE RTSMB_FAR *PRTSMB2_CREATE_CONTEXT_WIRE;

#define MAX_CREATE_CONTEXTS_ON_WIRE 16 // Should be plenty
typedef struct s_RTSMB2_CREATE_CONTEXT_INTERNAL {
  PRTSMB2_CREATE_CONTEXT_WIRE p_context_entry_wire; // Pointer to raw wire record
  dword NameDw;                                     // 4 byte name from p_context_entry_wire->NameOffset (will be a problem for 3.X names. Will need to encode those larger names into internale handle names
  word  Reserved;                                   // Nul terminates name so we can print it as a string
  PFVOID p_payload;                                 // pointer to data of length p_context_entry_wire->DataLength
} RTSMB2_CREATE_CONTEXT_INTERNAL;
typedef RTSMB2_CREATE_CONTEXT_INTERNAL RTSMB_FAR *PRTSMB2_CREATE_CONTEXT_INTERNAL;

typedef struct s_RTSMB2_CREATE_DECODED_CREATE_CONTEXTS {
  PRTSMB2_CREATE_CONTEXT_INTERNAL pExtA;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pSecD;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDHnQ;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDHnC;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pAISi;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pMxAc;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pTWrp;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pQFid;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pRqLs;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pRq2s;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDH2Q;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDH2C;
  int n_create_context_request_values;                         // Return value, number of valid create contexts decoded
  dword error_code;                                            // Return value, error code if any problems were detected
  RTSMB2_CREATE_CONTEXT_INTERNAL context_values[MAX_CREATE_CONTEXTS_ON_WIRE];
} RTSMB2_CREATE_DECODED_CREATE_CONTEXTS;
typedef RTSMB2_CREATE_DECODED_CREATE_CONTEXTS RTSMB_FAR *PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS;

#define RTSMB2_CREATE_CONTEXT_WIRE_SIZE (sizeof(RTSMB2_CREATE_CONTEXT_WIRE)-1) // -1 because buffer is optional






BBOOL Proc_smb2_Create(smb2_stream  *pStream)
{
	RTSMB2_CREATE_C command;
	RTSMB2_CREATE_R response;
    byte file_name[RTSMB2_MAX_FILENAME_SIZE];
    byte create_content[MAX_CREATE_CONTEXT_LENGTH_TOTAL];
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
    RTSMB2_CREATE_DECODED_CREATE_CONTEXTS decoded_create_context;

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
    pStream->ReadBufferParms[1].pBuffer = create_content;
    pStream->ReadBufferParms[1].byte_count = sizeof(create_content);


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

    if (command.NameLength!=0)
    {
      PFRTCHAR p = (PFRTCHAR) file_name;
      rtsmb_char s = '\\';               // Return INVALID_PARAMETER If the first character is a path separator.
      if (*p==s)
      {
         RtsmbWriteSrvStatus(pStream, SMB2_STATUS_INVALID_PARAMETER);
         return TRUE;
      }
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


    if (pTree->type == ST_PRINTQ)
    { // Don't open IPCs or printers yet.
      RtsmbWriteSrvStatus(pStream, SMB2_STATUS_NOT_SUPPORTED);
      return TRUE;
    }
    // Decode CreateContexts into decoded_create_context structure
    if (command.CreateContextsOffset)
    {
       int decode_r;
       printf("Processing command.CreateContextsOffset == %d\n",  command.CreateContextsOffset);
       decode_r = decode_create_context_request_values(&decoded_create_context, (PFVOID) create_content, command.CreateContextsLength);
    }
#if (HARDWIRED_INCLUDE_DCE)
    if (pTree->type == ST_IPC)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA 4 IPC!!...\n",0);
    }
#endif
    if (command.NameLength==0)
    { // opening the root of the share
      PFRTCHAR p = (PFRTCHAR) file_name;
      rtsmb_char s = '\\';     // pass file_name[0] = \. so it stats the root.
      rtsmb_char d = '.';     // pass file_name[0] = \\ so it stats the root.
      *p++ = s; *p++ = d; *p = 0;
      flags = RTP_FILE_O_RDONLY;
      TURN_ON(command.FileAttributes, 0x80);
      // Hack, include extra info in stream if no file
      wants_extra_info = TRUE;
      printf ("Cretae options == %X\n", command.CreateOptions);
      r = OpenOrCreate (pStream->psmb2Session->pSmbCtx, pTree, file_name, (word)0/*flags*/, (word)0/*mode*/, &externalFid, &fid);
      printf ("Open on root returned : %x, external fileid == %d \n", r, externalFid);
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
#if (HARDWIRED_INCLUDE_DCE)
    if (pTree->type == ST_IPC)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA 5 IPC!!...\n",0);
    }
#endif
    if (r != 0)
    {
        printf("OpenOrCreate failed r == %x\n", r);
//        r = SMB_NT_STATUS_NO_SUCH_FILE;
        RtsmbWriteSrvStatus(pStream, r);
        return TRUE;
    }

#if (HARDWIRED_INCLUDE_DCE)
    if (pTree->type == ST_IPC)
    {
      RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_INFO_LVL, "Proc_smb2_Create:  YA YA 6 IPC!!...\n",0);
    }
#endif
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
    *((word *) &response.FileId[0]) = (word) 0xABCD;
    *((word *) &response.FileId[1]) = (word) externalFid;
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

// Windows starts with "DHnQ","MxAc","QFid" on the root of the tree


#define SMB2_CREATE_EA_BUFFER                    0x45787441   // "ExtA"  The data contains the extended attributes that MUST be stored on the created file. This value MUST NOT be set for named pipes and print files.
#define SMB2_CREATE_SD_BUFFER                    0x53656344   // "SecD"  The data contains a security descriptor that MUST be stored on the created file.   This value MUST NOT be set for named pipes and print files.
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST       0x44486e51   // "DHnQ"  The client is requesting the open to be durable (see section 3.3.5.9.6).
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT     0x44486e43   // "DHnC"  The client is requesting to reconnect to a durable open after being disconnected (see section 3.3.5.9.7).
#define SMB2_CREATE_ALLOCATION_SIZE              0x416c5369   // "AISi"  The data contains the required allocation size of the newly created file.
#define SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST 0x4d784163   // "MxAc"  The client is requesting that the server return maximal access information.
#define SMB2_CREATE_TIMEWARP_TOKEN               0x54577270   // "TWrp"  The client is requesting that the server open an earlier version of the file identified by the provided time stamp.
#define SMB2_CREATE_QUERY_ON_DISK_ID             0x51466964   // "QFid"  The client is requesting that the server return a 32-byte opaque BLOB that uniquely identifies the file being opened on disk. No data is passed to the server by the client.
#define SMB2_CREATE_REQUEST_LEASE                0x52714c73   // "RqLs"  SMB2.1 and above
#define SMB2_CREATE_REQUEST_LEASE_V2             0x52713273   // "Rq2s"  may be a typo In SMB2 spec as 0x52714c73
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2    0x44483251   // "DH2Q"  SMB3.X
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2  0x44483243   // "DH2C"  SMB3.X
#define SMB2_CREATE_APP_INSTANCE_ID              0x45BCA66A   // EFA7F74A9008FA462E144D74 SMB3.X
#define SMB2_CREATE_APP_INSTANCE_VERSION         0xB982D0B7   // 3B56074FA07B524A8116A010 SMB3.X
#define SVHDX_OPEN_DEVICE_CONTEXT                0x9CCBCF9E   // 04C1E643980E158DA1F6EC83 SMB3.X

#if 0
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CREATE_CONTEXT_WIRE {
  dword Next;
  word NameOffset;
  word NameLength;
  word Reserved;
  word  DataOffset;
  word DataLength;
  byte Buffer[1];
} PACK_ATTRIBUTE RTSMB2_CREATE_CONTEXT_WIRE;
PACK_PRAGMA_POP
#endif

static void dump_decoded_create_context_request_values(PRTSMB2_CREATE_CONTEXT_INTERNAL p_decoded_create_context_request_values,int n_create_context_request_values);

int decode_create_context_request_values(PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS pdecoded_create_context, PFVOID pcreate_context_buffer, int create_context_buffer_length);


int decode_create_context_request_values(PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS pdecoded_create_context, PFVOID pcreate_context_buffer, int create_context_buffer_length)
{
PRTSMB2_CREATE_CONTEXT_INTERNAL p_current_value=&pdecoded_create_context->context_values[0];
PRTSMB2_CREATE_CONTEXT_WIRE p_current_context_onwire = (PRTSMB2_CREATE_CONTEXT_WIRE)pcreate_context_buffer;
PFVOID p_current_create_context_buffer=pcreate_context_buffer;
int current_create_context_buffer_length = create_context_buffer_length;
PFVOID p_data_buffer_end = PADD(pcreate_context_buffer, create_context_buffer_length);

  tc_memset(pdecoded_create_context,0,sizeof(*pdecoded_create_context));
  printf("decode_create_context_request_values: length : %d\n", create_context_buffer_length);
  while (current_create_context_buffer_length>=RTSMB2_CREATE_CONTEXT_WIRE_SIZE)
  {
    BBOOL is_error_record = FALSE;
    BBOOL take_next_record = TRUE;
    p_current_value=&pdecoded_create_context->context_values[pdecoded_create_context->n_create_context_request_values];

    tc_memset(p_current_value, 0, sizeof(*p_current_value));

      if (p_current_context_onwire->NameOffset < RTSMB2_CREATE_CONTEXT_WIRE_SIZE)
      {
         // Error condition
         is_error_record = TRUE;
         take_next_record = FALSE;
      }
      else if (p_current_context_onwire->NameLength != 4)
      {
         take_next_record = FALSE;
      }
      else
      {
         PFVOID pName;
         pName=PADD((PFVOID)p_current_context_onwire,p_current_context_onwire->NameOffset);

         p_current_value->NameDw = *((dword *)pName); // TBD Byte order issue
         p_current_value->p_context_entry_wire=p_current_context_onwire;

         switch (SMB_NTOHD(p_current_value->NameDw))
         {
            case SMB2_CREATE_EA_BUFFER                    :   // "ExtA"  The data contains the extended attributes that MUST be stored on the created file. This value MUST NOT be set for named pipes and print files.
              pdecoded_create_context->pExtA = p_current_value;
            break;
            case SMB2_CREATE_SD_BUFFER                    :   // "SecD"  The data contains a security descriptor that MUST be stored on the created file.   This value MUST NOT be set for named pipes and print files.
              pdecoded_create_context->pSecD = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_REQUEST       :   // "DHnQ"  The client is requesting the open to be durable (see section 3.3.5.9.6).
              pdecoded_create_context->pDHnQ = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_RECONNECT     :   // "DHnC"  The client is requesting to reconnect to a durable open after being disconnected (see section 3.3.5.9.7).
              pdecoded_create_context->pDHnC = p_current_value;
            break;
            case SMB2_CREATE_ALLOCATION_SIZE              :   // "AISi"  The data contains the required allocation size of the newly created file.
              pdecoded_create_context->pAISi = p_current_value;
            break;
            case SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST :   // "MxAc"  The client is requesting that the server return maximal access information.
              pdecoded_create_context->pMxAc = p_current_value;
            break;
            case SMB2_CREATE_TIMEWARP_TOKEN               :   // "TWrp"  The client is requesting that the server open an earlier version of the file identified by the provided time stamp.
              pdecoded_create_context->pTWrp = p_current_value;
            break;
            case SMB2_CREATE_QUERY_ON_DISK_ID             :   // "QFid"  The client is requesting that the server return a 32-byte opaque BLOB that uniquely identifies the file being opened on disk. No data is passed to the server by the client.
              pdecoded_create_context->pQFid = p_current_value;
            break;
            case SMB2_CREATE_REQUEST_LEASE                :   // "RqLs"  SMB2.1 and above
              pdecoded_create_context->pRqLs = p_current_value;
            case SMB2_CREATE_REQUEST_LEASE_V2             :   // "Rq2s"  may be a typo In SMB2 spec as 0x52714c73
              pdecoded_create_context->pRq2s = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2    :   // "DH2Q"  SMB3.X
              pdecoded_create_context->pDH2Q = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2  :   // "DH2C"  SMB3.X
              pdecoded_create_context->pDH2C = p_current_value;
            break;
            case SMB2_CREATE_APP_INSTANCE_ID              :   // EFA7F74A9008FA462E144D74 SMB3.X
            case SMB2_CREATE_APP_INSTANCE_VERSION         :   // 3B56074FA07B524A8116A010 SMB3.X
            case SVHDX_OPEN_DEVICE_CONTEXT                :   // 04C1E643980E158DA1F6EC83 SMB3.X
            default:
              take_next_record = FALSE;
            break;
         }
         if (take_next_record)
         {
           if (p_current_context_onwire->DataLength)
           {
             p_current_value->p_payload = PADD((PFVOID)p_current_context_onwire,p_current_context_onwire->DataOffset);
             if (p_current_value->p_payload >= p_data_buffer_end)
             {
               // Error condition
               is_error_record = TRUE;
             }
           }
           pdecoded_create_context->n_create_context_request_values += 1;
           if (pdecoded_create_context->n_create_context_request_values == MAX_CREATE_CONTEXTS_ON_WIRE)
             goto error_return;
         }
         if (p_current_context_onwire->Next==0)
            break;
         else
         {
         PFVOID pv;
         int delta;
            pv=PADD((PFVOID)p_current_context_onwire,p_current_context_onwire->Next);
            delta = (int)PDIFF(pv,(PFVOID)p_current_context_onwire);
            if (current_create_context_buffer_length>=delta)
            {
              current_create_context_buffer_length -= delta;
              p_current_context_onwire = (PRTSMB2_CREATE_CONTEXT_WIRE) pv;
            }
            else
            {
              is_error_record = TRUE;
              current_create_context_buffer_length = 0;
            }
         }
      }
      if (is_error_record)
        goto error_return;
  } //   while (current_create_context_buffer_length>=RTSMB2_CREATE_CONTEXT_WIRE_SIZE)


  dump_decoded_create_context_request_values(pdecoded_create_context->context_values,pdecoded_create_context->n_create_context_request_values);

//  if (pdecoded_create_context->pDHnQ)
//  if (pdecoded_create_context->pQfid)
  if (pdecoded_create_context->pMxAc)
  {
    printf("p_decoded_create_context_request_values->pMxAc->p_context_entry_wire->DataLength: %d\n", pdecoded_create_context->pMxAc->p_context_entry_wire->DataLength);
    printf("p_decoded_create_context_request_values->pMxAc->p_context_entry_wire->NameOffset: %d\n", pdecoded_create_context->pMxAc->p_context_entry_wire->NameOffset);
    printf("p_decoded_create_context_request_values->pMxAc->p_context_entry_wire->NameLength: %d\n", pdecoded_create_context->pMxAc->p_context_entry_wire->NameLength);
    printf("pdecoded_create_context->pMxAc->p_payload: %X\n", pdecoded_create_context->pMxAc->p_payload);
  }

  return pdecoded_create_context->n_create_context_request_values;
error_return:
  printf("decode_create_context_request_values: erro return\n");
  dump_decoded_create_context_request_values(&pdecoded_create_context->context_values,pdecoded_create_context->n_create_context_request_values);
  return -1;
}
static void dump_decoded_create_context_request_values(PRTSMB2_CREATE_CONTEXT_INTERNAL p_decoded_create_context_request_values,int n_create_context_request_values)
{
int i;
  printf("dump_decoded_create_context_request_values NValues == : %d\n", n_create_context_request_values);
  for (i = 0; i < n_create_context_request_values; i++)
  {
    printf("Name: %X, \"%s\"\n", p_decoded_create_context_request_values[i].NameDw, (char *) &p_decoded_create_context_request_values[i].NameDw);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->NameOffset: %x\n",  p_decoded_create_context_request_values[i].p_context_entry_wire->NameOffset);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->NameLength: %d\n",  p_decoded_create_context_request_values[i].p_context_entry_wire->NameLength);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->DataOffset: %x\n",  p_decoded_create_context_request_values[i].p_context_entry_wire->DataOffset);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->DataLength: %d\n", p_decoded_create_context_request_values[i].p_context_entry_wire->DataLength);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->p_payload: %X\n", p_decoded_create_context_request_values[i].p_payload);
  }
}

#endif
#endif
