#ifndef __SMB2_WIREDEFS_H__
#define __SMB2_WIREDEFS_H__


/* If compiler requires #pragma pack(1), replace all PACK_PRAGMA_ONE with #pragma pack(1) */
#define PACK_PRAGMA_ONE
/* If compiler requires #pragma pack(), replace all PACK_PRAGMA_POP with #pragma pack() */
#define PACK_PRAGMA_POP
/* If compiler supports __attribute__((packed)) set PACK_ATTRIBUTE to attribute__((packed)) */
#define PACK_ATTRIBUTE  __attribute__((packed))
#include <assert.h>
#define PACK_STRUCT_TO_WIRE(PSTRUCT,STYPE,SFIXED) \
    if (size<SFIXED)return -1;\
    tc_memcpy(buf,PSTRUCT,SFIXED);\
    buf=PADD(buf,SFIXED);\
    size-=SFIXED;

#define UNPACK_STRUCT_FR_WIRE(PSTRUCT,STYPE,SFIXED) \
    if (size<SFIXED)return -1;\
    tc_memcpy(PSTRUCT, buf, SFIXED);\
    buf=PADD(buf,SFIXED);\
    size-=SFIXED;


//****************************************************************************
//**
//**    smb2_wiredefs.h
//**    Header - Description
//**
//**
//****************************************************************************
//============================================================================
//    INTERFACE REQUIRED HEADERS
//============================================================================

//============================================================================
//    INTERFACE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================



#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001   // When set, indicates that security signatures are enabled on the server.
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002   // When set, indicates that security signatures are required by the server.
#define SMB2_SESSION_FLAG_BINDING 0x01           //  When set, indicates that the request is to bind an existing session to a new connection.

#define SMB2_DIALECT_2002  0x0202
#define SMB2_DIALECT_2100  0x0210
#define SMB2_DIALECT_3000  0x0300
#define SMB2_DIALECT_3002  0x0302
#define SMB2_DIALECT_WILD  0x02FF

#define SMB2IS3XXDIALECT(D) (D >= SMB2_DIALECT_3000)

/* EncryptionAlgorithm field in SMB2 TRANSFORM_HEADER */
#define SMB2_ENCRYPTION_AES128_CCM 0x0001


/* SMB2 Header structure command values and flag vlues. See  2.2.1.2, page 30 */
#define SMB2_NEGOTIATE          0x0000
#define SMB2_SESSION_SETUP      0x0001
#define SMB2_LOGOFF             0x0002
#define SMB2_TREE_CONNECT       0x0003
#define SMB2_TREE_DISCONNECT    0x0004
#define SMB2_CREATE             0x0005
#define SMB2_CLOSE              0x0006
#define SMB2_FLUSH              0x0007
#define SMB2_READ               0x0008
#define SMB2_WRITE              0x0009
#define SMB2_LOCK               0x000A
#define SMB2_IOCTL              0x000B
#define SMB2_CANCEL             0x000C
#define SMB2_ECHO               0x000D
#define SMB2_QUERY_DIRECTORY    0x000E
#define SMB2_CHANGE_NOTIFY      0x000F
#define SMB2_QUERY_INFO         0x0010
#define SMB2_SET_INFO           0x0011
#define SMB2_OPLOCK_BREAK       0x0012

#define SMB2_FLAGS_SERVER_TO_REDIR      0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND        0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS   0x00000004
#define SMB2_FLAGS_SIGNED               0x00000008
#define SMB2_FLAGS_DFS_OPERATIONS       0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION     0x20000000



/* Not sure if error scheme is the same, distinguish for now  */
// TBD
#define SMB2_EC_ERRSRV SMB_EC_ERRSRV
#define SMB2_ERRSRV_ERROR SMB_ERRSRV_ERROR
#define SMB2_ERRSRV_SRVERROR SMB_ERRSRV_SRVERROR

#define SMB2_STATUS_SUCCESS                     0x00000000 /* The client request is successful. */
#define SMB2_STATUS_INVALID_SMB                 0x00010002 /* An invalid SMB client request is received by the server. */
#define SMB2_STATUS_SMB_BAD_COMMAND             0x00160002 /* The client request received by the server contains an unknown SMB command code. */
#define SMB2_STATUS_SMB_USE_STANDARD            0x00FB0002 /* The client request received by the server is for a non-standard SMB operation (for example, an SMB_COM_READ_MPX request on a non-disk share ). The client SHOULD send another request with a different SMB command to perform this operation. */

#define SMB_STATUS_ACCOUNT_RESTRICTION          0xC000006E /* The client request to the server contains an invalid UID value. */


#define SMB2_STATUS_BUFFER_OVERFLOW             0x80000005 /* The data was too large to fit into the specified buffer. */
#define SMB2_STATUS_NO_MORE_FILES               0x80000006 /* No more files were found that match the file specification. */
#define SMB2_STATUS_STOPPED_ON_SYMLINK          0x8000002D /* The create operation stopped after reaching a symbolic link. */
#define SMB2_STATUS_UNSUCCESSFUL                0xC0000001 /* The requested operation failed */
#define SMB2_STATUS_NOT_IMPLEMENTED             0xC0000002 /* The requested operation is not implemented. */

#define SMB2_STATUS_INVALID_INFO_CLASS          0xC0000003 /*  */
#define SMB2_STATUS_INVALID_HANDLE              0xC0000008 /* Invalid file handle */
#define SMB2_STATUS_INVALID_PARAMETER           0xC000000D /* The parameter specified in the request is not valid. */
#define SMB2_STATUS_NO_SUCH_DEVICE              0xC000000E /* A device that does not exist was specified. */
#define SMB2_STATUS_INVALID_DEVICE_REQUEST      0xC0000010 /* The specified request is not a valid operation for the target device. */
#define SMB2_STATUS_MORE_PROCESSING_REQUIRED    0xC0000016 /* If extended security has been negotiated, then this error code can be returned in the SMB_COM_SESSION_SETUP_ANDX response from the server to indicate that additional authentication information is to be exchanged. See section 2.2.4.6 for details. */
#define SMB2_STATUS_ACCESS_DENIED               0xC0000022 /* The client did not have the required permission needed for the operation. */
#define SMB2_STATUS_BUFFER_TOO_SMALL            0xC0000023 /* The buffer is too small to contain the entry. No information has been written to the buffer. */
#define SMB2_STATUS_OBJECT_NAME_NOT_FOUND       0xC0000034 /* The object name is not found. */
#define SMB2_STATUS_OBJECT_NAME_COLLISION       0xC0000035 /* The object name already exists. */
#define SMB2_STATUS_OBJECT_PATH_NOT_FOUND       0xC000003A /* The path to the directory specified was not found. This error is also returned on a create request if the operation requires the creation of more than one new directory level for the path specified. */
#define SMB2_STATUS_BAD_IMPERSONATION_LEVEL     0xC00000A5 /* A specified impersonation level is invalid. This error is also used to indicate that a required impersonation level was not provided. */
#define SMB2_STATUS_IO_TIMEOUT                  0xC00000B5 /* The specified I/O operation was not completed before the time-out period expired. */
#define SMB2_STATUS_FILE_IS_A_DIRECTORY         0xC00000BA /* The file that was specified as a target is a directory and the caller specified that it could be anything but a directory. */
#define SMB2_STATUS_NOT_SUPPORTED               0xC00000BB /* The client request is not supported. */
#define SMB2_STATUS_NETWORK_NAME_DELETED        0xC00000C9 /* The network name specified by the client has been deleted on the server. This error is returned if the client specifies an incorrect TID or the share on the server represented by the TID was deleted. */
#define SMB2_STATUS_BAD_NETWORK_NAME            0xC00000CC /* The network or file name in a tree connect request was not found.  */
#define SMB2_STATUS_USER_SESSION_DELETED        0xC0000203 /* The user session specified by the client has been deleted on the server. This error is returned by the server if the client sends an incorrect UID. */
#define SMB2_STATUS_NOT_FOUND                   0xC0000225 /* Experimental. Send in response to a DFS_GET_REFERRALS query */
#define SMB2_STATUS_NETWORK_SESSION_EXPIRED     0xC000035C /* The client's session has expired; therefore, the client MUST re-authenticate to continue accessing remote resources. */
#define SMB2_STATUS_SMB_TOO_MANY_GUIDS_REQUESTED 0xC0000082
#define SMB2_STATUS_OBJECTID_NOT_FOUND           0xC00002F0
#define SMB2_STATUS_DUPLICATE_NAME               0xC00000BD

#define SMB2_STATUS_DISK_FULL                   0xC000007F
#define SMB2_STATUS_INFO_LENGTH_MISMATCH        0xC0000004
#define SMB2_STATUS_NO_SUCH_FILE                0xC000000F





#define  STG_E_WRITEFAULT  0x8003001D

#define SMB2_STATUS_INSUFFICIENT_RESOURCES      0xC000009A
#define SMB2_STATUS_REQUEST_NOT_ACCEPTED        0xC00000D0
/* Session flags - see section 2.2.6 only one at a time */
#define SMB2_SESSION_FLAG_IS_GUEST      0x0001
#define SMB2_SESSION_FLAG_IS_NULL       0x0002
#define SMB2_SESSION_FLAG_ENCRYPT_DATA  0x0004


#define SMB2_GLOBAL_CAP_DFS 0x00000001                  /* When set, indicates that the server supports the Distributed File System (DFS). */
#define SMB2_GLOBAL_CAP_LEASING 0x00000002              /* When set, indicates that the server supports leasing. This flag is not valid for the SMB 2.002 dialect. */
#define SMB2_GLOBAL_CAP_LARGE_MTU 0x00000004            /* ** When set, indicates that the server supports multi-credit operations. This flag is not valid for the SMB 2.002 dialect. */
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL 0x00000008        /* ** When set, indicates that the server supports establishing multiple channels for a single session. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. . */
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010   /* ** When set, indicates that the server supports persistent handles. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. */
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING 0x00000020    /* ** When set, indicates that the server supports directory leasing. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. */
#define SMB2_GLOBAL_CAP_ENCRYPTION 0x00000040           /* ** When set, indicates that the server supports encryption. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects. */




/*  File_pipe_printer access mask, section 2.2.13.1.1 */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_DATA         0x00000001   /* ** This value indicates the right to read data from the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA        0x00000002   /* ** This value indicates the right to write data into the file or named pipe beyond the end of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA       0x00000004   /* ** This value indicates the right to append data into the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_EA           0x00000008   /* ** This value indicates the right to read the extended attributes of the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_EA          0x00000010   /* ** This value indicates the right to write or change the extended attributes to the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_DELETE_CHILD      0x00000040   /* ** This value indicates the right to delete entries within a directory. */
#define SMB2_FPP_ACCESS_MASK_FILE_EXECUTE           0x00000020   /* ** This value indicates the right to execute the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_ATTRIBUTES   0x00000080   /* ** This value indicates the right to read the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_ATTRIBUTES  0x00000100   /* ** This value indicates the right to change the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_DELETE                 0x00010000   /* ** This value indicates the right to delete the file. */
#define SMB2_FPP_ACCESS_MASK_READ_CONTROL           0x00020000   /* ** This value indicates the right to read the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_WRITE_DAC              0x00040000   /* ** This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP]. */
#define SMB2_FPP_ACCESS_MASK_WRITE_OWNER            0x00080000   /* ** This value indicates the right to change the owner in the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_SYNCHRONIZE            0x00100000   /* ** SMB2 clients set this flag to any value. SMB2 servers SHOULD ignore this flag. */
#define SMB2_FPP_ACCESS_MASK_ACCESS_SYSTEM_SECURITY 0x01000000   /* ** This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42> */
#define SMB2_FPP_ACCESS_MASK_MAXIMUM_ALLOWED        0x02000000   /* ** This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_ALL            0x10000000   /* ** This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_EXECUTE        0x20000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_WRITE          0x40000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_READ           0x80000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL. */


/*  directory access mask, section 2.2.13.1.1 */
#define SMB2_DIR_ACCESS_MASK_FILE_LIST_DIRECTORY    0x00000001   /* ** This value indicates the right to enumerate the contents of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_ADD_FILE          0x00000002   /* ** This value indicates the right to create a file under the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_ADD_SUBDIRECTORY  0x00000004   /* ** This value indicates the right to add a sub-directory under the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_READ_EA           0x00000008   /* ** This value indicates the right to read the extended attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_WRITE_EA          0x00000010   /* ** This value indicates the right to write or change the extended attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_TRAVERSE          0x00000020   /* ** This value indicates the right to traverse this directory if the server enforces traversal checking */
#define SMB2_DIR_ACCESS_MASK_FILE_DELETE_CHILD      0x00000040   /* ** This value indicates the right to delete the files and directories within this directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_READ_ATTRIBUTES   0x00000080   /* ** This value indicates the right to read the attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_FILE_WRITE_ATTRIBUTES  0x00000100   /* ** This value indicates the right to change the attributes of the directory. */
#define SMB2_DIR_ACCESS_MASK_DELETE                 0x00010000   /* ** This value indicates the right to delete the directory. */
#define SMB2_DIR_ACCESS_MASK_READ_CONTROL           0x00020000   /* ** This value indicates the right to read the security descriptor for the directory. */
#define SMB2_DIR_ACCESS_MASK_WRITE_DAC              0x00040000   /* ** This value indicates the right to change the DACL in the security descriptor for the directory. For the DACL data structure, see ACL in [MS-DTYP]. */
#define SMB2_DIR_ACCESS_MASK_WRITE_OWNER            0x00080000   /* ** This value indicates the right to change the owner in the security descriptor for the directory. */
#define SMB2_DIR_ACCESS_MASK_SYNCHRONIZE            0x00100000   /* ** SMB2 clients set this flag to any value.<43> SMB2 servers SHOULD<44> ignore this flag. */
#define SMB2_DIR_ACCESS_MASK_ACCESS_SYSTEM_SECURITY 0x01000000   /* ** This value indicates the right to read or change the SACL in the security descriptor for the directory. For the SACL data structure, see ACL in [MS-DTYP].<45> */
#define SMB2_DIR_ACCESS_MASK_MAXIMUM_ALLOWED        0x02000000   /* ** This value indicates that the client is requesting an open to the directory with the highest level of access the client has on this directory. If no access is granted for the client on this directory, the server MUST fail the open with STATUS_ACCESS_DENIED. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_ALL            0x10000000   /* ** This value indicates a request for all the access flags that are listed above except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_EXECUTE        0x20000000   /* ** This value indicates a request for the following access flags listed above: FILE_READ_ATTRIBUTES| FILE_TRAVERSE| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_WRITE          0x40000000   /* ** This value indicates a request for the following access flags listed above: FILE_ADD_FILE| FILE_ADD_SUBDIRECTORY| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_DIR_ACCESS_MASK_GENERIC_READ           0x80000000   /* ** This value indicates a request for the following access flags listed above: FILE_LIST_DIRECTORY| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL. */

// GET/SET INFO
#define SMB2_0_INFO_FILE       0x01
#define SMB2_0_INFO_FILESYSTEM 0x02
#define SMB2_0_INFO_SECURITY   0x03
#define SMB2_0_INFO_QUOTA      0x04


#define SMB2_0_FileRenameInformation       0x0a
#define SMB2_0_FileSetDisposition          0x0d
#define SMB2_0_FileEndofFile               0x14


//============================================================================
//    INTERFACE DATA DECLARATIONS
//============================================================================
#define PACK_CLIENT_MID(TO,F) *((unsigned short *)(TO)) = F
#define UNPACK_CLIENT_MID(F)  (unsigned short) *((unsigned short *)(F))

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_HEADER
{
    byte ProtocolId[4];
    word StructureSize; // 64
    word CreditCharge; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
    dword Status_ChannelSequenceReserved; /*  (4 bytes): */
    word Command;
    word CreditRequest_CreditResponse;
    dword Flags;
    dword NextCommand;
    ddword MessageId;
#define ProcessidH Reserved // use this as an alias until Reserved is changed in the header and u\all uses
    dword Reserved;
    dword TreeId;
    ddword SessionId;
    byte Signature[16];

} PACK_ATTRIBUTE RTSMB2_HEADER;
PACK_PRAGMA_POP
typedef RTSMB2_HEADER RTSMB_FAR *PRTSMB2_HEADER;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_NEGOTIATE_C
{
    word StructureSize; // 36
    word DialectCount;
    word SecurityMode;
    word Reserved;
    dword Capabilities;
    byte  guid[16];
    FILETIME_T ClientStartTime;
    word Dialects[4];
} PACK_ATTRIBUTE RTSMB2_NEGOTIATE_C;
PACK_PRAGMA_POP
typedef RTSMB2_NEGOTIATE_C RTSMB_FAR *PRTSMB2_NEGOTIATE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_NEGOTIATE_R
{
    word StructureSize; // 65
    word SecurityMode;
    word DialectRevision;
    word Reserved;
    byte  ServerGuid[16];
    dword Capabilities;
    dword MaxTransactSize;
    dword MaxReadSize;
    dword MaxWriteSize;
    ddword SystemTime;
    ddword ServerStartTime;
    word SecurityBufferOffset;
    word SecurityBufferLength;
    dword Reserved2;
    byte  SecurityBuffer;
} PACK_ATTRIBUTE RTSMB2_NEGOTIATE_R;
PACK_PRAGMA_POP
typedef RTSMB2_NEGOTIATE_R RTSMB_FAR *PRTSMB2_NEGOTIATE_R;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SESSION_SETUP_C
{
    word  StructureSize; // 25
	byte  Flags;
	byte  SecurityMode;
	dword Capabilities;
	dword Channel;
	word  SecurityBufferOffset;
	word  SecurityBufferLength;
    ddword PreviousSessionId;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_SESSION_SETUP_C;
PACK_PRAGMA_POP
typedef RTSMB2_SESSION_SETUP_C RTSMB_FAR *PRTSMB2_SESSION_SETUP_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SESSION_SETUP_R
{
    word  StructureSize; // 9
	word  SessionFlags;
	word  SecurityBufferOffset;
	word  SecurityBufferLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_SESSION_SETUP_R;
PACK_PRAGMA_POP
typedef RTSMB2_SESSION_SETUP_R RTSMB_FAR *PRTSMB2_SESSION_SETUP_R;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOGOFF_C
{
    word  StructureSize; // 4
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_LOGOFF_C;
PACK_PRAGMA_POP
typedef RTSMB2_LOGOFF_C RTSMB_FAR *PRTSMB2_LOGOFF_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOGOFF_R
{
    word  StructureSize; // 16
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_LOGOFF_R;
PACK_PRAGMA_POP
typedef RTSMB2_LOGOFF_R RTSMB_FAR *PRTSMB2_LOGOFF_R;

#define SMB2_SHARE_TYPE_DISK 0x01
#define SMB2_SHARE_TYPE_PIPE 0x02
#define SMB2_SHARE_TYPE_PRINT 0x03

#define SMB2_SHAREFLAG_MANUAL_CACHING 0x00000000
#define SMB2_SHAREFLAG_AUTO_CACHING 0x00000010
#define SMB2_SHAREFLAG_VDO_CACHING 0x00000020
#define SMB2_SHAREFLAG_NO_CACHING 0x00000030
#define SMB2_SHAREFLAG_DFS 0x00000001
#define SMB2_SHAREFLAG_DFS_ROOT 0x00000002
#define SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS 0x00000100
#define SMB2_SHAREFLAG_FORCE_SHARED_DELETE 0x00000200
#define SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING 0x00000400
#define SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM 0x00000800
#define SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK 0x00001000
#define SMB2_SHAREFLAG_ENABLE_HASH_V1 0x00002000
#define SMB2_SHAREFLAG_ENABLE_HASH_V2 0x00004000
#define SMB2_SHAREFLAG_ENCRYPT_DATA 0x00008000
#define SMB2_SHARE_CAP_DFS 0x00000008
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY 0x00000010
#define SMB2_SHARE_CAP_SCALEOUT 0x00000020
#define SMB2_SHARE_CAP_CLUSTER 0x00000040
#define SMB2_SHARE_CAP_ASYMMETRIC 0x00000080

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_CONNECT_C
{
    word  StructureSize; // 9
    word  Reserved;
    word  PathOffset;
    word  PathLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_TREE_CONNECT_C;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_CONNECT_C RTSMB_FAR *PRTSMB2_TREE_CONNECT_C;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_CONNECT_R
{
    word  StructureSize; // 16
    byte  ShareType;
    byte  Reserved;
    dword ShareFlags;
    dword Capabilities;
    dword MaximalAccess;
} PACK_ATTRIBUTE RTSMB2_TREE_CONNECT_R;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_CONNECT_R RTSMB_FAR *PRTSMB2_TREE_CONNECT_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_DISCONNECT_C
{
    word  StructureSize; // 4
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_TREE_DISCONNECT_C;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_DISCONNECT_C RTSMB_FAR *PRTSMB2_TREE_DISCONNECT_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TREE_DISCONNECT_R
{
    word  StructureSize; // 4
    word  Reserved;
} PACK_ATTRIBUTE RTSMB2_TREE_DISCONNECT_R;
PACK_PRAGMA_POP
typedef RTSMB2_TREE_DISCONNECT_R RTSMB_FAR *PRTSMB2_TREE_DISCONNECT_R;


#define SMB2_OPLOCK_LEVEL_NONE 0x00
#define SMB2_OPLOCK_LEVEL_II 0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08
#define SMB2_OPLOCK_LEVEL_BATCH 0x09
#define SMB2_OPLOCK_LEVEL_LEASE 0xFF

#define SMB2_ImpersonationLevel_Anonymous           0x00000000
#define SMB2_ImpersonationLevel_Identification      0x00000001
#define SMB2_ImpersonationLevel_Impersonation       0x00000002
#define SMB2_ImpersonationLevel_Delegate            0x00000003

/* RTSMB2_CREATE_C::ShareAccess */
#define SMB2_FILE_SHARE_READ                        0x00000001
#define SMB2_FILE_SHARE_WRITE                       0x00000002
#define SMB2_FILE_SHARE_DELETE                      0x00000004

/* RTSMB2_CREATE_C::CreateDisposition */
#define SMB2_FILE_SUPERSEDE                         0x00000000
#define SMB2_FILE_OPEN                              0x00000001
#define SMB2_FILE_CREATE                            0x00000002
#define SMB2_FILE_OPEN_IF                           0x00000003
#define SMB2_FILE_OVERWRITE                         0x00000004
#define SMB2_FILE_OVERWRITE_IF                      0x00000005

/* RTSMB2_CREATE_C::CreateOptions */
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000
#define FILE_OPEN_REMOTE_INSTANCE 0x00000400
#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000
#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000

/* Note sections 2.2.13.2 contains several create contexts taht extend create
    Create contexts are defined in another file
*/

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CREATE_C
{
    word  StructureSize; // 57
	byte  SecurityFlags;
	byte  RequestedOplockLevel;
	dword ImpersonationLevel;
	byte  SmbCreateFlags[8];
	byte  Reserved[8];
	dword DesiredAccess;
	dword FileAttributes;
	dword ShareAccess;
	dword CreateDisposition;
	dword CreateOptions;
    word  NameOffset;
    word  NameLength;
	dword CreateContextsOffset;
	dword CreateContextsLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_CREATE_C;
PACK_PRAGMA_POP
typedef RTSMB2_CREATE_C RTSMB_FAR *PRTSMB2_CREATE_C;

/* Note sections 2.2.14.2 contains several create contexts that extend create response
    Create contexts are defined in another file
*/
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CREATE_R
{
    word  StructureSize; // 89
	byte  OplockLevel;
	byte  Flags;
	dword CreateAction;
	FILETIME_T CreationTime;
	FILETIME_T LastAccessTime;
	FILETIME_T LastWriteTime;
	FILETIME_T ChangeTime;
	ddword AllocationSize;
	ddword EndofFile;
	dword  FileAttributes;
	dword  Reserved2;
    byte   FileId[16];
	dword CreateContextsOffset;
	dword CreateContextsLength;
    byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_CREATE_R;
PACK_PRAGMA_POP
typedef RTSMB2_CREATE_R RTSMB_FAR *PRTSMB2_CREATE_R;

#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 0x0001
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CLOSE_C
{
    word  StructureSize; // 24
	word  Flags;
	dword Reserved;
	byte  FileId[16];
} PACK_ATTRIBUTE RTSMB2_CLOSE_C;
PACK_PRAGMA_POP
typedef RTSMB2_CLOSE_C RTSMB_FAR *PRTSMB2_CLOSE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CLOSE_R
{
    word  StructureSize; // 60
	word  Flags;
	dword Reserved;
	FILETIME_T CreationTime;
	FILETIME_T LastAccessTime;
	FILETIME_T LastWriteTime;
	FILETIME_T ChangeTime;
	ddword AllocationSize;
	ddword EndofFile;
	dword  FileAttributes;
} PACK_ATTRIBUTE RTSMB2_CLOSE_R;
PACK_PRAGMA_POP
typedef RTSMB2_CLOSE_R RTSMB_FAR *PRTSMB2_CLOSE_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_FLUSH_C
{
    word  StructureSize; // 24
	word  Reserved1;
	dword Reserved2;
	byte  FileId[16];
} PACK_ATTRIBUTE RTSMB2_FLUSH_C;
PACK_PRAGMA_POP
typedef RTSMB2_FLUSH_C RTSMB_FAR *PRTSMB2_FLUSH_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_FLUSH_R
{
    word  StructureSize; // 4
	word  Reserved;
} PACK_ATTRIBUTE RTSMB2_FLUSH_R;
PACK_PRAGMA_POP
typedef RTSMB2_FLUSH_R RTSMB_FAR *PRTSMB2_FLUSH_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_READ_C
{
    word    StructureSize; // 49
	byte    Padding;
	byte    Flags;
	dword   Length;
	ddword  Offset;
	byte    FileId[16];
	dword   MinimumCount;
	dword   Channel;
	dword   RemainingBytes;
	word    ReadChannelInfoOffset;
	word    ReadChannelInfoLength;
	byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_READ_C;
PACK_PRAGMA_POP
typedef RTSMB2_READ_C RTSMB_FAR *PRTSMB2_READ_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_READ_R
{
    word  StructureSize; // 17
	byte  DataOffset;
	byte  Reserved;
	dword DataLength;
	dword DataRemaining;
	dword Reserved2;
	byte  Buffer;
} PACK_ATTRIBUTE RTSMB2_READ_R;
PACK_PRAGMA_POP
typedef RTSMB2_READ_R RTSMB_FAR *PRTSMB2_READ_R;

#define SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_WRITE_C
{
    word    StructureSize; // 49
	word    DataOffset;
	dword   Length;
	ddword  Offset;
	byte    FileId[16];
	dword   Channel;
	dword   RemainingBytes;
	word    WriteChannelInfoOffset;
	word    WriteChannelInfoLength;
	dword   Flags;
	byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_WRITE_C;
PACK_PRAGMA_POP
typedef RTSMB2_WRITE_C RTSMB_FAR *PRTSMB2_WRITE_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_WRITE_R
{
    word  StructureSize; // 17
	word  Reserved;
	dword Count;
	dword Remaining;
	word  WriteChannelInfoOffset;
	word  WriteChannelInfoLength;
} PACK_ATTRIBUTE RTSMB2_WRITE_R;
PACK_PRAGMA_POP
typedef RTSMB2_WRITE_R RTSMB_FAR *PRTSMB2_WRITE_R;

/* Server -> Client */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_OPLOCK_BREAK_C
{
    word    StructureSize; // 24
	byte    OplockLevel;
	byte    Reserved;
	dword   Reserved2;
	byte    FileId[16];
} PACK_ATTRIBUTE RTSMB2_OPLOCK_BREAK_C;
PACK_PRAGMA_POP
typedef RTSMB2_OPLOCK_BREAK_C RTSMB_FAR *PRTSMB2_OPLOCK_BREAK_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_OPLOCK_BREAK_R
{
    word    StructureSize; // 24
	byte    OplockLevel;
	byte    Reserved;
	dword   Reserved2;
	byte    FileId[16];
} PACK_ATTRIBUTE RTSMB2_OPLOCK_BREAK_R;  /* Acnowledgement */
PACK_PRAGMA_POP
typedef RTSMB2_OPLOCK_BREAK_R RTSMB_FAR *PRTSMB2_OPLOCK_BREAK_R;


#define SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED 0x01

#define SMB2_LEASE_READ_CACHING 0x01
#define SMB2_LEASE_HANDLE_CACHING 0x02
#define SMB2_LEASE_WRITE_CACHING 0x04

/* Server -> Client */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LEASE_BREAK_C
{
    word    StructureSize; // 44
    word    NewEpoch;
	dword   Flags;
	byte    LeaseKey[16];
	dword   CurrentLeaseState;
	dword   NewLeaseState;
	dword   BreakReason;
	dword   AccessMaskHint;
	dword   ShareMaskHint;
} PACK_ATTRIBUTE RTSMB2_LEASE_BREAK_C;
PACK_PRAGMA_POP
typedef RTSMB2_LEASE_BREAK_C RTSMB_FAR *PRTSMB2_LEASE_BREAK_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LEASE_BREAK_R
{
    word    StructureSize; // 36
    word    Reserved;
	dword   Flags;
	byte    LeaseKey[16];
	dword   LeaseState;
	ddword  LeaseDuration;
} PACK_ATTRIBUTE RTSMB2_LEASE_BREAK_R;
PACK_PRAGMA_POP
typedef RTSMB2_LEASE_BREAK_R RTSMB_FAR *PRTSMB2_LEASE_BREAK_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOCK_ELEMENT
{
	ddword   Offset;
	ddword   Length;
	dword    Flags;
	dword    Reserved;
} PACK_ATTRIBUTE RTSMB2_LOCK_ELEMENT;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOCK_REQUEST_C
{
    word    StructureSize; // 48
	word    LockCount;
	dword   LockSequence;
	byte    FileId[16];
    RTSMB2_LOCK_ELEMENT Locks;
} PACK_ATTRIBUTE RTSMB2_LOCK_REQUEST_C;
PACK_PRAGMA_POP
typedef RTSMB2_LOCK_REQUEST_C RTSMB_FAR *PRTSMB2_LOCK_REQUEST_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_LOCK_REQUEST_R
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_LOCK_REQUEST_R;
PACK_PRAGMA_POP
typedef RTSMB2_LOCK_REQUEST_R RTSMB_FAR *PRTSMB2_LOCK_REQUEST_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_ECHO_C
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_ECHO_C;
PACK_PRAGMA_POP
typedef RTSMB2_ECHO_C RTSMB_FAR *PRTSMB2_ECHO_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_ECHO_R
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_ECHO_R;
PACK_PRAGMA_POP
typedef RTSMB2_ECHO_R RTSMB_FAR *PRTSMB2_ECHO_R;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CANCEL_C
{
    word    StructureSize; // 4
	word    Reserved;
} PACK_ATTRIBUTE RTSMB2_CANCEL_C;
PACK_PRAGMA_POP
typedef RTSMB2_CANCEL_C RTSMB_FAR *PRTSMB2_CANCEL_C;



#define FSCTL_DFS_GET_REFERRALS         0x00060194
#define FSCTL_VALIDATE_NEGOTIATE_INFO   0x00140204

// None of these are serviced.

#define FSCTL_GET_OBJECT_ID             0x0009009c
#define FSCTL_CREATE_OR_GET_OBJECT_ID   0x000900c0
#define FSCTL_DELETE_OBJECT_ID          0x000900a0
#define FSCTL_DELETE_REPARSE_POINT              0x900ac
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE         0x98344
#define FSCTL_FILE_LEVEL_TRIM         0x98208
#define FSCTL_FILESYSTEM_GET_STATISTICS         0x90060
#define FSCTL_FIND_FILES_BY_SID         0x9008f
#define FSCTL_GET_COMPRESSION         0x9003c
#define FSCTL_GET_INTEGRITY_INFORMATION         0x9027c
#define FSCTL_GET_NTFS_VOLUME_DATA         0x90064
#define FSCTL_GET_REFS_VOLUME_DATA         0x902D8
#define FSCTL_GET_REPARSE_POINT         0x900a8
#define FSCTL_LMR_SET_LINK_TRACKING_INFORMATION         0x1400ec
#define FSCTL_OFFLOAD_READ         0x94264
#define FSCTL_OFFLOAD_WRITE         0x98268
#define FSCTL_PIPE_PEEK         0x11400c
#define FSCTL_PIPE_WAIT         0x110018
#define FSCTL_QUERY_ALLOCATED_RANGES         0x940cf
#define FSCTL_QUERY_FAT_BPB         0x90058
#define FSCTL_QUERY_FILE_REGIONS         0x90284
#define FSCTL_QUERY_ON_DISK_VOLUME_INFO         0x9013c
#define FSCTL_QUERY_SPARING_INFO         0x90138
#define FSCTL_READ_FILE_USN_DATA         0x900eb
#define FSCTL_RECALL_FILE         0x90117
#define FSCTL_SET_COMPRESSION         0x9c040
#define FSCTL_SET_DEFECT_MANAGEMENT         0x98134
#define FSCTL_SET_ENCRYPTION         0x900D7
#define FSCTL_SET_INTEGRITY_INFORMATION         0x9C280
#define FSCTL_SET_OBJECT_ID         0x90098
#define FSCTL_SET_OBJECT_ID_EXTENDED         0x900bc
#define FSCTL_SET_REPARSE_POINT         0x900a4
#define FSCTL_SET_SPARSE         0x900c4
#define FSCTL_SET_ZERO_DATA         0x980c8
#define FSCTL_SET_ZERO_ON_DEALLOCATION         0x90194
#define FSCTL_SIS_COPYFILE         0x90100
#define FSCTL_WRITE_USN_CLOSE_RECORD         0x900ef


#define FSCTL_DFS_GET_REFERRALS      0x00060194
#define FSCTL_DFS_GET_REFERRALS_EX   0x000601B0
#define FSCTL_REQUEST_OPLOCK_LEVEL_1 0x00090000
#define FSCTL_REQUEST_OPLOCK_LEVEL_2 0x00090004
#define FSCTL_REQUEST_BATCH_OPLOCK   0x00090008
#define FSCTL_LOCK_VOLUME            0x00090018
#define FSCTL_UNLOCK_VOLUME          0x0009001C
#define FSCTL_IS_PATHNAME_VALID      0x0009002C
#define FSCTL_FILESYSTEM_GET_STATS   0x00090060
#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073
#define FSCTL_IS_VOLUME_DIRTY        0x00090078
#define FSCTL_ALLOW_EXTENDED_DASD_IO 0x00090083
#define FSCTL_REQUEST_FILTER_OPLOCK  0x0009008C
#define FSCTL_ENCRYPTION_FSCTL_IO    0x000900DB
#define FSCTL_WRITE_RAW_ENCRYPTED    0x000900DF
#define FSCTL_READ_RAW_ENCRYPTED     0x000900E3
#define FSCTL_SET_ZERO_ON_DEALLOC    0x00090194
#define FSCTL_SET_SHORT_NAME_BEHAVIOR 0x000901B
#define FSCTL_SIS_LINK_FILES         0x0009C104
#define FSCTL_PIPE_TRANSCEIVE        0x0011C017
#define FSCTL_SRV_ENUMERATE_SNAPSHOTS 0x00144064
#define FSCTL_SRV_REQUEST_RESUME_KEY 0x00140078
#define FSCTL_LMR_REQUEST_RESILIENCY 0x001401D4
#define FSCTL_LMR_GET_LINK_TRACK_INF 0x001400E8
#define FSCTL_LMR_SET_LINK_TRACK_INF 0x001400EC
#define FSCTL_VALIDATE_NEGOTIATE_INFO 0x00140204
/* Perform server-side data movement */
#define FSCTL_SRV_COPYCHUNK 0x001440F2
#define FSCTL_SRV_COPYCHUNK_WRITE 0x001480F2
#define FSCTL_QUERY_NETWORK_INTERFACE_INFO 0x001401FC
#define FSCTL_SRV_READ_HASH          0x001441BB

/* See FSCC 2.1.2.5 */
#define IO_REPARSE_TAG_MOUNT_POINT   0xA0000003
#define IO_REPARSE_TAG_HSM           0xC0000004
#define IO_REPARSE_TAG_SIS           0x80000007
#define IO_REPARSE_TAG_HSM2          0x80000006
#define IO_REPARSE_TAG_DRIVER_EXTENDER 0x80000005
#define IO_REPARSE_TAG_DFS           0x8000000A
#define IO_REPARSE_TAG_DFSR          0x80000012
#define IO_REPARSE_TAG_FILTER_MANAGER 0x8000000B
#define IO_REPARSE_TAG_SYMLINK       0xA000000C
#define IO_REPARSE_TAG_DEDUP         0x80000013
#define IO_REPARSE_APPXSTREAM        0xC0000014
#define IO_REPARSE_TAG_NFS           0x80000014

#define SMB2_0_IOCTL_IS_FSCTL           0x00000001


/* Note: 2.2.31.1 contains formats for IOCTL requests */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_IOCTL_C
{
    word    StructureSize; // 57
	word    Reserved;
	dword   CtlCode;
	byte    FileId[16];
	dword   InputOffset;
	dword   InputCount;
	dword   MaxInputResponse;
	dword   OutputOffset;
	dword   OutputCount;
	dword   MaxOutputResponse;
	dword   Flags;
    dword   Reserved2;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_IOCTL_C;
PACK_PRAGMA_POP
typedef RTSMB2_IOCTL_C RTSMB_FAR *PRTSMB2_IOCTL_C;

/* Note: 2.2.32.1 contains formats for IOCTL replies */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_IOCTL_R
{
    word    StructureSize; // 49
	word    Reserved;
	dword   CtlCode;
	byte    FileId[16];
	dword   InputOffset;
	dword   InputCount;
	dword   OutputOffset;
	dword   OutputCount;
	dword   Flags;
    dword   Reserved2;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_IOCTL_R;
PACK_PRAGMA_POP
typedef RTSMB2_IOCTL_R RTSMB_FAR *PRTSMB2_IOCTL_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_DIRECTORY_C
{
    word    StructureSize; // 33
	byte    FileInformationClass;
	byte    Flags;
	dword   FileIndex;
	byte    FileId[16];
	word    FileNameOffset;
	word    FileNameLength;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_DIRECTORY_C;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_DIRECTORY_C RTSMB_FAR *PRTSMB2_QUERY_DIRECTORY_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_DIRECTORY_R
{
    word    StructureSize; // 9
	word    OutputBufferOffset;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_DIRECTORY_R;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_DIRECTORY_R RTSMB_FAR *PRTSMB2_QUERY_DIRECTORY_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CHANGE_NOTIFY_C
{
    word    StructureSize; // 33
	word    Flags;
	dword   OutputBufferLength;
	byte    FileId[16];
    dword   CompletionFilter;
    dword   Reserved;
} PACK_ATTRIBUTE RTSMB2_CHANGE_NOTIFY_C;
PACK_PRAGMA_POP
typedef RTSMB2_CHANGE_NOTIFY_C RTSMB_FAR *PRTSMB2_CHANGE_NOTIFY_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_CHANGE_NOTIFY_R
{
    word    StructureSize; // 9
	word    OutputBufferOffset;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_CHANGE_NOTIFY_R;
PACK_PRAGMA_POP
typedef RTSMB2_CHANGE_NOTIFY_R RTSMB_FAR *PRTSMB2_CHANGE_NOTIFY_R;

/* Section 2.2.37.1 contains info request decriptions */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_INFO_C
{
    word    StructureSize; // 41
	byte    InfoType;
	byte    FileInfoClass;
	dword   OutputBufferLength;
	word    InputBufferOffset;
	word    Reserved;
	dword   InputBufferLength;
	dword   AdditionalInformation;
	dword   Flags;
	byte    FileId[16];
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_INFO_C;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_INFO_C RTSMB_FAR *PRTSMB2_QUERY_INFO_C;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_QUERY_INFO_R
{
    word    StructureSize; // 9
	word    OutputBufferOffset;
	dword   OutputBufferLength;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_QUERY_INFO_R;
PACK_PRAGMA_POP
typedef RTSMB2_QUERY_INFO_R RTSMB_FAR *PRTSMB2_QUERY_INFO_R;

/* Section 2.2.39.1 contains set info request decriptions */
PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SET_INFO_C
{
    word    StructureSize; // 33
	byte    InfoType;
	byte    FileInfoClass;
	dword   BufferLength;
	word    BufferOffset;
	word    Reserved;
	dword   AdditionalInformation;
	byte    FileId[16];
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_SET_INFO_C;
PACK_PRAGMA_POP
typedef RTSMB2_SET_INFO_C RTSMB_FAR *PRTSMB2_SET_INFO_C;

PACK_PRAGMA_ONE
typedef struct s_FILE_RENAME_INFORMATION_TYPE_2
{
	byte    ReplaceIfExists;
	byte    Reserved[7];
	ddword  RootDirectory;
	dword   FileNameLength;  // Bytes
    byte    Buffer[1];
} PACK_ATTRIBUTE FILE_RENAME_INFORMATION_TYPE_2;
PACK_PRAGMA_POP
typedef FILE_RENAME_INFORMATION_TYPE_2 RTSMB_FAR *PFILE_RENAME_INFORMATION_TYPE_2;


PACK_PRAGMA_ONE
typedef struct s_FILE_DISPOSITION_INFO
{
  byte    DeletePending; // 2
} PACK_ATTRIBUTE FILE_DISPOSITION_INFO;
PACK_PRAGMA_POP




PACK_PRAGMA_ONE
typedef struct s_RTSMB2_SET_INFO_R
{
    word    StructureSize; // 2
} PACK_ATTRIBUTE RTSMB2_SET_INFO_R;
PACK_PRAGMA_POP
typedef RTSMB2_SET_INFO_R RTSMB_FAR *PRTSMB2_SET_INFO_R;

PACK_PRAGMA_ONE
typedef struct s_RTSMB2_TRANSFORM_HEADER
{
	byte    ProtocolId[4];
	byte    Signature[16];
	byte    Nonce[16];
    dword   OriginalMessageSize;
    word    Reserved;
    word    EncryptionAlgorithm;
	ddword  SessionId;
} PACK_ATTRIBUTE RTSMB2_TRANSFORM_HEADER;
PACK_PRAGMA_POP
typedef RTSMB2_TRANSFORM_HEADER RTSMB_FAR *PRTSMB2_TRANSFORM_HEADER;


PACK_PRAGMA_ONE
typedef struct s_RTSMB2_ERROR_R
{
    word    StructureSize; // 9
	word    Reserved;
	dword   ByteCount;
    byte    Buffer;
} PACK_ATTRIBUTE RTSMB2_ERROR_R;
PACK_PRAGMA_POP
typedef RTSMB2_ERROR_R RTSMB_FAR *PRTSMB2_ERROR_R;


PACK_PRAGMA_ONE
typedef struct s_MSFSCC_BOTH_DIRECTORY_INFO
{
	dword file_index;
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_end_of_file;
	dword high_end_of_file;
	dword low_allocation_size;
	dword high_allocation_size;

	dword extended_file_attributes;
	dword ea_size;

	byte short_name_size;	/* size in characters */
	rtsmb_char short_name[13];	/* 8.3 name */

	dword filename_size;
    // byte    Buffer;
} MSFSCC_BOTH_DIRECTORY_INFO;
PACK_PRAGMA_POP



PACK_PRAGMA_ONE
// Possible errors STATUS_INFO_LENGTH_MISMATCH 0xC0000004
typedef struct s_MSFSCC_FILE_FS_SIZE_INFO
{
	ddword TotalAllocationUnits;
	ddword AvailableAllocationUnits;
	dword SectorsPerAllocationUnit;
	dword BytesPerSector;
} MSFSCC_FILE_FS_SIZE_INFO;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
// Possible errors STATUS_INFO_LENGTH_MISMATCH 0xC0000004
typedef struct s_MSFSCC_FILE_FS_FULL_SIZE_INFO
{
	ddword TotalAllocationUnits;
	ddword CallerAvailableAllocationUnits;
	ddword ActualAvailableAllocationUnits;
	dword SectorsPerAllocationUnit;
	dword BytesPerSector;
} MSFSCC_FILE_FS_FULL_SIZE_INFO;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
// Possible errors STATUS_INFO_LENGTH_MISMATCH 0xC0000004
typedef struct s_MSFSCC_FILE_FS_VOLUME_INFO
{
	ddword VolumeCreationTime;
	dword VolumeSerialNumber;
	dword VolumeLabelLength;
	byte  SupportsObjects;
	byte  Reserved;
} MSFSCC_FILE_FS_VOLUME_INFO;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_MSFSCC_FULL_DIRECTORY_INFO
{
	dword file_index;
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_end_of_file;
	dword high_end_of_file;
	dword low_allocation_size;
	dword high_allocation_size;
	dword extended_file_attributes;
	dword filename_size;
	dword ea_size;
    // byte    Buffer;
} MSFSCC_FULL_DIRECTORY_INFO;
PACK_PRAGMA_POP



PACK_PRAGMA_ONE
typedef struct s_MSFSCC_STANDARD_DIRECTORY_INFO
{
	dword low_allocation_size;
	dword high_allocation_size;
	dword low_end_of_file;
	dword high_end_of_file;
	dword number_of_links;
	byte  delete_pending;
	byte  directory;
	word  reserved;
} MSFSCC_STANDARD_DIRECTORY_INFO;
PACK_PRAGMA_POP

// See ms-fscc page 98
PACK_PRAGMA_ONE
typedef struct s_MSFSCC_ALL_DIRECTORY_INFO
{
// BasicInformation (40 bytes): A FILE_BASIC_INFORMATION structure specified in section 2.4.7.
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword extended_file_attributes;
	dword resered_dw;
// StandardInformation (24 bytes): A FILE_STANDARD_INFORMATION structure specified in section 2.4.38.
	dword low_allocation_size;
	dword high_allocation_size;
	dword low_end_of_file;
	dword high_end_of_file;
	dword number_of_links;
	byte  delete_pending;
	byte  is_directory;
	word  reserved;
// InternalInformation (8 bytes): A FILE_INTERNAL_INFORMATION structure specified in section 2.4.20.
    ddword IndexNumber; // (8 bytes): A 64-bit signed integer that contains the 8-byte file reference number for the file. This number MUST be assigned by the file system and is unique to the volume on which the file or directory is located. This file reference number is the same as the file reference number that is stored in the FileId field of the FILE_ID_BOTH_DIR_INFORMATION and
// EaInformation (4 bytes): A FILE_EA_INFORMATION structure specified in section 2.4.12.
    dword EaSize; //  (4 bytes): A 32-bit unsigned integer that contains the combined length, in bytes, of the extended attributes (EA) for the file
// AccessInformation (4 bytes): A FILE_ACCESS_INFORMATION structure specified in section 2.4.1.
    ddword AccessFlags; // (4 bytes): A 32-bit unsigned integer that MUST contain values specified in [MS-SMB2] section 2.2.13.1.
// PositionInformation (8 bytes): A FILE_POSITION_INFORMATION structure specified in section 2.4.32.
    dword CurrentByteOffset; // Not sure about this (8 bytes):
// ModeInformation (4 bytes): A FILE_MODE_INFORMATION structure specified in section 2.4.24.
    dword Mode;   // (4 bytes): A 32-bit unsigned integer that specifies how the file will subsequently be accessed
// AlignmentInformation (4 bytes): A FILE_ALIGNMENT_INFORMATION structure specified 2.4.3
    dword AlignmentRequirement; //  (4 bytes):  FILE_BYTE_ALIGNMENT 0x00000000 If this value is specified, there are no alignment requirements for the device.
    dword FileNameLength; //
    // Filename
} MSFSCC_ALL_DIRECTORY_INFO;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_MSFSCC_FILE_NETWORK_OPEN_INFORMATION
{
	dword low_creation_time;
	dword high_creation_time;
	dword low_last_access_time;
	dword high_last_access_time;
	dword low_last_write_time;
	dword high_last_write_time;
	dword low_change_time;
	dword high_change_time;
	dword low_allocation_size;
	dword high_allocation_size;
	dword low_end_of_file;
	dword high_end_of_file;
	dword extended_file_attributes;
	dword reserved;
} MSFSCC_FILE_NETWORK_OPEN_INFORMATION;
PACK_PRAGMA_POP




//============================================================================
//    INTERFACE FUNCTION PROTOTYPES
//============================================================================
//============================================================================
//    INTERFACE TRAILING HEADERS
//============================================================================
//****************************************************************************
//**
//**    END HEADER smb2.h
//**
//****************************************************************************
#endif // SMB2_WIREDEFS_H__
