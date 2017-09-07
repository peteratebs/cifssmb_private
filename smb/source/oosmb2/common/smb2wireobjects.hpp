//
// smb2wireobjects.hpp -
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
#ifndef include_smb2wireobjects
#define include_smb2wireobjects

// #include "smb2session.hpp"

// Current layering cant access the session from her
extern ddword getCurrentActiveSession_session_id();


extern "C" {
}

#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001   // When set, indicates that security signatures are enabled on the server.
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002   // When set, indicates that security signatures are required by the server.
#define SMB2_SESSION_FLAG_BINDING         0x01   //  When set, indicates that the request is to bind an existing session to a new connection.

#define SMB2_DIALECT_2002  0x0202
#define SMB2_DIALECT_2100  0x0210
#define SMB2_DIALECT_3000  0x0300
#define SMB2_DIALECT_3002  0x0302
#define SMB2_DIALECT_WILD  0x02FF


/* SMB2 Header structure command values and flag vlues. See  2.2.1.2, page 30 */
#define SMB2_NEGOTIATE          0x0000   // Smartpointer and handler  completed
#define SMB2_SESSION_SETUP      0x0001   // Smartpointer and handler  completed
#define SMB2_LOGOFF             0x0002   // Smartpointer completed
#define SMB2_TREE_CONNECT       0x0003   // Smartpointer and handler  completed
#define SMB2_TREE_DISCONNECT    0x0004   // Smartpointer completed
#define SMB2_CREATE             0x0005   // Smartpointer and handler  completed
#define SMB2_CLOSE              0x0006   // Smartpointer and handler  completed
#define SMB2_FLUSH              0x0007   // Smartpointer and handler  completed
#define SMB2_READ               0x0008   // Smartpointer and handler  completed
#define SMB2_WRITE              0x0009   // Smartpointer and handler  completed
#define SMB2_LOCK               0x000A
#define SMB2_IOCTL              0x000B
#define SMB2_CANCEL             0x000C
#define SMB2_ECHO               0x000D   // Smartpointer and handler  completed
#define SMB2_QUERY_DIRECTORY    0x000E   // Smartpointer and handler  completed
#define SMB2_CHANGE_NOTIFY      0x000F
#define SMB2_QUERY_INFO         0x0010
#define SMB2_SET_INFO           0x0011  // Smartpointer and handler  completed
#define SMB2_OPLOCK_BREAK       0x0012


#define SMB2_FLAGS_SERVER_TO_REDIR              0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND                0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS           0x00000004
#define SMB2_FLAGS_SIGNED                       0x00000008
#define SMB2_FLAGS_DFS_OPERATIONS               0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION             0x20000000


#define SMB2_NT_STATUS_SUCCESS                  0x00000000
#define SMB2_STATUS_INFO_LENGTH_MISMATCH        0xC0000004
#define SMB2_STATUS_NO_MORE_FILES               0x80000006 /* No more files were found that match the file specification. */
#define SMB2_STATUS_INVALID_PARAMETER           0xC000000D /* The parameter specified in the request is not valid. */
#define SMB_NT_STATUS_MORE_PROCESSING_REQUIRED  0xC0000016
#define SMB2_STATUS_NOT_SUPPORTED               0xC00000BB /* The client request is not supported. */



/* RTSMB2_QUERY_DIRECTORY_C.FileInformationClass */
#define SMB2_QUERY_FileDirectoryInformation       0x01  /*  Basic information about a file or directory. Basic information is defined as the file's name, time stamp, size and attributes. File attributes are as specified in [MS-FSCC] section 2.6. */
#define SMB2_QUERY_FileFullDirectoryInformation   0x02  /*  Full information about a file or directory. Full information is defined as all the basic information plus extended attribute size. */
#define SMB2_QUERY_FileIdFullDirectoryInformation 0x26  /*  Full information plus volume file ID about a file or directory. A volume file ID is defined as a number assigned by the underlying object store that uniquely identifies a file within a volume. */
#define SMB2_QUERY_FileBothDirectoryInformation   0x03  /*  Basic information plus extended attribute size and short name about a file or directory. */
#define SMB2_QUERY_FileIdBothDirectoryInformation 0x25  /*  FileBothDirectoryInformation plus volume file ID about a file or directory. */
#define SMB2_QUERY_FileNamesInformation           0x0C  /*  Detailed information on the names of files and directories in a directory. */
/* RTSMB2_QUERY_DIRECTORY_C.Flags */
#define SMB2_QUERY_RESTART_SCANS          0x01     /*  The server MUST restart the enumeration from the beginning, but the search pattern is not changed. */
#define SMB2_QUERY_RETURN_SINGLE_ENTRY    0x02     /*  The server MUST only return the first entry of the search results. */
#define SMB2_QUERY_INDEX_SPECIFIED        0x04     /*  The server SHOULD<64> return entries beginning at the byte number specified by FileIndex. */
#define SMB2_QUERY_REOPEN                 0x10     /*  The server MUST restart the enumeration from the beginning, and the search pattern MUST be changed to the provided value. This often involves silently closing and reopening the directory on the server side. */



class NetNbssHeader  : public NetWireStruct   {
  public:
   NetNbssHeader() {objectsize=4;}
   NetWirebyte       nbss_packet_type;
   NetWire24bitword  nbss_packet_size;
   byte *FixedStructureAddress() { return base_address; };
   const char *command_name() { return "";} // not an smb command so these are bogus
   int   command_id()   { return 0;}
   int  PackedStructureSize()  { return FixedStructureSize(); };
   int  FixedStructureSize()  { return objectsize; };
   void SetDefaults()  { };
   unsigned char *bindpointers(byte *_raw_address) {
        base_address = _raw_address;
        BindAddressesToBuffer( _raw_address);
        return _raw_address+objectsize;
    }
    void push_output(NetStreamOutputBuffer  &StreamBuffer)
    {
      StreamBuffer.add_to_buffer_count( FixedStructureSize());
    }
    void show_contents()
    {
        long psize = nbss_packet_size();
        ddword d=(ddword)FixedStructureAddress();
        diag_printf_fn(DIAG_INFORMATIONAL,"Incoming NetNbssHeader at : %X\n", d);
        diag_printf_fn(DIAG_INFORMATIONAL,"                  Size    : %d\n", psize);
    }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2Header  : public NetWireStruct   {
public:
  NetSmb2Header() {objectsize=64; }
  NetWireblob4 ProtocolId;
  NetWireword StructureSize; // 64
  NetWireword CreditCharge; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
  NetWiredword Status_ChannelSequenceReserved; /*  (4 bytes): */
  NetWireword Command;
  NetWireword CreditRequest_CreditResponse;
  NetWiredword Flags;
  NetWiredword NextCommand;
  NetWireddword MessageId;
  NetWiredword Reserved;
  NetWiredword TreeId;
  NetWireddword SessionId;
  NetWireblob16 Signature;

  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  void InitializeReply(NetSmb2Header &Smb2Header)
  {
    ProtocolId                     = (byte *)Smb2Header.ProtocolId();
    Command                        = Smb2Header.Command();
    CreditCharge                   = Smb2Header.CreditCharge() ;
    Status_ChannelSequenceReserved = Smb2Header.Status_ChannelSequenceReserved() ;
    Command                        = Smb2Header.Command() ;
    CreditRequest_CreditResponse   = Smb2Header.CreditRequest_CreditResponse() ;
    Flags = SMB2_FLAGS_SERVER_TO_REDIR; // Smb2Header.Flags() ;
//    NextCommand = NextCommand.NextCommand() ;
    MessageId                       = Smb2Header.MessageId() ;
    Reserved                        = Smb2Header.Reserved() ;
    TreeId                          = Smb2Header.TreeId() ;
    SessionId                       = Smb2Header.SessionId() ;
//    Signature = Signature.Signature ;
  }
  void Initialize(dword command,ddword mid, ddword _SessionId)
  {
    ProtocolId    =     (byte *)"\xfeSMB";
    StructureSize =     64       ; // 64
    CreditCharge =      0; /* (2 bytes): In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. */
    Status_ChannelSequenceReserved = 0; /*  (4 bytes): */
    Command = command;
    CreditRequest_CreditResponse = 0;
    Flags = 0;         // All client messages are signed
    NextCommand = 0;
    MessageId = mid;
    Reserved = 0;
    TreeId =  0;
    SessionId = _SessionId;
    Signature = (byte *)"IAMTHESIGNATURE";
  }
  const char *command_name() { return "SMB2";} // not an smb command so these are bogus
  int   command_id()   { return 0;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  int  FixedStructureSize()  { return 64; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };

  void push_output(NetStreamOutputBuffer  &StreamBuffer) {  StreamBuffer.add_to_buffer_count( FixedStructureSize()); }
  void show_contents()
  {
    ddword d=(ddword)FixedStructureAddress();
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header At: %X\n", d);
     char c[4]; c[0] = ProtocolId()[1]; c[1] = ProtocolId()[2]; c[2] = ProtocolId()[3]; c[3] = 0;
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header Proto         : %s\n", c );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header size          : %d\n", StructureSize() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header CreditCharge  : %d\n", CreditCharge() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header Status        : %X\n", Status_ChannelSequenceReserved() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header Command       : %d\n", Command() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header CreditResponse: %d\n", CreditRequest_CreditResponse() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header Flags         : %X\n", Flags() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header NextCommand   : %d\n", NextCommand() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header MessageId     : %d\n", MessageId() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header TreeId        : %X\n", TreeId() );
     diag_printf_fn(DIAG_INFORMATIONAL,":::::: NetSmb2Header SessionId     : %llX\n", SessionId() );
  }

private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2NegotiateCmd  : public NetWireStruct   {
public:
  NetSmb2NegotiateCmd() {objectsize=36; }
    NetWireword StructureSize; // 36
    NetWireword DialectCount;
    NetWireword SecurityMode;
    NetWireword Reserved;
    NetWiredword Capabilities;
    NetWireblob16 guid;
    NetWireFileTime ClientStartTime;
    NetWireword Dialect0;
    NetWireword Dialect1;
    NetWireword Dialect2;
    NetWireword Dialect3;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_NEGOTIATE";}
  int   command_id()   { return SMB2_NEGOTIATE;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return 0; };
  void SetDefaults()  { };
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
    StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2NegotiateReply  : public NetWireStruct   {
public:
  NetSmb2NegotiateReply() {objectsize=65; }
    NetWireword StructureSize; // 65
    NetWireword SecurityMode;
    NetWireword DialectRevision;
    NetWireword Reserved;
    NetWireblob16 ServerGuid;
    NetWiredword Capabilities;
    NetWiredword MaxTransactSize;
    NetWiredword MaxReadSize;
    NetWiredword MaxWriteSize;
    NetWireddword SystemTime;
    NetWireddword ServerStartTime;
    NetWireword SecurityBufferOffset;
    NetWireword SecurityBufferLength;
    NetWiredword Reserved2;
    NetWirebyte  SecurityBuffer;      // Variable part starts here

  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_NEGOTIATE";}
  int   command_id()   { return SMB2_NEGOTIATE;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return 0; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2SetupCmd  : public NetWireStruct   {
public:
  NetSmb2SetupCmd() {objectsize=25; }
    NetWireword  StructureSize; // 25
    NetWirebyte  Flags;
    NetWirebyte  SecurityMode;
    NetWiredword Capabilities;
    NetWiredword Channel;
    NetWireword SecurityBufferOffset;
    NetWireword  SecurityBufferLength;
    NetWireddword PreviousSessionId;
    NetWirebyte  Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  int VariableContentOffset()  { return (int)SecurityBufferOffset(); }
  const char *command_name() { return "SMB2_SESSION_SETUP";}
  int   command_id()   { return SMB2_SESSION_SETUP;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2SetupReply  : public NetWireStruct   {
public:
  NetSmb2SetupReply() {objectsize=9; }
    NetWireword  StructureSize; // 9
    NetWireword  SessionFlags;
    NetWireword  SecurityBufferOffset;
    NetWireword  SecurityBufferLength;
    NetWirebyte  Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}

  const char *command_name() { return "SMB2_SESSION_SETUP";}
  int   command_id()   { return SMB2_SESSION_SETUP;}
  int  PackedStructureSize()   { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2TreeconnectCmd  : public NetWireStruct   {
public:
  NetSmb2TreeconnectCmd() {objectsize=9; }
  NetWireword  StructureSize; // 9
  NetWireword  Reserved;
  NetWireword  PathOffset;
  NetWireword  PathLength;
  NetWirebyte  Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  int VariableContentOffset() { return PackedStructureSize(); };
  const char *command_name() { return "SMB2_TREE_CONNECT";}
  int   command_id()   { return SMB2_TREE_CONNECT;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  void copyto_variable_content(void *pcontent, int content_size)
  {
     addto_variable_content(content_size);  // we have to do this
     memcpy(FixedStructureAddress()+VariableContentOffset(), pcontent, content_size);
  }

private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2TreeconnectReply  : public NetWireStruct   {
public:
  NetSmb2TreeconnectReply() {objectsize=16; }
  NetWireword  StructureSize;
  NetWirebyte  ShareType;
  NetWirebyte  Reserved;
  NetWiredword ShareFlags;
  NetWiredword Capabilities;
  NetWiredword MaximalAccess;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_TREE_CONNECT";}
  int   command_id()   { return SMB2_TREE_CONNECT;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


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

class NetSmb2CreateCmd  : public NetWireStruct   {
public:
  NetSmb2CreateCmd() {objectsize=57; }
  NetWireword  StructureSize; // 57
  NetWirebyte  SecurityFlags;
  NetWirebyte  RequestedOplockLevel;
  NetWiredword ImpersonationLevel;
  NetWireddword SmbCreateFlags;
  NetWireblob8 Reserved;
  NetWiredword DesiredAccess;
  NetWiredword FileAttributes;
  NetWiredword ShareAccess;
  NetWiredword CreateDisposition;
  NetWiredword CreateOptions;
  NetWireword  NameOffset;
  NetWireword  NameLength;
  NetWiredword CreateContextsOffset;
  NetWiredword CreateContextsLength;
  NetWirebyte  Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  int VariableContentOffset() { return PackedStructureSize(); };
  const char *command_name() { return "SMB2_CREATE";}
  int   command_id()   { return SMB2_CREATE;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  void copyto_variable_content(void *pcontent, int content_size)
  {
     addto_variable_content(content_size);  // we have to do this
     memcpy(FixedStructureAddress()+VariableContentOffset(), pcontent, content_size);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

/* Note sections 2.2.14.2 contains several create contexts that extend create response
    Create contexts are defined in another file
*/
class NetSmb2CreateReply  : public NetWireStruct   {
public:
  NetSmb2CreateReply() {objectsize=0x59; }
  NetWireword  StructureSize;
  NetWirebyte  OplockLevel;
  NetWirebyte  Flags;
  NetWiredword CreateAction;
  NetWireFileTime CreationTime;
  NetWireFileTime LastAccessTime;
  NetWireFileTime LastWriteTime;
  NetWireFileTime ChangeTime;
  NetWireddword   AllocationSize;
  NetWireddword   EndofFile;
  NetWiredword    FileAttributes;
  NetWiredword    Reserved2;
  NetWireFileId   FileId;
  NetWiredword    CreateContextsOffset;
  NetWiredword    CreateContextsLength;
  NetWirebyte     Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_CREATE";}
  int   command_id()   { return SMB2_CREATE;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2DisconnectCmd  : public NetWireStruct   {
public:
  NetSmb2DisconnectCmd() {objectsize=4; }
  NetWireword  StructureSize; // 4
  NetWireword  Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_TREE_DISCONNECT";}
  int   command_id()   { return SMB2_TREE_DISCONNECT;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2DisconnectReply  : public NetWireStruct   {
public:
  NetSmb2DisconnectReply() {objectsize=4; }
  NetWireword  StructureSize; // 4
  NetWireword  Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_TREE_DISCONNECT";}
  int   command_id()   { return SMB2_TREE_DISCONNECT;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2LogoffCmd  : public NetWireStruct   {
public:
  NetSmb2LogoffCmd() {objectsize=4; }
  NetWireword  StructureSize; // 4
  NetWireword  Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_LOGOFF";}
  int   command_id()   { return SMB2_LOGOFF;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2LogoffReply  : public NetWireStruct   {
public:
  NetSmb2LogoffReply() {objectsize=4; }
  NetWireword  StructureSize; // 4
  NetWireword  Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_LOGOFF";}
  int   command_id()   { return SMB2_LOGOFF;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB 0x0001
class NetSmb2CloseCmd  : public NetWireStruct   {
public:
    NetSmb2CloseCmd() {objectsize=24; }
    NetWireword  StructureSize; // 24
    NetWireword  Flags;
    NetWiredword Reserved;
    NetWireFileId   FileId;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_CLOSE";}
  int   command_id()   { return SMB2_CLOSE;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2CloseReply  : public NetWireStruct   {
public:
  NetSmb2CloseReply() {objectsize=60; }
  NetWireword  StructureSize; // 60
  NetWireword  Flags;
  NetWiredword Reserved;
  NetWireFileTime CreationTime;
  NetWireFileTime LastAccessTime;
  NetWireFileTime LastWriteTime;
  NetWireFileTime ChangeTime;
  NetWireddword AllocationSize;
  NetWireddword EndofFile;
  NetWiredword  FileAttributes;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_CLOSE";}
  int   command_id()   { return SMB2_CLOSE;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2SetinfoCmd  : public NetWireStruct   {
public:
    NetSmb2SetinfoCmd() {objectsize=33; }
    NetWireword    StructureSize; // 33
    NetWirebyte    InfoType;
    NetWirebyte    FileInfoClass;
    NetWiredword   BufferLength;
    NetWireword    BufferOffset;
    NetWireword    Reserved;
    NetWiredword   AdditionalInformation;
    NetWireFileId  FileId;
    NetWirebyte    Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_SET_INFO";}
  int   command_id()   { return SMB2_SET_INFO;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  byte *VariableContentAddress() { return base_address+PackedStructureSize(); };
  void copyto_variable_content(void *pcontent, int content_size)
  {
     addto_variable_content(content_size);  // we have to do this
     memcpy(FixedStructureAddress()+BufferOffset(), pcontent, content_size);
  }
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2RenameInfoType2  : public NetWireStruct   {
public:
    NetSmb2RenameInfoType2() {objectsize=21; }
    NetWirebyte    ReplaceIfExists;
    NetWireblob7   Reserved;
    NetWireddword  RootDirectory;
    NetWiredword   FileNameLength;  // Bytes
    NetWirebyte    Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_SET_INFO";}
  int   command_id()   { return SMB2_SET_INFO;}
  int  PackedStructureSize()  {   return FixedStructureSize()-1; };
  byte *VariableContentAddress() { return base_address+PackedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults() { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};



class NetSmb2SetinfoReply  : public NetWireStruct   {
public:
    NetSmb2SetinfoReply() {objectsize=2; }
    NetWireword    StructureSize; // 2
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_SET_INFO";}
  int   command_id()   { return SMB2_SET_INFO;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

/// Minimum possible reply NBSS:SMB:THIS (too bad the designers didn't include the command in the reply)
class NetSmb2MinimumReply  : public NetWireStruct   {
public:
    NetSmb2MinimumReply() {objectsize=2; }
    NetWireword    StructureSize; // 2
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "MINIMUM";}
  int   command_id()   { return 0;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2QuerydirectoryCmd  : public NetWireStruct   {
public:
  NetSmb2QuerydirectoryCmd() {objectsize=33; }
  NetWireword  StructureSize; // 33
  NetWirebyte    FileInformationClass;
  NetWirebyte    Flags;
  NetWiredword   FileIndex;
  NetWireblob16  FileId;
  NetWireword    FileNameOffset;
  NetWireword    FileNameLength;
  NetWiredword   OutputBufferLength;
  NetWirebyte    Buffer;

  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}

  void copyto_variable_content(void *pcontent, int content_size)
  {
     addto_variable_content(content_size);  // we have to do this
     memcpy(FixedStructureAddress()+VariableContentOffset(), pcontent, content_size);
  }

  int  VariableContentOffset() { return PackedStructureSize(); }
  const char *command_name() { return "SMB2_QUERY_DIRECTORY";}
  int   command_id()   { return SMB2_QUERY_DIRECTORY;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2QuerydirectoryReply  : public NetWireStruct   {
public:
  NetSmb2QuerydirectoryReply() {objectsize=9; }
  NetWireword    StructureSize; // 9
  NetWireword    OutputBufferOffset;
  NetWiredword   OutputBufferLength;
  NetWirebyte    Buffer;

  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_QUERY_DIRECTORY";}
  int   command_id()   { return SMB2_QUERY_DIRECTORY;}
  int  PackedStructureSize() { return FixedStructureSize()-1; }
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2FlushCmd  : public NetWireStruct   {
public:
  NetSmb2FlushCmd() {objectsize=24; }
  NetWireword  StructureSize; // 24
  NetWireword  Reserved1;
  NetWiredword Reserved2;
  NetWireFileId FileId;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_FLUSH";}
  int   command_id()   { return SMB2_FLUSH;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2FlushReply  : public NetWireStruct   {
public:
  NetSmb2FlushReply() {objectsize=4; }
  NetWireword  StructureSize; // 4
  NetWireword  Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}

  const char *command_name() { return "SMB2_FLUSH";}
  int   command_id()   { return SMB2_FLUSH;}
  int  PackedStructureSize()   { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2ReadCmd  : public NetWireStruct   {
public:
  NetSmb2ReadCmd() {objectsize=49; }
  NetWireword    StructureSize; // 49
  NetWirebyte    Padding;
  NetWirebyte    Flags;
  NetWiredword   Length;
  NetWireddword  Offset;
  NetWireFileId  FileId;
  NetWiredword   MinimumCount;
  NetWiredword   Channel;
  NetWiredword   RemainingBytes;
  NetWireword    ReadChannelInfoOffset;
  NetWireword    ReadChannelInfoLength;
  NetWirebyte    Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_READ";}
  int   command_id()   { return SMB2_READ;}
  int  VariableContentOffset() { return PackedStructureSize(); }
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  void copyto_variable_content(void *pcontent, int content_size)
  {
     addto_variable_content(content_size);  // we have to do this
     memcpy(FixedStructureAddress()+VariableContentOffset(), pcontent, content_size);
  }
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2ReadReply  : public NetWireStruct   {
public:
  NetSmb2ReadReply() {objectsize=17; }
  NetWireword  StructureSize; // 17
  NetWireword  DataOffset;
  NetWiredword DataLength;
  NetWiredword DataRemaining;
  NetWiredword Reserved;
  NetWirebyte  Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}

  const char *command_name() { return "SMB2_READ";}
  int   command_id()   { return SMB2_READ;}
  int  PackedStructureSize()   { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


#define SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002

class NetSmb2WriteCmd  : public NetWireStruct   {
public:
  NetSmb2WriteCmd() {objectsize=49; }
  NetWireword    StructureSize; // 49
  NetWireword    DataOffset;
  NetWiredword   Length;
  NetWireddword  Offset;
  NetWireFileId  FileId;
  NetWiredword   Channel;
  NetWiredword   RemainingBytes;
  NetWireword    WriteChannelInfoOffset;
  NetWireword    WriteChannelInfoLength;
  NetWiredword   Flags;
  NetWirebyte    Buffer;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_WRITE";}
  int   command_id()   { return SMB2_WRITE;}
  int  PackedStructureSize()  { return FixedStructureSize()-1; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  int  VariableContentOffset() { return PackedStructureSize(); }
  void copyto_variable_content(void *pcontent, int content_size)
  {
     addto_variable_content(content_size);  // we have to do this
     memcpy(FixedStructureAddress()+VariableContentOffset(), pcontent, content_size);
  }
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2WriteReply  : public NetWireStruct   {
public:
  NetSmb2WriteReply() {objectsize=17; }
   NetWireword  StructureSize; // 17
   NetWireword  Reserved;
   NetWiredword Count;
   NetWiredword Remaining;
   NetWireword  WriteChannelInfoOffset;
   NetWireword  WriteChannelInfoLength;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}

  const char *command_name() { return "SMB2_WRITE";}
  int   command_id()   { return SMB2_WRITE;}
  int  PackedStructureSize()   { return 16; }; // the actual size is 16 but it will be 17 in the header
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2EchoCmd  : public NetWireStruct   {
public:
  NetSmb2EchoCmd() {objectsize=4; }
  NetWireword    StructureSize; // 4
  NetWireword    Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_ECHO";}
  int   command_id()   { return SMB2_ECHO;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  int  VariableContentOffset() { return PackedStructureSize(); }
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

class NetSmb2EchoReply  : public NetWireStruct   {
public:
  NetSmb2EchoReply() {objectsize=4; }
   NetWireword  StructureSize; // 4
   NetWireword  Reserved;
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
  const char *command_name() { return "SMB2_ECHO";}
  int   command_id()   { return SMB2_ECHO;}
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

#endif // include_smb2wireobjects
