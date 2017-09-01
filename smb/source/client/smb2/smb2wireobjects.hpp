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

// Cuurent layering cant access the session from her
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


#define SMB2_FLAGS_SERVER_TO_REDIR              0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND                0x00000002
#define SMB2_FLAGS_RELATED_OPERATIONS           0x00000004
#define SMB2_FLAGS_SIGNED                       0x00000008
#define SMB2_FLAGS_DFS_OPERATIONS               0x10000000
#define SMB2_FLAGS_REPLAY_OPERATION             0x20000000


#define SMB2_NT_STATUS_SUCCESS                  0x00000000
#define SMB2_STATUS_INFO_LENGTH_MISMATCH        0xC0000004
#define SMB2_STATUS_NO_MORE_FILES               0x80000006 /* No more files were found that match the file specification. */
#define SMB_NT_STATUS_MORE_PROCESSING_REQUIRED  0xC0000016




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
#endif // include_smb2wireobjects


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
  int  PackedStructureSize()  { return FixedStructureSize(); };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

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
  const char *command_name() {return "CLOSE";}
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       BindAddressesToBuffer( _raw_address);
       return _raw_address+FixedStructureSize();}
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
  int  PackedStructureSize() { return FixedStructureSize()-1; }
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};

template <class T>
class NetSmb2NBSSReply {
public:
  NetSmb2NBSSReply(word command, Smb2Session  *_pSmb2Session, NetNbssHeader  &_nbss, NetSmb2Header   &_smb2,  T &_reply)
  {
    pSmb2Session=_pSmb2Session; nbss =&_nbss;   smb2 =&_smb2;  reply  =&_reply ;
    isvariable = false; base_address=0; variablesize=0;
    smb2_command = command;
    dword bytes_ready;
    byte *nbsshead =  pSmb2Session->ReplyBuffer.buffered_data_pointer(bytes_ready);
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail =   bindpointers(nbsshead);
  }
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  reply->FixedStructureSize();};
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize;};
  void push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
    StreamBuffer.add_to_buffer_count(objectsize+variablesize);
  }
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       byte *nbsshead = _raw_address; // Was this in earklier build. ReplyBuffer->session_wire_incoming_nbss_header;
       byte *nbsstail =nbss->bindpointers(nbsshead);
       byte *smbtail = smb2->bindpointers(nbsstail);
       byte *replytail = reply->bindpointers(smbtail);
       return _raw_address+FixedStructureSize();}
  byte *FixedStructureAddress() { return base_address; };

  private:
     T                     *reply;
     Smb2Session           *pSmb2Session;
     NetNbssHeader         *nbss;
     NetSmb2Header         *smb2;
     word                   smb2_command;
     byte *base_address;
     bool isvariable;
     dword objectsize;
     dword variablesize;
};




///    Template class for generating frames of nbssheader:smb2:<commandtype>
///      Template helps fills out the nbss and smb2 headers in the buffer and also helps send the buffer.
//       The specific cmd is exposed for populating
///   See _rtsmb2_cli_session_send_negotiate() for an example
///     Requires specific prolog usage in a funtions:
///      dword variable_content_size = (dword)2*sizeof(word);   optional arg defaults to zero
///      NetNbssHeader       OutNbssHeader;     Nsss and smb2 declarations are always the same
///      NetSmb2Header       OutSmb2Header;
///      NetSmb2NegotiateCmd Smb2NegotiateCmd;  The command to be templated.
///      NetSmb2NBSSCmd<NetSmb2NegotiateCmd> Smb2NBSSCmd(SMB2_NEGOTIATE, SendBuffer,OutNbssHeader,OutSmb2Header, Smb2NegotiateCmd, variable_content_size);

bool checkSessionSigned();


template <class T>
class NetSmb2NBSSCmd {
public:
//  int status;
  NetSmb2NBSSCmd(word command, Smb2Session  *_pSmb2Session, NetNbssHeader  &_nbss, NetSmb2Header &_smb2,  T &_cmd, dword _variable_size=0)
  {
    pSmb2Session = _pSmb2Session; nbss =&_nbss;   smb2 =&_smb2;  cmd  =&_cmd ;
    isvariable = false; base_address=0; variablesize=_variable_size;
    smb2_command = command;

    pSmb2Session->PrepSessionForCommand(); // Drain inp and output buffers to start a new command

    dword bytes_available_for_sending;
    byte *nbsshead = pSmb2Session->SendBuffer.output_buffer_address(bytes_available_for_sending);
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail = bindpointers(nbsshead);
    cmdtail  += _variable_size;   // Add in 2 variable words, not good

    nbss->nbss_packet_type = RTSMB_NBSS_COM_MESSAGE;
    nbss->nbss_packet_size = PDIFF(cmdtail,nbsstail);
    ddword SessionId = getCurrentActiveSession_session_id(); // getCurrentActiveSession()->session_server_info_smb2_session_id;

    if (smb2_command == SMB2_NEGOTIATE)
      pSmb2Session->SendBuffer.stream_buffer_mid = pSmb2Session->unconnected_message_id();
    else
      pSmb2Session->SendBuffer.stream_buffer_mid = pSmb2Session->next_message_id();
    smb2->Initialize(command,(ddword) pSmb2Session->SendBuffer.stream_buffer_mid, SessionId);

    // Sign the message is signing is enabe and it should be signed (>= SMB2_TREE_CONNECT should be correct since we don't support encrypted voumes
    if (smb2_command >= SMB2_TREE_CONNECT && checkSessionSigned())
    {
       dword Flags = smb2->Flags();
       Flags += SMB2_FLAGS_SIGNED;
       smb2->Flags = Flags;
    }

    nbss->push_output(pSmb2Session->SendBuffer);   // account for sizes in the buffer
    smb2->push_output(pSmb2Session->SendBuffer);
  }
  bool flush()
  {
    pSmb2Session->update_timestamp();
    cmd->push_output(pSmb2Session->SendBuffer);
    byte signature[16];
    if (checkSessionSigned())
    {
      size_t length=0;
      byte *signme = RangeRequiringSigning(length);
      calculate_smb2_signing_key((void *)pSmb2Session->session_key(), (void *)signme, length, (unsigned char *)signature);
//     memset (signature, 0xaa , 16);
    }
    else
     memset (signature, 0 , 16);
    smb2->Signature = signature;

    bool r=true;
    NetStatus Status = pSmb2Session->SendBuffer.flush_output();
    if (Status !=NetStatusOk)
    {
      setSessionSocketError(pSmb2Session , true, NetStatusDeviceSendFailed);
      pSmb2Session->diag_text_warning("Socket error sending message:%d status:%d",smb2_command,Status);
      r=false;
    }
    return r;
  }
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  cmd->FixedStructureSize();}
  byte *RangeRequiringSigning(size_t &length)  { length = variablesize + smb2->FixedStructureSize()+cmd->FixedStructureSize();return smb2->FixedStructureAddress();}
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize; };
  void push_output(NetStreamOutputBuffer  &StreamBuffer) { StreamBuffer.add_to_buffer_count(objectsize+variablesize); }
  unsigned char *bindpointers(byte *_raw_address) {
       memset(_raw_address, 0, FixedStructureSize()); // uninitialized fields default to zero
       base_address = _raw_address;
       byte *nbsshead = _raw_address;
       byte *nbsstail =nbss->bindpointers(nbsshead);
       byte *smbtail = smb2->bindpointers(nbsstail);
       byte *cmdtail = cmd->bindpointers(smbtail);
       return _raw_address+FixedStructureSize();}
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  private:
     Smb2Session            *pSmb2Session;
     word                   smb2_command;
     T                      *cmd;
     NetNbssHeader          *nbss;
     NetSmb2Header          *smb2;
     byte *base_address;
     bool isvariable;
     dword objectsize;
     dword variablesize;
};
