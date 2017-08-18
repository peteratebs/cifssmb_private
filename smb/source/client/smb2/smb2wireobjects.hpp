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

extern "C" {
}

#define SMB2_NEGOTIATE_SIGNING_ENABLED  0x0001   // When set, indicates that security signatures are enabled on the server.
#define SMB2_NEGOTIATE_SIGNING_REQUIRED 0x0002   // When set, indicates that security signatures are required by the server.
#define SMB2_SESSION_FLAG_BINDING       0x01     //  When set, indicates that the request is to bind an existing session to a new connection.

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


#define SMB2_NT_STATUS_SUCCESS                  0x00000000
#define SMB2_STATUS_INFO_LENGTH_MISMATCH        0xC0000004
#define SMB2_STATUS_NO_MORE_FILES               0x80000006 /* No more files were found that match the file specification. */
#define SMB_NT_STATUS_MORE_PROCESSING_REQUIRED  0xC0000016




/* RTSMB2_QUERY_DIRECTORY_C.FileInformationClass */
#define SMB2_QUERY_FileDirectoryInformation 0x01        /*  Basic information about a file or directory. Basic information is defined as the file's name, time stamp, size and attributes. File attributes are as specified in [MS-FSCC] section 2.6. */
#define SMB2_QUERY_FileFullDirectoryInformation 0x02    /*  Full information about a file or directory. Full information is defined as all the basic information plus extended attribute size. */
#define SMB2_QUERY_FileIdFullDirectoryInformation 0x26  /*  Full information plus volume file ID about a file or directory. A volume file ID is defined as a number assigned by the underlying object store that uniquely identifies a file within a volume. */
#define SMB2_QUERY_FileBothDirectoryInformation 0x03    /*  Basic information plus extended attribute size and short name about a file or directory. */
#define SMB2_QUERY_FileIdBothDirectoryInformation 0x25  /*  FileBothDirectoryInformation plus volume file ID about a file or directory. */
#define SMB2_QUERY_FileNamesInformation 0x0C            /*  Detailed information on the names of files and directories in a directory. */
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
   int  FixedStructureSize()  { return objectsize; };
   void SetDefaults()  { };
   unsigned char *bindpointers(byte *_raw_address) {
        base_address = _raw_address;
        BindAddressesToBuffer( _raw_address);
        return _raw_address+objectsize;
    }
    NetStatus push_output(NetStreamOutputBuffer  &StreamBuffer)
    {
     return StreamBuffer.push_to_buffer(base_address, objectsize);
    }
    void show_contents()
    {
        long psize = nbss_packet_size();
        ddword d=(ddword)FixedStructureAddress();
        cout << ":::::: Incoming NetNbssHeader at : " << std::hex << d << endl;
        cout << "::::::::: of Size: " << std::dec << psize << endl;
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
    Flags = 0;
    NextCommand = 0;
    MessageId = mid;
    Reserved = 0;
    TreeId =  0;
    SessionId = _SessionId;
    Signature = (byte *)"IAMTHESIGNATURE";
  }
  int  FixedStructureSize()  { return 64; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };

  NetStatus push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
    return StreamBuffer.push_to_buffer(base_address, FixedStructureSize());
  }
  void show_contents()
  {
    ddword d=(ddword)FixedStructureAddress();
     cout << ":::::: NetSmb2Header At: " << std::hex << d << endl;
    char c[4]; c[0] = ProtocolId()[1]; c[1] = ProtocolId()[2]; c[2] = ProtocolId()[3]; c[3] = 0;
     cout << ":::::: NetSmb2Header Proto         : " <<  ProtocolId() << endl;
     cout << ":::::: NetSmb2Header size          : " << StructureSize() << endl;
     cout << ":::::: NetSmb2Header CreditCharge  : " << CreditCharge() << endl;
     cout << ":::::: NetSmb2Header Status        : " << Status_ChannelSequenceReserved() << endl;
     cout << ":::::: NetSmb2Header Command       : " << Command() << endl;
     cout << ":::::: NetSmb2Header CreditResponse: " << CreditRequest_CreditResponse() << endl;
     cout << ":::::: NetSmb2Header Flags         : " << std::hex << Flags() << std::dec << endl;
     cout << ":::::: NetSmb2Header NextCommand   : " << NextCommand() << endl;
     cout << ":::::: NetSmb2Header MessageId     : " << MessageId() << endl;
     cout << ":::::: NetSmb2Header TreeId        : " << TreeId() << endl;
     cout << ":::::: NetSmb2Header SessionId     : " << SessionId() << endl;
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
  byte *FixedStructureAddress() { return 0; };
  void SetDefaults()  { };
  NetStatus push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   return StreamBuffer.push_to_buffer(base_address, objectsize+variablesize);
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
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  NetStatus push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
   return StreamBuffer.push_to_buffer(base_address, objectsize+variablesize);
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
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
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
  NetSmb2NBSSReply(word command, NetStreamInputBuffer &_ReplyBuffer, NetNbssHeader  &_nbss, NetSmb2Header   &_smb2,  T &_reply)
  {
    ReplyBuffer=&_ReplyBuffer; nbss =&_nbss;   smb2 =&_smb2;  reply  =&_reply ;
    isvariable = false; base_address=0; variablesize=0;
    dword bytes_ready;
    byte *nbsshead =  ReplyBuffer->buffered_data_pointer(bytes_ready);
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail =   bindpointers(nbsshead);
    status=RTSMB_CLI_SSN_RV_OK;
  }
  int status;
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  reply->FixedStructureSize();};
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize;};
  NetStatus push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
    return StreamBuffer.push_to_buffer(base_address, objectsize+variablesize);
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
     T                  *reply;
     NetStreamInputBuffer    *ReplyBuffer;
     NetNbssHeader       *nbss;
     NetSmb2Header       *smb2;
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

template <class T>
class NetSmb2NBSSCmd {
public:
  int status;
  NetSmb2NBSSCmd(word command, NetStreamOutputBuffer &_SendBuffer, NetNbssHeader  &_nbss, NetSmb2Header   &_smb2,  T &_cmd, dword _variable_size=0)
  {
    SendBuffer=&_SendBuffer; nbss =&_nbss;   smb2 =&_smb2;  cmd  =&_cmd ;
    isvariable = false; base_address=0; variablesize=_variable_size;
    dword bytes_available_for_sending;
    byte *nbsshead = SendBuffer->output_buffer_address(bytes_available_for_sending);
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail = bindpointers(nbsshead);
    cmdtail  += _variable_size;   // Add in 2 variable words, not good

    nbss->nbss_packet_type = RTSMB_NBSS_COM_MESSAGE;
    nbss->nbss_packet_size = PDIFF(cmdtail,nbsstail);
    ddword SessionId = 0;

    status = RTSMB_CLI_SSN_RV_OK;
    smb2->Initialize(command,(ddword) SendBuffer->stream_buffer_mid, SessionId);

    if (nbss->push_output(*SendBuffer) != NetStatusOk)   // nbss to buffer in net byte order
      status = RTSMB_CLI_SSN_RV_DEAD;
    if (smb2->push_output(*SendBuffer) != NetStatusOk)   // smb header to buffer in net byte order
      status = RTSMB_CLI_SSN_RV_DEAD;
  }
  void flush()
  {
    if (SendBuffer->push_output()==NetStatusOk)
      status=RTSMB_CLI_SSN_RV_SENT;
    else
      status=RTSMB_CLI_SSN_RV_DEAD;
  }
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  cmd->FixedStructureSize();}
  byte *RangeRequiringSigning(size_t &length)  { length = variablesize + smb2->FixedStructureSize()+cmd->FixedStructureSize();return smb2->FixedStructureAddress();}
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize; };
  NetStatus push_output(NetStreamOutputBuffer  &StreamBuffer)
  {
    return StreamBuffer.push_to_buffer(base_address, objectsize+variablesize);
  }
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       byte *nbsshead = _raw_address;
       byte *nbsstail =nbss->bindpointers(nbsshead);
       byte *smbtail = smb2->bindpointers(nbsstail);
       byte *cmdtail = cmd->bindpointers(smbtail);
       return _raw_address+FixedStructureSize();}
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };
  private:
     T                  *cmd;
     NetStreamOutputBuffer  *SendBuffer;
     NetNbssHeader          *nbss;
     NetSmb2Header          *smb2;
     byte *base_address;
     bool isvariable;
     dword objectsize;
     dword variablesize;
};
