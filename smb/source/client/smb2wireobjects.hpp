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

#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "smb2utils.hpp"


class NetNbssHeader  : public NetWireStruct   {
  public:
   NetNbssHeader() {objectsize=4;}
   NetWirebyte       nbss_packet_type;
   NetWire24bitword  nbss_packet_size;
   byte *FixedStructureAddress() { return 0; };
   int  FixedStructureSize()  { return objectsize; };
   void SetDefaults()  { };
   unsigned char *bindpointers(byte *_raw_address) {
        base_address = _raw_address;
        BindAddressesToBuffer( _raw_address);
        return _raw_address+objectsize;
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
  void Initialize(dword command,ddword mid, ddword SessionId)
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
    SessionId = SessionId;
    Signature = (byte *)"IAMTHESIGNATURE";
  }
  int  FixedStructureSize()  { return 64; };
  byte *FixedStructureAddress() { return base_address; };
  void SetDefaults()  { };

  NetStatus push_output(NetStreamBuffer  &StreamBuffer)
  {
    return StreamBuffer.push_output(base_address, FixedStructureSize());
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
  NetSmb2NBSSReply(word command, NetStreamBuffer &_ReplyBuffer, NetNbssHeader  &_nbss, NetSmb2Header   &_smb2,  T &_reply)
  {
    ReplyBuffer=&_ReplyBuffer; nbss =&_nbss;   smb2 =&_smb2;  reply  =&_reply ;
    isvariable = false; base_address=0; variablesize=0;
    byte *nbsshead =  ReplyBuffer->peek_input();
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail =   bindpointers(nbsshead);

    status=RTSMB_CLI_SSN_RV_OK;


//    if (nbss->push_output(*ReplyBuffer) != NetStatusOk)
//      status = RTSMB_CLI_SSN_RV_DEAD;
//    if (smb2->push_output(*ReplyBuffer) != NetStatusOk)
//      status = RTSMB_CLI_SSN_RV_DEAD;


//    if (nbss->pull_output(*SendBuffer) != NetStatusOk)
//      status = RTSMB_CLI_SSN_RV_DEAD;
//    if (smb2->pull_output(*SendBuffer) != NetStatusOk)
//      status = RTSMB_CLI_SSN_RV_DEAD;

  }
  int status;
  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  reply->FixedStructureSize();};
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize;};
  NetStatus push_output(NetStreamBuffer  &StreamBuffer)
  {
    return StreamBuffer.push_output(base_address, objectsize+variablesize);
  }
  unsigned char *bindpointers(byte *_raw_address) {
       base_address = _raw_address;
       byte *nbsshead = ReplyBuffer->session_pStream()->pSession->wire.incoming_nbss_header;
       byte *nbsstail =nbss->bindpointers(nbsshead);
       byte *smbtail = smb2->bindpointers(base_address);
       byte *replytail = reply->bindpointers(smbtail);
       ReplyBuffer->attach_nbss(nbss->nbss_packet_size());     // Log the size of the new frame
       return _raw_address+FixedStructureSize();}
  byte *FixedStructureAddress() { return base_address; };

  private:
     T                  *reply;
     NetStreamBuffer    *ReplyBuffer;
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
  NetSmb2NBSSCmd(word command, NetStreamBuffer &_SendBuffer, NetNbssHeader  &_nbss, NetSmb2Header   &_smb2,  T &_cmd, dword _variable_size=0)
  {
    SendBuffer=&_SendBuffer; nbss =&_nbss;   smb2 =&_smb2;  cmd  =&_cmd ;
    isvariable = false; base_address=0; variablesize=_variable_size;
    byte *nbsshead = SendBuffer->peek_input();
    byte *nbsstail  = nbsshead+4;
    byte *cmdtail = bindpointers(nbsshead);
    cmdtail  += _variable_size;   // Add in 2 variable words, not good

    nbss->nbss_packet_type = RTSMB_NBSS_COM_MESSAGE;
    nbss->nbss_packet_size = PDIFF(cmdtail,nbsstail);
    ddword SessionId = 0;

    status = RTSMB_CLI_SSN_RV_OK;
    smb2->Initialize(command,(ddword) SendBuffer->session_pStream()->pBuffer->mid, SessionId);

    if (nbss->push_output(*SendBuffer) != NetStatusOk)
      status = RTSMB_CLI_SSN_RV_DEAD;
    if (smb2->push_output(*SendBuffer) != NetStatusOk)
      status = RTSMB_CLI_SSN_RV_DEAD;

  }
  int status;
  void flush() {
    if (rtsmb_cli_wire_smb2_iostream_flush_sendbufferptr(SendBuffer)==0)
      status=RTSMB_CLI_SSN_RV_SENT;
    else
      status=RTSMB_CLI_SSN_RV_DEAD;

  }

  // Cloned from NetWireStruct()
  int  FixedStructureSize()  { return nbss->FixedStructureSize() + smb2->FixedStructureSize() +  cmd->FixedStructureSize();};
  void addto_variable_content(dword delta_variablesize) {variablesize += delta_variablesize; };
  NetStatus push_output(NetStreamBuffer  &StreamBuffer)
  {
    return StreamBuffer.push_output(base_address, objectsize+variablesize);
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
     NetStreamBuffer    *SendBuffer;
     NetNbssHeader       *nbss;
     NetSmb2Header       *smb2;
     byte *base_address;
     bool isvariable;
     dword objectsize;
     dword variablesize;
};
