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
#include "client.h"
}

#include "netstreambuffer.hpp"
#include "wireobjects.hpp"

#include <map>
#include <algorithm>
#include <iostream>
using std::cout;
using std::endl;


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
  byte *FixedStructureAddress() { return 0; };
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
