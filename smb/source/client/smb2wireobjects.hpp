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

#include "client.h"
#include "wireobjects.hpp"


#include <map>
#include <algorithm>
#include <iostream>
using std::cout;
using std::endl;


class NetNbssHeader  : public NetWireStruct   {
  public:
   NetNbssHeader() {}
   NetWirebyte       nbss_packet_type;
   NetWire24bitword  nbss_packet_size;
   byte *FixedStructureAddress() { return 0; };
   int  FixedStructureSize()  { return 4; };
   void SetDefaults()  { };
   unsigned char *bindpointers(byte *_raw_address) {
        BindAddressesToBuffer( _raw_address);
        return _raw_address+4;
    }
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};


class NetSmb2Header  : public NetWireStruct   {
public:
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
       BindAddressesToBuffer( _raw_address);
       return _raw_address+64;}
  NetSmb2Header() { }
  int  FixedStructureSize()  { return 64; };
  byte *FixedStructureAddress() { return 0; };
  void SetDefaults()  { };
private:
  void BindAddressOpen(BindNetWireArgs & args) {};
  void BindAddressClose(BindNetWireArgs & args) {};
  void BindAddressesToBuffer(byte *base);
};
#endif // include_smb2wireobjects
