//
// smb2wireobjects.cpp -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2018
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  SMB2 client session level interface
//
#include "smb2defs.hpp"
#include "smb2socks.hpp"
#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "smb2wireobjects.hpp"
#include "mswireobjects.hpp"
#include "smb2session.hpp"
#include "smb2socks.hpp"



void NetNbssHeader::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(nbss_packet_type);
  BINDPOINTERS(nbss_packet_size);
}

void NetSmb2Header::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(ProtocolId);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(CreditCharge);
  BINDPOINTERS(Status_ChannelSequenceReserved);
  BINDPOINTERS(Command);
  BINDPOINTERS(CreditRequest_CreditResponse);
  BINDPOINTERS(Flags);
  BINDPOINTERS(NextCommand);
  BINDPOINTERS(MessageId);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(TreeId);
  BINDPOINTERS(SessionId);
  BINDPOINTERS(Signature);
}

void NetSmb2NegotiateCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 36
  BINDPOINTERS(DialectCount);
  BINDPOINTERS(SecurityMode);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(Capabilities);
  BINDPOINTERS(guid);
  BINDPOINTERS(ClientStartTime);
  // Variable number of arguments right after the fixed section behaves the same as fixed
  BINDPOINTERS(Dialect0);
  BINDPOINTERS(Dialect1);
  BINDPOINTERS(Dialect2);
  BINDPOINTERS(Dialect3);
}

void NetSmb2NegotiateReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 65
  BINDPOINTERS(SecurityMode);
  BINDPOINTERS(DialectRevision);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(ServerGuid);
  BINDPOINTERS(Capabilities);
  BINDPOINTERS(MaxTransactSize);
  BINDPOINTERS(MaxReadSize);
  BINDPOINTERS(MaxWriteSize);
  BINDPOINTERS(SystemTime);
  BINDPOINTERS(ServerStartTime);
  BINDPOINTERS(SecurityBufferOffset);
  BINDPOINTERS(SecurityBufferLength);
  BINDPOINTERS(Reserved2);
  BINDPOINTERS(SecurityBuffer);      // Variable part starts here
}

void NetSmb2SetupCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 25
  BINDPOINTERS(Flags);
  BINDPOINTERS(SecurityMode);
  BINDPOINTERS(Capabilities);
  BINDPOINTERS(Channel);
  BINDPOINTERS(SecurityBufferOffset);
  BINDPOINTERS(SecurityBufferLength);
  BINDPOINTERS(PreviousSessionId);
  BINDPOINTERS(Buffer);
}

void NetSmb2SetupReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 9
  BINDPOINTERS(SessionFlags);
  BINDPOINTERS(SecurityBufferOffset);
  BINDPOINTERS(SecurityBufferLength);
  BINDPOINTERS(Buffer);
}


void NetSmb2TreeconnectCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(PathOffset);
  BINDPOINTERS(PathLength);
  BINDPOINTERS(Buffer);
};


void NetSmb2TreeconnectReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(ShareType);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(ShareFlags);
  BINDPOINTERS(Capabilities);
  BINDPOINTERS(MaximalAccess);
};


void NetSmb2LogoffCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Reserved);
};

void NetSmb2LogoffReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Reserved);
};

void NetSmb2DisconnectCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Reserved);
};

void NetSmb2DisconnectReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Reserved);
};


void NetSmb2QuerydirectoryCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 33
  BINDPOINTERS(FileInformationClass);
  BINDPOINTERS(Flags);
  BINDPOINTERS(FileIndex);
  BINDPOINTERS(FileId);
  BINDPOINTERS(FileNameOffset);
  BINDPOINTERS(FileNameLength);
  BINDPOINTERS(OutputBufferLength);
  BINDPOINTERS(Buffer);
}


void NetSmb2QuerydirectoryReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 9
  BINDPOINTERS(OutputBufferOffset);
  BINDPOINTERS(OutputBufferLength);
  BINDPOINTERS(Buffer);
}
