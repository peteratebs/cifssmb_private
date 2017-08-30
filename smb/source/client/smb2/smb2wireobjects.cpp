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
#include "smb2clientincludes.hpp"


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

void NetSmb2CreateCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize); // 57
  BINDPOINTERS(SecurityFlags);
  BINDPOINTERS(RequestedOplockLevel);
  BINDPOINTERS(ImpersonationLevel);
  BINDPOINTERS(SmbCreateFlags);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(DesiredAccess);
  BINDPOINTERS(FileAttributes);
  BINDPOINTERS(ShareAccess);
  BINDPOINTERS(CreateDisposition);
  BINDPOINTERS(CreateOptions);
  BINDPOINTERS(NameOffset);
  BINDPOINTERS(NameLength);
  BINDPOINTERS(CreateContextsOffset);
  BINDPOINTERS(CreateContextsLength);
  BINDPOINTERS(Buffer);
}

void NetSmb2CreateReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(OplockLevel);
  BINDPOINTERS(Flags);
  BINDPOINTERS(CreateAction);
  BINDPOINTERS(CreationTime);
  BINDPOINTERS(LastAccessTime);
  BINDPOINTERS(LastWriteTime);
  BINDPOINTERS(ChangeTime);
  BINDPOINTERS(AllocationSize);
  BINDPOINTERS(EndofFile);
  BINDPOINTERS(FileAttributes);
  BINDPOINTERS(Reserved2);
  BINDPOINTERS(FileId);
  BINDPOINTERS(CreateContextsOffset);
  BINDPOINTERS(CreateContextsLength);
  BINDPOINTERS(Buffer);
};

void NetSmb2CloseCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Flags);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(FileId);
}

void NetSmb2CloseReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(Flags);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(CreationTime);
  BINDPOINTERS(LastAccessTime);
  BINDPOINTERS(LastWriteTime);
  BINDPOINTERS(ChangeTime);
  BINDPOINTERS(AllocationSize);
  BINDPOINTERS(EndofFile);
  BINDPOINTERS(FileAttributes);
}

void NetSmb2SetinfoCmd::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
  BINDPOINTERS(InfoType);
  BINDPOINTERS(FileInfoClass);
  BINDPOINTERS(BufferLength);
  BINDPOINTERS(BufferOffset);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(AdditionalInformation);
  BINDPOINTERS(FileId);
  BINDPOINTERS(Buffer);
}

void NetSmb2SetinfoReply::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(StructureSize);
}

void NetSmb2RenameInfoType2::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(ReplaceIfExists);
  BINDPOINTERS(Reserved);
  BINDPOINTERS(RootDirectory);
  BINDPOINTERS(FileNameLength);  // Bytes
  BINDPOINTERS(Buffer);
}
