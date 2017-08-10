//
// mswireobjects.hpp -
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
#ifndef include_mswireobjects
#define include_mswireobjects

extern "C" {
}
//#include "smb2utils.hpp"
//#include "netstreambuffer.hpp"
//#include "wireobjects.hpp"

// Returned structures Borrowed from server code for now, need to fix


class ms_FILE_ID_BOTH_DIR_INFORMATION  : public NetWireStruct   {
public:
  ms_FILE_ID_BOTH_DIR_INFORMATION() {objectsize=105; }
  NetWiredword NextEntryOffset;
  NetWiredword FileIndex;
  NetWireFileTime CreationTime;
  NetWireFileTime LastAccessTime;
  NetWireFileTime LastWriteTime;
  NetWireFileTime ChangeTime;
  NetWireddword EndofFile;
  NetWireddword AllocationSize;
  NetWiredword FileAttributes;
  NetWiredword FileNameLength;

  NetWiredword EaSize;
  NetWirebyte  ShortNameLength;
  NetWirebyte  Reserved1;
  NetWireblob24  ShortName;
  NetWireword  Reserved2;
  NetWireddword FileId;
  NetWirebyte  FileName;
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



#endif
