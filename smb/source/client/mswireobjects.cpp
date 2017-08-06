//
// mswireobjects.cpp -
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
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
#include "smb2utils.hpp"

#include "smbdefs.h"

//#include "client.h"
#include <netstreambuffer.hpp>
#include <wireobjects.hpp>
#include <mswireobjects.hpp>
void ms_FILE_ID_BOTH_DIR_INFORMATION::BindAddressesToBuffer(byte *base)
{
  BindNetWireArgs A(base);
  BINDPOINTERS(NextEntryOffset);
  BINDPOINTERS(FileIndex);
  BINDPOINTERS(CreationTime);
  BINDPOINTERS(LastAccessTime);
  BINDPOINTERS(LastWriteTime);
  BINDPOINTERS(ChangeTime);
  BINDPOINTERS(EndofFile);
  BINDPOINTERS(AllocationSize);
  BINDPOINTERS(FileAttributes);
  BINDPOINTERS(FileNameLength);
  BINDPOINTERS(EaSize);
  BINDPOINTERS(ShortNameLength);
  BINDPOINTERS(Reserved1);
  BINDPOINTERS(ShortName);
  BINDPOINTERS(Reserved2);
  BINDPOINTERS(FileId);
  BINDPOINTERS(FileName);
}
