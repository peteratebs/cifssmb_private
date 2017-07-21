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
#include <map>
#include <algorithm>
#include <iostream>
#include <string>
using std::cout;
using std::endl;

#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#if (INCLUDE_RTSMB_CLIENT)
#include "client.h"
#include <wireobjects.hpp>
#include <smb2wireobjects.hpp>

#endif /* INCLUDE_RTSMB_CLIENT */
#endif
