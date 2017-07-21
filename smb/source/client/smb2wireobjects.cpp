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
#include <netstreambuffer.hpp>

/// ===============================


void show_cpp_rtsmb2_cli_session_recv_negotiate(smb2_iostream  *pStream)
{
NetNbssHeader NbssHeader;
NetSmb2Header Smb2Header;
   cout << "Parsing live input  !!" << endl;
//   byte *pSmb2Raw = NbssHeader.bindpointers((byte *)pStream->read_origin);
//   cout << "(NBSS Size :)" << NbssHeader.nbss_packet_size.get() << endl;
   byte *pSmb2Raw =(byte *)pStream->read_origin;
   pSmb2Raw = Smb2Header.bindpointers(pSmb2Raw);
   cout << "(SMB2 Size :)" << Smb2Header.StructureSize.get() << endl;

}
void show_cpp_rtsmb2_cli_session_send_negotiate(smb2_iostream  *pStream)
{
NetNbssHeader NbssHeader;
NetSmb2Header Smb2Header;

    cout << "Parsing live output !!" << endl;
    byte *pSmb2Raw = NbssHeader.bindpointers((byte *)pStream->write_origin);
    cout << "(NBSS Size :)" << NbssHeader.nbss_packet_size.get() << endl;
    pSmb2Raw = Smb2Header.bindpointers(pSmb2Raw);
    cout << "(SMB2 Size :)" << Smb2Header.StructureSize.get() << endl;

}


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

#endif /* INCLUDE_RTSMB_CLIENT */
#endif
