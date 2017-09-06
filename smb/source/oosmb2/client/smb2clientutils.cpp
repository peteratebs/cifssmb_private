//
// smb2logon.cpp -
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
#include "rtpdate.h"


NetStatus NetStreamInputBuffer::pull_nbss_frame_checked(const char *arg_command_name, size_t arg_packed_structure_size, dword &bytes_pulled)
{
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  NetSmb2MinimumReply  Smb2MinimumReply;
  NetStatus           r = NetStatusOk;
  dword min_packet_bytes_pulled,more_bytes_pulled;
  size_t min_reply_size = InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+Smb2MinimumReply.PackedStructureSize();
  size_t good_reply_size = InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize()+arg_packed_structure_size;

  bytes_pulled = 0;

  byte *pBase = input_buffer_pointer();
   // Pull enough for the fixed part and then map pointers to input buffer
  r = pull_new_nbss_frame(min_reply_size, min_packet_bytes_pulled);
  if (r != NetStatusOk) return r;
  if (min_packet_bytes_pulled != min_reply_size)
  {
    getCurrentActiveSession()->diag_text_warning("%s command failed pulling SMB2 header from the socket",arg_command_name);
    return NetStatusDeviceRecvUnderflow;
  }
  // look at the headers for status
  InNbssHeader.bindpointers(pBase);
  InSmb2Header.bindpointers(pBase+InNbssHeader.FixedStructureSize());
  Smb2MinimumReply.bindpointers(pBase+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
  more_bytes_pulled = 0;

  getCurrentActiveSession()->diag_text_warning("%s replied with status:%X", arg_command_name, InSmb2Header.Status_ChannelSequenceReserved());

  if (InSmb2Header.Status_ChannelSequenceReserved() != SMB2_NT_STATUS_SUCCESS)
  {
    getCurrentActiveSession()->diag_text_warning("%s command failed pulling SMB2 header from the socket",arg_command_name);
    r = NetStatusServerErrorStatus;
  }
  else
  {
    if (min_packet_bytes_pulled < good_reply_size)
    {
       r = pull_nbss_data(good_reply_size-min_packet_bytes_pulled, more_bytes_pulled);
       if (r != NetStatusOk) return r;
       if (more_bytes_pulled != good_reply_size-min_packet_bytes_pulled)
       {
         getCurrentActiveSession()->diag_text_warning("%s: command failed pulling CMD header from the socket",arg_command_name);
         r = NetStatusDeviceRecvBadLength;
       }
     }
  }

  bytes_pulled = more_bytes_pulled + min_packet_bytes_pulled;
  if (r == NetStatusOk && bytes_pulled != good_reply_size)
  {
     getCurrentActiveSession()->diag_text_warning("%s: unexpected command bytes_pulled != good_reply_size",arg_command_name);
     r = NetStatusDeviceRecvBadLength;
  }

  return r;
}

