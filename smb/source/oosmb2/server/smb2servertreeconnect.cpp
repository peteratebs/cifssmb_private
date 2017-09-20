//
// smb2servertreeconnect.cpp -
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

#include "smb2serverincludes.hpp"



/*  File_pipe_printer access mask, section 2.2.13.1.1 */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_DATA         0x00000001   /* ** This value indicates the right to read data from the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA        0x00000002   /* ** This value indicates the right to write data into the file or named pipe beyond the end of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA       0x00000004   /* ** This value indicates the right to append data into the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_EA           0x00000008   /* ** This value indicates the right to read the extended attributes of the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_EA          0x00000010   /* ** This value indicates the right to write or change the extended attributes to the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_FILE_DELETE_CHILD      0x00000040   /* ** This value indicates the right to delete entries within a directory. */
#define SMB2_FPP_ACCESS_MASK_FILE_EXECUTE           0x00000020   /* ** This value indicates the right to execute the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_READ_ATTRIBUTES   0x00000080   /* ** This value indicates the right to read the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_FILE_WRITE_ATTRIBUTES  0x00000100   /* ** This value indicates the right to change the attributes of the file. */
#define SMB2_FPP_ACCESS_MASK_DELETE                 0x00010000   /* ** This value indicates the right to delete the file. */
#define SMB2_FPP_ACCESS_MASK_READ_CONTROL           0x00020000   /* ** This value indicates the right to read the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_WRITE_DAC              0x00040000   /* ** This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP]. */
#define SMB2_FPP_ACCESS_MASK_WRITE_OWNER            0x00080000   /* ** This value indicates the right to change the owner in the security descriptor for the file or named pipe. */
#define SMB2_FPP_ACCESS_MASK_SYNCHRONIZE            0x00100000   /* ** SMB2 clients set this flag to any value. SMB2 servers SHOULD ignore this flag. */
#define SMB2_FPP_ACCESS_MASK_ACCESS_SYSTEM_SECURITY 0x01000000   /* ** This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42> */
#define SMB2_FPP_ACCESS_MASK_MAXIMUM_ALLOWED        0x02000000   /* ** This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_ALL            0x10000000   /* ** This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_EXECUTE        0x20000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_WRITE          0x40000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL. */
#define SMB2_FPP_ACCESS_MASK_GENERIC_READ           0x80000000   /* ** This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL. */



int  Smb2ServerSession::ProcessTreeconnect()
{
  byte *nbss_read_origin= (byte *) read_origin;
  byte *sharename_origin;
  nbss_read_origin -= 4; // Look at the NBSS header
  NetNbssHeader       InNbssHeader;
  NetSmb2Header       InSmb2Header;
  InNbssHeader.bindpointers(nbss_read_origin);
  InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());
  NetSmb2TreeconnectCmd Smb2TreeconnectCmd;
  Smb2TreeconnectCmd.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());
  NetNbssHeader       OutNbssHeader;
  NetSmb2Header       OutSmb2Header;

  sharename_origin = InSmb2Header.FixedStructureAddress()+Smb2TreeconnectCmd.PathOffset();


  NetSmb2TreeconnectReply     Smb2TreeconnectReply;
  byte *nbss_write_origin= (byte *) write_origin;
  nbss_write_origin-=4;
  memset(nbss_write_origin, 0,OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2TreeconnectReply.FixedStructureSize());
  OutNbssHeader.bindpointers(nbss_write_origin);
  OutSmb2Header.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize());
  Smb2TreeconnectReply.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize());

  // sharename_origin, Smb2TreeconnectCmd.PathLength;
  OutSmb2Header.InitializeReply(InSmb2Header);
  Smb2TreeconnectReply.StructureSize = Smb2TreeconnectReply.FixedStructureSize();

  // make sure it is null terminated, we're peeking at the buffer so this is okay
  word savew= ((word *)sharename_origin)[Smb2TreeconnectCmd.PathLength()/2];
  ((word *)sharename_origin)[Smb2TreeconnectCmd.PathLength()/2] = 0;
  Smb2ServerShareStruct *pShare = map_sharename_to_sharehandle((word *)sharename_origin, Smb2TreeconnectCmd.PathLength());
  ((word *)sharename_origin)[Smb2TreeconnectCmd.PathLength()/2]=savew;

  if (pShare)
  {
  // case RTSMB_SHARE_TYPE_DISK 1,  RTSMB_SHARE_TYPE_PRINTER 3,  RTSMB_SHARE_TYPE_IPC, 2
    OutSmb2Header.TreeId               = pShare->share_id;
    Smb2TreeconnectReply.ShareType     = pShare->share_type;
    Smb2TreeconnectReply.ShareFlags    = 0; // SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK These are okay SMB2_SHAREFLAG_NO_CACHING|SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS;
    Smb2TreeconnectReply.Capabilities  = 0;
    if (pShare->is_readonly)
      Smb2TreeconnectReply.MaximalAccess = SMB2_FPP_ACCESS_MASK_FILE_READ_DATA;
    else
      Smb2TreeconnectReply.MaximalAccess = SMB2_FPP_ACCESS_MASK_FILE_READ_DATA|SMB2_FPP_ACCESS_MASK_FILE_WRITE_DATA|SMB2_FPP_ACCESS_MASK_SYNCHRONIZE|SMB2_FPP_ACCESS_MASK_FILE_APPEND_DATA;
  }
  else
  {
    OutSmb2Header.Status_ChannelSequenceReserved = SMB2_STATUS_ACCESS_DENIED; // SMB2_NT_STATUS_SUCCESS;
  }

  //  server_shares[shareid-1].maximal_access = Smb2TreeconnectReply.MaximalAccess();
  OutNbssHeader.nbss_packet_size = OutSmb2Header.FixedStructureSize()+ Smb2TreeconnectReply.FixedStructureSize();

  return OutNbssHeader.nbss_packet_size()+4;
}
