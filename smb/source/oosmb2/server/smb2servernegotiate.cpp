//
// smbservernegotiate.pp -
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


// See SMB2_NEGOTIATE, should move to it's own file

// Send this in NTLM reponse to evoke an NTLMSSP_NEGOTIATE response from the client.
// Contents:
// OID: 1.3.6.1.5.5.2 (SPNEGO - Simple Protected Negotiation)
// MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
// principal: not_defined_in_RFC4178@please_ignore
// Evoke SPNEGO
static byte spnego_ntlmssp_blob[] = {
  0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa3,0x2a,0x30,0x28,0xa0,0x26,
  0x1b,0x24,0x6e,0x6f,0x74,0x5f,0x64,0x65,0x66,0x69,0x6e,0x65,0x64,0x5f,0x69,0x6e,0x5f,0x52,0x46,0x43,0x34,0x31,0x37,0x38,0x40,0x70,0x6c,0x65,0x61,0x73,0x65,0x5f,0x69,0x67,0x6e,0x6f,0x72,0x65};
// Callback to send reponse in NTLMSSP_NEGOTIATE response when the client accepts CAP_EXTENDED_SECURITY and the server is configured for NTLM security.
static int spnego_get_negotiate_ntlmssp_blob(byte **pblob)
{
    *pblob = spnego_ntlmssp_blob;
    return sizeof(spnego_ntlmssp_blob);
}
// Alternate API for spnego_get_negotiate_ntlmssp_blob() used in several places.
static byte *RTSmb2_Encryption_Get_Spnego_Default(dword *buffer_size)
{
byte *b;
    *buffer_size = spnego_get_negotiate_ntlmssp_blob(&b);
    return (byte *) b;
}

struct smb2_dialect_entry_s {word dialect;word *name; int priority;};
static  word srv_dialect_smb2002[] = {'S', 'M', 'B', '2', '.', '0', '0', '2', '\0'};
static  word srv_dialect_smb2100[] = {'S', 'M', 'B', '2', '.', '1', '0', '0', '\0'};
static struct smb2_dialect_entry_s smb2_dialectList[] =
{
{SMB2_DIALECT_2002, srv_dialect_smb2002, 1},
{SMB2_DIALECT_2100, srv_dialect_smb2100, 2},
};
#define NUM_SMB2_DIALECTS (int)(sizeof(smb2_dialectList)/sizeof(smb2_dialectList[0]))
static struct smb2_dialect_entry_s *RTSMB_FindBestDialect(int inDialectCount, word inDialects[])
{
int i,entry;
word dialect = 0;
struct smb2_dialect_entry_s *pEntry = 0;

   for (entry = 0; entry < inDialectCount; entry++)
   {//check dialect field against dialect list
      for (i = 0; i < NUM_SMB2_DIALECTS; i++)
      {
        if (inDialects[entry] == smb2_dialectList[i].dialect)
        {
            if ((dialect == 0)	|| (smb2_dialectList[dialect].priority < smb2_dialectList[i].priority))
            {
               dialect = i;
               pEntry = &smb2_dialectList[i];
           }
        }
      }
   }
   return pEntry;
}

int Smb2ServerSession::ProcessNegotiate()
{
    byte *nbss_read_origin= (byte *) read_origin;
    nbss_read_origin-=4;
    NetNbssHeader            InNbssHeader;
    NetSmb2Header            InSmb2Header;
    NetSmb2NegotiateCmd      Smb2NegotiateCmd;

    InNbssHeader.bindpointers(nbss_read_origin);
    InSmb2Header.bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize());
    Smb2NegotiateCmd.        bindpointers(nbss_read_origin+InNbssHeader.FixedStructureSize()+InSmb2Header.FixedStructureSize());

    NetNbssHeader            OutNbssHeader;
    NetSmb2Header            OutSmb2Header;
    NetSmb2NegotiateReply    Smb2NegotiateReply;
    byte *nbss_write_origin= (byte *) write_origin;
    nbss_write_origin-=4;
    memset(nbss_write_origin, 0,OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2NegotiateReply.FixedStructureSize());
    OutNbssHeader.bindpointers(nbss_write_origin);
    OutSmb2Header.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize());
    Smb2NegotiateReply.bindpointers(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize());

    OutSmb2Header.InitializeReply(InSmb2Header);
    OutNbssHeader.nbss_packet_size = OutSmb2Header.FixedStructureSize()+ Smb2NegotiateReply.FixedStructureSize();
    Smb2NegotiateReply.StructureSize = Smb2NegotiateReply.FixedStructureSize();


    //  TBD  - Need to drop if a dialect is already established
    //    If Connection.NegotiateDialect is 0x0202, 0x0210, 0x0300, or 0x0302 the server MUST disconnect the connection,
    //    as specified in section 3.3.7.1, and not reply.
    //
    //if (pStream->psmb2Session->Connection->NegotiateDialect && pStream->psmb2Session->Connection->NegotiateDialect!=SMB2_DIALECT_WILD)
    //{
    //    pStream->doSocketClose = TRUE;
    //}

    /* The server MUST set Connection.ClientCapabilities to the capabilities received in the SMB2 NEGOTIATE request. */
    //pStream->psmb2Session->Connection->ClientCapabilities = command.Capabilities;

    /* If the server implements the SMB 3.x dialect family, the server MUST set Connection.ClientSecurityMode to the SecurityMode field of the SMB2 NEGOTIATE Request. */
    //pStream->psmb2Session->Connection->ClientSecurityMode = command.SecurityMode;

    /* If the server implements the SMB2.1 or 3.x dialect family, the server MUST set Connection.ClientGuid to the ClientGuid field of the SMB2 NEGOTIATE Request. */
    //tc_memcpy(pStream->psmb2Session->Connection->ClientGuid, command.guid, 16);

    /* If SMB2_NEGOTIATE_SIGNING_REQUIRED is set in SecurityMode, the server MUST set Connection.ShouldSign to TRUE. */
    //if (command.SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
    //    pStream->psmb2Session->Connection->ShouldSign = TRUE;


    /*  If the DialectCount of the SMB2 NEGOTIATE Request is 0, the server MUST fail the request with STATUS_INVALID_PARAMETER. */
    if (Smb2NegotiateCmd.DialectCount() == 0)
      OutSmb2Header.Status_ChannelSequenceReserved = SMB2_STATUS_INVALID_PARAMETER;
    else
    {
      struct smb2_dialect_entry_s *pEntry=0;
      word inDialects[4];
      inDialects[0]=Smb2NegotiateCmd.Dialect0();  inDialects[1]=Smb2NegotiateCmd.Dialect1();
      inDialects[2]=Smb2NegotiateCmd.Dialect2();  inDialects[3]=Smb2NegotiateCmd.Dialect3();

      pEntry = RTSMB_FindBestDialect(Smb2NegotiateCmd.DialectCount(), inDialects);
      /* If a common dialect is not found, the server MUST fail the request with STATUS_NOT_SUPPORTED. */
      if (pEntry == 0)
        OutSmb2Header.Status_ChannelSequenceReserved = SMB2_STATUS_NOT_SUPPORTED;
      else
      {
         // if  (select_3x_only && !SMB2IS3XXDIALECT(pEntry->dialect))
         //  SMB2_STATUS_INVALID_PARAMETER);
        // If the common dialect is SMB 2.1 or 3.x dialect family and the underlying connection is either TCP port 445 or RDMA,     Connection.SupportsMultiCredit MUST be set to TRUE; otherwise, it MUST be set to FALSE.
        //pEntry->dialect != SMB2_DIALECT_2002)
        //    pStream->psmb2Session->Connection->SupportsMultiCredit = TRUE;
        //  else
        //    pStream->psmb2Session->Connection->SupportsMultiCredit = TRUE;

      /* DialectRevision MUST be set to the common dialect. */
         Smb2NegotiateReply.DialectRevision    = pEntry->dialect;
      /* ServerGuid is set to the global ServerGuid value. */
         Smb2NegotiateReply.ServerGuid = server_guid;

         Smb2NegotiateReply.SecurityMode       = SMB2_NEGOTIATE_SIGNING_ENABLED;
//         if (Smb2NegotiateCmd.SecurityMode() & SMB2_NEGOTIATE_SIGNING_REQUIRED)    ; //  pStream->psmb2Session->Connection->ShouldSign = TRUE;
         if (server_require_signing)
           Smb2NegotiateReply.SecurityMode   = Smb2NegotiateReply.SecurityMode() | SMB2_NEGOTIATE_SIGNING_REQUIRED;
        client_capabilities = Smb2NegotiateCmd.Capabilities();
      /* The Capabilities field MUST be set to a combination of zero or more of the following bit values, as specified in section 2.2.4 */
         Smb2NegotiateReply.Capabilities       = server_global_caps&client_capabilities; // LARGE_MTU Or use Smb2_util_get_global_caps(pStream->psmb2Session->Connection, 0); // command==0 , no SMB3

         /* MaxTransactSize is set to the maximum buffer size<221>,in bytes, that the server will accept on this connection for QUERY_INFO,
             QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations. */
         Smb2NegotiateReply.MaxTransactSize    =  server_max_transaction_size;
          /* MaxReadSize is set to the maximum size,<222> in bytes, of the Length in an SMB2 READ Request */
         Smb2NegotiateReply.MaxReadSize        =  server_max_transaction_size;
          /* MaxWriteSize is set to the maximum size,<223> in bytes, of the Length in an SMB2 WRITE Request */
         Smb2NegotiateReply.MaxWriteSize       =  server_max_transaction_size;
          /* SystemTime is set to the current time */
         Smb2NegotiateReply.SystemTime         =  rtsmb_util_get_current_filetime();
          /* ServerStartTime is set to the global ServerStartTime value */
      //    response.ServerStartTime    =  pSmb2SrvGlobal->ServerStartTime;
         Smb2NegotiateReply.ServerStartTime    =  0; // pSmb2SrvGlobal->ServerStartTime;
        /* SecurityBufferOffset is set to the offset to the Buffer field in the response, in bytes, from the beginning of the SMB2 header.
            SecurityBufferLength is set to the length of the data being returned in the Buffer field. */
        dword buffer_size;
        byte *Spnego_Default =  RTSmb2_Encryption_Get_Spnego_Default(&buffer_size);
        memcpy(nbss_write_origin+OutNbssHeader.FixedStructureSize()+OutSmb2Header.FixedStructureSize()+Smb2NegotiateReply.FixedStructureSize(),Spnego_Default,buffer_size);
        Smb2NegotiateReply.SecurityBufferOffset = (word) (OutSmb2Header.FixedStructureSize() + Smb2NegotiateReply.PackedStructureSize());
        Smb2NegotiateReply.SecurityBufferLength = (word) buffer_size;
        if (Smb2NegotiateReply.SecurityBufferLength())
        {
            Smb2NegotiateReply.SecurityBufferOffset = (word) (OutSmb2Header.FixedStructureSize()+Smb2NegotiateReply.PackedStructureSize());
        }
        OutNbssHeader.nbss_packet_size =
             OutSmb2Header.FixedStructureSize()+
             Smb2NegotiateReply.PackedStructureSize() +
             Smb2NegotiateReply.SecurityBufferLength();
      }
//      OutNbssHeader.show_contents();
//      OutSmb2Header.show_contents();
      if (OutSmb2Header.Status_ChannelSequenceReserved() != 0)
      {   // Clear variable content if there is an error
          Smb2NegotiateReply.SecurityBufferLength    =  0;
          OutNbssHeader.nbss_packet_size = OutSmb2Header.FixedStructureSize()+Smb2NegotiateReply.FixedStructureSize();
      }
    }
    return OutNbssHeader.nbss_packet_size()+4;
}
