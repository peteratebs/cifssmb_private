#define HEREHERE

//
// CLI_SMB_WIRE.C -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2013
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
//  Exports two public functions:
//      RtsmbStreamEncodeCommand(smb2_iostream *pStream, PFVOID pItem) - Encode an SMB request in the local structure pointed to by pItem into the output buffer managed by pStream.
//      RtsmbStreamDecodeResponse(smb2_iostream *pStream, PFVOID pItem)- Decode an SMB response into the local structure pointed to by pItem from the input buffer managed by pStream.
//
//      These two routines are called to encode and decode packets at the request of logic in the file cli_smb_proc.c
//
//      Variable length output parameters like path names, write data, security blobs etc are passed to RtsmbStreamEncodeCommand in pStream->WriteBufferParms[0]
//      If a second variable length output parameters is needed like channel names are passed to RtsmbStreamEncodeCommand in pStream->WriteBufferParms[1]
//
//      Variable length input parameters like read data, security blobs etc are passed to RtsmbStreamDecodeCommand in pStream->ReadBufferParms[0]
//      If a second variable length input parameter is needed like channel names are passed to RtsmbStreamDecodeCommand in pStream->ReadBufferParms[1]
//
//
//
//

#include "smbdefs.h"
#include "rtpmem.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */
#if (INCLUDE_RTSMB_CLIENT)
// #include "com_smb2.h"
#include "smbpack.h"
#include "smbread.h"


#include "cliwire.h"
#include "smbutil.h"
#include "smbnbss.h"
#include "clians.h"
#include "smbnet.h"
#include "clicfg.h"
#include "smbdebug.h"
#include "smbconf.h"

#include "rtpnet.h"
#include "rtptime.h"

// These are either duplicated from server files or they are derived from functions in the server's com_smb2_wire.c
// implementaion. sm2_stream structure that handles both server and client, these functions allow us to exclude
// the smb2_stream declaration and use the smb2_iostream declaration which is excludes server specific fields


/* Unpacks a 64 byte SMB2 header from a stream.
    Updates:
        pStream->pInBuf,  pStream->read_buffer_remaining
    Returns:
        -1   If read_buffer_remaining is too small to contain the header
        > 0  The number of bytes in the header (should be 64)
*/
int cmd_read_transform_header_smb2(PFVOID origin, PFVOID buf, rtsmb_size size, RTSMB2_TRANSFORM_HEADER *pHeader)
{
	PFVOID s, e;
	s = buf;
    UNPACK_STRUCT_FR_WIRE(pHeader,RTSMB2_TRANSFORM_HEADER, 52);
	if (pHeader->ProtocolId[0] != 0xFD)
		return -1;
	if (tc_strncmp ((char *)&pHeader->ProtocolId[1], "SMB", 3) != 0)
		return -1;

	e = buf;
	return (int) PDIFF (e, s);

}

// This is referenced for SMB3 fetures but it is never called.
// A function signing algorithm is provided by calculate_smb2_signing_key().
void  RTSmb2_Encryption_Sign_message(byte *Signature,byte *Key,byte SigningRule, byte *Message, rtsmb_size messageLength)
{
   rtp_memcpy(Signature , "IMSIGNEDBABYYAYA" , 16);
}

static byte *RTSmb2_Encryption_Get_Encrypt_Buffer(byte *origin, rtsmb_size  buffer_size)
{
    return (byte *)rtp_malloc(buffer_size*2);
}
/* Start encryption. Called on a stream from the top level dispatch if the session is set up and known to be encrypted.
   Wraps the stream in a buffer with an SMB2 transform header prepended. The message finalize process will encrypt the outgoing messge. */
void  smb2_iostream_start_encryption(smb2_iostream *pStream)
{
    pStream->EncryptMessage   = TRUE;
    pStream->saved_write_origin = pStream->write_origin;
    /* Request a buffer that can hold pStream->write_buffer_size, if encrypt in place is possible return the passed address, which is just beyond the transform header. The write buffer has padding to contain the header.  */
    pStream->pOutBuf =
    pStream->write_origin =
        RTSmb2_Encryption_Get_Encrypt_Buffer( ((PFBYTE)pStream->saved_write_origin)+RTSMB2_NBSS_TRANSFORM_HEADER_SIZE, pStream->write_buffer_size);  /* SPR - added casting to fix compile error */
}



const char *DebugSMB2CommandToString(int command)
{
const char * r = 0;
	switch(command)
	{
        case SMB2_NEGOTIATE:
            r="SMB2_NEGOTIATE";
			break;
        case SMB2_SESSION_SETUP  :
            r="SMB2_SESSION_SETUP  ";
			break;
        case SMB2_LOGOFF         :
            r="SMB2_LOGOFF         ";
			break;
        case SMB2_TREE_CONNECT   :
            r="SMB2_TREE_CONNECT   ";
			break;
        case SMB2_TREE_DISCONNECT:
            r="SMB2_TREE_DISCONNECT";
			break;
        case SMB2_CREATE         :
            r="SMB2_CREATE         ";
			break;
        case SMB2_CLOSE          :
            r="SMB2_CLOSE          ";
			break;
        case SMB2_FLUSH          :
            r="SMB2_FLUSH          ";
			break;
        case SMB2_READ           :
            r="SMB2_READ           ";
			break;
        case SMB2_WRITE          :
            r="SMB2_WRITE          ";
			break;
        case SMB2_LOCK           :
            r="SMB2_LOCK           ";
			break;
        case SMB2_IOCTL          :
            r="SMB2_IOCTL          ";
			break;
        case SMB2_CANCEL         :
            r="SMB2_CANCEL         ";
			break;
        case SMB2_ECHO           :
            r="SMB2_ECHO           ";
			break;
        case SMB2_QUERY_DIRECTORY:
            r="SMB2_QUERY_DIRECTORY";
			break;
        case SMB2_CHANGE_NOTIFY  :
            r="SMB2_CHANGE_NOTIFY  ";
			break;
        case SMB2_QUERY_INFO     :
            r="SMB2_QUERY_INFO     ";
			break;
        case SMB2_SET_INFO       :
            r="SMB2_SET_INFO       ";
			break;
        case SMB2_OPLOCK_BREAK   :
            r="SMB2_OPLOCK_BREAK   ";
			break;
		default:
		    r=("UNKOWN COMMAND");
		    break;
	}
    return r;
}

// ======================================
// This is called via smbdefs #define SMB_SWAP_BYTES_DD(A) (ddword) swapdword(A)
ddword swapdword(const ddword i)
{
    ddword  rval;
    ddword  *input = (ddword  *) &i;
    byte    *data = (byte *)&rval;
    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;
    return rval;
}

/* Unpacks a 64 byte SMB2 header from a buffer.
    Returns:
        -1   If size is too small to contain the header or it is not an SMB2 packet by signature
        > 0  The number of bytes in the header (should be 64)
*/
int cmd_read_header_raw_smb2 (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB2_HEADER pHeader)
{
	PFVOID s, e;
	s = buf;
    UNPACK_STRUCT_FR_WIRE(pHeader,RTSMB2_HEADER, 64);
	if (pHeader->ProtocolId[0] != 0xFE)
		return -1;
	if (tc_strncmp ((char *)&pHeader->ProtocolId[1], "SMB", 3) != 0)
		return -1;
	e = buf;
	return (int) PDIFF (e, s);
}

/* Generic routine for decoding variable portions of most MSB2 messgages.

    Takes the packet's data offset fields and data length fileds as arguments.

    Calculates offset on the wire to data (if any)
    Reads padding bytes from the wire if needed.

    Reads bytes into into pStream->ReadBufferParms[0].pBuffer and sets pStream->ReadBufferParms[0].byte_count.

    Returns bytes transfered or -1 if byte count is larger than wire count.

*/
int RtsmbWireVarDecode (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize)
{
PFVOID s=buf;
	if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset- (dword)(StructureSize+pStream->InHdr.StructureSize-1);
	    if (OffsetToBuffer)
	    {
        dword i;
        byte b;
	        for(i = 0; i < OffsetToBuffer; i++)
            {
                RTSMB_READ_BYTE(&b);
            }
	    }
        if (!pStream->ReadBufferParms[0].pBuffer || BufferLength > pStream->ReadBufferParms[0].byte_count)
        {
            RTP_DEBUG_OUTPUT_SYSLOG(SYSLOG_ERROR_LVL,"RtsmbWireVarDecode  failed(pBuffer, Length, bytes alloced)): %ld %ld %ld\n", pStream->ReadBufferParms[0].pBuffer,BufferLength,pStream->ReadBufferParms[0].byte_count);
            return -1;
        }
        pStream->ReadBufferParms[0].byte_count = BufferLength;
        RTSMB_READ_ITEM  (pStream->ReadBufferParms[0].pBuffer, pStream->ReadBufferParms[0].byte_count);
    }
	return PDIFF (buf, s);
}

int RtsmbWireVarDecodePartTwo (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize)
{
PFVOID s=buf;
	if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset- (dword)(StructureSize+pStream->InHdr.StructureSize-1);
	    if (OffsetToBuffer)
	    {
        dword i;
        byte b;
	        for(i = 0; i < OffsetToBuffer; i++)
            {
                RTSMB_READ_BYTE(&b);
            }
	    }
        if (!pStream->ReadBufferParms[1].pBuffer || BufferLength > pStream->ReadBufferParms[1].byte_count)
            return -1;
        pStream->ReadBufferParms[1].byte_count = BufferLength;
        RTSMB_READ_ITEM  (pStream->ReadBufferParms[1].pBuffer, pStream->ReadBufferParms[1].byte_count);
    }
	return PDIFF (buf, s);
}


int RtsmbWireVarEncode(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, word StructureSize)
{
PFVOID s=buf;
    if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset-(dword)(StructureSize+pStream->OutHdr.StructureSize-1);
        while(OffsetToBuffer-- > 0)
            RTSMB_PACK_BYTE(0);
        if (!pStream->WriteBufferParms[0].pBuffer || BufferLength > pStream->WriteBufferParms[0].byte_count)
            return -1;
        RTSMB_PACK_ITEM (pStream->WriteBufferParms[0].pBuffer, BufferLength);
    }
    return PDIFF (buf, s);
}

int RtsmbWireVarEncodePartTwo(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, dword UsedSize)
{
PFVOID s=buf;
    if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset-(dword)(UsedSize+pStream->OutHdr.StructureSize-1);
        while(OffsetToBuffer-- > 0)
            RTSMB_PACK_BYTE(0);
        if (BufferLength > pStream->WriteBufferParms[1].byte_count)
            return -1;
        RTSMB_PACK_ITEM (pStream->WriteBufferParms[1].pBuffer, BufferLength);
    }
    return PDIFF (buf, s);
}


int RtsmbWireEncodeSmb2(smb2_iostream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarEncodeFn_t pVarEncodeFn)
{
BBOOL doSign = FALSE;
    FILL_PROLOG_TEMPLATE
    /* PACK_STRUCT_TO_WIRE checks if the local variable "size" is large enough to contain the buffer. If not returns -1.
       Otherwise copy the bytes from the structure to the wire, decrease the variable size, and increase the pointer variable buf
       The stream buffer values are offloaded and uploaded by the PROLOG and EPILOG macros . */
    if (pStream->pSession)
       pStream->OutHdr.SessionId = pStream->pSession->server_info.smb2_session_id;

    PACK_STRUCT_TO_WIRE(&pStream->OutHdr,RTSMB2_HEADER,64);
    PACK_STRUCT_TO_WIRE(pItem,BLOB,FixedSize);
    if (pVarEncodeFn)
    {
        int var_size;
        var_size = pVarEncodeFn(pStream, origin,buf,size,pItem);
        if (var_size < 0)
            return -1;
        buf=PADD(buf,var_size);
        size -= (rtsmb_size) var_size;
    }

	e = buf;
    if (pStream->PadValue) RTSMB_PACK_PAD_TO(pStream->PadValue);
    consumed = (rtsmb_size)PDIFF (e, s);
    pStream->pOutBuf = PADD(pStream->pOutBuf, consumed);
    pStream->write_buffer_remaining-=consumed;
    pStream->OutBodySize+=consumed;

    // If the request was signed by the client, the response message being sent contains a nonzero SessionId and a zero TreeId in the SMB2 header, and the session identified by SessionId has Session.SigningRequired equal to TRUE.
    if (pStream->InHdr.Flags&SMB2_FLAGS_SIGNED && pStream->InHdr.SessionId != 0 && pStream->InHdr.TreeId ==0)
       doSign = TRUE;
    // If the request was signed by the client, the response message being sent contains a nonzero SessionId, and a nonzero TreeId in the SMB2 header, and the session identified by SessionId
    // has Session.SigningRequired equal to TRUE, if either global EncryptData is FALSE or Connection.ClientCapabilities does not include the SMB2_GLOBAL_CAP_ENCRYPTION bit.
    if (pStream->InHdr.Flags&SMB2_FLAGS_SIGNED && pStream->OutHdr.SessionId != 0 && pStream->InHdr.TreeId != 0)
       doSign = TRUE;
    // If the request was signed by the client, and the response is not an interim response to an asynchronously processed request.
    // So more or less, anything not a CANCEL response I think.
    if (pStream->InHdr.Flags&SMB2_FLAGS_SIGNED)
       doSign = TRUE;

    if (doSign && pStream->SigningKey)
        RTSmb2_Encryption_Sign_message(pStream->OutHdr.Signature,pStream->SigningKey, pStream->SigningRule, pStream->write_origin,consumed);
	return (int) consumed;
}


int RtsmbWireDecodeSmb2(smb2_iostream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarDecodeFn_t pVarDecodeFn)
{
    READ_PROLOG_TEMPLATE

    /* UNPACK_STRUCT_FR_WIRE checks if the local variable "size" is large enough to hold the structure. If not returns -1.
       Otherwise copy the bytes from wire to the structure, decrease the variable size, and increase the pointer variable buf
       The stream buffer values are offloaded and uploaded by the PROLOG and EPILOG macros . */
    UNPACK_STRUCT_FR_WIRE(pItem, BLOB, FixedSize);
    if (pVarDecodeFn)
    {
        int var_size;
        var_size = pVarDecodeFn(pStream, origin,buf,size,pItem);
        if (var_size < 0)
            return -1;
        buf=PADD(buf,var_size);
        size -= (rtsmb_size) var_size;
    }
    {
    int consumed;
	e = buf;
        consumed = PDIFF (e, s);
        pStream->pInBuf = PADD(pStream->pInBuf, consumed);
        pStream->read_buffer_remaining-=(rtsmb_size)consumed;
//        if (pStream->SigningKey)
//            RTSmb2_Encryption_Sign_message(pStream->OutHdr.Signature,pStream->SigningKey, pStream->SigningRule, pStream->read_origin,consumed);
        return consumed;
    }
}

PFCHAR (*rtsmb_glue_get_server_name_from_cache) (PFINT i) = 0;
BBOOL (*rtsmb_glue_are_other_workgroups) (void) = (BBOOL)0;
BBOOL (*rtsmb_glue_do_we_have_server_list) (void) = (BBOOL)0;
PFCHAR (*rtsmb_glue_get_our_server_name) (void) = 0;
void (*rtsmb_glue_process_nbds_message) (PFCHAR dest_name, byte command, PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB_HEADER pheader) = 0;



#endif /* INCLUDE_RTSMB_CLIENT */
#endif