#ifndef __CLI_WIRE_H__
#define __CLI_WIRE_H__

#include "smbdefs.h"

#include "smbobjs.h"
#include "clicmds.h"
#include "clians.h"
#include "smbnbss.h"
#include "smbnbns.h"
#include "rtpnet.h"
#include "smbconf.h"
// =====================
// These are either duplicated from server headers or they are derived from structures in the server that were previously required.
/* Building up a client session definition here to aid in building the server. Move this later when it is complete */
#if (defined(BUILDING_CLIENT))


typedef struct Rtsmb2ClientSession_s
{
    BBOOL inUse;
    ddword SessionId;
} Rtsmb2ClientSession;
/* Used to pass buffers along with command/response/headers to/from SMB2 encode/decode */
typedef struct
{
    void *pBuffer;
    rtsmb_size  byte_count;
} RTSMB2_BUFFER_PARM;
typedef RTSMB2_BUFFER_PARM RTSMB_FAR *PRTSMB2_BUFFER_PARM;
#endif

#include "com_smb2_wiredefs.h"

extern const char *DebugSMB2CommandToString(int command);

PACK_PRAGMA_ONE
typedef struct smb2_iostream_s {
     // Signing rules. Set by calling smb2_stream_set_signing_rule
    byte     *SigningKey;                           // For writes, the key for signing, For reads the key for checking the signature
#define SIGN_NONE         0                         // - Used for 3.x. Generates 16 byte hash over entire message including Header and padding.
#define SIGN_AES_CMAC_128 1                         // - Used for 3.x. Generates 16 byte hash over entire message including Header and padding.
#define SIGN_HMAC_SHA256  2                         // - Used for 2.002 and 2.100 generates 32 byte hash over entire message including Header and padding. Copy low 16 bytes into the keyfield
    byte     SigningRule;
    struct RTSMB_CLI_WIRE_BUFFER_s *pBuffer;        // For a client. points to the controlling SMBV1 buffer structure.
    struct RTSMB_CLI_SESSION_T     *pSession;       // For a client. points to the controlling SMBV1 session structure.
//    struct Rtsmb2ClientSession_s   *psmb2Session;   // For a client. points to smb2 session structure
    struct RTSMB_CLI_SESSION_JOB_T *pJob;           // For a client points to the controlling SMBV1 job structure.

    int      PadValue;                              // If the stream contains a compound message, set to the proper pad value between commands.
    BBOOL    EncryptMessage;                        // For write operations, encryption is required. For reads decryption is required.
    BBOOL    Success;                               // Indicates the current state of read or write operation is succesful.

    RTSMB2_HEADER OutHdr;                           // Buffer control and header for response
	RTSMB2_BUFFER_PARM WriteBufferParms[2];         // For writes, points to data source for data. Second slot is used in rare cases where 2 variable length parameters are present.
	PFVOID   write_origin;                          // Points to the beginning of the buffer, the NBSS header.
    PFVOID   saved_write_origin;                    // Original origin if the packet is beign encrypted
    PFVOID   pOutBuf;                               // Current position in the output stream buffer.
    rtsmb_size write_buffer_size;
    rtsmb_size write_buffer_remaining;
    rtsmb_size OutBodySize;

    RTSMB2_HEADER InHdr;                            // Buffer control and header from command
	RTSMB2_BUFFER_PARM ReadBufferParms[2];          // For reads points to sink for extra data.  Second slot is used in rare cases where 2 variable length parameters are present.
	PFVOID   read_origin;
    rtsmb_size read_buffer_size;
    rtsmb_size read_buffer_remaining;
//xx    rtsmb_size InBodySize;
//xx	PFVOID   saved_read_origin;
    PFVOID   pInBuf;
//    PFVOID   StreamBuffer;
} PACK_ATTRIBUTE smb2_iostream;
PACK_PRAGMA_POP

#define RTSMB2_NBSS_TRANSFORM_HEADER_SIZE 52

#if (defined(BUILDING_CLIENT))
typedef int (* pVarEncodeFn_t) (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);

int RtsmbWireVarDecode (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize);
int RtsmbWireVarEncode(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, word StructureSize);
int RtsmbWireVarEncodePartTwo(smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, dword UsedSize);

//extern int RtsmbWireEncodeSmb2(smb2_stream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarEncodeFn_t pVarEncodeFn);
typedef int (* pVarDecodeFn_t) (smb2_iostream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,PFVOID pItem);
#endif
// int RtsmbWireDecodeSmb2(smb2_stream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarDecodeFn_t pVarDecodeFn);


#define FILL_PROLOG_TEMPLATE \
    PFVOID origin,buf;\
    rtsmb_size size;\
    rtsmb_size consumed;\
    PFVOID s, e;\
    origin  = pStream->write_origin;\
    buf     = pStream->pOutBuf;\
    size    = (rtsmb_size)pStream->write_buffer_remaining; \
    s = buf;

#define FILL_EPILOG_TEMPLATE \
	e = buf;\
    if (pStream->PadValue) RTSMB_PACK_PAD_TO(pStream->PadValue);\
    consumed = (rtsmb_size)PDIFF (e, s);\
    pStream->pOutBuf = PADD(pStream->pOutBuf,consumed);\
    pStream->write_buffer_remaining-=consumed;\
    pStream->OutBodySize+=consumed;\
	return (int) consumed;


#define READ_PROLOG_TEMPLATE \
PFVOID origin,buf;\
rtsmb_size size;\
PFVOID s, e;\
    origin  = pStream->read_origin;\
    buf     = pStream->pInBuf;\
    size    = (rtsmb_size)pStream->read_buffer_remaining;\
	s = buf;\
	origin = origin; /* origin = origin Quiets compiler */

#define READ_EPILOG_TEMPLATE \
    {\
    int consumed;\
	e = buf;\
    consumed = PDIFF (e, s);\
    pStream->pInBuf+=consumed;\
    pStream->read_buffer_remaining-=consumed;\
	return (int) consumed;\
    }
// END These are either duplicated from server headers or they are derived from structures in the server that were previously required.


// =====================
/* error codes */
#define RTSMB_CLI_WIRE_ERROR_BAD_STATE	-50
#define RTSMB_CLI_WIRE_TOO_MANY_REQUESTS	-51
#define RTSMB_CLI_WIRE_BAD_MID			-52


#define RTSMB_CLI_WIRE_MAX_BUFFER_SIZE	(prtsmb_cli_ctx->buffer_size - RTSMB_NBSS_HEADER_SIZE)


typedef enum
{
	DEAD,
	UNCONNECTED,
	CONNECTED,
	NBS_CONNECTED
} RTSMB_CLI_WIRE_SESSION_STATE;

typedef enum
{
	UNUSED,
	BEING_FILLED,
	WAITING_ON_SERVER,
	WAITING_ON_US,
	TIMEOUT,
	DONE
} RTSMB_CLI_WIRE_BUFFER_STATE;

#define INFO_CAN_TIMEOUT	     0x0001  /* can this request time out? */
#define INFO_CHAINED_ZERO_COPY   0x0002  /* this buffer includes a second section
                                            marked as 'zero-copy' for inclusion when
                                            sent on the wire */

typedef struct RTSMB_CLI_WIRE_BUFFER_s
{
	word flags;	/* flags about this buffer */

	RTSMB_CLI_WIRE_BUFFER_STATE state;

	word mid;

	unsigned long end_time_base;	/* time when this will be considered timed out */

	PFVOID last_section;	/* used for andx requests */
	PFVOID buffer_end;

	PFBYTE     attached_data;
	rtsmb_size attached_size;

	rtsmb_size buffer_size;
	PFBYTE buffer;

    rtsmb_size allocated_buffer_size; /* Added for SMB2 */
    smb2_iostream smb2stream;

} RTSMB_CLI_WIRE_BUFFER;
typedef RTSMB_CLI_WIRE_BUFFER RTSMB_FAR *PRTSMB_CLI_WIRE_BUFFER;



typedef struct RTSMB_CLI_WIRE_SESSION_s
{
	RTP_SOCKET socket;	/* socket into which all data is sent */

	byte server_ip [4];	/* ip of server */
	char server_name [RTSMB_NB_NAME_SIZE + 1]; /* name of server */

	word next_mid;

	byte   incoming_nbss_header[4];

	RTSMB_CLI_WIRE_SESSION_STATE state;	/* the state that we are in */

	int num_nbss_sent;
	unsigned long temp_end_time_base;	/* timeout for personal things, like netbios layer */

	PFBYTE temp_buffer;

	BBOOL reading; /* TRUE if we are in the middle of reading a packet */
	rtsmb_size total_to_read; /* how big the currently being read packet is */
	rtsmb_size total_read; /* how much we have read so far */

	/* our buffers */
	PRTSMB_CLI_WIRE_BUFFER buffers;

	/* boolean - set to non-zero if NOT using NetBIOS session service as transport layer */
	int usingSmbOverTcp;

	/* data related to connect state machine */
	int nbssStatus;
	int tcpStatus;
	unsigned long startMsec;
	RTP_SOCKET nbssAttempt;
	RTP_SOCKET tcpAttempt;
	int tryingSmbOverTcp;

	unsigned long physical_packet_size;

} RTSMB_CLI_WIRE_SESSION;
typedef RTSMB_CLI_WIRE_SESSION RTSMB_FAR *PRTSMB_CLI_WIRE_SESSION;


typedef enum
{
	NON_EXISTANT,
	WAITING,
	TIMED_OUT,
	FINISHED
} RTSMB_CLI_MESSAGE_STATE;


int rtsmb_cli_wire_session_new (PRTSMB_CLI_WIRE_SESSION pSession, PFCHAR name, PFBYTE ip, int blocking);
int rtsmb_cli_wire_session_close (PRTSMB_CLI_WIRE_SESSION pSession);
int rtsmb_cli_wire_connect_cycle (PRTSMB_CLI_WIRE_SESSION pSession);

RTSMB_CLI_MESSAGE_STATE rtsmb_cli_wire_check_message (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

// int rtsmb_cli_wire_cycle (PRTSMB_CLI_SESSION pClientSession, PRTSMB_CLI_WIRE_SESSION pSession, long timeout);

/* adding stuff to a session sends data to the server */
int rtsmb_cli_wire_smb_add_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

int rtsmb_cli_wire_smb_add_header (PRTSMB_CLI_WIRE_SESSION pSession, word mid,
	PRTSMB_HEADER pHeader);
#ifdef INCLUDE_RTSMB_CLI_ZERO_COPY
int rtsmb_cli_wire_smb_add_data (PRTSMB_CLI_WIRE_SESSION pSession, word mid, PFBYTE data, long size);
#endif
int rtsmb_cli_wire_smb_add_end (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

/* reading stuff from a session reads data from the server */
int rtsmb_cli_wire_smb_read_start (PRTSMB_CLI_WIRE_SESSION pSession, word mid);
int rtsmb_cli_wire_smb_read_header (PRTSMB_CLI_WIRE_SESSION pSession, word mid,
	PRTSMB_HEADER pHeader);
int rtsmb_cli_wire_smb_read_end (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

int rtsmb_cli_wire_smb_close (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

/* DON'T USE THIS FUNCTION -- internal use only */
PRTSMB_CLI_WIRE_BUFFER rtsmb_cli_wire_get_buffer (PRTSMB_CLI_WIRE_SESSION pSession, word mid);

/* would like to make these not defined globally */
#define rtsmb_cli_wire_smb_add(pSession, mid, pFunction, pStruct, rv)\
{\
	PRTSMB_CLI_WIRE_BUFFER pBuffer;\
	RTSMB_HEADER header;\
	int r;\
	rv = 0;\
	\
	pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);\
	\
	if (!pBuffer)\
		rv = RTSMB_CLI_WIRE_BAD_MID;\
	\
	if (rv == 0)\
	{\
		r = cli_cmd_read_header (PADD (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE),\
		                         PADD (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE),\
		                         prtsmb_cli_ctx->buffer_size - RTSMB_NBSS_HEADER_SIZE, &header);\
		\
		if (r >= 0)\
		{\
			r = pFunction (PADD (pBuffer->buffer, RTSMB_NBSS_HEADER_SIZE), pBuffer->buffer_end,\
			               prtsmb_cli_ctx->buffer_size - (rtsmb_size) PDIFF (pBuffer->buffer_end, pBuffer->buffer),\
			               &header, pStruct);\
			\
			if (r < 0)\
				rv = -3;\
			else\
			{\
				pBuffer->last_section = pBuffer->buffer_end;\
				pBuffer->buffer_end = PADD (pBuffer->buffer_end, r);\
				pBuffer->buffer_size = (rtsmb_size) PDIFF (pBuffer->buffer_end, pBuffer->buffer);\
			}\
		}\
		else\
		{\
			rv = -3;\
		}\
	}\
}

#define rtsmb_cli_wire_smb_read(pSession, mid, pFunction, pStruct, rv)\
{\
	PRTSMB_CLI_WIRE_BUFFER pBuffer;\
	RTSMB_HEADER header;\
	int r;\
	rv = 0;\
	\
	pBuffer = rtsmb_cli_wire_get_buffer (pSession, mid);\
	\
	if (!pBuffer)\
		rv = RTSMB_CLI_WIRE_BAD_MID;\
	\
	if (rv == 0)\
	{\
		r = cli_cmd_read_header (pBuffer->buffer, pBuffer->buffer,\
			prtsmb_cli_ctx->buffer_size, &header);\
		\
		if (r >= 0)\
		{\
			r = pFunction (pBuffer->buffer, pBuffer->buffer_end,\
				pBuffer->buffer_size,\
				&header, pStruct);\
			\
			if (r < 0)\
				rv = -3;\
			else\
			{\
				pBuffer->last_section = pBuffer->buffer_end;\
				pBuffer->buffer_end = PADD (pBuffer->buffer_end, r);\
				pBuffer->buffer_size -= (dword)r;\
			}\
		}\
		else\
		{\
			rv = -3;\
		}\
	}\
}

#endif // ifndef __CLI_WIRE_H__
