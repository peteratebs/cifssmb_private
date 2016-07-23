/*
|  SRVSRVSVC.C - Support for RPC interface SRVSVC (Microsoft Server Services),
|               including NetrShareEnum
|
|  EBS - RTSMB embedded SMB/CIFS client and server
|
|   $Author: pvanoudenaren $
|   $Date: 2016/06/02 19:53:12 $
|   $Name:  $
|   $Revision: 1.1 $
|
|  Copyright EBS Inc. , 2016
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/

//============================================================================
//    IMPLEMENTATION HEADERS
//============================================================================
#include "smbdefs.h"
#include "rtpwcs.h" /* _YI_ 9/24/2004 */

#if (INCLUDE_RTSMB_SERVER)

#include "srvsrvsvc.h"
#include "srvnet.h"
#include "smbnb.h"
#include "srvrsrcs.h"
#include "srvshare.h"
#include "srvfio.h"
#include "smbobjs.h"
#include "srvans.h"
#include "srvcmds.h"
#include "smbutil.h"
#include "srvnbns.h"
#include "smbnb.h"
#include "smbnbds.h"
#include "smbbrcfg.h"
#include "srvbrbak.h"
#include "srvbrws.h"


#include "rtpsignl.h"
#include "rtpmem.h"
#include "smbdebug.h"

#include "com_smb2_wiredefs.h"    // For SMB2_STATUS_NOT_SUPPORTED, is actuall NT_STATUS

//============================================================================
//    IMPLEMENTATION PRIVATE DEFINITIONS / ENUMERATIONS / SIMPLE TYPEDEFS
//============================================================================

//============================================================================
//    IMPLEMENTATION PRIVATE STRUCTURES
//============================================================================
// borrowed from com_smb2_wiredefs
/* If compiler requires #pragma pack(1), replace all PACK_PRAGMA_ONE with #pragma pack(1) */
#define PACK_PRAGMA_ONE
/* If compiler requires #pragma pack(), replace all PACK_PRAGMA_POP with #pragma pack() */
#define PACK_PRAGMA_POP
/* If compiler supports __attribute__((packed)) set PACK_ATTRIBUTE to attribute__((packed)) */
#define PACK_ATTRIBUTE  __attribute__((packed))

PACK_PRAGMA_ONE
typedef struct s_DCE_BIND_HEADER
{
    byte  version;        // 5
    byte  version_minor;  // 0
	byte  packet_type;
	byte  packet_flags;
	dword data_representation;
	word  frag_length;
	word  auth_length;
	dword call_id;
	word  max_xmit_frag;
	word  max_recv_frag;
	dword assoc_group;
	byte  num_context_items;
}  DCE_BIND_HEADER;
PACK_PRAGMA_POP
typedef DCE_BIND_HEADER RTSMB_FAR *PDCE_BIND_HEADER;

PACK_PRAGMA_ONE
typedef struct s_DCE_BIND_REPLY_HEADER
{
    byte  version;                // 5
    byte  version_minor;          // 0
	byte  packet_type;            //
	byte  packet_flags;
	dword data_representation;
	word  frag_length;
	word  auth_length;
	dword call_id;
	word  max_xmit_frag;
	word  max_recv_frag;
	dword assoc_group;
	word  secondary_address_length; // 13
	byte  secondary_address[14]; // "\PIPE\lsarpc" or "\PIPE\srvsvc"
	byte  num_results;           // 1
	// byte  results[24];           //  0x00,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00
    // \PIPE\ls_arpc'\0'[num_results[1byte][tranmitndrformrequest]]
}  DCE_BIND_REPLY_HEADER;
PACK_PRAGMA_POP
typedef DCE_BIND_HEADER RTSMB_FAR *PDCE_BIND_HEADER;


typedef struct s_DCE_HEADER
{
    byte  version;        // 5
    byte  version_minor;  // 0
	byte  packet_type;
	byte  packet_flags;
	dword data_representation;
	word  frag_length;
	word  auth_length;
	dword call_id;
	dword alloc_hint;
	word  context_id;
	word  opnum;
}  DCE_HEADER;
PACK_PRAGMA_POP
typedef DCE_HEADER RTSMB_FAR *PDCE_HEADER;

PACK_PRAGMA_ONE
typedef struct s_DCE_ENUM_REPLY_HEADER
{
    byte  version;        // 5
    byte  version_minor;  // 0
	byte  packet_type;
	byte  packet_flags;
	dword data_representation;
	word  frag_length;
	word  auth_length;
	dword call_id;
    /* end common fields */
    /* needed for request, response, fault */
	dword alloc_hint;
	word  context_id;

    /* data rep */
    /* needed for response or fault */
	byte  cancel_count;
	byte  pad;

	/* stub data here, 8-octet aligned

    /* optional authentication verifier */
    /* following fields present iff auth_length != 0 */
    // auth_verifier_co_t auth
}  DCE_ENUM_REPLY_HEADER,DCE_LSARP_POLICY2_REPLY;
PACK_PRAGMA_POP

PACK_PRAGMA_ONE
typedef struct s_DCE_LSARP_GET_USER_NAME_REPLY
{
    byte  version;        // 5
    byte  version_minor;  // 0
	byte  packet_type;
	byte  packet_flags;
	dword data_representation;
	word  frag_length;
	word  auth_length;
	dword call_id;
	dword alloc_hint;
	word  context_id;
	byte  cancel_count;
	byte  pad;
    /* end common fields */

} DCE_LSARP_GET_USER_NAME_REPLY;
PACK_PRAGMA_POP


PACK_PRAGMA_ONE
typedef struct s_DCE_LSARP_LOOKUP_NAMES_REPLY
{
    byte  version;        // 5
    byte  version_minor;  // 0
	byte  packet_type;
	byte  packet_flags;
	dword data_representation;
	word  frag_length;
	word  auth_length;
	dword call_id;
	dword alloc_hint;
	word  context_id;
	byte  cancel_count;
	byte  pad;
    /* end common fields */

} DCE_LSARP_LOOKUP_NAMES_REPLY;
PACK_PRAGMA_POP



//============================================================================
//    IMPLEMENTATION REQUIRED EXTERNAL REFERENCES (AVOID)
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE DATA
//============================================================================
//============================================================================
//    INTERFACE DATA
//============================================================================
//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTION PROTOTYPES
//============================================================================
static int SRVSVC_Execute (void *pTransaction_data, word *pRdata_count,void **pRheap_data,void **pRdata, dword *reply_status_code, rtsmb_size size_left);

//============================================================================
//    IMPLEMENTATION PRIVATE FUNCTIONS
//============================================================================



#define  DCE_PACKET_REQUEST                  0
#define  DCE_PACKET_REPLY                    2
#define DCE_PACKET_BIND                    11
#define DCE_PACKET_BIND_REPLY              12
#define DCE_PACKET_ENUM_ALL_SHARES         15
#define DCE_PACKET_ENUM_ALL_SHARES_REPLY   16

#define DCE_PACKET_GETSHARE_INFO            16

static const byte dce_bind_response_capture[] = {0x05,0x00,0x0c,0x03,0x10,0x00,0x00,0x00,0x44,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xb8,0x10,0xb8,0x10,0xf0,0x53,0x00,0x00,0x0d,0x00,0x5c,0x50,0x49,0x50,0x45,0x5c,0x73,0x72,0x76,0x73,0x76,0x63,0x00,0x00,
0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00};
static const byte bind_accepance_item[24] = { 0x00,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00};

//static const byte user_name_item[] = { 'e', 0, 'b', 0, 's', 0 };
//static const byte authority_name_item[] = { 'a', 0, 'u', 0, 't', 0, 'h', 0 };

//static const byte user_name_item[] = { peter };
//static const byte authority_name_item[] = { PETER-XPS-8300 };
static const byte user_name_item[] = { 'p',0,'e',0,'t',0,'e',0,'r',0 };
static const byte authority_name_item[] = { 'P',0,'E',0,'T',0,'E',0,'R',0,'-',0,'X',0,'P',0,'S',0,'-',0,'8',0,'3',0,'0',0,'0',0 };

static const byte my_sid[] = { 0x01,0x04, 0x00,0x00,0x00,0x00,0x00, 0x05, 0x15, 0x0,0x0, 0x0, 0x73, 0xf0, 0xb3, 0x58, 0xcd, 0x73, 0x43, 0xd9, 0x4f, 0x7b, 0xf9, 0x3e };


static const byte policy_handle[20] = {0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x00,0x00,0x00,0x01,0x02,0x03,0x04 };

#define DCE_LSARP_CLOSE               0
#define DCE_LSARP_GET_USER_NAME      45
#define DCE_LSARP_GET_OPEN_POLICY2   44
#define DCE_LSARP_LOOKUP_NAMES       14

extern const byte zeros24[24];


PACK_PRAGMA_ONE
typedef struct s_DCE_ARRAY_VALUES
{
	dword max_count;
	dword offset;
	dword actual_count;
	byte  actual_data[64];
}  DCE_ARRAY_VALUES;
PACK_PRAGMA_POP






//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================


// Interface used by ProcTransaction() to implement DCE trough the Proc interface (Mac)
int SRVSVC_ProcTransaction (PSMB_SESSIONCTX pCtx,
    PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{
   dword reply_status_code=0;

   if (pTransaction->setup_size == 2 && pTransaction->setup[0] == TRANS_TRANSACT_NMPIPE)
     ;
   else
     return -1;
   // Processing TRANS_TRANSACT_NMPIPE. pTransaction->setup[2] = fid;
   // pInBuf points at PIPE
   printf("Inside SRVSVC_ProcTransaction TRANS_TRANSACT_NMPIPE FID == %X\n", pTransaction->setup[1]);
   printf("Inside SRVSVC_ProcTransaction %X\n", pTransaction->setup[1]);

   pTransactionR->setup_size = 0;
   pTransactionR->parameter_count = 0;
   pTransactionR->heap_data = 0;


   return SRVSVC_Execute ( pTransaction->data, &pTransactionR->data_count, &pTransactionR->heap_data,&pTransactionR->data,&reply_status_code, size_left);

}

// Interface between stream and SrvSrvc, write performs the execute and allocates storage ans saves the rply
int SMBU_StreamWriteToSrvcSrvc (void *pIndata, rtsmb_size size_left,StreamtoSrvSrvc *pReturn)
{
   int r;
   word reply_data_count=0;
   void *rely_heap_data=0;
   void *rely_response_data=0;
   dword reply_status_code=0;
   r = SRVSVC_Execute (pIndata, &reply_data_count, &rely_heap_data,&rely_response_data,&reply_status_code, size_left);
   pReturn->reply_data_count    =reply_data_count;
   pReturn->reply_heap_data     =rely_heap_data;
   pReturn->reply_response_data =rely_response_data;
   pReturn->reply_status_code = reply_status_code;
   return r;
}



static int consume_full_dce_pointer(dword *pdata, dword *Referentid, dword *MaxCount, dword *Offset, dword *Length)
{
  int r=0;
  *Referentid = *pdata++;
  if (*Referentid == 0)
  {
    *MaxCount = *Offset = *Length = 0;
    r = 4;
  }
  else
  {
     if (*Referentid != 1)
       printf("DCE strange referent id :%X\n",*Referentid);
     *MaxCount = *pdata++;
      r = 8;
      if (*MaxCount)
      {
        *Offset   = *pdata++;
        *Length   = *pdata++;
        r = 16;
      }
  }
  return r;
}

//
//  Referentid:Length:Size:Referentid+4:MaxCount:Offset:Actual:String
//
//
//
//
//
//

static int encode_dce_string(dword *pout, dword Referentid, void *pin, word payload_size)
{
  int r=0;
  word *pwout;
  *pout++ = Referentid;             // Referentid:Length:Size:Referentid+4:MaxCount:Offset:Actual:String
   pwout = (word *) pout;
  *pwout++ = payload_size;           //            Length:Size:Referentid+4:MaxCount:Offset:Actual:String
  *pwout++ = payload_size;           //                   Size:Referentid+4:MaxCount:Offset:Actual:String
  pout++;
  Referentid += 4;
  *pout++ = Referentid;             //                        Referentid+4:MaxCount:Offset:Actual:String
  *pout++ = payload_size/2;           //                                      MaxCount:Offset:Actual:String
  *pout++ = 0;                      //                                               Offset:Actual:String
  *pout++ = payload_size/2;          //                                                       Actual:String
   memcpy(pout, pin, payload_size); //   Actual:String
   r = (int)payload_size+24;
   // If we null terminate the string ?
//   pwout = (word *) PADD(((void*)pout),payload_size);
//   *pwout = 0;
//   r = (int)payload_size+2+24;
   return r;
}


static int encode_dce_string_stupid(dword *pout, dword Referentid, void *pin, word payload_size)
{
  int r=0;
  *pout++ = Referentid;             // Referentid:Length:Size:Referentid+4:MaxCount:Offset:Actual:String
  *pout++ = (dword) payload_size/2;           //            Length:Size:Referentid+4:MaxCount:Offset:Actual:String
  *pout++ = (dword) 0;                     //                                              Offset:Actual:String
  *pout++ = (dword) payload_size/2;           //                   Size:Referentid+4:MaxCount:Offset:Actual:String
   memcpy(pout, pin, payload_size); //                                                       Actual:String
   r = (int)payload_size+16;
   return r;
}

static int encode_dce_string_pointer(dword *pout, dword Referentid, void *pin, word payload_size)
{
  int r=0;
  word *pwout;
  *pout++ = Referentid;             // Referentid:Length:Size:Referentid+4:MaxCount:Offset:Actual:String
   pwout = (word *) pout;
  *pwout++ = payload_size;           //            Length:Size:Referentid+4:MaxCount:Offset:Actual:String
  *pwout++ = payload_size;           //                   Size:Referentid+4:MaxCount:Offset:Actual:String
  pout++;
  r = 8 + encode_dce_string_stupid(pout, Referentid+4, pin, payload_size);
   return r;
}





// 0xC00000BB. STATUS_NOT_SUPPORTED
//
// Exectute a DCE request and return the reults inpRdata, pRdata_count. If the response is head, pRheap_data contains the base o the heap sectin to be freed.
//
// Implements the minimum we need to succesfully connect and basic share enumerate.
//   DCE_PACKET_BIND  - Return capture data
//   DCE_PACKET_ENUM_ALL_SHARES  - return live share data
//
//
static int SRVSVC_Execute (void *pTransaction_data, word *pRdata_count,void **pRheap_data,void **pRdata, dword *reply_status_code, rtsmb_size size_left)
{
PDCE_HEADER pdce_header;
int i;
int rval = -1;
int heap_size = 1024;
void *start;
printf("IN SRVSVC_Execute\n");

   *reply_status_code = 0;   // No errror

printf("!!!!!!! malloc\n");
    *pRheap_data = rtp_malloc(heap_size);
    pdce_header = (PDCE_HEADER) pTransaction_data;
    rtp_memset(*pRheap_data,0,heap_size);


    start = *pRheap_data;
    start= ptralign(start, 4);
    *pRdata_count = 0;
    *pRdata       = start;

    if (0 && pdce_header->packet_type == DCE_PACKET_BIND) // original SMBV1 code
    {  // Fake a bind reply from captured data
       // Make sure the call id is updated in the response
       PDCE_HEADER p = (PDCE_HEADER)dce_bind_response_capture;
       p->call_id = pdce_header->call_id;
//      pdw[3] =  pdce_header->call_id;
       *pRdata_count = sizeof(dce_bind_response_capture);
      memcpy(pRdata, dce_bind_response_capture,sizeof(dce_bind_response_capture));
      rval = 0;
    }
    else if (pdce_header->packet_type == DCE_PACKET_BIND)
    {
      word *pfraglength;
      void *start_results;
      DCE_BIND_HEADER *pin  = (DCE_BIND_HEADER *) pdce_header;
      DCE_BIND_REPLY_HEADER *pout;

      pout = (DCE_BIND_REPLY_HEADER *) start;

       // Fill the dce header
      pout->version = pin->version;        // 5
      pout->version_minor = pin->version_minor;  // 0
      pout->packet_type = DCE_PACKET_BIND_REPLY;                    // Response
      pout->packet_flags = pin->packet_flags;
      pout->data_representation = pin->data_representation;
      pout->frag_length       = 0; // sizeof(DCE_BIND_REPLY_HEADER);
      pfraglength             = &pout->frag_length;
      pout->auth_length = 0;
      pout->call_id = pin->call_id;
      pout->max_xmit_frag = 4280; // pin->max_xmit_frag;
      pout->max_recv_frag = 4280; // pin->max_recv_frag;
      pout->assoc_group = pin->assoc_group;
      pout->secondary_address_length = 13;
      strcpy(pout->secondary_address, "\\PIPE\\lsarpc"); //  or "\\PIPE\\srvsvc"
      pout->num_results = 1;           // 1
      pout += 1;
      start_results = (void *) pout;
      start_results= ptralign(start_results, 4);
      memcpy(start_results,bind_accepance_item ,24);           //  0x00,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00
      start_results=PADD(start_results,24);
     *pfraglength = PDIFF(start_results,start);
      *pRdata_count = *pfraglength; // sizeof(DCE_BIND_REPLY_HEADER);
      rval = 0;
     }
     else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_LSARP_CLOSE)
     {
       DCE_ENUM_REPLY_HEADER *pout;
       void *results;
       start = *pRheap_data;
       start= ptralign(start, 4);
       word *pfraglength;
       dword *pdw;
       pout = (DCE_ENUM_REPLY_HEADER *) start;

       pout->version              = pdce_header->version;
       pout->version_minor        = pdce_header->version_minor;   // 0
       pout->packet_type          = DCE_PACKET_REPLY;                    // Response
       pout->packet_flags         = pdce_header->packet_flags;
       pout->data_representation  = pdce_header->data_representation;
       pout->frag_length          = 0; // Fill this in later
       pfraglength                = &pout->frag_length;
       pout->auth_length          = 0;
       pout->call_id              = pdce_header->call_id;
       pout->alloc_hint           = 0;  // Supposed to be allowed to be zero
       pout->context_id           = pdce_header->context_id;
       pout->cancel_count         = 0;
       pout->pad                  = 0;
       pout += 1;
       results = (void *) pout;
       results= ptralign(results, 4);
       pdw = (dword *) results;
       *pdw++ =0; *pdw++ =0;  *pdw++ =0; // Handle is 20 bytes 00000000
       *pdw++ =0; *pdw++ =0;
       *pdw++ = 0; // NTstatus of zero
       *pfraglength  = PDIFF(pdw, start);
       *pRdata_count = *pfraglength;
       rval = 0;
     }
     else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_LSARP_GET_OPEN_POLICY2)
     {
       void *start;
       void *results;
       word *pfraglength;
       DCE_LSARP_GET_USER_NAME_REPLY *pout;
       start = *pRheap_data;
       start= ptralign(start, 4);
       pout = (DCE_LSARP_POLICY2_REPLY *) start;

//     NTSTATUS LsarOpenPolicy2(
//     [in, unique, string] wchar_t* SystemName,
//     [in] PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes,
//     [in] ACCESS_MASK DesiredAccess,
//     [out] LSAPR_HANDLE* PolicyHandle );

// LET serverInfo be a SERVER_INFO_101 structure CALL ServerGetInfo(101, &serverInfo)
// LET isDomainController be a boolean initialized to FALSE
// IF (serverInfo.sv101_version_type & (SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL))
// THEN Set isDomainController equal to TRUE END IF
// IF ((isDomainController equals FALSE) and (IsRequestorAnonymous() and LsaRestrictAnonymous is set to TRUE))
// THEN Return STATUS_ACCESS_DENIED END IF
       pout->version              = pdce_header->version;
       pout->version_minor        = pdce_header->version_minor;   // 0
       pout->packet_type          = DCE_PACKET_REPLY;                    // Response
       pout->packet_flags         = pdce_header->packet_flags;
       pout->data_representation  = pdce_header->data_representation;
       pout->frag_length          = 0; // Fill this in later
       pfraglength                = &pout->frag_length;
       pout->auth_length          = 0;
       pout->call_id              = pdce_header->call_id;
       pout->alloc_hint           = 0;  // Supposed to be allowed to be zero
       pout->context_id           = pdce_header->context_id;
       pout->cancel_count         = 0;
       pout->pad                  = 0;

       pout += 1;
       results = (void *) pout;
       results= ptralign(results, 4);
       memcpy(results, policy_handle,sizeof(policy_handle));
       results= PADD(results, sizeof(policy_handle));
       results= ptralign(results, 4);
       // NT error status zero
       *((dword *)results) =  0;
       results = PADD(results,4);
       *pfraglength  = PDIFF(results, start);
       *pRdata_count = *pfraglength;
       rval = 0;
     }
     else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_LSARP_LOOKUP_NAMES)
     {
       dword  MaxCount, Offset,Length;
       DCE_LSARP_LOOKUP_NAMES_REPLY *pout;
       void *results;
       dword *pdw;
       int l;
       word *pfraglength;
       dword *palloc_hint;
       word *pw;

       start = *pRheap_data;
       start= ptralign(start, 4);
       pout = ( DCE_LSARP_LOOKUP_NAMES_REPLY *) start;

       pout->version              = pdce_header->version;
       pout->version_minor        = pdce_header->version_minor;   // 0
       pout->packet_type          = DCE_PACKET_REPLY;                    // Response
       pout->packet_flags         = pdce_header->packet_flags;
       pout->data_representation  = pdce_header->data_representation;
       pout->frag_length          = 0; // Fill this in later
       pfraglength                = &pout->frag_length;
       pout->auth_length          = 0;
       pout->call_id              = pdce_header->call_id;
       pout->alloc_hint           = 0;  // Supposed to be allowed to be zero
       palloc_hint                = &pout->alloc_hint;
       pout->context_id           = pdce_header->context_id;
       pout->cancel_count         = 0;
       pout->pad                  = 0;

       pout += 1;
       results = (void *) pout;
       results= ptralign(results, 4);
       pdw = (dword *) results ;
       // Encode domains
       *pdw++ = 0x20004;
       *pdw++ = 1;        // count
       *pdw++ = 0x20008;  // pointer to domains
       *pdw++ = 32;       // max size
       *pdw++ =  1;        // Maxcount ??

       pw = (word *) pdw;
       *pw++ = sizeof(authority_name_item);            // len
       *pw =   sizeof(authority_name_item)+2;          // size
       pdw++;

       *pdw++ = 0x200c0;     // pointer to string
       *pdw++ = 0x20010;     // pointer to sid

       *pdw++ = sizeof(authority_name_item)/2 + 1;             // max count for string
       *pdw++ = 0;                                       //  offset for string
       *pdw++ = sizeof(authority_name_item)/2;           // actual for string
       memcpy(pdw, authority_name_item,sizeof(authority_name_item) ); // String
       results= PADD(pdw, sizeof(authority_name_item));
       results= ptralign(results, 4);
       pdw = (dword *) results;
       *pdw++ = 4;           // count for sid type
       memcpy(pdw, my_sid, sizeof(my_sid)); //   sid type

       results= (PADD(pdw, sizeof(my_sid)));
       results= ptralign(results, 4);
       pdw = (dword *) results;

       // Translated sids
       *pdw++ = 1;     // count
       *pdw++ = 0x20014;
       *pdw++ = 1;     // maxcount
       *pdw++ = 1;     // user
       *pdw++ = 0x3eb; // rid
       *pdw++ = 0;     // index

       *pdw++ = 1;     // count  WTF ??
       *pdw++ = 0;     // NT error status zero

       *pfraglength  = PDIFF(pdw, start);
       *palloc_hint  = *pfraglength - sizeof(DCE_LSARP_LOOKUP_NAMES_REPLY);
       *pRdata_count = *pfraglength;
        rval = 0;
     }
     else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_LSARP_GET_USER_NAME)
     {
       dword Referentid, MaxCount, Offset,Length;
       dword TossReferentid, TossMaxCount, TossOffset,TossLength;
       dword prevReferentid=0;
       dword * pdata = (dword *) (pdce_header + 1);
       int l;
       word *pfraglength;
       dword *palloc_hint;

       void *start;
       void *results;
       DCE_LSARP_GET_USER_NAME_REPLY *pout;

       pdata = ptralign(pdata, 4);

       start = *pRheap_data;
       start= ptralign(start, 4);
       pout = ( DCE_LSARP_GET_USER_NAME_REPLY *) start;

        // Consume the System name
        l =  consume_full_dce_pointer((dword *)pdata, &Referentid, &MaxCount, &Offset, &Length);
        pdata = PADD(pdata,l);
        if (Length)
       {
          rtsmb_dump_bytes("System name", pdata, Length*2, DUMPUNICODE);
          pdata = PADD(pdata,Length);
          pdata = ptralign(pdata, 4);
       }
        // Consume the Account name
        l =  consume_full_dce_pointer((dword *)pdata, &Referentid, &MaxCount, &Offset, &Length);
        pdata = PADD(pdata,l);
        if (Length)
        {
          rtsmb_dump_bytes("Account name", pdata, Length*2, DUMPUNICODE);
         pdata = PADD(pdata,Length);
          pdata = ptralign(pdata, 4);
        }
        // Consume the Authority name
        l =  consume_full_dce_pointer((dword *)pdata, &Referentid, &MaxCount, &Offset, &Length);
        pdata = PADD(pdata,l);
        if (Length)
        {
          rtsmb_dump_bytes("Authority name", pdata, Length*2, DUMPUNICODE);
          pdata = PADD(pdata,Length);
          pdata = ptralign(pdata, 4);
       }

       pout->version              = pdce_header->version;
       pout->version_minor        = pdce_header->version_minor;   // 0
       pout->packet_type          = DCE_PACKET_REPLY;                    // Response
       pout->packet_flags         = pdce_header->packet_flags;
       pout->data_representation  = pdce_header->data_representation;
       pout->frag_length          = 0; // Fill this in later
       pfraglength                = &pout->frag_length;
       pout->auth_length          = 0;
       pout->call_id              = pdce_header->call_id;
       pout->alloc_hint           = 0;  // Supposed to be allowed to be zero
       palloc_hint                = &pout->alloc_hint;
       pout->context_id           = pdce_header->context_id;
       pout->cancel_count         = 0;
       pout->pad                  = 0;

       pout += 1;
       results = (void *) pout;
       results= ptralign(results, 4);
       {
         // Encode user name
         dword Referentid = 0x20008;
         l = encode_dce_string((dword *)results, Referentid, user_name_item, sizeof(user_name_item));
         results = PADD(results,l);
         results= ptralign(results, 4);
         Referentid += 8;

         // Encode auth Referent and payload length/size
         *((dword *)results) =  Referentid;
         results = PADD(results,4);

         // Encode auth string
         Referentid += 4;
         l = encode_dce_string_pointer((dword *)results, Referentid, authority_name_item, sizeof(authority_name_item));
         results = PADD(results,l);
//         results= ptralign(results, 4);
       }
       // NT error status zero
       *((dword *)results) =  0;
       results = PADD(results,4);

       *pfraglength  = PDIFF(results, start);
       *palloc_hint  = *pfraglength - 24;
       *pRdata_count = *pfraglength;

       rval = 0;
     }
     else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_PACKET_GETSHARE_INFO)
     {
     dword len;
     dword * pdata = (dword *) (pdce_header + 1);
       pdata = ptralign(pdata, 4);
        printf("DCE_PACKET_GETSHARE_INFO  Referent id :%X\n",*pdata++);
        printf("DCE_PACKET_GETSHARE_INFO  max count   :%X\n",*pdata++);
        printf("DCE_PACKET_GETSHARE_INFO  offset      :%X\n",*pdata++);
        len = *pdata++;
        printf("DCE_PACKET_GETSHARE_INFO  actual count:%X\n",len);
        rtsmb_dump_bytes("DCE_PACKET_GETSHARE_INFO unc", pdata, len*2, DUMPUNICODE);
        pdata = (dword *) PADD(pdata,len*2);
        pdata = ptralign(pdata, 4);
        printf("DCE_PACKET_GETSHARE_INFO  max count   :%X\n",*pdata++);
        printf("DCE_PACKET_GETSHARE_INFO  offset      :%X\n",*pdata++);
        len = *pdata++;
        printf("DCE_PACKET_GETSHARE_INFO  actual count:%X\n",len);
        rtsmb_dump_bytes("DCE_PACKET_GETSHARE_INFO share:", pdata, len*2, DUMPUNICODE);
        pdata = (dword *) PADD(pdata,len*2);
        pdata = ptralign(pdata, 4);
        printf("DCE_PACKET_GETSHARE_INFO  level        :%X\n",*pdata);
        rval = 0;
     }
     else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_PACKET_ENUM_ALL_SHARES)
     {  // Fake a shares reply from captured data
        int total_shares = 0;
       PSR_RESOURCE pOutRes; // Share ierator
  //      PDCE_HEADER p = (PDCE_HEADER)dce_enum_response_capture;
        DCE_ENUM_REPLY_HEADER *p;
        void *start;
        dword *pdw;
        word *pfraglength;
        dword *pdwcount;
        dword *pdwmaxcount;
        dword rev_base =  0x0002000c;
        {
          // Calculate roughly how much heap we'll need for the response, add 512 byte to be super safe
         int heap_needed = 512;
          CLAIM_SHARE ();
          for(pOutRes = SR_FirstResource(); pOutRes != (PSR_RESOURCE)0; pOutRes = SR_NextResource(pOutRes))
          {
             heap_needed += 36; // Unique pointer and share type. plus max_count, offset, actual caount for conmetn and name
              heap_needed += 4*(rtsmb_len((PFCHAR)pOutRes->name)+1); // We only need 2X but take 4X in case we allso use the name as the comment
              heap_needed += 2*(rtsmb_len((PFCHAR)pOutRes->comment)+1);
          }
          RELEASE_SHARE();
          if (heap_needed > heap_size)
          {
            rtp_free(*pRheap_data);
            *pRheap_data = rtp_malloc(heap_needed);
          }
          start = *pRheap_data;
       }

       start= ptralign(start, 4);
       p = (DCE_ENUM_REPLY_HEADER *) start;

        // Fill the dce header

        p->version              = pdce_header->version;
        p->version_minor        = pdce_header->version_minor;   // 0
        p->packet_type          = DCE_PACKET_REPLY;                    // Response
        p->packet_flags         = pdce_header->packet_flags;
        p->data_representation  = pdce_header->data_representation;
        p->frag_length          = 0; // Fill this in later
        pfraglength             = &p->frag_length;
        p->auth_length          = 0;
        p->call_id              = pdce_header->call_id;
        p->alloc_hint           = 0;  // Supposed to be allowed to be zero
        p->context_id           = pdce_header->context_id;
        p->cancel_count         = 0;
        p->pad                  = 0;

        /* stub data here, 8-octet aligned */
        p++;                 // Add 24 and look at as a dword
        pdw = (dword *) ptralign(p,4);


        *pdw++ = 1;  // 0x01,0x00,0x00,0x00,                        // level 1
        *pdw++ = 1;  // 0x01,0x00,0x00,0x00,                        // srvsvc_NetShareCtr
        *pdw++ = rev_base; rev_base += 4; // 0x0c,0x00,0x02,0x00,                        // Referent -
        *pdw =  0;                                                       // Count
         pdwcount = pdw++;                                                 // Remember the address of count
        *pdw++ = rev_base; rev_base += 4; // 0x10,0x00,0x02,0x00,                        // Referent -
        *pdw = 0;                                                         // MaxCount
        pdwmaxcount = pdw++;;                                             // Remember the address of maxcount


       {
        CLAIM_SHARE ();
       for(pOutRes = SR_FirstResource(); pOutRes != (PSR_RESOURCE)0; pOutRes = SR_NextResource(pOutRes))
        {
            // Emit
            *pdw++ =  rev_base;     // Referent  points to sharename
            rev_base +=4;
            *pdw++ = pOutRes->stype;// Type, like disktree
            *pdw++ =  rev_base;     // Referent  points to comment
           rev_base +=4;
            total_shares++;
        }
        // 4 byte align the pointer
       pdw = (dword *)ptralign((void *)pdw,4);

        // pack each share into the buffer.
        for(pOutRes = SR_FirstResource(); pOutRes != (PSR_RESOURCE)0; pOutRes = SR_NextResource(pOutRes))
        {
            dword l;
            PFCHAR pstring;
           void *p;
            pstring = pOutRes->name;
            l = (rtsmb_len(pstring )+1);
            *pdw++=l; // p->max_count = unicode string length
           *pdw++=0; // p->dword offset;
    	      *pdw++=l; // p->dword actual_count;
            p = (void *)pdw;
            tc_memcpy(p, pstring, l*2);
            rtsmb_dump_bytes("SHARENAME", pstring , l*2, DUMPUNICODE);
            p = PADD(p, l*2);
            pdw = (dword *)ptralign(p,4);

            pstring = pOutRes->comment;
            l = rtsmb_len(pstring)+1;
            if (l==1)
           { // If no comment use the name as a comment
              pstring = pOutRes->name;
              l = (rtsmb_len(pstring)+1);
            }
            *pdw++=l; // p->max_count = ;
            *pdw++=0; // p->dword offset;
            *pdw++=l; // p->dword actual_count;
           rtsmb_dump_bytes("SHARECOMMENT", pstring, l*2, DUMPUNICODE);
            p = (void *)pdw;
            tc_memcpy(p, pstring, l*2);
            p = PADD(p, l*2);
           pdw = (dword *)ptralign(p,4);
        }
        RELEASE_SHARE();
       }
        *pdw++ = total_shares;                        // Pointer total entries
        *pdw++ =  rev_base;                         // Referent for resume handle
        rev_base +=4;
       *pdw++  =  0;                                // Resume handle
        *pdw++  =  0;                                // WERR_OK
        *pdwcount    = total_shares;
        *pdwmaxcount = total_shares;
        *pRdata_count = (word) PDIFF(pdw,start);
        *pfraglength = PDIFF(pdw,start);
         rval = 0;
     }
     else
     {
       printf("Unhandled dce\n");
       printf("packet_type  : %d\n",pdce_header->packet_type);
       printf("pdce_header->opnum : %d\n", pdce_header->opnum);

       rtp_free(*pRheap_data);
       *pRheap_data = 0;

       return 0; // Windows clients behave nicer like this is seems.
     }
printf("!!!!!!! DONE rval == %d\n", rval);
     if (rval == -1)
     {
       rtp_free(*pRheap_data);
       *pRheap_data = 0;
     }

     return rval;
}

/**

 Retrieval of policy settings by clients

To achieve the second scenario, only RPC methods
LsarOpenPolicy2 (section 3.1.4.4.1),
LsarOpenPolicy (section 3.1.4.4.2),
LsarQueryInformationPolicy2 (section 3.1.4.4.3),
LsarQueryInformationPolicy (section 3.1.4.4.4),
and LsarClose (section 3.1.4.9.4)
(and associated data structures specified in these method definitions) must be implemented by a listener of this protocol.

*/


//****************************************************************************
//**
//**    END MODULE SRVSVC.C
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */
