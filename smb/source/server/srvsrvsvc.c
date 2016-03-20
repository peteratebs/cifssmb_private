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
}  DCE_ENUM_REPLY_HEADER;
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
static int SRVSVC_Execute (void *pTransaction_data, word *pRdata_count,void **pRheap_data,void **pRdata, rtsmb_size size_left);

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

static byte dce_bind_response_capture[] = {0x05,0x00,0x0c,0x03,0x10,0x00,0x00,0x00,0x44,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xb8,0x10,0xb8,0x10,0xf0,0x53,0x00,0x00,0x0d,0x00,0x5c,0x50,0x49,0x50,0x45,0x5c,0x73,0x72,0x76,0x73,0x76,0x63,0x00,0x00,
0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,0x02,0x00,0x00,0x00};


static byte dce_enum_response_capture_ram[512];


PACK_PRAGMA_ONE
typedef struct s_DCE_ARRAY_VALUES
{
	dword max_count;
	dword offset;
	dword actual_count;
	byte  actual_data[64];
}  DCE_ARRAY_VALUES;
PACK_PRAGMA_POP



static void *ptralign(void *ptr, int a)
{
 ddword dd = (ddword) ptr;
 ddword s = (ddword)(a-1);
 dd=(dd+s)&~s;
 return (void *) dd;
}



//============================================================================
//    INTERFACE FUNCTIONS
//============================================================================


// Interface used by ProcTransaction() to implement DCE trough the Proc interface (Mac)
int SRVSVC_ProcTransaction (PSMB_SESSIONCTX pCtx,
    PRTSMB_HEADER pInHdr, PRTSMB_TRANSACTION pTransaction, PFVOID pInBuf,
    PRTSMB_HEADER pOutHdr, PRTSMB_TRANSACTION_R pTransactionR, rtsmb_size size_left)
{

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


   return SRVSVC_Execute ( pTransaction->data, &pTransactionR->data_count, &pTransactionR->heap_data,&pTransactionR->data, size_left);

}

// Interface between stream and SrvSrvc, write performs the execute and allocates storage ans saves the rply
int SMBU_StreamWriteToSrvcSrvc (void *pIndata, rtsmb_size size_left,StreamtoSrvSrvc *pReturn)
{
   int r;
   word reply_data_count=0;
   void *rely_heap_data=0;
   void *rely_response_data=0;
   r = SRVSVC_Execute (pIndata, &reply_data_count, &rely_heap_data,&rely_response_data, size_left);
   pReturn->reply_data_count    =reply_data_count;
   pReturn->reply_heap_data     =rely_heap_data;
   pReturn->reply_response_data =rely_response_data;
   return r;
}



//
// Exectute a DCE request and return the reults inpRdata, pRdata_count. If the response is head, pRheap_data contains the base o the heap sectin to be freed.
//
// Implements the minimum we need to succesfully connect and basic share enumerate.
//   DCE_PACKET_BIND  - Return capture data
//   DCE_PACKET_ENUM_ALL_SHARES  - return live share data
//
//
static int SRVSVC_Execute (void *pTransaction_data, word *pRdata_count,void **pRheap_data,void **pRdata, rtsmb_size size_left)
{
PDCE_HEADER pdce_header;
int i;

   pdce_header = (PDCE_HEADER) pTransaction_data;

   *pRheap_data  = 0;
   *pRdata       = 0;
   *pRdata_count = 0;

   if (pdce_header->packet_type == DCE_PACKET_BIND)
   {  // Fake a bind reply from captured data
      // Make sure the call id is updated in the response
      PDCE_HEADER p = (PDCE_HEADER)dce_bind_response_capture;
      p->call_id = pdce_header->call_id;
//      pdw[3] =  pdce_header->call_id;
      *pRdata_count = sizeof(dce_bind_response_capture);
      *pRdata       = dce_bind_response_capture;
      return 0;
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
      return 0;
   }
   else if (pdce_header->packet_type == DCE_PACKET_REQUEST && pdce_header->opnum == DCE_PACKET_ENUM_ALL_SHARES)
   {  // Fake a shares reply from captured data
      int total_shares = 0;
      PSR_RESOURCE pOutRes; // Share ierator
//      PDCE_HEADER p = (PDCE_HEADER)dce_enum_response_capture;
      DCE_ENUM_REPLY_HEADER *p;
      void *start = dce_enum_response_capture_ram;
      dword *pdw;
      dword *pfraglength;
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
        *pRheap_data = rtp_malloc(heap_needed);
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
       *pRdata       = start;
      *pfraglength = PDIFF(pdw,start);

       return 0;
   }
   else
   {
     printf("Unhandled dce\n");
     printf("packet_type  : %d\n",pdce_header->packet_type);
     printf("pdce_header->opnum : %d\n", pdce_header->opnum);
     return 0; // Windows clients behave nicer lijke this is seems.
   }

   return -1;
}




//****************************************************************************
//**
//**    END MODULE SRVSVC.C
//**
//****************************************************************************

#endif /* INCLUDE_RTSMB_SERVER */
