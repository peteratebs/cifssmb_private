//
// smb2createcontext.cpp -
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
#include "mswireobjects.hpp"

#define SMB_NTOHD(X) X // bogus

const unsigned char pMxAc_info_response[] =
{
 0x00,0x00,0x00,0x00, 0x10,0x00,0x04,0x00,
 0x00,0x00,0x18,0x00,0x08,0x00,0x00,0x00,
 0x4d,0x78,0x41,0x63,0x00,0x00,0x00,0x00,
 0x00,0x00,0x00,0x00,0x27,0x00,0x01,0x00};

//0xff,0x01,0x1f, 0x00,}; // pMxAc Access mask


const unsigned char pQfid_info_response[] = {
 0x00,0x00,0x00,0x00,0x10,0x00,0x04,0x00,
 0x00,0x00,0x18,0x00,0x20,0x00,0x00,0x00,
 0x51,0x46,0x69,0x64,0x00,0x00,0x00,0x00,

 0x9e,0x3b,0x06,0x00,0x00,0x00,0x00,0x00,       // Volume 16 bytes
 0x00,0xfc,0x00,0x00,0x00,0x00,0x00,0x00,       // File handle to the open file
 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

// Note leading 4 bytes are 0x20 00 00 00 , which is "next"
const unsigned char pMxAc_and_pQfid_info_response[] = {
 0x20,0x00,0x00,0x00,0x10,0x00,0x04,0x00,
 0x00,0x00,0x18,0x00,0x08,0x00,0x00,0x00,
 0x4d,0x78,0x41,0x63,0x00,0x00,0x00,0x00,
 0x00,0x00,0x00,0x00, 0xff,0x01,0x1f,0x00, //
 0x00,0x00,0x00,0x00,0x10,0x00,0x04,0x00,
 0x00,0x00,0x18,0x00,0x20,0x00,0x00,0x00,
 0x51,0x46,0x69,0x64,0x00,0x00,0x00,0x00,
 0x9e,0x3b,0x06,0x00,0x00,0x00,0x00,0x00,
 0x00,0xfc,0x00,0x00,0x00,0x00,0x00,0x00,
 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

#include "rtptime.h"

#define MAX_CREATE_CONTEXT_LENGTH_TOTAL 512 // Don't need much, mostly 4 byte values
typedef struct s_RTSMB2_CREATE_CONTEXT_WIRE {
  dword Next;
  word NameOffset;
  dword NameLength;
  word  DataOffset;
  dword DataLength;
  byte Buffer[1];
} RTSMB2_CREATE_CONTEXT_WIRE;

typedef RTSMB2_CREATE_CONTEXT_WIRE  *PRTSMB2_CREATE_CONTEXT_WIRE;


#define MAX_CREATE_CONTEXTS_ON_WIRE 16 // Should be plenty
typedef struct s_RTSMB2_CREATE_CONTEXT_INTERNAL {
  byte *p_context_entry_wire; // Pointer to raw wire record
  dword NameDw;                                     // 4 byte name from p_context_entry_wire->NameOffset (will be a problem for 3.X names. Will need to encode those larger names into internale handle names
  word  Reserved;                                   // Nul terminates name so we can print it as a string
  byte * p_payload;                                 // pointer to data of length p_context_entry_wire->DataLength
} RTSMB2_CREATE_CONTEXT_INTERNAL;
typedef RTSMB2_CREATE_CONTEXT_INTERNAL  *PRTSMB2_CREATE_CONTEXT_INTERNAL;


typedef struct s_RTSMB2_CREATE_DECODED_CREATE_CONTEXTS {
  PRTSMB2_CREATE_CONTEXT_INTERNAL pExtA;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pSecD;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDHnQ;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDHnC;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pAISi;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pMxAc;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pTWrp;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pQFid;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pRqLs;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pRq2s;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDH2Q;
  PRTSMB2_CREATE_CONTEXT_INTERNAL pDH2C;
  int n_create_context_request_values;                         // Return value, number of valid create contexts decoded
  dword error_code;                                            // Return value, error code if any problems were detected
  RTSMB2_CREATE_CONTEXT_INTERNAL context_values[MAX_CREATE_CONTEXTS_ON_WIRE];
} RTSMB2_CREATE_DECODED_CREATE_CONTEXTS;
typedef RTSMB2_CREATE_DECODED_CREATE_CONTEXTS  *PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS;

#define RTSMB2_CREATE_CONTEXT_WIRE_SIZE (sizeof(RTSMB2_CREATE_CONTEXT_WIRE)-1) // -1 because buffer is optional

static int _decode_create_context_request_values(PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS pdecoded_create_context, byte * pcreate_context_buffer, int create_context_buffer_length);


// Windows starts with "DHnQ","MxAc","QFid" on the root of the tree


#define SMB2_CREATE_EA_BUFFER                    0x45787441   // "ExtA"  The data contains the extended attributes that MUST be stored on the created file. This value MUST NOT be set for named pipes and print files.
#define SMB2_CREATE_SD_BUFFER                    0x53656344   // "SecD"  The data contains a security descriptor that MUST be stored on the created file.   This value MUST NOT be set for named pipes and print files.
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST       0x44486e51   // "DHnQ"  The client is requesting the open to be durable (see section 3.3.5.9.6).
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT     0x44486e43   // "DHnC"  The client is requesting to reconnect to a durable open after being disconnected (see section 3.3.5.9.7).
#define SMB2_CREATE_ALLOCATION_SIZE              0x416c5369   // "AISi"  The data contains the required allocation size of the newly created file.
#define SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST 0x4d784163   // "MxAc"  The client is requesting that the server return maximal access information.
#define SMB2_CREATE_TIMEWARP_TOKEN               0x54577270   // "TWrp"  The client is requesting that the server open an earlier version of the file identified by the provided time stamp.
#define SMB2_CREATE_QUERY_ON_DISK_ID             0x51466964   // "QFid"  The client is requesting that the server return a 32-byte opaque BLOB that uniquely identifies the file being opened on disk. No data is passed to the server by the client.
#define SMB2_CREATE_REQUEST_LEASE                0x52714c73   // "RqLs"  SMB2.1 and above
#define SMB2_CREATE_REQUEST_LEASE_V2             0x52713273   // "Rq2s"  may be a typo In SMB2 spec as 0x52714c73
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2    0x44483251   // "DH2Q"  SMB3.X
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2  0x44483243   // "DH2C"  SMB3.X
#define SMB2_CREATE_APP_INSTANCE_ID              0x45BCA66A   // EFA7F74A9008FA462E144D74 SMB3.X
#define SMB2_CREATE_APP_INSTANCE_VERSION         0xB982D0B7   // 3B56074FA07B524A8116A010 SMB3.X
#define SVHDX_OPEN_DEVICE_CONTEXT                0x9CCBCF9E   // 04C1E643980E158DA1F6EC83 SMB3.X


static void dump_decoded_create_context_request_values(PRTSMB2_CREATE_CONTEXT_INTERNAL p_decoded_create_context_request_values,int n_create_context_request_values);

// int decode_create_context_request_values(PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS pdecoded_create_context, byte * pcreate_context_buffer, int create_context_buffer_length);
RTSMB2_CREATE_DECODED_CREATE_CONTEXTS s_decoded_create_context;

int decode_create_context_request_values( byte * pcreate_context_buffer, int create_context_buffer_length)
{
PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS pdecoded_create_context;
 return _decode_create_context_request_values(&s_decoded_create_context, pcreate_context_buffer, create_context_buffer_length);
}

static int _decode_create_context_request_values(PRTSMB2_CREATE_DECODED_CREATE_CONTEXTS pdecoded_create_context, byte * pcreate_context_buffer, int create_context_buffer_length)
{
PRTSMB2_CREATE_CONTEXT_INTERNAL p_current_value=&pdecoded_create_context->context_values[0];
byte *p_current_context_onwire = (byte *) pcreate_context_buffer;
byte * p_current_create_context_buffer=pcreate_context_buffer;
int current_create_context_buffer_length = create_context_buffer_length;
byte * p_data_buffer_end = pcreate_context_buffer + create_context_buffer_length;

  ms_RTSMB2_CREATE_CONTEXT_WIRE Createcontext;


//  Createcontext.Next;
//  Createcontext.NameOffset;
//  Createcontext.NameLength;
//  Createcontext.DataOffset;
//  Createcontext.DataLength;


  memset(pdecoded_create_context,0,sizeof(*pdecoded_create_context));
  while (current_create_context_buffer_length>=Createcontext.PackedStructureSize())
  {
    bool is_error_record = false;
    bool take_next_record = true;
    p_current_value=&pdecoded_create_context->context_values[pdecoded_create_context->n_create_context_request_values];

      Createcontext.bindpointers(p_current_context_onwire);
      memset(p_current_value, 0, sizeof(*p_current_value));

      if (Createcontext.NameOffset() < RTSMB2_CREATE_CONTEXT_WIRE_SIZE)
      {
         // Error condition
         is_error_record = true;
         take_next_record = false;
      }
      else if (Createcontext.NameLength() != 4)
      {
         take_next_record = false;
      }
      else
      {
         byte * pName;
         pName=Createcontext.FixedStructureAddress() + Createcontext.NameOffset();

         NetWiredword NameDw;
         NameDw.bindaddress(pName);
         p_current_value->NameDw = NameDw();
         p_current_value->p_context_entry_wire=pName;

         switch (p_current_value->NameDw)
         {
            case SMB2_CREATE_EA_BUFFER                    :   // "ExtA"  The data contains the extended attributes that MUST be stored on the created file. This value MUST NOT be set for named pipes and print files.
              pdecoded_create_context->pExtA = p_current_value;
            break;
            case SMB2_CREATE_SD_BUFFER                    :   // "SecD"  The data contains a security descriptor that MUST be stored on the created file.   This value MUST NOT be set for named pipes and print files.
              pdecoded_create_context->pSecD = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_REQUEST       :   // "DHnQ"  The client is requesting the open to be durable (see section 3.3.5.9.6).
              pdecoded_create_context->pDHnQ = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_RECONNECT     :   // "DHnC"  The client is requesting to reconnect to a durable open after being disconnected (see section 3.3.5.9.7).
              pdecoded_create_context->pDHnC = p_current_value;
            break;
            case SMB2_CREATE_ALLOCATION_SIZE              :   // "AISi"  The data contains the required allocation size of the newly created file.
              pdecoded_create_context->pAISi = p_current_value;
            break;
            case SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST :   // "MxAc"  The client is requesting that the server return maximal access information.
              pdecoded_create_context->pMxAc = p_current_value;
            break;
            case SMB2_CREATE_TIMEWARP_TOKEN               :   // "TWrp"  The client is requesting that the server open an earlier version of the file identified by the provided time stamp.
              pdecoded_create_context->pTWrp = p_current_value;
            break;
            case SMB2_CREATE_QUERY_ON_DISK_ID             :   // "QFid"  The client is requesting that the server return a 32-byte opaque BLOB that uniquely identifies the file being opened on disk. No data is passed to the server by the client.
              pdecoded_create_context->pQFid = p_current_value;
            break;
            case SMB2_CREATE_REQUEST_LEASE                :   // "RqLs"  SMB2.1 and above
              pdecoded_create_context->pRqLs = p_current_value;
            case SMB2_CREATE_REQUEST_LEASE_V2             :   // "Rq2s"  may be a typo In SMB2 spec as 0x52714c73
              pdecoded_create_context->pRq2s = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2    :   // "DH2Q"  SMB3.X
              pdecoded_create_context->pDH2Q = p_current_value;
            break;
            case SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2  :   // "DH2C"  SMB3.X
              pdecoded_create_context->pDH2C = p_current_value;
            break;
            case SMB2_CREATE_APP_INSTANCE_ID              :   // EFA7F74A9008FA462E144D74 SMB3.X
            case SMB2_CREATE_APP_INSTANCE_VERSION         :   // 3B56074FA07B524A8116A010 SMB3.X
            case SVHDX_OPEN_DEVICE_CONTEXT                :   // 04C1E643980E158DA1F6EC83 SMB3.X
            default:
              take_next_record = false;
            break;
         }
         if (take_next_record)
         {
           if (Createcontext.DataLength())
            {
             byte * b= (byte * )Createcontext.FixedStructureAddress();
             p_current_value->p_payload = b + Createcontext.DataOffset();
             if (p_current_value->p_payload >= p_data_buffer_end)
             {
               // Error condition
               is_error_record = true;
             }
           }
           pdecoded_create_context->n_create_context_request_values += 1;
           if (pdecoded_create_context->n_create_context_request_values == MAX_CREATE_CONTEXTS_ON_WIRE)
             goto error_return;
         }
         if (Createcontext.Next()==0)
            break;
         else
         {
         byte * pv;
         int delta;
            byte * b= (byte * )Createcontext.FixedStructureAddress(); // p_current_context_onwire;
            pv= b + Createcontext.Next();
            delta = (int)(pv-b);
            if (current_create_context_buffer_length>=delta)
            {
              current_create_context_buffer_length -= delta;
              p_current_context_onwire = pv;
            }
            else
            {
              is_error_record = true;
              current_create_context_buffer_length = 0;
            }
         }
      }
      if (is_error_record)
        goto error_return;
  } //   while (current_create_context_buffer_length>=RTSMB2_CREATE_CONTEXT_WIRE_SIZE)

  return pdecoded_create_context->n_create_context_request_values;
error_return:
  dump_decoded_create_context_request_values(pdecoded_create_context->context_values,pdecoded_create_context->n_create_context_request_values);
  return -1;
}

static void dump_decoded_create_context_request_values(PRTSMB2_CREATE_CONTEXT_INTERNAL p_decoded_create_context_request_values,int n_create_context_request_values)
{
#if(0)
int i;
  printf("dump_decoded_create_context_request_values NValues == : %d\n", n_create_context_request_values);
  for (i = 0; i < n_create_context_request_values; i++)
  {
    printf("Name: %X, \"%s\"\n", p_decoded_create_context_request_values[i].NameDw, (char *) &p_decoded_create_context_request_values[i].NameDw);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->NameOffset: %x\n",  p_decoded_create_context_request_values[i].p_context_entry_wire->NameOffset);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->NameLength: %d\n",  p_decoded_create_context_request_values[i].p_context_entry_wire->NameLength);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->DataOffset: %x\n",  p_decoded_create_context_request_values[i].p_context_entry_wire->DataOffset);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->DataLength: %d\n", p_decoded_create_context_request_values[i].p_context_entry_wire->DataLength);
    printf("p_decoded_create_context_request_values[i].p_context_entry_wire->p_payload: %X\n", p_decoded_create_context_request_values[i].p_payload);
  }
#endif
}



