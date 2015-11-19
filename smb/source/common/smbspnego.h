//
// SMBSPNEGO.H -
//
// EBSnet - RTSMB
//
// Copyright EBSnet Inc. , 2003
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Deal with SPNEGO packets
//


#define NegTokenInit       0xa0
#define NegTokenTarg       0xa1
#define AppConstructObject 0x60

#define MAX_OID_SIZE 64
#define MAX_OID_COUNT 8

#define SPNEGO_NO_ERROR           0
#define SPNEGO_NOT_INIT_PACKET   -1
#define SPNEGO_MALFORMED_PACKET  -2
#define SPNEGO_SYSTEM_ERROR      -3


typedef enum {
  oid_none,
  oid_unkown,
  oid_spnego,
  oid_kerb5,
  oid_kerb5l,
  oid_ntlmssp
} oid_t;


#define MAX_OID_SIZE 64
#define MAX_OID_COUNT 8
typedef struct parsed_init_token_s {
 dword Flags;
 int   mechTypesCount;
 oid_t mechTypes[MAX_OID_COUNT];
 byte  *mechToken;    // null to start, allocated with malloc() and copied in if found and must be freed
 size_t mechTokenSize;  // 0 to start
 byte  *mechListMic;  // null to start, allocated with malloc() and copied in if found and must be freed
 size_t mechListMicSize;  // 0 to start
} parsed_init_token_t;

void parsed_neg_init_token_destructor(parsed_init_token_t *parsed_token);
int parse_spnego_init_packet(parsed_init_token_t *parsed_init_token, unsigned char *pinbuffer, size_t buffer_length);
int rtsmb_util_get_spnego_ntlmssp_blob(byte **pblob);
void rtsmb_util_get_new_Guid(byte *pGuid);
int rtsmb_util_get_spnego_other_blob(byte **pblob);
int encode_spnego_ntlm2_type2_response_packet(unsigned char *outbuffer, size_t buffer_length);


#define INCLUDE_RTSMB_EXTENDED_SECURITY 1
