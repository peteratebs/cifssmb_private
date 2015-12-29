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

#define MAX_LEGAL_SECURITY_BUFFER_SIZE 512 // To protect against allocating huge buffers with bad values

#define SPNEGO_NO_ERROR           0
#define SPNEGO_NOT_INIT_PACKET   -1
#define SPNEGO_MALFORMED_PACKET  -2
#define SPNEGO_SYSTEM_ERROR      -3

// Encodings for what OID's were detected in a stream and should be encoded.
typedef enum {
  oid_none,
  oid_unkown,
  oid_spnego,
  oid_kerb5,
  oid_kerb5l,
  oid_ntlmssp
} oid_t;

// For instructing decoders what type of object to decode.
typedef enum {
  objtype_oid    = 0,
  objtype_length,
  objtype_bitstring,
} asn1_objtype_t;



// Structure populated by spnego_decode_NegTokenInit_packet() when a SETUP_ANDX packet containing a type1 NTLM security blob
typedef struct decoded_NegTokenInit_s {
 dword Flags;
 int   mechTypesCount;
 oid_t mechTypes[MAX_OID_COUNT];
 byte  *mechToken;    // null to start, allocated with malloc() and copied in if found and must be freed
 size_t mechTokenSize;  // 0 to start
 byte  *mechListMic;  // null to start, allocated with malloc() and copied in if found and must be freed
 size_t mechListMicSize;  // 0 to start
} decoded_NegTokenInit_t;



typedef struct SecurityBuffer_s {
  dword size;
  word  offset;
  byte  *value_at_offset;
} SecurityBuffer_t;

// Structure populated by spnego_decode_NegTokenTarg_packet() when a SETUP_ANDX packet containing a type3 NTLM security blob
typedef struct decoded_NegTokenTarg_s {
  dword Flags;
  SecurityBuffer_t *lm_response;
  SecurityBuffer_t *ntlm_response;
  SecurityBuffer_t *user_name;
  SecurityBuffer_t *domain_name;
  SecurityBuffer_t *host_name;
  SecurityBuffer_t *session_key;
} decoded_NegTokenTarg_t;


typedef struct ntlmv2_blob_s {

  byte  rversion ;             // 1 byte       ntlmssp.ntlmv2_response.rversion
  byte  hirversion;            // 1 byte       ntlmssp.ntlmv2_response.hirversion
  dword z1;                    // 4 bytes      ntlmssp.ntlmv2_response.z
  dword time_high;             // 8 bytes      ntlmssp.ntlmv2_response.time
  dword time_low;
  byte client_challenge[8];    // 8 bytes      ntlmssp.ntlmv2_response.chal
  dword z2;                    // 4 bytes      ntlmssp.ntlmv2_response.z
} ntlmv2_blob_t;

typedef struct ntlmv2_response_s {

  byte                  ntproofstr[16];         // 16 bytes      ntlmssp.ntlmv2_response.ntproofstr
  ntlmv2_blob_t         ntlmv2_blob;
} ntlmv2_response_t;

typedef struct decoded_NegTokenTarg_challenge_s {
    dword Flags;
    byte ntlmserverchallenge[8];
    SecurityBuffer_t *target_name;
    SecurityBuffer_t *target_info;
} decoded_NegTokenTarg_challenge_t;



void spnego_decoded_NegTokenInit_destructor(decoded_NegTokenInit_t *decoded_token);
int spnego_decode_NegTokenTarg_challenge(decoded_NegTokenTarg_challenge_t *decoded_targ_token, unsigned char *pinbuffer, size_t buffer_length);
void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token);
int spnego_decode_NegTokenInit_packet(decoded_NegTokenInit_t *decoded_init_token, unsigned char *pinbuffer, size_t buffer_length);
void spnego_decoded_NegTokenTarg_destructor(decoded_NegTokenTarg_t *decoded_token);
int spnego_decode_NegTokenTarg_packet(decoded_NegTokenTarg_t *decoded_token, unsigned char *pinbuffer, size_t buffer_length);
int spnego_get_negotiate_ntlmssp_blob(byte **pblob);
void spnego_get_Guid(byte *pGuid);
int spnego_encode_ntlm2_type2_response_packet(unsigned char *outbuffer, size_t buffer_length,byte *challenge);
int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key);
void spnego_init_extended_security(void);

int spnego_get_client_ntlmssp_negotiate_blob(byte **pblob);
