/*
|  __SMBSPNEGO.PPP -
|
|  EBS -
|
|
|  Copyright EBS Inc. , 2017
|  All rights reserved.
|  This code may not be redistributed in source or linkable object form
|  without the consent of its author.
*/
///

#ifndef __SMBSPNEGO_H__
#define __SMBSPNEGO_H__

// Module description:
// Deal with SPNEGO packets
//

#define MAX_OBJECT_PER_OUTPUT_STREAM 64
// Stream data type for encoding output buffer into streams and substreams and for fixing up variable length width fields
typedef struct spnego_output_stream_s {
  void  *context;
  bool resolving_widths;              // If true we are enumerating to calculate widths
  int  object_index;                  // index at this level of who we are
  int   object_count;                  // If resolving_widths phase is completed this is the maximum depth
#define OBJECT_WIDTH_UNRESOLVED 0x8000ul // ored in if we don't know it yet.
  dword  object_widths[MAX_OBJECT_PER_OUTPUT_STREAM];
  byte  *stream_base;
  byte  *stream_pointer;
  byte  *stream_end;
} spnego_output_stream_t;

#define SPNEGO_PACKET_TOO_LARGE -1
#define SPNEGO_OBJCOUNT_TOO_DEEP -2

// Stream data type for decoding input buffer into streams and substreams a pouplating decoded_toke structure from stream content.
typedef struct decode_token_stream_s {
  void  *decoded_token;  // Actually of typ decoded_init_token_t *.
  byte  *stream_base;
  byte  *stream_pointer;
  byte  *stream_next;
} decode_token_stream_t;


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

/// class SpnegoClient - Public methods and private helpers to implment ntlmv2 client over spnego
/// should be broken into a spnego base class and Client and server classes, will do when server it implemented.
class SpnegoClient : public local_allocator {
public:
  SpnegoClient() {}
  ~SpnegoClient() {}
public:
  int spnego_decode_NegTokenTarg_challenge(decoded_NegTokenTarg_challenge_t *decoded_targ_token, unsigned char *pinbuffer, size_t buffer_length);
  int spnego_get_client_ntlmv2_response_blob(byte *pblob);
  int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key);
  int spnego_encode_NegTokenInit_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key);
private: // messy catch all of private methods, all memory is allocated and freed through local_allocator::.
  int decode_token_stream_fetch_byte(decode_token_stream_t *pstream, byte *b);
  int decode_token_stream_fetch_length(decode_token_stream_t *pstream, size_t *l);
  int decode_token_stream_fetch_oid(decode_token_stream_t *pstream, byte *poid);
  unsigned long asn1_decode_length(unsigned char **ppbuffer);
  size_t asn1_calculate_width_of_width_field(unsigned long l);
  oid_t oid_string_to_oid_t(byte *pbuffer);
  unsigned char *asn1_encode_length(unsigned char *pbuffer,unsigned long l);
  void decode_token_stream_constructor(decode_token_stream_t *pstream,void  *decoded_token,byte  *stream_base, size_t stream_len);
  int decode_token_stream_fetch(decode_token_stream_t *pstream,byte  *fetch_buffer, size_t fetch_count);
  int decode_token_stream_fetch_obj(decode_token_stream_t *pstream, void *prv, asn1_objtype_t objtype);
  int decode_token_stream_fetch_flags(decode_token_stream_t *pstream, dword *pFlags);
  word *rtsmb_util_malloc_ascii_to_unicode (char *ascii_string);
  int decode_token_stream_fetch_word(decode_token_stream_t *pstream, word *w);
  int decode_token_stream_fetch_dword(decode_token_stream_t *pstream, dword *dw);
  int spnego_decode_NegTokenInit_packet(decoded_NegTokenInit_t *decoded_init_token, unsigned char *pinbuffer, size_t buffer_length);
  int _spnego_decode_NegTokenTarg_challenge(decoded_NegTokenTarg_challenge_t *decoded_targ_token, unsigned char *pinbuffer, size_t buffer_length);
  int _spnego_get_client_ntlmv2_response_blob(byte *pblob);
  word rtsmb_util_unicode_strlen(void *_str);
  int  decode_token_stream_encode_bytes(spnego_output_stream_t *pstream, void *_pb, size_t width);
  void decode_token_stream_encode_fixup_lengths(spnego_output_stream_t *pstream);
  int  decode_token_stream_encode_app_container(spnego_output_stream_t *pstream, byte Token);
  void spnego_output_stream_stream_constructor(spnego_output_stream_t *pstream,void  *context,byte  *stream_base, size_t stream_len,bool resolving_widths);

  int  decode_token_stream_encode_byte(spnego_output_stream_t *pstream, byte b);
  int  decode_token_stream_encode_length(spnego_output_stream_t *pstream, dword l);
  int  decode_token_stream_fetch_security_buffer(decode_token_stream_t *pstream, byte *blob_base, SecurityBuffer_t **_presource);

};

#endif /* __SMBSPNEGO_H__ */
