//
// smb2logon.cpp -
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
#include "smb2defs.hpp"
#include "smb2socks.hpp"
#include "netstreambuffer.hpp"
#include "wireobjects.hpp"
#include "smb2wireobjects.hpp"
#include "mswireobjects.hpp"
#include "session.hpp"
#include "smb2socks.hpp"
#include "smb2spnego.hpp"

//
// SMBSPNEGO.C -
//
// EBS - RTSMB
//
// Copyright EBS Inc. , 2015
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Deal with SPNEGO packets
//

// int    spnego_decode_NegTokenInit_packet(decoded_NegTokenInit_t *decoded_init_token, unsigned char *pinbuffer, size_t buffer_length)
// void   spnego_decoded_NegTokenInit_destructor(decoded_NegTokenInit_t *decoded_token)
// void   spnego_decoded_NegTokenTarg_destructor(decoded_NegTokenTarg_t *decoded_targ_token)
// int    spnego_get_negotiate_ntlmssp_blob(byte **pblob)


// OIDs
static const byte SPNEGO[] =  {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};   // 1.3.6.1.5.5.2
static const byte KERBV5[] =  {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}; // 1.2.840.113554.1.2.2
static const byte KERBV5L[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}; // 1.2.840.48018.1.2.2
static const byte NTLMSSP[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};   // 1.3.6.1.4.1.311.2.2.10

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


// NTLM_RESP_FLAGS

#define NEGOTIATE_56                (1Ull << 31)
#define NEGOTIATE_KEYEX             (1Ull << 30)
#define NEGOTIATE_128               (1Ull << 29)
#define NEGOTIATE_XX0               (1Ull << 28)
#define NEGOTIATE_XX1               (1Ull << 27)
#define NEGOTIATE_XX2               (1Ull << 26)
#define NEGOTIATE_VERSION           (1Ull << 25)
#define NEGOTIATE_XX3               (1Ull << 24)
#define NEGOTIATE_TARGINFO          (1Ull << 23)
#define NEGOTIATE_NONNT             (1Ull << 22)
#define NEGOTIATE_XX3A              (1Ull << 21)
#define NEGOTIATE_IDENTITY          (1Ull << 20)
#define NEGOTIATE_EXTENDED_SECURITY (1Ull << 19)
#define NEGOTIATE_TYPE_SHARE        (1Ull << 18)
#define NEGOTIATE_TYPE_SERVER       (1Ull << 17)
#define NEGOTIATE_TYPE_DOMAIN       (1Ull << 16)
#define NEGOTIATE_ALWAYS_SIGN       (1Ull << 15)
#define NEGOTIATE_XX4               (1Ull << 14)
#define NEGOTIATE_OEM_WS_SUPPLIED   (1Ull << 13)
#define NEGOTIATE_OEM_DOM_SUPPLIED  (1Ull << 12)
#define NEGOTIATE_ANONYMOUS         (1Ull << 11)
#define NEGOTIATE_NT_ONLY           (1Ull << 10)
#define NEGOTIATE_NTLM_KEY          (1Ull << 9)
#define NEGOTIATE_XX5               (1Ull << 8)
#define NEGOTIATE_LAN_MAN           (1Ull << 7)
#define NEGOTIATE_DATAGRAM          (1Ull << 6)
#define NEGOTIATE_SEAL              (1Ull << 5)
#define NEGOTIATE_SIGN              (1Ull << 4)
#define NEGOTIATE_XX6               (1Ull << 3)
#define NEGOTIATE_REQUEST_TARGET    (1Ull << 2)
#define NEGOTIATE_NEGOTIATE_OEM     (1Ull << 1)
#define NEGOTIATE_NEGOTIATE_UNICODE (1Ull << 0)

  // NEGOTIATE_LAN_MAN was NEGOTIATE_NTLM_KEY

#define TYPICAL_WINDOWS_NTLM_RESP_FLAGS \
    NEGOTIATE_56               |\
    NEGOTIATE_KEYEX            |\
    NEGOTIATE_128              |\
    NEGOTIATE_VERSION          |\
    NEGOTIATE_TARGINFO         |\
    NEGOTIATE_EXTENDED_SECURITY|\
    NEGOTIATE_TYPE_SERVER      |\
    NEGOTIATE_ALWAYS_SIGN      |\
    NEGOTIATE_NTLM_KEY         |\
    NEGOTIATE_SIGN             |\
    NEGOTIATE_REQUEST_TARGET   |\
    NEGOTIATE_NEGOTIATE_UNICODE

//     NEGOTIATE_KEYEX            | removed
//     NEGOTIATE_NTLM_KEY         | made exclusive of NEGOTIATE_EXTENDED_SECURITY

#if (HARDWIRED_INCLUDE_NTLM2_IN_CHALLENGE==1)
#define DO_NEGOTIATE_EXTENDED_SECURITY NEGOTIATE_EXTENDED_SECURITY |NEGOTIATE_KEYEX|NEGOTIATE_NTLM_KEY
#else
#define DO_NEGOTIATE_EXTENDED_SECURITY 0
#endif
#define DEFAULT_NTLM_RESP_FLAGS \
    NEGOTIATE_56               |\
    NEGOTIATE_128              |\
    NEGOTIATE_VERSION          |\
    NEGOTIATE_TARGINFO         |\
    NEGOTIATE_TYPE_SERVER      |\
    DO_NEGOTIATE_EXTENDED_SECURITY|\
    NEGOTIATE_REQUEST_TARGET   |\
    NEGOTIATE_NEGOTIATE_UNICODE

static const dword spnego_flags = DEFAULT_NTLM_RESP_FLAGS; // Should be 0x15828ae2;

// Constant fragments needed for packet construction
// these are const buty the compiler complains about passing them if declared const
static /*const*/ byte ntlm_challenge_blob[] =  {
0xA0, 0x03, 0x0A, 0x01,0x01, // Element 0 0xA0(l=3, val= negResult 0x0A(l=1,val=1) accept incomplete (0,1,2) see below
0xa1, 0xc,                   // Element 1 0xA0(l=12, val=supportedMech NTLM
0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}; // NTLM 1.3.6.1.4.1.311.2.2.10};
static /*const*/ char ntlmssp_str[] = "NTLMSSP";
static /*const*/ byte ntlm_reserved[] = {0x0 , 0x0 ,0x0 ,0x0 ,0x0 ,0x0 ,0x0, 0x0};         // zeros
static /*const*/ byte ntlm_version[] = {0x06 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x0f};   // Version 6.1 (Build 0); NTLM Current Revision 15


// ================================================================================================================================
//
// Temporary solution for EXTENDED security passwords domain names etc. TBD
//
typedef struct target_config_unicode_str_s
{
  word *target_name;
  word *netbios_domain_name;
  word *netbios_computer_name;
  word *dns_domain_name;
  word *dns_computer_name;
} target_config_unicode_str_t;

typedef struct target_config_ascii_str_s
{
  char *target_name;
  char *netbios_domain_name;
  char *netbios_computer_name;
  char *dns_domain_name;
  char *dns_computer_name;
} target_config_ascii_str_t;

#define HARDWIRED_TARGET_NAME       "VBOXUNBUNTU"
#define HARDWIRED_NBDOMAIN_NAME     "DOMAIN"
#define HARDWIRED_NBCOMPUTER_NAME   "NETBIOSCOMPUTERAME"
#define HARDWIRED_DNSDOMAIN_NAME    "DNSDOMAINNAME"
#define HARDWIRED_DNSCOMPUTER_NAME  "DNSCOMPUTERAME"

target_config_ascii_str_t target_config_ascii =
{
  (char *)HARDWIRED_TARGET_NAME     ,
  (char *)HARDWIRED_NBDOMAIN_NAME   ,
  (char *)HARDWIRED_NBCOMPUTER_NAME ,
  (char *)HARDWIRED_DNSDOMAIN_NAME  ,
  (char *)HARDWIRED_DNSCOMPUTER_NAME,
};

target_config_unicode_str_t target_config_unicode;

// ================================================================================================================================


static int decode_token_stream_fetch_byte(decode_token_stream_t *pstream, byte *b);
static int decode_token_stream_fetch_length(decode_token_stream_t *pstream, size_t *l);
static int decode_token_stream_fetch_oid(decode_token_stream_t *pstream, byte *poid);
static int decode_token_stream_fetch_byte(decode_token_stream_t *pstream, byte *b);
static unsigned long asn1_decode_length(unsigned char **ppbuffer);
static size_t asn1_calculate_width_of_width_field(unsigned long l);
static oid_t oid_string_to_oid_t(byte *pbuffer);
static unsigned char *asn1_encode_length(unsigned char *pbuffer,unsigned long l);
static void decode_token_stream_constructor(decode_token_stream_t *pstream,void  *decoded_token,byte  *stream_base, size_t stream_len);
static int decode_token_stream_fetch(decode_token_stream_t *pstream,byte  *fetch_buffer, size_t fetch_count);
static int decode_token_stream_fetch_obj(decode_token_stream_t *pstream, void *prv, asn1_objtype_t objtype);
static int decode_token_stream_fetch_flags(decode_token_stream_t *pstream, dword *pFlags);
static word *rtsmb_util_malloc_ascii_to_unicode (char *ascii_string);
static int decode_token_stream_fetch_word(decode_token_stream_t *pstream, word *w);
static int decode_token_stream_fetch_dword(decode_token_stream_t *pstream, dword *dw);



// Make sure the unicode versions name, domain etc of are loaded and any other extended security initialization
void spnego_init_extended_security(void)
{
  target_config_unicode.target_name            =  rtsmb_util_malloc_ascii_to_unicode (target_config_ascii.target_name          );
  target_config_unicode.netbios_domain_name    =  rtsmb_util_malloc_ascii_to_unicode (target_config_ascii.netbios_domain_name  );
  target_config_unicode.netbios_computer_name  =  rtsmb_util_malloc_ascii_to_unicode (target_config_ascii.netbios_computer_name);
  target_config_unicode.dns_domain_name        =  rtsmb_util_malloc_ascii_to_unicode (target_config_ascii.dns_domain_name      );
  target_config_unicode.dns_computer_name      =  rtsmb_util_malloc_ascii_to_unicode (target_config_ascii.dns_computer_name    );
}

void spnego_free_extended_security(void)
{
  if (target_config_unicode.target_name)
  {
    rtp_free(target_config_unicode.target_name            );  // exit_level but not used
    rtp_free(target_config_unicode.netbios_domain_name    );  // exit_level but not used
    rtp_free(target_config_unicode.netbios_computer_name  );  // exit_level but not used
    rtp_free(target_config_unicode.dns_domain_name        );  // exit_level but not used
    rtp_free(target_config_unicode.dns_computer_name      );  // exit_level but not used
  }
}

// This function is spnego_decode_init_packet() returns so it can release any allocated storage from a decoded_init_token_t.
void spnego_decoded_NegTokenInit_destructor(decoded_NegTokenInit_t *decoded_token)
{
  if (decoded_token->mechToken) rtp_free(decoded_token->mechToken);         // command_level
  if (decoded_token->mechListMic) rtp_free(decoded_token->mechListMic);     // command_level
}


//  This function is called by ProcSetupAndx when command.capabilities & CAP_EXTENDED_SECURITY is true and it is not an NTLMSSP security request
//  returns 0 on succes < 0 (SPNEGO_MALFORMED_PACKET, SPNEGO_NOT_INIT_PACKET etc ) for failure.
//
//  You must call decoded_neg_init_token_destructor() - to release memory allocated by this function
//
//    Populates this structure if all is well.
//     typedef struct decoded_NegTokenInit_s {
//      dword Flags;
//      int   mechTypesCount;
//      oid_t mechTypes[MAX_OID_COUNT];
//      byte  *mechToken;    // null to start, allocated with malloc() and copied in if found and must be freed
//      size_t mechTokenSize;  // 0 to start
//      byte  *mechListMic;  // null to start, allocated with malloc() and copied in if found and must be freed
//      size_t mechListMicSize;  // 0 to start
//     } decoded_NegTokenInit_t;

int spnego_decode_NegTokenInit_packet(decoded_NegTokenInit_t *decoded_init_token, unsigned char *pinbuffer, size_t buffer_length)
{
  byte b;
  size_t l;
  byte   current_context;
  size_t l_current_context;
  int r;
  decode_token_stream_t decode_token_stream;
  unsigned char OID_buffer[MAX_OID_SIZE];
  unsigned char *pbuffer=pinbuffer;

  // Initialize the decoded_init_packet, the caller will call the destructor after the results have benn processed.
  rtp_memset(decoded_init_token,0,sizeof(*decoded_init_token));


//   This is what we expect
//   NegTokenInit ::= SEQUENCE {
//   NegTokenInit ::= SEQUENCE {
//      mechTypes     [0]  MechTypeList  OPTIONAL,
//      reqFlags      [1]  ContextFlags  OPTIONAL,
//      mechToken     [2]  OCTET STRING  OPTIONAL,   Security token to use in the challenge if we support the the protocol in mechTypes[0]. This is called optimistic token and is sent in the hope that server will also select the same mechanism as client.
//      mechListMIC   [3]  OCTET STRING  OPTIONAL    probably this for NTLM tbd "not_defined_in_rfc4178@please_ignore"  Mechanism List Message Integrity Code, Used for signing
//   }

  // Build a stream from the input buffer
  decode_token_stream_constructor(&decode_token_stream,(void *)decoded_init_token,pinbuffer, buffer_length);

  // Get the {0x60,len} app constructed object token present in the inittoken
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <0 || b !=0x60) // The ini token is preceeded by an app constructed object 0x60
    return SPNEGO_NOT_INIT_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<0)
    return SPNEGO_MALFORMED_PACKET;
  // Rebuild a stream from the length of the object
  decode_token_stream_constructor(&decode_token_stream,(void *)decoded_init_token,decode_token_stream.stream_pointer, l);

  // Get the spnego oid
  r = decode_token_stream_fetch_oid(&decode_token_stream, OID_buffer);
  if (r < 0)
    return r;
  if (oid_string_to_oid_t(OID_buffer) != oid_spnego)
    return SPNEGO_MALFORMED_PACKET;

  // Get the AO NegTokenIt Token and length
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0 || b !=0xA0)
    return SPNEGO_NOT_INIT_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;
  // Get the sequence element and length
  if (decode_token_stream_fetch_byte  (&decode_token_stream, &b) <=0 || b != 0x30)
     return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;

  // Now enumerate the optional ASN1 elements
  while (decode_token_stream.stream_pointer<decode_token_stream.stream_next)
  {
    decode_token_stream_t decode_context_stream;
    // Get the {0xAx,len}
    if (decode_token_stream_fetch_byte(&decode_token_stream, &current_context) <=0)
      return SPNEGO_MALFORMED_PACKET;
    if (decode_token_stream_fetch_length(&decode_token_stream, &l_current_context)<=0)
      return SPNEGO_MALFORMED_PACKET;

    // build a stream for parsing the current context
    decode_token_stream_constructor(&decode_context_stream,(void *)decoded_init_token,decode_token_stream.stream_pointer, l_current_context);
    // Advance the outer stream pointer, we'll enumerate decode_context_stream now
    decode_token_stream.stream_pointer += l_current_context;
    switch (current_context)
    {
      case 0xa0: //      mechTypes     [0]  MechTypeList  OPTIONAL
      {
        // // BER constructed object {0x30,L} {oid_t,oid_t...}
        if (decode_token_stream_fetch_byte  (&decode_context_stream, &b) <=0 || b != 0x30) return SPNEGO_MALFORMED_PACKET;
        if (decode_token_stream_fetch_length(&decode_context_stream, &l)<=0)             return SPNEGO_MALFORMED_PACKET;
        while (decode_context_stream.stream_pointer < decode_context_stream.stream_next)
        {
          r = decode_token_stream_fetch_oid(&decode_context_stream, OID_buffer);
          if (r <= 0)
            return r;
          decoded_init_token->mechTypes[decoded_init_token->mechTypesCount] = oid_string_to_oid_t(OID_buffer);
          if (decoded_init_token->mechTypes[decoded_init_token->mechTypesCount] == oid_none || (decoded_init_token->mechTypesCount+1 == MAX_OID_COUNT) )
            return SPNEGO_MALFORMED_PACKET;
          decoded_init_token->mechTypesCount += 1;
        }
      }
      break;
      case 0xa1: //      reqFlags      [1]  ContextFlags  OPTIONAL,
        if (decode_token_stream_fetch_byte  (&decode_context_stream, &b) <=0 || b != 0x3) return SPNEGO_MALFORMED_PACKET; // BER bit string followed by flags
        if (decode_token_stream_fetch_length(&decode_context_stream, &l)<=0)             return SPNEGO_MALFORMED_PACKET;
        if (decode_token_stream_fetch_flags(&decode_context_stream, &decoded_init_token->Flags)<=0) return SPNEGO_MALFORMED_PACKET;
      break;
      case 0xa2: //      mechToken     [2]  OCTET STRING  OPTIONAL,   Security token to use in the challenge if we support the the protocol in mechTypes[0]. This is called optimistic token and is sent in the hope that server will also select the same mechanism as client.
        if (decode_token_stream_fetch_byte  (&decode_context_stream, &b) <=0 || b != 0x4) return SPNEGO_MALFORMED_PACKET; // BER octet string followed by length of mechToken
        if (decode_token_stream_fetch_length(&decode_context_stream, &l)<=0)             return SPNEGO_MALFORMED_PACKET;
        decoded_init_token->mechToken = (byte*)rtp_malloc(l);
        if (!decoded_init_token->mechToken)
          return SPNEGO_SYSTEM_ERROR;
        decoded_init_token->mechTokenSize = l;
        memcpy(decoded_init_token->mechToken, decode_context_stream.stream_pointer, l);
        break;
      case 0xa3: //      mechListMIC   [3]  OCTET STRING  OPTIONAL    probably this for NTLM tbd "not_defined_in_rfc4178@please_ignore"  Mechanism List Message Integrity Code, Used for signing
        decoded_init_token->mechListMic = (byte*)rtp_malloc(l_current_context);
        if (!decoded_init_token->mechListMic)
          return SPNEGO_SYSTEM_ERROR;
        memcpy(decoded_init_token->mechListMic, decode_context_stream.stream_pointer, l_current_context);
        decoded_init_token->mechListMicSize = l_current_context;
        break;
      break;
      default:
         return SPNEGO_MALFORMED_PACKET;
    }
  }
  return 0;

}

static void decode_token_stream_security_buffer_destructor(SecurityBuffer_t *presource)
{
  if (presource) {
    if (presource->value_at_offset)
      rtp_free(presource->value_at_offset);                                // command_level
    rtp_free(presource);                                                   // command_level
  }
}

void spnego_decoded_NegTokenTarg_destructor(decoded_NegTokenTarg_t *decoded_targ_token)
{
  decode_token_stream_security_buffer_destructor(decoded_targ_token->lm_response);
  decode_token_stream_security_buffer_destructor(decoded_targ_token->ntlm_response);
  decode_token_stream_security_buffer_destructor(decoded_targ_token->user_name);
  decode_token_stream_security_buffer_destructor(decoded_targ_token->domain_name);
  decode_token_stream_security_buffer_destructor(decoded_targ_token->host_name);
  decode_token_stream_security_buffer_destructor(decoded_targ_token->session_key);
}

void spnego_decoded_NegTokenTarg_challenge_destructor(decoded_NegTokenTarg_challenge_t *decoded_targ_token)
{
  decode_token_stream_security_buffer_destructor(decoded_targ_token->target_name);
  decode_token_stream_security_buffer_destructor(decoded_targ_token->target_info);
}


// Extract a resurce object length, max_length and offset from a stream.
// Allocate and copy in the rest
static int decode_token_stream_fetch_security_buffer(decode_token_stream_t *pstream, byte *blob_base, SecurityBuffer_t **_presource)
{
dword dw;
word length_w, max_w;
  if (decode_token_stream_fetch_word(pstream, &length_w ) <=0)  // Length
    return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_word(pstream, &max_w) <= 0)  // MaxLength
    return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_dword(pstream, &dw) <=0)  // offset
    return SPNEGO_MALFORMED_PACKET;
  byte  *value_at_offset;
  *_presource = 0;

  if (length_w > MAX_LEGAL_SECURITY_BUFFER_SIZE)
    return SPNEGO_SYSTEM_ERROR;
  if (length_w)
  {
    SecurityBuffer_t *presource = (SecurityBuffer_t *)rtp_malloc(sizeof(SecurityBuffer_t));
    if (!presource)
      return SPNEGO_SYSTEM_ERROR;
    *_presource = presource;
    presource->size = length_w;
    presource->offset = (word) dw;
    // allocate the buffer, add 2 bytes so we can null terminate in case it's a string since strings are not terminated in the packet
    presource->value_at_offset = (byte *)rtp_malloc(length_w+2);
    if (!presource->value_at_offset)
    {
      *_presource = 0;
      rtp_free(presource);
      return SPNEGO_SYSTEM_ERROR;
    }
    byte *data_at_offset = blob_base + dw;
    memcpy(presource->value_at_offset, data_at_offset,length_w);
    // null terminate in case it's a string since strings are not terminated in the packet
    word *pw = (word *)presource->value_at_offset;
    pw[(length_w/2)]=0;
  }
  return 0;
}

// decode a length field and return the value, update the buffer address
static unsigned long asn1_decode_length(unsigned char **ppbuffer)
{
unsigned long l = 0;
unsigned char c;
unsigned char *pbuffer = *ppbuffer;
  c = *pbuffer;
  if (c&0x80)
  { // We have a length so see how many characters to follow
    unsigned char nchars = c&0x7f;
    pbuffer++;
    do
    {
      l <<= 8;
      c = *pbuffer++;
      l |= c;
      nchars--;
    } while (nchars);
  }
  else
  {
   l=(unsigned long)c;
   pbuffer++;
  }
  *ppbuffer = pbuffer;
  return l;
}

// Extract the oid field from a buffer and advance the buffer, return the oid type if it is known
static oid_t oid_string_to_oid_t(byte *pbuffer)
{
 oid_t r = oid_none;
 if (*pbuffer == 0x06)
 {
   r = oid_unkown;
   if (memcmp(pbuffer,SPNEGO, sizeof(SPNEGO)) == 0)
     r = oid_spnego;
   else if (memcmp(pbuffer,KERBV5, sizeof(KERBV5)) == 0)
     r = oid_kerb5;
   else if (memcmp(pbuffer,KERBV5L, sizeof(KERBV5L)) == 0)
     r = oid_kerb5l;
   else if (memcmp(pbuffer,NTLMSSP, sizeof(NTLMSSP)) == 0)
     r = oid_ntlmssp;
 }
 return r;

}
//  This function is called by ProcSetupAndx when command.capabilities & CAP_EXTENDED_SECURITY is true and it is not an NTLMSSP security request
//  returns 0 on succes < 0 (SPNEGO_MALFORMED_PACKET, SPNEGO_NOT_INIT_PACKET etc ) for failure.
//
//  You must call decoded_NegTokenTarg_destructor() - to release memory allocated by this function
//
//    Populates this structure if all is well.
//   typedef struct decoded_NegTokenTarg_s {
//     dword Flags;
//     dword user_name_size;
//     word *user_name;	       /* in unicode */
//     dword domain_name_size;
//     word *domain_name;	  /* in unicode */
//     dword host_name_size;
//     word *host_name;	      /* in unicode */
//     dword session_key_size;
//     byte *session_key;
//   } decoded_NegTokenTarg_t;
//
// Decodes NTLMSSP_AUTH


//  This function is called by ProcSetupAndx when command.capabilities & CAP_EXTENDED_SECURITY is true and it is not an NTLMSSP security request
//  returns 0 on succes < 0 (SPNEGO_MALFORMED_PACKET, SPNEGO_NOT_INIT_PACKET etc ) for failure.
//
//  You must call decoded_NegTokenTarg__challenge_destructor() - to release memory allocated by this function
//
//    Populates this structure if all is well.
//   typedef struct decoded_NegTokenTarg__challenge_s {
//    dword Flags;
//    byte *target_name;
//    byte ntlmserverchallenge[8];
//    dword target_info_size;
//    byte *target_info;
//   } decoded_NegTokenTarg__challenge_t;


int spnego_decode_NegTokenTarg_challenge(decoded_NegTokenTarg_challenge_t *decoded_targ_token, unsigned char *pinbuffer, size_t buffer_length)
{
  byte b;
  size_t l;
  byte   current_context;
  size_t l_current_context;
  int r;
  decode_token_stream_t decode_token_stream;
  unsigned char OID_buffer[MAX_OID_SIZE];
  unsigned char *pbuffer=pinbuffer;
  word  w;
  dword dw;


  rtp_memset(decoded_targ_token,0,sizeof(*decoded_targ_token));

  // Build a stream from the input buffer
  decode_token_stream_constructor(&decode_token_stream,(void *)decoded_targ_token,pinbuffer, buffer_length);

  // Get the A1 NegTokenTarg Token and length
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0 || b !=0xA1)
    return SPNEGO_NOT_INIT_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;
  // Get the sequence element and length
  if (decode_token_stream_fetch_byte  (&decode_token_stream, &b) <=0 || b != 0x30)
     return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;
  // Rebuild a stream from the length of the object
  decode_token_stream_constructor(&decode_token_stream,(void *)decoded_targ_token,decode_token_stream.stream_pointer, l);


  // TBD Get the A0 application envelope ??
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0)// || b !=0xA0)
    return SPNEGO_MALFORMED_PACKET;
  // TBD Get the 03 application envelope ??
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0)// || b !=0x03)
    return SPNEGO_MALFORMED_PACKET;
  // TBD Get the 0A application envelope ??
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0)// || b !=0x0A)
    return SPNEGO_MALFORMED_PACKET;
  // TBD Get the 10 ??
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0)// || b !=0x01)
    return SPNEGO_MALFORMED_PACKET;
  // TBD Get the 01 ??
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0)// || b !=0x01)
    return SPNEGO_MALFORMED_PACKET;

  // TBD Get the A1 application envelope ??
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0 || b !=0xA1)
    return SPNEGO_MALFORMED_PACKET;

  // TBD Get the length.
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;

  // TBD Get the ntlm oid
  r = decode_token_stream_fetch_oid(&decode_token_stream, OID_buffer);
  if (r < 0)
    return r;
  if (oid_string_to_oid_t(OID_buffer) != oid_ntlmssp)
    return SPNEGO_MALFORMED_PACKET;

  // TBD Get the A2 application envelope and length
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0 || b !=0xA2)
    return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;

  // Get the 04 envelope and length
  if (decode_token_stream_fetch_byte(&decode_token_stream, &b) <=0 || b !=0x04)
    return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_length(&decode_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;

 // Save this as the base from which resource objecxts are extracted
  byte *blob_base=decode_token_stream.stream_pointer;

  // Verify NTLMSSP signature
  byte  ntlm_fetch_buffer[sizeof(ntlmssp_str)];
  if (decode_token_stream_fetch(&decode_token_stream, ntlm_fetch_buffer, sizeof(ntlmssp_str))!=sizeof(ntlmssp_str))
    return SPNEGO_MALFORMED_PACKET;
  if (memcmp(ntlm_fetch_buffer,ntlmssp_str,sizeof(ntlmssp_str)) != 0)
    return SPNEGO_MALFORMED_PACKET;
  // Verify NTLM Message Type: NTLMSSP_CHALLENGE (0x00000002)
  dword ntlm_message_type;
  if (decode_token_stream_fetch(&decode_token_stream, (byte  *)&ntlm_message_type, 4)!=4)
    return SPNEGO_MALFORMED_PACKET;
  if (ntlm_message_type != SMB_HTOID(0x000000002))
    return SPNEGO_MALFORMED_PACKET;

  //  Get ntlmssp.challenge.target_name
  r=decode_token_stream_fetch_security_buffer(&decode_token_stream, blob_base,&decoded_targ_token->target_name); if (r<0) return r;
  // Get ntlmssp.negotiateflags
  if (decode_token_stream_fetch_dword(&decode_token_stream, &decoded_targ_token->Flags) <=0)  // offset
    return SPNEGO_MALFORMED_PACKET;
  //  Get ntlmssp.ntlmserverchallenge

  r=decode_token_stream_fetch(&decode_token_stream, decoded_targ_token->ntlmserverchallenge, 8); if (r<0) return r;
  // get ntlmssp.reserved 2 dwords
  if (decode_token_stream_fetch_dword(&decode_token_stream, &dw) <=0)  return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_dword(&decode_token_stream, &dw) <=0)  return SPNEGO_MALFORMED_PACKET;

  //  Get ntlmssp.challenge.target_info
  r=decode_token_stream_fetch_security_buffer(&decode_token_stream, blob_base,&decoded_targ_token->target_info); if (r<0) return r;


  return 0;
}



//  decode_token_stream_encode_byte(spnego_output_stream_t *pstream, byte b)
//  if in pass1, (pstream->resolving_widths) adds the witdrh of 1 byte to the object width stack
//  if in pass2, (!pstream->resolving_widths) pushes the byte onto the stream.
//   return SPNEGO_OBJCOUNT_TOO_DEEP if too many objects.
//   return SPNEGO_PACKET_TOO_LARGE  if stream buffer is too small
//   return width(1) if all is well
static int decode_token_stream_encode_byte(spnego_output_stream_t *pstream, byte b)
{
  if (pstream->resolving_widths)
  {
    if (pstream->object_count == MAX_OBJECT_PER_OUTPUT_STREAM)
       return SPNEGO_OBJCOUNT_TOO_DEEP;
    pstream->object_widths[pstream->object_count] = 1;
    pstream->object_count += 1;
  }
  else
  {
    if (pstream->stream_pointer >= pstream->stream_end) return SPNEGO_PACKET_TOO_LARGE;
    *pstream->stream_pointer = b;
    pstream->stream_pointer += 1;
    pstream->object_index += 1;
  }
  return 1;
}

//  decode_token_stream_encode_bytes(spnego_output_stream_t *pstream, byte b)
//   Encode a known width array of bytes into the output stream
//  if in pass1, (pstream->resolving_widths) adds the witdh of N bytes to the object width stack
//  if in pass2, (!pstream->resolving_widths) pushes the bytes onto the stream.
//   return SPNEGO_OBJCOUNT_TOO_DEEP if too many objects.
//   return SPNEGO_PACKET_TOO_LARGE  if stream buffer is too small
//   return width if all is well
static int decode_token_stream_encode_bytes(spnego_output_stream_t *pstream, void *_pb, size_t width)
{
  byte *pb = (byte *)_pb;
  if (pstream->resolving_widths)
  {
    if (pstream->object_count == MAX_OBJECT_PER_OUTPUT_STREAM)
       return SPNEGO_OBJCOUNT_TOO_DEEP;
    pstream->object_widths[pstream->object_count] = (dword) width;
    pstream->object_count += 1;
  }
  else
  {
    if (pstream->stream_pointer+width >= pstream->stream_end) return SPNEGO_PACKET_TOO_LARGE;
    memcpy(pstream->stream_pointer,pb,width);
    pstream->stream_pointer += width;
    pstream->object_index += 1;
  }
  return (int) width;
}



//  decode_token_stream_encode_length(spnego_output_stream_t *pstream, dword l)
//  if in pass1, (pstream->resolving_widths) adds the width required for the width field.
//  if in pass2, (!pstream->resolving_widths) pushed the encoded width bytes onto the stream.
//   return SPNEGO_OBJCOUNT_TOO_DEEP if too many objects.
//   return SPNEGO_PACKET_TOO_LARGE  if stream buffer is too small
//   return width if all is well
static int decode_token_stream_encode_length(spnego_output_stream_t *pstream, dword l)
{
dword _l;
int extra_width=0;
  if (l > 128)
  {
    dword _l=l;
    while (_l)
    {
      extra_width+=1;
      _l>>=8;
    }
  }

  if (pstream->resolving_widths)
  {
    if (pstream->object_count == MAX_OBJECT_PER_OUTPUT_STREAM)
       return SPNEGO_OBJCOUNT_TOO_DEEP;
    pstream->object_widths[pstream->object_count] = 1+(dword)extra_width;
    pstream->object_count += 1;
  }
  else
  {
    if (l < 128)
    {
      if (pstream->stream_pointer >= pstream->stream_end) return SPNEGO_PACKET_TOO_LARGE;
      *pstream->stream_pointer = (byte)l&0x7f;
      pstream->stream_pointer += 1;
    }
    else
    {
     if (pstream->stream_pointer >= pstream->stream_end) return SPNEGO_PACKET_TOO_LARGE;
     *pstream->stream_pointer++ = 0x80|(byte)extra_width;
     for (_l = 1; _l <= (dword)extra_width; _l++) // Shift the extra width value out high byte first
     {
       byte b;
       if (pstream->stream_pointer >= pstream->stream_end) return SPNEGO_PACKET_TOO_LARGE;
       b = (byte) (l >> (((dword)extra_width-_l)*8))&0xff;
       *pstream->stream_pointer++ = b;
     }
     }
     pstream->object_index += 1;
  }
  return 1+extra_width;;
}

//  int decode_token_stream_encode_oid(spnego_output_stream_t *pstream, oid_t oid)
//   pushes an OID that is already encoded in an array onto the outpu stream
//  if in pass1, (pstream->resolving_widths) adds the width required for the OID field.
//  if in pass2, (!pstream->resolving_widths) pushed the OID bytes onto the stream.
//   return SPNEGO_OBJCOUNT_TOO_DEEP if too many objects.
//   return SPNEGO_PACKET_TOO_LARGE  if stream buffer is too small
//   return width if all is well
#ifdef NOTUSED
static int decode_token_stream_encode_oid(spnego_output_stream_t *pstream, oid_t oid)
{
int lwidth=0;
const byte *p=0;
  if (oid==oid_spnego)
  {
    lwidth=sizeof(SPNEGO);
    p=SPNEGO;

  }
  else if (oid==oid_kerb5)
  {
    lwidth=sizeof(KERBV5);
    p=KERBV5;

  }
  else if (oid==oid_kerb5l)
  {
    lwidth=sizeof(KERBV5L);
    p=KERBV5L;

  }
  else // Always return something to avid catastrophe if (oid==oid_ntlmss)
  {
    lwidth=sizeof(NTLMSSP);
    p=NTLMSSP;
  }
  if (pstream->resolving_widths)
  {
    if (pstream->object_count == MAX_OBJECT_PER_OUTPUT_STREAM)
       return SPNEGO_OBJCOUNT_TOO_DEEP;
    pstream->object_widths[pstream->object_count] = (dword)lwidth;
    pstream->object_count += 1;
  }
  else
  {
    if (pstream->stream_pointer+lwidth>= pstream->stream_end) return SPNEGO_PACKET_TOO_LARGE;
    memcpy(pstream->stream_pointer,p,(size_t)lwidth);
    pstream->stream_pointer += lwidth;
    pstream->object_index += 1;
  }
  return lwidth;
}

// Calculate the width of an asn1 width variable
static int decode_token_stream_get_length_fieldwidth(dword l)
{
int width=1;
  if (l > 128)
  {
    dword _l=l;
    while (_l)
    {
      width+=1;
      _l>>=8;
    }
  }
  return width;
}

#endif
//  After pass 1 completes, Resolve foreward references to unknown length values for containers.
static void decode_token_stream_encode_fixup_lengths(spnego_output_stream_t *pstream)
{
 int object_index;
 dword inner_l=0;

 if (pstream->object_count)
 {
  // Now work backwords.
  for (object_index=pstream->object_count-1; object_index >0 ; object_index--)
  {
    if ( (pstream->object_widths[object_index] & OBJECT_WIDTH_UNRESOLVED) == OBJECT_WIDTH_UNRESOLVED)
    {
       size_t width_field_width = asn1_calculate_width_of_width_field(inner_l);
       pstream->object_widths[object_index] = inner_l;              // This is what we emit for this tag
       inner_l += width_field_width;
    }
    else
    {
      inner_l += pstream->object_widths[object_index];             // Add a known length field.
    }
  }                                                          // we return this to the next nesting level.
 }
}

// Encode a container type (app token or sequence token).
//  decode_token_stream_encode_app_container(spnego_output_stream_t *pstream, byte Token)
//   Encode an unkown width structured sequence the output stream
//  if in pass1, (pstream->resolving_widths) adds the the tag to the object width stack plus adds a marker for a width location that must be resolved by: decode_token_stream_encode_fixup_lengths()
//  if in pass2, (!pstream->resolving_widths) pushes the bytes onto the stream.
//   return SPNEGO_OBJCOUNT_TOO_DEEP if too many objects.
//   return SPNEGO_PACKET_TOO_LARGE  if stream buffer is too small
//   return width if all is well

static int decode_token_stream_encode_app_container(spnego_output_stream_t *pstream, byte Token)
{
int lwidth;
int r;
  if (pstream->resolving_widths)
  {
    lwidth=1;
    dword meta_data = OBJECT_WIDTH_UNRESOLVED|Token;
    if (pstream->object_count+3 >= MAX_OBJECT_PER_OUTPUT_STREAM) return SPNEGO_OBJCOUNT_TOO_DEEP;
    r = decode_token_stream_encode_byte(pstream, Token); if (r < 0) return r;         // Make sure the tag gets pushed into the length arrary
    pstream->object_widths[pstream->object_count++] = meta_data;       // Length field is unresolved
  }
  else
  {
    dword l;
    r = decode_token_stream_encode_byte(pstream, Token); if (r < 0) return r;   // Encode the tag and increase pstream->object_index
    l = pstream->object_widths[pstream->object_index];                         // retrieve count of bytes from the fixup array for length
    r = decode_token_stream_encode_length(pstream, l); if (r < 0) return r;     // encode count of bytes in the rest of the packet into length and increase pstream->object_index
    lwidth=1+r;                                                                // Add the 1 for the tag + the bytes needed to encode the length + the length of the blob
  }
  return lwidth;
}

// Initialize an output stream or substream starting at stream_base with length stream_len do not zero width accumulators when resolving_widths == false
static void spnego_output_stream_stream_constructor(spnego_output_stream_t *pstream,void  *context,byte  *stream_base, size_t stream_len,bool resolving_widths)
{
  if (resolving_widths)
     rtp_memset(pstream,0,sizeof(*pstream));
  pstream->object_index=0;
  pstream->context = context;
  pstream->resolving_widths=resolving_widths;
  pstream->stream_base  = stream_base;
  pstream->stream_pointer=stream_base;
  pstream->stream_end=stream_base+stream_len;
}

static word rtsmb_util_unicode_strlen(void *_str)
{
word l=0;
word *str = (word *) _str;
  while (str[l]) l++;
  return l;
}
static word *rtsmb_util_malloc_ascii_to_unicode (char *ascii_string)
{
word *p;
size_t w;
  w=rtp_strlen(ascii_string)*2+2;
  p=(word*)rtp_malloc(w);
  rtsmb_util_ascii_to_unicode (ascii_string ,p , w);
  return (p);
}

typedef struct resource_strings_s {
  byte *offset_fixup_location;
  void *content;
  word content_width;
} resource_strings_t;

#define TARGET_INFORMATION_SIZE 512


//0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00}; // 0x0101000 00000000
//rtsmb_util_get_current_filetime();       // timestamp
//0000000                                  // zero
static const byte spnego_client_ntlmssp_response_blob[] = {0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00}; // 0x0101000 00000000
static byte mystamp[] = {0x11,0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
static byte mynonce[] = {0x88,0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
int spnego_get_client_ntlmv2_response_blob(byte *pblob)
{
    memcpy(pblob, spnego_client_ntlmssp_response_blob, sizeof (spnego_client_ntlmssp_response_blob) );
    ddword *pddw= (ddword *)(pblob+8);
    *pddw = rtsmb_util_get_current_filetime();
    memcpy(pddw, mystamp, 8); // Overwrite stamp
    rtsmb_util_guid(pblob+16);
    memcpy(pblob+16, mynonce, 8); // Overwrite random nonce
    dword *pdw= (dword *)(pblob+24);
    *pdw= 0;
    return 28;
}

// encode a type 3 NTLM response in response to to a server's challenge into outbuffer and return the length
int spnego_encode_ntlm2_type3_packet(unsigned char *outbuffer, size_t buffer_length, byte *ntlm_response_buffer, int ntlm_response_buffer_size, byte *domain_name, byte *user_name, byte *workstation_name, byte *session_key)
{
// DATA                    // Challenge data
bool doing_size = true;
spnego_output_stream_t outstream;
int i;
int r;

  for(i=0; i < 2; i++, doing_size = !doing_size)
  {
    int saved_object_count=0;
    int fixups = 0;
    int wire_length=0;
    int i;
    dword dw;
    word  w,iw;
    word server_name[16];
    resource_strings_t resource_strings[32];
    byte target_information_buffer[TARGET_INFORMATION_SIZE];
    byte *security_base=0;

    // On the second pass remember the object count so we can enumerate the size place holders
    spnego_output_stream_stream_constructor(&outstream,0, outbuffer, buffer_length,doing_size);
    // On the second pass fixup the place holders
    if (!doing_size)
      decode_token_stream_encode_fixup_lengths(&outstream);
  // 0xA1, len NegTokenTarg
    r = decode_token_stream_encode_app_container(&outstream, 0xA1); if (r < 0) return r;
    // The length returned for the outer capsule is the wire length
  // 0x30 len  Sequence length
    r = decode_token_stream_encode_app_container(&outstream, 0x30);  if (r < 0) return r;
  // 0xA2, Seq. Element 2 response token and length
    r = decode_token_stream_encode_app_container(&outstream, 0xA2); if (r < 0) return r;
  // 0x04, length            Octet string length
    r = decode_token_stream_encode_app_container(&outstream, 0x04);  if (r < 0) return r;
   // NTLMSSP\0
    // Save the starting point for fixing up resource
    security_base = outstream.stream_pointer;
    r = decode_token_stream_encode_bytes(&outstream, ntlmssp_str, sizeof(ntlmssp_str));  if (r < 0) return r;
   // NTLM Message Type: NTLMSSP_AUTH (0x00000003)
    dw = SMB_HTOID((dword) 3);
    r = decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;

    // Lan Manager Response: 000000000000000000000000000000000000000000000000
    byte lan_man_response_buffer[24];
    w = 24;
    memset(lan_man_response_buffer, 0, 24);
   // Encode our target information
   // Set length and allocated length the same.
    iw = SMB_HTOIW((word) w);
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer length
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer Maxlength
    resource_strings[fixups].offset_fixup_location = outstream.stream_pointer;
    resource_strings[fixups].content = lan_man_response_buffer;
    resource_strings[fixups++].content_width = w;
    dw = 0;
    decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.

//    r = decode_token_stream_encode_bytes(&outstream, ntlm_reserved,  8);  if (r < 0) return r;  // client challenge, 8 Zeros.

    // NTLM Response: bcd3406e8f2e835fc2d235e11deb06370101000000000000...
    w = ntlm_response_buffer_size;
   // Encode our target information
   // Set length and allocated length the same.
    iw = SMB_HTOIW((word) w);
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer length
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer Maxlength
    resource_strings[fixups].offset_fixup_location = outstream.stream_pointer;
    resource_strings[fixups].content = ntlm_response_buffer;
    resource_strings[fixups++].content_width = w;
    dw = 0;
    decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.


    //   resource_string Domain name: UBUNTU14-VIRTUALBOX  unicode
    w = rtsmb_util_unicode_strlen(domain_name)*2+2;  // item_string null is terminator record
    iw = SMB_HTOIW((word) w);
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer length
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer Maxlength
    resource_strings[fixups].offset_fixup_location = outstream.stream_pointer;
    resource_strings[fixups].content = domain_name;
    resource_strings[fixups++].content_width = w;
    dw = 0;
    decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.


    //   resource_string User name: peter                  unicode
    w = rtsmb_util_unicode_strlen(user_name)*2+2;  // item_string null is terminator record
    iw = SMB_HTOIW((word) w);
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer length
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer Maxlength
    resource_strings[fixups].offset_fixup_location = outstream.stream_pointer;
    resource_strings[fixups].content = user_name;
    resource_strings[fixups++].content_width = w;
    dw = 0;
    decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.

    //   resource_string Host name: workstation            unicode
    w = rtsmb_util_unicode_strlen(workstation_name)*2+2;  // item_string null is terminator record
    iw = SMB_HTOIW((word) w);
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer length
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer Maxlength
    resource_strings[fixups].offset_fixup_location = outstream.stream_pointer;
    resource_strings[fixups].content = workstation_name;
    resource_strings[fixups++].content_width = w;
    dw = 0;
    decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.


    //   resource_string Session Key: 0520e5ff12dee6acfabfd0e78b5842ec
    w = 16;
    iw = SMB_HTOIW((word) w);
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer length
    r = decode_token_stream_encode_bytes(&outstream, &iw,  2);  if (r < 0) return r;  // Target info layer Maxlength
    resource_strings[fixups].offset_fixup_location = outstream.stream_pointer;
    resource_strings[fixups].content = session_key;
    resource_strings[fixups++].content_width = w;
    dw = 0;
    decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.


    // Negotiate Flags: 0x62880205
    dw = SMB_HTOID((dword) 0x62880205);
    r = decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;

    // Version 6.1 (Build 7600); NTLM Current Revision 0
    decode_token_stream_encode_bytes(&outstream, ntlm_version,  sizeof(ntlm_version));  if (r < 0) return r;    // push 0 for offset from security_base, we'll get back to it.
//    r = decode_token_stream_encode_bytes(&outstream, &dw,  4);  if (r < 0) return r;

    // Now the after copy in the resources
    {
    int fixup;
    for (fixup=0; fixup<fixups; fixup++)
    {
      if (!doing_size)
      {
        dw =  SMB_HTOID((dword) PDIFF (outstream.stream_pointer, security_base));  // ofsset
        memcpy(resource_strings[fixup].offset_fixup_location,&dw, 4);
      }
      // Do this in either case because when doing_size we need the length
      decode_token_stream_encode_bytes(&outstream, resource_strings[fixup].content,resource_strings[fixup].content_width);  if (r < 0) return r;
    }
    }
  }
  return (int) PDIFF (outstream.stream_pointer, outstream.stream_base);

}



// encode length field and return the pointer to the next byte in the stream.
#define MAX_LENGTHFIELD_WIDTH 32
static unsigned char *asn1_encode_length(unsigned char *pbuffer,unsigned long l)
{
//unsigned char c;
//  c = *pbuffer;
  if (l < 0x80)
  { // We have a length so see how many characters to follow
    *pbuffer++ = (unsigned char) l;
  }
  else
  {
    unsigned char nchars = 0;
    unsigned long _l = l;
    do
    {
      _l >>= 8;
      nchars++;
    } while (_l);
    *pbuffer++ = nchars | 0x80;
    do
    {
      // shift out in big endian mode hi byte to low byte
      *pbuffer++ = (unsigned char) ((l>>((nchars-1)*8))&0xff);
      nchars--;
    } while (nchars);
  }
  return pbuffer;
}

static size_t asn1_calculate_width_of_width_field(unsigned long l)
{
unsigned char buffer[MAX_LENGTHFIELD_WIDTH];
unsigned char *p = asn1_encode_length(buffer,l);
 return (size_t) (p-&buffer[0]);
}

// Initialize a stream or substream starting at stream_base with length stream_len
static void decode_token_stream_constructor(decode_token_stream_t *pstream,void  *decoded_token,byte  *stream_base, size_t stream_len)
{
  rtp_memset(pstream,0,sizeof(*pstream));
  pstream->decoded_token = decoded_token;
  pstream->stream_base  = stream_base;
  pstream->stream_pointer=stream_base;
  pstream->stream_next=stream_base+stream_len;
}


// Extract as many as fetch_count bytes from the stream up to the number of bytes left in the stream.
// return number of bytes consumed, < 0 error, 0 means past end of stream
static int decode_token_stream_fetch(decode_token_stream_t *pstream,byte  *fetch_buffer, size_t fetch_count)
{
  if (pstream->stream_pointer<pstream->stream_next)
  {
     size_t nleft = (size_t)(pstream->stream_next-pstream->stream_pointer);
     fetch_count = nleft<fetch_count?nleft:fetch_count;
     rtp_memcpy(fetch_buffer,pstream->stream_pointer,fetch_count);
     pstream->stream_pointer += fetch_count;
     return (int)fetch_count;
  }
  return 0;
}



// Extract an asn1 encoded length value from a stream
// return number of bytes consumed, < 0 error, 0 means past end of stream
static int decode_token_stream_fetch_obj(decode_token_stream_t *pstream, void *prv, asn1_objtype_t objtype)
{
  int r=SPNEGO_MALFORMED_PACKET;
  byte  *saved_stream_pointer = pstream->stream_pointer;
  if (pstream->stream_pointer < pstream->stream_next)   // don't go past stream
  {
    if (objtype== objtype_length)
    {  // Get the length out of the stream and advance stream_pointer
      unsigned long length;
      byte  *lstream_pointer=pstream->stream_pointer;
      size_t *l = (size_t *) prv;
      length = asn1_decode_length(&lstream_pointer);
      if (lstream_pointer > pstream->stream_next) // if too long must be bogus
      {
        *l = (size_t) 0;
        pstream->stream_pointer = pstream->stream_next;
        r = SPNEGO_MALFORMED_PACKET;;
      }
      else
      {
         *l = (size_t) length;
         pstream->stream_pointer=lstream_pointer;
         r = 0;
      }
    }
    else if (objtype==objtype_oid)
    {  // Get the oid out of the stream and advance stream_pointer 0x6,len, (x,y,z .. len bytes)
      if (*pstream->stream_pointer == 0x06)
      {
        int l = 0;
        byte b;
        int lr;

        decode_token_stream_fetch_byte(pstream, &b); // consume the oid tag
        lr = decode_token_stream_fetch_obj(pstream, (void *)&l, objtype_length);
        if (lr)
        {
           int oid_l = 1 + lr + l; // Total length == (06 token, PLUS bytes used to encode the length, PLUS the cargo of length=l
           if (saved_stream_pointer+oid_l>pstream->stream_next || oid_l >= MAX_OID_SIZE) // if too long or malformed must be bogus
           {
             r = SPNEGO_MALFORMED_PACKET;
             pstream->stream_pointer=pstream->stream_next;
           }
           else
           {  // We keep the whole pattern including the 0x6 and the length.
              memcpy(prv, saved_stream_pointer, (size_t)oid_l);
              pstream->stream_pointer=saved_stream_pointer+oid_l;
           }
           r = 0;
        }
      }
    }
  }
  else
    return 0; // end of stream
  if (r==0)
  {
    r = (int) (pstream->stream_pointer-saved_stream_pointer);
  }
  return r;
}

// Extract an asn1 encoded bitfield limited to 4 bytes from a stream
// return number of bytes consumed, < 0 error, 0 means past end of stream
static int decode_token_stream_fetch_flags(decode_token_stream_t *pstream, dword *pFlags)
{
byte  *saved_stream_pointer = pstream->stream_pointer;
size_t l, unused_bits;
byte b;
dword dw=0;
int r=SPNEGO_MALFORMED_PACKET;
decode_token_stream_t decode_bitstream_stream;

  if (decode_token_stream_fetch_byte(pstream, &b) <=0 || b != 0x03) return SPNEGO_MALFORMED_PACKET;
  if (decode_token_stream_fetch_length(pstream, &l) <=0) return SPNEGO_MALFORMED_PACKET;
      // build a stream for parsing the current context        HEREHERE
  decode_token_stream_constructor(&decode_bitstream_stream, pstream->decoded_token,pstream->stream_pointer,l);

  if (decode_token_stream_fetch_length(&decode_bitstream_stream, &unused_bits) <=0) return SPNEGO_MALFORMED_PACKET;
  if (l >4)
     return SPNEGO_MALFORMED_PACKET;
  while (decode_bitstream_stream.stream_pointer < decode_bitstream_stream.stream_next)
  {
    dw<<=8;
    if (decode_token_stream_fetch_byte(&decode_bitstream_stream, &b) <=0) return SPNEGO_MALFORMED_PACKET;
    dw|=b;
  }
  if (unused_bits)
  {
    dw>>=unused_bits;
  }
  r = (int) (decode_bitstream_stream.stream_pointer-saved_stream_pointer);

  return r; // Code had been not returning a value here. Returning r does not break it so it should help
}

// Extract an asn1 encoded length value from a stream
// return number of bytes consumed, < 0 error, 0 means past end of stream
static int decode_token_stream_fetch_length(decode_token_stream_t *pstream, size_t *l)
{
  return decode_token_stream_fetch_obj(pstream, (void *)l, objtype_length);
}

// Fetch an asn1 encoded oid from a stream
// return number of bytes consumed, < 0 error, 0 means past end of stream
static int decode_token_stream_fetch_oid(decode_token_stream_t *pstream, byte *poid)
{
  return decode_token_stream_fetch_obj(pstream, (void *)poid, objtype_oid);
}
// Fetch an asn1 encoded length value from a stream
// return 1, < 0 means past end of stream
static int decode_token_stream_fetch_byte(decode_token_stream_t *pstream, byte *b)
{
  int r=SPNEGO_MALFORMED_PACKET;
  if (pstream->stream_pointer < pstream->stream_next)   // don't go past stream
  {
    *b = *pstream->stream_pointer++;
     r = 1;
  }
  return r;
}

// Fetch a word from the stream convert to host byte order, reetur <= 0 of error
// return 1, < 0 means past end of stream
static int decode_token_stream_fetch_word(decode_token_stream_t *pstream, word *w)
{
  int r=SPNEGO_MALFORMED_PACKET;
  if (pstream->stream_pointer+1 < pstream->stream_next)   // don't go past stream
  {
    word _w = *(word *)pstream->stream_pointer;
    *w = SMB_ITOHW(_w);
    pstream->stream_pointer += 2;
     r = 1;
  }
  return r;
}

// Fetch a dword from the stream convert to host byte order, reetur <= 0 of error
static int decode_token_stream_fetch_dword(decode_token_stream_t *pstream, dword *dw)
{
  int r=SPNEGO_MALFORMED_PACKET;
  if (pstream->stream_pointer+3 < pstream->stream_next)   // don't go past stream
  {
    dword _dw = *(dword *)pstream->stream_pointer;
    *dw = SMB_ITOHD(_dw);
    pstream->stream_pointer += 4;
     r = 1;
  }
  return r;
}
