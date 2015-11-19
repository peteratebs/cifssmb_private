//
// SMBNB.C -
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

#include "smbdefs.h"
#include "smbnb.h"
#include "smbpack.h"
#include "smbread.h"
#include "smbutil.h"
#include "smbspnego.h"
#include <malloc.h>
#include <string.h>

// Kerberos OIDs
static const byte SPNEGO[] =  {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};   // 1.3.6.1.5.5.2
static const byte KERBV5[] =  {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}; // 1.2.840.113554.1.2.2
static const byte KERBV5L[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}; // 1.2.840.48018.1.2.2
static const byte NTLMSSP[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};   // 1.3.6.1.4.1.311.2.2.10



// Stream data type for chopping a buffer into streams and substreams.
typedef struct parse_token_stream_s {
  void  *parsed_token;
  byte  *stream_base;
  byte  *stream_pointer;
  byte  *stream_next;
} parse_token_stream_t;


typedef enum {
  objtype_oid,
  objtype_length,
  objtype_bitstring,
} asn1_objtype_t;


static int parse_token_stream_fetch_byte(parse_token_stream_t *pstream, byte *b);
static int parse_token_stream_fetch_length(parse_token_stream_t *pstream, size_t *l);
static int parse_token_stream_fetch_oid(parse_token_stream_t *pstream, byte *poid);
static int parse_token_stream_fetch_byte(parse_token_stream_t *pstream, byte *b);
static unsigned long asn1_decode_length(unsigned char **ppbuffer);
static oid_t oid_string_to_oid_t(byte *pbuffer);
static unsigned char *asn1_encode_length(unsigned char *pbuffer,unsigned long l);
static void parsed_neg_init_token_constructor(parsed_init_token_t *parsed_token);
static void parse_token_stream_constructor(parse_token_stream_t *pstream,void  *parsed_token,byte  *stream_base, size_t stream_len);
static int parse_token_stream_fetch(parse_token_stream_t *pstream,byte  *fetch_buffer, size_t fetch_count);
static int parse_token_stream_fetch_obj(parse_token_stream_t *pstream, void *prv, asn1_objtype_t objtype);
static int parse_token_stream_fetch_flags(parse_token_stream_t *pstream, dword *pFlags);


// Release any allocated storage from a parsed_init_token_t.
void parsed_neg_init_token_destructor(parsed_init_token_t *parsed_token)
{
  if (parsed_token->mechToken) free(parsed_token->mechToken);
  if (parsed_token->mechListMic) free(parsed_token->mechListMic);
}

int parse_spnego_init_packet(parsed_init_token_t *parsed_init_token, unsigned char *pinbuffer, size_t buffer_length)
{
  byte b;
  size_t l;
  byte   current_context;
  size_t l_current_context;
  int r;
  parse_token_stream_t parse_token_stream;
  unsigned char OID_buffer[MAX_OID_SIZE];
  unsigned char *pbuffer=pinbuffer;

  // Initialize the parsed_init_packet, the caller will call the destructor after the results have benn processed.
  parsed_neg_init_token_constructor(parsed_init_token);

//   This is what we expect
//   NegTokenInit ::= SEQUENCE {
//   NegTokenInit ::= SEQUENCE {
//      mechTypes     [0]  MechTypeList  OPTIONAL,
//      reqFlags      [1]  ContextFlags  OPTIONAL,
//      mechToken     [2]  OCTET STRING  OPTIONAL,   Security token to use in the challenge if we support the the protocol in mechTypes[0]. This is called optimistic token and is sent in the hope that server will also select the same mechanism as client.
//      mechListMIC   [3]  OCTET STRING  OPTIONAL    probably this for NTLM tbd "not_defined_in_rfc4178@please_ignore"  Mechanism List Message Integrity Code, Used for signing
//   }

  // Build a stream from the input buffer
  parse_token_stream_constructor(&parse_token_stream,(void *)parsed_init_token,pinbuffer, buffer_length);

  // Get the {0x60,len} app constructed object token present in the inittoken
  if (parse_token_stream_fetch_byte(&parse_token_stream, &b) <0 || b !=0x60) // The ini token is preceeded by an app constructed object 0x60
    return SPNEGO_NOT_INIT_PACKET;
  if (parse_token_stream_fetch_length(&parse_token_stream, &l)<0)
    return SPNEGO_MALFORMED_PACKET;
  // Rebuild a stream from the length of the object
  parse_token_stream_constructor(&parse_token_stream,(void *)parsed_init_token,parse_token_stream.stream_pointer, l);

  // Get the spnego oid
  r = parse_token_stream_fetch_oid(&parse_token_stream, OID_buffer);
  if (r < 0)
    return r;
  if (oid_string_to_oid_t(OID_buffer) != oid_spnego)
    return SPNEGO_MALFORMED_PACKET;

  // Get the AO NegTokenIt Token and length
  if (parse_token_stream_fetch_byte(&parse_token_stream, &b) <=0 || b !=0xA0)
    return SPNEGO_NOT_INIT_PACKET;
  if (parse_token_stream_fetch_length(&parse_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;
  // Get the sequence element and length
  if (parse_token_stream_fetch_byte  (&parse_token_stream, &b) <=0 || b != 0x30)
     return SPNEGO_MALFORMED_PACKET;
  if (parse_token_stream_fetch_length(&parse_token_stream, &l)<=0)
    return SPNEGO_MALFORMED_PACKET;

  // Now enumerate the optional ASN1 elements
  while (parse_token_stream.stream_pointer<parse_token_stream.stream_next)
  {
    parse_token_stream_t parse_context_stream;
    // Get the {0xAx,len}
    if (parse_token_stream_fetch_byte(&parse_token_stream, &current_context) <=0)
      return SPNEGO_MALFORMED_PACKET;
    if (parse_token_stream_fetch_length(&parse_token_stream, &l_current_context)<=0)
      return SPNEGO_MALFORMED_PACKET;

    // build a stream for parsing the current context
    parse_token_stream_constructor(&parse_context_stream,(void *)parsed_init_token,parse_token_stream.stream_pointer, l_current_context);
    // Advance the outer stream pointer, we'll enumerate parse_context_stream now
    parse_token_stream.stream_pointer += l_current_context;
    switch (current_context)
    {
      case 0xa0: //      mechTypes     [0]  MechTypeList  OPTIONAL
      {
        // // BER constructed object {0x30,L} {oid_t,oid_t...}
        if (parse_token_stream_fetch_byte  (&parse_context_stream, &b) <=0 || b != 0x30) return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_length(&parse_context_stream, &l)<=0)             return SPNEGO_MALFORMED_PACKET;
        while (parse_context_stream.stream_pointer < parse_context_stream.stream_next)
        {
          r = parse_token_stream_fetch_oid(&parse_context_stream, OID_buffer);
          if (r <= 0)
            return r;
          parsed_init_token->mechTypes[parsed_init_token->mechTypesCount] = oid_string_to_oid_t(OID_buffer);
          if (parsed_init_token->mechTypes[parsed_init_token->mechTypesCount] == oid_none || (parsed_init_token->mechTypesCount+1 == MAX_OID_COUNT) )
            return SPNEGO_MALFORMED_PACKET;
          parsed_init_token->mechTypesCount += 1;
        }
      }
      break;
      case 0xa1: //      reqFlags      [1]  ContextFlags  OPTIONAL,
        if (parse_token_stream_fetch_byte  (&parse_context_stream, &b) <=0 || b != 0x3) return SPNEGO_MALFORMED_PACKET; // BER bit string followed by flags
        if (parse_token_stream_fetch_length(&parse_context_stream, &l)<=0)             return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_flags(&parse_context_stream, &parsed_init_token->Flags)<=0) return SPNEGO_MALFORMED_PACKET;
      break;
      case 0xa2: //      mechToken     [2]  OCTET STRING  OPTIONAL,   Security token to use in the challenge if we support the the protocol in mechTypes[0]. This is called optimistic token and is sent in the hope that server will also select the same mechanism as client.
        if (parse_token_stream_fetch_byte  (&parse_context_stream, &b) <=0 || b != 0x4) return SPNEGO_MALFORMED_PACKET; // BER octet string followed by length of mechToken
        if (parse_token_stream_fetch_length(&parse_context_stream, &l)<=0)             return SPNEGO_MALFORMED_PACKET;
        parsed_init_token->mechToken = malloc(l);
        if (!parsed_init_token->mechToken)
          return SPNEGO_SYSTEM_ERROR;
        parsed_init_token->mechTokenSize = l;
        memcpy(parsed_init_token->mechToken, parse_context_stream.stream_pointer, l);
        break;
      case 0xa3: //      mechListMIC   [3]  OCTET STRING  OPTIONAL    probably this for NTLM tbd "not_defined_in_rfc4178@please_ignore"  Mechanism List Message Integrity Code, Used for signing
        parsed_init_token->mechListMic = malloc(l_current_context);
        if (!parsed_init_token->mechListMic)
          return SPNEGO_SYSTEM_ERROR;
        memcpy(parsed_init_token->mechListMic, parse_context_stream.stream_pointer, l_current_context);
        parsed_init_token->mechListMicSize = l_current_context;
        break;
      break;
      default:
         return SPNEGO_MALFORMED_PACKET;
    }
  }
  return 0;

}

/*
http://davenport.sourceforge.net/ntlm.html#ntlmsspAndSspi
AcceptSecurityContext called with ASC_REQ_INTEGRITY and ASC_REQ_CONFIDENTIALITY.
Produces Type 2 message:

4e544c4d53535000020000000c000c003000000035828100b019d38bad875c9d
0000000000000000460046003c00000054004500530054004e00540002000c00
54004500530054004e00540001000c004d0045004d0042004500520003001e00
6d0065006d006200650072002e0074006500730074002e0063006f006d000000
0000

4e544c4d53535000    "NTLMSSP"
02000000            Type 2 message
0c000c0030000000    Target Name header (length 12, offset 48)
35828100            Flags
    Negotiate Unicode              (0x00000001)
    Request Target                 (0x00000004)
    Negotiate Sign                 (0x00000010)
    Negotiate Seal                 (0x00000020)
    Negotiate NTLM                 (0x00000200)
    Negotiate Always Sign          (0x00008000)
    Target Type Domain             (0x00010000)
    Negotiate Target Info          (0x00800000)
b019d38bad875c9d    Challenge
0000000000000000    Context
460046003c000000    Target Information header (length 70, length 60)
54004500530054004e005400    Target Name ("TESTNT")
Target Information block:
    02000c00    NetBIOS Domain Name (length 12)
    54004500530054004e005400    "TESTNT"
    01000c00    NetBIOS Server Name (length 12)
    4d0045004d00420045005200    "MEMBER"
    03001e00    DNS Server Name (length 30)
    6d0065006d006200650072002e0074006500730074002e0063006f006d00
        "member.test.com"
    00000000    Target Information Terminator




0xA1, len NegTokenTarg
0x30 len  Sequence length
0xA0, 0x03, 0x0A, 0x01  // constant - Seq. Element 0, negResult, length 1
0x0A, 0x01, 0x01        // Enumerated accept incomplete (0,1,2) see below
0xa1, 0xc               // Seq. Element 1 supportedMech NTLM and length C
0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a // NTLM 1.3.6.1.4.1.311.2.2.10

0xa2, len               // Seq. Element 2 response token and length
0xa4, length            // Octet string length



'N','T','L','M','S','S','P','\0',

DATA                    // Challenge data

NegTokenTarg      ::=  SEQUENCE {
   negResult      [0]  ENUMERATED {
                            accept_completed (0),
                            accept_incomplete (1),
                            rejected (2) }  OPTIONAL,
   supportedMech  [1]  MechType             OPTIONAL,
   responseToken  [2]  OCTET STRING         OPTIONAL,
   mechListMIC    [3]  OCTET STRING         OPTIONAL
}


*/

byte sig_blob[] =  {
0xA0, 0x03, 0x0A, 0x01,  // constant - Seq. Element 0, negResult, length 1
0x0A, 0x01, 0x01,        // Enumerated accept incomplete (0,1,2) see below
0xa1, 0xc,               // Seq. Element 1 supportedMech NTLM and length C
0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a // NTLM 1.3.6.1.4.1.311.2.2.10
};
// above Type 2 message
byte dav_blob[] = {
0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x0c,0x00,0x0c,0x00,0x30,0x00,0x00,0x00,0x35,0x82,0x81,0x00,0xb0,0x19,0xd3,0x8b,0xad,0x87,0x5c,0x9d,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,0x00,0x46,0x00,0x3c,0x00,0x00,0x00,0x54,0x00,0x45,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x54,0x00,0x02,0x00,0x0c,0x00,
0x54,0x00,0x45,0x00,0x53,0x00,0x54,0x00,0x4e,0x00,0x54,0x00,0x01,0x00,0x0c,0x00,0x4d,0x00,0x45,0x00,0x4d,0x00,0x42,0x00,0x45,0x00,0x52,0x00,0x03,0x00,0x1e,0x00,
0x6d,0x00,0x65,0x00,0x6d,0x00,0x62,0x00,0x65,0x00,0x72,0x00,0x2e,0x00,0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x2e,0x00,0x63,0x00,0x6f,0x00,0x6d,0x00,0x00,0x00,
0x00,0x00};


#define MAX_OBJECT_PER_OUTPUT_STREAM 32
// Stream data type for chopping a buffer into streams and substreams.
typedef struct spnego_output_stream_s {
  void  *context;
  BBOOL resolving_widths;              // If true we are enumerating to calculate widths
  int  object_index;                  // index at this level of who we are
  int   object_count;                  // If resolving_widths phase is completed this is the maximum depth
#define OBJECT_WIDTH_UNRESOLVED 0x8000 // ored in if we don't know it yet.
  dword  object_widths[MAX_OBJECT_PER_OUTPUT_STREAM];
  byte  *stream_base;
  byte  *stream_pointer;
  byte  *stream_end;
} spnego_output_stream_t;

#define SPNEGO_PACKET_TOO_LARGE -1
#define SPNEGO_OBJCOUNT_TOO_DEEP -2

static int parse_token_stream_encode_byte(spnego_output_stream_t *pstream, byte b)
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

static int parse_token_stream_encode_bytes(spnego_output_stream_t *pstream, byte *pb, size_t width)
{
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
  return width;
}


static int parse_token_stream_get_length_fieldwidth(dword l)
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

static int parse_token_stream_encode_length(spnego_output_stream_t *pstream, dword l)
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
    pstream->object_widths[pstream->object_count] = (dword)1+extra_width;
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

static int parse_token_stream_encode_oid(spnego_output_stream_t *pstream, oid_t oid)
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


//
//
//
//
//

dword resolve_a_30(pstream, int &index)
{
dword sub_length = 0;
int object_index = *index+1;
    while(object_index < pstream->object_count)
    {
      if ((pstream->object_widths[object_index] & OBJECT_WIDTH_UNRESOLVED) != OBJECT_WIDTH_UNRESOLVED)
      {
        sub_length += pstream->object_widths[object_index];
      }
      else
      {
         byte Token = (byte) pstream->object_widths[object_index]&0xf0;
         if (token==0x30)
         {
            sub_length += dword resolve_a_30(pstream, &object_index);
         }
         else
            break;
      }
    }
    return sublength;
}
void resolve_all_30s(spnego_output_stream_t *pstream)
{
int object_index=0;
    while (object_index < pstream->object_count)
    {
      byte Token = 0xff
      if ((pstream->object_widths[object_index] & OBJECT_WIDTH_UNRESOLVED) == OBJECT_WIDTH_UNRESOLVED)
      {
        Token = (byte) pstream->object_widths[object_index]&0xf0;
        if (Token==0x30)
        {
          int new_object_index = object_index;
          pstream->object_widths[object_index] = resolve_a_30(pstream, &new_object_index);
          object_index = new_object_index;
        }
      }
     if (Token!=0x30)
       object_index += 1;
    }
}



static void parse_token_stream_encode_fixup_lengths(spnego_output_stream_t *pstream)
{
 int object_index;
 dword l;

 if (pstream->object_count)
 {
  // Go foreward fixing up 0x30 substreams into resolved values.
  resolve_all_30s(pstream);
  // Now work backwords.
  for (object_index=pstream->object_count-1; object_index >0 ; object_index--)
  {
    if ( (pstream->object_widths[object_index] & OBJECT_WIDTH_UNRESOLVED) == OBJECT_WIDTH_UNRESOLVED)
    {
      byte Tag= (byte) (pstream->object_widths[object_index])&0xff;
      pstream->object_widths[object_index] = l;              // This is what we emit for this tag
//      l += parse_token_stream_get_length_fieldwidth(l);       // Add resolved length of this field to the next nesting level.
    }
    else
      l += pstream->object_widths[object_index];             // Add a known length field.
  }                                                          // we return this to the next nesting level.
 }
}

// Encode an app token or a sequence token. If we are emitting and not counting length also emit the associated lentgh
static int parse_token_stream_encode_app_container(spnego_output_stream_t *pstream, byte Token)
{
int lwidth;
int r;
  if (pstream->resolving_widths)
  {
    lwidth=1;
    dword meta_data = OBJECT_WIDTH_UNRESOLVED|Token;
    if (pstream->object_count+3 >= MAX_OBJECT_PER_OUTPUT_STREAM) return SPNEGO_OBJCOUNT_TOO_DEEP;
    r = parse_token_stream_encode_byte(pstream, Token); if (r < 0) return r;         // Make sure the tag gets pushed into the length arrary
    pstream->object_widths[pstream->object_count++] = OBJECT_WIDTH_UNRESOLVED;       // Length field is unresolved
  }
  else
  {
    dword l;
    r = parse_token_stream_encode_byte(pstream, Token); if (r < 0) return r;   // Encode the tag
    l = pstream->object_widths[pstream->object_index];                         // retrieve count of bytes from the fixup array for length
    r = parse_token_stream_encode_length(pstream, l); if (r < 0) return r;     // encode count of bytes in the rest of the packet into length
    lwidth=1+r;                                                                // Add the 1 for the tag + the bytes needed to encode the length + the length of the blob
    pstream->object_index += 1;                                                // skip the blob
  }
  return lwidth;
}

// Initialize an outout stream or substream starting at stream_base with length stream_len do not zero width accumulators when resolving_widths == FALSE
static void spnego_output_stream_stream_constructor(spnego_output_stream_t *pstream,void  *context,byte  *stream_base, size_t stream_len,BBOOL resolving_widths)
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

int encode_spnego_ntlm2_type2_response_packet(unsigned char *outbuffer, size_t buffer_length)
{
// DATA                    // Challenge data
BBOOL doing_size = TRUE;
spnego_output_stream_t outstream;
int wire_length=0;;
int i;
  for(i=0; i < 2; i++, doing_size = !doing_size)
  {
    int r;
    int saved_object_count=0;
    // On the second pass remember the object count so we can enumerate the size place holders
    spnego_output_stream_stream_constructor(&outstream,0, outbuffer, buffer_length,doing_size);
    // On the second pass fixup the place holders
    if (!doing_size)
      parse_token_stream_encode_fixup_lengths(&outstream);
  // 0xA1, len NegTokenTarg
    r = parse_token_stream_encode_app_container(&outstream, 0xA1); if (r < 0) return r;
    // The length returned for the outer capsule is the wire lentgh
    if (!doing_size)
      wire_length=1+r;
  // 0x30 len  Sequence length
    r = parse_token_stream_encode_app_container(&outstream, 0x30);  if (r < 0) return r;
  // Send this
    //0xA0, 0x03, 0x0A, 0x01  // constant - Seq. Element 0, negResult, length 1
    //0x0A, 0x01, 0x01        // Enumerated accept incomplete (0,1,2) see below
    //0xa1, 0xc               // Seq. Element 1 supportedMech NTLM and length C
    //0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a // NTLM 1.3.6.1.4.1.311.2.2.10
    r = parse_token_stream_encode_bytes(&outstream, sig_blob, sizeof(sig_blob));  if (r < 0) return r;
  // 0xA2, Seq. Element 2 response token and length
    r = parse_token_stream_encode_app_container(&outstream, 0xA2); if (r < 0) return r;
  // 0xa4, length            Octet string length
    r = parse_token_stream_encode_app_container(&outstream, 0xA4);  if (r < 0) return r;
  // Send the securty string
    r = parse_token_stream_encode_bytes(&outstream, dav_blob, sizeof(dav_blob));  if (r < 0) return r;
  }
  return wire_length;
}


#if (0)
int encode_spnego_response_packet(unsigned char *outbuffer, size_t buffer_length)
{
int dav_blob_len = sizeof(dav_blob);
int sig_blob_len = sizeof(sig_blob);
int tag_length=3; // 30 , a2, a4
int dav_blob_len_width =  dav_blob_len < 128?1:2; // 0xx 0r 0x8N 0xWW where N will be 1
int sig_blob_len_width =  1; // 0xx 0r 0x8N 0xWW where N will be 1

    outbuffer[0] = 0xA1;
}
0x30 len  Sequence length
byte sig_blob[] =  {
0xa2, len               // Seq. Element 2 response token and length
0xa4, length            // Octet string length
byte dav_blob[] = {
}

#endif

// Parse a length field and return the value, update the buffer address
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

// Extract the oid field and advance the buffer, return the oid type if it is known
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

// encode length field and return the pointer to the next byte in the stream.
static unsigned char *asn1_encode_length(unsigned char *pbuffer,unsigned long l)
{
unsigned char c;

  c = *pbuffer;
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

/* Useful resources
https://msdn.microsoft.com/en-us/library/ms995331.aspx
https://msdn.microsoft.com/en-us/library/ms995330.aspx
http://blogs.msdn.com/b/openspecification/archive/2011/06/24/authentication-101.aspx
http://davenport.sourceforge.net/ntlm.html#ntlmTerminology


Additionally, when an InitToken is sent, it is prepended by an Application Constructed Object specifier (0x60),
and the OID for SPNEGO (see value in OID table above). This is the generic GSSAPI header.

MechType ::= OBJECT IDENTIFIER
MechTypeList ::= SEQUENCE of MechType

ContextFlags ::= BIT_STRING {
   delegFlag     (0),
   mutualFlag    (1),
   replayFlag    (2),
   sequenceFlag  (3),
   anonFlag      (4),
   confFlag      (5),
   integFlag     (6)
}

NegTokenInit ::= SEQUENCE {
   mechTypes     [0]  MechTypeList  OPTIONAL,
   reqFlags      [1]  ContextFlags  OPTIONAL,
   mechToken     [2]  OCTET STRING  OPTIONAL,   Security token to use in the challenge if we support the the protocol in mechTypes[0]. This is called optimistic token and is sent in the hope that server will also select the same mechanism as client.
   mechListMIC   [3]  OCTET STRING  OPTIONAL    probably this for NTLM tbd "not_defined_in_rfc4178@please_ignore"  Mechanism List Message Integrity Code, Used for signing
}


The little endian representation that you would see in the hex detail window in netmon is
 30 0c 06 0a 2b 06 01 04-01 82 37 02 02 0a. This value is used as the message to generate
 mechListMIC by the client. Client sends this with Authenticate message.
*/


// Zero out a parsed_init_token_t structure that will hold the results of enumerating a NegTokenInit buffer
static void parsed_neg_init_token_constructor(parsed_init_token_t *parsed_token)
{
  rtp_memset(parsed_token,0,sizeof(*parsed_token));
}


// Extract as many as fetch_count bytes from the stream up to the number of bytes left in the stream.
// return the number of bytes consumed, 0 means past end of stream
static int parse_token_stream_fetch(parse_token_stream_t *pstream,byte  *fetch_buffer, size_t fetch_count)
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

// Initialize a stream or substream starting at stream_base with length stream_len
static void parse_token_stream_constructor(parse_token_stream_t *pstream,void  *parsed_token,byte  *stream_base, size_t stream_len)
{
  rtp_memset(pstream,0,sizeof(*pstream));
  pstream->parsed_token = parsed_token;
  pstream->stream_base  = stream_base;
  pstream->stream_pointer=stream_base;
  pstream->stream_next=stream_base+stream_len;
}


// Extract an asn1 encoded length value from a stream
// return the number of bytes consumed, 0 means past end of stream
static int parse_token_stream_fetch_obj(parse_token_stream_t *pstream, void *prv, asn1_objtype_t objtype)
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

        parse_token_stream_fetch_byte(pstream, &b); // consume the oid tag
        lr = parse_token_stream_fetch_obj(pstream, (void *)&l, objtype_length);
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
// return the number of bytes consumed
static int parse_token_stream_fetch_flags(parse_token_stream_t *pstream, dword *pFlags)
{
byte  *saved_stream_pointer = pstream->stream_pointer;
size_t l, unused_bits;
byte b;
dword dw=0;
int r=SPNEGO_MALFORMED_PACKET;
parse_token_stream_t parse_bitstream_stream;

  if (parse_token_stream_fetch_byte(pstream, &b) <=0 || b != 0x03) return SPNEGO_MALFORMED_PACKET;
  if (parse_token_stream_fetch_length(pstream, &l) <=0) return SPNEGO_MALFORMED_PACKET;
      // build a stream for parsing the current context        HEREHERE
  parse_token_stream_constructor(&parse_bitstream_stream, pstream->parsed_token,pstream->stream_pointer,l);

  if (parse_token_stream_fetch_length(&parse_bitstream_stream, &unused_bits) <=0) return SPNEGO_MALFORMED_PACKET;
  if (l >4)
     return SPNEGO_MALFORMED_PACKET;
  while (parse_bitstream_stream.stream_pointer < parse_bitstream_stream.stream_next)
  {
    dw<<=8;
    if (parse_token_stream_fetch_byte(&parse_bitstream_stream, &b) <=0) return SPNEGO_MALFORMED_PACKET;
    dw|=b;
  }
  if (unused_bits)
  {
    dw>>=unused_bits;
  }
  r = (int) (parse_bitstream_stream.stream_pointer-saved_stream_pointer);

}

// Extract an asn1 encoded length value from a stream
// return the number of bytes consumed, 0 means past end of stream
static int parse_token_stream_fetch_length(parse_token_stream_t *pstream, size_t *l)
{
  return parse_token_stream_fetch_obj(pstream, (void *)l, objtype_length);
}
static int parse_token_stream_fetch_oid(parse_token_stream_t *pstream, byte *poid)
{
  return parse_token_stream_fetch_obj(pstream, (void *)poid, objtype_oid);
}
// Extract an asn1 encoded length value from a stream
// return the number of bytes consumed, 0 means past end of stream
static int parse_token_stream_fetch_byte(parse_token_stream_t *pstream, byte *b)
{
  int r=SPNEGO_MALFORMED_PACKET;
  if (pstream->stream_pointer < pstream->stream_next)   // don't go past stream
  {
    *b = *pstream->stream_pointer++;
     r = 1;
  }
  return r;
}



#if (INCLUDE_RTSMB_EXTENDED_SECURITY)
/* See RFC4122 */
void rtsmb_util_get_new_Guid(byte *pGuid)
{
ddword t;
dword *pdw;
word  *pw;
byte   *pb;
word clock_seq = (word) tc_rand();
byte node_address[6];

    rtp_net_get_node_address (node_address);
    pdw = (dword *) pGuid;
    t = rtsmb_util_get_current_filetime();
    *pdw++ = (dword) t;     /* [32] Time low */
    pw = (word *) pdw;                     /* [16] Time hi & version */
    *pw++ = (word) (t>>32) & 0xFFFF;       /* [16] Time mid */
    *pw  = (word) (t>>48) & 0x0FFF;        /* [16] Time hi & version */
    *pw++  |= (1<<12);
    pb  =  (byte *) pw;                     /* [16] clock_seq_hi & reserved */
    *pb =  (byte) ((clock_seq & 0x3F00) >> 8);
    *pb++ |= 0x80;
    tc_memcpy(pb, node_address, sizeof (node_address) );
}
//  local pos, oid = bin.unpack(">A6", smb['security_blob'], 5)
//    sp_nego = ( oid == "\x2b\x06\x01\x05\x05\x02" ) -- check for SPNEGO OID 1.3.6.1.5.5.2
//    byte spnego_blob[128]={0x60,127,0x6,0x2b,0x06,0x01,0x05,0x05,0x02}; works
//                                                   len    neg
//0xa1,0x82,0x01,0x00,0x30,0x81,0xfd,0xa0,0x03,0x0a,(0x01),(0x01),(0xa1,0x0c),OID(0x06),(0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,)0xa2,0x81,0xe7,0x04,0x81,0xe4,0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x26,0x00,0x26,0x00,

/*
#define ASN1_APPLICATION(x) ((x)+0x60)
#define ASN1_APPLICATION_SIMPLE(x) ((x)+0x40)
#define ASN1_SEQUENCE(x) ((x)+0x30)
#define ASN1_CONTEXT(x) ((x)+0xa0)
#define ASN1_CONTEXT_SIMPLE(x) ((x)+0x80)
#define ASN1_GENERAL_STRING 0x1b
#define ASN1_OCTET_STRING 0x4
#define ASN1_OID 0x6
#define ASN1_BOOLEAN 0x1
#define ASN1_INTEGER 0x2
#define ASN1_BIT_STRING 0x3
#define ASN1_ENUMERATED 0xa
#define ASN1_SET 0x31


A1 820100(256)
  30 81FD(253)
    A0 03
      0A 01 01
    A1 0C
      06 0A 2B06010401823702020A
    A2 81E7(231)
      04 81E4(228) 4E544C4D5353500002000000260026003800000015828AE2A4E8571FA5...
*/


typedef struct security_buffer_s {
  word buffer_length;
  word buffer_allocated;
  dword buffer_offset;
 } security_buffer_t;

typedef struct os_versionstruct_s {
  byte major;
  byte minor;
  word build;
  dword ntlm_revision;     //  15
 } os_versionstruct_t;

struct ntlm_type2_s {
 byte  Signature[8];
 dword MessageType;
 security_buffer_t TargetName;
 dword Flags;
 byte  Challenge[8];
 dword Context[2];
 security_buffer_t  TargetInformation;
 os_versionstruct_t OSVersion;
} __attribute__((packed));

typedef struct ntlm_type2_s ntlm_type2_t;



ntlm_type2_t ntlmv2_blob = {
   {'N','T','L','M','S','S','P','\0'},
   0x00000002,
   {0,0,0},
   0x80000020,
   {'C','H','A','L','L','E','N','\0'},
   {0,0},
   {0,0,0},
   {0,0,0,15},
};

// Send this in NTLM reponse to evoke an NTLMSSP_NEGOTIATE response from the client.
// Contents:
// OID: 1.3.6.1.5.5.2 (SPNEGO - Simple Protected Negotiation)
// MechType: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
// principal: not_defined_in_RFC4178@please_ignore
static byte spnego_ntlmssp_blob[] = {
  0x60,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa3,0x2a,0x30,0x28,0xa0,0x26,
  0x1b,0x24,0x6e,0x6f,0x74,0x5f,0x64,0x65,0x66,0x69,0x6e,0x65,0x64,0x5f,0x69,0x6e,0x5f,0x52,0x46,0x43,0x34,0x31,0x37,0x38,0x40,0x70,0x6c,0x65,0x61,0x73,0x65,0x5f,0x69,0x67,0x6e,0x6f,0x72,0x65
};

// Callback to send reponse in NTLMSSP_NEGOTIATE response when the client accepts CAP_EXTENDED_SECURITY and the server is configured for NTLM security.
int rtsmb_util_get_spnego_ntlmssp_blob(byte **pblob)
{
    *pblob = spnego_ntlmssp_blob;
    return sizeof(spnego_ntlmssp_blob);
}

// Forget what this is
byte other_spnego_blob[] = {
0xa1,0x82,0x01,0x00,0x30,0x81,0xfd,0xa0,0x03,0x0a,0x01,0x01,0xa1,0x0c,0x06,
0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x81,0xe7,0x04,0x81,0xe4,0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x26,0x00,0x26,0x00,
0x38,0x00,0x00,0x00,0x15,0x82,0x8a,0xe2,0xa4,0xe8,0x57,0x1f,0xa5,0xd8,0x25,0xea,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x86,0x00,0x86,0x00,0x5e,0x00,0x00,0x00,0x06,0x01,0x00,0x00,0x00,0x00,0x00,0x0f,0x55,0x00,0x42,0x00,0x55,0x00,0x4e,0x00,
0x54,0x00,0x55,0x00,0x31,0x00,0x34,0x00,0x2d,0x00,0x56,0x00,0x49,0x00,0x52,0x00,0x54,0x00,0x55,0x00,0x41,0x00,0x4c,0x00,0x42,0x00,0x4f,0x00,0x58,0x00,0x02,0x00,0x26,0x00,0x55,0x00,0x42,0x00,0x55,0x00,0x4e,0x00,0x54,0x00,0x55,0x00,0x31,0x00,
0x34,0x00,0x2d,0x00,0x56,0x00,0x49,0x00,0x52,0x00,0x54,0x00,0x55,0x00,0x41,0x00,0x4c,0x00,0x42,0x00,0x4f,0x00,0x58,0x00,0x01,0x00,0x26,0x00,0x55,0x00,0x42,0x00,0x55,0x00,0x4e,0x00,0x54,0x00,0x55,0x00,0x31,0x00,0x34,0x00,0x2d,0x00,0x56,0x00,
0x49,0x00,0x52,0x00,0x54,0x00,0x55,0x00,0x41,0x00,0x4c,0x00,0x42,0x00,0x4f,0x00,0x58,0x00,0x04,0x00,0x00,0x00,0x03,0x00,0x26,0x00,0x75,0x00,0x62,0x00,0x75,0x00,0x6e,0x00,0x74,0x00,0x75,0x00,0x31,0x00,0x34,0x00,0x2d,0x00,0x76,0x00,0x69,0x00,
0x72,0x00,0x74,0x00,0x75,0x00,0x61,0x00,0x6c,0x00,0x62,0x00,0x6f,0x00,0x78,0x00,0x00,0x00,0x00,0x00};
int rtsmb_util_get_spnego_other_blob(byte **pblob)
{
    *pblob = other_spnego_blob;
    return sizeof(other_spnego_blob);
}
#endif


