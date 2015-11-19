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
#include "smbpnegoh.h"

#include <malloc.h>
#include <string.h>

// Kerberos OIDs
static const byte SPNEGO[] =  {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};   // 1.3.6.1.5.5.2
static const byte KERBV5[] =  {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}; // 1.2.840.113554.1.2.2
static const byte KERBV5L[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02}; // 1.2.840.48018.1.2.2
static const byte NTLMSSP[] = {0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};   // 1.3.6.1.4.1.311.2.2.10

#define NegTokenInit       0xa0
#define NegTokenTarg       0xa1
#define AppConstructObject 0x60

#define MAX_OID_SIZE 64
#define MAX_OID_COUNT 8

#define SPNEGO_NO_ERROR           0
#define SPNEGO_NOT_INIT_PACKET   -1
#define SPNEGO_MALFORMED_PACKET  -2
#define SPNEGO_SYSTEM_ERROR      -3


// Parse a length field and return the value, update the buffer address
unsigned long asn1_decode_length(unsigned char **ppbuffer)
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
   l=c&0x80;
   pbuffer++;
  }
  *ppbuffer = pbuffer;
  return l;
}
typedef enum {
  oid_none,
  oid_unkown,
  oid_spnego,
  oid_kerb5,
  oid_kerb5l,
  oid_ntlmssp
} oid_t;


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
unsigned char *asn1_encode_length(unsigned char *pbuffer,unsigned long l)
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

#define MAX_OID_SIZE 64
#define MAX_OID_COUNT 8
typedef struct parsed_init_token_s {
 int  mechTypesCount;
 oid_t mechTypes[MAX_OID_COUNT];
 byte  *mechToken;    // null to start, allocated with malloc() and copied in if found and must be freed
 byte  *mechListMic;  // null to start, allocated with malloc() and copied in if found and must be freed
} parsed_init_token_t;

// Stream data type for copping a buffer into streams and substreams.
typedef struct parse_token_stream_s {
  void  *parsed_token;
  byte  *stream_base;
  byte  *stream_pointer;
  byte  *stream_next;
} parse_token_stream_t;

// Zero out a parsed_init_token_t structure that will hold the results of enumerating a NegTokenInit buffer
void parsed_neg_init_token_constructor(parsed_init_token_t *parsed_token)
{
  rtp_memset(parsed_token,0,sizeof(*parsed_token));
}

// Release any allocated storage from a parsed_init_token_t.
void parsed_neg_token_destructor(parsed_init_token_t *parsed_token)
{
  if (parsed_token->mechToken) free(parsed_token->mechToken);
  if (parsed_token->mechListMic) free(parsed_token->mechListMic);
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
     return fetch_count;
  }
  return 0;
}




typedef enum {
  objtype_oid,
  objtype_length,
} asn1_objtype_t;


// Extract an asn1 encoded length value from a stream
// return the number of bytes consumed, 0 means past end of stream

static int parse_token_stream_fetch_obj(parse_token_stream_t *pstream, void *prv, asn1_objtype_t objtype)
{
  int r=SPNEGO_MALFORMED_PACKET;
  byte  *saved_stream_pointer = pstream->stream_pointer;
  if (pstream->stream_pointer < pstream->stream_next)   // don't go past stream
  {
    if (pstream->stream_pointer > pstream->stream_next)
      r = 0;
    else
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
          size_t l = 0;
          int lr = parse_token_stream_fetch_obj(pstream, (void *)&l, objtype_length);
          if (lr)
          {
             size_t oid_l = 1 + lr + l; // Total length == (06 token, PLUS bytes used to encode the length, PLUS the cargo of length=l
             if (saved_stream_pointer+oid_l>pstream->stream_next || oid_l >= MAX_OID_SIZE) // if too long or malformed must be bogus
             {
               r = SPNEGO_MALFORMED_PACKET;;
               pstream->stream_pointer=pstream->stream_next;
             }
             else
             {  // We keep the whole pattern including the 0x6 and the length.
                memcpy(prv, saved_stream_pointer, oid_l);
                pstream->stream_pointer=saved_stream_pointer+oid_l;
             }
             r = 0;
          }
        }
      }
    }
  }
  return r;
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
  parsed_neg_token_constructor(parsed_init_token);

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
  if (r != 0)
    return r;
  if (oid_string_to_oid_t(pbuffer) != oid_spnego)
    return SPNEGO_MALFORMED_PACKET;

  // Get the NegTokenIt Token sequence element and length
  if (parse_token_stream_fetch_byte(&parse_token_stream, &b) <0 || b !=0xA0)
    return SPNEGO_NOT_INIT_PACKET;
  if (parse_token_stream_fetch_length(&parse_token_stream, &l)<0)
    return SPNEGO_MALFORMED_PACKET;

  // Now enumerate the optional ASN1 elements
  while (parse_token_stream.stream_pointer<parse_token_stream.stream_next)
  {
    parse_token_stream_t parse_context_stream;
    // Get the {0xAx,len} NegTokenInit {0xax,length}
    if (parse_token_stream_fetch_byte(&parse_token_stream, &current_context) <0)
      return SPNEGO_MALFORMED_PACKET;
    if (parse_token_stream_fetch_length(&parse_token_stream, &l_current_context)<0)
      return SPNEGO_MALFORMED_PACKET;

    // build a stream for parsing the current context
    parse_token_stream_constructor(&parse_context_stream,(void *)parsed_init_token,parse_token_stream.stream_pointer, l_current_context);
    // Advance the outer stream pointer, we'll enumerate parse_context_stream now
    parse_token_stream.stream_pointer += l_current_context;
    switch (current_context)
    {
      case 0xa0: //      mechTypes     [0]  MechTypeList  OPTIONAL
      {
        // {0x30,L}{A0,L}{0x30,L} {oid_t,oid_t...}
        if (parse_token_stream_fetch_byte  (&parse_context_stream, &b) <0 || b != 0x30) return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_length(&parse_context_stream, &l)<0)             return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_byte  (&parse_context_stream, &b) <0 || b != 0xA0) return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_length(&parse_context_stream, &l)<0)             return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_byte  (&parse_context_stream, &b) <0 || b != 0x30) return SPNEGO_MALFORMED_PACKET;
        if (parse_token_stream_fetch_length(&parse_context_stream, &l)<0)             return SPNEGO_MALFORMED_PACKET;
        while (parse_context_stream.stream_pointer < parse_context_stream.stream_next)
        {
          r = parse_token_stream_fetch_oid(&parse_context_stream, OID_buffer);
          if (r != 0)
            return r;
          parsed_init_token->mechTypes[parsed_init_token->mechTypesCount] = oid_string_to_oid_t(pbuffer);
          if (parsed_init_token->mechTypes[parsed_init_token->mechTypesCount] == oid_none || (parsed_init_token->mechTypesCount+1 == MAX_OID_COUNT) )
            return SPNEGO_MALFORMED_PACKET;
          parsed_init_token->mechTypesCount += 1;
        }
      }
      break;
      case 0xa1: //      reqFlags      [1]  ContextFlags  OPTIONAL,
      break;
      case 0xa2: //      mechToken     [2]  OCTET STRING  OPTIONAL,   Security token to use in the challenge if we support the the protocol in mechTypes[0]. This is called optimistic token and is sent in the hope that server will also select the same mechanism as client.
        parsed_init_token->mechToken = malloc(l_current_context);
        if (!parsed_init_token->mechToken)
          return SPNEGO_SYSTEM_ERROR;
        memcpy(parsed_init_token->mechToken, parse_context_stream.stream_pointer, l_current_context);
        break;
      case 0xa3: //      mechListMIC   [3]  OCTET STRING  OPTIONAL    probably this for NTLM tbd "not_defined_in_rfc4178@please_ignore"  Mechanism List Message Integrity Code, Used for signing
        parsed_init_token->mechListMic = malloc(l_current_context);
        if (!parsed_init_token->mechListMic)
          return SPNEGO_SYSTEM_ERROR;
        memcpy(parsed_init_token->mechListMic, parse_context_stream.stream_pointer, l_current_context);
        break;
      break;
      default:
         return SPNEGO_MALFORMED_PACKET;
    }
  }
  return 0;

}
#if (0)
static bool read_negTokenInit(struct asn1_data *asn1, TALLOC_CTX *mem_ctx,
			      struct spnego_negTokenInit *token)
{
	ZERO_STRUCTP(token);

	if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
	if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;

	while (!asn1->has_error && 0 < asn1_tag_remaining(asn1)) {
		int i;
		uint8_t context;

		if (!asn1_peek_uint8(asn1, &context)) {
			asn1->has_error = true;
			break;
		}

		switch (context) {
		/* Read mechTypes */
		case ASN1_CONTEXT(0): {
			const char **mechTypes;

			if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
			if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;

			mechTypes = talloc(mem_ctx, const char *);
			if (mechTypes == NULL) {
				asn1->has_error = true;
				return false;
			}
			for (i = 0; !asn1->has_error &&
				     0 < asn1_tag_remaining(asn1); i++) {
				char *oid;
				const char **p;
				p = talloc_realloc(mem_ctx,
						   mechTypes,
						   const char *, i+2);
				if (p == NULL) {
					talloc_free(mechTypes);
					asn1->has_error = true;
					return false;
				}
				mechTypes = p;

				if (!asn1_read_OID(asn1, mechTypes, &oid)) return false;
				mechTypes[i] = oid;
			}
			mechTypes[i] = NULL;
			token->mechTypes = mechTypes;

			asn1_end_tag(asn1);
			asn1_end_tag(asn1);
			break;
		}
		/* Read reqFlags */
		case ASN1_CONTEXT(1):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(1))) return false;
			if (!asn1_read_BitString(asn1, mem_ctx, &token->reqFlags,
					    &token->reqFlagsPadding)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
                /* Read mechToken */
		case ASN1_CONTEXT(2):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(2))) return false;
			if (!asn1_read_OctetString(asn1, mem_ctx, &token->mechToken)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
		/* Read mecListMIC */
		case ASN1_CONTEXT(3):
		{
			uint8_t type_peek;
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(3))) return false;
			if (!asn1_peek_uint8(asn1, &type_peek)) {
				asn1->has_error = true;
				break;
			}
			if (type_peek == ASN1_OCTET_STRING) {
				if (!asn1_read_OctetString(asn1, mem_ctx,
						      &token->mechListMIC)) return false;
			} else {
				/* RFC 2478 says we have an Octet String here,
				   but W2k sends something different... */
				char *mechListMIC;
				if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;
				if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
				if (!asn1_read_GeneralString(asn1, mem_ctx, &mechListMIC)) return false;
				if (!asn1_end_tag(asn1)) return false;
				if (!asn1_end_tag(asn1)) return false;

				token->targetPrincipal = mechListMIC;
			}
			if (!asn1_end_tag(asn1)) return false;
			break;
		}
		default:
			asn1->has_error = true;
			break;
		}
	}

	if (!asn1_end_tag(asn1)) return false;
	if (!asn1_end_tag(asn1)) return false;

	return !asn1->has_error;
}

#endif
















#define RTSMB_NB_CHAR_DECOMPRESS(c, h, l) {h=(byte)(((byte)(c>>4)&0x0F)+(byte)0x41); l=(byte)((byte)(c & 0x0F)+(byte)0x41);}
#define RTSMB_NB_CHAR_COMPRESS(h, l, c) {c= (byte)(((byte)(h-0x41)<<4) | (byte)((l-0x41) & 0x0F));}

/* |name| must be RTSMB_NB_NAME_SIZE big */
int rtsmb_nb_fill_name (PFVOID buf, rtsmb_size size, PFCHAR name)
{
	PFVOID s, e;
	int i;
	byte namebuf [RTSMB_NB_NAME_SIZE * 2 + 1];

	for (i = 0; i < RTSMB_NB_NAME_SIZE; i++)
	{
		RTSMB_NB_CHAR_DECOMPRESS (name[i], namebuf[i * 2], namebuf[(i * 2) + 1]);
	}
	namebuf[i * 2] = '\0';

	s = buf;
	PACK_BYTE (buf, &size, RTSMB_NB_NAME_SIZE * 2, -1);	/* size of name in bytes (once it's in the buffer) */
	PACK_ITEM (buf, &size, namebuf, RTSMB_NB_NAME_SIZE * 2 + 1, -1);
	e = buf;

	return (int) PDIFF (e, s);
}

/* |dest| must be (RTSMB_NB_NAME_SIZE + 1) characters big */
int rtsmb_nb_read_name (PFVOID buf, rtsmb_size size, PFCHAR dest)
{
	PFVOID e, s;
	byte b;
	int i;
    byte *bdest = (byte *) dest;
	byte namebuf [RTSMB_NB_NAME_SIZE * 2 + 1];

	s = buf;
	READ_BYTE (buf, &size, &b, -1);	/* size of name in bytes */
	ASSURE (b == RTSMB_NB_NAME_SIZE * 2, -1);
	READ_ITEM (buf, &size, namebuf, RTSMB_NB_NAME_SIZE * 2 + 1, -1);
	e = buf;

	for (i = 0; i < RTSMB_NB_NAME_SIZE; i++)
	{
		RTSMB_NB_CHAR_COMPRESS (namebuf[i * 2], namebuf[(i * 2) + 1], bdest[i]);
	}

	dest[i] = '\0';

	return (int) PDIFF (e, s);
}
