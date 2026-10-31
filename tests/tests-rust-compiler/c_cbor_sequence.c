/* C reference for the Rust CBOR SEQUENCE map vector.
 * Source: generated Packet and C CBOR codecs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: constructed CBOR parity.
 */
#include <Packet.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdio.h>
#include <string.h>

/* Bounded output and current write position for callback delivery. */
typedef struct output_s {
    unsigned char bytes[128]; /* Encoded output state variable. */
    size_t used; /* Number of occupied output octets, state variable. */
} output_t;

/* Append one codec callback fragment to a bounded buffer.
 * Inputs: bytes/length are the fragment; key points to output_t.
 * Returns zero or -1 on overflow or invalid input. Errors: none thrown.
 * Source: CBOR callback API. Version: 2026-10-30. Responsible: maintainers.
 * History: vector fixture. Example: append("x", 1, &output).
 */
static int
append(const void *bytes, size_t length, void *key) {
    output_t *output = key;
    if(!output || (!bytes && length) || output->used > sizeof(output->bytes)
       || length > sizeof(output->bytes) - output->used) return -1;
    if(length) memcpy(output->bytes + output->used, bytes, length);
    output->used += length;
    return 0;
}

/* Verify C output equals the Rust vector and C decodes the same value.
 * Inputs: none. Returns zero on success, one on mismatch. Errors: none thrown.
 * Source: C SEQUENCE CBOR mapping. Version: 2026-10-30.
 * Responsible: maintainers. History: Rust/C interoperability regression.
 * Example: run `./c-cbor-sequence`.
 */
int
main(void) {
    const unsigned char expected[] = {
        0xa6, 0x64, 'f', 'l', 'a', 'g', 0xf5, 0x65, 'e', 'm', 'p', 't', 'y', 0xf6,
        0x66, 'a', 'm', 'o', 'u', 'n', 't', 0x21, 0x65, 'm', 'a', 'y', 'b', 'e', 0xf4,
        0x66, 'o', 'p', 'a', 'q', 'u', 'e', 0x42, 0, 0xa5, 0x65, 'u', 's', 'u', 'a',
        'l', 2
    };
    unsigned char octets[] = {0, 0xa5};
    Packet_t value = {0};
    Packet_t *decoded = NULL;
    ANY_t any = {0};
    BOOLEAN_t maybe = 0;
    long usual = 2;
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    value.flag = 1;
    value.amount = -2;
    value.maybe = &maybe;
    value.usual = &usual;
    any.buf = octets;
    any.size = sizeof(octets);
    value.opaque = &any;
    encoded = cbor_encode(&asn_DEF_Packet, &value, append, &output);
    result = cbor_decode(NULL, &asn_DEF_Packet, (void **)&decoded, expected, sizeof(expected));
    if(encoded.encoded != (ssize_t)sizeof(expected) || output.used != sizeof(expected)
       || memcmp(output.bytes, expected, sizeof(expected)) || result.code != RC_OK
       || result.consumed != sizeof(expected) || !decoded || decoded->flag != 1
       || decoded->amount != -2 || !decoded->maybe || *decoded->maybe != 0
       || !decoded->opaque || decoded->opaque->size != sizeof(octets)
       || memcmp(decoded->opaque->buf, octets, sizeof(octets))
       || !decoded->usual || *decoded->usual != usual) {
        fputs("C CBOR SEQUENCE vector mismatch\n", stderr);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
        return 1;
    }
    ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return 0;
}
