/* Generated C reference for Rust CBOR SEQUENCE string-field vector.
 * Source: C SEQUENCE and string CBOR codecs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: Rust field parity.
 */
#include <Record.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdio.h>
#include <string.h>

/* Bounded callback storage and used length. */
typedef struct output_s {
    unsigned char bytes[128]; /* Output octets, state variable. */
    size_t used; /* Used output length, state variable. */
} output_t;

/* Append one encoded fragment to bounded output.
 * Inputs: bytes/length are the fragment; key points to output_t.
 * Returns zero or -1 on invalid input or overflow; no exception.
 * Source: CBOR callback API. Version: 2026-10-30. Responsible: maintainers.
 * History: C/Rust vector fixture. Example: append("x", 1, &output).
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

/* Compare C output and decoded fields with Rust's CBOR string map vector.
 * Inputs: none. Returns zero on success or one on mismatch; no exception.
 * Source: generated Record CBOR codec. Version: 2026-10-30.
 * Responsible: maintainers. History: SEQUENCE string-field parity.
 * Example: run `./c-cbor-sequence-strings`.
 */
int
main(void) {
    const unsigned char expected[] = {
        0xa4, 0x64, 'b', 'i', 't', 's', 0x43, 7, 0x80, 0, 0x66, 'o', 'c', 't', 'e',
        't', 's', 0x42, 0xa5, 0x5a, 0x69, 'm', 'a', 'y', 'b', 'e', 'B', 'i', 't',
        's', 0x42, 5, 0xa0, 0x6b, 'm', 'a', 'y', 'b', 'e', 'O', 'c', 't', 'e', 't',
        's', 0x40
    };
    unsigned char bit_data[] = {0x80, 0};
    unsigned char octet_data[] = {0xa5, 0x5a};
    unsigned char maybe_data[] = {0xa0};
    Record_t value = {0};
    Record_t *decoded = NULL;
    BIT_STRING_t maybe_bits = {0};
    OCTET_STRING_t maybe_octets = {0};
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    value.bits.buf = bit_data; value.bits.size = sizeof(bit_data); value.bits.bits_unused = 7;
    value.octets.buf = octet_data; value.octets.size = sizeof(octet_data);
    maybe_bits.buf = maybe_data; maybe_bits.size = sizeof(maybe_data); maybe_bits.bits_unused = 5;
    value.maybeBits = &maybe_bits;
    value.maybeOctets = &maybe_octets;
    encoded = cbor_encode(&asn_DEF_Record, &value, append, &output);
    result = cbor_decode(NULL, &asn_DEF_Record, (void **)&decoded, expected, sizeof(expected));
    if(encoded.encoded != (ssize_t)sizeof(expected) || output.used != sizeof(expected)
       || memcmp(output.bytes, expected, sizeof(expected)) || result.code != RC_OK
       || result.consumed != sizeof(expected) || !decoded
       || decoded->bits.size != sizeof(bit_data) || decoded->bits.bits_unused != 7
       || memcmp(decoded->bits.buf, bit_data, sizeof(bit_data))
       || decoded->octets.size != sizeof(octet_data)
       || memcmp(decoded->octets.buf, octet_data, sizeof(octet_data))
       || !decoded->maybeBits || decoded->maybeBits->bits_unused != 5
       || decoded->maybeBits->size != sizeof(maybe_data)
       || memcmp(decoded->maybeBits->buf, maybe_data, sizeof(maybe_data))
       || !decoded->maybeOctets || decoded->maybeOctets->size != 0) {
        fputs("C CBOR SEQUENCE string vector mismatch\n", stderr);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Record, decoded);
        return 1;
    }
    ASN_STRUCT_FREE(asn_DEF_Record, decoded);
    return 0;
}
