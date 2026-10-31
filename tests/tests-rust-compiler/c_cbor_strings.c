/* Generated C reference for direct Rust CBOR string vectors.
 * Source: C BIT/OCTET STRING CBOR codecs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: Rust CBOR string parity.
 */
#include <FixedOctets.h>
#include <BoundedOctets.h>
#include <FixedBits.h>
#include <BoundedBits.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdio.h>
#include <string.h>

/* Bounded callback storage and used length. */
typedef struct output_s {
    unsigned char bytes[64]; /* Output octet state variable. */
    size_t used; /* Used output length state variable. */
} output_t;

/* Append one encoded fragment to bounded storage.
 * Inputs: bytes/length describe the fragment; key points to output_t.
 * Returns zero or -1. Errors: invalid input/overflow return -1.
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

/* Compare one C encoding and decoding result with the Rust wire vector.
 * Inputs: type/value identify the C value; wire/length are expected bytes.
 * Returns zero or one for mismatch. Errors: none thrown.
 * Source: C CBOR codec API. Version: 2026-10-30. Responsible: maintainers.
 * History: direct string parity. Example: check(&asn_DEF_FixedBits, &bits, w, 3).
 */
static int
check(asn_TYPE_descriptor_t *type, const void *value, const unsigned char *wire, size_t length) {
    output_t output = {{0}, 0};
    void *decoded = NULL;
    asn_enc_rval_t encoded = cbor_encode(type, value, append, &output);
    asn_dec_rval_t result = cbor_decode(NULL, type, &decoded, wire, length);
    int failed = encoded.encoded != (ssize_t)length || output.used != length
        || memcmp(output.bytes, wire, length) || result.code != RC_OK
        || result.consumed != length || !decoded;
    if(decoded && type->op->compare_struct)
        failed |= type->op->compare_struct(type, value, decoded) != 0;
    if(decoded) ASN_STRUCT_FREE(*type, decoded);
    return failed;
}

/* Run C/Rust direct string wire parity checks.
 * Inputs: none. Returns zero on success or one on mismatch. Errors: none thrown.
 * Source: C CBOR string mapping. Version: 2026-10-30.
 * Responsible: maintainers. History: generated C/Rust interop.
 * Example: run `./c-cbor-strings`.
 */
int
main(void) {
    unsigned char octet_data[] = {0xa5, 0x5a};
    unsigned char bit_data[] = {0xa0};
    unsigned char wide_data[] = {0x80, 0};
    FixedOctets_t octets = {0};
    BoundedOctets_t empty_octets = {0};
    FixedBits_t bits = {0};
    BoundedBits_t wide = {0};
    const unsigned char octet_wire[] = {0x42, 0xa5, 0x5a};
    const unsigned char empty_wire[] = {0x40};
    const unsigned char bit_wire[] = {0x42, 5, 0xa0};
    const unsigned char wide_wire[] = {0x43, 7, 0x80, 0};
    octets.buf = octet_data; octets.size = sizeof(octet_data);
    bits.buf = bit_data; bits.size = sizeof(bit_data); bits.bits_unused = 5;
    wide.buf = wide_data; wide.size = sizeof(wide_data); wide.bits_unused = 7;
    if(check(&asn_DEF_FixedOctets, &octets, octet_wire, sizeof(octet_wire))
       || check(&asn_DEF_BoundedOctets, &empty_octets, empty_wire, sizeof(empty_wire))
       || check(&asn_DEF_FixedBits, &bits, bit_wire, sizeof(bit_wire))
       || check(&asn_DEF_BoundedBits, &wide, wide_wire, sizeof(wide_wire))) {
        fputs("C CBOR string vector mismatch\n", stderr);
        return 1;
    }
    return 0;
}
