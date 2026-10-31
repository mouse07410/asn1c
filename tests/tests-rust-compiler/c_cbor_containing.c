/* Check raw C CBOR byte-string parity with typed Rust CONTAINING vectors.
 * Source: C CBOR BIT/OCTET STRING codecs. Version: 2026-10-30.
 * Responsible: maintainers. History: typed Rust CONTAINING CBOR subset.
 */
#include <Oct.h>
#include <Bits.h>
#include <BoolOct.h>
#include <BoolBits.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdio.h>
#include <string.h>

/* Bounded output callback state for one generated encoding. */
typedef struct output_s {
    unsigned char bytes[16]; /* Encoded byte state variable. */
    size_t used; /* Used output length state variable. */
} output_t;

/* Append one encoded fragment to bounded storage.
 * Inputs: bytes and length describe fragment; key points to output.
 * Returns zero on success or -1 on invalid input/overflow. Exceptions: none.
 * Source: CBOR callback API. Version: 2026-10-30. Responsible: maintainers.
 * History: parity fixture. Example: append("x", 1, &output).
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

/* Compare C encoding/decoding with a typed Rust wire vector.
 * Inputs: type/value select C data; wire/length specify expected bytes.
 * Returns zero for parity or one on mismatch. Exceptions: none.
 * Source: C CBOR API. Version: 2026-10-30. Responsible: maintainers.
 * History: typed CONTAINING parity. Example: check(&asn_DEF_Oct, &oct, wire, 2).
 */
static int
check(asn_TYPE_descriptor_t *type, const void *value, const unsigned char *wire, size_t length) {
    output_t output = {{0}, 0};
    void *decoded = NULL;
    asn_enc_rval_t encoded = cbor_encode(type, value, append, &output);
    asn_dec_rval_t result = cbor_decode(NULL, type, &decoded, wire, length);
    int failed = asn_check_constraints_with_syntax(type, value, ATS_CBOR, NULL, NULL) != 0
        || encoded.encoded != (ssize_t)length || output.used != length
        || memcmp(output.bytes, wire, length) || result.code != RC_OK
        || result.consumed != length || !decoded;
    if(decoded && type->op->compare_struct)
        failed |= type->op->compare_struct(type, value, decoded) != 0;
    if(decoded) ASN_STRUCT_FREE(*type, decoded);
    return failed;
}

/* Run four C/Rust CBOR CONTAINING raw-byte vectors.
 * Inputs: none. Returns zero on success or one on mismatch. Exceptions: none.
 * Source: C CBOR mapping. Version: 2026-10-30. Responsible: maintainers.
 * History: typed Rust parity. Example: run `./c-cbor-containing`.
 */
int
main(void) {
    unsigned char integer[] = {2}, boolean[] = {0xf5};
    const unsigned char oct_wire[] = {0x41, 2};
    const unsigned char bit_wire[] = {0x42, 0, 2};
    const unsigned char bool_oct_wire[] = {0x41, 0xf5};
    const unsigned char bool_bit_wire[] = {0x42, 0, 0xf5};
    Oct_t oct = {0}; Bits_t bits = {0};
    BoolOct_t bool_oct = {0}; BoolBits_t bool_bits = {0};
    oct.buf = integer; oct.size = 1;
    bits.buf = integer; bits.size = 1;
    bool_oct.buf = boolean; bool_oct.size = 1;
    bool_bits.buf = boolean; bool_bits.size = 1;
    if(check(&asn_DEF_Oct, &oct, oct_wire, sizeof(oct_wire))
       || check(&asn_DEF_Bits, &bits, bit_wire, sizeof(bit_wire))
       || check(&asn_DEF_BoolOct, &bool_oct, bool_oct_wire, sizeof(bool_oct_wire))
       || check(&asn_DEF_BoolBits, &bool_bits, bool_bit_wire, sizeof(bool_bit_wire))) {
        fputs("C CBOR CONTAINING wire mismatch\n", stderr);
        return 1;
    }
    /* Constraint validation interprets complete inner CBOR and checks bounds. */
    integer[0] = 3;
    if(!asn_check_constraints_with_syntax(&asn_DEF_Oct, &oct, ATS_CBOR, NULL, NULL)) return 1;
    integer[0] = 2;
    bits.bits_unused = 1;
    if(!asn_check_constraints_with_syntax(&asn_DEF_Bits, &bits, ATS_CBOR, NULL, NULL)) return 1;
    return 0;
}
