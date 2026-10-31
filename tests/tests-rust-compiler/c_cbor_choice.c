/* Generated C reference for Rust direct CBOR CHOICE vectors.
 * Source: C CHOICE CBOR one-pair map codec. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: Rust CBOR CHOICE parity.
 */
#include <Value.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdio.h>
#include <string.h>

/* Bounded callback output and used length. */
typedef struct output_s {
    unsigned char bytes[64]; /* Output octets, state variable. */
    size_t used; /* Occupied length, state variable. */
} output_t;

/* Append a codec callback fragment to bounded output.
 * Inputs: bytes/length are the fragment; key points to output_t.
 * Returns zero or -1 on invalid input or overflow. Errors: none thrown.
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

/* Compare one C CHOICE encoding and decoding result with a Rust wire vector.
 * Inputs: value is selected CHOICE; wire/length are expected bytes.
 * Returns zero or one on mismatch. Errors: none thrown.
 * Source: CHOICE CBOR codec. Version: 2026-10-30. Responsible: maintainers.
 * History: variant interoperability. Example: check(&value, wire, 7).
 */
static int
check(const Value_t *value, const unsigned char *wire, size_t length) {
    output_t output = {{0}, 0};
    Value_t *decoded = NULL;
    asn_enc_rval_t encoded = cbor_encode(&asn_DEF_Value, value, append, &output);
    asn_dec_rval_t result = cbor_decode(NULL, &asn_DEF_Value, (void **)&decoded, wire, length);
    int failed = encoded.encoded != (ssize_t)length || output.used != length
        || memcmp(output.bytes, wire, length) || result.code != RC_OK
        || result.consumed != length || !decoded || decoded->present != value->present;
    if(decoded && asn_DEF_Value.op->compare_struct)
        failed |= asn_DEF_Value.op->compare_struct(&asn_DEF_Value, value, decoded) != 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    return failed;
}

/* Check every direct CHOICE alternative against Rust CBOR bytes.
 * Inputs: none. Returns zero on success or one on mismatch. Errors: none.
 * Source: generated Value CBOR codec. Version: 2026-10-30.
 * Responsible: maintainers. History: bounded Rust CHOICE slice.
 * Example: run `./c-cbor-choice`.
 */
int
main(void) {
    const unsigned char flag_wire[] = {0xa1, 0x64, 'f', 'l', 'a', 'g', 0xf5};
    const unsigned char null_wire[] = {0xa1, 0x65, 'e', 'm', 'p', 't', 'y', 0xf6};
    const unsigned char count_wire[] = {0xa1, 0x65, 'c', 'o', 'u', 'n', 't', 0x21};
    const unsigned char data_wire[] = {0xa1, 0x64, 'd', 'a', 't', 'a', 0x42, 0, 0xa5};
    unsigned char data[] = {0, 0xa5};
    Value_t value = {0};
    value.present = Value_PR_flag;
    value.choice.flag = 1;
    if(check(&value, flag_wire, sizeof(flag_wire))) return 1;
    value.present = Value_PR_empty;
    value.choice.empty = 0;
    if(check(&value, null_wire, sizeof(null_wire))) return 1;
    value.present = Value_PR_count;
    value.choice.count = -2;
    if(check(&value, count_wire, sizeof(count_wire))) return 1;
    value.present = Value_PR_data;
    value.choice.data.buf = data;
    value.choice.data.size = sizeof(data);
    if(check(&value, data_wire, sizeof(data_wire))) {
        fputs("C CBOR CHOICE vector mismatch\n", stderr);
        return 1;
    }
    return 0;
}
