/* Check C direct CBOR primitive and opaque ANY vectors against Rust.
 * Source: C CBOR codec APIs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: Rust CBOR parity.
 */
#include <Flag.h>
#include <Empty.h>
#include <Count.h>
#include <Value.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Bounded callback buffer. */
typedef struct buffer_s {
    unsigned char data[512]; /* Output octet state variable. */
    size_t length; /* Used length state variable. */
} buffer_t;

/* Append callback bytes. Inputs: bytes, length and buffer. Returns zero or -1;
 * no exceptions. Source: CBOR callback API. Version: 2026-10-30. Responsible:
 * asn1c maintainers. History: vector fixture. Example: append("x", 1, &buf).
 */
static int
append(const void *bytes, size_t length, void *key) {
    buffer_t *buffer = key;
    if(!buffer || (!bytes && length) || length > sizeof(buffer->data) - buffer->length) return -1;
    if(length) memcpy(buffer->data + buffer->length, bytes, length);
    buffer->length += length;
    return 0;
}

/* Compare one encoded value and decode the vector. Inputs: descriptor, value,
 * expected bytes and length. Returns zero on success or one on failure; no
 * exceptions. Source: C CBOR API. Version: 2026-10-30. Responsible: asn1c
 * maintainers. History: vector fixture. Example: check(&asn_DEF_Flag, &v, w, 1).
 */
static int
check(asn_TYPE_descriptor_t *type, const void *value, const unsigned char *expected, size_t length) {
    buffer_t output = {{0}, 0};
    void *decoded = NULL;
    asn_enc_rval_t encoded = cbor_encode(type, value, append, &output);
    asn_dec_rval_t result = cbor_decode(NULL, type, &decoded, expected, length);
    int failed = encoded.encoded != (ssize_t)length || output.length != length
        || memcmp(output.data, expected, length) || result.code != RC_OK || !decoded
        || result.consumed != length;
    if(decoded && type->op->compare_struct)
        failed |= type->op->compare_struct(type, value, decoded) != 0;
    if(decoded) ASN_STRUCT_FREE(*type, decoded);
    return failed;
}

/* Compare integer boundary vectors. Input: signed value and its expected wire;
 * returns zero or one; no exceptions. Source: C INTEGER CBOR. Version:
 * 2026-10-30. Responsible: asn1c maintainers. History: integer boundaries.
 * Example: check_integer(-1, {0x20}, 1).
 */
static int
check_integer(intmax_t number, const unsigned char *wire, size_t length) {
    Count_t value = {0};
    int failed;
    if(asn_imax2INTEGER(&value, number)) return 1;
    failed = check(&asn_DEF_Count, &value, wire, length);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Count, &value);
    return failed;
}

/* Run direct CBOR vectors. Inputs: none; returns zero or one; no exceptions.
 * Source: CBOR skeletons. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: primitive interoperability. Example: ./c-cbor.
 */
int
main(void) {
    const unsigned char yes[] = {0xf5}, nil[] = {0xf6}, octets[] = {0x42, 0, 0xa5};
    const unsigned char pos[] = {0x18, 24}, neg[] = {0x38, 24};
    const unsigned char max[] = {0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const unsigned char min[] = {0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char payload[] = {0, 0xa5};
    Flag_t flag = 1; Empty_t empty = 0; Value_t any = {0};
    unsigned char long_payload[256], long_wire[259];
    any.buf = payload; any.size = 2;
    memset(long_payload, 0xa5, sizeof(long_payload));
    long_wire[0] = 0x59; long_wire[1] = 1; long_wire[2] = 0;
    memcpy(long_wire + 3, long_payload, sizeof(long_payload));
    if(check(&asn_DEF_Flag, &flag, yes, sizeof(yes)) || check(&asn_DEF_Empty, &empty, nil, sizeof(nil))
       || check(&asn_DEF_Value, &any, octets, sizeof(octets)) || check_integer(24, pos, sizeof(pos))
       || check_integer(-25, neg, sizeof(neg)) || check_integer(INT64_MAX, max, sizeof(max))
       || check_integer(INT64_MIN, min, sizeof(min))) {
        fputs("C CBOR vector mismatch\n", stderr);
        return 1;
    }
    any.buf = long_payload; any.size = sizeof(long_payload);
    return check(&asn_DEF_Value, &any, long_wire, sizeof(long_wire));
}
