/*-
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_application.h>
#include <INTEGER.h>
#include <cbor_decoder.h>
#include <cbor_encoder.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* A fixed output buffer used by the encoder callback. */
typedef struct output_s {
    uint8_t bytes[64]; /* Encoded output. */
    size_t used; /* Length of encoded output; state variable. */
} output_t;

/*
 * Purpose: append one bounded encoded chunk to a test buffer.
 * Source: CBOR encoder callback contract. Version: 2026-11-12.
 * Inputs: bytes and size describe a chunk; key points to the output buffer.
 * Returns: zero on success or -1 for invalid input or insufficient space.
 * Exceptions: none. Author: asn1c maintainers. History: boundary regression.
 * Example: append("a", 1, &output) writes one byte.
 */
static int
append(const void *bytes, size_t size, void *key) {
    output_t *out = key;
    if(!out || (size && !bytes) || out->used > sizeof(out->bytes)
       || size > sizeof(out->bytes) - out->used) return -1;
    if(size) memcpy(out->bytes + out->used, bytes, size);
    out->used += size;
    return 0;
}

/*
 * Purpose: verify decoding and preferred re-encoding of an integer vector.
 * Source: CBOR integer and bignum representation. Version: 2026-11-12.
 * Inputs: wire and expected are byte sequences with respective lengths.
 * Returns: zero on success, one on failure. Exceptions: none.
 * Author: asn1c maintainers. History: integer boundary regression.
 * Example: check_vector(tagged_zero, 2, zero, 1).
 */
static int
check_vector(const uint8_t *wire, size_t wire_size,
             const uint8_t *expected, size_t expected_size) {
    INTEGER_t *value = 0;
    output_t out = {{0}, 0};
    asn_dec_rval_t decoded = cbor_decode(0, &asn_DEF_INTEGER, (void **)&value, wire, wire_size);
    int failed = decoded.code != RC_OK || decoded.consumed != wire_size;
    if(!failed) {
        asn_enc_rval_t encoded = cbor_encode(&asn_DEF_INTEGER, value, append, &out);
        failed = encoded.encoded < 0 || out.used != expected_size
                 || memcmp(out.bytes, expected, expected_size) != 0;
    }
    if(value) ASN_STRUCT_FREE(asn_DEF_INTEGER, value);
    return failed;
}

/*
 * Purpose: exercise negative major-one limits and permissive bignum input.
 * Source: CBOR integer and bignum representation. Version: 2026-11-12.
 * Inputs: none. Returns: zero on success, one on failure. Exceptions: none.
 * Author: asn1c maintainers. History: integer boundary regression.
 * Example: run check-CBOR-integer-preferred.
 */
int
main(void) {
    static const uint8_t neg63[] = {0x3b,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    static const uint8_t below63[] = {0x3b,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t neg64[] = {0x3b,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    static const uint8_t below64[] = {0xc3,0x49,0x01,0,0,0,0,0,0,0,0};
    static const uint8_t pos64[] = {0xc2,0x49,0x01,0,0,0,0,0,0,0,0};
    static const uint8_t neg64_padded[] = {0xc3,0x49,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    static const uint8_t zero_tag[] = {0xc2,0x40};
    static const uint8_t minus_one_tag[] = {0xc3,0x40};
    static const uint8_t zero[] = {0x00};
    static const uint8_t minus_one[] = {0x20};
    static const uint8_t malformed[][3] = {{0xc2,0x41,0}, {0xc3,0x61,0}, {0xc3,0x5a,0}};
    size_t i;
    if(check_vector(neg63, sizeof(neg63), neg63, sizeof(neg63))
       || check_vector(below63, sizeof(below63), below63, sizeof(below63))
       || check_vector(neg64, sizeof(neg64), neg64, sizeof(neg64))
       || check_vector(below64, sizeof(below64), below64, sizeof(below64))
       || check_vector(pos64, sizeof(pos64), pos64, sizeof(pos64))
       || check_vector(neg64_padded, sizeof(neg64_padded), neg64, sizeof(neg64))
       || check_vector(zero_tag, sizeof(zero_tag), zero, sizeof(zero))
       || check_vector(minus_one_tag, sizeof(minus_one_tag), minus_one, sizeof(minus_one))) return 1;

    /* Truncated heads and non-byte-string bignums must leave existing output intact. */
    for(i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        INTEGER_t *value = 0;
        asn_dec_rval_t result;
        static const uint8_t initial[] = {0x01};
        result = cbor_decode(0, &asn_DEF_INTEGER, (void **)&value, initial, sizeof(initial));
        if(result.code != RC_OK || !value) return 1;
        result = cbor_decode(0, &asn_DEF_INTEGER, (void **)&value, malformed[i], 2);
        if(result.code == RC_OK || value->size != 1 || value->buf[0] != 1) {
            ASN_STRUCT_FREE(asn_DEF_INTEGER, value);
            return 1;
        }
        ASN_STRUCT_FREE(asn_DEF_INTEGER, value);
    }
    puts("CBOR INTEGER preferred encoding passed");
    return 0;
}
