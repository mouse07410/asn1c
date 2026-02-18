/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * CBOR (Concise Binary Object Representation) support.
 * RFC 7049 (original), RFC 8949 (STD 94, update), RFC 8742, RFC 8610.
 */
#ifndef CBOR_SUPPORT_H
#define CBOR_SUPPORT_H

#include <asn_system.h>  /* Platform-specific types */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CBOR major types (upper 3 bits of initial byte).
 */
#define CBOR_MAJOR_UNSIGNED  0   /* Major type 0: unsigned integer */
#define CBOR_MAJOR_NEGATIVE  1   /* Major type 1: negative integer */
#define CBOR_MAJOR_BYTES     2   /* Major type 2: byte string */
#define CBOR_MAJOR_TEXT      3   /* Major type 3: text string */
#define CBOR_MAJOR_ARRAY     4   /* Major type 4: array */
#define CBOR_MAJOR_MAP       5   /* Major type 5: map */
#define CBOR_MAJOR_TAG       6   /* Major type 6: tagged item */
#define CBOR_MAJOR_SIMPLE    7   /* Major type 7: float/simple */

/*
 * CBOR simple values (major type 7).
 */
#define CBOR_SIMPLE_FALSE    20  /* Boolean false */
#define CBOR_SIMPLE_TRUE     21  /* Boolean true */
#define CBOR_SIMPLE_NULL     22  /* Null */
#define CBOR_SIMPLE_UNDEF    23  /* Undefined */

/*
 * CBOR well-known tags (RFC 8949, Appendix B).
 */
#define CBOR_TAG_DATETIME_STRING  0   /* Date/time string */
#define CBOR_TAG_DATETIME_NUM     1   /* Epoch-based date/time */
#define CBOR_TAG_BIGNUM_POS       2   /* Positive bignum */
#define CBOR_TAG_BIGNUM_NEG       3   /* Negative bignum */
#define CBOR_TAG_DECIMAL_FRAC     4   /* Decimal fraction */
#define CBOR_TAG_BIGFLOAT         5   /* Bigfloat */
#define CBOR_TAG_OID             35   /* Object Identifier */
#define CBOR_TAG_CBOR_SEQ       100   /* CBOR sequence (RFC 8742) */

/*
 * Pre-computed CBOR constraints.
 * Currently empty; kept for future extension and API symmetry with OER/JER.
 */
typedef struct asn_cbor_constraints_s {
    int unused; /* Placeholder; no CBOR-specific constraints yet */
} asn_cbor_constraints_t;

/*
 * Encode a CBOR unsigned integer header (major type + length/value).
 * major: one of CBOR_MAJOR_*
 * value: the value or length to encode
 * buf: output buffer (must have at least 9 bytes)
 * Returns: number of bytes written (1, 2, 3, 5, or 9)
 */
size_t cbor_encode_uint_header(uint8_t major, uint64_t value,
                               uint8_t *buf);

/*
 * Write a CBOR header (major type + length/value) via callback.
 * Returns: number of bytes written, or -1 on failure.
 * Note: cb must be compatible with asn_app_consume_bytes_f signature.
 */
ssize_t cbor_write_uint_header(uint8_t major, uint64_t value,
                                asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Decode a CBOR initial byte: returns major type and argument value.
 * buf:   input buffer
 * size:  buffer size
 * major_out: receives the major type (CBOR_MAJOR_*)
 * value_out: receives the additional value (count, length, etc.)
 * Returns: number of bytes consumed, or:
 *   0  if more data is needed
 *  -1  if the encoding is invalid
 */
ssize_t cbor_read_uint_header(const uint8_t *buf, size_t size,
                               uint8_t *major_out, uint64_t *value_out);

ssize_t cbor_write_text_header(size_t length, asn_app_consume_bytes_f *cb,
                                void *app_key);
ssize_t cbor_write_bytes_header(size_t length, asn_app_consume_bytes_f *cb,
                                 void *app_key);
ssize_t cbor_write_array_header(size_t count, asn_app_consume_bytes_f *cb,
                                 void *app_key);
ssize_t cbor_write_map_header(size_t count, asn_app_consume_bytes_f *cb,
                               void *app_key);
ssize_t cbor_write_simple(uint8_t simple_value, asn_app_consume_bytes_f *cb,
                           void *app_key);
ssize_t cbor_write_tag(uint64_t tag_number, asn_app_consume_bytes_f *cb,
                        void *app_key);
ssize_t cbor_write_double(double value, asn_app_consume_bytes_f *cb,
                           void *app_key);

#ifdef __cplusplus
}
#endif

#endif  /* CBOR_SUPPORT_H */
