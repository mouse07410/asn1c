/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef _CBOR_SUPPORT_H_
#define _CBOR_SUPPORT_H_

#include <asn_application.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CBOR major types (RFC 8949 section 3.1)
 */
#define CBOR_MAJOR_UINT     0  /* major type 0: unsigned integer */
#define CBOR_MAJOR_NEGINT   1  /* major type 1: negative integer */
#define CBOR_MAJOR_BYTES    2  /* major type 2: byte string */
#define CBOR_MAJOR_TEXT     3  /* major type 3: text string */
#define CBOR_MAJOR_ARRAY    4  /* major type 4: array */
#define CBOR_MAJOR_MAP      5  /* major type 5: map */
#define CBOR_MAJOR_TAG      6  /* major type 6: tagged item */
#define CBOR_MAJOR_SIMPLE   7  /* major type 7: float/simple value */

/*
 * CBOR additional info values for 1/2/4/8-byte argument lengths
 */
#define CBOR_AI_1BYTE       24  /* 1-byte argument follows */
#define CBOR_AI_2BYTE       25  /* 2-byte argument follows */
#define CBOR_AI_4BYTE       26  /* 4-byte argument follows */
#define CBOR_AI_8BYTE       27  /* 8-byte argument follows */

/*
 * CBOR simple values
 */
#define CBOR_SV_FALSE       0xF4  /* simple value: false */
#define CBOR_SV_TRUE        0xF5  /* simple value: true */
#define CBOR_SV_NULL        0xF6  /* simple value: null */
#define CBOR_SV_UNDEF       0xF7  /* simple value: undefined */

/*
 * CBOR tags (RFC 8949 section 3.4 and IANA CBOR Tags Registry).
 * Full list: https://www.iana.org/assignments/cbor-tags/
 */
#define CBOR_TAG_DATETIME_STRING    0   /* Standard date/time string (text) */
#define CBOR_TAG_EPOCH_DATETIME     1   /* Epoch-based date/time (number) */
#define CBOR_TAG_POSINT_BIGNUM      2   /* Positive bignum (bytes) */
#define CBOR_TAG_NEGINT_BIGNUM      3   /* Negative bignum (bytes) */
#define CBOR_TAG_DECIMAL_FRACTION   4   /* Decimal fraction [exp, mantissa] */
#define CBOR_TAG_BIGFLOAT           5   /* Bigfloat [exp, mantissa] */
#define CBOR_TAG_BASE64URL          21  /* Expected base64url encoding hint */
#define CBOR_TAG_BASE64             22  /* Expected base64 encoding hint */
#define CBOR_TAG_BASE16             23  /* Expected base16 encoding hint */
#define CBOR_TAG_ENCODED_CBOR       24  /* Encoded CBOR data item (bytes) */
#define CBOR_TAG_URI                32  /* URI (text) */
#define CBOR_TAG_BASE64URL_STR      33  /* Base64url string (text) */
#define CBOR_TAG_BASE64_STR         34  /* Base64 string (text) */
#define CBOR_TAG_REGEX              35  /* Regular expression (text) */
#define CBOR_TAG_MIME_MESSAGE       36  /* MIME message (text) */
#define CBOR_TAG_UUID               37  /* Binary UUID (bytes, 16 octets) */
#define CBOR_TAG_CBOR_SEQ           63  /* CBOR sequence (bytes) */
#define CBOR_TAG_NETWORK_ADDR      260  /* Network address (IPv4/IPv6/MAC) */
#define CBOR_TAG_SELF_DESCRIBED  55799  /* Self-described CBOR marker */

/*
 * Encode a CBOR item header (major type + argument) into the stream.
 * Uses shortest canonical encoding.
 * Returns number of bytes written (>0), or -1 on callback error.
 */
ssize_t cbor_encode_head(uint8_t major, uint64_t argument,
                         asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Decode a CBOR item header from buffer.
 * Returns number of bytes consumed (>0), or -1 on error/truncation.
 * On success, sets *major_out and *argument_out.
 */
ssize_t cbor_decode_head(const uint8_t *buf, size_t size,
                         uint8_t *major_out, uint64_t *argument_out);

/* Validate strict RFC 3629 UTF-8 for a CBOR text string; 1 valid, 0 invalid. */
int cbor_utf8_valid(const uint8_t *data, size_t length);

/*
 * Encode a CBOR unsigned integer (canonical: shortest encoding).
 */
ssize_t cbor_encode_uint(uint64_t value,
                         asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Encode a CBOR negative integer.
 * Encodes -(value+1). Canonical shortest encoding.
 */
ssize_t cbor_encode_negint(uint64_t value,
                           asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Encode a CBOR byte string (header + data).
 */
ssize_t cbor_encode_bytes(const void *data, size_t len,
                          asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Encode a CBOR text string (header + data).
 */
ssize_t cbor_encode_text(const char *str, size_t len,
                         asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Encode a CBOR tag.
 */
ssize_t cbor_encode_tag(uint64_t tag,
                        asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Skip any leading CBOR tag headers from the buffer.
 * CBOR tags (major type 6) are optional semantic annotations that precede
 * a data item. Tag-transparent decoders call this function to strip tags
 * before decoding the underlying value.
 *
 * Returns the total number of bytes consumed by leading tags (>= 0), or
 * -1 on error (truncated input).  A return value of 0 means no tags were
 * present.  The caller must add the returned value to the final consumed
 * count so that tags are correctly accounted for in the input stream.
 */
ssize_t cbor_skip_tags(const uint8_t *buf, size_t size);

/*
 * Emit a complete single-byte simple encoding (0xe0..0xf7), including
 * CBOR_SV_TRUE/FALSE/NULL/UNDEF. The argument is an encoded octet, not a
 * logical simple-value number. For floats use cbor_encode_float().
 */
ssize_t cbor_encode_simple(uint8_t simple_val,
                           asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Encode a CBOR IEEE 754 double in the explicit 64-bit representation.
 * This compatibility helper always emits nine bytes, including for values
 * that have exact half- or single-precision representations.
 */
ssize_t cbor_encode_float64(double value,
                            asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Decode an explicit CBOR IEEE 754 double (input must start with 0xFB).
 * Returns 9 bytes on success or -1 on invalid pointers or truncation.
 */
ssize_t cbor_decode_float64(const uint8_t *buf, size_t size, double *value_out);

/*
 * Encode a CBOR IEEE 754 value using the shortest exact width (half, single,
 * then double). NaNs use the canonical half-precision encoding f9 7e 00.
 * This is preferred-width serialization and does not canonicalize map keys.
 * Returns the encoded byte count, or -1 for a null callback or callback error.
 */
ssize_t cbor_encode_float(double value,
                          asn_app_consume_bytes_f *cb, void *app_key);

/*
 * Decode one CBOR IEEE 754 value in half-, single-, or double-precision form.
 * Returns the consumed byte count (3, 5, or 9), or -1 for invalid pointers,
 * non-float input, or truncation. The decoded value is written on success.
 */
ssize_t cbor_decode_float(const uint8_t *buf, size_t size, double *value_out);

/*
 * Skip a complete CBOR data item starting at buf[0].
 * Handles definite and indefinite arrays, maps and strings, tags, integers,
 * floats and simple values. Validates UTF-8 per text chunk and rejects
 * malformed simple values. This is structural validation: duplicate generic
 * map keys and registered tag semantics remain the application's responsibility.
 * Returns total bytes consumed, or -1 on error/truncation/stack limit or
 * nesting beyond 128 levels (also enforced when stack checks are disabled).
 */
ssize_t cbor_skip_item_with_ctx(const asn_codec_ctx_t *opt_codec_ctx,
                                const uint8_t *buf, size_t size);

/*
 * Compatibility wrapper for callers that do not have decoder context.
 * ASN.1 decoders should call cbor_skip_item_with_ctx() so recursive
 * skipping is covered by the same stack limit as normal decoding.
 */
ssize_t cbor_skip_item(const uint8_t *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif  /* _CBOR_SUPPORT_H_ */
