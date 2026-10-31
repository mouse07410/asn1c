/* Compare C ANY APER, OER and JER output with the Rust fixed vectors.
 * Source: generated codec APIs. Version/date: 2026-10-30.
 * Responsible: asn1c maintainers. History: opaque ANY codec parity.
 */
#include <Value.h>
#include <aper_encoder.h>
#include <aper_decoder.h>
#include <oer_encoder.h>
#include <oer_decoder.h>
#include <jer_encoder.h>
#include <jer_decoder.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Output callback state. */
typedef struct buffer_s {
    unsigned char data[32]; /* state variable: encoded token bytes. */
    size_t length; /* state variable: used bytes. */
} buffer_t;

/* Append callback data; returns zero or -1. Inputs are bytes, length, buffer.
 * No exceptions. Source: encoder callback API. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: bounded output for C parity.
 * Example: append("x", 1, &buffer).
 */
static int
append(const void *bytes, size_t length, void *key) {
    buffer_t *buffer = key;
    if(!buffer || (!bytes && length) || length > sizeof(buffer->data) - buffer->length) return -1;
    if(length) memcpy(buffer->data + buffer->length, bytes, length);
    buffer->length += length;
    return 0;
}

/* Compare a payload and decode APER and OER vectors.
 * Input length is 0, 1 or 128; returns zero on success, one on error.
 * No exceptions. Source: C ANY APIs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: additional codec parity.
 * Example: check(128) verifies the long OER length determinant.
 */
static int
check(size_t length) {
    unsigned char payload[128], oer[132], expected[132];
    Value_t value = {0}, *decoded = NULL;
    void *aper = NULL;
    ssize_t aper_len;
    asn_enc_rval_t result;
    asn_dec_rval_t decoded_result;
    size_t header = length < 128 ? 1 : 2;
    int failed;
    memset(payload, 0xa5, sizeof(payload));
    value.buf = payload;
    value.size = (int)length;
    expected[0] = length < 128 ? (unsigned char)length : 0x81;
    if(length >= 128) expected[1] = 0x80;
    memcpy(expected + header, payload, length);
    result = oer_encode_to_buffer(&asn_DEF_Value, NULL, &value, oer, sizeof(oer));
    failed = result.encoded != (ssize_t)(header + length) || memcmp(oer, expected, header + length);
    decoded_result = oer_decode(NULL, &asn_DEF_Value, (void **)&decoded, expected, header + length);
    failed |= decoded_result.code != RC_OK || !decoded || decoded->size != (int)length
        || (length && memcmp(decoded->buf, payload, length));
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    decoded = NULL;
    aper_len = aper_encode_to_new_buffer(&asn_DEF_Value, NULL, &value, &aper);
    expected[0] = length < 128 ? (unsigned char)length : 0x80;
    if(length >= 128) expected[1] = 0x80;
    failed |= aper_len != (ssize_t)(header + length)
        || (aper && memcmp(aper, expected, header + length));
    decoded_result = aper_decode_complete(NULL, &asn_DEF_Value, (void **)&decoded, expected, header + length);
    failed |= decoded_result.code != RC_OK || !decoded || decoded->size != (int)length
        || (length && memcmp(decoded->buf, payload, length));
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    free(aper);
    return failed;
}

/* Verify the fixed hexadecimal JER token. Inputs: none; returns zero or one.
 * No exceptions. Source: ANY_encode_jer. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: initial JER parity.
 * Example: check_jer() verifies the token for 0xa5.
 */
static int
check_jer(void) {
    unsigned char payload[] = {0xa5};
    Value_t value = {0};
    buffer_t buffer = {{0}, 0};
    asn_enc_rval_t result;
    asn_dec_rval_t decoded_result;
    Value_t *decoded = NULL;
    int failed;
    value.buf = payload;
    value.size = 1;
    result = jer_encode(&asn_DEF_Value, &value, JER_F_MINIFIED, append, &buffer);
    decoded_result = jer_decode(NULL, &asn_DEF_Value, (void **)&decoded, "\"A5\"", 4);
    failed = result.encoded != 4 || buffer.length != 4 || memcmp(buffer.data, "\"A5\"", 4)
        || decoded_result.code != RC_OK || !decoded || decoded->size != 1 || decoded->buf[0] != 0xa5;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    return failed;
}

/* Run C vectors. Inputs: none; returns zero or one; no exceptions.
 * Source: ANY codecs. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: initial cross-language vectors. Example: ./c-any-additional.
 */
int
main(void) {
    if(check(0) || check(1) || check(128) || check_jer()) {
        fputs("C ANY additional codec mismatch\n", stderr);
        return 1;
    }
    return 0;
}
