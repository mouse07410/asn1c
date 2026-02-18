/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * OCTET STRING CBOR codec.
 * OCTET STRING encodes as CBOR byte string (major type 2).
 * Text/UTF-8 string types encode as CBOR text string (major type 3).
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <cbor_support.h>

/*
 * Encode OCTET STRING as a CBOR byte string.
 */
asn_enc_rval_t
OCTET_STRING_encode_cbor(const asn_TYPE_descriptor_t *td,
                         const asn_cbor_constraints_t *constraints,
                         const void *sptr,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    /* CBOR byte string header (major type 2) */
    ret = cbor_write_bytes_header((size_t)st->size, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /* Byte string contents */
    if(st->size > 0) {
        if(cb(st->buf, (size_t)st->size, app_key) < 0) ASN__ENCODE_FAILED;
        er.encoded += st->size;
    }

    ASN__ENCODED_OK(er);
}

/*
 * Encode a text-based string type as CBOR text string (major type 3).
 */
asn_enc_rval_t
OCTET_STRING_encode_cbor_utf8(const asn_TYPE_descriptor_t *td,
                               const asn_cbor_constraints_t *constraints,
                               const void *sptr,
                               asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    /* CBOR text string header (major type 3) */
    ret = cbor_write_text_header((size_t)st->size, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /* Text string contents */
    if(st->size > 0) {
        if(cb(st->buf, (size_t)st->size, app_key) < 0) ASN__ENCODE_FAILED;
        er.encoded += st->size;
    }

    ASN__ENCODED_OK(er);
}

/*
 * Decode a CBOR byte string into an OCTET STRING.
 */
asn_dec_rval_t
OCTET_STRING_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *td,
                          const asn_cbor_constraints_t *constraints,
                          void **sptr, const void *buf_ptr, size_t size) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_OCTET_STRING_specs;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t str_len;
    ssize_t hlen;

    (void)opt_codec_ctx;
    (void)constraints;

    hlen = cbor_read_uint_header(p, size, &major, &str_len);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;

    if(major != CBOR_MAJOR_BYTES) ASN__DECODE_FAILED;
    if(str_len == (uint64_t)-1) ASN__DECODE_FAILED; /* No indefinite-length */
    if(str_len > size - (size_t)hlen) ASN__DECODE_STARVED;

    if(!st) {
        st = (OCTET_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) ASN__DECODE_FAILED;
    }

    if(str_len > 0) {
        void *buf = REALLOC(st->buf, (size_t)str_len + 1);
        if(!buf) ASN__DECODE_FAILED;
        st->buf = (uint8_t *)buf;
        memcpy(st->buf, p + hlen, (size_t)str_len);
        st->buf[str_len] = '\0';  /* Null-terminate for convenience */
    } else {
        if(!st->buf) {
            st->buf = (uint8_t *)CALLOC(1, 1);
            if(!st->buf) ASN__DECODE_FAILED;
        }
        st->buf[0] = '\0';
    }
    st->size = (int)str_len;

    asn_dec_rval_t rval = {RC_OK, (size_t)(hlen + str_len)};
    return rval;
}

/*
 * Decode a CBOR text string (major type 3) into an OCTET STRING.
 * Also accepts CBOR byte strings (major type 2) for flexibility.
 */
asn_dec_rval_t
OCTET_STRING_decode_cbor_utf8(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td,
                               const asn_cbor_constraints_t *constraints,
                               void **sptr, const void *buf_ptr, size_t size) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_OCTET_STRING_specs;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t str_len;
    ssize_t hlen;

    (void)opt_codec_ctx;
    (void)constraints;

    hlen = cbor_read_uint_header(p, size, &major, &str_len);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;

    /* Accept both text string (major 3) and byte string (major 2) */
    if(major != CBOR_MAJOR_TEXT && major != CBOR_MAJOR_BYTES) {
        ASN__DECODE_FAILED;
    }
    if(str_len == (uint64_t)-1) ASN__DECODE_FAILED; /* No indefinite-length */
    if(str_len > size - (size_t)hlen) ASN__DECODE_STARVED;

    if(!st) {
        st = (OCTET_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) ASN__DECODE_FAILED;
    }

    if(str_len > 0) {
        void *buf = REALLOC(st->buf, (size_t)str_len + 1);
        if(!buf) ASN__DECODE_FAILED;
        st->buf = (uint8_t *)buf;
        memcpy(st->buf, p + hlen, (size_t)str_len);
        st->buf[str_len] = '\0';
    } else {
        if(!st->buf) {
            st->buf = (uint8_t *)CALLOC(1, 1);
            if(!st->buf) ASN__DECODE_FAILED;
        }
        st->buf[0] = '\0';
    }
    st->size = (int)str_len;

    asn_dec_rval_t rval = {RC_OK, (size_t)(hlen + str_len)};
    return rval;
}
