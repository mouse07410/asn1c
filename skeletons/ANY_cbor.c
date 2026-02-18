/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * ANY CBOR codec.
 * The ANY type encodes as a CBOR byte string (major type 2) containing
 * the raw BER-encoded value.
 */
#include <asn_internal.h>
#include <ANY.h>
#include <cbor_support.h>

asn_enc_rval_t
ANY_encode_cbor(const asn_TYPE_descriptor_t *td,
                const asn_cbor_constraints_t *constraints,
                const void *sptr,
                asn_app_consume_bytes_f *cb, void *app_key) {
    const ANY_t *st = (const ANY_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    /* Encode as CBOR byte string */
    ret = cbor_write_bytes_header((size_t)st->size, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    if(st->size > 0) {
        if(cb(st->buf, (size_t)st->size, app_key) < 0) ASN__ENCODE_FAILED;
        er.encoded += st->size;
    }

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
ANY_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_cbor_constraints_t *constraints,
                void **sptr, const void *buf_ptr, size_t size) {
    ANY_t *st = (ANY_t *)*sptr;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t str_len;
    ssize_t hlen;

    (void)opt_codec_ctx;
    (void)td;
    (void)constraints;

    hlen = cbor_read_uint_header(p, size, &major, &str_len);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;

    if(major != CBOR_MAJOR_BYTES) ASN__DECODE_FAILED;
    if(str_len == (uint64_t)-1) ASN__DECODE_FAILED;
    if(str_len > size - (size_t)hlen) ASN__DECODE_STARVED;

    if(!st) {
        st = (ANY_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    {
        void *buf = REALLOC(st->buf, (size_t)str_len + 1);
        if(!buf) ASN__DECODE_FAILED;
        st->buf = (uint8_t *)buf;
        memcpy(st->buf, p + hlen, (size_t)str_len);
        st->buf[str_len] = '\0';
        st->size = (int)str_len;
    }

    asn_dec_rval_t rval = {RC_OK, (size_t)(hlen + str_len)};
    return rval;
}
