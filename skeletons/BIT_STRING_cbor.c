/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * BIT STRING CBOR codec.
 * BIT STRING encodes as CBOR byte string (major type 2).
 * The first byte of the byte string contains the number of unused bits
 * in the last byte (0-7). This mirrors the BER/DER encoding convention.
 * For a BIT STRING with no content, the encoding is a 1-byte string
 * containing 0x00.
 */
#include <asn_internal.h>
#include <BIT_STRING.h>
#include <cbor_support.h>

asn_enc_rval_t
BIT_STRING_encode_cbor(const asn_TYPE_descriptor_t *td,
                        const asn_cbor_constraints_t *constraints,
                        const void *sptr,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    uint8_t unused_bits;
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    unused_bits = st->bits_unused & 0x07;

    /* Encode as CBOR byte string: [unused_bits] || content */
    ret = cbor_write_bytes_header((size_t)st->size + 1, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /* First byte: unused bits count */
    if(cb(&unused_bits, 1, app_key) < 0) ASN__ENCODE_FAILED;
    er.encoded += 1;

    /* BIT STRING content */
    if(st->size > 0) {
        if(cb(st->buf, (size_t)st->size, app_key) < 0) ASN__ENCODE_FAILED;
        er.encoded += st->size;
    }

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
BIT_STRING_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td,
                        const asn_cbor_constraints_t *constraints,
                        void **sptr, const void *buf_ptr, size_t size) {
    BIT_STRING_t *st = (BIT_STRING_t *)*sptr;
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
    if(str_len == (uint64_t)-1) ASN__DECODE_FAILED;  /* No indefinite */
    if(str_len < 1) ASN__DECODE_FAILED;  /* Must have at least 1 byte for unused */
    if(str_len > size - (size_t)hlen) ASN__DECODE_STARVED;

    if(!st) {
        st = (BIT_STRING_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    {
        const uint8_t *body = p + hlen;
        uint8_t unused = body[0] & 0x07;
        size_t content_len = (size_t)str_len - 1;

        st->bits_unused = unused;

        if(content_len > 0) {
            void *buf = REALLOC(st->buf, content_len + 1);
            if(!buf) ASN__DECODE_FAILED;
            st->buf = (uint8_t *)buf;
            memcpy(st->buf, body + 1, content_len);
            st->buf[content_len] = '\0';
        } else {
            FREEMEM(st->buf);
            st->buf = (uint8_t *)CALLOC(1, 1);
            if(!st->buf) ASN__DECODE_FAILED;
        }
        st->size = (int)content_len;
    }

    asn_dec_rval_t rval = {RC_OK, (size_t)(hlen + str_len)};
    return rval;
}
