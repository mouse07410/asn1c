/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * OBJECT IDENTIFIER CBOR codec.
 * OID encodes as CBOR byte string (major type 2) containing the
 * DER-encoded OID body (without tag and length), tagged with CBOR tag 6
 * which is the well-known OID tag from the IANA CBOR Tags registry.
 */
#include <asn_internal.h>
#include <OBJECT_IDENTIFIER.h>
#include <cbor_support.h>

asn_enc_rval_t
OBJECT_IDENTIFIER_encode_cbor(const asn_TYPE_descriptor_t *td,
                                const asn_cbor_constraints_t *constraints,
                                const void *sptr,
                                asn_app_consume_bytes_f *cb, void *app_key) {
    const OBJECT_IDENTIFIER_t *st = (const OBJECT_IDENTIFIER_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || !st->buf) ASN__ENCODE_FAILED;

    /* Tag 6: OID (IANA CBOR tag) */
    ret = cbor_write_tag(CBOR_TAG_OID, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /* Byte string containing DER-encoded OID body */
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
OBJECT_IDENTIFIER_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td,
                               const asn_cbor_constraints_t *constraints,
                               void **sptr, const void *buf_ptr, size_t size) {
    OBJECT_IDENTIFIER_t *st = (OBJECT_IDENTIFIER_t *)*sptr;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t value;
    ssize_t hlen;

    (void)opt_codec_ctx;
    (void)td;
    (void)constraints;

    hlen = cbor_read_uint_header(p, size, &major, &value);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;

    /* Accept either tagged (tag 6 + byte string) or bare byte string */
    if(major == CBOR_MAJOR_TAG) {
        if(value != CBOR_TAG_OID) ASN__DECODE_FAILED;
        p += hlen;
        size -= (size_t)hlen;
        hlen = cbor_read_uint_header(p, size, &major, &value);
        if(hlen == 0) ASN__DECODE_STARVED;
        if(hlen < 0) ASN__DECODE_FAILED;
    }

    if(major != CBOR_MAJOR_BYTES) ASN__DECODE_FAILED;
    if(value == (uint64_t)-1) ASN__DECODE_FAILED;  /* No indefinite */
    if(value > size - (size_t)hlen) ASN__DECODE_STARVED;

    if(!st) {
        st = (OBJECT_IDENTIFIER_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    {
        size_t body_len = (size_t)value;
        uint8_t *buf = (uint8_t *)MALLOC(body_len + 1);
        if(!buf) ASN__DECODE_FAILED;
        memcpy(buf, p + hlen, body_len);
        buf[body_len] = '\0';
        FREEMEM(st->buf);
        st->buf = buf;
        st->size = (int)body_len;
    }

    asn_dec_rval_t rval = {RC_OK, (size_t)((p - (const uint8_t *)buf_ptr) + hlen + value)};
    return rval;
}
