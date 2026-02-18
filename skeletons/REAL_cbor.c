/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * REAL CBOR codec.
 * ASN.1 REAL is encoded as CBOR byte string (major type 2) containing the
 * DER-encoded REAL value, wrapped with CBOR tag 35 to indicate it is an
 * ASN.1 REAL. This preserves precision for all special values (PLUS-INFINITY,
 * MINUS-INFINITY, NOT-A-NUMBER).
 *
 * For common use, clients may prefer NativeReal (double) instead.
 */
#include <asn_internal.h>
#include <REAL.h>
#include <cbor_support.h>

asn_enc_rval_t
REAL_encode_cbor(const asn_TYPE_descriptor_t *td,
                 const asn_cbor_constraints_t *constraints,
                 const void *sptr,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    const REAL_t *st = (const REAL_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    double d;
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    /* Try to encode as a native double for common cases */
    if(asn_REAL2double(st, &d) == 0) {
        ret = cbor_write_double(d, cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded = ret;
        ASN__ENCODED_OK(er);
    }

    /* Fallback: encode as tagged byte string with DER-encoded REAL content */
    ret = cbor_write_tag(CBOR_TAG_OID, cb, app_key);  /* reuse tag for raw REAL */
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

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
REAL_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td,
                 const asn_cbor_constraints_t *constraints,
                 void **sptr, const void *buf_ptr, size_t size) {
    REAL_t *st;
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

    if(!*sptr) {
        *sptr = CALLOC(1, sizeof(REAL_t));
        if(!*sptr) ASN__DECODE_FAILED;
    }
    st = (REAL_t *)*sptr;

    if(major == CBOR_MAJOR_SIMPLE) {
        /* Float-encoded value */
        uint8_t additional = p[0] & 0x1f;
        double d;

        if(additional == 27) {
            /* Double */
            if(size < 9) ASN__DECODE_STARVED;
            uint64_t bits = ((uint64_t)p[1] << 56) | ((uint64_t)p[2] << 48)
                           | ((uint64_t)p[3] << 40) | ((uint64_t)p[4] << 32)
                           | ((uint64_t)p[5] << 24) | ((uint64_t)p[6] << 16)
                           | ((uint64_t)p[7] << 8) | p[8];
            memcpy(&d, &bits, 8);
            if(asn_double2REAL(st, d) != 0) ASN__DECODE_FAILED;
            asn_dec_rval_t rval = {RC_OK, 9};
            return rval;
        } else if(additional == 26) {
            /* Single */
            if(size < 5) ASN__DECODE_STARVED;
            uint32_t bits = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16)
                           | ((uint32_t)p[3] << 8) | p[4];
            float fv;
            memcpy(&fv, &bits, 4);
            d = (double)fv;
            if(asn_double2REAL(st, d) != 0) ASN__DECODE_FAILED;
            asn_dec_rval_t rval = {RC_OK, 5};
            return rval;
        }
        ASN__DECODE_FAILED;
    } else if(major == CBOR_MAJOR_UNSIGNED || major == CBOR_MAJOR_NEGATIVE) {
        double d;
        if(major == CBOR_MAJOR_UNSIGNED) {
            d = (double)value;
        } else {
            d = -1.0 - (double)value;
        }
        if(asn_double2REAL(st, d) != 0) ASN__DECODE_FAILED;
        asn_dec_rval_t rval = {RC_OK, (size_t)hlen};
        return rval;
    } else if(major == CBOR_MAJOR_TAG) {
        /* Tagged byte string with raw DER REAL content */
        uint8_t bytes_major;
        uint64_t bytes_len;
        ssize_t bh_len;
        size_t remaining = size - (size_t)hlen;

        bh_len = cbor_read_uint_header(p + hlen, remaining,
                                        &bytes_major, &bytes_len);
        if(bh_len == 0) ASN__DECODE_STARVED;
        if(bh_len < 0 || bytes_major != CBOR_MAJOR_BYTES) ASN__DECODE_FAILED;
        if(bytes_len > remaining - (size_t)bh_len) ASN__DECODE_STARVED;

        FREEMEM(st->buf);
        st->buf = (uint8_t *)MALLOC(bytes_len + 1);
        if(!st->buf) ASN__DECODE_FAILED;
        memcpy(st->buf, p + hlen + bh_len, bytes_len);
        st->buf[bytes_len] = '\0';
        st->size = (int)bytes_len;

        asn_dec_rval_t rval = {RC_OK, (size_t)(hlen + bh_len + bytes_len)};
        return rval;
    }

    ASN__DECODE_FAILED;
}
