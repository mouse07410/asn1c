/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * NativeReal CBOR codec.
 * Native double encoded as CBOR double-precision float (major type 7, value 27).
 */
#include <asn_internal.h>
#include <NativeReal.h>
#include <cbor_support.h>
#include <math.h>

asn_enc_rval_t
NativeReal_encode_cbor(const asn_TYPE_descriptor_t *td,
                        const asn_cbor_constraints_t *constraints,
                        const void *sptr,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const double *native = (const double *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!native) ASN__ENCODE_FAILED;

    ret = cbor_write_double(*native, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
NativeReal_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td,
                        const asn_cbor_constraints_t *constraints,
                        void **sptr, const void *buf_ptr, size_t size) {
    double *native = (double *)*sptr;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t value;
    ssize_t consumed;

    (void)opt_codec_ctx;
    (void)td;
    (void)constraints;

    consumed = cbor_read_uint_header(p, size, &major, &value);
    if(consumed == 0) ASN__DECODE_STARVED;
    if(consumed < 0) ASN__DECODE_FAILED;

    if(!native) {
        native = (double *)(*sptr = CALLOC(1, sizeof(*native)));
        if(!native) ASN__DECODE_FAILED;
    }

    if(major != CBOR_MAJOR_SIMPLE) {
        /* Also accept integer encoding for backwards compatibility */
        if(major == CBOR_MAJOR_UNSIGNED) {
            *native = (double)value;
        } else if(major == CBOR_MAJOR_NEGATIVE) {
            *native = -1.0 - (double)value;
        } else {
            ASN__DECODE_FAILED;
        }
        asn_dec_rval_t rval = {RC_OK, (size_t)consumed};
        return rval;
    }

    {
        uint8_t additional = p[0] & 0x1f;

        if(additional == 26) {
            /* Single-precision float */
            uint32_t bits;
            float fval;
            if(size < 5) ASN__DECODE_STARVED;
            bits = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16)
                 | ((uint32_t)p[3] << 8) | p[4];
            memcpy(&fval, &bits, 4);
            *native = (double)fval;
            asn_dec_rval_t rval = {RC_OK, 5};
            return rval;
        } else if(additional == 27) {
            /* Double-precision float */
            uint64_t bits;
            if(size < 9) ASN__DECODE_STARVED;
            bits = ((uint64_t)p[1] << 56) | ((uint64_t)p[2] << 48)
                 | ((uint64_t)p[3] << 40) | ((uint64_t)p[4] << 32)
                 | ((uint64_t)p[5] << 24) | ((uint64_t)p[6] << 16)
                 | ((uint64_t)p[7] << 8) | p[8];
            memcpy(native, &bits, 8);
            asn_dec_rval_t rval = {RC_OK, 9};
            return rval;
        } else if(additional == 25) {
            /* Half-precision float (RFC 8949 Appendix D) */
            uint16_t half;
            int exp, mant;
            if(size < 3) ASN__DECODE_STARVED;
            half = (uint16_t)(((uint16_t)p[1] << 8) | p[2]);
            exp = (half >> 10) & 0x1f;
            mant = half & 0x3ff;
            double val;
            if(exp == 0) {
                val = ldexp((double)mant, -24);
            } else if(exp != 31) {
                val = ldexp((double)(mant + 1024), exp - 25);
            } else {
                val = (mant != 0) ? 0.0/0.0 : 1.0/0.0;  /* NaN or Inf */
            }
            *native = (half & 0x8000) ? -val : val;
            asn_dec_rval_t rval = {RC_OK, 3};
            return rval;
        }
    }

    ASN__DECODE_FAILED;
}
