/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * ENUMERATED CBOR codec.
 * ENUMERATED values encode as CBOR unsigned integer (major type 0) for
 * non-negative enumeration numbers, negative integer (major type 1) for
 * negative extension values.
 */
#include <asn_internal.h>
#include <ENUMERATED.h>
#include <cbor_support.h>

asn_enc_rval_t
ENUMERATED_encode_cbor(const asn_TYPE_descriptor_t *td,
                        const asn_cbor_constraints_t *constraints,
                        const void *sptr,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const ENUMERATED_t *st = (const ENUMERATED_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    int64_t value;
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st || !st->buf) ASN__ENCODE_FAILED;

    if(asn_INTEGER2int64(st, &value) != 0) ASN__ENCODE_FAILED;

    if(value >= 0) {
        ret = cbor_write_uint_header(CBOR_MAJOR_UNSIGNED,
                                     (uint64_t)value, cb, app_key);
    } else {
        ret = cbor_write_uint_header(CBOR_MAJOR_NEGATIVE,
                                     (uint64_t)(-1 - value), cb, app_key);
    }

    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
ENUMERATED_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td,
                        const asn_cbor_constraints_t *constraints,
                        void **sptr, const void *buf_ptr, size_t size) {
    ENUMERATED_t *st = (ENUMERATED_t *)*sptr;
    uint8_t major;
    uint64_t value;
    ssize_t consumed;

    (void)opt_codec_ctx;
    (void)td;
    (void)constraints;

    consumed = cbor_read_uint_header((const uint8_t *)buf_ptr, size,
                                     &major, &value);
    if(consumed == 0) ASN__DECODE_STARVED;
    if(consumed < 0) ASN__DECODE_FAILED;

    if(!st) {
        st = (ENUMERATED_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    if(major == CBOR_MAJOR_UNSIGNED) {
        if(asn_uint642INTEGER(st, value) != 0) ASN__DECODE_FAILED;
    } else if(major == CBOR_MAJOR_NEGATIVE) {
        int64_t neg = -1 - (int64_t)value;
        if(asn_int642INTEGER(st, neg) != 0) ASN__DECODE_FAILED;
    } else {
        ASN__DECODE_FAILED;
    }

    asn_dec_rval_t rval = {RC_OK, (size_t)consumed};
    return rval;
}
