/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * NativeEnumerated CBOR codec.
 * Enumerated values encode as CBOR unsigned integer (major type 0).
 */
#include <asn_internal.h>
#include <NativeEnumerated.h>
#include <cbor_support.h>

asn_enc_rval_t
NativeEnumerated_encode_cbor(const asn_TYPE_descriptor_t *td,
                               const asn_cbor_constraints_t *constraints,
                               const void *sptr,
                               asn_app_consume_bytes_f *cb, void *app_key) {
    const long *native = (const long *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!native) ASN__ENCODE_FAILED;

    if(*native >= 0) {
        ret = cbor_write_uint_header(CBOR_MAJOR_UNSIGNED,
                                     (uint64_t)*native, cb, app_key);
    } else {
        ret = cbor_write_uint_header(CBOR_MAJOR_NEGATIVE,
                                     (uint64_t)(-1 - *native), cb, app_key);
    }

    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
NativeEnumerated_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td,
                               const asn_cbor_constraints_t *constraints,
                               void **sptr, const void *buf_ptr, size_t size) {
    long *native = (long *)*sptr;
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

    if(!native) {
        native = (long *)(*sptr = CALLOC(1, sizeof(*native)));
        if(!native) ASN__DECODE_FAILED;
    }

    if(major == CBOR_MAJOR_UNSIGNED) {
        if(value > (uint64_t)LONG_MAX) ASN__DECODE_FAILED;
        *native = (long)value;
    } else if(major == CBOR_MAJOR_NEGATIVE) {
        if(value > (uint64_t)LONG_MAX) ASN__DECODE_FAILED;
        *native = -1 - (long)value;
    } else {
        ASN__DECODE_FAILED;
    }

    asn_dec_rval_t rval = {RC_OK, (size_t)consumed};
    return rval;
}
