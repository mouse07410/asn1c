/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NULL.h>
#include <cbor_support.h>

asn_enc_rval_t
NULL_encode_cbor(const asn_TYPE_descriptor_t *td,
                 const asn_cbor_constraints_t *constraints,
                 const void *sptr,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;
    (void)sptr;

    /* CBOR null: simple value 0xF6 */
    ret = cbor_write_simple(CBOR_SIMPLE_NULL, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
NULL_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td,
                 const asn_cbor_constraints_t *constraints,
                 void **sptr, const void *buf_ptr, size_t size) {
    NULL_t *st = (NULL_t *)*sptr;
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

    /* Accept CBOR null (simple 22) or undefined (simple 23) */
    if(major != CBOR_MAJOR_SIMPLE) ASN__DECODE_FAILED;
    if(value != CBOR_SIMPLE_NULL && value != CBOR_SIMPLE_UNDEF) {
        ASN__DECODE_FAILED;
    }

    if(!st) {
        st = (NULL_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    asn_dec_rval_t rval = {RC_OK, (size_t)consumed};
    return rval;
}
