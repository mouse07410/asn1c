/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BOOLEAN.h>
#include <cbor_support.h>

asn_enc_rval_t
BOOLEAN_encode_cbor(const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    const void *sptr,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;
    (void)constraints;

    if(!st) ASN__ENCODE_FAILED;

    /* CBOR: simple value 0xF5 (true) or 0xF4 (false) */
    ret = cbor_write_simple(*st ? CBOR_SIMPLE_TRUE : CBOR_SIMPLE_FALSE,
                            cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
BOOLEAN_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    void **sptr, const void *buf_ptr, size_t size) {
    BOOLEAN_t *st = (BOOLEAN_t *)*sptr;
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

    /* Accept only CBOR simple values true (21) and false (20) */
    if(major != CBOR_MAJOR_SIMPLE) ASN__DECODE_FAILED;
    if(value != CBOR_SIMPLE_FALSE && value != CBOR_SIMPLE_TRUE) {
        ASN__DECODE_FAILED;
    }

    if(!st) {
        st = (BOOLEAN_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    *st = (value == CBOR_SIMPLE_TRUE) ? 0xFF : 0;

    asn_dec_rval_t rval = {RC_OK, (size_t)consumed};
    return rval;
}
