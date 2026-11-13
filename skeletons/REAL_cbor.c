/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <REAL.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>

/*
 * Purpose: encode an ASN.1 REAL as a preferred-width CBOR float.
 * Source: ASN.1 REAL CBOR mapping. Version: 2026-11-12.
 * Inputs: td/sptr identify the value; cb/app_key consume the encoding.
 * Returns: encoder result. Errors: invalid REAL values or callback failures.
 * Author: asn1c maintainers. History: switched to exact shortest float width.
 * Example: a REAL equal to 1.5 is emitted as binary16.
 */
asn_enc_rval_t
REAL_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    const REAL_t *st = (const REAL_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    double d;
    ssize_t ret;

    (void)td;

    if(!st || !st->buf || !cb) ASN__ENCODE_FAILED;
    if(asn_REAL2double(st, &d)) ASN__ENCODE_FAILED;

    ret = cbor_encode_float(d, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode a CBOR float into an ASN.1 REAL.
 * Source: ASN.1 REAL CBOR mapping. Version: 2026-11-12.
 * Inputs: td/sptr identify the destination; buf/size bound the input item.
 * Returns: decoder result with consumed bytes. Errors: malformed input or
 * allocation/conversion failures return RC_FAIL. Author: asn1c maintainers.
 * History: added binary16/binary32 input and pointer checks.
 * Example: a tagged binary16 item decodes to its underlying REAL.
 */
asn_dec_rval_t
REAL_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td,
                 void **sptr, const void *buf_ptr, size_t size) {
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    REAL_t *st;
    ssize_t tag_skip;
    double d;
    ssize_t consumed;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    (void)opt_codec_ctx;
    (void)td;

    if(!sptr || !buf || size == 0) ASN__DECODE_FAILED;
    st = (REAL_t *)*sptr;
    if(!st) {
        st = (REAL_t *)CALLOC(1, sizeof(*st));
        if(!st) ASN__DECODE_FAILED;
        *sptr = st;
    }

    /* Skip any leading CBOR tags (RFC 8949 §3.4) */
    tag_skip = cbor_skip_tags(buf, size);
    if(tag_skip < 0) ASN__DECODE_FAILED;

    consumed = cbor_decode_float(buf + tag_skip, size - (size_t)tag_skip, &d);
    if(consumed < 0) ASN__DECODE_FAILED;

    if(asn_double2REAL(st, d)) ASN__DECODE_FAILED;

    rval.consumed = (size_t)tag_skip + (size_t)consumed;
    rval.code = RC_OK;
    return rval;
}
