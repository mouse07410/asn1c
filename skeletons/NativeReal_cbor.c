/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeReal.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>

/*
 * Purpose: encode a native REAL as a preferred-width CBOR float.
 * Source: NativeReal CBOR mapping. Version: 2026-11-12.
 * Inputs: td/sptr identify the value; cb/app_key consume the encoding.
 * Returns: encoder result. Errors: invalid pointers or callback failures.
 * Author: asn1c maintainers. History: switched to exact shortest float width.
 * Example: a native REAL equal to 1.5 is emitted as binary16.
 */
asn_enc_rval_t
NativeReal_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    double native;
    ssize_t ret;

    if(!td || !sptr || !cb) ASN__ENCODE_FAILED;
    native = NativeReal__get_double(td, sptr);
    ret = cbor_encode_float(native, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode a CBOR float into a native REAL value.
 * Source: NativeReal CBOR mapping. Version: 2026-11-12.
 * Inputs: td/sptr identify the destination; buf/size bound the input item.
 * Returns: decoder result with consumed bytes. Errors: malformed input or
 * destination conversion failures return RC_FAIL. Author: asn1c maintainers.
 * History: added binary16/binary32 input and pointer checks.
 * Example: a tagged binary16 item decodes to its underlying native REAL.
 */
asn_dec_rval_t
NativeReal_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                       const asn_TYPE_descriptor_t *td,
                       void **sptr, const void *buf_ptr, size_t size) {
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    ssize_t tag_skip;
    double d;
    ssize_t consumed;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    (void)opt_codec_ctx;

    if(!td || !sptr || !buf || size == 0) ASN__DECODE_FAILED;

    /* Skip any leading CBOR tags (RFC 8949 §3.4) */
    tag_skip = cbor_skip_tags(buf, size);
    if(tag_skip < 0) ASN__DECODE_FAILED;

    consumed = cbor_decode_float(buf + tag_skip, size - (size_t)tag_skip, &d);
    if(consumed < 0) ASN__DECODE_FAILED;

    if(NativeReal__set(td, sptr, d) < 0) ASN__DECODE_FAILED;

    rval.consumed = (size_t)tag_skip + (size_t)consumed;
    rval.code = RC_OK;
    return rval;
}
