/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BIT_STRING.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>

/*
 * Purpose: encode BIT STRING as a byte string with one unused-bit octet.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: td identifies the type; sptr is the BIT STRING; cb/app_key consume
 * output. Returns: encoded bytes or failure. Errors: invalid length, padding,
 * or callback fail. Author: asn1c maintainers.
 * History: added padding and overflow validation.
 * Example: a one-bit 0x80 value emits 0x42 0x07 0x80.
 */
asn_enc_rval_t
BIT_STRING_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;
    uint8_t unused_byte;

    (void)td;

    if(!st || !cb || st->size > (size_t)SSIZE_MAX - 10
       || (st->size > 0 && !st->buf)
       || st->bits_unused < 0 || st->bits_unused > 7
       || (st->size == 0 && st->bits_unused != 0)) ASN__ENCODE_FAILED;
    if(st->size && st->bits_unused
       && (st->buf[st->size - 1] & ((1u << st->bits_unused) - 1u))) ASN__ENCODE_FAILED;

    /* The encoded byte string has length = 1 + st->size */
    /* First byte = unused bits count (0-7), rest = bit data */
    unused_byte = (uint8_t)st->bits_unused;

    /* Emit the byte string header */
    ret = cbor_encode_head(CBOR_MAJOR_BYTES, (uint64_t)(st->size + 1), cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /* Emit unused bits byte */
    if(cb(&unused_byte, 1, app_key) < 0) ASN__ENCODE_FAILED;
    er.encoded += 1;

    /* Emit bit data */
    if(st->size > 0) {
        if(cb(st->buf, st->size, app_key) < 0) ASN__ENCODE_FAILED;
        er.encoded += st->size;
    }

    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode a definite CBOR byte string into BIT STRING storage.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: opt_codec_ctx limits nesting; td identifies type; sptr owns output;
 * buf_ptr/size bound input. Returns: status and consumed bytes.
 * Errors: malformed length/padding and allocation failures preserve an
 * existing value. Author: asn1c maintainers.
 * History: added checked lengths and canonical padding validation.
 * Example: 0x42 0x07 0x80 decodes to one set bit.
 */
asn_dec_rval_t
BIT_STRING_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                       const asn_TYPE_descriptor_t *td,
                       void **sptr, const void *buf_ptr, size_t size) {
    BIT_STRING_t *st;
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    ssize_t tag_skip;
    uint8_t major;
    uint64_t bstr_len;
    ssize_t hlen;
    size_t prefix, data_len;
    const uint8_t *data;
    uint8_t bits_unused;
    uint8_t *p = NULL;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    (void)opt_codec_ctx;
    (void)td;

    if(!sptr || !buf || size < 1) ASN__DECODE_FAILED;

    /* Skip any leading CBOR tags (RFC 8949 §3.4) */
    tag_skip = cbor_skip_tags(buf, size);
    if(tag_skip < 0 || (size_t)tag_skip >= size) ASN__DECODE_FAILED;

    hlen = cbor_decode_head(buf + tag_skip, size - (size_t)tag_skip,
                            &major, &bstr_len);
    if(hlen < 0 || major != CBOR_MAJOR_BYTES) ASN__DECODE_FAILED;
    prefix = (size_t)tag_skip + (size_t)hlen;
    if(bstr_len > SIZE_MAX || bstr_len > size - prefix) ASN__DECODE_FAILED;

    /* Minimum 1 byte for unused bits indicator */
    if(bstr_len < 1) ASN__DECODE_FAILED;

    data = buf + prefix;
    bits_unused = data[0];
    data_len = (size_t)bstr_len - 1;

    if(bits_unused > 7) ASN__DECODE_FAILED;
    if(data_len == 0 && bits_unused != 0) ASN__DECODE_FAILED;
    if(data_len && bits_unused
       && (data[data_len] & ((1u << bits_unused) - 1u))) ASN__DECODE_FAILED;

    /* Allocate bit data */
    if(data_len > 0) {
        if(data_len == SIZE_MAX) ASN__DECODE_FAILED;
        p = (uint8_t *)MALLOC(data_len + 1);
        if(!p) ASN__DECODE_FAILED;
        memcpy(p, data + 1, data_len);
        p[data_len] = '\0';
    }

    st = (BIT_STRING_t *)*sptr;
    if(!st) {
        st = (BIT_STRING_t *)CALLOC(1, sizeof(*st));
        if(!st) {
            FREEMEM(p);
            ASN__DECODE_FAILED;
        }
        *sptr = st;
    }
    FREEMEM(st->buf);
    st->buf = p;
    st->size = data_len;
    st->bits_unused = bits_unused;

    rval.consumed = prefix + (size_t)bstr_len;
    rval.code = RC_OK;
    return rval;
}
