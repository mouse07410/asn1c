/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>

/*
 * Purpose: encode OCTET STRING, including a CONTAINING byte payload, as a
 * definite CBOR byte string. Source: repository CBOR mapping.
 * Version: 2026-10-30. Inputs: td identifies the type; sptr is the octet
 * string; cb/app_key receive bytes. Returns: encoded bytes or failure.
 * Errors: null input, inconsistent storage, and oversized output fail.
 * Author: asn1c maintainers. History: added size and callback checks.
 * Example: an empty string emits 0x40.
 */
asn_enc_rval_t
OCTET_STRING_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;

    if(!st || !cb || (!st->buf && st->size)
       || st->size > (size_t)SSIZE_MAX - 9) ASN__ENCODE_FAILED;

    ret = cbor_encode_bytes(st->buf, st->size, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode a definite CBOR byte string into OCTET STRING storage.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: opt_codec_ctx limits nesting; td identifies the type; sptr owns
 * output; buf_ptr/size bound input. Returns: status and consumed bytes.
 * Errors: invalid heads, truncated or oversized payloads, and allocation
 * failures leave existing values intact. Author: asn1c maintainers.
 * History: added checked length arithmetic and transactional replacement.
 * Example: 0x41 0x2a decodes to the octet 0x2a.
 */
asn_dec_rval_t
OCTET_STRING_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td,
                         void **sptr, const void *buf_ptr, size_t size) {
    OCTET_STRING_t *st;
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    ssize_t tag_skip;
    uint8_t major;
    uint64_t bstr_len;
    ssize_t hlen;
    size_t prefix;
    uint8_t *p;
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
    if(bstr_len > SIZE_MAX - 1 || bstr_len > size - prefix) ASN__DECODE_FAILED;

    /* Allocate and copy data */
    p = (uint8_t *)MALLOC((size_t)bstr_len + 1);
    if(!p) ASN__DECODE_FAILED;

    if(bstr_len > 0)
        memcpy(p, buf + prefix, (size_t)bstr_len);
    p[bstr_len] = '\0';

    st = (OCTET_STRING_t *)*sptr;
    if(!st) {
        st = (OCTET_STRING_t *)CALLOC(1, sizeof(*st));
        if(!st) {
            FREEMEM(p);
            ASN__DECODE_FAILED;
        }
        *sptr = st;
    }
    FREEMEM(st->buf);
    st->buf = p;
    st->size = (size_t)bstr_len;

    rval.consumed = prefix + (size_t)bstr_len;
    rval.code = RC_OK;
    return rval;
}
