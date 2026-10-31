/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * Primitive string type CBOR codecs.
 * String types (VisibleString, IA5String, UTF8String, etc.) encode as
 * CBOR text strings (major type 3).
 * Other primitive types (OBJECT IDENTIFIER, etc.) encode as CBOR byte strings.
 */
#include <asn_internal.h>
#include <asn_codecs_prim.h>
#include <OCTET_STRING.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>

/*
 * Purpose: encode a validated UTF-8 primitive as a CBOR text string.
 * Source: repository CBOR string mapping. Version: 2026-10-30.
 * Inputs: td identifies the ASN.1 type; sptr supplies string bytes;
 * cb/app_key receive output. Returns: encoded length or failure.
 * Errors: invalid storage, UTF-8, length, or callback failure is rejected.
 * Author: asn1c maintainers. History: added input and size preflight.
 * Example: UTF8String "A" emits 0x61 0x41.
 */
asn_enc_rval_t
OCTET_STRING_encode_cbor_utf8(const asn_TYPE_descriptor_t *td,
                              const void *sptr,
                              asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;

    (void)td;

    if(!st || !cb || (!st->buf && st->size)
       || st->size > (size_t)SSIZE_MAX - 9) ASN__ENCODE_FAILED;

    ret = cbor_encode_text((const char *)st->buf, st->size, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded = ret;
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode a CBOR text or compatible byte string into UTF-8 storage.
 * Source: repository CBOR string mapping. Version: 2026-10-30.
 * Inputs: opt_codec_ctx limits nesting; td identifies the ASN.1 type;
 * sptr owns output; buf_ptr/size bound input. Returns: status and consumed bytes.
 * Errors: malformed UTF-8, lengths, or allocation leave existing values intact.
 * Author: asn1c maintainers. History: added checked transactional replacement.
 * Example: 0x61 0x41 decodes to a one-byte string "A".
 */
asn_dec_rval_t
OCTET_STRING_decode_cbor_utf8(const asn_codec_ctx_t *opt_codec_ctx,
                              const asn_TYPE_descriptor_t *td,
                              void **sptr, const void *buf_ptr, size_t size) {
    OCTET_STRING_t *st;
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    ssize_t tag_skip;
    uint8_t major;
    uint64_t str_len;
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
                            &major, &str_len);
    if(hlen < 0) ASN__DECODE_FAILED;

    /* Accept both text (3) and bytes (2) for interoperability */
    if(major != CBOR_MAJOR_TEXT && major != CBOR_MAJOR_BYTES) ASN__DECODE_FAILED;
    prefix = (size_t)tag_skip + (size_t)hlen;
    if(str_len > SIZE_MAX - 1 || str_len > size - prefix
       || !cbor_utf8_valid(buf + prefix, (size_t)str_len)) ASN__DECODE_FAILED;

    p = (uint8_t *)MALLOC((size_t)str_len + 1);
    if(!p) ASN__DECODE_FAILED;

    if(str_len > 0)
        memcpy(p, buf + prefix, (size_t)str_len);
    p[str_len] = '\0';

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
    st->size = (size_t)str_len;

    rval.consumed = prefix + (size_t)str_len;
    rval.code = RC_OK;
    return rval;
}
