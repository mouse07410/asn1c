/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * SET CBOR codec: same as SEQUENCE (CBOR map with text keys).
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>
#include <string.h>

/*
 * Purpose: Detect SET descriptors containing synthetic extension-group members.
 * Source: Compiler-emitted ATF_EXTENSION_GROUP metadata in constr_TYPE.h.
 * Version: 1.0, 2026-10-30.
 * Parameters: td is the SET type descriptor to inspect.
 * Returns: Nonzero for invalid descriptors or descriptors with a group member.
 * Exceptions: None; this C helper reports rejection through its return value.
 * Responsible party: ASN.1 compiler runtime maintainers.
 * History: Added to prevent unsupported CBOR group handling from partially
 *          encoding or allocating decoder state.
 * Example: if(SET_cbor_has_extension_groups(td)) ASN__ENCODE_FAILED;
 */
static int
SET_cbor_has_extension_groups(const asn_TYPE_descriptor_t *td) {
    size_t edx;

    if(!td || !td->specifics || (td->elements_count && !td->elements)) return 1;

    for(edx = 0; edx < td->elements_count; edx++) {
        if(td->elements[edx].flags & ATF_EXTENSION_GROUP) return 1;
    }

    return 0;
}

/*
 * Purpose: Encode a SET value as a CBOR map keyed by member names.
 * Source: This SET CBOR runtime skeleton.
 * Version: 1.0, 2026-10-30.
 * Parameters: td is the SET descriptor; sptr is the value; cb consumes output;
 *             app_key is passed to cb.
 * Returns: Encoded byte count on success, or an ASN.1 encode failure result.
 * Exceptions: None; output and child encoder failures use ASN__ENCODE_FAILED.
 * Responsible party: ASN.1 compiler runtime maintainers.
 * History: Rejects unsupported extension-group descriptors before output.
 * Example: SET_encode_cbor(td, value, consume_bytes, key);
 */
asn_enc_rval_t
SET_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    size_t edx;
    size_t count = 0;
    ssize_t ret;

    if(SET_cbor_has_extension_groups(td) || !sptr) ASN__ENCODE_FAILED;

    /* Count present members */
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        if(elm->flags & ATF_POINTER) {
            const void *memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->optional || elm->default_value_set) continue;
                ASN__ENCODE_FAILED;
            }
        }
        count++;
    }

    ret = cbor_encode_head(CBOR_MAJOR_MAP, count, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;
        asn_enc_rval_t tmper;

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->optional || elm->default_value_set) continue;
                ASN__ENCODE_FAILED;
            }
        } else {
            memb_ptr = (const char *)sptr + elm->memb_offset;
        }

        ret = cbor_encode_text(elm->name, strlen(elm->name), cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        if(!elm->type->op->cbor_encoder) ASN__ENCODE_FAILED;
        tmper = elm->type->op->cbor_encoder(elm->type, memb_ptr, cb, app_key);
        if(tmper.encoded < 0) return tmper;
        er.encoded += tmper.encoded;
    }

    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode or skip one CBOR value selected by a SET map key.
 * Source: SET member descriptors and CBOR recursive-skip contract.
 * Version/date: 1.0, 2026-10-30. Inputs: codec/td/st describe the value;
 * key/key_len identify the member; buf/size bound the encoded value.
 * Returns: consumed bytes or -1. Exceptions: none; malformed input fails.
 * Author: asn1c maintainers. History: extracted to bound decoder complexity.
 * Example: an unknown key skips its complete CBOR value.
 */
static ssize_t
SET_cbor_decode_member(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td, void *st,
                       const char *key, size_t key_len, const uint8_t *buf, size_t size) {
    size_t edx;
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        void *member;
        void **slot;
        asn_dec_rval_t result;
        if(strlen(elm->name) != key_len || memcmp(elm->name, key, key_len)) continue;
        if(elm->flags & ATF_POINTER) slot = (void **)((char *)st + elm->memb_offset);
        else { member = (char *)st + elm->memb_offset; slot = &member; }
        if(!elm->type->op->cbor_decoder) return -1;
        result = elm->type->op->cbor_decoder(codec, elm->type, slot, buf, size);
        if(result.code != RC_OK || result.consumed > size || result.consumed > SSIZE_MAX) return -1;
        return (ssize_t)result.consumed;
    }
    if(!size) return -1;
    return cbor_skip_item_with_ctx(codec, buf, size);
}

/*
 * Purpose: Decode a CBOR map into a SET value using member names as keys.
 * Source: This SET CBOR runtime skeleton.
 * Version: 1.0, 2026-10-30.
 * Parameters: opt_codec_ctx controls decoder limits; td is the SET descriptor;
 *             sptr receives the value; buf_ptr and size describe input bytes.
 * Returns: Decode status and the number of consumed bytes.
 * Exceptions: None; invalid input or unsupported descriptors return RC_FAIL.
 * Responsible party: ASN.1 compiler runtime maintainers.
 * History: Rejects unsupported extension-group descriptors before allocation.
 * Example: rval = SET_decode_cbor(ctx, td, &value, bytes, length);
 */
asn_dec_rval_t
SET_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                void **sptr, const void *buf_ptr, size_t size) {
    const asn_SET_specifics_t *specs;
    void *st;
    const uint8_t *buf = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t map_count;
    ssize_t hlen;
    size_t consumed = 0;
    uint64_t i;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    if(SET_cbor_has_extension_groups(td) || !sptr || !td->specifics) {
        ASN__DECODE_FAILED;
    }
    specs = (const asn_SET_specifics_t *)td->specifics;
    st = *sptr;

    if(!st) {
        st = *sptr = CALLOC(1, specs->struct_size);
        if(!st) ASN__DECODE_FAILED;
    }

    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx)) ASN__DECODE_FAILED;

    /* Skip any leading CBOR tags (RFC 8949 §3.4) */
    {
        ssize_t tag_skip = cbor_skip_tags(buf, size);
        if(tag_skip < 0) ASN__DECODE_FAILED;
        consumed += (size_t)tag_skip;
    }

    hlen = cbor_decode_head(buf + consumed, size - consumed, &major, &map_count);
    if(hlen < 0 || major != CBOR_MAJOR_MAP) ASN__DECODE_FAILED;
    consumed += (size_t)hlen;

    for(i = 0; i < map_count; i++) {
        uint8_t key_major;
        uint64_t key_len;
        ssize_t key_hlen;
        const char *key_str;

        if(consumed >= size) ASN__DECODE_FAILED;
        key_hlen = cbor_decode_head(buf + consumed, size - consumed,
                                    &key_major, &key_len);
        if(key_hlen < 0 || key_major != CBOR_MAJOR_TEXT) ASN__DECODE_FAILED;
        consumed += (size_t)key_hlen;
        if(size - consumed < key_len) ASN__DECODE_FAILED;
        key_str = (const char *)(buf + consumed);
        consumed += (size_t)key_len;

        {
            ssize_t used = SET_cbor_decode_member(opt_codec_ctx, td, st, key_str, (size_t)key_len,
                                                  buf + consumed, size - consumed);
            if(used < 0 || (size_t)used > size - consumed) ASN__DECODE_FAILED;
            consumed += (size_t)used;
        }
    }

    rval.consumed = consumed;
    rval.code = RC_OK;
    return rval;
}
