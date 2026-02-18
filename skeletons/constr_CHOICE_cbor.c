/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * CHOICE CBOR codec.
 * CHOICE encodes as a CBOR map (major type 5) with a single key-value pair
 * where the key is the name of the chosen alternative (text string) and
 * the value is the encoded member value.
 */
#include <asn_internal.h>
#include <constr_CHOICE.h>
#include <cbor_support.h>

asn_enc_rval_t
CHOICE_encode_cbor(const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    const void *sptr,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_CHOICE_specifics_t *specs =
        (const asn_CHOICE_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0, 0, 0};
    unsigned present;
    ssize_t ret;

    (void)constraints;

    if(!sptr) ASN__ENCODE_FAILED;

    present = _fetch_present_idx(sptr, specs->pres_offset, specs->pres_size);

    if(present == 0 || present > td->elements_count) {
        ASN__ENCODE_FAILED;
    }

    {
        const asn_TYPE_member_t *elm = &td->elements[present - 1];
        const void *memb_ptr;
        size_t mlen = strlen(elm->name);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) ASN__ENCODE_FAILED;
        } else {
            memb_ptr = (const char *)sptr + elm->memb_offset;
        }

        /* Write CBOR map with 1 pair */
        ret = cbor_write_map_header(1, cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        /* Write the alternative name as a text string key */
        ret = cbor_write_text_header(mlen, cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        if(mlen > 0) {
            if(cb(elm->name, mlen, app_key) < 0) ASN__ENCODE_FAILED;
            er.encoded += (ssize_t)mlen;
        }

        /* Write the member value */
        if(!elm->type->op->cbor_encoder) ASN__ENCODE_FAILED;

        {
            asn_enc_rval_t tmper =
                elm->type->op->cbor_encoder(elm->type, NULL,
                                             memb_ptr, cb, app_key);
            if(tmper.encoded < 0) return tmper;
            er.encoded += tmper.encoded;
        }
    }

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
CHOICE_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    void **struct_ptr, const void *buf_ptr, size_t size) {
    const asn_CHOICE_specifics_t *specs =
        (const asn_CHOICE_specifics_t *)td->specifics;
    void *st = *struct_ptr;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t map_count;
    ssize_t hlen;
    size_t consumed = 0;

    (void)opt_codec_ctx;
    (void)constraints;

    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx)) ASN__DECODE_FAILED;

    if(!st) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(!st) ASN__DECODE_FAILED;
    }

    hlen = cbor_read_uint_header(p, size, &major, &map_count);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;
    if(major != CBOR_MAJOR_MAP) ASN__DECODE_FAILED;
    if(map_count != 1) ASN__DECODE_FAILED;  /* CHOICE must have exactly 1 pair */

    consumed += (size_t)hlen;

    {
        uint8_t key_major;
        uint64_t key_len;
        ssize_t kh_len;
        size_t remaining = size - consumed;

        kh_len = cbor_read_uint_header(p + consumed, remaining,
                                        &key_major, &key_len);
        if(kh_len == 0) ASN__DECODE_STARVED;
        if(kh_len < 0 || key_major != CBOR_MAJOR_TEXT) ASN__DECODE_FAILED;
        if(key_len > remaining - (size_t)kh_len) ASN__DECODE_STARVED;

        {
            const char *key_str = (const char *)(p + consumed + kh_len);
            size_t key_str_len = (size_t)key_len;
            size_t edx;

            consumed += (size_t)kh_len + key_str_len;
            remaining = size - consumed;

            for(edx = 0; edx < td->elements_count; edx++) {
                const asn_TYPE_member_t *elm = &td->elements[edx];
                if(strlen(elm->name) == key_str_len &&
                   memcmp(elm->name, key_str, key_str_len) == 0) {
                    void *memb_ptr;
                    void **memb_ptr2;
                    asn_dec_rval_t tmprval;

                    if(elm->flags & ATF_POINTER) {
                        memb_ptr2 = (void **)((char *)st + elm->memb_offset);
                    } else {
                        memb_ptr = (char *)st + elm->memb_offset;
                        memb_ptr2 = &memb_ptr;
                    }

                    if(!elm->type->op->cbor_decoder) ASN__DECODE_FAILED;

                    tmprval = elm->type->op->cbor_decoder(
                        opt_codec_ctx, elm->type, NULL,
                        memb_ptr2, p + consumed, remaining);

                    if(tmprval.code == RC_WMORE) ASN__DECODE_STARVED;
                    if(tmprval.code != RC_OK) ASN__DECODE_FAILED;

                    consumed += tmprval.consumed;

                    /* Set the present index */
                    _set_present_idx(st, specs->pres_offset,
                                     specs->pres_size, edx + 1);
                    break;
                }
            }

            if(edx == td->elements_count) {
                /* Unknown alternative */
                ASN__DECODE_FAILED;
            }
        }
    }

    asn_dec_rval_t rval = {RC_OK, consumed};
    return rval;
}
