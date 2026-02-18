/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * SET CBOR codec.
 * SET encodes as a CBOR map (major type 5), same as SEQUENCE.
 * The SET encoding follows the same format as SEQUENCE since CBOR maps
 * don't have a specific ordering requirement.
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <cbor_support.h>

asn_enc_rval_t
SET_encode_cbor(const asn_TYPE_descriptor_t *td,
                 const asn_cbor_constraints_t *constraints,
                 const void *sptr,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    size_t edx;
    size_t present_count = 0;
    ssize_t ret;

    (void)constraints;

    if(!sptr) ASN__ENCODE_FAILED;

    /* Count present members */
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        if(elm->flags & ATF_POINTER) {
            const void *memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr && (elm->optional || elm->default_value_set)) continue;
        }
        present_count++;
    }

    /* Write CBOR map header */
    ret = cbor_write_map_header(present_count, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /* Encode each present member */
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr_actual;
        void *tmp_def_val = NULL;

        if(elm->flags & ATF_POINTER) {
            const void *memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->default_value_set) {
                    if(elm->default_value_set(&tmp_def_val)) ASN__ENCODE_FAILED;
                    memb_ptr_actual = tmp_def_val;
                } else if(elm->optional) {
                    continue;
                } else {
                    ASN__ENCODE_FAILED;
                }
            } else {
                memb_ptr_actual = memb_ptr;
            }
        } else {
            memb_ptr_actual = (const char *)sptr + elm->memb_offset;
        }

        /* Write key as text string */
        {
            size_t mlen = strlen(elm->name);
            ret = cbor_write_text_header(mlen, cb, app_key);
            if(ret < 0) {
                if(tmp_def_val) ASN_STRUCT_FREE(*elm->type, tmp_def_val);
                ASN__ENCODE_FAILED;
            }
            er.encoded += ret;
            if(mlen > 0) {
                if(cb(elm->name, mlen, app_key) < 0) {
                    if(tmp_def_val) ASN_STRUCT_FREE(*elm->type, tmp_def_val);
                    ASN__ENCODE_FAILED;
                }
                er.encoded += (ssize_t)mlen;
            }
        }

        /* Write value */
        {
            asn_enc_rval_t tmper = {0, 0, 0};
            if(elm->type->op->cbor_encoder) {
                tmper = elm->type->op->cbor_encoder(elm->type, NULL,
                                                     memb_ptr_actual, cb,
                                                     app_key);
            } else {
                if(tmp_def_val) ASN_STRUCT_FREE(*elm->type, tmp_def_val);
                ASN__ENCODE_FAILED;
            }
            if(tmp_def_val) {
                ASN_STRUCT_FREE(*elm->type, tmp_def_val);
                tmp_def_val = NULL;
            }
            if(tmper.encoded < 0) return tmper;
            er.encoded += tmper.encoded;
        }
    }

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
SET_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td,
                 const asn_cbor_constraints_t *constraints,
                 void **struct_ptr, const void *buf_ptr, size_t size) {
    const asn_SET_specifics_t *specs =
        (const asn_SET_specifics_t *)td->specifics;
    void *st = *struct_ptr;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t map_count;
    ssize_t hlen;
    size_t consumed = 0;
    uint64_t pair_idx;

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
    if(map_count == (uint64_t)-1) ASN__DECODE_FAILED;

    consumed += (size_t)hlen;

    for(pair_idx = 0; pair_idx < map_count; pair_idx++) {
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
                    break;
                }
            }

            if(edx == td->elements_count) {
                /* Skip unknown member */
                uint8_t skip_major;
                uint64_t skip_len;
                ssize_t skip_hlen;

                skip_hlen = cbor_read_uint_header(p + consumed, remaining,
                                                   &skip_major, &skip_len);
                if(skip_hlen == 0) ASN__DECODE_STARVED;
                if(skip_hlen < 0) ASN__DECODE_FAILED;

                if(skip_major <= CBOR_MAJOR_NEGATIVE || skip_major == CBOR_MAJOR_SIMPLE) {
                    consumed += (size_t)skip_hlen;
                } else if(skip_major == CBOR_MAJOR_BYTES || skip_major == CBOR_MAJOR_TEXT) {
                    if(skip_len > remaining - (size_t)skip_hlen) ASN__DECODE_STARVED;
                    consumed += (size_t)skip_hlen + (size_t)skip_len;
                } else {
                    ASN__DECODE_FAILED;
                }
            }
        }
    }

    asn_dec_rval_t rval = {RC_OK, consumed};
    return rval;
}
