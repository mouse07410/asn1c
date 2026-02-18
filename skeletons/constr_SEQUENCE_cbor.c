/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * SEQUENCE CBOR codec.
 * SEQUENCE encodes as a CBOR map (major type 5) with field names as text
 * string keys and member values as values.
 * Optional absent members are omitted from the map.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <cbor_support.h>

/*
 * Encode a SEQUENCE as a CBOR map.
 */
asn_enc_rval_t
SEQUENCE_encode_cbor(const asn_TYPE_descriptor_t *td,
                      const asn_cbor_constraints_t *constraints,
                      const void *sptr,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    size_t edx;
    size_t present_count = 0;
    ssize_t ret;

    (void)constraints;

    if(!sptr) ASN__ENCODE_FAILED;

    /* Check recursion depth */
    if(ASN__STACK_OVERFLOW_CHECK(NULL))
        ASN__ENCODE_FAILED;

    /* Count present (non-absent optional) members */
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;

        if(elm->flags & ATF_POINTER) {
            memb_ptr = *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->default_value_set || elm->optional) continue;
                /* Missing mandatory member */
                ASN__ENCODE_FAILED;
            }
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
        const void *memb_ptr;
        const void *memb_ptr_actual;
        void *tmp_def_val = NULL;

        if(elm->flags & ATF_POINTER) {
            memb_ptr = *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->default_value_set) {
                    if(elm->default_value_set(&tmp_def_val)) ASN__ENCODE_FAILED;
                    memb_ptr_actual = tmp_def_val;
                } else if(elm->optional) {
                    continue;  /* Skip absent optional */
                } else {
                    ASN__ENCODE_FAILED;  /* Missing mandatory */
                }
            } else {
                memb_ptr_actual = memb_ptr;
            }
        } else {
            memb_ptr_actual = (const char *)sptr + elm->memb_offset;
        }

        /* Write the member name as a CBOR text string key */
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

        /* Write the member value */
        {
            asn_enc_rval_t tmper = {0, 0, 0};
            if(elm->type->op->cbor_encoder) {
                tmper = elm->type->op->cbor_encoder(
                    elm->type,
                    elm->encoding_constraints.oer_constraints
                        ? NULL : NULL,  /* No CBOR-specific constraints yet */
                    memb_ptr_actual, cb, app_key);
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

/*
 * Decode a CBOR map into a SEQUENCE.
 */
asn_dec_rval_t
SEQUENCE_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_cbor_constraints_t *constraints,
                      void **struct_ptr, const void *buf_ptr, size_t size) {
    const asn_SEQUENCE_specifics_t *specs =
        (const asn_SEQUENCE_specifics_t *)td->specifics;
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

    /* Allocate structure if needed */
    if(!st) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(!st) ASN__DECODE_FAILED;
    }

    hlen = cbor_read_uint_header(p, size, &major, &map_count);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;
    if(major != CBOR_MAJOR_MAP) ASN__DECODE_FAILED;
    if(map_count == (uint64_t)-1) ASN__DECODE_FAILED; /* No indefinite */

    consumed += (size_t)hlen;

    /* Decode each key-value pair */
    for(pair_idx = 0; pair_idx < map_count; pair_idx++) {
        uint8_t key_major;
        uint64_t key_len;
        ssize_t kh_len;
        size_t remaining = size - consumed;

        /* Read key (text string) */
        kh_len = cbor_read_uint_header(p + consumed, remaining,
                                        &key_major, &key_len);
        if(kh_len == 0) ASN__DECODE_STARVED;
        if(kh_len < 0) ASN__DECODE_FAILED;
        if(key_major != CBOR_MAJOR_TEXT) ASN__DECODE_FAILED;
        if(key_len > remaining - (size_t)kh_len) ASN__DECODE_STARVED;

        {
            const char *key_str = (const char *)(p + consumed + kh_len);
            size_t key_str_len = (size_t)key_len;
            size_t edx;

            consumed += (size_t)kh_len + key_str_len;
            remaining = size - consumed;

            /* Find the matching member by name */
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
                /* Unknown member: skip the value */
                uint8_t skip_major;
                uint64_t skip_len;
                ssize_t skip_hlen;

                skip_hlen = cbor_read_uint_header(p + consumed, remaining,
                                                   &skip_major, &skip_len);
                if(skip_hlen == 0) ASN__DECODE_STARVED;
                if(skip_hlen < 0) ASN__DECODE_FAILED;

                switch(skip_major) {
                case CBOR_MAJOR_UNSIGNED:
                case CBOR_MAJOR_NEGATIVE:
                case CBOR_MAJOR_SIMPLE:
                    consumed += (size_t)skip_hlen;
                    break;
                case CBOR_MAJOR_BYTES:
                case CBOR_MAJOR_TEXT:
                    if(skip_len > remaining - (size_t)skip_hlen) ASN__DECODE_STARVED;
                    consumed += (size_t)skip_hlen + (size_t)skip_len;
                    break;
                default:
                    /* Complex types (array, map, tag): skip is complex.
                     * For now, fail on unknown complex members. */
                    ASN__DECODE_FAILED;
                }
            }
        }
    }

    asn_dec_rval_t rval = {RC_OK, consumed};
    return rval;
}
