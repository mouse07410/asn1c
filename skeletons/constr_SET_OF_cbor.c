/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * SET OF CBOR codec.
 * SET OF encodes as a CBOR array (major type 4), same as SEQUENCE OF.
 */
#include <asn_internal.h>
#include <constr_SET_OF.h>
#include <asn_SET_OF.h>
#include <cbor_support.h>

asn_enc_rval_t
SET_OF_encode_cbor(const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    const void *sptr,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
    const asn_TYPE_member_t *elm = td->elements;
    asn_enc_rval_t er = {0, 0, 0};
    ssize_t ret;
    int i;

    (void)constraints;

    if(!sptr) ASN__ENCODE_FAILED;

    /* Write CBOR array header */
    ret = cbor_write_array_header((size_t)list->count, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t tmper;
        const void *memb_ptr = list->array[i];

        if(!memb_ptr) {
            if(elm->optional) continue;
            ASN__ENCODE_FAILED;
        }

        if(!elm->type->op->cbor_encoder) ASN__ENCODE_FAILED;

        tmper = elm->type->op->cbor_encoder(elm->type, NULL,
                                             memb_ptr, cb, app_key);
        if(tmper.encoded < 0) return tmper;
        er.encoded += tmper.encoded;
    }

    ASN__ENCODED_OK(er);
}

asn_dec_rval_t
SET_OF_decode_cbor(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_cbor_constraints_t *constraints,
                    void **struct_ptr, const void *buf_ptr, size_t size) {
    const asn_SET_OF_specifics_t *specs =
        (const asn_SET_OF_specifics_t *)td->specifics;
    asn_anonymous_set_ *list;
    const asn_TYPE_member_t *elm = td->elements;
    const uint8_t *p = (const uint8_t *)buf_ptr;
    uint8_t major;
    uint64_t arr_count;
    ssize_t hlen;
    size_t consumed = 0;
    uint64_t i;

    (void)opt_codec_ctx;
    (void)constraints;

    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx)) ASN__DECODE_FAILED;

    if(!*struct_ptr) {
        *struct_ptr = CALLOC(1, specs->struct_size);
        if(!*struct_ptr) ASN__DECODE_FAILED;
    }
    list = _A_SET_FROM_VOID(*struct_ptr);

    hlen = cbor_read_uint_header(p, size, &major, &arr_count);
    if(hlen == 0) ASN__DECODE_STARVED;
    if(hlen < 0) ASN__DECODE_FAILED;
    if(major != CBOR_MAJOR_ARRAY) ASN__DECODE_FAILED;
    if(arr_count == (uint64_t)-1) ASN__DECODE_FAILED;

    consumed += (size_t)hlen;

    for(i = 0; i < arr_count; i++) {
        void *memb_ptr = NULL;
        asn_dec_rval_t tmprval;

        if(!elm->type->op->cbor_decoder) ASN__DECODE_FAILED;

        tmprval = elm->type->op->cbor_decoder(
            opt_codec_ctx, elm->type, NULL,
            &memb_ptr, p + consumed, size - consumed);

        if(tmprval.code == RC_WMORE) {
            if(memb_ptr) elm->type->op->free_struct(elm->type, memb_ptr,
                                                     ASFM_FREE_EVERYTHING);
            ASN__DECODE_STARVED;
        }
        if(tmprval.code != RC_OK) {
            if(memb_ptr) elm->type->op->free_struct(elm->type, memb_ptr,
                                                     ASFM_FREE_EVERYTHING);
            ASN__DECODE_FAILED;
        }

        consumed += tmprval.consumed;

        {
            void **new_array;
            new_array = (void **)REALLOC(list->array,
                                          (list->count + 1) * sizeof(void *));
            if(!new_array) {
                elm->type->op->free_struct(elm->type, memb_ptr,
                                            ASFM_FREE_EVERYTHING);
                ASN__DECODE_FAILED;
            }
            list->array = new_array;
            list->array[list->count++] = memb_ptr;
        }
    }

    asn_dec_rval_t rval = {RC_OK, consumed};
    return rval;
}
