/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/* SET OF and SEQUENCE OF use the same definite CBOR array mapping. */
#include <asn_internal.h>
#include <constr_SET_OF.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>
#include <limits.h>

/*
 * Purpose: check generated collection layout before reading or allocating it.
 * Source: SET OF metadata and ASN.1 list storage. Version: 2026-10-30.
 * Inputs: td describes either collection. Returns: zero or -1 for malformed metadata.
 * Errors: missing child/free callbacks and out-of-bounds context fail closed.
 * Author: asn1c maintainers. History: added CBOR collection preflight.
 * Example: a placeholder descriptor without specifics fails.
 */
static int
SET_OF_cbor_shape(const asn_TYPE_descriptor_t *td) {
    const asn_SET_OF_specifics_t *specs;
    if(!td || !td->op || !td->op->free_struct
       || (td->op->kind != ASN_KIND_SET_OF && td->op->kind != ASN_KIND_SEQUENCE_OF)
       || !td->specifics || !td->elements || td->elements_count != 1
       || !td->elements[0].type || !td->elements[0].type->op
       || !td->elements[0].type->op->free_struct) return -1;
    specs = td->specifics;
    if(specs->struct_size < sizeof(asn_anonymous_set_)
       || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset) return -1;
    return 0;
}

/*
 * Purpose: preflight all SET OF elements and encode one definite CBOR array.
 * Source: repository CBOR collection mapping. Version: 2026-10-30.
 * Inputs: td/sptr describe the value; cb/app_key receive encoded bytes.
 * Returns: encoded byte count or failure. Errors: invalid list, child, or callback.
 * Author: asn1c maintainers. History: rejected null and inconsistent entries.
 * Example: two INTEGER values emit an array with count two.
 */
asn_enc_rval_t
SET_OF_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    const asn_anonymous_set_ *list;
    const asn_TYPE_descriptor_t *child;
    ssize_t used;
    int i;
    if(SET_OF_cbor_shape(td) || !sptr || !cb) ASN__ENCODE_FAILED;
    list = _A_CSET_FROM_VOID(sptr);
    child = td->elements[0].type;
    if(!child->op->cbor_encoder || list->count < 0 || list->size < list->count
       || (list->count && !list->array)) ASN__ENCODE_FAILED;
    /* Reject holes before emitting a header that promises more values. */
    for(i = 0; i < list->count; i++) {
        if(!list->array[i]) ASN__ENCODE_FAILED;
    }
    used = cbor_encode_head(CBOR_MAJOR_ARRAY, (uint64_t)list->count, cb, app_key);
    if(used < 0) ASN__ENCODE_FAILED;
    er.encoded = used;
    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t item = child->op->cbor_encoder(child, list->array[i], cb, app_key);
        if(item.encoded <= 0 || item.encoded > SSIZE_MAX - er.encoded) ASN__ENCODE_FAILED;
        er.encoded += item.encoded;
    }
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: decode an array into staged storage and commit only on success.
 * Source: repository CBOR collection mapping. Version: 2026-10-30.
 * Inputs: codec bounds recursion; td/sptr identify target; buf_ptr/size bound input.
 * Returns: decoded prefix and consumed bytes or RC_FAIL. Errors: malformed
 * lengths, child results, allocations, and list append failures fail closed.
 * Author: asn1c maintainers. History: made collection decode transactional.
 * Example: a truncated second value preserves a preallocated caller list.
 */
asn_dec_rval_t
SET_OF_decode_cbor(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                   void **sptr, const void *buf_ptr, size_t size) {
    const asn_SET_OF_specifics_t *specs;
    const asn_TYPE_descriptor_t *child;
    const uint8_t *buf = buf_ptr;
    asn_anonymous_set_ *list;
    asn_dec_rval_t rval = {RC_FAIL, 0};
    uint8_t major;
    uint64_t count, i;
    size_t used = 0;
    ssize_t head;
    void *st = 0;
    if(SET_OF_cbor_shape(td) || !sptr || !buf || size > SSIZE_MAX
       || ASN__STACK_OVERFLOW_CHECK(codec)) return rval;
    specs = td->specifics;
    child = td->elements[0].type;
    if(!child->op->cbor_decoder) return rval;
    head = cbor_skip_tags(buf, size);
    if(head < 0 || (size_t)head > size) return rval;
    used = (size_t)head;
    head = cbor_decode_head(buf + used, size - used, &major, &count);
    if(head < 0 || (size_t)head > size - used || major != CBOR_MAJOR_ARRAY) return rval;
    used += (size_t)head;
    /* Each array element requires at least one input byte and one list slot. */
    if(count > INT_MAX || count > size - used) return rval;
    st = CALLOC(1, specs->struct_size);
    if(!st) return rval;
    list = _A_SET_FROM_VOID(st);
    for(i = 0; i < count; i++) {
        asn_dec_rval_t item;
        void *value = 0;
        item = child->op->cbor_decoder(codec, child, &value, buf + used, size - used);
        if(item.code != RC_OK || !item.consumed || item.consumed > size - used
           || !value) {
            if(value) ASN_STRUCT_FREE(*child, value);
            goto failed;
        }
        used += item.consumed;
        if(ASN_SET_ADD(list, value)) {
            ASN_STRUCT_FREE(*child, value);
            goto failed;
        }
    }
    if(*sptr) {
        ASN_STRUCT_RESET(*td, *sptr);
        memcpy(*sptr, st, specs->struct_size);
        FREEMEM(st);
    } else {
        *sptr = st;
    }
    st = 0;
    rval.code = RC_OK;
    rval.consumed = used;
failed:
    if(st) ASN_STRUCT_FREE(*td, st);
    return rval;
}
