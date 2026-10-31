/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_CHOICE.h>
#include <constr_SET.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>
#include <string.h>

/*
 * Purpose: validate CHOICE presence and variant storage before CBOR dispatch.
 * Source: CHOICE specifics and generated member layout contracts.
 * Version: 2026-10-30. Inputs: td describes the CHOICE.
 * Returns: zero for valid metadata or -1. Errors: malformed layouts fail.
 * Author: maintainers. History: added pre-allocation CBOR validation.
 * Example: an out-of-bounds variant slot rejects before decode allocation.
 */
static int
CHOICE_cbor_shape(const asn_TYPE_descriptor_t *td) {
    const asn_CHOICE_specifics_t *specs;
    size_t i, j;
    if(!td || !td->op || td->op->kind != ASN_KIND_CHOICE || !td->op->free_struct
       || !td->specifics || !td->elements || !td->elements_count) return -1;
    specs = td->specifics;
    if(!specs->struct_size || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset
       || (specs->pres_size != sizeof(char) && specs->pres_size != sizeof(short)
           && specs->pres_size != sizeof(int))
       || specs->pres_offset > specs->struct_size
       || specs->pres_size > specs->struct_size - specs->pres_offset) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t width;
        if(!member->name || !member->type || !member->type->op
           || !member->type->op->free_struct
           || (member->flags & (ATF_EXTENSION_GROUP | ATF_OPEN_TYPE))) return -1;
        width = sizeof(void *);
        if(!(member->flags & ATF_POINTER)
           && SET_inline_value_size(member->type, &width)) return -1;
        if(member->memb_offset > specs->struct_size
           || width > specs->struct_size - member->memb_offset) return -1;
        for(j = 0; j < i; j++) {
            if(!strcmp(member->name, td->elements[j].name)) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: locate a CHOICE variant by a bounded CBOR text key.
 * Source: generated variant names. Version: 2026-10-30.
 * Inputs: td describes members; key/length identify map text bytes.
 * Returns: variant index or elements_count if unknown. Errors: none.
 * Author: maintainers. History: added bounded key routing.
 * Example: key "truth" selects the truth variant.
 */
static size_t
CHOICE_cbor_member_index(const asn_TYPE_descriptor_t *td,
                         const uint8_t *key, size_t length) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const char *name = td->elements[i].name;
        if(strlen(name) == length && !memcmp(name, key, length)) return i;
    }
    return td->elements_count;
}

/*
 * Purpose: encode one CHOICE arm as a single-entry CBOR text-key map.
 * Source: repository CBOR CHOICE mapping. Version: 2026-10-30.
 * Inputs: td/sptr identify a value; cb/app_key receive encoded bytes.
 * Returns: byte count or failure. Errors: invalid descriptor, presence, missing
 * arm and child failures. Author: maintainers. History: added preflight.
 * Example: truth TRUE becomes a map containing key "truth".
 */
asn_enc_rval_t
CHOICE_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_CHOICE_specifics_t *specs;
    asn_enc_rval_t er = {0, 0, 0};
    unsigned present;
    const asn_TYPE_member_t *elm;
    const void *memb_ptr;
    ssize_t ret;

    if(CHOICE_cbor_shape(td) || !sptr || !cb) ASN__ENCODE_FAILED;
    specs = td->specifics;

    present = _fetch_present_idx(sptr, specs->pres_offset, specs->pres_size);
    if(present == 0 || present > td->elements_count) ASN__ENCODE_FAILED;

    elm = &td->elements[present - 1];
    if(!elm->type->op->cbor_encoder) ASN__ENCODE_FAILED;

    if(elm->flags & ATF_POINTER) {
        memb_ptr =
            *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const char *)sptr + elm->memb_offset;
    }

    /* CBOR map with one entry: key=name, value=encoded value */
    ret = cbor_encode_head(CBOR_MAJOR_MAP, 1, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    ret = cbor_encode_text(elm->name, strlen(elm->name), cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    {
        asn_enc_rval_t tmper =
            elm->type->op->cbor_encoder(elm->type, memb_ptr, cb, app_key);
        if(tmper.encoded < 0) return tmper;
        er.encoded += tmper.encoded;
    }

    ASN__ENCODED_OK(er);
}

/* One complete CBOR map value and its selected generated CHOICE arm. */
typedef struct CHOICE_cbor_item_s {
    size_t member_index;       /* Zero-based generated arm index. */
    const uint8_t *value;      /* Borrowed encoded child value. */
    size_t value_size;         /* Exact encoded child item length. */
    size_t consumed;           /* Bytes used by the outer one-entry map. */
} CHOICE_cbor_item_t;

/*
 * Purpose: parse one CBOR text-key map and bound its complete child item.
 * Source: CBOR definite map and skip contracts. Version: 2026-10-30.
 * Inputs: codec/td identify mapping; buf/size bound bytes; item receives result.
 * Returns: zero or -1. Errors: invalid tags, keys, counts, UTF-8, or child framing.
 * Author: maintainers. History: added complete-item parsing before allocation.
 * Example: a map with two pairs rejects before any CHOICE storage is allocated.
 */
static int
CHOICE_cbor_parse(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                  const uint8_t *buf, size_t size, CHOICE_cbor_item_t *item) {
    uint8_t major;
    uint64_t count, key_length;
    size_t offset = 0;
    ssize_t used;
    used = cbor_skip_tags(buf, size);
    if(used < 0 || (size_t)used > size) return -1;
    offset = (size_t)used;
    used = cbor_decode_head(buf + offset, size - offset, &major, &count);
    if(used < 0 || (size_t)used > size - offset || major != CBOR_MAJOR_MAP || count != 1)
        return -1;
    offset += (size_t)used;
    used = cbor_decode_head(buf + offset, size - offset, &major, &key_length);
    if(used < 0 || (size_t)used > size - offset || major != CBOR_MAJOR_TEXT) return -1;
    offset += (size_t)used;
    if(key_length > size - offset || !cbor_utf8_valid(buf + offset, (size_t)key_length)) return -1;
    item->member_index = CHOICE_cbor_member_index(td, buf + offset, (size_t)key_length);
    if(item->member_index == td->elements_count) return -1;
    offset += (size_t)key_length;
    used = cbor_skip_item_with_ctx(codec, buf + offset, size - offset);
    if(used <= 0 || (size_t)used > size - offset || (size_t)used > SSIZE_MAX - offset) return -1;
    item->value = buf + offset;
    item->value_size = (size_t)used;
    item->consumed = offset + (size_t)used;
    return 0;
}

/*
 * Purpose: decode one CBOR CHOICE arm transactionally.
 * Source: CHOICE ownership and CBOR exact-item contracts. Version: 2026-10-30.
 * Inputs: codec limits recursion; td describes arms; sptr receives the value;
 * buf_ptr/size bound input. Returns: RC_OK with bytes used or RC_FAIL.
 * Errors: malformed input leaves preallocated storage untouched.
 * Author: maintainers. History: added selected-arm staging and cleanup.
 * Example: a truncated nested record does not overwrite an existing arm.
 */
asn_dec_rval_t
CHOICE_decode_cbor(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                   void **sptr, const void *buf_ptr, size_t size) {
    const asn_CHOICE_specifics_t *specs;
    const asn_TYPE_member_t *member;
    CHOICE_cbor_item_t item;
    asn_dec_rval_t result = {RC_FAIL, 0}, child;
    void *st, *inline_value;
    void **slot;
    if(CHOICE_cbor_shape(td) || !sptr || !buf_ptr || !size || size > SSIZE_MAX
       || ASN__STACK_OVERFLOW_CHECK(codec)) return result;
    if(CHOICE_cbor_parse(codec, td, buf_ptr, size, &item)) return result;
    member = &td->elements[item.member_index];
    if(!member->type->op->cbor_decoder) return result;
    specs = td->specifics;
    st = CALLOC(1, specs->struct_size);
    if(!st) return result;
    if(CHOICE_variant_set_presence(td, st, (unsigned)item.member_index + 1)) goto failed;
    if(member->flags & ATF_POINTER)
        slot = (void **)((char *)st + member->memb_offset);
    else {
        inline_value = (char *)st + member->memb_offset;
        slot = &inline_value;
    }
    child = member->type->op->cbor_decoder(codec, member->type, slot,
                                            item.value, item.value_size);
    if(!(member->flags & ATF_POINTER)
       && inline_value != (char *)st + member->memb_offset) {
        if(inline_value) ASN_STRUCT_FREE(*member->type, inline_value);
        goto failed;
    }
    if(child.code != RC_OK || child.consumed != item.value_size) goto failed;
    if(*sptr) {
        ASN_STRUCT_RESET(*td, *sptr);
        memcpy(*sptr, st, specs->struct_size);
        FREEMEM(st);
    } else {
        *sptr = st;
    }
    result.code = RC_OK;
    result.consumed = item.consumed;
    return result;
failed:
    ASN_STRUCT_FREE(*td, st);
    return result;
}
