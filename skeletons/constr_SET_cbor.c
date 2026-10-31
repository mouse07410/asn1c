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
#include <stdlib.h>

/*
 * Purpose: Validate basic SET layout and reject synthetic extension groups.
 * Source: Compiler-emitted ATF_EXTENSION_GROUP metadata in constr_TYPE.h.
 * Version: 1.0, 2026-10-30.
 * Parameters: td is the SET type descriptor to inspect.
 * Returns: Nonzero for invalid descriptors or descriptors with a group member.
 * Exceptions: None; this C helper reports rejection through its return value.
 * Responsible party: ASN.1 compiler runtime maintainers.
 * History: Added group rejection, then basic pre-allocation layout validation.
 * Example: if(SET_cbor_has_extension_groups(td)) ASN__ENCODE_FAILED;
 */
static int
SET_cbor_has_extension_groups(const asn_TYPE_descriptor_t *td) {
    size_t edx, presence_words, presence_bytes;
    const asn_SET_specifics_t *specs;

    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics
       || (td->elements_count && !td->elements)) return 1;
    specs = td->specifics;
    presence_words = td->elements_count / (8 * sizeof(unsigned int));
    if(td->elements_count % (8 * sizeof(unsigned int))) presence_words++;
    if(presence_words > SIZE_MAX / sizeof(unsigned int)) return 1;
    presence_bytes = presence_words * sizeof(unsigned int);
    if(!specs->struct_size || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset
       || specs->pres_offset > specs->struct_size
       || presence_bytes > specs->struct_size - specs->pres_offset
       || (td->elements_count && !specs->_mandatory_elements)) return 1;

    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *member = &td->elements[edx];
        size_t minimum = (member->flags & ATF_POINTER) ? sizeof(void *) : 1;
        if((member->flags & ATF_EXTENSION_GROUP)
           || !member->name || !member->type || !member->type->op
           || member->memb_offset > specs->struct_size
           || minimum > specs->struct_size - member->memb_offset) return 1;
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

    if(SET_cbor_has_extension_groups(td) || !sptr || !cb) ASN__ENCODE_FAILED;

    /* Validate all member storage before reading any value or writing output. */
    for(edx = 0; edx < td->elements_count; edx++) {
        asn_SET_member_view_t view;
        if(SET_member_view(td, sptr, (unsigned)edx, ASN_SET_DIRECT_MEMBER, &view)
           || (view.present && ((view.member->flags & ATF_OPEN_TYPE)
                                || !view.member->type->op->cbor_encoder))) ASN__ENCODE_FAILED;
    }

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

/* A borrowed input key used to detect duplicate map entries after decoding. */
typedef struct SET_cbor_key_s {
    const uint8_t *data; /* Start of key bytes in the input. */
    size_t size; /* Number of key bytes. */
} SET_cbor_key_t;

/*
 * Purpose: compare borrowed map keys for deterministic duplicate detection.
 * Source: CBOR text key bytes. Version: 2026-10-30.
 * Inputs: left/right point to keys. Returns: qsort ordering. Errors: none.
 * Author: asn1c maintainers. History: added for duplicate key rejection.
 * Example: equal text byte strings compare equal regardless of encoding length.
 */
static int
SET_cbor_key_compare(const void *left, const void *right) {
    const SET_cbor_key_t *a = left, *b = right;
    size_t common = a->size < b->size ? a->size : b->size;
    int order = memcmp(a->data, b->data, common);
    if(order) return order;
    return (a->size > b->size) - (a->size < b->size);
}

/*
 * Purpose: decode a known SET member or skip an unknown map value.
 * Source: SET member descriptors and CBOR skip contract. Version: 2026-10-30.
 * Inputs: codec/td/st describe the value; seen tracks decoded members;
 * key/key_len and buf/size bound the key and encoded value.
 * Returns: consumed bytes or -1. Errors: malformed or duplicate members fail.
 * Author: asn1c maintainers. History: added mandatory and duplicate tracking.
 * Example: a second root key is rejected before decoding its value.
 */
static ssize_t
SET_cbor_decode_member(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td, void *st,
                       uint8_t *seen, const char *key, size_t key_len, const uint8_t *buf, size_t size) {
    size_t edx;
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        asn_SET_member_view_t view;
        void *member;
        void **slot;
        asn_dec_rval_t result;
        if(strlen(elm->name) != key_len || memcmp(elm->name, key, key_len)) continue;
        if(seen[edx] || SET_member_view(td, st, (unsigned)edx, ASN_SET_DIRECT_MEMBER, &view)) return -1;
        if((elm->flags & ATF_OPEN_TYPE) || !elm->type->op->cbor_decoder) return -1;
        if(elm->flags & ATF_POINTER) slot = (void **)((char *)st + elm->memb_offset);
        else { member = (char *)st + elm->memb_offset; slot = &member; }
        result = elm->type->op->cbor_decoder(codec, elm->type, slot, buf, size);
        if(result.code != RC_OK || result.consumed > size || result.consumed > SSIZE_MAX) return -1;
        seen[edx] = 1;
        ASN_SET_MKPRESENT((char *)st + view.owner_specs->pres_offset, edx);
        return (ssize_t)result.consumed;
    }
    if(!size) return -1;
    return cbor_skip_item_with_ctx(codec, buf, size);
}

/*
 * Purpose: validate required SET members and duplicate unknown map keys.
 * Source: SET optional metadata and CBOR map key uniqueness. Version: 2026-10-30.
 * Inputs: td/seen describe decoded fields; keys/count contain borrowed keys.
 * Returns: zero for valid input, otherwise -1. Errors: none.
 * Author: asn1c maintainers. History: added strict SET map validation.
 * Example: an empty map cannot represent a SET with a required member.
 */
static int
SET_cbor_validate_members(const asn_TYPE_descriptor_t *td, const uint8_t *seen,
                          SET_cbor_key_t *keys, size_t count) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        if(!seen[i] && !member->optional && !member->default_value_set) return -1;
    }
    if(count > 1) qsort(keys, count, sizeof(*keys), SET_cbor_key_compare);
    for(i = 1; i < count; i++) {
        if(!SET_cbor_key_compare(&keys[i - 1], &keys[i])) return -1;
    }
    return 0;
}

/*
 * Purpose: decode a CBOR map into a SET with unique keys and required members.
 * Source: SET metadata and CBOR map framing. Version: 2026-10-30.
 * Inputs: codec controls limits, td describes SET, sptr receives the value,
 * buf_ptr/size bound the input. Returns: decode status and consumed bytes.
 * Errors: invalid inputs, metadata, malformed keys or child failures return RC_FAIL.
 * Author: asn1c maintainers. History: reject duplicates and missing members.
 * Example: an empty map is accepted only when all members are optional.
 */
asn_dec_rval_t
SET_decode_cbor(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                void **sptr, const void *buf_ptr, size_t size) {
    const asn_SET_specifics_t *specs;
    const uint8_t *buf = buf_ptr;
    SET_cbor_key_t *keys = 0;
    uint8_t *seen = 0, major;
    uint64_t map_count, i;
    size_t consumed = 0, edx;
    ssize_t used;
    void *st;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    if(SET_cbor_has_extension_groups(td) || !sptr || !buf || size > SSIZE_MAX
       || ASN__STACK_OVERFLOW_CHECK(codec)) return rval;
    specs = td->specifics;
    if(!specs->struct_size) return rval;
    st = *sptr;
    if(!st) {
        st = *sptr = CALLOC(1, specs->struct_size);
        if(!st) return rval;
    }
    /* Validate each member layout before decoding any incoming map values. */
    for(edx = 0; edx < td->elements_count; edx++) {
        asn_SET_member_view_t view;
        if(SET_member_view(td, st, (unsigned)edx, ASN_SET_DIRECT_MEMBER, &view)) return rval;
    }
    used = cbor_skip_tags(buf, size);
    if(used < 0 || (size_t)used > size) return rval;
    consumed = (size_t)used;
    used = cbor_decode_head(buf + consumed, size - consumed, &major, &map_count);
    if(used < 0 || (size_t)used > size - consumed || major != CBOR_MAJOR_MAP) return rval;
    consumed += (size_t)used;
    /* Every pair needs at least a key header and a value, bounding allocations. */
    if(map_count > (size - consumed) / 2 || map_count > SIZE_MAX / sizeof(*keys)) return rval;
    if(map_count && !(keys = CALLOC((size_t)map_count, sizeof(*keys)))) return rval;
    if(td->elements_count && !(seen = CALLOC(td->elements_count, 1))) goto done;
    for(i = 0; i < map_count; i++) {
        uint64_t key_len;
        used = cbor_decode_head(buf + consumed, size - consumed, &major, &key_len);
        if(used < 0 || (size_t)used > size - consumed || major != CBOR_MAJOR_TEXT) goto done;
        consumed += (size_t)used;
        if(key_len > size - consumed) goto done;
        keys[i].data = buf + consumed;
        keys[i].size = (size_t)key_len;
        consumed += (size_t)key_len;
        used = SET_cbor_decode_member(codec, td, st, seen, (const char *)keys[i].data,
                                      keys[i].size, buf + consumed, size - consumed);
        if(used < 0 || (size_t)used > size - consumed) goto done;
        consumed += (size_t)used;
    }
    if(SET_cbor_validate_members(td, seen, keys, (size_t)map_count)) goto done;
    rval.code = RC_OK;
    rval.consumed = consumed;
done:
    FREEMEM(seen);
    FREEMEM(keys);
    return rval;
}
