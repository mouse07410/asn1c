/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * SET CBOR codec: same as SEQUENCE (CBOR map with text keys).
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <constr_CHOICE.h>
#include <OPEN_TYPE.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>
#include <string.h>
#include <stdlib.h>

/* One flattened CBOR map entry from a direct SET member or a group leaf. */
typedef struct SET_cbor_leaf_s {
    unsigned outer; /* Index of the direct member or owning extension group. */
    unsigned child; /* Group leaf index, or ASN_SET_DIRECT_MEMBER. */
    const asn_TYPE_member_t *member; /* Descriptor used for the map key and value. */
} SET_cbor_leaf_t;

/*
 * Purpose: Build a bounded, unambiguous list of flat SET CBOR map entries.
 * Source: SET group layout and JER's transparent group-name mapping.
 * Version: 2026-10-30. Inputs: td describes the SET; output receives entries.
 * Returns: zero and allocated entries, or -1 on invalid metadata/allocation.
 * Errors: duplicate names, nested groups and group OPEN TYPE leaves fail closed.
 * Author: asn1c maintainers. History: replaced the group-wide rejection.
 * Example: group { x, y } contributes the map keys "x" and "y".
 */
static int
SET_cbor_leaves(const asn_TYPE_descriptor_t *td, SET_cbor_leaf_t **output, size_t *count) {
    SET_cbor_leaf_t *leaves;
    size_t total = 0, i, j, used = 0;
    if(!output || !count || !td || !td->op || !td->op->free_struct
       || SET_descriptor_valid(td) || SET_group_metadata_valid(td)) return -1;
    *output = 0;
    *count = 0;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *outer = &td->elements[i];
        size_t width = (outer->flags & ATF_EXTENSION_GROUP) ? outer->type->elements_count : 1;
        if((outer->flags & ATF_EXTENSION_GROUP)
           && (!(outer->flags & ATF_POINTER) || !outer->type->op->free_struct
               || ((const asn_SET_specifics_t *)td->specifics)->extensible != 3)) return -1;
        if(!width || width > 16384 - total) return -1;
        total += width;
    }
    leaves = CALLOC(total ? total : 1, sizeof(*leaves));
    if(!leaves) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *outer = &td->elements[i];
        size_t width = (outer->flags & ATF_EXTENSION_GROUP) ? outer->type->elements_count : 1;
        for(j = 0; j < width; j++) {
            const asn_TYPE_member_t *member = (outer->flags & ATF_EXTENSION_GROUP)
                ? &outer->type->elements[j] : outer;
            size_t prior;
            if(!member->name || !member->type || !member->type->op || !member->type->op->free_struct
               || (member->flags & ATF_EXTENSION_GROUP)
               || (member->default_value_set && !(member->flags & ATF_POINTER))
               || !cbor_utf8_valid((const uint8_t *)member->name, strlen(member->name))
               || ((outer->flags & ATF_EXTENSION_GROUP) && (member->flags & ATF_OPEN_TYPE))) goto invalid;
            for(prior = 0; prior < used; prior++) {
                if(!strcmp(leaves[prior].member->name, member->name)) goto invalid;
            }
            leaves[used].outer = (unsigned)i;
            leaves[used].child = (outer->flags & ATF_EXTENSION_GROUP)
                ? (unsigned)j : ASN_SET_DIRECT_MEMBER;
            leaves[used++].member = member;
        }
    }
    *output = leaves;
    *count = total;
    return 0;
invalid:
    FREEMEM(leaves);
    return -1;
}

/*
 * Purpose: validate a selected CHOICE arm's layout before accessing it.
 * Source: generated CHOICE specifics and runtime type widths. Version: 2026-10-30.
 * Inputs: specs/variant describe storage and selected identifies its type.
 * Returns: zero for valid storage or -1. Errors: malformed layouts fail.
 * Author: asn1c maintainers. History: added bounds checks for open values.
 * Example: a pointer arm must fit fully inside the CHOICE wrapper.
 */
static int
SET_cbor_choice_valid(const asn_CHOICE_specifics_t *specs, const asn_TYPE_member_t *variant,
                      asn_type_selector_result_t selected) {
    size_t selected_size = 0, slot_size;
    int size_status = SET_inline_value_size(selected.type_descriptor, &selected_size);
    if(size_status && (!(variant->flags & ATF_POINTER) || size_status != -2)) return -1;
    slot_size = (variant->flags & ATF_POINTER) ? sizeof(void *) : selected_size;
    if(variant->type != selected.type_descriptor || !specs->struct_size
       || (specs->pres_size != sizeof(char) && specs->pres_size != sizeof(short)
           && specs->pres_size != sizeof(int))
       || specs->pres_offset > specs->struct_size
       || specs->pres_size > specs->struct_size - specs->pres_offset
       || variant->memb_offset > specs->struct_size
       || slot_size > specs->struct_size - variant->memb_offset) return -1;
    return 0;
}

/*
 * Purpose: validate an IOC selector and its generated CHOICE wrapper.
 * Source: OPEN_TYPE_cbor_get and generated CHOICE metadata. Version: 2026-10-30.
 * Inputs: td/st describe the parent, member its open field, encoding selects
 * encoder validation. Returns: zero for a supported selection, else -1.
 * Errors: missing selectors, inconsistent arms, or malformed layouts fail.
 * Author: asn1c maintainers. History: added for direct SET open members.
 * Example: an unknown table selector is rejected before child dispatch.
 */
static int
SET_cbor_open_valid(const asn_TYPE_descriptor_t *td, const void *st,
                    const asn_TYPE_member_t *member, int encoding) {
    asn_type_selector_result_t selected;
    const asn_TYPE_member_t *variant;
    const void *value;
    if(!member->type_selector || !member->type->specifics || !member->type->elements
       || !member->type->elements_count) return -1;
    selected = member->type_selector(td, st);
    if(!selected.presence_index || selected.presence_index > member->type->elements_count
       || !selected.type_descriptor || !selected.type_descriptor->op) return -1;
    if(encoding ? !selected.type_descriptor->op->cbor_encoder : !selected.type_descriptor->op->cbor_decoder)
        return -1;
    variant = &member->type->elements[selected.presence_index - 1];
    if(SET_cbor_choice_valid(member->type->specifics, variant, selected)) return -1;
    if(!encoding) return 0;
    value = (const char *)st + member->memb_offset;
    if(member->flags & ATF_POINTER) value = *(const void *const *)value;
    if(!value || CHOICE_variant_get_presence(member->type, value) != selected.presence_index) return -1;
    if((variant->flags & ATF_POINTER)
       && !*(const void *const *)((const char *)value + variant->memb_offset)) return -1;
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
    SET_cbor_leaf_t *leaves = 0;
    size_t edx, leaf_count = 0, count = 0;
    ssize_t ret;

    if(!sptr || !cb || SET_cbor_leaves(td, &leaves, &leaf_count)) ASN__ENCODE_FAILED;

    /* Preflight every flattened member before writing the map header. */
    for(edx = 0; edx < leaf_count; edx++) {
        asn_SET_member_view_t view;
        const SET_cbor_leaf_t *leaf = &leaves[edx];
        const asn_TYPE_member_t *outer = &td->elements[leaf->outer];
        if(SET_member_view(td, sptr, leaf->outer, leaf->child, &view)) goto failed;
        if(leaf->child != ASN_SET_DIRECT_MEMBER) {
            if(!view.owner) {
                if(!outer->optional && !outer->default_value_set) goto failed;
                continue;
            }
            if(SET_group_is_populated(outer->type, view.owner) != 1) goto failed;
        }
        if(!view.present) {
            if(!view.member->optional && !view.member->default_value_set) goto failed;
            continue;
        }
        if((view.member->flags & ATF_OPEN_TYPE)
           ? SET_cbor_open_valid(td, sptr, view.member, 1)
           : !view.member->type->op->cbor_encoder) goto failed;
        count++;
    }

    ret = cbor_encode_head(CBOR_MAJOR_MAP, count, cb, app_key);
    if(ret < 0) goto failed;
    er.encoded += ret;

    /* Emit group leaves in their descriptor positions, like the JER map. */
    for(edx = 0; edx < leaf_count; edx++) {
        asn_SET_member_view_t view;
        asn_enc_rval_t tmper;
        if(SET_member_view(td, sptr, leaves[edx].outer, leaves[edx].child, &view)) goto failed;
        if(!view.present) continue;
        ret = cbor_encode_text(view.member->name, strlen(view.member->name), cb, app_key);
        if(ret < 0) goto failed;
        er.encoded += ret;
        if(view.member->flags & ATF_OPEN_TYPE)
            tmper = OPEN_TYPE_cbor_put(td, sptr, view.member, cb, app_key);
        else
            tmper = view.member->type->op->cbor_encoder(view.member->type, view.value, cb, app_key);
        if(tmper.encoded < 0) goto failed;
        er.encoded += tmper.encoded;
    }
    FREEMEM(leaves);
    ASN__ENCODED_OK(er);
failed:
    FREEMEM(leaves);
    ASN__ENCODE_FAILED;
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
                       const SET_cbor_leaf_t *leaves, size_t leaf_count, uint8_t *seen,
                       SET_cbor_key_t *pending, const char *key, size_t key_len,
                       const uint8_t *buf, size_t size) {
    size_t edx;
    for(edx = 0; edx < leaf_count; edx++) {
        const SET_cbor_leaf_t *leaf = &leaves[edx];
        const asn_TYPE_member_t *elm = leaf->member;
        asn_SET_member_view_t view;
        void *member;
        void *owner = st;
        void **slot;
        asn_dec_rval_t result;
        if(strlen(elm->name) != key_len || memcmp(elm->name, key, key_len)) continue;
        if(seen[edx] || SET_member_view(td, st, leaf->outer, leaf->child, &view)) return -1;
        if(leaf->child != ASN_SET_DIRECT_MEMBER && !view.owner) {
            const asn_TYPE_member_t *group = &td->elements[leaf->outer];
            void **group_slot = (void **)((char *)st + group->memb_offset);
            *group_slot = CALLOC(1, view.owner_specs->struct_size);
            if(!*group_slot || SET_member_view(td, st, leaf->outer, leaf->child, &view)) return -1;
        }
        if(leaf->child != ASN_SET_DIRECT_MEMBER) {
            const asn_TYPE_member_t *group = &td->elements[leaf->outer];
            owner = *(void **)((char *)st + group->memb_offset);
        }
        if(elm->flags & ATF_OPEN_TYPE) {
            ssize_t length = cbor_skip_item_with_ctx(codec, buf, size);
            if(length <= 0 || (size_t)length > size) return -1;
            pending[edx].data = buf;
            pending[edx].size = (size_t)length;
            seen[edx] = 1;
            return length;
        }
        if(!elm->type->op->cbor_decoder) return -1;
        if(elm->flags & ATF_POINTER) slot = (void **)((char *)owner + elm->memb_offset);
        else { member = (char *)owner + elm->memb_offset; slot = &member; }
        result = elm->type->op->cbor_decoder(codec, elm->type, slot, buf, size);
        if(result.code != RC_OK || !result.consumed || result.consumed > size
           || result.consumed > SSIZE_MAX) return -1;
        seen[edx] = 1;
        ASN_SET_MKPRESENT((char *)owner + view.owner_specs->pres_offset, view.owner_index);
        if(leaf->child != ASN_SET_DIRECT_MEMBER) {
            const asn_SET_specifics_t *specs = td->specifics;
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, leaf->outer);
        }
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
SET_cbor_validate_members(const asn_TYPE_descriptor_t *td, const void *st,
                          const SET_cbor_leaf_t *leaves, size_t leaf_count,
                          const uint8_t *seen, SET_cbor_key_t *keys, size_t count) {
    size_t i, offset = 0;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *outer = &td->elements[i];
        size_t start = offset, j;
        int group_seen = 0;
        while(offset < leaf_count && leaves[offset].outer == i) offset++;
        if(!(outer->flags & ATF_EXTENSION_GROUP)) {
            if(!seen[start] && !outer->optional && !outer->default_value_set) return -1;
            continue;
        }
        for(j = start; j < offset; j++) if(seen[j]) group_seen = 1;
        if(!group_seen) {
            if(!outer->optional && !outer->default_value_set) return -1;
            continue;
        }
        {
            const void *group = *(const void *const *)((const char *)st + outer->memb_offset);
            if(!group || SET_group_is_populated(outer->type, group) != 1) return -1;
        }
        for(j = start; j < offset; j++) {
            const asn_TYPE_member_t *member = leaves[j].member;
            if(!seen[j] && !member->optional && !member->default_value_set) return -1;
        }
    }
    if(count > 1) qsort(keys, count, sizeof(*keys), SET_cbor_key_compare);
    for(i = 1; i < count; i++) {
        if(!SET_cbor_key_compare(&keys[i - 1], &keys[i])) return -1;
    }
    return 0;
}

/*
 * Purpose: decode saved open members after all selector fields are available.
 * Source: OPEN_TYPE_cbor_get and SET presence metadata. Version: 2026-10-30.
 * Inputs: codec/td/st describe the parent; seen records available siblings;
 * pending stores bounded value slices.
 * Returns: zero on success, -1 on invalid selector or malformed child.
 * Errors: malformed values and incomplete child consumption fail.
 * Author: asn1c maintainers. History: added selector-independent map decoding.
 * Example: a value preceding its selector decodes after the selector is read.
 */
static int
SET_cbor_decode_open(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                     void *st, const SET_cbor_leaf_t *leaves, size_t leaf_count,
                     const uint8_t *seen, const SET_cbor_key_t *pending) {
    const asn_SET_specifics_t *specs = td->specifics;
    size_t i, j;
    for(i = 0; i < leaf_count; i++) {
        asn_dec_rval_t result;
        const asn_TYPE_member_t *member = leaves[i].member;
        if(!pending[i].data) continue;
        if(leaves[i].child != ASN_SET_DIRECT_MEMBER) return -1;
        /* Generated selectors are opaque and may dereference any sibling. */
        for(j = 0; j < leaf_count; j++) {
            asn_SET_member_view_t view;
            if(j == i) continue;
            if(!seen[j] || SET_member_view(td, st, leaves[j].outer,
                                           leaves[j].child, &view) || !view.present) return -1;
        }
        if(SET_cbor_open_valid(td, st, member, 0)) return -1;
        result = OPEN_TYPE_cbor_get(codec, td, st, member, pending[i].data, pending[i].size);
        if(result.code != RC_OK || result.consumed != pending[i].size) return -1;
        ASN_SET_MKPRESENT((char *)st + specs->pres_offset, leaves[i].outer);
    }
    return 0;
}

/*
 * Purpose: restore omitted pointer-backed DEFAULT values after map decoding.
 * Source: SET OER default restoration and transparent group storage views.
 * Version: 2026-10-30. Inputs: td/st identify the SET; leaves and seen track
 * wire entries. Returns: zero or -1 on invalid storage or setter failure.
 * Errors: inline defaults are rejected because setters own pointer storage.
 * Author: asn1c maintainers. History: added CBOR group DEFAULT restoration.
 * Example: a present group omitting its DEFAULT five receives a value of five.
 */
static int
SET_cbor_defaults(const asn_TYPE_descriptor_t *td, void *st,
                  const SET_cbor_leaf_t *leaves, size_t leaf_count, const uint8_t *seen) {
    size_t i;
    for(i = 0; i < leaf_count; i++) {
        const SET_cbor_leaf_t *leaf = &leaves[i];
        asn_SET_member_view_t view;
        void *owner = st;
        void **slot;
        if(seen[i] || !leaf->member->default_value_set) continue;
        if(SET_member_view(td, st, leaf->outer, leaf->child, &view)) return -1;
        if(!view.owner) continue;
        if(!(view.member->flags & ATF_POINTER)) return -1;
        if(leaf->child != ASN_SET_DIRECT_MEMBER) {
            const asn_TYPE_member_t *group = &td->elements[leaf->outer];
            owner = *(void **)((char *)st + group->memb_offset);
        }
        slot = (void **)((char *)owner + view.member->memb_offset);
        if(!*slot && view.member->default_value_set(slot)) return -1;
        ASN_SET_MKPRESENT((char *)owner + view.owner_specs->pres_offset, view.owner_index);
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
    SET_cbor_leaf_t *leaves = 0;
    SET_cbor_key_t *keys = 0, *pending = 0;
    uint8_t *seen = 0, major;
    uint64_t map_count, i;
    size_t consumed = 0, leaf_count = 0;
    ssize_t used;
    void *st;
    asn_dec_rval_t rval = {RC_FAIL, 0};

    if(!sptr || !buf || size > SSIZE_MAX || ASN__STACK_OVERFLOW_CHECK(codec)
       || SET_cbor_leaves(td, &leaves, &leaf_count)) return rval;
    specs = td->specifics;
    /* Decode into fresh storage so failures preserve preallocated callers. */
    st = CALLOC(1, specs->struct_size);
    if(!st) goto done;
    used = cbor_skip_tags(buf, size);
    if(used < 0 || (size_t)used > size) goto done;
    consumed = (size_t)used;
    used = cbor_decode_head(buf + consumed, size - consumed, &major, &map_count);
    if(used < 0 || (size_t)used > size - consumed || major != CBOR_MAJOR_MAP) goto done;
    consumed += (size_t)used;
    /* Every pair needs at least a key header and a value, bounding allocations. */
    if(map_count > (size - consumed) / 2 || map_count > SIZE_MAX / sizeof(*keys)) goto done;
    if(map_count && !(keys = CALLOC((size_t)map_count, sizeof(*keys)))) goto done;
    if(leaf_count && !(seen = CALLOC(leaf_count, 1))) goto done;
    if(leaf_count && !(pending = CALLOC(leaf_count, sizeof(*pending)))) goto done;
    for(i = 0; i < map_count; i++) {
        uint64_t key_len;
        used = cbor_decode_head(buf + consumed, size - consumed, &major, &key_len);
        if(used < 0 || (size_t)used > size - consumed || major != CBOR_MAJOR_TEXT) goto done;
        consumed += (size_t)used;
        if(key_len > size - consumed
           || !cbor_utf8_valid(buf + consumed, (size_t)key_len)) goto done;
        keys[i].data = buf + consumed;
        keys[i].size = (size_t)key_len;
        consumed += (size_t)key_len;
        used = SET_cbor_decode_member(codec, td, st, leaves, leaf_count, seen, pending,
                                      (const char *)keys[i].data, keys[i].size,
                                      buf + consumed, size - consumed);
        if(used < 0 || (size_t)used > size - consumed) goto done;
        consumed += (size_t)used;
    }
    if(SET_cbor_defaults(td, st, leaves, leaf_count, seen)
       || SET_cbor_validate_members(td, st, leaves, leaf_count, seen, keys, (size_t)map_count)
       || SET_cbor_decode_open(codec, td, st, leaves, leaf_count, seen, pending)) goto done;
    if(*sptr) {
        ASN_STRUCT_RESET(*td, *sptr);
        memcpy(*sptr, st, specs->struct_size);
        FREEMEM(st);
    } else {
        *sptr = st;
    }
    st = 0;
    rval.code = RC_OK;
    rval.consumed = consumed;
done:
    if(st) ASN_STRUCT_FREE(*td, st);
    FREEMEM(leaves);
    FREEMEM(pending);
    FREEMEM(seen);
    FREEMEM(keys);
    return rval;
}
