/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <constr_CHOICE.h>
#include <OPEN_TYPE.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <cbor_support.h>
#include <stdlib.h>
#include <string.h>

/* A borrowed CBOR key or deferred open value; input remains caller-owned. */
typedef struct SEQUENCE_cbor_slice_s {
    const uint8_t *data; /* First encoded byte. */
    size_t size;         /* Length of the borrowed slice. */
} SEQUENCE_cbor_slice_t;

/*
 * Purpose: validate generated SEQUENCE storage before accessing members.
 * Source: generated layout metadata. Version: 2026-10-30.
 * Inputs: td describes a SEQUENCE. Returns: zero if safely addressable.
 * Errors: malformed metadata and unsupported groups return -1.
 * Author: maintainers. History: added CBOR preflight.
 * Example: a pointer slot past struct_size fails before allocation.
 */
static int
SEQUENCE_cbor_shape(const asn_TYPE_descriptor_t *td) {
    const asn_SEQUENCE_specifics_t *specs;
    size_t i, j, open_count = 0;
    if(!td || !td->op || td->op->kind != ASN_KIND_SEQUENCE || !td->op->free_struct
       || !td->specifics || (td->elements_count && !td->elements)) return -1;
    specs = td->specifics;
    if(!specs->struct_size || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t width;
        if((member->flags & ATF_EXTENSION_GROUP) || !member->name || !member->type
           || !member->type->op || !member->type->op->free_struct
           || ((member->flags & ATF_OPEN_TYPE) && !member->type_selector)) return -1;
        if(!cbor_utf8_valid((const uint8_t *)member->name, strlen(member->name))) return -1;
        width = sizeof(void *);
        if(!(member->flags & ATF_POINTER)) {
            /* The selected OPEN TYPE arm is validated by its child codec. */
            int status = (member->flags & ATF_OPEN_TYPE)
                ? SET_shallow_inline_value_size(member->type, &width)
                : SET_inline_value_size(member->type, &width);
            if(status) return -1;
        }
        if(member->memb_offset > specs->struct_size
           || width > specs->struct_size - member->memb_offset) return -1;
        if(member->flags & ATF_OPEN_TYPE) open_count++;
        for(j = 0; j < i; j++) {
            if(!strcmp(member->name, td->elements[j].name)) return -1;
        }
    }
    return open_count > 1 ? -1 : 0;
}

/*
 * Purpose: validate an IOC-selected open value before writing CBOR output.
 * Source: generated selector and CHOICE arm contracts. Version: 2026-10-30.
 * Inputs: td/sptr identify the parent; member is the open value.
 * Returns: zero for a consistent selected arm or -1. Errors: malformed
 * metadata, unknown selectors and mismatched arms fail. Author: maintainers.
 * History: added encoder preflight. Example: a selected but absent arm fails.
 */
static int
SEQUENCE_cbor_open_valid(const asn_TYPE_descriptor_t *td, const void *sptr,
                         const asn_TYPE_member_t *member) {
    asn_type_selector_result_t selected;
    const asn_TYPE_member_t *variant;
    const void *value = (const char *)sptr + member->memb_offset;
    size_t i;
    if(!member->type_selector) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *sibling = &td->elements[i];
        if(sibling == member || !(sibling->flags & ATF_POINTER)) continue;
        if(!*(const void *const *)((const char *)sptr + sibling->memb_offset)) return -1;
    }
    selected = member->type_selector(td, sptr);
    if(!selected.presence_index || !selected.type_descriptor
       || !selected.type_descriptor->op || !selected.type_descriptor->op->cbor_encoder) return -1;
    if(!member->type->elements_count) return member->type == selected.type_descriptor ? 0 : -1;
    if(!member->type->elements || !member->type->specifics
       || selected.presence_index > member->type->elements_count) return -1;
    variant = &member->type->elements[selected.presence_index - 1];
    if(variant->type != selected.type_descriptor) return -1;
    if(member->flags & ATF_POINTER) value = *(const void *const *)value;
    if(!value || CHOICE_variant_get_presence(member->type, value) != selected.presence_index)
        return -1;
    if((variant->flags & ATF_POINTER)
       && !*(const void *const *)((const char *)value + variant->memb_offset)) return -1;
    return 0;
}

/*
 * Purpose: compare borrowed CBOR map keys for duplicate detection.
 * Source: CBOR text key bytes. Version: 2026-10-30.
 * Inputs: left/right identify key slices. Returns: qsort ordering.
 * Errors: none. Author: maintainers. History: added strict map uniqueness.
 * Example: equal text keys compare equal despite different head widths.
 */
static int
SEQUENCE_cbor_key_compare(const void *left, const void *right) {
    const SEQUENCE_cbor_slice_t *a = left, *b = right;
    size_t common = a->size < b->size ? a->size : b->size;
    int order = memcmp(a->data, b->data, common);
    if(order) return order;
    return (a->size > b->size) - (a->size < b->size);
}

/*
 * Purpose: validate required fields and every map key's uniqueness.
 * Source: ASN.1 OPTIONAL metadata and CBOR map text keys.
 * Version: 2026-10-30. Inputs: td/seen describe fields; keys/count describe keys.
 * Returns: zero if valid. Errors: missing fields or duplicates return -1.
 * Author: maintainers. History: added complete map validation.
 * Example: a duplicate unknown key is rejected.
 */
static int
SEQUENCE_cbor_validate(const asn_TYPE_descriptor_t *td, const uint8_t *seen,
                       SEQUENCE_cbor_slice_t *keys, size_t count) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        if(!seen[i] && !member->optional && !member->default_value_set) return -1;
    }
    if(count > 1) qsort(keys, count, sizeof(*keys), SEQUENCE_cbor_key_compare);
    for(i = 1; i < count; i++) {
        if(!SEQUENCE_cbor_key_compare(&keys[i - 1], &keys[i])) return -1;
    }
    return 0;
}

/*
 * Purpose: restore omitted ASN.1 DEFAULT values in staged storage.
 * Source: SEQUENCE OER default setter contract. Version: 2026-10-30.
 * Inputs: td/st identify target and seen records wire presence.
 * Returns: zero or -1 if a generated default setter fails.
 * Errors: partial setters are cleaned with staged storage; inline setters
 * receive a local pointer to their bounded slot. Author: maintainers.
 * History: added CBOR DEFAULT restoration. Example: absent TRUE becomes TRUE.
 */
static int
SEQUENCE_cbor_defaults(const asn_TYPE_descriptor_t *td, void *st, const uint8_t *seen) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        void *inline_value;
        if(seen[i] || !member->default_value_set) continue;
        if(member->flags & ATF_POINTER) {
            if(member->default_value_set((void **)((char *)st + member->memb_offset))) return -1;
        } else {
            inline_value = (char *)st + member->memb_offset;
            if(member->default_value_set(&inline_value)
               || inline_value != (char *)st + member->memb_offset) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: dispatch a known field or defer an IOC-selected open field.
 * Source: child CBOR decoder and OPEN TYPE selector contracts.
 * Version: 2026-10-30. Inputs: codec/td/st describe target, index selects field,
 * pending saves open bytes, buf/size bound the encoded value.
 * Returns: consumed bytes or -1. Errors: malformed child data fails.
 * Author: maintainers. History: added selector-order-independent CBOR mapping.
 * Example: content can precede contentType in the input map.
 */
static ssize_t
SEQUENCE_cbor_decode_member(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                            void *st, size_t index, SEQUENCE_cbor_slice_t *pending,
                            const uint8_t *buf, size_t size) {
    const asn_TYPE_member_t *member = &td->elements[index];
    void *inline_value;
    void **slot;
    asn_dec_rval_t result;
    ssize_t used;
    if(!size) return -1;
    if(member->flags & ATF_OPEN_TYPE) {
        if(!member->type_selector) return -1;
        used = cbor_skip_item_with_ctx(codec, buf, size);
        if(used <= 0 || (size_t)used > size) return -1;
        pending[index].data = buf;
        pending[index].size = (size_t)used;
        return used;
    }
    if(!member->type->op->cbor_decoder) return -1;
    if(member->flags & ATF_POINTER)
        slot = (void **)((char *)st + member->memb_offset);
    else {
        inline_value = (char *)st + member->memb_offset;
        slot = &inline_value;
    }
    result = member->type->op->cbor_decoder(codec, member->type, slot, buf, size);
    if(result.code != RC_OK || !result.consumed || result.consumed > size
       || result.consumed > SSIZE_MAX) return -1;
    return (ssize_t)result.consumed;
}

/*
 * Purpose: decode deferred open fields after all ordinary selector fields.
 * Source: generated IOC selector callback contract. Version: 2026-10-30.
 * Inputs: codec/td/st identify parent; seen/pending describe decoded map.
 * Returns: zero on success or -1. Errors: absent siblings fail conservatively.
 * Author: maintainers. History: added deferred CBOR selection.
 * Example: an open value before its selector decodes after the map is read.
 */
static int
SEQUENCE_cbor_decode_open(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                          void *st, const uint8_t *seen,
                          const SEQUENCE_cbor_slice_t *pending) {
    size_t i, j;
    for(i = 0; i < td->elements_count; i++) {
        asn_dec_rval_t result;
        if(!pending[i].data) continue;
        /* Opaque generated selectors may dereference any sibling field. */
        for(j = 0; j < td->elements_count; j++) {
            const asn_TYPE_member_t *sibling = &td->elements[j];
            if(j == i) continue;
            if(!seen[j] || ((sibling->flags & ATF_POINTER)
               && !*(void **)((char *)st + sibling->memb_offset))) return -1;
        }
        result = OPEN_TYPE_cbor_get(codec, td, st, &td->elements[i],
                                    pending[i].data, pending[i].size);
        if(result.code != RC_OK || result.consumed != pending[i].size) return -1;
    }
    return 0;
}

/*
 * Purpose: encode a SEQUENCE as a definite CBOR map keyed by member names.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: td/sptr identify the value; cb/app_key receive encoded bytes.
 * Returns: encoded byte count or failure. Errors: malformed metadata, missing
 * mandatory members and child codec failures. Author: maintainers.
 * History: added descriptor preflight. Example: absent OPTIONAL fields are omitted.
 */
asn_enc_rval_t
SEQUENCE_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    size_t edx;
    size_t count = 0;
    ssize_t ret;

    if(SEQUENCE_cbor_shape(td) || !sptr || !cb) ASN__ENCODE_FAILED;

    /*
     * First pass: count present members to emit definite-length map header.
     */
    for(edx = 0; edx < td->elements_count; edx++) {
        const asn_TYPE_member_t *elm = &td->elements[edx];
        if(elm->flags & ATF_POINTER) {
            const void *memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->optional || elm->default_value_set) continue;
                ASN__ENCODE_FAILED;  /* Mandatory member missing */
            }
        }
        if((elm->flags & ATF_OPEN_TYPE) ? SEQUENCE_cbor_open_valid(td, sptr, elm)
           : !elm->type->op->cbor_encoder) ASN__ENCODE_FAILED;
        count++;
    }

    /* Emit CBOR map header */
    ret = cbor_encode_head(CBOR_MAJOR_MAP, count, cb, app_key);
    if(ret < 0) ASN__ENCODE_FAILED;
    er.encoded += ret;

    /*
     * Second pass: encode each present member.
     * Must mirror the counting loop exactly.
     */
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

        /* Encode key: text string of member name */
        ret = cbor_encode_text(elm->name, strlen(elm->name), cb, app_key);
        if(ret < 0) ASN__ENCODE_FAILED;
        er.encoded += ret;

        /* Encode value */
        if(elm->flags & ATF_OPEN_TYPE) {
            tmper = OPEN_TYPE_cbor_put(td, sptr, elm, cb, app_key);
        } else {
            if(!elm->type->op->cbor_encoder) ASN__ENCODE_FAILED;
            tmper = elm->type->op->cbor_encoder(elm->type, memb_ptr, cb, app_key);
        }
        if(tmper.encoded < 0) return tmper;
        er.encoded += tmper.encoded;
    }

    ASN__ENCODED_OK(er);
}

/*
 * Purpose: find a CBOR text key in generated SEQUENCE member names.
 * Source: repository CBOR map mapping. Version: 2026-10-30.
 * Inputs: td describes members; key/length bound the name.
 * Returns: member index or elements_count when unknown. Errors: none.
 * Author: maintainers. History: added bounded dispatch.
 * Example: the key contentType finds its selector member.
 */
static size_t
SEQUENCE_cbor_member_index(const asn_TYPE_descriptor_t *td,
                           const uint8_t *key, size_t length) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const char *name = td->elements[i].name;
        if(strlen(name) == length && !memcmp(name, key, length)) return i;
    }
    return td->elements_count;
}

/*
 * Purpose: parse one CBOR text key and one value from a SEQUENCE map.
 * Source: definite CBOR map framing and child codec contracts.
 * Version: 2026-10-30. Inputs: codec/td/st identify target, keys/pending/seen
 * track fields, buf/size bound input, consumed is the current offset.
 * Returns: zero on progress or -1 on malformed data. Author: maintainers.
 * Errors: bad keys, duplicates, truncated values and child failures.
 * History: added bounded per-entry parsing. Example: unknown keys are skipped.
 */
static int
SEQUENCE_cbor_decode_entry(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                           void *st, SEQUENCE_cbor_slice_t *key,
                           SEQUENCE_cbor_slice_t *pending, uint8_t *seen,
                           const uint8_t *buf, size_t size, size_t *consumed) {
    uint8_t major;
    uint64_t key_len;
    size_t index;
    ssize_t used;
    used = cbor_decode_head(buf + *consumed, size - *consumed, &major, &key_len);
    if(used < 0 || (size_t)used > size - *consumed || major != CBOR_MAJOR_TEXT) return -1;
    *consumed += (size_t)used;
    if(key_len > size - *consumed) return -1;
    if(!cbor_utf8_valid(buf + *consumed, (size_t)key_len)) return -1;
    key->data = buf + *consumed;
    key->size = (size_t)key_len;
    *consumed += (size_t)key_len;
    index = SEQUENCE_cbor_member_index(td, key->data, key->size);
    if(index == td->elements_count) {
        used = cbor_skip_item_with_ctx(codec, buf + *consumed, size - *consumed);
    } else {
        if(seen[index]) return -1;
        used = SEQUENCE_cbor_decode_member(codec, td, st, index, pending,
                                           buf + *consumed, size - *consumed);
        if(used > 0) seen[index] = 1;
    }
    if(used <= 0 || (size_t)used > size - *consumed) return -1;
    *consumed += (size_t)used;
    return 0;
}

/*
 * Purpose: decode one CBOR map into fresh SEQUENCE storage.
 * Source: repository map framing and child codec contracts.
 * Version: 2026-10-30. Inputs: codec/td/st describe target, buf/size input.
 * Returns: consumed bytes or -1. Errors: malformed maps and allocations fail.
 * Author: maintainers. History: added transactional map parsing.
 * Example: a malformed later field leaves an existing caller value untouched.
 */
static ssize_t
SEQUENCE_cbor_decode_map(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                         void *st, const uint8_t *buf, size_t size) {
    SEQUENCE_cbor_slice_t *keys = 0, *pending = 0;
    uint8_t *seen = 0, major;
    uint64_t map_count, i;
    size_t consumed = 0;
    ssize_t used, outcome = -1;
    used = cbor_skip_tags(buf, size);
    if(used < 0 || (size_t)used > size) return -1;
    consumed = (size_t)used;
    used = cbor_decode_head(buf + consumed, size - consumed, &major, &map_count);
    if(used < 0 || (size_t)used > size - consumed || major != CBOR_MAJOR_MAP) return -1;
    consumed += (size_t)used;
    if(map_count > (size - consumed) / 2 || map_count > SIZE_MAX / sizeof(*keys)) return -1;
    if(map_count && !(keys = CALLOC((size_t)map_count, sizeof(*keys)))) return -1;
    if(td->elements_count && !(seen = CALLOC(td->elements_count, 1))) goto done;
    if(td->elements_count && !(pending = CALLOC(td->elements_count, sizeof(*pending)))) goto done;
    for(i = 0; i < map_count; i++) {
        if(SEQUENCE_cbor_decode_entry(codec, td, st, &keys[i], pending, seen,
                                      buf, size, &consumed)) goto done;
    }
    if(SEQUENCE_cbor_validate(td, seen, keys, (size_t)map_count)
       || SEQUENCE_cbor_defaults(td, st, seen)
       || SEQUENCE_cbor_decode_open(codec, td, st, seen, pending)
       || consumed > SSIZE_MAX) goto done;
    outcome = (ssize_t)consumed;
done:
    FREEMEM(pending);
    FREEMEM(seen);
    FREEMEM(keys);
    return outcome;
}

/*
 * Purpose: decode CBOR transactionally into a SEQUENCE value.
 * Source: ASN.1 decoder ownership and CBOR map contracts. Version: 2026-10-30.
 * Inputs: codec limits recursion, td describes storage, sptr receives the value,
 * and buf_ptr/size bound the input. Returns: RC_OK or RC_FAIL.
 * Errors: malformed input leaves preexisting storage untouched.
 * Author: maintainers. History: added staging storage and strict map validation.
 * Example: duplicate keys do not overwrite a preallocated object.
 */
asn_dec_rval_t
SEQUENCE_decode_cbor(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                     void **sptr, const void *buf_ptr, size_t size) {
    const asn_SEQUENCE_specifics_t *specs;
    asn_dec_rval_t result = {RC_FAIL, 0};
    void *st;
    ssize_t used;
    if(SEQUENCE_cbor_shape(td) || !sptr || !buf_ptr || !size || size > SSIZE_MAX
       || ASN__STACK_OVERFLOW_CHECK(codec)) return result;
    specs = td->specifics;
    st = CALLOC(1, specs->struct_size);
    if(!st) return result;
    used = SEQUENCE_cbor_decode_map(codec, td, st, buf_ptr, size);
    if(used > 0) {
        if(*sptr) {
            ASN_STRUCT_RESET(*td, *sptr);
            memcpy(*sptr, st, specs->struct_size);
            FREEMEM(st);
        } else {
            *sptr = st;
        }
        result.code = RC_OK;
        result.consumed = (size_t)used;
    } else {
        ASN_STRUCT_FREE(*td, st);
    }
    return result;
}
