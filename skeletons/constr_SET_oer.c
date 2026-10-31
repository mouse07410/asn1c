/*
 * Copyright (c) 2026.
 * All rights reserved. Redistribution and modifications are permitted subject
 * to the BSD license.
 */
#include <asn_internal.h>
#include <asn_bit_data.h>
#include <constr_SET.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>
#include <OPEN_TYPE.h>
#include <oer_decoder.h>
#include <oer_encoder.h>
#include <oer_support.h>
#include <stdlib.h>

#ifndef ASN_DISABLE_OER_SUPPORT

/* The SET free path uses these phases to identify owned OER maps. */
#define SET_OER_PHASE_INITIAL 1000
#define SET_OER_PHASE_COMPLETE 1002

/* Buffered complete envelopes awaiting a table selector. */
typedef struct SET_oer_pending_s {
    struct SET_oer_pending_s *next; /* Next buffered member. */
    unsigned index;                 /* Parent member index. */
    size_t size;                    /* Encoded envelope length. */
    uint8_t bytes[1];               /* Owned complete OER envelope. */
} SET_oer_pending_t;

/*
 * Purpose: Free an OER member preamble and its deferred envelopes.
 * Source: SET OER streaming state. Version: 2026-10-30.
 * Inputs: ctx owns the member phase cursor. Returns: nothing.
 * Errors: None. Author: asn1c maintainers. History: cleanup for deferred fields.
 * Example: Called when freeing a SET after an incomplete decode.
 */
void
SET_oer_free_member_context(asn_struct_ctx_t *ctx) {
    asn_bit_data_t *bits;
    SET_oer_pending_t *entry;
    if(!ctx || !ctx->ptr) return;
    bits = (asn_bit_data_t *)ctx->ptr;
    entry = (SET_oer_pending_t *)bits->refill_key;
    while(entry) {
        SET_oer_pending_t *next = entry->next;
        FREEMEM(entry);
        entry = next;
    }
    FREEMEM(bits);
    ctx->ptr = 0;
}

/*
 * Purpose: Save one complete OER envelope without selecting its type yet.
 * Source: OER open-type length determinant. Version: 2026-10-30.
 * Inputs: ctx and index identify the owner; ptr/size provide available bytes.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; consumed receives saved bytes.
 * Errors: Overflow and allocation failures fail. Author: asn1c maintainers.
 * History: Added for selectors that follow their open type in SET order.
 * Example: Partial envelopes return RC_WMORE without consuming their bytes.
 */
static int
SET_oer_save_open(asn_struct_ctx_t *ctx, unsigned index, const char *ptr,
                  size_t size, size_t *consumed) {
    asn_bit_data_t *bits = (asn_bit_data_t *)ctx->ptr;
    SET_oer_pending_t *entry;
    size_t length = 0, total;
    ssize_t header = oer_fetch_length(ptr, size, &length);
    if(header < 0 || !bits) return RC_FAIL;
    if(header == 0) return RC_WMORE;
    if((size_t)header > size || length > size - (size_t)header) return RC_WMORE;
    total = (size_t)header + length;
    if(total > SIZE_MAX - sizeof(*entry)) return RC_FAIL;
    entry = (SET_oer_pending_t *)MALLOC(sizeof(*entry) + total);
    if(!entry) return RC_FAIL;
    entry->next = (SET_oer_pending_t *)bits->refill_key;
    entry->index = index;
    entry->size = total;
    memcpy(entry->bytes, ptr, total);
    bits->refill_key = entry;
    *consumed = total;
    return RC_OK;
}

/*
 * Purpose: Decode saved open envelopes after the governing fields are present.
 * Source: OPEN_TYPE_oer_get contract. Version: 2026-10-30.
 * Inputs: codec/td/st identify the SET; ctx owns saved complete envelopes.
 * Returns: RC_OK or RC_FAIL. Errors: invalid or incompletely decoded data fail.
 * Author: asn1c maintainers. History: supports canonical SET ordering.
 * Example: A selector later in wire order is available before decoding.
 */
static int
SET_oer_resolve_pending(const asn_codec_ctx_t *codec,
                        const asn_TYPE_descriptor_t *td, void *st,
                        asn_struct_ctx_t *ctx) {
    asn_bit_data_t *bits = (asn_bit_data_t *)ctx->ptr;
    SET_oer_pending_t *entry = bits ? (SET_oer_pending_t *)bits->refill_key : 0;
    for(; entry; entry = entry->next) {
        asn_dec_rval_t result = OPEN_TYPE_oer_get(codec, td, st,
            &td->elements[entry->index], entry->bytes, entry->size);
        if(result.code != RC_OK || result.consumed != entry->size) return RC_FAIL;
    }
    return RC_OK;
}

/* A root tag and member index form one qsort key for canonical ordering. */
typedef struct SET_oer_root_tag_s {
    ber_tlv_tag_t tag;       /* Minimum root tag for this SET member. */
    unsigned member_index;   /* Index in the SET descriptor's member array. */
} SET_oer_root_tag_t;

/*
 * Purpose: compare two root-tag sort keys by ASN.1 tag class and number.
 * Source: X.696 canonical SET root ordering and BER tag representation.
 * Version/date: 2026-10-30. Inputs: left/right point to local qsort keys.
 * Returns: negative, zero, or positive when left sorts before, equal, or after.
 * Errors: none. Author: asn1c maintainers. History: added for OER SET ordering.
 * Example: a universal-class tag sorts before a context-class tag.
 */
static int
SET_oer_root_tag_compare(const void *left, const void *right) {
    const SET_oer_root_tag_t *left_key =
        (const SET_oer_root_tag_t *)left;
    const SET_oer_root_tag_t *right_key =
        (const SET_oer_root_tag_t *)right;
    int left_class = BER_TAG_CLASS(left_key->tag);
    int right_class = BER_TAG_CLASS(right_key->tag);

    if(left_class != right_class) return left_class < right_class ? -1 : 1;
    if(BER_TAG_VALUE(left_key->tag) != BER_TAG_VALUE(right_key->tag))
        return BER_TAG_VALUE(left_key->tag) < BER_TAG_VALUE(right_key->tag)
            ? -1 : 1;
    return 0;
}

/*
 * Purpose: validate base SET descriptor fields and saved-context bounds.
 * Original source: OER SET metadata checks in SET_oer_build_order.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td and specs provide generated descriptor metadata.
 * Returns: zero for usable metadata, otherwise -1.
 * Exceptions: none. History: split out to keep validation auditable.
 * Example: reject a context offset that leaves no room for asn_struct_ctx_t.
 */
static int
SET_oer_descriptor_valid(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs) {
    if(!td || !specs || !specs->struct_size) return -1;
    if(td->elements_count && !td->elements) return -1;
    if(td->elements_count && !specs->_mandatory_elements) return -1;
    if(specs->ctx_offset > specs->struct_size) return -1;
    if(sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset)
        return -1;
    return 0;
}

/*
 * Purpose: calculate allocation sizes and validate SET presence storage.
 * Original source: checked size arithmetic in SET_oer_build_order.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/specs provide counts and storage bounds; order_bytes receives size.
 * Returns: zero for valid sizes, otherwise -1.
 * Exceptions: none. History: extracted to isolate overflow and offset checks.
 * Example: an undersized presence bitmap region is rejected.
 */
static int
SET_oer_layout_valid(const asn_TYPE_descriptor_t *td,
                     const asn_SET_specifics_t *specs, size_t order_count,
                     size_t *order_bytes) {
    size_t words;
    size_t presence_bytes;

    *order_bytes = order_count * sizeof(unsigned);
    if(order_count && *order_bytes / sizeof(unsigned) != order_count)
        return -1;
    words = (size_t)td->elements_count / (8 * sizeof(unsigned int));
    if(td->elements_count % (8 * sizeof(unsigned int))) words++;
    if(words > SIZE_MAX / sizeof(unsigned int)) return -1;
    presence_bytes = words * sizeof(unsigned int);
    if(specs->pres_offset > specs->struct_size) return -1;
    if(presence_bytes > specs->struct_size - specs->pres_offset) return -1;
    return 0;
}

/*
 * Purpose: obtain the generated canonical tag map after validating its span.
 * Original source: SET_oer_build_order's tag2el_cxer setup.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/specs describe map expectations; map/count receive the map.
 * Returns: zero for a usable map, otherwise -1.
 * Exceptions: none. History: separated map shape checks from traversal.
 * Example: a nonempty SET with a null tag map is rejected.
 */
static int
SET_oer_get_map(const asn_TYPE_descriptor_t *td,
                const asn_SET_specifics_t *specs, unsigned root_count,
                const asn_TYPE_tag2member_t **map, unsigned *count) {
    *map = specs->tag2el_cxer;
    *count = specs->tag2el_cxer_count;
    if(*count && !*map) return -1;
    if(root_count && !*map) return -1;
    (void)td;
    return 0;
}

/*
 * Purpose: validate tag-map entries and collect minimum tags for SET roots.
 * Source: generated SET tag2el_cxer map and v2 root membership.
 * Version/date: 2026-10-30. Inputs: td/map/specs identify map entries and roots;
 * seen/minimum_tags receive per-member state. Returns: zero or -1 if invalid.
 * Errors: invalid indexes and duplicate non-CHOICE entries are rejected.
 * Author: asn1c maintainers. History: split from the canonical ordering pass.
 * Example: an untagged CHOICE stores its least root alternative tag.
 */
static int
SET_oer_collect_root_tags(const asn_TYPE_descriptor_t *td,
                          const asn_TYPE_tag2member_t *map,
                          unsigned map_count, unsigned root_count,
                          const asn_SET_specifics_t *specs, uint8_t *seen,
                          ber_tlv_tag_t *minimum_tags) {
    size_t i;

    for(i = 0; i < root_count; i++)
        seen[specs->extensible >= 2 ? specs->root_map[i] : i] = 1;
    for(i = 0; i < map_count; i++) {
        unsigned index = map[i].el_no;
        const asn_TYPE_member_t *member;

        if(index >= td->elements_count) return -1;
        member = &td->elements[index];
        if(seen[index] == 1) {
            seen[index] = 2;
            minimum_tags[index] = map[i].el_tag;
        } else if(seen[index] == 2 || seen[index] == 3) {
            if(!member->type || !member->type->op
            || member->type->op->kind != ASN_KIND_CHOICE) return -1;
            if(seen[index] == 2
            && (BER_TAG_CLASS(map[i].el_tag) < BER_TAG_CLASS(minimum_tags[index])
                || (BER_TAG_CLASS(map[i].el_tag)
                        == BER_TAG_CLASS(minimum_tags[index])
                    && BER_TAG_VALUE(map[i].el_tag)
                        < BER_TAG_VALUE(minimum_tags[index]))))
                minimum_tags[index] = map[i].el_tag;
        } else {
            seen[index] = 3;
        }
    }
    for(i = 0; i < root_count; i++) {
        unsigned index = specs->extensible >= 2 ? specs->root_map[i]
                                                 : (unsigned)i;
        if(seen[index] != 2)
            return -1;
    }
    return 0;
}

/*
 * Purpose: sort root members by their collected minimum ASN.1 tags.
 * Source: X.696 canonical SET ordering and the generated root partition.
 * Version/date: 2026-10-30. Inputs: root_count/specs/minimum_tags describe
 * roots; order receives their canonical member indexes. Returns: zero or -1.
 * Errors: allocation failure and duplicate canonical root tags are rejected.
 * Author: asn1c maintainers. History: uses local qsort keys without global state.
 * Example: root_map indexes are emitted in increasing class and tag number.
 */
static int
SET_oer_sort_roots(unsigned root_count, const asn_SET_specifics_t *specs,
                   const ber_tlv_tag_t *minimum_tags, unsigned *order) {
    size_t i;
    SET_oer_root_tag_t *root_tags;

    if((size_t)root_count > SIZE_MAX / sizeof(*root_tags)) return -1;
    root_tags = root_count
        ? (SET_oer_root_tag_t *)MALLOC(root_count * sizeof(*root_tags)) : 0;
    if(root_count && !root_tags) return -1;
    for(i = 0; i < root_count; i++) {
        unsigned index = specs->extensible >= 2 ? specs->root_map[i]
                                                 : (unsigned)i;
        root_tags[i].tag = minimum_tags[index];
        root_tags[i].member_index = index;
    }
    if(root_count > 1)
        qsort(root_tags, root_count, sizeof(*root_tags),
              SET_oer_root_tag_compare);
    for(i = 0; i < root_count; i++) {
        if(i && !SET_oer_root_tag_compare(&root_tags[i - 1], &root_tags[i])) {
            FREEMEM(root_tags);
            return -1;
        }
        order[i] = root_tags[i].member_index;
    }
    FREEMEM(root_tags);
    return 0;
}

/*
 * Purpose: derive canonical tag-minimum order for all root members.
 * Source: generated CXER tag map and X.696 canonical SET ordering.
 * Version/date: 2026-10-30. Inputs: td/map/specs describe the SET; order,
 * seen, and minimum_tags are output buffers. Returns: zero or -1.
 * Errors: malformed member mappings and duplicate root tags fail.
 * Author: asn1c maintainers. History: collection and sorting are separate.
 * Example: each CHOICE contributes its minimum root alternative tag.
 */
static int
SET_oer_map_order(const asn_TYPE_descriptor_t *td,
                  const asn_TYPE_tag2member_t *map, unsigned map_count,
                  unsigned root_count, const asn_SET_specifics_t *specs,
                  unsigned *order, uint8_t *seen,
                  ber_tlv_tag_t *minimum_tags) {
    if(SET_oer_collect_root_tags(td, map, map_count, root_count, specs,
                                 seen, minimum_tags)) return -1;
    return SET_oer_sort_roots(root_count, specs, minimum_tags, order);
}

/*
 * Purpose: validate member descriptors and containing-structure offsets.
 * Original source: final member pass in SET_oer_build_order.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/specs describe members and the containing structure.
 * Returns: zero when all direct member storage spans are valid, otherwise -1.
 * Exceptions: none. History: validates before any OER access to member storage;
 * Root table-selected open types use deferred selection.
 * Example: an inline field extending past the SET structure is rejected.
 */
static int
SET_oer_validate_members(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs,
                         size_t *optional_count) {
    size_t i;

    *optional_count = 0;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t offset = member->memb_offset;

        if(!member->type || !member->type->op
        || ((member->flags & ATF_OPEN_TYPE) && !member->type_selector)
        || offset >= specs->struct_size
        || ((member->flags & ATF_POINTER)
            && sizeof(void *) > specs->struct_size - offset))
            return -1;
    }
    return 0;
}

/*
 * Purpose: validate the version and bounds of v2 SET partition metadata.
 * Source: compiler-emitted ASN_SET_SPECIFICS_VERSION fields.
 * Version/date: 2026-10-30. Inputs: td/specs identify the descriptor.
 * Returns: zero when v2 metadata is complete, otherwise -1.
 * Errors: legacy sentinels, bad counts, or missing maps fail.
 * Author: asn1c maintainers. History: split from partition traversal.
 * Example: an extension map must cover every non-root member.
 */
static int
SET_oer_v2_metadata_valid(const asn_TYPE_descriptor_t *td,
                          const asn_SET_specifics_t *specs) {
    if(!SET_version_valid(specs)
    || specs->root_count > td->elements_count
    || specs->extension_count != td->elements_count - specs->root_count
    || (specs->root_count && !specs->root_map)
    || (specs->extension_count && !specs->extension_map)) return -1;
    return 0;
}

/*
 * Purpose: verify that each mapped root or addition is valid and unique.
 * Source: compiler-generated v2 root_map and extension_map arrays.
 * Version/date: 2026-10-30. Inputs: td/specs provide the partition; seen is
 * a zeroed member-count bitmap. Returns: zero for a valid partition or -1.
 * Errors: duplicates, groups, missing types, and inline additions fail.
 * Author: asn1c maintainers. History: bounded map traversal helper.
 * Example: a pointer-backed extension addition marks its member index once.
 */
static int
SET_oer_partition_members_valid(const asn_TYPE_descriptor_t *td,
                                const asn_SET_specifics_t *specs,
                                uint8_t *seen) {
    size_t total = (size_t)specs->root_count + specs->extension_count;
    size_t i;

    for(i = 0; i < total; i++) {
        int addition = i >= specs->root_count;
        unsigned index = addition
            ? specs->extension_map[i - specs->root_count] : specs->root_map[i];
        const asn_TYPE_member_t *member;

        if(index >= td->elements_count || seen[index]) return -1;
        member = &td->elements[index];
        if(!member->type || !member->type->op
        || ((member->flags & ATF_EXTENSION_GROUP) && (!addition || specs->extensible != 3))
        || (addition && !(member->flags & ATF_POINTER))) return -1;
        seen[index] = 1;
    }
    return 0;
}

/*
 * Purpose: validate v2 SET maps and derive the number of root members.
 * Source: compiler-emitted ASN_SET_SPECIFICS_VERSION partition metadata.
 * Version/date: 2026-10-30. Inputs: td/specs describe the SET; root_count is
 * an output. Returns: zero for legacy nonextensible or valid v2 metadata.
 * Errors: legacy extensible layouts, groups, duplicates, and bad indexes fail.
 * Author: asn1c maintainers. History: added for individual OER additions.
 * Example: every member belongs to exactly one root or addition map.
 */
static int
SET_oer_partition_valid(const asn_TYPE_descriptor_t *td,
                        const asn_SET_specifics_t *specs,
                        unsigned *root_count) {
    uint8_t *seen;

    if(specs->extensible == 0) {
        *root_count = td->elements_count;
        return 0;
    }
    if(SET_oer_v2_metadata_valid(td, specs)) return -1;
    seen = td->elements_count ? CALLOC(td->elements_count, 1) : 0;
    if(td->elements_count && !seen) return -1;
    if(SET_oer_partition_members_valid(td, specs, seen) || SET_group_metadata_valid(td)) {
        FREEMEM(seen);
        return -1;
    }
    FREEMEM(seen);
    *root_count = specs->root_count;
    return 0;
}

/*
 * Purpose: allocate validation buffers and construct the canonical root order.
 * Source: generated tag2el_cxer map and validated SET partition metadata.
 * Version/date: 2026-10-30. Inputs: td/specs/map/count/root_count describe the
 * SET; order_bytes bounds the order allocation. Outputs: order_out receives it.
 * Returns: zero or -1 for invalid maps or allocation failure.
 * Errors: partial allocations are released before failure is returned.
 * Author: asn1c maintainers. History: split allocation from descriptor checks.
 * Example: an extension-only SET returns a null root order successfully.
 */
static int
SET_oer_allocate_order(const asn_TYPE_descriptor_t *td,
                       const asn_SET_specifics_t *specs,
                       const asn_TYPE_tag2member_t *map, unsigned map_count,
                       unsigned root_count, size_t order_bytes,
                       unsigned **order_out) {
    unsigned *order = 0;
    uint8_t *seen = 0;
    ber_tlv_tag_t *minimum_tags = 0;
    int result = -1;

    *order_out = 0;
    if(root_count) {
        order = (unsigned *)MALLOC(order_bytes);
        if(!order) goto cleanup;
    }
    seen = td->elements_count
        ? (uint8_t *)CALLOC(td->elements_count, sizeof(*seen)) : 0;
    if(td->elements_count && !seen) goto cleanup;
    minimum_tags = root_count
        ? (ber_tlv_tag_t *)CALLOC(td->elements_count, sizeof(*minimum_tags))
        : 0;
    if(root_count && !minimum_tags) goto cleanup;
    if(SET_oer_map_order(td, map, map_count, root_count, specs, order, seen,
                         minimum_tags)) goto cleanup;
    *order_out = order;
    order = 0;
    result = 0;

cleanup:
    FREEMEM(seen);
    FREEMEM(minimum_tags);
    FREEMEM(order);
    return result;
}

/*
 * Purpose: count OPTIONAL root components in canonical tag order.
 * Source: X.696 SET preamble rules and ordered member descriptors.
 * Version/date: 2026-10-30. Inputs: td/order/root_count describe the roots.
 * Returns: count of OPTIONAL or DEFAULT root presence bits.
 * Errors: none. Author: asn1c maintainers. History: extracted from order setup.
 * Example: a SET with two OPTIONAL roots returns two.
 */
static size_t
SET_oer_optional_root_count(const asn_TYPE_descriptor_t *td,
                            const unsigned *order, unsigned root_count) {
    size_t count = 0;
    unsigned i;

    for(i = 0; i < root_count; i++)
        if(td->elements[order[i]].optional) count++;
    return count;
}

/*
 * Purpose: resolve canonical root order and validate OER SET metadata.
 * Original source: compiler-generated tag2el_cxer map and X.696 clause 18.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/specs describe the SET; order_out/optional_count receive results.
 * Returns: zero on success; -1 for unsupported or malformed descriptors/OOM.
 * Exceptions: none. History: validates one canonical entry per root member.
 * Example: an untagged CHOICE contributes its minimum possible root tag.
 */
static int
SET_oer_build_order(const asn_TYPE_descriptor_t *td,
                    const asn_SET_specifics_t *specs, unsigned **order_out,
                    size_t *optional_count) {
    const asn_TYPE_tag2member_t *map;
    unsigned map_count;
    unsigned root_count;
    unsigned *order = 0;
    size_t order_bytes;

    if(!td || !specs || !order_out || !optional_count) return -1;
    if(SET_oer_descriptor_valid(td, specs)) return -1;
    if(SET_oer_partition_valid(td, specs, &root_count)) return -1;
    if(root_count > (unsigned)SHRT_MAX / 2) return -1;
    if(SET_oer_layout_valid(td, specs, root_count, &order_bytes)) return -1;
    if(SET_oer_get_map(td, specs, root_count, &map, &map_count)) return -1;
    if(SET_oer_allocate_order(td, specs, map, map_count, root_count,
                              order_bytes, &order)) return -1;
    if(SET_oer_validate_members(td, specs, optional_count)) {
        FREEMEM(order);
        return -1;
    }
    *optional_count = SET_oer_optional_root_count(td, order, root_count);
    *order_out = order;
    return 0;
}

/*
 * Purpose: return the address of a SET member or its pointer slot.
 * Source: Generated member offsets and ATF_POINTER storage convention.
 * Version: 2026-10-30.
 * Parameters: st/member identify the value; temporary stores inline address.
 * Returns: pointer slot for indirect fields, or temporary inline address.
 * Errors: none; the caller validates descriptor offsets first.
 * Author: asn1c maintainers.
 * History: Added as the common OER member-address helper.
 * Example: a pointer-backed field returns its location in the containing SET.
 */
static void **
SET_oer_element_ptrptr(void *st, const asn_TYPE_member_t *member,
                       void **temporary) {
    if(member->flags & ATF_POINTER)
        return (void **)((char *)st + member->memb_offset);
    *temporary = (char *)st + member->memb_offset;
    return temporary;
}

/*
 * Purpose: read the address of a SET component without changing it.
 * Source: Generated member offsets and ATF_POINTER storage convention.
 * Version: 2026-10-30.
 * Parameters: st/member identify the value and member descriptor.
 * Returns: pointed-to value for indirect fields, or inline member address.
 * Errors: none; the caller validates descriptor offsets first.
 * Author: asn1c maintainers.
 * History: Added as the common OER member-address helper.
 * Example: an absent OPTIONAL pointer field returns NULL.
 */
static const void *
SET_oer_element_ptr(const void *st, const asn_TYPE_member_t *member) {
    if(member->flags & ATF_POINTER)
        return *(const void *const *)((const char *)st + member->memb_offset);
    return (const char *)st + member->memb_offset;
}

/*
 * Purpose: validate the complete storage span of each canonical SET member.
 * Original source: SET_member_view's checked pointer and inline layouts.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td and st identify the value; order lists its member indices.
 * Returns: zero when all member storage is valid, otherwise -1.
 * Exceptions: none. History: reject truncated inline fields before OER I/O.
 * Example: an inline long at the last struct byte is rejected.
 */
static int
SET_oer_members_valid(const asn_TYPE_descriptor_t *td, const void *st) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
        asn_SET_member_view_t view;
        unsigned child = (td->elements[i].flags & ATF_EXTENSION_GROUP) ? 0 : ASN_SET_DIRECT_MEMBER;
        if(SET_member_view(td, st, (unsigned)i, child, &view))
            return -1;
    }
    return 0;
}

/*
 * Purpose: validate the root-member phase and its saved OPTIONAL bit count.
 * Source: SET OER phase markers and canonical root order.
 * Version/date: 2026-10-30. Inputs: td/order/counts and ctx describe saved state.
 * Returns: nonzero when member position, pending state, and bit count agree.
 * Errors: negative positions and inconsistent map ownership are rejected.
 * Author: asn1c maintainers. History: split from complete context validation.
 * Example: a pending OPTIONAL child includes its consumed bit in context.
 */
static int
SET_oer_members_context_valid(const asn_TYPE_descriptor_t *td,
                              const unsigned *order, size_t root_count,
                              size_t optional_count, int has_preamble,
                              const asn_struct_ctx_t *ctx) {
    size_t position;
    size_t optional_seen = 0;
    size_t i;
    int pending;
    const asn_SET_specifics_t *specs =
        (const asn_SET_specifics_t *)td->specifics;

    if(ctx->step < 0 || ctx->context < 0
    || (size_t)ctx->context > optional_count
    || (has_preamble != (ctx->ptr != 0))
    || (specs->extensible < 2 && ctx->left != 0)
    || (specs->extensible >= 2 && ctx->left != 0 && ctx->left != 1))
        return 0;
    position = (unsigned short)ctx->step >> 1;
    pending = ctx->step & 1;
    if(position > root_count || (position == root_count && pending))
        return 0;
    for(i = 0; i < position; i++)
        if(td->elements[order[i]].optional) optional_seen++;
    if(pending && position < root_count
    && td->elements[order[position]].optional)
        optional_seen++;
    return optional_seen == (size_t)ctx->context;
}

/*
 * Purpose: validate the extension-map phase before any bitmap allocation.
 * Source: SET OER extension phase state and saved extension indicator.
 * Version/date: 2026-10-30. Inputs: ctx is the SET decoder context.
 * Returns: nonzero when the saved cursor and extension indicator are valid.
 * Errors: stale counters, pointers, and invalid indicators are rejected.
 * Author: asn1c maintainers. History: split phase-specific state checks.
 * Example: a partial bitmap read retains buffered open envelopes.
 */
static int
SET_oer_extension_map_context_valid(const asn_struct_ctx_t *ctx) {
    return ctx->ptr && ctx->step == 0 && ctx->context == 0
        && ctx->left >= 0 && ctx->left <= 1;
}

/*
 * Purpose: validate the owned extension bitmap cursor before resuming decode.
 * Source: asn_bit_data_t moved count and OER extension phase state.
 * Version/date: 2026-10-30. Inputs: ctx stores the owned map and bit position.
 * Returns: nonzero when phase, flag, and consumed-bit count agree.
 * Errors: missing maps and inconsistent cursor state are rejected.
 * Author: asn1c maintainers. History: split phase-specific state checks.
 * Example: ctx->context advances once for every saved bitmap position.
 */
static int
SET_oer_extensions_context_valid(const asn_struct_ctx_t *ctx) {
    const asn_bit_data_t *bits = (const asn_bit_data_t *)ctx->ptr;

    return ctx->step == 0 && ctx->left == 1 && ctx->context >= 0 && bits
        && (size_t)ctx->context == bits->moved
        && bits->nboff <= bits->nbits;
}

/*
 * Purpose: validate an untouched initial or completed SET decoder context.
 * Source: SET OER phase markers and owned-map cleanup rules.
 * Version/date: 2026-10-30. Inputs: ctx is the saved decoder state.
 * Returns: nonzero when counters, flags, and pointer ownership are empty.
 * Errors: stale state is rejected before decoding restarts.
 * Author: asn1c maintainers. History: shared by initial and completion phases.
 * Example: a completed SET has no saved bitmap pointer.
 */
static int
SET_oer_empty_context_valid(const asn_struct_ctx_t *ctx) {
    return !ctx->ptr && ctx->step == 0 && ctx->context == 0 && ctx->left == 0;
}

/*
 * Purpose: dispatch saved-context validation to the active SET OER phase.
 * Source: SET OER phase markers and the phase-specific validators.
 * Version/date: 2026-10-30. Inputs: td/order/counts describe roots; ctx is state.
 * Returns: nonzero when the active phase state is internally consistent.
 * Errors: unknown phases and malformed state return zero.
 * Author: asn1c maintainers. History: split to keep each validator bounded.
 * Example: phase 1004 validates the owned extension bitmap's moved count.
 */
static int
SET_oer_context_valid(const asn_TYPE_descriptor_t *td,
                      const unsigned *order, size_t optional_count,
                      const asn_struct_ctx_t *ctx) {
    const asn_SET_specifics_t *specs =
        (const asn_SET_specifics_t *)td->specifics;
    size_t root_count = specs->extensible >= 2
        ? specs->root_count : td->elements_count;
    int has_preamble = 1; /* The member cursor also owns deferred envelopes. */

    switch(ctx->phase) {
    case SET_OER_PHASE_INITIAL:
    case SET_OER_PHASE_COMPLETE:
        return SET_oer_empty_context_valid(ctx);
    case ASN_SET_OER_PHASE_MEMBERS:
        return SET_oer_members_context_valid(td, order, root_count,
            optional_count, has_preamble, ctx);
    case ASN_SET_OER_PHASE_EXTENSION_MAP:
        return SET_oer_extension_map_context_valid(ctx);
    case ASN_SET_OER_PHASE_EXTENSIONS:
        return SET_oer_extensions_context_valid(ctx);
    default:
        return 0;
    }
}

/*
 * Purpose: validate arguments needed to begin OER SET decoding.
 * Original source: argument guards from SET_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: codec/td/struct_ptr/input/size identify the decode request.
 * Returns: nonzero when arguments are usable.
 * Exceptions: none. History: separated guards from the streaming state machine.
 * Example: nonempty input with a null data pointer is rejected.
 */
static int
SET_oer_decode_args_valid(const asn_codec_ctx_t *codec,
                          const asn_TYPE_descriptor_t *td, void **struct_ptr,
                          const void *input, size_t size) {
    if(ASN__STACK_OVERFLOW_CHECK(codec)) return 0;
    if(!td || !td->specifics || !td->op) return 0;
    if(td->op->kind != ASN_KIND_SET || !struct_ptr) return 0;
    if(size && !input) return 0;
    return 1;
}

/*
 * Purpose: allocate a SET value and validate its resumable decode context.
 * Original source: state setup from SET_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/specs/order/count describe the SET; value/context receive state.
 * Returns: zero for valid resumable state, otherwise -1.
 * Exceptions: none. History: preserves phase 1001 ownership and validation.
 * Example: a phase 1000 preamble owns its bit reader only after allocation.
 */
static int
SET_oer_prepare_decode(const asn_TYPE_descriptor_t *td,
                       const asn_SET_specifics_t *specs, void **value,
                       const unsigned *order, size_t optional_count,
                       asn_struct_ctx_t **context) {
    void *st = *value;
    asn_struct_ctx_t *ctx;

    if(!st) {
        st = *value = CALLOC(1, specs->struct_size);
        if(!st) return -1;
    }
    if(SET_oer_members_valid(td, st)) return -1;
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
    if(ctx->phase == SET_OER_PHASE_COMPLETE) return -1;
    if(ctx->phase != 0 && ctx->phase != SET_OER_PHASE_INITIAL
    && ctx->phase != ASN_SET_OER_PHASE_MEMBERS
    && ctx->phase != ASN_SET_OER_PHASE_EXTENSION_MAP
    && ctx->phase != ASN_SET_OER_PHASE_EXTENSIONS) return -1;
    if(ctx->phase == 0) {
        if(ctx->ptr) return -1;
        ctx->phase = SET_OER_PHASE_INITIAL;
        ctx->step = 0;
        ctx->context = 0;
        ctx->left = 0;
    }
    if(!SET_oer_context_valid(td, order, optional_count, ctx)) return -1;
    *context = ctx;
    return 0;
}

/*
 * Purpose: consume and retain the OPTIONAL presence map before SET members.
 * Original source: preamble branch from SET_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: ctx/count and input cursor state describe the preamble.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; cursor and consumed are updated.
 * Exceptions: none. History: phase 1001 retains ownership for resumed calls.
 * Example: incomplete preamble input returns RC_WMORE without consuming bytes.
 */
static int
SET_oer_read_preamble(asn_struct_ctx_t *ctx, int extensible,
                      size_t optional_count,
                      const char **ptr, size_t *size, size_t *consumed) {
    size_t preamble_bits = optional_count + (extensible != 0);
    size_t preamble_bytes;

    if(ctx->phase != SET_OER_PHASE_INITIAL) return RC_OK;
    if(ctx->ptr) return RC_FAIL;
    preamble_bytes = preamble_bits / 8 + (preamble_bits % 8 != 0);
    if(preamble_bytes > *size) return RC_WMORE;
    if(preamble_bits && (preamble_bits & 7)) {
        unsigned unused = (unsigned)(8 - (preamble_bits & 7));
        uint8_t last = (uint8_t)(*ptr)[preamble_bytes - 1];
        if(last & ((1u << unused) - 1u)) return RC_FAIL;
    }
    {
        static const char empty = 0;
        asn_bit_data_t *preamble = asn_bit_data_new_contiguous(
            preamble_bits ? *ptr : &empty, preamble_bits);
        if(!preamble) return RC_FAIL;
        if(extensible) {
            int32_t has_extensions = asn_get_few_bits(preamble, 1);
            if(has_extensions < 0) {
                FREEMEM(preamble);
                return RC_FAIL;
            }
            ctx->left = has_extensions;
        }
        ctx->ptr = preamble;
        *consumed += preamble_bytes;
        if(preamble_bytes) *ptr += preamble_bytes;
        *size -= preamble_bytes;
    }
    ctx->phase = ASN_SET_OER_PHASE_MEMBERS;
    return RC_OK;
}

/*
 * Purpose: consume the presence bit and skip an absent OPTIONAL member.
 * Original source: optional member branch from SET_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: ctx/member/member_ptr identify saved decode state and target value.
 * Returns: 1 to decode, 0 when absent and skipped, or -1 for invalid state.
 * Exceptions: none. History: defaults are applied on absent optional members.
 * Example: an absent OPTIONAL field advances the saved member position.
 */
static int
SET_oer_member_should_decode(asn_struct_ctx_t *ctx,
                             const asn_TYPE_member_t *member,
                             void **member_ptr, size_t position) {
    int pending = ctx->step & 1;

    if(pending || !member->optional) return 1;
    if(!ctx->ptr) return -1;
    {
        int32_t present = asn_get_few_bits((asn_bit_data_t *)ctx->ptr, 1);
        if(present < 0) return -1;
        ctx->context++;
        if(!present) {
            if(member->default_value_set
            && member->default_value_set(member_ptr)) return -1;
            ctx->step = (short)((position + 1) << 1);
            return 0;
        }
    }
    return 1;
}

/*
 * Purpose: invoke one member decoder and advance the active input cursor.
 * Original source: child dispatch and bounds checks from SET_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: codec/td/st/member/member_ptr and cursor state describe the child.
 * Returns: decoder status; rval also receives child consumption and errors.
 * Exceptions: none. History: handles open types through their dedicated path.
 * Example: a child claiming more bytes than available is rejected.
 */
static int
SET_oer_decode_member_value(const asn_codec_ctx_t *codec,
                            const asn_TYPE_descriptor_t *td, void *st,
                            asn_TYPE_member_t *member, void **member_ptr,
                            const char **ptr, size_t *size, size_t *consumed,
                            asn_dec_rval_t *rval) {
    if(member->flags & ATF_OPEN_TYPE) {
        *rval = OPEN_TYPE_oer_get(codec, td, st, member, *ptr, *size);
    } else {
        if(!member->type->op->oer_decoder) return RC_FAIL;
        *rval = member->type->op->oer_decoder(
            codec, member->type, member->encoding_constraints.oer_constraints,
            member_ptr, *ptr, *size);
    }
    if(rval->code == RC_FAIL) return RC_FAIL;
    if(rval->consumed > *size) return RC_FAIL;
    if(rval->code != RC_OK && rval->code != RC_WMORE) return RC_FAIL;
    *ptr += rval->consumed;
    *size -= rval->consumed;
    *consumed += rval->consumed;
    return rval->code;
}

/*
 * Purpose: decode the member at the context's saved canonical position.
 * Original source: one iteration of SET_decode_oer's member loop.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: descriptor, storage, order, context, and cursor describe the member.
 * Returns: RC_OK on child completion or absent member, RC_FAIL on error, or
 *          RC_WMORE when the child needs more data.
 * Exceptions: none. History: retains pending status across split child values.
 * Example: a resumed decoder retries the pending member without its presence bit.
 */
static int
SET_oer_decode_next_member(const asn_codec_ctx_t *codec,
                           const asn_TYPE_descriptor_t *td,
                           const asn_SET_specifics_t *specs, void *st,
                           const unsigned *order, asn_struct_ctx_t *ctx,
                           const char **ptr, size_t *size, size_t *consumed,
                           asn_dec_rval_t *rval) {
    size_t position = (unsigned short)ctx->step >> 1;
    unsigned index = order[position];
    asn_TYPE_member_t *member = &td->elements[index];
    void *temporary = 0;
    void **member_ptr = SET_oer_element_ptrptr(st, member, &temporary);
    int should_decode = SET_oer_member_should_decode(
        ctx, member, member_ptr, position);
    int status;

    if(should_decode < 0) return -1;
    if(!should_decode) return RC_OK;
    ctx->step = (short)((position << 1) | 1);
    if(member->flags & ATF_OPEN_TYPE) {
        size_t saved = 0;
        status = SET_oer_save_open(ctx, index, *ptr, *size, &saved);
        if(status != RC_OK) return status;
        *ptr += saved;
        *size -= saved;
        *consumed += saved;
    } else {
        status = SET_oer_decode_member_value(codec, td, st, member, member_ptr,
                                             ptr, size, consumed, rval);
        if(status != RC_OK) return status;
    }
    ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
    ctx->step = (short)((position + 1) << 1);
    return RC_OK;
}

/*
 * Purpose: verify that all mandatory root members decoded successfully.
 * Source: generated SET mandatory-member map and v2 root_map metadata.
 * Version/date: 2026-10-30. Inputs: td/st/specs identify the decoded value.
 * Returns: nonzero when every mandatory root presence bit is set.
 * Errors: malformed indexes or missing mandatory values return zero.
 * Author: asn1c maintainers. History: extensions are optional additions.
 * Example: absent mandatory extension additions do not invalidate the roots.
 */
static int
SET_oer_roots_populated(const asn_TYPE_descriptor_t *td, const void *st,
                        const asn_SET_specifics_t *specs) {
    size_t count = specs->extensible >= 2
        ? specs->root_count : td->elements_count;
    size_t word_bits = 8 * sizeof(unsigned int);
    size_t i;

    if(specs->extensible == 0) return _SET_is_populated(td, st);
    for(i = 0; i < count; i++) {
        unsigned index = specs->root_map[i];
        unsigned int mandatory;
        if(index >= td->elements_count) return 0;
        memcpy(&mandatory,
               (const char *)specs->_mandatory_elements
                   + (index / word_bits) * sizeof(mandatory),
               sizeof(mandatory));
        mandatory = sys_ntohl(mandatory);
        if(mandatory & (1u << (word_bits - 1 - (index % word_bits)))) {
            unsigned int present;
            memcpy(&present,
                   (const char *)st + specs->pres_offset
                       + (index / word_bits) * sizeof(present),
                   sizeof(present));
            if(!(present & (1u << (word_bits - 1 - (index % word_bits)))))
                return 0;
        }
    }
    return 1;
}

/*
 * Purpose: reject malformed padding in an extension-group SEQUENCE preamble.
 * Source: X.696 16.2.3–16.2.4 and generated group optional-member metadata.
 * Version/date: 1.0, 2026-10-30. Inputs: adapter and bounded payload bytes.
 * Returns: zero for valid preamble padding, -1 for truncation or nonzero bits.
 * Errors: closed containers without a complete preamble are malformed.
 * Author: asn1c maintainers. History: validates before the SEQUENCE decoder.
 * Example: a two-bit preamble rejects any of its six unused bits being set.
 */
static int
SET_oer_group_preamble_valid(const asn_TYPE_descriptor_t *adapter, const char *ptr, size_t size) {
    const asn_SEQUENCE_specifics_t *specs = (const asn_SEQUENCE_specifics_t *)adapter->specifics;
    size_t bytes = specs->roms_count / 8 + (specs->roms_count % 8 != 0);
    unsigned unused = (8 - (specs->roms_count % 8)) % 8;
    if(bytes > size) return -1;
    if(unused && ((uint8_t)ptr[bytes - 1] & ((1u << unused) - 1u))) return -1;
    return 0;
}

/*
 * Purpose: decode one complete OER open type and require exact child use.
 * Source: X.696 open-type length framing and the child OER decoder contract.
 * Version/date: 2026-10-30. Inputs: member/slot/cursor identify one addition.
 * Returns: consumed bytes, zero when more bytes are needed, or -1 on error.
 * Errors: malformed lengths, incomplete payloads, and trailing bytes fail.
 * Author: asn1c maintainers. History: bounds strict individual additions.
 * Example: a valid integer open type consumes its entire length-delimited body.
 */
static ssize_t
SET_oer_get_open_type(const asn_codec_ctx_t *codec,
                      const asn_TYPE_descriptor_t *td, unsigned index, void **slot,
                      const char *ptr, size_t size) {
    const asn_TYPE_member_t *member = &td->elements[index];
    asn_TYPE_descriptor_t adapter;
    const asn_TYPE_descriptor_t *wire_type = member->type;
    size_t length = 0;
    ssize_t length_size = oer_fetch_length(ptr, size, &length);
    asn_dec_rval_t decoded;
    void *old_value = *slot;
    void *decoded_value = 0;

    if(length_size <= 0) return length_size;
    if(length > size - (size_t)length_size) return 0;
    if(length > (size_t)SSIZE_MAX - (size_t)length_size) return -1;
    if(!member->type->op->oer_decoder || !member->type->op->free_struct)
        return -1;
    if(member->flags & ATF_EXTENSION_GROUP) {
        if(SET_group_adapter(td, index, &adapter)
        || SET_oer_group_preamble_valid(&adapter, ptr + length_size, length)) return -1;
        wire_type = &adapter;
    }
    decoded = wire_type->op->oer_decoder(
        codec, wire_type, member->encoding_constraints.oer_constraints,
        &decoded_value, ptr + length_size, length);
    if((member->flags & ATF_EXTENSION_GROUP) && decoded_value
    && SET_group_clear_wire_context(member->type, decoded_value)) decoded.code = RC_FAIL;
    if(decoded.code != RC_OK || decoded.consumed != length
    || ((member->flags & ATF_EXTENSION_GROUP)
        && SET_group_mark_present(member->type, decoded_value))) {
        if(decoded_value && member->type->op->free_struct) {
            member->type->op->free_struct(
                member->type, decoded_value, ASFM_FREE_EVERYTHING);
        }
        return -1;
    }
    if(old_value && member->type->op->free_struct)
        member->type->op->free_struct(
            member->type, old_value, ASFM_FREE_EVERYTHING);
    *slot = decoded_value;
    return length_size + (ssize_t)length;
}

/*
 * Purpose: parse the OER extension bitmap into owned resumable bit storage.
 * Source: X.696 clauses 16.4.1 through 16.4.3.
 * Version/date: 2026-10-30. Inputs: ptr/size are the encoded bitmap bytes.
 * Outputs: map receives an owned bit cursor; consumed receives header size.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL for valid, incomplete, or bad input.
 * Errors: invalid unused counts, nonzero padding, and excessive maps fail.
 * Author: asn1c maintainers. History: added for v2 individual additions.
 * Compatibility: empty and all-zero maps are accepted like SEQUENCE OER,
 * although the canonical encoder never emits them when no addition is present.
 * Example: a partial length determinant returns RC_WMORE without advancing.
 */
static int
SET_oer_read_extension_map(const char *ptr, size_t size,
                           asn_bit_data_t **map, size_t *consumed) {
    size_t content_length = 0;
    size_t bitmap_bytes;
    size_t bit_count;
    unsigned unused_bits;
    ssize_t length_size = oer_fetch_length(ptr, size, &content_length);
    asn_bit_data_t *bits;

    *map = 0;
    *consumed = 0;
    if(length_size == 0) return RC_WMORE;
    if(length_size < 0) return RC_FAIL;
    if(content_length == 0) {
        static const uint8_t empty_byte = 0;
        *map = asn_bit_data_new_contiguous(&empty_byte, 0);
        if(!*map) return RC_FAIL;
        *consumed = (size_t)length_size;
        return RC_OK;
    }
    bitmap_bytes = content_length - 1;
    if(bitmap_bytes > SIZE_MAX / 8
    || bitmap_bytes > ((size_t)INT_MAX + 7) / 8) return RC_FAIL;
    if(content_length > size - (size_t)length_size) return RC_WMORE;
    unused_bits = (uint8_t)ptr[length_size];
    if(unused_bits > 7 || (bitmap_bytes == 0 && unused_bits != 0)
    || (bitmap_bytes && unused_bits >= bitmap_bytes * 8)) return RC_FAIL;
    bit_count = bitmap_bytes * 8 - unused_bits;
    if(bit_count > INT_MAX || bit_count > SIZE_MAX - 7) return RC_FAIL;
    if(unused_bits
    && ((uint8_t)ptr[length_size + content_length - 1]
        & ((1u << unused_bits) - 1u))) return RC_FAIL;
    bits = asn_bit_data_new_contiguous(ptr + length_size + 1, bit_count);
    if(!bits) return RC_FAIL;
    *map = bits;
    *consumed = (size_t)length_size + content_length;
    return RC_OK;
}

/*
 * Purpose: Retain the inner open envelope of an OER extension addition.
 * Source: X.696 extension and open-type length framing. Version: 2026-10-30.
 * Inputs: ctx/index own the saved field; ptr/size hold the outer envelope.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; consumed receives outer bytes.
 * Errors: Invalid nested framing and incomplete inner values fail.
 * Author: maintainers. History: Defers selection until additions complete.
 * Example: A later addition may select an earlier open-type addition.
 */
static int
SET_oer_save_open_addition(asn_struct_ctx_t *ctx, unsigned index,
                           const char *ptr, size_t size, size_t *consumed) {
    size_t length = 0, saved = 0;
    ssize_t header = oer_fetch_length(ptr, size, &length);
    int status;
    if(header < 0 || (header > 0 && (size_t)header > size)) return RC_FAIL;
    if(header == 0 || length > size - (size_t)header) return RC_WMORE;
    status = SET_oer_save_open(ctx, index, ptr + header, length, &saved);
    if(status != RC_OK || saved != length) return RC_FAIL;
    *consumed = (size_t)header + length;
    return RC_OK;
}

/*
 * Purpose: decode present known additions and skip unknown open types.
 * Source: X.696 extension-addition bitmap ordering and open-type framing.
 * Version/date: 2026-10-30. Inputs: td/st/specs/ctx and input cursor describe
 * one extension phase. Returns: RC_OK, RC_WMORE, or RC_FAIL.
 * Errors: malformed known values and unknown open types fail safely.
 * Author: asn1c maintainers. History: bitmap cursor resumes across chunks.
 * Example: trailing unknown set bits are consumed as opaque open types.
 */
static int
SET_oer_decode_extensions(const asn_codec_ctx_t *codec,
                          const asn_TYPE_descriptor_t *td, void *st,
                          const asn_SET_specifics_t *specs,
                          asn_struct_ctx_t *ctx, const char **ptr,
                          size_t *size, size_t *consumed) {
    asn_bit_data_t *bits = (asn_bit_data_t *)ctx->ptr;

    while(bits && bits->nboff < bits->nbits) {
        int32_t present = asn_get_few_bits(bits, 1);
        int status = RC_OK;
        unsigned bit_index = (unsigned)ctx->context;

        if(present < 0 || ctx->context < 0) return RC_FAIL;
        if(present && bit_index < specs->extension_count) {
            unsigned member_index = specs->extension_map[bit_index];
            const asn_TYPE_member_t *member = &td->elements[member_index];
            void **slot = (void **)((char *)st + member->memb_offset);
            size_t used = 0;
            if(member->flags & ATF_OPEN_TYPE) {
                status = SET_oer_save_open_addition(ctx, member_index,
                                                    *ptr, *size, &used);
            } else {
                ssize_t decoded = SET_oer_get_open_type(
                    codec, td, member_index, slot, *ptr, *size);
                if(decoded == 0) status = RC_WMORE;
                else if(decoded < 0) status = RC_FAIL;
                else used = (size_t)decoded;
            }
            if(status == RC_OK) {
                if(used > *size) return RC_FAIL;
                *ptr += used;
                *size -= used;
                *consumed += used;
                ASN_SET_MKPRESENT((char *)st + specs->pres_offset,
                                  member_index);
            }
        } else if(present) {
            size_t length = 0;
            ssize_t length_size = oer_fetch_length(*ptr, *size, &length);
            ssize_t skipped;
            if(length_size == 0) {
                asn_get_undo(bits, 1);
                return RC_WMORE;
            }
            if(length_size < 0) {
                asn_get_undo(bits, 1);
                return RC_FAIL;
            }
            if(length > *size - (size_t)length_size) {
                asn_get_undo(bits, 1);
                return RC_WMORE;
            }
            if(length > (size_t)SSIZE_MAX - (size_t)length_size) {
                asn_get_undo(bits, 1);
                return RC_FAIL;
            }
            skipped = length_size + (ssize_t)length;
            if(skipped == 0) status = RC_WMORE;
            else if(skipped < 0 || (size_t)skipped > *size)
                status = RC_FAIL;
            else {
                *ptr += skipped;
                *size -= (size_t)skipped;
                *consumed += (size_t)skipped;
            }
        }
        if(status != RC_OK) {
            asn_get_undo(bits, 1);
            return status;
        }
        ctx->context++;
    }
    return RC_OK;
}

/*
 * Purpose: initialize DEFAULT values for absent pointer-backed additions.
 * Source: SET v2 extension_map and X.696 extension-addition defaults.
 * Version/date: 2026-10-30. Inputs: td/st/specs identify the decoded SET.
 * Returns: zero on success, -1 if a default setter fails.
 * Errors: malformed indexes and allocation failures are reported.
 * Author: asn1c maintainers. History: added for individual OER additions.
 * Example: an omitted DEFAULT addition receives its declared value.
 */
static int
SET_oer_extension_defaults(const asn_TYPE_descriptor_t *td, void *st,
                           const asn_SET_specifics_t *specs) {
    unsigned i;

    if(specs->extensible < 2) return 0;
    for(i = 0; i < specs->extension_count; i++) {
        unsigned index = specs->extension_map[i];
        asn_TYPE_member_t *member = &td->elements[index];
        void **slot = (void **)((char *)st + member->memb_offset);
        if(!*slot && member->default_value_set
        && !ASN_SET_ISPRESENT2((char *)st + specs->pres_offset, index)) {
            if(member->default_value_set(slot)) return -1;
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
        }
    }
    return 0;
}

/*
 * Purpose: mark a fully decoded SET complete and release its presence map.
 * Original source: completion branch from SET_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/st/context/optional_count describe the completed SET.
 * Returns: zero when complete, otherwise -1.
 * Exceptions: none. History: keeps the owned bit map until final validation.
 * Example: only a populated SET with all optional bits consumed is completed.
 */
static int
SET_oer_finish_decode(const asn_codec_ctx_t *codec,
                      const asn_TYPE_descriptor_t *td, void *st,
                      const asn_SET_specifics_t *specs,
                      asn_struct_ctx_t *ctx) {
    if(!SET_oer_roots_populated(td, st, specs)
    || SET_oer_extension_defaults(td, st, specs)
    || SET_oer_resolve_pending(codec, td, st, ctx) != RC_OK) return -1;
    SET_oer_free_member_context(ctx);
    ctx->phase = SET_OER_PHASE_COMPLETE;
    ctx->step = 0;
    ctx->context = 0;
    ctx->left = 0;
    return 0;
}

/*
 * Purpose: decode root members and transition to the extension-map phase.
 * Source: X.696 SET root order and its root OPTIONAL preamble bits.
 * Version/date: 2026-10-30. Inputs: codec/td/st/order/count/context describe
 * the roots; ptr/size/consumed track streaming input. Returns RC status.
 * Errors: incomplete child values return RC_WMORE; invalid roots return fail.
 * Author: asn1c maintainers. History: extracted to bound decoder complexity.
 * Example: a resumed decoder continues at the saved canonical root position.
 */
static int
SET_oer_decode_roots(const asn_codec_ctx_t *codec,
                     const asn_TYPE_descriptor_t *td,
                     const asn_SET_specifics_t *specs, void *st,
                     const unsigned *order, size_t root_count,
                     size_t optional_count, asn_struct_ctx_t *ctx,
                     const char **ptr, size_t *size, size_t *consumed,
                     asn_dec_rval_t *rval) {
    while(ctx->phase == ASN_SET_OER_PHASE_MEMBERS
          && ((unsigned short)ctx->step >> 1) < root_count) {
        int status = SET_oer_decode_next_member(
            codec, td, specs, st, order, ctx, ptr, size, consumed, rval);
        if(status != RC_OK) return status;
    }
    if(ctx->phase == ASN_SET_OER_PHASE_MEMBERS) {
        if(ctx->context != (int)optional_count) return RC_FAIL;
        ctx->phase = ASN_SET_OER_PHASE_EXTENSION_MAP;
        ctx->step = 0;
        ctx->context = 0;
    }
    return RC_OK;
}

/*
 * Purpose: parse, decode, or skip additions and complete the SET value.
 * Source: X.696 extension bitmap and individual open-type rules.
 * Version/date: 2026-10-30. Inputs: codec/td/st/specs/context describe state;
 * ptr/size/consumed track streaming input. Returns RC_OK, RC_WMORE, or RC_FAIL.
 * Errors: malformed maps, open types, defaults, or mandatory roots fail.
 * Author: asn1c maintainers. History: extracted to bound decoder complexity.
 * Example: unknown set bits skip their complete length-delimited open types.
 */
static int
SET_oer_decode_additions(const asn_codec_ctx_t *codec,
                         const asn_TYPE_descriptor_t *td, void *st,
                         const asn_SET_specifics_t *specs,
                         asn_struct_ctx_t *ctx, const char **ptr,
                         size_t *size, size_t *consumed) {
    int status;

    if(ctx->phase == ASN_SET_OER_PHASE_EXTENSION_MAP) {
        if(!ctx->left)
            return SET_oer_finish_decode(codec, td, st, specs, ctx)
                ? RC_FAIL : RC_OK;
        {
            asn_bit_data_t *extension_map = 0;
            size_t map_bytes = 0;
            status = SET_oer_read_extension_map(*ptr, *size, &extension_map,
                                                &map_bytes);
            if(status != RC_OK) return status;
            /* Transfer saved envelopes to the newly owned bitmap cursor. */
            {
                asn_bit_data_t *previous = (asn_bit_data_t *)ctx->ptr;
                extension_map->refill_key = previous->refill_key;
                previous->refill_key = 0;
                FREEMEM(previous);
            }
            ctx->ptr = extension_map;
            ctx->context = 0;
            ctx->step = 0;
            ctx->phase = ASN_SET_OER_PHASE_EXTENSIONS;
            *ptr += map_bytes;
            *size -= map_bytes;
            *consumed += map_bytes;
        }
    }
    if(ctx->phase == ASN_SET_OER_PHASE_EXTENSIONS) {
        status = SET_oer_decode_extensions(codec, td, st, specs, ctx,
                                           ptr, size, consumed);
        if(status != RC_OK) return status;
        return SET_oer_finish_decode(codec, td, st, specs, ctx) ? RC_FAIL : RC_OK;
    }
    return RC_FAIL;
}

/*
 * Purpose: incrementally decode root values and additions of an OER SET.
 * Original source: X.696 clauses 8 and 18; adapted from SEQUENCE_decode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: codec/td/constraints/struct_ptr/input/size describe the decode.
 * Returns: decoder status and bytes consumed from this input chunk.
 * Exceptions: none. History: streams members and owns phase 1001 preamble state.
 * Example: a split component resumes at its canonical SET member.
 */
asn_dec_rval_t
SET_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td,
               const asn_oer_constraints_t *constraints, void **struct_ptr,
               const void *input, size_t input_size) {
    const asn_SET_specifics_t *specs;
    asn_dec_rval_t rval = {RC_FAIL, 0};
    asn_struct_ctx_t *ctx;
    unsigned *order = 0;
    size_t root_count;
    size_t optional_count = 0;
    const char *ptr = (const char *)input;
    size_t size = input_size;
    size_t consumed = 0;
    int status;
    void *st;

    (void)constraints;
    if(!SET_oer_decode_args_valid(opt_codec_ctx, td, struct_ptr, input,
                                  input_size))
        return rval;
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(SET_oer_build_order(td, specs, &order, &optional_count)) return rval;
    root_count = specs->extensible >= 2
        ? specs->root_count : td->elements_count;
    if(SET_oer_prepare_decode(td, specs, struct_ptr, order, optional_count,
                             &ctx)) {
        st = *struct_ptr;
        goto done;
    }
    st = *struct_ptr;

    status = SET_oer_read_preamble(ctx, specs->extensible >= 2,
                                   optional_count, &ptr, &size,
                                   &consumed);
    if(status != RC_OK) {
        rval.code = status == RC_WMORE ? RC_WMORE : RC_FAIL;
        goto done;
    }
    status = SET_oer_decode_roots(opt_codec_ctx, td, specs, st, order,
                                  root_count, optional_count, ctx, &ptr, &size,
                                  &consumed, &rval);
    if(status != RC_OK) {
        rval.code = status == RC_WMORE ? RC_WMORE : RC_FAIL;
        goto done;
    }
    status = SET_oer_decode_additions(opt_codec_ctx, td, st, specs, ctx,
                                      &ptr, &size, &consumed);
    if(status != RC_OK) {
        rval.code = status == RC_WMORE ? RC_WMORE : RC_FAIL;
        goto done;
    }
    rval.code = RC_OK;

done:
    rval.consumed = consumed;
    FREEMEM(order);
    return rval;
}

/*
 * Purpose: precompute OPTIONAL presence and validate mandatory SET values.
 * Original source: presence pass from SET_encode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/sptr/order describe values; present receives canonical presence.
 * Returns: zero for valid values, otherwise -1.
 * Exceptions: none. History: default-valued fields remain absent on the wire.
 * Example: an absent mandatory member fails before the preamble is emitted.
 */
static int
SET_oer_encode_presence(const asn_TYPE_descriptor_t *td, const void *sptr,
                        const unsigned *order, size_t root_count,
                        uint8_t *present) {
    size_t i;

    for(i = 0; i < root_count; i++) {
        asn_TYPE_member_t *member = &td->elements[order[i]];
        const void *value = SET_oer_element_ptr(sptr, member);

        if(value && member->default_value_cmp
        && member->default_value_cmp(value) == 0)
            value = 0;
        if(!value && !member->optional) return -1;
        present[i] = value != 0;
        if(present[i] && !member->type->op->oer_encoder) return -1;
    }
    return 0;
}

/*
 * Purpose: write the canonical OPTIONAL presence map and count its bytes.
 * Original source: preamble pass from SET_encode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/order/present describe bits; cb/key emit bytes; size is output.
 * Returns: zero on success, otherwise -1 for callback or bit writer failure.
 * Exceptions: none. History: OPTIONAL bits follow canonical member order.
 * Example: no OPTIONAL members produce no preamble bytes.
 */
static int
SET_oer_encode_preamble(const asn_TYPE_descriptor_t *td,
                       const unsigned *order, const uint8_t *present,
                       size_t root_count, size_t optional_count,
                       int extensible, int extensions_present,
                       asn_app_consume_bytes_f *cb, void *app_key,
                       size_t *computed_size) {
    asn_bit_outp_t preamble;
    size_t i;
    int ret;

    if(!optional_count && !extensible) return 0;
    memset(&preamble, 0, sizeof(preamble));
    preamble.output = cb;
    preamble.op_key = app_key;
    if(extensible && asn_put_few_bits(&preamble, extensions_present, 1) < 0)
        return -1;
    for(i = 0; i < root_count; i++) {
        if(td->elements[order[i]].optional) {
            ret = asn_put_few_bits(&preamble, present[i], 1);
            if(ret < 0) return -1;
        }
    }
    ret = asn_put_aligned_flush(&preamble);
    if(ret < 0) return -1;
    if(*computed_size > (size_t)SSIZE_MAX
    || preamble.flushed_bytes > (size_t)SSIZE_MAX - *computed_size)
        return -1;
    *computed_size += preamble.flushed_bytes;
    return 0;
}

/*
 * Purpose: encode present SET members and add their checked byte counts.
 * Original source: member emission pass from SET_encode_oer.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/sptr/order/present describe members; cb/key emit; size is output.
 * Returns: zero on success, otherwise -1 for child or size errors.
 * Exceptions: none. History: open types keep their dedicated encoder path.
 * Example: absent optional members are skipped without calling a child encoder.
 */
static int
SET_oer_encode_members(const asn_TYPE_descriptor_t *td, const void *sptr,
                       const unsigned *order, const uint8_t *present,
                       size_t root_count,
                       asn_app_consume_bytes_f *cb, void *app_key,
                       size_t *computed_size) {
    size_t i;

    for(i = 0; i < root_count; i++) {
        asn_TYPE_member_t *member = &td->elements[order[i]];
        asn_enc_rval_t child;
        const void *value;

        if(!present[i]) continue;
        value = SET_oer_element_ptr(sptr, member);
        if(member->flags & ATF_OPEN_TYPE) {
            child = OPEN_TYPE_oer_put(td, sptr, member, cb, app_key);
        } else {
            child = member->type->op->oer_encoder(
                member->type, member->encoding_constraints.oer_constraints,
                value, cb, app_key);
        }
        if(child.encoded < 0 || *computed_size > (size_t)SSIZE_MAX
        || (size_t)child.encoded > (size_t)SSIZE_MAX - *computed_size)
            return -1;
        *computed_size += (size_t)child.encoded;
    }
    return 0;
}

/*
 * Purpose: determine whether a pointer-backed addition is encoded on the wire.
 * Source: X.696 default omission and compiler-generated extension_map.
 * Version/date: 2026-10-30. Inputs: member/value identify the addition.
 * Returns: nonzero for a present non-default value.
 * Errors: none. Author: asn1c maintainers. History: shared by bitmap and body.
 * Example: an addition equal to DEFAULT is represented by a zero bitmap bit.
 */
static int
SET_oer_addition_present(const asn_TYPE_descriptor_t *td, const void *st, unsigned index) {
    const asn_TYPE_member_t *member = &td->elements[index];
    const void *value = SET_oer_element_ptr(st, member);
    if(member->flags & ATF_EXTENSION_GROUP) return SET_group_wire_present(td, st, index);
    return value && (!member->default_value_cmp || member->default_value_cmp(value) != 0);
}

/* Parent and member metadata for an OER open-addition encoder. */
typedef struct SET_oer_open_adapter_s {
    const asn_TYPE_descriptor_t *parent; /* SET descriptor for selection. */
    const asn_TYPE_member_t *member;     /* Open addition metadata. */
} SET_oer_open_adapter_t;

/*
 * Purpose: Verify a selected wrapper matches its parent table selector.
 * Source: OPEN TYPE CHOICE metadata. Version: 2026-10-30.
 * Inputs: td/sptr identify the parent; member describes its open field.
 * Returns: zero when consistent, -1 for invalid metadata or selection.
 * Errors: Invalid wrapper bounds and mismatched CHOICE arms fail.
 * Author: maintainers. History: Protects nested OER extension encoding.
 * Example: A selector choosing arm one rejects a wrapper holding arm two.
 */
static int
SET_oer_open_selection_valid(const asn_TYPE_descriptor_t *td, const void *sptr,
                             const asn_TYPE_member_t *member) {
    asn_type_selector_result_t selected;
    const asn_CHOICE_specifics_t *specs;
    const void *value;
    if(!member->type_selector || !member->type) return -1;
    selected = member->type_selector(td, sptr);
    if(!selected.type_descriptor || !selected.presence_index) return -1;
    if(!member->type->elements_count) return 0;
    if(!member->type->elements || !member->type->specifics
    || selected.presence_index > member->type->elements_count) return -1;
    specs = (const asn_CHOICE_specifics_t *)member->type->specifics;
    if((specs->pres_size != sizeof(char) && specs->pres_size != sizeof(short)
        && specs->pres_size != sizeof(int))
    || specs->pres_offset > specs->struct_size
    || specs->pres_size > specs->struct_size - specs->pres_offset) return -1;
    value = SET_oer_element_ptr(sptr, member);
    if(!value || CHOICE_variant_get_presence(member->type, value) != selected.presence_index
    || member->type->elements[selected.presence_index - 1].type != selected.type_descriptor)
        return -1;
    return 0;
}

/*
 * Purpose: Encode an inner open value under its parent's table selector.
 * Source: OPEN_TYPE_oer_put. Version: 2026-10-30.
 * Inputs: td carries adapter metadata; sptr is the parent; cb/key receive bytes.
 * Returns: encoder result. Errors: Invalid selection or encoding fails.
 * Author: maintainers. History: Adds extension-addition outer framing.
 * Example: A selected INTEGER is written inside two OER envelopes.
 */
static asn_enc_rval_t
SET_oer_encode_open_adapter(const asn_TYPE_descriptor_t *td,
                            const asn_oer_constraints_t *constraints,
                            const void *sptr, asn_app_consume_bytes_f *cb,
                            void *key) {
    const SET_oer_open_adapter_t *adapter = td->specifics;
    (void)constraints;
    if(SET_oer_open_selection_valid(adapter->parent, sptr, adapter->member))
        ASN__ENCODE_FAILED;
    return OPEN_TYPE_oer_put(adapter->parent, sptr, adapter->member, cb, key);
}

/*
 * Purpose: encode present SET extension values as bounded OER open types.
 * Source: X.696 16.5 and the validated v3 SEQUENCE group adapters.
 * Version/date: 1.0, 2026-10-30. Inputs: td/sptr/specs describe additions;
 * cb/app_key receive bytes and computed_size accumulates the output size.
 * Returns: zero on success, -1 for invalid values, codecs, or size overflow.
 * Errors: callback and open-type failures propagate to the caller.
 * Author: asn1c maintainers. History: split from extension bitmap emission.
 * Example: one present group emits one length-delimited SEQUENCE body.
 */
static int
SET_oer_encode_extension_values(const asn_TYPE_descriptor_t *td, const void *sptr,
                                const asn_SET_specifics_t *specs,
                                asn_app_consume_bytes_f *cb, void *app_key,
                                size_t *computed_size) {
    size_t i;
    for(i = 0; i < specs->extension_count; i++) {
        const asn_TYPE_member_t *member =
            &td->elements[specs->extension_map[i]];
        const void *value = SET_oer_element_ptr(sptr, member);
        ssize_t wrote;
        asn_TYPE_descriptor_t adapter;
        asn_TYPE_operation_t operations;
        SET_oer_open_adapter_t open_adapter;
        const asn_TYPE_descriptor_t *wire_type = member->type;
        int present = SET_oer_addition_present(td, sptr, specs->extension_map[i]);

        if(present < 0) return -1;
        if(!present) continue;
        if(member->flags & ATF_OPEN_TYPE) {
            adapter = *member->type;
            memset(&operations, 0, sizeof(operations));
            operations.oer_encoder = SET_oer_encode_open_adapter;
            open_adapter.parent = td;
            open_adapter.member = member;
            adapter.op = &operations;
            adapter.specifics = &open_adapter;
            wire_type = &adapter;
            value = sptr;
        } else if(member->flags & ATF_EXTENSION_GROUP) {
            if(SET_group_adapter(td, specs->extension_map[i], &adapter)) return -1;
            wire_type = &adapter;
        }
        if(!wire_type->op->oer_encoder) return -1;
        wrote = oer_open_type_put(wire_type,
            member->encoding_constraints.oer_constraints, value, cb, app_key);
        if(wrote < 0 || *computed_size > (size_t)SSIZE_MAX
        || (size_t)wrote > (size_t)SSIZE_MAX - *computed_size)
            return -1;
        *computed_size += (size_t)wrote;
    }
    return 0;
}

/*
 * Purpose: encode the declared extension bitmap and present open-type values.
 * Source: X.696 clauses 16.4 and 16.5.1.
 * Version/date: 2026-10-30. Inputs: td/sptr/specs describe additions; cb/key
 * emit bytes and computed_size receives their count. Returns: zero or -1.
 * Errors: allocation, callback, missing codec, and count overflow fail.
 * Author: asn1c maintainers. History: added for individual OER additions.
 * Example: extension_map[0] controls the first most-significant bitmap bit.
 */
static int
SET_oer_encode_extensions(const asn_TYPE_descriptor_t *td, const void *sptr,
                          const asn_SET_specifics_t *specs,
                          int extensions_present,
                          asn_app_consume_bytes_f *cb, void *app_key,
                          size_t *computed_size) {
    size_t bitmap_bytes;
    size_t content_length;
    size_t i;
    uint8_t unused_bits;
    uint8_t *bitmap = 0;
    ssize_t length_size;

    if(!extensions_present) return 0;
    bitmap_bytes = specs->extension_count / 8 + (specs->extension_count % 8 != 0);
    unused_bits = (uint8_t)((8 - (specs->extension_count & 7)) & 7);
    if(!specs->extension_count || bitmap_bytes == SIZE_MAX) return -1;
    content_length = 1 + bitmap_bytes;
    if(content_length > (size_t)SSIZE_MAX - sizeof(size_t) - 1)
        return -1;
    if(*computed_size > (size_t)SSIZE_MAX - content_length
                                      - sizeof(size_t) - 1)
        return -1;
    bitmap = (uint8_t *)CALLOC(bitmap_bytes, 1);
    if(!bitmap) return -1;
    for(i = 0; i < specs->extension_count; i++) {
        int present = SET_oer_addition_present(td, sptr, specs->extension_map[i]);
        if(present < 0) { FREEMEM(bitmap); return -1; }
        if(present) bitmap[i / 8] |= (uint8_t)(0x80u >> (i % 8));
    }
    length_size = oer_serialize_length(content_length, cb, app_key);
    if(length_size < 0 || cb(&unused_bits, 1, app_key) < 0
    || cb(bitmap, bitmap_bytes, app_key) < 0) {
        FREEMEM(bitmap);
        return -1;
    }
    *computed_size += (size_t)length_size + content_length;
    FREEMEM(bitmap);

    return SET_oer_encode_extension_values(td, sptr, specs, cb, app_key, computed_size);
}

/*
 * Purpose: encode a SET's canonical roots and individual OER additions.
 * Original source: X.696 clauses 8 and 18; tag2el_cxer supplies root order.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/constraints/sptr describe the SET; cb/app_key receive bytes.
 * Returns: encoded result with the total number of bytes written.
 * Exceptions: none. History: emits canonical preamble and root members.
 * Example: OPTIONAL bits and values follow each member's minimum tag.
 */
asn_enc_rval_t
SET_encode_oer(const asn_TYPE_descriptor_t *td,
               const asn_oer_constraints_t *constraints, const void *sptr,
               asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_SET_specifics_t *specs;
    unsigned *order = 0;
    uint8_t *present = 0;
    size_t root_count;
    size_t optional_count = 0;
    size_t i;
    int extensions_present = 0;
    size_t computed_size = 0;
    asn_enc_rval_t er = {0, 0, 0};

    (void)constraints;
    if(!td || !td->specifics || !td->op || td->op->kind != ASN_KIND_SET
    || !sptr || !cb) ASN__ENCODE_FAILED;
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(SET_oer_build_order(td, specs, &order, &optional_count))
        ASN__ENCODE_FAILED;
    root_count = specs->extensible >= 2
        ? specs->root_count : td->elements_count;
    if(SET_oer_members_valid(td, sptr)) {
        FREEMEM(order);
        ASN__ENCODE_FAILED;
    }
    OER_ENCODER_RECURSION_DEPTH_INC();

    if(root_count) {
        present = (uint8_t *)CALLOC(root_count, sizeof(*present));
        if(!present) goto failed;
    }
    if(SET_oer_encode_presence(td, sptr, order, root_count, present))
        goto failed;
    for(i = 0; specs->extensible >= 2 && i < specs->extension_count; i++) {
        int present_addition = SET_oer_addition_present(td, sptr, specs->extension_map[i]);
        if(present_addition < 0) goto failed;
        if(present_addition) extensions_present = 1;
    }
    if(SET_oer_encode_preamble(td, order, present, root_count, optional_count,
                               specs->extensible >= 2, extensions_present,
                               cb, app_key, &computed_size))
        goto failed;
    if(SET_oer_encode_members(td, sptr, order, present, root_count, cb,
                              app_key, &computed_size))
        goto failed;
    if(SET_oer_encode_extensions(td, sptr, specs, extensions_present,
                                 cb, app_key, &computed_size))
        goto failed;

    FREEMEM(present);
    FREEMEM(order);
    OER_ENCODER_RECURSION_DEPTH_DEC();
    er.encoded = (ssize_t)computed_size;
    ASN__ENCODED_OK(er);

failed:
    FREEMEM(present);
    FREEMEM(order);
    OER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODE_FAILED;
}

#endif /* ASN_DISABLE_OER_SUPPORT */
