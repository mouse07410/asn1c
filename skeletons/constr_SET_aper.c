/*
 * Aligned PER codec for ASN.1 SET roots and individual v2 extension additions.
 *
 * Copyright (c) 2026 asn1c maintainers.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <OPEN_TYPE.h>
#include <ANY.h>
#include <aper_encoder.h>
#include <aper_opentype.h>
#include <aper_support.h>
#include <string.h>

#ifndef ASN_DISABLE_APER_SUPPORT

/*
 * Purpose: compare two encoded tags in the numeric order used by generated maps.
 * Source: Compiler tag2el sorting by tag class and tag number.
 * Version: 2026-10-30.
 * Parameters: left and right are encoded ASN.1 tags.
 * Returns: -1, 0, or 1 according to tag order.
 * Errors: None.
 * Author: asn1c maintainers.
 * History: Added for SET APER canonical root-order validation.
 * Example: SET_aper_tag_compare(tag_a, tag_b) validates a sorted map.
 */
static int
SET_aper_tag_compare(ber_tlv_tag_t left, ber_tlv_tag_t right) {
    int left_class = BER_TAG_CLASS(left);
    int right_class = BER_TAG_CLASS(right);
    ber_tlv_tag_t left_value = BER_TAG_VALUE(left);
    ber_tlv_tag_t right_value = BER_TAG_VALUE(right);

    if(left_class != right_class)
        return left_class < right_class ? -1 : 1;
    if(left_value != right_value)
        return left_value < right_value ? -1 : 1;
    return 0;
}

/*
 * Purpose: order legacy SET components by their lowest tag-map entry.
 * Source: SET tag2el_cxer map emitted with FTE_CANONICAL_XER.
 * Version: 2026-10-30.
 * Parameters: td/specs describe the SET; order receives member indexes.
 * Returns: 0 for a complete order, -1 for malformed or incomplete metadata.
 * Errors: Missing members, out-of-range indexes, or unsorted tags fail.
 * Author: asn1c maintainers.
 * History: Added for SET APER support using compiler canonical tag ordering.
 * Example: Multiple CHOICE tags still produce one SET member position.
 */
static int
SET_aper_legacy_order(const asn_TYPE_descriptor_t *td,
                      const asn_SET_specifics_t *specs, unsigned *order) {
    unsigned i;
    uint8_t *seen;

    if(specs->tag2el_cxer_count < td->elements_count
    || (specs->tag2el_cxer_count && !specs->tag2el_cxer)) return -1;
    seen = td->elements_count ? CALLOC(td->elements_count, 1) : 0;
    if(td->elements_count && !seen) return -1;
    for(i = 0; i < specs->tag2el_cxer_count; i++) {
        const asn_TYPE_tag2member_t *entry = &specs->tag2el_cxer[i];
        const asn_TYPE_member_t *member;
        if(entry->el_no >= td->elements_count
        || (i && SET_aper_tag_compare(specs->tag2el_cxer[i - 1].el_tag,
                                      entry->el_tag) >= 0)) {
            FREEMEM(seen);
            return -1;
        }
        member = &td->elements[entry->el_no];
        if(seen[entry->el_no]
        && (!member->type || !member->type->op
            || member->type->op->kind != ASN_KIND_CHOICE)) {
            FREEMEM(seen);
            return -1;
        }
        seen[entry->el_no] = 1;
    }
    for(i = 0; i < td->elements_count; i++) {
        if(!seen[i]) {
            FREEMEM(seen);
            return -1;
        }
    }
    if(td->elements_count) memset(seen, 0, td->elements_count);
    for(i = 0; i < td->elements_count; i++) {
        unsigned j;
        unsigned best = td->elements_count;
        ber_tlv_tag_t best_tag = 0;
        for(j = 0; j < specs->tag2el_cxer_count; j++) {
            const asn_TYPE_tag2member_t *entry = &specs->tag2el_cxer[j];
            if(seen[entry->el_no]) continue;
            if(best == td->elements_count
            || SET_aper_tag_compare(entry->el_tag, best_tag) < 0) {
                best = entry->el_no;
                best_tag = entry->el_tag;
            }
        }
        if(best == td->elements_count) {
            FREEMEM(seen);
            return -1;
        }
        seen[best] = 1;
        order[i] = best;
    }
    FREEMEM(seen);
    return 0;
}

/*
 * Purpose: determine whether a CXER map entry names a version 2 SET root.
 * Source: Compiler-generated root_map metadata.
 * Version/date: 2026-10-30.
 * Inputs: specs contains the root member indexes; index is one map member.
 * Returns: Nonzero if index is a root member.
 * Errors: None. Author: asn1c maintainers. History: Added for marker filtering.
 * Example: A root after a marker is still selected into canonical order.
 */
static int
SET_aper_is_root_member(const asn_SET_specifics_t *specs, unsigned index) {
    unsigned i;
    for(i = 0; i < specs->root_count; i++)
        if(specs->root_map[i] == index) return 1;
    return 0;
}

/*
 * Purpose: select the lowest unused root tag from the complete CXER map.
 * Source: ASN.1 canonical SET tag ordering and v2 root membership.
 * Version/date: 2026-10-30.
 * Inputs: td/specs/seen identify used roots; best_out receives selected index.
 * Returns: 0 on selection, -1 when no root tag remains.
 * Errors: None. Author: asn1c maintainers. History: Split root ordering logic.
 * Example: Duplicate CHOICE alternatives collapse to one member position.
 */
static int
SET_aper_next_root(const asn_TYPE_descriptor_t *td,
                   const asn_SET_specifics_t *specs, const uint8_t *seen,
                   unsigned *best_out) {
    unsigned i;
    unsigned best = td->elements_count;
    ber_tlv_tag_t best_tag = 0;

    for(i = 0; i < specs->tag2el_cxer_count; i++) {
        const asn_TYPE_tag2member_t *entry = &specs->tag2el_cxer[i];
        if(seen[entry->el_no]
        || !SET_aper_is_root_member(specs, entry->el_no)) continue;
        if(best == td->elements_count
        || SET_aper_tag_compare(entry->el_tag, best_tag) < 0) {
            best = entry->el_no;
            best_tag = entry->el_tag;
        }
    }
    if(best == td->elements_count) return -1;
    *best_out = best;
    return 0;
}

/*
 * Purpose: build a v2 root order across marker-split CXER map regions.
 * Source: Version 2 SET root_map and canonical tag map.
 * Version/date: 2026-10-30.
 * Inputs: td/specs describe the SET; order has root_count slots.
 * Returns: 0 for a complete order, -1 for invalid maps or allocation failure.
 * Errors: Missing root tags and out-of-range map members fail closed.
 * Author: asn1c maintainers. History: Added for trailing APER roots.
 * Example: Roots before and after markers are sorted together by ASN.1 tag.
 */
static int
SET_aper_v2_root_order(const asn_TYPE_descriptor_t *td,
                       const asn_SET_specifics_t *specs, unsigned *order) {
    unsigned i;
    unsigned n;
    uint8_t *seen;

    if((specs->root_count && !specs->tag2el_cxer_count)
    || (specs->tag2el_cxer_count && !specs->tag2el_cxer)) return -1;
    seen = td->elements_count ? CALLOC(td->elements_count, 1) : 0;
    if(td->elements_count && !seen) return -1;
    for(i = 0; i < specs->tag2el_cxer_count; i++) {
        if(specs->tag2el_cxer[i].el_no >= td->elements_count) {
            FREEMEM(seen);
            return -1;
        }
    }
    for(n = 0; n < specs->root_count; n++) {
        unsigned best;
        if(SET_aper_next_root(td, specs, seen, &best)) {
            FREEMEM(seen);
            return -1;
        }
        seen[best] = 1;
        order[n] = best;
    }
    FREEMEM(seen);
    return 0;
}

/*
 * Purpose: select legacy or v2 canonical ordering after partition validation.
 * Source: Generated tag2el_cxer map and versioned SET root map.
 * Version/date: 2026-10-30.
 * Inputs: td/specs/root_count describe the SET; order receives member indexes.
 * Returns: 0 on a complete order, -1 for inconsistent metadata.
 * Errors: Root counts differing from the v2 map are rejected.
 * Author: asn1c maintainers. History: Handles both legacy and root-only maps.
 * Example: A v2 map may include a root after an extension marker.
 */
static int
SET_aper_order_from_cxer(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs,
                         unsigned root_count, unsigned *order) {
    if(specs->extensible < 2) return SET_aper_legacy_order(td, specs, order);
    if(root_count != specs->root_count) return -1;
    return SET_aper_v2_root_order(td, specs, order);
}

/*
 * Purpose: allocate and validate the canonical member order for a SET.
 * Source: SET canonical CXER map emitted by the compiler.
 * Version: 2026-10-30.
 * Parameters: td/specs describe the SET; order_out receives allocated indexes.
 * Returns: 0 on success, -1 for invalid maps or allocation failure.
 * Errors: A partially populated or out-of-range map is rejected.
 * Author: asn1c maintainers.
 * History: Centralized canonical map validation for the SET APER codecs.
 * Example: Empty SETs succeed with a NULL order array.
 */
static int
SET_aper_canonical_order(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs,
                         unsigned root_count, unsigned **order_out) {
    unsigned *order;
    size_t bytes;
    int result;

    *order_out = 0;
    if(root_count == 0) return 0;
    if((size_t)root_count > SIZE_MAX / sizeof(*order)) return -1;
    bytes = (size_t)root_count * sizeof(*order);
    order = MALLOC(bytes);
    if(!order) return -1;
    result = SET_aper_order_from_cxer(td, specs, root_count, order);
    if(result) {
        FREEMEM(order);
        return -1;
    }
    *order_out = order;
    return 0;
}

/*
 * Purpose: validate the SET descriptor's fixed context and presence storage.
 * Source: Generated SET specifics and _presence_map layout.
 * Version: 2026-10-30.
 * Parameters: td/specs describe one SET descriptor.
 * Returns: Nonzero if all fixed storage lies within struct_size.
 * Errors: Missing maps, overflow, and out-of-range offsets return zero.
 * Author: asn1c maintainers.
 * History: Added to reject malformed PER descriptors before bit access.
 * Example: A presence offset beyond struct_size is rejected safely.
 */
static int
SET_aper_layout_valid(const asn_TYPE_descriptor_t *td,
                      const asn_SET_specifics_t *specs) {
    size_t bits_per_word = 8 * sizeof(unsigned int);
    size_t words;
    size_t presence_bytes;

    if(!td || !specs || !specs->struct_size
    || (td->elements_count && (!td->elements || !specs->_mandatory_elements)))
        return 0;
    if(specs->ctx_offset > specs->struct_size
    || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset)
        return 0;
    if((size_t)td->elements_count > SIZE_MAX - (bits_per_word - 1)) return 0;
    words = ((size_t)td->elements_count + bits_per_word - 1) / bits_per_word;
    if(words > SIZE_MAX / sizeof(unsigned int)) return 0;
    presence_bytes = words * sizeof(unsigned int);
    return specs->pres_offset <= specs->struct_size
        && presence_bytes <= specs->struct_size - specs->pres_offset;
}

/*
 * Purpose: validate the versioned root/addition partition for extensible SETs.
 * Source: Version 2 compiler-generated SET maps.
 * Version/date: 2026-10-30.
 * Inputs: td and specs describe the generated SET metadata.
 * Returns: 0 for a complete safe partition, -1 for malformed or legacy data.
 * Errors: Duplicate indexes, groups, and inline additions are rejected.
 * Author: asn1c maintainers. History: Added for individual APER additions.
 * Example: root and extension maps partition every component exactly once.
 */
/*
 * Purpose: validate the v2 header and root/addition map pointers.
 * Source: Compiler-generated asn_SET_specifics_t version 2 fields.
 * Version/date: 2026-10-30.
 * Inputs: td/specs describe the SET descriptor.
 * Returns: Nonzero when version, counts, and map pointers are consistent.
 * Errors: Missing or inconsistent metadata returns zero.
 * Author: asn1c maintainers. History: Split from complete partition checks.
 * Example: Legacy extension sentinel metadata fails this check.
 */
static int
SET_aper_v2_metadata_valid(const asn_TYPE_descriptor_t *td,
                           const asn_SET_specifics_t *specs) {
    return SET_version_valid(specs)
        && specs->root_count <= td->elements_count
        && specs->extension_count <= td->elements_count
        && specs->root_count == td->elements_count - specs->extension_count
        && (!specs->root_count || specs->root_map)
        && (!specs->extension_count || specs->extension_map);
}

/*
 * Purpose: validate and mark one index in the v2 SET partition.
 * Source: Generated root_map and extension_map arrays.
 * Version/date: 2026-10-30.
 * Inputs: td/index identify a member; is_addition and seen validate its role.
 * Returns: 0 when the component is valid and unique, otherwise -1.
 * Errors: Groups, missing types, duplicate indexes, and inline additions fail.
 * Author: asn1c maintainers. History: Split v2 partition validation.
 * Example: An addition without ATF_POINTER is rejected.
 */
static int
SET_aper_partition_index_valid(const asn_TYPE_descriptor_t *td,
                               unsigned index, int is_addition,
                               int group_allowed, uint8_t *seen) {
    const asn_TYPE_member_t *member;

    if(index >= td->elements_count || seen[index]) return -1;
    member = &td->elements[index];
    if(!member->type || !member->type->op
    || ((member->flags & ATF_EXTENSION_GROUP) && (!is_addition || !group_allowed))
    || (is_addition && !(member->flags & ATF_POINTER))) return -1;
    seen[index] = 1;
    return 0;
}

/*
 * Purpose: validate the complete version 2 root/addition partition.
 * Source: Compiler-generated SET v2 maps.
 * Version/date: 2026-10-30.
 * Inputs: td and specs describe the generated SET metadata.
 * Returns: 0 for non-extensible or valid v2 data; -1 for malformed/legacy data.
 * Errors: Duplicate indexes, groups, inline additions, and sentinels fail.
 * Author: asn1c maintainers. History: Added for individual APER additions.
 * Example: Every direct member belongs to exactly one map.
 */
static int
SET_aper_partition_valid(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs) {
    size_t total;
    size_t i;
    uint8_t *seen;

    if(specs->extensible == 0) return 0;
    if(!SET_aper_v2_metadata_valid(td, specs)) return -1;
    total = (size_t)specs->root_count + specs->extension_count;
    seen = td->elements_count ? CALLOC(td->elements_count, 1) : 0;
    if(td->elements_count && !seen) return -1;
    for(i = 0; i < total; i++) {
        int is_addition = i >= specs->root_count;
        unsigned index = is_addition
            ? specs->extension_map[i - specs->root_count] : specs->root_map[i];
        if(SET_aper_partition_index_valid(td, index, is_addition, specs->extensible == 3, seen)) {
            FREEMEM(seen);
            return -1;
        }
    }
    FREEMEM(seen);
    return SET_group_metadata_valid(td);
}

/*
 * Purpose: validate the basic APER SET descriptor fields.
 * Source: Generated SET descriptor, operation table, and member array.
 * Version: 2026-10-30.
 * Parameters: td is the descriptor; specs_out receives its SET specifics.
 * Returns: 0 on success, or -1 for a missing or malformed descriptor.
 * Errors: Missing operations and member storage are rejected before codec use.
 * Author: asn1c maintainers.
 * History: Shared by SET APER encode and decode after control-flow factoring.
 * Example: A valid SET descriptor supplies its specifics for layout checks.
 */
static int
SET_aper_descriptor_valid(const asn_TYPE_descriptor_t *td,
                          const asn_SET_specifics_t **specs_out) {
    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics
    || (td->elements_count && !td->elements)) return -1;
    *specs_out = (const asn_SET_specifics_t *)td->specifics;
    return 0;
}

/*
 * Purpose: validate one direct SET member before invoking its APER operation.
 * Source: SET_member_view storage validation and generated member operations.
 * Version: 2026-10-30.
 * Parameters: td/st identify the SET; index selects a direct member.
 * Returns: 0 for valid storage and operations, -1 for malformed descriptors.
 * Errors: Invalid offsets and missing operations fail.
 * Author: asn1c maintainers.
 * History: Added to keep malformed member metadata out of codec loops.
 * Example: An inline value with an invalid storage width is rejected.
 */
static int
SET_aper_member_valid(const asn_TYPE_descriptor_t *td, const void *st,
                      unsigned index) {
    const asn_TYPE_member_t *member;
    asn_SET_member_view_t view;

    if(index >= td->elements_count) return -1;
    member = &td->elements[index];
    if(!member->type || !member->type->op || !member->type->op->free_struct)
        return -1;
    if((member->flags & ATF_OPEN_TYPE) && !member->type_selector
       && !OPEN_TYPE_aper_has_fallback(member->type)) return -1;
    if(member->flags & ATF_EXTENSION_GROUP) {
        asn_TYPE_descriptor_t adapter;
        if(SET_group_adapter(td, index, &adapter)) return -1;
        return SET_member_view(td, st, index, 0, &view);
    }
    return SET_member_view(td, st, index, ASN_SET_DIRECT_MEMBER, &view);
}

/*
 * Purpose: resolve one SET member's wire presence, including DEFAULT omission.
 * Source: SET pointer representation and DEFAULT comparison callbacks.
 * Version: 2026-10-30.
 * Parameters: td/st identify the SET; index selects a member.
 * Returns: 1 when encoded, 0 when optional or DEFAULT-absent, -1 on error.
 * Errors: Missing mandatory pointers and invalid member storage return -1.
 * Author: asn1c maintainers.
 * History: Added to share presence logic across preamble and content passes.
 * Example: A present DEFAULT value produces zero.
 */
static int
SET_aper_member_present(const asn_TYPE_descriptor_t *td, const void *st,
                        unsigned index) {
    const asn_TYPE_member_t *member = &td->elements[index];
    asn_SET_member_view_t view;

    if(SET_aper_member_valid(td, st, index)
    || SET_member_view(td, st, index, ASN_SET_DIRECT_MEMBER, &view)) return -1;
    if(!view.present) return member->optional ? 0 : -1;
    if(member->default_value_cmp && member->default_value_cmp(view.value) == 0)
        return 0;
    return 1;
}

/*
 * Purpose: validate every SET member needed by the APER decoder.
 * Source: Generated SET member descriptors and APER decoder operations.
 * Version: 2026-10-30.
 * Parameters: td/st describe the value; order gives canonical member indexes.
 * Returns: 0 when all direct members have usable storage and decoder methods.
 * Errors: Invalid storage, extension groups, and missing decoders return -1.
 * Author: asn1c maintainers.
 * History: Split from SET_decode_aper to keep codec control flow auditable.
 * Example: Called before reading the SET presence preamble.
 */
static int
SET_aper_decode_members_valid(const asn_TYPE_descriptor_t *td, const void *st,
                              const asn_SET_specifics_t *specs,
                              const unsigned *order, unsigned count,
                              size_t *optional_count) {
    size_t i;

    *optional_count = 0;
    for(i = 0; i < count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];

        if(SET_aper_member_valid(td, st, index)
        || (!(member->flags & ATF_OPEN_TYPE)
            && !member->type->op->aper_decoder)) return -1;
        if(member->optional) (*optional_count)++;
    }
    if(specs->extensible >= 2) {
        for(i = 0; i < specs->extension_count; i++) {
            unsigned index = specs->extension_map[i];
            const asn_TYPE_member_t *member = &td->elements[index];
            if(SET_aper_member_valid(td, st, index)
            || (!(member->flags & ATF_OPEN_TYPE)
                && !member->type->op->aper_decoder)) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: prepare and validate storage before the SET APER preamble is read.
 * Source: Generated SET layout, tag order, and member codec callbacks.
 * Version/date: 2026-10-30.
 * Inputs: ctx/td/specs/sptr describe decoding; outputs receive storage, order,
 *         root count, and optional-root count.
 * Returns: 0 on success, -1 for malformed metadata, allocation, or stack limit.
 * Errors: Allocated order storage is freed when preparation fails.
 * Author: asn1c maintainers. History: Factored from SET_decode_aper.
 * Example: Called before reading the extension-present bit.
 */
static int
SET_aper_decode_prepare(const asn_codec_ctx_t *ctx,
                        const asn_TYPE_descriptor_t *td,
                        const asn_SET_specifics_t *specs, void **sptr,
                        void **st_out, unsigned **order_out,
                        unsigned *root_count, size_t *optional_count) {
    *order_out = 0;
    if(!SET_aper_layout_valid(td, specs)
    || SET_aper_partition_valid(td, specs)) return -1;
    *root_count = specs->extensible >= 2 ? specs->root_count : td->elements_count;
    if(SET_aper_canonical_order(td, specs, *root_count, order_out)) return -1;
    if(ASN__STACK_OVERFLOW_CHECK(ctx)) goto failed;
    if(!*sptr) {
        *sptr = CALLOC(1, specs->struct_size);
        if(!*sptr) goto failed;
    }
    *st_out = *sptr;
    if(SET_aper_decode_members_valid(td, *st_out, specs, *order_out,
                                     *root_count, optional_count)) goto failed;
    return 0;

failed:
    FREEMEM(*order_out);
    *order_out = 0;
    return -1;
}

/*
 * Purpose: read the optional-member presence bits for one SET value.
 * Source: X.691 SET preamble and the existing PER bit reader.
 * Version: 2026-10-30.
 * Parameters: pd is the bit input; count is the number of optional members;
 *             storage and bits receive the owned buffer and its bit reader.
 * Returns: 0 on success, 1 when input is truncated, or -1 on allocation error.
 * Errors: Size overflow, allocation failure, and malformed input are reported.
 * Author: asn1c maintainers.
 * History: Split from SET_decode_aper to isolate preamble handling.
 * Example: A zero count initializes an empty bit reader without allocation.
 */
static int
SET_aper_decode_presence(asn_per_data_t *pd, size_t count, uint8_t **storage,
                         asn_per_data_t *bits) {
    size_t presence_bytes;

    *storage = 0;
    memset(bits, 0, sizeof(*bits));
    if(!count) return 0;
    if(count > SIZE_MAX - 7) return -1;
    presence_bytes = ((count + 7) >> 3) + 1;
    if(presence_bytes < count / 8) return -1;
    *storage = MALLOC(presence_bytes);
    if(!*storage) return -1;
    if(per_get_many_bits(pd, *storage, 0, count)) return 1;
    bits->buffer = *storage;
    bits->nbits = count;
    return 0;
}

/*
 * Purpose: Replay a buffered open-type envelope once all SET fields exist.
 * Source: SET APER canonical ordering and OPEN_TYPE_aper_get. Version: 2026-10-30.
 * Inputs: ctx/td/st select the parent; member and payload identify a value.
 * Returns: Decoder status. Errors: allocation or invalid envelope fails.
 * Author: asn1c maintainers. History: defer table selection until roots decode.
 * Example: An open field before its selector is decoded after that selector.
 */
static asn_dec_rval_t
SET_aper_resolve_open(const asn_codec_ctx_t *ctx,
                      const asn_TYPE_descriptor_t *td, void *st,
                      asn_TYPE_member_t *member, const ANY_t *payload) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    asn_per_data_t input;
    void *encoded = 0;
    ssize_t size = aper_encode_to_new_buffer(&asn_DEF_ANY, 0, payload, &encoded);

    if(size <= 0 || (size_t)size > SIZE_MAX / 8) {
        FREEMEM(encoded);
        return result;
    }
    memset(&input, 0, sizeof(input));
    input.buffer = encoded;
    input.nbits = (size_t)size * 8;
    result = OPEN_TYPE_aper_get(ctx, td, st, member, &input);
    FREEMEM(encoded);
    return result;
}

/*
 * Purpose: Release every saved open payload in a SET decoding attempt.
 * Source: Local APER SET decoder. Version: 2026-10-30.
 * Inputs: values is a count-entry array of nullable ANY pointers.
 * Returns: Nothing. Errors: None. Author: asn1c maintainers.
 * History: Added for deferred table selection. Example: cleanup after RC_WMORE.
 */
static void
SET_aper_free_pending(ANY_t **values, unsigned count) {
    unsigned i;
    if(!values) return;
    for(i = 0; i < count; i++) {
        if(values[i]) ASN_STRUCT_FREE(asn_DEF_ANY, values[i]);
    }
    FREEMEM(values);
}

/*
 * Purpose: decode all SET members after the optional presence preamble.
 * Source: X.691 SET component order and generated member callbacks.
 * Version: 2026-10-30.
 * Parameters: ctx/td/st/specs/order identify the SET; pd/bits hold input;
 *             rv receives child decoder status.
 * Returns: 0 on success, 1 for truncated presence input, 2 for child failure,
 *          or -1 for invalid DEFAULT handling.
 * Errors: Member callbacks retain their own RC status in rv.
 * Author: asn1c maintainers.
 * History: Split from SET_decode_aper to isolate component decoding.
 * Example: Called after all member descriptors have passed validation.
 */
static int
SET_aper_decode_content(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td, void *st,
                        const asn_SET_specifics_t *specs,
                        const unsigned *order, unsigned count,
                        asn_per_data_t *pd,
                        asn_per_data_t *optional_bits, asn_dec_rval_t *rv,
                        ANY_t **pending) {
    size_t i;

    for(i = 0; i < count; i++) {
        unsigned index = order[i];
        asn_TYPE_member_t *member = &td->elements[index];
        void *inline_value;
        void **member_pointer;
        int present = 1;

        if(member->flags & ATF_POINTER) {
            member_pointer = (void **)((char *)st + member->memb_offset);
        } else {
            inline_value = (char *)st + member->memb_offset;
            member_pointer = &inline_value;
        }
        if(member->optional) {
            present = per_get_few_bits(optional_bits, 1);
            if(present < 0) return 1;
        }
        if(!present) {
            if(member->default_value_set) {
                if(member->default_value_set(member_pointer)) return -1;
                ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
            }
            continue;
        }
        if(member->flags & ATF_OPEN_TYPE) {
            *rv = ANY_decode_aper(opt_codec_ctx, &asn_DEF_ANY, 0,
                                  (void **)&pending[index], pd);
        } else {
            *rv = member->type->op->aper_decoder(
                opt_codec_ctx, member->type,
                member->encoding_constraints.per_constraints,
                member_pointer, pd);
        }
        if(rv->code != RC_OK) return 2;
        ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
    }
    return 0;
}

/*
 * Purpose: check mandatory presence bits for roots while ignoring additions.
 * Source: Generated SET mandatory-element mask and root map.
 * Version/date: 2026-10-30.
 * Inputs: td, st, and specs identify one decoded SET value.
 * Returns: Nonzero when all mandatory roots have their presence bit set.
 * Errors: Invalid root indexes return zero.
 * Author: asn1c maintainers. History: Added for extensible SET decoding.
 * Example: An omitted addition does not invalidate a populated root value.
 */
static int
SET_aper_roots_populated(const asn_TYPE_descriptor_t *td, const void *st,
                         const asn_SET_specifics_t *specs) {
    size_t i;
    size_t word_bits = 8 * sizeof(unsigned int);

    if(specs->extensible == 0) return _SET_is_populated(td, st);
    for(i = 0; i < specs->root_count; i++) {
        unsigned index = specs->root_map[i];
        size_t word_index = index / word_bits;
        unsigned int mandatory;

        if(index >= td->elements_count) return 0;
        memcpy(&mandatory,
               (const char *)specs->_mandatory_elements
                   + word_index * sizeof(mandatory),
               sizeof(mandatory));
        mandatory = sys_ntohl(mandatory);
        if((mandatory & (1u << (word_bits - 1 - (index % word_bits))))
        && !ASN_SET_ISPRESENT2((char *)st + specs->pres_offset, index))
            return 0;
    }
    return 1;
}

/*
 * Purpose: initialize DEFAULT values for absent pointer-backed additions.
 * Source: X.691 SET extension addition default handling.
 * Version/date: 2026-10-30.
 * Inputs: td, st, and specs identify the decoded SET.
 * Returns: 0 on success, -1 if member storage or a default setter fails.
 * Errors: Invalid indexes and allocation failures are reported to the caller.
 * Author: asn1c maintainers. History: Added for version 2 addition maps.
 * Example: An absent DEFAULT addition receives its declared default value.
 */
static int
SET_aper_extension_defaults(const asn_TYPE_descriptor_t *td, void *st,
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
 * Purpose: read and validate one APER SET extension bitmap.
 * Source: X.691 normally-small extension-map length and aligned bitmap.
 * Version/date: 2026-10-30.
 * Inputs: pd is the input cursor; storage/map receive owned bytes and a cursor.
 * Returns: 0 on success, -2 for truncation, or -1 for malformed data/allocation.
 * Errors: Empty maps and all-zero maps are rejected.
 * Author: asn1c maintainers. History: Split from the extension decode loop.
 * Example: A bitmap with only unknown high bits is valid and nonempty.
 */
static int
SET_aper_extension_map_get(asn_per_data_t *pd, uint8_t **storage,
                           asn_per_data_t *map) {
    ssize_t bit_count = aper_get_nslength(pd);
    size_t bitmap_bytes;
    int i;

    *storage = 0;
    memset(map, 0, sizeof(*map));
    if(bit_count < 0) return -2;
    if(bit_count == 0 || bit_count > INT_MAX
    || (size_t)bit_count > SIZE_MAX - 7) return -1;
    if(!pd->refill && (pd->nboff > pd->nbits
    || (size_t)bit_count > pd->nbits - pd->nboff)) return -2;
    bitmap_bytes = ((size_t)bit_count + 7) / 8;
    *storage = CALLOC(bitmap_bytes + 1, 1);
    if(!*storage) return -1;
    if(per_get_many_bits(pd, *storage, 0, (int)bit_count)) {
        FREEMEM(*storage);
        *storage = 0;
        return -2;
    }
    for(i = 0; i < (int)bitmap_bytes; i++) {
        if((*storage)[i]) break;
    }
    if(i == (int)bitmap_bytes) {
        FREEMEM(*storage);
        *storage = 0;
        return -1;
    }
    if(aper_get_align(pd) < 0) {
        FREEMEM(*storage);
        *storage = 0;
        return -2;
    }
    map->buffer = *storage;
    map->nbits = (size_t)bit_count;
    return 0;
}

/*
 * Purpose: Save an addition's inner open envelope for later table selection.
 * Source: X.691 extension-addition and open-type framing. Version: 2026-10-30.
 * Inputs: ctx/pd read the outer envelope; pending receives the inner payload.
 * Returns: decoder status; incomplete outer input retains RC_WMORE.
 * Errors: Invalid inner framing or nonzero padding fails. Author: maintainers.
 * History: Supports open additions selected by later extension fields.
 * Example: An inner open value remains undecoded until the SET is complete.
 */
static asn_dec_rval_t
SET_aper_save_open_addition(const asn_codec_ctx_t *ctx, asn_per_data_t *pd,
                            ANY_t **pending) {
    ANY_t *outer = 0;
    asn_per_data_t inner;
    asn_dec_rval_t result;
    size_t padding;

    result = ANY_decode_aper(ctx, &asn_DEF_ANY, 0, (void **)&outer, pd);
    if(result.code != RC_OK) goto done;
    if(!outer || outer->size < 0 || (size_t)outer->size > SIZE_MAX / 8) {
        result.code = RC_FAIL;
        goto done;
    }
    memset(&inner, 0, sizeof(inner));
    inner.buffer = outer->buf;
    inner.nbits = (size_t)outer->size * 8;
    result = ANY_decode_aper(ctx, &asn_DEF_ANY, 0, (void **)pending, &inner);
    if(result.code != RC_OK || inner.moved > (size_t)outer->size * 8) {
        result.code = RC_FAIL;
        goto done;
    }
    padding = (size_t)outer->size * 8 - inner.moved;
    if(padding >= 8 || (padding && per_get_few_bits(&inner, (int)padding) != 0))
        result.code = RC_FAIL;
done:
    if(outer) ASN_STRUCT_FREE(asn_DEF_ANY, outer);
    return result;
}

/*
 * Purpose: decode one known extension addition from its aligned open type.
 * Source: X.691 extension-addition encoding and APER open-type runtime.
 * Version/date: 2026-10-30.
 * Inputs: ctx/td/st/specs identify the value; index and pd select the addition.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; successful values become present.
 * Errors: Missing APER child callbacks or malformed payloads are reported.
 * Author: asn1c maintainers. History: Split from the bitmap traversal.
 * Example: extension_map[0] selects the first declared addition.
 */
static asn_dec_rval_t
SET_aper_decode_addition(const asn_codec_ctx_t *ctx,
                        const asn_TYPE_descriptor_t *td, void *st,
                        const asn_SET_specifics_t *specs, unsigned index,
                        asn_per_data_t *pd, ANY_t **pending) {
    asn_dec_rval_t rv;
    asn_TYPE_member_t *member = &td->elements[index];
    void **slot = (void **)((char *)st + member->memb_offset);

    if(!member->type || !member->type->op
    || (!(member->flags & ATF_OPEN_TYPE) && !member->type->op->aper_decoder)) {
        rv.code = RC_FAIL;
        rv.consumed = 0;
        return rv;
    }
    if(member->flags & ATF_OPEN_TYPE) {
        rv = SET_aper_save_open_addition(ctx, pd, &pending[index]);
    } else if(member->flags & ATF_EXTENSION_GROUP) {
        asn_TYPE_descriptor_t adapter;
        void *temporary = 0;
        if(SET_group_adapter(td, index, &adapter)) {
            rv.code = RC_FAIL;
            rv.consumed = 0;
            return rv;
        }
        rv = aper_open_type_get(ctx, &adapter, 0, &temporary, pd);
        if(temporary && SET_group_clear_wire_context(member->type, temporary)) rv.code = RC_FAIL;
        if(rv.code == RC_OK && SET_group_mark_present(member->type, temporary)) rv.code = RC_FAIL;
        if(rv.code != RC_OK) {
            if(temporary) member->type->op->free_struct(member->type, temporary, ASFM_FREE_EVERYTHING);
            return rv;
        }
        if(*slot) member->type->op->free_struct(member->type, *slot, ASFM_FREE_EVERYTHING);
        *slot = temporary;
    } else {
        rv = aper_open_type_get(ctx, member->type,
            member->encoding_constraints.per_constraints, slot, pd);
    }
    if(rv.code == RC_OK)
        ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
    return rv;
}

/*
 * Purpose: decode known and unknown individual SET extension additions.
 * Source: X.691 extension bitmap and APER open-type helpers.
 * Version/date: 2026-10-30.
 * Inputs: ctx/td/st/specs describe the SET; pd carries additions when present.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL for the addition phase.
 * Errors: Truncated maps or open types return RC_WMORE where the helper allows.
 * Author: asn1c maintainers. History: Added for v2 SET metadata.
 * Example: Known additions decode by declaration index; later bits are skipped.
 */
static asn_dec_rval_t
SET_aper_decode_extensions(const asn_codec_ctx_t *ctx,
                           const asn_TYPE_descriptor_t *td, void *st,
                           const asn_SET_specifics_t *specs,
                           asn_per_data_t *pd, int extpresent, ANY_t **pending) {
    asn_dec_rval_t rv = {RC_OK, 0};

    if(extpresent) {
        uint8_t *bitmap;
        asn_per_data_t bits;
        int map_status = SET_aper_extension_map_get(pd, &bitmap, &bits);
        size_t i;
        if(map_status) {
            rv.code = map_status == -2 ? RC_WMORE : RC_FAIL;
            return rv;
        }

        /* Bitmap positions map directly to declaration-ordered additions. */
        for(i = 0; i < bits.nbits; i++) {
            int present = per_get_few_bits(&bits, 1);
            if(present < 0) {
                rv.code = RC_WMORE;
                break;
            }
            if(present) {
                if(i < specs->extension_count) {
                    rv = SET_aper_decode_addition(ctx, td, st, specs,
                                                  specs->extension_map[i], pd, pending);
                    if(rv.code != RC_OK) break;
                } else {
                    rv = aper_open_type_skip_result(ctx, pd);
                    if(rv.code != RC_OK) break;
                }
            }
        }
        FREEMEM(bitmap);
        if(rv.code != RC_OK) return rv;
    }
    if(SET_aper_extension_defaults(td, st, specs)) rv.code = RC_FAIL;
    return rv;
}

/*
 * Purpose: decode APER SET roots and individual version 2 additions.
 * Source: X.691 SET root ordering, extension maps, and APER open types.
 * Version: 2026-10-30.
 * Parameters: ctx/td/constraints/sptr/pd are the standard APER decoder inputs.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL with consumed input bits.
 * Errors: Legacy sentinels, groups, malformed maps, and bad members fail.
 * Author: asn1c maintainers.
 * History: Extended root-only APER support with version 2 additions.
 * Example: Known additions decode from declaration-indexed open types.
 */
asn_dec_rval_t
SET_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, void **sptr,
                asn_per_data_t *pd) {
    const asn_SET_specifics_t *specs;
    asn_dec_rval_t rv = {RC_FAIL, 0};
    asn_per_data_t optional_bits;
    uint8_t *presence = 0;
    unsigned *order = 0;
    ANY_t **pending = 0;
    unsigned i;
    void *st;
    size_t optional_count = 0;
    unsigned root_count;
    int extpresent = 0; /* state variable: indicates an extension map follows */
    int status;

    (void)constraints;
    if(!sptr || !pd || SET_aper_descriptor_valid(td, &specs))
        ASN__DECODE_FAILED;
    if(SET_aper_decode_prepare(opt_codec_ctx, td, specs, sptr, &st, &order,
                               &root_count, &optional_count)) ASN__DECODE_FAILED;
    pending = (ANY_t **)CALLOC(td->elements_count ? td->elements_count : 1,
                              sizeof(*pending));
    if(!pending) goto failed;
    if(specs->extensible >= 2) {
        extpresent = per_get_few_bits(pd, 1);
        if(extpresent < 0) goto starved;
    }
    status = SET_aper_decode_presence(pd, optional_count, &presence,
                                      &optional_bits);
    if(status == 1) goto starved;
    if(status) goto failed;
    status = SET_aper_decode_content(opt_codec_ctx, td, st, specs, order,
                                     root_count,
                                     pd, &optional_bits, &rv, pending);
    if(status == 1) goto starved;
    if(status == 2) goto child_failed;
    if(status) goto failed;
    rv = SET_aper_decode_extensions(opt_codec_ctx, td, st, specs, pd,
                                    extpresent, pending);
    if(rv.code == RC_WMORE) goto starved;
    if(rv.code != RC_OK) goto failed;
    if(!SET_aper_roots_populated(td, st, specs)) goto failed;
    for(i = 0; i < td->elements_count; i++) {
        if(pending[i]) {
            rv = SET_aper_resolve_open(opt_codec_ctx, td, st,
                                       &td->elements[i], pending[i]);
            if(rv.code != RC_OK) goto failed;
        }
    }
    rv.code = RC_OK;
    rv.consumed = pd->moved;
    FREEMEM(presence);
    FREEMEM(order);
    SET_aper_free_pending(pending, td->elements_count);
    return rv;

starved:
    rv.code = RC_WMORE;
    rv.consumed = 0;
    goto cleanup;
child_failed:
    goto cleanup;
failed:
    rv.code = RC_FAIL;
    rv.consumed = 0;
cleanup:
    FREEMEM(presence);
    FREEMEM(order);
    SET_aper_free_pending(pending, td->elements_count);
    return rv;
}

/*
 * Purpose: validate all SET members needed by the APER encoder.
 * Source: Generated SET member descriptors and APER encoder operations.
 * Version: 2026-10-30.
 * Parameters: td/sptr describe the value; order gives canonical member indexes.
 * Returns: 0 when each member has valid storage and an available encoder.
 * Errors: Invalid storage, missing mandatory values, or missing encoders return
 *         -1.
 * Author: asn1c maintainers.
 * History: Split from SET_encode_aper to isolate descriptor validation.
 * Example: Called before writing any SET preamble bits.
 */
static int
SET_aper_encode_members_valid(const asn_TYPE_descriptor_t *td,
                              const void *sptr, const unsigned *order,
                              unsigned count) {
    size_t i;

    for(i = 0; i < count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        int present = SET_aper_member_present(td, sptr, index);

        if(present < 0
        || (!(member->flags & ATF_OPEN_TYPE)
            && !member->type->op->aper_encoder)) return -1;
    }
    return 0;
}

/*
 * Purpose: emit the optional-member presence preamble for a SET value.
 * Source: X.691 SET preamble and the existing PER bit writer.
 * Version: 2026-10-30.
 * Parameters: td/sptr identify the value; order gives canonical member order;
 *             po is the APER output stream.
 * Returns: 0 when all presence bits are written, or -1 on invalid data/output.
 * Errors: Invalid member presence and bit-writer failures return -1.
 * Author: asn1c maintainers.
 * History: Split from SET_encode_aper to isolate preamble output.
 * Example: Optional members are represented in canonical SET order.
 */
static int
SET_aper_encode_presence(const asn_TYPE_descriptor_t *td, const void *sptr,
                         const unsigned *order, unsigned count,
                         asn_per_outp_t *po) {
    size_t i;

    for(i = 0; i < count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        int present = SET_aper_member_present(td, sptr, index);

        if(present < 0
        || (member->optional && per_put_few_bits(po, present, 1))) return -1;
    }
    return 0;
}

/*
 * Purpose: encode all present SET members in canonical APER order.
 * Source: X.691 SET component order and generated member callbacks.
 * Version: 2026-10-30.
 * Parameters: td/sptr identify the SET; order gives member indexes; po is the
 *             output stream; er receives the last child encoder result.
 * Returns: 0 on success, or -1 on invalid data or child encoder failure.
 * Errors: Child encoder failures are preserved in er for the caller.
 * Author: asn1c maintainers.
 * History: Split from SET_encode_aper to isolate component output.
 * Example: Called after descriptor validation and presence preamble emission.
 */
static int
SET_aper_encode_content(const asn_TYPE_descriptor_t *td, const void *sptr,
                        const unsigned *order, unsigned count,
                        asn_per_outp_t *po,
                        asn_enc_rval_t *er) {
    size_t i;

    for(i = 0; i < count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        asn_SET_member_view_t view;
        int present = SET_aper_member_present(td, sptr, index);

        if(present < 0) return -1;
        if(!present) continue;
        if(SET_member_view(td, sptr, index, ASN_SET_DIRECT_MEMBER, &view))
            return -1;
        if(member->flags & ATF_OPEN_TYPE) {
            *er = OPEN_TYPE_aper_put(td, sptr, member, po);
        } else if(member->type->op->aper_encoder) {
            *er = member->type->op->aper_encoder(
                member->type, member->encoding_constraints.per_constraints,
                view.value, po);
        } else {
            return -1;
        }
        if(er->encoded == -1) return -1;
    }
    return 0;
}

/*
 * Purpose: determine whether one pointer-backed extension addition is encoded.
 * Source: SET member storage and DEFAULT omission semantics.
 * Version/date: 2026-10-30.
 * Inputs: td/sptr identify the SET; index selects a declared addition.
 * Returns: 1 if encoded, 0 if absent or DEFAULT-valued, -1 on invalid storage.
 * Errors: Malformed member layouts fail closed.
 * Author: asn1c maintainers. History: Added for individual APER additions.
 * Example: An absent optional pointer produces zero.
 */
static int
SET_aper_extension_present(const asn_TYPE_descriptor_t *td, const void *sptr,
                           unsigned index) {
    const asn_TYPE_member_t *member = &td->elements[index];
    asn_SET_member_view_t view;

    if(member->flags & ATF_EXTENSION_GROUP) return SET_group_wire_present(td, sptr, index);
    if(SET_aper_member_valid(td, sptr, index)
    || SET_member_view(td, sptr, index, ASN_SET_DIRECT_MEMBER, &view)) return -1;
    if(!view.present) return 0;
    if(member->default_value_cmp && member->default_value_cmp(view.value) == 0)
        return 0;
    return 1;
}

/*
 * Purpose: validate all individual addition types before writing APER bits.
 * Source: v2 SET extension map and generated APER operations.
 * Version/date: 2026-10-30.
 * Inputs: td/sptr identify the SET; specs supplies declaration-order indexes.
 * Returns: 0 when every addition has usable storage and an encoder, else -1.
 * Errors: Groups, inline additions, and missing callbacks are rejected.
 * Author: asn1c maintainers. History: Added for fail-closed extension support.
 * Example: An absent addition still must have a valid descriptor.
 */
static int
SET_aper_encode_extensions_valid(const asn_TYPE_descriptor_t *td,
                                 const void *sptr,
                                 const asn_SET_specifics_t *specs) {
    unsigned i;

    if(specs->extensible < 2) return 0;
    for(i = 0; i < specs->extension_count; i++) {
        unsigned index = specs->extension_map[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        if(SET_aper_member_valid(td, sptr, index)
        || !member->type->op->aper_encoder
        || SET_aper_extension_present(td, sptr, index) < 0) return -1;
    }
    return 0;
}

/* Parent and member metadata used by an extension OPEN TYPE encoder. */
typedef struct SET_aper_open_adapter_s {
    const asn_TYPE_descriptor_t *parent; /* SET descriptor for selection. */
    const asn_TYPE_member_t *member;     /* Addition being selected. */
} SET_aper_open_adapter_t;

/*
 * Purpose: Encode an inner open envelope using its containing SET selector.
 * Source: OPEN_TYPE_aper_put contract. Version: 2026-10-30.
 * Inputs: td carries adapter metadata; sptr is the parent and po is output.
 * Returns: encoder result. Errors: Invalid selectors and values fail.
 * Author: maintainers. History: Nested extension-addition framing.
 * Example: The outer addition wraps the selector-validated inner encoding.
 */
static asn_enc_rval_t
SET_aper_encode_open_adapter(const asn_TYPE_descriptor_t *td,
                             const asn_per_constraints_t *constraints,
                             const void *sptr, asn_per_outp_t *po) {
    const SET_aper_open_adapter_t *adapter = td->specifics;
    const asn_TYPE_member_t *member = adapter->member;
    (void)constraints;
    if(member->type_selector && member->type->elements_count) {
        asn_type_selector_result_t selected = member->type_selector(adapter->parent, sptr);
        if(selected.presence_index && selected.type_descriptor) {
            if(!member->type->elements || selected.presence_index > member->type->elements_count
            || member->type->elements[selected.presence_index - 1].type != selected.type_descriptor)
                ASN__ENCODE_FAILED;
        }
    }
    return OPEN_TYPE_aper_put(adapter->parent, sptr, member, po);
}

/*
 * Purpose: encode the APER extension map and present open-type additions.
 * Source: X.691 extension addition bitmap and APER open-type helpers.
 * Version/date: 2026-10-30.
 * Inputs: td/sptr/specs identify the value; po receives the extension phase.
 * Returns: 0 on success, -1 for malformed members or output failures.
 * Errors: Open-type encoders and bit writers report failure.
 * Author: asn1c maintainers. History: Added for v2 SET additions.
 * Example: The bitmap bit at i selects extension_map[i].
 */
static int
SET_aper_encode_extensions(const asn_TYPE_descriptor_t *td, const void *sptr,
                           const asn_SET_specifics_t *specs,
                           asn_per_outp_t *po) {
    unsigned i;
    int any_present = 0;

    if(specs->extensible < 2) return 0;
    for(i = 0; i < specs->extension_count; i++) {
        int present = SET_aper_extension_present(td, sptr,
                                                specs->extension_map[i]);
        if(present < 0) return -1;
        any_present |= present;
    }
    if(!any_present) return 0;
    if(!specs->extension_count
    || aper_put_nslength(po, specs->extension_count)) return -1;
    for(i = 0; i < specs->extension_count; i++) {
        int present = SET_aper_extension_present(td, sptr,
                                                specs->extension_map[i]);
        if(present < 0 || per_put_few_bits(po, present, 1)) return -1;
    }
    if(aper_put_align(po) < 0) return -1;
    for(i = 0; i < specs->extension_count; i++) {
        unsigned index = specs->extension_map[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        const void *value = *(const void *const *)((const char *)sptr
                                                    + member->memb_offset);
        int present = SET_aper_extension_present(td, sptr, index);
        if(present < 0) return -1;
        if(present) {
            asn_TYPE_descriptor_t adapter;
            asn_TYPE_operation_t operations;
            SET_aper_open_adapter_t open_adapter;
            const asn_TYPE_descriptor_t *wire_type = member->type;
            if(member->flags & ATF_OPEN_TYPE) {
                adapter = *member->type;
                memset(&operations, 0, sizeof(operations));
                operations.aper_encoder = SET_aper_encode_open_adapter;
                open_adapter.parent = td;
                open_adapter.member = member;
                adapter.op = &operations;
                adapter.specifics = &open_adapter;
                wire_type = &adapter;
                value = sptr;
            } else if(member->flags & ATF_EXTENSION_GROUP) {
                if(SET_group_adapter(td, index, &adapter)) return -1;
                wire_type = &adapter;
            }
            if(aper_open_type_put(wire_type, member->encoding_constraints.per_constraints, value, po)) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: encode APER SET roots and individual version 2 additions.
 * Source: X.691 SET root ordering, extension maps, and APER open types.
 * Version: 2026-10-30.
 * Parameters: td/constraints/sptr/po are the standard APER encoder inputs.
 * Returns: APER encoding result, or failure for invalid values and metadata.
 * Errors: Legacy sentinels, groups, malformed maps, absent mandatory roots,
 *         and child encoder failures are rejected before unsafe access.
 * Author: asn1c maintainers.
 * History: Extended root-only APER support with version 2 additions.
 * Example: Present additions are encoded as declaration-ordered open types.
 */
asn_enc_rval_t
SET_encode_aper(const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, const void *sptr,
                asn_per_outp_t *po) {
    const asn_SET_specifics_t *specs;
    asn_enc_rval_t er = {0, 0, 0};
    unsigned *order = 0;
    unsigned root_count;
    int status;

    (void)constraints;
    if(!sptr || !po || SET_aper_descriptor_valid(td, &specs))
        ASN__ENCODE_FAILED;
    APER_ENCODER_RECURSION_DEPTH_INC();
    if(!SET_aper_layout_valid(td, specs)
    || SET_aper_partition_valid(td, specs)) goto failed_recursive;
    root_count = specs->extensible >= 2 ? specs->root_count : td->elements_count;
    if(SET_aper_canonical_order(td, specs, root_count, &order))
        goto failed_recursive;
    if(SET_aper_encode_members_valid(td, sptr, order, root_count)
    || SET_aper_encode_extensions_valid(td, sptr, specs))
        goto failed_recursive;
    if(specs->extensible >= 2) {
        unsigned i;
        int extpresent = 0; /* state variable: tracks present additions */
        for(i = 0; i < specs->extension_count; i++) {
            int present = SET_aper_extension_present(td, sptr,
                                                     specs->extension_map[i]);
            if(present < 0) goto failed_recursive;
            extpresent |= present;
        }
        if(per_put_few_bits(po, extpresent, 1)) goto failed_recursive;
    }
    if(SET_aper_encode_presence(td, sptr, order, root_count, po))
        goto failed_recursive;
    status = SET_aper_encode_content(td, sptr, order, root_count, po, &er);
    if(!status) status = SET_aper_encode_extensions(td, sptr, specs, po);
    if(status) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
        FREEMEM(order);
        if(er.encoded == -1) return er;
        ASN__ENCODE_FAILED;
    }
    APER_ENCODER_RECURSION_DEPTH_DEC();
    FREEMEM(order);
    ASN__ENCODED_OK(er);

failed_recursive:
    APER_ENCODER_RECURSION_DEPTH_DEC();
    FREEMEM(order);
    ASN__ENCODE_FAILED;
}

#endif /* ASN_DISABLE_APER_SUPPORT */
