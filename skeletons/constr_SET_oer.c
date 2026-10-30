/*
 * Copyright (c) 2026.
 * All rights reserved. Redistribution and modifications are permitted subject
 * to the BSD license.
 */
#include <asn_internal.h>
#include <asn_bit_data.h>
#include <constr_SET.h>
#include <OPEN_TYPE.h>

#ifndef ASN_DISABLE_OER_SUPPORT

/* The SET free path uses this private phase to identify an owned OER map. */
#define SET_OER_PHASE_INITIAL 1000
#define SET_OER_PHASE_COMPLETE 1002

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
    if(specs->extensible || td->elements_count > (size_t)SHRT_MAX / 2)
        return -1;
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
                     const asn_SET_specifics_t *specs, size_t *order_bytes) {
    size_t words;
    size_t presence_bytes;

    *order_bytes = (size_t)td->elements_count * sizeof(unsigned);
    if(td->elements_count
    && *order_bytes / sizeof(unsigned) != (size_t)td->elements_count)
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
                const asn_SET_specifics_t *specs,
                const asn_TYPE_tag2member_t **map, unsigned *count) {
    *map = specs->tag2el_cxer;
    *count = specs->tag2el_cxer_count;
    if(td->elements_count && !*map) return -1;
    if(*count && !*map) return -1;
    if(*count != td->elements_count) return -1;
    return 0;
}

/*
 * Purpose: validate the canonical map as a complete member permutation.
 * Original source: SET_aper_order_from_cxer's canonical map checks.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/map/count describe the ordered map; order/seen are output buffers.
 * Returns: zero for a sorted permutation, otherwise -1.
 * Exceptions: none. History: malformed duplicate member entries are rejected.
 * Example: each CHOICE contributes its minimum possible canonical tag.
 */
static int
SET_oer_map_order(const asn_TYPE_descriptor_t *td,
                  const asn_TYPE_tag2member_t *map, unsigned map_count,
                  unsigned *order, uint8_t *seen) {
    size_t i;
    ber_tlv_tag_t previous_tag = 0;

    for(i = 0; i < map_count; i++) {
        unsigned el_no = map[i].el_no;
        ber_tlv_tag_t tag = map[i].el_tag;

        if(i) {
            int previous_class = BER_TAG_CLASS(previous_tag);
            int current_class = BER_TAG_CLASS(tag);
            ber_tlv_tag_t previous_value = BER_TAG_VALUE(previous_tag);
            ber_tlv_tag_t current_value = BER_TAG_VALUE(tag);
            if(previous_class > current_class
            || (previous_class == current_class
                && previous_value >= current_value))
                return -1;
        }
        previous_tag = tag;
        if(el_no >= td->elements_count || seen[el_no]) return -1;
        seen[el_no] = 1;
        order[i] = el_no;
    }
    return 0;
}

/*
 * Purpose: validate member descriptors and count OPTIONAL root members.
 * Original source: final member pass in SET_oer_build_order.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td/specs/order identify members; optional_count receives the count.
 * Returns: zero when all direct member storage spans are valid, otherwise -1.
 * Exceptions: none. History: validates before any OER access to member storage;
 * table-selected open types need deferred selector resolution and are rejected.
 * Example: an inline field extending past the SET structure is rejected.
 */
static int
SET_oer_validate_members(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs,
                         const unsigned *order, size_t *optional_count) {
    size_t i;

    *optional_count = 0;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[order[i]];
        size_t offset = member->memb_offset;

        if(!member->type || !member->type->op
        || (member->flags & (ATF_EXTENSION_GROUP | ATF_OPEN_TYPE))
        || offset >= specs->struct_size
        || ((member->flags & ATF_POINTER)
            && sizeof(void *) > specs->struct_size - offset))
            return -1;
        if(member->optional) (*optional_count)++;
    }
    return 0;
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
    unsigned *order = 0;
    uint8_t *seen = 0;
    size_t order_bytes;

    if(!td || !specs || !order_out || !optional_count) return -1;
    if(SET_oer_descriptor_valid(td, specs)) return -1;
    if(SET_oer_layout_valid(td, specs, &order_bytes)) return -1;
    if(SET_oer_get_map(td, specs, &map, &map_count)) return -1;
    if(td->elements_count) {
        order = (unsigned *)MALLOC(order_bytes);
        seen = (uint8_t *)CALLOC(td->elements_count, sizeof(*seen));
        if(!order || !seen) goto failed;
    }
    if(SET_oer_map_order(td, map, map_count, order, seen)) goto failed;
    if(SET_oer_validate_members(td, specs, order, optional_count)) goto failed;

    FREEMEM(seen);
    *order_out = order;
    return 0;

failed:
    FREEMEM(seen);
    FREEMEM(order);
    return -1;
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
SET_oer_members_valid(const asn_TYPE_descriptor_t *td, const void *st,
                      const unsigned *order) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
        asn_SET_member_view_t view;
        if(SET_member_view(td, st, order[i], ASN_SET_DIRECT_MEMBER, &view))
            return -1;
    }
    return 0;
}

/*
 * Purpose: validate saved OER parser context before resuming a SET decode.
 * Source: SET OER phase markers, canonical member position, and bit map.
 * Version: 2026-10-30.
 * Parameters: td/order/optional_count describe the SET; ctx is saved state.
 * Returns: nonzero when phase, position, and optional-bit count agree.
 * Errors: negative or out-of-range state and inconsistent ownership are bad.
 * Author: asn1c maintainers.
 * History: Added to reject corrupted state before indexing members or bits.
 * Example: a suspended optional member records one consumed presence bit.
 */
static int
SET_oer_context_valid(const asn_TYPE_descriptor_t *td,
                      const unsigned *order, size_t optional_count,
                      const asn_struct_ctx_t *ctx) {
    size_t position;
    size_t optional_seen = 0;
    size_t i;
    int pending;

    if(ctx->phase == SET_OER_PHASE_INITIAL)
        return !ctx->ptr && ctx->step == 0 && ctx->context == 0;
    if(ctx->phase != ASN_SET_OER_PHASE_MEMBERS || ctx->step < 0
    || ctx->context < 0 || (size_t)ctx->context > optional_count
    || ((optional_count != 0) != (ctx->ptr != 0)))
        return 0;

    position = (unsigned short)ctx->step >> 1;
    pending = ctx->step & 1;
    if(position > td->elements_count
    || (position == td->elements_count && pending))
        return 0;
    for(i = 0; i < position; i++) {
        if(td->elements[order[i]].optional) optional_seen++;
    }
    if(pending && position < td->elements_count
    && td->elements[order[position]].optional)
        optional_seen++;
    return optional_seen == (size_t)ctx->context;
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
    if(SET_oer_members_valid(td, st, order)) return -1;
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
    if(ctx->phase == SET_OER_PHASE_COMPLETE) return -1;
    if(ctx->phase != 0 && ctx->phase != SET_OER_PHASE_INITIAL
    && ctx->phase != ASN_SET_OER_PHASE_MEMBERS) return -1;
    if(ctx->phase == 0) {
        if(ctx->ptr) return -1;
        ctx->phase = SET_OER_PHASE_INITIAL;
        ctx->step = 0;
        ctx->context = 0;
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
SET_oer_read_preamble(asn_struct_ctx_t *ctx, size_t optional_count,
                      const char **ptr, size_t *size, size_t *consumed) {
    size_t preamble_bytes;

    if(ctx->phase != SET_OER_PHASE_INITIAL) return RC_OK;
    if(ctx->ptr) return RC_FAIL;
    preamble_bytes = optional_count / 8 + (optional_count % 8 != 0);
    if(preamble_bytes > *size) return RC_WMORE;
    if(optional_count && (optional_count & 7)) {
        unsigned unused = (unsigned)(8 - (optional_count & 7));
        uint8_t last = (uint8_t)(*ptr)[preamble_bytes - 1];
        if(last & ((1u << unused) - 1u)) return RC_FAIL;
    }
    if(optional_count) {
        asn_bit_data_t *preamble = asn_bit_data_new_contiguous(
            *ptr, optional_count);
        if(!preamble) return RC_FAIL;
        ctx->ptr = preamble;
        *consumed += preamble_bytes;
        *ptr += preamble_bytes;
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
    status = SET_oer_decode_member_value(codec, td, st, member, member_ptr,
                                         ptr, size, consumed, rval);
    if(status != RC_OK) return status;
    ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
    ctx->step = (short)((position + 1) << 1);
    return RC_OK;
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
SET_oer_finish_decode(const asn_TYPE_descriptor_t *td, void *st,
                      asn_struct_ctx_t *ctx, size_t optional_count) {
    if(ctx->context != (int)optional_count || !_SET_is_populated(td, st))
        return -1;
    if(ctx->ptr) FREEMEM(ctx->ptr);
    ctx->ptr = 0;
    ctx->phase = SET_OER_PHASE_COMPLETE;
    ctx->step = 0;
    ctx->context = 0;
    return 0;
}

/*
 * Purpose: incrementally decode a non-extensible SET using canonical OER.
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
    if(SET_oer_prepare_decode(td, specs, struct_ptr, order, optional_count,
                             &ctx)) {
        st = *struct_ptr;
        goto done;
    }
    st = *struct_ptr;

    status = SET_oer_read_preamble(ctx, optional_count, &ptr, &size,
                                   &consumed);
    if(status == RC_WMORE) rval.code = RC_WMORE;
    if(status != RC_OK) goto done;

    while(((unsigned short)ctx->step >> 1) < td->elements_count) {
        status = SET_oer_decode_next_member(
            opt_codec_ctx, td, specs, st, order, ctx, &ptr, &size,
            &consumed, &rval);
        if(status == RC_WMORE) goto done;
        if(status != RC_OK) {
            rval.code = RC_FAIL;
            goto done;
        }
    }
    rval.code = RC_FAIL;
    if(SET_oer_finish_decode(td, st, ctx, optional_count)) goto done;
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
                        const unsigned *order, uint8_t *present) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
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
                       size_t optional_count,
                       asn_app_consume_bytes_f *cb, void *app_key,
                       size_t *computed_size) {
    asn_bit_outp_t preamble;
    size_t i;
    int ret;

    if(!optional_count) return 0;
    memset(&preamble, 0, sizeof(preamble));
    preamble.output = cb;
    preamble.op_key = app_key;
    for(i = 0; i < td->elements_count; i++) {
        if(td->elements[order[i]].optional) {
            ret = asn_put_few_bits(&preamble, present[i], 1);
            if(ret < 0) return -1;
        }
    }
    ret = asn_put_aligned_flush(&preamble);
    if(ret < 0) return -1;
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
                       asn_app_consume_bytes_f *cb, void *app_key,
                       size_t *computed_size) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
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
        if(child.encoded < 0
        || (size_t)child.encoded > (size_t)SSIZE_MAX - *computed_size)
            return -1;
        *computed_size += (size_t)child.encoded;
    }
    return 0;
}

/*
 * Purpose: encode a non-extensible SET using canonical OER.
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
    size_t optional_count = 0;
    size_t computed_size = 0;
    asn_enc_rval_t er = {0, 0, 0};

    (void)constraints;
    if(!td || !td->specifics || !td->op || td->op->kind != ASN_KIND_SET
    || !sptr || !cb) ASN__ENCODE_FAILED;
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(SET_oer_build_order(td, specs, &order, &optional_count))
        ASN__ENCODE_FAILED;
    if(SET_oer_members_valid(td, sptr, order)) {
        FREEMEM(order);
        ASN__ENCODE_FAILED;
    }
    OER_ENCODER_RECURSION_DEPTH_INC();

    if(td->elements_count) {
        present = (uint8_t *)CALLOC(td->elements_count, sizeof(*present));
        if(!present) goto failed;
    }
    if(SET_oer_encode_presence(td, sptr, order, present)) goto failed;
    if(SET_oer_encode_preamble(td, order, present, optional_count, cb,
                               app_key, &computed_size))
        goto failed;
    if(SET_oer_encode_members(td, sptr, order, present, cb, app_key,
                              &computed_size))
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
