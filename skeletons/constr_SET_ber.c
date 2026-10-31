/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <constr_CHOICE.h>
#include <OPEN_TYPE.h>

/*
 * Number of bytes left for this structure.
 * (ctx->left) indicates the number of bytes _transferred_ for the structure.
 * (size) contains the number of bytes in the buffer passed.
 */
#define LEFT ((size<(size_t)ctx->left)?size:(size_t)ctx->left)

/*
 * If the subprocessor function returns with an indication that it wants
 * more data, it may well be a fatal decoding problem, because the
 * size is constrained by the <TLV>'s L, even if the buffer size allows
 * reading more data.
 * For example, consider the buffer containing the following TLVs:
 * <T:5><L:1><V> <T:6>...
 * The TLV length clearly indicates that one byte is expected in V, but
 * if the V processor returns with "want more data" even if the buffer
 * contains way more data than the V processor have seen.
 */
#define SIZE_VIOLATION (ctx->left >= 0 && (size_t)ctx->left <= size)

/*
 * This macro "eats" the part of the buffer which is definitely "consumed",
 * i.e. was correctly converted into local representation or rightfully skipped.
 */
#undef ADVANCE
#define ADVANCE(num_bytes)                \
    do {                                  \
        size_t num = num_bytes;           \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        if(ctx->left >= 0)                \
            ctx->left -= num;             \
        consumed_myself += num;           \
    } while(0)

/*
 * Switch to the next phase of parsing.
 */
#undef NEXT_PHASE
#define NEXT_PHASE(ctx)  \
    do {                 \
        ctx->phase++;    \
        ctx->step = 0;   \
    } while(0)

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

/*
 * Tags are canonically sorted in the tag2element map.
 */
static int
_t2e_cmp(const void *ap, const void *bp) {
    const asn_TYPE_tag2member_t *a = (const asn_TYPE_tag2member_t *)ap;
    const asn_TYPE_tag2member_t *b = (const asn_TYPE_tag2member_t *)bp;

    int a_class = BER_TAG_CLASS(a->el_tag);
    int b_class = BER_TAG_CLASS(b->el_tag);

    if(a_class == b_class) {
        ber_tlv_tag_t a_value = BER_TAG_VALUE(a->el_tag);
        ber_tlv_tag_t b_value = BER_TAG_VALUE(b->el_tag);

        if(a_value == b_value)
            return 0;
        else if(a_value < b_value)
            return -1;
        else
            return 1;
    } else if(a_class < b_class) {
        return -1;
    } else {
        return 1;
    }
}

/*
 * Purpose: resolve a BER tag to one leaf of a synthetic SET group.
 * Source: The group's compiler-generated SET tag-to-member table.
 * Version: 2026-10-22.
 * Parameters: td is the group descriptor; tag is the BER tag; leaf gets index.
 * Returns: 1 for a match, 0 for no matching leaf, -1 for malformed metadata.
 * Errors: invalid table entries or non-SET descriptors return -1.
 * Author: asn1c maintainers.
 * History: Added to route flat SET extension-group tags to leaf storage.
 * Example: a child's context-specific tag resolves to its group leaf index.
 */
static int
_SET_find_group_leaf(const asn_TYPE_descriptor_t *td, ber_tlv_tag_t tag,
		     unsigned *leaf) {
	const asn_SET_specifics_t *specs;
	asn_TYPE_tag2member_t key;
	const asn_TYPE_tag2member_t *match;

	if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics
	|| !td->elements || !td->elements_count) return -1;
	specs = (const asn_SET_specifics_t *)td->specifics;
	if(!specs->tag2el || !specs->tag2el_count) return -1;
	key.el_tag = tag;
	match = (const asn_TYPE_tag2member_t *)bsearch(&key, specs->tag2el,
		specs->tag2el_count, sizeof(specs->tag2el[0]), _t2e_cmp);
	if(!match) return 0;
	if(match->el_no >= td->elements_count) return -1;
	*leaf = match->el_no;
	return 1;
}

/*
 * Purpose: resolve one parent BER tag to an ordinary member or group leaf.
 * Source: Parent and synthetic SET tag-to-member tables.
 * Version: 2026-10-22.
 * Parameters: td/st identify the SET; tag is the current TLV tag; indexes get
 *             the selected parent slot and either a leaf index or sentinel.
 * Returns: 1 for a match, 0 for no match, -1 for invalid descriptors.
 * Errors: malformed indexes, group layouts, or tag tables return -1.
 * Author: asn1c maintainers.
 * History: Added to keep transparent routing separate from the BER state loop.
 * Example: a child tag maps through the parent group slot to its group leaf.
 */
static int
_SET_ber_resolve_tag(const asn_TYPE_descriptor_t *td, const void *st,
                     const asn_SET_specifics_t *specs, ber_tlv_tag_t tag,
                     unsigned *outer, unsigned *child) {
    asn_TYPE_tag2member_t key;
    const asn_TYPE_tag2member_t *match;
    asn_SET_member_view_t view;
    int result;

    if(specs->tag2el_count && !specs->tag2el) return -1;
    key.el_tag = tag;
    match = specs->tag2el_count
        ? (const asn_TYPE_tag2member_t *)bsearch(&key, specs->tag2el,
              specs->tag2el_count, sizeof(specs->tag2el[0]), _t2e_cmp)
        : 0;
    if(!match) return 0;
    if(match->el_no >= td->elements_count) return -1;
    *outer = match->el_no;
    *child = ASN_SET_DIRECT_MEMBER;
    if(!(td->elements[*outer].flags & ATF_EXTENSION_GROUP)) return 1;
    result = _SET_find_group_leaf(td->elements[*outer].type, tag, child);
    if(result != 1
    || SET_member_view(td, st, *outer, *child, &view) != 0) return -1;
    return 1;
}

/*
 * Purpose: prepare one selected SET member's storage for BER decoding.
 * Source: SET member offsets, group storage, and presence maps.
 * Version: 2026-10-22.
 * Parameters: td/st/outer/child identify the selected leaf; ctx holds a saved
 *             group child index; view and pointer outputs receive decoder data.
 * Returns: 0 when ready, -1 for duplicates, invalid storage, or allocation.
 * Errors: malformed descriptors and repeated leaves are rejected.
 * Author: asn1c maintainers.
 * History: Added to keep leaf allocation and duplicate checks out of BER loop.
 * Example: prepare group leaf zero, allocating its group object when needed.
 */
static int
_SET_ber_prepare_member(const asn_TYPE_descriptor_t *td, void *st,
                        unsigned outer, unsigned child,
                        asn_struct_ctx_t *ctx, asn_SET_member_view_t *view,
                        void **member_ptr, void ***member_ptr2, int mode) {
    const asn_TYPE_member_t *outer_member = &td->elements[outer];
    int is_group = (outer_member->flags & ATF_EXTENSION_GROUP) != 0;
    void *owner = st;

    if(is_group) {
        void **group_slot;
        if(ctx->context <= 0 || (unsigned)(ctx->context - 1)
           != child || child >= outer_member->type->elements_count)
            return -1;
        if(SET_member_view(td, st, outer, child, view) != 0) return -1;
        group_slot = (void **)((char *)st + outer_member->memb_offset);
        if(!*group_slot) {
            *group_slot = CALLOC(1, view->owner_specs->struct_size);
            if(!*group_slot) return -1;
        }
        owner = *group_slot;
    } else if(child != ASN_SET_DIRECT_MEMBER || ctx->context != 0) {
        return -1;
    }
    if(SET_member_view(td, st, outer, child, view) != 0) return -1;
    if(mode != 2 && ASN_SET_ISPRESENT2((char *)owner
                          + view->owner_specs->pres_offset,
                          view->owner_index)) return -1;
    if(view->member->flags & ATF_POINTER) {
        *member_ptr2 = (void **)((char *)owner
                                 + view->member->memb_offset);
    } else {
        *member_ptr = (char *)owner + view->member->memb_offset;
        *member_ptr2 = member_ptr;
    }
    return 0;
}

/*
 * Purpose: mark one successfully decoded leaf and its containing group slot.
 * Source: Parent and child SET presence maps.
 * Version: 2026-10-22.
 * Parameters: td/st identify the parent; outer selects the member; view is the
 *             resolved leaf; ctx is the parent decoder context.
 * Returns: not applicable; updates presence bits and the saved group selector.
 * Errors: callers provide a previously validated view.
 * Author: asn1c maintainers.
 * History: Added with transparent SET group BER routing.
 * Example: marking a group leaf also records that its parent group was seen.
 */
static void
_SET_ber_mark_member(const asn_TYPE_descriptor_t *td, void *st,
                     unsigned outer, const asn_SET_member_view_t *view,
                     asn_struct_ctx_t *ctx) {
    const asn_SET_specifics_t *specs =
        (const asn_SET_specifics_t *)td->specifics;
    void *owner = st;

    if(td->elements[outer].flags & ATF_EXTENSION_GROUP)
        owner = *(void **)((char *)st + td->elements[outer].memb_offset);
    ASN_SET_MKPRESENT((char *)owner + view->owner_specs->pres_offset,
                      view->owner_index);
    if(td->elements[outer].flags & ATF_EXTENSION_GROUP)
        ASN_SET_MKPRESENT((char *)st + specs->pres_offset, outer);
    ctx->context = 0;
    ctx->step = 0;
}

/*
 * Purpose: consume bytes already accepted by the SET decoder.
 * Source: BER SET length accounting and decoder input spans.
 * Version: 2026-10-22.
 * Parameters: ctx tracks the enclosing length; ptr/size track input; amount is
 *             the consumed byte count.
 * Returns: not applicable; updates input and the definite-length remainder.
 * Errors: callers must ensure amount does not exceed the available span.
 * Author: asn1c maintainers.
 * History: Added for bounded BER decoder step helpers.
 * Example: consuming one skipped TLV advances input and decrements ctx->left.
 */
static void
_SET_ber_consume(asn_struct_ctx_t *ctx, const void **ptr, size_t *size,
                 size_t amount) {
    *ptr = (const char *)*ptr + amount;
    *size -= amount;
    if(ctx->left >= 0) ctx->left -= amount;
}

/*
 * Purpose: inspect the next BER body tag without consuming a member.
 * Source: BER tag fetch and indefinite-length SET framing rules.
 * Version: 2026-10-22.
 * Parameters: ctx tracks the SET; ptr/size are remaining input; tag/tag_len
 *             receive the parsed identifier when available.
 * Returns: 1 for a tag, 2 for the indefinite terminator, 0 for more input,
 *          and -1 for malformed or truncated definite-length input.
 * Errors: malformed tags and incomplete definite-length bodies fail.
 * Author: asn1c maintainers.
 * History: Split tag framing from the BER SET route selector.
 * Example: an indefinite 00 00 pair returns terminator status two.
 */
static int
_SET_ber_current_tag(const asn_struct_ctx_t *ctx, const void *ptr,
                     size_t size, ber_tlv_tag_t *tag, ssize_t *tag_len) {
    size_t available = ctx->left >= 0 && (size_t)ctx->left < size
        ? (size_t)ctx->left : size;

    *tag_len = ber_fetch_tag(ptr, available, tag);
    if(*tag_len == 0)
        return ctx->left >= 0 && (size_t)ctx->left <= size ? -1 : 0;
    if(*tag_len < 0) return -1;
    if(ctx->left < 0 && available && ((const uint8_t *)ptr)[0] == 0) {
        if(available < 2)
            return ctx->left >= 0 && (size_t)ctx->left <= size ? -1 : 0;
        if(((const uint8_t *)ptr)[1] == 0) return 2;
    }
    return 1;
}

/*
 * Purpose: skip one unknown extension TLV from a SET body.
 * Source: BER length skipper and the SET's remaining input boundary.
 * Version: 2026-10-22.
 * Parameters: codec/ctx identify parsing; ptr/size are mutable bounded input;
 *             tag_len is the parsed identifier length.
 * Returns: RC_OK after a complete skip, RC_WMORE for incomplete input,
 *          RC_FAIL for invalid or truncated TLVs; consumed reports progress.
 * Errors: a skipped length beyond parent remaining bytes is not accepted.
 * Author: asn1c maintainers.
 * History: Isolated unknown-extension skipping from tag routing.
 * Example: an extensible SET advances over an unknown constructed TLV.
 */
static asn_dec_rval_t
_SET_ber_skip_unknown(const asn_codec_ctx_t *codec, asn_struct_ctx_t *ctx,
                      const void **ptr, size_t *size, ssize_t tag_len) {
    asn_dec_rval_t rval = {RC_FAIL, 0};
    size_t available = ctx->left >= 0 && (size_t)ctx->left < *size
        ? (size_t)ctx->left : *size;
    ssize_t length = ber_skip_length(codec, BER_TLV_CONSTRUCTED(*ptr),
                      (const char *)*ptr + tag_len,
                      available - (size_t)tag_len);

    if(length == 0) {
        rval.code = ctx->left >= 0 && (size_t)ctx->left <= *size
            ? RC_FAIL : RC_WMORE;
        return rval;
    }
    if(length < 0) return rval;
    _SET_ber_consume(ctx, ptr, size, (size_t)tag_len + (size_t)length);
    rval.code = RC_OK;
    rval.consumed = (size_t)tag_len + (size_t)length;
    return rval;
}

/*
 * Purpose: resolve a parsed BER tag to a direct member or group leaf.
 * Source: Parent and synthetic-group tag maps.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/specs/ctx identify the SET; ptr/size contain the tag;
 *             tag/tag_len are parsed; outer/child/selected/body_end receive route.
 * Returns: decoder result; consumed counts bytes only for skipped extensions.
 * Errors: invalid tags, maps, or unexpected non-extension fields fail.
 * Author: asn1c maintainers.
 * History: Separated parsed-tag routing from BER input framing.
 * Example: a leaf tag routes to its group while preserving the flat wire form.
 */
static asn_dec_rval_t
_SET_ber_route_tag(const asn_codec_ctx_t *codec,
                   const asn_TYPE_descriptor_t *td, const void *st,
                   const asn_SET_specifics_t *specs, asn_struct_ctx_t *ctx,
                   const void **ptr, size_t *size, ber_tlv_tag_t tag,
                   ssize_t tag_len, unsigned *outer, unsigned *child,
                   int *selected) {
    asn_dec_rval_t rval = {RC_FAIL, 0};
    int resolved = _SET_ber_resolve_tag(td, st, specs, tag, outer, child);

    if(resolved < 0) return rval;
    if(resolved == 0) {
        if(!specs->extensible) return rval;
        return _SET_ber_skip_unknown(codec, ctx, ptr, size, tag_len);
    }
    if(*outer > (SHRT_MAX - 1) / 2
    || (*child != ASN_SET_DIRECT_MEMBER && *child >= INT_MAX)) return rval;
    ctx->context = *child == ASN_SET_DIRECT_MEMBER ? 0 : (int)*child + 1;
    /* state variable: selected group leaf index plus one. */
    ctx->step = (short)((*outer << 1) + 1);
    *selected = 1;
    rval.code = RC_OK;
    return rval;
}

/*
 * Purpose: restore a previously selected member after a BER input suspension.
 * Source: SET context step and group-leaf selector state.
 * Version: 2026-10-22.
 * Parameters: td/ctx identify saved state; outer/child receive the selection.
 * Returns: 1 for valid selection or 0 for invalid state.
 * Errors: invalid outer indexes and missing group selectors return zero.
 * Author: asn1c maintainers.
 * History: Added to bound resumable BER group member routing.
 * Example: an odd context step restores its parent and child indexes.
 */
static int
_SET_ber_restore_selection(const asn_TYPE_descriptor_t *td,
                           const asn_struct_ctx_t *ctx, unsigned *outer,
                           unsigned *child) {
    if(ctx->step < 0 || (size_t)(ctx->step >> 1) >= td->elements_count)
        return 0;
    *outer = (unsigned)(ctx->step >> 1);
    if(td->elements[*outer].flags & ATF_EXTENSION_GROUP) {
        if(ctx->context <= 0) return 0;
        *child = (unsigned)(ctx->context - 1);
    } else {
        if(ctx->context != 0) return 0;
        *child = ASN_SET_DIRECT_MEMBER;
    }
    return 1;
}

/*
 * Purpose: select the next BER SET member or report body completion.
 * Source: SET context, tag framing, and one-level group tag maps.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/specs/ctx identify the SET; ptr/size are input;
 *             outer/child receive a route; selected/body_end report the event.
 * Returns: RC_OK for a route/progress/end, RC_WMORE for more input, RC_FAIL on
 *          malformed tags or descriptors; consumed reports skipped bytes.
 * Errors: malformed tags, unknown non-extension tags, and map errors fail.
 * Author: asn1c maintainers.
 * History: Extracted BER tag resolution from SET_decode_ber.
 * Example: an interleaved group tag resolves to its child and parent indexes.
 */
static asn_dec_rval_t
_SET_ber_select_next(const asn_codec_ctx_t *codec,
                     const asn_TYPE_descriptor_t *td, const void *st,
                     const asn_SET_specifics_t *specs, asn_struct_ctx_t *ctx,
                     const void **ptr, size_t *size, unsigned *outer,
                     unsigned *child, int *selected, int *body_end) {
    asn_dec_rval_t rval = {RC_OK, 0};
    ber_tlv_tag_t tag;
    ssize_t tag_len;
    int tag_status;

    *selected = 0;
    *body_end = 0;
    if(ctx->step & 1) {
        if(!_SET_ber_restore_selection(td, ctx, outer, child)) {
            rval.code = RC_FAIL;
            return rval;
        }
        *selected = 1;
        return rval;
    }
    if(ctx->left == 0) {
        *body_end = 1;
        return rval;
    }
    tag_status = _SET_ber_current_tag(ctx, *ptr, *size, &tag, &tag_len);
    if(tag_status <= 0) {
        rval.code = tag_status == 0 ? RC_WMORE : RC_FAIL;
        return rval;
    }
    if(tag_status == 2) {
        *body_end = 1;
        return rval;
    }
    return _SET_ber_route_tag(codec, td, st, specs, ctx, ptr, size, tag,
                              tag_len, outer, child, selected);
}

/*
 * Purpose: Validate a BER table selection and, when encoding, its active arm.
 * Source: OPEN TYPE selector contract. Version: 2026-10-30.
 * Inputs: td/st identify the parent; member is open; encoding checks presence.
 * Returns: selected descriptor and index, or an empty result for invalid data.
 * Errors: missing or inconsistent selectors fail. Author: maintainers.
 * History: Added for parent-aware SET BER dispatch.
 * Example: A selector for arm one rejects an active arm two.
 */
static asn_type_selector_result_t
_SET_ber_open_selection(const asn_TYPE_descriptor_t *td, const void *st,
                        const asn_TYPE_member_t *member, int encoding) {
    asn_type_selector_result_t selected = {0, 0};
    const void *value;
    if(!member->type || !member->type_selector) return selected;
    selected = member->type_selector(td, st);
    if(!selected.presence_index || !selected.type_descriptor || !selected.type_descriptor->op
    || (encoding ? !selected.type_descriptor->op->der_encoder : !selected.type_descriptor->op->ber_decoder))
        goto invalid;
    if(!member->type->elements_count) {
        if(member->type != selected.type_descriptor) goto invalid;
        return selected;
    }
    if(!member->type->elements || selected.presence_index > member->type->elements_count
    || member->type->elements[selected.presence_index - 1].type != selected.type_descriptor) goto invalid;
    if(!encoding) return selected;
    value = (const char *)st + member->memb_offset;
    if(member->flags & ATF_POINTER) value = *(const void *const *)value;
    if(value && CHOICE_variant_get_presence(member->type, value) == selected.presence_index) return selected;
invalid:
    selected.presence_index = 0;
    selected.type_descriptor = 0;
    return selected;
}

/*
 * Purpose: Decode a selected CHOICE arm in transactionally owned storage.
 * Source: BER member and CHOICE lifecycle contracts. Version: 2026-10-30.
 * Inputs: codec/member/selected describe the arm; target receives the wrapper;
 * ptr/size hold its complete TLV. Returns: decoder status and consumption.
 * Errors: Invalid payloads and allocation failures fail without leaking storage.
 * Author: maintainers. History: Added for SET selected-type decoding.
 * Example: An inline arm failure never frees an interior wrapper address.
 */
static asn_dec_rval_t
_SET_ber_open_wrapper(const asn_codec_ctx_t *codec, const asn_TYPE_member_t *member,
                      asn_type_selector_result_t selected, void **target,
                      const void *ptr, size_t size) {
    const asn_CHOICE_specifics_t *specs = member->type->specifics;
    const asn_TYPE_member_t *arm = &member->type->elements[selected.presence_index - 1];
    asn_dec_rval_t result = {RC_FAIL, 0};
    void *wrapper;
    void *inner;
    if((member->flags & ATF_POINTER) ? *target != NULL
       : CHOICE_variant_get_presence(member->type, *target) != 0) return result;
    wrapper = CALLOC(1, specs->struct_size);
    if(!wrapper) return result;
    inner = (arm->flags & ATF_POINTER) ? 0 : (char *)wrapper + arm->memb_offset;
    result = selected.type_descriptor->op->ber_decoder(codec, selected.type_descriptor,
                                                       &inner, ptr, size, member->tag_mode);
    if(result.code == RC_OK && result.consumed == size
    && !CHOICE_variant_set_presence(member->type, wrapper, selected.presence_index)) {
        if(arm->flags & ATF_POINTER) *(void **)((char *)wrapper + arm->memb_offset) = inner;
        if(member->flags & ATF_POINTER) {
            if(*target) { ASN_STRUCT_FREE(*member->type, wrapper); result.code = RC_FAIL; return result; }
            *target = wrapper;
        } else {
            memcpy(*target, wrapper, specs->struct_size);
            FREEMEM(wrapper);
        }
        return result;
    }
    if(inner) {
        if(arm->flags & ATF_POINTER) ASN_STRUCT_FREE(*selected.type_descriptor, inner);
        else ASN_STRUCT_RESET(*selected.type_descriptor, inner);
    }
    FREEMEM(wrapper);
    result.code = RC_FAIL;
    result.consumed = 0;
    return result;
}

/*
 * Purpose: Decode a selected direct or CHOICE-wrapped SET open member.
 * Source: BER selected-value contracts. Version: 2026-10-30.
 * Inputs: codec/td/st/member/target describe output; ptr/size provide one TLV.
 * Returns: decoder result. Errors: invalid selections and incomplete values fail.
 * Author: maintainers. History: Added transactional SET open decoding.
 * Example: A sibling selected after the open TLV chooses its concrete type.
 */
static asn_dec_rval_t
_SET_ber_open_decode(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                     void *st, const asn_TYPE_member_t *member, void **target,
                     const void *ptr, size_t size) {
    asn_type_selector_result_t selected = _SET_ber_open_selection(td, st, member, 0);
    asn_dec_rval_t result = {RC_FAIL, 0};
    void *inner;
    if(!selected.type_descriptor) return result;
    if(member->type->elements_count)
        return _SET_ber_open_wrapper(codec, member, selected, target, ptr, size);
    if((member->flags & ATF_POINTER) && *target) return result;
    inner = (member->flags & ATF_POINTER) ? 0 : *target;
    result = selected.type_descriptor->op->ber_decoder(codec, selected.type_descriptor,
                                                       &inner, ptr, size, member->tag_mode);
    if(result.code == RC_OK && result.consumed == size) {
        if(member->flags & ATF_POINTER) *target = inner;
        return result;
    }
    if(inner) {
        if(member->flags & ATF_POINTER) ASN_STRUCT_FREE(*selected.type_descriptor, inner);
        else ASN_STRUCT_RESET(*selected.type_descriptor, inner);
    }
    result.code = RC_FAIL;
    result.consumed = 0;
    return result;
}

/*
 * Purpose: decode one already-selected SET leaf using its bounded input span.
 * Source: Member BER operation, storage view, and duplicate presence checks.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/ctx identify state; outer/child select leaf;
 *             ptr/size are mutable input and rval reports decoder progress.
 * Returns: child result with consumed bytes; malformed descriptors fail.
 * Errors: duplicates, missing decoders, over-consume, and child errors fail.
 * Author: asn1c maintainers.
 * History: Extracted leaf invocation from the BER SET state loop.
 * Example: a resumed group leaf receives only the parent's remaining bytes.
 */
static asn_dec_rval_t
_SET_ber_decode_leaf(const asn_codec_ctx_t *codec,
                     const asn_TYPE_descriptor_t *td, void *st,
                     asn_struct_ctx_t *ctx, unsigned outer, unsigned child,
                     const void **ptr, size_t *size, int mode) {
    asn_dec_rval_t rval = {RC_FAIL, 0};
    asn_SET_member_view_t view;
    void *member_ptr;
    void **member_ptr2;
    size_t available = ctx->left >= 0 && (size_t)ctx->left < *size
        ? (size_t)ctx->left : *size;

    if(_SET_ber_prepare_member(td, st, outer, child, ctx, &view, &member_ptr,
                               &member_ptr2, mode) != 0) return rval;
    if((mode == 1 && (view.member->flags & ATF_OPEN_TYPE))
    || (mode == 2 && !(view.member->flags & ATF_OPEN_TYPE))) {
        ber_tlv_tag_t tag;
        ssize_t tag_len = ber_fetch_tag(*ptr, available, &tag);
        if(tag_len <= 0) return rval;
        rval = _SET_ber_skip_unknown(codec, ctx, ptr, size, tag_len);
        if(rval.code == RC_OK) _SET_ber_mark_member(td, st, outer, &view, ctx);
        return rval;
    }
    if(view.member->flags & ATF_OPEN_TYPE) {
        ber_tlv_tag_t tag;
        ssize_t tag_len = ber_fetch_tag(*ptr, available, &tag);
        ssize_t length;
        if(child != ASN_SET_DIRECT_MEMBER || tag_len <= 0) return rval;
        length = ber_skip_length(codec, BER_TLV_CONSTRUCTED(*ptr),
                                 (const char *)*ptr + tag_len, available - (size_t)tag_len);
        if(length <= 0 || (size_t)length > available - (size_t)tag_len) return rval;
        rval = _SET_ber_open_decode(codec, td, st, view.member, member_ptr2,
                                    *ptr, (size_t)tag_len + (size_t)length);
    } else {
        if(!view.member->type->op || !view.member->type->op->ber_decoder) return rval;
        rval = view.member->type->op->ber_decoder(codec, view.member->type,
                      member_ptr2, *ptr, available, view.member->tag_mode);
    }
    if(rval.consumed > available) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }
    if(rval.code == RC_WMORE) {
        if(ctx->left >= 0 && (size_t)ctx->left <= *size) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    } else if(rval.code == RC_OK) {
        _SET_ber_mark_member(td, st, outer, &view, ctx);
    } else {
        rval.consumed = 0;
        return rval;
    }
    _SET_ber_consume(ctx, ptr, size, rval.consumed);
    return rval;
}

/*
 * Purpose: perform one synchronization or leaf-decode step in a BER SET body.
 * Source: BER tag selection and SET leaf decoding helpers.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/specs/ctx identify the body; ptr/size are input;
 *             body_end reports a definite end or indefinite terminator.
 * Returns: RC_OK for progress/end, RC_WMORE for incomplete input, RC_FAIL on
 *          malformed data; consumed counts all bytes advanced in this step.
 * Errors: propagated from tag resolution and the selected leaf decoder.
 * Author: asn1c maintainers.
 * History: Added to keep SET_decode_ber as a bounded phase coordinator.
 * Example: a skipped extension consumes bytes and requests another step.
 */
static asn_dec_rval_t
_SET_ber_decode_step(const asn_codec_ctx_t *codec,
                     const asn_TYPE_descriptor_t *td, void *st,
                     const asn_SET_specifics_t *specs, asn_struct_ctx_t *ctx,
                     const void **ptr, size_t *size, int *body_end, int mode) {
    asn_dec_rval_t rval;
    unsigned outer;
    unsigned child;
    int selected;

    rval = _SET_ber_select_next(codec, td, st, specs, ctx, ptr, size, &outer,
                                &child, &selected, body_end);
    if(rval.code != RC_OK || !selected) return rval;
    {
        asn_dec_rval_t leaf = _SET_ber_decode_leaf(codec, td, st, ctx, outer,
                                                   child, ptr, size, mode);
        leaf.consumed += rval.consumed;
        return leaf;
    }
}

/*
 * Purpose: drain the SET tail, finish indefinite framing, and validate required
 *          parent and group members.
 * Source: BER SET extension handling and shared SET presence validation.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/ctx identify the SET; ptr/size provide remaining data.
 * Returns: RC_OK when complete, RC_WMORE for incomplete framing, RC_FAIL for
 *          invalid tails or missing required members; consumed reports progress.
 * Errors: malformed indefinite terminators and unexpected tails are rejected.
 * Author: asn1c maintainers.
 * History: Extracted tail draining from SET_decode_ber.
 * Example: a completed indefinite SET consumes its 00 00 terminator.
 */
static asn_dec_rval_t
_SET_ber_drain(const asn_codec_ctx_t *codec,
               const asn_TYPE_descriptor_t *td, void *st,
               asn_struct_ctx_t *ctx, const void *input, size_t input_size) {
    const void *ptr = input;
    size_t size = input_size;
    ssize_t consumed_myself = 0;
    ber_tlv_tag_t tag;
    asn_dec_rval_t rval;

    switch(ctx->phase) {
    case 3:
    case 4:
        while(ctx->left) {
            ssize_t tag_len;
            ssize_t length;

            tag_len = ber_fetch_tag(ptr, LEFT, &tag);
            if(tag_len == 0) {
                if(!SIZE_VIOLATION) RETURN(RC_WMORE);
                RETURN(RC_FAIL);
            }
            if(tag_len < 0) RETURN(RC_FAIL);
            if(ctx->left < 0 && ((const uint8_t *)ptr)[0] == 0) {
                if(LEFT < 2) {
                    if(SIZE_VIOLATION) RETURN(RC_FAIL);
                    RETURN(RC_WMORE);
                }
                if(((const uint8_t *)ptr)[1] == 0) {
                    ADVANCE(2);
                    ctx->left++;
                    ctx->phase = 4;
                    continue;
                }
            }
            if(!((const asn_SET_specifics_t *)td->specifics)->extensible
            || ctx->phase == 4) RETURN(RC_FAIL);
            length = ber_skip_length(codec, BER_TLV_CONSTRUCTED(ptr),
                                     (const char *)ptr + tag_len,
                                     LEFT - (size_t)tag_len);
            if(length == 0) {
                if(!SIZE_VIOLATION) RETURN(RC_WMORE);
                RETURN(RC_FAIL);
            }
            if(length < 0) RETURN(RC_FAIL);
            ADVANCE((size_t)tag_len + (size_t)length);
        }
        ctx->phase = 5;
        /* Fall through */
    case 5:
        if(!_SET_is_populated(td, st)) RETURN(RC_FAIL);
        NEXT_PHASE(ctx);
        break;
    default:
        RETURN(RC_FAIL);
    }
    RETURN(RC_OK);
}

/*
 * Purpose: validate and initialize a SET BER decode target and parser context.
 * Source: SET descriptor layout, BER input contract, and codec stack guard.
 * Version: 2026-10-22.
 * Parameters: codec/td/struct_ptr/input/size identify the decode; outputs
 *             receive specifics, structure storage, and embedded context.
 * Returns: 0 when ready or -1 for malformed descriptors, stack limit, or OOM.
 * Errors: malformed offsets and allocation failures are reported to caller.
 * Author: asn1c maintainers.
 * History: Extracted target setup from SET_decode_ber.
 * Example: a fresh SET is allocated before its decoder context is restored.
 */
static int
_SET_ber_prepare(const asn_codec_ctx_t *codec,
                 const asn_TYPE_descriptor_t *td, void **struct_ptr,
                 const void *input, size_t size,
                 const asn_SET_specifics_t **specs, void **st,
                 asn_struct_ctx_t **ctx) {
    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics
    || !struct_ptr || (td->elements_count && !td->elements)
    || (size && !input)) return -1;
    *specs = (const asn_SET_specifics_t *)td->specifics;
    if(!(*specs)->struct_size || (*specs)->ctx_offset > (*specs)->struct_size
    || (*specs)->struct_size - (*specs)->ctx_offset
       < sizeof(asn_struct_ctx_t)) return -1;
    if(ASN__STACK_OVERFLOW_CHECK(codec)) return -1;
    *st = *struct_ptr;
    if(!*st) {
        *st = *struct_ptr = CALLOC(1, (*specs)->struct_size);
        if(!*st) return -1;
    }
    *ctx = (asn_struct_ctx_t *)((char *)*st + (*specs)->ctx_offset);
    return 0;
}

/*
 * Purpose: decode BER SET members, including interleaved flat group leaves.
 * Source: Existing SET BER state machine and one-level group route helpers.
 * Version: 2026-10-22.
 * Parameters: codec/td/struct_ptr identify the SET; ptr/size hold input;
 *             tag_mode controls the outer tag form.
 * Returns: RC_OK for a complete SET, RC_WMORE for incomplete input, or RC_FAIL.
 * Errors: malformed descriptors, duplicate fields, child failures, and missing
 *         required values fail; caller-owned partial objects remain freeable.
 * Author: asn1c maintainers.
 * History: Refactored to flatten SET extension groups and validate bounded input.
 * Example: a group child tag routes to its synthetic SET leaf without a wrapper.
 */
static asn_dec_rval_t
_SET_decode_ber_pass(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td, void **struct_ptr,
               const void *ptr, size_t size, int tag_mode, int mode) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SET_specifics_t *specs;

    /*
     * Parts of the structure being constructed.
     */
    void *st;                /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder state variable. */

    asn_dec_rval_t rval;    /* Return code from subparsers */

    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */

    if(_SET_ber_prepare(opt_codec_ctx, td, struct_ptr, ptr, size, &specs, &st,
                        &ctx) != 0) ASN__DECODE_FAILED;
    ASN_DEBUG("Decoding %s as SET", td->name);

    /* Check recursion depth to prevent stack overflow */
    ASN__DECODER_RECURSION_DEPTH_CHECK(opt_codec_ctx);

    /*
     * Start to parse where left previously
     */
    switch(ctx->phase) {
    case 0:
        /*
         * PHASE 0.
         * Check that the set of tags associated with given structure
         * perfectly fits our expectations.
         */

        rval = ber_check_tags(opt_codec_ctx, td, ctx, ptr, size,
                              tag_mode, 1, &ctx->left, 0);
        if(rval.code != RC_OK) {
            ASN_DEBUG("%s tagging check failed: %d",
                      td->name, rval.code);
            return rval;
        }

        if(ctx->left >= 0)
            ctx->left += rval.consumed;  /* ?Subtracted below! */
        ADVANCE(rval.consumed);

        NEXT_PHASE(ctx);

        ASN_DEBUG("Structure advertised %ld bytes, "
                  "buffer contains %ld", (long)ctx->left, (long)size);

        /* Fall through */
    case 1:
        /*
         * Decode interleaved direct members and transparent group leaves.
         */
        for(;;) {
            int body_end;
            rval = _SET_ber_decode_step(opt_codec_ctx, td, st, specs, ctx,
                                        &ptr, &size, &body_end, mode);
            consumed_myself += rval.consumed;
            if(rval.code != RC_OK) RETURN(rval.code);
            if(body_end) break;
        }
        ctx->phase = 3;
        /* Fall through */

    case 3:
    case 4:
    case 5:
        rval = _SET_ber_drain(opt_codec_ctx, td, st, ctx, ptr, size);
        consumed_myself += rval.consumed;
        if(rval.code != RC_OK) RETURN(rval.code);
        break;
    }

    RETURN(RC_OK);
}

/*
 * Purpose: Validate an unambiguous explicitly tagged SET open member.
 * Source: SET tag maps and opaque table-selector contracts. Version: 2026-10-30.
 * Inputs: td is the SET descriptor. Returns: 1 for one valid open field,
 * 0 for none, or -1 for unsupported or ambiguous metadata.
 * Errors: Multiple open fields, group leaves and colliding tags fail closed.
 * Author: maintainers. History: Added for transactional BER selection.
 * Example: An untagged open field cannot be routed unambiguously.
 */
static int
_SET_ber_open_shape(const asn_TYPE_descriptor_t *td) {
    const asn_SET_specifics_t *specs = td->specifics;
    unsigned i, open_index = 0, count = 0, matches = 0;
    size_t width;
    if(!specs || (td->elements_count && !td->elements)) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        if(member->flags & ATF_OPEN_TYPE) {
            if(!member->type_selector || member->tag == (ber_tlv_tag_t)-1) return -1;
            open_index = i;
            count++;
        }
    }
    if(!count) return 0;
    if(count != 1 || SET_inline_value_size(td, &width) || !specs->tag2el) return -1;
    /* Group presence does not prove each possible selector dependency exists. */
    for(i = 0; i < td->elements_count; i++) {
        if(td->elements[i].flags & ATF_EXTENSION_GROUP) return -1;
    }
    for(i = 0; i < specs->tag2el_count; i++) {
        if(specs->tag2el[i].el_tag == td->elements[open_index].tag) {
            if(specs->tag2el[i].el_no != open_index) return -1;
            matches++;
        }
    }
    return matches == 1 ? 1 : -1;
}

/*
 * Purpose: Require every non-open sibling before invoking an opaque selector.
 * Source: SET presence metadata and selector safety. Version: 2026-10-30.
 * Inputs: td/st describe the decoded parent. Returns: zero or -1.
 * Errors: Absent siblings fail closed. Author: maintainers.
 * History: Restricts opaque selectors to initialized data.
 * Example: An unrelated omitted OPTIONAL sibling is conservatively rejected.
 */
static int
_SET_ber_open_dependencies(const asn_TYPE_descriptor_t *td, const void *st) {
    const asn_SET_specifics_t *specs = td->specifics;
    unsigned i;
    for(i = 0; i < td->elements_count; i++) {
        unsigned int word;
        size_t word_bits = 8 * sizeof(word);
        const char *map = (const char *)st + specs->pres_offset;
        if(td->elements[i].flags & ATF_OPEN_TYPE) continue;
        memcpy(&word, map + (i / word_bits) * sizeof(word), sizeof(word));
        if(!(word & (1u << (word_bits - 1 - (i % word_bits))))) return -1;
    }
    return 0;
}

/*
 * Purpose: Decode a direct SET open field after every sibling is available.
 * Source: BER SET ordering and selector safety. Version: 2026-10-30.
 * Inputs: codec/td/target/input/size/tag_mode follow the BER decoder API.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL and consumed bytes.
 * Errors: Invalid metadata, duplicate fields, and unknown selectors fail.
 * Author: maintainers. History: Atomic two-pass decode owns no staged bytes.
 * Example: A selector can follow its explicitly tagged open field.
 */
asn_dec_rval_t
SET_decode_ber(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
               void **target, const void *input, size_t size, int tag_mode) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    const asn_SET_specifics_t *specs;
    asn_struct_ctx_t *ctx;
    ber_tlv_tag_t tag;
    ssize_t tag_len, content_len;
    unsigned i;
    int shape;
    if(!td || !target || (!input && size)) return result;
    shape = _SET_ber_open_shape(td);
    if(shape < 0) return result;
    if(!shape) return _SET_decode_ber_pass(codec, td, target, input, size, tag_mode, 0);
    if(!size) { result.code = RC_WMORE; return result; }
    tag_len = ber_fetch_tag(input, size, &tag);
    if(tag_len == 0) { result.code = RC_WMORE; return result; }
    if(tag_len < 0 || (size_t)tag_len > size) return result;
    content_len = ber_skip_length(codec, BER_TLV_CONSTRUCTED(input),
                                  (const char *)input + tag_len, size - (size_t)tag_len);
    if(content_len == 0) { result.code = RC_WMORE; return result; }
    if(content_len < 0 || (size_t)content_len > size - (size_t)tag_len) return result;
    size = (size_t)tag_len + (size_t)content_len;
    result = _SET_decode_ber_pass(codec, td, target, input, size, tag_mode, 1);
    if(result.code != RC_OK || result.consumed != size) { result.code = RC_FAIL; return result; }
    specs = td->specifics;
    for(i = 0; i < td->elements_count; i++) {
        if((td->elements[i].flags & ATF_OPEN_TYPE)
        && ASN_SET_ISPRESENT2((char *)*target + specs->pres_offset, i)
        && _SET_ber_open_dependencies(td, *target)) { result.code = RC_FAIL; return result; }
    }
    ctx = (asn_struct_ctx_t *)((char *)*target + specs->ctx_offset);
    memset(ctx, 0, sizeof(*ctx));
    result = _SET_decode_ber_pass(codec, td, target, input, size, tag_mode, 2);
    if(result.code == RC_OK && result.consumed != size) result.code = RC_FAIL;
    return result;
}

/*
 * Purpose: hold one present leaf in globally tag-sorted DER output order.
 * Source: SET member descriptors plus each value's actual BER outmost tag.
 * Version: 2026-10-22.
 * Parameters: no runtime parameters; members retain a const member view and tag.
 * Returns: not applicable; this structure is internal to the DER encoder.
 * Errors: allocation and descriptor errors are reported by the gathering helper.
 * Author: asn1c maintainers.
 * History: Added to flatten extension-group leaves into SET DER contents.
 * Example: each group child becomes one entry with its own canonical tag.
 */
typedef struct SET_der_member_s {
    asn_SET_member_view_t view; /* Const leaf descriptor and value storage. */
    ber_tlv_tag_t tag;          /* Actual tag, including dynamic CHOICE choice. */
} SET_der_member_t;

/*
 * Purpose: compare two DER leaf entries by their actual canonical tags.
 * Source: X.690 tag class and tag-number ordering.
 * Version: 2026-10-22.
 * Parameters: ap and bp point to SET_der_member_t entries.
 * Returns: negative, zero, or positive according to their BER tag order.
 * Errors: none; callers provide valid entries.
 * Author: asn1c maintainers.
 * History: Added for flattened SET DER sorting.
 * Example: a lower tag class sorts before a higher class.
 */
static int
_SET_der_member_cmp(const void *ap, const void *bp) {
    const SET_der_member_t *a = (const SET_der_member_t *)ap;
    const SET_der_member_t *b = (const SET_der_member_t *)bp;
    asn_TYPE_tag2member_t at;
    asn_TYPE_tag2member_t bt;

    at.el_tag = a->tag;
    bt.el_tag = b->tag;
    return _t2e_cmp(&at, &bt);
}

/*
 * Purpose: Ensure DER emits every sibling before resolving an opaque selector.
 * Source: SET member presence and selector safety. Version: 2026-10-30.
 * Inputs: td/st identify the parent; open identifies its selected member.
 * Returns: zero when all siblings are emitted, otherwise -1.
 * Errors: Absent, default-omitted or grouped siblings fail closed.
 * Author: maintainers. History: Mirrors BER selector dependency validation.
 * Example: An unrelated missing OPTIONAL sibling makes selected encoding fail.
 */
static int
_SET_der_open_dependencies(const asn_TYPE_descriptor_t *td, const void *st,
                           const asn_TYPE_member_t *open) {
    unsigned i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        asn_SET_member_view_t view;
        if(member == open) continue;
        if(member->flags & ATF_EXTENSION_GROUP) return -1;
        if(SET_member_view(td, st, i, ASN_SET_DIRECT_MEMBER, &view) || !view.present)
            return -1;
        if(member->default_value_cmp && member->default_value_cmp(view.value) == 0)
            return -1;
    }
    return 0;
}

/*
 * Purpose: size one present SET leaf and append its actual-tag sort entry.
 * Source: Member DER encoder and generated SET member descriptor.
 * Version: 2026-10-22.
 * Parameters: view is the resolved leaf; entries/capacity/count hold output;
 *             size accumulates content bytes; error receives child failures.
 * Returns: 0 on success, -1 on absence, malformed data, or size overflow.
 * Errors: a child DER encoder failure is copied to error.
 * Author: asn1c maintainers.
 * History: Added to share sizing for ordinary and grouped SET leaves.
 * Example: a present CHOICE is sized and stored with its selected tag.
 */
static int
_SET_der_add_member(const asn_TYPE_descriptor_t *td, const void *sptr,
                    const asn_SET_member_view_t *view, SET_der_member_t *entries, size_t capacity,
                    size_t *count, size_t *size, asn_enc_rval_t *error) {
    const asn_TYPE_member_t *member = view->member;
    asn_enc_rval_t child;

    if(!view->present) return member->optional ? 0 : -1;
    if(!member->type || !member->type->op || !member->type->op->der_encoder)
        return -1;
    if(member->default_value_cmp && member->default_value_cmp(view->value) == 0)
        return 0;
    if(*count >= capacity) return -1;
    if(member->flags & ATF_OPEN_TYPE) {
        asn_type_selector_result_t selected;
        if(view->owner != sptr || _SET_der_open_dependencies(td, sptr, member)) return -1;
        selected = _SET_ber_open_selection(td, sptr, member, 1);
        if(!selected.type_descriptor) return -1;
        child = OPEN_TYPE_ber_put(td, sptr, member, member->tag_mode, member->tag, 0, 0);
    } else {
        child = member->type->op->der_encoder(member->type, view->value,
                                              member->tag_mode, member->tag, 0, 0);
    }
    if(child.encoded < 0) {
        *error = child;
        return -2;
    }
    if((size_t)child.encoded > SIZE_MAX - *size) return -1;
    *size += (size_t)child.encoded;
    entries[*count].view = *view;
    entries[*count].tag = (member->flags & ATF_OPEN_TYPE) ? member->tag
        : asn_TYPE_outmost_tag(member->type, view->value, member->tag_mode, member->tag);
    (*count)++;
    return 0;
}

/*
 * Purpose: flatten present ordinary and extension-group SET leaves for DER.
 * Source: SET descriptors, mandatory masks, and member DER encoders.
 * Version: 2026-10-22.
 * Parameters: td/sptr identify the value; entries/count/size receive output;
 *             error receives a nested DER failure when one occurs.
 * Returns: 0 on success, -1 on missing mandatory values or malformed metadata.
 * Errors: allocation failures are handled by the caller; child errors in error.
 * Author: asn1c maintainers.
 * History: Added to encode groups without wrapper TLVs and sort all leaves.
 * Example: interleaved group leaves join ordinary SET fields in one tag order.
 */
static int
_SET_der_gather(const asn_TYPE_descriptor_t *td, const void *sptr,
                SET_der_member_t **entries, size_t *count, size_t *size,
                asn_enc_rval_t *error) {
    size_t capacity = 0;
    size_t i;
    int status;

    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t add = 1;
        if(member->flags & ATF_EXTENSION_GROUP) {
            asn_SET_member_view_t view;
            if(SET_member_view(td, sptr, (unsigned)i, 0, &view) != 0)
                return -1;
            add = member->type->elements_count;
        }
        if(add > SIZE_MAX - capacity) return -1;
        capacity += add;
    }
    if(capacity > SIZE_MAX / sizeof((*entries)[0])) return -1;
    *entries = capacity ? CALLOC(capacity, sizeof((*entries)[0])) : 0;
    if(capacity && !*entries) return -1;

    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        asn_SET_member_view_t view;
        size_t j;

        if(member->flags & ATF_EXTENSION_GROUP) {
            int populated;
            if(SET_member_view(td, sptr, (unsigned)i, 0, &view) != 0)
                return -1;
            if(!view.owner) {
                if(!member->optional) return -1;
                continue;
            }
            populated = SET_group_is_populated(member->type, view.owner);
            if(populated != 1) return -1;
            for(j = 0; j < member->type->elements_count; j++) {
                if(SET_member_view(td, sptr, (unsigned)i, (unsigned)j,
                                   &view) != 0) return -1;
                status = _SET_der_add_member(td, sptr, &view, *entries, capacity,
                                             count, size, error);
                if(status != 0) return status;
            }
        } else {
            if(SET_member_view(td, sptr, (unsigned)i, ASN_SET_DIRECT_MEMBER,
                               &view) != 0) return -1;
            status = _SET_der_add_member(td, sptr, &view, *entries, capacity, count,
                                         size, error);
            if(status != 0) return status;
        }
    }
    return 0;
}

/*
 * Purpose: DER-encode a SET with transparent extension-group leaves.
 * Source: X.690 DER rules and compiler-generated SET metadata.
 * Version: 2026-10-22.
 * Parameters: td/sptr describe the SET; tag_mode/tag describe outer tagging;
 *             cb/app_key receive the encoded TLV when cb is non-NULL.
 * Returns: encoded length and success state, or a failed encoding result.
 * Errors: invalid descriptors, absent mandatory values, overflow, and callbacks
 *         fail the operation; nested encoder failures are propagated.
 * Author: asn1c maintainers.
 * History: Reworked to flatten extension groups and sort by actual leaf tags.
 * Example: a group [3] field is emitted among the parent's ordinary SET fields.
 */
asn_enc_rval_t
SET_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr, int tag_mode,
               ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb, void *app_key) {
    SET_der_member_t *entries = 0;
    size_t count = 0;
    size_t computed_size = 0;
    size_t i;
    asn_enc_rval_t error;
    asn_enc_rval_t er;
    ssize_t ret;
    int gather_status;

    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !sptr
    || !td->specifics
    || (td->elements_count && !td->elements)) ASN__ENCODE_FAILED;
    if(_SET_ber_open_shape(td) < 0) ASN__ENCODE_FAILED;
    ASN__ENCODER_RECURSION_DEPTH_INC();
    error.encoded = -1;
    error.failed_type = td;
    error.structure_ptr = sptr;
    gather_status = _SET_der_gather(td, sptr, &entries, &count,
                                    &computed_size, &error);
    if(gather_status != 0) {
        FREEMEM(entries);
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        if(gather_status == -2) return error;
        ASN__ENCODE_FAILED;
    }
    if(computed_size > (size_t)SSIZE_MAX) {
        FREEMEM(entries);
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }
    if(count > 1)
        qsort(entries, count, sizeof(entries[0]), _SET_der_member_cmp);

    ret = der_write_tags(td, computed_size, tag_mode, 1, tag, cb, app_key);
    if(ret < 0 || (size_t)ret > SIZE_MAX - computed_size
    || (size_t)ret > (size_t)SSIZE_MAX - computed_size) {
        FREEMEM(entries);
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODE_FAILED;
    }
    er.encoded = computed_size + (size_t)ret;
    if(!cb) {
        FREEMEM(entries);
        ASN__ENCODER_RECURSION_DEPTH_DEC();
        ASN__ENCODED_OK(er);
    }

    for(i = 0; i < count; i++) {
        const asn_SET_member_view_t *view = &entries[i].view;
        const asn_TYPE_member_t *member = view->member;
        asn_enc_rval_t child;

        if(member->flags & ATF_OPEN_TYPE)
            child = OPEN_TYPE_ber_put(td, sptr, member, member->tag_mode, member->tag, cb, app_key);
        else
            child = member->type->op->der_encoder(member->type, view->value,
                                                  member->tag_mode, member->tag, cb, app_key);
        if(child.encoded < 0) {
            FREEMEM(entries);
            ASN__ENCODER_RECURSION_DEPTH_DEC();
            return child;
        }
        if((size_t)child.encoded > computed_size) {
            FREEMEM(entries);
            ASN__ENCODER_RECURSION_DEPTH_DEC();
            ASN__ENCODE_FAILED;
        }
        computed_size -= (size_t)child.encoded;
    }
    FREEMEM(entries);
    ASN__ENCODER_RECURSION_DEPTH_DEC();
    if(computed_size != 0) ASN__ENCODE_FAILED;
    ASN__ENCODED_OK(er);
}
