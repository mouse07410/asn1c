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
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

#undef XER_ADVANCE
#define XER_ADVANCE(num_bytes)                    \
    do {                                          \
        size_t num = num_bytes;                   \
        buf_ptr = ((const char *)buf_ptr) + num;  \
        size -= num;                              \
        consumed_myself += num;                   \
    } while(0)

/*
 * Purpose: find an ordinary member or extension-group leaf by XML name.
 * Source: SET member names and one-level synthetic group descriptors.
 * Version: 2026-10-22.
 * Parameters: td/st identify the SET; buf/ch_size describe the current tag;
 *             outer and child receive indexes, with child sentinel for direct.
 * Returns: 1 for a matching opening/both tag, 0 for no match, -1 if malformed.
 * Errors: invalid group descriptors and indexes return -1.
 * Author: asn1c maintainers.
 * History: Added for flat XER extension-group name routing.
 * Example: a group leaf's XML name selects its parent group and leaf indexes.
 */
static int
_SET_xer_find_member(const asn_TYPE_descriptor_t *td, const void *st,
                     const void *buf, size_t ch_size, unsigned *outer,
                     unsigned *child) {
    size_t i;

    if(ch_size > INT_MAX) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        if(member->flags & ATF_EXTENSION_GROUP) {
            asn_SET_member_view_t view;
            size_t j;
            if(!member->type || !member->type->elements_count
            || SET_member_view(td, st, (unsigned)i, 0, &view) != 0)
                return -1;
            for(j = 0; j < member->type->elements_count; j++) {
                xer_check_tag_e check;
                if(SET_member_view(td, st, (unsigned)i, (unsigned)j,
                                   &view) != 0) return -1;
                check = xer_check_tag(buf, ch_size, view.member->name);
                if(check == XCT_BOTH || check == XCT_OPENING) {
                    *outer = (unsigned)i;
                    *child = (unsigned)j;
                    return 1;
                }
                if(check != XCT_UNKNOWN_OP && check != XCT_UNKNOWN_BO)
                    return 0;
            }
        } else {
            xer_check_tag_e check = xer_check_tag(buf, ch_size, member->name);
            if(check == XCT_BOTH || check == XCT_OPENING) {
                *outer = (unsigned)i;
                *child = ASN_SET_DIRECT_MEMBER;
                return 1;
            }
            if(check != XCT_UNKNOWN_OP && check != XCT_UNKNOWN_BO) return 0;
        }
    }
    return 0;
}

/*
 * Purpose: validate selected XER CHOICE storage and context fields.
 * Source: generated CHOICE metadata and runtime type widths. Version: 2026-10-30.
 * Inputs: specs/arm describe the wrapper; selected identifies its child.
 * Returns: zero when valid, -1 otherwise. Errors: invalid spans fail.
 * Author: maintainers. History: split storage validation from selector dispatch.
 * Example: an out-of-bounds pointer arm is rejected before any allocation.
 */
static int
_SET_xer_choice_valid(const asn_CHOICE_specifics_t *specs, const asn_TYPE_member_t *arm,
                      asn_type_selector_result_t selected) {
    size_t width = 0, slot;
    int status = SET_inline_value_size(selected.type_descriptor, &width);
    if(status && (!(arm->flags & ATF_POINTER) || status != -2)) return -1;
    slot = (arm->flags & ATF_POINTER) ? sizeof(void *) : width;
    if(arm->type != selected.type_descriptor || !specs->struct_size
       || (specs->pres_size != sizeof(char) && specs->pres_size != sizeof(short)
           && specs->pres_size != sizeof(int)) || specs->pres_offset > specs->struct_size
       || specs->pres_size > specs->struct_size - specs->pres_offset
       || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset
       || (specs->pres_offset < specs->ctx_offset + sizeof(asn_struct_ctx_t)
           && specs->ctx_offset < specs->pres_offset + specs->pres_size)
       || arm->memb_offset > specs->struct_size || slot > specs->struct_size - arm->memb_offset) return -1;
    if(arm->memb_offset < specs->pres_offset + specs->pres_size
       && specs->pres_offset < arm->memb_offset + slot) return -1;
    if(arm->memb_offset < specs->ctx_offset + sizeof(asn_struct_ctx_t)
       && specs->ctx_offset < arm->memb_offset + slot) return -1;
    return 0;
}

/*
 * Purpose: validate the selected IOC arm and its complete wrapper storage.
 * Source: generated SET/CHOICE metadata. Version: 2026-10-30.
 * Inputs: td/st identify the parent; member selects the open field; result
 * receives its selector. Returns: zero or -1. Errors: invalid metadata fails.
 * Author: asn1c maintainers. History: added direct XER open dispatch.
 * Example: an unknown selector or truncated arm fails before decoding.
 */
static int
_SET_xer_open_selection(const asn_TYPE_descriptor_t *td, const void *st,
                        const asn_TYPE_member_t *member, asn_type_selector_result_t *result) {
    const asn_TYPE_member_t *arm;
    if(!member->type_selector || !member->type || !member->type->specifics
       || !member->type->elements || !member->type->elements_count) return -1;
    *result = member->type_selector(td, st);
    if(!result->presence_index || result->presence_index > member->type->elements_count
       || !result->type_descriptor || !result->type_descriptor->op
       || !result->type_descriptor->op->free_struct
       || !result->type_descriptor->op->xer_decoder
       || !result->type_descriptor->op->xer_encoder) return -1;
    arm = &member->type->elements[result->presence_index - 1];
    if(_SET_xer_choice_valid(member->type->specifics, arm, *result)) return -1;
    return 0;
}

/*
 * Purpose: locate a complete direct open element without consuming partial input.
 * Source: XER token framing and SET streaming contract. Version: 2026-10-30.
 * Inputs: member is the selected field, buf/size bound available bytes, start/end
 * receive the inner slice. Returns: 1 complete, 0 needs more, -1 malformed.
 * Errors: invalid tags, excessive lengths or nesting fail. Author: maintainers.
 * History: buffers by caller replay rather than retaining owned parser state.
 * Example: a truncated value returns zero consumed so the caller can append.
 */
static int
_SET_xer_open_frame(const asn_TYPE_member_t *member, const char *buf, size_t size,
                    size_t *start, size_t *end, size_t *total) {
    size_t offset = 0, depth = 0;
    int context = 0;
    while(offset < size) {
        pxer_chunk_type_e type;
        ssize_t length = xer_next_token(&context, buf + offset, size - offset, &type);
        xer_check_tag_e tag;
        if(length < 0) return -1;
        if(type == PXER_WMORE) return 0;
        if(length == 0 || (size_t)length > size - offset || length > INT_MAX) return -1;
        if(type != PXER_TAG) { offset += (size_t)length; continue; }
        tag = xer_check_tag(buf + offset, (int)length, depth ? 0 : member->name);
        if(tag == XCT_BROKEN) return -1;
        if(!depth) {
            if(tag != XCT_OPENING) return -1;
            *start = offset + (size_t)length;
            depth = 1;
        } else if((tag & 3) == XCT_OPENING) {
            if(depth == SIZE_MAX) return -1;
            depth++;
        } else if((tag & 3) == XCT_CLOSING) {
            if(--depth == 0) {
                if(xer_check_tag(buf + offset, (int)length, member->name) != XCT_CLOSING) return -1;
                *end = offset;
                *total = offset + (size_t)length;
                return 1;
            }
        }
        offset += (size_t)length;
    }
    return 0;
}

/*
 * Purpose: decode a complete selector-first IOC open SET member.
 * Source: XER child decoder and CHOICE ownership contracts. Version: 2026-10-30.
 * Inputs: codec/td/st/outer identify the value, buf/size bound XML input.
 * Returns: child status and consumed bytes. Errors: bad selection and XML fail.
 * Author: asn1c maintainers. History: caller retains incomplete value bytes.
 * Example: a selected INTEGER child is decoded after every sibling is present.
 */
static asn_dec_rval_t
_SET_xer_decode_open(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                     void *st, unsigned outer, const char *buf, size_t size) {
    const asn_SET_specifics_t *parent = td->specifics;
    const asn_TYPE_member_t *member = &td->elements[outer], *arm;
    const asn_CHOICE_specifics_t *specs;
    asn_type_selector_result_t selected;
    asn_dec_rval_t result = {RC_FAIL, 0};
    size_t i, start, end, total;
    void *wrapper, *inner;
    void **slot;
    int framed;
    /* The selector is opaque, so every other sibling must already be present. */
    for(i = 0; i < td->elements_count; i++) {
        if(i != outer && !ASN_SET_ISPRESENT2((char *)st + parent->pres_offset, i)) return result;
    }
    if(_SET_xer_open_selection(td, st, member, &selected)) return result;
    framed = _SET_xer_open_frame(member, buf, size, &start, &end, &total);
    if(framed == 0) { result.code = RC_WMORE; return result; }
    if(framed < 0) return result;
    specs = member->type->specifics;
    if(member->flags & ATF_POINTER) {
        slot = (void **)((char *)st + member->memb_offset);
        if(!*slot && !(*slot = CALLOC(1, specs->struct_size))) return result;
        wrapper = *slot;
    } else wrapper = (char *)st + member->memb_offset;
    if(CHOICE_variant_set_presence(member->type, wrapper, selected.presence_index)) return result;
    arm = &member->type->elements[selected.presence_index - 1];
    if(arm->flags & ATF_POINTER) inner = *(void **)((char *)wrapper + arm->memb_offset);
    else inner = (char *)wrapper + arm->memb_offset;
    result = selected.type_descriptor->op->xer_decoder(codec, selected.type_descriptor, &inner,
                                                       0, buf + start, total - start);
    if(arm->flags & ATF_POINTER) *(void **)((char *)wrapper + arm->memb_offset) = inner;
    if(result.code != RC_OK || result.consumed > end - start) {
        result.code = RC_FAIL; result.consumed = 0; return result;
    }
    /* Only XML whitespace may remain between the child and the outer close. */
    for(i = start + result.consumed; i < end; i++) {
        if(buf[i] != ' ' && buf[i] != '\t' && buf[i] != '\r' && buf[i] != '\n') {
            result.code = RC_FAIL; result.consumed = 0; return result;
        }
    }
    result.consumed = total;
    return result;
}

/*
 * Purpose: decode one XER member selected by the SET body parser.
 * Source: Generated SET member descriptors and child XER decoders.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/ctx identify the decode; outer and child select the
 *             leaf; buf/size are bounded input; rval receives child progress.
 * Returns: 0 when a decoder was invoked, -1 for malformed storage or duplicate.
 * Errors: invalid descriptors, duplicate leaves, allocation, and over-consume
 *         are rejected; child WMORE/FAIL is returned in rval.
 * Author: asn1c maintainers.
 * History: Added to isolate group allocation and presence handling from parser.
 * Example: the helper allocates a group on its first leaf and resumes that leaf.
 */
static int
_SET_xer_decode_member(const asn_codec_ctx_t *codec,
                       const asn_TYPE_descriptor_t *td, void *st,
                       asn_struct_ctx_t *ctx, unsigned outer,
                       unsigned child, const char *buf, size_t size,
                       asn_dec_rval_t *rval) {
    asn_SET_member_view_t view;
    const asn_TYPE_member_t *outer_member;
    void *member_ptr;
    void *owner = st;
    void **member_ptr2;

    if(outer >= td->elements_count) return -1;
    outer_member = &td->elements[outer];
    if(outer_member->flags & ATF_EXTENSION_GROUP) {
        void **group_slot;
        if(child >= outer_member->type->elements_count
        || SET_member_view(td, st, outer, child, &view) != 0) return -1;
        group_slot = (void **)((char *)st + outer_member->memb_offset);
        if(!*group_slot) {
            *group_slot = CALLOC(1, view.owner_specs->struct_size);
            if(!*group_slot) return -1;
        }
        owner = *group_slot;
    } else if(child != ASN_SET_DIRECT_MEMBER) {
        return -1;
    }
    if(SET_member_view(td, st, outer, child, &view) != 0) return -1;
    if(ASN_SET_ISPRESENT2((char *)owner + view.owner_specs->pres_offset,
                          view.owner_index)) return -1;
    if(!view.member->type || !view.member->type->op) return -1;
    if(view.member->flags & ATF_OPEN_TYPE) {
        if(child != ASN_SET_DIRECT_MEMBER) return -1;
        *rval = _SET_xer_decode_open(codec, td, st, outer, buf, size);
        if(rval->code == RC_OK) {
            ASN_SET_MKPRESENT((char *)st + view.owner_specs->pres_offset, view.owner_index);
            ctx->ptr = 0;
        }
        return 0;
    }
    if(!view.member->type->op->xer_decoder) return -1;
    if(view.member->flags & ATF_POINTER) {
        member_ptr2 = (void **)((char *)owner + view.member->memb_offset);
    } else {
        member_ptr = (char *)owner + view.member->memb_offset;
        member_ptr2 = &member_ptr;
    }
    *rval = view.member->type->op->xer_decoder(codec, view.member->type,
              member_ptr2, view.member->name, buf, size);
    if(rval->consumed > size) {
        rval->code = RC_FAIL;
        rval->consumed = 0;
        return -1;
    }
    if(rval->code == RC_OK) {
        ASN_SET_MKPRESENT((char *)owner + view.owner_specs->pres_offset,
                          view.owner_index);
        if(outer_member->flags & ATF_EXTENSION_GROUP) {
            const asn_SET_specifics_t *specs =
                (const asn_SET_specifics_t *)td->specifics;
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, outer);
        }
        ctx->ptr = 0;
    }
    return 0;
}

/*
 * Purpose: recover the selected child index from a suspended XER member.
 * Source: Static member descriptor addresses stored in the SET context.
 * Version: 2026-10-22.
 * Parameters: td/st describe the parent; ctx stores the outer index and child
 *             descriptor pointer; child receives the leaf index or sentinel.
 * Returns: 0 for a valid selection, -1 for malformed context or descriptors.
 * Errors: pointers outside the selected group's descriptor array are rejected.
 * Author: asn1c maintainers.
 * History: Added to resume flat XER group leaves safely.
 * Example: a saved address for group element one resolves to index one.
 */
static int
_SET_xer_selected_child(const asn_TYPE_descriptor_t *td, const void *st,
                        const asn_struct_ctx_t *ctx, unsigned outer,
                        unsigned *child) {
    const asn_TYPE_member_t *member;
    asn_SET_member_view_t view;
    size_t i;

    if(outer >= td->elements_count) return -1;
    member = &td->elements[outer];
    if(!(member->flags & ATF_EXTENSION_GROUP)) {
        *child = ASN_SET_DIRECT_MEMBER;
        return ctx->ptr ? -1 : 0;
    }
    if(SET_member_view(td, st, outer, 0, &view) != 0 || !ctx->ptr)
        return -1;
    for(i = 0; i < member->type->elements_count; i++) {
        if(ctx->ptr == &member->type->elements[i]) {
            *child = (unsigned)i;
            return 0;
        }
    }
    return -1;
}

/*
 * Purpose: select a member or enter the extension-skip phase for one tag.
 * Source: XER tag classes, SET member names, and extension skip rules.
 * Version: 2026-10-22.
 * Parameters: td/st/specs/ctx identify the SET; tcv/buf/ch_size describe a
 *             tag; outer/child receive a selected member when returned.
 * Returns: -1 for an unknown tag, 0 for extension skip, or 1 for a member.
 * Errors: invalid group descriptors and non-extensible unknown tags fail.
 * Author: asn1c maintainers.
 * History: Split member selection out of the XER tag phase transition.
 * Example: a group leaf opening tag stores its borrowed descriptor pointer.
 */
static int
_SET_xer_select_tag(const asn_TYPE_descriptor_t *td, const void *st,
                    const asn_SET_specifics_t *specs, asn_struct_ctx_t *ctx,
                    xer_check_tag_e tcv, const void *buf, size_t ch_size,
                    unsigned *outer, unsigned *child) {
    int selected;

    if(ctx->phase != 1) return -1;
    selected = _SET_xer_find_member(td, st, buf, ch_size, outer, child);
    if(selected < 0) return -1;
    if(selected > 0) {
        if(*outer > SHRT_MAX) return -1;
        ctx->step = (short)*outer;
        /* state variable: borrowed static child descriptor, never owned. */
        ctx->ptr = *child == ASN_SET_DIRECT_MEMBER ? 0
            : (void *)&td->elements[*outer].type->elements[*child];
        ctx->phase = 2;
        return 1;
    }
    if(!specs->extensible) return -1;
    if(!(tcv & XCT_CLOSING)) {
        ctx->left = 1;
        ctx->phase = 3;
    }
    return 0;
}

/*
 * Purpose: apply one XER tag to the SET parser's phase and member selection.
 * Source: XER tag classes, SET member names, and extension skip rules.
 * Version: 2026-10-22.
 * Parameters: td/st/specs/ctx identify the SET; tcv/buf/ch_size describe a
 *             tag; outer/child receive a selected member when returned.
 * Returns: -1 error, 0 consume tag, 1 decode selected leaf, 2 complete SET.
 * Errors: premature close, unexpected tags, and malformed group metadata fail.
 * Author: asn1c maintainers.
 * History: Extracted tag transitions from SET_decode_xer for bounded flow.
 * Example: a group leaf opening tag selects phase two and returns one.
 */
static int
_SET_xer_handle_tag(const asn_TYPE_descriptor_t *td, const void *st,
                    const asn_SET_specifics_t *specs, asn_struct_ctx_t *ctx,
                    xer_check_tag_e tcv, const void *buf, size_t ch_size,
                    unsigned *outer, unsigned *child) {
    int skipped;

    if(ctx->phase == 3) {
        skipped = xer_skip_unknown(tcv, &ctx->left);
        if(skipped < 0) {
            ctx->phase = 4;
            return -1;
        }
        if(skipped < 2) {
            if(skipped == 1) ctx->phase = 1;
            return 0;
        }
        ctx->phase = 1;
    }
    if(tcv == XCT_CLOSING) {
        if(ctx->phase == 0) return -1;
        ctx->phase = 0;
        tcv = XCT_BOTH;
    }
    if(tcv == XCT_BOTH && ctx->phase == 0) {
        if(!_SET_is_populated(td, st)) return -1;
        ctx->phase = 4;
        return 2;
    }
    if(tcv == XCT_OPENING && ctx->phase == 0) {
        ctx->phase = 1;
        return 0;
    }
    if(tcv == XCT_OPENING || tcv == XCT_BOTH
    || tcv == XCT_UNKNOWN_OP || tcv == XCT_UNKNOWN_BO)
        return _SET_xer_select_tag(td, st, specs, ctx, tcv, buf, ch_size,
                                  outer, child);
    return -1;
}

/*
 * Purpose: read and route one XER token without storing borrowed buffer state.
 * Source: xer_next_token and the transparent SET tag dispatcher.
 * Version: 2026-10-22.
 * Parameters: td/st/specs/ctx identify the SET; buf and size are current input;
 *             consumed reports bytes advanced; outer/child receive selection.
 * Returns: -2 need more data, -1 malformed input, 0 continue, 1 decode, 2 done.
 * Errors: malformed tokens and unknown non-extension tags return -1.
 * Author: asn1c maintainers.
 * History: Isolated token handling from the resumable SET XER main loop.
 * Example: comments are consumed with status zero; a member opening returns 1.
 */
static int
_SET_xer_next(const asn_TYPE_descriptor_t *td, const void *st,
              const asn_SET_specifics_t *specs, asn_struct_ctx_t *ctx,
              const char *xml_tag, const void **buf, size_t *size,
              ssize_t *consumed, unsigned *outer, unsigned *child) {
    pxer_chunk_type_e ch_type;
    ssize_t ch_size;
    xer_check_tag_e tcv;
    int action;

    ch_size = xer_next_token(&ctx->context, *buf, *size, &ch_type);
    if(ch_size < 0) return -1;
    if(ch_type == PXER_WMORE) return -2;
    if(ch_type == PXER_COMMENT || ch_type == PXER_TEXT) {
        *buf = (const char *)*buf + ch_size;
        *size -= (size_t)ch_size;
        *consumed += ch_size;
        return 0;
    }
    if(ch_type != PXER_TAG) return -1;
    if(ch_size > INT_MAX) return -1;
    tcv = xer_check_tag(*buf, (size_t)ch_size, xml_tag);
    action = _SET_xer_handle_tag(td, st, specs, ctx, tcv, *buf,
                                 (size_t)ch_size, outer, child);
    if(action == 0 || action == 2) {
        *buf = (const char *)*buf + ch_size;
        *size -= (size_t)ch_size;
        *consumed += ch_size;
    }
    return action;
}

/*
 * Purpose: validate and initialize the target for resumable SET XER decoding.
 * Source: SET descriptor layout and the XER decoder's stack guard.
 * Version: 2026-10-22.
 * Parameters: codec/td/struct_ptr identify the decode; outputs receive the
 *             allocated or existing object, SET specifics, and parser context.
 * Returns: 0 when initialized, -1 for invalid metadata, stack limit, or OOM.
 * Errors: malformed SET layout and allocation failures are reported to caller.
 * Author: asn1c maintainers.
 * History: Extracted validation and allocation from SET_decode_xer.
 * Example: a fresh object is zero-allocated before its embedded context is read.
 */
static int
_SET_xer_prepare(const asn_codec_ctx_t *codec,
                 const asn_TYPE_descriptor_t *td, void **struct_ptr,
                 const asn_SET_specifics_t **specs, void **st,
                 asn_struct_ctx_t **ctx) {
    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics
    || !struct_ptr || (td->elements_count && !td->elements)) return -1;
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
 * Purpose: resume decoding the leaf selected before a SET XER suspension.
 * Source: Saved outer index, borrowed child descriptor, and child XER decoder.
 * Version: 2026-10-22.
 * Parameters: codec/td/st/ctx identify state; buf/size bound the input bytes.
 * Returns: child decoder result, or RC_FAIL for invalid context or over-consume.
 * Errors: invalid state and malformed consumed counts fail safely.
 * Author: asn1c maintainers.
 * History: Extracted per-leaf resumption from the SET XER loop.
 * Example: partial leaf input returns RC_WMORE with its consumed byte count.
 */
static asn_dec_rval_t
_SET_xer_resume_member(const asn_codec_ctx_t *codec,
                       const asn_TYPE_descriptor_t *td, void *st,
                       asn_struct_ctx_t *ctx, const void *buf, size_t size) {
    asn_dec_rval_t rval = {RC_FAIL, 0};
    unsigned outer;
    unsigned child;

    if(ctx->step < 0 || (size_t)ctx->step >= td->elements_count) return rval;
    outer = (unsigned)ctx->step;
    if(_SET_xer_selected_child(td, st, ctx, outer, &child) != 0
    || _SET_xer_decode_member(codec, td, st, ctx, outer, child, buf, size,
                              &rval) != 0) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }
    if(rval.consumed > size) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
    } else if(rval.code == RC_OK) {
        ctx->phase = 1;
        ctx->step = 0;
    }
    return rval;
}

/*
 * Purpose: decode SET XER content while routing extension-group leaves flat.
 * Source: Existing SET XER parser and one-level group name routing helpers.
 * Version: 2026-10-22.
 * Parameters: codec/td/struct_ptr identify the SET; opt_mname selects its XML
 *             wrapper; buf_ptr/size contain available XML bytes.
 * Returns: RC_OK for completion, RC_WMORE for partial input, or RC_FAIL.
 * Errors: malformed tags, duplicate members, invalid descriptors, stack limits,
 *         and missing required values fail; partial values remain freeable.
 * Author: asn1c maintainers.
 * History: Added flat name routing, child resumption, and stack protection.
 * Example: a group leaf tag decodes as a sibling of the SET's ordinary fields.
 */
asn_dec_rval_t
SET_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td, void **struct_ptr,
               const char *opt_mname, const void *buf_ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SET_specifics_t *specs;
    const char *xml_tag;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st;                /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context state variable. */

    asn_dec_rval_t rval;          /* Return value from a decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    unsigned outer_index;
    unsigned child_index;
    int selected;

    if((size && !buf_ptr) || size > SSIZE_MAX) RETURN(RC_FAIL);
    if(!buf_ptr) buf_ptr = "";
    if(_SET_xer_prepare(opt_codec_ctx, td, struct_ptr, &specs, &st, &ctx) != 0)
        RETURN(RC_FAIL);
    xml_tag = opt_mname ? opt_mname : td->xml_tag;

    /*
     * Phases of XER/XML processing:
     * Phase 0: Check that the opening tag matches our expectations.
     * Phase 1: Processing body and reacting on closing tag.
     * Phase 2: Processing inner type.
     * Phase 3: Skipping unknown extensions.
     * Phase 4: PHASED OUT
     */
    for(; ctx->phase <= 3;) {
        /*
         * Go inside the inner member of a set.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval = _SET_xer_resume_member(
                opt_codec_ctx, td, st, ctx, buf_ptr, size);
            XER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ASN_DEBUG("XER/SET phase => %d", ctx->phase);
            /* Fall through */
        }

        selected = _SET_xer_next(td, st, specs, ctx, xml_tag, &buf_ptr,
                                 &size, &consumed_myself, &outer_index,
                                 &child_index);
        if(selected == -2) RETURN(RC_WMORE);
        if(selected < 0) RETURN(RC_FAIL);
        if(selected == 0) {
            continue;
        }
        if(selected == 1) continue;
        if(selected == 2) RETURN(RC_OK);
        RETURN(RC_FAIL);
    }

    ctx->phase = 4;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}

/*
 * Purpose: encode one XER SET member with its element-name wrapper.
 * Source: Existing SET XER wrapper behavior and child XER encoder operations.
 * Version: 2026-10-22.
 * Parameters: member/value identify the leaf; previous_bytes and ilevel select
 *             formatting; flags and cb/app_key control encoding and output.
 * Returns: encoded byte count or an encoding failure result.
 * Errors: missing child encoders and callback failures return failure.
 * Author: asn1c maintainers.
 * History: Extracted so ordinary and group leaves share identical wrappers.
 * Example: a group child is emitted as its own sibling XML element.
 */
static asn_enc_rval_t
_SET_xer_encode_leaf(const asn_TYPE_descriptor_t *parent, const void *parent_value,
                     const asn_TYPE_member_t *member, const void *value,
                     ssize_t previous_bytes, int ilevel,
                     enum xer_encoder_flags_e flags,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_TYPE_descriptor_t *td = member->type;
    const void *sptr = value;
    asn_enc_rval_t er = {0, 0, 0};
    asn_enc_rval_t child;
    const char *name = member->name;
    size_t name_size = strlen(name);
    int canonical = (flags & XER_F_CANONICAL) != 0;

    if(!td || !td->op || !td->op->xer_encoder) ASN__ENCODE_FAILED;
    if(!canonical) {
        if(previous_bytes == 0) {
            ASN__TEXT_INDENT(1, ilevel);
        } else {
            int tmp_i;
            for(tmp_i = 0; tmp_i < ilevel; tmp_i++)
                ASN__CALLBACK("    ", 4);
        }
    }
    ASN__CALLBACK3("<", 1, name, name_size, ">", 1);
    if(member->flags & ATF_OPEN_TYPE)
        child = OPEN_TYPE_xer_put(parent, parent_value, member, ilevel + 1, flags, cb, app_key);
    else child = td->op->xer_encoder(td, value, ilevel + 1, flags, cb, app_key);
    if(child.encoded < 0) return child;
    if(child.encoded > SSIZE_MAX - er.encoded) ASN__ENCODE_FAILED;
    er.encoded += child.encoded;
    if(!canonical) {
        if(child.encoded > 0 && ASN__IS_STRUCTURED_TYPE(member))
            ASN__TEXT_INDENT(0, ilevel);
        ASN__CALLBACK3("</", 2, name, name_size, ">\n", 2);
    } else {
        ASN__CALLBACK3("</", 2, name, name_size, ">", 1);
    }
    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Purpose: ensure a present open value can be decoded under the sibling gate.
 * Source: SET member storage and XER selector ordering. Version: 2026-10-30.
 * Inputs: td/st identify the parent and member identifies its open field.
 * Returns: zero if every other sibling exists, -1 otherwise. Errors: invalid
 * layouts fail. Author: maintainers. History: align encoder with decoder gate.
 * Example: an absent unrelated OPTIONAL sibling blocks open-value encoding.
 */
static int
_SET_xer_encode_siblings(const asn_TYPE_descriptor_t *td, const void *st,
                         const asn_TYPE_member_t *member) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *sibling = &td->elements[i];
        asn_SET_member_view_t view;
        unsigned child = (sibling->flags & ATF_EXTENSION_GROUP) ? 0 : ASN_SET_DIRECT_MEMBER;
        if(sibling == member) continue;
        if(SET_member_view(td, st, (unsigned)i, child, &view)) return -1;
        if((sibling->flags & ATF_EXTENSION_GROUP) ? !view.owner : !view.present) return -1;
    }
    return 0;
}

/*
 * Purpose: encode a resolved SET leaf, synthesizing absent DEFAULT values in
 *          XER without modifying the const input structure.
 * Source: SET member default callbacks and X.693 canonical-XER rules.
 * Version: 2026-10-22.
 * Parameters: parent/parent_value identify the SET; view selects a leaf;
 *             previous_bytes and ilevel select formatting; flags/callbacks
 *             control its representation and output.
 * Returns: encoded count, zero when omitted, or an encoding failure.
 * Errors: default allocation, mandatory absence, child, and callback failures.
 * Author: asn1c maintainers.
 * History: Materializes absent DEFAULT values in both XER modes.
 * Example: a NULL DEFAULT pointer is encoded through a temporary value.
 */
static asn_enc_rval_t
_SET_xer_encode_view(const asn_TYPE_descriptor_t *parent, const void *parent_value,
                     const asn_SET_member_view_t *view,
                     ssize_t previous_bytes, int ilevel,
                     enum xer_encoder_flags_e flags,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_TYPE_member_t *member = view->member;
    const asn_TYPE_descriptor_t *td = member->type;
    const void *sptr = view->value;
    const void *value = view->value;
    void *default_value = 0;
    asn_enc_rval_t er = {0, 0, 0};

    if(!td || !td->op || !td->op->xer_encoder) ASN__ENCODE_FAILED;
    if(!view->present) {
        if(member->default_value_set) {
            if(member->default_value_set(&default_value) != 0 || !default_value) {
                if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
                ASN__ENCODE_FAILED;
            }
            value = default_value;
        } else if(member->optional) {
            ASN__ENCODED_OK(er);
        } else {
            ASN__ENCODE_FAILED;
        }
    }
    if(member->flags & ATF_OPEN_TYPE) {
        asn_type_selector_result_t selected;
        if(view->owner != parent_value || _SET_xer_encode_siblings(parent, parent_value, member)
           || _SET_xer_open_selection(parent, parent_value, member, &selected)
           || CHOICE_variant_get_presence(member->type, value) != selected.presence_index) {
            if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
            ASN__ENCODE_FAILED;
        }
    }
    er = _SET_xer_encode_leaf(parent, parent_value, member, value,
                              previous_bytes, ilevel, flags, cb, app_key);
    if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
    return er;
}

/*
 * Purpose: encode a present synthetic SET group as sibling XER leaves.
 * Source: One-level group descriptors and each child's XER encoder.
 * Version: 2026-10-22.
 * Parameters: td/sptr identify the parent; outer selects the group;
 *             previous_bytes/ilevel/flags control formatting; cb/app_key
 *             receive encoded bytes.
 * Returns: encoded byte count, zero for an absent optional group, or failure.
 * Errors: incomplete mandatory leaves and child or callback errors are returned.
 * Author: asn1c maintainers.
 * History: Added to keep the public SET XER encoder's control flow bounded.
 * Example: a present group emits its child elements without a group wrapper.
 */
static asn_enc_rval_t
_SET_xer_encode_group(const asn_TYPE_descriptor_t *td, const void *sptr,
                      unsigned outer, ssize_t previous_bytes, int ilevel,
                      enum xer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_TYPE_member_t *member = &td->elements[outer];
    asn_SET_member_view_t view;
    asn_enc_rval_t er = {0, 0, 0};
    size_t i;

    if(!member->type || !member->type->elements_count
    || SET_member_view(td, sptr, outer, 0, &view) != 0) ASN__ENCODE_FAILED;
    if(!view.owner) {
        if(member->optional) ASN__ENCODED_OK(er);
        ASN__ENCODE_FAILED;
    }
    if(SET_group_is_populated(member->type, view.owner) != 1)
        ASN__ENCODE_FAILED;
    for(i = 0; i < member->type->elements_count; i++) {
        asn_enc_rval_t child;
        if(SET_member_view(td, sptr, outer, (unsigned)i, &view) != 0)
            ASN__ENCODE_FAILED;
        child = _SET_xer_encode_view(td, sptr, &view, previous_bytes,
                                     ilevel, flags, cb, app_key);
        if(child.encoded < 0) return child;
        if(child.encoded > SSIZE_MAX - er.encoded) ASN__ENCODE_FAILED;
        er.encoded += child.encoded;
        if(child.encoded > SSIZE_MAX - previous_bytes) ASN__ENCODE_FAILED;
        previous_bytes += child.encoded;
    }
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: dispatch one ordered SET member to its direct or group encoder.
 * Source: SET member flags and transparent extension-group storage.
 * Version: 2026-10-22.
 * Parameters: td/sptr identify the value; outer selects a parent component;
 *             previous_bytes/ilevel/flags control formatting; cb/app_key
 *             receive encoded bytes.
 * Returns: encoded byte count, zero for an absent optional member, or failure.
 * Errors: invalid member views and child encoders return failure.
 * Author: asn1c maintainers.
 * History: Added to flatten members outside the public encoder loop.
 * Example: a direct member uses one wrapper, while a group emits its leaves.
 */
static asn_enc_rval_t
_SET_xer_encode_member(const asn_TYPE_descriptor_t *td, const void *sptr,
                       unsigned outer, ssize_t previous_bytes, int ilevel,
                       enum xer_encoder_flags_e flags,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    asn_SET_member_view_t view;

    if(td->elements[outer].flags & ATF_EXTENSION_GROUP)
        return _SET_xer_encode_group(td, sptr, outer, previous_bytes, ilevel,
                                     flags, cb, app_key);
    if(SET_member_view(td, sptr, outer, ASN_SET_DIRECT_MEMBER, &view) != 0)
        ASN__ENCODE_FAILED;
    return _SET_xer_encode_view(td, sptr, &view, previous_bytes, ilevel, flags,
                                cb, app_key);
}

/*
 * Purpose: XER-encode SET contents in parent order, flattening group leaves.
 * Source: SET tag2el_cxer ordering and generated group member descriptors.
 * Version: 2026-10-22.
 * Parameters: td/sptr describe the SET; ilevel/flags select formatting;
 *             cb/app_key receive the XML bytes.
 * Returns: encoded byte count or an encoding failure result.
 * Errors: invalid descriptors, absent mandatory values, child and callback
 *         failures return an encoding error.
 * Author: asn1c maintainers.
 * History: Reworked to flatten groups and materialize canonical defaults.
 * Example: each group leaf is emitted at the group's parent ordering position.
 */
asn_enc_rval_t
SET_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
               enum xer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
               void *app_key) {
    const asn_SET_specifics_t *specs;
    const asn_TYPE_tag2member_t *order;
    size_t order_count;
    size_t i;
    asn_enc_rval_t er = {0, 0, 0};

    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !sptr
    || !td->specifics
    || (td->elements_count && !td->elements)) ASN__ENCODE_FAILED;
    specs = (const asn_SET_specifics_t *)td->specifics;
    order = specs->tag2el_cxer;
    order_count = specs->tag2el_cxer_count;
    if(order_count != td->elements_count
    || (order_count && !order)) ASN__ENCODE_FAILED;
    /* A present open member must follow every sibling in the emitted order. */
    for(i = 0; i < order_count; i++) {
        unsigned outer = order[i].el_no;
        asn_SET_member_view_t view;
        if(outer >= td->elements_count) ASN__ENCODE_FAILED;
        if(!(td->elements[outer].flags & ATF_OPEN_TYPE)) continue;
        if(SET_member_view(td, sptr, outer, ASN_SET_DIRECT_MEMBER, &view)) ASN__ENCODE_FAILED;
        if(view.present && i + 1 != order_count) ASN__ENCODE_FAILED;
    }
    XER_ENCODER_RECURSION_DEPTH_INC();

    for(i = 0; i < order_count; i++) {
        unsigned outer = order[i].el_no;
        asn_enc_rval_t child;

        if(outer >= td->elements_count) goto failed;
        child = _SET_xer_encode_member(td, sptr, outer, er.encoded, ilevel,
                                       flags, cb, app_key);
        if(child.encoded < 0) {
            XER_ENCODER_RECURSION_DEPTH_DEC();
            return child;
        }
        if(child.encoded > SSIZE_MAX - er.encoded) goto failed;
        er.encoded += child.encoded;
    }
    XER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODED_OK(er);
failed:
    XER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODE_FAILED;
}
