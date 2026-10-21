/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h> /* for .bits_unused member */
#include <ObjectDescriptor.h>
#include <UTF8String.h>
#include <NumericString.h>
#include <PrintableString.h>
#include <T61String.h>
#include <TeletexString.h>
#include <VideotexString.h>
#include <IA5String.h>
#include <UTCTime.h>
#include <GeneralizedTime.h>
#include <GraphicString.h>
#include <VisibleString.h>
#include <ISO646String.h>
#include <GeneralString.h>
#include <UniversalString.h>
#include <BMPString.h>
#include <limits.h>

/* Private `bits_chopped` states for explicit frames that cannot carry BIT data. */
#define OS_EXPLICIT_FRAME_EMPTY 2
#define OS_EXPLICIT_FRAME_HAS_CHILD 3

/* Map built-in string operations to their CER component universal tags. */
struct octet_string_fragment_tag {
    const asn_TYPE_operation_t *operation; /* Built-in value operation table. */
    ber_tlv_tag_t tag; /* Universal tag used by constructed string components. */
};

static const struct octet_string_fragment_tag octet_string_fragment_tags[] = {
    {&asn_OP_BIT_STRING, ASN_TAG_CLASS_UNIVERSAL | (3u << 2)},
    {&asn_OP_OCTET_STRING, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_ObjectDescriptor, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_UTF8String, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_NumericString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_PrintableString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_T61String, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_TeletexString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_VideotexString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_IA5String, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_UTCTime, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_GeneralizedTime, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_GraphicString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_VisibleString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_ISO646String, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_GeneralString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_UniversalString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)},
    {&asn_OP_BMPString, ASN_TAG_CLASS_UNIVERSAL | (4u << 2)}
};

#undef _CH_PHASE
#define _CH_PHASE(ctx, inc) do {\
        if(ctx->phase == 0)\
            ctx->context = 0;\
        ctx->phase += inc;\
    } while(0)

#undef NEXT_PHASE
#define NEXT_PHASE(ctx) _CH_PHASE(ctx, +1)
#undef PREV_PHASE
#define PREV_PHASE(ctx) _CH_PHASE(ctx, -1)

/*
 * The main reason why ASN.1 is still alive is that too much time and effort
 * is necessary for learning it more or less adequately, thus creating a gut
 * necessity to demonstrate that acquired skill everywhere afterwards.
 * No, I am not going to explain what the following stuff is.
 */
/*
 * Select or allocate the next constructed-string parser frame.
 * Original source: Existing asn1c OCTET STRING BER decoder.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: st owns the frame chain and current cursor.
 * Returns: The next initialized frame, or NULL when allocation fails.
 * Errors: Allocation failure is returned as NULL.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: the BER decoder calls this before parsing a nested string chunk.
 */
static struct _stack_el *
OS__add_stack_el(struct _stack *st) {
    struct _stack_el *nel;

    /*
     * Reuse the old stack frame or allocate a new one.
     */
    if(st->cur_ptr && st->cur_ptr->next) {
        nel = st->cur_ptr->next;
        nel->bits_chopped = 0;
        nel->got = 0;
        /* Retain the nel->cont_level, it's correct. */
    } else {
        nel = (struct _stack_el *)CALLOC(1, sizeof(struct _stack_el));
        if(nel == NULL)
            return NULL;

        if(st->tail) {
            /* Increase a subcontainment depth */
            nel->cont_level = st->tail->cont_level + 1;
            st->tail->next = nel;
        }
        nel->prev = st->tail;
        st->tail = nel;
    }

    st->cur_ptr = nel;

    return nel;
}

/*
 * Allocate a constructed-string frame stack for incremental BER decoding.
 * Original source: Existing asn1c OCTET STRING BER decoder.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: None.
 * Returns: A zero-initialized stack, or NULL when allocation fails.
 * Errors: Allocation failure is reported by a NULL return value.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: OCTET_STRING_decode_ber uses it for constructed string values.
 */
static struct _stack *
_new_stack(void) {
    return (struct _stack *)CALLOC(1, sizeof(struct _stack));
}

/*
 * Find an explicit wrapper whose following tags remain descriptor-checked.
 * Original source: New BER/CER compatibility helper, following X.690 8.1.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/tags describe the string; ptr/size bound input; tag_mode
 *             selects an unknown member wrapper or a descriptor outer tag.
 * Returns: Positive T+L width for a constructed TLV, otherwise 0.
 * Errors: Malformed/incomplete headers return 0 for normal-checker handling.
 * Responsible party: asn1c maintainers. History: Added for CER explicit wrappers.
 * Example: detects a mode-0 explicit tag and leaves inner tags for stack checks.
 */
static ssize_t
OCTET_STRING__explicit_wrapper_header(
    const asn_TYPE_descriptor_t *td, const void *ptr, size_t size,
    int tag_mode, int *descriptor_tag_skip, ber_tlv_len_t *wrapper_length) {
    ber_tlv_tag_t tag;
    ber_tlv_len_t length;
    ssize_t tag_size;
    ssize_t length_size;
    int constructed;

    if(!td || !descriptor_tag_skip || !wrapper_length) return 0;
    *descriptor_tag_skip = 0;
    *wrapper_length = 0;
    if(tag_mode != 0 && tag_mode != 1 && tag_mode != -1) return 0;
    if((tag_mode == 0 || tag_mode == -1) && td->tags_count < 2) return 0;
    if((tag_mode == 0 || tag_mode == -1) && !td->tags) return 0;
    tag_size = ber_fetch_tag(ptr, size, &tag);
    if(tag_size <= 0) return 0;
    if(tag_mode == 0 && tag != td->tags[0]) return 0;
    constructed = BER_TLV_CONSTRUCTED(ptr);
    if(!constructed) return 0;
    length_size = ber_fetch_length(constructed,
                                   (const char *)ptr + tag_size,
                                   size - (size_t)tag_size, &length);
    if(length_size <= 0 || length < -1) return 0;
    *descriptor_tag_skip = (tag_mode != 1);
    *wrapper_length = length;
    return tag_size + length_size;
}

/*
 * Seed string parsing with an expectation for an open explicit wrapper.
 * Original source: New BER/CER compatibility helper, following X.690 8.1.3.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: ctx stores phase/bounds/stack; tag_skip counts skipped tags;
 *             variant determines whether the wrapper needs one-child checks;
 *             header_size and wrapper_length initialize the outer frame.
 * Returns: 0 after installing an outer frame, otherwise -1.
 * Errors: Allocation failure returns -1; caller reports RC_FAIL.
 * Responsible party: asn1c maintainers. History: Added for CER explicit wrappers;
 * version 1.1 exempts opaque ANY wrappers from typed one-child accounting.
 * Example: an empty A0 00 wrapper is retained for ASN_OSUBV_ANY.
 */
static int
OCTET_STRING__seed_explicit_wrapper(asn_struct_ctx_t *ctx, int tag_skip,
                                    enum asn_OS_Subvariant variant,
                                    ssize_t header_size,
                                    ber_tlv_len_t wrapper_length) {
    struct _stack *stck = _new_stack();
    struct _stack_el *wrapper;

    if(!stck || header_size < 0 || wrapper_length < -1
    || (size_t)header_size > ((size_t)-1 >> 1)) {
        FREEMEM(stck);
        return -1;
    }
    wrapper = OS__add_stack_el(stck);
    if(!wrapper) {
        FREEMEM(stck);
        return -1;
    }
    wrapper->left = wrapper_length;
    wrapper->want_nulls = wrapper_length == -1;
    if(variant != ASN_OSUBV_ANY)
        wrapper->bits_chopped = OS_EXPLICIT_FRAME_EMPTY;
    wrapper->cont_level = (unsigned)tag_skip;
    wrapper->got = header_size;
    ctx->left = -1;
    ctx->ptr = stck;
    return 0;
}

/*
 * State carried between bounded OCTET STRING decoder phases.
 * Original source: asn1c BER decoder state, split from its phase machine.
 * Version/date: 1.1, 2026-10-11. Responsible party: asn1c maintainers.
 * History/example: Added state members for explicit CER wrapper support.
 */
struct OCTET_STRING_ber_state {
    const asn_TYPE_descriptor_t *td; /* state variable: descriptor being decoded. */
    BIT_STRING_t *st; /* state variable: shared string value prefix. */
    asn_struct_ctx_t *ctx; /* state variable: incremental parser context. */
    const uint8_t *buf_ptr; /* state variable: current input cursor. */
    size_t size; /* state variable: readable bytes at the cursor. */
    ssize_t consumed; /* state variable: bytes stored from this call. */
    int tag_mode; /* state variable: BER implicit/explicit tag mode. */
    int tlv_constr; /* state variable: last header's constructed form. */
    struct _stack *stck; /* state variable: constructed-value expectations. */
    struct _stack_el *sel; /* state variable: active expectation. */
    enum asn_OS_Subvariant variant; /* state variable: string value kind. */
};

/*
 * Build a decoder result with the input progress already stored in state.
 * Original source: New local helper for the OCTET STRING BER phase machine.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state contains consumed input; code is the decoder status.
 * Returns: A result with the requested status and consumed byte count.
 * Errors: None; the caller supplies RC_OK, RC_WMORE, or RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: shared phase result.
 */
static asn_dec_rval_t
octet_string_ber_result(const struct OCTET_STRING_ber_state *state,
                        enum asn_dec_rval_code_e code) {
    asn_dec_rval_t rval;
    rval.code = code;
    rval.consumed = state->consumed;
    return rval;
}

/*
 * Advance the decoder cursor after checking input and count bounds.
 * Original source: New local helper replacing the decoder ADVANCE macro.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state owns the cursor; amount is the requested byte count.
 * Returns: 0 after advancing; -1 for invalid pointers, bounds, or overflow.
 * Errors: No input is read; invalid progress is rejected.
 * Responsible party: asn1c maintainers. History/example: phase cursor update.
 */
static int
octet_string_ber_advance(struct OCTET_STRING_ber_state *state,
                          size_t amount) {
    size_t max_count = ((size_t)-1) >> 1;

    if(amount > state->size || amount > max_count - (size_t)state->consumed)
        return -1;
    if(amount) {
        if(!state->buf_ptr) return -1;
        state->buf_ptr += amount;
    }
    state->size -= amount;
    state->consumed += (ssize_t)amount;
    return 0;
}

/*
 * Append bounded decoded content while maintaining a nul terminator.
 * Original source: New checked form of the OCTET STRING APPEND macro.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state owns the string and capacity; data/amount describe bytes.
 * Returns: 0 after appending; -1 for invalid sizes or allocation failure.
 * Errors: Rejects negative/capacity-overflow state and failed reallocation.
 * Responsible party: asn1c maintainers. History/example: handles empty BIT data.
 */
static int
octet_string_ber_append(struct OCTET_STRING_ber_state *state,
                         const void *data, size_t amount) {
    size_t current;
    size_t needed;
    size_t capacity;
    uint8_t *buffer;

    if((!data && amount) || state->ctx->context < 0) return -1;
    current = state->st->size;
    if((current && !state->st->buf) || current >= (size_t)INT_MAX
    || amount > (size_t)INT_MAX - 1 - current)
        return -1;
    needed = current + amount;
    capacity = (size_t)state->ctx->context;
    if(capacity <= needed || !state->st->buf) {
        capacity = capacity ? capacity : 16;
        while(capacity <= needed) {
            if(capacity > (size_t)INT_MAX / 2) {
                capacity = needed + 1;
                break;
            }
            capacity <<= 1;
        }
        if(capacity <= needed || capacity > (size_t)INT_MAX) return -1;
        buffer = (uint8_t *)REALLOC(state->st->buf, capacity);
        if(!buffer) return -1;
        state->st->buf = buffer;
        state->ctx->context = (int)capacity;
    }
    if(amount) memcpy(state->st->buf + current, data, amount);
    state->st->buf[needed] = '\0';
    state->st->size = needed;
    return 0;
}

/*
 * Parse the initial string tag or seed a CER explicit-wrapper stack.
 * Original source: New bounded phase extracted from OCTET_STRING_decode_ber.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: state carries descriptor/input; opt_codec_ctx bounds BER tags.
 * Returns: RC_OK when the next phase is ready, otherwise BER status.
 * Errors: Invalid descriptors, malformed headers, depth overflow, or allocation.
 * Responsible party: asn1c maintainers. History/example: accepts [5] EXPLICIT.
 */
static asn_dec_rval_t
octet_string_ber_phase0(struct OCTET_STRING_ber_state *state,
                        const asn_codec_ctx_t *opt_codec_ctx) {
    asn_dec_rval_t rval;
    ssize_t explicit_header; /* state variable: detected outer header width. */
    int descriptor_tag_skip; /* state variable: named descriptor layers skipped. */
    ber_tlv_len_t wrapper_length; /* state variable: outer frame content size. */

    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
        return octet_string_ber_result(state, RC_FAIL);
    explicit_header = OCTET_STRING__explicit_wrapper_header(
        state->td, state->buf_ptr, state->size, state->tag_mode,
        &descriptor_tag_skip, &wrapper_length);
    if(explicit_header > 0) {
        if(((state->tag_mode == 0 || state->tag_mode == -1)
            && state->td->tags_count > BER_EXPLICIT_TAG_DEPTH_LIMIT)
        || (state->tag_mode == 1
            && state->td->tags_count >= BER_EXPLICIT_TAG_DEPTH_LIMIT))
            return octet_string_ber_result(state, RC_FAIL);
        if(OCTET_STRING__seed_explicit_wrapper(state->ctx,
                descriptor_tag_skip, state->variant, explicit_header,
                wrapper_length))
            return octet_string_ber_result(state, RC_FAIL);
        state->tlv_constr = 1;
        if(octet_string_ber_advance(state, (size_t)explicit_header))
            return octet_string_ber_result(state, RC_FAIL);
        NEXT_PHASE(state->ctx);
        return octet_string_ber_result(state, RC_OK);
    }

    rval = ber_check_tags(opt_codec_ctx, state->td, state->ctx,
                          state->buf_ptr, state->size, state->tag_mode, -1,
                          &state->ctx->left, &state->tlv_constr);
    if(rval.code != RC_OK) return rval;
    if(state->tlv_constr) {
        state->ctx->ptr = _new_stack();
        if(!state->ctx->ptr)
            return octet_string_ber_result(state, RC_FAIL);
        NEXT_PHASE(state->ctx);
        return octet_string_ber_result(state, RC_OK);
    }

    _CH_PHASE(state->ctx, 3);
    if(state->variant == ASN_OSUBV_ANY && state->tag_mode != 1
    && octet_string_ber_append(state, state->buf_ptr, rval.consumed))
        return octet_string_ber_result(state, RC_FAIL);
    if(octet_string_ber_advance(state, rval.consumed))
        return octet_string_ber_result(state, RC_FAIL);
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Move from a completed constructed string child to its parent frame.
 * Original source: New checked helper extracted from the BER stack loop.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state contains the selected frame and expectation stack.
 * Returns: 1 to parse/continue, 0 when the stack is complete, -1 on bad state.
 * Errors: Rejects inconsistent lengths and accounting overflow.
 * Responsible party: asn1c maintainers. History/example: closes nested chunks.
 */
static int
octet_string_ber_unwind(struct OCTET_STRING_ber_state *state) {
    size_t max_count = ((size_t)-1) >> 1;

    /*
     * Each completed child contributes its full encoded size to its parent.
     * Keep closing parents that are also complete before asking for input.
     */
    for(;;) {
        struct _stack_el *sel = state->sel;
        struct _stack_el *prev;

        if(!sel) return state->stck->tail ? 0 : 1;
        if(sel->left < -1 || sel->got < 0 || sel->want_nulls < 0
        || sel->want_nulls > 1)
            return -1;
        if(sel->left > 0 || sel->want_nulls) return 1;
        if(sel->bits_chopped == OS_EXPLICIT_FRAME_EMPTY) return -1;
        if(!sel->prev) {
            state->sel = state->stck->cur_ptr = 0;
            return 0;
        }

        prev = sel->prev;
        if(prev->left < -1 || prev->got < 0) return -1;
        if(prev->left != -1) {
            if(prev->left < sel->got) return -1;
            prev->left -= sel->got;
        }
        if(prev->bits_chopped == OS_EXPLICIT_FRAME_EMPTY)
            prev->bits_chopped = OS_EXPLICIT_FRAME_HAS_CHILD;
        if((size_t)sel->got > max_count - (size_t)prev->got) return -1;
        prev->got += sel->got;
        state->sel = state->stck->cur_ptr = prev;
        state->tlv_constr = 1;
    }
}

/*
 * Select the tag expected at the current constructed-string nesting level.
 * Original source: New helper extracted from the OCTET STRING BER tag switch.
 * Version/date: 1.1, 2026-10-21.
 * Parameters: state supplies descriptor and frame; actual is the fetched tag.
 * Returns: Effective descriptor tag for strings, or actual for untyped ANY.
 * Errors: None; malformed descriptor arrays are rejected by decoder entry.
 * Responsible party: asn1c maintainers. History: version 1.1 uses the effective
 * `tags` chain instead of `all_tags`, which may contain superseded explicit
 * wrapper tags (ASN1-0017).
 * Example: validates chunks.
 */
static ber_tlv_tag_t
octet_string_ber_expected_tag(const struct OCTET_STRING_ber_state *state,
                              ber_tlv_tag_t actual) {
    unsigned level;

    if(state->variant == ASN_OSUBV_ANY || !state->sel) return actual;
    level = state->sel->cont_level;
    if(level < state->td->tags_count)
        return state->td->tags[level];
    if(state->td->tags_count)
        return state->td->tags[state->td->tags_count - 1];
    return actual;
}

/*
 * Find the CER component tag associated with a built-in string operation.
 * Original source: New asn1c BER/CER tag resolver, following X.690 8.23.3.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: td identifies the operation table; tag receives the component tag.
 * Returns: 1 when a built-in operation is recognized, otherwise 0.
 * Errors: None; unknown/custom operations remain descriptor-only.
 * Responsible party: asn1c maintainers. History: Maps character components to 4.
 * Example: resolves UTF8String to OCTET STRING tag 4 and BIT STRING to tag 3.
 */
static int
octet_string_ber_fragment_tag(const asn_TYPE_descriptor_t *td,
                              ber_tlv_tag_t *tag) {
    size_t index;

    if(!td || !td->op || !tag) return 0;
    for(index = 0; index < sizeof(octet_string_fragment_tags)
                          / sizeof(octet_string_fragment_tags[0]); index++) {
        if(td->op == octet_string_fragment_tags[index].operation) {
            *tag = octet_string_fragment_tags[index].tag;
            return 1;
        }
    }
    return 0;
}

/*
 * Match descriptor prefixes or legal OCTET/BIT STRING component tags.
 * Original source: New asn1c BER/CER compatibility helper, following X.690 9.2.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: state identifies the active frame; actual/expected are wire tags.
 * Returns: 1 for an exact descriptor tag or the operation's component tag.
 * Errors: Custom operations and explicit wrappers receive no fallback.
 * Responsible party: asn1c maintainers. History: Rejects natural UTF8 chunks.
 * Example: accepts UTF8String components with tag 4, never tag 12 by fallback.
 */
static int
octet_string_ber_child_tag_matches(
    const struct OCTET_STRING_ber_state *state, ber_tlv_tag_t actual,
    ber_tlv_tag_t expected) {
    ber_tlv_tag_t fragment_tag;

    if(actual == expected) return 1;
    if(!state->sel
    || state->sel->bits_chopped == OS_EXPLICIT_FRAME_EMPTY
    || state->sel->bits_chopped == OS_EXPLICIT_FRAME_HAS_CHILD)
        return 0;
    return octet_string_ber_fragment_tag(state->td, &fragment_tag)
        && actual == fragment_tag;
}

/*
 * One fully read child tag/length pair bounded by its containing frame.
 * Original source: New OCTET STRING BER phase parser state.
 * Version/date: 1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History/example: Split from child processing to keep validation bounded.
 */
struct OCTET_STRING_ber_header {
    ber_tlv_tag_t tag; /* state variable: child tag. */
    ber_tlv_len_t length; /* state variable: child length or indefinite marker. */
    ssize_t tag_size; /* state variable: encoded tag width. */
    ssize_t length_size; /* state variable: encoded length width. */
    size_t frame_size; /* state variable: readable bytes in parent frame. */
    int constructed; /* state variable: child's P/C bit. */
};

/*
 * Fetch a child header without advancing the caller's input cursor.
 * Original source: New bounded helper extracted from OCTET STRING stack parsing.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state supplies input/frame; header receives parsed T and L.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL; input progress remains unchanged.
 * Errors: Invalid stack bounds, malformed tags, and malformed lengths fail.
 * Responsible party: asn1c maintainers. History/example: parses chunk headers.
 */
static asn_dec_rval_t
octet_string_ber_read_header(struct OCTET_STRING_ber_state *state,
                             struct OCTET_STRING_ber_header *header) {
    ssize_t fetched;

    if(state->sel && state->sel->left < -1)
        return octet_string_ber_result(state, RC_FAIL);
    header->frame_size = state->size;
    if(state->sel && state->sel->left >= 0
    && (size_t)state->sel->left < header->frame_size)
        header->frame_size = (size_t)state->sel->left;
    fetched = ber_fetch_tag(state->buf_ptr, header->frame_size, &header->tag);
    if(fetched < 0) return octet_string_ber_result(state, RC_FAIL);
    if(fetched == 0) return octet_string_ber_result(state, RC_WMORE);
    header->tag_size = fetched;
    header->constructed = BER_TLV_CONSTRUCTED(state->buf_ptr);
    fetched = ber_fetch_length(header->constructed,
        (const char *)state->buf_ptr + header->tag_size,
        header->frame_size - (size_t)header->tag_size, &header->length);
    if(fetched < 0) return octet_string_ber_result(state, RC_FAIL);
    if(fetched == 0) return octet_string_ber_result(state, RC_WMORE);
    header->length_size = fetched;
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Validate an exact two-octet primitive universal tag-zero EOC.
 * Original source: New helper for strict constructed-string EOC handling.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state supplies bytes; header holds the previously parsed T/L.
 * Returns: 1 only for the exact 00 00 encoding; otherwise 0.
 * Errors: Does not advance or modify decoder state.
 * Responsible party: asn1c maintainers. History/example: rejects long-form EOC.
 */
static int
octet_string_ber_exact_eoc(const struct OCTET_STRING_ber_state *state,
                           const struct OCTET_STRING_ber_header *header) {
    if(header->constructed || header->tag_size != 1
    || header->length_size != 1 || header->frame_size < 2)
        return 0;
    if(!state->buf_ptr || state->buf_ptr[0] != 0 || state->buf_ptr[1] != 0)
        return 0;
    return 1;
}

/*
 * Check EOC counters and parent length before closing one stack frame.
 * Original source: New helper for strict constructed-string EOC handling.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: sel is the active frame receiving an EOC pair.
 * Returns: 1 for valid counters; 0 for inconsistent state.
 * Errors: Rejects invalid lengths/counts before input or value mutation.
 * Responsible party: asn1c maintainers. History/example: guards EOC updates.
 */
static int
octet_string_ber_valid_eoc_state(const struct _stack_el *sel) {
    size_t max_count = ((size_t)-1) >> 1;

    if(sel->got < 0 || sel->got > (ber_tlv_len_t)(max_count - 2)) return 0;
    if(sel->left < -1 || (sel->left != -1 && sel->left < 2)) return 0;
    return sel->want_nulls == 1;
}

/*
 * Identify stack frames for explicit wrappers that must contain one TLV.
 * Original source: New helper for the bounded OCTET STRING BER decoder.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state supplies descriptor/tag mode; sel is the active frame.
 * Returns: Nonzero for unknown outer or named explicit wrapper frames.
 * Errors: None; invalid descriptors are rejected before stack parsing.
 * Responsible party: asn1c maintainers. History: Enforces explicit cardinality.
 * Example: a `[5] EXPLICIT OCTET STRING` frame accepts one inner TLV.
 */
static int
octet_string_ber_is_explicit_frame(
    const struct OCTET_STRING_ber_state *state,
    const struct _stack_el *sel) {
    if(!sel || state->variant == ASN_OSUBV_ANY) return 0;
    if(state->tag_mode == 1 && !sel->prev && !sel->cont_level) return 1;
    return state->td->tags_count > 1
        && sel->cont_level < state->td->tags_count;
}

/*
 * Consume one expected EOC and update its enclosing indefinite frame.
 * Original source: New bounded helper extracted from OCTET STRING stack parsing.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state owns the active frame; header is a validated T/L pair.
 * Returns: 1 when consumed, 0 when not an EOC, and -1 on invalid accounting.
 * Errors: Rejects malformed EOC bytes, frame lengths, and counter overflow.
 * Responsible party: asn1c maintainers. History/example: handles nested EOCs.
 */
static int
octet_string_ber_consume_eoc(struct OCTET_STRING_ber_state *state,
                              const struct OCTET_STRING_ber_header *header) {
    struct _stack_el *sel = state->sel;

    if(!sel || !sel->want_nulls || header->tag != 0 || header->length != 0)
        return 0;
    if(!octet_string_ber_exact_eoc(state, header)
    || !octet_string_ber_valid_eoc_state(sel)) return -1;
    if(octet_string_ber_is_explicit_frame(state, sel)
    && sel->bits_chopped != OS_EXPLICIT_FRAME_HAS_CHILD)
        return -1;
    if(state->variant == ASN_OSUBV_ANY
    && (state->tag_mode != 1 || sel->cont_level)
    && octet_string_ber_append(state, "\0\0", 2))
        return -1;
    if(octet_string_ber_advance(state, 2)) return -1;
    sel->got += 2;
    if(sel->left != -1) sel->left -= 2;
    sel->want_nulls--;
    state->tlv_constr = 1;
    if(!sel->want_nulls) sel->left = 0;
    return 1;
}

/*
 * Validate the fetched child tag and all lengths against its parent frame.
 * Original source: New bounded helper extracted from OCTET STRING stack parsing.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state supplies the expected tag; header contains fetched T/L.
 * Returns: 0 for a valid child; -1 for tag, length, or parent-bound failures.
 * Errors: No input or value state is changed.
 * Responsible party: asn1c maintainers. History/example: validates chunk bounds.
 */
static int
octet_string_ber_validate_child(
    const struct OCTET_STRING_ber_state *state,
    const struct OCTET_STRING_ber_header *header, ssize_t *tlv_size_out) {
    ber_tlv_tag_t expected_tag;
    size_t tlv_size;
    size_t total;
    size_t max_count = ((size_t)-1) >> 1;

    expected_tag = octet_string_ber_expected_tag(state, header->tag);
    if(!octet_string_ber_child_tag_matches(state, header->tag, expected_tag)
    || header->length < -1)
        return -1;
    if((size_t)header->tag_size > max_count - (size_t)header->length_size)
        return -1;
    tlv_size = (size_t)header->tag_size + (size_t)header->length_size;
    if(header->length >= 0
    && (size_t)header->length > max_count - tlv_size)
        return -1;
    if(state->sel && state->sel->left != -1) {
        if(state->sel->left < 0) return -1;
        total = tlv_size;
        if(header->length >= 0) total += (size_t)header->length;
        if((size_t)state->sel->left < total) return -1;
    }
    if(!header->constructed
    && ((state->tag_mode == 1 && !state->sel)
        || (state->td->tags_count > 1
            && (state->sel ? state->sel->cont_level : 0)
                < state->td->tags_count - 1)))
        return -1;
    *tlv_size_out = (ssize_t)tlv_size;
    return 0;
}

/*
 * Push a validated child and advance past its tag and length.
 * Original source: New bounded helper extracted from OCTET STRING stack parsing.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state owns stack/input; header and tlv_size are validated values.
 * Returns: RC_OK after advancing or RC_FAIL on allocation/accounting failure.
 * Errors: Failed stack allocation or invalid content counters return RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: enters each chunk.
 */
static asn_dec_rval_t
octet_string_ber_push_child(struct OCTET_STRING_ber_state *state,
                            const struct OCTET_STRING_ber_header *header,
                            ssize_t tlv_size) {
    struct _stack_el *sel;
    size_t max_count = ((size_t)-1) >> 1;

    if(state->sel
    && state->sel->cont_level >= BER_EXPLICIT_TAG_DEPTH_LIMIT)
        return octet_string_ber_result(state, RC_FAIL);
    sel = OS__add_stack_el(state->stck);
    if(!sel) return octet_string_ber_result(state, RC_FAIL);
    state->sel = sel;
    sel->tag = header->tag;
    sel->want_nulls = (header->length == -1);
    if(octet_string_ber_is_explicit_frame(state, sel))
        sel->bits_chopped = OS_EXPLICIT_FRAME_EMPTY;
    if(sel->prev && sel->prev->left != -1) {
        if(header->length == -1)
            sel->left = sel->prev->left - tlv_size;
        else
            sel->left = header->length;
    } else {
        sel->left = header->length;
    }
    if(sel->got < 0 || (size_t)tlv_size > max_count - (size_t)sel->got)
        return octet_string_ber_result(state, RC_FAIL);
    if(state->variant == ASN_OSUBV_ANY
    && (state->tag_mode != 1 || sel->cont_level)
    && octet_string_ber_append(state, state->buf_ptr, (size_t)tlv_size))
        return octet_string_ber_result(state, RC_FAIL);
    sel->got += tlv_size;
    state->tlv_constr = header->constructed;
    if(octet_string_ber_advance(state, (size_t)tlv_size))
        return octet_string_ber_result(state, RC_FAIL);
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Read one constructed-string child header and update its expectation stack.
 * Original source: New bounded helper extracted from the BER stack loop.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: state owns the cursor, active frame, and descriptor metadata.
 * Returns: RC_OK after a child/EOC; RC_WMORE or RC_FAIL on input problems.
 * Errors: Rejects malformed tag-zero encodings and EOCs outside active
 *         indefinite frames, plus impossible lengths and bad stack accounting.
 * Responsible party: asn1c maintainers. History: Added strict EOC handling
 * while preserving a bounded legacy ANY zero-pair value.
 * Example: rejects 00 01 as EOC but retains definite ANY bytes 00 00.
 */
static asn_dec_rval_t
octet_string_ber_read_child(struct OCTET_STRING_ber_state *state) {
    struct OCTET_STRING_ber_header header; /* state variable: fetched child. */
    asn_dec_rval_t rval;
    ssize_t tlv_size; /* state variable: encoded child header width. */
    int consumed_eoc; /* state variable: whether an EOC closed this frame. */

    rval = octet_string_ber_read_header(state, &header);
    if(rval.code != RC_OK) return rval;
    consumed_eoc = octet_string_ber_consume_eoc(state, &header);
    if(consumed_eoc < 0) return octet_string_ber_result(state, RC_FAIL);
    if(consumed_eoc) return octet_string_ber_result(state, RC_OK);
    if(header.tag == 0) {
        /* Keep legacy ANY bytes 00 00 only as a primitive in a definite frame. */
        if(state->variant != ASN_OSUBV_ANY || !state->sel
        || state->sel->left < 0
        || !octet_string_ber_exact_eoc(state, &header))
            return octet_string_ber_result(state, RC_FAIL);
    }
    if(octet_string_ber_is_explicit_frame(state, state->sel)
    && state->sel->bits_chopped == OS_EXPLICIT_FRAME_HAS_CHILD)
        return octet_string_ber_result(state, RC_FAIL);
    if(octet_string_ber_validate_child(state, &header, &tlv_size))
        return octet_string_ber_result(state, RC_FAIL);
    return octet_string_ber_push_child(state, &header, tlv_size);
}

/*
 * Process constructed-string headers until content or completion is reached.
 * Original source: New bounded phase extracted from OCTET_STRING_decode_ber.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state carries the incremental value and input.
 * Returns: RC_OK for the next phase, RC_WMORE for missing bytes, or RC_FAIL.
 * Errors: Invalid stack metadata and child TLVs return RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: handles CER EOCs.
 */
static asn_dec_rval_t
octet_string_ber_phase1(struct OCTET_STRING_ber_state *state) {
    asn_dec_rval_t rval;
    int active; /* state variable: whether a stack frame needs input. */

    state->stck = (struct _stack *)state->ctx->ptr;
    if(!state->stck) return octet_string_ber_result(state, RC_FAIL);
    state->sel = state->stck->cur_ptr;
    state->tlv_constr = 1;
    for(;;) {
        active = octet_string_ber_unwind(state);
        if(active < 0) return octet_string_ber_result(state, RC_FAIL);
        if(!active) {
            _CH_PHASE(state->ctx, +3);
            return octet_string_ber_result(state, RC_OK);
        }
        rval = octet_string_ber_read_child(state);
        if(rval.code != RC_OK) return rval;
        if(!state->tlv_constr) break;
    }
    NEXT_PHASE(state->ctx);
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Copy the current constructed-string payload into the decoded value.
 * Original source: New bounded phase extracted from OCTET_STRING_decode_ber.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state identifies frame, string storage, and available bytes.
 * Returns: RC_OK when the frame closes, RC_WMORE for incomplete content.
 * Errors: Invalid lengths or allocation/accounting failures return RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: handles BIT chunks.
 */
static asn_dec_rval_t
octet_string_ber_phase2(struct OCTET_STRING_ber_state *state) {
    struct _stack_el *sel;
    size_t length;
    size_t amount;
    size_t max_count = ((size_t)-1) >> 1;

    state->stck = (struct _stack *)state->ctx->ptr;
    if(!state->stck || !(sel = state->stck->cur_ptr))
        return octet_string_ber_result(state, RC_FAIL);
    if(sel->left < 0 || sel->got < 0)
        return octet_string_ber_result(state, RC_FAIL);
    length = (size_t)sel->left;
    amount = state->size < length ? state->size : length;
    if(amount) {
        if((size_t)sel->got > max_count - amount)
            return octet_string_ber_result(state, RC_FAIL);
        if(state->variant == ASN_OSUBV_BIT && !sel->bits_chopped) {
            state->st->bits_unused = state->buf_ptr[0];
            if(octet_string_ber_append(state, state->buf_ptr + 1, amount - 1))
                return octet_string_ber_result(state, RC_FAIL);
            sel->bits_chopped = 1;
        } else if(octet_string_ber_append(state, state->buf_ptr, amount)) {
            return octet_string_ber_result(state, RC_FAIL);
        }
        if(octet_string_ber_advance(state, amount))
            return octet_string_ber_result(state, RC_FAIL);
        sel->left -= (ber_tlv_len_t)amount;
        sel->got += (ssize_t)amount;
    }
    if(sel->left) return octet_string_ber_result(state, RC_WMORE);
    PREV_PHASE(state->ctx);
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Copy a primitive string payload, preserving unused-bit state across feeds.
 * Original source: New bounded phase extracted from OCTET_STRING_decode_ber.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state contains the primitive content length and input cursor.
 * Returns: RC_OK when complete, RC_WMORE while content remains, or RC_FAIL.
 * Errors: Invalid context lengths and append failures return RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: decodes primitive BIT.
 */
static asn_dec_rval_t
octet_string_ber_phase3(struct OCTET_STRING_ber_state *state) {
    size_t amount;
    size_t remaining;

    if(state->ctx->left < 0) return octet_string_ber_result(state, RC_FAIL);
    remaining = (size_t)state->ctx->left;
    if(state->size < remaining) {
        if(!state->size) return octet_string_ber_result(state, RC_WMORE);
        amount = state->size;
        if(state->variant == ASN_OSUBV_BIT && !state->ctx->context) {
            state->st->bits_unused = state->buf_ptr[0];
            state->ctx->left--;
            if(octet_string_ber_advance(state, 1))
                return octet_string_ber_result(state, RC_FAIL);
            amount--;
        }
        if(octet_string_ber_append(state, state->buf_ptr, amount))
            return octet_string_ber_result(state, RC_FAIL);
        if(octet_string_ber_advance(state, amount))
            return octet_string_ber_result(state, RC_FAIL);
        state->ctx->left -= (ber_tlv_len_t)amount;
        return octet_string_ber_result(state, RC_WMORE);
    }

    amount = remaining;
    if(state->variant == ASN_OSUBV_BIT && !state->ctx->context && amount) {
        state->st->bits_unused = state->buf_ptr[0];
        state->ctx->left--;
        amount--;
        if(octet_string_ber_advance(state, 1))
            return octet_string_ber_result(state, RC_FAIL);
    }
    if(octet_string_ber_append(state, state->buf_ptr, amount))
        return octet_string_ber_result(state, RC_FAIL);
    if(octet_string_ber_advance(state, amount))
        return octet_string_ber_result(state, RC_FAIL);
    state->ctx->left = 0;
    NEXT_PHASE(state->ctx);
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Validate completed stack state and finalize BIT STRING unused bits.
 * Original source: New bounded completion helper for OCTET_STRING_decode_ber.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state identifies decoded value, final stack, and input progress.
 * Returns: RC_OK when complete, RC_WMORE for open wrappers, or RC_FAIL.
 * Errors: Invalid stack completion or unused-bit metadata return RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: closes BIT decoding.
 */
static asn_dec_rval_t
octet_string_ber_finish(struct OCTET_STRING_ber_state *state) {
    struct _stack *stck = (struct _stack *)state->ctx->ptr;
    struct _stack_el *sel = stck ? stck->cur_ptr : 0;

    if(sel) {
        if(sel->left < -1) return octet_string_ber_result(state, RC_FAIL);
        if(sel->prev || sel->want_nulls > 1 || sel->left > 0)
            return octet_string_ber_result(state, RC_WMORE);
    }
    if(state->variant == ASN_OSUBV_BIT) {
        if(state->st->size) {
            if(!state->st->buf || state->st->bits_unused < 0
            || state->st->bits_unused > 7)
                return octet_string_ber_result(state, RC_FAIL);
            state->st->buf[state->st->size - 1] &=
                (uint8_t)(0xff << state->st->bits_unused);
        } else if(state->st->bits_unused) {
            return octet_string_ber_result(state, RC_FAIL);
        }
    }
    ASN_DEBUG("Took %ld bytes to encode %s: [%s]:%ld",
              (long)state->consumed, state->td->name,
              (state->variant == ASN_OSUBV_STR) ? (char *)state->st->buf
                                                : "<data>",
              (long)state->st->size);
    return octet_string_ber_result(state, RC_OK);
}

/*
 * Check descriptor layout and tag arrays before string decoder access.
 * Original source: New metadata guard for the OCTET STRING BER decoder.
 * Version/date: 1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * Parameters: td/specs describe storage; both must have internally consistent
 *             layout and tag arrays.
 * Returns: 1 when offsets, sizes, variants, and tag arrays are usable.
 * Errors: Returns 0 for null or inconsistent descriptor metadata.
 * History/example: Added before incremental CER wrapper handling.
 */
static int
OCTET_STRING__valid_ber_descriptor(
    const asn_TYPE_descriptor_t *td,
    const asn_OCTET_STRING_specifics_t *specs) {
    size_t context_offset;
    size_t minimum_size;

    if(!td || !specs) return 0;
    if(specs->subvariant < ASN_OSUBV_ANY || specs->subvariant > ASN_OSUBV_U32)
        return 0;
    context_offset = specs->subvariant == ASN_OSUBV_BIT
        ? offsetof(BIT_STRING_t, _asn_ctx)
        : offsetof(OCTET_STRING_t, _asn_ctx);
    minimum_size = context_offset + sizeof(asn_struct_ctx_t);
    if(specs->struct_size < minimum_size
    || specs->ctx_offset < context_offset
    || specs->ctx_offset > specs->struct_size - sizeof(asn_struct_ctx_t))
        return 0;
    if(td->tags_count > BER_EXPLICIT_TAG_DEPTH_LIMIT
    || td->all_tags_count > BER_EXPLICIT_TAG_DEPTH_LIMIT
    || (td->tags_count && !td->tags)
    || (td->all_tags_count && !td->all_tags))
        return 0;
    return 1;
}

/*
 * Run the incremental string decoder until it needs more input or completes.
 * Original source: New dispatcher split from OCTET_STRING_decode_ber.
 * Version/date: 1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * Parameters: state holds value/input; opt_codec_ctx bounds BER tag checking.
 * Returns: RC_OK on completion, RC_WMORE for input shortage, or RC_FAIL.
 * Errors: Invalid phase/state and phase helper errors propagate as RC_FAIL.
 * History/example: dispatches phase 0 through the finalization phase.
 */
static asn_dec_rval_t
octet_string_ber_run(struct OCTET_STRING_ber_state *state,
                     const asn_codec_ctx_t *opt_codec_ctx) {
    asn_dec_rval_t rval;

    for(;;) {
        switch(state->ctx->phase) {
        case 0:
            rval = octet_string_ber_phase0(state, opt_codec_ctx);
            break;
        case 1:
            rval = octet_string_ber_phase1(state);
            break;
        case 2:
            rval = octet_string_ber_phase2(state);
            break;
        case 3:
            rval = octet_string_ber_phase3(state);
            break;
        case 4:
            return octet_string_ber_finish(state);
        default:
            return octet_string_ber_result(state, RC_FAIL);
        }
        if(rval.code != RC_OK) return rval;
    }
}

/*
 * Decode an OCTET STRING-family value with bounded incremental phases.
 * Original source: asn1c OCTET STRING BER decoder with mixed CER wrappers.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: opt_codec_ctx bounds decoder stack; td/sptr describe output;
 *             buf_ptr/size provide input; tag_mode selects tag handling.
 * Returns: RC_OK on completion, RC_WMORE with stored progress, or RC_FAIL.
 * Errors: Rejects malformed metadata, tags, lengths, EOCs, and allocation errors.
 * Responsible party: asn1c maintainers. History: Added mixed CER wrapper support.
 * Example: incrementally decodes an indefinite explicit OCTET STRING wrapper.
 */
asn_dec_rval_t
OCTET_STRING_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td, void **sptr,
                        const void *buf_ptr, size_t size, int tag_mode) {
    const asn_OCTET_STRING_specifics_t *specs;
    struct OCTET_STRING_ber_state state; /* state variable: current decode. */
    asn_dec_rval_t rval;

    if(!td || !sptr || tag_mode < -1 || tag_mode > 1
    || (!buf_ptr && size)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }
    specs = td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                          : &asn_SPC_OCTET_STRING_specs;
    if(!OCTET_STRING__valid_ber_descriptor(td, specs)) {
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    memset(&state, 0, sizeof(state));
    state.td = td;
    state.st = (BIT_STRING_t *)*sptr;
    state.buf_ptr = (const uint8_t *)buf_ptr;
    state.size = size;
    state.tag_mode = tag_mode;
    state.variant = specs->subvariant;
    if(!state.st) {
        state.st = (BIT_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!state.st) return octet_string_ber_result(&state, RC_FAIL);
    }
    state.ctx = (asn_struct_ctx_t *)((char *)state.st + specs->ctx_offset);
    return octet_string_ber_run(&state, opt_codec_ctx);
}

/*
 * Encode an OCTET STRING-family value using DER.
 * Original source: Existing asn1c OCTET STRING DER encoder.
 * Version/date: 1.1, 2026-10-11.
 * Parameters: td describes the string; sptr points to its value; tag_mode/tag
 *             control tagging; cb/app_key receive encoded bytes.
 * Returns: DER encoding result, or failure details when encoding fails.
 * Errors: Invalid string storage, tag generation, or callback failures fail.
 * Responsible party: asn1c maintainers. History: Documentation completed.
 * Example: encodes an OCTET STRING using its universal or descriptor tag.
 */
asn_enc_rval_t
OCTET_STRING_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int tag_mode, ber_tlv_tag_t tag,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = { 0, 0, 0 };
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_OCTET_STRING_specs;
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    enum asn_OS_Subvariant type_variant = specs->subvariant;
    int fix_last_byte = 0;

    ASN_DEBUG("%s %s as OCTET STRING",
              cb?"Estimating":"Encoding", td->name);

    /*
     * Write tags.
     */
    if(type_variant != ASN_OSUBV_ANY || tag_mode == 1) {
        er.encoded = der_write_tags(td,
                                    (type_variant == ASN_OSUBV_BIT) + st->size,
                                    tag_mode, type_variant == ASN_OSUBV_ANY, tag,
                                    cb, app_key);
        if(er.encoded == -1) {
            er.failed_type = td;
            er.structure_ptr = sptr;
            return er;
        }
    } else {
        /* Disallow: [<tag>] IMPLICIT ANY */
        assert(type_variant != ASN_OSUBV_ANY || tag_mode != -1);
        er.encoded = 0;
    }

    if(!cb) {
        er.encoded += (type_variant == ASN_OSUBV_BIT) + st->size;
        ASN__ENCODED_OK(er);
    }

    /*
     * Prepare to deal with the last octet of BIT STRING.
     */
    if(type_variant == ASN_OSUBV_BIT) {
        uint8_t b = st->bits_unused & 0x07;
        if(b && st->size) fix_last_byte = 1;
        ASN__CALLBACK(&b, 1);
    }

    /* Invoke callback for the main part of the buffer */
    ASN__CALLBACK(st->buf, st->size - fix_last_byte);

    /* The last octet should be stripped off the unused bits */
    if(fix_last_byte) {
        uint8_t b = st->buf[st->size-1] & (0xff << st->bits_unused);
        ASN__CALLBACK(&b, 1);
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
