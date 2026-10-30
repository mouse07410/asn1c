/* Copyright (c) 2017 Lev Walkin; 2026 asn1c contributors.
 * Redistribution and modifications are permitted subject to BSD license. */
#include <asn_internal.h>
#include <constr_SET.h>
#include <string.h>

/* pjson_parse state ST_VALUE_BODY in jer_support.c; consumed value precedes delimiter. */
#define SET_JER_TOKENIZER_VALUE_BODY 5

#define JER_MEMBER_NAME(elm) \
    (((elm)->encoding_constraints.jer_constraints && (elm)->encoding_constraints.jer_constraints->wire_name) \
        ? (elm)->encoding_constraints.jer_constraints->wire_name : (elm)->name)

/*
 * Purpose: locate a direct SET member or transparent group leaf by JER name.
 * Source: generated SET member descriptors and X.697 clauses 27 and 29.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st identify the SET; key/len
 * describe the token; outer/child receive indexes. Returns: 1 match, 0 unknown,
 * -1 malformed. Exceptions: none. Author: asn1c maintainers.
 * History: added for flat group routing. Example: first selects ext1.first.
 */
static int
SET_jer_find(const asn_TYPE_descriptor_t *td, const void *st, const void *key, size_t len,
             unsigned *outer, unsigned *child) {
    size_t i, j;
    int found = 0;
    if(len > INT_MAX) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        unsigned count = (member->flags & ATF_EXTENSION_GROUP) && member->type
            ? member->type->elements_count : 1;
        if(!count) return -1;
        for(j = 0; j < count; j++) {
            asn_SET_member_view_t view;
            unsigned index = (member->flags & ATF_EXTENSION_GROUP) ? (unsigned)j : ASN_SET_DIRECT_MEMBER;
            if(SET_member_view(td, st, (unsigned)i, index, &view) || !JER_MEMBER_NAME(view.member)) return -1;
            if(jer_check_sym(key, (int)len, JER_MEMBER_NAME(view.member)) == JCK_KEY) {
                if(found) return -1;
                *outer = (unsigned)i;
                *child = index;
                found = 1;
            }
        }
    }
    return found;
}

/*
 * Purpose: recover the group leaf stored in a suspended decoder context.
 * Source: static descriptor pointers and SET context contract.
 * Version/date: 1.0, 2026-10-30. Inputs: td/ctx select the member; child
 * receives its index. Returns: zero or -1 on invalid state. Exceptions: none.
 * Author: asn1c maintainers. History: added for resumable JER groups.
 * Example: ctx->ptr identifies the selected group's leaf.
 */
static int
SET_jer_child(const asn_TYPE_descriptor_t *td, const asn_struct_ctx_t *ctx, unsigned *child) {
    const asn_TYPE_member_t *member;
    size_t i;
    if(ctx->step < 0 || (unsigned)ctx->step >= td->elements_count) return -1;
    member = &td->elements[ctx->step];
    if(!(member->flags & ATF_EXTENSION_GROUP)) {
        *child = ASN_SET_DIRECT_MEMBER;
        return ctx->ptr ? -1 : 0;
    }
    if(!member->type || !member->type->elements || !ctx->ptr) return -1;
    for(i = 0; i < member->type->elements_count; i++) {
        if(ctx->ptr == &member->type->elements[i]) { *child = (unsigned)i; return 0; }
    }
    return -1;
}

/*
 * Purpose: decode a selected member and mark its owner and parent presence.
 * Source: SET member views and child JER decoder contracts.
 * Version/date: 1.0, 2026-10-30. Inputs: codec/td/st/ctx identify the value;
 * buf/size provide bytes; result receives child progress. Returns: 0 or -1.
 * Exceptions: none; malformed metadata, duplicates and overconsumption fail.
 * Author: asn1c maintainers. History: added for transparent group decoding.
 * Example: the first group leaf allocates its synthetic owner lazily.
 */
static int
SET_jer_decode_member(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td, void *st,
                      asn_struct_ctx_t *ctx, const void *buf, size_t size, asn_dec_rval_t *result) {
    unsigned child, outer = (unsigned)ctx->step;
    const asn_TYPE_member_t *member;
    asn_SET_member_view_t view;
    void *owner, *inline_value;
    void **slot;
    if(SET_jer_child(td, ctx, &child) || SET_member_view(td, st, outer, child, &view)) return -1;
    member = &td->elements[outer];
    owner = st;
    if(child != ASN_SET_DIRECT_MEMBER) {
        slot = (void **)((char *)st + member->memb_offset);
        if(!*slot) *slot = CALLOC(1, view.owner_specs->struct_size);
        if(!*slot) return -1;
        owner = *slot;
        if(SET_member_view(td, st, outer, child, &view)) return -1;
    }
    if(ASN_SET_ISPRESENT2((char *)owner + view.owner_specs->pres_offset, view.owner_index)) return -1;
    if(view.member->flags & ATF_OPEN_TYPE) return -1;
    if(!view.member->type || !view.member->type->op || !view.member->type->op->jer_decoder) return -1;
    if(view.member->flags & ATF_POINTER) slot = (void **)((char *)owner + view.member->memb_offset);
    else { inline_value = (char *)owner + view.member->memb_offset; slot = &inline_value; }
    *result = view.member->type->op->jer_decoder(codec, view.member->type,
        view.member->encoding_constraints.jer_constraints, slot, buf, size);
    if(result->consumed > size || result->consumed > (size_t)SSIZE_MAX) return -1;
    if(result->code == RC_OK) {
        const asn_SET_specifics_t *specs = td->specifics;
        ASN_SET_MKPRESENT((char *)owner + view.owner_specs->pres_offset, view.owner_index);
        if(child != ASN_SET_DIRECT_MEMBER) ASN_SET_MKPRESENT((char *)st + specs->pres_offset, outer);
        ctx->ptr = 0;
    }
    return 0;
}

/*
 * Purpose: select a JER key or start skipping an unknown extension.
 * Source: SET name routing and JER extension handling.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st/ctx identify the SET;
 * key/len describe the token. Returns: zero or -1 on invalid input.
 * Exceptions: none. Author: asn1c maintainers. History: group key routing.
 * Example: a group leaf saves its descriptor until decoding completes.
 */
static int
SET_jer_select(const asn_TYPE_descriptor_t *td, const void *st, asn_struct_ctx_t *ctx,
               const void *key, size_t len) {
    unsigned outer, child;
    int found = SET_jer_find(td, st, key, len, &outer, &child);
    if(found < 0) return -1;
    if(!found) {
        if(!((const asn_SET_specifics_t *)td->specifics)->extensible) return -1;
        ctx->phase = 7;
        return 0;
    }
    if(outer > SHRT_MAX) return -1;
    ctx->step = (short)outer;
    /* state variable: borrowed member descriptor, not owned by the context. */
    ctx->ptr = child == ASN_SET_DIRECT_MEMBER ? 0 : (void *)&td->elements[outer].type->elements[child];
    ctx->phase = 5; /* The colon may arrive in a later input chunk. */
    return 0;
}

/*
 * Purpose: find a complete unknown JSON value without consuming partial input.
 * Source: JSON string escaping and balanced container delimiters.
 * Version/date: 1.0, 2026-10-30. Inputs: buf/size describe available bytes.
 * Returns: length, zero for incomplete input, or -1 for invalid nesting.
 * Exceptions: none. Author: asn1c maintainers. History: added to skip nested
 * unknown SET extensions. Example: an object containing an array is one value.
 */
static ssize_t
SET_jer_skip_value(const void *buf, size_t size) {
    const unsigned char *s = buf;
    unsigned char stack[128]; /* Expected closing delimiters; state variable. */
    size_t i = 0, depth = 0;
    int string = 0, escaped = 0, container = 0;
    if(size > (size_t)SSIZE_MAX) return -1;
    while(i < size && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++;
    if(i == size) return 0;
    if(s[i] == '{' || s[i] == '[') container = 1;
    for(; i < size; i++) {
        unsigned char c = s[i];
        if(string) {
            if(escaped) escaped = 0;
            else if(c == '\\') escaped = 1;
            else if(c == '"') { string = 0; if(!container) return (ssize_t)(i + 1); }
            continue;
        }
        if(c == '"') { string = 1; continue; }
        if(c == '{' || c == '[') {
            if(depth == sizeof(stack)) return -1;
            stack[depth++] = c == '{' ? '}' : ']';
        } else if(c == '}' || c == ']') {
            if(!depth) return container ? -1 : (ssize_t)i;
            if(stack[--depth] != c) return -1;
            if(!depth) return (ssize_t)(i + 1);
        } else if(!depth && (c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t')) {
            return (ssize_t)i;
        }
    }
    return 0;
}

/*
 * Purpose: validate SET storage and member offsets before decoding input.
 * Source: SET presence bitmap and member-view layout contracts.
 * Version/date: 1.0, 2026-10-30. Inputs: td describes the SET, st is storage.
 * Returns: zero or -1 for invalid metadata. Exceptions: none.
 * Author: asn1c maintainers. History: added for JER decoder preflight.
 * Example: an out-of-bounds group pointer offset is rejected.
 */
static int
SET_jer_preflight(const asn_TYPE_descriptor_t *td, const void *st) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        asn_SET_member_view_t view;
        size_t j, count = (member->flags & ATF_EXTENSION_GROUP) && member->type ? member->type->elements_count : 1;
        if(!count) return -1;
        for(j = 0; j < count; j++) {
            unsigned child = (member->flags & ATF_EXTENSION_GROUP) ? (unsigned)j : ASN_SET_DIRECT_MEMBER;
            if(SET_member_view(td, st, (unsigned)i, child, &view)) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: apply an object token to the SET JER parser.
 * Source: JER key routing and SET presence validation.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st/ctx identify the SET;
 * ptr/len/type describe the token. Returns: -1 error, 0 continue, 1 done.
 * Exceptions: none. Author: asn1c maintainers. History: split parser logic.
 * Example: a closing object validates required group leaves.
 */
static int
SET_jer_token(const asn_TYPE_descriptor_t *td, void *st, asn_struct_ctx_t *ctx,
              const void *ptr, ssize_t len, pjer_chunk_type_e type) {
    jer_check_sym_e sym;
    if(ctx->phase == 5 || ctx->phase == 7) {
        if(type != PJER_TEXT) return -1;
        ctx->phase = ctx->phase == 5 ? 6 : 8;
        return 0;
    }
    if(type == PJER_TEXT) return 0;
    sym = jer_check_sym(ptr, (int)len, 0);
    if(ctx->phase == 0 && sym == JCK_OSTART) { ctx->phase = 1; return 0; }
    if(ctx->phase != 1) return -1;
    if(sym == JCK_OEND) return _SET_is_populated(td, st) ? 1 : -1;
    if(sym == JCK_COMMA) return 0;
    if(type == PJER_KEY) return SET_jer_select(td, st, ctx, ptr, (size_t)len);
    return -1;
}

/*
 * Purpose: process a selected or unknown value in the SET JER parser.
 * Source: group child decoder and unknown-value scanner.
 * Version/date: 1.0, 2026-10-30. Inputs: codec/td/st/ctx identify the value;
 * ptr/size/consumed are the mutable input cursor. Returns: -1 error, 0
 * continue, 1 incomplete. Exceptions: none. Author: asn1c maintainers.
 * History: split parser logic. Example: a partial scalar remains unconsumed.
 */
static int
SET_jer_value(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td, void *st,
              asn_struct_ctx_t *ctx, const void **ptr, size_t *size, size_t *consumed) {
    ssize_t used = 0;
    if(ctx->phase == 8) {
        used = SET_jer_skip_value(*ptr, *size);
        if(used < 0) return -1;
        if(!used) return 1;
        ctx->context = SET_JER_TOKENIZER_VALUE_BODY;
        ctx->phase = 1;
    } else if(ctx->phase == 6) {
        int probe = ctx->context;
        pjer_chunk_type_e type;
        if(jer_next_token(&probe, *ptr, *size, &type) < 0) return -1;
        if(type == PJER_WMORE) return 1;
        ctx->phase = 2;
        return 0;
    } else {
        asn_dec_rval_t result;
        if(SET_jer_decode_member(codec, td, st, ctx, *ptr, *size, &result)) return -1;
        used = (ssize_t)result.consumed;
        *ptr = (const char *)*ptr + used; *size -= (size_t)used; *consumed += (size_t)used;
        if(result.code == RC_WMORE) return 1;
        if(result.code != RC_OK) return -1;
        ctx->phase = 1;
        return 0;
    }
    *ptr = (const char *)*ptr + used; *size -= (size_t)used; *consumed += (size_t)used;
    return 0;
}

/*
 * Purpose: run the resumable token loop after validating SET storage.
 * Source: SET JER token and selected-value helpers.
 * Version/date: 1.0, 2026-10-30. Inputs: codec/td/st/ctx identify the SET;
 * ptr/size describe input. Returns: decode status and consumed bytes.
 * Exceptions: none. Author: asn1c maintainers. History: split parser loop.
 * Example: a partial selected member returns RC_WMORE with consumed bytes.
 */
static asn_dec_rval_t
SET_jer_loop(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td, void *st,
             asn_struct_ctx_t *ctx, const void *ptr, size_t size) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    size_t consumed = 0;
    while(ctx->phase != 4) {
        pjer_chunk_type_e type;
        ssize_t len;
        int token_result;
        if(ctx->phase == 8 || ctx->phase == 6 || ctx->phase == 2) {
            int status = SET_jer_value(codec, td, st, ctx, &ptr, &size, &consumed);
            if(status < 0) break;
            if(status > 0) { result.code = RC_WMORE; result.consumed = consumed; return result; }
            continue;
        }
        len = jer_next_token(&ctx->context, ptr, size, &type);
        if(len < 0) break;
        if(type == PJER_WMORE) { result.code = RC_WMORE; result.consumed = consumed; return result; }
        if(!len || (size_t)len > size || len > INT_MAX) break;
        token_result = SET_jer_token(td, st, ctx, ptr, len, type);
        if(token_result < 0) break;
        if(token_result > 0) {
            consumed += (size_t)len;
            result.code = RC_OK; result.consumed = consumed; ctx->phase = 4; return result;
        }
        ptr = (const char *)ptr + len; size -= (size_t)len; consumed += (size_t)len;
    }
    ctx->phase = 4; result.code = RC_FAIL; result.consumed = consumed; return result;
}

/*
 * Purpose: decode a SET object with transparent extension-group components.
 * Source: existing SET JER parser and X.697 clauses 27 and 29.
 * Version/date: 1.0, 2026-10-30. Inputs: codec/td/constraints describe the
 * decoder; struct_ptr receives the value; ptr/size provide input bytes.
 * Returns: decoder status and consumed count. Exceptions: none; malformed
 * input, descriptor and allocation failures return RC_FAIL.
 * Author: asn1c maintainers. History: reworked for flat groups and streaming.
 * Example: a grouped first leaf is decoded from the outer JSON object.
 */
asn_dec_rval_t
SET_decode_jer(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
               const asn_jer_constraints_t *constraints, void **struct_ptr, const void *ptr, size_t size) {
    const asn_SET_specifics_t *specs;
    asn_struct_ctx_t *ctx;
    void *st;
    asn_dec_rval_t result = {RC_FAIL, 0};
    static const char empty = 0;
    (void)constraints;
    if(!td || !td->specifics || !struct_ptr || (!ptr && size)
    || size > (size_t)SSIZE_MAX || (td->elements_count && !td->elements)) return result;
    if(!ptr) ptr = &empty;
    specs = td->specifics;
    if(SET_descriptor_valid(td)) return result;
    st = *struct_ptr;
    if(!st) { st = *struct_ptr = CALLOC(1, specs->struct_size); if(!st) return result; }
    if(SET_jer_preflight(td, st)) return result;
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
    if(ASN__STACK_OVERFLOW_CHECK(codec)) return result;
    return SET_jer_loop(codec, td, st, ctx, ptr, size);
}

/* Output state for a single SET JER object. */
typedef struct SET_jer_output_s {
    asn_app_consume_bytes_f *cb; /* Receives encoded bytes. */
    void *key; /* Callback context. */
    ssize_t count; /* Emitted byte count; state variable. */
    int members; /* Number of members emitted; state variable. */
    int ilevel; /* Current indentation level. */
    enum jer_encoder_flags_e flags; /* Formatting flags. */
} SET_jer_output_t;

/*
 * Purpose: write a bounded output fragment and update the encoded length.
 * Source: JER callback and encoded-length contracts.
 * Version/date: 1.0, 2026-10-30. Inputs: output is state, buf/size are bytes.
 * Returns: zero or -1 on callback or length failure. Exceptions: none.
 * Author: asn1c maintainers. History: added for transparent group encoding.
 * Example: SET_jer_write(output, "{", 1) starts the JSON object.
 */
static int
SET_jer_write(SET_jer_output_t *output, const void *buf, size_t size) {
    if(size > (size_t)(SSIZE_MAX - output->count) || output->cb(buf, size, output->key) < 0) return -1;
    output->count += (ssize_t)size;
    return 0;
}

/*
 * Purpose: emit indentation for pretty JER output.
 * Source: existing JER formatting convention.
 * Version/date: 1.0, 2026-10-30. Inputs: output is state; level is indentation.
 * Returns: zero or -1. Exceptions: none. Author: asn1c maintainers.
 * History: added for grouped SET formatting. Example: level 1 indents a member.
 */
static int
SET_jer_indent(SET_jer_output_t *output, int level) {
    int i;
    if(output->flags & JER_F_MINIFIED) return 0;
    if(level < 0 || SET_jer_write(output, "\n", 1)) return -1;
    for(i = 0; i < level; i++) if(SET_jer_write(output, "    ", 4)) return -1;
    return 0;
}

/*
 * Purpose: reject names that the existing JER key matcher cannot represent.
 * Source: jer_check_sym's literal key comparison.
 * Version/date: 1.0, 2026-10-30. Input: name is the replacement wire name.
 * Returns: nonzero for a safe literal key, zero otherwise. Exceptions: none.
 * Author: asn1c maintainers. History: fail closed on unhandled JSON escapes.
 * Example: a quote in a NAME override is rejected instead of corrupting JSON.
 */
static int
SET_jer_name_safe(const char *name) {
    const unsigned char *p = (const unsigned char *)name;
    if(!p) return 0;
    for(; *p; p++) if(*p < 0x20 || *p == '"' || *p == '\\') return 0;
    return 1;
}

/*
 * Purpose: write one JSON member's name and separator.
 * Source: SET JER formatting and output callbacks.
 * Version/date: 1.0, 2026-10-30. Inputs: output is sink; name is key.
 * Returns: zero or -1. Exceptions: none. Author: asn1c maintainers.
 * History: extracted for bounded leaf encoding. Example: emits a comma when needed.
 */
static int
SET_jer_encode_key(SET_jer_output_t *output, const char *name) {
    if(output->members && SET_jer_write(output, ",", 1)) return -1;
    if(SET_jer_indent(output, output->ilevel + 1)) return -1;
    if(SET_jer_write(output, "\"", 1) || SET_jer_write(output, name, strlen(name))) return -1;
    if(SET_jer_write(output, "\":", 2)) return -1;
    if(!(output->flags & JER_F_MINIFIED) && SET_jer_write(output, " ", 1)) return -1;
    return 0;
}

/*
 * Purpose: emit one validated SET leaf including its JSON key and value.
 * Source: SET member view and existing SEQUENCE JER DEFAULT behavior.
 * Version/date: 1.0, 2026-10-30. Inputs: view selects the leaf; output
 * describes the sink. Returns: zero or -1. Exceptions: none; invalid values,
 * child and callback failures return -1. Author: asn1c maintainers.
 * History: added for flat JER groups. Example: first emits as a sibling key.
 */
static int
SET_jer_encode_leaf(const asn_SET_member_view_t *view, SET_jer_output_t *output) {
    const asn_TYPE_member_t *member = view->member;
    const void *value = view->value;
    void *default_value = 0;
    asn_enc_rval_t child;
    const char *name = JER_MEMBER_NAME(member);
    int failed = 0;
    if(!SET_jer_name_safe(name) || !member->type || !member->type->op) return -1;
    if((member->flags & ATF_OPEN_TYPE) || !member->type->op->jer_encoder) return -1;
    if(!view->present) {
        if(member->default_value_set) {
            if(member->default_value_set(&default_value) || !default_value) {
                if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
                return -1;
            }
            value = default_value;
        } else return member->optional ? 0 : -1;
    }
    if(SET_jer_encode_key(output, name)) failed = 1;
    if(!failed) {
        child = member->type->op->jer_encoder(member->type, member->encoding_constraints.jer_constraints,
                                              value, output->ilevel + 1, output->flags, output->cb, output->key);
        if(child.encoded < 0 || child.encoded > SSIZE_MAX - output->count) failed = 1;
        else output->count += child.encoded;
    }
    if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
    if(failed) return -1;
    output->members++;
    return 0;
}

/*
 * Purpose: emit an ordinary SET member or all leaves of a present group.
 * Source: validated SET member views and group mandatory-value checks.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st identify the SET; outer
 * selects its member; output receives bytes. Returns: zero or -1.
 * Exceptions: none; invalid descriptors and incomplete groups fail.
 * Author: asn1c maintainers. History: added for flat SET JER.
 * Example: an absent group emits no JSON members.
 */
static int
SET_jer_encode_member(const asn_TYPE_descriptor_t *td, const void *st, unsigned outer, SET_jer_output_t *output) {
    const asn_TYPE_member_t *member = &td->elements[outer];
    asn_SET_member_view_t view;
    size_t i;
    if(!(member->flags & ATF_EXTENSION_GROUP)) {
        if(SET_member_view(td, st, outer, ASN_SET_DIRECT_MEMBER, &view)) return -1;
        return SET_jer_encode_leaf(&view, output);
    }
    if(!member->type || !member->type->elements_count || SET_member_view(td, st, outer, 0, &view)) return -1;
    if(!view.owner) return member->optional ? 0 : -1;
    if(SET_group_is_populated(member->type, view.owner) != 1) return -1;
    for(i = 0; i < member->type->elements_count; i++) {
        if(SET_member_view(td, st, outer, (unsigned)i, &view)
        || SET_jer_encode_leaf(&view, output)) return -1;
    }
    return 0;
}

/*
 * Purpose: encode a SET as a JER object with flat extension-group leaves.
 * Source: X.697 clauses 27.3 and 29 and validated SET member views.
 * Version/date: 1.0, 2026-10-30. Inputs: td/constraints/sptr describe the
 * value; ilevel/flags control format; cb/key receive bytes. Returns: encoded
 * length or failure. Exceptions: none; invalid values or callbacks fail.
 * Author: asn1c maintainers. History: added for transparent SET JER groups.
 * Example: a present first group leaf appears directly in the outer object.
 */
asn_enc_rval_t
SET_encode_jer(const asn_TYPE_descriptor_t *td, const asn_jer_constraints_t *constraints, const void *sptr,
               int ilevel, enum jer_encoder_flags_e flags, asn_app_consume_bytes_f *cb, void *key) {
    SET_jer_output_t output = {cb, key, 0, 0, ilevel, flags};
    asn_enc_rval_t er = {0, 0, 0};
    size_t i;
    int groups = 0;
    if(!td || !td->specifics || !sptr || !cb || (td->elements_count && !td->elements)) ASN__ENCODE_FAILED;
    for(i = 0; i < td->elements_count; i++) if(td->elements[i].flags & ATF_EXTENSION_GROUP) groups = 1;
    if(!groups) return SEQUENCE_encode_jer(td, constraints, sptr, ilevel, flags, cb, key);
    if(SET_descriptor_valid(td) || SET_jer_preflight(td, sptr)) ASN__ENCODE_FAILED;
    JER_ENCODER_RECURSION_DEPTH_INC();
    if(SET_jer_write(&output, "{", 1)) goto failed;
    for(i = 0; i < td->elements_count; i++) {
        if(SET_jer_encode_member(td, sptr, (unsigned)i, &output)) goto failed;
    }
    if(SET_jer_indent(&output, ilevel) || SET_jer_write(&output, "}", 1)) goto failed;
    JER_ENCODER_RECURSION_DEPTH_DEC();
    er.encoded = output.count;
    ASN__ENCODED_OK(er);
failed:
    JER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODE_FAILED;
}
