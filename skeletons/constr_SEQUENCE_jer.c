/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <OPEN_TYPE.h>
#include <string.h>

#define JER_MEMBER_NAME(elm) \
    (((elm)->encoding_constraints.jer_constraints \
      && (elm)->encoding_constraints.jer_constraints->wire_name) \
         ? (elm)->encoding_constraints.jer_constraints->wire_name \
         : (elm)->name)

/*
 * Purpose: map a flattened SEQUENCE index to a member descriptor.
 * Source: generated ATF_EXTENSION_GROUP metadata.
 * Version/date: 1.0, 2026-10-31. Inputs: td is the sequence; flat is the
 * logical field index; outer/child receive indexes. Returns: zero or -1.
 * Errors: malformed group descriptors and indexes outside the type fail.
 * Author: asn1c maintainers. History: added for flat-group JER dispatch.
 * Example: each group leaf receives a consecutive logical index.
 */
static int
SEQUENCE_jer_flat_map(const asn_TYPE_descriptor_t *td, size_t flat,
                      size_t *outer, size_t *child) {
    size_t i;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t count = (member->flags & ATF_EXTENSION_GROUP) && member->type
            ? member->type->elements_count : 1;
        if(flat < count) {
            *outer = i;
            *child = (member->flags & ATF_EXTENSION_GROUP) ? flat : SIZE_MAX;
            return 0;
        }
        flat -= count;
    }
    return -1;
}

/*
 * Purpose: count logical fields after expanding one group level.
 * Source: generated SEQUENCE member tables.
 * Version/date: 1.0, 2026-10-31. Input: td is a SEQUENCE descriptor.
 * Returns: flattened field count, or SIZE_MAX for invalid metadata/overflow.
 * Errors: missing or malformed group descriptors return SIZE_MAX.
 * Author: asn1c maintainers. History: added for flat-group JER dispatch.
 * Example: a group of two leaves contributes two logical fields.
 */
static size_t
SEQUENCE_jer_flat_count(const asn_TYPE_descriptor_t *td) {
    size_t i, count = 0;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t add = 1;
        if(member->flags & ATF_EXTENSION_GROUP) {
            if(!member->type || !member->type->elements
            || !member->type->elements_count || !member->type->specifics
            || !member->type->op || member->type->op->kind != ASN_KIND_SEQUENCE)
                return SIZE_MAX;
            add = member->type->elements_count;
        }
        if(add > SIZE_MAX - count) return SIZE_MAX;
        count += add;
    }
    return count;
}

/*
 * Purpose: validate a SEQUENCE member's storage before offset arithmetic.
 * Source: SEQUENCE specifics and native inline-value widths.
 * Version/date: 1.0, 2026-10-31. Inputs: td/member describe the field.
 * Returns: zero for bounded storage, -1 for malformed metadata.
 * Errors: invalid widths and offsets outside the owner are rejected.
 * Author: asn1c maintainers. History: bounds checks for flat-group JER.
 * Example: pointer members require a full pointer-width slot.
 */
static int
SEQUENCE_jer_member_valid(const asn_TYPE_descriptor_t *td,
                          const asn_TYPE_member_t *member) {
    const asn_SEQUENCE_specifics_t *specs = td->specifics;
    size_t width;
    if(!specs || !member || !member->type || !member->name
    || member->memb_offset > specs->struct_size) return -1;
    if(member->flags & ATF_POINTER) width = sizeof(void *);
    else if(SET_inline_value_size(member->type, &width)) return -1;
    return width <= specs->struct_size - member->memb_offset ? 0 : -1;
}

/*
 * Purpose: obtain group storage after validating its pointer offset.
 * Source: generated SEQUENCE group pointer member.
 * Version/date: 1.0, 2026-10-31. Inputs: td/value identify owner; member is a
 * synthetic group. Returns: group pointer or NULL if absent/invalid.
 * Errors: malformed descriptors are returned as NULL.
 * Author: asn1c maintainers. History: added for flat-group JER dispatch.
 * Example: an absent extension group returns NULL.
 */
static void *
SEQUENCE_jer_group_value(const asn_TYPE_descriptor_t *td, const void *value,
                         const asn_TYPE_member_t *member) {
    if(SEQUENCE_jer_member_valid(td, member)
    || !(member->flags & ATF_EXTENSION_GROUP)
    || !(member->flags & ATF_POINTER)) return 0;
    return *(void *const *)((const char *)value + member->memb_offset);
}

/*
 * Purpose: validate flat-group descriptor offsets and decoder context bounds.
 * Source: generated SEQUENCE specifics and synthetic-group layout metadata.
 * Version/date: 1.0, 2026-10-31. Inputs: td/specs/count describe the type.
 * Returns: zero for valid metadata or -1 for malformed layouts.
 * Errors: bad offsets, nested groups, and invalid contexts are rejected.
 * Author: asn1c maintainers. History: extracted from flat decoder preflight.
 * Example: an out-of-range group leaf offset fails before allocation.
 */
static int
SEQUENCE_jer_flat_preflight(const asn_TYPE_descriptor_t *td,
                            const asn_SEQUENCE_specifics_t *specs,
                            size_t count) {
    size_t i, j;
    if(count == SIZE_MAX || count >= SHRT_MAX
    || specs->ctx_offset > specs->struct_size
    || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset)
        return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *outer = &td->elements[i];
        if(SEQUENCE_jer_member_valid(td, outer)) return -1;
        if(!(outer->flags & ATF_EXTENSION_GROUP)) continue;
        if(!(outer->flags & ATF_POINTER) || !outer->type
        || !outer->type->elements || !outer->type->specifics
        || !outer->type->op || outer->type->op->kind != ASN_KIND_SEQUENCE)
            return -1;
        {
            const asn_SEQUENCE_specifics_t *group_specs = outer->type->specifics;
            if(group_specs->ctx_offset > group_specs->struct_size
            || sizeof(asn_struct_ctx_t)
                > group_specs->struct_size - group_specs->ctx_offset) return -1;
        }
        for(j = 0; j < outer->type->elements_count; j++) {
            const asn_TYPE_member_t *leaf = &outer->type->elements[j];
            if(SEQUENCE_jer_member_valid(outer->type, leaf)
            || (leaf->flags & (ATF_EXTENSION_GROUP | ATF_OPEN_TYPE))) return -1;
        }
    }
    return 0;
}

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
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

#undef JER_ADVANCE
#define JER_ADVANCE(num_bytes)            \
    do {                                  \
        size_t num = (num_bytes);         \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        consumed_myself += num;           \
    } while(0)

static int SEQUENCE_jer_flat_find(const asn_TYPE_descriptor_t *, const void *,
                                  size_t, size_t, size_t *);
static int SEQUENCE_jer_flat_can_skip(const asn_TYPE_descriptor_t *, const void *,
                                      size_t, size_t);
static int SEQUENCE_jer_flat_complete(const asn_TYPE_descriptor_t *, const void *,
                                      size_t, size_t);
static asn_dec_rval_t SEQUENCE_jer_flat_decode_member(const asn_codec_ctx_t *,
    const asn_TYPE_descriptor_t *, void *, asn_struct_ctx_t *, const void *, size_t);
static int SEQUENCE_jer_flat_preflight(const asn_TYPE_descriptor_t *,
    const asn_SEQUENCE_specifics_t *, size_t);
static int SEQUENCE_jer_flat_select_key(const asn_TYPE_descriptor_t *,
    const asn_SEQUENCE_specifics_t *, void *, asn_struct_ctx_t *,
    const void *, size_t, size_t);
static asn_dec_rval_t SEQUENCE_jer_flat_next_token(const asn_TYPE_descriptor_t *,
    const asn_SEQUENCE_specifics_t *, void *, asn_struct_ctx_t *, const void *,
    size_t, size_t);

/*
 * Purpose: validate tokenizer text between a key and value.
 * Source: JSON object member separator syntax.
 * Version/date: 1.0, 2026-10-31. Inputs: buf/size is the key-value separator.
 * Returns: nonzero when it contains one colon and optional JSON whitespace.
 * Errors: repeated/missing colons or other bytes return false. Exceptions: none.
 * Author: asn1c maintainers. History: added for flat-group parser hardening.
 * Example: ` : ` is accepted; ` junk: ` is rejected.
 */
static int
SEQUENCE_jer_colon_valid(const void *buf, size_t size) {
    const unsigned char *text = buf;
    size_t i;
    int colon = 0;
    for(i = 0; i < size; i++) {
        if(text[i] == ':') {
            if(colon) return 0;
            colon = 1;
        } else if(text[i] != ' ' && text[i] != '\t'
               && text[i] != '\r' && text[i] != '\n') {
            return 0;
        }
    }
    return colon;
}

static int SEQUENCE_jer_json_value(const unsigned char *, size_t, size_t *, unsigned);

/*
 * Purpose: parse one JSON string and validate escape spelling.
 * Source: JSON string grammar.
 * Version/date: 1.0, 2026-10-31. Inputs: text/size are bytes; pos points at `"`.
 * Returns: 1 complete, 0 incomplete, -1 malformed. Exceptions: none.
 * Author: asn1c maintainers. History: added for unknown extension values.
 * Example: `\\u0041` is accepted; `\\u12xz` is rejected.
 */
static int
SEQUENCE_jer_json_string(const unsigned char *text, size_t size, size_t *pos) {
    size_t i = *pos + 1, digit;
    if(*pos >= size || text[*pos] != '"') return -1;
    while(i < size) {
        unsigned char c = text[i++];
        if(c == '"') { *pos = i; return 1; }
        if(c < 0x20) return -1;
        if(c != '\\') continue;
        if(i == size) return 0;
        c = text[i++];
        if(c != 'u') {
            if(!strchr("\"\\/bfnrt", c)) return -1;
            continue;
        }
        for(digit = 0; digit < 4; digit++) {
            unsigned char hex;
            if(i == size) return 0;
            hex = text[i++];
            if(!((hex >= '0' && hex <= '9') || (hex >= 'a' && hex <= 'f')
              || (hex >= 'A' && hex <= 'F'))) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: parse a strict JSON object or array at the current byte position.
 * Source: JSON object/array grammar and recursive value parser.
 * Version/date: 1.0, 2026-10-31. Inputs: text/size are bytes; pos points at
 * `{` or `[`; depth bounds recursive nesting. Returns: 1, 0 incomplete, -1 bad.
 * Errors: missing separators, trailing commas, and malformed children fail.
 * Author: asn1c maintainers. History: strict unknown-extension scanning.
 * Example: nested arrays and objects are accepted when all delimiters match.
 */
static int
SEQUENCE_jer_json_container(const unsigned char *text, size_t size,
                            size_t *pos, unsigned depth) {
    int object = text[*pos] == '{';
    unsigned char close = object ? '}' : ']';
    size_t i = *pos + 1;
    for(;;) {
        int parsed;
        while(i < size && (text[i] == ' ' || text[i] == '\n'
            || text[i] == '\r' || text[i] == '\t')) i++;
        if(i == size) return 0;
        if(text[i] == close) { *pos = i + 1; return 1; }
        if(object) {
            parsed = SEQUENCE_jer_json_string(text, size, &i);
            if(parsed != 1) return parsed;
            while(i < size && (text[i] == ' ' || text[i] == '\n'
                || text[i] == '\r' || text[i] == '\t')) i++;
            if(i == size) return 0;
            if(text[i++] != ':') return -1;
        }
        parsed = SEQUENCE_jer_json_value(text, size, &i, depth + 1);
        if(parsed != 1) return parsed;
        while(i < size && (text[i] == ' ' || text[i] == '\n'
            || text[i] == '\r' || text[i] == '\t')) i++;
        if(i == size) return 0;
        if(text[i] == close) { *pos = i + 1; return 1; }
        if(text[i++] != ',') return -1;
        while(i < size && (text[i] == ' ' || text[i] == '\n'
            || text[i] == '\r' || text[i] == '\t')) i++;
        if(i == size) return 0;
        if(text[i] == close) return -1;
    }
}

/*
 * Purpose: parse one JSON number and require a value boundary.
 * Source: JSON number grammar.
 * Version/date: 1.0, 2026-10-31. Inputs: text/size are bytes; pos points at a
 * number start. Returns: 1 complete, 0 incomplete, -1 malformed. Exceptions: none.
 * Author: asn1c maintainers. History: strict unknown scalar validation.
 * Example: `-1.25e+2,` is valid; `01,` is rejected.
 */
static int
SEQUENCE_jer_json_number(const unsigned char *text, size_t size, size_t *pos) {
    size_t i = *pos;
    if(text[i] == '-') { if(++i == size) return 0; }
    if(text[i] == '0') {
        i++;
        if(i < size && text[i] >= '0' && text[i] <= '9') return -1;
    } else if(text[i] >= '1' && text[i] <= '9') {
        do { i++; } while(i < size && text[i] >= '0' && text[i] <= '9');
    } else return -1;
    if(i < size && text[i] == '.') {
        if(++i == size) return 0;
        if(text[i] < '0' || text[i] > '9') return -1;
        do { i++; } while(i < size && text[i] >= '0' && text[i] <= '9');
    }
    if(i < size && (text[i] == 'e' || text[i] == 'E')) {
        i++;
        if(i == size) return 0;
        if(text[i] == '+' || text[i] == '-') i++;
        if(i == size) return 0;
        if(text[i] < '0' || text[i] > '9') return -1;
        do { i++; } while(i < size && text[i] >= '0' && text[i] <= '9');
    }
    if(i == size) return 0;
    if(text[i] != ',' && text[i] != ']' && text[i] != '}'
    && text[i] != ' ' && text[i] != '\n' && text[i] != '\r' && text[i] != '\t')
        return -1;
    *pos = i;
    return 1;
}

/*
 * Purpose: parse one JSON value recursively with a fixed nesting limit.
 * Source: JSON literals, number, string, object, and array grammar.
 * Version/date: 1.0, 2026-10-31. Inputs: text/size are bytes; pos is the cursor;
 * depth tracks nested containers. Returns: 1 complete, 0 incomplete, -1 invalid.
 * Errors: invalid tokens and nesting beyond 128 fail. Exceptions: none.
 * Author: asn1c maintainers. History: added for strict extension skipping.
 * Example: `{"x":[true,null]}` parses as one complete value.
 */
static int
SEQUENCE_jer_json_value(const unsigned char *text, size_t size, size_t *pos,
                        unsigned depth) {
    static const char *const literals[] = {"true", "false", "null"};
    size_t i, length;
    unsigned literal;
    int parsed;
    while(*pos < size && (text[*pos] == ' ' || text[*pos] == '\n'
        || text[*pos] == '\r' || text[*pos] == '\t')) (*pos)++;
    if(*pos == size) return 0;
    if(depth > 128) return -1;
    if(text[*pos] == '"') return SEQUENCE_jer_json_string(text, size, pos);
    if(text[*pos] == '{' || text[*pos] == '[')
        return SEQUENCE_jer_json_container(text, size, pos, depth);
    if(text[*pos] == '-' || (text[*pos] >= '0' && text[*pos] <= '9'))
        return SEQUENCE_jer_json_number(text, size, pos);
    for(literal = 0; literal < sizeof(literals) / sizeof(literals[0]); literal++) {
        length = strlen(literals[literal]);
        for(i = 0; i < length && *pos + i < size; i++) {
            if(text[*pos + i] != (unsigned char)literals[literal][i]) break;
        }
        if(i < length) {
            if(*pos + i == size) return 0;
            continue;
        }
        *pos += length;
        parsed = *pos < size ? 1 : 0;
        if(parsed && text[*pos] != ',' && text[*pos] != ']' && text[*pos] != '}'
        && text[*pos] != ' ' && text[*pos] != '\n' && text[*pos] != '\r'
        && text[*pos] != '\t') return -1;
        return parsed;
    }
    return -1;
}

/*
 * Purpose: return the complete size of one strict JSON value.
 * Source: recursive JSON value parser above.
 * Version/date: 1.0, 2026-10-31. Inputs: buf/size is an available value prefix.
 * Returns: byte length, zero when more input is needed, or -1 if malformed.
 * Errors: malformed JSON and values over SSIZE_MAX are rejected. Exceptions: none.
 * Author: asn1c maintainers. History: replaced permissive unknown-value skipping.
 * Example: nested unknown extensions are skipped only after complete parsing.
 */
static ssize_t
SEQUENCE_jer_skip_value(const void *buf, size_t size) {
    size_t pos = 0;
    int result;
    if(size > (size_t)SSIZE_MAX) return -1;
    result = SEQUENCE_jer_json_value(buf, size, &pos, 0);
    if(result <= 0) return result;
    return pos > (size_t)SSIZE_MAX ? -1 : (ssize_t)pos;
}

/*
 * Purpose: check whether a tokenizer text fragment contains JSON whitespace.
 * Source: RFC 8259 whitespace characters recognized by the JER parser.
 * Version/date: 1.0, 2026-10-31. Input: ptr/size is the text fragment.
 * Returns: one when all bytes are whitespace, zero otherwise.
 * Errors: null with nonzero size is rejected. Exceptions: none.
 * Author: asn1c maintainers. History: added to reject text outside values.
 * Example: spaces before the opening object brace are accepted.
 */
static int
SEQUENCE_jer_is_whitespace(const void *ptr, size_t size) {
    const unsigned char *text = ptr;
    size_t i;
    if(!ptr && size) return 0;
    for(i = 0; i < size; i++) {
        if(text[i] != ' ' && text[i] != '\t' && text[i] != '\n'
        && text[i] != '\r') return 0;
    }
    return 1;
}

/*
 * Purpose: validate a tokenizer delimiter with only JSON whitespace before it.
 * Source: strict JSON object framing for flat SEQUENCE JER input.
 * Version/date: 1.0, 2026-10-31. Inputs: ptr/size is the token; expected is
 * the required delimiter. Returns: one for an exact delimiter token, zero otherwise.
 * Errors: null or malformed token input is rejected. Exceptions: none.
 * Author: asn1c maintainers. History: added because ST_TEXT ignores prefixes.
 * Example: whitespace followed by `{` is valid at the object start.
 */
static int
SEQUENCE_jer_delimiter_valid(const void *ptr, size_t size, char expected) {
    const unsigned char *text = ptr;
    size_t whitespace = jer_whitespace_span(ptr, size);
    return ptr && whitespace < size && whitespace + 1 == size
        && text[whitespace] == (unsigned char)expected;
}

/*
 * Purpose: process one flat SEQUENCE JER token and update decoder state.
 * Source: JER tokenizer, field routing, and strict unknown-value parser.
 * Version/date: 1.0, 2026-10-31. Inputs: td/specs/st/ctx describe parser state;
 * ptr/size hold input; count is the flattened member count.
 * Returns: token status and consumed bytes. Errors: malformed JSON or keys fail.
 * Author: asn1c maintainers. History: extracted to keep decoder complexity bounded.
 * Example: a complete key token advances ctx to colon processing.
 */
static asn_dec_rval_t
SEQUENCE_jer_flat_next_token(const asn_TYPE_descriptor_t *td,
                             const asn_SEQUENCE_specifics_t *specs,
                             void *st, asn_struct_ctx_t *ctx,
                             const void *ptr, size_t size, size_t count) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    pjer_chunk_type_e chunk_type;
    ssize_t chunk_size;
    jer_check_sym_e symbol;
    if(ctx->phase == 3) {
        ssize_t value_size = SEQUENCE_jer_skip_value(ptr, size);
        if(value_size < 0) return result;
        result.code = value_size ? RC_OK : RC_WMORE;
        result.consumed = value_size > 0 ? (size_t)value_size : 0;
        if(value_size > 0) ctx->phase = 1;
        return result;
    }
    chunk_size = jer_next_token(&ctx->context, ptr, size, &chunk_type);
    if(chunk_size == -1) return result;
    if(chunk_type == PJER_WMORE) { result.code = RC_WMORE; return result; }
    if(chunk_size < 0 || (size_t)chunk_size > size || chunk_size > INT_MAX)
        return result;
    if(ctx->phase == 5) {
        if(chunk_type != PJER_TEXT
        || !SEQUENCE_jer_colon_valid(ptr, (size_t)chunk_size)) return result;
        ctx->phase = ctx->left ? 3 : 2;
        result.code = RC_OK;
        result.consumed = (size_t)chunk_size;
        return result;
    }
    if(chunk_type == PJER_TEXT) {
        if(!SEQUENCE_jer_is_whitespace(ptr, (size_t)chunk_size)) return result;
        result.code = RC_OK;
        result.consumed = (size_t)chunk_size;
        return result;
    }
    symbol = jer_check_sym(ptr, (int)chunk_size, NULL);
    if(ctx->phase == 0) {
        if(symbol != JCK_OSTART
        || !SEQUENCE_jer_delimiter_valid(ptr, (size_t)chunk_size, '{'))
            return result;
        ctx->phase = 1;
    } else if(ctx->phase != 1) {
        return result;
    } else if(symbol == JCK_OEND) {
        if(SEQUENCE_jer_flat_complete(td, st, (size_t)ctx->step, count)) return result;
        ctx->phase = 4;
        result.consumed = (size_t)chunk_size
            + jer_whitespace_span((const char *)ptr + chunk_size,
                                  size - (size_t)chunk_size);
        result.code = RC_OK;
        return result;
    } else if(symbol == JCK_KEY || symbol == JCK_UNKNOWN) {
        if(SEQUENCE_jer_flat_select_key(td, specs, st, ctx, ptr,
                                        (size_t)chunk_size, count)) return result;
    } else if(symbol != JCK_COMMA) {
        return result;
    }
    result.code = RC_OK;
    result.consumed = (size_t)chunk_size;
    return result;
}

/*
 * Purpose: decode a SEQUENCE whose extension groups use flat JER keys.
 * Source: ordered SEQUENCE JER fields and generated extension-group storage.
 * Version/date: 1.0, 2026-10-31. Inputs: codec/td describe the decoder;
 * struct_ptr receives output; ptr/size supply a JSON chunk.
 * Returns: decode status and consumed bytes. Errors: malformed descriptors,
 * duplicate/out-of-order keys, child failures, and allocation failures reject.
 * Author: asn1c maintainers. History: added for flat SEQUENCE group parity.
 * Example: a `first` group leaf decodes directly from the outer JSON object.
 */
static asn_dec_rval_t
SEQUENCE_decode_jer_flat(const asn_codec_ctx_t *codec,
                         const asn_TYPE_descriptor_t *td,
                         void **struct_ptr, const void *ptr, size_t size) {
    const asn_SEQUENCE_specifics_t *specs;
    asn_struct_ctx_t *ctx;
    void *st;
    size_t count;
    ssize_t consumed = 0;
    asn_dec_rval_t result = {RC_FAIL, 0};
#define FLAT_RETURN(_status) do { result.code = (_status); result.consumed = consumed; return result; } while(0)
#define FLAT_ADVANCE(amount) do { \
    size_t step = (amount); \
    if(step > size || step > (size_t)(SSIZE_MAX - consumed)) FLAT_RETURN(RC_FAIL); \
    ptr = (const char *)ptr + step; size -= step; consumed += (ssize_t)step; \
} while(0)
    if(!td || !td->specifics || !struct_ptr || (!ptr && size)
    || size > (size_t)SSIZE_MAX || (td->elements_count && !td->elements))
        FLAT_RETURN(RC_FAIL);
    specs = td->specifics;
    count = SEQUENCE_jer_flat_count(td);
    if(SEQUENCE_jer_flat_preflight(td, specs, count)) FLAT_RETURN(RC_FAIL);
    if(size == 0) FLAT_RETURN(RC_WMORE);
    st = *struct_ptr;
    if(!st) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(!st) FLAT_RETURN(RC_FAIL);
    }
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
    if(ASN__STACK_OVERFLOW_CHECK(codec)) FLAT_RETURN(RC_FAIL);
    if(ctx->step < 0 || (size_t)ctx->step > count) FLAT_RETURN(RC_FAIL);
    for(;;) {
        if(ctx->phase == 2) {
            asn_dec_rval_t child_result = SEQUENCE_jer_flat_decode_member(
                codec, td, st, ctx, ptr, size);
            FLAT_ADVANCE(child_result.consumed);
            if(child_result.code != RC_OK) FLAT_RETURN(child_result.code);
            continue;
        }
        result = SEQUENCE_jer_flat_next_token(td, specs, st, ctx,
                                              ptr, size, count);
        FLAT_ADVANCE(result.consumed);
        if(result.code != RC_OK) FLAT_RETURN(result.code);
        if(ctx->phase == 4) FLAT_RETURN(RC_OK);
    }
#undef FLAT_ADVANCE
#undef FLAT_RETURN
}

/*
 * Purpose: find a unique flattened SEQUENCE field for an input JER key.
 * Source: member names, optional JER NAME overrides, and group metadata.
 * Version/date: 1.0, 2026-10-31. Inputs: td/key/size describe the key;
 * flat receives the logical index. Returns: 1 match, 0 unknown, -1 ambiguous.
 * Errors: duplicate names in the descriptor fail closed.
 * Author: asn1c maintainers. History: added for flat-group decoding.
 * Example: a group leaf key resolves to its flattened index.
 */
static int
SEQUENCE_jer_flat_find(const asn_TYPE_descriptor_t *td, const void *key,
                       size_t size, size_t count, size_t *flat) {
    size_t i, match = SIZE_MAX;
    if(size > INT_MAX) return -1;
    for(i = 0; i < count; i++) {
        size_t outer, child;
        const asn_TYPE_member_t *member;
        if(SEQUENCE_jer_flat_map(td, i, &outer, &child)) return -1;
        member = child == SIZE_MAX ? &td->elements[outer]
            : &td->elements[outer].type->elements[child];
        if(jer_check_sym(key, (int)size, JER_MEMBER_NAME(member)) == JCK_KEY) {
            if(match != SIZE_MAX) return -1;
            match = i;
        }
    }
    if(match == SIZE_MAX) return 0;
    *flat = match;
    return 1;
}

/*
 * Purpose: decide whether a flattened field may be omitted before a key.
 * Source: SEQUENCE optional/default rules and extension-group presence.
 * Version/date: 1.0, 2026-10-31. Inputs: td/st/flat identify the field;
 * target is the matched key index or SIZE_MAX at object end.
 * Returns: nonzero when omission is legal, zero for a required field.
 * Errors: malformed layouts fail closed. Author: asn1c maintainers.
 * History: added for ordered flat-group decoding.
 * Example: an absent group can be skipped before a later field.
 */
static int
SEQUENCE_jer_flat_can_skip(const asn_TYPE_descriptor_t *td, const void *st,
                           size_t flat, size_t target) {
    size_t outer, child, target_outer = SIZE_MAX, target_child;
    const asn_TYPE_member_t *member;
    const asn_SEQUENCE_specifics_t *specs = td->specifics;
    if(SEQUENCE_jer_flat_map(td, flat, &outer, &child)) return 0;
    if(target != SIZE_MAX
    && SEQUENCE_jer_flat_map(td, target, &target_outer, &target_child)) return 0;
    if(child != SIZE_MAX) {
        const asn_TYPE_member_t *group = &td->elements[outer];
        const void *owner = SEQUENCE_jer_group_value(td, st, group);
        member = &group->type->elements[child];
        if(!owner && target_outer != outer) return 1;
        return member->optional || member->default_value_set;
    }
    member = &td->elements[outer];
    return (specs->first_extension >= 0
            && (size_t)specs->first_extension <= outer)
        || member->optional || member->default_value_set;
}

/*
 * Purpose: verify remaining fields are optional when a JSON object closes.
 * Source: SEQUENCE required-component rules and transparent group presence.
 * Version/date: 1.0, 2026-10-31. Inputs: td/st describe the value; next is the
 * next logical field. Returns: zero or -1 when a required field is missing.
 * Errors: missing required root/group fields reject the object.
 * Author: asn1c maintainers. History: added for flat-group decoding.
 * Example: an absent extension group is allowed at object closure.
 */
static int
SEQUENCE_jer_flat_complete(const asn_TYPE_descriptor_t *td, const void *st,
                           size_t next, size_t count) {
    size_t i;
    for(i = next; i < count; i++) {
        if(!SEQUENCE_jer_flat_can_skip(td, st, i, SIZE_MAX)) return -1;
    }
    return 0;
}

/*
 * Purpose: select a known ordered field or mark an unknown extension key.
 * Source: flattened name lookup and SEQUENCE omission rules.
 * Version/date: 1.0, 2026-10-31. Inputs: td/specs/st/ctx describe state;
 * key/size/count describe the candidate. Returns: zero or -1.
 * Errors: ambiguous, duplicate, out-of-order, and nonextensible unknown keys fail.
 * Author: asn1c maintainers. History: extracted from flat decoder dispatch.
 * Example: a valid `first` key sets ctx->step to that group's logical index.
 */
static int
SEQUENCE_jer_flat_select_key(const asn_TYPE_descriptor_t *td,
                             const asn_SEQUENCE_specifics_t *specs,
                             void *st, asn_struct_ctx_t *ctx,
                             const void *key, size_t size, size_t count) {
    size_t target = SIZE_MAX, i;
    int found = SEQUENCE_jer_flat_find(td, key, size, count, &target);
    if(found < 0 || (found && target < (size_t)ctx->step)) return -1;
    if(!found) {
        if(specs->first_extension < 0) return -1;
        ctx->left = 1;
    } else {
        for(i = (size_t)ctx->step; i < target; i++) {
            if(!SEQUENCE_jer_flat_can_skip(td, st, i, target)) return -1;
        }
        ctx->step = (short)target;
        ctx->left = 0;
    }
    ctx->phase = 5;
    return 0;
}


/*
 * Purpose: decode the field selected by the flat logical cursor.
 * Source: generated sequence storage and child JER decoder contracts.
 * Version/date: 1.0, 2026-10-31. Inputs: codec/td/st/ctx identify owner;
 * ptr/size hold the child JSON. Returns: child status and consumed bytes.
 * Errors: invalid layouts, allocation failure, and child errors propagate.
 * Author: asn1c maintainers. History: extracted to bound decoder complexity.
 * Example: a group pointer is allocated lazily before its first child decode.
 */
static asn_dec_rval_t
SEQUENCE_jer_flat_decode_member(const asn_codec_ctx_t *codec,
                               const asn_TYPE_descriptor_t *td, void *st,
                               asn_struct_ctx_t *ctx, const void *ptr,
                               size_t size) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    size_t outer_index, child_index;
    const asn_TYPE_member_t *member;
    const asn_TYPE_descriptor_t *owner_td = td;
    void *owner = st;
    void *inline_value;
    void **member_slot;
    int value_context = ctx->context;
    pjer_chunk_type_e value_chunk_type;
    ssize_t value_chunk_size;
    if(SEQUENCE_jer_flat_map(td, (size_t)ctx->step,
                             &outer_index, &child_index)) return result;
    if(child_index != SIZE_MAX) {
        const asn_TYPE_member_t *group = &td->elements[outer_index];
        void **group_slot = (void **)((char *)st + group->memb_offset);
        if(!*group_slot) {
            const asn_SEQUENCE_specifics_t *group_specs = group->type->specifics;
            *group_slot = CALLOC(1, group_specs->struct_size);
        }
        if(!*group_slot) return result;
        owner_td = group->type;
        owner = *group_slot;
        member = &group->type->elements[child_index];
    } else {
        member = &td->elements[outer_index];
    }
    if(SEQUENCE_jer_member_valid(owner_td, member)
    || !member->type->op || !member->type->op->jer_decoder) return result;
    if(size == 0) {
        result.code = RC_WMORE;
        return result;
    }
    value_chunk_size = jer_next_token(&value_context, ptr, size,
                                      &value_chunk_type);
    if(value_chunk_size == -1) return result;
    if(value_chunk_type == PJER_WMORE) {
        result.code = RC_WMORE;
        return result;
    }
    if(member->flags & ATF_POINTER) {
        member_slot = (void **)((char *)owner + member->memb_offset);
    } else {
        inline_value = (char *)owner + member->memb_offset;
        member_slot = &inline_value;
    }
    if(member->flags & ATF_OPEN_TYPE) {
        result = OPEN_TYPE_jer_get(codec, owner_td, owner, member, ptr, size);
    } else {
        result = member->type->op->jer_decoder(codec, member->type,
            member->encoding_constraints.jer_constraints, member_slot, ptr, size);
    }
    if(result.consumed > size || result.consumed > (size_t)SSIZE_MAX) {
        result.code = RC_FAIL;
        result.consumed = 0;
        return result;
    }
    if(result.code == RC_OK) {
        ctx->step++;
        ctx->phase = 1;
    }
    return result;
}

/*
 * Decode the JER (JSON) data.
 */
asn_dec_rval_t
SEQUENCE_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_jer_constraints_t *constraints,
                    void **struct_ptr, const void *ptr, size_t size) {
    static const char empty = 0;
    /*
     * Bring closer parts of structure description.
     */
    const asn_SEQUENCE_specifics_t *specs;
    asn_TYPE_member_t *elements;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    asn_dec_rval_t rval = {RC_FAIL, 0}; /* Return value from a decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    ssize_t edx;                   /* Element index */

    if(!td || !td->specifics || !struct_ptr || (!ptr && size)
    || size > (size_t)SSIZE_MAX || (td->elements_count && !td->elements))
        RETURN(RC_FAIL);
    specs = (const asn_SEQUENCE_specifics_t *)td->specifics;
    elements = td->elements;
    st = *struct_ptr;
    if(!ptr) ptr = &empty;
    (void)constraints;

    for(edx = 0; edx < td->elements_count; edx++) {
        if(elements[edx].flags & ATF_EXTENSION_GROUP)
            return SEQUENCE_decode_jer_flat(opt_codec_ctx, td, struct_ptr,
                                            ptr, size);
    }

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) RETURN(RC_FAIL);
    }

    /*
     * Restore parsing context.
     */
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

    /* Check recursion depth to prevent stack overflow */
    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
        RETURN(RC_FAIL);

    /*
     * Phases of JER/JSON processing:
     * Phase 0: Check that the key matches our expectations.
     * Phase 1: Processing body and reacting on closing token.
     * Phase 2: Processing inner type.
     * Phase 3: Skipping unknown extensions.
     * Phase 4: PHASED OUT
     */
    for(edx = ctx->step; ctx->phase <= 3;) {
        pjer_chunk_type_e ch_type;  /* JER chunk type */
        ssize_t ch_size;            /* Chunk size */
        jer_check_sym_e scv;        /* Tag check value */
        asn_TYPE_member_t *elm;


        /*
         * Go inside the inner member of a sequence.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval;
            void *memb_ptr_dontuse;  /* Pointer to the member */
            void **memb_ptr2;        /* Pointer to that pointer */

            elm = &td->elements[edx];
            if(elm->flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st + elm->memb_offset);
            } else {
                memb_ptr_dontuse = (char *)st + elm->memb_offset;
                memb_ptr2 = &memb_ptr_dontuse;  /* Only use of memb_ptr_dontuse */
            }

            if(elm->flags & ATF_OPEN_TYPE) {
                tmprval = OPEN_TYPE_jer_get(opt_codec_ctx, td, st, elm, ptr, size);
            } else {
                /* Invoke the inner type decoder, m.b. multiple times */
                tmprval = elm->type->op->jer_decoder(opt_codec_ctx,
                                                     elm->type,
                                                     elm->encoding_constraints.jer_constraints,
                                                     memb_ptr2,
                                                     ptr, size);
            }
            JER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 1;  /* Back to body processing */
            ctx->step = ++edx;
            ASN_DEBUG("JER/SEQUENCE phase => %d, step => %d",
                ctx->phase, ctx->step);
            /* Fall through */
        }

        /*
         * Get the next part of the JSON stream.
         */
        ch_size = jer_next_token(&ctx->context, ptr, size,
            &ch_type);
        if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
            switch(ch_type) {
            case PJER_WMORE:
                RETURN(RC_WMORE);

            case PJER_TEXT:  /* Ignore free-standing text */
                JER_ADVANCE(ch_size);  /* Skip silently */
                continue;

            case PJER_DLM:
            case PJER_VALUE:
            case PJER_KEY:
                break;  /* Check the rest down there */
            }
        }

        scv = jer_check_sym(ptr, ch_size, NULL);
        ASN_DEBUG("JER/SEQUENCE: scv = %d, ph=%d [%s]",
                  scv, ctx->phase, td->name);


        /* Skip the extensions section */
        if(ctx->phase == 3) {
            switch(jer_skip_unknown(scv, &ctx->left)) {
            case -1:
                ctx->phase = 4;
                RETURN(RC_FAIL);
            case 0:
                JER_ADVANCE(ch_size);
                continue;
            case 1:
                JER_ADVANCE(ch_size);
                ctx->phase = 1;
                continue;
            case 2:
                ctx->phase = 1;
                break;
            }
        }

        switch(scv) {
        case JCK_OEND:
            if(ctx->phase == 0) break;
            ctx->phase = 0;

            if(edx >= td->elements_count ||
               /* Explicit OPTIONAL specs reaches the end */
               (edx + elements[edx].optional == td->elements_count) ||
               /* All extensions are optional */
               IN_EXTENSION_GROUP(specs, edx)) {
                JER_ADVANCE(ch_size);
                JER_ADVANCE(jer_whitespace_span(ptr, size));
                ctx->phase = 4; /* Phase out */
                RETURN(RC_OK);
            } else {
                ASN_DEBUG("Premature end of JER SEQUENCE");
                RETURN(RC_FAIL);
            }
        case JCK_COMMA:
            JER_ADVANCE(ch_size);
            continue;
            /* Fall through */
        case JCK_OSTART: /* '{' */
            if(ctx->phase == 0) {
                JER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }

            /* Fall through */
        case JCK_KEY:
        case JCK_UNKNOWN:
            ASN_DEBUG("JER/SEQUENCE: scv=%d, ph=%d, edx=%" ASN_PRI_SIZE "",
                      scv, ctx->phase, edx);
            if(ctx->phase != 1) {
                break;  /* Really unexpected */
            }

            if (td->elements_count == 0) {
                JER_ADVANCE(ch_size);
                continue;
            }

            if(edx < td->elements_count) {
                /*
                 * We have to check which member is next.
                 */
                size_t n;
                size_t edx_end = edx + elements[edx].optional + 1;
                if(edx_end > td->elements_count) {
                    edx_end = td->elements_count;
                }

                for(n = edx; n < edx_end; n++) {
                    elm = &td->elements[n];
                    scv = jer_check_sym(ptr, ch_size, JER_MEMBER_NAME(elm));
                    switch (scv) {
                        case JCK_KEY:
                            ctx->step = edx = n;
                            ctx->phase = 2;

                            JER_ADVANCE(ch_size); /* skip key */
                            /* skip colon */
                            ch_size = jer_next_token(&ctx->context, ptr, size,
                                    &ch_type);
                            if(ch_size == -1) {
                                RETURN(RC_FAIL);
                            } else {
                                switch(ch_type) {
                                case PJER_WMORE:
                                    RETURN(RC_WMORE);
                                case PJER_TEXT:
                                    JER_ADVANCE(ch_size);
                                    break;
                                default:
                                    RETURN(RC_FAIL);
                                }
                            }
                            break;
                        case JCK_UNKNOWN:
                            continue;
                        default:
                            n = edx_end;
                            break; /* Phase out */
                    }
                    break;
                }
                if(n != edx_end)
                    continue;
            } else {
                ASN_DEBUG("Out of defined members: %" ASN_PRI_SIZE "/%u",
                          edx, td->elements_count);
            }

            /* It is expected extension */
            if(IN_EXTENSION_GROUP(specs,
                edx + (edx < td->elements_count
                    ? elements[edx].optional : 0))) {
                ASN_DEBUG("Got anticipated extension at %" ASN_PRI_SIZE "",
                          edx);
                ctx->left = 1;
                ctx->phase = 3;  /* Skip ...'s */
                JER_ADVANCE(ch_size);
                continue;
            }

            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected JSON key in SEQUENCE [%c%c%c%c%c%c]",
                  size>0?((const char *)ptr)[0]:'.',
                  size>1?((const char *)ptr)[1]:'.',
                  size>2?((const char *)ptr)[2]:'.',
                  size>3?((const char *)ptr)[3]:'.',
                  size>4?((const char *)ptr)[4]:'.',
                  size>5?((const char *)ptr)[5]:'.');
        break;
    }

    ctx->phase = 4;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}

/* Output state for one flattened SEQUENCE JER object. */
typedef struct SEQUENCE_jer_output_s {
    asn_app_consume_bytes_f *cb; /* Receives output fragments. */
    void *key; /* Callback context. */
    ssize_t count; /* Emitted byte count; state variable. */
    size_t members; /* Number of emitted fields; state variable. */
    int ilevel; /* Current indentation level. */
    enum jer_encoder_flags_e flags; /* Formatting flags. */
} SEQUENCE_jer_output_t;

/*
 * Purpose: write one bounded fragment and account for its output bytes.
 * Source: JER callback and encoded-length contracts.
 * Version/date: 1.0, 2026-10-31. Inputs: output is the sink; buf/size are bytes.
 * Returns: zero on success, -1 for callback or length overflow.
 * Exceptions: none. Author: asn1c maintainers.
 * History: added to emit flat SEQUENCE extension groups.
 * Example: writing `{` starts one encoded object.
 */
static int
SEQUENCE_jer_write(SEQUENCE_jer_output_t *output, const void *buf, size_t size) {
    if(size > (size_t)(SSIZE_MAX - output->count)
    || output->cb(buf, size, output->key) < 0) return -1;
    output->count += (ssize_t)size;
    return 0;
}

/*
 * Purpose: indent one line in non-minified JER output.
 * Source: existing SEQUENCE JER formatting convention.
 * Version/date: 1.0, 2026-10-31. Inputs: output is state; level is indentation.
 * Returns: zero on success, -1 for invalid levels or callback failure.
 * Exceptions: none. Author: asn1c maintainers.
 * History: added for flat SEQUENCE group output.
 * Example: level one emits four spaces after a newline.
 */
static int
SEQUENCE_jer_indent(SEQUENCE_jer_output_t *output, int level) {
    int i;
    if(output->flags & JER_F_MINIFIED) return 0;
    if(level < 0 || SEQUENCE_jer_write(output, "\n", 1)) return -1;
    for(i = 0; i < level; i++) {
        if(SEQUENCE_jer_write(output, "    ", 4)) return -1;
    }
    return 0;
}

/*
 * Purpose: reject JER names that cannot be written as literal JSON keys.
 * Source: jer_check_sym's literal wire-name matching.
 * Version/date: 1.0, 2026-10-31. Input: name is the effective member name.
 * Returns: nonzero when safe, zero for null or JSON-special names.
 * Exceptions: none. Author: asn1c maintainers.
 * History: fail closed for malformed flat-group keys.
 * Example: a quote in a wire name is rejected instead of corrupting JSON.
 */
static int
SEQUENCE_jer_name_safe(const char *name) {
    const unsigned char *p = (const unsigned char *)name;
    if(!p) return 0;
    for(; *p; p++) if(*p < 0x20 || *p == '"' || *p == '\\') return 0;
    return 1;
}

/*
 * Purpose: emit a SEQUENCE member name and JSON separator.
 * Source: X.697 member names and existing JER formatting.
 * Version/date: 1.0, 2026-10-31. Inputs: output is the sink; name is a wire key.
 * Returns: zero on success, -1 for unsafe names or callback failure.
 * Exceptions: none. Author: asn1c maintainers.
 * History: extracted for flat group and ordinary member encoding.
 * Example: emits `"field":` before its JER value.
 */
static int
SEQUENCE_jer_key(SEQUENCE_jer_output_t *output, const char *name) {
    if(!SEQUENCE_jer_name_safe(name)) return -1;
    if(output->members && SEQUENCE_jer_write(output, ",", 1)) return -1;
    if(SEQUENCE_jer_indent(output, output->ilevel + 1)
    || SEQUENCE_jer_write(output, "\"", 1)
    || SEQUENCE_jer_write(output, name, strlen(name))
    || SEQUENCE_jer_write(output, "\":", 2)) return -1;
    if(!(output->flags & JER_F_MINIFIED)
    && SEQUENCE_jer_write(output, " ", 1)) return -1;
    return 0;
}

/*
 * Purpose: encode one direct or grouped SEQUENCE field.
 * Source: generated member offsets and JER child encoder contracts.
 * Version/date: 1.0, 2026-10-31. Inputs: parent/member/value identify the field;
 * output receives its name and value. Returns: zero or -1.
 * Errors: missing required values, invalid metadata, and child failures reject.
 * Author: asn1c maintainers. History: added for flat extension-group output.
 * Example: a grouped child is encoded as an outer object sibling.
 */
static int
SEQUENCE_jer_encode_leaf(const asn_TYPE_descriptor_t *owner_td,
                         const void *owner_value,
                         const asn_TYPE_member_t *member,
                         SEQUENCE_jer_output_t *output) {
    const void *value;
    void *default_value = 0;
    asn_enc_rval_t child;
    const char *name = JER_MEMBER_NAME(member);
    if(SEQUENCE_jer_member_valid(owner_td, member) || !member->type->op) return -1;
    if(member->flags & ATF_POINTER) {
        value = *(const void *const *)((const char *)owner_value + member->memb_offset);
    } else {
        value = (const char *)owner_value + member->memb_offset;
    }
    if(!value) {
        if(member->default_value_set) {
            if(member->default_value_set(&default_value) || !default_value) {
                if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
                return -1;
            }
            value = default_value;
        } else if(member->optional) {
            return 0;
        } else {
            return -1;
        }
    }
    if(SEQUENCE_jer_key(output, name)) goto failed;
    if(member->flags & ATF_OPEN_TYPE) {
        child = OPEN_TYPE_jer_put(owner_td, owner_value, member,
            output->ilevel + 1, output->flags, output->cb, output->key);
    } else if(member->type->op->jer_encoder) {
        child = member->type->op->jer_encoder(member->type,
            member->encoding_constraints.jer_constraints, value,
            output->ilevel + 1, output->flags, output->cb, output->key);
    } else {
        goto failed;
    }
    if(child.encoded < 0 || child.encoded > SSIZE_MAX - output->count) goto failed;
    output->count += child.encoded;
    output->members++;
    if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
    return 0;
failed:
    if(default_value) ASN_STRUCT_FREE(*member->type, default_value);
    return -1;
}

/*
 * Purpose: encode a SEQUENCE with transparent extension-addition groups.
 * Source: X.697 flat JER component naming and generated group descriptors.
 * Version/date: 1.0, 2026-10-31. Inputs: td/value describe the SEQUENCE;
 * output controls formatting and callbacks. Returns: zero or -1.
 * Errors: malformed groups, missing required values, or callback failures fail.
 * Author: asn1c maintainers. History: added for flat SEQUENCE JER groups.
 * Example: `{[[]]}` children are written as sibling object properties.
 */
static int
SEQUENCE_jer_encode_flat(const asn_TYPE_descriptor_t *td, const void *value,
                         SEQUENCE_jer_output_t *output) {
    size_t i;
    if(SEQUENCE_jer_write(output, "{", 1)) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        if(member->flags & ATF_EXTENSION_GROUP) {
            const void *group;
            size_t child;
            if(SEQUENCE_jer_member_valid(td, member)
            || !(member->flags & ATF_POINTER) || !member->type
            || !member->type->elements || !member->type->elements_count
            || !member->type->specifics || !member->type->op
            || member->type->op->kind != ASN_KIND_SEQUENCE) return -1;
            group = SEQUENCE_jer_group_value(td, value, member);
            if(!group) {
                if(!member->optional) return -1;
                continue;
            }
            for(child = 0; child < member->type->elements_count; child++) {
                const asn_TYPE_member_t *leaf = &member->type->elements[child];
                if(leaf->flags & (ATF_EXTENSION_GROUP | ATF_OPEN_TYPE)) return -1;
                if(SEQUENCE_jer_encode_leaf(member->type, group, leaf, output)) return -1;
            }
        } else if(SEQUENCE_jer_encode_leaf(td, value, member, output)) {
            return -1;
        }
    }
    if(SEQUENCE_jer_indent(output, output->ilevel)
    || SEQUENCE_jer_write(output, "}", 1)) return -1;
    return 0;
}


asn_enc_rval_t SEQUENCE_encode_jer(const asn_TYPE_descriptor_t *td,
                    const asn_jer_constraints_t* constraints, const void *sptr,
                    int ilevel, enum jer_encoder_flags_e flags,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};
    int jmin = (flags & JER_F_MINIFIED);
    asn_TYPE_descriptor_t *tmp_def_val_td = 0;
    void *tmp_def_val = 0;
    size_t edx;
    int has_groups = 0;

    if(!td || !sptr || !cb || (td->elements_count && !td->elements))
        ASN__ENCODE_FAILED;
    for(edx = 0; edx < td->elements_count; edx++) {
        if(td->elements[edx].flags & ATF_EXTENSION_GROUP) has_groups = 1;
    }
    if(has_groups) {
        SEQUENCE_jer_output_t output = {cb, app_key, 0, 0, ilevel, flags};
        JER_ENCODER_RECURSION_DEPTH_INC();
        if(SEQUENCE_jer_flat_count(td) == SIZE_MAX
        || SEQUENCE_jer_encode_flat(td, sptr, &output)) {
            JER_ENCODER_RECURSION_DEPTH_DEC();
            ASN__ENCODE_FAILED;
        }
        JER_ENCODER_RECURSION_DEPTH_DEC();
        er.encoded = output.count;
        ASN__ENCODED_OK(er);
    }

    /* Check recursion depth to prevent stack overflow */
    JER_ENCODER_RECURSION_DEPTH_INC();

    er.encoded = 0;

    int bAddComma = 0;
    ASN__CALLBACK("{", 1);
    for(edx = 0; edx < td->elements_count; edx++) {
        asn_enc_rval_t tmper = {0,0,0};
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;
        const char *mname = JER_MEMBER_NAME(elm);
        unsigned int mlen = strlen(mname);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                assert(tmp_def_val == 0);
                if(elm->default_value_set) {
                    if(elm->default_value_set(&tmp_def_val)) {
                        JER_ENCODER_RECURSION_DEPTH_DEC();
                        ASN__ENCODE_FAILED;
                    } else {
                        memb_ptr = tmp_def_val;
                        tmp_def_val_td = elm->type;
                    }
                } else if(elm->optional) {
                    continue;
                } else {
                    /* Mandatory element is missing */
                    JER_ENCODER_RECURSION_DEPTH_DEC();
                    ASN__ENCODE_FAILED;
                }
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        if (bAddComma == 1) {
          ASN__CALLBACK(",", 1);
          bAddComma = 0;
        }

        if(!jmin) {
            ASN__TEXT_INDENT(1, ilevel + 1);
            ASN__CALLBACK3("\"", 1, mname, mlen, "\": ", 3);
        } else {
            ASN__CALLBACK3("\"", 1, mname, mlen, "\":", 2);
        }

        /* Print the member itself */
        if(elm->flags & ATF_OPEN_TYPE) {
            tmper = OPEN_TYPE_jer_put(td, sptr, elm, ilevel + 1, flags, cb, app_key);
        } else {
            tmper = elm->type->op->jer_encoder(elm->type,
                                               elm->encoding_constraints.jer_constraints,
                                               memb_ptr,
                                               ilevel + 1, flags, cb, app_key);
        }
        if(tmp_def_val) {
            ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
            tmp_def_val = 0;
        }
        if(tmper.encoded == -1) {
            JER_ENCODER_RECURSION_DEPTH_DEC();
            return tmper;
        }
        er.encoded += tmper.encoded;
        if (edx != td->elements_count - 1) {
          bAddComma = 1;
        }
    }
    if(!jmin) ASN__TEXT_INDENT(1, ilevel);
    ASN__CALLBACK("}", 1);


    JER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODED_OK(er);
cb_failed:
    if(tmp_def_val) ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
    JER_ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODE_FAILED;
}
