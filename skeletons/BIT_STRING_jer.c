/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_application.h>
#include <asn_internal.h>
#include <BIT_STRING.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/*
 * Skip JSON whitespace while parsing a BIT STRING value.
 *
 * Original source: local JER decoder helper. Version/date: 2026-10-30.
 * Parameters: cursor is the current input pointer; end is one past input.
 * Returns: no value; cursor advances over JSON whitespace. Throws: nothing.
 * Responsible party: asn1c maintainers. History: strict BIT STRING JER parse.
 * Example: spaces before '{' are skipped before the caller checks the brace.
 */
static void
BIT_STRING__jer_skip_whitespace(const char **cursor, const char *end) {
    while(*cursor < end) {
        switch(**cursor) {
        case 0x09: case 0x0a: case 0x0d: case 0x20:
            ++*cursor;
            break;
        default:
            return;
        }
    }
}

/*
 * Match a required JSON punctuation byte after optional whitespace.
 *
 * Original source: local JER decoder helper. Version/date: 2026-10-30.
 * Parameters: cursor/end bound the input; expected is the required byte.
 * Returns: 1 for match, 0 for incomplete input, -1 for invalid input.
 * Throws: nothing. Responsible party: asn1c maintainers.
 * History: strict BIT STRING JER parse. Example: match the object's '{'.
 */
static int
BIT_STRING__jer_expect_char(const char **cursor, const char *end,
                            int expected) {
    BIT_STRING__jer_skip_whitespace(cursor, end);
    if(*cursor == end) return 0;
    if(**cursor != expected) return -1;
    ++*cursor;
    return 1;
}

/*
 * Match an exact, unescaped JSON object member name.
 *
 * Original source: local JER decoder helper. Version/date: 2026-10-30.
 * Parameters: cursor/end bound input; expected is the required ASCII name.
 * Returns: 1 for match, 0 for incomplete input, -1 for invalid input.
 * Throws: nothing. Responsible party: asn1c maintainers.
 * History: reject unknown, escaped, and duplicate members. Example: match
 * `value` while rejecting `valueExtra`.
 */
static int
BIT_STRING__jer_expect_key(const char **cursor, const char *end,
                           const char *expected) {
    const char *key_start;
    size_t key_length = strlen(expected);

    BIT_STRING__jer_skip_whitespace(cursor, end);
    if(*cursor == end || **cursor != '"') {
        return *cursor == end ? 0 : -1;
    }
    key_start = ++*cursor;
    while(*cursor < end && **cursor != '"') ++*cursor;
    if(*cursor == end) return 0;
    if((size_t)(*cursor - key_start) != key_length
       || memcmp(key_start, expected, key_length) != 0) {
        return -1;
    }
    ++*cursor;
    return 1;
}

/*
 * Decode one quoted hexadecimal string into a newly allocated octet buffer.
 *
 * Original source: local JER decoder helper. Version/date: 2026-10-30.
 * Parameters: cursor/end bound input; bytes and byte_count receive output.
 * Returns: 1 for success, 0 for incomplete input, -1 for malformed input or
 * allocation failure. Throws: nothing. Responsible party: asn1c maintainers.
 * History: validates complete even-length hex before allocating. Example:
 * `"A0"` produces one byte with value 0xA0.
 */
static int
BIT_STRING__jer_parse_hex(const char **cursor, const char *end,
                          uint8_t **bytes, size_t *byte_count) {
    const char *start;
    const char *stop;
    uint8_t *decoded;
    size_t length;
    size_t i;

    BIT_STRING__jer_skip_whitespace(cursor, end);
    if(*cursor == end) return 0;
    if(**cursor != '"') return -1;
    start = ++*cursor;
    for(stop = start; stop < end && *stop != '"'; ++stop) {
        unsigned char ch = (unsigned char)*stop;
        if(!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')
             || (ch >= 'a' && ch <= 'f'))) return -1;
    }
    if(stop == end) return 0;
    length = (size_t)(stop - start);
    if(length & 1) return -1;
    if(length / 2 == SIZE_MAX) return -1;
    decoded = (uint8_t *)MALLOC(length / 2 + 1);
    if(!decoded) return -1;

    /* Convert each validated pair, retaining a terminator for legacy users. */
    for(i = 0; i < length / 2; ++i) {
        unsigned char high = (unsigned char)start[i * 2];
        unsigned char low = (unsigned char)start[i * 2 + 1];
        unsigned int high_value = high <= '9' ? high - '0'
            : (high <= 'F' ? high - 'A' + 10 : high - 'a' + 10);
        unsigned int low_value = low <= '9' ? low - '0'
            : (low <= 'F' ? low - 'A' + 10 : low - 'a' + 10);
        decoded[i] = (uint8_t)((high_value << 4) | low_value);
    }
    decoded[length / 2] = 0;
    *bytes = decoded;
    *byte_count = length / 2;
    *cursor = stop + 1;
    return 1;
}

/*
 * Parse the unsigned `length` member and close its containing JSON object.
 *
 * Original source: local JER decoder helper. Version/date: 2026-10-30.
 * Parameters: cursor/end bound input; bit_count receives the parsed value.
 * Returns: 1 for success, 0 for incomplete input, -1 for invalid syntax or
 * overflow. Throws: nothing. Responsible party: asn1c maintainers.
 * History: rejects negative, fractional, exponent, and overflowing lengths.
 * Example: `8}` sets bit_count to 8 and consumes the closing brace.
 */
static int
BIT_STRING__jer_parse_length(const char **cursor, const char *end,
                             size_t *bit_count) {
    size_t value = 0;
    size_t digits = 0;

    BIT_STRING__jer_skip_whitespace(cursor, end);
    while(*cursor < end && **cursor >= '0' && **cursor <= '9') {
        unsigned int digit = (unsigned int)(**cursor - '0');
        if(value > (SIZE_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
        ++digits;
        ++*cursor;
    }
    if(!digits) return *cursor == end ? 0 : -1;
    if(digits > 1 && (*cursor - digits)[0] == '0') return -1;

    BIT_STRING__jer_skip_whitespace(cursor, end);
    if(*cursor == end) return 0;
    if(**cursor != '}') return -1;
    ++*cursor;
    *bit_count = value;
    return 1;
}

/*
 * Validate BIT STRING storage, padding, overflow, and an optional fixed size.
 *
 * Original source: local JER encoder helper. Version/date: 2026-10-30.
 * Parameters: value is the source BIT STRING; fixed_bits is -1 or exact size;
 * bit_count receives the logical width. Returns: zero for valid, -1 otherwise.
 * Throws: nothing. Responsible party: asn1c maintainers.
 * History: protect JER hex output from invalid storage and padding. Example:
 * a one-byte value with `bits_unused == 3` has five meaningful bits.
 */
static int
BIT_STRING__jer_validate_value(const BIT_STRING_t *value, ssize_t fixed_bits,
                               size_t *bit_count) {
    size_t capacity;
    size_t unused;
    size_t expected_bytes;

    if(!value || (value->size && !value->buf) || fixed_bits < -1
       || value->bits_unused < 0 || value->bits_unused > 7
       || value->size > SIZE_MAX / 8) return -1;
    if(value->size == 0 && value->bits_unused != 0) return -1;
    capacity = value->size * 8;
    unused = (size_t)value->bits_unused;
    if(unused > capacity) return -1;
    if(value->size && unused
       && (value->buf[value->size - 1] & ((1u << unused) - 1u))) return -1;
    *bit_count = capacity - unused;
    if(fixed_bits >= 0) {
        if((size_t)fixed_bits != *bit_count) return -1;
        expected_bytes = ((size_t)fixed_bits + 7) / 8;
        if(value->size != expected_bytes) return -1;
    }
    return 0;
}

/*
 * Emit BIT STRING bytes as uppercase hexadecimal in bounded callback chunks.
 *
 * Original source: local JER encoder helper. Version/date: 2026-10-30.
 * Parameters: value supplies bytes; cb/key are the output callback pair;
 * encoded tracks successful output bytes. Returns: zero on success, -1 on
 * callback or count overflow. Throws: nothing. Responsible party: maintainers.
 * History: shares fixed and variable wire output. Example: 0xAB emits `AB`.
 */
static int
BIT_STRING__jer_emit_hex(const BIT_STRING_t *value,
                         asn_app_consume_bytes_f *cb, void *key,
                         asn_enc_rval_t *encoded) {
    static const char hex[] = "0123456789ABCDEF";
    char chunk[32];
    size_t offset;

    for(offset = 0; offset < value->size; offset += sizeof(chunk) / 2) {
        size_t count = value->size - offset;
        size_t i;
        if(count > sizeof(chunk) / 2) count = sizeof(chunk) / 2;
        for(i = 0; i < count; ++i) {
            uint8_t byte = value->buf[offset + i];
            chunk[i * 2] = hex[byte >> 4];
            chunk[i * 2 + 1] = hex[byte & 0x0f];
        }
        if(encoded->encoded > SSIZE_MAX - (ssize_t)(count * 2)
           || cb(chunk, count * 2, key) < 0) return -1;
        encoded->encoded += (ssize_t)(count * 2);
    }
    return 0;
}

/*
 * Encode a BIT STRING using fixed quoted hex or the variable JER object form.
 *
 * Original source: asn1c BIT STRING JER encoder, hardened locally.
 * Version/date: 2026-10-30. Parameters: td supplies descriptor constraints;
 * constraints optionally overrides them; sptr is the BIT STRING; ilevel and
 * flags select formatting; cb/app_key receive output. Returns: encoded byte
 * count or -1 with failure metadata. Throws: nothing. Responsible party:
 * asn1c maintainers. History: validates bounds/padding and permits empty data.
 * Example: empty variable value encodes as {"value":"","length":0}.
 */
asn_enc_rval_t
BIT_STRING_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      const void *sptr, int ilevel,
                      enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    const asn_jer_constraints_t *cts = constraints;
    size_t bit_count;
    ssize_t fixed_bits = -1;
    int minified = (flags & JER_F_MINIFIED) != 0;
    char scratch[64];
    int written;

    if(!cts && td) cts = td->encoding_constraints.jer_constraints;
    if(cts) fixed_bits = cts->size;
    if(!cb || BIT_STRING__jer_validate_value(st, fixed_bits, &bit_count)) {
        ASN__ENCODE_FAILED;
    }
    (void)bit_count;

    if(fixed_bits >= 0) {
        ASN__CALLBACK("\"", 1);
        if(BIT_STRING__jer_emit_hex(st, cb, app_key, &er)) ASN__ENCODE_FAILED;
        ASN__CALLBACK("\"", 1);
    } else {
        ASN__CALLBACK("{", 1);
        if(!minified) ASN__TEXT_INDENT(1, ilevel + 1);
        ASN__CALLBACK(minified ? "\"value\":" : "\"value\": ",
                      minified ? 8 : 9);
        ASN__CALLBACK("\"", 1);
        if(BIT_STRING__jer_emit_hex(st, cb, app_key, &er)) ASN__ENCODE_FAILED;
        ASN__CALLBACK("\",", 2);
        if(!minified) ASN__TEXT_INDENT(1, ilevel + 1);
        ASN__CALLBACK(minified ? "\"length\":" : "\"length\": ",
                      minified ? 9 : 10);
        written = snprintf(scratch, sizeof(scratch), "%zu", bit_count);
        if(written < 0 || (size_t)written >= sizeof(scratch)) {
            ASN__ENCODE_FAILED;
        }
        ASN__CALLBACK(scratch, (size_t)written);
        if(!minified) ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK("}", 1);
    }
    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                                      \
    do {                                                   \
        rval.code = (_code);                              \
        rval.consumed = (ssize_t)(p - input);              \
        FREEMEM(new_buf);                                  \
        return rval;                                       \
    } while(0)

/*
 * Decode fixed quoted hex or a variable BIT STRING JER value transactionally.
 *
 * Original source: asn1c BIT STRING JER decoder, hardened locally.
 * Version/date: 2026-10-30. Parameters: opt_codec_ctx is unused; td supplies
 * descriptor constraints; constraints optionally overrides them; sptr is the
 * destination pointer; buf_ptr/size describe one input value. Returns: RC_OK
 * with consumed bytes, RC_WMORE for incomplete input, or RC_FAIL. Throws:
 * nothing. Responsible party: asn1c maintainers. History: exact sizes,
 * padding, overflow, and malformed JSON checks; failed parses preserve values.
 * Example: a variable value uses {"value":"AB","length":8}.
 */
asn_dec_rval_t
BIT_STRING_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      void **sptr, const void *buf_ptr, size_t size) {
    static const char empty_input[] = "";
    BIT_STRING_t *st;
    const asn_jer_constraints_t *cts = constraints;
    const char *input = empty_input;
    const char *p = empty_input;
    const char *end;
    asn_dec_rval_t rval = {RC_FAIL, 0};
    uint8_t *new_buf = 0;
    size_t byte_count = 0;
    size_t bit_count = 0;
    size_t fixed_bits = 0;
    int variable;
    int parse_result;

    (void)opt_codec_ctx;
    if(!sptr || (size && !buf_ptr) || size > PTRDIFF_MAX) RETURN(RC_FAIL);
    if(!cts && td) cts = td->encoding_constraints.jer_constraints;
    variable = !cts || cts->size == -1;
    if(cts && cts->size < -1) RETURN(RC_FAIL);
    input = buf_ptr ? (const char *)buf_ptr : empty_input;
    p = input;
    end = input + size;

    /* Variable BIT STRING values require the exact value/length object shape. */
    if(variable) {
        parse_result = BIT_STRING__jer_expect_char(&p, end, '{');
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
        parse_result = BIT_STRING__jer_expect_key(&p, end, "value");
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
        parse_result = BIT_STRING__jer_expect_char(&p, end, ':');
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
    }

    /* Parse the complete hex string into temporary storage for transactionality. */
    parse_result = BIT_STRING__jer_parse_hex(&p, end, &new_buf, &byte_count);
    if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);

    if(variable) {
        parse_result = BIT_STRING__jer_expect_char(&p, end, ',');
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
        parse_result = BIT_STRING__jer_expect_key(&p, end, "length");
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
        parse_result = BIT_STRING__jer_expect_char(&p, end, ':');
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
        parse_result = BIT_STRING__jer_parse_length(&p, end, &bit_count);
        if(parse_result <= 0) RETURN(parse_result == 0 ? RC_WMORE : RC_FAIL);
    } else {
        fixed_bits = (size_t)cts->size;
        bit_count = fixed_bits;
    }

    /* Confirm byte count, logical width, and all discarded low bits agree. */
    if(byte_count > SIZE_MAX / 8 || bit_count > byte_count * 8
       || byte_count * 8 - bit_count > 7) RETURN(RC_FAIL);
    if(!variable) {
        size_t expected_bytes = (fixed_bits + 7) / 8;
        size_t expected_unused = expected_bytes * 8 - fixed_bits;
        if(byte_count != expected_bytes || byte_count * 8 - bit_count
           != expected_unused) RETURN(RC_FAIL);
    }
    if(byte_count && (byte_count * 8 != bit_count)
       && (new_buf[byte_count - 1]
           & ((1u << (byte_count * 8 - bit_count)) - 1u))) RETURN(RC_FAIL);

    /* Allocate the result only after every member and bit invariant is valid. */
    st = (BIT_STRING_t *)*sptr;
    if(!st) {
        st = (BIT_STRING_t *)CALLOC(1, sizeof(*st));
        if(!st) RETURN(RC_FAIL);
    }
    if(st->buf) FREEMEM(st->buf);
    st->buf = new_buf;
    st->size = byte_count;
    st->bits_unused = (int)(byte_count * 8 - bit_count);
    new_buf = 0;
    *sptr = st;
    RETURN(RC_OK);
}
