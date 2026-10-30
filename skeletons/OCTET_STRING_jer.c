/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>  /* for .bits_unused member */

static const char jer_base64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode an OCTET STRING as the established uppercase hexadecimal JER string.
 *
 * Original source: asn1c OCTET STRING JER encoder.
 * Version/date: 2026-10-30. Parameters: td/constraints describe the ASN.1
 * type; sptr supplies the octets; ilevel/flags select formatting; cb/app_key
 * receive output. Returns: encoded byte count or -1 on failure. Throws:
 * nothing. Responsible party: asn1c maintainers. History: empty values use
 * valid backing storage before forming the end pointer. Example: empty input
 * emits `""`.
 */
asn_enc_rval_t
OCTET_STRING_encode_jer(const asn_TYPE_descriptor_t *td,
                        const asn_jer_constraints_t *constraints,
                        const void *sptr, int ilevel,
                        enum jer_encoder_flags_e flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const char * const h2c = "0123456789ABCDEF";
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    char scratch[16 * 3 + 4];
    char *p = scratch;
    static const uint8_t empty[1] = {0};
    const uint8_t *buf;
    const uint8_t *end;
    size_t i;

    (void)ilevel;
    (void)flags;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    er.encoded = 0;

    /*
     * Dump the contents of the buffer in hexadecimal.
     */
    /* Use valid storage for empty strings before forming the end pointer. */
    buf = st->buf ? st->buf : empty;
    end = buf + st->size;
    ASN__CALLBACK("\"", 1);
    for(i = 0; buf < end; buf++, i++) {
      if(!(i % 16) && (i || st->size > 16)) {
        ASN__CALLBACK(scratch, p-scratch);
        p = scratch;
      }
      *p++ = h2c[(*buf >> 4) & 0x0F];
      *p++ = h2c[*buf & 0x0F];
    }
    if(p - scratch) {
      ASN__CALLBACK(scratch, p-scratch);  /* Dump the rest */
    }
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Encode an OCTET STRING as the established padded base64 JER string.
 *
 * Original source: asn1c OCTET STRING base64 JER encoder.
 * Version/date: 2026-10-30. Parameters: td/constraints describe the ASN.1
 * type; sptr supplies the octets; ilevel/flags select formatting; cb/app_key
 * receive output. Returns: encoded byte count or -1 on failure. Throws:
 * nothing. Responsible party: asn1c maintainers. History: empty values use
 * valid backing storage before forming the end pointer. Example: empty input
 * emits `""`.
 */
asn_enc_rval_t
OCTET_STRING_encode_jer_base64(const asn_TYPE_descriptor_t *td,
                               const asn_jer_constraints_t *constraints,
                               const void *sptr, int ilevel,
                               enum jer_encoder_flags_e flags,
                               asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    char scratch[128];
    char *p = scratch;
    static const uint8_t empty[1] = {0};
    const uint8_t *buf;
    size_t remaining;

    (void)td;
    (void)constraints;
    (void)ilevel;
    (void)flags;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    er.encoded = 0;
    ASN__CALLBACK("\"", 1);

    /* Use valid storage for empty strings before iterating over octets. */
    buf = st->buf ? st->buf : empty;
    remaining = st->size;
    while(remaining) {
        uint32_t value = 0;
        int bytes_to_encode = remaining >= 3 ? 3 : (int)remaining;
        int i;

        for(i = 0; i < bytes_to_encode; i++)
            value = (value << 8) | buf[i];
        if(bytes_to_encode < 3)
            value <<= 8 * (3 - bytes_to_encode);
        buf += bytes_to_encode;
        remaining -= (size_t)bytes_to_encode;

        for(i = 0; i < 4; i++) {
            if(p >= scratch + sizeof(scratch) - 4) {
                ASN__CALLBACK(scratch, p - scratch);
                p = scratch;
            }
            if(i < bytes_to_encode + 1) {
                int idx = (value >> (18 - i * 6)) & 0x3F;
                *p++ = jer_base64_encode_table[idx];
            } else {
                *p++ = '=';
            }
        }
    }

    if(p > scratch)
        ASN__CALLBACK(scratch, p - scratch);
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

static const struct OCTET_STRING__jer_escape_table_s {
    const char *string;
    int size;
} OCTET_STRING__jer_escape_table[] = {
#define OSXBT(s)  { "\\"s"", sizeof(s) + 1 - 1 }
#define OSXUT(s)  { "\\u00"s"", sizeof(s) + 4 - 1 }
    OSXUT("00"),  /* NULL */
    OSXUT("01"),  /* Start of header */
    OSXUT("02"),  /* Start of text */
    OSXUT("03"),  /* End of text */
    OSXUT("04"),  /* End of transmission */
    OSXUT("05"),  /* Enquiry */
    OSXUT("06"),  /* Ack */
    OSXUT("07"),  /* Bell */
    OSXBT("b"),   /* \b */
    OSXBT("t"),   /* \t */
    OSXBT("n"),   /* \n */
    OSXUT("0b"),  /* Vertical tab */
    OSXBT("f"),   /* \f */
    OSXBT("r"),   /* \r */
    OSXUT("0e"),  /* Shift out */
    OSXUT("0f"),  /* Shift in */
    OSXUT("10"),  /* Data link escape */
    OSXUT("11"),  /* Device control 1 */
    OSXUT("12"),  /* Device control 2 */
    OSXUT("13"),  /* Device control 3 */
    OSXUT("14"),  /* Device control 4 */
    OSXUT("15"),  /* Negative ack */
    OSXUT("16"),  /* Synchronous idle */
    OSXUT("17"),  /* End of transmission block */
    OSXUT("18"),  /* Cancel */
    OSXUT("19"),  /* End of medium */
    OSXUT("1a"),  /* Substitute */
    OSXUT("1b"),  /* Escape */
    OSXUT("1c"),  /* File separator */
    OSXUT("1d"),  /* Group separator */
    OSXUT("1e"),  /* Record separator */
    OSXUT("1f"),  /* Unit separator */
    { 0, 0 },                           /* " " */
    { 0, 0 },                           /* ! */
    OSXBT("\""),                  /* \" */
    { 0, 0 },                           /* # */
    { 0, 0 },                           /* $ */
    { 0, 0 },                           /* % */
    { 0, 0 },  /* &amp; */
    { 0, 0 },                           /* ' */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},  /* ()*+,-./ */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},  /* 01234567 */
    {0,0},{0,0},{0,0},{0,0},            /* 89:; */
    { 0, 0 },  /* &lt; */
    { 0, 0 },                           /* = */
    { 0, 0 },  /* &gt; */
    { 0, 0 },  /* ? */
    { 0, 0 },  /* @ */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, /* ABCDEFGH */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, /* IJKLMNOP */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, /* QRSTUVWX */
    {0,0},{0,0},                                     /* YZ */
    { 0, 0 },  /* [ */
    OSXBT("\\"),  /* \\ */
};

static int
OS__check_escaped_control_char(const void *buf, int size) {
    size_t i;
    /*
     * Inefficient algorithm which translates the escape sequences
     * defined above into characters. Returns -1 if not found.
     * TODO: replace by a faster algorithm (bsearch(), hash or
     * nested table lookups).
     */
    for(i = 0; i < 32 /* Don't spend time on the bottom half */; i++) {
        const struct OCTET_STRING__jer_escape_table_s *el;
        el = &OCTET_STRING__jer_escape_table[i];
        if(el->size == size && memcmp(buf, el->string, size) == 0)
            return i;
    }
    return -1;
}

static int
OCTET_STRING__handle_control_chars(void *struct_ptr, const void *chunk_buf, size_t chunk_size) {
    /*
     * This might be one of the escape sequences
     * for control characters. Check it out.
     * #11.15.5
     */
    int control_char = OS__check_escaped_control_char(chunk_buf,chunk_size);
    if(control_char >= 0) {
        OCTET_STRING_t *st = (OCTET_STRING_t *)struct_ptr;
        void *p = REALLOC(st->buf, st->size + 2);
        if(p) {
            st->buf = (uint8_t *)p;
            st->buf[st->size++] = control_char;
            st->buf[st->size] = '\0';  /* nul-termination */
            return 0;
        }
    }

    return -1;  /* No, it's not */
}

asn_enc_rval_t
OCTET_STRING_encode_jer_utf8(const asn_TYPE_descriptor_t *td,
                             const asn_jer_constraints_t *constraints,
                             const void *sptr, int ilevel,
                             enum jer_encoder_flags_e flags,
                             asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    uint8_t *buf, *end;
    uint8_t *ss;  /* Sequence start */
    ssize_t encoded_len = 0;

    (void)ilevel;  /* Unused argument */
    (void)flags;  /* Unused argument */

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    buf = st->buf;
    end = buf + st->size;
    ASN__CALLBACK("\"", 1);
    for(ss = buf; buf < end; buf++) {
        unsigned int ch = *buf;
        int s_len;	/* Special encoding sequence length */

        /*
         * Escape certain characters
         */
        if(ch < sizeof(OCTET_STRING__jer_escape_table)
            / sizeof(OCTET_STRING__jer_escape_table[0])
        && (s_len = OCTET_STRING__jer_escape_table[ch].size)) {
            if(((buf - ss) && cb(ss, buf - ss, app_key) < 0)
            || cb(OCTET_STRING__jer_escape_table[ch].string, s_len, app_key) < 0)
                ASN__ENCODE_FAILED;
            encoded_len += (buf - ss) + s_len;
            ss = buf + 1;
        }
    }

    encoded_len += (buf - ss);
    if((buf - ss) && cb(ss, buf - ss, app_key) < 0)
        goto cb_failed;

    er.encoded += encoded_len;

    ASN__CALLBACK("\"", 1);
    ASN__ENCODED_OK(er);

cb_failed:
    ASN__ENCODE_FAILED;
}

#define CQUOTE 0x22

/*
 * Convert from hexadecimal format (cstring): "AB CD EF"
 */
static ssize_t OCTET_STRING__convert_hexadecimal(void *sptr, const void *chunk_buf, size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
    const char *chunk_stop = (const char *)chunk_buf;
    const char *p = chunk_stop;
    const char *pend = p + chunk_size;
    unsigned int clv = 0;
    int half = 0;	/* Half bit */
    uint8_t *buf;

    /* Strip quotes */
    for (; p < pend; ++p) {
        if (*p == CQUOTE) {
            ++p;
            break;
        }
    }
    /* Find ending quote - ensure we don't go below the start */
    if (pend > (const char *)chunk_buf) {
        --pend;
        for (; pend >= p; --pend) {
            if (*pend == CQUOTE)
                break;
        }
    }
    if (pend < p) return -1;
    chunk_size = pend - p;

    /* Reallocate buffer according to high cap estimation */
    size_t hex_byte_count = (chunk_size + 1) / 2;
    /* Check for potential overflow */
    if (hex_byte_count > SIZE_MAX - st->size - 1) return -1;
    size_t new_size = st->size + hex_byte_count;
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    /*
     * If something like " a b c " appears here, the " a b":3 will be
     * converted, and the rest skipped. That is, unless buf_size is greater
     * than chunk_size, then it'll be equivalent to "ABC0".
     */
    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        switch(ch) {
        /* allow LF, FF, CR, space */
        case 0x0a: case 0x0c: case 0x0d: case 0x20:
            continue;
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
            clv = (clv << 4) + (ch - 0x30);
            break;
        case 0x41: case 0x42: case 0x43:  /* ABC */
        case 0x44: case 0x45: case 0x46:  /* DEF */
            clv = (clv << 4) + (ch - 0x41 + 10);
            break;
        case 0x61: case 0x62: case 0x63:  /* abc */
        case 0x64: case 0x65: case 0x66:  /* def */
            clv = (clv << 4) + (ch - 0x61 + 10);
            break;
        default:
            *buf = 0;  /* JIC */
            return -1;
        }
        if(half++) {
            half = 0;
            *buf++ = clv;
            chunk_stop = p + 1;
        }
    }

    /*
     * Check partial decoding.
     */
    if(half) {
        if(have_more) {
            /*
             * Partial specification is fine,
             * because no more more PJER_TEXT data is available.
             */
            *buf++ = clv << 4;
            chunk_stop = p;
        }
    } else {
        ++p;
        chunk_stop = p;
    }

    st->size = buf - st->buf;  /* Adjust the buffer size */
    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    /* Ensure return value is valid */
    ssize_t consumed = chunk_stop - (const char *)chunk_buf;
    if (consumed < 0 || (size_t)consumed > chunk_size + 2) return -1;  /* +2 for quotes */
    return consumed;  /* Converted size */
}

/*
 * Something like strtod(), but with stricter rules.
 */
static int
OS__strtoent(const char *buf, const char *end, int32_t *ret_value) {
	const int32_t last_unicode_codepoint = 0x10ffff;
	int32_t val = 0;
	const char *p;

	for(p = buf; p < end; p++) {
		int ch = *p;

        switch(ch) {
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
            val = val * 16 + (ch - 0x30);
            break;
        case 0x41: case 0x42: case 0x43:  /* ABC */
        case 0x44: case 0x45: case 0x46:  /* DEF */
            val = val * 16 + (ch - 0x41 + 10);
            break;
        case 0x61: case 0x62: case 0x63:  /* abc */
        case 0x64: case 0x65: case 0x66:  /* def */
            val = val * 16 + (ch - 0x61 + 10);
            break;
        default:
            return -1;  /* Character set error */
        }

        /* Value exceeds the Unicode range. */
        if(val > last_unicode_codepoint) {
            return -1;
        }
    }

    *ret_value = val;
    return (p - buf);
}

/*
 * Decode a JSON string and validate its escapes and Unicode surrogate pairs.
 * Original source: asn1c JER character-string decoder. Version: 2026-10-30.
 * Inputs: sptr receives octets; chunk_buf/chunk_size contain the JSON token;
 * have_more indicates whether the current token is complete. Returns bytes
 * consumed, or -1 for invalid content or allocation failure. No exceptions.
 * Owner: asn1c maintainers. History: reject invalid JSON escapes. Example:
 * the pair \ud83d\ude00 becomes the UTF-8 bytes for U+1F600.
 */
static ssize_t
OCTET_STRING__convert_entrefs(void *sptr, const void *chunk_buf,
                              size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
    const char *p = (const char *)chunk_buf;
    const char *pend;
    uint8_t *buf;

    if(!sptr || !chunk_buf || chunk_size < 2) return -1;
    pend = p + chunk_size;
    /* Strip quotes */
    for(; p < pend; ++p) {
        if (*p == CQUOTE) {
            ++p;
            break;
        }
    }
    --pend;
    for(; pend >= p; --pend) {
        if (*pend == CQUOTE)
            break;
    }
    if(pend - p < 0)
        return -1;

    /* Reallocate without wrapping the size or the terminator. */
    if(st->size == SIZE_MAX || (size_t)(pend - p) > SIZE_MAX - st->size - 1) return -1;
    size_t new_size = st->size + (pend - p);
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    /*
     * Convert into the octet string.
     */
    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        size_t len;  /* Length of the rest of the chunk */

        if(ch != 0x5c /* '\' */) {
            if(ch < 0x20) return -1;
            *buf++ = ch;
            continue;  /* That was easy... */
        }

        /*
         * Process entity reference.
         */
        len = (size_t)(pend - p);
        if(len == 1 /* "\" */) goto want_more;
        switch(p[1]) {
        case 0x75: /* 'u' */
            ;
            const char *pval;  /* Pointer to start of digits */
            int32_t val = 0;  /* Entity reference value */

            if(len < 6) goto want_more;
            pval = p + 2;
            len = OS__strtoent(pval, pval + 4, &val);
            if(len != 4) return -1;
            p += 5;  /* Advance past the four hexadecimal digits. */
            if(val >= 0xd800 && val <= 0xdbff) {
                int32_t low;
                if(pend - p < 7 || p[1] != '\\' || p[2] != 'u'
                   || OS__strtoent(p + 3, p + 7, &low) != 4
                   || low < 0xdc00 || low > 0xdfff) return -1;
                val = 0x10000 + ((val - 0xd800) << 10) + (low - 0xdc00);
                p += 6;
            } else if(val >= 0xdc00 && val <= 0xdfff) {
                return -1;
            }

            if(val < 0x80) {
                *buf++ = (char)val;
            } else if(val < 0x800) {
                *buf++ = 0xc0 | ((val >> 6));
                *buf++ = 0x80 | ((val & 0x3f));
            } else if(val < 0x10000) {
                *buf++ = 0xe0 | ((val >> 12));
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            } else if(val < 0x200000) {
                *buf++ = 0xf0 | ((val >> 18));
                *buf++ = 0x80 | ((val >> 12) & 0x3f);
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            } else if(val < 0x4000000) {
                *buf++ = 0xf8 | ((val >> 24));
                *buf++ = 0x80 | ((val >> 18) & 0x3f);
                *buf++ = 0x80 | ((val >> 12) & 0x3f);
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            } else {
                *buf++ = 0xfc | ((val >> 30) & 0x1);
                *buf++ = 0x80 | ((val >> 24) & 0x3f);
                *buf++ = 0x80 | ((val >> 18) & 0x3f);
                *buf++ = 0x80 | ((val >> 12) & 0x3f);
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            }
            break;
        case 0x22: /* " */
            *buf++ = 0x22;
            ++p;
            break;
        case 0x2f: /* / */
            *buf++ = 0x2f;
            ++p;
            break;
        case 0x5c: /* \ */
            *buf++ = 0x5c;
            ++p;
            break;
        case 0x62: /* b */
            *buf++ = 0x08;
            ++p;
            break;
        case 0x66: /* f */
            *buf++ = 0x0c;
            ++p;
            break;
        case 0x6e: /* n */
            *buf++ = 0x0a;
            ++p;
            break;
        case 0x72: /* r */
            *buf++ = 0x0d;
            ++p;
            break;
        case 0x74: /* t */
            *buf++ = 0x09;
            ++p;
            break;
        default:
            /* JSON permits only the escape sequences listed above. */
            return -1;
        }
        continue;
    want_more:
        if(have_more) return -1;
        chunk_size = (p - (const char *)chunk_buf);
        /* Processing stalled: need more data */
        break;
    }

    st->size = buf - st->buf;
    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    return chunk_size;  /* Converted in full */
}

/*
 * Decode OCTET STRING from the JSON element's value.
 */
static asn_dec_rval_t
OCTET_STRING__decode_jer(
    const asn_codec_ctx_t *opt_codec_ctx, const asn_TYPE_descriptor_t *td,
    void **sptr, const void *buf_ptr, size_t size,
    int (*opt_unexpected_tag_decoder)(void *struct_ptr, const void *chunk_buf,
                                      size_t chunk_size),
    ssize_t (*body_receiver)(void *struct_ptr, const void *chunk_buf,
                             size_t chunk_size, int have_more)) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_OCTET_STRING_specs;
    asn_struct_ctx_t *ctx;  /* Per-structure parser context */
    asn_dec_rval_t rval;  /* Return value from the decoder */
    int st_allocated;

    /*
     * Create the string if does not exist.
     */
    if(!st) {
        st = (OCTET_STRING_t *)CALLOC(1, specs->struct_size);
        *sptr = (void *)st;
        if(!st) goto sta_failed;
        st_allocated = 1;
    } else {
        st_allocated = 0;
    }
    if(!st->buf) {
        /* This is separate from above section */
        st->buf = (uint8_t *)CALLOC(1, 1);
        if(!st->buf) {
            if(st_allocated) {
                *sptr = 0;
                goto stb_failed;
            } else {
                goto sta_failed;
            }
        }
    }

    /* Restore parsing context */
    ctx = (asn_struct_ctx_t *)(((char *)*sptr) + specs->ctx_offset);

    return jer_decode_general(opt_codec_ctx, ctx, *sptr,
                              buf_ptr, size,
                              opt_unexpected_tag_decoder,
                              body_receiver);

stb_failed:
    FREEMEM(st);
sta_failed:
    rval.code = RC_FAIL;
    rval.consumed = 0;
    return rval;
}

/*
 * Decode OCTET STRING from the hexadecimal data.
 */
asn_dec_rval_t
OCTET_STRING_decode_jer_hex(const asn_codec_ctx_t *opt_codec_ctx,
                            const asn_TYPE_descriptor_t *td,
                            const asn_jer_constraints_t *constraints,
                            void **sptr,
                            const void *buf_ptr, size_t size) {
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_hexadecimal);
}

static int
jer_base64_decode_char(char c) {
    if(c >= 'A' && c <= 'Z') return c - 'A';
    if(c >= 'a' && c <= 'z') return c - 'a' + 26;
    if(c >= '0' && c <= '9') return c - '0' + 52;
    if(c == '+') return 62;
    if(c == '/') return 63;
    if(c == '=') return -2;
    return -1;
}

static ssize_t
OCTET_STRING__convert_base64(void *sptr, const void *chunk_buf,
                             size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
    const char *p = (const char *)chunk_buf;
    const char *pend = p + chunk_size;
    size_t original_size = chunk_size;
    uint8_t *buf;
    uint32_t value;
    int bits_collected;
    int padding_seen;
    size_t new_size;
    void *nptr;

    for(; p < pend; ++p) {
        if(*p == CQUOTE) {
            ++p;
            break;
        }
    }
    if(pend > (const char *)chunk_buf) {
        --pend;
        for(; pend >= p; --pend) {
            if(*pend == CQUOTE)
                break;
        }
    }
    if(pend < p) return -1;
    chunk_size = pend - p;

    new_size = st->size + (chunk_size * 3 / 4) + 3;
    nptr = REALLOC(st->buf, new_size + 1);

    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    if(!st->_xer_decode_state.decoder_initialized) {
        st->_xer_decode_state.accumulated_value = 0;
        st->_xer_decode_state.bits_collected = 0;
        st->_xer_decode_state.padding_seen = 0;
        st->_xer_decode_state.decoder_initialized = 1;
    }

    value = st->_xer_decode_state.accumulated_value;
    bits_collected = st->_xer_decode_state.bits_collected;
    padding_seen = st->_xer_decode_state.padding_seen;

    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        int decoded = jer_base64_decode_char((char)ch);

        if(decoded == -1) return -1;
        if(decoded == -2) {
            padding_seen = 1;
            continue;
        }
        if(padding_seen) return -1;

        value = (value << 6) | (uint32_t)decoded;
        bits_collected += 6;
        while(bits_collected >= 8) {
            bits_collected -= 8;
            *buf++ = (uint8_t)((value >> bits_collected) & 0xFF);
        }
    }

    st->size = buf - st->buf;
    st->buf[st->size] = 0;
    st->_xer_decode_state.accumulated_value = value;
    st->_xer_decode_state.bits_collected = bits_collected;
    st->_xer_decode_state.padding_seen = padding_seen;

    if(!have_more && bits_collected != 0 && !padding_seen)
        return -1;

    return original_size;
}

asn_dec_rval_t
OCTET_STRING_decode_jer_base64(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td,
                               const asn_jer_constraints_t *constraints,
                               void **sptr, const void *buf_ptr, size_t size) {
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_base64);
}

/*
 * Decode OCTET STRING from the string (ASCII/UTF-8) data.
 */
asn_dec_rval_t
OCTET_STRING_decode_jer_utf8(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td,
                             const asn_jer_constraints_t *constraints,
                             void **sptr, const void *buf_ptr, size_t size) {
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr,
                                    buf_ptr, size,
                                    OCTET_STRING__handle_control_chars,
                                    OCTET_STRING__convert_entrefs);
}
