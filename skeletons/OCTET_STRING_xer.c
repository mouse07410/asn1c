/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>  /* for .bits_unused member */

asn_enc_rval_t
OCTET_STRING_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int ilevel, enum xer_encoder_flags_e flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const char * const h2c = "0123456789ABCDEF";
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    char scratch[16 * 3 + 4];
    char *p = scratch;
    uint8_t *buf;
    uint8_t *end;
    size_t i;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    er.encoded = 0;

    /*
     * Dump the contents of the buffer in hexadecimal.
     */
    buf = st->buf;
    end = buf + st->size;
    if(flags & XER_F_CANONICAL) {
        char *scend = scratch + (sizeof(scratch) - 2);
        for(; buf < end; buf++) {
            if(p >= scend) {
                ASN__CALLBACK(scratch, p - scratch);
                p = scratch;
            }
            *p++ = h2c[(*buf >> 4) & 0x0F];
            *p++ = h2c[*buf & 0x0F];
        }

        ASN__CALLBACK(scratch, p-scratch);  /* Dump the rest */
    } else {
        for(i = 0; buf < end; buf++, i++) {
            if(!(i % 16) && (i || st->size > 16)) {
                ASN__CALLBACK(scratch, p-scratch);
                p = scratch;
                ASN__TEXT_INDENT(1, ilevel);
            }
            *p++ = h2c[(*buf >> 4) & 0x0F];
            *p++ = h2c[*buf & 0x0F];
            *p++ = 0x20;
        }
        if(p - scratch) {
            p--;  /* Remove the tail space */
            ASN__CALLBACK(scratch, p-scratch);  /* Dump the rest */
            if(st->size > 16)
                ASN__TEXT_INDENT(1, ilevel-1);
        }
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

static const struct OCTET_STRING__xer_escape_table_s {
    const char *string;
    int size;
} OCTET_STRING__xer_escape_table[] = {
#define	OSXET(s)	{ s, sizeof(s) - 1 }
    OSXET("\074\156\165\154\057\076"),  /* <nul/> */
    OSXET("\074\163\157\150\057\076"),  /* <soh/> */
    OSXET("\074\163\164\170\057\076"),  /* <stx/> */
    OSXET("\074\145\164\170\057\076"),  /* <etx/> */
    OSXET("\074\145\157\164\057\076"),  /* <eot/> */
    OSXET("\074\145\156\161\057\076"),  /* <enq/> */
    OSXET("\074\141\143\153\057\076"),  /* <ack/> */
    OSXET("\074\142\145\154\057\076"),  /* <bel/> */
    OSXET("\074\142\163\057\076"),      /* <bs/> */
    OSXET("\011"),                      /* \t */
    OSXET("\012"),                      /* \n */
    OSXET("\074\166\164\057\076"),      /* <vt/> */
    OSXET("\074\146\146\057\076"),      /* <ff/> */
    OSXET("\015"),                      /* \r */
    OSXET("\074\163\157\057\076"),      /* <so/> */
    OSXET("\074\163\151\057\076"),      /* <si/> */
    OSXET("\074\144\154\145\057\076"),  /* <dle/> */
    OSXET("\074\144\143\061\057\076"),  /* <de1/> */
    OSXET("\074\144\143\062\057\076"),  /* <de2/> */
    OSXET("\074\144\143\063\057\076"),  /* <de3/> */
    OSXET("\074\144\143\064\057\076"),  /* <de4/> */
    OSXET("\074\156\141\153\057\076"),  /* <nak/> */
    OSXET("\074\163\171\156\057\076"),  /* <syn/> */
    OSXET("\074\145\164\142\057\076"),  /* <etb/> */
    OSXET("\074\143\141\156\057\076"),  /* <can/> */
    OSXET("\074\145\155\057\076"),      /* <em/> */
    OSXET("\074\163\165\142\057\076"),  /* <sub/> */
    OSXET("\074\145\163\143\057\076"),  /* <esc/> */
    OSXET("\074\151\163\064\057\076"),  /* <is4/> */
    OSXET("\074\151\163\063\057\076"),  /* <is3/> */
    OSXET("\074\151\163\062\057\076"),  /* <is2/> */
    OSXET("\074\151\163\061\057\076"),  /* <is1/> */
    { 0, 0 },                           /* " " */
    { 0, 0 },                           /* ! */
    { 0, 0 },                           /* \" */
    { 0, 0 },                           /* # */
    { 0, 0 },                           /* $ */
    { 0, 0 },                           /* % */
    OSXET("\046\141\155\160\073"),      /* &amp; */
    { 0, 0 },                           /* ' */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},  /* ()*+,-./ */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},  /* 01234567 */
    {0,0},{0,0},{0,0},{0,0},            /* 89:; */
    OSXET("\046\154\164\073"),          /* &lt; */
    { 0, 0 },                           /* = */
    OSXET("\046\147\164\073"),          /* &gt; */
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
        const struct OCTET_STRING__xer_escape_table_s *el;
        el = &OCTET_STRING__xer_escape_table[i];
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
OCTET_STRING_encode_xer_utf8(const asn_TYPE_descriptor_t *td, const void *sptr,
                             int ilevel, enum xer_encoder_flags_e flags,
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
    for(ss = buf; buf < end; buf++) {
        unsigned int ch = *buf;
        int s_len;	/* Special encoding sequence length */

        /*
         * Escape certain characters: X.680/11.15
         */
        if(ch < sizeof(OCTET_STRING__xer_escape_table)
            / sizeof(OCTET_STRING__xer_escape_table[0])
        && (s_len = OCTET_STRING__xer_escape_table[ch].size)) {
            if(((buf - ss) && cb(ss, buf - ss, app_key) < 0)
            || cb(OCTET_STRING__xer_escape_table[ch].string, s_len, app_key) < 0)
                ASN__ENCODE_FAILED;
            encoded_len += (buf - ss) + s_len;
            ss = buf + 1;
        }
    }

    encoded_len += (buf - ss);
    if((buf - ss) && cb(ss, buf - ss, app_key) < 0)
        ASN__ENCODE_FAILED;

    er.encoded = encoded_len;
    ASN__ENCODED_OK(er);
}

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

    /* Reallocate buffer according to high cap estimation */
    size_t new_size = st->size + (chunk_size + 1) / 2;
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
        case 0x09: case 0x0a: case 0x0c: case 0x0d:
        case 0x20:
            /* Ignore whitespace */
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
             * because no more more PXER_TEXT data is available.
             */
            *buf++ = clv << 4;
            chunk_stop = p;
        }
    } else {
        chunk_stop = p;
    }

    st->size = buf - st->buf;  /* Adjust the buffer size */
    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    return (chunk_stop - (const char *)chunk_buf);  /* Converted size */
}

/*
 * Convert from binary format: "00101011101"
 */
static ssize_t OCTET_STRING__convert_binary(void *sptr, const void *chunk_buf, size_t chunk_size, int have_more) {
    BIT_STRING_t *st = (BIT_STRING_t *)sptr;
    const char *p = (const char *)chunk_buf;
    const char *pend = (p == NULL)? NULL : p + chunk_size;
    int bits_unused = st->bits_unused & 0x7;
    uint8_t *buf;

    /* Reallocate buffer according to high cap estimation */
    size_t new_size = st->size + (chunk_size + 7) / 8;
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    (void)have_more;

    if(bits_unused == 0)
        bits_unused = 8;
    else if(st->size)
        buf--;

    /*
     * Convert series of 0 and 1 into the octet string.
     */
    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        switch(ch) {
        case 0x09: case 0x0a: case 0x0c: case 0x0d:
        case 0x20:
            /* Ignore whitespace */
            break;
        case 0x30:
        case 0x31:
            if(bits_unused-- <= 0) {
                *++buf = 0;	/* Clean the cell */
                bits_unused = 7;
            }
            *buf |= (ch&1) << bits_unused;
            break;
        default:
            st->bits_unused = bits_unused;
            return -1;
        }
    }

    if(bits_unused == 8) {
        st->size = buf - st->buf;
        st->bits_unused = 0;
    } else {
        st->size = buf - st->buf + 1;
        st->bits_unused = bits_unused;
    }

    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    return chunk_size;  /* Converted in full */
}

/*
 * Convert from hexadecimal format to BIT STRING: "0455AA..."
 * This is similar to OCTET_STRING__convert_hexadecimal but sets bits_unused to 0.
 */
static ssize_t BIT_STRING__convert_hexadecimal(void *sptr, const void *chunk_buf, size_t chunk_size, int have_more) {
    BIT_STRING_t *st = (BIT_STRING_t *)sptr;
    const char *chunk_stop = (const char *)chunk_buf;
    const char *p = chunk_stop;
    const char *pend = p + chunk_size;
    unsigned int clv = 0;
    int half = 0;	/* Half bit */
    uint8_t *buf;

    /* Reallocate buffer according to high cap estimation */
    size_t new_size = st->size + (chunk_size + 1) / 2;
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        switch(ch) {
        case 0x09: case 0x0a: case 0x0c: case 0x0d:
        case 0x20:
            /* Ignore whitespace */
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
             * because no more PXER_TEXT data is available.
             */
            *buf++ = clv << 4;
            chunk_stop = p;
        }
    } else {
        chunk_stop = p;
    }

    st->size = buf - st->buf;  /* Adjust the buffer size */
    st->bits_unused = 0;  /* For BIT STRING, hex means all bits are used */
    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    return (chunk_stop - (const char *)chunk_buf);  /* Converted size */
}

/*
 * Check if the content looks like binary format (only 0s, 1s, and whitespace).
 * Returns 1 if content appears to be binary, 0 otherwise.
 */
static int
BIT_STRING__is_binary(const void *chunk_buf, size_t chunk_size) {
    const unsigned char *p = (const unsigned char *)chunk_buf;
    const unsigned char *pend = p + chunk_size;

    for (; p < pend; p++) {
        unsigned char ch = *p;
        switch(ch) {
        case 0x09: case 0x0a: case 0x0c: case 0x0d:
        case 0x20:
            /* Whitespace is allowed */
            continue;
        case 0x30:  /* '0' */
        case 0x31:  /* '1' */
            /* Binary digits */
            continue;
        default:
            /* Non-binary character found, not binary format */
            return 0;
        }
    }
    return 1;  /* Only binary characters found */
}

/*
 * Auto-detect and convert from either binary or hexadecimal format for BIT STRING.
 * Supports explicit prefixes per X.693:
 *   - B'...' or b'...' for binary format
 *   - H'...' or h'...' for hexadecimal format
 * Without explicit prefixes, defaults to binary unless hexadecimal digits (2-9, A-F)
 * are found in the string.
 */
static ssize_t
BIT_STRING__convert_binary_or_hex(void *sptr, const void *chunk_buf,
                                  size_t chunk_size, int have_more) {
    const unsigned char *buf_start = (const unsigned char *)chunk_buf;
    const unsigned char *p = buf_start;
    const unsigned char *pend = p + chunk_size;
    int explicit_binary = 0;
    int explicit_hex = 0;

    /* Skip leading whitespace */
    while(p < pend && (*p == 0x09 || *p == 0x0a || *p == 0x0c ||
                       *p == 0x0d || *p == 0x20)) {
        p++;
    }

    /* Check for explicit B or H prefix */
    if(p < pend) {
        if((*p == 'B' || *p == 'b') && (p + 1) < pend && p[1] == '\'') {
            explicit_binary = 1;
            p += 2;  /* Skip B' */
        } else if((*p == 'H' || *p == 'h') && (p + 1) < pend && p[1] == '\'') {
            explicit_hex = 1;
            p += 2;  /* Skip H' */
        }
    }

    if(explicit_binary || explicit_hex) {
        /* Find the closing quote and calculate actual content size */
        const unsigned char *content_start = p;
        const unsigned char *content_end = p;
        while(content_end < pend && *content_end != '\'') {
            content_end++;
        }
        size_t content_size = content_end - content_start;
        ssize_t result;

        if(explicit_binary) {
            result = OCTET_STRING__convert_binary(sptr, content_start, content_size, have_more);
        } else {
            result = BIT_STRING__convert_hexadecimal(sptr, content_start, content_size, have_more);
        }

        if(result < 0) return result;

        /* Return total consumed from original buffer including prefix and closing quote */
        size_t total_consumed = (content_end - buf_start);
        if(content_end < pend && *content_end == '\'') {
            total_consumed++;  /* Include closing quote */
        }
        return total_consumed;
    }

    /* No explicit prefix - auto-detect based on content */
    /* Default to binary unless hex digits (2-9, A-F) are found */
    if(BIT_STRING__is_binary(chunk_buf, chunk_size)) {
        return OCTET_STRING__convert_binary(sptr, chunk_buf, chunk_size, have_more);
    } else {
        return BIT_STRING__convert_hexadecimal(sptr, chunk_buf, chunk_size, have_more);
    }
}

/*
 * Something like strtod(), but with stricter rules.
 */
static int
OS__strtoent(int base, const char *buf, const char *end, int32_t *ret_value) {
	const int32_t last_unicode_codepoint = 0x10ffff;
	int32_t val = 0;
	const char *p;

	for(p = buf; p < end; p++) {
		int ch = *p;

        switch(ch) {
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
            val = val * base + (ch - 0x30);
            break;
        case 0x41: case 0x42: case 0x43:  /* ABC */
        case 0x44: case 0x45: case 0x46:  /* DEF */
            val = val * base + (ch - 0x41 + 10);
            break;
        case 0x61: case 0x62: case 0x63:  /* abc */
        case 0x64: case 0x65: case 0x66:  /* def */
            val = val * base + (ch - 0x61 + 10);
            break;
        case 0x3b:  /* ';' */
            *ret_value = val;
            return (p - buf) + 1;
        default:
            return -1;  /* Character set error */
        }

        /* Value exceeds the Unicode range. */
        if(val > last_unicode_codepoint) {
            return -1;
        }
    }

    *ret_value = -1;
    return (p - buf);
}

/*
 * Convert from the plain UTF-8 format, expanding entity references: "2 &lt; 3"
 */
static ssize_t
OCTET_STRING__convert_entrefs(void *sptr, const void *chunk_buf,
                              size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
    const char *p = (const char *)chunk_buf;
    const char *pend = p + chunk_size;
    uint8_t *buf;

    /* Reallocate buffer */
    size_t new_size = st->size + chunk_size;
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    /*
     * Convert series of 0 and 1 into the octet string.
     */
    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        int len;  /* Length of the rest of the chunk */

        if(ch != 0x26 /* '&' */) {
            *buf++ = ch;
            continue;  /* That was easy... */
        }

        /*
         * Process entity reference.
         */
        len = chunk_size - (p - (const char *)chunk_buf);
        if(len == 1 /* "&" */) goto want_more;
        if(p[1] == 0x23 /* '#' */) {
            const char *pval;  /* Pointer to start of digits */
            int32_t val = 0;  /* Entity reference value */
            int base;

            if(len == 2 /* "&#" */) goto want_more;
            if(p[2] == 0x78 /* 'x' */)
                pval = p + 3, base = 16;
            else
                pval = p + 2, base = 10;
            len = OS__strtoent(base, pval, p + len, &val);
            if(len == -1) {
                /* Invalid charset. Just copy verbatim. */
                *buf++ = ch;
                continue;
            }
            if(!len || pval[len-1] != 0x3b) goto want_more;
            assert(val > 0);
            p += (pval - p) + len - 1;  /* Advance past entref */

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
        } else {
            /*
             * Ugly, limited parsing of &amp; &gt; &lt;
             */
            char *sc = (char *)memchr(p, 0x3b, len > 5 ? 5 : len);
            if(!sc) goto want_more;
            if((sc - p) == 4
                && p[1] == 0x61  /* 'a' */
                && p[2] == 0x6d  /* 'm' */
                && p[3] == 0x70  /* 'p' */) {
                *buf++ = 0x26;
                p = sc;
                continue;
            }
            if((sc - p) == 3) {
                if(p[1] == 0x6c) {
                    *buf = 0x3c;  /* '<' */
                } else if(p[1] == 0x67) {
                    *buf = 0x3e;  /* '>' */
                } else {
                    /* Unsupported entity reference */
                    *buf++ = ch;
                    continue;
                }
                if(p[2] != 0x74) {
                    /* Unsupported entity reference */
                    *buf++ = ch;
                    continue;
                }
                buf++;
                p = sc;
                continue;
            }
            /* Unsupported entity reference */
            *buf++ = ch;
        }

        continue;
    want_more:
        if(have_more) {
            /*
             * We know that no more data (of the same type)
             * is coming. Copy the rest verbatim.
             */
            *buf++ = ch;
            continue;
        }
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
 * Base64 encoding table
 */
static const char base64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode OCTET STRING to Base64 format for XER
 */
asn_enc_rval_t
OCTET_STRING_encode_xer_base64(const asn_TYPE_descriptor_t *td, const void *sptr,
                               int ilevel, enum xer_encoder_flags_e flags,
                               asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    char scratch[80];  /* 76 chars per line + newline is typical for Base64 */
    char *p = scratch;
    const uint8_t *buf;
    const uint8_t *end;
    size_t i;
    int chars_on_line = 0;
    const int max_chars_per_line = 76;

    (void)td;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    er.encoded = 0;
    buf = st->buf;
    end = buf + st->size;

    /*
     * Encode buffer in Base64.
     * Process 3 bytes at a time into 4 Base64 characters.
     */
    while(buf < end) {
        uint32_t value = 0;
        int bytes_left = end - buf;
        int bytes_to_encode = (bytes_left >= 3) ? 3 : bytes_left;
        
        /* Build a 24-bit value from up to 3 bytes */
        for(i = 0; i < bytes_to_encode; i++) {
            value = (value << 8) | buf[i];
        }
        
        /* Shift to align if we have fewer than 3 bytes */
        if(bytes_to_encode < 3) {
            value <<= 8 * (3 - bytes_to_encode);
        }
        
        buf += bytes_to_encode;
        
        /* Extract 4 6-bit values and encode them */
        for(i = 0; i < 4; i++) {
            if(p >= scratch + sizeof(scratch) - 2) {
                /* Flush buffer */
                ASN__CALLBACK(scratch, p - scratch);
                p = scratch;
                chars_on_line = 0;
            }
            
            if(!(flags & XER_F_CANONICAL) && chars_on_line >= max_chars_per_line) {
                /* Add line break for readability (not in canonical mode) */
                ASN__CALLBACK(scratch, p - scratch);
                p = scratch;
                ASN__TEXT_INDENT(1, ilevel);
                chars_on_line = 0;
            }
            
            if(i < bytes_to_encode + 1) {
                /* Valid data character */
                int idx = (value >> (18 - i * 6)) & 0x3F;
                *p++ = base64_encode_table[idx];
                chars_on_line++;
            } else {
                /* Padding */
                *p++ = '=';
                chars_on_line++;
            }
        }
    }

    /* Flush any remaining data */
    if(p > scratch) {
        ASN__CALLBACK(scratch, p - scratch);
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Base64 decoding table (inverse of encode table)
 * Returns -1 for invalid characters, -2 for padding '='
 */
static int
base64_decode_char(char c) {
    if(c >= 'A' && c <= 'Z') return c - 'A';
    if(c >= 'a' && c <= 'z') return c - 'a' + 26;
    if(c >= '0' && c <= '9') return c - '0' + 52;
    if(c == '+') return 62;
    if(c == '/') return 63;
    if(c == '=') return -2;  /* Padding */
    return -1;  /* Invalid character */
}

/*
 * Convert from Base64 format.
 *  
 * This function is called incrementally by the XER decoder, potentially one
 * character at a time. We handle this by buffering the input characters
 * in the output buffer, then decoding them once we have complete groups or
 * reach the end of input.
 */
static ssize_t
OCTET_STRING__convert_base64(void *sptr, const void *chunk_buf,
                             size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;

    /* Reallocate buffer to hold existing data plus new input 
     * We use the buffer to accumulate Base64 characters as text initially */
    size_t new_size = st->size + chunk_size + 2;  /* +2 for null term and extra space */
    void *nptr = REALLOC(st->buf, new_size);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;

    /* Append new characters to the buffer (treating it as text for now) */
    memcpy(st->buf + st->size, chunk_buf, chunk_size);
    st->size += chunk_size;
    st->buf[st->size] = '\0';  /* Null terminate for safety */

    /* Check if we should decode. We decode when:
     * 1. We have reached the end of the element (have_more == 0), OR
     * 2. We have padding chars (1+ '=' marks end of Base64), OR
     * 3. We have a complete Base64 group (multiple of 4 chars excluding whitespace)
     * This handles single padding, double padding, no padding, and incremental cases. */
    int should_decode = 0;
    
    if(!have_more) {
        /* We've reached the end of the element, so decode whatever we have */
        should_decode = 1;
    } else if(st->size >= 1) {
        /* Count consecutive '=' from the end, ignoring whitespace */
        int padding_count = 0;
        int non_ws_chars = 0;  /* Count non-whitespace chars for length check */
        
        for(ssize_t i = st->size - 1; i >= 0; i--) {
            int ch = st->buf[i];
            if(ch == '=') {
                if(padding_count == 0) {
                    padding_count++;
                } else if(i < st->size - 1 && st->buf[i+1] == '=') {
                    /* Consecutive padding */
                    padding_count++;
                } else {
                    /* Non-consecutive '=' - might be in the middle, not padding */
                    break;
                }
            } else if(ch == 0x09 || ch == 0x0a || ch == 0x0c || ch == 0x0d || ch == 0x20) {
                continue;  /* Skip whitespace */
            } else {
                /* Hit a non-whitespace, non-padding char */
                break;
            }
        }
        
        /* Count total non-whitespace characters for complete group check */
        for(ssize_t i = 0; i < st->size; i++) {
            int ch = st->buf[i];
            if(ch != 0x09 && ch != 0x0a && ch != 0x0c && ch != 0x0d && ch != 0x20) {
                non_ws_chars++;
            }
        }
        
        /* Decode if we have padding (marks end of Base64) */
        if(padding_count >= 1) {
            should_decode = 1;
        }
        /* Or decode if we have a complete Base64 group (multiple of 4 chars) */
        else if(non_ws_chars > 0 && (non_ws_chars % 4) == 0) {
            should_decode = 1;
        }
    }
    
    /* Only decode if we've detected end-of-Base64 or have complete group */
    if(should_decode && st->size > 0) {
        /* Now decode the complete Base64 string in-place */
        const char *src = (const char *)st->buf;
        const char *src_end = src + st->size;
        uint8_t *dst = st->buf;  /* Decode in-place */
        uint32_t value = 0;
        int bits_collected = 0;
        int padding_seen = 0;

        for(; src < src_end; src++) {
            int ch = *(const unsigned char *)src;
            int decoded;
            
            /* Skip whitespace */
            switch(ch) {
            case 0x09: case 0x0a: case 0x0c: case 0x0d: case 0x20:
                continue;
            default:
                break;
            }
            
            decoded = base64_decode_char(ch);
            
            if(decoded == -1) {
                /* Invalid character - error */
                st->size = dst - st->buf;
                st->buf[st->size] = 0;
                return -1;
            }
            
            if(decoded == -2) {
                /* Padding character */
                padding_seen = 1;
                continue;
            }
            
            if(padding_seen) {
                /* Data after padding is invalid */
                st->size = dst - st->buf;
                st->buf[st->size] = 0;
                return -1;
            }
            
            /* Accumulate 6 bits */
            value = (value << 6) | decoded;
            bits_collected += 6;
            
            /* When we have 8 or more bits, extract a byte */
            if(bits_collected >= 8) {
                bits_collected -= 8;
                *dst++ = (value >> bits_collected) & 0xFF;
            }
        }

        /* Update size to reflect decoded data */
        st->size = dst - st->buf;
        if(st->size < new_size) {
            st->buf[st->size] = 0;  /* Null terminate */
        }
    }

    /* Return amount of input consumed (all of it) */
    return chunk_size;
}

/*
 * Check if the content looks like hexadecimal encoding.
 * Returns 1 if content appears to be hex, 0 if it appears to be Base64.
 * 
 * Since Base64 is the default XER encoding for OCTET STRING (per X.693),
 * we prefer Base64 decoding in ambiguous cases. Only treat as hex if we
 * have strong indicators:
 * 
 * Definite hex indicators:
 * - 0x/0X prefix
 * - Spaces between character pairs (hex encoder adds spaces in normal mode)
 * 
 * Definite Base64 indicators:
 * - Characters G-Z, g-z, +, /, = (not valid in hex)
 * - Lowercase a-f (our hex encoder uses uppercase only)
 * 
 * Ambiguous (all uppercase A-F and 0-9): prefer Base64
 */
static int
OCTET_STRING__is_hexadecimal(const void *chunk_buf, size_t chunk_size) {
    const unsigned char *p = (const unsigned char *)chunk_buf;
    const unsigned char *pend = p + chunk_size;
    int has_0x_prefix = 0;
    int has_spaces_between = 0;
    int hex_digits = 0;
    int prev_was_hex = 0;

    /* Skip leading whitespace */
    while (p < pend && (*p == 0x09 || *p == 0x0a || *p == 0x0c ||
                        *p == 0x0d || *p == 0x20)) {
        p++;
    }

    /* Check for 0x / 0X prefix - strong hex indicator */
    if (p + 1 < pend && *p == '0' && (p[1] == 'x' || p[1] == 'X')) {
        has_0x_prefix = 1;
        p += 2;
    }

    for (; p < pend; p++) {
        unsigned char ch = *p;

        /* Check for spaces between hex digits (hex encoder adds these) */
        if (ch == 0x09 || ch == 0x0a || ch == 0x0c || ch == 0x0d || ch == 0x20) {
            if (prev_was_hex && hex_digits >= 2) {
                has_spaces_between = 1;
            }
            prev_was_hex = 0;
            continue;
        }

        /* Lowercase a-f: our hex encoder uses uppercase only */
        if (ch >= 'a' && ch <= 'f') {
            return 0;  /* Treat as Base64 */
        }

        /* Other Base64-only chars or padding => definitely Base64 */
        if ((ch >= 'G' && ch <= 'Z') ||
            (ch >= 'g' && ch <= 'z') ||
            ch == '+' || ch == '/' || ch == '=') {
            return 0;
        }

        /* Uppercase hex digits (0-9, A-F) */
        if ((ch >= '0' && ch <= '9') ||
            (ch >= 'A' && ch <= 'F')) {
            hex_digits++;
            prev_was_hex = 1;
            continue;
        }

        /* Any other character not valid in either format */
        return 0;
    }

    /* No content -> not hex */
    if (hex_digits == 0) return 0;

    /* Odd number of hex digits -> not valid hex */
    if (hex_digits & 1) return 0;

    /* Strong hex indicators present -> treat as hex */
    if (has_0x_prefix || has_spaces_between) {
        return 1;
    }

    /* Ambiguous case (only uppercase hex chars, no spaces, no prefix):
     * Prefer Base64 since it's the default XER encoding for OCTET STRING.
     * This handles cases like "AAEA" which is valid Base64 for 3 bytes but
     * could be misinterpreted as 2 hex bytes.
     */
    return 0;
}

/*
 * Auto-detect and convert from either hexadecimal or Base64 format.
 * Supports explicit prefixes per X.693:
 *   - H'...' or h'...' for hexadecimal format
 * Without explicit prefixes, detects the format by examining the content.
 */
static ssize_t
OCTET_STRING__convert_auto(void *sptr, const void *chunk_buf,
                           size_t chunk_size, int have_more) {
    const unsigned char *buf_start = (const unsigned char *)chunk_buf;
    const unsigned char *p = buf_start;
    const unsigned char *pend = p + chunk_size;

    /* Skip leading whitespace */
    while(p < pend && (*p == 0x09 || *p == 0x0a || *p == 0x0c ||
                       *p == 0x0d || *p == 0x20)) {
        p++;
    }

    /* Check for explicit H' prefix (X.693 hexadecimal string notation) */
    if((p + 1) < pend && (*p == 'H' || *p == 'h') && p[1] == '\'') {
        /* Found H' prefix - parse as hexadecimal */
        const unsigned char *content_start = p + 2;
        const unsigned char *content_end = content_start;
        ssize_t result;

        /* Find the closing quote */
        while(content_end < pend && *content_end != '\'') {
            content_end++;
        }

        /* Validate that we found the closing quote */
        if(content_end >= pend || *content_end != '\'') {
            /* Unterminated string - return error */
            return -1;
        }

        size_t content_size = content_end - content_start;

        /* Content between quotes is complete, so pass have_more=0 */
        result = OCTET_STRING__convert_hexadecimal(sptr, content_start, content_size, 0);
        if(result < 0) return result;

        /* Return total consumed from original buffer including prefix and closing quote */
        size_t total_consumed = (content_end - buf_start) + 1;  /* +1 for closing quote */
        return total_consumed;
    }

    /* No explicit prefix - auto-detect based on content */
    int is_hex = OCTET_STRING__is_hexadecimal(chunk_buf, chunk_size);
    if(is_hex) {
        return OCTET_STRING__convert_hexadecimal(sptr, chunk_buf, chunk_size, have_more);
    } else {
        return OCTET_STRING__convert_base64(sptr, chunk_buf, chunk_size, have_more);
    }
}

/*
 * Decode OCTET STRING from the XML element's body.
 */
static asn_dec_rval_t
OCTET_STRING__decode_xer(
    const asn_codec_ctx_t *opt_codec_ctx, const asn_TYPE_descriptor_t *td,
    void **sptr, const char *opt_mname, const void *buf_ptr, size_t size,
    int (*opt_unexpected_tag_decoder)(void *struct_ptr, const void *chunk_buf,
                                      size_t chunk_size),
    ssize_t (*body_receiver)(void *struct_ptr, const void *chunk_buf,
                             size_t chunk_size, int have_more)) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_OCTET_STRING_specs;
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;
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

    return xer_decode_general(opt_codec_ctx, ctx, *sptr, xml_tag,
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
OCTET_STRING_decode_xer_hex(const asn_codec_ctx_t *opt_codec_ctx,
                            const asn_TYPE_descriptor_t *td, void **sptr,
                            const char *opt_mname, const void *buf_ptr,
                            size_t size) {
    return OCTET_STRING__decode_xer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_hexadecimal);
}

/*
 * Decode OCTET STRING from the binary (0/1) data.
 */
asn_dec_rval_t
OCTET_STRING_decode_xer_binary(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td, void **sptr,
                               const char *opt_mname, const void *buf_ptr,
                               size_t size) {
    return OCTET_STRING__decode_xer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_binary);
}

/*
 * Decode BIT STRING with auto-detection of binary or hexadecimal format.
 * This allows XER input to use either binary (0/1) or hexadecimal format.
 */
asn_dec_rval_t
BIT_STRING_decode_xer_binary_or_hex(const asn_codec_ctx_t *opt_codec_ctx,
                                    const asn_TYPE_descriptor_t *td, void **sptr,
                                    const char *opt_mname, const void *buf_ptr,
                                    size_t size) {
    return OCTET_STRING__decode_xer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size, 0,
                                    BIT_STRING__convert_binary_or_hex);
}

/*
 * Decode OCTET STRING from the string (ASCII/UTF-8) data.
 */
asn_dec_rval_t
OCTET_STRING_decode_xer_utf8(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td, void **sptr,
                             const char *opt_mname, const void *buf_ptr,
                             size_t size) {
    return OCTET_STRING__decode_xer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size,
                                    OCTET_STRING__handle_control_chars,
                                    OCTET_STRING__convert_entrefs);
}

/*
 * Decode OCTET STRING from Base64-encoded data.
 */
asn_dec_rval_t
OCTET_STRING_decode_xer_base64(const asn_codec_ctx_t *opt_codec_ctx,
                               const asn_TYPE_descriptor_t *td, void **sptr,
                               const char *opt_mname, const void *buf_ptr,
                               size_t size) {
    return OCTET_STRING__decode_xer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_base64);
}

/*
 * Decode OCTET STRING with auto-detection of hexadecimal or Base64 format.
 * This allows XER input to use either format seamlessly.
 */
asn_dec_rval_t
OCTET_STRING_decode_xer_auto(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td, void **sptr,
                             const char *opt_mname, const void *buf_ptr,
                             size_t size) {
    return OCTET_STRING__decode_xer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_auto);
}
