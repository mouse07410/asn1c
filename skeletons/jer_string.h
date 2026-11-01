/* JSON string character output shared by BMPString and UniversalString. */
#ifndef ASN_JER_STRING_H
#define ASN_JER_STRING_H

#include <asn_internal.h>

/*
 * Purpose: encode one Unicode scalar as a JSON string fragment.
 * Source: JSON string escaping rules and UTF-8 scalar encoding.
 * Version/date: 1.0, 2026-10-31. Inputs: codepoint is a Unicode scalar;
 * cb/key receive its escaped UTF-8 representation.
 * Returns: emitted byte count, or -1 for invalid scalars/callback failure.
 * Exceptions: none. Author: asn1c maintainers.
 * History: added for BMPString and UniversalString JER output.
 * Example: quote emits the two bytes backslash-quote.
 */
static ssize_t
jer_write_escaped_codepoint(uint32_t codepoint,
                            asn_app_consume_bytes_f *cb, void *key) {
    static const char hex[] = "0123456789abcdef";
    char bytes[6];
    size_t length;
    if(!cb || codepoint > 0x10ffff
    || (codepoint >= 0xd800 && codepoint <= 0xdfff)) return -1;
    if(codepoint < 0x20) {
        switch(codepoint) {
        case '\b': bytes[0] = '\\'; bytes[1] = 'b'; length = 2; break;
        case '\t': bytes[0] = '\\'; bytes[1] = 't'; length = 2; break;
        case '\n': bytes[0] = '\\'; bytes[1] = 'n'; length = 2; break;
        case '\f': bytes[0] = '\\'; bytes[1] = 'f'; length = 2; break;
        case '\r': bytes[0] = '\\'; bytes[1] = 'r'; length = 2; break;
        default:
            bytes[0] = '\\'; bytes[1] = 'u'; bytes[2] = '0'; bytes[3] = '0';
            bytes[4] = hex[(codepoint >> 4) & 0xf];
            bytes[5] = hex[codepoint & 0xf];
            length = 6;
            break;
        }
    } else if(codepoint == '"' || codepoint == '\\') {
        bytes[0] = '\\'; bytes[1] = (char)codepoint; length = 2;
    } else if(codepoint < 0x80) {
        bytes[0] = (char)codepoint; length = 1;
    } else if(codepoint < 0x800) {
        bytes[0] = (char)(0xc0 | (codepoint >> 6));
        bytes[1] = (char)(0x80 | (codepoint & 0x3f));
        length = 2;
    } else if(codepoint < 0x10000) {
        bytes[0] = (char)(0xe0 | (codepoint >> 12));
        bytes[1] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
        bytes[2] = (char)(0x80 | (codepoint & 0x3f));
        length = 3;
    } else {
        bytes[0] = (char)(0xf0 | (codepoint >> 18));
        bytes[1] = (char)(0x80 | ((codepoint >> 12) & 0x3f));
        bytes[2] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
        bytes[3] = (char)(0x80 | (codepoint & 0x3f));
        length = 4;
    }
    return cb(bytes, length, key) < 0 ? -1 : (ssize_t)length;
}

#endif /* ASN_JER_STRING_H */
