/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cbor_support.h>
#include <string.h>

/*
 * Purpose: encode a shortest-form CBOR item head.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: major is 0..7; argument is the head value; cb/app_key receive bytes.
 * Returns: written byte count or -1. Errors: invalid major or callback fail.
 * Author: asn1c maintainers. History: added argument validation.
 * Example: major 2, argument 1 emits 0x41.
 */
ssize_t
cbor_encode_head(uint8_t major, uint64_t argument,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf[9];
    size_t len;
    uint8_t prefix = (major & 0x07) << 5;

    if(major > 7 || !cb) return -1;

    if(argument <= 23) {
        buf[0] = prefix | (uint8_t)argument;
        len = 1;
    } else if(argument <= 0xFF) {
        buf[0] = prefix | CBOR_AI_1BYTE;
        buf[1] = (uint8_t)argument;
        len = 2;
    } else if(argument <= 0xFFFF) {
        buf[0] = prefix | CBOR_AI_2BYTE;
        buf[1] = (uint8_t)(argument >> 8);
        buf[2] = (uint8_t)(argument);
        len = 3;
    } else if(argument <= 0xFFFFFFFF) {
        buf[0] = prefix | CBOR_AI_4BYTE;
        buf[1] = (uint8_t)(argument >> 24);
        buf[2] = (uint8_t)(argument >> 16);
        buf[3] = (uint8_t)(argument >> 8);
        buf[4] = (uint8_t)(argument);
        len = 5;
    } else {
        buf[0] = prefix | CBOR_AI_8BYTE;
        buf[1] = (uint8_t)(argument >> 56);
        buf[2] = (uint8_t)(argument >> 48);
        buf[3] = (uint8_t)(argument >> 40);
        buf[4] = (uint8_t)(argument >> 32);
        buf[5] = (uint8_t)(argument >> 24);
        buf[6] = (uint8_t)(argument >> 16);
        buf[7] = (uint8_t)(argument >> 8);
        buf[8] = (uint8_t)(argument);
        len = 9;
    }

    if(cb(buf, len, app_key) < 0)
        return -1;
    return (ssize_t)len;
}

/*
 * Purpose: decode one definite CBOR item head.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: buf/size bound input; major_out/argument_out receive the result.
 * Returns: consumed header bytes or -1. Errors: invalid pointers, reserved
 * additional information, and truncation fail. Author: asn1c maintainers.
 * History: added pointer validation. Example: 0x41 means one-byte byte string.
 */
ssize_t
cbor_decode_head(const uint8_t *buf, size_t size,
                 uint8_t *major_out, uint64_t *argument_out) {
    if(!buf || !major_out || !argument_out || size < 1) return -1;

    uint8_t first = buf[0];
    uint8_t major = first >> 5;
    uint8_t info  = first & 0x1F;

    *major_out = major;

    if(info <= 23) {
        *argument_out = info;
        return 1;
    } else if(info == CBOR_AI_1BYTE) {
        if(size < 2) return -1;
        *argument_out = buf[1];
        return 2;
    } else if(info == CBOR_AI_2BYTE) {
        if(size < 3) return -1;
        *argument_out = ((uint64_t)buf[1] << 8) | buf[2];
        return 3;
    } else if(info == CBOR_AI_4BYTE) {
        if(size < 5) return -1;
        *argument_out = ((uint64_t)buf[1] << 24) | ((uint64_t)buf[2] << 16)
                      | ((uint64_t)buf[3] << 8)  | (uint64_t)buf[4];
        return 5;
    } else if(info == CBOR_AI_8BYTE) {
        if(size < 9) return -1;
        *argument_out = ((uint64_t)buf[1] << 56) | ((uint64_t)buf[2] << 48)
                      | ((uint64_t)buf[3] << 40) | ((uint64_t)buf[4] << 32)
                      | ((uint64_t)buf[5] << 24) | ((uint64_t)buf[6] << 16)
                      | ((uint64_t)buf[7] << 8)  | (uint64_t)buf[8];
        return 9;
    } else {
        /* Reserved or break code */
        return -1;
    }
}

/*
 * Purpose: validate the UTF-8 scalar-value encoding of CBOR text bytes.
 * Source: RFC 3629 UTF-8 byte ranges. Version: 2026-10-30.
 * Inputs: data/length bound the text. Returns: 1 for valid UTF-8, else 0.
 * Errors: overlong forms, surrogates, truncation, and values above U+10FFFF
 * return 0. Author: asn1c maintainers. History: added CBOR key validation.
 * Example: C2 A2 is valid, while C0 80 is not.
 */
int
cbor_utf8_valid(const uint8_t *data, size_t length) {
    size_t offset = 0;
    if(length && !data) return 0;
    while(offset < length) {
        uint8_t first = data[offset];
        uint8_t minimum = 0x80, maximum = 0xbf;
        size_t needed, follow;

        if(first <= 0x7f) {
            offset++;
            continue;
        }
        if(first >= 0xc2 && first <= 0xdf) needed = 1;
        else if(first == 0xe0) { needed = 2; minimum = 0xa0; }
        else if(first == 0xed) { needed = 2; maximum = 0x9f; }
        else if((first >= 0xe1 && first <= 0xec) || (first >= 0xee && first <= 0xef)) needed = 2;
        else if(first == 0xf0) { needed = 3; minimum = 0x90; }
        else if(first == 0xf4) { needed = 3; maximum = 0x8f; }
        else if(first >= 0xf1 && first <= 0xf3) needed = 3;
        else return 0;

        if(needed > length - offset - 1) return 0;
        if(data[offset + 1] < minimum || data[offset + 1] > maximum) return 0;
        for(follow = 2; follow <= needed; follow++) {
            if(data[offset + follow] < 0x80 || data[offset + follow] > 0xbf) return 0;
        }
        offset += needed + 1;
    }
    return 1;
}

ssize_t
cbor_encode_uint(uint64_t value, asn_app_consume_bytes_f *cb, void *app_key) {
    return cbor_encode_head(CBOR_MAJOR_UINT, value, cb, app_key);
}

ssize_t
cbor_encode_negint(uint64_t value, asn_app_consume_bytes_f *cb, void *app_key) {
    return cbor_encode_head(CBOR_MAJOR_NEGINT, value, cb, app_key);
}

/*
 * Purpose: encode an opaque byte payload as one definite CBOR byte string.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: data/len describe bytes; cb/app_key consume output.
 * Returns: encoded byte count or -1. Errors: invalid input, length overflow,
 * and callback failures. Author: asn1c maintainers.
 * History: added signed-size bounds. Example: one octet emits 0x41 then data.
 */
ssize_t
cbor_encode_bytes(const void *data, size_t len,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    if(!cb || (len && !data) || len > (size_t)SSIZE_MAX - 9) return -1;
    ssize_t hlen = cbor_encode_head(CBOR_MAJOR_BYTES, len, cb, app_key);
    if(hlen < 0) return -1;
    if(len > 0) {
        if(cb(data, len, app_key) < 0) return -1;
    }
    return hlen + (ssize_t)len;
}

/*
 * Purpose: encode a UTF-8 byte sequence as one definite CBOR text string.
 * Source: repository CBOR mapping. Version: 2026-10-30.
 * Inputs: str/len describe bytes; cb/app_key consume output.
 * Returns: encoded byte count or -1. Errors: invalid input, length overflow,
 * and callback failures. Author: asn1c maintainers.
 * History: added signed-size bounds. Example: "A" emits 0x61 0x41.
 */
ssize_t
cbor_encode_text(const char *str, size_t len,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    if(!cb || (len && !str) || len > (size_t)SSIZE_MAX - 9
       || !cbor_utf8_valid((const uint8_t *)str, len)) return -1;
    ssize_t hlen = cbor_encode_head(CBOR_MAJOR_TEXT, len, cb, app_key);
    if(hlen < 0) return -1;
    if(len > 0) {
        if(cb(str, len, app_key) < 0) return -1;
    }
    return hlen + (ssize_t)len;
}

ssize_t
cbor_encode_tag(uint64_t tag, asn_app_consume_bytes_f *cb, void *app_key) {
    return cbor_encode_head(CBOR_MAJOR_TAG, tag, cb, app_key);
}

/*
 * Skip any leading CBOR tag headers.
 * Tags (major type 6) are optional semantic annotations; they carry a tag
 * number followed by exactly one tagged data item.  This function peels off
 * every consecutive tag header so that the caller can decode the underlying
 * value without knowing which tags are present.
 *
 * Returns total bytes consumed by tags (>= 0), or -1 on truncation/error.
 */
ssize_t
cbor_skip_tags(const uint8_t *buf, size_t size) {
    size_t total = 0;

    if((size && !buf) || size > (size_t)SSIZE_MAX) return -1;

    for(;;) {
        uint8_t major;
        uint64_t arg;
        ssize_t hlen;

        if(total >= size) {
            /*
             * End of input while still expecting the tagged item.
             * If we consumed at least one tag header, the stream is
             * truncated (a tag without a following data item is invalid).
             * If no tags were seen yet, the caller may have passed an
             * empty slice – return 0 so the caller's own size check fires.
             */
            return (total > 0) ? -1 : 0;
        }

        hlen = cbor_decode_head(buf + total, size - total, &major, &arg);
        if(hlen < 0)
            return -1;

        if(major != CBOR_MAJOR_TAG)
            return (ssize_t)total;  /* non-tag item – stop here */

        total += (size_t)hlen;
    }
}

ssize_t
cbor_encode_simple(uint8_t simple_val,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    /* Simple values 0..19 and 32..255: encode as single byte with major 7 */
    uint8_t buf = simple_val;
    if(cb(&buf, 1, app_key) < 0) return -1;
    return 1;
}

ssize_t
cbor_encode_float64(double value, asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf[9];
    uint64_t bits;

    buf[0] = (CBOR_MAJOR_SIMPLE << 5) | CBOR_AI_8BYTE;  /* 0xFB */
    memcpy(&bits, &value, 8);
    buf[1] = (uint8_t)(bits >> 56);
    buf[2] = (uint8_t)(bits >> 48);
    buf[3] = (uint8_t)(bits >> 40);
    buf[4] = (uint8_t)(bits >> 32);
    buf[5] = (uint8_t)(bits >> 24);
    buf[6] = (uint8_t)(bits >> 16);
    buf[7] = (uint8_t)(bits >> 8);
    buf[8] = (uint8_t)(bits);

    if(cb(buf, 9, app_key) < 0) return -1;
    return 9;
}

ssize_t
cbor_decode_float64(const uint8_t *buf, size_t size, double *value_out) {
    uint64_t bits;

    if(size < 9) return -1;
    if(buf[0] != 0xFB) return -1;  /* Must be 0xFB for float64 */

    bits = ((uint64_t)buf[1] << 56) | ((uint64_t)buf[2] << 48)
         | ((uint64_t)buf[3] << 40) | ((uint64_t)buf[4] << 32)
         | ((uint64_t)buf[5] << 24) | ((uint64_t)buf[6] << 16)
         | ((uint64_t)buf[7] << 8)  | (uint64_t)buf[8];
    memcpy(value_out, &bits, 8);
    return 9;
}

/*
 * Purpose: skip one complete CBOR item, including nested arrays and maps.
 * Source: repository CBOR extension handling. Version: 2026-10-30.
 * Inputs: opt_codec_ctx bounds recursion; buf/size bound the input.
 * Returns: consumed bytes or -1. Errors: malformed or truncated items,
 * oversized input, and arithmetic overflow fail. Author: asn1c maintainers.
 * History: replaced signed accumulation with bounded size arithmetic.
 * Example: a two-item array skips its head and both nested items.
 */
ssize_t
cbor_skip_item_with_ctx(const asn_codec_ctx_t *opt_codec_ctx,
                        const uint8_t *buf, size_t size) {
    uint8_t major;
    uint64_t arg;
    ssize_t hlen;
    size_t total;
    uint64_t i;

    if(!buf || size < 1 || size > (size_t)SSIZE_MAX) return -1;
    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx)) return -1;

    hlen = cbor_decode_head(buf, size, &major, &arg);
    if(hlen < 0) return -1;
    total = (size_t)hlen;

    switch(major) {
    case CBOR_MAJOR_UINT:    /* 0: unsigned integer — header only */
    case CBOR_MAJOR_NEGINT:  /* 1: negative integer — header only */
        break;

    case CBOR_MAJOR_BYTES:   /* 2: byte string — arg bytes follow */
    case CBOR_MAJOR_TEXT:    /* 3: text string — arg bytes follow */
        if(arg > size - total) return -1;
        if(major == CBOR_MAJOR_TEXT && !cbor_utf8_valid(buf + total, (size_t)arg)) return -1;
        total += (size_t)arg;
        break;

    case CBOR_MAJOR_ARRAY:   /* 4: array of arg items */
        for(i = 0; i < arg; i++) {
            ssize_t n;
            if(total >= size) return -1;
            n = cbor_skip_item_with_ctx(opt_codec_ctx, buf + total,
                                        size - total);
            if(n <= 0 || (size_t)n > size - total) return -1;
            total += (size_t)n;
        }
        break;

    case CBOR_MAJOR_MAP:     /* 5: map of arg key/value pairs */
        for(i = 0; i < arg; i++) {
            ssize_t n;
            /* key */
            if(total >= size) return -1;
            n = cbor_skip_item_with_ctx(opt_codec_ctx, buf + total,
                                        size - total);
            if(n <= 0 || (size_t)n > size - total) return -1;
            total += (size_t)n;
            /* value */
            if(total >= size) return -1;
            n = cbor_skip_item_with_ctx(opt_codec_ctx, buf + total,
                                        size - total);
            if(n <= 0 || (size_t)n > size - total) return -1;
            total += (size_t)n;
        }
        break;

    case CBOR_MAJOR_TAG:     /* 6: tag number + one tagged item */
        {
            ssize_t n;
            if(total >= size) return -1;
            n = cbor_skip_item_with_ctx(opt_codec_ctx, buf + total,
                                        size - total);
            if(n <= 0 || (size_t)n > size - total) return -1;
            total += (size_t)n;
        }
        break;

    case CBOR_MAJOR_SIMPLE:  /* 7: floats/simple — header already includes all bytes */
        /*
         * cbor_decode_head consumed the AI=24/25/26/27 argument bytes
         * (which encode the float16/32/64 payload) as part of the header,
         * so there are no additional bytes to skip here.
         */
        break;

    default:
        return -1;
    }

    return (ssize_t)total;
}

ssize_t
cbor_skip_item(const uint8_t *buf, size_t size) {
    return cbor_skip_item_with_ctx(NULL, buf, size);
}
