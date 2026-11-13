/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cbor_support.h>
#include <float.h>
#include <math.h>
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
        /* RFC 8949 section 3.3 forbids two-byte simple values below 32. */
        if(major == CBOR_MAJOR_SIMPLE && buf[1] < 32) return -1;
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

/*
 * Purpose: emit a complete one-byte CBOR simple-value encoding.
 * Source: repository compatibility API. Version: 2026-11-12.
 * Inputs: simple_val is an encoded octet (e0..f7); cb/app_key receive it.
 * Returns: 1 or -1 for invalid input/callback failure. No exceptions.
 * Author: asn1c maintainers. History: validate callback and complete encoding.
 * Example: CBOR_SV_TRUE emits f5; this API does not take logical value 21.
 */
ssize_t
cbor_encode_simple(uint8_t simple_val,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf = simple_val;
    if(!cb || simple_val < 0xe0 || simple_val > 0xf7) return -1;
    if(cb(&buf, 1, app_key) < 0) return -1;
    return 1;
}

/*
 * Purpose: convert finite binary32 bits to the exact equivalent double.
 * Source: IEEE 754 binary32 field layout. Version: 2026-11-12.
 * Inputs: bits is a binary32 bit pattern. Returns: its binary64 value.
 * Errors: none. Author: asn1c maintainers. History: added CBOR float widths.
 * Example: 0x3f800000 converts to 1.0.
 */
static double
cbor_binary32_to_double(uint32_t bits) {
    unsigned exponent = (unsigned)((bits >> 23) & 0xffu);
    uint32_t fraction = bits & 0x7fffffu;
    double value;
    int power;

    if(exponent == 0xffu) {
        if(fraction) return NAN;
        return bits >> 31 ? -INFINITY : INFINITY;
    }
    if(exponent == 0) {
        value = (double)fraction;
        power = -149;
    } else {
        value = 1.0 + (double)fraction / 8388608.0;
        power = (int)exponent - 127;
    }
    while(power > 0) { value *= 2.0; power--; }
    while(power < 0) { value *= 0.5; power++; }
    return bits >> 31 ? -value : value;
}

/*
 * Purpose: convert finite binary16 bits to the exact equivalent double.
 * Source: IEEE 754 binary16 field layout. Version: 2026-11-12.
 * Inputs: bits is a binary16 bit pattern. Returns: its binary64 value.
 * Errors: none. Author: asn1c maintainers. History: added CBOR float widths.
 * Example: 0x3c00 converts to 1.0.
 */
static double
cbor_binary16_to_double(uint16_t bits) {
    unsigned exponent = (unsigned)((bits >> 10) & 0x1fu);
    uint16_t fraction = bits & 0x03ffu;
    double value;
    int power;

    if(exponent == 0x1fu) {
        if(fraction) return NAN;
        return bits >> 15 ? -INFINITY : INFINITY;
    }
    if(exponent == 0) {
        value = (double)fraction;
        power = -24;
    } else {
        value = 1.0 + (double)fraction / 1024.0;
        power = (int)exponent - 15;
    }
    while(power > 0) { value *= 2.0; power--; }
    while(power < 0) { value *= 0.5; power++; }
    return bits >> 15 ? -value : value;
}

/*
 * Purpose: verify that host double storage is IEEE 754 binary64.
 * Source: IEEE 754 binary64 representation. Version: 2026-11-12.
 * Inputs: none. Returns: 1 when the size, model, and 1.0 bit pattern match.
 * Errors: none. Author: asn1c maintainers. History: guards bit serialization.
 * Example: IEEE binary64 stores 1.0 as 0x3ff0000000000000.
 */
static int
cbor_host_binary64_supported(void) {
#if DBL_MANT_DIG == 53 && DBL_MAX_EXP == 1024
    double one = 1.0;
    uint64_t bits;
    if(sizeof(one) != sizeof(bits)) return 0;
    memcpy(&bits, &one, sizeof(bits));
    return bits == UINT64_C(0x3ff0000000000000);
#else
    return 0;
#endif
}

/*
 * Purpose: verify that host float storage is IEEE 754 binary32.
 * Source: IEEE 754 binary32 representation. Version: 2026-11-12.
 * Inputs: none. Returns: 1 when the size, model, and 1.0 bit pattern match.
 * Errors: none. Author: asn1c maintainers. History: guards narrowing casts.
 * Example: IEEE binary32 stores 1.0 as 0x3f800000.
 */
static int
cbor_host_binary32_supported(void) {
#if FLT_RADIX == 2 && FLT_MANT_DIG == 24 && FLT_MAX_EXP == 128
    float one = 1.0f;
    uint32_t bits;
    if(sizeof(one) != sizeof(bits)) return 0;
    memcpy(&bits, &one, sizeof(bits));
    return bits == 0x3f800000u;
#else
    return 0;
#endif
}

/*
 * Purpose: identify binary32 values that are exactly representable in binary16.
 * Source: IEEE 754 binary16/binary32 field layouts. Version: 2026-11-12.
 * Inputs: bits is a binary32 bit pattern; half_out receives matching bits.
 * Returns: 1 for exact conversion, 0 otherwise. Errors: none.
 * Author: asn1c maintainers. History: added preferred-width float encoding.
 * Example: 0x3f800000 maps to binary16 0x3c00.
 */
static int
cbor_binary32_to_binary16_exact(uint32_t bits, uint16_t *half_out) {
#if FLT_RADIX == 2 && FLT_MANT_DIG == 24 && FLT_MAX_EXP == 128
    uint32_t sign = (bits >> 16) & 0x8000u;
    unsigned exponent = (unsigned)((bits >> 23) & 0xffu);
    uint32_t fraction = bits & 0x7fffffu;
    int power;

    if(exponent == 0xffu) {
        if(fraction) return 0;
        *half_out = (uint16_t)(sign | 0x7c00u);
        return 1;
    }
    if(exponent == 0) {
        if(fraction) return 0;
        *half_out = (uint16_t)sign;
        return 1;
    }

    power = (int)exponent - 127;
    if(power >= -14 && power <= 15) {
        if(fraction & 0x1fffu) return 0;
        *half_out = (uint16_t)(sign | (uint32_t)(power + 15) << 10
                               | (fraction >> 13));
        return 1;
    }
    if(power < -24 || power > -15) return 0;
    {
        unsigned shift = (unsigned)(-power - 1);
        uint32_t significand = 0x800000u | fraction;
        uint32_t mask = (1u << shift) - 1u;
        if(significand & mask) return 0;
        *half_out = (uint16_t)(sign | (significand >> shift));
        return 1;
    }
#else
    (void)bits;
    (void)half_out;
    return 0;
#endif
}

/*
 * Purpose: encode a CBOR IEEE 754 double in its explicit 64-bit form.
 * Source: RFC 8949 major type 7, additional information 27. Version: 2026-11-12.
 * Inputs: value is the value; cb/app_key consume its nine encoded bytes.
 * Returns: 9, or -1 for a null callback or callback failure. Errors: see return.
 * Author: asn1c maintainers. History: retained as a compatibility API.
 * Example: 1.0 is emitted with the 0xfb binary64 marker.
 */
ssize_t
cbor_encode_float64(double value, asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf[9];
    uint64_t bits;

    if(!cb || !cbor_host_binary64_supported()) return -1;
    buf[0] = 0xfb;
    memcpy(&bits, &value, sizeof(bits));
    buf[1] = (uint8_t)(bits >> 56);
    buf[2] = (uint8_t)(bits >> 48);
    buf[3] = (uint8_t)(bits >> 40);
    buf[4] = (uint8_t)(bits >> 32);
    buf[5] = (uint8_t)(bits >> 24);
    buf[6] = (uint8_t)(bits >> 16);
    buf[7] = (uint8_t)(bits >> 8);
    buf[8] = (uint8_t)bits;
    if(cb(buf, sizeof(buf), app_key) < 0) return -1;
    return (ssize_t)sizeof(buf);
}

/*
 * Purpose: decode an explicit CBOR binary64 value.
 * Source: RFC 8949 major type 7, additional information 27. Version: 2026-11-12.
 * Inputs: buf/size bound the wire item; value_out receives the decoded number.
 * Returns: 9 or -1. Errors: null pointers, wrong marker, or truncation fail.
 * Author: asn1c maintainers. History: retained as a compatibility API.
 * Example: a 0xfb-prefixed eight-byte payload decodes as binary64.
 */
ssize_t
cbor_decode_float64(const uint8_t *buf, size_t size, double *value_out) {
    uint64_t bits;

    if(!buf || !value_out || size < 9 || buf[0] != 0xfb
       || !cbor_host_binary64_supported()) return -1;
    bits = ((uint64_t)buf[1] << 56) | ((uint64_t)buf[2] << 48)
         | ((uint64_t)buf[3] << 40) | ((uint64_t)buf[4] << 32)
         | ((uint64_t)buf[5] << 24) | ((uint64_t)buf[6] << 16)
         | ((uint64_t)buf[7] << 8)  | (uint64_t)buf[8];
    memcpy(value_out, &bits, sizeof(bits));
    return 9;
}

/*
 * Purpose: encode a value using its shortest exact CBOR float width.
 * Source: RFC 8949 preferred serialization for floating-point values.
 * Version: 2026-11-12. Inputs: value is encoded; cb/app_key consume bytes.
 * Returns: 3, 5, or 9 bytes, or -1 on invalid callback or callback failure.
 * Errors: null callbacks and callback errors fail. Author: asn1c maintainers.
 * History: added preferred-width serialization. Example: 1.5 becomes f9 3e 00.
 */
ssize_t
cbor_encode_float(double value, asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf[9];
    size_t len;
    uint64_t bits64;
    uint32_t bits32;
    uint16_t bits16;

    if(!cb || !cbor_host_binary64_supported()) return -1;
    if(value != value) {
        buf[0] = 0xf9;
        buf[1] = 0x7e;
        buf[2] = 0x00;
        len = 3;
    } else {
        int encoded_narrow = 0;
#if FLT_RADIX == 2 && FLT_MANT_DIG == 24 && FLT_MAX_EXP == 128
        if(value == INFINITY || value == -INFINITY) {
            bits16 = signbit(value) ? 0xfc00u : 0x7c00u;
            buf[0] = 0xf9;
            buf[1] = (uint8_t)(bits16 >> 8);
            buf[2] = (uint8_t)bits16;
            len = 3;
            encoded_narrow = 1;
        } else if(cbor_host_binary32_supported()
                  && value <= FLT_MAX && value >= -FLT_MAX) {
            float single = (float)value;
            memcpy(&bits32, &single, sizeof(bits32));
            if(cbor_binary32_to_double(bits32) == value
               && (!(value == 0.0)
                   || ((bits32 >> 31) == (signbit(value) != 0)))) {
                if(cbor_binary32_to_binary16_exact(bits32, &bits16)) {
                    buf[0] = 0xf9;
                    buf[1] = (uint8_t)(bits16 >> 8);
                    buf[2] = (uint8_t)bits16;
                    len = 3;
                } else {
                    buf[0] = 0xfa;
                    buf[1] = (uint8_t)(bits32 >> 24);
                    buf[2] = (uint8_t)(bits32 >> 16);
                    buf[3] = (uint8_t)(bits32 >> 8);
                    buf[4] = (uint8_t)bits32;
                    len = 5;
                }
                encoded_narrow = 1;
            }
        }
#endif
        if(!encoded_narrow) {
            buf[0] = 0xfb;
            memcpy(&bits64, &value, sizeof(bits64));
            buf[1] = (uint8_t)(bits64 >> 56);
            buf[2] = (uint8_t)(bits64 >> 48);
            buf[3] = (uint8_t)(bits64 >> 40);
            buf[4] = (uint8_t)(bits64 >> 32);
            buf[5] = (uint8_t)(bits64 >> 24);
            buf[6] = (uint8_t)(bits64 >> 16);
            buf[7] = (uint8_t)(bits64 >> 8);
            buf[8] = (uint8_t)bits64;
            len = 9;
        }
    }
    if(cb(buf, len, app_key) < 0) return -1;
    return (ssize_t)len;
}

/*
 * Purpose: decode one CBOR IEEE 754 value of any supported width.
 * Source: RFC 8949 major type 7 float16/float32/float64 forms.
 * Version: 2026-11-12. Inputs: buf/size bound the item; value_out receives it.
 * Returns: 3, 5, or 9 bytes, or -1 on invalid pointers, marker, or truncation.
 * Errors: malformed and incomplete float items fail. Author: asn1c maintainers.
 * History: added binary16 and binary32 decoding. Example: f9 3e 00 is 1.5.
 */
ssize_t
cbor_decode_float(const uint8_t *buf, size_t size, double *value_out) {
    if(!buf || !value_out || size == 0 || !cbor_host_binary64_supported())
        return -1;
    if(buf[0] == 0xf9) {
        uint16_t bits;
        if(size < 3) return -1;
        bits = (uint16_t)(((uint16_t)buf[1] << 8) | buf[2]);
        *value_out = cbor_binary16_to_double(bits);
        return 3;
    }
    if(buf[0] == 0xfa) {
        uint32_t bits;
        if(size < 5) return -1;
        bits = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16)
             | ((uint32_t)buf[3] << 8) | (uint32_t)buf[4];
        *value_out = cbor_binary32_to_double(bits);
        return 5;
    }
    return cbor_decode_float64(buf, size, value_out);
}

/* Internal recursive scanner; the explicit depth bound also applies under ASan. */
static ssize_t cbor_skip_bounded(const asn_codec_ctx_t *, const uint8_t *, size_t, unsigned);

/*
 * Purpose: scan the contents of an indefinite string, array, or map.
 * Source: RFC 8949 section 3.2. Version: 2026-11-12.
 * Inputs: ctx limits stack; buf/size bound input; major selects container;
 * depth counts enclosing containers. Returns: bytes through break, or -1.
 * Errors: wrong chunks, odd maps, missing breaks, and invalid children fail.
 * Author: asn1c maintainers. History: added extension-value interoperability.
 * Example: 9f 01 ff consumes three bytes.
 */
static ssize_t
cbor_skip_indefinite(const asn_codec_ctx_t *ctx, const uint8_t *buf,
                     size_t size, uint8_t major, unsigned depth) {
    size_t total = 1;
    int pending_value = 0; /* state variable: an indefinite map needs its value. */

    if(major < CBOR_MAJOR_BYTES || major > CBOR_MAJOR_MAP) return -1;
    while(total < size) {
        ssize_t used;
        if(buf[total] == 0xff) {
            if(pending_value) return -1;
            return (ssize_t)(total + 1);
        }
        /* String chunks must be definite, untagged, and of the same type. */
        if(major == CBOR_MAJOR_BYTES || major == CBOR_MAJOR_TEXT) {
            if((buf[total] >> 5) != major || (buf[total] & 31) == 31) return -1;
        }
        used = cbor_skip_bounded(ctx, buf + total, size - total, depth + 1);
        if(used <= 0 || (size_t)used > size - total) return -1;
        total += (size_t)used;
        if(major == CBOR_MAJOR_MAP) pending_value = !pending_value;
    }
    return -1;
}

/*
 * Purpose: validate and skip one CBOR item without allocating input-sized storage.
 * Source: RFC 8949 sections 3.1-3.3. Version: 2026-11-12.
 * Inputs: ctx bounds stack; buf/size bound input; depth counts ancestors.
 * Returns: consumed bytes or -1 on malformed/truncated input or resource limit.
 * Author: asn1c maintainers. History: added indefinite forms and hard depth cap.
 * Example: 82 00 f5 skips a two-element array in three bytes.
 */
static ssize_t
cbor_skip_bounded(const asn_codec_ctx_t *ctx, const uint8_t *buf,
                  size_t size, unsigned depth) {
    uint8_t major;
    uint64_t arg, count, i;
    ssize_t hlen;
    size_t total;

    if(!buf || !size || size > (size_t)SSIZE_MAX || depth > 128) return -1;
    if(ASN__STACK_OVERFLOW_CHECK(ctx)) return -1;
    major = buf[0] >> 5;
    if((buf[0] & 31) == 31)
        return cbor_skip_indefinite(ctx, buf, size, major, depth);
    hlen = cbor_decode_head(buf, size, &major, &arg);
    if(hlen < 0) return -1;
    total = (size_t)hlen;

    /* Definite strings carry bytes, with UTF-8 validity checked per chunk. */
    if(major == CBOR_MAJOR_BYTES || major == CBOR_MAJOR_TEXT) {
        if(arg > size - total) return -1;
        if(major == CBOR_MAJOR_TEXT && !cbor_utf8_valid(buf + total, (size_t)arg)) return -1;
        return (ssize_t)(total + (size_t)arg);
    }
    if(major != CBOR_MAJOR_ARRAY && major != CBOR_MAJOR_MAP && major != CBOR_MAJOR_TAG)
        return hlen;

    /* Every child consumes at least one byte; bound loops before traversal. */
    count = (major == CBOR_MAJOR_TAG) ? 1 : arg;
    if(major == CBOR_MAJOR_MAP) {
        if(count > (size - total) / 2) return -1;
        count *= 2;
    }
    if(count > size - total) return -1;
    for(i = 0; i < count; i++) {
        ssize_t used = cbor_skip_bounded(ctx, buf + total, size - total, depth + 1);
        if(used <= 0 || (size_t)used > size - total) return -1;
        total += (size_t)used;
    }
    return (ssize_t)total;
}

/*
 * Purpose: skip one CBOR item with both caller stack and hard nesting limits.
 * Source: repository extension scanner. Version: 2026-11-12.
 * Inputs: opt_codec_ctx optionally bounds stack; buf/size bound the item.
 * Returns: consumed prefix bytes or -1; no allocation or exceptions.
 * Author: asn1c maintainers. History: unconditional 128-level nesting bound.
 * Example: cbor_skip_item_with_ctx(NULL, bytes, length).
 */
ssize_t
cbor_skip_item_with_ctx(const asn_codec_ctx_t *opt_codec_ctx,
                        const uint8_t *buf, size_t size) {
    return cbor_skip_bounded(opt_codec_ctx, buf, size, 0);
}

/*
 * Purpose: skip a raw item when no ASN.1 decoder context is available.
 * Source: repository CBOR API. Version: 2026-11-12.
 * Inputs: buf/size bound input. Returns: consumed bytes or -1 on invalid input.
 * Errors: malformed input or nesting above 128. Author: asn1c maintainers.
 * History: bounded compatibility wrapper. Example: 00 consumes one byte.
 */
ssize_t
cbor_skip_item(const uint8_t *buf, size_t size) {
    return cbor_skip_item_with_ctx(NULL, buf, size);
}
