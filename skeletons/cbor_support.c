/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * CBOR (Concise Binary Object Representation) support functions.
 * RFC 7049 (original), RFC 8949 (STD 94, update).
 */
#include <asn_internal.h>
#include <cbor_support.h>
#include <string.h>

/*
 * Encode a CBOR unsigned integer header into a pre-allocated buffer.
 * Returns the number of bytes written.
 */
size_t
cbor_encode_uint_header(uint8_t major, uint64_t value, uint8_t *buf) {
    uint8_t major_byte = (uint8_t)(major << 5);

    if(value <= 23) {
        buf[0] = major_byte | (uint8_t)value;
        return 1;
    } else if(value <= 0xFFu) {
        buf[0] = major_byte | 24;
        buf[1] = (uint8_t)value;
        return 2;
    } else if(value <= 0xFFFFu) {
        buf[0] = major_byte | 25;
        buf[1] = (uint8_t)(value >> 8);
        buf[2] = (uint8_t)(value);
        return 3;
    } else if(value <= 0xFFFFFFFFu) {
        buf[0] = major_byte | 26;
        buf[1] = (uint8_t)(value >> 24);
        buf[2] = (uint8_t)(value >> 16);
        buf[3] = (uint8_t)(value >> 8);
        buf[4] = (uint8_t)(value);
        return 5;
    } else {
        buf[0] = major_byte | 27;
        buf[1] = (uint8_t)(value >> 56);
        buf[2] = (uint8_t)(value >> 48);
        buf[3] = (uint8_t)(value >> 40);
        buf[4] = (uint8_t)(value >> 32);
        buf[5] = (uint8_t)(value >> 24);
        buf[6] = (uint8_t)(value >> 16);
        buf[7] = (uint8_t)(value >> 8);
        buf[8] = (uint8_t)(value);
        return 9;
    }
}

/*
 * Write a CBOR unsigned integer header via callback.
 */
ssize_t
cbor_write_uint_header(uint8_t major, uint64_t value,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf[9];
    size_t len = cbor_encode_uint_header(major, value, buf);
    if(cb(buf, len, app_key) < 0) return -1;
    return (ssize_t)len;
}

/*
 * Read a CBOR initial byte and decode the argument value.
 * Returns number of bytes consumed, 0 if need more, -1 if invalid.
 */
ssize_t
cbor_read_uint_header(const uint8_t *buf, size_t size,
                       uint8_t *major_out, uint64_t *value_out) {
    uint8_t initial_byte;
    uint8_t major;
    uint8_t additional;

    if(size < 1) return 0;

    initial_byte = buf[0];
    major = initial_byte >> 5;
    additional = initial_byte & 0x1f;

    *major_out = major;

    if(additional <= 23) {
        *value_out = additional;
        return 1;
    } else if(additional == 24) {
        if(size < 2) return 0;
        *value_out = buf[1];
        return 2;
    } else if(additional == 25) {
        if(size < 3) return 0;
        *value_out = ((uint64_t)buf[1] << 8) | buf[2];
        return 3;
    } else if(additional == 26) {
        if(size < 5) return 0;
        *value_out = ((uint64_t)buf[1] << 24) | ((uint64_t)buf[2] << 16)
                   | ((uint64_t)buf[3] << 8) | buf[4];
        return 5;
    } else if(additional == 27) {
        if(size < 9) return 0;
        *value_out = ((uint64_t)buf[1] << 56) | ((uint64_t)buf[2] << 48)
                   | ((uint64_t)buf[3] << 40) | ((uint64_t)buf[4] << 32)
                   | ((uint64_t)buf[5] << 24) | ((uint64_t)buf[6] << 16)
                   | ((uint64_t)buf[7] << 8) | buf[8];
        return 9;
    } else if(additional == 31) {
        /* Indefinite length; treat as valid for major types that support it */
        *value_out = (uint64_t)-1;
        return 1;
    } else {
        /* 28-30: reserved, invalid */
        return -1;
    }
}

ssize_t
cbor_write_text_header(size_t length, asn_app_consume_bytes_f *cb,
                       void *app_key) {
    return cbor_write_uint_header(CBOR_MAJOR_TEXT, (uint64_t)length, cb,
                                   app_key);
}

ssize_t
cbor_write_bytes_header(size_t length, asn_app_consume_bytes_f *cb,
                        void *app_key) {
    return cbor_write_uint_header(CBOR_MAJOR_BYTES, (uint64_t)length, cb,
                                   app_key);
}

ssize_t
cbor_write_array_header(size_t count, asn_app_consume_bytes_f *cb,
                        void *app_key) {
    return cbor_write_uint_header(CBOR_MAJOR_ARRAY, (uint64_t)count, cb,
                                   app_key);
}

ssize_t
cbor_write_map_header(size_t count, asn_app_consume_bytes_f *cb,
                      void *app_key) {
    return cbor_write_uint_header(CBOR_MAJOR_MAP, (uint64_t)count, cb,
                                   app_key);
}

ssize_t
cbor_write_simple(uint8_t simple_value, asn_app_consume_bytes_f *cb,
                  void *app_key) {
    uint8_t buf[2];
    size_t len;

    if(simple_value <= 23) {
        buf[0] = (uint8_t)((CBOR_MAJOR_SIMPLE << 5) | simple_value);
        len = 1;
    } else {
        /* simple_value 24-255: use 1-byte extended form */
        buf[0] = (uint8_t)((CBOR_MAJOR_SIMPLE << 5) | 24);
        buf[1] = simple_value;
        len = 2;
    }

    if(cb(buf, len, app_key) < 0) return -1;
    return (ssize_t)len;
}

ssize_t
cbor_write_tag(uint64_t tag_number, asn_app_consume_bytes_f *cb,
               void *app_key) {
    return cbor_write_uint_header(CBOR_MAJOR_TAG, tag_number, cb, app_key);
}

ssize_t
cbor_write_double(double value, asn_app_consume_bytes_f *cb, void *app_key) {
    uint8_t buf[9];
    uint64_t bits;

    buf[0] = (uint8_t)((CBOR_MAJOR_SIMPLE << 5) | 27);  /* float64 */

    /* Copy double bits to uint64 in big-endian order */
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
