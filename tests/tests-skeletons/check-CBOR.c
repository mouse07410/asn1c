/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 *
 * Tests for CBOR (Concise Binary Object Representation) encoder and decoder.
 * RFC 7049 (original) / RFC 8949 (STD 94, update).
 */
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <asn_application.h>
#include <cbor_support.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <BOOLEAN.h>
#include <NULL.h>
#include <INTEGER.h>
#include <NativeInteger.h>
#include <NativeReal.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <ENUMERATED.h>

static uint8_t enc_buf[1024];
static size_t enc_len;

static int
fill_buffer(const void *data, size_t size, void *app_key) {
    size_t *offset = (size_t *)app_key;
    assert(*offset + size <= sizeof(enc_buf));
    memcpy(&enc_buf[*offset], data, size);
    *offset += size;
    return 0;
}

static void
check_hex(int lineno, const uint8_t *got, size_t got_len,
          const uint8_t *exp, size_t exp_len) {
    if(got_len != exp_len || memcmp(got, exp, got_len) != 0) {
        size_t i;
        fprintf(stderr, "Line %d: CBOR mismatch\n  got: ", lineno);
        for(i = 0; i < got_len; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n  exp: ");
        for(i = 0; i < exp_len; i++) fprintf(stderr, "%02x", exp[i]);
        fprintf(stderr, "\n");
        assert(0);
    }
}

/*
 * Test CBOR header encoding (cbor_support.c).
 */
static void
test_cbor_header_encoding(void) {
    uint8_t buf[9];
    size_t len;

    fprintf(stderr, "Testing CBOR header encoding...\n");

    /* Unsigned integer: 0 */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 0, buf);
    assert(len == 1 && buf[0] == 0x00);

    /* Unsigned integer: 23 */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 23, buf);
    assert(len == 1 && buf[0] == 0x17);

    /* Unsigned integer: 24 (1-byte extended) */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 24, buf);
    assert(len == 2 && buf[0] == 0x18 && buf[1] == 0x18);

    /* Unsigned integer: 255 */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 255, buf);
    assert(len == 2 && buf[0] == 0x18 && buf[1] == 0xff);

    /* Unsigned integer: 256 (2-byte extended) */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 256, buf);
    assert(len == 3 && buf[0] == 0x19 && buf[1] == 0x01 && buf[2] == 0x00);

    /* Unsigned integer: 65535 */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 65535, buf);
    assert(len == 3 && buf[0] == 0x19 && buf[1] == 0xff && buf[2] == 0xff);

    /* Unsigned integer: 65536 (4-byte extended) */
    len = cbor_encode_uint_header(CBOR_MAJOR_UNSIGNED, 65536, buf);
    assert(len == 5 && buf[0] == 0x1a);

    /* Byte string header: length 5 */
    len = cbor_encode_uint_header(CBOR_MAJOR_BYTES, 5, buf);
    assert(len == 1 && buf[0] == 0x45);

    /* Text string header: length 3 */
    len = cbor_encode_uint_header(CBOR_MAJOR_TEXT, 3, buf);
    assert(len == 1 && buf[0] == 0x63);

    fprintf(stderr, "  ✓ CBOR header encoding tests passed\n");
}

/*
 * Test CBOR header decoding (cbor_support.c).
 */
static void
test_cbor_header_decoding(void) {
    uint8_t major;
    uint64_t value;
    ssize_t consumed;

    fprintf(stderr, "Testing CBOR header decoding...\n");

    /* Positive integer: 0x17 = unsigned 23 */
    {
        uint8_t buf[] = {0x17};
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 1 && major == CBOR_MAJOR_UNSIGNED && value == 23);
    }

    /* Positive integer: 0x18 0x18 = unsigned 24 */
    {
        uint8_t buf[] = {0x18, 0x18};
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 2 && major == CBOR_MAJOR_UNSIGNED && value == 24);
    }

    /* Byte string: 0x44 = 4-byte byte string header */
    {
        uint8_t buf[] = {0x44};
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 1 && major == CBOR_MAJOR_BYTES && value == 4);
    }

    /* Simple value: 0xf4 = false */
    {
        uint8_t buf[] = {0xf4};
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 1 && major == CBOR_MAJOR_SIMPLE && value == 20);
    }

    /* Simple value: 0xf5 = true */
    {
        uint8_t buf[] = {0xf5};
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 1 && major == CBOR_MAJOR_SIMPLE && value == 21);
    }

    /* Simple value: 0xf6 = null */
    {
        uint8_t buf[] = {0xf6};
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 1 && major == CBOR_MAJOR_SIMPLE && value == 22);
    }

    /* Need more data */
    {
        uint8_t buf[] = {0x18};  /* Should have 1 more byte */
        consumed = cbor_read_uint_header(buf, sizeof(buf), &major, &value);
        assert(consumed == 0);
    }

    fprintf(stderr, "  ✓ CBOR header decoding tests passed\n");
}

/*
 * Test BOOLEAN CBOR encoding/decoding.
 */
static void
test_boolean_cbor(void) {
    BOOLEAN_t val_true = 0xFF;
    BOOLEAN_t val_false = 0x00;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    BOOLEAN_t *decoded = NULL;

    fprintf(stderr, "Testing BOOLEAN CBOR...\n");

    /* Encode TRUE */
    enc_len = 0;
    er = BOOLEAN_encode_cbor(&asn_DEF_BOOLEAN, NULL, &val_true,
                              fill_buffer, &enc_len);
    assert(er.encoded == 1);
    {
        uint8_t expected[] = {0xf5};  /* CBOR true */
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    /* Decode TRUE */
    decoded = NULL;
    dr = BOOLEAN_decode_cbor(NULL, &asn_DEF_BOOLEAN, NULL,
                              (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL && *decoded != 0);
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, decoded);

    /* Encode FALSE */
    enc_len = 0;
    er = BOOLEAN_encode_cbor(&asn_DEF_BOOLEAN, NULL, &val_false,
                              fill_buffer, &enc_len);
    assert(er.encoded == 1);
    {
        uint8_t expected[] = {0xf4};  /* CBOR false */
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    /* Decode FALSE */
    decoded = NULL;
    dr = BOOLEAN_decode_cbor(NULL, &asn_DEF_BOOLEAN, NULL,
                              (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL && *decoded == 0);
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, decoded);

    fprintf(stderr, "  ✓ BOOLEAN CBOR tests passed\n");
}

/*
 * Test NULL CBOR encoding/decoding.
 */
static void
test_null_cbor(void) {
    NULL_t null_val = 0;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    NULL_t *decoded = NULL;

    fprintf(stderr, "Testing NULL CBOR...\n");

    enc_len = 0;
    er = NULL_encode_cbor(&asn_DEF_NULL, NULL, &null_val,
                           fill_buffer, &enc_len);
    assert(er.encoded == 1);
    {
        uint8_t expected[] = {0xf6};  /* CBOR null */
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    decoded = NULL;
    dr = NULL_decode_cbor(NULL, &asn_DEF_NULL, NULL,
                           (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL);
    ASN_STRUCT_FREE(asn_DEF_NULL, decoded);

    fprintf(stderr, "  ✓ NULL CBOR tests passed\n");
}

/*
 * Test NativeInteger CBOR encoding/decoding.
 */
static void
test_native_integer_cbor(void) {
    long val;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    long *decoded;

    fprintf(stderr, "Testing NativeInteger CBOR...\n");

    /* Test encoding 0 */
    val = 0;
    enc_len = 0;
    er = NativeInteger_encode_cbor(&asn_DEF_INTEGER, NULL, &val,
                                    fill_buffer, &enc_len);
    assert(er.encoded == 1);
    {
        uint8_t expected[] = {0x00};
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    /* Test encoding 1 */
    val = 1;
    enc_len = 0;
    er = NativeInteger_encode_cbor(&asn_DEF_INTEGER, NULL, &val,
                                    fill_buffer, &enc_len);
    assert(er.encoded == 1);
    {
        uint8_t expected[] = {0x01};
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    /* Test encoding -1 */
    val = -1;
    enc_len = 0;
    er = NativeInteger_encode_cbor(&asn_DEF_INTEGER, NULL, &val,
                                    fill_buffer, &enc_len);
    assert(er.encoded == 1);
    {
        uint8_t expected[] = {0x20};  /* CBOR -1 = 0x20 */
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    /* Test encoding -100 */
    val = -100;
    enc_len = 0;
    er = NativeInteger_encode_cbor(&asn_DEF_INTEGER, NULL, &val,
                                    fill_buffer, &enc_len);
    assert(er.encoded == 2);
    {
        uint8_t expected[] = {0x38, 0x63};  /* CBOR -100 */
        check_hex(__LINE__, enc_buf, enc_len, expected, sizeof(expected));
    }

    /* Test round-trip for various values */
    long test_vals[] = {0, 1, 23, 24, 100, 255, 256, 1000, -1, -100, -1000};
    size_t i;
    for(i = 0; i < sizeof(test_vals)/sizeof(test_vals[0]); i++) {
        val = test_vals[i];
        enc_len = 0;
        er = NativeInteger_encode_cbor(&asn_DEF_INTEGER, NULL, &val,
                                        fill_buffer, &enc_len);
        assert(er.encoded > 0);

        decoded = NULL;
        dr = NativeInteger_decode_cbor(NULL, &asn_DEF_INTEGER, NULL,
                                        (void **)&decoded,
                                        enc_buf, enc_len);
        assert(dr.code == RC_OK);
        assert(decoded != NULL && *decoded == val);
        FREEMEM(decoded);
    }

    fprintf(stderr, "  ✓ NativeInteger CBOR tests passed\n");
}

/*
 * Test NativeReal CBOR encoding/decoding.
 */
static void
test_native_real_cbor(void) {
    double val;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    double *decoded;

    fprintf(stderr, "Testing NativeReal CBOR...\n");

    double test_vals[] = {0.0, 1.0, -1.0, 3.14, 1e10, -2.5, 0.1};
    size_t i;
    for(i = 0; i < sizeof(test_vals)/sizeof(test_vals[0]); i++) {
        val = test_vals[i];
        enc_len = 0;
        er = NativeReal_encode_cbor(&asn_DEF_NativeReal, NULL, &val,
                                     fill_buffer, &enc_len);
        assert(er.encoded == 9);  /* Always double (9 bytes) */
        assert(enc_buf[0] == 0xfb);  /* CBOR float64 */

        decoded = NULL;
        dr = NativeReal_decode_cbor(NULL, &asn_DEF_NativeReal, NULL,
                                     (void **)&decoded, enc_buf, enc_len);
        assert(dr.code == RC_OK);
        assert(decoded != NULL && *decoded == val);
        FREEMEM(decoded);
    }

    fprintf(stderr, "  ✓ NativeReal CBOR tests passed\n");
}

/*
 * Test OCTET STRING CBOR encoding/decoding.
 */
static void
test_octet_string_cbor(void) {
    OCTET_STRING_t st;
    OCTET_STRING_t *decoded;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};

    fprintf(stderr, "Testing OCTET STRING CBOR...\n");

    /* Encode */
    st.buf = data;
    st.size = sizeof(data);
    enc_len = 0;
    er = OCTET_STRING_encode_cbor(&asn_DEF_OCTET_STRING, NULL, &st,
                                   fill_buffer, &enc_len);
    assert(er.encoded == 5);  /* 1 header + 4 bytes */
    assert(enc_buf[0] == 0x44);  /* Byte string, length 4 */
    assert(memcmp(enc_buf + 1, data, 4) == 0);

    /* Decode */
    decoded = NULL;
    dr = OCTET_STRING_decode_cbor(NULL, &asn_DEF_OCTET_STRING, NULL,
                                   (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL);
    assert(decoded->size == 4);
    assert(memcmp(decoded->buf, data, 4) == 0);
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);

    /* Test empty OCTET STRING */
    st.buf = NULL;
    st.size = 0;
    enc_len = 0;
    er = OCTET_STRING_encode_cbor(&asn_DEF_OCTET_STRING, NULL, &st,
                                   fill_buffer, &enc_len);
    assert(er.encoded == 1);
    assert(enc_buf[0] == 0x40);  /* Empty byte string */

    decoded = NULL;
    dr = OCTET_STRING_decode_cbor(NULL, &asn_DEF_OCTET_STRING, NULL,
                                   (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL && decoded->size == 0);
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);

    /* Test text string encoding (UTF-8) */
    uint8_t text[] = "Hello";
    st.buf = text;
    st.size = 5;
    enc_len = 0;
    er = OCTET_STRING_encode_cbor_utf8(&asn_DEF_OCTET_STRING, NULL, &st,
                                        fill_buffer, &enc_len);
    assert(er.encoded == 6);  /* 1 header + 5 bytes */
    assert(enc_buf[0] == 0x65);  /* Text string, length 5 */
    assert(memcmp(enc_buf + 1, "Hello", 5) == 0);

    /* Decode text string */
    decoded = NULL;
    dr = OCTET_STRING_decode_cbor_utf8(NULL, &asn_DEF_OCTET_STRING, NULL,
                                        (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL && decoded->size == 5);
    assert(memcmp(decoded->buf, "Hello", 5) == 0);
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);

    fprintf(stderr, "  ✓ OCTET STRING CBOR tests passed\n");
}

/*
 * Test BIT STRING CBOR encoding/decoding.
 */
static void
test_bit_string_cbor(void) {
    BIT_STRING_t st;
    BIT_STRING_t *decoded;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    uint8_t data[] = {0xAB, 0xC0};

    fprintf(stderr, "Testing BIT STRING CBOR...\n");

    /* BIT STRING: 0xAB 0xC0 with 4 unused bits */
    st.buf = data;
    st.size = 2;
    st.bits_unused = 4;

    enc_len = 0;
    er = BIT_STRING_encode_cbor(&asn_DEF_BIT_STRING, NULL, &st,
                                 fill_buffer, &enc_len);
    /* Should be: 0x43 (byte string, len 3) 0x04 (unused bits) 0xAB 0xC0 */
    assert(er.encoded == 4);
    assert(enc_buf[0] == 0x43);  /* Byte string header, length 3 */
    assert(enc_buf[1] == 0x04);  /* 4 unused bits */
    assert(enc_buf[2] == 0xAB);
    assert(enc_buf[3] == 0xC0);

    /* Decode */
    decoded = NULL;
    dr = BIT_STRING_decode_cbor(NULL, &asn_DEF_BIT_STRING, NULL,
                                 (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL);
    assert(decoded->size == 2);
    assert(decoded->bits_unused == 4);
    assert(memcmp(decoded->buf, data, 2) == 0);
    ASN_STRUCT_FREE(asn_DEF_BIT_STRING, decoded);

    fprintf(stderr, "  ✓ BIT STRING CBOR tests passed\n");
}

/*
 * Test via asn_encode / asn_decode API.
 */
static void
test_via_asn_api(void) {
    BOOLEAN_t val = 0xFF;
    BOOLEAN_t *decoded = NULL;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;

    fprintf(stderr, "Testing via asn_encode/asn_decode API...\n");

    /* Encode via asn_encode */
    enc_len = 0;
    er = asn_encode(NULL, ATS_CBOR, &asn_DEF_BOOLEAN, &val,
                    fill_buffer, &enc_len);
    assert(er.encoded == 1);
    assert(enc_buf[0] == 0xf5);

    /* Decode via asn_decode */
    dr = asn_decode(NULL, ATS_CBOR, &asn_DEF_BOOLEAN,
                    (void **)&decoded, enc_buf, enc_len);
    assert(dr.code == RC_OK);
    assert(decoded != NULL && *decoded != 0);
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, decoded);

    fprintf(stderr, "  ✓ asn_encode/asn_decode API tests passed\n");
}

/*
 * RFC 8949 Appendix A - CBOR test vectors (selected).
 */
static void
test_rfc8949_vectors(void) {
    fprintf(stderr, "Testing RFC 8949 test vectors...\n");

    uint8_t major;
    uint64_t value;
    ssize_t consumed;

    /* 0x00 -> uint 0 */
    {
        uint8_t buf[] = {0x00};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 0 && value == 0);
    }

    /* 0x01 -> uint 1 */
    {
        uint8_t buf[] = {0x01};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 0 && value == 1);
    }

    /* 0x0a -> uint 10 */
    {
        uint8_t buf[] = {0x0a};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 0 && value == 10);
    }

    /* 0x17 -> uint 23 */
    {
        uint8_t buf[] = {0x17};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 0 && value == 23);
    }

    /* 0x18 0x18 -> uint 24 */
    {
        uint8_t buf[] = {0x18, 0x18};
        consumed = cbor_read_uint_header(buf, 2, &major, &value);
        assert(consumed == 2 && major == 0 && value == 24);
    }

    /* 0x18 0x64 -> uint 100 */
    {
        uint8_t buf[] = {0x18, 0x64};
        consumed = cbor_read_uint_header(buf, 2, &major, &value);
        assert(consumed == 2 && major == 0 && value == 100);
    }

    /* 0x19 0x03 0xe8 -> uint 1000 */
    {
        uint8_t buf[] = {0x19, 0x03, 0xe8};
        consumed = cbor_read_uint_header(buf, 3, &major, &value);
        assert(consumed == 3 && major == 0 && value == 1000);
    }

    /* 0x20 -> nint -1 */
    {
        uint8_t buf[] = {0x20};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 1 && value == 0);
    }

    /* 0x29 -> nint -10 */
    {
        uint8_t buf[] = {0x29};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 1 && value == 9);
    }

    /* 0xf4 -> false */
    {
        uint8_t buf[] = {0xf4};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 7 && value == 20);
    }

    /* 0xf5 -> true */
    {
        uint8_t buf[] = {0xf5};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 7 && value == 21);
    }

    /* 0xf6 -> null */
    {
        uint8_t buf[] = {0xf6};
        consumed = cbor_read_uint_header(buf, 1, &major, &value);
        assert(consumed == 1 && major == 7 && value == 22);
    }

    fprintf(stderr, "  ✓ RFC 8949 test vector tests passed\n");
}

int
main(void) {
    fprintf(stderr, "=== CBOR Codec Tests ===\n\n");

    test_cbor_header_encoding();
    test_cbor_header_decoding();
    test_boolean_cbor();
    test_null_cbor();
    test_native_integer_cbor();
    test_native_real_cbor();
    test_octet_string_cbor();
    test_bit_string_cbor();
    test_via_asn_api();
    test_rfc8949_vectors();

    fprintf(stderr, "\n=== All CBOR tests passed ===\n");
    return 0;
}
