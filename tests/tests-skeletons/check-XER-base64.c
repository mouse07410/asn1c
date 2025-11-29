/*
 * Comprehensive tests for XER Base64 encoding/decoding of OCTET STRING
 */
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <OCTET_STRING.h>

/*
 * Test helper: encode OCTET_STRING to Base64 XER
 */
static char encode_buffer[4096];

static int
collect_bytes(const void *buffer, size_t size, void *app_key) {
    size_t *offset = app_key;
    assert(*offset + size < sizeof(encode_buffer));
    memcpy(encode_buffer + *offset, buffer, size);
    *offset += size;
    return 0;
}

static void
test_encode_decode(const char *test_name, const uint8_t *data, size_t data_len, 
                   const char *expected_base64) {
    OCTET_STRING_t os;
    OCTET_STRING_t *decoded = NULL;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    size_t encode_offset = 0;
    char xml_buffer[4096];
    
    printf("Test: %s\n", test_name);
    
    /* Setup OCTET_STRING */
    memset(&os, 0, sizeof(os));
    os.buf = malloc(data_len);
    assert(os.buf);
    memcpy(os.buf, data, data_len);
    os.size = data_len;
    
    /* Encode to Base64 */
    memset(encode_buffer, 0, sizeof(encode_buffer));
    er = OCTET_STRING_encode_xer_base64(&asn_DEF_OCTET_STRING, &os,
                                        0, XER_F_CANONICAL,
                                        collect_bytes, &encode_offset);
    
    assert(er.encoded >= 0);
    encode_buffer[encode_offset] = '\0';
    
    printf("  Input size: %zu bytes\n", data_len);
    printf("  Encoded: %s\n", encode_buffer);
    
    /* Verify encoding if expected is provided */
    if(expected_base64) {
        assert(strcmp(encode_buffer, expected_base64) == 0);
        printf("  Encoding matches expected: PASS\n");
    }
    
    /* Decode back - wrap in XML tags for XER decoder */
    if(data_len == 0 && encode_offset == 0) {
        /* Empty string */
        snprintf(xml_buffer, sizeof(xml_buffer), "<tag></tag>");
    } else {
        snprintf(xml_buffer, sizeof(xml_buffer), "<tag>%s</tag>", encode_buffer);
    }
    
    dr = OCTET_STRING_decode_xer_base64(NULL, &asn_DEF_OCTET_STRING,
                                        (void **)&decoded, "tag",
                                        xml_buffer, strlen(xml_buffer));
    
    if(dr.code != RC_OK) {
        printf("  ERROR: Decode failed with code %d, consumed %zu bytes\n", 
               dr.code, dr.consumed);
        printf("  XML was: '%s'\n", xml_buffer);
        assert(0);
    }
    assert(decoded != NULL);
    assert(decoded->size == data_len);
    
    if(data_len > 0) {
        assert(memcmp(decoded->buf, data, data_len) == 0);
    }
    
    printf("  Decode round-trip: PASS\n");
    
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
    
    /* Cleanup */
    free(os.buf);
    printf("  %s: SUCCESS\n\n", test_name);
}

static void
test_decode_whitespace() {
    const char *inputs[] = {
        /* Base64 with various whitespace - in XML tags */
        "<tag>SGVsbG8sIFdvcmxkIQ==</tag>",
        "<tag>SGVs bG8s IFdv cmxk IQ==</tag>",
        "<tag>SGVs\nbG8s\nIFdv\ncmxk\nIQ==</tag>",
        "<tag>SGVs\tbG8s\tIFdv\tcmxk\tIQ==</tag>",
        "<tag>  SGVsbG8sIFdvcmxkIQ==  </tag>",
        "<tag>\nSGVsbG8sIFdvcmxkIQ==\n</tag>",
    };
    const char *expected = "Hello, World!";
    size_t expected_len = strlen(expected);
    
    printf("Test: Base64 decoding with whitespace variations\n");
    
    for(size_t i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
        OCTET_STRING_t *decoded = NULL;
        asn_dec_rval_t dr;
        
        dr = OCTET_STRING_decode_xer_base64(NULL, &asn_DEF_OCTET_STRING,
                                            (void **)&decoded, "tag",
                                            inputs[i], strlen(inputs[i]));
        
        assert(dr.code == RC_OK);
        assert(decoded != NULL);
        assert(decoded->size == expected_len);
        assert(memcmp(decoded->buf, expected, expected_len) == 0);
        
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
        printf("  Input %zu: PASS\n", i + 1);
    }
    
    printf("  Whitespace handling: SUCCESS\n\n");
}

static void
test_invalid_base64() {
    const char *invalid_inputs[] = {
        "<tag>SGVs!bG8</tag>",          /* Invalid character ! */
        "<tag>SGVs@bG8</tag>",          /* Invalid character @ */
        "<tag>SGV=bG8sIQ==</tag>",      /* Padding in middle */
    };
    
    printf("Test: Invalid Base64 rejection\n");
    
    for(size_t i = 0; i < sizeof(invalid_inputs)/sizeof(invalid_inputs[0]); i++) {
        OCTET_STRING_t *decoded = NULL;
        asn_dec_rval_t dr;
        
        dr = OCTET_STRING_decode_xer_base64(NULL, &asn_DEF_OCTET_STRING,
                                            (void **)&decoded, "tag",
                                            invalid_inputs[i], strlen(invalid_inputs[i]));
        
        /* Should fail to decode invalid Base64 */
        if(dr.code == RC_OK) {
            printf("  Input %zu FAILED: Should have rejected invalid Base64: %s\n", 
                   i + 1, invalid_inputs[i]);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
            assert(0);
        }
        
        /* Free the structure even on error to prevent memory leak */
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
        
        printf("  Input %zu: Correctly rejected\n", i + 1);
    }
    
    printf("  Invalid input rejection: SUCCESS\n\n");
}

static void
test_edge_cases() {
    printf("Test: Edge cases\n");
    
    /* Empty string */
    test_encode_decode("Empty string", (const uint8_t *)"", 0, "");
    
    /* Single byte (requires == padding) */
    test_encode_decode("Single byte", (const uint8_t *)"A", 1, "QQ==");
    
    /* Two bytes (requires = padding) */
    test_encode_decode("Two bytes", (const uint8_t *)"AB", 2, "QUI=");
    
    /* Three bytes (no padding) */
    test_encode_decode("Three bytes", (const uint8_t *)"ABC", 3, "QUJD");
    
    /* Four bytes */
    test_encode_decode("Four bytes", (const uint8_t *)"ABCD", 4, "QUJDRA==");
    
    /* All zeros */
    uint8_t zeros[10];
    memset(zeros, 0, sizeof(zeros));
    test_encode_decode("All zeros", zeros, sizeof(zeros), "AAAAAAAAAAAAAA==");
    
    /* All 0xFF */
    uint8_t ones[10];
    memset(ones, 0xFF, sizeof(ones));
    test_encode_decode("All 0xFF", ones, sizeof(ones), "/////////////w==");
    
    printf("  Edge cases: SUCCESS\n\n");
}

static void
test_binary_data() {
    printf("Test: Binary data patterns\n");
    
    /* Sequential bytes */
    uint8_t seq[256];
    for(int i = 0; i < 256; i++) {
        seq[i] = i;
    }
    test_encode_decode("Sequential 0-255", seq, sizeof(seq), NULL);
    
    /* Alternating pattern */
    uint8_t alt[16];
    for(int i = 0; i < 16; i++) {
        alt[i] = (i % 2) ? 0xFF : 0x00;
    }
    test_encode_decode("Alternating 0x00/0xFF", alt, sizeof(alt), NULL);
    
    /* Random-looking data */
    uint8_t random[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    test_encode_decode("Random bytes", random, sizeof(random), "EjRWeJq83vA=");
    
    printf("  Binary data: SUCCESS\n\n");
}

static void
test_text_data() {
    printf("Test: Text data\n");
    
    const char *texts[] = {
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "ASN.1 XER Base64 encoding test",
        "Special chars: !@#$%^&*()_+-=[]{}|;:',.<>?/~`",
        "Line1\nLine2\nLine3",
        "Tab\tSeparated\tValues",
    };
    
    for(size_t i = 0; i < sizeof(texts)/sizeof(texts[0]); i++) {
        test_encode_decode(texts[i], (const uint8_t *)texts[i], 
                          strlen(texts[i]), NULL);
    }
    
    printf("  Text data: SUCCESS\n\n");
}

static void
test_xml_context() {
    printf("Test: Base64 in XML context\n");
    
    /* Simulate decoding from XML tags */
    struct {
        const char *xml;
        const char *tag;
        const char *expected;
        size_t expected_len;
    } tests[] = {
        {"<tag>SGVsbG8sIFdvcmxkIQ==</tag>", "tag", "Hello, World!", 13},
        {"<Data>QUJDREVGR0g=</Data>", "Data", "ABCDEFGH", 8},
        {"<OctetString>AAECA//+/Q==</OctetString>", "OctetString", 
         "\x00\x01\x02\x03\xff\xfe\xfd", 7},
    };
    
    for(size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        OCTET_STRING_t *decoded = NULL;
        asn_dec_rval_t dr;
        
        dr = OCTET_STRING_decode_xer_base64(NULL, &asn_DEF_OCTET_STRING,
                                            (void **)&decoded, tests[i].tag,
                                            tests[i].xml, strlen(tests[i].xml));
        
        assert(dr.code == RC_OK);
        assert(decoded != NULL);
        assert(decoded->size == tests[i].expected_len);
        assert(memcmp(decoded->buf, tests[i].expected, tests[i].expected_len) == 0);
        
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
        printf("  XML example %zu: PASS\n", i + 1);
    }
    
    printf("  XML context: SUCCESS\n\n");
}

static void
test_large_data() {
    printf("Test: Large data encoding/decoding\n");
    
    /* Test with 1KB of data */
    uint8_t *large = malloc(1024);
    assert(large);
    for(size_t i = 0; i < 1024; i++) {
        large[i] = (uint8_t)(i & 0xFF);
    }
    
    OCTET_STRING_t os;
    OCTET_STRING_t *decoded = NULL;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    size_t encode_offset = 0;
    
    memset(&os, 0, sizeof(os));
    os.buf = large;
    os.size = 1024;
    
    /* Encode */
    memset(encode_buffer, 0, sizeof(encode_buffer));
    er = OCTET_STRING_encode_xer_base64(&asn_DEF_OCTET_STRING, &os,
                                        0, XER_F_CANONICAL,
                                        collect_bytes, &encode_offset);
    
    assert(er.encoded > 0);
    encode_buffer[encode_offset] = '\0';
    
    printf("  Encoded 1KB to %zu Base64 chars\n", encode_offset);
    
    /* Decode - wrap in XML tags */
    char xml_buffer[8192];
    snprintf(xml_buffer, sizeof(xml_buffer), "<tag>%s</tag>", encode_buffer);
    
    dr = OCTET_STRING_decode_xer_base64(NULL, &asn_DEF_OCTET_STRING,
                                        (void **)&decoded, "tag",
                                        xml_buffer, strlen(xml_buffer));
    
    assert(dr.code == RC_OK);
    assert(decoded != NULL);
    assert(decoded->size == 1024);
    assert(memcmp(decoded->buf, large, 1024) == 0);
    
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
    free(large);
    
    printf("  Large data: SUCCESS\n\n");
}

static void
test_hex_prefix() {
    printf("Test: H'...' prefix notation (X.693)\n");
    
    struct {
        const char *xml;
        const char *tag;
        const uint8_t *expected;
        size_t expected_len;
    } tests[] = {
        /* Simple hex with H' prefix */
        {"<tag>H'30030101FF'</tag>", "tag", 
         (const uint8_t *)"\x30\x03\x01\x01\xFF", 5},
        /* Lowercase h' prefix */
        {"<tag>h'AABBCCDD'</tag>", "tag",
         (const uint8_t *)"\xAA\xBB\xCC\xDD", 4},
        /* H' prefix with whitespace before it */
        {"<tag>  H'1234'</tag>", "tag",
         (const uint8_t *)"\x12\x34", 2},
        /* H' prefix with lowercase hex digits */
        {"<tag>H'aabbccdd'</tag>", "tag",
         (const uint8_t *)"\xAA\xBB\xCC\xDD", 4},
        /* H' prefix with mixed case */
        {"<tag>H'AaBbCcDd'</tag>", "tag",
         (const uint8_t *)"\xAA\xBB\xCC\xDD", 4},
        /* Empty hex string */
        {"<tag>H''</tag>", "tag",
         (const uint8_t *)"", 0},
    };
    
    for(size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        OCTET_STRING_t *decoded = NULL;
        asn_dec_rval_t dr;
        
        dr = OCTET_STRING_decode_xer_auto(NULL, &asn_DEF_OCTET_STRING,
                                          (void **)&decoded, tests[i].tag,
                                          tests[i].xml, strlen(tests[i].xml));
        
        if(dr.code != RC_OK) {
            printf("  ERROR: Test %zu failed to decode: %s\n", i + 1, tests[i].xml);
            printf("  Decode result: code=%d, consumed=%zu\n", dr.code, dr.consumed);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
            assert(0);
        }
        
        assert(decoded != NULL);
        assert(decoded->size == tests[i].expected_len);
        
        if(tests[i].expected_len > 0) {
            if(memcmp(decoded->buf, tests[i].expected, tests[i].expected_len) != 0) {
                printf("  ERROR: Test %zu data mismatch\n", i + 1);
                printf("  Expected: ");
                for(size_t j = 0; j < tests[i].expected_len; j++)
                    printf("%02X ", tests[i].expected[j]);
                printf("\n  Got:      ");
                for(size_t j = 0; j < decoded->size; j++)
                    printf("%02X ", decoded->buf[j]);
                printf("\n");
                ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
                assert(0);
            }
        }
        
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
        printf("  Test %zu: PASS (%s)\n", i + 1, tests[i].xml);
    }
    
    printf("  H' prefix notation: SUCCESS\n\n");
}

static void
test_invalid_hex_prefix() {
    printf("Test: Invalid H' prefix notation rejection\n");
    
    const char *invalid_inputs[] = {
        /* Unterminated string - no closing quote */
        "<tag>H'30030101FF</tag>",
        /* Invalid hex characters with H' prefix */
        "<tag>H'GHIJ'</tag>",
    };
    
    for(size_t i = 0; i < sizeof(invalid_inputs)/sizeof(invalid_inputs[0]); i++) {
        OCTET_STRING_t *decoded = NULL;
        asn_dec_rval_t dr;
        
        dr = OCTET_STRING_decode_xer_auto(NULL, &asn_DEF_OCTET_STRING,
                                          (void **)&decoded, "tag",
                                          invalid_inputs[i], strlen(invalid_inputs[i]));
        
        /* Should fail to decode invalid input */
        if(dr.code == RC_OK) {
            printf("  Input %zu FAILED: Should have rejected: %s\n", 
                   i + 1, invalid_inputs[i]);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
            assert(0);
        }
        
        /* Free the structure even on error to prevent memory leak */
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, decoded);
        
        printf("  Input %zu: Correctly rejected\n", i + 1);
    }
    
    printf("  Invalid H' prefix rejection: SUCCESS\n\n");
}

int
main() {
    printf("=== XER Base64 OCTET_STRING Comprehensive Tests ===\n\n");
    
    /* Run all test suites */
    test_edge_cases();
    test_binary_data();
    test_text_data();
    test_decode_whitespace();
    test_invalid_base64();
    test_xml_context();
    test_large_data();
    test_hex_prefix();
    test_invalid_hex_prefix();
    
    printf("=== All tests passed ===\n");
    return 0;
}
