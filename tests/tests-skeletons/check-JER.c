#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <asn_application.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <BOOLEAN.h>
#include <BMPString.h>
#include <UniversalString.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

/* Forward declaration for OCTET_STRING JER decoders */
asn_dec_rval_t OCTET_STRING_decode_jer_utf8(
    const asn_codec_ctx_t *opt_codec_ctx,
    const asn_TYPE_descriptor_t *td,
    const asn_jer_constraints_t *constraints,
    void **structure,
    const void *ptr, size_t size
);

/*
 * Test JER (JSON Encoding Rules) decoding functionality,
 * specifically for large JSON files that exceed the default buffer size.
 * This test validates the fix for issue #248 where JER decoding fails
 * for inputs larger than 16384 bytes.
 *
 * While this test verifies that the JER decoder itself can handle large
 * JSON inputs, the actual bug was in the converter-example.c file's
 * data_decode_from_file() function which reads files in chunks.
 * The fix ensures that large JSON files are read entirely into memory
 * before parsing, preventing failures due to partial tokens at chunk boundaries.
 */

static void
test_jer_decode_boolean_literals(void) {
    static const char *valid[] = {
        "true", "false",
        "true\n", "false\n",
        " true ", "\tfalse\r\n"
    };
    static const char *invalid[] = {
        "", "t", "tr", "tru",
        "f", "fa", "fal", "fals",
        "\"true\"", "truex", "falsehood", "true false"
    };
    size_t i;

    for(i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        BOOLEAN_t *boolean = NULL;
        asn_dec_rval_t rval = asn_decode(NULL, ATS_JER, &asn_DEF_BOOLEAN,
                                          (void **)&boolean, valid[i],
                                          strlen(valid[i]));
        printf("BOOLEAN JER valid [%s]: code=%d, consumed=%zu\n",
               valid[i], rval.code, rval.consumed);
        assert(rval.code == RC_OK);
        assert(boolean != NULL);
        ASN_STRUCT_FREE(asn_DEF_BOOLEAN, boolean);
    }

    for(i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        BOOLEAN_t *boolean = NULL;
        asn_dec_rval_t rval = asn_decode(NULL, ATS_JER, &asn_DEF_BOOLEAN,
                                          (void **)&boolean, invalid[i],
                                          strlen(invalid[i]));
        printf("BOOLEAN JER invalid [%s]: code=%d, consumed=%zu\n",
               invalid[i], rval.code, rval.consumed);
        assert(rval.code != RC_OK);
        if(boolean) ASN_STRUCT_FREE(asn_DEF_BOOLEAN, boolean);
    }

    printf("✓ BOOLEAN JER literal validation test passed\n");
}

static void
test_jer_decode_small_json(void) {
    const char *small_json = "\"Hello, World!\"";
    OCTET_STRING_t *octet_string = NULL;
    asn_dec_rval_t rval;

    /* Test small JSON decoding using the UTF8 decoder directly */
    rval = OCTET_STRING_decode_jer_utf8(0, &asn_DEF_OCTET_STRING, NULL, 
                                        (void **)&octet_string,
                                        small_json, strlen(small_json));

    printf("Small JSON test: code=%d, consumed=%zu\n", rval.code, rval.consumed);
    assert(rval.code == RC_OK);
    assert(octet_string != NULL);
    assert(octet_string->size == 13); /* "Hello, World!" */
    assert(memcmp(octet_string->buf, "Hello, World!", 13) == 0);

    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, octet_string);
    printf("✓ Small JSON decoding test passed\n");
}

static void
test_jer_decode_large_json(void) {
    /* Create a large JSON string (> 16384 bytes to trigger the bug) */
    const size_t large_size = 20000;
    char *large_json = malloc(large_size + 10);
    assert(large_json != NULL);

    /* Create a JSON string with a large payload */
    strcpy(large_json, "\"");
    for(size_t i = 1; i < large_size - 1; i++) {
        large_json[i] = 'A' + ((i - 1) % 26); /* Cycle through alphabet, starting with A */
    }
    large_json[large_size - 1] = '"';
    large_json[large_size] = '\0';

    OCTET_STRING_t *octet_string = NULL;
    asn_dec_rval_t rval;

    /* Test large JSON decoding using the UTF8 decoder */
    rval = OCTET_STRING_decode_jer_utf8(0, &asn_DEF_OCTET_STRING, NULL,
                                        (void **)&octet_string,
                                        large_json, strlen(large_json));

    printf("Large JSON test: code=%d, consumed=%zu\n", rval.code, rval.consumed);
    assert(rval.code == RC_OK);
    assert(octet_string != NULL);
    assert(octet_string->size == large_size - 2); /* Exclude quotes */

    /* Verify first few characters are correct */
    assert(octet_string->buf[0] == 'A');
    assert(octet_string->buf[1] == 'B');
    assert(octet_string->buf[2] == 'C');

    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, octet_string);
    free(large_json);
    printf("✓ Large JSON decoding test passed\n");
}

static void
test_jer_decode_with_file(void) {
    /*
     * Test the file-based decoding by creating a temporary file.
     * The name is made unique per process so that concurrent test runs
     * (e.g. parallel `make check` and `make distcheck` CI jobs sharing
     * one host) do not race on the same /tmp file.
     */
    char temp_filename[64];
    FILE *temp_file;

    snprintf(temp_filename, sizeof(temp_filename),
             "/tmp/test_large_jer.%ld.json", (long)getpid());
    
    /* Create a large JSON file */
    temp_file = fopen(temp_filename, "w");
    assert(temp_file != NULL);
    
    fprintf(temp_file, "\"");
    for(size_t i = 0; i < 20000; i++) {
        fputc('X', temp_file);
    }
    fprintf(temp_file, "\"");
    fclose(temp_file);
    
    /* Test file-based decoding */
    temp_file = fopen(temp_filename, "r");
    assert(temp_file != NULL);
    
    /* Get file size */
    fseek(temp_file, 0, SEEK_END);
    long file_size = ftell(temp_file);
    fseek(temp_file, 0, SEEK_SET);
    
    /* Read entire file */
    char *file_content = malloc(file_size + 1);
    assert(file_content != NULL);
    size_t read_size = fread(file_content, 1, file_size, temp_file);
    assert(read_size == (size_t)file_size);
    file_content[file_size] = '\0';
    fclose(temp_file);
    
    /* Test JER decoding using the UTF8 decoder */
    OCTET_STRING_t *octet_string = NULL;
    asn_dec_rval_t rval;
    
    rval = OCTET_STRING_decode_jer_utf8(0, &asn_DEF_OCTET_STRING, NULL,
                                        (void **)&octet_string,
                                        file_content, file_size);
    
    printf("File-based test: code=%d, consumed=%zu, file_size=%ld\n", 
           rval.code, rval.consumed, file_size);
    assert(rval.code == RC_OK);
    assert(octet_string != NULL);
    assert(octet_string->size == 20000); /* Content without quotes */
    
    /* Verify content */
    for(size_t i = 0; i < 100; i++) { /* Check first 100 chars */
        assert(octet_string->buf[i] == 'X');
    }
    
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, octet_string);
    free(file_content);
    unlink(temp_filename);
    printf("✓ File-based JSON decoding test passed\n");
}

/*
 * Test strict JER decoding of variable-length BIT STRING objects.
 *
 * Original source: regression test added for the JER duplicate-member issue.
 * Version: 2026-09-24.
 * Input parameters: none; the test supplies valid and malformed JER literals.
 * Return value: none; assertions abort the test on an unexpected result.
 * Exceptions: none; decoder failures are checked through return codes.
 * Responsible party: asn1c maintainers.
 * History: added to ensure each X.697 value/length member occurs once and
 * that unknown or malformed object members are not silently skipped.
 * Use example: run the check-JER test executable from the build tree.
 */
static void
test_jer_decode_bit_string_object(void) {
    static const char *valid[] = {
        "{\"value\":\"AB\",\"length\":8}",
        "{ \n \"value\" : \"AB\" ,\t \"length\" : 8 \n }"
    };
    static const char *invalid[] = {
        "{\"value\":\"AB\",\"length\":8,\"value\":\"CD\",\"length\":8}",
        "{\"value\":\"AB\",\"length\":8,\"length\":0}",
        "{\"value\":\"AB\",\"length\":8,\"unknown\":0}",
        "{\"value\":\"AB\",\"length\":8,}",
        "{\"value\":\"AB\",\"length\":8x}"
    };
    size_t i;

    for(i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        BIT_STRING_t *bits = NULL;
        asn_dec_rval_t rval = asn_decode(NULL, ATS_JER, &asn_DEF_BIT_STRING,
                                          (void **)&bits, valid[i],
                                          strlen(valid[i]));
        assert(rval.code == RC_OK);
        assert(bits != NULL);
        assert(bits->size == 1);
        assert(bits->buf[0] == 0xAB);
        assert(bits->bits_unused == 0);
        ASN_STRUCT_FREE(asn_DEF_BIT_STRING, bits);
    }

    {
        BIT_STRING_t *bits = NULL;
        const char *minified = "{\"value\":\"AB\",\"length\":8}";
        asn_dec_rval_t rval = asn_decode(NULL, ATS_JER_MINIFIED,
                                          &asn_DEF_BIT_STRING, (void **)&bits,
                                          minified, strlen(minified));
        assert(rval.code == RC_OK);
        assert(bits != NULL && bits->size == 1 && bits->buf[0] == 0xAB);
        ASN_STRUCT_FREE(asn_DEF_BIT_STRING, bits);
    }

    for(i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        BIT_STRING_t *bits = NULL;
        asn_dec_rval_t rval = asn_decode(NULL, ATS_JER, &asn_DEF_BIT_STRING,
                                          (void **)&bits, invalid[i],
                                          strlen(invalid[i]));
        assert(rval.code != RC_OK);
        if(bits) ASN_STRUCT_FREE(asn_DEF_BIT_STRING, bits);
    }

    printf("✓ BIT STRING JER object validation test passed\n");
}

/*
 * Hold bounded output from a direct JER encoder callback.
 * Every member describes the caller-owned capture buffer and its used prefix.
 */
typedef struct jer_capture_s {
    char data[128]; /* Captured output bytes, followed by a local NUL. */
    size_t length;  /* Number of captured bytes, excluding the local NUL. */
} jer_capture_t;

/*
 * Append one encoder callback chunk to a bounded test capture.
 * Parameters: bytes/length are the callback chunk; key is jer_capture_t.
 * Returns zero when copied, -1 on invalid arguments or capacity exhaustion.
 * Throws: nothing. Original source: check-JER regression fixture.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * History: added to inspect direct BIT STRING and OCTET STRING JER output.
 * Example: callback appends a quoted empty string as two output bytes.
 */
static int
capture_jer_bytes(const void *bytes, size_t length, void *key) {
    jer_capture_t *capture = (jer_capture_t *)key;
    if(!capture || capture->length >= sizeof(capture->data) || (length && !bytes)
       || length > sizeof(capture->data) - capture->length - 1) return -1;
    if(length) memcpy(capture->data + capture->length, bytes, length);
    capture->length += length;
    capture->data[capture->length] = '\0';
    return 0;
}

/*
 * Purpose: force a direct JER encoder callback failure.
 * Source: asn_app_consume_bytes_f callback contract.
 * Version/date: 1.0, 2026-10-31. Inputs: bytes/length are ignored; key is unused.
 * Returns: always -1. Exceptions: none. Author: asn1c maintainers.
 * History: added for BMPString and UniversalString failure coverage.
 * Example: the string encoder propagates this callback's failure.
 */
static int
reject_jer_bytes(const void *bytes, size_t length, void *key) {
    (void)bytes;
    (void)length;
    (void)key;
    return -1;
}

/*
 * Verify BMPString and UniversalString emit valid escaped JSON strings.
 * Original source: issue 594 C JER regression coverage. Version/date: 2026-10-31.
 * Inputs: none; local UCS-2/UCS-4 values cover escapes and invalid storage.
 * Returns: no value. Errors: assertions identify encoder regressions.
 * Author: asn1c maintainers. History: added for JSON string escaping.
 * Example: quote and backslash code points are escaped in the JSON output.
 */
static void
test_jer_bmp_and_universal_string_escaping(void) {
    static uint8_t bmp_data[] = {0, 0x22, 0, 0x5c, 0, 1, 0, 0, 0, 0xe9};
    static const char bmp_expected[] = "\"\\\"\\\\\\u0001\\u0000\xc3\xa9\"";
    static uint8_t bmp_surrogate[] = {0xd8, 0};
    static uint8_t bmp_odd[] = {0};
    static uint8_t universal_data[] = {
        0, 0, 0, 0x22, 0, 0, 0, 0x5c, 0, 0, 0, 10,
        0, 1, 0xf6, 0x00
    };
    static const char universal_expected[] = "\"\\\"\\\\\\n\xf0\x9f\x98\x80\"";
    static uint8_t universal_surrogate[] = {0, 0, 0xd8, 0};
    static uint8_t universal_too_large[] = {0, 0x11, 0, 0};
    static uint8_t universal_partial[] = {0};
    BMPString_t bmp = {bmp_data, sizeof(bmp_data), {0}};
    UniversalString_t universal = {universal_data, sizeof(universal_data), {0}};
    BMPString_t empty_bmp = {0};
    UniversalString_t empty_universal = {0};
    BMPString_t invalid_bmp = {bmp_surrogate, sizeof(bmp_surrogate), {0}};
    BMPString_t odd_bmp = {bmp_odd, sizeof(bmp_odd), {0}};
    UniversalString_t invalid_universal = {
        universal_surrogate, sizeof(universal_surrogate), {0}
    };
    UniversalString_t large_universal = {
        universal_too_large, sizeof(universal_too_large), {0}
    };
    UniversalString_t partial_universal = {
        universal_partial, sizeof(universal_partial), {0}
    };
    jer_capture_t capture = {{0}, 0};
    asn_enc_rval_t encoded;

    encoded = BMPString_encode_jer(&asn_DEF_BMPString, 0, &bmp, 0,
                                   JER_F_MINIFIED, capture_jer_bytes, &capture);
    assert(encoded.encoded == (ssize_t)(sizeof(bmp_expected) - 1));
    assert(strcmp(capture.data, bmp_expected) == 0);
    capture.length = 0;
    capture.data[0] = '\0';
    encoded = UniversalString_encode_jer(&asn_DEF_UniversalString, 0,
        &universal, 0, JER_F_MINIFIED, capture_jer_bytes, &capture);
    assert(encoded.encoded == (ssize_t)(sizeof(universal_expected) - 1));
    assert(strcmp(capture.data, universal_expected) == 0);

    capture.length = 0;
    capture.data[0] = '\0';
    assert(BMPString_encode_jer(&asn_DEF_BMPString, 0, &empty_bmp, 0,
        JER_F_MINIFIED, capture_jer_bytes, &capture).encoded == 2);
    capture.length = 0;
    capture.data[0] = '\0';
    assert(UniversalString_encode_jer(&asn_DEF_UniversalString, 0,
        &empty_universal, 0, JER_F_MINIFIED, capture_jer_bytes,
        &capture).encoded == 2);
    assert(BMPString_encode_jer(&asn_DEF_BMPString, 0, &invalid_bmp, 0,
        JER_F_MINIFIED, capture_jer_bytes, &capture).encoded == -1);
    assert(BMPString_encode_jer(&asn_DEF_BMPString, 0, &odd_bmp, 0,
        JER_F_MINIFIED, capture_jer_bytes, &capture).encoded == -1);
    assert(UniversalString_encode_jer(&asn_DEF_UniversalString, 0,
        &invalid_universal, 0, JER_F_MINIFIED, capture_jer_bytes,
        &capture).encoded == -1);
    assert(UniversalString_encode_jer(&asn_DEF_UniversalString, 0,
        &large_universal, 0, JER_F_MINIFIED, capture_jer_bytes,
        &capture).encoded == -1);
    assert(UniversalString_encode_jer(&asn_DEF_UniversalString, 0,
        &partial_universal, 0, JER_F_MINIFIED, capture_jer_bytes,
        &capture).encoded == -1);
    assert(BMPString_encode_jer(&asn_DEF_BMPString, 0, &bmp, 0,
        JER_F_MINIFIED, reject_jer_bytes, 0).encoded == -1);
    assert(UniversalString_encode_jer(&asn_DEF_UniversalString, 0,
        &universal, 0, JER_F_MINIFIED, reject_jer_bytes, 0).encoded == -1);
}

/*
 * Exercise empty, fixed-size, malformed, and transactional BIT STRING JER.
 * Parameters: none; the test owns its descriptors, literals, and values.
 * Returns: no value; assertions report any mismatch. Throws: nothing.
 * Original source: check-JER regression fixture. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: empty and malformed values.
 * Example: run check-JER to verify empty fixed and variable round trips.
 */
static void
test_jer_bit_string_edges(void) {
    static const char empty_object[] = "{\"value\":\"\",\"length\":0}";
    static const char fixed_empty[] = "\"\"";
    static const char *invalid[] = {
        "{\"value\":\"AB\",\"length\":-1}",
        "{\"value\":\"AB\",\"length\":1.0}",
        "{\"value\":\"AB\",\"length\":18446744073709551616}",
        "{\"value\":\"AB\",\"length\":1}",
        "{\"value\":\"AB\",\"length\":5}",
        "{\"value\":\"A\",\"length\":4}",
        "{\"value\":\"AG\",\"length\":8}"
    };
    const asn_jer_constraints_t variable = {-1, 0, 0};
    const asn_jer_constraints_t fixed_zero = {0, 0, 0};
    const asn_jer_constraints_t fixed_nine = {9, 0, 0};
    unsigned char nine_bits[] = {0xab, 0x80};
    BIT_STRING_t fixed_value = {nine_bits, sizeof(nine_bits), 7, {0}};
    BIT_STRING_t old_value = {0};
    jer_capture_t capture = {{0}, 0};
    void *decoded = 0;
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;
    size_t i;

    /* Empty variable and fixed values use their established wire shapes. */
    result = BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &variable,
                                  &decoded, empty_object,
                                  sizeof(empty_object) - 1);
    assert(result.code == RC_OK && decoded);
    assert(((BIT_STRING_t *)decoded)->size == 0);
    assert(((BIT_STRING_t *)decoded)->bits_unused == 0);
    encoded = BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &variable, decoded,
                                    0, JER_F_MINIFIED, capture_jer_bytes,
                                    &capture);
    assert(encoded.encoded == (ssize_t)(sizeof(empty_object) - 1));
    assert(strcmp(capture.data, empty_object) == 0);
    ASN_STRUCT_FREE(asn_DEF_BIT_STRING, decoded);
    decoded = 0;

    result = BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &variable,
                                  &decoded, "{\"value\":\"A8\",\"length\":5}",
                                  sizeof("{\"value\":\"A8\",\"length\":5}") - 1);
    assert(result.code == RC_OK && ((BIT_STRING_t *)decoded)->bits_unused == 3);
    ASN_STRUCT_FREE(asn_DEF_BIT_STRING, decoded);
    decoded = 0;

    result = BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &fixed_zero,
                                  &decoded, fixed_empty,
                                  sizeof(fixed_empty) - 1);
    assert(result.code == RC_OK && decoded);
    capture.length = 0;
    capture.data[0] = '\0';
    encoded = BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &fixed_zero, decoded,
                                    0, JER_F_MINIFIED, capture_jer_bytes,
                                    &capture);
    assert(encoded.encoded == 2 && strcmp(capture.data, fixed_empty) == 0);
    ASN_STRUCT_FREE(asn_DEF_BIT_STRING, decoded);

    /* Nine fixed bits require exactly two octets and seven zero padding bits. */
    decoded = 0;
    result = BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &fixed_nine,
                                  &decoded, "\"AB80\"", 6);
    assert(result.code == RC_OK && ((BIT_STRING_t *)decoded)->size == 2);
    ASN_STRUCT_FREE(asn_DEF_BIT_STRING, decoded);
    decoded = 0;
    assert(BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &fixed_nine,
                                 &decoded, "\"AB8000\"", 8).code == RC_FAIL);
    assert(decoded == 0);
    assert(BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &fixed_nine,
                                 &decoded, "\"AB\"", 4).code == RC_FAIL);
    assert(BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &fixed_nine,
                                 &decoded, "\"AB81\"", 6).code == RC_FAIL);
    assert(BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &variable,
                                 &decoded, 0, 0).code == RC_WMORE);
    assert(BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &variable,
                                 0, empty_object,
                                 sizeof(empty_object) - 1).code == RC_FAIL);

    /* Every malformed variable object leaves an existing value untouched. */
    old_value.buf = (uint8_t *)malloc(1);
    assert(old_value.buf);
    old_value.buf[0] = 0x5a;
    old_value.size = 1;
    old_value.bits_unused = 0;
    for(i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        void *owned = &old_value;
        result = BIT_STRING_decode_jer(NULL, &asn_DEF_BIT_STRING, &variable,
                                      &owned, invalid[i], strlen(invalid[i]));
        assert(result.code == RC_FAIL);
        assert(owned == &old_value && old_value.buf[0] == 0x5a);
        assert(old_value.size == 1 && old_value.bits_unused == 0);
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_BIT_STRING, &old_value);

    /* Encoder accepts a NULL pointer only for a genuinely empty value. */
    {
        BIT_STRING_t empty = {0};
        capture.length = 0;
        capture.data[0] = '\0';
        encoded = BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &variable, &empty,
                                        0, JER_F_MINIFIED, capture_jer_bytes,
                                        &capture);
        assert(encoded.encoded == (ssize_t)(sizeof(empty_object) - 1));
        empty.bits_unused = 1;
        assert(BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &variable, &empty,
                                     0, JER_F_MINIFIED, capture_jer_bytes,
                                     &capture).encoded < 0);
        {
            unsigned char invalid_pad_data[] = {0xab};
            BIT_STRING_t invalid_pad = {invalid_pad_data, 1, 3, {0}};
            BIT_STRING_t missing_data = {0};
            missing_data.size = 1;
            assert(BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &variable,
                                         &invalid_pad, 0, JER_F_MINIFIED,
                                         capture_jer_bytes, &capture).encoded < 0);
            assert(BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &variable,
                                         &missing_data, 0, JER_F_MINIFIED,
                                         capture_jer_bytes, &capture).encoded < 0);
        }
        capture.length = 0;
        capture.data[0] = '\0';
        encoded = BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &fixed_nine,
                                        &fixed_value, 0, JER_F_MINIFIED,
                                        capture_jer_bytes, &capture);
        assert(encoded.encoded == 6 && strcmp(capture.data, "\"AB80\"") == 0);
        {
            unsigned char extra_data[] = {0xab, 0x80, 0};
            BIT_STRING_t extra = {extra_data, sizeof(extra_data), 7, {0}};
            assert(BIT_STRING_encode_jer(&asn_DEF_BIT_STRING, &fixed_nine,
                                         &extra, 0, JER_F_MINIFIED,
                                         capture_jer_bytes, &capture).encoded < 0);
        }
    }

    printf("✓ BIT STRING JER empty and malformed-value tests passed\n");
}

/*
 * Verify empty OCTET STRING values encode without NULL pointer arithmetic.
 * Parameters: none; the test exercises hexadecimal and base64 encoders.
 * Returns: no value; assertions report output mismatches. Throws: nothing.
 * Original source: check-JER regression fixture. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: empty encoder guard.
 * Example: both encoders produce the JSON string `""` for an empty value.
 */
static void
test_jer_empty_octet_string_encoders(void) {
    const OCTET_STRING_t empty = {0};
    const char expected[] = "\"\"";
    jer_capture_t capture = {{0}, 0};
    asn_enc_rval_t result;

    result = OCTET_STRING_encode_jer(&asn_DEF_OCTET_STRING, 0, &empty, 0,
                                     JER_F_MINIFIED, capture_jer_bytes,
                                     &capture);
    assert(result.encoded == 2 && strcmp(capture.data, expected) == 0);
    capture.length = 0;
    capture.data[0] = '\0';
    result = OCTET_STRING_encode_jer_base64(&asn_DEF_OCTET_STRING, 0, &empty,
                                            0, JER_F_MINIFIED,
                                            capture_jer_bytes, &capture);
    assert(result.encoded == 2 && strcmp(capture.data, expected) == 0);
}

/*
 * Reject invalid JSON escapes while decoding JER character strings.
 * Original source: OPEN TYPE malformed-value regression. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertion on a codec regression.
 * Author: asn1c maintainers. History: test JSON escape and Unicode handling.
 * Example: an invalid escaped letter must not decode as a character string.
 */
static void
test_jer_character_escapes(void) {
    static const char *invalid[] = {
        "\"\\lice\"", "\"\\u12xz\"", "\"\\ud800\"",
        "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"a\nb\""
    };
    static const struct { const char *json; const char *value; size_t size; } valid[] = {
        {"\"\\/\\n\\\\\\\"\"", "/\n\\\"", 4},
        {"\"\\u0041\"", "A", 1},
        {"\"\\ud83d\\ude00\"", "\xf0\x9f\x98\x80", 4}
    };
    size_t i;
    for(i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        OCTET_STRING_t *value = NULL;
        asn_dec_rval_t result = OCTET_STRING_decode_jer_utf8(
            NULL, &asn_DEF_OCTET_STRING, NULL, (void **)&value,
            invalid[i], strlen(invalid[i]));
        assert(result.code != RC_OK);
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, value);
    }
    for(i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        OCTET_STRING_t *value = NULL;
        asn_dec_rval_t result = OCTET_STRING_decode_jer_utf8(
            NULL, &asn_DEF_OCTET_STRING, NULL, (void **)&value,
            valid[i].json, strlen(valid[i].json));
        assert(result.code == RC_OK && value && value->size == valid[i].size);
        assert(memcmp(value->buf, valid[i].value, valid[i].size) == 0);
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, value);
    }
}

/*
 * Recurse through syntax-aware validation to exercise its depth bound.
 * Source: CONTAINING recursion guard. Version: 2026-10-30. Inputs: td is a
 * test descriptor, sptr points to the remaining depth, cb/key are unused.
 * Returns: zero within the bound and -1 when the guard is reached. Exceptions:
 * none. Author: asn1c maintainers. History: recursive CONTAINING hardening.
 * Example: a remaining depth of one enters one additional constraint check.
 */
static int
test_recursive_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                          asn_app_constraint_failed_f *cb, void *key) {
    unsigned remaining = *(const unsigned *)sptr;
    (void)cb;
    (void)key;
    if(!remaining) return 0;
    --remaining;
    return asn_check_constraints_with_syntax(td, &remaining, ATS_JER, NULL, NULL);
}

/*
 * Verify the nested constraint depth limit and restoration after failure.
 * Source: CONTAINING recursion guard. Version: 2026-10-30. Inputs: none.
 * Returns: nothing. Errors: assertions on regression. No exceptions.
 * Author: asn1c maintainers. History: recursive CONTAINING hardening.
 * Example: a later shallow check succeeds after a rejected deep check.
 */
static void
test_containing_constraint_depth(void) {
    asn_TYPE_descriptor_t descriptor = asn_DEF_BOOLEAN;
    unsigned depth = 63;
    descriptor.encoding_constraints.general_constraints = test_recursive_constraint;
    assert(asn_check_constraints_with_syntax(&descriptor, &depth, ATS_JER, NULL, NULL) == 0);
    depth = 64;
    assert(asn_check_constraints_with_syntax(&descriptor, &depth, ATS_JER, NULL, NULL) == -1);
    depth = 0;
    assert(asn_check_constraints_with_syntax(&descriptor, &depth, ATS_JER, NULL, NULL) == 0);
}

int
main(void) {
    printf("Running JER (JSON Encoding Rules) decoding tests...\n");

    test_jer_decode_boolean_literals();
    test_jer_decode_small_json();
    test_jer_bmp_and_universal_string_escaping();
    test_jer_character_escapes();
    test_containing_constraint_depth();
    test_jer_decode_large_json();
    test_jer_decode_with_file();
    test_jer_decode_bit_string_object();
    test_jer_bit_string_edges();
    test_jer_empty_octet_string_encoders();
    
    printf("✓ All JER decoding tests passed!\n");
    return 0;
}
