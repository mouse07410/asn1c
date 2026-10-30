/*
 * Compare generated C JER primitive encodings with fixed compact tokens.
 * Original source: asn1c generated-code parity fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
 * primitive parity tests. Example: c-jer [--decode-dir directory].
 */
#include <asn_application.h>
#include <jer_decoder.h>
#include <jer_encoder.h>
#include <INTEGER.h>
#include <BMPString.h>

#include <Count.h>
#include <Empty.h>
#include <Flag.h>
#include <SignBounds.h>
#include <Singleton.h>
#include <EmptyHexOctets.h>
#include <MixedHexOctets.h>
#include <BoundedHexOctets.h>
#include <ThreeBits.h>
#include <BoundedBits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JER_BUFFER_CAPACITY 64

/*
 * Bounded storage for one tiny primitive JSON token.
 * Each member describes callback output state; the buffer and its length are
 * state variables scoped to a single encoding operation.
 */
typedef struct jer_buffer_s {
    char data[JER_BUFFER_CAPACITY]; /* state variable: token plus terminating NUL. */
    size_t length;                  /* state variable: current token byte count. */
} jer_buffer_t;

/*
 * One generated C value and its independently fixed compact JER token.
 * Each member selects a descriptor, initialized value, expected token, and
 * diagnostic label. This structure contains no mutable state variables.
 */
typedef struct jer_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated ASN.1 descriptor. */
    const void *value;                 /* Initialized value for the encoder. */
    const char *expected;              /* Independent compact JSON token. */
    const char *name;                  /* Diagnostic case name. */
} jer_case_t;

/*
 * Append callback bytes to bounded JER storage and maintain a C string.
 * Parameters: bytes is the emitted chunk, length is its byte count, and key
 * points to the operation's output buffer.
 * Returns zero on success or -1 for invalid input or insufficient capacity.
 * Exceptions: none. Original source: asn1c application callback fixture.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
 * initial JER parity tests. Example: callback("true", 4, &buffer).
 */
static int
append_bytes(const void *bytes, size_t length, void *key) {
    jer_buffer_t *buffer = (jer_buffer_t *)key;

    if(!buffer || (!bytes && length != 0)
       || buffer->length >= JER_BUFFER_CAPACITY
       || length >= JER_BUFFER_CAPACITY - buffer->length) {
        return -1;
    }
    if(length) memcpy(buffer->data + buffer->length, bytes, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return 0;
}

/*
 * Encode and decode one value, checking the independent fixed token.
 * Parameters: item contains its descriptor, source value, expected token, and
 * diagnostic label.
 * Returns zero when encode, decode, and re-encode all match; otherwise one.
 * Exceptions: none; allocation and codec failures become a failure return.
 * Original source: generated C JER parity fixture. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: initial primitive tests.
 * Example: check_case(&cases[0]) compares BOOLEAN FALSE with `false`.
 */
static int
check_case(const jer_case_t *item) {
    jer_buffer_t first = {{0}, 0};
    jer_buffer_t second = {{0}, 0};
    void *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t expected_length;
    int failed;

    if(!item || !item->type || !item->value || !item->expected || !item->name) {
        return 1;
    }
    expected_length = strlen(item->expected);
    encoded = jer_encode(item->type, item->value, JER_F_MINIFIED,
                         append_bytes, &first);
    failed = encoded.encoded < 0 || first.length != expected_length
             || memcmp(first.data, item->expected, expected_length) != 0;
    if(!failed) {
        result = jer_decode(NULL, item->type, &decoded, item->expected,
                            expected_length);
        failed = result.code != RC_OK || !decoded;
    }
    if(!failed) {
        encoded = jer_encode(item->type, decoded, JER_F_MINIFIED,
                             append_bytes, &second);
        failed = encoded.encoded < 0 || second.length != expected_length
                 || memcmp(second.data, item->expected, expected_length) != 0;
    }
    if(decoded) ASN_STRUCT_FREE(*item->type, decoded);
    if(failed) fprintf(stderr, "C JER vector mismatch: %s\n", item->name);
    return failed;
}

/*
 * Decode and re-encode a Rust-generated token from a named fixture file.
 * Parameters: type is the generated descriptor, directory is the fixture
 * folder, and filename is a stable `jer_*.json` filename.
 * Returns zero when C decodes and reproduces the complete token; otherwise one.
 * Exceptions: none; file and codec failures become a failure return.
 * Original source: generated Rust/C JER interoperability fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: initial JER parity.
 * Example: check_rust_file(&asn_DEF_Flag, path, "jer_flag_true.json").
 */
static int
check_rust_file(const asn_TYPE_descriptor_t *type, const char *directory,
                const char *filename) {
    char path[4096];
    char input[JER_BUFFER_CAPACITY];
    jer_buffer_t output = {{0}, 0};
    void *decoded = NULL;
    FILE *stream;
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;
    size_t length;
    int extra;
    int failed;
    int path_length;

    if(!type || !directory || !directory[0] || !filename || !filename[0]) return 1;
    path_length = snprintf(path, sizeof(path), "%s/%s", directory, filename);
    if(path_length < 0 || (size_t)path_length >= sizeof(path)) return 1;
    stream = fopen(path, "rb");
    if(!stream) {
        fprintf(stderr, "cannot open Rust JER vector: %s\n", path);
        return 1;
    }
    length = fread(input, 1, sizeof(input) - 1, stream);
    extra = fgetc(stream);
    failed = ferror(stream) || extra != EOF;
    if(fclose(stream) != 0) failed = 1;
    if(failed || length == 0) {
        fprintf(stderr, "invalid Rust JER vector size: %s\n", path);
        return 1;
    }
    input[length] = '\0';

    result = jer_decode(NULL, type, &decoded, input, length);
    failed = result.code != RC_OK || !decoded;
    if(!failed) {
        encoded = jer_encode(type, decoded, JER_F_MINIFIED, append_bytes, &output);
        failed = encoded.encoded < 0 || output.length != length
                 || memcmp(output.data, input, length) != 0;
    }
    if(decoded) ASN_STRUCT_FREE(*type, decoded);
    if(failed) fprintf(stderr, "C could not round-trip Rust JER vector: %s\n", path);
    return failed;
}

/*
 * Encode one C value and save its compact JER token for the Rust decoder.
 * Parameters: type is the generated descriptor; value is a valid value;
 * directory is the output folder; filename is a fixed test filename.
 * Returns zero on success or one for codec, path, or file errors. Exceptions:
 * none. Original source: generated C JER interoperability fixture.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
 * added OCTET STRING cross-decoding. Example: save an empty OCTET STRING token.
 */
static int
write_c_vector(const asn_TYPE_descriptor_t *type, const void *value,
               const char *directory, const char *filename) {
    char path[4096];
    jer_buffer_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    FILE *stream;
    int path_length;
    int failed;

    if(!type || !value || !directory || !directory[0] || !filename || !filename[0])
        return 1;
    path_length = snprintf(path, sizeof(path), "%s/%s", directory, filename);
    if(path_length < 0 || (size_t)path_length >= sizeof(path)) return 1;
    encoded = jer_encode(type, value, JER_F_MINIFIED, append_bytes, &output);
    if(encoded.encoded < 0) return 1;
    stream = fopen(path, "wb");
    if(!stream) return 1;
    failed = fwrite(output.data, 1, output.length, stream) != output.length;
    if(fclose(stream) != 0) failed = 1;
    if(failed) fprintf(stderr, "cannot write C JER vector: %s\n", path);
    return failed;
}

/*
 * Exercise the BMPString helper in a JER-only C build without print or XER.
 * Parameters: none. Returns zero for a compact encode/decode round trip or
 * one on failure. Exceptions: none; codec failures become a return value.
 * Original source: generated C JER guard regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: verifies BMPString__dump is
 * declared and linked when only JER uses it. Example: `check_bmp_string()`.
 */
static int
check_bmp_string(void) {
    unsigned char letter[] = {0x00, 0x41};
    BMPString_t value = {letter, sizeof(letter)};
    jer_buffer_t output = {{0}, 0};
    jer_buffer_t repeated = {{0}, 0};
    void *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;

    encoded = jer_encode(&asn_DEF_BMPString, &value, JER_F_MINIFIED,
                         append_bytes, &output);
    failed = encoded.encoded < 0 || output.length != 3
             || memcmp(output.data, "\"A\"", 3) != 0;
    if(!failed) {
        result = jer_decode(NULL, &asn_DEF_BMPString, &decoded,
                            output.data, output.length);
        failed = result.code != RC_OK || !decoded;
    }
    if(!failed) {
        encoded = jer_encode(&asn_DEF_BMPString, decoded, JER_F_MINIFIED,
                             append_bytes, &repeated);
        failed = encoded.encoded < 0 || repeated.length != output.length
                 || memcmp(repeated.data, output.data, output.length) != 0;
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_BMPString, decoded);
    if(failed) fprintf(stderr, "C JER BMPString round trip failed\n");
    return failed;
}

/*
 * Check C fixed vectors and optionally consume the Rust-generated token files.
 * Parameters: argc is the argument count; argv contains no arguments or the
 * pair `--decode-dir directory`, `--decode-octet-dir directory`,
 * `--decode-bit-dir directory`, or `--write-dir directory`.
 * Returns zero on success or one for invalid arguments or any mismatch.
 * Exceptions: none. Original source: C/Rust JER interoperability fixture.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
 * initial JER primitive parity tests. Example: `c-jer --decode-dir vectors`.
 */
int
main(int argc, char **argv) {
    BOOLEAN_t flag_false = 0;
    BOOLEAN_t flag_true = 1;
    Empty_t empty = 0;
    Count_t count_min = -10;
    Count_t count_max = 10;
    Singleton_t singleton = 5;
    SignBounds_t sign_min = -129;
    SignBounds_t sign_max = 128;
    unsigned char empty_octet_storage = 0; /* state variable: safe non-NULL zero-size backing. */
    unsigned char mixed_octets[] = {0x00, 0xaf, 0xff}; /* state variable: mixed test bytes. */
    unsigned char bounded_octets[] = {0x00, 0xaf, 0xff}; /* state variable: bounded payload. */
    unsigned char fixed_bit_storage = 0xa0; /* state variable: fixed three-bit payload. */
    unsigned char bounded_bit_storage = 0xa8; /* state variable: bounded five-bit payload. */
    OCTET_STRING_t empty_octets = {&empty_octet_storage, 0};
    OCTET_STRING_t mixed_octet_value = {mixed_octets, sizeof(mixed_octets)};
    OCTET_STRING_t bounded_octet_value = {bounded_octets, sizeof(bounded_octets)};
    BIT_STRING_t fixed_bit_value = {&fixed_bit_storage, 1, 5};
    BIT_STRING_t bounded_bit_value = {&bounded_bit_storage, 1, 3};
    const jer_case_t cases[] = {
        {&asn_DEF_Flag, &flag_false, "false", "BOOLEAN FALSE"},
        {&asn_DEF_Flag, &flag_true, "true", "BOOLEAN TRUE"},
        {&asn_DEF_Empty, &empty, "null", "NULL"},
        {&asn_DEF_Count, &count_min, "-10", "Count minimum"},
        {&asn_DEF_Count, &count_max, "10", "Count maximum"},
        {&asn_DEF_Singleton, &singleton, "5", "Singleton"},
        {&asn_DEF_SignBounds, &sign_min, "-129", "SignBounds minimum"},
        {&asn_DEF_SignBounds, &sign_max, "128", "SignBounds maximum"},
    };
    size_t index;
    int failed = 0;
    const char *directory = NULL;
    const char *octet_directory = NULL;
    const char *bit_directory = NULL;
    const char *write_directory = NULL;

    if(argc == 3 && strcmp(argv[1], "--decode-dir") == 0) {
        directory = argv[2];
    } else if(argc == 3 && strcmp(argv[1], "--decode-octet-dir") == 0) {
        octet_directory = argv[2];
    } else if(argc == 3 && strcmp(argv[1], "--decode-bit-dir") == 0) {
        bit_directory = argv[2];
    } else if(argc == 3 && strcmp(argv[1], "--write-dir") == 0) {
        write_directory = argv[2];
    } else if(argc != 1) {
        fprintf(stderr,
                "usage: %s [--decode-dir directory | --decode-octet-dir directory "
                "| --decode-bit-dir directory | --write-dir directory]\n", argv[0]);
        return 1;
    }
    for(index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        failed |= check_case(&cases[index]);
    }
    failed |= check_bmp_string();
    {
        const jer_case_t octet_cases[] = {
            {&asn_DEF_EmptyHexOctets, &empty_octets, "\"\"", "empty OCTET STRING"},
            {&asn_DEF_MixedHexOctets, &mixed_octet_value, "\"00AFFF\"",
             "mixed OCTET STRING"},
            {&asn_DEF_BoundedHexOctets, &bounded_octet_value, "\"00AFFF\"",
             "bounded OCTET STRING"},
        };
        for(index = 0; index < sizeof(octet_cases) / sizeof(octet_cases[0]); index++)
            failed |= check_case(&octet_cases[index]);
    }
    {
        const jer_case_t bit_cases[] = {
            {&asn_DEF_ThreeBits, &fixed_bit_value, "\"A0\"", "fixed three-bit BIT STRING"},
            {&asn_DEF_BoundedBits, &bounded_bit_value,
             "{\"value\":\"A8\",\"length\":5}", "bounded five-bit BIT STRING"},
        };
        for(index = 0; index < sizeof(bit_cases) / sizeof(bit_cases[0]); index++)
            failed |= check_case(&bit_cases[index]);
    }
    if(write_directory) {
        failed |= write_c_vector(&asn_DEF_EmptyHexOctets, &empty_octets,
                                 write_directory, "jer_empty_octets.json");
        failed |= write_c_vector(&asn_DEF_MixedHexOctets, &mixed_octet_value,
                                 write_directory, "jer_mixed_octets.json");
        failed |= write_c_vector(&asn_DEF_BoundedHexOctets, &bounded_octet_value,
                                 write_directory, "jer_bounded_octets.json");
        failed |= write_c_vector(&asn_DEF_ThreeBits, &fixed_bit_value,
                                 write_directory, "jer_three_bits.json");
        failed |= write_c_vector(&asn_DEF_BoundedBits, &bounded_bit_value,
                                 write_directory, "jer_bounded_bits.json");
    }
    if(directory) {
        failed |= check_rust_file(&asn_DEF_Flag, directory, "jer_flag_false.json");
        failed |= check_rust_file(&asn_DEF_Flag, directory, "jer_flag_true.json");
        failed |= check_rust_file(&asn_DEF_Empty, directory, "jer_empty.json");
        failed |= check_rust_file(&asn_DEF_Count, directory, "jer_count_min.json");
        failed |= check_rust_file(&asn_DEF_Count, directory, "jer_count_max.json");
        failed |= check_rust_file(&asn_DEF_Singleton, directory, "jer_singleton.json");
        failed |= check_rust_file(&asn_DEF_SignBounds, directory,
                                  "jer_sign_bounds_min.json");
        failed |= check_rust_file(&asn_DEF_SignBounds, directory,
                                  "jer_sign_bounds_max.json");
    }
    if(octet_directory) {
        failed |= check_rust_file(&asn_DEF_EmptyHexOctets, octet_directory,
                                  "jer_empty_octets.json");
        failed |= check_rust_file(&asn_DEF_MixedHexOctets, octet_directory,
                                  "jer_mixed_octets.json");
        failed |= check_rust_file(&asn_DEF_BoundedHexOctets, octet_directory,
                                  "jer_bounded_octets.json");
    }
    if(bit_directory) {
        failed |= check_rust_file(&asn_DEF_ThreeBits, bit_directory,
                                  "jer_three_bits.json");
        failed |= check_rust_file(&asn_DEF_BoundedBits, bit_directory,
                                  "jer_bounded_bits.json");
    }
    return failed;
}
