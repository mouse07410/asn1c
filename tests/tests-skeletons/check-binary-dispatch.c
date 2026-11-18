/*
 * Purpose: Exercise generic binary transfer-syntax dispatch against explicit
 * codec entrypoints, independent wire fixtures, and bounded hostile inputs.
 * Original source: New test for the asn1c skeleton regression suite.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: Built-in BOOLEAN and OCTET STRING descriptors plus fixed byte vectors.
 * Returns: EXIT_SUCCESS if every dispatch and rejection assertion passes.
 * Exceptions: No C++ exceptions; failed assertions exit with EXIT_FAILURE.
 * Responsible party: asn1c maintainers.
 * History: Added generic binary-format and CER decoder dispatch coverage.
 * Example: Run `make -C tests/tests-skeletons check-binary-dispatch`.
 */
#include <asn_application.h>
#include <BOOLEAN.h>
#include <OCTET_STRING.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <ber_decoder.h>
#include <cbor_decoder.h>
#include <cbor_encoder.h>
#include <cer_decoder.h>
#include <cer_encoder.h>
#include <der_encoder.h>
#include <errno.h>
#include <oer_decoder.h>
#include <oer_encoder.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

/* Golden encodings for TRUE and FALSE, fixed independently of dispatch. */
static const uint8_t bool_true_ber[] = {0x01, 0x01, 0xff};
static const uint8_t bool_false_ber[] = {0x01, 0x01, 0x00};
static const uint8_t bool_true_oer[] = {0xff};
static const uint8_t bool_false_oer[] = {0x00};
static const uint8_t bool_true_per[] = {0x80};
static const uint8_t bool_false_per[] = {0x00};
static const uint8_t bool_true_cbor[] = {0xf5};
static const uint8_t bool_false_cbor[] = {0xf4};

/* Fixed-capacity callback output prevents the test from growing unboundedly. */
struct capture_buffer {
    uint8_t *data;     /* Caller-owned output memory. */
    size_t capacity;   /* Maximum number of bytes the callback may write. */
    size_t length;     /* State variable: number of bytes successfully captured. */
};

/* One generic syntax/value pair and its independent encoded fixture. */
struct binary_case {
    enum asn_transfer_syntax syntax; /* Generic selector under test. */
    const char *name;                /* Printable selector and value label. */
    BOOLEAN_t value;                 /* Semantic BOOLEAN expected after decode. */
    const uint8_t *golden;           /* Reviewed wire fixture for this mode. */
    size_t golden_size;              /* Exact fixture length in bytes. */
};

/*
 * Purpose: Fail the executable with the current test and a concrete reason.
 * Original source: New test helper.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: `where` names the check; `detail` explains the failed condition.
 * Returns: Does not return; exits with EXIT_FAILURE.
 * Exceptions: No C++ exceptions; uses fprintf and exit.
 * Responsible party: asn1c maintainers.
 * History: Added with the generic dispatch regression.
 * Example: require_condition(result == RC_OK, "decode", "expected RC_OK").
 */
static void
require_condition(int condition, const char *where, const char *detail) {
    if(!condition) {
        fprintf(stderr, "FAIL: %s: %s\n", where, detail);
        exit(EXIT_FAILURE);
    }
}

/*
 * Purpose: Capture explicit CBOR encoder output into a fixed test buffer.
 * Original source: New test helper.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: `data` and `size` describe emitted bytes; `key` is a capture_buffer.
 * Returns: Zero when copied; negative when arguments or capacity are invalid.
 * Exceptions: No C++ exceptions; no allocation is performed.
 * Responsible party: asn1c maintainers.
 * History: Added for parity checks against `asn_encode_to_buffer`.
 * Example: Pass this callback to `cbor_encode` with a capture_buffer key.
 */
static int
capture_output(const void *data, size_t size, void *key) {
    struct capture_buffer *capture = (struct capture_buffer *)key;

    if(!capture) return -1;
    if(size == 0) return 0;
    if(!data || !capture->data) return -1;
    if(capture->length > capture->capacity
       || size > capture->capacity - capture->length) {
        return -1;
    }
    memcpy(capture->data + capture->length, data, size);
    capture->length += size;
    return 0;
}

/*
 * Purpose: Encode BOOLEAN through the explicit codec selected by `syntax`.
 * Original source: New test helper using public skeleton codec entrypoints.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: `syntax` selects a binary codec; `value` is the BOOLEAN to encode;
 *         `buffer` and `size` bound the resulting bytes.
 * Returns: Encoder result; PER results count meaningful bits.
 * Exceptions: No C++ exceptions; invalid selectors return an error result.
 * Responsible party: asn1c maintainers.
 * History: Added to compare generic and explicit dispatch behavior.
 * Example: `encode_explicit(ATS_DER, &truth, bytes, sizeof(bytes))`.
 */
static asn_enc_rval_t
encode_explicit(enum asn_transfer_syntax syntax, const BOOLEAN_t *value,
                uint8_t *buffer, size_t size) {
    asn_enc_rval_t result = {-1, 0, 0};

    switch(syntax) {
    case ATS_BER:
    case ATS_DER:
        return der_encode_to_buffer(&asn_DEF_BOOLEAN, value, buffer, size);
    case ATS_CER:
        return cer_encode_to_buffer(0, &asn_DEF_BOOLEAN, value, buffer, size);
    case ATS_BASIC_OER:
    case ATS_CANONICAL_OER:
        return oer_encode_to_buffer(&asn_DEF_BOOLEAN, 0, value, buffer, size);
    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER:
        return uper_encode_to_buffer(&asn_DEF_BOOLEAN, 0, value, buffer, size);
    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER:
        return aper_encode_to_buffer(&asn_DEF_BOOLEAN, 0, value, buffer, size);
    case ATS_CBOR: {
        struct capture_buffer capture;

        capture.data = buffer;
        capture.capacity = size;
        capture.length = 0;
        result = cbor_encode(&asn_DEF_BOOLEAN, value, capture_output, &capture);
        if(result.encoded >= 0 && (size_t)result.encoded != capture.length) {
            result.encoded = -1;
        }
        return result;
    }
    default:
        result.failed_type = &asn_DEF_BOOLEAN;
        result.structure_ptr = value;
        return result;
    }
}

/*
 * Purpose: Decode BOOLEAN through the explicit codec selected by `syntax`.
 * Original source: New test helper using public skeleton codec entrypoints.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: `syntax` selects a decoder; `buffer` and `size` are the fixture.
 *         `decoded` receives the allocated BOOLEAN value.
 * Returns: Decoder result with byte or bit consumption as defined by codec.
 * Exceptions: No C++ exceptions; decoder allocation failure returns RC_FAIL.
 * Responsible party: asn1c maintainers.
 * History: Added to compare generic and explicit dispatch behavior.
 * Example: `decode_explicit(ATS_BASIC_OER, wire, len, (void **)&value)`.
 */
static asn_dec_rval_t
decode_explicit(enum asn_transfer_syntax syntax, const void *buffer,
                size_t size, void **decoded) {
    switch(syntax) {
    case ATS_BER:
    case ATS_DER:
        return ber_decode(0, &asn_DEF_BOOLEAN, decoded, buffer, size);
    case ATS_CER:
        return cer_decode(0, &asn_DEF_BOOLEAN, decoded, buffer, size);
    case ATS_BASIC_OER:
    case ATS_CANONICAL_OER:
        return oer_decode(0, &asn_DEF_BOOLEAN, decoded, buffer, size);
    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER:
        return uper_decode_complete(0, &asn_DEF_BOOLEAN, decoded, buffer, size);
    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER:
        return aper_decode_complete(0, &asn_DEF_BOOLEAN, decoded, buffer, size);
    case ATS_CBOR:
        return cbor_decode(0, &asn_DEF_BOOLEAN, decoded, buffer, size);
    default: {
        asn_dec_rval_t result = {RC_FAIL, 0};
        return result;
    }
    }
}

/*
 * Purpose: Check generic encode/decode, explicit codec parity, and golden bytes.
 * Original source: New binary dispatch regression.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: `test` supplies syntax, semantic value, and exact fixture bytes.
 * Returns: No value; any mismatch exits the test executable.
 * Exceptions: No C++ exceptions; decoder allocations are freed on success.
 * Responsible party: asn1c maintainers.
 * History: Added coverage for all generic binary selectors.
 * Example: Invoke once for each `binary_case` in `test_binary_dispatch`.
 */
static void
check_binary_case(const struct binary_case *test) {
    uint8_t generic_bytes[8] = {0};
    uint8_t explicit_bytes[8] = {0};
    BOOLEAN_t *generic_value = 0;
    BOOLEAN_t *explicit_value = 0;
    asn_enc_rval_t generic_encoded;
    asn_enc_rval_t explicit_encoded;
    asn_dec_rval_t generic_decoded;
    asn_dec_rval_t explicit_decoded;

    generic_encoded = asn_encode_to_buffer(0, test->syntax, &asn_DEF_BOOLEAN,
                                           &test->value, generic_bytes,
                                           sizeof(generic_bytes));
    require_condition(generic_encoded.encoded == (ssize_t)test->golden_size,
                      test->name, "generic encoded size differs from fixture");
    require_condition(memcmp(generic_bytes, test->golden, test->golden_size) == 0,
                      test->name, "generic bytes differ from golden fixture");

    explicit_encoded = encode_explicit(test->syntax, &test->value,
                                       explicit_bytes, sizeof(explicit_bytes));
    require_condition(explicit_encoded.encoded >= 0, test->name,
                      "explicit encoder failed");
    require_condition(memcmp(explicit_bytes, test->golden, test->golden_size) == 0,
                      test->name, "explicit bytes differ from golden fixture");
    require_condition(memcmp(generic_bytes, explicit_bytes, test->golden_size) == 0,
                      test->name, "generic and explicit bytes differ");
    if(test->syntax == ATS_UNALIGNED_BASIC_PER
       || test->syntax == ATS_UNALIGNED_CANONICAL_PER
       || test->syntax == ATS_ALIGNED_BASIC_PER
       || test->syntax == ATS_ALIGNED_CANONICAL_PER) {
        require_condition(explicit_encoded.encoded == 1, test->name,
                          "explicit PER encoder must report one meaningful bit");
    } else {
        require_condition(explicit_encoded.encoded == (ssize_t)test->golden_size,
                          test->name, "explicit encoder size differs from fixture");
    }

    generic_decoded = asn_decode(0, test->syntax, &asn_DEF_BOOLEAN,
                                 (void **)&generic_value, test->golden,
                                 test->golden_size);
    explicit_decoded = decode_explicit(test->syntax, test->golden,
                                       test->golden_size,
                                       (void **)&explicit_value);
    require_condition(generic_decoded.code == RC_OK && generic_value,
                      test->name, "generic decoder rejected golden fixture");
    require_condition(explicit_decoded.code == RC_OK && explicit_value,
                      test->name, "explicit decoder rejected golden fixture");
    require_condition(!!*generic_value == !!test->value
                      && !!*explicit_value == !!test->value,
                      test->name, "decoded BOOLEAN differs from expected value");
    require_condition(generic_decoded.consumed == explicit_decoded.consumed,
                      test->name, "generic and explicit consumption differs");

    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, generic_value);
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, explicit_value);
}

/*
 * Purpose: Exercise BER, DER, CER, both OER/PER variants, and CBOR dispatch.
 * Original source: New binary dispatch regression.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: Independent TRUE/FALSE golden vectors declared above.
 * Returns: No value; any mismatch exits the test executable.
 * Exceptions: No C++ exceptions; test failures exit with EXIT_FAILURE.
 * Responsible party: asn1c maintainers.
 * History: Added to prevent generic selector regressions.
 * Example: Called by `main` before malformed-input checks.
 */
static void
test_binary_dispatch(void) {
    static const struct binary_case cases[] = {
        {ATS_BER, "BER TRUE", 1, bool_true_ber, sizeof(bool_true_ber)},
        {ATS_DER, "DER TRUE", 1, bool_true_ber, sizeof(bool_true_ber)},
        {ATS_CER, "CER TRUE", 1, bool_true_ber, sizeof(bool_true_ber)},
        {ATS_BASIC_OER, "basic OER TRUE", 1, bool_true_oer, sizeof(bool_true_oer)},
        {ATS_CANONICAL_OER, "canonical OER TRUE", 1, bool_true_oer,
         sizeof(bool_true_oer)},
        {ATS_UNALIGNED_BASIC_PER, "basic UPER TRUE", 1, bool_true_per,
         sizeof(bool_true_per)},
        {ATS_UNALIGNED_CANONICAL_PER, "canonical UPER TRUE", 1, bool_true_per,
         sizeof(bool_true_per)},
        {ATS_ALIGNED_BASIC_PER, "basic APER TRUE", 1, bool_true_per,
         sizeof(bool_true_per)},
        {ATS_ALIGNED_CANONICAL_PER, "canonical APER TRUE", 1, bool_true_per,
         sizeof(bool_true_per)},
        {ATS_CBOR, "CBOR TRUE", 1, bool_true_cbor, sizeof(bool_true_cbor)},
        {ATS_BER, "BER FALSE", 0, bool_false_ber, sizeof(bool_false_ber)},
        {ATS_DER, "DER FALSE", 0, bool_false_ber, sizeof(bool_false_ber)},
        {ATS_CER, "CER FALSE", 0, bool_false_ber, sizeof(bool_false_ber)},
        {ATS_BASIC_OER, "basic OER FALSE", 0, bool_false_oer,
         sizeof(bool_false_oer)},
        {ATS_CANONICAL_OER, "canonical OER FALSE", 0, bool_false_oer,
         sizeof(bool_false_oer)},
        {ATS_UNALIGNED_BASIC_PER, "basic UPER FALSE", 0, bool_false_per,
         sizeof(bool_false_per)},
        {ATS_UNALIGNED_CANONICAL_PER, "canonical UPER FALSE", 0,
         bool_false_per, sizeof(bool_false_per)},
        {ATS_ALIGNED_BASIC_PER, "basic APER FALSE", 0, bool_false_per,
         sizeof(bool_false_per)},
        {ATS_ALIGNED_CANONICAL_PER, "canonical APER FALSE", 0,
         bool_false_per, sizeof(bool_false_per)},
        {ATS_CBOR, "CBOR FALSE", 0, bool_false_cbor, sizeof(bool_false_cbor)}
    };
    size_t i;

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_binary_case(&cases[i]);
    }
}

/*
 * Purpose: Verify generic CER decode is strict and rejects BER-only forms.
 * Original source: New regression for the ATS_CER dispatcher.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: CER BOOLEAN, BER-only noncanonical BOOLEAN, truncation, and bad tag.
 * Returns: No value; any mismatch exits the test executable.
 * Exceptions: No C++ exceptions; allocated decoded values are freed.
 * Responsible party: asn1c maintainers.
 * History: Added to expose the declared CER decode path; updated when ATS_CER
 *          moved from BER delegation to strict cer_decode().
 * Example: Called by `main`; encode dispatch also checks canonical TRUE bytes.
 */
static void
test_cer_boolean_dispatch(void) {
    static const uint8_t cer_true[] = {0x01, 0x01, 0xff};
    static const uint8_t ber_noncanonical_true[] = {0x01, 0x01, 0x01};
    static const uint8_t wrong_tag[] = {0x02, 0x01, 0x01};
    BOOLEAN_t *generic_value = 0;
    BOOLEAN_t *explicit_value = 0;
    asn_dec_rval_t generic_result;
    asn_dec_rval_t explicit_result;
    asn_enc_rval_t encode_result;
    uint8_t output[8];

    generic_result = asn_decode(0, ATS_CER, &asn_DEF_BOOLEAN,
                                (void **)&generic_value, cer_true,
                                sizeof(cer_true));
    explicit_result = ber_decode(0, &asn_DEF_BOOLEAN,
                                 (void **)&explicit_value, cer_true,
                                 sizeof(cer_true));
    require_condition(generic_result.code == RC_OK && generic_value,
                      "CER BOOLEAN", "generic CER decoder rejected valid input");
    require_condition(explicit_result.code == RC_OK && explicit_value,
                      "CER BOOLEAN", "explicit BER decoder rejected CER input");
    require_condition(!!*generic_value && !!*explicit_value,
                      "CER BOOLEAN", "decoded TRUE value differs");
    require_condition(generic_result.consumed == explicit_result.consumed,
                      "CER BOOLEAN", "generic and BER consumption differs");
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, generic_value);
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, explicit_value);
    generic_value = 0;
    explicit_value = 0;

    /* This BER-valid form is not CER-canonical, so strict CER must reject it. */
    generic_result = asn_decode(0, ATS_CER, &asn_DEF_BOOLEAN,
                                (void **)&generic_value,
                                ber_noncanonical_true,
                                sizeof(ber_noncanonical_true));
    explicit_result = ber_decode(0, &asn_DEF_BOOLEAN,
                                 (void **)&explicit_value,
                                 ber_noncanonical_true,
                                 sizeof(ber_noncanonical_true));
    require_condition(generic_result.code == RC_FAIL
                      && generic_result.consumed == 0 && generic_value == 0,
                      "CER strictness", "generic CER accepted BER-only TRUE");
    require_condition(explicit_result.code == RC_OK && explicit_value
                      && !!*explicit_value,
                      "CER strictness", "BER decoder rejected BER-only TRUE");
    ASN_STRUCT_FREE(asn_DEF_BOOLEAN, explicit_value);

    generic_value = 0;
    generic_result = asn_decode(0, ATS_CER, &asn_DEF_BOOLEAN,
                                (void **)&generic_value, cer_true,
                                sizeof(cer_true) - 1);
    explicit_value = 0;
    explicit_result = ber_decode(0, &asn_DEF_BOOLEAN,
                                 (void **)&explicit_value, cer_true,
                                 sizeof(cer_true) - 1);
    require_condition(generic_result.code != RC_OK
                      && generic_result.code == explicit_result.code
                      && generic_result.consumed == 0 && generic_value == 0,
                      "CER truncation", "truncated BOOLEAN must fail safely");
    if(generic_value) ASN_STRUCT_FREE(asn_DEF_BOOLEAN, generic_value);
    if(explicit_value) ASN_STRUCT_FREE(asn_DEF_BOOLEAN, explicit_value);

    generic_value = 0;
    generic_result = asn_decode(0, ATS_CER, &asn_DEF_BOOLEAN,
                                (void **)&generic_value, wrong_tag,
                                sizeof(wrong_tag));
    explicit_value = 0;
    explicit_result = ber_decode(0, &asn_DEF_BOOLEAN,
                                 (void **)&explicit_value, wrong_tag,
                                 sizeof(wrong_tag));
    require_condition(generic_result.code == RC_FAIL
                      && generic_result.code == explicit_result.code
                      && generic_result.consumed == 0 && generic_value == 0,
                      "CER malformed tag", "wrong BOOLEAN tag must fail");
    if(generic_value) ASN_STRUCT_FREE(asn_DEF_BOOLEAN, generic_value);
    if(explicit_value) ASN_STRUCT_FREE(asn_DEF_BOOLEAN, explicit_value);

    errno = 0;
    encode_result = asn_encode_to_buffer(0, ATS_CER, &asn_DEF_BOOLEAN,
                                         &(BOOLEAN_t){1}, output,
                                         sizeof(output));
    require_condition(encode_result.encoded == (ssize_t)sizeof(cer_true)
                      && memcmp(output, cer_true, sizeof(cer_true)) == 0,
                      "CER encode", "CER TRUE must use canonical ff contents");
}

/*
 * Purpose: Check CER constructed OCTET STRING fragments and hostile truncation.
 * Original source: New regression for generic ATS_CER dispatch.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: A bounded 1001-octet CER string with 1000-octet first fragment.
 * Returns: No value; any mismatch exits the test executable.
 * Exceptions: No C++ exceptions; allocations are checked and freed.
 * Responsible party: asn1c maintainers.
 * History: Added for indefinite-length and fragment-boundary coverage.
 * Example: Called by `main` after primitive CER vectors.
 */
static void
test_cer_constructed_octets(void) {
    const size_t payload_size = 1001;
    const size_t input_size = 1011;
    uint8_t *wire = calloc(input_size, 1);
    size_t offset = 0; /* State variable: next fixture byte to write. */
    OCTET_STRING_t *generic_value = 0;
    OCTET_STRING_t *explicit_value = 0;
    asn_dec_rval_t generic_result;
    asn_dec_rval_t explicit_result;
    asn_codec_ctx_t bounded_context;

    require_condition(wire != 0, "CER constructed allocation", "calloc failed");

    /* Outer constructed value is indefinite; the first primitive fragment is
     * exactly 1000 octets and the final fragment contains the remaining byte.
     */
    wire[offset++] = 0x24;
    wire[offset++] = 0x80;
    wire[offset++] = 0x04;
    wire[offset++] = 0x82;
    wire[offset++] = 0x03;
    wire[offset++] = 0xe8;
    memset(wire + offset, 'A', 1000);
    offset += 1000;
    wire[offset++] = 0x04;
    wire[offset++] = 0x01;
    wire[offset++] = 'Z';
    wire[offset++] = 0x00;
    wire[offset++] = 0x00;
    require_condition(offset == input_size, "CER constructed fixture",
                      "fixture size calculation is inconsistent");

    generic_result = asn_decode(0, ATS_CER, &asn_DEF_OCTET_STRING,
                                (void **)&generic_value, wire, input_size);
    explicit_result = ber_decode(0, &asn_DEF_OCTET_STRING,
                                 (void **)&explicit_value, wire, input_size);
    require_condition(generic_result.code == RC_OK && generic_value,
                      "CER constructed", "generic CER decoder rejected fragments");
    require_condition(explicit_result.code == RC_OK && explicit_value,
                      "CER constructed", "explicit BER decoder rejected fragments");
    require_condition(generic_result.consumed == input_size
                      && explicit_result.consumed == input_size,
                      "CER constructed", "decoder did not consume full value");
    require_condition((size_t)generic_value->size == payload_size
                      && (size_t)explicit_value->size == payload_size,
                      "CER constructed", "decoded payload length differs");
    require_condition(memcmp(generic_value->buf, explicit_value->buf,
                             payload_size) == 0
                      && generic_value->buf[0] == 'A'
                      && generic_value->buf[payload_size - 1] == 'Z',
                      "CER constructed", "decoded fragment bytes differ");
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, generic_value);
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, explicit_value);
    generic_value = 0;
    explicit_value = 0;

    /* One missing EOC octet must not be reported as a complete value. */
    generic_result = asn_decode(0, ATS_CER, &asn_DEF_OCTET_STRING,
                                (void **)&generic_value, wire, input_size - 1);
    explicit_result = ber_decode(0, &asn_DEF_OCTET_STRING,
                                 (void **)&explicit_value, wire, input_size - 1);
    require_condition(generic_result.code != RC_OK
                      && generic_result.code == explicit_result.code
                      && generic_result.consumed == 0 && generic_value == 0
                      && explicit_result.consumed <= input_size - 1,
                      "CER EOC truncation", "truncated value must not over-consume");
    if(generic_value) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, generic_value);
    if(explicit_value) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, explicit_value);
    generic_value = 0;
    explicit_value = 0;

    /* Advertise a huge payload with only its header present; this must remain
     * a bounded need-more-input result rather than attempting a huge copy.
     */
    {
        static const uint8_t huge_length[] = {
            0x04, 0x84, 0x7f, 0xff, 0xff, 0xff
        };

        memset(&bounded_context, 0, sizeof(bounded_context));
        bounded_context.max_stack_size = 1024;
        generic_result = asn_decode(&bounded_context, ATS_CER,
                                    &asn_DEF_OCTET_STRING,
                                    (void **)&generic_value, huge_length,
                                    sizeof(huge_length));
        explicit_result = ber_decode(&bounded_context, &asn_DEF_OCTET_STRING,
                                     (void **)&explicit_value, huge_length,
                                     sizeof(huge_length));
        require_condition(generic_result.code != RC_OK
                          && generic_result.code == explicit_result.code
                          && generic_result.consumed == 0
                          && generic_value == 0
                          && explicit_result.consumed <= sizeof(huge_length),
                          "CER huge length", "header-only input must stay bounded");
        if(generic_value) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, generic_value);
        if(explicit_value) ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, explicit_value);
    }

    free(wire);
}

/*
 * Purpose: Verify generic dispatcher parameter and unsupported-selector errors.
 * Original source: New binary dispatch regression.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: Invalid selector, missing descriptor/value/output, and null buffer.
 * Returns: No value; any mismatch exits the test executable.
 * Exceptions: No C++ exceptions; decoder outputs are freed if unexpectedly set.
 * Responsible party: asn1c maintainers.
 * History: Added malformed-call coverage for generic APIs.
 * Example: Called by `main` after valid binary and CER vectors.
 */
static void
test_invalid_dispatch_arguments(void) {
    BOOLEAN_t value = 1;
    BOOLEAN_t *decoded = 0;
    uint8_t output[8];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    const uint8_t valid_der[] = {0x01, 0x01, 0xff};

    errno = 0;
    encoded = asn_encode_to_buffer(0, ATS_INVALID, &asn_DEF_BOOLEAN, &value,
                                   output, sizeof(output));
    require_condition(encoded.encoded == -1 && errno == ENOENT,
                      "invalid encode selector", "expected ENOENT");

    result = asn_decode(0, ATS_INVALID, &asn_DEF_BOOLEAN,
                        (void **)&decoded, valid_der, sizeof(valid_der));
    require_condition(result.code == RC_FAIL && errno == ENOENT,
                      "invalid decode selector", "expected RC_FAIL and ENOENT");

    errno = 0;
    encoded = asn_encode_to_buffer(0, ATS_BER, 0, &value,
                                   output, sizeof(output));
    require_condition(encoded.encoded == -1 && errno == EINVAL,
                      "null descriptor", "encode must reject a null descriptor");

    errno = 0;
    encoded = asn_encode_to_buffer(0, ATS_BER, &asn_DEF_BOOLEAN, 0,
                                   output, sizeof(output));
    require_condition(encoded.encoded == -1 && errno == EINVAL,
                      "null value", "encode must reject a null value");

    errno = 0;
    encoded = asn_encode_to_buffer(0, ATS_BER, &asn_DEF_BOOLEAN, &value, 0, 1);
    require_condition(encoded.encoded == -1 && errno == EINVAL,
                      "null output buffer", "nonempty output needs a buffer");

    result = asn_decode(0, ATS_BER, 0, (void **)&decoded,
                        valid_der, sizeof(valid_der));
    require_condition(result.code == RC_FAIL,
                      "null decode descriptor", "decode must reject null descriptor");

    result = asn_decode(0, ATS_BER, &asn_DEF_BOOLEAN, 0,
                        valid_der, sizeof(valid_der));
    require_condition(result.code == RC_FAIL,
                      "null output pointer", "decode must reject null output pointer");

    result = asn_decode(0, ATS_BER, &asn_DEF_BOOLEAN, (void **)&decoded, 0, 1);
    require_condition(result.code == RC_FAIL,
                      "null input buffer", "nonempty input needs a buffer");

    /* Exercise the BER entry point directly, including absent operations. */
    {
        asn_TYPE_descriptor_t missing_ops = asn_DEF_BOOLEAN;
        asn_TYPE_operation_t missing_decoder = *asn_DEF_BOOLEAN.op;
        missing_ops.op = 0;
        result = ber_decode(0, 0, (void **)&decoded, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "BER null descriptor", "must fail without consuming input");
        result = ber_decode(0, &missing_ops, (void **)&decoded, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "BER missing operations", "must fail without consuming input");
        missing_decoder.ber_decoder = 0;
        missing_ops.op = &missing_decoder;
        result = ber_decode(0, &missing_ops, (void **)&decoded, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "BER missing decoder", "must fail without consuming input");
        result = ber_decode(0, &asn_DEF_BOOLEAN, 0, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "BER null output", "must fail without consuming input");
        result = ber_decode(0, &asn_DEF_BOOLEAN, (void **)&decoded, 0, 1);
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "BER null input", "must fail without consuming input");

        missing_ops.op = 0;
        result = oer_decode(0, 0, (void **)&decoded, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "OER null descriptor", "must fail without consuming input");
        result = oer_decode(0, &missing_ops, (void **)&decoded, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "OER missing operations", "must fail without consuming input");
        missing_decoder.oer_decoder = 0;
        missing_ops.op = &missing_decoder;
        result = oer_decode(0, &missing_ops, (void **)&decoded, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "OER missing decoder", "must fail without consuming input");
        result = oer_decode(0, &asn_DEF_BOOLEAN, 0, valid_der, sizeof(valid_der));
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "OER null output", "must fail without consuming input");
        result = oer_decode(0, &asn_DEF_BOOLEAN, (void **)&decoded, 0, 1);
        require_condition(result.code == RC_FAIL && result.consumed == 0,
                          "OER null input", "must fail without consuming input");
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_BOOLEAN, decoded);
}

/*
 * Purpose: Run all binary syntax, CER, malformed-input, and argument checks.
 * Original source: New test program entrypoint.
 * Version/date: 1.0, 2026-10-11.
 * Inputs: None; test fixtures are compiled into this executable.
 * Returns: EXIT_SUCCESS when all tests pass; helper failures exit early.
 * Exceptions: No C++ exceptions; allocation failures are reported as failures.
 * Responsible party: asn1c maintainers.
 * History: Added as `check-binary-dispatch`.
 * Example: Execute `./check-binary-dispatch` in the skeleton test directory.
 */
int
main(void) {
    test_binary_dispatch();
    test_cer_boolean_dispatch();
    test_cer_constructed_octets();
    test_invalid_dispatch_arguments();
    puts("PASS: generic binary-format dispatch");
    return EXIT_SUCCESS;
}
