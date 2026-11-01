/* Compare generated C BER/DER/CER SEQUENCE bytes with the Rust vectors. */
#include <asn_application.h>
#include <DefaultRecord.h>
#include <EmptyRecord.h>
#include <OptionalRecord.h>
#include <RequiredRecord.h>

#include <stdio.h>
#include <string.h>

/* Test descriptors bind one value to one transfer syntax and exact byte vector. */
typedef struct sequence_vector_s {
    const asn_TYPE_descriptor_t *type; /* Generated C ASN.1 descriptor. */
    const void *value; /* Borrowed generated C value. */
    enum asn_transfer_syntax syntax; /* DER or CER rule under test. */
    const unsigned char *expected; /* Independent Rust conformance bytes. */
    size_t length; /* Exact expected byte count. */
    const char *name; /* Useful failure diagnostic. */
} sequence_vector_t;

/*
 * Purpose: compare one C constructed encoding against an independent vector.
 * Parameters: vector supplies type, value, syntax, and exact expected bytes.
 * Returns zero for a match; one for invalid input, encoder failure, or mismatch.
 * Errors: mismatch information is printed to stderr; no exception is thrown.
 * Original source: generated-code BER/CER regression. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: initial SEQUENCE Rust parity vectors.
 * Example: check_vector(&vectors[0]) checks DER RequiredRecord.
 */
static int
check_vector(const sequence_vector_t *vector) {
    unsigned char actual[32];
    asn_enc_rval_t encoded;

    /* Validate the descriptor before passing the caller-owned pointers to C. */
    if(!vector || !vector->type || !vector->value || !vector->expected
       || vector->length > sizeof(actual)) return 1;

    /* Exercise the generated C encoder with the same rule and bytes as Rust. */
    encoded = asn_encode_to_buffer(NULL, vector->syntax, vector->type,
                                   vector->value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != vector->length
       || memcmp(actual, vector->expected, vector->length) != 0) {
        fprintf(stderr, "C BER/CER SEQUENCE mismatch: %s\n", vector->name);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode one independently specified required-record vector in C.
 * Parameters: syntax selects DER or CER; bytes and length carry one complete TLV.
 * Returns zero when C reports exact consumption and expected field values.
 * Errors: decoder failures, wrong values, or wrong prefix sizes return one.
 * Original source: asn1c generic transfer-syntax decoder.
 * Version/date: 2026-10-31. Author: asn1c maintainers.
 * History: bidirectional record interoperability. Example: check_required_decode(ATS_DER, ...).
 */
static int
check_required_decode(enum asn_transfer_syntax syntax,
                      const unsigned char *bytes, size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    RequiredRecord_t *value;
    int failed;

    /* Reject malformed arguments before invoking the generated decoder. */
    if(!bytes || !length) return 1;
    result = asn_decode(NULL, syntax, &asn_DEF_RequiredRecord, &decoded, bytes, length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != length || !value
        || !value->flag || value->empty != 0 || value->number != 3;
    if(failed) {
        fprintf(stderr, "C record decode mismatch: syntax=%d code=%d consumed=%zu/%zu",
                (int)syntax, (int)result.code, result.consumed, length);
        if(value) fprintf(stderr, " values=%d/%d/%ld", value->flag,
                          value->empty, value->number);
        fputc('\n', stderr);
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RequiredRecord, decoded);
    return failed;
}

/*
 * Purpose: compare required, optional, defaulted, and empty record encodings.
 * Parameters: none. Returns zero when all C bytes match, one on first failure.
 * Errors: generated encoder failure or vector mismatch is reported.
 * Original source: X.690 SEQUENCE framing and generated C codecs.
 * Version/date: 2026-10-31. Author: asn1c maintainers.
 * History: first constructed Rust BER/CER parity test.
 * Example: RequiredRecord DER is compared to its fixed test vector.
 */
int
main(void) {
    static const unsigned char required_der[] = {
        0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03
    };
    static const unsigned char required_cer[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x03, 0x00, 0x00
    };
    static const unsigned char absent_der[] = {0x30, 0x00};
    static const unsigned char absent_cer[] = {0x30, 0x80, 0x00, 0x00};
    static const unsigned char optional_der[] = {
        0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0xff
    };
    static const unsigned char optional_cer[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0xff, 0x00, 0x00
    };
    static const unsigned char default_der[] = {0x30, 0x02, 0x05, 0x00};
    static const unsigned char default_cer[] = {0x30, 0x80, 0x05, 0x00, 0x00, 0x00};
    static const unsigned char nondefault_der[] = {
        0x30, 0x08, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x02
    };
    static const unsigned char nondefault_cer[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00, 0x02, 0x01, 0x02, 0x00, 0x00
    };
    static const unsigned char empty_der[] = {0x30, 0x00};
    static const unsigned char empty_cer[] = {0x30, 0x80, 0x00, 0x00};
    long optional_number = -1;
    long default_number = 2;
    RequiredRecord_t required = {1, 0, 3, {0}};
    OptionalRecord_t absent = {NULL, NULL, NULL, {0}};
    OptionalRecord_t optional = {NULL, NULL, NULL, {0}};
    DefaultRecord_t defaults = {0, 0, NULL, {0}};
    DefaultRecord_t nondefaults = {1, 0, &default_number, {0}};
    EmptyRecord_t empty = {{0}};
    sequence_vector_t vectors[] = {
        {&asn_DEF_RequiredRecord, &required, ATS_DER,
         required_der, sizeof(required_der), "DER required fields"},
        {&asn_DEF_RequiredRecord, &required, ATS_CER,
         required_cer, sizeof(required_cer), "CER required fields"},
        {&asn_DEF_OptionalRecord, &absent, ATS_DER,
         absent_der, sizeof(absent_der), "DER absent OPTIONAL fields"},
        {&asn_DEF_OptionalRecord, &absent, ATS_CER,
         absent_cer, sizeof(absent_cer), "CER absent OPTIONAL fields"},
        {&asn_DEF_OptionalRecord, &optional, ATS_DER,
         optional_der, sizeof(optional_der), "DER present OPTIONAL fields"},
        {&asn_DEF_OptionalRecord, &optional, ATS_CER,
         optional_cer, sizeof(optional_cer), "CER present OPTIONAL fields"},
        {&asn_DEF_DefaultRecord, &defaults, ATS_DER,
         default_der, sizeof(default_der), "DER DEFAULT omission"},
        {&asn_DEF_DefaultRecord, &defaults, ATS_CER,
         default_cer, sizeof(default_cer), "CER DEFAULT omission"},
        {&asn_DEF_DefaultRecord, &nondefaults, ATS_DER,
         nondefault_der, sizeof(nondefault_der), "DER nondefault values"},
        {&asn_DEF_DefaultRecord, &nondefaults, ATS_CER,
         nondefault_cer, sizeof(nondefault_cer), "CER nondefault values"},
        {&asn_DEF_EmptyRecord, &empty, ATS_DER,
         empty_der, sizeof(empty_der), "DER empty record"},
        {&asn_DEF_EmptyRecord, &empty, ATS_CER,
         empty_cer, sizeof(empty_cer), "CER empty record"},
    };
    size_t index;

    /* Populate the optional and nondefault scalar pointers used by C layouts. */
    optional.flag = &(BOOLEAN_t){1};
    optional.empty = &(NULL_t){0};
    optional.number = &optional_number;

    /* Keep each comparison scoped to one exact schema-value/rule pair. */
    for(index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        if(check_vector(&vectors[index])) return 1;
    }
    if(check_required_decode(ATS_DER, required_der, sizeof(required_der))) return 1;
    if(check_required_decode(ATS_CER, required_cer, sizeof(required_cer))) return 1;
    return 0;
}
