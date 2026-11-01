/* Compare generated C BER/DER/CER SEQUENCE bytes with the Rust vectors. */
#include <asn_application.h>
#include <BIT_STRING.h>
#include <ENUMERATED.h>
#include <DefaultRecord.h>
#include <ExtendedRecord.h>
#include <EmptyRecord.h>
#include <EnumeratedRecord.h>
#include <OctetBoundaryRecord.h>
#include <BitBoundaryRecord.h>
#include <OptionalRecord.h>
#include <RequiredRecord.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
 * Purpose: decode one mixed record and inspect its enum/string/integer values.
 * Parameters: syntax selects DER/CER; bytes and length carry the record TLV.
 * Returns zero for exact consumption and expected fields, otherwise one.
 * Errors: malformed data, failed conversions, or mismatched values return one.
 * Original source: generated C transfer-syntax decoder. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: bidirectional third-wave record parity.
 * Example: check_extended_decode(ATS_DER, vector, sizeof(vector)).
 */
static int
check_extended_decode(enum asn_transfer_syntax syntax,
                      const unsigned char *bytes, size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    ExtendedRecord_t *value;
    int64_t state = 0;
    int failed;

    if(!bytes || !length) return 1;
    result = asn_decode(NULL, syntax, &asn_DEF_ExtendedRecord, &decoded, bytes, length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != length || !value
        || !value->state_value || asn_INTEGER2int64(value->state_value, &state) != 0
        || state != 3 || value->number != -2 || value->octets.size != 2
        || !value->octets.buf || memcmp(value->octets.buf, "AB", 2) != 0 || !value->bits
        || value->bits->size != 1 || value->bits->bits_unused != 5
        || !value->bits->buf || value->bits->buf[0] != 0xa0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExtendedRecord, decoded);
    return failed;
}

/*
 * Purpose: confirm the generated C BER decoder flattens constructed strings.
 * Parameters: none. Returns zero for full consumption and expected fields.
 * Errors: decoder errors or unexpected values return one; no exception.
 * Original source: BER constructed string rules. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: constructed-child interoperability.
 * Example: OCTET fragments and a two-fragment nine-bit BIT STRING decode.
 */
static int
check_constructed_octets_ber(void) {
    static const unsigned char wire[] = {
        0x30, 0x80, 0x24, 0x80, 0x04, 0x01, 0x41, 0, 0,
        0x02, 0x01, 0, 0, 0
    };
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_ExtendedRecord,
                                       &decoded, wire, sizeof(wire));
    ExtendedRecord_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != sizeof(wire) || !value
        || value->octets.size != 1 || !value->octets.buf || value->octets.buf[0] != 0x41
        || value->number != 0;

    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExtendedRecord, decoded);
    if(failed) return 1;
    decoded = NULL;
    {
        static const unsigned char bit_wire[] = {
            0x30, 0x80, 0x04, 0x01, 0x41, 0x23, 0x80, 0x03, 0x02, 0, 0x80,
            0x03, 0x02, 7, 0x80, 0, 0, 0x02, 0x01, 0, 0, 0
        };
        result = asn_decode(NULL, ATS_BER, &asn_DEF_ExtendedRecord, &decoded,
                            bit_wire, sizeof(bit_wire));
        value = decoded;
        failed = result.code != RC_OK || result.consumed != sizeof(bit_wire) || !value
            || !value->bits || value->bits->size != 2 || !value->bits->buf
            || value->bits->bits_unused != 7 || value->bits->buf[0] != 0x80
            || value->bits->buf[1] != 0x80 || value->number != 0;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_ExtendedRecord, decoded);
    }
    return failed;
}

/* Append the minimal short, one-octet, or two-octet definite length form. */
/*
 * Purpose: append a minimal definite length to a bounded expected vector.
 * Parameters: output is writable storage; length is the TLV payload size.
 * Returns the encoded length-octet count. Errors: caller bounds it to 65535.
 * Original source: X.690 length determinant. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: third-wave C/Rust vectors.
 * Example: append_length(out, 128) writes `81 80`.
 */
static size_t
append_length(unsigned char *output, size_t length) {
    if(length < 128) {
        output[0] = (unsigned char)length;
        return 1;
    }
    if(length <= 255) {
        output[0] = 0x81;
        output[1] = (unsigned char)length;
        return 2;
    }
    output[0] = 0x82;
    output[1] = (unsigned char)(length >> 8);
    output[2] = (unsigned char)length;
    return 3;
}

/*
 * Purpose: append one primitive TLV to the expected buffer.
 * Parameters: output/offset identify storage; tag/payload/length define a TLV.
 * Returns the first free offset. Errors: caller ensures sufficient capacity.
 * Original source: X.690 primitive TLV. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: independent string boundary vectors.
 * Example: append_primitive(out, 0, 4, data, 3) appends three OCTET bytes.
 */
static size_t
append_primitive(unsigned char *output, size_t offset, unsigned char tag,
                 const unsigned char *payload, size_t length) {
    size_t length_size;
    output[offset++] = tag;
    length_size = append_length(output + offset, length);
    offset += length_size;
    if(length) memcpy(output + offset, payload, length);
    return offset + length;
}

/*
 * Purpose: build an independent one-field OCTET STRING SEQUENCE vector.
 * Parameters: output receives bytes; payload/length define the value; syntax
 * selects DER or CER. Returns the complete encoded size. Errors: test caller
 * provides buffers large enough for values through 1001 octets.
 * Original source: X.690 record/string framing. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: fragmentation boundary checks.
 * Example: expected_octet_record(out, data, 1001, ATS_CER).
 */
static size_t
expected_octet_record(unsigned char *output, const unsigned char *payload,
                      size_t length, enum asn_transfer_syntax syntax) {
    size_t offset = 0;
    if(syntax == ATS_CER) {
        output[offset++] = 0x30;
        output[offset++] = 0x80;
        if(length > 1000) {
            size_t position = 0;
            output[offset++] = 0x24;
            output[offset++] = 0x80;
            while(position < length) {
                size_t fragment = length - position;
                if(fragment > 1000) fragment = 1000;
                offset = append_primitive(output, offset, 4,
                                          payload + position, fragment);
                position += fragment;
            }
            output[offset++] = 0;
            output[offset++] = 0;
        } else {
            offset = append_primitive(output, offset, 4, payload, length);
        }
        output[offset++] = 0;
        output[offset++] = 0;
        return offset;
    }
    {
        unsigned char child[1100];
        size_t child_length = append_primitive(child, 0, 4, payload, length);
        output[offset++] = 0x30;
        offset += append_length(output + offset, child_length);
        memcpy(output + offset, child, child_length);
        return offset + child_length;
    }
}

/*
 * Purpose: compare C DER/CER OCTET boundary encodings and decode vectors.
 * Parameters: length is a test size; syntax is ATS_DER or ATS_CER.
 * Returns zero for exact bytes/consumption/value, otherwise one.
 * Errors: encoder/decoder failures and mismatches return one; no exception.
 * Original source: generated C codecs. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: DER 127/128 and CER 1000/1001.
 * Example: check_octet_boundary(128, ATS_DER).
 */
static int
check_octet_boundary(size_t length, enum asn_transfer_syntax syntax) {
    unsigned char payload[1001];
    unsigned char expected[1100];
    unsigned char actual[1100];
    OctetBoundaryRecord_t value = {0};
    void *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t expected_length;
    size_t index;
    int failed;

    if(length > sizeof(payload)) return 1;
    for(index = 0; index < length; index++) payload[index] = 0x5a;
    value.octets.buf = payload;
    value.octets.size = length;
    expected_length = expected_octet_record(expected, payload, length, syntax);
    encoded = asn_encode_to_buffer(NULL, syntax, &asn_DEF_OctetBoundaryRecord,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
       || memcmp(actual, expected, expected_length) != 0) return 1;
    result = asn_decode(NULL, syntax, &asn_DEF_OctetBoundaryRecord, &decoded,
                        expected, expected_length);
    failed = result.code != RC_OK || result.consumed != expected_length || !decoded
        || ((OctetBoundaryRecord_t *)decoded)->octets.size != length
        || !((OctetBoundaryRecord_t *)decoded)->octets.buf
        || memcmp(((OctetBoundaryRecord_t *)decoded)->octets.buf, payload, length) != 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_OctetBoundaryRecord, decoded);
    return failed;
}

/*
 * Purpose: build an independent one-field CER BIT STRING record vector.
 * Parameters: output receives bytes; payload/length carry whole-byte bits.
 * Returns complete size. Errors: test inputs are bounded at 1000 bytes.
 * Original source: X.690 BIT STRING fragmentation. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: content threshold C/Rust vectors.
 * Example: expected_bit_record(out, data, 1000) produces constructed CER.
 */
static size_t
expected_bit_record(unsigned char *output, const unsigned char *payload,
                    size_t length) {
    size_t offset = 0;
    output[offset++] = 0x30;
    output[offset++] = 0x80;
    if(length + 1 > 1000) {
        size_t position = 0;
        output[offset++] = 0x23;
        output[offset++] = 0x80;
        while(position < length) {
            unsigned char content[1000];
            size_t fragment = length - position;
            if(fragment > 999) fragment = 999;
            content[0] = 0;
            memcpy(content + 1, payload + position, fragment);
            offset = append_primitive(output, offset, 3, content, fragment + 1);
            position += fragment;
        }
        output[offset++] = 0;
        output[offset++] = 0;
    } else {
        unsigned char content[1000];
        content[0] = 0;
        memcpy(content + 1, payload, length);
        offset = append_primitive(output, offset, 3, content, length + 1);
    }
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: compare CER BIT STRING boundary vectors and verify C decoding.
 * Parameters: length is the whole-byte payload size, 999 or 1000.
 * Returns zero for exact bytes/consumption/value, otherwise one.
 * Errors: C encoder/decoder errors and mismatches return one.
 * Original source: generated C codecs. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: primitive/constructed CER boundary.
 * Example: check_bit_boundary(1000).
 */
static int
check_bit_boundary(size_t length) {
    unsigned char payload[1000];
    unsigned char expected[1100];
    unsigned char actual[1100];
    BitBoundaryRecord_t value = {0};
    void *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t expected_length;
    size_t index;
    int failed;

    if(length > sizeof(payload)) return 1;
    for(index = 0; index < length; index++) payload[index] = 0xa5;
    value.bits.buf = payload;
    value.bits.size = length;
    value.bits.bits_unused = 0;
    expected_length = expected_bit_record(expected, payload, length);
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_BitBoundaryRecord,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
       || memcmp(actual, expected, expected_length) != 0) return 1;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_BitBoundaryRecord, &decoded,
                        expected, expected_length);
    failed = result.code != RC_OK || result.consumed != expected_length || !decoded
        || ((BitBoundaryRecord_t *)decoded)->bits.size != length
        || ((BitBoundaryRecord_t *)decoded)->bits.bits_unused != 0
        || !((BitBoundaryRecord_t *)decoded)->bits.buf
        || memcmp(((BitBoundaryRecord_t *)decoded)->bits.buf, payload, length) != 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_BitBoundaryRecord, decoded);
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
    static const unsigned char extended_der[] = {
        0x30, 0x0e, 0x0a, 0x01, 0x03, 0x04, 0x02, 0x41, 0x42,
        0x03, 0x02, 0x05, 0xa0, 0x02, 0x01, 0xfe
    };
    static const unsigned char extended_cer[] = {
        0x30, 0x80, 0x0a, 0x01, 0x03, 0x04, 0x02, 0x41, 0x42,
        0x03, 0x02, 0x05, 0xa0, 0x02, 0x01, 0xfe, 0, 0
    };
    static unsigned char extended_octets[] = {0x41, 0x42};
    static unsigned char extended_bits[] = {0xa0};
    ENUMERATED_t state = {0};
    ExtendedRecord_t extended = {0};
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
        {&asn_DEF_ExtendedRecord, &extended, ATS_DER,
         extended_der, sizeof(extended_der), "DER enum and bounded strings"},
        {&asn_DEF_ExtendedRecord, &extended, ATS_CER,
         extended_cer, sizeof(extended_cer), "CER enum and bounded strings"},
    };
    size_t index;
    int failed = 0;

    /* Populate the optional and nondefault scalar pointers used by C layouts. */
    optional.flag = &(BOOLEAN_t){1};
    optional.empty = &(NULL_t){0};
    optional.number = &optional_number;
    if(asn_int642INTEGER(&state, 3) != 0) {
        failed = 1;
        goto cleanup;
    }
    extended.state_value = &state;
    extended.octets.buf = extended_octets;
    extended.octets.size = sizeof(extended_octets);
    extended.bits = &(BIT_STRING_t){extended_bits, sizeof(extended_bits), 5, {0}};
    extended.number = -2;

    /* Keep each comparison scoped to one exact schema-value/rule pair. */
    for(index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        if(check_vector(&vectors[index])) {
            failed = 1;
            goto cleanup;
        }
    }
    if(check_required_decode(ATS_DER, required_der, sizeof(required_der))
       || check_required_decode(ATS_CER, required_cer, sizeof(required_cer))
       || check_extended_decode(ATS_DER, extended_der, sizeof(extended_der))
       || check_extended_decode(ATS_CER, extended_cer, sizeof(extended_cer))
       || check_constructed_octets_ber()) {
        failed = 1;
        goto cleanup;
    }
    if(check_octet_boundary(125, ATS_DER) || check_octet_boundary(126, ATS_DER)
       || check_octet_boundary(127, ATS_DER) || check_octet_boundary(128, ATS_DER)
       || check_octet_boundary(1000, ATS_CER) || check_octet_boundary(1001, ATS_CER)
       || check_bit_boundary(999) || check_bit_boundary(1000)) failed = 1;

cleanup:
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ENUMERATED, &state);
    return failed;
}
