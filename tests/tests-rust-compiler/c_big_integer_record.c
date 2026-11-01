/* Compare wide C INTEGER fields in generated BER/DER/CER records. */
#include <asn_application.h>
#include <INTEGER.h>
#include <Sequence.h>
#include <SequenceRequired.h>
#include <SetOptional.h>
#include <SetRequired.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_CAPACITY 2048

/*
 * Purpose: bind signed content bytes to their size and diagnostic name.
 * Each member is borrowed from test-local static storage.
 */
typedef struct integer_vector_s {
    const uint8_t *bytes; /* Borrowed canonical two's-complement contents. */
    size_t length; /* Number of content octets. */
    const char *name; /* Diagnostic label. */
} integer_vector_t;

/*
 * Purpose: append one X.690 short- or long-form definite length.
 * Inputs: length is the content size; output is caller-owned length storage.
 * Returns: number of bytes written. Errors: none; inputs are fixed test sizes.
 * Source: X.690 definite-length encoding. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: wide INTEGER record stage.
 * Example: length 128 appends `81 80`.
 */
static size_t
append_length(size_t length, uint8_t *output) {
    if(length < 128) {
        output[0] = (uint8_t)length;
        return 1;
    }
    if(length <= 255) {
        output[0] = 0x81;
        output[1] = (uint8_t)length;
        return 2;
    }
    output[0] = 0x82;
    output[1] = (uint8_t)(length >> 8);
    output[2] = (uint8_t)length;
    return 3;
}

/*
 * Purpose: append one INTEGER TLV from canonical signed content.
 * Parameters: content/length supply two's-complement bytes; output is storage.
 * Returns: total TLV size. Errors: none; caller provides bounded arrays.
 * Source: X.690 INTEGER encoding. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: C/Rust record vector checks.
 * Example: `00 80` appends `02 02 00 80`.
 */
static size_t
append_integer(const uint8_t *content, size_t length, uint8_t *output) {
    size_t offset = 0;
    output[offset++] = 2;
    offset += append_length(length, output + offset);
    memcpy(output + offset, content, length);
    return offset + length;
}

/*
 * Purpose: construct exact expected bytes for the scalar record schema.
 * Parameters: tag is the record tag; cer selects indefinite framing; integer
 * and length supply optional signed content; present controls omission;
 * output receives bytes. Returns: encoded size. Errors: none for fixed vectors.
 * Source: X.690 field and record encoding. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: wide record differential tests.
 * Example: tag 31 with CER builds an optional-integer SET.
 */
static size_t
build_optional(uint8_t tag, int cer, const uint8_t *integer, size_t length,
               int present, uint8_t *output) {
    uint8_t body[WIRE_CAPACITY];
    size_t body_length = 0;
    size_t offset = 0;
    body[body_length++] = 1;
    body[body_length++] = 1;
    body[body_length++] = 0xff;
    if(present) body_length += append_integer(integer, length, body + body_length);
    body[body_length++] = 4;
    body[body_length++] = 1;
    body[body_length++] = 0xa5;
    output[offset++] = tag;
    if(cer) {
        output[offset++] = 0x80;
        memcpy(output + offset, body, body_length);
        offset += body_length;
        output[offset++] = 0;
        output[offset++] = 0;
    } else {
        offset += append_length(body_length, output + offset);
        memcpy(output + offset, body, body_length);
        offset += body_length;
    }
    return offset;
}

/*
 * Purpose: compare exact encodings and decoded values for one descriptor.
 * Inputs: descriptor and expected_value describe the C record; der/cer and
 * their lengths are golden TLVs; label identifies failures.
 * Returns: zero for parity, one for a mismatch. Errors: diagnostics go to stderr.
 * Source: generated C descriptors and independent X.690 vectors.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: wide INTEGER record support. Example: compare one Sequence value.
 */
static int
check_record(asn_TYPE_descriptor_t *descriptor, const void *expected_value,
             const uint8_t *der, size_t der_length,
             const uint8_t *cer, size_t cer_length, const char *label) {
    uint8_t actual[WIRE_CAPACITY];
    enum asn_transfer_syntax syntax;
    for(syntax = ATS_DER; syntax <= ATS_CER; syntax++) {
        const uint8_t *expected = syntax == ATS_DER ? der : cer;
        size_t length = syntax == ATS_DER ? der_length : cer_length;
        if(length > sizeof(actual)) return 1;
        asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, syntax, descriptor,
            expected_value, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != length
           || memcmp(actual, expected, length) != 0) {
            fprintf(stderr, "%s encode mismatch for syntax %d\n", label, (int)syntax);
            fprintf(stderr, "actual (%zd):", encoded.encoded);
            if(encoded.encoded >= 0 && (size_t)encoded.encoded <= sizeof(actual)) {
                for(size_t index = 0; index < (size_t)encoded.encoded; index++)
                    fprintf(stderr, " %02x", actual[index]);
            }
            fprintf(stderr, "\nexpected (%zu):", length);
            for(size_t index = 0; index < length; index++)
                fprintf(stderr, " %02x", expected[index]);
            fputc('\n', stderr);
            return 1;
        }
    }
    for(syntax = ATS_BER; syntax <= ATS_CER; syntax += 2) {
        const uint8_t *wire = syntax == ATS_BER ? der : cer;
        size_t length = syntax == ATS_BER ? der_length : cer_length;
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor, &decoded, wire, length);
        int failed = result.code != RC_OK || result.consumed != length || !decoded
            || descriptor->op->compare_struct(descriptor, expected_value, decoded) != 0;
        if(failed)
            fprintf(stderr, "%s decode mismatch for syntax %d, code %d\n",
                    label, (int)syntax, (int)result.code);
        if(decoded) ASN_STRUCT_FREE(*descriptor, decoded);
        if(failed) return 1;
    }
    return 0;
}

/*
 * Purpose: compare one present optional INTEGER SEQUENCE.
 * Inputs: content/length are signed value bytes; label names the vector.
 * Returns: zero for exact C parity, one on mismatch. Errors: diagnostic output.
 * Source: generated `Sequence` descriptor. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: arbitrary-precision record stage.
 * Example: check a 129-octet signed content value.
 */
static int
check_sequence_vector(const uint8_t *content, size_t length, const char *label) {
    INTEGER_t integer = {.buf = (uint8_t *)content, .size = length};
    uint8_t tail[] = {0xa5};
    Sequence_t value = {.flag = 1, .value = &integer,
                        .tail = {.buf = tail, .size = sizeof(tail)}};
    uint8_t der[WIRE_CAPACITY];
    uint8_t cer[WIRE_CAPACITY];
    size_t der_length = build_optional(0x30, 0, content, length, 1, der);
    size_t cer_length = build_optional(0x30, 1, content, length, 1, cer);
    return check_record(&asn_DEF_Sequence, &value, der, der_length, cer, cer_length, label);
}

/*
 * Purpose: compare one present optional INTEGER SET in universal-tag order.
 * Inputs: content/length are signed value bytes; label names the vector.
 * Returns: zero for exact C parity, one on mismatch. Errors: diagnostic output.
 * Source: generated `SetOptional` and X.690 SET order.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: arbitrary-precision record stage. Example: compare SET value 128.
 */
static int
check_set_vector(const uint8_t *content, size_t length, const char *label) {
    INTEGER_t integer = {.buf = (uint8_t *)content, .size = length};
    uint8_t tail[] = {0xa5};
    SetOptional_t value = {.tail = {.buf = tail, .size = sizeof(tail)},
                           .value = &integer, .flag = 1};
    uint8_t der[WIRE_CAPACITY];
    uint8_t cer[WIRE_CAPACITY];
    size_t der_length;
    size_t cer_length;
    ASN_SET_MKPRESENT(value._presence_map, SetOptional_PR_tail);
    ASN_SET_MKPRESENT(value._presence_map, SetOptional_PR_value);
    ASN_SET_MKPRESENT(value._presence_map, SetOptional_PR_flag);
    der_length = build_optional(0x31, 0, content, length, 1, der);
    cer_length = build_optional(0x31, 1, content, length, 1, cer);
    return check_record(&asn_DEF_SetOptional, &value, der, der_length, cer, cer_length, label);
}

/*
 * Purpose: verify absent OPTIONAL and required INTEGER record components.
 * Inputs: none. Returns zero when all record vectors match.
 * Errors: reports encoding/decoding differences and returns one.
 * Source: generated C record descriptors. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: presence coverage.
 * Example: an omitted INTEGER does not appear in canonical SET output.
 */
static int
check_presence(void) {
    static uint8_t one[] = {1};
    static uint8_t tail[] = {0xa5};
    static uint8_t absent_seq_der[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x04, 0x01, 0xa5};
    static uint8_t absent_seq_cer[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x04, 0x01, 0xa5, 0, 0
    };
    static uint8_t absent_set_der[] = {0x31, 0x06, 0x01, 0x01, 0xff, 0x04, 0x01, 0xa5};
    static uint8_t absent_set_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x04, 0x01, 0xa5, 0, 0
    };
    static uint8_t required_seq_der[] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff
    };
    static uint8_t required_seq_cer[] = {
        0x30, 0x80, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff, 0, 0
    };
    static uint8_t required_set_der[] = {
        0x31, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x04, 0x01, 0xa5
    };
    static uint8_t required_set_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01,
        0x04, 0x01, 0xa5, 0, 0
    };
    Sequence_t sequence = {.flag = 1, .value = NULL,
                           .tail = {.buf = tail, .size = sizeof(tail)}};
    SetOptional_t set = {.tail = {.buf = tail, .size = sizeof(tail)},
                         .value = NULL, .flag = 1};
    INTEGER_t integer = {.buf = one, .size = sizeof(one)};
    SequenceRequired_t required_sequence = {.value = integer, .flag = 1};
    SetRequired_t required_set = {.tail = {.buf = tail, .size = sizeof(tail)},
                                  .value = integer, .flag = 1};
    ASN_SET_MKPRESENT(set._presence_map, SetOptional_PR_tail);
    ASN_SET_MKPRESENT(set._presence_map, SetOptional_PR_flag);
    ASN_SET_MKPRESENT(required_set._presence_map, SetRequired_PR_tail);
    ASN_SET_MKPRESENT(required_set._presence_map, SetRequired_PR_value);
    ASN_SET_MKPRESENT(required_set._presence_map, SetRequired_PR_flag);
    if(check_record(&asn_DEF_Sequence, &sequence, absent_seq_der, sizeof(absent_seq_der),
                    absent_seq_cer, sizeof(absent_seq_cer), "absent SEQUENCE field")) return 1;
    if(check_record(&asn_DEF_SetOptional, &set, absent_set_der, sizeof(absent_set_der),
                    absent_set_cer, sizeof(absent_set_cer), "absent SET field")) return 1;
    if(check_record(&asn_DEF_SequenceRequired, &required_sequence,
                    required_seq_der, sizeof(required_seq_der), required_seq_cer,
                    sizeof(required_seq_cer), "required SEQUENCE field")) return 1;
    return check_record(&asn_DEF_SetRequired, &required_set, required_set_der,
                        sizeof(required_set_der), required_set_cer,
                        sizeof(required_set_cer), "required SET field");
}

/*
 * Purpose: prove BER accepts reordered SET fields and strict CER rejects them.
 * Inputs: none. Returns zero for the expected status, prefix, and value.
 * Errors: reports mismatches and returns one. Source: X.690 SET ordering.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: natural SET field coverage. Example: decode OCTETS before BOOLEAN.
 */
static int
check_reversed_set(void) {
    static const uint8_t ber[] = {
        0x31, 0x09, 0x04, 0x01, 0xa5, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff
    };
    static const uint8_t cer[] = {
        0x31, 0x80, 0x04, 0x01, 0xa5, 0x02, 0x01, 0x01,
        0x01, 0x01, 0xff, 0, 0
    };
    static uint8_t one[] = {1};
    static uint8_t tail[] = {0xa5};
    INTEGER_t integer = {.buf = one, .size = sizeof(one)};
    SetOptional_t expected = {.tail = {.buf = tail, .size = sizeof(tail)},
                              .value = &integer, .flag = 1};
    void *decoded = NULL;
    asn_dec_rval_t result;
    ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_tail);
    ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_value);
    ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_flag);
    result = asn_decode(NULL, ATS_BER, &asn_DEF_SetOptional, &decoded, ber, sizeof(ber));
    if(result.code != RC_OK || result.consumed != sizeof(ber) || !decoded
       || asn_DEF_SetOptional.op->compare_struct(&asn_DEF_SetOptional, &expected,
                                                  decoded) != 0) {
        fprintf(stderr, "C BER did not accept reversed SET field order\n");
        if(decoded) ASN_STRUCT_FREE(asn_DEF_SetOptional, decoded);
        return 1;
    }
    ASN_STRUCT_FREE(asn_DEF_SetOptional, decoded);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_SetOptional, &decoded, cer, sizeof(cer));
    if(result.code == RC_OK) {
        fprintf(stderr, "C strict CER accepted reversed SET field order\n");
        if(decoded) ASN_STRUCT_FREE(asn_DEF_SetOptional, decoded);
        return 1;
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetOptional, decoded);
    return 0;
}

/*
 * Purpose: test BER normalization of aliases and strict CER canonicality.
 * Inputs: none. Returns zero when BER accepts and CER rejects each form.
 * Errors: reports decoder/status/value mismatches and returns one.
 * Source: wide C BER/CER record codecs. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: malformed content probes.
 * Example: BER accepts empty INTEGER content; CER rejects it.
 */
static int
check_ber_aliases(void) {
    static const uint8_t redundant_ber[] = {
        0x30, 0x0a, 0x01, 0x01, 0xff, 0x02, 0x02, 0, 1, 0x04, 1, 0xa5
    };
    static const uint8_t alias_ber[] = {
        0x30, 0x0a, 0x01, 1, 0xff, 0x1f, 2, 1, 1, 0x04, 1, 0xa5
    };
    static const uint8_t redundant_cer[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x02, 2, 0, 1, 0x04, 1, 0xa5, 0, 0
    };
    static const uint8_t alias_cer[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x1f, 2, 1, 1, 0x04, 1, 0xa5, 0, 0
    };
    static const uint8_t empty_ber[] = {
        0x30, 0x08, 0x01, 1, 0xff, 0x02, 0x00, 0x04, 1, 0xa5
    };
    static const uint8_t empty_cer[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x02, 0x00, 0x04, 1, 0xa5, 0, 0
    };
    const uint8_t *ber[] = {redundant_ber, alias_ber, empty_ber};
    const uint8_t *cer[] = {redundant_cer, alias_cer, empty_cer};
    const size_t ber_len[] = {
        sizeof(redundant_ber), sizeof(alias_ber), sizeof(empty_ber)
    };
    const size_t cer_len[] = {
        sizeof(redundant_cer), sizeof(alias_cer), sizeof(empty_cer)
    };
    size_t index;
    for(index = 0; index < 3; index++) {
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Sequence,
                                            &decoded, ber[index], ber_len[index]);
        int failed = result.code != RC_OK || result.consumed != ber_len[index] || !decoded;
        if(!failed && index < 2) {
            Sequence_t *record = decoded;
            int64_t integer_value = 0;
            failed = asn_INTEGER2int64(record->value, &integer_value)
                   || integer_value != 1 || !record->flag
                   || !record->tail.buf || record->tail.size != 1
                   || record->tail.buf[0] != 0xa5;
        } else if(!failed) {
            Sequence_t *record = decoded;
            failed = !record->value || record->value->size != 0 || !record->flag
                   || !record->tail.buf || record->tail.size != 1
                   || record->tail.buf[0] != 0xa5;
        }
        if(failed)
            fprintf(stderr, "C BER record compatibility case %zu failed\n", index);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Sequence, decoded);
        if(failed) return 1;
        decoded = NULL;
        result = asn_decode(NULL, ATS_CER, &asn_DEF_Sequence, &decoded,
                            cer[index], cer_len[index]);
        failed = result.code == RC_OK;
        if(failed) fprintf(stderr, "C CER accepted record compatibility case %zu\n", index);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Sequence, decoded);
        if(failed) return 1;
    }
    return 0;
}

/*
 * Purpose: compare wide C record codecs for signed vectors and field presence.
 * Inputs: none. Returns zero when C DER/CER and BER/CER checks all pass.
 * Errors: returns one after a diagnostic for any mismatch.
 * Source: generated descriptors with `-fwide-types`. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: unbounded INTEGER record slice.
 * Example: run after generating `BigIntegerRecord.asn1` with wide types.
 */
int
main(void) {
    static uint8_t zero[] = {0};
    static uint8_t one[] = {1};
    static uint8_t minus_one[] = {0xff};
    static uint8_t minus_129[] = {0xff, 0x7f};
    static uint8_t minus_128[] = {0x80};
    static uint8_t plus_127[] = {0x7f};
    static uint8_t plus_128[] = {0, 0x80};
    static uint8_t max_i64[] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static uint8_t min_i64[] = {0x80, 0, 0, 0, 0, 0, 0, 0};
    static uint8_t plus_2_64[] = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    static uint8_t minus_2_65[] = {0xfe, 0, 0, 0, 0, 0, 0, 0, 0};
    static uint8_t long_content[129];
    static uint8_t length_127[127];
    static uint8_t length_128[128];
    static uint8_t length_1000[1000];
    static uint8_t length_1001[1001];
    static const integer_vector_t values[] = {
        {zero, sizeof(zero), "zero"}, {one, sizeof(one), "one"},
        {minus_one, sizeof(minus_one), "minus one"},
        {minus_129, sizeof(minus_129), "minus 129"},
        {minus_128, sizeof(minus_128), "minus 128"},
        {plus_127, sizeof(plus_127), "127"}, {plus_128, sizeof(plus_128), "128"},
        {max_i64, sizeof(max_i64), "i64 max"}, {min_i64, sizeof(min_i64), "i64 min"},
        {plus_2_64, sizeof(plus_2_64), "2^64"},
        {minus_2_65, sizeof(minus_2_65), "-2^65"},
        {long_content, sizeof(long_content), "129 octets"},
    };
    integer_vector_t long_vectors[] = {
        {length_127, sizeof(length_127), "127 content octets"},
        {length_128, sizeof(length_128), "128 content octets"},
        {length_1000, sizeof(length_1000), "1000 content octets"},
        {length_1001, sizeof(length_1001), "1001 content octets"},
    };
    size_t index;
    long_content[0] = 1;
    length_127[0] = 1;
    length_128[0] = 1;
    length_1000[0] = 1;
    length_1001[0] = 1;
    for(index = 0; index < sizeof(values) / sizeof(values[0]); index++) {
        if(check_sequence_vector(values[index].bytes, values[index].length, values[index].name)
           || check_set_vector(values[index].bytes, values[index].length, values[index].name))
            return 1;
    }
    for(index = 0; index < sizeof(long_vectors) / sizeof(long_vectors[0]); index++) {
        if(check_sequence_vector(long_vectors[index].bytes, long_vectors[index].length,
                                 long_vectors[index].name)
           || check_set_vector(long_vectors[index].bytes, long_vectors[index].length,
                               long_vectors[index].name)) return 1;
    }
    return check_presence() || check_reversed_set() || check_ber_aliases();
}
