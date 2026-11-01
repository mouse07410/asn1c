/* Compare generated C IMPLICIT-tag SEQUENCE codecs with the Rust vectors. */
#include <asn_application.h>
#include <BIT_STRING.h>
#include <OCTET_STRING.h>
#include <AutomaticRecord.h>
#include <TaggedRecord.h>
#include <TaggedSetParity.h>
#include <TaggedStringRecord.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Purpose: compare a C BER/DER/CER encoder with a fixed generated-Rust vector.
 * Parameters: syntax selects DER or CER; value is the C record; expected and
 * length hold the independent wire vector. Returns zero for an exact match.
 * Errors: invalid arguments, encoder errors, or byte mismatches return one.
 * Source: X.690 high-tag-number record encodings. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: IMPLICIT tag parity. Example: DER 31/128.
 */
static int
check_encoding(enum asn_transfer_syntax syntax, const TaggedRecord_t *value,
               const unsigned char *expected, size_t length) {
    unsigned char actual[32];
    asn_enc_rval_t result;
    if(!value || !expected || length > sizeof(actual)) return 1;
    result = asn_encode_to_buffer(NULL, syntax, &asn_DEF_TaggedRecord, value,
                                  actual, sizeof(actual));
    if(result.encoded < 0 || (size_t)result.encoded != length
       || memcmp(actual, expected, length) != 0) {
        fprintf(stderr, "C tagged SEQUENCE encode mismatch for syntax %d\n", (int)syntax);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode a Rust wire vector and confirm exact consumption and values.
 * Parameters: syntax selects DER/CER; wire and length contain the record.
 * Returns zero for a matching C record and exact prefix consumption.
 * Errors: malformed input, wrong values, or mismatched consumption return one.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: bidirectional IMPLICIT-tag parity.
 * Example: decode a CER record carrying context tags 31 and 128.
 */
static int
check_decoding(enum asn_transfer_syntax syntax, const unsigned char *wire,
               size_t length, size_t expected_consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    TaggedRecord_t *value;
    int failed;
    if(!wire || !length) return 1;
    result = asn_decode(NULL, syntax, &asn_DEF_TaggedRecord, &decoded, wire, length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != expected_consumed || !value
        || !value->flag || value->count != 3;
    if(failed)
        fprintf(stderr,
            "C tagged SEQUENCE decode mismatch: syntax=%d consumed=%zu/%zu value=%p flag=%d count=%ld\n",
            (int)syntax, result.consumed, expected_consumed, (void *)value,
            value ? value->flag : -1, value ? value->count : -1L);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_TaggedRecord, decoded);
    return failed;
}

/*
 * Purpose: construct the independent CER vector for large implicit strings.
 * Parameters: output receives at least 2100 writable bytes.
 * Returns the complete vector length, or zero for invalid output storage.
 * Errors: insufficient storage returns zero without writing past the buffer.
 * Source: X.690 CER 1000-octet fragment rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged string interoperability.
 * Example: OCTET 1001 and BIT STRING 8000 bits use constructed context roots.
 */
static size_t
make_string_cer(unsigned char *output, size_t capacity) {
    size_t offset = 0;
    if(!output || capacity < 2100) return 0;
    output[offset++] = 0x30;
    output[offset++] = 0x80;
    output[offset++] = 0xbf;
    output[offset++] = 0x1f;
    output[offset++] = 0x80;
    output[offset++] = 0x04;
    output[offset++] = 0x82;
    output[offset++] = 0x03;
    output[offset++] = 0xe8;
    memset(output + offset, 0x5a, 1000);
    offset += 1000;
    output[offset++] = 0x04;
    output[offset++] = 0x01;
    output[offset++] = 0x5a;
    output[offset++] = 0x00;
    output[offset++] = 0x00;
    output[offset++] = 0xbf;
    output[offset++] = 0x81;
    output[offset++] = 0x00;
    output[offset++] = 0x80;
    output[offset++] = 0x03;
    output[offset++] = 0x82;
    output[offset++] = 0x03;
    output[offset++] = 0xe8;
    output[offset++] = 0x00;
    memset(output + offset, 0xa5, 999);
    offset += 999;
    output[offset++] = 0x03;
    output[offset++] = 0x02;
    output[offset++] = 0x00;
    output[offset++] = 0xa5;
    output[offset++] = 0x00;
    output[offset++] = 0x00;
    output[offset++] = 0x00;
    output[offset++] = 0x00;
    return offset;
}

/*
 * Purpose: compare large context-tagged CER strings and decode BER fragments.
 * Parameters: none. Returns zero when generated C matches the independent vector.
 * Errors: wrong bytes, values, or prefix use return one; allocated decode storage
 * is released before returning. Source: X.690 constructed string rules.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: implicit string interoperability. Example: run as test binary.
 */
/*
 * Validate decoded implicit string fields against independent payloads.
 * Parameters: value is decoded; octets/bits give expected bytes and lengths;
 * unused is the expected final BIT STRING padding count. Returns zero on match.
 * Errors: missing fields, wrong lengths, padding, or bytes return one.
 * Source: X.690 string content semantics. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged string parity. Example: CER value.
 */
static int
check_string_value(const TaggedStringRecord_t *value, const unsigned char *octets,
                   size_t octet_count, const unsigned char *bits, size_t bit_count,
                   int unused) {
    if(!value || !value->octets.buf || !value->bits || !value->bits->buf) return 1;
    if(value->octets.size != octet_count || value->bits->size != bit_count) return 1;
    if(value->bits->bits_unused != unused) return 1;
    if(memcmp(value->octets.buf, octets, octet_count) != 0) return 1;
    if(memcmp(value->bits->buf, bits, bit_count) != 0) return 1;
    return 0;
}

/*
 * Compare the large CER strings and verify C decodes their semantic bytes.
 * Parameters: none. Returns zero for exact DER-independent CER agreement.
 * Errors: any encode, decode, byte, or length mismatch returns one.
 * Source: X.690 CER fragment thresholds. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged string interoperability.
 * Example: OCTET 1001 and BIT 8000-bit values are fragmented.
 */
static int
check_cer_tagged_strings(void) {
    unsigned char octets[1001];
    unsigned char bit_bytes[1000];
    unsigned char expected[2200];
    unsigned char actual[2200];
    BIT_STRING_t bits = {0};
    TaggedStringRecord_t input = {0};
    asn_enc_rval_t encoded;
    size_t expected_length;
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    TaggedStringRecord_t *value;
    memset(octets, 0x5a, sizeof(octets));
    memset(bit_bytes, 0xa5, sizeof(bit_bytes));
    expected_length = make_string_cer(expected, sizeof(expected));
    if(!expected_length) return 1;
    bits.buf = bit_bytes;
    bits.size = sizeof(bit_bytes);
    input.octets.buf = octets;
    input.octets.size = sizeof(octets);
    input.bits = &bits;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_TaggedStringRecord,
                                   &input, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
       || memcmp(actual, expected, expected_length) != 0) return 1;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_TaggedStringRecord, &decoded,
                        expected, expected_length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != expected_length
        || check_string_value(value, octets, sizeof(octets), bit_bytes,
                              sizeof(bit_bytes), 0);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_TaggedStringRecord, decoded);
    return failed;
}

/*
 * Decode BER constructed implicit strings and check fragment flattening.
 * Parameters: none. Returns zero for expected OCTET/BIT bytes and full consume.
 * Errors: decoder, prefix, value, or allocation mismatches return one.
 * Source: X.690 BER constructed-string forms. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged BER interoperability.
 * Example: two OCTET fragments flatten to the bytes `AB`.
 */
static int
check_constructed_ber_tagged_strings(void) {
    static const unsigned char wire[] = {
        0x30, 0x80, 0xbf, 0x1f, 0x80, 0x04, 1, 'A', 0x04, 1, 'B', 0, 0,
        0xbf, 0x81, 0, 0x80, 0x03, 2, 0, 0x80, 0x03, 2, 7, 0x80, 0, 0, 0, 0
    };
    static const unsigned char octets[] = {'A', 'B'};
    static const unsigned char bit_bytes[] = {0x80, 0x80};
    void *decoded = NULL;
    asn_dec_rval_t result;
    TaggedStringRecord_t *value;
    int failed;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_TaggedStringRecord, &decoded,
                        wire, sizeof(wire));
    value = decoded;
    failed = result.code != RC_OK || result.consumed != sizeof(wire)
        || check_string_value(value, octets, sizeof(octets), bit_bytes,
                              sizeof(bit_bytes), 7);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_TaggedStringRecord, decoded);
    return failed;
}

/*
 * Run the independent C cases for implicit strings.
 * Parameters: none. Returns zero when both CER and BER cases pass.
 * Errors: either child check returns one. Source: X.690 tagged string rules.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: split test helpers for bounded complexity. Example: run C harness.
 */
static int
check_tagged_strings(void) {
    if(check_cer_tagged_strings()) return 1;
    return check_constructed_ber_tagged_strings();
}

/*
 * Purpose: compare C SET ordering and decode Rust DER/CER records.
 * Parameters: none. Returns zero when generated C and Rust vectors agree.
 * Errors: encoder/decoder failures or unexpected field values return one.
 * Source: X.690 SET ordering by effective class and tag number.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: context-specific SET parity. Example: universal BOOLEAN default is omitted.
 */
/*
 * Decode a SET vector and compare every required and optional value.
 * Parameters: syntax selects rules; wire/length contain one record.
 * Returns zero on full consumption and semantic equality.
 * Errors: malformed data or mismatched fields return one.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged SET differential checks.
 * Example: CER canonical order and BER arbitrary order use the same fields.
 */
static int
check_tagged_set_decode(enum asn_transfer_syntax syntax, const unsigned char *wire,
                        size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    TaggedSetParity_t *value;
    int failed;
    result = asn_decode(NULL, syntax, &asn_DEF_TaggedSetParity, &decoded, wire, length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != length || !value;
    if(!failed && (!value->count || *value->count != 3)) failed = 1;
    if(!failed && (value->marker != 0 || !value->flag)) failed = 1;
    if(!failed && (!value->high || !*value->high)) failed = 1;
    if(!failed && (!value->second || *value->second != 0)) failed = 1;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_TaggedSetParity, decoded);
    return failed;
}

/*
 * Compare C DER and CER SET encodings against Rust-derived vectors.
 * Parameters: input contains all field values; der/cer provide expected bytes.
 * Returns zero for exact encodings. Errors: mismatch or encoder failure returns one.
 * Source: X.690 SET order. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: context-specific SET parity.
 * Example: universal BOOLEAN sorts before context-specific members.
 */
static int
check_tagged_set_encoding(const TaggedSetParity_t *input,
                          const unsigned char *der, size_t der_length,
                          const unsigned char *cer, size_t cer_length) {
    unsigned char actual[64];
    asn_enc_rval_t encoded;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_TaggedSetParity,
                                   input, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_length
       || memcmp(actual, der, der_length) != 0) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_TaggedSetParity,
                                   input, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_length
       || memcmp(actual, cer, cer_length) != 0) return 1;
    return 0;
}

/*
 * Compare canonical and reordered SET vectors with the C generated codecs.
 * Parameters: none. Returns zero when encoding and three decode directions pass.
 * Errors: any wire or field mismatch returns one.
 * Source: X.690 SET ordering and generated C vectors. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: split helper complexity.
 * Example: reordered BER is valid while canonical DER/CER are sorted.
 */
static int
check_tagged_set(void) {
    static const unsigned char der[] = {
        0x31, 0x12, 0x01, 0x01, 0xff, 0x82, 0x01, 0x03, 0x9f, 0x1f, 0x00,
        0x9f, 0x7f, 0x01, 0x00, 0x9f, 0x81, 0x00, 0x01, 0xff
    };
    static const unsigned char cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x82, 0x01, 0x03, 0x9f, 0x1f, 0x00,
        0x9f, 0x7f, 0x01, 0x00, 0x9f, 0x81, 0x00, 0x01, 0xff, 0, 0
    };
    static const unsigned char reordered[] = {
        0x31, 0x12, 0x9f, 0x81, 0x00, 0x01, 0xff, 0x9f, 0x7f, 0x01, 0x00,
        0x9f, 0x1f, 0x00, 0x82, 0x01, 0x03, 0x01, 0x01, 0xff
    };
    BOOLEAN_t high = 1;
    BOOLEAN_t second = 0;
    long count = 3;
    TaggedSetParity_t input = {0};
    input.high = &high;
    input.marker = 0;
    input.count = &count;
    input.flag = 1;
    input.second = &second;
    ASN_SET_MKPRESENT(&input._presence_map, TaggedSetParity_PR_high);
    ASN_SET_MKPRESENT(&input._presence_map, TaggedSetParity_PR_marker);
    ASN_SET_MKPRESENT(&input._presence_map, TaggedSetParity_PR_count);
    ASN_SET_MKPRESENT(&input._presence_map, TaggedSetParity_PR_flag);
    ASN_SET_MKPRESENT(&input._presence_map, TaggedSetParity_PR_second);
    if(check_tagged_set_encoding(&input, der, sizeof(der), cer, sizeof(cer))) {
        fprintf(stderr, "C tagged SET canonical ordering mismatch\n");
        return 1;
    }
    if(check_tagged_set_decode(ATS_DER, der, sizeof(der))) return 1;
    if(check_tagged_set_decode(ATS_CER, cer, sizeof(cer))) return 1;
    return check_tagged_set_decode(ATS_BER, reordered, sizeof(reordered));
}

/*
 * Purpose: check C DER encoding and decoding of fixer-assigned AUTO TAGS.
 * Parameters: none. Returns zero for matching tag-zero-through-three values.
 * Errors: encoder or decoder mismatches return one; decoded storage is freed.
 * Source: fixed parser-tree automatic component tags. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: automatic tag parity. Example: context [0] flag.
 */
static int
check_automatic_record(void) {
    static const unsigned char der[] = {
        0x30, 0x0c, 0x80, 0x01, 0xff, 0x81, 0x01, 0xff,
        0x82, 0x00, 0x83, 0x02, 0x41, 0x42
    };
    static unsigned char octets[] = {'A', 'B'};
    unsigned char actual[32];
    NULL_t empty = 0;
    OCTET_STRING_t text = {0};
    AutomaticRecord_t input = {0};
    asn_enc_rval_t encoded;
    void *decoded = NULL;
    asn_dec_rval_t result;
    AutomaticRecord_t *value;
    int failed;

    text.buf = octets;
    text.size = sizeof(octets);
    input.flag = 1;
    input.count = -1;
    input.empty = &empty;
    input.octets = &text;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_AutomaticRecord,
                                   &input, actual, sizeof(actual));
    failed = encoded.encoded < 0 || (size_t)encoded.encoded != sizeof(der)
        || memcmp(actual, der, sizeof(der)) != 0;
    if(failed) return 1;
    result = asn_decode(NULL, ATS_DER, &asn_DEF_AutomaticRecord, &decoded,
                        der, sizeof(der));
    value = decoded;
    failed = result.code != RC_OK || result.consumed != sizeof(der) || !value
        || !value->flag || value->count != -1 || !value->empty || !value->octets
        || value->octets->size != sizeof(octets) || !value->octets->buf
        || memcmp(value->octets->buf, octets, sizeof(octets)) != 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AutomaticRecord, decoded);
    return failed;
}

/*
 * Purpose: exercise C and Rust interoperation for context tags 31 and 128.
 * Parameters: none. Returns zero after both encoder and decoder checks pass.
 * Errors: any C/Rust wire mismatch returns one.
 * Source: generated Rust tagged-sequence conformance vectors.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: high-tag C differential fixture. Example: run as a harness binary.
 */
int
main(void) {
    static const unsigned char der[] = {
        0x30, 0x09, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03
    };
    static const unsigned char cer[] = {
        0x30, 0x80, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03, 0, 0
    };
    static const unsigned char der_suffix[] = {
        0x30, 0x09, 0x9f, 0x1f, 0x01, 0xff, 0x9f, 0x81, 0x00, 0x01, 0x03, 0xaa
    };
    static const unsigned char redundant_tag_ber[] = {
        0x30, 0x80, 0x9f, 0x80, 0x1f, 0x01, 0xff,
        0x9f, 0x81, 0x00, 0x01, 0x03, 0x00, 0x00
    };
    TaggedRecord_t value = {0};
    int failed = 0;

    value.flag = 1;
    value.count = 3;
    failed |= check_encoding(ATS_DER, &value, der, sizeof(der));
    failed |= check_encoding(ATS_CER, &value, cer, sizeof(cer));
    failed |= check_decoding(ATS_DER, der, sizeof(der), sizeof(der));
    failed |= check_decoding(ATS_CER, cer, sizeof(cer), sizeof(cer));
    failed |= check_decoding(ATS_BER, der_suffix, sizeof(der_suffix), sizeof(der));
    failed |= check_decoding(ATS_BER, redundant_tag_ber, sizeof(redundant_tag_ber),
                             sizeof(redundant_tag_ber));
    failed |= check_tagged_strings();
    failed |= check_tagged_set();
    failed |= check_automatic_record();
    return failed;
}
