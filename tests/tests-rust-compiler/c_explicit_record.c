#include <asn_application.h>
#include <BIT_STRING.h>
#include <INTEGER.h>
#include <ExplicitRecord.h>
#include <ExplicitSetRecord.h>
#include <ExplicitStringRecord.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Purpose: compare one generated C explicit-record encoding with fixed bytes.
 * Parameters: syntax selects DER/CER; value is the record; expected/length
 * provide the independent vector. Returns zero for an exact match.
 * Errors: invalid arguments, encoder errors, and mismatches return one.
 * Source: X.690 EXPLICIT component encodings. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit tag interoperability.
 * Example: compare an explicit tag-zero BOOLEAN in DER.
 */
static int
check_record_encoding(enum asn_transfer_syntax syntax, const ExplicitRecord_t *value,
                      const unsigned char *expected, size_t length) {
    unsigned char actual[64];
    asn_enc_rval_t encoded;
    if(!value || !expected || length > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, syntax, &asn_DEF_ExplicitRecord,
                                   value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != length
       || memcmp(actual, expected, length) != 0) {
        size_t index = 0;
        size_t actual_length = encoded.encoded < 0 ? 0 : (size_t)encoded.encoded;
        while(index < length && index < actual_length && actual[index] == expected[index]) index++;
        fprintf(stderr, "C explicit record encoding mismatch: syntax=%d length=%zd/%zu "
                "at=%zu actual=%02x expected=%02x\n", (int)syntax, encoded.encoded,
                length, index, index < actual_length ? actual[index] : 0,
                index < length ? expected[index] : 0);
        for(index = 0; index < actual_length; index++)
            fprintf(stderr, "%02x%s", actual[index], index + 1 == actual_length ? "\n" : " ");
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode a Rust DER/CER vector and inspect semantic field values.
 * Parameters: syntax selects the transfer syntax; wire/length hold one TLV.
 * Returns zero for exact consumption and matching fields; otherwise one.
 * Errors: malformed data, defaults, wrong values, or consumption mismatch fail.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: bidirectional explicit-tag parity.
 * Example: decode explicit tags 0, 30, 31, 127, and 128.
 */
static int
check_record_decoding(enum asn_transfer_syntax syntax, const unsigned char *wire,
                      size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    ExplicitRecord_t *value;
    int64_t state_value = 0;
    int failed;
    if(!wire || !length) return 1;
    result = asn_decode(NULL, syntax, &asn_DEF_ExplicitRecord, &decoded, wire, length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != length || !value
        || !value->flag || !value->count || *value->count != 4 || !value->marker
        || asn_INTEGER2int64(&value->state, &state_value) != 0 || state_value != 2
        || !value->extra || *value->extra != 0;
    if(failed)
        fprintf(stderr, "C explicit record decode mismatch: syntax=%d consumed=%zu/%zu\n",
                (int)syntax, result.consumed, length);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExplicitRecord, decoded);
    return failed;
}

/*
 * Purpose: compare generated C SET encoding with fixed DER/CER vectors.
 * Parameters: syntax selects the canonical rule; value is the generated SET;
 * expected/length carry the independent byte sequence. Returns zero on match.
 * Errors: invalid values, encoder errors, or mismatches return one.
 * Source: X.690 SET canonical ordering. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit SET parity.
 * Example: universal tag one precedes context tag zero.
 */
static int
check_set_encoding(enum asn_transfer_syntax syntax, const ExplicitSetRecord_t *value,
                    const unsigned char *expected, size_t length) {
    unsigned char actual[64];
    asn_enc_rval_t encoded;
    if(!value || !expected || length > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, syntax, &asn_DEF_ExplicitSetRecord,
                                   value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != length
       || memcmp(actual, expected, length) != 0) return 1;
    return 0;
}

/*
 * Purpose: decode a Rust explicit SET vector and verify semantic fields.
 * Parameters: syntax selects the decoder; wire/length carry the complete SET.
 * Returns zero for exact consumption and expected values; otherwise one.
 * Errors: malformed input and mismatched values/consumption return one.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: bidirectional explicit SET parity.
 * Example: decode universal BOOLEAN before context-specific wrappers.
 */
static int
check_set_decoding(enum asn_transfer_syntax syntax, const unsigned char *wire,
                   size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    ExplicitSetRecord_t *value;
    int64_t state_value = 0;
    int failed;
    if(!wire || !length) return 1;
    result = asn_decode(NULL, syntax, &asn_DEF_ExplicitSetRecord, &decoded, wire, length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != length || !value
        || !value->flag || !value->plain || *value->plain != 0 || !value->count
        || *value->count != 4 || !value->marker
        || asn_INTEGER2int64(&value->setstate, &state_value) != 0 || state_value != 2
        || !value->extra || *value->extra != 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExplicitSetRecord, decoded);
    return failed;
}

/*
 * Purpose: append one primitive definite-length TLV to a bounded vector.
 * Parameters: output/capacity/offset select storage; tag, payload, and length
 * describe the TLV. Returns the next offset or SIZE_MAX on invalid storage.
 * Errors: null payloads, overflow, and insufficient capacity return SIZE_MAX.
 * Source: X.690 primitive TLV rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit string differential vectors.
 * Example: append the final one-byte OCTET STRING fragment.
 */
static size_t
append_primitive(unsigned char *output, size_t capacity, size_t offset,
                 unsigned char tag, const unsigned char *payload, size_t length) {
    size_t header = length < 128 ? 2 : length <= 255 ? 3 : 4;
    if(!output || offset > capacity || header > capacity - offset
       || length > capacity - offset - header || (length && !payload)
       || length > 65535) return SIZE_MAX;
    output[offset++] = tag;
    if(length < 128) output[offset++] = (unsigned char)length;
    else if(length <= 255) {
        output[offset++] = 0x81;
        output[offset++] = (unsigned char)length;
    }
    else {
        output[offset++] = 0x82;
        output[offset++] = (unsigned char)(length >> 8);
        output[offset++] = (unsigned char)length;
    }
    if(length) memcpy(output + offset, payload, length);
    return offset + length;
}

/*
 * Purpose: build CER with explicit wrappers around fragmented strings.
 * Parameters: output receives a vector of capacity at least 2200 bytes;
 * octets and bits supply 1001 and 1000 bytes. Returns total length or zero.
 * Errors: null pointers or insufficient storage return zero.
 * Source: X.690 CER string fragmentation. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit constructed string parity.
 * Example: tag 31 wraps CER OCTET STRING fragments under an indefinite length.
 */
static size_t
make_string_cer(unsigned char *output, size_t capacity,
                const unsigned char *octets, const unsigned char *bits) {
    size_t offset = 0;
    if(!output || capacity < 2200 || !octets || !bits) return 0;
    output[offset++] = 0x30;
    output[offset++] = 0x80;
    output[offset++] = 0xbf;
    output[offset++] = 0x1f;
    output[offset++] = 0x80;
    output[offset++] = 0x24;
    output[offset++] = 0x80;
    offset = append_primitive(output, capacity, offset, 0x04, octets, 1000);
    if(offset == SIZE_MAX) return 0;
    offset = append_primitive(output, capacity, offset, 0x04, octets + 1000, 1);
    if(offset == SIZE_MAX) return 0;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0xbf;
    output[offset++] = 0x81;
    output[offset++] = 0x00;
    output[offset++] = 0x80;
    output[offset++] = 0x23;
    output[offset++] = 0x80;
    output[offset++] = 0x03;
    output[offset++] = 0x82;
    output[offset++] = 0x03;
    output[offset++] = 0xe8;
    output[offset++] = 0x00;
    memcpy(output + offset, bits, 999);
    offset += 999;
    output[offset++] = 0x03;
    output[offset++] = 0x02;
    output[offset++] = 0;
    output[offset++] = bits[999];
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: validate decoded explicit OCTET/BIT STRING payloads and lengths.
 * Parameters: value is the decoded record; octets/bits supply expected bytes.
 * Returns zero when both fields match, or one for missing/mismatched data.
 * Errors: null fields, length/padding differences, or byte mismatches fail.
 * Source: X.690 string semantic values. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit string differential tests.
 * Example: check a decoded record containing 1001 octets and 8000 bits.
 */
static int
check_explicit_string_value(const ExplicitStringRecord_t *value,
                            const unsigned char *octets, size_t octet_count,
                            const unsigned char *bits, size_t bit_count) {
    if(!value || !value->octets.buf || !value->bits || !value->bits->buf) return 1;
    if(value->octets.size != octet_count || value->bits->size != bit_count
       || value->bits->bits_unused != 0) return 1;
    if(memcmp(value->octets.buf, octets, octet_count) != 0) return 1;
    return memcmp(value->bits->buf, bits, bit_count) != 0;
}

/*
 * Purpose: verify C CER encoding and BER/CER decoding for explicit strings.
 * Parameters: none. Returns zero when bytes, payload values, and consumption
 * match the independent constructed vector. Errors: any mismatch returns one.
 * Source: X.690 EXPLICIT and CER string rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: large explicit string interoperability.
 * Example: 1001 OCTET bytes and 8000 BIT bits are encoded and decoded.
 */
static int
check_explicit_strings(void) {
    unsigned char octets[1001];
    unsigned char bit_data[1000];
    unsigned char expected[2200];
    unsigned char actual[2200];
    BIT_STRING_t bits = {0};
    ExplicitStringRecord_t input = {0};
    asn_enc_rval_t encoded;
    size_t expected_length;
    void *decoded = NULL;
    asn_dec_rval_t result;
    ExplicitStringRecord_t *value;
    int failed;
    memset(octets, 0x5a, sizeof(octets));
    memset(bit_data, 0xa5, sizeof(bit_data));
    expected_length = make_string_cer(expected, sizeof(expected), octets, bit_data);
    if(!expected_length) return 1;
    bits.buf = bit_data;
    bits.size = sizeof(bit_data);
    input.octets.buf = octets;
    input.octets.size = sizeof(octets);
    input.bits = &bits;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_ExplicitStringRecord,
                                   &input, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
       || memcmp(actual, expected, expected_length) != 0) return 1;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_ExplicitStringRecord, &decoded,
                        expected, expected_length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != expected_length
        || check_explicit_string_value(value, octets, sizeof(octets), bit_data,
                                       sizeof(bit_data));
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExplicitStringRecord, decoded);
    if(failed) return 1;
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_ExplicitStringRecord, &decoded,
                        expected, expected_length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != expected_length
        || check_explicit_string_value(value, octets, sizeof(octets), bit_data,
                                       sizeof(bit_data));
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExplicitStringRecord, decoded);
    return failed;
}

/*
 * Purpose: check bidirectional C interoperability for explicit SEQUENCE tags.
 * Parameters: none. Returns zero when C matches DER/CER vectors and decodes
 * both vectors. Errors: allocation, encoding, or decoding mismatches return one.
 * Source: X.690 explicit record encodings. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit high-tag parity. Example: main.
 */
int
main(void) {
    static const unsigned char der[] = {
        0x30, 0x1c, 0xa0, 0x03, 0x01, 0x01, 0xff, 0xbe, 0x03, 0x02, 0x01, 0x04,
        0xbf, 0x1f, 0x02, 0x05, 0x00, 0xbf, 0x7f, 0x03, 0x0a, 0x01, 0x02, 0xbf,
        0x81, 0x00, 0x03, 0x01, 0x01, 0x00
    };
    static const unsigned char cer[] = {
        0x30, 0x80, 0xa0, 0x80, 0x01, 0x01, 0xff, 0, 0, 0xbe, 0x80, 0x02, 0x01,
        0x04, 0, 0, 0xbf, 0x1f, 0x80, 0x05, 0x00, 0, 0, 0xbf, 0x7f, 0x80, 0x0a,
        0x01, 0x02, 0, 0, 0xbf, 0x81, 0x00, 0x80, 0x01, 0x01, 0x00, 0, 0, 0, 0
    };
    static const unsigned char set_der[] = {
        0x31, 0x1f, 0x01, 0x01, 0x00, 0xa0, 0x03, 0x01, 0x01, 0xff, 0xbe, 0x03, 0x02,
        0x01, 0x04, 0xbf, 0x1f, 0x02, 0x05, 0x00, 0xbf, 0x7f, 0x03, 0x0a, 0x01, 0x02,
        0xbf, 0x81, 0x00, 0x03, 0x01, 0x01, 0x00
    };
    static const unsigned char set_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0x00, 0xa0, 0x80, 0x01, 0x01, 0xff, 0, 0, 0xbe, 0x80,
        0x02, 0x01, 0x04, 0, 0, 0xbf, 0x1f, 0x80, 0x05, 0x00, 0, 0, 0xbf, 0x7f, 0x80,
        0x0a, 0x01, 0x02, 0, 0, 0xbf, 0x81, 0x00, 0x80, 0x01, 0x01, 0x00, 0, 0, 0, 0
    };
    ExplicitRecord_t value = {0};
    ExplicitSetRecord_t set_value = {0};
    long count = 4;
    long set_count = 4;
    NULL_t marker = 0;
    BOOLEAN_t extra = 0;
    BOOLEAN_t plain = 0;
    int failed = 0;
    value.flag = 1;
    value.count = &count;
    value.marker = &marker;
    if(asn_long2INTEGER(&value.state, 2) != 0) failed = 1;
    value.extra = &extra;
    set_value.flag = 1;
    set_value.plain = &plain;
    set_value.count = &set_count;
    set_value.marker = &marker;
    if(asn_long2INTEGER(&set_value.setstate, 2) != 0) failed = 1;
    set_value.extra = &extra;
    if(!failed && (check_record_encoding(ATS_DER, &value, der, sizeof(der))
       || check_record_encoding(ATS_CER, &value, cer, sizeof(cer))
       || check_record_decoding(ATS_DER, der, sizeof(der))
       || check_record_decoding(ATS_CER, cer, sizeof(cer))
       || check_set_encoding(ATS_DER, &set_value, set_der, sizeof(set_der))
       || check_set_encoding(ATS_CER, &set_value, set_cer, sizeof(set_cer))
       || check_set_decoding(ATS_DER, set_der, sizeof(set_der))
       || check_set_decoding(ATS_CER, set_cer, sizeof(set_cer))
       || check_explicit_strings())) failed = 1;
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ENUMERATED, &value.state);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ENUMERATED, &set_value.setstate);
    return failed;
}
