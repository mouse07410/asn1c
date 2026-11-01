/* Live C differential vectors for restricted-string fields in flat records. */
/* Source: X.690 vectors and generated C descriptors. Version/date: 2026-11-01. */
/* Responsible party: asn1c maintainers. History: flat string-field stage. */
#include <SequenceBMP.h>
#include <SequenceGeneral.h>
#include <SequenceGraphic.h>
#include <SequenceISO646.h>
#include <SequenceNumeric.h>
#include <SequenceObjectDescriptor.h>
#include <SequencePrintable.h>
#include <SequenceT61.h>
#include <SequenceTeletex.h>
#include <SequenceUniversal.h>
#include <SequenceUtf8.h>
#include <SequenceUtf8BoundedSiblings.h>
#include <SequenceUtf8Optional.h>
#include <SequenceVideotex.h>
#include <SequenceVisible.h>
#include <SetISO646Optional.h>
#include <SetPrintableOptional.h>
#include <SetT61Optional.h>
#include <asn_application.h>
#include <asn_internal.h>
#include <OCTET_STRING.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 8192

/* Forward declarations keep the shared encoder checker independent of helper order. */
static int decode_value(enum asn_transfer_syntax, asn_TYPE_descriptor_t *,
                        const void *, const uint8_t *, size_t, size_t);
static int cer_rejects(asn_TYPE_descriptor_t *, const uint8_t *, size_t);
static int ber_rejects(asn_TYPE_descriptor_t *, const uint8_t *, size_t);

/*
 * Purpose: append a shortest definite length to a bounded test buffer.
 * Inputs: output/capacity identify storage; length is the content length.
 * Returns encoded octet count, or zero on insufficient capacity.
 * Errors: oversized values or inadequate buffers are rejected.
 * Source: X.690. Version/date: 2026-11-01. Responsible party: maintainers.
 * History: shared record vectors. Example: length 1001 yields `82 03 e9`.
 */
static size_t
append_length(uint8_t *output, size_t capacity, size_t length) {
    if(length < 128) {
        if(capacity < 1) return 0;
        output[0] = (uint8_t)length;
        return 1;
    }
    if(length < 256) {
        if(capacity < 2) return 0;
        output[0] = 0x81;
        output[1] = (uint8_t)length;
        return 2;
    }
    if(capacity < 3 || length > UINT16_MAX) return 0;
    output[0] = 0x82;
    output[1] = (uint8_t)(length >> 8);
    output[2] = (uint8_t)length;
    return 3;
}

/*
 * Purpose: append one bounded definite-length TLV.
 * Inputs: output/capacity are destination; tag/content/length form the value.
 * Returns total encoded size, or zero on invalid input or insufficient space.
 * Errors: nonempty null content and exhausted capacity fail.
 * Source: X.690. Version/date: 2026-11-01. Responsible party: maintainers.
 * History: live record vectors. Example: BOOLEAN TRUE is `01 01 ff`.
 */
static size_t
append_tlv(uint8_t *output, size_t capacity, uint8_t tag,
           const uint8_t *content, size_t length) {
    size_t length_size;
    if(!output || (length && !content) || capacity < 1) return 0;
    length_size = append_length(output + 1, capacity - 1, length);
    if(!length_size || length > capacity - 1 - length_size) return 0;
    output[0] = tag;
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: encode a canonical primitive or fragmented CER character string.
 * Inputs: output/capacity receive bytes; tag/content/length describe the value.
 * Returns encoded size, or zero on invalid input or insufficient capacity.
 * Errors: missing nonempty content and capacity exhaustion fail.
 * Source: X.690 CER string rules. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: universal tag-4 fragments.
 * Example: 1001 UTF8 octets form 1000- and 1-octet children.
 */
static size_t
append_cer_string(uint8_t *output, size_t capacity, uint8_t tag,
                  const uint8_t *content, size_t length) {
    size_t offset = 0;
    size_t index;
    if(length <= 1000) return append_tlv(output, capacity, tag, content, length);
    if(!output || !content || capacity < 4) return 0;
    output[0] = (uint8_t)(tag | 0x20);
    output[1] = 0x80;
    offset = 2;
    for(index = 0; index < length; index += 1000) {
        size_t fragment = length - index;
        size_t written;
        if(fragment > 1000) fragment = 1000;
        written = append_tlv(output + offset, capacity - offset, 0x04,
                             content + index, fragment);
        if(!written) return 0;
        offset += written;
    }
    if(capacity - offset < 2) return 0;
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: construct the expected SEQUENCE with one string and TRUE.
 * Inputs: output/capacity receive the TLV; tag/content/length define the string;
 * `cer` selects canonical indefinite CER framing.
 * Returns encoded size, or zero on helper failure.
 * Errors: invalid storage or insufficient capacity returns zero.
 * Source: RestrictedStringRecord vectors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: differential record encoding.
 * Example: UTF8 `A` gives `30 06 0c 01 41 01 01 ff` for DER.
 */
static size_t
make_sequence(uint8_t *output, size_t capacity, uint8_t tag,
              const uint8_t *content, size_t length, int cer) {
    static const uint8_t boolean_true[] = {0xff};
    uint8_t body[WIRE_MAX];
    size_t body_size;
    size_t string_size;
    size_t boolean_size;
    if(!output || (length && !content)) return 0;
    string_size = cer
        ? append_cer_string(body, sizeof(body), tag, content, length)
        : append_tlv(body, sizeof(body), tag, content, length);
    if(!string_size) return 0;
    boolean_size = append_tlv(body + string_size, sizeof(body) - string_size,
                              0x01, boolean_true, sizeof(boolean_true));
    if(!boolean_size) return 0;
    body_size = string_size + boolean_size;
    if(cer) {
        if(capacity < body_size + 4) return 0;
        output[0] = 0x30;
        output[1] = 0x80;
        memcpy(output + 2, body, body_size);
        output[body_size + 2] = 0;
        output[body_size + 3] = 0;
        return body_size + 4;
    }
    return append_tlv(output, capacity, 0x30, body, body_size);
}

/*
 * Purpose: build DER/CER record vectors with tagged bounded OCTET/BIT siblings.
 * Inputs: output/capacity receive the record; `cer` selects root framing.
 * Returns complete size, or zero when any bounded buffer is insufficient.
 * Errors: helper failures or null output return zero.
 * Source: RestrictedStringRecord ASN.1 fixture. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: bounded scalar compatibility.
 * Example: explicit OCTET tag 0 and implicit BIT tag 1 follow UTF8String.
 */
static size_t
make_tagged_siblings_sequence(uint8_t *output, size_t capacity, int cer) {
    static const uint8_t utf8[] = {'A'};
    static const uint8_t octets[] = {0xaa};
    static const uint8_t bits[] = {3, 0xa0};
    static const uint8_t boolean_true[] = {0xff};
    uint8_t body[64];
    uint8_t inner[8];
    size_t offset = 0;
    size_t inner_size;
    size_t written;
    if(!output) return 0;
    written = append_tlv(body + offset, sizeof(body) - offset, 0x0c,
                         utf8, sizeof(utf8));
    if(!written) return 0;
    offset += written;
    inner_size = append_tlv(inner, sizeof(inner), 0x04, octets, sizeof(octets));
    if(!inner_size) return 0;
    if(cer) {
        if(sizeof(body) - offset < inner_size + 4) return 0;
        body[offset++] = 0xa0;
        body[offset++] = 0x80;
        memcpy(body + offset, inner, inner_size);
        offset += inner_size;
        body[offset++] = 0;
        body[offset++] = 0;
    } else {
        written = append_tlv(body + offset, sizeof(body) - offset, 0xa0,
                             inner, inner_size);
        if(!written) return 0;
        offset += written;
    }
    written = append_tlv(body + offset, sizeof(body) - offset, 0x81,
                         bits, sizeof(bits));
    if(!written) return 0;
    offset += written;
    written = append_tlv(body + offset, sizeof(body) - offset, 0x01,
                         boolean_true, sizeof(boolean_true));
    if(!written) return 0;
    offset += written;
    if(cer) {
        if(capacity < offset + 4) return 0;
        output[0] = 0x30;
        output[1] = 0x80;
        memcpy(output + 2, body, offset);
        output[offset + 2] = 0;
        output[offset + 3] = 0;
        return offset + 4;
    }
    return append_tlv(output, capacity, 0x30, body, offset);
}

/*
 * Purpose: compare C parity for one string beside bounded tagged scalar fields.
 * Inputs: none; local values select explicit OCTET and implicit BIT wrappers.
 * Returns zero on DER/CER bytes and BER/CER decoded-value parity.
 * Errors: encoder, decoder, or strict-CER mismatch returns one.
 * Source: generated C descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: scalar sibling composition.
 * Example: the explicit OCTET wrapper encloses exactly one primitive TLV.
 */
static int
check_tagged_sibling_record(void) {
    static uint8_t value_content[] = {'A'};
    static uint8_t octet_content[] = {0xaa};
    static uint8_t bit_content[] = {0xa0};
    SequenceUtf8BoundedSiblings_t expected = {0};
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    size_t der_size = make_tagged_siblings_sequence(der, sizeof(der), 0);
    size_t cer_size = make_tagged_siblings_sequence(cer, sizeof(cer), 1);
    asn_enc_rval_t encoded;
    expected.value.buf = value_content;
    expected.value.size = sizeof(value_content);
    expected.payload.buf = octet_content;
    expected.payload.size = sizeof(octet_content);
    expected.bits.buf = bit_content;
    expected.bits.size = sizeof(bit_content);
    expected.bits.bits_unused = 3;
    expected.flag = 1;
    if(!der_size || !cer_size || der_size >= sizeof(der) || cer_size >= sizeof(cer)) {
        fprintf(stderr, "FAIL: bounded-sibling expected vectors could not be built\n");
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_SequenceUtf8BoundedSiblings,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "FAIL: C DER with bounded OCTET/BIT siblings\n");
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_SequenceUtf8BoundedSiblings,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "FAIL: C CER with bounded OCTET/BIT siblings\n");
        return 1;
    }
    der[der_size] = 0x55;
    cer[cer_size] = 0x55;
    if(decode_value(ATS_BER, &asn_DEF_SequenceUtf8BoundedSiblings, &expected,
                    der, der_size + 1, der_size)
       || decode_value(ATS_BER, &asn_DEF_SequenceUtf8BoundedSiblings, &expected,
                      cer, cer_size + 1, cer_size)
       || decode_value(ATS_CER, &asn_DEF_SequenceUtf8BoundedSiblings, &expected,
                      cer, cer_size + 1, cer_size)) {
        fprintf(stderr, "FAIL: C decode with bounded OCTET/BIT siblings\n");
        return 1;
    }
    if(!cer_rejects(&asn_DEF_SequenceUtf8BoundedSiblings, der, der_size)) {
        fprintf(stderr, "FAIL: strict CER accepted bounded-sibling DER record\n");
        return 1;
    }
    return 0;
}

/*
 * Purpose: construct the absent-field UTF8 SEQUENCE used by optional tests.
 * Inputs: output/capacity receive the root; `cer` selects root framing.
 * Returns encoded size or zero on invalid storage/capacity.
 * Errors: insufficient output space returns zero.
 * Source: RestrictedStringRecord ASN.1. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: optional fields.
 * Example: absent DER value is `30 03 01 01 ff`.
 */
static size_t
make_absent_sequence(uint8_t *output, size_t capacity, int cer) {
    static const uint8_t boolean_true[] = {0xff};
    uint8_t body[3];
    if(!output) return 0;
    size_t size = append_tlv(body, sizeof(body), 0x01,
                             boolean_true, sizeof(boolean_true));
    if(!size) return 0;
    if(cer) {
        if(capacity < size + 4) return 0;
        output[0] = 0x30;
        output[1] = 0x80;
        memcpy(output + 2, body, size);
        output[size + 2] = 0;
        output[size + 3] = 0;
        return size + 4;
    }
    return append_tlv(output, capacity, 0x30, body, size);
}

/*
 * Purpose: compare one C encoding and both decoders against a record value.
 * Inputs: descriptor/expected identify the generated record; tag/content/length
 * describe its string field. Returns zero for exact DER/CER and decoded parity.
 * Errors: encode, strict-CER, value, or prefix mismatches return one.
 * Source: generated C runtime. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: per-kind live comparison.
 * Example: call with `asn_DEF_SequenceUtf8` and one valid UTF8 byte.
 */
static int
check_sequence(asn_TYPE_descriptor_t *descriptor, const void *expected,
               uint8_t tag, const uint8_t *content, size_t length) {
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    asn_enc_rval_t encoded;
    size_t der_size = make_sequence(der, sizeof(der), tag, content, length, 0);
    size_t cer_size = make_sequence(cer, sizeof(cer), tag, content, length, 1);
    if(!der_size || !cer_size || der_size >= sizeof(der) || cer_size >= sizeof(cer)) {
        fprintf(stderr, "FAIL: expected vector construction at tag %u length %zu\n",
                tag, length);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "FAIL: C DER record tag %u length %zu\n", tag, length);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "FAIL: C CER record tag %u length %zu\n", tag, length);
        return 1;
    }
    der[der_size] = 0x55;
    cer[cer_size] = 0x55;
    if(decode_value(ATS_BER, descriptor, expected, der, der_size + 1, der_size)
       || decode_value(ATS_BER, descriptor, expected, cer, cer_size + 1, cer_size)
       || decode_value(ATS_CER, descriptor, expected, cer, cer_size + 1, cer_size)) {
        fprintf(stderr, "FAIL: C record decode tag %u length %zu\n", tag, length);
        return 1;
    }
    if(!cer_rejects(descriptor, der, der_size)) {
        fprintf(stderr, "FAIL: C strict CER accepted DER record tag %u\n", tag);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode and compare one expected record prefix with C.
 * Inputs: syntax/descriptor/value identify expected result; wire/length and
 * consumed specify the candidate and expected exact prefix.
 * Returns zero on exact decoded value and consumption, otherwise one.
 * Errors: all partially decoded allocations are freed before return.
 * Source: generated C descriptor API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix-safe comparisons.
 * Example: a suffix after a valid CER record is left unconsumed.
 */
static int
decode_value(enum asn_transfer_syntax syntax, asn_TYPE_descriptor_t *descriptor,
             const void *expected, const uint8_t *wire, size_t length,
             size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor, &decoded,
                                       wire, length);
    int failed = result.code != RC_OK || result.consumed != consumed || !decoded
        || !descriptor->op->compare_struct
        || (decoded && descriptor->op->compare_struct(descriptor, expected, decoded));
    if(failed)
        fprintf(stderr, "FAIL: C decode syntax=%d consumed=%zu expected=%zu\n",
                (int)syntax, result.consumed, consumed);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: require strict CER rejection of a candidate record.
 * Inputs: descriptor selects the record; wire/length are the candidate.
 * Returns one on rejection, zero if C unexpectedly accepts it.
 * Errors: partial decoded values are freed.
 * Source: generated strict CER adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: framing and repertoire gates.
 * Example: a definite DER SEQUENCE must fail strict CER decoding.
 */
static int
cer_rejects(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire,
            size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, descriptor, &decoded,
                                       wire, length);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: require BER rejection of malformed constructed field input.
 * Inputs: descriptor selects the generated record; wire/length are candidate.
 * Returns one on rejection, zero on unexpected acceptance.
 * Errors: any partially decoded C allocation is freed.
 * Source: generated C BER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed child checks.
 * Example: a UTF8 fragment with child tag 12 is rejected; tag 4 is required.
 */
static int
ber_rejects(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire,
            size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, descriptor, &decoded,
                                       wire, length);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: initialize and check one generated direct-string SEQUENCE type.
 * Inputs: descriptor and tag select the schema; the macro supplies C type/data.
 * Returns zero on DER/CER round-trip parity, otherwise one.
 * Errors: failed C codecs are reported by `check_sequence`.
 * Source: generated C type aliases. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: macro for all AST kinds.
 * Example: `CHECK_SEQUENCE(SequenceUtf8, 12, content)` checks UTF8String.
 */
#define CHECK_SEQUENCE(type, descriptor_name, tag_number, bytes) do { \
    type expected_value = {0}; \
    expected_value.value.buf = (uint8_t *)(bytes); \
    expected_value.value.size = sizeof(bytes); \
    expected_value.flag = 1; \
    if(check_sequence(&asn_DEF_##descriptor_name, &expected_value, tag_number, \
                      (bytes), sizeof(bytes))) return 1; \
} while(0)

/*
 * Purpose: check optional SET encoding with a required TRUE sibling.
 * Inputs: descriptor and expected object identify the typed value; string data
 * and presence control tag 19/20/26 emission.
 * Returns zero for exact C DER/CER and BER/CER decode parity, otherwise one.
 * Errors: encoding or decoding mismatch is reported and allocations are freed.
 * Source: X.690 SET ordering and generated C descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: optional string fields.
 * Example: present PrintableString `A` precedes BOOLEAN by tag order.
 */
static int
check_optional_set(asn_TYPE_descriptor_t *descriptor, const void *expected,
                   uint8_t tag, const uint8_t *content, size_t length,
                   int present) {
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    uint8_t body[WIRE_MAX];
    static const uint8_t boolean_true[] = {0xff};
    size_t body_size = append_tlv(body, sizeof(body), 0x01,
                                  boolean_true, sizeof(boolean_true));
    size_t der_size;
    size_t cer_size;
    asn_enc_rval_t encoded;
    if(present) {
        size_t written = append_tlv(body + body_size, sizeof(body) - body_size,
                                    tag, content, length);
        if(!written) return 1;
        body_size += written;
    }
    der_size = append_tlv(der, sizeof(der), 0x31, body, body_size);
    if(!der_size) return 1;
    cer[0] = 0x31;
    cer[1] = 0x80;
    memcpy(cer + 2, body, body_size);
    cer[body_size + 2] = 0;
    cer[body_size + 3] = 0;
    cer_size = body_size + 4;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "FAIL: optional SET DER tag %u presence %d\n", tag, present);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "FAIL: optional SET CER tag %u presence %d\n", tag, present);
        return 1;
    }
    der[der_size] = 0x55;
    cer[cer_size] = 0x55;
    if(decode_value(ATS_BER, descriptor, expected, der, der_size + 1, der_size)
       || decode_value(ATS_BER, descriptor, expected, cer, cer_size + 1, cer_size)
       || decode_value(ATS_CER, descriptor, expected, cer, cer_size + 1, cer_size)) {
        fprintf(stderr, "FAIL: optional SET decode tag %u presence %d\n", tag, present);
        return 1;
    }
    if(!cer_rejects(descriptor, der, der_size)) {
        fprintf(stderr, "FAIL: strict CER accepted DER optional SET tag %u\n", tag);
        return 1;
    }
    return 0;
}

/*
 * Purpose: compare present and absent OPTIONAL UTF8String SEQUENCE fields.
 * Inputs: `expected` is the typed C record; content/length apply when present.
 * Returns zero for exact DER/CER bytes and decoded value/prefix parity.
 * Errors: any encoder or decoder mismatch returns one.
 * Source: generated optional-field descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: OPTIONAL SEQUENCE coverage.
 * Example: an absent field leaves only the required TRUE BOOLEAN.
 */
static int
check_optional_sequence(const SequenceUtf8Optional_t *expected,
                        const uint8_t *content, size_t length, int present) {
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    size_t der_size = present
        ? make_sequence(der, sizeof(der), 12, content, length, 0)
        : make_absent_sequence(der, sizeof(der), 0);
    size_t cer_size = present
        ? make_sequence(cer, sizeof(cer), 12, content, length, 1)
        : make_absent_sequence(cer, sizeof(cer), 1);
    asn_enc_rval_t encoded;
    if(!der_size || !cer_size || der_size >= sizeof(der) || cer_size >= sizeof(cer)) {
        fprintf(stderr, "FAIL: optional UTF8 expected vector construction\n");
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_SequenceUtf8Optional,
                                   expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "FAIL: optional UTF8 DER, present=%d\n", present);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_SequenceUtf8Optional,
                                   expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "FAIL: optional UTF8 CER, present=%d\n", present);
        return 1;
    }
    der[der_size] = 0x55;
    cer[cer_size] = 0x55;
    if(decode_value(ATS_BER, &asn_DEF_SequenceUtf8Optional, expected,
                    der, der_size + 1, der_size)
       || decode_value(ATS_BER, &asn_DEF_SequenceUtf8Optional, expected,
                      cer, cer_size + 1, cer_size)
       || decode_value(ATS_CER, &asn_DEF_SequenceUtf8Optional, expected,
                      cer, cer_size + 1, cer_size)) {
        fprintf(stderr, "FAIL: optional UTF8 decode, present=%d\n", present);
        return 1;
    }
    if(!cer_rejects(&asn_DEF_SequenceUtf8Optional, der, der_size)) {
        fprintf(stderr, "FAIL: strict CER accepted optional UTF8 DER record\n");
        return 1;
    }
    return 0;
}

/*
 * Purpose: compare C record boundary encodings for UTF8String, BMP, and Universal.
 * Inputs: no arguments; local aligned content buffers reach CER cutovers.
 * Returns zero if every exact DER/CER vector and decode succeeds.
 * Errors: first C mismatch is reported.
 * Source: restricted-string record schema. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: per-kind fragmentation.
 * Example: UTF8 length 1001 uses CER tag-4 fragments.
 */
static int
check_boundaries(void) {
    static uint8_t utf8[2001];
    static uint8_t bmp[2000];
    static uint8_t universal[2000];
    static const size_t utf8_sizes[] = {0, 127, 128, 999, 1000, 1001, 2001};
    static const size_t bmp_sizes[] = {998, 1000, 1002, 2000};
    static const size_t universal_sizes[] = {996, 1000, 1004, 2000};
    size_t index;
    memset(utf8, 'A', sizeof(utf8));
    for(index = 0; index < sizeof(utf8_sizes) / sizeof(utf8_sizes[0]); index++) {
        size_t length = utf8_sizes[index];
        SequenceUtf8_t expected = {0};
        expected.value.buf = utf8;
        expected.value.size = length;
        expected.flag = 1;
        if(check_sequence(&asn_DEF_SequenceUtf8, &expected, 12, utf8, length)) return 1;
    }
    for(index = 0; index < sizeof(bmp_sizes) / sizeof(bmp_sizes[0]); index++) {
        size_t length = bmp_sizes[index];
        SequenceBMP_t expected = {0};
        memset(bmp, 0, length);
        for(size_t offset = 1; offset < length; offset += 2) bmp[offset] = 65;
        expected.value.buf = bmp;
        expected.value.size = length;
        expected.flag = 1;
        if(check_sequence(&asn_DEF_SequenceBMP, &expected, 30, bmp, length)) return 1;
    }
    for(index = 0; index < sizeof(universal_sizes) / sizeof(universal_sizes[0]); index++) {
        size_t length = universal_sizes[index];
        SequenceUniversal_t expected = {0};
        memset(universal, 0, length);
        for(size_t offset = 3; offset < length; offset += 4) universal[offset] = 65;
        expected.value.buf = universal;
        expected.value.size = length;
        expected.flag = 1;
        if(check_sequence(&asn_DEF_SequenceUniversal, &expected, 28,
                          universal, length)) return 1;
    }
    return 0;
}

/*
 * Purpose: prove BER accepts raw high-bit UTF8 bytes while CER validates content.
 * Inputs: no arguments; the vector uses canonical indefinite outer framing.
 * Returns zero when BER preserves the byte and both CER paths reject it.
 * Errors: any status, value, encoding, or consumption mismatch returns one.
 * Source: approved C-compatible UTF8 policy. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: field-level repertoire tests.
 * Example: BER retains `ff`; CER rejects it after fragment reassembly.
 */
static int
check_invalid_utf8_cer(void) {
    static const uint8_t raw[] = {0xff};
    static const uint8_t wire[] = {
        0x30, 0x80, 0x2c, 0x80, 0x04, 1, 0xff, 0, 0,
        0x01, 0x01, 0xff, 0, 0,
    };
    SequenceUtf8_t expected = {0};
    uint8_t actual[64];
    asn_enc_rval_t encoded;
    expected.value.buf = (uint8_t *)raw;
    expected.value.size = sizeof(raw);
    expected.flag = 1;
    if(decode_value(ATS_BER, &asn_DEF_SequenceUtf8, &expected,
                    wire, sizeof(wire), sizeof(wire))) return 1;
    if(!cer_rejects(&asn_DEF_SequenceUtf8, wire, sizeof(wire))) {
        fprintf(stderr, "FAIL: strict CER accepted invalid UTF8 field content\n");
        return 1;
    }
    {
        uint8_t primitive_wire[64];
        size_t primitive_size = make_sequence(primitive_wire, sizeof(primitive_wire),
                                              12, raw, sizeof(raw), 1);
        if(!primitive_size
           || decode_value(ATS_BER, &asn_DEF_SequenceUtf8, &expected,
                           primitive_wire, primitive_size, primitive_size)
           || !cer_rejects(&asn_DEF_SequenceUtf8, primitive_wire, primitive_size)) {
            fprintf(stderr, "FAIL: canonical parent did not isolate invalid UTF8 CER\n");
            return 1;
        }
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_SequenceUtf8,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded >= 0) {
        fprintf(stderr, "FAIL: C CER encoder accepted invalid UTF8 field content\n");
        return 1;
    }
    return 0;
}

/*
 * Purpose: verify BER raw-content preservation and C CER validator failures.
 * Inputs: descriptor/expected identify one generated kind; tag/content/length
 * define raw bytes that violate only that string kind's CER content rule.
 * Returns zero when BER accepts and strict CER plus CER encoding reject.
 * Errors: wire, value, or unexpected encoder/decoder status returns one.
 * Source: generated C string descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: per-kind CER validation.
 * Example: odd-length BMP content is retained by BER but rejected by CER.
 */
static int
check_invalid_string_content(asn_TYPE_descriptor_t *descriptor,
                             const void *expected, uint8_t tag,
                             const uint8_t *content, size_t length,
                             const char *name) {
    uint8_t wire[64];
    uint8_t output[64];
    size_t wire_size = make_sequence(wire, sizeof(wire), tag, content, length, 1);
    asn_enc_rval_t encoded;
    if(!wire_size
       || decode_value(ATS_BER, descriptor, expected, wire, wire_size, wire_size)) {
        fprintf(stderr, "FAIL: C BER did not preserve invalid %s bytes\n", name);
        return 1;
    }
    if(!cer_rejects(descriptor, wire, wire_size)) {
        fprintf(stderr, "FAIL: strict CER accepted invalid %s bytes\n", name);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   output, sizeof(output));
    if(encoded.encoded >= 0) {
        fprintf(stderr, "FAIL: C CER encoder accepted invalid %s bytes\n", name);
        return 1;
    }
    return 0;
}

/*
 * Purpose: exercise independent C CER content validators in record context.
 * Inputs: none; each typed record contains one canonical-framed invalid value.
 * Returns zero when all five C BER/CER behavior checks match the policy.
 * Errors: any unexpected acceptance or failed BER preservation returns one.
 * Source: C descriptor constraints. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: embedded string validators.
 * Example: NumericString `A` is BER-preserved but fails strict CER.
 */
static int
check_invalid_string_kinds(void) {
    static const uint8_t numeric[] = {'A'};
    static const uint8_t printable[] = {'@'};
    static const uint8_t visible[] = {0x1f};
    static const uint8_t bmp[] = {0};
    static const uint8_t universal[] = {0, 0, 0};
    SequenceNumeric_t numeric_value = {0};
    SequencePrintable_t printable_value = {0};
    SequenceVisible_t visible_value = {0};
    SequenceBMP_t bmp_value = {0};
    SequenceUniversal_t universal_value = {0};
    numeric_value.value.buf = (uint8_t *)numeric;
    numeric_value.value.size = sizeof(numeric);
    numeric_value.flag = 1;
    printable_value.value.buf = (uint8_t *)printable;
    printable_value.value.size = sizeof(printable);
    printable_value.flag = 1;
    visible_value.value.buf = (uint8_t *)visible;
    visible_value.value.size = sizeof(visible);
    visible_value.flag = 1;
    bmp_value.value.buf = (uint8_t *)bmp;
    bmp_value.value.size = sizeof(bmp);
    bmp_value.flag = 1;
    universal_value.value.buf = (uint8_t *)universal;
    universal_value.value.size = sizeof(universal);
    universal_value.flag = 1;
    return check_invalid_string_content(&asn_DEF_SequenceNumeric, &numeric_value,
                                        18, numeric, sizeof(numeric), "NumericString")
        || check_invalid_string_content(&asn_DEF_SequencePrintable, &printable_value,
                                        19, printable, sizeof(printable), "PrintableString")
        || check_invalid_string_content(&asn_DEF_SequenceVisible, &visible_value,
                                        26, visible, sizeof(visible), "VisibleString")
        || check_invalid_string_content(&asn_DEF_SequenceBMP, &bmp_value,
                                        30, bmp, sizeof(bmp), "BMPString")
        || check_invalid_string_content(&asn_DEF_SequenceUniversal, &universal_value,
                                        28, universal, sizeof(universal), "UniversalString");
}

/*
 * Purpose: exercise a C-compatible five-byte UTF8 sequence across the CER cut.
 * Inputs: none; content has 999 ASCII bytes followed by one legacy UTF8 value.
 * Returns zero for exact DER/CER and decode parity.
 * Errors: C encoding, framing, value, or strict-decode mismatch returns one.
 * Source: C UTF8String descriptor vectors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: cross-fragment sequence.
 * Example: the first `f8` byte is the final octet of the first CER fragment.
 */
static int
check_utf8_fragment_boundary(void) {
    static uint8_t content[1004];
    SequenceUtf8_t expected = {0};
    memset(content, 'A', 999);
    memcpy(content + 999, (const uint8_t[]){0xf8, 0x88, 0x80, 0x80, 0x80}, 5);
    expected.value.buf = content;
    expected.value.size = sizeof(content);
    expected.flag = 1;
    return check_sequence(&asn_DEF_SequenceUtf8, &expected, 12,
                          content, sizeof(content));
}

/*
 * Purpose: check BER's universal tag-4 child fragments and strict CER rejection.
 * Inputs: none; local vectors encode a valid and malformed constructed SEQUENCE.
 * Returns zero on accepted value parity and rejected malformed/canonical forms.
 * Errors: status, value, or prefix mismatch returns one.
 * Source: X.690 constructed strings. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: record fragment checks.
 * Example: constructed BER fragments `A` and `B` reassemble to `AB`.
 */
static int
check_constructed_ber(void) {
    static const uint8_t content[] = {'A', 'B'};
    static const uint8_t constructed[] = {
        0x30, 0x80, 0x2c, 0x80, 0x04, 1, 'A', 0x04, 1, 'B', 0, 0,
        0x01, 0x01, 0xff, 0, 0,
    };
    static const uint8_t wrong_child[] = {
        0x30, 0x80, 0x2c, 0x80, 0x0c, 1, 'A', 0, 0, 0x01, 0x01, 0xff, 0, 0,
    };
    static const uint8_t truncated_child[] = {
        0x30, 0x80, 0x2c, 0x80, 0x04, 2, 'A', 0, 0, 0x01, 0x01, 0xff, 0, 0,
    };
    SequenceUtf8_t expected = {0};
    expected.value.buf = (uint8_t *)content;
    expected.value.size = sizeof(content);
    expected.flag = 1;
    if(decode_value(ATS_BER, &asn_DEF_SequenceUtf8, &expected,
                    constructed, sizeof(constructed), sizeof(constructed))) return 1;
    if(!cer_rejects(&asn_DEF_SequenceUtf8, constructed, sizeof(constructed))) {
        fprintf(stderr, "FAIL: strict CER accepted constructed short UTF8 field\n");
        return 1;
    }
    if(!ber_rejects(&asn_DEF_SequenceUtf8, wrong_child, sizeof(wrong_child))
       || !ber_rejects(&asn_DEF_SequenceUtf8, truncated_child,
                       sizeof(truncated_child))) {
        fprintf(stderr, "FAIL: C BER accepted malformed UTF8 fragment field\n");
        return 1;
    }
    return 0;
}

/*
 * Purpose: exercise the supported direct string field kinds and aliases.
 * Inputs: none. Returns zero when all generated C comparisons succeed.
 * Errors: the first descriptor/vector mismatch returns one with a diagnostic.
 * Source: RestrictedStringRecord ASN.1 fixture. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: live C parity suite.
 * Example: T61 and Teletex are distinct C descriptors sharing tag 20.
 */
int
main(void) {
    static uint8_t printable[] = {'A', 'z', '0', '9', ' ', '\'', '(', ')', '+',
                                  ',', '-', '.', '/', ':', '=', '?'};
    static uint8_t numeric[] = {' ', '1', '9'};
    static uint8_t ascii[] = {' ', '~'};
    static uint8_t universal[] = {0, 0, 0, 65};
    static uint8_t bmp[] = {0, 65};
    static uint8_t object_descriptor[] = {0xff};
    static uint8_t teletex[] = {0xff};
    static uint8_t t61[] = {0xfe};
    static uint8_t videotex[] = {0x80};
    static uint8_t graphic[] = {0x81};
    static uint8_t general[] = {0xff};
    static uint8_t utf8[] = {'A'};

    CHECK_SEQUENCE(SequenceObjectDescriptor_t, SequenceObjectDescriptor, 7, object_descriptor);
    CHECK_SEQUENCE(SequenceUtf8_t, SequenceUtf8, 12, utf8);
    CHECK_SEQUENCE(SequenceNumeric_t, SequenceNumeric, 18, numeric);
    CHECK_SEQUENCE(SequencePrintable_t, SequencePrintable, 19, printable);
    CHECK_SEQUENCE(SequenceTeletex_t, SequenceTeletex, 20, teletex);
    CHECK_SEQUENCE(SequenceT61_t, SequenceT61, 20, t61);
    CHECK_SEQUENCE(SequenceVideotex_t, SequenceVideotex, 21, videotex);
    CHECK_SEQUENCE(SequenceGraphic_t, SequenceGraphic, 25, graphic);
    CHECK_SEQUENCE(SequenceVisible_t, SequenceVisible, 26, ascii);
    CHECK_SEQUENCE(SequenceISO646_t, SequenceISO646, 26, ascii);
    CHECK_SEQUENCE(SequenceGeneral_t, SequenceGeneral, 27, general);
    CHECK_SEQUENCE(SequenceUniversal_t, SequenceUniversal, 28, universal);
    CHECK_SEQUENCE(SequenceBMP_t, SequenceBMP, 30, bmp);
    if(check_boundaries() || check_constructed_ber() || check_utf8_fragment_boundary()
       || check_tagged_sibling_record() || check_invalid_utf8_cer()
       || check_invalid_string_kinds()) return 1;

    {
        static uint8_t content[] = {'A'};
        UTF8String_t text = {content, sizeof(content)};
        SequenceUtf8Optional_t present = {0};
        SequenceUtf8Optional_t absent = {0};
        present.value = &text;
        present.flag = 1;
        absent.flag = 1;
        if(check_optional_sequence(&present, content, sizeof(content), 1)
           || check_optional_sequence(&absent, NULL, 0, 0)) return 1;
    }

    {
        static uint8_t content[] = {'A'};
        PrintableString_t text = {content, sizeof(content)};
        SetPrintableOptional_t present = {0};
        SetPrintableOptional_t absent = {0};
        present.value = &text;
        present.flag = 1;
        absent.flag = 1;
        ASN_SET_MKPRESENT(present._presence_map, SetPrintableOptional_PR_value);
        ASN_SET_MKPRESENT(present._presence_map, SetPrintableOptional_PR_flag);
        ASN_SET_MKPRESENT(absent._presence_map, SetPrintableOptional_PR_flag);
        if(check_optional_set(&asn_DEF_SetPrintableOptional, &present, 19,
                              content, sizeof(content), 1)
           || check_optional_set(&asn_DEF_SetPrintableOptional, &absent, 19,
                                 NULL, 0, 0)) return 1;
    }
    {
        static uint8_t content[] = {'A'};
        T61String_t text = {content, sizeof(content)};
        SetT61Optional_t present = {0};
        present.value = &text;
        present.flag = 1;
        ASN_SET_MKPRESENT(present._presence_map, SetT61Optional_PR_value);
        ASN_SET_MKPRESENT(present._presence_map, SetT61Optional_PR_flag);
        if(check_optional_set(&asn_DEF_SetT61Optional, &present, 20,
                              content, sizeof(content), 1)) return 1;
    }
    {
        static uint8_t content[] = {'A'};
        ISO646String_t text = {content, sizeof(content)};
        SetISO646Optional_t present = {0};
        present.value = &text;
        present.flag = 1;
        ASN_SET_MKPRESENT(present._presence_map, SetISO646Optional_PR_value);
        ASN_SET_MKPRESENT(present._presence_map, SetISO646Optional_PR_flag);
        if(check_optional_set(&asn_DEF_SetISO646Optional, &present, 26,
                              content, sizeof(content), 1)) return 1;
    }
    return 0;
}
