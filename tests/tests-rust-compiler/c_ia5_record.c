/* Live C vectors for IA5String fields in flat BER/CER records. */
/* Source: approved X.690 vectors. Version/date: 2026-11-01. */
/* Responsible party: asn1c maintainers. History: IA5 record stage. */
#include <Sequence.h>
#include <Set.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 4096

/*
 * Purpose: append a shortest definite length to a bounded test buffer.
 * Parameters: output has capacity; length is the content byte count.
 * Returns encoded length-field size, or zero if capacity is insufficient.
 * Errors: oversized length is rejected. Source: X.690 length encoding.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: IA5 record vectors. Example: 1001 encodes as `82 03 e9`.
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
 * Purpose: append a definite primitive TLV with one-octet tag.
 * Parameters: output/capacity are destination; tag and content describe value.
 * Returns complete size, or zero when output capacity is insufficient.
 * Errors: missing content for nonempty length and exhausted capacity fail.
 * Source: X.690 primitive framing. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: record vectors.
 * Example: IA5 tag 22 and `A` produce `16 01 41`.
 */
static size_t
append_tlv(uint8_t *output, size_t capacity, uint8_t tag,
           const uint8_t *content, size_t length) {
    size_t length_size;
    if(!output || capacity < 1 || (length && !content)) return 0;
    length_size = append_length(output + 1, capacity - 1, length);
    if(!length_size || length > capacity - 1 - length_size) return 0;
    output[0] = tag;
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: append canonical IA5String CER framing and universal OCTET fragments.
 * Parameters: output/capacity receive bytes; content/length are raw IA5 data.
 * Returns total size, or zero on insufficient output capacity.
 * Errors: invalid destination/content ranges and capacity exhaustion fail.
 * Source: X.690 CER string fragmentation. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: 1000-octet cutover.
 * Example: 1001 bytes become tag 36 with tag-4 fragments of 1000 and 1.
 */
static size_t
append_cer_ia5(uint8_t *output, size_t capacity,
               const uint8_t *content, size_t length) {
    size_t offset = 0;
    size_t index;
    if(length <= 1000) return append_tlv(output, capacity, 0x16, content, length);
    if(!output || !content || capacity < 4) return 0;
    output[0] = 0x36;
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
 * Purpose: append one sequence vector with fixed BOOLEAN, INTEGER, and OCTET fields.
 * Parameters: output is destination; content/length describe optional IA5;
 * `present` selects OPTIONAL presence and `cer` selects canonical framing.
 * Returns complete root size, or zero when a helper runs out of buffer space.
 * Errors: insufficient output capacity fails. Source: Ia5Record schema.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: live C/Rust record parity. Example: absent IA5 omits tag 22.
 */
static size_t
make_sequence(uint8_t *output, size_t capacity, const uint8_t *content,
              size_t length, int present, int cer) {
    static const uint8_t boolean_content[] = {0xff};
    static const uint8_t integer_content[] = {2};
    static const uint8_t octet_content[] = {0xaa};
    uint8_t body[WIRE_MAX];
    size_t body_size = 0;
    size_t written;
    if(!output || capacity < 4) return 0;
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x01, boolean_content, sizeof(boolean_content));
    if(!written) return 0;
    body_size += written;
    if(present) {
        written = cer
            ? append_cer_ia5(body + body_size, sizeof(body) - body_size, content, length)
            : append_tlv(body + body_size, sizeof(body) - body_size, 0x16,
                         content, length);
        if(!written) return 0;
        body_size += written;
    }
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x02, integer_content, sizeof(integer_content));
    if(!written) return 0;
    body_size += written;
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x04, octet_content, sizeof(octet_content));
    if(!written) return 0;
    body_size += written;
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
 * Purpose: decode one candidate against a generated descriptor and value.
 * Parameters: syntax selects BER/CER; descriptor/expected identify value;
 * wire/size are input; consumed is expected prefix length.
 * Returns zero for exact successful value/prefix parity, otherwise one.
 * Errors: decoder failures or compare mismatches fail and release storage.
 * Source: generated C decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: record prefix tests.
 * Example: a suffix remains after one decoded record.
 */
static int
decode_value(enum asn_transfer_syntax syntax, asn_TYPE_descriptor_t *descriptor,
             const void *expected, const uint8_t *wire, size_t size,
             size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor,
                                       &decoded, wire, size);
    int failed = result.code != RC_OK || result.consumed != consumed || !decoded
        || !descriptor->op->compare_struct
        || (decoded && descriptor->op->compare_struct(descriptor, expected, decoded));
    if(failed)
        fprintf(stderr, "C record decode mismatch: syntax=%d consumed=%zu/%zu\n",
                (int)syntax, result.consumed, consumed);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: require strict CER rejection for a complete candidate value.
 * Parameters: descriptor selects generated type; wire/size supply candidate.
 * Returns zero when rejected, one on unexpected successful decode.
 * Errors: partial decode values are always freed. Source: C strict CER adapter.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: canonicality checks. Example: definite DER record is not strict CER.
 */
static int
cer_rejects(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, descriptor,
                                       &decoded, wire, size);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code == RC_OK;
}

/*
 * Purpose: compare C encoding and decoding for one IA5-bearing Sequence.
 * Parameters: content/length define present IA5 data; present controls its
 * OPTIONAL pointer. Returns zero for exact DER/CER and decoded-value matches.
 * Errors: encoding, framing, value, or prefix mismatch returns one.
 * Source: generated Sequence descriptor and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: live boundary matrix.
 * Example: run with 1001 bytes to check constructed CER fragments.
 */
static int
check_sequence(const uint8_t *content, size_t length, int present) {
    static const uint8_t byte_content[] = {0xaa};
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    uint8_t empty_storage = 0;
    IA5String_t text = {(uint8_t *)(length ? content : &empty_storage), length};
    Sequence_t expected = {0};
    asn_enc_rval_t encoded;
    size_t der_size;
    size_t cer_size;
    expected.before = 1;
    expected.text = present ? &text : NULL;
    expected.count = 2;
    expected.bytes.buf = (uint8_t *)byte_content;
    expected.bytes.size = sizeof(byte_content);
    der_size = make_sequence(der, sizeof(der), content, length, present, 0);
    cer_size = make_sequence(cer, sizeof(cer), content, length, present, 1);
    if(!der_size || !cer_size) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Sequence,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "C Sequence DER mismatch at IA5 length %zu\n", length);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Sequence,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "C Sequence CER mismatch at IA5 length %zu\n", length);
        return 1;
    }
    der[der_size] = 0xff;
    cer[cer_size] = 0xff;
    if(decode_value(ATS_BER, &asn_DEF_Sequence, &expected, der,
                    der_size + 1, der_size)) return 1;
    if(decode_value(ATS_BER, &asn_DEF_Sequence, &expected, cer,
                    cer_size + 1, cer_size)) return 1;
    if(decode_value(ATS_CER, &asn_DEF_Sequence, &expected, cer,
                    cer_size + 1, cer_size)) return 1;
    return cer_rejects(&asn_DEF_Sequence, der, der_size);
}

/*
 * Purpose: verify canonical C SET bytes and unordered BER dispatch.
 * Parameters: none. Returns zero for expected DER/CER and decode behavior.
 * Errors: output/value mismatch or strict CER acceptance returns one.
 * Source: X.690 SET order and C descriptor probes. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural tag-22 SET member.
 * Example: IA5 tag 22 sorts before context-specific tag 4.
 */
static int
check_set(void) {
    static const uint8_t letter[] = {'A'};
    static const uint8_t der[] = {0x31, 0x06, 0x16, 1, 'A', 0x84, 1, 0xff};
    static const uint8_t cer[] = {
        0x31, 0x80, 0x16, 1, 'A', 0x84, 1, 0xff, 0, 0,
    };
    static const uint8_t reversed[] = {
        0x31, 0x80, 0x84, 1, 0xff, 0x16, 1, 'A', 0, 0,
    };
    uint8_t actual[32];
    Set_t expected = {0};
    asn_enc_rval_t encoded;
    expected.text.buf = (uint8_t *)letter;
    expected.text.size = sizeof(letter);
    expected.flag = 0xff;
    ASN_SET_MKPRESENT(expected._presence_map, Set_PR_text);
    ASN_SET_MKPRESENT(expected._presence_map, Set_PR_flag);
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Set,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)sizeof(der) || memcmp(actual, der, sizeof(der))) {
        fputs("C IA5 SET DER mismatch\n", stderr);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Set,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)sizeof(cer) || memcmp(actual, cer, sizeof(cer))) {
        fputs("C IA5 SET CER mismatch\n", stderr);
        return 1;
    }
    if(decode_value(ATS_BER, &asn_DEF_Set, &expected, der, sizeof(der), sizeof(der)))
        return 1;
    if(decode_value(ATS_BER, &asn_DEF_Set, &expected, cer, sizeof(cer), sizeof(cer)))
        return 1;
    if(decode_value(ATS_CER, &asn_DEF_Set, &expected, cer, sizeof(cer), sizeof(cer)))
        return 1;
    if(decode_value(ATS_BER, &asn_DEF_Set, &expected,
                    reversed, sizeof(reversed), sizeof(reversed))) return 1;
    if(cer_rejects(&asn_DEF_Set, der, sizeof(der))) return 1;
    return cer_rejects(&asn_DEF_Set, reversed, sizeof(reversed));
}

/*
 * Purpose: check constructed BER IA5 fragments and malformed child rejection.
 * Parameters: none. Returns zero when C decodes flattened AB and rejects tag 22.
 * Errors: decode/value/prefix mismatches return one and release allocated data.
 * Source: C IA5 decoder probes. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: flat-record fragment coverage.
 * Example: constructed tag 36 contains universal OCTET STRING fragments.
 */
static int
check_constructed_ber(void) {
    static const uint8_t wire[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x36, 0x80,
        0x04, 0x01, 'A', 0x04, 0x01, 'B', 0, 0,
        0x02, 0x01, 2, 0x04, 0x01, 0xaa, 0, 0,
    };
    static const uint8_t bad_child[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x36, 0x80,
        0x16, 0x01, 'A', 0, 0, 0x02, 0x01, 2,
        0x04, 0x01, 0xaa, 0, 0,
    };
    static const uint8_t expected_content[] = {'A', 'B'};
    static const uint8_t bytes[] = {0xaa};
    IA5String_t text = {(uint8_t *)expected_content, sizeof(expected_content)};
    Sequence_t expected = {0};
    void *decoded = NULL;
    asn_dec_rval_t result;
    expected.before = 1;
    expected.text = &text;
    expected.count = 2;
    expected.bytes.buf = (uint8_t *)bytes;
    expected.bytes.size = sizeof(bytes);
    if(decode_value(ATS_BER, &asn_DEF_Sequence, &expected,
                    wire, sizeof(wire), sizeof(wire))) return 1;
    if(cer_rejects(&asn_DEF_Sequence, wire, sizeof(wire))) {
        fputs("C unexpectedly accepted noncanonical constructed IA5 CER\n", stderr);
        return 1;
    }
    result = asn_decode(NULL, ATS_BER, &asn_DEF_Sequence,
                       &decoded, bad_child, sizeof(bad_child));
    if(decoded) {
        asn_DEF_Sequence.op->free_struct(&asn_DEF_Sequence, decoded,
                                         ASFM_FREE_EVERYTHING);
    }
    return result.code == RC_OK;
}

/*
 * Purpose: preserve arbitrary IA5 bytes in BER/DER but reject them in CER.
 * Parameters: none. Returns zero when C matches the documented behavior.
 * Errors: encode/decode mismatch returns one. Source: C IA5 descriptor timing.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: invalid repertoire within a record. Example: byte 80 remains raw.
 */
static int
check_high_byte(void) {
    static const uint8_t high[] = {0x80};
    static const uint8_t der[] = {
        0x30, 0x0c, 0x01, 1, 0xff, 0x16, 1, 0x80,
        0x02, 1, 2, 0x04, 1, 0xaa,
    };
    static const uint8_t cer_framing[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x16, 1, 0x80,
        0x02, 1, 2, 0x04, 1, 0xaa, 0, 0,
    };
    uint8_t actual[32];
    IA5String_t text = {(uint8_t *)high, sizeof(high)};
    static const uint8_t byte_content[] = {0xaa};
    Sequence_t expected = {0};
    asn_enc_rval_t encoded;
    expected.before = 1;
    expected.text = &text;
    expected.count = 2;
    expected.bytes.buf = (uint8_t *)byte_content;
    expected.bytes.size = sizeof(byte_content);
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Sequence,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)sizeof(der) || memcmp(actual, der, sizeof(der))) return 1;
    if(decode_value(ATS_BER, &asn_DEF_Sequence, &expected,
                    der, sizeof(der), sizeof(der))) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Sequence,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded >= 0) return 1;
    if(decode_value(ATS_BER, &asn_DEF_Sequence, &expected, cer_framing,
                    sizeof(cer_framing), sizeof(cer_framing))) return 1;
    if(cer_rejects(&asn_DEF_Sequence, cer_framing, sizeof(cer_framing))) return 1;
    return 0;
}

/*
 * Purpose: compare every configured IA5 content boundary and invalid byte.
 * Parameters: none. Returns zero on all live C checks; otherwise one.
 * Errors: any vector mismatch propagates from helpers. Source: C/Rust vectors.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: IA5 flat-record support. Example: test lengths around CER's 1000.
 */
int
main(void) {
    static const size_t lengths[] = {0, 1, 127, 128, 999, 1000, 1001, 2001};
    uint8_t content[2001];
    size_t index;
    memset(content, 'A', sizeof(content));
    for(index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
        if(check_sequence(content, lengths[index], 1)) {
            fprintf(stderr, "C IA5 sequence vector failed at length %zu\n", lengths[index]);
            return 1;
        }
    }
    if(check_sequence(content, 1, 0)) {
        fputs("C IA5 OPTIONAL-absent sequence failed\n", stderr);
        return 1;
    }
    if(check_set()) return 1;
    if(check_high_byte()) {
        fputs("C IA5 high-byte BER/DER behavior mismatch\n", stderr);
        return 1;
    }
    if(check_constructed_ber()) {
        fputs("C constructed IA5 BER behavior mismatch\n", stderr);
        return 1;
    }
    return 0;
}
