/* Live C vectors for OBJECT IDENTIFIER fields in flat BER/CER records. */
/* Source: X.690 and the approved OID record slice. Date: 2026-11-01. */
/* Responsible party: asn1c maintainers. History: flat record OID vectors. */
#include <Sequence.h>
#include <Set.h>
#include <SetOptional.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CONTENT_MAX 1001
#define WIRE_MAX 4096

/*
 * Purpose: append a shortest definite length to a bounded output buffer.
 * Inputs: `output` is writable; `capacity` is available bytes; `length` is content.
 * Returns encoded byte count, or zero on capacity/representability failure.
 * Errors: lengths above 65535 and insufficient output storage fail.
 * Source: X.690 length form. Date: 2026-11-01. Responsible: asn1c maintainers.
 * History: OID record vectors. Example: 128 encodes as `81 80`.
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
 * Purpose: append one primitive TLV with a one-octet universal tag.
 * Inputs: destination/capacity bound output; tag and content describe the TLV.
 * Returns complete size, or zero on invalid pointers or insufficient space.
 * Errors: missing nonempty content and output exhaustion fail safely.
 * Source: X.690 TLV framing. Date: 2026-11-01. Responsible: asn1c maintainers.
 * History: C/Rust record comparison. Example: tag 6 wraps base-128 OID bytes.
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
 * Purpose: build expected Sequence DER or CER bytes from optional OID fields.
 * Inputs: output/capacity bound storage; oid/relative and flags give values;
 * `cer` selects indefinite root framing. Returns full size or zero on failure.
 * Errors: any bounded append failure aborts without writing past the buffer.
 * Source: OidRecord.asn1 and X.690. Date: 2026-11-01. Responsible: maintainers.
 * History: C/Rust vectors. Example: OID fields remain primitive in CER.
 */
static size_t
make_sequence(uint8_t *output, size_t capacity,
              const uint8_t *oid, size_t oid_size, int oid_present,
              const uint8_t *relative, size_t relative_size, int relative_present,
              int cer) {
    static const uint8_t boolean_value[] = {0xff};
    static const uint8_t integer_value[] = {2};
    static const uint8_t octet_value[] = {0xaa};
    uint8_t body[WIRE_MAX];
    size_t body_size = 0;
    size_t written;
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x01, boolean_value, sizeof(boolean_value));
    if(!written) return 0;
    body_size += written;
    if(oid_present) {
        written = append_tlv(body + body_size, sizeof(body) - body_size,
                             0x06, oid, oid_size);
        if(!written) return 0;
        body_size += written;
    }
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x02, integer_value, sizeof(integer_value));
    if(!written) return 0;
    body_size += written;
    if(relative_present) {
        written = append_tlv(body + body_size, sizeof(body) - body_size,
                             0x0d, relative, relative_size);
        if(!written) return 0;
        body_size += written;
    }
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x04, octet_value, sizeof(octet_value));
    if(!written) return 0;
    body_size += written;
    if(cer) {
        if(!output || capacity < body_size + 4) return 0;
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
 * Purpose: decode one candidate and compare semantic value and prefix length.
 * Inputs: syntax selects the decoder; descriptor/expected define type/value;
 * wire/size are input; consumed is the expected prefix size.
 * Returns zero on exact decode equality, otherwise one and frees partial data.
 * Errors: decode, compare callback, value, and consumption mismatches fail.
 * Source: generated C descriptor API. Date: 2026-11-01. Responsible: maintainers.
 * History: OID record prefix tests. Example: a suffix follows one root TLV.
 */
static int
decode_matches(enum asn_transfer_syntax syntax, asn_TYPE_descriptor_t *descriptor,
               const void *expected, const uint8_t *wire, size_t size,
               size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor,
                                       &decoded, wire, size);
    int failed = result.code != RC_OK || result.consumed != consumed || !decoded
        || !descriptor->op->compare_struct
        || (decoded && descriptor->op->compare_struct(descriptor, expected, decoded));
    if(failed)
        fprintf(stderr, "C OID record decode mismatch: syntax=%d consumed=%zu/%zu\n",
                (int)syntax, result.consumed, consumed);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: assert strict CER rejection and free any partial decoded value.
 * Inputs: descriptor selects record type; wire/size are the candidate prefix.
 * Returns one when CER unexpectedly succeeds, otherwise zero.
 * Errors: partial decoder allocations are released. Source: C CER adapter.
 * Date: 2026-11-01. Responsible: asn1c maintainers. History: canonicality tests.
 * Example: a reversed SET member order is rejected by strict CER.
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
 * Purpose: build canonical optional SET bytes with tag-sorted direct members.
 * Inputs: output/capacity bound storage; optional byte slices supply OID fields;
 * `cer` selects indefinite outer framing. Returns size or zero on failure.
 * Errors: bounded append failure aborts without overflowing a buffer.
 * Source: OidRecord.asn1 and X.690. Date: 2026-11-01. Responsible: maintainers.
 * History: optional OID SET. Example: absent OIDs leave only context tag 4.
 */
static size_t
make_optional_set(uint8_t *output, size_t capacity,
                  const uint8_t *oid, size_t oid_size, int oid_present,
                  const uint8_t *relative, size_t relative_size,
                  int relative_present, int cer) {
    static const uint8_t flag[] = {0xff};
    uint8_t body[WIRE_MAX];
    size_t body_size = 0;
    size_t written;
    if(oid_present) {
        written = append_tlv(body + body_size, sizeof(body) - body_size,
                             0x06, oid, oid_size);
        if(!written) return 0;
        body_size += written;
    }
    if(relative_present) {
        written = append_tlv(body + body_size, sizeof(body) - body_size,
                             0x0d, relative, relative_size);
        if(!written) return 0;
        body_size += written;
    }
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x84, flag, sizeof(flag));
    if(!written) return 0;
    body_size += written;
    if(cer) {
        if(!output || capacity < body_size + 4) return 0;
        output[0] = 0x31;
        output[1] = 0x80;
        memcpy(output + 2, body, body_size);
        output[body_size + 2] = 0;
        output[body_size + 3] = 0;
        return body_size + 4;
    }
    return append_tlv(output, capacity, 0x31, body, body_size);
}

/*
 * Purpose: compare C Sequence DER/CER encoders and BER/CER decoders.
 * Inputs: optional content and presence flags build one expected Sequence.
 * Returns zero on byte/value parity and correct suffix consumption.
 * Errors: any output/decode mismatch returns one and releases decoder storage.
 * Source: generated Sequence descriptor. Date: 2026-11-01. Responsible: maintainers.
 * History: OID record boundaries. Example: 1001 OID bytes remain primitive CER.
 */
static int
check_sequence(const uint8_t *oid, size_t oid_size, int oid_present,
               const uint8_t *relative, size_t relative_size,
               int relative_present) {
    static const uint8_t bytes_value[] = {0xaa};
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    OBJECT_IDENTIFIER_t oid_value = {(uint8_t *)oid, oid_size};
    RELATIVE_OID_t relative_value = {(uint8_t *)relative, relative_size};
    Sequence_t expected = {0};
    asn_enc_rval_t encoded;
    size_t der_size;
    size_t cer_size;
    expected.before = 1;
    expected.oid = oid_present ? &oid_value : NULL;
    expected.count = 2;
    expected.relative = relative_present ? &relative_value : NULL;
    expected.bytes.buf = (uint8_t *)bytes_value;
    expected.bytes.size = sizeof(bytes_value);
    der_size = make_sequence(der, sizeof(der), oid, oid_size, oid_present,
                             relative, relative_size, relative_present, 0);
    cer_size = make_sequence(cer, sizeof(cer), oid, oid_size, oid_present,
                             relative, relative_size, relative_present, 1);
    if(!der_size || !cer_size) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Sequence,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "C OID Sequence DER mismatch at lengths %zu/%zu\n",
                oid_size, relative_size);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Sequence,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "C OID Sequence CER mismatch at lengths %zu/%zu\n",
                oid_size, relative_size);
        return 1;
    }
    der[der_size] = 0xff;
    cer[cer_size] = 0xff;
    if(decode_matches(ATS_BER, &asn_DEF_Sequence, &expected,
                      der, der_size + 1, der_size)) return 1;
    if(decode_matches(ATS_BER, &asn_DEF_Sequence, &expected,
                      cer, cer_size + 1, cer_size)) return 1;
    if(decode_matches(ATS_CER, &asn_DEF_Sequence, &expected,
                      cer, cer_size + 1, cer_size)) return 1;
    if(cer_rejects(&asn_DEF_Sequence, der, der_size)) {
        fputs("C strict CER unexpectedly accepted definite OID Sequence\n", stderr);
        return 1;
    }
    return 0;
}

/*
 * Purpose: compare required OID fields and SET's canonical tag ordering.
 * Inputs: OID byte slices are canonical base-128 content.
 * Returns zero for C encoding, value decode, and unordered BER parity.
 * Errors: byte/value mismatch or strict CER acceptance returns one.
 * Source: generated Set descriptor and X.690. Date: 2026-11-01.
 * Responsible: asn1c maintainers. History: OID SET order vectors.
 * Example: tags 6, 13, and context 4 encode in that effective-tag order.
 */
static int
check_set(const uint8_t *oid, size_t oid_size,
          const uint8_t *relative, size_t relative_size) {
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t reversed[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    uint8_t body[WIRE_MAX];
    uint8_t reverse_body[WIRE_MAX];
    static const uint8_t boolean_value[] = {0xff};
    size_t body_size = 0;
    size_t reverse_size = 0;
    size_t written;
    size_t der_size;
    size_t cer_size;
    size_t reverse_wire_size;
    OBJECT_IDENTIFIER_t oid_value = {(uint8_t *)oid, oid_size};
    RELATIVE_OID_t relative_value = {(uint8_t *)relative, relative_size};
    Set_t expected = {0};
    asn_enc_rval_t encoded;
    expected.oid = oid_value;
    expected.relative = relative_value;
    expected.flag = 0xff;
    ASN_SET_MKPRESENT(expected._presence_map, Set_PR_oid);
    ASN_SET_MKPRESENT(expected._presence_map, Set_PR_relative);
    ASN_SET_MKPRESENT(expected._presence_map, Set_PR_flag);
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x06, oid, oid_size);
    if(!written) return 1;
    body_size += written;
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x0d, relative, relative_size);
    if(!written) return 1;
    body_size += written;
    written = append_tlv(body + body_size, sizeof(body) - body_size,
                         0x84, boolean_value, sizeof(boolean_value));
    if(!written) return 1;
    body_size += written;
    der_size = append_tlv(der, sizeof(der), 0x31, body, body_size);
    if(!der_size || body_size + 4 > sizeof(cer)) return 1;
    cer[0] = 0x31;
    cer[1] = 0x80;
    memcpy(cer + 2, body, body_size);
    cer[body_size + 2] = 0;
    cer[body_size + 3] = 0;
    cer_size = body_size + 4;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Set,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Set,
                                   &expected, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) return 1;
    if(decode_matches(ATS_BER, &asn_DEF_Set, &expected, der, der_size, der_size)) return 1;
    if(decode_matches(ATS_BER, &asn_DEF_Set, &expected, cer, cer_size, cer_size)) return 1;
    if(decode_matches(ATS_CER, &asn_DEF_Set, &expected, cer, cer_size, cer_size)) return 1;
    written = append_tlv(reverse_body + reverse_size, sizeof(reverse_body) - reverse_size,
                         0x84, boolean_value, sizeof(boolean_value));
    if(!written) return 1;
    reverse_size += written;
    written = append_tlv(reverse_body + reverse_size, sizeof(reverse_body) - reverse_size,
                         0x0d, relative, relative_size);
    if(!written) return 1;
    reverse_size += written;
    written = append_tlv(reverse_body + reverse_size, sizeof(reverse_body) - reverse_size,
                         0x06, oid, oid_size);
    if(!written || reverse_size + written + 4 > sizeof(reversed)) return 1;
    reverse_size += written;
    reversed[0] = 0x31;
    reversed[1] = 0x80;
    memcpy(reversed + 2, reverse_body, reverse_size);
    reversed[reverse_size + 2] = 0;
    reversed[reverse_size + 3] = 0;
    reverse_wire_size = reverse_size + 4;
    if(decode_matches(ATS_BER, &asn_DEF_Set, &expected,
                      reversed, reverse_wire_size, reverse_wire_size)) return 1;
    if(cer_rejects(&asn_DEF_Set, reversed, reverse_wire_size)) {
        fputs("C strict CER unexpectedly accepted reversed OID SET\n", stderr);
        return 1;
    }
    return 0;
}

/*
 * Purpose: verify all OPTIONAL OID SET states and unordered BER dispatch.
 * Inputs: canonical OID contents are used in the four presence combinations.
 * Returns zero for exact C DER/CER and decode parity; otherwise one.
 * Errors: encoding, comparison, presence, or canonicality failures return one.
 * Source: generated SetOptional descriptor. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: optional OID SET stage.
 * Example: the absent state emits only BOOLEAN under context tag 4.
 */
static int
check_optional_set(const uint8_t *oid, size_t oid_size,
                   const uint8_t *relative, size_t relative_size) {
    static const uint8_t reversed[] = {
        0x31, 0x80, 0x84, 1, 0xff, 0x0d, 2, 0x81, 0,
        0x06, 2, 0x2b, 3, 0, 0,
    };
    OBJECT_IDENTIFIER_t oid_value = {(uint8_t *)oid, oid_size};
    RELATIVE_OID_t relative_value = {(uint8_t *)relative, relative_size};
    size_t state;
    for(state = 0; state < 4; state++) {
        int oid_present = (state & 1) != 0;
        int relative_present = (state & 2) != 0;
        SetOptional_t expected = {0};
        uint8_t der[WIRE_MAX];
        uint8_t cer[WIRE_MAX];
        uint8_t actual[WIRE_MAX];
        size_t der_size;
        size_t cer_size;
        asn_enc_rval_t encoded;
        expected.oid = oid_present ? &oid_value : NULL;
        expected.relative = relative_present ? &relative_value : NULL;
        expected.flag = 0xff;
        ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_flag);
        if(oid_present) ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_oid);
        if(relative_present)
            ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_relative);
        der_size = make_optional_set(der, sizeof(der), oid, oid_size, oid_present,
                                     relative, relative_size, relative_present, 0);
        cer_size = make_optional_set(cer, sizeof(cer), oid, oid_size, oid_present,
                                     relative, relative_size, relative_present, 1);
        if(!der_size || !cer_size) return 1;
        encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_SetOptional,
                                       &expected, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
           || memcmp(actual, der, der_size)) return 1;
        encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_SetOptional,
                                       &expected, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
           || memcmp(actual, cer, cer_size)) return 1;
        if(decode_matches(ATS_BER, &asn_DEF_SetOptional, &expected,
                          der, der_size, der_size)) return 1;
        if(decode_matches(ATS_BER, &asn_DEF_SetOptional, &expected,
                          cer, cer_size, cer_size)) return 1;
        if(decode_matches(ATS_CER, &asn_DEF_SetOptional, &expected,
                          cer, cer_size, cer_size)) return 1;
    }
    {
        SetOptional_t expected = {0};
        expected.oid = &oid_value;
        expected.relative = &relative_value;
        expected.flag = 0xff;
        ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_oid);
        ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_relative);
        ASN_SET_MKPRESENT(expected._presence_map, SetOptional_PR_flag);
        if(decode_matches(ATS_BER, &asn_DEF_SetOptional, &expected,
                          reversed, sizeof(reversed), sizeof(reversed))) return 1;
        return cer_rejects(&asn_DEF_SetOptional, reversed, sizeof(reversed));
    }
}

/*
 * Purpose: compare C BER's preserved OID content in canonical record framing.
 * Inputs: wire and expected sizes describe one Sequence carrying malformed OID.
 * Returns zero when BER preserves exact raw bytes; otherwise one.
 * Errors: decode, prefix, or content mismatch fails; allocated data is freed.
 * Source: C OID decoder probe. Date: 2026-11-01. Responsible: asn1c maintainers.
 * History: C/Rust invalid-content divergence. Example: empty OID BER can decode.
 */
static int
check_ber_oid_raw(const uint8_t *wire, size_t wire_size,
                  const uint8_t *expected, size_t oid_size, int relative) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Sequence,
                                       &decoded, wire, wire_size);
    Sequence_t *value = decoded;
    OBJECT_IDENTIFIER_t *oid_value = NULL;
    int failed;
    if(value) oid_value = relative ? (OBJECT_IDENTIFIER_t *)value->relative : value->oid;
    failed = result.code != RC_OK || result.consumed != wire_size || !oid_value
        || oid_value->size != oid_size;
    if(!failed && oid_size && (!oid_value->buf
       || memcmp(oid_value->buf, expected, oid_size))) failed = 1;
    if(failed)
        fprintf(stderr, "C BER raw OID record mismatch: consumed=%zu/%zu\n",
                result.consumed, wire_size);
    if(decoded)
        asn_DEF_Sequence.op->free_struct(&asn_DEF_Sequence, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: exercise canonical boundary vectors, optional states, and C BER quirks.
 * Inputs: none. Returns zero when all configured live C checks pass.
 * Errors: any failed C codec assertion returns one with a diagnostic where useful.
 * Source: OidRecord schema and C OID probes. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: OID record conformance stage.
 * Example: test 1001-byte OBJECT IDENTIFIER content in both DER and CER.
 */
int
main(void) {
    static const uint8_t oid_simple[] = {0x2b, 0x03};
    static const uint8_t relative_simple[] = {0x81, 0x00};
    static const uint8_t oid_large_arc[] = {
        0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    };
    static const uint8_t empty_oid[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x06, 0, 0x02, 1, 2, 0x04, 1, 0xaa, 0, 0,
    };
    static const uint8_t dangling_relative[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x02, 1, 2,
        0x0d, 1, 0x80, 0x04, 1, 0xaa, 0, 0,
    };
    static const uint8_t redundant_oid[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x06, 2, 0x80, 0x2b,
        0x02, 1, 2, 0x04, 1, 0xaa, 0, 0,
    };
    static const uint8_t redundant_relative[] = {
        0x30, 0x80, 0x01, 1, 0xff, 0x02, 1, 2,
        0x0d, 2, 0x80, 0x00, 0x04, 1, 0xaa, 0, 0,
    };
    uint8_t large[CONTENT_MAX] = {0};
    size_t lengths[] = {1, 2, 11, 127, 128, 1001};
    size_t index;
    if(check_sequence(oid_simple, sizeof(oid_simple), 1,
                      relative_simple, sizeof(relative_simple), 1)) {
        fputs("C OID Sequence present vector failed\n", stderr);
        return 1;
    }
    if(check_sequence(oid_simple, sizeof(oid_simple), 0,
                      relative_simple, sizeof(relative_simple), 0)) {
        fputs("C OID Sequence absent vector failed\n", stderr);
        return 1;
    }
    if(check_sequence(oid_simple, sizeof(oid_simple), 1,
                      relative_simple, sizeof(relative_simple), 0)) {
        fputs("C OID Sequence OID-only vector failed\n", stderr);
        return 1;
    }
    if(check_sequence(oid_simple, sizeof(oid_simple), 0,
                      relative_simple, sizeof(relative_simple), 1)) {
        fputs("C OID Sequence relative-only vector failed\n", stderr);
        return 1;
    }
    if(check_sequence(oid_large_arc, sizeof(oid_large_arc), 1,
                      relative_simple, sizeof(relative_simple), 1)) {
        fputs("C OID large-arc Sequence failed\n", stderr);
        return 1;
    }
    if(check_set(oid_simple, sizeof(oid_simple),
                 relative_simple, sizeof(relative_simple))) {
        fputs("C OID SET vector failed\n", stderr);
        return 1;
    }
    if(check_optional_set(oid_simple, sizeof(oid_simple),
                          relative_simple, sizeof(relative_simple))) {
        fputs("C OPTIONAL OID SET vectors failed\n", stderr);
        return 1;
    }
    for(index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
        if(check_sequence(large, lengths[index], 1,
                          large, lengths[index], 1)) {
            fprintf(stderr, "C OID large Sequence failed at %zu octets\n",
                    lengths[index]);
            return 1;
        }
    }
    if(check_ber_oid_raw(empty_oid, sizeof(empty_oid), NULL, 0, 0)
       || check_ber_oid_raw(dangling_relative, sizeof(dangling_relative),
                            (uint8_t[]){0x80}, 1, 1)
       || check_ber_oid_raw(redundant_oid, sizeof(redundant_oid),
                            (uint8_t[]){0x80, 0x2b}, 2, 0)
       || check_ber_oid_raw(redundant_relative, sizeof(redundant_relative),
                            (uint8_t[]){0x80, 0}, 2, 1)) {
        fputs("C BER malformed OID record probe failed\n", stderr);
        return 1;
    }
    if(cer_rejects(&asn_DEF_Sequence, empty_oid, sizeof(empty_oid))
       || cer_rejects(&asn_DEF_Sequence, dangling_relative, sizeof(dangling_relative))
       || cer_rejects(&asn_DEF_Sequence, redundant_oid, sizeof(redundant_oid))
       || cer_rejects(&asn_DEF_Sequence, redundant_relative,
                      sizeof(redundant_relative))) {
        fputs("C strict CER accepted malformed or nonminimal OID record content\n", stderr);
        return 1;
    }
    return 0;
}
