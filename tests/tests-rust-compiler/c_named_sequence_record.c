/* Live C/Rust vectors for a named SEQUENCE child in flat records. */
/* Source: X.680/X.690 descriptors and approved nested-record slice. */
/* Date: 2026-11-01. Responsible party: asn1c maintainers. */
#include <Inner.h>
#include <Packet.h>
#include <PacketLeaves.h>
#include <SequenceExplicit.h>
#include <SequenceImplicit.h>
#include <SequenceOptional.h>
#include <SetDefaults.h>
#include <SetExplicit.h>
#include <SetImplicit.h>
#include <SetOptional.h>
#include <SetPacket.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 64

/*
 * Purpose: compare C DER/CER output and decoded record values against vectors.
 * Inputs: descriptor/expected select a populated value; DER/CER are exact TLVs.
 * Returns zero when encoding, BER, strict CER, prefix, and value checks pass.
 * Errors: codec, prefix, byte, or semantic mismatches return one.
 * Source: generated C descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named child differential.
 * Example: check_vector(&asn_DEF_Packet, &value, der, sizeof der, cer, sizeof cer).
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor, const void *expected,
             const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    uint8_t actual[WIRE_MAX];
    uint8_t suffixed[WIRE_MAX];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    void *decoded = NULL;
    size_t available;
    if(!descriptor || !expected || !der || !cer || der_size > sizeof(actual)
       || cer_size + 1 > sizeof(suffixed) || !descriptor->op->compare_struct) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "DER mismatch %s: %zd/%zu\n", descriptor->name,
                encoded.encoded, der_size);
        goto fail;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "CER mismatch %s: %zd/%zu\n", descriptor->name,
                encoded.encoded, cer_size);
        goto fail;
    }
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, der, der_size);
    if(result.code != RC_OK || result.consumed != der_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) {
        fprintf(stderr, "BER DER-value mismatch %s: status=%d consumed=%zu/%zu\n",
                descriptor->name, result.code, result.consumed, der_size);
        goto fail;
    }
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, cer, cer_size);
    if(result.code != RC_OK || result.consumed != cer_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) {
        fprintf(stderr, "BER CER-value mismatch %s: status=%d consumed=%zu/%zu\n",
                descriptor->name, result.code, result.consumed, cer_size);
        goto fail;
    }
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, cer, cer_size);
    if(result.code != RC_OK || result.consumed != cer_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) {
        fprintf(stderr, "strict CER mismatch %s: status=%d consumed=%zu/%zu\n",
                descriptor->name, result.code, result.consumed, cer_size);
        goto fail;
    }
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, der, der_size);
    if(result.code == RC_OK) {
        fprintf(stderr, "strict CER accepted DER %s\n", descriptor->name);
        goto fail;
    }
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    available = cer_size + 1;
    memcpy(suffixed, cer, cer_size);
    suffixed[cer_size] = 0x5a;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, suffixed, available);
    if(result.code != RC_OK || result.consumed != cer_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) {
        fprintf(stderr, "strict CER suffix mismatch %s: status=%d consumed=%zu/%zu\n",
                descriptor->name, result.code, result.consumed, cer_size);
        goto fail;
    }
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return 0;
fail:
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    fprintf(stderr, "named SEQUENCE C vector failed for %s\n", descriptor->name);
    return 1;
}

/*
 * Purpose: decode a SET permutation with BER and require strict CER rejection.
 * Inputs: expected is the semantic value; wire is the permuted BER SET prefix.
 * Returns zero on exact BER value/consumption and CER rejection.
 * Errors: status, field, value, or canonicality mismatch returns one.
 * Source: generated SET descriptor and X.690. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: unordered child dispatch.
 * Example: fields arrive context-4, context-0, then universal child.
 */
static int
check_set_permutation(const SetPacket_t *expected, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    void *strict = NULL;
    asn_dec_rval_t ber = asn_decode(NULL, ATS_BER, &asn_DEF_SetPacket,
                                    &decoded, wire, size);
    asn_dec_rval_t cer = asn_decode(NULL, ATS_CER, &asn_DEF_SetPacket,
                                    &strict, wire, size);
    int failed = ber.code != RC_OK || ber.consumed != size || !decoded
        || asn_DEF_SetPacket.op->compare_struct(&asn_DEF_SetPacket, expected, decoded)
        || cer.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetPacket, decoded);
    if(strict) ASN_STRUCT_FREE(asn_DEF_SetPacket, strict);
    if(failed) fprintf(stderr, "named SEQUENCE SET permutation mismatch\n");
    return failed;
}

/*
 * Purpose: require one malformed child frame to fail under the selected syntax.
 * Inputs: syntax/wire/size select a decoder invocation. Returns zero on reject.
 * Errors: partial decoded storage is released; unexpected acceptance returns one.
 * Source: generated C descriptors. Date: 2026-11-01. Responsible: maintainers.
 * History: nested boundary validation. Example: reject a missing child EOC.
 */
static int
check_rejected(asn_TYPE_descriptor_t *descriptor, enum asn_transfer_syntax syntax,
               const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor, &decoded, wire, size);
    int failed = result.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "C unexpectedly accepted malformed %s input\n", descriptor->name);
    return failed;
}

/*
 * Purpose: accept a BER child-tag alias and require strict CER canonical rejection.
 * Inputs: descriptor/expected select type and value; wire is the alias form.
 * Returns zero when BER consumes the value and CER rejects the alias.
 * Errors: status, prefix, value, or canonicality mismatch returns one.
 * Source: generated C descriptors and BER alias probes. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: nested identifier aliases.
 * Example: constructed universal high-tag `3f 10` aliases SEQUENCE tag 16.
 */
static int
check_ber_alias(asn_TYPE_descriptor_t *descriptor, const void *expected,
                const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    void *strict = NULL;
    asn_dec_rval_t ber = asn_decode(NULL, ATS_BER, descriptor, &decoded, wire, size);
    asn_dec_rval_t cer = asn_decode(NULL, ATS_CER, descriptor, &strict, wire, size);
    int failed = ber.code != RC_OK || ber.consumed != size || !decoded
        || descriptor->op->compare_struct(descriptor, expected, decoded) || cer.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(strict) descriptor->op->free_struct(descriptor, strict, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "C BER child alias mismatch for %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: distinguish C BER parsing from the later target range constraint.
 * Inputs: none. Returns zero when BER parses value 6 and constraint checking rejects.
 * Errors: status, consumption, decoded fields, or constraint mismatch returns one.
 * Source: generated INTEGER (0..5) target descriptor. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: nested range timing.
 * Example: BER accepts the wire; `asn_check_constraints` reports value 6 invalid.
 */
static int
check_out_of_range(void) {
    static const uint8_t wire[] = {
        0x30, 0x0b, 0x30, 0x06, 0x02, 0x01, 0x06, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    Packet_t *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Packet,
                                       (void **)&decoded, wire, sizeof(wire));
    char diagnostic[128];
    size_t diagnostic_size = sizeof(diagnostic);
    int failed = result.code != RC_OK || result.consumed != sizeof(wire) || !decoded
        || !decoded->child || decoded->child->number != 6 || !decoded->after
        || asn_check_constraints(&asn_DEF_Packet, decoded, diagnostic,
                                 &diagnostic_size) == 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    if(failed) fprintf(stderr, "C nested INTEGER constraint timing mismatch\n");
    return failed;
}

/*
 * Purpose: verify C encoder parity and framing for all named-child forms.
 * Inputs: none. Returns zero on all canonical vectors and malformed checks.
 * Errors: any exact wire/value, rejection, or constraint check mismatch returns one.
 * Source: generated C descriptors and approved vectors. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named SEQUENCE composition.
 * Example: the natural child is one shared-context nested SEQUENCE.
 */
int
main(void) {
    static const uint8_t packet_der[] = {
        0x30, 0x0b, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t packet_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    };
    static const uint8_t packet_child_alias[] = {
        0x30, 0x80, 0x3f, 0x10, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    };
    static const uint8_t leaves_der[] = {
        0x30, 0x12, 0x30, 0x10, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x0a, 0x01, 0x01,
        0x81, 0x01, 0xaa, 0x03, 0x02, 0x03, 0xa0,
    };
    static const uint8_t leaves_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x0a, 0x01, 0x01,
        0x81, 0x01, 0xaa, 0x03, 0x02, 0x03, 0xa0, 0, 0, 0, 0,
    };
    static const uint8_t packet_primitive_child_alias[] = {
        0x30, 0x80, 0x1f, 0x10, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84,
        0x01, 0xff, 0, 0,
    };
    static const uint8_t implicit_der[] = {
        0x30, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t implicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    };
    static const uint8_t set_implicit_der[] = {
        0x31, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t set_implicit_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    };
    static const uint8_t set_explicit_der[] = {
        0x31, 0x0d, 0xa3, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01,
        0xff,
    };
    static const uint8_t set_explicit_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0,
        0, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t set_optional_der[] = {0x31, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t set_optional_cer[] = {0x31, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t set_optional_present_der[] = {
        0x31, 0x0b, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t set_optional_present_cer[] = {
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    };
    static const uint8_t set_defaults_der[] = {
        0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff,
    };
    static const uint8_t set_defaults_cer[] = {
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t set_defaults_nondefault_der[] = {
        0x31, 0x0e, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x30, 0x06, 0x02, 0x01, 0x02,
        0x01, 0x01, 0xff,
    };
    static const uint8_t set_defaults_nondefault_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x30, 0x80, 0x02, 0x01, 0x02,
        0x01, 0x01, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t explicit_der[] = {
        0x30, 0x0d, 0xa3, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff,
        0x84, 0x01, 0xff,
    };
    static const uint8_t explicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff,
        0, 0, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t explicit_mixed_lengths[] = {
        0x30, 0x80, 0xa3, 0x0a, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t optional_der[] = {0x30, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t optional_cer[] = {0x30, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t set_der[] = {
        0x31, 0x0e, 0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0x80, 0x01, 0xff,
        0x84, 0x01, 0xff,
    };
    static const uint8_t set_cer[] = {
        0x31, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0, 0x80, 0x01,
        0xff, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t set_reversed[] = {
        0x31, 0x80, 0x84, 0x01, 0xff, 0x80, 0x01, 0xff, 0x30, 0x80, 0x02, 0x01, 0x02,
        0x01, 0x01, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t bad_eoc[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x02, 0, 0, 0, 0,
    };
    Inner_t inner = {.number = 2, .flag = 0xff};
    long count_nondefault = 3;
    uint8_t data_byte = 0xaa;
    uint8_t bits_byte = 0xa0;
    InnerLeaves_t leaves = {
        .number = 2,
        .flag = 0xff,
        .mode = 1,
        .data = {.buf = &data_byte, .size = 1},
        .bits = {.buf = &bits_byte, .size = 1, .bits_unused = 3},
    };
    PacketLeaves_t packet_leaves = {.child = &leaves};
    Packet_t packet = {.child = &inner, .after = 0xff};
    SequenceImplicit_t implicit = {.child = &inner, .after = 0xff};
    SequenceExplicit_t explicit_value = {.child = &inner, .after = 0xff};
    SequenceOptional_t optional = {.after = 0xff};
    SequenceOptional_t optional_present = {.child = &inner, .after = 0xff};
    SetPacket_t set = {.child = &inner, .after = 0xff, .before = 0xff};
    SetImplicit_t set_implicit = {.child = &inner, .after = 0xff};
    SetExplicit_t set_explicit = {.child = &inner, .after = 0xff};
    SetOptional_t set_optional = {.after = 0xff};
    SetOptional_t set_optional_present = {.child = &inner, .after = 0xff};
    SetDefaults_t set_defaults = {
        .child = &inner, .enabled = 0, .count = NULL,
    };
    SetDefaults_t set_defaults_nondefault = {
        .child = &inner, .enabled = 0xff, .count = &count_nondefault,
    };
    int failed = 0;
    failed |= check_vector(&asn_DEF_Packet, &packet, packet_der, sizeof(packet_der),
                           packet_cer, sizeof(packet_cer));
    failed |= check_vector(&asn_DEF_PacketLeaves, &packet_leaves, leaves_der,
                           sizeof(leaves_der), leaves_cer, sizeof(leaves_cer));
    failed |= check_ber_alias(&asn_DEF_Packet, &packet, packet_child_alias,
                              sizeof(packet_child_alias));
    failed |= check_rejected(&asn_DEF_Packet, ATS_BER, packet_primitive_child_alias,
                             sizeof(packet_primitive_child_alias));
    failed |= check_vector(&asn_DEF_SequenceImplicit, &implicit, implicit_der,
                           sizeof(implicit_der), implicit_cer, sizeof(implicit_cer));
    failed |= check_vector(&asn_DEF_SequenceExplicit, &explicit_value, explicit_der,
                           sizeof(explicit_der), explicit_cer, sizeof(explicit_cer));
    failed |= check_rejected(&asn_DEF_SequenceExplicit, ATS_BER, explicit_mixed_lengths,
                             sizeof(explicit_mixed_lengths));
    failed |= check_vector(&asn_DEF_SequenceOptional, &optional, optional_der,
                           sizeof(optional_der), optional_cer, sizeof(optional_cer));
    failed |= check_vector(&asn_DEF_SequenceOptional, &optional_present, packet_der,
                           sizeof(packet_der), packet_cer, sizeof(packet_cer));
    ASN_SET_MKPRESENT(set._presence_map, SetPacket_PR_after);
    ASN_SET_MKPRESENT(set._presence_map, SetPacket_PR_child);
    ASN_SET_MKPRESENT(set._presence_map, SetPacket_PR_before);
    failed |= check_vector(&asn_DEF_SetPacket, &set, set_der, sizeof(set_der),
                           set_cer, sizeof(set_cer));
    failed |= check_set_permutation(&set, set_reversed, sizeof(set_reversed));
    ASN_SET_MKPRESENT(set_implicit._presence_map, SetImplicit_PR_child);
    ASN_SET_MKPRESENT(set_implicit._presence_map, SetImplicit_PR_after);
    ASN_SET_MKPRESENT(set_explicit._presence_map, SetExplicit_PR_child);
    ASN_SET_MKPRESENT(set_explicit._presence_map, SetExplicit_PR_after);
    ASN_SET_MKPRESENT(set_optional._presence_map, SetOptional_PR_after);
    ASN_SET_MKPRESENT(set_optional_present._presence_map, SetOptional_PR_after);
    ASN_SET_MKPRESENT(set_optional_present._presence_map, SetOptional_PR_child);
    ASN_SET_MKPRESENT(set_defaults._presence_map, SetDefaults_PR_child);
    ASN_SET_MKPRESENT(set_defaults_nondefault._presence_map, SetDefaults_PR_child);
    ASN_SET_MKPRESENT(set_defaults_nondefault._presence_map, SetDefaults_PR_enabled);
    ASN_SET_MKPRESENT(set_defaults_nondefault._presence_map, SetDefaults_PR_count);
    failed |= check_vector(&asn_DEF_SetImplicit, &set_implicit, set_implicit_der,
                           sizeof(set_implicit_der), set_implicit_cer,
                           sizeof(set_implicit_cer));
    failed |= check_vector(&asn_DEF_SetExplicit, &set_explicit, set_explicit_der,
                           sizeof(set_explicit_der), set_explicit_cer,
                           sizeof(set_explicit_cer));
    failed |= check_vector(&asn_DEF_SetOptional, &set_optional, set_optional_der,
                           sizeof(set_optional_der), set_optional_cer,
                           sizeof(set_optional_cer));
    failed |= check_vector(&asn_DEF_SetOptional, &set_optional_present,
                           set_optional_present_der, sizeof(set_optional_present_der),
                           set_optional_present_cer, sizeof(set_optional_present_cer));
    failed |= check_vector(&asn_DEF_SetDefaults, &set_defaults, set_defaults_der,
                           sizeof(set_defaults_der), set_defaults_cer,
                           sizeof(set_defaults_cer));
    failed |= check_vector(&asn_DEF_SetDefaults, &set_defaults_nondefault,
                           set_defaults_nondefault_der, sizeof(set_defaults_nondefault_der),
                           set_defaults_nondefault_cer, sizeof(set_defaults_nondefault_cer));
    failed |= check_rejected(&asn_DEF_Packet, ATS_BER, bad_eoc, sizeof(bad_eoc));
    failed |= check_out_of_range();
    if(failed) fprintf(stderr, "C named SEQUENCE child fixture failed\n");
    return failed;
}
