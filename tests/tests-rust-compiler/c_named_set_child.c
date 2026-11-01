/* Live C/Rust vectors for a same-module named SET child. */
/* Source: generated C descriptors, design vectors, and X.690. */
/* Version/date: 2026-11-01. Responsible party: asn1c maintainers. */
#include <InnerSet.h>
#include <SequenceExplicit.h>
#include <SequenceImplicit.h>
#include <SequenceNatural.h>
#include <SequenceOptional.h>
#include <SetDefaults.h>
#include <SetExplicit.h>
#include <SetImplicit.h>
#include <SetNatural.h>
#include <SetOptional.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 64

/*
 * Purpose: compare generated C output and decoded values with one wire pair.
 * Inputs: descriptor/value identify the type and value; DER/CER are full TLVs.
 * Returns zero when encodings, values, prefix lengths, and strict CER checks pass.
 * Errors: a mismatch or codec error returns one; decoded storage is freed.
 * Source: generated descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named SET child differential.
 * Example: check_vector(&asn_DEF_SequenceNatural, &value, der, n, cer, m).
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
    if(!descriptor || !expected || !der || !cer || der_size > sizeof(actual)
       || cer_size + 1 > sizeof(suffixed) || !descriptor->op->compare_struct) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) goto fail;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) goto fail;
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, der, der_size);
    if(result.code != RC_OK || result.consumed != der_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) goto fail;
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, cer, cer_size);
    if(result.code != RC_OK || result.consumed != cer_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) goto fail;
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, cer, cer_size);
    if(result.code != RC_OK || result.consumed != cer_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) goto fail;
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, der, der_size);
    if(result.code == RC_OK) goto fail;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    memcpy(suffixed, cer, cer_size);
    suffixed[cer_size] = 0x5a;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, suffixed, cer_size + 1);
    if(result.code != RC_OK || result.consumed != cer_size || !decoded
       || descriptor->op->compare_struct(descriptor, expected, decoded)) goto fail;
    descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return 0;
fail:
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    fprintf(stderr, "named SET child vector failed for %s\n", descriptor->name);
    return 1;
}

/*
 * Purpose: accept a reordered parent or child SET in BER and reject it in CER.
 * Inputs: descriptor/value select the expected semantic record; wire is reordered.
 * Returns zero on exact BER prefix/value and strict CER rejection.
 * Errors: status, consumption, value, or canonicality mismatches return one.
 * Source: generated SET descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: independent SET ordering.
 * Example: swap the parent's `[4]` BOOLEAN before its explicit child.
 */
static int
check_reordered(asn_TYPE_descriptor_t *descriptor, const void *expected,
                const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    void *strict = NULL;
    asn_dec_rval_t ber = asn_decode(NULL, ATS_BER, descriptor, &decoded, wire, size);
    asn_dec_rval_t cer = asn_decode(NULL, ATS_CER, descriptor, &strict, wire, size);
    int failed = ber.code != RC_OK || ber.consumed != size || !decoded
        || descriptor->op->compare_struct(descriptor, expected, decoded) || cer.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(strict) descriptor->op->free_struct(descriptor, strict, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "named SET child order check failed for %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: require a malformed child or wrapper input to be rejected.
 * Inputs: descriptor, syntax, wire, and size select a decode operation.
 * Returns zero on rejection; unexpected decoded objects are always released.
 * Errors: decoder acceptance returns one. Source: X.690 malformed frames.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: named child framing. Example: reject a missing child SET EOC.
 */
static int
check_rejected(asn_TYPE_descriptor_t *descriptor, enum asn_transfer_syntax syntax,
               const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor, &decoded, wire, size);
    int failed = result.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "malformed named SET input accepted by %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: exercise malformed child frames and target INTEGER constraints.
 * Inputs: natural is the valid semantic value used for the reversed child case.
 * Returns zero when malformed cases reject and C accepts out-of-range BER.
 * Errors: decoder, consumption, value, or constraint mismatches return one.
 * Source: generated descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named SET validation.
 * Example: reject duplicate child tags while retaining C constraint timing.
 */
static int
check_malformed_and_constraints(const SequenceNatural_t *natural) {
    static const uint8_t missing_child_eoc[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t extra_child_eoc[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0, 0x84, 0x01,
        0xff, 0, 0,
    };
    static const uint8_t duplicate_child[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x80, 0x01, 0x03, 0x81, 0x01, 0xff, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t unknown_child[] = {
        0x30, 0x80, 0x31, 0x80, 0x82, 0x01, 0x01, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0,
        0, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t wrong_explicit_child[] = {
        0x30, 0x80, 0xa3, 0x80, 0x30, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t child_reversed_sequence[] = {
        0x30, 0x80, 0x31, 0x80, 0x81, 0x01, 0xff, 0x80, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    };
    static const uint8_t out_of_range[] = {
        0x30, 0x0b, 0x31, 0x06, 0x80, 0x01, 0x06, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    SequenceNatural_t *decoded = NULL;
    asn_dec_rval_t result;
    char diagnostic[128];
    size_t diagnostic_size = sizeof(diagnostic);
    int failed = 0;

    failed |= check_rejected(&asn_DEF_SequenceNatural, ATS_BER, missing_child_eoc,
                             sizeof(missing_child_eoc));
    failed |= check_rejected(&asn_DEF_SequenceNatural, ATS_BER, extra_child_eoc,
                             sizeof(extra_child_eoc));
    failed |= check_rejected(&asn_DEF_SequenceNatural, ATS_BER, duplicate_child,
                             sizeof(duplicate_child));
    failed |= check_rejected(&asn_DEF_SequenceNatural, ATS_BER, unknown_child,
                             sizeof(unknown_child));
    failed |= check_reordered(&asn_DEF_SequenceNatural, natural, child_reversed_sequence,
                              sizeof(child_reversed_sequence));
    failed |= check_rejected(&asn_DEF_SequenceExplicit, ATS_BER, wrong_explicit_child,
                             sizeof(wrong_explicit_child));

    result = asn_decode(NULL, ATS_BER, &asn_DEF_SequenceNatural, (void **)&decoded,
                        out_of_range, sizeof(out_of_range));
    if(result.code != RC_OK || result.consumed != sizeof(out_of_range) || !decoded
       || !decoded->child || decoded->child->number != 6 || !decoded->after
       || asn_check_constraints(&asn_DEF_SequenceNatural, decoded, diagnostic,
                                &diagnostic_size) == 0) {
        fprintf(stderr, "named SET child INTEGER constraint timing mismatch\n");
        failed = 1;
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, decoded);
    return failed;
}

/*
 * Purpose: compare named SET children, optional forms, and both SET order levels.
 * Inputs: none. Returns zero when all C vectors and malformed cases pass.
 * Errors: any failed vector or status check returns one.
 * Source: generated C descriptors and design vectors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: same-module named SET child.
 * Example: encode InnerSet in natural, IMPLICIT, and EXPLICIT parent fields.
 */
int
main(void) {
    static const uint8_t natural_der[] = {
        0x30, 0x0b, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t natural_cer[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    };
    static const uint8_t implicit_der[] = {
        0x30, 0x0b, 0xa3, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t implicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    };
    static const uint8_t explicit_der[] = {
        0x30, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01,
        0xff,
    };
    static const uint8_t explicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t sequence_absent_der[] = {0x30, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t sequence_absent_cer[] = {0x30, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t sequence_present_der[] = {
        0x30, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01,
        0xff,
    };
    static const uint8_t sequence_present_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t set_der[] = {
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01,
        0xff,
    };
    static const uint8_t set_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t set_natural_der[] = {
        0x31, 0x0b, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t set_natural_cer[] = {
        0x31, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    };
    static const uint8_t set_implicit_der[] = {
        0x31, 0x0b, 0xa3, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t set_implicit_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0x84, 0x01, 0xff,
        0, 0,
    };
    static const uint8_t set_absent_der[] = {0x31, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t set_absent_cer[] = {0x31, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t set_present_der[] = {
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0x84, 0x01,
        0xff,
    };
    static const uint8_t set_present_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t defaults_der[] = {
        0x31, 0x0a, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff,
    };
    static const uint8_t defaults_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01, 0xff, 0, 0, 0,
        0, 0, 0,
    };
    static const uint8_t defaults_true_der[] = {
        0x31, 0x0d, 0x01, 0x01, 0xff, 0xa3, 0x08, 0x31, 0x06, 0x80, 0x01, 0x02,
        0x81, 0x01, 0xff,
    };
    static const uint8_t defaults_true_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02,
        0x81, 0x01, 0xff, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t set_reversed_parent[] = {
        0x31, 0x80, 0x84, 0x01, 0xff, 0xa3, 0x80, 0x31, 0x80, 0x80, 0x01, 0x02, 0x81, 0x01,
        0xff, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t set_reversed_child[] = {
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x81, 0x01, 0xff, 0x80, 0x01, 0x02, 0, 0, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    InnerSet_t child = {.number = 2, .flag = 0xff};
    SequenceNatural_t natural = {.child = &child, .after = 0xff};
    SequenceImplicit_t implicit = {.child = &child, .after = 0xff};
    SequenceExplicit_t explicit_value = {.child = &child, .after = 0xff};
    SequenceOptional_t sequence_absent = {.after = 0xff};
    SequenceOptional_t sequence_present = {.child = &child, .after = 0xff};
    SetExplicit_t set_value = {.child = &child, .after = 0xff};
    SetNatural_t set_natural = {.child = &child, .after = 0xff};
    SetImplicit_t set_implicit = {.child = &child, .after = 0xff};
    SetOptional_t set_absent = {.after = 0xff};
    SetOptional_t set_present = {.child = &child, .after = 0xff};
    SetDefaults_t defaults = {.child = &child, .enabled = 0};
    SetDefaults_t defaults_true = {.child = &child, .enabled = 0xff};
    int failed = 0;
    ASN_SET_MKPRESENT(child._presence_map, InnerSet_PR_number);
    ASN_SET_MKPRESENT(child._presence_map, InnerSet_PR_flag);
    failed |= check_vector(&asn_DEF_SequenceNatural, &natural, natural_der, sizeof(natural_der),
                           natural_cer, sizeof(natural_cer));
    failed |= check_vector(&asn_DEF_SequenceImplicit, &implicit, implicit_der,
                           sizeof(implicit_der), implicit_cer, sizeof(implicit_cer));
    failed |= check_vector(&asn_DEF_SequenceExplicit, &explicit_value, explicit_der,
                           sizeof(explicit_der), explicit_cer, sizeof(explicit_cer));
    failed |= check_vector(&asn_DEF_SequenceOptional, &sequence_absent, sequence_absent_der,
                           sizeof(sequence_absent_der), sequence_absent_cer,
                           sizeof(sequence_absent_cer));
    failed |= check_vector(&asn_DEF_SequenceOptional, &sequence_present, sequence_present_der,
                           sizeof(sequence_present_der), sequence_present_cer,
                           sizeof(sequence_present_cer));
    ASN_SET_MKPRESENT(set_value._presence_map, SetExplicit_PR_child);
    ASN_SET_MKPRESENT(set_value._presence_map, SetExplicit_PR_after);
    ASN_SET_MKPRESENT(set_natural._presence_map, SetNatural_PR_child);
    ASN_SET_MKPRESENT(set_natural._presence_map, SetNatural_PR_after);
    ASN_SET_MKPRESENT(set_implicit._presence_map, SetImplicit_PR_child);
    ASN_SET_MKPRESENT(set_implicit._presence_map, SetImplicit_PR_after);
    ASN_SET_MKPRESENT(set_absent._presence_map, SetOptional_PR_after);
    ASN_SET_MKPRESENT(set_present._presence_map, SetOptional_PR_child);
    ASN_SET_MKPRESENT(set_present._presence_map, SetOptional_PR_after);
    ASN_SET_MKPRESENT(defaults._presence_map, SetDefaults_PR_child);
    ASN_SET_MKPRESENT(defaults_true._presence_map, SetDefaults_PR_child);
    ASN_SET_MKPRESENT(defaults_true._presence_map, SetDefaults_PR_enabled);
    failed |= check_vector(&asn_DEF_SetExplicit, &set_value, set_der, sizeof(set_der),
                           set_cer, sizeof(set_cer));
    failed |= check_vector(&asn_DEF_SetNatural, &set_natural, set_natural_der,
                           sizeof(set_natural_der), set_natural_cer,
                           sizeof(set_natural_cer));
    failed |= check_vector(&asn_DEF_SetImplicit, &set_implicit, set_implicit_der,
                           sizeof(set_implicit_der), set_implicit_cer,
                           sizeof(set_implicit_cer));
    failed |= check_vector(&asn_DEF_SetOptional, &set_absent, set_absent_der,
                           sizeof(set_absent_der), set_absent_cer, sizeof(set_absent_cer));
    failed |= check_vector(&asn_DEF_SetOptional, &set_present, set_present_der,
                           sizeof(set_present_der), set_present_cer, sizeof(set_present_cer));
    failed |= check_vector(&asn_DEF_SetDefaults, &defaults, defaults_der, sizeof(defaults_der),
                           defaults_cer, sizeof(defaults_cer));
    failed |= check_vector(&asn_DEF_SetDefaults, &defaults_true, defaults_true_der,
                           sizeof(defaults_true_der), defaults_true_cer,
                           sizeof(defaults_true_cer));
    failed |= check_reordered(&asn_DEF_SetExplicit, &set_value, set_reversed_parent,
                              sizeof(set_reversed_parent));
    failed |= check_reordered(&asn_DEF_SetExplicit, &set_value, set_reversed_child,
                              sizeof(set_reversed_child));
    failed |= check_malformed_and_constraints(&natural);
    return failed;
}
