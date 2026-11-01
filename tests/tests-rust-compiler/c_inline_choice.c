/* Live C reference vectors for one inline primitive CHOICE child. */
/* Source: generated ASN.1 BER/DER/CER descriptors. Version/date: 2026-11-01. */
/* Responsible party: asn1c maintainers. History: inline CHOICE differential. */
#include <SequenceExplicit.h>
#include <SequenceNatural.h>
#include <SequenceOptional.h>
#include <SetExplicit.h>
#include <SetOptional.h>
#include <asn_application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Purpose: compare exact C DER/CER output and decode values against vectors.
 * Inputs: descriptor/value identify one generated type; der/cer are wire bytes.
 * Returns zero on exact output, accepted decode, value equality, and CER strictness.
 * Errors: any mismatch returns one and frees decoder allocations.
 * Source: generated descriptor and approved X.690 vectors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE differential.
 * Example: check_vector(&asn_DEF_SequenceNatural, &value, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor, const void *expected,
             const uint8_t *der, size_t der_size, const uint8_t *cer,
             size_t cer_size) {
    uint8_t actual[32];
    void *decoded = NULL;
    asn_enc_rval_t encoded = {0};
    asn_dec_rval_t result;
    int failed = 0;
    if(!descriptor || !expected || !der || !cer || der_size > sizeof(actual)
       || cer_size > sizeof(actual) || !descriptor->op->compare_struct) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    failed |= encoded.encoded < 0 || (size_t)encoded.encoded != der_size
        || memcmp(actual, der, der_size);
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    failed |= encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
        || memcmp(actual, cer, cer_size);
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, der, der_size);
    failed |= result.code != RC_OK || result.consumed != der_size || !decoded;
    if(decoded) {
        failed |= descriptor->op->compare_struct(descriptor, expected, decoded) != 0;
        descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
        decoded = NULL;
    }
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, cer, cer_size);
    failed |= result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) {
        failed |= descriptor->op->compare_struct(descriptor, expected, decoded) != 0;
        descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
        decoded = NULL;
    }
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, cer, cer_size);
    failed |= result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) {
        failed |= descriptor->op->compare_struct(descriptor, expected, decoded) != 0;
        descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
        decoded = NULL;
    }
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, der, der_size);
    failed |= result.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "C inline CHOICE vector mismatch: %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: require one BER decode failure and clean any partial object.
 * Inputs: descriptor/input/size identify the malformed encoded value.
 * Returns zero only when the selected syntax rejects it. Errors: unexpected
 * acceptance returns one. Source: generated descriptor API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed wrapper tests.
 * Example: reject an EXPLICIT CHOICE wrapper with two selected children.
 */
static int
check_rejected(asn_TYPE_descriptor_t *descriptor, enum asn_transfer_syntax syntax,
               const uint8_t *input, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor, &decoded, input, size);
    int failed = result.code == RC_OK;
    if(failed) fprintf(stderr, "C inline CHOICE malformed input accepted: %s syntax=%d\n",
                       descriptor->name, syntax);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: verify C BER alias acceptance and one-prefix consumption.
 * Inputs: none. Returns zero when the selected INTEGER alias becomes Count(2).
 * Errors: decode status, selected value, consumption, or CER acceptance fails.
 * Source: C BER compatibility and X.690 strict CER. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline natural CHOICE alias.
 * Example: a high-tag alias for universal INTEGER within a SEQUENCE.
 */
static int
check_alias_prefix(void) {
    static const uint8_t alias[] = {
        0x30, 0x07, 0x1f, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0xaa,
    };
    static const uint8_t canonical_suffix[] = {
        0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0, 0xaa,
    };
    SequenceNatural_t *decoded = NULL;
    SequenceNatural_t *cer_decoded = NULL;
    SequenceNatural_t *suffix_decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_SequenceNatural,
                                      (void **)&decoded, alias, sizeof(alias));
    asn_dec_rval_t cer_result = asn_decode(NULL, ATS_CER, &asn_DEF_SequenceNatural,
                                          (void **)&cer_decoded, alias, sizeof(alias));
    asn_dec_rval_t suffix_result = asn_decode(NULL, ATS_CER, &asn_DEF_SequenceNatural,
                                              (void **)&suffix_decoded, canonical_suffix,
                                              sizeof(canonical_suffix));
    int failed = result.code != RC_OK || result.consumed != 9 || !decoded
        || decoded->choice.present != SequenceNatural__choice_PR_count
        || decoded->choice.choice.count != 2 || decoded->after == 0
        || cer_result.code == RC_OK || suffix_result.code != RC_OK
        || suffix_result.consumed != sizeof(canonical_suffix) - 1 || !suffix_decoded
        || suffix_decoded->choice.present != SequenceNatural__choice_PR_count
        || suffix_decoded->choice.choice.count != 2 || suffix_decoded->after == 0;
    if(failed) {
        fprintf(stderr,
                "C inline CHOICE alias/prefix mismatch: BER=%d/%zu CER=%d "
                "suffix CER=%d/%zu expected=%zu decoded=%p\n",
                result.code, result.consumed, cer_result.code, suffix_result.code,
                suffix_result.consumed, sizeof(canonical_suffix) - 1,
                (void *)suffix_decoded);
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, decoded);
    if(cer_decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, cer_decoded);
    if(suffix_decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, suffix_decoded);
    return failed;
}

/*
 * Purpose: check C BER BOOLEAN aliases inside a natural parent CHOICE.
 * Inputs: input is a malformed-but-C-accepted BOOLEAN record; expected is DER.
 * Returns zero when BER decodes/canonicalizes and CER rejects. Errors: mismatch.
 * Source: C BOOLEAN BER path and shared parent descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline selected-arm parsing.
 * Example: zero-length BOOLEAN content decodes as FALSE under BER.
 */
static int
check_boolean_alias(const uint8_t *input, size_t input_size,
                    const uint8_t *expected, size_t expected_size,
                    BOOLEAN_t expected_value, const char *case_name) {
    uint8_t actual[16];
    SequenceNatural_t *decoded = NULL;
    SequenceNatural_t *cer_decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_SequenceNatural,
                                       (void **)&decoded, input, input_size);
    asn_dec_rval_t cer_result = asn_decode(NULL, ATS_CER, &asn_DEF_SequenceNatural,
                                           (void **)&cer_decoded, input, input_size);
    asn_enc_rval_t encoded = {0};
    int failed = result.code != RC_OK || result.consumed != input_size || !decoded
        || cer_result.code == RC_OK;
    if(!failed) {
        encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_SequenceNatural,
                                       decoded, actual, sizeof(actual));
        failed = decoded->choice.present != SequenceNatural__choice_PR_flag
            || !!decoded->choice.choice.flag != !!expected_value || decoded->after == 0
            || encoded.encoded < 0 || (size_t)encoded.encoded != expected_size
            || memcmp(actual, expected, expected_size);
    }
    if(failed) {
        fprintf(stderr,
                "C inline CHOICE BOOLEAN case failed: %s BER=%d/%zu CER=%d "
                "DER=%zd expected=%zu\n",
                case_name, result.code, result.consumed, cer_result.code,
                encoded.encoded, expected_size);
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, decoded);
    if(cer_decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, cer_decoded);
    return failed;
}

/*
 * Purpose: compare C values for required, optional, and parent SET layouts.
 * Inputs: none. Returns zero when exact C wire and both decoder modes agree.
 * Errors: any vector mismatch, alias, malformed wrapper, or suffix mismatch fails.
 * Source: docs/rust/ber-der-cer-design.md inline CHOICE vectors.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: one inline primitive CHOICE gate. Example: run the fixture executable.
 */
int
main(void) {
    static const uint8_t natural_flag_der[] = {
        0x30, 0x06, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t natural_flag_cer[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t natural_null_der[] = {
        0x30, 0x05, 0x05, 0x00, 0x84, 0x01, 0xff,
    };
    static const uint8_t natural_null_cer[] = {
        0x30, 0x80, 0x05, 0x00, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t natural_der[] = {0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t natural_cer[] = {0x30, 0x80, 0x02, 0x01, 0x02,
        0x84, 0x01, 0xff, 0, 0};
    static const uint8_t explicit_der[] = {0x30, 0x08, 0xa3, 0x03, 0x02, 0x01,
        0x02, 0x84, 0x01, 0xff};
    static const uint8_t explicit_cer[] = {0x30, 0x80, 0xa3, 0x80, 0x02, 0x01,
        0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t explicit_flag_der[] = {
        0x30, 0x08, 0xa3, 0x03, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t explicit_flag_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x01, 0x01, 0xff, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t explicit_null_der[] = {
        0x30, 0x07, 0xa3, 0x02, 0x05, 0x00, 0x84, 0x01, 0xff,
    };
    static const uint8_t explicit_null_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x05, 0x00, 0, 0,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t set_der[] = {0x31, 0x08, 0xa3, 0x03, 0x02, 0x01,
        0x02, 0x84, 0x01, 0xff};
    static const uint8_t set_cer[] = {0x31, 0x80, 0xa3, 0x80, 0x02, 0x01,
        0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t optional_absent_der[] = {0x31, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t optional_absent_cer[] = {0x31, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t optional_null_der[] = {0x31, 0x07, 0xa3, 0x02, 0x05, 0x00,
        0x84, 0x01, 0xff};
    static const uint8_t optional_null_cer[] = {0x31, 0x80, 0xa3, 0x80, 0x05, 0x00,
        0, 0, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t optional_sequence_absent_der[] = {
        0x30, 0x06, 0x80, 0x01, 0x01, 0x84, 0x01, 0xff,
    };
    static const uint8_t optional_sequence_absent_cer[] = {
        0x30, 0x80, 0x80, 0x01, 0x01, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t optional_sequence_der[] = {
        0x30, 0x09, 0x80, 0x01, 0x01, 0x02, 0x01, 0x02,
        0x84, 0x01, 0xff,
    };
    static const uint8_t optional_sequence_cer[] = {
        0x30, 0x80, 0x80, 0x01, 0x01, 0x02, 0x01, 0x02,
        0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t bool_empty[] = {0x30, 0x05, 0x01, 0x00, 0x84, 0x01, 0xff};
    static const uint8_t bool_empty_der[] = {
        0x30, 0x06, 0x01, 0x01, 0x00, 0x84, 0x01, 0xff,
    };
    static const uint8_t bool_multioctet[] = {
        0x30, 0x07, 0x01, 0x02, 0x00, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t missing_choice[] = {0x30, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t empty_wrapper[] = {0x30, 0x05, 0xa3, 0x00, 0x84, 0x01, 0xff};
    static const uint8_t multiple_wrapper[] = {0x30, 0x0a, 0xa3, 0x05,
        0x02, 0x01, 0x02, 0x05, 0x00, 0x84, 0x01, 0xff};
    static const uint8_t wrong_wrapper[] = {0x30, 0x08, 0xa3, 0x03,
        0x04, 0x01, 0x41, 0x84, 0x01, 0xff};
    SequenceNatural_t natural = {
        .choice = {.present = SequenceNatural__choice_PR_count, .choice.count = 2},
        .after = 1,
    };
    SequenceNatural_t natural_flag = {
        .choice = {.present = SequenceNatural__choice_PR_flag, .choice.flag = 1},
        .after = 1,
    };
    SequenceNatural_t natural_null = {
        .choice = {.present = SequenceNatural__choice_PR_nothing},
        .after = 1,
    };
    SequenceExplicit_t explicit_value = {
        .choice = {.present = SequenceExplicit__choice_PR_count, .choice.count = 2},
        .after = 1,
    };
    SequenceExplicit_t explicit_flag = {
        .choice = {.present = SequenceExplicit__choice_PR_flag, .choice.flag = 1},
        .after = 1,
    };
    SequenceExplicit_t explicit_null = {
        .choice = {.present = SequenceExplicit__choice_PR_nothing},
        .after = 1,
    };
    SetExplicit_t set_value = {
        .choice = {.present = SetExplicit__choice_PR_count, .choice.count = 2},
        .after = 1,
    };
    SetOptional_t optional_absent = {.after = 1, .choice = NULL};
    SetOptional_t optional_present = {.after = 1};
    SequenceOptional_t sequence_optional_absent = {.before = 1, .choice = NULL, .after = 1};
    SequenceOptional_t sequence_optional_present = {.before = 1, .after = 1};
    int failed;
    optional_present.choice = calloc(1, sizeof(*optional_present.choice));
    if(!optional_present.choice) {
        fprintf(stderr, "C inline CHOICE optional SET allocation failed\n");
        return 1;
    }
    optional_present.choice->present = SetOptional__choice_PR_nothing;
    sequence_optional_present.choice = calloc(1, sizeof(*sequence_optional_present.choice));
    if(!sequence_optional_present.choice) {
        fprintf(stderr, "C inline CHOICE optional SEQUENCE allocation failed\n");
        free(optional_present.choice);
        return 1;
    }
    sequence_optional_present.choice->present = SequenceOptional__choice_PR_count;
    sequence_optional_present.choice->choice.count = 2;
    failed = check_vector(&asn_DEF_SequenceNatural, &natural,
                          natural_der, sizeof(natural_der),
                          natural_cer, sizeof(natural_cer))
        || check_vector(&asn_DEF_SequenceNatural, &natural_flag,
                        natural_flag_der, sizeof(natural_flag_der),
                        natural_flag_cer, sizeof(natural_flag_cer))
        || check_vector(&asn_DEF_SequenceNatural, &natural_null,
                        natural_null_der, sizeof(natural_null_der),
                        natural_null_cer, sizeof(natural_null_cer))
        || check_vector(&asn_DEF_SequenceExplicit, &explicit_value,
                        explicit_der, sizeof(explicit_der),
                        explicit_cer, sizeof(explicit_cer))
        || check_vector(&asn_DEF_SequenceExplicit, &explicit_flag,
                        explicit_flag_der, sizeof(explicit_flag_der),
                        explicit_flag_cer, sizeof(explicit_flag_cer))
        || check_vector(&asn_DEF_SequenceExplicit, &explicit_null,
                        explicit_null_der, sizeof(explicit_null_der),
                        explicit_null_cer, sizeof(explicit_null_cer))
        || check_vector(&asn_DEF_SetExplicit, &set_value,
                        set_der, sizeof(set_der), set_cer, sizeof(set_cer))
        || check_vector(&asn_DEF_SetOptional, &optional_absent,
                        optional_absent_der, sizeof(optional_absent_der),
                        optional_absent_cer, sizeof(optional_absent_cer))
        || check_vector(&asn_DEF_SetOptional, &optional_present,
                        optional_null_der, sizeof(optional_null_der),
                        optional_null_cer, sizeof(optional_null_cer))
        || check_vector(&asn_DEF_SequenceOptional, &sequence_optional_absent,
                        optional_sequence_absent_der, sizeof(optional_sequence_absent_der),
                        optional_sequence_absent_cer, sizeof(optional_sequence_absent_cer))
        || check_vector(&asn_DEF_SequenceOptional, &sequence_optional_present,
                        optional_sequence_der, sizeof(optional_sequence_der),
                        optional_sequence_cer, sizeof(optional_sequence_cer));
    if(optional_present.choice) free(optional_present.choice);
    if(sequence_optional_present.choice) free(sequence_optional_present.choice);
    if(failed) {
        fprintf(stderr, "C inline CHOICE canonical value vectors failed\n");
        return 1;
    }
    if(check_alias_prefix()) return 1;
    if(check_boolean_alias(bool_empty, sizeof(bool_empty), bool_empty_der,
                           sizeof(bool_empty_der), 0, "empty BOOLEAN")
       || check_boolean_alias(bool_multioctet, sizeof(bool_multioctet),
                              natural_flag_der, sizeof(natural_flag_der), 1,
                              "multi-octet BOOLEAN")
       || check_rejected(&asn_DEF_SequenceNatural, ATS_BER,
                         missing_choice, sizeof(missing_choice))) return 1;
    if(check_rejected(&asn_DEF_SequenceExplicit, ATS_BER,
                      empty_wrapper, sizeof(empty_wrapper))
       || check_rejected(&asn_DEF_SequenceExplicit, ATS_BER,
                         multiple_wrapper, sizeof(multiple_wrapper))
       || check_rejected(&asn_DEF_SequenceExplicit, ATS_BER,
                         wrong_wrapper, sizeof(wrong_wrapper))) return 1;
    return 0;
}
