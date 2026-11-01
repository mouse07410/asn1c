/* C/Rust vectors for DER-selected and CER-minimum natural CHOICE SET order. */
/* Source: approved X.690 and C descriptor probes. Version/date: 2026-11-01. */
/* Responsible party: asn1c maintainers. History: natural CHOICE in SET. */
#include <Values.h>
#include <asn_application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Purpose: compare C canonical encodings and decoded values against one vector.
 * Inputs: expected is a populated value; der/cer are exact complete SET TLVs.
 * Returns zero when both encoders and all decoder paths agree; otherwise one.
 * Errors: unexpected status, prefix length, value, or CER acceptance fails.
 * Source: generated Values descriptor and approved vectors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET differential.
 * Example: check_vector(&value, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_vector(const Values_t *expected, const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    uint8_t actual[32];
    void *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed = 0;
    if(!expected || !der || !cer || der_size > sizeof(actual)
       || cer_size > sizeof(actual) || !asn_DEF_Values.op->compare_struct) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Values, expected,
                                   actual, sizeof(actual));
    failed |= encoded.encoded < 0 || (size_t)encoded.encoded != der_size
        || memcmp(actual, der, der_size);
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Values, expected,
                                   actual, sizeof(actual));
    failed |= encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
        || memcmp(actual, cer, cer_size);
    result = asn_decode(NULL, ATS_BER, &asn_DEF_Values, &decoded, der, der_size);
    failed |= result.code != RC_OK || result.consumed != der_size || !decoded;
    if(decoded) {
        failed |= asn_DEF_Values.op->compare_struct(&asn_DEF_Values, expected, decoded) != 0;
        asn_DEF_Values.op->free_struct(&asn_DEF_Values, decoded, ASFM_FREE_EVERYTHING);
        decoded = NULL;
    }
    result = asn_decode(NULL, ATS_BER, &asn_DEF_Values, &decoded, cer, cer_size);
    failed |= result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) {
        failed |= asn_DEF_Values.op->compare_struct(&asn_DEF_Values, expected, decoded) != 0;
        asn_DEF_Values.op->free_struct(&asn_DEF_Values, decoded, ASFM_FREE_EVERYTHING);
        decoded = NULL;
    }
    result = asn_decode(NULL, ATS_CER, &asn_DEF_Values, &decoded, cer, cer_size);
    failed |= result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) {
        failed |= asn_DEF_Values.op->compare_struct(&asn_DEF_Values, expected, decoded) != 0;
        asn_DEF_Values.op->free_struct(&asn_DEF_Values, decoded, ASFM_FREE_EVERYTHING);
        decoded = NULL;
    }
    result = asn_decode(NULL, ATS_CER, &asn_DEF_Values, &decoded, der, der_size);
    failed |= result.code == RC_OK;
    if(decoded) asn_DEF_Values.op->free_struct(&asn_DEF_Values, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "C natural CHOICE SET vector mismatch\n");
    return failed;
}

/*
 * Purpose: build one C value and compare its selected or absent CHOICE form.
 * Inputs: arm chooses the optional arm; DER/CER point to expected SET bytes.
 * Returns zero on parity, one on allocation or encoding mismatch.
 * Errors: unknown arm, allocation, codec, or decoded-value failures return one.
 * Source: generated Values layout. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET vectors.
 * Example: make_value(Values__choice_PR_nothing, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_value(Values__choice_PR arm, const uint8_t *der, size_t der_size,
            const uint8_t *cer, size_t cer_size) {
    static const uint8_t octet = 0xaa;
    Values_t value = {0};
    int failed;
    value.octets.buf = (uint8_t *)&octet;
    value.octets.size = 1;
    value.marker = Values__marker_one;
    value.after = 1;
    ASN_SET_MKPRESENT(value._presence_map, Values_PR_octets);
    ASN_SET_MKPRESENT(value._presence_map, Values_PR_marker);
    ASN_SET_MKPRESENT(value._presence_map, Values_PR_after);
    if(arm != Values__choice_PR_NOTHING) {
        value.choice = calloc(1, sizeof(*value.choice));
        if(!value.choice) return 1;
        value.choice->present = arm;
        ASN_SET_MKPRESENT(value._presence_map, Values_PR_choice);
        if(arm == Values__choice_PR_flag) value.choice->choice.flag = 0xff;
        else if(arm == Values__choice_PR_count) value.choice->choice.count = 2;
        else if(arm != Values__choice_PR_nothing) {
            free(value.choice);
            return 1;
        }
    }
    failed = check_vector(&value, der, der_size, cer, cer_size);
    free(value.choice);
    return failed;
}

/*
 * Purpose: require a selected syntax to reject one malformed SET prefix.
 * Inputs: syntax and bytes identify one decoder attempt. Returns zero on reject.
 * Errors: unexpected acceptance returns one and frees the partial result.
 * Source: generated C descriptor API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed natural-choice SET.
 * Example: reject two different alternatives occupying the logical CHOICE slot.
 */
static int
check_rejected(enum asn_transfer_syntax syntax, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_Values,
                                       &decoded, wire, size);
    int failed = result.code == RC_OK;
    if(failed) fprintf(stderr, "C natural CHOICE SET unexpectedly accepted input\n");
    if(decoded) asn_DEF_Values.op->free_struct(&asn_DEF_Values, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: verify BER permutation/alias handling and canonical CER prefix use.
 * Inputs: none. Returns zero on accepted BER permutations and strict CER rejects.
 * Errors: status, value, consumption, or canonicality mismatch returns one.
 * Source: C BER compatibility and X.690 CER rules. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET dispatch.
 * Example: CER's minimum tag puts the CHOICE before universal tag 4.
 */
static int
check_ber_forms(void) {
    static const uint8_t reversed[] = {
        0x31, 0x80, 0x04, 0x01, 0xaa, 0x05, 0x00,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    };
    static const uint8_t alias[] = {
        0x31, 0x80, 0x04, 0x01, 0xaa, 0x1f, 0x05, 0x00,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    };
    static const uint8_t canonical_suffix[] = {
        0x31, 0x80, 0x05, 0x00, 0x04, 0x01, 0xaa,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0, 0xaa,
    };
    Values_t *decoded = NULL;
    Values_t *strict = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Values,
        (void **)&decoded, reversed, sizeof(reversed));
    asn_dec_rval_t cer_result = asn_decode(NULL, ATS_CER, &asn_DEF_Values,
        (void **)&strict, reversed, sizeof(reversed));
    int failed = result.code != RC_OK || result.consumed != sizeof(reversed)
        || !decoded || decoded->choice == NULL
        || decoded->choice->present != Values__choice_PR_nothing
        || decoded->octets.size != 1 || decoded->octets.buf[0] != 0xaa
        || !decoded->after || cer_result.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Values, decoded);
    if(strict) ASN_STRUCT_FREE(asn_DEF_Values, strict);
    decoded = NULL;
    strict = NULL;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_Values, (void **)&decoded,
                        alias, sizeof(alias));
    cer_result = asn_decode(NULL, ATS_CER, &asn_DEF_Values, (void **)&strict,
                            alias, sizeof(alias));
    failed |= result.code != RC_OK || result.consumed != sizeof(alias) || !decoded
        || decoded->choice == NULL
        || decoded->choice->present != Values__choice_PR_nothing || cer_result.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Values, decoded);
    if(strict) ASN_STRUCT_FREE(asn_DEF_Values, strict);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_Values, (void **)&decoded,
                        canonical_suffix, sizeof(canonical_suffix));
    failed |= result.code != RC_OK || result.consumed != sizeof(canonical_suffix) - 1
        || !decoded || decoded->choice == NULL
        || decoded->choice->present != Values__choice_PR_nothing;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Values, decoded);
    if(failed) fprintf(stderr, "C natural CHOICE SET BER form mismatch\n");
    return failed;
}

/*
 * Purpose: compare all canonical selected-arm and absent-choice SET values.
 * Inputs: none. Returns zero when every C DER/CER vector matches the schema.
 * Errors: any byte or semantic mismatch returns one.
 * Source: approved live C SET probe. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: DER/CER natural-choice order.
 * Example: NULL-selected DER places tag 4 before tag 5; CER places it after.
 */
int
main(void) {
    static const uint8_t flag_der[] = {
        0x31, 0x0c, 0x01, 0x01, 0xff, 0x04, 0x01, 0xaa,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
    };
    static const uint8_t flag_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x04, 0x01, 0xaa,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    };
    static const uint8_t null_der[] = {
        0x31, 0x0b, 0x04, 0x01, 0xaa, 0x05, 0x00,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
    };
    static const uint8_t null_cer[] = {
        0x31, 0x80, 0x05, 0x00, 0x04, 0x01, 0xaa,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    };
    static const uint8_t count_der[] = {
        0x31, 0x0c, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
    };
    static const uint8_t count_cer[] = {
        0x31, 0x80, 0x02, 0x01, 0x02, 0x04, 0x01, 0xaa,
        0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    };
    static const uint8_t absent_der[] = {
        0x31, 0x09, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff,
    };
    static const uint8_t absent_cer[] = {
        0x31, 0x80, 0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01,
        0x80, 0x01, 0xff, 0, 0,
    };
    static const uint8_t duplicate_choice[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x05, 0x00,
        0x04, 0x01, 0xaa, 0x0a, 0x01, 0x01, 0x80, 0x01, 0xff, 0, 0,
    };
    int failed = check_value(Values__choice_PR_flag, flag_der, sizeof(flag_der),
                             flag_cer, sizeof(flag_cer))
        || check_value(Values__choice_PR_nothing, null_der, sizeof(null_der),
                       null_cer, sizeof(null_cer))
        || check_value(Values__choice_PR_count, count_der, sizeof(count_der),
                       count_cer, sizeof(count_cer))
        || check_value(Values__choice_PR_NOTHING, absent_der, sizeof(absent_der),
                       absent_cer, sizeof(absent_cer));
    if(failed) return 1;
    if(check_ber_forms()) return 1;
    if(check_rejected(ATS_BER, duplicate_choice, sizeof(duplicate_choice))) return 1;
    return 0;
}
