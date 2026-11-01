/* C differential vectors for an imported bounded INTEGER member. */
/* Source: X.680/X.690 and approved ImportedIntegerBase/Client schemas. */
/* Version/date: 2026-11-01. Responsible party: asn1c maintainers. */
#include <DefaultSequence.h>
#include <DefaultSet.h>
#include <ExplicitSequence.h>
#include <ExplicitSet.h>
#include <ImplicitSequence.h>
#include <ImplicitSet.h>
#include <NaturalSequence.h>
#include <NaturalSet.h>
#include <OptionalSequence.h>
#include <OptionalSet.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 64

/*
 * Purpose: decode DER and CER with C BER and compare semantic values.
 * Inputs: descriptor and two exact TLVs identify one imported-type vector.
 * Returns zero when both full prefixes decode to equal C values.
 * Errors: argument, status, consumption, allocation, or value errors return one.
 * Source: generated C descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported INTEGER vectors.
 * Example: compare NaturalSequence DER and CER values.
 */
static int
decode_pair(asn_TYPE_descriptor_t *descriptor,
            const uint8_t *der, size_t der_size,
            const uint8_t *cer, size_t cer_size,
            void **value) {
    void *canonical = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor || !descriptor->op || !descriptor->op->compare_struct
       || !descriptor->op->free_struct || !der || !cer || !value) return 1;
    result = asn_decode(NULL, ATS_BER, descriptor, value, der, der_size);
    if(result.code != RC_OK || result.consumed != der_size || !*value) return 1;
    result = asn_decode(NULL, ATS_BER, descriptor, &canonical, cer, cer_size);
    failed = result.code != RC_OK || result.consumed != cer_size || !canonical
        || descriptor->op->compare_struct(descriptor, *value, canonical);
    if(canonical) descriptor->op->free_struct(descriptor, canonical, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: compare DER and CER encoder output against exact fixed vectors.
 * Inputs: descriptor/value identify the decoded C value; vectors are TLVs.
 * Returns zero on both byte matches. Errors: codec or size mismatch returns one.
 * Source: generated C codecs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported INTEGER vectors.
 * Example: re-encode the value from a NaturalSequence DER vector.
 */
static int
check_encodings(asn_TYPE_descriptor_t *descriptor, const void *value,
                const uint8_t *der, size_t der_size,
                const uint8_t *cer, size_t cer_size) {
    uint8_t actual[WIRE_MAX];
    asn_enc_rval_t encoded;
    if(!descriptor || !descriptor->op || !value || !der || !cer || der_size > sizeof(actual)
       || cer_size > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) return 1;
    return 0;
}

/*
 * Purpose: require strict CER to accept canonical bytes and preserve suffixes.
 * Inputs: descriptor/DER/CER identify the vector; sizes bound the buffers.
 * Returns zero on CER success, DER rejection, and exact prefix consumption.
 * Errors: malformed or unexpected status/consumption returns one.
 * Source: generated strict CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix/canonical tests.
 * Example: accept CER followed by 0x5a but consume only the CER TLV.
 */
static int
check_strict_and_suffix(asn_TYPE_descriptor_t *descriptor,
                        const uint8_t *der, size_t der_size,
                        const uint8_t *cer, size_t cer_size) {
    uint8_t suffixed[WIRE_MAX];
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct
       || !der || !cer || cer_size >= sizeof(suffixed)) return 1;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, cer, cer_size);
    failed = result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, der, der_size);
    failed |= result.code == RC_OK && result.consumed == der_size;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    memcpy(suffixed, cer, cer_size);
    suffixed[cer_size] = 0x5a;
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, suffixed, cer_size + 1);
    failed |= result.code != RC_OK || result.consumed != cer_size || !decoded;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: run the C encoder/decoder differential checks for one vector.
 * Inputs: descriptor plus exact DER/CER TLVs. Returns zero when all checks pass.
 * Errors: codec or byte mismatches return one; every decoded value is released.
 * Source: generated C descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported INTEGER vectors.
 * Example: check natural SEQUENCE and explicit SET encodings.
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor,
             const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    void *value = NULL;
    int failed;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct
       || !descriptor->op->compare_struct || !der || !cer
       || der_size > WIRE_MAX || cer_size >= WIRE_MAX) return 1;
    failed = decode_pair(descriptor, der, der_size, cer, cer_size, &value);
    if(!failed) failed = check_encodings(descriptor, value, der, der_size, cer, cer_size);
    if(value) descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    if(!failed) failed = check_strict_and_suffix(descriptor, der, der_size, cer, cer_size);
    if(failed) fprintf(stderr, "imported INTEGER vector failed for %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: require full BER rejection of malformed tag or explicit content.
 * Inputs: descriptor and bounded BER wire bytes. Returns zero on rejection.
 * Errors: full-input acceptance returns one and partial values are freed.
 * Source: X.690 constructed-wrapper framing. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed import values.
 * Example: reject an EXPLICIT wrapper containing two INTEGER TLVs.
 */
static int
check_rejected(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct || !wire) return 1;
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, wire, size);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code == RC_OK && result.consumed == size;
}

/*
 * Purpose: require strict CER to reject a complete noncanonical value.
 * Inputs: descriptor and complete mutated/default-bearing CER candidate.
 * Returns zero on rejection. Errors: full-input acceptance returns one.
 * Source: generated strict CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported DEFAULT rules.
 * Example: reject a DEFAULT FALSE field encoded explicitly in CER.
 */
static int
check_cer_rejected(asn_TYPE_descriptor_t *descriptor,
                   const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor || !descriptor->op || !descriptor->op->free_struct || !wire) return 1;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, wire, size);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code == RC_OK && result.consumed == size;
}

/*
 * Purpose: preserve C's decode-then-constraint-check timing for range failures.
 * Inputs: invalid is a complete BER record with imported integer value six.
 * Returns zero if BER decodes it but the generated constraint rejects it.
 * Errors: status, consumption, or constraint mismatch returns one.
 * Source: generated C descriptors and X.680 range. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: out-of-range differential.
 * Example: decode Small=6, then require asn_check_constraints to fail.
 */
static int
check_range_timing(const uint8_t *invalid, size_t invalid_size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    char diagnostic[128];
    size_t diagnostic_size = sizeof(diagnostic);
    int failed;
    if(!invalid) return 1;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_NaturalSequence,
                        &decoded, invalid, invalid_size);
    failed = result.code != RC_OK || result.consumed != invalid_size || !decoded;
    if(!failed) {
        failed = asn_check_constraints(&asn_DEF_NaturalSequence, decoded,
                                       diagnostic, &diagnostic_size) == 0;
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_NaturalSequence, decoded);
    return failed;
}

/*
 * Purpose: compare every required, OPTIONAL, tagged, SET, and DEFAULT vector.
 * Inputs: none. Returns zero when all C vectors and malformed cases pass.
 * Errors: any vector or range mismatch returns one.
 * Source: approved C vector list and generated descriptors. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported bounded INTEGER.
 * Example: compare NaturalSequence and ExplicitSet against their DER/CER bytes.
 */
int
main(void) {
    static const uint8_t natural_der[] = {0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t natural_cer[] = {
        0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t absent_sequence_der[] = {0x30, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t absent_sequence_cer[] = {0x30, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t present_sequence_der[] = {0x30, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t present_sequence_cer[] = {
        0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t implicit_sequence_der[] = {0x30, 0x06, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t implicit_sequence_cer[] = {
        0x30, 0x80, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t explicit_sequence_der[] = {
        0x30, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff,
    };
    static const uint8_t explicit_sequence_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t natural_set_der[] = {0x31, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t natural_set_cer[] = {
        0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t absent_set_der[] = {0x31, 0x03, 0x84, 0x01, 0xff};
    static const uint8_t absent_set_cer[] = {0x31, 0x80, 0x84, 0x01, 0xff, 0, 0};
    static const uint8_t present_set_der[] = {0x31, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t present_set_cer[] = {
        0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t implicit_set_der[] = {0x31, 0x06, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff};
    static const uint8_t implicit_set_cer[] = {
        0x31, 0x80, 0x83, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t explicit_set_der[] = {
        0x31, 0x08, 0xa3, 0x03, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff,
    };
    static const uint8_t explicit_set_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t default_sequence_der[] = {0x30, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t default_sequence_cer[] = {0x30, 0x80, 0x02, 0x01, 0x02, 0, 0};
    static const uint8_t default_sequence_true_der[] = {
        0x30, 0x06, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff,
    };
    static const uint8_t default_sequence_true_cer[] = {
        0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0,
    };
    static const uint8_t default_set_der[] = {0x31, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t default_set_cer[] = {0x31, 0x80, 0x02, 0x01, 0x02, 0, 0};
    static const uint8_t default_set_true_der[] = {
        0x31, 0x06, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff,
    };
    static const uint8_t default_set_true_cer[] = {
        0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 0,
    };
    static const uint8_t explicit_default_false[] = {
        0x30, 0x80, 0x02, 0x01, 0x02, 0x01, 0x01, 0x00, 0, 0,
    };
    static const uint8_t explicit_set_default_false[] = {
        0x31, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0x00, 0, 0,
    };
    static const uint8_t out_of_range[] = {0x30, 0x06, 0x02, 0x01, 0x06, 0x84, 0x01, 0xff};
    static const uint8_t wrong_tag[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff};
    static const uint8_t wrong_explicit_inner[] = {
        0x30, 0x08, 0xa3, 0x03, 0x01, 0x01, 0xff, 0x84, 0x01, 0xff,
    };
    static const uint8_t multiple_explicit[] = {
        0x30, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x84, 0x01, 0xff,
    };
    static const uint8_t duplicate_value[] = {
        0x30, 0x09, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x84, 0x01, 0xff,
    };
    static const uint8_t unknown_member[] = {
        0x30, 0x06, 0x02, 0x01, 0x02, 0x85, 0x01, 0xff,
    };
    static const uint8_t malformed_eoc[] = {
        0x30, 0x80, 0x02, 0x01, 0x02, 0x84, 0x01, 0xff, 0, 1,
    };
    int failed = 0;

    failed |= check_vector(&asn_DEF_NaturalSequence, natural_der, sizeof(natural_der),
                           natural_cer, sizeof(natural_cer));
    failed |= check_vector(&asn_DEF_OptionalSequence, absent_sequence_der,
                           sizeof(absent_sequence_der), absent_sequence_cer,
                           sizeof(absent_sequence_cer));
    failed |= check_vector(&asn_DEF_OptionalSequence, present_sequence_der,
                           sizeof(present_sequence_der), present_sequence_cer,
                           sizeof(present_sequence_cer));
    failed |= check_vector(&asn_DEF_ImplicitSequence, implicit_sequence_der,
                           sizeof(implicit_sequence_der), implicit_sequence_cer,
                           sizeof(implicit_sequence_cer));
    failed |= check_vector(&asn_DEF_ExplicitSequence, explicit_sequence_der,
                           sizeof(explicit_sequence_der), explicit_sequence_cer,
                           sizeof(explicit_sequence_cer));
    failed |= check_vector(&asn_DEF_NaturalSet, natural_set_der, sizeof(natural_set_der),
                           natural_set_cer, sizeof(natural_set_cer));
    failed |= check_vector(&asn_DEF_OptionalSet, absent_set_der, sizeof(absent_set_der),
                           absent_set_cer, sizeof(absent_set_cer));
    failed |= check_vector(&asn_DEF_OptionalSet, present_set_der, sizeof(present_set_der),
                           present_set_cer, sizeof(present_set_cer));
    failed |= check_vector(&asn_DEF_ImplicitSet, implicit_set_der, sizeof(implicit_set_der),
                           implicit_set_cer, sizeof(implicit_set_cer));
    failed |= check_vector(&asn_DEF_ExplicitSet, explicit_set_der, sizeof(explicit_set_der),
                           explicit_set_cer, sizeof(explicit_set_cer));
    failed |= check_vector(&asn_DEF_DefaultSequence, default_sequence_der,
                           sizeof(default_sequence_der), default_sequence_cer,
                           sizeof(default_sequence_cer));
    failed |= check_vector(&asn_DEF_DefaultSequence, default_sequence_true_der,
                           sizeof(default_sequence_true_der), default_sequence_true_cer,
                           sizeof(default_sequence_true_cer));
    failed |= check_vector(&asn_DEF_DefaultSet, default_set_der, sizeof(default_set_der),
                           default_set_cer, sizeof(default_set_cer));
    failed |= check_vector(&asn_DEF_DefaultSet, default_set_true_der,
                           sizeof(default_set_true_der), default_set_true_cer,
                           sizeof(default_set_true_cer));
    failed |= check_range_timing(out_of_range, sizeof(out_of_range));
    failed |= check_rejected(&asn_DEF_NaturalSequence, wrong_tag, sizeof(wrong_tag));
    failed |= check_rejected(&asn_DEF_ExplicitSequence, wrong_explicit_inner,
                             sizeof(wrong_explicit_inner));
    failed |= check_rejected(&asn_DEF_ExplicitSequence, multiple_explicit,
                             sizeof(multiple_explicit));
    failed |= check_rejected(&asn_DEF_NaturalSequence, duplicate_value,
                             sizeof(duplicate_value));
    failed |= check_rejected(&asn_DEF_NaturalSequence, unknown_member,
                             sizeof(unknown_member));
    failed |= check_rejected(&asn_DEF_NaturalSequence, malformed_eoc,
                             sizeof(malformed_eoc));
    failed |= check_cer_rejected(&asn_DEF_DefaultSequence, explicit_default_false,
                                 sizeof(explicit_default_false));
    failed |= check_cer_rejected(&asn_DEF_DefaultSet, explicit_set_default_false,
                                 sizeof(explicit_set_default_false));
    return failed;
}
