/* Live C vectors for same-module named bounded INTEGER record fields. */
/* Source: X.680/X.690 and the approved named INTEGER field slice. */
/* Date: 2026-11-01. Responsible party: asn1c maintainers. */
#include <Sequence.h>
#include <SequenceBits.h>
#include <SequenceExplicit.h>
#include <SequenceImplicit.h>
#include <SequenceOptional.h>
#include <Set.h>
#include <SetExplicit.h>
#include <SetImplicit.h>
#include <SetOptional.h>
#include <Small.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 64

/*
 * Purpose: compare C encoder output and decoded values for one exact vector.
 * Inputs: descriptor/expected select the C type; DER/CER arguments are bytes.
 * Returns zero on full parity, otherwise one and releases decoded storage.
 * Errors: encode, decode, semantic, or prefix mismatches fail safely.
 * Source: generated asn1c descriptors and X.690. Date: 2026-11-01.
 * Responsible: asn1c maintainers. History: named INTEGER record vectors.
 * Example: check a required Small SEQUENCE against DER and CER encodings.
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor, const void *expected,
             const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    uint8_t actual[WIRE_MAX];
    uint8_t suffixed[WIRE_MAX];
    asn_enc_rval_t encoded;
    size_t available;
    asn_dec_rval_t decoded;
    void *value = NULL;
    if(!descriptor || !expected || !der || !cer
       || der_size > sizeof(actual) || cer_size > sizeof(actual)) {
        fprintf(stderr, "invalid C vector arguments for %s\n",
                descriptor ? descriptor->name : "(null)");
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "DER encoding mismatch for %s: %zd/%zu\n",
                descriptor->name, encoded.encoded, der_size);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "CER encoding mismatch for %s: %zd/%zu\n",
                descriptor->name, encoded.encoded, cer_size);
        return 1;
    }
    decoded = asn_decode(NULL, ATS_BER, descriptor, &value, der, der_size);
    if(decoded.code != RC_OK || decoded.consumed != der_size || !value
       || !descriptor->op->compare_struct
       || descriptor->op->compare_struct(descriptor, expected, value)) goto fail;
    descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    value = NULL;
    decoded = asn_decode(NULL, ATS_BER, descriptor, &value, cer, cer_size);
    if(decoded.code != RC_OK || decoded.consumed != cer_size || !value
       || descriptor->op->compare_struct(descriptor, expected, value)) goto fail;
    descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    value = NULL;
    decoded = asn_decode(NULL, ATS_CER, descriptor, &value, cer, cer_size);
    if(decoded.code != RC_OK || decoded.consumed != cer_size || !value
       || descriptor->op->compare_struct(descriptor, expected, value)) goto fail;
    descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    value = NULL;
    decoded = asn_decode(NULL, ATS_CER, descriptor, &value, der, der_size);
    if(decoded.code == RC_OK) {
        fprintf(stderr, "strict CER accepted DER for %s\n", descriptor->name);
        goto fail;
    }
    if(value) descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    available = cer_size + 1;
    if(available > sizeof(suffixed)) return 1;
    memcpy(suffixed, cer, cer_size);
    suffixed[cer_size] = 0x5a;
    decoded = asn_decode(NULL, ATS_CER, descriptor, &value, suffixed, available);
    if(decoded.code != RC_OK || decoded.consumed != cer_size || !value
       || descriptor->op->compare_struct(descriptor, expected, value)) goto fail;
    descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    return 0;
fail:
    if(value) descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
    fprintf(stderr, "named INTEGER C vector failed for %s\n", descriptor->name);
    return 1;
}

/*
 * Purpose: check the C target's range callback for decoded named INTEGERs.
 * Inputs: descriptor/value identify a record with an out-of-range value.
 * Returns one when the C constraint checker rejects the candidate.
 * Errors: diagnostics are not emitted; this is a boolean test helper.
 * Source: generated C constraints. Date: 2026-11-01. Responsible: maintainers.
 * History: range timing comparison. Example: Small value 6 is outside 0..5.
 */
static int
constraints_reject(asn_TYPE_descriptor_t *descriptor, const void *value) {
    char error[128];
    size_t length = sizeof(error);
    return asn_check_constraints(descriptor, value, error, &length) != 0;
}

/*
 * Purpose: accept one BER alias and verify value, consumed prefix, and CER failure.
 * Inputs: descriptor/expected select type and value; alias/canonical are wires.
 * Returns zero when BER accepts exactly and strict CER rejects the alias.
 * Errors: partial decoder allocations are released before return.
 * Source: C BER/CER adapters. Date: 2026-11-01. Responsible: maintainers.
 * History: implicit tag aliases. Example: `9f 03` aliases context tag 3.
 */
static int
check_alias(asn_TYPE_descriptor_t *descriptor, const void *expected,
            const uint8_t *alias, size_t alias_size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, descriptor, &decoded,
                                       alias, alias_size);
    int failed = result.code != RC_OK || result.consumed != alias_size || !decoded
        || descriptor->op->compare_struct(descriptor, expected, decoded);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) {
        fprintf(stderr, "BER alias mismatch for %s: status=%d consumed=%zu/%zu\n",
                descriptor->name, (int)result.code, result.consumed, alias_size);
        return 1;
    }
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, alias, alias_size);
    failed = result.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "strict CER accepted alias for %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: require a candidate to fail BER and release partial decoder storage.
 * Inputs: descriptor identifies the type; wire/size bound the malformed TLV.
 * Returns zero on rejection and one if the C BER decoder accepts the input.
 * Errors: none; decoder failure is the expected outcome.
 * Source: generated C decoder. Date: 2026-11-01. Responsible: maintainers.
 * History: explicit wrapper validation. Example: BOOLEAN is not a Small INTEGER.
 */
static int
ber_rejects(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, descriptor, &decoded, wire, size);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    return result.code == RC_OK;
}

/*
 * Purpose: compare canonical encodings and decoders for direct Sequence forms.
 * Inputs: none; each local object represents one fixed C test value.
 * Returns zero on parity, otherwise one. Errors: vector helper failure.
 * Source: NamedIntegerRecord.asn1 and X.690. Date: 2026-11-01.
 * Responsible: asn1c maintainers. History: SEQUENCE reference gate vectors.
 * Example: an EXPLICIT context tag wraps exactly one bounded INTEGER TLV.
 */
static int
check_sequences(void) {
    static const uint8_t octets[] = {0xaa};
    static const uint8_t der[] = {0x30, 9, 1, 1, 0xff, 2, 1, 2, 4, 1, 0xaa};
    static const uint8_t cer[] = {0x30, 0x80, 1, 1, 0xff, 2, 1, 2, 4, 1, 0xaa, 0, 0};
    static const uint8_t optional_absent_der[] = {0x30, 3, 1, 1, 0xff};
    static const uint8_t optional_absent_cer[] = {0x30, 0x80, 1, 1, 0xff, 0, 0};
    static const uint8_t implicit_der[] = {0x30, 6, 0x83, 1, 2, 1, 1, 0xff};
    static const uint8_t implicit_cer[] = {0x30, 0x80, 0x83, 1, 2, 1, 1, 0xff, 0, 0};
    static const uint8_t explicit_der[] = {0x30, 8, 0xa3, 3, 2, 1, 2, 1, 1, 0xff};
    static const uint8_t explicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 2, 1, 2, 0, 0, 1, 1, 0xff, 0, 0
    };
    static const uint8_t explicit_absent_der[] = {0x30, 3, 1, 1, 0xff};
    static const uint8_t explicit_absent_cer[] = {0x30, 0x80, 1, 1, 0xff, 0, 0};
    Small_t small = 2;
    Sequence_t sequence = {1, 2, {(uint8_t *)octets, sizeof(octets)}};
    SequenceOptional_t absent = {NULL, 1};
    SequenceOptional_t present = {&small, 1};
    SequenceImplicit_t implicit = {2, 1};
    SequenceExplicit_t explicit_value = {&small, 1};
    SequenceExplicit_t explicit_absent = {NULL, 1};
    SequenceImplicit_t expected_implicit = {2, 1};
    static const uint8_t integer_alias[] = {
        0x30, 0x80, 0x01, 0x01, 0xff, 0x1f, 0x02, 0x01, 0x02,
        0x04, 0x01, 0xaa, 0, 0
    };
    static const uint8_t implicit_alias[] = {
        0x30, 0x80, 0x9f, 0x03, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0
    };
    static const uint8_t invalid_range[] = {
        0x30, 0x06, 0x83, 0x01, 0x06, 0x01, 0x01, 0xff
    };
    static const uint8_t invalid_natural_range[] = {
        0x30, 0x09, 0x01, 0x01, 0xff, 0x02, 0x01, 0x06, 0x04, 0x01, 0xaa
    };
    static const uint8_t wrong_explicit[] = {
        0x30, 0x08, 0xa3, 0x03, 0x01, 0x01, 0xff, 0x01, 0x01, 0xff
    };
    static const uint8_t multiple_explicit[] = {
        0x30, 0x0b, 0xa3, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03,
        0x01, 0x01, 0xff
    };
    static const uint8_t constructed_implicit[] = {
        0x30, 0x80, 0xa3, 0x01, 0x02, 0x01, 0x01, 0xff, 0, 0
    };
    void *decoded = NULL;
    asn_dec_rval_t result;
    static const uint8_t present_der[] = {0x30, 6, 2, 1, 2, 1, 1, 0xff};
    static const uint8_t present_cer[] = {0x30, 0x80, 2, 1, 2, 1, 1, 0xff, 0, 0};
    if(check_vector(&asn_DEF_Sequence, &sequence, der, sizeof(der), cer, sizeof(cer)))
        return 1;
    if(check_vector(&asn_DEF_SequenceOptional, &absent,
                    optional_absent_der, sizeof(optional_absent_der),
                    optional_absent_cer, sizeof(optional_absent_cer))) return 1;
    if(check_vector(&asn_DEF_SequenceOptional, &present,
                    present_der, sizeof(present_der), present_cer, sizeof(present_cer)))
        return 1;
    if(check_vector(&asn_DEF_SequenceImplicit, &implicit,
                    implicit_der, sizeof(implicit_der), implicit_cer, sizeof(implicit_cer)))
        return 1;
    if(check_vector(&asn_DEF_SequenceExplicit, &explicit_value,
                    explicit_der, sizeof(explicit_der), explicit_cer, sizeof(explicit_cer)))
        return 1;
    if(check_vector(&asn_DEF_SequenceExplicit, &explicit_absent,
                    explicit_absent_der, sizeof(explicit_absent_der),
                    explicit_absent_cer, sizeof(explicit_absent_cer))) return 1;
    if(check_alias(&asn_DEF_Sequence, &sequence,
                   integer_alias, sizeof(integer_alias))) return 1;
    if(check_alias(&asn_DEF_SequenceImplicit, &expected_implicit,
                   implicit_alias, sizeof(implicit_alias))) return 1;
    if(ber_rejects(&asn_DEF_SequenceExplicit, wrong_explicit, sizeof(wrong_explicit))) {
        fprintf(stderr, "BER accepted a wrong EXPLICIT named INTEGER child\n");
        return 1;
    }
    if(ber_rejects(&asn_DEF_SequenceExplicit, multiple_explicit,
                   sizeof(multiple_explicit))) {
        fprintf(stderr, "BER accepted multiple EXPLICIT named INTEGER children\n");
        return 1;
    }
    if(ber_rejects(&asn_DEF_SequenceImplicit, constructed_implicit,
                   sizeof(constructed_implicit))) {
        fprintf(stderr, "BER accepted constructed form for primitive IMPLICIT INTEGER\n");
        return 1;
    }
    result = asn_decode(NULL, ATS_BER, &asn_DEF_SequenceImplicit, &decoded,
                        invalid_range, sizeof(invalid_range));
    if(result.code != RC_OK || result.consumed != sizeof(invalid_range) || !decoded
       || ((SequenceImplicit_t *)decoded)->value != 6
       || !constraints_reject(&asn_DEF_SequenceImplicit, decoded)) {
        if(decoded) asn_DEF_SequenceImplicit.op->free_struct(
            &asn_DEF_SequenceImplicit, decoded, ASFM_FREE_EVERYTHING);
        fprintf(stderr, "C BER or constraint check accepted bad implicit INTEGER\n");
        return 1;
    }
    asn_DEF_SequenceImplicit.op->free_struct(
        &asn_DEF_SequenceImplicit, decoded, ASFM_FREE_EVERYTHING);
    sequence.value = 6;
    if(!constraints_reject(&asn_DEF_Sequence, &sequence)) {
        fprintf(stderr, "C constraints accepted out-of-range natural named INTEGER\n");
        return 1;
    }
    decoded = NULL;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_Sequence, &decoded,
                        invalid_natural_range, sizeof(invalid_natural_range));
    if(result.code != RC_OK || result.consumed != sizeof(invalid_natural_range) || !decoded
       || ((Sequence_t *)decoded)->value != 6
       || !constraints_reject(&asn_DEF_Sequence, decoded)) {
        if(decoded) asn_DEF_Sequence.op->free_struct(
            &asn_DEF_Sequence, decoded, ASFM_FREE_EVERYTHING);
        fprintf(stderr, "C BER or constraint check accepted bad natural INTEGER\n");
        return 1;
    }
    asn_DEF_Sequence.op->free_struct(&asn_DEF_Sequence, decoded, ASFM_FREE_EVERYTHING);
    return 0;
}

/*
 * Purpose: compare a named INTEGER with a finite bounded BIT STRING sibling.
 * Inputs: none. The five-bit value exercises the sibling's unused-bit field.
 * Returns zero on exact DER/CER parity; otherwise one.
 * Errors: C encoder/decoder or comparison failures are reported by check_vector.
 * Source: NamedIntegerRecord.asn1 and X.690. Date: 2026-11-01.
 * Responsible: asn1c maintainers. History: bounded string sibling coverage.
 * Example: five bits `10100` are stored in one octet as `a0` with three unused bits.
 */
static int
check_bit_sibling(void) {
    static uint8_t bits[] = {0xa0};
    static const uint8_t der[] = {0x30, 7, 2, 1, 2, 3, 2, 3, 0xa0};
    static const uint8_t cer[] = {0x30, 0x80, 2, 1, 2, 3, 2, 3, 0xa0, 0, 0};
    SequenceBits_t value = {2, {bits, sizeof(bits), 3}};
    return check_vector(&asn_DEF_SequenceBits, &value,
                        der, sizeof(der), cer, sizeof(cer));
}

/*
 * Purpose: compare canonical SET encodings and verify optional/tagged fields.
 * Inputs: none; presence maps mark the generated C SET components.
 * Returns zero on parity, otherwise one. Errors: vector helper failure.
 * Source: NamedIntegerRecord.asn1 and X.690. Date: 2026-11-01.
 * Responsible: asn1c maintainers. History: SET reference gate vectors.
 * Example: universal tags sort before a context-specific IMPLICIT tag.
 */
static int
check_sets(void) {
    static const uint8_t octets[] = {0xaa};
    static const uint8_t der[] = {0x31, 9, 1, 1, 0xff, 2, 1, 2, 4, 1, 0xaa};
    static const uint8_t cer[] = {0x31, 0x80, 1, 1, 0xff, 2, 1, 2, 4, 1, 0xaa, 0, 0};
    static const uint8_t optional_absent_der[] = {0x31, 6, 1, 1, 0xff, 4, 1, 0xaa};
    static const uint8_t optional_absent_cer[] = {0x31, 0x80, 1, 1, 0xff, 4, 1, 0xaa, 0, 0};
    static const uint8_t implicit_der[] = {0x31, 6, 1, 1, 0xff, 0x83, 1, 2};
    static const uint8_t implicit_cer[] = {0x31, 0x80, 1, 1, 0xff, 0x83, 1, 2, 0, 0};
    static const uint8_t explicit_der[] = {0x31, 8, 1, 1, 0xff, 0xa3, 3, 2, 1, 2};
    static const uint8_t explicit_cer[] = {
        0x31, 0x80, 1, 1, 0xff, 0xa3, 0x80, 2, 1, 2, 0, 0, 0, 0
    };
    static const uint8_t explicit_absent_der[] = {0x31, 3, 1, 1, 0xff};
    static const uint8_t explicit_absent_cer[] = {0x31, 0x80, 1, 1, 0xff, 0, 0};
    static const uint8_t present_der[] = {0x31, 9, 1, 1, 0xff, 2, 1, 2, 4, 1, 0xaa};
    static const uint8_t present_cer[] = {0x31, 0x80, 1, 1, 0xff, 2, 1, 2, 4, 1, 0xaa, 0, 0};
    Small_t small = 2;
    Set_t required = {1, 2, {(uint8_t *)octets, sizeof(octets)}, {0}};
    SetOptional_t absent = {{(uint8_t *)octets, sizeof(octets)}, NULL, 1, {0}};
    SetOptional_t present = {{(uint8_t *)octets, sizeof(octets)}, &small, 1, {0}};
    SetImplicit_t implicit = {2, 1, {0}};
    SetExplicit_t explicit_value = {&small, 1, {0}};
    SetExplicit_t explicit_absent = {NULL, 1, {0}};
    ASN_SET_MKPRESENT(required._presence_map, Set_PR_flag);
    ASN_SET_MKPRESENT(required._presence_map, Set_PR_value);
    ASN_SET_MKPRESENT(required._presence_map, Set_PR_tail);
    ASN_SET_MKPRESENT(absent._presence_map, SetOptional_PR_tail);
    ASN_SET_MKPRESENT(absent._presence_map, SetOptional_PR_flag);
    ASN_SET_MKPRESENT(present._presence_map, SetOptional_PR_tail);
    ASN_SET_MKPRESENT(present._presence_map, SetOptional_PR_value);
    ASN_SET_MKPRESENT(present._presence_map, SetOptional_PR_flag);
    ASN_SET_MKPRESENT(implicit._presence_map, SetImplicit_PR_value);
    ASN_SET_MKPRESENT(implicit._presence_map, SetImplicit_PR_flag);
    ASN_SET_MKPRESENT(explicit_value._presence_map, SetExplicit_PR_value);
    ASN_SET_MKPRESENT(explicit_value._presence_map, SetExplicit_PR_flag);
    ASN_SET_MKPRESENT(explicit_absent._presence_map, SetExplicit_PR_flag);
    if(check_vector(&asn_DEF_Set, &required, der, sizeof(der), cer, sizeof(cer))) return 1;
    if(check_vector(&asn_DEF_SetOptional, &absent,
                    optional_absent_der, sizeof(optional_absent_der),
                    optional_absent_cer, sizeof(optional_absent_cer))) return 1;
    if(check_vector(&asn_DEF_SetOptional, &present,
                    present_der, sizeof(present_der), present_cer, sizeof(present_cer)))
        return 1;
    if(check_vector(&asn_DEF_SetImplicit, &implicit,
                    implicit_der, sizeof(implicit_der), implicit_cer, sizeof(implicit_cer)))
        return 1;
    if(check_vector(&asn_DEF_SetExplicit, &explicit_value,
                    explicit_der, sizeof(explicit_der), explicit_cer, sizeof(explicit_cer)))
        return 1;
    return check_vector(&asn_DEF_SetExplicit, &explicit_absent,
                        explicit_absent_der, sizeof(explicit_absent_der),
                        explicit_absent_cer, sizeof(explicit_absent_cer));
}

/*
 * Purpose: run the live C parity checks for each named INTEGER record shape.
 * Inputs: none. Returns standard zero on success and one on first mismatch.
 * Errors: helper failures are reported on stderr with the descriptor name.
 * Source: generated C record descriptors. Date: 2026-11-01.
 * Responsible: asn1c maintainers. History: focused generator parity fixture.
 * Example: `c-named-integer-record` returns zero when all vectors match.
 */
int
main(void) {
    if(check_sequences() || check_bit_sibling() || check_sets()) return 1;
    puts("named INTEGER record C vectors passed");
    return 0;
}
