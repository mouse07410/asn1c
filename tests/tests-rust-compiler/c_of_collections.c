/* Compare generated C collection BER/DER/CER behavior with fixed Rust vectors. */
#include <asn_application.h>
#include <SequenceBoolean.h>
#include <SequenceInteger.h>
#include <SequenceNull.h>
#include <SetBoolean.h>
#include <SetInteger.h>
#include <SetNull.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 128

/* One exact generated C encoding vector. */
typedef struct encoding_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated collection descriptor. */
    const void *value; /* Borrowed generated C value. */
    enum asn_transfer_syntax syntax; /* DER or CER. */
    const uint8_t *wire; /* Canonical encoded bytes. */
    size_t size; /* Canonical encoded byte count. */
} encoding_case_t;

/*
 * Purpose: compare a generated C collection encoder with canonical bytes.
 * Parameters: item contains the descriptor, value, syntax, and expected TLV.
 * Returns zero for exact equality or one after reporting an encoder mismatch.
 * Errors: encoder failures and output mismatches return one.
 * Source: generated C collection descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: first OF differential.
 * Example: check_encoding(&case) compares one DER sequence-of value.
 */
static int
check_encoding(const encoding_case_t *item) {
    uint8_t actual[WIRE_MAX];
    asn_enc_rval_t result;
    if(!item || !item->type || !item->value || !item->wire
       || item->size > sizeof(actual)) return 1;
    result = asn_encode_to_buffer(NULL, item->syntax, item->type, item->value,
                                  actual, sizeof(actual));
    if(result.encoded < 0 || (size_t)result.encoded != item->size
       || memcmp(actual, item->wire, item->size)) {
        fprintf(stderr, "C collection encode mismatch: %s syntax=%d\n",
                item->type->name, (int)item->syntax);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode one collection and compare its canonical re-encoding.
 * Parameters: type/syntax select the decoder; wire is input; canonical is the
 * expected re-encoding under output_syntax; consumed is exact prefix length.
 * Returns zero on status, consumption, and byte equality; partial values free.
 * Errors: decoder or encoder mismatches return one.
 * Source: generated C collection descriptors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: decode interoperability.
 * Example: BER SET OF order can canonicalize under CER to sorted child TLVs.
 */
static int
check_decode(const asn_TYPE_descriptor_t *type, enum asn_transfer_syntax syntax,
             const uint8_t *wire, size_t size,
             enum asn_transfer_syntax output_syntax, const uint8_t *canonical,
             size_t canonical_size, size_t consumed) {
    uint8_t actual[WIRE_MAX];
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    asn_enc_rval_t encoded = {0, 0, 0};
    if(!type || !wire || !size || !canonical || canonical_size > sizeof(actual)) return 1;
    result = asn_decode(NULL, syntax, type, &decoded, wire, size);
    failed = result.code != RC_OK || result.consumed != consumed || !decoded;
    if(!failed) {
        encoded = asn_encode_to_buffer(NULL, output_syntax, type, decoded,
                                       actual, sizeof(actual));
        failed = encoded.encoded < 0 || (size_t)encoded.encoded != canonical_size
            || memcmp(actual, canonical, canonical_size);
    }
    if(failed) {
        fprintf(stderr,
            "C collection decode/reencode mismatch: %s syntax=%d code=%d consumed=%zu/%zu "
            "encoded=%zd/%zu\n", type ? type->name : "(null)", (int)syntax,
            (int)result.code, result.consumed, consumed, encoded.encoded,
            canonical_size);
    }
    if(decoded && type->op->free_struct)
        type->op->free_struct(type, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: require a collection decoder to reject malformed/noncanonical data.
 * Parameters: type/syntax select the decoder; wire/size describe one TLV.
 * Returns zero on rejection, one if accepted; any allocated value is freed.
 * Errors: decoder acceptance is reported as a fixture failure.
 * Source: generated C BER/CER collection decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: negative OF vectors.
 * Example: CER must reject a definite-length root.
 */
static int
check_rejects(const asn_TYPE_descriptor_t *type, enum asn_transfer_syntax syntax,
              const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    if(!type || !wire || !size) return 1;
    asn_dec_rval_t result = asn_decode(NULL, syntax, type, &decoded, wire, size);
    int rejected = result.code != RC_OK;
    if(!rejected) fprintf(stderr, "C collection decoder accepted invalid %s\n",
                          type->name);
    if(decoded && type->op->free_struct)
        type->op->free_struct(type, decoded, ASFM_FREE_EVERYTHING);
    return rejected ? 0 : 1;
}

/*
 * Purpose: run canonical encoding vectors for all approved element kinds.
 * Parameters: none. Returns zero when all DER/CER encodings match.
 * Errors: any exact byte mismatch returns one.
 * Source: X.690 collection framing and generated C descriptors.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: initial SEQUENCE OF/SET OF comparison. Example: empty SEQUENCE OF.
 */
static int
check_encodings(void) {
    static const uint8_t seq_bool_der[] = {0x30, 9, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff};
    static const uint8_t seq_bool_cer[] = {
        0x30, 0x80, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff, 0, 0
    };
    static const uint8_t empty_seq_der[] = {0x30, 0};
    static const uint8_t empty_seq_cer[] = {0x30, 0x80, 0, 0};
    static const uint8_t single_bool_der[] = {0x30, 3, 1, 1, 0xff};
    static const uint8_t single_bool_cer[] = {0x30, 0x80, 1, 1, 0xff, 0, 0};
    static const uint8_t set_bool_der[] = {0x31, 9, 1, 1, 0, 1, 1, 0xff, 1, 1, 0xff};
    static const uint8_t set_bool_cer[] = {
        0x31, 0x80, 1, 1, 0, 1, 1, 0xff, 1, 1, 0xff, 0, 0
    };
    static const uint8_t seq_null_der[] = {0x30, 6, 5, 0, 5, 0, 5, 0};
    static const uint8_t seq_null_cer[] = {0x30, 0x80, 5, 0, 5, 0, 5, 0, 0, 0};
    static const uint8_t set_null_der[] = {0x31, 6, 5, 0, 5, 0, 5, 0};
    static const uint8_t set_null_cer[] = {0x31, 0x80, 5, 0, 5, 0, 5, 0, 0, 0};
    static const uint8_t seq_int_der[] = {0x30, 9, 2, 1, 2, 2, 1, 0xff, 2, 1, 0};
    static const uint8_t seq_int_cer[] = {
        0x30, 0x80, 2, 1, 2, 2, 1, 0xff, 2, 1, 0, 0, 0
    };
    static const uint8_t set_int_der[] = {
        0x31, 0x0d, 2, 1, 0, 2, 1, 2, 2, 1, 0xff, 2, 2, 0, 0x80
    };
    static const uint8_t set_int_cer[] = {
        0x31, 0x80, 2, 1, 0, 2, 1, 2, 2, 1, 0xff, 2, 2, 0, 0x80, 0, 0
    };
    static const uint8_t empty_set_der[] = {0x31, 0};
    static const uint8_t empty_set_cer[] = {0x31, 0x80, 0, 0};
    BOOLEAN_t yes = 1, no = 0;
    NULL_t null_value = 0;
    long integers[4] = {2, -1, 0, 128};
    SequenceBoolean_t sequence_bool = {0};
    SequenceBoolean_t empty_sequence_bool = {0};
    SequenceBoolean_t single_sequence_bool = {0};
    SetBoolean_t set_bool = {0};
    SetBoolean_t empty_set_bool = {0};
    SequenceNull_t sequence_null = {0};
    SequenceNull_t empty_sequence_null = {0};
    SetNull_t set_null = {0};
    SetNull_t empty_set_null = {0};
    SequenceInteger_t sequence_int = {0};
    SequenceInteger_t empty_sequence_int = {0};
    SetInteger_t set_int = {0};
    SetInteger_t empty_set_int = {0};
    encoding_case_t cases[24];
    size_t count = 0;
    int failed = 0;
    failed |= ASN_SEQUENCE_ADD(&single_sequence_bool.list, &yes) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_bool.list, &yes) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_bool.list, &no) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_bool.list, &yes) != 0;
    failed |= ASN_SET_ADD(&set_bool.list, &yes) != 0;
    failed |= ASN_SET_ADD(&set_bool.list, &no) != 0;
    failed |= ASN_SET_ADD(&set_bool.list, &yes) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_null.list, &null_value) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_null.list, &null_value) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_null.list, &null_value) != 0;
    failed |= ASN_SET_ADD(&set_null.list, &null_value) != 0;
    failed |= ASN_SET_ADD(&set_null.list, &null_value) != 0;
    failed |= ASN_SET_ADD(&set_null.list, &null_value) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_int.list, &integers[0]) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_int.list, &integers[1]) != 0;
    failed |= ASN_SEQUENCE_ADD(&sequence_int.list, &integers[2]) != 0;
    failed |= ASN_SET_ADD(&set_int.list, &integers[0]) != 0;
    failed |= ASN_SET_ADD(&set_int.list, &integers[1]) != 0;
    failed |= ASN_SET_ADD(&set_int.list, &integers[2]) != 0;
    failed |= ASN_SET_ADD(&set_int.list, &integers[3]) != 0;
#define ADD_CASE(descriptor, value, rule, bytes) \
    cases[count++] = (encoding_case_t){&descriptor, &value, rule, bytes, sizeof(bytes)}
    ADD_CASE(asn_DEF_SequenceBoolean, empty_sequence_bool, ATS_DER, empty_seq_der);
    ADD_CASE(asn_DEF_SequenceBoolean, empty_sequence_bool, ATS_CER, empty_seq_cer);
    ADD_CASE(asn_DEF_SequenceBoolean, single_sequence_bool, ATS_DER, single_bool_der);
    ADD_CASE(asn_DEF_SequenceBoolean, single_sequence_bool, ATS_CER, single_bool_cer);
    ADD_CASE(asn_DEF_SequenceBoolean, sequence_bool, ATS_DER, seq_bool_der);
    ADD_CASE(asn_DEF_SequenceBoolean, sequence_bool, ATS_CER, seq_bool_cer);
    ADD_CASE(asn_DEF_SetBoolean, set_bool, ATS_DER, set_bool_der);
    ADD_CASE(asn_DEF_SetBoolean, set_bool, ATS_CER, set_bool_cer);
    ADD_CASE(asn_DEF_SequenceNull, sequence_null, ATS_DER, seq_null_der);
    ADD_CASE(asn_DEF_SequenceNull, sequence_null, ATS_CER, seq_null_cer);
    ADD_CASE(asn_DEF_SetNull, set_null, ATS_DER, set_null_der);
    ADD_CASE(asn_DEF_SetNull, set_null, ATS_CER, set_null_cer);
    ADD_CASE(asn_DEF_SequenceInteger, sequence_int, ATS_DER, seq_int_der);
    ADD_CASE(asn_DEF_SequenceInteger, sequence_int, ATS_CER, seq_int_cer);
    ADD_CASE(asn_DEF_SetInteger, set_int, ATS_DER, set_int_der);
    ADD_CASE(asn_DEF_SetInteger, set_int, ATS_CER, set_int_cer);
    ADD_CASE(asn_DEF_SetBoolean, empty_set_bool, ATS_DER, empty_set_der);
    ADD_CASE(asn_DEF_SetBoolean, empty_set_bool, ATS_CER, empty_set_cer);
    ADD_CASE(asn_DEF_SequenceNull, empty_sequence_null, ATS_DER, empty_seq_der);
    ADD_CASE(asn_DEF_SetNull, empty_set_null, ATS_CER, empty_set_cer);
    ADD_CASE(asn_DEF_SequenceInteger, empty_sequence_int, ATS_DER, empty_seq_der);
    ADD_CASE(asn_DEF_SetInteger, empty_set_int, ATS_CER, empty_set_cer);
#undef ADD_CASE
    for(size_t i = 0; i < count; i++) failed |= check_encoding(&cases[i]);
    free(sequence_bool.list.array);
    free(set_bool.list.array);
    free(sequence_null.list.array);
    free(set_null.list.array);
    free(sequence_int.list.array);
    free(set_int.list.array);
    free(single_sequence_bool.list.array);
    return failed;
}

/*
 * Purpose: verify BER acceptance, canonicalization, and strict CER rejection.
 * Parameters: none. Returns zero when all decode probes match expected behavior.
 * Errors: any unexpected status, value, consumption, or canonicality returns one.
 * Source: C generated collection codecs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: BER/CER negative vectors.
 * Example: reversed BER SET OF re-encodes in sorted CER order.
 */
static int
check_decodings(void) {
    static const uint8_t bool_cer[] = {
        0x30, 0x80, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff, 0, 0
    };
    static const uint8_t bool_der[] = {0x30, 9, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff};
    static const uint8_t set_two_sorted_cer[] = {
        0x31, 0x80, 1, 1, 0, 1, 1, 0xff, 0, 0
    };
    static const uint8_t set_reversed[] = {0x31, 0x80, 1, 1, 0xff, 1, 1, 0, 0, 0};
    static const uint8_t bool_zero_length[] = {0x30, 2, 1, 0};
    static const uint8_t bool_multi_octet[] = {0x30, 4, 1, 2, 0, 1};
    static const uint8_t bool_single_false[] = {0x30, 3, 1, 1, 0};
    static const uint8_t bool_single_true[] = {0x30, 3, 1, 1, 0xff};
    static const uint8_t root_alias[] = {0x3f, 0x10, 0};
    static const uint8_t empty_sequence[] = {0x30, 0};
    static const uint8_t null_der[] = {0x30, 6, 5, 0, 5, 0, 5, 0};
    static const uint8_t null_cer[] = {0x30, 0x80, 5, 0, 5, 0, 5, 0, 0, 0};
    static const uint8_t set_null_der[] = {0x31, 6, 5, 0, 5, 0, 5, 0};
    static const uint8_t set_null_cer[] = {0x31, 0x80, 5, 0, 5, 0, 5, 0, 0, 0};
    static const uint8_t int_der[] = {0x30, 9, 2, 1, 2, 2, 1, 0xff, 2, 1, 0};
    static const uint8_t int_cer[] = {
        0x30, 0x80, 2, 1, 2, 2, 1, 0xff, 2, 1, 0, 0, 0
    };
    static const uint8_t set_int_der[] = {
        0x31, 0x0d, 2, 1, 0, 2, 1, 2, 2, 1, 0xff, 2, 2, 0, 0x80
    };
    static const uint8_t set_int_cer[] = {
        0x31, 0x80, 2, 1, 0, 2, 1, 2, 2, 1, 0xff, 2, 2, 0, 0x80, 0, 0
    };
    static const uint8_t set_int_reversed[] = {
        0x31, 0x80, 2, 2, 0, 0x80, 2, 1, 0xff, 2, 1, 2, 2, 1, 0, 0, 0
    };
    static const uint8_t bool_cer_suffix[] = {
        0x30, 0x80, 1, 1, 0xff, 1, 1, 0, 1, 1, 0xff, 0, 0, 0xaa
    };
    static const uint8_t int_redundant[] = {0x30, 4, 2, 2, 0, 2};
    static const uint8_t int_two_der[] = {0x30, 3, 2, 1, 2};
    static const uint8_t int_out_of_range[] = {0x30, 3, 2, 1, 4};
    static const uint8_t int_four_der[] = {0x30, 3, 2, 1, 4};
    static const uint8_t bad_eoc[] = {0x30, 0x80, 1, 1, 0xff};
    static const uint8_t bad_child[] = {0x30, 2, 5, 0};
    int failed = 0;
    failed |= check_decode(&asn_DEF_SequenceBoolean, ATS_CER,
        bool_cer, sizeof(bool_cer), ATS_CER, bool_cer, sizeof(bool_cer), sizeof(bool_cer));
    failed |= check_decode(&asn_DEF_SequenceBoolean, ATS_CER,
        bool_cer_suffix, sizeof(bool_cer_suffix), ATS_CER,
        bool_cer, sizeof(bool_cer), sizeof(bool_cer));
    failed |= check_decode(&asn_DEF_SequenceBoolean, ATS_BER,
        bool_der, sizeof(bool_der), ATS_DER, bool_der, sizeof(bool_der), sizeof(bool_der));
    failed |= check_decode(&asn_DEF_SetBoolean, ATS_BER,
        set_reversed, sizeof(set_reversed), ATS_CER, set_two_sorted_cer,
        sizeof(set_two_sorted_cer), sizeof(set_reversed));
    failed |= check_decode(&asn_DEF_SequenceBoolean, ATS_BER,
        bool_zero_length, sizeof(bool_zero_length), ATS_DER, bool_single_false,
        sizeof(bool_single_false), sizeof(bool_zero_length));
    failed |= check_decode(&asn_DEF_SequenceBoolean, ATS_BER,
        bool_multi_octet, sizeof(bool_multi_octet), ATS_DER, bool_single_true,
        sizeof(bool_single_true), sizeof(bool_multi_octet));
    failed |= check_decode(&asn_DEF_SequenceBoolean, ATS_BER,
        root_alias, sizeof(root_alias), ATS_DER, empty_sequence,
        sizeof(empty_sequence), sizeof(root_alias));
    failed |= check_decode(&asn_DEF_SequenceNull, ATS_BER,
        null_der, sizeof(null_der), ATS_DER, null_der, sizeof(null_der), sizeof(null_der));
    failed |= check_decode(&asn_DEF_SequenceNull, ATS_CER,
        null_cer, sizeof(null_cer), ATS_CER, null_cer, sizeof(null_cer), sizeof(null_cer));
    failed |= check_decode(&asn_DEF_SetNull, ATS_BER,
        set_null_der, sizeof(set_null_der), ATS_DER,
        set_null_der, sizeof(set_null_der), sizeof(set_null_der));
    failed |= check_decode(&asn_DEF_SetNull, ATS_CER,
        set_null_cer, sizeof(set_null_cer), ATS_CER,
        set_null_cer, sizeof(set_null_cer), sizeof(set_null_cer));
    failed |= check_decode(&asn_DEF_SequenceInteger, ATS_BER,
        int_der, sizeof(int_der), ATS_DER, int_der, sizeof(int_der), sizeof(int_der));
    failed |= check_decode(&asn_DEF_SequenceInteger, ATS_CER,
        int_cer, sizeof(int_cer), ATS_CER, int_cer, sizeof(int_cer), sizeof(int_cer));
    failed |= check_decode(&asn_DEF_SequenceInteger, ATS_BER,
        int_redundant, sizeof(int_redundant), ATS_DER,
        int_two_der, sizeof(int_two_der), sizeof(int_redundant));
    failed |= check_decode(&asn_DEF_SequenceInteger, ATS_BER,
        int_out_of_range, sizeof(int_out_of_range), ATS_DER,
        int_four_der, sizeof(int_four_der), sizeof(int_out_of_range));
    failed |= check_decode(&asn_DEF_SetInteger, ATS_BER,
        set_int_der, sizeof(set_int_der), ATS_DER,
        set_int_der, sizeof(set_int_der), sizeof(set_int_der));
    failed |= check_decode(&asn_DEF_SetInteger, ATS_CER,
        set_int_cer, sizeof(set_int_cer), ATS_CER,
        set_int_cer, sizeof(set_int_cer), sizeof(set_int_cer));
    failed |= check_decode(&asn_DEF_SetInteger, ATS_BER,
        set_int_reversed, sizeof(set_int_reversed), ATS_CER,
        set_int_cer, sizeof(set_int_cer), sizeof(set_int_reversed));
    failed |= check_rejects(&asn_DEF_SetBoolean, ATS_CER,
                            set_reversed, sizeof(set_reversed));
    failed |= check_rejects(&asn_DEF_SequenceBoolean, ATS_CER,
        bool_zero_length, sizeof(bool_zero_length));
    failed |= check_rejects(&asn_DEF_SequenceBoolean, ATS_CER,
        bool_multi_octet, sizeof(bool_multi_octet));
    failed |= check_rejects(&asn_DEF_SequenceBoolean, ATS_CER,
                            root_alias, sizeof(root_alias));
    failed |= check_rejects(&asn_DEF_SequenceInteger, ATS_CER,
                            int_redundant, sizeof(int_redundant));
    failed |= check_rejects(&asn_DEF_SetInteger, ATS_CER,
                            set_int_reversed, sizeof(set_int_reversed));
    failed |= check_rejects(&asn_DEF_SequenceBoolean, ATS_BER,
                            bad_eoc, sizeof(bad_eoc));
    failed |= check_rejects(&asn_DEF_SequenceBoolean, ATS_BER,
                            bad_child, sizeof(bad_child));
    return failed;
}

/*
 * Purpose: run canonical C vectors and BER/CER structural probes.
 * Parameters: none. Returns zero when every differential check passes.
 * Errors: any failed test returns one.
 * Source: generated C collection runtime. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: initial OF conformance.
 * Example: invoked by the backend harness after generated C compilation.
 */
int
main(void) {
    return check_encodings() || check_decodings();
}
