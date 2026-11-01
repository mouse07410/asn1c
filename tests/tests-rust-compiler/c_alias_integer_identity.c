/*
 * Verify alias identity, exact BER/CER prefixes, bounds, and DEFAULT siblings.
 * Original source: C differential counterpart to Rust alias identity tests.
 * Version/date: 1.0, 2026-11-01. Inputs: generated descriptors for two modules.
 * Returns: EXIT_SUCCESS when all 11 fixed-value pairs and negative checks pass.
 * Errors: Reports the first mismatch and exits nonzero; C has no exceptions.
 * Responsible party: asn1c maintainers. History: alias identity regressions.
 * Example: compile with both alias ASN.1 files in one generated C directory.
 */
#include <DefaultSequence.h>
#include <DefaultSet.h>
#include <Signed-Alias.h>
#include <Signed-Base.h>
#include <Singleton.h>
#include <Small.h>
#include <asn_application.h>
#include <constraints.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIRE_CAPACITY 32

/*
 * Purpose: release one decoded allocation without trusting a missing callback.
 * Original source: generated C descriptor ownership API.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type describes the value; value points at its owned pointer slot.
 * Returns: no value; successful release sets *value to NULL.
 * Errors: a NULL descriptor, callback, slot, or pointee is ignored safely.
 * Responsible party: asn1c maintainers. History: regression harness cleanup.
 * Example: release_value(&asn_DEF_DefaultSet, &decoded).
 */
static void
release_value(asn_TYPE_descriptor_t *type, void **value) {
    if(type && type->op && type->op->free_struct && value && *value) {
        type->op->free_struct(type, *value, ASFM_FREE_EVERYTHING);
        *value = NULL;
    }
}

/*
 * Purpose: compare generated constraint validation with one expected result.
 * Original source: generated descriptor constraints and X.680 subtype bounds.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type/value identify a candidate; should_accept and label describe it.
 * Returns: zero when the constraint result matches, otherwise one.
 * Errors: invalid inputs or a mismatched constraint result return one.
 * Responsible party: asn1c maintainers. History: alias boundary coverage.
 * Example: check_constraint(&asn_DEF_Singleton, &one, 0, "below range").
 */
static int
check_constraint(asn_TYPE_descriptor_t *type, const void *value,
                 int should_accept, const char *label) {
    char error[128];
    size_t error_size = sizeof(error); /* Diagnostic capacity state variable. */
    int accepted;
    if(!type || !value || !type->op || !label) return 1;
    accepted = asn_check_constraints(type, value, error, &error_size) == 0;
    if(accepted == should_accept) return 0;
    fprintf(stderr, "%s: constraint result mismatch\n", label);
    return 1;
}

/*
 * Purpose: compare generated encoder bytes with one fixed canonical vector.
 * Original source: asn1c C encoder API and X.690 DER/CER rules.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type/expected select the value; syntax selects the codec; wire and
 * wire_size bound the expected bytes.
 * Returns: zero on exact byte parity, otherwise one.
 * Errors: invalid arguments, capacity excess, or output mismatch return one.
 * Responsible party: asn1c maintainers. History: alias wire identity probe.
 * Example: check_encoded_bytes(&asn_DEF_Small, &two, ATS_DER, der, sizeof(der)).
 */
static int
check_encoded_bytes(asn_TYPE_descriptor_t *type, const void *expected,
                    enum asn_transfer_syntax syntax, const uint8_t *wire,
                    size_t wire_size) {
    uint8_t actual[WIRE_CAPACITY];
    asn_enc_rval_t encoded;
    if(!type || !type->op || !expected || !wire || !wire_size
       || wire_size > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, syntax, type, expected,
                                   actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != wire_size
       || memcmp(actual, wire, wire_size)) {
        fprintf(stderr, "%s: fixed encoding mismatch\n", type->name);
        return 1;
    }
    return 0;
}

/*
 * Purpose: compare DEFAULT records by ASN.1 value rather than C storage state.
 * Original source: generated DEFAULT semantics and BOOLEAN nonzero truth values.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type selects an alias record; expected and actual are complete values.
 * Returns: one when equal, zero when not equal.
 * Errors: caller validates type callbacks before this helper is called.
 * Responsible party: asn1c maintainers. History: DEFAULT decode normalization.
 * Example: a BOOLEAN TRUE decoded as 0xff equals a default stored as 1.
 */
static int
values_equal(asn_TYPE_descriptor_t *type, const void *expected, const void *actual) {
    if(type == &asn_DEF_DefaultSequence) {
        const DefaultSequence_t *left = expected;
        const DefaultSequence_t *right = actual;
        int left_flag = left->flag ? *left->flag != 0 : 1;
        int right_flag = right->flag ? *right->flag != 0 : 1;
        return left->value == right->value && left_flag == right_flag;
    }
    if(type == &asn_DEF_DefaultSet) {
        const DefaultSet_t *left = expected;
        const DefaultSet_t *right = actual;
        int left_flag = left->flag ? *left->flag != 0 : 1;
        int right_flag = right->flag ? *right->flag != 0 : 1;
        /* Compare SET fields, not its generated presence-map representation. */
        /* BOOLEAN decode may store TRUE as 0xff, while defaults use value 1. */
        return left->value == right->value && left_flag == right_flag;
    }
    return type->op->compare_struct(type, expected, actual) == 0;
}

/*
 * Purpose: decode one complete value and check its semantics and constraints.
 * Original source: generated BER/CER decoder and descriptor comparison APIs.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type/syntax select the decoder; wire/wire_size bound input;
 * expected is the matching C value.
 * Returns: zero on exact successful decode and value parity, otherwise one.
 * Errors: decoder allocations are released on success and every failure path.
 * Responsible party: asn1c maintainers. History: identity and DEFAULT vectors.
 * Example: check_decoded_value(&asn_DEF_Small, ATS_CER, wire, size, &two).
 */
static int
check_decoded_value(asn_TYPE_descriptor_t *type, enum asn_transfer_syntax syntax,
                    const void *wire, size_t wire_size, const void *expected) {
    asn_dec_rval_t decoded;
    void *actual = NULL; /* Decoded allocation ownership state variable. */
    int failed; /* Decode validation state variable. */
    if(!type || !type->op || !type->op->compare_struct || !type->op->free_struct
       || !expected
       || !wire || !wire_size) return 1;
    decoded = asn_decode(NULL, syntax, type, &actual, wire, wire_size);
    failed = decoded.code != RC_OK || decoded.consumed != wire_size || !actual;
    if(!failed && !values_equal(type, expected, actual)) {
        fprintf(stderr, "%s: decoded structure differs\n", type->name);
        failed = 1;
    }
    if(!failed && asn_check_constraints(type, actual, NULL, NULL) != 0) {
        fprintf(stderr, "%s: decoded structure violates constraints\n", type->name);
        failed = 1;
    }
    release_value(type, &actual);
    if(failed) fprintf(stderr, "%s: decode or semantic mismatch\n", type->name);
    return failed;
}

/*
 * Purpose: check that one decoder consumes exactly the first encoded value.
 * Original source: BER/CER prefix-decoding contract.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type/syntax select the decoder; wire/wire_size bound input;
 * expected is its semantic value.
 * Returns: zero for exact prefix consumption and matching value, otherwise one.
 * Errors: invalid sizes or decoder failures return one; decoded storage is freed.
 * Responsible party: asn1c maintainers. History: alias prefix parity coverage.
 * Example: a trailing 0xee remains outside the consumed CER prefix.
 */
static int
check_decoded_prefix(asn_TYPE_descriptor_t *type, enum asn_transfer_syntax syntax,
                     const uint8_t *wire, size_t wire_size,
                     const void *expected) {
    uint8_t suffixed[WIRE_CAPACITY];
    asn_dec_rval_t decoded;
    void *actual = NULL; /* Decoded allocation ownership state variable. */
    int failed; /* Prefix validation state variable. */
    if(wire_size >= sizeof(suffixed) || !type || !type->op
       || !wire || !wire_size
       || !type->op->compare_struct || !type->op->free_struct || !expected) return 1;
    memcpy(suffixed, wire, wire_size);
    suffixed[wire_size] = 0xee;
    decoded = asn_decode(NULL, syntax, type, &actual, suffixed, wire_size + 1);
    failed = decoded.code != RC_OK || decoded.consumed != wire_size || !actual;
    if(!failed) failed = !values_equal(type, expected, actual);
    release_value(type, &actual);
    if(failed) fprintf(stderr, "%s: decoder did not consume the exact prefix\n",
                       type->name);
    return failed;
}

/*
 * Purpose: run all fixed byte, decode, prefix, and range checks for one value.
 * Original source: asn1c C codec API and named alias regression requirements.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type/expected select the value; der/cer arguments hold fixed vectors.
 * Returns: zero when every check succeeds, otherwise one.
 * Errors: any encoder, decoder, constraint, or prefix mismatch returns one.
 * Responsible party: asn1c maintainers. History: C counterpart to Rust vectors.
 * Example: check both DER and CER forms of a bounded signed alias.
 */
static int
check_vector(asn_TYPE_descriptor_t *type, const void *expected,
             const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    if(check_constraint(type, expected, 1, type ? type->name : "(null)")) return 1;
    if(check_encoded_bytes(type, expected, ATS_DER, der, der_size)
       || check_encoded_bytes(type, expected, ATS_CER, cer, cer_size)) return 1;
    if(check_decoded_value(type, ATS_BER, der, der_size, expected)
       || check_decoded_value(type, ATS_BER, cer, cer_size, expected)
       || check_decoded_value(type, ATS_CER, cer, cer_size, expected)) return 1;
    if(check_decoded_prefix(type, ATS_BER, der, der_size, expected)
       || check_decoded_prefix(type, ATS_CER, cer, cer_size, expected)) return 1;
    return 0;
}

/*
 * Purpose: require a complete noncanonical wire form to fail one decoder.
 * Original source: strict CER decoder contract and generated C ownership API.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: type/syntax select the decoder; wire and size bound the TLV bytes.
 * Returns: zero only for RC_FAIL; all other outcomes return one.
 * Errors: invalid arguments or accepted/nonterminal input is a test failure.
 * Responsible party: asn1c maintainers. History: canonical default rejection.
 * Example: strict CER must reject a reversed SET field sequence.
 */
static int
check_decoder_rejects(asn_TYPE_descriptor_t *type, enum asn_transfer_syntax syntax,
                      const uint8_t *wire, size_t wire_size) {
    asn_dec_rval_t decoded;
    void *value = NULL; /* Decoded allocation ownership state variable. */
    if(!type || !type->op || !type->op->free_struct || !wire || !wire_size) return 1;
    decoded = asn_decode(NULL, syntax, type, &value, wire, wire_size);
    release_value(type, &value);
    if(decoded.code == RC_FAIL) return 0;
    fprintf(stderr, "%s: decoder accepted a noncanonical wire form\n", type->name);
    return 1;
}

/*
 * Purpose: allow reversed SET components in BER but reject them in strict CER.
 * Original source: X.690 SET ordering and generated C record descriptors.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: expected is the SET whose fields are reversed on the wire.
 * Returns: zero when BER accepts and CER rejects, otherwise one.
 * Errors: decode mismatch or a noncanonical CER acceptance returns one.
 * Responsible party: asn1c maintainers. History: SET order validation.
 * Example: context-tagged FALSE precedes universal INTEGER in the input.
 */
static int
check_set_reversed(const DefaultSet_t *expected) {
    static const uint8_t reversed[] = {
        0x31, 0x80, 0x84, 0x01, 0x00, 0x02, 0x01, 0xfe, 0x00, 0x00
    };
    if(check_decoded_value(&asn_DEF_DefaultSet, ATS_BER, reversed,
                           sizeof(reversed), expected)) return 1;
    return check_decoder_rejects(&asn_DEF_DefaultSet, ATS_CER, reversed,
                                 sizeof(reversed));
}

/*
 * Purpose: permit explicit DEFAULT TRUE in BER but reject it in strict CER.
 * Original source: X.690 canonical DEFAULT omission and generated C descriptors.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: expected is the semantic SEQUENCE containing default TRUE.
 * Returns: zero when BER accepts and strict CER rejects, otherwise one.
 * Errors: decode mismatch or CER acceptance returns one.
 * Responsible party: asn1c maintainers. History: BOOLEAN default normalization.
 * Example: CER rejects an explicitly encoded TRUE DEFAULT field.
 */
static int
check_explicit_default(const DefaultSequence_t *expected) {
    static const uint8_t explicit_true[] = {
        0x30, 0x80, 0x02, 0x01, 0xfe, 0x84, 0x01, 0xff, 0x00, 0x00
    };
    if(check_decoded_value(&asn_DEF_DefaultSequence, ATS_BER, explicit_true,
                           sizeof(explicit_true), expected)) return 1;
    return check_decoder_rejects(&asn_DEF_DefaultSequence, ATS_CER,
                                 explicit_true, sizeof(explicit_true));
}

/*
 * Purpose: check DEFAULT TRUE omission for noncanonical nonzero C booleans.
 * Original source: BOOLEAN nonzero truth contract and generated DEFAULT callbacks.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: none; local records use true values 0xff and 7.
 * Returns: zero when both DER and CER omit TRUE for both record kinds.
 * Errors: any encoded byte mismatch returns one; no decoded storage is allocated.
 * Responsible party: asn1c maintainers. History: boolean default regression.
 * Example: a C BOOLEAN_t value of 7 still compares equal to DEFAULT TRUE.
 */
static int
check_noncanonical_default_truth(void) {
    static const uint8_t sequence_der[] = {0x30, 0x03, 0x02, 0x01, 0xfe};
    static const uint8_t sequence_cer[] = {0x30, 0x80, 0x02, 0x01, 0xfe, 0, 0};
    static const uint8_t set_der[] = {0x31, 0x03, 0x02, 0x01, 0xfe};
    static const uint8_t set_cer[] = {0x31, 0x80, 0x02, 0x01, 0xfe, 0, 0};
    BOOLEAN_t truth_values[] = {0xff, 7};
    size_t index; /* Truth representation iteration state variable. */
    for(index = 0; index < sizeof(truth_values) / sizeof(truth_values[0]); index++) {
        DefaultSequence_t sequence = {
            .value = -2,
            .flag = &truth_values[index],
        };
        DefaultSet_t set = {
            .flag = &truth_values[index],
            .value = -2,
        };
        ASN_SET_MKPRESENT(set._presence_map, DefaultSet_PR_flag);
        ASN_SET_MKPRESENT(set._presence_map, DefaultSet_PR_value);
        if(check_encoded_bytes(&asn_DEF_DefaultSequence, &sequence, ATS_DER,
                               sequence_der, sizeof(sequence_der))
           || check_encoded_bytes(&asn_DEF_DefaultSequence, &sequence, ATS_CER,
                                  sequence_cer, sizeof(sequence_cer))
           || check_encoded_bytes(&asn_DEF_DefaultSet, &set, ATS_DER,
                                  set_der, sizeof(set_der))
           || check_encoded_bytes(&asn_DEF_DefaultSet, &set, ATS_CER,
                                  set_cer, sizeof(set_cer))) {
            fprintf(stderr, "DEFAULT TRUE omission failed for BOOLEAN_t %u\n",
                    truth_values[index]);
            return 1;
        }
    }
    return 0;
}

/*
 * Purpose: reject values immediately below and above each aliased INTEGER range.
 * Original source: generated alias constraint callbacks and X.680 subtype bounds.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: none; local candidates exercise Small, Signed-Alias, and Singleton.
 * Returns: zero when all candidates fail constraints, otherwise one.
 * Errors: an accepted out-of-range value fails the test; C has no exceptions.
 * Responsible party: asn1c maintainers. History: alias range regressions.
 * Example: Singleton accepts only 2 and must reject both 1 and 3.
 */
static int
check_bad_alias_ranges(void) {
    long signed_bad_low = -3, signed_bad_high = 6;
    long singleton_bad_low = 1, singleton_bad_high = 3;
    long small_bad_low = -1, small_bad_high = 6;
    return check_constraint(&asn_DEF_Small, &small_bad_low, 0, "Small below range")
        || check_constraint(&asn_DEF_Small, &small_bad_high, 0, "Small above range")
        || check_constraint(&asn_DEF_Signed_Alias, &signed_bad_low, 0, "Signed-Alias below range")
        || check_constraint(&asn_DEF_Signed_Alias, &signed_bad_high, 0, "Signed-Alias above range")
        || check_constraint(&asn_DEF_Singleton, &singleton_bad_low, 0, "Singleton below range")
        || check_constraint(&asn_DEF_Singleton, &singleton_bad_high, 0, "Singleton above range");
}

/*
 * Purpose: run all 11 fixed value pairs and independent range/canonical checks.
 * Original source: AliasIntegerRecord and AliasIntegerIdentity ASN.1 schemas.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: no parameters; generated descriptors supply the tested values.
 * Returns: EXIT_SUCCESS on parity, EXIT_FAILURE on the first regression.
 * Errors: diagnostics identify the failed type, range, or canonical rule.
 * Responsible party: asn1c maintainers. History: transparent alias identity.
 * Example: run after generating C from both schemas in one module set.
 */
int
main(void) {
    static const uint8_t integer_0[] = {0x02, 0x01, 0x00};
    static const uint8_t integer_2[] = {0x02, 0x01, 0x02};
    static const uint8_t integer_5[] = {0x02, 0x01, 0x05};
    static const uint8_t integer_minus_2[] = {0x02, 0x01, 0xfe};
    static const uint8_t sequence_default_der[] = {0x30, 0x03, 0x02, 0x01, 0xfe};
    static const uint8_t sequence_default_cer[] = {0x30, 0x80, 0x02, 0x01, 0xfe, 0, 0};
    static const uint8_t sequence_false_der[] = {0x30, 0x06, 0x02, 0x01, 0xfe, 0x84, 1, 0};
    static const uint8_t sequence_false_cer[] = {
        0x30, 0x80, 0x02, 0x01, 0xfe, 0x84, 1, 0, 0, 0
    };
    static const uint8_t set_default_der[] = {0x31, 0x03, 0x02, 0x01, 0xfe};
    static const uint8_t set_default_cer[] = {0x31, 0x80, 0x02, 0x01, 0xfe, 0, 0};
    static const uint8_t set_false_der[] = {0x31, 0x06, 0x02, 0x01, 0xfe, 0x84, 1, 0};
    static const uint8_t set_false_cer[] = {
        0x31, 0x80, 0x02, 0x01, 0xfe, 0x84, 1, 0, 0, 0
    };
    long small_0 = 0, small_2 = 2, small_5 = 5;
    Signed_Alias_t signed_minus_2 = -2, signed_0 = 0, signed_5 = 5;
    Singleton_t singleton_2 = 2;
    BOOLEAN_t default_true = 1, explicit_false = 0;
    DefaultSequence_t sequence_true = {.value = -2, .flag = &default_true};
    DefaultSequence_t sequence_false = {.value = -2, .flag = &explicit_false};
    DefaultSet_t set_true = {.flag = &default_true, .value = -2};
    DefaultSet_t set_false = {.flag = &explicit_false, .value = -2};
    ASN_SET_MKPRESENT(set_true._presence_map, DefaultSet_PR_flag);
    ASN_SET_MKPRESENT(set_true._presence_map, DefaultSet_PR_value);
    ASN_SET_MKPRESENT(set_false._presence_map, DefaultSet_PR_flag);
    ASN_SET_MKPRESENT(set_false._presence_map, DefaultSet_PR_value);

    if(check_vector(&asn_DEF_Small, &small_0, integer_0, sizeof(integer_0),
                    integer_0, sizeof(integer_0))
       || check_vector(&asn_DEF_Small, &small_2, integer_2, sizeof(integer_2),
                       integer_2, sizeof(integer_2))
       || check_vector(&asn_DEF_Small, &small_5, integer_5, sizeof(integer_5),
                       integer_5, sizeof(integer_5))) return EXIT_FAILURE;
    if(check_vector(&asn_DEF_Signed_Alias, &signed_minus_2, integer_minus_2,
                    sizeof(integer_minus_2), integer_minus_2, sizeof(integer_minus_2))
       || check_vector(&asn_DEF_Signed_Alias, &signed_0, integer_0, sizeof(integer_0),
                       integer_0, sizeof(integer_0))
       || check_vector(&asn_DEF_Signed_Alias, &signed_5, integer_5, sizeof(integer_5),
                       integer_5, sizeof(integer_5))) return EXIT_FAILURE;
    if(check_vector(&asn_DEF_Singleton, &singleton_2, integer_2, sizeof(integer_2),
                    integer_2, sizeof(integer_2))) return EXIT_FAILURE;
    if(check_vector(&asn_DEF_DefaultSequence, &sequence_true,
                    sequence_default_der, sizeof(sequence_default_der),
                    sequence_default_cer, sizeof(sequence_default_cer))
       || check_vector(&asn_DEF_DefaultSequence, &sequence_false,
                       sequence_false_der, sizeof(sequence_false_der),
                       sequence_false_cer, sizeof(sequence_false_cer)))
        return EXIT_FAILURE;
    if(check_vector(&asn_DEF_DefaultSet, &set_true,
                    set_default_der, sizeof(set_default_der),
                    set_default_cer, sizeof(set_default_cer))
       || check_vector(&asn_DEF_DefaultSet, &set_false,
                       set_false_der, sizeof(set_false_der),
                       set_false_cer, sizeof(set_false_cer))) return EXIT_FAILURE;

    if(check_bad_alias_ranges()) return EXIT_FAILURE;
    if(check_noncanonical_default_truth()
       || check_set_reversed(&set_false)
       || check_explicit_default(&sequence_true))
        return EXIT_FAILURE;
    puts("alias identity C vectors passed: 11 value pairs and boundary checks");
    puts("noncanonical BOOLEAN DEFAULT TRUE encodings omitted for 0xff and 7");
    return EXIT_SUCCESS;
}
