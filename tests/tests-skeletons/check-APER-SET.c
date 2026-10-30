/*
 * Regression tests for the root-only SET APER encoder and decoder.
 * Copyright (c) 2026 asn1c maintainers.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <asn_internal.h>
#include <BOOLEAN.h>
#include <NativeInteger.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <constr_SET.h>

/* Test value storage mirrors a generated SET with one optional DEFAULT. */
typedef struct SET_aper_test_value_s {
    BOOLEAN_t *flag;                 /* Optional BOOLEAN DEFAULT TRUE. */
    long number;                     /* Mandatory constrained INTEGER. */
    unsigned int presence_map[1];    /* Runtime SET member presence bits. */
    asn_struct_ctx_t context;        /* Runtime streaming decode context. */
} SET_aper_test_value_t;

/*
 * Purpose: compare the optional flag with its BOOLEAN DEFAULT value.
 * Source: Generated default_value_cmp callback contract.
 * Version: 2026-10-30.
 * Parameters: sptr points to a BOOLEAN value.
 * Returns: 0 when TRUE is the default, nonzero otherwise.
 * Errors: A NULL value is treated as non-default.
 * Author: asn1c maintainers.
 * History: Added for SET APER default-presence tests.
 * Example: SET_aper_test_flag_cmp(&true_value) returns zero.
 */
static int
SET_aper_test_flag_cmp(const void *sptr) {
    return !sptr || *(const BOOLEAN_t *)sptr != 1;
}

/*
 * Purpose: allocate and set the optional BOOLEAN DEFAULT value.
 * Source: Generated default_value_set callback contract.
 * Version: 2026-10-30.
 * Parameters: sptr points to the member pointer to initialize.
 * Returns: 0 on success; -1 for a missing argument or allocation failure.
 * Errors: The member pointer remains unchanged if allocation fails.
 * Author: asn1c maintainers.
 * History: Added for absent DEFAULT APER decode tests.
 * Example: A NULL member pointer becomes a pointer to TRUE.
 */
static int
SET_aper_test_flag_set(void **sptr) {
    BOOLEAN_t *value;

    if(!sptr) return -1;
    if(*sptr) return 0;
    value = MALLOC(sizeof(*value));
    if(!value) return -1;
    *value = 1;
    *sptr = value;
    return 0;
}

/* The number field uses the full 8-bit constrained APER range. */
static asn_per_constraints_t number_constraints = {
    .value = {
        APC_CONSTRAINED,
        8,
        8,
        0,
        255
    }
};

/* Declaration order intentionally differs from ascending tag order. */
static asn_TYPE_member_t test_members[] = {
    {
        .flags = ATF_POINTER,
        .optional = 1,
        .memb_offset = offsetof(SET_aper_test_value_t, flag),
        .tag = ASN_TAG_CLASS_CONTEXT | (3 << 2),
        .type = &asn_DEF_BOOLEAN,
        .default_value_cmp = SET_aper_test_flag_cmp,
        .default_value_set = SET_aper_test_flag_set,
        .name = "flag"
    },
    {
        .flags = ATF_NOFLAGS,
        .optional = 0,
        .memb_offset = offsetof(SET_aper_test_value_t, number),
        .tag = ASN_TAG_CLASS_CONTEXT | (1 << 2),
        .type = &asn_DEF_NativeInteger,
        .encoding_constraints.per_constraints = &number_constraints,
        .name = "number"
    }
};

/* Canonical root tags order INTEGER before BOOLEAN regardless of declaration. */
static const asn_TYPE_tag2member_t test_tag_order[] = {
    {ASN_TAG_CLASS_CONTEXT | (1 << 2), 1, 0, 0},
    {ASN_TAG_CLASS_CONTEXT | (3 << 2), 0, 0, 0}
};

/* Neither member is mandatory through the runtime presence-map mechanism. */
static const unsigned int mandatory_map[] = {0};

/* Descriptor metadata models compiler output for a non-extensible SET. */
static asn_SET_specifics_t test_specifics = {
    sizeof(SET_aper_test_value_t),
    offsetof(SET_aper_test_value_t, context),
    offsetof(SET_aper_test_value_t, presence_map),
    test_tag_order,
    2,
    test_tag_order,
    2,
    0,
    mandatory_map
};

/* Reusable SET descriptor for the direct runtime API tests. */
static asn_TYPE_descriptor_t test_descriptor = {
    "APER-SET-Test",
    "APER-SET-Test",
    &asn_OP_SET,
    0, 0, 0, 0,
    {0},
    test_members,
    2,
    &test_specifics
};

/*
 * Purpose: assert the SET emits the expected canonical, aligned byte sequence.
 * Source: X.691 SET canonical member ordering and INTEGER APER alignment.
 * Version: 2026-10-30.
 * Parameters: None; uses the static test descriptor.
 * Returns: None.
 * Errors: Assertion failure indicates incorrect SET encoding.
 * Author: asn1c maintainers.
 * History: Added to distinguish tag order from declaration order.
 * Example: number 0x5a and present flag FALSE encode to 80 5a 00.
 */
static void
SET_aper_test_encoding(void) {
    SET_aper_test_value_t value;
    BOOLEAN_t flag = 0;
    uint8_t encoded[8];
    asn_enc_rval_t result;

    memset(&value, 0, sizeof(value));
    value.number = 0x5a;
    value.flag = &flag;
    result = aper_encode_to_buffer(&test_descriptor, 0, &value,
                                   encoded, sizeof(encoded));
    assert(result.encoded == 17);
    assert(encoded[0] == 0x80);
    assert(encoded[1] == 0x5a);
    assert(encoded[2] == 0x00);
}

/*
 * Purpose: round-trip a present optional member after an aligned child value.
 * Source: Public APER encoder and decoder entry points.
 * Version: 2026-10-30.
 * Parameters: None; uses the static test descriptor.
 * Returns: None.
 * Errors: Assertion failure indicates a codec or alignment regression.
 * Author: asn1c maintainers.
 * History: Added for present optional APER SET values.
 * Example: A false optional BOOLEAN follows the constrained INTEGER payload.
 */
static void
SET_aper_test_round_trip(void) {
    SET_aper_test_value_t value;
    SET_aper_test_value_t *decoded = 0;
    BOOLEAN_t flag = 0;
    uint8_t encoded[8];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;

    memset(&value, 0, sizeof(value));
    value.number = 0xa5;
    value.flag = &flag;
    enc = aper_encode_to_buffer(&test_descriptor, 0, &value,
                                encoded, sizeof(encoded));
    assert(enc.encoded == 17);
    dec = aper_decode(0, &test_descriptor, (void **)&decoded, encoded,
                      (size_t)(enc.encoded + 7) / 8, 0,
                      (int)((8 - (enc.encoded & 7)) & 7));
    assert(dec.code == RC_OK);
    assert(decoded != 0);
    assert(decoded->number == value.number);
    assert(decoded->flag != 0 && *decoded->flag == 0);
    FREEMEM(decoded->flag);
    FREEMEM(decoded);
}

/*
 * Purpose: verify absent DEFAULT handling and suppression of an explicit default.
 * Source: SET optional bitmap semantics and generated default callbacks.
 * Version: 2026-10-30.
 * Parameters: None; uses the static test descriptor.
 * Returns: None.
 * Errors: Assertion failure indicates incorrect DEFAULT presence handling.
 * Author: asn1c maintainers.
 * History: Added for DEFAULT omission and materialization coverage.
 * Example: Both absent and explicitly TRUE flags encode as absent.
 */
static void
SET_aper_test_default(void) {
    SET_aper_test_value_t value;
    SET_aper_test_value_t *decoded = 0;
    uint8_t encoded[8];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;

    memset(&value, 0, sizeof(value));
    value.number = 9;
    enc = aper_encode_to_buffer(&test_descriptor, 0, &value,
                                encoded, sizeof(encoded));
    assert(enc.encoded == 16);
    assert(encoded[0] == 0x00 && encoded[1] == 0x09);
    dec = aper_decode(0, &test_descriptor, (void **)&decoded, encoded, 2, 0, 0);
    assert(dec.code == RC_OK);
    assert(decoded != 0 && decoded->number == 9);
    assert(decoded->flag != 0 && *decoded->flag == 1);
    FREEMEM(decoded->flag);
    FREEMEM(decoded);

    value.flag = MALLOC(sizeof(*value.flag));
    assert(value.flag != 0);
    *value.flag = 1;
    enc = aper_encode_to_buffer(&test_descriptor, 0, &value,
                                encoded, sizeof(encoded));
    assert(enc.encoded == 16);
    assert(encoded[0] == 0x00 && encoded[1] == 0x09);
    FREEMEM(value.flag);
}

/*
 * Purpose: check starvation on a missing bitmap and truncated member payload.
 * Source: APER decoder result contract for incomplete input.
 * Version: 2026-10-30.
 * Parameters: None; uses the static test descriptor.
 * Returns: None.
 * Errors: Assertion failure indicates truncation was not reported as RC_WMORE.
 * Author: asn1c maintainers.
 * History: Added for malformed and incomplete SET input coverage.
 * Example: A 16-bit prefix without the final BOOLEAN reports RC_WMORE.
 */
static void
SET_aper_test_truncation(void) {
    uint8_t input[] = {0x80, 0x5a};
    SET_aper_test_value_t *decoded = 0;
    asn_dec_rval_t result;

    result = aper_decode(0, &test_descriptor, (void **)&decoded, input, 0, 0, 0);
    assert(result.code == RC_WMORE);
    FREEMEM(decoded);

    decoded = 0;
    result = aper_decode(0, &test_descriptor, (void **)&decoded,
                         input, sizeof(input), 0, 0);
    assert(result.code == RC_WMORE);
    FREEMEM(decoded);
}

/*
 * Purpose: reject extensible SETs and malformed or missing canonical maps.
 * Source: APER root-only SET support and compiler map invariants.
 * Version: 2026-10-30.
 * Parameters: None; uses copies of the static test descriptor.
 * Returns: None.
 * Errors: Assertion failure indicates malformed metadata was accepted.
 * Author: asn1c maintainers.
 * History: Added for invalid descriptor and map handling.
 * Example: A duplicated member index in tag2el_cxer is rejected.
 */
static void
SET_aper_test_invalid_metadata(void) {
    asn_SET_specifics_t bad_specifics = test_specifics;
    asn_TYPE_descriptor_t bad_descriptor = test_descriptor;
    asn_TYPE_tag2member_t bad_map[2];
    SET_aper_test_value_t value;
    SET_aper_test_value_t *decoded = 0;
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    uint8_t encoded[8];

    memset(&value, 0, sizeof(value));
    value.number = 3;
    bad_specifics.extensible = 1;
    bad_descriptor.specifics = &bad_specifics;
    enc = aper_encode_to_buffer(&bad_descriptor, 0, &value,
                                encoded, sizeof(encoded));
    assert(enc.encoded == -1);

    bad_specifics = test_specifics;
    bad_map[0] = test_tag_order[0];
    bad_map[1] = test_tag_order[0];
    bad_specifics.tag2el_cxer = bad_map;
    bad_specifics.tag2el_cxer_count = 2;
    bad_descriptor.specifics = &bad_specifics;
    enc = aper_encode_to_buffer(&bad_descriptor, 0, &value,
                                encoded, sizeof(encoded));
    assert(enc.encoded == -1);
    dec = aper_decode(0, &bad_descriptor, (void **)&decoded, encoded,
                      sizeof(encoded), 0, 0);
    assert(dec.code == RC_FAIL);
    assert(decoded == 0);

    bad_specifics = test_specifics;
    bad_specifics.tag2el_cxer = 0;
    bad_specifics.tag2el_cxer_count = 0;
    bad_descriptor.specifics = &bad_specifics;
    enc = aper_encode_to_buffer(&bad_descriptor, 0, &value,
                                encoded, sizeof(encoded));
    assert(enc.encoded == -1);
}

/*
 * Purpose: execute all SET APER regression cases.
 * Source: Local C runtime test suite.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Zero when every assertion passes.
 * Errors: Assertions abort the test on the first failure.
 * Author: asn1c maintainers.
 * History: Added with initial SET APER support.
 * Example: Invoked by make check-APER-SET.
 */
int
main(void) {
    SET_aper_test_encoding();
    SET_aper_test_round_trip();
    SET_aper_test_default();
    SET_aper_test_truncation();
    SET_aper_test_invalid_metadata();
    return 0;
}
