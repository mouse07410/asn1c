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
#include <ANY.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <NativeInteger.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <uper_decoder.h>
#include <oer_decoder.h>
#include <oer_encoder.h>
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
 * History: Added for malformed and incomplete SET input coverage; free
 * partially decoded pointer members on starvation.
 * Example: A 16-bit prefix without the final BOOLEAN reports RC_WMORE.
 */
static void
SET_aper_test_truncation(void) {
    uint8_t input[] = {0x80, 0x5a};
    SET_aper_test_value_t *decoded = 0;
    asn_dec_rval_t result;

    result = aper_decode(0, &test_descriptor, (void **)&decoded, input, 0, 0, 0);
    assert(result.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(test_descriptor, decoded);

    decoded = 0;
    result = aper_decode(0, &test_descriptor, (void **)&decoded,
                         input, sizeof(input), 0, 0);
    assert(result.code == RC_WMORE);
    /* BOOLEAN_decode_aper may allocate flag before discovering the missing bit. */
    assert(decoded != 0 && decoded->flag != 0);
    ASN_STRUCT_FREE(test_descriptor, decoded);
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
 * Purpose: reject malformed ANY storage and exercise empty and short envelopes.
 * Source: PER ANY decoder security review. Version: 2026-10-30.
 * Parameters: none. Returns: none. Errors: failed assertions abort the test.
 * Responsible party: asn1c maintainers. History: regression for checked sizes.
 * Example: A negative ANY size fails before the decoder reallocates its buffer.
 */
static void
SET_aper_test_any_validation(void) {
    uint8_t empty[] = {0};
    uint8_t truncated[] = {1};
    asn_per_data_t input;
    asn_dec_rval_t result;
    ANY_t invalid = {0};
    ANY_t *value = &invalid;
    asn_TYPE_descriptor_t descriptor = asn_DEF_ANY;
    asn_OCTET_STRING_specifics_t specs = asn_SPC_ANY_specs;
    int aligned;
    size_t storage_size = 0;

    assert(SET_inline_value_size(&asn_DEF_ANY, &storage_size) == 0);
    assert(storage_size == sizeof(ANY_t));
    specs.ctx_offset = sizeof(ANY_t);
    descriptor.specifics = &specs;
    assert(SET_inline_value_size(&descriptor, &storage_size) == -1);
    specs = asn_SPC_ANY_specs;
    for(aligned = 0; aligned < 2; aligned++) {
        memset(&input, 0, sizeof(input));
        input.buffer = empty;
        input.nbits = 8;
        invalid.size = -1;
        result = aligned ? ANY_decode_aper(0, &asn_DEF_ANY, 0, (void **)&value, &input)
                         : ANY_decode_uper(0, &asn_DEF_ANY, 0, (void **)&value, &input);
        assert(result.code == RC_FAIL);
        invalid.size = 0;
        specs.struct_size = sizeof(ANY_t) - 1;
        descriptor.specifics = &specs;
        result = aligned ? ANY_decode_aper(0, &descriptor, 0, (void **)&value, &input)
                         : ANY_decode_uper(0, &descriptor, 0, (void **)&value, &input);
        assert(result.code == RC_FAIL);
        result = aligned ? ANY_decode_aper(0, &asn_DEF_ANY, 0, (void **)&value, &input)
                         : ANY_decode_uper(0, &asn_DEF_ANY, 0, (void **)&value, &input);
        assert(result.code == RC_OK && invalid.size == 0 && invalid.buf);
        input.buffer = truncated;
        input.nboff = 0;
        input.nbits = 8;
        result = aligned ? ANY_decode_aper(0, &asn_DEF_ANY, 0, (void **)&value, &input)
                         : ANY_decode_uper(0, &asn_DEF_ANY, 0, (void **)&value, &input);
        assert(result.code == RC_WMORE);
        FREEMEM(invalid.buf);
        invalid.buf = 0;
    }
    invalid.buf = MALLOC(1);
    assert(invalid.buf);
    invalid.size = 1;
    assert(ANY_fromType_aper(&invalid, &asn_DEF_BOOLEAN, 0) == 0);
    assert(invalid.buf == 0 && invalid.size == 0);
}

/* SET fixture with the open value ordered before its governing identifier. */
typedef struct SET_aper_open_value_s {
    long payload;                 /* The selected INTEGER payload. */
    long selector;                /* The table-selection identifier. */
    unsigned int presence[1];     /* Runtime presence state variable. */
    asn_struct_ctx_t context;     /* Decode state variable. */
} SET_aper_open_value_t;

/*
 * Purpose: Select INTEGER only after the matching identifier is decoded.
 * Source: Test IOC selector contract. Version: 2026-10-30.
 * Inputs: td is unused; parent holds the identifier. Returns: selected type.
 * Errors: Unknown identifiers return an empty result. Author: asn1c maintainers.
 * History: Exercises SET canonical ordering. Example: 90 selects INTEGER.
 */
static asn_type_selector_result_t
SET_aper_open_selector(const asn_TYPE_descriptor_t *td, const void *parent) {
    const SET_aper_open_value_t *value = (const SET_aper_open_value_t *)parent;
    asn_type_selector_result_t result = {0, 0};
    (void)td;
    if(value->selector == 90) {
        result.type_descriptor = &asn_DEF_NativeInteger;
        result.presence_index = 1;
    }
    return result;
}

/* Canonical tag order deliberately places the open field first. */
static asn_TYPE_member_t SET_aper_open_members[] = {
    {.flags = ATF_OPEN_TYPE, .memb_offset = offsetof(SET_aper_open_value_t, payload),
     .tag = ASN_TAG_CLASS_CONTEXT | (1 << 2), .type = &asn_DEF_NativeInteger,
     .type_selector = SET_aper_open_selector, .name = "payload"},
    {.memb_offset = offsetof(SET_aper_open_value_t, selector),
     .tag = ASN_TAG_CLASS_CONTEXT | (2 << 2), .type = &asn_DEF_NativeInteger,
     .encoding_constraints.per_constraints = &number_constraints, .name = "selector"}
};
static const asn_TYPE_tag2member_t SET_aper_open_order[] = {
    {ASN_TAG_CLASS_CONTEXT | (1 << 2), 0, 0, 0},
    {ASN_TAG_CLASS_CONTEXT | (2 << 2), 1, 0, 0}
};
static asn_SET_specifics_t SET_aper_open_specs = {
    sizeof(SET_aper_open_value_t), offsetof(SET_aper_open_value_t, context),
    offsetof(SET_aper_open_value_t, presence), SET_aper_open_order, 2,
    SET_aper_open_order, 2, 0, mandatory_map
};
static asn_TYPE_descriptor_t SET_aper_open_descriptor = {
    "OpenSet", "OpenSet", &asn_OP_SET, 0, 0, 0, 0, {0},
    SET_aper_open_members, 2, &SET_aper_open_specs
};

/*
 * Purpose: Verify deferred selection and failure on truncation or unknown IDs.
 * Source: Generated SET descriptor contract. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: Assertions abort. Author: maintainers.
 * History: Regression for open values ordered ahead of their selector.
 * Example: A payload of 42 with selector 90 round-trips successfully.
 */
static void
SET_aper_test_deferred_open(void) {
    SET_aper_open_value_t original = {0};
    SET_aper_open_value_t *decoded = 0;
    uint8_t wire[32];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t bytes;

    original.payload = 42;
    original.selector = 90;
    encoded = aper_encode_to_buffer(&SET_aper_open_descriptor, 0, &original,
                                    wire, sizeof(wire));
    assert(encoded.encoded > 0);
    bytes = ((size_t)encoded.encoded + 7) / 8;
    result = aper_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                         wire, bytes, 0, 0);
    assert(result.code == RC_OK && decoded->payload == 42 && decoded->selector == 90);
    ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
    decoded = 0;
    result = aper_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                         wire, bytes - 1, 0, 0);
    assert(result.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
    decoded = 0;
    wire[bytes - 1] = 91;
    result = aper_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                         wire, bytes, 0, 0);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
    decoded = 0;
    wire[bytes - 1] = 90;
    wire[0] = 0;
    result = aper_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                         wire, bytes, 0, 0);
    assert(result.code != RC_OK);
    if(decoded) ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
}

/*
 * Purpose: Exercise deferred OER selection with fragmented input and cleanup.
 * Source: OER incremental decoder contract. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Regresses open values ordered before their governing identifiers.
 * Example: Each prefix is supplied with any bytes previously left unconsumed.
 */
static void
SET_oer_test_deferred_open(void) {
    SET_aper_open_value_t original = {0};
    SET_aper_open_value_t *decoded = 0;
    uint8_t wire[32];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result = {RC_WMORE, 0};
    size_t available, consumed = 0, bytes;

    original.payload = 42;
    original.selector = 90;
    encoded = oer_encode_to_buffer(&SET_aper_open_descriptor, 0, &original,
                                   wire, sizeof(wire));
    assert(encoded.encoded > 0);
    bytes = (size_t)encoded.encoded;
    for(available = 1; available <= bytes; available++) {
        result = oer_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                            wire + consumed, available - consumed);
        consumed += result.consumed;
        if(available < bytes) assert(result.code == RC_WMORE);
    }
    assert(result.code == RC_OK && consumed == bytes);
    assert(decoded->payload == 42 && decoded->selector == 90);
    ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
    decoded = 0;
    result = oer_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                        wire, bytes - 1);
    assert(result.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
    decoded = 0;
    wire[bytes - 1] = 91;
    result = oer_decode(0, &SET_aper_open_descriptor, (void **)&decoded,
                        wire, bytes);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(SET_aper_open_descriptor, decoded);
}

/* An extensible SET whose selector is carried as an extension addition. */
typedef struct SET_oer_extension_selector_s {
    long payload;                   /* Root open value. */
    long *selector;                 /* Optional extension selector. */
    unsigned int presence[1];       /* SET presence state variable. */
    asn_struct_ctx_t context;       /* Incremental decode state variable. */
} SET_oer_extension_selector_t;

/*
 * Purpose: Select INTEGER from the extension-carried selector.
 * Source: Test selector contract. Version: 2026-10-30.
 * Inputs: td is unused; value owns the extension pointer. Returns: selection.
 * Errors: Missing or unknown selector returns no type. Author: maintainers.
 * History: Regression for root OPEN TYPE selected by an addition.
 * Example: Selector 90 selects INTEGER.
 */
static asn_type_selector_result_t
SET_oer_extension_selector(const asn_TYPE_descriptor_t *td, const void *value) {
    const SET_oer_extension_selector_t *parent = value;
    asn_type_selector_result_t selected = {0, 0};
    (void)td;
    if(parent->selector && *parent->selector == 90) {
        selected.type_descriptor = &asn_DEF_NativeInteger;
        selected.presence_index = 1;
    }
    return selected;
}

/* Descriptor metadata partitions the open root and selector addition. */
static asn_TYPE_member_t SET_oer_extension_members[] = {
    {.flags = ATF_OPEN_TYPE,
     .memb_offset = offsetof(SET_oer_extension_selector_t, payload),
     .tag = ASN_TAG_CLASS_CONTEXT | (1 << 2), .type = &asn_DEF_NativeInteger,
     .type_selector = SET_oer_extension_selector, .name = "payload"},
    {.flags = ATF_POINTER, .optional = 1,
     .memb_offset = offsetof(SET_oer_extension_selector_t, selector),
     .tag = ASN_TAG_CLASS_CONTEXT | (2 << 2), .type = &asn_DEF_NativeInteger,
     .name = "selector"}
};
static const unsigned SET_oer_extension_root[] = {0};
static const unsigned SET_oer_extension_addition[] = {1};
static asn_SET_specifics_t SET_oer_extension_specs = {
    .struct_size = sizeof(SET_oer_extension_selector_t),
    .ctx_offset = offsetof(SET_oer_extension_selector_t, context),
    .pres_offset = offsetof(SET_oer_extension_selector_t, presence),
    .tag2el = SET_aper_open_order, .tag2el_count = 2,
    .tag2el_cxer = SET_aper_open_order, .tag2el_cxer_count = 2,
    .extensible = 2, ._mandatory_elements = mandatory_map,
    .specifics_size = sizeof(asn_SET_specifics_t),
    .specifics_version = ASN_SET_SPECIFICS_VERSION,
    .root_map = SET_oer_extension_root, .root_count = 1,
    .extension_map = SET_oer_extension_addition, .extension_count = 1
};
static asn_TYPE_descriptor_t SET_oer_extension_descriptor = {
    "ExtensionSelector", "ExtensionSelector", &asn_OP_SET, 0, 0, 0, 0, {0},
    SET_oer_extension_members, 2, &SET_oer_extension_specs
};

/* Empty SET storage carries only the runtime's incremental state. */
typedef struct SET_oer_empty_s {
    asn_struct_ctx_t context;      /* Incremental decode state variable. */
} SET_oer_empty_t;

/* No-preamble descriptor exercises the valid NULL, zero-length input. */
static asn_SET_specifics_t SET_oer_empty_specs = {
    .struct_size = sizeof(SET_oer_empty_t),
    .ctx_offset = offsetof(SET_oer_empty_t, context),
    .pres_offset = 0
};
static asn_TYPE_descriptor_t SET_oer_empty_descriptor = {
    "Empty", "Empty", &asn_OP_SET, 0, 0, 0, 0, {0},
    0, 0, &SET_oer_empty_specs
};

/*
 * Purpose: decode an empty SET from an absent input buffer.
 * Source: OER zero-byte preamble contract. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Guards the decoder against pointer arithmetic on NULL.
 * Example: An empty OER SET consumes zero bytes and succeeds.
 */
static void
SET_oer_test_empty_null_input(void) {
    SET_oer_empty_t *decoded = 0;
    asn_dec_rval_t result = oer_decode(0, &SET_oer_empty_descriptor,
                                       (void **)&decoded, 0, 0);
    assert(result.code == RC_OK && result.consumed == 0 && decoded);
    ASN_STRUCT_FREE(SET_oer_empty_descriptor, decoded);
}

/*
 * Purpose: Resolve root open values only after extension additions complete.
 * Source: SET OER streaming regression. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Covers deferred state through extension map and value splits.
 * Example: Each encoded prefix can be decoded and freed safely.
 */
static void
SET_oer_test_extension_selector(void) {
    SET_oer_extension_selector_t original = {0}, *decoded = 0;
    long selector = 90;
    uint8_t wire[32];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result = {RC_WMORE, 0};
    size_t bytes, available, consumed = 0;

    original.payload = 42;
    original.selector = &selector;
    encoded = oer_encode_to_buffer(&SET_oer_extension_descriptor, 0, &original,
                                   wire, sizeof(wire));
    assert(encoded.encoded > 0);
    bytes = (size_t)encoded.encoded;
    for(available = 1; available < bytes; available++) {
        SET_oer_extension_selector_t *partial = 0;
        result = oer_decode(0, &SET_oer_extension_descriptor, (void **)&partial,
                            wire, available);
        assert(result.code == RC_WMORE);
        if(partial) ASN_STRUCT_FREE(SET_oer_extension_descriptor, partial);
    }
    for(available = 1; available <= bytes; available++) {
        result = oer_decode(0, &SET_oer_extension_descriptor, (void **)&decoded,
                            wire + consumed, available - consumed);
        consumed += result.consumed;
        if(available < bytes) assert(result.code == RC_WMORE);
    }
    assert(result.code == RC_OK && consumed == bytes);
    assert(decoded->payload == 42 && decoded->selector && *decoded->selector == 90);
    ASN_STRUCT_FREE(SET_oer_extension_descriptor, decoded);
}

/* Fixed-size callback destination for ANY codec regressions. */
typedef struct ANY_test_output_s {
    uint8_t bytes[128]; /* Captured encoded output. */
    size_t size;        /* Number of bytes already captured. */
} ANY_test_output_t;

/*
 * Purpose: Collect encoded bytes without overflowing the test output array.
 * Source: ASN.1 encoder callback contract. Version: 2026-10-30.
 * Inputs: bytes/size are output; key points to the destination.
 * Returns: zero or -1 if output does not fit. Errors: none. Author: maintainers.
 * History: Added for ANY OER/CBOR codec tests. Example: capture a two-byte value.
 */
static int
ANY_test_collect(const void *bytes, size_t size, void *key) {
    ANY_test_output_t *out = key;
    if(size > sizeof(out->bytes) - out->size || (size && !bytes)) return -1;
    if(size) memcpy(out->bytes + out->size, bytes, size);
    out->size += size;
    return 0;
}

/*
 * Purpose: Verify ABI-safe ANY byte codecs and reject malformed payload sizes.
 * Source: OER and CBOR byte-string mappings. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Tests signed-length adapters and poisoned structure padding.
 * Example: The payload 01 02 survives both OER and CBOR round trips.
 */
static void
ANY_test_oer_cbor(void) {
    uint8_t payload[] = {1, 2};
    uint8_t huge_oer[] = {0x84, 0x80, 0, 0, 0};
    uint8_t huge_cbor[] = {0x5a, 0x80, 0, 0, 0};
    ANY_test_output_t out = {{0}, 0};
    ANY_t source, *decoded = 0;
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;

    memset(&source, 0xff, sizeof(source));
    source.buf = payload;
    source.size = 2;
    memset(&source._asn_ctx, 0, sizeof(source._asn_ctx));
    enc = ANY_encode_oer(&asn_DEF_ANY, 0, &source, ANY_test_collect, &out);
    assert(enc.encoded == 3 && out.size == 3);
    dec = ANY_decode_oer(0, &asn_DEF_ANY, 0, (void **)&decoded, out.bytes, out.size);
    assert(dec.code == RC_OK && decoded->size == 2 && !memcmp(decoded->buf, payload, 2));
    ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
    decoded = 0;
    dec = ANY_decode_oer(0, &asn_DEF_ANY, 0, (void **)&decoded, out.bytes, out.size - 1);
    assert(dec.code == RC_WMORE && !decoded);
    dec = ANY_decode_oer(0, &asn_DEF_ANY, 0, (void **)&decoded, huge_oer, sizeof(huge_oer));
    assert(dec.code == RC_FAIL && !decoded);

    out.size = 0;
    enc = ANY_encode_cbor(&asn_DEF_ANY, &source, ANY_test_collect, &out);
    assert(enc.encoded == 3 && out.size == 3);
    dec = ANY_decode_cbor(0, &asn_DEF_ANY, (void **)&decoded, out.bytes, out.size);
    assert(dec.code == RC_OK && decoded->size == 2 && !memcmp(decoded->buf, payload, 2));
    ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
    decoded = 0;
    dec = ANY_decode_cbor(0, &asn_DEF_ANY, (void **)&decoded, huge_cbor, sizeof(huge_cbor));
    assert(dec.code == RC_FAIL && !decoded);
    dec = ANY_decode_cbor(0, &asn_DEF_ANY, (void **)&decoded, out.bytes, out.size - 1);
    assert(dec.code == RC_FAIL && !decoded);
    source.size = -1;
    assert(ANY_encode_oer(&asn_DEF_ANY, 0, &source, ANY_test_collect, &out).encoded == -1);
    assert(ANY_encode_cbor(&asn_DEF_ANY, &source, ANY_test_collect, &out).encoded == -1);
}

/*
 * Purpose: Round-trip hexadecimal JER and XER ANY with a signed-size layout.
 * Source: Existing OCTET STRING hexadecimal text mapping. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Exercises adapters with poisoned padding and malformed text.
 * Example: Encoded 0102 yields the payload bytes 01 02.
 */
static void
ANY_test_text_codecs(void) {
    static const char jer[] = "\"0102\"";
    static const char bad_jer[] = "\"01GG\"";
    static const char xer[] = "<ANY>0102</ANY>";
    uint8_t payload[] = {1, 2};
    ANY_test_output_t out = {{0}, 0};
    ANY_t source, *decoded = 0;
    asn_dec_rval_t dec;
    asn_enc_rval_t enc;

    memset(&source, 0xff, sizeof(source));
    source.buf = payload;
    source.size = 2;
    memset(&source._asn_ctx, 0, sizeof(source._asn_ctx));
    enc = ANY_encode_jer(&asn_DEF_ANY, 0, &source, 0, 0, ANY_test_collect, &out);
    assert(enc.encoded == 6 && out.size == 6 && !memcmp(out.bytes, jer, 6));
    dec = ANY_decode_jer(0, &asn_DEF_ANY, 0, (void **)&decoded, jer, sizeof(jer) - 1);
    assert(dec.code == RC_OK && decoded->size == 2 && !memcmp(decoded->buf, payload, 2));
    ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
    decoded = 0;
    {
        size_t available, consumed = 0;
        for(available = 1; available < sizeof(jer); available++) {
            dec = ANY_decode_jer(0, &asn_DEF_ANY, 0, (void **)&decoded,
                                 jer + consumed, available - consumed);
            consumed += dec.consumed;
            if(available < sizeof(jer) - 1) assert(dec.code == RC_WMORE);
        }
        assert(dec.code == RC_OK && decoded->size == 2);
        ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
        decoded = 0;
    }
    dec = ANY_decode_jer(0, &asn_DEF_ANY, 0, (void **)&decoded, bad_jer, sizeof(bad_jer) - 1);
    assert(dec.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
    decoded = 0;
    out.size = 0;
    enc = ANY_encode_xer(&asn_DEF_ANY, &source, 0, 0, ANY_test_collect, &out);
    assert(enc.encoded > 0 && out.size > 0);
    dec = ANY_decode_xer(0, &asn_DEF_ANY, (void **)&decoded, 0, xer, sizeof(xer) - 1);
    assert(dec.code == RC_OK && decoded->size == 2 && !memcmp(decoded->buf, payload, 2));
    ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
}

/*
 * Purpose: Exercise BER ANY decoding and DER output with signed-size storage.
 * Source: BER opaque ANY representation. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Covers incremental input and poisoned padding in the DER encoder.
 * Example: INTEGER 42 retains the original 02 01 2a TLV.
 */
static void
ANY_test_ber_der(void) {
    uint8_t bytes[] = {2, 1, 42};
    ANY_test_output_t out = {{0}, 0};
    ANY_t *decoded = 0;
    asn_dec_rval_t dec;
    asn_enc_rval_t enc;
    size_t consumed = 0, available;

    for(available = 1; available <= sizeof(bytes); available++) {
        dec = ANY_decode_ber(0, &asn_DEF_ANY, (void **)&decoded,
                             bytes + consumed, available - consumed, 0);
        consumed += dec.consumed;
        if(available < sizeof(bytes)) assert(dec.code == RC_WMORE);
    }
    assert(dec.code == RC_OK && decoded->size == 3 && !memcmp(decoded->buf, bytes, 3));
    enc = ANY_encode_der(&asn_DEF_ANY, decoded, 0, 0, ANY_test_collect, &out);
    assert(enc.encoded == 3 && out.size == 3 && !memcmp(out.bytes, bytes, 3));
    enc = ANY_encode_der(&asn_DEF_ANY, decoded, 0, 0, 0, 0);
    assert(enc.encoded == 3);
    ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
    decoded = ANY_new_fromBuf((const char *)bytes, (int)sizeof(bytes));
    assert(decoded && decoded->size == 3 && !memcmp(decoded->buf, bytes, 3));
    assert(ANY_fromBuf(decoded, (const char *)decoded->buf + 1, 2) == 0);
    assert(decoded->size == 2 && decoded->buf[0] == 1 && decoded->buf[1] == 42);
    assert(ANY_fromType(decoded, &asn_DEF_NativeInteger, 0) == 0);
    assert(!decoded->buf && decoded->size == 0);
    ASN_STRUCT_FREE(asn_DEF_ANY, decoded);
}

/* SET with an open addition followed by its selector addition. */
typedef struct SET_open_addition_s {
    long *payload;              /* Selected open value. */
    long *selector;             /* Later extension selector. */
    unsigned int presence[1];   /* SET presence state variable. */
    asn_struct_ctx_t context;   /* Decode state variable. */
} SET_open_addition_t;

/*
 * Purpose: Select the addition's INTEGER from a later extension value.
 * Source: Test table selector contract. Version: 2026-10-30.
 * Inputs: td is unused and parent owns the selector. Returns: selected type.
 * Errors: Missing and unknown selectors return empty. Author: maintainers.
 * History: Tests addition-to-addition selection. Example: 90 selects INTEGER.
 */
static asn_type_selector_result_t
SET_open_addition_selector(const asn_TYPE_descriptor_t *td, const void *parent) {
    const SET_open_addition_t *value = parent;
    asn_type_selector_result_t result = {0, 0};
    (void)td;
    if(value->selector && *value->selector == 90) {
        result.type_descriptor = &asn_DEF_NativeInteger;
        result.presence_index = 1;
    }
    return result;
}

/* Both fields are additions, with the open envelope first on the wire. */
static asn_TYPE_member_t SET_open_addition_members[] = {
    {.flags = ATF_OPEN_TYPE | ATF_POINTER, .optional = 1,
     .memb_offset = offsetof(SET_open_addition_t, payload),
     .tag = ASN_TAG_CLASS_CONTEXT | (1 << 2), .type = &asn_DEF_NativeInteger,
     .type_selector = SET_open_addition_selector, .name = "payload"},
    {.flags = ATF_POINTER, .optional = 1,
     .memb_offset = offsetof(SET_open_addition_t, selector),
     .tag = ASN_TAG_CLASS_CONTEXT | (2 << 2), .type = &asn_DEF_NativeInteger,
     .name = "selector"}
};
static const unsigned SET_open_additions[] = {0, 1};
static asn_SET_specifics_t SET_open_addition_specs = {
    .struct_size = sizeof(SET_open_addition_t),
    .ctx_offset = offsetof(SET_open_addition_t, context),
    .pres_offset = offsetof(SET_open_addition_t, presence),
    .tag2el = SET_aper_open_order, .tag2el_count = 2,
    .tag2el_cxer = SET_aper_open_order, .tag2el_cxer_count = 2,
    .extensible = 2, ._mandatory_elements = mandatory_map,
    .specifics_size = sizeof(asn_SET_specifics_t),
    .specifics_version = ASN_SET_SPECIFICS_VERSION,
    .extension_map = SET_open_additions, .extension_count = 2
};
static asn_TYPE_descriptor_t SET_open_addition_descriptor = {
    "OpenAddition", "OpenAddition", &asn_OP_SET, 0, 0, 0, 0, {0},
    SET_open_addition_members, 2, &SET_open_addition_specs
};

/*
 * Purpose: Round-trip nested open additions and a later selector in both codecs.
 * Source: SET extension-addition encoding. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Covers fragmented OER and truncated APER extension envelopes.
 * Example: Open INTEGER 42 is selected by the later addition value 90.
 */
static void
SET_test_open_additions(void) {
    SET_open_addition_t original = {0}, *decoded = 0;
    long payload = 42, selector = 90;
    uint8_t wire[64];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t bytes, available, consumed;
    original.payload = &payload;
    original.selector = &selector;

    encoded = aper_encode_to_buffer(&SET_open_addition_descriptor, 0, &original,
                                    wire, sizeof(wire));
    assert(encoded.encoded > 0);
    bytes = ((size_t)encoded.encoded + 7) / 8;
    result = aper_decode(0, &SET_open_addition_descriptor, (void **)&decoded,
                         wire, bytes, 0, 0);
    assert(result.code == RC_OK && decoded->payload && *decoded->payload == 42);
    assert(decoded->selector && *decoded->selector == 90);
    ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
    decoded = 0;
    result = aper_decode(0, &SET_open_addition_descriptor, (void **)&decoded,
                         wire, bytes - 1, 0, 0);
    assert(result.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
    decoded = 0;
    assert(bytes >= 5 && wire[2] == 3 && wire[3] == 2);
    wire[3] = 0x7f; /* Inner length exceeds the complete outer addition. */
    result = aper_decode(0, &SET_open_addition_descriptor, (void **)&decoded,
                         wire, bytes, 0, 0);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
    decoded = 0;

    encoded = oer_encode_to_buffer(&SET_open_addition_descriptor, 0, &original,
                                   wire, sizeof(wire));
    assert(encoded.encoded > 0);
    bytes = (size_t)encoded.encoded;
    consumed = 0;
    for(available = 1; available <= bytes; available++) {
        result = oer_decode(0, &SET_open_addition_descriptor, (void **)&decoded,
                            wire + consumed, available - consumed);
        consumed += result.consumed;
        if(available < bytes) assert(result.code == RC_WMORE);
    }
    assert(result.code == RC_OK && decoded->payload && *decoded->payload == 42);
    assert(decoded->selector && *decoded->selector == 90 && consumed == bytes);
    ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
    decoded = 0;
    for(available = 1; available < bytes; available++) {
        result = oer_decode(0, &SET_open_addition_descriptor, (void **)&decoded,
                            wire, available);
        assert(result.code == RC_WMORE);
        if(decoded) ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
        decoded = 0;
    }
    {
        size_t length = 0, offset = 1;
        ssize_t header = oer_fetch_length(wire + offset, bytes - offset, &length);
        assert(header > 0 && length <= bytes - offset - (size_t)header);
        offset += (size_t)header + length;
        header = oer_fetch_length(wire + offset, bytes - offset, &length);
        assert(header > 0 && length > 0 && length <= bytes - offset - (size_t)header);
        offset += (size_t)header;
        wire[offset] = 0x7f; /* The inner envelope cannot fit in its outer envelope. */
        result = oer_decode(0, &SET_open_addition_descriptor, (void **)&decoded, wire, bytes);
        assert(result.code == RC_FAIL);
        if(decoded) ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
        decoded = 0;
    }
    selector = 91;
    assert(aper_encode_to_buffer(&SET_open_addition_descriptor, 0, &original,
                                 wire, sizeof(wire)).encoded == -1);
    assert(oer_encode_to_buffer(&SET_open_addition_descriptor, 0, &original,
                                wire, sizeof(wire)).encoded == -1);
    original.payload = 0;
    original.selector = 0;
    encoded = aper_encode_to_buffer(&SET_open_addition_descriptor, 0, &original,
                                    wire, sizeof(wire));
    assert(encoded.encoded > 0);
    result = aper_decode(0, &SET_open_addition_descriptor, (void **)&decoded, wire,
                         ((size_t)encoded.encoded + 7) / 8, 0, 0);
    assert(result.code == RC_OK && !decoded->payload && !decoded->selector);
    ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
    decoded = 0;
    encoded = oer_encode_to_buffer(&SET_open_addition_descriptor, 0, &original,
                                   wire, sizeof(wire));
    assert(encoded.encoded > 0);
    result = oer_decode(0, &SET_open_addition_descriptor, (void **)&decoded,
                        wire, (size_t)encoded.encoded);
    assert(result.code == RC_OK && !decoded->payload && !decoded->selector);
    ASN_STRUCT_FREE(SET_open_addition_descriptor, decoded);
}

/* Two-arm wrapper used to test selector/choice consistency. */
typedef struct SET_open_choice_s {
    long value;                 /* Selected INTEGER value. */
    unsigned present;           /* CHOICE state variable. */
    asn_struct_ctx_t context;   /* Decoder state variable. */
} SET_open_choice_t;

/*
 * Purpose: Reject mismatched wrapper alternatives in extension encoding.
 * Source: OPEN TYPE selector and CHOICE contract. Version: 2026-10-30.
 * Inputs: none. Returns: none. Errors: assertions abort. Author: maintainers.
 * History: Covers parent-aware nested OER and APER encoders.
 * Example: A selector for arm one rejects an active arm two.
 */
static void
SET_test_open_choice_addition(void) {
    asn_TYPE_member_t variants[2] = {{0}, {0}};
    asn_CHOICE_specifics_t choice_specs = {0};
    asn_TYPE_descriptor_t choice = {0};
    asn_TYPE_member_t members[2];
    asn_TYPE_descriptor_t descriptor = SET_open_addition_descriptor;
    SET_open_addition_t original = {0}, *decoded = 0;
    SET_open_choice_t wrapper = {0};
    long selector = 90;
    uint8_t wire[64];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t bytes;

    variants[0].memb_offset = offsetof(SET_open_choice_t, value);
    variants[0].type = &asn_DEF_NativeInteger;
    variants[1] = variants[0];
    choice_specs.struct_size = sizeof(wrapper);
    choice_specs.ctx_offset = offsetof(SET_open_choice_t, context);
    choice_specs.pres_offset = offsetof(SET_open_choice_t, present);
    choice_specs.pres_size = sizeof(wrapper.present);
    choice.name = "OpenChoice";
    choice.xml_tag = "OpenChoice";
    choice.op = &asn_OP_OPEN_TYPE;
    choice.elements = variants;
    choice.elements_count = 2;
    choice.specifics = &choice_specs;
    memcpy(members, SET_open_addition_members, sizeof(members));
    members[0].type = &choice;
    descriptor.elements = members;
    wrapper.value = 42;
    wrapper.present = 1;
    original.payload = (long *)&wrapper;
    original.selector = &selector;

    encoded = aper_encode_to_buffer(&descriptor, 0, &original, wire, sizeof(wire));
    assert(encoded.encoded > 0);
    bytes = ((size_t)encoded.encoded + 7) / 8;
    result = aper_decode(0, &descriptor, (void **)&decoded, wire, bytes, 0, 0);
    assert(result.code == RC_OK && decoded->payload);
    assert(((SET_open_choice_t *)decoded->payload)->value == 42);
    ASN_STRUCT_FREE(descriptor, decoded);
    decoded = 0;
    encoded = oer_encode_to_buffer(&descriptor, 0, &original, wire, sizeof(wire));
    assert(encoded.encoded > 0);
    result = oer_decode(0, &descriptor, (void **)&decoded, wire, (size_t)encoded.encoded);
    assert(result.code == RC_OK && decoded->payload);
    assert(((SET_open_choice_t *)decoded->payload)->value == 42);
    ASN_STRUCT_FREE(descriptor, decoded);
    wrapper.present = 2;
    assert(aper_encode_to_buffer(&descriptor, 0, &original, wire, sizeof(wire)).encoded == -1);
    assert(oer_encode_to_buffer(&descriptor, 0, &original, wire, sizeof(wire)).encoded == -1);
    wrapper.present = 1;
    variants[0].type = &asn_DEF_BOOLEAN;
    assert(aper_encode_to_buffer(&descriptor, 0, &original, wire, sizeof(wire)).encoded == -1);
    assert(oer_encode_to_buffer(&descriptor, 0, &original, wire, sizeof(wire)).encoded == -1);
}

/*
 * Purpose: Fail before consuming input for an open member lacking a selector.
 * Source: APER SET descriptor validation. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Regression for malformed deferred OPEN TYPE metadata.
 * Example: A plain INTEGER flagged as OPEN TYPE has no selector or fallback.
 */
static void
SET_aper_test_missing_open_selector(void) {
    SET_aper_test_value_t *decoded = 0;
    asn_TYPE_member_t members[2];
    asn_TYPE_descriptor_t descriptor = test_descriptor;
    asn_dec_rval_t result;
    uint8_t input = 0;
    memcpy(members, test_members, sizeof(members));
    members[1].flags |= ATF_OPEN_TYPE;
    descriptor.elements = members;
    result = aper_decode(0, &descriptor, (void **)&decoded, &input, 0, 0, 0);
    assert(result.code == RC_FAIL && result.consumed == 0);
    if(decoded) ASN_STRUCT_FREE(descriptor, decoded);
}

/*
 * Purpose: Reject selector-less OER SET open members before reading input.
 * Source: SET OER descriptor validation. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Regresses malformed table-selected member metadata.
 * Example: An INTEGER flagged OPEN TYPE without a selector fails immediately.
 */
static void
SET_oer_test_missing_open_selector(void) {
    SET_aper_test_value_t *decoded = 0;
    asn_TYPE_member_t members[2];
    asn_TYPE_descriptor_t descriptor = test_descriptor;
    asn_dec_rval_t result;
    uint8_t input = 0;
    memcpy(members, test_members, sizeof(members));
    members[1].flags |= ATF_OPEN_TYPE;
    descriptor.elements = members;
    result = oer_decode(0, &descriptor, (void **)&decoded, &input, 0);
    assert(result.code == RC_FAIL && result.consumed == 0 && !decoded);
}

/*
 * Purpose: Reject selector-less SET UPER open members before wire access.
 * Source: SET UPER descriptor validation. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers malformed flags on an ordinary INTEGER member.
 * Example: An open member without a table selector fails on empty input.
 */
static void
SET_uper_test_missing_open_selector(void) {
    SET_aper_test_value_t *decoded = 0;
    asn_TYPE_member_t members[2];
    asn_TYPE_descriptor_t descriptor = test_descriptor;
    asn_dec_rval_t result;
    uint8_t input = 0;
    memcpy(members, test_members, sizeof(members));
    members[1].flags |= ATF_OPEN_TYPE;
    descriptor.elements = members;
    result = uper_decode(0, &descriptor, (void **)&decoded, &input, 0, 0, 0);
    assert(result.code == RC_FAIL && result.consumed == 0 && !decoded);
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
/* Constraint test storage models two required values and two pointer fields. */
typedef struct SET_constraint_test_value_s {
    long first;                 /* First mandatory INTEGER. */
    long second;                /* Second mandatory INTEGER. */
    long *optional;             /* Optional INTEGER. */
    long *required;             /* Mandatory pointer INTEGER. */
} SET_constraint_test_value_t;

/*
 * Purpose: reject INTEGER values outside the test range of zero through ten.
 * Source: Generated member constraint callback contract.
 * Version/date: 1.0, 2026-10-30. Inputs: td names the INTEGER; sptr points
 * to its value; cb/app_key are unused. Returns: zero or -1. Exceptions: none.
 * Author: asn1c maintainers. History: added for complete SET traversal.
 * Example: a value of eleven is rejected.
 */
static int
SET_constraint_test_integer(const asn_TYPE_descriptor_t *td, const void *sptr,
                            asn_app_constraint_failed_f *cb, void *app_key) {
    long value;
    (void)td;
    (void)cb;
    (void)app_key;
    if(!sptr) return -1;
    value = *(const long *)sptr;
    return value >= 0 && value <= 10 ? 0 : -1;
}

/*
 * Purpose: verify SET constraints visit every present member and pointer.
 * Source: SET_constraint regression for later-member validation.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing; assertions
 * abort on failure. Exceptions: none. Author: asn1c maintainers.
 * History: added after discovering first-member-only checking.
 * Example: an invalid second or present optional INTEGER fails.
 */
static void
SET_test_all_member_constraints(void) {
    asn_TYPE_member_t members[4];
    asn_TYPE_descriptor_t descriptor = test_descriptor;
    SET_constraint_test_value_t value;
    long optional = 3;
    long required = 4;
    size_t i;

    memset(members, 0, sizeof(members));
    memset(&value, 0, sizeof(value));
    for(i = 0; i < 4; i++) {
        members[i].type = &asn_DEF_NativeInteger;
        members[i].encoding_constraints.general_constraints = SET_constraint_test_integer;
    }
    members[0].name = "first";
    members[0].memb_offset = offsetof(SET_constraint_test_value_t, first);
    members[1].name = "second";
    members[1].memb_offset = offsetof(SET_constraint_test_value_t, second);
    members[2].name = "optional";
    members[2].flags = ATF_POINTER;
    members[2].optional = 1;
    members[2].memb_offset = offsetof(SET_constraint_test_value_t, optional);
    members[3].name = "required";
    members[3].flags = ATF_POINTER;
    members[3].memb_offset = offsetof(SET_constraint_test_value_t, required);
    descriptor.elements = members;
    descriptor.elements_count = 4;

    value.first = 1;
    value.second = 2;
    value.required = &required;
    assert(SET_constraint(&descriptor, &value, 0, 0) == 0);
    value.first = -1;
    assert(SET_constraint(&descriptor, &value, 0, 0) != 0);
    value.first = 1;
    value.second = 11;
    assert(SET_constraint(&descriptor, &value, 0, 0) != 0);
    value.second = 2;
    value.optional = &optional;
    assert(SET_constraint(&descriptor, &value, 0, 0) == 0);
    optional = 11;
    assert(SET_constraint(&descriptor, &value, 0, 0) != 0);
    value.optional = 0;
    value.required = 0;
    assert(SET_constraint(&descriptor, &value, 0, 0) != 0);
    value.required = &required;
    assert(SET_constraint(0, &value, 0, 0) != 0);
    descriptor.elements = 0;
    assert(SET_constraint(&descriptor, &value, 0, 0) != 0);
    descriptor.elements = members;
    members[2].type = 0;
    assert(SET_constraint(&descriptor, &value, 0, 0) != 0);
}

int
main(void) {
    SET_test_all_member_constraints();
    SET_oer_test_empty_null_input();
    SET_uper_test_missing_open_selector();
    SET_oer_test_missing_open_selector();
    SET_aper_test_missing_open_selector();
    SET_test_open_choice_addition();
    SET_test_open_additions();
    ANY_test_ber_der();
    ANY_test_text_codecs();
    ANY_test_oer_cbor();
    SET_oer_test_extension_selector();
    SET_oer_test_deferred_open();
    SET_aper_test_deferred_open();
    SET_aper_test_any_validation();
    SET_aper_test_encoding();
    SET_aper_test_round_trip();
    SET_aper_test_default();
    SET_aper_test_truncation();
    SET_aper_test_invalid_metadata();
    return 0;
}
