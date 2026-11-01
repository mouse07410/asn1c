/* Regression coverage for issue #595: PER constraints on top-level aliases. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <GeneralizedTime.h>
#include <GTA2.h>
#include <NSA2.h>
#include <NSSize.h>
#include <NumericString.h>
#include <UTCA2.h>
#include <UTCTime.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

/*
 * Purpose: compare an alias descriptor's PER constraints with its built-in.
 * Original source: issue #595 regression requirements.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: alias and base are generated and built-in descriptors; alphabet
 *         identifies types that require character conversion callbacks.
 * Returns: none.
 * Errors: assertions report missing or mismatched generated constraints.
 * Author: asn1c maintainers. History: added for issue #595.
 * Example: compare the two-level UTCTime alias with asn_DEF_UTCTime.
 */
static void
check_constraints(const asn_TYPE_descriptor_t *alias,
                  const asn_TYPE_descriptor_t *base, int alphabet) {
    const asn_per_constraints_t *actual =
        alias->encoding_constraints.per_constraints;
    const asn_per_constraints_t *expected =
        base->encoding_constraints.per_constraints;

    assert(expected);
    assert(actual);
    assert(actual->value.flags == expected->value.flags);
    assert(actual->value.range_bits == expected->value.range_bits);
    assert(actual->value.lower_bound == expected->value.lower_bound);
    assert(actual->value.upper_bound == expected->value.upper_bound);
    assert(actual->size.flags == expected->size.flags);
    assert(actual->size.effective_bits == expected->size.effective_bits);
    assert(actual->size.lower_bound == expected->size.lower_bound);
    assert(actual->size.upper_bound == expected->size.upper_bound);
    if(alphabet) {
        assert(actual->value2code);
        assert(actual->code2value);
    }
}

/*
 * Purpose: compare alias and built-in PER wire forms and round-trip the alias.
 * Original source: issue #595 regression requirements.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: alias/base descriptors, valid bytes, size, and aligned selects APER.
 * Returns: none.
 * Errors: assertions report encoding, decoding, or content mismatches.
 * Author: asn1c maintainers. History: added for issue #595.
 * Example: encode a NumericString through both descriptors with UPER.
 */
static void
check_valid_value(const asn_TYPE_descriptor_t *alias,
                  const asn_TYPE_descriptor_t *base, const char *value,
                  size_t value_size, int aligned) {
    OCTET_STRING_t source = {(uint8_t *)value, value_size};
    OCTET_STRING_t *decoded = 0;
    uint8_t alias_wire[64] = {0};
    uint8_t base_wire[64] = {0};
    asn_enc_rval_t alias_result;
    asn_enc_rval_t base_result;
    asn_dec_rval_t decode_result;

    if(aligned) {
        alias_result = aper_encode_to_buffer(alias, 0, &source, alias_wire,
                                             sizeof(alias_wire));
        base_result = aper_encode_to_buffer(base, 0, &source, base_wire,
                                            sizeof(base_wire));
    } else {
        alias_result = uper_encode_to_buffer(alias, 0, &source, alias_wire,
                                             sizeof(alias_wire));
        base_result = uper_encode_to_buffer(base, 0, &source, base_wire,
                                            sizeof(base_wire));
    }
    assert(alias_result.encoded > 0);
    assert(alias_result.encoded == base_result.encoded);
    assert(memcmp(alias_wire, base_wire,
                  (size_t)(alias_result.encoded + 7) / 8) == 0);

    if(aligned) {
        decode_result = aper_decode_complete(0, alias, (void **)&decoded,
                                             alias_wire,
                                             (size_t)(alias_result.encoded + 7)
                                                 / 8);
    } else {
        decode_result = uper_decode_complete(0, alias, (void **)&decoded,
                                             alias_wire,
                                             (size_t)(alias_result.encoded + 7)
                                                 / 8);
    }
    assert(decode_result.code == RC_OK);
    assert(decoded && decoded->size == value_size);
    assert(memcmp(decoded->buf, value, value_size) == 0);
    ASN_STRUCT_FREE(*alias, decoded);
}

/*
 * Purpose: verify an independent golden UPER encoding for a string alias.
 * Original source: X.691 UPER length and constrained-alphabet encoding.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: alias/value describe the ASN.1 value; golden/golden_size and bits
 *         give the expected packed bytes and exact encoded bit count.
 * Returns: none.
 * Errors: assertions report a mismatch from the independently derived vector.
 * Author: asn1c maintainers. History: added for issue #595.
 * Example: check the 7-bit UTCTime and 4-bit NumericString wire forms.
 */
static void
check_golden_uper(const asn_TYPE_descriptor_t *alias, const char *value,
                  size_t value_size, const uint8_t *golden,
                  size_t golden_size, ssize_t bits) {
    OCTET_STRING_t source = {(uint8_t *)value, value_size};
    uint8_t encoded[64] = {0};
    asn_enc_rval_t result;

    result = uper_encode_to_buffer(alias, 0, &source, encoded,
                                   sizeof(encoded));
    assert(result.encoded == bits);
    assert((size_t)(result.encoded + 7) / 8 == golden_size);
    assert(memcmp(encoded, golden, golden_size) == 0);
}

/*
 * Purpose: verify invalid characters fail during alias PER encoding.
 * Original source: issue #595 regression requirements.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: alias descriptor, invalid byte sequence, size, and APER selector.
 * Returns: none.
 * Errors: assertions fail if the alias accepts an invalid NumericString.
 * Author: asn1c maintainers. History: added for issue #595.
 * Example: reject an alphabetic byte in a NumericString alias.
 */
static void
check_invalid_value(const asn_TYPE_descriptor_t *alias, const char *value,
                    size_t value_size, int aligned) {
    OCTET_STRING_t source = {(uint8_t *)value, value_size};
    uint8_t encoded[64] = {0};
    asn_enc_rval_t result;

    if(aligned) {
        result = aper_encode_to_buffer(alias, 0, &source, encoded,
                                       sizeof(encoded));
    } else {
        result = uper_encode_to_buffer(alias, 0, &source, encoded,
                                       sizeof(encoded));
    }
    assert(result.encoded == -1);
}

/*
 * Purpose: reject reserved NumericString alphabet codes after alias decoding.
 * Original source: issue #595 regression requirements and NumericString map.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: alias descriptor and aligned selects APER instead of UPER.
 * Returns: none.
 * Errors: assertion fails if any alias accepts a reserved four-bit code.
 * Author: asn1c maintainers. History: added for issue #595.
 * Example: code 15 is outside NumericString's space-and-digit alphabet.
 */
static void
check_invalid_numeric_code(const asn_TYPE_descriptor_t *alias, int aligned) {
    static const uint8_t invalid_code[] = {0x01, 0xf0};
    OCTET_STRING_t *decoded = 0;
    asn_dec_rval_t result;

    if(aligned) {
        result = aper_decode_complete(0, alias, (void **)&decoded,
                                      invalid_code, sizeof(invalid_code));
    } else {
        result = uper_decode_complete(0, alias, (void **)&decoded,
                                      invalid_code, sizeof(invalid_code));
    }
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(*alias, decoded);
}

/*
 * Purpose: run issue #595 checks for built-in constraints and both PER rules.
 * Original source: new regression test entry point.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: none.
 * Returns: zero when every assertion passes.
 * Errors: assertions stop on unexpected constraints or codec behavior.
 * Author: asn1c maintainers. History: added for issue #595.
 * Example: check-assembly.sh runs this source with UPER and APER generation.
 */
int
main(void) {
    static const char utc[] = "241231235959Z";
    static const char utc_golden_value[] = "240115143000Z";
    static const char generalized[] = "20241231235959Z";
    static const char numeric[] = " 0123456789";
    static const char numeric_golden_value[] = "0123 456";
    static const char bad_numeric[] = "12A4";
    static const char short_numeric[] = "123";
    static const uint8_t utc_golden[] = {
        0x0d, 0x64, 0xd1, 0x83, 0x16, 0x2d, 0x58,
        0xb4, 0x66, 0xc1, 0x83, 0x0b, 0x40
    };
    static const uint8_t numeric_golden[] = {
        0x08, 0x12, 0x34, 0x05, 0x67
    };
    int aligned;

    check_constraints(&asn_DEF_UTCA2, &asn_DEF_UTCTime, 0);
    check_constraints(&asn_DEF_GTA2, &asn_DEF_GeneralizedTime, 0);
    check_constraints(&asn_DEF_NSA2, &asn_DEF_NumericString, 1);
    assert(asn_DEF_NSSize.encoding_constraints.per_constraints);
    assert(asn_DEF_NSSize.encoding_constraints.per_constraints->value2code);
    assert(asn_DEF_NSSize.encoding_constraints.per_constraints->code2value);
    assert(asn_DEF_NSSize.encoding_constraints.per_constraints->size.lower_bound
           == 2);
    assert(asn_DEF_NSSize.encoding_constraints.per_constraints->size.upper_bound
           == 5);
    check_golden_uper(&asn_DEF_UTCA2, utc_golden_value,
                      sizeof(utc_golden_value) - 1, utc_golden,
                      sizeof(utc_golden), 99);
    check_golden_uper(&asn_DEF_NSA2, numeric_golden_value,
                      sizeof(numeric_golden_value) - 1, numeric_golden,
                      sizeof(numeric_golden), 40);

    for(aligned = 0; aligned <= 1; aligned++) {
        check_valid_value(&asn_DEF_UTCA2, &asn_DEF_UTCTime, utc,
                          sizeof(utc) - 1, aligned);
        check_valid_value(&asn_DEF_GTA2, &asn_DEF_GeneralizedTime,
                          generalized, sizeof(generalized) - 1, aligned);
        check_valid_value(&asn_DEF_NSA2, &asn_DEF_NumericString, numeric,
                          sizeof(numeric) - 1, aligned);
        check_valid_value(&asn_DEF_NSSize, &asn_DEF_NSSize,
                          short_numeric, sizeof(short_numeric) - 1, aligned);
        check_invalid_value(&asn_DEF_NSA2, bad_numeric,
                            sizeof(bad_numeric) - 1, aligned);
        check_invalid_value(&asn_DEF_NSSize, bad_numeric,
                            sizeof(bad_numeric) - 1, aligned);
        check_invalid_numeric_code(&asn_DEF_NSA2, aligned);
    }
    return 0;
}
