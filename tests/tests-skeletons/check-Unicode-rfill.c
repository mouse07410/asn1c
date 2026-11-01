/*
 * Purpose: keep randomized wide strings representable by JSON Encoding Rules.
 * Original source: regression for the C/C++ CI randomized string bundles.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: built-in BMPString and UniversalString descriptors.
 * Returns: zero on success, one on failure, or 77 when required codecs are off.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: added after CI run 41266285095.
 * Example: make check-Unicode-rfill && ./check-Unicode-rfill.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <BMPString.h>
#include <UniversalString.h>
#include <asn_application.h>
#include <asn_random_fill.h>
#include <constraints.h>

#if !defined(ASN_DISABLE_RFILL_SUPPORT) \
    && (!defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)) \
    && !defined(ASN_DISABLE_JER_SUPPORT)
/*
 * Read one network-order character from a generated wide string.
 * Original source: this regression test.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: bytes points to a character; unit_bytes is two or four.
 * Returns: its unsigned code point. Exceptions: none.
 * Responsible party: asn1c maintainers. History: initial implementation.
 * Example: read_codepoint(value->buf, 2) reads the first BMP character.
 */
static uint32_t
read_codepoint(const uint8_t *bytes, unsigned int unit_bytes) {
    uint32_t codepoint = 0;
    unsigned int index;

    for(index = 0; index < unit_bytes; index++) {
        codepoint = (codepoint << 8) | bytes[index];
    }
    return codepoint;
}

/*
 * Check that a sampled value can be encoded and decoded without loss.
 * Original source: this regression test.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: td describes the value; value holds generated wide characters.
 * Returns: zero on success or one on encoding, decoding, or comparison error.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: initial implementation. Example: check_jer_roundtrip(&asn_DEF_BMPString, value).
 */
static int
check_jer_roundtrip(const asn_TYPE_descriptor_t *td,
                    const OCTET_STRING_t *value) {
    uint8_t encoded[256];
    void *decoded = NULL;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    int failed;

    er = asn_encode_to_buffer(NULL, ATS_JER, td, value,
                              encoded, sizeof(encoded));
    if(er.encoded < 0 || (size_t)er.encoded > sizeof(encoded)) return 1;

    dr = asn_decode(NULL, ATS_JER, td, &decoded, encoded, (size_t)er.encoded);
    failed = dr.code != RC_OK || !decoded;
    if(!failed) {
        const OCTET_STRING_t *actual = (const OCTET_STRING_t *)decoded;
        failed = actual->size != value->size
                 || (value->size && memcmp(actual->buf, value->buf,
                                            value->size) != 0);
    }
    if(decoded) ASN_STRUCT_FREE(*td, decoded);
    return failed;
}

/*
 * Exercise an alphabet whose boundaries surround the surrogate block.
 * Original source: this regression test.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: td is BMPString or UniversalString; unit_bytes selects storage.
 * Returns: zero if every character is U+D7FF or U+E000 and JER round trips.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: initial implementation. Example: check_scalar_boundary(&asn_DEF_BMPString, 2).
 */
static int
check_scalar_boundary(const asn_TYPE_descriptor_t *td,
                      unsigned int unit_bytes) {
    asn_per_constraints_t per = {
        { APC_CONSTRAINED, 12, 12, 0xd7ff, 0xe000 },
        { APC_CONSTRAINED, 0, 0, 16, 16 }, NULL, NULL
    };
    asn_encoding_constraints_t member = { 0 };
    void *value = NULL;
    int failed = 0;
    int iteration;

    member.per_constraints = &per;
    for(iteration = 0; iteration < 16 && !failed; iteration++) {
        const OCTET_STRING_t *string_value;
        size_t offset;
        asn_random_fill_result_t result =
            OCTET_STRING_random_fill(td, &value, &member, 16);

        if(result.code != ARFILL_OK || !value) {
            failed = 1;
            break;
        }
        string_value = (const OCTET_STRING_t *)value;
        if(string_value->size != 16 * unit_bytes || !string_value->buf) {
            failed = 1;
            break;
        }
        for(offset = 0; offset < string_value->size; offset += unit_bytes) {
            uint32_t scalar = read_codepoint(string_value->buf + offset,
                                             unit_bytes);
            if(scalar != 0xd7ff && scalar != 0xe000) failed = 1;
        }
        if(!failed) failed = check_jer_roundtrip(td, string_value);
    }
    if(value) ASN_STRUCT_FREE(*td, value);
    return failed;
}

/*
 * Verify built-in wide-string metadata never samples non-scalar UCS-4 values.
 * Original source: this regression test.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: td is BMPString or UniversalString; unit_bytes selects storage.
 * Returns: zero if generated values are valid scalars and JER round trips.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: initial implementation. Example: check_builtin_range(&asn_DEF_UniversalString, 4).
 */
static int
check_builtin_range(const asn_TYPE_descriptor_t *td,
                    unsigned int unit_bytes) {
    void *value = NULL;
    int failed = 0;
    int iteration;

    for(iteration = 0; iteration < 32 && !failed; iteration++) {
        const OCTET_STRING_t *string_value;
        size_t offset;
        asn_random_fill_result_t result =
            OCTET_STRING_random_fill(td, &value, NULL, 16);

        if(result.code != ARFILL_OK || !value) {
            failed = 1;
            break;
        }
        string_value = (const OCTET_STRING_t *)value;
        if(!string_value->buf || string_value->size % unit_bytes) {
            failed = 1;
            break;
        }
        for(offset = 0; offset < string_value->size; offset += unit_bytes) {
            uint32_t scalar = read_codepoint(string_value->buf + offset,
                                             unit_bytes);
            if(scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff))
                failed = 1;
        }
        if(!failed) failed = check_jer_roundtrip(td, string_value);
    }
    if(value) ASN_STRUCT_FREE(*td, value);
    return failed;
}

/*
 * Reject an alphabet containing only non-scalar code points.
 * Original source: this regression test.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: td is a built-in wide-string descriptor; lower and upper bound the
 *         invalid alphabet.
 * Returns: zero if fill fails without installing a partial value, else one.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: initial implementation.
 * Example: check_rejected_range(&asn_DEF_BMPString, 0xd800, 0xdfff).
 */
static int
check_rejected_range(const asn_TYPE_descriptor_t *td, int lower, int upper) {
    asn_per_constraints_t per = {
        { APC_CONSTRAINED, 12, 12, 0, 0 },
        { APC_CONSTRAINED, 0, 0, 1, 1 }, NULL, NULL
    };
    asn_encoding_constraints_t member = { 0 };
    void *value = NULL;
    asn_random_fill_result_t result;
    int installed;

    per.value.lower_bound = lower;
    per.value.upper_bound = upper;
    member.per_constraints = &per;
    result = OCTET_STRING_random_fill(td, &value, &member, 1);
    installed = value != NULL;
    if(value) ASN_STRUCT_FREE(*td, value);
    return result.code != ARFILL_FAILED || installed;
}
#endif

/*
 * Run the wide-string random-fill and JER regressions.
 * Original source: this regression test.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: none. Returns: zero on success, one on failure, or 77 if disabled.
 * Exceptions: none. Responsible party: asn1c maintainers.
 * History: initial implementation. Example: ./check-Unicode-rfill.
 */
int
main(void) {
#if defined(ASN_DISABLE_RFILL_SUPPORT) \
    || (defined(ASN_DISABLE_UPER_SUPPORT) && defined(ASN_DISABLE_APER_SUPPORT)) \
    || defined(ASN_DISABLE_JER_SUPPORT)
    return 77;
#else
    if(check_scalar_boundary(&asn_DEF_BMPString, 2)
       || check_scalar_boundary(&asn_DEF_UniversalString, 4)
       || check_builtin_range(&asn_DEF_BMPString, 2)
       || check_builtin_range(&asn_DEF_UniversalString, 4)
       || check_rejected_range(&asn_DEF_BMPString, 0xd800, 0xdfff)
       || check_rejected_range(&asn_DEF_UniversalString, 0xd800, 0xdfff)
       || check_rejected_range(&asn_DEF_UniversalString, 0x110000, 0x110fff)) {
        fputs("wide-string random fill produced a non-scalar value\n", stderr);
        return 1;
    }
    return 0;
#endif
}
