#include <asn_application.h>
#include <ENUMERATED.h>
#include <ExplicitBoolean.h>
#include <ExplicitSequence.h>
#include <ExplicitSet.h>
#include <ImplicitSequence.h>

#include <stdio.h>
#include <string.h>

/*
 * Purpose: compare one generated C encoding with an independent X.690 vector.
 * Parameters: descriptor/value identify the generated type and value; syntax
 * selects DER or CER; expected/length describe the exact expected bytes.
 * Returns: zero for a match, one for invalid input or an encoding mismatch.
 * Errors: encoder failures and mismatches are reported to stderr.
 * Original source: X.690 explicit and implicit tag rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit embedded ENUMERATED regression.
 * Example: check_encoding(&asn_DEF_ExplicitSequence, &value, ATS_DER, ...).
 */
static int
check_encoding(const asn_TYPE_descriptor_t *descriptor, const void *value,
               enum asn_transfer_syntax syntax, const unsigned char *expected,
               size_t length) {
    unsigned char actual[32];
    asn_enc_rval_t result;

    if(!descriptor || !value || !expected || length > sizeof(actual)) return 1;
    result = asn_encode_to_buffer(NULL, syntax, descriptor, value, actual,
                                  sizeof(actual));
    if(result.encoded < 0 || (size_t)result.encoded != length
       || memcmp(actual, expected, length) != 0) {
        fprintf(stderr, "explicit ENUMERATED encoding mismatch: %s/%d\n",
                descriptor->name, (int)syntax);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode one BER or CER vector and verify its canonical re-encoding.
 * Parameters: descriptor identifies the generated type; syntax selects BER or
 * CER; wire/length carry one complete vector; expected gives canonical bytes.
 * Returns: zero for full decode and exact re-encoding, one otherwise.
 * Errors: invalid arguments, decoder failure, and mismatch return one.
 * Original source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: explicit ENUMERATED BER/CER decoding.
 * Example: check_decoding(&asn_DEF_ExplicitSet, ATS_CER, ...).
 */
static int
check_decoding(const asn_TYPE_descriptor_t *descriptor,
               enum asn_transfer_syntax syntax, const unsigned char *wire,
               size_t length, const unsigned char *expected,
               size_t expected_length) {
    unsigned char actual[32];
    enum asn_transfer_syntax encoding_syntax;
    asn_enc_rval_t encoded;
    asn_dec_rval_t decoded;
    void *value = NULL;
    int failed;

    if(!descriptor || !wire || !length || !expected
       || expected_length > sizeof(actual)) return 1;
    decoded = asn_decode(NULL, syntax, descriptor, &value, wire, length);
    failed = decoded.code != RC_OK || decoded.consumed != length || !value;
    if(failed) {
        fprintf(stderr, "explicit ENUMERATED decode mismatch: %s/%d\n",
                descriptor->name, (int)syntax);
        if(value) ASN_STRUCT_FREE(*descriptor, value);
        return 1;
    }
    encoding_syntax = syntax == ATS_CER ? ATS_CER : ATS_DER;
    encoded = asn_encode_to_buffer(NULL, encoding_syntax, descriptor, value,
                                   actual, sizeof(actual));
    failed = encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
        || memcmp(actual, expected, expected_length) != 0;
    if(failed)
        fprintf(stderr, "explicit ENUMERATED decode mismatch: %s/%d\n",
                descriptor->name, (int)syntax);
    if(value) ASN_STRUCT_FREE(*descriptor, value);
    return failed;
}

/*
 * Purpose: check DER/CER bytes and BER/CER decoding for all tag-mode controls.
 * Parameters: none. Returns zero when all independent vectors match.
 * Errors: any encoder or decoder mismatch returns one.
 * Original source: X.690 tag and CER framing rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: inline ENUMERATED explicit-tag fix.
 * Example: main() checks explicit ENUMERATED, implicit ENUMERATED, and BOOLEAN.
 */
int
main(void) {
    static const unsigned char seq_der[] = {0x30, 6, 0xbf, 0x7f, 3, 0x0a, 1, 2};
    static const unsigned char seq_cer[] = {
        0x30, 0x80, 0xbf, 0x7f, 0x80, 0x0a, 1, 2, 0, 0, 0, 0
    };
    static const unsigned char set_der[] = {0x31, 6, 0xbf, 0x7f, 3, 0x0a, 1, 2};
    static const unsigned char set_cer[] = {
        0x31, 0x80, 0xbf, 0x7f, 0x80, 0x0a, 1, 2, 0, 0, 0, 0
    };
    static const unsigned char implicit_der[] = {0x30, 4, 0x9f, 0x7f, 1, 2};
    static const unsigned char implicit_cer[] = {
        0x30, 0x80, 0x9f, 0x7f, 1, 2, 0, 0
    };
    static const unsigned char boolean_der[] = {
        0x30, 6, 0xbf, 0x7e, 3, 1, 1, 0xff
    };
    static const unsigned char boolean_cer[] = {
        0x30, 0x80, 0xbf, 0x7e, 0x80, 1, 1, 0xff, 0, 0, 0, 0
    };
    ExplicitSequence_t sequence = {0};
    ExplicitSet_t set = {0};
    ImplicitSequence_t implicit = {0};
    ExplicitBoolean_t boolean = {0};
    int failed = 0;

    sequence.state = 2;
    set.state = 2;
    implicit.state = 2;
    boolean.value = 1;
    failed |= check_encoding(&asn_DEF_ExplicitSequence, &sequence, ATS_DER,
                             seq_der, sizeof(seq_der));
    failed |= check_encoding(&asn_DEF_ExplicitSequence, &sequence, ATS_CER,
                             seq_cer, sizeof(seq_cer));
    failed |= check_encoding(&asn_DEF_ExplicitSet, &set, ATS_DER,
                             set_der, sizeof(set_der));
    failed |= check_encoding(&asn_DEF_ExplicitSet, &set, ATS_CER,
                             set_cer, sizeof(set_cer));
    failed |= check_encoding(&asn_DEF_ImplicitSequence, &implicit, ATS_DER,
                             implicit_der, sizeof(implicit_der));
    failed |= check_encoding(&asn_DEF_ImplicitSequence, &implicit, ATS_CER,
                             implicit_cer, sizeof(implicit_cer));
    failed |= check_encoding(&asn_DEF_ExplicitBoolean, &boolean, ATS_DER,
                             boolean_der, sizeof(boolean_der));
    failed |= check_encoding(&asn_DEF_ExplicitBoolean, &boolean, ATS_CER,
                             boolean_cer, sizeof(boolean_cer));
    failed |= check_decoding(&asn_DEF_ExplicitSequence, ATS_BER, seq_der,
                             sizeof(seq_der), seq_der, sizeof(seq_der));
    failed |= check_decoding(&asn_DEF_ExplicitSequence, ATS_CER, seq_cer,
                             sizeof(seq_cer), seq_cer, sizeof(seq_cer));
    failed |= check_decoding(&asn_DEF_ExplicitSet, ATS_BER, set_der,
                             sizeof(set_der), set_der, sizeof(set_der));
    failed |= check_decoding(&asn_DEF_ExplicitSet, ATS_CER, set_cer,
                             sizeof(set_cer), set_cer, sizeof(set_cer));
    failed |= check_decoding(&asn_DEF_ImplicitSequence, ATS_BER, implicit_der,
                             sizeof(implicit_der), implicit_der,
                             sizeof(implicit_der));
    failed |= check_decoding(&asn_DEF_ImplicitSequence, ATS_CER, implicit_cer,
                             sizeof(implicit_cer), implicit_cer,
                             sizeof(implicit_cer));
    failed |= check_decoding(&asn_DEF_ExplicitBoolean, ATS_BER, boolean_der,
                             sizeof(boolean_der), boolean_der,
                             sizeof(boolean_der));
    failed |= check_decoding(&asn_DEF_ExplicitBoolean, ATS_CER, boolean_cer,
                             sizeof(boolean_cer), boolean_cer,
                             sizeof(boolean_cer));
    return failed;
}
