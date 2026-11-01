/* Compare the C BER/DER/CER codecs with one IMPLICIT SEQUENCE root vector. */
#include <asn_application.h>
#include <RootTag31.h>
#include <RootTagMax.h>
#include <RootTag3.h>

#include <stdio.h>
#include <string.h>

/*
 * Purpose: compare generated C DER/CER output with the canonical root vector.
 * Parameters: syntax chooses the rule; value supplies the ASN.1 field; expected
 * and length describe the fixed independent bytes. Returns zero on exact match.
 * Errors: invalid input, encoder failure, or a byte mismatch returns one.
 * Source: X.690 constructed context-specific root encoding. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: tagged root generator slice.
 * Example: DER tag 3 and INTEGER value 2 produce `a3 03 02 01 02`.
 */
static int
check_encoding(enum asn_transfer_syntax syntax,
               const asn_TYPE_descriptor_t *type, const void *value,
               const unsigned char *expected, size_t length) {
    unsigned char actual[16];
    asn_enc_rval_t encoded;
    if(!type || !value || !expected || length > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, syntax, type, value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != length
       || memcmp(actual, expected, length) != 0) {
        fprintf(stderr, "C tagged root encoding mismatch for syntax %d\n", (int)syntax);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode a fixed root vector and check field and prefix consumption.
 * Parameters: syntax selects BER/CER; wire and length are supplied bytes;
 * expected_consumed is the prefix length. Returns zero for a matching record.
 * Errors: malformed input, mismatched consumption, or wrong value returns one.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged root interoperability. Example: decode CER.
 */
static int
check_decoding(enum asn_transfer_syntax syntax, const asn_TYPE_descriptor_t *type,
               const unsigned char *wire, size_t length, size_t expected_consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    const long *field;
    int failed;
    if(!type || !wire || !length) return 1;
    result = asn_decode(NULL, syntax, type, &decoded, wire, length);
    field = decoded;
    failed = result.code != RC_OK || result.consumed != expected_consumed
        || !field || *field != 2;
    if(failed)
        fprintf(stderr, "C tagged root decode mismatch: syntax=%d consumed=%zu/%zu\n",
                (int)syntax, result.consumed, expected_consumed);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTag3, decoded);
    return failed;
}

/*
 * Purpose: check expected root rejection and BER alias acceptance.
 * Parameters: none. Returns zero when malformed/CER alias behavior matches.
 * Errors: an accepted malformed root or rejected BER alias returns one.
 * Source: X.690 constructed bit, high-tag alias, and canonical CER rules.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: root-tag parser differential. Example: BER accepts `bf 03` for tag 3.
 */
static int
check_root_rejections(void) {
    static const unsigned char alias[] = {0xbf, 0x03, 0x03, 0x02, 0x01, 0x02};
    static const unsigned char primitive[] = {0x83, 0x03, 0x02, 0x01, 0x02};
    static const unsigned char definite[] = {0xa3, 0x03, 0x02, 0x01, 0x02};
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_RootTag3, &decoded,
                        alias, sizeof(alias));
    failed |= result.code != RC_OK || result.consumed != sizeof(alias)
        || !decoded || ((RootTag3_t *)decoded)->x != 2;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTag3, decoded);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTag3, &decoded,
                        alias, sizeof(alias));
    failed |= result.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTag3, decoded);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTag3, &decoded,
                        definite, sizeof(definite));
    failed |= result.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTag3, decoded);
    decoded = NULL;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_RootTag3, &decoded,
                        primitive, sizeof(primitive));
    failed |= result.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTag3, decoded);
    return failed;
}

/*
 * Purpose: run C parity and decoder checks for one tagged root SEQUENCE.
 * Parameters: none. Returns zero when canonical bytes and hostile forms agree.
 * Errors: any encode/decode mismatch returns one. No allocation is retained.
 * Source: independent DER/CER vectors plus generated C codecs. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: root tag parity. Example: run test binary.
 */
int
main(void) {
    static const unsigned char der[] = {0xa3, 0x03, 0x02, 0x01, 0x02};
    static const unsigned char cer[] = {0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0};
    static const unsigned char der_31[] = {0xbf, 0x1f, 3, 2, 1, 2};
    static const unsigned char cer_31[] = {0xbf, 0x1f, 0x80, 2, 1, 2, 0, 0};
    static const unsigned char der_max[] = {
        0xbf, 0x83, 0xff, 0xff, 0xff, 0x7f, 3, 2, 1, 2
    };
    static const unsigned char cer_max[] = {
        0xbf, 0x83, 0xff, 0xff, 0xff, 0x7f, 0x80, 2, 1, 2, 0, 0
    };
    static const unsigned char indefinite_ber[] = {
        0xa3, 0x80, 0x02, 0x01, 0x02, 0, 0
    };
    RootTag3_t value = {2};
    RootTag31_t value_31 = {2};
    RootTagMax_t value_max = {2};
    int failed = 0;
    failed |= check_encoding(ATS_DER, &asn_DEF_RootTag3, &value, der, sizeof(der));
    failed |= check_encoding(ATS_CER, &asn_DEF_RootTag3, &value, cer, sizeof(cer));
    failed |= check_encoding(ATS_DER, &asn_DEF_RootTag31, &value_31,
                             der_31, sizeof(der_31));
    failed |= check_encoding(ATS_CER, &asn_DEF_RootTag31, &value_31,
                             cer_31, sizeof(cer_31));
    failed |= check_encoding(ATS_DER, &asn_DEF_RootTagMax, &value_max,
                             der_max, sizeof(der_max));
    failed |= check_encoding(ATS_CER, &asn_DEF_RootTagMax, &value_max,
                             cer_max, sizeof(cer_max));
    failed |= check_decoding(ATS_BER, &asn_DEF_RootTag3, der, sizeof(der), sizeof(der));
    failed |= check_decoding(ATS_BER, &asn_DEF_RootTag31,
                             der_31, sizeof(der_31), sizeof(der_31));
    failed |= check_decoding(ATS_BER, &asn_DEF_RootTagMax,
                             der_max, sizeof(der_max), sizeof(der_max));
    failed |= check_decoding(ATS_BER, &asn_DEF_RootTag3,
                             indefinite_ber, sizeof(indefinite_ber),
                             sizeof(indefinite_ber));
    failed |= check_decoding(ATS_CER, &asn_DEF_RootTag3, cer, sizeof(cer), sizeof(cer));
    failed |= check_decoding(ATS_CER, &asn_DEF_RootTag31,
                             cer_31, sizeof(cer_31), sizeof(cer_31));
    failed |= check_decoding(ATS_CER, &asn_DEF_RootTagMax,
                             cer_max, sizeof(cer_max), sizeof(cer_max));
    failed |= check_root_rejections();
    return failed;
}
