/* Compare generated C BER/DER/CER SET bytes with the Rust conformance vectors. */
#include <asn_application.h>
#include <BIT_STRING.h>
#include <ENUMERATED.h>
#include <OCTET_STRING.h>
#include <SetAllRecord.h>
#include <SetPresenceRecord.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Purpose: verify one generated C SET encoder against a fixed byte vector.
 * Parameters: descriptor/value select a generated record; syntax selects DER/CER;
 * expected/length contain the oracle bytes; name labels a failure.
 * Returns: zero for an exact match, one for invalid arguments or mismatch.
 * Errors: encoder failures and mismatches are printed to stderr.
 * Source: asn1c generated-code BER/CER differential test. Version/date:
 * 2026-10-31. Author: asn1c maintainers. History: fourth-wave SET parity.
 * Example: check_encoding(&asn_DEF_SetAllRecord, &value, ATS_DER, wire, size, "DER").
 */
static int
check_encoding(const asn_TYPE_descriptor_t *descriptor, const void *value,
               enum asn_transfer_syntax syntax, const unsigned char *expected,
               size_t expected_length, const char *name) {
    unsigned char actual[64];
    asn_enc_rval_t encoded;
    if(!descriptor || !value || !expected || expected_length > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, syntax, descriptor, value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
       || memcmp(actual, expected, expected_length) != 0) {
        fprintf(stderr, "C BER/CER SET mismatch: %s\n", name);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode a Rust-produced required SET vector and check its values.
 * Parameters: syntax selects BER/DER/CER; wire and wire_length carry one TLV.
 * Returns: zero for exact prefix consumption and matching values, else one.
 * Errors: malformed input, wrong values, or wrong consumption return one.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: bidirectional SET interoperability.
 * Example: check_required_decode(ATS_CER, cer, sizeof(cer)).
 */
static int
check_required_decode(enum asn_transfer_syntax syntax, const unsigned char *wire,
                      size_t wire_length) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    SetAllRecord_t *value;
    int64_t state = 0;
    int failed;
    result = asn_decode(NULL, syntax, &asn_DEF_SetAllRecord, &decoded, wire, wire_length);
    value = decoded;
    failed = result.code != RC_OK || result.consumed != wire_length || !value
        || value->number != 3 || !value->flag || value->empty != 0
        || asn_INTEGER2int64(&value->state, &state) != 0 || state != 3
        || value->bits.size != 1 || value->bits.bits_unused != 3 || !value->bits.buf
        || value->bits.buf[0] != 0xa8 || value->octets.size != 2 || !value->octets.buf
        || memcmp(value->octets.buf, "AB", 2) != 0;
    if(failed)
        fprintf(stderr, "C SET decoder mismatch: syntax=%d code=%d consumed=%zu/%zu\n",
                (int)syntax, (int)result.code, result.consumed, wire_length);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_SetAllRecord, decoded);
    return failed;
}

/*
 * Purpose: compare required/default SET encoders and decode Rust wire vectors.
 * Parameters: none. Returns zero when all checks pass, otherwise one.
 * Errors: generated encoder/decoder mismatch or enum allocation failure returns one.
 * Source: independent Rust SET conformance vectors and generated C codec.
 * Version/date: 2026-10-31. Author: asn1c maintainers.
 * History: fourth-wave C SET parity. Example: run the fixture as a test binary.
 */
int
main(void) {
    static const unsigned char required_der[] = {
        0x31, 0x13, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8,
        0x04, 0x02, 0x41, 0x42, 0x05, 0x00, 0x0a, 0x01, 0x03
    };
    static const unsigned char required_cer[] = {
        0x31, 0x80, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x03, 0x02, 0x03, 0xa8,
        0x04, 0x02, 0x41, 0x42, 0x05, 0x00, 0x0a, 0x01, 0x03, 0x00, 0x00
    };
    static const unsigned char reordered_ber[] = {
        0x31, 0x13, 0x0a, 0x01, 0x03, 0x05, 0x00, 0x04, 0x02, 0x41, 0x42,
        0x03, 0x02, 0x03, 0xa8, 0x02, 0x01, 0x03, 0x01, 0x01, 0xff
    };
    static const unsigned char empty_der[] = {0x31, 0x00};
    static const unsigned char empty_cer[] = {0x31, 0x80, 0x00, 0x00};
    static unsigned char bit_bytes[] = {0xa8};
    static unsigned char octet_bytes[] = {'A', 'B'};
    SetAllRecord_t required = {0};
    SetPresenceRecord_t presence = {0};
    int failed = 0;

    /* Bind all six required fields to C-owned scalar and borrowed string storage. */
    required.number = 3;
    required.bits.buf = bit_bytes;
    required.bits.size = sizeof(bit_bytes);
    required.bits.bits_unused = 3;
    required.flag = 1;
    required.octets.buf = octet_bytes;
    required.octets.size = sizeof(octet_bytes);
    if(asn_int642INTEGER(&required.state, 3) != 0) {
        failed = 1;
        goto cleanup;
    }
    ASN_SET_MKPRESENT(&required._presence_map, SetAllRecord_PR_number);
    ASN_SET_MKPRESENT(&required._presence_map, SetAllRecord_PR_bits);
    ASN_SET_MKPRESENT(&required._presence_map, SetAllRecord_PR_state);
    ASN_SET_MKPRESENT(&required._presence_map, SetAllRecord_PR_flag);
    ASN_SET_MKPRESENT(&required._presence_map, SetAllRecord_PR_octets);
    ASN_SET_MKPRESENT(&required._presence_map, SetAllRecord_PR_empty);

    /* Null pointers select both DEFAULT values and omit all OPTIONAL fields. */
    presence.flag = 0;
    failed |= check_encoding(&asn_DEF_SetAllRecord, &required, ATS_DER,
                             required_der, sizeof(required_der), "required DER");
    failed |= check_encoding(&asn_DEF_SetAllRecord, &required, ATS_CER,
                             required_cer, sizeof(required_cer), "required CER");
    failed |= check_required_decode(ATS_DER, required_der, sizeof(required_der));
    failed |= check_required_decode(ATS_CER, required_cer, sizeof(required_cer));
    failed |= check_required_decode(ATS_BER, reordered_ber, sizeof(reordered_ber));
    failed |= check_encoding(&asn_DEF_SetPresenceRecord, &presence, ATS_DER,
                             empty_der, sizeof(empty_der), "default DER");
    failed |= check_encoding(&asn_DEF_SetPresenceRecord, &presence, ATS_CER,
                             empty_cer, sizeof(empty_cer), "default CER");
cleanup:
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ENUMERATED, &required.state);
    return failed;
}
