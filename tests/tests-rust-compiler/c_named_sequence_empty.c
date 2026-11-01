/* Live C vectors for required/OPTIONAL empty named SEQUENCE children. */
/* Source: generated C descriptors and X.690. Date: 2026-11-01. */
/* Responsible party: asn1c maintainers. History: empty-child regression. */
#include <Empty.h>
#include <OptionalOnly.h>
#include <OptionalPacket.h>
#include <RequiredOnly.h>
#include <RequiredPacket.h>
#include <asn_application.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Purpose: compare one empty-child C descriptor against exact DER/CER vectors.
 * Inputs: descriptor/value select the record; both wire arguments are full TLVs.
 * Returns zero on encoding, decoding, value, and strict-CER parity; otherwise one.
 * Errors: codec and semantic mismatches fail. Partial decode values are freed.
 * Source: generated C descriptors and approved schema. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: empty named child gate.
 * Example: the required child is `30 00`, then wrapped by a parent SEQUENCE.
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor, const void *expected,
             const uint8_t *der, size_t der_size,
             const uint8_t *cer, size_t cer_size) {
    uint8_t actual[32];
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    void *decoded = NULL;
    int failed = 0;
    if(!descriptor || !expected || der_size > sizeof(actual) || cer_size > sizeof(actual)
       || !descriptor->op->compare_struct) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, descriptor, expected,
                                   actual, sizeof(actual));
    failed |= encoded.encoded < 0 || (size_t)encoded.encoded != der_size
        || memcmp(actual, der, der_size);
    encoded = asn_encode_to_buffer(NULL, ATS_CER, descriptor, expected,
                                   actual, sizeof(actual));
    failed |= encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
        || memcmp(actual, cer, cer_size);
    result = asn_decode(NULL, ATS_BER, descriptor, &decoded, der, der_size);
    failed |= result.code != RC_OK || result.consumed != der_size || !decoded
        || descriptor->op->compare_struct(descriptor, expected, decoded);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, cer, cer_size);
    failed |= result.code != RC_OK || result.consumed != cer_size || !decoded
        || descriptor->op->compare_struct(descriptor, expected, decoded);
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, descriptor, &decoded, der, der_size);
    failed |= result.code == RC_OK;
    if(decoded) descriptor->op->free_struct(descriptor, decoded, ASFM_FREE_EVERYTHING);
    if(failed) fprintf(stderr, "C empty-child vector failed for %s\n", descriptor->name);
    return failed;
}

/*
 * Purpose: verify BER default decoding and strict CER omission of explicit defaults.
 * Inputs: none. Returns zero when BER restores defaults and CER rejects the wire.
 * Errors: status, prefix, semantic, or canonicality mismatch returns one.
 * Source: generated RequiredPacket descriptor and X.690. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: default canonicality check.
 * Example: BOOLEAN FALSE is BER-decodable but omitted in CER output.
 */
static int
check_explicit_default(void) {
    static const uint8_t wire[] = {
        0x30, 0x80, 0x30, 0x80, 0, 0, 0x01, 0x01, 0x00, 0, 0,
    };
    RequiredPacket_t *decoded = NULL;
    RequiredPacket_t *strict = NULL;
    asn_dec_rval_t ber = asn_decode(NULL, ATS_BER, &asn_DEF_RequiredPacket,
                                    (void **)&decoded, wire, sizeof(wire));
    asn_dec_rval_t cer = asn_decode(NULL, ATS_CER, &asn_DEF_RequiredPacket,
                                    (void **)&strict, wire, sizeof(wire));
    int failed = ber.code != RC_OK || ber.consumed != sizeof(wire) || !decoded
        || !decoded->child || decoded->enabled || decoded->count != 0 || cer.code == RC_OK;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RequiredPacket, decoded);
    if(strict) ASN_STRUCT_FREE(asn_DEF_RequiredPacket, strict);
    if(failed) fprintf(stderr, "C explicit DEFAULT behavior mismatch\n");
    return failed;
}

/*
 * Purpose: verify empty child, OPTIONAL absence, and parent DEFAULT omission.
 * Inputs: none. Returns zero when all independent vectors match.
 * Errors: encoder, decoder, or exact-byte mismatch returns one.
 * Source: X.690 and generated parent descriptors. Date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: empty SEQUENCE target coverage.
 * Example: absent child/defaults yield `30 00` in DER and `30 80 00 00` in CER.
 */
int
main(void) {
    static const uint8_t required_der[] = {0x30, 0x02, 0x30, 0x00};
    static const uint8_t required_cer[] = {0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0};
    static const uint8_t absent_der[] = {0x30, 0x00};
    static const uint8_t absent_cer[] = {0x30, 0x80, 0, 0};
    static const uint8_t defaults_der[] = {
        0x30, 0x08, 0x30, 0x00, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03,
    };
    static const uint8_t defaults_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0, 0, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0, 0,
    };
    Empty_t empty = {0};
    RequiredOnly_t required = {.child = &empty};
    OptionalOnly_t optional_absent = {0};
    OptionalOnly_t optional_present = {.child = &empty};
    RequiredPacket_t defaults = {.child = &empty, .enabled = 0, .count = 0};
    RequiredPacket_t nondefaults = {.child = &empty, .enabled = 0xff, .count = 3};
    int failed = 0;
    failed |= check_vector(&asn_DEF_RequiredOnly, &required, required_der,
                           sizeof(required_der), required_cer, sizeof(required_cer));
    failed |= check_vector(&asn_DEF_OptionalOnly, &optional_absent, absent_der,
                           sizeof(absent_der), absent_cer, sizeof(absent_cer));
    failed |= check_vector(&asn_DEF_OptionalOnly, &optional_present, required_der,
                           sizeof(required_der), required_cer, sizeof(required_cer));
    failed |= check_vector(&asn_DEF_RequiredPacket, &defaults, required_der,
                           sizeof(required_der), required_cer, sizeof(required_cer));
    failed |= check_vector(&asn_DEF_RequiredPacket, &nondefaults, defaults_der,
                           sizeof(defaults_der), defaults_cer, sizeof(defaults_cer));
    failed |= check_explicit_default();
    if(failed) fprintf(stderr, "C empty named SEQUENCE fixture failed\n");
    return failed;
}
