/* Live C reference for generated Rust primitive CHOICE vectors.
 * Source: generated ASN.1 BER/DER/CER descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: direct CHOICE differential.
 */
#include <Value.h>
#include <asn_application.h>

#include <stdio.h>
#include <string.h>

/* Compare one encoded C choice and decode the same exact primitive TLV. */
typedef struct choice_case_s {
    Value_t value; /* Selected generated C alternative. */
    const uint8_t *wire; /* Expected primitive TLV bytes. */
    size_t size; /* Expected byte count. */
} choice_case_t;

/*
 * Purpose: compare C DER/CER output and BER/CER decoded selected values.
 * Inputs: item stores a selected value and its canonical primitive wire.
 * Returns zero on exact encoding, status, consumption, and value equality.
 * Errors: codec mismatches return one with a concise diagnostic.
 * Source: generated Value descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: CHOICE differential fixture.
 * Example: check_canonical(&item, ATS_DER, ATS_BER).
 */
static int
check_canonical(const choice_case_t *item, enum asn_transfer_syntax output_syntax,
                enum asn_transfer_syntax input_syntax) {
    uint8_t actual[16];
    Value_t *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;
    if(!item || !item->wire || item->size > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, output_syntax, &asn_DEF_Value,
                                   &item->value, actual, sizeof(actual));
    result = asn_decode(NULL, input_syntax, &asn_DEF_Value, (void **)&decoded,
                        item->wire, item->size);
    failed = encoded.encoded < 0 || (size_t)encoded.encoded != item->size
        || memcmp(actual, item->wire, item->size) || result.code != RC_OK
        || result.consumed != item->size || !decoded || !asn_DEF_Value.op->compare_struct
        || asn_DEF_Value.op->compare_struct(&asn_DEF_Value, &item->value, decoded);
    if(failed) {
        fprintf(stderr, "C primitive CHOICE mismatch syntax=%d/%d code=%d consumed=%zu/%zu\n",
                (int)output_syntax, (int)input_syntax, (int)result.code,
                result.consumed, item->size);
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    return failed;
}

/*
 * Purpose: require an encoding to be accepted by BER and canonicalized.
 * Inputs: wire/size give an alias; expected is its canonical primitive TLV.
 * Returns zero on BER success and exact DER output, one otherwise.
 * Errors: rejected input or mismatched canonicalization returns one.
 * Source: generated Value descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: BER alias vectors.
 * Example: high-tag BOOLEAN identifier canonicalizes to tag 1.
 */
static int
check_ber_alias(const uint8_t *wire, size_t size, const uint8_t *expected,
                size_t expected_size) {
    Value_t *decoded = NULL;
    Value_t *cer_decoded = NULL;
    uint8_t actual[16];
    asn_dec_rval_t result;
    asn_dec_rval_t cer_result;
    asn_enc_rval_t encoded;
    int failed;
    if(!wire || !size || !expected || expected_size > sizeof(actual)) return 1;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_Value, (void **)&decoded, wire, size);
    failed = result.code != RC_OK || result.consumed != size || !decoded;
    cer_result = asn_decode(NULL, ATS_CER, &asn_DEF_Value, (void **)&cer_decoded,
                            wire, size);
    failed |= cer_result.code == RC_OK;
    if(!failed) {
        encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Value, decoded,
                                       actual, sizeof(actual));
        failed = encoded.encoded < 0 || (size_t)encoded.encoded != expected_size
            || memcmp(actual, expected, expected_size);
    }
    if(failed) fprintf(stderr, "C primitive CHOICE BER alias mismatch\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    if(cer_decoded) ASN_STRUCT_FREE(asn_DEF_Value, cer_decoded);
    return failed;
}

/*
 * Purpose: verify BER prefix decoding leaves a suffix untouched.
 * Inputs: none. Returns zero for the exact three-byte CHOICE prefix.
 * Errors: decode status, value, or consumption mismatches return one.
 * Source: generated Value descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix interoperability.
 * Example: BOOLEAN TRUE followed by an unrelated 0xaa octet.
 */
static int
check_prefix(void) {
    static const uint8_t wire[] = {0x01, 0x01, 0xff, 0xaa};
    Value_t *decoded = NULL;
    Value_t *cer_decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Value,
                                      (void **)&decoded, wire, sizeof(wire));
    asn_dec_rval_t cer_result = asn_decode(NULL, ATS_CER, &asn_DEF_Value,
                                          (void **)&cer_decoded, wire, sizeof(wire));
    int failed = result.code != RC_OK || result.consumed != 3 || !decoded
        || decoded->present != Value_PR_flag || decoded->choice.flag == 0
        || cer_result.code != RC_OK || cer_result.consumed != 3 || !cer_decoded
        || cer_decoded->present != Value_PR_flag || cer_decoded->choice.flag == 0;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    if(cer_decoded) ASN_STRUCT_FREE(asn_DEF_Value, cer_decoded);
    return failed;
}

/*
 * Purpose: run exact C vectors and alias canonicalization probes.
 * Inputs: none. Returns zero when C and checked Rust vectors agree.
 * Errors: any encoding, decoding, or alias mismatch returns one.
 * Source: generated Value C descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: initial direct CHOICE stage.
 * Example: execute the compiled fixture from check-rust-backend.sh.
 */
int
main(void) {
    static const uint8_t yes[] = {0x01, 0x01, 0xff};
    static const uint8_t no[] = {0x01, 0x01, 0x00};
    static const uint8_t null_value[] = {0x05, 0x00};
    static const uint8_t minus_two[] = {0x02, 0x01, 0xfe};
    static const uint8_t five[] = {0x02, 0x01, 0x05};
    static const uint8_t bool_alias[] = {0x1f, 0x01, 0x01, 0xff};
    static const uint8_t null_alias[] = {0x1f, 0x05, 0x00};
    static const uint8_t int_alias[] = {0x1f, 0x02, 0x01, 0x05};
    static const uint8_t bool_length_alias[] = {0x01, 0x81, 0x01, 0xff};
    static const uint8_t null_length_alias[] = {0x05, 0x81, 0x00};
    static const uint8_t int_length_alias[] = {0x02, 0x81, 0x01, 0x05};
    static const uint8_t bool_empty[] = {0x01, 0x00};
    static const uint8_t bool_multioctet[] = {0x01, 0x02, 0x00, 0xff};
    static const uint8_t int_redundant[] = {0x02, 0x02, 0x00, 0x05};
    const choice_case_t cases[] = {
        {{.present = Value_PR_flag, .choice.flag = 1}, yes, sizeof(yes)},
        {{.present = Value_PR_flag, .choice.flag = 0}, no, sizeof(no)},
        {{.present = Value_PR_empty, .choice.empty = 0}, null_value, sizeof(null_value)},
        {{.present = Value_PR_count, .choice.count = -2}, minus_two, sizeof(minus_two)},
        {{.present = Value_PR_count, .choice.count = 5}, five, sizeof(five)},
    };
    size_t index;
    for(index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        if(check_canonical(&cases[index], ATS_DER, ATS_BER)
           || check_canonical(&cases[index], ATS_CER, ATS_CER)) return 1;
    }
    if(check_ber_alias(bool_alias, sizeof(bool_alias), yes, sizeof(yes))
       || check_ber_alias(null_alias, sizeof(null_alias), null_value, sizeof(null_value))
       || check_ber_alias(int_alias, sizeof(int_alias), five, sizeof(five))
       || check_ber_alias(bool_length_alias, sizeof(bool_length_alias), yes, sizeof(yes))
       || check_ber_alias(null_length_alias, sizeof(null_length_alias), null_value,
                          sizeof(null_value))
       || check_ber_alias(int_length_alias, sizeof(int_length_alias), five, sizeof(five))
       || check_ber_alias(bool_empty, sizeof(bool_empty), no, sizeof(no))
       || check_ber_alias(bool_multioctet, sizeof(bool_multioctet), yes, sizeof(yes))
       || check_ber_alias(int_redundant, sizeof(int_redundant), five, sizeof(five))
       || check_prefix()) return 1;
    return 0;
}
