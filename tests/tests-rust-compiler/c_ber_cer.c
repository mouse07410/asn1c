/* Compare generated C BER/DER/CER vectors with the generated Rust tests. */
#include <asn_application.h>
#include <BIT_STRING.h>
#include <Bits.h>
#include <Color.h>
#include <FixedBits.h>
#include <FixedOctets.h>
#include <Octets.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Test case descriptors contain the generated type, value, and expected TLV. */
typedef struct vector_s {
    const asn_TYPE_descriptor_t *type; /* Generated C ASN.1 descriptor. */
    const void *value; /* Borrowed value passed to the C encoder. */
    enum asn_transfer_syntax syntax; /* DER or CER encoding rule under test. */
    const unsigned char *expected; /* Independent canonical wire bytes. */
    size_t length; /* Exact expected TLV length. */
    const char *name; /* Diagnostic name for the selected vector. */
} vector_t;

/*
 * Purpose: compare one generated C TLV with its independent fixed vector.
 * Parameters: item supplies a descriptor, value, syntax, and expected bytes.
 * Returns zero for an exact match and one for invalid input or mismatch.
 * Errors: encoder errors and mismatches print a diagnostic; no exception.
 * Original source: asn1c generated-code BER/CER regression. Version/date:
 * 2026-10-31. Author: asn1c maintainers. History: initial Rust parity vector.
 * Example: check_vector(&vectors[0]) compares DER ENUMERATED -3.
 */
static int
check_vector(const vector_t *item) {
    unsigned char actual[16];
    asn_enc_rval_t encoded;

    /* Reject incomplete descriptors before calling a generated encoder. */
    if(!item || !item->type || !item->value || !item->expected
       || item->length > sizeof(actual)) return 1;

    /* Exercise the live C dispatch path using the same vector as Rust. */
    encoded = asn_encode_to_buffer(NULL, item->syntax, item->type,
                                   item->value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != item->length
       || memcmp(actual, item->expected, item->length) != 0) {
        fprintf(stderr, "C BER/CER vector mismatch: %s\n", item->name);
        return 1;
    }
    return 0;
}

/*
 * Purpose: run DER/CER comparisons for ENUMERATED and fixed/bounded strings.
 * Parameters: none. Returns zero when all encodings match; one on failure.
 * Errors: reports the first C encoder mismatch; no exception is thrown.
 * Original source: generated C codecs and X.690 primitive vectors.
 * Version/date: 2026-10-31. Author: asn1c maintainers.
 * History: initial BER/DER/CER generated Rust integration fixture.
 * Example: `c-ber-cer` verifies both rules for each primitive value.
 */
int
main(void) {
    static const unsigned char enum_min[] = {0x0a, 0x01, 0xfd};
    static const unsigned char enum_max[] = {0x0a, 0x01, 0x07};
    static const unsigned char enum_wide_min[] = {
        0x0a, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0
    };
    static const unsigned char enum_wide_max[] = {
        0x0a, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    static const unsigned char octets_wire[] = {0x04, 0x02, 0xa5, 0x5a};
    static const unsigned char bits_wire[] = {0x03, 0x02, 0x05, 0xa0};
    unsigned char octets_data[] = {0xa5, 0x5a};
    unsigned char bits_data[] = {0xa0};
    Color_t color_min = {0};
    Color_t color_max = {0};
    Color_t color_wide_min = {0};
    Color_t color_wide_max = {0};
    Octets_t octets = {octets_data, sizeof(octets_data)};
    FixedOctets_t fixed_octets = {octets_data, sizeof(octets_data)};
    Bits_t bits = {bits_data, sizeof(bits_data), 5};
    FixedBits_t fixed_bits = {bits_data, sizeof(bits_data), 5};
    vector_t vectors[] = {
        {&asn_DEF_Color, &color_min, ATS_DER, enum_min, sizeof(enum_min), "DER enum -3"},
        {&asn_DEF_Color, &color_min, ATS_CER, enum_min, sizeof(enum_min), "CER enum -3"},
        {&asn_DEF_Color, &color_max, ATS_DER, enum_max, sizeof(enum_max), "DER enum 7"},
        {&asn_DEF_Color, &color_max, ATS_CER, enum_max, sizeof(enum_max), "CER enum 7"},
        {&asn_DEF_Color, &color_wide_min, ATS_DER, enum_wide_min,
         sizeof(enum_wide_min), "DER enum i64 minimum"},
        {&asn_DEF_Color, &color_wide_min, ATS_CER, enum_wide_min,
         sizeof(enum_wide_min), "CER enum i64 minimum"},
        {&asn_DEF_Color, &color_wide_max, ATS_DER, enum_wide_max,
         sizeof(enum_wide_max), "DER enum i64 maximum"},
        {&asn_DEF_Color, &color_wide_max, ATS_CER, enum_wide_max,
         sizeof(enum_wide_max), "CER enum i64 maximum"},
        {&asn_DEF_Octets, &octets, ATS_DER, octets_wire, sizeof(octets_wire), "DER bounded octets"},
        {&asn_DEF_Octets, &octets, ATS_CER, octets_wire, sizeof(octets_wire), "CER bounded octets"},
        {&asn_DEF_FixedOctets, &fixed_octets, ATS_DER, octets_wire, sizeof(octets_wire), "DER fixed octets"},
        {&asn_DEF_FixedOctets, &fixed_octets, ATS_CER, octets_wire, sizeof(octets_wire), "CER fixed octets"},
        {&asn_DEF_Bits, &bits, ATS_DER, bits_wire, sizeof(bits_wire), "DER bounded bits"},
        {&asn_DEF_Bits, &bits, ATS_CER, bits_wire, sizeof(bits_wire), "CER bounded bits"},
        {&asn_DEF_FixedBits, &fixed_bits, ATS_DER, bits_wire, sizeof(bits_wire), "DER fixed bits"},
        {&asn_DEF_FixedBits, &fixed_bits, ATS_CER, bits_wire, sizeof(bits_wire), "CER fixed bits"},
    };
    size_t index;
    int failed = 0;

    /* Generated C stores ENUMERATED as INTEGER_t, not a native long. */
    if(asn_int642INTEGER(&color_min, -3) != 0
       || asn_int642INTEGER(&color_max, 7) != 0
       || asn_int642INTEGER(&color_wide_min, INT64_MIN) != 0
       || asn_int642INTEGER(&color_wide_max, INT64_MAX) != 0) {
        failed = 1;
        goto cleanup;
    }

    /* Each vector checks one encoder/type/rule combination. */
    for(index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        if(check_vector(&vectors[index])) {
            failed = 1;
            break;
        }
    }

cleanup:
    /* Release all buffer-backed ENUMERATED values, including partial setup. */
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Color, &color_min);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Color, &color_max);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Color, &color_wide_min);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Color, &color_wide_max);
    return failed;
}
