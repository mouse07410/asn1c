/* Compare wide generated C INTEGER BER/DER/CER behavior to fixed vectors. */
#include <asn_application.h>
#include <Huge.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Each vector binds signed bytes to exact DER/CER output bytes. */
typedef struct integer_vector_s {
    const char *name; /* Vector label for diagnostics. */
    uint8_t *value; /* Borrowed two's-complement bytes. */
    size_t value_length; /* Byte length of the signed integer. */
    const uint8_t *wire; /* Exact universal INTEGER TLV. */
    size_t wire_length; /* Exact total TLV length. */
} integer_vector_t;

/*
 * Purpose: verify generated C DER/CER encoders and decoders for one vector.
 * Parameters: item contains canonical signed bytes and a fixed TLV vector.
 * Returns: zero for exact round-trip; one for encoding, decoding, or mismatch.
 * Errors: reports C codec failures and mismatched values to stderr.
 * Source: wide-type asn1c generated INTEGER codecs and X.690 vectors.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: initial unconstrained BigInteger generator comparison.
 * Example: check_vector(&vectors[0]) tests INTEGER zero.
 */
static int
check_vector(const integer_vector_t *item) {
    uint8_t actual[140];
    enum asn_transfer_syntax syntax;

    if(!item || !item->name || !item->value || !item->wire
       || item->value_length == 0 || item->wire_length > sizeof(actual)) return 1;
    for(syntax = ATS_DER; syntax <= ATS_CER; syntax++) {
        asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, syntax, &asn_DEF_Huge,
            &(Huge_t){.buf = item->value, .size = item->value_length}, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != item->wire_length
           || memcmp(actual, item->wire, item->wire_length) != 0) {
            fprintf(stderr, "C wide INTEGER %s encode mismatch for syntax %d\n",
                    item->name, (int)syntax);
            return 1;
        }
    }
    for(syntax = ATS_BER; syntax <= ATS_CER; syntax += 2) {
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_Huge, &decoded,
                                            item->wire, item->wire_length);
        Huge_t *value = decoded;
        int failed = result.code != RC_OK || result.consumed != item->wire_length
            || !value || value->size != item->value_length || !value->buf
            || memcmp(value->buf, item->value, item->value_length) != 0;
        if(failed)
            fprintf(stderr, "C wide INTEGER %s decode mismatch: syntax %d, code %d\n",
                    item->name, (int)syntax, (int)result.code);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
        if(failed) return 1;
    }
    return 0;
}

/*
 * Purpose: check BER compatibility for redundant signs and legacy empty input.
 * Parameters: none. Returns zero when BER accepts and CER rejects both forms.
 * Errors: unexpected decoder status or consumption returns one.
 * Source: wide C INTEGER BER decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: empty and redundant-sign behavior.
 * Example: BER accepts `02 02 00 01`; strict CER rejects it.
 */
static int
check_ber_compatibility(void) {
    static const uint8_t redundant[] = {0x02, 0x02, 0x00, 0x01};
    static const uint8_t empty[] = {0x02, 0x00};
    static const uint8_t alias[] = {0x1f, 0x02, 0x01, 0x01};
    const uint8_t *inputs[] = {redundant, empty, alias};
    const size_t lengths[] = {sizeof(redundant), sizeof(empty), sizeof(alias)};
    size_t index;

    for(index = 0; index < sizeof(inputs) / sizeof(inputs[0]); index++) {
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Huge, &decoded,
                                            inputs[index], lengths[index]);
        Huge_t *value = decoded;
        int64_t integer_value = 0;
        if(result.code != RC_OK || result.consumed != lengths[index] || !decoded) {
            fprintf(stderr, "C wide INTEGER BER compatibility case %zu failed\n", index);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
            return 1;
        }
        if((index == 0 || index == 2)
           && (asn_INTEGER2int64(value, &integer_value) != 0 || integer_value != 1)) {
            fprintf(stderr, "C wide INTEGER BER compatibility value %zu was not one\n", index);
            ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
            return 1;
        }
        ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
        decoded = NULL;
        result = asn_decode(NULL, ATS_CER, &asn_DEF_Huge, &decoded,
                            inputs[index], lengths[index]);
        if(result.code == RC_OK) {
            fprintf(stderr, "C strict CER accepted compatibility case %zu\n", index);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
            return 1;
        }
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
    }
    return 0;
}

/*
 * Purpose: verify BER reports the exact prefix before a trailing byte.
 * Parameters: none. Returns zero for the expected three-byte prefix.
 * Errors: a decoder status, consumption, or value mismatch returns one.
 * Source: wide C INTEGER BER decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: primitive prefix interoperability.
 * Example: `02 01 01 ff` decodes one-byte integer plus one suffix octet.
 */
static int
check_ber_prefix(void) {
    static const uint8_t wire[] = {0x02, 0x01, 0x01, 0xff};
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Huge, &decoded,
                                        wire, sizeof(wire));
    Huge_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != 3 || !value
        || value->size != 1 || !value->buf || value->buf[0] != 1;
    if(failed)
        fprintf(stderr, "C wide INTEGER BER prefix mismatch: code %d, consumed %zu/3\n",
                (int)result.code, result.consumed);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Huge, decoded);
    return failed;
}

/*
 * Purpose: compare generated wide C INTEGER encodings to exact signed vectors.
 * Parameters: none. Returns zero when all vectors and compatibility probes pass.
 * Errors: any vector mismatch returns one; no exception is thrown.
 * Source: generated C and Rust BigInteger conformance vectors.
 * Version/date: 2026-11-01. Author: asn1c maintainers.
 * History: initial unconstrained INTEGER C/Rust differential fixture.
 * Example: run the fixture binary after generating with `-fwide-types`.
 */
int
main(void) {
    static uint8_t zero[] = {0x00};
    static uint8_t one[] = {0x01};
    static uint8_t minus_one[] = {0xff};
    static uint8_t minus_129[] = {0xff, 0x7f};
    static uint8_t minus_128[] = {0x80};
    static uint8_t plus_127[] = {0x7f};
    static uint8_t plus_128[] = {0x00, 0x80};
    static uint8_t max_i64[] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static uint8_t min_i64[] = {0x80, 0, 0, 0, 0, 0, 0, 0};
    static uint8_t plus_2_64[] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0};
    static uint8_t minus_2_65[] = {0xfe, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t wire_zero[] = {0x02, 0x01, 0x00};
    static const uint8_t wire_one[] = {0x02, 0x01, 0x01};
    static const uint8_t wire_minus_one[] = {0x02, 0x01, 0xff};
    static const uint8_t wire_minus_129[] = {0x02, 0x02, 0xff, 0x7f};
    static const uint8_t wire_minus_128[] = {0x02, 0x01, 0x80};
    static const uint8_t wire_127[] = {0x02, 0x01, 0x7f};
    static const uint8_t wire_128[] = {0x02, 0x02, 0x00, 0x80};
    static const uint8_t wire_max_i64[] = {
        0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    static const uint8_t wire_min_i64[] = {
        0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t wire_plus_2_64[] = {
        0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0
    };
    static const uint8_t wire_minus_2_65[] = {
        0x02, 0x09, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0
    };
    integer_vector_t vectors[] = {
        {"zero", zero, sizeof(zero), wire_zero, sizeof(wire_zero)},
        {"one", one, sizeof(one), wire_one, sizeof(wire_one)},
        {"minus one", minus_one, sizeof(minus_one), wire_minus_one, sizeof(wire_minus_one)},
        {"minus 129", minus_129, sizeof(minus_129), wire_minus_129, sizeof(wire_minus_129)},
        {"minus 128", minus_128, sizeof(minus_128), wire_minus_128, sizeof(wire_minus_128)},
        {"127", plus_127, sizeof(plus_127), wire_127, sizeof(wire_127)},
        {"128", plus_128, sizeof(plus_128), wire_128, sizeof(wire_128)},
        {"i64 maximum", max_i64, sizeof(max_i64), wire_max_i64, sizeof(wire_max_i64)},
        {"i64 minimum", min_i64, sizeof(min_i64), wire_min_i64, sizeof(wire_min_i64)},
        {"2^64", plus_2_64, sizeof(plus_2_64), wire_plus_2_64, sizeof(wire_plus_2_64)},
        {"-2^65", minus_2_65, sizeof(minus_2_65), wire_minus_2_65,
         sizeof(wire_minus_2_65)},
    };
    uint8_t very_wide_value[129] = {0};
    uint8_t very_wide_wire[132] = {0x02, 0x81, 0x81};
    integer_vector_t very_wide;
    size_t index;

    /* A 129-octet positive body independently crosses the long-form length. */
    very_wide_value[0] = 1;
    memcpy(very_wide_wire + 3, very_wide_value, sizeof(very_wide_value));
    very_wide = (integer_vector_t){"129-octet body", very_wide_value,
        sizeof(very_wide_value), very_wide_wire, sizeof(very_wide_wire)};
    for(index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        if(check_vector(&vectors[index])) return 1;
    }
    if(check_vector(&very_wide) || check_ber_compatibility() || check_ber_prefix()) return 1;
    return 0;
}
