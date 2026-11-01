/* Compare generated C SET-root codecs with fixed BER/DER/CER vectors. */
#include <asn_application.h>
#include <RootMixed.h>
#include <RootTag0.h>
#include <RootTag127.h>
#include <RootTag30.h>
#include <RootTag31.h>
#include <RootTagMax.h>
#include <RootTagged.h>

#include <stdio.h>
#include <string.h>

/* One generated SET encoding and its independent canonical wire vector. */
typedef struct vector_s {
    const asn_TYPE_descriptor_t *type; /* Generated descriptor. */
    const void *value; /* Borrowed value encoded by the C runtime. */
    enum asn_transfer_syntax syntax; /* DER or CER rule. */
    const unsigned char *wire; /* Expected TLV bytes. */
    size_t length; /* Exact expected TLV size. */
} vector_t;

/*
 * Purpose: compare one generated C encoding with its expected DER/CER bytes.
 * Parameters: item supplies descriptor, value, syntax, vector, and size.
 * Returns zero on exact equality; one on invalid input, encoder error, or mismatch.
 * Errors: failures print a diagnostic and return one.
 * Source: generated C BER/CER encoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged SET root parity. Example: encode tag 3.
 */
static int
check_encoding(const vector_t *item) {
    unsigned char actual[32];
    asn_enc_rval_t encoded;
    if(!item || !item->type || !item->value || !item->wire
       || item->length > sizeof(actual)) return 1;
    encoded = asn_encode_to_buffer(NULL, item->syntax, item->type,
                                   item->value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != item->length
       || memcmp(actual, item->wire, item->length) != 0) {
        fprintf(stderr, "C tagged SET encode mismatch for %s (%d)\n",
                item->type->name, (int)item->syntax);
        return 1;
    }
    return 0;
}

/*
 * Purpose: decode one tagged SET wire value and check complete prefix use.
 * Parameters: descriptor, syntax, wire, length, and expected consumed bytes.
 * Returns zero for a complete decode; one for malformed or partial input.
 * Errors: decoder status or prefix mismatches return one.
 * Source: generated C transfer-syntax decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged SET root probe. Example: CER root decode.
 */
static int
check_decoding(const asn_TYPE_descriptor_t *type, enum asn_transfer_syntax syntax,
               const unsigned char *wire, size_t length, size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!type || !wire || !length) return 1;
    result = asn_decode(NULL, syntax, type, &decoded, wire, length);
    failed = result.code != RC_OK || result.consumed != consumed || !decoded;
    if(failed)
        fprintf(stderr, "C tagged SET decode mismatch for %s (%d): %d, %zu/%zu\n",
                type->name, (int)syntax, (int)result.code, result.consumed, consumed);
    if(decoded) ASN_STRUCT_FREE(*type, decoded);
    return failed;
}

/*
 * Purpose: verify BER decodes reversed SET fields and accepts root aliases.
 * Parameters: none. Returns zero when BER accepts and strict CER rejects aliases.
 * Errors: wrong values, consumption, or CER acceptance return one.
 * Source: X.690 SET order and identifier canonicality. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged SET hostile input. Example: `bf 03` aliases tag 3.
 */
static int
check_ber_order_and_alias(void) {
    static const unsigned char reversed[] = {0xa3, 6, 0x81, 1, 0xff, 0x80, 1, 2};
    static const unsigned char reversed_indefinite[] = {
        0xa3, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 0
    };
    static const unsigned char alias[] = {0xbf, 3, 6, 0x80, 1, 2, 0x81, 1, 0xff};
    static const unsigned char alias_indefinite[] = {
        0xbf, 3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0
    };
    static const unsigned char alias_31[] = {
        0xbf, 0x80, 0x1f, 0x80, 2, 1, 2, 0, 0
    };
    static const unsigned char definite[] = {0xa3, 6, 0x80, 1, 2, 0x81, 1, 0xff};
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed = 0;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_RootTagged, &decoded,
                        reversed, sizeof(reversed));
    failed |= result.code != RC_OK || result.consumed != sizeof(reversed)
        || !decoded || ((RootTagged_t *)decoded)->x != 2
        || !((RootTagged_t *)decoded)->y;
    if(failed) fprintf(stderr, "C BER failed to decode reversed tagged SET fields\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTagged, decoded);
    decoded = NULL;
    failed |= check_decoding(&asn_DEF_RootTagged, ATS_BER,
                             reversed_indefinite, sizeof(reversed_indefinite),
                             sizeof(reversed_indefinite));
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTagged, &decoded,
                        reversed_indefinite, sizeof(reversed_indefinite));
    failed |= result.code == RC_OK;
    if(result.code == RC_OK) fprintf(stderr, "C CER accepted reversed indefinite SET order\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTagged, decoded);
    decoded = NULL;
    failed |= check_decoding(&asn_DEF_RootTagged, ATS_BER,
                             alias, sizeof(alias), sizeof(alias));
    failed |= check_decoding(&asn_DEF_RootTagged, ATS_BER,
                             alias_indefinite, sizeof(alias_indefinite),
                             sizeof(alias_indefinite));
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTagged, &decoded,
                        alias_indefinite, sizeof(alias_indefinite));
    failed |= result.code == RC_OK;
    if(result.code == RC_OK) fprintf(stderr, "C CER accepted indefinite root alias\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTagged, decoded);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTagged, &decoded,
                        alias, sizeof(alias));
    failed |= result.code == RC_OK;
    if(result.code == RC_OK) fprintf(stderr, "C CER accepted tag-3 root alias\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTagged, decoded);
    decoded = NULL;
    failed |= check_decoding(&asn_DEF_RootTag31, ATS_BER,
                             alias_31, sizeof(alias_31), sizeof(alias_31));
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTag31, &decoded,
                        alias_31, sizeof(alias_31));
    failed |= result.code == RC_OK;
    if(result.code == RC_OK) fprintf(stderr, "C CER accepted tag-31 root alias\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTag31, decoded);
    decoded = NULL;
    result = asn_decode(NULL, ATS_CER, &asn_DEF_RootTagged, &decoded,
                        definite, sizeof(definite));
    failed |= result.code == RC_OK;
    if(result.code == RC_OK) fprintf(stderr, "C CER accepted definite SET root\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootTagged, decoded);
    return failed;
}

/*
 * Purpose: run C parity vectors and tagged-root BER/CER decoder probes.
 * Parameters: none. Returns zero when all fixed vectors and decoded forms pass.
 * Errors: any encoder, decoder, field, or alias mismatch returns one.
 * Source: X.690 tagged SET vectors and generated C codecs. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged SET root stage. Example: run test binary.
 */
int
main(void) {
    static const unsigned char root_der[] = {
        0xa3, 6, 0x80, 1, 2, 0x81, 1, 0xff
    };
    static const unsigned char root_cer[] = {
        0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0
    };
    static const unsigned char mixed_der[] = {
        0xa3, 9, 2, 1, 3, 0x80, 1, 2, 0x81, 1, 0xff
    };
    static const unsigned char mixed_cer[] = {
        0xa3, 0x80, 2, 1, 3, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0
    };
    static const unsigned char der_0[] = {0xa0, 3, 2, 1, 2};
    static const unsigned char cer_0[] = {0xa0, 0x80, 2, 1, 2, 0, 0};
    static const unsigned char der_30[] = {0xbe, 3, 2, 1, 2};
    static const unsigned char cer_30[] = {0xbe, 0x80, 2, 1, 2, 0, 0};
    static const unsigned char der_31[] = {0xbf, 0x1f, 3, 2, 1, 2};
    static const unsigned char cer_31[] = {0xbf, 0x1f, 0x80, 2, 1, 2, 0, 0};
    static const unsigned char der_127[] = {0xbf, 0x7f, 3, 2, 1, 2};
    static const unsigned char cer_127[] = {0xbf, 0x7f, 0x80, 2, 1, 2, 0, 0};
    static const unsigned char der_max[] = {
        0xbf, 0x83, 0xff, 0xff, 0xff, 0x7f, 3, 2, 1, 2
    };
    static const unsigned char cer_max[] = {
        0xbf, 0x83, 0xff, 0xff, 0xff, 0x7f, 0x80, 2, 1, 2, 0, 0
    };
    RootTagged_t tagged = {0};
    RootMixed_t mixed = {0};
    RootTag0_t value_0 = {2};
    RootTag30_t value_30 = {2};
    RootTag31_t value_31 = {2};
    RootTag127_t value_127 = {2};
    RootTagMax_t value_max = {2};
    const vector_t vectors[] = {
        {&asn_DEF_RootTagged, &tagged, ATS_DER, root_der, sizeof(root_der)},
        {&asn_DEF_RootTagged, &tagged, ATS_CER, root_cer, sizeof(root_cer)},
        {&asn_DEF_RootMixed, &mixed, ATS_DER, mixed_der, sizeof(mixed_der)},
        {&asn_DEF_RootMixed, &mixed, ATS_CER, mixed_cer, sizeof(mixed_cer)},
        {&asn_DEF_RootTag0, &value_0, ATS_DER, der_0, sizeof(der_0)},
        {&asn_DEF_RootTag0, &value_0, ATS_CER, cer_0, sizeof(cer_0)},
        {&asn_DEF_RootTag30, &value_30, ATS_DER, der_30, sizeof(der_30)},
        {&asn_DEF_RootTag30, &value_30, ATS_CER, cer_30, sizeof(cer_30)},
        {&asn_DEF_RootTag31, &value_31, ATS_DER, der_31, sizeof(der_31)},
        {&asn_DEF_RootTag31, &value_31, ATS_CER, cer_31, sizeof(cer_31)},
        {&asn_DEF_RootTag127, &value_127, ATS_DER, der_127, sizeof(der_127)},
        {&asn_DEF_RootTag127, &value_127, ATS_CER, cer_127, sizeof(cer_127)},
        {&asn_DEF_RootTagMax, &value_max, ATS_DER, der_max, sizeof(der_max)},
        {&asn_DEF_RootTagMax, &value_max, ATS_CER, cer_max, sizeof(cer_max)},
    };
    size_t i;
    int failed = 0;
    tagged.y = 1;
    tagged.x = 2;
    mixed.y = 1;
    mixed.a = 3;
    mixed.x = 2;
    for(i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
        failed |= check_encoding(&vectors[i]);
    failed |= check_decoding(&asn_DEF_RootTagged, ATS_BER,
                             root_der, sizeof(root_der), sizeof(root_der));
    failed |= check_decoding(&asn_DEF_RootTagged, ATS_CER,
                             root_cer, sizeof(root_cer), sizeof(root_cer));
    failed |= check_ber_order_and_alias();
    return failed;
}
