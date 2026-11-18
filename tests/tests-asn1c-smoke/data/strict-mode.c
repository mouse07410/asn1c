/* Strict-policy golden vectors, malformed-input checks and bounded mutation.
 * Source: X.691 30.6 and repository codec APIs; 2026-11-17.
 * Responsible party: asn1c maintainers. Run through check-strict-mode.sh. */
#include <assert.h>
#include <string.h>
#include "asn_internal.h"
#include "constraints.h"
#include "aper_support.h"
#include "N.h"
#include "Wide.h"
#include "T.h"
#include "Utf.h"
#include "Alias.h"
#include "Ext.h"
#include "Tele.h"
#include "T61.h"
#include "Video.h"
#include "Graphic.h"
#include "General.h"
#include "Object.h"
#include "Octets.h"
#include "Bits.h"
#include "Items.h"
#include "Bag.h"
#include "Bmp.h"
#include "Universal.h"
#include "E.h"
#include "Known.h"
#include "C.h"
#include "Pair.h"
#include "Encoded.h"

#ifdef ASN_STRICT_MODE
#define STRICT_POLICY 1
#else
#define STRICT_POLICY 0
#endif

/* All public format families, including the DER input alias. */
static const enum asn_transfer_syntax formats[] = {
    ATS_DER, ATS_CER, ATS_BASIC_OER, ATS_UNALIGNED_BASIC_PER,
    ATS_ALIGNED_BASIC_PER, ATS_BASIC_XER, ATS_JER, ATS_CBOR
};

/* Purpose: Verify valid values and hostile values at every codec boundary.
 * Source: ASN.1 N/Wide fixture; version/date: 2026-11-17; owner: asn1c maintainers.
 * Inputs/returns: none. Exceptions: assertion failure. History: strict policy.
 * Example: INTEGER 3 is encodable as Wide but violates N in all formats. */
static void
check_boundaries(void) {
    size_t i;
    long valid = 2, invalid = 3;
    unsigned char bytes[256];
    for(i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        asn_enc_rval_t er;
        asn_dec_rval_t dr;
        void *decoded = NULL; /* state variable: decoder-owned output. */
        /* Validate normal round trips through the exact selected syntax. */
        er = asn_encode_to_buffer(NULL, formats[i], &asn_DEF_N, &valid, bytes, sizeof(bytes));
        assert(er.encoded > 0);
        dr = asn_decode(NULL, formats[i], &asn_DEF_N, &decoded, bytes, (size_t)er.encoded);
        assert(dr.code == RC_OK && *(long *)decoded == valid);
        ASN_STRUCT_FREE(asn_DEF_N, decoded);
        decoded = NULL;

        /* Same-width PER ranges give an unused code point for the narrow type. */
        er = asn_encode_to_buffer(NULL, formats[i], &asn_DEF_Wide, &invalid, bytes, sizeof(bytes));
        assert(er.encoded > 0);
        dr = asn_decode(NULL, formats[i], &asn_DEF_N, &decoded, bytes, (size_t)er.encoded);
        if(STRICT_POLICY) assert(dr.code == RC_FAIL);
        ASN_STRUCT_FREE(asn_DEF_N, decoded);

        /* Invalid root values must fail before any byte reaches the caller. */
        memset(bytes, 0xa5, sizeof(bytes));
        er = asn_encode_to_buffer(NULL, formats[i], &asn_DEF_N, &invalid, bytes, sizeof(bytes));
        if(STRICT_POLICY) assert(er.encoded == -1 && bytes[0] == 0xa5);
    }
}

/* Purpose: Exercise direct APIs, preventing bypass through buffer helpers.
 * Source: public C codec APIs; date: 2026-11-17; owner: asn1c maintainers.
 * Inputs/returns: none. Exceptions: assertions. History: strict regression.
 * Example: der_encode_to_buffer must reject an out-of-range native INTEGER. */
static void
check_direct_calls(void) {
    long invalid = 3;
    unsigned char bytes[64];
    asn_enc_rval_t result;
    asn_dec_rval_t decoded;
    void *value = NULL; /* state variable: decoded native integer. */
    result = der_encode_to_buffer(&asn_DEF_N, &invalid, bytes, sizeof(bytes));
    if(STRICT_POLICY) assert(result.encoded == -1);
    result = oer_encode_to_buffer(&asn_DEF_N, NULL, &invalid, bytes, sizeof(bytes));
    if(STRICT_POLICY) assert(result.encoded == -1);
    decoded = ber_decode(NULL, &asn_DEF_N, &value, "\002\001\003", 3);
    if(STRICT_POLICY) assert(decoded.code == RC_FAIL);
    ASN_STRUCT_FREE(asn_DEF_N, value);
}

/* Purpose: Check the reported independent UPER bytes and every NKM root.
 * Source: PR #494 comment and X.691 30.6; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions. History: strict PER policy.
 * Example: strict T.s="ab" is 02 61 62, compatibility T is 09 85 88. */
static void
check_strings(void) {
    const asn_TYPE_descriptor_t *roots[] = {
        &asn_DEF_Utf, &asn_DEF_Alias, &asn_DEF_Ext, &asn_DEF_Tele,
        &asn_DEF_T61, &asn_DEF_Video, &asn_DEF_Graphic, &asn_DEF_General, &asn_DEF_Object
    };
    const unsigned char strict[] = {2, 'a', 'b'};
    const unsigned char compatible[] = {0x09, 0x85, 0x88};
    unsigned char bytes[64];
    T_t record;
    OCTET_STRING_t text;
    asn_enc_rval_t er;
    size_t i;
    memset(&record, 0, sizeof(record));
    memset(&text, 0, sizeof(text));
    assert(OCTET_STRING_fromBuf(&record.s, "ab", 2) == 0);
    assert(OCTET_STRING_fromBuf(&text, "ab", 2) == 0);
    er = uper_encode_to_buffer(&asn_DEF_T, NULL, &record, bytes, sizeof(bytes));
    assert(er.encoded == (STRICT_POLICY ? 24 : 22));
    assert(memcmp(bytes, STRICT_POLICY ? strict : compatible, 3) == 0);

    /* NKM includes aliases and extensible SIZE, for both PER alignments. */
    if(STRICT_POLICY) {
        for(i = 0; i < sizeof(roots) / sizeof(roots[0]); ++i) {
            er = uper_encode_to_buffer(roots[i], NULL, &text, bytes, sizeof(bytes));
            assert(er.encoded == 24 && memcmp(bytes, strict, 3) == 0);
            er = aper_encode_to_buffer(roots[i], NULL, &text, bytes, sizeof(bytes));
            assert(er.encoded == 24 && memcmp(bytes, strict, 3) == 0);
        }
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_T, &record);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Octets, &text);
}

/* Purpose: Preserve BER flexibility and streaming while checking strict DER.
 * Source: X.690 BOOLEAN/INTEGER and X.691 filler; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions. History: policy distinctions.
 * Example: redundant INTEGER sign octets are accepted as BER, rejected as DER. */
static void
check_framing(void) {
    const unsigned char ber[] = {2, 2, 0, 1};
    const unsigned char padded[] = {0x41}; /* N=1 followed by nonzero filler. */
    const unsigned char der[] = {2, 1, 1};
    size_t split;
    void *value = NULL; /* state variable: resumable decode storage. */
    asn_dec_rval_t result;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_N, &value, ber, sizeof(ber));
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_N, value);
    value = NULL;
    result = asn_decode(NULL, ATS_DER, &asn_DEF_N, &value, ber, sizeof(ber));
    if(STRICT_POLICY) assert(result.code == RC_FAIL);
    ASN_STRUCT_FREE(asn_DEF_N, value);
    value = NULL;
    result = uper_decode_complete(NULL, &asn_DEF_N, &value, padded, sizeof(padded));
    assert(result.code == (STRICT_POLICY ? RC_FAIL : RC_OK));
    ASN_STRUCT_FREE(asn_DEF_N, value);
    value = NULL;
    result = aper_decode_complete(NULL, &asn_DEF_N, &value, padded, sizeof(padded));
    assert(result.code == (STRICT_POLICY ? RC_FAIL : RC_OK));
    ASN_STRUCT_FREE(asn_DEF_N, value);
    value = NULL;

    if(STRICT_POLICY) {
        /* Strict DER retries use the complete PDU after one-shot RC_WMORE. */
        for(split = 0; split < sizeof(der); ++split) {
            result = asn_decode(NULL, ATS_DER, &asn_DEF_N, &value, der, split);
            assert(result.code == RC_WMORE && result.consumed == 0 && value == NULL);
            result = asn_decode(NULL, ATS_DER, &asn_DEF_N, &value, der, sizeof(der));
            assert(result.code == RC_OK);
            ASN_STRUCT_FREE(asn_DEF_N, value);
            value = NULL;
        }
    }

    /* A constraint must never be evaluated on a partial streaming object. */
    result = ber_decode(NULL, &asn_DEF_N, &value, der, 2);
    assert(result.code == RC_WMORE);
    split = result.consumed;
    result = ber_decode(NULL, &asn_DEF_N, &value, der + split, sizeof(der) - split);
    assert(result.code == RC_OK && *(long *)value == 1);
    ASN_STRUCT_FREE(asn_DEF_N, value);
}

/* Purpose: Reject nonstandard XER value notation and meta-syntax wrappers.
 * Source: X.693/repository compatibility branches; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions. History: strict XER regression.
 * Example: <Octets>H'6162'</Octets> is a compatibility extension. */
static void
check_xer(void) {
    const char *quoted = "<Octets>H'6162'</Octets>";
    const char *normal = "<Octets>6162</Octets>";
    void *value = NULL; /* state variable: decoded octets. */
    asn_dec_rval_t result = xer_decode(NULL, &asn_DEF_Octets, &value, normal, strlen(normal));
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_Octets, value);
    value = NULL;
    result = xer_decode(NULL, &asn_DEF_Octets, &value, quoted, strlen(quoted));
    assert(result.code == (STRICT_POLICY ? RC_FAIL : RC_OK));
    ASN_STRUCT_FREE(asn_DEF_Octets, value);
    value = NULL;
    quoted = "<Octets>YWI=</Octets>";
    result = xer_decode(NULL, &asn_DEF_Octets, &value, quoted, strlen(quoted));
    assert(result.code == (STRICT_POLICY ? RC_FAIL : RC_OK));
    ASN_STRUCT_FREE(asn_DEF_Octets, value);
    value = NULL;
    quoted = "<Encoded>YWI=</Encoded>";
    result = xer_decode(NULL, &asn_DEF_Encoded, &value, quoted, strlen(quoted));
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_Encoded, value);
    value = NULL;
    quoted = "<Bits>1010</Bits>";
    result = xer_decode(NULL, &asn_DEF_Bits, &value, quoted, strlen(quoted));
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_Bits, value);
    value = NULL;
    quoted = "<Bits>H'A'</Bits>";
    result = xer_decode(NULL, &asn_DEF_Bits, &value, quoted, strlen(quoted));
    assert(result.code == (STRICT_POLICY ? RC_FAIL : RC_OK));
    ASN_STRUCT_FREE(asn_DEF_Bits, value);
}

/* Purpose: Check standard wrappers and fragmented XER collection parsing.
 * Source: X.693 collection grammar; date: 2026-11-17; owner: asn1c maintainers.
 * Inputs/returns: none; exceptions: assertions. History: strict wrapper checks.
 * Example: debug wrappers and unrelated closing tags fail strict decoding. */
static void
check_collections(void) {
    const asn_TYPE_descriptor_t *types[] = {&asn_DEF_Items, &asn_DEF_Bag};
    const char *valid[] = {"<Items><INTEGER>1</INTEGER></Items>", "<Bag><INTEGER>1</INTEGER></Bag>"};
    const char *bad[] = {"<Items><SEQUENCE-OF><INTEGER>1</INTEGER></SEQUENCE-OF></Items>",
                         "<Bag><SET-OF><INTEGER>1</INTEGER></SET-OF></Bag>",
                         "<Items><INTEGER>1</INTEGER></wrong>", "<Items>garbage</Items>"};
    size_t i, split;
    for(i = 0; i < 2; ++i) {
        for(split = 0; split < strlen(valid[i]); ++split) {
            void *value = NULL; /* state variable: resumable collection storage. */
            asn_dec_rval_t dr = xer_decode(NULL, types[i], &value, valid[i], split);
            if(dr.code == RC_WMORE) {
                size_t used = dr.consumed;
                dr = xer_decode(NULL, types[i], &value, valid[i] + used, strlen(valid[i]) - used);
            }
            assert(dr.code == RC_OK);
            ASN_STRUCT_FREE(*types[i], value);
        }
    }
    if(STRICT_POLICY) {
        for(i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
            void *value = NULL; /* state variable: malformed collection storage. */
            const asn_TYPE_descriptor_t *td = i == 1 ? types[1] : types[0];
            asn_dec_rval_t dr = xer_decode(NULL, td, &value, bad[i], strlen(bad[i]));
            assert(dr.code != RC_OK);
            ASN_STRUCT_FREE(*td, value);
        }
    }
}

/* Purpose: Preserve standards-defined unknown enum/choice extension handling.
 * Source: X.691/X.696 extensibility; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions. History: boundary validation.
 * Example: extension ENUMERATED index zero survives strict root validation. */
static void
check_extensions(void) {
    const unsigned char unknown_enum[] = {0x80};
    const unsigned char unknown_choice[] = {0x80, 0x01, 0x00};
    void *value = NULL; /* state variable: decoded extension marker storage. */
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;
    unsigned char relay[8];
    result = uper_decode_complete(NULL, &asn_DEF_E, &value, unknown_enum, sizeof(unknown_enum));
    assert(result.code == RC_OK);
    encoded = uper_encode_to_buffer(&asn_DEF_E, NULL, value, relay, sizeof(relay));
    assert(encoded.encoded == 8 && relay[0] == unknown_enum[0]);
    encoded = asn_encode_to_buffer(NULL, ATS_UNALIGNED_CANONICAL_PER,
                                   &asn_DEF_E, value, relay, sizeof(relay));
    assert(encoded.encoded == 1 && relay[0] == unknown_enum[0]);
    encoded = asn_encode_to_buffer(NULL, ATS_ALIGNED_CANONICAL_PER,
                                   &asn_DEF_E, value, relay, sizeof(relay));
    assert(encoded.encoded == 1 && relay[0] == unknown_enum[0]);
    ASN_STRUCT_FREE(asn_DEF_E, value);
    value = NULL;
    result = aper_decode_complete(NULL, &asn_DEF_E, &value, unknown_enum, sizeof(unknown_enum));
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_E, value);
    value = NULL;
    result = uper_decode_complete(NULL, &asn_DEF_C, &value, unknown_choice, sizeof(unknown_choice));
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_C, value);
    value = NULL;
    result = uper_decode_complete(NULL, &asn_DEF_Pair, &value, "\200\200\001\000", 4);
    assert(result.code == RC_OK);
    ASN_STRUCT_FREE(asn_DEF_Pair, value);
#if LONG_MAX > 2147483647L
    if(STRICT_POLICY) {
        /* Never narrow native storage to a C enum before membership checking. */
        long invalid = (long)1 << 32;
        assert(asn_check_constraints(&asn_DEF_E, &invalid, NULL, NULL) == -1);
    }
#endif
}

/* Purpose: Keep unknown enum markers distinct from locally known additions.
 * Source: X.691 extension ordinal mapping; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions. History: strict marker identity.
 * Example: marker ordinal zero cannot stand in for known extension three(2). */
static void
check_known_extensions(void) {
    unsigned char bytes[16];
    long forged = LONG_MAX;
    long unknown = LONG_MAX - 1;
    long known = 2;
    void *decoded = NULL; /* state variable: enum round-trip output. */
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    er = uper_encode_to_buffer(&asn_DEF_Known, NULL, &forged, bytes, sizeof(bytes));
    if(STRICT_POLICY) assert(er.encoded == -1);
    er = aper_encode_to_buffer(&asn_DEF_Known, NULL, &forged, bytes, sizeof(bytes));
    if(STRICT_POLICY) {
        char error[128] = {0};
        size_t length = sizeof(error);
        assert(er.encoded == -1);
        assert(asn_check_constraints_with_syntax(&asn_DEF_Known, &forged,
                   ATS_UNALIGNED_BASIC_PER, error, &length) == -1);
        assert(length > 0 && error[0] != 0);
    }

    /* Known additions use their real value, and later unknown ordinals relay. */
    er = uper_encode_to_buffer(&asn_DEF_Known, NULL, &known, bytes, sizeof(bytes));
    assert(er.encoded == 8 && bytes[0] == 0x80);
    dr = uper_decode_complete(NULL, &asn_DEF_Known, &decoded, bytes, 1);
    assert(dr.code == RC_OK && *(long *)decoded == known);
    ASN_STRUCT_FREE(asn_DEF_Known, decoded);
    decoded = NULL;
    er = uper_encode_to_buffer(&asn_DEF_Known, NULL, &unknown, bytes, sizeof(bytes));
    assert(er.encoded == 8 && bytes[0] == 0x81);
    dr = uper_decode_complete(NULL, &asn_DEF_Known, &decoded, bytes, 1);
    assert(dr.code == RC_OK && *(long *)decoded == unknown);
    ASN_STRUCT_FREE(asn_DEF_Known, decoded);
}

/* Purpose: Reject invalid Unicode and malformed fixed-width content before SIZE.
 * Source: ISO/IEC 10646 representation; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions. History: base/subtype checks.
 * Example: one byte is not a BMPString despite a truncated character count of 0. */
static void
check_repertoire(void) {
    const asn_TYPE_descriptor_t *types[] = {
        &asn_DEF_Utf, &asn_DEF_Utf, &asn_DEF_Utf, &asn_DEF_Bmp,
        &asn_DEF_Bmp, &asn_DEF_Universal, &asn_DEF_Universal, &asn_DEF_Universal
    };
    const char *bad[] = {
        "\355\240\200", "\364\220\200\200", "\370\210\200\200\200", "A",
        "\330\000", "ABC", "\000\021\000\000", "\000\000\330\000"
    };
    const int lengths[] = {3, 4, 5, 1, 2, 3, 4, 4};
    unsigned char bytes[64];
    size_t i;
    for(i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        OCTET_STRING_t text;
        asn_enc_rval_t er;
        memset(&text, 0, sizeof(text));
        assert(OCTET_STRING_fromBuf(&text, bad[i], lengths[i]) == 0);
        er = der_encode_to_buffer(types[i], &text, bytes, sizeof(bytes));
        if(STRICT_POLICY) assert(er.encoded == -1);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Octets, &text);
    }
}

/* Purpose: Verify zero APER alignment filler and truncation handling.
 * Source: X.691 octet alignment; date: 2026-11-17; owner: asn1c maintainers.
 * Inputs/returns: none. Exceptions: assertions. History: strict alignment.
 * Example: seven nonzero padding bits fail strict mode before aligned content. */
static void
check_alignment(void) {
    unsigned char byte = 1;
    asn_per_data_t cursor; /* state variable: bounded alignment test cursor. */
    memset(&cursor, 0, sizeof(cursor));
    cursor.buffer = &byte;
    cursor.nboff = 1;
    cursor.nbits = 8;
    assert(aper_get_align(&cursor) == (STRICT_POLICY ? -1 : 1));
    cursor.nboff = 1;
    cursor.nbits = 1;
    assert(aper_get_align(&cursor) == -1);
    byte = 0;
    cursor.nboff = 1;
    cursor.nbits = 8;
    assert(aper_get_align(&cursor) == 0);
}

/* Purpose: Reject malformed raw PER arguments before pointer/size operations.
 * Source: public UPER/APER contracts; date: 2026-11-17; owner: asn1c maintainers.
 * Inputs/returns: none. Exceptions: assertions. History: input hardening checks.
 * Example: oversized byte counts never reach the bit-count multiplication. */
static void
check_decoder_arguments(void) {
    typedef asn_dec_rval_t (*decoder_f)(const asn_codec_ctx_t *,
        const asn_TYPE_descriptor_t *, void **, const void *, size_t, int, int);
    decoder_f decoders[] = {uper_decode, aper_decode};
    unsigned char bytes[1] = {0};
    void *value = NULL; /* state variable: guard tests must not allocate output. */
    size_t i;
    for(i = 0; i < sizeof(decoders) / sizeof(decoders[0]); ++i) {
        assert(decoders[i](NULL, NULL, &value, bytes, 1, 0, 0).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, NULL, bytes, 1, 0, 0).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, NULL, 1, 0, 0).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, bytes, SIZE_MAX / 8 + 1, 0, 0).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, bytes, 1, -1, 0).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, bytes, 1, 8, 0).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, bytes, 1, 0, -1).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, bytes, 1, 0, 8).code == RC_FAIL);
        assert(decoders[i](NULL, &asn_DEF_N, &value, bytes, 0, 0, 1).code == RC_FAIL);
        assert(value == NULL);
    }
}

/* Purpose: Deterministically mutate small inputs across every format family.
 * Source: strict boundary fuzz regression; date: 2026-11-17; owner: asn1c.
 * Inputs/returns: none. Exceptions: assertions/sanitizer findings.
 * History: bounded hostile-input smoke coverage. Example: all one-octet PDUs. */
static void
check_mutations(void) {
    size_t i;
    unsigned mutation;
    for(i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        for(mutation = 0; mutation < 256; ++mutation) {
            unsigned char bytes[] = {(unsigned char)mutation, 1, 3};
            void *value = NULL; /* state variable: mutation-owned output. */
            asn_dec_rval_t result = asn_decode(NULL, formats[i], &asn_DEF_N, &value, bytes, sizeof(bytes));
            if(STRICT_POLICY && result.code == RC_OK) assert(*(long *)value >= 0 && *(long *)value <= 2);
            ASN_STRUCT_FREE(asn_DEF_N, value);
        }
    }
}

/* Purpose: Run strict and compatibility regressions. Source: local smoke tests.
 * Version/date: 2026-11-17; owner: asn1c maintainers. Inputs: none; return: zero.
 * Exceptions: assertion/sanitizer failures. History: strict flag. Example: ./policy-test. */
int
main(void) {
    check_boundaries();
    check_direct_calls();
    check_strings();
    check_framing();
    check_xer();
    check_collections();
    check_extensions();
    check_known_extensions();
    check_repertoire();
    check_alignment();
    check_decoder_arguments();
    check_mutations();
    return 0;
}
