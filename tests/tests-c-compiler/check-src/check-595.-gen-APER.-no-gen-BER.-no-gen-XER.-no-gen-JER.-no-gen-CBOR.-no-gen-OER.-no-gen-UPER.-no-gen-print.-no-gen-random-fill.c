/*
 * Exercise generated non-extensible SET APER support and dependency selection.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <APerSet.h>
#include <CrossClass.h>
#include <aper_decoder.h>
#include <aper_encoder.h>

/*
 * Purpose: run generated SET APER encode, decode, DEFAULT, and truncation checks.
 * Source: Regression coverage for APER-only generated SET skeleton inclusion.
 * Version: 1.0, 2026-10-30.
 * Parameters: none.
 * Returns: zero when all assertions pass.
 * Errors: assertions terminate on an unexpected codec result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-30.
 * Example: check-assembly.sh runs this source with -gen-APER only.
 */
int
main(void) {
    APerSet_t source;
    APerSet_t *decoded = 0;
    uint8_t encoded[8];
    asn_enc_rval_t er;
    asn_dec_rval_t dr;

    memset(&source, 0, sizeof(source));
    source.flag = MALLOC(sizeof(*source.flag));
    assert(source.flag != 0);
    *source.flag = 0;
    source.number = 0x5a;
    er = aper_encode_to_buffer(&asn_DEF_APerSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == 17);
    assert(encoded[0] == 0x80 && encoded[1] == 0x5a && encoded[2] == 0x00);
    dr = aper_decode(0, &asn_DEF_APerSet, (void **)&decoded, encoded,
                     3, 0, 7);
    assert(dr.code == RC_OK);
    assert(decoded->number == source.number);
    assert(decoded->flag && *decoded->flag == 0);
    ASN_STRUCT_FREE(asn_DEF_APerSet, decoded);
    decoded = 0;

    /* The absent flag is DEFAULT TRUE, so the wire preamble remains zero. */
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_APerSet, &source);
    memset(&source, 0, sizeof(source));
    source.number = 9;
    er = aper_encode_to_buffer(&asn_DEF_APerSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == 16);
    assert(encoded[0] == 0x00 && encoded[1] == 0x09);
    dr = aper_decode(0, &asn_DEF_APerSet, (void **)&decoded, encoded, 2, 0, 0);
    assert(dr.code == RC_OK);
    assert(decoded->number == 9);
    assert(decoded->flag && *decoded->flag == 1);
    ASN_STRUCT_FREE(asn_DEF_APerSet, decoded);
    decoded = 0;

    /* Truncation after the aligned INTEGER is reported as needing more data. */
    encoded[0] = 0x80;
    encoded[1] = 0x5a;
    dr = aper_decode(0, &asn_DEF_APerSet, (void **)&decoded, encoded, 2, 0, 0);
    assert(dr.code == RC_WMORE);
    ASN_STRUCT_FREE(asn_DEF_APerSet, decoded);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_APerSet, &source);

    /* UNIVERSAL INTEGER precedes context [0] BOOLEAN in canonical order. */
    {
        CrossClass_t cross = {0};
        CrossClass_t *round_trip = 0;
        cross.context = 1;
        cross.universal = 0x2a;
        er = aper_encode_to_buffer(&asn_DEF_CrossClass, 0, &cross,
                                   encoded, sizeof(encoded));
        assert(er.encoded == 9);
        assert(encoded[0] == 0x2a && encoded[1] == 0x80);
        dr = aper_decode(0, &asn_DEF_CrossClass, (void **)&round_trip,
                         encoded, 2, 0, 7);
        assert(dr.code == RC_OK);
        assert(round_trip->context != 0 && round_trip->universal == 0x2a);
        ASN_STRUCT_FREE(asn_DEF_CrossClass, round_trip);
    }

    /* Sweep every one-byte prefix; the aligned INTEGER is still missing. */
    {
        unsigned candidate;
        for(candidate = 0; candidate < 256; candidate++) {
            uint8_t first = (uint8_t)candidate;
            decoded = 0;
            dr = aper_decode(0, &asn_DEF_APerSet, (void **)&decoded,
                             &first, 1, 0, 0);
            assert(dr.code != RC_OK);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_APerSet, decoded);
        }
    }
    /* Table-selected members need deferred selector resolution in SET order. */
    {
        asn_TYPE_member_t *number = &asn_DEF_APerSet.elements[1];
        int original_flags = number->flags;
        memset(&source, 0, sizeof(source));
        source.number = 9;
        number->flags |= ATF_OPEN_TYPE;
        decoded = 0;
        er = aper_encode_to_buffer(&asn_DEF_APerSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_APerSet, (void **)&decoded,
                         encoded, 2, 0, 0);
        assert(dr.code == RC_FAIL);
        number->flags = original_flags;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_APerSet, decoded);
    }
    return 0;
}
