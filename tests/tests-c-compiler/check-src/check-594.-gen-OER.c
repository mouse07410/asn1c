/*
 * Verify OER canonical tag ordering, preamble bits, and streaming SET decode.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <OerSet.h>
#include <ChoiceSet.h>
#include <ExtensibleSet.h>

/*
 * Purpose: exercise non-extensible SET OER encode/decode and error cases.
 * Original source: New regression coverage for OER SET support.
 * Version/date: 1.0, 2026-10-30.
 * Parameters: none.
 * Returns: zero when all assertions pass.
 * Errors: assertions terminate the test on an unexpected codec result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-30.
 * Example: run through tests-c-compiler/check-assembly.sh.
 */
int
main(void) {
    OerSet_t source;
    OerSet_t *decoded = 0;
    ChoiceSet_t choice_source;
    ChoiceSet_t *choice_decoded = 0;
    ExtensibleSet_t extensible;
    ExtensibleSet_t *extensible_decoded = 0;
    uint8_t encoded[64];
    size_t encoded_size;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    size_t offset;
    long *expected_default;

    memset(&source, 0, sizeof(source));
    source.first = 5;
    source.later = (long *)calloc(1, sizeof(*source.later));
    assert(source.later);
    *source.later = 9;

    /* Tag order is first [0], defaulted [1], later [2]. */
    er = oer_encode_to_buffer(&asn_DEF_OerSet, 0, &source, encoded,
                              sizeof(encoded));
    assert(er.encoded == 3);
    encoded_size = (size_t)er.encoded;
    assert(encoded[0] == 0x40); /* default absent, later present */
    assert(encoded[1] == 5);
    assert(encoded[2] == 9);

    /* Feed one byte at a time to cover saved preamble and member state. */
    for(offset = 0; offset < encoded_size; offset++) {
        dr = asn_DEF_OerSet.op->oer_decoder(
            0, &asn_DEF_OerSet, 0, (void **)&decoded, encoded + offset, 1);
        if(offset + 1 < encoded_size) assert(dr.code == RC_WMORE);
        assert(dr.consumed <= 1);
    }
    assert(dr.code == RC_OK);
    assert(decoded->first == source.first);
    assert(decoded->later && *decoded->later == *source.later);
    expected_default = decoded->defaulted;
    assert(expected_default && *expected_default == 7);
    ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
    decoded = 0;

    /* An incomplete final INTEGER remains resumable and reports starvation. */
    dr = asn_DEF_OerSet.op->oer_decoder(
        0, &asn_DEF_OerSet, 0, (void **)&decoded, encoded, encoded_size - 1);
    assert(dr.code == RC_WMORE);
    ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
    decoded = 0;

    /* Nonzero unused preamble bits are malformed canonical OER. */
    encoded[0] |= 0x01;
    dr = asn_DEF_OerSet.op->oer_decoder(
        0, &asn_DEF_OerSet, 0, (void **)&decoded, encoded, encoded_size);
    assert(dr.code == RC_FAIL);
    assert(decoded != 0);
    ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
    decoded = 0;
    encoded[0] &= (uint8_t)~0x01;

    /* An absent DEFAULT is materialized even when its optional bit is zero. */
    encoded[0] = 0x00;
    dr = asn_DEF_OerSet.op->oer_decoder(
        0, &asn_DEF_OerSet, 0, (void **)&decoded, encoded, 2);
    assert(dr.code == RC_OK);
    assert(decoded->first == source.first);
    assert(decoded->defaulted && *decoded->defaulted == 7);
    assert(decoded->later == 0);
    ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
    decoded = 0;

    /* An untagged CHOICE is ordered by its lowest possible canonical tag. */
    memset(&choice_source, 0, sizeof(choice_source));
    choice_source.high = 9;
    choice_source.low = 1;
    choice_source.picked = (Pick_t *)calloc(1, sizeof(*choice_source.picked));
    assert(choice_source.picked);
    choice_source.picked->present = Pick_PR_pickHigh;
    choice_source.picked->choice.pickHigh = 7;
    er = oer_encode_to_buffer(&asn_DEF_ChoiceSet, 0, &choice_source, encoded,
                              sizeof(encoded));
    assert(er.encoded == 4);
    assert(encoded[0] == 0xff); /* low [0]: canonical OER TRUE */
    assert(encoded[1] == 0x83 && encoded[2] == 7); /* selected tag [3] */
    assert(encoded[3] == 9); /* high [2] */
    dr = asn_DEF_ChoiceSet.op->oer_decoder(
        0, &asn_DEF_ChoiceSet, 0, (void **)&choice_decoded, encoded,
        (size_t)er.encoded);
    assert(dr.code == RC_OK && dr.consumed == (size_t)er.encoded);
    assert(choice_decoded->low != 0 && choice_decoded->high == 9);
    assert(choice_decoded->picked
           && choice_decoded->picked->present == Pick_PR_pickHigh
           && choice_decoded->picked->choice.pickHigh == 7);
    ASN_STRUCT_FREE(asn_DEF_ChoiceSet, choice_decoded);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ChoiceSet, &choice_source);
    choice_decoded = 0;

    /* A truncated inline long in malformed metadata must fail before I/O. */
    {
        asn_SET_specifics_t *specs = (asn_SET_specifics_t *)asn_DEF_OerSet.specifics;
        asn_TYPE_member_t *first = &asn_DEF_OerSet.elements[2];
        size_t original_offset = first->memb_offset;
        first->memb_offset = specs->struct_size - 1;
        er = oer_encode_to_buffer(&asn_DEF_OerSet, 0, &source,
                                  encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = asn_DEF_OerSet.op->oer_decoder(
            0, &asn_DEF_OerSet, 0, (void **)&decoded, encoded, encoded_size);
        assert(dr.code == RC_FAIL);
        first->memb_offset = original_offset;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
        decoded = 0;
    }

    /* An OPEN TYPE without its table selector is malformed. */
    {
        asn_TYPE_member_t *first = &asn_DEF_OerSet.elements[2];
        int original_flags = first->flags;
        first->flags |= ATF_OPEN_TYPE;
        er = oer_encode_to_buffer(&asn_DEF_OerSet, 0, &source,
                                  encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = asn_DEF_OerSet.op->oer_decoder(
            0, &asn_DEF_OerSet, 0, (void **)&decoded, encoded, encoded_size);
        assert(dr.code == RC_FAIL);
        first->flags = original_flags;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
        decoded = 0;
    }

    /* Extensible SET without additions round-trips through v2 metadata. */
    memset(&extensible, 0, sizeof(extensible));
    extensible.first = 1;
    er = oer_encode_to_buffer(&asn_DEF_ExtensibleSet, 0, &extensible,
                              encoded, sizeof(encoded));
    assert(er.encoded > 0);
    dr = asn_DEF_ExtensibleSet.op->oer_decoder(
        0, &asn_DEF_ExtensibleSet, 0, (void **)&extensible_decoded, encoded, (size_t)er.encoded);
    assert(dr.code == RC_OK && extensible_decoded->first == 1);
    ASN_STRUCT_FREE(asn_DEF_ExtensibleSet, extensible_decoded);

    /* Exhaust every one-octet preamble as a bounded malformed-input sweep. */
    for(offset = 0; offset < 256; offset++) {
        uint8_t candidate = (uint8_t)offset;
        dr = asn_DEF_OerSet.op->oer_decoder(
            0, &asn_DEF_OerSet, 0, (void **)&decoded, &candidate, 1);
        assert(dr.code != RC_OK);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OerSet, decoded);
        decoded = 0;
    }

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OerSet, &source);
    return 0;
}
