/* Regression coverage for OER SET extension additions and streaming. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <OerIndividualSet.h>
#include <ExtChoiceSet.h>

/* X.696 16.2, 16.4, 16.5 and 18: root tag order, then addition order. */
static const uint8_t golden[] = {0xe0, 0xff, 0x06, 0x09, 0x02, 0x05, 0xc0, 0x01, 0xff, 0x01, 0x05};
static const uint8_t unknown[] = {0xe0, 0xff, 0x06, 0x09, 0x02, 0x04, 0x10, 0x02, 0xa5, 0x5a};

/*
 * Purpose: decode a vector at every input split, preserving unconsumed bytes.
 * Source: X.696 16.4/16.5 and the OER streaming decoder contract.
 * Version/date: 1.0, 2026-10-30. Inputs: bytes, length, known-addition flag.
 * Returns: nothing. Errors: assertions detect unexpected decoder results.
 * Author: asn1c maintainers. History: added for SET OER additions.
 * Example: check_splits(golden, sizeof(golden), 1).
 */
static void
check_splits(const uint8_t *bytes, size_t length, int known) {
    size_t split;
    for(split = 0; split <= length; split++) {
        OerIndividualSet_t *decoded = 0;
        asn_dec_rval_t result;
        size_t used;
        result = asn_DEF_OerIndividualSet.op->oer_decoder(
            0, &asn_DEF_OerIndividualSet, 0, (void **)&decoded, bytes, split);
        assert(result.consumed <= split);
        used = result.consumed;
        if(split < length) {
            assert(result.code == RC_WMORE);
            result = asn_DEF_OerIndividualSet.op->oer_decoder(
                0, &asn_DEF_OerIndividualSet, 0, (void **)&decoded, bytes + used, length - used);
        }
        assert(result.code == RC_OK);
        assert(decoded->rootHigh == 9 && decoded->rootLow && *decoded->rootLow);
        assert(decoded->trailingRoot && *decoded->trailingRoot == 6);
        assert(decoded->addedDefault && *decoded->addedDefault == 3);
        if(known) {
            assert(decoded->addedFlag && *decoded->addedFlag);
            assert(decoded->addedValue && *decoded->addedValue == 5);
        } else {
            assert(!decoded->addedFlag && !decoded->addedValue);
        }
        ASN_STRUCT_FREE(asn_DEF_OerIndividualSet, decoded);
    }
}

/*
 * Purpose: exercise malformed wire values and reject unsafe descriptor metadata.
 * Source: X.696 16.2/16.4 and generated v2 SET descriptor.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Errors: assertions detect unexpected codec results.
 * Author: asn1c maintainers. History: added for malformed SET OER coverage.
 * Example: check_invalid() runs after the golden-vector checks.
 */
static void
check_invalid(void) {
    OerIndividualSet_t *decoded = 0;
    asn_SET_specifics_t *specs = (asn_SET_specifics_t *)asn_DEF_OerIndividualSet.specifics;
    asn_TYPE_member_t *member = &asn_DEF_OerIndividualSet.elements[3];
    const unsigned *saved_map = specs->root_map;
    static const unsigned duplicate[] = {0, 1, 1};
    uint8_t bad[sizeof(golden)];
    asn_dec_rval_t result;
    int saved_flags = member->flags;
    int saved_extensible = specs->extensible;
    size_t i;

    /* Reject nonzero preamble padding, invalid bitmap count and padding. */
    for(i = 0; i < 3; i++) {
        memcpy(bad, golden, sizeof(bad));
        if(i == 0) bad[0] |= 1;
        if(i == 1) bad[5] = 8;
        if(i == 2) bad[6] |= 1;
        result = asn_DEF_OerIndividualSet.op->oer_decoder(
            0, &asn_DEF_OerIndividualSet, 0, (void **)&decoded, bad, sizeof(bad));
        assert(result.code == RC_FAIL);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OerIndividualSet, decoded);
        decoded = 0;
    }
    /* A complete open type must not contain trailing undecoded octets. */
    {
        static const uint8_t trailing[] = {
            0xe0, 0xff, 0x06, 0x09, 0x02, 0x05, 0xc0, 0x02, 0xff, 0x00, 0x01, 0x05
        };
        result = asn_DEF_OerIndividualSet.op->oer_decoder(
            0, &asn_DEF_OerIndividualSet, 0, (void **)&decoded, trailing, sizeof(trailing));
        assert(result.code == RC_FAIL);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OerIndividualSet, decoded);
        decoded = 0;
    }
    /* Reject legacy extension metadata, duplicate map entries and groups. */
    for(i = 0; i < 3; i++) {
        if(i == 0) specs->extensible = 1;
        if(i == 1) specs->root_map = duplicate;
        if(i == 2) member->flags |= ATF_EXTENSION_GROUP;
        result = asn_DEF_OerIndividualSet.op->oer_decoder(
            0, &asn_DEF_OerIndividualSet, 0, (void **)&decoded, golden, sizeof(golden));
        assert(result.code == RC_FAIL);
        specs->extensible = saved_extensible;
        specs->root_map = saved_map;
        member->flags = saved_flags;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_OerIndividualSet, decoded);
        decoded = 0;
    }
}

/*
 * Purpose: verify independent OER vector, defaults, unknowns and streaming.
 * Source: X.696 16 and 18; generated 599 schema.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: zero on success.
 * Errors: assertions detect unexpected codec results.
 * Author: asn1c maintainers. History: added for individual SET additions.
 * Example: invoked by the generated C compiler test harness.
 */
int
main(void) {
    OerIndividualSet_t source;
    uint8_t encoded[32];
    asn_enc_rval_t result;
    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.rootLow = calloc(1, sizeof(*source.rootLow));
    source.trailingRoot = calloc(1, sizeof(*source.trailingRoot));
    source.addedFlag = calloc(1, sizeof(*source.addedFlag));
    source.addedValue = calloc(1, sizeof(*source.addedValue));
    assert(source.rootLow && source.trailingRoot && source.addedFlag && source.addedValue);
    *source.rootLow = 1;
    *source.trailingRoot = 6;
    *source.addedFlag = 1;
    *source.addedValue = 5;
    result = oer_encode_to_buffer(&asn_DEF_OerIndividualSet, 0, &source, encoded, sizeof(encoded));
    assert(result.encoded == (ssize_t)sizeof(golden));
    assert(memcmp(encoded, golden, sizeof(golden)) == 0);
    /* An explicitly present DEFAULT produces the same canonical encoding. */
    source.addedDefault = calloc(1, sizeof(*source.addedDefault));
    assert(source.addedDefault);
    *source.addedDefault = 3;
    result = oer_encode_to_buffer(&asn_DEF_OerIndividualSet, 0, &source, encoded, sizeof(encoded));
    assert(result.encoded == (ssize_t)sizeof(golden));
    assert(memcmp(encoded, golden, sizeof(golden)) == 0);
    /* Reject an extension group and malformed map on the encoding path too. */
    {
        asn_SET_specifics_t *specs = (asn_SET_specifics_t *)asn_DEF_OerIndividualSet.specifics;
        asn_TYPE_member_t *member = &asn_DEF_OerIndividualSet.elements[3];
        const unsigned *saved_map = specs->root_map;
        static const unsigned duplicate[] = {0, 1, 1};
        int saved_flags = member->flags;
        member->flags |= ATF_EXTENSION_GROUP;
        result = oer_encode_to_buffer(&asn_DEF_OerIndividualSet, 0, &source, encoded, sizeof(encoded));
        assert(result.encoded == -1);
        member->flags = saved_flags;
        specs->root_map = duplicate;
        result = oer_encode_to_buffer(&asn_DEF_OerIndividualSet, 0, &source, encoded, sizeof(encoded));
        assert(result.encoded == -1);
        specs->root_map = saved_map;
    }
    /* CHOICE extension tag [1] cannot sort before the enclosing root [2]. */
    {
        ExtChoiceSet_t choice;
        static const uint8_t expected[] = {0x07, 0x83, 0xff};
        memset(&choice, 0, sizeof(choice));
        choice.n = 7;
        choice.c = calloc(1, sizeof(*choice.c));
        assert(choice.c);
        choice.c->present = ExtChoice_PR_root;
        choice.c->choice.root = 1;
        result = oer_encode_to_buffer(&asn_DEF_ExtChoiceSet, 0, &choice, encoded, sizeof(encoded));
        assert(result.encoded == (ssize_t)sizeof(expected));
        assert(memcmp(encoded, expected, sizeof(expected)) == 0);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ExtChoiceSet, &choice);
    }
    check_splits(golden, sizeof(golden), 1);
    check_splits(unknown, sizeof(unknown), 0);
    check_invalid();
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OerIndividualSet, &source);
    return 0;
}
