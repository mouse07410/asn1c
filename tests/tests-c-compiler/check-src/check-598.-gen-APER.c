/* Exercise APER encoding of individual SET extension additions. */
#undef NDEBUG
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <AperIndividualSet.h>
#include <Choice.h>
#include <ChoiceSet.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <aper_opentype.h>
#include <aper_support.h>

/*
 * Purpose: append one APER unknown extension map and its open-type payloads.
 * Source: X.691 normally-small bitmap length and aligned open-type rules.
 * Version/date: 1.0, 2026-10-30.
 * Inputs: buffer/capacity bound output; root_bits marks the root boundary;
 *         bitmap/bitmap_bits select entries; arrays provide open-type payloads.
 * Returns: zero on success, -1 on invalid test arguments or helper failure.
 * Errors: output overflow or invalid APER determinants return -1.
 * Author: asn1c maintainers. History: Added for unknown-addition coverage.
 * Example: bitmap=1 and bitmap_bits=4 selects unknown addition index 3.
 */
static int
append_unknown_addition(uint8_t *buffer, size_t capacity, size_t root_bits,
                        unsigned bitmap, unsigned bitmap_bits,
                        const uint8_t *const *payloads,
                        const size_t *payload_sizes, size_t payload_count,
                        size_t *total_bits) {
    asn_per_outp_t output;
    size_t i;

    if(!buffer || (payload_count && (!payloads || !payload_sizes))
    || payload_count > bitmap_bits || !total_bits
    || !bitmap_bits || bitmap_bits > 31 || capacity > SIZE_MAX / 8) return -1;
    buffer[0] |= 0x80;
    memset(&output, 0, sizeof(output));
    output.buffer = buffer;
    output.nboff = root_bits;
    output.nbits = capacity * 8;
    if(aper_put_nslength(&output, bitmap_bits)
    || per_put_few_bits(&output, bitmap, (int)bitmap_bits)) return -1;
    if(aper_put_align(&output) < 0) return -1;
    for(i = 0; i < payload_count; i++) {
        ssize_t encoded_size;
        int need_eom = 0;
        if(!payloads[i] || !payload_sizes[i]
        || payload_sizes[i] > (size_t)INT_MAX / 8) return -1;
        encoded_size = aper_put_length(&output, -1, -1, payload_sizes[i],
                                       &need_eom);
        if(encoded_size != (ssize_t)payload_sizes[i] || need_eom) return -1;
        if(per_put_many_bits(&output, payloads[i],
                             (int)(payload_sizes[i] * 8))) return -1;
    }
    *total_bits = (size_t)(output.buffer - buffer) * 8 + output.nboff;
    return 0;
}

/*
 * Purpose: check canonical APER order for an untagged CHOICE SET member.
 * Source: X.691 SET component order and a multi-tag canonical map.
 * Version/date: 1.0, 2026-10-30.
 * Inputs: none; the descriptor has two tags for its single CHOICE component.
 * Returns: zero when encode/decode and malformed-map checks pass.
 * Errors: assertions stop execution on an unexpected codec result.
 * Author: asn1c maintainers. History: Added for APER legacy-map coverage.
 * Example: repeated CHOICE tags are accepted; repeated integer tags fail.
 */
static int
check_untagged_choice_order(void) {
    ChoiceSet_t source;
    ChoiceSet_t *decoded = 0;
    Choice_t choice;
    asn_SET_specifics_t *specs =
        (asn_SET_specifics_t *)asn_DEF_ChoiceSet.specifics;
    asn_TYPE_tag2member_t saved_entries[3];
    const asn_TYPE_tag2member_t *saved_map = specs->tag2el_cxer;
    unsigned saved_count = specs->tag2el_cxer_count;
    uint8_t encoded[8] = {0};
    asn_enc_rval_t er;
    asn_dec_rval_t dr;

    memset(&source, 0, sizeof(source));
    memset(&choice, 0, sizeof(choice));
    source.n = 7;
    source.c = &choice;
    choice.present = Choice_PR_x;
    choice.choice.x = 1;
    assert(specs->tag2el_count == 3);
    assert(specs->tag2el_count > asn_DEF_ChoiceSet.elements_count);
    memcpy(saved_entries, specs->tag2el, sizeof(saved_entries));
    specs->tag2el_cxer = specs->tag2el;
    specs->tag2el_cxer_count = specs->tag2el_count;
    er = aper_encode_to_buffer(&asn_DEF_ChoiceSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded > 0);
    dr = aper_decode(0, &asn_DEF_ChoiceSet, (void **)&decoded, encoded,
                     (size_t)(er.encoded + 7) / 8, 0,
                     (int)(((er.encoded + 7) / 8) * 8 - er.encoded));
    assert(dr.code == RC_OK);
    assert(decoded->n == source.n && decoded->c);
    assert(decoded->c->present == Choice_PR_x && decoded->c->choice.x == 1);
    ASN_STRUCT_FREE(asn_DEF_ChoiceSet, decoded);
    decoded = 0;

    saved_entries[2].el_no = saved_entries[1].el_no;
    specs->tag2el_cxer = saved_entries;
    specs->tag2el_cxer_count = 3;
    er = aper_encode_to_buffer(&asn_DEF_ChoiceSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == -1);
    memcpy(saved_entries, specs->tag2el, sizeof(saved_entries));
    saved_entries[1].el_no = saved_entries[2].el_no;
    specs->tag2el_cxer = saved_entries;
    specs->tag2el_cxer_count = 3;
    er = aper_encode_to_buffer(&asn_DEF_ChoiceSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == -1);
    specs->tag2el_cxer = saved_map;
    specs->tag2el_cxer_count = saved_count;
    return 0;
}


static const uint8_t golden[] = {
    0xf6, 0x90, 0x58, 0x01, 0x80, 0x01, 0x50
};
static const uint8_t unknown_payload[] = {0xa5};
static const uint8_t second_unknown_payload[] = {0x5a, 0xc3};
static const uint8_t *unknown_payloads[] = {unknown_payload};
static const size_t unknown_payload_sizes[] = {sizeof(unknown_payload)};
static const uint8_t *two_unknown_payloads[] = {
    unknown_payload, second_unknown_payload
};
static const size_t two_unknown_payload_sizes[] = {
    sizeof(unknown_payload), sizeof(second_unknown_payload)
};
static const unsigned expected_roots[] = {0, 1, 2};
static const unsigned expected_additions[] = {3, 4, 5};


/*
 * Purpose: test unknown SET addition skips and truncation statuses.
 * Source: X.691 extension maps and APER open-type helpers.
 * Version/date: 1.0, 2026-10-30.
 * Inputs: none; test-local roots and payloads form the wire value.
 * Returns: zero when unknown additions skip and malformed data is rejected.
 * Errors: Assertions stop on unexpected encoder/decoder results.
 * Author: asn1c maintainers. History: Added for individual APER additions.
 * Example: two unknown bitmap bits consume two open types.
 */
static int
check_unknown_cases(void) {
    AperIndividualSet_t source;
    AperIndividualSet_t *decoded = 0;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    uint8_t encoded[16] = {0};
    uint8_t unknown[16] = {0};
    size_t root_bits;
    size_t unknown_bits;
    size_t unknown_bytes;

    /* Append an unknown high bitmap bit after a known no-addition root value. */
    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.rootLow = MALLOC(sizeof(*source.rootLow));
    source.trailingRoot = MALLOC(sizeof(*source.trailingRoot));
    assert(source.rootLow && source.trailingRoot);
    *source.rootLow = 1;
    *source.trailingRoot = 6;
    er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                               encoded, sizeof(encoded));
    assert(er.encoded > 0);
    root_bits = (size_t)er.encoded;
    memset(unknown, 0, sizeof(unknown));
    memcpy(unknown, encoded, ((root_bits + 7) / 8));
    assert(append_unknown_addition(unknown, sizeof(unknown), root_bits, 1, 4,
                                   unknown_payloads, unknown_payload_sizes, 1,
                                   &unknown_bits) == 0);
    unknown_bytes = (unknown_bits + 7) / 8;
    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     unknown, unknown_bytes, 0,
                     (int)(unknown_bytes * 8 - unknown_bits));
    assert(dr.code == RC_OK);
    assert(decoded->addedFlag == 0 && decoded->addedValue == 0);
    assert(decoded->addedDefault && *decoded->addedDefault == 3);
    ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;

    /* Two unknown bits beyond the schema each consume a separate open type. */
    memset(unknown, 0, sizeof(unknown));
    memcpy(unknown, encoded, ((root_bits + 7) / 8));
    assert(append_unknown_addition(unknown, sizeof(unknown), root_bits, 3, 5,
                                   two_unknown_payloads,
                                   two_unknown_payload_sizes, 2,
                                   &unknown_bits) == 0);
    unknown_bytes = (unknown_bits + 7) / 8;
    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     unknown, unknown_bytes, 0,
                     (int)(unknown_bytes * 8 - unknown_bits));
    assert(dr.code == RC_OK);
    assert(decoded->addedFlag == 0 && decoded->addedValue == 0);
    ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;

    /* The open-type determinant is complete but its payload octet is absent. */
    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     unknown, unknown_bytes - 1, 0, 0);
    assert(dr.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;

    /* Missing bitmap and open-type octets return WMORE; a zero map fails. */
    unknown[0] |= 0x80;
    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     unknown, 1, 0, 0);
    assert(dr.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;
    memset(unknown, 0, sizeof(unknown));
    memcpy(unknown, encoded, ((root_bits + 7) / 8));
    assert(append_unknown_addition(unknown, sizeof(unknown), root_bits, 0, 3,
                                   unknown_payloads, unknown_payload_sizes, 1,
                                   &unknown_bits) == 0);
    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     unknown, (unknown_bits + 7) / 8, 0,
                     (int)(((unknown_bits + 7) / 8) * 8 - unknown_bits));
    assert(dr.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;


    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_AperIndividualSet, &source);
    return 0;
}

/*
 * Purpose: reject malformed v2 SET maps, versions, types, and groups.
 * Source: Generated v2 specifics and member descriptors.
 * Version/date: 1.0, 2026-10-30.
 * Inputs: none; descriptor mutations are restored after each check.
 * Returns: zero when every malformed descriptor is rejected.
 * Errors: Assertions stop on unexpected results.
 * Author: asn1c maintainers. History: Added for fail-closed APER metadata.
 * Example: an out-of-range extension index fails before storage access.
 */
static int
check_invalid_metadata_cases(void) {
    AperIndividualSet_t source;
    AperIndividualSet_t *decoded = 0;
    asn_SET_specifics_t *specs =
        (asn_SET_specifics_t *)asn_DEF_AperIndividualSet.specifics;
    asn_TYPE_member_t *member = &asn_DEF_AperIndividualSet.elements[3];
    const unsigned *saved_root_map;
    uint8_t encoded[16] = {0};
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    static const unsigned duplicate_roots[] = {0, 1, 1};
    static const unsigned invalid_additions[] = {3, 4, 99};

    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.rootLow = MALLOC(sizeof(*source.rootLow));
    source.trailingRoot = MALLOC(sizeof(*source.trailingRoot));
    assert(source.rootLow && source.trailingRoot);
    *source.rootLow = 1;
    *source.trailingRoot = 6;

    /* V2 rejects legacy sentinels and extension groups before reading values. */
    {
        int saved_extensible = specs->extensible;
        specs->extensible = 1;
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         encoded, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        specs->extensible = saved_extensible;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
        decoded = 0;
    }
    member = &asn_DEF_AperIndividualSet.elements[3];
    {
        int saved_flags = member->flags;
        member->flags |= ATF_EXTENSION_GROUP;
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         encoded, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        member->flags = saved_flags;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
        decoded = 0;
    }

    /* Invalid v2 metadata and unsafe members fail even when additions are absent. */
    {
        unsigned saved_size = specs->specifics_size;
        unsigned saved_version = specs->specifics_version;
        specs->specifics_size = (unsigned)(offsetof(asn_SET_specifics_t, extension_groups) - 1);
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         golden, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        specs->specifics_size = saved_size;
        specs->specifics_version++;
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         golden, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        specs->specifics_version = saved_version;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
        decoded = 0;
    }
    {
        const unsigned *saved_additions = specs->extension_map;
        specs->extension_map = invalid_additions;
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         golden, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        specs->extension_map = saved_additions;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
        decoded = 0;
    }
    {
        asn_TYPE_descriptor_t *saved_type = member->type;
        member->type = 0;
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         golden, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        member->type = saved_type;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
        decoded = 0;
    }
    {
        int saved_flags = member->flags;
        member->flags &= ~ATF_POINTER;
        er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                                   encoded, sizeof(encoded));
        assert(er.encoded == -1);
        dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                         golden, sizeof(golden), 0, 0);
        assert(dr.code == RC_FAIL);
        member->flags = saved_flags;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
        decoded = 0;
    }

    /* Duplicate partition entries are rejected before member codec calls. */
    saved_root_map = specs->root_map;
    specs->root_map = duplicate_roots;
    er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                               encoded, sizeof(encoded));
    assert(er.encoded == -1);
    specs->root_map = saved_root_map;

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_AperIndividualSet, &source);
    return 0;
}
/* Purpose: run the individual SET APER and unknown-addition regression checks.
 * Source: Generated 598 descriptor and APER open-type utilities.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: zero on success.
 * Errors: Assertions fail on unexpected encodings or decoder statuses.
 * Author: asn1c maintainers. History: Added for SET APER extension support.
 * Example: check-assembly.sh invokes this source with -gen-APER.
 */
int
main(void) {
    AperIndividualSet_t source;
    AperIndividualSet_t *decoded = 0;
    asn_SET_specifics_t *specs;
    unsigned char encoded[16] = {0};
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    size_t encoded_bytes;

    {
        asn_per_data_t short_open_type;
        uint8_t short_open_type_bytes[] = {0x01};
        memset(&short_open_type, 0, sizeof(short_open_type));
        short_open_type.buffer = short_open_type_bytes;
        short_open_type.nbits = sizeof(short_open_type_bytes) * 8;
        assert(aper_open_type_skip_result(0, 0).code == RC_FAIL);
        assert(aper_open_type_skip(0, 0) == -1);
        assert(aper_open_type_skip_result(0, &short_open_type).code == RC_WMORE);
    }

    specs = (asn_SET_specifics_t *)asn_DEF_AperIndividualSet.specifics;
    assert(specs && specs->extensible == 2);
    assert(specs->specifics_size >= offsetof(asn_SET_specifics_t, extension_groups));
    assert(specs->specifics_version == ASN_SET_SPECIFICS_VERSION);
    assert(specs->root_count == 3 && specs->extension_count == 3);
    assert(memcmp(specs->root_map, expected_roots, sizeof(expected_roots)) == 0);
    assert(memcmp(specs->extension_map, expected_additions,
                  sizeof(expected_additions)) == 0);

    /* Values exercise canonical tag order with a root after extension markers. */
    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.rootLow = MALLOC(sizeof(*source.rootLow));
    source.trailingRoot = MALLOC(sizeof(*source.trailingRoot));
    source.addedFlag = MALLOC(sizeof(*source.addedFlag));
    source.addedValue = MALLOC(sizeof(*source.addedValue));
    assert(source.rootLow && source.trailingRoot && source.addedFlag
           && source.addedValue);
    *source.rootLow = 1;
    *source.trailingRoot = 6;
    *source.addedFlag = 1;
    *source.addedValue = 5;

    er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                               encoded, sizeof(encoded));
    assert(er.encoded == (ssize_t)(sizeof(golden) * 8));
    assert(memcmp(encoded, golden, sizeof(golden)) == 0);
    encoded_bytes = ((size_t)er.encoded + 7) / 8;

    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     encoded, encoded_bytes, 0, 0);
    assert(dr.code == RC_OK);
    assert(decoded->rootHigh == source.rootHigh);
    assert(decoded->rootLow && *decoded->rootLow == *source.rootLow);
    assert(decoded->trailingRoot
           && *decoded->trailingRoot == *source.trailingRoot);
    assert(decoded->addedFlag && *decoded->addedFlag == *source.addedFlag);
    assert(decoded->addedValue && *decoded->addedValue == *source.addedValue);
    assert(decoded->addedDefault && *decoded->addedDefault == 3);
    ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;

    /* A known open type missing its final payload octet needs more input. */
    dr = aper_decode(0, &asn_DEF_AperIndividualSet, (void **)&decoded,
                     golden, sizeof(golden) - 1, 0, 0);
    assert(dr.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AperIndividualSet, decoded);
    decoded = 0;

    /* Present DEFAULT values are omitted and restored by the decoder. */
    source.addedDefault = MALLOC(sizeof(*source.addedDefault));
    assert(source.addedDefault);
    *source.addedDefault = 3;
    memset(encoded, 0, sizeof(encoded));
    er = aper_encode_to_buffer(&asn_DEF_AperIndividualSet, 0, &source,
                               encoded, sizeof(encoded));
    assert(er.encoded == (ssize_t)(sizeof(golden) * 8));
    assert(memcmp(encoded, golden, sizeof(golden)) == 0);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_AperIndividualSet, &source);

    assert(check_unknown_cases() == 0);
    assert(check_invalid_metadata_cases() == 0);
    assert(check_untagged_choice_order() == 0);
    return 0;
}
