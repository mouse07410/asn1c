/* Verify versioned UPER metadata for extensible SET additions and groups. */
#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <SetMetadata.h>
#include <constr_SET.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

/*
 * Purpose: check SET v3 maps and extension-group wire adapters.
 * Source: Generated descriptors for 596-set-uper-extension-metadata-OK.asn1.
 * Version/date: 1.0, 2026-10-30.
 * Parameters: none.
 * Returns: zero when generated metadata matches ASN.1 component order.
 * Errors: assertions terminate on an unexpected generated descriptor.
 * Responsible party: asn1c maintainers. History: Added 2026-10-30.
 * Example: check-assembly.sh compiles this source with generated UPER support.
 */
int
main(void) {
    const asn_SET_specifics_t *specs =
        (const asn_SET_specifics_t *)asn_DEF_SetMetadata.specifics;
    const asn_TYPE_descriptor_t *group_type;
    const asn_SET_specifics_t *group_specs;
    const unsigned expected_roots[] = {0, 1, 2};
    const unsigned expected_additions[] = {3, 4};
    const asn_TYPE_member_t *group;
    SetMetadata_t source;
    SetMetadata_t *decoded = 0;
    unsigned char encoded[8] = {0};
    asn_enc_rval_t er;
    asn_dec_rval_t dr;

    assert(specs != 0);
    assert(specs->extensible == 3);
    assert(specs->specifics_size >= sizeof(*specs));
    assert(specs->specifics_version == ASN_SET_SPECIFICS_VERSION_3);
    assert(specs->extension_groups && specs->extension_group_count == 1);
    assert(specs->extension_groups[0].member_index == 4);
    assert(specs->extension_groups[0].sequence_specifics);
    assert(specs->root_count == sizeof(expected_roots) / sizeof(expected_roots[0]));
    assert(specs->extension_count ==
           sizeof(expected_additions) / sizeof(expected_additions[0]));
    assert(memcmp(specs->root_map, expected_roots, sizeof(expected_roots)) == 0);
    assert(memcmp(specs->extension_map, expected_additions,
                  sizeof(expected_additions)) == 0);

    /* Root maps retain declaration order while tags use canonical order. */
    assert(asn_DEF_SetMetadata.elements[0].name == 0 ||
           strcmp(asn_DEF_SetMetadata.elements[0].name, "rootHigh") == 0);
    assert(specs->tag2el_cxer[0].el_no == 1);

    group = &asn_DEF_SetMetadata.elements[4];
    assert(group->flags & ATF_EXTENSION_GROUP);
    assert(group->flags & ATF_POINTER);
    group_type = group->type;
    assert(group_type != 0 && group_type->elements_count == 2);
    group_specs = (const asn_SET_specifics_t *)group_type->specifics;
    assert(group_specs != 0);
    assert(group_specs->specifics_version == ASN_SET_SPECIFICS_VERSION);
    assert(strcmp(group_type->elements[0].name, "groupEarlier") == 0);
    assert(strcmp(group_type->elements[1].name, "groupLater") == 0);

    /* The group has one presence bit and decodes through its v3 adapter. */
    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.ext1 = calloc(1, sizeof(*source.ext1));
    assert(source.ext1);
    source.ext1->groupEarlier = 1;
    source.ext1->groupLater = 7;
    er = uper_encode_to_buffer(&asn_DEF_SetMetadata, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded > 0);
    {
        size_t bytes = (size_t)(er.encoded + 7) / 8;
        int unused = (int)(bytes * 8 - er.encoded);
        dr = uper_decode(0, &asn_DEF_SetMetadata, (void **)&decoded, encoded,
                         bytes, 0, unused);
    }
    assert(dr.code == RC_OK && decoded && decoded->rootHigh == 9);
    assert(decoded->ext1 && decoded->ext1->groupEarlier && decoded->ext1->groupLater == 7);
    ASN_STRUCT_FREE(asn_DEF_SetMetadata, decoded);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SetMetadata, &source);
    return 0;
}
