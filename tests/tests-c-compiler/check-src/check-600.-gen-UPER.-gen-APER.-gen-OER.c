/* Verify SET extension groups across packed and octet encodings. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <GroupSet.h>
#include <OlderGroupSet.h>
#include <constr_SEQUENCE.h>
#include <uper_decoder.h>
#include <uper_encoder.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <der_encoder.h>

/* X.696: root preamble and values, three addition bits, then open types. */
/* X.691: 84 UPER bits; APER aligns 8-bit root integers and open types. */
static const uint8_t uper_golden[] = {0xc0, 0x42, 0x41, 0x70, 0x28, 0x1e, 0x00, 0x1a, 0x00, 0x10, 0x80};
static const uint8_t aper_golden[] = {0xc0, 0x01, 0x09, 0x05, 0xc0, 0x03, 0x80, 0x07, 0x80, 0x01, 0xa0, 0x01, 0x08};
static const uint8_t oer_golden[] = {
    0xc0, 0x01, 0x09, 0x02, 0x05, 0xe0, 0x03, 0x80, 0x07, 0xff, 0x02, 0x80, 0xff, 0x01, 0x08
};

/*
 * Purpose: populate both groups, a standalone addition, and a trailing root.
 * Source: generated GroupSet layout and the extension-group regression schema.
 * Version/date: 1.0, 2026-10-30. Input: value receives initialized fields.
 * Returns: nothing. Errors: assertions fail on allocation failure.
 * Author: asn1c maintainers. History: added for v3 SET adapters.
 * Example: init_value(&value) creates the vector used by each codec.
 */
static void
init_value(GroupSet_t *value) {
    memset(value, 0, sizeof(*value));
    value->root = 1;
    value->trailing = calloc(1, sizeof(*value->trailing));
    value->ext1 = calloc(1, sizeof(*value->ext1));
    value->ext2 = calloc(1, sizeof(*value->ext2));
    value->extra = calloc(1, sizeof(*value->extra));
    assert(value->trailing && value->ext1 && value->ext2 && value->extra);
    value->ext1->flag = calloc(1, sizeof(*value->ext1->flag));
    value->ext2->onlyFlag = calloc(1, sizeof(*value->ext2->onlyFlag));
    assert(value->ext1->flag && value->ext2->onlyFlag);
    *value->trailing = 9;
    value->ext1->first = 7;
    *value->ext1->flag = 1;
    *value->ext2->onlyFlag = 1;
    *value->extra = 8;
}

/*
 * Purpose: check every field and restored DEFAULT in a decoded group value.
 * Source: schema values initialized by init_value.
 * Version/date: 1.0, 2026-10-30. Input: value is the decoded SET.
 * Returns: nothing. Errors: assertions reject missing or incorrect fields.
 * Author: asn1c maintainers. History: added for group codec round trips.
 * Example: check_value(decoded) verifies restored group defaults.
 */
static void
check_value(const GroupSet_t *value) {
    assert(value && value->root == 1 && value->trailing && *value->trailing == 9);
    assert(value->ext1 && value->ext1->first == 7 && value->ext1->flag && *value->ext1->flag);
    assert(value->ext1->defaulted && *value->ext1->defaulted == 3);
    assert(value->ext2 && value->ext2->onlyFlag && *value->ext2->onlyFlag);
    assert(value->ext2->onlyValue && *value->ext2->onlyValue == 3);
    assert(value->extra && *value->extra == 8);
}

/*
 * Purpose: check OER group framing and every split of the complete message.
 * Source: independent X.696 clauses 16 and 18 wire vector.
 * Version/date: 1.0, 2026-10-30. Input: source is the initialized value.
 * Returns: nothing. Errors: assertions detect malformed statuses or values.
 * Author: asn1c maintainers. History: added for resumable group decoding.
 * Example: check_oer(&source) feeds the vector at every byte boundary.
 */
static void
check_oer(const GroupSet_t *source) {
    uint8_t output[64];
    asn_enc_rval_t encoded = oer_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output));
    size_t split;
    assert(encoded.encoded == (ssize_t)sizeof(oer_golden));
    assert(!memcmp(output, oer_golden, sizeof(oer_golden)));
    for(split = 0; split <= sizeof(oer_golden); split++) {
        GroupSet_t *decoded = 0;
        asn_dec_rval_t result = asn_DEF_GroupSet.op->oer_decoder(
            0, &asn_DEF_GroupSet, 0, (void **)&decoded, oer_golden, split);
        size_t used = result.consumed;
        assert(used <= split);
        if(split < sizeof(oer_golden)) {
            assert(result.code == RC_WMORE);
            result = asn_DEF_GroupSet.op->oer_decoder(
                0, &asn_DEF_GroupSet, 0, (void **)&decoded, oer_golden + used, sizeof(oer_golden) - used);
        }
        assert(result.code == RC_OK);
        check_value(decoded);
        ASN_STRUCT_FREE(asn_DEF_GroupSet, decoded);
    }
}

/*
 * Purpose: check packed extension-group round trips and truncated payloads.
 * Source: X.691 clauses 19.9 and 21 and the generated GroupSet descriptor.
 * Version/date: 1.0, 2026-10-30. Input: source is the initialized value.
 * Returns: nothing. Errors: assertions reject mismatches or wrong statuses.
 * Author: asn1c maintainers. History: added for UPER and APER adapters.
 * Example: check_per(&source, 1) tests aligned PER.
 */
static void
check_per(const GroupSet_t *source, int aligned) {
    uint8_t output[64];
    GroupSet_t *decoded = 0;
    asn_enc_rval_t encoded = aligned
        ? aper_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output))
        : uper_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output));
    size_t bytes;
    int unused;
    asn_dec_rval_t result;
    assert(encoded.encoded > 0);
    bytes = (size_t)(encoded.encoded + 7) / 8;
    assert(encoded.encoded == (aligned ? 104 : 84));
    assert(!memcmp(output, aligned ? aper_golden : uper_golden, bytes));
    unused = (int)(bytes * 8 - encoded.encoded);
    result = aligned ? aper_decode(0, &asn_DEF_GroupSet, (void **)&decoded, output, bytes, 0, unused)
                     : uper_decode(0, &asn_DEF_GroupSet, (void **)&decoded, output, bytes, 0, unused);
    assert(result.code == RC_OK);
    check_value(decoded);
    ASN_STRUCT_FREE(asn_DEF_GroupSet, decoded);
    decoded = 0;
    result = aligned ? aper_decode(0, &asn_DEF_GroupSet, (void **)&decoded, output, bytes - 1, 0, 0)
                     : uper_decode(0, &asn_DEF_GroupSet, (void **)&decoded, output, bytes - 1, 0, 0);
    assert(result.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_GroupSet, decoded);
}

/*
 * Purpose: verify empty and DEFAULT-only optional groups are omitted.
 * Source: X.691 19.9 and X.696 16.5.3.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Errors: assertions fail on inconsistent group-presence encoding.
 * Author: asn1c maintainers. History: added for group presence semantics.
 * Example: an allocated wrapper with no encoded members equals an absent one.
 */
static void
check_empty_group(void) {
    GroupSet_t source;
    struct ext2 *saved;
    uint8_t baseline[64], output[64];
    asn_enc_rval_t expected, actual;
    int codec;
    init_value(&source);
    saved = source.ext2;
    source.ext2 = 0;
    for(codec = 0; codec < 3; codec++) {
        expected = codec == 0 ? oer_encode_to_buffer(&asn_DEF_GroupSet, 0, &source, baseline, sizeof(baseline))
            : codec == 1 ? uper_encode_to_buffer(&asn_DEF_GroupSet, 0, &source, baseline, sizeof(baseline))
            : aper_encode_to_buffer(&asn_DEF_GroupSet, 0, &source, baseline, sizeof(baseline));
        assert(expected.encoded > 0);
        source.ext2 = saved;
        free(saved->onlyFlag);
        saved->onlyFlag = 0;
        if(!saved->onlyValue) saved->onlyValue = calloc(1, sizeof(*saved->onlyValue));
        assert(saved->onlyValue);
        *saved->onlyValue = 3;
        actual = codec == 0 ? oer_encode_to_buffer(&asn_DEF_GroupSet, 0, &source, output, sizeof(output))
            : codec == 1 ? uper_encode_to_buffer(&asn_DEF_GroupSet, 0, &source, output, sizeof(output))
            : aper_encode_to_buffer(&asn_DEF_GroupSet, 0, &source, output, sizeof(output));
        assert(actual.encoded == expected.encoded);
        assert(!memcmp(output, baseline, (size_t)(codec == 0 ? actual.encoded : (actual.encoded + 7) / 8)));
        source.ext2 = 0;
    }
    source.ext2 = saved;
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_GroupSet, &source);
}

/*
 * Purpose: ensure older descriptors skip unknown group and ordinary additions.
 * Source: X.691 and X.696 open-type extension framing.
 * Version/date: 1.0, 2026-10-30. Input: source is the initialized value.
 * Returns: nothing. Errors: assertions reject bad status or root values.
 * Author: asn1c maintainers. History: added for forward compatibility.
 * Example: an older decoder skips all three newer SET additions.
 */
static void
check_unknown(const GroupSet_t *source) {
    int codec;
    for(codec = 0; codec < 3; codec++) {
        uint8_t output[64];
        OlderGroupSet_t *decoded = 0;
        asn_enc_rval_t encoded = codec == 0
            ? oer_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output))
            : codec == 1 ? uper_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output))
            : aper_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output));
        size_t bytes = (size_t)(codec == 0 ? encoded.encoded : (encoded.encoded + 7) / 8);
        int unused = codec == 0 ? 0 : (int)(bytes * 8 - encoded.encoded);
        asn_dec_rval_t result;
        assert(encoded.encoded > 0);
        result = codec == 0 ? asn_DEF_OlderGroupSet.op->oer_decoder(
            0, &asn_DEF_OlderGroupSet, 0, (void **)&decoded, output, bytes)
            : codec == 1 ? uper_decode(0, &asn_DEF_OlderGroupSet, (void **)&decoded, output, bytes, 0, unused)
            : aper_decode(0, &asn_DEF_OlderGroupSet, (void **)&decoded, output, bytes, 0, unused);
        assert(result.code == RC_OK && decoded->root == 1 && decoded->trailing && *decoded->trailing == 9);
        ASN_STRUCT_FREE(asn_DEF_OlderGroupSet, decoded);
    }
}

/*
 * Purpose: reject malformed v3 and legacy group metadata before value access.
 * Source: compiler-emitted v3 group table and v2 compatibility contract.
 * Version/date: 1.0, 2026-10-30. Input: source identifies valid data.
 * Returns: nothing. Errors: assertions reject unexpected encoder success.
 * Author: asn1c maintainers. History: added for malformed metadata coverage.
 * Example: a missing adapter table must fail all three encoders.
 */
static void
check_metadata(const GroupSet_t *source) {
    asn_SET_specifics_t *specs = (asn_SET_specifics_t *)asn_DEF_GroupSet.specifics;
    const asn_SET_extension_group_t *saved = specs->extension_groups;
    asn_SET_extension_group_t bad_table[2];
    asn_SEQUENCE_specifics_t bad_sequence = *saved[0].sequence_specifics;
    asn_TYPE_descriptor_t *child = asn_DEF_GroupSet.elements[saved[0].member_index].type;
    asn_TYPE_operation_t *saved_op = child->op;
    asn_TYPE_operation_t bad_op = *saved_op;
    int saved_extensible = specs->extensible;
    unsigned saved_size = specs->specifics_size;
    uint8_t output[64];
    int codec, mutation;
    memcpy(bad_table, saved, sizeof(bad_table));
    for(mutation = 0; mutation < 6; mutation++) {
        if(mutation == 0) specs->extension_groups = 0;
        if(mutation == 1) specs->extensible = 2;
        if(mutation == 2) specs->specifics_size = (unsigned)(sizeof(*specs) - 1);
        if(mutation == 3) {
            bad_table[1].member_index = bad_table[0].member_index;
            specs->extension_groups = bad_table;
        }
        if(mutation == 4) {
            bad_table[1] = saved[1];
            bad_sequence.ctx_offset = bad_sequence.struct_size;
            bad_table[0].sequence_specifics = &bad_sequence;
            specs->extension_groups = bad_table;
        }
        if(mutation == 5) { bad_op.free_struct = 0; child->op = &bad_op; }
        for(codec = 0; codec < 3; codec++) {
            GroupSet_t *decoded = 0;
            asn_enc_rval_t encoded = codec == 0
                ? oer_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output))
                : codec == 1 ? uper_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output))
                : aper_encode_to_buffer(&asn_DEF_GroupSet, 0, source, output, sizeof(output));
            asn_dec_rval_t result = codec == 0 ? asn_DEF_GroupSet.op->oer_decoder(
                0, &asn_DEF_GroupSet, 0, (void **)&decoded, oer_golden, sizeof(oer_golden))
                : codec == 1 ? uper_decode(0, &asn_DEF_GroupSet, (void **)&decoded,
                                            uper_golden, sizeof(uper_golden), 0, 4)
                : aper_decode(0, &asn_DEF_GroupSet, (void **)&decoded,
                              aper_golden, sizeof(aper_golden), 0, 0);
            assert(encoded.encoded == -1 && result.code == RC_FAIL);
            if(decoded) ASN_STRUCT_FREE(asn_DEF_GroupSet, decoded);
        }
        specs->extension_groups = saved;
        specs->extensible = saved_extensible;
        specs->specifics_size = saved_size;
        child->op = saved_op;
    }
}

/*
 * Purpose: verify replacement, failure cleanup, and later DER use of groups.
 * Source: SET ownership and the length-delimited SEQUENCE wire adapter.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Errors: assertions reject lost existing values or invalid decoded SET state.
 * Author: asn1c maintainers. History: added for adapter lifetime coverage.
 * Example: a malformed replacement leaves the original group allocated.
 */
static void
check_ownership(void) {
    GroupSet_t *value = calloc(1, sizeof(*value));
    struct ext1 *original;
    uint8_t malformed[sizeof(oer_golden)];
    uint8_t encoded[128];
    asn_dec_rval_t result;
    asn_enc_rval_t der;
    assert(value);
    init_value(value);
    original = value->ext1;
    memcpy(malformed, oer_golden, sizeof(malformed));
    malformed[6] = 2; /* Complete open type, but required BOOLEAN is truncated. */
    result = asn_DEF_GroupSet.op->oer_decoder(
        0, &asn_DEF_GroupSet, 0, (void **)&value, malformed, sizeof(malformed));
    assert(result.code == RC_FAIL && value->ext1 == original);
    ASN_STRUCT_FREE(asn_DEF_GroupSet, value);

    value = 0;
    memcpy(malformed, oer_golden, sizeof(malformed));
    malformed[7] |= 1; /* Unused group preamble bits must be zero. */
    result = asn_DEF_GroupSet.op->oer_decoder(
        0, &asn_DEF_GroupSet, 0, (void **)&value, malformed, sizeof(malformed));
    assert(result.code == RC_FAIL);
    if(value) ASN_STRUCT_FREE(asn_DEF_GroupSet, value);

    value = calloc(1, sizeof(*value));
    assert(value);
    init_value(value);
    result = asn_DEF_GroupSet.op->oer_decoder(
        0, &asn_DEF_GroupSet, 0, (void **)&value, oer_golden, sizeof(oer_golden));
    assert(result.code == RC_OK);
    check_value(value);
    der = der_encode_to_buffer(&asn_DEF_GroupSet, value, encoded, sizeof(encoded));
    assert(der.encoded > 0);
    ASN_STRUCT_FREE(asn_DEF_GroupSet, value);
}

/*
 * Purpose: run SET extension-group wire and round-trip regressions.
 * Source: 600 schema and X.691/X.696 extension-addition rules.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: zero on success.
 * Errors: assertions terminate on an unexpected codec result.
 * Author: asn1c maintainers. History: added for SET v3 adapters.
 * Example: invoked by the generated-C compiler test harness.
 */
int
main(void) {
    GroupSet_t source;
    init_value(&source);
    check_oer(&source);
    check_per(&source, 0);
    check_per(&source, 1);
    check_empty_group();
    check_unknown(&source);
    check_metadata(&source);
    check_ownership();
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_GroupSet, &source);
    return 0;
}
