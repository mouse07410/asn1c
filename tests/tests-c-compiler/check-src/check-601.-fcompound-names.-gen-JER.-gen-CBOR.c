/* Verify transparent SET JER groups and fail-closed SET CBOR groups. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <JerGroupSet.h>
#include <JerPlainSet.h>
#include <JerAllOptional.h>
#include <JerRecursive.h>
#include <jer_decoder.h>
#include <jer_encoder.h>
#include <cbor_decoder.h>
#include <cbor_encoder.h>

/* Bounded callback output and its current state variable. */
typedef struct output_s {
    char bytes[256]; /* Encoded bytes. */
    size_t used; /* Number of bytes stored; state variable. */
} output_t;

/*
 * Purpose: collect encoder output without exceeding the fixture buffer.
 * Source: asn_app_consume_bytes_f callback contract.
 * Version/date: 1.0, 2026-10-30. Inputs: buf/size are bytes; key is output.
 * Returns: zero on success or -1 on overflow. Exceptions: none.
 * Author: asn1c maintainers. History: added for grouped SET regression.
 * Example: jer_encode passes each emitted fragment to append_output.
 */
static int
append_output(const void *buf, size_t size, void *key) {
    output_t *output = key;
    if(size > sizeof(output->bytes) - output->used) return -1;
    memcpy(output->bytes + output->used, buf, size);
    output->used += size;
    return 0;
}

/*
 * Purpose: populate both groups and a standalone addition.
 * Source: generated JerGroupSet descriptor and fixture schema.
 * Version/date: 1.0, 2026-10-30. Input: value receives initialized fields.
 * Returns: nothing. Exceptions: none; assertions report allocation failure.
 * Author: asn1c maintainers. History: added for flat JER regression.
 * Example: init_value(&value) creates the expected wire value.
 */
static void
init_value(JerGroupSet_t *value) {
    memset(value, 0, sizeof(*value));
    value->root = 1;
    value->ext1 = calloc(1, sizeof(*value->ext1));
    value->ext2 = calloc(1, sizeof(*value->ext2));
    value->extra = calloc(1, sizeof(*value->extra));
    assert(value->ext1 && value->ext2 && value->extra);
    value->ext1->flag = calloc(1, sizeof(*value->ext1->flag));
    value->ext2->second = calloc(1, sizeof(*value->ext2->second));
    assert(value->ext1->flag && value->ext2->second);
    value->ext1->first = 2;
    *value->ext1->flag = 1;
    *value->ext2->second = 3;
    *value->extra = 4;
}

/*
 * Purpose: verify decoded grouped and ungrouped fields.
 * Source: fixture values from init_value.
 * Version/date: 1.0, 2026-10-30. Input: value is the decoded SET.
 * Returns: nothing. Exceptions: none; assertions detect missing values.
 * Author: asn1c maintainers. History: added for flat JER regression.
 * Example: check_value(decoded) verifies both groups.
 */
static void
check_value(const JerGroupSet_t *value) {
    assert(value && value->root == 1 && value->ext1 && value->ext2);
    assert(value->ext1->first == 2 && value->ext1->flag && *value->ext1->flag);
    assert(value->ext2->second && *value->ext2->second == 3);
    assert(value->ext2->defaulted && *value->ext2->defaulted == 5);
    assert(value->extra && *value->extra == 4);
}

/*
 * Purpose: verify flat exact output and every streaming input split.
 * Source: X.697 clauses 27.3 and 29, and fixture component values.
 * Version/date: 1.0, 2026-10-30. Input: source is an initialized SET.
 * Returns: nothing. Exceptions: none; assertions reject incorrect behavior.
 * Author: asn1c maintainers. History: added for transparent SET groups.
 * Example: check_wire(&source) tests the complete flat object and splits.
 */
static void
check_wire(const JerGroupSet_t *source) {
    static const char wire[] = "{\"root\":1,\"first\":2,\"flag\":true,\"second\":3,\"defaulted\":5,\"extra\":4}";
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded = jer_encode(&asn_DEF_JerGroupSet, source, JER_F_MINIFIED, append_output, &output);
    size_t split;
    assert(encoded.encoded == (ssize_t)(sizeof(wire) - 1));
    assert(output.used == sizeof(wire) - 1 && !memcmp(output.bytes, wire, output.used));
    for(split = 0; split <= sizeof(wire) - 1; split++) {
        JerGroupSet_t *decoded = 0;
        asn_dec_rval_t result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded, wire, split);
        size_t used = result.consumed;
        assert(used <= split);
        if(split < sizeof(wire) - 1) {
            if(result.code != RC_WMORE) fprintf(stderr, "split=%zu status=%d used=%zu\n", split, result.code, used);
            assert(result.code == RC_WMORE);
            result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded,
                                wire + used, sizeof(wire) - 1 - used);
        }
        assert(result.code == RC_OK);
        check_value(decoded);
        ASN_STRUCT_FREE(asn_DEF_JerGroupSet, decoded);
    }
}

/*
 * Purpose: check arbitrary ordering, unknown extensions and invalid groups.
 * Source: X.697 component identifiers and SET mandatory-component semantics.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: none; assertions report invalid acceptance or loss of data.
 * Author: asn1c maintainers. History: added for grouped SET key routing.
 * Example: a group containing flag but lacking first must be rejected.
 */
static void
check_inputs(void) {
    static const char valid[] =
        "{\"flag\":true,\"unknown\":{\"nested\":[1,2]},\"second\":3,"
        "\"defaulted\":5,\"root\":1,\"extra\":4,\"first\":2}";
    static const char *invalid[] = {
        "{\"root\":1,\"first\":2,\"first\":3}",
        "{\"root\":1,\"flag\":true}",
        "{\"first\":2}"
    };
    JerGroupSet_t *value = 0;
    asn_dec_rval_t result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&value, valid, sizeof(valid) - 1);
    size_t i;
    assert(result.code == RC_OK);
    check_value(value);
    ASN_STRUCT_FREE(asn_DEF_JerGroupSet, value);
    for(i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        value = 0;
        result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&value, invalid[i], strlen(invalid[i]));
        assert(result.code == RC_FAIL);
        if(value) ASN_STRUCT_FREE(asn_DEF_JerGroupSet, value);
    }
}


/*
 * Purpose: honor a leaf NAME override on both encode and decode.
 * Source: generated member JER constraints and X.697 clause 27.3.2.
 * Version/date: 1.0, 2026-10-30. Input: source is an initialized SET.
 * Returns: nothing. Exceptions: none; assertions reject wrong wire names.
 * Author: asn1c maintainers. History: added for grouped leaf NAME routing.
 * Example: first is represented by the replacement name wireFirst.
 */
static void
check_wire_name(const JerGroupSet_t *source) {
    static const char wire[] = "{\"root\":1,\"wireFirst\":2,\"flag\":true,\"second\":3,\"defaulted\":5,\"extra\":4}";
    asn_TYPE_member_t *leaf = &asn_DEF_JerGroupSet.elements[1].type->elements[0];
    const asn_jer_constraints_t *saved = leaf->encoding_constraints.jer_constraints;
    asn_jer_constraints_t constraints = {0};
    output_t output = {{0}, 0};
    JerGroupSet_t *decoded = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    if(saved) constraints = *saved;
    constraints.wire_name = "wireFirst";
    leaf->encoding_constraints.jer_constraints = &constraints;
    encoded = jer_encode(&asn_DEF_JerGroupSet, source, JER_F_MINIFIED, append_output, &output);
    assert(encoded.encoded == (ssize_t)(sizeof(wire) - 1));
    assert(output.used == sizeof(wire) - 1 && !memcmp(output.bytes, wire, output.used));
    result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded, wire, sizeof(wire) - 1);
    assert(result.code == RC_OK);
    check_value(decoded);
    ASN_STRUCT_FREE(asn_DEF_JerGroupSet, decoded);
    leaf->encoding_constraints.jer_constraints = saved;
}

/*
 * Purpose: reject a present group with a missing mandatory pointer leaf.
 * Source: recursive fixture type and SET group completeness requirement.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: none; assertions report allocation or encoder failure errors.
 * Author: asn1c maintainers. History: added for invalid group encoding.
 * Example: an allocated group without its recursive child is rejected.
 */
static void
check_missing_encode(void) {
    JerRecursive_t value;
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    memset(&value, 0, sizeof(value));
    value.ext1 = calloc(1, sizeof(*value.ext1));
    assert(value.ext1);
    encoded = jer_encode(&asn_DEF_JerRecursive, &value, JER_F_MINIFIED, append_output, &output);
    assert(encoded.encoded == -1);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_JerRecursive, &value);
}

/*
 * Purpose: check absent groups and omitted DEFAULT value semantics.
 * Source: existing JER default materialization and generated pointer storage.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: none; assertions detect incorrect group or DEFAULT handling.
 * Author: asn1c maintainers. History: added for grouped JER defaults.
 * Example: a missing default pointer encodes as the value five.
 */
static void
check_defaults(void) {
    static const char absent[] = "{\"root\":1}";
    static const char omitted[] = "{\"root\":1,\"second\":3}";
    static const char expected[] = "{\"root\":1,\"second\":3,\"defaulted\":5}";
    JerGroupSet_t *value = 0;
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&value, absent, sizeof(absent) - 1);
    assert(result.code == RC_OK && value && !value->ext1 && !value->ext2);
    ASN_STRUCT_FREE(asn_DEF_JerGroupSet, value);
    value = 0;
    result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&value, omitted, sizeof(omitted) - 1);
    assert(result.code == RC_OK && value->ext2 && !value->ext2->defaulted);
    encoded = jer_encode(&asn_DEF_JerGroupSet, value, JER_F_MINIFIED, append_output, &output);
    assert(encoded.encoded == (ssize_t)(sizeof(expected) - 1));
    assert(output.used == sizeof(expected) - 1 && !memcmp(output.bytes, expected, output.used));
    ASN_STRUCT_FREE(asn_DEF_JerGroupSet, value);
}

/*
 * Purpose: reject malformed SET layouts before decoder allocation.
 * Source: generated descriptor storage and SET bounds contract.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: none; assertions detect incorrect acceptance.
 * Author: asn1c maintainers. History: added for descriptor preflight.
 * Example: a presence map outside the structure cannot be decoded.
 */
static void
check_bad_layout(void) {
    static const char wire[] = "{\"root\":1}";
    asn_TYPE_descriptor_t td = asn_DEF_JerGroupSet;
    asn_SET_specifics_t specs = *(const asn_SET_specifics_t *)td.specifics;
    JerGroupSet_t *decoded = 0;
    asn_dec_rval_t result;
    result = jer_decode(0, &td, (void **)&decoded, 0, 0);
    assert(result.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_JerGroupSet, decoded);
    decoded = 0;
    result = jer_decode(0, &td, (void **)&decoded, wire, (size_t)SSIZE_MAX + 1);
    assert(result.code == RC_FAIL && !decoded);
    specs.pres_offset = specs.struct_size;
    td.specifics = &specs;
    result = jer_decode(0, &td, (void **)&decoded, wire, sizeof(wire) - 1);
    assert(result.code == RC_FAIL && !decoded);
}

/*
 * Purpose: reject ambiguous group leaf wire names during decoding.
 * Source: JER NAME constraints and descriptor name routing.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: none; assertions detect unexpected decoding success.
 * Author: asn1c maintainers. History: added for ambiguous NAME metadata.
 * Example: a group leaf cannot share root's wire name.
 */
static void
check_duplicate_name(void) {
    static const char wire[] = "{\"root\":1}";
    asn_TYPE_member_t *leaf = &asn_DEF_JerGroupSet.elements[1].type->elements[0];
    const asn_jer_constraints_t *saved = leaf->encoding_constraints.jer_constraints;
    asn_jer_constraints_t constraints = {0};
    JerGroupSet_t *decoded = 0;
    asn_dec_rval_t result;
    if(saved) constraints = *saved;
    constraints.wire_name = "root";
    leaf->encoding_constraints.jer_constraints = &constraints;
    result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded, wire, sizeof(wire) - 1);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_JerGroupSet, decoded);
    leaf->encoding_constraints.jer_constraints = saved;
}

/*
 * Purpose: reject unsupported table-selected grouped JER leaf dispatch.
 * Source: SET JER open-type fail-closed behavior.
 * Version/date: 1.0, 2026-10-30. Input: source is an initialized SET.
 * Returns: nothing. Exceptions: none; assertions detect wrong status.
 * Author: asn1c maintainers. History: added for unsupported open types.
 * Example: an open-type marked group leaf is rejected on both paths.
 */
static void
check_open_type(const JerGroupSet_t *source) {
    static const char wire[] = "{\"root\":1,\"first\":2}";
    asn_TYPE_member_t *leaf = &asn_DEF_JerGroupSet.elements[1].type->elements[0];
    enum asn_TYPE_flags_e saved = leaf->flags;
    output_t output = {{0}, 0};
    JerGroupSet_t *decoded = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    leaf->flags |= ATF_OPEN_TYPE;
    encoded = jer_encode(&asn_DEF_JerGroupSet, source, JER_F_MINIFIED, append_output, &output);
    assert(encoded.encoded == -1);
    result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded, wire, sizeof(wire) - 1);
    assert(result.code == RC_FAIL);
    leaf->flags = saved;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_JerGroupSet, decoded);
}

/*
 * Purpose: verify pretty JER remains decodable with grouped leaves.
 * Source: SET JER output and decoding contracts.
 * Version/date: 1.0, 2026-10-30. Input: source is an initialized SET.
 * Returns: nothing. Exceptions: none; assertions detect output failures.
 * Author: asn1c maintainers. History: added for pretty group output.
 * Example: indentation precedes the first outer member.
 */
static void
check_pretty(const JerGroupSet_t *source) {
    output_t output = {{0}, 0};
    JerGroupSet_t *decoded = 0;
    asn_enc_rval_t encoded = jer_encode(&asn_DEF_JerGroupSet, source, JER_F, append_output, &output);
    asn_dec_rval_t result;
    assert(encoded.encoded > 0 && memchr(output.bytes, '\n', output.used));
    result = jer_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded, output.bytes, output.used);
    assert(result.code == RC_OK);
    check_value(decoded);
    ASN_STRUCT_FREE(asn_DEF_JerGroupSet, decoded);
}

/*
 * Purpose: reject grouped CBOR before emitting bytes or allocating a value.
 * Source: explicit unsupported group mapping and CBOR codec contracts.
 * Version/date: 1.0, 2026-10-30. Input: source is an initialized grouped SET.
 * Returns: nothing. Exceptions: none; assertions detect unexpected success.
 * Author: asn1c maintainers. History: added pending a defined CBOR mapping.
 * Example: even an empty map must fail for a group-bearing descriptor.
 */
static void
check_cbor(const JerGroupSet_t *source) {
    static const uint8_t empty_map[] = {0xa0};
    JerGroupSet_t *decoded = 0;
    JerPlainSet_t plain = {0};
    JerGroupSet_t absent = {0};
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded = cbor_encode(&asn_DEF_JerGroupSet, source, append_output, &output);
    asn_dec_rval_t result = cbor_decode(0, &asn_DEF_JerGroupSet, (void **)&decoded, empty_map, sizeof(empty_map));
    assert(encoded.encoded == -1 && output.used == 0);
    assert(result.code == RC_FAIL && !decoded);
    encoded = cbor_encode(&asn_DEF_JerGroupSet, &absent, append_output, &output);
    assert(encoded.encoded == -1 && output.used == 0);
    encoded = cbor_encode(&asn_DEF_JerPlainSet, &plain, append_output, &output);
    assert(encoded.encoded > 0 && output.used > 0);
}

/*
 * Purpose: verify SET CBOR required fields, duplicates, and malformed inputs.
 * Source: generated SET presence and CBOR map contracts. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect regressions.
 * Author: asn1c maintainers. History: added strict SET map validation.
 * Example: an empty map cannot omit the required root member.
 */
static void
check_cbor_plain_inputs(void) {
    static const uint8_t valid[] = {0xa1, 0x64, 'r', 'o', 'o', 't', 0x01};
    static const uint8_t both[] = {0xa2, 0x64, 'f', 'l', 'a', 'g', 0xf5,
                                  0x64, 'r', 'o', 'o', 't', 0x01};
    static const uint8_t empty[] = {0xa0};
    static const uint8_t duplicate[] = {0xa2, 0x64, 'r', 'o', 'o', 't', 1,
                                       0x64, 'r', 'o', 'o', 't', 2};
    static const uint8_t unknown_duplicate[] = {0xa3, 0x61, 'x', 1, 0x61, 'x', 2,
                                               0x64, 'r', 'o', 'o', 't', 1};
    const uint8_t *inputs[] = {empty, duplicate, unknown_duplicate};
    size_t lengths[] = {sizeof(empty), sizeof(duplicate), sizeof(unknown_duplicate)};
    JerPlainSet_t *value = 0;
    asn_dec_rval_t result;
    size_t i;
    JerAllOptional_t *optional = 0;

    result = cbor_decode(0, &asn_DEF_JerAllOptional, (void **)&optional, empty, sizeof(empty));
    assert(result.code == RC_OK && optional && !optional->flag);
    ASN_STRUCT_FREE(asn_DEF_JerAllOptional, optional);
    result = cbor_decode(0, &asn_DEF_JerPlainSet, (void **)&value, valid, sizeof(valid));
    assert(result.code == RC_OK && value->root == 1 && !value->flag);
    ASN_STRUCT_FREE(asn_DEF_JerPlainSet, value);
    value = 0;
    result = cbor_decode(0, &asn_DEF_JerPlainSet, (void **)&value, both, sizeof(both));
    assert(result.code == RC_OK && value->root == 1 && value->flag && *value->flag);
    ASN_STRUCT_FREE(asn_DEF_JerPlainSet, value);
    for(i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        value = 0;
        result = cbor_decode(0, &asn_DEF_JerPlainSet, (void **)&value, inputs[i], lengths[i]);
        assert(result.code == RC_FAIL);
        if(value) ASN_STRUCT_FREE(asn_DEF_JerPlainSet, value);
    }
    for(i = 0; i < sizeof(valid); i++) {
        value = 0;
        result = cbor_decode(0, &asn_DEF_JerPlainSet, (void **)&value, valid, i);
        assert(result.code != RC_OK);
        if(value) ASN_STRUCT_FREE(asn_DEF_JerPlainSet, value);
    }
}

/*
 * Purpose: reject invalid CBOR input and malformed SET member descriptors.
 * Source: SET decoder argument contracts. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect invalid acceptance.
 * Author: asn1c maintainers. History: added descriptor guards.
 * Example: a missing member type must fail before dereference.
 */
static void
check_cbor_bad_descriptor(void) {
    static const uint8_t wire[] = {0xa1, 0x64, 'r', 'o', 'o', 't', 1};
    asn_TYPE_descriptor_t td = asn_DEF_JerPlainSet;
    asn_TYPE_member_t members[2];
    JerPlainSet_t *value = 0;
    asn_dec_rval_t result;
    memcpy(members, td.elements, sizeof(members));
    td.elements = members;
    members[0].type = 0;
    result = cbor_decode(0, &td, (void **)&value, wire, sizeof(wire));
    assert(result.code == RC_FAIL && !value);
    members[0] = asn_DEF_JerPlainSet.elements[0];
    members[0].name = 0;
    result = cbor_decode(0, &td, (void **)&value, wire, sizeof(wire));
    assert(result.code == RC_FAIL && !value);
    members[0] = asn_DEF_JerPlainSet.elements[0];
    members[0].memb_offset = sizeof(JerPlainSet_t);
    result = cbor_decode(0, &td, (void **)&value, wire, sizeof(wire));
    assert(result.code == RC_FAIL && !value);
    result = SET_decode_cbor(0, &asn_DEF_JerPlainSet, (void **)&value, 0, 1);
    assert(result.code == RC_FAIL && !value);
    members[0] = asn_DEF_JerPlainSet.elements[0];
    members[1].flags |= ATF_OPEN_TYPE;
    result = cbor_decode(0, &td, (void **)&value, wire, sizeof(wire));
    assert(result.code == RC_OK && value && !value->flag);
    ASN_STRUCT_FREE(asn_DEF_JerPlainSet, value);
}

/*
 * Purpose: run grouped JER and unsupported grouped CBOR regressions.
 * Source: the 601 generated-C fixture.
 * Version/date: 1.0, 2026-10-30. Inputs: none. Returns: zero on success.
 * Exceptions: none; assertions terminate on failure.
 * Author: asn1c maintainers. History: added for SET group codec coverage.
 * Example: invoked by the generated-C compiler test harness.
 */
int
main(void) {
    JerGroupSet_t source;
    init_value(&source);
    check_wire(&source);
    check_wire_name(&source);
    check_missing_encode();
    check_defaults();
    check_bad_layout();
    check_duplicate_name();
    check_open_type(&source);
    check_pretty(&source);
    check_inputs();
    check_cbor(&source);
    check_cbor_plain_inputs();
    check_cbor_bad_descriptor();
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_JerGroupSet, &source);
    return 0;
}
