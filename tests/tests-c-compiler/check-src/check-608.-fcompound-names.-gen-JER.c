/* Verify flattened SEQUENCE extension groups in the C JER runtime. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <SeqGroups.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

/* Bounded output and its current state variable. */
typedef struct jer_output_s {
    char bytes[256]; /* Encoded bytes. */
    size_t used; /* Number of bytes stored; state variable. */
} jer_output_t;

/*
 * Purpose: append encoder bytes to a bounded buffer.
 * Source: JER callback contract. Version/date: 1.0, 2026-10-31.
 * Inputs: buf/size are the fragment; key points to the destination.
 * Returns: zero on success, -1 on overflow. Exceptions: none.
 * Author: asn1c maintainers. History: added for SEQUENCE JER regression.
 * Example: jer_encode forwards each output fragment to this callback.
 */
static int
append_bytes(const void *buf, size_t size, void *key) {
    jer_output_t *output = key;
    if(!output || (size && !buf) || output->used > sizeof(output->bytes)
    || size > sizeof(output->bytes) - output->used) return -1;
    memcpy(output->bytes + output->used, buf, size);
    output->used += size;
    return 0;
}

/*
 * Purpose: force a JER encoder callback failure for cleanup coverage.
 * Source: asn_app_consume_bytes_f callback contract.
 * Version/date: 1.0, 2026-10-31. Inputs: buf/size are ignored; key is unused.
 * Returns: always -1. Exceptions: none.
 * Author: asn1c maintainers. History: added for callback failure regression.
 * Example: jer_encode reports failure when this callback receives output.
 */
static int
reject_bytes(const void *buf, size_t size, void *key) {
    (void)buf;
    (void)size;
    (void)key;
    return -1;
}

/*
 * Purpose: allocate and populate all fields represented by the golden JSON.
 * Source: generated SeqGroups descriptor and fixture schema.
 * Version/date: 1.0, 2026-10-31. Input: value receives initialized fields.
 * Returns: nothing. Errors: assertions catch allocation failure.
 * Author: asn1c maintainers. History: added for flat group encode/decode.
 * Example: init_value(&source) prepares both synthetic group structures.
 */
static void
init_value(SeqGroups_t *value) {
    memset(value, 0, sizeof(*value));
    value->root = 1;
    value->ext1 = calloc(1, sizeof(*value->ext1));
    value->ext2 = calloc(1, sizeof(*value->ext2));
    value->extra = calloc(1, sizeof(*value->extra));
    assert(value->ext1 && value->ext2 && value->extra);
    value->ext1->flag = calloc(1, sizeof(*value->ext1->flag));
    assert(value->ext1->flag);
    value->ext1->first = 2;
    *value->ext1->flag = 1;
    value->ext2->second = 3;
    *value->extra = 4;
}

/*
 * Purpose: assert all decoded sequence and group values.
 * Source: fixture values from init_value.
 * Version/date: 1.0, 2026-10-31. Input: value is the decoded sequence.
 * Returns: nothing. Errors: assertions flag missing or incorrect values.
 * Author: asn1c maintainers. History: added for flat group round trips.
 * Example: check_value(decoded) verifies each group leaf.
 */
static void
check_value(const SeqGroups_t *value) {
    assert(value && value->root == 1 && value->ext1 && value->ext2);
    assert(value->ext1->first == 2 && value->ext1->flag);
    assert(*value->ext1->flag && value->ext2->second == 3);
    assert(value->extra && *value->extra == 4);
}

/*
 * Purpose: check exact flat output and decoding at every input split.
 * Source: X.697 JER component names and the generated sequence fixture.
 * Version/date: 1.0, 2026-10-31. Input: source is fully populated.
 * Returns: nothing. Errors: assertions flag formatting or streaming failures.
 * Author: asn1c maintainers. History: added for flat group JER parity.
 * Example: check_wire(&source) confirms group keys are outer siblings.
 */
static void
check_wire(const SeqGroups_t *source) {
    static const char wire[] =
        "{\"root\":1,\"first\":2,\"flag\":true,\"second\":3,\"extra\":4}";
    jer_output_t output = {{0}, 0};
    asn_enc_rval_t encoded = jer_encode(&asn_DEF_SeqGroups, source,
        JER_F_MINIFIED, append_bytes, &output);
    size_t split;
    assert(encoded.encoded == (ssize_t)(sizeof(wire) - 1));
    assert(output.used == sizeof(wire) - 1);
    assert(memcmp(output.bytes, wire, output.used) == 0);
    for(split = 0; split <= sizeof(wire) - 1; split++) {
        SeqGroups_t *decoded = 0;
        asn_dec_rval_t result = jer_decode(0, &asn_DEF_SeqGroups,
            (void **)&decoded, wire, split);
        size_t used = result.consumed;
        assert(used <= split);
        if(split < sizeof(wire) - 1) {
            if(result.code != RC_WMORE) {
                fprintf(stderr, "split=%zu status=%d consumed=%zu\n",
                        split, result.code, used);
            }
            assert(result.code == RC_WMORE);
            result = jer_decode(0, &asn_DEF_SeqGroups, (void **)&decoded,
                                wire + used, sizeof(wire) - 1 - used);
        }
        assert(result.code == RC_OK);
        check_value(decoded);
        ASN_STRUCT_FREE(asn_DEF_SeqGroups, decoded);
    }
}

/*
 * Purpose: reject duplicate, out-of-order, and incomplete group input.
 * Source: SEQUENCE order and mandatory extension-group child requirements.
 * Version/date: 1.0, 2026-10-31. Inputs: none. Returns: nothing.
 * Errors: assertions detect malformed JSON accepted by the decoder.
 * Author: asn1c maintainers. History: added for flat-group validation.
 * Example: a present group with only its optional `flag` is incomplete.
 */
static void
check_invalid_inputs(void) {
    static const char *invalid[] = {
        "{\"root\":1,\"root\":2}",
        "{\"first\":2,\"root\":1}",
        "{\"root\":1,\"flag\":true}",
        "{\"root\"junk:1}",
        "x{\"root\":1}",
        "{x\"root\":1}",
        "{\"root\":1,\"future\":01}",
        "{\"root\":1,\"future\":{\"x\":,}}",
        "{\"root\":1,\"future\":\"bad\\u12xz\"}"
    };
    size_t i;
    for(i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        SeqGroups_t *decoded = 0;
        asn_dec_rval_t result = jer_decode(0, &asn_DEF_SeqGroups,
            (void **)&decoded, invalid[i], strlen(invalid[i]));
        assert(result.code == RC_FAIL);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_SeqGroups, decoded);
    }
}

/*
 * Purpose: accept an unknown extension value while preserving known fields.
 * Source: extensible SEQUENCE unknown-addition skipping.
 * Version/date: 1.0, 2026-10-31. Input: none. Returns: nothing.
 * Errors: assertions detect unknown-value or known-field regressions.
 * Author: asn1c maintainers. History: added for flat-group decoder coverage.
 * Example: nested unknown values are skipped as one extension addition.
 */
static void
check_unknown_extension(void) {
    static const char wire[] =
        "{\"root\":1,\"first\":2,\"second\":3,\"unknown\":{"
        "\"text\":\"comma,escaped quote: \\\"\",\"array\":[1,{\"nested\":true}]}}";
    SeqGroups_t *decoded = 0;
    asn_dec_rval_t result = jer_decode(0, &asn_DEF_SeqGroups,
        (void **)&decoded, wire, sizeof(wire) - 1);
    assert(result.code == RC_OK);
    assert(decoded && decoded->root == 1 && decoded->ext1 && decoded->ext2);
    assert(decoded->ext1->first == 2 && decoded->ext2->second == 3);
    ASN_STRUCT_FREE(asn_DEF_SeqGroups, decoded);
}

/*
 * Purpose: fail safely on malformed member storage and encoder callbacks.
 * Source: descriptor bounds and callback error contracts.
 * Version/date: 1.0, 2026-10-31. Inputs: none. Returns: nothing.
 * Errors: assertions catch unsafe offsets or ignored callback failures.
 * Author: asn1c maintainers. History: added for malformed layout defenses.
 * Example: a group pointer offset at struct_size is rejected before access.
 */
static void
check_bad_layout_and_callback(const SeqGroups_t *source) {
    asn_TYPE_descriptor_t td = asn_DEF_SeqGroups;
    asn_SEQUENCE_specifics_t specs =
        *(const asn_SEQUENCE_specifics_t *)td.specifics;
    asn_TYPE_member_t members[8];
    SeqGroups_t *decoded = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    assert(td.elements_count <= sizeof(members) / sizeof(members[0]));
    memcpy(members, td.elements, td.elements_count * sizeof(*members));
    members[1].memb_offset = specs.struct_size;
    td.elements = members;
    encoded = jer_encode(&td, source, JER_F_MINIFIED, append_bytes,
                         &(jer_output_t){{0}, 0});
    assert(encoded.encoded == -1);
    result = jer_decode(0, &td, (void **)&decoded, "{\"root\":1}", 10);
    assert(result.code == RC_FAIL && decoded == 0);
    encoded = jer_encode(&asn_DEF_SeqGroups, source, JER_F_MINIFIED,
                         reject_bytes, 0);
    assert(encoded.encoded == -1);
}

/*
 * Purpose: run flat group encode/decode and malformed-input regressions.
 * Source: issue 594 C JER follow-up fixture. Version/date: 2026-10-31.
 * Inputs: none. Returns: zero when all assertions pass.
 * Errors: assertion failure signals a JER regression. Author: maintainers.
 * History: added for SEQUENCE group output and input parity.
 * Example: check-assembly.sh check-src/check-608...c builds this test.
 */
int
main(void) {
    SeqGroups_t source;
    init_value(&source);
    check_wire(&source);
    check_invalid_inputs();
    check_unknown_extension();
    check_bad_layout_and_callback(&source);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SeqGroups, &source);
    return 0;
}
