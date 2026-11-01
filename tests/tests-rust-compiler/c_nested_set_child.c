/* Compare C-generated nested SET encoders and decoders with the Rust vectors. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "SequenceExplicit.h"
#include "SequenceImplicit.h"
#include "SequenceLeaves.h"
#include "SequenceNatural.h"
#include "SequenceOptional.h"
#include "SetExplicit.h"
#include "ber_decoder.h"
#include "cer_decoder.h"
#include "cer_encoder.h"
#include "der_encoder.h"

/* Check successful full BER or strict CER decoding and release returned values.
 * Inputs: td selects the generated schema; wire/size provide one full TLV;
 * canonical selects strict CER instead of BER. Returns zero on acceptance.
 * Errors: a failed decode, partial consumption, or null result returns one.
 * Source: generated C decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: nested SET comparison.
 * Example: check_decode(&asn_DEF_SequenceNatural, cer, sizeof(cer), 1).
 */
static int
check_decode(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size,
             int canonical) {
    void *value = NULL;
    asn_dec_rval_t result;
    if(!td || !wire || !size) return 1;
    result = canonical ? cer_decode(NULL, td, &value, wire, size)
                       : ber_decode(NULL, td, &value, wire, size);
    if(result.code != RC_OK || result.consumed != size || !value) {
        if(value) ASN_STRUCT_FREE(*td, value);
        return 1;
    }
    ASN_STRUCT_FREE(*td, value);
    return 0;
}

/* Confirm strict CER rejects a complete BER form with noncanonical framing.
 * Inputs: td selects the schema; wire/size provide one complete encoding.
 * Returns zero only when CER rejects it. Errors: acceptance returns one.
 * Source: generated C CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: nested SET vectors.
 * Example: reject a definite explicit wrapper around an indefinite SET.
 */
static int
check_cer_rejects(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size) {
    void *value = NULL;
    asn_dec_rval_t result;
    if(!td || !wire || !size) return 1;
    result = cer_decode(NULL, td, &value, wire, size);
    if(value) ASN_STRUCT_FREE(*td, value);
    return result.code == RC_OK;
}

/* Confirm the C BER adapter rejects a frame combination it cannot compose.
 * Inputs: td selects the schema; wire/size provide one complete BER candidate.
 * Returns zero on rejection, one when BER unexpectedly accepts it.
 * Errors: invalid arguments return one. Source: generated C BER adapter.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: mixed nested SET wrapper divergence. Example: mixed EXPLICIT lengths.
 */
static int
check_ber_rejects(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size) {
    void *value = NULL;
    asn_dec_rval_t result;
    if(!td || !wire || !size) return 1;
    result = ber_decode(NULL, td, &value, wire, size);
    if(value) ASN_STRUCT_FREE(*td, value);
    return result.code == RC_OK;
}

/* Confirm a C decoder reconstructs a value equal to its source structure.
 * Inputs: td selects the schema; expected is the original value; wire/size
 * contain one complete BER or CER TLV; canonical selects strict CER.
 * Returns zero for structural equality, one on decode/compare failure.
 * Source: generated C descriptor compare callback. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: live C/Rust parity vectors.
 * Example: compare a decoded SET child against the encoded value.
 */
static int
check_decoded_equal(asn_TYPE_descriptor_t *td, const void *expected,
                    const uint8_t *wire, size_t size, int canonical) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!td || !expected || !wire || !size || !td->op || !td->op->compare_struct)
        return 1;
    result = canonical ? cer_decode(NULL, td, &decoded, wire, size)
                       : ber_decode(NULL, td, &decoded, wire, size);
    failed = result.code != RC_OK || result.consumed != size || !decoded
          || td->op->compare_struct(td, expected, decoded) != 0;
    if(decoded) ASN_STRUCT_FREE(*td, decoded);
    return failed;
}

/* Compare both C encoders with fixed Rust vectors and exercise both decoders.
 * Inputs: name is diagnostic text; td/value identify generated C data; der/cer
 * contain exact independent wire vectors. Returns zero on parity.
 * Errors: encoder/decoder failure, size mismatch, or unequal bytes returns one.
 * Source: generated C BER/CER implementation. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline SET child gate.
 * Example: compare SequenceNatural with a child SET ordered by tags 0 then 1.
 */
static int
check_vectors(const char *name, asn_TYPE_descriptor_t *td, const void *value,
              const uint8_t *der, size_t der_size,
              const uint8_t *cer, size_t cer_size) {
    uint8_t actual[64];
    asn_enc_rval_t encoded;
    (void)name;
    if(!td || !value || !der || !cer || der_size > sizeof(actual)
       || cer_size > sizeof(actual)) return 1;
    encoded = der_encode_to_buffer(td, value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)
       || check_decoded_equal(td, value, der, der_size, 0)) return 1;
    encoded = cer_encode_to_buffer(NULL, td, value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)
       || check_decoded_equal(td, value, cer, cer_size, 1)) return 1;
    return 0;
}

/* Verify BER accepts shuffled child and parent SET fields but CER rejects them.
 * Inputs: no external parameters; fixed complete TLVs target generated schemas.
 * Returns zero when decoders preserve the expected BOOLEAN/INTEGER values.
 * Errors: wrong status, consumption, decoded values, or failed cleanup returns 1.
 * Source: X.690 unordered BER SET and canonical CER order. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: nested SET ordering.
 * Example: reverse only the child's tag order while parent SEQUENCE stays fixed.
 */
static int
check_reordered(void) {
    static const uint8_t child_reverse[] = {
        0x30, 0x08, 0x31, 0x06, 0x81, 1, 0xff, 0x80, 1, 2,
    };
    static const uint8_t parent_reverse[] = {
        0x31, 0x80, 0x84, 1, 0xff, 0xa3, 0x80, 0x31, 0x80,
        0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t set_child_reverse[] = {
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x81, 1, 0xff,
        0x80, 1, 2, 0, 0, 0, 0, 0x84, 1, 0xff, 0, 0,
    };
    SequenceNatural_t *sequence = NULL;
    SetExplicit_t *set = NULL;
    SetExplicit_t expected = {0};
    asn_dec_rval_t result;
    result = ber_decode(NULL, &asn_DEF_SequenceNatural, (void **)&sequence,
                        child_reverse, sizeof(child_reverse));
    if(result.code != RC_OK || result.consumed != sizeof(child_reverse)
       || !sequence || sequence->child.x != 2 || !sequence->child.y) goto fail;
    ASN_STRUCT_FREE(asn_DEF_SequenceNatural, sequence);
    sequence = NULL;
    if(check_cer_rejects(&asn_DEF_SequenceNatural, child_reverse, sizeof(child_reverse)))
        return 1;
    result = ber_decode(NULL, &asn_DEF_SetExplicit, (void **)&set,
                        parent_reverse, sizeof(parent_reverse));
    if(result.code != RC_OK || result.consumed != sizeof(parent_reverse)
       || !set || set->child.x != 2 || !set->child.y || !set->after) goto fail;
    ASN_STRUCT_FREE(asn_DEF_SetExplicit, set);
    set = NULL;
    expected.after = 1;
    expected.child.x = 2;
    expected.child.y = 1;
    ASN_SET_MKPRESENT(expected._presence_map, SetExplicit_PR_after);
    ASN_SET_MKPRESENT(expected._presence_map, SetExplicit_PR_child);
    ASN_SET_MKPRESENT(expected.child._presence_map, SetExplicit__child_PR_x);
    ASN_SET_MKPRESENT(expected.child._presence_map, SetExplicit__child_PR_y);
    if(check_cer_rejects(&asn_DEF_SetExplicit, parent_reverse, sizeof(parent_reverse))
       || check_decoded_equal(&asn_DEF_SetExplicit, &expected, set_child_reverse,
                              sizeof(set_child_reverse), 0)
       || check_cer_rejects(&asn_DEF_SetExplicit, set_child_reverse,
                            sizeof(set_child_reverse))) return 1;
    return 0;
fail:
    if(sequence) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, sequence);
    if(set) ASN_STRUCT_FREE(asn_DEF_SetExplicit, set);
    return 1;
}

/* Check mixed BER wrappers, their strict-CER rejection, and prefix consumption.
 * Inputs: none; test vectors contain one valid BOOLEAN/INTEGER child SET.
 * Returns zero on expected decoder behavior, one for status/value mismatch.
 * Errors: malformed or noncanonical status divergence fails this check.
 * Source: X.690 explicit tagging and generated C decoders.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: nested SET child vectors. Example: CER accepts a canonical prefix.
 */
static int
check_mixed_framing_and_prefix(void) {
    static const uint8_t parent_definite[] = {
        0x30, 0x0c, 0xa3, 0x0a, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0,
    };
    static const uint8_t wrapper_indefinite[] = {
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
        0, 0, 0, 0,
    };
    static const uint8_t canonical_prefix[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff,
        0, 0, 0, 0, 0xee,
    };
    static const uint8_t child_eoc[] = {0x30, 0x04, 0x31, 0x02, 0, 0};
    static const uint8_t truncated_child[] = {
        0x30, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1,
    };
    SequenceNatural_t expected = {0};
    SequenceNatural_t *decoded = NULL;
    asn_dec_rval_t result;
    expected.child.x = 2;
    expected.child.y = 1;
    ASN_SET_MKPRESENT(expected.child._presence_map, SequenceNatural__child_PR_x);
    ASN_SET_MKPRESENT(expected.child._presence_map, SequenceNatural__child_PR_y);
    if(check_ber_rejects(&asn_DEF_SequenceExplicit, parent_definite,
                         sizeof(parent_definite))
       || check_cer_rejects(&asn_DEF_SequenceExplicit, parent_definite,
                            sizeof(parent_definite))
       || check_ber_rejects(&asn_DEF_SequenceExplicit, wrapper_indefinite,
                            sizeof(wrapper_indefinite))
       || check_cer_rejects(&asn_DEF_SequenceExplicit, wrapper_indefinite,
                            sizeof(wrapper_indefinite))
       || check_ber_rejects(&asn_DEF_SequenceNatural, child_eoc, sizeof(child_eoc))
       || check_cer_rejects(&asn_DEF_SequenceNatural, child_eoc, sizeof(child_eoc))
       || check_ber_rejects(&asn_DEF_SequenceNatural, truncated_child,
                            sizeof(truncated_child))
       || check_cer_rejects(&asn_DEF_SequenceNatural, truncated_child,
                            sizeof(truncated_child))) return 1;
    result = cer_decode(NULL, &asn_DEF_SequenceNatural, (void **)&decoded,
                        canonical_prefix, sizeof(canonical_prefix));
    if(result.code != RC_OK || result.consumed != sizeof(canonical_prefix) - 1
       || !decoded || asn_DEF_SequenceNatural.op->compare_struct(
           &asn_DEF_SequenceNatural, &expected, decoded) != 0) {
        if(decoded) ASN_STRUCT_FREE(asn_DEF_SequenceNatural, decoded);
        return 1;
    }
    ASN_STRUCT_FREE(asn_DEF_SequenceNatural, decoded);
    return 0;
}

/* Encode and decode the natural, implicit, explicit, and six-leaf child SETs.
 * Inputs: none. Returns zero when C bytes equal the Rust conformance vectors.
 * Errors: any encoder/decoder failure or byte mismatch returns one.
 * Source: generated C compiler and X.690 tags. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline SET child gate.
 * Example: natural SET fields encode by effective tags, not ASN.1 declaration.
 */
int
main(void) {
    SequenceNatural_t natural = {0};
    SequenceImplicit_t implicit = {0};
    SequenceExplicit_t explicit_value = {0};
    SequenceOptional_t optional_absent = {0};
    SetExplicit_t set = {0};
    SequenceLeaves_t leaves = {0};
    uint8_t bit_bytes[] = {0xa0};
    uint8_t octet_bytes[] = {0xaa};
    uint8_t enum_bytes[] = {1};
    static const uint8_t natural_der[] = {
        0x30, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    };
    static const uint8_t natural_cer[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t implicit_der[] = {
        0x30, 0x08, 0xa3, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    };
    static const uint8_t implicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t explicit_der[] = {
        0x30, 0x0a, 0xa3, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    };
    static const uint8_t explicit_cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff,
        0, 0, 0, 0, 0, 0,
    };
    static const uint8_t set_der[] = {
        0x31, 0x0d, 0xa3, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
        0x84, 1, 0xff,
    };
    static const uint8_t set_cer[] = {
        0x31, 0x80, 0xa3, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff,
        0, 0, 0, 0, 0x84, 1, 0xff, 0, 0,
    };
    static const uint8_t optional_der[] = {0x30, 0x00};
    static const uint8_t optional_cer[] = {0x30, 0x80, 0, 0};
    static const uint8_t leaves_der[] = {
        0x30, 0x14, 0x31, 0x12, 0x80, 1, 0xff, 0x81, 1, 3,
        0x82, 2, 5, 0xa0, 0x83, 1, 0xaa, 0x84, 0, 0x85, 1, 1,
    };
    static const uint8_t leaves_cer[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 1, 0xff, 0x81, 1, 3,
        0x82, 2, 5, 0xa0, 0x83, 1, 0xaa, 0x84, 0, 0x85, 1, 1, 0, 0, 0, 0,
    };

    natural.child.y = implicit.child.y = explicit_value.child.y = 1;
    natural.child.x = implicit.child.x = explicit_value.child.x = 2;
    ASN_SET_MKPRESENT(natural.child._presence_map, SequenceNatural__child_PR_y);
    ASN_SET_MKPRESENT(natural.child._presence_map, SequenceNatural__child_PR_x);
    ASN_SET_MKPRESENT(implicit.child._presence_map, SequenceImplicit__child_PR_y);
    ASN_SET_MKPRESENT(implicit.child._presence_map, SequenceImplicit__child_PR_x);
    ASN_SET_MKPRESENT(explicit_value.child._presence_map, SequenceExplicit__child_PR_y);
    ASN_SET_MKPRESENT(explicit_value.child._presence_map, SequenceExplicit__child_PR_x);

    set.after = 1;
    set.child.y = 1;
    set.child.x = 2;
    ASN_SET_MKPRESENT(set._presence_map, SetExplicit_PR_after);
    ASN_SET_MKPRESENT(set._presence_map, SetExplicit_PR_child);
    ASN_SET_MKPRESENT(set.child._presence_map, SetExplicit__child_PR_y);
    ASN_SET_MKPRESENT(set.child._presence_map, SetExplicit__child_PR_x);

    leaves.child.flag = 1;
    leaves.child.number = 3;
    leaves.child.bits.buf = bit_bytes;
    leaves.child.bits.size = sizeof(bit_bytes);
    leaves.child.bits.bits_unused = 5;
    leaves.child.octets.buf = octet_bytes;
    leaves.child.octets.size = sizeof(octet_bytes);
    leaves.child.state.buf = enum_bytes;
    leaves.child.state.size = sizeof(enum_bytes);
    ASN_SET_MKPRESENT(leaves.child._presence_map, SequenceLeaves__child_PR_flag);
    ASN_SET_MKPRESENT(leaves.child._presence_map, SequenceLeaves__child_PR_number);
    ASN_SET_MKPRESENT(leaves.child._presence_map, SequenceLeaves__child_PR_bits);
    ASN_SET_MKPRESENT(leaves.child._presence_map, SequenceLeaves__child_PR_octets);
    ASN_SET_MKPRESENT(leaves.child._presence_map, SequenceLeaves__child_PR_nothing);
    ASN_SET_MKPRESENT(leaves.child._presence_map, SequenceLeaves__child_PR_state);

    if(check_vectors("natural SET", &asn_DEF_SequenceNatural, &natural,
                     natural_der, sizeof(natural_der), natural_cer, sizeof(natural_cer))
       || check_vectors("implicit SET", &asn_DEF_SequenceImplicit, &implicit,
                        implicit_der, sizeof(implicit_der), implicit_cer, sizeof(implicit_cer))
       || check_vectors("explicit SET", &asn_DEF_SequenceExplicit, &explicit_value,
                        explicit_der, sizeof(explicit_der), explicit_cer, sizeof(explicit_cer))
       || check_vectors("parent SET", &asn_DEF_SetExplicit, &set,
                        set_der, sizeof(set_der), set_cer, sizeof(set_cer))
       || check_vectors("six leaf SET", &asn_DEF_SequenceLeaves, &leaves,
                        leaves_der, sizeof(leaves_der), leaves_cer, sizeof(leaves_cer))
       || check_vectors("optional absent", &asn_DEF_SequenceOptional, &optional_absent,
                        optional_der, sizeof(optional_der), optional_cer, sizeof(optional_cer))
       || check_reordered() || check_mixed_framing_and_prefix()) return 1;
    return 0;
}
