/* Fixed C comparison for packed Rust BOOLEAN record representations.
 * Source: BoolStorage and BoolImport schemas, reused checked C vector helpers.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: bitset/getter regression coverage. Example: run with generated C.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "Bool4.h"
#include "SixRequiredSet.h"
#include "NamedParent.h"
#include "ImportedParent.h"
#include "ber_decoder.h"
#include "cer_decoder.h"
#include "cer_encoder.h"
#include "der_encoder.h"
#define WIRE_CAP 256
static int check_prefix(asn_TYPE_descriptor_t *, const uint8_t *, size_t, int);
static int check_cer_rejects(asn_TYPE_descriptor_t *, const uint8_t *, size_t);
/* Validate callbacks required by the generic vector helpers.
 * Parameters: td is the generated C descriptor. Returns one when compare/free
 * callbacks exist. Errors: missing descriptor operations return zero.
 * Source: asn_TYPE_operation_t. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: generic codec probes.
 * Example: descriptor_ready(&asn_DEF_Bool4).
 */
static int
descriptor_ready(asn_TYPE_descriptor_t *td) {
    return td && td->op && td->op->compare_struct && td->op->free_struct;
}

/* Release a decoded C value through its validated descriptor callback.
 * Parameters: td owns value. Returns no value; null or incomplete inputs are ignored.
 * Errors: none. Source: generated descriptor free callback. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported record probes.
 * Example: release_value(&asn_DEF_Bool4, decoded).
 */
static void
release_value(asn_TYPE_descriptor_t *td, void *value) {
    if(descriptor_ready(td) && value)
        td->op->free_struct(td, value, ASFM_FREE_EVERYTHING);
}

/*
 * Purpose: compare imported SET values without C DEFAULT or presence storage.
 * Original source: ASN.1 record semantics and generated descriptor comparisons.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: td selects the record; expected and actual are decoded/source values.
 * Returns: one for semantic equality, zero for a mismatch.
 * Errors: missing imported child or comparison callback returns zero.
 * Responsible party: asn1c maintainers. History: packed imported SET parity.
 * Example: an absent DEFAULT count is equal to a present value of 2.
 */
static int
values_equal(asn_TYPE_descriptor_t *td, const void *expected, const void *actual) {
    if(td == &asn_DEF_ImportedParent) {
        const ImportedParent_t *left = expected;
        const ImportedParent_t *right = actual;
        long left_count = left->count ? *left->count : 2;
        long right_count = right->count ? *right->count : 2;
        if(!descriptor_ready(&asn_DEF_RemoteLeaf)
           || !left->child || !right->child) return 0;
        return asn_DEF_RemoteLeaf.op->compare_struct(
                   &asn_DEF_RemoteLeaf, left->child, right->child) == 0
            && (left->enabled != 0) == (right->enabled != 0)
            && left_count == right_count;
    }
    return td->op->compare_struct(td, expected, actual) == 0;
}

/* Compare one generated DER or CER encoding with its fixed vector.
 * Parameters: td/value describe the object; wire/size are expected bytes;
 * canonical selects CER when nonzero. Returns zero on equality, one on error.
 * Source: generated C encoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: encoding vector helper.
 * Example: check_encoding(&asn_DEF_Bool4, &value, der, sizeof(der), 0).
 */
static int
check_encoding(asn_TYPE_descriptor_t *td, const void *value,
               const uint8_t *wire, size_t size, int canonical) {
    uint8_t actual[WIRE_CAP];
    asn_enc_rval_t result;
    if(!descriptor_ready(td) || !value || !wire || size > sizeof(actual)) return 1;
    result = canonical ? cer_encode_to_buffer(NULL, td, value, actual, sizeof(actual))
                       : der_encode_to_buffer(td, value, actual, sizeof(actual));
    return result.encoded < 0 || (size_t)result.encoded != size
        || memcmp(actual, wire, size);
}

/* Decode one BER or strict-CER value and compare its generated structure.
 * Parameters: td/value describe the object; wire/size are input bytes;
 * strict selects CER validation. Returns zero on semantic equality.
 * Errors: decode, consumption, compare, or callback errors return one.
 * Source: generated C decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: decode vector helper.
 * Example: check_decoding(&asn_DEF_Bool4, &value, cer, sizeof(cer), 1).
 */
static int
check_decoding(asn_TYPE_descriptor_t *td, const void *value,
               const uint8_t *wire, size_t size, int strict) {
    void *decoded_value = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor_ready(td) || !value || !wire || !size) return 1;
    result = strict ? cer_decode(NULL, td, &decoded_value, wire, size)
                    : ber_decode(NULL, td, &decoded_value, wire, size);
    failed = result.code != RC_OK || result.consumed != size || !decoded_value;
    if(failed) {
        fprintf(stderr, "%s %s decode failed: status=%d consumed=%zu/%zu\n",
                td->name, strict ? "CER" : "BER", (int)result.code,
                result.consumed, size);
    }
    if(!failed) {
        failed = !values_equal(td, value, decoded_value);
        if(failed) fprintf(stderr, "%s %s decoded value differs\n",
                           td->name, strict ? "CER" : "BER");
    }
    release_value(td, decoded_value);
    return failed;
}

/* Compare encoders and decoders with independent DER/CER vectors.
 * Parameters: td/value identify the C type and source value; der/cer are wire TLVs.
 * Returns zero for byte and semantic equality. Errors return one; no exceptions.
 * Source: generated C codec APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported records.
 * Example: check_vectors(&asn_DEF_Bool4, &value, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_vectors(asn_TYPE_descriptor_t *td, const void *value,
              const uint8_t *der, size_t der_size,
              const uint8_t *cer, size_t cer_size) {
    if(!descriptor_ready(td) || !value || !der || !cer) return 1;
    if(check_encoding(td, value, der, der_size, 0)) {
        fprintf(stderr, "%s DER encoding differs\n", td->name);
        return 1;
    }
    if(check_encoding(td, value, cer, cer_size, 1)) {
        fprintf(stderr, "%s CER encoding differs\n", td->name);
        return 1;
    }
    if(check_decoding(td, value, der, der_size, 0)
       || check_decoding(td, value, cer, cer_size, 1)) return 1;
    if(check_prefix(td, der, der_size, 0) || check_prefix(td, cer, cer_size, 1)) {
        fprintf(stderr, "%s prefix decode differs\n", td->name);
        return 1;
    }
    if(check_cer_rejects(td, der, der_size)) {
        fprintf(stderr, "%s strict CER accepted DER\n", td->name);
        return 1;
    }
    return 0;
}

/* Decode one DER or CER TLV followed by a suffix and check exact prefix use.
 * Parameters: td/wire/size select the value; strict selects CER validation.
 * Returns zero for RC_OK and exact consumption. Errors return one.
 * Source: generated BER/CER decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix conformance.
 * Example: check_prefix(&asn_DEF_SetPair, cer, sizeof(cer), 1).
 */
static int
check_prefix(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size,
             int strict) {
    uint8_t input[WIRE_CAP + 1];
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor_ready(td) || !wire || !size || size >= sizeof(input)) return 1;
    memcpy(input, wire, size);
    input[size] = 0xee;
    result = strict ? cer_decode(NULL, td, &decoded, input, size + 1)
                    : ber_decode(NULL, td, &decoded, input, size + 1);
    if(result.code != RC_OK || result.consumed != size || !decoded) {
        release_value(td, decoded);
        return 1;
    }
    release_value(td, decoded);
    return 0;
}

/* Require strict CER rejection for one complete definite DER value.
 * Parameters: td/wire/size identify the type and complete DER TLV.
 * Returns zero when CER rejects it. Errors: acceptance returns one.
 * Source: strict C CER adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: canonicality checks.
 * Example: reject a definite nested record where CER requires indefinite lengths.
 */
static int
check_cer_rejects(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor_ready(td) || !wire || !size) return 1;
    result = cer_decode(NULL, td, &decoded, wire, size);
    release_value(td, decoded);
    return result.code == RC_OK && result.consumed == size;
}

/*
 * Compare four packed booleans with interleaved scalar/default/optional siblings.
 * Inputs: none; fixed vectors and generated descriptors define the case.
 * Returns zero on C encode/decode/prefix parity, one on failure; no exceptions.
 * Source: BoolStorage and X.690 TLVs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: packed BOOLEAN storage.
 * Example: FALSE/TRUE defaults and INTEGER 2 are omitted canonically.
 */
static int
check_sequence(void) {
    static const uint8_t der[] = {0x30, 6, 1, 1, 0xff, 0x80, 1, 0};
    static const uint8_t cer[] = {0x30, 0x80, 1, 1, 0xff, 0x80, 1, 0, 0, 0};
    static const uint8_t present_der[] = {
        0x30, 0x14, 1, 1, 0xff, 2, 1, 4, 0x80, 1, 0,
        0x81, 1, 0, 0xa2, 3, 1, 1, 0xff, 0x83, 1, 0
    };
    static const uint8_t present_cer[] = {
        0x30, 0x80, 1, 1, 0xff, 2, 1, 4, 0x80, 1, 0, 0x81, 1, 0,
        0xa2, 0x80, 1, 1, 0xff, 0, 0, 0x83, 1, 0, 0, 0
    };
    long count = 2;
    BOOLEAN_t fourth = 1;
    Bool4_t value = {.first = 1, .count = &count, .type = 0, .third = 0, .fourth = &fourth};
    BOOLEAN_t maybe = 0;
    BOOLEAN_t present_fourth = 0;
    long present_count = 4;
    Bool4_t present = {
        .first = 1, .count = &present_count, .type = 0, .maybe = &maybe,
        .third = 1, .fourth = &present_fourth
    };
    if(check_vectors(&asn_DEF_Bool4, &value, der, sizeof(der), cer, sizeof(cer))) return 1;
    return check_vectors(&asn_DEF_Bool4, &present, present_der, sizeof(present_der),
                         present_cer, sizeof(present_cer));
}

/*
 * Purpose: accept an explicitly encoded DEFAULT FALSE in BER and reject it in CER.
 * Original source: BoolStorage schema and X.690 canonical DEFAULT rules.
 * Version/date: 1.0, 2026-11-01.
 * Inputs: none; the fixed indefinite-length CER-like sequence contains explicit FALSE.
 * Returns: zero when BER normalizes the value and strict CER rejects the input.
 * Errors: decode, semantic comparison, or unexpected CER acceptance returns one.
 * Responsible party: asn1c maintainers. History: DEFAULT BOOLEAN canonicality coverage.
 * Example: an explicit [2] BOOLEAN FALSE is accepted by BER and rejected by CER.
 */
static int
check_explicit_default(void) {
    static const uint8_t wire[] = {
        0x30, 0x80, 1, 1, 0xff, 0x80, 1, 0,
        0xa2, 0x80, 1, 1, 0, 0, 0, 0, 0
    };
    long count = 2;
    BOOLEAN_t fourth = 1;
    Bool4_t expected = {
        .first = 1, .count = &count, .type = 0, .third = 0, .fourth = &fourth
    };
    if(check_decoding(&asn_DEF_Bool4, &expected, wire, sizeof(wire), 0)) {
        fputs("explicit DEFAULT BER decode failed\n", stderr);
        return 1;
    }
    if(check_cer_rejects(&asn_DEF_Bool4, wire, sizeof(wire))) {
        fputs("strict CER accepted explicit DEFAULT\n", stderr);
        return 1;
    }
    return 0;
}

/*
 * Compare six required SET booleans in independent effective-tag order.
 * Inputs: none. Returns zero on fixed-vector and prefix parity, one on failure.
 * Errors: checked helpers report missing callbacks or codec failures.
 * Source: SixRequiredSet schema. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: six-bit storage regression.
 * Example: alternating TRUE/FALSE values use six distinct effective tags.
 */
static int
check_set(void) {
    static const uint8_t der[] = {
        0x31, 18, 1, 1, 0, 0x80, 1, 0xff, 0x81, 1, 0,
        0x82, 1, 0xff, 0x83, 1, 0, 0x84, 1, 0xff
    };
    static const uint8_t cer[] = {
        0x31, 0x80, 1, 1, 0, 0x80, 1, 0xff, 0x81, 1, 0,
        0x82, 1, 0xff, 0x83, 1, 0, 0x84, 1, 0xff, 0, 0
    };
    SixRequiredSet_t value = {.second = 1, .fourth = 1, .sixth = 1};
    /* All six SET components are required and present in this source value. */
    ASN_SET_MKPRESENT(value._presence_map, SixRequiredSet_PR_first);
    ASN_SET_MKPRESENT(value._presence_map, SixRequiredSet_PR_second);
    ASN_SET_MKPRESENT(value._presence_map, SixRequiredSet_PR_third);
    ASN_SET_MKPRESENT(value._presence_map, SixRequiredSet_PR_fourth);
    ASN_SET_MKPRESENT(value._presence_map, SixRequiredSet_PR_fifth);
    ASN_SET_MKPRESENT(value._presence_map, SixRequiredSet_PR_sixth);
    return check_vectors(&asn_DEF_SixRequiredSet, &value, der, sizeof(der), cer, sizeof(cer));
}

/*
 * Compare one local packed child under an OPTIONAL EXPLICIT parent member.
 * Inputs: none. Returns zero on fixed-vector and prefix parity, one on failure.
 * Errors: checked helpers report codec and comparison failures.
 * Source: LocalLeaf/NamedParent schema. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: child callback storage.
 * Example: child values TRUE/FALSE/TRUE/FALSE preserve parent DEFAULT omission.
 */
static int
check_local_child(void) {
    static const uint8_t der[] = {
        0x30, 18, 0xa3, 16, 0x30, 14, 1, 1, 0xff, 0x80, 1, 0,
        0xa1, 3, 1, 1, 0xff, 0x82, 1, 0
    };
    static const uint8_t cer[] = {
        0x30, 0x80, 0xa3, 0x80, 0x30, 0x80, 1, 1, 0xff, 0x80, 1, 0,
        0xa1, 0x80, 1, 1, 0xff, 0, 0, 0x82, 1, 0, 0, 0, 0, 0, 0, 0
    };
    LocalLeaf_t child = {.first = 1, .third = 1};
    long count = 2;
    NamedParent_t value = {.child = &child, .count = &count};
    return check_vectors(&asn_DEF_NamedParent, &value, der, sizeof(der), cer, sizeof(cer));
}

/*
 * Compare an imported packed SET child and parent scalar DEFAULT omission.
 * Inputs: none. Returns zero on fixed-vector and prefix parity, one on failure.
 * Errors: checked helpers report codec and comparison failures.
 * Source: BoolImportBase/Client schema. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: cross-module packed storage.
 * Example: EXPLICIT context 4 contains a SET with its own sorted leaf tags.
 */
static int
check_imported_child(void) {
    static const uint8_t der[] = {
        0x31, 18, 0xa4, 16, 0x31, 14, 0x80, 1, 0xff, 0x81, 1, 0,
        0xa2, 3, 1, 1, 0xff, 0x83, 1, 0
    };
    static const uint8_t cer[] = {
        0x31, 0x80, 0xa4, 0x80, 0x31, 0x80, 0x80, 1, 0xff, 0x81, 1, 0,
        0xa2, 0x80, 1, 1, 0xff, 0, 0, 0x83, 1, 0, 0, 0, 0, 0, 0, 0
    };
    RemoteLeaf_t child = {.first = 1, .third = 1};
    long count = 2;
    ImportedParent_t value = {.child = &child, .count = &count};
    /* Mark required leaves; parent DEFAULT fields stay absent in both values. */
    ASN_SET_MKPRESENT(child._presence_map, RemoteLeaf_PR_first);
    ASN_SET_MKPRESENT(child._presence_map, RemoteLeaf_PR_second);
    ASN_SET_MKPRESENT(child._presence_map, RemoteLeaf_PR_third);
    ASN_SET_MKPRESENT(child._presence_map, RemoteLeaf_PR_fourth);
    ASN_SET_MKPRESENT(value._presence_map, ImportedParent_PR_child);
    return check_vectors(&asn_DEF_ImportedParent, &value, der, sizeof(der), cer, sizeof(cer));
}

/*
 * Run all five independent DER/CER value pairs for BOOLEAN field packing.
 * Inputs: none. Returns zero on success, one if any checked case fails.
 * Errors: emits a diagnostic on vector failure; no exceptions.
 * Source: fixed C comparison fixtures. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: private bitset regression.
 * Example: run after generating BoolStorage and BoolImport C descriptors.
 */
int
main(void) {
    if(check_sequence()) return fputs("Bool4 vector failed\n", stderr), 1;
    if(check_explicit_default()) return fputs("Bool4 explicit DEFAULT vector failed\n", stderr), 1;
    if(check_set()) return fputs("SixRequiredSet vector failed\n", stderr), 1;
    if(check_local_child()) return fputs("NamedParent vector failed\n", stderr), 1;
    if(check_imported_child()) return fputs("ImportedParent vector failed\n", stderr), 1;
    puts("packed BOOLEAN C vectors passed: five DER/CER value pairs");
    return 0;
}
