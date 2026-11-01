/* C vectors for imported owned leaves, defaults, equivalent budgets, and names.
 * Source: generated C descriptors and the imported-record ASN.1 fixtures.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * Example: compile against c-gen and run to verify the expanded C reference slice.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "AlphaPacket.h"
#include "BetaPacket.h"
#include "DefaultParent.h"
#include "ImportedCommonAlphaSource_Common.h"
#include "ImportedCommonBetaSource_Common.h"
#include "ImportedEquivalent.h"
#include "LocalEquivalent.h"
#include "OwnedPair.h"
#include "RemoteOwned.h"
#include "RemoteSeq.h"
#include "ber_decoder.h"
#include "cer_decoder.h"
#include "cer_encoder.h"
#include "der_encoder.h"

#define WIRE_CAP 64

static int check_prefix(asn_TYPE_descriptor_t *, const uint8_t *, size_t, int);
static int check_cer_rejects(asn_TYPE_descriptor_t *, const uint8_t *, size_t);
static int descriptor_ready(asn_TYPE_descriptor_t *);
static void release_value(asn_TYPE_descriptor_t *, void *);
static int check_encoding(asn_TYPE_descriptor_t *, const void *, const uint8_t *,
                          size_t, int);
static int check_decoding(asn_TYPE_descriptor_t *, const void *, const uint8_t *,
                          size_t, int);

/* Validate callbacks required by the generic vector helpers.
 * Parameters: descriptor is the generated C type descriptor. Returns one when
 * comparison and free callbacks exist. Errors: absent operations return zero.
 * Source: asn_TYPE_operation_t. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: generic codec probes.
 * Example: descriptor_ready(&asn_DEF_OwnedPair).
 */
static int
descriptor_ready(asn_TYPE_descriptor_t *descriptor) {
    return descriptor && descriptor->op && descriptor->op->compare_struct
        && descriptor->op->free_struct;
}

/* Release a decoded value through its validated descriptor callback.
 * Parameters: descriptor owns value. Returns no value; invalid/null inputs are ignored.
 * Errors: none. Source: generated descriptor free callback. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported record probes.
 * Example: release_value(&asn_DEF_OwnedPair, decoded).
 */
static void
release_value(asn_TYPE_descriptor_t *descriptor, void *value) {
    if(descriptor_ready(descriptor) && value)
        descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
}

/* Compare one generated DER or CER encoding with its fixed vector.
 * Parameters: descriptor/value describe the object; wire/size are expected bytes;
 * canonical selects CER when nonzero. Returns zero on equality, one on error.
 * Source: generated C encoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: encoding vector helper.
 * Example: check_encoding(&asn_DEF_OwnedPair, &value, der, sizeof(der), 0).
 */
static int
check_encoding(asn_TYPE_descriptor_t *descriptor, const void *value,
               const uint8_t *wire, size_t size, int canonical) {
    uint8_t actual[WIRE_CAP];
    asn_enc_rval_t result;
    if(!descriptor_ready(descriptor) || !value || !wire
       || size > sizeof(actual)) return 1;
    result = canonical
        ? cer_encode_to_buffer(NULL, descriptor, value, actual, sizeof(actual))
        : der_encode_to_buffer(descriptor, value, actual, sizeof(actual));
    return result.encoded < 0 || (size_t)result.encoded != size
        || memcmp(actual, wire, size);
}

/* Decode one BER or strict-CER value and compare its generated structure.
 * Parameters: descriptor/value describe the object; wire/size are input bytes;
 * strict selects CER validation. Returns zero on semantic equality.
 * Errors: decode, consumption, compare, or callback errors return one.
 * Source: generated C decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: decode vector helper.
 * Example: check_decoding(&asn_DEF_OwnedPair, &value, cer, sizeof(cer), 1).
 */
static int
check_decoding(asn_TYPE_descriptor_t *descriptor, const void *value,
               const uint8_t *wire, size_t size, int strict) {
    void *decoded_value = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor_ready(descriptor) || !value || !wire || !size) return 1;
    result = strict ? cer_decode(NULL, descriptor, &decoded_value, wire, size)
                    : ber_decode(NULL, descriptor, &decoded_value, wire, size);
    failed = result.code != RC_OK || result.consumed != size || !decoded_value;
    if(!failed)
        failed = descriptor->op->compare_struct(descriptor, value, decoded_value) != 0;
    release_value(descriptor, decoded_value);
    return failed;
}

/* Compare DER/CER encoders and BER/CER decoders with one reference value.
 * Parameters: descriptor/value select the generated type; wire arrays are fixed TLVs.
 * Returns zero for exact bytes and semantic decode equality, one on mismatch.
 * Errors: codec, allocation, comparison, or length mismatch fails.
 * Source: generated C codecs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported owned/default probes.
 * Example: check_vectors(&asn_DEF_OwnedPair, &value, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_vectors(asn_TYPE_descriptor_t *descriptor, const void *value,
              const uint8_t *der, size_t der_size,
              const uint8_t *cer, size_t cer_size) {
    return !descriptor_ready(descriptor) || !value || !der || !cer
        || check_encoding(descriptor, value, der, der_size, 0)
        || check_encoding(descriptor, value, cer, cer_size, 1)
        || check_decoding(descriptor, value, der, der_size, 0)
        || check_decoding(descriptor, value, cer, cer_size, 1)
        || check_prefix(descriptor, der, der_size, 0)
        || check_prefix(descriptor, cer, cer_size, 1)
        || check_cer_rejects(descriptor, der, der_size);
}

/* Check one exact BER/CER prefix after appending a trailing sentinel octet.
 * Parameters: descriptor/wire/size identify the value; strict selects CER.
 * Returns zero for RC_OK and exact consumption; errors return one.
 * Source: generated prefix decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix checks.
 * Example: check_prefix(&asn_DEF_AlphaPacket, cer, sizeof(cer), 1).
 */
static int
check_prefix(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire,
             size_t size, int strict) {
    uint8_t input[WIRE_CAP + 1];
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor_ready(descriptor) || !wire || !size || size >= sizeof(input)) return 1;
    memcpy(input, wire, size);
    input[size] = 0xee;
    result = strict ? cer_decode(NULL, descriptor, &decoded, input, size + 1)
                    : ber_decode(NULL, descriptor, &decoded, input, size + 1);
    if(result.code != RC_OK || result.consumed != size || !decoded) {
        release_value(descriptor, decoded);
        return 1;
    }
    release_value(descriptor, decoded);
    return 0;
}

/* Require strict CER to reject one complete definite DER value.
 * Parameters: descriptor/wire/size identify the generated type and DER bytes.
 * Returns zero when the decoder rejects DER; errors return one.
 * Source: C strict-CER re-encoding adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: canonicality checks.
 * Example: reject definite wrappers around an imported constructed child.
 */
static int
check_cer_rejects(asn_TYPE_descriptor_t *descriptor, const uint8_t *wire,
                  size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor_ready(descriptor) || !wire || !size) return 1;
    result = cer_decode(NULL, descriptor, &decoded, wire, size);
    release_value(descriptor, decoded);
    return result.code == RC_OK;
}

/* Check DEFAULT omission and reject explicitly encoded default values as CER.
 * Parameters: none. Returns zero for BER compatibility and strict-CER rejection.
 * Errors: wrong decoded default values, missing fields, or accepted CER fail.
 * Source: ASN.1 DEFAULT rules. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: parent scalar defaults.
 * Example: BER accepts FALSE/3 defaults; strict CER requires omission.
 */
static int
check_explicit_defaults(void) {
    static const uint8_t der[] = {
        0x30, 0x0e, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
        0x01, 1, 0x00, 0x02, 1, 3,
    };
    static const uint8_t cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0x01, 1, 0x00, 0x02, 1, 3, 0, 0,
    };
    DefaultParent_t *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor_ready(&asn_DEF_DefaultParent)) return 1;
    result = ber_decode(NULL, &asn_DEF_DefaultParent, (void **)&decoded,
                        der, sizeof(der));
    failed = result.code != RC_OK || result.consumed != sizeof(der)
        || !decoded || !decoded->child || decoded->child->number != 2
        || decoded->enabled || !decoded->count || *decoded->count != 3;
    release_value(&asn_DEF_DefaultParent, decoded);
    return failed || check_cer_rejects(&asn_DEF_DefaultParent, der, sizeof(der))
        || check_cer_rejects(&asn_DEF_DefaultParent, cer, sizeof(cer));
}

/* Check target bounds stay independent for same-spelled imported assignments.
 * Parameters: none. Returns zero if Alpha rejects four and Beta accepts six.
 * Errors: constraint checker disagreement returns one.
 * Source: two source modules exporting distinct `Common` ranges.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: module-path and bound-isolation check.
 * Example: AlphaCommon accepts 0..3; BetaCommon accepts 0..7.
 */
static int
check_independent_ranges(void) {
    ImportedCommonAlphaSource_Common_t alpha = {.value = 4};
    ImportedCommonBetaSource_Common_t beta = {.value = 6};
    char diagnostic[128];
    size_t size = sizeof(diagnostic);
    int alpha_failed = asn_check_constraints(&asn_DEF_ImportedCommonAlphaSource_Common,
        &alpha, diagnostic, &size) != 0;
    size = sizeof(diagnostic);
    return !alpha_failed || asn_check_constraints(&asn_DEF_ImportedCommonBetaSource_Common,
        &beta, diagnostic, &size) != 0;
}

/* Check BER padding tolerance and second-child framing for owned BIT STRING leaves.
 * Parameters: canonical is one OwnedPair CER value. Returns zero on expected statuses.
 * Errors: BER padding rejection or malformed second-child acceptance returns one.
 * Source: X.690 BIT STRING padding and EXPLICIT framing. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: owned imported leaf errors.
 * Example: mutate the second child's packed-bit padding bits and constructed tag.
 */
static int
check_owned_mutations(const uint8_t *canonical, size_t size) {
    uint8_t bad_padding[WIRE_CAP];
    uint8_t bad_child[WIRE_CAP];
    void *decoded = NULL;
    asn_dec_rval_t result;
    if(!descriptor_ready(&asn_DEF_OwnedPair) || !canonical
       || size > sizeof(bad_padding) || size <= 25) return 1;
    memcpy(bad_padding, canonical, size);
    bad_padding[25] = 0xa1;
    result = ber_decode(NULL, &asn_DEF_OwnedPair, &decoded, bad_padding, size);
    if(result.code != RC_OK || result.consumed != size || !decoded) {
        fprintf(stderr, "padding BER status=%d consumed=%zu decoded=%d\n",
                result.code, result.consumed, decoded != NULL);
        release_value(&asn_DEF_OwnedPair, decoded);
        return 1;
    }
    release_value(&asn_DEF_OwnedPair, decoded);
    memcpy(bad_child, canonical, size);
    bad_child[16] = 0x31;
    decoded = NULL;
    result = ber_decode(NULL, &asn_DEF_OwnedPair, &decoded, bad_child, size);
    release_value(&asn_DEF_OwnedPair, decoded);
    if(result.code == RC_OK && result.consumed == size)
        fputs("malformed second child accepted\n", stderr);
    return result.code == RC_OK && result.consumed == size;
}

/* Compare extended imported-record C vectors and noncanonical cases.
 * Parameters: none. Returns zero for all fixed values, one on any mismatch.
 * Errors: encoder/decoder, range, padding, or default mismatch returns one.
 * Source: generated C reference vectors. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: owned/default extension.
 * Example: compare imported and local equivalent child operation values.
 */
int
main(void) {
    static const uint8_t owned_der[] = {
        0x30, 0x16, 0xa2, 0x08, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0,
        0xa3, 0x0a, 0x30, 0x08, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0,
    };
    static const uint8_t owned_cer[] = {
        0x30, 0x80, 0xa2, 0x80, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0, 0, 0,
        0xa3, 0x80, 0x30, 0x80, 0x04, 2, 0xaa, 0xbb, 0x03, 2, 5, 0xa0,
        0, 0, 0, 0, 0, 0,
    };
    static const uint8_t defaults_der[] = {
        0x30, 0x08, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t defaults_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t equivalent_der[] = {
        0x30, 0x0b, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff, 0x84, 1, 0xff,
    };
    static const uint8_t equivalent_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0x84, 1, 0xff, 0, 0,
    };
    static const uint8_t alpha_der[] = {0x30, 0x05, 0x30, 0x03, 0x02, 1, 2};
    static const uint8_t alpha_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0, 0, 0, 0,
    };
    static const uint8_t beta_der[] = {0x30, 0x05, 0x30, 0x03, 0x02, 1, 6};
    static const uint8_t beta_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 6, 0, 0, 0, 0,
    };
    uint8_t octets[] = {0xaa, 0xbb};
    uint8_t bits[] = {0xa0};
    BOOLEAN_t true_value = 1;
    int failed = 0;
    RemoteSeq_t remote = {.number = 2, .flag = &true_value};
    RemoteOwned_t owned_value = {0};
    OwnedPair_t owned = {0};
    DefaultParent_t defaults = {.child = &remote};
    LocalEquivalentLeaf_t local_leaf = {.number = 2, .flag = &true_value};
    LocalEquivalent_t local = {.child = &local_leaf, .tail = 1};
    ImportedEquivalent_t imported = {.child = &remote, .tail = 1};
    ImportedCommonAlphaSource_Common_t alpha_value = {.value = 2};
    ImportedCommonBetaSource_Common_t beta_value = {.value = 6};
    AlphaPacket_t alpha = {.child = &alpha_value};
    BetaPacket_t beta = {.child = &beta_value};
    owned_value.octets.buf = octets;
    owned_value.octets.size = sizeof(octets);
    owned_value.bits.buf = bits;
    owned_value.bits.size = sizeof(bits);
    owned_value.bits.bits_unused = 5;
    owned.implicitChild = &owned_value;
    owned.explicitChild = &owned_value;
    if(check_vectors(&asn_DEF_OwnedPair, &owned, owned_der, sizeof(owned_der),
                     owned_cer, sizeof(owned_cer))) {
        fputs("OwnedPair vectors failed\n", stderr);
        failed = 1;
    }
    if(check_vectors(&asn_DEF_DefaultParent, &defaults, defaults_der,
                     sizeof(defaults_der), defaults_cer, sizeof(defaults_cer))) {
        fputs("DefaultParent vectors failed\n", stderr);
        failed = 1;
    }
    if(check_vectors(&asn_DEF_LocalEquivalent, &local, equivalent_der,
                     sizeof(equivalent_der), equivalent_cer, sizeof(equivalent_cer))) {
        fputs("LocalEquivalent vectors failed\n", stderr);
        failed = 1;
    }
    if(check_vectors(&asn_DEF_ImportedEquivalent, &imported, equivalent_der,
                     sizeof(equivalent_der), equivalent_cer, sizeof(equivalent_cer))) {
        fputs("ImportedEquivalent vectors failed\n", stderr);
        failed = 1;
    }
    if(check_vectors(&asn_DEF_AlphaPacket, &alpha, alpha_der, sizeof(alpha_der),
                     alpha_cer, sizeof(alpha_cer))) {
        fputs("AlphaPacket vectors failed\n", stderr);
        failed = 1;
    }
    if(check_vectors(&asn_DEF_BetaPacket, &beta, beta_der, sizeof(beta_der),
                     beta_cer, sizeof(beta_cer))) {
        fputs("BetaPacket vectors failed\n", stderr);
        failed = 1;
    }
    if(check_explicit_defaults()) { fputs("explicit defaults failed\n", stderr); failed = 1; }
    if(check_independent_ranges()) { fputs("independent ranges failed\n", stderr); failed = 1; }
    if(check_owned_mutations(owned_cer, sizeof(owned_cer))) {
        fputs("owned mutations failed\n", stderr);
        failed = 1;
    }
    return failed;
}
