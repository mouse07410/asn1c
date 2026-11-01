/* C DER/CER reference vectors for direct imported SEQUENCE/SET children.
 * Source: split-file imported record schemas and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported named-record slice.
 * Example: compile with generated c-gen and run for exact encodings and decode checks.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "EmptyPair.h"
#include "NonemptySetPair.h"
#include "OptionalOrder.h"
#include "RepeatedPair.h"
#include "SeqPair.h"
#include "SetPair.h"
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
 * Parameters: td is the generated C descriptor. Returns one when compare/free
 * callbacks exist. Errors: missing descriptor operations return zero.
 * Source: asn_TYPE_operation_t. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: generic codec probes.
 * Example: descriptor_ready(&asn_DEF_SeqPair).
 */
static int
descriptor_ready(asn_TYPE_descriptor_t *td) {
    return td && td->op && td->op->compare_struct && td->op->free_struct;
}

/* Release a decoded C value through its validated descriptor callback.
 * Parameters: td owns value. Returns no value; null or incomplete inputs are ignored.
 * Errors: none. Source: generated descriptor free callback. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported record probes.
 * Example: release_value(&asn_DEF_SeqPair, decoded).
 */
static void
release_value(asn_TYPE_descriptor_t *td, void *value) {
    if(descriptor_ready(td) && value)
        td->op->free_struct(td, value, ASFM_FREE_EVERYTHING);
}

/* Compare one generated DER or CER encoding with its fixed vector.
 * Parameters: td/value describe the object; wire/size are expected bytes;
 * canonical selects CER when nonzero. Returns zero on equality, one on error.
 * Source: generated C encoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: encoding vector helper.
 * Example: check_encoding(&asn_DEF_SeqPair, &value, der, sizeof(der), 0).
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
 * Example: check_decoding(&asn_DEF_SeqPair, &value, cer, sizeof(cer), 1).
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
    if(!failed) failed = td->op->compare_struct(td, value, decoded_value) != 0;
    release_value(td, decoded_value);
    return failed;
}

/* Compare encoders and decoders with independent DER/CER vectors.
 * Parameters: td/value identify the C type and source value; der/cer are wire TLVs.
 * Returns zero for byte and semantic equality. Errors return one; no exceptions.
 * Source: generated C codec APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported records.
 * Example: check_vectors(&asn_DEF_SeqPair, &value, der, sizeof(der), cer, sizeof(cer)).
 */
static int
check_vectors(asn_TYPE_descriptor_t *td, const void *value,
              const uint8_t *der, size_t der_size,
              const uint8_t *cer, size_t cer_size) {
    return !descriptor_ready(td) || !value || !der || !cer
        || check_encoding(td, value, der, der_size, 0)
        || check_encoding(td, value, cer, cer_size, 1)
        || check_decoding(td, value, der, der_size, 0)
        || check_decoding(td, value, cer, cer_size, 1)
        || check_prefix(td, der, der_size, 0)
        || check_prefix(td, cer, cer_size, 1)
        || check_cer_rejects(td, der, der_size);
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
    return result.code == RC_OK;
}

/* Check the decoded semantic value of a reversed SET pair.
 * Parameters: value is the decoded SetPair. Returns one when both children
 * match their reference fields. Errors: absent or mismatched fields return zero.
 * Source: fixed C SET-order probe. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: canonical-order regression.
 * Example: set_pair_value_matches(decoded) after BER decoding reversed members.
 */
static int
set_pair_value_matches(const SetPair_t *value) {
    return value && value->imported && value->imported->number == 2
        && value->imported->flag && value->local && value->local->number == 3
        && value->local->flag;
}

/* Confirm BER accepts reversed parent and child SET members but CER rejects them.
 * Parameters: none. Returns zero for unordered BER and strict-CER rejection.
 * Errors: decoder status, value, or order mismatch returns one.
 * Source: X.690 SET component order. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported SET composition.
 * Example: child SET [1] appears before [0], and the parent SET's SET precedes SEQUENCE.
 */
static int
check_reversed_set_order(void) {
    static const uint8_t reversed[] = {
        0x31, 0x10, 0x31, 0x06, 0x81, 1, 0xff, 0x80, 1, 2,
        0x30, 0x06, 0x02, 1, 3, 0x01, 1, 0xff,
    };
    static const uint8_t reversed_cer[] = {
        0x31, 0x80, 0x31, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 0,
        0x30, 0x80, 0x02, 1, 3, 0x01, 1, 0xff, 0, 0, 0, 0,
    };
    SetPair_t *decoded = NULL;
    asn_dec_rval_t result;
    int failed;
    if(!descriptor_ready(&asn_DEF_SetPair)) return 1;
    result = ber_decode(NULL, &asn_DEF_SetPair, (void **)&decoded,
                        reversed, sizeof(reversed));
    failed = result.code != RC_OK || result.consumed != sizeof(reversed)
        || !set_pair_value_matches(decoded);
    release_value(&asn_DEF_SetPair, decoded);
    if(failed || check_cer_rejects(&asn_DEF_SetPair, reversed, sizeof(reversed)))
        return 1;
    decoded = NULL;
    result = ber_decode(NULL, &asn_DEF_SetPair, (void **)&decoded,
                        reversed_cer, sizeof(reversed_cer));
    failed = result.code != RC_OK || result.consumed != sizeof(reversed_cer)
        || !set_pair_value_matches(decoded);
    release_value(&asn_DEF_SetPair, decoded);
    return failed || check_cer_rejects(&asn_DEF_SetPair, reversed_cer,
                                       sizeof(reversed_cer));
}

/* Confirm optional imported-child and child-leaf absence survives BER decode.
 * Parameters: none. Returns zero when both absent values decode correctly.
 * Errors: malformed wire, wrong prefix, or unexpected field presence returns one.
 * Source: ASN.1 OPTIONAL and generated C BER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: imported optional fields.
 * Example: an absent RemoteSeq.flag and absent EXPLICIT parent child are preserved.
 */
static int
check_optional_absence(void) {
    static const uint8_t leaf_absent[] = {
        0x30, 0x0d, 0x30, 0x03, 0x02, 1, 2,
        0x31, 0x06, 0x80, 1, 3, 0x81, 1, 0xff,
    };
    static const uint8_t child_absent[] = {
        0x31, 0x0b, 0x80, 1, 0xff, 0xa2, 0x06,
        0x02, 1, 2, 0x01, 1, 0xff,
    };
    SeqPair_t *sequence = NULL;
    OptionalOrder_t *set = NULL;
    asn_dec_rval_t first;
    asn_dec_rval_t second;
    int failed;
    if(!descriptor_ready(&asn_DEF_SeqPair)
       || !descriptor_ready(&asn_DEF_OptionalOrder)) return 1;
    first = ber_decode(NULL, &asn_DEF_SeqPair, (void **)&sequence,
                       leaf_absent, sizeof(leaf_absent));
    second = ber_decode(NULL, &asn_DEF_OptionalOrder, (void **)&set,
                        child_absent, sizeof(child_absent));
    failed = first.code != RC_OK || first.consumed != sizeof(leaf_absent)
        || !sequence || !sequence->imported || sequence->imported->flag
        || second.code != RC_OK || second.consumed != sizeof(child_absent) || !set
        || set->explicitChild || !set->marker || !set->implicitChild;
    release_value(&asn_DEF_SeqPair, sequence);
    release_value(&asn_DEF_OptionalOrder, set);
    return failed;
}

/* Encode all imported record shapes and exercise boundary behavior.
 * Parameters: none. Returns zero for all fixed vectors and malformed cases.
 * Errors: C encoder/decoder mismatch or invalid wrapper acceptance returns one.
 * Source: imported-record ASN.1 fixtures. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: cross-module record parity.
 * Example: main compares natural, tagged, repeated, optional, empty, and SET targets.
 */
int
main(void) {
    static const uint8_t seq_der[] = {
        0x30, 0x10, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
        0x31, 0x06, 0x80, 1, 3, 0x81, 1, 0xff,
    };
    static const uint8_t seq_cer[] = {
        0x30, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0x31, 0x80, 0x80, 1, 3, 0x81, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t set_der[] = {
        0x31, 0x10, 0x30, 0x06, 0x02, 1, 3, 0x01, 1, 0xff,
        0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    };
    static const uint8_t set_cer[] = {
        0x31, 0x80, 0x30, 0x80, 0x02, 1, 3, 0x01, 1, 0xff, 0, 0,
        0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t repeated_der[] = {
        0x30, 0x12, 0xa2, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
        0xa3, 0x08, 0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t repeated_cer[] = {
        0x30, 0x80, 0xa2, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0, 0, 0, 0,
    };
    static const uint8_t optional_der[] = {
        0x31, 0x0b, 0x80, 1, 0xff, 0xa2, 0x06,
        0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t optional_cer[] = {
        0x31, 0x80, 0x80, 1, 0xff, 0xa2, 0x80,
        0x02, 1, 2, 0x01, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t optional_present_der[] = {
        0x31, 0x15, 0x80, 1, 0xff, 0xa2, 0x06,
        0x02, 1, 2, 0x01, 1, 0xff, 0xa3, 0x08,
        0x30, 0x06, 0x02, 1, 2, 0x01, 1, 0xff,
    };
    static const uint8_t optional_present_cer[] = {
        0x31, 0x80, 0x80, 1, 0xff, 0xa2, 0x80,
        0x02, 1, 2, 0x01, 1, 0xff, 0, 0,
        0xa3, 0x80, 0x30, 0x80, 0x02, 1, 2, 0x01, 1, 0xff,
        0, 0, 0, 0, 0, 0,
    };
    static const uint8_t empty_der[] = {0x30, 0x02, 0x30, 0x00};
    static const uint8_t empty_cer[] = {0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0};
    static const uint8_t child_set_der[] = {
        0x30, 0x08, 0x31, 0x06, 0x80, 1, 2, 0x81, 1, 0xff,
    };
    static const uint8_t child_set_cer[] = {
        0x30, 0x80, 0x31, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0, 0, 0,
    };
    BOOLEAN_t true_value = 1;
    RemoteSeq_t remote = {.number = 2, .flag = &true_value};
    LocalSet_t local_set = {.number = 3, .flag = 1};
    LocalPairSeq_t local_sequence = {.number = 3, .flag = 1};
    NonemptyRemoteSet_t remote_set = {.number = 2, .flag = 1};
    SeqPair_t sequence_pair = {.imported = &remote, .local = &local_set};
    SetPair_t set_pair = {.imported = &remote_set, .local = &local_sequence};
    RepeatedPair_t repeated = {.implicitChild = &remote, .explicitChild = &remote};
    OptionalOrder_t optional = {.marker = 1, .implicitChild = &remote};
    OptionalOrder_t optional_present = {.marker = 1, .implicitChild = &remote};
    EmptyRemoteSeq_t empty_child = {0};
    EmptyPair_t empty = {.child = &empty_child};
    NonemptyRemoteSet_t nested_set = {.number = 2, .flag = 1};
    NonemptySetPair_t set_child = {.child = &nested_set};
    int failed = 0;
    optional_present.explicitChild = &remote;
    ASN_SET_MKPRESENT(local_set._presence_map, LocalSet_PR_number);
    ASN_SET_MKPRESENT(local_set._presence_map, LocalSet_PR_flag);
    ASN_SET_MKPRESENT(remote_set._presence_map, NonemptyRemoteSet_PR_number);
    ASN_SET_MKPRESENT(remote_set._presence_map, NonemptyRemoteSet_PR_flag);
    ASN_SET_MKPRESENT(set_pair._presence_map, SetPair_PR_imported);
    ASN_SET_MKPRESENT(set_pair._presence_map, SetPair_PR_local);
    ASN_SET_MKPRESENT(optional._presence_map, OptionalOrder_PR_marker);
    ASN_SET_MKPRESENT(optional._presence_map, OptionalOrder_PR_implicitChild);
    ASN_SET_MKPRESENT(optional_present._presence_map, OptionalOrder_PR_marker);
    ASN_SET_MKPRESENT(optional_present._presence_map, OptionalOrder_PR_implicitChild);
    ASN_SET_MKPRESENT(optional_present._presence_map, OptionalOrder_PR_explicitChild);
    ASN_SET_MKPRESENT(nested_set._presence_map, NonemptyRemoteSet_PR_number);
    ASN_SET_MKPRESENT(nested_set._presence_map, NonemptyRemoteSet_PR_flag);
    failed |= check_vectors(&asn_DEF_SeqPair, &sequence_pair,
                            seq_der, sizeof(seq_der), seq_cer, sizeof(seq_cer));
    failed |= check_vectors(&asn_DEF_SetPair, &set_pair,
                            set_der, sizeof(set_der), set_cer, sizeof(set_cer));
    failed |= check_vectors(&asn_DEF_RepeatedPair, &repeated,
                            repeated_der, sizeof(repeated_der),
                            repeated_cer, sizeof(repeated_cer));
    failed |= check_vectors(&asn_DEF_OptionalOrder, &optional,
                            optional_der, sizeof(optional_der), optional_cer,
                            sizeof(optional_cer));
    failed |= check_vectors(&asn_DEF_OptionalOrder, &optional_present,
                            optional_present_der, sizeof(optional_present_der),
                            optional_present_cer, sizeof(optional_present_cer));
    failed |= check_vectors(&asn_DEF_EmptyPair, &empty,
                            empty_der, sizeof(empty_der), empty_cer, sizeof(empty_cer));
    failed |= check_vectors(&asn_DEF_NonemptySetPair, &set_child,
                            child_set_der, sizeof(child_set_der),
                            child_set_cer, sizeof(child_set_cer));
    failed |= check_reversed_set_order();
    failed |= check_optional_absence();
    if(failed) fputs("imported record C vectors failed\n", stderr);
    return failed;
}
