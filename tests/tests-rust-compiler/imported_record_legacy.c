/* C vectors for imported record forms converted from existing rejection tests.
 * Source: ImportedRecordLegacy*.asn1 and generated C codec APIs.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * Example: compile against generated legacy-c and run for three DER/CER pairs.
 */
#include <stdint.h>
#include <string.h>
#include "BooleanSequence.h"
#include "BooleanSet.h"
#include "IntegerChild.h"
#include "ImportedRecordConstructedClient_Packet.h"
#include "ImportedRecordSequenceClient_Packet.h"
#include "ImportedRecordSetClient_Packet.h"
#include "ber_decoder.h"
#include "cer_decoder.h"
#include "cer_encoder.h"
#include "der_encoder.h"

#define WIRE_CAP 32

/* Validate descriptor callbacks before generic compare/free operations.
 * Parameters: descriptor identifies one generated top-level type.
 * Returns one when compare and free callbacks exist; otherwise zero.
 * Errors: missing descriptor operations return zero.
 * Source: asn_TYPE_operation_t. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: legacy conversion vectors.
 * Example: descriptor_ready(&asn_DEF_ImportedRecordConstructedClient_Packet).
 */
static int
descriptor_ready(asn_TYPE_descriptor_t *descriptor) {
    return descriptor && descriptor->op && descriptor->op->compare_struct
        && descriptor->op->free_struct;
}

/* Free one decoded value through the checked generated callback.
 * Parameters: descriptor owns value. Returns no value; null inputs are ignored.
 * Errors: none. Source: generated descriptor callback. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: legacy conversion vectors.
 * Example: release_value(&asn_DEF_ImportedRecordSetClient_Packet, decoded).
 */
static void
release_value(asn_TYPE_descriptor_t *descriptor, void *value) {
    if(descriptor_ready(descriptor) && value)
        descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
}

/* Compare one DER or CER encoding against its fixed reference bytes.
 * Parameters: descriptor/value identify the generated value; wire/size are
 * expected bytes; canonical selects CER. Returns zero on equality, one on error.
 * Errors: invalid arguments, encoding failure, or byte mismatch return one.
 * Source: generated C DER/CER encoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: legacy conversion vectors.
 * Example: check_encoding(&asn_DEF_..., &value, der, sizeof(der), 0).
 */
static int
check_encoding(asn_TYPE_descriptor_t *descriptor, const void *value,
               const uint8_t *wire, size_t size, int canonical) {
    uint8_t actual[WIRE_CAP];
    asn_enc_rval_t result;
    if(!descriptor_ready(descriptor) || !value || !wire || size > sizeof(actual))
        return 1;
    result = canonical
        ? cer_encode_to_buffer(NULL, descriptor, value, actual, sizeof(actual))
        : der_encode_to_buffer(descriptor, value, actual, sizeof(actual));
    return result.encoded < 0 || (size_t)result.encoded != size
        || memcmp(actual, wire, size);
}

/* Decode one BER or strict-CER value and compare the decoded structure.
 * Parameters: descriptor/value identify the generated type; wire/size are input;
 * strict selects CER. Returns zero on semantic equality; otherwise one.
 * Errors: invalid arguments, decoder failure, or mismatch return one.
 * Source: generated C BER/CER decoders. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: legacy conversion vectors.
 * Example: check_decoding(&asn_DEF_..., &value, cer, sizeof(cer), 1).
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

/* Compare a generated value with exact DER/CER bytes and decoder results.
 * Parameters: descriptor/value identify the value; der/cer are independent TLVs.
 * Returns zero when both encoders and decoders agree; one on any mismatch.
 * Errors: invalid inputs, codec errors, or byte/structure mismatch return one.
 * Source: generated C codecs and fixed Rust conformance vectors.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: imported record former-negative conversion. Example: BooleanSet child.
 */
static int
check_vectors(asn_TYPE_descriptor_t *descriptor, const void *value,
              const uint8_t *der, size_t der_size,
              const uint8_t *cer, size_t cer_size) {
    return !descriptor_ready(descriptor) || !value || !der || !cer
        || check_encoding(descriptor, value, der, der_size, 0)
        || check_encoding(descriptor, value, cer, cer_size, 1)
        || check_decoding(descriptor, value, der, der_size, 0)
        || check_decoding(descriptor, value, cer, cer_size, 1);
}

/* Compare imported INTEGER-SEQUENCE, BOOLEAN-SEQUENCE, and BOOLEAN-SET vectors.
 * Parameters: none. Returns zero on success, one for any C codec/vector mismatch.
 * Errors: C encoding, decoding, or structure comparison failures return one.
 * Source: imported record acceptance probes. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: former rejection conversions.
 * Example: the parent Packet contains a directly imported BooleanSet.
 */
int
main(void) {
    static const uint8_t integer_der[] = {0x30, 5, 0x30, 3, 2, 1, 2};
    static const uint8_t integer_cer[] = {
        0x30, 0x80, 0x30, 0x80, 2, 1, 2, 0, 0, 0, 0,
    };
    static const uint8_t sequence_der[] = {0x30, 5, 0x30, 3, 1, 1, 0xff};
    static const uint8_t sequence_cer[] = {
        0x30, 0x80, 0x30, 0x80, 1, 1, 0xff, 0, 0, 0, 0,
    };
    static const uint8_t set_der[] = {0x30, 5, 0x31, 3, 1, 1, 0xff};
    static const uint8_t set_cer[] = {0x30, 0x80, 0x31, 0x80, 1, 1, 0xff, 0, 0, 0, 0};
    IntegerChild_t integer = {.value = 2};
    BooleanSequence_t sequence = {.flag = 1};
    BooleanSet_t set = {.flag = 1};
    ImportedRecordConstructedClient_Packet_t integer_parent = {.value = &integer};
    ImportedRecordSequenceClient_Packet_t sequence_parent = {.child = &sequence};
    ImportedRecordSetClient_Packet_t set_parent = {.child = &set};
    ASN_SET_MKPRESENT(set._presence_map, BooleanSet_PR_flag);
    return check_vectors(&asn_DEF_ImportedRecordConstructedClient_Packet,
                         &integer_parent, integer_der, sizeof(integer_der),
                         integer_cer, sizeof(integer_cer))
        || check_vectors(&asn_DEF_ImportedRecordSequenceClient_Packet,
                         &sequence_parent, sequence_der, sizeof(sequence_der),
                         sequence_cer, sizeof(sequence_cer))
        || check_vectors(&asn_DEF_ImportedRecordSetClient_Packet,
                         &set_parent, set_der, sizeof(set_der), set_cer, sizeof(set_cer));
}
