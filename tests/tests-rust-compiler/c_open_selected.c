/* Compare generated C IOC-selected UPER vectors with Rust.
 * Source: generated C OPEN TYPE API. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: primitive selected OPEN TYPE.
 */
#include <Packet.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <stdio.h>
#include <string.h>

/* Encode and decode one selected value against a fixed vector.
 * Inputs: selector chooses row; boolean_value or integer_value supplies data;
 * wire is the expected three-octet value. Returns zero or one; no exceptions.
 * Source: generated UPER API. Version: 2026-10-30. Responsible: asn1c
 * maintainers. History: C/Rust interoperability. Example: check(1, 1, 0, wire).
 */
static int
check(long selector, int boolean_value, long integer_value, const unsigned char wire[3]) {
    Packet_t packet = {0};
    Packet_t *decoded = NULL;
    unsigned char output[3] = {0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;
    packet.id = selector;
    if(selector == 1) {
        packet.value.present = value_PR_BOOLEAN;
        packet.value.choice.BOOLEAN = boolean_value;
    } else if(selector == 2) {
        packet.value.present = value_PR_INTEGER_0_2_;
        packet.value.choice.INTEGER_0_2_ = integer_value;
    } else {
        packet.value.present = value_PR_INTEGER_5_5_;
        packet.value.choice.INTEGER_5_5_ = integer_value;
    }
    encoded = uper_encode_to_buffer(&asn_DEF_Packet, NULL, &packet, output, sizeof(output));
    result = uper_decode_complete(NULL, &asn_DEF_Packet, (void **)&decoded, wire, 3);
    failed = encoded.encoded != 24 || memcmp(output, wire, 3) || result.code != RC_OK
        || !decoded || decoded->id != selector || decoded->value.present != packet.value.present;
    if(decoded && selector == 1) failed |= !!decoded->value.choice.BOOLEAN != !!boolean_value;
    if(decoded && selector == 2) failed |= decoded->value.choice.INTEGER_0_2_ != integer_value;
    if(decoded && selector == 3) failed |= decoded->value.choice.INTEGER_5_5_ != integer_value;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return failed;
}

/* Run selected-row vectors. Inputs: none; returns zero or one; no exceptions.
 * Source: generated C UPER. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: primitive IOC parity. Example: ./c-open-selected.
 */
int
main(void) {
    const unsigned char yes[] = {1, 1, 0x80}, no[] = {1, 1, 0}, two[] = {2, 1, 0x80};
    const unsigned char singleton[] = {3, 1, 0};
    if(check(1, 1, 0, yes) || check(1, 0, 0, no) || check(2, 0, 2, two)
       || check(3, 0, 5, singleton)) {
        fputs("C selected OPEN TYPE vector mismatch\n", stderr);
        return 1;
    }
    return 0;
}
