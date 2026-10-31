/* Compare a wide OER selector and integer selected value with Rust.
 * Source: generated OER codecs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: wide OER parity.
 */
#include <Packet.h>
#include <oer_encoder.h>
#include <oer_decoder.h>
#include <string.h>

/* Check the independent five-octet vector. Inputs: none; returns zero or one;
 * no exceptions. Source: generated OER API. Version: 2026-10-30. Responsible:
 * asn1c maintainers. History: wide selected values. Example: ./c-open-wide.
 */
int
main(void) {
    const unsigned char expected[] = {0, 2, 2, 1, 0};
    unsigned char output[sizeof(expected)] = {0};
    Packet_t packet = {0}, *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;
    packet.id = 2;
    packet.value.present = value_PR_INTEGER_0_256_;
    packet.value.choice.INTEGER_0_256_ = 256;
    encoded = oer_encode_to_buffer(&asn_DEF_Packet, NULL, &packet, output, sizeof(output));
    result = oer_decode(NULL, &asn_DEF_Packet, (void **)&decoded, expected, sizeof(expected));
    failed = encoded.encoded != sizeof(expected) || memcmp(output, expected, sizeof(expected))
        || result.code != RC_OK || !decoded || decoded->id != 2
        || decoded->value.present != value_PR_INTEGER_0_256_
        || decoded->value.choice.INTEGER_0_256_ != 256;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return failed;
}
