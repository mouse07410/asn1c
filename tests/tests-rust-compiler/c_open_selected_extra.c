/* Compare selected APER and OER OPEN TYPE records with Rust vectors.
 * Source: generated C codecs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: selected primitive codec parity.
 */
#include <Packet.h>
#include <aper_encoder.h>
#include <aper_decoder.h>
#include <oer_encoder.h>
#include <oer_decoder.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test one generated selector, selected arm, and expected APER/OER bytes.
 * Inputs: row identifies one of three variants; vectors carry three bytes.
 * Returns zero on success or one on failure; no exceptions. Source: generated
 * codec APIs. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: cross-language vectors. Example: check(1, aper, oer).
 */
static int
check(int row, const unsigned char aper[3], const unsigned char oer[3]) {
    Packet_t packet = {0}, *decoded = NULL;
    unsigned char output[8] = {0};
    void *aper_output = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    ssize_t length;
    int failed;
    packet.id = row;
    if(row == 1) { packet.value.present = value_PR_BOOLEAN; packet.value.choice.BOOLEAN = 1; }
    else if(row == 2) { packet.value.present = value_PR_INTEGER_0_2_; packet.value.choice.INTEGER_0_2_ = 2; }
    else { packet.value.present = value_PR_INTEGER_5_5_; packet.value.choice.INTEGER_5_5_ = 5; }
    length = aper_encode_to_new_buffer(&asn_DEF_Packet, NULL, &packet, &aper_output);
    failed = length != 3 || !aper_output || (aper_output && memcmp(aper_output, aper, 3));
    result = aper_decode_complete(NULL, &asn_DEF_Packet, (void **)&decoded, aper, 3);
    failed |= result.code != RC_OK || !decoded || decoded->id != row
        || decoded->value.present != packet.value.present;
    if(decoded && row == 1) failed |= !decoded->value.choice.BOOLEAN;
    if(decoded && row == 2) failed |= decoded->value.choice.INTEGER_0_2_ != 2;
    if(decoded && row == 3) failed |= decoded->value.choice.INTEGER_5_5_ != 5;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    decoded = NULL;
    free(aper_output);
    encoded = oer_encode_to_buffer(&asn_DEF_Packet, NULL, &packet, output, sizeof(output));
    failed |= encoded.encoded != 3 || memcmp(output, oer, 3);
    result = oer_decode(NULL, &asn_DEF_Packet, (void **)&decoded, oer, 3);
    failed |= result.code != RC_OK || !decoded || decoded->id != row
        || decoded->value.present != packet.value.present;
    if(decoded && row == 1) failed |= !decoded->value.choice.BOOLEAN;
    if(decoded && row == 2) failed |= decoded->value.choice.INTEGER_0_2_ != 2;
    if(decoded && row == 3) failed |= decoded->value.choice.INTEGER_5_5_ != 5;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return failed;
}

/* Run BOOLEAN, bounded INTEGER and singleton INTEGER vectors.
 * Inputs: none; returns zero or one; no exceptions. Source: generated codecs.
 * Version: 2026-10-30. Responsible: asn1c maintainers. History: parity tests.
 * Example: ./c-open-selected-extra.
 */
int
main(void) {
    const unsigned char a1[] = {1, 1, 0x80}, o1[] = {1, 1, 0xff};
    const unsigned char a2[] = {2, 1, 0x80}, o2[] = {2, 1, 2};
    const unsigned char a3[] = {3, 1, 0}, o3[] = {3, 1, 5};
    if(check(1, a1, o1) || check(2, a2, o2) || check(3, a3, o3)) {
        fputs("C APER/OER selected OPEN TYPE mismatch\n", stderr);
        return 1;
    }
    return 0;
}
