/* Cross-check inline OPTIONAL enumeration UPER bytes with generated C.
 * Source: X.691 root indices. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: inline enum parity.
 * Example: compile with the generated Packet codec and run.
 */
#include <Packet.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <stdio.h>

/* Compare one value and decode the independent Rust-compatible vector.
 * Parameters: number is an optional enum value; expected is its wire byte.
 * Returns zero on success or one on failure; no exceptions are thrown.
 * Source: generated UPER API. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: inline enum parity.
 * Example: check(NULL, 0x40) checks an absent field.
 */
static int
check(long *number, unsigned char expected) {
    Packet_t packet = {0};
    Packet_t *decoded = NULL;
    unsigned char output[1] = {0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;
    packet.enabled = 1;
    packet.maybe = number;
    packet.single = single_only;
    encoded = uper_encode_to_buffer(&asn_DEF_Packet, NULL, &packet, output, sizeof(output));
    result = uper_decode_complete(NULL, &asn_DEF_Packet, (void **)&decoded, &expected, 1);
    failed = encoded.encoded != (number ? 4 : 2) || output[0] != expected
             || result.code != RC_OK || !decoded || decoded->enabled != 1
             || decoded->single != single_only || (!!decoded->maybe != !!number)
             || (number && decoded && decoded->maybe && *decoded->maybe != *number);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return failed;
}

/* Run present, absent and numeric-order vectors. Inputs: no arguments.
 * Returns zero on success or one on mismatch; no exceptions are thrown.
 * Source: independent fixed vectors. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: inline enum parity.
 * Example: ./c-sequence-enum.
 */
int
main(void) {
    long low = maybe_low, middle = maybe_middle, high = maybe_high;
    if(check(NULL, 0x40) || check(&low, 0xc0) || check(&middle, 0xd0)
       || check(&high, 0xe0)) {
        fputs("C inline ENUMERATED UPER mismatch\n", stderr);
        return 1;
    }
    return 0;
}
