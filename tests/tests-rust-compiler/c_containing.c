/* Check C string wire vectors and contained-value validation.
 * Source: X.691 and generated C descriptors. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: Rust CONTAINING parity.
 */
#include <Oct.h>
#include <Bits.h>
#include <BoolOct.h>
#include <BoolBits.h>
#include <Packet.h>
#include <uper_encoder.h>
#include <stdio.h>
#include <string.h>

/* Validate and encode a string against the independent Rust vector.
 * Inputs: type and value identify the C string; expected is its wire bytes;
 * bit_count is the encoded meaningful length. Returns zero or one; no exceptions.
 * Source: generated constraint and UPER APIs. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: contained primitive tests.
 * Example: check(&asn_DEF_Oct, &octets, vector, 16).
 */
static int
check(asn_TYPE_descriptor_t *type, void *value, const unsigned char *expected, int bit_count) {
    unsigned char output[2] = {0};
    asn_enc_rval_t result;
    if(asn_check_constraints_with_syntax(type, value, ATS_UNALIGNED_BASIC_PER, NULL, NULL)) return 1;
    result = uper_encode_to_buffer(type, NULL, value, output, sizeof(output));
    return result.encoded != bit_count || memcmp(output, expected, sizeof(output));
}

/* Compare unaligned required and OPTIONAL CONTAINING fields.
 * Inputs: none; returns zero or one; no exceptions. Source: UPER vectors.
 * Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: composed CONTAINING values. Example: check_packet().
 */
static int
check_packet(void) {
    unsigned char bits[] = {0x80}, output[4] = {0};
    const unsigned char expected[] = {0xc0, 0x60, 0, 0x60};
    OCTET_STRING_t inner = {0};
    Packet_t packet = {0};
    asn_enc_rval_t result;
    inner.buf = bits; inner.size = 1;
    packet.x = 1; packet.i = &inner;
    packet.b.buf = bits; packet.b.size = 1; packet.b.bits_unused = 7;
    result = uper_encode_to_buffer(&asn_DEF_Packet, NULL, &packet, output, sizeof(output));
    return result.encoded != 27 || memcmp(output, expected, sizeof(expected));
}

/* Check integer and BOOLEAN contents in octet and bit strings.
 * Inputs: none. Returns zero or one; no exceptions. Source: UPER vectors.
 * Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: C/Rust parity. Example: ./c-containing.
 */
int
main(void) {
    unsigned char valid[] = {0x80}, invalid[] = {0xc0}, padding[] = {0x81};
    unsigned char octet_wire[] = {1, 0x80}, bit_wire[] = {2, 0x80}, bool_wire[] = {1, 0x80};
    Oct_t octets = {0};
    Bits_t bits = {0};
    BoolOct_t bool_octets = {0};
    BoolBits_t bool_bits = {0};
    octets.buf = valid; octets.size = 1;
    bits.buf = valid; bits.size = 1; bits.bits_unused = 6;
    bool_octets.buf = valid; bool_octets.size = 1;
    bool_bits.buf = valid; bool_bits.size = 1; bool_bits.bits_unused = 7;
    if(check(&asn_DEF_Oct, &octets, octet_wire, 16)
       || check(&asn_DEF_Bits, &bits, bit_wire, 10)
       || check(&asn_DEF_BoolOct, &bool_octets, bool_wire, 16)
       || check(&asn_DEF_BoolBits, &bool_bits, bool_wire, 9) || check_packet()) return 1;
    octets.buf = invalid;
    if(!asn_check_constraints_with_syntax(&asn_DEF_Oct, &octets, ATS_UNALIGNED_BASIC_PER, NULL, NULL)) return 1;
    octets.buf = padding;
    if(!asn_check_constraints_with_syntax(&asn_DEF_Oct, &octets, ATS_UNALIGNED_BASIC_PER, NULL, NULL)) return 1;
    return 0;
}
