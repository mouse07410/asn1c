/* Check C selected OPEN TYPE CBOR vectors against generated Rust.
 * Source: C SEQUENCE and OPEN TYPE CBOR codecs. Version: 2026-10-30.
 * Responsible: maintainers. History: selected CBOR parity.
 */
#include <Packet.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#include <stdio.h>
#include <string.h>

/* Bounded callback output for one selected record. */
typedef struct output_s {
    unsigned char bytes[32]; /* Encoded byte state variable. */
    size_t used; /* Used output length state variable. */
} output_t;

/* Append a bounded fragment to the output.
 * Inputs: bytes/length are fragment; key is output. Returns zero/-1.
 * Errors: invalid input or overflow. Source: CBOR callback API.
 * Version: 2026-10-30. Responsible: maintainers. History: parity fixture.
 * Example: append("x", 1, &output).
 */
static int
append(const void *bytes, size_t length, void *key) {
    output_t *out = key;
    if(!out || (!bytes && length) || out->used > sizeof(out->bytes)
       || length > sizeof(out->bytes) - out->used) return -1;
    if(length) memcpy(out->bytes + out->used, bytes, length);
    out->used += length;
    return 0;
}

/* Encode and decode one selected value against the Rust map vector.
 * Inputs: selector/selected identify row and value; wire/length are expected.
 * Returns zero on parity or one on failure. Errors: none thrown.
 * Source: C CBOR OPEN TYPE API. Version: 2026-10-30. Responsible: maintainers.
 * History: selected map fixture. Example: check(1, 1, wire, 12).
 */
static int
check(long selector, long selected, const unsigned char *wire, size_t length) {
    Packet_t packet = {0};
    Packet_t *decoded = NULL;
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;
    packet.id = selector;
    if(selector == 1) {
        packet.value.present = value_PR_BOOLEAN;
        packet.value.choice.BOOLEAN = selected;
    } else if(selector == 2) {
        packet.value.present = value_PR_INTEGER_0_2_;
        packet.value.choice.INTEGER_0_2_ = selected;
    } else {
        packet.value.present = value_PR_INTEGER_5_5_;
        packet.value.choice.INTEGER_5_5_ = selected;
    }
    encoded = cbor_encode(&asn_DEF_Packet, &packet, append, &output);
    result = cbor_decode(NULL, &asn_DEF_Packet, (void **)&decoded, wire, length);
    failed = encoded.encoded != (ssize_t)length || output.used != length
        || memcmp(output.bytes, wire, length) || result.code != RC_OK
        || result.consumed != length || !decoded || decoded->id != selector
        || decoded->value.present != packet.value.present;
    if(decoded && selector == 1) failed |= !!decoded->value.choice.BOOLEAN != !!selected;
    if(decoded && selector == 2) failed |= decoded->value.choice.INTEGER_0_2_ != selected;
    if(decoded && selector == 3) failed |= decoded->value.choice.INTEGER_5_5_ != selected;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return failed;
}

/* Run selected CBOR map parity vectors.
 * Inputs: none. Returns zero/one. Errors: none thrown. Source: C mapping.
 * Version: 2026-10-30. Responsible: maintainers. History: parity fixture.
 * Example: run `./c-cbor-open-selected`.
 */
int
main(void) {
    const unsigned char yes[] = {0xa2, 0x62, 'i', 'd', 1, 0x65, 'v', 'a', 'l', 'u', 'e', 0xf5};
    const unsigned char two[] = {0xa2, 0x62, 'i', 'd', 2, 0x65, 'v', 'a', 'l', 'u', 'e', 2};
    const unsigned char five[] = {0xa2, 0x62, 'i', 'd', 3, 0x65, 'v', 'a', 'l', 'u', 'e', 5};
    if(check(1, 1, yes, sizeof(yes)) || check(2, 2, two, sizeof(two))
       || check(3, 5, five, sizeof(five))) {
        fputs("C CBOR selected OPEN TYPE mismatch\n", stderr);
        return 1;
    }
    return 0;
}
