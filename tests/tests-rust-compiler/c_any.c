/* Check independent ANY UPER vectors against the generated C codec.
 * Source: X.691 length framing. Version/date: 2026-10-30.
 * Responsible: asn1c maintainers. History: Rust interoperability.
 */
#include <Value.h>
#include <Packet.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Check one payload length and its expected determinant.
 * Inputs: length is the opaque byte count. Returns zero on success, one on
 * failure. No exceptions. Source: generated ANY UPER API. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: interoperability boundary vectors.
 * Example: check(128) checks the two-octet determinant.
 */
static int
check(size_t length) {
    Value_t value = {0};
    Value_t *decoded = NULL;
    size_t capacity = length + 3;
    unsigned char *wire = calloc(capacity, 1);
    unsigned char *payload = malloc(length ? length : 1);
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t header = length < 128 ? 1 : length < 16384 ? 2 : 1;
    int failed;
    if(!wire || !payload) { free(wire); free(payload); return 1; }
    memset(payload, 0xa5, length);
    value.buf = payload;
    value.size = (int)length;
    encoded = uper_encode_to_buffer(&asn_DEF_Value, NULL, &value, wire, capacity);
    if(encoded.encoded < 0) { free(payload); free(wire); return 1; }
    result = uper_decode_complete(NULL, &asn_DEF_Value, (void **)&decoded, wire,
                                  (size_t)(encoded.encoded + 7) / 8);
    failed = encoded.encoded != (ssize_t)((length + header + (length == 16384)) * 8)
        || wire[0] != (length < 128 ? length : length < 16384 ? (0x80 | (length >> 8)) : 0xc1)
        || (length >= 128 && length < 16384 && wire[1] != (length & 255))
        || (length && memcmp(wire + header, payload, length))
        || (length == 16384 && wire[length + header] != 0)
        || result.code != RC_OK || !decoded || decoded->size != (int)length
        || (length && memcmp(decoded->buf, payload, length));
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Value, decoded);
    free(payload);
    free(wire);
    return failed;
}

/* Compare an OPTIONAL ANY packed after two presence/value bits.
 * Inputs: none. Returns zero on success, one on mismatch. No exceptions.
 * Source: UPER SEQUENCE and ANY framing. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: shared-cursor interoperability.
 * Example: check_packet() verifies the independent Rust wire vector.
 */
static int
check_packet(void) {
    unsigned char data[] = {0xa5};
    unsigned char expected[] = {0xc0, 0x69, 0x40};
    unsigned char output[sizeof(expected)] = {0};
    ANY_t payload = {0};
    Packet_t packet = {0};
    Packet_t *decoded = NULL;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    int failed;
    payload.buf = data;
    payload.size = 1;
    packet.flag = 1;
    packet.payload = &payload;
    encoded = uper_encode_to_buffer(&asn_DEF_Packet, NULL, &packet, output, sizeof(output));
    result = uper_decode_complete(NULL, &asn_DEF_Packet, (void **)&decoded, expected, sizeof(expected));
    failed = encoded.encoded != 18 || memcmp(output, expected, sizeof(expected))
        || result.code != RC_OK || !decoded || !decoded->payload || decoded->payload->size != 1
        || decoded->payload->buf[0] != 0xa5 || !decoded->flag;
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Packet, decoded);
    return failed;
}

/* Run boundary vectors. Inputs: none. Returns zero on success, one on failure.
 * No exceptions. Source: ANY UPER framing. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: C parity. Example: ./c-any.
 */
int
main(void) {
    if(check(0) || check(1) || check(127) || check(128) || check(16383) || check(16384) || check_packet()) {
        fputs("C ANY UPER vector mismatch\n", stderr);
        return 1;
    }
    return 0;
}
