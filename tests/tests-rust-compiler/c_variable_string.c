/*
 * Compare bounded OCTET STRING UPER values between generated C and Rust vectors.
 * Original source: asn1c generated-code regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: bounded octet UPER slice.
 * Example: compile beside VariableString C sources and run without arguments.
 */
#include <asn_application.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <Data.h>
#include <Packet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * One expected complete UPER encoding and its source value.
 * Members describe immutable configuration for one C/Rust vector comparison.
 */
typedef struct variable_string_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated C type descriptor. */
    const void *value;                 /* Valid source value. */
    const unsigned char *bytes;        /* Expected complete output bytes. */
    size_t byte_len;                   /* Expected complete output length. */
    size_t bit_len;                    /* Expected meaningful bit count. */
    const char *name;                  /* Diagnostic vector name. */
} variable_string_case_t;

/*
 * Compare one C encoding and decoding with a fixed independent vector.
 * Parameters: item supplies descriptor, value, and expected encoding.
 * Returns zero on match and one on error; no exception is thrown.
 * Original source: generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: bounded octets.
 * Example: check_case(&cases[0]).
 */
static int
check_case(const variable_string_case_t *item) {
    unsigned char packed[8] = {0};
    void *complete = NULL;
    void *decoded = NULL;
    ssize_t complete_len;
    asn_enc_rval_t bits;
    asn_enc_rval_t decoded_bits;
    asn_dec_rval_t decode;
    unsigned char decoded_packed[8] = {0};
    int failed;
    if(!item || !item->type || !item->value || !item->bytes || !item->name
       || item->byte_len > sizeof(packed)) return 1;

    /* Compare buffer and complete encoders before validating a C decode. */
    bits = uper_encode_to_buffer(item->type, NULL, item->value,
                                 packed, sizeof(packed));
    complete_len = uper_encode_to_new_buffer(item->type, NULL,
                                              item->value, &complete);
    failed = bits.encoded < 0 || complete_len < 0
             || (size_t)bits.encoded != item->bit_len
             || (size_t)complete_len != item->byte_len;
    if(!failed) failed = memcmp(complete, item->bytes, item->byte_len) != 0
                        || memcmp(packed, item->bytes, item->byte_len) != 0;
    if(!failed) {
        decode = uper_decode_complete(0, item->type, &decoded,
                                      item->bytes, item->byte_len);
        failed = decode.code != RC_OK || !decoded;
        if(!failed) {
            decoded_bits = uper_encode_to_buffer(item->type, NULL, decoded,
                                                 decoded_packed,
                                                 sizeof(decoded_packed));
            failed = decoded_bits.encoded < 0
                     || (size_t)decoded_bits.encoded != item->bit_len
                     || memcmp(decoded_packed, item->bytes, item->byte_len) != 0;
        }
    }
    if(decoded) ASN_STRUCT_FREE(*item->type, decoded);
    free(complete);
    if(failed) fprintf(stderr, "C UPER bounded string mismatch: %s\n", item->name);
    return failed;
}

/*
 * Compare standalone and OPTIONAL-record values against golden UPER vectors.
 * Parameters: argc is the argument count; argv is unused.
 * Returns zero on all matches and one on error; no exception is thrown.
 * Original source: generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: bounded octets.
 * Example: ./c-variable-string.
 */
int
main(int argc, char **argv) {
    unsigned char one_octet[] = {0xa5};
    unsigned char two_octets[] = {0xa5, 0x5a};
    unsigned char tail_octets[] = {0xaa, 0xbb, 0xcc};
    const unsigned char one_wire[] = {0x29, 0x40};
    const unsigned char two_wire[] = {0x69, 0x56, 0x80};
    const unsigned char packet_wire[] = {0xda, 0x55, 0xa6, 0xaa, 0xef, 0x30};
    Data_t one = {0};
    Data_t two = {0};
    Packet_t packet = {0};
    variable_string_case_t cases[3];
    size_t i;
    int failed = 0;
    (void)argv;
    if(argc != 1) return 1;

    /* Populate generated C storage using caller-owned source octets. */
    one.buf = one_octet;
    one.size = sizeof(one_octet);
    two.buf = two_octets;
    two.size = sizeof(two_octets);
    packet.flag = 1;
    packet.maybe = calloc(1, sizeof(*packet.maybe));
    if(!packet.maybe) return 1;
    packet.maybe->buf = two_octets;
    packet.maybe->size = sizeof(two_octets);
    packet.tail.buf = tail_octets;
    packet.tail.size = sizeof(tail_octets);
    cases[0] = (variable_string_case_t){
        &asn_DEF_Data, &one, one_wire, sizeof(one_wire), 10, "Data one octet"};
    cases[1] = (variable_string_case_t){
        &asn_DEF_Data, &two, two_wire, sizeof(two_wire), 18, "Data two octets"};
    cases[2] = (variable_string_case_t){
        &asn_DEF_Packet, &packet, packet_wire, sizeof(packet_wire), 46, "Packet"};
    for(i = 0; i < 3; i++) failed |= check_case(&cases[i]);
    free(packet.maybe);
    return failed;
}
