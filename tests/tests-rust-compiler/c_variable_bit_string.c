/*
 * Compare bounded BIT STRING UPER values between generated C and Rust vectors.
 * Original source: asn1c generated-code regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: bounded bit UPER slice.
 * Example: compile beside VariableBitString C sources and run without arguments.
 */
#include <asn_application.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <Bits.h>
#include <Packet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * One expected complete UPER encoding and its source value.
 * Members describe immutable configuration for one C/Rust vector comparison.
 */
typedef struct variable_bit_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated C type descriptor. */
    const void *value;                 /* Valid source value. */
    const unsigned char *bytes;        /* Expected complete output bytes. */
    size_t byte_len;                   /* Expected complete output length. */
    size_t bit_len;                    /* Expected meaningful bit count. */
    const char *name;                  /* Diagnostic vector name. */
} variable_bit_case_t;

/*
 * Compare one C encode/decode cycle with a fixed complete UPER vector.
 * Parameters: item supplies descriptor, value, and expected encoding.
 * Returns zero on match and one on error; no exception is thrown.
 * Original source: generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: bounded bits.
 * Example: check_case(&cases[0]).
 */
static int
check_case(const variable_bit_case_t *item) {
    unsigned char packed[8] = {0};
    unsigned char decoded_packed[8] = {0};
    void *complete = NULL;
    void *decoded = NULL;
    ssize_t complete_len;
    asn_enc_rval_t bits;
    asn_enc_rval_t decoded_bits;
    asn_dec_rval_t decode;
    int failed;
    if(!item || !item->type || !item->value || !item->bytes || !item->name
       || item->byte_len > sizeof(packed)) return 1;

    /* Compare both C encoder entry points with the independent golden bytes. */
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
    }
    if(!failed) {
        decoded_bits = uper_encode_to_buffer(item->type, NULL, decoded,
                                             decoded_packed,
                                             sizeof(decoded_packed));
        failed = decoded_bits.encoded < 0
                 || (size_t)decoded_bits.encoded != item->bit_len
                 || memcmp(decoded_packed, item->bytes, item->byte_len) != 0;
    }
    if(decoded) ASN_STRUCT_FREE(*item->type, decoded);
    free(complete);
    if(failed) fprintf(stderr, "C UPER bounded BIT STRING mismatch: %s\n", item->name);
    return failed;
}

/*
 * Compare standalone and OPTIONAL-record values against bounded-bit vectors.
 * Parameters: argc is the argument count; argv is unused.
 * Returns zero on all matches and one on error; no exception is thrown.
 * Original source: generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: bounded bits.
 * Example: ./c-variable-bit-string.
 */
int
main(int argc, char **argv) {
    unsigned char one_data[] = {0x80};
    unsigned char three_data[] = {0xA0};
    unsigned char maybe_data[] = {0x80};
    unsigned char tail_data[] = {0xC0};
    unsigned char absent_tail_data[] = {0x40};
    const unsigned char one_wire[] = {0x20};
    const unsigned char three_wire[] = {0xA8};
    const unsigned char present_wire[] = {0xD9, 0xC0};
    const unsigned char absent_wire[] = {0x04};
    Bits_t one = {0};
    Bits_t three = {0};
    Packet_t present = {0};
    Packet_t absent = {0};
    variable_bit_case_t cases[4];
    size_t i;
    int failed = 0;
    (void)argv;
    if(argc != 1) return 1;

    /* Set each C `bits_unused` value to match the logical source width. */
    one.buf = one_data;
    one.size = sizeof(one_data);
    one.bits_unused = 7;
    three.buf = three_data;
    three.size = sizeof(three_data);
    three.bits_unused = 5;
    present.prefix = 1;
    present.maybe = calloc(1, sizeof(*present.maybe));
    if(!present.maybe) return 1;
    present.maybe->buf = maybe_data;
    present.maybe->size = sizeof(maybe_data);
    present.maybe->bits_unused = 6;
    present.tail.buf = tail_data;
    present.tail.size = sizeof(tail_data);
    present.tail.bits_unused = 5;
    absent.prefix = 0;
    absent.tail.buf = absent_tail_data;
    absent.tail.size = sizeof(absent_tail_data);
    absent.tail.bits_unused = 6;

    cases[0] = (variable_bit_case_t){
        &asn_DEF_Bits, &one, one_wire, sizeof(one_wire), 3, "one bit"};
    cases[1] = (variable_bit_case_t){
        &asn_DEF_Bits, &three, three_wire, sizeof(three_wire), 5, "three bits"};
    cases[2] = (variable_bit_case_t){
        &asn_DEF_Packet, &present, present_wire, sizeof(present_wire), 11,
        "present optional"};
    cases[3] = (variable_bit_case_t){
        &asn_DEF_Packet, &absent, absent_wire, sizeof(absent_wire), 6,
        "absent optional"};
    for(i = 0; i < 4; i++) failed |= check_case(&cases[i]);
    free(present.maybe);
    return failed;
}
