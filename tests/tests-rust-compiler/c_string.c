/*
 * Compare C UPER fixed string encodings with independent Rust vectors.
 * Original source: asn1c generated-code regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: fixed string UPER slice.
 * Example: compile beside StringSlice C sources and run without arguments.
 */
#include <asn_application.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <EmptyBits.h>
#include <EmptyOctets.h>
#include <MixedStringRecord.h>
#include <OneOctet.h>
#include <ThreeBits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * One expected complete UPER encoding and its source value.
 * Members describe immutable configuration for one C/Rust vector comparison.
 */
typedef struct string_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated C type descriptor. */
    const void *value;                 /* Valid source value. */
    const unsigned char *bytes;        /* Expected complete output bytes. */
    size_t byte_len;                   /* Expected complete output length. */
    size_t bit_len;                    /* Expected meaningful bit count. */
    const char *name;                  /* Diagnostic vector name. */
} string_case_t;

/*
 * Compare one C encoding with a fixed vector and its meaningful bit count.
 * Parameters: item supplies descriptor, value, and expected encoding.
 * Returns zero on match and one on error; no exception is thrown.
 * Original source: asn1c generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: fixed strings.
 * Example: check_case(&cases[0]).
 */
static int
check_case(const string_case_t *item) {
    unsigned char packed[8] = {0};
    void *complete = NULL;
    void *decoded = NULL;
    ssize_t complete_len;
    asn_enc_rval_t bits;
    asn_dec_rval_t decode;
    int failed;
    if(!item || !item->type || !item->value || !item->bytes || !item->name
       || item->byte_len > sizeof(packed)) return 1;

    /* Compare both C APIs so the zero-width complete filler is checked. */
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
    if(decoded) ASN_STRUCT_FREE(*item->type, decoded);
    free(complete);
    if(failed) fprintf(stderr, "C UPER string mismatch: %s\n", item->name);
    return failed;
}

/*
 * Run fixed octet, bit, empty, and mixed SEQUENCE C comparisons.
 * Parameters: argc is the argument count; argv is unused.
 * Returns zero on all matches and one on error; no exception is thrown.
 * Original source: asn1c generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: fixed strings.
 * Example: ./c-string.
 */
int
main(int argc, char **argv) {
    unsigned char octet_data[] = {0xa5};
    unsigned char two_octets[] = {0xa5, 0x5a};
    unsigned char bit_data[] = {0xa0};
    unsigned char five_bits[] = {0xa8};
    const unsigned char octet_wire[] = {0xa5};
    const unsigned char bit_wire[] = {0xa0};
    const unsigned char empty_wire[] = {0};
    const unsigned char mixed_wire[] = {0xd2, 0xad, 0x56};
    OneOctet_t octet = {0};
    ThreeBits_t bits = {0};
    EmptyOctets_t empty_octet = {0};
    EmptyBits_t empty_bits = {0};
    MixedStringRecord_t mixed = {0};
    string_case_t cases[5];
    size_t i;
    int failed = 0;
    (void)argv;
    if(argc != 1) return 1;

    /* Assign fixed source buffers and the same expected bytes used by Rust. */
    octet.buf = octet_data;
    octet.size = sizeof(octet_data);
    bits.buf = bit_data;
    bits.size = sizeof(bit_data);
    bits.bits_unused = 5;
    mixed.prefix = 1;
    mixed.octets.buf = two_octets;
    mixed.octets.size = sizeof(two_octets);
    mixed.bits.buf = five_bits;
    mixed.bits.size = sizeof(five_bits);
    mixed.bits.bits_unused = 3;
    mixed.suffix = 2;
    cases[0] = (string_case_t){&asn_DEF_OneOctet, &octet, octet_wire, 1, 8, "OneOctet"};
    cases[1] = (string_case_t){&asn_DEF_ThreeBits, &bits, bit_wire, 1, 3, "ThreeBits"};
    cases[2] = (string_case_t){&asn_DEF_EmptyOctets, &empty_octet, empty_wire, 1, 0, "EmptyOctets"};
    cases[3] = (string_case_t){&asn_DEF_EmptyBits, &empty_bits, empty_wire, 1, 0, "EmptyBits"};
    cases[4] = (string_case_t){&asn_DEF_MixedStringRecord, &mixed, mixed_wire, 3, 24, "Mixed"};
    for(i = 0; i < 5; i++) failed |= check_case(&cases[i]);
    return failed;
}
