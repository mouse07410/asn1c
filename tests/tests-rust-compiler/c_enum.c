/*
 * Compare C UPER ENUMERATED encodings with independent Rust vectors.
 * Original source: asn1c generated-code regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: root ENUMERATED UPER slice.
 * Example: compile beside EnumSlice C sources and run without arguments.
 */
#include <asn_application.h>
#include <uper_encoder.h>
#include <uper_decoder.h>
#include <INTEGER.h>
#include <Color.h>
#include <Only.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Compare one C source value with a fixed complete UPER vector.
 * Parameters: type is its descriptor; value is the initialized value;
 * expected is the output byte; bit_len is the meaningful bit count.
 * Returns zero on match, one on failure; no exception is thrown.
 * Original source: generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: root enums.
 * Example: check_case(&asn_DEF_Color, &value, 0x80, 2).
 */
static int
check_case(const asn_TYPE_descriptor_t *type, const void *value,
           unsigned char expected, size_t bit_len) {
    void *encoded = NULL;
    void *decoded = NULL;
    ssize_t length;
    asn_enc_rval_t bits;
    asn_dec_rval_t decode;
    unsigned char packed[2] = {0};
    int failed;
    if(!type || !value) return 1;
    bits = uper_encode_to_buffer(type, NULL, value, packed, sizeof(packed));
    length = uper_encode_to_new_buffer(type, NULL, value, &encoded);
    failed = bits.encoded < 0 || length != 1 || (size_t)bits.encoded != bit_len;
    if(!failed) failed = ((const unsigned char *)encoded)[0] != expected
                        || packed[0] != expected;
    if(!failed) {
        decode = uper_decode_complete(0, type, &decoded, &expected, 1);
        failed = decode.code != RC_OK || !decoded;
    }
    if(decoded) ASN_STRUCT_FREE(*type, decoded);
    free(encoded);
    if(failed) fprintf(stderr, "C UPER ENUMERATED mismatch\n");
    return failed;
}

/*
 * Run numeric-order and singleton enumeration comparisons.
 * Parameters: argc is the argument count; argv is unused.
 * Returns zero on success, one on failure; no exception is thrown.
 * Original source: asn1c generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: root enums.
 * Example: ./c-enum.
 */
int
main(int argc, char **argv) {
    Color_t color = {0};
    Only_t only = {0};
    int failed = 0;
    (void)argv;
    if(argc != 1) return 1;
    if(asn_long2INTEGER(&color, 20) != 0) return 1;
    failed |= check_case(&asn_DEF_Color, &color, 0x80, 2);
    if(asn_long2INTEGER(&color, 2) != 0) failed = 1;
    else failed |= check_case(&asn_DEF_Color, &color, 0x00, 2);
    if(asn_long2INTEGER(&color, 9) != 0) failed = 1;
    else failed |= check_case(&asn_DEF_Color, &color, 0x40, 2);
    if(asn_long2INTEGER(&only, 5) != 0) failed = 1;
    else failed |= check_case(&asn_DEF_Only, &only, 0x00, 0);
    free(color.buf);
    free(only.buf);
    return failed;
}
