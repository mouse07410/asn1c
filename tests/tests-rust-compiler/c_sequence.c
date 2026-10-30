/*
 * Compare generated C UPER SEQUENCE bytes with independent Rust vectors.
 * Original source: asn1c generated-code regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: flat Rust SEQUENCE slice.
 * Example: compile beside SequenceSlice C sources and run with no arguments.
 */
#include <asn_application.h>
#include <uper_encoder.h>
#include <INTEGER.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AllZero.h>
#include <CrossByte.h>
#include <Packet.h>
#include <WideRecord.h>

/*
 * Description of one expected complete UPER encoding.
 * Every member is immutable configuration for one comparison case.
 */
typedef struct sequence_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated C descriptor. */
    const void *value;                /* Typed source value. */
    const unsigned char *bytes;       /* Expected complete bytes. */
    size_t byte_len;                  /* Expected complete byte count. */
    size_t bit_len;                   /* Expected meaningful bit count. */
    const char *name;                 /* Diagnostic case name. */
} sequence_case_t;

/*
 * Compare one generated C encoding against a fixed UPER vector.
 * Parameters: item supplies descriptor, source value, bytes, and bit count.
 * Returns zero on equality or one for invalid input/encoding/mismatch.
 * Exceptions: none; allocation failures become error returns.
 * Original source: generated C UPER comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: first flat
 * constructed Rust codec. Example: check_case(&cases[0]).
 */
static int
check_case(const sequence_case_t *item) {
    unsigned char packed[16] = {0};
    void *complete = NULL;
    ssize_t complete_len;
    asn_enc_rval_t bits;
    int failed;
    if(!item || !item->type || !item->value || !item->bytes || !item->name
       || item->byte_len > sizeof(packed)) return 1;

    /* Compare both C APIs, including complete-value zero-width filler. */
    bits = uper_encode_to_buffer(item->type, NULL, item->value,
                                 packed, sizeof(packed));
    complete_len = uper_encode_to_new_buffer(item->type, NULL,
                                              item->value, &complete);
    failed = bits.encoded < 0 || complete_len < 0
             || (size_t)bits.encoded != item->bit_len
             || (size_t)complete_len != item->byte_len;
    if(!failed) failed = memcmp(complete, item->bytes, item->byte_len) != 0;
    free(complete);
    if(failed) fprintf(stderr, "C UPER SEQUENCE mismatch: %s\n", item->name);
    return failed;
}

/*
 * Run C comparisons for non-octet, cross-byte, zero-width, and wide fields.
 * Parameters: argc is argument count; argv is the unused argument array.
 * Returns zero for all matches or one for a mismatch/extra argument.
 * Exceptions: none. Original source: asn1c regression fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: first flat
 * constructed Rust codec. Example: ./c-sequence.
 */
int
main(int argc, char **argv) {
    Packet_t packet = {0};
    AllZero_t all_zero = {0};
    CrossByte_t cross = {0};
    WideRecord_t wide = {0};
    const unsigned char packet_bytes[] = {0xd0};
    const unsigned char zero_bytes[] = {0x00};
    const unsigned char cross_bytes[] = {0xd5, 0x80};
    const unsigned char wide_bytes[] = {0, 0, 0, 0, 0, 0, 0, 0, 0x80};
    sequence_case_t cases[4];
    size_t i, count = 3;
    int failed = 0;
    (void)argv;
    if(argc != 1) return 1;

    /* Initialize the direct fields and expected wire-case descriptors. */
    packet.first = 1;
    packet.count = 5;
    packet.fixed = 7;
    cross.first = 1;
    cross.octet = 0xab;
    all_zero.fixed = 7;
    cases[0] = (sequence_case_t){&asn_DEF_Packet, &packet, packet_bytes, 1, 5, "Packet"};
    cases[1] = (sequence_case_t){&asn_DEF_AllZero, &all_zero, zero_bytes, 1, 0, "AllZero"};
    cases[2] = (sequence_case_t){&asn_DEF_CrossByte, &cross, cross_bytes, 2, 10, "CrossByte"};
    if(sizeof(long) >= 8) {
        if(asn_long2INTEGER(&wide.wide, LONG_MIN) != 0) return 1;
        wide.tail = 1;
        cases[3] = (sequence_case_t){&asn_DEF_WideRecord, &wide, wide_bytes, 9, 65, "WideRecord"};
        count = 4;
    }
    for(i = 0; i < count; i++) failed |= check_case(&cases[i]);
    free(wide.wide.buf);
    return failed;
}
