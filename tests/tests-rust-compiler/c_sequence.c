/*
 * Compare generated C UPER SEQUENCE bytes with independent Rust vectors.
 * Original source: asn1c generated-code regression. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: flat Rust SEQUENCE slice.
 * Example: compile beside SequenceSlice C sources and run with no arguments.
 */
#include <asn_application.h>
#include <uper_decoder.h>
#include <uper_encoder.h>
#include <INTEGER.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AllZero.h>
#include <OptionalBoolean.h>
#include <OptionalPacket.h>
#include <BitmapAcrossOctets.h>
#include <ZeroOptional.h>
#include <CrossByte.h>
#include <Packet.h>
#include <WideRecord.h>
#include <DefaultPacket.h>
#include <NestedPacket.h>

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
    OptionalPacket_t optional_absent = {0};
    OptionalPacket_t optional_present = {0};
    OptionalBoolean_t boolean_absent = {0};
    OptionalBoolean_t boolean_present = {0};
    ZeroOptional_t zero_absent = {0};
    ZeroOptional_t zero_present = {0};
    BitmapAcrossOctets_t bitmap_crossing = {0};
    DefaultPacket_t defaults_omitted = {0};
    DefaultPacket_t defaults_mixed = {0};
    NestedPacket_t nested = {0};
    struct maybe nested_maybe = {0};
    NULL_t null_value = 0;
    long optional_number = 2;
    long optional_single = 7;
    BOOLEAN_t optional_boolean = 1;
    BOOLEAN_t optional_false = 0;
    BOOLEAN_t default_before = 0;
    BOOLEAN_t default_after = 1;
    BOOLEAN_t default_active = 0;
    BOOLEAN_t default_enabled = 1;
    long default_count = 1;
    long default_tail = 2;
    long nested_count = 3;
    BOOLEAN_t nested_enabled = 1;
    unsigned char optional_octet_data[] = {0xa5};
    unsigned char optional_bits_data[] = {0xa0};
    OCTET_STRING_t optional_octet = {optional_octet_data, 1};
    BIT_STRING_t optional_bits = {optional_bits_data, 1, 5};
    OCTET_STRING_t empty_octets = {NULL, 0};
    BIT_STRING_t empty_bits = {NULL, 0, 0};
    const unsigned char packet_bytes[] = {0xd0};
    const unsigned char zero_bytes[] = {0x00};
    const unsigned char cross_bytes[] = {0xd5, 0x80};
    const unsigned char wide_bytes[] = {0, 0, 0, 0, 0, 0, 0, 0, 0x80};
    const unsigned char optional_absent_bytes[] = {0x08};
    const unsigned char optional_present_bytes[] = {0xfd, 0x4b, 0x40};
    const unsigned char boolean_absent_bytes[] = {0x00};
    const unsigned char boolean_present_bytes[] = {0xc0};
    const unsigned char zero_optional_absent_bytes[] = {0x00};
    const unsigned char zero_optional_present_bytes[] = {0xf0};
    const unsigned char bitmap_crossing_bytes[] = {0x80, 0xc0, 0x00};
    const unsigned char default_omitted_bytes[] = {0x04};
    const unsigned char default_mixed_bytes[] = {0xda, 0xe0};
    const unsigned char default_present_bytes[] = {0x71, 0x80};
    const unsigned char nested_bytes[] = {0xef, 0xa0};
    sequence_case_t cases[14];
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
    /* Compare absent and present optional fields with independent Rust vectors. */
    optional_absent.first = 1;
    optional_present.first = 1;
    optional_present.nothing = &null_value;
    optional_present.number = &optional_number;
    optional_present.octet = &optional_octet;
    optional_present.bits = &optional_bits;
    boolean_present.maybe = &optional_boolean;
    zero_present.nothing = &null_value;
    zero_present.single = &optional_single;
    zero_present.emptyoctets = &empty_octets;
    zero_present.emptybits = &empty_bits;
    bitmap_crossing.o1 = &optional_boolean;
    bitmap_crossing.o9 = &optional_false;
    defaults_omitted.enabled = 0;
    defaults_omitted.count = NULL;
    defaults_omitted.active = NULL;
    defaults_omitted.tail = default_tail;
    defaults_mixed.before = &default_before;
    defaults_mixed.enabled = default_enabled;
    defaults_mixed.count = &default_count;
    defaults_mixed.active = &default_active;
    defaults_mixed.after = &default_after;
    defaults_mixed.tail = 3;
    nested.prefix = 1;
    nested.fixed.flag = 0;
    nested.fixed.count = &nested_count;
    nested.fixed.suffix = 1;
    nested_maybe.number = 2;
    nested_maybe.enabled = &nested_enabled;
    nested.maybe = &nested_maybe;
    nested.tail = 0;
    cases[count++] = (sequence_case_t){&asn_DEF_OptionalPacket, &optional_absent,
        optional_absent_bytes, 1, 5, "OptionalPacket absent"};
    cases[count++] = (sequence_case_t){&asn_DEF_OptionalPacket, &optional_present,
        optional_present_bytes, 3, 18, "OptionalPacket present"};
    cases[count++] = (sequence_case_t){&asn_DEF_OptionalBoolean, &boolean_absent,
        boolean_absent_bytes, 1, 1, "OptionalBoolean absent"};
    cases[count++] = (sequence_case_t){&asn_DEF_OptionalBoolean, &boolean_present,
        boolean_present_bytes, 1, 2, "OptionalBoolean present"};
    cases[count++] = (sequence_case_t){&asn_DEF_ZeroOptional, &zero_absent,
        zero_optional_absent_bytes, 1, 4, "ZeroOptional absent"};
    cases[count++] = (sequence_case_t){&asn_DEF_ZeroOptional, &zero_present,
        zero_optional_present_bytes, 1, 4, "ZeroOptional present"};
    cases[count++] = (sequence_case_t){&asn_DEF_BitmapAcrossOctets, &bitmap_crossing,
        bitmap_crossing_bytes, 3, 20, "BitmapAcrossOctets"};
    cases[count++] = (sequence_case_t){&asn_DEF_DefaultPacket, &defaults_omitted,
        default_omitted_bytes, 1, 7, "DefaultPacket omitted"};
    cases[count++] = (sequence_case_t){&asn_DEF_DefaultPacket, &defaults_mixed,
        default_mixed_bytes, 2, 11, "DefaultPacket mixed"};
    cases[count++] = (sequence_case_t){&asn_DEF_NestedPacket, &nested,
        nested_bytes, 2, 12, "NestedPacket"};
    for(i = 0; i < count; i++) failed |= check_case(&cases[i]);
    {
        void *decoded = NULL;
        asn_dec_rval_t result = uper_decode_complete(
            NULL, &asn_DEF_DefaultPacket, &decoded,
            default_present_bytes, sizeof(default_present_bytes));
        DefaultPacket_t *value = (DefaultPacket_t *)decoded;
        if(result.code != RC_OK || !value || value->before || value->after
           || value->enabled != 0 || !value->count || *value->count != 1
           || !value->active || *value->active != 1
           || value->tail != 0) {
            fprintf(stderr, "C UPER DEFAULT decoder mismatch: DefaultPacket\n");
            failed = 1;
        }
        if(decoded) ASN_STRUCT_FREE(asn_DEF_DefaultPacket, decoded);
    }
    {
        void *decoded = NULL;
        asn_dec_rval_t result = uper_decode_complete(
            NULL, &asn_DEF_NestedPacket, &decoded,
            nested_bytes, sizeof(nested_bytes));
        NestedPacket_t *value = (NestedPacket_t *)decoded;
        if(result.code != RC_OK || !value || value->prefix != 1
           || value->fixed.flag != 0 || !value->fixed.count
           || *value->fixed.count != 3 || value->fixed.suffix != 1
           || !value->maybe || value->maybe->number != 2
           || !value->maybe->enabled || *value->maybe->enabled != 1
           || value->tail != 0) {
            fprintf(stderr, "C UPER nested decoder mismatch: NestedPacket\n");
            failed = 1;
        }
        if(decoded) ASN_STRUCT_FREE(asn_DEF_NestedPacket, decoded);
    }
    free(wide.wide.buf);
    return failed;
}
