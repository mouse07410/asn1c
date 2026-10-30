/* Exercise UPER encoding of individual SET extension additions. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <IndividualSet.h>
#include <uper_decoder.h>
#include <uper_encoder.h>
#include <uper_opentype.h>
#include <uper_support.h>

/*
 * Purpose: verify a generated SET with ordinary extension additions.
 * Source: Generated descriptors for 597-set-uper-individual-additions-OK.asn1.
 * Version/date: 1.0, 2026-10-30.
 * Parameters: none.
 * Returns: zero when the golden UPER vector round-trips correctly.
 * Errors: assertions terminate on an unexpected descriptor or codec result.
 * Responsible party: asn1c maintainers. History: Added 2026-10-30.
 * Example: check-assembly.sh compiles this source with generated UPER support.
 */
/*
 * Purpose: append one complete PER open type to an existing bitstream.
 * Source: X.691 open-type length and payload encoding.
 * Version/date: 1.0, 2026-10-30.
 * Parameters: buffer/capacity bound output; bit_offset is the starting bit;
 *             payload and payload_size provide one complete open-type value.
 * Returns: zero on success, -1 if the output buffer or PER helper fails.
 * Errors: none. Author: asn1c maintainers. History: Added 2026-10-30.
 * Example: append a one-byte unknown extension payload to a test value.
 */
static int
append_open_type(uint8_t *buffer, size_t capacity, size_t *bit_offset,
                 const uint8_t *payload, size_t payload_size) {
    asn_per_outp_t output;
    ssize_t encoded_size;
    int need_eom = 0;

    /* Append a length-delimited payload after the existing root encoding. */
    memset(&output, 0, sizeof(output));
    output.buffer = buffer;
    output.nboff = *bit_offset;
    output.nbits = capacity * 8;
    encoded_size = uper_put_length(&output, payload_size, &need_eom);
    if(encoded_size != (ssize_t)payload_size || need_eom) return -1;
    if(per_put_many_bits(&output, payload, (int)(payload_size * 8))) return -1;
    *bit_offset = (size_t)(output.buffer - buffer) * 8 + output.nboff;
    return 0;
}

/*
 * Purpose: append a deliberately truncated PER open type.
 * Source: X.691 open-type length and payload encoding.
 * Version/date: 1.0, 2026-10-30.
 * Parameters: buffer/capacity bound output; bit_offset is the starting bit;
 *             payload contributes bytes after a length of two octets.
 * Returns: zero on success, -1 if a PER helper fails.
 * Errors: none. Author: asn1c maintainers. History: Added 2026-10-30.
 * Example: claim two bytes while providing one to trigger decoder starvation.
 */
static int
append_truncated_open_type(uint8_t *buffer, size_t capacity,
                           size_t *bit_offset, const uint8_t *payload) {
    asn_per_outp_t output;
    ssize_t encoded_size;
    int need_eom = 0;

    /* Keep the claimed size larger than the actual payload for the regression. */
    memset(&output, 0, sizeof(output));
    output.buffer = buffer;
    output.nboff = *bit_offset;
    output.nbits = capacity * 8;
    encoded_size = uper_put_length(&output, 2, &need_eom);
    if(encoded_size != 2 || need_eom) return -1;
    if(per_put_many_bits(&output, payload, 8)) return -1;
    *bit_offset = (size_t)(output.buffer - buffer) * 8 + output.nboff;
    return 0;
}

/*
 * Purpose: build a SET wire suffix containing unknown additions.
 * Source: X.691 extension bitmap and open-type encoding rules.
 * Version/date: 1.0, 2026-10-30.
 * Parameters: buffer/root_bits identify the encoded roots; bitmap/length select
 *             extension bits; payloads carry open types; bit_count is output.
 * Returns: zero on success, -1 when a buffer or PER helper rejects the input.
 * Errors: none. Responsible party: asn1c maintainers. History: Added 2026-10-30.
 * Example: bitmap 001 with length 3 skips unknown addition index 2.
 */
static int
append_unknown_additions(uint8_t *buffer, size_t capacity, size_t root_bits,
                         unsigned bitmap, unsigned bitmap_length,
                         const uint8_t **payloads, const size_t *payload_sizes,
                         size_t payload_count, size_t *bit_count) {
    asn_per_outp_t output;
    size_t i;

    /* Mark the value extensible, then write the long bitmap and unknown TLVs. */
    if(!buffer || !payloads || !payload_sizes || !bit_count
       || !bitmap_length || bitmap_length > 31) return -1;
    buffer[0] |= 0x80;
    memset(&output, 0, sizeof(output));
    output.buffer = buffer;
    output.nboff = root_bits;
    output.nbits = capacity * 8;
    if(uper_put_nslength(&output, bitmap_length)
       || per_put_few_bits(&output, bitmap, (int)bitmap_length)) return -1;
    *bit_count = (size_t)(output.buffer - buffer) * 8 + output.nboff;
    for(i = 0; i < payload_count; i++) {
        if(append_open_type(buffer, capacity, bit_count, payloads[i],
                            payload_sizes[i])) return -1;
    }
    return 0;
}

int
main(void) {
    static const unsigned char expected[] = {
        0xf6, 0x90, 0x58, 0x06, 0x00, 0x05, 0x40
    };
    static const unsigned char unknown_one[] = {0xa5};
    static const unsigned char unknown_two[] = {0x5a, 0xc3};
    static const uint8_t *unknown_single_payloads[] = {unknown_one};
    static const size_t unknown_single_sizes[] = {sizeof(unknown_one)};
    static const uint8_t *unknown_multiple_payloads[] = {
        unknown_one, unknown_two
    };
    static const size_t unknown_multiple_sizes[] = {
        sizeof(unknown_one), sizeof(unknown_two)
    };
    static const unsigned expected_roots[] = {0, 1, 2};
    static const unsigned expected_additions[] = {3, 4, 5};
    static const unsigned duplicate_roots[] = {0, 1, 1};
    static const unsigned out_of_range_roots[] = {0, 1, 99};
    IndividualSet_t source;
    IndividualSet_t *decoded = 0;
    asn_SET_specifics_t *specs;
    asn_TYPE_member_t *addition;
    const unsigned *saved_root_map;
    asn_TYPE_descriptor_t *saved_type;
    unsigned char encoded[16] = {0};
    unsigned char unknown[16] = {0};
    asn_enc_rval_t er;
    asn_dec_rval_t dr;
    size_t encoded_bytes;
    size_t unknown_bits;
    size_t unknown_bytes;

    assert(uper_open_type_skip_result(0, 0).code == RC_FAIL);
    assert(uper_open_type_skip(0, 0) == -1);

    specs = (asn_SET_specifics_t *)asn_DEF_IndividualSet.specifics;
    assert(specs && specs->extensible == 2);
    assert(specs->specifics_size >= offsetof(asn_SET_specifics_t, extension_groups));
    assert(specs->specifics_version == ASN_SET_SPECIFICS_VERSION);
    assert(specs->root_count == 3 && specs->extension_count == 3);
    assert(memcmp(specs->root_map, expected_roots, sizeof(expected_roots)) == 0);
    assert(memcmp(specs->extension_map, expected_additions,
                  sizeof(expected_additions)) == 0);
    assert(specs->tag2el_cxer[0].el_no == 1);
    assert(specs->tag2el_cxer[1].el_no == 2);

    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.rootLow = MALLOC(sizeof(*source.rootLow));
    source.trailingRoot = MALLOC(sizeof(*source.trailingRoot));
    source.addedFlag = MALLOC(sizeof(*source.addedFlag));
    source.addedValue = MALLOC(sizeof(*source.addedValue));
    source.addedDefault = MALLOC(sizeof(*source.addedDefault));
    assert(source.rootLow && source.trailingRoot && source.addedFlag
           && source.addedValue && source.addedDefault);
    *source.rootLow = 1;
    *source.trailingRoot = 6;
    *source.addedFlag = 1;
    *source.addedValue = 5;
    *source.addedDefault = 3;

    er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == 54);
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    encoded_bytes = ((size_t)er.encoded + 7) / 8;

    dr = uper_decode(0, &asn_DEF_IndividualSet, (void **)&decoded, encoded,
                     encoded_bytes, 0, 0);
    assert(dr.code == RC_OK);
    assert(decoded->rootHigh == source.rootHigh);
    assert(decoded->rootLow && *decoded->rootLow == *source.rootLow);
    assert(decoded->trailingRoot
           && *decoded->trailingRoot == *source.trailingRoot);
    assert(decoded->addedFlag && *decoded->addedFlag == *source.addedFlag);
    assert(decoded->addedValue && *decoded->addedValue == *source.addedValue);
    assert(decoded->addedDefault && *decoded->addedDefault == 3);

    /* A length-four map with only unknown index 3 set skips one open type. */
    ASN_STRUCT_FREE(asn_DEF_IndividualSet, decoded);
    decoded = 0;
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_IndividualSet, &source);
    memset(&source, 0, sizeof(source));
    source.rootHigh = 9;
    source.rootLow = MALLOC(sizeof(*source.rootLow));
    source.trailingRoot = MALLOC(sizeof(*source.trailingRoot));
    assert(source.rootLow && source.trailingRoot);
    *source.rootLow = 1;
    *source.trailingRoot = 6;
    er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded > 0);
    encoded_bytes = ((size_t)er.encoded + 7) / 8;
    memcpy(unknown, encoded, sizeof(unknown));
    assert(append_unknown_additions(unknown, sizeof(unknown),
                                    (size_t)er.encoded, 1, 4,
                                    unknown_single_payloads,
                                    unknown_single_sizes, 1, &unknown_bits) == 0);
    unknown_bytes = (unknown_bits + 7) / 8;
    dr = uper_decode(0, &asn_DEF_IndividualSet, (void **)&decoded, unknown,
                     unknown_bytes, 0, (int)(unknown_bytes * 8 - unknown_bits));
    assert(dr.code == RC_OK);
    assert(decoded->rootHigh == source.rootHigh);
    assert(decoded->rootLow && *decoded->rootLow == *source.rootLow);
    assert(decoded->trailingRoot
           && *decoded->trailingRoot == *source.trailingRoot);
    assert(decoded->addedFlag == 0 && decoded->addedValue == 0);
    assert(decoded->addedDefault && *decoded->addedDefault == 3);

    /* Two unknown bitmap bits each consume and skip their open type. */
    ASN_STRUCT_FREE(asn_DEF_IndividualSet, decoded);
    decoded = 0;
    memcpy(unknown, encoded, sizeof(unknown));
    assert(append_unknown_additions(unknown, sizeof(unknown),
                                    (size_t)er.encoded, 3, 5,
                                    unknown_multiple_payloads,
                                    unknown_multiple_sizes, 2,
                                    &unknown_bits) == 0);
    unknown_bytes = (unknown_bits + 7) / 8;
    dr = uper_decode(0, &asn_DEF_IndividualSet, (void **)&decoded, unknown,
                     unknown_bytes, 0, (int)(unknown_bytes * 8 - unknown_bits));
    assert(dr.code == RC_OK);
    assert(decoded->rootHigh == source.rootHigh);
    assert(decoded->rootLow && *decoded->rootLow == *source.rootLow);
    assert(decoded->trailingRoot
           && *decoded->trailingRoot == *source.trailingRoot);
    assert(decoded->addedFlag == 0 && decoded->addedValue == 0);
    assert(decoded->addedDefault && *decoded->addedDefault == 3);

    /* Truncate an unknown open type after its length and one of two bytes. */
    ASN_STRUCT_FREE(asn_DEF_IndividualSet, decoded);
    decoded = 0;
    memcpy(unknown, encoded, sizeof(unknown));
    assert(append_unknown_additions(unknown, sizeof(unknown),
                                    (size_t)er.encoded, 1, 4,
                                    unknown_single_payloads,
                                    unknown_single_sizes, 0, &unknown_bits) == 0);
    assert(append_truncated_open_type(unknown, sizeof(unknown), &unknown_bits,
                                      unknown_one) == 0);
    unknown_bytes = (unknown_bits + 7) / 8;
    dr = uper_decode(0, &asn_DEF_IndividualSet, (void **)&decoded, unknown,
                     unknown_bytes, 0, (int)(unknown_bytes * 8 - unknown_bits));
    assert(dr.code == RC_WMORE);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_IndividualSet, decoded);
    decoded = 0;

    /* Duplicate and out-of-range map entries must fail before storage access. */
    saved_root_map = specs->root_map;
    specs->root_map = duplicate_roots;
    er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == -1);
    specs->root_map = out_of_range_roots;
    er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == -1);
    specs->root_map = saved_root_map;

    /* Missing leaf types and inline optional additions are malformed v2 data. */
    addition = &asn_DEF_IndividualSet.elements[3];
    saved_type = addition->type;
    addition->type = 0;
    er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                               sizeof(encoded));
    assert(er.encoded == -1);
    addition->type = saved_type;
    {
        int saved_flags = addition->flags;
        addition->flags &= ~ATF_POINTER;
        er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                                   sizeof(encoded));
        assert(er.encoded == -1);
        addition->flags = saved_flags;
    }

    /* Legacy extensible=1 metadata has no v2 maps and remains unsupported. */
    {
        int saved_extensible = specs->extensible;
        specs->extensible = 1;
        er = uper_encode_to_buffer(&asn_DEF_IndividualSet, 0, &source, encoded,
                                   sizeof(encoded));
        assert(er.encoded == -1);
        dr = uper_decode(0, &asn_DEF_IndividualSet, (void **)&decoded, encoded,
                         encoded_bytes, 0, 0);
        assert(dr.code == RC_FAIL);
        specs->extensible = saved_extensible;
        if(decoded) ASN_STRUCT_FREE(asn_DEF_IndividualSet, decoded);
        decoded = 0;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_IndividualSet, &source);
    return 0;
}
