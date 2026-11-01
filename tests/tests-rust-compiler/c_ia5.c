/* Compare generated C BER/DER/CER IA5String behavior with Rust vectors. */
#include <asn_application.h>
#include <IA5String.h>
#include <AsciiValue.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IA5_MAX 2001
#define IA5_WIRE_MAX 2200

/*
 * Purpose: append a shortest definite length to a bounded test vector.
 * Parameters: output receives the bytes; length is the content length.
 * Returns the encoded length-field size. Errors are impossible for this suite.
 * Source: X.690 length encoding. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: IA5 C/Rust vectors.
 * Example: length 1000 appends `82 03 e8`.
 */
static size_t
append_length(uint8_t *output, size_t length) {
    if(length < 128) {
        output[0] = (uint8_t)length;
        return 1;
    }
    if(length < 256) {
        output[0] = 0x81;
        output[1] = (uint8_t)length;
        return 2;
    }
    output[0] = 0x82;
    output[1] = (uint8_t)(length >> 8);
    output[2] = (uint8_t)length;
    return 3;
}

/*
 * Purpose: append one definite primitive TLV.
 * Parameters: output is destination; tag, content, and length describe value.
 * Returns total bytes written. Errors are impossible for fixed test buffers.
 * Source: X.690 primitive TLV layout. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: IA5 expected encodings.
 * Example: tag 22 with empty content produces `16 00`.
 */
static size_t
make_primitive(uint8_t *output, uint8_t tag,
               const uint8_t *content, size_t length) {
    size_t length_size;
    output[0] = tag;
    length_size = append_length(output + 1, length);
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: build the canonical IA5String CER vector independently.
 * Parameters: content and length are valid IA5 bytes; output stores the TLV.
 * Returns the encoded size. Errors are impossible through IA5_MAX bytes.
 * Source: X.690 CER string fragmentation. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: live C cutover comparison.
 * Example: 1001 bytes use tag 36 and OCTET STRING fragments.
 */
static size_t
make_cer(const uint8_t *content, size_t length, uint8_t *output) {
    size_t offset;
    size_t index;
    if(length <= 1000) return make_primitive(output, 0x16, content, length);
    output[0] = 0x36;
    output[1] = 0x80;
    offset = 2;
    for(index = 0; index < length; index += 1000) {
        size_t fragment = length - index;
        if(fragment > 1000) fragment = 1000;
        offset += make_primitive(output + offset, 0x04,
                                 content + index, fragment);
    }
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: compare one C IA5 BER decode with content and prefix expectations.
 * Parameters: wire/length are bytes; expected/size are raw content; consumed
 * is the expected TLV prefix. Returns zero for an exact semantic match.
 * Errors: decode or value mismatch returns one; all allocated results are freed.
 * Source: generated C BER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: BER prefix tests.
 * Example: `16 01 41 ff` decodes one byte and leaves the suffix.
 */
static int
decode_matches(enum asn_transfer_syntax syntax, const uint8_t *wire,
               size_t length, const uint8_t *expected, size_t size,
               size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_AsciiValue,
                                       &decoded, wire, length);
    AsciiValue_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != consumed || !value
        || value->size != size
        || (size && (!value->buf || memcmp(value->buf, expected, size)));
    if(failed)
        fprintf(stderr, "C IA5 decode mismatch: syntax=%d size=%zu consumed=%zu/%zu\n",
                (int)syntax, size, result.consumed, consumed);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AsciiValue, decoded);
    return failed;
}

/*
 * Purpose: require strict CER rejection and release partial decode storage.
 * Parameters: wire and size are a complete candidate IA5String TLV.
 * Returns zero on rejection. Errors: successful decoding returns one.
 * Source: generated C strict CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: IA5 canonicality probes.
 * Example: CER rejects an invalid high-bit IA5 byte.
 */
static int
cer_rejects(const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, &asn_DEF_AsciiValue,
                                       &decoded, wire, size);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AsciiValue, decoded);
    return result.code == RC_OK;
}

/*
 * Purpose: require BER rejection for malformed lengths or invalid child tags.
 * Parameters: wire and size are one complete malformed candidate.
 * Returns zero on rejection. Errors: successful decoding returns one.
 * Source: generated C BER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed IA5 probes.
 * Example: a constructed IA5String may contain OCTET STRING children only.
 */
static int
ber_rejects(const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_AsciiValue,
                                       &decoded, wire, size);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AsciiValue, decoded);
    return result.code == RC_OK;
}

/*
 * Purpose: confirm C's decoded constructed-empty null-buffer representation.
 * Parameters: none. Returns zero when BER succeeds and direct CER re-encode fails.
 * Errors: unexpected storage or encoding behavior returns one.
 * Source: C IA5 empty constructed probe. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: C/Rust empty normalization.
 * Example: C BER decodes `36 80 00 00` with size zero and a null buffer.
 */
static int
check_empty_constructed_storage(void) {
    static const uint8_t wire[] = {0x36, 0x80, 0, 0};
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_AsciiValue,
                                       &decoded, wire, sizeof(wire));
    AsciiValue_t *value = decoded;
    asn_enc_rval_t encoded;
    int failed = result.code != RC_OK || result.consumed != sizeof(wire)
        || !value || value->size != 0 || value->buf != NULL;
    if(!failed) {
        encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_AsciiValue,
                                       value, (uint8_t[4]){0}, 4);
        failed = encoded.encoded >= 0;
    }
    if(decoded) ASN_STRUCT_FREE(asn_DEF_AsciiValue, decoded);
    return failed;
}

/*
 * Purpose: compare C IA5 DER/CER output and decode for one valid byte vector.
 * Parameters: content/length provide IA5 data; actual vectors are ASCII.
 * Returns zero when encoding, decoded bytes, and full consumption agree.
 * Errors: any mismatch returns one. Source: generated C codec and X.690.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: live IA5 fragmentation boundary. Example: length 1001 fragments.
 */
static int
check_valid_vector(const uint8_t *content, size_t length) {
    uint8_t der[IA5_WIRE_MAX];
    uint8_t cer[IA5_WIRE_MAX];
    uint8_t actual[IA5_WIRE_MAX];
    uint8_t empty_storage = 0;
    AsciiValue_t value = {(uint8_t *)(length ? content : &empty_storage), length};
    size_t der_size = make_primitive(der, 0x16, content, length);
    size_t cer_size = make_cer(content, length, cer);
    asn_enc_rval_t encoded;

    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_AsciiValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "C IA5 DER mismatch at length %zu\n", length);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_AsciiValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "C IA5 CER mismatch at length %zu\n", length);
        return 1;
    }
    der[der_size] = 0xff;
    cer[cer_size] = 0xff;
    if(decode_matches(ATS_BER, der, der_size + 1, content, length, der_size)) return 1;
    if(decode_matches(ATS_CER, cer, cer_size + 1, content, length, cer_size)) return 1;
    return 0;
}

/*
 * Purpose: check C raw-byte BER/DER and strict CER behavior for byte 80.
 * Parameters: none. Returns zero for expected syntax-specific behavior.
 * Errors: any encode/decode mismatch returns one; decoded values are freed.
 * Source: C IA5 constraint timing probe. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: BER versus CER distinction.
 * Example: DER and BER preserve `16 01 80`; CER rejects it.
 */
static int
check_invalid_high_byte(void) {
    static const uint8_t high_byte[] = {0x80};
    static const uint8_t wire[] = {0x16, 0x01, 0x80};
    AsciiValue_t value = {(uint8_t *)high_byte, sizeof(high_byte)};
    uint8_t actual[8];
    asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, ATS_DER,
        &asn_DEF_AsciiValue, &value, actual, sizeof(actual));
    if(encoded.encoded != 3 || memcmp(actual, wire, sizeof(wire))) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_AsciiValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded >= 0) return 1;
    if(decode_matches(ATS_BER, wire, sizeof(wire), high_byte,
                      sizeof(high_byte), sizeof(wire)))
        return 1;
    return cer_rejects(wire, sizeof(wire));
}

/*
 * Purpose: check constructed BER nesting, permitted child tags, and aliases.
 * Parameters: none. Returns zero when C accepts and rejects documented forms.
 * Errors: status, value, or consumption mismatch returns one.
 * Source: X.690 constructed string rules and C probes. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: IA5 BER nested forms.
 * Example: OCTET STRING children flatten to IA5 bytes under tag 36.
 */
static int
check_constructed_ber(void) {
    static const uint8_t empty_constructed[] = {0x36, 0x80, 0, 0};
    static const uint8_t nested_definite[] = {
        0x36, 0x08, 0x04, 0x01, 'A', 0x24, 0x03, 0x04, 0x01, 'B'
    };
    static const uint8_t nested_indefinite[] = {
        0x36, 0x80, 0x04, 0x01, 'A', 0x24, 0x80, 0x04, 0x01, 'B',
        0, 0, 0, 0
    };
    static const uint8_t root_alias[] = {0x1f, 0x16, 0x01, 'A'};
    static const uint8_t child_alias[] = {
        0x36, 0x80, 0x1f, 0x04, 0x01, 'A', 0, 0
    };
    static const uint8_t invalid_high_child[] = {
        0x36, 0x80, 0x04, 0x01, 0x80, 0, 0
    };
    static const uint8_t wrong_child[] = {0x36, 0x80, 0x16, 0x01, 'A', 0, 0};
    static const uint8_t truncated_eoc[] = {0x36, 0x80, 0x04, 0x01, 'A', 0};
    static const uint8_t empty[] = {0x36, 0x80, 0x00, 0x00};
    static const uint8_t one[] = {'A'};
    static const uint8_t two[] = {'A', 'B'};

    if(decode_matches(ATS_BER, nested_definite, sizeof(nested_definite), two, 2,
                      sizeof(nested_definite))) return 1;
    if(decode_matches(ATS_BER, nested_indefinite, sizeof(nested_indefinite), two, 2,
                      sizeof(nested_indefinite))) return 1;
    if(decode_matches(ATS_BER, root_alias, sizeof(root_alias), one, 1,
                      sizeof(root_alias)))
        return 1;
    if(decode_matches(ATS_BER, child_alias, sizeof(child_alias), one, 1,
                      sizeof(child_alias)))
        return 1;
    if(decode_matches(ATS_BER, invalid_high_child, sizeof(invalid_high_child),
                      (uint8_t[]){0x80}, 1, sizeof(invalid_high_child))) return 1;
    if(decode_matches(ATS_BER, empty_constructed, sizeof(empty_constructed),
                      NULL, 0, sizeof(empty_constructed))) return 1;
    if(ber_rejects(wrong_child, sizeof(wrong_child))) return 1;
    if(ber_rejects(truncated_eoc, sizeof(truncated_eoc))) return 1;
    if(cer_rejects(empty, sizeof(empty))) return 1;
    if(cer_rejects(root_alias, sizeof(root_alias))) return 1;
    if(cer_rejects(child_alias, sizeof(child_alias))) return 1;
    if(cer_rejects(invalid_high_child, sizeof(invalid_high_child))) return 1;
    return check_empty_constructed_storage();
}

/*
 * Purpose: compare generated C IA5String fragmentation and malformed probes.
 * Parameters: none. Returns zero when every supported boundary matches.
 * Errors: mismatch returns one; all allocated decoder values are freed.
 * Source: C BER/DER/CER IA5 codec and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: direct IA5String slice.
 * Example: test empty and 999/1000/1001/2001 byte content.
 */
int
main(void) {
    static const size_t lengths[] = {0, 127, 128, 999, 1000, 1001, 2001};
    static const uint8_t control_repertoire[] = {0x00, 0x1b, 0x7f};
    uint8_t content[IA5_MAX];
    size_t index;
    memset(content, 'A', sizeof(content));
    for(index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
        if(check_valid_vector(content, lengths[index])) return 1;
    }
    if(check_valid_vector(control_repertoire, sizeof(control_repertoire))) return 1;
    if(check_invalid_high_byte() || check_constructed_ber()) {
        fprintf(stderr, "C IA5 byte validation or constructed BER probe failed\n");
        return 1;
    }
    return 0;
}
