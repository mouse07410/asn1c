/* Compare generated C BER/DER/CER codecs for OID primitive content. */
#include <asn_application.h>
#include <OBJECT_IDENTIFIER.h>
#include <OidValue.h>
#include <RelativeValue.h>
#include <RELATIVE-OID.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define OID_CONTENT_MAX 1001
#define OID_WIRE_MAX 1100

/*
 * Purpose: append the shortest definite length encoding to a test vector.
 * Parameters: output is the destination; length is the content length.
 * Returns the number of bytes appended. Errors are impossible for tested sizes.
 * Source: X.690 length encoding. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: live OID vectors.
 * Example: length 128 appends `81 80`.
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
 * Purpose: construct one expected primitive OID TLV from raw content.
 * Parameters: tag is universal 6 or 13; content and length supply base-128 data.
 * Returns total TLV size. Errors are impossible within OID_WIRE_MAX.
 * Source: X.690 universal OID tags. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: C/Rust differential vectors.
 * Example: tag 6 and content 00 become `06 01 00`.
 */
static size_t
make_tlv(uint8_t tag, const uint8_t *content, size_t length, uint8_t *output) {
    size_t length_size;
    output[0] = tag;
    length_size = append_length(output + 1, length);
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: release a decoded OID value through its selected descriptor.
 * Parameters: descriptor owns the type; value is decoder-allocated storage.
 * Returns no value. Errors cannot be reported by the runtime free callback.
 * Source: asn1c descriptor API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: leak-safe C differential.
 * Example: free a decoded OBJECT IDENTIFIER after comparing content.
 */
static void
free_value(asn_TYPE_descriptor_t *descriptor, void *value) {
    if(value) descriptor->op->free_struct(descriptor, value, ASFM_FREE_EVERYTHING);
}

/*
 * Purpose: compare C DER/CER encoding and BER/CER decoding for one OID value.
 * Parameters: descriptor selects OID flavor; tag is 6 or 13; content is canonical.
 * Returns zero for exact bytes, semantic content, and complete consumption.
 * Errors: encoder, decoder, or content mismatch returns one.
 * Source: generated C OID codec and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: OID C/Rust interoperability.
 * Example: 1001 zero subidentifiers remain primitive under CER.
 */
static int
check_vector(asn_TYPE_descriptor_t *descriptor, uint8_t tag,
             const uint8_t *content, size_t content_size) {
    uint8_t expected[OID_WIRE_MAX];
    uint8_t actual[OID_WIRE_MAX];
    OBJECT_IDENTIFIER_t value = {(uint8_t *)content, content_size};
    size_t expected_size = make_tlv(tag, content, content_size, expected);
    enum asn_transfer_syntax syntax;

    for(syntax = ATS_DER; syntax <= ATS_CER; syntax++) {
        asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, syntax, descriptor,
                                                      &value, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_size
           || memcmp(actual, expected, expected_size)) {
            fprintf(stderr, "C OID encode mismatch: tag=%02x size=%zu syntax=%d\n",
                    tag, content_size, (int)syntax);
            return 1;
        }
    }
    expected[expected_size] = 0xff;
    for(syntax = ATS_BER; syntax <= ATS_CER; syntax += 2) {
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, syntax, descriptor, &decoded,
                                            expected, expected_size + 1);
        OBJECT_IDENTIFIER_t *round_trip = decoded;
        int failed = result.code != RC_OK || result.consumed != expected_size
            || !round_trip || round_trip->size != content_size
            || (content_size && (!round_trip->buf
                || memcmp(round_trip->buf, content, content_size)));
        if(failed)
            fprintf(stderr, "C OID decode mismatch: tag=%02x size=%zu syntax=%d\n",
                    tag, content_size, (int)syntax);
        free_value(descriptor, decoded);
        if(failed) return 1;
    }
    return 0;
}

/*
 * Purpose: check C BER's raw-content compatibility for invalid OID content.
 * Parameters: descriptor and wire select the primitive type and complete TLV;
 * expected and size describe the preserved content. Returns zero on exact match.
 * Errors: non-acceptance, wrong consumption, or changed bytes returns one.
 * Source: C BER decoder behavior. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: documented C/Rust divergence.
 * Example: C BER accepts an empty OBJECT IDENTIFIER content field.
 */
static int
check_ber_raw_content(asn_TYPE_descriptor_t *descriptor,
                      const uint8_t *wire, size_t wire_size,
                      const uint8_t *expected, size_t expected_size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, descriptor, &decoded,
                                        wire, wire_size);
    OBJECT_IDENTIFIER_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != wire_size || !value
        || value->size != expected_size
        || (expected_size && (!value->buf || memcmp(value->buf, expected, expected_size)));
    if(failed)
        fprintf(stderr, "C BER raw OID mismatch: consumed=%zu/%zu\n",
                result.consumed, wire_size);
    free_value(descriptor, decoded);
    return failed;
}

/*
 * Purpose: require strict CER rejection and release any partial decode result.
 * Parameters: descriptor selects the OID flavor; wire is a full candidate TLV.
 * Returns zero for rejection. Errors: a successful CER decode returns one.
 * Source: generated C CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: canonical OID validation.
 * Example: CER rejects a redundant leading base-128 group.
 */
static int
check_cer_rejects(asn_TYPE_descriptor_t *descriptor,
                  const uint8_t *wire, size_t wire_size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, descriptor, &decoded,
                                        wire, wire_size);
    free_value(descriptor, decoded);
    return result.code == RC_OK;
}

/*
 * Purpose: compare canonical vectors and C-specific malformed BER acceptance.
 * Parameters: none. Returns zero when all OID comparisons match.
 * Errors: any unexpected encoding, decode, or consumption returns one.
 * Source: generated C reference and X.690. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: direct OID slice.
 * Example: compare 0.0, arcs above 64 bits, and 1001 content octets.
 */
int
main(void) {
    static const uint8_t oid_low[] = {0x00};
    static const uint8_t oid_first_arcs[] = {0x4f, 0x7f};
    static const uint8_t oid_high_arcs[] = {0x88, 0x37, 0x81, 0x00};
    static const uint8_t oid_large_arc[] = {
        0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00
    };
    static const uint8_t relative_low[] = {0x00};
    static const uint8_t relative_arcs[] = {0x7f, 0x81, 0x00};
    static const uint8_t relative_large_arc[] = {
        0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00
    };
    static const uint8_t empty_oid[] = {0x06, 0x00};
    static const uint8_t unterminated_oid[] = {0x06, 0x01, 0x80};
    static const uint8_t empty_relative[] = {0x0d, 0x00};
    static const uint8_t unterminated_relative[] = {0x0d, 0x01, 0x80};
    static const uint8_t oid_redundant_group[] = {0x06, 0x02, 0x80, 0x00};
    static const uint8_t relative_redundant_group[] = {0x0d, 0x02, 0x80, 0x00};
    static const uint8_t oid_tag_alias[] = {0x1f, 0x06, 0x01, 0x00};
    static const uint8_t relative_tag_alias[] = {0x1f, 0x0d, 0x01, 0x00};
    uint8_t zeros[OID_CONTENT_MAX] = {0};
    size_t lengths[] = {127, 128, 1001};
    size_t index;

    if(check_vector(&asn_DEF_OidValue, 0x06, oid_low, sizeof(oid_low))
       || check_vector(&asn_DEF_OidValue, 0x06, oid_first_arcs, sizeof(oid_first_arcs))
       || check_vector(&asn_DEF_OidValue, 0x06, oid_high_arcs, sizeof(oid_high_arcs))
       || check_vector(&asn_DEF_OidValue, 0x06, oid_large_arc, sizeof(oid_large_arc))
       || check_vector(&asn_DEF_RelativeValue, 0x0d, relative_low, sizeof(relative_low))
       || check_vector(&asn_DEF_RelativeValue, 0x0d, relative_arcs, sizeof(relative_arcs))
       || check_vector(&asn_DEF_RelativeValue, 0x0d, relative_large_arc,
                       sizeof(relative_large_arc))) return 1;
    for(index = 0; index < sizeof(lengths) / sizeof(lengths[0]); index++) {
        if(check_vector(&asn_DEF_OidValue, 0x06, zeros, lengths[index])
           || check_vector(&asn_DEF_RelativeValue, 0x0d, zeros, lengths[index]))
            return 1;
    }
    if(check_ber_raw_content(&asn_DEF_OidValue, empty_oid, sizeof(empty_oid), NULL, 0)
       || check_ber_raw_content(&asn_DEF_OidValue, unterminated_oid,
                                sizeof(unterminated_oid), (uint8_t[]){0x80}, 1)
       || check_ber_raw_content(&asn_DEF_RelativeValue, empty_relative,
                                sizeof(empty_relative), NULL, 0)
       || check_ber_raw_content(&asn_DEF_RelativeValue, unterminated_relative,
                                sizeof(unterminated_relative), (uint8_t[]){0x80}, 1))
        return 1;
    if(check_ber_raw_content(&asn_DEF_OidValue, oid_redundant_group,
                             sizeof(oid_redundant_group), (uint8_t[]){0x80, 0}, 2)
       || check_ber_raw_content(&asn_DEF_RelativeValue, relative_redundant_group,
                                sizeof(relative_redundant_group),
                                (uint8_t[]){0x80, 0}, 2)
       || check_ber_raw_content(&asn_DEF_OidValue, oid_tag_alias,
                                sizeof(oid_tag_alias), (uint8_t[]){0}, 1)
       || check_ber_raw_content(&asn_DEF_RelativeValue, relative_tag_alias,
                                sizeof(relative_tag_alias), (uint8_t[]){0}, 1))
        return 1;
    if(check_cer_rejects(&asn_DEF_OidValue, empty_oid, sizeof(empty_oid))
       || check_cer_rejects(&asn_DEF_OidValue, unterminated_oid,
                            sizeof(unterminated_oid))
       || check_cer_rejects(&asn_DEF_RelativeValue, empty_relative,
                            sizeof(empty_relative))
       || check_cer_rejects(&asn_DEF_RelativeValue, unterminated_relative,
                            sizeof(unterminated_relative))
       || check_cer_rejects(&asn_DEF_OidValue, oid_redundant_group,
                            sizeof(oid_redundant_group))
       || check_cer_rejects(&asn_DEF_RelativeValue, relative_redundant_group,
                            sizeof(relative_redundant_group))
       || check_cer_rejects(&asn_DEF_OidValue, oid_tag_alias, sizeof(oid_tag_alias))
       || check_cer_rejects(&asn_DEF_RelativeValue, relative_tag_alias,
                            sizeof(relative_tag_alias)))
        return 1;
    return 0;
}
