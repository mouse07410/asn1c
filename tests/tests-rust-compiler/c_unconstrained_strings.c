/* Compare generated C BER/DER/CER codecs for unbounded BIT/OCTET STRINGs. */
#include <asn_application.h>
#include <BIT_STRING.h>
#include <Bits.h>
#include <OCTET_STRING.h>
#include <Octets.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAYLOAD_MAX 2001
#define WIRE_MAX 2100

/*
 * Purpose: append a shortest definite length to a C test vector.
 * Parameters: output is the destination; length is the content length.
 * Returns the number of bytes appended; test sizes fit the supported range.
 * Errors: none; callers provide WIRE_MAX storage for lengths up to PAYLOAD_MAX.
 * Original source: X.690 length encoding. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: unconstrained string parity vectors.
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
 * Purpose: append one primitive TLV with definite length.
 * Parameters: output is the destination; tag and content describe the value.
 * Returns total TLV bytes written. Errors: none for the fixed test lengths.
 * Original source: X.690 primitive encoding. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: C/Rust string vectors.
 * Example: tag 4 and empty content produce `04 00`.
 */
static size_t
append_primitive(uint8_t *output, uint8_t tag,
                 const uint8_t *content, size_t content_length) {
    size_t length_bytes;
    output[0] = tag;
    length_bytes = append_length(output + 1, content_length);
    if(content_length) memcpy(output + 1 + length_bytes, content, content_length);
    return 1 + length_bytes + content_length;
}

/*
 * Purpose: build a canonical OCTET STRING CER vector independently of C.
 * Parameters: payload supplies bytes; length is its payload size; output stores TLV.
 * Returns the encoded size. Errors: none for payload sizes no greater than 2001.
 * Original source: X.690 CER 1000-octet fragmentation. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: live boundary comparison.
 * Example: 1001 payload octets use two primitive children.
 */
static size_t
build_octet_cer(const uint8_t *payload, size_t length, uint8_t *output) {
    size_t offset = 0;
    size_t index;
    if(length <= 1000) return append_primitive(output, 0x04, payload, length);
    output[0] = 0x24;
    output[1] = 0x80;
    offset = 2;
    for(index = 0; index < length; index += 1000) {
        size_t fragment_length = length - index;
        if(fragment_length > 1000) fragment_length = 1000;
        offset += append_primitive(output + offset, 0x04,
                                   payload + index, fragment_length);
    }
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: build a canonical BIT STRING CER vector with final padding.
 * Parameters: payload, length, and unused bits describe packed data; output stores TLV.
 * Returns the encoded size. Errors: none for valid fixed test payloads.
 * Original source: X.690 CER BIT STRING fragmentation. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: C/Rust fragmented bit vectors.
 * Example: a final value with three unused bits has low bits cleared.
 */
static size_t
build_bit_cer(const uint8_t *payload, size_t length, uint8_t unused,
              uint8_t *output) {
    size_t offset;
    size_t index;
    uint8_t content[1000];
    if(length + 1 <= 1000) {
        content[0] = unused;
        if(length) memcpy(content + 1, payload, length);
        return append_primitive(output, 0x03, content, length + 1);
    }
    output[0] = 0x23;
    output[1] = 0x80;
    offset = 2;
    for(index = 0; index < length; index += 999) {
        size_t fragment_length = length - index;
        uint8_t fragment_unused;
        if(fragment_length > 999) fragment_length = 999;
        fragment_unused = index + fragment_length == length ? unused : 0;
        content[0] = fragment_unused;
        memcpy(content + 1, payload + index, fragment_length);
        offset += append_primitive(output + offset, 0x03,
                                   content, fragment_length + 1);
    }
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: compare generated C encoders and decoders for OCTET STRING vectors.
 * Parameters: length selects the payload length; payload bytes are all `5a`.
 * Returns zero when DER/CER encodings and BER/CER decoded values match.
 * Errors: encoder, decoder, prefix, or payload mismatches return one.
 * Original source: generated C codecs and X.690 vectors. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: unbounded OCTET STRING parity.
 * Example: check_octet_case(1001) checks CER fragmentation.
 */
static int
check_octet_case(size_t length) {
    uint8_t payload[PAYLOAD_MAX];
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    Octets_t value;
    enum asn_transfer_syntax syntax;
    size_t der_length;
    size_t cer_length;

    if(length > sizeof(payload)) return 1;
    memset(payload, 0x5a, length);
    value.buf = payload;
    value.size = length;
    der_length = append_primitive(der, 0x04, payload, length);
    cer_length = build_octet_cer(payload, length, cer);
    for(syntax = ATS_DER; syntax <= ATS_CER; syntax++) {
        const uint8_t *expected = syntax == ATS_DER ? der : cer;
        size_t expected_length = syntax == ATS_DER ? der_length : cer_length;
        asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, syntax,
            &asn_DEF_Octets, &value, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
           || memcmp(actual, expected, expected_length) != 0) {
            fprintf(stderr, "C OCTET STRING encode mismatch at length %zu\n", length);
            return 1;
        }
    }
    for(syntax = ATS_BER; syntax <= ATS_CER; syntax += 2) {
        const uint8_t *wire = syntax == ATS_BER ? der : cer;
        size_t wire_length = syntax == ATS_BER ? der_length : cer_length;
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_Octets,
                                            &decoded, wire, wire_length);
        Octets_t *round_trip = decoded;
        int failed = result.code != RC_OK || result.consumed != wire_length
            || !round_trip || round_trip->size != length
            || (length && (!round_trip->buf || memcmp(round_trip->buf, payload, length)));
        if(failed)
            fprintf(stderr, "C OCTET STRING decode mismatch at length %zu\n", length);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Octets, decoded);
        if(failed) return 1;
    }
    return 0;
}

/*
 * Purpose: compare generated C encoders and decoders for BIT STRING vectors.
 * Parameters: length selects payload bytes; unused selects final zero padding.
 * Returns zero when DER/CER encodings and BER/CER decoded values match.
 * Errors: encoder, decoder, padding, or payload mismatches return one.
 * Original source: generated C codecs and X.690 vectors. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: unbounded BIT STRING parity.
 * Example: check_bit_case(1000, 3) checks a fragmented padded final octet.
 */
static int
check_bit_case(size_t length, uint8_t unused) {
    uint8_t payload[PAYLOAD_MAX];
    uint8_t der_content[PAYLOAD_MAX + 1];
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    Bits_t value;
    enum asn_transfer_syntax syntax;
    size_t der_length;
    size_t cer_length;

    if(length > sizeof(payload) || unused > 7 || (!length && unused)) return 1;
    memset(payload, 0x5a, length);
    if(length && unused) payload[length - 1] &= (uint8_t)(0xffu << unused);
    value.buf = payload;
    value.size = length;
    value.bits_unused = unused;
    der_content[0] = unused;
    if(length) memcpy(der_content + 1, payload, length);
    der_length = append_primitive(der, 0x03, der_content, length + 1);
    cer_length = build_bit_cer(payload, length, unused, cer);
    for(syntax = ATS_DER; syntax <= ATS_CER; syntax++) {
        const uint8_t *expected = syntax == ATS_DER ? der : cer;
        size_t expected_length = syntax == ATS_DER ? der_length : cer_length;
        asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, syntax,
            &asn_DEF_Bits, &value, actual, sizeof(actual));
        if(encoded.encoded < 0 || (size_t)encoded.encoded != expected_length
           || memcmp(actual, expected, expected_length) != 0) {
            fprintf(stderr, "C BIT STRING encode mismatch at %zu/%u\n",
                    length, (unsigned)unused);
            return 1;
        }
    }
    for(syntax = ATS_BER; syntax <= ATS_CER; syntax += 2) {
        const uint8_t *wire = syntax == ATS_BER ? der : cer;
        size_t wire_length = syntax == ATS_BER ? der_length : cer_length;
        void *decoded = NULL;
        asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_Bits,
                                            &decoded, wire, wire_length);
        Bits_t *round_trip = decoded;
        int failed = result.code != RC_OK || result.consumed != wire_length
            || !round_trip || round_trip->size != length
            || round_trip->bits_unused != (int)unused
            || (length && (!round_trip->buf || memcmp(round_trip->buf, payload, length)));
        if(failed)
            fprintf(stderr, "C BIT STRING decode mismatch at %zu/%u\n",
                    length, (unsigned)unused);
        if(decoded) ASN_STRUCT_FREE(asn_DEF_Bits, decoded);
        if(failed) return 1;
    }
    return 0;
}

/*
 * Purpose: check an OCTET STRING BER decode and release all decoder storage.
 * Parameters: wire/length are input bytes; expected/size describe value; consumed
 * is the expected prefix size. Returns zero for a matching value and prefix.
 * Errors: decoder failure or mismatch returns one. Original source: C BER probe.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: leak-safe probes.
 * Example: a one-byte prefix decodes `04 01 5a ff` as `5a`.
 */
static int
octets_match(const uint8_t *wire, size_t length, const uint8_t *expected,
             size_t size, size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Octets,
                                       &decoded, wire, length);
    Octets_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != consumed || !value
        || value->size != size
        || (size && (!value->buf || memcmp(value->buf, expected, size)));
    if(failed) fprintf(stderr, "OCTET BER mismatch: size=%zu consumed=%zu/%zu\n",
                       size, result.consumed, consumed);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Octets, decoded);
    return failed;
}

/*
 * Purpose: check a BIT STRING BER decode, its exact bit shape, and release memory.
 * Parameters: wire/length are input bytes; expected/size/unused describe value;
 * consumed is the expected prefix size. Returns zero for a matching value.
 * Errors: decoder failure or mismatch returns one. Original source: C BER probe.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: leak-safe probes.
 * Example: `03 02 03 a7` normalizes to byte `a0` with five significant bits.
 */
static int
bits_match(const uint8_t *wire, size_t length, const uint8_t *expected,
           size_t size, int unused, size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_Bits,
                                       &decoded, wire, length);
    Bits_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != consumed || !value
        || value->size != size || value->bits_unused != unused
        || (size && (!value->buf || memcmp(value->buf, expected, size)));
    if(failed) fprintf(stderr, "BIT BER mismatch: size=%zu unused=%d consumed=%zu/%zu\n",
                       size, unused, result.consumed, consumed);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Bits, decoded);
    return failed;
}

/*
 * Purpose: ensure strict CER rejects an OCTET STRING vector and free partial data.
 * Parameters: wire and length are the complete candidate TLV. Returns zero only
 * when decoding rejects it. Errors: accidental acceptance returns one.
 * Original source: generated C CER decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: alias and canonicality probes.
 * Example: a nonminimal fragment identifier must be rejected.
 */
static int
octets_cer_rejects(const uint8_t *wire, size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, &asn_DEF_Octets,
                                       &decoded, wire, length);
    if(result.code == RC_OK) fprintf(stderr, "OCTET CER accepted alias/BER form\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Octets, decoded);
    return result.code == RC_OK;
}

/*
 * Purpose: ensure strict CER rejects a BIT STRING vector and free partial data.
 * Parameters: wire and length are the complete candidate TLV. Returns zero only
 * when decoding rejects it. Errors: accidental acceptance returns one.
 * Original source: generated C CER decoder. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: alias and padding probes.
 * Example: nonzero unused bits in a final octet must be rejected.
 */
static int
bits_cer_rejects(const uint8_t *wire, size_t length) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, &asn_DEF_Bits,
                                       &decoded, wire, length);
    if(result.code == RC_OK) fprintf(stderr, "BIT CER accepted alias/BER form\n");
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Bits, decoded);
    return result.code == RC_OK;
}

/*
 * Purpose: probe aliases, constructed values, prefixes, and malformed BIT behavior.
 * Parameters: none. Returns zero when C compatibility forms match the probes.
 * Errors: unexpected status, consumption, or value returns one.
 * Original source: C BER/CER implementation probes and X.690. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: string alias differences.
 * Example: BER accepts an OCTET STRING high-tag alias and CER rejects it.
 */
static int
check_alias_padding_and_prefix(void) {
    static const uint8_t octet_alias[] = {0x1f, 0x04, 0x01, 0x5a};
    static const uint8_t bit_alias[] = {0x1f, 0x03, 0x02, 0x00, 0xa0};
    static const uint8_t octet_fragment_alias[] = {
        0x24, 0x80, 0x1f, 0x04, 0x01, 0xaa, 0x00, 0x00
    };
    static const uint8_t bit_fragment_alias[] = {
        0x23, 0x80, 0x1f, 0x03, 0x02, 0x00, 0xa0, 0x00, 0x00
    };
    static const uint8_t nonfinal_padding[] = {
        0x23, 0x80, 0x03, 0x02, 0x03, 0xa0,
        0x03, 0x02, 0x00, 0xaa, 0x00, 0x00
    };
    static const uint8_t empty_constructed_octets[] = {0x24, 0x80, 0, 0};
    static const uint8_t empty_constructed_bits[] = {0x23, 0x80, 0, 0};
    static const uint8_t nested_definite_octets[] = {
        0x24, 0x08, 0x04, 0x02, 0x5a, 0x5a, 0x24, 0x02, 0x04, 0x00
    };
    static const uint8_t nested_indefinite_octets[] = {
        0x24, 0x80, 0x04, 0x01, 0xaa, 0x24, 0x80, 0x04, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t nested_definite_bits[] = {
        0x23, 0x08, 0x03, 0x02, 0, 0xa0, 0x03, 0x02, 0, 0x58
    };
    static const uint8_t nested_indefinite_bits[] = {
        0x23, 0x80, 0x03, 0x02, 0, 0xa0, 0x23, 0x80,
        0x03, 0x02, 0, 0x58, 0, 0, 0, 0
    };
    static const uint8_t prefixed_octets[] = {0x04, 0x01, 0x5a, 0xff};
    static const uint8_t one_octet[] = {0xaa};
    static const uint8_t five_a_octet[] = {0x5a};
    static const uint8_t two_octets[] = {0xaa, 0xbb};
    static const uint8_t bit_bytes[] = {0xa0, 0x58};
    static const uint8_t alias_bit[] = {0xa0};
    uint8_t invalid_padding[] = {0xa7};
    Bits_t malformed = {invalid_padding, sizeof(invalid_padding), 3, {0}};
    uint8_t actual[8];
    asn_enc_rval_t encoded;

    if(octets_match(octet_alias, sizeof(octet_alias), five_a_octet, 1,
                    sizeof(octet_alias))) return 1;
    if(octets_cer_rejects(octet_alias, sizeof(octet_alias))) return 1;
    if(bits_match(bit_alias, sizeof(bit_alias), alias_bit, 1, 0,
                  sizeof(bit_alias))) return 1;
    if(bits_cer_rejects(bit_alias, sizeof(bit_alias))) return 1;
    if(octets_match(octet_fragment_alias, sizeof(octet_fragment_alias),
                    one_octet, 1, sizeof(octet_fragment_alias))) return 1;
    if(octets_cer_rejects(octet_fragment_alias,
                          sizeof(octet_fragment_alias))) return 1;
    if(bits_match(bit_fragment_alias, sizeof(bit_fragment_alias), alias_bit,
                  1, 0, sizeof(bit_fragment_alias))) return 1;
    if(bits_cer_rejects(bit_fragment_alias, sizeof(bit_fragment_alias))) return 1;
    if(bits_match(nonfinal_padding, sizeof(nonfinal_padding),
                  (uint8_t[]){0xa0, 0xaa}, 2, 0,
                  sizeof(nonfinal_padding))) return 1;
    if(bits_cer_rejects(nonfinal_padding, sizeof(nonfinal_padding))) return 1;
    if(octets_match(prefixed_octets, sizeof(prefixed_octets),
                    five_a_octet, 1, 3)) return 1;
    if(octets_match(empty_constructed_octets, sizeof(empty_constructed_octets),
                    NULL, 0, sizeof(empty_constructed_octets))) return 1;
    if(bits_match(empty_constructed_bits, sizeof(empty_constructed_bits),
                  NULL, 0, 0, sizeof(empty_constructed_bits))) return 1;
    if(octets_match(nested_definite_octets, sizeof(nested_definite_octets),
                    (uint8_t[]){0x5a, 0x5a}, 2,
                    sizeof(nested_definite_octets))) return 1;
    if(octets_match(nested_indefinite_octets, sizeof(nested_indefinite_octets),
                    two_octets, 2, sizeof(nested_indefinite_octets))) return 1;
    if(bits_match(nested_definite_bits, sizeof(nested_definite_bits), bit_bytes,
                  2, 0, sizeof(nested_definite_bits))) return 1;
    if(bits_match(nested_indefinite_bits, sizeof(nested_indefinite_bits),
                  bit_bytes, 2, 0, sizeof(nested_indefinite_bits))) return 1;

    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_Bits, &malformed,
                                   actual, sizeof(actual));
    if(encoded.encoded != 4 || memcmp(actual, (uint8_t[]){3, 2, 3, 0xa0}, 4))
        return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_Bits, &malformed,
                                   actual, sizeof(actual));
    return encoded.encoded >= 0;
}

/*
 * Purpose: run exact C/Rust string boundaries and C compatibility probes.
 * Parameters: none. Returns zero when all vectors and probes pass.
 * Errors: any mismatch returns one; no exception is thrown.
 * Original source: generated C string codecs and X.690. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: unconstrained string generator stage.
 * Example: run this fixture after C and Rust generation.
 */
int
main(void) {
    static const size_t octet_lengths[] = {0, 999, 1000, 1001, 2001};
    static const size_t bit_lengths[] = {0, 998, 999, 1000, 1000, 2001};
    static const uint8_t unused_bits[] = {0, 0, 0, 0, 3, 3};
    size_t index;
    for(index = 0; index < sizeof(octet_lengths) / sizeof(octet_lengths[0]); index++) {
        if(check_octet_case(octet_lengths[index])) return 1;
    }
    for(index = 0; index < sizeof(bit_lengths) / sizeof(bit_lengths[0]); index++) {
        if(check_bit_case(bit_lengths[index], unused_bits[index])) return 1;
    }
    if(check_alias_padding_and_prefix()) {
        fprintf(stderr, "C BER/CER string alias or padding probe failed\n");
        return 1;
    }
    return 0;
}
