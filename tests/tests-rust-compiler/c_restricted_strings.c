/* Compare C BER/DER/CER codecs for direct restricted character-string roots. */
#include <asn_application.h>
#include <OCTET_STRING.h>
#include <ObjectDescriptorValue.h>
#include <UTF8Value.h>
#include <NumericValue.h>
#include <PrintableValue.h>
#include <TeletexValue.h>
#include <T61Value.h>
#include <VideotexValue.h>
#include <GraphicValue.h>
#include <VisibleValue.h>
#include <ISO646Value.h>
#include <GeneralValue.h>
#include <UniversalValue.h>
#include <BMPValue.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CONTENT_MAX 2001
#define WIRE_MAX 2300

/*
 * Purpose: append a shortest definite length.
 * Parameters: output receives length octets; length is content size.
 * Returns the number of bytes appended. Errors are impossible for bounded tests.
 * Source: X.690. Version/date: 2026-11-01. Responsible party: maintainers.
 * History: restricted string differential. Example: length 1001 is `82 03 e9`.
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
 * Purpose: append one primitive universal string TLV.
 * Parameters: output is destination; tag/content/length define the value.
 * Returns total encoded bytes. Errors are impossible for fixed test buffers.
 * Source: X.690. Version/date: 2026-11-01. Responsible party: maintainers.
 * History: expected C vectors. Example: empty tag 12 is `0c 00`.
 */
static size_t
make_primitive(uint8_t *output, uint8_t tag, const uint8_t *content,
               size_t length) {
    size_t length_size;
    output[0] = tag;
    length_size = append_length(output + 1, length);
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: build canonical CER primitive or 1000-octet fragments.
 * Parameters: output receives encoding; tag/content/length describe value.
 * Returns encoded size. Errors are impossible for CONTENT_MAX input.
 * Source: X.690 CER. Version/date: 2026-11-01. Responsible party: maintainers.
 * History: live fragment boundaries. Example: 1001 bytes use outer constructed tag.
 */
static size_t
make_cer(uint8_t *output, uint8_t tag, const uint8_t *content, size_t length) {
    size_t offset = 0;
    size_t index;
    if(length <= 1000) return make_primitive(output, tag, content, length);
    output[offset++] = (uint8_t)(tag | 0x20);
    output[offset++] = 0x80;
    for(index = 0; index < length; index += 1000) {
        size_t part = length - index;
        if(part > 1000) part = 1000;
        offset += make_primitive(output + offset, 4, content + index, part);
    }
    output[offset++] = 0;
    output[offset++] = 0;
    return offset;
}

/*
 * Purpose: decode and compare content plus exact prefix consumption.
 * Parameters: td selects a generated descriptor; syntax/wire/expected are input.
 * Returns zero on match. All partially or fully decoded storage is freed.
 * Source: generated C BER/CER decoders. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: differential decode checks.
 * Example: a suffix byte is excluded from the decoded prefix.
 */
static int
decode_matches(asn_TYPE_descriptor_t *td, enum asn_transfer_syntax syntax,
               const uint8_t *wire, size_t wire_size, const uint8_t *expected,
               size_t expected_size, size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, td, &decoded, wire, wire_size);
    OCTET_STRING_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != consumed || !value
        || value->size != expected_size
        || (expected_size && (!value->buf || memcmp(value->buf, expected, expected_size)));
    if(failed) {
        fprintf(stderr, "%s decode mismatch: syntax=%d consumed=%zu/%zu size=%zu/%zu\n",
                td->name, (int)syntax, result.consumed, consumed,
                value ? value->size : 0, expected_size);
    }
    if(decoded && td->op->free_struct)
        td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: require a strict CER decoder to reject a supplied encoding.
 * Parameters: td selects the root type; wire/size is one candidate TLV.
 * Returns one on rejection and zero on success; decoded storage is always freed.
 * Source: generated C CER decoder. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: canonicality probes.
 * Example: CER rejects a nonminimal constructed representation.
 */
static int
cer_rejects(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, td, &decoded, wire, size);
    if(decoded && td->op->free_struct)
        td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: require BER rejection for malformed input and free partial storage.
 * Parameters: td selects the descriptor; wire and size are the candidate TLV.
 * Returns one on rejection and zero on success; no allocation is retained.
 * Source: generated C BER decoder. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: malformed string vectors.
 * Example: a wrong fragment tag must fail BER decoding.
 */
static int
ber_rejects(asn_TYPE_descriptor_t *td, const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, td, &decoded, wire, size);
    if(decoded && td->op->free_struct)
        td->op->free_struct(td, decoded, ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: compare one type's C DER/CER output and both decode paths.
 * Parameters: td/tag identify the type; content/size are raw bytes.
 * Returns zero on exact parity; failure identifies type and content size.
 * Source: generated C descriptors and X.690. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: per-kind live C vectors.
 * Example: `check_valid(&asn_DEF_UTF8Value, 12, bytes, 1001)`.
 */
static int
check_valid(asn_TYPE_descriptor_t *td, uint8_t tag, const uint8_t *content,
            size_t size) {
    uint8_t der[WIRE_MAX];
    uint8_t cer[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    uint8_t empty_storage = 0;
    OCTET_STRING_t value = {(uint8_t *)(size ? content : &empty_storage), size};
    size_t der_size = make_primitive(der, tag, content, size);
    size_t cer_size = make_cer(cer, tag, content, size);
    asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, ATS_DER, td, &value,
                                                  actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != der_size
       || memcmp(actual, der, der_size)) {
        fprintf(stderr, "%s DER mismatch at content length %zu\n", td->name, size);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, td, &value, actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != cer_size
       || memcmp(actual, cer, cer_size)) {
        fprintf(stderr, "%s CER mismatch at content length %zu\n", td->name, size);
        return 1;
    }
    der[der_size] = 0xff;
    cer[cer_size] = 0xff;
    if(decode_matches(td, ATS_BER, der, der_size + 1, content, size, der_size)) return 1;
    if(decode_matches(td, ATS_CER, cer, cer_size + 1, content, size, cer_size)) return 1;
    if(decode_matches(td, ATS_BER, cer, cer_size, content, size, cer_size)) return 1;
    return 0;
}

/*
 * Purpose: prove invalid raw bytes remain BER/DER data but fail CER validation.
 * Parameters: td/tag choose the C descriptor; content/size is invalid there.
 * Returns zero on expected timing. Errors are reported as mismatch.
 * Source: C descriptor constraints. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: BER/CER constraint split.
 * Example: high-bit UTF8 content is BER data and invalid CER.
 */
static int
check_invalid_cer(asn_TYPE_descriptor_t *td, uint8_t tag,
                  const uint8_t *content, size_t size) {
    uint8_t wire[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    OCTET_STRING_t value = {(uint8_t *)content, size};
    size_t wire_size = make_primitive(wire, tag, content, size);
    asn_enc_rval_t encoded = asn_encode_to_buffer(NULL, ATS_DER, td, &value,
                                                  actual, sizeof(actual));
    if(encoded.encoded < 0 || (size_t)encoded.encoded != wire_size
       || memcmp(actual, wire, wire_size)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, td, &value, actual, sizeof(actual));
    if(encoded.encoded >= 0) return 1;
    if(decode_matches(td, ATS_BER, wire, wire_size, content, size, wire_size)) return 1;
    return cer_rejects(td, wire, wire_size) ? 0 : 1;
}

/*
 * Purpose: test constructed BER nesting, universal OCTET fragments, and errors.
 * Parameters: td/tag/unit select type and valid content alignment.
 * Returns zero on accepted/rejected forms. Decoded values are freed.
 * Source: C BER decoder probes. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: generic constructed strings.
 * Example: nested tag-4 fragments flatten to `AB`.
 */
static int
check_constructed(asn_TYPE_descriptor_t *td, uint8_t tag, size_t unit) {
    uint8_t first[4] = {'A', 0, 0, 0};
    uint8_t second[4] = {'B', 0, 0, 0};
    uint8_t one[4];
    uint8_t two[8];
    uint8_t child_first[16];
    uint8_t child_second[16];
    uint8_t nested[32];
    uint8_t content[64];
    uint8_t definite[80];
    uint8_t indefinite[80];
    uint8_t empty[] = {0, 0x80, 0, 0};
    uint8_t wrong[32];
    uint8_t truncated[32];
    uint8_t root_alias[16];
    uint8_t child_alias[24];
    size_t first_size, second_size, nested_size, content_size, definite_size;
    size_t indefinite_size, wrong_size, truncated_size, offset;
    size_t root_alias_size, child_alias_size;
    if(tag == 18) {
        first[0] = '1';
        second[0] = '2';
    } else if(tag == 30) {
        first[0] = 0;
        first[1] = 'A';
        second[0] = 0;
        second[1] = 'B';
    } else if(tag == 28) {
        first[0] = first[1] = first[2] = 0;
        first[3] = 'A';
        second[0] = second[1] = second[2] = 0;
        second[3] = 'B';
    }
    memcpy(one, first, unit);
    memcpy(two, first, unit);
    memcpy(two + unit, second, unit);
    first_size = make_primitive(child_first, 4, first, unit);
    second_size = make_primitive(child_second, 4, second, unit);
    nested_size = make_primitive(nested, 0x24, child_second, second_size);
    memcpy(content, child_first, first_size);
    memcpy(content + first_size, nested, nested_size);
    content_size = first_size + nested_size;
    definite_size = make_primitive(definite, (uint8_t)(tag | 0x20),
                                   content, content_size);
    offset = 0;
    indefinite[offset++] = (uint8_t)(tag | 0x20);
    indefinite[offset++] = 0x80;
    memcpy(indefinite + offset, child_first, first_size);
    offset += first_size;
    indefinite[offset++] = 0x24;
    indefinite[offset++] = 0x80;
    memcpy(indefinite + offset, child_second, second_size);
    offset += second_size;
    indefinite[offset++] = 0;
    indefinite[offset++] = 0;
    indefinite[offset++] = 0;
    indefinite[offset++] = 0;
    indefinite_size = offset;
    empty[0] = (uint8_t)(tag | 0x20);
    offset = 0;
    wrong[offset++] = (uint8_t)(tag | 0x20);
    wrong[offset++] = 0x80;
    offset += make_primitive(wrong + offset, tag, first, unit);
    wrong[offset++] = 0;
    wrong[offset++] = 0;
    wrong_size = offset;
    root_alias[0] = 0x1f;
    root_alias[1] = tag;
    root_alias_size = 2 + append_length(root_alias + 2, unit);
    memcpy(root_alias + root_alias_size, one, unit);
    root_alias_size += unit;
    child_alias[0] = (uint8_t)(tag | 0x20);
    child_alias[1] = 0x80;
    child_alias[2] = 0x1f;
    child_alias[3] = 4;
    child_alias_size = 4 + append_length(child_alias + 4, unit);
    memcpy(child_alias + child_alias_size, one, unit);
    child_alias_size += unit;
    child_alias[child_alias_size++] = 0;
    child_alias[child_alias_size++] = 0;
    offset = 0;
    truncated[offset++] = (uint8_t)(tag | 0x20);
    truncated[offset++] = 0x80;
    offset += make_primitive(truncated + offset, 4, first, unit);
    truncated[offset++] = 0;
    truncated_size = offset;
    if(decode_matches(td, ATS_BER, definite, definite_size, two, unit * 2,
                      definite_size)) return 1;
    if(decode_matches(td, ATS_BER, indefinite, indefinite_size,
                      two, unit * 2, indefinite_size)) return 1;
    if(decode_matches(td, ATS_BER, empty, sizeof(empty), NULL, 0, sizeof(empty))) return 1;
    if(decode_matches(td, ATS_BER, root_alias, root_alias_size, one, unit,
                      root_alias_size)) return 1;
    if(decode_matches(td, ATS_BER, child_alias, child_alias_size, one, unit,
                      child_alias_size)) return 1;
    if(!ber_rejects(td, wrong, wrong_size)
       || !ber_rejects(td, truncated, truncated_size)) return 1;
    if(!cer_rejects(td, definite, definite_size)
       || !cer_rejects(td, indefinite, indefinite_size)
       || !cer_rejects(td, empty, sizeof(empty))
       || !cer_rejects(td, root_alias, root_alias_size)
       || !cer_rejects(td, child_alias, child_alias_size)
       || !cer_rejects(td, wrong, wrong_size)
       || !cer_rejects(td, truncated, truncated_size)) return 1;
    return 0;
}

/*
 * Purpose: exercise C's legacy-compatible UTF8 validator on CER paths.
 * Parameters: none. Returns zero when minimal legacy forms pass and invalid
 * forms fail. Errors are reported by check helpers. Source: C descriptor
 * probes. Version/date: 2026-11-01. Responsible party: maintainers.
 * History: C-compatible 1-6-byte UTF8. Example: six-byte minimal form passes.
 */
static int
check_utf8_legacy(void) {
    static const uint8_t valid[] = {
        0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80,
        0xf8, 0x88, 0x80, 0x80, 0x80,
        0xfc, 0x84, 0x80, 0x80, 0x80, 0x80
    };
    static const uint8_t invalid[] = {
        0xc0, 0x80, 0xe2, 0x82, 0xfe
    };
    uint8_t split[1002];
    memset(split, 'A', 999);
    split[999] = 0xe2;
    split[1000] = 0x82;
    split[1001] = 0xac;
    return check_valid(&asn_DEF_UTF8Value, 12, valid, sizeof(valid))
        || check_valid(&asn_DEF_UTF8Value, 12, split, sizeof(split))
        || check_invalid_cer(&asn_DEF_UTF8Value, 12, invalid, sizeof(invalid));
}

/*
 * Purpose: run the live C vector suite for all aliases and validators.
 * Parameters: none. Returns zero on success; failure reports the type.
 * Source: generated C runtime and approved design matrix. Version/date: 2026-11-01.
 * Responsible party: maintainers. History: direct restricted-string support.
 * Example: both T61 and Teletex descriptors exercise tag 20 independently.
 */
int
main(void) {
    /* Map each generated descriptor to its intrinsic tag and valid unit size. */
    static const struct {
        asn_TYPE_descriptor_t *td; /* Generated C descriptor under test. */
        uint8_t tag; /* Intrinsic universal tag number. */
        size_t unit; /* Content alignment required by CER, otherwise one. */
    } kinds[] = {
        {&asn_DEF_ObjectDescriptorValue, 7, 1},
        {&asn_DEF_UTF8Value, 12, 1},
        {&asn_DEF_NumericValue, 18, 1},
        {&asn_DEF_PrintableValue, 19, 1},
        {&asn_DEF_TeletexValue, 20, 1},
        {&asn_DEF_T61Value, 20, 1},
        {&asn_DEF_VideotexValue, 21, 1},
        {&asn_DEF_GraphicValue, 25, 1},
        {&asn_DEF_VisibleValue, 26, 1},
        {&asn_DEF_ISO646Value, 26, 1},
        {&asn_DEF_GeneralValue, 27, 1},
        {&asn_DEF_UniversalValue, 28, 4},
        {&asn_DEF_BMPValue, 30, 2}
    };
    static const size_t byte_lengths[] = {0, 127, 128, 999, 1000, 1001};
    static const uint8_t numeric_invalid[] = {'A'};
    static const uint8_t printable_invalid[] = {'@'};
    static const uint8_t visible_invalid[] = {0x7f};
    static const uint8_t utf8_invalid[] = {0xc0, 0x80};
    static const uint8_t bmp_invalid[] = {0x41};
    static const uint8_t universal_invalid[] = {0, 0, 0};
    static const uint8_t bmp_surrogate[] = {0xd8, 0x00};
    static const uint8_t universal_out_of_range[] = {0, 0x11, 0, 0};
    uint8_t content[CONTENT_MAX];
    uint8_t numeric_content[CONTENT_MAX];
    size_t index;
    memset(content, 'A', sizeof(content));
    memset(numeric_content, '1', sizeof(numeric_content));
    for(index = 0; index < sizeof(kinds) / sizeof(kinds[0]); index++) {
        size_t j;
        for(j = 0; j < sizeof(byte_lengths) / sizeof(byte_lengths[0]); j++) {
            size_t length = byte_lengths[j];
            if(length % kinds[index].unit) continue;
            const uint8_t *bytes = kinds[index].td == &asn_DEF_NumericValue
                ? numeric_content : content;
            if(check_valid(kinds[index].td, kinds[index].tag, bytes, length)) return 1;
        }
        if(check_constructed(kinds[index].td, kinds[index].tag,
                             kinds[index].unit)) return 1;
    }
    if(check_valid(&asn_DEF_BMPValue, 30, content, 1002)
       || check_valid(&asn_DEF_UniversalValue, 28, content, 1004)) return 1;
    if(check_invalid_cer(&asn_DEF_NumericValue, 18, numeric_invalid,
                         sizeof(numeric_invalid))
       || check_invalid_cer(&asn_DEF_PrintableValue, 19, printable_invalid,
                            sizeof(printable_invalid))
       || check_invalid_cer(&asn_DEF_VisibleValue, 26, visible_invalid,
                            sizeof(visible_invalid))
       || check_invalid_cer(&asn_DEF_ISO646Value, 26, visible_invalid,
                            sizeof(visible_invalid))
       || check_invalid_cer(&asn_DEF_UTF8Value, 12, utf8_invalid,
                            sizeof(utf8_invalid))
       || check_invalid_cer(&asn_DEF_BMPValue, 30, bmp_invalid,
                            sizeof(bmp_invalid))
       || check_invalid_cer(&asn_DEF_UniversalValue, 28, universal_invalid,
                            sizeof(universal_invalid))) {
        fprintf(stderr, "C restricted-string CER validation mismatch\n");
        return 1;
    }
    if(check_utf8_legacy()) {
        fprintf(stderr, "C UTF8 legacy validation or fragmentation mismatch\n");
        return 1;
    }
    if(check_valid(&asn_DEF_BMPValue, 30, bmp_surrogate, sizeof(bmp_surrogate))
       || check_valid(&asn_DEF_UniversalValue, 28, universal_out_of_range,
                      sizeof(universal_out_of_range))) {
        fprintf(stderr, "C BMP/Universal code-unit compatibility mismatch\n");
        return 1;
    }
    return 0;
}
