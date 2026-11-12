/* Compare generated C BER/DER/CER UTCTime behavior with fixed Rust vectors. */
#include <asn_application.h>
#include <OCTET_STRING.h>
#include <UtcValue.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 128

/*
 * Purpose: append a short-form definite length for bounded time values.
 * Parameters: output receives the length; length is the content size.
 * Returns the number of bytes written. Errors are impossible for these cases.
 * Source: X.690 definite length. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: UTCTime golden vectors.
 * Example: length 13 appends one octet `0d`.
 */
static size_t
append_length(uint8_t *output, size_t length) {
    if(length >= 128) return 0;
    output[0] = (uint8_t)length;
    return 1;
}

/*
 * Purpose: assemble one primitive universal tag-23 TLV.
 * Parameters: output is destination; content/length are raw UTCTime bytes.
 * Returns the encoded size. Errors are impossible for WIRE_MAX test values.
 * Source: X.690 tag 23. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: DER and CER vectors.
 * Example: `make_tlv(out, bytes, 13)` emits `17 0d` plus the content.
 */
static size_t
make_tlv(uint8_t *output, const uint8_t *content, size_t length) {
    size_t length_size;
    output[0] = 0x17;
    length_size = append_length(output + 1, length);
    if(!length_size) return 0;
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: compare one C decode's value and exact prefix consumption.
 * Parameters: syntax selects BER/CER; wire/expected and sizes describe data.
 * Returns zero on a match. Any decoded storage is released.
 * Source: generated C UTCTime descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix interoperability.
 * Example: a trailing byte is excluded from consumed time bytes.
 */
static int
decode_matches(enum asn_transfer_syntax syntax, const uint8_t *wire,
               size_t wire_size, const uint8_t *expected,
               size_t expected_size, size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_UtcValue,
                                       &decoded, wire, wire_size);
    OCTET_STRING_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != consumed || !value
        || value->size != expected_size
        || (expected_size && (!value->buf || memcmp(value->buf, expected, expected_size)));
    if(failed) {
        fprintf(stderr, "UTCTime decode mismatch: syntax=%d size=%zu/%zu consumed=%zu/%zu\n",
                (int)syntax, value ? value->size : 0, expected_size,
                result.consumed, consumed);
    }
    if(decoded && asn_DEF_UtcValue.op->free_struct)
        asn_DEF_UtcValue.op->free_struct(&asn_DEF_UtcValue, decoded,
                                         ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: require strict CER rejection and free any partial time value.
 * Parameters: wire/size is one complete candidate UTCTime TLV.
 * Returns one on rejection and zero if C accepts it.
 * Source: strict C CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: time canonicality.
 * Example: a UTC offset spelling is rejected after canonical normalization.
 */
static int
cer_rejects(const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, &asn_DEF_UtcValue,
                                       &decoded, wire, size);
    if(decoded && asn_DEF_UtcValue.op->free_struct)
        asn_DEF_UtcValue.op->free_struct(&asn_DEF_UtcValue, decoded,
                                         ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: require BER rejection for a malformed UTCTime framing vector.
 * Parameters: wire/size is one complete candidate value.
 * Returns one on rejection and zero on success; partial values are freed.
 * Source: C OCTET STRING BER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed time fragments.
 * Example: child tag 26 is not a legal constructed time fragment.
 */
static int
ber_rejects(const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_UtcValue,
                                       &decoded, wire, size);
    if(decoded && asn_DEF_UtcValue.op->free_struct)
        asn_DEF_UtcValue.op->free_struct(&asn_DEF_UtcValue, decoded,
                                         ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: compare DER raw content and normalized CER for one valid time.
 * Parameters: raw is input spelling; canonical is expected seconds-and-Z form.
 * Returns zero when both encoders and BER/CER decoders agree.
 * Source: C UTCTime CER adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: normalizing time vectors.
 * Example: `9912312359Z` canonicalizes to `991231235900Z`.
 */
static int
check_time(const uint8_t *raw, size_t raw_size, const uint8_t *canonical,
           size_t canonical_size) {
    uint8_t raw_wire[WIRE_MAX];
    uint8_t canonical_wire[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    UtcValue_t value = {(uint8_t *)raw, raw_size};
    size_t raw_wire_size = make_tlv(raw_wire, raw, raw_size);
    size_t canonical_wire_size = make_tlv(canonical_wire, canonical,
                                          canonical_size);
    asn_enc_rval_t encoded;
    if(!raw_wire_size || !canonical_wire_size) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_UtcValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)raw_wire_size
       || memcmp(actual, raw_wire, raw_wire_size)) {
        fprintf(stderr, "UTCTime DER mismatch for content size %zu\n", raw_size);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_UtcValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)canonical_wire_size
       || memcmp(actual, canonical_wire, canonical_wire_size)) {
        fprintf(stderr, "UTCTime CER normalization mismatch for content size %zu\n",
                raw_size);
        return 1;
    }
    raw_wire[raw_wire_size] = 0xff;
    canonical_wire[canonical_wire_size] = 0xff;
    if(decode_matches(ATS_BER, raw_wire, raw_wire_size + 1, raw, raw_size,
                      raw_wire_size)) return 1;
    if(decode_matches(ATS_CER, canonical_wire, canonical_wire_size + 1,
                      canonical, canonical_size, canonical_wire_size)) return 1;
    if(raw_size != canonical_size || memcmp(raw, canonical, raw_size))
        return cer_rejects(raw_wire, raw_wire_size) ? 0 : 1;
    return 0;
}

/*
 * Purpose: test strict BER/CER time validation and raw DER preservation.
 * Parameters: raw/size is arbitrary untrusted text.
 * Returns zero if BER/CER reject malformed time and DER preserves raw bytes.
 * Source: strict C UTCTime BER adapter and UTCTime CER parser.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: codec validation policy. Example: `junk` remains DER data.
 */
static int
check_invalid_time(const uint8_t *raw, size_t size) {
    uint8_t wire[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    UtcValue_t value = {(uint8_t *)raw, size};
    size_t wire_size = make_tlv(wire, raw, size);
    asn_enc_rval_t encoded;
    if(!wire_size) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_UtcValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)wire_size
       || memcmp(actual, wire, wire_size)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_UtcValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded >= 0) return 1;
    return ber_rejects(wire, wire_size) && cer_rejects(wire, wire_size) ? 0 : 1;
}

/*
 * Purpose: verify strict BER accepts a valid value at the Unix epoch edge.
 * Parameters: none. Returns zero when BER validates text without time_t conversion.
 * Source: strict C UTCTime BER adapter. Version/date: 2026-11-12.
 * Responsible party: asn1c maintainers. History: epoch sentinel regression.
 * Example: 1969-12-31 23:59:59Z remains valid ASN.1 UTCTime.
 */
static int
check_epoch_ber(void) {
    static const uint8_t epoch[] = "691231235959Z";
    uint8_t wire[WIRE_MAX];
    size_t wire_size = make_tlv(wire, epoch, sizeof(epoch) - 1);
    if(!wire_size) return 1;
    return decode_matches(ATS_BER, wire, wire_size, epoch, sizeof(epoch) - 1,
                          wire_size);
}

/*
 * Purpose: accept valid BER spellings whose CER UTC year crosses the pivot.
 * Parameters: raw/size is valid text outside CER's normalized year window.
 * Returns zero when DER and BER preserve bytes and CER rejects normalization.
 * Source: UTCTime pivot-window rules. Version/date: 2026-11-12.
 * Responsible party: asn1c maintainers. History: strict BER/CER distinction.
 * Example: `5001010000+0100` is valid BER but normalizes outside the window.
 */
static int
check_normalization_window(const uint8_t *raw, size_t size) {
    uint8_t wire[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    UtcValue_t value = {(uint8_t *)raw, size};
    size_t wire_size = make_tlv(wire, raw, size);
    asn_enc_rval_t encoded;
    if(!wire_size) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_UtcValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)wire_size
       || memcmp(actual, wire, wire_size)) return 1;
    if(decode_matches(ATS_BER, wire, wire_size, raw, size, wire_size)) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_UtcValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded >= 0) return 1;
    return cer_rejects(wire, wire_size) ? 0 : 1;
}

/*
 * Purpose: check valid nested constructed BER and strict CER framing.
 * Parameters: none. Returns zero when C accepts and rejects the fixed inputs.
 * Source: C OCTET STRING BER decoder and time descriptor CER policy.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: time framing probes. Example: tag-4 fragments flatten under tag 23.
 */
static int
check_constructed_ber(void) {
    static const uint8_t definite[] = {
        0x37, 0x13, 0x04, 0x06, '9', '9', '1', '2', '3', '1',
        0x24, 0x09, 0x04, 0x07, '2', '3', '5', '9', '0', '0', 'Z'
    };
    static const uint8_t indefinite[] = {
        0x37, 0x80, 0x04, 0x06, '9', '9', '1', '2', '3', '1',
        0x24, 0x80, 0x04, 0x07, '2', '3', '5', '9', '0', '0', 'Z',
        0, 0, 0, 0
    };
    static const uint8_t empty[] = {0x37, 0x80, 0, 0};
    static const uint8_t canonical_time[] = "991231235900Z";
    static const uint8_t canonical_constructed[] =
        "\x37\x80\x04\x0d" "991231235900Z" "\x00\x00";
    static const uint8_t root_alias[] = "\x1f\x17\x0d" "991231235900Z";
    static const uint8_t child_alias[] = {
        0x37, 0x80, 0x1f, 0x04, 0x01, 'A', 0, 0
    };
    static const uint8_t wrong_child[] = {0x37, 0x03, 0x1a, 0x01, 'A'};
    static const uint8_t truncated_eoc[] = {0x37, 0x80, 0x04, 0x01, 'A', 0};
    if(decode_matches(ATS_BER, definite, sizeof(definite), canonical_time,
                      sizeof(canonical_time) - 1, sizeof(definite))) return 1;
    if(decode_matches(ATS_BER, indefinite, sizeof(indefinite), canonical_time,
                      sizeof(canonical_time) - 1, sizeof(indefinite))) return 1;
    if(!ber_rejects(empty, sizeof(empty))) return 1;
    if(decode_matches(ATS_BER, root_alias, sizeof(root_alias),
                      canonical_time, sizeof(canonical_time) - 1,
                      sizeof(root_alias) - 1)) return 1;
    if(decode_matches(ATS_BER, canonical_constructed,
                      sizeof(canonical_constructed) - 1, canonical_time,
                      sizeof(canonical_time) - 1,
                      sizeof(canonical_constructed) - 1)) return 1;
    if(!ber_rejects(child_alias, sizeof(child_alias))) return 1;
    if(!ber_rejects(wrong_child, sizeof(wrong_child))
       || !ber_rejects(truncated_eoc, sizeof(truncated_eoc))) return 1;
    if(cer_rejects(definite, sizeof(definite))
       && cer_rejects(indefinite, sizeof(indefinite))
       && cer_rejects(empty, sizeof(empty))
       && cer_rejects(root_alias, sizeof(root_alias) - 1)
       && cer_rejects(canonical_constructed, sizeof(canonical_constructed) - 1)
       && cer_rejects(child_alias, sizeof(child_alias))
       && cer_rejects(wrong_child, sizeof(wrong_child))
       && cer_rejects(truncated_eoc, sizeof(truncated_eoc))) return 0;
    return 1;
}

/*
 * Purpose: execute C UTCTime normalizations, limits of the pivot, and errors.
 * Parameters: none. Returns zero on success and one for any mismatch.
 * Source: C CER vectors and the time_t -1 sentinel behavior.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: direct UTCTime generator comparison. Example: test leap year 2000.
 */
int
main(void) {
    /* One normalization record captures the input and expected CER wire forms. */
    static const struct {
        const uint8_t *raw; /* Original BER/DER content bytes. */
        size_t raw_size; /* Number of original content bytes. */
        const uint8_t *canonical; /* Canonical UTC seconds-and-Z bytes. */
        size_t canonical_size; /* Number of canonical content bytes. */
    } vectors[] = {
        {(const uint8_t *)"5001010000Z", 11,
         (const uint8_t *)"500101000000Z", 13},
        {(const uint8_t *)"9912312359Z", 11,
         (const uint8_t *)"991231235900Z", 13},
        {(const uint8_t *)"4912312359Z", 11,
         (const uint8_t *)"491231235900Z", 13},
        {(const uint8_t *)"991231235900Z", 13,
         (const uint8_t *)"991231235900Z", 13},
        {(const uint8_t *)"9912312359+0000", 15,
         (const uint8_t *)"991231235900Z", 13},
        {(const uint8_t *)"991231235900+0000", 17,
         (const uint8_t *)"991231235900Z", 13},
        {(const uint8_t *)"240101120000+0230", 17,
         (const uint8_t *)"240101093000Z", 13},
        {(const uint8_t *)"240101120000-0230", 17,
         (const uint8_t *)"240101143000Z", 13},
        {(const uint8_t *)"0001010030+0100", 15,
         (const uint8_t *)"991231233000Z", 13},
        {(const uint8_t *)"000229120000Z", 13,
         (const uint8_t *)"000229120000Z", 13}
    };
    static const uint8_t invalid[] = "junk";
    size_t index;
    for(index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        if(check_time(vectors[index].raw, vectors[index].raw_size,
                      vectors[index].canonical, vectors[index].canonical_size))
            return 1;
    }
    if(check_invalid_time(invalid, sizeof(invalid) - 1)) return 1;
    if(check_epoch_ber()) return 1;
    if(check_normalization_window((const uint8_t *)"5001010000+0100", 15)
       || check_normalization_window((const uint8_t *)"4912312359-0001", 15)
       || check_invalid_time((const uint8_t *)"010229000000Z", 13)
       || check_constructed_ber()) {
        fprintf(stderr, "C UTCTime invalid-value or BER framing probe failed\n");
        return 1;
    }
    return 0;
}
