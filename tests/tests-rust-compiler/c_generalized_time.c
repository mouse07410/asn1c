/* Compare C GeneralizedTime adapter behavior against fixed Rust vectors. */
#include <asn_application.h>
#include <GeneralizedTime.h>
#include <GenValue.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_MAX 128

/*
 * Purpose: append a short-form definite length for bounded time vectors.
 * Parameters: output receives one length byte; length is the content size.
 * Returns the byte count or zero when the input would need long form.
 * Source: X.690 definite length. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: GeneralizedTime vectors.
 * Example: length fifteen appends `0f`.
 */
static size_t
append_length(uint8_t *output, size_t length) {
    if(length >= 128) return 0;
    output[0] = (uint8_t)length;
    return 1;
}

/*
 * Purpose: assemble one primitive universal tag-24 TLV.
 * Parameters: output receives the wire; content/length are raw bytes.
 * Returns encoded size or zero for unsupported test lengths.
 * Source: X.690 tag 24. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: time interoperability.
 * Example: `make_tlv(out, text, 15)` emits `18 0f` plus the text.
 */
static size_t
make_tlv(uint8_t *output, const uint8_t *content, size_t length) {
    size_t length_size;
    output[0] = 0x18;
    length_size = append_length(output + 1, length);
    if(!length_size) return 0;
    if(length) memcpy(output + 1 + length_size, content, length);
    return 1 + length_size + length;
}

/*
 * Purpose: compare one C BER/CER decode's content and prefix consumption.
 * Parameters: syntax selects BER/CER; wire and expected describe the value.
 * Returns zero on a match and frees every allocated decode result.
 * Source: generated GeneralizedTime descriptor. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prefix interoperability.
 * Example: a suffix is left outside the consumed prefix.
 */
static int
decode_matches(enum asn_transfer_syntax syntax, const uint8_t *wire,
               size_t wire_size, const uint8_t *expected,
               size_t expected_size, size_t consumed) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, syntax, &asn_DEF_GenValue,
                                       &decoded, wire, wire_size);
    GeneralizedTime_t *value = decoded;
    int failed = result.code != RC_OK || result.consumed != consumed || !value
        || value->size != expected_size
        || (expected_size && (!value->buf || memcmp(value->buf, expected, expected_size)));
    if(failed) {
        fprintf(stderr,
            "GeneralizedTime decode mismatch: syntax=%d size=%zu/%zu consumed=%zu/%zu\n",
            (int)syntax, value ? value->size : 0, expected_size,
            result.consumed, consumed);
    }
    if(decoded && asn_DEF_GenValue.op->free_struct)
        asn_DEF_GenValue.op->free_struct(&asn_DEF_GenValue, decoded,
                                         ASFM_FREE_EVERYTHING);
    return failed;
}

/*
 * Purpose: require strict CER rejection and release partial decoder storage.
 * Parameters: wire/size is one complete candidate GeneralizedTime TLV.
 * Returns one on rejection and zero when C accepts the input.
 * Source: strict C CER decoder. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: canonical framing checks.
 * Example: a canonicalized source offset is rejected as noncanonical CER.
 */
static int
cer_rejects(const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_CER, &asn_DEF_GenValue,
                                       &decoded, wire, size);
    if(decoded && asn_DEF_GenValue.op->free_struct)
        asn_DEF_GenValue.op->free_struct(&asn_DEF_GenValue, decoded,
                                         ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: require BER rejection for a malformed GeneralizedTime TLV.
 * Parameters: wire/size is one complete candidate encoding.
 * Returns one on rejection and frees any partially returned value.
 * Source: C OCTET STRING BER adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: malformed fragment tests.
 * Example: universal tag 26 is not a legal tag-4 fragment.
 */
static int
ber_rejects(const uint8_t *wire, size_t size) {
    void *decoded = NULL;
    asn_dec_rval_t result = asn_decode(NULL, ATS_BER, &asn_DEF_GenValue,
                                       &decoded, wire, size);
    if(decoded && asn_DEF_GenValue.op->free_struct)
        asn_DEF_GenValue.op->free_struct(&asn_DEF_GenValue, decoded,
                                         ASFM_FREE_EVERYTHING);
    return result.code != RC_OK;
}

/*
 * Purpose: require C CER encoding to reject one raw time string.
 * Parameters: raw/size is the source content, without a tag or length.
 * Returns one when the encoder fails and zero when it emits a value.
 * Source: C GeneralizedTime CER adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: invalid-time checks.
 * Example: a missing timezone is rejected before CER output.
 */
static int
cer_encode_rejects(const uint8_t *raw, size_t size) {
    uint8_t output[WIRE_MAX];
    GeneralizedTime_t value = {(uint8_t *)raw, size};
    asn_enc_rval_t result = asn_encode_to_buffer(NULL, ATS_CER,
        &asn_DEF_GenValue, &value, output, sizeof(output));
    return result.encoded < 0;
}

/*
 * Purpose: compare C DER/CER canonicalization on valid explicit-zone text.
 * Parameters: raw is source text; canonical is the expected normalized text.
 * Returns zero when both encoders and BER/CER prefix decoders agree.
 * Source: C GeneralizedTime adapter. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: canonical time vectors.
 * Example: comma fractions normalize to a period.
 */
static int
check_time(const uint8_t *raw, size_t raw_size, const uint8_t *canonical,
           size_t canonical_size) {
    uint8_t raw_wire[WIRE_MAX];
    uint8_t canonical_wire[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    GeneralizedTime_t value = {(uint8_t *)raw, raw_size};
    size_t raw_wire_size = make_tlv(raw_wire, raw, raw_size);
    size_t canonical_wire_size = make_tlv(canonical_wire, canonical,
                                          canonical_size);
    asn_enc_rval_t encoded;
    if(!raw_wire_size || !canonical_wire_size) return 1;
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_GenValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)canonical_wire_size
       || memcmp(actual, canonical_wire, canonical_wire_size)) {
        fprintf(stderr, "GeneralizedTime DER mismatch for content size %zu\n",
                raw_size);
        return 1;
    }
    encoded = asn_encode_to_buffer(NULL, ATS_CER, &asn_DEF_GenValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)canonical_wire_size
       || memcmp(actual, canonical_wire, canonical_wire_size)) {
        fprintf(stderr, "GeneralizedTime CER mismatch for content size %zu\n",
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
 * Purpose: document C adapter divergences outside shared valid wire vectors.
 * Parameters: none. Returns zero when each distinct C behavior is observed.
 * Source: GeneralizedTime DER and CER adapters. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: qualified compatibility.
 * Example: zoneless DER uses the process-local timezone, while CER rejects it.
 */
static int
check_c_divergences(void) {
    static const uint8_t local_time[] = "20261011120000";
    static const uint8_t invalid_date[] = "20260230120000Z";
    static const uint8_t normalized_date[] = "20260302120000Z";
    static const uint8_t excess_fraction[] = "20261011120000.1234567899Z";
    static const uint8_t truncated_fraction[] = "20261011120000.123456789Z";
    static const uint8_t epoch[] = "19691231235959Z";
    uint8_t raw_wire[WIRE_MAX];
    uint8_t canonical_wire[WIRE_MAX];
    uint8_t actual[WIRE_MAX];
    size_t raw_wire_size;
    size_t canonical_wire_size;
    GeneralizedTime_t value;
    asn_enc_rval_t encoded;

    value.buf = (uint8_t *)local_time;
    value.size = sizeof(local_time) - 1;
    raw_wire_size = make_tlv(raw_wire, local_time, value.size);
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_GenValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded <= 0 || actual[0] != 0x18
       || !cer_rejects(raw_wire, raw_wire_size)
       || !cer_encode_rejects(local_time, sizeof(local_time) - 1)) return 1;

    value.buf = (uint8_t *)invalid_date;
    value.size = sizeof(invalid_date) - 1;
    raw_wire_size = make_tlv(raw_wire, invalid_date, value.size);
    canonical_wire_size = make_tlv(canonical_wire, normalized_date,
                                   sizeof(normalized_date) - 1);
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_GenValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)canonical_wire_size
       || memcmp(actual, canonical_wire, canonical_wire_size)
       || !cer_rejects(raw_wire, raw_wire_size)
       || !cer_encode_rejects(invalid_date, sizeof(invalid_date) - 1)) return 1;

    value.buf = (uint8_t *)excess_fraction;
    value.size = sizeof(excess_fraction) - 1;
    raw_wire_size = make_tlv(raw_wire, excess_fraction, value.size);
    canonical_wire_size = make_tlv(canonical_wire, truncated_fraction,
                                   sizeof(truncated_fraction) - 1);
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_GenValue,
                                   &value, actual, sizeof(actual));
    if(encoded.encoded != (ssize_t)canonical_wire_size
       || memcmp(actual, canonical_wire, canonical_wire_size)
       || !cer_rejects(raw_wire, raw_wire_size)
       || !cer_encode_rejects(excess_fraction,
                              sizeof(excess_fraction) - 1)) return 1;

    value.buf = (uint8_t *)epoch;
    value.size = sizeof(epoch) - 1;
    raw_wire_size = make_tlv(raw_wire, epoch, value.size);
    encoded = asn_encode_to_buffer(NULL, ATS_DER, &asn_DEF_GenValue,
                                   &value, actual, sizeof(actual));
    return encoded.encoded >= 0 || !cer_rejects(raw_wire, raw_wire_size)
        || !cer_encode_rejects(epoch, sizeof(epoch) - 1);
}

/*
 * Purpose: test BER-valid constructed and aliased framing with valid text.
 * Parameters: none. Returns zero on full BER acceptance and CER rejection.
 * Source: C OCTET STRING BER adapter and strict CER re-encoding.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: canonical time content isolates framing. Example: tag-4 chunks flatten.
 */
static int
check_noncanonical_framing(void) {
    static const uint8_t canonical[] = "20260101120000Z";
    static const uint8_t constructed[] =
        "\x38\x80\x04\x08" "20260101" "\x04\x07" "120000Z" "\x00\x00";
    static const uint8_t root_alias[] = "\x1f\x18\x0f" "20260101120000Z";
    static const uint8_t child_alias[] =
        "\x38\x80\x1f\x04\x08" "20260101" "\x04\x07" "120000Z" "\x00\x00";
    static const uint8_t wrong_child[] = {0x38, 0x03, 0x1a, 0x01, 'A'};
    static const uint8_t truncated_eoc[] = {0x38, 0x80, 0x04, 0x01, 'A', 0};
    static const uint8_t empty[] = {0x18, 0x00};
    static const uint8_t raw_junk[] = {0x18, 0x04, 'j', 'u', 'n', 'k'};
    size_t constructed_size = sizeof(constructed) - 1;
    size_t alias_size = sizeof(root_alias) - 1;
    size_t child_alias_size = sizeof(child_alias) - 1;
    if(decode_matches(ATS_BER, constructed, constructed_size,
                      canonical, sizeof(canonical) - 1, constructed_size)) return 1;
    if(decode_matches(ATS_BER, root_alias, alias_size,
                      canonical, sizeof(canonical) - 1, alias_size)) return 1;
    if(decode_matches(ATS_BER, child_alias, child_alias_size,
                      canonical, sizeof(canonical) - 1, child_alias_size)) return 1;
    if(decode_matches(ATS_BER, empty, sizeof(empty), NULL, 0, sizeof(empty))
       || decode_matches(ATS_BER, raw_junk, sizeof(raw_junk),
                         raw_junk + 2, sizeof(raw_junk) - 2,
                         sizeof(raw_junk))) return 1;
    if(!ber_rejects(wrong_child, sizeof(wrong_child))
       || !ber_rejects(truncated_eoc, sizeof(truncated_eoc))) return 1;
    return cer_rejects(constructed, constructed_size)
        && cer_rejects(root_alias, alias_size)
        && cer_rejects(child_alias, child_alias_size)
        && cer_rejects(empty, sizeof(empty))
        && cer_rejects(raw_junk, sizeof(raw_junk))
        && cer_rejects(wrong_child, sizeof(wrong_child))
        && cer_rejects(truncated_eoc, sizeof(truncated_eoc)) ? 0 : 1;
}

/*
 * Purpose: run C-compatible canonical vectors and isolated adapter differences.
 * Parameters: none. Returns zero on success and one for a mismatch.
 * Source: C GeneralizedTime descriptor and approved Rust contract.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: direct tag-24 generator comparison. Example: comma fraction trims.
 */
int
main(void) {
    /* Each record pairs zoned source bytes with canonical UTC content. */
    static const struct {
        const uint8_t *raw; /* Explicitly zoned source text. */
        size_t raw_size; /* Number of source content bytes. */
        const uint8_t *canonical; /* Normalized UTC canonical text. */
        size_t canonical_size; /* Number of canonical content bytes. */
    } vectors[] = {
        {(const uint8_t *)"20261011120000Z", 15,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"2026101112Z", 11,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"202610111200Z", 13,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"20261011120000.123456789Z", 25,
         (const uint8_t *)"20261011120000.123456789Z", 25},
        {(const uint8_t *)"20261011120000,123450000Z", 25,
         (const uint8_t *)"20261011120000.12345Z", 21},
        {(const uint8_t *)"20261011120000.000Z", 19,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"20261011140000+0200", 19,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"20261011140000+02", 17,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"20261011100000-0200", 19,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"20261011100000-02", 17,
         (const uint8_t *)"20261011120000Z", 15},
        {(const uint8_t *)"20000229000000Z", 15,
         (const uint8_t *)"20000229000000Z", 15}
    };
    size_t index;
    for(index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        if(check_time(vectors[index].raw, vectors[index].raw_size,
                      vectors[index].canonical, vectors[index].canonical_size))
            return 1;
    }
    return check_noncanonical_framing() || check_c_divergences();
}
