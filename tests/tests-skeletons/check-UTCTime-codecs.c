#include <asn_internal.h>
#include <UTCTime.h>
#include <OCTET_STRING.h>
#include <ber_decoder.h>
#include <errno.h>
#include <string.h>

/*
 * Select a codec pair for exercising UTCTime's registered decoder wrappers.
 * Original source: issue #596 UTCTime decoder regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: ASN.1 transfer syntax value.
 * Returns: Its generic encoder syntax, matching direct decoder selection.
 * Errors: Invalid syntax is rejected by test assertions; no exceptions thrown.
 * Responsible party: asn1c maintainers. History: Added codec regressions.
 * Example: ATS_BER selects the BER decoder and DER test encoder.
 */
static enum asn_transfer_syntax
encoder_syntax(enum asn_transfer_syntax syntax) {
    if(syntax == ATS_BER) return ATS_DER;
    return syntax;
}

/*
 * Encode arbitrary ASCII UTCTime text through OCTET STRING operations.
 * Original source: issue #596 all-codec regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Syntax, NUL-terminated text, output buffer, and capacity.
 * Returns: Encoded byte count; assertions report encoding failures.
 * Errors: Encoder failure is an assertion; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added raw malformed vectors.
 * Example: encode_text(ATS_DER, "040231120000Z", wire, sizeof(wire)).
 */
static size_t
encode_text(enum asn_transfer_syntax syntax, const char *text,
            uint8_t *output, size_t capacity) {
    uint8_t text_storage[256];
    asn_TYPE_descriptor_t raw_td = asn_DEF_UTCTime;
    asn_TYPE_operation_t raw_ops = *asn_DEF_UTCTime.op;
    UTCTime_t input;
    asn_enc_rval_t encoded;
    size_t text_size;

    assert(text);
    assert(output || !capacity);
    text_size = strlen(text);
    assert(text_size <= sizeof(text_storage));
    memcpy(text_storage, text, text_size);

    raw_td.op = &raw_ops;
    raw_td.encoding_constraints.general_constraints = 0;
#if !defined(ASN_DISABLE_XER_SUPPORT)
    raw_ops.xer_encoder = OCTET_STRING_encode_xer_utf8;
#endif
#if !defined(ASN_DISABLE_JER_SUPPORT)
    raw_ops.jer_encoder = OCTET_STRING_encode_jer_utf8;
#endif
    input.buf = text_storage;
    input.size = text_size;
    encoded = asn_encode_to_buffer(NULL, encoder_syntax(syntax), &raw_td,
                                   &input, output, capacity);
    assert(encoded.encoded >= 0);
    assert((size_t)encoded.encoded <= capacity);
    return (size_t)encoded.encoded;
}

/*
 * Decode a complete buffer by calling the UTCTime operation directly.
 * Original source: issue #596 direct-wrapper regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Transfer syntax, input buffer and size, and output value pointer.
 * Returns: Decoder status and consumed count from the selected wrapper.
 * Errors: Unsupported syntaxes return RC_FAIL; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added direct wrapper coverage.
 * Example: direct_decode(ATS_BER, wire, size, &value).
 */
static asn_dec_rval_t
direct_decode(enum asn_transfer_syntax syntax, const void *input, size_t size,
              void **value) {
    asn_dec_rval_t result = {RC_FAIL, 0};

    if(!value || (!input && size) || size > SIZE_MAX / 8) return result;

#if !defined(ASN_DISABLE_BER_SUPPORT)
    if(syntax == ATS_BER || syntax == ATS_DER) {
        return asn_DEF_UTCTime.op->ber_decoder(
            NULL, &asn_DEF_UTCTime, value, input, size, 0);
    }
#endif
#if !defined(ASN_DISABLE_XER_SUPPORT)
    if(syntax == ATS_BASIC_XER || syntax == ATS_CANONICAL_XER) {
        return asn_DEF_UTCTime.op->xer_decoder(
            NULL, &asn_DEF_UTCTime, value, NULL, input, size);
    }
#endif
#if !defined(ASN_DISABLE_JER_SUPPORT)
    if(syntax == ATS_JER || syntax == ATS_JER_MINIFIED) {
        return asn_DEF_UTCTime.op->jer_decoder(
            NULL, &asn_DEF_UTCTime,
            asn_DEF_UTCTime.encoding_constraints.jer_constraints, value,
            input, size);
    }
#endif
#if !defined(ASN_DISABLE_OER_SUPPORT)
    if(syntax == ATS_BASIC_OER || syntax == ATS_CANONICAL_OER) {
        return asn_DEF_UTCTime.op->oer_decoder(
            NULL, &asn_DEF_UTCTime,
            asn_DEF_UTCTime.encoding_constraints.oer_constraints, value,
            input, size);
    }
#endif
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    if(syntax == ATS_UNALIGNED_BASIC_PER
    || syntax == ATS_UNALIGNED_CANONICAL_PER) {
        asn_per_data_t *per_data = asn_bit_data_new_contiguous(input, size * 8);
        if(!per_data) return result;
        result = asn_DEF_UTCTime.op->uper_decoder(
            NULL, &asn_DEF_UTCTime,
            asn_DEF_UTCTime.encoding_constraints.per_constraints, value,
            per_data);
        FREEMEM(per_data);
        return result;
    }
#endif
#if !defined(ASN_DISABLE_APER_SUPPORT)
    if(syntax == ATS_ALIGNED_BASIC_PER
    || syntax == ATS_ALIGNED_CANONICAL_PER) {
        asn_per_data_t *per_data = asn_bit_data_new_contiguous(input, size * 8);
        if(!per_data) return result;
        result = asn_DEF_UTCTime.op->aper_decoder(
            NULL, &asn_DEF_UTCTime,
            asn_DEF_UTCTime.encoding_constraints.per_constraints, value,
            per_data);
        FREEMEM(per_data);
        return result;
    }
#endif
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    if(syntax == ATS_CBOR) {
        return asn_DEF_UTCTime.op->cbor_decoder(
            NULL, &asn_DEF_UTCTime, value, input, size);
    }
#endif
    return result;
}

/*
 * Release a decoded UTCTime regardless of the decoder result.
 * Original source: asn1c skeleton test utilities.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Optional decoded pointer, possibly partially populated on failure.
 * Returns: No value.
 * Errors: None; descriptor cleanup owns all decoded allocations.
 * Responsible party: asn1c maintainers. History: Added for codec tests.
 * Example: free_decoded(value) after a failed BER decode.
 */
static void
free_decoded(void *value) {
    if(value) ASN_STRUCT_FREE(asn_DEF_UTCTime, value);
}

/*
 * Assert that direct and generic paths agree on one decoded text value.
 * Original source: issue #596 all-codec regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Syntax, UTCTime text, and expected success/failure policy.
 * Returns: No value; mismatches abort the test.
 * Errors: Assertions identify a codec regression; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added strict/tolerant checks.
 * Example: check_codec(ATS_BER, "040231120000Z", expected_invalid_result).
 */
static void
check_codec(enum asn_transfer_syntax syntax, const char *text, int accepted) {
    uint8_t wire[256];
    size_t wire_size = encode_text(syntax, text, wire, sizeof(wire));
    enum asn_dec_rval_code_e expected = accepted ? RC_OK : RC_FAIL;
    asn_dec_rval_t result;
    void *value = NULL;

    result = direct_decode(syntax, wire, wire_size, &value);
    assert(result.code == expected);
    if(result.code == RC_OK) {
        UTCTime_t *decoded = (UTCTime_t *)value;
        assert(decoded->size == strlen(text));
        assert(memcmp(decoded->buf, text, decoded->size) == 0);
    }
    free_decoded(value);

    value = NULL;
    result = asn_decode(NULL, syntax, &asn_DEF_UTCTime, &value,
                        wire, wire_size);
    assert(result.code == expected);
    if(result.code == RC_OK) {
        UTCTime_t *decoded = (UTCTime_t *)value;
        assert(decoded->size == strlen(text));
        assert(memcmp(decoded->buf, text, decoded->size) == 0);
    }
    free_decoded(value);
}

/*
 * Exercise one valid value and one impossible calendar date through a codec.
 * Original source: issue #596 all-codec regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: One enabled transfer syntax.
 * Returns: No value; codec behavior is checked by assertions.
 * Errors: Assertion failure indicates dispatch or validation drift.
 * Responsible party: asn1c maintainers. History: Added direct/generic vectors.
 * Example: check_codec_pair(ATS_BER) covers direct and generic BER decode.
 */
static void
check_codec_pair(enum asn_transfer_syntax syntax) {
#ifdef ASN_ENABLE_TOLERANT_UTCTIME
    const int malformed_accepted = 1;
#else
    const int malformed_accepted = 0;
#endif

    check_codec(syntax, "240229120000Z", 1);
    check_codec(syntax, "040231120000Z", malformed_accepted);
    check_codec(syntax, "691231235959Z", 1);
    check_codec(syntax, "0001010030+0100", 1);
    check_codec(syntax, "0002310030+0100", malformed_accepted);
}

/*
 * Feed BER one byte at a time through the direct UTCTime decoder wrapper.
 * Original source: issue #596 incremental BER regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Complete DER TLV and expected decoded text.
 * Returns: No value; incomplete, failed, or mismatched decode asserts.
 * Errors: Decoder status is checked after every incremental input byte.
 * Responsible party: asn1c maintainers. History: Added streaming validation.
 * Example: check_ber_stream(wire, size, "240229120000Z").
 */
static void
check_ber_stream(const uint8_t *wire, size_t wire_size, const char *expected) {
    uint8_t pending[256];
    size_t pending_size = 0;
    size_t input_offset = 0;
    void *value = NULL;
    asn_dec_rval_t result = {RC_WMORE, 0};

    assert(wire);
    assert(expected);
    assert(wire_size <= sizeof(pending));
    while(input_offset < wire_size) {
        pending[pending_size++] = wire[input_offset++];
        result = UTCTime_decode_ber(NULL, &asn_DEF_UTCTime, &value,
                                    pending, pending_size, 0);
        assert(result.consumed <= pending_size);
        if(result.consumed) {
            pending_size -= result.consumed;
            memmove(pending, pending + result.consumed, pending_size);
        }
        if(result.code == RC_OK || result.code == RC_FAIL) break;
        assert(result.code == RC_WMORE);
    }

    assert(input_offset == wire_size);
    assert(result.code == RC_OK);
    assert(pending_size == 0);
    assert(value);
    assert(((UTCTime_t *)value)->size == strlen(expected));
    assert(memcmp(((UTCTime_t *)value)->buf, expected, strlen(expected)) == 0);
    free_decoded(value);
}

/*
 * Decode primitive and constructed BER values, including an impossible date.
 * Original source: issue #596 BER constructed-string regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: No external arguments; fixed bounded BER vectors.
 * Returns: No value; malformed strict input must fail.
 * Errors: Assertions report tag, stream, or calendar validation failures.
 * Responsible party: asn1c maintainers. History: Added constructed coverage.
 * Example: constructs UTCTime from universal OCTET STRING fragments.
 */
static void
check_ber_constructed(void) {
    static const uint8_t valid_constructed[] = {
        0x37, 0x80,
        0x04, 0x06, '2', '4', '0', '2', '2', '9',
        0x04, 0x07, '1', '2', '0', '0', '0', '0', 'Z',
        0x00, 0x00
    };
    static const uint8_t invalid_constructed[] = {
        0x37, 0x80,
        0x04, 0x06, '0', '4', '0', '2', '3', '1',
        0x04, 0x07, '1', '2', '0', '0', '0', '0', 'Z',
        0x00, 0x00
    };
    void *value = NULL;
    asn_dec_rval_t result;

    result = UTCTime_decode_ber(NULL, &asn_DEF_UTCTime, &value,
                                valid_constructed,
                                sizeof(valid_constructed), 0);
    assert(result.code == RC_OK);
    assert(value);
    assert(((UTCTime_t *)value)->size == 13);
    assert(memcmp(((UTCTime_t *)value)->buf, "240229120000Z", 13) == 0);
    free_decoded(value);

    value = NULL;
    result = asn_decode(NULL, ATS_BER, &asn_DEF_UTCTime, &value,
                        invalid_constructed, sizeof(invalid_constructed));
#ifdef ASN_ENABLE_TOLERANT_UTCTIME
    assert(result.code == RC_OK);
#else
    assert(result.code == RC_FAIL);
#endif
    free_decoded(value);
}

/*
 * Mutate every BER TLV byte through all byte values deterministically.
 * Original source: issue #596 hostile-input regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: A valid fixed DER UTCTime TLV.
 * Returns: No value; decoder bounds and strict postchecks are asserted.
 * Errors: No input mutation may consume beyond its supplied buffer.
 * Responsible party: asn1c maintainers. History: Added bounded mutation cases.
 * Example: mutates tag, length, and each time octet independently.
 */
static void
check_ber_mutations(const uint8_t *original, size_t original_size) {
    size_t offset;
    unsigned mutation;

    for(offset = 0; offset < original_size; offset++) {
        for(mutation = 0; mutation <= 255; mutation++) {
            uint8_t input[256];
            void *value = NULL;
            asn_dec_rval_t result;

            assert(original_size <= sizeof(input));
            memcpy(input, original, original_size);
            input[offset] = (uint8_t)mutation;
            result = UTCTime_decode_ber(NULL, &asn_DEF_UTCTime, &value,
                                        input, original_size, 0);
            assert(result.consumed <= original_size);
            assert(result.code == RC_OK || result.code == RC_WMORE
                   || result.code == RC_FAIL);
#ifndef ASN_ENABLE_TOLERANT_UTCTIME
            if(result.code == RC_OK) {
                assert(value);
                assert(UTCTime_constraint(&asn_DEF_UTCTime, value, 0, 0) == 0);
            }
#endif
            free_decoded(value);
        }
    }
}

/*
 * Verify lexical constraints accept the valid epoch sentinel syntax.
 * Original source: issue #596 time_t sentinel regression requirement.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: No external arguments; fixed epoch-boundary UTCTime.
 * Returns: No value; an invalid constraint result asserts.
 * Errors: asn_UT2time may return -1 for this valid instant on POSIX time_t.
 * Responsible party: asn1c maintainers. History: Added syntax-only coverage.
 * Example: 691231235959Z parses to the Unix epoch's preceding second.
 */
static void
check_epoch_sentinel(void) {
#ifndef ASN_ENABLE_TOLERANT_UTCTIME
    uint8_t epoch_text[] = "691231235959Z";
    UTCTime_t value;

    value.buf = epoch_text;
    value.size = sizeof(epoch_text) - 1;
    assert(UTCTime_constraint(&asn_DEF_UTCTime, &value, 0, 0) == 0);
#endif
}

/*
 * Run direct and generic decoder coverage for every enabled codec.
 * Original source: issue #596 all-codec regression requirements.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Standard process arguments are ignored.
 * Returns: 0 after all assertions pass.
 * Errors: Assertion failure identifies a codec regression.
 * Responsible party: asn1c maintainers. History: Added codec matrix tests.
 * Example: called by the tests-skeletons `check-UTCTime-codecs` target.
 */
int
main(void) {
#if !defined(ASN_DISABLE_BER_SUPPORT)
    check_codec_pair(ATS_BER);
#endif
#if !defined(ASN_DISABLE_XER_SUPPORT)
    check_codec_pair(ATS_BASIC_XER);
#endif
#if !defined(ASN_DISABLE_JER_SUPPORT)
    check_codec_pair(ATS_JER);
#endif
#if !defined(ASN_DISABLE_OER_SUPPORT)
    check_codec_pair(ATS_BASIC_OER);
#endif
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    check_codec_pair(ATS_UNALIGNED_BASIC_PER);
#endif
#if !defined(ASN_DISABLE_APER_SUPPORT)
    check_codec_pair(ATS_ALIGNED_BASIC_PER);
#endif
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    check_codec_pair(ATS_CBOR);
#endif

    check_epoch_sentinel();
#if !defined(ASN_DISABLE_BER_SUPPORT)
    {
        uint8_t wire[256];
        size_t size = encode_text(ATS_BER, "240229120000Z", wire,
                                  sizeof(wire));
        check_ber_stream(wire, size, "240229120000Z");
        check_ber_constructed();
        check_ber_mutations(wire, size);
    }
#endif
    return 0;
}
