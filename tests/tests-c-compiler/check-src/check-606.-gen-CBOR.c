/*
 * Verify CBOR CHOICE one-entry maps and transactional selected-arm decoding.
 * Source: generated 606 fixture and repository CBOR CHOICE mapping.
 * Version: 2026-10-30. Author: asn1c maintainers.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Variant.h"
#include "Record.h"
#include <cbor_decoder.h>
#include <cbor_encoder.h>
#include <OCTET_STRING.h>

/* Bounded CBOR output retained by the test callback. */
typedef struct cbor_output_s {
    uint8_t bytes[1024]; /* Initialized encoded bytes. */
    size_t used;          /* Current length; state variable. */
} cbor_output_t;

/*
 * Purpose: append bytes without exceeding fixed test storage.
 * Source: asn_app_consume_bytes_f. Version: 2026-10-30.
 * Inputs: data/size are encoded bytes; key is cbor_output_t.
 * Returns: zero or -1 on invalid input/capacity. Exceptions: none.
 * Author: maintainers. History: added bounded output.
 * Example: cbor_encode(..., append_bytes, &output).
 */
static int
append_bytes(const void *data, size_t size, void *key) {
    cbor_output_t *output = key;
    if(!output || (!data && size) || output->used > sizeof(output->bytes)
       || size > sizeof(output->bytes) - output->used) return -1;
    if(size) memcpy(output->bytes + output->used, data, size);
    output->used += size;
    return 0;
}

/*
 * Purpose: verify the BOOLEAN CHOICE wire form and malformed key rejection.
 * Source: CBOR map and BOOLEAN mappings. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Exceptions: assertions on regression.
 * Author: maintainers. History: added one-entry map round trip.
 * Example: TRUE encodes as A1 65 'truth' F5.
 */
static void
check_truth(void) {
    static const uint8_t expected[] = {0xa1, 0x65, 't', 'r', 'u', 't', 'h', 0xf5};
    static const uint8_t unknown[] = {0xa1, 0x61, 'x', 0xf5};
    static const uint8_t invalid_utf8[] = {0xa1, 0x61, 0xff, 0xf5};
    static const uint8_t empty_map[] = {0xa0};
    static const uint8_t two_pairs[] = {0xa2, 0x65, 't', 'r', 'u', 't', 'h', 0xf5,
                                        0x61, 'x', 0xf4};
    Variant_t source = {0}, *decoded = NULL;
    cbor_output_t output = {{0}, 0};
    asn_dec_rval_t result;
    size_t cut;
    source.present = Variant_PR_truth;
    source.choice.truth = 1;
    assert(cbor_encode(&asn_DEF_Variant, &source, append_bytes, &output).encoded >= 0);
    assert(output.used == sizeof(expected) && !memcmp(output.bytes, expected, sizeof(expected)));
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, output.bytes, output.used);
    assert(result.code == RC_OK && result.consumed == output.used);
    assert(decoded && decoded->present == Variant_PR_truth && decoded->choice.truth == 1);
    ASN_STRUCT_FREE(asn_DEF_Variant, decoded);

    /* All proper prefixes and incorrect map shapes fail before allocation. */
    for(cut = 0; cut < output.used; cut++) {
        decoded = NULL;
        result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, output.bytes, cut);
        assert(result.code != RC_OK && decoded == NULL);
    }
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, unknown, sizeof(unknown));
    assert(result.code != RC_OK && decoded == NULL);
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded,
                         invalid_utf8, sizeof(invalid_utf8));
    assert(result.code != RC_OK && decoded == NULL);
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, empty_map, sizeof(empty_map));
    assert(result.code != RC_OK && decoded == NULL);
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, two_pairs, sizeof(two_pairs));
    assert(result.code != RC_OK && decoded == NULL);
}

/*
 * Purpose: verify an inline opaque ANY CHOICE arm uses a CBOR byte string.
 * Source: generated 606 ANY variant and C ANY CBOR mapping.
 * Version: 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: assertions on mismatch. Author: maintainers.
 * History: added opaque selected-arm round trip.
 * Example: BER NULL bytes are retained as opaque CBOR byte-string content.
 */
static void
check_opaque(void) {
    static const uint8_t raw[] = {0x05, 0x00};
    Variant_t source = {0}, *decoded = NULL;
    cbor_output_t output = {{0}, 0};
    asn_dec_rval_t result;
    source.present = Variant_PR_opaque;
    source.choice.opaque.buf = malloc(sizeof(raw));
    assert(source.choice.opaque.buf);
    memcpy(source.choice.opaque.buf, raw, sizeof(raw));
    source.choice.opaque.size = sizeof(raw);
    assert(cbor_encode(&asn_DEF_Variant, &source, append_bytes, &output).encoded >= 0);
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, output.bytes, output.used);
    assert(result.code == RC_OK && result.consumed == output.used);
    assert(decoded && decoded->present == Variant_PR_opaque);
    assert(decoded->choice.opaque.size == sizeof(raw));
    assert(!memcmp(decoded->choice.opaque.buf, raw, sizeof(raw)));
    ASN_STRUCT_FREE(asn_DEF_Variant, decoded);
    ASN_STRUCT_RESET(asn_DEF_Variant, &source);
}

/*
 * Purpose: verify nested child failures leave a preallocated CHOICE untouched.
 * Source: generated Record child and transactional decoder. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Exceptions: assertions on regression.
 * Author: maintainers. History: added partial-arm cleanup test.
 * Example: a truncated nested record cannot replace a truth arm.
 */
static void
check_record_failure(void) {
    Variant_t source = {0}, *decoded, *preallocated;
    cbor_output_t output = {{0}, 0};
    asn_dec_rval_t result;
    size_t cut;
    static const uint8_t missing_label[] = {
        0xa1, 0x66, 'r', 'e', 'c', 'o', 'r', 'd',
        0xa1, 0x66, 'a', 'c', 't', 'i', 'v', 'e', 0xf5
    };
    source.present = Variant_PR_record;
    source.choice.record = calloc(1, sizeof(*source.choice.record));
    assert(source.choice.record);
    assert(OCTET_STRING_fromString(&source.choice.record->label, "Alice") == 0);
    assert(cbor_encode(&asn_DEF_Variant, &source, append_bytes, &output).encoded >= 0);
    assert(output.used > 10);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, output.bytes, output.used);
    assert(result.code == RC_OK && decoded && decoded->present == Variant_PR_record);
    assert(decoded->choice.record && decoded->choice.record->label.size == 5);
    ASN_STRUCT_FREE(asn_DEF_Variant, decoded);

    /* The final child byte is required and partial storage is released. */
    preallocated = calloc(1, sizeof(*preallocated));
    assert(preallocated);
    preallocated->present = Variant_PR_truth;
    preallocated->choice.truth = 1;
    for(cut = 0; cut < output.used; cut++) {
        decoded = preallocated;
        result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded, output.bytes, cut);
        assert(result.code != RC_OK && decoded == preallocated);
        assert(preallocated->present == Variant_PR_truth && preallocated->choice.truth == 1);
    }
    decoded = preallocated;
    result = cbor_decode(0, &asn_DEF_Variant, (void **)&decoded,
                         missing_label, sizeof(missing_label));
    assert(result.code != RC_OK && decoded == preallocated);
    assert(preallocated->present == Variant_PR_truth && preallocated->choice.truth == 1);
    ASN_STRUCT_FREE(asn_DEF_Variant, preallocated);
    ASN_STRUCT_RESET(asn_DEF_Variant, &source);
}

/*
 * Purpose: simulate a child decoder that falsely reports short success.
 * Source: cbor_type_decoder_f contract. Version: 2026-10-30.
 * Inputs: codec/td are unused; sptr receives partial child storage; buf/size
 * bound a complete item. Returns: RC_OK with one fewer byte than size.
 * Errors: allocation failure returns RC_FAIL. Author: maintainers.
 * History: added exact child-consumption regression.
 * Example: CHOICE must reject this child's incomplete success.
 */
static asn_dec_rval_t
short_child(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
            void **sptr, const void *buf, size_t size) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    (void)codec;
    (void)td;
    (void)buf;
    if(!sptr || !size) return result;
    *sptr = calloc(1, sizeof(Record_t));
    if(!*sptr) return result;
    result.code = RC_OK;
    result.consumed = size - 1;
    return result;
}

/*
 * Purpose: reject a short-success child and release its partial allocation.
 * Source: mutable generated descriptors and CHOICE ownership contract.
 * Version: 2026-10-30. Inputs: none. Returns: nothing.
 * Exceptions: assertions on regression. Author: maintainers.
 * History: added exact-item-consumption test.
 * Example: a child consuming N-1 of N bytes cannot complete the CHOICE.
 */
static void
check_short_child(void) {
    static const uint8_t record_map[] = {
        0xa1, 0x66, 'r', 'e', 'c', 'o', 'r', 'd',
        0xa1, 0x65, 'l', 'a', 'b', 'e', 'l', 0x41, 'A'
    };
    asn_TYPE_descriptor_t malformed = asn_DEF_Variant, fake_record = asn_DEF_Record;
    asn_TYPE_operation_t fake_ops = *asn_DEF_Record.op;
    asn_TYPE_member_t members[3];
    Variant_t *decoded = NULL;
    asn_dec_rval_t result;
    fake_ops.cbor_decoder = short_child;
    fake_record.op = &fake_ops;
    memcpy(members, malformed.elements, sizeof(members));
    members[1].type = &fake_record;
    malformed.elements = members;
    result = cbor_decode(0, &malformed, (void **)&decoded,
                         record_map, sizeof(record_map));
    assert(result.code != RC_OK && decoded == NULL);
}

/*
 * Purpose: reject malformed variant metadata before output or allocation.
 * Source: CHOICE descriptor layout contracts. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Exceptions: assertions on regression.
 * Author: maintainers. History: added descriptor preflight test.
 * Example: a pointer slot outside struct_size fails closed.
 */
static void
check_bad_descriptor(void) {
    Variant_t source = {0}, *decoded = NULL;
    asn_TYPE_descriptor_t malformed = asn_DEF_Variant;
    asn_TYPE_member_t members[3];
    cbor_output_t output = {{0}, 0};
    asn_dec_rval_t result;
    static const uint8_t truth[] = {0xa1, 0x65, 't', 'r', 'u', 't', 'h', 0xf5};
    source.present = Variant_PR_truth;
    source.choice.truth = 1;
    memcpy(members, malformed.elements, sizeof(members));
    members[0].memb_offset = sizeof(source) - 1;
    malformed.elements = members;
    assert(cbor_encode(&malformed, &source, append_bytes, &output).encoded < 0);
    assert(output.used == 0);
    result = cbor_decode(0, &malformed, (void **)&decoded, truth, sizeof(truth));
    assert(result.code != RC_OK && decoded == NULL);
}

/*
 * Purpose: fuzz CHOICE map framing, selection and partial child cleanup.
 * Source: libFuzzer input contract. Version: 2026-10-30.
 * Inputs: data/size are arbitrary bytes. Returns: zero after cleanup.
 * Errors: malformed bytes must not leak or crash. Author: maintainers.
 * History: added generated CHOICE CBOR fuzz entry.
 * Example: mutate the one-entry truth and record map corpus.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Variant_t *value = NULL;
    if(!data && size) return 0;
    cbor_decode(0, &asn_DEF_Variant, (void **)&value, data, size);
    ASN_STRUCT_FREE(asn_DEF_Variant, value);
    return 0;
}

/*
 * Purpose: run generated CHOICE CBOR regressions.
 * Source: 606 fixture. Version: 2026-10-30.
 * Inputs: none. Returns: zero on success. Exceptions: assertions on failure.
 * Author: maintainers. History: added C CHOICE CBOR coverage.
 * Example: ./check-program.
 */
int
main(void) {
    check_truth();
    check_opaque();
    check_record_failure();
    check_short_child();
    check_bad_descriptor();
    return 0;
}
