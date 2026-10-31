/* IOC-selected SET CBOR regression, including pointer-backed selected arms. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <SetOpen.h>
#include <SeqOpen.h>
#include <cbor_decoder.h>
#include <cbor_encoder.h>
#include <OCTET_STRING.h>

/* Bounded destination for encoder output. */
typedef struct output_s {
    uint8_t data[128]; /* Encoded CBOR bytes. */
    size_t size; /* Used bytes; state variable. */
} output_t;

/*
 * Purpose: append encoder output to a bounded fixture buffer.
 * Source: CBOR callback contract. Version: 2026-10-30.
 * Inputs: buffer/size contain bytes and key identifies the output.
 * Returns: zero on success, -1 on overflow. Errors: no exceptions.
 * Author: asn1c maintainers. History: IOC SET CBOR fixture.
 * Example: cbor_encode writes successive fragments to this callback.
 */
static int
collect(const void *buffer, size_t size, void *key) {
    output_t *out = key;
    if(!out || size > sizeof(out->data) - out->size) return -1;
    memcpy(out->data + out->size, buffer, size);
    out->size += size;
    return 0;
}

/*
 * Purpose: verify one complete open-value CBOR map.
 * Source: generated IOC selector and SET CBOR mapping. Version: 2026-10-30.
 * Inputs: wire/size bound an expected payload and status is the expected result.
 * Returns: nothing. Errors: assertions expose a decoding mismatch.
 * Author: asn1c maintainers. History: added open-before-selector regression.
 * Example: both map orders produce the same selected Payload value.
 */
static void
check_wire(const uint8_t *wire, size_t size, enum asn_dec_rval_code_e status) {
    SetOpen_t *value = 0;
    asn_dec_rval_t result = cbor_decode(0, &asn_DEF_SetOpen, (void **)&value, wire, size);
    assert(result.code == status);
    if(status == RC_OK) {
        assert(value && value->id == 1 && value->value);
        assert(value->value->present == SetOpen__value_PR_Payload);
        assert(value->value->choice.Payload && value->value->choice.Payload->number == 7);
        assert(value->value->choice.Payload->text.size == 1);
        assert(value->value->choice.Payload->text.buf[0] == 'A');
    }
    if(value) ASN_STRUCT_FREE(asn_DEF_SetOpen, value);
}

/*
 * Purpose: exercise both map orders and malformed selector/value cases.
 * Source: CBOR map encoding and generated SET IOC selection. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect incorrect results.
 * Author: asn1c maintainers. History: added selector-order-independent tests.
 * Example: invalid selected content is rejected after allocating its child.
 */
static void
check_decode(void) {
    static const uint8_t forward[] = {0xa2, 0x62, 'i', 'd', 1, 0x65, 'v', 'a', 'l', 'u', 'e',
        0xa2, 0x64, 't', 'e', 'x', 't', 0x41, 'A', 0x66, 'n', 'u', 'm', 'b', 'e', 'r', 7};
    static const uint8_t reverse[] = {0xa2, 0x65, 'v', 'a', 'l', 'u', 'e',
        0xa2, 0x64, 't', 'e', 'x', 't', 0x41, 'A', 0x66, 'n', 'u', 'm', 'b', 'e', 'r', 7,
        0x62, 'i', 'd', 1};
    static const uint8_t unknown[] = {0xa2, 0x62, 'i', 'd', 3, 0x65, 'v', 'a', 'l', 'u', 'e', 0xf5};
    static const uint8_t duplicate[] = {0xa3, 0x62, 'i', 'd', 1, 0x62, 'i', 'd', 1,
        0x65, 'v', 'a', 'l', 'u', 'e', 0xf5};
    static const uint8_t invalid[] = {0xa2, 0x62, 'i', 'd', 1, 0x65, 'v', 'a', 'l', 'u', 'e',
        0xa2, 0x64, 't', 'e', 'x', 't', 0x41, 'A', 0x66, 'n', 'u', 'm', 'b', 'e', 'r', 0xf5};
    static const uint8_t omitted[] = {0xa1, 0x62, 'i', 'd', 3};
    static const uint8_t boolean[] = {0xa2, 0x65, 'v', 'a', 'l', 'u', 'e', 0xf5, 0x62, 'i', 'd', 2};
    SetOpen_t *value = 0;
    asn_dec_rval_t result;
    size_t i;
    check_wire(forward, sizeof(forward), RC_OK);
    check_wire(reverse, sizeof(reverse), RC_OK);
    check_wire(unknown, sizeof(unknown), RC_FAIL);
    check_wire(duplicate, sizeof(duplicate), RC_FAIL);
    check_wire(invalid, sizeof(invalid), RC_FAIL);
    for(i = 0; i < sizeof(reverse); i++) check_wire(reverse, i, RC_FAIL);
    result = cbor_decode(0, &asn_DEF_SetOpen, (void **)&value, omitted, sizeof(omitted));
    assert(result.code == RC_OK && value && value->id == 3 && !value->value);
    ASN_STRUCT_FREE(asn_DEF_SetOpen, value);
    value = 0;
    result = cbor_decode(0, &asn_DEF_SetOpen, (void **)&value, boolean, sizeof(boolean));
    assert(result.code == RC_OK && value && value->value);
    assert(value->value->present == SetOpen__value_PR_BOOLEAN && value->value->choice.BOOLEAN);
    ASN_STRUCT_FREE(asn_DEF_SetOpen, value);
    {
        asn_TYPE_member_t *arm = &asn_DEF_SetOpen.elements[1].type->elements[1];
        size_t offset = arm->memb_offset;
        arm->memb_offset = sizeof(SetOpen__value) - 1;
        value = 0;
        result = cbor_decode(0, &asn_DEF_SetOpen, (void **)&value, boolean, sizeof(boolean));
        assert(result.code == RC_FAIL);
        arm->memb_offset = offset;
        if(value) ASN_STRUCT_FREE(asn_DEF_SetOpen, value);
    }
}

/*
 * Purpose: verify selected encoder output and selector consistency.
 * Source: generated SET and OPEN TYPE descriptors. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect unexpected output.
 * Author: asn1c maintainers. History: added CBOR IOC encoder tests.
 * Example: an arm inconsistent with the selector must fail before output.
 */
static void
check_encode(void) {
    static const uint8_t expected[] = {0xa2, 0x62, 'i', 'd', 1, 0x65, 'v', 'a', 'l', 'u', 'e',
        0xa2, 0x64, 't', 'e', 'x', 't', 0x41, 'A', 0x66, 'n', 'u', 'm', 'b', 'e', 'r', 7};
    SetOpen_t source = {0};
    output_t output = {{0}, 0};
    SeqOpen_t *sequence = 0;
    asn_dec_rval_t decoded;
    asn_enc_rval_t result;
    source.id = 1;
    source.value = calloc(1, sizeof(*source.value));
    assert(source.value);
    source.value->present = SetOpen__value_PR_Payload;
    source.value->choice.Payload = calloc(1, sizeof(*source.value->choice.Payload));
    assert(source.value->choice.Payload);
    assert(OCTET_STRING_fromString(&source.value->choice.Payload->text, "A") == 0);
    source.value->choice.Payload->number = 7;
    result = cbor_encode(&asn_DEF_SetOpen, &source, collect, &output);
    assert(result.encoded > 0 && (size_t)result.encoded == output.size);
    assert(output.size == sizeof(expected) && !memcmp(output.data, expected, sizeof(expected)));
    check_wire(output.data, output.size, RC_OK);
    decoded = cbor_decode(0, &asn_DEF_SeqOpen, (void **)&sequence, output.data, output.size);
    assert(decoded.code == RC_OK && sequence && sequence->id == 1 && sequence->value);
    output.size = 0;
    result = cbor_encode(&asn_DEF_SeqOpen, sequence, collect, &output);
    assert(result.encoded == (ssize_t)sizeof(expected));
    check_wire(output.data, output.size, RC_OK);
    ASN_STRUCT_FREE(asn_DEF_SeqOpen, sequence);
    output.size = 0;
    source.id = 2;
    result = cbor_encode(&asn_DEF_SetOpen, &source, collect, &output);
    assert(result.encoded == -1 && output.size == 0);
    source.id = 3;
    result = cbor_encode(&asn_DEF_SetOpen, &source, collect, &output);
    assert(result.encoded == -1 && output.size == 0);
    source.id = 1;
    {
        asn_TYPE_member_t *open = &asn_DEF_SetOpen.elements[1];
        asn_TYPE_member_t *arm = &open->type->elements[0];
        size_t offset = arm->memb_offset;
        arm->memb_offset = sizeof(*source.value) - 1;
        result = cbor_encode(&asn_DEF_SetOpen, &source, collect, &output);
        assert(result.encoded == -1 && output.size == 0);
        arm->memb_offset = offset;
    }
    ASN_STRUCT_RESET(asn_DEF_SetOpen, &source);
}

/*
 * Purpose: run direct SET IOC CBOR regression cases.
 * Source: generated 601 fixture. Version: 2026-10-30.
 * Inputs: none. Returns: zero on success. Errors: assertions terminate on failure.
 * Author: asn1c maintainers. History: added CBOR SET IOC coverage.
 * Example: invoked by tests-c-compiler/check-assembly.sh.
 */
int
main(void) {
    check_decode();
    check_encode();
    return 0;
}
