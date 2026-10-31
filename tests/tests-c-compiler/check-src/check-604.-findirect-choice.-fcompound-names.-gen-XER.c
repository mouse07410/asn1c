/* Streaming IOC-selected direct SET XER regression. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <SetOpenXer.h>
#include <SeqOpenXer.h>
#include <GroupedXer.h>
#include <ReverseXer.h>
#include <xer_decoder.h>
#include <xer_encoder.h>

/* A bounded output buffer for generated XER. */
typedef struct output_s {
    char bytes[512]; /* Encoded XML bytes. */
    size_t size; /* Number of bytes written; state variable. */
} output_t;

/*
 * Purpose: collect a generated XER fragment without overflowing the buffer.
 * Source: XER encoder callback contract. Version: 2026-10-30.
 * Inputs: buf/size hold the fragment; key identifies the buffer.
 * Returns: zero on success or -1 on overflow. Errors: no exceptions.
 * Author: asn1c maintainers. History: added SET IOC fixture.
 * Example: xer_encode emits fragments into output_t.
 */
static int
collect(const void *buf, size_t size, void *key) {
    output_t *out = key;
    if(!out || size > sizeof(out->bytes) - out->size) return -1;
    memcpy(out->bytes + out->size, buf, size);
    out->size += size;
    return 0;
}

/*
 * Purpose: decode one fixture and verify its expected status and selected arm.
 * Source: generated SET and XER decoder contract. Version: 2026-10-30.
 * Inputs: wire contains XML and expected is the required decode status.
 * Returns: nothing. Errors: assertions detect regressions. Author: maintainers.
 * History: added selector-order and malformed input tests.
 * Example: an unknown selector is rejected before decoding the value.
 */
static void
check_wire(const char *wire, enum asn_dec_rval_code_e expected) {
    SetOpenXer_t *value = 0;
    asn_dec_rval_t result = xer_decode(0, &asn_DEF_SetOpenXer, (void **)&value, wire, strlen(wire));
    assert(result.code == expected);
    if(expected == RC_OK && value->value) {
        assert(value->id == 1 && value->flag && *value->flag);
        assert(value->value->present == SetOpenXer__value_PR_Payload);
        assert(value->value->choice.Payload && *value->value->choice.Payload == 42);
    }
    if(value) ASN_STRUCT_FREE(asn_DEF_SetOpenXer, value);
}

/*
 * Purpose: test selector-first decoding and every streaming input split.
 * Source: XER SET member order and caller replay contract. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions terminate on failure.
 * Author: maintainers. History: added buffered open-element replay coverage.
 * Example: a partial open element is replayed from its unconsumed start.
 */
static void
check_stream(void) {
    static const char wire[] = "<SetOpenXer><id>1</id><flag><true/></flag>"
                               "<value><Payload>42</Payload></value></SetOpenXer>";
    size_t split;
    check_wire(wire, RC_OK);
    for(split = 0; split < sizeof(wire) - 1; split++) {
        SetOpenXer_t *value = 0;
        asn_dec_rval_t result = xer_decode(0, &asn_DEF_SetOpenXer, (void **)&value, wire, split);
        size_t consumed = result.consumed;
        assert(result.code == RC_WMORE && consumed <= split);
        result = xer_decode(0, &asn_DEF_SetOpenXer, (void **)&value, wire + consumed,
                            sizeof(wire) - 1 - consumed);
        assert(result.code == RC_OK && value->value && value->value->choice.Payload);
        assert(*value->value->choice.Payload == 42);
        ASN_STRUCT_FREE(asn_DEF_SetOpenXer, value);
    }
}

/*
 * Purpose: reject missing sibling, duplicate and invalid selector/value inputs.
 * Source: bounded SET IOC XER contract. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect acceptance errors.
 * Author: maintainers. History: added conservative selector gating.
 * Example: an omitted unrelated optional sibling blocks a present open value.
 */
static void
check_rejections(void) {
    check_wire("<SetOpenXer><value><Payload>42</Payload></value><id>1</id>"
               "<flag><true/></flag></SetOpenXer>", RC_FAIL);
    check_wire("<SetOpenXer><id>1</id><value><Payload>42</Payload></value></SetOpenXer>", RC_FAIL);
    check_wire("<SetOpenXer><id>9</id><flag><true/></flag><value><Payload>42</Payload></value>"
               "</SetOpenXer>", RC_FAIL);
    check_wire("<SetOpenXer><id>1</id><id>1</id><flag><true/></flag>"
               "<value><Payload>42</Payload></value></SetOpenXer>", RC_FAIL);
    check_wire("<SetOpenXer><id>1</id><flag><true/></flag><value><Payload>bad</Payload></value>"
               "</SetOpenXer>", RC_FAIL);
    check_wire("<SetOpenXer><id>1</id></SetOpenXer>", RC_OK);
    check_wire("<SetOpenXer><id>1</id><flag><true/></flag><value/></SetOpenXer>", RC_FAIL);
    {
        static const char wire[] = "<SetOpenXer><id>3</id><flag><true/></flag>"
                                   "<value><NullPayload/></value></SetOpenXer>";
        SetOpenXer_t *value = 0;
        asn_dec_rval_t result = xer_decode(0, &asn_DEF_SetOpenXer, (void **)&value,
                                           wire, sizeof(wire) - 1);
        assert(result.code == RC_OK && value->value && value->value->present == SetOpenXer__value_PR_NullPayload);
        ASN_STRUCT_FREE(asn_DEF_SetOpenXer, value);
    }
    {
        asn_TYPE_member_t *arm = &asn_DEF_SetOpenXer.elements[2].type->elements[0];
        size_t offset = arm->memb_offset;
        arm->memb_offset = sizeof(SetOpenXer__value) - 1;
        check_wire("<SetOpenXer><id>1</id><flag><true/></flag>"
                   "<value><Payload>42</Payload></value></SetOpenXer>", RC_FAIL);
        arm->memb_offset = offset;
    }
}

/*
 * Purpose: verify selector-checked encoding with generated XER decoders.
 * Source: generated SET and SEQUENCE IOC descriptors. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions reject bad encodings.
 * Author: maintainers. History: added open SET encoder coverage.
 * Example: selector 1 encodes Payload 42 within the member wrapper.
 */
static void
check_encode(void) {
    SetOpenXer_t value = {0}, *decoded = 0;
    SetOpenXer__value open = {0};
    BOOLEAN_t flag = 1;
    Payload_t payload = 42;
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    value.id = 1;
    value.flag = &flag;
    value.value = &open;
    open.present = SetOpenXer__value_PR_Payload;
    open.choice.Payload = &payload;
    encoded = xer_encode(&asn_DEF_SetOpenXer, &value, XER_F_CANONICAL, collect, &output);
    assert(encoded.encoded > 0 && output.size == (size_t)encoded.encoded);
    result = xer_decode(0, &asn_DEF_SetOpenXer, (void **)&decoded, output.bytes, output.size);
    assert(result.code == RC_OK && decoded->value && *decoded->value->choice.Payload == 42);
    ASN_STRUCT_FREE(asn_DEF_SetOpenXer, decoded);
    output.size = 0;
    value.id = 2;
    encoded = xer_encode(&asn_DEF_SetOpenXer, &value, XER_F_CANONICAL, collect, &output);
    assert(encoded.encoded == -1);
    value.id = 1;
    value.flag = 0;
    output.size = 0;
    encoded = xer_encode(&asn_DEF_SetOpenXer, &value, XER_F_CANONICAL, collect, &output);
    assert(encoded.encoded == -1);
}

/*
 * Purpose: keep a preallocated selected wrapper freeable after child failure.
 * Source: CHOICE ownership and generated SET XER decoder. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect failure handling.
 * Author: maintainers. History: regression for partial selected-value cleanup.
 * Example: invalid INTEGER input leaves a safely freeable CHOICE value.
 */
static void
check_preallocated_failure(void) {
    static const char wire[] = "<SetOpenXer><id>1</id><flag><true/></flag>"
                               "<value><Payload>bad</Payload></value></SetOpenXer>";
    SetOpenXer_t *value = calloc(1, sizeof(*value));
    asn_dec_rval_t result;
    assert(value);
    value->value = calloc(1, sizeof(*value->value));
    assert(value->value);
    value->value->present = SetOpenXer__value_PR_Payload;
    value->value->choice.Payload = calloc(1, sizeof(*value->value->choice.Payload));
    assert(value->value->choice.Payload);
    result = xer_decode(0, &asn_DEF_SetOpenXer, (void **)&value, wire, sizeof(wire) - 1);
    assert(result.code == RC_FAIL);
    ASN_STRUCT_FREE(asn_DEF_SetOpenXer, value);
}

/*
 * Purpose: compare generated SET and SEQUENCE encodings of the same IOC value.
 * Source: generated XER descriptors and shared component mapping.
 * Version: 2026-10-30. Inputs: none. Returns: nothing.
 * Errors: assertions detect different component XML. Author: asn1c maintainers.
 * History: added generated SET/SEQUENCE interoperability check.
 * Example: the body of both canonical encodings is byte-identical.
 */
static void
check_interop(void) {
    SetOpenXer_t set = {0};
    SeqOpenXer_t sequence = {0};
    SetOpenXer__value set_open = {0};
    SeqOpenXer__value seq_open = {0};
    BOOLEAN_t flag = 1;
    Payload_t payload = 42;
    output_t a = {{0}, 0}, b = {{0}, 0};
    asn_enc_rval_t result;
    const char *a_body, *b_body;
    size_t a_length, b_length;
    set.id = sequence.id = 1;
    set.flag = sequence.flag = &flag;
    set.value = &set_open;
    sequence.value = &seq_open;
    set_open.present = SetOpenXer__value_PR_Payload;
    seq_open.present = SeqOpenXer__value_PR_Payload;
    set_open.choice.Payload = seq_open.choice.Payload = &payload;
    result = xer_encode(&asn_DEF_SetOpenXer, &set, XER_F_CANONICAL, collect, &a);
    assert(result.encoded > 0 && a.size < sizeof(a.bytes));
    result = xer_encode(&asn_DEF_SeqOpenXer, &sequence, XER_F_CANONICAL, collect, &b);
    assert(result.encoded > 0 && b.size < sizeof(b.bytes));
    a.bytes[a.size] = b.bytes[b.size] = 0;
    a_body = strchr(a.bytes, '>');
    b_body = strchr(b.bytes, '>');
    assert(a_body && b_body);
    a_body++;
    b_body++;
    assert(a.size >= (size_t)(a_body - a.bytes) + sizeof("</SetOpenXer>") - 1);
    assert(b.size >= (size_t)(b_body - b.bytes) + sizeof("</SeqOpenXer>") - 1);
    a_length = a.size - (size_t)(a_body - a.bytes) - (sizeof("</SetOpenXer>") - 1);
    b_length = b.size - (size_t)(b_body - b.bytes) - (sizeof("</SeqOpenXer>") - 1);
    assert(a_length == b_length && !memcmp(a_body, b_body, a_length));
}

/*
 * Purpose: reject encoding when canonical order precedes the selector.
 * Source: SET canonical tag order and bounded XER replay. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions detect incorrect order.
 * Author: maintainers. History: prevent emitting values the decoder cannot read.
 * Example: a value tagged before id can still decode when id appears first.
 */
static void
check_reverse_order(void) {
    static const char wire[] = "<ReverseXer><id>1</id><value><Payload>42</Payload></value></ReverseXer>";
    ReverseXer_t source = {0}, *decoded = 0;
    ReverseXer__value value = {0};
    Payload_t payload = 42;
    output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    source.id = 1;
    source.value = &value;
    value.present = ReverseXer__value_PR_Payload;
    value.choice.Payload = &payload;
    encoded = xer_encode(&asn_DEF_ReverseXer, &source, XER_F_CANONICAL, collect, &output);
    assert(encoded.encoded == -1);
    result = xer_decode(0, &asn_DEF_ReverseXer, (void **)&decoded, wire, sizeof(wire) - 1);
    assert(result.code == RC_OK && decoded && decoded->value);
    assert(decoded->value->present == ReverseXer__value_PR_Payload);
    assert(decoded->value->choice.Payload && *decoded->value->choice.Payload == 42);
    ASN_STRUCT_FREE(asn_DEF_ReverseXer, decoded);
}

/*
 * Purpose: reject OPEN TYPE flags on synthetic SET extension-group leaves.
 * Source: grouped SET descriptors and direct-only IOC XER scope.
 * Version: 2026-10-30. Inputs: none. Returns: nothing.
 * Errors: assertions detect unintended acceptance. Author: asn1c maintainers.
 * History: added explicit unsupported grouped-open regression.
 * Example: a grouped leaf cannot use the outer parent's selector implicitly.
 */
static void
check_group_rejected(void) {
    static const char wire[] = "<GroupedXer><id>1</id><leaf><true/></leaf></GroupedXer>";
    asn_TYPE_member_t *leaf = &asn_DEF_GroupedXer.elements[1].type->elements[0];
    enum asn_TYPE_flags_e flags = leaf->flags;
    GroupedXer_t *decoded = 0, source = {0};
    struct GroupedXer__ext1 group = {0};
    BOOLEAN_t boolean = 1;
    output_t output = {{0}, 0};
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;
    source.id = 1;
    source.ext1 = &group;
    group.leaf = &boolean;
    leaf->flags |= ATF_OPEN_TYPE;
    result = xer_decode(0, &asn_DEF_GroupedXer, (void **)&decoded, wire, sizeof(wire) - 1);
    encoded = xer_encode(&asn_DEF_GroupedXer, &source, XER_F_CANONICAL, collect, &output);
    leaf->flags = flags;
    assert(result.code == RC_FAIL && encoded.encoded == -1);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_GroupedXer, decoded);
}

/*
 * Purpose: run generated IOC SET XER regressions.
 * Source: 604 ASN.1 fixture. Version: 2026-10-30.
 * Inputs: none. Returns: zero on success. Errors: assertions terminate.
 * Author: maintainers. History: initial selector-first SET XER test.
 * Example: invoked through tests-c-compiler/check-assembly.sh.
 */
int
main(void) {
    check_stream();
    check_rejections();
    check_preallocated_failure();
    check_encode();
    check_interop();
    check_reverse_order();
    check_group_rejected();
    return 0;
}
