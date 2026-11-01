/*-
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * Exercise CBOR OPEN TYPE storage checks with a valid large IOC alphabet.
 * The selected arm must encode without traversing every unused descriptor.
 */
#include <asn_application.h>
#include <NativeInteger.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <cbor_decoder.h>
#include <cbor_encoder.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ARM_COUNT 1025u

/* One inline OPEN TYPE wrapper with a selected native integer arm. */
typedef struct test_choice_s {
    long amount; /* Selected arm's inline value. */
    asn_struct_ctx_t context; /* Runtime CHOICE context. */
    int present; /* One-based selected arm index. */
} test_choice_t;

/* Parent SEQUENCE containing a selector and the inline OPEN TYPE wrapper. */
typedef struct test_parent_s {
    long id; /* IOC selector value. */
    test_choice_t value; /* Selected OPEN TYPE value. */
    asn_struct_ctx_t context; /* Runtime SEQUENCE context. */
} test_parent_t;

/* Bounded output buffer for an encoded CBOR value. */
typedef struct test_buffer_s {
    uint8_t bytes[128]; /* Encoded bytes. */
    size_t used; /* Number of bytes written; state variable. */
} test_buffer_t;

/*
 * Purpose: select the first IOC arm from a valid parent descriptor.
 * Source: generated OPEN TYPE selector contract. Version: 2026-11-01.
 * Inputs: parent describes the SEQUENCE; sptr is its value.
 * Returns: selected descriptor and one-based arm index, or an empty result.
 * Errors: malformed input gives an empty result. Author: asn1c maintainers.
 * History: introduced for the large IOC CBOR regression.
 * Example: select_value(&parent_type, &parent_value) selects arm one.
 */
static asn_type_selector_result_t
select_value(const asn_TYPE_descriptor_t *parent, const void *sptr) {
    asn_type_selector_result_t result = {0};
    const asn_TYPE_descriptor_t *wrapper;
    if(!parent || !sptr || parent->elements_count < 2 || !parent->elements) return result;
    wrapper = parent->elements[1].type;
    if(!wrapper || !wrapper->elements || !wrapper->elements_count) return result;
    result.type_descriptor = wrapper->elements[0].type;
    result.presence_index = 1;
    return result;
}

/*
 * Purpose: append encoded bytes without overflowing the test buffer.
 * Source: CBOR application callback contract. Version: 2026-11-01.
 * Inputs: bytes/sz are the chunk; key is a test_buffer_t.
 * Returns: zero on success, negative one on invalid input or no capacity.
 * Errors: none thrown. Author: asn1c maintainers.
 * History: introduced for the large IOC CBOR regression.
 * Example: append_bytes("x", 1, &buffer) appends one byte.
 */
static int
append_bytes(const void *bytes, size_t sz, void *key) {
    test_buffer_t *buffer = key;
    if(!buffer || (!bytes && sz) || buffer->used > sizeof(buffer->bytes)
       || sz > sizeof(buffer->bytes) - buffer->used) return -1;
    if(sz) memcpy(buffer->bytes + buffer->used, bytes, sz);
    buffer->used += sz;
    return 0;
}

/*
 * Purpose: verify successful CBOR encoding/decoding and malformed layout rejection.
 * Source: F1AP OPEN TYPE CBOR regression and descriptor validation contracts.
 * Version: 2026-11-01. Inputs: parent is the complete descriptor; wrapper and
 * arm describe the selected value; choice gives its storage; value is the input.
 * Returns: zero if all cases pass, otherwise one. Errors: none thrown.
 * Author: asn1c maintainers. History: introduced for large IOC alphabets.
 * Example: check_cases(&parent, &wrapper, &arms[0], &choice, &value).
 */
static int
check_cases(asn_TYPE_descriptor_t *parent, asn_TYPE_descriptor_t *wrapper,
            asn_TYPE_member_t *arm, asn_CHOICE_specifics_t *choice,
            test_parent_t *value) {
    test_buffer_t buffer = {{0}, 0};
    test_parent_t *decoded = 0;
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t width = 0;
    unsigned saved_offset;

    /* Immediate wrapper storage is valid independent of inactive arms. */
    if(SET_shallow_inline_value_size(wrapper, &width) != 0
       || width != sizeof(value->value)) return 1;

    /* The selected arm can be encoded and decoded without unused arms. */
    encoded = cbor_encode(parent, value, append_bytes, &buffer);
    if(encoded.encoded < 0 || (size_t)encoded.encoded != buffer.used) return 1;
    result = cbor_decode(0, parent, (void **)&decoded, buffer.bytes, buffer.used);
    if(result.code != RC_OK || result.consumed != buffer.used || !decoded
       || decoded->id != value->id || decoded->value.present != 1
       || decoded->value.amount != value->value.amount) {
        if(decoded) ASN_STRUCT_FREE(*parent, decoded);
        return 1;
    }
    ASN_STRUCT_FREE(*parent, decoded);

    /* A malformed wrapper presence offset must fail before field access. */
    saved_offset = choice->pres_offset;
    choice->pres_offset = choice->struct_size;
    buffer.used = 0;
    encoded = cbor_encode(parent, value, append_bytes, &buffer);
    choice->pres_offset = saved_offset;
    if(encoded.encoded >= 0) return 1;

    /* An arm outside its wrapper must also fail, even with a valid selector. */
    saved_offset = arm->memb_offset;
    arm->memb_offset = choice->struct_size;
    buffer.used = 0;
    encoded = cbor_encode(parent, value, append_bytes, &buffer);
    arm->memb_offset = saved_offset;
    if(encoded.encoded >= 0) return 1;

    /* A mismatched selected arm cannot be read as the first arm. */
    value->value.present = 2;
    buffer.used = 0;
    encoded = cbor_encode(parent, value, append_bytes, &buffer);
    value->value.present = 1;
    return encoded.encoded < 0 ? 0 : 1;
}

/*
 * Purpose: build a large but valid IOC wrapper and run CBOR regression cases.
 * Source: generated F1AP OPEN TYPE layout. Version: 2026-11-01.
 * Inputs: none. Returns: zero on success, one on allocation or test failure.
 * Errors: none thrown. Author: asn1c maintainers.
 * History: introduced after F1AP exceeded the recursive layout budget.
 * Example: run check-CBOR-open-large as part of make check.
 */
int
main(void) {
    asn_TYPE_descriptor_t *aliases = calloc(TEST_ARM_COUNT, sizeof(*aliases));
    asn_TYPE_member_t *arms = calloc(TEST_ARM_COUNT, sizeof(*arms));
    char (*names)[16] = calloc(TEST_ARM_COUNT, sizeof(*names));
    asn_TYPE_member_t fields[2] = {{0}};
    asn_CHOICE_specifics_t choice = {0};
    asn_SEQUENCE_specifics_t sequence = {0};
    asn_TYPE_descriptor_t wrapper = {0}, parent = {0};
    test_parent_t value = {0};
    size_t i;
    int failed = 1;

    if(!aliases || !arms || !names) goto cleanup;
    /* Distinct aliases make recursive validation exceed its 1024-type limit. */
    for(i = 0; i < TEST_ARM_COUNT; i++) {
        int written = snprintf(names[i], sizeof(names[i]), "arm%zu", i);
        if(written < 0 || (size_t)written >= sizeof(names[i])) goto cleanup;
        aliases[i] = asn_DEF_NativeInteger;
        arms[i].type = &aliases[i];
        arms[i].memb_offset = offsetof(test_choice_t, amount);
        arms[i].name = names[i];
    }

    /* Describe the inline OPEN TYPE wrapper and its selected first arm. */
    choice.struct_size = sizeof(test_choice_t);
    choice.ctx_offset = offsetof(test_choice_t, context);
    choice.pres_offset = offsetof(test_choice_t, present);
    choice.pres_size = sizeof(value.value.present);
    choice.ext_start = -1;
    wrapper.name = "OPEN TYPE";
    wrapper.xml_tag = "OPEN_TYPE";
    wrapper.op = &asn_OP_OPEN_TYPE;
    wrapper.elements = arms;
    wrapper.elements_count = TEST_ARM_COUNT;
    wrapper.specifics = &choice;

    /* Describe a SEQUENCE with a native selector and an open value. */
    fields[0].type = &asn_DEF_NativeInteger;
    fields[0].memb_offset = offsetof(test_parent_t, id);
    fields[0].name = "id";
    fields[1].flags = ATF_OPEN_TYPE;
    fields[1].type = &wrapper;
    fields[1].type_selector = select_value;
    fields[1].memb_offset = offsetof(test_parent_t, value);
    fields[1].name = "value";
    sequence.struct_size = sizeof(test_parent_t);
    sequence.ctx_offset = offsetof(test_parent_t, context);
    sequence.first_extension = -1;
    parent.name = "LargeOpenParent";
    parent.xml_tag = "LargeOpenParent";
    parent.op = &asn_OP_SEQUENCE;
    parent.elements = fields;
    parent.elements_count = 2;
    parent.specifics = &sequence;
    value.id = 1;
    value.value.amount = 7;
    value.value.present = 1;
    failed = check_cases(&parent, &wrapper, &arms[0], &choice, &value);

cleanup:
    free(names);
    free(arms);
    free(aliases);
    if(failed) fprintf(stderr, "large OPEN TYPE CBOR regression failed\n");
    return failed;
}
