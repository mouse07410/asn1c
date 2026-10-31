/*
 * Runtime regression tests for OER open-type CHOICE wrapper cleanup.
 * Copyright (c) 2026 asn1c maintainers.
 */
#undef NDEBUG
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <constr_SET_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <BIT_STRING.h>
#include <NativeInteger.h>
#include <BOOLEAN.h>
#include <oer_decoder.h>

/* Inline CHOICE layout used to detect variant-address frees. */
/* Inline CHOICE wrapper used to verify that its variant is never freed as a heap object. */
typedef struct test_choice_s {
    long value; /* Inline test variant value. */
    unsigned present; /* CHOICE presence state. */
    asn_struct_ctx_t context; /* Parser state variable. */
} test_choice_t;

/* Parent containing the CHOICE wrapper by value. */
/* Parent value that embeds the open-type CHOICE wrapper directly. */
typedef struct test_parent_inline_s {
    test_choice_t choice; /* Inline CHOICE open-type wrapper. */
    asn_struct_ctx_t context; /* Parser state variable. */
} test_parent_inline_t;

/* Parent containing the CHOICE wrapper by pointer. */
/* Parent value that owns a separately allocated open-type CHOICE wrapper. */
typedef struct test_parent_pointer_s {
    test_choice_t *choice; /* Pointer CHOICE open-type wrapper. */
    asn_struct_ctx_t context; /* Parser state variable. */
} test_parent_pointer_t;

/* CHOICE layout with a heap-backed variant. */
/* CHOICE wrapper whose selected variant owns a heap value. */
typedef struct test_choice_pointer_variant_s {
    int *value; /* Heap-backed selected variant. */
    unsigned present; /* CHOICE presence state. */
    asn_struct_ctx_t context; /* Parser state variable. */
} test_choice_pointer_variant_t;

static asn_TYPE_descriptor_t *selected_override; /* Test selection state variable. */
static unsigned decoder_calls; /* Decoder call counter state variable. */
static unsigned free_calls; /* Variant free counter state variable. */
static unsigned invalid_free_modes; /* Invalid free counter state variable. */
static int allocate_before_failure; /* Allocation control state variable. */
static void *last_allocated; /* Allocated variant state variable. */
static enum asn_dec_rval_code_e decoder_result; /* Decoder result state variable. */

/*
 * Decode a controlled test value to exercise open-type success and failure.
 * Original source: Test-only OER type operation.
 * Version: 2026-10-30.
 * Parameters:
 *   codec_ctx: Optional codec context; unused by this controlled decoder.
 *   td: Type descriptor; unused because this test uses one type.
 *   constraints: OER constraints; unused by this controlled decoder.
 *   struct_ptr: Value slot, optionally populated with an allocated value.
 *   buffer: Encoded bytes; unused because outcomes are configured globally.
 *   size: Encoded byte count, returned as consumed on successful decode.
 * Returns: Configured decoder status and byte count.
 * Exceptions: Allocation failure returns RC_FAIL.
 * Author: asn1c runtime test maintainers.
 * History: Added to cover OER open-type cleanup paths.
 * Example: Configured to fail after allocating a pointer variant.
 */
static asn_dec_rval_t
test_oer_decoder(const asn_codec_ctx_t *codec_ctx,
                 const asn_TYPE_descriptor_t *td,
                 const asn_oer_constraints_t *constraints, void **struct_ptr,
                 const void *buffer, size_t size) {
    asn_dec_rval_t result = {decoder_result, 0};

    (void)codec_ctx;
    (void)td;
    (void)constraints;
    (void)buffer;
    decoder_calls++;
    if(allocate_before_failure && !*struct_ptr) {
        *struct_ptr = malloc(sizeof(int));
        if(!*struct_ptr) {
            result.code = RC_FAIL;
            return result;
        }
        last_allocated = *struct_ptr;
    }
    if(decoder_result == RC_OK) {
        result.consumed = size;
    }
    return result;
}

/*
 * Record and safely perform cleanup requested by oer_open_type_get().
 * Original source: Test-only OER type operation.
 * Version: 2026-10-30.
 * Parameters:
 *   td: Type descriptor; unused because this test uses one type.
 *   ptr: Value to release or reset.
 *   method: Requested free operation.
 * Returns: Nothing.
 * Exceptions: None; unexpected freeing of a non-heap address is recorded.
 * Author: asn1c runtime test maintainers.
 * History: Added to assert the decoder's ownership contract.
 * Example: A failed inline decode requests UNDERLYING_AND_RESET.
 */
static void
test_free(const asn_TYPE_descriptor_t *td, void *ptr,
          enum asn_struct_free_method method) {
    (void)td;
    if(!ptr) {
        return;
    }
    free_calls++;
    if(method == ASFM_FREE_EVERYTHING) {
        if(ptr == last_allocated) {
            free(ptr);
            last_allocated = NULL;
        } else {
            invalid_free_modes++;
        }
    } else if(method == ASFM_FREE_UNDERLYING_AND_RESET) {
        memset(ptr, 0, sizeof(int));
    } else if(method != ASFM_FREE_UNDERLYING) {
        invalid_free_modes++;
    }
}

/* Data structures: operation callbacks and member layouts for the tests. */
static asn_TYPE_operation_t test_operations = {
    .kind = ASN_KIND_PRIMITIVE,
    .free_struct = NativeInteger_free,
    .oer_decoder = test_oer_decoder
}; /* OER test operation state variable. */
static asn_TYPE_descriptor_t test_variant_descriptor = {
    .name = "TestVariant",
    .op = &test_operations
}; /* Test descriptor state variable. */
static asn_TYPE_descriptor_t test_choice_descriptor; /* CHOICE state variable. */
static asn_TYPE_member_t test_inline_variant; /* Inline member state variable. */
static asn_TYPE_member_t test_pointer_variant; /* Pointer member state variable. */
static asn_CHOICE_specifics_t test_inline_specifics; /* Inline layout state variable. */
static asn_CHOICE_specifics_t test_pointer_specifics; /* Pointer layout state variable. */
static asn_SEQUENCE_specifics_t test_parent_specifics = {
    .struct_size = sizeof(test_parent_inline_t),
    .ctx_offset = offsetof(test_parent_inline_t, context)
}; /* Parent storage layout state variable. */
static asn_TYPE_descriptor_t test_parent_descriptor = {
    .name = "TestParent",
    .op = &asn_OP_SEQUENCE,
    .specifics = &test_parent_specifics
}; /* Parent descriptor state variable. */

/*
 * Select the one supported test variant from a parent value.
 * Original source: Test-only type selector.
 * Version: 2026-10-30.
 * Parameters:
 *   parent_td: Parent descriptor; unused because this test has one parent.
 *   parent: Parent value; unused because the test variant is fixed.
 * Returns: The test variant descriptor and its 1-based CHOICE index.
 * Exceptions: None.
 * Author: asn1c runtime test maintainers.
 * History: Added with the OER open-type cleanup regression.
 * Example: Always returns the test variant at presence index 1.
 */
static asn_type_selector_result_t
test_type_selector(const asn_TYPE_descriptor_t *parent_td,
                   const void *parent) {
    asn_type_selector_result_t result = {&test_variant_descriptor, 1};

    (void)parent_td;
    (void)parent;
    if(selected_override) result.type_descriptor = selected_override;
    return result;
}

/*
 * Initialize descriptor metadata for the inline and pointer variant layouts.
 * Original source: Test-only descriptor setup.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing.
 * Exceptions: None.
 * Author: asn1c runtime test maintainers.
 * History: Added with the OER open-type cleanup regression.
 * Example: Called before constructing each tested open-type member.
 */
static void
test_initialize_descriptors(void) {
    memset(&test_inline_variant, 0, sizeof(test_inline_variant));
    test_inline_variant.memb_offset = offsetof(test_choice_t, value);
    test_inline_variant.type = &test_variant_descriptor;
    test_inline_variant.name = "inlineValue";

    memset(&test_pointer_variant, 0, sizeof(test_pointer_variant));
    test_pointer_variant.flags = ATF_POINTER;
    test_pointer_variant.memb_offset =
        offsetof(test_choice_pointer_variant_t, value);
    test_pointer_variant.type = &test_variant_descriptor;
    test_pointer_variant.name = "pointerValue";

    memset(&test_inline_specifics, 0, sizeof(test_inline_specifics));
    test_inline_specifics.struct_size = sizeof(test_choice_t);
    test_inline_specifics.ctx_offset = offsetof(test_choice_t, context);
    test_inline_specifics.pres_offset = offsetof(test_choice_t, present);
    test_inline_specifics.pres_size = sizeof(unsigned);

    memset(&test_pointer_specifics, 0, sizeof(test_pointer_specifics));
    test_pointer_specifics.struct_size = sizeof(test_choice_pointer_variant_t);
    test_pointer_specifics.ctx_offset = offsetof(test_choice_pointer_variant_t, context);
    test_pointer_specifics.pres_offset =
        offsetof(test_choice_pointer_variant_t, present);
    test_pointer_specifics.pres_size = sizeof(unsigned);

    test_choice_descriptor.name = "TestChoice";
    test_choice_descriptor.op = &asn_OP_CHOICE;
    test_choice_descriptor.elements = &test_inline_variant;
    test_choice_descriptor.elements_count = 1;
    test_choice_descriptor.specifics = &test_inline_specifics;
}

/*
 * Reset counters and configure the controlled decoder for a single test.
 * Original source: Test-only state setup.
 * Version: 2026-10-30.
 * Parameters: result: Decoder result to return after optional allocation.
 * Returns: Nothing.
 * Exceptions: None.
 * Author: asn1c runtime test maintainers.
 * History: Added with the OER open-type cleanup regression.
 * Example: Configure RC_FAIL before testing a closed-container failure.
 */
static void
test_reset(enum asn_dec_rval_code_e result) {
    assert(last_allocated == NULL);
    decoder_calls = 0;
    free_calls = 0;
    invalid_free_modes = 0;
    allocate_before_failure = 0;
    decoder_result = result;
}

/*
 * Verify incomplete data cleans an inline wrapper without freeing its variant.
 * Original source: OER open-type runtime behavior.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions fail if cleanup uses a variant address as owned.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Regression test for an incomplete length-delimited container.
 * Example: Input declares two payload bytes but supplies only one.
 */
static void
test_incomplete_inline_wrapper(void) {
    static const uint8_t input[] = {2, 0x11};
    test_parent_inline_t parent = {{0, 0}};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;

    test_reset(RC_OK);
    member.flags = ATF_OPEN_TYPE;
    member.memb_offset = offsetof(test_parent_inline_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));

    assert(result.code == RC_WMORE);
    assert(result.consumed == 0);
    assert(parent.choice.present == 0);
    assert(decoder_calls == 0);
    assert(free_calls == 0);
    assert(invalid_free_modes == 0);
}

/*
 * Verify incomplete input releases a pointer wrapper and leaves no variant free.
 * Original source: OER open-type runtime behavior.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions check status, ownership and decoder activity.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Covers the allocated-wrapper branch of incomplete cleanup.
 * Example: A null wrapper is allocated before an incomplete container is read.
 */
static void
test_incomplete_pointer_wrapper(void) {
    static const uint8_t input[] = {2, 0x11};
    test_parent_pointer_t parent = {NULL};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;

    test_reset(RC_OK);
    member.flags = ATF_OPEN_TYPE | ATF_POINTER;
    member.memb_offset = offsetof(test_parent_pointer_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));

    assert(result.code == RC_WMORE);
    assert(result.consumed == 0);
    assert(parent.choice == NULL);
    assert(decoder_calls == 0);
    assert(free_calls == 0);
    assert(invalid_free_modes == 0);
}

/*
 * Verify incomplete input also disposes a previously populated pointer wrapper.
 * Original source: OER open-type runtime behavior.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions check active-arm and wrapper cleanup.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Regression for wrapper cleanup after resetting an active arm.
 * Example: A heap wrapper starts with its inline arm active before decode.
 */
static void
test_incomplete_populated_pointer_wrapper(void) {
    static const uint8_t input[] = {2, 0x11};
    test_parent_pointer_t parent = {NULL};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;

    test_reset(RC_OK);
    parent.choice = calloc(1, sizeof(*parent.choice));
    assert(parent.choice != NULL);
    parent.choice->value = 23;
    parent.choice->present = 1;
    member.flags = ATF_OPEN_TYPE | ATF_POINTER;
    member.memb_offset = offsetof(test_parent_pointer_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));

    assert(result.code == RC_WMORE);
    assert(result.consumed == 0);
    assert(parent.choice == NULL);
    assert(decoder_calls == 0);
    assert(free_calls == 0);
    assert(invalid_free_modes == 0);
}

/*
 * Sweep every one-byte length determinant through incomplete and empty cases.
 * Original source: OER open-type runtime behavior.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions bound consumption and verify safe cleanup.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Added bounded malformed/incomplete length coverage.
 * Example: High-bit determinants without their length octets return RC_WMORE.
 */
static void
test_single_octet_length_determinants(void) {
    test_parent_inline_t parent;
    asn_TYPE_member_t member = {0};
    unsigned octet;

    member.flags = ATF_OPEN_TYPE;
    member.memb_offset = offsetof(test_parent_inline_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";

    for(octet = 0; octet <= 0xff; octet++) {
        uint8_t input = (uint8_t)octet;
        asn_dec_rval_t result;

        test_reset(RC_OK);
        memset(&parent, 0, sizeof(parent));
        result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent,
                                   &member, &input, sizeof(input));
        assert(result.consumed <= sizeof(input));
        assert(invalid_free_modes == 0);
        if(octet == 0 || octet == 0x80) {
            assert(result.code == RC_OK);
            assert(result.consumed == sizeof(input));
            assert(decoder_calls == 1);
            assert(parent.choice.present == 1);
            assert(CHOICE_variant_set_presence(&test_choice_descriptor,
                                               &parent.choice, 0) == 0);
        } else {
            assert(result.code == RC_WMORE);
            assert(result.consumed == 0);
            assert(decoder_calls == 0);
            assert(parent.choice.present == 0);
            assert(free_calls == 0);
        }
    }
}

/*
 * Reject a CHOICE member offset that falls outside the wrapper allocation.
 * Original source: OER open-type runtime validation.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions check bounded rejection and wrapper cleanup.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Added to cover malformed generated layout metadata.
 * Example: An inline member offset equal to struct_size is rejected.
 */
static void
test_invalid_variant_offset(void) {
    static const uint8_t input[] = {1, 0x11};
    test_parent_pointer_t parent = {NULL};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;
    unsigned saved_offset;

    test_reset(RC_OK);
    saved_offset = test_inline_variant.memb_offset;
    test_inline_variant.memb_offset = sizeof(test_choice_t);
    member.flags = ATF_OPEN_TYPE | ATF_POINTER;
    member.memb_offset = offsetof(test_parent_pointer_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    test_inline_variant.memb_offset = saved_offset;

    assert(result.code == RC_FAIL);
    assert(result.consumed == 0);
    assert(parent.choice == NULL);
    assert(decoder_calls == 0);
    assert(free_calls == 0);
    assert(invalid_free_modes == 0);
}

/*
 * Reject and release a wrapper carrying an out-of-range presence index.
 * Original source: OER open-type runtime validation.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions verify invalid state does not reach the decoder.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Added to guard CHOICE reset against corrupted presence state.
 * Example: A one-arm CHOICE wrapper stores presence index two.
 */
static void
test_invalid_existing_presence(void) {
    static const uint8_t input[] = {1, 0x11};
    test_parent_pointer_t parent = {NULL};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;

    test_reset(RC_OK);
    parent.choice = calloc(1, sizeof(*parent.choice));
    assert(parent.choice != NULL);
    parent.choice->present = 2;
    member.flags = ATF_OPEN_TYPE | ATF_POINTER;
    member.memb_offset = offsetof(test_parent_pointer_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));

    assert(result.code == RC_FAIL);
    assert(result.consumed == 0);
    assert(parent.choice == NULL);
    assert(decoder_calls == 0);
    assert(free_calls == 0);
    assert(invalid_free_modes == 0);
}

/*
 * Verify decoder failure releases both a pointer variant and its wrapper.
 * Original source: OER open-type runtime behavior.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions check variant and wrapper ownership cleanup.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Covers failure after a pointer variant has been allocated.
 * Example: A closed one-byte container fails after creating the selected value.
 */
static void
test_failed_pointer_variant(void) {
    static const uint8_t input[] = {1, 0x11};
    test_parent_pointer_t parent = {NULL};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;

    test_reset(RC_FAIL);
    allocate_before_failure = 1;
    test_operations.free_struct = test_free;
    test_choice_descriptor.elements = &test_pointer_variant;
    test_choice_descriptor.specifics = &test_pointer_specifics;
    member.flags = ATF_OPEN_TYPE | ATF_POINTER;
    member.memb_offset = offsetof(test_parent_pointer_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));

    assert(result.code == RC_FAIL);
    assert(parent.choice == NULL);
    assert(decoder_calls == 1);
    assert(free_calls == 1);
    assert(invalid_free_modes == 0);
    assert(last_allocated == NULL);
    test_choice_descriptor.elements = &test_inline_variant;
    test_choice_descriptor.specifics = &test_inline_specifics;
    test_operations.free_struct = NativeInteger_free;
}

/*
 * Reject missing decoder arguments before invoking the selector or allocating.
 * Original source: OPEN_TYPE_oer_get() argument validation.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Nothing; assertions verify clean failures and zero consumption.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Added malformed API-argument coverage.
 * Example: Nonempty input with a null data pointer returns RC_FAIL.
 */
static void
test_invalid_arguments(void) {
    test_parent_inline_t parent = {{0, 0}};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;

    test_reset(RC_OK);
    member.flags = ATF_OPEN_TYPE;
    member.memb_offset = offsetof(test_parent_inline_t, choice);
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(NULL, NULL, &parent, &member, NULL, 0);
    assert(result.code == RC_FAIL && result.consumed == 0);
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, NULL, &member,
                               NULL, 0);
    assert(result.code == RC_FAIL && result.consumed == 0);
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, NULL,
                               NULL, 0);
    assert(result.code == RC_FAIL && result.consumed == 0);
    result = OPEN_TYPE_oer_get(NULL, &test_parent_descriptor, &parent, &member,
                               NULL, 1);
    assert(result.code == RC_FAIL && result.consumed == 0);
    assert(decoder_calls == 0 && free_calls == 0);
}

/*
 * Purpose: Reject mismatched selected descriptors and undersized inline slots.
 * Source: OPEN TYPE storage validation review. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers malicious wrapper and direct-type descriptors.
 * Example: A long starting one byte before wrapper end is rejected.
 */
static void
test_malicious_selected_storage(void) {
    static const uint8_t input[] = {1, 0x11};
    test_parent_inline_t parent = {{0, 0}};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;
    unsigned old_offset = test_inline_variant.memb_offset;
    asn_TYPE_descriptor_t *old_type = test_inline_variant.type;
    test_reset(RC_OK);
    member.flags = ATF_OPEN_TYPE;
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    test_inline_variant.memb_offset = sizeof(test_choice_t) - 1;
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && decoder_calls == 0);
    test_inline_variant.memb_offset = old_offset;
    test_inline_variant.type = &asn_DEF_BOOLEAN;
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && decoder_calls == 0);
    test_inline_variant.type = old_type;
    member.type = &asn_DEF_BOOLEAN; /* Direct member disagrees with selector. */
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && decoder_calls == 0);
    member.type = &test_variant_descriptor;
    member.memb_offset = sizeof(test_parent_inline_t) - 1;
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && decoder_calls == 0);
    member.flags |= ATF_POINTER;
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && decoder_calls == 0);
}

/*
 * Purpose: Preserve a preallocated destination after malformed OER contents.
 * Source: oer_open_type_get ownership contract. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Rejects trailing data without losing preexisting allocations.
 * Example: Two payload bytes cannot represent a one-byte INTEGER value.
 */
static void
test_preallocated_trailing_data(void) {
    static const uint8_t input[] = {2, 42, 0};
    const asn_oer_constraints_t constraints = {{1, 1}, -1};
    long *value = malloc(sizeof(*value));
    long *original = value;
    ssize_t result;
    assert(value);
    *value = 7;
    result = oer_open_type_get(0, &asn_DEF_NativeInteger, &constraints,
                               (void **)&value, input, sizeof(input));
    assert(result == -1 && value == original && *value == 0);
    free(value);
}

/* Parent with an owned pointer-backed direct open value. */
typedef struct test_direct_parent_s {
    long *value; /* Heap-backed selected INTEGER. */
    asn_struct_ctx_t context; /* Parser state variable. */
} test_direct_parent_t;

/*
 * Purpose: Select NativeInteger for a direct open-type test member.
 * Source: Test selector contract. Version: 2026-10-30.
 * Inputs: td and parent are unused. Returns: the selected descriptor.
 * Errors: none. Author: maintainers. History: preallocated ownership regression.
 * Example: A matching direct member stores an owned long pointer.
 */
static asn_type_selector_result_t
test_select_native(const asn_TYPE_descriptor_t *td, const void *parent) {
    asn_type_selector_result_t selected = {&asn_DEF_NativeInteger, 1};
    (void)td;
    (void)parent;
    return selected;
}

/*
 * Purpose: Release a preallocated direct member after malformed trailing data.
 * Source: OPEN TYPE OER failure ownership contract. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Exercises a preexisting pointer through exact-consumption failure.
 * Example: A closed INTEGER envelope with an extra byte fails and clears it.
 */
static void
test_preallocated_direct_member(void) {
    static const uint8_t input[] = {3, 1, 42, 0};
    test_direct_parent_t parent = {0};
    asn_SEQUENCE_specifics_t specs = {
        .struct_size = sizeof(parent), .ctx_offset = offsetof(test_direct_parent_t, context)
    };
    asn_TYPE_descriptor_t descriptor = {0};
    asn_TYPE_member_t member = {0};
    asn_dec_rval_t result;
    parent.value = malloc(sizeof(*parent.value));
    assert(parent.value);
    *parent.value = 7;
    descriptor.name = "DirectParent";
    descriptor.op = &asn_OP_SEQUENCE;
    descriptor.specifics = &specs;
    member.flags = ATF_OPEN_TYPE | ATF_POINTER;
    member.memb_offset = offsetof(test_direct_parent_t, value);
    member.type = &asn_DEF_NativeInteger;
    member.type_selector = test_select_native;
    member.name = "value";
    result = OPEN_TYPE_oer_get(0, &descriptor, &parent, &member, input, sizeof(input));
    assert(result.code == RC_FAIL && parent.value == 0);
}

/*
 * Purpose: Reject forged context, presence and collection layout metadata.
 * Source: Constructed storage contracts. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers malformed inline children before decoder or cleanup calls.
 * Example: A context crossing struct_size fails before child allocation.
 */
static void
test_malformed_constructed_metadata(void) {
    asn_TYPE_descriptor_t type = {0};
    asn_SEQUENCE_specifics_t sequence = {.struct_size = 256, .ctx_offset = 0};
    asn_SET_specifics_t set = {.struct_size = 256, .ctx_offset = 0, .pres_offset = 128};
    asn_CHOICE_specifics_t choice = {.struct_size = 256, .ctx_offset = 0,
                                     .pres_offset = 128, .pres_size = sizeof(int)};
    asn_SET_OF_specifics_t list = {.struct_size = 256, .ctx_offset = sizeof(asn_anonymous_set_)};
    asn_OCTET_STRING_specifics_t octets = asn_SPC_OCTET_STRING_specs;
    asn_TYPE_member_t element = {.type = &asn_DEF_NativeInteger};
    unsigned int mandatory = 0;
    size_t size;
    int kind;

    type.op = &asn_OP_SEQUENCE;
    type.specifics = &sequence;
    assert(SET_inline_value_size(&type, &size) == 0);
    sequence.ctx_offset = sequence.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    sequence.ctx_offset = 0;
    type.elements_count = 1;
    type.elements = 0;
    assert(SET_inline_value_size(&type, &size) == -1);
    type.elements = &element;
    element.flags = ATF_POINTER;
    element.memb_offset = sequence.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    element.memb_offset = 0;
    element.type = &type;
    assert(SET_inline_value_size(&type, &size) == 0); /* Pointer cycle is legal. */
    element.flags = ATF_NOFLAGS;
    assert(SET_inline_value_size(&type, &size) == -1); /* Inline cycle is invalid. */
    element.type = &asn_DEF_NativeInteger;
    type.op = &asn_OP_SET;
    type.specifics = &set;
    type.elements = &element;
    type.elements_count = 1;
    set._mandatory_elements = &mandatory;
    assert(SET_inline_value_size(&type, &size) == 0);
    element.type = &type;
    assert(SET_inline_value_size(&type, &size) == -1); /* Inline SET self-cycle. */
    element.flags = ATF_POINTER;
    assert(SET_inline_value_size(&type, &size) == 0); /* Pointer SET self-cycle. */
    element.type = &asn_DEF_NativeInteger;
    element.flags = ATF_NOFLAGS;
    set.pres_offset = 0;
    assert(SET_inline_value_size(&type, &size) == -1);
    set.pres_offset = set.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    set.pres_offset = 128;
    set.ctx_offset = set.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    type.op = &asn_OP_CHOICE;
    type.specifics = &choice;
    assert(SET_inline_value_size(&type, &size) == 0);
    choice.pres_offset = 0;
    assert(SET_inline_value_size(&type, &size) == -1);
    choice.pres_offset = choice.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    choice.pres_offset = 128;
    choice.ctx_offset = choice.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    type.op = &asn_OP_OPEN_TYPE;
    assert(SET_inline_value_size(&type, &size) == -1);
    type.specifics = &list;
    for(kind = 0; kind < 2; kind++) {
        type.op = kind ? &asn_OP_SET_OF : &asn_OP_SEQUENCE_OF;
        assert(SET_inline_value_size(&type, &size) == 0);
        list.ctx_offset = list.struct_size - 1;
        assert(SET_inline_value_size(&type, &size) == -1);
        list.ctx_offset = 0;
        assert(SET_inline_value_size(&type, &size) == -1);
        list.ctx_offset = sizeof(asn_anonymous_set_);
        list.struct_size = sizeof(asn_anonymous_set_) - 1;
        assert(SET_inline_value_size(&type, &size) == -1);
        list.struct_size = 256;
        type.elements_count = 0;
        assert(SET_inline_value_size(&type, &size) == -1);
        type.elements_count = 1;
    }
    type = asn_DEF_OCTET_STRING;
    type.specifics = &octets;
    assert(SET_inline_value_size(&type, &size) == 0);
    octets.ctx_offset = octets.struct_size - 1;
    assert(SET_inline_value_size(&type, &size) == -1);
    assert(SET_inline_value_size(&asn_DEF_BIT_STRING, &size) == 0);
}

/*
 * Purpose: Bound descriptor graph traversal while allowing pointer recursion.
 * Source: Constructed descriptor graph validation. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers mixed inline/pointer cycles and excessive nesting.
 * Example: A pointer to B containing inline A is a valid recursive layout.
 */
static void
test_recursive_constructed_layouts(void) {
    asn_TYPE_descriptor_t types[66];
    asn_SEQUENCE_specifics_t specs[66];
    asn_TYPE_member_t members[66];
    size_t width, i;
    memset(types, 0, sizeof(types));
    memset(specs, 0, sizeof(specs));
    memset(members, 0, sizeof(members));
    for(i = 0; i < 66; i++) {
        types[i].op = &asn_OP_SEQUENCE;
        types[i].specifics = &specs[i];
        types[i].elements = &members[i];
        types[i].elements_count = 1;
        specs[i].struct_size = 256;
        specs[i].ctx_offset = 0;
        members[i].flags = ATF_POINTER;
        members[i].type = i + 1 < 66 ? &types[i + 1] : &asn_DEF_NativeInteger;
    }
    assert(SET_inline_value_size(&types[0], &width) == -1);
    members[0].type = &types[1];
    members[1].flags = ATF_NOFLAGS;
    members[1].type = &types[0];
    assert(SET_inline_value_size(&types[0], &width) == 0);
    {
        asn_TYPE_member_t alternatives[2] = {members[0], members[0]};
        alternatives[1].flags = ATF_NOFLAGS;
        types[0].elements = alternatives;
        types[0].elements_count = 2;
        assert(SET_inline_value_size(&types[0], &width) == -1);
        types[0].elements = &members[0];
        types[0].elements_count = 1;
    }
    members[0].flags = ATF_NOFLAGS;
    assert(SET_inline_value_size(&types[0], &width) == -1);
}

/*
 * Purpose: Ensure malformed selected child context is rejected before decode.
 * Source: OER OPEN TYPE descriptor validation. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Tests a forged constructed arm without touching wrapper storage.
 * Example: An out-of-range child parser context yields RC_FAIL.
 */
static void
test_malformed_selected_child(void) {
    static const uint8_t input[] = {1, 0};
    test_parent_inline_t parent = {0};
    asn_TYPE_descriptor_t child = {0};
    asn_SEQUENCE_specifics_t specs = {.struct_size = sizeof(asn_struct_ctx_t),
                                      .ctx_offset = sizeof(asn_struct_ctx_t) - 1};
    asn_TYPE_member_t member = {0};
    asn_TYPE_descriptor_t *old_type = test_inline_variant.type;
    asn_dec_rval_t result;
    parent.choice.value = 77;
    child.op = &asn_OP_SEQUENCE;
    child.specifics = &specs;
    test_inline_variant.type = &child;
    selected_override = &child;
    member.flags = ATF_OPEN_TYPE;
    member.type = &test_choice_descriptor;
    member.type_selector = test_type_selector;
    member.name = "openType";
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && parent.choice.value == 77 && !parent.choice.present);
    specs.ctx_offset = 0;
    child.elements_count = 1;
    child.elements = 0;
    result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                               input, sizeof(input));
    assert(result.code == RC_FAIL && parent.choice.value == 77 && !parent.choice.present);
    {
        asn_TYPE_member_t nested = {.flags = ATF_POINTER,
                                    .memb_offset = sizeof(asn_struct_ctx_t) - 1,
                                    .type = &asn_DEF_NativeInteger};
        child.elements = &nested;
        result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &parent, &member,
                                   input, sizeof(input));
        assert(result.code == RC_FAIL && parent.choice.value == 77 && !parent.choice.present);
        child.elements = 0;
    }
    test_inline_variant.type = old_type;
    {
        test_parent_pointer_t pointer_parent = {0};
        asn_TYPE_descriptor_t *old_pointer_type = test_pointer_variant.type;
        asn_SET_OF_specifics_t list = {.struct_size = 256,
                                       .ctx_offset = sizeof(asn_anonymous_set_)};
        asn_TYPE_operation_t element_ops = asn_OP_NativeInteger;
        asn_TYPE_descriptor_t element_type = asn_DEF_NativeInteger;
        asn_TYPE_member_t element = {0};
        member.flags |= ATF_POINTER;
        test_choice_descriptor.elements = &test_pointer_variant;
        test_choice_descriptor.specifics = &test_pointer_specifics;
        test_pointer_variant.type = &child;
        result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &pointer_parent, &member,
                                   input, sizeof(input));
        assert(result.code == RC_FAIL && !pointer_parent.choice);
        element_ops.oer_decoder = 0;
        element_type.op = &element_ops;
        element.type = &element_type;
        child.op = &asn_OP_SEQUENCE_OF;
        child.specifics = &list;
        child.elements = &element;
        child.elements_count = 1;
        result = OPEN_TYPE_oer_get(0, &test_parent_descriptor, &pointer_parent, &member,
                                   input, sizeof(input));
        assert(result.code == RC_FAIL && !pointer_parent.choice);
        test_pointer_variant.type = old_pointer_type;
        test_choice_descriptor.elements = &test_inline_variant;
        test_choice_descriptor.specifics = &test_inline_specifics;
    }
    selected_override = 0;
}

/*
 * Run the focused OER open-type cleanup regressions.
 * Original source: Test suite entry point.
 * Version: 2026-10-30.
 * Parameters: None.
 * Returns: Zero when all runtime ownership assertions pass.
 * Exceptions: Assertion failure terminates the test.
 * Author: asn1c runtime test maintainers.
 * History: Added for incomplete and failed CHOICE-wrapper cleanup.
 * Example: Invoked by the check-OER-OPEN-TYPE Automake target.
 */
int
main(void) {
    test_initialize_descriptors();
    test_malformed_constructed_metadata();
    test_recursive_constructed_layouts();
    test_malformed_selected_child();
    test_malicious_selected_storage();
    test_preallocated_trailing_data();
    test_preallocated_direct_member();
    test_incomplete_inline_wrapper();
    test_incomplete_pointer_wrapper();
    test_incomplete_populated_pointer_wrapper();
    test_single_octet_length_determinants();
    test_invalid_variant_offset();
    test_invalid_existing_presence();
    test_failed_pointer_variant();
    test_invalid_arguments();
    return 0;
}
