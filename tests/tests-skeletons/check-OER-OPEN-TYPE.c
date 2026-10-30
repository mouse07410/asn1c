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

/* Inline CHOICE layout used to detect variant-address frees. */
/* Inline CHOICE wrapper used to verify that its variant is never freed as a heap object. */
typedef struct test_choice_s {
    int value; /* Inline test variant value. */
    unsigned present; /* CHOICE presence state. */
} test_choice_t;

/* Parent containing the CHOICE wrapper by value. */
/* Parent value that embeds the open-type CHOICE wrapper directly. */
typedef struct test_parent_inline_s {
    test_choice_t choice; /* Inline CHOICE open-type wrapper. */
} test_parent_inline_t;

/* Parent containing the CHOICE wrapper by pointer. */
/* Parent value that owns a separately allocated open-type CHOICE wrapper. */
typedef struct test_parent_pointer_s {
    test_choice_t *choice; /* Pointer CHOICE open-type wrapper. */
} test_parent_pointer_t;

/* CHOICE layout with a heap-backed variant. */
/* CHOICE wrapper whose selected variant owns a heap value. */
typedef struct test_choice_pointer_variant_s {
    int *value; /* Heap-backed selected variant. */
    unsigned present; /* CHOICE presence state. */
} test_choice_pointer_variant_t;

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
    .free_struct = test_free,
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
static asn_TYPE_descriptor_t test_parent_descriptor = {
    .name = "TestParent"
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
    test_inline_specifics.pres_offset = offsetof(test_choice_t, present);
    test_inline_specifics.pres_size = sizeof(unsigned);

    memset(&test_pointer_specifics, 0, sizeof(test_pointer_specifics));
    test_pointer_specifics.struct_size = sizeof(test_choice_pointer_variant_t);
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
    assert(free_calls == 1);
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
