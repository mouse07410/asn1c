/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <aper_opentype.h>
#include <ANY.h>
#include <limits.h>
#include <stdint.h>

/*
 * Purpose: Validate that a descriptor is the runtime ANY representation.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: type is the candidate member descriptor.
 * Returns: 1 when it uses the ANY APER callbacks and has enough storage.
 * Errors: Invalid or incompatible descriptors return 0.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586.
 * Example: Used before interpreting the flagged final CHOICE member as ANY_t.
 */
static int
open_type_is_any_descriptor(const asn_TYPE_descriptor_t *type) {
    const asn_OCTET_STRING_specifics_t *specs;

    if(!type || !type->op || type->op->aper_decoder != ANY_decode_aper
       || type->op->aper_encoder != ANY_encode_aper) {
        return 0;
    }
    specs = (const asn_OCTET_STRING_specifics_t *)type->specifics;
    return !specs || specs->struct_size >= sizeof(ANY_t);
}

/*
 * Purpose: Validate CHOICE storage metadata before reading its presence index.
 * Original source: Runtime validation helper for APER open-type wrappers.
 * Version: 2026-10-22.
 * Parameters: type is the candidate wrapper descriptor.
 * Returns: 1 for a valid nonempty CHOICE layout, otherwise 0.
 * Errors: Invalid member tables, structure sizes, or presence offsets are rejected.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586 malformed-descriptor hardening.
 * Example: Used before clearing a choice or allocating a wrapper.
 */
static int
open_type_choice_descriptor_valid(const asn_TYPE_descriptor_t *type) {
    const asn_CHOICE_specifics_t *specs;

    if(!type || !type->elements || !type->elements_count || !type->specifics) {
        return 0;
    }
    specs = (const asn_CHOICE_specifics_t *)type->specifics;
    if(!specs->struct_size
       || (specs->pres_size != sizeof(char)
           && specs->pres_size != sizeof(short)
           && specs->pres_size != sizeof(int))) {
        return 0;
    }
    return specs->pres_offset <= specs->struct_size
           && specs->pres_size <= specs->struct_size - specs->pres_offset;
}

/*
 * Purpose: Locate the final CHOICE member marked as the opaque ANY fallback.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: type is the open-type wrapper descriptor.
 * Returns: The flagged final member, or NULL for an invalid descriptor.
 * Errors: Invalid descriptor shape is reported as NULL.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586; identity is determined by flag and position.
 * Example: Used by OPEN_TYPE_aper_get and OPEN_TYPE_encode_aper.
 */
static const asn_TYPE_member_t *
open_type_unknown_variant(const asn_TYPE_descriptor_t *type) {
    const asn_TYPE_member_t *member;
    const asn_CHOICE_specifics_t *specifics;
    const asn_OCTET_STRING_specifics_t *any_specs;
    size_t required_size;

    if(!open_type_choice_descriptor_valid(type)) return NULL;
    member = &type->elements[type->elements_count - 1];
    if(!(member->flags & ATF_OPEN_TYPE_UNKNOWN)
       || !open_type_is_any_descriptor(member->type)) {
        return NULL;
    }
    specifics = (const asn_CHOICE_specifics_t *)type->specifics;
    any_specs = member->type->specifics
                    ? (const asn_OCTET_STRING_specifics_t *)member->type->specifics
                    : &asn_SPC_ANY_specs;
    required_size = member->flags & ATF_POINTER
                        ? sizeof(void *) : any_specs->struct_size;
    if(member->memb_offset > specifics->struct_size
       || required_size > specifics->struct_size - member->memb_offset) {
        return NULL;
    }
    return member;
}

/*
 * Purpose: Report whether a wrapper can retain an unknown APER open value.
 * Source: Validated opaque fallback descriptor. Version: 2026-10-30.
 * Inputs: td describes the wrapper. Returns: nonzero for a valid fallback.
 * Errors: Invalid descriptors return zero. Author: asn1c maintainers.
 * History: Used to validate deferred SET members before reading input.
 * Example: A direct INTEGER descriptor has no unknown fallback.
 */
int
OPEN_TYPE_aper_has_fallback(const asn_TYPE_descriptor_t *td) {
    return open_type_unknown_variant(td) != NULL;
}

/*
 * Purpose: Clear a CHOICE only when its stored presence index is valid.
 * Original source: Runtime helper added for APER open-type cleanup.
 * Version: 2026-10-22.
 * Parameters: type and value describe the CHOICE instance to clear.
 * Returns: 0 on success, -1 for a missing or corrupt CHOICE descriptor.
 * Errors: Invalid presence indexes are rejected before CHOICE cleanup asserts.
 * Responsible party: asn1c runtime maintainers.
 * History: Added while hardening issue #586 failure cleanup.
 * Example: Used before decoding a replacement table-selected CHOICE arm.
 */
static int
open_type_clear_choice(const asn_TYPE_descriptor_t *type, void *value) {
    unsigned present;

    if(!value || !open_type_choice_descriptor_valid(type)) return -1;
    present = CHOICE_variant_get_presence(type, value);
    if(present > type->elements_count) return -1;
    return CHOICE_variant_set_presence(type, value, 0);
}

#ifndef ASN_REJECT_UNKNOWN_EXTENSIONS
/*
 * Purpose: Grow the temporary ANY buffer for bytes already present in input.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: value is the temporary ANY; capacity tracks allocated bytes;
 *             required is the capacity needed, including the trailing NUL.
 * Returns: 0 on success, -1 on overflow or allocation failure.
 * Errors: Allocation failure leaves the existing buffer owned by value.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586.
 * Example: Called after confirming payload bytes are available in the input.
 */
static int
open_type_any_reserve(ANY_t *value, size_t *capacity, size_t required) {
    size_t new_capacity;
    void *new_buffer;

    if(required <= *capacity) return 0;
    new_capacity = *capacity ? *capacity : 1;
    while(new_capacity < required) {
        if(new_capacity > SIZE_MAX / 2) {
            new_capacity = required;
            break;
        }
        new_capacity *= 2;
    }
    new_buffer = REALLOC(value->buf, new_capacity);
    if(!new_buffer) return -1;
    value->buf = (uint8_t *)new_buffer;
    *capacity = new_capacity;
    return 0;
}

/*
 * Purpose: Copy one available portion of an open-type payload into ANY.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: pd is the input stream; value, capacity, total, and left track
 *             the growing payload and the remaining octets in this fragment.
 * Returns: 1 when bytes were copied, 0 when input is incomplete, or -1 on error.
 * Errors: Size overflow and allocation failure return -1.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586; allocation is bounded by available input.
 * Example: Called once or more for each APER length fragment.
 */
static int
open_type_copy_payload_chunk(asn_per_data_t *pd, ANY_t *value,
                             size_t *capacity, size_t *total, size_t *left) {
    size_t available = (pd->nbits - pd->nboff) / 8;
    size_t take = available < *left ? available : *left;
    size_t required;
    int ret;

    /* Keep the PER API's signed int bit count small even for large buffers. */
    if(take > (size_t)65536) take = (size_t)65536;
    if(take == 0) {
        int32_t octet = per_get_few_bits(pd, 8);
        if(octet < 0) return 0;
        take = 1;
        if(*total >= (size_t)INT_MAX) return -1;
        required = *total + take + 1;
        if(open_type_any_reserve(value, capacity, required)) return -1;
        value->buf[(*total)++] = (uint8_t)octet;
    } else {
        if(take > (size_t)INT_MAX - *total) return -1;
        required = *total + take + 1;
        if(open_type_any_reserve(value, capacity, required)) return -1;
        ret = per_get_many_bits(pd, value->buf + *total, 0, (int)(take * 8));
        if(ret < 0) return 0;
        *total += take;
    }
    value->size = (int)*total;
    *left -= take;
    return 1;
}

/*
 * Purpose: Decode one APER open-type envelope into opaque ANY payload octets.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: pd is the input bit stream; value receives raw envelope octets.
 * Returns: RC_OK, RC_WMORE for incomplete input, or RC_FAIL on invalid data.
 * Errors: Allocation and size-limit failures return RC_FAIL without leaking.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586; allocation follows bytes verified available.
 * Example: Called for the flagged final ANY alternative of an IOC wrapper.
 */
static asn_dec_rval_t
open_type_decode_raw_octets(asn_per_data_t *pd, ANY_t *value) {
    asn_dec_rval_t rv = {RC_FAIL, 0};
    size_t initial_moved; /* state variable: input position before the envelope. */
    size_t capacity = 0; /* state variable: allocated payload capacity. */
    size_t total = 0; /* state variable: payload octets copied so far. */
    int repeat = 0; /* state variable: APER length says another fragment follows. */

    if(!pd || !value || pd->nboff > pd->nbits) return rv;
    initial_moved = pd->moved;
    do {
        ssize_t raw_length = aper_get_length(pd, -1, -1, -1, &repeat);
        size_t left;

        if(raw_length < 0) {
            rv.code = RC_WMORE;
            goto done;
        }
        if((uintmax_t)raw_length > (uintmax_t)INT_MAX - total
           || pd->nboff > pd->nbits) {
            rv.code = RC_FAIL;
            goto done;
        }
        left = (size_t)raw_length;
        while(left) {
            int copied = open_type_copy_payload_chunk(pd, value, &capacity,
                                                       &total, &left);
            if(copied < 0) goto done;
            if(copied == 0) {
                rv.code = RC_WMORE;
                goto done;
            }
        }
    } while(repeat);

    if(!value->buf && open_type_any_reserve(value, &capacity, 1)) goto done;
    value->buf[total] = 0;
    rv.code = RC_OK;

done:
    if(pd->moved >= initial_moved) rv.consumed = pd->moved - initial_moved;
    if(rv.code != RC_OK) {
        FREEMEM(value->buf);
        value->buf = NULL;
        value->size = 0;
    }
    return rv;
}

/*
 * Purpose: Find or allocate the wrapper storage for an open-type CHOICE.
 * Original source: Runtime helper added for APER open-type decoding.
 * Version: 2026-10-22.
 * Parameters: member and structure locate the wrapper; outputs provide its
 *             pointer slot and whether this helper allocated the wrapper.
 * Returns: 0 when storage is ready, -1 for invalid metadata or allocation.
 * Errors: Existing invalid presence indexes are rejected before cleanup.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted to keep opaque fallback decode validation bounded.
 * Example: Used before decoding a known or opaque alternative.
 */
static int
open_type_prepare_choice_wrapper(const asn_TYPE_member_t *member,
                                 void *structure, void **inline_value,
                                 void ***wrapper_pointer,
                                 int *wrapper_allocated) {
    const asn_CHOICE_specifics_t *specifics;
    void *field;

    if(!member || !member->type || !structure || !inline_value
       || !wrapper_pointer || !wrapper_allocated) return -1;
    specifics = (const asn_CHOICE_specifics_t *)member->type->specifics;
    if(!specifics || !open_type_choice_descriptor_valid(member->type)) {
        return -1;
    }

    *wrapper_allocated = 0;
    field = (char *)structure + member->memb_offset;
    if(member->flags & ATF_POINTER) {
        *wrapper_pointer = (void **)field;
    } else {
        *inline_value = field;
        *wrapper_pointer = inline_value;
    }
    if(!**wrapper_pointer) {
        **wrapper_pointer = CALLOC(1, specifics->struct_size);
        if(!**wrapper_pointer) return -1;
        *wrapper_allocated = 1;
    } else if(open_type_clear_choice(member->type, **wrapper_pointer)) {
        return -1;
    }
    return 0;
}

/*
 * Purpose: Install decoded opaque payload ownership into the fallback arm.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: type, fallback, wrapper, index, and decoded describe the choice.
 * Returns: 0 on success, -1 for invalid offsets, metadata, or allocation.
 * Errors: On failure decoded remains owned by the caller for cleanup.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted from the unknown path to isolate ownership transfer.
 * Example: Moves one decoded ANY buffer into the final flagged CHOICE member.
 */
static int
open_type_attach_unknown(const asn_TYPE_descriptor_t *type,
                         const asn_TYPE_member_t *fallback, void *wrapper,
                         unsigned index, ANY_t *decoded) {
    const asn_CHOICE_specifics_t *choice_specs;
    const asn_OCTET_STRING_specifics_t *any_specs;
    size_t required_size;
    void *target;

    if(!type || !fallback || !wrapper || !fallback->type || !decoded) {
        return -1;
    }
    choice_specs = (const asn_CHOICE_specifics_t *)type->specifics;
    any_specs = fallback->type->specifics
                    ? (const asn_OCTET_STRING_specifics_t *)fallback->type->specifics
                    : &asn_SPC_ANY_specs;
    if(!choice_specs || !any_specs || any_specs->struct_size < sizeof(ANY_t)) {
        return -1;
    }
    required_size = fallback->flags & ATF_POINTER
                        ? sizeof(void *) : any_specs->struct_size;
    if(fallback->memb_offset > choice_specs->struct_size
       || required_size > choice_specs->struct_size - fallback->memb_offset) {
        return -1;
    }
    if(CHOICE_variant_set_presence(type, wrapper, index)) return -1;

    if(fallback->flags & ATF_POINTER) {
        target = CALLOC(1, any_specs->struct_size);
        if(!target) return -1;
        *(void **)((char *)wrapper + fallback->memb_offset) = target;
    } else {
        target = (char *)wrapper + fallback->memb_offset;
    }
    *(ANY_t *)target = *decoded;
    memset(decoded, 0, sizeof(*decoded));
    return 0;
}

/*
 * Purpose: Roll back temporary payload and wrapper storage after decode error.
 * Original source: Runtime helper added for APER open-type failure cleanup.
 * Version: 2026-10-22.
 * Parameters: member, wrapper pointer, allocation state, and decoded value.
 * Returns: No value; all temporary ownership is released.
 * Errors: Invalid wrapper metadata is ignored after releasing decoded bytes.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted to make unknown decode cleanup consistent.
 * Example: Called for truncated payloads and failed wrapper attachment.
 */
static void
open_type_rollback_unknown(const asn_TYPE_member_t *member,
                           void **wrapper_pointer, int wrapper_allocated,
                           ANY_t *decoded) {
    FREEMEM(decoded->buf);
    if(member && member->type && wrapper_pointer && *wrapper_pointer) {
        CHOICE_variant_set_presence(member->type, *wrapper_pointer, 0);
    }
    if(wrapper_allocated && wrapper_pointer && *wrapper_pointer) {
        ASN_STRUCT_FREE(*member->type, *wrapper_pointer);
        *wrapper_pointer = NULL;
    }
}

/*
 * Purpose: Decode an unknown open type into the flagged ANY choice member.
 * Original source: Runtime helper added for APER extensible IOC fallback.
 * Version: 2026-10-22.
 * Parameters: ctx is the codec context; structure and member identify the
 *             open type; pd is its APER input stream.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL with consumed input bits.
 * Errors: Invalid descriptors, truncated data, and allocation failures fail
 *         cleanly; an allocated wrapper is freed on failure.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586; supports inline and pointer CHOICE wrappers.
 * Example: Called when the table selector has no recognized alternative.
 */
static asn_dec_rval_t
open_type_aper_get_unknown(const asn_codec_ctx_t *ctx, void *structure,
                           const asn_TYPE_member_t *member, asn_per_data_t *pd) {
    asn_dec_rval_t rv = {RC_FAIL, 0};
    const asn_TYPE_member_t *fallback;
    void *inline_value = NULL;
    void **wrapper_pointer = NULL;
    ANY_t decoded = {0};
    unsigned fallback_index;
    int wrapper_allocated = 0;

    if(ASN__STACK_OVERFLOW_CHECK(ctx)) return rv;
    if(!structure || !member || !pd
       || !(member->flags & ATF_OPEN_TYPE) || !member->type) {
        return rv;
    }
    fallback = open_type_unknown_variant(member->type);
    if(!fallback) return rv;
    fallback_index = member->type->elements_count;
    if(open_type_prepare_choice_wrapper(member, structure, &inline_value,
                                        &wrapper_pointer,
                                        &wrapper_allocated)) {
        return rv;
    }

    rv = open_type_decode_raw_octets(pd, &decoded);
    if(rv.code != RC_OK) {
        open_type_rollback_unknown(member, wrapper_pointer,
                                   wrapper_allocated, &decoded);
        return rv;
    }
    if(open_type_attach_unknown(member->type, fallback, *wrapper_pointer,
                                fallback_index, &decoded)) {
        rv.code = RC_FAIL;
        open_type_rollback_unknown(member, wrapper_pointer,
                                   wrapper_allocated, &decoded);
        return rv;
    }
    return rv;
}
#endif /* !ASN_REJECT_UNKNOWN_EXTENSIONS */

/*
 * Purpose: Locate the pointer slot for an inline or pointer-backed member.
 * Original source: Runtime helper extracted from APER open-type decoding.
 * Version: 2026-10-22.
 * Parameters: member and structure identify storage; inline_value holds inline
 *             storage's address when the member is not pointer-backed.
 * Returns: The pointer slot for the member value.
 * Errors: Arguments must be validated by the caller.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted for bounded APER open-type decoder complexity.
 * Example: Used for a field containing an OPEN_TYPE wrapper.
 */
static void **
open_type_member_pointer(const asn_TYPE_member_t *member, void *structure,
                         void **inline_value) {
    if(member->flags & ATF_POINTER) {
        return (void **)((char *)structure + member->memb_offset);
    }
    *inline_value = (char *)structure + member->memb_offset;
    return inline_value;
}

/*
 * Purpose: Prepare a selected CHOICE arm and locate its decode target.
 * Original source: Runtime helper extracted from the APER open-type decoder.
 * Version: 2026-10-22.
 * Parameters: member, selected, slot, and output pointers describe the target.
 * Returns: 0 when ready; -1 for malformed descriptors or allocation failure.
 * Errors: Validation completes before allocating or clearing the wrapper.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted for bounded APER open-type decoder complexity.
 * Example: Used before decoding a table-selected CHOICE alternative.
 */
static int
open_type_prepare_known_choice(const asn_TYPE_member_t *member,
                               asn_type_selector_result_t selected,
                               void **member_pointer,
                               const asn_TYPE_member_t **variant,
                               void **inner_value,
                               const asn_per_constraints_t **constraints,
                               size_t *member_offset,
                               int *wrapper_allocated) {
    const asn_CHOICE_specifics_t *specifics;

    if(!open_type_choice_descriptor_valid(member->type)
       || selected.presence_index > member->type->elements_count) {
        return -1;
    }
    *variant = &member->type->elements[selected.presence_index - 1];
    if(!(*variant)->type || !(*variant)->type->op) return -1;
    specifics = (const asn_CHOICE_specifics_t *)member->type->specifics;
    if(!specifics->struct_size) return -1;
    if(!*member_pointer) {
        *member_pointer = CALLOC(1, specifics->struct_size);
        if(!*member_pointer) return -1;
        *wrapper_allocated = 1;
    } else if(open_type_clear_choice(member->type, *member_pointer)) {
        return -1;
    }

    *member_offset = (*variant)->memb_offset;
    *constraints = (*variant)->encoding_constraints.per_constraints;
    if((*variant)->flags & ATF_POINTER) {
        *inner_value = *(void **)((char *)*member_pointer + *member_offset);
    } else {
        *inner_value = (char *)*member_pointer + *member_offset;
    }
    return 0;
}

/*
 * Purpose: Commit a completed selected open-type decode to its member slots.
 * Original source: Runtime helper extracted from the APER open-type decoder.
 * Version: 2026-10-22.
 * Parameters: member_pointer locates storage; variant, selected, offset, and
 *             inner_value describe the decoded CHOICE or direct value.
 * Returns: 0 on success, -1 if the CHOICE presence index cannot be set.
 * Errors: A failed presence update leaves cleanup to the caller.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted for bounded APER open-type decoder complexity.
 * Example: Called only after aper_open_type_get returns RC_OK.
 */
static int
open_type_commit_known(const asn_TYPE_member_t *member,
                       void **member_pointer,
                       const asn_TYPE_member_t *variant,
                       asn_type_selector_result_t selected,
                       size_t member_offset, void *inner_value) {
    if(member->type->elements_count) {
        if(CHOICE_variant_set_presence(member->type, *member_pointer,
                                       selected.presence_index)) {
            return -1;
        }
        if(variant->flags & ATF_POINTER) {
            *(void **)((char *)*member_pointer + member_offset) = inner_value;
        }
    } else if(member->flags & ATF_POINTER) {
        *member_pointer = inner_value;
    }
    return 0;
}

/*
 * Purpose: Release a failed known open-type decode and any temporary wrapper.
 * Original source: Existing APER open-type decoder cleanup, isolated here.
 * Version: 2026-10-22.
 * Parameters: member and member_pointer identify storage; selected, variant,
 *             inner_value, and wrapper_allocated describe the partial decode.
 * Returns: No value; partial nested values and temporary allocations are freed.
 * Errors: Cleanup relies on descriptors validated before decoding.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted for bounded APER open-type decoder complexity.
 * Example: Called after RC_WMORE or RC_FAIL while decoding a known table arm.
 */
static void
open_type_cleanup_known(const asn_TYPE_member_t *member,
                        void **member_pointer,
                        const asn_TYPE_member_t *variant,
                        asn_type_selector_result_t selected,
                        void *inner_value, int wrapper_allocated) {
    if(member->type->elements_count) {
        if(variant && (variant->flags & ATF_POINTER)) {
            if(inner_value) ASN_STRUCT_FREE(*selected.type_descriptor,
                                            inner_value);
        } else if(inner_value) {
            ASN_STRUCT_RESET(*selected.type_descriptor, inner_value);
        }
        if(*member_pointer) {
            CHOICE_variant_set_presence(member->type, *member_pointer, 0);
        }
        if(wrapper_allocated && *member_pointer) {
            ASN_STRUCT_FREE(*member->type, *member_pointer);
            *member_pointer = NULL;
        }
    } else if(member->flags & ATF_POINTER) {
        if(inner_value) ASN_STRUCT_FREE(*selected.type_descriptor, inner_value);
        *member_pointer = NULL;
    } else if(inner_value) {
        ASN_STRUCT_RESET(*selected.type_descriptor, inner_value);
    }
}

/*
 * Purpose: Decode a selected known open type into its wrapper alternative.
 * Original source: Existing asn1c APER open-type decoder, refactored here.
 * Version: 2026-10-22.
 * Parameters: ctx, structure, member, selected type, and pd describe the input.
 * Returns: The underlying APER decode result.
 * Errors: Invalid descriptors and failed decodes return RC_FAIL or RC_WMORE;
 *         partial values and allocated wrappers are released.
 * Responsible party: asn1c runtime maintainers.
 * History: Refactored for issue #586; unknown alternatives use a separate path.
 * Example: Called by OPEN_TYPE_aper_get for a known table selector result.
 */
static asn_dec_rval_t
open_type_aper_get_known(const asn_codec_ctx_t *ctx, void *structure,
                         const asn_TYPE_member_t *member,
                         asn_type_selector_result_t selected,
                         asn_per_data_t *pd) {
    asn_dec_rval_t rv = {RC_FAIL, 0};
    const asn_TYPE_member_t *variant = NULL;
    const asn_per_constraints_t *constraints = NULL;
    void *inline_value = NULL;
    void *inner_value = NULL;
    void **member_pointer;
    size_t member_offset = 0;
    int wrapper_allocated = 0;
    int wrapper_prepared = 0;

    if(!member || !member->type || !selected.presence_index
       || !selected.type_descriptor || !pd || !structure) return rv;
    member_pointer = open_type_member_pointer(member, structure, &inline_value);
    if(member->type->elements_count) {
        if(open_type_prepare_known_choice(member, selected, member_pointer,
                                          &variant, &inner_value, &constraints,
                                          &member_offset, &wrapper_allocated)) {
            return rv;
        }
        wrapper_prepared = 1;
    } else {
        inner_value = *member_pointer;
    }

    rv = aper_open_type_get(ctx, selected.type_descriptor, constraints,
                            &inner_value, pd);
    if(rv.code == RC_OK
       && !open_type_commit_known(member, member_pointer, variant, selected,
                                  member_offset, inner_value)) {
        return rv;
    }
    if(rv.code == RC_OK) rv.code = RC_FAIL;
    if(!wrapper_prepared && member->type->elements_count) return rv;
    open_type_cleanup_known(member, member_pointer, variant, selected,
                            inner_value, wrapper_allocated);
    return rv;
}

/*
 * Purpose: Decode an IOC table open type into its selected known or opaque arm.
 * Original source: Existing asn1c APER open-type decoder, dispatcher refactored.
 * Version: 2026-10-22.
 * Parameters: ctx, parent, structure, member, and pd identify the open type.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL from the chosen decoder path.
 * Errors: Unknown selectors fail when no fallback exists or strict mode is on.
 * Responsible party: asn1c runtime maintainers.
 * History: Added fallback dispatch for issue #586.
 * Example: Used by SEQUENCE_decode_aper for ATF_OPEN_TYPE members.
 */
asn_dec_rval_t
OPEN_TYPE_aper_get(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void *sptr,
                   const asn_TYPE_member_t *elm, asn_per_data_t *pd) {
    asn_type_selector_result_t selected = {0, 0};
    const asn_TYPE_member_t *fallback;
    if(!td || !sptr || !elm || !pd || !(elm->flags & ATF_OPEN_TYPE)
       || !elm->type) {
        ASN__DECODE_FAILED;
    }
    fallback = open_type_unknown_variant(elm->type);
    if(elm->type_selector) {
        selected = elm->type_selector(td, sptr);
    } else if(!fallback) {
        ASN__DECODE_FAILED;
    }
    if(!selected.presence_index || !selected.type_descriptor) {
#ifdef ASN_REJECT_UNKNOWN_EXTENSIONS
        ASN__DECODE_FAILED;
#else
        if(fallback) {
            return open_type_aper_get_unknown(opt_codec_ctx, sptr, elm, pd);
        }
        ASN__DECODE_FAILED;
#endif
    }
    return open_type_aper_get_known(opt_codec_ctx, sptr, elm, selected, pd);
}

/*
 * Purpose: Encode an open-type wrapper CHOICE using APER framing.
 * Original source: Existing asn1c APER wrapper encoder, extended for ANY.
 * Version: 2026-10-22.
 * Parameters: td and sptr identify the selected wrapper arm; po is output.
 * Returns: Encoding result, with encoded set to -1 on invalid data or failure.
 * Errors: Missing choices, invalid ANY buffers, and output errors fail.
 * Responsible party: asn1c runtime maintainers.
 * History: Added single-envelope output for issue #586 opaque fallback.
 * Example: Called by OPEN_TYPE_aper_put for table-selected wrappers.
 */
asn_enc_rval_t
OPEN_TYPE_encode_aper(const asn_TYPE_descriptor_t *td,
                      const asn_per_constraints_t *constraints,
                      const void *sptr, asn_per_outp_t *po) {
    const void *memb_ptr;   /* Pointer to the member */
    const asn_TYPE_member_t *elm; /* CHOICE's element */
    const asn_TYPE_member_t *fallback;
    asn_enc_rval_t er = {0,0,0};
    unsigned present;

    (void)constraints;

    if(!td || !sptr || !po || !open_type_choice_descriptor_valid(td))
        ASN__ENCODE_FAILED;

    if(td->elements_count == 0) {
        /* Direct type mode: no CHOICE wrapper, encode directly */
        ASN_DEBUG("Encoding %s OPEN TYPE in direct type mode", td->name);
        
        /* In direct type mode, sptr points directly to the value to encode */
        /* We can't encode it because we don't know the actual type descriptor */
        /* This should not happen - the parent should handle this case */
        ASN_DEBUG("ERROR: OPEN_TYPE_encode_aper called in direct type mode");
        ASN__ENCODE_FAILED;
    }

    /* CHOICE wrapper mode: use presence indicator */
    present = CHOICE_variant_get_presence(td, sptr);
    if(present == 0 || present > td->elements_count) {
        ASN__ENCODE_FAILED;
    } else {
        present--;
    }

    ASN_DEBUG("Encoding %s OPEN TYPE element %d", td->name, present);

    elm = &td->elements[present];
    if(!elm->type || !elm->type->op || !elm->type->op->aper_encoder) {
        ASN__ENCODE_FAILED;
    }
    if(elm->flags & ATF_POINTER) {
        /* Member is a pointer to another structure */
        memb_ptr =
            *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const char *)sptr + elm->memb_offset;
    }

    fallback = open_type_unknown_variant(td);
    if(fallback && elm == fallback) {
        /* ANY_encode_aper writes the one envelope around opaque payload bytes. */
        er = ANY_encode_aper(elm->type, NULL, memb_ptr, po);
        if(er.encoded == -1) ASN__ENCODE_FAILED;
        ASN__ENCODED_OK(er);
    }

    if(aper_open_type_put(elm->type,
                          elm->encoding_constraints.per_constraints,
                          memb_ptr, po) < 0) {
        ASN__ENCODE_FAILED;
    }

    er.encoded = 0;
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: Resolve known versus unknown selector state without assuming a table.
 * Original source: Runtime helper added for APER open-type selector handling.
 * Version: 2026-10-22.
 * Parameters: td and structure describe the parent; member is the open type;
 *             fallback identifies the optional unknown arm; outputs receive
 *             the selector result and whether the result is unknown.
 * Returns: 0 on a usable selector state, -1 when no selector or fallback exists.
 * Errors: Missing selectors are valid only for wrappers with opaque fallback.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for extensible empty IOC tables in issue #586.
 * Example: Empty tables resolve directly to their opaque fallback arm.
 */
static int
open_type_resolve_selector(const asn_TYPE_descriptor_t *td,
                           const void *structure,
                           const asn_TYPE_member_t *member,
                           const asn_TYPE_member_t *fallback,
                           asn_type_selector_result_t *selected,
                           int *selector_unknown) {
    if(member->type_selector) {
        *selected = member->type_selector(td, structure);
    } else if(!fallback) {
        return -1;
    }
    *selector_unknown = !selected->presence_index || !selected->type_descriptor;
    return 0;
}

/*
 * Purpose: Return the inline member address or the pointed-to member value.
 * Original source: Runtime helper extracted from OPEN_TYPE_aper_put.
 * Version: 2026-10-22.
 * Parameters: structure is the containing object; member describes its field.
 * Returns: The field address, or NULL for a missing pointer-backed field.
 * Errors: Callers validate structure and field metadata before use.
 * Responsible party: asn1c runtime maintainers.
 * History: Extracted for bounded OPEN_TYPE_aper_put complexity.
 * Example: Used to pass the selected wrapper to its APER encoder.
 */
static const void *
open_type_member_value(const void *structure, const asn_TYPE_member_t *member) {
    const void *field = (const char *)structure + member->memb_offset;
    if(member->flags & ATF_POINTER) {
        field = *(const void *const *)field;
    }
    return field;
}

/*
 * Purpose: Check that selector state matches the active wrapper CHOICE arm.
 * Original source: Runtime helper extracted from OPEN_TYPE_aper_put.
 * Version: 2026-10-22.
 * Parameters: wrapper descriptor/value, selected table result, unknown state,
 *             and fallback member describe the expected active alternative.
 * Returns: 0 for a matching active arm, -1 for inconsistent metadata/value.
 * Errors: Invalid presence indexes and known/opaque mismatches are rejected.
 * Responsible party: asn1c runtime maintainers.
 * History: Added to prevent re-encoding opaque bytes under a mutated known id.
 * Example: Rejects unknown choice data after its identifier changes to known.
 */
static int
open_type_choice_matches_selector(const asn_TYPE_descriptor_t *type,
                                  const void *wrapper,
                                  asn_type_selector_result_t selected,
                                  int selector_unknown,
                                  const asn_TYPE_member_t *fallback) {
    unsigned present;
    unsigned fallback_index;

    if(!wrapper || !open_type_choice_descriptor_valid(type)) return -1;
    present = CHOICE_variant_get_presence(type, wrapper);
    if(!present || present > type->elements_count) return -1;
    fallback_index = fallback ? type->elements_count : 0;
    if(selector_unknown) return fallback && present == fallback_index ? 0 : -1;
    if(!selected.presence_index || selected.presence_index > type->elements_count
       || present != selected.presence_index) {
        return -1;
    }
    return fallback && present == fallback_index ? -1 : 0;
}

/*
 * Purpose: Encode an IOC open type after checking its table selector and arm.
 * Original source: Existing asn1c APER open-type encoder, extended for ANY.
 * Version: 2026-10-22.
 * Parameters: td and sptr are the parent and structure; elm is the open type;
 *             po receives the selected arm's APER encoding.
 * Returns: Encoding result, with encoded set to -1 on invalid data or failure.
 * Errors: Selector/arm mismatches and invalid descriptors fail.
 * Responsible party: asn1c runtime maintainers.
 * History: Added selector consistency checks for issue #586.
 * Example: Called by SEQUENCE_encode_aper for ATF_OPEN_TYPE members.
 */
asn_enc_rval_t
OPEN_TYPE_aper_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                   const asn_TYPE_member_t *elm, asn_per_outp_t *po) {
    asn_type_selector_result_t selected = {0, 0};
    const void *memb_ptr;
    const asn_TYPE_member_t *fallback;
    asn_enc_rval_t er = {0,0,0};
    int selector_unknown;

    if(!td || !sptr || !elm || !po || !(elm->flags & ATF_OPEN_TYPE)) {
        ASN__ENCODE_FAILED;
    }

    if(!elm->type || !elm->type->op || !elm->type->op->aper_encoder) {
        ASN__ENCODE_FAILED;
    }
    fallback = open_type_unknown_variant(elm->type);
    if(open_type_resolve_selector(td, sptr, elm, fallback, &selected,
                                  &selector_unknown)) {
        ASN__ENCODE_FAILED;
    }
    memb_ptr = open_type_member_value(sptr, elm);
    if(!memb_ptr) ASN__ENCODE_FAILED;

    if(elm->type->elements_count) {
        if(open_type_choice_matches_selector(elm->type, memb_ptr, selected,
                                             selector_unknown, fallback)) {
            ASN__ENCODE_FAILED;
        }
        er = elm->type->op->aper_encoder(elm->type,
                                         elm->encoding_constraints.per_constraints,
                                         memb_ptr, po);
        if(er.encoded == -1) ASN__ENCODE_FAILED;
        ASN__ENCODED_OK(er);
    }
    if(selector_unknown || !selected.type_descriptor) ASN__ENCODE_FAILED;
    if(aper_open_type_put(selected.type_descriptor, NULL, memb_ptr, po) < 0) {
        ASN__ENCODE_FAILED;
    }
    er.encoded = 0;
    ASN__ENCODED_OK(er);
}


/*
 * Purpose: Report whether a table selector has no recognized open-type arm.
 * Original source: Existing public APER open-type compatibility helper.
 * Version: 2026-10-22.
 * Parameters: td and sptr describe the parent value; elm is the open-type member.
 * Returns: 1 for unknown or invalid selector input, 0 for a known type.
 * Errors: Invalid inputs are treated as unknown rather than dereferenced.
 * Responsible party: asn1c runtime maintainers.
 * History: Retained for API compatibility; SEQUENCE decode uses fallback dispatch.
 * Example: Callers can test an IOC selector before handling a legacy descriptor.
 */
int
OPEN_TYPE_aper_is_unknown_type(const asn_TYPE_descriptor_t *td, void *sptr,
                               const asn_TYPE_member_t *elm) {
    asn_type_selector_result_t selected;

    if(!td || !sptr || !elm || !elm->type_selector) return 1;
    selected = elm->type_selector(td, sptr);
    return !selected.presence_index || !selected.type_descriptor;
}

/*
 * Purpose: Consume and discard APER open-type fragments for legacy callers.
 * Original source: Existing public APER open-type discard helper.
 * Version: 2026-10-22.
 * Parameters: pd is the input PER stream.
 * Returns: RC_OK after all fragments are consumed; RC_FAIL for invalid input.
 * Errors: Null streams, malformed lengths, oversized fragments, and truncation
 *         return RC_FAIL without leaking the temporary buffer.
 * Responsible party: asn1c runtime maintainers.
 * History: Kept for public API compatibility; extensible IOC decode now retains
 *          opaque payload bytes through the flagged ANY alternative.
 * Example: Legacy code may discard an unknown open type when retention is unwanted.
 */
asn_dec_rval_t
OPEN_TYPE_aper_unknown_type_discard_bytes (asn_per_data_t *pd) {
#define ASN_DUMMY_BYTES 256
    unsigned char dummy[ASN_DUMMY_BYTES], *dummy_ptr = NULL;
    ssize_t bytes;
    int repeat;
    asn_dec_rval_t rv;
    size_t initial_consumed;

    rv.consumed = 0;
    rv.code = RC_FAIL;
    if(!pd) return rv;
    initial_consumed = pd->moved;

    do {
        bytes = aper_get_length(pd, -1, -1, -1, &repeat);
        if (bytes < 0) {
            /* Invalid length - return error */
            return rv;
        }
        if (bytes > 10 * ASN_DUMMY_BYTES)
        {
            return rv;
        }
        else if (bytes > ASN_DUMMY_BYTES)
        {
            dummy_ptr = CALLOC(1, bytes);
            if (!dummy_ptr)
                return rv;
        }

        if (per_get_many_bits(pd, (dummy_ptr ? dummy_ptr : dummy), 0, bytes << 3) < 0) {
            /* Error during bit consumption */
            if (dummy_ptr) {
                FREEMEM(dummy_ptr);
            }
            return rv;
        }

        if (dummy_ptr)
        {
            FREEMEM(dummy_ptr);
            dummy_ptr = NULL;
        }
    } while (repeat);

    /* Update consumed to reflect actual bits consumed */
    if(pd->moved >= initial_consumed) {
        rv.consumed = pd->moved - initial_consumed;
    }
    rv.code = RC_OK;
    return rv;
#undef ASN_DUMMY_BYTES
}
