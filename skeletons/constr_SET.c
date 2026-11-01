/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <BOOLEAN.h>
#include <NULL.h>
#include <NativeInteger.h>
#include <NativeReal.h>
#include <OCTET_STRING.h>
#include <ANY.h>
#include <BIT_STRING.h>
#include <asn_codecs_prim.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SET_OF.h>

asn_TYPE_operation_t asn_OP_SET = {
    .kind = ASN_KIND_SET,
    SET_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    SET_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    SET_compare,
    SET_copy,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    SET_decode_ber,
    SET_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    SET_decode_xer,
    SET_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    SET_decode_jer,
    SET_encode_jer,
#else
	0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    SET_decode_oer,
    SET_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    SET_decode_uper,
    SET_encode_uper,
#else
    0,
    0,
#endif
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    SET_decode_aper,
    SET_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    SET_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */,
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    SET_decode_cbor,
    SET_encode_cbor,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};

/*
 * Purpose: calculate the byte size of a SET presence bitmap safely.
 * Source: SET element count and the unsigned-int presence-word representation.
 * Version: 2026-10-22.
 * Parameters: count is the number of SET members; bytes receives bitmap size.
 * Returns: 0 on success, -1 if rounding or multiplication would overflow.
 * Errors: overflow is rejected before any descriptor storage is read.
 * Author: asn1c maintainers.
 * History: Added for validated SET and extension-group layouts.
 * Example: 33 members require two unsigned-int presence words.
 */
static int
_SET_presence_size(unsigned count, size_t *bytes) {
	size_t words;
	size_t bits = 8 * sizeof(unsigned int);

	if((size_t)count > SIZE_MAX - (bits - 1)) return -1;
	words = ((size_t)count + bits - 1) / bits;
	if(words > SIZE_MAX / sizeof(unsigned int)) return -1;
	*bytes = words * sizeof(unsigned int);
	return 0;
}

/*
 * Purpose: validate the fixed context and presence-map storage of a SET value.
 * Source: SET specifics and compiler-generated mandatory bitmap metadata.
 * Version: 2026-10-22.
 * Parameters: td/specs describe one SET descriptor and its structure layout.
 * Returns: nonzero when context and presence storage fit within struct_size.
 * Errors: missing maps, overflow, and out-of-range offsets return zero.
 * Author: asn1c maintainers.
 * History: Added to reject malformed parent layouts before member decoding.
 * Example: a presence offset beyond struct_size is rejected before bit access.
 */
static int
_SET_layout_valid(const asn_TYPE_descriptor_t *td,
		  const asn_SET_specifics_t *specs) {
	size_t presence_bytes;

	if(!td || !specs || !specs->struct_size
	|| (td->elements_count && (!td->elements || !specs->_mandatory_elements)))
		return 0;
	if(specs->ctx_offset > specs->struct_size
	|| sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset)
		return 0;
	if(specs->pres_offset > specs->struct_size
	|| _SET_presence_size(td->elements_count, &presence_bytes) != 0)
		return 0;
    if(presence_bytes > specs->struct_size - specs->pres_offset) return 0;
    if(presence_bytes && specs->pres_offset < specs->ctx_offset + sizeof(asn_struct_ctx_t)
    && specs->ctx_offset < specs->pres_offset + presence_bytes) return 0;
    return 1;
}

/*
 * Purpose: validate the storage layout of a synthetic extension-group SET.
 * Source: Generated SET struct size, context offset, and presence offset.
 * Version: 2026-10-22.
 * Parameters: td/specs describe the group descriptor and its structure.
 * Returns: nonzero when all fixed storage regions fit the structure.
 * Errors: empty, overflowing, or out-of-range layouts return zero.
 * Author: asn1c maintainers.
 * History: Split from group descriptor validation to keep checks bounded.
 * Example: an undersized presence map is rejected before indexing it.
 */
static int
_SET_group_layout_valid(const asn_TYPE_descriptor_t *td,
			const asn_SET_specifics_t *specs) {
	return td->elements_count && _SET_layout_valid(td, specs);
}

/*
 * Purpose: validate a group's child flags and tag-to-member map.
 * Source: Compiler-generated one-level extension-group SET metadata.
 * Version: 2026-10-22.
 * Parameters: td/specs describe the group's child descriptors and tag map.
 * Returns: nonzero if no nested groups exist and every mapped index is valid.
 * Errors: missing maps, nested groups, and invalid member indexes return zero.
 * Author: asn1c maintainers.
 * History: Split from group descriptor validation to keep checks bounded.
 * Example: a tag map pointing beyond the leaf array is rejected.
 */
static int
_SET_group_members_valid(const asn_TYPE_descriptor_t *td,
			 const asn_SET_specifics_t *specs) {
	unsigned i;

	if(!specs->_mandatory_elements || !specs->tag2el
	|| !specs->tag2el_count) return 0;
	for(i = 0; i < td->elements_count; i++)
		if(td->elements[i].flags & ATF_EXTENSION_GROUP) return 0;
	for(i = 0; i < specs->tag2el_count; i++)
		if(specs->tag2el[i].el_no >= td->elements_count) return 0;
	return 1;
}

/*
 * Purpose: validate a parent member and its synthetic SET group descriptor.
 * Source: Compiler-emitted ATF_EXTENSION_GROUP metadata.
 * Version: 2026-10-22.
 * Parameters: member is the parent member descriptor.
 * Returns: group specifics on success, NULL for a malformed group.
 * Errors: malformed kinds, offsets, nested groups, and tag indexes are rejected.
 * Author: asn1c maintainers.
 * History: Added for flat SET extension-group runtime support.
 * Example: a SET-backed extension group returns its generated specifics.
 */
static const asn_SET_specifics_t *
_SET_group_specifics(const asn_TYPE_member_t *member) {
	const asn_TYPE_descriptor_t *td;
	const asn_SET_specifics_t *specs;

	if(!member || !(member->flags & ATF_EXTENSION_GROUP)
	|| !(member->flags & ATF_POINTER) || !member->type
	|| !member->type->op || member->type->op->kind != ASN_KIND_SET
	|| !member->type->specifics) return 0;
	td = member->type;
	specs = (const asn_SET_specifics_t *)td->specifics;
	if(!_SET_group_layout_valid(td, specs)
	|| !_SET_group_members_valid(td, specs)) return 0;
	return specs;
}

/*
 * Purpose: report the byte width of a native integer's inline storage.
 * Source: NativeInteger specifics and NativeInteger_free reset semantics.
 * Version: 2026-10-22.
 * Parameters: td is the native descriptor; size receives its storage width.
 * Returns: zero for a documented 1/2/4/8-byte width, otherwise -1.
 * Errors: malformed field widths are rejected.
 * Author: asn1c maintainers.
 * History: Added to bound inline SET members before access.
 * Example: field_width zero resolves to the legacy sizeof(long) storage.
 */
static int
_SET_native_integer_size(const asn_TYPE_descriptor_t *td, size_t *size) {
	const asn_INTEGER_specifics_t *specifics;
	int width;

	specifics = (const asn_INTEGER_specifics_t *)td->specifics;
	width = specifics ? specifics->field_width : 0;
	if(width == 0) {
		*size = sizeof(long);
		return 0;
	}
	if(width != 1 && width != 2 && width != 4 && width != 8) return -1;
	*size = (size_t)width;
	return 0;
}

/*
 * Purpose: report the byte width of a native REAL's inline storage.
 * Source: NativeReal specifics and NativeReal_free reset semantics.
 * Version: 2026-10-22.
 * Parameters: td is the native descriptor; size receives its storage width.
 * Returns: zero for float or double storage, otherwise -1.
 * Errors: malformed float_size values are rejected.
 * Author: asn1c maintainers.
 * History: Added to bound inline SET members before access.
 * Example: a descriptor without specifics resolves to sizeof(double).
 */
static int
_SET_native_real_size(const asn_TYPE_descriptor_t *td, size_t *size) {
	const asn_NativeReal_specifics_t *specifics;

	specifics = (const asn_NativeReal_specifics_t *)td->specifics;
	*size = specifics ? specifics->float_size : sizeof(double);
	return *size == sizeof(float) || *size == sizeof(double) ? 0 : -1;
}

/*
 * Purpose: Verify a decoder context lies wholly within its declared storage.
 * Source: Constructed and string specifics metadata. Version: 2026-10-30.
 * Inputs: size is the enclosing size and offset locates the parser context.
 * Returns: nonzero for a bounded context; zero for malformed metadata.
 * Errors: Overflowing offsets are rejected before subtraction. Author: maintainers.
 * History: Protects selected inline values and their cleanup paths.
 * Example: A context starting at the end of a structure is invalid.
 */
static int
_SET_context_valid(size_t size, size_t offset) {
    return offset <= size && sizeof(asn_struct_ctx_t) <= size - offset;
}

/*
 * Purpose: Validate CHOICE presence and parsing context within its storage.
 * Source: CHOICE specifics contract. Version: 2026-10-30.
 * Inputs: specs describes the generated CHOICE layout.
 * Returns: nonzero when both fields fit, otherwise zero. Errors: none.
 * Author: maintainers. History: Rejects forged inline wrapper descriptors.
 * Example: Presence stored outside struct_size is rejected.
 */
static int
_SET_choice_layout_valid(const asn_CHOICE_specifics_t *specs) {
    return specs && specs->struct_size
        && _SET_context_valid(specs->struct_size, specs->ctx_offset)
        && (specs->pres_size == sizeof(char) || specs->pres_size == sizeof(short)
            || specs->pres_size == sizeof(int))
        && specs->pres_offset <= specs->struct_size
        && specs->pres_size <= specs->struct_size - specs->pres_offset
        && (specs->pres_offset >= specs->ctx_offset + sizeof(asn_struct_ctx_t)
            || specs->ctx_offset >= specs->pres_offset + specs->pres_size);
}

/*
 * Purpose: resolve known primitive inline C storage widths without codec calls.
 * Source: Built-in runtime free callbacks and their documented C layouts.
 * Version: 2026-10-22.
 * Parameters: td is the member descriptor; size receives its storage width.
 * Returns: zero for built-in storage, otherwise -1 for unknown layouts.
 * Errors: malformed or custom primitive layouts fail closed.
 * Author: asn1c maintainers.
 * History: Added to prevent out-of-bounds inline member access.
 * Example: INTEGER uses ASN__PRIMITIVE_TYPE_t; native INTEGER uses its width.
 */
static int
_SET_primitive_inline_size(const asn_TYPE_descriptor_t *td, size_t *size) {
    /* OPEN TYPE wrappers use CHOICE storage despite their primitive operation kind. */
    if(td->op->free_struct == CHOICE_free) {
        const asn_CHOICE_specifics_t *specs = td->specifics;
        if(!td->elements || !td->elements_count || !_SET_choice_layout_valid(specs))
            return -1;
        *size = specs->struct_size;
        return *size ? 0 : -1;
    }
	if(td->op->free_struct == NativeInteger_free)
		return _SET_native_integer_size(td, size);
	if(td->op->free_struct == NativeReal_free)
		return _SET_native_real_size(td, size);
	if(td->op->free_struct == BOOLEAN_free) {
		*size = sizeof(BOOLEAN_t);
		return 0;
	}
	if(td->op->free_struct == NULL_free) {
		*size = sizeof(NULL_t);
		return 0;
	}
	if(td->op->free_struct == ASN__PRIMITIVE_TYPE_free) {
		*size = sizeof(ASN__PRIMITIVE_TYPE_t);
		return 0;
	}
	if(td->op->free_struct == OCTET_STRING_free) {
		const asn_OCTET_STRING_specifics_t *specifics =
			(const asn_OCTET_STRING_specifics_t *)td->specifics;
        size_t minimum = sizeof(OCTET_STRING_t);
        size_t context_offset = offsetof(OCTET_STRING_t, _asn_ctx);
        if(specifics && specifics->subvariant == ASN_OSUBV_ANY) {
            minimum = sizeof(ANY_t);
            context_offset = offsetof(ANY_t, _asn_ctx);
        } else if(specifics && specifics->subvariant == ASN_OSUBV_BIT) {
            minimum = sizeof(BIT_STRING_t);
            context_offset = offsetof(BIT_STRING_t, _asn_ctx);
        }
        if(specifics && specifics->ctx_offset != context_offset) return -1;
		*size = specifics ? specifics->struct_size : sizeof(OCTET_STRING_t);
        return *size >= minimum && _SET_context_valid(*size, context_offset) ? 0 : -1;
	}
	return -2;
}

/*
 * Purpose: resolve a constructed type's compiler-emitted structure width.
 * Source: Runtime operation kind and its generated specifics structure.
 * Version: 2026-10-22.
 * Parameters: td is the member descriptor; size receives the structure width.
 * Returns: zero for a matching built-in constructed operation, otherwise -1.
 * Errors: missing specifics, mismatched callbacks, or zero sizes are rejected.
 * Author: asn1c maintainers.
 * History: Added to bound inline constructed SET members.
 * Example: a SEQUENCE width comes from asn_SEQUENCE_specifics_t.struct_size.
 */
static int
_SET_constructed_inline_size(const asn_TYPE_descriptor_t *td, size_t *size) {
    size_t context_offset;
    if(td->op->kind == ASN_KIND_SEQUENCE && td->op->free_struct == SEQUENCE_free) {
        const asn_SEQUENCE_specifics_t *specs = td->specifics;
        *size = specs->struct_size;
        context_offset = specs->ctx_offset;
    } else if(td->op->kind == ASN_KIND_SET && td->op->free_struct == SET_free) {
        const asn_SET_specifics_t *specs = td->specifics;
        if(!_SET_layout_valid(td, specs)) return -1;
        *size = specs->struct_size;
        context_offset = specs->ctx_offset;
    } else if(td->op->kind == ASN_KIND_CHOICE && td->op->free_struct == CHOICE_free) {
        const asn_CHOICE_specifics_t *specs = td->specifics;
        if(!_SET_choice_layout_valid(specs)) return -1;
        *size = specs->struct_size;
        context_offset = specs->ctx_offset;
    } else if((td->op->kind == ASN_KIND_SEQUENCE_OF || td->op->kind == ASN_KIND_SET_OF)
              && td->op->free_struct == SET_OF_free) {
        const asn_SET_OF_specifics_t *specs = td->specifics;
        if(specs->struct_size < sizeof(asn_anonymous_set_)
        || specs->ctx_offset < sizeof(asn_anonymous_set_)
        || td->elements_count != 1 || !td->elements || !td->elements[0].type
        || !td->elements[0].type->op || !td->elements[0].type->op->free_struct) return -1;
        *size = specs->struct_size;
        context_offset = specs->ctx_offset;
    } else return -1;
    return *size && _SET_context_valid(*size, context_offset) ? 0 : -1;
}

/* Maximum graph nesting and distinct layouts validated during one call. */
#define SET_INLINE_VALIDATION_DEPTH 64
#define SET_INLINE_VALIDATION_TYPES 1024
#define SET_INLINE_VALIDATION_STEPS 16384

/* Descriptor graph state for bounded validation; arrays own no descriptors. */
typedef struct SET_validation_state_s {
    const asn_TYPE_descriptor_t *path[SET_INLINE_VALIDATION_DEPTH]; /* Active path. */
    uint8_t pointer_edge[SET_INLINE_VALIDATION_DEPTH]; /* Incoming edge kinds. */
    const asn_TYPE_descriptor_t *done[SET_INLINE_VALIDATION_TYPES]; /* Validated types. */
    size_t widths[SET_INLINE_VALIDATION_TYPES]; /* Width for each validated type. */
    size_t count; /* Number of cached type layouts; state variable. */
    size_t steps; /* Number of examined descriptors; state variable. */
    size_t cycles; /* Number of legal pointer cycles seen; state variable. */
} SET_validation_state_t;

/*
 * Purpose: Validate a descriptor's own fixed storage and determine its width.
 * Source: Built-in descriptor layouts. Version: 2026-10-30.
 * Inputs: td is the descriptor and size receives its storage width.
 * Returns: 0 for valid, -1 for malformed, -2 for unknown primitive.
 * Errors: Invalid arguments fail. Author: maintainers.
 * History: Shared by cycle, nested-member, and CBOR selected-arm validation.
 * Example: INTEGER uses long storage without traversing sibling descriptors.
 */
int
SET_shallow_inline_value_size(const asn_TYPE_descriptor_t *td, size_t *size) {
    if(!td || !td->op || !td->op->free_struct || !size) return -1;
    if(td->op->kind == ASN_KIND_PRIMITIVE) return _SET_primitive_inline_size(td, size);
    if(!td->specifics) return -1;
    return _SET_constructed_inline_size(td, size);
}

static int _SET_inline_value_size_checked(const asn_TYPE_descriptor_t *, size_t *,
                                          SET_validation_state_t *, size_t, int);

/*
 * Purpose: Validate a heap-backed child while allowing pointer recursion.
 * Source: Generated pointer-member and collection layouts. Version: 2026-10-30.
 * Inputs: child is the descriptor; state/depth track validation ancestry.
 * Returns: 0 for valid or unknown custom primitive, otherwise -1.
 * Errors: Malformed known layouts and excessive graphs fail. Author: maintainers.
 * History: Added for cycle-safe pointer graph traversal. Example: A linked list is valid.
 */
static int
_SET_pointer_child_valid(const asn_TYPE_descriptor_t *child,
                         SET_validation_state_t *state, size_t depth) {
    size_t unused;
    int result = _SET_inline_value_size_checked(child, &unused, state, depth, 1);
    return result == 0 || result == -2 ? 0 : -1;
}

/*
 * Purpose: Validate all member descriptors and storage slots of one value.
 * Source: SEQUENCE, SET and CHOICE layout contracts. Version: 2026-10-30.
 * Inputs: td and size describe the owner; state/depth track graph traversal.
 * Returns: zero for valid members or -1 for invalid or out-of-bounds storage.
 * Errors: Unknown inline layouts and malformed child descriptors fail.
 * Author: maintainers. History: Extracted to bound decoder-check complexity.
 * Example: A pointer field extending beyond its owner is rejected.
 */
static int
_SET_inline_members_valid(const asn_TYPE_descriptor_t *td, size_t size,
                          SET_validation_state_t *state, size_t depth) {
    size_t i;
    if(td->elements_count && !td->elements) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        size_t width;
        if(!member->type || !member->type->op || !member->type->op->free_struct)
            return -1;
        if(member->flags & ATF_POINTER) {
            width = sizeof(void *);
            if(_SET_pointer_child_valid(member->type, state, depth + 1)) return -1;
        } else if(_SET_inline_value_size_checked(member->type, &width, state, depth + 1, 0))
            return -1;
        if(member->memb_offset > size || width > size - member->memb_offset) return -1;
    }
    return 0;
}

/*
 * Purpose: Decide whether a detected descriptor cycle contains a pointer edge.
 * Source: Inline storage recursion contract. Version: 2026-10-30.
 * Inputs: state describes the active path; start/depth bound the cycle;
 * incoming_pointer describes its closing edge. Returns: nonzero when legal.
 * Errors: Callers validate indexes. Author: maintainers.
 * History: Preserves mixed pointer/inline recursion. Example: A pointer to B is legal.
 */
static int
_SET_pointer_cycle(const SET_validation_state_t *state, size_t start,
                   size_t depth, int incoming_pointer) {
    size_t i;
    if(incoming_pointer) return 1;
    for(i = start + 1; i < depth; i++) if(state->pointer_edge[i]) return 1;
    return 0;
}

/*
 * Purpose: Identify descriptors whose members occupy slots in the owner.
 * Source: Runtime operation-kind metadata. Version: 2026-10-30.
 * Inputs: td is a descriptor whose operation table has been checked.
 * Returns: nonzero for SEQUENCE, SET, CHOICE or OPEN TYPE wrappers.
 * Errors: none. Author: maintainers. History: Extracted for bounded complexity.
 * Example: A SEQUENCE OF element is separately heap allocated.
 */
static int
_SET_has_inline_members(const asn_TYPE_descriptor_t *td) {
    return td->op->kind == ASN_KIND_SEQUENCE || td->op->kind == ASN_KIND_SET
        || td->op->kind == ASN_KIND_CHOICE || td->op->free_struct == CHOICE_free;
}

/*
 * Purpose: Validate complete storage and every reachable constructed member.
 * Source: Constructed descriptor and SET member storage contracts.
 * Version: 2026-10-30. Inputs: td/size identify the descriptor and width;
 * state/depth/incoming_pointer track and bound the active descriptor graph.
 * Returns: 0 for valid storage, -1 for malformed, -2 for unknown primitive.
 * Errors: Inline-only cycles, malformed slots, and excessive graphs fail.
 * Author: asn1c maintainers. History: Added recursive child layout validation.
 * Example: A pointer crossing its enclosing SEQUENCE boundary is rejected.
 */
static int
_SET_inline_value_size_checked(const asn_TYPE_descriptor_t *td, size_t *size,
                               SET_validation_state_t *state, size_t depth,
                               int incoming_pointer) {
    size_t i, cycles_before = state->cycles;
    int status, members_inline;
    if(!td || !size || depth >= SET_INLINE_VALIDATION_DEPTH
    || state->steps++ >= SET_INLINE_VALIDATION_STEPS) return -1;
    for(i = 0; i < depth; i++) {
        if(state->path[i] == td) {
            if(!_SET_pointer_cycle(state, i, depth, incoming_pointer)) return -1;
            state->cycles++;
            return SET_shallow_inline_value_size(td, size);
        }
    }
    for(i = 0; i < state->count; i++) {
        if(state->done[i] == td) { *size = state->widths[i]; return 0; }
    }
    state->path[depth] = td;
    state->pointer_edge[depth] = incoming_pointer != 0;
    status = SET_shallow_inline_value_size(td, size);
    if(status) return status;
    members_inline = _SET_has_inline_members(td);
    if(members_inline) {
        if(_SET_inline_members_valid(td, *size, state, depth)) return -1;
    } else if((td->op->kind == ASN_KIND_SEQUENCE_OF || td->op->kind == ASN_KIND_SET_OF)
              && _SET_pointer_child_valid(td->elements[0].type, state, depth + 1)) return -1;
    /* A cycle's validity depends on its path, so do not cache that result. */
    if(state->cycles != cycles_before) return 0;
    if(state->count == SET_INLINE_VALIDATION_TYPES) return -1;
    state->done[state->count] = td;
    state->widths[state->count++] = *size;
    return 0;
}

/*
 * Purpose: Resolve a supported descriptor's complete validated storage width.
 * Source: Built-in ASN.1 descriptors. Version: 2026-10-30.
 * Inputs: td identifies the type; size receives its storage width.
 * Returns: 0 for valid, -1 for malformed, or -2 for unknown primitive layout.
 * Errors: Inline-only cycles, graphs over 1024 types, 16384 visits, or 64 levels fail.
 * Author: asn1c maintainers. History: Added bounded recursive layout checks.
 * Example: A valid generated CHOICE reports its full wrapper size.
 */
int
SET_inline_value_size(const asn_TYPE_descriptor_t *td, size_t *size) {
    SET_validation_state_t state;
    memset(&state, 0, sizeof(state));
    return _SET_inline_value_size_checked(td, size, &state, 0, 0);
}

/*
 * Purpose: verify a member's full storage span fits its owning SET layout.
 * Source: Compiler-emitted struct_size, member offsets, and runtime type layouts.
 * Version: 2026-10-22.
 * Parameters: specs describes the owner; member describes its storage slot.
 * Returns: nonzero when the complete pointer or inline value fits.
 * Errors: malformed member layouts and unknown inline primitive widths fail.
 * Author: asn1c maintainers.
 * History: Strengthened to validate complete inline values, not just start offsets.
 * Example: a native INTEGER at struct_size-1 is rejected before decoding.
 */
static int
_SET_member_offset_valid(const asn_SET_specifics_t *specs,
			 const asn_TYPE_member_t *member) {
	size_t slot_size;

	if(!specs || !member || !member->type || !member->name
	|| specs->struct_size == 0)
		return 0;
	if(member->flags & ATF_POINTER) {
		slot_size = sizeof(void *);
	} else if(SET_inline_value_size(member->type, &slot_size) != 0) {
		return 0;
	}
	return member->memb_offset <= specs->struct_size
		&& slot_size <= specs->struct_size - member->memb_offset;
}

/*
 * Purpose: validate a SET descriptor's complete direct and group storage.
 * Source: SET layout, group metadata, and member-offset validation helpers.
 * Version/date: 1.0, 2026-10-30. Input: td describes the SET.
 * Returns: zero or -1 for malformed metadata. Exceptions: none.
 * Author: asn1c maintainers. History: added for decoder preallocation checks.
 * Example: an invalid group child offset is rejected before allocation.
 */
int
SET_descriptor_valid(const asn_TYPE_descriptor_t *td) {
    const asn_SET_specifics_t *specs;
    size_t i, j;
    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics) return -1;
    specs = td->specifics;
    if(!_SET_layout_valid(td, specs)) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        const asn_SET_specifics_t *child;
        if(!_SET_member_offset_valid(specs, member)) return -1;
        if(!(member->flags & ATF_EXTENSION_GROUP)) continue;
        child = _SET_group_specifics(member);
        if(!child || !member->type->elements_count) return -1;
        for(j = 0; j < member->type->elements_count; j++) {
            if(!_SET_member_offset_valid(child, &member->type->elements[j])) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: resolve ordinary or one-level grouped SET member storage.
 * Source: Compiler-emitted SET member offsets and extension-group flags.
 * Version: 2026-10-22.
 * Parameters: td and st identify the parent; outer_index selects a member;
 *             child_index is ASN_SET_DIRECT_MEMBER or a group leaf index;
 *             view receives the const descriptor, owner, value, and presence.
 * Returns: 0 for a valid view, -1 for invalid arguments or descriptors.
 * Errors: invalid indexes and malformed extension-group metadata are rejected.
 * Author: asn1c maintainers.
 * History: Added as the shared leaf-storage interface for SET runtimes.
 * Example: SET_member_view(td, st, 2, 0, &view) selects group leaf zero.
 */
int
SET_member_view(const asn_TYPE_descriptor_t *td, const void *st,
		unsigned outer_index, unsigned child_index,
		asn_SET_member_view_t *view) {
	const asn_SET_specifics_t *specs;
	const asn_TYPE_member_t *member;
	const void *owner;

	if(!td || !st || !td->op || td->op->kind != ASN_KIND_SET
	|| !td->specifics || !td->elements || !view
	|| outer_index >= td->elements_count) return -1;
	specs = (const asn_SET_specifics_t *)td->specifics;
	if(!_SET_layout_valid(td, specs)) return -1;
	member = &td->elements[outer_index];
	if(!_SET_member_offset_valid(specs, member)) return -1;
	owner = st;
	if(member->flags & ATF_EXTENSION_GROUP) {
		const asn_SET_specifics_t *group_specs =
			_SET_group_specifics(member);
		if(!group_specs || child_index == ASN_SET_DIRECT_MEMBER
		|| child_index >= member->type->elements_count) return -1;
		owner = *(const void *const *)((const char *)st
						+ member->memb_offset);
		member = &member->type->elements[child_index];
		if(!_SET_member_offset_valid(group_specs, member)) return -1;
		specs = group_specs;
		view->owner_index = child_index;
	} else {
		if(child_index != ASN_SET_DIRECT_MEMBER) return -1;
		view->owner_index = outer_index;
	}
	view->member = member;
	view->owner = owner;
	view->owner_specs = specs;
	if(member->flags & ATF_POINTER) {
		view->value = owner ? *(const void *const *)((const char *)owner
						+ member->memb_offset) : 0;
		view->present = view->value != 0;
	} else {
		view->value = owner ? (const char *)owner + member->memb_offset : 0;
		view->present = owner != 0;
	}
	return 0;
}

/*
 * Purpose: read whether one group child is marked mandatory by its mask.
 * Source: Network-order unsigned-int words in generated SET specifics.
 * Version: 2026-10-22.
 * Parameters: specs is validated group metadata; index selects a child.
 * Returns: nonzero when the child is mandatory, zero otherwise.
 * Errors: none; callers validate the descriptor and index first.
 * Author: asn1c maintainers.
 * History: Added for value-based group completeness checks.
 * Example: a set bit in the child's mask word returns nonzero.
 */
static int
_SET_group_member_mandatory(const asn_SET_specifics_t *specs,
			    size_t index) {
	unsigned bits = 8 * sizeof(unsigned int);
	unsigned word = (unsigned)(index / bits);
	unsigned mask = 1u << (bits - 1 - (index % bits));
	unsigned int raw;

	memcpy(&raw, (const uint8_t *)specs->_mandatory_elements
		+ word * sizeof(raw), sizeof(raw));
	return (sys_ntohl(raw) & mask) != 0;
}

/*
 * Purpose: report whether one required group child has a stored value.
 * Source: SET member layout and mandatory mask.
 * Version: 2026-10-22.
 * Parameters: specs/st describe group storage; td/index select the child.
 * Returns: 1 present or optional, 0 missing mandatory pointer, -1 malformed.
 * Errors: invalid offsets and nested group descriptors return -1.
 * Author: asn1c maintainers.
 * History: Split leaf validation from group traversal.
 * Example: a missing mandatory pointer produces zero.
 */
static int
_SET_group_member_present(const asn_TYPE_descriptor_t *td,
			  const asn_SET_specifics_t *specs, const void *st,
			  size_t index) {
	const asn_TYPE_member_t *member = &td->elements[index];
	if(!_SET_member_offset_valid(specs, member)
	|| (member->flags & ATF_EXTENSION_GROUP)) return -1;
	if(!_SET_group_member_mandatory(specs, index)
	|| !(member->flags & ATF_POINTER)) return 1;
	return *(const void *const *)((const char *)st + member->memb_offset)
		? 1 : 0;
}

/*
 * Purpose: check a synthetic extension group's mandatory leaf values.
 * Source: SET mandatory masks and generated member storage layout.
 * Version: 2026-10-22.
 * Parameters: td is a one-level group SET descriptor; st is its value.
 * Returns: 1 when required values exist, 0 when one is absent, -1 if malformed.
 * Errors: a missing mandatory pointer is incomplete, not malformed.
 * Author: asn1c maintainers.
 * History: Added for value-based DER and CER group validation.
 * Example: a null mandatory leaf pointer returns zero.
 */
int
SET_group_is_populated(const asn_TYPE_descriptor_t *td, const void *st) {
	const asn_SET_specifics_t *specs;
	size_t i;
	int present;

	if(!td || !st || !td->op || td->op->kind != ASN_KIND_SET
	|| !td->specifics || !td->elements) return -1;
	specs = (const asn_SET_specifics_t *)td->specifics;
	if(!_SET_group_layout_valid(td, specs)
	|| !_SET_group_members_valid(td, specs)) return -1;
	for(i = 0; i < td->elements_count; i++) {
		present = _SET_group_member_present(td, specs, st, i);
		if(present != 1) return present;
	}
	return 1;
}

/*
 * Purpose: validate the versioned SET partition metadata prefix safely.
 * Source: SET v2/v3 layout and legacy ABI boundary.
 * Version/date: 1.0, 2026-10-30. Input: specs identifies SET metadata.
 * Returns: 1 for a valid v2 or v3 prefix, 0 for unsupported metadata.
 * Errors: unsupported sentinels and short metadata fail without reading v3.
 * Author: asn1c maintainers. History: added for versioned group adapters.
 * Example: a v2 object need only cover the fields preceding v3 extensions.
 */
int
SET_version_valid(const asn_SET_specifics_t *specs) {
    if(!specs) return 0;
    if(specs->extensible == 2)
        return specs->specifics_size >= offsetof(asn_SET_specifics_t, extension_groups)
            && specs->specifics_version == ASN_SET_SPECIFICS_VERSION;
    if(specs->extensible == 3)
        return specs->specifics_size >= sizeof(*specs)
            && specs->specifics_version == ASN_SET_SPECIFICS_VERSION_3;
    return 0;
}

/*
 * Purpose: locate the unique SEQUENCE layout assigned to a SET group.
 * Source: Generated SET v3 extension-group table.
 * Version/date: 1.0, 2026-10-30. Inputs: parent and member index.
 * Returns: matching layout, or NULL when absent or duplicated.
 * Errors: missing and duplicate entries fail closed.
 * Author: asn1c maintainers. History: split from adapter validation.
 * Example: a duplicated member index never selects an arbitrary layout.
 */
static const asn_SEQUENCE_specifics_t *
_SET_group_find_sequence(const asn_SET_specifics_t *parent, unsigned index) {
    const asn_SEQUENCE_specifics_t *sequence = 0;
    unsigned i, count = 0;
    for(i = 0; i < parent->extension_group_count; i++) {
        if(parent->extension_groups[i].member_index == index) {
            sequence = parent->extension_groups[i].sequence_specifics;
            count++;
        }
    }
    return count == 1 ? sequence : 0;
}

/*
 * Purpose: validate the group SEQUENCE layout and declaration-order map.
 * Source: Generated group child and SEQUENCE optional-member metadata.
 * Version/date: 1.0, 2026-10-30. Inputs: member/child/sequence describe a group.
 * Returns: zero for a compatible layout or -1 for invalid metadata.
 * Errors: unsupported children, offsets, and optional indexes are rejected.
 * Author: asn1c maintainers. History: split from adapter validation.
 * Example: the optional map must enumerate optional children in order.
 */
static int
_SET_group_sequence_valid(const asn_TYPE_member_t *member, const asn_SET_specifics_t *child,
                          const asn_SEQUENCE_specifics_t *sequence) {
    unsigned i, optional = 0;
    if(!sequence || sequence->struct_size != child->struct_size
    || sequence->ctx_offset != child->ctx_offset || sequence->first_extension != -1
    || sequence->aoms_count || sequence->roms_count > member->type->elements_count
    || (sequence->roms_count && !sequence->oms)) return -1;
    for(i = 0; i < member->type->elements_count; i++) {
        if(!_SET_member_offset_valid(child, &member->type->elements[i])
        || (member->type->elements[i].flags & ATF_OPEN_TYPE)) return -1;
        if(member->type->elements[i].optional) {
            if(optional >= sequence->roms_count || sequence->oms[optional] != (int)i) return -1;
            optional++;
        }
    }
    return optional == sequence->roms_count ? 0 : -1;
}

/*
 * Purpose: locate and validate a generated SEQUENCE view of one SET group.
 * Source: SET v3 group metadata and the SEQUENCE descriptor contract.
 * Version/date: 1.0, 2026-10-30. Inputs: td/index identify an addition;
 * adapter receives the temporary descriptor. Returns: 0 or -1.
 * Errors: inconsistent group layout or optional maps are rejected.
 * Author: asn1c maintainers. History: added for SET extension-group codecs.
 * Example: a group adapter shares the child elements and storage offsets.
 */
int
SET_group_adapter(const asn_TYPE_descriptor_t *td, unsigned index,
                  asn_TYPE_descriptor_t *adapter) {
    const asn_SET_specifics_t *parent, *child;
    const asn_SEQUENCE_specifics_t *sequence;
    const asn_TYPE_member_t *member;

    if(!td || !td->specifics || !td->elements || !adapter || index >= td->elements_count) return -1;
    parent = (const asn_SET_specifics_t *)td->specifics;
    if(parent->extensible != 3 || !SET_version_valid(parent)
    || !parent->extension_groups || !parent->extension_group_count
    || parent->extension_group_count > parent->extension_count) return -1;
    member = &td->elements[index];
    if(!_SET_layout_valid(td, parent) || !_SET_member_offset_valid(parent, member)) return -1;
    child = _SET_group_specifics(member);
    if(!child || !member->type->op->free_struct) return -1;
    sequence = _SET_group_find_sequence(parent, index);
    if(_SET_group_sequence_valid(member, child, sequence)) return -1;
    *adapter = *member->type;
    adapter->op = &asn_OP_SEQUENCE;
    adapter->specifics = sequence;
    return 0;
}

/*
 * Purpose: validate the bounds and pointers of a v3 SET group partition.
 * Source: Compiler-emitted SET v3 metadata fields.
 * Version/date: 1.0, 2026-10-30. Inputs: td and specs identify the descriptor.
 * Returns: zero for usable partition bounds, otherwise -1.
 * Errors: incomplete or inconsistent metadata is rejected.
 * Author: asn1c maintainers. History: split from group table validation.
 * Example: a nonzero root count requires a root map.
 */
static int
_SET_group_partition_bounds(const asn_TYPE_descriptor_t *td, const asn_SET_specifics_t *specs) {
    if(!SET_version_valid(specs) || !specs->extension_groups || !specs->extension_group_count
    || specs->root_count > td->elements_count
    || specs->extension_count != td->elements_count - specs->root_count
    || (specs->root_count && !specs->root_map)
    || (specs->extension_count && !specs->extension_map)) return -1;
    return 0;
}

/*
 * Purpose: verify the v3 adapter table exactly covers extension groups.
 * Source: SET v3 metadata and the generated extension partition.
 * Version/date: 1.0, 2026-10-30. Input: td identifies a SET descriptor.
 * Returns: 0 for valid metadata, -1 for missing or misplaced groups.
 * Errors: malformed metadata fails before codec dispatch.
 * Author: asn1c maintainers. History: added for SET extension-group codecs.
 * Example: a group in the root partition is rejected.
 */
int
SET_group_metadata_valid(const asn_TYPE_descriptor_t *td) {
    const asn_SET_specifics_t *specs;
    unsigned i, groups = 0;
    asn_TYPE_descriptor_t adapter;

    if(!td || !td->specifics || (td->elements_count && !td->elements)) return -1;
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(specs->extensible != 3) return 0;
    if(_SET_group_partition_bounds(td, specs)) return -1;
    for(i = 0; i < specs->root_count; i++) {
        if(specs->root_map[i] >= td->elements_count
        || (td->elements[specs->root_map[i]].flags & ATF_EXTENSION_GROUP)) return -1;
    }
    for(i = 0; i < specs->extension_count; i++) {
        unsigned index = specs->extension_map[i];
        if(index >= td->elements_count) return -1;
        if(td->elements[index].flags & ATF_EXTENSION_GROUP) {
            if(SET_group_adapter(td, index, &adapter)) return -1;
            groups++;
        }
    }
    return groups == specs->extension_group_count ? 0 : -1;
}

/*
 * Purpose: determine whether an extension group contributes a wire addition.
 * Source: X.691 19.9, X.696 16.5.3 and SET group storage conventions.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st/index identify a group.
 * Returns: 1 if encoded, 0 if absent, or -1 for invalid or incomplete data.
 * Errors: invalid storage or missing mandatory pointer leaves fail.
 * Author: asn1c maintainers. History: added for grouped SET codec support.
 * Example: an allocated all-optional group with no values is omitted.
 */
int
SET_group_wire_present(const asn_TYPE_descriptor_t *td, const void *st, unsigned index) {
    const asn_TYPE_member_t *group;
    const void *value;
    asn_TYPE_descriptor_t adapter;
    unsigned i;
    int any = 0;

    if(!td || !td->elements || index >= td->elements_count || !st
    || SET_group_adapter(td, index, &adapter)) return -1;
    group = &td->elements[index];
    value = *(const void *const *)((const char *)st + group->memb_offset);
    if(!value) return 0;
    if(SET_group_is_populated(group->type, value) != 1) return -1;
    for(i = 0; i < group->type->elements_count; i++) {
        asn_SET_member_view_t view;
        if(SET_member_view(td, st, index, i, &view)) return -1;
        if(view.present && (!view.member->default_value_cmp
           || view.member->default_value_cmp(view.value))) any = 1;
    }
    return any;
}

/*
 * Purpose: discard SEQUENCE decoder state before returning to SET ownership.
 * Source: SEQUENCE OER context ownership and synthetic SET group layout.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st identify temporary group data.
 * Returns: 0 on success, -1 on invalid group layout.
 * Errors: invalid context offsets are rejected before accessing storage.
 * Author: asn1c maintainers. History: prevents retained preamble leaks.
 * Example: OER group decoding releases its SEQUENCE phase-10 bitmap.
 */
int
SET_group_clear_wire_context(const asn_TYPE_descriptor_t *td, void *st) {
    const asn_SET_specifics_t *specs;
    asn_struct_ctx_t *ctx;

    if(!td || !td->specifics || !st) return -1;
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(!_SET_group_layout_valid(td, specs)) return -1;
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);
    FREEMEM(ctx->ptr);
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

/*
 * Purpose: rebuild SET presence bits after decoding the SEQUENCE wire view.
 * Source: SET child descriptor and generated presence bitmap convention.
 * Version/date: 1.0, 2026-10-30. Inputs: td/st identify a decoded group.
 * Returns: 0 on success or -1 if its layout is invalid or incomplete.
 * Errors: malformed storage or missing required pointer leaves fail.
 * Author: asn1c maintainers. History: maintains BER/XER compatibility.
 * Example: a decoded mandatory inline member gets its presence bit set.
 */
int
SET_group_mark_present(const asn_TYPE_descriptor_t *td, void *st) {
    const asn_SET_specifics_t *specs;
    unsigned i;

    if(SET_group_is_populated(td, st) != 1) return -1;
    specs = (const asn_SET_specifics_t *)td->specifics;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        if(!(member->flags & ATF_POINTER)
        || *(void **)((char *)st + member->memb_offset))
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, i);
    }
    return 0;
}

/*
 * Purpose: test whether a SET presence bitmap includes mandatory members.
 * Source: The SET descriptor's network-order mandatory bit mask.
 * Version: 2026-10-22.
 * Parameters: td is the SET descriptor; st is its decoded value.
 * Returns: 1 when complete, 0 when mandatory members are absent or invalid.
 * Errors: malformed descriptor storage is treated as incomplete.
 * Author: asn1c maintainers.
 * History: Added to share presence validation with transparent groups.
 * Example: a decoded SET lacking a required bit returns zero.
 */
static int
_SET_presence_populated(const asn_TYPE_descriptor_t *td, const void *st) {
	const asn_SET_specifics_t *specs =
		(const asn_SET_specifics_t *)td->specifics;
	size_t edx;
	size_t words;
	size_t presence_bytes;

	if((size_t)td->elements_count > SIZE_MAX
		- (8 * sizeof(unsigned int) - 1)) return 0;
	words = ((size_t)td->elements_count + 8 * sizeof(unsigned int) - 1)
		/ (8 * sizeof(unsigned int));
	if(words > SIZE_MAX / sizeof(unsigned int)) return 0;
	presence_bytes = words * sizeof(unsigned int);
	if(presence_bytes > specs->struct_size
	|| specs->pres_offset > specs->struct_size - presence_bytes
	|| (td->elements_count && !specs->_mandatory_elements)) return 0;
	for(edx = 0; edx < td->elements_count;
		edx += 8 * sizeof(specs->_mandatory_elements[0])) {
		unsigned index = (unsigned)(edx / (8 * sizeof(unsigned int)));
		unsigned int present;
		unsigned int mandatory;
		memcpy(&present, (const char *)st + specs->pres_offset
			+ index * sizeof(present), sizeof(present));
		memcpy(&mandatory, (const uint8_t *)specs->_mandatory_elements
			+ index * sizeof(mandatory), sizeof(mandatory));
		mandatory = sys_ntohl(mandatory);
		if((present & mandatory) != mandatory) return 0;
	}
	return 1;
}

int
_SET_is_populated(const asn_TYPE_descriptor_t *td, const void *st) {
	const asn_SET_specifics_t *specs;
	size_t edx;

	if(!td || !st || !td->specifics || (td->elements_count && !td->elements))
		return 0;
	specs = (const asn_SET_specifics_t *)td->specifics;
	if(!_SET_presence_populated(td, st)) return 0;
	for(edx = 0; edx < td->elements_count; edx++) {
		const asn_TYPE_member_t *member = &td->elements[edx];
		const asn_SET_specifics_t *group_specs;
		const void *group_st;
		if(!(member->flags & ATF_EXTENSION_GROUP)) continue;
		if(!_SET_member_offset_valid(specs, member)) return 0;
		group_specs = _SET_group_specifics(member);
		if(!group_specs) return 0;
		group_st = *(const void *const *)((const char *)st
						+ member->memb_offset);
		if(group_st
		&& !_SET_presence_populated(member->type, group_st)) return 0;
	}

	return 1;
}

void
SET_free(const asn_TYPE_descriptor_t *td, void *ptr,
         enum asn_struct_free_method method) {
    size_t edx;
    const asn_SET_specifics_t *specs;

	if(!td || !ptr)
		return;

	ASN_DEBUG("Freeing %s as SET", td->name);

    /* OER member and extension phases own ctx->ptr; other codecs may borrow it. */
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(specs && specs->ctx_offset <= specs->struct_size
    && sizeof(asn_struct_ctx_t) <= specs->struct_size - specs->ctx_offset) {
        asn_struct_ctx_t *ctx = (asn_struct_ctx_t *)((char *)ptr + specs->ctx_offset);
        if(ctx->phase == ASN_SET_OER_PHASE_MEMBERS
        || ctx->phase == ASN_SET_OER_PHASE_EXTENSION_MAP
        || ctx->phase == ASN_SET_OER_PHASE_EXTENSIONS) {
#ifndef ASN_DISABLE_OER_SUPPORT
            SET_oer_free_member_context(ctx);
#endif
        }
    }

	for(edx = 0; edx < td->elements_count; edx++) {
		asn_TYPE_member_t *elm = &td->elements[edx];
		void *memb_ptr;
		if(elm->flags & ATF_POINTER) {
			memb_ptr = *(void **)((char *)ptr + elm->memb_offset);
			if(memb_ptr)
				ASN_STRUCT_FREE(*elm->type, memb_ptr);
		} else {
			memb_ptr = (void *)((char *)ptr + elm->memb_offset);
			ASN_STRUCT_FREE_CONTENTS_ONLY(*elm->type, memb_ptr);
		}
	}

    switch(method) {
    case ASFM_FREE_EVERYTHING:
        FREEMEM(ptr);
        break;
    case ASFM_FREE_UNDERLYING:
        break;
    case ASFM_FREE_UNDERLYING_AND_RESET:
        memset(ptr, 0,
               ((const asn_SET_specifics_t *)(td->specifics))->struct_size);
        break;
    }
}

/*
 * Purpose: check every present SET member and reject missing mandatory members.
 * Source: SEQUENCE_constraint and generated SET member descriptors.
 * Version/date: 1.1, 2026-10-30. Inputs: td/sptr identify the SET;
 * ctfailcb/app_key receive constraint errors. Returns: zero or child failure.
 * Exceptions: none. Author: asn1c maintainers. History: check all members.
 * Example: a failing second member rejects the complete SET.
 */
int
SET_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
               asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    size_t edx;

	if(!td || (td->elements_count && !td->elements)) return -1;

	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}

	/*
	 * Iterate over structure members and check their validity.
	 */
	for(edx = 0; edx < td->elements_count; edx++) {
		asn_TYPE_member_t *elm = &td->elements[edx];
		const void *memb_ptr;
		asn_constr_check_f *constr;
		int ret;

		if(!elm->type || !elm->name) return -1;

		if(elm->flags & ATF_POINTER) {
			memb_ptr = *(const void * const *)((const char *)sptr + elm->memb_offset);
			if(!memb_ptr) {
				if(elm->optional)
					continue;
				ASN__CTFAIL(app_key, td, sptr,
				"%s: mandatory element %s absent (%s:%d)",
				td->name, elm->name, __FILE__, __LINE__);
				return -1;
			}
		} else {
			memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
		}

		/* A successful child does not exempt later members from validation. */
		constr = elm->encoding_constraints.general_constraints;
		if(!constr) constr = elm->type->encoding_constraints.general_constraints;
		if(!constr) return -1;
		ret = constr(elm->type, memb_ptr, ctfailcb, app_key);
		if(ret) return ret;
	}

	return 0;
}

int
SET_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
            const void *bptr) {
    size_t edx;

	for(edx = 0; edx < td->elements_count; edx++) {
		asn_TYPE_member_t *elm = &td->elements[edx];
		const void *amemb;
		const void *bmemb;
		int ret;

		if(elm->flags & ATF_POINTER) {
            amemb =
                *(const void *const *)((const char *)aptr + elm->memb_offset);
            bmemb =
                *(const void *const *)((const char *)bptr + elm->memb_offset);
            if(!amemb) {
                if(!bmemb) continue;
                return -1;
            } else if(!bmemb) {
                return 1;
            }
		} else {
            amemb = (const void *)((const char *)aptr + elm->memb_offset);
            bmemb = (const void *)((const char *)bptr + elm->memb_offset);
		}

        ret = elm->type->op->compare_struct(elm->type, amemb, bmemb);
        if(ret != 0) return ret;
    }

    return 0;
}

int
SET_copy(const asn_TYPE_descriptor_t *td, void **aptr,
         const void *bptr) {
    if(!td) return -1;

    const asn_SET_specifics_t *specs =
        (const asn_SET_specifics_t *)td->specifics;
    size_t edx;
    void *st = *aptr;        /* Target structure */

    if(!bptr) {
        if(st) {
            SET_free(td, st, ASFM_FREE_EVERYTHING);
            *aptr = 0;
        }
        return 0;
    }

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *aptr = CALLOC(1, specs->struct_size);
        if(st == 0) return -1;
    }

	for(edx = 0; edx < td->elements_count; edx++) {
		asn_TYPE_member_t *elm = &td->elements[edx];
		void *amemb;
		void **amembp;
		const void *bmemb;
        int ret;

        if(elm->flags & ATF_POINTER) {
            /* Member is a pointer to another structure */
            amembp = (void **)((char *)st + elm->memb_offset);
            bmemb = *(const void* const*)((const char*)bptr + elm->memb_offset);
        } else {
            amemb = (char *)st + elm->memb_offset;
            amembp = &amemb;
            bmemb = (const void*)((const char*)bptr + elm->memb_offset);
        }

        ret = elm->type->op->copy_struct(elm->type, amembp, bmemb);
        if(ret != 0) return ret;
    }

    return 0;
}
