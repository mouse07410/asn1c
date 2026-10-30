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
    SEQUENCE_encode_jer,
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
	return presence_bytes <= specs->struct_size - specs->pres_offset;
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
		*size = specifics ? specifics->struct_size : sizeof(OCTET_STRING_t);
		return *size >= sizeof(OCTET_STRING_t) ? 0 : -1;
	}
	return -1;
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
	if(td->op->kind == ASN_KIND_SEQUENCE && td->op->free_struct == SEQUENCE_free)
		*size = ((const asn_SEQUENCE_specifics_t *)td->specifics)->struct_size;
	else if(td->op->kind == ASN_KIND_SET && td->op->free_struct == SET_free)
		*size = ((const asn_SET_specifics_t *)td->specifics)->struct_size;
	else if(td->op->kind == ASN_KIND_CHOICE && td->op->free_struct == CHOICE_free)
		*size = ((const asn_CHOICE_specifics_t *)td->specifics)->struct_size;
	else if(td->op->kind == ASN_KIND_SEQUENCE_OF
		&& td->op->free_struct == SET_OF_free)
		*size = ((const asn_SET_OF_specifics_t *)td->specifics)->struct_size;
	else if(td->op->kind == ASN_KIND_SET_OF && td->op->free_struct == SET_OF_free)
		*size = ((const asn_SET_OF_specifics_t *)td->specifics)->struct_size;
	else
		return -1;
	return *size ? 0 : -1;
}

/*
 * Purpose: resolve the known byte width required for an inline member value.
 * Source: Runtime callback identities and generated constructed specifics.
 * Version: 2026-10-22.
 * Parameters: td is the member descriptor; size receives its storage width.
 * Returns: zero for known layouts, otherwise -1 for unsupported layouts.
 * Errors: custom primitive and malformed descriptors are rejected.
 * Author: asn1c maintainers.
 * History: Added to validate complete inline slots before pointer arithmetic.
 * Example: SET_member_view rejects a primitive whose storage exceeds its owner.
 */
static int
_SET_inline_value_size(const asn_TYPE_descriptor_t *td, size_t *size) {
	if(!td || !td->op || !td->op->free_struct || !size)
		return -1;
	if(td->op->kind == ASN_KIND_PRIMITIVE)
		return _SET_primitive_inline_size(td, size);
	if(!td->specifics) return -1;
	return _SET_constructed_inline_size(td, size);
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
	} else if(_SET_inline_value_size(member->type, &slot_size) != 0) {
		return 0;
	}
	return member->memb_offset <= specs->struct_size
		&& slot_size <= specs->struct_size - member->memb_offset;
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

    /* Only the OER member phase owns ctx->ptr; XER may store a borrowed
     * descriptor there in other phases. Release interrupted OER preambles. */
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(specs && specs->ctx_offset <= specs->struct_size
    && sizeof(asn_struct_ctx_t) <= specs->struct_size - specs->ctx_offset) {
        asn_struct_ctx_t *ctx = (asn_struct_ctx_t *)((char *)ptr + specs->ctx_offset);
        if(ctx->phase == ASN_SET_OER_PHASE_MEMBERS) {
            FREEMEM(ctx->ptr);
            ctx->ptr = 0;
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

int
SET_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
               asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    size_t edx;

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

		if(elm->encoding_constraints.general_constraints) {
			return elm->encoding_constraints.general_constraints(
					elm->type, memb_ptr, ctfailcb, app_key);
		} else {
			return elm->type->encoding_constraints.general_constraints(
					elm->type, memb_ptr, ctfailcb, app_key);
		}
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
