/*
 * UPER codec for ASN.1 SET values.
 *
 * Kept separate from constr_SET.c to match this fork's split skeleton
 * layout. The implementation is adapted from vlm/asn1c PR #543.
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <uper_opentype.h>

#ifndef ASN_DISABLE_UPER_SUPPORT

/*
 * X.691 (#20): the UPER encoding of a SET is the same as that of a
 * SEQUENCE, except that the root components are transmitted in the
 * canonical order of their tags (X.680 #8.6), not in the declaration
 * order. The CXER map excludes CHOICE extension alternatives, whose tags
 * must not affect the root component order. Generated descriptors alias it
 * to tag2el when the two maps are identical.
 *
 * Purpose: fill corder with every SET member in canonical root tag order.
 * Original source: SET UPER codec adapted from vlm/asn1c PR #543; the CXER
 * map selection follows the generated root-only CHOICE tag map.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * Inputs: td describes members; specs supplies sorted tag maps; corder has
 * room for td->elements_count unsigned indices.
 * Returns: zero on success, -1 on an incomplete or malformed map.
 * Exceptions: none. History: reject CHOICE extension tags in SET ordering.
 * Example: for tags [2], CHOICE root [3] and extension [1], returns [0, 1].
 */
static int
SET__canonical_order(const asn_TYPE_descriptor_t *td,
                     const asn_SET_specifics_t *specs, unsigned *corder) {
    const asn_TYPE_tag2member_t *map = specs->tag2el_cxer;
    unsigned count = specs->tag2el_cxer_count;
    unsigned i;
    unsigned n = 0;
    unsigned expected = specs->extensible == 2 ? specs->root_count : td->elements_count;

    if(!map && expected) return -1;

    /* Select the lowest tag among remaining roots; the CXER map may have
     * separately sorted regions when extension markers are present. */
    while(n < expected) {
        unsigned best = td->elements_count;
        ber_tlv_tag_t best_tag = 0;
        for(i = 0; i < count; i++) {
            unsigned el_no = map[i].el_no;
            unsigned j;
            ber_tlv_tag_t tag = map[i].el_tag;
            if(el_no >= td->elements_count) return -1;
            if(specs->extensible == 2) {
                for(j = 0; j < specs->root_count; j++)
                    if(specs->root_map[j] == el_no) break;
                if(j == specs->root_count) continue;
            }
            for(j = 0; j < n; j++) if(corder[j] == el_no) break;
            if(j != n) continue;
            if(best == td->elements_count || (tag & 3) < (best_tag & 3)
               || ((tag & 3) == (best_tag & 3) && (tag >> 2) < (best_tag >> 2))) {
                best = el_no;
                best_tag = tag;
            }
        }
        if(best == td->elements_count) return -1;
        corder[n++] = best;
    }

    return (n == expected) ? 0 : -1;
}

/*
 * Purpose: validate the v2 partition before any indexed access.
 * Source: generated SET v2 metadata. Version: 2026-10-30.
 * Inputs: td and specs describe the SET. Returns: 0 if valid, otherwise -1.
 * Errors: none. Author: asn1c maintainers. History: initial v2 validation.
 * Example: duplicate or out-of-range component indices fail.
 */
static int
SET__uper_base_layout(const asn_TYPE_descriptor_t *td, const asn_SET_specifics_t *specs) {
    if(!td || !specs || (td->elements_count && !td->elements)) return -1;
    if(!specs->struct_size || specs->pres_offset > specs->struct_size
       || td->elements_count / (8 * sizeof(unsigned))
          + (td->elements_count % (8 * sizeof(unsigned)) != 0)
          > (specs->struct_size - specs->pres_offset) / sizeof(unsigned)
       || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset) return -1;
    return 0;
}

/*
 * Purpose: verify every root and addition index occurs exactly once.
 * Source: v2 SET maps. Version: 2026-10-30.
 * Inputs: td and specs provide validated maps. Returns: 0 or -1.
 * Errors: invalid entries fail. Author: asn1c maintainers.
 * History: split partition traversal. Example: duplicate indexes fail.
 */
static int
SET__uper_partition(const asn_TYPE_descriptor_t *td, const asn_SET_specifics_t *specs) {
    unsigned i, j, total;
    total = specs->root_count + specs->extension_count;
    for(i = 0; i < total; i++) {
        unsigned idx = i < specs->root_count ? specs->root_map[i] : specs->extension_map[i - specs->root_count];
        if(idx >= td->elements_count) return -1;
        if(!td->elements[idx].type || !td->elements[idx].type->op) return -1;
        if(td->elements[idx].flags & ATF_EXTENSION_GROUP) return -1;
        if(i >= specs->root_count && !(td->elements[idx].flags & ATF_POINTER)) return -1;
        for(j = 0; j < i; j++) {
            unsigned prev = j < specs->root_count ? specs->root_map[j] : specs->extension_map[j - specs->root_count];
            if(idx == prev) return -1;
        }
    }
    return 0;
}

/*
 * Purpose: validate the versioned component partition. Source: v2 metadata.
 * Version: 2026-10-30. Inputs: td/specs identify the descriptor.
 * Returns: 0 or -1. Errors: none. Author: asn1c maintainers.
 * History: split basic bounds from map checks. Example: duplicate indexes fail.
 */
static int
SET__uper_layout(const asn_TYPE_descriptor_t *td, const asn_SET_specifics_t *specs) {
    if(SET__uper_base_layout(td, specs)) return -1;
    if(specs->extensible == 0) return 0;
    if(specs->extensible != 2 || specs->specifics_size < sizeof(*specs)
       || specs->specifics_version != 2) return -1;
    if(specs->root_count > td->elements_count || specs->extension_count > td->elements_count
       || specs->root_count != td->elements_count - specs->extension_count) return -1;
    if((specs->root_count && !specs->root_map) || (specs->extension_count && !specs->extension_map)) return -1;
    return SET__uper_partition(td, specs);
}

/*
 * Purpose: validate v2 storage before reading or writing any member.
 * Source: SET member view validation. Version: 2026-10-30.
 * Inputs: td and st describe the SET. Returns: 0 or -1 for invalid metadata.
 * Errors: none. Author: asn1c maintainers. History: initial v2 validation.
 * Example: an out-of-bounds member offset fails before codec dispatch.
 */
static int
SET__uper_storage(const asn_TYPE_descriptor_t *td, const void *st) {
    unsigned i;
    for(i = 0; i < td->elements_count; i++) {
        asn_SET_member_view_t view;
        if(SET_member_view(td, st, i, ASN_SET_DIRECT_MEMBER, &view)) return -1;
    }
    return 0;
}

/*
 * Purpose: encode or decode one addition as a PER open type.
 * Source: X.691 extension additions. Version: 2026-10-30.
 * Inputs: td/st/idx identify storage; ctx/pd decode or po encodes.
 * Returns: 0 on success, -1 on malformed input or codec failure.
 * Errors: none. Author: asn1c maintainers. History: initial v2 support.
 * Example: an individual addition is passed to its open-type codec.
 */
static int
SET__uper_addition(const asn_TYPE_descriptor_t *td, void *st, unsigned idx,
                   const asn_codec_ctx_t *ctx, asn_per_data_t *pd, asn_per_outp_t *po) {
    asn_TYPE_member_t *member = &td->elements[idx];
    const asn_TYPE_descriptor_t *type = member->type;
    asn_SET_member_view_t view;
    void *inline_value, **slot;
    int result;
    if(SET_member_view(td, st, idx, ASN_SET_DIRECT_MEMBER, &view)) return -1;
    if(member->flags & ATF_POINTER) slot = (void **)((char *)st + member->memb_offset);
    else { inline_value = (char *)st + member->memb_offset; slot = &inline_value; }
    if(!type || !type->op || (po && (!type->op->uper_encoder || !*slot)) || (pd && !type->op->uper_decoder)) {
        return -1;
    }
    if(po) result = uper_open_type_put(type, member->encoding_constraints.per_constraints, *slot, po);
    else {
        asn_dec_rval_t rv = uper_open_type_get(ctx, type, member->encoding_constraints.per_constraints, slot, pd);
        result = rv.code == RC_OK ? 0 : (rv.code == RC_WMORE ? -2 : -1);
        if(!result) {
            const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, idx);
        }
    }
    return result;
}

/*
 * Purpose: determine whether an addition is encoded after validating storage.
 * Source: SET member and extension-group metadata. Version: 2026-10-30.
 * Inputs: td/st describe the value, idx selects an addition.
 * Returns: one if present, zero if absent, or -1 for invalid metadata.
 * Errors: none. Author: asn1c maintainers. History: initial v2 support.
 * Example: an absent pointer or default-valued addition is omitted.
 */
static int
SET__uper_present(const asn_TYPE_descriptor_t *td, const void *st, unsigned idx) {
    const asn_TYPE_member_t *elm = &td->elements[idx];
    asn_SET_member_view_t view;
    if(SET_member_view(td, st, idx, ASN_SET_DIRECT_MEMBER, &view)) return -1;
    return view.present && (!elm->default_value_cmp || elm->default_value_cmp(view.value));
}

/*
 * Purpose: encode the addition bitmap and open types. Source: X.691.
 * Version: 2026-10-30. Inputs: td/st describe the value, po is output.
 * Returns: 0 or -1. Errors: codec and output errors fail.
 * Author: asn1c maintainers. History: split encoding from decoding.
 * Example: two present additions produce two open types.
 */
static int
SET__uper_extensions_put(const asn_TYPE_descriptor_t *td, void *st, asn_per_outp_t *po) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    unsigned i;
    if(!specs->extension_count || uper_put_nslength(po, specs->extension_count)) return -1;
    for(i = 0; i < specs->extension_count; i++) {
        int present = SET__uper_present(td, st, specs->extension_map[i]);
        if(present < 0 || per_put_few_bits(po, present, 1)) return -1;
    }
    for(i = 0; i < specs->extension_count; i++) {
        int present = SET__uper_present(td, st, specs->extension_map[i]);
        if(present < 0 || (present && SET__uper_addition(td, st, specs->extension_map[i], 0, 0, po)))
            return -1;
    }
    return 0;
}

/*
 * Purpose: process an extension bitmap and its open types.
 * Source: X.691 extension addition encoding. Version: 2026-10-30.
 * Inputs: td/st describe the value; ctx/pd decode or po encodes.
 * Returns: 0 on success, -1 on failure, or -2 on truncated input.
 * Errors: none. Author: asn1c maintainers. History: initial v2 support.
 * Example: unknown set bits each consume one open type.
 */
static int
SET__uper_extensions(const asn_TYPE_descriptor_t *td, void *st, const asn_codec_ctx_t *ctx,
                     asn_per_data_t *pd, asn_per_outp_t *po) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    ssize_t bits;
    unsigned i;
    uint8_t *bitmap;
    asn_per_data_t map;
    int any = 0;
    if(po) return SET__uper_extensions_put(td, st, po);
    bits = uper_get_nslength(pd);
    if(bits < 0) return -2;
    if(bits == 0 || bits > INT_MAX || (size_t)bits > (SIZE_MAX - 7)) return -1;
    if(!pd->refill && (pd->nboff > pd->nbits || (size_t)bits > pd->nbits - pd->nboff)) return -2;
    bitmap = MALLOC(((size_t)bits + 7) / 8);
    if(!bitmap) return -1;
    if(per_get_many_bits(pd, bitmap, 0, bits)) { FREEMEM(bitmap); return -2; }
    memset(&map, 0, sizeof(map));
    map.buffer = bitmap;
    map.nbits = bits;
    for(i = 0; i < (size_t)bits; i++) {
        int present = per_get_few_bits(&map, 1);
        int result;
        if(present < 0) { FREEMEM(bitmap); return -2; }
        if(!present) continue;
        any = 1;
        if(i < specs->extension_count) {
            result = SET__uper_addition(td, st, specs->extension_map[i], ctx, pd, 0);
        } else {
            asn_dec_rval_t rv = uper_open_type_skip_result(ctx, pd);
            result = rv.code == RC_OK ? 0 : (rv.code == RC_WMORE ? -2 : -1);
        }
        if(result) { FREEMEM(bitmap); return result; }
    }
    FREEMEM(bitmap);
    return any ? 0 : -1;
}

/*
 * Purpose: populate absent extension defaults after decoding.
 * Source: X.691 extension addition defaults. Version: 2026-10-30.
 * Inputs: td and st describe the decoded value. Returns: 0 or -1 on failure.
 * Errors: invalid member layout or default allocation failure.
 * Author: asn1c maintainers. History: initial v2 support.
 * Example: an absent pointer-backed default is allocated by its setter.
 */
static int
SET__uper_extension_defaults(const asn_TYPE_descriptor_t *td, void *st) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    unsigned i;
    for(i = 0; i < specs->extension_count; i++) {
        unsigned idx = specs->extension_map[i];
        asn_TYPE_member_t *elm = &td->elements[idx];
        asn_SET_member_view_t view;
        if(elm->flags & ATF_EXTENSION_GROUP) continue;
        if(SET_member_view(td, st, idx, ASN_SET_DIRECT_MEMBER, &view)) return -1;
        if(!view.present && elm->default_value_set && (elm->flags & ATF_POINTER)) {
            void **slot = (void **)((char *)st + elm->memb_offset);
            if(elm->default_value_set(slot)) return -1;
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, idx);
        }
    }
    return 0;
}

/*
 * Purpose: decode the ordered root components. Source: SET UPER codec.
 * Version: 2026-10-30. Inputs: ctx/td/st/order/count/map/pd describe the decode.
 * Returns: member decode status. Errors: malformed values or defaults fail.
 * Author: asn1c maintainers. History: extracted root traversal.
 * Example: absent DEFAULT members are initialized before returning.
 */
static asn_dec_rval_t
SET__uper_root_get(const asn_codec_ctx_t *ctx, const asn_TYPE_descriptor_t *td, void *st,
                   const unsigned *order, unsigned count, asn_per_data_t *map, asn_per_data_t *pd) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    asn_dec_rval_t rv;
    unsigned i;
    for(i = 0; i < count; i++) {
        unsigned idx = order[i];
        asn_TYPE_member_t *elm = &td->elements[idx];
        void *value, **slot;
        if(elm->flags & ATF_POINTER) slot = (void **)((char *)st + elm->memb_offset);
        else { value = (char *)st + elm->memb_offset; slot = &value; }
        if(elm->optional) {
            int present = per_get_few_bits(map, 1);
            if(present < 0) ASN__DECODE_FAILED;
            if(!present) {
                if(elm->default_value_set) {
                    if(elm->default_value_set(slot)) ASN__DECODE_FAILED;
                    ASN_SET_MKPRESENT((char *)st + specs->pres_offset, idx);
                }
                continue;
            }
        }
        if(!elm->type || !elm->type->op || !elm->type->op->uper_decoder) ASN__DECODE_FAILED;
        rv = elm->type->op->uper_decoder(ctx, elm->type, elm->encoding_constraints.per_constraints, slot, pd);
        if(rv.code != RC_OK) return rv;
        ASN_SET_MKPRESENT((char *)st + specs->pres_offset, idx);
    }
    rv.code = RC_OK;
    rv.consumed = 0;
    return rv;
}

/*
 * Purpose: write the ordered root optional bitmap. Source: SET UPER codec.
 * Version: 2026-10-30. Inputs: td/st/order/count describe the value; po is output.
 * Returns: zero or -1. Errors: output and member metadata errors fail.
 * Author: asn1c maintainers. History: extracted bitmap traversal.
 * Example: a DEFAULT value emits an absent bit.
 */
static int
SET__uper_root_bitmap(const asn_TYPE_descriptor_t *td, const void *st,
                      const unsigned *order, unsigned count, asn_per_outp_t *po) {
    unsigned i;
    for(i = 0; i < count; i++) {
        const asn_TYPE_member_t *elm = &td->elements[order[i]];
        const void *value;
        int present;
        if(!elm->optional) continue;
        value = (elm->flags & ATF_POINTER) ? *(const void *const *)((const char *)st + elm->memb_offset)
                                         : (const char *)st + elm->memb_offset;
        present = value && (!elm->default_value_cmp || elm->default_value_cmp(value));
        if(per_put_few_bits(po, present, 1)) return -1;
    }
    return 0;
}

/*
 * Purpose: encode ordered root values. Source: SET UPER codec.
 * Version: 2026-10-30. Inputs: td/st/order/count describe the value; po is output.
 * Returns: encoder result. Errors: missing required values or codec errors fail.
 * Author: asn1c maintainers. History: extracted root traversal.
 * Example: absent optional members emit no root payload.
 */
static asn_enc_rval_t
SET__uper_root_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                   const unsigned *order, unsigned count, asn_per_outp_t *po) {
    asn_enc_rval_t er;
    unsigned i;
    er.encoded = 0;
    for(i = 0; i < count; i++) {
        const asn_TYPE_member_t *elm = &td->elements[order[i]];
        const void *value = (elm->flags & ATF_POINTER)
            ? *(const void *const *)((const char *)sptr + elm->memb_offset) : (const char *)sptr + elm->memb_offset;
        if(!value) { if(elm->optional) continue; ASN__ENCODE_FAILED; }
        if(elm->default_value_cmp && !elm->default_value_cmp(value)) continue;
        if(!elm->type || !elm->type->op || !elm->type->op->uper_encoder) ASN__ENCODE_FAILED;
        er = elm->type->op->uper_encoder(elm->type, elm->encoding_constraints.per_constraints, value, po);
        if(er.encoded == -1) return er;
    }
    ASN__ENCODED_OK(er);
}

/*
 * Purpose: read the optional root presence bitmap. Source: SET UPER codec.
 * Version: 2026-10-30. Inputs: td/order/count/pd describe the root and input.
 * Outputs: map and allocation receive the bitmap. Returns: 0, -1 or -2 (short).
 * Errors: allocation failure and truncated input are distinguished.
 * Author: asn1c maintainers. History: extracted bitmap preparation.
 * Example: an empty bitmap needs no allocation.
 */
static int
SET__uper_root_map(const asn_TYPE_descriptor_t *td, const unsigned *order, unsigned count,
                   asn_per_data_t *pd, asn_per_data_t *map, uint8_t **allocation) {
    size_t n = 0;
    unsigned i;
    for(i = 0; i < count; i++) if(td->elements[order[i]].optional) n++;
    memset(map, 0, sizeof(*map));
    *allocation = 0;
    if(!n) return 0;
    if(n > SIZE_MAX - 7 || n > INT_MAX) return -1;
    *allocation = MALLOC(((n + 7) >> 3) + 1);
    if(!*allocation) return -1;
    if(per_get_many_bits(pd, *allocation, 0, n)) {
        FREEMEM(*allocation);
        *allocation = 0;
        return -2;
    }
    map->buffer = *allocation;
    map->nbits = n;
    return 0;
}

/*
 * Purpose: allocate the root canonical order. Source: generated tag maps.
 * Version: 2026-10-30. Inputs: td/specs describe the SET; out receives order.
 * Returns: 0 or -1. Errors: allocation or malformed tag map fails.
 * Author: asn1c maintainers. History: extracted order allocation.
 * Example: an empty SET returns a null order.
 */
static int
SET__uper_order_alloc(const asn_TYPE_descriptor_t *td, const asn_SET_specifics_t *specs, unsigned **out) {
    *out = 0;
    if(!td->elements_count) return 0;
    if((size_t)td->elements_count > SIZE_MAX / sizeof(**out)) return -1;
    *out = MALLOC(td->elements_count * sizeof(**out));
    if(!*out) return -1;
    if(SET__canonical_order(td, specs, *out)) { FREEMEM(*out); *out = 0; return -1; }
    return 0;
}

/*
 * Purpose: allocate and validate the target SET storage. Source: SET metadata.
 * Version: 2026-10-30. Inputs: td/specs/sptr describe the descriptor and target.
 * Returns: 0 or -1. Errors: allocation and malformed storage fail.
 * Author: asn1c maintainers. History: extracted target preparation.
 * Example: a null target pointer receives a zeroed SET value.
 */
static int
SET__uper_target(const asn_TYPE_descriptor_t *td, const asn_SET_specifics_t *specs, void **sptr) {
    if(!*sptr) {
        *sptr = CALLOC(1, specs->struct_size);
        if(!*sptr) return -1;
    }
    if(specs->extensible == 2 && SET__uper_storage(td, *sptr)) return -1;
    return 0;
}

/*
 * Purpose: decode a SET in UPER canonical root order and addition order.
 * Source: SET UPER codec adapted from vlm/asn1c PR #543.
 * Version: 2026-10-30. Author: asn1c maintainers.
 * Inputs: opt_codec_ctx, td, constraints, sptr and pd follow the decoder API.
 * Returns: decode status and consumed count. Errors: malformed or short input fails.
 * History: extended with versioned SET extension metadata.
 * Example: a known addition is decoded from its open type.
 */
asn_dec_rval_t
SET_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, void **sptr,
                asn_per_data_t *pd) {
    const asn_SET_specifics_t *specs = td ? (const asn_SET_specifics_t *)td->specifics : 0;
	void *st = sptr ? *sptr : 0;	/* Target structure. */
	uint8_t *opres;		/* Presence of optional root members */
	asn_per_data_t opmd;
	asn_dec_rval_t rv;
	unsigned *corder;	/* Canonical tag order of the members */
    unsigned root_count;
    int extpresent = 0;
    (void)constraints;
    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx)) ASN__DECODE_FAILED;
    if(!sptr || !pd || SET__uper_layout(td, specs)) ASN__DECODE_FAILED;
    if(SET__uper_target(td, specs, sptr)) ASN__DECODE_FAILED;
    st = *sptr;
    root_count = specs->extensible == 2 ? specs->root_count : td->elements_count;
    if(specs->extensible == 2) {
        extpresent = per_get_few_bits(pd, 1);
        if(extpresent < 0) ASN__DECODE_STARVED;
    }
    if(SET__uper_order_alloc(td, specs, &corder)) ASN__DECODE_FAILED;
    {
        int result = SET__uper_root_map(td, corder, root_count, pd, &opmd, &opres);
        if(result) {
            FREEMEM(corder);
            if(result == -2) ASN__DECODE_STARVED;
            ASN__DECODE_FAILED;
        }
    }

    rv = SET__uper_root_get(opt_codec_ctx, td, st, corder, root_count, &opmd, pd);

	FREEMEM(opres);
	FREEMEM(corder);
    if(rv.code != RC_OK) return rv;

    if(extpresent) {
        int result = SET__uper_extensions(td, st, opt_codec_ctx, pd, 0);
        if(result == -2) ASN__DECODE_STARVED;
        if(result) ASN__DECODE_FAILED;
    }
    if(specs->extensible == 2 && SET__uper_extension_defaults(td, st)) ASN__DECODE_FAILED;

	rv.consumed = 0;
	rv.code = RC_OK;
	return rv;
}

/*
 * Purpose: encode a SET in UPER canonical root order and addition order.
 * Source: SET UPER codec adapted from vlm/asn1c PR #543.
 * Version: 2026-10-30. Author: asn1c maintainers.
 * Inputs: td, constraints, sptr and po follow the encoder API.
 * Returns: encode status. Errors: invalid descriptors or values fail.
 * History: extended with versioned SET extension metadata.
 * Example: a present addition is encoded in an open type.
 */
asn_enc_rval_t
SET_encode_uper(const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, const void *sptr,
                asn_per_outp_t *po) {
    const asn_SET_specifics_t *specs = td ? (const asn_SET_specifics_t *)td->specifics : 0;
	asn_enc_rval_t er;
	unsigned *corder;	/* Canonical tag order of the members */
	size_t i;
    int extpresent = 0;
    unsigned root_count;

	(void)constraints;

	if(!sptr || !po || SET__uper_layout(td, specs))
		ASN__ENCODE_FAILED;

	er.encoded = 0;

	ASN_DEBUG("Encoding %s as SET (UPER)", td->name);

    if(specs->extensible == 2 && SET__uper_storage(td, sptr)) ASN__ENCODE_FAILED;
    root_count = specs->extensible == 2 ? specs->root_count : td->elements_count;
    if(specs->extensible == 2) {
        for(i = 0; i < specs->extension_count; i++) {
            int present = SET__uper_present(td, sptr, specs->extension_map[i]);
            if(present < 0) ASN__ENCODE_FAILED;
            if(present) extpresent = 1;
        }
        if(per_put_few_bits(po, extpresent, 1)) ASN__ENCODE_FAILED;
    }

    if(SET__uper_order_alloc(td, specs, &corder)) ASN__ENCODE_FAILED;

    if(SET__uper_root_bitmap(td, sptr, corder, root_count, po)) {
        FREEMEM(corder);
        ASN__ENCODE_FAILED;
    }
    er = SET__uper_root_put(td, sptr, corder, root_count, po);
    if(er.encoded == -1) { FREEMEM(corder); return er; }

	FREEMEM(corder);
    if(extpresent && SET__uper_extensions(td, (void *)sptr, 0, 0, po)) ASN__ENCODE_FAILED;

	ASN__ENCODED_OK(er);
}

#endif  /* ASN_DISABLE_UPER_SUPPORT */
