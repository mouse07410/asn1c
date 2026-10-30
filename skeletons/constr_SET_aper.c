/*
 * Aligned PER codec for non-extensible ASN.1 SET values.
 *
 * Copyright (c) 2026 asn1c maintainers.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET.h>
#include <OPEN_TYPE.h>
#include <aper_opentype.h>
#include <string.h>

#ifndef ASN_DISABLE_APER_SUPPORT

/*
 * Purpose: compare two encoded tags in the numeric order used by generated maps.
 * Source: Compiler tag2el sorting by tag class and tag number.
 * Version: 2026-10-30.
 * Parameters: left and right are encoded ASN.1 tags.
 * Returns: -1, 0, or 1 according to tag order.
 * Errors: None.
 * Author: asn1c maintainers.
 * History: Added for SET APER canonical root-order validation.
 * Example: SET_aper_tag_compare(tag_a, tag_b) validates a sorted map.
 */
static int
SET_aper_tag_compare(ber_tlv_tag_t left, ber_tlv_tag_t right) {
    int left_class = BER_TAG_CLASS(left);
    int right_class = BER_TAG_CLASS(right);
    ber_tlv_tag_t left_value = BER_TAG_VALUE(left);
    ber_tlv_tag_t right_value = BER_TAG_VALUE(right);

    if(left_class != right_class)
        return left_class < right_class ? -1 : 1;
    if(left_value != right_value)
        return left_value < right_value ? -1 : 1;
    return 0;
}

/*
 * Purpose: validate an explicit compiler-generated canonical order map.
 * Source: SET tag2el_cxer map emitted with FTE_CANONICAL_XER.
 * Version: 2026-10-30.
 * Parameters: td/specs describe the SET; order receives member indexes.
 * Returns: 0 for a complete permutation, -1 for malformed metadata.
 * Errors: Missing, duplicated, out-of-range, or unsorted entries are rejected.
 * Author: asn1c maintainers.
 * History: Added for SET APER support using compiler canonical tag ordering.
 * Example: Three unique entries produce order[0..3].
 */
static int
SET_aper_order_from_cxer(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs,
                         unsigned *order) {
    unsigned i;
    uint8_t *seen;

    if(specs->tag2el_cxer_count != td->elements_count
    || !specs->tag2el_cxer) return -1;
    seen = td->elements_count ? CALLOC(td->elements_count, 1) : 0;
    if(td->elements_count && !seen) return -1;
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_tag2member_t *entry = &specs->tag2el_cxer[i];
        if(entry->el_no >= td->elements_count || seen[entry->el_no]
        || (i && SET_aper_tag_compare(specs->tag2el_cxer[i - 1].el_tag,
                                      entry->el_tag) >= 0)) {
            FREEMEM(seen);
            return -1;
        }
        seen[entry->el_no] = 1;
        order[i] = entry->el_no;
    }
    FREEMEM(seen);
    return 0;
}

/*
 * Purpose: allocate and validate the canonical member order for a SET.
 * Source: SET canonical CXER map emitted by the compiler.
 * Version: 2026-10-30.
 * Parameters: td/specs describe the SET; order_out receives allocated indexes.
 * Returns: 0 on success, -1 for invalid maps or allocation failure.
 * Errors: A partially populated or out-of-range map is rejected.
 * Author: asn1c maintainers.
 * History: Centralized canonical map validation for the SET APER codecs.
 * Example: Empty SETs succeed with a NULL order array.
 */
static int
SET_aper_canonical_order(const asn_TYPE_descriptor_t *td,
                         const asn_SET_specifics_t *specs,
                         unsigned **order_out) {
    unsigned *order;
    size_t bytes;
    int result;

    *order_out = 0;
    if(td->elements_count == 0) return 0;
    if((size_t)td->elements_count > SIZE_MAX / sizeof(*order)) return -1;
    bytes = (size_t)td->elements_count * sizeof(*order);
    order = MALLOC(bytes);
    if(!order) return -1;
    result = SET_aper_order_from_cxer(td, specs, order);
    if(result) {
        FREEMEM(order);
        return -1;
    }
    *order_out = order;
    return 0;
}

/*
 * Purpose: validate the SET descriptor's fixed context and presence storage.
 * Source: Generated SET specifics and _presence_map layout.
 * Version: 2026-10-30.
 * Parameters: td/specs describe one SET descriptor.
 * Returns: Nonzero if all fixed storage lies within struct_size.
 * Errors: Missing maps, overflow, and out-of-range offsets return zero.
 * Author: asn1c maintainers.
 * History: Added to reject malformed PER descriptors before bit access.
 * Example: A presence offset beyond struct_size is rejected safely.
 */
static int
SET_aper_layout_valid(const asn_TYPE_descriptor_t *td,
                      const asn_SET_specifics_t *specs) {
    size_t bits_per_word = 8 * sizeof(unsigned int);
    size_t words;
    size_t presence_bytes;

    if(!td || !specs || !specs->struct_size
    || (td->elements_count && (!td->elements || !specs->_mandatory_elements)))
        return 0;
    if(specs->ctx_offset > specs->struct_size
    || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset)
        return 0;
    if((size_t)td->elements_count > SIZE_MAX - (bits_per_word - 1)) return 0;
    words = ((size_t)td->elements_count + bits_per_word - 1) / bits_per_word;
    if(words > SIZE_MAX / sizeof(unsigned int)) return 0;
    presence_bytes = words * sizeof(unsigned int);
    return specs->pres_offset <= specs->struct_size
        && presence_bytes <= specs->struct_size - specs->pres_offset;
}

/*
 * Purpose: validate the basic APER SET descriptor fields.
 * Source: Generated SET descriptor, operation table, and member array.
 * Version: 2026-10-30.
 * Parameters: td is the descriptor; specs_out receives its SET specifics.
 * Returns: 0 on success, or -1 for a missing or malformed descriptor.
 * Errors: Missing operations and member storage are rejected before codec use.
 * Author: asn1c maintainers.
 * History: Shared by SET APER encode and decode after control-flow factoring.
 * Example: A valid SET descriptor supplies its specifics for layout checks.
 */
static int
SET_aper_descriptor_valid(const asn_TYPE_descriptor_t *td,
                          const asn_SET_specifics_t **specs_out) {
    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics
    || (td->elements_count && !td->elements)) return -1;
    *specs_out = (const asn_SET_specifics_t *)td->specifics;
    return 0;
}

/*
 * Purpose: validate one direct SET member before invoking its APER operation.
 * Source: SET_member_view storage validation and generated member operations.
 * Version: 2026-10-30.
 * Parameters: td/st identify the SET; index selects a direct member.
 * Returns: 0 for valid storage and operations, -1 for malformed descriptors.
 * Errors: Group/open-type members, invalid offsets, and missing operations fail.
 * Author: asn1c maintainers.
 * History: Added to keep malformed member metadata out of codec loops.
 * Example: An inline value with an invalid storage width is rejected.
 */
static int
SET_aper_member_valid(const asn_TYPE_descriptor_t *td, const void *st,
                      unsigned index) {
    const asn_TYPE_member_t *member;
    asn_SET_member_view_t view;

    if(index >= td->elements_count) return -1;
    member = &td->elements[index];
    if(!member->type || !member->type->op || !member->type->op->free_struct
    || (member->flags & (ATF_EXTENSION_GROUP | ATF_OPEN_TYPE))) return -1;
    return SET_member_view(td, st, index, ASN_SET_DIRECT_MEMBER, &view);
}

/*
 * Purpose: resolve one SET member's wire presence, including DEFAULT omission.
 * Source: SET pointer representation and DEFAULT comparison callbacks.
 * Version: 2026-10-30.
 * Parameters: td/st identify the SET; index selects a member.
 * Returns: 1 when encoded, 0 when optional or DEFAULT-absent, -1 on error.
 * Errors: Missing mandatory pointers and invalid member storage return -1.
 * Author: asn1c maintainers.
 * History: Added to share presence logic across preamble and content passes.
 * Example: A present DEFAULT value produces zero.
 */
static int
SET_aper_member_present(const asn_TYPE_descriptor_t *td, const void *st,
                        unsigned index) {
    const asn_TYPE_member_t *member = &td->elements[index];
    asn_SET_member_view_t view;

    if(SET_aper_member_valid(td, st, index)
    || SET_member_view(td, st, index, ASN_SET_DIRECT_MEMBER, &view)) return -1;
    if(!view.present) return member->optional ? 0 : -1;
    if(member->default_value_cmp && member->default_value_cmp(view.value) == 0)
        return 0;
    return 1;
}

/*
 * Purpose: validate every SET member needed by the APER decoder.
 * Source: Generated SET member descriptors and APER decoder operations.
 * Version: 2026-10-30.
 * Parameters: td/st describe the value; order gives canonical member indexes.
 * Returns: 0 when all direct members have usable storage and decoder methods.
 * Errors: Invalid storage, extension groups, and missing decoders return -1.
 * Author: asn1c maintainers.
 * History: Split from SET_decode_aper to keep codec control flow auditable.
 * Example: Called before reading the SET presence preamble.
 */
static int
SET_aper_decode_members_valid(const asn_TYPE_descriptor_t *td, const void *st,
                              const unsigned *order, size_t *optional_count) {
    size_t i;

    *optional_count = 0;
    for(i = 0; i < td->elements_count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];

        if(SET_aper_member_valid(td, st, index)
        || (!(member->flags & ATF_OPEN_TYPE)
            && !member->type->op->aper_decoder)) return -1;
        if(member->optional) (*optional_count)++;
    }
    return 0;
}

/*
 * Purpose: read the optional-member presence bits for one SET value.
 * Source: X.691 SET preamble and the existing PER bit reader.
 * Version: 2026-10-30.
 * Parameters: pd is the bit input; count is the number of optional members;
 *             storage and bits receive the owned buffer and its bit reader.
 * Returns: 0 on success, 1 when input is truncated, or -1 on allocation error.
 * Errors: Size overflow, allocation failure, and malformed input are reported.
 * Author: asn1c maintainers.
 * History: Split from SET_decode_aper to isolate preamble handling.
 * Example: A zero count initializes an empty bit reader without allocation.
 */
static int
SET_aper_decode_presence(asn_per_data_t *pd, size_t count, uint8_t **storage,
                         asn_per_data_t *bits) {
    size_t presence_bytes;

    *storage = 0;
    memset(bits, 0, sizeof(*bits));
    if(!count) return 0;
    if(count > SIZE_MAX - 7) return -1;
    presence_bytes = ((count + 7) >> 3) + 1;
    if(presence_bytes < count / 8) return -1;
    *storage = MALLOC(presence_bytes);
    if(!*storage) return -1;
    if(per_get_many_bits(pd, *storage, 0, count)) return 1;
    bits->buffer = *storage;
    bits->nbits = count;
    return 0;
}

/*
 * Purpose: decode all SET members after the optional presence preamble.
 * Source: X.691 SET component order and generated member callbacks.
 * Version: 2026-10-30.
 * Parameters: ctx/td/st/specs/order identify the SET; pd/bits hold input;
 *             rv receives child decoder status.
 * Returns: 0 on success, 1 for truncated presence input, 2 for child failure,
 *          or -1 for invalid DEFAULT handling.
 * Errors: Member callbacks retain their own RC status in rv.
 * Author: asn1c maintainers.
 * History: Split from SET_decode_aper to isolate component decoding.
 * Example: Called after all member descriptors have passed validation.
 */
static int
SET_aper_decode_content(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td, void *st,
                        const asn_SET_specifics_t *specs,
                        const unsigned *order, asn_per_data_t *pd,
                        asn_per_data_t *optional_bits, asn_dec_rval_t *rv) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
        unsigned index = order[i];
        asn_TYPE_member_t *member = &td->elements[index];
        void *inline_value;
        void **member_pointer;
        int present = 1;

        if(member->flags & ATF_POINTER) {
            member_pointer = (void **)((char *)st + member->memb_offset);
        } else {
            inline_value = (char *)st + member->memb_offset;
            member_pointer = &inline_value;
        }
        if(member->optional) {
            present = per_get_few_bits(optional_bits, 1);
            if(present < 0) return 1;
        }
        if(!present) {
            if(member->default_value_set) {
                if(member->default_value_set(member_pointer)) return -1;
                ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
            }
            continue;
        }
        if(member->flags & ATF_OPEN_TYPE) {
            *rv = OPEN_TYPE_aper_get(opt_codec_ctx, td, st, member, pd);
        } else {
            *rv = member->type->op->aper_decoder(
                opt_codec_ctx, member->type,
                member->encoding_constraints.per_constraints,
                member_pointer, pd);
        }
        if(rv->code != RC_OK) return 2;
        ASN_SET_MKPRESENT((char *)st + specs->pres_offset, index);
    }
    return 0;
}

/*
 * Purpose: decode a non-extensible SET using APER canonical member order.
 * Source: X.691 SET root encoding and existing SET UPER presence handling.
 * Version: 2026-10-30.
 * Parameters: ctx/td/constraints/sptr/pd are the standard APER decoder inputs.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL with consumed input bits.
 * Errors: Extensible SETs, malformed maps, bad members, and truncation fail.
 * Author: asn1c maintainers.
 * History: Initial APER runtime for root-only SET values.
 * Example: Called by aper_decode for compiler-generated non-extensible SETs.
 */
asn_dec_rval_t
SET_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, void **sptr,
                asn_per_data_t *pd) {
    const asn_SET_specifics_t *specs;
    asn_dec_rval_t rv = {RC_FAIL, 0};
    asn_per_data_t optional_bits;
    uint8_t *presence = 0;
    unsigned *order = 0;
    void *st;
    size_t optional_count = 0;
    int status;

    (void)constraints;
    if(!sptr || !pd || SET_aper_descriptor_valid(td, &specs))
        ASN__DECODE_FAILED;
    if(!SET_aper_layout_valid(td, specs) || specs->extensible
    || SET_aper_canonical_order(td, specs, &order)) ASN__DECODE_FAILED;
    if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx)) {
        FREEMEM(order);
        ASN__DECODE_FAILED;
    }
    st = *sptr;
    if(!st) {
        st = *sptr = CALLOC(1, specs->struct_size);
        if(!st) {
            FREEMEM(order);
            ASN__DECODE_FAILED;
        }
    }
    if(SET_aper_decode_members_valid(td, st, order, &optional_count))
        goto failed;
    status = SET_aper_decode_presence(pd, optional_count, &presence,
                                      &optional_bits);
    if(status == 1) goto starved;
    if(status) goto failed;
    status = SET_aper_decode_content(opt_codec_ctx, td, st, specs, order,
                                     pd, &optional_bits, &rv);
    if(status == 1) goto starved;
    if(status == 2) goto child_failed;
    if(status) goto failed;
    if(!_SET_is_populated(td, st)) goto failed;
    rv.code = RC_OK;
    rv.consumed = pd->moved;
    FREEMEM(presence);
    FREEMEM(order);
    return rv;

starved:
    rv.code = RC_WMORE;
    rv.consumed = 0;
    goto cleanup;
child_failed:
    goto cleanup;
failed:
    rv.code = RC_FAIL;
    rv.consumed = 0;
cleanup:
    FREEMEM(presence);
    FREEMEM(order);
    return rv;
}

/*
 * Purpose: validate all SET members needed by the APER encoder.
 * Source: Generated SET member descriptors and APER encoder operations.
 * Version: 2026-10-30.
 * Parameters: td/sptr describe the value; order gives canonical member indexes.
 * Returns: 0 when each member has valid storage and an available encoder.
 * Errors: Invalid storage, missing mandatory values, or missing encoders return
 *         -1.
 * Author: asn1c maintainers.
 * History: Split from SET_encode_aper to isolate descriptor validation.
 * Example: Called before writing any SET preamble bits.
 */
static int
SET_aper_encode_members_valid(const asn_TYPE_descriptor_t *td,
                              const void *sptr, const unsigned *order) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        int present = SET_aper_member_present(td, sptr, index);

        if(present < 0
        || (!(member->flags & ATF_OPEN_TYPE)
            && !member->type->op->aper_encoder)) return -1;
    }
    return 0;
}

/*
 * Purpose: emit the optional-member presence preamble for a SET value.
 * Source: X.691 SET preamble and the existing PER bit writer.
 * Version: 2026-10-30.
 * Parameters: td/sptr identify the value; order gives canonical member order;
 *             po is the APER output stream.
 * Returns: 0 when all presence bits are written, or -1 on invalid data/output.
 * Errors: Invalid member presence and bit-writer failures return -1.
 * Author: asn1c maintainers.
 * History: Split from SET_encode_aper to isolate preamble output.
 * Example: Optional members are represented in canonical SET order.
 */
static int
SET_aper_encode_presence(const asn_TYPE_descriptor_t *td, const void *sptr,
                         const unsigned *order, asn_per_outp_t *po) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        int present = SET_aper_member_present(td, sptr, index);

        if(present < 0
        || (member->optional && per_put_few_bits(po, present, 1))) return -1;
    }
    return 0;
}

/*
 * Purpose: encode all present SET members in canonical APER order.
 * Source: X.691 SET component order and generated member callbacks.
 * Version: 2026-10-30.
 * Parameters: td/sptr identify the SET; order gives member indexes; po is the
 *             output stream; er receives the last child encoder result.
 * Returns: 0 on success, or -1 on invalid data or child encoder failure.
 * Errors: Child encoder failures are preserved in er for the caller.
 * Author: asn1c maintainers.
 * History: Split from SET_encode_aper to isolate component output.
 * Example: Called after descriptor validation and presence preamble emission.
 */
static int
SET_aper_encode_content(const asn_TYPE_descriptor_t *td, const void *sptr,
                        const unsigned *order, asn_per_outp_t *po,
                        asn_enc_rval_t *er) {
    size_t i;

    for(i = 0; i < td->elements_count; i++) {
        unsigned index = order[i];
        const asn_TYPE_member_t *member = &td->elements[index];
        asn_SET_member_view_t view;
        int present = SET_aper_member_present(td, sptr, index);

        if(present < 0) return -1;
        if(!present) continue;
        if(SET_member_view(td, sptr, index, ASN_SET_DIRECT_MEMBER, &view))
            return -1;
        if(member->flags & ATF_OPEN_TYPE) {
            *er = OPEN_TYPE_aper_put(td, sptr, member, po);
        } else if(member->type->op->aper_encoder) {
            *er = member->type->op->aper_encoder(
                member->type, member->encoding_constraints.per_constraints,
                view.value, po);
        } else {
            return -1;
        }
        if(er->encoded == -1) return -1;
    }
    return 0;
}

/*
 * Purpose: encode a non-extensible SET using APER canonical member order.
 * Source: X.691 SET root encoding and existing SET UPER presence handling.
 * Version: 2026-10-30.
 * Parameters: td/constraints/sptr/po are the standard APER encoder inputs.
 * Returns: APER encoding result, or failure for invalid values and metadata.
 * Errors: Extensible SETs, malformed maps, absent mandatory members, and child
 *         encoder failures are reported without dereferencing invalid storage.
 * Author: asn1c maintainers.
 * History: Initial APER runtime for root-only SET values.
 * Example: Called by aper_encode for compiler-generated non-extensible SETs.
 */
asn_enc_rval_t
SET_encode_aper(const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, const void *sptr,
                asn_per_outp_t *po) {
    const asn_SET_specifics_t *specs;
    asn_enc_rval_t er = {0, 0, 0};
    unsigned *order = 0;
    int status;

    (void)constraints;
    if(!sptr || !po || SET_aper_descriptor_valid(td, &specs))
        ASN__ENCODE_FAILED;
    APER_ENCODER_RECURSION_DEPTH_INC();
    if(!SET_aper_layout_valid(td, specs) || specs->extensible
    || SET_aper_canonical_order(td, specs, &order)) goto failed_recursive;
    if(SET_aper_encode_members_valid(td, sptr, order))
        goto failed_recursive;
    if(SET_aper_encode_presence(td, sptr, order, po)) goto failed_recursive;
    status = SET_aper_encode_content(td, sptr, order, po, &er);
    if(status) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
        FREEMEM(order);
        if(er.encoded == -1) return er;
        ASN__ENCODE_FAILED;
    }
    APER_ENCODER_RECURSION_DEPTH_DEC();
    FREEMEM(order);
    ASN__ENCODED_OK(er);

failed_recursive:
    APER_ENCODER_RECURSION_DEPTH_DEC();
    FREEMEM(order);
    ASN__ENCODE_FAILED;
}

#endif /* ASN_DISABLE_APER_SUPPORT */
