/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

asn_dec_rval_t
OPEN_TYPE_ber_get(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, void *sptr,
                  const asn_TYPE_member_t *elm, const void *ptr, size_t size) {
    size_t consumed_myself = 0;
    asn_type_selector_result_t selected;
    void *memb_ptr;   /* Pointer to the member */
    void **memb_ptr2; /* Pointer to that pointer */
    void *inner_value;
    asn_dec_rval_t rv;

    if(!(elm->flags & ATF_OPEN_TYPE)) {
        ASN__DECODE_FAILED;
    }

    /* Validate elm->type before accessing its members */
    if(!elm->type) {
        ASN_DEBUG("Open Type %s->%s: type descriptor is NULL",
                  td->name, elm->name);
        ASN__DECODE_FAILED;
    }

    if(!elm->type_selector) {
        ASN_DEBUG("Type selector is not defined for Open Type %s->%s->%s",
                  td->name, elm->name, elm->type->name);
        ASN__DECODE_FAILED;
    }

    selected = elm->type_selector(td, sptr);
    if(!selected.presence_index) {
        ASN__DECODE_FAILED;
    }

    /* Fetch the pointer to this member */
    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
    } else {
        memb_ptr = (char *)sptr + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
    }

    /* Check if this OPEN_TYPE uses CHOICE wrapper (elements_count > 0) or direct type */
    if(elm->type->elements_count > 0) {
        /* CHOICE wrapper mode: validate and allocate CHOICE structure */
        
        /* Validate the selected variant */
        if(selected.presence_index > elm->type->elements_count) {
            ASN_DEBUG("Open Type %s->%s: presence index %u out of bounds (max %u)",
                      td->name, elm->name, selected.presence_index,
                      elm->type->elements_count);
            ASN__DECODE_FAILED;
        }
        
        /* Ensure we can access the elements array if needed */
        if(!elm->type->elements) {
            ASN_DEBUG("Open Type %s->%s: elements array is NULL but elements_count is %u",
                      td->name, elm->name, elm->type->elements_count);
            ASN__DECODE_FAILED;
        }

        /* Allocate the CHOICE structure if not already present */
        if(*memb_ptr2 == NULL) {
            const asn_CHOICE_specifics_t *specs = 
                (const asn_CHOICE_specifics_t *)elm->type->specifics;
            if(!specs) {
                ASN_DEBUG("Open Type %s->%s: type specifics is NULL",
                          td->name, elm->name);
                ASN__DECODE_FAILED;
            }
            *memb_ptr2 = CALLOC(1, specs->struct_size);
            if(*memb_ptr2 == NULL) {
                ASN__DECODE_FAILED;
            }
        } else {
            /* Make sure we reset the structure first before decoding */
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2, 0) != 0) {
                ASN__DECODE_FAILED;
            }
        }
    } else {
        /* Direct type mode: no CHOICE wrapper, decode directly into member */
        ASN_DEBUG("Open Type %s->%s: using direct type mode (no CHOICE wrapper)",
                  td->name, elm->name);
    }

    /* Compute inner_value based on CHOICE wrapper mode or direct type mode */
    unsigned int memb_offset = 0;
    if(elm->type->elements_count > 0) {
        /* CHOICE wrapper mode: compute offset from elements array */
        if(elm->type->elements && selected.presence_index > 0 
           && selected.presence_index <= elm->type->elements_count) {
            memb_offset = elm->type->elements[selected.presence_index - 1].memb_offset;
        }
        inner_value = (char *)*memb_ptr2 + memb_offset;
    } else {
        /* Direct type mode: decode directly into the member pointer */
        inner_value = *memb_ptr2;
    }

    ASN_DEBUG("presence %d\n", selected.presence_index);

    rv = selected.type_descriptor->op->ber_decoder(
        opt_codec_ctx, selected.type_descriptor, &inner_value, ptr, size,
        elm->tag_mode);
    ADVANCE(rv.consumed);
    rv.consumed = 0;
    switch(rv.code) {
    case RC_OK:
        if(elm->type->elements_count > 0) {
            /* CHOICE wrapper mode: set presence indicator */
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                           selected.presence_index)
               == 0) {
                rv.code = RC_OK;
                rv.consumed = consumed_myself;
                return rv;
            } else {
                /* Oh, now a full-blown failure failure */
            }
        } else {
            /* Direct type mode: update member pointer with decoded value if pointer type */
            if(elm->flags & ATF_POINTER) {
                *memb_ptr2 = inner_value;
            }
            rv.code = RC_OK;
            rv.consumed = consumed_myself;
            return rv;
        }
        /* Fall through */
    case RC_FAIL:
        rv.consumed = consumed_myself;
        /* Fall through */
    case RC_WMORE:
        break;
    }

    if(*memb_ptr2) {
        if(elm->flags & ATF_POINTER) {
            ASN_STRUCT_FREE(*selected.type_descriptor, inner_value);
            *memb_ptr2 = NULL;
        } else {
            ASN_STRUCT_RESET(*selected.type_descriptor,
                                          inner_value);
        }
    }
    return rv;
}
