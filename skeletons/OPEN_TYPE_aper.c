/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <aper_opentype.h>

asn_dec_rval_t
OPEN_TYPE_aper_get(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void *sptr,
                   const asn_TYPE_member_t *elm, asn_per_data_t *pd) {
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

    ASN_DEBUG("OPEN_TYPE_aper_get: elm->type=%s, elements=%p, elements_count=%u, selected.presence_index=%u, selected.type=%s",
              elm->type->name, (void*)elm->type->elements, elm->type->elements_count,
              selected.presence_index, selected.type_descriptor->name);

    /* Validate the selected variant */
    if(selected.presence_index > elm->type->elements_count) {
        ASN_DEBUG("Open Type %s->%s: presence index %u out of bounds (max %u)",
                  td->name, elm->name, selected.presence_index,
                  elm->type->elements_count);
        ASN__DECODE_FAILED;
    }
    
    /* Ensure we can access the elements array if needed */
    if(!elm->type->elements && elm->type->elements_count > 0) {
        ASN_DEBUG("Open Type %s->%s: elements array is NULL but elements_count is %u",
                  td->name, elm->name, elm->type->elements_count);
        ASN__DECODE_FAILED;
    }

    /* Fetch the pointer to this member */
    assert(elm->flags == ATF_OPEN_TYPE);
    if(elm->flags & ATF_POINTER) {
        memb_ptr2 = (void **)((char *)sptr + elm->memb_offset);
    } else {
        memb_ptr = (char *)sptr + elm->memb_offset;
        memb_ptr2 = &memb_ptr;
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
        if(CHOICE_variant_set_presence(elm->type, *memb_ptr2, 0)
           != 0) {
            ASN__DECODE_FAILED;
        }
    }

    /* Compute inner_value and constraints based on whether elements exist */
    unsigned int memb_offset = 0;
    const asn_per_constraints_t *constraints = NULL;
    
    if(elm->type->elements && selected.presence_index > 0 
       && selected.presence_index <= elm->type->elements_count) {
        memb_offset = elm->type->elements[selected.presence_index - 1].memb_offset;
        constraints = elm->type->elements[selected.presence_index - 1].encoding_constraints.per_constraints;
    }
    
    inner_value = (char *)*memb_ptr2 + memb_offset;

    rv = aper_open_type_get(opt_codec_ctx, selected.type_descriptor,
                            constraints, &inner_value, pd);
    ASN_DEBUG("aper_open_type_get returned code=%d for %s", rv.code, selected.type_descriptor->name);
    switch(rv.code) {
    case RC_OK:
        ASN_DEBUG("Calling CHOICE_variant_set_presence(elm->type=%s, presence_index=%u, elements_count=%u)",
                  elm->type->name, selected.presence_index, elm->type->elements_count);
        if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                       selected.presence_index)
           == 0) {
            ASN_DEBUG("CHOICE_variant_set_presence succeeded");
            break;
        } else {
            ASN_DEBUG("CHOICE_variant_set_presence FAILED");
            rv.code = RC_FAIL;
        }
        /* Fall through */
    case RC_WMORE:
    case RC_FAIL:
        ASN_DEBUG("Cleaning up after failure, code=%d", rv.code);
        if(*memb_ptr2) {
            if(elm->flags & ATF_POINTER) {
                ASN_STRUCT_FREE(*selected.type_descriptor, inner_value);
                *memb_ptr2 = NULL;
            } else {
                ASN_STRUCT_RESET(*selected.type_descriptor,
                                              inner_value);
            }
        }
    }
    return rv;
}

asn_enc_rval_t
OPEN_TYPE_encode_aper(const asn_TYPE_descriptor_t *td,
                      const asn_per_constraints_t *constraints,
                      const void *sptr, asn_per_outp_t *po) {
    const void *memb_ptr;   /* Pointer to the member */
    asn_TYPE_member_t *elm; /* CHOICE's element */
    asn_enc_rval_t er = {0,0,0};
    unsigned present;

    (void)constraints;

    present = CHOICE_variant_get_presence(td, sptr);
    if(present == 0 || present > td->elements_count) {
        ASN__ENCODE_FAILED;
    } else {
        present--;
    }

    ASN_DEBUG("Encoding %s OPEN TYPE element %d", td->name, present);

    elm = &td->elements[present];
    if(elm->flags & ATF_POINTER) {
        /* Member is a pointer to another structure */
        memb_ptr =
            *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const char *)sptr + elm->memb_offset;
    }

    if(aper_open_type_put(elm->type, elm->encoding_constraints.per_constraints, memb_ptr, po) < 0) {
        ASN__ENCODE_FAILED;
    }

    er.encoded = 0;
    ASN__ENCODED_OK(er);
}


int OPEN_TYPE_aper_is_unknown_type(const asn_TYPE_descriptor_t *td, void *sptr, const asn_TYPE_member_t *elm) {
    asn_type_selector_result_t selected;

    if(!elm->type_selector) {
        return 1;
    }
    else {
        selected = elm->type_selector(td, sptr);
        if(!selected.presence_index) {
            return 1;
        }
    }
    return 0;
}

asn_dec_rval_t
OPEN_TYPE_aper_unknown_type_discard_bytes (asn_per_data_t *pd) {
#define ASN_DUMMY_BYTES 256
    unsigned char dummy[ASN_DUMMY_BYTES], *dummy_ptr = NULL;
    ssize_t bytes;
    int repeat;
    asn_dec_rval_t rv;
    size_t initial_consumed = pd->moved;  /* Track initial position */

    rv.consumed = 0;
    rv.code = RC_FAIL;

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
    rv.consumed = pd->moved - initial_consumed;
    rv.code = RC_OK;
    return rv;
#undef ASN_DUMMY_BYTES
}
