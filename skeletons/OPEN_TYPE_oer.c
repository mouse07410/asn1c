/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

asn_dec_rval_t
OPEN_TYPE_oer_get(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, void *sptr,
                  asn_TYPE_member_t *elm, const void *ptr, size_t size) {
    asn_type_selector_result_t selected;
    void *memb_ptr;   /* Pointer to the member */
    void **memb_ptr2; /* Pointer to that pointer */
    void *inner_value;
    asn_dec_rval_t rv;
    size_t ot_ret;


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
    const asn_TYPE_member_t *variant_elm = NULL;
    
    if(elm->type->elements_count > 0) {
        /* CHOICE wrapper mode: get variant element info */
        if(elm->type->elements && selected.presence_index > 0 
           && selected.presence_index <= elm->type->elements_count) {
            variant_elm = &elm->type->elements[selected.presence_index - 1];
            memb_offset = variant_elm->memb_offset;
        }
        
        /*
         * For ATF_POINTER variants (e.g., "PersonInfo *PersonInfo" in CHOICE):
         *   - The field is a pointer itself, freshly CALLOC'd to NULL
         *   - We need to read the pointer value (NULL) from the field
         *   - Decoder will allocate structure and update inner_value
         *   - We'll copy inner_value back to the field after decoding
         * 
         * For non-pointer variants (e.g., "int value" in CHOICE):
         *   - The field is embedded in the CHOICE structure
         *   - We pass the address of the field to the decoder
         *   - Decoder writes directly into the field
         */
        if(variant_elm && (variant_elm->flags & ATF_POINTER)) {
            /* Read the current pointer value from the field */
            inner_value = *(void **)((char *)*memb_ptr2 + memb_offset);
        } else {
            /* Compute address of the embedded value field */
            inner_value = (char *)*memb_ptr2 + memb_offset;
        }
    } else {
        /* Direct type mode: decode directly into the member pointer */
        inner_value = *memb_ptr2;
    }

    ot_ret = oer_open_type_get(opt_codec_ctx, selected.type_descriptor, NULL,
                               &inner_value, ptr, size);
    switch(ot_ret) {
    default:
        if(elm->type->elements_count > 0) {
            /* Set presence indicator FIRST, before copying pointer */
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                           selected.presence_index)
               == 0) {
                /* CHOICE wrapper mode: for pointer variants, copy decoded pointer back to field */
                if(variant_elm && (variant_elm->flags & ATF_POINTER)) {
                    /*
                     * The decoder allocated a structure and stored pointer in inner_value.
                     * Copy it back to the actual field in the CHOICE structure.
                     */
                    void **variant_ptr = (void **)((char *)*memb_ptr2 + memb_offset);
                    *variant_ptr = inner_value;
                }
                rv.code = RC_OK;
                rv.consumed = ot_ret;
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
            rv.consumed = ot_ret;
            return rv;
        }
        /* Fall through */
    case -1:
        rv.code = RC_FAIL;
        rv.consumed = ot_ret;
        break;
    case 0:
        rv.code = RC_WMORE;
        rv.consumed = 0;
        break;
    }

    if(*memb_ptr2) {
        const asn_CHOICE_specifics_t *specs =
            selected.type_descriptor->specifics;
        if(elm->flags & ATF_POINTER) {
            ASN_STRUCT_FREE(*selected.type_descriptor, inner_value);
            *memb_ptr2 = NULL;
        } else {
            ASN_STRUCT_FREE_CONTENTS_ONLY(*selected.type_descriptor,
                                          inner_value);
            memset(*memb_ptr2, 0, specs->struct_size);
        }
    }
    return rv;
}

asn_enc_rval_t
OPEN_TYPE_encode_oer(const asn_TYPE_descriptor_t *td,
                  const asn_oer_constraints_t *constraints, const void *sptr,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    asn_TYPE_member_t *elm;
    unsigned present;
    const void *memb_ptr;
    ssize_t encoded;
    asn_enc_rval_t er = {0, 0, 0};

    (void)constraints;

    if(!sptr) ASN__ENCODE_FAILED;

    if(td->elements_count == 0) {
        /* Direct type mode: no CHOICE wrapper, encode directly */
        ASN_DEBUG("Encoding %s OPEN TYPE in direct type mode", td->name);
        
        /* In direct type mode, sptr points directly to the value to encode */
        /* We can't encode it because we don't know the actual type descriptor */
        /* This should not happen - the parent should handle this case */
        ASN_DEBUG("ERROR: OPEN_TYPE_encode_oer called in direct type mode");
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
    if(elm->flags & ATF_POINTER) {
        memb_ptr =
            *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(memb_ptr == 0) {
            /* Mandatory element absent */
            ASN__ENCODE_FAILED;
        }
    } else {
        memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
    }

    if((encoded = oer_open_type_put(elm->type,
                          elm->encoding_constraints.oer_constraints,
                          memb_ptr, cb, app_key)) < 0) {
        ASN__ENCODE_FAILED;
    }

    er.encoded = encoded;
    ASN__ENCODED_OK(er);

    return er;
}

asn_enc_rval_t
OPEN_TYPE_oer_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                  const asn_TYPE_member_t *elm,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    asn_type_selector_result_t selected;
    const void *memb_ptr;
    ssize_t encoded;
    asn_enc_rval_t er = {0,0,0};

    if(!(elm->flags & ATF_OPEN_TYPE)) {
        ASN__ENCODE_FAILED;
    }

    /* Validate elm->type before accessing its members */
    if(!elm->type) {
        ASN_DEBUG("Open Type %s->%s: type descriptor is NULL",
                  td->name, elm->name);
        ASN__ENCODE_FAILED;
    }

    if(!elm->type->op || !elm->type->op->oer_encoder) {
        ASN_DEBUG("Open Type %s->%s: OER encoder is not defined",
                  td->name, elm->name);
        ASN__ENCODE_FAILED;
    }

    if(!elm->type_selector) {
        ASN_DEBUG("Type selector is not defined for Open Type %s->%s->%s",
                  td->name, elm->name, elm->type->name);
        ASN__ENCODE_FAILED;
    }

    selected = elm->type_selector(td, sptr);
    if(!selected.presence_index) {
        ASN__ENCODE_FAILED;
    }

    ASN_DEBUG("OPEN_TYPE_oer_put: elm->type=%s, elements=%p, elements_count=%u, selected.presence_index=%u, selected.type=%s",
              elm->type->name, (void*)elm->type->elements, elm->type->elements_count,
              selected.presence_index, selected.type_descriptor->name);

    /* Fetch the pointer to this member */
    assert(elm->flags & ATF_OPEN_TYPE);
    if(elm->flags & ATF_POINTER) {
        memb_ptr = *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
    }

    /* Check if this OPEN_TYPE uses CHOICE wrapper (elements_count > 0) or direct type */
    if(elm->type->elements_count > 0) {
        /* 
         * CHOICE wrapper mode: encode the CHOICE directly.
         * When elements_count > 0, the CHOICE structure is already selected and
         * populated by the type selector, so we encode it directly using its native
         * OER encoder. The encoder will handle the choice index and variant encoding
         * according to its own constraints (constrained vs. extension variants).
         * Wrapping it again with open type framing would be redundant and incorrect.
         */
        er = elm->type->op->oer_encoder(elm->type, 
                                        elm->encoding_constraints.oer_constraints,
                                        memb_ptr, cb, app_key);
        if(er.encoded < 0) {
            ASN__ENCODE_FAILED;
        }
        ASN__ENCODED_OK(er);
        return er;
    } else {
        /* 
         * Direct type mode: encode using the selected type descriptor.
         * Since this is direct type without CHOICE wrapper, we need the 
         * open type length determinant wrapper.
         */
        ASN_DEBUG("Direct type mode: encoding using %s wrapped in OPEN TYPE", selected.type_descriptor->name);
        if((encoded = oer_open_type_put(selected.type_descriptor, elm->encoding_constraints.oer_constraints, memb_ptr, cb, app_key)) < 0) {
            ASN__ENCODE_FAILED;
        }
        er.encoded = encoded;
        ASN__ENCODED_OK(er);
        return er;
    }
}
