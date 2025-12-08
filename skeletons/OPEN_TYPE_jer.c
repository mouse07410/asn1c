/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

asn_dec_rval_t
OPEN_TYPE_jer_get(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td,
                  void *sptr, const asn_TYPE_member_t *elm, const void *ptr,
                  size_t size) {
    size_t consumed_myself = 0;
    asn_type_selector_result_t selected;
    void *memb_ptr;   /* Pointer to the member */
    void **memb_ptr2; /* Pointer to that pointer */
    void *inner_value;
    asn_dec_rval_t rv;

    int jer_context = 0;
    ssize_t ch_size;
    pjer_chunk_type_e ch_type;

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
    assert(elm->flags & ATF_OPEN_TYPE);
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
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2, 0)
               != 0) {
                ASN__DECODE_FAILED;
            }
        }
    } else {
        /* Direct type mode: no CHOICE wrapper, decode directly into member */
        ASN_DEBUG("Open Type %s->%s: using direct type mode (no CHOICE wrapper)",
                  td->name, elm->name);
    }

    /*
     * Confirm wrapper.
     */
    for(;;) {
        ch_size = jer_next_token(&jer_context, ptr, size, &ch_type);
        if(ch_size < 0) {
            ASN__DECODE_FAILED;
        } else {
            switch(ch_type) {
            case PJER_WMORE:
                ASN__DECODE_STARVED;
            case PJER_TEXT:
            case PJER_DLM:
                ADVANCE(ch_size);
                continue;
            case PJER_KEY:
            default:
                break;
            }
            break;
        }

    }

    /*
     * Wrapper value confirmed.
     */
    switch(jer_check_sym(ptr, ch_size, NULL)) {
    case JCK_UNKNOWN:
        ADVANCE(ch_size);
        break;
    case JCK_BROKEN:
    default:
        ASN__DECODE_FAILED;
    }


    /* Skip colon */
    ch_size = jer_next_token(&jer_context, ptr, size, &ch_type);
    if(ch_size < 0 || ch_type != PJER_TEXT)  {
        ASN__DECODE_FAILED;
    } else {
        ADVANCE(ch_size);
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

    rv = selected.type_descriptor->op->jer_decoder(
        opt_codec_ctx, selected.type_descriptor, selected.type_descriptor->encoding_constraints.jer_constraints,
        &inner_value, ptr, size);
    ADVANCE(rv.consumed);
    rv.consumed = 0;
    switch(rv.code) {
    case RC_OK:
        if(elm->type->elements_count > 0) {
            /* CHOICE wrapper mode: for pointer variants, copy decoded pointer back to field */
            if(variant_elm && (variant_elm->flags & ATF_POINTER)) {
                /*
                 * The decoder allocated a structure and stored pointer in inner_value.
                 * Copy it back to the actual field in the CHOICE structure.
                 */
                void **variant_ptr = (void **)((char *)*memb_ptr2 + memb_offset);
                *variant_ptr = inner_value;
            }
            /* Set presence indicator */
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                           selected.presence_index)
               == 0) {
                break;
            } else {
                rv.code = RC_FAIL;
            }
        } else {
            /* Direct type mode: update member pointer with decoded value if pointer type */
            if(elm->flags & ATF_POINTER) {
                ASN_DEBUG("Direct type mode: updating member pointer");
                *memb_ptr2 = inner_value;
            } else {
                ASN_DEBUG("Direct type mode: decode successful (non-pointer)");
            }
            break;
        }
        /* Fall through */
    case RC_FAIL:
        /* Point to a best position where failure occurred */
        rv.consumed = consumed_myself;
        /* Fall through */
    case RC_WMORE:
        /* Wrt. rv.consumed==0:
         * In case a genuine RC_WMORE, the whole Open Type decoding
         * will have to be restarted.
         */
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


    /*
     * Finalize wrapper.
     */
    for(;;) {
        ch_size = jer_next_token(&jer_context, ptr, size, &ch_type);
        if(ch_size < 0) {
            ASN__DECODE_FAILED;
        } else {
            switch(ch_type) {
            case PJER_WMORE:
                ASN__DECODE_STARVED;
            case PJER_TEXT:
                ADVANCE(ch_size);
                continue;
            default:
                break;
            }
            break;
        }
    }

    /*
     * Wrapper value confirmed.
     */
    switch(jer_check_sym(ptr, ch_size, NULL)) {
    case JCK_KEY:
    case JCK_OEND:
        ADVANCE(ch_size);
        break;
    case JCK_BROKEN:
    default:
        ASN__DECODE_FAILED;
    }

    rv.consumed += consumed_myself;

    return rv;
}

asn_enc_rval_t
OPEN_TYPE_jer_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                  const asn_TYPE_member_t *elm, int ilevel,
                  enum jer_encoder_flags_e flags,
                  asn_app_consume_bytes_f *cb, void *app_key) {
    asn_type_selector_result_t selected;
    const void *memb_ptr;
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

    if(!elm->type_selector) {
        ASN_DEBUG("Type selector is not defined for Open Type %s->%s->%s",
                  td->name, elm->name, elm->type->name);
        ASN__ENCODE_FAILED;
    }

    selected = elm->type_selector(td, sptr);
    if(!selected.presence_index) {
        ASN__ENCODE_FAILED;
    }

    ASN_DEBUG("OPEN_TYPE_jer_put: elm->type=%s, elements=%p, elements_count=%u, selected.presence_index=%u, selected.type=%s",
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
        /* CHOICE wrapper mode: use standard CHOICE encoder */
        return CHOICE_encode_jer(elm->type, elm->encoding_constraints.jer_constraints,
                                memb_ptr, ilevel, flags, cb, app_key);
    } else {
        /* Direct type mode: encode using the selected type descriptor with wrapper */
        ASN_DEBUG("Direct type mode: encoding using %s", selected.type_descriptor->name);
        
        const char *type_name = selected.type_descriptor->xml_tag;  /* Using xml_tag as JSON key */
        if(!type_name || !*type_name) {
            /* Fallback to type name if xml_tag is not set */
            type_name = selected.type_descriptor->name;
            if(!type_name) {
                ASN_DEBUG("ERROR: Type descriptor has no name or xml_tag");
                ASN__ENCODE_FAILED;
            }
        }
        size_t type_name_len = strlen(type_name);
        asn_enc_rval_t tmper;
        int jmin = (flags & JER_F_MINIFIED);
        
        er.encoded = 0;
        
        /* Output opening brace and key for the selected type */
        ASN__CALLBACK("{", 1);
        if(!jmin) {
            ASN__TEXT_INDENT(1, ilevel + 1);
            ASN__CALLBACK3("\"", 1, type_name, type_name_len, "\": ", 3);
        } else {
            ASN__CALLBACK3("\"", 1, type_name, type_name_len, "\":", 2);
        }
        
        /* Encode the actual content */
        tmper = selected.type_descriptor->op->jer_encoder(
            selected.type_descriptor, selected.type_descriptor->encoding_constraints.jer_constraints,
            memb_ptr, ilevel + 1, flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
        
        /* Output closing brace */
        if(!jmin) ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK("}", 1);
        
        ASN__ENCODED_OK(er);
    }
cb_failed:
    ASN__ENCODE_FAILED;
}
