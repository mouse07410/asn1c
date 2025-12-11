/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

asn_dec_rval_t
OPEN_TYPE_xer_get(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, void *sptr,
                  const asn_TYPE_member_t *elm, const void *ptr, size_t size) {
    size_t consumed_myself = 0;
    asn_type_selector_result_t selected;
    void *memb_ptr;   /* Pointer to the member */
    void **memb_ptr2; /* Pointer to that pointer */
    void *inner_value;
    asn_dec_rval_t rv;

    int xer_context = 0;
    ssize_t ch_size;
    pxer_chunk_type_e ch_type;

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

    ASN_DEBUG("OPEN_TYPE_xer_get: elm->type=%s, elements=%p, elements_count=%u, selected.presence_index=%u, selected.type=%s",
              elm->type->name, (void*)elm->type->elements, elm->type->elements_count,
              selected.presence_index, selected.type_descriptor->name);

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
        ch_size = xer_next_token(&xer_context, ptr, size, &ch_type);
        if(ch_size < 0) {
            ASN__DECODE_FAILED;
        } else {
            switch(ch_type) {
            case PXER_WMORE:
                ASN__DECODE_STARVED;
            case PXER_COMMENT:
            case PXER_TEXT:
                ADVANCE(ch_size);
                continue;
            case PXER_TAG:
                break;
            }
            break;
        }
    }

    /*
     * Wrapper value confirmed.
     */
    switch(xer_check_tag(ptr, ch_size, elm->name)) {
    case XCT_OPENING:
        ADVANCE(ch_size);
        break;
    case XCT_BROKEN:
    default:
        ASN__DECODE_FAILED;
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

    rv = selected.type_descriptor->op->xer_decoder(
        opt_codec_ctx, selected.type_descriptor, &inner_value, NULL, ptr, size);
    ADVANCE(rv.consumed);
    rv.consumed = 0;
    ASN_DEBUG("xer_decoder returned code=%d for %s", rv.code, selected.type_descriptor->name);
    switch(rv.code) {
    case RC_OK:
        if(elm->type->elements_count > 0) {
            /* Set presence indicator FIRST, before copying pointer */
            ASN_DEBUG("Calling CHOICE_variant_set_presence(elm->type=%s, presence_index=%u, elements_count=%u)",
                      elm->type->name, selected.presence_index, elm->type->elements_count);
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                           selected.presence_index)
               != 0) {
                ASN_DEBUG("CHOICE_variant_set_presence FAILED");
                rv.code = RC_FAIL;
                /* Fall through to cleanup */
            } else {
                ASN_DEBUG("CHOICE_variant_set_presence succeeded");
                /* CHOICE wrapper mode: for pointer variants, copy decoded pointer back to field */
                if(variant_elm && (variant_elm->flags & ATF_POINTER)) {
                    /*
                     * The decoder allocated a structure and stored pointer in inner_value.
                     * Copy it back to the actual field in the CHOICE structure.
                     */
                    void **variant_ptr = (void **)((char *)*memb_ptr2 + memb_offset);
                    *variant_ptr = inner_value;
                }
                break;
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
        ASN_DEBUG("Cleaning up after failure, code=%d", rv.code);
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
        ch_size = xer_next_token(&xer_context, ptr, size, &ch_type);
        if(ch_size < 0) {
            ASN__DECODE_FAILED;
        } else {
            switch(ch_type) {
            case PXER_WMORE:
                ASN__DECODE_STARVED;
            case PXER_COMMENT:
            case PXER_TEXT:
                ADVANCE(ch_size);
                continue;
            case PXER_TAG:
                break;
            }
            break;
        }
    }

    /*
     * Wrapper value confirmed.
     */
    switch(xer_check_tag(ptr, ch_size, elm->name)) {
    case XCT_CLOSING:
        ADVANCE(ch_size);
        break;
    case XCT_BROKEN:
    default:
        ASN__DECODE_FAILED;
    }

    rv.consumed += consumed_myself;

    return rv;
}

asn_enc_rval_t
OPEN_TYPE_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                     int ilevel, enum xer_encoder_flags_e flags,
                     asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};

    if(!sptr)
        ASN__ENCODE_FAILED;

    /* Check if this OPEN_TYPE uses direct type mode (elements_count == 0) */
    if(td->elements_count == 0) {
        /* Direct type mode: no CHOICE wrapper, encode directly */
        ASN_DEBUG("Encoding %s OPEN TYPE in direct type mode", td->name);
        
        /* In direct type mode, sptr points directly to the value to encode */
        /* We can't encode it because we don't know the actual type descriptor */
        /* This should not happen - the parent should handle this case */
        ASN_DEBUG("ERROR: OPEN_TYPE_encode_xer called in direct type mode");
        ASN__ENCODE_FAILED;
    }

    /* CHOICE wrapper mode: use CHOICE encoder */
    return CHOICE_encode_xer(td, sptr, ilevel, flags, cb, app_key);
}

asn_enc_rval_t
OPEN_TYPE_xer_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                  const asn_TYPE_member_t *elm, int ilevel,
                  enum xer_encoder_flags_e flags,
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

    ASN_DEBUG("OPEN_TYPE_xer_put: elm->type=%s, elements=%p, elements_count=%u, selected.presence_index=%u, selected.type=%s",
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
        return CHOICE_encode_xer(elm->type, memb_ptr, ilevel, flags, cb, app_key);
    } else {
        /* Direct type mode: encode using the selected type descriptor with wrapper tag */
        ASN_DEBUG("Direct type mode: encoding using %s", selected.type_descriptor->name);
        
        const char *type_name = selected.type_descriptor->xml_tag;
        if(!type_name || !*type_name) {
            /* Fallback to type name if xml_tag is not set */
            type_name = selected.type_descriptor->name;
            if(!type_name) {
                ASN_DEBUG("ERROR: Type descriptor has no name or xml_tag");
                ASN__ENCODE_FAILED;
            }
        }
        
        /* Check if type_name contains ASN.1 meta-syntax keywords that should not be output as wrapper tags */
        int skip_wrapper = asn_is_meta_syntax_keyword(type_name);
        if(skip_wrapper) {
            ASN_DEBUG("Skipping wrapper tag for ASN.1 meta-syntax: %s", type_name);
        }
        
        size_t type_name_len = skip_wrapper ? 0 : strlen(type_name);
        asn_enc_rval_t tmper;
        
        er.encoded = 0;
        
        /* Output opening tag for the selected type (unless it's ASN.1 meta-syntax) */
        if(!skip_wrapper) {
            if(!(flags & XER_F_CANONICAL)) ASN__TEXT_INDENT(1, ilevel);
            ASN__CALLBACK3("<", 1, type_name, type_name_len, ">", 1);
        }
        
        /* Encode the actual content */
        tmper = selected.type_descriptor->op->xer_encoder(
            selected.type_descriptor, memb_ptr, skip_wrapper ? ilevel : ilevel + 1, flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
        
        /* Output closing tag (unless it's ASN.1 meta-syntax) */
        if(!skip_wrapper) {
            if(!(flags & XER_F_CANONICAL)) ASN__TEXT_INDENT(1, ilevel - 1);
            ASN__CALLBACK3("</", 2, type_name, type_name_len, ">", 1);
        }
        
        ASN__ENCODED_OK(er);
    }
cb_failed:
    ASN__ENCODE_FAILED;
}
