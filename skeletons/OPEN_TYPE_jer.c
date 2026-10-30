/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

/*
 * Decode an IOC-selected JER value into its open-type member.
 * Original source: asn1c OPEN TYPE JER decoder. Version: 2026-10-30.
 * Inputs: opt_codec_ctx controls decoding; td and sptr describe the parent;
 * elm describes the selected member; ptr and size provide the JSON input.
 * Returns: decoder status and consumed bytes. Errors: invalid descriptors or
 * malformed input return failure; incomplete input returns RC_WMORE. No
 * exceptions. Owner: asn1c maintainers. History: correct partial-arm cleanup.
 * Example: decode a selected PersonInfo value in a SEQUENCE.
 */
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
    int choice_wrapper_allocated = 0;

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
    if(!selected.presence_index || !selected.type_descriptor
       || !selected.type_descriptor->op
       || !selected.type_descriptor->op->jer_decoder) {
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
        if(!elm->type->specifics) {
            ASN__DECODE_FAILED;
        }
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
            choice_wrapper_allocated = 1;
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
     * Per ITU-T X.697 Clause 41: "The encoding of an open type value shall be
     * the encoding of the value of the contained type."
     * 
     * For OPEN TYPE, the encoder does NOT add a CHOICE wrapper key in the JSON,
     * even if elm->type is internally structured as a CHOICE (elements_count > 0).
     * The value is encoded directly as per the selected type.
     *
     * Therefore, the decoder should NOT try to parse a CHOICE key wrapper.
     * We proceed directly to decoding the value using the selected type descriptor.
     */

    /*
     * Compute inner_value pointer based on internal structure.
     * Note: This handles the internal ASN.1 CHOICE structure representation,
     * NOT JSON format (which has no CHOICE wrapper for OPEN TYPE).
     */
    unsigned int memb_offset = 0;
    const asn_TYPE_member_t *variant_elm = NULL;
    
    if(elm->type->elements_count > 0) {
        /* Internal CHOICE structure mode: get variant element info */
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
            /* Set presence indicator FIRST, before copying pointer */
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2,
                                           selected.presence_index)
               == 0) {
                /* Internal CHOICE structure: for pointer variants, copy decoded pointer back to field */
                if(variant_elm && (variant_elm->flags & ATF_POINTER)) {
                    /*
                     * The decoder allocated a structure and stored pointer in inner_value.
                     * Copy it back to the actual field in the internal CHOICE structure.
                     */
                    void **variant_ptr = (void **)((char *)*memb_ptr2 + memb_offset);
                    *variant_ptr = inner_value;
                }
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
        /* The selected arm's ownership is independent of the wrapper's.
         * The decoder may have allocated inner_value even when the original
         * member slot was NULL; release that partial value on either result. */
        if(inner_value) {
            if(variant_elm ? (variant_elm->flags & ATF_POINTER)
                           : (elm->flags & ATF_POINTER)) {
                ASN_STRUCT_FREE(*selected.type_descriptor, inner_value);
                if(!variant_elm) *memb_ptr2 = NULL;
            } else {
                ASN_STRUCT_RESET(*selected.type_descriptor, inner_value);
            }
        }
        /* A newly allocated wrapper has no active arm and must be freed
         * separately; an existing wrapper remains available to its owner. */
        if(choice_wrapper_allocated) {
            FREEMEM(*memb_ptr2);
            *memb_ptr2 = NULL;
        }
        return rv;
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
        ASN_DEBUG("Open Type %s->%s: type_selector returned presence_index=0",
                  td->name, elm->name);
        ASN__ENCODE_FAILED;
    }

    /* Validate selected type descriptor */
    if(!selected.type_descriptor) {
        ASN_DEBUG("Open Type %s->%s: type_selector returned NULL type descriptor",
                  td->name, elm->name);
        ASN__ENCODE_FAILED;
    }

    if(!selected.type_descriptor->op || !selected.type_descriptor->op->jer_encoder) {
        ASN_DEBUG("Open Type %s->%s: selected type %s has no JER encoder",
                  td->name, elm->name, selected.type_descriptor->name);
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
        /* CHOICE wrapper mode: get the actual member to encode */
        const asn_CHOICE_specifics_t *choice_specs = 
            (const asn_CHOICE_specifics_t *)elm->type->specifics;
        
        if(!choice_specs) {
            ASN_DEBUG("Open Type CHOICE wrapper has no specifics");
            ASN__ENCODE_FAILED;
        }
        
        /* Validate the selected variant */
        if(selected.presence_index == 0 || selected.presence_index > elm->type->elements_count) {
            ASN_DEBUG("Open Type %s->%s: presence index %u out of bounds (max %u)",
                      td->name, elm->name, selected.presence_index,
                      elm->type->elements_count);
            ASN__ENCODE_FAILED;
        }
        
        /* Get the element descriptor for the selected variant */
        const asn_TYPE_member_t *variant_elm = &elm->type->elements[selected.presence_index - 1];
        const void *variant_memb_ptr;
        
        /* Get pointer to the actual data */
        if(variant_elm->flags & ATF_POINTER) {
            variant_memb_ptr = *(const void *const *)((const char *)memb_ptr + variant_elm->memb_offset);
            if(!variant_memb_ptr) {
                ASN_DEBUG("Open Type %s->%s: variant data pointer is NULL",
                          td->name, elm->name);
                ASN__ENCODE_FAILED;
            }
        } else {
            variant_memb_ptr = (const void *)((const char *)memb_ptr + variant_elm->memb_offset);
        }
        
        /* Validate type descriptor match for safety */
        if(variant_elm->type && variant_elm->type != selected.type_descriptor) {
            ASN_DEBUG("Open Type %s->%s: WARNING - variant type %s != selected type %s",
                      td->name, elm->name, 
                      variant_elm->type->name, selected.type_descriptor->name);
        }
        
        /* 
         * ITU-T X.697 Clause 41: "The encoding of an open type value shall be 
         * the encoding of the value of the contained type."
         * Encode directly without type name wrapper.
         */
        ASN_DEBUG("Open Type CHOICE wrapper mode: encoding %s (variant %s) at offset %u, ATF_POINTER=%d", 
                  selected.type_descriptor->name, variant_elm->name,
                  variant_elm->memb_offset, !!(variant_elm->flags & ATF_POINTER));
        return selected.type_descriptor->op->jer_encoder(
            selected.type_descriptor, selected.type_descriptor->encoding_constraints.jer_constraints,
            variant_memb_ptr, ilevel, flags, cb, app_key);
    } else {
        /* 
         * Direct type mode: encode using the selected type descriptor directly.
         * ITU-T X.697 Clause 41: "The encoding of an open type value shall be 
         * the encoding of the value of the contained type."
         * No type name wrapper should be added.
         */
        ASN_DEBUG("Open Type direct mode: encoding %s, memb_ptr=%p, ATF_POINTER=%d", 
                  selected.type_descriptor->name, memb_ptr, !!(elm->flags & ATF_POINTER));
        return selected.type_descriptor->op->jer_encoder(
            selected.type_descriptor, selected.type_descriptor->encoding_constraints.jer_constraints,
            memb_ptr, ilevel, flags, cb, app_key);
    }
}
