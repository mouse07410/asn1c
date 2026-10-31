/*
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <cbor_encoder.h>
#include <cbor_decoder.h>

/*
 * Purpose: validate presence storage in an open CHOICE wrapper.
 * Source: asn_CHOICE_specifics_t. Version: 2026-10-30.
 * Inputs: specs is the wrapper layout. Returns: zero if valid or -1.
 * Errors: malformed layouts fail. Author: asn1c maintainers.
 * History: extracted CBOR open storage validation. Example: a missing presence field fails.
 */
static int
OPEN_TYPE_cbor_choice_valid(const asn_CHOICE_specifics_t *specs) {
    if(!specs || !specs->struct_size
       || (specs->pres_size != sizeof(char) && specs->pres_size != sizeof(short)
           && specs->pres_size != sizeof(int))
       || specs->pres_offset > specs->struct_size
       || specs->pres_size > specs->struct_size - specs->pres_offset) return -1;
    return 0;
}

/*
 * Purpose: validate the complete parent and selected open-value storage spans.
 * Source: generated SET/SEQUENCE, CHOICE, and built-in type layouts.
 * Version: 2026-10-30. Inputs: parent and member describe the enclosing slot;
 * selected identifies the IOC arm. Returns: zero if bounded, otherwise -1.
 * Errors: invalid metadata and unknown inline widths fail. Author: maintainers.
 * History: adapted from OER storage preflight. Example: a truncated inline arm fails.
 */
static int
OPEN_TYPE_cbor_storage_valid(const asn_TYPE_descriptor_t *parent,
                             const asn_TYPE_member_t *member,
                             asn_type_selector_result_t selected) {
    size_t parent_size, member_size, selected_size = 0, slot_size;
    const asn_TYPE_member_t *slot = member;
    size_t owner_size;
    int selected_status;
    if(!parent || !parent->op || !parent->specifics || !member || !member->type
       || !selected.type_descriptor || !selected.presence_index) return -1;
    if(parent->op->kind == ASN_KIND_SET)
        parent_size = ((const asn_SET_specifics_t *)parent->specifics)->struct_size;
    else if(parent->op->kind == ASN_KIND_SEQUENCE)
        parent_size = ((const asn_SEQUENCE_specifics_t *)parent->specifics)->struct_size;
    else return -1;
    if(member->type->elements_count) {
        const asn_CHOICE_specifics_t *specs = member->type->specifics;
        if(OPEN_TYPE_cbor_choice_valid(specs) || !member->type->elements
           || selected.presence_index > member->type->elements_count) return -1;
        slot = &member->type->elements[selected.presence_index - 1];
        if(slot->type != selected.type_descriptor) return -1;
        owner_size = specs->struct_size;
        member_size = (member->flags & ATF_POINTER) ? sizeof(void *) : owner_size;
    } else {
        if(member->type != selected.type_descriptor) return -1;
        owner_size = parent_size;
        member_size = 0;
    }
    selected_status = SET_inline_value_size(selected.type_descriptor, &selected_size);
    if(selected_status && (!(slot->flags & ATF_POINTER) || selected_status != -2)) return -1;
    slot_size = (slot->flags & ATF_POINTER) ? sizeof(void *) : selected_size;
    if(!member->type->elements_count) member_size = slot_size;
    if(member->memb_offset > parent_size || member_size > parent_size - member->memb_offset
       || slot->memb_offset > owner_size || slot_size > owner_size - slot->memb_offset) return -1;
    return 0;
}

/*
 * Purpose: decode a table-selected CBOR value into its open-type wrapper.
 * Source: asn1c IOC selector and CHOICE ownership contracts. Version: 2026-10-30.
 * Inputs: opt_codec_ctx limits recursion, td/sptr describe the parent,
 * elm selects its open member, and ptr/size bound encoded input.
 * Returns: child decode result. Errors: malformed selector or child data fails.
 * Author: asn1c maintainers. History: partial arms are attached before cleanup.
 * Example: a failed pointer-backed selected SEQUENCE is freed with its wrapper.
 */
asn_dec_rval_t
OPEN_TYPE_cbor_get(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td,
                   void *sptr, const asn_TYPE_member_t *elm,
                   const void *ptr, size_t size) {
    asn_type_selector_result_t selected;
    void *memb_ptr;   /* Pointer to the member */
    void **memb_ptr2; /* Pointer to that pointer */
    void *inner_value;
    asn_dec_rval_t rv;

    if(!td || !sptr || !elm || (!ptr && size) || !(elm->flags & ATF_OPEN_TYPE)) {
        ASN__DECODE_FAILED;
    }

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
       || !selected.type_descriptor->op || !selected.type_descriptor->op->cbor_decoder
       || OPEN_TYPE_cbor_storage_valid(td, elm, selected)) {
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

    if(elm->type->elements_count > 0) {
        /* CHOICE wrapper mode */
        const asn_CHOICE_specifics_t *specs =
            (const asn_CHOICE_specifics_t *)elm->type->specifics;
        const asn_TYPE_member_t *variant_elm;
        unsigned int memb_offset;

        if(!specs || !specs->struct_size
           || (specs->pres_size != sizeof(char) && specs->pres_size != sizeof(short)
               && specs->pres_size != sizeof(int))
           || specs->pres_offset > specs->struct_size
           || specs->pres_size > specs->struct_size - specs->pres_offset) {
            ASN__DECODE_FAILED;
        }

        if(selected.presence_index > elm->type->elements_count) {
            ASN_DEBUG("Open Type %s->%s: presence index %u out of bounds",
                      td->name, elm->name, selected.presence_index);
            ASN__DECODE_FAILED;
        }

        if(!elm->type->elements) {
            ASN_DEBUG("Open Type %s->%s: elements array is NULL",
                      td->name, elm->name);
            ASN__DECODE_FAILED;
        }

        if(*memb_ptr2 == NULL) {
            *memb_ptr2 = CALLOC(1, specs->struct_size);
            if(*memb_ptr2 == NULL) {
                ASN__DECODE_FAILED;
            }
        } else {
            if(CHOICE_variant_set_presence(elm->type, *memb_ptr2, 0) != 0) {
                ASN__DECODE_FAILED;
            }
        }

        variant_elm = &elm->type->elements[selected.presence_index - 1];
        memb_offset = variant_elm->memb_offset;
        if(variant_elm->type != selected.type_descriptor || memb_offset >= specs->struct_size
           || ((variant_elm->flags & ATF_POINTER)
               && sizeof(void *) > specs->struct_size - memb_offset)
           || CHOICE_variant_set_presence(elm->type, *memb_ptr2, selected.presence_index)) {
            ASN__DECODE_FAILED;
        }

        if(variant_elm->flags & ATF_POINTER) {
            inner_value = *(void **)((char *)*memb_ptr2 + memb_offset);
        } else {
            inner_value = (char *)*memb_ptr2 + memb_offset;
        }
    } else {
        /* Direct type mode */
        inner_value = *memb_ptr2;
    }

    if(!selected.type_descriptor->op->cbor_decoder) {
        ASN_DEBUG("Open Type %s->%s: selected type %s has no CBOR decoder",
                  td->name, elm->name, selected.type_descriptor->name);
        ASN__DECODE_FAILED;
    }

    rv = selected.type_descriptor->op->cbor_decoder(
        opt_codec_ctx, selected.type_descriptor, &inner_value, ptr, size);

    /* Attach the partially decoded arm before cleanup can free the wrapper. */
    if(elm->type->elements_count > 0) {
        const asn_TYPE_member_t *variant = &elm->type->elements[selected.presence_index - 1];
        if(variant->flags & ATF_POINTER) {
            *(void **)((char *)*memb_ptr2 + variant->memb_offset) = inner_value;
        }
    } else if(elm->flags & ATF_POINTER) {
        *memb_ptr2 = inner_value;
    }

    switch(rv.code) {
    case RC_OK:
        break;
    case RC_FAIL:
    case RC_WMORE:
        if(elm->type->elements_count > 0) {
            /*
             * CHOICE-wrapper mode: *memb_ptr2 points to the CHOICE wrapper
             * (type elm->type). Do not free inner_value directly — it may
             * refer to embedded storage inside the wrapper. Free or reset
             * the wrapper as a whole instead.
             */
            if(*memb_ptr2) {
                if(elm->flags & ATF_POINTER) {
                    ASN_STRUCT_FREE(*elm->type, *memb_ptr2);
                    *memb_ptr2 = NULL;
                } else {
                    ASN_STRUCT_RESET(*elm->type, *memb_ptr2);
                }
            }
        } else {
            /*
             * Direct type mode: inner_value is the instance of the selected
             * type. Clean it up using selected.type_descriptor.
             */
            if(inner_value) {
                if(elm->flags & ATF_POINTER) {
                    ASN_STRUCT_FREE(*selected.type_descriptor, inner_value);
                    *memb_ptr2 = NULL;
                } else {
                    ASN_STRUCT_RESET(*selected.type_descriptor, inner_value);
                }
            }
        }
        return rv;
    }

    return rv;
}

/*
 * Purpose: encode an open value using its parent table selector.
 * Source: asn1c IOC selector and CBOR child encoder contracts.
 * Version: 2026-10-30. Inputs: td/sptr describe parent, elm selects its member,
 * cb/app_key receive bytes. Returns: child encoder result or failure.
 * Errors: missing selector, value, or codec fails. Author: asn1c maintainers.
 * History: parent-aware CBOR open dispatch. Example: encode a selected BOOLEAN.
 */
asn_enc_rval_t
OPEN_TYPE_cbor_put(const asn_TYPE_descriptor_t *td, const void *sptr,
                   const asn_TYPE_member_t *elm,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    asn_type_selector_result_t selected;
    const void *memb_ptr;

    if(!td || !sptr || !elm || !cb || !(elm->flags & ATF_OPEN_TYPE)) {
        ASN__ENCODE_FAILED;
    }

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

    if(!selected.type_descriptor) {
        ASN_DEBUG("Open Type %s->%s: type_selector returned NULL type descriptor",
                  td->name, elm->name);
        ASN__ENCODE_FAILED;
    }

    if(OPEN_TYPE_cbor_storage_valid(td, elm, selected)) ASN__ENCODE_FAILED;

    if(!selected.type_descriptor->op || !selected.type_descriptor->op->cbor_encoder) {
        ASN_DEBUG("Open Type %s->%s: selected type %s has no CBOR encoder",
                  td->name, elm->name, selected.type_descriptor->name);
        ASN__ENCODE_FAILED;
    }

    /* Fetch the pointer to this member */
    assert(elm->flags & ATF_OPEN_TYPE);
    if(elm->flags & ATF_POINTER) {
        memb_ptr = *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
    }

    if(elm->type->elements_count > 0) {
        /* CHOICE wrapper mode */
        const asn_TYPE_member_t *variant_elm;
        const void *variant_memb_ptr;

        if(selected.presence_index == 0
           || selected.presence_index > elm->type->elements_count) {
            ASN_DEBUG("Open Type %s->%s: presence index %u out of bounds",
                      td->name, elm->name, selected.presence_index);
            ASN__ENCODE_FAILED;
        }

        if(CHOICE_variant_get_presence(elm->type, memb_ptr) != selected.presence_index)
            ASN__ENCODE_FAILED;
        variant_elm = &elm->type->elements[selected.presence_index - 1];

        if(variant_elm->flags & ATF_POINTER) {
            variant_memb_ptr =
                *(const void *const *)((const char *)memb_ptr
                                       + variant_elm->memb_offset);
            if(!variant_memb_ptr) {
                ASN_DEBUG("Open Type %s->%s: variant data pointer is NULL",
                          td->name, elm->name);
                ASN__ENCODE_FAILED;
            }
        } else {
            variant_memb_ptr =
                (const void *)((const char *)memb_ptr + variant_elm->memb_offset);
        }

        return selected.type_descriptor->op->cbor_encoder(
            selected.type_descriptor, variant_memb_ptr, cb, app_key);
    } else {
        /* Direct type mode */
        return selected.type_descriptor->op->cbor_encoder(
            selected.type_descriptor, memb_ptr, cb, app_key);
    }
}
