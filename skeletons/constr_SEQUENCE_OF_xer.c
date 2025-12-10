/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE_OF.h>
#include <asn_SEQUENCE_OF.h>

/*
 * SEQUENCE OF XER decoder with preprocessing to handle ASN.1 keyword wrapper tags.
 * 
 * This implementation wraps SET_OF_decode_xer but first checks for and skips
 * ASN.1 meta-syntax wrapper tags like <SEQUENCE OF> that may appear in
 * debug-annotated XER files but are not part of the standard XER encoding.
 */
asn_dec_rval_t
SEQUENCE_OF_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                       const asn_TYPE_descriptor_t *td, void **struct_ptr,
                       const char *opt_mname, const void *buf_ptr, size_t size) {
    asn_dec_rval_t rval;
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;
    const char *buf = (const char *)buf_ptr;
    size_t consumed_myself = 0;
    
    /* Parse through leading whitespace and comments to find the first tag */
    while(size > 0) {
        /* Skip whitespace */
        while(size > 0 && (*buf == ' ' || *buf == '\t' || *buf == '\r' || *buf == '\n')) {
            buf++;
            size--;
            consumed_myself++;
        }
        
        if(size == 0) break;
        
        /* Check for XML comments */
        if(size >= 4 && buf[0] == '<' && buf[1] == '!' && buf[2] == '-' && buf[3] == '-') {
            /* Find end of comment */
            const char *p = buf + 4;
            size_t remaining = size - 4;
            while(remaining >= 3) {
                if(p[0] == '-' && p[1] == '-' && p[2] == '>') {
                    size_t comment_len = (p - buf) + 3;
                    buf += comment_len;
                    size -= comment_len;
                    consumed_myself += comment_len;
                    break;
                }
                p++;
                remaining--;
            }
            if(remaining < 3) {
                /* Incomplete comment, let SET_OF_decode_xer handle it */
                break;
            }
            continue;
        }
        
        /* Check for ASN.1 keyword wrapper tag like <SEQUENCE OF> */
        if(size > 2 && buf[0] == '<' && buf[1] != '/' && buf[1] != '!') {
            /* Look for the tag name */
            const char *tag_start = buf + 1;
            const char *tag_end = tag_start;
            while(tag_end < buf + size && *tag_end != '>' && *tag_end != ' ' 
                  && *tag_end != '\t' && *tag_end != '\r' && *tag_end != '\n' && *tag_end != '/') {
                tag_end++;
            }
            
            /* Check if this matches "SEQUENCE OF" or "SEQUENCE-OF" */
            /* Note: tag_start points after '<', so we compare 11 characters of tag content (the part between '<' and '>') */
            /* The full tag including angle brackets is 13 characters: "<SEQUENCE OF>" or "<SEQUENCE-OF>" */
            if((tag_end - tag_start >= 11) && (tag_start + 11 <= buf + size) &&
               (strncmp(tag_start, "SEQUENCE OF", 11) == 0 || 
                strncmp(tag_start, "SEQUENCE-OF", 11) == 0)) {
                /* Find the end of the opening tag */
                const char *close = tag_end;
                while(close < buf + size && *close != '>') {
                    close++;
                }
                if(close < buf + size) {
                    size_t tag_len = (close - buf) + 1;
                    ASN_DEBUG("SEQUENCE_OF_decode_xer: Skipping ASN.1 keyword wrapper tag");
                    buf += tag_len;
                    size -= tag_len;
                    consumed_myself += tag_len;
                    continue;
                }
            }
        }
        
        /* No more preprocessing needed */
        break;
    }
    
    /* Call the standard SET_OF decoder with adjusted buffer */
    rval = SET_OF_decode_xer(opt_codec_ctx, td, struct_ptr, xml_tag, buf, size);
    
    /* Adjust consumed count to include what we skipped */
    if(rval.code != RC_FAIL) {
        rval.consumed += consumed_myself;
    }
    
    return rval;
}

asn_enc_rval_t
SEQUENCE_OF_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                       int ilevel, enum xer_encoder_flags_e flags,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    /*
     * XER Encoding of SEQUENCE OF:
     * 
     * IMPORTANT: This encoder outputs ONLY the member elements, NOT wrapper tags
     * like <SEQUENCE OF>. Such wrapper tags are ASN.1 meta-syntax and are NOT
     * part of the XER encoding standard (ITU-T X.693).
     * 
     * CORRECT XER encoding for SEQUENCE OF Integer { 1, 2, 3 } with member name "item":
     *   <item>1</item>
     *   <item>2</item>
     *   <item>3</item>
     * 
     * INCORRECT (would include meta-syntax wrapper tags):
     *   <SEQUENCE OF>
     *     <item>1</item>
     *     <item>2</item>
     *     <item>3</item>
     *   </SEQUENCE OF>
     * 
     * The decoder has been made tolerant to gracefully skip such wrapper tags
     * if they appear in debug-annotated or malformed XER input files, but this
     * encoder never outputs them.
     */
    asn_enc_rval_t er = {0,0,0};
    const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_sequence_ *list = _A_CSEQUENCE_FROM_VOID(sptr);
    const char *mname;
    
    if(specs->as_XMLValueList) {
        mname = 0;
    } else {
        if(!elm) {
            ASN_DEBUG("SEQUENCE OF has no element type descriptor");
            ASN__ENCODE_FAILED;
        }
        mname = (*elm->name) ? elm->name : elm->type->xml_tag;
        
        /* Check if mname contains ASN.1 meta-syntax keywords that should not be output */
        if(mname) {
            size_t len = strlen(mname);
            /* Check for "SEQUENCE OF" or "SEQUENCE-OF" followed by space, hyphen, uppercase, or end */
            if((len >= 11 && strncmp(mname, "SEQUENCE OF", 11) == 0 &&
                (len == 11 || mname[11] == ' ' || mname[11] == '-' || (mname[11] >= 'A' && mname[11] <= 'Z'))) ||
               (len >= 11 && strncmp(mname, "SEQUENCE-OF", 11) == 0 &&
                (len == 11 || mname[11] == ' ' || mname[11] == '-' || (mname[11] >= 'A' && mname[11] <= 'Z'))) ||
               (len >= 6 && strncmp(mname, "SET OF", 6) == 0 &&
                (len == 6 || mname[6] == ' ' || mname[6] == '-' || (mname[6] >= 'A' && mname[6] <= 'Z'))) ||
               (len >= 6 && strncmp(mname, "SET-OF", 6) == 0 &&
                (len == 6 || mname[6] == ' ' || mname[6] == '-' || (mname[6] >= 'A' && mname[6] <= 'Z')))) {
                /* This is an ASN.1 keyword wrapper tag - use element type instead */
                mname = elm->type->xml_tag;  /* Use the element type's tag instead */
            }
        }
    }
    size_t mlen = mname ? strlen(mname) : 0;
    int xcan = (flags & XER_F_CANONICAL);
    int i;

    if(!sptr) ASN__ENCODE_FAILED;

    er.encoded = 0;

    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t tmper = {0,0,0};
        void *memb_ptr = list->array[i];
        if(!memb_ptr) continue;

        if(mname) {
            if(!xcan) ASN__TEXT_INDENT(1, ilevel);
            ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);
        }

        tmper = elm->type->op->xer_encoder(elm->type, memb_ptr, ilevel + 1,
                                           flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
        if(tmper.encoded == 0 && specs->as_XMLValueList) {
            const char *name = elm->type->xml_tag;
            size_t len = strlen(name);
            if(!xcan) ASN__TEXT_INDENT(1, ilevel + 1);
            ASN__CALLBACK3("<", 1, name, len, "/>", 2);
        }

        if(mname) {
            ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
        }
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
