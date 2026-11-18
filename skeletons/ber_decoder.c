/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>

#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {					\
		size_t num = num_bytes;					\
		ptr = ((const char *)ptr) + num;			\
		size -= num;						\
		consumed_myself += num;					\
	} while(0)
#undef	RETURN
#define	RETURN(_code)	do {						\
		asn_dec_rval_t rval;					\
		rval.code = _code;					\
		if(opt_ctx) opt_ctx->step = step; /* Save context */	\
		if(_code == RC_OK || opt_ctx)				\
			rval.consumed = consumed_myself;		\
		else							\
			rval.consumed = 0;	/* Context-free */	\
		return rval;						\
	} while(0)

/*
 * The BER decoder of any type.
 */
asn_dec_rval_t
ber_decode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *type_descriptor, void **struct_ptr,
           const void *ptr, size_t size) {
    asn_codec_ctx_t s_codec_ctx;

    /* Reject invalid public arguments before dispatching into type code. */
    if(!type_descriptor || !type_descriptor->op || !type_descriptor->op->ber_decoder || !struct_ptr
       || (size && !ptr)) {
        /* The descriptor may be absent, so do not use the td-based debug macro. */
        asn_dec_rval_t failure = {RC_FAIL, 0};
        return failure;
    }

	/*
	 * Stack checker requires that the codec context
	 * must be allocated on the stack.
	 */
	if(opt_codec_ctx) {
		if(opt_codec_ctx->max_stack_size) {
			s_codec_ctx = *opt_codec_ctx;
			opt_codec_ctx = &s_codec_ctx;
		}
	} else {
		/* If context is not given, be security-conscious anyway */
		memset(&s_codec_ctx, 0, sizeof(s_codec_ctx));
		s_codec_ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
		opt_codec_ctx = &s_codec_ctx;
	}

	/*
	 * Invoke type-specific decoder.
	 */
	return ASN__STRICT_DECODE_RESULT(type_descriptor, struct_ptr, ATS_BER,
        type_descriptor->op->ber_decoder(opt_codec_ctx, type_descriptor,
		struct_ptr,	/* Pointer to the destination structure */
		ptr, size,	/* Buffer and its size */
		0		/* Default tag mode is 0 */
		));
}

/*
 * Check the set of <TL<TL<TL...>>> tags matches the definition.
 */
asn_dec_rval_t
ber_check_tags(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td, asn_struct_ctx_t *opt_ctx,
               const void *ptr, size_t size, int tag_mode, int last_tag_form,
               ber_tlv_len_t *last_length, int *opt_tlv_form) {
    ssize_t consumed_myself = 0;
	ssize_t tag_len;
	ssize_t len_len;
	ber_tlv_tag_t tlv_tag;
	ber_tlv_len_t tlv_len;
	ber_tlv_len_t limit_len = -1;
	int expect_00_terminators = 0;
	int tlv_constr = -1;	/* If CHOICE, opt_tlv_form is not given */
	int step = opt_ctx ? opt_ctx->step : 0;	/* Where we left previously */
	int tagno;

	/*
	 * Make sure we didn't exceed the maximum stack size.
	 */
	if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
		RETURN(RC_FAIL);

	/*
	 * So what does all this implicit skip stuff mean?
	 * Imagine two types,
	 * 	A ::= [5] IMPLICIT	T
	 * 	B ::= [2] EXPLICIT	T
	 * Where T is defined as
	 *	T ::= [4] IMPLICIT SEQUENCE { ... }
	 * 
	 * Let's say, we are starting to decode type A, given the
	 * following TLV stream: <5> <0>. What does this mean?
	 * It means that the type A contains type T which is,
	 * in turn, empty.
	 * Remember though, that we are still in A. We cannot
	 * just pass control to the type T decoder. Why? Because
	 * the type T decoder expects <4> <0>, not <5> <0>.
	 * So, we must make sure we are going to receive <5> while
	 * still in A, then pass control to the T decoder, indicating
	 * that the tag <4> was implicitly skipped. The decoder of T
	 * hence will be prepared to treat <4> as valid tag, and decode
	 * it appropriately.
	 */

	tagno = step	/* Continuing where left previously */
		+ (tag_mode==1?-1:0)
		;
	ASN_DEBUG("ber_check_tags(%s, size=%ld, tm=%d, step=%d, tagno=%d)",
		td->name, (long)size, tag_mode, step, tagno);
	/* assert(td->tags_count >= 1) May not be the case for CHOICE or ANY */

	if(tag_mode == 0 && tagno == (int)td->tags_count) {
		/*
		 * This must be the _untagged_ ANY type,
		 * which outermost tag isn't known in advance.
		 * Fetch the tag and length separately.
		 */
		tag_len = ber_fetch_tag(ptr, size, &tlv_tag);
		switch(tag_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}
		tlv_constr = BER_TLV_CONSTRUCTED(ptr);
		len_len = ber_fetch_length(tlv_constr,
			(const char *)ptr + tag_len, size - tag_len, &tlv_len);
		switch(len_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}
		ASN_DEBUG("Advancing %ld in ANY case",
			(long)(tag_len + len_len));
		ADVANCE(tag_len + len_len);
	} else {
		assert(tagno < (int)td->tags_count);	/* At least one loop */
	}
	for((void)tagno; tagno < (int)td->tags_count; tagno++, step++) {

		/*
		 * Fetch and process T from TLV.
		 */
		tag_len = ber_fetch_tag(ptr, size, &tlv_tag);
			ASN_DEBUG("Fetching tag from {%p,%ld}: "
				"len %ld, step %d, tagno %d got %s",
				ptr, (long)size,
				(long)tag_len, step, tagno,
				ber_tlv_tag_string(tlv_tag));
		switch(tag_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}

		tlv_constr = BER_TLV_CONSTRUCTED(ptr);

		/*
		 * If {I}, don't check anything.
		 * If {I,B,C}, check B and C unless we're at I.
		 */
		if(tag_mode != 0 && step == 0) {
			/*
			 * We don't expect tag to match here.
			 * It's just because we don't know how the tag
			 * is supposed to look like.
			 */
		} else {
		    assert(tagno >= 0);	/* Guaranteed by the code above */
		    if(tlv_tag != td->tags[tagno]) {
			/*
			 * Unexpected tag. Too bad.
			 */
		    	ASN_DEBUG("Expected: %s, "
				"expectation failed (tn=%d, tm=%d)",
				ber_tlv_tag_string(td->tags[tagno]),
				tagno, tag_mode
			);
			RETURN(RC_FAIL);
		    }
		}

		/*
		 * Attention: if there are more tags expected,
		 * ensure that the current tag is presented
		 * in constructed form (it contains other tags!).
		 * If this one is the last one, check that the tag form
		 * matches the one given in descriptor.
		 */
		if(tagno < ((int)td->tags_count - 1)) {
			if(tlv_constr == 0) {
				ASN_DEBUG("tlv_constr = %d, expfail",
					tlv_constr);
				RETURN(RC_FAIL);
			}
		} else {
			if(last_tag_form != tlv_constr
			&& last_tag_form != -1) {
				ASN_DEBUG("last_tag_form %d != %d",
					last_tag_form, tlv_constr);
				RETURN(RC_FAIL);
			}
		}

		/*
		 * Fetch and process L from TLV.
		 */
		len_len = ber_fetch_length(tlv_constr,
			(const char *)ptr + tag_len, size - tag_len, &tlv_len);
		ASN_DEBUG("Fetching len = %ld", (long)len_len);
		switch(len_len) {
		case -1: RETURN(RC_FAIL);
		case 0: RETURN(RC_WMORE);
		}

		/*
		 * FIXME
		 * As of today, the chain of tags
		 * must either contain several indefinite length TLVs,
		 * or several definite length ones.
		 * No mixing is allowed.
		 */
		if(tlv_len == -1) {
			/*
			 * Indefinite length.
			 */
			if(limit_len == -1) {
				expect_00_terminators++;
			} else {
				ASN_DEBUG("Unexpected indefinite length "
					"in a chain of definite lengths");
				RETURN(RC_FAIL);
			}
			ADVANCE(tag_len + len_len);
			continue;
		} else {
			if(expect_00_terminators) {
				ASN_DEBUG("Unexpected definite length "
					"in a chain of indefinite lengths");
				RETURN(RC_FAIL);
			}
		}

		/*
		 * Check that multiple TLVs specify ever decreasing length,
		 * which is consistent.
		 */
		if(limit_len == -1) {
			limit_len    = tlv_len + tag_len + len_len;
			if(limit_len < 0) {
				/* Too great tlv_len value? */
				RETURN(RC_FAIL);
			}
		} else if(limit_len != tlv_len + tag_len + len_len) {
			/*
			 * Inner TLV specifies length which is inconsistent
			 * with the outer TLV's length value.
			 */
			ASN_DEBUG("Outer TLV is %ld and inner is %ld",
				(long)limit_len, (long)tlv_len);
			RETURN(RC_FAIL);
		}

		ADVANCE(tag_len + len_len);

		limit_len -= (tag_len + len_len);
		if((ssize_t)size > limit_len) {
			/*
			 * Make sure that we won't consume more bytes
			 * from the parent frame than the inferred limit.
			 */
			size = limit_len;
		}
	}

	if(opt_tlv_form)
		*opt_tlv_form = tlv_constr;
	if(expect_00_terminators)
		*last_length = -expect_00_terminators;
	else
		*last_length = tlv_len;

	RETURN(RC_OK);
}

static asn_dec_rval_t ber_tag_result(enum asn_dec_rval_code_e code,
                                    size_t consumed);

/*
 * State accumulated while parsing one bounded explicit tag chain.
 * Original source: New asn1c BER parser, based on X.690 8.1.3 and 8.1.5.
 * Version/date: 1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History/example: Added to keep explicit-wrapper parsing bounded and resumable.
 */
struct ber_explicit_chain_state {
    const uint8_t *cursor; /* state variable: current header position. */
    size_t size; /* state variable: bytes readable at cursor. */
    size_t consumed; /* state variable: header bytes already checked. */
    ber_tlv_len_t limit_len; /* state variable: remaining definite wrapper size. */
    ber_tlv_len_t last_length; /* state variable: innermost primitive content. */
    int eoc_count; /* state variable: indefinite wrappers awaiting EOCs. */
};

/*
 * Validate descriptor tags and constructed bits for one explicit-chain layer.
 * Original source: New asn1c helper, based on X.690 8.1.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td supplies natural tags; index/tag/form identify this layer.
 * Returns: RC_OK for a matching layer; otherwise RC_FAIL.
 * Errors: Mismatched natural tags or primitive/constructed form return failure.
 * Responsible party: asn1c maintainers. History/example: used by explicit parser.
 */
static enum asn_dec_rval_code_e
ber_validate_explicit_tag(const asn_TYPE_descriptor_t *td, int tag_index,
                          int is_unknown_wrapper, int is_final,
                          ber_tlv_tag_t tag, int constructed) {
    if(!is_unknown_wrapper && tag != td->tags[tag_index]) return RC_FAIL;
    if(is_final && constructed) return RC_FAIL;
    if(!is_final && !constructed) return RC_FAIL;
    return RC_OK;
}

/*
 * Record an indefinite wrapper after checking its position and tag form.
 * Original source: New asn1c helper, based on X.690 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state carries lengths/EOC count; index identifies chain depth.
 * Returns: RC_OK for an open wrapper; otherwise RC_FAIL.
 * Errors: Indefinite primitive/final layers and mixed bounded parents fail.
 * Responsible party: asn1c maintainers. History/example: counts wrapper EOCs.
 */
static enum asn_dec_rval_code_e
ber_accept_indefinite_layer(struct ber_explicit_chain_state *state,
                            int index, int final_index, int constructed) {
    if(!constructed) return RC_FAIL;
    if(state->limit_len != -1) return RC_FAIL;
    if(index == final_index) return RC_FAIL;
    state->eoc_count++;
    return RC_OK;
}

/*
 * Check a definite layer length against its parent and EOC position.
 * Original source: New asn1c helper, based on X.690 8.1.3 and 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state/index describe the layer; header_len/value_len are lengths.
 * Returns: RC_OK after recording a bounded value; otherwise RC_FAIL.
 * Errors: Overflow, inconsistent wrappers, or a nonfinal mixed layer fail.
 * Responsible party: asn1c maintainers. History/example: bounds nested TLVs.
 */
static enum asn_dec_rval_code_e
ber_accept_definite_layer(struct ber_explicit_chain_state *state, int index,
                          int final_index, size_t header_len,
                          ber_tlv_len_t value_len) {
    size_t total_len;
    size_t max_length = ((size_t)-1) >> 1;

    if(value_len < 0 || header_len > max_length) return RC_FAIL;
    if((size_t)value_len > max_length - header_len) return RC_FAIL;
    if(state->eoc_count && index != final_index) return RC_FAIL;
    total_len = header_len + (size_t)value_len;
    if(state->limit_len == -1) {
        state->limit_len = (ber_tlv_len_t)total_len;
    } else if((size_t)state->limit_len != total_len) {
        return RC_FAIL;
    }
    state->last_length = value_len;
    return RC_OK;
}

/*
 * Advance past a validated tag header and tighten its definite parent bound.
 * Original source: New asn1c helper, based on X.690 8.1.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: state receives header_len bytes of progress.
 * Returns: RC_OK after advancing; otherwise RC_FAIL on accounting overflow.
 * Errors: Header larger than input or consumed-count overflow fails.
 * Responsible party: asn1c maintainers. History/example: preserves input bounds.
 */
static enum asn_dec_rval_code_e
ber_advance_explicit_header(struct ber_explicit_chain_state *state,
                            size_t header_len) {
    if(header_len > state->size) return RC_FAIL;
    if(header_len > ((size_t)-1) - state->consumed) return RC_FAIL;
    state->cursor += header_len;
    state->size -= header_len;
    state->consumed += header_len;
    if(state->limit_len != -1) {
        state->limit_len -= (ber_tlv_len_t)header_len;
        if(state->size > (size_t)state->limit_len)
            state->size = (size_t)state->limit_len;
    }
    return RC_OK;
}

/*
 * Parse and validate a single explicit/natural tag and its length.
 * Original source: New asn1c BER parser, based on X.690 8.1.3 and 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td describes tags; state is updated for the indexed layer.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL without consuming caller input.
 * Errors: Invalid tag, form, length, or wrapper nesting returns RC_FAIL.
 * Responsible party: asn1c maintainers. History/example: one parser iteration.
 */
static enum asn_dec_rval_code_e
ber_check_explicit_layer(const asn_TYPE_descriptor_t *td,
                         struct ber_explicit_chain_state *state, int index,
                         int layer_count, int tag_mode) {
    ber_tlv_tag_t tag;
    ssize_t tag_len = ber_fetch_tag(state->cursor, state->size, &tag);
    ssize_t len_len;
    size_t header_len;
    int constructed;
    int is_unknown_wrapper = tag_mode != 0 && index == 0;
    int tag_index = index - (tag_mode == 1);
    int is_final = index == layer_count - 1;
    enum asn_dec_rval_code_e code;

    if(tag_len < 0) return RC_FAIL;
    if(tag_len == 0) return RC_WMORE;
    constructed = BER_TLV_CONSTRUCTED(state->cursor);
    code = ber_validate_explicit_tag(td, tag_index, is_unknown_wrapper,
                                     is_final, tag, constructed);
    if(code != RC_OK) return code;
    len_len = ber_fetch_length(constructed,
                               (const char *)state->cursor + tag_len,
                               state->size - (size_t)tag_len,
                               &state->last_length);
    if(len_len < 0) return RC_FAIL;
    if(len_len == 0) return RC_WMORE;
    if(!constructed && ((const uint8_t *)state->cursor)[tag_len] == 0x80)
        return RC_FAIL;
    header_len = (size_t)tag_len + (size_t)len_len;
    if(state->last_length == -1) {
        code = ber_accept_indefinite_layer(state, index,
                                           layer_count - 1, constructed);
    } else {
        code = ber_accept_definite_layer(state, index,
                                         layer_count - 1, header_len,
                                         state->last_length);
    }
    if(code != RC_OK) return code;
    return ber_advance_explicit_header(state, header_len);
}

/*
 * Parse a mixed-length explicit chain ending in a primitive TLV.
 * Original source: New asn1c BER parser, based on X.690 8.1.3 and 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td provides descriptor tags; ptr/size bound input; tag_mode 1
 *             adds an unknown wrapper, while -1 skips the first tag identity.
 *             Outputs report header bytes, primitive content length, and EOCs.
 * Returns: RC_OK for a valid bounded header chain, RC_WMORE or RC_FAIL.
 * Errors: Rejects excessive depth, mismatched tags/forms, and bad lengths.
 * Responsible party: asn1c maintainers. History: Added for explicit scalars.
 * Example: parses `[5] EXPLICIT INTEGER` with an indefinite `[5]` wrapper.
 */
static asn_dec_rval_t
ber_check_primitive_explicit_tags(const asn_TYPE_descriptor_t *td,
                                  const void *ptr, size_t size,
                                  ber_tlv_len_t *last_length,
                                  int *opt_eoc_count, int tag_mode) {
    struct ber_explicit_chain_state state; /* state variable: parsed headers. */
    enum asn_dec_rval_code_e code;
    int index; /* state variable: current explicit/natural tag layer. */
    int extra_wrapper = tag_mode == 1;
    int layer_count;

    if(!td || !td->tags || td->tags_count == 0
    || td->tags_count
        > (unsigned)(BER_EXPLICIT_TAG_DEPTH_LIMIT - extra_wrapper)
    || (!ptr && size))
        return ber_tag_result(RC_FAIL, 0);
    layer_count = (int)td->tags_count + extra_wrapper;
    memset(&state, 0, sizeof(state));
    state.cursor = (const uint8_t *)ptr;
    state.size = size;
    state.limit_len = -1;
    for(index = 0; index < layer_count; index++) {
        code = ber_check_explicit_layer(td, &state, index, layer_count,
                                        tag_mode);
        if(code != RC_OK) return ber_tag_result(code, 0);
    }
    *last_length = state.last_length;
    *opt_eoc_count = state.eoc_count;
    return ber_tag_result(RC_OK, state.consumed);
}

/*
 * Construct a decoder result without repeating result-field assignments.
 * Original source: New local BER parser utility.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: code is the BER status; consumed is validated header bytes.
 * Returns: A complete asn_dec_rval_t value.
 * Errors: None; the code argument carries the parse outcome.
 * Responsible party: asn1c maintainers. History: Added for explicit scalars.
 * Example: returns RC_WMORE with zero consumed bytes for a partial header.
 */
static asn_dec_rval_t
ber_tag_result(enum asn_dec_rval_code_e code, size_t consumed) {
    asn_dec_rval_t rval;
    rval.code = code;
    rval.consumed = consumed;
    return rval;
}

/*
 * Check tags and expose EOC wrappers for primitive decoder families.
 * Original source: New asn1c BER helper, retaining ber_check_tags ABI.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: Same as ber_check_tags plus opt_eoc_count output.
 * Returns: Header-check result; last_length is the innermost value length.
 * Errors: RC_WMORE for partial input; RC_FAIL for invalid wrappers or tags.
 * Responsible party: asn1c maintainers. History: Added for CER explicit scalars.
 * Example: returns the payload size and one EOC for `[5] EXPLICIT INTEGER`.
 */
asn_dec_rval_t
ber_check_tags_ex(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, asn_struct_ctx_t *opt_ctx,
                  const void *ptr, size_t size, int tag_mode,
                  int last_tag_form, ber_tlv_len_t *last_length,
                  int *opt_eoc_count, int *opt_tlv_form) {
    asn_dec_rval_t rval;

    if(!td || !opt_eoc_count || !last_length || tag_mode < -1 || tag_mode > 1
    || (!ptr && size))
        return ber_tag_result(RC_FAIL, 0);
    *opt_eoc_count = 0;
    if((tag_mode == 1 || td->tags_count > 0)
    && last_tag_form == 0 && !opt_ctx) {
        if(ASN__STACK_OVERFLOW_CHECK(opt_codec_ctx))
            return ber_tag_result(RC_FAIL, 0);
        rval = ber_check_primitive_explicit_tags(td, ptr, size, last_length,
                                                 opt_eoc_count, tag_mode);
        if(rval.code == RC_OK && opt_tlv_form) *opt_tlv_form = 0;
        return rval;
    }
    rval = ber_check_tags(opt_codec_ctx, td, opt_ctx, ptr, size, tag_mode,
                          last_tag_form, last_length, opt_tlv_form);
    if(rval.code == RC_OK && *last_length < 0)
        *opt_eoc_count = (int)-*last_length;
    return rval;
}

/*
 * Validate EOC octets following a definite primitive value.
 * Original source: New asn1c BER helper, following X.690 8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ptr/size bound value+suffix; length and count describe them.
 * Returns: RC_OK after exact zero-pair validation, RC_WMORE or RC_FAIL.
 * Errors: Negative values, overflow, or nonzero suffix bytes return RC_FAIL.
 * Responsible party: asn1c maintainers. History: Added for explicit wrappers.
 * Example: validates `00 00` after a primitive's value octets.
 */
enum asn_dec_rval_code_e
ber_check_eoc_suffix(const void *ptr, size_t size, ber_tlv_len_t length,
                     int eoc_count, size_t *opt_eoc_size) {
    const uint8_t *bytes = (const uint8_t *)ptr;
    size_t value_size;
    size_t eoc_size;
    size_t index; /* state variable: current EOC pair being validated. */

    if(opt_eoc_size) *opt_eoc_size = 0;
    if(!ptr && size) return RC_FAIL;
    if(length < 0 || eoc_count < 0) return RC_FAIL;
    value_size = (size_t)length;
    if(value_size > size) return RC_WMORE;
    if((size_t)eoc_count > ((size_t)-1) / 2) return RC_FAIL;
    eoc_size = (size_t)eoc_count * 2;
    if(eoc_size > size - value_size) return RC_WMORE;
    for(index = 0; index < eoc_size; index += 2) {
        if(bytes[value_size + index] != 0
        || bytes[value_size + index + 1] != 0) return RC_FAIL;
    }
    if(opt_eoc_size) *opt_eoc_size = eoc_size;
    return RC_OK;
}

/*
 * Check primitive tags and bound both value and explicit EOC suffix.
 * Original source: New asn1c BER helper, following X.690 8.1.3/8.1.5.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ptr/size are advanced to contents; length/eoc_size are outputs.
 * Returns: Header-byte consumption when all content and EOCs are present.
 * Errors: RC_WMORE for truncation; RC_FAIL for invalid headers or EOC bytes.
 * Responsible party: asn1c maintainers. History: Added for primitive wrappers.
 * Example: common preflight for BOOLEAN, INTEGER, NULL, and REAL decoders.
 */
asn_dec_rval_t
ber_check_primitive_tags(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, const void **ptr,
                         size_t *size, int tag_mode,
                         ber_tlv_len_t *length, size_t *eoc_size) {
    asn_dec_rval_t rval;
    int eoc_count = 0;
    const uint8_t *value_ptr;

    if(!ptr || !size || !length || !eoc_size || (!*ptr && *size))
        return ber_tag_result(RC_FAIL, 0);
    rval = ber_check_tags_ex(opt_codec_ctx, td, 0, *ptr, *size, tag_mode, 0,
                             length, &eoc_count, 0);
    if(rval.code != RC_OK) return rval;
    if(rval.consumed > *size || *length < 0)
        return ber_tag_result(RC_FAIL, 0);
    value_ptr = (const uint8_t *)*ptr + rval.consumed;
    rval.code = ber_check_eoc_suffix(value_ptr, *size - rval.consumed,
                                     *length, eoc_count, eoc_size);
    if(rval.code != RC_OK) return ber_tag_result(rval.code, 0);
    *ptr = value_ptr;
    *size -= rval.consumed;
    return rval;
}
