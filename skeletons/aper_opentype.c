/*
 * Copyright (c) 2007 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <aper_encoder.h>
#include <aper_support.h>
#include <aper_opentype.h>

static asn_dec_rval_t
aper_open_type_get_simple(const asn_codec_ctx_t *ctx,
                          const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints, void **sptr, asn_per_data_t *pd) {
	asn_dec_rval_t rv;
	ssize_t chunk_bytes;
	int repeat;
	uint8_t *buf = 0;
	size_t bufLen = 0;
	size_t bufSize = 0;
	asn_per_data_t spd;
	size_t padding;

	ASN__STACK_OVERFLOW_CHECK(ctx);

	ASN_DEBUG("Getting open type %s...", td->name);

	do {
	        chunk_bytes = aper_get_length(pd, -1, -1, -1, &repeat);
		if(chunk_bytes < 0) {
			FREEMEM(buf);
			ASN__DECODE_STARVED;
		}
		if(bufLen + chunk_bytes > bufSize) {
			void *ptr;
			bufSize = chunk_bytes + (bufSize << 2);
			ptr = REALLOC(buf, bufSize);
			if(!ptr) {
				FREEMEM(buf);
				ASN__DECODE_FAILED;
			}
			buf = ptr;
		}
		if(per_get_many_bits(pd, buf ? buf + bufLen : NULL, 0, chunk_bytes << 3)) {
			FREEMEM(buf);
			ASN__DECODE_STARVED;
		}
		bufLen += chunk_bytes;
	} while(repeat);

	ASN_DEBUG("Getting open type %s encoded in %ld bytes", td->name,
		(long)bufLen);

	memset(&spd, 0, sizeof(spd));
	spd.buffer = buf;
	spd.nbits = bufLen << 3;

	ASN_DEBUG_INDENT_ADD(+4);
	rv = td->op->aper_decoder(ctx, td, constraints, sptr, &spd);
	ASN_DEBUG_INDENT_ADD(-4);

	if(rv.code == RC_OK) {
		/* Check padding validity */
		padding = spd.nbits - spd.nboff;
                if (((padding > 0 && padding < 8) ||
		/* X.691#10.1.3 */
		(spd.nboff == 0 && spd.nbits == 8 && spd.buffer == buf)) &&
                    per_get_few_bits(&spd, padding) == 0) {
			/* Everything is cool */
			FREEMEM(buf);
			return rv;
		}
		FREEMEM(buf);
		if(padding >= 8) {
			ASN_DEBUG("Too large padding %d in open type", (int)padding);
			ASN__DECODE_FAILED;
		} else {
			ASN_DEBUG("No padding");
		}
	} else {
		FREEMEM(buf);
		/* rv.code could be RC_WMORE, nonsense in this context */
		rv.code = RC_FAIL; /* Noone would give us more */
	}

	return rv;
}

int
aper_open_type_put(const asn_TYPE_descriptor_t *td,
                   const asn_per_constraints_t *constraints,
                   const void *sptr, asn_per_outp_t *po) {
	void *buf;
	void *bptr;
	ssize_t size;
	size_t toGo;

	ASN_DEBUG("Open type put %s ...", td->name);

	size = aper_encode_to_new_buffer(td, constraints, sptr, &buf);
	if(size <= 0) return -1;

	for(bptr = buf, toGo = size; toGo;) {
        int need_eom = 0;
		ssize_t maySave = aper_put_length(po, -1, -1, toGo, &need_eom);
		if(maySave < 0) break;
		if(per_put_many_bits(po, bptr, maySave * 8)) break;
		bptr = (char *)bptr + maySave;
		toGo -= maySave;
        if(need_eom && (aper_put_length(po, -1, -1, 0, NULL) < 0)) {
            FREEMEM(buf);
            return -1;
        }
	}

	FREEMEM(buf);
	if(toGo) return -1;

	ASN_DEBUG("Open type put %s of length %zd + overhead (1byte?)",
			  td->name, size);

	return 0;
}

asn_dec_rval_t
aper_open_type_get(const asn_codec_ctx_t *ctx,
                   const asn_TYPE_descriptor_t *td,
                   const asn_per_constraints_t *constraints,
                   void **sptr, asn_per_data_t *pd) {

	return aper_open_type_get_simple(ctx, td, constraints, sptr, pd);
}

/*
 * Purpose: skip an unknown APER open type while preserving decode status.
 * Source: Existing aper_open_type_skip implementation.
 * Version/date: 2026-10-30.
 * Inputs: ctx provides decoder limits; pd is the encoded open type input.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL from the APER open-type decoder.
 * Errors: A null input fails; malformed input and truncation retain status.
 * Author: asn1c maintainers. History: Added a status-preserving interface.
 * Example: A short open-type payload returns RC_WMORE.
 */
asn_dec_rval_t
aper_open_type_skip_result(const asn_codec_ctx_t *ctx, asn_per_data_t *pd) {
	asn_TYPE_descriptor_t s_td;
	asn_TYPE_operation_t op_t;
	if(!pd) {
		asn_dec_rval_t invalid = {RC_FAIL, 0};
		return invalid;
	}
	memset(&s_td, 0, sizeof(s_td));
	memset(&op_t, 0, sizeof(op_t));
	s_td.name = "<unknown extension>";
	s_td.op = &op_t;
	op_t.aper_decoder = uper_sot_suck;
	return aper_open_type_get(ctx, &s_td, 0, 0, pd);
}

/*
 * Purpose: skip an APER open type through the legacy integer interface.
 * Source: aper_open_type_skip_result.
 * Version/date: 2026-10-30.
 * Inputs: ctx and pd follow the APER open-type decoder API.
 * Returns: zero on success, -1 for truncation or malformed data.
 * Errors: Detailed decoder status is available from aper_open_type_skip_result.
 * Author: asn1c maintainers. History: Retained for ABI compatibility.
 * Example: A complete open type returns zero.
 */
int
aper_open_type_skip(const asn_codec_ctx_t *ctx, asn_per_data_t *pd) {
	return aper_open_type_skip_result(ctx, pd).code == RC_OK ? 0 : -1;
}
