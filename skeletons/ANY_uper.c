/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ANY.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#undef RETURN
#define RETURN(_code)                       \
    do {                                    \
        asn_dec_rval_t tmprval;             \
        tmprval.code = _code;               \
        tmprval.consumed = consumed_myself; \
        return tmprval;                     \
    } while(0)

/*
 * Purpose: Decode a PER open-type payload into ABI-compatible ANY storage.
 * Original source: asn1c ANY PER decoder. Version: 2026-10-30.
 * Parameters: codec context and constraints are unused; td describes storage;
 *             sptr receives the value; pd supplies the encoded bit stream.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL and the number of payload bits read.
 * Errors: Invalid descriptors, oversized payloads, and allocation failure fail.
 * Responsible party: asn1c maintainers.
 * History: Check signed size and bit count before allocation and arithmetic.
 * Example: A zero-length envelope yields an empty, terminated payload.
 */
asn_dec_rval_t
ANY_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, void **sptr,
                asn_per_data_t *pd) {
    const asn_OCTET_STRING_specifics_t *specs;
    size_t consumed_myself = 0;
    ANY_t *st;
    int repeat;

    (void)opt_codec_ctx;
    (void)constraints;
    if(!td || !sptr || !pd) RETURN(RC_FAIL);
    specs = td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                          : &asn_SPC_ANY_specs;
    if(specs->struct_size < sizeof(ANY_t)
       || specs->ctx_offset != offsetof(ANY_t, _asn_ctx)) RETURN(RC_FAIL);
    st = (ANY_t *)*sptr;
    if(st && (st->size < 0 || (st->size > 0 && !st->buf))) RETURN(RC_FAIL);
    if(!st) {
        st = (ANY_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) RETURN(RC_FAIL);
    }

    /* Decode fragments using checked arithmetic before growing the buffer. */
    st->size = 0;
    do {
        ssize_t raw_len = uper_get_length(pd, -1, 0, &repeat);
        size_t length;
        uint8_t *buffer;
        if(raw_len < 0) RETURN(RC_WMORE);
        length = (size_t)raw_len;
        if(length > (size_t)INT_MAX - (size_t)st->size
           || length > (size_t)INT_MAX / 8
           || length > (SIZE_MAX - consumed_myself) / 8) RETURN(RC_FAIL);
        buffer = (uint8_t *)REALLOC(st->buf, (size_t)st->size + length + 1);
        if(!buffer) RETURN(RC_FAIL);
        st->buf = buffer;
        if(per_get_many_bits(pd, st->buf + st->size, 0, (int)(length * 8)))
            RETURN(RC_WMORE);
        consumed_myself += length * 8;
        st->size += (int)length;
    } while(repeat);
    st->buf[st->size] = 0;
    RETURN(RC_OK);
}

asn_enc_rval_t
ANY_encode_uper(const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, const void *sptr,
                asn_per_outp_t *po) {
    const ANY_t *st = (const ANY_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    const uint8_t *buf;
    size_t size;
    int ret;

    (void)constraints;

    if(!td || !po || !st || st->size < 0 || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    buf = st->buf;
    size = st->size;
    do {
        int need_eom = 0;
        ssize_t may_save = uper_put_length(po, size, &need_eom);
        if(may_save < 0) ASN__ENCODE_FAILED;

        ret = per_put_many_bits(po, buf, may_save * 8);
        if(ret) ASN__ENCODE_FAILED;

        if(may_save) buf += may_save;
        size -= may_save;
        assert(!(may_save & 0x07) || !size);
        if(need_eom && uper_put_length(po, 0, 0))
            ASN__ENCODE_FAILED; /* End of Message length */
    } while(size);

    ASN__ENCODED_OK(er);
}
