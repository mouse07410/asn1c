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
 * Purpose: Replace an ANY payload with an APER encoding of a typed value.
 * Source: asn1c APER ANY conversion. Version: 2026-10-30.
 * Parameters: st is the destination, td describes sptr, and sptr is nullable.
 * Returns: 0 on success, -1 on invalid arguments, encoding failure or overflow.
 * Errors: An oversized encoding is freed without replacing the destination.
 * Responsible party: asn1c maintainers. History: Validate the signed size field.
 * Example: Passing a null sptr clears both the buffer and its length.
 */
int
ANY_fromType_aper(ANY_t *st, asn_TYPE_descriptor_t *td, void *sptr) {
    uint8_t *buffer = NULL;
    ssize_t erval;

    if(!st || !td) {
        errno = EINVAL;
        return -1;
    }

    if(!sptr) {
        if(st->buf) FREEMEM(st->buf);
        st->buf = NULL;
        st->size = 0;
        return 0;
    }

    erval = aper_encode_to_new_buffer(td, td->encoding_constraints.per_constraints, sptr, (void**)&buffer);

    if(erval < 0 || (size_t)erval > INT_MAX) {
        if(buffer) FREEMEM(buffer);
        return -1;
    }
    assert((size_t)erval > 0);

    if(st->buf) FREEMEM(st->buf);
    st->buf = buffer;
    st->size = (int)erval;

    return 0;
}

ANY_t *
ANY_new_fromType_aper(asn_TYPE_descriptor_t *td, void *sptr) {
    ANY_t tmp;
    ANY_t *st;

    if(!td || !sptr) {
        errno = EINVAL;
        return 0;
    }

    memset(&tmp, 0, sizeof(tmp));

    if(ANY_fromType_aper(&tmp, td, sptr)) return 0;

    st = (ANY_t *)CALLOC(1, sizeof(ANY_t));
    if(st) {
        *st = tmp;
        return st;
    } else {
        FREEMEM(tmp.buf);
        return 0;
    }
}

int
ANY_to_type_aper(ANY_t *st, asn_TYPE_descriptor_t *td, void **struct_ptr) {
    asn_dec_rval_t rval;
    void *newst = 0;

    if(!st || !td || !struct_ptr) {
        errno = EINVAL;
        return -1;
    }

    if(st->buf == 0) {
        /* Nothing to convert, make it empty. */
        *struct_ptr = (void *)0;
        return 0;
    }

    rval = aper_decode(0, td, (void **)&newst, st->buf, st->size, 0, 0);
    if(rval.code == RC_OK) {
        *struct_ptr = newst;
        return 0;
    } else {
        /* Remove possibly partially decoded data. */
        ASN_STRUCT_FREE(*td, newst);
        return -1;
    }
}

int
ANY_to_type_aper_checked(ANY_t *st, asn_TYPE_descriptor_t *td, void **struct_ptr) {
 	return ANY_to_type_aper(st, td, struct_ptr) == 0 && *struct_ptr != 0 ? 0 : -1;
}

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
ANY_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
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
        ssize_t raw_len = aper_get_length(pd, -1, -1, -1, &repeat);
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

/*
 * Purpose: Encode ANY payload octets using APER length determinants.
 * Original source: Existing asn1c ANY APER encoder, hardened for empty values.
 * Version: 2026-10-22.
 * Parameters: td identifies ANY; constraints are unused; sptr is ANY_t; po is
 *             the destination APER bit stream.
 * Returns: Encoding result, with encoded set to -1 for invalid values or I/O.
 * Errors: Negative size, missing payload storage, or output errors fail.
 * Responsible party: asn1c runtime maintainers.
 * History: Empty ANY is emitted as a zero-length envelope for issue #586.
 * Example: Used to emit opaque payload octets as exactly one open-type envelope.
 */
asn_enc_rval_t
ANY_encode_aper(const asn_TYPE_descriptor_t *td,
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
    if(size == 0) {
        if(aper_put_length(po, -1, -1, 0, NULL) < 0) ASN__ENCODE_FAILED;
        ASN__ENCODED_OK(er);
    }
    do {
        int need_eom = 0;
        ssize_t may_save = aper_put_length(po, -1, -1, size, &need_eom);
        if(may_save <= 0) ASN__ENCODE_FAILED;

        ret = per_put_many_bits(po, buf, may_save * 8);
        if(ret) ASN__ENCODE_FAILED;

        buf += may_save;
        size -= may_save;
        assert(!(may_save & 0x07) || !size);
        if(need_eom && aper_put_length(po, -1, -1, 0, NULL))
            ASN__ENCODE_FAILED; /* End of Message length */
    } while(size);

    ASN__ENCODED_OK(er);
}
