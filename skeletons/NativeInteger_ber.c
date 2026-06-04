/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeInteger.h>
#include <INTEGER.h>

/*
 * Decode INTEGER type.
 */
asn_dec_rval_t
NativeInteger_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **nint_ptr,
                         const void *buf_ptr, size_t size, int tag_mode) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    void *native = *nint_ptr;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;

    /*
     * If the structure is not there, allocate it.
     */
    if(native == NULL) {
        native = (*nint_ptr = CALLOC(1, NativeInteger_field_width(specs)));
        if(native == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("Decoding %s as INTEGER (tm=%d)",
              td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_tags(opt_codec_ctx, td, 0, buf_ptr, size,
                          tag_mode, 0, &length, 0);
    if(rval.code != RC_OK)
        return rval;

    ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

    /*
     * Make sure we have this length.
     */
    buf_ptr = ((const char *)buf_ptr) + rval.consumed;
    size -= rval.consumed;
    if(length > (ber_tlv_len_t)size) {
        rval.code = RC_WMORE;
        rval.consumed = 0;
        return rval;
    }

    /*
     * ASN.1 encoded INTEGER: buf_ptr, length
     * Fill the native, at the same time checking for overflow.
     * If overflow occurred, return with RC_FAIL.
     */
    {
        INTEGER_t tmp;
        union {
            const void *constbuf;
            void *nonconstbuf;
        } unconst_buf;

        unconst_buf.constbuf = buf_ptr;
        tmp.buf = (uint8_t *)unconst_buf.nonconstbuf;
        tmp.size = length;

        if(NativeInteger_store_from_INTEGER(native, specs, &tmp)) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    rval.code = RC_OK;
    rval.consumed += length;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s",
              (long)rval.consumed, (long)length, td->name);

    return rval;
}

/*
 * Encode the NativeInteger using the standard INTEGER type DER encoder.
 */
asn_enc_rval_t
NativeInteger_encode_der(const asn_TYPE_descriptor_t *sd, const void *ptr,
                         int tag_mode, ber_tlv_tag_t tag,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_TYPE_descriptor_t *td = sd;  /* for ASN__ENCODE_FAILED */
    const void *sptr = ptr;                /* for ASN__ENCODE_FAILED */
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)sd->specifics;
    asn_enc_rval_t erval = {0,0,0};
    INTEGER_t tmp;

    /* Materialize the native member (any width) as a canonical INTEGER. */
    if(NativeInteger_to_INTEGER(ptr, specs, &tmp)) {
        ASN__ENCODE_FAILED;
    }

    erval = INTEGER_encode_der(sd, &tmp, tag_mode, tag, cb, app_key);
    if(erval.structure_ptr == &tmp) {
        erval.structure_ptr = ptr;
    }
    if(tmp.buf) FREEMEM(tmp.buf);
    return erval;
}
