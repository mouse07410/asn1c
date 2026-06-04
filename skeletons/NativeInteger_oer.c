/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeInteger.h>

asn_dec_rval_t
NativeInteger_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td,
                         const asn_oer_constraints_t *constraints,
                         void **nint_ptr, const void *ptr, size_t size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    asn_dec_rval_t rval = {RC_OK, 0};
    void *native = *nint_ptr;
    INTEGER_t tmpint;
    INTEGER_t *tmpintptr = &tmpint;

    memset(&tmpint, 0, sizeof(tmpint));

    if(!native) {
        native = (*nint_ptr = CALLOC(1, NativeInteger_field_width(specs)));
        if(!native) ASN__DECODE_FAILED;
    }

    rval = INTEGER_decode_oer(opt_codec_ctx, td, constraints,
                              (void **)&tmpintptr, ptr, size);
    if(rval.code != RC_OK) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &tmpint);
        return rval;
    }

    {
        int ok = (NativeInteger_store_from_INTEGER(native, specs, &tmpint) == 0);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &tmpint);
        if(!ok) {
            rval.code = RC_FAIL;
            return rval;
        }
    }

    return rval;
}

/*
 * Encode as Canonical OER.
 */
asn_enc_rval_t
NativeInteger_encode_oer(const asn_TYPE_descriptor_t *td,
                         const asn_oer_constraints_t *constraints,
                         const void *sptr, asn_app_consume_bytes_f *cb,
                         void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    INTEGER_t tmpint;

    if(!sptr) ASN__ENCODE_FAILED;

    if(NativeInteger_to_INTEGER(sptr, specs, &tmpint)) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &tmpint);
        ASN__ENCODE_FAILED;
    } else {
        asn_enc_rval_t er =
            INTEGER_encode_oer(td, constraints, &tmpint, cb, app_key);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &tmpint);
        return er;
    }
}
