/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <NativeInteger.h>

asn_dec_rval_t
NativeInteger_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                          const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints, void **sptr, asn_per_data_t *pd) {

    const asn_INTEGER_specifics_t *specs = (const asn_INTEGER_specifics_t *)td->specifics;
    asn_dec_rval_t rval;
    void *native = *sptr;
    INTEGER_t tmpint;
    void *tmpintptr = &tmpint;

    (void)opt_codec_ctx;
    ASN_DEBUG("Decoding NativeInteger %s (APER)", td->name);

    if(!native) {
        native = (*sptr = CALLOC(1, NativeInteger_field_width(specs)));
        if(!native) ASN__DECODE_FAILED;
    }

    memset(&tmpint, 0, sizeof tmpint);
    rval = INTEGER_decode_aper(opt_codec_ctx, td, constraints,
                               &tmpintptr, pd);
    if(rval.code == RC_OK) {
        if(NativeInteger_store_from_INTEGER(native, specs, &tmpint))
            rval.code = RC_FAIL;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &tmpint);

    return rval;
}

asn_enc_rval_t
NativeInteger_encode_aper(const asn_TYPE_descriptor_t *td,
                          const asn_per_constraints_t *constraints,
                          const void *sptr, asn_per_outp_t *po) {

    const asn_INTEGER_specifics_t *specs = (const asn_INTEGER_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0,0,0};
    INTEGER_t tmpint;

    if(!sptr) ASN__ENCODE_FAILED;

    ASN_DEBUG("Encoding NativeInteger %s (APER)", td->name);

    if(NativeInteger_to_INTEGER(sptr, specs, &tmpint))
        ASN__ENCODE_FAILED;
    er = INTEGER_encode_aper(td, constraints, &tmpint, po);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &tmpint);
    return er;
}
