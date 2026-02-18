/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cbor_decoder.h>
#include <errno.h>

/*
 * The CBOR decoder for any type. May be invoked by the application.
 */
asn_dec_rval_t
cbor_decode(const asn_codec_ctx_t *opt_codec_ctx,
            const asn_TYPE_descriptor_t *type_descriptor,
            void **struct_ptr, const void *buffer, size_t size) {
    const asn_TYPE_descriptor_t *td = type_descriptor;
    ASN_DEBUG("CBOR decoder invoked for %s", td->name);

    if(!td->op->cbor_decoder) {
        errno = ENOENT;
        ASN__DECODE_FAILED;
    }

    return td->op->cbor_decoder(
        opt_codec_ctx, td, 0,
        struct_ptr, buffer, size);
}
