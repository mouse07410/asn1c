/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * CBOR (Concise Binary Object Representation) decoder.
 * RFC 7049 (original), RFC 8949 (STD 94, update).
 */
#ifndef CBOR_DECODER_H
#define CBOR_DECODER_H

#include <asn_application.h>
#include <cbor_support.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;  /* Forward declaration */
struct asn_codec_ctx_s;        /* Forward declaration */

/*
 * Type of the generic CBOR decoder function.
 */
typedef asn_dec_rval_t(cbor_type_decoder_f)(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const asn_cbor_constraints_t *constraints,
    void **struct_ptr,
    const void *buf_ptr,
    size_t size);

/*
 * The CBOR decoder for any ASN.1 type. May be invoked by the application.
 * Parses Canonical CBOR and Basic CBOR (RFC 8949).
 */
asn_dec_rval_t cbor_decode(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of that buffer */
);

#ifdef __cplusplus
}
#endif

#endif  /* CBOR_DECODER_H */
