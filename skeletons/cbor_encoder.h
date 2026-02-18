/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * CBOR (Concise Binary Object Representation) encoder.
 * RFC 7049 (original), RFC 8949 (STD 94, update).
 */
#ifndef CBOR_ENCODER_H
#define CBOR_ENCODER_H

#include <asn_application.h>
#include <cbor_support.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;  /* Forward declaration */

/*
 * The CBOR encoder for any ASN.1 type. May be invoked by the application.
 * Produces Canonical CBOR output (RFC 8949).
 */
asn_enc_rval_t cbor_encode(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr, /* Structure to be encoded */
    asn_app_consume_bytes_f *consume_bytes_cb,
    void *app_key /* Arbitrary callback argument */
);

/*
 * A variant of cbor_encode() which encodes data into a pre-allocated buffer.
 */
asn_enc_rval_t cbor_encode_to_buffer(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const asn_cbor_constraints_t *constraints,
    const void *struct_ptr, /* Structure to be encoded */
    void *buffer,           /* Pre-allocated buffer */
    size_t buffer_size      /* Maximum buffer size */
);

/*
 * Type of the generic CBOR encoder function.
 */
typedef asn_enc_rval_t(cbor_type_encoder_f)(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const asn_cbor_constraints_t *constraints,
    const void *struct_ptr,                    /* Structure to be encoded */
    asn_app_consume_bytes_f *consume_bytes_cb, /* Callback */
    void *app_key                              /* Arbitrary callback argument */
);

#ifdef __cplusplus
}
#endif

#endif  /* CBOR_ENCODER_H */
