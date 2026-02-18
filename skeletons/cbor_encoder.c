/*
 * Copyright (c) 2024 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cbor_encoder.h>
#include <errno.h>

/*
 * The CBOR encoder for any type. May be invoked by the application.
 */
asn_enc_rval_t
cbor_encode(const asn_TYPE_descriptor_t *type_descriptor,
            const void *struct_ptr,
            asn_app_consume_bytes_f *consume_bytes, void *app_key) {
    const asn_TYPE_descriptor_t *td = type_descriptor;
    const void *sptr = struct_ptr;
    ASN_DEBUG("CBOR encoder invoked for %s", td->name);

    if(!td->op->cbor_encoder) {
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }

    return td->op->cbor_encoder(
        td, 0,
        sptr,
        consume_bytes, app_key);
}

/*
 * Argument type and callback necessary for cbor_encode_to_buffer().
 */
typedef struct enc_to_buf_arg {
    void *buffer;
    size_t left;
} enc_to_buf_arg;

static int
encode_to_buffer_cb(const void *buffer, size_t size, void *key) {
    enc_to_buf_arg *arg = (enc_to_buf_arg *)key;

    if(arg->left < size) return -1;

    memcpy(arg->buffer, buffer, size);
    arg->buffer = ((char *)arg->buffer) + size;
    arg->left -= size;

    return 0;
}

asn_enc_rval_t
cbor_encode_to_buffer(const asn_TYPE_descriptor_t *type_descriptor,
                      const asn_cbor_constraints_t *constraints,
                      const void *struct_ptr,
                      void *buffer, size_t buffer_size) {
    enc_to_buf_arg arg;
    asn_enc_rval_t ec;

    arg.buffer = buffer;
    arg.left = buffer_size;

    if(!type_descriptor->op->cbor_encoder) {
        ec.encoded = -1;
        ec.failed_type = type_descriptor;
        ec.structure_ptr = struct_ptr;
    } else {
        ec = type_descriptor->op->cbor_encoder(
            type_descriptor, constraints,
            struct_ptr,
            encode_to_buffer_cb, &arg);
        if(ec.encoded != -1) {
            assert(ec.encoded == (ssize_t)(buffer_size - arg.left));
        }
    }
    return ec;
}
