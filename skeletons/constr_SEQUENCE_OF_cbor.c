/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/* SEQUENCE OF shares SET OF's definite-array CBOR mapping and storage layout. */
#include <constr_SEQUENCE_OF.h>
#include <constr_SET_OF.h>

/*
 * Purpose: encode SEQUENCE OF with the shared validated CBOR array codec.
 * Source: SET OF CBOR array mapping. Version: 2026-10-30.
 * Inputs: td/sptr describe the collection; cb/app_key receive its bytes.
 * Returns: encoded byte count or failure. Errors: invalid values or callbacks.
 * Author: asn1c maintainers. History: shared hardened collection codec.
 * Example: SEQUENCE_OF_encode_cbor(td, value, append, key).
 */
asn_enc_rval_t
SEQUENCE_OF_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    return SET_OF_encode_cbor(td, sptr, cb, app_key);
}

/*
 * Purpose: decode SEQUENCE OF with the shared staged CBOR array codec.
 * Source: SET OF CBOR array mapping. Version: 2026-10-30.
 * Inputs: codec bounds recursion; td/sptr describe the target; buf/size bound input.
 * Returns: decoded prefix and byte count or failure. Errors: malformed input.
 * Author: asn1c maintainers. History: shared hardened collection codec.
 * Example: SEQUENCE_OF_decode_cbor(NULL, td, &value, bytes, length).
 */
asn_dec_rval_t
SEQUENCE_OF_decode_cbor(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                        void **sptr, const void *buf, size_t size) {
    return SET_OF_decode_cbor(codec, td, sptr, buf, size);
}
