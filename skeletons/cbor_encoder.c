/*-
 * Copyright (c) 2025 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cbor_encoder.h>

/*
 * Purpose: dispatch an ASN.1 value to its CBOR encoder.
 * Source: existing CBOR codec dispatch. Version: 2026-10-30.
 * Inputs: td identifies the type; sptr is the value; cb/app_key consume bytes.
 * Returns: encoded byte count or failure. Errors: invalid inputs and missing
 * codec operations fail before dispatch. Author: asn1c maintainers.
 * History: added descriptor and callback validation.
 * Example: cbor_encode(&asn_DEF_INTEGER, &value, sink, context).
 */
asn_enc_rval_t
cbor_encode(const asn_TYPE_descriptor_t *td, const void *sptr,
            asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};

    if(!td || !td->op || !sptr || !cb || !td->op->cbor_encoder) {
        ASN__ENCODE_FAILED;
    }

    er = td->op->cbor_encoder(td, sptr, cb, app_key);
    return er;
}
