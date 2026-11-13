/*-
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <cbor_support.h>

/* Fixed float storage used to check encode/decode equivalence. */
struct float_output {
    uint8_t bytes[9]; /* Encoded float bytes. */
    size_t size; /* Number of bytes written. */
};

/*
 * Purpose: collect a single float encoding in bounded local storage.
 * Source: repository fuzz harness. Version: 2026-11-12.
 * Inputs: data/size are emitted bytes; key points to float_output.
 * Returns: zero or -1 on overflow; no exceptions. Author: asn1c maintainers.
 * History: initial harness. Example: cbor_encode_float(value, collect, &out).
 */
static int
collect(const void *data, size_t size, void *key) {
    struct float_output *out = (struct float_output *)key;
    if(size > sizeof(out->bytes) - out->size) return -1;
    memcpy(out->bytes + out->size, data, size);
    out->size += size;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

/*
 * Purpose: fuzz structural scanning and all CBOR floating-point widths.
 * Source: RFC 8949 codec invariants. Version: 2026-11-12.
 * Inputs: data/size are arbitrary fuzz bytes. Returns: zero; assertions abort
 * on codec invariant violations, no exceptions. Author: asn1c maintainers.
 * History: initial bounded CBOR fuzz target. Example: libFuzzer invokes it.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ssize_t used = cbor_skip_item(data, size);
    double value, decoded;
    struct float_output out;
    assert(used == -1 || (used > 0 && (size_t)used <= size));

    /* Decode arbitrary float prefixes, then require exact preferred round trips. */
    if(cbor_decode_float(data, size, &value) > 0) {
        memset(&out, 0, sizeof(out));
        used = cbor_encode_float(value, collect, &out);
        assert(used > 0 && (size_t)used == out.size);
        assert(cbor_decode_float(out.bytes, out.size, &decoded) == used);
        assert(isnan(value) ? isnan(decoded) : value == decoded);
        if(value == 0.0) assert((signbit(value) != 0) == (signbit(decoded) != 0));
    }
    return 0;
}
