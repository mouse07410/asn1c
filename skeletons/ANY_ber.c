/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ANY.h>
#include <errno.h>
#include <limits.h>

struct _callback_arg {
    uint8_t *buffer;
    size_t offset;
    size_t size;
};

/*
 * Purpose: Append DER output while bounding the public ANY signed length.
 * Source: Existing ANY DER callback. Version: 2026-10-30.
 * Inputs: buffer/size are emitted bytes; key holds the accumulating buffer.
 * Returns: zero on success, -1 on overflow, invalid bytes or allocation failure.
 * Errors: Payloads above INT_MAX are rejected. Author: maintainers.
 * History: Replaced unchecked allocation arithmetic.
 * Example: Appending bytes preserves the existing prefix.
 */
static int ANY__consume_bytes(const void *buffer, size_t size, void *key) {
    struct _callback_arg *arg = (struct _callback_arg *)key;
    size_t required;
    void *replacement;
    if(!arg || (size && !buffer) || arg->offset > INT_MAX
    || size > (size_t)INT_MAX - arg->offset) return -1;
    required = arg->offset + size + 1;
    if(required > arg->size) {
        replacement = REALLOC(arg->buffer, required);
        if(!replacement) return -1;
        arg->buffer = (uint8_t *)replacement;
        arg->size = required;
    }
    if(size) memcpy(arg->buffer + arg->offset, buffer, size);
    arg->offset += size;
    return 0;
}

int
ANY_fromType(ANY_t *st, asn_TYPE_descriptor_t *td, void *sptr) {
    struct _callback_arg arg;
    asn_enc_rval_t erval = {0,0,0};

    if(!st || !td) {
        errno = EINVAL;
        return -1;
    }

    if(!sptr) {
        if(st->buf) FREEMEM(st->buf);
        st->buf = NULL;
        st->size = 0;
        return 0;
    }

    arg.offset = arg.size = 0;
    arg.buffer = 0;

    erval = der_encode(td, sptr, ANY__consume_bytes, &arg);
    if(erval.encoded == -1) {
        if(arg.buffer) FREEMEM(arg.buffer);
        return -1;
    }
    assert((size_t)erval.encoded == arg.offset);

    if(st->buf) FREEMEM(st->buf);
    st->buf = arg.buffer;
    st->size = (int)arg.offset;

    return 0;
}

ANY_t *
ANY_new_fromType(asn_TYPE_descriptor_t *td, void *sptr) {
    ANY_t tmp;
    ANY_t *st;

    if(!td || !sptr) {
        errno = EINVAL;
        return 0;
    }

    memset(&tmp, 0, sizeof(tmp));

    if(ANY_fromType(&tmp, td, sptr)) return 0;

    st = (ANY_t *)CALLOC(1, sizeof(ANY_t));
    if(st) {
        *st = tmp;
        return st;
    } else {
        FREEMEM(tmp.buf);
        return 0;
    }
}

int
ANY_to_type(ANY_t *st, asn_TYPE_descriptor_t *td, void **struct_ptr) {
    asn_dec_rval_t rval;
    void *newst = 0;

    if(!st || !td || !struct_ptr || st->size < 0
       || (st->size > 0 && !st->buf)) {
        errno = EINVAL;
        return -1;
    }

    if(st->buf == 0) {
        /* Nothing to convert, make it empty. */
        *struct_ptr = (void *)0;
        return 0;
    }

    rval = ber_decode(0, td, (void **)&newst, st->buf, st->size);
    if(rval.code == RC_OK) {
        *struct_ptr = newst;
        return 0;
    } else {
        /* Remove possibly partially decoded data. */
        ASN_STRUCT_FREE(*td, newst);
        return -1;
    }
}
