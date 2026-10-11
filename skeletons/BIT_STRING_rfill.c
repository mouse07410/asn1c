/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BIT_STRING.h>

struct asn_random_buffer {
    uint8_t *data;
    size_t size;
    size_t allocated;
};

static int
asn_random_buffer_append(const void *data, size_t size, void *key) {
    struct asn_random_buffer *buffer = (struct asn_random_buffer *)key;
    if(size > SIZE_MAX - buffer->size) return -1;
    if(buffer->size + size > buffer->allocated) {
        size_t allocated = buffer->allocated ? buffer->allocated : 16;
        while(allocated < buffer->size + size) {
            if(allocated > SIZE_MAX / 2) {
                allocated = buffer->size + size;
                break;
            }
            allocated *= 2;
        }
        void *p = REALLOC(buffer->data, allocated);
        if(!p) return -1;
        buffer->data = (uint8_t *)p;
        buffer->allocated = allocated;
    }
    memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    return 0;
}

static asn_random_fill_result_t
BIT_STRING_random_fill_containing(
                                  const asn_TYPE_descriptor_t *contained_type,
                                  void **sptr, size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 0};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    struct asn_random_buffer buffer = {0, 0, 0};
    void *contained_value = 0;
    BIT_STRING_t *st;
    asn_enc_rval_t erv;
    ssize_t encoded_bits;
    int syntax = asn_random_fill_current_syntax();

    if(asn_random_fill_with_syntax(contained_type, &contained_value,
                                   max_length, syntax) != 0) {
        goto fail;
    }

    switch(syntax) {
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER:
        erv = uper_encode(contained_type, 0, contained_value,
                          asn_random_buffer_append, &buffer);
        encoded_bits = erv.encoded;
        break;
#endif
#if !defined(ASN_DISABLE_APER_SUPPORT)
    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER:
        erv = aper_encode(contained_type, 0, contained_value,
                          asn_random_buffer_append, &buffer);
        encoded_bits = erv.encoded;
        break;
#endif
    default: {
        asn_encode_to_new_buffer_result_t encoded =
            asn_encode_to_new_buffer(0, (enum asn_transfer_syntax)syntax,
                                     contained_type, contained_value);
        erv = encoded.result;
        buffer.data = (uint8_t *)encoded.buffer;
        buffer.size = erv.encoded < 0 ? 0 : (size_t)erv.encoded;
        buffer.allocated = buffer.size + 1;
        encoded_bits = erv.encoded < 0 ? -1 : (ssize_t)(buffer.size * 8);
        break;
    }
    }

    if(erv.encoded < 0 || encoded_bits < 0) goto fail;
    if(encoded_bits == 0) {
        uint8_t zero = 0;
        if(asn_random_buffer_append(&zero, 1, &buffer) < 0) goto fail;
        encoded_bits = 8;
    }
    if(buffer.size > max_length
       || buffer.size != ((size_t)encoded_bits + 7) / 8) {
        goto skipped;
    }

    if(contained_value) {
        ASN_STRUCT_FREE(*contained_type, contained_value);
        contained_value = 0;
    }
    if(*sptr) {
        st = (BIT_STRING_t *)*sptr;
        FREEMEM(st->buf);
    } else {
        st = (BIT_STRING_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) goto fail;
    }
    st->buf = buffer.data;
    st->size = buffer.size;
    st->bits_unused = (8 - (encoded_bits & 7)) & 7;
    if(st->bits_unused) {
        st->buf[st->size - 1] &= (uint8_t)(0xff << st->bits_unused);
    }
    result_ok.length = st->size;
    return result_ok;

skipped:
    if(contained_value) {
        ASN_STRUCT_FREE(*contained_type, contained_value);
    }
    FREEMEM(buffer.data);
    return result_skipped;

fail:
    if(contained_value) {
        ASN_STRUCT_FREE(*contained_type, contained_value);
    }
    FREEMEM(buffer.data);
    return result_failed;
}

asn_random_fill_result_t
BIT_STRING_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                       const asn_encoding_constraints_t *constraints,
                       size_t max_length) {
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_BIT_STRING_specs;
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    static unsigned lengths[] = {0,     1,     2,     3,     4,     8,
                                 126,   127,   128,   16383, 16384, 16385,
                                 65534, 65535, 65536, 65537};
    uint8_t *buf;
    uint8_t *bend;
    uint8_t *b;
    size_t rnd_bits, rnd_len;
    BIT_STRING_t *st;

    if(max_length == 0) return result_skipped;
    if(constraints && constraints->contained_type) {
        return BIT_STRING_random_fill_containing(
            constraints->contained_type, sptr, max_length);
    } else if(td->encoding_constraints.contained_type) {
        return BIT_STRING_random_fill_containing(
            td->encoding_constraints.contained_type, sptr, max_length);
    }

    switch(specs->subvariant) {
    case ASN_OSUBV_ANY:
        return result_failed;
    case ASN_OSUBV_BIT:
        break;
    default:
        break;
    }

    /* Figure out how far we should go */
    rnd_bits = lengths[asn_random_between(
        0, sizeof(lengths) / sizeof(lengths[0]) - 1)];
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
    if(!constraints || !constraints->per_constraints)
        constraints = &td->encoding_constraints;
    if(constraints->per_constraints) {
        const asn_per_constraint_t *pc = &constraints->per_constraints->size;
        if(pc->flags & APC_CONSTRAINED) {
            long suggested_upper_bound = pc->upper_bound < (ssize_t)max_length
                                             ? pc->upper_bound
                                             : (ssize_t)max_length;
            if(max_length < (size_t)pc->lower_bound) {
                return result_skipped;
            }
            if(pc->flags & APC_EXTENSIBLE) {
                switch(asn_random_between(0, 5)) {
                case 0:
                    if(pc->lower_bound > 0) {
                        rnd_bits = pc->lower_bound - 1;
                        break;
                    }
                    /* Fall through */
                case 1:
                    rnd_bits = pc->upper_bound + 1;
                    break;
                case 2:
                    /* Keep rnd_bits from the table */
                    if(rnd_bits < max_length) {
                        break;
                    }
                    /* Fall through */
                default:
                    rnd_bits = asn_random_between(pc->lower_bound,
                                                  suggested_upper_bound);
                }
            } else {
                rnd_bits =
                    asn_random_between(pc->lower_bound, suggested_upper_bound);
            }
        } else {
            rnd_bits = asn_random_between(0, max_length - 1);
        }
    } else {
#else
    if(!constraints) constraints = &td->encoding_constraints;
    {
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
        if(rnd_bits >= max_length) {
            rnd_bits = asn_random_between(0, max_length - 1);
        }
    }

    rnd_len = (rnd_bits + 7) / 8;
    buf = CALLOC(1, rnd_len + 1);
    if(!buf) return result_failed;

    bend = &buf[rnd_len];

    for(b = buf; b < bend; b++) {
        *(uint8_t *)b = asn_random_between(0, 255);
    }
    *b = 0; /* Zero-terminate just in case. */

    if(*sptr) {
        st = *sptr;
        FREEMEM(st->buf);
    } else {
        st = (BIT_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) {
            FREEMEM(buf);
            return result_failed;
        }
    }

    st->buf = buf;
    st->size = rnd_len;
    st->bits_unused = (8 - (rnd_bits & 0x7)) & 0x7;
    if(st->bits_unused) {
        assert(st->size > 0);
        st->buf[st->size-1] &= 0xff << st->bits_unused;
    }

    result_ok.length = st->size;
    return result_ok;
}
