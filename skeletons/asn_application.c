/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <asn_application.h>
#include <constraints.h>
#include <BIT_STRING.h>
#include <OCTET_STRING.h>
#include <errno.h>
#if !defined(ASN_DISABLE_BER_SUPPORT) && !defined(ASN_DISABLE_CER_SUPPORT)
#include <cer_encoder.h>
#include <cer_decoder.h>
#endif
#if !defined(ASN_DISABLE_APER_SUPPORT)
#include <aper_decoder.h>
#endif
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
#include <cbor_encoder.h>
#include <cbor_decoder.h>
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
#include <uper_decoder.h>
#endif

static asn_enc_rval_t asn_encode_internal(const asn_codec_ctx_t *opt_codec_ctx,
                                          enum asn_transfer_syntax syntax,
                                          const asn_TYPE_descriptor_t *td,
                                          const void *sptr,
                                          asn_app_consume_bytes_f *callback,
                                          void *callback_key);


/* Forward plaintext output while counting successfully consumed bytes. */
struct callback_count_bytes_key {
    asn_app_consume_bytes_f *callback; /* Application byte consumer. */
    void *callback_key; /* Opaque application callback context. */
    size_t computed_size; /* state variable: successfully consumed byte count. */
};

/*
 * Forward one plaintext chunk and count successful application consumption.
 * Source: existing asn1c plaintext callback. Version/date: documented 2026-10-11.
 * Inputs: data/size identify bytes; keyp contains callback, context, and count.
 * Returns: the application callback result; negative means output failure.
 * Errors: application-defined; no exceptions. Owner: asn1c maintainers.
 * History: original callback retained during CER dispatch refactoring.
 * Example: used by asn_encode_plaintext_family for printable values.
 */
static int
callback_count_bytes_cb(const void *data, size_t size, void *keyp) {
    struct callback_count_bytes_key *key = keyp;
    int ret;

    ret = key->callback(data, size, key->callback_key);
    if(ret >= 0) {
        key->computed_size += size;
    }

    return ret;
}

/* Caller-owned output window and total produced-byte accounting. */
struct overrun_encoder_key {
    void *buffer; /* Destination; NULL is permitted for a zero-sized window. */
    size_t buffer_size; /* Available destination bytes. */
    size_t computed_size; /* state variable: total bytes produced so far. */
};

/* Grow caller-owned output storage while retaining required-size accounting. */
struct dynamic_encoder_key {
    void *buffer; /* Allocated destination, NULL after allocation failure. */
    size_t buffer_size; /* state variable: destination allocation capacity. */
    size_t computed_size; /* state variable: total bytes produced by the codec. */
};

/* Preserve the application's callback and track its failure across codecs. */
struct callback_failure_catch_key {
    asn_app_consume_bytes_f *callback; /* Application byte consumer. */
    void *callback_key; /* Opaque application context. */
    int callback_failed; /* state variable: a negative callback was observed. */
};

/*
 * Copy the available output prefix while counting the complete encoding.
 * Source: asn1c generic buffer callback, hardened for atomic CER output.
 * Version/date: 2026-10-11. Inputs: data/size are the encoder's byte span;
 * keyp points to the destination window and accumulated byte count.
 * Returns: zero on success, -1 on unrepresentable size or invalid byte span.
 * Errors: EOVERFLOW or EINVAL; no exceptions. Responsible: asn1c maintainers.
 * History: preserve partial chunks and check addition before copying.
 * Example: asn_encode_to_buffer(NULL, ATS_CER, td, value, out, 1).
 */
static int
overrun_encoder_cb(const void *data, size_t size, void *keyp) {
    struct overrun_encoder_key *key = keyp;
    size_t copy_size = 0;

    /* Count only representable byte spans; never form an overflowing sum. */
    if(size > (((size_t)-1) >> 1) - key->computed_size) {
        errno = EOVERFLOW;
        return -1;
    }
    if(size && !data) {
        errno = EINVAL;
        return -1;
    }

    /* Keep the prefix even when one callback exceeds the remaining window. */
    if(key->computed_size < key->buffer_size) {
        copy_size = key->buffer_size - key->computed_size;
        if(copy_size > size) copy_size = size;
    }
    if(copy_size) {
        memcpy((char *)key->buffer + key->computed_size, data, copy_size);
    }
    key->computed_size += size;

    return 0;
}

/*
 * Append dynamically allocated output and retain counts on allocation failure.
 * Source: existing asn1c dynamic callback. Version/date: documented 2026-10-11.
 * Inputs: data/size identify bytes; keyp stores destination and byte accounting.
 * Returns: zero, including when allocation fails and only counting continues.
 * Errors: allocation may leave buffer NULL; no exceptions.
 * Owner: asn1c maintainers. History: legacy allocation contract retained.
 * Example: used by asn_encode_to_new_buffer to collect generated bytes.
 */
static int
dynamic_encoder_cb(const void *data, size_t size, void *keyp) {
    struct dynamic_encoder_key *key = keyp;

    if(key->buffer) {
        if(key->computed_size + size >= key->buffer_size) {
            void *p;
            size_t new_size = key->buffer_size;

            do {
                new_size *= 2;
            } while(new_size <= key->computed_size + size);

            p = REALLOC(key->buffer, new_size);
            if(p) {
                key->buffer = p;
                key->buffer_size = new_size;
            } else {
                FREEMEM(key->buffer);
                key->buffer = 0;
                key->buffer_size = 0;
                key->computed_size += size;
                return 0;
            }
        }
        memcpy((char *)key->buffer + key->computed_size, data, size);
    }

    key->computed_size += size;

    return 0;
}

/*
 * Record application callback failures for generic EIO reporting.
 * Source: asn1c generic callback wrapper. Version/date: 2026-10-11.
 * Inputs: data/size describe bytes; keyp holds the callback and opaque key.
 * Returns: the application's callback result. Errors: callback-defined;
 * asn_encode maps negative results to EIO. No exceptions.
 * Responsible: asn1c maintainers. History: documented for CER integration.
 * Example: called internally by asn_encode(..., application_callback, key).
 */
static int
callback_failure_catch_cb(const void *data, size_t size, void *keyp) {
    struct callback_failure_catch_key *key = keyp;
    int ret;

    ret = key->callback(data, size, key->callback_key);
    if(ret < 0) {
        key->callback_failed = 1;
    }

    return ret;
}

/*
 * Encode using the selected syntax and report callback failures without aborting.
 * Source: asn1c generic encoder wrapper. Version/date: 2026-10-11.
 * Inputs: opt_codec_ctx is an optional resource context; syntax selects the
 * codec; td/sptr describe the value; callback/callback_key consume its bytes.
 * Returns: byte count or -1 with a failure descriptor and errno.
 * Errors: EINVAL for invalid arguments, ENOENT for unavailable support,
 * codec-specific value/resource errors, or EIO on callback failure.
 * No exceptions. Responsible: asn1c maintainers.
 * History: accept precise CER errors and remove callback-failure assertions.
 * Example: asn_encode(NULL, ATS_CER, td, value, write_bytes, destination).
 */
asn_enc_rval_t
asn_encode(const asn_codec_ctx_t *opt_codec_ctx,
           enum asn_transfer_syntax syntax, const asn_TYPE_descriptor_t *td,
           const void *sptr, asn_app_consume_bytes_f *callback, void *callback_key) {
    struct callback_failure_catch_key cb_key;
    asn_enc_rval_t er = {0,0,0};

    if(!callback) {
        errno = EINVAL;
        ASN__ENCODE_FAILED;
    }

    cb_key.callback = callback;
    cb_key.callback_key = callback_key;
    cb_key.callback_failed = 0;

    er = asn_encode_internal(opt_codec_ctx, syntax, td, sptr,
                             callback_failure_catch_cb, &cb_key);
    if(cb_key.callback_failed) {
        /* The callback contract applies even to a codec that ignores failure. */
        er.encoded = -1;
        if(!er.failed_type) {
            er.failed_type = td;
            er.structure_ptr = sptr;
        }
        errno = EIO;
    }

    return er;
}

/*
 * Encode into an output window and return the complete required byte count.
 * Source: existing asn1c fixed-buffer API. Version/date: documented 2026-10-11.
 * Inputs: opt_codec_ctx selects resource limits; syntax selects the codec;
 * td/sptr describe the value; buffer/buffer_size specify the destination window.
 * Returns: complete encoded size, including for short windows, or -1 on error.
 * Errors: EINVAL for a NULL nonempty window and codec-specific errors;
 * no exceptions. Owner: asn1c maintainers.
 * History: CER integration preserves sizing and copies the available prefix.
 * Example: asn_encode_to_buffer(NULL, ATS_CER, td, value, bytes, sizeof(bytes)).
 */
asn_enc_rval_t
asn_encode_to_buffer(const asn_codec_ctx_t *opt_codec_ctx,
                     enum asn_transfer_syntax syntax,
                     const asn_TYPE_descriptor_t *td, const void *sptr,
                     void *buffer, size_t buffer_size) {
    struct overrun_encoder_key buf_key;
    asn_enc_rval_t er = {0,0,0};

    if(buffer_size > 0 && !buffer) {
        errno = EINVAL;
        ASN__ENCODE_FAILED;
    }

    buf_key.buffer = buffer;
    buf_key.buffer_size = buffer_size;
    buf_key.computed_size = 0;

    er = asn_encode_internal(opt_codec_ctx, syntax, td, sptr,
                             overrun_encoder_cb, &buf_key);

    if(er.encoded >= 0 && (size_t)er.encoded != buf_key.computed_size) {
        ASN_DEBUG("asn_encode() returned %" ASN_PRI_SSIZE
                  " yet produced %" ASN_PRI_SIZE " bytes",
                  er.encoded, buf_key.computed_size);
        assert(er.encoded < 0 || (size_t)er.encoded == buf_key.computed_size);
    }

    return er;
}

/*
 * Encode into newly allocated storage, terminated with an additional zero byte.
 * Source: existing asn1c allocating API. Version/date: documented 2026-10-11.
 * Inputs: opt_codec_ctx selects limits; syntax selects the codec; td/sptr
 * describe the value. Returns: codec result and allocated output pointer.
 * Errors: buffer may be NULL after allocation failure; codec errors follow the
 * selected family. No exceptions. Owner: asn1c maintainers.
 * History: legacy allocation and counting contract retained for CER.
 * Example: asn_encode_to_new_buffer(NULL, ATS_CER, td, value); free its buffer.
 */
asn_encode_to_new_buffer_result_t
asn_encode_to_new_buffer(const asn_codec_ctx_t *opt_codec_ctx,
                         enum asn_transfer_syntax syntax,
                         const asn_TYPE_descriptor_t *td, const void *sptr) {
    struct dynamic_encoder_key buf_key;
    asn_encode_to_new_buffer_result_t res;

    buf_key.buffer_size = 16;
    buf_key.buffer = MALLOC(buf_key.buffer_size);
    buf_key.computed_size = 0;

    res.result = asn_encode_internal(opt_codec_ctx, syntax, td, sptr,
                                     dynamic_encoder_cb, &buf_key);

    if(res.result.encoded >= 0
       && (size_t)res.result.encoded != buf_key.computed_size) {
        ASN_DEBUG("asn_encode() returned %" ASN_PRI_SSIZE
                  " yet produced %" ASN_PRI_SIZE " bytes",
                  res.result.encoded, buf_key.computed_size);
        assert(res.result.encoded < 0
               || (size_t)res.result.encoded == buf_key.computed_size);
    }

    res.buffer = buf_key.buffer;

    /* 0-terminate just in case. */
    if(res.buffer) {
        assert(buf_key.computed_size < buf_key.buffer_size);
        ((char *)res.buffer)[buf_key.computed_size] = '\0';
    }

    return res;
}

/* Validated immutable inputs shared by the bounded codec dispatch units. */
typedef struct asn_encode_arguments_s {
    const asn_codec_ctx_t *codec_ctx; /* Optional codec resource context. */
    enum asn_transfer_syntax syntax; /* Requested wire transfer syntax. */
    const asn_TYPE_descriptor_t *td; /* Validated type descriptor and operations. */
    const void *sptr; /* Non-null source value. */
    asn_app_consume_bytes_f *callback; /* Non-null byte consumer. */
    void *callback_key; /* Opaque application callback key. */
} asn_encode_arguments_t;

/* Signature of a private encoder family accepting validated shared inputs. */
typedef asn_enc_rval_t (asn_encode_dispatch_f)(const asn_encode_arguments_t *);

/*
 * Dispatch the plaintext encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_plaintext_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
    case ATS_NONSTANDARD_PLAINTEXT:
        if(td->op->print_struct) {
            struct callback_count_bytes_key cb_key;
            cb_key.callback = callback;
            cb_key.callback_key = callback_key;
            cb_key.computed_size = 0;
            if(td->op->print_struct(td, sptr, 1, callback_count_bytes_cb,
                                    &cb_key)
                   < 0
               || callback_count_bytes_cb("\n", 1, &cb_key) < 0) {
                errno = EBADF; /* Structure has incorrect form. */
                er.encoded = -1;
                er.failed_type = td;
                er.structure_ptr = sptr;
            } else {
                er.encoded = cb_key.computed_size;
                er.failed_type = 0;
                er.structure_ptr = 0;
            }
        } else {
            errno = ENOENT; /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;

    case ATS_RANDOM:
        errno = ENOENT; /* Randomization doesn't make sense on output. */
        ASN__ENCODE_FAILED;

    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the der encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_der_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_BER_SUPPORT)
    case ATS_BER:
        /* BER is a superset of DER. */
        /* Fall through. */
    case ATS_DER:
        if(td->op->der_encoder) {
            er = der_encode(td, sptr, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->der_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* DER is not defined for this type. */
                }
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
    case ATS_CER:
#if !defined(ASN_DISABLE_CER_SUPPORT)
        return cer_encode(args->codec_ctx, td, sptr, callback, callback_key);
#else
        errno = ENOENT;
        ASN__ENCODE_FAILED;
#endif
#else
    case ATS_BER:
    case ATS_DER:
    case ATS_CER:
        errno = ENOENT;  /* BER is not defined. */
        ASN__ENCODE_FAILED;

#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */

    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the oer encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_oer_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_OER_SUPPORT)
    case ATS_BASIC_OER:
        /* CANONICAL-OER is a superset of BASIC-OER. */
        /* Fall through. */
    case ATS_CANONICAL_OER:
        if(td->op->oer_encoder) {
            er = oer_encode(td, sptr, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->oer_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* OER is not defined for this type. */
                }
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
#else
    case ATS_BASIC_OER:
    case ATS_CANONICAL_OER:
        errno = ENOENT;  /* OER is not defined. */
        ASN__ENCODE_FAILED;
        break;
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */

    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the uper encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_uper_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    case ATS_UNALIGNED_BASIC_PER:
        /* CANONICAL-UPER is a superset of BASIC-UPER. */
        /* Fall through. */
    case ATS_UNALIGNED_CANONICAL_PER:
        if(td->op->uper_encoder) {
            er = uper_encode(td, 0, sptr, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->uper_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* UPER is not defined for this type. */
                }
            } else {
                ASN_DEBUG("Complete encoded in %ld bits", (long)er.encoded);
                if(er.encoded == 0) {
                    /* Enforce "Complete Encoding" of X.691 #11.1 */
                    if(callback("\0", 1, callback_key) < 0) {
                        errno = EBADF;
                        ASN__ENCODE_FAILED;
                    }
                    er.encoded = 8;  /* Exactly 8 zero bits is added. */
                }
                /* Convert bits into bytes */
                er.encoded = (er.encoded + 7) >> 3;
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
#else
    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER:
        errno = ENOENT;  /* UPER is not defined. */
        ASN__ENCODE_FAILED;
        break;
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the aper encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_aper_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_APER_SUPPORT)
    case ATS_ALIGNED_BASIC_PER:
        /* CANONICAL-APER is a superset of BASIC-APER. */
        /* Fall through. */
    case ATS_ALIGNED_CANONICAL_PER:
        if(td->op->aper_encoder) {
            er = aper_encode(td, 0, sptr, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->aper_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* APER is not defined for this type. */
                }
            } else {
                ASN_DEBUG("Complete encoded in %ld bits", (long)er.encoded);
                if(er.encoded == 0) {
                    /* Enforce "Complete Encoding" of X.691 #11.1 */
                    if(callback("\0", 1, callback_key) < 0) {
                        errno = EBADF;
                        ASN__ENCODE_FAILED;
                    }
                    er.encoded = 8;  /* Exactly 8 zero bits is added. */
                }
                /* Convert bits into bytes */
                er.encoded = (er.encoded + 7) >> 3;
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
#else
    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER:
        errno = ENOENT;  /* APER is not defined. */
        ASN__ENCODE_FAILED;
        break;
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the xer encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_xer_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
#if !defined(ASN_DISABLE_XER_SUPPORT)
    enum xer_encoder_flags_e xer_flags = XER_F_CANONICAL;
#endif
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_XER_SUPPORT)
    case ATS_BASIC_XER:
        /* CANONICAL-XER is a superset of BASIC-XER. */
        xer_flags &= ~XER_F_CANONICAL;
        xer_flags |= XER_F_BASIC;
        /* Fall through. */
    case ATS_CANONICAL_XER:
        if(td->op->xer_encoder) {
            er = xer_encode(td, sptr, xer_flags, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->xer_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* XER is not defined for this type. */
                }
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
#else
    case ATS_BASIC_XER:
    case ATS_CANONICAL_XER:
        errno = ENOENT;  /* XER is not defined. */
        ASN__ENCODE_FAILED;
        break;
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */

    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the jer encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_jer_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
#if !defined(ASN_DISABLE_JER_SUPPORT)
    enum jer_encoder_flags_e jer_flags = JER_F;
#endif
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_JER_SUPPORT)
    case ATS_JER_MINIFIED:
        /* Currently JER_F and JER_F_MINIFIED have opposite purposes
        *  so we just flip the flag. */
        jer_flags &= ~JER_F;
        jer_flags |= JER_F_MINIFIED;
        /* Fall through. */
    case ATS_JER:
        if(td->op->jer_encoder) {
            er = jer_encode(td, sptr, jer_flags, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->jer_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* JER is not defined for this type. */
                }
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
#endif /* !defined(ASN_DISABLE_JER_SUPPORT) */

    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Dispatch the cbor encoder family while preserving generic API behavior.
 * Source: existing asn1c generic encoder switch, split into bounded units.
 * Version/date: 2026-10-11. Parameter: args contains validated descriptor,
 * value, syntax, optional context, callback, and opaque callback key.
 * Returns: encoded byte count or -1 with failure descriptor and errno.
 * Errors: ENOENT for disabled/missing support; codec or callback failures
 * report EBADF, with precise CER resource errors preserved. No exceptions.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: invoked by asn_encode_internal for the selected transfer syntax.
 */
static asn_enc_rval_t
asn_encode_cbor_family(const asn_encode_arguments_t *args) {
    const asn_TYPE_descriptor_t *td = args->td;
    const void *sptr = args->sptr;
    enum asn_transfer_syntax syntax = args->syntax;
    asn_app_consume_bytes_f *callback = args->callback;
    void *callback_key = args->callback_key;
    asn_enc_rval_t er = {0,0,0};
    (void)callback;
    (void)callback_key;

    /* Keep family-specific variant flags and complete-PER padding local. */
    switch(syntax) {
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    case ATS_CBOR:
        if(td->op->cbor_encoder) {
            er = cbor_encode(td, sptr, callback, callback_key);
            if(er.encoded == -1) {
                if(er.failed_type && er.failed_type->op && er.failed_type->op->cbor_encoder) {
                    errno = EBADF;   /* Structure has incorrect form. */
                } else {
                    errno = ENOENT;  /* CBOR is not defined for this type. */
                }
            }
        } else {
            errno = ENOENT;  /* Transfer syntax is not defined for this type. */
            ASN__ENCODE_FAILED;
        }
        break;
#else
    case ATS_CBOR:
        errno = ENOENT;  /* CBOR is not defined. */
        ASN__ENCODE_FAILED;
        break;
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
    default:
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }
    return er;
}

/*
 * Select one bounded encoder family for a transfer syntax.
 * Source: existing asn1c generic switch. Version/date: 2026-10-11.
 * Parameter: syntax is the requested wire format. Returns a family function,
 * or NULL for unsupported selectors. Errors/exceptions: none; no allocation.
 * Responsible: asn1c maintainers. History: extracted for CER integration.
 * Example: asn_encode_family(ATS_CER) selects the BER/DER/CER family.
 */
static asn_encode_dispatch_f *
asn_encode_family(enum asn_transfer_syntax syntax) {
    switch(syntax) {
    case ATS_NONSTANDARD_PLAINTEXT: return asn_encode_plaintext_family;
    case ATS_BER:
    case ATS_DER:
    case ATS_CER: return asn_encode_der_family;
    case ATS_BASIC_OER:
    case ATS_CANONICAL_OER: return asn_encode_oer_family;
    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER: return asn_encode_uper_family;
    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER: return asn_encode_aper_family;
    case ATS_BASIC_XER:
    case ATS_CANONICAL_XER: return asn_encode_xer_family;
    case ATS_JER:
    case ATS_JER_MINIFIED: return asn_encode_jer_family;
    case ATS_CBOR: return asn_encode_cbor_family;
    default: return NULL;
    }
}

/*
 * Validate common encoder inputs and dispatch to a bounded codec family.
 * Source: existing asn1c generic encoder. Version/date: 2026-10-11.
 * Parameters: opt_codec_ctx carries optional limits; syntax selects the codec;
 * td/sptr identify the descriptor and value; callback consumes bytes and
 * callback_key is its opaque key. Returns encoded byte count or -1.
 * Errors: EINVAL for invalid inputs, ENOENT for unsupported syntax, or codec
 * errors. No exceptions. Responsible: asn1c maintainers.
 * History: adds CER and splits the former monolithic switch.
 * Example: asn_encode_internal(ctx, ATS_CER, td, value, callback, key).
 */
static asn_enc_rval_t
asn_encode_internal(const asn_codec_ctx_t *opt_codec_ctx,
                    enum asn_transfer_syntax syntax,
                    const asn_TYPE_descriptor_t *td, const void *sptr,
                    asn_app_consume_bytes_f *callback, void *callback_key) {
    asn_encode_arguments_t args;
    asn_encode_dispatch_f *dispatch;

    if(!td || !td->op || !sptr || !callback) {
        errno = EINVAL;
        ASN__ENCODE_FAILED;
    }
    dispatch = asn_encode_family(syntax);
    if(!dispatch) {
        errno = ENOENT;
        ASN__ENCODE_FAILED;
    }

    /* Publish a complete validated argument set to the selected family. */
    args.codec_ctx = opt_codec_ctx;
    args.syntax = syntax;
    args.td = td;
    args.sptr = sptr;
    args.callback = callback;
    args.callback_key = callback_key;
    return dispatch(&args);
}

/*
 * Purpose: Dispatch a transfer-syntax decode to its generic codec.
 * Original source: Existing asn1c generic dispatcher; no external code copied.
 * Version/date: Updated 2026-10-11; baseline 5a0ccf24ede9b176e8fd76861bf4855ed95f5105.
 * Parameters:
 *   opt_codec_ctx: Optional codec limits and decoding context.
 *   syntax: Transfer syntax selecting the decoder.
 *   td: Type descriptor for the value to decode.
 *   sptr: Address of the target value pointer, possibly initially NULL.
 *   buffer: Input bytes; may be NULL only when size is zero.
 *   size: Number of available input bytes.
 * Returns: RC_OK, RC_WMORE, or RC_FAIL and the number of bytes consumed.
 * Errors/exceptions: Sets ENOENT for unsupported or disabled syntax; C has no
 *   exceptions, and malformed or incomplete input is reported in the result.
 * Author/responsible party: asn1c maintainers.
 * History: 2026-10-11 routes ATS_CER through the strict cer_decode, which
 *   rejects noncanonical input and is not restartable (see cer_decoder.h).
 * Example: asn_decode(ctx, ATS_CER, &asn_DEF_Type, &value, input, input_size).
 */
asn_dec_rval_t
asn_decode(const asn_codec_ctx_t *opt_codec_ctx,
           enum asn_transfer_syntax syntax, const asn_TYPE_descriptor_t *td,
           void **sptr, const void *buffer, size_t size) {
    if(!td || !td->op || !sptr || (size && !buffer)) {
        ASN__DECODE_FAILED;
    }

    switch(syntax) {
    case ATS_NONSTANDARD_PLAINTEXT:
    default:
        errno = ENOENT;
        ASN__DECODE_FAILED;

    case ATS_RANDOM:
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
        if(!td->op->random_fill) {
            ASN__DECODE_FAILED;
        } else {
            if(asn_random_fill(td, sptr, 16000) == 0) {
                asn_dec_rval_t ret = {RC_OK, 0};
                return ret;
            } else {
                ASN__DECODE_FAILED;
            }
        }
        break;
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */

    case ATS_CER:
#if !defined(ASN_DISABLE_BER_SUPPORT) && !defined(ASN_DISABLE_CER_SUPPORT)
        return cer_decode(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !ASN_DISABLE_BER_SUPPORT && !ASN_DISABLE_CER_SUPPORT */

    case ATS_DER:
    case ATS_BER:
#if !defined(ASN_DISABLE_BER_SUPPORT)
        return ber_decode(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */

    case ATS_BASIC_OER:
    case ATS_CANONICAL_OER:
#if !defined(ASN_DISABLE_OER_SUPPORT)
        return oer_decode(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */

    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER:
#if !defined(ASN_DISABLE_UPER_SUPPORT)
        return uper_decode_complete(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */

    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER:
#if !defined(ASN_DISABLE_APER_SUPPORT)
        return aper_decode_complete(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

    case ATS_BASIC_XER:
    case ATS_CANONICAL_XER:
#if !defined(ASN_DISABLE_XER_SUPPORT)
        return xer_decode(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */

    case ATS_JER:
    case ATS_JER_MINIFIED:
#if !defined(ASN_DISABLE_JER_SUPPORT)
        return jer_decode(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */

    case ATS_CBOR:
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
        return cbor_decode(opt_codec_ctx, td, sptr, buffer, size);
#else
        errno = ENOENT;
        ASN__DECODE_FAILED;
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
    }
}

/*
 * Validate a BIT STRING's CONTAINING value under the current transfer syntax.
 * Source: existing asn1c CONTAINING checker. Version/date: documented 2026-10-11.
 * Inputs: type_descriptor/struct_ptr identify the outer value; contained_type
 * identifies its decoded type; cb/key receive an optional failure diagnostic.
 * Returns: zero when valid or unconstrained, -1 on decoding/constraint failure.
 * Errors: invokes cb on failure; no exceptions. Owner: asn1c maintainers.
 * History: existing validation preserved during CER dispatch refactoring.
 * Example: invoked by generated BIT STRING constraint functions.
 */
int
asn_check_containing_constraint(const asn_TYPE_descriptor_t *type_descriptor,
                                const void *struct_ptr,
                                const asn_TYPE_descriptor_t *contained_type,
                                asn_app_constraint_failed_f *cb, void *key) {
    const BIT_STRING_t *st;
    void *contained_value = 0;
    asn_dec_rval_t rval;
    int syntax = asn_check_constraints_current_syntax();
    int failed = 0;
    int decoded = 0;
    size_t bit_count;

    if(!contained_type) return 0;
    st = (const BIT_STRING_t *)struct_ptr;
    if(!st || !st->buf || st->size == 0 || st->bits_unused < 0
       || st->bits_unused > 7 || st->size > SIZE_MAX / 8
       || (st->bits_unused
           && (st->buf[st->size - 1] & ((1u << st->bits_unused) - 1)))) {
        failed = 1;
    } else {
        bit_count = st->size * 8 - st->bits_unused;
        switch(syntax) {
#if !defined(ASN_DISABLE_UPER_SUPPORT)
        case ATS_UNALIGNED_BASIC_PER:
        case ATS_UNALIGNED_CANONICAL_PER:
            rval = uper_decode(0, contained_type, &contained_value, st->buf,
                               st->size, 0, st->bits_unused);
            decoded = rval.code == RC_OK && rval.consumed == bit_count;
            break;
#endif
#if !defined(ASN_DISABLE_APER_SUPPORT)
        case ATS_ALIGNED_BASIC_PER:
        case ATS_ALIGNED_CANONICAL_PER:
            rval = aper_decode(0, contained_type, &contained_value, st->buf,
                               st->size, 0, st->bits_unused);
            decoded = rval.code == RC_OK && rval.consumed == bit_count;
            break;
#endif
        default:
            if(st->bits_unused == 0) {
                rval = asn_decode(0, (enum asn_transfer_syntax)syntax,
                                  contained_type, &contained_value, st->buf,
                                  st->size);
                decoded = rval.code == RC_OK && rval.consumed == st->size;
            }
            break;
        }
        if(!decoded
           || asn_check_constraints_with_syntax(contained_type,
                                                contained_value, syntax, 0,
                                                0) != 0) {
            failed = 1;
        }
    }

    if(contained_value) {
        ASN_STRUCT_FREE(*contained_type, contained_value);
    }
    if(failed) {
        if(cb) {
            cb(key, type_descriptor, struct_ptr,
               "%s: contents do not encode a valid value of %s (%s:%d)",
               type_descriptor->name, contained_type->name, __FILE__, __LINE__);
        }
        return -1;
    }
    return 0;
}

/*
 * Validate an OCTET STRING containing a complete encoding of another value.
 * Original source: asn1c BIT STRING CONTAINING checker. Version: 2026-10-30.
 * Inputs: td and sptr describe the outer value, contained identifies its type,
 * cb and key optionally receive a diagnostic. Returns zero on success, -1 on
 * invalid content or unsupported syntax. Errors: decoder failures are reported
 * through cb; no exceptions. Owner: asn1c maintainers. History: added OCTET
 * STRING support. Example: validate a padded UPER encoding of BOOLEAN.
 */
int
asn_check_octet_containing_constraint(const asn_TYPE_descriptor_t *td,
                                      const void *sptr,
                                      const asn_TYPE_descriptor_t *contained,
                                      asn_app_constraint_failed_f *cb, void *key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    void *value = 0;
    asn_dec_rval_t rval = {RC_FAIL, 0};
    int syntax = asn_check_constraints_current_syntax();
    int per = 0;
    int valid = 0;
    const uint8_t empty_buffer = 0;
    const uint8_t *buffer;

    if(!td || !contained) return -1;
    if(!st || (!st->buf && st->size) || st->size > SIZE_MAX / 8) goto done;
    buffer = st->buf ? st->buf : &empty_buffer;
    /* PER decoders report bits, allowing exact trailing padding checks. */
    switch(syntax) {
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    case ATS_UNALIGNED_BASIC_PER:
    case ATS_UNALIGNED_CANONICAL_PER:
        per = 1;
        rval = uper_decode(0, contained, &value, buffer, st->size, 0, 0);
        break;
#endif
#if !defined(ASN_DISABLE_APER_SUPPORT)
    case ATS_ALIGNED_BASIC_PER:
    case ATS_ALIGNED_CANONICAL_PER:
        per = 1;
        rval = aper_decode(0, contained, &value, buffer, st->size, 0, 0);
        break;
#endif
    default:
        rval = asn_decode(0, (enum asn_transfer_syntax)syntax, contained,
                          &value, buffer, st->size);
        break;
    }
    if(rval.code != RC_OK) goto done;
    if(per) {
        size_t bits = rval.consumed;
        size_t padding;
        if(!st->size || bits > st->size * 8) goto done;
        padding = st->size * 8 - bits;
        if(bits == 0) {
            if(st->size != 1 || st->buf[0] != 0) goto done;
        } else if(padding > 7
                  || (padding && (st->buf[st->size - 1] & ((1u << padding) - 1)))) {
            goto done;
        }
    } else if(rval.consumed != st->size) {
        goto done;
    }
    valid = asn_check_constraints_with_syntax(contained, value, syntax, 0, 0) == 0;

done:
    if(value) ASN_STRUCT_FREE(*contained, value);
    if(!valid && cb)
        cb(key, td, sptr, "%s: contents do not encode a valid value of %s (%s:%d)",
           td->name, contained->name, __FILE__, __LINE__);
    return valid ? 0 : -1;
}
