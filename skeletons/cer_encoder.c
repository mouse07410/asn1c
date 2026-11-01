/*
 * Copyright (c) 2026 Contributors. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <cer_encoder.h>
#include <errno.h>

#if !defined(ASN_DISABLE_BER_SUPPORT) && !defined(ASN_DISABLE_CER_SUPPORT)
#include <constraints.h>
#include <der_encoder.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <BOOLEAN.h>
#include <NULL.h>
#include <REAL.h>
#include <GeneralizedTime.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SET_OF.h>
#include <constr_SEQUENCE.h>
#include <constr_SET.h>
#include <OPEN_TYPE.h>
#include <NativeInteger.h>
#include <NativeEnumerated.h>
#include <NativeReal.h>
#include <UTF8String.h>
#include <NumericString.h>
#include <PrintableString.h>
#include <IA5String.h>
#include <VisibleString.h>
#include <ISO646String.h>
#include <ObjectDescriptor.h>
#include <GeneralString.h>
#include <GraphicString.h>
#include <VideotexString.h>
#include <T61String.h>
#include <TeletexString.h>
#include <UniversalString.h>
#include <BMPString.h>
#include <UTCTime.h>
#include <limits.h>

#ifndef ASN_CER_MAX_ENCODED_SIZE
#define ASN_CER_MAX_ENCODED_SIZE (64u * 1024u * 1024u)
#endif
#ifndef ASN_CER_MAX_SCRATCH_SIZE
#define ASN_CER_MAX_SCRATCH_SIZE (128u * 1024u * 1024u)
#endif
#ifndef ASN_CER_MAX_ELEMENTS
#define ASN_CER_MAX_ELEMENTS 1000000u
#endif
#ifndef ASN_CER_MAX_WORK_ITEMS
#define ASN_CER_MAX_WORK_ITEMS 4000000u
#endif

/* Buffer ownership and aggregate workspace accounting for one CER call. */
typedef struct cer_context_s {
    const asn_codec_ctx_t *codec_ctx; /* Optional inherited stack limit. */
    size_t active_scratch; /* state variable: bytes held by live allocations. */
    size_t work_items; /* state variable: descriptor/value visits so far. */
    unsigned depth; /* state variable: active value recursion depth. */
    int error; /* state variable: first errno-style failure. */
    const asn_TYPE_descriptor_t *failed_type; /* Descriptor at the failure. */
    const void *failed_ptr; /* Value at the failure. */
} cer_context_t;

/* A growable byte string charged against the call's aggregate scratch budget. */
typedef struct cer_buffer_s {
    uint8_t *data; /* Owned encoded bytes. */
    size_t length; /* Number of initialized bytes. */
    size_t capacity; /* Allocated bytes, also charged to scratch. */
} cer_buffer_t;

/* Encoded SET and SET OF members retained until canonical ordering is known. */
typedef struct cer_item_s {
    cer_buffer_t bytes; /* Complete CER encoding for this member. */
    ber_tlv_tag_t sort_tag; /* Static minimum tag used by SET. */
    size_t declaration_index; /* Stable tie breaker for equal SET tags. */
} cer_item_t;

/* A resolved member view, including runtime-selected open types. */
typedef struct cer_member_view_s {
    const asn_TYPE_descriptor_t *type; /* Concrete descriptor to encode. */
    const void *value; /* Address of inline or indirect member value. */
    int tag_mode; /* Member implicit, untagged, or explicit mode. */
    ber_tlv_tag_t tag; /* Member-level tag, when tag_mode is nonzero. */
    int present; /* Whether the member contributes to the encoding. */
} cer_member_view_t;

/* Private adapter for capturing a DER callback into a bounded CER buffer. */
typedef struct cer_capture_key_s {
    cer_context_t *context; /* Active encoder limits and error state. */
    cer_buffer_t *buffer; /* Destination temporary DER buffer. */
    const asn_TYPE_descriptor_t *type; /* Descriptor currently being captured. */
    const void *value; /* Value currently being captured. */
} cer_capture_key_t;

static int cer_encode_value(cer_context_t *, const asn_TYPE_descriptor_t *,
                            const void *, int, ber_tlv_tag_t, cer_buffer_t *);
static int cer_encode_member(cer_context_t *, const asn_TYPE_descriptor_t *,
                             const void *, const asn_TYPE_member_t *,
                             cer_buffer_t *, cer_member_view_t *);
static int cer_encode_extension_group_body(cer_context_t *,
                                           const asn_TYPE_descriptor_t *,
                                           const void *, cer_buffer_t *);
static int cer_set_item_capacity(cer_context_t *,
                                 const asn_TYPE_descriptor_t *, const void *,
                                 unsigned, size_t *);
static int cer_validate_set_group(cer_context_t *,
                                 const asn_TYPE_descriptor_t *, const void *);
static int cer_collect_set_group(cer_context_t *,
                                 const asn_TYPE_descriptor_t *, const void *,
                                 const asn_TYPE_member_t *, cer_item_t *,
                                 size_t, size_t *);
static int cer_capture_bytes_cb(const void *, size_t, void *);
static int cer_check_tag_depth(cer_context_t *,
                               const asn_TYPE_descriptor_t *, const void *,
                               int);
static int cer_minimum_tag(cer_context_t *, const asn_TYPE_descriptor_t *,
                           unsigned, ber_tlv_tag_t *);
static int cer_member_minimum_tag(cer_context_t *,
                                  const asn_TYPE_member_t *, unsigned,
                                  ber_tlv_tag_t *);
static int cer_inline_value_size(cer_context_t *,
                                const asn_TYPE_descriptor_t *, size_t *);
static int cer_check_primitive_constraints(cer_context_t *,
                                          const asn_TYPE_descriptor_t *,
                                          const void *);
static int cer_validate_generalized_time(cer_context_t *,
                                        const asn_TYPE_descriptor_t *,
                                        const GeneralizedTime_t *);
static int cer_validate_canonical_generalized_time(cer_context_t *,
                                                   const asn_TYPE_descriptor_t *,
                                                   const void *,
                                                   const cer_buffer_t *);
static int cer_replace_outer_tag(cer_context_t *,
                                 const asn_TYPE_descriptor_t *, const void *,
                                 const cer_buffer_t *, ber_tlv_tag_t,
                                 cer_buffer_t *);
static int cer_encode_constructed(cer_context_t *, const asn_TYPE_descriptor_t *,
                                  const void *, int, ber_tlv_tag_t,
                                  cer_buffer_t *);
static int cer_fail(cer_context_t *, int, const asn_TYPE_descriptor_t *,
                    const void *);

/*
 * Validate a binary REAL's exponent and return the mantissa offset.
 * Original source: New asn1c CER validator, following X.690 11.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; bytes/size hold REAL content;
 *   exponent_size and mantissa_offset receive validated positions.
 * Returns: 0 for a minimal base-2 exponent, otherwise -1.
 * Errors: EBADF for invalid binary form; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_validate_real() before checking the mantissa.
 */
static int
cer_validate_real_layout(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                         const void *value, const uint8_t *bytes, size_t size,
                         size_t *exponent_size, size_t *mantissa_offset) {
    unsigned exponent_code = bytes[0] & 0x03;
    const uint8_t *exponent;

    if(((bytes[0] >> 4) & 0x03) || ((bytes[0] >> 2) & 0x03)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    *exponent_size = exponent_code < 3 ? exponent_code + 1 :
                     (size > 1 ? bytes[1] : 0);
    *mantissa_offset = 1 + (exponent_code == 3) + *exponent_size;
    if(*exponent_size == 0 || *exponent_size > 8 ||
       *mantissa_offset >= size ||
       (exponent_code == 3 && bytes[1] < 4)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    exponent = bytes + 1 + (exponent_code == 3);
    if(*exponent_size > 1 &&
       ((exponent[0] == 0 && (exponent[1] & 0x80) == 0) ||
        (exponent[0] == 0xff && (exponent[1] & 0x80) != 0))) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Validate the supported canonical binary and special REAL content subset.
 * Original source: New asn1c CER encoder validator, following X.690 11.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; bytes/size hold REAL content.
 * Returns: 0 for zero, canonical special values, or minimal base-2 binary form.
 * Errors: EBADF for malformed/noncanonical binary; ENOENT for decimal forms.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_validate_real(ctx, td, value, content, content_size).
 */
static int
cer_validate_real(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                  const void *value, const uint8_t *bytes, size_t size) {
    size_t exponent_size;
    size_t mantissa_offset;

    if(size == 0) return 0;
    if(!bytes) return cer_fail(ctx, EBADF, td, value);
    if(size == 1 && bytes[0] >= 0x40 && bytes[0] <= 0x43) return 0;
    if((bytes[0] & 0xc0) == 0x40) return cer_fail(ctx, EBADF, td, value);
    if((bytes[0] & 0x80) == 0) return cer_fail(ctx, ENOENT, td, value);
    if(cer_validate_real_layout(ctx, td, value, bytes, size, &exponent_size,
                                &mantissa_offset)) return -1;
    if(bytes[mantissa_offset] == 0 || (bytes[size - 1] & 1) == 0) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Validate INTEGER/ENUMERATED storage before DER can scan its contents.
 * Original source: New asn1c CER input validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the integer representation.
 * Returns: 0 for bounded native or buffer-backed integer storage.
 * Errors: EBADF for empty/null buffers or invalid native width; EOVERFLOW for
 *   excessive input size.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before INTEGER_encode_der() on tag 2 or 10.
 */
static int
cer_validate_integer_input(cer_context_t *ctx,
                           const asn_TYPE_descriptor_t *td,
                           const void *value) {
    der_type_encoder_f *encoder = td->op->der_encoder;

    if(encoder == NativeInteger_encode_der ||
       encoder == NativeEnumerated_encode_der) {
        const asn_INTEGER_specifics_t *specs =
            (const asn_INTEGER_specifics_t *)td->specifics;
        int width = specs ? specs->field_width : 0;
        if(width && width != 1 && width != 2 && width != 4 && width != 8) {
            return cer_fail(ctx, EBADF, td, value);
        }
        return 0;
    }
    {
        const INTEGER_t *integer = (const INTEGER_t *)value;
        if(!integer->buf || integer->size == 0) {
            return cer_fail(ctx, EBADF, td, value);
        }
        if(integer->size > ASN_CER_MAX_ENCODED_SIZE) {
            return cer_fail(ctx, EOVERFLOW, td, value);
        }
    }
    return 0;
}

/*
 * Validate string-like C storage before a type adapter reads it.
 * Original source: New asn1c CER input validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the value; number is its universal tag.
 * Returns: 0 for bounded OCTET, BIT, OID, relative OID, string, and time data.
 * Errors: EBADF for invalid pointer/unused-bit state; EOVERFLOW for huge input.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before DER capture for universal string tags.
 */
static int
cer_validate_string_input(cer_context_t *ctx,
                          const asn_TYPE_descriptor_t *td,
                          const void *value, ber_tlv_tag_t number) {
    const OCTET_STRING_t *string = (const OCTET_STRING_t *)value;

    if(string->size && !string->buf) return cer_fail(ctx, EBADF, td, value);
    if(string->size > ASN_CER_MAX_ENCODED_SIZE) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(number == 3) {
        const BIT_STRING_t *bits = (const BIT_STRING_t *)value;
        if(bits->bits_unused < 0 || bits->bits_unused > 7 ||
           (bits->size == 0 && bits->bits_unused != 0) ||
           (bits->size && bits->bits_unused &&
            (bits->buf[bits->size - 1] &
             ((1u << bits->bits_unused) - 1u)) != 0)) {
            return cer_fail(ctx, EBADF, td, value);
        }
    }
    return 0;
}

/*
 * Validate REAL storage without assuming native and raw layouts match.
 * Original source: New asn1c CER input validator, dated 2026-10-11.
 * Parameters: ctx/td/value identify the descriptor and its value storage.
 * Returns: 0 for bounded native float/double or raw buffer-backed content.
 * Errors: EBADF for an unsupported native width or missing raw buffer;
 *   EOVERFLOW when raw content exceeds the configured input ceiling.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called for intrinsic universal tag 9 before invoking its adapter.
 */
static int
cer_validate_real_input(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                        const void *value) {
    if(td->op->der_encoder == NativeReal_encode_der) {
        const asn_NativeReal_specifics_t *specs =
            (const asn_NativeReal_specifics_t *)td->specifics;
        size_t float_size = specs ? specs->float_size : sizeof(double);
        if(float_size != sizeof(float) && float_size != sizeof(double)) {
            return cer_fail(ctx, EBADF, td, value);
        }
        return 0;
    }
    {
        const ASN__PRIMITIVE_TYPE_t *real =
            (const ASN__PRIMITIVE_TYPE_t *)value;
        if(real->size && !real->buf) return cer_fail(ctx, EBADF, td, value);
        if(real->size > ASN_CER_MAX_ENCODED_SIZE) {
            return cer_fail(ctx, EOVERFLOW, td, value);
        }
    }
    return 0;
}

/*
 * Validate primitive input layouts before type-specific DER adapters read them.
 * Original source: New asn1c CER encoder validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the value; universal_tag identifies its
 *   intrinsic universal tag number.
 * Returns: 0 when bounded storage is safe to pass to the DER adapter.
 * Errors: EBADF for malformed storage, EOVERFLOW for excessive primitive size,
 *   and ENOENT for unsupported raw types.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before cer_capture_der() to avoid unsafe adapter reads.
 */
static int
cer_validate_primitive_input(cer_context_t *ctx,
                             const asn_TYPE_descriptor_t *td,
                             const void *value, ber_tlv_tag_t number) {

    if(number == 2 || number == 10) {
        return cer_validate_integer_input(ctx, td, value);
    }
    if(number == 24) {
        const GeneralizedTime_t *time_value =
            (const GeneralizedTime_t *)value;
        if(cer_validate_string_input(ctx, td, value, number)) return -1;
        if(td->op->der_encoder != GeneralizedTime_encode_der) {
            return cer_fail(ctx, ENOENT, td, value);
        }
        return cer_validate_generalized_time(ctx, td, time_value);
    }
    if(number == 3 || number == 4 || number == 6 || number == 13 ||
       number == 7 || (number >= 12 && number <= 30)) {
        return cer_validate_string_input(ctx, td, value, number);
    }
    if(number == 9) return cer_validate_real_input(ctx, td, value);
    return 0;
}

/*
 * Record the first failure without overwriting a more useful cause.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call; error is an errno-style failure;
 *   td and value identify the failing descriptor and value.
 * Returns: Always -1 for direct propagation by private helpers.
 * Errors: Sets ctx->error; this helper does not allocate or throw.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: return cer_fail(ctx, EOVERFLOW, td, value).
 */
static int
cer_fail(cer_context_t *ctx, int error, const asn_TYPE_descriptor_t *td,
         const void *value) {
    if(ctx->error == 0) {
        ctx->error = error;
        ctx->failed_type = td;
        ctx->failed_ptr = value;
    }
    return -1;
}

/*
 * Charge one descriptor, member, or list-element visit against the work cap.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call and td/value identify the current node.
 * Returns: 0 when the visit is allowed; -1 after the shared work cap is hit.
 * Errors: Sets EOVERFLOW through cer_fail(); C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: if(cer_charge_work(ctx, td, value)) return -1.
 */
static int
cer_charge_work(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                const void *value) {
    if(ctx->work_items >= ASN_CER_MAX_WORK_ITEMS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    ctx->work_items++;
    return 0;
}

/*
 * Allocate memory while enforcing the aggregate active scratch limit.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call, size is the allocation size, and td/value
 *   identify the owning ASN.1 value for diagnostics.
 * Returns: Allocated pointer, or NULL with ctx->error set.
 * Errors: EOVERFLOW when the shared scratch cap is exceeded; ENOMEM on failure.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: items = cer_alloc(ctx, bytes, td, value).
 */
static void *
cer_alloc(cer_context_t *ctx, size_t size, const asn_TYPE_descriptor_t *td,
          const void *value) {
    void *memory;

    if(size == 0) size = 1;
    if(ctx->active_scratch > ASN_CER_MAX_SCRATCH_SIZE ||
       size > ASN_CER_MAX_SCRATCH_SIZE - ctx->active_scratch) {
        cer_fail(ctx, EOVERFLOW, td, value);
        return NULL;
    }
    memory = MALLOC(size);
    if(!memory) {
        cer_fail(ctx, ENOMEM, td, value);
        return NULL;
    }
    ctx->active_scratch += size;
    return memory;
}

/*
 * Release a charged allocation and return its bytes to the shared budget.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call, memory is the allocation, and size is
 *   the exact charged size (zero-size requests are charged as one byte).
 * Returns: No value.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_free(ctx, array, array_size).
 */
static void
cer_free(cer_context_t *ctx, void *memory, size_t size) {
    if(!memory) return;
    FREEMEM(memory);
    if(size == 0) size = 1;
    if(ctx->active_scratch >= size) ctx->active_scratch -= size;
    else ctx->active_scratch = 0;
}

/*
 * Grow a CER buffer without exceeding output or aggregate scratch bounds.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call, buffer is the owned byte string,
 *   needed is its minimum capacity, and td/value identify its owner.
 * Returns: 0 on success; -1 after setting a precise failure in ctx.
 * Errors: EOVERFLOW for size limits and ENOMEM for allocation failure.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_buffer_reserve(ctx, &out, out.length + 4, td, value).
 */
static int
cer_buffer_reserve(cer_context_t *ctx, cer_buffer_t *buffer, size_t needed,
                   const asn_TYPE_descriptor_t *td, const void *value) {
    size_t capacity;
    uint8_t *grown;

    if(needed > ASN_CER_MAX_ENCODED_SIZE ||
       needed > (((size_t)-1) >> 1)) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(needed <= buffer->capacity) return 0;
    capacity = buffer->capacity ? buffer->capacity :
               (ASN_CER_MAX_ENCODED_SIZE < 64 ?
                ASN_CER_MAX_ENCODED_SIZE : 64);
    if(capacity == 0) return cer_fail(ctx, EOVERFLOW, td, value);
    while(capacity < needed) {
        if(capacity > ASN_CER_MAX_ENCODED_SIZE / 2) {
            capacity = ASN_CER_MAX_ENCODED_SIZE;
            break;
        }
        capacity *= 2;
    }
    if(capacity < needed || capacity > ASN_CER_MAX_ENCODED_SIZE) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(ctx->active_scratch > ASN_CER_MAX_SCRATCH_SIZE ||
       capacity > ASN_CER_MAX_SCRATCH_SIZE - ctx->active_scratch) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }

    /* Charge the new block before realloc so growth is safe even if it moves. */
    ctx->active_scratch += capacity;
    grown = REALLOC(buffer->data, capacity);
    if(!grown) {
        ctx->active_scratch -= capacity;
        return cer_fail(ctx, ENOMEM, td, value);
    }
    if(ctx->active_scratch >= buffer->capacity) {
        ctx->active_scratch -= buffer->capacity;
    }
    buffer->data = grown;
    buffer->capacity = capacity;
    return 0;
}

/*
 * Append bytes to a bounded CER buffer.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call; buffer is the destination; data/size
 *   describe bytes to append; td/value identify the owning value.
 * Returns: 0 on success or -1 after setting ctx->error.
 * Errors: EOVERFLOW for size bounds and ENOMEM for growth failure.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_buffer_append(ctx, &out, child.data, child.length, td, value).
 */
static int
cer_buffer_append(cer_context_t *ctx, cer_buffer_t *buffer, const void *data,
                  size_t size, const asn_TYPE_descriptor_t *td,
                  const void *value) {
    if(size == 0) return 0;
    if(buffer->length > ASN_CER_MAX_ENCODED_SIZE || !data ||
       size > ASN_CER_MAX_ENCODED_SIZE - buffer->length) {
        return cer_fail(ctx, data ? EOVERFLOW : EBADF, td, value);
    }
    if(cer_buffer_reserve(ctx, buffer, buffer->length + size, td, value)) {
        return -1;
    }
    memcpy(buffer->data + buffer->length, data, size);
    buffer->length += size;
    return 0;
}

/*
 * Release a buffer and clear its ownership fields.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call and buffer is the owned buffer to clear.
 * Returns: No value.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_buffer_release(ctx, &temporary).
 */
static void
cer_buffer_release(cer_context_t *ctx, cer_buffer_t *buffer) {
    cer_free(ctx, buffer->data, buffer->capacity);
    memset(buffer, 0, sizeof(*buffer));
}

/*
 * Emit one definite or indefinite TLV around an existing content buffer.
 * Original source: New asn1c CER encoder helper; tag/length primitives are
 *   reused from asn1c ber_tlv_tag and DER length support.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx is the active call; tag is the ASN.1 tag; constructed picks
 *   the form; indefinite selects CER's constructed length; content is copied;
 *   td/value identify the owning value.
 * Returns: 0 on success or -1 on callback-independent encoding failure.
 * Errors: EOVERFLOW, ENOMEM, or EBADF for invalid tag/content metadata.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_make_tlv(ctx, td, value, tag, 1, 1, &body, &wrapped).
 */
static int
cer_make_tlv(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
             const void *value, ber_tlv_tag_t tag, int constructed,
             int indefinite, const cer_buffer_t *content,
             cer_buffer_t *wrapped) {
    uint8_t header[32];
    size_t tag_size;
    size_t length_size;
    int status = -1;

    memset(wrapped, 0, sizeof(*wrapped));
    if(!constructed && indefinite) {
        cer_fail(ctx, EBADF, td, value);
        goto fail;
    }
    tag_size = ber_tlv_tag_serialize(tag, header, sizeof(header));
    if(tag_size == 0 || tag_size >= sizeof(header)) {
        cer_fail(ctx, EBADF, td, value);
        goto fail;
    }
    if(constructed) header[0] |= 0x20;
    if(cer_buffer_append(ctx, wrapped, header, tag_size, td, value)) goto fail;

    if(indefinite) {
        const uint8_t length_byte = 0x80;
        if(cer_buffer_append(ctx, wrapped, &length_byte, 1, td, value)) {
            goto fail;
        }
    } else {
        if(!content || content->length > (((size_t)-1) >> 1)) {
            cer_fail(ctx, EOVERFLOW, td, value);
            goto fail;
        }
        length_size = der_tlv_length_serialize((ber_tlv_len_t)content->length,
                                               header, sizeof(header));
        if(length_size == 0 || length_size > sizeof(header)) {
            cer_fail(ctx, EBADF, td, value);
            goto fail;
        }
        if(cer_buffer_append(ctx, wrapped, header, length_size, td, value)) {
            goto fail;
        }
    }
    if(content && cer_buffer_append(ctx, wrapped, content->data,
                                    content->length, td, value)) {
        goto fail;
    }
    if(indefinite) {
        static const uint8_t eoc[2] = {0, 0};
        if(cer_buffer_append(ctx, wrapped, eoc, sizeof(eoc), td, value)) {
            goto fail;
        }
    }
    status = 0;
fail:
    if(status) cer_buffer_release(ctx, wrapped);
    return status;
}

/*
 * Parse one definite-length DER tag and expose its content bounds.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the call; bytes and size are a DER slice;
 *   tag/content_offset/content_size receive parsed metadata.
 * Returns: 0 for one well-formed TLV; -1 for malformed DER or resource bounds.
 * Errors: EBADF for malformed or indefinite data; no C exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_parse_tlv(ctx, td, value, der, n, &tag, &off, &len).
 */
static int
cer_parse_tlv(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
              const void *value, const uint8_t *bytes, size_t size,
              ber_tlv_tag_t *tag, size_t *content_offset,
              size_t *content_size) {
    ssize_t tag_size;
    ssize_t length_size;
    ber_tlv_len_t length;

    tag_size = ber_fetch_tag(bytes, size, tag);
    if(tag_size <= 0 || (size_t)tag_size >= size) {
        return cer_fail(ctx, EBADF, td, value);
    }
    length_size = ber_fetch_length(0, bytes + tag_size, size - tag_size,
                                   &length);
    if(length_size <= 0 || length < 0 ||
       (size_t)length > size - (size_t)tag_size - (size_t)length_size) {
        return cer_fail(ctx, EBADF, td, value);
    }
    *content_offset = (size_t)tag_size + (size_t)length_size;
    *content_size = (size_t)length;
    return 0;
}

/*
 * Extract a primitive's canonical content from the DER encoder output.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the value; der is its temporary encoding;
 *   intrinsic_tag is the resolved universal tag; content receives its body.
 * Returns: 0 on one matching primitive; -1 if the DER output is not its shape.
 * Errors: EBADF for malformed shape, ENOENT for absent primitive DER support.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_extract_der_content(ctx, td, value, &der, tag2, &body).
 */
static int
cer_extract_der_content(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                        const void *value, const cer_buffer_t *der,
                        ber_tlv_tag_t intrinsic_tag,
                        cer_buffer_t *content) {
    ber_tlv_tag_t parsed_tag;
    size_t offset;
    size_t length;

    memset(content, 0, sizeof(*content));
    if(!der->data || !der->length ||
       cer_parse_tlv(ctx, td, value, der->data, der->length, &parsed_tag,
                      &offset, &length)) {
        if(!ctx->error) cer_fail(ctx, EBADF, td, value);
        return -1;
    }
    if(parsed_tag != intrinsic_tag || BER_TLV_CONSTRUCTED(der->data) ||
       offset + length != der->length) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return cer_buffer_append(ctx, content, der->data + offset, length, td,
                             value);
}

/*
 * Capture canonical DER emitted by a primitive type operation.
 * Original source: New asn1c CER encoder helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the primitive; intrinsic_tag is its
 *   resolved universal tag and output receives the adapter's DER TLV.
 * Returns: 0 on success; -1 when DER encoding or bounded capture fails.
 * Errors: Preserves ENOMEM/EOVERFLOW; otherwise reports EBADF or ENOENT.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_capture_der(ctx, td, value, intrinsic_tag, &der).
 */
static int
cer_capture_der(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                const void *value, ber_tlv_tag_t intrinsic_tag,
                cer_buffer_t *der) {
    asn_TYPE_descriptor_t capture_td = *td;
    ber_tlv_tag_t capture_tag = intrinsic_tag;
    cer_capture_key_t key;
    asn_enc_rval_t encoded;

    memset(der, 0, sizeof(*der));
    if(!td->op || !td->op->der_encoder) {
        return cer_fail(ctx, ENOENT, td, value);
    }
    /* Let DER encode only the semantic primitive TLV; CER adds descriptor
     * wrappers afterward, without DER's fixed four-tag scratch limit. */
    capture_td.tags = &capture_tag;
    capture_td.tags_count = 1;
    capture_td.all_tags = &capture_tag;
    capture_td.all_tags_count = 1;
    key.context = ctx;
    key.buffer = der;
    /* Failures must always retain the caller-owned descriptor, not capture_td. */
    key.type = td;
    key.value = value;
    errno = 0;
    encoded = td->op->der_encoder(&capture_td, value, 0, 0,
                                  cer_capture_bytes_cb, &key);
    if(encoded.encoded < 0) {
        if(ctx->error) return -1;
        if(errno == ENOMEM) return cer_fail(ctx, ENOMEM, td, value);
        return cer_fail(ctx, EBADF, td, value);
    }
    if((size_t)encoded.encoded != der->length) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Capture DER bytes while charging the temporary buffer to the shared budget.
 * Original source: New asn1c CER encoder callback adapter.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: data/size are callback bytes; keyp identifies the bounded target.
 * Returns: 0 on success and -1 to stop DER encoding after a limit/allocation
 *   failure.
 * Errors: Preserves the error recorded by cer_buffer_append().
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_capture_der() as the DER output callback.
 */
static int
cer_capture_bytes_cb(const void *data, size_t size, void *keyp) {
    cer_capture_key_t *key = (cer_capture_key_t *)keyp;

    if(!key || !key->context || !key->buffer) return -1;
    return cer_buffer_append(key->context, key->buffer, data, size,
                             key->type, key->value);
}

/*
 * Compare tags numerically for the static-minimum-tag SET rule.
 * Original source: New asn1c CER encoder helper, following X.690 9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: left/right are encoded outer tags.
 * Returns: Negative, zero, or positive according to tag number ordering.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_item_compare() when sorting SET components.
 */
static int
cer_tag_compare(ber_tlv_tag_t left, ber_tlv_tag_t right) {
    unsigned left_class = BER_TAG_CLASS(left);
    unsigned right_class = BER_TAG_CLASS(right);
    unsigned left_number = BER_TAG_VALUE(left);
    unsigned right_number = BER_TAG_VALUE(right);

    if(left_class != right_class) return left_class < right_class ? -1 : 1;
    return left_number < right_number ? -1 : left_number > right_number ? 1 : 0;
}

/*
 * Compare final CER encodings using X.690's zero-padded SET OF rule.
 * Original source: New asn1c CER encoder helper, following X.690 11.6.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: left/right are encoded items retained during SET OF sorting.
 * Returns: Lexicographic zero-padded comparison, then stable input order.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by qsort() for SET OF members.
 */
static int
cer_item_compare(const void *leftp, const void *rightp) {
    const cer_item_t *left = (const cer_item_t *)leftp;
    const cer_item_t *right = (const cer_item_t *)rightp;
    size_t limit = left->bytes.length > right->bytes.length ?
                   left->bytes.length : right->bytes.length;
    size_t i;

    for(i = 0; i < limit; i++) {
        unsigned a = i < left->bytes.length ? left->bytes.data[i] : 0;
        unsigned b = i < right->bytes.length ? right->bytes.data[i] : 0;
        if(a != b) return a < b ? -1 : 1;
    }
    return left->declaration_index < right->declaration_index ? -1 :
           left->declaration_index > right->declaration_index ? 1 : 0;
}

/*
 * Compare SET members by their static minimum outer tag.
 * Original source: New asn1c CER encoder helper, following X.690 9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: left/right are encoded member records.
 * Returns: Tag ordering, then declaration order for equal minimum tags.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by qsort() for SET components.
 */
static int
cer_set_item_compare(const void *leftp, const void *rightp) {
    const cer_item_t *left = (const cer_item_t *)leftp;
    const cer_item_t *right = (const cer_item_t *)rightp;
    int result = cer_tag_compare(left->sort_tag, right->sort_tag);

    if(result) return result;
    return left->declaration_index < right->declaration_index ? -1 :
           left->declaration_index > right->declaration_index ? 1 : 0;
}

/*
 * Resolve an effective member tag without reading its runtime value.
 * Original source: New asn1c CER encoder helper, following X.690 9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/member identify the member; depth bounds nested CHOICE walks;
 *   result receives its effective static tag.
 * Returns: 0 on success or -1 for malformed descriptors/resource limits.
 * Errors: EOVERFLOW for descriptor work/depth limits; EBADF for bad metadata.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_member_minimum_tag(ctx, member, 1, &item.sort_tag).
 */
static int
cer_member_minimum_tag(cer_context_t *ctx, const asn_TYPE_member_t *member,
                       unsigned depth, ber_tlv_tag_t *result) {
    if(!member || !member->type) return cer_fail(ctx, EBADF, NULL, NULL);
    if(member->tag_mode == -1 || member->tag_mode == 1) {
        *result = member->tag;
        return 0;
    }
    return cer_minimum_tag(ctx, member->type, depth, result);
}

/*
 * Resolve a type's lowest possible effective outer tag without reading values.
 * Original source: New asn1c CER encoder helper, following X.690 9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td identify the descriptor graph; depth bounds CHOICE walks;
 *   result receives the minimum effective tag.
 * Returns: 0 on success or -1 for malformed descriptors/resource limits.
 * Errors: EOVERFLOW for descriptor work/depth limits; EBADF for bad metadata.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_minimum_tag(ctx, member->type, 0, &item.sort_tag).
 */
static int
cer_minimum_tag(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                unsigned depth, ber_tlv_tag_t *result) {
    unsigned i;
    int have_tag = 0;

    if(!td || !td->op || !result) return cer_fail(ctx, EBADF, td, NULL);
    if(depth >= ASN_STACK_OVERFLOW_LIMIT ||
       depth >= sizeof(unsigned) * CHAR_BIT) {
        return cer_fail(ctx, EOVERFLOW, td, NULL);
    }
    if(cer_charge_work(ctx, td, NULL)) return -1;
    if(td->tags_count) {
        if(td->tags_count > ASN_CER_MAX_ELEMENTS) {
            return cer_fail(ctx, EOVERFLOW, td, NULL);
        }
        if(!td->tags) {
            return cer_fail(ctx, EBADF, td, NULL);
        }
        *result = td->tags[0];
        return 0;
    }
    if(td->elements_count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, NULL);
    }
    if(td->op->kind != ASN_KIND_CHOICE || !td->elements ||
       td->elements_count == 0) {
        return cer_fail(ctx, ENOENT, td, NULL);
    }
    for(i = 0; i < td->elements_count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];
        ber_tlv_tag_t candidate;

        if(cer_charge_work(ctx, td, NULL)) return -1;
        if(cer_member_minimum_tag(ctx, member, depth + 1, &candidate)) {
            return -1;
        }
        if(!have_tag || cer_tag_compare(candidate, *result) < 0) {
            *result = candidate;
            have_tag = 1;
        }
    }
    return have_tag ? 0 : cer_fail(ctx, EBADF, td, NULL);
}

/*
 * Get the C structure size from trusted descriptor-specific metadata.
 * Original source: New asn1c CER encoder helper, based on OPEN_TYPE_ber_put.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td identifies the descriptor; size receives its structure size.
 * Returns: 0 for SEQUENCE, SET, or CHOICE; -1 for other/malformed metadata.
 * Errors: EBADF for absent specifics; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_descriptor_size(parent_type, &parent_size).
 */
static int
cer_descriptor_size(const asn_TYPE_descriptor_t *td, size_t *size) {
    if(!td || !td->op || !td->specifics || !size) return -1;
    switch(td->op->kind) {
    case ASN_KIND_SEQUENCE:
        *size = ((const asn_SEQUENCE_specifics_t *)td->specifics)->struct_size;
        return 0;
    case ASN_KIND_SET:
        *size = ((const asn_SET_specifics_t *)td->specifics)->struct_size;
        return 0;
    case ASN_KIND_CHOICE:
        *size = ((const asn_CHOICE_specifics_t *)td->specifics)->struct_size;
        return 0;
    case ASN_KIND_SEQUENCE_OF:
    case ASN_KIND_SET_OF:
        *size = ((const asn_SET_OF_specifics_t *)td->specifics)->struct_size;
        return 0;
    default:
        return -1;
    }
}

/*
 * Check that a descriptor member lies within its containing C structure.
 * Original source: New asn1c CER input validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the owner; structure_size is the trusted
 *   byte size; offset/member_size describe the stored field.
 * Returns: 0 when the field bounds fit; -1 on malformed metadata.
 * Errors: EBADF for out-of-bounds offsets; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_check_member_offset(ctx, td, value, struct_size, off, sizeof(void*)).
 */
static int
cer_check_member_offset(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                        const void *value, size_t structure_size,
                        unsigned offset, size_t member_size) {
    if(offset > structure_size || member_size > structure_size - offset) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Resolve a runtime-selected OPEN TYPE into a checked concrete member value.
 * Original source: New asn1c CER encoder helper, based on OPEN_TYPE_ber_put.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/parent/member are descriptor metadata; parent_value and
 *   stored_value are the containing value and stored open member; view receives
 *   the checked selected descriptor and concrete data address.
 * Returns: 0 for a consistent selector and value, otherwise -1.
 * Errors: EBADF for inconsistent choice/offset; ENOENT for absent selector.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_encode_member() for ATF_OPEN_TYPE fields.
 */
static int
cer_resolve_open_type(cer_context_t *ctx,
                      const asn_TYPE_descriptor_t *parent,
                      const void *parent_value,
                      const asn_TYPE_member_t *member, const void *stored_value,
                      cer_member_view_t *view) {
    asn_type_selector_result_t selected;

    if(!member->type_selector) return cer_fail(ctx, ENOENT, member->type,
                                                stored_value);
    selected = member->type_selector(parent, parent_value);
    if(!selected.type_descriptor || !selected.presence_index) {
        return cer_fail(ctx, ENOENT, member->type, stored_value);
    }
    if(member->type->elements_count) {
        const asn_TYPE_member_t *variant;
        const asn_CHOICE_specifics_t *specs;
        unsigned present;

        if(!member->type->elements || !member->type->specifics ||
           selected.presence_index > member->type->elements_count) {
            return cer_fail(ctx, EBADF, member->type, stored_value);
        }
        specs = (const asn_CHOICE_specifics_t *)member->type->specifics;
        if(specs->pres_size == 0 || specs->pres_size > sizeof(unsigned) ||
           cer_check_member_offset(ctx, member->type, stored_value,
                                   specs->struct_size, specs->pres_offset,
                                   specs->pres_size)) return -1;
        present = CHOICE_variant_get_presence(member->type, stored_value);
        if(present != selected.presence_index) {
            return cer_fail(ctx, EBADF, member->type, stored_value);
        }
        variant = &member->type->elements[present - 1];
        {
            size_t variant_size;
            if(variant->type != selected.type_descriptor ||
               ((variant->flags & ATF_POINTER) &&
                cer_check_member_offset(ctx, member->type, stored_value,
                                        specs->struct_size,
                                        variant->memb_offset,
                                        sizeof(void *))) ||
               (!(variant->flags & ATF_POINTER) &&
                (cer_inline_value_size(ctx, variant->type, &variant_size) ||
                 cer_check_member_offset(ctx, member->type, stored_value,
                                         specs->struct_size,
                                         variant->memb_offset, variant_size)))) {
                return cer_fail(ctx, EBADF, member->type, stored_value);
            }
        }
        view->value = (const char *)stored_value + variant->memb_offset;
        if(variant->flags & ATF_POINTER) {
            view->value = *(const void *const *)view->value;
        }
        if(!view->value) return cer_fail(ctx, EBADF, variant->type,
                                          stored_value);
    } else {
        view->value = stored_value;
    }
    view->type = selected.type_descriptor;
    return 0;
}

/*
 * Resolve a component's stored value, tags, and optional/open-type presence.
 * Original source: New asn1c CER encoder helper, based on OPEN_TYPE_ber_put.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx and parent descriptor/value identify the containing value;
 *   member selects a field; view receives the resolved encoding instruction.
 * Returns: 0 on success or -1 after recording malformed/unsupported metadata.
 * Errors: EBADF for invalid members; ENOENT for ANY/unresolved open values.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for every SEQUENCE, SET, and CHOICE component.
 */
static int
cer_encode_member(cer_context_t *ctx, const asn_TYPE_descriptor_t *parent_type,
                  const void *parent_value, const asn_TYPE_member_t *member,
                  cer_buffer_t *output, cer_member_view_t *view) {
    const void *stored;
    size_t parent_size;
    size_t member_size;

    (void)output;
    memset(view, 0, sizeof(*view));
    if(!parent_type || !parent_value || !member || !member->type ||
       cer_descriptor_size(parent_type, &parent_size)) {
        return cer_fail(ctx, EBADF, parent_type, parent_value);
    }
    if(member->flags & ATF_POINTER) {
        member_size = sizeof(void *);
    } else if(cer_inline_value_size(ctx, member->type, &member_size)) {
        return -1;
    }
    if(cer_check_member_offset(ctx, parent_type, parent_value, parent_size,
                               member->memb_offset, member_size)) return -1;
    stored = (const char *)parent_value + member->memb_offset;
    view->value = (member->flags & ATF_POINTER) ?
                  *(const void *const *)stored : stored;
    view->type = member->type;
    view->tag_mode = member->tag_mode;
    view->tag = member->tag;
    if(!view->value) {
        if(member->optional || member->default_value_cmp) return 0;
        return cer_fail(ctx, EBADF, member->type, parent_value);
    }
    if(member->default_value_cmp && member->default_value_cmp(view->value) == 0) {
        return 0;
    }
    /* An absent optional ANY has no opaque value to encode. */
    if(member->flags & ATF_ANY_TYPE) return cer_fail(ctx, ENOENT, member->type,
                                                      parent_value);
    if(member->flags & ATF_OPEN_TYPE) {
        if(cer_resolve_open_type(ctx, parent_type, parent_value, member,
                                 view->value, view)) return -1;
    }
    view->present = 1;
    return 0;
}

/*
 * Map built-in OCTET_STRING-family operation tables to intrinsic tags.
 * Original source: New asn1c CER descriptor resolver, dated 2026-10-11.
 * Parameters: td is the descriptor; number receives its semantic tag.
 * Returns: 1 when its operation table identifies a built-in string, else 0.
 * Errors: None; caller handles unsupported custom primitive operations.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: resolves an implicitly retagged UTF8String to tag 12.
 */
static int
cer_known_string_tag(const asn_TYPE_descriptor_t *td,
                     ber_tlv_tag_t *number) {
    if(td->op == &asn_OP_OCTET_STRING) *number = 4;
    else if(td->op == &asn_OP_ObjectDescriptor) *number = 7;
    else if(td->op == &asn_OP_UTF8String) *number = 12;
    else if(td->op == &asn_OP_NumericString) *number = 18;
    else if(td->op == &asn_OP_PrintableString) *number = 19;
    else if(td->op == &asn_OP_T61String || td->op == &asn_OP_TeletexString) {
        *number = 20;
    } else if(td->op == &asn_OP_VideotexString) *number = 21;
    else if(td->op == &asn_OP_IA5String) *number = 22;
    else if(td->op == &asn_OP_UTCTime) *number = 23;
    else if(td->op == &asn_OP_GraphicString) *number = 25;
    else if(td->op == &asn_OP_VisibleString || td->op == &asn_OP_ISO646String) {
        *number = 26;
    } else if(td->op == &asn_OP_GeneralString) *number = 27;
    else if(td->op == &asn_OP_UniversalString) *number = 28;
    else if(td->op == &asn_OP_BMPString) *number = 30;
    else return 0;
    return 1;
}

/*
 * Resolve the raw adapter's semantic primitive tag from its validated chain.
 * Original source: New asn1c CER descriptor resolver, dated 2026-10-11.
 * Parameters: ctx/td/value identify metadata; number receives tag 6, 9, or 13.
 * Returns: 0 for a recognized universal tag, otherwise -1.
 * Errors: ENOENT when the raw primitive operation has no supported tag.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: maps REAL, OBJECT IDENTIFIER, and RELATIVE-OID descriptors.
 */
static int
cer_resolve_raw_primitive_tag(cer_context_t *ctx,
                              const asn_TYPE_descriptor_t *td,
                              const void *value, ber_tlv_tag_t *number) {
    unsigned i;
    int found = 0;

    for(i = 0; i < td->all_tags_count; i++) {
        ber_tlv_tag_t candidate;
        if(BER_TAG_CLASS(td->all_tags[i]) != ASN_TAG_CLASS_UNIVERSAL) continue;
        candidate = BER_TAG_VALUE(td->all_tags[i]);
        if(candidate == 6 || candidate == 9 || candidate == 13) {
            *number = candidate;
            found = 1;
        }
    }
    return found ? 0 : cer_fail(ctx, ENOENT, td, value);
}

/*
 * Resolve an intrinsic tag from its concrete adapter or primitive chain.
 * Original source: New asn1c CER encoder descriptor validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the descriptor; number receives its tag.
 * Returns: 0 for known adapter storage, otherwise -1.
 * Errors: ENOENT for unsupported adapter/tag combinations.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: separates NativeInteger storage from an IMPLICIT outer tag.
 */
static int
cer_resolve_intrinsic_tag(cer_context_t *ctx,
                          const asn_TYPE_descriptor_t *td, const void *value,
                          ber_tlv_tag_t *number) {
    der_type_encoder_f *encoder = td->op->der_encoder;

    if(cer_known_string_tag(td, number)) return 0;
    if(encoder == BOOLEAN_encode_der) *number = 1;
    else if(encoder == INTEGER_encode_der ||
            encoder == NativeInteger_encode_der) *number = 2;
    else if(encoder == NativeEnumerated_encode_der) *number = 10;
    else if(encoder == NULL_encode_der) *number = 5;
    else if(encoder == NativeReal_encode_der) *number = 9;
    else if(encoder == GeneralizedTime_encode_der) *number = 24;
    else if(encoder == OCTET_STRING_encode_der) {
        const asn_OCTET_STRING_specifics_t *specs =
            (const asn_OCTET_STRING_specifics_t *)td->specifics;
        if(specs && specs->subvariant == ASN_OSUBV_BIT) *number = 3;
        else if(specs && specs->subvariant == ASN_OSUBV_U16) *number = 30;
        else if(specs && specs->subvariant == ASN_OSUBV_U32) *number = 28;
        else return cer_fail(ctx, ENOENT, td, value);
    } else if(encoder == der_encode_primitive) {
        return cer_resolve_raw_primitive_tag(ctx, td, value, number);
    } else {
        return cer_fail(ctx, ENOENT, td, value);
    }
    return 0;
}

/*
 * Find the semantic universal tag without confusing it with an IMPLICIT tag.
 * Original source: New asn1c CER encoder descriptor validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify metadata; number receives intrinsic tag.
 * Returns: 0 for recognized adapter storage or -1 for invalid/unsupported data.
 * Errors: EBADF for malformed metadata, EOVERFLOW for tag-array limits,
 *   ENOENT when no safe intrinsic tag is identifiable.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: maps a retagged NativeInteger to INTEGER content safely.
 */
static int
cer_universal_tag(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                  const void *value, ber_tlv_tag_t *number) {
    if(!td || !td->op || !number || !td->all_tags || td->all_tags_count == 0 ||
       td->tags_count > td->all_tags_count) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(td->all_tags_count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    return cer_resolve_intrinsic_tag(ctx, td, value, number);
}

/*
 * Return the inline width for native INTEGER/ENUMERATED adapters.
 * Original source: New asn1c CER member-bound validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td identify the adapter; size receives its native width.
 * Returns: 0 for supported widths or -1 for malformed specifics.
 * Errors: EBADF when the descriptor width is not 1, 2, 4, or 8 bytes.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for inline NativeInteger and NativeEnumerated members.
 */
static int
cer_native_integer_storage_size(cer_context_t *ctx,
                                const asn_TYPE_descriptor_t *td,
                                size_t *size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    unsigned width = specs ? (unsigned)specs->field_width : 0;

    if(width == 0) width = sizeof(long);
    if(width != 1 && width != 2 && width != 4 && width != 8) {
        return cer_fail(ctx, EBADF, td, NULL);
    }
    *size = width;
    return 0;
}

/*
 * Return the inline width for a native REAL adapter.
 * Original source: New asn1c CER member-bound validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td identify the adapter; size receives float or double width.
 * Returns: 0 for valid specifics or -1 for malformed metadata.
 * Errors: EBADF unless the configured native width matches float or double.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for inline native REAL members.
 */
static int
cer_native_real_storage_size(cer_context_t *ctx,
                             const asn_TYPE_descriptor_t *td, size_t *size) {
    const asn_NativeReal_specifics_t *specs =
        (const asn_NativeReal_specifics_t *)td->specifics;

    *size = specs ? specs->float_size : sizeof(double);
    if(*size != sizeof(float) && *size != sizeof(double)) {
        return cer_fail(ctx, EBADF, td, NULL);
    }
    return 0;
}

/*
 * Return storage width for a supported scalar primitive member.
 * Original source: New asn1c CER member-bound validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td identify the descriptor; number selects the scalar;
 *   size receives its inline width.
 * Returns: 0 for BOOLEAN/INTEGER/ENUMERATED/NULL/REAL or -1 otherwise.
 * Errors: EBADF for malformed adapter specifics; ENOENT for unsupported tags.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_primitive_storage_size() for non-string values.
 */
static int
cer_scalar_storage_size(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                        ber_tlv_tag_t number, size_t *size) {
    if(number == 1) {
        *size = sizeof(BOOLEAN_t);
    } else if(number == 2 || number == 10) {
        if(td->op->der_encoder == NativeInteger_encode_der ||
           td->op->der_encoder == NativeEnumerated_encode_der) {
            return cer_native_integer_storage_size(ctx, td, size);
        }
        *size = sizeof(INTEGER_t);
    } else if(number == 5) {
        *size = sizeof(NULL_t);
    } else if(number == 9) {
        if(td->op->der_encoder == NativeReal_encode_der) {
            return cer_native_real_storage_size(ctx, td, size);
        }
        *size = sizeof(REAL_t);
    } else {
        return cer_fail(ctx, ENOENT, td, NULL);
    }
    return 0;
}

/*
 * Return storage width for the primitive's documented C representation.
 * Original source: New asn1c CER input validator using built-in adapters.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td identify the descriptor; number is the intrinsic tag;
 *   size receives the inline width.
 * Returns: 0 for supported primitive layouts or -1 otherwise.
 * Errors: EBADF for inconsistent specifics and ENOENT for unsupported types.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_inline_value_size() for primitive member offsets.
 */
static int
cer_primitive_storage_size(cer_context_t *ctx,
                           const asn_TYPE_descriptor_t *td,
                           ber_tlv_tag_t number, size_t *size) {
    if(number == 3) {
        *size = sizeof(BIT_STRING_t);
        return 0;
    }
    /* OID adapters use raw primitive storage, without OCTET STRING decoder state. */
    if(number == 6 || number == 13) {
        if(!td->op || td->op->der_encoder != der_encode_primitive) {
            return cer_fail(ctx, EBADF, td, NULL);
        }
        *size = sizeof(ASN__PRIMITIVE_TYPE_t);
        return 0;
    }
    if(number == 4 || number == 7 || (number >= 12 && number <= 30)) {
        *size = sizeof(OCTET_STRING_t);
        return 0;
    }
    return cer_scalar_storage_size(ctx, td, number, size);
}

/*
 * Return the inline C value width needed to validate a descriptor member offset.
 * Original source: New asn1c CER input validator using built-in adapters.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td identify the member type; size receives its inline width.
 * Returns: 0 for known storage layouts or -1 for malformed/unknown metadata.
 * Errors: EBADF for inconsistent details and ENOENT for unsupported layouts.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used before dereferencing an inline SEQUENCE/CHOICE field.
 */
static int
cer_inline_value_size(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                      size_t *size) {
    ber_tlv_tag_t number;

    if(!td || !size) return cer_fail(ctx, EBADF, td, NULL);
    if(td->op && td->specifics &&
       td->op->der_encoder == CHOICE_encode_der) {
        *size = ((const asn_CHOICE_specifics_t *)td->specifics)->struct_size;
        return *size ? 0 : cer_fail(ctx, EBADF, td, NULL);
    }
    if(cer_descriptor_size(td, size) == 0) return 0;
    if(!td->op || td->op->kind != ASN_KIND_PRIMITIVE ||
       cer_universal_tag(ctx, td, NULL, &number)) {
        return cer_fail(ctx, ENOENT, td, NULL);
    }
    return cer_primitive_storage_size(ctx, td, number, size);
}

/*
 * Add explicit/implicit descriptor wrappers around one encoded inner TLV.
 * Original source: New asn1c CER encoder helper, based on DER tag semantics.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the operation; encoded is the current TLV;
 *   tag_mode/tag apply the member's additional tag; result receives final bytes.
 * Returns: 0 on success or -1 after setting a bounded-resource error.
 * Errors: EBADF for invalid tag metadata; EOVERFLOW/ENOMEM for buffer limits.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used after primitive, constructed, or CHOICE member encoding.
 */
static int
cer_wrap_descriptor_tags(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                         const void *value, int tag_mode, ber_tlv_tag_t tag,
                         const cer_buffer_t *encoded, cer_buffer_t *result) {
    cer_buffer_t current = {0};
    unsigned index;

    if(!td->tags_count) {
        if(cer_buffer_append(ctx, &current, encoded->data, encoded->length,
                             td, value)) goto fail;
    } else {
        if(td->tags_count > ASN_CER_MAX_ELEMENTS) {
            cer_fail(ctx, EOVERFLOW, td, value);
            goto fail;
        }
        if(!td->tags) {
            cer_fail(ctx, EBADF, td, value);
            goto fail;
        }
        if(cer_buffer_append(ctx, &current, encoded->data, encoded->length,
                             td, value)) goto fail;
        for(index = td->tags_count - 1; index > 0; index--) {
            cer_buffer_t wrapper = {0};
            ber_tlv_tag_t wrap_tag = td->tags[index - 1];
            if(index == 1 && tag_mode == -1) wrap_tag = tag;
            if(cer_make_tlv(ctx, td, value, wrap_tag, 1, 1,
                            &current, &wrapper)) {
                cer_buffer_release(ctx, &current);
                goto fail;
            }
            cer_buffer_release(ctx, &current);
            current = wrapper;
        }
    }
    if(tag_mode == -1 && td->tags_count == 0) {
        cer_buffer_t wrapper = {0};
        if(cer_make_tlv(ctx, td, value, tag, 1, 1, &current, &wrapper)) {
            cer_buffer_release(ctx, &current);
            goto fail;
        }
        cer_buffer_release(ctx, &current);
        current = wrapper;
    } else if(tag_mode == 1) {
        cer_buffer_t wrapper = {0};
        if(cer_make_tlv(ctx, td, value, tag, 1, 1, &current, &wrapper)) {
            cer_buffer_release(ctx, &current);
            goto fail;
        }
        cer_buffer_release(ctx, &current);
        current = wrapper;
    } else if(tag_mode != 0 && tag_mode != -1) {
        cer_fail(ctx, EBADF, td, value);
        goto fail;
    }
    *result = current;
    return 0;

fail:
    cer_buffer_release(ctx, &current);
    return -1;
}

/*
 * Apply CHOICE descriptor tags around its selected alternative exactly once.
 * Original source: New asn1c CER encoder helper, following X.690 8.13/9.1.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the choice; tag_mode/tag are enclosing
 *   member tags; encoded is the selected child TLV; result receives final bytes.
 * Returns: 0 on success or -1 for invalid tag metadata/resource failure.
 * Errors: EBADF/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called after encoding the selected CHOICE alternative.
 */
static int
cer_wrap_choice_tags(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                     const void *value, int tag_mode, ber_tlv_tag_t tag,
                     const cer_buffer_t *encoded, cer_buffer_t *result) {
    cer_buffer_t current = {0};
    unsigned remaining;

    if(tag_mode != 0 && tag_mode != -1 && tag_mode != 1) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(cer_buffer_append(ctx, &current, encoded->data, encoded->length,
                         td, value)) return -1;
    if(td->tags_count > ASN_CER_MAX_ELEMENTS) {
        cer_buffer_release(ctx, &current);
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(td->tags_count && !td->tags) {
        cer_buffer_release(ctx, &current);
        return cer_fail(ctx, EBADF, td, value);
    }
    for(remaining = td->tags_count; remaining > 0; remaining--) {
        ber_tlv_tag_t wrap_tag = td->tags[remaining - 1];
        cer_buffer_t wrapper = {0};

        if(remaining == 1 && tag_mode == -1) wrap_tag = tag;
        if(cer_make_tlv(ctx, td, value, wrap_tag, 1, 1, &current, &wrapper)) {
            cer_buffer_release(ctx, &current);
            return -1;
        }
        cer_buffer_release(ctx, &current);
        current = wrapper;
    }
    if(tag_mode == 1) {
        cer_buffer_t wrapper = {0};
        if(cer_make_tlv(ctx, td, value, tag, 1, 1, &current, &wrapper)) {
            cer_buffer_release(ctx, &current);
            return -1;
        }
        cer_buffer_release(ctx, &current);
        current = wrapper;
    } else if(tag_mode == -1 && td->tags_count == 0) {
        if(cer_replace_outer_tag(ctx, td, value, &current, tag, result)) {
            cer_buffer_release(ctx, &current);
            return -1;
        }
        cer_buffer_release(ctx, &current);
        return 0;
    }
    *result = current;
    return 0;
}

/*
 * Build the complete CER form of a primitive's validated DER content.
 * Original source: New asn1c CER encoder helper, following X.690 9.2/9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the type; universal_tag identifies the
 *   intrinsic universal type; bit_string selects the BIT STRING fragmentation
 *   content prefix; named_bits requests trailing-zero removal; tag mode applies
 *   member tagging; content is canonical primitive content; result receives TLV.
 * Returns: 0 on success or -1 for malformed values, unsupported types, or caps.
 * Errors: EBADF/EOVERFLOW/ENOMEM/ENOENT according to failure.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_encode_value() for primitive values.
 */
/*
 * Encode non-BIT string content using CER's 1000-octet fragmentation rule.
 * Character-string components use OCTET STRING tag 4 per X.690 8.23.3.
 * Original source: New asn1c CER encoder helper, following X.690 8.23.3/9.2.
 * Version/date: 1.1, 2026-10-12.
 * Parameters: ctx/td/value identify the operation; content holds canonical
 *   contents; base_tag is the effective outer type tag; result receives the TLV.
 * Returns: 0 on success; -1 for bounded allocation or encoding failure.
 * Errors: EOVERFLOW, ENOMEM, or EBADF through ctx->error.
 * Responsible party: asn1c maintainers. History: Corrected component tags to
 * universal 4 for non-BIT character strings; BIT STRING remains on tag 3.
 * Example: used for long OCTET STRING and character-string values.
 */
static int
cer_encode_octet_fragments(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                           const void *value, ber_tlv_tag_t base_tag,
                           const cer_buffer_t *content,
                           cer_buffer_t *result) {
    cer_buffer_t fragments = {0};
    const ber_tlv_tag_t fragment_tag =
        ASN_TAG_CLASS_UNIVERSAL | (4u << 2);
    size_t offset = 0;

    while(offset < content->length) {
        size_t take = content->length - offset;
        cer_buffer_t part = {0};
        cer_buffer_t fragment = {0};

        if(take > 1000) take = 1000;
        if(cer_buffer_append(ctx, &part, content->data + offset, take, td,
                             value) ||
           cer_make_tlv(ctx, td, value, fragment_tag, 0, 0, &part,
                        &fragment) ||
           cer_buffer_append(ctx, &fragments, fragment.data, fragment.length,
                             td, value)) {
            cer_buffer_release(ctx, &part);
            cer_buffer_release(ctx, &fragment);
            cer_buffer_release(ctx, &fragments);
            return -1;
        }
        cer_buffer_release(ctx, &part);
        cer_buffer_release(ctx, &fragment);
        offset += take;
    }
    if(cer_make_tlv(ctx, td, value, base_tag, 1, 1, &fragments, result)) {
        cer_buffer_release(ctx, &fragments);
        return -1;
    }
    cer_buffer_release(ctx, &fragments);
    return 0;
}

/*
 * Remove trailing zero bits from a named BIT STRING content view.
 * Original source: New asn1c CER helper, following X.690 11.2.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the string; content is DER BIT STRING
 *   content; data_size and unused receive the compacted logical content size.
 * Returns: 0 for valid contents or -1 for malformed data.
 * Errors: EBADF for missing content; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used before encoding named BIT STRING fragments.
 */
static int
cer_trim_named_bits(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                    const void *value, const cer_buffer_t *content,
                    size_t *data_size, uint8_t *unused) {
    uint8_t last;

    if(content->length == 0 || !content->data) {
        return cer_fail(ctx, EBADF, td, value);
    }
    *data_size = content->length - 1;
    while(*data_size && content->data[*data_size] == 0) (*data_size)--;
    *unused = 0;
    if(*data_size) {
        last = content->data[*data_size];
        while(*unused < 7 && ((last >> *unused) & 1u) == 0) (*unused)++;
    }
    return 0;
}

/*
 * Emit a short primitive BIT STRING with its unused-bits octet.
 * Original source: New asn1c CER encoder helper, following X.690 8.6.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the string; content/data_size/unused
 *   provide the canonical bit body; base_tag is its effective tag; result
 *   receives the primitive TLV.
 * Returns: 0 on success or -1 for bounded buffer failure.
 * Errors: EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for BIT STRINGs with at most 1000 content octets.
 */
static int
cer_encode_short_bits(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                      const void *value, ber_tlv_tag_t base_tag,
                      const cer_buffer_t *content, size_t data_size,
                      uint8_t unused, cer_buffer_t *result) {
    cer_buffer_t body = {0};
    int status;

    status = cer_buffer_append(ctx, &body, &unused, 1, td, value) ||
             cer_buffer_append(ctx, &body, content->data + 1, data_size,
                               td, value) ||
             cer_make_tlv(ctx, td, value, base_tag, 0, 0, &body, result);
    cer_buffer_release(ctx, &body);
    return status ? -1 : 0;
}

/*
 * Append one BIT STRING fragment with its final or intermediate unused count.
 * Original source: New asn1c CER encoder helper, following X.690 9.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; universal_tag is the fragment
 *   tag; content/offset/take select payload; unused is the final bit count;
 *   fragments receives the encoded component.
 * Returns: 0 on success or -1 after a bounded append failure.
 * Errors: EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called once for every at-most-999-octet BIT STRING fragment.
 */
static int
cer_append_bit_fragment(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                        const void *value, ber_tlv_tag_t universal_tag,
                        const cer_buffer_t *content, size_t offset,
                        size_t take, uint8_t unused, cer_buffer_t *fragments) {
    uint8_t part_bytes[1000];
    cer_buffer_t part = {0};
    cer_buffer_t fragment = {0};
    int status;

    part_bytes[0] = offset + take < content->length - 1 ? 0 : unused;
    memcpy(part_bytes + 1, content->data + 1 + offset, take);
    status = cer_buffer_append(ctx, &part, part_bytes, take + 1, td, value) ||
             cer_make_tlv(ctx, td, value, universal_tag, 0, 0, &part,
                          &fragment) ||
             cer_buffer_append(ctx, fragments, fragment.data, fragment.length,
                               td, value);
    cer_buffer_release(ctx, &part);
    cer_buffer_release(ctx, &fragment);
    return status ? -1 : 0;
}

/*
 * Encode BIT STRING contents with a one-octet unused-bits count per fragment.
 * Original source: New asn1c CER encoder helper, following X.690 9.2/11.2.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the operation; universal_tag and base_tag
 *   identify fragments and outer TLV; content holds DER BIT STRING contents;
 *   named_bits enables canonical trailing-zero removal; result receives TLV.
 * Returns: 0 on success; -1 for invalid contents, resource bounds, or allocation.
 * Errors: EBADF/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for ordinary and named BIT STRING values.
 */
static int
cer_encode_bit_fragments(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                         const void *value, ber_tlv_tag_t universal_tag,
                         ber_tlv_tag_t base_tag, int named_bits,
                         const cer_buffer_t *content, cer_buffer_t *result) {
    cer_buffer_t fragments = {0};
    size_t data_size, offset = 0;
    uint8_t unused;

    if(content->length == 0 || !content->data) {
        return cer_fail(ctx, EBADF, td, value);
    }
    data_size = content->length - 1;
    unused = content->data[0];
    if(unused > 7) return cer_fail(ctx, EBADF, td, value);
    if(named_bits &&
       cer_trim_named_bits(ctx, td, value, content, &data_size, &unused)) {
        return -1;
    }
    if(data_size + 1 <= 1000) {
        return cer_encode_short_bits(ctx, td, value, base_tag, content,
                                     data_size, unused, result);
    }
    while(offset < data_size) {
        size_t take = data_size - offset;
        if(take > 999) take = 999;
        if(cer_append_bit_fragment(ctx, td, value, universal_tag, content,
                                   offset, take, unused, &fragments)) {
            cer_buffer_release(ctx, &fragments);
            return -1;
        }
        offset += take;
    }
    if(cer_make_tlv(ctx, td, value, base_tag, 1, 1, &fragments, result)) {
        cer_buffer_release(ctx, &fragments);
        return -1;
    }
    cer_buffer_release(ctx, &fragments);
    return 0;
}

/*
 * Assemble a canonical primitive value and apply its descriptor-level tags.
 * Original source: New asn1c CER encoder helper, following X.690 sections 9-11.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; tag_mode/tag apply member tags;
 *   universal_tag is the intrinsic tag; fragmentable/bit_string/named_bits
 *   select string handling; content contains canonical DER primitive bytes.
 * Returns: 0 on success or -1 after recording the precise failure.
 * Errors: EBADF, ENOENT, EOVERFLOW, or ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_encode_value() after checked DER capture.
 */
static int
cer_build_primitive_tlv(cer_context_t *ctx,
                             const asn_TYPE_descriptor_t *td,
                             const void *value, int tag_mode,
                             ber_tlv_tag_t tag, ber_tlv_tag_t universal_tag,
                             int fragmentable, int bit_string, int named_bits,
                             cer_buffer_t *content, cer_buffer_t *result) {
    cer_buffer_t inner = {0};
    ber_tlv_tag_t base_tag;
    int status = 0;

    if(td->tags_count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(!td->tags || td->tags_count == 0) {
        return cer_fail(ctx, EBADF, td, value);
    }
    base_tag = (tag_mode == -1 && td->tags_count == 1) ? tag :
               td->tags[td->tags_count - 1];
    if(bit_string) {
        status = cer_encode_bit_fragments(ctx, td, value, universal_tag,
                                          base_tag, named_bits, content, &inner);
    } else if(fragmentable && content->length > 1000) {
        status = cer_encode_octet_fragments(ctx, td, value, base_tag, content,
                                            &inner);
    } else {
        status = cer_make_tlv(ctx, td, value, base_tag, 0, 0, content, &inner);
    }
    if(status) {
        cer_buffer_release(ctx, &inner);
        return -1;
    }
    status = cer_wrap_descriptor_tags(ctx, td, value, tag_mode, tag, &inner,
                                      result);
    cer_buffer_release(ctx, &inner);
    return status;
}

/*
 * Validate object-identifier content before accepting raw DER primitive bytes.
 * Original source: New asn1c CER encoder validator, following X.690 8.19/8.20.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; bytes/size hold OID content.
 * Returns: 0 for complete minimally encoded base-128 subidentifiers.
 * Errors: EBADF for empty, unterminated, or nonminimal subidentifiers.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_validate_oid(ctx, td, value, content, content_size).
 */
static int
cer_validate_oid(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                 const void *value, const uint8_t *bytes, size_t size) {
    size_t i;
    int at_start = 1;

    if(size == 0 || !bytes) return cer_fail(ctx, EBADF, td, value);
    for(i = 0; i < size; i++) {
        if(at_start && bytes[i] == 0x80) {
            return cer_fail(ctx, EBADF, td, value);
        }
        at_start = (bytes[i] & 0x80) == 0;
    }
    return at_start ? 0 : cer_fail(ctx, EBADF, td, value);
}

/*
 * Check a Gregorian year for leap-day rules.
 * Original source: New asn1c CER helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: year is a Gregorian calendar year.
 * Returns: 1 for leap year, 0 otherwise.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_is_leap_year(2000) returns 1.
 */
static unsigned
cer_is_leap_year(unsigned year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

/*
 * Return the leap-year-aware day offset before a month.
 * Original source: New asn1c CER helper using Gregorian calendar arithmetic.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: year/month are valid Gregorian calendar fields.
 * Returns: Zero-based day offset from January 1.
 * Errors: Caller validates ranges; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_days_before_month(2000, 3) returns 60.
 */
static unsigned
cer_days_before_month(unsigned year, unsigned month) {
    static const unsigned short days[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    unsigned result = days[month - 1];
    if(month > 2 && cer_is_leap_year(year)) result++;
    return result;
}

/* Parsed UTCTime fields normalized to the UTC calendar. */
typedef struct cer_utc_fields_s {
    unsigned year; /* Full year in the ASN.1 1950-2049 window. */
    unsigned month; /* Month from 1 through 12. */
    unsigned day; /* Day of month after calendar validation. */
    unsigned hour; /* Hour from 0 through 23. */
    unsigned minute; /* Minute from 0 through 59. */
    unsigned second; /* Seconds, zero when absent in input. */
    unsigned offset_hour; /* Parsed numeric zone hour. */
    unsigned offset_minute; /* Parsed numeric zone minute. */
    int zone_sign; /* Positive input offset is subtracted to obtain UTC. */
    size_t field_count; /* Five fields without seconds, six with seconds. */
} cer_utc_fields_t;

/*
 * Parse a pair of decimal digits from a bounded UTCTime buffer.
 * Original source: New asn1c CER time parser.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: source is a validated non-null string; offset selects two octets;
 *   number receives their decimal value.
 * Returns: 0 for two digits and -1 for out-of-range/non-digit input.
 * Errors: No errno mutation or allocation; caller records malformed syntax.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_read_two_digits(source, 0, &year).
 */
static int
cer_read_two_digits(const OCTET_STRING_t *source, size_t offset,
                    unsigned *number) {
    uint8_t first, second;
    if(offset + 1 >= source->size) return -1;
    first = source->buf[offset];
    second = source->buf[offset + 1];
    if(first < '0' || first > '9' || second < '0' || second > '9') return -1;
    *number = (first - '0') * 10 + (second - '0');
    return 0;
}

/*
 * Parsed GeneralizedTime fields before canonical UTC conversion.
 * The cursor and precision count bound parsing of the original text.
 */
typedef struct cer_generalized_time_fields_s {
    unsigned year; /* Four-digit Gregorian year. */
    unsigned month; /* Month from 1 through 12. */
    unsigned day; /* Day of month validated against the calendar. */
    unsigned hour; /* Hour from 0 through 23. */
    unsigned minute; /* Minute from 0 through 59, defaulting to zero. */
    unsigned second; /* Second from 0 through 59, defaulting to zero. */
    unsigned fraction_digits; /* Fraction precision accepted by the adapter. */
    size_t position; /* state variable: next unparsed input octet. */
    int has_minute; /* Whether the optional minute component was present. */
    int has_second; /* Whether the optional second component was present. */
} cer_generalized_time_fields_t;

/*
 * Identify an ASCII decimal digit without locale-dependent classification.
 * Original source: New asn1c CER time parser.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: octet is one input byte.
 * Returns: Nonzero for '0' through '9', zero otherwise.
 * Errors: None; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by the GeneralizedTime component and fraction parser.
 */
static int
cer_is_decimal_digit(uint8_t octet) {
    return octet >= '0' && octet <= '9';
}

/*
 * Read one two-digit GeneralizedTime component and advance its cursor.
 * Original source: New asn1c CER time parser.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify errors; source is bounded; fields carries
 *   the cursor; component receives the decimal pair.
 * Returns: 0 for two digits, otherwise -1 with EBADF.
 * Errors: EBADF for truncated or nondecimal components.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for year, month, day, hour, minute, second, and zone fields.
 */
static int
cer_read_generalized_component(cer_context_t *ctx,
                               const asn_TYPE_descriptor_t *td,
                               const GeneralizedTime_t *source,
                               const void *value,
                               cer_generalized_time_fields_t *fields,
                               unsigned *component) {
    if(cer_read_two_digits((const OCTET_STRING_t *)source, fields->position,
                           component)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    fields->position += 2;
    return 0;
}

/*
 * Parse optional GeneralizedTime minute/second fields.
 * Original source: New asn1c CER parser, following X.690 11.7.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify errors; source is bounded; fields receives
 *   optional component values and cursor updates.
 * Returns: 0 for complete pairs, otherwise -1 with EBADF.
 * Errors: EBADF for truncated optional fields; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used between mandatory hour parsing and fraction parsing.
 */
static int
cer_parse_generalized_optional_clock(cer_context_t *ctx,
                                     const asn_TYPE_descriptor_t *td,
                                     const GeneralizedTime_t *source,
                                     const void *value,
                                     cer_generalized_time_fields_t *fields) {
    if(fields->position < source->size &&
       cer_is_decimal_digit(source->buf[fields->position])) {
        if(cer_read_generalized_component(ctx, td, source, value, fields,
                                          &fields->minute)) return -1;
        fields->has_minute = 1;
    }
    if(fields->position < source->size &&
       cer_is_decimal_digit(source->buf[fields->position])) {
        if(cer_read_generalized_component(ctx, td, source, value, fields,
                                          &fields->second)) return -1;
        fields->has_second = 1;
    }
    return 0;
}

/*
 * Parse a bounded GeneralizedTime fractional component.
 * Original source: New asn1c CER parser, following X.690 11.7.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify errors; source is bounded; fields holds
 *   the cursor and receives the number of fractional digits.
 * Returns: 0 when absent or supported; otherwise -1.
 * Errors: EBADF for malformed syntax; ENOENT above nine fractional digits.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: validates precision before the DER adapter can truncate it.
 */
static int
cer_parse_generalized_fraction(cer_context_t *ctx,
                               const asn_TYPE_descriptor_t *td,
                               const GeneralizedTime_t *source,
                               const void *value,
                               cer_generalized_time_fields_t *fields) {
    if(fields->position == source->size ||
       (source->buf[fields->position] != '.' &&
        source->buf[fields->position] != ',')) return 0;
    if(!fields->has_minute || !fields->has_second) {
        return cer_fail(ctx, ENOENT, td, value);
    }
    fields->position++;
    while(fields->position < source->size &&
          cer_is_decimal_digit(source->buf[fields->position])) {
        fields->fraction_digits++;
        if(fields->fraction_digits > 9) return cer_fail(ctx, ENOENT, td, value);
        fields->position++;
    }
    return fields->fraction_digits ? 0 : cer_fail(ctx, EBADF, td, value);
}

/*
 * Parse GeneralizedTime calendar and clock fields before calling timegm().
 * Original source: New asn1c CER parser, following X.690 11.7.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; fields receives parsed values.
 * Returns: 0 for supported syntax or -1 for invalid/unsupported precision.
 * Errors: EBADF for malformed fields; ENOENT for precision above nine digits.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before the GeneralizedTime DER adapter to prevent truncation.
 */
static int
cer_parse_generalized_time_clock(cer_context_t *ctx,
                                 const asn_TYPE_descriptor_t *td,
                                 const GeneralizedTime_t *source,
                                 const void *value,
                                 cer_generalized_time_fields_t *fields) {
    unsigned high_year, low_year;

    memset(fields, 0, sizeof(*fields));
    if(!source->buf || source->size < 10) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(cer_read_generalized_component(ctx, td, source, value, fields,
                                      &high_year) ||
       cer_read_generalized_component(ctx, td, source, value, fields,
                                      &low_year)) return -1;
    fields->year = high_year * 100 + low_year;
    if(cer_read_generalized_component(ctx, td, source, value, fields,
                                      &fields->month) ||
       cer_read_generalized_component(ctx, td, source, value, fields,
                                      &fields->day) ||
       cer_read_generalized_component(ctx, td, source, value, fields,
                                      &fields->hour)) return -1;
    if(cer_parse_generalized_optional_clock(ctx, td, source, value, fields) ||
       cer_parse_generalized_fraction(ctx, td, source, value, fields)) return -1;
    return 0;
}

/*
 * Validate GeneralizedTime calendar fields before the adapter normalizes them.
 * Original source: New asn1c CER validator, following X.690 11.7.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify errors; fields contains parsed fields.
 * Returns: 0 for valid Gregorian date/time or -1 for invalid fields.
 * Errors: EBADF for year zero, invalid day, or out-of-range clock values.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used before zone conversion to reject normalized invalid dates.
 */
static int
cer_validate_generalized_time_calendar(cer_context_t *ctx,
                                      const asn_TYPE_descriptor_t *td,
                                      const void *value,
                                      const cer_generalized_time_fields_t *fields) {
    static const unsigned char month_days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    unsigned max_day;

    if(fields->year == 0 || fields->month < 1 || fields->month > 12 ||
       fields->hour > 23 || fields->minute > 59 || fields->second > 59) {
        return cer_fail(ctx, EBADF, td, value);
    }
    max_day = month_days[fields->month - 1];
    if(fields->month == 2 && cer_is_leap_year(fields->year)) max_day++;
    return fields->day >= 1 && fields->day <= max_day ? 0 :
           cer_fail(ctx, EBADF, td, value);
}

/*
 * Require an explicit, in-range GeneralizedTime zone suffix.
 * Original source: New asn1c CER parser, following X.690 11.7.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify errors; source and fields carry bounded
 *   text and the cursor immediately before its zone.
 * Returns: 0 for Z or +/-hh[mm], otherwise -1.
 * Errors: ENOENT for local time; EBADF for malformed or out-of-range zones.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: prevents timegm() from interpreting input in the process local zone.
 */
static int
cer_validate_generalized_time_zone(cer_context_t *ctx,
                                   const asn_TYPE_descriptor_t *td,
                                   const GeneralizedTime_t *source,
                                   const void *value,
                                   cer_generalized_time_fields_t *fields) {
    size_t remaining = source->size - fields->position;
    unsigned hour, minute = 0;

    if(remaining == 0) return cer_fail(ctx, ENOENT, td, value);
    if(remaining == 1 && source->buf[fields->position] == 'Z') return 0;
    if((remaining != 3 && remaining != 5) ||
       (source->buf[fields->position] != '+' &&
        source->buf[fields->position] != '-')) {
        return cer_fail(ctx, EBADF, td, value);
    }
    fields->position++;
    if(cer_read_generalized_component(ctx, td, source, value, fields, &hour)) {
        return -1;
    }
    if(remaining == 5 &&
       cer_read_generalized_component(ctx, td, source, value, fields, &minute)) {
        return -1;
    }
    return hour <= 23 && minute <= 59 ? 0 :
           cer_fail(ctx, EBADF, td, value);
}

/*
 * Validate all supported GeneralizedTime forms before canonical conversion.
 * Original source: New asn1c CER validator, following X.690 11.7.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify errors; source is the candidate value.
 * Returns: 0 for valid zoned text or -1 for malformed/unsupported input.
 * Errors: EBADF for invalid calendar/syntax, ENOENT for local or >9-digit time.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before GeneralizedTime_encode_der() performs UTC rendering.
 */
static int
cer_validate_generalized_time(cer_context_t *ctx,
                              const asn_TYPE_descriptor_t *td,
                              const GeneralizedTime_t *source) {
    cer_generalized_time_fields_t fields;

    if(cer_parse_generalized_time_clock(ctx, td, source, source, &fields) ||
       cer_validate_generalized_time_calendar(ctx, td, source, &fields) ||
       cer_validate_generalized_time_zone(ctx, td, source, source, &fields)) {
        return -1;
    }
    return 0;
}

/*
 * Check mandatory fields and lexical form of adapter-produced CER time text.
 * Original source: New asn1c CER post-adapter validator, dated 2026-10-11.
 * Parameters: ctx/td/value identify errors; content holds bounded text bytes.
 * Returns: 0 for YYYYMMDDHHMMSS[.fraction]Z, otherwise -1.
 * Errors: EBADF for malformed output; ENOENT for unsupported precision.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: rejects a normalized time that crossed the four-digit year range.
 */
static int
cer_check_generalized_canonical_shape(cer_context_t *ctx,
                                      const asn_TYPE_descriptor_t *td,
                                      const void *value,
                                      const cer_buffer_t *content) {
    size_t i;
    size_t fraction_digits = 0;

    if(!content->data || content->length < 15 ||
       content->data[content->length - 1] != 'Z') {
        return cer_fail(ctx, EBADF, td, value);
    }
    for(i = 0; i < 14; i++) {
        if(!cer_is_decimal_digit(content->data[i])) {
            return cer_fail(ctx, EBADF, td, value);
        }
    }
    if(content->length == 15) return 0;
    if(content->data[14] != '.') return cer_fail(ctx, EBADF, td, value);
    for(i = 15; i + 1 < content->length; i++) {
        if(!cer_is_decimal_digit(content->data[i])) {
            return cer_fail(ctx, EBADF, td, value);
        }
        fraction_digits++;
    }
    if(fraction_digits == 0) return cer_fail(ctx, EBADF, td, value);
    if(fraction_digits > 9) return cer_fail(ctx, ENOENT, td, value);
    if(content->data[content->length - 2] == '0') {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Validate canonical GeneralizedTime adapter output and its calendar fields.
 * Original source: New asn1c CER post-adapter validator, dated 2026-10-11.
 * Parameters: ctx/td/value identify the value; content contains DER text bytes.
 * Returns: 0 for canonical four-digit UTC form; otherwise -1.
 * Errors: EBADF for invalid calendar or shape; ENOENT for unsupported precision.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: validates GeneralizedTime before constructing its CER primitive TLV.
 */
static int
cer_validate_canonical_generalized_time(cer_context_t *ctx,
                                        const asn_TYPE_descriptor_t *td,
                                        const void *value,
                                        const cer_buffer_t *content) {
    GeneralizedTime_t normalized;

    if(cer_check_generalized_canonical_shape(ctx, td, value, content)) {
        return -1;
    }
    memset(&normalized, 0, sizeof(normalized));
    normalized.buf = content->data;
    normalized.size = content->length;
    return cer_validate_generalized_time(ctx, td, &normalized);
}

/*
 * Validate the parsed UTCTime calendar fields.
 * Original source: New asn1c CER time parser, following X.690 11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: fields contains parsed numeric date/time values.
 * Returns: 0 for a valid date/time and -1 otherwise.
 * Errors: No allocation or exceptions; caller sets EBADF.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_validate_utc_fields(&fields).
 */
static int
cer_validate_utc_fields(const cer_utc_fields_t *fields) {
    static const unsigned char month_days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    unsigned max_day;

    if(fields->month < 1 || fields->month > 12 || fields->hour > 23 ||
       fields->minute > 59 || fields->second > 59) return -1;
    max_day = month_days[fields->month - 1];
    if(fields->month == 2 && cer_is_leap_year(fields->year)) max_day++;
    return fields->day >= 1 && fields->day <= max_day ? 0 : -1;
}

/*
 * Parse decimal fields from UTCTime into full calendar values.
 * Original source: New asn1c CER time parser, following X.690 11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; source holds bounded bytes;
 *   fields receives the parsed calendar fields.
 * Returns: 0 on valid decimal fields or -1 for malformed digits.
 * Errors: EBADF for invalid text; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_parse_utc_fields() before zone validation.
 */
static int
cer_parse_utc_digits(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                     const void *value, const OCTET_STRING_t *source,
                     cer_utc_fields_t *fields) {
    unsigned *values[6];
    size_t i;

    fields->field_count = (source->size == 11 || source->size == 15) ? 5 : 6;
    values[0] = &fields->year;
    values[1] = &fields->month;
    values[2] = &fields->day;
    values[3] = &fields->hour;
    values[4] = &fields->minute;
    values[5] = &fields->second;
    for(i = 0; i < fields->field_count; i++) {
        if(cer_read_two_digits(source, 2 * i, values[i])) {
            return cer_fail(ctx, EBADF, td, value);
        }
    }
    fields->year += fields->year >= 50 ? 1900 : 2000;
    return 0;
}

/*
 * Parse a UTCTime zone suffix and store its offset in calendar fields.
 * Original source: New asn1c CER time parser, following X.690 11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; source contains bounded bytes;
 *   fields supplies the component width and receives the zone offset.
 * Returns: 0 for Z or a valid numeric offset; -1 for malformed suffixes.
 * Errors: EBADF for malformed zone syntax; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_parse_utc_fields() after decimal fields are parsed.
 */
static int
cer_parse_utc_zone(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                   const void *value, const OCTET_STRING_t *source,
                   cer_utc_fields_t *fields) {
    size_t offset = fields->field_count * 2;
    unsigned zone_hour, zone_minute;

    if(source->buf[source->size - 1] == 'Z') {
        return source->size == offset + 1 ? 0 :
               cer_fail(ctx, EBADF, td, value);
    }
    if(offset + 5 != source->size ||
       (source->buf[offset] != '+' && source->buf[offset] != '-')) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(cer_read_two_digits(source, offset + 1, &zone_hour) ||
       cer_read_two_digits(source, offset + 3, &zone_minute) ||
       zone_hour > 23 || zone_minute > 59) {
        return cer_fail(ctx, EBADF, td, value);
    }
    fields->offset_hour = zone_hour;
    fields->offset_minute = zone_minute;
    fields->zone_sign = source->buf[offset] == '+' ? 1 : -1;
    return 0;
}

/*
 * Parse UTCTime's permitted date, optional seconds, and numeric zone.
 * Original source: New asn1c CER time parser, following X.690 11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; source holds its bounded bytes;
 *   fields receives the validated fields.
 * Returns: 0 on valid syntax or -1 for malformed input.
 * Errors: EBADF for invalid text/date/zone; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_parse_utc_fields(ctx, td, value, source, &fields).
 */
static int
cer_parse_utc_fields(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                     const void *value, const OCTET_STRING_t *source,
                     cer_utc_fields_t *fields) {
    memset(fields, 0, sizeof(*fields));
    if(!source->buf || (source->size != 11 && source->size != 13 &&
       source->size != 15 && source->size != 17)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(cer_parse_utc_digits(ctx, td, value, source, fields) ||
       cer_parse_utc_zone(ctx, td, value, source, fields)) return -1;
    return cer_validate_utc_fields(fields) ?
           cer_fail(ctx, EBADF, td, value) : 0;
}

/*
 * Convert validated local UTCTime fields to minutes since 1950-01-01 UTC.
 * Original source: New asn1c CER time parser using Gregorian arithmetic.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: fields contains valid calendar and zone data.
 * Returns: Signed minute offset from the supported 1950 UTC epoch.
 * Errors: None; caller validates that the result stays in the UTCTime window.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_utc_minutes_since_1950(&fields).
 */
static int64_t
cer_utc_minutes_since_1950(const cer_utc_fields_t *fields) {
    unsigned day_index = 0;
    unsigned year;

    for(year = 1950; year < fields->year; year++) {
        day_index += cer_is_leap_year(year) ? 366 : 365;
    }
    day_index += cer_days_before_month(fields->year, fields->month);
    day_index += fields->day - 1;
    return (int64_t)day_index * 1440 + fields->hour * 60 + fields->minute -
           fields->zone_sign *
           (int64_t)(fields->offset_hour * 60 + fields->offset_minute);
}

/*
 * Convert epoch minutes back to a UTCTime calendar within years 1950-2049.
 * Original source: New asn1c CER time parser using Gregorian arithmetic.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the conversion; minutes is the signed UTC
 *   minute offset; fields receives normalized year/month/day/hour/minute.
 * Returns: 0 on success or -1 when zone conversion leaves the UTCTime window.
 * Errors: EOVERFLOW when the canonical UTC year would be outside 1950-2049.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_normalize_utc_fields(ctx, td, value, minutes, &fields).
 */
static int
cer_normalize_utc_fields(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                         const void *value, int64_t minutes,
                         cer_utc_fields_t *fields) {
    unsigned days_in_year, year = 1950, month = 1, day_index;

    if(minutes < 0) return cer_fail(ctx, EOVERFLOW, td, value);
    while(year <= 2049) {
        days_in_year = cer_is_leap_year(year) ? 366 : 365;
        if(minutes < (int64_t)days_in_year * 1440) break;
        minutes -= (int64_t)days_in_year * 1440;
        year++;
    }
    if(year > 2049) return cer_fail(ctx, EOVERFLOW, td, value);
    day_index = (unsigned)(minutes / 1440);
    fields->hour = (unsigned)((minutes % 1440) / 60);
    fields->minute = (unsigned)(minutes % 60);
    while(month < 12) {
        unsigned month_days = cer_days_before_month(year, month + 1) -
                              cer_days_before_month(year, month);
        if(day_index < month_days) break;
        day_index -= month_days;
        month++;
    }
    fields->year = year;
    fields->month = month;
    fields->day = day_index + 1;
    return 0;
}

/*
 * Render normalized UTCTime fields as the 13-octet CER canonical text.
 * Original source: New asn1c CER time renderer, following X.690 11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify destination accounting; fields contains
 *   normalized fields; result receives YYMMDDhhmmssZ.
 * Returns: 0 on bounded append success or -1 on allocation failure.
 * Errors: EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_normalize_utc_time() after zone conversion.
 */
static int
cer_render_utc_time(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                    const void *value, const cer_utc_fields_t *fields,
                    cer_buffer_t *result) {
    uint8_t output[13];
    unsigned year = fields->year % 100;
    const unsigned components[6] = {
        year, fields->month, fields->day, fields->hour, fields->minute,
        fields->second
    };
    size_t i;

    for(i = 0; i < 6; i++) {
        output[2 * i] = (uint8_t)('0' + components[i] / 10);
        output[2 * i + 1] = (uint8_t)('0' + components[i] % 10);
    }
    output[12] = 'Z';
    return cer_buffer_append(ctx, result, output, sizeof(output), td, value);
}

/*
 * Parse and normalize UTCTime to the required seconds-and-Z representation.
 * Original source: New asn1c CER helper, following X.690 11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; source is the input text;
 *   result receives a newly allocated 13-octet canonical time string.
 * Returns: 0 on canonical output; -1 for invalid fields or allocation failure.
 * Errors: EBADF for invalid syntax/date/offset, EOVERFLOW for unsupported years,
 *   and ENOMEM for scratch allocation failure.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_normalize_utc_time(ctx, td, value, source, result).
 */
static int
cer_normalize_utc_time(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                       const void *value, const OCTET_STRING_t *source,
                       cer_buffer_t *result) {
    cer_utc_fields_t fields;
    int64_t minutes;

    memset(result, 0, sizeof(*result));
    if(cer_parse_utc_fields(ctx, td, value, source, &fields)) return -1;
    minutes = cer_utc_minutes_since_1950(&fields);
    if(cer_normalize_utc_fields(ctx, td, value, minutes, &fields)) return -1;
    return cer_render_utc_time(ctx, td, value, &fields, result);
}

/*
 * Return whether a universal tag uses CER's long-string fragmentation form.
 * Original source: New asn1c CER helper, following X.690 9.2.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: number is the intrinsic universal tag number.
 * Returns: Nonzero for BIT/OCTET and supported character string tags.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_is_fragmentable_tag(4) identifies OCTET STRING.
 */
static int
cer_is_fragmentable_tag(ber_tlv_tag_t number) {
    return number == 3 || number == 4 || number == 7 || number == 12 ||
           (number >= 18 && number <= 22) ||
           (number >= 25 && number <= 30);
}

/*
 * Replace the outermost tag while preserving its primitive/constructed form.
 * Original source: New asn1c CER helper for IMPLICIT tagging of CHOICE.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the encoding; source is one complete CER
 *   encoding; replacement is its implicit tag; result receives the new TLV.
 * Returns: 0 on success or -1 for malformed/oversized source.
 * Errors: EBADF/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used for an implicitly tagged untagged CHOICE value.
 */
static int
cer_replace_outer_tag(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                      const void *value, const cer_buffer_t *source,
                      ber_tlv_tag_t replacement, cer_buffer_t *result) {
    uint8_t header[32];
    ssize_t old_size;
    size_t new_size;

    if(!source->data || source->length == 0) {
        return cer_fail(ctx, EBADF, td, value);
    }
    old_size = ber_fetch_tag(source->data, source->length, NULL);
    if(old_size <= 0 || (size_t)old_size >= source->length) {
        return cer_fail(ctx, EBADF, td, value);
    }
    new_size = ber_tlv_tag_serialize(replacement, header, sizeof(header));
    if(new_size == 0 || new_size >= sizeof(header)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    header[0] = (header[0] & (uint8_t)~0x20) |
                (source->data[0] & 0x20);
    if(cer_buffer_append(ctx, result, header, new_size, td, value) ||
       cer_buffer_append(ctx, result, source->data + old_size,
                         source->length - (size_t)old_size, td, value)) {
        cer_buffer_release(ctx, result);
        return -1;
    }
    return 0;
}

/*
 * Validate the primitive descriptor and collect its encoding metadata.
 * Original source: New asn1c CER encoder helper, following X.690 sections 9-11.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the primitive; number receives its
 *   universal tag number; fragmentable/bit_string/named_bits receive flags.
 * Returns: 0 for supported descriptor metadata or -1 for invalid/unsupported.
 * Errors: EBADF/ENOENT/EOVERFLOW through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before capturing the primitive DER adapter output.
 */
static int
cer_primitive_metadata(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                       const void *value, ber_tlv_tag_t *number,
                       int *fragmentable, int *bit_string, int *named_bits) {
    if(!value || !td->op || !td->op->der_encoder || !td->tags_count ||
       !td->tags) return cer_fail(ctx, ENOENT, td, value);
    if(cer_universal_tag(ctx, td, value, number)) return -1;
    if(*number == 4 && td->name && strcmp(td->name, "ANY") == 0) {
        return cer_fail(ctx, ENOENT, td, value);
    }
    if(cer_validate_primitive_input(ctx, td, value, *number) ||
       cer_check_primitive_constraints(ctx, td, value)) return -1;
    *bit_string = *number == 3;
    *fragmentable = cer_is_fragmentable_tag(*number);
    *named_bits = 0;
    if(*bit_string && td->specifics) {
        const asn_OCTET_STRING_specifics_t *specs =
            (const asn_OCTET_STRING_specifics_t *)td->specifics;
        if(specs->subvariant != ASN_OSUBV_BIT) {
            return cer_fail(ctx, EBADF, td, value);
        }
        *named_bits = specs->has_named_bits != 0;
    }
    return 0;
}

/*
 * Apply a primitive descriptor's character and subtype constraints.
 * Original source: New asn1c CER pre-encoder validation helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify an already storage-validated primitive.
 * Returns: 0 when no constraint fails, otherwise -1.
 * Errors: EBADF for a rejected primitive; callback diagnostics are suppressed.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: validates character alphabets before DER adapters capture bytes.
 */
static int
cer_check_primitive_constraints(cer_context_t *ctx,
                               const asn_TYPE_descriptor_t *td,
                               const void *value) {
    asn_constr_check_f *check = td->encoding_constraints.general_constraints;

    if(check && check(td, value, NULL, NULL)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Bound temporary memory used internally by the selected DER adapter.
 * Original source: New asn1c CER resource accounting helper.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td identifies the adapter selected by the descriptor.
 * Returns: Conservative byte charge, or zero for adapters without heap scratch.
 * Errors: None; allocation failure is reported by cer_alloc().
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: reserve this charge for the duration of cer_capture_der().
 */
static size_t
cer_adapter_scratch_size(const asn_TYPE_descriptor_t *td) {
    der_type_encoder_f *encoder = td->op->der_encoder;

    if(encoder == NativeInteger_encode_der ||
       encoder == NativeEnumerated_encode_der) return 16;
    if(encoder == NativeReal_encode_der) return 64;
    if(encoder == GeneralizedTime_encode_der) return 128;
    return 0;
}

/*
 * Validate or normalize canonical-only primitive contents after DER capture.
 * Original source: New asn1c CER validator/normalizer, following X.690 11.3/11.8.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the source; number selects OID, REAL, or
 *   UTCTime handling; content is replaced when UTC normalization is required.
 * Returns: 0 for supported canonical content or -1 for invalid/unsupported.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called between extracting DER content and building CER fragments.
 */
static int
cer_canonicalize_content(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                         const void *value, ber_tlv_tag_t number,
                         cer_buffer_t *content) {
    cer_buffer_t normalized = {0};

    if(number == 6 || number == 13) {
        return cer_validate_oid(ctx, td, value, content->data, content->length);
    }
    if(number == 9) {
        return cer_validate_real(ctx, td, value, content->data, content->length);
    }
    if(number == 23) {
        if(cer_normalize_utc_time(ctx, td, value,
                                  (const OCTET_STRING_t *)value, &normalized)) {
            return -1;
        }
        cer_buffer_release(ctx, content);
        *content = normalized;
    }
    if(number == 24) {
        return cer_validate_canonical_generalized_time(ctx, td, value, content);
    }
    return 0;
}

/*
 * Capture DER content and assemble a canonical primitive CER encoding.
 * Original source: New asn1c CER encoder helper, using canonical DER adapters.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the value; tag mode/tag apply member
 *   tagging; number and flags describe the intrinsic value; result receives TLV.
 * Returns: 0 on success or -1 after recording malformed/unsupported input.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM as described by the public API.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_encode_primitive() for validated descriptor metadata.
 */
static int
cer_encode_primitive_content(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                             const void *value, int tag_mode,
                             ber_tlv_tag_t tag, ber_tlv_tag_t number,
                             int fragmentable, int bit_string, int named_bits,
                             cer_buffer_t *result) {
    cer_buffer_t der = {0};
    cer_buffer_t content = {0};
    ber_tlv_tag_t universal_tag = ASN_TAG_CLASS_UNIVERSAL | (number << 2);
    int status = -1;

    if(cer_capture_der(ctx, td, value, universal_tag, &der) ||
       cer_extract_der_content(ctx, td, value, &der, universal_tag, &content)) {
        goto done;
    }
    if(cer_canonicalize_content(ctx, td, value, number, &content)) goto done;
    status = cer_build_primitive_tlv(ctx, td, value, tag_mode, tag,
                                     universal_tag, fragmentable, bit_string,
                                     named_bits, &content, result);
done:
    cer_buffer_release(ctx, &content);
    cer_buffer_release(ctx, &der);
    return status;
}

/*
 * Encode one validated primitive value, normalizing canonical-only content.
 * Original source: New asn1c CER encoder helper, using canonical DER adapters.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the primitive; tag mode/tag apply member
 *   tagging; result receives the complete CER TLV.
 * Returns: 0 on success or -1 after recording malformed/unsupported input.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM as described by the public API.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_encode_value() for primitive descriptors.
 */
static int
cer_encode_primitive(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                     const void *value, int tag_mode, ber_tlv_tag_t tag,
                     cer_buffer_t *result) {
    void *adapter_charge = NULL;
    size_t adapter_charge_size;
    ber_tlv_tag_t number;
    int bit_string;
    int named_bits = 0;
    int fragmentable;
    int status;

    if(cer_primitive_metadata(ctx, td, value, &number, &fragmentable,
                              &bit_string, &named_bits)) return -1;
    adapter_charge_size = cer_adapter_scratch_size(td);
    if(adapter_charge_size) {
        adapter_charge = cer_alloc(ctx, adapter_charge_size, td, value);
        if(!adapter_charge) return -1;
    }
    status = cer_encode_primitive_content(ctx, td, value, tag_mode, tag, number,
                                          fragmentable, bit_string, named_bits,
                                          result);
    if(adapter_charge) cer_free(ctx, adapter_charge, adapter_charge_size);
    return status;
}

/*
 * Encode one member in a SET and retain its CER bytes for canonical ordering.
 * Original source: New asn1c CER encoder helper, following X.690 9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the parent; member_index selects a field;
 *   item receives complete bytes and the member's static minimum tag.
 * Returns: 0 for present or omitted member; -1 for invalid value/metadata.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called while collecting SET fields before qsort().
 */
static int
cer_collect_set_member(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                       const void *value, const asn_TYPE_member_t *member,
                       cer_item_t *item) {
    cer_member_view_t view;

    memset(item, 0, sizeof(*item));
    if(cer_encode_member(ctx, td, value, member, NULL, &view)) return -1;
    if(!view.present) return 0;
    if(view.tag_mode) {
        item->sort_tag = view.tag;
    } else if(cer_minimum_tag(ctx, view.type, 0, &item->sort_tag)) {
        return -1;
    }
    if(cer_encode_value(ctx, view.type, view.value, view.tag_mode, view.tag,
                        &item->bytes)) {
        cer_buffer_release(ctx, &item->bytes);
        return -1;
    }
    item->declaration_index = 0;
    return 1;
}

/*
 * Validate one synthetic SET group's descriptor and storage bounds.
 * Original source: New asn1c CER SET extension-group encoder.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: ctx records errors; td/value identify the group descriptor/value.
 * Returns: 0 for valid SET metadata, or -1 for malformed bounds.
 * Errors: EBADF for invalid fields; EOVERFLOW for element or size limits.
 * Responsible party: asn1c maintainers. History: Added for SET group support.
 * Example: called before checking mandatory values or reading group leaves.
 */
static int
cer_validate_set_group(cer_context_t *ctx,
                       const asn_TYPE_descriptor_t *td, const void *value) {
    const asn_SET_specifics_t *specs;
    size_t structure_size;
    size_t words;
    size_t presence_size;
    size_t bits = 8 * sizeof(unsigned int);

    if(!td || !td->op || td->op->kind != ASN_KIND_SET || !td->specifics ||
       !td->elements || td->elements_count == 0) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(td->elements_count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(cer_descriptor_size(td, &structure_size)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    specs = (const asn_SET_specifics_t *)td->specifics;
    if(!specs->_mandatory_elements || specs->struct_size != structure_size ||
       specs->ctx_offset > structure_size ||
       sizeof(asn_struct_ctx_t) > structure_size - specs->ctx_offset) {
        return cer_fail(ctx, EBADF, td, value);
    }
    words = ((size_t)td->elements_count + bits - 1) / bits;
    if(words > ((size_t)-1) / sizeof(unsigned int)) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    presence_size = words * sizeof(unsigned int);
    if(specs->pres_offset > structure_size ||
       presence_size > structure_size - specs->pres_offset) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return 0;
}

/*
 * Count the bounded item workspace needed to flatten SET extension groups.
 * Original source: New asn1c CER SET extension-group encoder.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: ctx/td/value identify the SET; count bounds parent members;
 *   capacity receives an upper bound on the flattened item count.
 * Returns: 0 on success or -1 for malformed metadata or configured limits.
 * Errors: EBADF for invalid descriptors; EOVERFLOW for the element ceiling.
 * Responsible party: asn1c maintainers. History: Added for SET group support.
 * Example: called before allocating the canonical SET item array.
 */
static int
cer_set_item_capacity(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                      const void *value, unsigned count, size_t *capacity) {
    size_t total = count;
    unsigned i;

    if(!capacity || count > ASN_CER_MAX_ELEMENTS ||
       (count && !td->elements)) {
        return cer_fail(ctx, count > ASN_CER_MAX_ELEMENTS ? EOVERFLOW : EBADF,
                        td, value);
    }
    for(i = 0; i < count; i++) {
        const asn_TYPE_member_t *member = &td->elements[i];

        if(!(member->flags & ATF_EXTENSION_GROUP)) continue;
        if(!member->type || !member->type->op ||
           member->type->op->kind != ASN_KIND_SET) {
            return cer_fail(ctx, EBADF, td, value);
        }
        if(cer_validate_set_group(ctx, member->type, value)) return -1;
        if(member->type->elements_count > ASN_CER_MAX_ELEMENTS ||
           (member->type->elements_count && !member->type->elements)) {
            return cer_fail(ctx, member->type->elements_count >
                            ASN_CER_MAX_ELEMENTS ? EOVERFLOW : EBADF,
                            member->type, value);
        }
        if((size_t)member->type->elements_count >
           ASN_CER_MAX_ELEMENTS - total) {
            return cer_fail(ctx, EOVERFLOW, td, value);
        }
        total += member->type->elements_count;
    }
    *capacity = total;
    return 0;
}

/*
 * Collect each present child of one SET extension group as a SET item.
 * Original source: New asn1c CER SET extension-group encoder.
 * Version/date: 1.0, 2026-10-22.
 * Parameters: ctx/td/value identify the parent; member selects the group;
 *   items/capacity/used manage the bounded flat item array.
 * Returns: 0 on success or -1 for invalid values, metadata, or limits.
 * Errors: EBADF for an incomplete group; EOVERFLOW for depth/work bounds.
 * Responsible party: asn1c maintainers. History: Added for SET group support.
 * Example: called by cer_encode_set_members() for flagged SET members.
 */
static int
cer_collect_set_group(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                      const void *value, const asn_TYPE_member_t *member,
                      cer_item_t *items, size_t capacity, size_t *used) {
    cer_member_view_t group;
    unsigned i;
    int populated;
    int status = -1;

    if(cer_encode_member(ctx, td, value, member, NULL, &group)) return -1;
    if(!group.present) return 0;
    if(!group.type->op || group.type->op->kind != ASN_KIND_SET ||
       !items || !used) return cer_fail(ctx, EBADF, group.type, group.value);
    populated = SET_group_is_populated(group.type, group.value);
    if(populated != 1) return cer_fail(ctx, EBADF, group.type, group.value);
    if(ctx->depth >= ASN_STACK_OVERFLOW_LIMIT ||
       ASN__STACK_OVERFLOW_CHECK(ctx->codec_ctx) != 0) {
        return cer_fail(ctx, EOVERFLOW, group.type, group.value);
    }
    if(cer_charge_work(ctx, group.type, group.value)) return -1;
    ctx->depth++;
    status = 0;
    for(i = 0; i < group.type->elements_count; i++) {
        const asn_TYPE_member_t *child = &group.type->elements[i];
        cer_member_view_t view;
        cer_item_t *item;

        if(child->flags & ATF_EXTENSION_GROUP) {
            status = cer_fail(ctx, EBADF, group.type, group.value);
            break;
        }
        if(cer_charge_work(ctx, group.type, group.value) ||
           cer_encode_member(ctx, group.type, group.value, child, NULL,
                             &view)) {
            status = -1;
            break;
        }
        if(!view.present) continue;
        if(*used >= capacity) {
            status = cer_fail(ctx, EOVERFLOW, group.type, group.value);
            break;
        }
        item = &items[*used];
        memset(item, 0, sizeof(*item));
        if(view.tag_mode) {
            item->sort_tag = view.tag;
        } else if(cer_minimum_tag(ctx, view.type, 0, &item->sort_tag)) {
            status = -1;
            break;
        }
        if(cer_encode_value(ctx, view.type, view.value, view.tag_mode,
                            view.tag, &item->bytes)) {
            cer_buffer_release(ctx, &item->bytes);
            status = -1;
            break;
        }
        item->declaration_index = *used;
        (*used)++;
    }
    ctx->depth--;
    return status;
}

/*
 * Encode fields in declaration order, omitting absent optional values.
 * Original source: New asn1c CER encoder helper, following X.690 9.1.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the record; count bounds descriptor fields;
 *   body receives concatenated child encodings.
 * Returns: 0 on success or -1 for invalid members/resource failures.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called for SEQUENCE values by cer_encode_struct_members().
 */
static int
cer_encode_sequence_members(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                            const void *value, unsigned count,
                            cer_buffer_t *body) {
    unsigned i;

    for(i = 0; i < count; i++) {
        cer_member_view_t view;
        cer_buffer_t child = {0};
        const asn_TYPE_member_t *member = &td->elements[i];
        if(cer_charge_work(ctx, td, value) ||
           cer_encode_member(ctx, td, value, member, NULL, &view)) {
            return -1;
        }
        if(view.present) {
            int encode_status;

            /* X.690 SEQUENCE extension groups contribute only their children. */
            if(member->flags & ATF_EXTENSION_GROUP) {
                encode_status = cer_encode_extension_group_body(
                    ctx, view.type, view.value, &child);
            } else {
                encode_status = cer_encode_value(ctx, view.type, view.value,
                                                 view.tag_mode, view.tag, &child);
            }
            if(encode_status ||
               cer_buffer_append(ctx, body, child.data, child.length, td,
                                 value)) {
                cer_buffer_release(ctx, &child);
                return -1;
            }
        }
        cer_buffer_release(ctx, &child);
    }
    return 0;
}

/*
 * Encode a synthetic extension group's members without its SEQUENCE TLV.
 * Original source: New asn1c CER extension-group encoder, following X.690 8.9.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: ctx tracks depth/work/scratch; td/value identify the synthetic
 *   group; body receives the concatenated CER encodings of its components.
 * Returns: 0 on success, or -1 after recording malformed data/resource errors.
 * Errors: EBADF for a non-group descriptor; EOVERFLOW/ENOMEM for bounded work.
 * Responsible party: asn1c maintainers. History: Added for issue #583 CER.
 * Example: append the group body directly within its containing SEQUENCE TLV.
 */
static int
cer_encode_extension_group_body(cer_context_t *ctx,
                                const asn_TYPE_descriptor_t *td,
                                const void *value, cer_buffer_t *body) {
    const asn_SEQUENCE_specifics_t *specs;
    size_t structure_size;
    int status;

    if(!ctx) return -1;
    if(!td || !td->op || td->op->kind != ASN_KIND_SEQUENCE || !value ||
       !body || cer_descriptor_size(td, &structure_size)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    specs = (const asn_SEQUENCE_specifics_t *)td->specifics;
    if(!specs->extension_group) return cer_fail(ctx, EBADF, td, value);
    if(ctx->depth >= ASN_STACK_OVERFLOW_LIMIT ||
       ASN__STACK_OVERFLOW_CHECK(ctx->codec_ctx) != 0) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(cer_charge_work(ctx, td, value)) return -1;
    ctx->depth++;
    if(td->elements_count > ASN_CER_MAX_ELEMENTS ||
       (td->elements_count && !td->elements)) {
        status = cer_fail(ctx, td->elements_count > ASN_CER_MAX_ELEMENTS
                          ? EOVERFLOW : EBADF, td, value);
    } else {
        status = cer_encode_sequence_members(ctx, td, value,
                                              td->elements_count, body);
    }
    ctx->depth--;
    return status;
}

/*
 * Encode and canonical-order SET members by their static minimum tags.
 * Original source: New asn1c CER encoder helper, following X.690 9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the record; count bounds members; body
 *   receives the sorted child encodings.
 * Returns: 0 on success or -1 for invalid members or bounded allocation failure.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called for SET values by cer_encode_struct_members().
 */
static int
cer_encode_set_members(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                       const void *value, unsigned count, cer_buffer_t *body) {
    cer_item_t *items;
    size_t capacity;
    size_t item_bytes;
    size_t used = 0;
    unsigned i;
    int status = -1;

    if(cer_set_item_capacity(ctx, td, value, count, &capacity)) return -1;
    if(capacity == 0) return 0;
    if(capacity > ((size_t)-1) / sizeof(*items)) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    item_bytes = capacity * sizeof(*items);
    items = cer_alloc(ctx, item_bytes, td, value);
    if(!items) return -1;
    memset(items, 0, item_bytes);
    for(i = 0; i < count; i++) {
        int present;
        const asn_TYPE_member_t *member = &td->elements[i];

        if(cer_charge_work(ctx, td, value)) goto done;
        if(member->flags & ATF_EXTENSION_GROUP) {
            if(cer_collect_set_group(ctx, td, value, member, items,
                                     capacity, &used)) goto done;
        } else {
            present = cer_collect_set_member(ctx, td, value, member,
                                            &items[used]);
            if(present < 0) goto done;
            if(present) {
                items[used].declaration_index = used;
                used++;
            }
        }
    }
    if(used > 1) qsort(items, used, sizeof(*items), cer_set_item_compare);
    for(i = 0; i < used; i++) {
        if(cer_buffer_append(ctx, body, items[i].bytes.data,
                             items[i].bytes.length, td, value)) goto done;
    }
    status = 0;
done:
    for(i = 0; i < capacity; i++) cer_buffer_release(ctx, &items[i].bytes);
    cer_free(ctx, items, item_bytes);
    return status;
}

/*
 * Dispatch bounded member encoding for a constructed SEQUENCE or SET.
 * Original source: New asn1c CER encoder helper, following X.690 9.1/9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the record; set_order selects tag sorting;
 *   body receives concatenated child encodings.
 * Returns: 0 on success or -1 for invalid metadata or resource failures.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_encode_constructed() for SEQUENCE and SET.
 */
static int
cer_encode_struct_members(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                          const void *value, int set_order,
                          cer_buffer_t *body) {
    unsigned count = td->elements_count;

    if(count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(count && !td->elements) {
        return cer_fail(ctx, EBADF, td, value);
    }
    return set_order ? cer_encode_set_members(ctx, td, value, count, body) :
           cer_encode_sequence_members(ctx, td, value, count, body);
}

/*
 * Validate list metadata before reading its element array.
 * Original source: New asn1c CER descriptor input validator.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the list; list/count receive checked data.
 * Returns: 0 for a bounded one-element-type list or -1 for malformed metadata.
 * Errors: EBADF for malformed fields; no allocation or exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called before the SEQUENCE OF and SET OF loops.
 */
static int
cer_validate_of_list(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                     const void *value, const asn_anonymous_set_ **list_out,
                     size_t *count_out) {
    const asn_anonymous_set_ *list = (const asn_anonymous_set_ *)value;

    if(!list || !list_out || !count_out || list->count < 0 || list->size < 0 ||
       list->count > list->size ||
       (list->count && !list->array) || !td->elements ||
       td->elements_count != 1 || !td->elements[0].type) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if((unsigned)list->count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    *list_out = list;
    *count_out = (size_t)list->count;
    return 0;
}

/*
 * Encode one SEQUENCE OF or SET OF element into its destination.
 * Original source: New asn1c CER encoder helper, following X.690 9.1/11.6.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/list identify the list; index selects the entry; set_order
 *   retains it in items, otherwise its bytes append directly to body.
 * Returns: 0 on success or -1 for a null entry, child failure, or append error.
 * Errors: EBADF/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called by cer_encode_of_members() for each checked list entry.
 */
static int
cer_encode_of_item(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                   const asn_anonymous_set_ *list, size_t index, int set_order,
                   cer_item_t *items, cer_buffer_t *body) {
    cer_buffer_t child = {0};
    const void *entry = list->array[index];

    if(!entry || cer_charge_work(ctx, td, entry) ||
       cer_encode_value(ctx, td->elements[0].type, entry, 0, 0, &child)) {
        cer_buffer_release(ctx, &child);
        return -1;
    }
    if(set_order) {
        items[index].bytes = child;
        items[index].declaration_index = index;
        return 0;
    }
    if(cer_buffer_append(ctx, body, child.data, child.length, td, entry)) {
        cer_buffer_release(ctx, &child);
        return -1;
    }
    cer_buffer_release(ctx, &child);
    return 0;
}

/*
 * Append SET OF encodings sorted using their final CER octets.
 * Original source: New asn1c CER encoder helper, following X.690 11.6.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the list; items/count are retained encodings;
 *   body receives their canonical concatenation.
 * Returns: 0 on success or -1 if a bounded append fails.
 * Errors: EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: called after collecting SET OF elements.
 */
static int
cer_append_sorted_of(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                     const void *value, cer_item_t *items, size_t count,
                     cer_buffer_t *body) {
    size_t i;

    if(count > 1) qsort(items, count, sizeof(*items), cer_item_compare);
    for(i = 0; i < count; i++) {
        if(cer_buffer_append(ctx, body, items[i].bytes.data,
                             items[i].bytes.length, td, value)) return -1;
    }
    return 0;
}

/*
 * Encode members of SEQUENCE OF or sort final CER encodings for SET OF.
 * Original source: New asn1c CER encoder helper, following X.690 9.1/11.6.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the list; set_order chooses SET OF sorting;
 *   body receives concatenated encoded elements.
 * Returns: 0 on success or -1 for malformed list state/resource failure.
 * Errors: EBADF/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_encode_constructed() for either OF kind.
 */
static int
cer_encode_of_members(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                      const void *value, int set_order, cer_buffer_t *body) {
    const asn_anonymous_set_ *list;
    cer_item_t *items = NULL;
    size_t count;
    size_t item_bytes = 0;
    size_t i;
    int result = -1;

    if(cer_validate_of_list(ctx, td, value, &list, &count)) return -1;
    if(set_order && count) {
        if(count > ((size_t)-1) / sizeof(*items)) {
            return cer_fail(ctx, EOVERFLOW, td, value);
        }
        item_bytes = count * sizeof(*items);
        items = cer_alloc(ctx, item_bytes, td, value);
        if(!items) return -1;
        memset(items, 0, item_bytes);
    }
    for(i = 0; i < count; i++) {
        if(cer_encode_of_item(ctx, td, list, i, set_order, items, body)) goto done;
    }
    if(set_order && cer_append_sorted_of(ctx, td, value, items, count, body)) {
        goto done;
    }
    result = 0;
done:
    if(items) {
        for(i = 0; i < count; i++) cer_buffer_release(ctx, &items[i].bytes);
        cer_free(ctx, items, item_bytes);
    }
    return result;
}

/*
 * Encode a constructed SEQUENCE, SET, or OF value with indefinite length.
 * Original source: New asn1c CER encoder helper, following X.690 9.1/9.3.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the structure; tag_mode/tag apply member
 *   tagging; result receives its complete CER encoding.
 * Returns: 0 on success or -1 for invalid metadata, values, or resource limits.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_encode_value() for constructed descriptor kinds.
 */
static int
cer_encode_constructed(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                       const void *value, int tag_mode, ber_tlv_tag_t tag,
                       cer_buffer_t *result) {
    cer_buffer_t body = {0};
    cer_buffer_t inner = {0};
    ber_tlv_tag_t base_tag;
    int status;

    if(!td->tags || td->tags_count == 0 || !td->op || !value) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(td->op->kind == ASN_KIND_SEQUENCE || td->op->kind == ASN_KIND_SET) {
        status = cer_encode_struct_members(ctx, td, value,
                   td->op->kind == ASN_KIND_SET, &body);
    } else if(td->op->kind == ASN_KIND_SEQUENCE_OF ||
              td->op->kind == ASN_KIND_SET_OF) {
        if(!td->elements || td->elements_count != 1 || !td->elements[0].type) {
            return cer_fail(ctx, EBADF, td, value);
        }
        status = cer_encode_of_members(ctx, td, value,
                       td->op->kind == ASN_KIND_SET_OF, &body);
    } else {
        return cer_fail(ctx, ENOENT, td, value);
    }
    if(status) goto done;
    base_tag = (tag_mode == -1 && td->tags_count == 1) ? tag :
               td->tags[td->tags_count - 1];
    if(cer_make_tlv(ctx, td, value, base_tag, 1, 1, &body, &inner) ||
       cer_wrap_descriptor_tags(ctx, td, value, tag_mode, tag, &inner, result)) {
        status = -1;
        goto done;
    }
    status = 0;
done:
    cer_buffer_release(ctx, &body);
    cer_buffer_release(ctx, &inner);
    return status;
}

/*
 * Encode the selected CHOICE value and apply its enclosing CER tags.
 * Original source: New asn1c CER encoder helper, following X.690 8.13/9.1.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the choice; tag_mode/tag apply parent
 *   tagging; result receives the selected alternative encoding.
 * Returns: 0 on success or -1 for absent/invalid alternatives or resource caps.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM through ctx->error.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used by cer_encode_value() for ASN_KIND_CHOICE.
 */
static int
cer_encode_choice(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                  const void *value, int tag_mode, ber_tlv_tag_t tag,
                  cer_buffer_t *result) {
    const asn_CHOICE_specifics_t *specs;
    unsigned present;
    size_t structure_size;
    cer_member_view_t view;
    cer_buffer_t child = {0};
    int status = -1;

    if(td->elements_count > ASN_CER_MAX_ELEMENTS) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(!td->specifics || !td->elements || !td->elements_count) {
        return cer_fail(ctx, EBADF, td, value);
    }
    specs = (const asn_CHOICE_specifics_t *)td->specifics;
    structure_size = specs->struct_size;
    if(specs->pres_size != sizeof(char) &&
       specs->pres_size != sizeof(short) &&
       specs->pres_size != sizeof(int)) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(cer_check_member_offset(ctx, td, value, structure_size,
                               specs->pres_offset, specs->pres_size)) return -1;
    present = CHOICE_variant_get_presence(td, value);
    if(present == 0 || present > td->elements_count) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(cer_charge_work(ctx, td, value) ||
       cer_encode_member(ctx, td, value, &td->elements[present - 1], NULL,
                         &view)) goto done;
    if(!view.present) {
        cer_fail(ctx, EBADF, td, value);
        goto done;
    }
    if(cer_encode_value(ctx, view.type, view.value, view.tag_mode, view.tag,
                        &child)) goto done;
    status = cer_wrap_choice_tags(ctx, td, value, tag_mode, tag, &child,
                                  result);
done:
    cer_buffer_release(ctx, &child);
    return status;
}

/*
 * Bound descriptor tag wrapping before tag metadata is traversed or copied.
 * Original source: New asn1c CER resource guard, following the stack limit.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx/td/value identify the descriptor; tag_mode selects member
 *   tagging, with mode 1 adding a wrapper and mode -1 replacing the outer tag.
 * Returns: 0 when the effective wrapper chain fits; otherwise -1.
 * Errors: EBADF for unsupported tag mode and EOVERFLOW above the depth limit.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: rejects 30 descriptor tags plus one explicit member wrapper.
 */
static int
cer_check_tag_depth(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                    const void *value, int tag_mode) {
    if(tag_mode != 0 && tag_mode != -1 && tag_mode != 1) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(td->tags_count > ASN_STACK_OVERFLOW_LIMIT ||
       (tag_mode == 1 && td->tags_count >= ASN_STACK_OVERFLOW_LIMIT)) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    return 0;
}

/*
 * Walk one value descriptor and emit its complete CER representation.
 * Original source: New asn1c descriptor-driven CER encoder, X.690 (2015).
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx tracks budgets/depth; td/value are the node; tag_mode/tag
 *   carry parent member tagging; result receives the complete encoding.
 * Returns: 0 on success or -1 with the first failure recorded in ctx.
 * Errors: EBADF/ENOENT/EOVERFLOW/ENOMEM for invalid, unsupported, or bounded
 *   resource failures. Callback errors are handled by the public entry points.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_encode_value(ctx, td, value, 0, 0, &encoded).
 */
static int
cer_encode_value(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                 const void *value, int tag_mode, ber_tlv_tag_t tag,
                 cer_buffer_t *result) {
    int status;

    memset(result, 0, sizeof(*result));
    if(!ctx) return -1;
    if(!td || !td->op || !value) {
        return cer_fail(ctx, EBADF, td, value);
    }
    if(ctx->depth >= ASN_STACK_OVERFLOW_LIMIT ||
       ASN__STACK_OVERFLOW_CHECK(ctx->codec_ctx) != 0) {
        return cer_fail(ctx, EOVERFLOW, td, value);
    }
    if(cer_check_tag_depth(ctx, td, value, tag_mode)) return -1;
    if(cer_charge_work(ctx, td, value)) return -1;
    ctx->depth++;
    if(td->elements_count > ASN_CER_MAX_ELEMENTS) {
        status = cer_fail(ctx, EOVERFLOW, td, value);
    } else if(td->elements_count && !td->elements) {
        status = cer_fail(ctx, EBADF, td, value);
    } else if(td->op->kind == ASN_KIND_CHOICE) {
        status = cer_encode_choice(ctx, td, value, tag_mode, tag, result);
    } else if(td->op->kind == ASN_KIND_PRIMITIVE) {
        status = cer_encode_primitive(ctx, td, value, tag_mode, tag, result);
    } else {
        status = cer_encode_constructed(ctx, td, value, tag_mode, tag, result);
    }
    ctx->depth--;
    return status;
}

/*
 * Finish a CER call and report its first precise failure to the application.
 * Original source: New asn1c CER public API implementation.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx contains the first error and failed node; td/value are root.
 * Returns: A failed asn_enc_rval_t with encoded=-1.
 * Errors: Sets errno to ctx->error or EBADF if no cause was recorded.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: return cer_error_result(&ctx, td, value).
 */
static asn_enc_rval_t
cer_error_result(cer_context_t *ctx, const asn_TYPE_descriptor_t *td,
                 const void *value) {
    asn_enc_rval_t result;
    errno = ctx->error ? ctx->error : EBADF;
    result.encoded = -1;
    result.failed_type = ctx->failed_type ? ctx->failed_type : td;
    result.structure_ptr = ctx->failed_ptr ? ctx->failed_ptr : value;
    return result;
}

/*
 * Initialize bounded CER state with a stack-local copy of the caller context.
 * Original source: New asn1c CER public API initialization.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: ctx receives CER budgets; local_stack owns the codec context;
 *   opt_codec_ctx is copied when supplied, otherwise defaults are installed.
 * Returns: No value.
 * Errors: None; C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_initialize_context(&ctx, &local_stack, opt_codec_ctx).
 */
static void
cer_initialize_context(cer_context_t *ctx, asn_codec_ctx_t *local_stack,
                       const asn_codec_ctx_t *opt_codec_ctx) {
    memset(ctx, 0, sizeof(*ctx));
    if(opt_codec_ctx) {
        *local_stack = *opt_codec_ctx;
    } else {
        memset(local_stack, 0, sizeof(*local_stack));
        local_stack->max_stack_size = ASN__DEFAULT_STACK_MAX;
    }
    ctx->codec_ctx = local_stack;
}

/*
 * Encode a descriptor value to a callback after complete bounded validation.
 * Original source: New asn1c CER public API implementation.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: opt_codec_ctx applies inherited stack bounds; td/value select
 *   the root; cb/key receive the complete CER byte sequence.
 * Returns: Encoded byte count on success, otherwise encoded=-1.
 * Errors: EINVAL for invalid arguments; value/resource/callback errors are
 *   EBADF/ENOENT/EOVERFLOW/ENOMEM/EIO. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_encode(NULL, &asn_DEF_BOOLEAN, &truth, consume, key).
 */
asn_enc_rval_t
cer_encode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *td, const void *value,
           asn_app_consume_bytes_f *cb, void *key) {
    cer_context_t ctx;
    asn_codec_ctx_t local_stack;
    cer_buffer_t encoded = {0};
    asn_enc_rval_t result;

    cer_initialize_context(&ctx, &local_stack, opt_codec_ctx);
    if(!td || !value || !cb) {
        errno = EINVAL;
        result.encoded = -1;
        result.failed_type = td;
        result.structure_ptr = value;
        return result;
    }
    if(cer_encode_value(&ctx, td, value, 0, 0, &encoded)) {
        cer_buffer_release(&ctx, &encoded);
        return cer_error_result(&ctx, td, value);
    }
    if(cb(encoded.data, encoded.length, key) < 0) {
        ctx.error = EIO;
        ctx.failed_type = td;
        ctx.failed_ptr = value;
        cer_buffer_release(&ctx, &encoded);
        return cer_error_result(&ctx, td, value);
    }
    result.encoded = (ssize_t)encoded.length;
    result.failed_type = NULL;
    result.structure_ptr = NULL;
    cer_buffer_release(&ctx, &encoded);
    return result;
}

/*
 * Encode completely before copying to a fixed buffer, failing on short space.
 * Original source: New asn1c CER public API implementation.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: opt_codec_ctx applies inherited stack bounds; td/value select
 *   the root; buffer/size describe caller-owned complete-output space.
 * Returns: Encoded byte count, or encoded=-1 without modifying a short buffer.
 * Errors: EINVAL for bad pointers, ENOSPC for insufficient space, and all
 *   encoding/resource errors documented by cer_encode().
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: cer_encode_to_buffer(NULL, &asn_DEF_NULL, &nullv, out, sizeof(out)).
 */
asn_enc_rval_t
cer_encode_to_buffer(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, const void *value,
                     void *buffer, size_t buffer_size) {
    cer_context_t ctx;
    asn_codec_ctx_t local_stack;
    cer_buffer_t encoded = {0};
    asn_enc_rval_t result;

    cer_initialize_context(&ctx, &local_stack, opt_codec_ctx);
    if(!td || !value || (!buffer && buffer_size)) {
        errno = EINVAL;
        result.encoded = -1;
        result.failed_type = td;
        result.structure_ptr = value;
        return result;
    }
    if(cer_encode_value(&ctx, td, value, 0, 0, &encoded)) {
        cer_buffer_release(&ctx, &encoded);
        return cer_error_result(&ctx, td, value);
    }
    if(encoded.length > buffer_size) {
        cer_buffer_release(&ctx, &encoded);
        errno = ENOSPC;
        result.encoded = -1;
        result.failed_type = td;
        result.structure_ptr = value;
        return result;
    }
    if(encoded.length) memcpy(buffer, encoded.data, encoded.length);
    result.encoded = (ssize_t)encoded.length;
    result.failed_type = NULL;
    result.structure_ptr = NULL;
    cer_buffer_release(&ctx, &encoded);
    return result;
}

#else /* CER encoding requires the BER/DER primitive adapter substrate. */

/*
 * Report that CER encoding was disabled by the generated skeleton config.
 * Original source: New asn1c CER disabled-support stub.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/value describe the attempted root; callback/key are ignored.
 * Returns: A failed result with encoded=-1.
 * Errors: Sets errno to ENOENT. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used when ASN_DISABLE_CER_SUPPORT or ASN_DISABLE_BER_SUPPORT is set.
 */
asn_enc_rval_t
cer_encode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *td, const void *value,
           asn_app_consume_bytes_f *cb, void *key) {
    asn_enc_rval_t result;
    (void)opt_codec_ctx;
    (void)cb;
    (void)key;
    errno = ENOENT;
    result.encoded = -1;
    result.failed_type = td;
    result.structure_ptr = value;
    return result;
}

/*
 * Report disabled CER support from the fixed-buffer convenience API.
 * Original source: New asn1c CER disabled-support stub.
 * Version/date: 1.0, 2026-10-11.
 * Parameters: td/value identify the attempted root; buffer/size are ignored.
 * Returns: A failed result with encoded=-1.
 * Errors: Sets errno to ENOENT. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added 2026-10-11.
 * Example: used when ASN_DISABLE_CER_SUPPORT or ASN_DISABLE_BER_SUPPORT is set.
 */
asn_enc_rval_t
cer_encode_to_buffer(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, const void *value,
                     void *buffer, size_t buffer_size) {
    asn_enc_rval_t result;
    (void)opt_codec_ctx;
    (void)buffer;
    (void)buffer_size;
    errno = ENOENT;
    result.encoded = -1;
    result.failed_type = td;
    result.structure_ptr = value;
    return result;
}

#endif /* CER encoding support enabled. */
