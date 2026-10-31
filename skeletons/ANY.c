/*
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <ANY.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
#include <cbor_support.h>
#endif

asn_OCTET_STRING_specifics_t asn_SPC_ANY_specs = {
    sizeof(ANY_t),
    offsetof(ANY_t, _asn_ctx),
    ASN_OSUBV_ANY
};
asn_TYPE_operation_t asn_OP_ANY = {
    .kind = ASN_KIND_PRIMITIVE,
    OCTET_STRING_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    ANY_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    ANY_compare,
    ANY_copy,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    ANY_decode_ber,
    ANY_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    ANY_decode_xer,
    ANY_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    ANY_decode_jer,
    ANY_encode_jer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    ANY_decode_oer,
    ANY_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    ANY_decode_uper,
    ANY_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    ANY_decode_aper,
    ANY_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
    0,  /* Random fill is not defined for ANY type */
    0,  /* Use generic outmost tag fetcher */
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    ANY_decode_cbor,
    ANY_encode_cbor,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};

#if !defined(ASN_DISABLE_PRINT_SUPPORT)
/*
 * Purpose: Print ANY octets without interpreting its int size as a size_t.
 * Original source: Adapter to the asn1c OCTET STRING hexadecimal printer.
 * Version: 2026-10-22.
 * Parameters: td identifies ANY; sptr is the nullable value; ilevel controls
 *             indentation; cb consumes printed bytes using app_key as context.
 * Returns: 0 on success or -1 for invalid values, missing callbacks, or I/O errors.
 * Errors: Negative sizes and missing nonempty storage are rejected before access.
 * Responsible party: asn1c maintainers.
 * History: Issue #586 uses ANY for opaque values; normalize its layout for printing.
 * Example: A one-octet value 0x80 prints as "80", independent of structure padding.
 */
int
ANY_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
           asn_app_consume_bytes_f *cb, void *app_key) {
    const ANY_t *value = (const ANY_t *)sptr;
    OCTET_STRING_t view;

    if(!td || !cb) return -1;
    if(!value) return OCTET_STRING_print(td, NULL, ilevel, cb, app_key);
    if(value->size < 0 || (value->size > 0 && !value->buf)) return -1;
    if(value->size == 0) return 0;

    /* Only the temporary view uses the OCTET STRING layout; payload stays borrowed. */
    memset(&view, 0, sizeof(view));
    view.buf = value->buf;
    view.size = (size_t)value->size;
    return OCTET_STRING_print(&asn_DEF_OCTET_STRING, &view, ilevel, cb, app_key);
}
#endif /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
asn_TYPE_descriptor_t asn_DEF_ANY = {
    "ANY",
    "ANY",
    &asn_OP_ANY,
    0, 0, 0, 0,
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
        asn_generic_no_constraint
    },  /* No constraints */
    0, 0,  /* No members */
    &asn_SPC_ANY_specs,
};

/*
 * Purpose: Compare two ANY payloads without treating a negative int size as huge.
 * Original source: OCTET_STRING_compare adapted for the public ANY_t layout.
 * Version: 2026-10-22.
 * Parameters: td is the ANY descriptor; aptr and bptr are nullable ANY values.
 * Returns: Negative, zero, or positive according to payload ordering.
 * Errors: Malformed sizes or missing positive-size buffers sort after valid data.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for issue #586's ANY-backed opaque open-type choice arm.
 * Example: Equal opaque payloads compare as zero even when their buffers differ.
 */
int
ANY_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
            const void *bptr) {
    const ANY_t *a = (const ANY_t *)aptr;
    const ANY_t *b = (const ANY_t *)bptr;
    int a_invalid;
    int b_invalid;
    size_t common_size;
    int result;

    (void)td;
    if(!a) return b ? -1 : 0;
    if(!b) return 1;

    a_invalid = a->size < 0 || (a->size > 0 && !a->buf);
    b_invalid = b->size < 0 || (b->size > 0 && !b->buf);
    if(a_invalid || b_invalid) {
        if(a_invalid != b_invalid) return a_invalid ? 1 : -1;
        if(a->size < b->size) return -1;
        if(a->size > b->size) return 1;
        return 0;
    }

    common_size = (size_t)(a->size < b->size ? a->size : b->size);
    result = common_size ? memcmp(a->buf, b->buf, common_size) : 0;
    if(result) return result < 0 ? -1 : 1;
    if(a->size < b->size) return -1;
    if(a->size > b->size) return 1;
    return 0;
}

/*
 * Purpose: Deep-copy an ANY payload using ANY_t's signed-int size field.
 * Original source: OCTET_STRING_copy adapted for the public ANY_t layout.
 * Version: 2026-10-22.
 * Parameters: td describes ANY storage; aptr receives the copy; bptr is source.
 * Returns: 0 on success, -1 for malformed values or allocation failure.
 * Errors: Negative sizes, missing positive-size buffers, and invalid storage
 *         descriptors fail without replacing the destination contents.
 * Responsible party: asn1c runtime maintainers.
 * History: Added for opaque APER fallback lifecycle support in issue #586.
 * Example: Copying an empty ANY produces an independently owned empty buffer.
 */
int
ANY_copy(const asn_TYPE_descriptor_t *td, void **aptr, const void *bptr) {
    const asn_OCTET_STRING_specifics_t *specs;
    const ANY_t *source = (const ANY_t *)bptr;
    ANY_t *destination;
    uint8_t *new_buffer = NULL;
    size_t size;

    if(!td || !aptr) return -1;
    specs = td->specifics
                ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                : &asn_SPC_ANY_specs;
    if(specs->struct_size < sizeof(ANY_t)
       || specs->ctx_offset > specs->struct_size
       || sizeof(asn_struct_ctx_t) > specs->struct_size - specs->ctx_offset) {
        return -1;
    }
    destination = (ANY_t *)*aptr;

    if(!source) {
        if(destination) OCTET_STRING_free(td, destination, ASFM_FREE_EVERYTHING);
        *aptr = NULL;
        return 0;
    }
    if(source->size < 0 || (source->size > 0 && !source->buf)) return -1;
    if(destination == source) return 0;

    size = (size_t)source->size;
    if(size == SIZE_MAX) return -1;
    new_buffer = (uint8_t *)MALLOC(size + 1);
    if(!new_buffer) return -1;
    if(size) memcpy(new_buffer, source->buf, size);
    new_buffer[size] = 0;

    if(!destination) {
        destination = (ANY_t *)CALLOC(1, specs->struct_size);
        if(!destination) {
            FREEMEM(new_buffer);
            return -1;
        }
    }

    FREEMEM(destination->buf);
    destination->buf = new_buffer;
    destination->size = source->size;
    *aptr = destination;
    return 0;
}

/*
 * Purpose: Construct a borrowed OCTET STRING view without reading ANY padding.
 * Source: ANY and OCTET STRING public storage layouts. Version: 2026-10-30.
 * Inputs: value is an ANY payload; view receives its borrowed representation.
 * Returns: zero for valid payloads, -1 for invalid arguments or sizes.
 * Errors: Missing buffers and negative sizes are rejected. Author: maintainers.
 * History: Added to keep codec adapters compatible with ANY's signed int size.
 * Example: A zero-length ANY becomes an empty OCTET STRING view.
 */
int
ANY_to_octet_view(const ANY_t *value, OCTET_STRING_t *view) {
    if(!value || !view || value->size < 0 || (value->size && !value->buf))
        return -1;
    memset(view, 0, sizeof(*view));
    view->buf = value->buf;
    view->size = (size_t)value->size;
    return 0;
}

#if !defined(ASN_DISABLE_OER_SUPPORT) || !defined(ASN_DISABLE_CBOR_SUPPORT)
/*
 * Purpose: Replace an ANY value with a bounded copy of decoded payload bytes.
 * Source: ANY signed-size ABI. Version: 2026-10-30.
 * Inputs: td describes storage; target is its slot; bytes/size are payload.
 * Returns: zero on success, -1 for invalid metadata or allocation failure.
 * Errors: Oversized input fails before allocation. Author: asn1c maintainers.
 * History: Shared by stateless OER and CBOR decoders.
 * Example: A zero-length payload receives an owned terminating byte.
 */
static int
ANY_assign_decoded(const asn_TYPE_descriptor_t *td, void **target,
                   const uint8_t *bytes, size_t size) {
    const asn_OCTET_STRING_specifics_t *specs;
    ANY_t *value;
    uint8_t *buffer;
    if(!td || !target || size > INT_MAX || (size && !bytes)) return -1;
    specs = td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                          : &asn_SPC_ANY_specs;
    if(specs->struct_size < sizeof(ANY_t)
    || specs->ctx_offset != offsetof(ANY_t, _asn_ctx)) return -1;
    value = (ANY_t *)*target;
    if(value && (value->size < 0 || (value->size && !value->buf))) return -1;
    buffer = (uint8_t *)MALLOC(size + 1);
    if(!buffer) return -1;
    if(size) memcpy(buffer, bytes, size);
    buffer[size] = 0;
    if(!value) {
        value = (ANY_t *)CALLOC(1, specs->struct_size);
        if(!value) { FREEMEM(buffer); return -1; }
        *target = value;
    }
    FREEMEM(value->buf);
    value->buf = buffer;
    value->size = (int)size;
    return 0;
}
#endif

#if !defined(ASN_DISABLE_OER_SUPPORT)
/*
 * Purpose: Decode an OER ANY byte payload without casting ANY to OCTET STRING.
 * Source: OCTET STRING OER length framing. Version: 2026-10-30.
 * Inputs: codec/td/constraints describe decoding; target receives the value;
 *         input and size contain the available encoded bytes.
 * Returns: RC_OK, RC_WMORE or RC_FAIL with consumed bytes on success.
 * Errors: Invalid lengths, oversized payloads and allocation failures fail.
 * Author: asn1c maintainers. History: Preserves the public ANY_t ABI.
 * Example: A zero length determinant produces an empty value.
 */
asn_dec_rval_t
ANY_decode_oer(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
               const asn_oer_constraints_t *constraints, void **target,
               const void *input, size_t size) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    const asn_oer_constraints_t *cts;
    size_t length;
    ssize_t header = 0;
    (void)codec;
    if(!td || !target || (!input && size)) return result;
    cts = constraints ? constraints : td->encoding_constraints.oer_constraints;
    if(cts && cts->size >= 0) length = (size_t)cts->size;
    else {
        header = oer_fetch_length(input, size, &length);
        if(header == 0) { result.code = RC_WMORE; return result; }
        if(header < 0 || (size_t)header > size) return result;
    }
    if(length > INT_MAX) return result;
    if(length > size - (size_t)header) { result.code = RC_WMORE; return result; }
    if(ANY_assign_decoded(td, target,
           length ? (const uint8_t *)input + header : NULL, length)) return result;
    result.code = RC_OK;
    result.consumed = (size_t)header + length;
    return result;
}

/*
 * Purpose: Encode OER bytes using a checked borrowed view of ANY storage.
 * Source: OCTET STRING OER encoder. Version: 2026-10-30.
 * Inputs: td/constraints and value describe the payload; cb/key consume output.
 * Returns: encoder result. Errors: Invalid values or callbacks fail.
 * Author: asn1c maintainers. History: Avoids interpreting int as size_t.
 * Example: Encodes one byte with an OER length determinant of one.
 */
asn_enc_rval_t
ANY_encode_oer(const asn_TYPE_descriptor_t *td,
               const asn_oer_constraints_t *constraints, const void *sptr,
               asn_app_consume_bytes_f *cb, void *key) {
    OCTET_STRING_t view;
    if(!td || !cb || ANY_to_octet_view((const ANY_t *)sptr, &view))
        ASN__ENCODE_FAILED;
    return OCTET_STRING_encode_oer(td, constraints, &view, cb, key);
}
#endif

#if !defined(ASN_DISABLE_CBOR_SUPPORT)
/*
 * Purpose: Decode a CBOR byte string into ABI-compatible ANY storage.
 * Source: OCTET STRING CBOR mapping. Version: 2026-10-30.
 * Inputs: codec/td/target describe output; input/size provide encoded bytes.
 * Returns: RC_OK or RC_FAIL. Errors: Invalid, short or oversized data fail.
 * Author: asn1c maintainers. History: Enforces ANY's signed size bound.
 * Example: A 0x40 CBOR byte string decodes to an empty payload.
 */
asn_dec_rval_t
ANY_decode_cbor(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
                void **target, const void *input, size_t size) {
    asn_dec_rval_t result = {RC_FAIL, 0};
    const uint8_t *bytes = (const uint8_t *)input;
    uint64_t length;
    uint8_t major;
    ssize_t tags, header;
    size_t offset;
    (void)codec;
    if(!td || !target || !bytes || !size) return result;
    tags = cbor_skip_tags(bytes, size);
    if(tags < 0 || (size_t)tags > size) return result;
    header = cbor_decode_head(bytes + tags, size - (size_t)tags, &major, &length);
    if(header < 0 || major != CBOR_MAJOR_BYTES || length > INT_MAX) return result;
    offset = (size_t)tags + (size_t)header;
    if(offset > size || length > size - offset) return result;
    if(ANY_assign_decoded(td, target, bytes + offset, (size_t)length)) return result;
    result.code = RC_OK;
    result.consumed = offset + (size_t)length;
    return result;
}

/*
 * Purpose: Encode an ANY payload as a CBOR byte string using a safe view.
 * Source: OCTET STRING CBOR mapping. Version: 2026-10-30.
 * Inputs: td/value describe the payload; cb/key receive bytes.
 * Returns: encoder result. Errors: invalid payload or callback fails.
 * Author: asn1c maintainers. History: Removes signed-size layout casts.
 * Example: An empty payload emits CBOR 0x40.
 */
asn_enc_rval_t
ANY_encode_cbor(const asn_TYPE_descriptor_t *td, const void *sptr,
                asn_app_consume_bytes_f *cb, void *key) {
    OCTET_STRING_t view;
    if(!td || !cb || ANY_to_octet_view((const ANY_t *)sptr, &view))
        ASN__ENCODE_FAILED;
    return OCTET_STRING_encode_cbor(td, &view, cb, key);
}
#endif

#if !defined(ASN_DISABLE_BER_SUPPORT) || !defined(ASN_DISABLE_XER_SUPPORT) \
    || !defined(ASN_DISABLE_JER_SUPPORT)
/*
 * Purpose: Prepare a full OCTET STRING temporary for incremental ANY decoding.
 * Source: OCTET STRING BER and hexadecimal text decoders. Version: 2026-10-30.
 * Inputs: td/target describe the ANY; input_size bounds possible output;
 *         descriptor/specs/view receive the temporary representation.
 * Returns: zero on success, -1 on invalid state or allocation failure.
 * Errors: Oversized chunks and malformed storage fail. Author: maintainers.
 * History: Avoids accessing OCTET STRING fields beyond ANY allocation.
 * Example: An existing ANY context is copied into the temporary view.
 */
static int
ANY_text_prepare(const asn_TYPE_descriptor_t *td, void **target,
                 size_t input_size, asn_TYPE_descriptor_t *descriptor,
                 asn_OCTET_STRING_specifics_t *specs, OCTET_STRING_t *view) {
    const asn_OCTET_STRING_specifics_t *original;
    ANY_t *value;
    if(!td || !target) return -1;
    original = td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                             : &asn_SPC_ANY_specs;
    if(original->struct_size < sizeof(ANY_t)
    || original->ctx_offset != offsetof(ANY_t, _asn_ctx)) return -1;
    value = (ANY_t *)*target;
    if(!value) {
        value = (ANY_t *)CALLOC(1, original->struct_size);
        if(!value) return -1;
        *target = value;
    }
    if(ANY_to_octet_view(value, view)
    || input_size > (size_t)INT_MAX - view->size) return -1;
    view->_asn_ctx = value->_asn_ctx;
    *descriptor = *td;
    *specs = *original;
    specs->struct_size = sizeof(OCTET_STRING_t);
    specs->ctx_offset = offsetof(OCTET_STRING_t, _asn_ctx);
    descriptor->specifics = specs;
    return 0;
}

/*
 * Purpose: Save incremental decoder state back into ANY storage.
 * Source: ANY text decoder adapter. Version: 2026-10-30.
 * Inputs: value receives view's buffer, length and parsing context.
 * Returns: nothing. Errors: callers bound output before decoding.
 * Author: maintainers. History: Keeps the public ANY_t size unchanged.
 * Example: A partial text value can be resumed in the next call.
 */
static void
ANY_text_commit(ANY_t *value, const OCTET_STRING_t *view) {
    value->buf = view->buf;
    value->size = (int)view->size;
    value->_asn_ctx = view->_asn_ctx;
}
#endif

#if !defined(ASN_DISABLE_XER_SUPPORT)
/*
 * Purpose: Decode hexadecimal XER through an ABI-safe temporary OCTET STRING.
 * Source: OCTET_STRING_decode_xer_hex. Version: 2026-10-30.
 * Inputs: codec/td/target/name/input/size follow the XER decoder contract.
 * Returns: XER decoder result. Errors: Invalid or oversized input fails.
 * Author: maintainers. History: Preserve incremental parser state in ANY.
 * Example: A split hexadecimal body resumes without enlarging ANY_t.
 */
asn_dec_rval_t
ANY_decode_xer(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
               void **target, const char *name, const void *input, size_t size) {
    asn_TYPE_descriptor_t descriptor;
    asn_OCTET_STRING_specifics_t specs;
    OCTET_STRING_t view;
    void *temporary = &view;
    asn_dec_rval_t result = {RC_FAIL, 0};
    if(!input || ANY_text_prepare(td, target, size, &descriptor,
                                            &specs, &view)) return result;
    result = OCTET_STRING_decode_xer_hex(codec, &descriptor, &temporary,
                                        name, input, size);
    ANY_text_commit((ANY_t *)*target, &view);
    return result;
}
#endif

#if !defined(ASN_DISABLE_JER_SUPPORT)
/*
 * Purpose: Identify a complete JSON string before calling the JER parser.
 * Source: JSON string framing and ANY's hexadecimal JER mapping.
 * Version: 2026-10-30. Inputs: input/size hold unconsumed encoded bytes.
 * Returns: zero for an unfinished string, one for a complete or nonstring input.
 * Errors: Invalid input is left for the underlying parser to reject.
 * Author: maintainers. History: Avoids treating a string prefix as a value.
 * Example: An opening quote and one digit require more bytes.
 */
static int
ANY_jer_string_complete(const void *input, size_t size) {
    const uint8_t *bytes = (const uint8_t *)input;
    size_t i = 0;
    int escaped = 0;
    while(i < size && (bytes[i] == ' ' || bytes[i] == '\t'
                       || bytes[i] == '\r' || bytes[i] == '\n')) i++;
    if(i == size) return 0;
    if(bytes[i++] != '"') return 1;
    for(; i < size; i++) {
        if(!escaped && bytes[i] == '"') return 1;
        if(!escaped && bytes[i] == '\\') escaped = 1;
        else escaped = 0;
    }
    return 0;
}

/*
 * Purpose: Decode hexadecimal JER through an ABI-safe temporary OCTET STRING.
 * Source: OCTET_STRING_decode_jer_hex. Version: 2026-10-30.
 * Inputs: codec/td/constraints/target/input/size follow the JER contract.
 * Returns: JER decoder result. Errors: Invalid or oversized input fails.
 * Author: maintainers. History: Preserve incremental parser state in ANY.
 * Example: An encoded hexadecimal string populates ANY's signed-size buffer.
 */
asn_dec_rval_t
ANY_decode_jer(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
               const asn_jer_constraints_t *constraints, void **target,
               const void *input, size_t size) {
    asn_TYPE_descriptor_t descriptor;
    asn_OCTET_STRING_specifics_t specs;
    OCTET_STRING_t view;
    void *temporary = &view;
    asn_dec_rval_t result = {RC_FAIL, 0};
    if(!td || !target || (!input && size)) return result;
    if(!size || !ANY_jer_string_complete(input, size)) {
        result.code = RC_WMORE;
        return result;
    }
    if(ANY_text_prepare(td, target, size, &descriptor, &specs, &view)) return result;
    result = OCTET_STRING_decode_jer_hex(codec, &descriptor, constraints,
                                        &temporary, input, size);
    ANY_text_commit((ANY_t *)*target, &view);
    return result;
}
#endif

#if !defined(ASN_DISABLE_BER_SUPPORT)
/*
 * Purpose: Decode opaque BER bytes using a checked temporary OCTET STRING.
 * Source: OCTET_STRING_decode_ber. Version: 2026-10-30.
 * Inputs: codec/td/target/input/size/tag_mode follow the BER decoder contract.
 * Returns: BER decoder status and consumption. Errors: Invalid storage fails.
 * Author: maintainers. History: Preserves ANY's signed-size public ABI.
 * Example: A split BER value resumes using the copied parser context.
 */
asn_dec_rval_t
ANY_decode_ber(const asn_codec_ctx_t *codec, const asn_TYPE_descriptor_t *td,
               void **target, const void *input, size_t size, int tag_mode) {
    asn_TYPE_descriptor_t descriptor;
    asn_OCTET_STRING_specifics_t specs;
    OCTET_STRING_t view;
    void *temporary = &view;
    asn_dec_rval_t result = {RC_FAIL, 0};
    if(!input || ANY_text_prepare(td, target, size, &descriptor, &specs, &view))
        return result;
    result = OCTET_STRING_decode_ber(codec, &descriptor, &temporary,
                                     input, size, tag_mode);
    ANY_text_commit((ANY_t *)*target, &view);
    return result;
}

/*
 * Purpose: Encode opaque DER bytes through a checked ANY payload view.
 * Source: OCTET_STRING_encode_der. Version: 2026-10-30.
 * Inputs: td/sptr/tag_mode/tag describe the value; cb/key consume output.
 * Returns: encoder result. Errors: Invalid payload or callback fails.
 * Author: maintainers. History: Avoids interpreting ANY's int size as size_t.
 * Example: A stored INTEGER TLV is emitted as the same untagged bytes.
 */
asn_enc_rval_t
ANY_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
               int tag_mode, ber_tlv_tag_t tag,
               asn_app_consume_bytes_f *cb, void *key) {
    OCTET_STRING_t view;
    if(!td || ANY_to_octet_view((const ANY_t *)sptr, &view))
        ASN__ENCODE_FAILED;
    return OCTET_STRING_encode_der(td, &view, tag_mode, tag, cb, key);
}
#endif

/*
 * Purpose: Replace ANY contents with a copy of caller-provided bytes.
 * Source: OCTET_STRING_fromBuf contract adapted to ANY. Version: 2026-10-30.
 * Inputs: value is the destination; buffer/size select bytes, or size < 0
 *         selects a NUL-terminated input. A NULL buffer with size zero clears.
 * Returns: zero or -1. Errors: Invalid and oversized inputs fail safely.
 * Author: maintainers. History: Avoids an incompatible OCTET STRING cast.
 * Example: ANY_fromBuf(value, "x", 1) copies one byte.
 */
int
ANY_fromBuf(ANY_t *value, const char *buffer, int size) {
    size_t length;
    uint8_t *copy;
    if(!value || (!buffer && size)) { errno = EINVAL; return -1; }
    if(!buffer) {
        FREEMEM(value->buf);
        value->buf = 0;
        value->size = 0;
        return 0;
    }
    length = size < 0 ? strlen(buffer) : (size_t)size;
    if(length > INT_MAX) { errno = EOVERFLOW; return -1; }
    copy = (uint8_t *)MALLOC(length + 1);
    if(!copy) return -1;
    if(length) memcpy(copy, buffer, length);
    copy[length] = 0;
    FREEMEM(value->buf);
    value->buf = copy;
    value->size = (int)length;
    return 0;
}

/*
 * Purpose: Allocate an ANY and optionally initialize it from bytes.
 * Source: OCTET_STRING_new_fromBuf contract. Version: 2026-10-30.
 * Inputs: buffer/size select the initial contents. Returns: owned ANY or NULL.
 * Errors: Invalid input and allocation failure return NULL. Author: maintainers.
 * History: Retains ANY's public size and allocation layout.
 * Example: ANY_new_fromBuf("x", 1) creates a one-byte value.
 */
ANY_t *
ANY_new_fromBuf(const char *buffer, int size) {
    ANY_t *value = (ANY_t *)CALLOC(1, sizeof(*value));
    if(!value) return 0;
    if(buffer && ANY_fromBuf(value, buffer, size)) {
        FREEMEM(value);
        return 0;
    }
    return value;
}
