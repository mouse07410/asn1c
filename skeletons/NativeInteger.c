/*-
 * Copyright (c) 2004, 2005, 2006 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * Read the NativeInteger.h for the explanation wrt. differences between
 * INTEGER and NativeInteger.
 * Basically, both are decoders and encoders of ASN.1 INTEGER type, but this
 * implementation deals with the standard (machine-specific) representation
 * of them instead of using the platform-independent buffer.
 */
#include <asn_internal.h>
#include <NativeInteger.h>

/*
 * NativeInteger basic type description.
 */
static const ber_tlv_tag_t asn_DEF_NativeInteger_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_operation_t asn_OP_NativeInteger = {
    .kind = ASN_KIND_PRIMITIVE,
    NativeInteger_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    NativeInteger_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    NativeInteger_compare,
    NativeInteger_copy,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    NativeInteger_decode_ber,
    NativeInteger_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    NativeInteger_decode_xer,
    NativeInteger_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    NativeInteger_decode_jer,
    NativeInteger_encode_jer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    NativeInteger_decode_oer,  /* OER decoder */
    NativeInteger_encode_oer,  /* Canonical OER encoder */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    NativeInteger_decode_uper,  /* Unaligned PER decoder */
    NativeInteger_encode_uper,  /* Unaligned PER encoder */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    NativeInteger_decode_aper,  /* Aligned PER decoder */
    NativeInteger_encode_aper,  /* Aligned PER encoder */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    NativeInteger_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */,
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    NativeInteger_decode_cbor,
    NativeInteger_encode_cbor,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};
asn_TYPE_descriptor_t asn_DEF_NativeInteger = {
    "INTEGER",  /* The ASN.1 type is still INTEGER */
    "INTEGER",
    &asn_OP_NativeInteger,
    asn_DEF_NativeInteger_tags,
    sizeof(asn_DEF_NativeInteger_tags) / sizeof(asn_DEF_NativeInteger_tags[0]),
    asn_DEF_NativeInteger_tags,  /* Same as above */
    sizeof(asn_DEF_NativeInteger_tags) / sizeof(asn_DEF_NativeInteger_tags[0]),
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
    },
    0, 0,  /* No members */
    0  /* No specifics */
};

/*
 * Width-aware access helpers.  The native integer member occupies
 * field_width octets (1/2/4/8); when field_width is 0 the width defaults to
 * sizeof(long), so descriptors that do not set it behave exactly as before.
 */
size_t
NativeInteger_field_width(const asn_INTEGER_specifics_t *specs) {
    if(specs && specs->field_width)
        return (size_t)specs->field_width;
    return sizeof(long);
}

intmax_t
NativeInteger_load_s(const void *ptr, const asn_INTEGER_specifics_t *specs) {
    switch(NativeInteger_field_width(specs)) {
    case 1: return (intmax_t)(*(const int8_t  *)ptr);
    case 2: return (intmax_t)(*(const int16_t *)ptr);
    case 4: return (intmax_t)(*(const int32_t *)ptr);
    case 8: return (intmax_t)(*(const int64_t *)ptr);
    default: return (intmax_t)(*(const long *)ptr);
    }
}

uintmax_t
NativeInteger_load_u(const void *ptr, const asn_INTEGER_specifics_t *specs) {
    switch(NativeInteger_field_width(specs)) {
    case 1: return (uintmax_t)(*(const uint8_t  *)ptr);
    case 2: return (uintmax_t)(*(const uint16_t *)ptr);
    case 4: return (uintmax_t)(*(const uint32_t *)ptr);
    case 8: return (uintmax_t)(*(const uint64_t *)ptr);
    default: return (uintmax_t)(*(const unsigned long *)ptr);
    }
}

void
NativeInteger_store(void *ptr, const asn_INTEGER_specifics_t *specs,
                    uintmax_t v) {
    switch(NativeInteger_field_width(specs)) {
    case 1: *(uint8_t  *)ptr = (uint8_t)v;  break;
    case 2: *(uint16_t *)ptr = (uint16_t)v; break;
    case 4: *(uint32_t *)ptr = (uint32_t)v; break;
    case 8: *(uint64_t *)ptr = (uint64_t)v; break;
    default: *(unsigned long *)ptr = (unsigned long)v; break;
    }
}

/*
 * Decode an INTEGER_t into the native member, honoring field width and
 * signedness.  Returns 0 on success, -1 if the value does not fit the
 * configured native width (overflow).
 */
int
NativeInteger_store_from_INTEGER(void *ptr,
                                 const asn_INTEGER_specifics_t *specs,
                                 const INTEGER_t *tmp) {
    size_t w = NativeInteger_field_width(specs);
    if(specs && specs->field_unsigned) {
        uintmax_t u;
        if(asn_INTEGER2umax(tmp, &u)) return -1;
        if(w < sizeof(uintmax_t)) {
            uintmax_t max = (((uintmax_t)1 << (8 * w)) - 1);
            if(u > max) return -1;
        }
        NativeInteger_store(ptr, specs, u);
    } else {
        intmax_t s;
        if(asn_INTEGER2imax(tmp, &s)) return -1;
        if(w < sizeof(intmax_t)) {
            intmax_t hi = (((intmax_t)1 << (8 * w - 1)) - 1);
            intmax_t lo = -hi - 1;
            if(s < lo || s > hi) return -1;
        }
        NativeInteger_store(ptr, specs, (uintmax_t)s);
    }
    return 0;
}

/*
 * Materialize the native member as a canonical INTEGER_t (caller frees
 * tmp->buf).  Returns 0 on success.
 */
int
NativeInteger_to_INTEGER(const void *ptr,
                         const asn_INTEGER_specifics_t *specs,
                         INTEGER_t *tmp) {
    memset(tmp, 0, sizeof(*tmp));
    if(specs && specs->field_unsigned)
        return asn_umax2INTEGER(tmp, NativeInteger_load_u(ptr, specs));
    return asn_imax2INTEGER(tmp, NativeInteger_load_s(ptr, specs));
}

void
NativeInteger_free(const asn_TYPE_descriptor_t *td, void *ptr,
                   enum asn_struct_free_method method) {
    if(!td || !ptr)
		return;

	ASN_DEBUG("Freeing %s as INTEGER (%d, %p, Native)",
		td->name, method, ptr);

    switch(method) {
    case ASFM_FREE_EVERYTHING:
        FREEMEM(ptr);
        break;
    case ASFM_FREE_UNDERLYING:
        break;
    case ASFM_FREE_UNDERLYING_AND_RESET:
        memset(ptr, 0,
               NativeInteger_field_width(
                   (const asn_INTEGER_specifics_t *)td->specifics));
        break;
    }
}

int
NativeInteger_compare(const asn_TYPE_descriptor_t *td, const void *aptr, const void *bptr) {
    (void)td;

    if(aptr && bptr) {
        const asn_INTEGER_specifics_t *specs =
            (const asn_INTEGER_specifics_t *)td->specifics;
        if(specs && specs->field_unsigned) {
            uintmax_t a = NativeInteger_load_u(aptr, specs);
            uintmax_t b = NativeInteger_load_u(bptr, specs);
            if(a < b) return -1;
            else if(a > b) return 1;
            else return 0;
        } else {
            intmax_t a = NativeInteger_load_s(aptr, specs);
            intmax_t b = NativeInteger_load_s(bptr, specs);
            if(a < b) return -1;
            else if(a > b) return 1;
            else return 0;
        }
    } else if(!aptr) {
        return -1;
    } else {
        return 1;
    }
}

int
NativeInteger_copy(const asn_TYPE_descriptor_t *td, void **aptr, const void *bptr) {
    const asn_INTEGER_specifics_t *specs =
        td ? (const asn_INTEGER_specifics_t *)td->specifics : 0;
    size_t width = NativeInteger_field_width(specs);
    void *a = *aptr;

    /* Check if source has data */
    if(!bptr) {
        /* Clear destination */
        if(a) {
            FREEMEM(a);
            *aptr = 0;
        }
        return 0;
    }

    if(!a) {
        a = *aptr = MALLOC(width);
        if(!a) return -1;
    }

    memcpy(a, bptr, width);

    return 0;
}
