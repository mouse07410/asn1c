/*-
 * Copyright (c) 2004, 2007 Lev Walkin <vlm@lionet.info>. All rights reserved.
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
#include <NativeEnumerated.h>

/*
 * The unknown-extension reserved region published in NativeEnumerated.h is
 * sized by the widest extension index the PER runtime can transfer
 * (ASN_UPER_NSNNWN_MAX, per_support.h). NativeEnumerated.h must stay
 * self-contained -- it also ships in builds that do not carry per_support.h
 * -- so the two constants are defined independently; fail the build here,
 * where both are visible, if they ever drift apart.
 */
#if defined(ASN_UPER_NSNNWN_MAX) \
    && ASN_NATIVE_ENUMERATED_UNKNOWN_EXT_BASE != (LONG_MAX - ASN_UPER_NSNNWN_MAX)
#error ASN_NATIVE_ENUMERATED_UNKNOWN_EXT_BASE out of sync with ASN_UPER_NSNNWN_MAX
#endif

/*
 * NativeEnumerated basic type description.
 */
static const ber_tlv_tag_t asn_DEF_NativeEnumerated_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_operation_t asn_OP_NativeEnumerated = {
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
    NativeEnumerated_decode_ber,
    NativeEnumerated_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    NativeEnumerated_decode_xer,
    NativeEnumerated_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    NativeEnumerated_decode_jer,
    NativeEnumerated_encode_jer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    NativeEnumerated_decode_oer,
    NativeEnumerated_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    NativeEnumerated_decode_uper,
    NativeEnumerated_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    NativeEnumerated_decode_aper,
    NativeEnumerated_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    NativeEnumerated_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */,
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    NativeEnumerated_decode_cbor,
    NativeEnumerated_encode_cbor,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};

/*
 * Validate a named ENUMERATED value or a losslessly retained PER addition.
 * Source: existing asn1c enum mapping. Version/date: 2026-11-17.
 * Inputs: td supplies enum maps; sptr holds a native value; ctfailcb/app_key
 * receive optional diagnostics. Returns zero or -1. Exceptions: none.
 * Responsible: asn1c maintainers. History: retain standard strict PER relay.
 * Example: a bounded unknown-addition ordinal remains relayable through PER.
 */
int
NativeEnumerated_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                      asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)(td ? td->specifics : NULL);
    const long *native = (const long *)sptr;
    const asn_INTEGER_enum_map_t *el;
    if(!specs || !native) {
        ASN__CTFAIL(app_key, td, sptr, "%s: enum value or map not given", td ? td->name : "ENUMERATED");
        return -1;
    }

#ifdef ASN_STRICT_MODE
    /* Preserve bounded, lossless PER relay of explicit unknown-addition markers.
     * The ordinal must follow every locally known addition; otherwise a marker
     * would decode back as a different, known value. Other syntaxes cannot
     * infer an ASN.1 member from this internal ordinal. */
    if(specs->extension > 0 && specs->extension - 1 <= specs->map_count
       && ASN_NATIVE_ENUMERATED_IS_UNKNOWN_EXT(*native)
       && LONG_MAX - *native >= specs->map_count - specs->extension + 1
       && asn_check_constraints_is_per())
        return 0;
#endif
    el = INTEGER_map_value2enum(specs, *native);
    if(el) {
        return 0;
    } else {
        ASN_DEBUG("No element corresponds to the value %ld", *native);
        ASN__CTFAIL(app_key, td, sptr, "%s: no member corresponds to %ld", td->name, *native);
        return -1;
    }
}

asn_TYPE_descriptor_t asn_DEF_NativeEnumerated = {
    "ENUMERATED",  /* The ASN.1 type is still ENUMERATED */
    "ENUMERATED",
    &asn_OP_NativeEnumerated,
    asn_DEF_NativeEnumerated_tags,
    sizeof(asn_DEF_NativeEnumerated_tags) / sizeof(asn_DEF_NativeEnumerated_tags[0]),
    asn_DEF_NativeEnumerated_tags,  /* Same as above */
    sizeof(asn_DEF_NativeEnumerated_tags) / sizeof(asn_DEF_NativeEnumerated_tags[0]),
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
        NativeEnumerated_constraint
    },
    0, 0,  /* No members */
    0  /* No specifics */
};

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
int
NativeEnumerated__compar_value2enum(const void *ap, const void *bp) {
    const asn_INTEGER_enum_map_t *a = ap;
    const asn_INTEGER_enum_map_t *b = bp;
    if(a->nat_value == b->nat_value)
        return 0;
    if(a->nat_value < b->nat_value)
        return -1;
    return 1;
}
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
