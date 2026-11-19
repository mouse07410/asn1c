/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BIT_STRING.h>

/*
 * BIT STRING basic type description.
 */
static const ber_tlv_tag_t asn_DEF_BIT_STRING_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (3 << 2))
};
asn_OCTET_STRING_specifics_t asn_SPC_BIT_STRING_specs = {
    sizeof(BIT_STRING_t),
    offsetof(BIT_STRING_t, _asn_ctx),
    ASN_OSUBV_BIT
};
asn_TYPE_operation_t asn_OP_BIT_STRING = {
    .kind = ASN_KIND_PRIMITIVE,
    OCTET_STRING_free,         /* Implemented in terms of OCTET STRING */
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    BIT_STRING_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    BIT_STRING_compare,
    BIT_STRING_copy,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    OCTET_STRING_decode_ber,   /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_der,   /* Implemented in terms of OCTET STRING */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    BIT_STRING_decode_xer_binary_or_hex,
    BIT_STRING_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    BIT_STRING_decode_jer,
    BIT_STRING_encode_jer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    BIT_STRING_decode_oer,
    BIT_STRING_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    BIT_STRING_decode_uper,  /* Unaligned PER decoder */
    BIT_STRING_encode_uper,  /* Unaligned PER encoder */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    OCTET_STRING_decode_aper,  /* Aligned PER decoder */
    OCTET_STRING_encode_aper,  /* Aligned PER encoder */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    BIT_STRING_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */,
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    BIT_STRING_decode_cbor,
    BIT_STRING_encode_cbor,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};
asn_TYPE_descriptor_t asn_DEF_BIT_STRING = {
    "BIT STRING",
    "BIT_STRING",
    &asn_OP_BIT_STRING,
    asn_DEF_BIT_STRING_tags,
    sizeof(asn_DEF_BIT_STRING_tags)
      / sizeof(asn_DEF_BIT_STRING_tags[0]),
    asn_DEF_BIT_STRING_tags,  /* Same as above */
    sizeof(asn_DEF_BIT_STRING_tags)
      / sizeof(asn_DEF_BIT_STRING_tags[0]),
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
        BIT_STRING_constraint
    },
    0, 0,  /* No members */
    &asn_SPC_BIT_STRING_specs
};

/*
 * BIT STRING generic constraint.
 */
int
BIT_STRING_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                      asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;

	if(st && st->buf) {
		if((st->size == 0 && st->bits_unused)
		|| st->bits_unused < 0 || st->bits_unused > 7) {
			ASN__CTFAIL(app_key, td, sptr,
				"%s: invalid padding byte (%s:%d)",
				td->name, __FILE__, __LINE__);
			return -1;
		}
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}

	if(asn_check_containing_constraint(
	       td, sptr, td->encoding_constraints.contained_type, ctfailcb,
	       app_key)) {
		return -1;
	}

	return 0;
}

/*
 * Non-destructively remove the trailing 0-bits from the given bit string.
 */
const BIT_STRING_t *
BIT_STRING__compactify(const BIT_STRING_t *st, BIT_STRING_t *tmp) {
    const uint8_t *b;
    union {
        const uint8_t *c_buf;
        uint8_t *nc_buf;
    } unconst;

    if(st->size == 0) {
        assert(st->bits_unused == 0);
        return st;
    } else {
        for(b = &st->buf[st->size - 1]; b > st->buf && *b == 0; b--) {
            ;
        }
        /* b points to the last byte which may contain data */
        if(*b) {
            int unused = 7;
            uint8_t v = *b;
            v &= -(int8_t)v;
            if(v & 0x0F) unused -= 4;
            if(v & 0x33) unused -= 2;
            if(v & 0x55) unused -= 1;
            tmp->size = b-st->buf + 1;
            tmp->bits_unused = unused;
        } else {
            tmp->size = b-st->buf;
            tmp->bits_unused = 0;
        }

        assert(b >= st->buf);
    }

    unconst.c_buf = st->buf;
    tmp->buf = unconst.nc_buf;
    return tmp;
}

/*
 * Validate packed BIT STRING storage and calculate its width without mutation.
 * Source: JER encoder validation. Version/date: 2026-11-19.
 * Parameters: value supplies the bits; trim_trailing_zeros requests the
 * shortest equivalent named-bit width; bit_count receives the width on success.
 * Returns zero on success, -1 on invalid storage or overflow. Throws: nothing.
 * Responsible party: asn1c maintainers. History: shared by JER and strict SIZE.
 * Example: stored 0x80 with no unused bits has a trimmed width of one.
 */
int
BIT_STRING__get_size(const BIT_STRING_t *value, int trim_trailing_zeros, size_t *bit_count) {
    BIT_STRING_t compact;
    size_t unused;

    if(!bit_count || !value || (value->size && !value->buf) || value->size > SIZE_MAX / 8
       || value->bits_unused < 0 || value->bits_unused > 7) return -1;
    if(!value->size && value->bits_unused) return -1;
    unused = (size_t)value->bits_unused;
    if(unused && (value->buf[value->size - 1] & ((1u << unused) - 1u))) return -1;

    /* Compact only after checking the invariants required by the shared helper. */
    if(trim_trailing_zeros) value = BIT_STRING__compactify(value, &compact);
    *bit_count = value->size * 8 - (size_t)value->bits_unused;
    return 0;
}

/*
 * Return whether a BIT STRING can be compared safely.
 *
 * Purpose: Classify absent, well-formed, and malformed values before reading
 *          their storage.
 * Original source: asn1c BIT STRING skeleton, adapted for safe comparisons.
 * Version: 2026-10-21.
 * Parameters: value is the BIT STRING value to classify, or NULL if absent.
 * Returns: 0 for absent, 1 for well-formed, and 2 for malformed values.
 * Errors: Does not throw; malformed values are reported through the result.
 * Responsible party: asn1c maintainers.
 * History: Added for safe handling of empty and malformed values.
 * Example: BIT_STRING__compare_status(NULL) returns 0.
 */
static int
BIT_STRING__compare_status(const BIT_STRING_t *value) {
    if(!value) {
        return 0;
    }
    if(value->bits_unused < 0 || value->bits_unused > 7
       || (value->size == 0 && value->bits_unused != 0)
       || (value->size != 0 && !value->buf)) {
        return 2;
    }
    return 1;
}

/*
 * Compare two BIT STRING values while ignoring semantically trailing zero
 * bits.
 *
 * Purpose: Order absent, valid, and malformed values safely, then compare
 *          valid values according to X.680 trailing-zero semantics.
 * Original source: asn1c BIT STRING skeleton, based on the X.680 comparison.
 * Version: 2026-10-21.
 * Parameters: td is the BIT STRING descriptor; aptr and bptr are values.
 * Returns: A negative value, zero, or a positive value according to order.
 * Errors: Does not throw. Malformed values sort after valid values by size;
 *         an invalid descriptor returns zero because it has no defined order.
 * Responsible party: asn1c maintainers.
 * History: Added absent and malformed input handling and guarded empty compares.
 * Example: Two empty BIT STRING values compare equal.
 */
int
BIT_STRING_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                   const void *bptr) {
    /*
     * Remove information about trailing bits, since
     * X.680 (08/2015) #22.7 "ensure that different semantics are not"
     * "associated with [values that differ only in] the trailing 0 bits."
     */
    BIT_STRING_t compact_a, compact_b;
    const BIT_STRING_t *input_a = (const BIT_STRING_t *)aptr;
    const BIT_STRING_t *input_b = (const BIT_STRING_t *)bptr;
    int status_a = BIT_STRING__compare_status(input_a);
    int status_b = BIT_STRING__compare_status(input_b);
    const asn_OCTET_STRING_specifics_t *specs;
    const BIT_STRING_t *a;
    const BIT_STRING_t *b;

    /* Invalid descriptors have no meaningful BIT STRING ordering. */
    if(!td || !td->specifics) {
        return 0;
    }
    specs = td->specifics;
    if(specs->subvariant != ASN_OSUBV_BIT) {
        return 0;
    }

    /* Absent values sort first; malformed values sort after valid values. */
    if(status_a != status_b) {
        return status_a < status_b ? -1 : 1;
    }
    if(status_a == 0) {
        return 0;
    }
    if(status_a == 2) {
        if(input_a->size < input_b->size) {
            return -1;
        } else if(input_a->size > input_b->size) {
            return 1;
        } else {
            return 0;
        }
    }

    /* Compactification retains the BIT STRING trailing-zero comparison rule. */
    a = BIT_STRING__compactify(input_a, &compact_a);
    b = BIT_STRING__compactify(input_b, &compact_b);

    {
        size_t common_prefix_size = a->size <= b->size ? a->size : b->size;
        int ret = common_prefix_size
                      ? memcmp(a->buf, b->buf, common_prefix_size)
                      : 0;
        if(ret != 0) {
            return ret;
        }
    }
    if(a->size < b->size) {
        return -1;
    } else if(a->size > b->size) {
        return 1;
    } else if(a->bits_unused > b->bits_unused) {
        return -1;
    } else if(a->bits_unused < b->bits_unused) {
        return 1;
    }
    return 0;
}

/*
 * Copy a BIT STRING value, including its unused-bit count.
 *
 * Purpose: Replace the destination with an independent copy of the source.
 * Original source: asn1c BIT STRING skeleton, adapted from OCTET STRING copy.
 * Version: 2026-10-21.
 * Parameters: td is the BIT STRING descriptor; aptr points to destination;
 *             bptr is the source value, or NULL to clear the destination.
 * Returns: 0 on success; -1 for invalid metadata, source storage, overflow,
 *          or allocation failure.
 * Errors: Does not throw. Invalid metadata and nonempty NULL storage are
 *         rejected without changing the destination.
 * Responsible party: asn1c maintainers.
 * History: Added metadata, empty-copy, and allocation-size overflow guards.
 * Example: Copying a zero-length value allocates a terminated empty buffer.
 */
int
BIT_STRING_copy(const asn_TYPE_descriptor_t *td, void **aptr,
                const void *bptr) {
    const asn_OCTET_STRING_specifics_t *specs;
    BIT_STRING_t *a;
    const BIT_STRING_t *b = (const BIT_STRING_t *)bptr;

    /* Validate descriptor metadata before allocating or clearing a value. */
    if(!td || !td->specifics || !aptr) {
        return -1;
    }
    specs = td->specifics;
    if(specs->subvariant != ASN_OSUBV_BIT
       || specs->struct_size < sizeof(BIT_STRING_t)) {
        return -1;
    }

    a = (BIT_STRING_t *)*aptr;
    if(!b) {
        if(a) {
            FREEMEM(a->buf);
            FREEMEM(a);
            *aptr = 0;
        }
        return 0;
    }

    /* Reject invalid source storage before allocating or changing destination. */
    if(b->size == (size_t)-1 || BIT_STRING__compare_status(b) == 2) {
        return -1;
    }

    if(!a) {
        a = *aptr = CALLOC(1, specs->struct_size);
        if(!a) return -1;
    }

    uint8_t* buf = MALLOC(b->size + 1);
    if(!buf) return -1;
    if(b->size != 0) {
        memcpy(buf, b->buf, b->size);
    }
    buf[b->size] = 0;

    FREEMEM(a->buf);
    a->buf = buf;
    a->size = b->size;
    a->bits_unused = b->bits_unused;

    return 0;
}
