/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <UTCTime.h>
#include <GeneralizedTime.h>
#include <errno.h>

/*
 * Validate decimal fields without reading outside the encoded UTCTime buffer.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: UTCTime value, byte offset, digit count, and output integer pointer.
 * Returns: 1 for a valid decimal field, 0 for malformed or out-of-range input.
 * Errors: Sets errno to EINVAL for malformed input; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added for strict UTCTime.
 * Example: utc_get_digits(st, 2, 2, &month) reads the month field.
 */
#ifndef ASN_ENABLE_TOLERANT_UTCTIME
static int
utc_get_digits(const UTCTime_t *st, size_t offset, size_t count, int *value) {
    size_t i;
    int result = 0;

    if(!st || !st->buf || !value || offset > st->size
    || count > st->size - offset) {
        errno = EINVAL;
        return 0;
    }

    for(i = 0; i < count; i++) {
        unsigned char ch = st->buf[offset + i];
        if(ch < '0' || ch > '9') {
            errno = EINVAL;
            return 0;
        }
        result = result * 10 + (ch - '0');
    }

    *value = result;
    return 1;
}

/*
 * Determine whether a Gregorian year contains February 29.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Full Gregorian year.
 * Returns: Nonzero for a leap year, zero otherwise.
 * Errors: None; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added for strict UTCTime.
 * Example: utc_is_leap_year(2000) returns nonzero.
 */
static int
utc_is_leap_year(int year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

/*
 * Validate the date and clock fields in a UTCTime value.
 * Original source: asn1c UTCTime runtime skeleton; ranges follow X.680 47.2/47.3.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Encoded value and whether the seconds field is present.
 * Returns: 1 for valid date and clock fields, 0 otherwise.
 * Errors: Sets errno to EINVAL for malformed input; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added strict UTCTime checks.
 * Example: utc_validate_calendar(st, 0) validates a value without seconds.
 */
static int
utc_validate_calendar(const UTCTime_t *st, int has_seconds) {
    static const unsigned char month_days[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    int year2, month, day, hour, minute, second = 0;
    int year, max_day;

    if(!utc_get_digits(st, 0, 2, &year2)
    || !utc_get_digits(st, 2, 2, &month)
    || !utc_get_digits(st, 4, 2, &day)
    || !utc_get_digits(st, 6, 2, &hour)
    || !utc_get_digits(st, 8, 2, &minute)
    || (has_seconds && !utc_get_digits(st, 10, 2, &second))) {
        return 0;
    }

    if(hour > 23 || minute > 59 || second > 59
    || month < 1 || month > 12 || day < 1) {
        errno = EINVAL;
        return 0;
    }

    year = year2 <= 59 ? 2000 + year2 : 1900 + year2;
    max_day = month_days[month - 1];
    if(month == 2 && utc_is_leap_year(year)) {
        max_day++;
    }
    if(day > max_day) {
        errno = EINVAL;
        return 0;
    }

    return 1;
}

/*
 * Validate the required UTC marker or signed numeric timezone offset.
 * Original source: asn1c UTCTime runtime skeleton; syntax follows X.680 47.2/47.3.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Encoded value whose length has already been checked.
 * Returns: 1 for valid Z or +/-hhmm suffix, 0 otherwise.
 * Errors: Sets errno to EINVAL for malformed input; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added strict UTCTime checks.
 * Example: utc_validate_zone(st) accepts a suffix of "+0530".
 */
static int
utc_validate_zone(const UTCTime_t *st) {
    int zone_hour, zone_minute;
    int has_seconds = st->size == 13 || st->size == 17;
    int has_offset = st->size == 15 || st->size == 17;
    size_t time_end = 10 + (has_seconds ? 2 : 0);

    if(!has_offset) {
        if(st->buf[time_end] == 'Z') {
            return 1;
        }
        errno = EINVAL;
        return 0;
    }

    if((st->buf[time_end] != '+' && st->buf[time_end] != '-')
    || !utc_get_digits(st, time_end + 1, 2, &zone_hour)
    || !utc_get_digits(st, time_end + 3, 2, &zone_minute)
    || zone_hour > 23 || zone_minute > 59) {
        errno = EINVAL;
        return 0;
    }

    return 1;
}

/*
 * Validate UTCTime length, lexical form, clock fields, and Gregorian date.
 * Original source: asn1c UTCTime runtime skeleton; syntax follows X.680 47.2/47.3.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Encoded UTCTime value.
 * Returns: 1 for valid YYMMDDhhmm[ss](Z|+/-hhmm), 0 otherwise.
 * Errors: Sets errno to EINVAL for malformed input; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Added strict UTCTime checks.
 * Example: utc_validate(st) accepts "2402291200Z".
 */
static int
utc_validate(const UTCTime_t *st) {
    int has_seconds;

    if(!st || !st->buf
    || (st->size != 11 && st->size != 13
     && st->size != 15 && st->size != 17)) {
        errno = EINVAL;
        return 0;
    }

    has_seconds = st->size == 13 || st->size == 17;
    return utc_validate_calendar(st, has_seconds) && utc_validate_zone(st);
}
#endif  /* !ASN_ENABLE_TOLERANT_UTCTIME */

#ifndef ASN___INTERNAL_TEST_MODE

/*
 * Reject a decoded value when strict UTCTime validation fails.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Decoder result and address of decoded value pointer.
 * Returns: Original result unless RC_OK contains an invalid strict value.
 * Errors: Sets errno to EINVAL when rejecting a value; no exceptions thrown.
 * Responsible party: asn1c maintainers. History: Added for strict decoders.
 * Example: UTCTime_decode_check(rc, &value) postchecks a codec result.
 */
#if !defined(ASN_DISABLE_BER_SUPPORT) || !defined(ASN_DISABLE_XER_SUPPORT) \
 || !defined(ASN_DISABLE_JER_SUPPORT) || !defined(ASN_DISABLE_OER_SUPPORT) \
 || !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) \
 || !defined(ASN_DISABLE_CBOR_SUPPORT)
static asn_dec_rval_t
UTCTime_decode_check(asn_dec_rval_t rc, void **sptr) {
#ifdef ASN_ENABLE_TOLERANT_UTCTIME
    (void)sptr;
#else
    if(rc.code == RC_OK
    && (!sptr || !*sptr || !utc_validate((const UTCTime_t *)*sptr))) {
        rc.code = RC_FAIL;
        errno = EINVAL;
    }
#endif
    return rc;
}
#endif

#if !defined(ASN_DISABLE_BER_SUPPORT)
/*
 * Decode BER UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Standard BER decoder context, descriptor, target, buffer, size, tag.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict BER validation.
 * Example: UTCTime_decode_ber(ctx, td, &value, bytes, size, tag_mode).
 */
asn_dec_rval_t
UTCTime_decode_ber(const asn_codec_ctx_t *ctx, const asn_TYPE_descriptor_t *td,
                   void **sptr, const void *buf, size_t size, int tag_mode) {
    return UTCTime_decode_check(
        OCTET_STRING_decode_ber(ctx, td, sptr, buf, size, tag_mode), sptr);
}
#endif  /* !ASN_DISABLE_BER_SUPPORT */

#if !defined(ASN_DISABLE_XER_SUPPORT)
/*
 * Decode XER UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: XER decoder context, descriptor, target, member name, and text.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict XER validation.
 * Example: UTCTime_decode_xer(ctx, td, &value, name, text, size).
 */
asn_dec_rval_t
UTCTime_decode_xer(const asn_codec_ctx_t *ctx, const asn_TYPE_descriptor_t *td,
                   void **sptr, const char *mname, const void *buf,
                   size_t size) {
    return UTCTime_decode_check(
        OCTET_STRING_decode_xer_utf8(ctx, td, sptr, mname, buf, size), sptr);
}
#endif  /* !ASN_DISABLE_XER_SUPPORT */

#if !defined(ASN_DISABLE_JER_SUPPORT)
/*
 * Decode JER UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: JER decoder context, descriptor, constraints, target, and text.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict JER validation.
 * Example: UTCTime_decode_jer(ctx, td, constraints, &value, text, size).
 */
asn_dec_rval_t
UTCTime_decode_jer(const asn_codec_ctx_t *ctx, const asn_TYPE_descriptor_t *td,
                   const asn_jer_constraints_t *constraints, void **sptr,
                   const void *buf, size_t size) {
    return UTCTime_decode_check(OCTET_STRING_decode_jer_utf8(
        ctx, td, constraints, sptr, buf, size), sptr);
}
#endif  /* !ASN_DISABLE_JER_SUPPORT */

#if !defined(ASN_DISABLE_OER_SUPPORT)
/*
 * Decode OER UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: OER decoder context, descriptor, constraints, target, and input.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict OER validation.
 * Example: UTCTime_decode_oer(ctx, td, constraints, &value, bytes, size).
 */
asn_dec_rval_t
UTCTime_decode_oer(const asn_codec_ctx_t *ctx, const asn_TYPE_descriptor_t *td,
                   const asn_oer_constraints_t *constraints, void **sptr,
                   const void *buf, size_t size) {
    return UTCTime_decode_check(OCTET_STRING_decode_oer(
        ctx, td, constraints, sptr, buf, size), sptr);
}
#endif  /* !ASN_DISABLE_OER_SUPPORT */

#if !defined(ASN_DISABLE_UPER_SUPPORT)
/*
 * Decode UPER UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: UPER context, descriptor, constraints, target, and PER input state.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict UPER validation.
 * Example: UTCTime_decode_uper(ctx, td, constraints, &value, per_data).
 */
asn_dec_rval_t
UTCTime_decode_uper(const asn_codec_ctx_t *ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_per_constraints_t *constraints, void **sptr,
                    asn_per_data_t *pd) {
    return UTCTime_decode_check(OCTET_STRING_decode_uper(
        ctx, td, constraints, sptr, pd), sptr);
}
#endif  /* !ASN_DISABLE_UPER_SUPPORT */

#if !defined(ASN_DISABLE_APER_SUPPORT)
/*
 * Decode APER UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: APER context, descriptor, constraints, target, and PER input state.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict APER validation.
 * Example: UTCTime_decode_aper(ctx, td, constraints, &value, per_data).
 */
asn_dec_rval_t
UTCTime_decode_aper(const asn_codec_ctx_t *ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_per_constraints_t *constraints, void **sptr,
                    asn_per_data_t *pd) {
    return UTCTime_decode_check(OCTET_STRING_decode_aper(
        ctx, td, constraints, sptr, pd), sptr);
}
#endif  /* !ASN_DISABLE_APER_SUPPORT */

#if !defined(ASN_DISABLE_CBOR_SUPPORT)
/*
 * Decode CBOR UTCTime and apply strict lexical/calendar validation.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: CBOR decoder context, descriptor, target, and encoded input.
 * Returns: OCTET STRING decoder result, changed to RC_FAIL for invalid time.
 * Errors: Decoder errors pass through; malformed time sets errno to EINVAL.
 * Responsible party: asn1c maintainers. History: Added strict CBOR validation.
 * Example: UTCTime_decode_cbor(ctx, td, &value, bytes, size).
 */
asn_dec_rval_t
UTCTime_decode_cbor(const asn_codec_ctx_t *ctx,
                    const asn_TYPE_descriptor_t *td, void **sptr,
                    const void *buf, size_t size) {
    return UTCTime_decode_check(OCTET_STRING_decode_cbor_utf8(
        ctx, td, sptr, buf, size), sptr);
}
#endif  /* !ASN_DISABLE_CBOR_SUPPORT */

#endif  /* !ASN___INTERNAL_TEST_MODE */

#ifndef	ASN___INTERNAL_TEST_MODE

/*
 * UTCTime basic type description.
 */
static const ber_tlv_tag_t asn_DEF_UTCTime_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),  /* [UNIVERSAL 23] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),  /* [UNIVERSAL 26] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_DEF_UTCTime_constraints = {
    { APC_CONSTRAINED, 7, 7, 0x20, 0x7e },   /* Value */
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },  /* Size */
    0, 0
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_operation_t asn_OP_UTCTime = {
    .kind = ASN_KIND_PRIMITIVE,
    OCTET_STRING_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    UTCTime_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    UTCTime_compare,
    UTCTime_copy,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    UTCTime_decode_ber,
    OCTET_STRING_encode_der,  /* Implemented in terms of OCTET STRING */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    UTCTime_decode_xer,
    UTCTime_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
    UTCTime_decode_jer,
    UTCTime_encode_jer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    UTCTime_decode_oer,
    OCTET_STRING_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    UTCTime_decode_uper,
    OCTET_STRING_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    UTCTime_decode_aper,
    OCTET_STRING_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    UTCTime_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0,  /* Use generic outmost tag fetcher */
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
    UTCTime_decode_cbor,
    OCTET_STRING_encode_cbor_utf8,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */
};
asn_TYPE_descriptor_t asn_DEF_UTCTime = {
    "UTCTime",
    "UTCTime",
    &asn_OP_UTCTime,
    asn_DEF_UTCTime_tags,
    sizeof(asn_DEF_UTCTime_tags)
      / sizeof(asn_DEF_UTCTime_tags[0]) - 2,
    asn_DEF_UTCTime_tags,
    sizeof(asn_DEF_UTCTime_tags)
      / sizeof(asn_DEF_UTCTime_tags[0]),
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        &asn_DEF_UTCTime_constraints,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
        UTCTime_constraint
    },
    0, 0,  /* No members */
    0  /* No specifics */
};

#endif	/* ASN___INTERNAL_TEST_MODE */

/*
 * Check UTCTime lexical form and Gregorian calendar validity.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Descriptor, encoded value, optional failure callback, callback data.
 * Returns: 0 for valid input, -1 when the constraint is violated.
 * Errors: Reports EINVAL for invalid input; no exceptions are thrown.
 * Responsible party: asn1c maintainers. History: Strict mode uses utc_validate;
 * tolerant mode retains the legacy conversion-based constraint behavior.
 * Example: UTCTime_constraint(td, value, callback, key) validates a value.
 */
int
UTCTime_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                   asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const UTCTime_t *st = (const UTCTime_t *)sptr;

#ifdef ASN_ENABLE_TOLERANT_UTCTIME
	time_t tloc;

	errno = EPERM;			/* Just an unlikely error code */
	tloc = asn_UT2time(st, 0, 0);
	if(tloc == -1 && errno != EPERM) {
        ASN__CTFAIL(app_key, td, sptr, "%s: Invalid time format: %s (%s:%d)",
                    td->name, strerror(errno), __FILE__, __LINE__);
        return -1;
	}
#else
	if(!st || !utc_validate(st)) {
		errno = EINVAL;
        ASN__CTFAIL(app_key, td, sptr, "%s: Invalid time format: %s (%s:%d)",
                    td->name, strerror(errno), __FILE__, __LINE__);
        return -1;
	}
#endif

	return 0;
}

/*
 * Convert a UTCTime value after checking its strict syntax and calendar date.
 * Original source: asn1c UTCTime runtime skeleton, adapting GeneralizedTime.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Encoded UTCTime, optional tm output, and local/GMT conversion flag.
 * Returns: Converted time_t, or (time_t)-1 on invalid or unrepresentable input.
 * Errors: Sets errno for malformed or conversion errors; no exceptions thrown.
 * Responsible party: asn1c maintainers. History: Added strict validation guard.
 * Example: asn_UT2time(value, &tm, 1) converts a validated value to UTC.
 */
time_t
asn_UT2time(const UTCTime_t *st, struct tm *_tm, int as_gmt) {
	char buf[24];	/* "AAMMJJhhmmss+hhmm" + cushion */
	GeneralizedTime_t gt;

	if(!st || !st->buf
	|| st->size < 11 || st->size >= ((int)sizeof(buf) - 2)) {
		errno = EINVAL;
		return -1;
	}

#ifndef ASN_ENABLE_TOLERANT_UTCTIME
	if(!utc_validate(st)) {
		errno = EINVAL;
		return -1;
	}
#endif  /* !ASN_ENABLE_TOLERANT_UTCTIME */

	gt.buf = (unsigned char *)buf;
	gt.size = st->size + 2;
	memcpy(gt.buf + 2, st->buf, st->size);
	if(st->buf[0] > 0x35) {
		/* 19xx */
		gt.buf[0] = 0x31;
		gt.buf[1] = 0x39;
	} else {
		/* 20xx */
		gt.buf[0] = 0x32;
		gt.buf[1] = 0x30;
	}

	return asn_GT2time(&gt, _tm, as_gmt);
}

/*
 * Convert a broken-down calendar value to a UTCTime text value.
 * Original source: asn1c UTCTime runtime skeleton, adapting asn_time2GT.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Optional destination value, broken-down time, and force-GMT flag.
 * Returns: Updated destination or NULL when conversion or allocation fails.
 * Errors: Propagates GeneralizedTime conversion failures; no exceptions thrown.
 * Responsible party: asn1c maintainers. History: Existing UTCTime conversion.
 * Example: asn_time2UT(NULL, &tm, 1) creates a UTC UTCTime value.
 */
UTCTime_t *
asn_time2UT(UTCTime_t *opt_ut, const struct tm *tm, int force_gmt) {
	GeneralizedTime_t *gt = (GeneralizedTime_t *)opt_ut;

	gt = asn_time2GT(gt, tm, force_gmt);
	if(gt == 0) return 0;

	assert(gt->size >= 2);
	gt->size -= 2;
	memmove(gt->buf, gt->buf + 2, gt->size + 1);

	return (UTCTime_t *)gt;
}

/*
 * Compare two UTCTime values by their converted instants.
 * Original source: asn1c UTCTime runtime skeleton.
 * Version/date: 1.0, 2026-11-12.
 * Inputs: Descriptor plus two optional UTCTime values.
 * Returns: Negative, zero, or positive according to chronological order.
 * Errors: Invalid values fall back to octet comparison; no exceptions thrown.
 * Responsible party: asn1c maintainers. History: Existing time comparison.
 * Example: UTCTime_compare(td, earlier, later) returns a negative value.
 */
int
UTCTime_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                        const void *bptr) {
    const GeneralizedTime_t *a = aptr;
    const GeneralizedTime_t *b = bptr;

    (void)td;

    if(a && b) {
        time_t at, bt;
        int aerr, berr;

        errno = EPERM;
        at = asn_UT2time(a, 0, 0);
        aerr = errno;
        errno = EPERM;
        bt = asn_UT2time(b, 0, 0);
        berr = errno;

        if(at == -1 && aerr != EPERM) {
            if(bt == -1 && berr != EPERM) {
                return OCTET_STRING_compare(td, aptr, bptr);
            } else {
                return -1;
            }
        } else if(bt == -1 && berr != EPERM) {
            return 1;
        } else {
            /* Both values are valid. */
        }

        if(at < bt) {
            return -1;
        } else if(at > bt) {
            return 1;
        } else {
            return 0;
        }
    } else if(!a && !b) {
        return 0;
    } else if(!a) {
        return -1;
    } else {
        return 1;
    }
}

