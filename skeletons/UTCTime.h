/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_UTCTime_H_
#define	_UTCTime_H_

/* Include <time.h> first to ensure the system header is used.
 * On case-insensitive filesystems with -I. (macOS default APFS, Cygwin), a
 * local Time.h from ASN.1 schemas (e.g., RFC 3280) can shadow <time.h>.
 *
 * IMPORTANT FOR macOS AND OTHER CASE-INSENSITIVE FILESYSTEMS:
 * If you encounter "non-portable path" or header shadowing warnings,
 * you can ask asn1c to prefix generated filenames, e.g.:
 *   asn1c -fprefix=ASN1_ -pdu=Certificate ...
 * which will generate ASN1_Time.h instead of Time.h and avoid conflicts.
 * The -fprefix= flag automatically handles prefixing in both generated code
 * and makefiles, so no manual editing is required.
 *
 * This approach works transparently on Linux and other case-sensitive
 * filesystems. On macOS, the most robust workaround is to build on a
 * case-sensitive APFS volume so that Time.h and time.h cannot conflict.
 */
#ifdef	__CYGWIN__
#include "/usr/include/time.h"
#else
#include <time.h>
#endif	/* __CYGWIN__ */

#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t UTCTime_t;  /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t asn_DEF_UTCTime;
extern asn_TYPE_operation_t asn_OP_UTCTime;

#define UTCTime_free OCTET_STRING_free

#if !defined(ASN_DISABLE_PRINT_SUPPORT)
asn_struct_print_f UTCTime_print;
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */

asn_struct_compare_f UTCTime_compare;
#define UTCTime_copy OCTET_STRING_copy

asn_constr_check_f UTCTime_constraint;

#if !defined(ASN_DISABLE_BER_SUPPORT)
ber_type_decoder_f UTCTime_decode_ber;
#define UTCTime_encode_der OCTET_STRING_encode_der
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */

#if !defined(ASN_DISABLE_XER_SUPPORT)
xer_type_decoder_f UTCTime_decode_xer;
xer_type_encoder_f UTCTime_encode_xer;
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */

#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f UTCTime_decode_jer;
jer_type_encoder_f UTCTime_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */

#if !defined(ASN_DISABLE_OER_SUPPORT)
oer_type_decoder_f UTCTime_decode_oer;
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */

#if !defined(ASN_DISABLE_UPER_SUPPORT)
per_type_decoder_f UTCTime_decode_uper;
#define UTCTime_encode_uper OCTET_STRING_encode_uper
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
per_type_decoder_f UTCTime_decode_aper;
#define UTCTime_encode_aper OCTET_STRING_encode_aper
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

#if !defined(ASN_DISABLE_CBOR_SUPPORT)
cbor_type_decoder_f UTCTime_decode_cbor;
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */

#if !defined(ASN_DISABLE_RFILL_SUPPORT)
asn_random_fill_f UTCTime_random_fill;
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */

/***********************
 * Some handy helpers. *
 ***********************/

/* See asn_GT2time() in GeneralizedTime.h */
time_t asn_UT2time(const UTCTime_t *, struct tm *_optional_tm4fill, int as_gmt);

/* See asn_time2GT() in GeneralizedTime.h */
UTCTime_t *asn_time2UT(UTCTime_t *__opt_ut, const struct tm *, int force_gmt);

#ifdef __cplusplus
}
#endif

#endif	/* _UTCTime_H_ */
