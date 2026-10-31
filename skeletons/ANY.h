/*-
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef ASN_TYPE_ANY_H
#define ASN_TYPE_ANY_H

#include <OCTET_STRING.h>	/* Implemented via OCTET STRING type */

#ifdef __cplusplus
extern "C" {
#endif

/* An opaque ANY payload with its owned contents and incremental decode state. */
typedef struct ANY {
	uint8_t *buf;	/* Encoded contents octets (BER or PER payload) */
	int size;	/* Size of the above buffer */

	asn_struct_ctx_t _asn_ctx;	/* state variable: parsing across buffer boundaries */
} ANY_t;

extern asn_TYPE_descriptor_t asn_DEF_ANY;
extern asn_TYPE_operation_t asn_OP_ANY;
extern asn_OCTET_STRING_specifics_t asn_SPC_ANY_specs;

#define ANY_free OCTET_STRING_free

#if !defined(ASN_DISABLE_PRINT_SUPPORT)
asn_struct_print_f ANY_print;
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */

int ANY_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                const void *bptr);
int ANY_copy(const asn_TYPE_descriptor_t *td, void **aptr,
             const void *bptr);

#define ANY_constraint asn_generic_no_constraint

#if !defined(ASN_DISABLE_BER_SUPPORT)
ber_type_decoder_f ANY_decode_ber;
der_type_encoder_f ANY_encode_der;
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */

#if !defined(ASN_DISABLE_XER_SUPPORT)
xer_type_decoder_f ANY_decode_xer;
xer_type_encoder_f ANY_encode_xer;
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */

#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f ANY_decode_jer;
jer_type_encoder_f ANY_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */

#if !defined(ASN_DISABLE_OER_SUPPORT)
oer_type_decoder_f ANY_decode_oer;
oer_type_encoder_f ANY_encode_oer;
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */

#if !defined(ASN_DISABLE_CBOR_SUPPORT)
cbor_type_decoder_f ANY_decode_cbor;
cbor_type_encoder_f ANY_encode_cbor;
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */

/* Initialize a borrowed OCTET STRING view of a valid ANY value. */
int ANY_to_octet_view(const ANY_t *value, OCTET_STRING_t *view);

#if !defined(ASN_DISABLE_UPER_SUPPORT)
per_type_decoder_f ANY_decode_uper;
per_type_encoder_f ANY_encode_uper;
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
per_type_decoder_f ANY_decode_aper;
per_type_encoder_f ANY_encode_aper;
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

/******************************
 * Handy conversion routines. *
 ******************************/

/* Convert another ASN.1 type into the ANY. This implies DER encoding. */
int ANY_fromType(ANY_t *, asn_TYPE_descriptor_t *td, void *struct_ptr);
ANY_t *ANY_new_fromType(asn_TYPE_descriptor_t *td, void *struct_ptr);
#if !defined(ASN_DISABLE_APER_SUPPORT)
int ANY_fromType_aper(ANY_t *st, asn_TYPE_descriptor_t *td, void *sptr);
ANY_t *ANY_new_fromType_aper(asn_TYPE_descriptor_t *td, void *sptr);
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

/* Convert the contents of the ANY type into the specified type. */
int ANY_to_type(ANY_t *, asn_TYPE_descriptor_t *td, void **struct_ptr);
#if !defined(ASN_DISABLE_APER_SUPPORT)
int ANY_to_type_aper(ANY_t *, asn_TYPE_descriptor_t *td, void **struct_ptr);
int ANY_to_type_aper_checked(ANY_t *, asn_TYPE_descriptor_t *td, void **struct_ptr);
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

int ANY_fromBuf(ANY_t *value, const char *buffer, int size);
ANY_t *ANY_new_fromBuf(const char *buffer, int size);

#ifdef __cplusplus
}
#endif

#endif	/* ASN_TYPE_ANY_H */
