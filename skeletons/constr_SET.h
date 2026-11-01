/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_CONSTR_SET_H_
#define	_CONSTR_SET_H_

#include <asn_application.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASN_DISABLE_OER_SUPPORT
/* Release the OER member phase cursor and any buffered open values. */
void SET_oer_free_member_context(asn_struct_ctx_t *ctx);
#endif

struct asn_SEQUENCE_specifics_s;
struct asn_SET_extension_group_s;


typedef struct asn_SET_specifics_s {
	/*
	 * Target structure description.
	 */
	unsigned struct_size;       /* Size of the target structure. */
	unsigned ctx_offset;        /* Offset of the asn_struct_ctx_t member */
	unsigned pres_offset;       /* Offset of _presence_map member */

	/*
	 * Tags to members mapping table (sorted).
	 * Sometimes suitable for DER encoding (untagged CHOICE is present);
	 * if so, tag2el_count will be greater than td->elements_count.
	 */
	const asn_TYPE_tag2member_t *tag2el;
	unsigned tag2el_count;

	/*
	 * Tags to members mapping table, second edition.
	 * Suitable for CANONICAL-XER encoding.
	 */
	const asn_TYPE_tag2member_t *tag2el_cxer;
	unsigned tag2el_cxer_count;

	/*
	 * Extensions-related stuff.
	 */
	int extensible;             /* 0: nonextensible; 1: legacy; 2: v2; 3: v3. */
	const unsigned int *_mandatory_elements;    /* Bitmask of mandatory ones */

	/* Versioned metadata appended to preserve the legacy field offsets. */
	unsigned specifics_size;                    /* Size of this specifics object. */
	unsigned specifics_version;                 /* Metadata layout version. */
	const unsigned *root_map;                   /* Root member indexes in declaration order. */
	unsigned root_count;                        /* Number of root members. */
	const unsigned *extension_map;              /* Addition indexes in declaration order. */
	unsigned extension_count;                   /* Number of extension additions. */

	/* Version 3 metadata for extension groups encoded as SEQUENCE values. */
	const struct asn_SET_extension_group_s *extension_groups; /* Group wire views. */
	unsigned extension_group_count;              /* Number of group wire views. */
} asn_SET_specifics_t;

/* Version 2 adds explicit root and extension membership maps. */
#define ASN_SET_SPECIFICS_VERSION 2u
/* Version 3 adds per-group SEQUENCE wire-layout metadata. */
#define ASN_SET_SPECIFICS_VERSION_3 3u

/*
 * SEQUENCE wire-layout metadata for one synthetic SET extension group.
 * The original group descriptor and its storage layout remain unchanged.
 */
typedef struct asn_SET_extension_group_s {
	unsigned member_index; /* Outer SET element that owns this group. */
	const struct asn_SEQUENCE_specifics_s *sequence_specifics; /* SEQUENCE layout. */
} asn_SET_extension_group_t;

/*
 * A read-only view of a SET member and the SET presence map that owns it.
 * For transparent extension groups, member points to a child leaf while
 * owner and owner_specs refer to the synthetic group's storage and metadata.
 */
typedef struct asn_SET_member_view_s {
	const asn_TYPE_member_t *member; /* Leaf or ordinary member descriptor. */
	const void *value;               /* Value address, or NULL if pointer absent. */
	const void *owner;               /* Structure containing member. */
	const asn_SET_specifics_t *owner_specs; /* Presence metadata for owner. */
	unsigned owner_index;            /* Member index in owner. */
	int present;                     /* Whether a pointer-backed value exists. */
} asn_SET_member_view_t;

/* Return 0 for known width, -1 for malformed layout, or -2 for unknown primitive. */
int SET_inline_value_size(const asn_TYPE_descriptor_t *td, size_t *size);

/* Validate only the descriptor's immediate storage; child codecs validate selected values. */
int SET_shallow_inline_value_size(const asn_TYPE_descriptor_t *td, size_t *size);

/* Use this child_index to request an ordinary, non-group SET member. */
#define ASN_SET_DIRECT_MEMBER UINT_MAX

/*
 * A set specialized functions dealing with the SET type.
 */
asn_struct_free_f SET_free;

#if !defined(ASN_DISABLE_PRINT_SUPPORT)
asn_struct_print_f SET_print;
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */

asn_struct_compare_f SET_compare;
asn_struct_copy_f    SET_copy;

asn_constr_check_f SET_constraint;

#if !defined(ASN_DISABLE_BER_SUPPORT)
ber_type_decoder_f SET_decode_ber;
der_type_encoder_f SET_encode_der;
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */

#if !defined(ASN_DISABLE_XER_SUPPORT)
xer_type_decoder_f SET_decode_xer;
xer_type_encoder_f SET_encode_xer;
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */

#if !defined(ASN_DISABLE_JER_SUPPORT)
jer_type_decoder_f SET_decode_jer;
jer_type_encoder_f SEQUENCE_encode_jer; /* X.697 29. (2021) */
jer_type_encoder_f SET_encode_jer;
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
#if !defined(ASN_DISABLE_CBOR_SUPPORT)
cbor_type_decoder_f SET_decode_cbor;
cbor_type_encoder_f SET_encode_cbor;
#endif  /* !defined(ASN_DISABLE_CBOR_SUPPORT) */

#if !defined(ASN_DISABLE_UPER_SUPPORT)
per_type_decoder_f SET_decode_uper;
per_type_encoder_f SET_encode_uper;
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */

/* OER member and extension phases own their saved bit maps in ctx->ptr. */
#define ASN_SET_OER_PHASE_MEMBERS 1001
#define ASN_SET_OER_PHASE_EXTENSION_MAP 1003
#define ASN_SET_OER_PHASE_EXTENSIONS 1004

#if !defined(ASN_DISABLE_OER_SUPPORT)
oer_type_decoder_f SET_decode_oer;
oer_type_encoder_f SET_encode_oer;
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */

#if !defined(ASN_DISABLE_APER_SUPPORT)
per_type_decoder_f SET_decode_aper;
per_type_encoder_f SET_encode_aper;
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

#if !defined(ASN_DISABLE_RFILL_SUPPORT)
asn_random_fill_f  SET_random_fill;
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */

extern asn_TYPE_operation_t asn_OP_SET;


/* Check that all the mandatory members are present */
int _SET_is_populated(const asn_TYPE_descriptor_t *td, const void *st);

/*
 * Resolve a SET member to const storage without allocating or changing it.
 * child_index is ASN_SET_DIRECT_MEMBER for an ordinary member, or the leaf
 * index inside a one-level transparent extension group.
 */
int SET_member_view(const asn_TYPE_descriptor_t *td, const void *st,
                    unsigned outer_index, unsigned child_index,
                    asn_SET_member_view_t *view);

/* Check mandatory values in a synthetic extension-group SET by storage. */
int SET_descriptor_valid(const asn_TYPE_descriptor_t *td);
int SET_group_is_populated(const asn_TYPE_descriptor_t *td, const void *st);

/* Versioned metadata and SEQUENCE wire views for SET extension groups. */
int SET_version_valid(const asn_SET_specifics_t *specs);
int SET_group_metadata_valid(const asn_TYPE_descriptor_t *td);
int SET_group_adapter(const asn_TYPE_descriptor_t *td, unsigned index, asn_TYPE_descriptor_t *adapter);
int SET_group_wire_present(const asn_TYPE_descriptor_t *td, const void *st, unsigned index);
int SET_group_mark_present(const asn_TYPE_descriptor_t *td, void *st);
int SET_group_clear_wire_context(const asn_TYPE_descriptor_t *td, void *st);

/***********************
 * Some handy helpers. *
 ***********************/

/*
 * Figure out whether the SET member indicated by PR_x has already been decoded.
 * It is very simple bitfield test, despite its visual complexity.
 */
#define	ASN_SET_ISPRESENT(set_ptr, PR_x)				\
	ASN_SET_ISPRESENT2(&((set_ptr)->_presence_map), PR_x)
#define	ASN_SET_ISPRESENT2(map_ptr, PR_x)				\
	(((unsigned int *)(map_ptr))					\
		[(PR_x)	/ (8 * sizeof(unsigned int))]			\
		& (1u << ((8 * sizeof(unsigned int)) - 1			\
		- ((PR_x) % (8 * sizeof(unsigned int))))))

#define	ASN_SET_MKPRESENT(map_ptr, PR_x)				\
	(((unsigned int *)(map_ptr))					\
		[(PR_x)	/ (8 * sizeof(unsigned int))]			\
		|= (1u << ((8 * sizeof(unsigned int)) - 1		\
		- ((PR_x) % (8 * sizeof(unsigned int))))))

#ifdef __cplusplus
}
#endif

#endif	/* _CONSTR_SET_H_ */
