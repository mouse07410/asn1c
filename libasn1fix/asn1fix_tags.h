#ifndef	ASN1FIX_TAGS_H
#define	ASN1FIX_TAGS_H

struct asn1_namespace_s;   /* Forward declaration */

enum asn1f_aft_flags_e {
	AFT_IMAGINARY_ANY	= 0x01,	/* Treat ANY tag as [IMAGINARY ANY] */
	AFT_FETCH_OUTMOST	= 0x02,	/* Fetch only outmost tag */
	AFT_FULL_COLLECT	= 0x04,	/* Collect all tags */
	AFT_CANON_CHOICE	= 0x08,	/* Fetch the minimal CHOICE root tag */
};

/*
 * Logger signature of the tag-fetch entry points. The format attribute keeps
 * printf-style calls checked.
 */
typedef void (*asn1f_logger_f)(int is_fatal, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/*
 * Allocate and return an array of tags for the given type.
 * Type1 ::= [2] EXPLICIT Type2
 * Type2 ::= [3] IMPLICIT Type3
 * Type3 ::= [4] EXPLICIT SEQUENCE { ... }
 * Will return [2][3][UNIVERSAL 16] for the Type1.
 */
int asn1f_fetch_tags(asn1p_t *asn, struct asn1_namespace_s *ns,
                     asn1p_module_t *mod, asn1p_expr_t *expr,
                     struct asn1p_type_tag_s **tags,
                     enum asn1f_aft_flags_e flags);

/*
 * Same as asn1f_fetch_tags(), but report the diagnostics raised while
 * fetching through the given legacy logger. A nonzero debug_enabled installs
 * the logger as the debug sink (debug diagnostics are forwarded); a NULL
 * logger keeps the legacy behaviour silent.
 */
int asn1f_fetch_tags_ex(asn1p_t *asn, struct asn1_namespace_s *ns,
    asn1p_module_t *mod, asn1p_expr_t *expr,
    struct asn1p_type_tag_s **tags_r, enum asn1f_aft_flags_e flags,
    asn1f_logger_f logger, int debug_enabled);

/*
 * Fetch the outmost tag of the given type.
 * Type1 ::= Type2
 * Type2 ::= [2] Type3
 * Type3 ::= SEQUENCE { ... }
 * Will yield [2] for Type1.
 */
int asn1f_fetch_outmost_tag(asn1p_t *asn, struct asn1_namespace_s *ns,
                            asn1p_module_t *mod, asn1p_expr_t *expr,
                            struct asn1p_type_tag_s *tag,
                            enum asn1f_aft_flags_e);

/*
 * Same as asn1f_fetch_outmost_tag(), but report diagnostics as above.
 */
int asn1f_fetch_outmost_tag_ex(asn1p_t *asn, struct asn1_namespace_s *ns,
    asn1p_module_t *mod, asn1p_expr_t *expr,
    struct asn1p_type_tag_s *tag, enum asn1f_aft_flags_e flags,
    asn1f_logger_f logger, int debug_enabled);

#endif	/* ASN1FIX_TAGS_H */
