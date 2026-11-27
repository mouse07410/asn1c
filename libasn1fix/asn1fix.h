/*
 * This is the public interface for the processor (fixer) of the ASN.1 tree
 * produced by the libasn1parser.
 */
#ifndef	ASN1FIX_H
#define	ASN1FIX_H

#include <asn1parser.h>

/*
 * Operation flags for the function below.
 */
enum asn1f_flags {
	A1F_NOFLAGS,
	A1F_DEBUG			= 0x01,	/* Print debugging output */
	A1F_EXTENDED_SizeConstraint	= 0x02,	/* Enable constraint gen code */
	A1F_COMPOUND_NAMES		= 0x04,	/* A1C_COMPOUND_NAMES  */
	A1F_PREFER_IMPORT_SOURCE	= 0x08	/* IMPORTS resolution: require explicit name in xp_members,
					   skip whole-module fallback */
};

/*
 * Perform a set of semantics checks, transformations and small fixes
 * on the given tree.
 * RETURN VALUES:
 * 	-1:	Some fatal problems were encountered.
 *	 0:	No inconsistencies were found.
 *	 1:	Some warnings were issued, but no fatal problems encountered.
 */
int asn1f_process(asn1p_t *_asn,
	enum asn1f_flags,
	void (*error_log_callback)(int _severity, const char *fmt, ...));

/*
 * Same as asn1f_process(), but report every diagnostic through the callback
 * instead of printing.  A record carries the module file and the expression
 * line the fixer knows; column is 0 and token is NULL.  The callback, its key
 * and the message pointer are only valid during the call: the structured
 * channel is cleared before asn1f_process_diag() returns, so a lookup the
 * caller makes afterwards cannot reach it.
 */
int asn1f_process_diag(asn1p_t *_asn,
	enum asn1f_flags,
	asn1c_diag_cb cb, void *key);


/*
 * Explicitly mark type as known.
 */
int asn1f_make_known_external_type(const char *);

#endif	/* ASN1FIX_H */
