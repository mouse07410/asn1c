/*
 * This header exports fixer procedures that are common enough to be used
 * in other modules.
 */
#ifndef	ASN1FIX_EXPORT_H
#define	ASN1FIX_EXPORT_H

#include "asn1fix_tags.h"

struct asn1_namespace_s;   /* Forward declaration. */

void asn1f_use_standard_namespaces(asn1p_t *asn);

/*
 * Look up a module in a valid parsed tree. asn and module_name must be
 * non-NULL. If oid is NULL, module_name selects the module by name; otherwise
 * oid selects it and module_name is not used for matching.
 * Returns a borrowed module pointer, or NULL with errno set to ENOENT when
 * no module matches. The returned pointer remains owned by the parsed tree.
 */
asn1p_module_t *asn1f_lookup_module_ex(asn1p_t *asn, const char *module_name,
                                       const asn1p_oid_t *oid);

/*
 * Create a human-readable representation of a reference and value.
 */
char const *asn1f_printable_reference(const asn1p_ref_t *ref);
char const *asn1f_printable_value(asn1p_value_t *value);

/*
 * Control the diagnostics of the lookup functions in this interface.
 * With quiet != 0, they report no WARNING and no FATAL diagnostic.
 * Use this for a speculative lookup whose failure the caller handles,
 * for example a lookup of a parameterized type without its actual
 * parameters. Returns the previous setting.
 */
int asn1f_quiet_lookups(int quiet);

/*
 *  Exportable version of an asn1f_lookup_symbol().
 */
asn1p_expr_t *asn1f_lookup_symbol_ex(
		asn1p_t *asn,
		struct asn1_namespace_s *ns,
		asn1p_expr_t *expr,
		asn1p_ref_t *ref);

/*
 *  Exportable version of an asn1f_class_access().
 */
asn1p_expr_t *asn1f_class_access_ex(asn1p_t *asn, asn1p_module_t *mod,
                                    struct asn1_namespace_s *ns,
                                    asn1p_expr_t *expr,
                                    asn1p_expr_t *rhs_rspecs,
                                    const asn1p_ref_t *);

/*
 * Exportable version of asn1f_find_terminal_type().
 */
asn1p_expr_t *asn1f_find_terminal_type_ex(asn1p_t *asn,
                                          struct asn1_namespace_s *ns,
                                          asn1p_expr_t *tc);

/*
 * Exportable version of asn1f_fix_dereference_values();
 */
int asn1f_fix_dereference_values_ex(asn1p_t *asn, asn1p_module_t *mod,
	asn1p_expr_t *expr);

/*
 * Exportable version of asn1f_find_ancestor_type_with_PER_constraint().
 */
asn1p_expr_t *asn1f_find_ancestor_type_with_PER_constraint_ex(asn1p_t *asn,
	asn1p_expr_t *expr);

#endif	/* ASN1FIX_EXPORT_H */
