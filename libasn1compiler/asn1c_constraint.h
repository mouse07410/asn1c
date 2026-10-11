#ifndef	ASN1C_CONSTRAINT_H
#define	ASN1C_CONSTRAINT_H

int asn1c_emit_constraint_checking_code(arg_t *arg);

/*
 * Return the type T of a "BIT STRING (CONTAINING T)" constraint of the
 * expression (X.682, clause 11), or NULL if there is no such constraint.
 */
asn1p_expr_t *asn1c_find_contents_type(arg_t *arg, asn1p_expr_t *expr);

#endif	/* ASN1C_CONSTRAINT_H */
