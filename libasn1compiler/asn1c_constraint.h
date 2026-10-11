#ifndef	ASN1C_CONSTRAINT_H
#define	ASN1C_CONSTRAINT_H

int asn1c_emit_constraint_checking_code(arg_t *arg);
asn1p_expr_t *asn1c_find_contained_type(arg_t *arg, asn1p_expr_t *expr);

#endif	/* ASN1C_CONSTRAINT_H */
