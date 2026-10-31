#include "asn1fix_internal.h"
#include "asn1fix.h"
#include <limits.h>

/* Print everything to stderr */
static void _default_error_logger(int _severity, const char *fmt, ...);

/*
 * Internal check functions.
 */
static int asn1f_fix_module__phase_1(arg_t *arg);
static int oid_certainly_equal(const asn1p_oid_t *a, const asn1p_oid_t *b);
static int asn1f_fix_module__phase_2(arg_t *arg);
static int asn1f_fix_simple(arg_t *arg);	/* For INTEGER/ENUMERATED */
static int asn1f_fix_constructed(arg_t *arg);	/* For SEQUENCE/SET/CHOICE */
static int asn1f_resolve_constraints(arg_t *arg); /* For subtype constraints */
static int asn1f_check_constraints(arg_t *arg);	/* For subtype constraints */
static int asn1f_check_duplicate(arg_t *arg);
static int asn1f_apply_unique_index(arg_t *arg);
static int phase_1_1(arg_t *arg, int prm2);
static int asn1f_fix_late_containing(asn1p_t *asn, arg_t *arg);
static int asn1f_reject_late_containing(asn1p_t *asn, arg_t *arg);
static void asn1f_clear_phase1_marks(asn1p_t *asn);
static int asn1f_has_containing(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr);

/* Private state variable: this module declaration was promoted from contents. */
#define ASN1F_CONTAINING_ROOT (1u << 9)

static int asn1f_promote_containing_module(asn1p_t *asn,
                                          asn1p_module_t *mod, size_t *count);
static int asn1f_promote_containing_expr(asn1p_t *asn, asn1p_module_t *mod,
                                        asn1p_expr_t *expr, size_t *count);
static int asn1f_promote_containing_constraint(asn1p_t *asn,
                                              asn1p_module_t *mod,
                                              asn1p_constraint_t *constraint,
                                              size_t *count);
static int asn1f_promote_containing_node(asn1p_t *asn,
                                        asn1p_module_t *mod,
                                        asn1p_constraint_t *constraint,
                                        size_t *count);
static int asn1f_containing_name_exists(const asn1p_t *asn, const char *name);

/* state variable: unique inline CONTAINING declaration count for one fixer call. */
static size_t asn1f_containing_count;
/* state variable: whether the current traversal found a contents constraint. */
static int asn1f_containing_seen;
/* state variable: inspect constraint trees without modifying templates. */
static int asn1f_containing_scan_only;

arg_t a1f_replace_me_with_proper_interface_arg;

/*
 * Scan every module defined here in search for inconsistences.
 */
int
asn1f_process(asn1p_t *asn, enum asn1f_flags flags,
		error_logger_f error_logger) {
	arg_t arg;
	int fatals = 0;
	int warnings = 0;
	int ret;

	/*
	 * Check validity of arguments.
	 */
	if(asn == NULL) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * If errors handler is not specified, default to internal one.
	 */
	if(error_logger == 0) {
		error_logger = _default_error_logger;
	}

	memset(&arg, 0, sizeof(arg));
	arg.asn = asn;
	arg.eh = error_logger;

	if(flags & A1F_DEBUG) {
		arg.debug = arg.eh;
		arg.debug(-1, "Called %s() with flags %d", __func__, flags);
		flags &= ~A1F_DEBUG;
	}

	/* Allow SIZE() constraint for INTEGER and other types */
	if(flags & A1F_EXTENDED_SizeConstraint) {
		arg.flags |= A1F_EXTENDED_SizeConstraint;
		flags &= ~A1F_EXTENDED_SizeConstraint;
		if(arg.debug) {
			arg.debug(-1,
				"Extended SizeConstraint support enabled");
		}
	}

	if(flags & A1F_COMPOUND_NAMES) {
		arg.flags |= A1F_COMPOUND_NAMES;
		flags &= ~A1F_COMPOUND_NAMES;
		if(arg.debug) {
			arg.debug(-1,
				"Allow the same symbol name defined in two different modules");
		}
	}

	if(flags & A1F_PREFER_IMPORT_SOURCE) {
		arg.flags |= A1F_PREFER_IMPORT_SOURCE;
		flags &= ~A1F_PREFER_IMPORT_SOURCE;
		if(arg.debug) {
			arg.debug(-1,
				"IMPORTS resolution: require explicit xp_members match");
		}
	}

	a1f_replace_me_with_proper_interface_arg = arg;

	/*
	 * Check that we haven't missed an unknown flag.
	 */
	if(flags) {
		errno = EINVAL;
		return -1;
	}

	/* Give inline CONTAINING types their own descriptors before the fixer
	 * resolves references and computes codec-specific constraints. */
	asn1f_containing_count = 0;
	asn1f_containing_seen = 0;
	asn1f_containing_scan_only = 0;
	TQ_FOR(arg.mod, &(asn->modules), mod_next) {
		if(asn1f_promote_containing_module(asn, arg.mod,
		                                  &asn1f_containing_count)) return -1;
	}

    /*
     * Process each module in the list.
     * PHASE I.
     */
    TQ_FOR(arg.mod, &(asn->modules), mod_next) {
        arg.ns = asn1_namespace_new_from_module(arg.mod, 0);
        ret = asn1f_fix_module__phase_1(&arg);
        /*
         * These lines are used for illustration purposes.
         * RET2RVAL() is used everywhere else.
         */
        if(ret == -1) fatals++;
        if(ret == 1) warnings++;
        asn1_namespace_free(arg.ns);
        arg.ns = 0;
    }
    if((asn1f_containing_count || asn1f_containing_seen)
       && asn1f_fix_late_containing(asn, &arg)) fatals++;
    /*
     * Generated source files may contain definitions from several top-level
     * assignments, including parameterized specializations. Keep their inner
     * type indexes unique across the full ASN.1 input so generated C symbols
     * cannot collide when those assignments share an output file.
     */
    asn1f_apply_unique_index(0);
    /* PHASE II. */
    TQ_FOR(arg.mod, &(asn->modules), mod_next) {
        arg.ns = asn1_namespace_new_from_module(arg.mod, 0);
        ret = asn1f_fix_module__phase_2(&arg);
        if(ret == -1) fatals++;
        if(ret == 1) warnings++;
        asn1_namespace_free(arg.ns);
        arg.ns = 0;
    }
	if(asn1f_reject_late_containing(asn, &arg)) fatals++;
	/* Do not expose private phase state to later compiler operations. */
	asn1f_clear_phase1_marks(asn);

	a1f_replace_me_with_proper_interface_arg = (arg_t){
		.eh = arg.eh,
		.debug = arg.debug,
		.flags = arg.flags,
	};

	/*
	 * Compute a return value.
	 */
	return fatals?-1:warnings?1:0;
}

/*
 * Find and promote inline CONTAINING types in one module before fixing it.
 * Original source: ASN.1 contents-constraint AST and module member list.
 * Version/date: 2026-10-30. Inputs: asn is the full input, mod is the mutable
 * module, and count tracks names across modules.
 * Returns: zero on success or -1 for malformed/oversized input or allocation
 * failure. Exceptions: none. Author: asn1c maintainers.
 * History: added specialized descriptors for inline contained types.
 * Example: CONTAINING INTEGER (0..2) gains a generated named type.
 */
static int
asn1f_promote_containing_module(asn1p_t *asn, asn1p_module_t *mod,
                                 size_t *count) {
	asn1p_expr_t *expr;
	if(!asn || !mod || !count) return -1;
	TQ_FOR(expr, &mod->members, next) {
		/* Inspect templates without promoting their unbound formal parameters. */
		if(expr->lhs_params && expr->spec_index == -1) {
			int has_containing = asn1f_has_containing(asn, mod, expr);
			if(has_containing < 0) return -1;
			if(has_containing) asn1f_containing_seen = 1;
			continue;
		}
		if(asn1f_promote_containing_expr(asn, mod, expr, count)) return -1;
	}
	return 0;
}

/*
 * Inspect one type and its members for inline CONTAINING constraints.
 * Original source: fixer expression traversal. Version/date: 2026-10-30.
 * Inputs: asn is the full input, mod owns the type, expr is current, and
 * count caps new declarations. Returns zero or -1; no exceptions.
 * Author: asn1c maintainers. History: added pre-fix promotion traversal.
 * Example: inspect an OCTET STRING field inside a SEQUENCE.
 */
static int
asn1f_promote_containing_expr(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr,
	                            size_t *count) {
	asn1p_expr_t **pending;
	size_t used = 0;
	size_t capacity = 32;
	if(!asn || !mod || !expr || !count) return -1;
	pending = malloc(capacity * sizeof(*pending));
	if(!pending) return -1;
	pending[used++] = expr;
	while(used) {
		asn1p_expr_t *current = pending[--used];
		asn1p_expr_t *member;
		if(asn1f_promote_containing_constraint(asn, mod,
		                                     current->constraints, count)) {
			free(pending);
			return -1;
		}
		/* Parameter actuals are stored outside the ordinary member list. */
		if(current->rhs_pspecs) {
			if(used == capacity) {
				asn1p_expr_t **larger;
				if(capacity > (size_t)-1 / (2 * sizeof(*pending))) {
					free(pending);
					return -1;
				}
				capacity *= 2;
				larger = realloc(pending, capacity * sizeof(*pending));
				if(!larger) {
					free(pending);
					return -1;
				}
				pending = larger;
			}
			pending[used++] = current->rhs_pspecs;
		}
		TQ_FOR(member, &current->members, next) {
			if(used == capacity) {
				asn1p_expr_t **larger;
				if(capacity > (size_t)-1 / (2 * sizeof(*pending))) {
					free(pending);
					return -1;
				}
				capacity *= 2;
				larger = realloc(pending, capacity * sizeof(*pending));
				if(!larger) {
					free(pending);
					return -1;
				}
				pending = larger;
			}
			pending[used++] = member;
		}
	}
	free(pending);
	return 0;
}

/*
 * Scan a constraint tree iteratively for inline contents types.
 * Source: contents-constraint AST. Version/date: 2026-10-30.
 * Inputs: asn is the full input, mod owns declarations, constraint is the
 * root node, and count limits generated names. Returns zero or -1 on invalid
 * input/allocation failure; no exceptions. Author: asn1c maintainers.
 * History: avoids a new nesting limit on unrelated schemas.
 * Example: find CONTAINING inside a union of constraint elements.
 */
static int
asn1f_promote_containing_constraint(asn1p_t *asn, asn1p_module_t *mod,
                                    asn1p_constraint_t *constraint,
	                                    size_t *count) {
	asn1p_constraint_t **pending;
	size_t used = 0;
	size_t capacity = 32;
	if(!constraint) return 0;
	if(!asn || !mod || !count) return -1;
	pending = malloc(capacity * sizeof(*pending));
	if(!pending) return -1;
	pending[used++] = constraint;
	while(used) {
		asn1p_constraint_t *current = pending[--used];
		unsigned i;
		if(asn1f_promote_containing_node(asn, mod, current, count)) {
			free(pending);
			return -1;
		}
		for(i = current->el_count; i > 0; i--) {
			if(used == capacity) {
				asn1p_constraint_t **larger;
				if(capacity > (size_t)-1 / (2 * sizeof(*pending))) {
					free(pending);
					return -1;
				}
				capacity *= 2;
				larger = realloc(pending, capacity * sizeof(*pending));
				if(!larger) {
					free(pending);
					return -1;
				}
				pending = larger;
			}
			pending[used++] = current->elements[i - 1];
		}
	}
	free(pending);
	return 0;
}

/*
 * Promote one inline contents type and replace it with a named reference.
 * Original source: contents-constraint AST and module type registration.
 * Version/date: 2026-10-30. Inputs: asn is the full input, mod owns
 * declarations, constraint is one node, and count limits generated names.
 * Returns zero or -1 on invalid input/allocation failure; no exceptions.
 * Author: asn1c maintainers. History: added inline descriptor generation.
 * Example: CONTAINING SEQUENCE { x BOOLEAN } becomes a generated type.
 */
static int
asn1f_promote_containing_node(asn1p_t *asn, asn1p_module_t *mod,
                              asn1p_constraint_t *constraint, size_t *count) {
	if(!asn || !mod || !constraint || !count) return -1;
	if(constraint->type == ACT_CT_CTNG && constraint->value
	   && constraint->value->type == ATV_TYPE) {
		asn1p_expr_t *contained = constraint->value->value.v_type;
		asn1f_containing_seen = 1;
		if(!contained) return -1;
		if(asn1f_containing_scan_only) return 0;
		if(contained->expr_type != A1TC_REFERENCE || contained->constraints
		   || contained->rhs_pspecs) {
			asn1p_expr_t *reference = NULL;
			char name[64];
			char *identifier;
			do {
				if(++*count > 4096) return -1;
				if(snprintf(name, sizeof(name), "ASN1CContained%zu", *count)
				   < 0) return -1;
			} while(asn1f_containing_name_exists(asn, name));
			identifier = strdup(name);
			reference = asn1p_expr_new(contained->_lineno, mod);
			if(!identifier || !reference) {
				free(identifier);
				asn1p_expr_free(reference);
				return -1;
			}
			reference->meta_type = AMT_TYPE;
			reference->expr_type = A1TC_REFERENCE;
			reference->reference = asn1p_ref_new(contained->_lineno, mod);
			if(!reference->reference
			   || asn1p_ref_add_component(reference->reference, name, RLT_UNKNOWN)) {
				free(identifier);
				asn1p_expr_free(reference);
				return -1;
			}
			free(contained->Identifier);
			contained->Identifier = identifier;
			contained->module = mod;
			contained->_mark &= ~ASN1F_PHASE1_DONE;
			contained->_mark |= ASN1F_CONTAINING_ROOT;
			contained->_type_referenced = 1;
			/* Move the value's ownership of this type to the module list. */
			if(contained->ref_cnt) contained->ref_cnt--;
			constraint->value->value.v_type = reference;
			asn1p_module_member_add(mod, contained);
		}
	}
	return 0;
}

/*
 * Detect a contents constraint without changing its tree. Source: promotion
 * traversal. Version: 2026-10-30. Inputs: asn/mod/expr identify a type.
 * Returns one if present, zero if absent, -1 on failure; no exceptions.
 * Author: asn1c maintainers. History: restrict late work to contents types.
 * Example: an uninstantiated template can be inspected without promotion.
 */
static int
asn1f_has_containing(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr) {
	int previous_seen = asn1f_containing_seen;
	int result;
	asn1f_containing_seen = 0;
	asn1f_containing_scan_only = 1;
	result = asn1f_promote_containing_expr(asn, mod, expr, &asn1f_containing_count);
	asn1f_containing_scan_only = 0;
	if(!result) result = asn1f_containing_seen;
	asn1f_containing_seen = previous_seen;
	return result;
}

/*
 * Check generated-type name collisions across the entire ASN.1 input.
 * Original source: module declaration lists. Version/date: 2026-10-30.
 * Inputs: asn is the input tree, name is the candidate identifier.
 * Returns one for a collision and zero otherwise; no exceptions.
 * Author: asn1c maintainers. History: keep synthetic output files unique.
 * Example: a user-defined ASN1CContained1 forces the next candidate.
 */
static int
asn1f_containing_name_exists(const asn1p_t *asn, const char *name) {
	asn1p_module_t *mod;
	if(!asn || !name) return 1;
	TQ_FOR(mod, &asn->modules, mod_next) {
		asn1p_expr_t *expr;
		TQ_FOR(expr, &mod->members, next) {
			if(expr->Identifier && strcmp(expr->Identifier, name) == 0) return 1;
		}
	}
	return 0;
}

/*
 * Check the internals of a single module.
 */
static int
asn1f_fix_module__phase_1(arg_t *arg) {
	asn1p_expr_t *expr;
	int rvalue = 0;
	int ret;
	asn1p_module_t *omod;

	/*
	 * Check that we don't have a similarly named module.
	 */
	TQ_FOR(omod, &arg->asn->modules, mod_next) {
		int sameNames;
		if(omod == arg->mod) break;
		sameNames = strcmp(omod->ModuleName, arg->mod->ModuleName)?0:1;
		if(omod->module_oid && arg->mod->module_oid) {
			/* Compare only the OID. */
			if(asn1p_oid_compare(omod->module_oid,
					arg->mod->module_oid) == 0) {
				FATAL("ASN.1 module %s in %s "
					"has the same OBJECT IDENTIFIER"
					" as module %s",
					omod->ModuleName,
					omod->source_file_name,
					arg->mod->ModuleName
				);
				RET2RVAL(-1, rvalue);
			} else if(sameNames) {
				WARNING("ASN.1 module %s is defined more than once, with different OIDs", omod->ModuleName);
				RET2RVAL(1, rvalue);
			}
		} else if(sameNames) {
			FATAL("ASN.1 module %s is defined more than once",
				omod->ModuleName);
			RET2RVAL(-1, rvalue);
		}
	}

	/*
	 * X.680 (02/2021) 13.16 e): the module references in the IMPORTS
	 * clause shall be different from each other and from the importing
	 * module. The object identifiers, when present, shall also be
	 * different from each other and from the one of the importing module.
	 */
	{
		asn1p_xports_t *xp, *xp2;
		TQ_FOR(xp, &(arg->mod->imports), xp_next) {
			asn1p_expr_t *first = TQ_FIRST(&(xp->xp_members));
			int line = first ? first->_lineno : 0;
			if(strcmp(xp->fromModuleName, arg->mod->ModuleName) == 0
			|| oid_certainly_equal(xp->identifier.oid,
					arg->mod->module_oid)) {
				FATAL("IMPORTS of module %s name the module itself "
					"(%s) at line %d (X.680 13.16 e)",
					arg->mod->ModuleName, xp->fromModuleName, line);
				RET2RVAL(-1, rvalue);
			}
			for(xp2 = TQ_NEXT(xp, xp_next); xp2;
					xp2 = TQ_NEXT(xp2, xp_next)) {
				first = TQ_FIRST(&(xp2->xp_members));
				line = first ? first->_lineno : 0;
				if(strcmp(xp->fromModuleName, xp2->fromModuleName) == 0) {
					FATAL("IMPORTS of module %s name module %s more "
						"than once, at line %d (X.680 13.16 e)",
						arg->mod->ModuleName, xp2->fromModuleName, line);
					RET2RVAL(-1, rvalue);
				} else if(oid_certainly_equal(xp->identifier.oid,
						xp2->identifier.oid)) {
					FATAL("IMPORTS of module %s give modules %s and %s "
						"the same OBJECT IDENTIFIER, at line %d "
						"(X.680 13.16 e)",
						arg->mod->ModuleName, xp->fromModuleName,
						xp2->fromModuleName, line);
					RET2RVAL(-1, rvalue);
				}
			}
		}
	}

	switch((arg->mod->module_flags & MSF_MASK_TAGS)) {
	case MSF_NOFLAGS:
	case MSF_EXPLICIT_TAGS:
	case MSF_IMPLICIT_TAGS:
	case MSF_AUTOMATIC_TAGS:
		break;
	default:
		FATAL("Module %s defined with ambiguous global tagging mode",
			arg->mod->ModuleName);
		RET2RVAL(-1, rvalue);
	}

	switch((arg->mod->module_flags & MSF_MASK_INSTRUCTIONS)) {
	case MSF_NOFLAGS:
		/*
		 * arg->mod->module_flags |= MSF_TAG_INSTRUCTIONS;
		 */
		break;
	case MSF_unk_INSTRUCTIONS:
		WARNING("Module %s defined with unrecognized "
			"encoding reference", arg->mod->ModuleName);
		RET2RVAL(1, rvalue);
		/* Fall through */
	case MSF_TAG_INSTRUCTIONS:
	case MSF_XER_INSTRUCTIONS:
		break;
	default:
		FATAL("Module %s defined with ambiguous encoding reference",
			arg->mod->ModuleName);
		RET2RVAL(-1, rvalue);
	}

	/*
	 * Do various non-recursive transformations.
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		/* Skip encoding instructions */
		if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;
		
		arg->expr = expr;
		ret = phase_1_1(arg, 0);
		RET2RVAL(ret, rvalue);
		/*
		 * Make sure everybody's behaving well.
		 */
		assert(arg->expr == expr);
	}
	TQ_FOR(expr, &(arg->mod->members), next) {
		/* Skip encoding instructions */
		if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;
		
		arg->expr = expr;
		ret = phase_1_1(arg, 1);
		RET2RVAL(ret, rvalue);
		assert(arg->expr == expr);
	}



	/*
	 * 5. Automatic tagging
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		/* Skip encoding instructions */
		if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;

		arg->expr = expr;

		ret = asn1f_recurse_expr(arg, asn1f_fix_constr_autotag);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	/*
	 * 8. fix BIT STRING
	 * 9. fix spaces in cstrings
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		/* Skip encoding instructions */
		if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;
		
		arg->expr = expr;

		ret = asn1f_recurse_expr(arg, asn1f_fix_bit_string);
		RET2RVAL(ret, rvalue);

		ret = asn1f_recurse_expr(arg, asn1f_fix_cstring);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	/*
	 * ... Check for tags distinctness.
	 */
	TQ_FOR(expr, &(arg->mod->members), next) {
		/* Skip encoding instructions */
		if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;
		
		arg->expr = expr;

		ret = asn1f_recurse_expr(arg, asn1f_check_constr_tags_distinct);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	return rvalue;
}

static int
asn1f_fix_module__phase_2(arg_t *arg) {
	asn1p_expr_t *expr;
	int rvalue = 0;
	int ret;

	TQ_FOR(expr, &(arg->mod->members), next) {
		/* Skip encoding instructions */
		if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;

		arg->expr = expr;

		/*
		 * Dereference DEFAULT values.
		 */
		ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_defaults);
		RET2RVAL(ret, rvalue);

		/*
		 * Resolve references in constraints (the second pass).
		 */
		ret = asn1f_recurse_expr(arg, asn1f_resolve_constraints);
		RET2RVAL(ret, rvalue);

		/*
		 * Check semantic validity of constraints.
		 */
		ret = asn1f_recurse_expr(arg, asn1f_check_constraints);
		RET2RVAL(ret, rvalue);

		if (expr->ioc_table) {
			for (size_t rn = 0; rn < expr->ioc_table->rows; rn++) {
				for (size_t cn = 0; cn < expr->ioc_table->row[rn]->columns; cn++) {
					if (!expr->ioc_table->row[rn]->column[cn].value) {
						continue;
					}
					arg->expr = expr->ioc_table->row[rn]->column[cn].value;
					ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_defaults);
					RET2RVAL(ret, rvalue);

					ret = asn1f_recurse_expr(arg, asn1f_resolve_constraints);
					RET2RVAL(ret, rvalue);

					ret = asn1f_recurse_expr(arg, asn1f_check_constraints);
					RET2RVAL(ret, rvalue);
				}
			}
			arg->expr = expr;
		}

		/*
		 * Uniquely tag each inner type across all modules in this input.
		 */
		ret = asn1f_apply_unique_index(arg);
		RET2RVAL(ret, rvalue);

		assert(arg->expr == expr);
	}

	return rvalue;
}

static int
phase_1_1(arg_t *arg, int prm2) {
	asn1p_expr_t *expr = arg->expr;
	int rvalue = 0;
	int ret;

	if(expr->lhs_params && expr->spec_index == -1) {
		int i;
		if(!prm2)
			/* Do not process the parameterized type just yet */
			return 0;
		for(i = 0; i < expr->specializations.pspecs_count; i++) {
			arg->expr = expr->specializations.pspec[i].my_clone;
			ret = phase_1_1(arg, 0);
			RET2RVAL(ret, rvalue);
		}
		arg->expr = expr;	/* revert */
		return rvalue;
	} else if(prm2) {
		return 0;	/* Already done! */
	}
	if(expr->_mark & ASN1F_PHASE1_DONE) return 0;
	expr->_mark |= ASN1F_PHASE1_DONE;

	/* Process contained types cloned by specialization and any new declarations. */
	if(asn1f_promote_containing_expr(arg->asn, arg->mod, expr,
	                                &asn1f_containing_count)) return -1;

	/* Check whether this type is a duplicate */
	if(!expr->lhs_params) {
		ret = asn1f_check_duplicate(arg);
		RET2RVAL(ret, rvalue);
	}

	DEBUG("=== Now processing \"%s\" (%d/0x%x) at line %d ===",
		expr->Identifier, expr->meta_type, expr->expr_type,
		expr->_lineno);
	assert(expr->meta_type != AMT_INVALID);

	/*
	 * 2.1 Pre-process simple types (ENUMERATED, INTEGER, etc).
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_simple);
	RET2RVAL(ret, rvalue);

	/*
	 * 2.5.4
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_types);
	RET2RVAL(ret, rvalue);

	/*
	 * Fix tagging of top-level types.
	 */
	ret = asn1f_fix_constr_tag(arg, 1);
	RET2RVAL(ret, rvalue);

	/*
	 * 2.[234] Process SEQUENCE/SET/CHOICE types.
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_constructed);
	RET2RVAL(ret, rvalue);

	/*
	 * 2.5.5
	 */
	ret = asn1f_recurse_expr(arg, asn1f_fix_dereference_values);
	RET2RVAL(ret, rvalue);

	/*
	 * Resolve references in constraints.
	 */
	ret = asn1f_recurse_expr(arg, asn1f_resolve_constraints);
	RET2RVAL(ret, rvalue);

	/*
	 * Parse class information object sets.
	 */
	ret = asn1f_parse_class_object(arg);
	RET2RVAL(ret, rvalue);

	/*
	 * 6. INTEGER value processed at 2.5.4.
	 */

	return rvalue;
}

/*
 * Complete phase I for roots and specializations discovered after their module
 * was visited. Source: the normal module phase-I passes. Version: 2026-10-30.
 * Inputs: asn owns modules; arg provides diagnostics. Returns zero or -1.
 * Errors: fixer failures propagate; no exceptions. Author: asn1c maintainers.
 * History: process late cross-module specializations exactly once.
 * Example: an imported template can be specialized in a later module.
 */
static int
asn1f_fix_late_containing(asn1p_t *asn, arg_t *arg) {
	int progress, failed = 0;
	do {
		asn1p_module_t *mod;
		progress = 0;
		TQ_FOR(mod, &asn->modules, mod_next) {
			asn1p_expr_t *expr;
			arg->mod = mod;
			arg->ns = asn1_namespace_new_from_module(mod, 0);
			if(!arg->ns) return -1;
			TQ_FOR(expr, &mod->members, next) {
				int i, count = expr->lhs_params && expr->spec_index == -1
					? expr->specializations.pspecs_count : 1;
				if(expr->_mark & TM_ENCODING_INSTRUCTION) continue;
				for(i = 0; i < count; i++) {
					asn1p_expr_t *root = expr->lhs_params && expr->spec_index == -1
						? expr->specializations.pspec[i].my_clone : expr;
					int relevant;
					if(root->_mark & ASN1F_PHASE1_DONE) continue;
					relevant = (root->_mark & ASN1F_CONTAINING_ROOT) != 0;
					if(!relevant && root->spec_index >= 0)
						relevant = asn1f_has_containing(asn, mod, root);
					if(relevant < 0) { failed = 1; continue; }
					if(!relevant) continue;
					progress = 1;
					arg->expr = root;
					if(phase_1_1(arg, 0) < 0
					|| asn1f_recurse_expr(arg, asn1f_fix_constr_autotag) < 0
					|| asn1f_recurse_expr(arg, asn1f_fix_bit_string) < 0
					|| asn1f_recurse_expr(arg, asn1f_fix_cstring) < 0
					|| asn1f_recurse_expr(arg, asn1f_check_constr_tags_distinct) < 0)
						failed = 1;
				}
			}
			asn1_namespace_free(arg->ns);
			arg->ns = 0;
		}
	} while(progress);
	return failed ? -1 : 0;
}

/*
 * Clear temporary root processing marks after fixing. Source: phase-I worklist.
 * Version: 2026-10-30. Input: asn owns modules. Returns nothing; no exceptions.
 * Author: asn1c maintainers. History: keep fixer state private to one call.
 * Example: a later fixer call does not inherit a completed-work marker.
 */
static void
asn1f_clear_phase1_marks(asn1p_t *asn) {
	asn1p_module_t *mod;
	TQ_FOR(mod, &asn->modules, mod_next) {
		asn1p_expr_t *expr;
		TQ_FOR(expr, &mod->members, next) {
			int i;
			expr->_mark &= ~(ASN1F_PHASE1_DONE | ASN1F_CONTAINING_ROOT);
			for(i = 0; i < expr->specializations.pspecs_count; i++)
				expr->specializations.pspec[i].my_clone->_mark &= ~ASN1F_PHASE1_DONE;
		}
	}
}

/*
 * Reject contents-bearing specializations created too late for phase I.
 * Source: phase-II specialization audit. Version: 2026-10-30.
 * Inputs: asn owns the modules, arg provides diagnostics. Returns zero or -1.
 * Errors: unsupported late specialization or allocation failure; no exceptions.
 * Author: asn1c maintainers. History: prevent silently omitted constraints.
 * Example: a late constraint specialization fails before code generation.
 */
static int
asn1f_reject_late_containing(asn1p_t *asn, arg_t *arg) {
	asn1p_module_t *mod;
	TQ_FOR(mod, &asn->modules, mod_next) {
		asn1p_expr_t *expr;
		arg->mod = mod;
		TQ_FOR(expr, &mod->members, next) {
			int i;
			for(i = 0; i < expr->specializations.pspecs_count; i++) {
				asn1p_expr_t *clone = expr->specializations.pspec[i].my_clone;
				if(clone->_mark & ASN1F_PHASE1_DONE) continue;
				asn1f_containing_seen = 0;
				if(asn1f_promote_containing_expr(asn, mod, clone,
				                                 &asn1f_containing_count)) return -1;
				if(asn1f_containing_seen) {
					FATAL("CONTAINING specialization of %s was created after phase I",
					      expr->Identifier ? expr->Identifier : "anonymous type");
					return -1;
				}
			}
		}
	}
	return 0;
}

static int
asn1f_fix_simple(arg_t *arg) {
	int rvalue = 0;
	int ret;

	ret = asn1f_fix_enum(arg);
	RET2RVAL(ret, rvalue);

	ret = asn1f_fix_integer(arg);
	RET2RVAL(ret, rvalue);

	return rvalue;
}

static int
asn1f_fix_constructed(arg_t *arg) {
	int rvalue = 0;
	int ret;

	switch(arg->expr->expr_type) {
	case ASN_CONSTR_SEQUENCE_OF:
	case ASN_CONSTR_SET_OF:
		return asn1f_fix_constr_tag(arg, 0);
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
	case ASN_CONSTR_CHOICE:
		break;
	default:
		return 0;
	}

	/* Check identifier distinctness */
	ret = asn1f_check_unique_expr(arg);
	RET2RVAL(ret, rvalue);

	/* Fix extensibility */
	ret = asn1f_fix_constr_ext(arg);
	RET2RVAL(ret, rvalue);

	/* Fix tagging */
	ret = asn1f_fix_constr_tag(arg, 0);
	RET2RVAL(ret, rvalue);

	/* Import COMPONENTS OF stuff */
	ret = asn1f_pull_components_of(arg);
	RET2RVAL(ret, rvalue);

	return rvalue;
}

static int
asn1f_resolve_constraints(arg_t *arg) {
	asn1p_expr_t *top_parent;
	asn1p_expr_type_e etype;
	int rvalue = 0;
	int ret;

	top_parent = asn1f_find_terminal_type(arg, arg->expr);
	if(top_parent)
		etype = top_parent->expr_type;
	else	etype = A1TC_INVALID;

	DEBUG("(%s)", arg->expr->Identifier);

    ret = asn1constraint_resolve(arg, arg->expr->constraints, etype, 0);
    RET2RVAL(ret, rvalue);

	return rvalue;
}

static int
asn1f_check_constraints(arg_t *arg) {
	static enum asn1p_constraint_type_e test_types[] = {
		ACT_EL_RANGE, ACT_CT_SIZE, ACT_CT_FROM };
	asn1p_expr_t *top_parent;
	asn1cnst_range_t *range;
	asn1p_expr_type_e etype;
	unsigned int i;
	int rvalue = 0;
	int ret;

	DEBUG("(%s{%d/%d})",
		arg->expr->Identifier,
		arg->expr->meta_type, arg->expr->expr_type);

	top_parent = asn1f_find_terminal_type(arg, arg->expr);
	if(!top_parent)
		return 0;
	etype = top_parent->expr_type;

	ret = asn1constraint_pullup(arg);
	RET2RVAL(ret, rvalue);

	for(i = 0; i < sizeof(test_types)/sizeof(test_types[0]); i++) {
		range = asn1constraint_compute_constraint_range(
				arg->expr->Identifier,
				etype,
				arg->expr->combined_constraints,
				test_types[i], 0, 0,
				CPR_noflags /* ignore -fbless-SIZE */);
		if(!range && errno == EPERM) {
			FATAL("This error happened for \"%s\" (meta %d) "
				"at line %d",
				arg->expr->Identifier,
				arg->expr->meta_type,
				arg->expr->_lineno);
			return -1;
		}
		asn1constraint_range_free(range);
	}

	return rvalue;
}

static int
asn1f_check_duplicate(arg_t *arg) {
	arg_t tmparg = *arg;
	int rvalue = 0;

	/*
	 * This is a linear scan in search of a similar type.
	 * The linear scan is just fine for the task, no need to over-optimize.
	 */
	TQ_FOR(tmparg.mod, &arg->asn->modules, mod_next) {
		int critical = 1;	/* FATAL */

		if((arg->mod->_tags & MT_STANDARD_MODULE)
		!= (tmparg.mod->_tags & MT_STANDARD_MODULE)) {
			/* Ignore clashes with standard module */
			critical = 0;	/* WARNING */
		}

		TQ_FOR(tmparg.expr, &(tmparg.mod->members), next) {
			int diff_files;	/* different files */

			assert(tmparg.expr->Identifier);
			assert(arg->expr->Identifier);

			if(arg->expr->spec_index != -1)
				continue;
			
			/* Skip encoding instructions - they're not real types */
			if(arg->expr->_mark & TM_ENCODING_INSTRUCTION)
				continue;
			if(tmparg.expr->_mark & TM_ENCODING_INSTRUCTION)
				continue;

			if(tmparg.expr == arg->expr) break;

			if(strcmp(tmparg.expr->Identifier,
				  arg->expr->Identifier))
				continue;

			/* resolve clash of Identifier in different modules */
			int oid_exist = (tmparg.expr->module->module_oid && arg->expr->module->module_oid);
			if ((arg->flags & A1F_COMPOUND_NAMES) &&
				((!oid_exist && strcmp(tmparg.expr->module->ModuleName, arg->expr->module->ModuleName)) ||
				 (oid_exist && asn1p_oid_compare(tmparg.expr->module->module_oid, arg->expr->module->module_oid)))) {

				tmparg.expr->_mark |= TM_NAMECLASH;
				arg->expr->_mark |= TM_NAMECLASH;
				continue;
			}

			diff_files = strcmp(arg->mod->source_file_name,
					tmparg.mod->source_file_name) ? 1 : 0;

			LOG(critical,
			"ASN.1 expression \"%s\" at line %d of module %s\n"
			"clashes with expression \"%s\" at line %d of module %s"
			"%s%s%s.\n"
			"Rename or remove either instance "
				"to resolve the conflict",
				arg->expr->Identifier,
				arg->expr->_lineno,
				arg->mod->ModuleName,
				tmparg.expr->Identifier,
				tmparg.expr->_lineno,
				tmparg.mod->ModuleName,
				diff_files ? " (" : "",
				diff_files ? tmparg.mod->source_file_name : "",
				diff_files ? ")" : "");
			if(critical)
				return -1;
			RET2RVAL(1, rvalue);
		}
		if(tmparg.mod == arg->mod) break;
	}

	return rvalue;
}

/*
 * Purpose: Assign unique suffixes throughout expression and object-set trees.
 * Original source: ASN.1 fixer, phase-II inner-type indexing.
 * Version/date: 2026-10-23.
 * Parameters: arg is the current expression, or NULL to reset the counter.
 * Returns: Zero on success; -1 if a specialization is missing or indexes overflow.
 * Exceptions: Does not throw exceptions; sets errno on invalid state or overflow.
 * Responsible party: asn1c maintainers.
 * History: Assign indexes across one ASN.1 input and include nested object-set
 *   cell expressions so generated specializations cannot reuse symbol suffixes.
 * Example: asn1f_apply_unique_index(NULL) resets before phase II; then pass
 *   each module expression to assign indexes to its members and object-set cells.
 */
static int
asn1f_apply_unique_index(arg_t *arg) {
	static int unique_index; /* state variable: next per-input type suffix. */
	asn1p_expr_t *expr;
	asn1p_expr_t *member;
	int rvalue = 0;
	if(!arg) { unique_index = 0; return 0; }

	expr = arg->expr;
	if(!expr) { errno = EINVAL; return -1; }

	/* Use a temporary mark because class parsing may leave local indexes here. */
	if(expr->_mark & TM_UNIQUE_INDEX) return 0;
	expr->_mark |= TM_UNIQUE_INDEX;

	/* Parameter templates index each active specialization, not the template. */
	if(expr->lhs_params && expr->spec_index == -1) {
		for(int i = 0; i < expr->specializations.pspecs_count; i++) {
			arg->expr = expr->specializations.pspec[i].my_clone;
			if(!arg->expr) {
				RET2RVAL(-1, rvalue);
				continue;
			}
			RET2RVAL(asn1f_apply_unique_index(arg), rvalue);
		}
		arg->expr = expr;
		expr->_mark &= ~TM_UNIQUE_INDEX;
		return rvalue;
	}

	if(unique_index == INT_MAX) {
		errno = EOVERFLOW;
		expr->_mark &= ~TM_UNIQUE_INDEX;
		return -1;
	}
	expr->_type_unique_index = ++unique_index;

	TQ_FOR(member, &expr->members, next) {
		arg->expr = member;
		RET2RVAL(asn1f_apply_unique_index(arg), rvalue);
	}

	/* Table-cell values are expressions, but are not linked through members. */
	if(expr->ioc_table) {
		for(size_t rn = 0; rn < expr->ioc_table->rows; rn++) {
			asn1p_ioc_row_t *row = expr->ioc_table->row[rn];
			if(!row || (row->columns && !row->column)) {
				errno = EINVAL;
				RET2RVAL(-1, rvalue);
				continue;
			}
			for(size_t cn = 0; cn < row->columns; cn++) {
				asn1p_expr_t *value = row->column[cn].value;
				if(!value) continue;
				arg->expr = value;
				RET2RVAL(asn1f_apply_unique_index(arg), rvalue);
			}
		}
	}

	arg->expr = expr;
	expr->_mark &= ~TM_UNIQUE_INDEX;

	return rvalue;
}

/*
 * Return 1 if the two OIDs certainly denote the same object identifier,
 * 0 if they differ or cannot be compared.
 * Two arcs match when both have a number and the numbers are equal
 * (NumberForm or NameAndNumberForm), or when both are in NameForm
 * (number -1) and the names are equal. An arc in NameForm against an
 * arc with a number is not resolved here, so such OIDs are not
 * reported as equal. asn1p_oid_compare() is not used: it compares arc
 * numbers only, so it takes any two NameForm arcs for equal.
 */
static int
oid_certainly_equal(const asn1p_oid_t *a, const asn1p_oid_t *b) {
	if(a == NULL || b == NULL) return 0;
	if(a->arcs_count == 0 || a->arcs_count != b->arcs_count) return 0;
	for(int i = 0; i < a->arcs_count; i++) {
		const asn1p_oid_arc_t *aa = &a->arcs[i];
		const asn1p_oid_arc_t *ba = &b->arcs[i];
		if(aa->number >= 0 && ba->number >= 0) {
			if(aa->number != ba->number) return 0;
		} else if(aa->number < 0 && ba->number < 0
		       && aa->name && ba->name) {
			if(strcmp(aa->name, ba->name) != 0) return 0;
		} else {
			return 0;	/* Name against number: unresolved */
		}
	}
	return 1;
}

/*
 * Print everything to stderr
 */
static void
_default_error_logger(int _severity, const char *fmt, ...) {
	va_list ap;
	char *pfx = "";

	switch(_severity) {
	case -1: pfx = "DEBUG: "; break;
	case 0: pfx = "WARNING: "; break;
	case 1: pfx = "FATAL: "; break;
	}
	
	fprintf(stderr, "%s", pfx);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
