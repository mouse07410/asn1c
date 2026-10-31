#include "asn1fix_internal.h"

typedef struct resolver_arg {
	asn1p_expr_t	  *(*resolver)(asn1p_expr_t *, void *arg);
	arg_t		  *arg;
	asn1p_expr_t	  *original_expr;
	asn1p_paramlist_t *lhs_params;
	asn1p_expr_t	  *rhs_pspecs;
	char		  *resolved_name;
	asn1p_expr_t	 **containing_pending;
	size_t		   containing_used;
	size_t		   containing_capacity;
} resolver_arg_t;

static asn1p_expr_t *resolve_expr(asn1p_expr_t *, void *resolver_arg);
static int compare_specializations(const asn1p_expr_t *a, const asn1p_expr_t *b);
static asn1p_expr_t *find_target_specialization_byvalueset(resolver_arg_t *rarg, asn1p_constraint_t *ct);
static asn1p_expr_t *find_target_specialization_byref(resolver_arg_t *rarg, asn1p_ref_t *ref);
static asn1p_expr_t *find_target_specialization_bystr(resolver_arg_t *rarg, char *str);
static int resolve_containing_exprs(asn1p_expr_t *root, resolver_arg_t *rarg);
static int resolve_containing_constraints(asn1p_constraint_t *root,
		resolver_arg_t *rarg);
static int enqueue_containing_expr(resolver_arg_t *rarg, asn1p_expr_t *expr);

asn1p_expr_t *
asn1f_parameterization_fork(arg_t *arg, asn1p_expr_t *expr, asn1p_expr_t *rhs_pspecs) {
	resolver_arg_t rarg;	/* resolver argument */
	asn1p_expr_t *exc;	/* expr clone */
	asn1p_expr_t *rpc;	/* rhs_pspecs clone */
	asn1p_expr_t *m;	/* expr members */
	asn1p_expr_t *target;
	void *p;
	struct asn1p_pspec_s *pspec;
	int npspecs;

	assert(rhs_pspecs);
	assert(expr->lhs_params);
	assert(expr->parent_expr == 0);

	/*
	 * Find if this exact specialization has been used already.
	 */
	for(npspecs = 0;
		npspecs < expr->specializations.pspecs_count;
			npspecs++) {
		if(compare_specializations(rhs_pspecs,
			expr->specializations.pspec[npspecs].rhs_pspecs) == 0) {
			DEBUG("Reused parameterization for %s",
				expr->Identifier);
			return expr->specializations.pspec[npspecs].my_clone;
		}
	}

	DEBUG("Forking parameterization at %d for %s (%d alr)",
		rhs_pspecs->_lineno, expr->Identifier,
		expr->specializations.pspecs_count);

	rarg.resolver = resolve_expr;
	rarg.arg = arg;
	rarg.original_expr = expr;
	rarg.lhs_params = expr->lhs_params;
	rarg.rhs_pspecs = rhs_pspecs;
	rarg.resolved_name = NULL;
	rarg.containing_pending = NULL;
	rarg.containing_used = 0;
	rarg.containing_capacity = 0;
	exc = asn1p_expr_clone_with_resolver(expr, resolve_expr, &rarg);
	if(!exc) return NULL;
	/* Clones require their own phase-I work even if the source was processed. */
	exc->_mark &= ~ASN1F_PHASE1_DONE;
	if(rarg.resolved_name) {
		free(exc->Identifier);
		exc->Identifier = rarg.resolved_name;
		exc->_lineno = 0;
	}
	rarg.resolved_name = NULL;
	if(resolve_containing_exprs(exc, &rarg)) {
		free(rarg.resolved_name);
		asn1p_expr_free(exc);
		return NULL;
	}
	free(rarg.resolved_name);
	rarg.resolved_name = NULL;
	rpc = asn1p_expr_clone(rhs_pspecs, 0);
	assert(rpc);

	/*
	 * Create a new specialization.
	 */
	npspecs = expr->specializations.pspecs_count;
	p = realloc(expr->specializations.pspec,
			(npspecs + 1) * sizeof(expr->specializations.pspec[0]));
	assert(p);
	expr->specializations.pspec = p;
	pspec = &expr->specializations.pspec[npspecs];
	memset(pspec, 0, sizeof *pspec);

	pspec->rhs_pspecs = rpc;
	pspec->my_clone = exc;
	exc->spec_index = npspecs;
	exc->rhs_pspecs = asn1p_expr_clone_with_resolver(expr->rhs_pspecs ?
					expr->rhs_pspecs : rhs_pspecs,
					resolve_expr, &rarg);

	/* Passing arguments to members and type references */

	target = TQ_FIRST(&expr->members);
	TQ_FOR(m, &exc->members, next) {
		m->rhs_pspecs = asn1p_expr_clone_with_resolver(target->rhs_pspecs ?
						target->rhs_pspecs : exc->rhs_pspecs,
						resolve_expr, &rarg);
		target = TQ_NEXT(target, next);
	}

	DEBUG("Forked new parameterization for %s", expr->Identifier);

	/* Commit */
	expr->specializations.pspecs_count = npspecs + 1;
	return exc;
}

/*
 * Purpose: substitute formal types inside cloned CONTAINING constraints.
 * Source: parameterized expression resolver. Version/date: 2026-10-30.
 * Inputs: root is a cloned constraint and rarg identifies actual parameters.
 * Returns zero on success or -1 on malformed input/allocation failure; no exceptions.
 * Author: asn1c maintainers. History: added parameterized contents support.
 * Example: CONTAINING SEQUENCE { x T } binds T to an actual INTEGER type.
 */
static int
resolve_containing_constraints(asn1p_constraint_t *root, resolver_arg_t *rarg) {
	asn1p_constraint_t **pending;
	size_t used = 0, capacity = 32;
	if(!root) return 0;
	if(!rarg) return -1;
	pending = malloc(capacity * sizeof(*pending));
	if(!pending) return -1;
	pending[used++] = root;
	while(used) {
		asn1p_constraint_t *current = pending[--used];
		unsigned i;
		if(current->type == ACT_CT_CTNG && current->value
		   && current->value->type == ATV_TYPE) {
			asn1p_expr_t *source = current->value->value.v_type;
			asn1p_expr_t *copy;
			asn1p_value_t *replacement;
			if(!source) { free(pending); return -1; }
			copy = asn1p_expr_clone_with_resolver(source, resolve_expr, rarg);
			if(!copy) { free(pending); return -1; }
			replacement = asn1p_value_fromtype(copy);
			if(!replacement) {
				asn1p_expr_free(copy);
				free(pending);
				return -1;
			}
			/* The cloned expression has no separate owner outside this value. */
			copy->ref_cnt--;
			asn1p_value_free(current->value);
			current->value = replacement;
			if(enqueue_containing_expr(rarg, copy)) {
				free(pending);
				return -1;
			}
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
				if(!larger) { free(pending); return -1; }
				pending = larger;
			}
			pending[used++] = current->elements[i - 1];
		}
	}
	free(pending);
	return 0;
}

/*
 * Purpose: queue a contained expression without recursion or fixed depth.
 * Source: specialization contents traversal. Version/date: 2026-10-30.
 * Inputs: rarg owns the worklist and expr is the next cloned type.
 * Returns zero or -1 on invalid input/allocation failure; no exceptions.
 * Author: asn1c maintainers. History: supports nested CONTAINING values.
 * Example: queue a SEQUENCE inside an OCTET STRING contents constraint.
 */
static int
enqueue_containing_expr(resolver_arg_t *rarg, asn1p_expr_t *expr) {
	if(!rarg || !expr) return -1;
	if(rarg->containing_used == rarg->containing_capacity) {
		asn1p_expr_t **larger;
		size_t capacity = rarg->containing_capacity ? rarg->containing_capacity : 32;
		if(rarg->containing_capacity) {
			if(capacity > (size_t)-1 / (2 * sizeof(*larger))) return -1;
			capacity *= 2;
		}
		larger = realloc(rarg->containing_pending, capacity * sizeof(*larger));
		if(!larger) return -1;
		rarg->containing_pending = larger;
		rarg->containing_capacity = capacity;
	}
	rarg->containing_pending[rarg->containing_used++] = expr;
	return 0;
}

/*
 * Purpose: visit a specialization's members and bind contained formal types.
 * Source: parameterized expression clone tree. Version/date: 2026-10-30.
 * Inputs: root is the cloned specialization and rarg supplies parameter values.
 * Returns zero on success or -1 on malformed input/allocation failure; no exceptions.
 * Author: asn1c maintainers. History: added contained-type substitution.
 * Example: a parameterized OCTET STRING can contain a SEQUENCE using T.
 */
static int
resolve_containing_exprs(asn1p_expr_t *root, resolver_arg_t *rarg) {
	if(!root || !rarg) return -1;
	if(enqueue_containing_expr(rarg, root)) return -1;
	while(rarg->containing_used) {
		asn1p_expr_t *current = rarg->containing_pending[--rarg->containing_used];
		asn1p_expr_t *member;
		if(resolve_containing_constraints(current->constraints, rarg)) {
			free(rarg->containing_pending);
			rarg->containing_pending = NULL;
			return -1;
		}
		TQ_FOR(member, &current->members, next) {
			if(enqueue_containing_expr(rarg, member)) {
				free(rarg->containing_pending);
				rarg->containing_pending = NULL;
				return -1;
			}
		}
	}
	free(rarg->containing_pending);
	rarg->containing_pending = NULL;
	rarg->containing_capacity = 0;
	return 0;
}

static int
compare_specializations(const asn1p_expr_t *a, const asn1p_expr_t *b) {
    return asn1p_expr_compare(a, b);
}

static asn1p_expr_t *
resolve_expr(asn1p_expr_t *expr_to_resolve, void *resolver_arg) {
	resolver_arg_t *rarg = resolver_arg;
	arg_t *arg = rarg->arg;
	asn1p_expr_t *expr;
	asn1p_expr_t *nex;

	DEBUG("Resolving %s (meta %d)",
		expr_to_resolve->Identifier, expr_to_resolve->meta_type);

	if(expr_to_resolve->meta_type == AMT_TYPEREF) {
		expr = find_target_specialization_byref(rarg,
				expr_to_resolve->reference);
		if(!expr) return NULL;
	} else if(expr_to_resolve->meta_type == AMT_VALUE) {
		if(!expr_to_resolve->value) return NULL;
		expr = find_target_specialization_bystr(rarg,
				expr_to_resolve->Identifier);
		if(!expr) return NULL;
	} else if(expr_to_resolve->meta_type == AMT_VALUESET) {
		assert(expr_to_resolve->constraints);
		expr = find_target_specialization_byvalueset(rarg,
				expr_to_resolve->constraints);
		if(!expr) return NULL;
	} else {
		errno = ESRCH;
		return NULL;
	}

	DEBUG("Found target %s (%d/%x)",
		expr->Identifier, expr->meta_type, expr->expr_type);
	if(expr->meta_type == AMT_TYPE
	|| expr->meta_type == AMT_VALUE
	|| expr->meta_type == AMT_TYPEREF
	|| expr->meta_type == AMT_VALUESET) {
		DEBUG("Target is a simple type %s",
			ASN_EXPR_TYPE2STR(expr->expr_type));
		nex = asn1p_expr_clone(expr, 0);
		free(nex->Identifier);
		nex->Identifier = expr_to_resolve->Identifier
			? strdup(expr_to_resolve->Identifier) : 0;
		if(expr->meta_type == AMT_TYPEREF) {
			asn1p_ref_t *ref = expr->reference;
			free(rarg->resolved_name);
			rarg->resolved_name = calloc(1, strlen(rarg->original_expr->Identifier)
			                          + strlen(ref->components[ref->comp_count - 1].name) + 2);
			if(!rarg->resolved_name) {
				asn1p_expr_free(nex);
				return NULL;
			}
			sprintf(rarg->resolved_name, "%s_%s", rarg->original_expr->Identifier,
			        ref->components[ref->comp_count - 1].name);
		} else if(expr->meta_type == AMT_VALUESET) {
			asn1p_constraint_t *ct = expr->constraints;
			if(ct->type == ACT_EL_TYPE) {
				asn1p_ref_t *ref = ct->containedSubtype->value.v_type->reference;
				free(rarg->resolved_name);
				rarg->resolved_name = strdup(ref->components[ref->comp_count - 1].name);
			}
		}
		return nex;
	} else {
		FATAL("Feature not implemented for %s (%d/%x), "
			"please contact the asn1c author",
			rarg->original_expr->Identifier,
			expr->meta_type, expr->expr_type);
		errno = EPERM;
		return NULL;
	}

	return NULL;
}

static asn1p_expr_t *
find_target_specialization_byvalueset(resolver_arg_t *rarg, asn1p_constraint_t *ct) {
	asn1p_ref_t *ref;

	if (ct->type != ACT_EL_TYPE) return NULL;

	ref = ct->containedSubtype->value.v_type->reference;

	return find_target_specialization_byref(rarg, ref);
}

static asn1p_expr_t *
find_target_specialization_byref(resolver_arg_t *rarg, asn1p_ref_t *ref) {
	char *refstr;

	if(!ref || ref->comp_count != 1) {
		errno = ESRCH;
		return NULL;
	}

	refstr = ref->components[0].name;	/* T */

	return find_target_specialization_bystr(rarg, refstr);
}

static asn1p_expr_t *
find_target_specialization_bystr(resolver_arg_t *rarg, char *refstr) {
	arg_t *arg = rarg->arg;
	asn1p_expr_t *target;
	int i;

	if(!refstr) return NULL;

	target = TQ_FIRST(&rarg->rhs_pspecs->members);
	for(i = 0; i < rarg->lhs_params->params_count;
			i++, target = TQ_NEXT(target, next)) {
		struct asn1p_param_s *param = &rarg->lhs_params->params[i];
		if(!target) break;

		if(strcmp(param->argument, refstr))
			continue;

		return target;
	}
	if(i != rarg->lhs_params->params_count) {
		FATAL("Parameterization of %s failed: "
			"parameters number mismatch",
				rarg->original_expr->Identifier);
		errno = EPERM;
		return NULL;
	}

	errno = ESRCH;
	return NULL;
}
