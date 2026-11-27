#include "asn1fix_internal.h"
#include <asn1_namespace.h>

#define	ADD_TAG(skip, newtag)	do {					\
	void *__p;							\
	if(skip && !(flags & AFT_FULL_COLLECT)) {			\
		if(newtag.tag_mode != TM_IMPLICIT)			\
			skip--;						\
		break;							\
	} else {							\
		if(newtag.tag_mode == TM_IMPLICIT)			\
			skip++;						\
	}								\
	__p = realloc((*tags),						\
		sizeof(struct asn1p_type_tag_s) * (count + 1));		\
	if(!__p) return -1;						\
	*tags = __p;							\
	(*tags)[count++] = newtag;					\
	if((flags & AFT_FETCH_OUTMOST)) return count;			\
} while(0)

/* X.691, #22.2 */
static int asn1f_fetch_minimal_choice_root_tag(arg_t *arg, struct asn1p_type_tag_s *tag, enum asn1f_aft_flags_e flags);
static int asn1f_fetch_tags_impl(arg_t *arg, struct asn1p_type_tag_s **tags,
	int count, int skip, enum asn1f_aft_flags_e flags);

/*
 * Purpose: continue tag collection through a type reference or handle an
 * external type whose definition is unavailable.
 * Source: asn1c's tag collection for AMT_TYPEREF.
 * Version: 2026-11-26.
 * Parameters: arg holds the current reference and namespace; tags and count
 * hold the collected prefix; skip tracks replaced tags; flags select the
 * collection mode.
 * Returns: the final tag count, zero for an untagged external, or -1 on failure.
 * Errors: reports assumptions and incompatible modes for external types.
 * Responsible party: asn1c maintainers.
 * History: preserves the defining module's scope when following aliases.
 * Example: a reference to another module's alias can resolve its local base.
 */
static int
asn1f_fetch_reference_tags(arg_t *arg, struct asn1p_type_tag_s **tags,
		int count, int skip, enum asn1f_aft_flags_e flags) {
	asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *nexpr;

	DEBUG("Following the reference %s", expr->Identifier);
	nexpr = asn1f_lookup_symbol(arg, expr->rhs_pspecs, expr->reference);
	if(!nexpr) {
		if(errno != EEXIST) return -1;	/* Not a known external type. */
		if(!count) return 0;	/* Outer tag known only to the external descriptor. */
		if((*tags)[count - 1].tag_mode == TM_IMPLICIT) {
			WARNING("Tagging mode for %s is IMPLICIT, assuming %s has exactly one tag",
				expr->Identifier, asn1f_printable_reference(expr->reference));
			return count;
		}
		FATAL("Tagging mode %s -> %s dangerously incompatible",
			expr->Identifier, asn1f_printable_reference(expr->reference));
		return -1;
	}

	/* An imported alias can refer to names local to its defining module. */
	if(expr->_mark & TM_RECURSION) return -1;
	expr->_mark |= TM_RECURSION;
	arg->expr = nexpr;
	if(nexpr->module != arg->mod) {
		count = WITH_MODULE(nexpr->module,
			asn1f_fetch_tags_impl(arg, tags, count, skip, flags));
	} else {
		count = asn1f_fetch_tags_impl(arg, tags, count, skip, flags);
	}
	expr->_mark &= ~TM_RECURSION;
	return count;
}

static int
asn1f_fetch_tags_impl(arg_t *arg, struct asn1p_type_tag_s **tags, int count, int skip, enum asn1f_aft_flags_e flags) {
	asn1p_expr_t *expr = arg->expr;
	if(arg->debug) {
		const char *type_name = ASN_EXPR_TYPE2STR(expr->expr_type);
		DEBUG("Fetching tag from %s: meta %d, type %s",
			expr->Identifier ? expr->Identifier : "anonymous type",
			expr->meta_type,
			type_name ? type_name : "(unknown type)");
	}

	/* If this type is tagged, add this tag first */
	if(expr->tag.tag_class != TC_NOCLASS)
		ADD_TAG(skip, expr->tag);

	/* REMOVE ME */
	if(expr->expr_type == A1TC_EXTENSIBLE) {
		struct asn1p_type_tag_s tt;
		memset(&tt, 0, sizeof(tt));
		tt.tag_class = -1;
		ADD_TAG(skip, tt);
		return count;
	}

	if(expr->meta_type == AMT_TYPE) {
		struct asn1p_type_tag_s tt;
		memset(&tt, 0, sizeof(tt));
		tt.tag_class = TC_UNIVERSAL;
		tt.tag_value = expr_type2uclass_value[expr->expr_type];
		if(tt.tag_value == 0) {
			if(expr->expr_type == ASN_TYPE_ANY
				&& (flags & AFT_IMAGINARY_ANY))
				tt.tag_value = -1;
			else if(expr->expr_type != ASN_CONSTR_CHOICE)
				return -1;
			else if(count) return count;
			else if((flags & AFT_CANON_CHOICE) == 0)
				return -1;
			else {
				int result = asn1f_fetch_minimal_choice_root_tag(arg, &tt, flags);
				if(result == ASN1F_TAG_EXTERNAL) return 0;
				if(result < 0) return -1;
			}
		}
		ADD_TAG(skip, tt);
		return count;
	}

	if(expr->meta_type == AMT_TYPEREF)
		return asn1f_fetch_reference_tags(arg, tags, count, skip, flags);

	DEBUG("No tags discovered for type %d", expr->expr_type);

	return -1;
}

static int
asn1f_fetch_minimal_choice_root_tag(arg_t *arg, struct asn1p_type_tag_s *tag, enum asn1f_aft_flags_e flags) {
	struct asn1p_type_tag_s min_tag;
	asn1p_expr_t *v;

	memset(&min_tag, 0, sizeof(min_tag));
	min_tag.tag_class = TC_PRIVATE + 1;

	TQ_FOR(v, &(arg->expr->members), next) {
		arg_t tmparg = *arg;
		struct asn1p_type_tag_s *tags = 0;
		int count;

		if(v->expr_type == A1TC_EXTENSIBLE)
			break;	/* Search only within extension root */

		tmparg.expr = v;
		count  = asn1f_fetch_tags_impl(&tmparg, &tags, 0, 0, flags);
		if(count <= 0) {
			free(tags);
			/* The missing root tag could precede every known tag. */
			if(count == 0) return ASN1F_TAG_EXTERNAL;
			continue;
		}

		if(tags[0].tag_class < min_tag.tag_class)
			min_tag = tags[0];
		else if(tags[0].tag_class == min_tag.tag_class
			&& tags[0].tag_value < min_tag.tag_value)
				min_tag = tags[0];
		free(tags);
	}

	if(min_tag.tag_class == TC_PRIVATE + 1)
		return -1;
	else
		*tag = min_tag;
	return 0;
}

static int
asn1f_fetch_tags_run(arg_t *arg, struct asn1p_type_tag_s **tags_r, enum asn1f_aft_flags_e flags) {
	struct asn1p_type_tag_s *tags = 0;
	int count;

	count = asn1f_fetch_tags_impl(arg, &tags, 0, 0, flags);
	if (count <= 0) {
		free(tags);
		tags = 0;
	}
	*tags_r = tags;
	return count;
}

int
asn1f_fetch_outmost_tag(asn1p_t *asn, asn1_namespace_t *ns, asn1p_module_t *mod, asn1p_expr_t *expr, struct asn1p_type_tag_s *tag, enum asn1f_aft_flags_e flags) {
	return asn1f_fetch_outmost_tag_ex(asn, ns, mod, expr, tag, flags,
		NULL, 0);
}

int
asn1f_fetch_outmost_tag_ex(asn1p_t *asn, asn1_namespace_t *ns, asn1p_module_t *mod, asn1p_expr_t *expr, struct asn1p_type_tag_s *tag, enum asn1f_aft_flags_e flags, asn1f_logger_f logger, int debug_enabled) {
	struct asn1p_type_tag_s *tags;
	int count;

	flags |= AFT_FETCH_OUTMOST;

	count = asn1f_fetch_tags_ex(asn, ns, mod, expr, &tags, flags, logger,
		debug_enabled);
	if(count < 0) return count;
	if(count == 0) return ASN1F_TAG_EXTERNAL;

	*tag = tags[0];
	free(tags);

	return 0;
}

int
asn1f_fetch_tags(asn1p_t *asn, asn1_namespace_t *ns, asn1p_module_t *mod, asn1p_expr_t *expr, struct asn1p_type_tag_s **tags_r, enum asn1f_aft_flags_e flags) {
	return asn1f_fetch_tags_ex(asn, ns, mod, expr, tags_r, flags, NULL, 0);
}

int
asn1f_fetch_tags_ex(asn1p_t *asn, asn1_namespace_t *ns, asn1p_module_t *mod, asn1p_expr_t *expr, struct asn1p_type_tag_s **tags_r, enum asn1f_aft_flags_e flags, asn1f_logger_f logger, int debug_enabled) {
	arg_t arg;

	memset(&arg, 0, sizeof(arg));
	arg.asn = asn;
	arg.ns = ns;
	arg.mod = mod;
	arg.expr = expr;
	arg.flags = a1f_replace_me_with_proper_interface_arg.flags;
	arg.eh = logger;
	arg.debug = debug_enabled ? logger : NULL;

	return asn1f_fetch_tags_run(&arg, tags_r, flags);
}
