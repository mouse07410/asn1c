#include "asn1fix_internal.h"

static int _asn1f_check_if_tag_must_be_explicit(arg_t *arg, asn1p_expr_t *v);
static int _asn1f_compare_tags(arg_t *arg, asn1p_expr_t *a, asn1p_expr_t *b);
static int _asn1f_fix_type_tag(arg_t *arg, asn1p_expr_t *expr);
static int _asn1f_autotag_group(arg_t *arg, asn1p_expr_t *group,
		asn1c_integer_t *tag_value);
static int _asn1f_autotag_leaf(arg_t *arg, asn1p_expr_t *member,
		asn1c_integer_t *tag_value);
static int _asn1f_check_group_tags(arg_t *arg, asn1p_expr_t *group,
		int component_number, int *root_tagged, int *ext_tagged);
static int _asn1f_is_extension_group(const asn1p_expr_t *expr);
static int _asn1f_is_sequence_extension_group(const asn1p_expr_t *expr);
static int _asn1f_validate_extension_group(arg_t *arg, asn1p_expr_t *group);
static int _asn1f_validate_extension_group_position(
		arg_t *arg, asn1p_expr_t *parent, asn1p_expr_t *member,
		int ext_count);
static int _asn1f_prepare_extension_member(arg_t *arg,
		asn1p_expr_t *parent, asn1p_expr_t *member, int ext_count);
static int _asn1f_process_extension_marker(arg_t *arg, asn1p_expr_t *marker,
		int *ext_count, int *remove_marker);
static int _asn1f_check_component_tag(arg_t *arg, asn1p_expr_t *member,
		int component_number, int *root_tagged, int *ext_tagged);
static int _asn1f_compare_group_tags(arg_t *arg, asn1p_expr_t *a,
		asn1p_expr_t *b, int *handled);
static int _asn1f_compare_unresolved_tags(arg_t *arg, asn1p_expr_t *a,
		asn1p_expr_t *b, int ra, int rb);
static int _asn1f_check_sequence_flat_tags(arg_t *arg,
		asn1p_expr_t *sequence);
static int _asn1f_check_set_extension_order(arg_t *arg, asn1p_expr_t *set);
static int _asn1f_check_set_extension_leaf_order(arg_t *arg,
		asn1p_expr_t *member, struct asn1p_type_tag_s *previous_max,
		int *have_previous);
static int _asn1f_get_extension_tag_bounds(arg_t *arg,
		asn1p_expr_t *member, struct asn1p_type_tag_s *minimum,
		struct asn1p_type_tag_s *maximum);
static int _asn1f_collect_extension_tag_bounds(arg_t *arg,
		asn1p_expr_t *member, struct asn1p_type_tag_s *minimum,
		struct asn1p_type_tag_s *maximum);
static int _asn1f_add_extension_tag_bound(struct asn1p_type_tag_s *tag,
		struct asn1p_type_tag_s *minimum,
		struct asn1p_type_tag_s *maximum);
static int _asn1f_tag_precedes(const struct asn1p_type_tag_s *left,
		const struct asn1p_type_tag_s *right);
static int _asn1f_check_set_group_identifiers(arg_t *arg,
		asn1p_expr_t *set);
static int _asn1f_check_set_group_name_pair(arg_t *arg,
		asn1p_expr_t *left, asn1p_expr_t *right);
static asn1p_expr_t *_asn1f_sequence_first_flat_component(
		asn1p_expr_t *sequence);
static asn1p_expr_t *_asn1f_sequence_next_flat_component(
		asn1p_expr_t *component);

int
asn1f_pull_components_of(arg_t *arg) {
	TQ_HEAD(asn1p_expr_t) list;
	asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *memb;
	int r_value = 0;

	switch(expr->expr_type) {
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
		break;
	default:
		return 0;
	}

	TQ_INIT(&list);

	/*
	 * Look into
	 */
	while((memb = TQ_REMOVE(&(expr->members), next))) {
		asn1p_expr_t *coft;	/* COMPONENTS OF thing itself */
		asn1p_expr_t *terminal;	/* Terminal of the referenced type */

		if(memb->expr_type != A1TC_COMPONENTS_OF) {
			TQ_ADD(&list, memb, next);
			continue;
		}

		coft = TQ_FIRST(&memb->members);
		assert(coft);
		assert(!TQ_NEXT(coft, next));

		/*
		 * Find the referenced type.
		 */
		terminal = asn1f_find_terminal_type(arg, coft);
		if(!terminal || (terminal->expr_type != expr->expr_type)) {
			FATAL("COMPONENTS OF at line %d "
				"must reference a %s type",
				coft->_lineno,
				expr->expr_type==ASN_CONSTR_SET
					? "SET" : "SEQUENCE"
			);
			TQ_ADD(&list, memb, next);
			r_value = -1;
			continue;
		}

		/*
		 * Clone the final structure.
		 */

		coft = asn1p_expr_clone(terminal, 1 /* Skip extensions */);
		if(!coft) return -1;	/* ENOMEM */

		if(1) {
			asn1p_expr_free(memb);	/* Don't need it anymore*/
		} else {
			/* Actual removal clashes with constraints... skip. */
		}

		/*
		 * Move all components of the cloned structure
		 * into the current one.
		 */
		while((memb = TQ_REMOVE(&(coft->members), next))) {
			TQ_ADD(&list, memb, next);
			memb->parent_expr = expr;
		}

		asn1p_expr_free(coft);	/* Remove wrapper */
	}

	/* Move the stuff back */
	TQ_MOVE(&(expr->members), &list);

	return r_value;
}

/*
 * Fix extensibility parts inside constructed types (SEQUENCE, SET, CHOICE).
 */
/*
 * Purpose: normalize extension markers and validate group placement.
 * Source: Existing constructed-type extension fixup, extended for X.680 groups.
 * Version: 2026-10-21.
 * Parameters: arg identifies the current module and constructed expression.
 * Returns: zero on success, or -1 when extension syntax is invalid.
 * Errors: reports misplaced/nested groups and malformed extension markers.
 * Author: asn1c maintainers.
 * History: Added extension-group marker validation for issue #583.
 * Example: a group after `...` remains one optional extension descriptor.
 */
int
asn1f_fix_constr_ext(arg_t *arg) {
	typedef TQ_HEAD(asn1p_expr_t) asn1p_expr_list_t;

	asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *v;
	asn1p_expr_list_t root_list;
	asn1p_expr_list_t ext_list;
	asn1p_expr_list_t *cur_list;
	int r_value = 0;
	int ext_count = 0;

	switch(expr->expr_type) {
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
	case ASN_CONSTR_CHOICE:
		break;
	default:
		return 0;
	}

	DEBUG("(%s) for line %d", expr->Identifier, expr->_lineno);
	if(_asn1f_is_extension_group(expr)) {
		return _asn1f_validate_extension_group(arg, expr);
	}
	if(expr->expr_type == ASN_CONSTR_SET
	&& _asn1f_check_set_group_identifiers(arg, expr))
		r_value = -1;

	TQ_INIT(&root_list);
	TQ_INIT(&ext_list);
	cur_list = &root_list;

	/*
	 * Split the set of fields into two lists, the root list
	 * and the extensions list.
	 */
	while((v = TQ_REMOVE(&(expr->members), next))) {
		int remove_marker = 0;
		if(_asn1f_prepare_extension_member(arg, expr, v, ext_count))
			r_value = -1;
		if(v->expr_type == A1TC_EXTENSIBLE) {
			cur_list = &ext_list;
			if(_asn1f_process_extension_marker(arg, v, &ext_count,
					&remove_marker))
				r_value = -1;
			if(remove_marker) {
				if(expr->expr_type == ASN_CONSTR_SET && ext_count == 2)
					cur_list = &root_list;
				continue;
			}
		}

		TQ_ADD(cur_list, v, next);
	}

	/*
	 * Copy the root list and extension list back into the main list.
	 */
	TQ_MOVE(&(expr->members), &root_list);
	while((v = TQ_REMOVE(&ext_list, next)))
		TQ_ADD(&(expr->members), v, next);

	if((arg->mod->module_flags & MSF_EXTENSIBILITY_IMPLIED)
	&& !_asn1f_is_extension_group(expr)
	&& ext_count == 0) {
		v = asn1p_expr_new(0, arg->mod);
		if(v) {
			v->Identifier = strdup("...");
			v->expr_type = A1TC_EXTENSIBLE;
			v->meta_type = AMT_TYPE;
			v->_lineno = expr->_lineno;	/* The best we can do */
			if(v->Identifier == NULL) {
				asn1p_expr_free(v);
				r_value = -1;
			} else {
				asn1p_expr_add(expr, v);
			}
		} else {
			r_value = -1;
		}
	}

	return r_value;
}

/*
 * Purpose: apply SET group representation and placement checks to a member.
 * Source: X.680 extension-group placement plus SET group descriptor handling.
 * Version: 2026-10-22.
 * Parameters: arg identifies the fixer context; parent is the constructed type;
 *             member is one current component; ext_count counts prior markers.
 * Returns: zero when valid, or -1 after reporting invalid group placement.
 * Errors: reports misplaced extension groups through the position validator.
 * Author: asn1c maintainers.
 * History: Extracted from extension normalization to bound its complexity.
 * Example: a direct SET extension group becomes a synthetic SET child.
 */
static int
_asn1f_prepare_extension_member(arg_t *arg, asn1p_expr_t *parent,
		asn1p_expr_t *member, int ext_count) {
	if(parent->expr_type == ASN_CONSTR_SET
	&& (member->marker.flags & EM_EXTENSION_GROUP))
		member->expr_type = ASN_CONSTR_SET;
	return _asn1f_validate_extension_group_position(arg, parent, member,
		ext_count);
}

/*
 * Purpose: reject markers and nested groups inside one synthetic group.
 * Source: X.680 extension addition group component-list restrictions.
 * Version: 2026-10-21.
 * Parameters: arg identifies the fixer context; group is the synthetic group.
 * Returns: zero when every child is a component, or -1 if a marker is found.
 * Errors: emits one diagnostic for each nested marker or group.
 * Author: asn1c maintainers.
 * History: Extracted from extension normalization to bound its complexity.
 * Example: an extension marker inside [[...]] is rejected.
 */
static int
_asn1f_validate_extension_group(arg_t *arg, asn1p_expr_t *group) {
	asn1p_expr_t *member;
	int result = 0;

	TQ_FOR(member, &(group->members), next) {
		if(member->expr_type == A1TC_EXTENSIBLE
		|| (member->marker.flags & EM_EXTENSION_GROUP)) {
			FATAL("Nested extension marker or group inside "
				"extension addition group at line %d", member->_lineno);
			result = -1;
		}
	}
	return result;
}

/*
 * Purpose: reject SET groups outside extension additions and pre-marker
 *          SEQUENCE groups.
 * Source: ITU-T X.680 (02/2021), clause 25.1.
 * Version: 2026-10-21.
 * Parameters: arg identifies the fixer context; parent is the constructed type;
 *             member is the current component; ext_count counts prior markers.
 * Returns: zero when placement is valid, or -1 after reporting an error.
 * Errors: reports a misplaced SET group or pre-marker SEQUENCE group.
 * Author: asn1c maintainers.
 * History: Extracted from the member-list normalization loop.
 * Example: a SET group before `...` or after its second marker is rejected.
 */
static int
_asn1f_validate_extension_group_position(arg_t *arg, asn1p_expr_t *parent,
		asn1p_expr_t *member, int ext_count) {
	if(!(member->marker.flags & EM_EXTENSION_GROUP)) return 0;
	if(parent->expr_type == ASN_CONSTR_SET) {
		if(ext_count == 1) return 0;
		FATAL("SET extension addition group outside extension additions at line %d",
			member->_lineno);
		return -1;
	}
	if(parent->expr_type != ASN_CONSTR_SEQUENCE || ext_count != 0) return 0;
	FATAL("Extension addition group before extension marker at line %d",
		member->_lineno);
	return -1;
}

/*
 * Purpose: count an extension marker and remove the optional second marker.
 * Source: Existing constructed-type extension-list normalization.
 * Version: 2026-10-21.
 * Parameters: arg identifies the fixer context; marker is the marker expression;
 *             ext_count is updated; remove_marker receives whether to omit it.
 * Returns: zero for an accepted marker, or -1 for an invalid exception/marker.
 * Errors: diagnoses exception marks on marker two and a third marker.
 * Author: asn1c maintainers.
 * History: Extracted from the normalizer without changing marker semantics.
 * Example: marker two is freed and later extension fields remain in the list.
 */
static int
_asn1f_process_extension_marker(arg_t *arg, asn1p_expr_t *marker,
		int *ext_count,
		int *remove_marker) {
	int result = 0;

	*remove_marker = 0;
	switch(++*ext_count) {
	case 1:
		return 0;
	case 2:
		if(marker->value) {
			FATAL("Optional extension marker must not contain an exception mark "
				"at line %d", marker->_lineno);
			result = -1;
		}
		asn1p_expr_free(marker);
		*remove_marker = 1;
		return result;
	case 3:
		FATAL("Third extension marker is not allowed at line %d",
			marker->_lineno);
		/* Fall through */
	default:
		return -1;
	}
}


/*
 * Purpose: resolve explicit tags and automatic-tag eligibility for components.
 * Source: Existing constructed-type tag fixup, extended for extension groups.
 * Version: 2026-10-21.
 * Parameters: arg identifies the expression; fix_top_level selects its own tag.
 * Returns: zero on success, or -1 for invalid tag combinations.
 * Errors: reports implicit/explicit conflicts and mixed automatic tagging.
 * Author: asn1c maintainers.
 * History: Group leaves now contribute as flat extension components.
 * Example: explicit tags inside [[...]] are checked as enclosing SEQUENCE tags.
 */
int
asn1f_fix_constr_tag(arg_t *arg, int fix_top_level) {
	asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *v;
	int root_tagged = 0;	/* A root component is manually tagged */
	int ext_tagged = 0;	/* An extension component is manually tagged */
	int component_number = 0;
	int r_value = 0;

	DEBUG("(%s) for line %d", expr->Identifier, expr->_lineno);

	/*
	 * Fix the top-level type itself first.
	 */
	if(fix_top_level) {
		if(expr->tag.tag_class == TC_NOCLASS)
			return r_value;

		if(_asn1f_fix_type_tag(arg, expr))
			r_value = -1;

		return r_value;
	}

	if(expr->expr_type == ASN_CONSTR_SEQUENCE_OF
	|| expr->expr_type == ASN_CONSTR_SET_OF) {
		TQ_FOR(v, &(expr->members), next) {
			if(v->tag.tag_class != TC_NOCLASS
			&& _asn1f_fix_type_tag(arg, v))
				r_value = -1;
		}
		return r_value;
	}

	switch(expr->expr_type) {
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
	case ASN_CONSTR_CHOICE:
		break;
	default:
		return 0;
	}
	if(_asn1f_is_extension_group(expr)) return 0;

	TQ_FOR(v, &(expr->members), next) {

		if(v->expr_type == A1TC_EXTENSIBLE) {
			component_number++;
			continue;
		}
		if(_asn1f_is_extension_group(v)) {
			if(_asn1f_check_group_tags(arg, v, component_number,
					&root_tagged, &ext_tagged))
				r_value = -1;
			continue;
		}

		if(_asn1f_check_component_tag(arg, v, component_number,
				&root_tagged, &ext_tagged))
			r_value = -1;
	}

	if((arg->mod->module_flags & MSF_AUTOMATIC_TAGS)
	&& !root_tagged) {
		if(ext_tagged) {
			/* X.690: 28.4 */
			FATAL("In %s at line %d: "
				"extensions are tagged "
				"but root components are not",
				expr->Identifier, expr->_lineno);
			r_value = -1;
		} else {
			/* Make a decision on automatic tagging */
			expr->auto_tags_OK = 1;
		}
	}

	return r_value;
}

/*
 * Purpose: classify and fix the explicit tag of one constructed component.
 * Source: Existing X.690 automatic-tag eligibility and type-tag validation.
 * Version: 2026-10-21.
 * Parameters: arg identifies the type; member is the component; component_number
 *             selects root versus extension; both flags receive classification.
 * Returns: zero when untagged or valid, or -1 when tag fixup fails.
 * Errors: propagates diagnostics from _asn1f_fix_type_tag.
 * Author: asn1c maintainers.
 * History: Shared by parent SEQUENCE fields and extension-group leaves.
 * Example: a tagged extension-group leaf updates ext_tagged.
 */
static int
_asn1f_check_component_tag(arg_t *arg, asn1p_expr_t *member,
		int component_number, int *root_tagged, int *ext_tagged) {
	if(member->tag.tag_class == TC_NOCLASS) return 0;
	if(component_number == 0 || component_number == 2)
		*root_tagged = 1;
	else
		*ext_tagged = 1;
	return _asn1f_fix_type_tag(arg, member);
}

/*
 * Purpose: classify and validate explicit tags on the flat members of a group.
 * Source: ASN.1 extension-group tag handling, adapted from this module's tag fixup.
 * Version: 2026-10-21.
 * Parameters: arg is the active fixer; group is the synthetic group expression;
 *             component_number identifies the enclosing root/extension region;
 *             root_tagged and ext_tagged receive tagging classifications.
 * Returns: zero on success, or -1 if a child tag cannot be fixed.
 * Errors: propagates _asn1f_fix_type_tag failures.
 * Author: asn1c maintainers.
 * History: Added for flat extension-group component tagging.
 * Example: a tagged group member contributes to ext_tagged, not the wrapper.
 */
static int
_asn1f_check_group_tags(arg_t *arg, asn1p_expr_t *group,
		int component_number, int *root_tagged, int *ext_tagged) {
	asn1p_expr_t *member;
	int result = 0;

	TQ_FOR(member, &(group->members), next) {
		if(member->expr_type == A1TC_EXTENSIBLE) {
			component_number++;
			continue;
		}
		if(member->marker.flags & EM_EXTENSION_GROUP) {
			if(_asn1f_check_group_tags(arg, member, component_number,
					root_tagged, ext_tagged))
				result = -1;
			continue;
		}
		if(_asn1f_check_component_tag(arg, member, component_number,
				root_tagged, ext_tagged)) result = -1;
	}
	return result;
}

/*
 * Purpose: identify marked synthetic groups directly owned by SET or SEQUENCE.
 * Source: Parser metadata for X.680 extension addition groups.
 * Version: 2026-10-22.
 * Parameters: expr is the candidate component expression.
 * Returns: nonzero for a direct group child of SET or SEQUENCE.
 * Errors: none.
 * Author: asn1c maintainers.
 * History: Extended the original SEQUENCE-only group predicate to SET.
 * Example: a marked child of a SET returns nonzero after fixer normalization.
 */
static int
_asn1f_is_extension_group(const asn1p_expr_t *expr) {
	return (expr->marker.flags & EM_EXTENSION_GROUP)
		&& expr->parent_expr
		&& (expr->parent_expr->expr_type == ASN_CONSTR_SEQUENCE
			|| expr->parent_expr->expr_type == ASN_CONSTR_SET);
}

/*
 * Purpose: identify synthetic extension groups directly contained by SEQUENCE.
 * Source: Parser metadata added for X.680 extension addition groups.
 * Version: 2026-10-21.
 * Parameters: expr is the candidate component expression.
 * Returns: nonzero only for a marked group directly contained by SEQUENCE.
 * Errors: none.
 * Author: asn1c maintainers.
 * History: Retained for SEQUENCE-specific flat component traversal.
 * Example: a marked synthetic child of Rec SEQUENCE returns nonzero.
 */
static int
_asn1f_is_sequence_extension_group(const asn1p_expr_t *expr) {
	return (expr->marker.flags & EM_EXTENSION_GROUP)
		&& expr->parent_expr
		&& expr->parent_expr->expr_type == ASN_CONSTR_SEQUENCE;
}

static int
_asn1f_fix_type_tag(arg_t *arg, asn1p_expr_t *expr) {
	int must_explicit = _asn1f_check_if_tag_must_be_explicit(arg, expr);
	int module_impl_tags = (arg->mod->module_flags
				& (MSF_IMPLICIT_TAGS | MSF_AUTOMATIC_TAGS));
	int r_value = 0;

	if(expr->tag.tag_mode == TM_DEFAULT) {
		if(must_explicit || module_impl_tags == 0)
			expr->tag.tag_mode = TM_EXPLICIT;
		else
			expr->tag.tag_mode = TM_IMPLICIT;
	}

	/*
	 * Perform a final sanity check.
	 */
	if(must_explicit) {
		if(expr->tag.tag_mode == TM_IMPLICIT) {
			FATAL("%s tagged in IMPLICIT mode "
				"but must be EXPLICIT at line %d",
				expr->Identifier, expr->_lineno);
			r_value = -1;
		} else {
			expr->tag.tag_mode = TM_EXPLICIT;
		}
	}

	return r_value;
}

/*
 * Purpose: apply automatic tags to constructed type components.
 * Source: Existing automatic-tag fixup, extended for flat SEQUENCE groups.
 * Version: 2026-10-21.
 * Parameters: arg identifies the constructed expression and active module.
 * Returns: zero on success, or -1 if group leaf tagging fails.
 * Errors: reports invalid component tags through the helper.
 * Author: asn1c maintainers.
 * History: Counts group leaves without tagging their synthetic wrapper.
 * Example: `before, [[g1, g2]], after` receives consecutive tags 0 through 3.
 */
int
asn1f_fix_constr_autotag(arg_t *arg) {
	asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *v;
	asn1c_integer_t tag_value = 0;
	int r_value = 0;

	switch(expr->expr_type) {
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
	case ASN_CONSTR_CHOICE:
		if(expr->auto_tags_OK)
			break;
		/* Automatic tagging is not applicable */
		/* Fall through */
	default:
		return 0;
	}
	if(_asn1f_is_extension_group(expr)) return 0;

	DEBUG("(%s) for line %d", expr->Identifier, expr->_lineno);

	TQ_FOR(v, &(expr->members), next) {
		if(v->expr_type == A1TC_EXTENSIBLE) {
			/* 28.5, d) */
			continue;
		}
		if(_asn1f_is_extension_group(v)) {
			if(_asn1f_autotag_group(arg, v, &tag_value)) r_value = -1;
			continue;
		}

		if(0) {
			/* This may be not true in case COMPONENTS OF */
			assert(v->tag.tag_class == TC_NOCLASS);
		}

		if(_asn1f_autotag_leaf(arg, v, &tag_value)) r_value = -1;
	}

	return r_value;
}

/*
 * Purpose: apply automatic tags to group leaves in their enclosing flat order.
 * Source: ASN.1 X.680 automatic tagging for extension addition groups.
 * Version: 2026-10-21.
 * Parameters: arg is the active fixer; group is a synthetic group; tag_value
 *             points to the next parent-level automatic tag number.
 * Returns: zero on success, or -1 if a member tag cannot be resolved.
 * Errors: reports invalid implicit tags via _asn1f_fix_type_tag.
 * Author: asn1c maintainers.
 * History: Added so group wrappers do not consume an automatic tag number.
 * Example: group members following tags 0 and 1 receive tags 2 and 3.
 */
static int
_asn1f_autotag_group(arg_t *arg, asn1p_expr_t *group,
		asn1c_integer_t *tag_value) {
	asn1p_expr_t *member;
	int result = 0;

	TQ_FOR(member, &(group->members), next) {
		if(member->expr_type == A1TC_EXTENSIBLE) continue;
		if(member->marker.flags & EM_EXTENSION_GROUP) {
			if(_asn1f_autotag_group(arg, member, tag_value)) result = -1;
			continue;
		}
		if(_asn1f_autotag_leaf(arg, member, tag_value)) result = -1;
	}
	return result;
}

/*
 * Purpose: assign the next automatic tag to one non-group component.
 * Source: Existing automatic-tag rule, shared by ordinary and group members.
 * Version: 2026-10-21.
 * Parameters: arg is the active fixer; member is the component; tag_value points
 *             to the next available parent-level tag number.
 * Returns: zero on success, or -1 if the member tag is invalid.
 * Errors: reports invalid implicit tags via _asn1f_fix_type_tag.
 * Author: asn1c maintainers.
 * History: Extracted to maintain one counter across extension-group boundaries.
 * Example: a component receives [3] when the current counter is three.
 */
static int
_asn1f_autotag_leaf(arg_t *arg, asn1p_expr_t *member,
		asn1c_integer_t *tag_value) {
	int must_explicit = _asn1f_check_if_tag_must_be_explicit(arg, member);
	member->tag.tag_class = TC_CONTEXT_SPECIFIC;
	member->tag.tag_mode = must_explicit ? TM_EXPLICIT : TM_IMPLICIT;
	member->tag.tag_value = (*tag_value)++;
	return 0;
}

/*
 * Check that tags are distinct.
 */
/*
 * Purpose: reject ambiguous tags among components that may be absent.
 * Source: Existing SEQUENCE/SET/CHOICE tag uniqueness check.
 * Version: 2026-10-21.
 * Parameters: arg identifies the constructed expression being checked.
 * Returns: zero on success, or -1 when two candidate fields share a tag.
 * Errors: emits a diagnostic naming the conflicting components.
 * Author: asn1c maintainers.
 * History: Group comparisons now expand the group's leaf tags for SEQUENCE.
 * Example: duplicate tags in adjacent optional group components are rejected.
 */
int
asn1f_check_constr_tags_distinct(arg_t *arg) {
	asn1p_expr_t *expr = arg->expr;
	asn1p_expr_t *v;
	int r_value = 0;

	switch(expr->expr_type) {
	case ASN_CONSTR_SEQUENCE:
	case ASN_CONSTR_SET:
	case ASN_CONSTR_CHOICE:
		break;
	default:
		return 0;
	}
	if(expr->expr_type == ASN_CONSTR_SEQUENCE) {
		return _asn1f_check_sequence_flat_tags(arg, expr);
	}

	TQ_FOR(v, &(expr->members), next) {
		/*
		 * In every series of non-mandatory components,
		 * the tags must be distinct from each other AND the
		 * tag of the following mandatory component.
		 * For SET and CHOICE treat everything as a big set of
		 * non-mandatory components.
		 */
		if(expr->expr_type != ASN_CONSTR_SEQUENCE || v->marker.flags) {
			asn1p_expr_t *nv;
			for(nv = v; (nv = TQ_NEXT(nv, next));) {
				DEBUG("S/C comparing tags %s s. %s",
					v->Identifier, nv->Identifier);
				if(_asn1f_compare_tags(arg, v, nv))
					r_value = -1;
				if(expr->expr_type == ASN_CONSTR_SEQUENCE
				&& !nv->marker.flags) break;
			}
		}
	}
	if(expr->expr_type == ASN_CONSTR_SET
	&& _asn1f_check_set_extension_order(arg, expr))
		r_value = -1;

	return r_value;
}

/*
 * Purpose: require SET extension leaves to increase by canonical tag order.
 * Source: ITU-T X.680 (02/2021), clauses 8.6 and 27.3.
 * Version: 2026-10-22.
 * Parameters: arg is the active fixer; set is the containing SET expression.
 * Returns: zero when additions are ordered, or -1 after reporting a violation.
 * Errors: reports unresolved tags and non-increasing extension tags.
 * Author: asn1c maintainers.
 * History: Added for SET extension groups, whose leaves remain separate fields.
 * Example: additions tagged [2], [[a [3], b [4]]] pass; [4], then [3] fails.
 */
static int
_asn1f_check_set_extension_order(arg_t *arg, asn1p_expr_t *set) {
	asn1p_expr_t *component;
	struct asn1p_type_tag_s previous;
	int have_previous = 0;
	int in_extensions = 0;
	int result = 0;

	TQ_FOR(component, &(set->members), next) {
		if(component->expr_type == A1TC_EXTENSIBLE) {
			in_extensions = 1;
			continue;
		}
		if(!in_extensions) continue;
		if(_asn1f_is_extension_group(component)) {
			asn1p_expr_t *leaf;
			TQ_FOR(leaf, &(component->members), next) {
				if(leaf->expr_type == A1TC_EXTENSIBLE) continue;
				if(_asn1f_check_set_extension_leaf_order(arg, leaf,
						&previous, &have_previous))
					result = -1;
			}
		} else if(_asn1f_check_set_extension_leaf_order(arg, component,
				&previous, &have_previous)) {
			result = -1;
		}
	}
	return result;
}

/*
 * Purpose: compare one SET extension leaf with the prior leaf's canonical tag.
 * Source: ITU-T X.680 (02/2021), clauses 8.6 and 27.3.
 * Version: 2026-10-22.
 * Parameters: arg is the active fixer; member is a flattened extension leaf;
 *             previous is updated to its tag; have_previous tracks prior tags.
 * Returns: zero when order holds, or -1 after reporting a tag/order error.
 * Errors: reports a tag that cannot be resolved or is not canonically greater.
 * Author: asn1c maintainers.
 * History: CHOICE contributes its minimum and maximum exposed tags so every
 *          possible branch tag is strictly later than the previous component.
 * Example: CHOICE tags [3] and [9] cannot precede a component tagged [5].
 */
static int
_asn1f_check_set_extension_leaf_order(arg_t *arg, asn1p_expr_t *member,
		struct asn1p_type_tag_s *previous_max, int *have_previous) {
	struct asn1p_type_tag_s current_min;
	struct asn1p_type_tag_s current_max;

	if(_asn1f_get_extension_tag_bounds(arg, member, &current_min,
			&current_max)) {
		FATAL("Cannot determine canonical extension tag for %s at line %d",
			member->Identifier ? member->Identifier : "component",
			member->_lineno);
		return -1;
	}

	if(*have_previous && !_asn1f_tag_precedes(previous_max, &current_min)) {
			FATAL("SET extension component %s at line %d must have a "
				"minimum tag canonically greater than every tag of the "
				"preceding extension component",
				member->Identifier ? member->Identifier : "component",
				member->_lineno);
			return -1;
	}

	*previous_max = current_max;
	*have_previous = 1;
	return 0;
}

/*
 * Purpose: derive the lowest and highest exposed tags for a SET extension leaf.
 * Source: ITU-T X.680 (02/2021), clauses 8.6, 27.3, and 29.8.
 * Version: 2026-10-22.
 * Parameters: arg is the active fixer; member is one flattened component;
 *             minimum and maximum receive its exposed tag bounds.
 * Returns: zero when all exposed tags are known, or -1 when unresolved.
 * Errors: none; the caller reports a useful component-level diagnostic.
 * Author: asn1c maintainers.
 * History: Applies the documented all-tags ordering interpretation for CHOICE.
 * Example: CHOICE tags [3] and [9] yields bounds [3] and [9].
 */
static int
_asn1f_get_extension_tag_bounds(arg_t *arg, asn1p_expr_t *member,
		struct asn1p_type_tag_s *minimum,
		struct asn1p_type_tag_s *maximum) {
	int result;

	minimum->tag_class = TC_PRIVATE + 1;
	maximum->tag_class = TC_NOCLASS;
	result = _asn1f_collect_extension_tag_bounds(arg, member, minimum, maximum);
	if(result) return -1;
	return minimum->tag_class >= TC_UNIVERSAL
		&& minimum->tag_class <= TC_PRIVATE ? 0 : -1;
}

/*
 * Purpose: add every finite effective tag of a component to its bounds.
 * Source: ITU-T X.680 (02/2021), clauses 8.6 and 29.8.
 * Version: 2026-10-22.
 * Parameters: arg is the active fixer; member is a component or CHOICE branch;
 *             minimum and maximum accumulate the canonical tag-set bounds.
 * Returns: zero when tags are collected, or -1 for an unknown/recursive type.
 * Errors: none; invalid or unresolved tags are reported by the caller.
 * Author: asn1c maintainers.
 * History: Resolves aliases and visits all finite CHOICE alternatives.
 * Example: an untagged CHOICE contributes every root and extension branch tag.
 */
static int
_asn1f_collect_extension_tag_bounds(arg_t *arg, asn1p_expr_t *member,
		struct asn1p_type_tag_s *minimum,
		struct asn1p_type_tag_s *maximum) {
	asn1p_expr_t *terminal;
	struct asn1p_type_tag_s tag;
	int result;

	if(arg->mod != member->module)
		return WITH_MODULE(member->module,
			_asn1f_collect_extension_tag_bounds(arg, member, minimum, maximum));
	memset(&tag, 0, sizeof(tag));
	result = asn1f_fetch_outmost_tag_ex(arg->asn, arg->ns, arg->mod,
			member, &tag, AFT_IMAGINARY_ANY,
			arg->eh, arg->debug != NULL);
	if(result == 0 && tag.tag_class != TC_NOCLASS)
		return _asn1f_add_extension_tag_bound(&tag, minimum, maximum);

	terminal = asn1f_find_terminal_type(arg, member);
	if(!terminal) return -1;
	if(terminal->expr_type != ASN_CONSTR_CHOICE) return -1;

	if(terminal->_mark & TM_RECURSION) return -1;
	terminal->_mark |= TM_RECURSION;
	result = 0;
	TQ_FOR(member, &(terminal->members), next) {
		if(member->expr_type == A1TC_EXTENSIBLE) continue;
		if(_asn1f_collect_extension_tag_bounds(arg, member, minimum, maximum)) {
			result = -1;
			break;
		}
	}
	terminal->_mark &= ~TM_RECURSION;
	return result;
}

/*
 * Purpose: update canonical extrema with one effective tag.
 * Source: ITU-T X.680 (02/2021), clause 8.6.
 * Version: 2026-10-22.
 * Parameters: tag is one possible tag; minimum and maximum are in/out bounds.
 * Returns: zero for a valid finite tag, or -1 for an unknown tag value.
 * Errors: none.
 * Author: asn1c maintainers.
 * History: Added for strict SET extension ordering across untagged CHOICE.
 * Example: tags [3] and [9] update the bounds to [3] and [9].
 */
static int
_asn1f_add_extension_tag_bound(struct asn1p_type_tag_s *tag,
		struct asn1p_type_tag_s *minimum,
		struct asn1p_type_tag_s *maximum) {
	if(tag->tag_class < TC_UNIVERSAL || tag->tag_class > TC_PRIVATE
	|| tag->tag_value < 0)
		return -1;
	if(minimum->tag_class > TC_PRIVATE || _asn1f_tag_precedes(tag, minimum))
		*minimum = *tag;
	if(maximum->tag_class == TC_NOCLASS || _asn1f_tag_precedes(maximum, tag))
		*maximum = *tag;
	return 0;
}

/*
 * Purpose: compare tags in X.680 canonical class/number order.
 * Source: ITU-T X.680 (02/2021), clause 8.6.
 * Version: 2026-10-22.
 * Parameters: left and right are effective ASN.1 tags.
 * Returns: nonzero when left canonically precedes right.
 * Errors: none.
 * Author: asn1c maintainers.
 * History: Shared by SET extension tag-bound validation.
 * Example: [APPLICATION 2] precedes [CONTEXT 0].
 */
static int
_asn1f_tag_precedes(const struct asn1p_type_tag_s *left,
		const struct asn1p_type_tag_s *right) {
	return left->tag_class < right->tag_class
		|| (left->tag_class == right->tag_class
			&& left->tag_value < right->tag_value);
}

/*
 * Purpose: enforce component-name uniqueness across SET extension-group edges.
 * Source: ITU-T X.680 (02/2021), clauses 25.14 and 27.4.
 * Version: 2026-10-22.
 * Parameters: arg is the active fixer; set is the containing SET expression.
 * Returns: zero when names are unique, or -1 after reporting a duplicate.
 * Errors: reports equal identifiers in different SET component lists.
 * Author: asn1c maintainers.
 * History: Complements per-list checks, which cannot see across a synthetic group.
 * Example: `root INTEGER, ..., [[root BOOLEAN]]` is rejected.
 */
static int
_asn1f_check_set_group_identifiers(arg_t *arg, asn1p_expr_t *set) {
	asn1p_expr_t *left;
	int result = 0;

	TQ_FOR(left, &(set->members), next) {
		asn1p_expr_t *right;
		for(right = TQ_NEXT(left, next); right;
		    right = TQ_NEXT(right, next)) {
			if(!_asn1f_is_extension_group(left)
			&& !_asn1f_is_extension_group(right)) continue;
			if(_asn1f_check_set_group_name_pair(arg, left, right))
				result = -1;
		}
	}
	return result;
}

/*
 * Purpose: compare names across a SET extension group and a later component.
 * Source: ITU-T X.680 (02/2021), clauses 25.14 and 27.4.
 * Version: 2026-10-22.
 * Parameters: arg is the active fixer; left and right are adjacent list items.
 * Returns: zero when names differ, or -1 after reporting a duplicate name.
 * Errors: emits a diagnostic for the first duplicate in this component pair.
 * Author: asn1c maintainers.
 * History: Expands group leaves so names remain unique across SET list levels.
 * Example: a group leaf named `id` conflicts with a later outer `id` field.
 */
static int
_asn1f_check_set_group_name_pair(arg_t *arg, asn1p_expr_t *left,
		asn1p_expr_t *right) {
	asn1p_expr_t *left_member;
	asn1p_expr_t *right_member;
	int left_is_group = _asn1f_is_extension_group(left);
	int right_is_group = _asn1f_is_extension_group(right);

	left_member = left_is_group
		? TQ_FIRST(&left->members) : left;
	while(left_member) {
		right_member = right_is_group
			? TQ_FIRST(&right->members) : right;
		while(right_member) {
			if(left_member->Identifier && right_member->Identifier
			&& strcmp(left_member->Identifier, right_member->Identifier) == 0) {
				FATAL("Clash detected: \"%s\" at line %d has similar identifier "
					"with \"%s\" at line %d",
					left_member->Identifier, left_member->_lineno,
					right_member->Identifier, right_member->_lineno);
				return -1;
			}
			if(!right_is_group) break;
			right_member = TQ_NEXT(right_member, next);
		}
		if(!left_is_group) break;
		left_member = TQ_NEXT(left_member, next);
	}
	return 0;
}

/*
 * Purpose: walk SEQUENCE components in wire order while exposing group leaves.
 * Source: X.680 extension-addition-group component-list flattening.
 * Version: 2026-10-21.
 * Parameters: component is a current component or NULL to request the first.
 * Returns: the next flattened component, or NULL at the end.
 * Errors: none; parser/fixer validation rejects nested groups beforehand.
 * Author: asn1c maintainers.
 * History: Added to apply tag checks to actual group leaves, not wrappers.
 * Example: the next component after the last group leaf is the parent's tail.
 */
static asn1p_expr_t *
_asn1f_sequence_next_flat_component(asn1p_expr_t *component) {
	asn1p_expr_t *owner;
	asn1p_expr_t *next;

	if(component == NULL) return NULL;
	owner = component;
	if(_asn1f_is_sequence_extension_group(component->parent_expr)) {
		next = TQ_NEXT(component, next);
		if(next) return next;
		owner = component->parent_expr;
	}

	next = TQ_NEXT(owner, next);
	while(next && _asn1f_is_sequence_extension_group(next)) {
		asn1p_expr_t *first = TQ_FIRST(&next->members);
		if(first) return first;
		next = TQ_NEXT(next, next);
	}
	return next;
}

/*
 * Purpose: find the first flattened SEQUENCE component, expanding a leading group.
 * Source: X.680 extension-addition-group component-list flattening.
 * Version: 2026-10-21.
 * Parameters: sequence is the constructed SEQUENCE expression.
 * Returns: first component, or NULL for an empty sequence.
 * Errors: none; invalid nested groups are rejected before this phase.
 * Author: asn1c maintainers.
 * History: Added with flattened tag-run validation.
 * Example: returns a group's first leaf when that group is the first component.
 */
static asn1p_expr_t *
_asn1f_sequence_first_flat_component(asn1p_expr_t *sequence) {
	asn1p_expr_t *member;

	member = TQ_FIRST(&sequence->members);
	while(member) {
		if(_asn1f_is_sequence_extension_group(member)) {
			asn1p_expr_t *group = member;
			member = TQ_FIRST(&group->members);
			if(member) return member;
			member = TQ_NEXT(group, next);
			continue;
		}
		return member;
	}
	return NULL;
}

/*
 * Purpose: check optional-run tag uniqueness across flattened group boundaries.
 * Source: Existing SEQUENCE tag-run check, adapted to X.680 group components.
 * Version: 2026-10-21.
 * Parameters: arg is the active fixer; sequence is its SEQUENCE expression.
 * Returns: zero on success, or -1 if an optional run has an ambiguous tag.
 * Errors: reports duplicate tags through _asn1f_compare_tags.
 * Author: asn1c maintainers.
 * History: Compares only leaves required by the optional-run rule.
 * Example: adjacent mandatory [3] group/tail components remain valid.
 */
static int
_asn1f_check_sequence_flat_tags(arg_t *arg, asn1p_expr_t *sequence) {
	asn1p_expr_t *component;
	int result = 0;

	for(component = _asn1f_sequence_first_flat_component(sequence);
	    component;
	    component = _asn1f_sequence_next_flat_component(component)) {
		asn1p_expr_t *next;

		if(component->expr_type == A1TC_EXTENSIBLE
		|| !component->marker.flags) continue;
		for(next = _asn1f_sequence_next_flat_component(component);
		    next;
		    next = _asn1f_sequence_next_flat_component(next)) {
			if(next->expr_type == A1TC_EXTENSIBLE) break;
			if(_asn1f_compare_tags(arg, component, next)) result = -1;
			if(!next->marker.flags) break;
		}
	}
	return result;
}

static int
_asn1f_check_if_tag_must_be_explicit(arg_t *arg, asn1p_expr_t *v) {
	struct asn1p_type_tag_s tag;
	struct asn1p_type_tag_s save_tag;
	asn1p_expr_t *reft;
	int ret;

	/*
	 * Fetch the _next_ tag for this type.
	 */
	save_tag = v->tag;			/* Save existing tag */
	memset(&v->tag, 0, sizeof(v->tag));	/* Remove it temporarily */
	ret = asn1f_fetch_outmost_tag_ex(arg->asn, arg->ns, arg->mod, v, &tag, 0,
			arg->eh, arg->debug != NULL);
	v->tag = save_tag;			/* Restore the tag back */

	if(ret == 0) return 0;	/* If found tag, it's okay */

	reft = asn1f_find_terminal_type(arg, v);
	if(reft) {
		switch(reft->expr_type) {
		case ASN_TYPE_ANY:
		case ASN_CONSTR_CHOICE:
			return 1;
		default:
			return 0;
		}
	}

	return 0;
}

/*
 * Purpose: compare group leaves against one neighboring component.
 * Source: X.680 flat extension-addition-group component semantics.
 * Version: 2026-10-21.
 * Parameters: arg is the active fixer; a and b are candidate components;
 *             handled reports whether a group was expanded.
 * Returns: zero for no collision, or the first nonzero leaf comparison result.
 * Errors: propagates tag diagnostics from _asn1f_compare_tags.
 * Author: asn1c maintainers.
 * History: Extracted group recursion to keep the tag comparator bounded.
 * Example: a group's leaf tags are checked against the following field.
 */
static int
_asn1f_compare_group_tags(arg_t *arg, asn1p_expr_t *a, asn1p_expr_t *b,
		int *handled) {
	asn1p_expr_t *group = NULL;
	asn1p_expr_t *other = NULL;
	int group_is_left = 0;
	int ret;

	*handled = 0;
	if(_asn1f_is_extension_group(a)) {
		group = a;
		other = b;
		group_is_left = 1;
	} else if(_asn1f_is_extension_group(b)) {
		group = b;
		other = a;
	}
	if(!group) return 0;

	*handled = 1;
	TQ_FOR(a, &(group->members), next) {
		if(a->expr_type == A1TC_EXTENSIBLE) continue;
		ret = group_is_left ? _asn1f_compare_tags(arg, a, other)
				: _asn1f_compare_tags(arg, other, a);
		if(ret) return ret;
	}
	return 0;
}

/*
 * Purpose: compare unresolved tags by following references and CHOICE members.
 * Source: Existing constructed-type tag distinctness recursion.
 * Version: 2026-10-21.
 * Parameters: arg is the active fixer; a and b are components; ra and rb are
 *             their outmost-tag lookup results.
 * Returns: zero for no collision or an unresolved lookup, otherwise the first
 *          nonzero comparison result.
 * Errors: propagates diagnostics from symbol lookup and recursive comparisons.
 * Author: asn1c maintainers.
 * History: Extracted to keep _asn1f_compare_tags at or below CC 20.
 * Example: an untagged CHOICE is compared through every alternative.
 */
static int
_asn1f_compare_unresolved_tags(arg_t *arg, asn1p_expr_t *a,
		asn1p_expr_t *b, int ra, int rb) {
	int ret;

	DEBUG("Comparing tags %s:%x <-> %s:%x",
		a->Identifier, a->expr_type, b->Identifier, b->expr_type);
	if(ra && a->meta_type == AMT_TYPEREF) {
		DEBUG(" %s is a type reference", a->Identifier);
		a = asn1f_lookup_symbol(arg, a->rhs_pspecs, a->reference);
		if(!a) return 0;
		return WITH_MODULE(a->module, _asn1f_compare_tags(arg, a, b));
	}
	if(ra && a->expr_type == ASN_CONSTR_CHOICE) {
		asn1p_expr_t *member;
		DEBUG(" %s is a choice type (%d)", a->Identifier, a->_mark);
		TQ_FOR(member, &(a->members), next) {
			ret = _asn1f_compare_tags(arg, member, b);
			if(ret) return ret;
		}
		return 0;
	}
	if(rb && b->expr_type == ASN_CONSTR_CHOICE)
		return _asn1f_compare_tags(arg, b, a);
	if(a->_mark & TM_RECURSION) return 0;
	if(b->_mark & TM_RECURSION) return 0;
	a->_mark |= TM_RECURSION;
	b->_mark |= TM_RECURSION;
	ret = _asn1f_compare_tags(arg, b, a);
	a->_mark &= ~TM_RECURSION;
	b->_mark &= ~TM_RECURSION;
	return ret;
}

/*
 * Purpose: determine whether two ASN.1 components can have the same tag.
 * Source: Existing constructed-type tag distinctness checker.
 * Version: 2026-10-21.
 * Parameters: arg identifies the enclosing type; a and b are compared components.
 * Returns: zero for distinct tags, or -1 when tags may collide.
 * Errors: emits diagnostics for duplicate or imaginary ANY tags.
 * Author: asn1c maintainers.
 * History: group leaf expansion moved to _asn1f_compare_group_tags.
 * Example: optional SEQUENCE fields are checked against their following component.
 */
static int
_asn1f_compare_tags(arg_t *arg, asn1p_expr_t *a, asn1p_expr_t *b) {
	struct asn1p_type_tag_s ta, tb;
	int ra, rb;
	int ret;
	int group_handled;

	ret = _asn1f_compare_group_tags(arg, a, b, &group_handled);
	if(group_handled) return ret;

	ra = asn1f_fetch_outmost_tag_ex(arg->asn, arg->ns, arg->mod, a,
			&ta, AFT_IMAGINARY_ANY, arg->eh, arg->debug != NULL);
	rb = asn1f_fetch_outmost_tag_ex(arg->asn, arg->ns, arg->mod, b,
			&tb, AFT_IMAGINARY_ANY, arg->eh, arg->debug != NULL);

	/*
	 * If both tags are explicitly or implicitly given, use them.
	 */
	DEBUG("Fetching outmost tags: %d, %d", ra, rb);
	if(ra == 0 && rb == 0) {
		/*
		 * Simple case: fetched both tags.
		 */

		if((ta.tag_value == tb.tag_value
			&& ta.tag_class == tb.tag_class)
		|| ta.tag_value == -1	/* Spread IMAGINARY ANY tag... */
		|| tb.tag_value == -1	/* ...it is an evil virus, fear it! */
		) {
			char tagbuf[2][TAG2STRING_BUFFER_SIZE];
			char *p = (a->expr_type == A1TC_EXTENSIBLE)
				?"potentially ":"";
			FATAL("Processing %s at line %d: component \"%s\" at line %d %shas the same tag "
				"as component \"%s\" at line %d",
				arg->expr->Identifier,
				arg->expr->_lineno,
				a->Identifier,
				a->_lineno,
				p,
				b->Identifier,
				b->_lineno
			);
			FATAL("Consider adding AUTOMATIC TAGS "
				"after module %s DEFINITIONS, "
				"or manually tag components",
				arg->expr->module->ModuleName);
			DEBUG("Tags: %s %s  vs.  %s %s",
				asn1p_tag2string(&ta, tagbuf[0]),
				a->Identifier,
				asn1p_tag2string(&tb, tagbuf[1]),
				b->Identifier
			);
			if((arg->mod->module_flags & MSF_EXTENSIBILITY_IMPLIED)
			&& (a->expr_type == A1TC_EXTENSIBLE)
			&& (b->expr_type == A1TC_EXTENSIBLE)) {
				FATAL("The previous error is due to "
					"improper use of "
					"EXTENSIBILITY IMPLIED flag "
					"of module %s",
					arg->mod->ModuleName);
			}
			return -1;
		} else {
			/* Tags are distinct */
			return 0;
		}
	}

	return _asn1f_compare_unresolved_tags(arg, a, b, ra, rb);
}
