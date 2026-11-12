#include "asn1c_internal.h"
#include "asn1c_lang.h"
#include "asn1c_out.h"
#include "asn1c_save.h"
#include "asn1c_ioc.h"
#include "asn1c_naming.h"
#include "asn1c_encoding.h"
#include "asn1c_constraint.h"
#include "asn1c_rust.h"
#include <asn1fix_export.h>

/* Global integer native storage policy; see asn1compiler.h */
asn_integer_native_type_e asn1c_integer_native_type = AINT_NATIVE_AUTO;
asn_target_long_size_e asn1c_target_long_size = ASN_TARGET_LONG_AUTO;

static void default_logger_cb(int, const char *fmt, ...);
static int compiler_fatal_count;	/* FATAL diagnostics by default_logger_cb */
static int asn1c_compile_expr(arg_t *arg, const asn1c_ioc_table_and_objset_t *);
static int asn1c_detach_streams(asn1p_expr_t *expr);
static int asn1_compile_c(asn1p_t *, const char *, const char *,
                          enum asn1c_flags, int, int, char **, int);
static int asn1c_validate_dispatch_arguments(asn1p_t *, const char *,
                                            const char *, int, int, char **,
                                            asn1c_target_e);
static int asn1c_prepare_dependencies(arg_t *, enum asn1c_flags);
static int asn1c_apply_encoding_controls_to_modules(asn1p_t *);
static int asn1c_compile_modules(arg_t *, enum asn1c_flags);
static int asn1c_compile_module(arg_t *, asn1p_module_t *, enum asn1c_flags);
static void asn1c_cleanup_streams(asn1p_t *);
static void asn1c_mark_pdu_dependencies(arg_t *arg);
static void asn1c_mark_expr_dependencies(arg_t *arg, asn1p_expr_t *expr);
static void asn1c_mark_ioc_table_dependencies(arg_t *arg, asn1p_ioc_table_t *ioc_table);

/*
 * Dispatch a fixed tree to the selected complete code-generation backend.
 * Parameters: compiler inputs retain the historical asn1_compile() meanings;
 * target_options selects C or supplies Rust runtime and codec settings.
 * Returns zero on success or a negative error code; does not throw. Original
 * source: new dispatcher around the existing C compiler. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: C remains the
 * default. Example: asn1_compile_with_target(..., &rust_options).
 */
int
asn1_compile_with_target(asn1p_t *asn, const char *datadir,
                         const char *destdir, enum asn1c_flags flags,
                         int argc, int optc, char **argv, int complex_threshold,
                         const asn1c_target_options_t *target_options) {
	asn1c_target_e target = target_options ? target_options->target
	                                       : ASN1C_TARGET_C;
	if(target != ASN1C_TARGET_C && target != ASN1C_TARGET_RUST) {
		errno = EINVAL;
		fprintf(stderr, "asn1c: invalid code-generation target\n");
		return -1;
	}
	if(asn1c_validate_dispatch_arguments(asn, datadir, destdir, argc, optc,
	                                      argv, target)) return -1;
	if(target_options && target_options->target == ASN1C_TARGET_RUST) {
		return asn1c_rust_compile(asn, target_options->rust_runtime_dir,
		                           destdir, target_options->rust_codecs,
		                           !!(flags & A1C_TOLERANT_UTC_TIME));
	}
	return asn1_compile_c(asn, datadir, destdir, flags, argc, optc, argv,
	                      complex_threshold);
}

/*
 * Validate pointers and argument counts before dispatch can dereference them.
 * Parameters: asn is the fixed tree; datadir and destdir are C asset/output
 * paths; argc, optc, and argv describe original options; target controls which
 * paths are required. Returns zero or -1 with errno set to EINVAL. Original
 * source: new public target dispatcher. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: prevents invalid API calls
 * from reaching backend code. Example: rejects argc > 0 with argv == NULL.
 */
static int
asn1c_validate_dispatch_arguments(asn1p_t *asn, const char *datadir,
                                  const char *destdir, int argc, int optc,
                                  char **argv, asn1c_target_e target) {
	int i;
	if(!asn || argc < 0 || optc < 0 || optc > argc || (argc > 0 && !argv))
		goto invalid;
	for(i = 0; i < argc; i++) {
		if(!argv[i]) goto invalid;
	}
	if(target == ASN1C_TARGET_C && (!datadir || !destdir)) goto invalid;
	return 0;
invalid:
	errno = EINVAL;
	fprintf(stderr, "asn1c: invalid compiler input or argument vector\n");
	return -1;
}

/*
 * Preserve the existing public C compiler entry point and defaults.
 * Parameters: all arguments are passed unchanged to the C backend. Returns
 * zero on success or a negative error code; does not throw. Original source:
 * historical asn1_compile() API. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: delegates through target
 * dispatch with C selected. Example: existing C callers are unchanged.
 */
int
asn1_compile(asn1p_t *asn, const char *datadir, const char *destdir,
             enum asn1c_flags flags, int argc, int optc, char **argv,
             int complex_threshold) {
	const asn1c_target_options_t c_options = {ASN1C_TARGET_C, NULL, 0};
	return asn1_compile_with_target(asn, datadir, destdir, flags, argc, optc,
	                                argv, complex_threshold, &c_options);
}

/*
 * Run the unchanged C compilation pipeline for the compatibility backend.
 * Parameters: arguments preserve the historical asn1_compile() API contract.
 * Returns zero on success or a negative error code. Original source: existing
 * C compiler implementation. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: extracted behind target dispatch without
 * changing C behavior. Example: called only by asn1_compile_with_target().
 */
static int
asn1_compile_c(asn1p_t *asn, const char *datadir, const char *destdir,
		 enum asn1c_flags flags, int argc, int optc, char **argv,
		 int complex_threshold) {
	arg_t arg_s = {0};
	arg_t *arg = &arg_s;
	int ret;
	int fatal_count_at_start = compiler_fatal_count;

	c_name_clash_finder_init();

	/*
	 * Initialize target language.
	 */
	ret = asn1c_with_language(ASN1C_LANGUAGE_C);
	assert(ret == 0);

	memset(arg, 0, sizeof(*arg));
	arg->default_cb = asn1c_compile_expr;
	arg->logger_cb = default_logger_cb;
	arg->flags = flags;
	arg->asn = asn;
	arg->complex_threshold = complex_threshold;

	ret = asn1c_prepare_dependencies(arg, flags);
	if(ret) return ret > 0 ? 0 : ret;
	if(asn1c_apply_encoding_controls_to_modules(asn)) return -1;
	ret = asn1c_compile_modules(arg, flags);
	if(ret) return ret;

	if(c_name_clash(arg)) {
		if(arg->flags & A1C_COMPOUND_NAMES) {
			FATAL("Name clashes encountered even with -fcompound-names flag");
			/* Proceed further for better debugging. */
		} else {
			FATAL("Use \"-fcompound-names\" flag to asn1c to resolve name clashes");
			if(arg->flags & A1C_PRINT_COMPILED) {
				/* Proceed further for better debugging. */
			} else {
				return -1;
			}
		}
	}

	DEBUG("Saving compiled data");

	c_name_clash_finder_destroy();

	/*
	 * Save or print out the compiled result.
	 */
	if(asn1c_save_compiled_output(arg, datadir, destdir, argc, optc, argv))
		return -1;

	asn1c_cleanup_streams(asn);

	/*
	 * Some FATAL diagnostics let the compilation proceed "for better
	 * debugging". The output is then incomplete: report a failure.
	 */
	if(compiler_fatal_count > fatal_count_at_start)
		return -1;

	return 0;
}

/*
 * Validate and perform dependency-only compiler modes before code generation.
 * Parameters: arg holds the fixed tree and callbacks; flags select PDU behavior.
 * Returns 1 when dependency listing completed, 0 to continue, or -1 on error.
 * Original source: extracted from the historical C compiler. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: bounded
 * the C target dispatcher. Example: asn1c_prepare_dependencies(arg, flags).
 */
static int
asn1c_prepare_dependencies(arg_t *arg, enum asn1c_flags flags) {
	if(flags & A1C_LIST_DEPS) {
		asn1p_module_t *module;
		if(!(flags & (A1C_PDU_ALL | A1C_PDU_AUTO | A1C_PDU_TYPE))) {
			FATAL("-flist-deps requires -pdu={all|auto|Type} option");
			return -1;
		}
		asn1c_mark_pdu_dependencies(arg);
		TQ_FOR(module, &arg->asn->modules, mod_next) {
			TQ_FOR(arg->expr, &module->members, next) {
				if(arg->expr->_mark & TM_PDU_DEPENDENCY)
					printf("%s\n", arg->expr->Identifier);
			}
		}
		return 1;
	}
	if(flags & A1C_GEN_ONLY_PDU_DEPS) {
		if(!(flags & (A1C_PDU_ALL | A1C_PDU_AUTO | A1C_PDU_TYPE))) {
			FATAL("-fgen-only-pdu-deps requires -pdu={all|auto|Type} option");
			return -1;
		}
		asn1c_mark_pdu_dependencies(arg);
	}
	return 0;
}

/*
 * Apply C encoding instructions to every fixed module before visiting types.
 * Parameters: asn is the fixed tree. Returns zero on success or -1 if a module
 * fails processing. Original source: historical C compiler loop. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: extracted
 * to keep target compilation within source-unit limits. Example: called before
 * asn1c_compile_modules().
 */
static int
asn1c_apply_encoding_controls_to_modules(asn1p_t *asn) {
	asn1p_module_t *module;
	TQ_FOR(module, &asn->modules, mod_next) {
		if(asn1c_apply_encoding_controls(asn, module) < 0) return -1;
	}
	return 0;
}

/*
 * Compile all selected top-level declarations in the fixed tree.
 * Parameters: arg is the C backend context; flags select PDU filtering.
 * Returns zero or the first type compilation error. Original source: extracted
 * from the historical C compiler. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: bounded C backend callable. Example:
 * asn1c_compile_modules(arg, flags).
 */
static int
asn1c_compile_modules(arg_t *arg, enum asn1c_flags flags) {
	asn1p_module_t *module;
	TQ_FOR(module, &arg->asn->modules, mod_next) {
		int ret = asn1c_compile_module(arg, module, flags);
		if(ret) return ret;
	}
	return 0;
}

/*
 * Compile selected declarations belonging to one ASN.1 module.
 * Parameters: arg is the backend context; module supplies declarations; flags
 * select PDU filtering. Returns zero or the first visitor error. Original
 * source: extracted from the historical C type loop. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: bounded per-module
 * emission. Example: asn1c_compile_module(arg, module, flags).
 */
static int
asn1c_compile_module(arg_t *arg, asn1p_module_t *module,
		     enum asn1c_flags flags) {
	TQ_FOR(arg->expr, &module->members, next) {
		compiler_streams_t *streams;
		int ret;
		if(arg->expr->_mark & TM_ENCODING_INSTRUCTION) continue;
		if((flags & A1C_GEN_ONLY_PDU_DEPS)
		   && !(arg->expr->_mark & TM_PDU_DEPENDENCY)) {
			DEBUG("Skipping non-PDU type: %s", arg->expr->Identifier);
			continue;
		}
		arg->ns = asn1_namespace_new_from_module(module, 0);
		if(asn1c_attach_streams(arg->expr)) return -1;
		streams = arg->expr->data;
		streams->target = OT_TYPE_DECLS;
		arg->target = streams;
		ret = asn1c_compile_expr(arg, NULL);
		if(ret) {
			FATAL("Cannot compile \"%s\" (%x:%x) at line %d",
				arg->expr->Identifier, arg->expr->expr_type,
				arg->expr->meta_type, arg->expr->_lineno);
			return ret;
		}
		asn1_namespace_free(arg->ns);
		arg->ns = NULL;
	}
	return 0;
}

/*
 * Detach all temporary output streams from fixed-tree expressions.
 * Parameters: asn is the tree whose compiler streams are released. Returns no
 * value and raises no exception. Original source: historical C compiler loop.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: extracted during bounded C target dispatch. Example:
 * asn1c_cleanup_streams(asn).
 */
static void
asn1c_cleanup_streams(asn1p_t *asn) {
	asn1p_module_t *module;
	asn1p_expr_t *expr;
	TQ_FOR(module, &asn->modules, mod_next) {
		TQ_FOR(expr, &module->members, next)
			asn1c_detach_streams(expr);
	}
}

static int
asn1c_compile_expr(arg_t *arg, const asn1c_ioc_table_and_objset_t *opt_ioc) {
	asn1p_expr_t *expr = arg->expr;
	int (*type_cb)(arg_t *);
	int ret;

	assert((int)expr->meta_type >= AMT_INVALID);
	assert(expr->meta_type < AMT_EXPR_META_MAX);
	assert((int)expr->expr_type >= A1TC_INVALID);
	assert(expr->expr_type < ASN_EXPR_TYPE_MAX);

	type_cb = asn1_lang_map[expr->meta_type][expr->expr_type].type_cb;
	if(type_cb) {

		DEBUG("Compiling %s at line %d",
			expr->Identifier,
			expr->_lineno);

		if(expr->lhs_params && expr->spec_index == -1) {
			int i;
			ret = 0;
			DEBUG("Parameterized type %s at line %d: %s (%d)",
				expr->Identifier, expr->_lineno,
				expr->specializations.pspecs_count
				? "compiling" : "unused, skipping",
				expr->specializations.pspecs_count);
			for(i = 0; i<expr->specializations.pspecs_count; i++) {
				arg->expr = expr->specializations
						.pspec[i].my_clone;
				ret = asn1c_compile_expr(arg, opt_ioc);
				if(ret) break;
			}
			arg->expr = expr;	/* Restore */
		} else {
			ret = type_cb(arg);
		}
	} else {
		ret = -1;
		/*
		 * Even if the target language compiler does not know
		 * how to compile the given expression, we know that
		 * certain expressions need not to be compiled at all.
		 */
		switch(expr->meta_type) {
		case AMT_OBJECT:
		case AMT_OBJECTCLASS:
		case AMT_OBJECTFIELD:
		case AMT_VALUE:
		case AMT_VALUESET:
			ret = 0;
			break;
		default:
			break;
		}
	}

	if(ret == -1) {
		FATAL("Cannot compile \"%s\" (%x:%x) at line %d",
			arg->expr->Identifier,
			arg->expr->expr_type,
			arg->expr->meta_type,
			arg->expr->_lineno);
		OUT("#error Cannot compile \"%s\" (%x/%x) at line %d\n",
			arg->expr->Identifier,
			arg->expr->meta_type,
			arg->expr->expr_type,
			arg->expr->_lineno
		);
	}

	return ret;
}

int
asn1c_attach_streams(asn1p_expr_t *expr) {
	compiler_streams_t *cs;
	int i;

	if(expr->data)
		return 0;	/* Already attached? */

	expr->data = calloc(1, sizeof(compiler_streams_t));
	if(expr->data == NULL)
		return -1;

	cs = expr->data;
	for(i = 0; i < OT_MAX; i++) {
		TQ_INIT(&(cs->destination[i].chunks));
	}

	return 0;
}

int
asn1c_detach_streams(asn1p_expr_t *expr) {
	compiler_streams_t *cs;
	out_chunk_t *m;
	int i;

	if(!expr->data)
		return 0;	/* Already detached? */

	cs = expr->data;
	for(i = 0; i < OT_MAX; i++) {
		while((m = TQ_REMOVE(&(cs->destination[i].chunks), next))) {
			free(m->buf);
			free(m);
		}
	}
	free(expr->data);
	expr->data = (void *)NULL;

	return 0;
}

static void
default_logger_cb(int _severity, const char *fmt, ...) {
	va_list ap;
	char *pfx = "";

	switch(_severity) {
	case -1: pfx = "DEBUG: "; break;
	case 0: pfx = "WARNING: "; break;
	case 1: pfx = "FATAL: "; compiler_fatal_count++; break;
	}

	fprintf(stderr, "%s", pfx);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static void
asn1c_debug_expr_naming(arg_t *arg) {
    asn1p_expr_t *expr = arg->expr;

    printf("%s: ", expr->Identifier);
    printf("%s\n", c_names_format(c_name(arg)));

    printf("\n");

}

void
asn1c_debug_type_naming(asn1p_t *asn, enum asn1c_flags flags,
                        char **asn_type_names) {
    arg_t arg_s = {0};
    arg_t *arg = &arg_s;
	asn1p_module_t *mod;

    memset(arg, 0, sizeof(*arg));
	arg->logger_cb = default_logger_cb;
	arg->flags = flags;
	arg->asn = asn;

	c_name_clash_finder_init();

	/*
	 * Compile each individual top level structure.
	 */
	TQ_FOR(mod, &(asn->modules), mod_next) {
        int namespace_shown = 0;
		TQ_FOR(arg->expr, &(mod->members), next) {
			arg->ns = asn1_namespace_new_from_module(mod, 0);

            for(char **t = asn_type_names; *t; t++) {
                if(strcmp(*t, arg->expr->Identifier) == 0) {
                    if(!namespace_shown) {
                        namespace_shown = 1;
                        printf("Namespace %s\n",
                               asn1_namespace_string(arg->ns));
                    }
                    asn1c_debug_expr_naming(arg);
                }
            }

            asn1_namespace_free(arg->ns);
			arg->ns = 0;
		}
	}

	c_name_clash_finder_destroy();
}

/*
 * Helper to mark IOC table types as dependencies.
 */
static void
asn1c_mark_ioc_table_dependencies(arg_t *arg, asn1p_ioc_table_t *ioc_table) {
	if(!ioc_table) return;

	for(size_t rn = 0; rn < ioc_table->rows; rn++) {
		asn1p_ioc_row_t *row = ioc_table->row[rn];
		for(size_t cn = 0; cn < row->columns; cn++) {
			struct asn1p_ioc_cell_s *cell = &row->column[cn];
			if(cell->value) {
				DEBUG("IOC cell: meta=%d expr=%d has_ref=%d has_mod=%d id=%s",
					cell->value->meta_type,
					cell->value->expr_type,
					cell->value->reference ? 1 : 0,
					cell->value->module ? 1 : 0,
					cell->value->Identifier ? cell->value->Identifier : "(null)");
				/* 
				 * For type references (AMT_TYPEREF), resolve and mark the target type.
				 * We use the cell value's module namespace for symbol lookup since
				 * the type may be defined in a different module than the current context.
				 */
				if(cell->value->meta_type == AMT_TYPEREF && cell->value->reference) {
					asn1p_expr_t *ref_expr = NULL;
					if(cell->value->module) {
						ref_expr = WITH_MODULE_NAMESPACE(
							cell->value->module, cell_ns,
							asn1f_lookup_symbol_ex(arg->asn, cell_ns, 
								cell->value, cell->value->reference));
					} else {
						ref_expr = asn1f_lookup_symbol_ex(arg->asn,
							arg->ns, cell->value, cell->value->reference);
					}
					DEBUG("IOC cell ref resolved (AMT_TYPEREF): %s -> %s",
						cell->value->Identifier ? cell->value->Identifier : "(null)",
						ref_expr ? (ref_expr->Identifier ? ref_expr->Identifier : "(no id)") : "(not found)");
					if(ref_expr) {
						asn1c_mark_expr_dependencies(arg, ref_expr);
					}
				} else if(cell->value->expr_type == A1TC_REFERENCE && cell->value->reference) {
					/* For other type references */
					asn1p_expr_t *ref_expr = NULL;
					if(cell->value->module) {
						ref_expr = WITH_MODULE_NAMESPACE(
							cell->value->module, cell_ns,
							asn1f_lookup_symbol_ex(arg->asn, cell_ns, 
								cell->value, cell->value->reference));
					} else {
						ref_expr = asn1f_lookup_symbol_ex(arg->asn,
							arg->ns, cell->value, cell->value->reference);
					}
					DEBUG("IOC cell ref resolved (A1TC_REFERENCE): %s -> %s",
						cell->value->Identifier ? cell->value->Identifier : "(null)",
						ref_expr ? (ref_expr->Identifier ? ref_expr->Identifier : "(no id)") : "(not found)");
					if(ref_expr) {
						asn1c_mark_expr_dependencies(arg, ref_expr);
					}
				} else {
					/* Recursively mark the cell value and its members */
					asn1c_mark_expr_dependencies(arg, cell->value);
				}
			}
		}
	}
}

/*
 * Recursively mark all dependencies of a given expression as PDU dependencies.
 */
static void
asn1c_mark_expr_dependencies(arg_t *arg, asn1p_expr_t *expr) {
	asn1p_expr_t *member;

	if(!expr) return;

	/* Avoid infinite recursion */
	if(expr->_mark & TM_PDU_DEPENDENCY) return;
	if(expr->_mark & TM_RECURSION) return;

	/* Mark this expression as a PDU dependency */
	expr->_mark |= TM_PDU_DEPENDENCY;

	DEBUG("Marking %s as PDU dependency", expr->Identifier);

	/* Mark recursion to avoid infinite loops */
	expr->_mark |= TM_RECURSION;

	/* A CONTAINING type is a generated descriptor dependency even when the
	 * outer BIT/OCTET STRING has no ordinary type-reference member. */
	if(expr->combined_constraints) {
		asn1p_expr_t *contained = asn1c_find_contained_type(arg, expr);
		if(contained) asn1c_mark_expr_dependencies(arg, contained);
	}

	/* For type references, find and mark the referenced type */
	if(expr->expr_type == A1TC_REFERENCE && expr->reference) {
		/*
		 * Use the expression's module namespace if available, otherwise
		 * fall back to arg->ns. This is important for members that
		 * reference types in different modules.
		 */
		asn1p_expr_t *ref_expr = NULL;
		if(expr->module) {
			ref_expr = WITH_MODULE_NAMESPACE(
				expr->module, expr_ns,
				asn1f_lookup_symbol_ex(arg->asn, expr_ns, expr, expr->reference));
		} else {
			ref_expr = asn1f_lookup_symbol_ex(arg->asn, 
				arg->ns, expr, expr->reference);
		}
		if(ref_expr) {
			/*
			 * If this is a forked/specialized type (spec_index >= 0),
			 * we need to also mark the base parameterized type.
			 * The base type is what gets compiled into a .c/.h file.
			 *
			 * Since asn1f_lookup_symbol_ex returns a fork when rhs_pspecs is present,
			 * we need to mark the base type separately.
			 */
			if(ref_expr->spec_index >= 0 && expr->reference->comp_count > 0) {
				/* This is a fork - find and mark the base parameterized type */
				const char *base_name = expr->reference->components[0].name;
				asn1p_module_t *mod;
				TQ_FOR(mod, &(arg->asn->modules), mod_next) {
					asn1p_expr_t *base_type;
					TQ_FOR(base_type, &(mod->members), next) {
						if(base_type->Identifier 
						   && strcmp(base_type->Identifier, base_name) == 0
						   && base_type->lhs_params) {
							/* Found the base parameterized type.
							 * Mark it directly (but don't recurse into its formal
							 * parameter members, which would fail).
							 * Then mark all its specializations which have concrete types. */
							if(!(base_type->_mark & TM_PDU_DEPENDENCY)) {
								base_type->_mark |= TM_PDU_DEPENDENCY;
								for(int i = 0; i < base_type->specializations.pspecs_count; i++) {
									asn1p_expr_t *spec = base_type->specializations.pspec[i].my_clone;
									if(spec) {
										asn1c_mark_expr_dependencies(arg, spec);
									}
								}
							}
							break;
						}
					}
				}
			}

			asn1c_mark_expr_dependencies(arg, ref_expr);

			/*
			 * For parameterized type references with rhs_pspecs,
			 * also mark the appropriate specialization.
			 */
			if(expr->rhs_pspecs && ref_expr->lhs_params) {
				for(int i = 0; i < ref_expr->specializations.pspecs_count; i++) {
					asn1p_expr_t *spec = ref_expr->specializations.pspec[i].my_clone;
					if(spec) {
						asn1c_mark_expr_dependencies(arg, spec);
					}
				}
			}
		}
	}

	/*
	 * For parameterized types, also mark all their specializations
	 * since they may be needed for types that reference them.
	 */
	if(expr->lhs_params) {
		for(int i = 0; i < expr->specializations.pspecs_count; i++) {
			asn1p_expr_t *spec = expr->specializations.pspec[i].my_clone;
			if(spec) {
				asn1c_mark_expr_dependencies(arg, spec);
			}
		}
	}

	/* Recursively mark members of compound types */
	TQ_FOR(member, &(expr->members), next) {
		asn1c_mark_expr_dependencies(arg, member);

		/*
		 * Check if this member has a component relation constraint that
		 * references an Information Object Set. If so, mark all types
		 * in that IOC table as dependencies.
		 */
		const asn1p_constraint_t *cr_ct =
			asn1p_get_component_relation_constraint(member->constraints);
		if(cr_ct) {
			asn1p_ref_t *objset_ref =
				asn1c_get_information_object_set_reference_from_constraint(arg, cr_ct);
			if(objset_ref) {
				asn1p_expr_t *objset = NULL;
				if(expr->module) {
					objset = WITH_MODULE_NAMESPACE(
						expr->module, expr_ns,
						asn1f_lookup_symbol_ex(arg->asn, expr_ns, expr, objset_ref));
				} else {
					objset = asn1f_lookup_symbol_ex(arg->asn,
						arg->ns, expr, objset_ref);
				}
				if(objset && objset->ioc_table) {
					asn1c_mark_ioc_table_dependencies(arg, objset->ioc_table);
				}
			}
		}
	}

	/* Mark rhs_pspecs (right-hand side parameter specs) as dependencies.
	 * Also traverse IOC tables from pspecs which may be information object sets.
	 * pspecs can have nested structures like { { SomeIOC } }, so we need to
	 * traverse members recursively. */
	if(expr->rhs_pspecs) {
		asn1p_expr_t *pspec;
		TQ_FOR(pspec, &(expr->rhs_pspecs->members), next) {
			asn1c_mark_expr_dependencies(arg, pspec);
			/* If the pspec is a reference to an information object set,
			 * look it up and traverse its IOC table */
			if(pspec->expr_type == A1TC_REFERENCE && pspec->reference) {
				asn1p_expr_t *ref_expr = NULL;
				if(pspec->module) {
					ref_expr = WITH_MODULE_NAMESPACE(
						pspec->module, pspec_ns,
						asn1f_lookup_symbol_ex(arg->asn, pspec_ns, pspec, pspec->reference));
				} else {
					ref_expr = asn1f_lookup_symbol_ex(arg->asn,
						arg->ns, pspec, pspec->reference);
				}
				if(ref_expr && ref_expr->ioc_table) {
					asn1c_mark_ioc_table_dependencies(arg, ref_expr->ioc_table);
				}
			}
			/* Also check nested members (for { { IOC } } style params) */
			asn1p_expr_t *nested;
			TQ_FOR(nested, &(pspec->members), next) {
				if(nested->expr_type == A1TC_REFERENCE && nested->reference) {
					asn1p_expr_t *ref_expr = NULL;
					if(nested->module) {
						ref_expr = WITH_MODULE_NAMESPACE(
							nested->module, nested_ns,
							asn1f_lookup_symbol_ex(arg->asn, nested_ns, nested, nested->reference));
					} else {
						ref_expr = asn1f_lookup_symbol_ex(arg->asn,
							arg->ns, nested, nested->reference);
					}
					if(ref_expr && ref_expr->ioc_table) {
						asn1c_mark_ioc_table_dependencies(arg, ref_expr->ioc_table);
					}
				}
			}
		}
	}

	/*
	 * Mark types referenced in Information Object Class tables directly on this expr.
	 * This ensures that when -fgen-only-pdu-deps is used, types referenced
	 * in IOC tables (e.g., Reset, F1SetupRequest in F1AP) are also generated.
	 */
	asn1c_mark_ioc_table_dependencies(arg, expr->ioc_table);

	/* Clear recursion marker */
	expr->_mark &= ~TM_RECURSION;
}

/*
 * Mark all PDU types and their dependencies.
 */
static void
asn1c_mark_pdu_dependencies(arg_t *arg) {
	asn1p_module_t *mod;
	asn1p_expr_t *expr;

	/* First, mark the PDUs themselves */
	TQ_FOR(mod, &(arg->asn->modules), mod_next) {
		TQ_FOR(expr, &(mod->members), next) {
			/* Skip types that shouldn't be included in PDU collection */
			if(!asn1_lang_map[expr->meta_type][expr->expr_type].type_cb ||
				(expr->meta_type == AMT_VALUE)) {
				continue;
			}

			/* Skip parameterized types */
			if(expr->lhs_params) {
				continue;
			}

			/* Check if this is a PDU type we should generate */
			int is_pdu = 0;
			if((arg->flags & A1C_PDU_ALL)) {
				is_pdu = 1;
			} else if((arg->flags & A1C_PDU_AUTO) && !expr->_type_referenced) {
				is_pdu = 1;
			} else if(!(arg->flags & (A1C_PDU_ALL | A1C_PDU_AUTO | A1C_PDU_TYPE))
				&& !expr->_type_referenced) {
				is_pdu = 1;
			} else if(arg->flags & A1C_PDU_TYPE) {
				/* Check if this type is in the PDU list */
				if(asn1c__pdu_type_lookup(expr->Identifier)) {
					is_pdu = 1;
				}
			}

			if(is_pdu) {
				DEBUG("Found PDU type: %s", expr->Identifier);
				/* Set up namespace for this module before marking dependencies */
				arg->ns = asn1_namespace_new_from_module(mod, 0);
				asn1c_mark_expr_dependencies(arg, expr);
				asn1_namespace_free(arg->ns);
				arg->ns = 0;
			}
		}
	}
}
