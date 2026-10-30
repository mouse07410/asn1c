#include "asn1c_internal.h"
#include "asn1c_rust.h"
#include <asn1fix_crange.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdint.h>

#ifdef _WIN32
#include <direct.h>
#include <process.h>
#define rust_mkdir(path, mode) _mkdir(path)
#define rust_getpid() _getpid()
#else
#include <sys/stat.h>
#include <unistd.h>
#define rust_mkdir(path, mode) mkdir(path, mode)
#define rust_getpid() getpid()
#endif

/* Direct primitives and flat required-field UPER SEQUENCE use this backend. */
#define RUST_CODEC_UPER ((uint64_t)A1C_GEN_UPER)
#define RUST_CODEC_BER ((uint64_t)A1C_GEN_BER)
#define RUST_CODEC_CER ((uint64_t)A1C_GEN_CER)
#define RUST_CODEC_APER ((uint64_t)A1C_GEN_APER)
#define RUST_CODEC_OER ((uint64_t)A1C_GEN_OER)
#define RUST_CODEC_JER ((uint64_t)A1C_GEN_JER)
#define RUST_CODEC_MASK (RUST_CODEC_UPER | RUST_CODEC_BER | RUST_CODEC_CER \
                         | RUST_CODEC_APER | RUST_CODEC_OER | RUST_CODEC_JER)
#define RUST_CONSTRAINT_DEPTH_LIMIT 128
#define RUST_IDENTIFIER_LIMIT 80
#define RUST_MANIFEST_LIMIT (1024 * 1024)
#define RUST_MANIFEST_ENTRY_LIMIT 4096
#define RUST_SEQUENCE_FIELD_LIMIT 64
#define RUST_SEQUENCE_DEPTH_LIMIT 16
#define RUST_SEQUENCE_NODE_LIMIT 64
#define RUST_SEQUENCE_WORK_LIMIT 256
#define RUST_MODULE_NESTED_NAME_LIMIT 4096

/*
 * Paths used while staging and validating a generated crate.
 * Each member is a state variable for the current output transaction.
 */
typedef struct rust_output_s {
    char target[PATH_MAX]; /* Final project path state variable. */
    char stage[PATH_MAX];  /* Private staging directory state variable. */
    char backup[PATH_MAX]; /* Previous owned project path state variable. */
    int stage_created;     /* Staging-directory state variable. */
    int target_moved;      /* Backup-rename state variable. */
} rust_output_t;

static char *rust_identifier(const char *, int);
static char *rust_enum_variant(const char *);
static int rust_check_tree(asn1p_t *, uint64_t);
static int rust_check_module(asn1p_t *, asn1p_module_t *, int *, uint64_t);
static int rust_check_module_name(asn1p_t *, asn1p_module_t *);
static int rust_check_module_types(asn1p_module_t *, int *, uint64_t);
static int rust_check_type_name(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_type(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_sequence(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_sequence_tree(asn1p_module_t *, asn1p_expr_t *,
                                   asn1p_expr_t **, size_t, size_t *, size_t *);
static int rust_check_module_nested_names(asn1p_module_t *);
static int rust_collect_nested_names(asn1p_module_t *, asn1p_expr_t *,
                                     const char *, char **, size_t *, size_t);
static int rust_check_sequence_member(asn1p_module_t *, asn1p_expr_t *);
static int rust_sequence_member_shape_valid(const asn1p_expr_t *);
static int rust_sequence_default_literal(asn1p_expr_t *, char *, size_t);
static int rust_sequence_has_presence(const asn1p_expr_t *);
static int rust_check_sequence_name(asn1p_module_t *, asn1p_expr_t *, asn1p_expr_t *);
static int rust_constraint_supported(const asn1p_constraint_t *, unsigned);
static int rust_integer_bounds(asn1p_expr_t *, int64_t *, int64_t *);
static int rust_size_constraint_supported(const asn1p_constraint_t *, unsigned);
static int rust_fixed_size(asn1p_expr_t *, size_t *);
static int rust_check_enumerated(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_enum_item_valid(const asn1p_expr_t *);
static int rust_enum_name_safe(const char *);
static int rust_enum_unique(asn1p_expr_t *, asn1p_expr_t *);
static size_t rust_enumerated_rank(asn1p_expr_t *, asn1p_expr_t *);
static int rust_stage_project(asn1p_t *, const char *, rust_output_t *, uint64_t);
static int rust_publish_project(rust_output_t *);
static int rust_check_existing(const char *);
static int rust_check_owned_tree(const char *, const char *, const char *);
static int rust_manifest_contains(const char *, const char *);
static int rust_manifest_path_allowed(const char *);
static int rust_validate_manifest(const char *, const char *, size_t *);
static int rust_manifest_line_valid(const char *, const char *, char *);
static int rust_check_directory_entries(const char *);
static int rust_remove_tree(const char *);
static int rust_copy_runtime(const char *, const char *);
static int rust_make_directory(const char *);
static int rust_write_project(asn1p_t *, const char *, const char *, uint64_t);
static int rust_write_module(FILE *, asn1p_module_t *, uint64_t);
static int rust_write_module_file(asn1p_module_t *, const char *, uint64_t);
static int rust_write_type(FILE *, asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_write_boolean(FILE *, const char *, uint64_t);
static int rust_write_boolean_ber(FILE *);
static int rust_write_null(FILE *, const char *, uint64_t);
static int rust_write_null_ber(FILE *);
static int rust_write_integer(FILE *, const char *, int64_t, int64_t, uint64_t);
static int rust_write_string(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_enumerated(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_enumerated_jer(FILE *, asn1p_expr_t *);
static int rust_write_integer_ber(FILE *, const char *, const char *);
static int rust_write_sequence(FILE *, const char *, asn1p_expr_t *, int);
static int rust_write_all_sequences(FILE *, const char *, asn1p_expr_t *, int);
static int rust_write_sequence_field(FILE *, const char *, asn1p_expr_t *);
static int rust_write_sequence_encode_field(FILE *, asn1p_expr_t *);
static int rust_write_sequence_encode_default(FILE *, asn1p_expr_t *, const char *);
static int rust_write_sequence_encode_optional(FILE *, asn1p_expr_t *, const char *);
static int rust_write_sequence_decode_field(FILE *, const char *, asn1p_expr_t *,
                                            size_t *);
static int rust_write_sequence_decode_default(FILE *, asn1p_expr_t *, size_t);
static int rust_write_sequence_encode_presence(FILE *, asn1p_expr_t *);
static int rust_write_sequence_decode_presence(FILE *, asn1p_expr_t *);
static char *rust_nested_type_name(const char *, const asn1p_expr_t *);
static int rust_write_per_oer(FILE *, const char *, const char *,
                              const char *, const char *);
static int rust_write_method_doc(FILE *, const char *, const char *,
                                 const char *, const char *, const char *);
static int rust_write_manifest(asn1p_t *, const char *);
static int rust_copy_file(const char *, const char *);
static int rust_join(char *, size_t, const char *, const char *);
static int rust_write_cargo(FILE *);
static int rust_write_lib(asn1p_t *, const char *);
static int rust_format_bound(char *, size_t, int64_t);
static int rust_is_keyword(const char *);
static int rust_module_filename_reserved(const char *);
static int rust_identifier_append(char *, size_t *, unsigned char, int, int *);
static int rust_identifier_prefix(char *, size_t, size_t, int);
static int rust_check_tree_entry(const char *, const char *, const char *,
                                 const char *);
static int rust_check_owned_file(const char *, const char *, const char *);
static void rust_diagnostic(asn1p_module_t *, asn1p_expr_t *, const char *);

/*
 * Validate and emit a standalone Cargo project for the first Rust slice.
 * Parameters: asn is the fixed tree; runtime_dir is the matching runtime
 * source directory; destdir is the project path or NULL; codecs is the
 * requested codec mask. Returns zero or -1; does not throw. This
 * function stages all files before publishing. Original source: new backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: initial primitive codecs. Example: asn1c_rust_compile(tree,
 * runtime_path, output_path, A1C_GEN_UPER | A1C_GEN_CER).
 */
int
asn1c_rust_compile(asn1p_t *asn, const char *runtime_dir,
                   const char *destdir, uint64_t codecs) {
    rust_output_t output = {{0}, {0}, {0}, 0, 0};

    if(!asn || !runtime_dir || !*runtime_dir) {
        fprintf(stderr, "asn1c: Rust backend is missing its tree or runtime\n");
        return -1;
    }
    if(!codecs || (codecs & ~RUST_CODEC_MASK)) {
        fprintf(stderr,
                "asn1c: Rust backend supports UPER, APER, OER, BER, CER, and JER only\n");
        return -1;
    }
    if(rust_check_tree(asn, codecs)) return -1;
    if(destdir && *destdir) {
        if(strlen(destdir) >= sizeof(output.target)) return -1;
        strcpy(output.target, destdir);
        while(strlen(output.target) > 1
              && output.target[strlen(output.target) - 1] == '/') {
            output.target[strlen(output.target) - 1] = '\0';
        }
    } else {
        strcpy(output.target, "asn1c-rust");
    }
    if(rust_stage_project(asn, runtime_dir, &output, codecs)) return -1;
    if(rust_publish_project(&output)) {
        if(output.stage_created) rust_remove_tree(output.stage);
        return -1;
    }
    return 0;
}

/*
 * Validate module, type, constraint, and naming support before creating files.
 * Parameters: asn is the complete fixed tree; codecs is the requested mask.
 * Returns zero or -1. Diagnostics
 * retain ASN.1 source names and line numbers. No exception is raised. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: initial UPER type gate. Example:
 * rust_check_tree(fixed_tree).
 */
static int
rust_check_tree(asn1p_t *asn, uint64_t codecs) {
    asn1p_module_t *module;
    int emitted = 0;
    TQ_FOR(module, &asn->modules, mod_next) {
        if(module->_tags & MT_STANDARD_MODULE) continue;
        if(rust_check_module(asn, module, &emitted, codecs)) return -1;
    }
    if(!emitted) {
        fprintf(stderr, "asn1c: Rust backend found no supported type assignments\n");
        return -1;
    }
    return 0;
}

/*
 * Validate one module's name, declarations, and supported top-level types.
 * Parameters: asn is the fixed tree; module is the module to inspect; emitted
 * counts accepted assignments; codecs is the requested mask. Returns zero or
 * -1 with a diagnostic. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: split from tree preflight. Example:
 * rust_check_module(tree, module, &emitted).
 */
static int
rust_check_module(asn1p_t *asn, asn1p_module_t *module, int *emitted,
                  uint64_t codecs) {
    if(!module->ModuleName || !*module->ModuleName) {
        rust_diagnostic(module, NULL, "module has no usable name");
        return -1;
    }
    if(rust_check_module_name(asn, module)) return -1;
    if(module->imports.tq_head) {
        rust_diagnostic(module, NULL,
                        "IMPORTS are not supported by the initial Rust slice");
        return -1;
    }
    if(module->module_flags & MSF_MASK_INSTRUCTIONS) {
        rust_diagnostic(module, NULL,
                        "module encoding instructions are not supported");
        return -1;
    }
    return rust_check_module_types(module, emitted, codecs);
}

/*
 * Check one normalized module filename against reserved paths and siblings.
 * Parameters: asn supplies all modules; module is the candidate. Returns zero
 * or -1 after an ASN.1 diagnostic. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: split from tree preflight. Example: rust_check_module_name(tree, m).
 */
static int
rust_check_module_name(asn1p_t *asn, asn1p_module_t *module) {
    asn1p_module_t *prior;
    char *module_name = rust_identifier(module->ModuleName, 1);
    if(!module_name) {
        rust_diagnostic(module, NULL,
                        "module name is too long or cannot be sanitized");
        return -1;
    }
    if(rust_module_filename_reserved(module_name)) {
        rust_diagnostic(module, NULL,
                        "module name conflicts with a generated Rust path");
        free(module_name);
        return -1;
    }
    TQ_FOR(prior, &asn->modules, mod_next) {
        char *prior_name;
        if(prior == module || (prior->_tags & MT_STANDARD_MODULE)) continue;
        prior_name = rust_identifier(prior->ModuleName, 1);
        if(!prior_name) {
            free(module_name);
            return -1;
        }
        if(!strcmp(module_name, prior_name)) {
            rust_diagnostic(module, NULL,
                            "module names collide after Rust sanitization");
            free(prior_name);
            free(module_name);
            return -1;
        }
        free(prior_name);
    }
    free(module_name);
    return 0;
}

/*
 * Validate assignment kinds and ensure each emitted type name is unique.
 * Parameters: module is one source module; emitted counts accepted types;
 * codecs is the requested mask.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: split from tree
 * preflight. Example: rust_check_module_types(module, &emitted).
 */
static int
rust_check_module_types(asn1p_module_t *module, int *emitted, uint64_t codecs) {
    asn1p_expr_t *expr;
    if(rust_check_module_nested_names(module)) return -1;
    TQ_FOR(expr, &module->members, next) {
        if(expr->meta_type != AMT_TYPE) {
            rust_diagnostic(module, expr,
                            "only top-level type assignments are supported");
            return -1;
        }
        if(rust_check_type(module, expr, codecs) || rust_check_type_name(module, expr))
            return -1;
        (*emitted)++;
    }
    return 0;
}

/*
 * Check one generated type name against preceding declarations in its module.
 * Parameters: module owns expr. Returns zero when unique or -1 on collision.
 * Original source: new Rust backend. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: split from tree preflight.
 * Example: rust_check_type_name(module, assignment).
 */
static int
rust_check_type_name(asn1p_module_t *module, asn1p_expr_t *expr) {
    asn1p_expr_t *prior;
    char *name = rust_identifier(expr->Identifier, 0);
    if(!name) {
        rust_diagnostic(module, expr,
                        "type name is too long or cannot be sanitized");
        return -1;
    }
    TQ_FOR(prior, &module->members, next) {
        char *prior_name;
        if(prior == expr) break;
        prior_name = rust_identifier(prior->Identifier, 0);
        if(!prior_name) {
            free(name);
            return -1;
        }
        if(!strcmp(name, prior_name)) {
            rust_diagnostic(module, expr,
                            "type names collide after Rust sanitization");
            free(prior_name);
            free(name);
            return -1;
        }
        free(prior_name);
    }
    free(name);
    return 0;
}

/*
 * Reject one unsupported type before output publication.
 * Parameters: module and expr identify the fixed assignment; codecs is the
 * selected mask. Returns zero
 * when supported, otherwise -1 after a source-location diagnostic. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: initial primitive gate. Example:
 * rust_check_type(module, integer_type).
 */
static int
rust_check_type(asn1p_module_t *module, asn1p_expr_t *expr,
                uint64_t codecs) {
    if(!expr->Identifier || !*expr->Identifier) {
        rust_diagnostic(module, expr, "type has no usable name");
        return -1;
    }
    if(expr->encoding_control.encoding_type != EC_NONE) {
        rust_diagnostic(module, expr,
                        "encoding controls are not supported by the initial Rust slice");
        return -1;
    }
    if(expr->expr_type == A1TC_REFERENCE) {
        rust_diagnostic(module, expr,
                        "type aliases and references are not supported by the initial Rust slice");
        return -1;
    }
    if(expr->tag.tag_class != TC_NOCLASS) {
        rust_diagnostic(module, expr,
                        "explicit type tags are not supported by the initial Rust slice");
        return -1;
    }
    if(expr->expr_type == ASN_CONSTR_SEQUENCE)
        return rust_check_sequence(module, expr, codecs);
    if(expr->expr_type == ASN_BASIC_ENUMERATED)
        return rust_check_enumerated(module, expr, codecs);
    if(expr->lhs_params || expr->ioc_table || expr->members.tq_head) {
        rust_diagnostic(module, expr,
                        "parameterized, constructed, or object types are unsupported");
        return -1;
    }
    if(expr->expr_type == ASN_BASIC_BOOLEAN || expr->expr_type == ASN_BASIC_NULL) {
        if(expr->constraints || expr->combined_constraints) {
            rust_diagnostic(module, expr,
                            "constraints on BOOLEAN or NULL are unsupported");
            return -1;
        }
        return 0;
    }
    if(expr->expr_type == ASN_BASIC_INTEGER) {
        if(!expr->combined_constraints
           || !rust_constraint_supported(expr->combined_constraints, 0)
           || rust_integer_bounds(expr, &(int64_t){0}, &(int64_t){0})) {
            rust_diagnostic(module, expr,
                            "INTEGER needs one finite, nonextensible range fitting i64");
            return -1;
        }
        return 0;
    }
    if(expr->expr_type == ASN_BASIC_OCTET_STRING) {
        if(!codecs || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_JER))
           || !expr->combined_constraints
           || !rust_size_constraint_supported(expr->combined_constraints, 0)
           || rust_fixed_size(expr, &(size_t){0})) {
            rust_diagnostic(module, expr,
                "OCTET STRING needs UPER and/or JER with fixed, nonextensible SIZE below 65536");
            return -1;
        }
        return 0;
    }
    if(expr->expr_type == ASN_BASIC_BIT_STRING) {
        if(codecs != RUST_CODEC_UPER || !expr->combined_constraints
           || !rust_size_constraint_supported(expr->combined_constraints, 0)
           || rust_fixed_size(expr, &(size_t){0})) {
            rust_diagnostic(module, expr,
                "BIT STRING needs UPER-only fixed, nonextensible SIZE below 65536");
            return -1;
        }
        return 0;
    }
    rust_diagnostic(module, expr,
                    "only direct primitives and flat UPER SEQUENCE are supported");
    return -1;
}

/*
 * Accept a flat SEQUENCE only when every selected codec has an implementation.
 * Parameters: module and expr identify the fixed type; codecs is the selected
 * mask. Returns zero or -1 with a diagnostic; no exception is thrown.
 * Original source: Rust backend. Version/date: 0.2.0, 2026-10-30.
 * Responsible party: asn1c maintainers. History: first composable UPER slice.
 * Example: rust_check_sequence(module, record, RUST_CODEC_UPER).
 */
static int
rust_check_sequence(asn1p_module_t *module, asn1p_expr_t *expr,
                    uint64_t codecs) {
    asn1p_expr_t *stack[RUST_SEQUENCE_DEPTH_LIMIT + 1];
    size_t nodes = 0;
    size_t work = 0;
    if(codecs != RUST_CODEC_UPER || expr->constraints
       || expr->combined_constraints || expr->lhs_params || expr->ioc_table
       || expr->marker.flags || expr->rhs_pspecs) {
        rust_diagnostic(module, expr,
                        "SEQUENCE needs UPER-only selection and direct fields");
        return -1;
    }
    return rust_check_sequence_tree(module, expr, stack, 0, &nodes, &work);
}

/*
 * Check nested type names across every assignment in one generated module.
 * Parameters: module owns all assignments. Returns zero or -1 with a
 * diagnostic. Original source: Rust name-collision preflight. Version/date:
 * 0.4.0, 2026-10-30. Responsible party: asn1c maintainers. History: nested
 * type generation. Example: reject two records both named ParentChild.
 */
static int
rust_check_module_nested_names(asn1p_module_t *module) {
    asn1p_expr_t *expr;
    char *names[RUST_MODULE_NESTED_NAME_LIMIT] = {0};
    size_t name_count = 0;
    int failed = 0;
    TQ_FOR(expr, &module->members, next) {
        char *root;
        if(expr->expr_type != ASN_CONSTR_SEQUENCE) continue;
        root = rust_identifier(expr->Identifier, 0);
        if(!root || rust_collect_nested_names(module, expr, root, names,
                                              &name_count, 0)) failed = 1;
        free(root);
        if(failed) break;
    }
    while(name_count) free(names[--name_count]);
    return failed ? -1 : 0;
}

/*
 * Collect deterministic nested type names and reject every collision.
 * Parameters: module owns type assignments; sequence is the current record;
 * parent is its generated name; names stores earlier nested names.
 * Returns zero or -1. Original source: Rust backend name preflight.
 * Version/date: 0.4.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: inline SEQUENCE naming. Example: collect names under a parent type.
 */
static int
rust_collect_nested_names(asn1p_module_t *module, asn1p_expr_t *sequence,
                          const char *parent, char **names, size_t *name_count,
                          size_t depth) {
    asn1p_expr_t *member;
    asn1p_expr_t *assignment;
    if(depth >= RUST_SEQUENCE_DEPTH_LIMIT) {
        rust_diagnostic(module, sequence, "nested SEQUENCE depth limit exceeded");
        return -1;
    }
    TQ_FOR(member, &sequence->members, next) {
        char *name;
        size_t i;
        int collision = 0;
        if(member->expr_type != ASN_CONSTR_SEQUENCE) continue;
        name = rust_nested_type_name(parent, member);
        if(!name) {
            rust_diagnostic(module, member, "nested SEQUENCE type name is too long");
            return -1;
        }
        TQ_FOR(assignment, &module->members, next) {
            char *top_name = rust_identifier(assignment->Identifier, 0);
            collision = !top_name || !strcmp(name, top_name);
            free(top_name);
            if(collision) break;
        }
        if(collision || *name_count >= RUST_MODULE_NESTED_NAME_LIMIT) {
            rust_diagnostic(module, member, "nested SEQUENCE type names collide");
            free(name);
            return -1;
        }
        for(i = 0; i < *name_count; i++) {
            if(!strcmp(name, names[i])) {
                rust_diagnostic(module, member, "nested SEQUENCE type names collide");
                free(name);
                return -1;
            }
        }
        names[(*name_count)++] = name;
        if(rust_collect_nested_names(module, member, name, names, name_count,
                                     depth + 1))
            return -1;
    }
    return 0;
}

/*
 * Build a nested record type name from its parent and field identifier.
 * Parameters: parent is the generated enclosing name; member is the nested
 * field. Returns allocated normalized name or NULL. Original source: Rust
 * naming rules. Version/date: 0.4.0, 2026-10-30. Responsible party: asn1c.
 * History: introduced for inline SEQUENCE records. Example: ParentInner.
 */
static char *
rust_nested_type_name(const char *parent, const asn1p_expr_t *member) {
    size_t parent_length;
    size_t field_length;
    char *field_name;
    char *source;
    char *name;
    if(!parent || !member || !member->Identifier) return NULL;
    field_name = rust_enum_variant(member->Identifier);
    if(!field_name) return NULL;
    parent_length = strlen(parent);
    field_length = strlen(field_name);
    if(parent_length > SIZE_MAX - field_length - 1) {
        free(field_name);
        return NULL;
    }
    source = malloc(parent_length + field_length + 1);
    if(!source) {
        free(field_name);
        return NULL;
    }
    memcpy(source, parent, parent_length);
    memcpy(source + parent_length, field_name, field_length + 1);
    name = rust_identifier(source, 0);
    free(source);
    free(field_name);
    return name;
}

/*
 * Validate an inline SEQUENCE tree with cycle, depth, and aggregate-work caps.
 * Parameters: module supplies diagnostics; sequence is the current record;
 * stack tracks active records; nodes/work accumulate tree totals.
 * Returns zero or -1. Original source: Rust UPER generator preflight.
 * Version/date: 0.4.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: bounded inline SEQUENCE support. Example: validate a child record.
 */
static int
rust_check_sequence_tree(asn1p_module_t *module, asn1p_expr_t *sequence,
                         asn1p_expr_t **stack, size_t depth, size_t *nodes,
                         size_t *work) {
    asn1p_expr_t *member;
    size_t count = 0;
    size_t i;
    if(depth >= RUST_SEQUENCE_DEPTH_LIMIT || ++*nodes > RUST_SEQUENCE_NODE_LIMIT) {
        rust_diagnostic(module, sequence, "nested SEQUENCE depth or node limit exceeded");
        return -1;
    }
    for(i = 0; i < depth; i++) {
        if(stack[i] == sequence) {
            rust_diagnostic(module, sequence, "cyclic nested SEQUENCE is unsupported");
            return -1;
        }
    }
    if(sequence->expr_type != ASN_CONSTR_SEQUENCE || sequence->constraints
       || sequence->combined_constraints || sequence->lhs_params
       || sequence->ioc_table
       || (sequence->marker.flags != EM_NOMARK
           && sequence->marker.flags != EM_OPTIONAL)
       || sequence->rhs_pspecs
       || sequence->encoding_control.encoding_type != EC_NONE) {
        rust_diagnostic(module, sequence, "nested SEQUENCE has unsupported extensions or constraints");
        return -1;
    }
    stack[depth] = sequence;
    TQ_FOR(member, &sequence->members, next) {
        if(++count > RUST_SEQUENCE_FIELD_LIMIT
           || ++*work > RUST_SEQUENCE_WORK_LIMIT) {
            rust_diagnostic(module, member, "SEQUENCE aggregate field-work limit exceeded");
            return -1;
        }
        if(rust_check_sequence_name(module, sequence, member)) return -1;
        if(member->expr_type == ASN_CONSTR_SEQUENCE) {
            if(member->marker.flags == EM_DEFAULT) {
                rust_diagnostic(module, member, "constructed DEFAULT fields are unsupported");
                return -1;
            }
            if(!rust_sequence_member_shape_valid(member)
               || rust_check_sequence_tree(module, member, stack, depth + 1,
                                            nodes, work)) return -1;
        } else if(rust_check_sequence_member(module, member)) {
            return -1;
        }
    }
    return 0;
}

/*
 * Validate one required, OPTIONAL, or supported DEFAULT direct SEQUENCE field.
 * Parameters: module supplies diagnostics; member is the fixed field.
 * Returns zero when supported or -1 with a diagnostic. No exception is
 * thrown. Original source: Rust backend. Version/date: 0.2.0, 2026-10-30.
 * Responsible party: asn1c maintainers. History: first flat UPER field gate.
 * Example: rust_check_sequence_member(module, field).
 */
static int
rust_check_sequence_member(asn1p_module_t *module, asn1p_expr_t *member) {
    char default_literal[64];
    int supported = 0;
    if(!rust_sequence_member_shape_valid(member)) {
        rust_diagnostic(module, member,
                        "SEQUENCE field must be a direct primitive with supported shape");
        return -1;
    }
    if(member->members.tq_head) {
        rust_diagnostic(module, member,
                        "primitive SEQUENCE field cannot contain child members");
        return -1;
    }
    if(member->expr_type == ASN_BASIC_BOOLEAN
       || member->expr_type == ASN_BASIC_NULL) {
        supported = !member->constraints && !member->combined_constraints;
    } else if(member->expr_type == ASN_BASIC_INTEGER) {
        supported = member->combined_constraints
            && rust_constraint_supported(member->combined_constraints, 0)
            && !rust_integer_bounds(member, &(int64_t){0}, &(int64_t){0});
    } else if(member->expr_type == ASN_BASIC_OCTET_STRING
              || member->expr_type == ASN_BASIC_BIT_STRING) {
        supported = member->combined_constraints
            && rust_size_constraint_supported(member->combined_constraints, 0)
            && !rust_fixed_size(member, &(size_t){0});
    }
    if(supported && member->marker.flags == EM_DEFAULT
       && rust_sequence_default_literal(member, default_literal,
                                        sizeof(default_literal))) {
        rust_diagnostic(module, member,
                        "DEFAULT needs a literal BOOLEAN or in-range bounded INTEGER");
        return -1;
    }
    if(supported) return 0;
    rust_diagnostic(module, member,
                    "SEQUENCE field needs a supported direct UPER primitive");
    return -1;
}

/*
 * Check structural properties shared by every supported flat SEQUENCE field.
 * Parameters: member is an ASN.1 component. Returns one for a direct
 * primitive with a supported presence marker, otherwise zero. No exception.
 * Original source: fixed Rust UPER SEQUENCE gate.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: separated structural validation to keep gate complexity bounded.
 * Example: rust_sequence_member_shape_valid(field).
 */
static int
rust_sequence_member_shape_valid(const asn1p_expr_t *member) {
    return member && member->Identifier && *member->Identifier
        && member->meta_type == AMT_TYPE
        && (member->marker.flags == EM_NOMARK
            || member->marker.flags == EM_OPTIONAL
            || member->marker.flags == EM_DEFAULT)
        && member->encoding_control.encoding_type == EC_NONE
        && !member->lhs_params && !member->rhs_pspecs && !member->ioc_table;
}

/*
 * Format one supported SEQUENCE DEFAULT literal as a Rust expression.
 * Parameters: member is a validated direct field; literal receives a bounded
 * Rust literal. Returns zero on success or -1 for unsupported values.
 * Original source: ASN.1 DEFAULT value AST and Rust field representation.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: added UPER BOOLEAN and bounded INTEGER DEFAULT support.
 * Example: rust_sequence_default_literal(field, text, sizeof(text)).
 */
static int
rust_sequence_default_literal(asn1p_expr_t *member, char *literal,
                              size_t literal_size) {
    asn1p_value_t *value;
    if(!member || member->marker.flags != EM_DEFAULT || !literal
       || !literal_size) return -1;
    value = member->marker.default_value;
    if(!value) return -1;
    if(member->expr_type == ASN_BASIC_BOOLEAN) {
        const char *text = value->type == ATV_TRUE ? "true"
                           : value->type == ATV_FALSE ? "false" : NULL;
        size_t length;
        if(!text) return -1;
        length = strlen(text);
        if(length >= literal_size) return -1;
        memcpy(literal, text, length + 1);
        return 0;
    }
    if(member->expr_type == ASN_BASIC_INTEGER && value->type == ATV_INTEGER) {
        int64_t lower, upper;
        int64_t number;
        if(rust_integer_bounds(member, &lower, &upper)
           || value->value.v_integer < (asn1c_integer_t)lower
           || value->value.v_integer > (asn1c_integer_t)upper) return -1;
        number = (int64_t)value->value.v_integer;
        return rust_format_bound(literal, literal_size, number);
    }
    return -1;
}

/*
 * Return whether a field contributes one entry to the UPER presence bitmap.
 * Parameters: member is a SEQUENCE component. Returns one for OPTIONAL or
 * DEFAULT, otherwise zero. No exception is thrown.
 * Original source: X.691 optional/default presence preamble.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: shared OPTIONAL and DEFAULT bitmap support. Example:
 * rust_sequence_has_presence(field).
 */
static int
rust_sequence_has_presence(const asn1p_expr_t *member) {
    return member && (member->marker.flags == EM_OPTIONAL
        || member->marker.flags == EM_DEFAULT);
}

/*
 * Check a field's Rust name against every preceding field in its SEQUENCE.
 * Parameters: module supplies diagnostics; sequence owns the fields; member
 * is the current field. Returns zero or -1; allocation failures are errors.
 * Original source: Rust backend. Version/date: 0.2.0, 2026-10-30.
 * Responsible party: asn1c maintainers. History: SEQUENCE name preflight.
 * Example: rust_check_sequence_name(module, record, member).
 */
static int
rust_check_sequence_name(asn1p_module_t *module, asn1p_expr_t *sequence,
                         asn1p_expr_t *member) {
    asn1p_expr_t *prior;
    char *name = rust_identifier(member->Identifier, 1);
    if(!name) {
        rust_diagnostic(module, member, "SEQUENCE field name cannot be sanitized");
        return -1;
    }
    TQ_FOR(prior, &sequence->members, next) {
        char *previous;
        if(prior == member) break;
        previous = rust_identifier(prior->Identifier, 1);
        if(!previous || !strcmp(name, previous)) {
            rust_diagnostic(module, member, "SEQUENCE field names collide");
            free(previous);
            free(name);
            return -1;
        }
        free(previous);
    }
    free(name);
    return 0;
}

/*
 * Accept only finite range/value constraints combined by intersections.
 * Parameters: constraint is a fixed constraint node; depth bounds recursion.
 * Returns true for supported shapes. No exceptions are raised. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: initial conservative INTEGER gate.
 * Example: rust_constraint_supported(expr->combined_constraints, 0).
 */
static int
rust_constraint_supported(const asn1p_constraint_t *constraint,
                          unsigned depth) {
    unsigned i;
    if(!constraint || depth > RUST_CONSTRAINT_DEPTH_LIMIT) return 0;
    switch(constraint->type) {
    case ACT_CA_SET:
    case ACT_CA_INT:
        if(!constraint->el_count) return 0;
        for(i = 0; i < constraint->el_count; i++) {
            if(!rust_constraint_supported(constraint->elements[i], depth + 1))
                return 0;
        }
        return 1;
    case ACT_EL_RANGE:
        return constraint->range_start
            && constraint->range_stop
            && constraint->range_start->type == ATV_INTEGER
            && constraint->range_stop->type == ATV_INTEGER;
    case ACT_EL_VALUE:
        return constraint->value && constraint->value->type == ATV_INTEGER;
    default:
        return 0;
    }
}

/*
 * Extract one closed nonextensible PER range and prove it fits i64.
 * Parameters: expr is a direct fixed INTEGER; lower and upper receive bounds.
 * Returns zero on success and -1 otherwise. The range object is always freed.
 * Original source: based on asn1c_misc.c's PER range selection. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: adapted
 * for Rust's checked i64 newtype. Example: rust_integer_bounds(expr, &lo, &hi).
 */
static int
rust_integer_bounds(asn1p_expr_t *expr, int64_t *lower, int64_t *upper) {
    asn1cnst_range_t *range;
    const asn1c_integer_t min_i64 = -(asn1c_integer_t)INT64_MAX - 1;
    const asn1c_integer_t max_i64 = (asn1c_integer_t)INT64_MAX;
    if(!expr || !expr->combined_constraints || !lower || !upper) return -1;
    range = asn1constraint_compute_PER_range(expr->Identifier, expr->expr_type,
        expr->combined_constraints, ACT_EL_RANGE, 0, 0, CPR_noflags);
    if(!range) return -1;
    if(range->incompatible || range->empty_constraint || range->not_PER_visible
       || range->extensible || range->left.type != ARE_VALUE
       || range->right.type != ARE_VALUE
       || range->left.value < min_i64 || range->left.value > max_i64
       || range->right.value < min_i64 || range->right.value > max_i64
       || range->left.value > range->right.value) {
        asn1constraint_range_free(range);
        return -1;
    }
    *lower = (int64_t)range->left.value;
    *upper = (int64_t)range->right.value;
    asn1constraint_range_free(range);
    return 0;
}

/*
 * Accept only a SIZE wrapper with finite integer range or value leaves.
 * Parameters: constraint is the fixed parser node; depth bounds recursion.
 * Returns true for this conservative shape and false otherwise; no exception.
 * Original source: Rust backend constraint gate. Version/date: 0.3.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: fixed strings.
 * Example: rust_size_constraint_supported(expr->combined_constraints, 0).
 */
static int
rust_size_constraint_supported(const asn1p_constraint_t *constraint,
                               unsigned depth) {
    unsigned i;
    if(!constraint || depth > RUST_CONSTRAINT_DEPTH_LIMIT) return 0;
    if(constraint->type == ACT_CT_SIZE || constraint->type == ACT_CA_SET
       || constraint->type == ACT_CA_INT) {
        if(!constraint->el_count) return 0;
        for(i = 0; i < constraint->el_count; i++) {
            if(!rust_size_constraint_supported(constraint->elements[i], depth + 1))
                return 0;
        }
        return 1;
    }
    if(constraint->type == ACT_EL_RANGE)
        return constraint->range_start && constraint->range_stop
            && constraint->range_start->type == ATV_INTEGER
            && constraint->range_stop->type == ATV_INTEGER;
    if(constraint->type == ACT_EL_VALUE)
        return constraint->value && constraint->value->type == ATV_INTEGER;
    return 0;
}

/*
 * Extract a fixed, nonextensible PER SIZE below the fragmentation threshold.
 * Parameters: expr is a direct string type; length receives the unit count.
 * Returns zero on success and -1 otherwise; frees every computed range.
 * No exception is thrown.
 * Original source: asn1c_C.c PER size selection. Version/date: 0.3.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: fixed strings.
 * Example: rust_fixed_size(expr, &length).
 */
static int
rust_fixed_size(asn1p_expr_t *expr, size_t *length) {
    asn1cnst_range_t *range;
    if(!expr || !expr->combined_constraints || !length) return -1;
    range = asn1constraint_compute_PER_range(expr->Identifier, expr->expr_type,
        expr->combined_constraints, ACT_CT_SIZE, 0, 0, CPR_noflags);
    if(!range) return -1;
    if(range->incompatible || range->empty_constraint || range->not_PER_visible
       || range->extensible || range->left.type != ARE_VALUE
       || range->right.type != ARE_VALUE || range->left.value < 0
       || range->left.value != range->right.value
       || range->left.value >= 65536) {
        asn1constraint_range_free(range);
        return -1;
    }
    *length = (size_t)range->left.value;
    asn1constraint_range_free(range);
    return 0;
}

/*
 * Validate one direct, nonextensible ENUMERATED assignment for UPER output.
 * Parameters: module supplies diagnostics; expr is the assignment; codecs is
 * the selected mask. Returns zero or -1 and throws no exception.
 * Original source: asn1c_C.c value2enum ordering and Rust type preflight.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: first ENUMERATED slice. Example: rust_check_enumerated(m, e, mask).
 */
static int
rust_check_enumerated(asn1p_module_t *module, asn1p_expr_t *expr,
                      uint64_t codecs) {
    asn1p_expr_t *item;
    size_t count = 0;
    if(!(codecs & (RUST_CODEC_UPER | RUST_CODEC_JER))
       || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_JER)) || expr->constraints
       || expr->combined_constraints || expr->lhs_params || expr->ioc_table
       || expr->rhs_pspecs) {
        rust_diagnostic(module, expr,
            "ENUMERATED needs direct nonextensible values and UPER or JER");
        return -1;
    }
    TQ_FOR(item, &expr->members, next) {
        if(++count > RUST_SEQUENCE_FIELD_LIMIT || !rust_enum_item_valid(item)) {
            rust_diagnostic(module, item, "ENUMERATED item must be a finite direct i64 value");
            return -1;
        }
        if(rust_enum_unique(expr, item)) {
            rust_diagnostic(module, item, "ENUMERATED values or Rust names collide");
            return -1;
        }
    }
    if(!count) {
        rust_diagnostic(module, expr, "ENUMERATED needs at least one root value");
        return -1;
    }
    return 0;
}

/*
 * Check one enum root item for a direct finite signed numeric value.
 * Parameters: item is the parser member. Returns true when valid; no exception.
 * Original source: Rust ENUMERATED preflight. Version/date: 0.3.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: split gate to
 * bound function complexity. Example: rust_enum_item_valid(item).
 */
static int
rust_enum_item_valid(const asn1p_expr_t *item) {
    const asn1c_integer_t min_i64 = -(asn1c_integer_t)INT64_MAX - 1;
    const asn1c_integer_t max_i64 = (asn1c_integer_t)INT64_MAX;
    return item && item->expr_type == A1TC_UNIVERVAL
        && rust_enum_name_safe(item->Identifier)
        && item->value && item->value->type == ATV_INTEGER
        && item->value->value.v_integer >= min_i64
        && item->value->value.v_integer <= max_i64;
}

/*
 * Check that an ENUMERATED identifier can be emitted as a literal JSON name.
 * Parameters: name is an untrusted parser identifier. Returns true only for
 * ASCII letters, digits, and interior single hyphens; no exception is thrown.
 * Original source: ASN.1 identifier lexical shape and Rust JER generation.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: added to avoid raw-string injection in generated enum JER tables.
 * Example: rust_enum_name_safe("red-blue") is true.
 */
static int
rust_enum_name_safe(const char *name) {
    const unsigned char *cursor = (const unsigned char *)name;
    if(!cursor || !(('A' <= *cursor && *cursor <= 'Z')
                    || ('a' <= *cursor && *cursor <= 'z'))) return 0;
    for(cursor++; *cursor; cursor++) {
        if(*cursor == '-') {
            if(!cursor[1] || cursor[1] == '-') return 0;
        } else if(!(('A' <= *cursor && *cursor <= 'Z')
                 || ('a' <= *cursor && *cursor <= 'z')
                 || ('0' <= *cursor && *cursor <= '9'))) {
            return 0;
        }
    }
    return 1;
}

/*
 * Reject duplicate numeric values and post-normalization Rust variant names.
 * Parameters: expr owns the items; item is the current validated member.
 * Returns zero when unique or -1 otherwise; allocation failure is an error.
 * No exception is thrown.
 * Original source: Rust ENUMERATED preflight. Version/date: 0.3.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: split collision
 * gate. Example: rust_enum_unique(expr, item).
 */
static int
rust_enum_unique(asn1p_expr_t *expr, asn1p_expr_t *item) {
    asn1p_expr_t *prior;
    char *name = rust_enum_variant(item->Identifier);
    if(!name) return -1;
    TQ_FOR(prior, &expr->members, next) {
        char *previous;
        int collision;
        if(prior == item) break;
        previous = rust_enum_variant(prior->Identifier);
        collision = !previous || !strcmp(name, previous)
                    || prior->value->value.v_integer == item->value->value.v_integer;
        free(previous);
        if(collision) {
            free(name);
            return -1;
        }
    }
    free(name);
    return 0;
}

/*
 * Return the numeric-order UPER root index for one validated enum item.
 * Parameters: expr owns all values; item is one member. Returns its rank;
 * no exception is thrown. Original source: asn1c_C.c value2enum qsort.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: first ENUMERATED slice. Example: rust_enumerated_rank(expr, item).
 */
static size_t
rust_enumerated_rank(asn1p_expr_t *expr, asn1p_expr_t *item) {
    asn1p_expr_t *other;
    size_t rank = 0;
    TQ_FOR(other, &expr->members, next) {
        if(other->value->value.v_integer < item->value->value.v_integer)
            rank++;
    }
    return rank;
}

/*
 * Convert a sanitized ASN.1 enum item to a Rust CamelCase variant name.
 * Parameters: source is the ASN.1 item identifier. Returns allocated text or
 * NULL; caller frees it. No exception is thrown. Original source: Rust backend
 * identifier sanitizer.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: first ENUMERATED slice. Example: rust_enum_variant("red-blue").
 */
static char *
rust_enum_variant(const char *source) {
    char *name = rust_identifier(source, 0);
    size_t read, write = 0;
    int capital = 1;
    if(!name) return NULL;
    for(read = 0; name[read]; read++) {
        unsigned char ch = (unsigned char)name[read];
        if(ch == '_') {
            capital = 1;
            continue;
        }
        if(capital && ch >= 'a' && ch <= 'z') ch -= 'a' - 'A';
        else if(!capital && ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        name[write++] = (char)ch;
        capital = 0;
    }
    name[write] = '\0';
    if(!write) {
        free(name);
        return NULL;
    }
    if(rust_is_keyword(name)) {
        const size_t prefix = 4;
        size_t capacity = strlen(source) * 2 + 32;
        if(write + prefix + 1 > capacity) {
            free(name);
            return NULL;
        }
        memmove(name + prefix, name, write + 1);
        memcpy(name, "Asn1", prefix);
    }
    return name;
}

/*
 * Build a Rust-safe, deterministic module or type identifier.
 * Parameters: source is an ASN.1 identifier; module_name selects snake case.
 * Returns an allocated identifier or NULL on allocation failure. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: initial identifier sanitizer. Example:
 * rust_identifier("FirstSlice", 1) returns "first_slice".
 */
static char *
rust_identifier(const char *source, int module_name) {
    size_t i, used = 0, length;
    char *result;
    int previous_lower = 0;
    if(!source || !*source) return NULL;
    length = strlen(source);
    if(length > RUST_IDENTIFIER_LIMIT || length > (SIZE_MAX - 32) / 2)
        return NULL;
    result = malloc(length * 2 + 32);
    if(!result) return NULL;
    for(i = 0; i < length; i++) {
        if(rust_identifier_append(result, &used, (unsigned char)source[i],
                                  module_name, &previous_lower)) {
            free(result);
            return NULL;
        }
    }
    if(used > RUST_IDENTIFIER_LIMIT) {
        free(result);
        return NULL;
    }
    if(!used) result[used++] = 'x';
    result[used] = '\0';
    if(rust_identifier_prefix(result, length * 2 + 32, used, module_name)) {
        free(result);
        return NULL;
    }
    return result;
}

/*
 * Append one sanitized source character and update case-boundary state.
 * Parameters: output and used identify the buffer; ch is the source byte;
 * module_name selects snake case; previous_lower is the preceding-case state.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: sanitizer helper.
 * Example: rust_identifier_append(buffer, &used, 'A', 1, &previous_lower).
 */
static int
rust_identifier_append(char *output, size_t *used, unsigned char ch,
                       int module_name, int *previous_lower) {
    int upper = ch >= 'A' && ch <= 'Z';
    int lower = ch >= 'a' && ch <= 'z';
    int digit = ch >= '0' && ch <= '9';
    if(module_name && upper && *previous_lower && *used
       && output[*used - 1] != '_') output[(*used)++] = '_';
    if(upper || lower || digit || ch == '_') {
        output[(*used)++] = (char)(module_name && upper ? ch + ('a' - 'A') : ch);
        *previous_lower = lower || digit;
    } else {
        if(!*used || output[*used - 1] != '_') output[(*used)++] = '_';
        *previous_lower = 0;
    }
    return 0;
}

/*
 * Prefix identifiers that begin with a digit or collide with Rust/file names.
 * Parameters: name is mutable; capacity is its allocation; used is its length;
 * module_name selects file-reserved names. Returns zero or -1. Original source:
 * new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: portable path prefixing. Example:
 * rust_identifier_prefix(name, capacity, used, 1).
 */
static int
rust_identifier_prefix(char *name, size_t capacity, size_t used,
                       int module_name) {
    const char *prefix = NULL;
    size_t prefix_length;
    if(name[0] >= '0' && name[0] <= '9') prefix = "asn1";
    else if(rust_is_keyword(name)
            || (module_name && rust_module_filename_reserved(name)))
        prefix = "asn1_";
    if(!prefix) return 0;
    prefix_length = strlen(prefix);
    if(used + prefix_length + 1 > capacity) return -1;
    memmove(name + prefix_length, name, used + 1);
    memcpy(name, prefix, prefix_length);
    return 0;
}

/*
 * Test whether an identifier conflicts with Rust syntax or path keywords.
 * Parameters: name is a sanitized identifier. Returns 1 for a keyword, else
 * 0. No exceptions are raised. Original source: new Rust backend. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: initial
 * reserved-name set. Example: rust_is_keyword("type") returns 1.
 */
static int
rust_is_keyword(const char *name) {
    static const char *const keywords[] = {
        "as", "break", "const", "continue", "crate", "else", "enum",
        "extern", "false", "fn", "for", "if", "impl", "in", "let",
        "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
        "self", "Self", "static", "struct", "super", "trait", "true",
        "type", "unsafe", "use", "where", "while", "async", "await",
        "dyn", "abstract", "become", "box", "do", "final", "macro",
        "override", "priv", "typeof", "unsized", "virtual", "yield",
        "try"
    };
    size_t i;
    for(i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if(strcmp(name, keywords[i]) == 0) return 1;
    }
    return 0;
}

/*
 * Avoid generated crate files and Windows device names for module files.
 * Parameters: name is a normalized filename component. Returns true when the
 * name must be prefixed. Original source: new Rust backend. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: portable
 * file naming. Example: rust_module_filename_reserved("lib").
 */
static int
rust_module_filename_reserved(const char *name) {
    static const char *const fixed[] = {
        "lib", "core", "asn1c_runtime", "con", "prn", "aux", "nul",
        "com1", "com2", "com3",
        "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2",
        "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"
    };
    size_t i;
    for(i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        if(!strcmp(name, fixed[i])) return 1;
    }
    return 0;
}

/*
 * Print one source-located unsupported-feature diagnostic.
 * Parameters: module and expr supply context; reason describes the gate.
 * Returns nothing and raises no exception. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: initial Rust diagnostic format. Example: rust_diagnostic(mod,
 * expr, "type is not supported").
 */
static void
rust_diagnostic(asn1p_module_t *module, asn1p_expr_t *expr,
                const char *reason) {
    const char *module_name = module && module->ModuleName
                                  ? module->ModuleName : "<unknown-module>";
    const char *type_name = expr && expr->Identifier
                                ? expr->Identifier : "<module>";
    int line = expr ? expr->_lineno : 0;
    fprintf(stderr, "asn1c: Rust backend does not support %s.%s at line %d: %s\n",
            module_name, type_name, line, reason);
}

/*
 * Create a private sibling staging directory and write the complete project.
 * Parameters: asn is validated; runtime_dir supplies assets; output receives
 * transaction paths; codecs selects the generated encoding methods. Returns
 * zero or -1. Original source:
 * new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: initial staged writer. Example:
 * rust_stage_project(tree, runtime, &output, A1C_GEN_CER).
 */
static int
rust_stage_project(asn1p_t *asn, const char *runtime_dir,
                   rust_output_t *output, uint64_t codecs) {
    unsigned attempt;
    if(!output->target[0]) return -1;
    for(attempt = 0; attempt < 100; attempt++) {
        int written = snprintf(output->stage, sizeof(output->stage),
                              "%s.asn1c-stage-%ld-%u", output->target,
                              (long)rust_getpid(), attempt);
        if(written < 0 || (size_t)written >= sizeof(output->stage)) return -1;
        if(rust_mkdir(output->stage, 0700) == 0) {
            output->stage_created = 1;
            break;
        }
        if(errno != EEXIST) {
            fprintf(stderr, "asn1c: cannot create Rust staging directory: %s\n",
                    strerror(errno));
            return -1;
        }
    }
    if(!output->stage_created) return -1;
    if(rust_write_project(asn, runtime_dir, output->stage, codecs)) {
        rust_remove_tree(output->stage);
        output->stage_created = 0;
        return -1;
    }
    return 0;
}

/*
 * Verify that a managed tree contains no unlisted files or symlinks.
 * Parameters: root is the crate root; relative is the current relative path;
 * manifest is the absolute ownership manifest. Returns zero when safe. No
 * links are followed. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: initial tree
 * ownership check. Example: rust_check_owned_tree(root, "", manifest).
 */
static int
rust_check_owned_tree(const char *root, const char *relative,
                      const char *manifest) {
    char directory_path[PATH_MAX];
    DIR *directory;
    struct dirent *entry;
    if(*relative) {
        if(rust_join(directory_path, sizeof(directory_path), root, relative))
            return -1;
    } else if(strlen(root) >= sizeof(directory_path)) {
        return -1;
    } else {
        strcpy(directory_path, root);
    }
    directory = opendir(directory_path);
    if(!directory) return -1;
    while((entry = readdir(directory))) {
        if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if(rust_check_tree_entry(root, relative, entry->d_name, manifest)) {
            closedir(directory);
            return -1;
        }
    }
    closedir(directory);
    return 0;
}

/*
 * Check one output child without following symlinks.
 * Parameters: root, parent, and name identify the child; manifest identifies
 * owned files. Returns zero when safe, otherwise -1. Original source: new Rust
 * backend. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: split from recursive ownership traversal. Example:
 * rust_check_tree_entry(root, "src", "lib.rs", manifest).
 */
static int
rust_check_tree_entry(const char *root, const char *parent, const char *name,
                      const char *manifest) {
    char relative[PATH_MAX];
    char path[PATH_MAX];
    struct stat status;
    int written;
    if(*parent) written = snprintf(relative, sizeof(relative), "%s/%s", parent, name);
    else written = snprintf(relative, sizeof(relative), "%s", name);
    if(written < 0 || (size_t)written >= sizeof(relative)
       || rust_join(path, sizeof(path), root, relative)
       || lstat(path, &status) != 0 || S_ISLNK(status.st_mode)) {
        fprintf(stderr, "asn1c: symlink or unreadable path in Rust output: %s\n",
                name);
        return -1;
    }
    if(S_ISDIR(status.st_mode)) {
        if(strcmp(relative, "src") && strcmp(relative, "runtime")
           && strcmp(relative, "runtime/src")) {
            fprintf(stderr, "asn1c: unrelated directory in Rust output: %s\n",
                    relative);
            return -1;
        }
        return rust_check_owned_tree(root, relative, manifest);
    }
    if(S_ISREG(status.st_mode)) return rust_check_owned_file(path, relative, manifest);
    fprintf(stderr, "asn1c: unsupported filesystem entry in Rust output: %s\n",
            relative);
    return -1;
}

/*
 * Validate one regular output file against the exact ownership manifest.
 * Parameters: path is the file; relative is its manifest key; manifest is the
 * manifest file. Returns zero or -1. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: split from recursive ownership traversal. Example:
 * rust_check_owned_file(path, "src/lib.rs", manifest).
 */
static int
rust_check_owned_file(const char *path, const char *relative,
                      const char *manifest) {
    if(!strcmp(path, manifest)) return 0;
    if(!rust_manifest_path_allowed(relative)
       || !rust_manifest_contains(manifest, relative)) {
        fprintf(stderr, "asn1c: unrelated file in Rust output: %s\n", relative);
        return -1;
    }
    return 0;
}

/*
 * Check whether one safe relative path is listed in the ownership manifest.
 * Parameters: manifest is the manifest file; relative is the exact path.
 * Returns true if found, false on absence or read failure. Original source:
 * new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: initial output ownership check. Example:
 * rust_manifest_contains(path, "src/lib.rs").
 */
static int
rust_manifest_contains(const char *manifest, const char *relative) {
    FILE *stream = fopen(manifest, "r");
    char line[PATH_MAX];
    if(!stream) return 0;
    while(fgets(line, sizeof(line), stream)) {
        char *end = strchr(line, '\n');
        if(end) *end = '\0';
        if(!strcmp(line, relative)) {
            fclose(stream);
            return 1;
        }
    }
    fclose(stream);
    return 0;
}

/*
 * Limit manifest entries to the exact generated project layout.
 * Parameters: path is a relative file path. Returns true only for Cargo files,
 * runtime files, the crate root, or one module source file. Original source:
 * new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: initial manifest path allowlist. Example:
 * rust_manifest_path_allowed("src/types.rs").
 */
static int
rust_manifest_path_allowed(const char *path) {
    const char *module_name;
    const char *suffix;
    if(!strcmp(path, "Cargo.toml") || !strcmp(path, "src/lib.rs")
       || !strcmp(path, "runtime/Cargo.toml")
       || !strcmp(path, "runtime/README.md")
       || !strcmp(path, "runtime/LICENSE")
       || !strcmp(path, "runtime/src/lib.rs")
       || !strcmp(path, "runtime/src/jer.rs")
       || !strcmp(path, "runtime/src/aper.rs")
       || !strcmp(path, "runtime/src/oer.rs")
       || !strcmp(path, "runtime/src/uper_cursor.rs")) return 1;
    if(strncmp(path, "src/", 4)) return 0;
    module_name = path + 4;
    suffix = strrchr(module_name, '.');
    if(!suffix || strcmp(suffix, ".rs") || suffix == module_name) return 0;
    if(strchr(module_name, '/')) return 0;
    while(module_name < suffix) {
        unsigned char ch = (unsigned char)*module_name++;
        if(!(ch == '_' || (ch >= 'a' && ch <= 'z')
             || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')))
            return 0;
    }
    return 1;
}

/*
 * Remove a private or prevalidated output directory without following links.
 * Parameters: path is the directory tree. Returns zero on complete removal,
 * otherwise -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: staged-output
 * cleanup. Example: rust_remove_tree(stage_path).
 */
static int
rust_remove_tree(const char *path) {
    struct stat status;
    DIR *directory;
    struct dirent *entry;
    if(lstat(path, &status) != 0) return errno == ENOENT ? 0 : -1;
    if(S_ISLNK(status.st_mode)) return -1;
    if(!S_ISDIR(status.st_mode)) return unlink(path);
    directory = opendir(path);
    if(!directory) return -1;
    while((entry = readdir(directory))) {
        char child[PATH_MAX];
        if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if(rust_join(child, sizeof(child), path, entry->d_name)
           || rust_remove_tree(child)) {
            closedir(directory);
            return -1;
        }
    }
    closedir(directory);
    return rmdir(path);
}

/*
 * Copy the fixed runtime crate file set without following source symlinks.
 * Parameters: source is rust/asn1c-runtime; destination is the staged runtime
 * directory. Returns zero or -1. Original source: new Rust backend. Version/
 * date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History:
 * initial vendored runtime support. Example: rust_copy_runtime(src, stage).
 */
static int
rust_copy_runtime(const char *source, const char *destination) {
    static const char *const files[] = {
        "Cargo.toml", "README.md", "LICENSE", "src/lib.rs",
        "src/jer.rs", "src/aper.rs", "src/oer.rs", "src/uper_cursor.rs"
    };
    struct stat status;
    char source_src[PATH_MAX];
    size_t i;
    char source_file[PATH_MAX];
    char dest_file[PATH_MAX];
    if(lstat(source, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, "asn1c: Rust runtime directory is unavailable: %s\n",
                source);
        return -1;
    }
    if(rust_join(source_src, sizeof(source_src), source, "src")
       || lstat(source_src, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, "asn1c: refusing unsafe Rust runtime source tree: %s\n",
                source);
        return -1;
    }
    for(i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if(rust_join(source_file, sizeof(source_file), source, files[i])
           || rust_join(dest_file, sizeof(dest_file), destination, files[i])
           || rust_copy_file(source_file, dest_file)) return -1;
    }
    return 0;
}

/*
 * Create a directory or verify that an existing path is a real directory.
 * Parameters: path is the directory to create. Returns zero or -1; symlinks
 * are rejected. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: staged writer.
 * Example: rust_make_directory("stage/src").
 */
static int
rust_make_directory(const char *path) {
    struct stat status;
    if(rust_mkdir(path, 0700) == 0) return 0;
    if(errno != EEXIST || lstat(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, "asn1c: cannot create Rust project directory %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * Write the complete staged Cargo project and vendored runtime.
 * Parameters: asn is the fixed tree; runtime_dir is the asset root; stage is a
 * private new directory; codecs selects emitted methods. Returns zero or -1.
 * Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: first generated crate layout. Example: rust_write_project(tree,
 * runtime, stage, A1C_GEN_CER).
 */
static int
rust_write_project(asn1p_t *asn, const char *runtime_dir, const char *stage,
                   uint64_t codecs) {
    char path[PATH_MAX];
    char runtime_copy[PATH_MAX];
    FILE *cargo;
    asn1p_module_t *module;
    if(rust_join(path, sizeof(path), stage, "src")
       || rust_make_directory(path)
       || rust_join(runtime_copy, sizeof(runtime_copy), stage, "runtime")
       || rust_make_directory(runtime_copy)
       || rust_join(path, sizeof(path), runtime_copy, "src")
       || rust_make_directory(path)) return -1;
    if(rust_join(path, sizeof(path), stage, "Cargo.toml")) return -1;
    cargo = fopen(path, "wb");
    if(!cargo) return -1;
    {
        int cargo_error = rust_write_cargo(cargo);
        if(fclose(cargo) != 0) cargo_error = -1;
        if(cargo_error) return -1;
    }
    if(rust_join(path, sizeof(path), stage, "src/lib.rs")
       || rust_write_lib(asn, path)
       || rust_copy_runtime(runtime_dir, runtime_copy)) return -1;
    TQ_FOR(module, &asn->modules, mod_next) {
        if(module->_tags & MT_STANDARD_MODULE) continue;
        if(rust_write_module_file(module, stage, codecs)) return -1;
    }
    if(rust_write_manifest(asn, stage)) return -1;
    return 0;
}

/*
 * Write one ASN.1 module source file with its generated type wrappers.
 * Parameters: stream receives Rust; module identifies the source; codecs
 * selects emitted methods.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: first module
 * emitter. Example: rust_write_module(stream, module, codecs).
 */
static int
rust_write_module(FILE *stream, asn1p_module_t *module, uint64_t codecs) {
    asn1p_expr_t *expr;
    if(fputs("//! Generated bindings for ASN.1 module.\n\n", stream) == EOF)
        return -1;
    TQ_FOR(expr, &module->members, next) {
        if(rust_write_type(stream, module, expr, codecs)) return -1;
    }
    return ferror(stream) ? -1 : 0;
}

/*
 * Emit one supported primitive wrapper or flat SEQUENCE and its methods.
 * Parameters: stream receives Rust; module and expr identify the assignment;
 * codecs selects emitted methods.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: initial wrapper
 * generator. Example: rust_write_type(stream, module, boolean_type, codecs).
 */
static int
rust_write_type(FILE *stream, asn1p_module_t *module, asn1p_expr_t *expr,
                uint64_t codecs) {
    char *name = rust_identifier(expr->Identifier, 0);
    int ret;
    (void)module;
    if(!name) return -1;
    if(fputs("/// ASN.1 type generated from the fixed parser tree.\n", stream) == EOF) {
        free(name);
        return -1;
    }
    if(expr->expr_type == ASN_CONSTR_SEQUENCE) {
        ret = rust_write_all_sequences(stream, name, expr, 1);
    } else if(expr->expr_type == ASN_BASIC_BOOLEAN) {
        ret = rust_write_boolean(stream, name, codecs);
    } else if(expr->expr_type == ASN_BASIC_NULL) {
        ret = rust_write_null(stream, name, codecs);
    } else if(expr->expr_type == ASN_BASIC_OCTET_STRING
              || expr->expr_type == ASN_BASIC_BIT_STRING) {
        ret = rust_write_string(stream, name, expr, codecs);
    } else if(expr->expr_type == ASN_BASIC_ENUMERATED) {
        ret = rust_write_enumerated(stream, name, expr, codecs);
    } else {
        int64_t lower, upper;
        if(rust_integer_bounds(expr, &lower, &upper)) ret = -1;
        else ret = rust_write_integer(stream, name, lower, upper, codecs);
    }
    free(name);
    return ret || ferror(stream) ? -1 : 0;
}

/*
 * Emit one documented SEQUENCE struct with private shared-cursor helpers.
 * Parameters: stream receives Rust; name is its generated type name; expr owns
 * validated fields. Returns zero or -1. Original source: Rust UPER backend.
 * Version/date: 0.4.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: nested-record helpers share one cursor. Example: emit Packet.
 */
static int
rust_write_sequence(FILE *stream, const char *name, asn1p_expr_t *expr,
                    int top_level) {
    asn1p_expr_t *member;
    if(fprintf(stream,
        "/// ASN.1 SEQUENCE record with direct inline fields.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s {\n", name) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_field(stream, name, member)) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Write this record's presence map and payload into the shared UPER cursor.",
            "`self` supplies this record; `writer` belongs to the complete value.",
            "Returns `Ok(())` after appending this record's fields.",
            "Returns a cursor error for invalid fields or exhausted resources.",
            "`self.encode_uper_fields(writer)?;")) return -1;
    if(fputs("    fn encode_uper_fields(&self, writer: &mut ::asn1c_runtime::UperWriter) ->\n"
             "        ::core::result::Result<(), ::asn1c_runtime::Error> {\n",
             stream) == EOF) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_encode_presence(stream, member)) return -1;
    }
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_encode_field(stream, member)) return -1;
    }
    if(fputs("        Ok(())\n    }\n\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream,
            "Read this record's presence map and payload from the shared UPER cursor.",
            "`reader` belongs to the complete top-level value.",
            "Returns a record with validated required, OPTIONAL, and DEFAULT fields.",
            "Returns a cursor error for truncation, malformed values, or exhausted resources.",
            "`let value = Self::decode_uper_fields(reader)?;")) return -1;
    if(fputs("    fn decode_uper_fields(reader: &mut ::asn1c_runtime::UperReader) ->\n"
             "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n",
             stream) == EOF) return -1;
    if(rust_write_sequence_decode_presence(stream, expr)) return -1;
    if(fputs("        let value = Self {\n", stream) == EOF) return -1;
    {
        size_t presence_index = 0;
        TQ_FOR(member, &expr->members, next) {
            if(rust_write_sequence_decode_field(stream, name, member,
                                                &presence_index)) return -1;
        }
    }
    if(fputs("        };\n        Ok(value)\n    }\n\n", stream) == EOF)
        return -1;
    if(!top_level) return fputs("}\n\n", stream) == EOF ? -1 : 0;
    if(rust_write_method_doc(stream,
            "Encode the complete SEQUENCE with one shared UPER budget.",
            "`self` supplies the record; `limits` bounds the whole operation.",
            "Returns packed bytes and meaningful bit length.",
            "Returns an error for invalid fields or exhausted resources.",
            "`let encoded = value.encode_uper(&Default::default())?;")) return -1;
    if(fputs("    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
             "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
             "        let mut writer = ::asn1c_runtime::UperWriter::new(limits)?;\n"
             "        self.encode_uper_fields(&mut writer)?;\n"
             "        writer.finish()\n"
             "    }\n\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete SEQUENCE prefix with a shared UPER budget.",
            "`input` is the encoded prefix; `limits` bounds the whole operation.",
            "Returns validated fields and bit/byte prefix consumption.",
            "Returns an error for truncation, malformed fields, or exhausted resources.",
            "`let decoded = Type::decode_uper(input, &Default::default())?;")) return -1;
    if(fputs("    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
             "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
             "        let mut reader = ::asn1c_runtime::UperReader::new(input, limits)?;\n"
             "        let value = Self::decode_uper_fields(&mut reader)?;\n"
             "        let consumed = reader.finish()?;\n"
             "        Ok(::asn1c_runtime::Decoded {\n"
             "            value,\n"
             "            consumed_bits: consumed.consumed_bits,\n"
             "            consumed_bytes: consumed.consumed_bytes,\n"
             "        })\n"
             "    }\n}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit child records before their parent so generated Rust types are declared.
 * Parameters: stream receives Rust; name is the current generated name; expr
 * owns the validated record tree. Returns zero or -1. Original source: Rust
 * UPER backend. Version/date: 0.4.0, 2026-10-30. Responsible party: asn1c.
 * History: inline nested records. Example: emit ParentChild before Parent.
 */
static int
rust_write_all_sequences(FILE *stream, const char *name, asn1p_expr_t *expr,
                         int top_level) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        char *nested_name;
        if(member->expr_type != ASN_CONSTR_SEQUENCE) continue;
        nested_name = rust_nested_type_name(name, member);
        if(!nested_name) return -1;
        if(rust_write_all_sequences(stream, nested_name, member, 0)) {
            free(nested_name);
            return -1;
        }
        free(nested_name);
    }
    return rust_write_sequence(stream, name, expr, top_level);
}

/*
 * Emit one documented public Rust SEQUENCE field.
 * Parameters: stream receives Rust; member is a validated direct primitive.
 * Returns zero or -1 on output failure. Original source: Rust backend.
 * Version/date: 0.2.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: flat UPER SEQUENCE generation. Example: emit a BOOLEAN field.
 */
static int
rust_write_sequence_field(FILE *stream, const char *parent,
                         asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    char *nested_type = member->expr_type == ASN_CONSTR_SEQUENCE
        ? rust_nested_type_name(parent, member) : NULL;
    const char *type = nested_type ? nested_type
                       : member->expr_type == ASN_BASIC_BOOLEAN ? "bool"
                       : member->expr_type == ASN_BASIC_NULL ? "()"
                       : member->expr_type == ASN_BASIC_INTEGER ? "i64"
                       : "::std::vec::Vec<u8>";
    int ret = -1;
    if(name) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE && !nested_type) {
            ret = -1;
        } else ret = member->marker.flags == EM_OPTIONAL
            ? fprintf(stream,
                "    /// ASN.1 %s OPTIONAL field state variable.\n"
                "    pub %s: ::core::option::Option<%s>,\n",
                member->Identifier, name, type)
            : fprintf(stream,
                "    /// ASN.1 %s field state variable.\n    pub %s: %s,\n",
                member->Identifier, name, type);
    }
    free(name);
    free(nested_type);
    return ret < 0 ? -1 : 0;
}

/*
 * Emit one cursor write call for a validated SEQUENCE field.
 * Parameters: stream receives Rust; member supplies type and field name.
 * Returns zero or -1 on output failure. Original source: Rust backend.
 * Version/date: 0.2.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: flat UPER SEQUENCE generation. Example: writer.write_boolean(bit).
 */
static int
rust_write_sequence_encode_field(FILE *stream, asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    int ret = -1;
    if(!name) return -1;
    if(member->expr_type == ASN_CONSTR_SEQUENCE) {
        if(member->marker.flags == EM_OPTIONAL) {
            ret = fprintf(stream,
                "        if let Some(value) = self.%s.as_ref() {\n"
                "            value.encode_uper_fields(writer)?;\n"
                "        }\n", name);
        } else {
            ret = fprintf(stream,
                "        self.%s.encode_uper_fields(writer)?;\n", name);
        }
    } else if(member->marker.flags == EM_OPTIONAL) {
        ret = rust_write_sequence_encode_optional(stream, member, name);
    } else if(member->marker.flags == EM_DEFAULT) {
        ret = rust_write_sequence_encode_default(stream, member, name);
    } else if(member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fprintf(stream, "        writer.write_boolean(self.%s)?;\n", name);
    else if(member->expr_type == ASN_BASIC_NULL)
        ret = fputs("        writer.write_null()?;\n", stream);
    else if(member->expr_type == ASN_BASIC_OCTET_STRING
            || member->expr_type == ASN_BASIC_BIT_STRING) {
        size_t length;
        if(!rust_fixed_size(member, &length))
            ret = fprintf(stream, "        writer.write_%s(&self.%s, %zu)?;\n",
                member->expr_type == ASN_BASIC_OCTET_STRING ? "octets" : "bit_string",
                name, length);
    }
    else {
        int64_t lower, upper;
        char low[64], high[64];
        if(!rust_integer_bounds(member, &lower, &upper)
           && !rust_format_bound(low, sizeof(low), lower)
           && !rust_format_bound(high, sizeof(high), upper))
            ret = fprintf(stream,
                "        writer.write_integer(self.%s, %s, %s)?;\n",
                name, low, high);
    }
    free(name);
    return ret < 0 ? -1 : 0;
}

/*
 * Emit a DEFAULT payload only when its concrete field differs from the ASN.1
 * default. Parameters: stream receives Rust; member is a supported DEFAULT;
 * name is its sanitized field identifier. Returns zero or -1 on failure.
 * Original source: X.691 DEFAULT omission rule and Rust field representation.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: added direct BOOLEAN and bounded INTEGER DEFAULT fields.
 * Example: rust_write_sequence_encode_default(out, field, "enabled").
 */
static int
rust_write_sequence_encode_default(FILE *stream, asn1p_expr_t *member,
                                   const char *name) {
    char literal[64];
    if(rust_sequence_default_literal(member, literal, sizeof(literal))) return -1;
    if(member->expr_type == ASN_BASIC_BOOLEAN) {
        const char *negate = !strcmp(literal, "true") ? "!" : "";
        return fprintf(stream,
            "        if %sself.%s { writer.write_boolean(self.%s)?; }\n",
            negate, name, name) < 0 ? -1 : 0;
    }
    {
        int64_t lower, upper;
        char low[64], high[64];
        if(rust_integer_bounds(member, &lower, &upper)
           || rust_format_bound(low, sizeof(low), lower)
           || rust_format_bound(high, sizeof(high), upper)) return -1;
        return fprintf(stream,
            "        if self.%s != %s {\n"
            "            writer.write_integer(self.%s, %s, %s)?;\n"
            "        }\n", name, literal, name, low, high) < 0 ? -1 : 0;
    }
}

/*
 * Emit a conditional cursor write for one validated OPTIONAL field.
 * Parameters: stream receives Rust; member supplies its primitive type and
 * bounds; name is its sanitized Rust field name. Returns zero or -1 for
 * invalid metadata or output failure. No exception is thrown. Original source:
 * Rust backend. Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c
 * maintainers. History: extracted to bound SEQUENCE emitter complexity.
 * Example: rust_write_sequence_encode_optional(out, field, "maybe").
 */
static int
rust_write_sequence_encode_optional(FILE *stream, asn1p_expr_t *member,
                                    const char *name) {
    if(member->expr_type == ASN_BASIC_NULL) {
        return fprintf(stream,
            "        if self.%s.is_some() { writer.write_null()?; }\n", name) < 0 ? -1 : 0;
    }
    if(member->expr_type == ASN_BASIC_BOOLEAN) {
        return fprintf(stream,
            "        if let Some(value) = self.%s.as_ref() {\n"
            "            writer.write_boolean(*value)?;\n"
            "        }\n", name) < 0 ? -1 : 0;
    }
    if(member->expr_type == ASN_BASIC_INTEGER) {
        int64_t lower, upper;
        char low[64], high[64];
        if(rust_integer_bounds(member, &lower, &upper)
           || rust_format_bound(low, sizeof(low), lower)
           || rust_format_bound(high, sizeof(high), upper)) return -1;
        return fprintf(stream,
            "        if let Some(value) = self.%s.as_ref() {\n"
            "            writer.write_integer(*value, %s, %s)?;\n"
            "        }\n", name, low, high) < 0 ? -1 : 0;
    }
    {
        size_t length;
        if(rust_fixed_size(member, &length)) return -1;
        return fprintf(stream,
            "        if let Some(value) = self.%s.as_ref() {\n"
            "            writer.write_%s(value, %zu)?;\n"
            "        }\n", name,
            member->expr_type == ASN_BASIC_OCTET_STRING ? "octets" : "bit_string",
            length) < 0 ? -1 : 0;
    }
}

/*
 * Emit one OPTIONAL or DEFAULT presence bit before payload fields.
 * Parameters: stream receives Rust; member supplies the validated field name.
 * Returns zero or -1 on output failure. No exception is thrown. Original
 * source: Rust backend. Version/date: 0.3.0, 2026-10-30. Responsible party:
 * asn1c maintainers. History: OPTIONAL/DEFAULT UPER bitmap emission. Example:
 * rust_write_sequence_encode_presence(stream, member).
 */
static int
rust_write_sequence_encode_presence(FILE *stream, asn1p_expr_t *member) {
    char *name;
    int ret;
    if(!rust_sequence_has_presence(member)) return 0;
    name = rust_identifier(member->Identifier, 1);
    if(!name) return -1;
    if(member->marker.flags == EM_OPTIONAL) {
        ret = fprintf(stream,
            "        writer.write_boolean(self.%s.is_some())?;\n", name);
    } else {
        char literal[64];
        const char *negate;
        if(rust_sequence_default_literal(member, literal, sizeof(literal))) {
            free(name);
            return -1;
        }
        if(member->expr_type == ASN_BASIC_BOOLEAN) {
            negate = !strcmp(literal, "true") ? "!" : "";
            ret = fprintf(stream,
                "        writer.write_boolean(%sself.%s)?;\n", negate, name);
            free(name);
            return ret < 0 ? -1 : 0;
        }
        ret = fprintf(stream,
            "        writer.write_boolean(self.%s != %s)?;\n", name, literal);
    }
    free(name);
    return ret < 0 ? -1 : 0;
}

/*
 * Read all OPTIONAL and DEFAULT bits before decoding any payload field.
 * Parameters: stream receives Rust; expr owns validated SEQUENCE members.
 * Returns zero or -1 on output failure. No exception is thrown. Original
 * source: Rust backend. Version/date: 0.3.0, 2026-10-30. Responsible party:
 * asn1c maintainers. History: OPTIONAL UPER bitmap decoding. Example:
 * rust_write_sequence_decode_presence(stream, sequence).
 */
static int
rust_write_sequence_decode_presence(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    int any = 0;
    TQ_FOR(member, &expr->members, next) {
        if(rust_sequence_has_presence(member)) any = 1;
    }
    if(!any) return 0;
    if(fputs("        let __asn1c_presence = [\n", stream) == EOF) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_sequence_has_presence(member)
           && fputs("            reader.read_boolean()?,\n", stream) == EOF)
            return -1;
    }
    return fputs("        ];\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit a decoded field initializer and its presence bitmap condition.
 * Parameters: stream receives Rust; member supplies the field; presence_index
 * tracks OPTIONAL and DEFAULT positions. Returns zero or -1; no exception.
 * Original source: Rust backend. Version/date: 0.3.0, 2026-10-30. Responsible
 * party: asn1c maintainers. History: flat UPER field decoding. Example:
 * rust_write_sequence_decode_field(stream, member, &index).
 */
static int
rust_write_sequence_decode_field(FILE *stream, const char *parent,
                                 asn1p_expr_t *member, size_t *presence_index) {
    char *name = rust_identifier(member->Identifier, 1);
    char *nested_type = member->expr_type == ASN_CONSTR_SEQUENCE
        ? rust_nested_type_name(parent, member) : NULL;
    int ret = -1;
    if(!name || (member->expr_type == ASN_CONSTR_SEQUENCE && !nested_type)) {
        free(name);
        free(nested_type);
        return -1;
    }
    ret = fprintf(stream, "                %s: ", name);
    if(ret < 0) {
        free(name);
        free(nested_type);
        return -1;
    }
    if(member->expr_type == ASN_CONSTR_SEQUENCE) {
        if(member->marker.flags == EM_OPTIONAL) {
            ret = fprintf(stream,
                "if __asn1c_presence[%zu] { Some(%s::decode_uper_fields(reader)?) } "
                "else { None },\n", *presence_index, nested_type);
            (*presence_index)++;
        } else {
            ret = fprintf(stream, "%s::decode_uper_fields(reader)?,\n", nested_type);
        }
        free(name);
        free(nested_type);
        return ret < 0 ? -1 : 0;
    }
    if(member->expr_type == ASN_BASIC_NULL) {
        if(member->marker.flags == EM_OPTIONAL) {
            ret = fprintf(stream,
                "if __asn1c_presence[%zu] { reader.read_null()?; Some(()) } "
                "else { None },\n", *presence_index);
            (*presence_index)++;
        } else {
            ret = fputs("{ reader.read_null()?; },\n", stream);
        }
        free(name);
        free(nested_type);
        return ret < 0 ? -1 : 0;
    }
    if(member->marker.flags == EM_DEFAULT) {
        ret = rust_write_sequence_decode_default(stream, member, *presence_index);
        (*presence_index)++;
        free(name);
        free(nested_type);
        return ret < 0 ? -1 : 0;
    }
    if(member->marker.flags == EM_OPTIONAL) {
        ret = fprintf(stream,
            "if __asn1c_presence[%zu] { Some(", *presence_index);
        (*presence_index)++;
        if(ret < 0) {
            free(name);
            free(nested_type);
            return -1;
        }
    }
    if(member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fputs("reader.read_boolean()?", stream);
    else if(member->expr_type == ASN_BASIC_OCTET_STRING
            || member->expr_type == ASN_BASIC_BIT_STRING) {
        size_t length;
        if(!rust_fixed_size(member, &length))
            ret = fprintf(stream, "reader.read_%s(%zu)?",
                member->expr_type == ASN_BASIC_OCTET_STRING
                    ? "octets" : "bit_string", length);
    } else {
        int64_t lower, upper;
        char low[64], high[64];
        if(!rust_integer_bounds(member, &lower, &upper)
           && !rust_format_bound(low, sizeof(low), lower)
           && !rust_format_bound(high, sizeof(high), upper))
            ret = fprintf(stream, "reader.read_integer(%s, %s)?", low, high);
    }
    if(ret >= 0 && member->marker.flags == EM_OPTIONAL)
        ret = fputs(") } else { None },\n", stream);
    else if(ret >= 0)
        ret = fputs(",\n", stream);
    free(name);
    free(nested_type);
    return ret < 0 ? -1 : 0;
}

/*
 * Emit a DEFAULT value read, substituting its literal when the bit is absent.
 * Parameters: stream receives Rust; member is a supported DEFAULT field;
 * presence_index identifies its preamble bit. Returns zero or -1 on failure.
 * Original source: X.691 DEFAULT decoding and bounded Rust value types.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: added direct BOOLEAN and bounded INTEGER DEFAULT decoding.
 * Example: rust_write_sequence_decode_default(out, field, 0).
 */
static int
rust_write_sequence_decode_default(FILE *stream, asn1p_expr_t *member,
                                   size_t presence_index) {
    char literal[64];
    if(rust_sequence_default_literal(member, literal, sizeof(literal))) return -1;
    if(member->expr_type == ASN_BASIC_BOOLEAN) {
        return fprintf(stream,
            "if __asn1c_presence[%zu] { reader.read_boolean()? } else { %s },\n",
            presence_index, literal) < 0 ? -1 : 0;
    }
    {
        int64_t lower, upper;
        char low[64], high[64];
        if(rust_integer_bounds(member, &lower, &upper)
           || rust_format_bound(low, sizeof(low), lower)
           || rust_format_bound(high, sizeof(high), upper)) return -1;
        return fprintf(stream,
            "if __asn1c_presence[%zu] { reader.read_integer(%s, %s)? } "
            "else { %s },\n", presence_index, low, high, literal) < 0 ? -1 : 0;
    }
}

/*
 * Emit the validated constructor and accessor for fixed-size string wrappers.
 * Parameters: stream receives Rust; length is the ASN.1 SIZE; octets selects
 * OCTET STRING over BIT STRING. Returns zero or -1 on output failure; it
 * throws no exception.
 * Original source: Rust fixed-string API. Version/date: 0.4.0, 2026-10-30.
 * Responsible party: asn1c maintainers. History: shared UPER/JER wrapper.
 * Example: rust_write_string_constructor(out, 3, 1).
 */
static int
rust_write_string_constructor(FILE *stream, size_t length, int octets) {
    size_t byte_length = octets ? length : (length + 7) / 8;
    if(rust_write_method_doc(stream,
            "Construct a validated fixed-size ASN.1 string.",
            "`value` contains packed content octets; fixed BIT STRING uses zero trailing pad bits.",
            "Returns the validated value.",
            "Returns an error for the wrong length or nonzero BIT STRING pad bits.",
            "`let value = Type::new(vec![0x80])?;")) return -1;
    if(fputs(
        "    pub fn new(value: ::std::vec::Vec<u8>) ->\n"
        "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n",
        stream) == EOF) return -1;
    if(byte_length == 0) {
        if(fputs("        if !value.is_empty() {\n", stream) == EOF) return -1;
    } else if(fprintf(stream, "        if value.len() != %zu {\n", byte_length) < 0) {
        return -1;
    }
    if(fputs(
        "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"fixed ASN.1 string has wrong byte length\",\n"
        "            });\n        }\n", stream) == EOF) return -1;
    if(!octets && length % 8 != 0) {
        if(fprintf(stream,
            "        if value.last().is_some_and(|byte| byte & 0x%02x != 0) {\n"
            "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
            "                reason: \"nonzero unused BIT STRING bits\",\n"
            "            });\n        }\n", (unsigned)(0xffU >> (length % 8))) < 0)
            return -1;
    }
    if(fputs("        Ok(Self(value))\n    }\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream,
            "Return the packed ASN.1 string contents.",
            "`self` is the validated string value.",
            "Returns its octets; BIT STRING unused low bits are zero.",
            "This accessor cannot fail.",
            "`let bytes = value.as_bytes();")) return -1;
    return fputs("    #[must_use]\n    pub fn as_bytes(&self) -> &[u8] { &self.0 }\n",
                 stream) == EOF ? -1 : 0;
}

/*
 * Emit selected UPER methods for one validated fixed-size string wrapper.
 * Parameters: stream receives Rust; length is SIZE; octets selects its cursor
 * method. Returns zero or -1 on output failure; it throws no exception.
 * Original source: X.691 and the
 * Rust UPER cursor. Version/date: 0.4.0, 2026-10-30. Responsible party:
 * asn1c maintainers. History: split from the fixed-string writer. Example:
 * rust_write_string_uper(out, 3, 1).
 */
static int
rust_write_string_uper(FILE *stream, size_t length, int octets) {
    if(rust_write_method_doc(stream,
            "Encode the complete fixed-size string with UPER.",
            "`self` is the value; `limits` bounds output and work.",
            "Returns packed bytes and meaningful bit length.",
            "Returns an error for invalid content or exhausted resources.",
            "`let encoded = value.encode_uper(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let mut writer = ::asn1c_runtime::UperWriter::new(limits)?;\n"
        "        writer.write_%s(&self.0, %zu)?;\n"
        "        writer.finish()\n    }\n",
        octets ? "octets" : "bit_string", length) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete fixed-size UPER string.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the string and consumed prefix lengths.",
            "Returns an error for truncation, malformed input, or exhausted resources.",
            "`let decoded = Type::decode_uper(input, &Default::default())?;")) return -1;
    return fprintf(stream,
        "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let mut reader = ::asn1c_runtime::UperReader::new(input, limits)?;\n"
        "        let value = reader.read_%s(%zu)?;\n"
        "        let consumed = reader.finish()?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(value),\n"
        "            consumed_bits: consumed.consumed_bits,\n"
        "            consumed_bytes: consumed.consumed_bytes,\n"
        "        })\n    }\n",
        octets ? "octets" : "bit_string", length) < 0 ? -1 : 0;
}

/*
 * Emit selected JER methods for one fixed-size OCTET STRING wrapper.
 * Parameters: stream receives Rust; length is the declared octet count.
 * Returns zero or -1 on output failure; it throws no exception.
 * Original source: OCTET_STRING JER
 * helpers in the Rust runtime. Version/date: 0.4.0, 2026-10-30. Responsible
 * party: asn1c maintainers. History: direct fixed-size JER support. Example:
 * rust_write_string_jer(out, 3).
 */
static int
rust_write_string_jer(FILE *stream, size_t length) {
    if(rust_write_method_doc(stream,
            "Encode this fixed-size OCTET STRING as a JER hexadecimal string.",
            "`self` is the validated value; `limits` bounds output and work.",
            "Returns compact uppercase hexadecimal JSON and full byte counts.",
            "Returns an error for invalid content or exhausted resources.",
            "`let encoded = value.encode_jer(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_jer(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_octet_string_jer(&self.0, %zu, limits)\n"
        "    }\n", length) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete fixed-size OCTET STRING JER value.",
            "`input` is the entire JSON string; `limits` bounds input and work.",
            "Returns the validated value and full-input byte and bit counts.",
            "Returns an error for malformed hex, wrong size, trailing input, or limits.",
            "`let decoded = Type::decode_jer(input, &Default::default())?;")) return -1;
    return fprintf(stream,
        "    pub fn decode_jer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_octet_string_jer(input, %zu, limits)?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(decoded.value),\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n"
        "    }\n", length) < 0 ? -1 : 0;
}

/*
 * Emit a fixed-size OCTET STRING or BIT STRING wrapper and selected codecs.
 * Parameters: stream receives source; name is the Rust type name; expr is the
 * validated fixed string assignment; codecs selects emitted methods. Returns
 * zero or -1 on output failure; it throws no exception. Original source:
 * Rust backend. Version/date:
 * 0.4.0, 2026-10-30. Responsible party: asn1c maintainers. History: split
 * UPER and JER emitters. Example: rust_write_string(out, name, expr, codecs).
 */
static int
rust_write_string(FILE *stream, const char *name, asn1p_expr_t *expr,
                  uint64_t codecs) {
    size_t length;
    const int octets = expr->expr_type == ASN_BASIC_OCTET_STRING;
    if(rust_fixed_size(expr, &length)) return -1;
    if(fprintf(stream,
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// ASN.1 string payload state variable.\n"
        "    ::std::vec::Vec<u8>\n);\n\nimpl %s {\n", name, name) < 0)
        return -1;
    if(rust_write_string_constructor(stream, length, octets)) return -1;
    if((codecs & RUST_CODEC_UPER)
       && rust_write_string_uper(stream, length, octets)) return -1;
    if(octets && (codecs & RUST_CODEC_JER)
       && rust_write_string_jer(stream, length)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one nonextensible ENUMERATED with numeric-order UPER indexes and
 * optional JER name mapping.
 * Parameters: stream receives Rust; name is the sanitized type name; expr
 * owns validated members. Returns zero or -1 on output failure; no exception.
 * Original source: X.691 root enumeration rule and asn1c_C.c value2enum.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: UPER and JER enum slice. Example:
 * rust_write_enumerated(out, name, e, RUST_CODEC_JER).
 */
static int
rust_write_enumerated(FILE *stream, const char *name, asn1p_expr_t *expr,
                      uint64_t codecs) {
    asn1p_expr_t *item;
    size_t count = 0;
    TQ_FOR(item, &expr->members, next) count++;
    if(fprintf(stream,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n"
        "pub enum %s {\n", name) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = variant ? fprintf(stream,
            "    /// ASN.1 %s root enumeration value.\n    %s,\n",
            item->Identifier, variant) : -1;
        free(variant);
        if(ret < 0) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(codecs & RUST_CODEC_UPER) {
        if(rust_write_method_doc(stream,
                "Encode a root ENUMERATED value with UPER.",
                "`self` is a root variant; `limits` bounds output and work.",
                "Returns packed bytes and meaningful bit length.",
                "Returns an error when a resource limit is exceeded.",
                "`let encoded = value.encode_uper(&Default::default())?;")) return -1;
        if(fputs(
            "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let index = match self {\n", stream) == EOF) return -1;
        TQ_FOR(item, &expr->members, next) {
            char *variant = rust_enum_variant(item->Identifier);
            int ret = variant ? fprintf(stream, "            Self::%s => %zu,\n",
                variant, rust_enumerated_rank(expr, item)) : -1;
            free(variant);
            if(ret < 0) return -1;
        }
        if(fprintf(stream,
            "        };\n"
            "        let mut writer = ::asn1c_runtime::UperWriter::new(limits)?;\n"
            "        writer.write_integer(index, 0, %zu)?;\n"
            "        writer.finish()\n    }\n", count - 1) < 0) return -1;
        if(rust_write_method_doc(stream,
                "Decode one root ENUMERATED UPER value.",
                "`input` is the encoded prefix; `limits` bounds input and work.",
                "Returns a variant and consumed prefix lengths.",
                "Returns an error for truncation, unused indexes, or exhausted resources.",
                "`let decoded = Type::decode_uper(input, &Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
            "        let mut reader = ::asn1c_runtime::UperReader::new(input, limits)?;\n"
            "        let index = reader.read_integer(0, %zu)?;\n"
            "        let value = match index {\n", count - 1) < 0) return -1;
        TQ_FOR(item, &expr->members, next) {
            char *variant = rust_enum_variant(item->Identifier);
            int ret = variant ? fprintf(stream, "            %zu => Self::%s,\n",
                rust_enumerated_rank(expr, item), variant) : -1;
            free(variant);
            if(ret < 0) return -1;
        }
        if(fputs(
            "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
            "                reason: \"unused ENUMERATED root index\",\n"
            "            }),\n"
            "        };\n"
            "        let consumed = reader.finish()?;\n"
            "        Ok(::asn1c_runtime::Decoded {\n"
            "            value,\n"
            "            consumed_bits: consumed.consumed_bits,\n"
            "            consumed_bytes: consumed.consumed_bytes,\n"
            "        })\n    }\n", stream) == EOF) return -1;
    }
    if((codecs & RUST_CODEC_JER) && rust_write_enumerated_jer(stream, expr))
        return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit complete-input JER methods for one direct nonextensible ENUMERATED.
 * Parameters: stream receives Rust source; expr owns validated root values.
 * Returns zero or -1 on output failure; no exception is thrown.
 * Original source: ENUMERATED_jer.c string mapping and the Rust JER runtime.
 * Version/date: 0.3.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: added opt-in ENUMERATED JER parity. Example:
 * rust_write_enumerated_jer(stream, expr).
 */
static int
rust_write_enumerated_jer(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *item;
    size_t index = 0;

    if(rust_write_method_doc(stream,
            "Encode this ENUMERATED root value as a JER JSON string.",
            "self is a root variant; limits bounds output and work.",
            "Returns the complete quoted name and its bit length.",
            "Returns an error for invalid values or exhausted resources.",
            "`let encoded = value.encode_jer(&Default::default())?;")) return -1;
    if(fputs(
        "    pub fn encode_jer(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let index = match self {\n", stream) == EOF) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = variant ? fprintf(stream, "            Self::%s => %zu,\n",
                                     variant, index) : -1;
        free(variant);
        if(ret < 0) return -1;
        index++;
    }
    if(fputs("        };\n        ::asn1c_runtime::encode_enumerated_jer(index, &[",
             stream) == EOF) return -1;
    index = 0;
    TQ_FOR(item, &expr->members, next) {
        if(fprintf(stream, "%s\"%s\"", index ? ", " : "", item->Identifier) < 0)
            return -1;
        index++;
    }
    if(fputs("], limits)\n    }\n", stream) == EOF) return -1;

    if(rust_write_method_doc(stream,
            "Decode one complete JER ENUMERATED JSON string.",
            "input is the entire JSON primitive; limits bounds input and work.",
            "Returns the variant and full-input bit and byte counts.",
            "Returns an error for truncation, unknown names, trailing data, or limits.",
            "`let decoded = Type::decode_jer(input, &Default::default())?;")) return -1;
    if(fputs(
        "    pub fn decode_jer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_enumerated_jer(input, &[",
        stream) == EOF) return -1;
    index = 0;
    TQ_FOR(item, &expr->members, next) {
        if(fprintf(stream, "%s\"%s\"", index ? ", " : "", item->Identifier) < 0)
            return -1;
        index++;
    }
    if(fputs("], limits)?;\n        let value = match decoded.value {\n", stream) == EOF)
        return -1;
    index = 0;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = variant ? fprintf(stream, "            %zu => Self::%s,\n",
                                     index, variant) : -1;
        free(variant);
        if(ret < 0) return -1;
        index++;
    }
    if(fputs(
        "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unknown ENUMERATED JER root index\",\n"
        "            }),\n"
        "        };\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value,\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n"
        "    }\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit the safe BOOLEAN newtype and methods for selected codecs.
 * Parameters: stream receives Rust; name is a sanitized public type name;
 * codecs selects emitted methods.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: initial BOOLEAN
 * emitter. Example: rust_write_boolean(stream, "Flag", codecs).
 */
static int
rust_write_boolean(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// ASN.1 BOOLEAN payload state variable.\n"
        "    bool\n);\n\nimpl %s {\n", name, name) < 0) return -1;
    if(rust_write_method_doc(stream, "Construct a BOOLEAN value.",
            "`value` is the BOOLEAN payload.", "Returns the new value.",
            "This constructor cannot fail.", "`let value = Type::new(true);"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub const fn new(value: bool) -> Self { Self(value) }\n",
             stream) == EOF) return -1;
    if(rust_write_method_doc(stream, "Return the BOOLEAN payload.",
            "`self` is the value to inspect.", "Returns its Boolean payload.",
            "This accessor cannot fail.", "`let bit = value.value();")) return -1;
    if(fputs("    #[must_use]\n"
             "    pub const fn value(&self) -> bool { self.0 }\n", stream)
       == EOF) return -1;
    if(codecs & RUST_CODEC_UPER) {
        /* Emit both UPER directions only when the caller selected UPER. */
        if(rust_write_method_doc(stream, "Encode this value using UPER.",
                "`self` is the value; `limits` bounds encoding resources.",
                "Returns encoded bytes and meaningful bit length.",
                "Returns a runtime error if limits are exceeded.",
                "`let encoded = value.encode_uper(&Default::default())?;"))
            return -1;
        if(fputs("    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Encoded, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::encode_boolean(self.0, limits)\n    }\n",
                 stream) == EOF) return -1;
        if(rust_write_method_doc(stream,
                "Decode one UPER value and report prefix consumption.",
                "`input` is the encoded prefix; `limits` bounds decoding.",
                "Returns the value and consumed bit and byte counts.",
                "Returns an error for incomplete, malformed, or over-limit input.",
                "`let decoded = Type::decode_uper(input, &Default::default())?;"))
            return -1;
        if(fputs("    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::decode_boolean(input, limits)\n"
                 "            .map(|decoded| decoded.map(Self))\n    }\n",
                 stream) == EOF) return -1;
    }
    if(codecs & RUST_CODEC_CER) {
        if(rust_write_method_doc(stream, "Encode this value using CER.",
                "`self` is the value; `limits` bounds output and work.",
                "Returns the complete canonical BOOLEAN TLV.",
                "Returns a runtime error if a configured limit is exceeded.",
                "`let encoded = value.encode_cer(&Default::default())?;"))
            return -1;
        if(fputs("    pub fn encode_cer(&self, limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Encoded, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::encode_boolean_cer(self.0, limits)\n"
                 "    }\n", stream) == EOF)
            return -1;
        if(rust_write_method_doc(stream,
                "Strictly decode one CER BOOLEAN TLV and report prefix consumption.",
                "`input` is the encoded prefix; `limits` bounds input and work.",
                "Returns the value and consumed bit and byte counts.",
                "Returns an error for truncated, noncanonical, malformed, or over-limit input.",
                "`let decoded = Type::decode_cer(input, &Default::default())?;"))
            return -1;
        if(fputs("    pub fn decode_cer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::decode_boolean_cer(input, limits)\n"
                 "            .map(|decoded| decoded.map(Self))\n    }\n",
                 stream) == EOF)
            return -1;
    }
    if((codecs & RUST_CODEC_BER) && rust_write_boolean_ber(stream)) return -1;
    if((codecs & RUST_CODEC_APER)
       && rust_write_per_oer(stream, "aper", "boolean", NULL, NULL)) return -1;
    if((codecs & RUST_CODEC_OER)
       && rust_write_per_oer(stream, "oer", "boolean", NULL, NULL)) return -1;
    if((codecs & RUST_CODEC_JER)
       && rust_write_per_oer(stream, "jer", "boolean", NULL, NULL)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit the BOOLEAN DER encoder and BER prefix decoder methods.
 * Parameters: stream receives Rust source. Returns zero or -1. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-30. Responsible
 * party: asn1c maintainers. History: extracted to keep emitter complexity
 * bounded. Example: rust_write_boolean_ber(stream) emits both methods.
 */
static int
rust_write_boolean_ber(FILE *stream) {
    if(rust_write_method_doc(stream, "Encode this value using DER.",
            "`self` is the value; `limits` bounds output and work.",
            "Returns the complete canonical BOOLEAN TLV.",
            "Returns a runtime error if a configured limit is exceeded.",
            "`let encoded = value.encode_der(&Default::default())?;"))
        return -1;
    if(fputs("    pub fn encode_der(&self, limits: &::asn1c_runtime::Limits) ->\n"
             "        ::core::result::Result<::asn1c_runtime::Encoded, "
             "::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::encode_boolean_der(self.0, limits)\n"
             "    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream,
            "Decode one BER BOOLEAN TLV and report prefix consumption.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the value and consumed bit and byte counts.",
            "Returns an error for truncation, malformed input, or BOOLEAN "
            "content not exactly one octet.",
            "`let decoded = Type::decode_ber(input, &Default::default())?;"))
        return -1;
    if(fputs("    pub fn decode_ber(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
             "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
             "::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::decode_boolean_ber(input, limits)\n"
             "            .map(|decoded| decoded.map(Self))\n    }\n",
             stream) == EOF)
        return -1;
    return 0;
}

/*
 * Emit the safe NULL unit type and methods for selected codecs.
 * Parameters: stream receives Rust; name is a sanitized public type name;
 * codecs selects emitted methods.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: initial NULL
 * emitter. Example: rust_write_null(stream, "Empty", codecs).
 */
static int
rust_write_null(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream,
        "#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]\n"
        "pub struct %s;\n\nimpl %s {\n", name, name) < 0) return -1;
    if(codecs & RUST_CODEC_UPER) {
        /* Emit both UPER directions only when the caller selected UPER. */
        if(rust_write_method_doc(stream, "Encode this NULL value using UPER.",
                "`self` is the NULL value; `limits` bounds encoding resources.",
                "Returns the zero-width encoding.",
                "Returns a runtime error if limits are exceeded.",
                "`let encoded = value.encode_uper(&Default::default())?;"))
            return -1;
        if(fputs("    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Encoded, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::encode_null(limits)\n    }\n", stream)
           == EOF)
            return -1;
        if(rust_write_method_doc(stream,
                "Decode one UPER NULL value and report prefix consumption.",
                "`input` is the encoded prefix; `limits` bounds decoding.",
                "Returns the unit value and consumed bit and byte counts.",
                "Returns an error for incomplete, malformed, or over-limit input.",
                "`let decoded = Type::decode_uper(input, &Default::default())?;"))
            return -1;
        if(fputs("    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::decode_null(input, limits)\n"
                 "            .map(|decoded| decoded.map(|()| Self))\n    }\n",
                 stream) == EOF)
            return -1;
    }
    if(codecs & RUST_CODEC_CER) {
        if(rust_write_method_doc(stream, "Encode this NULL value using CER.",
                "`self` is the NULL value; `limits` bounds output and work.",
                "Returns the complete canonical NULL TLV.",
                "Returns a runtime error if a configured limit is exceeded.",
                "`let encoded = value.encode_cer(&Default::default())?;"))
            return -1;
        if(fputs("    pub fn encode_cer(&self, limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Encoded, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::encode_null_cer(limits)\n"
                 "    }\n", stream) == EOF)
            return -1;
        if(rust_write_method_doc(stream,
                "Strictly decode one CER NULL TLV and report prefix consumption.",
                "`input` is the encoded prefix; `limits` bounds input and work.",
                "Returns the value and consumed bit and byte counts.",
                "Returns an error for truncated, noncanonical, malformed, or over-limit input.",
                "`let decoded = Type::decode_cer(input, &Default::default())?;"))
            return -1;
        if(fputs("    pub fn decode_cer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
                 "::asn1c_runtime::Error> {\n"
                 "        ::asn1c_runtime::decode_null_cer(input, limits)\n"
                 "            .map(|decoded| decoded.map(|()| Self))\n    }\n",
                 stream) == EOF)
            return -1;
    }
    if((codecs & RUST_CODEC_BER) && rust_write_null_ber(stream)) return -1;
    if((codecs & RUST_CODEC_APER)
       && rust_write_per_oer(stream, "aper", "null", NULL, NULL)) return -1;
    if((codecs & RUST_CODEC_OER)
       && rust_write_per_oer(stream, "oer", "null", NULL, NULL)) return -1;
    if((codecs & RUST_CODEC_JER)
       && rust_write_per_oer(stream, "jer", "null", NULL, NULL)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit the NULL DER encoder and BER prefix decoder methods.
 * Parameters: stream receives Rust source. Returns zero or -1. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-30. Responsible
 * party: asn1c maintainers. History: extracted to keep emitter complexity
 * bounded. Example: rust_write_null_ber(stream) emits both methods.
 */
static int
rust_write_null_ber(FILE *stream) {
    if(rust_write_method_doc(stream, "Encode this NULL value using DER.",
            "`self` is the NULL value; `limits` bounds output and work.",
            "Returns the complete canonical NULL TLV.",
            "Returns a runtime error if a configured limit is exceeded.",
            "`let encoded = value.encode_der(&Default::default())?;"))
        return -1;
    if(fputs("    pub fn encode_der(&self, limits: &::asn1c_runtime::Limits) ->\n"
             "        ::core::result::Result<::asn1c_runtime::Encoded, "
             "::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::encode_null_der(limits)\n"
             "    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream,
            "Decode one BER NULL TLV and report prefix consumption.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the value and consumed bit and byte counts.",
            "Returns an error for truncated, malformed, or over-limit input.",
            "`let decoded = Type::decode_ber(input, &Default::default())?;"))
        return -1;
    if(fputs("    pub fn decode_ber(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
             "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
             "::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::decode_null_ber(input, limits)\n"
             "            .map(|decoded| decoded.map(|()| Self))\n    }\n",
             stream) == EOF)
        return -1;
    return 0;
}

/*
 * Emit a bounded i64 newtype and methods for selected codecs.
 * Parameters: stream receives Rust; name is public type name; lower and upper
 * are inclusive bounds; codecs selects emitted methods. Returns zero or -1.
 * Original source: new Rust
 * backend. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: initial constrained INTEGER emitter. Example:
 * rust_write_integer(stream, "Count", 0, 7, codecs).
 */
static int
rust_write_integer(FILE *stream, const char *name, int64_t lower,
                   int64_t upper, uint64_t codecs) {
    char low[64], high[64];
    int bounds_error = rust_format_bound(low, sizeof(low), lower);
    /* Format both endpoints before checking the combined error status. */
    bounds_error |= rust_format_bound(high, sizeof(high), upper);
    if(bounds_error) return -1;
    if(fprintf(stream,
        "/// Inclusive ASN.1 INTEGER bounds are `%s..=%s`.\n"
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// ASN.1 INTEGER payload state variable.\n"
        "    i64\n);\n\nimpl %s {\n", low, high, name, name) < 0)
        return -1;
    if(rust_write_method_doc(stream,
            "Construct an INTEGER after checking its ASN.1 range.",
            "`value` is the candidate signed integer.",
            "Returns a value when it lies inside the inclusive schema range.",
            "Returns a runtime error when the value is outside the range.",
            "`let value = Type::new(3)?;")) return -1;
    if(fprintf(stream,
        "    pub fn new(value: i64) -> ::core::result::Result<Self, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::validate_integer(value, %s, %s)?;\n"
        "        ::core::result::Result::Ok(Self(value))\n    }\n", low, high)
       < 0) return -1;
    if(rust_write_method_doc(stream, "Return the INTEGER payload.",
            "`self` is the value to inspect.", "Returns the signed integer payload.",
            "This accessor cannot fail.", "`let number = value.value();")) return -1;
    if(fputs("    #[must_use]\n"
             "    pub const fn value(&self) -> i64 { self.0 }\n", stream)
       == EOF) return -1;
    if(codecs & RUST_CODEC_UPER) {
        /* Emit both UPER directions only when the caller selected UPER. */
        if(rust_write_method_doc(stream, "Encode this value using UPER.",
                "`self` is the value; `limits` bounds encoding resources.",
                "Returns encoded bytes and meaningful bit length.",
                "Returns a runtime error if limits are exceeded.",
                "`let encoded = value.encode_uper(&Default::default())?;"))
            return -1;
        if(fprintf(stream,
            "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, "
            "::asn1c_runtime::Error> {\n"
            "        ::asn1c_runtime::encode_integer(self.0, %s, %s, limits)\n"
            "    }\n", low, high) < 0) return -1;
        if(rust_write_method_doc(stream,
                "Decode one UPER value and report prefix consumption.",
                "`input` is the encoded prefix; `limits` bounds decoding.",
                "Returns the value and consumed bit and byte counts.",
                "Returns an error for incomplete, malformed, out-of-range, or over-limit input.",
                "`let decoded = Type::decode_uper(input, &Default::default())?;"))
            return -1;
        if(fprintf(stream,
            "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
            "::asn1c_runtime::Error> {\n"
            "        ::asn1c_runtime::decode_integer(input, %s, %s, limits)\n"
            "            .map(|decoded| decoded.map(Self))\n    }\n", low, high) < 0)
            return -1;
    }
    if(codecs & RUST_CODEC_CER) {
        if(rust_write_method_doc(stream, "Encode this value using CER.",
                "`self` is the value; `limits` bounds output and work.",
                "Returns the complete minimal signed INTEGER TLV.",
                "Returns a runtime error if a configured limit is exceeded.",
                "`let encoded = value.encode_cer(&Default::default())?;"))
            return -1;
        if(fprintf(stream,
            "    pub fn encode_cer(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, "
            "::asn1c_runtime::Error> {\n"
            "        ::asn1c_runtime::encode_integer_cer(self.0, %s, %s, limits)\n"
            "    }\n", low, high) < 0)
            return -1;
        if(rust_write_method_doc(stream,
                "Strictly decode one CER INTEGER TLV and report prefix consumption.",
                "`input` is the encoded prefix; `limits` bounds input and work.",
                "Returns the value and consumed bit and byte counts.",
                "Returns an error for truncated, noncanonical, malformed, or over-limit input.",
                "`let decoded = Type::decode_cer(input, &Default::default())?;"))
            return -1;
        if(fprintf(stream,
            "    pub fn decode_cer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
            "::asn1c_runtime::Error> {\n"
            "        ::asn1c_runtime::decode_integer_cer(input, %s, %s, limits)\n"
            "            .map(|decoded| decoded.map(Self))\n    }\n", low, high) < 0)
            return -1;
    }
    if((codecs & RUST_CODEC_BER)
       && rust_write_integer_ber(stream, low, high)) return -1;
    if((codecs & RUST_CODEC_APER)
       && rust_write_per_oer(stream, "aper", "integer", low, high)) return -1;
    if((codecs & RUST_CODEC_OER)
       && rust_write_per_oer(stream, "oer", "integer", low, high)) return -1;
    if((codecs & RUST_CODEC_JER)
       && rust_write_per_oer(stream, "jer", "integer", low, high)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit the bounded INTEGER DER encoder and BER prefix decoder methods.
 * Parameters: stream receives Rust source; low and high are Rust bound
 * expressions. Returns zero or -1. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: extracted to keep emitter complexity bounded. Example:
 * rust_write_integer_ber(stream, "-10", "10").
 */
static int
rust_write_integer_ber(FILE *stream, const char *low, const char *high) {
    if(rust_write_method_doc(stream, "Encode this value using DER.",
            "`self` is the value; `limits` bounds output and work.",
            "Returns the complete minimal signed INTEGER TLV.",
            "Returns a runtime error if a configured limit is exceeded.",
            "`let encoded = value.encode_der(&Default::default())?;"))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_der(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_integer_der(self.0, %s, %s, limits)\n"
        "    }\n", low, high) < 0)
        return -1;
    if(rust_write_method_doc(stream,
            "Decode one BER INTEGER TLV and report prefix consumption.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the value and consumed bit and byte counts.",
            "Returns an error for truncated, malformed, out-of-range, or "
            "over-limit input.",
            "`let decoded = Type::decode_ber(input, &Default::default())?;"))
        return -1;
    if(fprintf(stream,
        "    pub fn decode_ber(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_integer_ber(input, %s, %s, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n", low, high) < 0)
        return -1;
    return 0;
}

/*
 * Emit one complete primitive APER, OER, or JER method pair.
 * Parameters: stream receives Rust; codec is "aper", "oer", or "jer"; kind is one of
 * "boolean", "null", or "integer"; low and high are required INTEGER bounds.
 * Returns zero or -1 for invalid arguments or output failure; no exception is
 * thrown. Original source: asn1c Rust backend. Version/date: 0.2.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: added primitive
 * APER/OER/JER generation. Example: rust_write_per_oer(out, "oer", "null", NULL,
 * NULL) emits the NULL codec pair.
 */
static int
rust_write_per_oer(FILE *stream, const char *codec, const char *kind,
                   const char *low, const char *high) {
    char encode_args[192];
    char decode_args[192];
    char purpose[96];
    char example[96];
    const char *mapping;
    const char *label;
    const char *decode_input;
    const char *decode_returns;
    int written;

    if(!stream || !codec || !kind
       || (strcmp(codec, "aper") && strcmp(codec, "oer")
           && strcmp(codec, "jer"))) return -1;
    label = !strcmp(codec, "aper") ? "APER"
          : !strcmp(codec, "oer") ? "OER" : "JER";
    decode_input = !strcmp(codec, "jer")
        ? "`input` is one complete JSON primitive; `limits` bounds input and work."
        : "`input` is the encoded prefix; `limits` bounds input and work.";
    decode_returns = !strcmp(codec, "jer")
        ? "Returns the value and full-input bit and byte counts."
        : "Returns the value and consumed bit and byte counts.";
    if(!strcmp(kind, "integer")) {
        if(!low || !high) return -1;
        written = snprintf(encode_args, sizeof(encode_args),
                           "self.0, %s, %s, limits", low, high);
        if(written < 0 || (size_t)written >= sizeof(encode_args)) return -1;
        written = snprintf(decode_args, sizeof(decode_args),
                           "input, %s, %s, limits", low, high);
        if(written < 0 || (size_t)written >= sizeof(decode_args)) return -1;
        mapping = "Self";
    } else if(!strcmp(kind, "boolean")) {
        strcpy(encode_args, "self.0, limits");
        strcpy(decode_args, "input, limits");
        mapping = "Self";
    } else if(!strcmp(kind, "null")) {
        strcpy(encode_args, "limits");
        strcpy(decode_args, "input, limits");
        mapping = "|()| Self";
    } else {
        return -1;
    }

    written = snprintf(purpose, sizeof(purpose), "Encode this value using %s.", label);
    if(written < 0 || (size_t)written >= sizeof(purpose)) return -1;
    written = snprintf(example, sizeof(example),
                       "`let encoded = value.encode_%s(&Default::default())?;", codec);
    if(written < 0 || (size_t)written >= sizeof(example)) return -1;
    if(rust_write_method_doc(stream, purpose,
            "`self` is the value; `limits` bounds output and work.",
            "Returns encoded bytes and meaningful bit length.",
            "Returns an error for an invalid value or exhausted resources.",
            example)) return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_%s_%s(%s)\n    }\n",
        codec, kind, codec, encode_args) < 0) return -1;
    written = snprintf(purpose, sizeof(purpose), "Decode one %s value.", label);
    if(written < 0 || (size_t)written >= sizeof(purpose)) return -1;
    written = snprintf(example, sizeof(example),
                       "`let decoded = Type::decode_%s(input, &Default::default())?;", codec);
    if(written < 0 || (size_t)written >= sizeof(example)) return -1;
    if(rust_write_method_doc(stream, purpose,
            decode_input, decode_returns,
            "Returns an error for incomplete, malformed, or over-limit input.",
            example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_%s_%s(%s)\n"
        "            .map(|decoded| decoded.map(%s))\n    }\n",
        codec, kind, codec, decode_args, mapping) < 0) return -1;
    return 0;
}

/*
 * Emit the complete API documentation required for a generated public method.
 * Parameters: stream receives Rust doc comments; purpose, inputs, returns,
 * errors, and example describe one method. Returns zero or -1. Original source:
 * new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: initial generated API docs. Example:
 * rust_write_method_doc(stream, "Encode", "...", "...", "...", "...").
 */
static int
rust_write_method_doc(FILE *stream, const char *purpose, const char *inputs,
                      const char *returns, const char *errors,
                      const char *example) {
    return fprintf(stream,
        "    /// %s\n    ///\n    /// # Parameters\n    /// %s\n"
        "    ///\n    /// # Returns\n    /// %s\n    ///\n"
        "    /// # Errors\n    /// %s\n    ///\n"
        "    /// # Source, version, history, and example\n"
        "    /// Original source: generated from the ASN.1 fixed tree.\n"
        "    /// Version/date: 0.1.0, 2026-10-11.\n"
        "    /// Responsible party: asn1c maintainers.\n"
        "    /// History: emitted by the codec-aware Rust backend.\n"
        "    /// Example: %s`\n",
        purpose, inputs, returns, errors, example) < 0 ? -1 : 0;
}

/*
 * Write the Cargo crate root and its module declarations.
 * Parameters: asn is the fixed tree; path is the staged src/lib.rs path.
 * Returns zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: first crate root
 * emitter. Example: rust_write_lib(tree, path).
 */
static int
rust_write_lib(asn1p_t *asn, const char *path) {
    FILE *stream = fopen(path, "wb");
    asn1p_module_t *module;
    int ret = 0;
    if(!stream) return -1;
    fputs("//! Generated ASN.1 Rust crate.\n#![forbid(unsafe_code)]\n\n", stream);
    TQ_FOR(module, &asn->modules, mod_next) {
        char *name;
        if(module->_tags & MT_STANDARD_MODULE) continue;
        name = rust_identifier(module->ModuleName, 1);
        if(!name || fprintf(stream, "pub mod %s;\n", name) < 0) ret = -1;
        free(name);
        if(ret) break;
    }
    if(fclose(stream) != 0) ret = -1;
    return ret;
}

/*
 * Write a source module directly into the staged crate.
 * Parameters: module is the fixed source module; stage is the project root;
 * codecs selects emitted methods. Returns zero
 * or -1. Original source: new Rust backend. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: initial module-file writer.
 * Example: called once for each nonstandard ASN.1 module.
 */
static int
rust_write_module_file(asn1p_module_t *module, const char *stage,
                       uint64_t codecs) {
    char *name = rust_identifier(module->ModuleName, 1);
    char path[PATH_MAX];
    FILE *stream;
    int ret;
    if(!name) return -1;
    {
        int written = snprintf(path, sizeof(path), "%s/src/%s.rs", stage, name);
        if(written < 0 || (size_t)written >= sizeof(path)) {
            free(name);
            return -1;
        }
    }
    free(name);
    stream = fopen(path, "wb");
    if(!stream) return -1;
    ret = rust_write_module(stream, module, codecs);
    if(fclose(stream) != 0) ret = -1;
    return ret;
}

/*
 * Write the deterministic list of project files owned by this generator.
 * Parameters: asn is the fixed tree; stage is the project root. Returns zero
 * or -1. Original source: new Rust backend. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: initial cleanup manifest.
 * Example: rust_write_manifest(tree, stage).
 */
static int
rust_write_manifest(asn1p_t *asn, const char *stage) {
    static const char *const fixed[] = {
        "Cargo.toml", "src/lib.rs", "runtime/Cargo.toml", "runtime/README.md",
        "runtime/LICENSE", "runtime/src/lib.rs", "runtime/src/jer.rs",
        "runtime/src/aper.rs",
        "runtime/src/oer.rs", "runtime/src/uper_cursor.rs"
    };
    char path[PATH_MAX];
    FILE *stream;
    size_t i;
    asn1p_module_t *module;
    if(rust_join(path, sizeof(path), stage, ".asn1c-rust-files")) return -1;
    stream = fopen(path, "wb");
    if(!stream) return -1;
    for(i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        if(fprintf(stream, "%s\n", fixed[i]) < 0) goto failure;
    }
    TQ_FOR(module, &asn->modules, mod_next) {
        char *name;
        if(module->_tags & MT_STANDARD_MODULE) continue;
        name = rust_identifier(module->ModuleName, 1);
        if(!name) goto failure;
        if(fprintf(stream, "src/%s.rs\n", name) < 0) {
            free(name);
            goto failure;
        }
        free(name);
    }
    if(fclose(stream) != 0) return -1;
    return 0;
failure:
    fclose(stream);
    return -1;
}

/*
 * Create a crate Cargo.toml with only the local runtime dependency.
 * Parameters: stream is the new manifest file. Returns zero or -1. Original
 * source: new Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: initial std-only project. Example:
 * rust_write_cargo(stream).
 */
static int
rust_write_cargo(FILE *stream) {
    return fputs("[package]\nname = \"asn1c-generated\"\nversion = \"0.1.0\"\n"
                 "edition = \"2021\"\n\n[dependencies]\n"
                 "asn1c-runtime = { path = \"runtime\" }\n", stream) < 0
               ? -1 : 0;
}

/*
 * Copy one regular runtime source file without following a final symlink.
 * Parameters: source and destination are explicit runtime file paths. Returns
 * zero or -1. Original source: new Rust backend. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: initial vendoring
 * helper. Example: rust_copy_file(runtime_source, staged_copy).
 */
static int
rust_copy_file(const char *source, const char *destination) {
    struct stat status;
    FILE *input;
    FILE *output;
    char buffer[8192];
    size_t count;
    int failed = 0;
    if(lstat(source, &status) != 0 || !S_ISREG(status.st_mode)) {
        fprintf(stderr, "asn1c: refusing non-regular Rust runtime asset: %s\n",
                source);
        return -1;
    }
    input = fopen(source, "rb");
    if(!input) return -1;
    output = fopen(destination, "wb");
    if(!output) {
        fclose(input);
        return -1;
    }
    while((count = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        if(fwrite(buffer, 1, count, output) != count) {
            failed = 1;
            break;
        }
    }
    if(ferror(input)) failed = 1;
    if(fclose(input) != 0) failed = 1;
    if(fclose(output) != 0) failed = 1;
    return failed ? -1 : 0;
}

/*
 * Join two filesystem path components with bounded output.
 * Parameters: output is the destination buffer; capacity is its size; left
 * and right are path components. Returns zero or -1. Original source: new
 * Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: initial path helper. Example: rust_join(buf, cap,
 * "crate", "src/lib.rs").
 */
static int
rust_join(char *output, size_t capacity, const char *left, const char *right) {
    size_t left_len = strlen(left);
    int written = snprintf(output, capacity, "%s%s%s", left,
                           left_len && left[left_len - 1] == '/' ? "" : "/",
                           right);
    return written < 0 || (size_t)written >= capacity ? -1 : 0;
}

/*
 * Format an inclusive i64 bound as compilable Rust source.
 * Parameters: output is the destination buffer; capacity is its size; value
 * is the bound. Returns zero or -1. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: first bound formatter. Example: rust_format_bound(buf, n, INT64_MIN).
 */
static int
rust_format_bound(char *output, size_t capacity, int64_t value) {
    int written;
    if(value == INT64_MIN) written = snprintf(output, capacity, "i64::MIN");
    else if(value == INT64_MAX) written = snprintf(output, capacity, "i64::MAX");
    else written = snprintf(output, capacity, "%" PRId64, value);
    return written < 0 || (size_t)written >= capacity ? -1 : 0;
}

/*
 * Publish the staged project after validating any prior output ownership.
 * Parameters: output contains complete stage and final paths. Returns zero or
 * -1 and rolls back the old directory if a rename fails. Original source: new
 * Rust backend. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: initial replacement transaction. Example:
 * rust_publish_project(&output).
 */
static int
rust_publish_project(rust_output_t *output) {
    struct stat status;
    unsigned attempt;
    int exists = lstat(output->target, &status) == 0;
    if(!exists && errno != ENOENT) {
        fprintf(stderr, "asn1c: cannot inspect Rust destination %s: %s\n",
                output->target, strerror(errno));
        return -1;
    }
    if(exists && rust_check_existing(output->target)) return -1;
    if(exists) {
        for(attempt = 0; attempt < 100; attempt++) {
            int written = snprintf(output->backup, sizeof(output->backup),
                "%s.asn1c-backup-%ld-%u", output->target,
                (long)rust_getpid(), attempt);
            if(written < 0 || (size_t)written >= sizeof(output->backup))
                return -1;
            if(lstat(output->backup, &status) != 0 && errno == ENOENT) break;
        }
        if(attempt == 100 || rename(output->target, output->backup) != 0) {
            fprintf(stderr, "asn1c: cannot preserve prior Rust project %s: %s\n",
                    output->target, strerror(errno));
            return -1;
        }
        output->target_moved = 1;
    }
    if(rename(output->stage, output->target) != 0) {
        int saved_errno = errno;
        if(output->target_moved) rename(output->backup, output->target);
        errno = saved_errno;
        fprintf(stderr, "asn1c: cannot publish Rust project %s: %s\n",
                output->target, strerror(errno));
        return -1;
    }
    output->stage_created = 0;
    if(output->target_moved) {
        if(rust_remove_tree(output->backup)) {
            fprintf(stderr, "asn1c: Rust project published but old files remain at %s\n",
                    output->backup);
            return -1;
        }
        output->target_moved = 0;
    }
    return 0;
}

/*
 * Accept only an empty directory or a crate whose ownership manifest is valid.
 * Parameters: path is the existing destination. Returns zero if safe to replace;
 * otherwise -1 without modifying it. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: initial managed-output preflight. Example:
 * rust_check_existing("generated-crate").
 */
static int
rust_check_existing(const char *path) {
    struct stat status;
    char manifest[PATH_MAX];
    if(lstat(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, "asn1c: Rust destination is not a real directory: %s\n",
                path);
        return -1;
    }
    if(rust_join(manifest, sizeof(manifest), path, ".asn1c-rust-files"))
        return -1;
    if(lstat(manifest, &status) != 0) {
        if(errno != ENOENT) return -1;
        return rust_check_directory_entries(path);
    }
    if(!S_ISREG(status.st_mode) || rust_validate_manifest(path, manifest, NULL)) {
        fprintf(stderr, "asn1c: unsafe Rust ownership manifest in %s\n", path);
        return -1;
    }
    if(rust_check_owned_tree(path, "", manifest)) return -1;
    return 0;
}

/*
 * Refuse a directory without a manifest unless it is completely empty.
 * Parameters: path is the requested output directory. Returns zero only when
 * empty; never changes files. Original source: new Rust backend. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: split
 * destination preflight. Example: rust_check_directory_entries(path).
 */
static int
rust_check_directory_entries(const char *path) {
    DIR *directory = opendir(path);
    struct dirent *entry;
    if(!directory) return -1;
    while((entry = readdir(directory))) {
        if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        closedir(directory);
        fprintf(stderr, "asn1c: refusing unrelated existing Rust destination %s\n",
                path);
        return -1;
    }
    return closedir(directory) == 0 ? 0 : -1;
}

/*
 * Validate a bounded ownership manifest and each listed path.
 * Parameters: root is the generated crate; manifest is its ownership file;
 * bytes optionally receives the parsed byte count. Returns zero or -1.
 * Original source: new Rust backend. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: split destination preflight.
 * Example: rust_manifest_line_valid(root, manifest, NULL).
 */
static int
rust_validate_manifest(const char *root, const char *manifest, size_t *bytes) {
    FILE *stream = fopen(manifest, "r");
    char line[PATH_MAX];
    char listed[PATH_MAX];
    size_t total = 0;
    size_t entries = 0;
    if(!stream) return -1;
    while(fgets(line, sizeof(line), stream)) {
        char *end = strchr(line, '\n');
        struct stat status;
        if(!end) goto failure;
        total += (size_t)(end - line) + 1;
        *end = '\0';
        if(rust_manifest_line_valid(root, line, listed)) goto failure;
        entries++;
        if(total > RUST_MANIFEST_LIMIT || entries > RUST_MANIFEST_ENTRY_LIMIT)
            goto failure;
        if(lstat(listed, &status) != 0 || S_ISLNK(status.st_mode)
           || !S_ISREG(status.st_mode)) goto failure;
    }
    if(ferror(stream) || !entries) goto failure;
    if(fclose(stream) != 0) return -1;
    if(bytes) *bytes = total;
    return 0;
failure:
    fclose(stream);
    return -1;
}

/*
 * Validate one manifest relative path and form its full destination path.
 * Parameters: root is the generated crate; relative is a manifest entry; full
 * receives its path. Returns zero or -1. Original source: new Rust backend.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: split from bounded manifest parsing. Example:
 * rust_manifest_line_valid(root, "src/lib.rs", full).
 */
static int
rust_manifest_line_valid(const char *root, const char *relative, char *full) {
    if(!relative[0] || relative[0] == '/') return -1;
    if(strstr(relative, "..") || strchr(relative, '\\') || strchr(relative, ':'))
        return -1;
    if(!rust_manifest_path_allowed(relative)) return -1;
    return rust_join(full, PATH_MAX, root, relative);
}
