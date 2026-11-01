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
#define RUST_CODEC_XER ((uint64_t)A1C_GEN_XER)
#define RUST_CODEC_CBOR ((uint64_t)A1C_GEN_CBOR)
#define RUST_CODEC_MASK (RUST_CODEC_UPER | RUST_CODEC_BER | RUST_CODEC_CER \
                         | RUST_CODEC_APER | RUST_CODEC_OER | RUST_CODEC_JER | RUST_CODEC_CBOR | RUST_CODEC_XER)
#define RUST_CONSTRAINT_DEPTH_LIMIT 128
#define RUST_IDENTIFIER_LIMIT 80
#define RUST_MANIFEST_LIMIT (1024 * 1024)
#define RUST_MANIFEST_ENTRY_LIMIT 4096
#define RUST_SEQUENCE_FIELD_LIMIT 64
#define RUST_SEQUENCE_DEPTH_LIMIT 16
#define RUST_SEQUENCE_NODE_LIMIT 64
#define RUST_SEQUENCE_WORK_LIMIT 256
#define RUST_BER_CER_FIELD_LIMIT 6
#define RUST_BER_CER_NODE_LIMIT 2
#define RUST_BER_CER_WORK_LIMIT 12
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

/* Bounded, nonextensible IOC-selected primitive row. */
typedef struct rust_open_row_s {
    int64_t key;   /* Selector key state variable. */
    int64_t lower; /* Inclusive value lower bound state variable. */
    int64_t upper; /* Inclusive value upper bound state variable. */
    int boolean;   /* BOOLEAN row state variable. */
} rust_open_row_t;

/* Validated one-record IOC OPEN TYPE generation plan. */
typedef struct rust_open_plan_s {
    asn1p_expr_t *sequence; /* Containing record state variable. */
    asn1p_expr_t *selector; /* Required selector member state variable. */
    asn1p_expr_t *member;   /* Required selected member state variable. */
    int64_t lower;         /* Selector lower bound state variable. */
    int64_t upper;         /* Selector upper bound state variable. */
    size_t rows;           /* Validated row count state variable. */
    rust_open_row_t row[32]; /* Bounded row state variables. */
} rust_open_plan_t;

static int rust_open_module_plan(asn1p_module_t *, rust_open_plan_t *);
static int rust_write_open_module(FILE *, const rust_open_plan_t *, uint64_t);
static int rust_open_write_cbor_encode(FILE *, const rust_open_plan_t *, const char *,
                                       const char *, const char *);
static int rust_open_write_cbor_decode(FILE *, const rust_open_plan_t *, const char *,
                                       const char *, const char *);
static char *rust_identifier(const char *, int);
static char *rust_enum_variant(const char *);
static int rust_check_tree(asn1p_t *, uint64_t);
static int rust_check_xer_record(asn1p_module_t *, asn1p_expr_t *);
static int rust_write_xer_record(FILE *, const char *, asn1p_expr_t *);
static int rust_check_module(asn1p_t *, asn1p_module_t *, int *, uint64_t);
static int rust_check_module_name(asn1p_t *, asn1p_module_t *);
static int rust_check_module_types(asn1p_module_t *, int *, uint64_t);
static int rust_check_type_name(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_unconstrained_string_codecs(asn1p_module_t *,
                                                asn1p_expr_t *, uint64_t);
static asn1p_expr_t *rust_contained_primitive(asn1p_module_t *, asn1p_expr_t *);
static const asn1p_constraint_t *rust_containing_node(const asn1p_constraint_t *, unsigned);
static int rust_write_containing(FILE *, const char *, asn1p_expr_t *, asn1p_expr_t *, uint64_t);
static int rust_check_type(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_tagged_record_root_candidate(const asn1p_expr_t *, uint64_t);
static int rust_check_sequence(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_sequence_ber_cer(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_set_ber_cer(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_cbor_sequence(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_cbor_choice(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_sequence_tree(asn1p_module_t *, asn1p_expr_t *,
                                   asn1p_expr_t **, size_t, size_t *, size_t *);
static int rust_check_module_nested_names(asn1p_module_t *);
static int rust_collect_nested_names(asn1p_module_t *, asn1p_expr_t *,
                                     const char *, char **, size_t *, size_t);
static int rust_check_sequence_member(asn1p_module_t *, asn1p_expr_t *);
static int rust_sequence_member_shape_valid(const asn1p_expr_t *);
static int rust_ber_cer_member_tag(const asn1p_expr_t *, int *, uint32_t *);
static int rust_ber_cer_member_explicit(const asn1p_expr_t *);
static int rust_ber_cer_has_tagged_members(asn1p_expr_t *);
static int rust_ber_cer_has_nested_sequence(asn1p_expr_t *);
static int rust_ber_cer_has_empty_nested_sequence(asn1p_expr_t *);
static int rust_ber_cer_tag_compare(const asn1p_expr_t *, const asn1p_expr_t *);
static int rust_ber_cer_duplicate_tag(asn1p_expr_t *, asn1p_expr_t *);
static int rust_ber_cer_member_shape_valid(asn1p_expr_t *);
static int rust_check_ber_cer_member(asn1p_module_t *, asn1p_expr_t *,
                                    asn1p_expr_t *, int, size_t *);
static int rust_check_ber_cer_nested_sequence(asn1p_module_t *, asn1p_expr_t *,
                                               size_t *);
static int rust_ber_cer_nested_sequence_shape_valid(asn1p_expr_t *);
static const char *rust_ber_cer_field_kind(const asn1p_expr_t *);
static const char *rust_ber_cer_tag_class(int);
static int rust_format_tag_number(char *, size_t, uint32_t);
static int rust_ber_cer_tag_local(const asn1p_expr_t *, char *, size_t);
static int rust_write_ber_cer_tag_locals(FILE *, asn1p_expr_t *);
static int rust_write_ber_cer_reader_tag_locals(FILE *, asn1p_expr_t *);
static int rust_write_ber_cer_tag(FILE *, const asn1p_expr_t *);
static int rust_write_ber_cer_field_descriptors(FILE *, asn1p_expr_t *, const char *);
static int rust_write_ber_cer_field_descriptor(FILE *, asn1p_expr_t *, const char *);
static int rust_sequence_default_literal(asn1p_expr_t *, char *, size_t);
static int rust_sequence_has_presence(const asn1p_expr_t *);
static int rust_check_sequence_name(asn1p_module_t *, asn1p_expr_t *, asn1p_expr_t *);
static int rust_constraint_supported(const asn1p_constraint_t *, unsigned);
static int rust_integer_bounds(asn1p_expr_t *, int64_t *, int64_t *);
static int rust_size_constraint_supported(const asn1p_constraint_t *, unsigned);
static int rust_fixed_size(asn1p_expr_t *, size_t *);
static int rust_bounded_size(asn1p_expr_t *, size_t *, size_t *);
static int rust_size_single_range_supported(const asn1p_constraint_t *,
                                            unsigned, int *);
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
static int rust_write_any(FILE *, const char *, uint64_t);
static int rust_write_any_codec(FILE *, const char *, const char *, const char *);
static int rust_write_boolean(FILE *, const char *, uint64_t);
static int rust_write_boolean_ber(FILE *);
static int rust_write_null(FILE *, const char *, uint64_t);
static int rust_write_null_ber(FILE *);
static int rust_write_integer(FILE *, const char *, int64_t, int64_t, uint64_t);
static int rust_write_big_integer(FILE *, const char *, uint64_t);
static int rust_write_big_integer_ber_cer(FILE *, int);
static int rust_write_string(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_unconstrained_string(FILE *, const char *, int, uint64_t);
static int rust_write_unconstrained_string_ber_cer(FILE *, int, int);
static int rust_write_bounded_octets(FILE *, const char *, size_t, size_t,
                                    uint64_t);
static int rust_write_bounded_octets_uper(FILE *, size_t, size_t);
static int rust_write_bounded_octets_jer(FILE *, size_t, size_t);
static int rust_write_string_ber_cer(FILE *, int, int, size_t, size_t, int);
static int rust_write_octet_cbor(FILE *, size_t, size_t);
static int rust_write_bit_cbor(FILE *, size_t, size_t, int);
static int rust_write_bounded_bits(FILE *, const char *, size_t, size_t,
                                  uint64_t);
static int rust_write_enumerated(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_inline_enum(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_enumerated_jer(FILE *, asn1p_expr_t *);
static int rust_write_enumerated_ber_cer(FILE *, asn1p_expr_t *, int);
static int rust_write_integer_ber(FILE *, const char *, const char *);
static int rust_write_sequence(FILE *, const char *, asn1p_expr_t *, int, uint64_t);
static int rust_write_sequence_ber_cer(FILE *, const char *, asn1p_expr_t *, int,
                                       uint64_t);
static int rust_write_set_ber_cer(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_set_ber_cer_decode_method(FILE *, asn1p_expr_t *, int);
static int rust_write_set_ber_cer_decode_helper(FILE *, const char *, asn1p_expr_t *);
static int rust_write_set(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_sequence_ber_cer_encode_field(FILE *, const char *, asn1p_expr_t *);
static int rust_write_sequence_ber_cer_decode_field(FILE *, const char *, asn1p_expr_t *, int);
static int rust_write_sequence_ber_cer_decode_method(FILE *, asn1p_expr_t *, int);
static int rust_write_sequence_ber_cer_decode_fields(FILE *, const char *, asn1p_expr_t *);
static int rust_write_nested_ber_cer_fields(FILE *, asn1p_expr_t *, const char *);
static int rust_write_nested_ber_cer_decode_value(FILE *, const char *, asn1p_expr_t *,
                                                  const char *);
static uint64_t rust_sequence_ber_cer_tag(const asn1p_expr_t *);
static int rust_write_sequence_ber_cer_enum_match(FILE *, const char *,
                                                 asn1p_expr_t *, const char *);
static int rust_write_sequence_ber_cer_enum_decode(FILE *, const char *,
                                                  asn1p_expr_t *);
static int rust_write_sequence_ber_cer_decode_value(FILE *, const char *,
                                                   asn1p_expr_t *, const char *);
static int rust_write_all_sequences(FILE *, const char *, asn1p_expr_t *, int, uint64_t);
static int rust_write_sequence_cbor(FILE *, asn1p_expr_t *);
static int rust_write_sequence_cbor_encode_field(FILE *, asn1p_expr_t *);
static int rust_write_sequence_cbor_decode_field(FILE *, asn1p_expr_t *);
static int rust_write_cbor_choice(FILE *, const char *, asn1p_expr_t *);
static int rust_write_cbor_choice_encode_arm(FILE *, asn1p_expr_t *);
static int rust_write_cbor_choice_decode_arm(FILE *, asn1p_expr_t *);
static int rust_write_sequence_field(FILE *, const char *, asn1p_expr_t *);
static int rust_write_sequence_encode_field(FILE *, asn1p_expr_t *);
static int rust_write_sequence_encode_string_field(FILE *, asn1p_expr_t *,
                                                   const char *);
static int rust_write_sequence_encode_default(FILE *, asn1p_expr_t *, const char *);
static int rust_write_sequence_encode_optional(FILE *, asn1p_expr_t *, const char *);
static int rust_write_sequence_decode_field(FILE *, const char *, asn1p_expr_t *,
                                            size_t *);
static int rust_write_sequence_decode_string_field(FILE *, asn1p_expr_t *);
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
                "asn1c: Rust backend supports UPER, APER, OER, BER, CER, JER, CBOR, and XER only\n");
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
    {
        rust_open_plan_t open_plan;
        if(!rust_open_module_plan(module, &open_plan)) {
            size_t i;
            if(!codecs || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_APER | RUST_CODEC_OER
                                     | RUST_CODEC_CBOR))) {
                rust_diagnostic(module, open_plan.sequence, "selected OPEN TYPE needs UPER, APER, OER, or CBOR");
                return -1;
            }
            if(codecs & RUST_CODEC_APER) {
                if(open_plan.lower != 0 || open_plan.upper != 255) {
                    rust_diagnostic(module, open_plan.sequence, "APER selected OPEN TYPE needs selector 0..255");
                    return -1;
                }
                for(i = 0; i < open_plan.rows; i++) {
                    if((uint64_t)open_plan.row[i].upper - (uint64_t)open_plan.row[i].lower > 255) {
                        rust_diagnostic(module, open_plan.sequence, "APER selected INTEGER range exceeds 255");
                        return -1;
                    }
                }
            }
            (*emitted)++;
            return 0;
        }
    }
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

/* Locate an uncombined component relation constraint.
 * Inputs: node is a constraint tree; depth bounds recursion. Returns the
 * relation or NULL; no exceptions. Source: fixed IOC tree. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: narrow OPEN TYPE gate.
 * Example: a sole ({Set}{@id}) constraint returns its relation.
 */
static const asn1p_constraint_t *
rust_open_relation(const asn1p_constraint_t *node, unsigned depth) {
    if(!node || depth > RUST_CONSTRAINT_DEPTH_LIMIT) return NULL;
    if(node->type == ACT_CA_CRC) return node;
    if(node->type == ACT_CA_SET && node->el_count == 1)
        return rust_open_relation(node->elements[0], depth + 1);
    return NULL;
}

/* Match a direct object-set or selector reference in an IOC relation.
 * Inputs: relation, element index, and expected name. Returns one on match;
 * no exceptions. Source: ASN.1 component relation AST. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: narrow OPEN TYPE gate.
 * Example: rust_open_ref(relation, 0, "Set").
 */
static int
rust_open_ref(const asn1p_constraint_t *relation, size_t index, const char *name) {
    const asn1p_constraint_t *item;
    const asn1p_ref_t *ref;
    if(!relation || !name || index >= relation->el_count || !(item = relation->elements[index])
       || item->type != ACT_EL_VALUE || !item->value || item->value->type != ATV_REFERENCED
       || !(ref = item->value->value.reference) || ref->comp_count != 1 || !ref->components[0].name) return 0;
    return !strcmp(ref->components[0].name, name);
}

/* Extract selector and type cells from a two-column IOC row.
 * Inputs: row and column names identify the cells; key and value receive them.
 * Returns zero or -1; no exceptions. Source: fixed IOC table. Version:
 * 2026-10-30. Responsible: asn1c maintainers. History: selected primitive rows.
 * Example: extract &id and &Type from one row.
 */
static int
rust_open_cells(const asn1p_ioc_row_t *row, const char *selector, const char *type,
                asn1p_expr_t **key, asn1p_expr_t **value) {
    size_t i;
    *key = NULL;
    *value = NULL;
    if(!row || !row->column || row->columns != 2) return -1;
    for(i = 0; i < row->columns; i++) {
        const struct asn1p_ioc_cell_s *cell = &row->column[i];
        if(!cell->field || !cell->field->Identifier || !cell->value) return -1;
        if(!strcmp(cell->field->Identifier, selector)) *key = cell->value;
        else if(!strcmp(cell->field->Identifier, type)) *value = cell->value;
        else return -1;
    }
    return *key && *value ? 0 : -1;
}

/* Extract and validate a selected IOC row.
 * Inputs: row is one class row, selector/type names identify its columns,
 * output receives bounds and key. Returns zero or -1; no exceptions.
 * Source: fixed IOC table. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: selected primitive rows. Example: BOOLEAN selected by integer 1.
 */
static int
rust_open_row(const asn1p_ioc_row_t *row, const char *selector, const char *type,
              rust_open_row_t *out) {
    asn1p_expr_t *key, *value;
    if(rust_open_cells(row, selector, type, &key, &value)
       || !key->value || key->value->type != ATV_INTEGER
       || value->meta_type != AMT_TYPE || value->tag.tag_class != TC_NOCLASS
       || value->lhs_params || value->rhs_pspecs || value->members.tq_head || value->ioc_table) return -1;
    if(key->value->value.v_integer < -(asn1c_integer_t)INT64_MAX - 1
       || key->value->value.v_integer > (asn1c_integer_t)INT64_MAX) return -1;
    out->key = (int64_t)key->value->value.v_integer;
    if(value->expr_type == ASN_BASIC_BOOLEAN && !value->constraints && !value->combined_constraints) {
        out->boolean = 1; out->lower = 0; out->upper = 1;
        return 0;
    }
    if(value->expr_type != ASN_BASIC_INTEGER || !value->combined_constraints
       || !rust_constraint_supported(value->combined_constraints, 0)
       || rust_integer_bounds(value, &out->lower, &out->upper)) return -1;
    out->boolean = 0;
    return 0;
}

/* Reject encoding controls and parameters on an OPEN TYPE record member.
 * Input: expr is one fixed record or member. Returns one if unsupported
 * attributes are absent, zero otherwise; no exceptions. Source: fixed tree.
 * Version: 2026-10-30. Responsible: asn1c maintainers. History: UPER gate.
 * Example: a direct unparameterized member is accepted.
 */
static int
rust_open_plain_expr(const asn1p_expr_t *expr) {
    return expr && expr->encoding_control.encoding_type == EC_NONE
        && !expr->lhs_params && !expr->rhs_pspecs && !expr->ioc_table;
}

/* Validate the two required ordered OPEN TYPE record members.
 * Input: plan points to the candidate sequence. Returns zero or -1; no
 * exceptions. Source: fixed tree. Version: 2026-10-30. Responsible: asn1c
 * maintainers. History: selected UPER gate. Example: inspect id and value.
 */
static int
rust_open_member_shape(rust_open_plan_t *out) {
    out->selector = TQ_FIRST(&out->sequence->members);
    out->member = out->selector ? TQ_NEXT(out->selector, next) : NULL;
    if(!out->selector || !out->member || TQ_NEXT(out->member, next)
       || !out->selector->Identifier || !out->member->Identifier
       || out->selector->marker.flags != EM_NOMARK || out->member->marker.flags != EM_NOMARK
       || out->selector->tag.tag_class != TC_NOCLASS || out->member->tag.tag_class != TC_NOCLASS
       || out->sequence->tag.tag_class != TC_NOCLASS || out->sequence->constraints
       || out->sequence->combined_constraints) return -1;
    if(!rust_open_plain_expr(out->sequence) || !rust_open_plain_expr(out->selector)
       || !rust_open_plain_expr(out->member)) return -1;
    return 0;
}

/* Match one direct class field reference.
 * Inputs: member supplies reference; class_name is the local class. Returns one
 * on match, zero otherwise; no exceptions. Source: fixed tree. Version:
 * 2026-10-30. Responsible: asn1c maintainers. History: selected UPER gate.
 * Example: CLASS.&id matches CLASS.
 */
static int
rust_open_class_ref(const asn1p_expr_t *member, const char *class_name) {
    const asn1p_ref_t *ref = member->reference;
    return member->meta_type == AMT_TYPEREF && ref && ref->comp_count == 2
        && ref->components[0].name && ref->components[1].name
        && !strcmp(ref->components[0].name, class_name);
}

/* Match the direct selector and selected member component relations.
 * Inputs: plan, class and set are fixed declarations. Returns zero on match,
 * -1 otherwise; no exceptions. Source: fixed IOC tree. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: selected UPER gate.
 * Example: selector id precedes value with relation {@id}.
 */
static int
rust_open_members(rust_open_plan_t *out, asn1p_expr_t *class_def, asn1p_expr_t *set) {
    const asn1p_constraint_t *selector_relation, *value_relation;
    char selector_name[128];
    if(rust_open_member_shape(out)
       || !rust_open_class_ref(out->selector, class_def->Identifier)
       || !rust_open_class_ref(out->member, class_def->Identifier)) return -1;
    selector_relation = rust_open_relation(out->selector->constraints, 0);
    value_relation = rust_open_relation(out->member->constraints, 0);
    if(!selector_relation || selector_relation->el_count != 1 || !value_relation || value_relation->el_count != 2
       || !rust_open_ref(selector_relation, 0, set->Identifier) || !rust_open_ref(value_relation, 0, set->Identifier)
       || strlen(out->selector->Identifier) >= sizeof(selector_name) - 1
       || snprintf(selector_name, sizeof(selector_name), "@%s", out->selector->Identifier) < 0
       || !rust_open_ref(value_relation, 1, selector_name)) return -1;
    return 0;
}

/* Resolve class columns and validate the bounded INTEGER selector.
 * Inputs: plan and class are fixed declarations; columns are output pointers.
 * Returns zero or -1; no exceptions. Source: IOC fixed tree. Version: 2026-10-30.
 * Responsible: asn1c maintainers. History: selector-based Rust support.
 * Example: extract &id and &Type from a two-field class.
 */
static int
rust_open_columns(rust_open_plan_t *out, asn1p_expr_t *class_def,
                  asn1p_expr_t **selector_field, asn1p_expr_t **type_field) {
    asn1p_expr_t *item, *inner;
    *selector_field = NULL;
    *type_field = NULL;
    TQ_FOR(item, &class_def->members, next) {
        if(!item->Identifier) return -1;
        if(!strcmp(item->Identifier, out->selector->reference->components[1].name)) *selector_field = item;
        else if(!strcmp(item->Identifier, out->member->reference->components[1].name)) *type_field = item;
        else return -1;
    }
    if(!*selector_field || !*type_field || (*selector_field)->expr_type != A1TC_CLASSFIELD_FTVFS
       || !(*selector_field)->unique || (*type_field)->expr_type != A1TC_CLASSFIELD_TFS) return -1;
    inner = TQ_FIRST(&(*selector_field)->members);
    if(!inner || TQ_NEXT(inner, next) || inner->expr_type != ASN_BASIC_INTEGER
       || !inner->combined_constraints || !rust_constraint_supported(inner->combined_constraints, 0)
       || rust_integer_bounds(inner, &out->lower, &out->upper)) return -1;
    return 0;
}

/* Validate a bounded, nonextensible local object set and its class.
 * Inputs: class_def and set identify declarations. Returns one when supported;
 * no exceptions. Source: IOC fixed tree. Version: 2026-10-30. Responsible:
 * asn1c maintainers. History: selected UPER gate. Example: a two-row local set.
 */
static int
rust_open_set_valid(const asn1p_expr_t *class_def, const asn1p_expr_t *set) {
    return class_def && set && class_def->Identifier && set->Identifier && set->ioc_table
        && set->ioc_table->row && set->ioc_table->rows && set->ioc_table->rows <= 32
        && !set->ioc_table->extensible && set->reference && set->reference->comp_count == 1
        && set->reference->components[0].name
        && !strcmp(set->reference->components[0].name, class_def->Identifier);
}

/* Validate IOC row types, selector ranges, and key uniqueness.
 * Inputs: out is the plan, set and fields identify the table. Returns zero or
 * -1; no exceptions. Source: IOC fixed tree. Version: 2026-10-30. Responsible:
 * asn1c maintainers. History: selected UPER gate. Example: two unique rows.
 */
static int
rust_open_rows(rust_open_plan_t *out, asn1p_expr_t *set,
               asn1p_expr_t *selector_field, asn1p_expr_t *type_field) {
    size_t i, j;
    out->rows = set->ioc_table->rows;
    for(i = 0; i < out->rows; i++) {
        if(rust_open_row(set->ioc_table->row[i], selector_field->Identifier, type_field->Identifier, &out->row[i])
           || out->row[i].key < out->lower || out->row[i].key > out->upper) return -1;
        for(j = 0; j < i; j++) if(out->row[j].key == out->row[i].key) return -1;
    }
    return 0;
}

/* Validate a local class, object set, and direct two-field UPER SEQUENCE.
 * Inputs: module owns declarations; out receives a bounded generation plan.
 * Returns zero on supported shape, otherwise -1; no exceptions. Source: IOC
 * fixed tree. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: first selector-driven Rust slice. Example: id then &Type({Set}{@id}).
 */
static int
rust_open_module_plan(asn1p_module_t *module, rust_open_plan_t *out) {
    asn1p_expr_t *item, *class_def = NULL, *set = NULL, *selector_field, *type_field;
    memset(out, 0, sizeof(*out));
    TQ_FOR(item, &module->members, next) {
        if(item->meta_type == AMT_OBJECTCLASS && !class_def) class_def = item;
        else if(item->meta_type == AMT_VALUESET && item->ioc_table && !set) set = item;
        else if(item->meta_type == AMT_TYPE && item->expr_type == ASN_CONSTR_SEQUENCE && !out->sequence)
            out->sequence = item;
        else return -1;
    }
    if(!out->sequence || !out->sequence->Identifier || !rust_open_set_valid(class_def, set)
       || rust_open_members(out, class_def, set)
       || rust_open_columns(out, class_def, &selector_field, &type_field)) return -1;
    return rust_open_rows(out, set, selector_field, type_field);
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

/* Find exactly one uncombined contents constraint, rejecting other forms.
 * Inputs: node is a constraint tree; depth limits recursion. Returns the node
 * or NULL. No exceptions. Source: Rust CONTAINING gate; version 2026-10-30.
 * Responsible: asn1c maintainers. History: UPER primitive subset.
 * Example: a single CONTAINING constraint is returned.
 */
static const asn1p_constraint_t *
rust_containing_node(const asn1p_constraint_t *node, unsigned depth) {
    if(!node || depth > RUST_CONSTRAINT_DEPTH_LIMIT) return NULL;
    if(node->type == ACT_CT_CTNG) return node;
    if((node->type == ACT_CA_SET || node->type == ACT_CA_INT) && node->el_count == 1)
        return rust_containing_node(node->elements[0], depth + 1);
    return NULL;
}

/* Resolve one local direct contained BOOLEAN or non-singleton bounded INTEGER.
 * Inputs: module owns declarations; expr is a string. Returns its contained
 * type or NULL. No exceptions. Source: fixed constraint tree; version 2026-10-30.
 * Responsible: asn1c maintainers. History: UPER primitive subset.
 * Example: OCTET STRING (CONTAINING LocalInteger) resolves LocalInteger.
 */
static asn1p_expr_t *
rust_contained_primitive(asn1p_module_t *module, asn1p_expr_t *expr) {
    const asn1p_constraint_t *node = rust_containing_node(expr->combined_constraints, 0);
    asn1p_expr_t *ref, *candidate;
    int64_t lower, upper;
    if(!node || !node->value || node->value->type != ATV_TYPE
       || !(ref = node->value->value.v_type) || ref->expr_type != A1TC_REFERENCE
       || !ref->reference || ref->reference->comp_count != 1 || ref->constraints) return NULL;
    TQ_FOR(candidate, &module->members, next) {
        if(!candidate->Identifier || strcmp(candidate->Identifier, ref->reference->components[0].name)) continue;
        if(candidate->expr_type == ASN_BASIC_BOOLEAN && !candidate->constraints
           && !candidate->combined_constraints) return candidate;
        if(candidate->expr_type == ASN_BASIC_INTEGER && candidate->combined_constraints
           && rust_constraint_supported(candidate->combined_constraints, 0)
           && !rust_integer_bounds(candidate, &lower, &upper) && lower < upper) return candidate;
        return NULL;
    }
    return NULL;
}

/*
 * Purpose: recognize the one tagged-root candidate codec and tag shape.
 * Inputs: expr is a fixed assignment and codecs is the selected mask.
 * Returns one for a context-specific IMPLICIT SEQUENCE/SET tag within C's
 * range and a nonempty BER/CER-only codec mask; no exceptions are generated.
 * Source: fixed ASN.1 AST and C BER tag limit. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged SEQUENCE and SET roots.
 * Example: `[3] IMPLICIT SET` selected for BER passes this check.
 */
static int
rust_tagged_record_root_candidate(const asn1p_expr_t *expr, uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    return expr && (expr->expr_type == ASN_CONSTR_SEQUENCE
                    || expr->expr_type == ASN_CONSTR_SET)
        && expr->tag.tag_class == TC_CONTEXT_SPECIFIC
        && expr->tag.tag_mode == TM_IMPLICIT
        && expr->tag.tag_value >= 0
        && expr->tag.tag_value <= (asn1c_integer_t)UINT32_C(0x3fffffff)
        && codecs && !(codecs & ~ber_cer);
}

/* Validate the codec mask for a direct unconstrained INTEGER assignment.
 * Inputs: module and expr identify the source assignment; codecs is selected.
 * Returns zero for BER/CER-only masks, otherwise -1 with a location diagnostic.
 * Errors: no exception. Source: Rust BigInteger stage. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: unbounded INTEGER codec gate.
 * Example: BER plus CER passes; BER plus UPER fails.
 */
static int
rust_check_big_integer_codecs(asn1p_module_t *module, asn1p_expr_t *expr,
                              uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    if(codecs && !(codecs & ~ber_cer)) return 0;
    rust_diagnostic(module, expr,
                    "unconstrained INTEGER requires BER/CER-only codec selection");
    return -1;
}

/* Validate the codec selection for one unconstrained direct string root.
 * Inputs: module and expr identify the assignment; codecs is the selected mask.
 * Returns zero for BER/CER-only selection, otherwise -1 with a diagnostic.
 * Errors: no exception. Original source: approved BER/CER string gate.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: direct unconstrained BIT/OCTET STRING support.
 * Example: BER plus CER is accepted; BER plus UPER is refused.
 */
static int
rust_check_unconstrained_string_codecs(asn1p_module_t *module,
                                       asn1p_expr_t *expr, uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    if(codecs && !(codecs & ~ber_cer)) return 0;
    rust_diagnostic(module, expr,
        "unconstrained BIT/OCTET STRING requires BER/CER-only codec selection");
    return -1;
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
    if(expr->tag.tag_class != TC_NOCLASS
       && !rust_tagged_record_root_candidate(expr, codecs)) {
        rust_diagnostic(module, expr,
                        "type tags are supported only on BER/CER-only flat SEQUENCE/SET roots");
        return -1;
    }
    if(codecs & RUST_CODEC_XER) {
        if(codecs == RUST_CODEC_XER
           && (expr->expr_type == ASN_CONSTR_SEQUENCE || expr->expr_type == ASN_CONSTR_SET))
            return rust_check_xer_record(module, expr);
        rust_diagnostic(module, expr, "XER requires an XER-only flat SET or SEQUENCE");
        return -1;
    }
    if((expr->expr_type == ASN_BASIC_OCTET_STRING || expr->expr_type == ASN_BASIC_BIT_STRING)
       && rust_containing_node(expr->combined_constraints, 0)) {
        asn1p_expr_t *inner = rust_contained_primitive(module, expr);
        if((codecs != RUST_CODEC_UPER && codecs != RUST_CODEC_CBOR
            && codecs != (RUST_CODEC_UPER | RUST_CODEC_CBOR)) || !inner) {
            rust_diagnostic(module, expr, "CONTAINING requires supported UPER or CBOR primitive codecs");
            return -1;
        }
        return 0;
    }
    if(expr->expr_type == ASN_TYPE_ANY) {
        if(!codecs || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_APER | RUST_CODEC_OER
                                  | RUST_CODEC_JER | RUST_CODEC_CBOR))
           || expr->reference || expr->constraints
           || expr->combined_constraints || expr->lhs_params || expr->ioc_table
           || expr->members.tq_head) {
            rust_diagnostic(module, expr, "ANY requires unqualified supported opaque framing");
            return -1;
        }
        return 0;
    }
    if(expr->expr_type == ASN_CONSTR_SEQUENCE)
        return rust_check_sequence(module, expr, codecs);
    if(expr->expr_type == ASN_CONSTR_SET)
        return rust_check_set_ber_cer(module, expr, codecs);
    if(expr->expr_type == ASN_CONSTR_CHOICE)
        return rust_check_cbor_choice(module, expr, codecs);
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
        if(!expr->constraints && !expr->combined_constraints)
            return rust_check_big_integer_codecs(module, expr, codecs);
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
        size_t lower, upper;
        if(!expr->constraints && !expr->combined_constraints)
            return rust_check_unconstrained_string_codecs(module, expr, codecs);
        if((!codecs || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_BER | RUST_CODEC_CER
                                   | RUST_CODEC_JER | RUST_CODEC_CBOR)))
           || !expr->combined_constraints
           || !rust_size_constraint_supported(expr->combined_constraints, 0)) {
            rust_diagnostic(module, expr,
                "OCTET STRING needs supported codecs with finite SIZE constraints");
            return -1;
        }
        if(!rust_fixed_size(expr, &(size_t){0})) return 0;
        if(!rust_bounded_size(expr, &lower, &upper)) return 0;
        rust_diagnostic(module, expr,
            "OCTET STRING needs fixed or bounded SIZE below 65536");
        return -1;
    }
    if(expr->expr_type == ASN_BASIC_BIT_STRING) {
        size_t lower, upper;
        if(!expr->constraints && !expr->combined_constraints)
            return rust_check_unconstrained_string_codecs(module, expr, codecs);
        if(!codecs || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_BER | RUST_CODEC_CER
                                  | RUST_CODEC_JER | RUST_CODEC_CBOR))
           || !expr->combined_constraints
           || !rust_size_constraint_supported(expr->combined_constraints, 0)) {
            rust_diagnostic(module, expr,
                "BIT STRING needs supported codecs with finite SIZE constraints");
            return -1;
        }
        if(!rust_fixed_size(expr, &(size_t){0})) return 0;
        if(!rust_bounded_size(expr, &lower, &upper)) return 0;
        rust_diagnostic(module, expr,
            "BIT STRING needs fixed or bounded nonextensible SIZE below 65536");
        return -1;
    }
    rust_diagnostic(module, expr,
                    "only direct primitives and flat UPER SEQUENCE are supported");
    return -1;
}

/*
 * Purpose: validate the type and default of one flat XER field.
 * Input: member describes a structurally valid ASN.1 field. Returns one if
 * supported, zero otherwise; no exceptions. Source: new Rust XER slice.
 * Version/date: 2026-10-31; responsible: asn1c maintainers. History: initial
 * XER output support. Example: rust_xer_member_type_supported(member).
 */
static int
rust_xer_member_type_supported(asn1p_expr_t *member) {
    char literal[64];
    if(member->expr_type == ASN_BASIC_BOOLEAN) {
        if(member->constraints || member->combined_constraints) return 0;
    } else if(member->expr_type == ASN_BASIC_INTEGER) {
        if(!member->combined_constraints
           || !rust_constraint_supported(member->combined_constraints, 0)
           || rust_integer_bounds(member, &(int64_t){0}, &(int64_t){0})) return 0;
    } else if(member->expr_type == ASN_STRING_IA5String) {
        if(member->constraints || member->combined_constraints || member->marker.flags == EM_DEFAULT)
            return 0;
    } else if(member->expr_type == ASN_BASIC_REAL) {
        return !member->constraints && !member->combined_constraints
            && member->marker.flags == EM_DEFAULT && member->marker.default_value
            && member->marker.default_value->type == ATV_REAL
            && member->marker.default_value->value.v_double == 0.5;
    } else return 0;
    return member->marker.flags != EM_DEFAULT
        || !rust_sequence_default_literal(member, literal, sizeof(literal));
}

/*
 * Purpose: accept untagged fields or fixer-assigned automatic tags only.
 * Inputs: module, record, member and zero-based index identify the field.
 * Returns one if supported, zero otherwise; no exceptions. Source: ASN.1
 * automatic tagging. Version/date: 2026-10-31; responsible: asn1c maintainers.
 * History: initial automatic XER slice. Example: check the first member.
 */
static int
rust_xer_tag_supported(asn1p_module_t *module, asn1p_expr_t *record,
                       asn1p_expr_t *member, size_t index) {
    if(member->tag.tag_class == TC_NOCLASS) return 1;
    return record->auto_tags_OK && (module->module_flags & MSF_AUTOMATIC_TAGS)
        && member->tag.tag_class == TC_CONTEXT_SPECIFIC
        && member->tag.tag_mode == TM_IMPLICIT
        && member->tag.tag_value == (asn1c_integer_t)index;
}

/*
 * Purpose: gate the encoder-only flat XER record slice before publication.
 * Inputs: module and expr identify a fixed ASN.1 record. Returns zero on
 * success, -1 on unsupported input; no exceptions. Source: new Rust XER slice.
 * Version/date: 2026-10-31; responsible: asn1c maintainers. History: initial
 * XER output support. Example: rust_check_xer_record(module, record).
 */
static int
rust_check_xer_record(asn1p_module_t *module, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    size_t count = 0;
    if(expr->constraints || expr->combined_constraints || expr->lhs_params
       || expr->ioc_table || expr->marker.flags || expr->rhs_pspecs) goto unsupported;
    TQ_FOR(member, &expr->members, next) {
        if(++count > RUST_SEQUENCE_FIELD_LIMIT || !rust_sequence_member_shape_valid(member)
           || member->members.tq_head || member->reference
           || !rust_xer_tag_supported(module, expr, member, count - 1)
           || rust_check_sequence_name(module, expr, member)
           || !rust_xer_member_type_supported(member))
            goto unsupported;
    }
    return 0;
unsupported:
    rust_diagnostic(module, expr, "unsupported flat XER record field or DEFAULT");
    return -1;
}

/*
 * Purpose: emit one checked field and its basic XER element.
 * Inputs: stream receives generated Rust; member describes a validated field.
 * Returns zero or -1 on output failure; no exceptions. Source: new Rust XER
 * slice. Version/date: 2026-10-31; responsible: asn1c maintainers. History:
 * initial output support. Example: rust_write_xer_field(out, field).
 */
static int
rust_write_xer_field(FILE *stream, asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    char literal[64];
    int ret = 0;
    int optional = member->marker.flags == EM_OPTIONAL;
    if(!name) return -1;
    if(optional) {
        ret = fprintf(stream, "        if let Some(value) = self.%s%s {\n", name,
                      member->expr_type == ASN_STRING_IA5String ? ".as_deref()" : "");
    } else if(member->marker.flags == EM_DEFAULT) {
        if(member->expr_type == ASN_BASIC_REAL) strcpy(literal, "0.5_f64");
        else if(rust_sequence_default_literal(member, literal, sizeof(literal))) ret = -1;
        if(ret >= 0) ret = fprintf(stream, "        let value = self.%s.unwrap_or(%s);\n", name, literal);
    } else {
        ret = fprintf(stream, "        let value = %sself.%s;\n",
                      member->expr_type == ASN_STRING_IA5String ? "&" : "", name);
    }
    if(ret >= 0) ret = fprintf(stream, "        writer.append(\"\\n    <%s>\")?;\n", member->Identifier);
    if(ret >= 0 && member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fputs("        writer.boolean(value)?;\n", stream);
    else if(ret >= 0 && member->expr_type == ASN_BASIC_INTEGER) {
        int64_t lower, upper;
        char low[64], high[64];
        if(rust_integer_bounds(member, &lower, &upper) || rust_format_bound(low, sizeof(low), lower)
           || rust_format_bound(high, sizeof(high), upper)) ret = -1;
        else ret = fprintf(stream, "        writer.integer(value, %s, %s)?;\n", low, high);
    } else if(ret >= 0 && member->expr_type == ASN_BASIC_REAL)
        ret = fputs("        writer.real(value)?;\n", stream);
    else if(ret >= 0) ret = fputs("        writer.ia5(value)?;\n", stream);
    if(ret >= 0) ret = fprintf(stream, "        writer.append(\"</%s>\")?;\n", member->Identifier);
    if(ret >= 0 && optional) ret = fputs("        }\n", stream);
    free(name);
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit a flat record and its basic XER encoder.
 * Inputs: stream receives Rust; name is its type; expr describes fields.
 * Returns zero or -1 on output failure; no exceptions. Source: new Rust XER
 * slice. Version/date: 2026-10-31; responsible: asn1c maintainers. History:
 * initial output support. Example: rust_write_xer_record(out, "S", record).
 */
static int
rust_write_xer_record(FILE *stream, const char *name, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    int has_real = 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_BASIC_REAL) has_real = 1;
    }
    if(fprintf(stream, "/// Flat ASN.1 XER record.\n#[derive(Clone, Debug, %sPartialEq)]\n"
               "pub struct %s {\n", has_real ? "" : "Eq, ", name) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        char *field = rust_identifier(member->Identifier, 1);
        const char *type = member->expr_type == ASN_BASIC_BOOLEAN ? "bool"
                         : member->expr_type == ASN_BASIC_INTEGER ? "i64"
                         : member->expr_type == ASN_BASIC_REAL ? "f64" : "::std::string::String";
        int present = member->marker.flags != EM_NOMARK;
        int ret = field ? fprintf(stream, "    /// ASN.1 field state variable.\n    pub %s: %s%s%s,\n",
                                  field, present ? "Option<" : "", type, present ? ">" : "") : -1;
        free(field);
        if(ret < 0) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(rust_write_method_doc(stream, "Encode this flat record as basic XER.",
        "`self` supplies fields; `limits` bounds output and work.", "Returns the complete XML bytes.",
        "Returns an error for invalid fields or exhausted resources.",
        "`let xml = value.encode_xer(&Default::default())?;")) return -1;
    if(fprintf(stream, "    pub fn encode_xer(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::std::vec::Vec<u8>, ::asn1c_runtime::Error> {\n"
        "        let mut writer = ::asn1c_runtime::xer::XerWriter::new(limits);\n"
        "        writer.append(\"<%s>\")?;\n", expr->Identifier) < 0) return -1;
    if(expr->expr_type == ASN_CONSTR_SET && !expr->auto_tags_OK) {
        static const asn1p_expr_type_e order[] = {
            ASN_BASIC_BOOLEAN, ASN_BASIC_INTEGER, ASN_BASIC_REAL, ASN_STRING_IA5String
        };
        size_t i;
        /* SET follows the C encoder's ascending universal tag order. */
        for(i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
            TQ_FOR(member, &expr->members, next) {
                if(member->expr_type == order[i] && rust_write_xer_field(stream, member)) return -1;
            }
        }
    } else {
        TQ_FOR(member, &expr->members, next) {
            if(rust_write_xer_field(stream, member)) return -1;
        }
    }
    return fprintf(stream, "        if writer.has_content_after(%zu) { writer.append(\"\\n\")?; }\n"
                   "        writer.append(\"</%s>\\n\")?;\n"
                   "        Ok(writer.finish())\n    }\n}\n\n", strlen(expr->Identifier) + 2,
                   expr->Identifier) < 0 ? -1 : 0;
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
    if(!codecs || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_CBOR
                              | RUST_CODEC_BER | RUST_CODEC_CER))
       || expr->constraints
       || expr->combined_constraints || expr->lhs_params || expr->ioc_table
       || expr->marker.flags || expr->rhs_pspecs) {
        rust_diagnostic(module, expr,
                        "SEQUENCE needs supported UPER, CBOR, BER, or CER codecs");
        return -1;
    }
    if(rust_check_sequence_tree(module, expr, stack, 0, &nodes, &work)) return -1;
    if((codecs & RUST_CODEC_UPER)
       && (codecs & (RUST_CODEC_BER | RUST_CODEC_CER))
       && rust_ber_cer_has_empty_nested_sequence(expr)) {
        rust_diagnostic(module, expr,
                        "empty inline BER/CER child SEQUENCE cannot be selected with UPER");
        return -1;
    }
    if((codecs & (RUST_CODEC_BER | RUST_CODEC_CER))
       && rust_check_sequence_ber_cer(module, expr, codecs)) return -1;
    return (codecs & RUST_CODEC_CBOR) ? rust_check_cbor_sequence(module, expr) : 0;
}

/*
 * Gate flat untagged SET support to the direct unique-tag BER/CER subset.
 * Parameters: module supplies diagnostics; expr is the SET; codecs selects
 * BER/DER and/or CER. Returns zero on success, -1 otherwise.
 * Errors: unsupported masks, classes/modes, fields, defaults, and extensions fail.
 * Original source: X.690 SET component order. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: fourth-wave SET codecs.
 * Example: `rust_check_set_ber_cer(module, set, RUST_CODEC_BER)`.
 */
static int
rust_check_set_ber_cer(asn1p_module_t *module, asn1p_expr_t *expr,
                       uint64_t codecs) {
    asn1p_expr_t *member;
    size_t count = 0;
    size_t nodes = 1;
    size_t work = 0;
    int tagged_root = expr->tag.tag_class != TC_NOCLASS;
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    if(expr->expr_type != ASN_CONSTR_SET || !(codecs & supported)
       || (codecs & ~supported) || expr->reference
       || (tagged_root && !rust_tagged_record_root_candidate(expr, codecs))
       || expr->constraints
       || expr->combined_constraints || expr->lhs_params || expr->ioc_table
       || expr->marker.flags || expr->rhs_pspecs) {
        rust_diagnostic(module, expr,
                        "BER/CER SET root needs an untagged root or one supported "
                        "context-specific IMPLICIT tag and BER/CER-only codecs");
        return -1;
    }
    TQ_FOR(member, &expr->members, next) {
        if(++count > RUST_BER_CER_FIELD_LIMIT || ++work > RUST_BER_CER_WORK_LIMIT) {
            rust_diagnostic(module, expr, "BER/CER SET exceeds the supported direct-field limit");
            return -1;
        }
        if(tagged_root && member->expr_type == ASN_CONSTR_SEQUENCE) {
            rust_diagnostic(module, member,
                            "tagged BER/CER SET roots require direct primitive fields");
            return -1;
        }
        if(member->expr_type == ASN_CONSTR_SEQUENCE
           && ++nodes > RUST_BER_CER_NODE_LIMIT) {
            rust_diagnostic(module, member, "BER/CER SET nesting exceeds the supported depth");
            return -1;
        }
        if(rust_check_ber_cer_member(module, expr, member, 1, &work)) return -1;
    }
    return 0;
}

/*
 * Purpose: limit BER/DER/CER SEQUENCE generation to supported direct primitives.
 * Inputs: module supplies diagnostics; expr owns the top-level record.
 * Returns zero when fields are direct unique-tag primitives in the six-tag
 * BOOLEAN, INTEGER, BIT/OCTET STRING, NULL, and ENUMERATED subset, with
 * untagged universal or resolved context-specific IMPLICIT/EXPLICIT member tags.
 * Errors: references, unsupported tag modes/classes, effective-tag collisions,
 * extensions, and unsupported defaults fail closed. One context-specific
 * IMPLICIT root is allowed only for flat BER/CER-only records. Source:
 * X.690 SEQUENCE order and member tags.
 * Version/date: 2026-10-31. Author: asn1c maintainers. History: third-wave
 * generated record codecs. Example: optional enum, bounded strings, INTEGER.
 */
static int
rust_check_sequence_ber_cer(asn1p_module_t *module, asn1p_expr_t *expr,
                            uint64_t codecs) {
    asn1p_expr_t *member;
    size_t count = 0;
    size_t nodes = 1;
    size_t work = 0;
    int tagged_root = expr->tag.tag_class != TC_NOCLASS;
    if(expr->expr_type != ASN_CONSTR_SEQUENCE || expr->reference
       || (tagged_root && !rust_tagged_record_root_candidate(expr, codecs))) {
        rust_diagnostic(module, expr,
                        "BER/CER SEQUENCE root needs an untagged root or one supported "
                        "context-specific IMPLICIT tag with BER/CER-only codecs");
        return -1;
    }
    TQ_FOR(member, &expr->members, next) {
        if(++count > RUST_BER_CER_FIELD_LIMIT || ++work > RUST_BER_CER_WORK_LIMIT) {
            rust_diagnostic(module, expr,
                            "BER/CER SEQUENCE exceeds the supported direct-field limit");
            return -1;
        }
        if(tagged_root && member->expr_type == ASN_CONSTR_SEQUENCE) {
            rust_diagnostic(module, member,
                            "tagged BER/CER SEQUENCE roots require direct primitive fields");
            return -1;
        }
        if(member->expr_type == ASN_CONSTR_SEQUENCE
           && ++nodes > RUST_BER_CER_NODE_LIMIT) {
            rust_diagnostic(module, member,
                            "BER/CER SEQUENCE nesting exceeds the supported depth");
            return -1;
        }
        if(rust_check_ber_cer_member(module, expr, member, 0, &work)) return -1;
    }
    return 0;
}

/*
 * Check the common shape of one direct BER/CER record member.
 * Parameters: member is the resolved field. Returns one when its primitive,
 * tag class/mode, constraints, and marker are supported. Source: X.680/X.690.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged fields.
 * Example: a context-specific EXPLICIT bounded INTEGER is accepted.
 */
static int
rust_ber_cer_member_shape_valid(asn1p_expr_t *member) {
    int tag_class;
    uint32_t tag_number;
    int new_kind = member->expr_type == ASN_BASIC_ENUMERATED
                || member->expr_type == ASN_BASIC_OCTET_STRING
                || member->expr_type == ASN_BASIC_BIT_STRING;
    if(!rust_sequence_member_shape_valid(member)
       || rust_ber_cer_member_tag(member, &tag_class, &tag_number)
       || member->reference || rust_containing_node(member->combined_constraints, 0)) return 0;
    if(new_kind && member->marker.flags != EM_NOMARK
       && member->marker.flags != EM_OPTIONAL) return 0;
    return 1;
}

/*
 * Validate one record member and report a field-specific diagnostic.
 * Parameters: module/expr/member identify source; set enables name checks.
 * Returns zero when valid, -1 otherwise. Errors: invalid member forms fail.
 * Source: X.680 resolved member tags. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: context-specific record support.
 * Example: validate one member before emitting a tagged decoder.
 */
static int
rust_check_ber_cer_member(asn1p_module_t *module, asn1p_expr_t *expr,
                          asn1p_expr_t *member, int set, size_t *work) {
    if(!rust_ber_cer_member_shape_valid(member)
       || (set && rust_check_sequence_name(module, expr, member))) {
        rust_diagnostic(module, member,
                        "BER/CER record needs direct supported fields with universal or "
                        "resolved context-specific IMPLICIT or EXPLICIT tags and supported markers");
        return -1;
    }
    if(member->expr_type == ASN_CONSTR_SEQUENCE) {
        if(member->marker.flags == EM_DEFAULT
           || rust_check_ber_cer_nested_sequence(module, member, work)) {
            rust_diagnostic(module, member,
                            "BER/CER constructed fields need one inline, nonrecursive SEQUENCE "
                            "with required or OPTIONAL primitive children");
            return -1;
        }
    } else if(rust_check_sequence_member(module, member)) {
        rust_diagnostic(module, member,
                        "BER/CER record needs direct supported fields with universal or "
                        "resolved context-specific IMPLICIT or EXPLICIT tags and supported markers");
        return -1;
    }
    if(rust_ber_cer_duplicate_tag(expr, member)) {
        rust_diagnostic(module, member,
                        "BER/CER record fields must have unique effective tags");
        return -1;
    }
    return 0;
}

/*
 * Validate one inline child SEQUENCE at the bounded BER/CER composition depth.
 * Inputs: module supplies diagnostics; sequence is one constructed component.
 * Returns zero for unique-tag primitive children or -1 for unsupported shapes.
 * Errors: references, extensions, DEFAULT, nested constructors, and field/work
 * excess fail closed. Source: approved inline SEQUENCE generator stage.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested BER/CER.
 * Example: a child with one bounded INTEGER is accepted.
 */
static int
rust_check_ber_cer_nested_sequence(asn1p_module_t *module,
                                   asn1p_expr_t *sequence, size_t *work) {
    asn1p_expr_t *member;
    size_t count = 0;
    if(!work || !rust_ber_cer_nested_sequence_shape_valid(sequence)) return -1;
    TQ_FOR(member, &sequence->members, next) {
        if(++count > RUST_BER_CER_FIELD_LIMIT
           || ++*work > RUST_BER_CER_WORK_LIMIT
           || member->expr_type == ASN_CONSTR_SEQUENCE
           || member->marker.flags == EM_DEFAULT
           || !rust_ber_cer_member_shape_valid(member)
           || rust_check_sequence_name(module, sequence, member)
           || rust_check_sequence_member(module, member)
           || rust_ber_cer_duplicate_tag(sequence, member)) {
            rust_diagnostic(module, member,
                            "nested BER/CER SEQUENCE children must be unique-tag required or "
                            "OPTIONAL primitive fields");
            return -1;
        }
    }
    return 0;
}

/*
 * Validate structural properties of one inline nested SEQUENCE.
 * Inputs: sequence is the parser node for the constructed child.
 * Returns one for inline SEQUENCE metadata without references or extensions;
 * an empty child is valid. Errors: malformed metadata returns zero. Source:
 * approved BER/CER slice.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested gate.
 * Example: an inline child without extensions passes this structural check.
 */
static int
rust_ber_cer_nested_sequence_shape_valid(asn1p_expr_t *sequence) {
    if(!sequence) return 0;
    return sequence->expr_type == ASN_CONSTR_SEQUENCE
        && !sequence->reference
        && !sequence->constraints
        && !sequence->combined_constraints
        && !sequence->lhs_params
        && !sequence->ioc_table
        && (sequence->marker.flags == EM_NOMARK
            || sequence->marker.flags == EM_OPTIONAL)
        && !sequence->rhs_pspecs
        && sequence->encoding_control.encoding_type == EC_NONE;
}

/*
 * Map a validated direct field kind to its X.690 universal tag number.
 * Parameters: member is one parser field. Returns zero for unsupported kinds.
 * Original source: X.680 universal primitive assignments. Version/date:
 * 2026-10-31. Author: asn1c maintainers. History: six-tag record expansion.
 * Example: OCTET STRING maps to universal tag 4.
 */
static uint64_t
rust_sequence_ber_cer_tag(const asn1p_expr_t *member) {
    if(!member) return 0;
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN: return 1;
    case ASN_BASIC_INTEGER: return 2;
    case ASN_BASIC_BIT_STRING: return 3;
    case ASN_BASIC_OCTET_STRING: return 4;
    case ASN_BASIC_NULL: return 5;
    case ASN_BASIC_ENUMERATED: return 10;
    case ASN_CONSTR_SEQUENCE: return 16;
    default: return 0;
    }
}

/*
 * Resolve one flat BER/CER field to its effective class and tag number.
 * Parameters: member is a direct field; class_out and number_out receive the
 * resolved identifier. Returns zero or -1. Errors: unsupported classes/modes,
 * negative values, and values above the C tag cap fail closed. Source: X.680.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged records.
 * Example: an untagged BOOLEAN resolves to UNIVERSAL tag 1.
 */
static int
rust_ber_cer_member_tag(const asn1p_expr_t *member, int *class_out,
                        uint32_t *number_out) {
    uint64_t universal;
    if(!member || !class_out || !number_out) return -1;
    universal = rust_sequence_ber_cer_tag(member);
    if(!universal) return -1;
    if(member->tag.tag_class == TC_NOCLASS) {
        if(universal > UINT32_C(0x3fffffff)) return -1;
        *class_out = TC_UNIVERSAL;
        *number_out = (uint32_t)universal;
        return 0;
    }
    if(member->tag.tag_class != TC_CONTEXT_SPECIFIC
       || (member->tag.tag_mode != TM_IMPLICIT && member->tag.tag_mode != TM_EXPLICIT)
       || member->tag.tag_value < 0
       || member->tag.tag_value > (asn1c_integer_t)UINT32_C(0x3fffffff)) return -1;
    *class_out = TC_CONTEXT_SPECIFIC;
    *number_out = (uint32_t)member->tag.tag_value;
    return 0;
}

/*
 * Report whether a validated field has one explicit context-specific wrapper.
 * Parameters: member is the fixed direct field. Returns one for TM_EXPLICIT.
 * Errors: callers must validate the mode before use. Source: fixed AST tags.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: explicit fields.
 * Example: distinguish an explicit wrapper from an implicit replacement.
 */
static int
rust_ber_cer_member_explicit(const asn1p_expr_t *member) {
    return member && member->tag.tag_class == TC_CONTEXT_SPECIFIC
        && member->tag.tag_mode == TM_EXPLICIT;
}

/*
 * Report whether a checked record contains any context-specific field tag.
 * Parameters: expr owns the direct fields. Returns one for tagged fields and
 * zero otherwise. Source: resolved ASN.1 member tags. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged record backend. Example: AUTO TAGS.
 */
static int
rust_ber_cer_has_tagged_members(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        if(member->tag.tag_class == TC_CONTEXT_SPECIFIC) return 1;
    }
    return 0;
}

/*
 * Detect whether a record needs nested scratch accounting at operation start.
 * Inputs: expr owns the record's direct fields. Returns one when a child
 * SEQUENCE occurs, otherwise zero. Errors: none. Source: runtime context policy.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested records.
 * Example: an OPTIONAL child uses nested accounting even when absent.
 */
static int
rust_ber_cer_has_nested_sequence(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE) return 1;
    }
    return 0;
}

/*
 * Detect empty inline children whose UPER helper shape is not qualified.
 * Inputs: expr owns the root record's direct fields. Returns one on an empty
 * inline SEQUENCE child, otherwise zero. Errors: none. Source: Rust codec gate.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested records.
 * Example: an empty child remains accepted when the caller selects BER/CER only.
 */
static int
rust_ber_cer_has_empty_nested_sequence(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE && !member->members.tq_head) return 1;
    }
    return 0;
}

/*
 * Compare two validated fields by effective class and tag number.
 * Parameters: left and right are checked direct fields. Returns negative,
 * zero, or positive for canonical SET order. Source: X.690 SET tag ordering.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged SET.
 * Example: universal tags sort before context-specific tags.
 */
static int
rust_ber_cer_tag_compare(const asn1p_expr_t *left, const asn1p_expr_t *right) {
    int left_class, right_class;
    uint32_t left_number, right_number;
    if(rust_ber_cer_member_tag(left, &left_class, &left_number)
       || rust_ber_cer_member_tag(right, &right_class, &right_number)) return 0;
    if(left_class != right_class) return left_class < right_class ? -1 : 1;
    if(left_number == right_number) return 0;
    return left_number < right_number ? -1 : 1;
}

/*
 * Detect a duplicate effective tag among fields before the current member.
 * Parameters: expr is the record; member is the current checked field.
 * Returns one for a collision, zero otherwise. Source: X.680 field tags.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged gates.
 * Example: two BOOLEAN fields at context tags 0 and 1 do not collide.
 */
static int
rust_ber_cer_duplicate_tag(asn1p_expr_t *expr, asn1p_expr_t *member) {
    asn1p_expr_t *prior;
    int member_class;
    uint32_t member_number;
    if(rust_ber_cer_member_tag(member, &member_class, &member_number)) return 1;
    TQ_FOR(prior, &expr->members, next) {
        int prior_class;
        uint32_t prior_number;
        if(prior == member) break;
        if(rust_ber_cer_member_tag(prior, &prior_class, &prior_number)) return 1;
        if(member_class == prior_class && member_number == prior_number) return 1;
    }
    return 0;
}

/*
 * Name one validated field kind for a runtime descriptor.
 * Parameters: member supplies the ASN.1 primitive. Returns a Rust enum token
 * or NULL for unsupported types. Source: runtime `FieldKind`. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: tagged reader descriptors.
 * Example: a BIT STRING maps to `BitString`.
 */
static const char *
rust_ber_cer_field_kind(const asn1p_expr_t *member) {
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN: return "Boolean";
    case ASN_BASIC_INTEGER: return "Integer";
    case ASN_BASIC_BIT_STRING: return "BitString";
    case ASN_BASIC_OCTET_STRING: return "OctetString";
    case ASN_BASIC_NULL: return "Null";
    case ASN_BASIC_ENUMERATED: return "Enumerated";
    case ASN_CONSTR_SEQUENCE: return "Sequence";
    default: return NULL;
    }
}

/*
 * Name one resolved class for the runtime `TagClass` constructor.
 * Parameters: class_code is a parser tag-class constant. Returns a Rust enum
 * token or NULL when unsupported. Source: X.680 tag classes. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: implicit tag support.
 * Example: TC_CONTEXT_SPECIFIC maps to `ContextSpecific`.
 */
static const char *
rust_ber_cer_tag_class(int class_code) {
    if(class_code == TC_UNIVERSAL) return "Universal";
    if(class_code == TC_CONTEXT_SPECIFIC) return "ContextSpecific";
    return NULL;
}

/*
 * Format a resolved tag number as a readable Rust integer literal.
 * Parameters: output/capacity receive the text; number is C-tag bounded.
 * Returns zero or -1 for insufficient capacity. Source: generated Rust syntax.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: strict Clippy.
 * Example: 1073741823 becomes `1_073_741_823`.
 */
static int
rust_format_tag_number(char *output, size_t capacity, uint32_t number) {
    char digits[16];
    size_t length;
    size_t first;
    size_t source = 0;
    size_t target = 0;
    int written;
    if(!output || !capacity) return -1;
    written = snprintf(digits, sizeof(digits), "%u", number);
    if(written < 0 || (size_t)written >= sizeof(digits)) return -1;
    length = (size_t)written;
    first = length % 3;
    if(!first) first = 3;
    while(source < length) {
        size_t group = source == 0 ? first : 3;
        if(target + group + 1 > capacity) return -1;
        memcpy(output + target, digits + source, group);
        target += group;
        source += group;
        if(source < length) output[target++] = '_';
    }
    if(target >= capacity) return -1;
    output[target] = '\0';
    return 0;
}

/*
 * Format one stable local name for a resolved context-specific field tag.
 * Parameters: member supplies the resolved tag; output/capacity receive its
 * generated local identifier. Returns zero or -1. Source: backend locals.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged fields.
 * Example: context tag 31 maps to `__asn1c_tag_3_31`.
 */
static int
rust_ber_cer_tag_local(const asn1p_expr_t *member, char *output,
                       size_t capacity) {
    int class_code;
    uint32_t number;
    int written;
    if(!output || !capacity
       || rust_ber_cer_member_tag(member, &class_code, &number)) return -1;
    written = snprintf(output, capacity, "__asn1c_tag_%u_%u",
                       (unsigned)class_code, number);
    return written < 0 || (size_t)written >= capacity ? -1 : 0;
}

/*
 * Emit checked local Tag values once at the start of a record encoder.
 * Parameters: stream receives Rust; expr owns checked fields. Returns zero
 * or -1. Errors: invalid tag or output failure. Source: runtime Tag API.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged fields.
 * Example: emit a checked context-specific tag before the record writer call.
 */
static int
rust_write_ber_cer_tag_locals(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        int class_code;
        uint32_t number;
        char local[48];
        char formatted_number[16];
        const char *class_name;
        if(rust_ber_cer_member_tag(member, &class_code, &number)) return -1;
        if(class_code != TC_CONTEXT_SPECIFIC) continue;
        class_name = rust_ber_cer_tag_class(class_code);
        if(!class_name || rust_format_tag_number(formatted_number,
                sizeof(formatted_number), number)
           || rust_ber_cer_tag_local(member, local, sizeof(local))
           || fprintf(stream,
                "        let %s = ::asn1c_runtime::ber::Tag::new(\n"
                "            ::asn1c_runtime::ber::TagClass::%s, %s)?;\n",
                local, class_name, formatted_number) < 0) return -1;
    }
    return 0;
}

/*
 * Emit every member tag local used by descriptor-backed child dispatch.
 * Inputs: stream receives Rust; expr owns validated direct fields. Returns
 * zero or -1. Errors: invalid tags or output failure. Source: runtime Tag API.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested readers.
 * Example: declare universal and context-specific tags before `next_tagged_field`.
 */
static int
rust_write_ber_cer_reader_tag_locals(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        int class_code;
        uint32_t number;
        char local[48];
        char formatted_number[16];
        const char *class_name;
        if(rust_ber_cer_member_tag(member, &class_code, &number)
           || rust_ber_cer_tag_local(member, local, sizeof(local))
           || rust_format_tag_number(formatted_number, sizeof(formatted_number), number))
            return -1;
        class_name = rust_ber_cer_tag_class(class_code);
        if(!class_name || fprintf(stream,
            "        let %s = ::asn1c_runtime::ber::Tag::new(\n"
            "            ::asn1c_runtime::ber::TagClass::%s, %s)?;\n",
            local, class_name, formatted_number) < 0) return -1;
    }
    return 0;
}

/*
 * Emit a checked runtime Tag constructor for one validated member.
 * Parameters: stream receives Rust; member owns the resolved tag.
 * Returns zero or -1 on invalid input or output failure. Source: runtime Tag.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged codecs.
 * Example: `Tag::new(TagClass::ContextSpecific, 31)?`.
 */
static int
rust_write_ber_cer_tag(FILE *stream, const asn1p_expr_t *member) {
    int class_code;
    uint32_t number;
    char formatted_number[16];
    const char *class_name;
    if(rust_ber_cer_member_tag(member, &class_code, &number)) return -1;
    class_name = rust_ber_cer_tag_class(class_code);
    if(!class_name || rust_format_tag_number(formatted_number,
            sizeof(formatted_number), number)) return -1;
    return fprintf(stream,
                   "::asn1c_runtime::ber::Tag::new("
                   "::asn1c_runtime::ber::TagClass::%s, %s)?",
                   class_name, formatted_number) < 0 ? -1 : 0;
}

/*
 * Emit a stack-bounded array of checked tag/kind descriptors for a record.
 * Parameters: stream receives Rust; expr owns at most six validated fields;
 * indent prefixes each generated source line. Returns zero or -1.
 * Errors: unsupported member class/kind or output failure. Source: runtime API.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged readers.
 * Example: emit descriptors in declaration order before opening a reader.
 */
static int
rust_write_ber_cer_field_descriptors(FILE *stream, asn1p_expr_t *expr,
                                     const char *indent) {
    asn1p_expr_t *member;
    if(expr->members.tq_head && fprintf(stream,
        "%suse ::asn1c_runtime::ber::{FieldKind, RecordField};\n", indent) < 0)
        return -1;
    TQ_FOR(member, &expr->members, next) {
        int class_code;
        uint32_t number;
        char local[48];
        char formatted_number[16];
        const char *class_name;
        if(rust_ber_cer_member_tag(member, &class_code, &number)) return -1;
        class_name = rust_ber_cer_tag_class(class_code);
        if(!class_name || rust_format_tag_number(formatted_number,
                sizeof(formatted_number), number)
           || rust_ber_cer_tag_local(member, local, sizeof(local))
           || fprintf(stream,
                "%slet %s = ::asn1c_runtime::ber::Tag::new(\n"
                "%s    ::asn1c_runtime::ber::TagClass::%s, %s)?;\n",
                indent, local, indent, class_name, formatted_number) < 0) return -1;
    }
    if(fprintf(stream, "%slet __asn1c_expected_fields = [\n", indent) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        const char *kind = rust_ber_cer_field_kind(member);
        const char *constructor = rust_ber_cer_member_explicit(member)
                                ? "new_explicit" : "new";
        char local[48];
        if(!kind || rust_ber_cer_tag_local(member, local, sizeof(local))
           || fprintf(stream,
                "%s    RecordField::%s(%s, FieldKind::%s)?,\n",
                indent, constructor, local, kind) < 0) return -1;
    }
    return fprintf(stream, "%s];\n", indent) < 0 ? -1 : 0;
}

/*
 * Emit one nested reader descriptor as a self-contained Rust expression.
 * Inputs: stream receives Rust; member supplies the validated tag and kind;
 * indent prefixes continuation lines. Returns zero or -1. Errors: unsupported
 * tags/kinds or output failure. Source: shared record reader descriptors.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested records.
 * Example: emit one universal INTEGER descriptor for a child reader.
 */
static int
rust_write_ber_cer_field_descriptor(FILE *stream, asn1p_expr_t *member,
                                    const char *indent) {
    int class_code;
    uint32_t number;
    char formatted_number[16];
    const char *class_name = NULL;
    const char *kind = rust_ber_cer_field_kind(member);
    const char *constructor = rust_ber_cer_member_explicit(member)
                            ? "new_explicit" : "new";
    if(!kind || rust_ber_cer_member_tag(member, &class_code, &number)
       || rust_format_tag_number(formatted_number, sizeof(formatted_number), number))
        return -1;
    class_name = rust_ber_cer_tag_class(class_code);
    if(!class_name) return -1;
    return fprintf(stream,
        "%s::asn1c_runtime::ber::RecordField::%s(\n"
        "%s    ::asn1c_runtime::ber::Tag::new(\n"
        "%s        ::asn1c_runtime::ber::TagClass::%s, %s)?,\n"
        "%s    ::asn1c_runtime::ber::FieldKind::%s)?,\n",
        indent, constructor, indent, indent, class_name, formatted_number,
        indent, kind) < 0 ? -1 : 0;
}

/*
 * Purpose: gate CBOR SEQUENCE generation to direct primitive map fields.
 * Source: C SEQUENCE CBOR text-key map and the Rust primitive CBOR slice.
 * Version/date: 2026-10-30. Inputs: module supplies diagnostics; expr owns
 * the validated record. Returns zero for a supported flat shape, -1 otherwise.
 * Errors: nested, selected, CONTAINING and unavailable primitive codecs fail.
 * Author: asn1c maintainers. History: first constructed CBOR Rust slice.
 * Example: required BOOLEAN plus OPTIONAL ANY is accepted.
 */
static int
rust_check_cbor_sequence(asn1p_module_t *module, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_BASIC_BOOLEAN || member->expr_type == ASN_BASIC_NULL
           || member->expr_type == ASN_BASIC_INTEGER
           || member->expr_type == ASN_BASIC_OCTET_STRING
           || member->expr_type == ASN_BASIC_BIT_STRING) {
            if((member->expr_type == ASN_BASIC_OCTET_STRING
                || member->expr_type == ASN_BASIC_BIT_STRING)
               && rust_containing_node(member->combined_constraints, 0)) {
                rust_diagnostic(module, member, "CBOR SEQUENCE CONTAINING is unsupported");
                return -1;
            }
            continue;
        }
        if(member->expr_type == ASN_TYPE_ANY && !member->reference
           && !member->constraints && !member->combined_constraints) continue;
        rust_diagnostic(module, member,
                        "CBOR SEQUENCE supports direct primitives, bounded strings, and ANY only");
        return -1;
    }
    return 0;
}

/*
 * Purpose: validate a bounded direct-alternative CHOICE for CBOR generation.
 * Source: C one-pair CHOICE CBOR text-key map. Version/date: 2026-10-30.
 * Inputs: module supplies diagnostics; expr owns alternatives; codecs is mask.
 * Returns zero for supported shape, -1 otherwise. Errors: extensions, aliases,
 * unsupported alternatives and post-sanitization collisions fail closed.
 * Author: maintainers. History: first Rust CBOR CHOICE slice.
 * Example: BOOLEAN or bounded INTEGER alternatives are accepted.
 */
static int
rust_check_cbor_choice(asn1p_module_t *module, asn1p_expr_t *expr,
                       uint64_t codecs) {
    asn1p_expr_t *item;
    size_t count = 0;
    if(codecs != RUST_CODEC_CBOR || expr->constraints || expr->combined_constraints
       || expr->lhs_params || expr->rhs_pspecs || expr->ioc_table || expr->marker.flags) {
        rust_diagnostic(module, expr, "CHOICE requires CBOR-only direct alternatives");
        return -1;
    }
    TQ_FOR(item, &expr->members, next) {
        asn1p_expr_t *prior;
        char *name;
        if(++count > 8 || !rust_sequence_member_shape_valid(item)
           || item->marker.flags != EM_NOMARK || !rust_enum_name_safe(item->Identifier)
           || (item->expr_type != ASN_BASIC_BOOLEAN
               && item->expr_type != ASN_BASIC_NULL
               && item->expr_type != ASN_BASIC_INTEGER
               && item->expr_type != ASN_TYPE_ANY)
           || rust_check_sequence_member(module, item)) {
            rust_diagnostic(module, item, "CBOR CHOICE needs at most eight direct supported alternatives");
            return -1;
        }
        name = rust_enum_variant(item->Identifier);
        if(!name) return -1;
        TQ_FOR(prior, &expr->members, next) {
            char *previous;
            int collision;
            if(prior == item) break;
            previous = rust_enum_variant(prior->Identifier);
            collision = !previous || !strcmp(name, previous)
                || !strcmp(item->Identifier, prior->Identifier);
            free(previous);
            if(collision) {
                free(name);
                rust_diagnostic(module, item, "CBOR CHOICE alternative names collide");
                return -1;
            }
        }
        free(name);
    }
    if(!count) {
        rust_diagnostic(module, expr, "CBOR CHOICE needs at least one alternative");
        return -1;
    }
    return 0;
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
        if(expr->expr_type != ASN_CONSTR_SEQUENCE && expr->expr_type != ASN_CONSTR_SET)
            continue;
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
        if(member->expr_type != ASN_CONSTR_SEQUENCE
           && member->expr_type != ASN_BASIC_ENUMERATED) continue;
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
        if(member->expr_type == ASN_CONSTR_SEQUENCE
           && rust_collect_nested_names(module, member, name, names, name_count,
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
    if((member->expr_type == ASN_BASIC_OCTET_STRING || member->expr_type == ASN_BASIC_BIT_STRING)
       && rust_containing_node(member->combined_constraints, 0)) {
        if(member->marker.flags != EM_DEFAULT && rust_contained_primitive(module, member)) return 0;
        rust_diagnostic(module, member, "SEQUENCE CONTAINING needs a supported UPER primitive");
        return -1;
    }
    if(member->expr_type == ASN_BASIC_ENUMERATED) {
        if(member->marker.flags == EM_DEFAULT) {
            rust_diagnostic(module, member, "ENUMERATED DEFAULT is unsupported");
            return -1;
        }
        return rust_check_enumerated(module, member, RUST_CODEC_UPER);
    }
    if(member->members.tq_head) {
        rust_diagnostic(module, member,
                        "primitive SEQUENCE field cannot contain child members");
        return -1;
    }
    if(member->expr_type == ASN_TYPE_ANY) {
        supported = !member->reference && !member->constraints && !member->combined_constraints
            && member->marker.flags != EM_DEFAULT;
    } else if(member->expr_type == ASN_BASIC_BOOLEAN
       || member->expr_type == ASN_BASIC_NULL) {
        supported = !member->constraints && !member->combined_constraints;
    } else if(member->expr_type == ASN_BASIC_INTEGER) {
        supported = member->combined_constraints
            && rust_constraint_supported(member->combined_constraints, 0)
            && !rust_integer_bounds(member, &(int64_t){0}, &(int64_t){0});
    } else if(member->expr_type == ASN_BASIC_OCTET_STRING) {
        supported = member->combined_constraints
            && rust_size_constraint_supported(member->combined_constraints, 0)
            && (!rust_fixed_size(member, &(size_t){0})
                || !rust_bounded_size(member, &(size_t){0}, &(size_t){0}));
    } else if(member->expr_type == ASN_BASIC_BIT_STRING) {
        supported = member->combined_constraints
            && rust_size_constraint_supported(member->combined_constraints, 0)
            && (!rust_fixed_size(member, &(size_t){0})
                || !rust_bounded_size(member, &(size_t){0}, &(size_t){0}));
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
 * Accept only one SIZE range rather than an interval union or fixed value.
 * Parameters: constraint is a fixed parser node; depth bounds recursion;
 * range_seen tracks the sole inclusive range leaf. Returns one when the
 * expression has exactly one integer range. No exception is thrown.
 * Original source: Rust UPER bounded-string gate. Version/date: 0.5.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: variable octets.
 * Example: rust_size_single_range_supported(node, 0, &seen).
 */
static int
rust_size_single_range_supported(const asn1p_constraint_t *constraint,
                                 unsigned depth, int *range_seen) {
    unsigned i;
    if(!constraint || !range_seen || depth > RUST_CONSTRAINT_DEPTH_LIMIT)
        return 0;
    if(constraint->type == ACT_EL_RANGE) {
        if(*range_seen || !constraint->range_start || !constraint->range_stop
           || constraint->range_start->type != ATV_INTEGER
           || constraint->range_stop->type != ATV_INTEGER) return 0;
        *range_seen = 1;
        return 1;
    }
    if(constraint->type != ACT_CT_SIZE && constraint->type != ACT_CA_SET
       && constraint->type != ACT_CA_INT) return 0;
    if(constraint->el_count != 1) return 0;
    for(i = 0; i < constraint->el_count; i++) {
        if(!rust_size_single_range_supported(constraint->elements[i], depth + 1,
                                             range_seen)) return 0;
    }
    return 1;
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
 * Extract one bounded nonextensible OCTET STRING size interval.
 * Parameters: expr is a direct string type; lower and upper receive inclusive
 * bounds. Returns zero for one contiguous nonempty range below 65536, else -1.
 * The computed PER range is released on every path; no exception is thrown.
 * Original source: X.691 constrained length selection. Version/date: 0.5.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: variable octets.
 * Example: rust_bounded_size(expr, &minimum, &maximum).
 */
static int
rust_bounded_size(asn1p_expr_t *expr, size_t *lower, size_t *upper) {
    asn1cnst_range_t *range;
    int range_seen = 0;
    if(!expr || !expr->combined_constraints || !lower || !upper
       || !rust_size_single_range_supported(expr->combined_constraints, 0,
                                            &range_seen)
       || !range_seen) return -1;
    range = asn1constraint_compute_PER_range(expr->Identifier, expr->expr_type,
        expr->combined_constraints, ACT_CT_SIZE, 0, 0, CPR_noflags);
    if(!range) return -1;
    if(range->incompatible || range->empty_constraint || range->not_PER_visible
       || range->extensible || range->left.type != ARE_VALUE
       || range->right.type != ARE_VALUE || range->left.value < 0
       || range->left.value >= range->right.value
       || range->right.value >= 65536) {
        asn1constraint_range_free(range);
        return -1;
    }
    *lower = (size_t)range->left.value;
    *upper = (size_t)range->right.value;
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
    if(!codecs
       || (codecs & ~(RUST_CODEC_UPER | RUST_CODEC_BER | RUST_CODEC_CER
                      | RUST_CODEC_JER)) || expr->constraints
       || expr->combined_constraints || expr->lhs_params || expr->ioc_table
       || expr->rhs_pspecs) {
        rust_diagnostic(module, expr,
            "ENUMERATED needs direct nonextensible values and supported codecs");
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
       || !strcmp(path, "runtime/src/big_integer.rs")
       || !strcmp(path, "runtime/src/ber.rs")
       || !strcmp(path, "runtime/src/cbor.rs")
       || !strcmp(path, "runtime/src/jer.rs")
       || !strcmp(path, "runtime/src/xer.rs")
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
        "Cargo.toml", "README.md", "LICENSE", "src/lib.rs", "src/big_integer.rs",
        "src/ber.rs",
        "src/cbor.rs", "src/jer.rs", "src/xer.rs", "src/aper.rs", "src/oer.rs", "src/uper_cursor.rs"
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
    {
        rust_open_plan_t open_plan;
        if(!rust_open_module_plan(module, &open_plan)) return rust_write_open_module(stream, &open_plan, codecs);
    }
    TQ_FOR(expr, &module->members, next) {
        if(rust_write_type(stream, module, expr, codecs)) return -1;
    }
    return ferror(stream) ? -1 : 0;
}

/* Emit selected variants and the selector-driven record declaration.
 * Inputs: stream is output; plan supplies rows; names identify Rust items.
 * Returns zero or -1; no exceptions. Source: fixed IOC plan. Version:
 * 2026-10-30. Responsible: asn1c maintainers. History: selected OPEN TYPE.
 * Example: emit Packet and its PacketValue variants.
 */
static int
rust_open_write_declarations(FILE *stream, const rust_open_plan_t *plan,
                             const char *record, const char *choice,
                             const char *selector, const char *member) {
    size_t i;
    if(fprintf(stream, "/// Selected ASN.1 OPEN TYPE alternatives.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub enum %s {\n", choice) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(fprintf(stream, "    /// Object-set row %zu selected by %" PRId64 ".\n"
                   "    Row%zu(%s),\n", i + 1, plan->row[i].key, i + 1,
                   plan->row[i].boolean ? "bool" : "i64") < 0) return -1;
    }
    return fprintf(stream, "}\n\n/// SEQUENCE with a selector-driven OPEN TYPE.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct %s {\n"
        "    /// Object-set selector state variable.\n    pub %s: i64,\n"
        "    /// Selected OPEN TYPE state variable.\n    pub %s: %s,\n}\n\nimpl %s {\n",
        record, selector, member, choice, record) < 0 ? -1 : 0;
}

/* Emit UPER encoding and selector/variant agreement checks.
 * Inputs: stream is output, plan supplies constraints, names identify fields.
 * Returns zero or -1; no exceptions. Source: X.691 open-type encoding.
 * Version: 2026-10-30. Responsible: asn1c maintainers. History: selected UPER.
 * Example: emit a BOOLEAN row and bounded INTEGER row.
 */
static int
rust_open_write_encode(FILE *stream, const rust_open_plan_t *plan, const char *choice,
                       const char *selector, const char *member, const char *codec) {
    char low[64], high[64];
    size_t i;
    if(rust_format_bound(low, sizeof(low), plan->lower)
       || rust_format_bound(high, sizeof(high), plan->upper)) return -1;
    if(rust_write_method_doc(stream, "Encode the selected OPEN TYPE with packed encoding rules.",
        "`self` supplies selector and value; `limits` bounds resources.", "Returns the packed encoding.",
        "Returns an error for a selector mismatch, invalid value, or limits.",
        "`let limits = Default::default();")) return -1;
    if(fprintf(stream, "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let mut writer = ::asn1c_runtime::UperWriter::new(limits)?;\n"
        "        writer.write_integer(self.%s, %s, %s)?;\n"
        "        match (self.%s, &self.%s) {\n", codec, selector, low, high, selector, member) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(rust_format_bound(low, sizeof(low), plan->row[i].lower)
           || rust_format_bound(high, sizeof(high), plan->row[i].upper)) return -1;
        if(fprintf(stream, "            (%" PRId64 ", %s::Row%zu(value)) =>\n"
            "                ::asn1c_runtime::uper_cursor::write_open_primitive_uper(\n"
            "                    &mut writer, %s, %s, %s)?,\n", plan->row[i].key, choice, i + 1,
            plan->row[i].boolean ? "i64::from(*value)" : "*value", low, high) < 0) return -1;
    }
    return fputs("            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"OPEN TYPE selector and value do not match\",\n"
        "            }),\n        }\n        writer.finish()\n    }\n", stream) == EOF ? -1 : 0;
}

/* Emit selector-directed UPER decoding with strict inner envelope checks.
 * Inputs: stream receives Rust, plan supplies rows, names identify fields.
 * Returns zero or -1; no exceptions. Source: X.691 open-type decoding.
 * Version: 2026-10-30. Responsible: asn1c maintainers. History: selected UPER.
 * Example: decode a bounded selected INTEGER.
 */
static int
rust_open_write_decode(FILE *stream, const rust_open_plan_t *plan, const char *choice,
                       const char *selector, const char *member, const char *codec) {
    char low[64], high[64];
    size_t i;
    if(rust_write_method_doc(stream, "Decode the selected OPEN TYPE with packed encoding rules.",
        "`input` supplies the prefix; `limits` bounds resources.", "Returns the record and prefix consumption.",
        "Returns an error for an unknown selector, invalid envelope, or limits.",
        "`let limits = Default::default();")) return -1;
    if(rust_format_bound(low, sizeof(low), plan->lower)
       || rust_format_bound(high, sizeof(high), plan->upper)) return -1;
    if(fprintf(stream, "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let mut reader = ::asn1c_runtime::UperReader::new(input, limits)?;\n"
        "        let __asn1c_selector = reader.read_integer(%s, %s)?;\n"
        "        let __asn1c_value = match __asn1c_selector {\n", codec, low, high) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(rust_format_bound(low, sizeof(low), plan->row[i].lower)
           || rust_format_bound(high, sizeof(high), plan->row[i].upper)) return -1;
        if(fprintf(stream, "            %" PRId64 " => %s::Row%zu(\n"
            "                ::asn1c_runtime::uper_cursor::read_open_primitive_uper(\n"
            "                    &mut reader, %s, %s)?%s),\n", plan->row[i].key, choice, i + 1,
            low, high, plan->row[i].boolean ? " != 0" : "") < 0) return -1;
    }
    return fprintf(stream, "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unknown OPEN TYPE selector\",\n"
        "            }),\n        };\n        let consumed = reader.finish()?;\n"
        "        Ok(::asn1c_runtime::Decoded { value: Self { %s: __asn1c_selector, %s: __asn1c_value },\n"
        "            consumed_bits: consumed.consumed_bits, consumed_bytes: consumed.consumed_bytes })\n"
        "    }\n", selector, member) < 0 ? -1 : 0;
}

/* Emit selected OER encoding with one cumulative operation budget.
 * Inputs: stream receives Rust; plan and names describe the validated record.
 * Returns zero or -1; no exceptions. Source: X.696 open-type encoding.
 * Version: 2026-10-30. Responsible: asn1c maintainers. History: OER selection.
 * Example: emit a bounded selected BOOLEAN row.
 */
static int
rust_open_write_oer_encode(FILE *stream, const rust_open_plan_t *plan, const char *choice,
                           const char *selector, const char *member) {
    char low[64], high[64], idlow[64], idhigh[64];
    size_t i;
    if(rust_format_bound(idlow, sizeof(idlow), plan->lower)
       || rust_format_bound(idhigh, sizeof(idhigh), plan->upper)) return -1;
    if(rust_write_method_doc(stream, "Encode the selected OPEN TYPE with OER.",
        "`self` supplies selector and value; `limits` bounds resources.", "Returns the OER encoding.",
        "Returns an error for a selector mismatch, invalid value, or limits.",
        "`value.encode_oer(&Default::default())?;")) return -1;
    if(fprintf(stream, "    pub fn encode_oer(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        match (self.%s, &self.%s) {\n", selector, member) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(rust_format_bound(low, sizeof(low), plan->row[i].lower)
           || rust_format_bound(high, sizeof(high), plan->row[i].upper)) return -1;
        if(fprintf(stream, "            (%" PRId64 ", %s::Row%zu(value)) =>\n"
            "                ::asn1c_runtime::oer::encode_open_record_oer(\n"
            "                    self.%s, (%s, %s), %s, (%s, %s), %s, limits),\n",
            plan->row[i].key, choice, i + 1, selector, idlow, idhigh,
            plan->row[i].boolean ? "i64::from(*value)" : "*value", low, high,
            plan->row[i].boolean ? "true" : "false") < 0) return -1;
    }
    return fputs("            _ => Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"OPEN TYPE selector and value do not match\",\n"
        "            }),\n        }\n    }\n", stream) == EOF ? -1 : 0;
}

/* Emit selected OER decoding and exact inner-envelope validation.
 * Inputs: stream receives Rust; plan and names describe the validated record.
 * Returns zero or -1; no exceptions. Source: X.696 open-type decoding.
 * Version: 2026-10-30. Responsible: asn1c maintainers. History: OER selection.
 * Example: decode a selected bounded INTEGER row.
 */
static int
rust_open_write_oer_decode(FILE *stream, const rust_open_plan_t *plan, const char *choice,
                           const char *selector, const char *member) {
    char low[64], high[64];
    size_t i;
    if(rust_write_method_doc(stream, "Decode the selected OPEN TYPE with OER.",
        "`input` supplies the prefix; `limits` bounds resources.", "Returns the record and consumption.",
        "Returns an error for an unknown selector, invalid envelope, or limits.",
        "`Type::decode_oer(input, &Default::default())?;")) return -1;
    if(rust_format_bound(low, sizeof(low), plan->lower)
       || rust_format_bound(high, sizeof(high), plan->upper)) return -1;
    if(fprintf(stream, "    pub fn decode_oer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let __asn1c_id = ::asn1c_runtime::oer::decode_integer_oer(input, %s, %s, limits)?;\n"
        "        let (__asn1c_value, __asn1c_decoded) = match __asn1c_id.value {\n", low, high) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(rust_format_bound(low, sizeof(low), plan->row[i].lower)
           || rust_format_bound(high, sizeof(high), plan->row[i].upper)) return -1;
        if(fprintf(stream, "            %" PRId64 " => {\n"
            "                let decoded = ::asn1c_runtime::oer::decode_open_payload_oer(\n"
            "                    input, __asn1c_id.consumed_bytes, (%s, %s), %s, limits)?;\n"
            "                (%s::Row%zu(decoded.value%s), decoded)\n            },\n",
            plan->row[i].key, low, high, plan->row[i].boolean ? "true" : "false", choice, i + 1,
            plan->row[i].boolean ? " != 0" : "") < 0) return -1;
    }
    return fprintf(stream, "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unknown OPEN TYPE selector\",\n"
        "            }),\n        };\n"
        "        Ok(::asn1c_runtime::Decoded { value: Self { %s: __asn1c_id.value, %s: __asn1c_value },\n"
        "            consumed_bits: __asn1c_decoded.consumed_bits,\n"
        "            consumed_bytes: __asn1c_decoded.consumed_bytes })\n    }\n", selector, member) < 0 ? -1 : 0;
}

/* Emit a selector-checked CBOR SEQUENCE map with a directly encoded selected arm.
 * Inputs: stream receives Rust; plan and names describe validated IOC rows.
 * Returns zero or -1; errors: write failures. Source: C SEQUENCE/OPEN_TYPE CBOR.
 * Version: 2026-10-30. Responsible: maintainers. History: selected CBOR slice.
 * Example: a selected BOOLEAN becomes map key "value" with CBOR true/false.
 */
static int
rust_open_write_cbor_encode(FILE *stream, const rust_open_plan_t *plan, const char *choice,
                            const char *selector, const char *member) {
    char low[64], high[64];
    size_t i;
    if(rust_format_bound(low, sizeof(low), plan->lower)
       || rust_format_bound(high, sizeof(high), plan->upper)) return -1;
    if(rust_write_method_doc(stream, "Encode the selected OPEN TYPE as a CBOR map.",
        "`self` supplies selector and selected value; `limits` bounds resources.",
        "Returns the encoded map.", "Returns an error for mismatched selectors, values, or limits.",
        "`value.encode_cbor(&Default::default())?;")) return -1;
    if(fprintf(stream, "    pub fn encode_cbor(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let id = ::asn1c_runtime::cbor::encode_integer_cbor(self.%s, %s, %s, limits)?;\n"
        "        let value = match (self.%s, &self.%s) {\n",
        selector, low, high, selector, member) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(rust_format_bound(low, sizeof(low), plan->row[i].lower)
           || rust_format_bound(high, sizeof(high), plan->row[i].upper)) return -1;
        if(fprintf(stream, "            (%" PRId64 ", %s::Row%zu(value)) =>\n"
            "                ::asn1c_runtime::cbor::encode_%s_cbor(*value, ",
            plan->row[i].key, choice, i + 1,
            plan->row[i].boolean ? "boolean" : "integer") < 0) return -1;
        if(plan->row[i].boolean) {
            if(fputs("limits)?,\n", stream) == EOF) return -1;
        } else if(fprintf(stream, "%s, %s, limits)?,\n", low, high) < 0) return -1;
    }
    return fprintf(stream, "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"OPEN TYPE selector and value do not match\" }),\n"
        "        };\n        ::asn1c_runtime::cbor::encode_map(&[(\"%s\", id), (\"%s\", value)], limits)\n"
        "    }\n", plan->selector->Identifier, plan->member->Identifier) < 0 ? -1 : 0;
}

/* Emit order-independent CBOR map decoding for one selector-directed arm.
 * Inputs: stream receives Rust; plan and names describe validated IOC rows.
 * Returns zero or -1; errors: write failures. Source: C CBOR SEQUENCE OPEN TYPE.
 * Version: 2026-10-30. Responsible: maintainers. History: selected CBOR slice.
 * Example: decode id after value by retaining a borrowed encoded value slice.
 */
static int
rust_open_write_cbor_decode(FILE *stream, const rust_open_plan_t *plan, const char *choice,
                            const char *selector, const char *member) {
    char low[64], high[64];
    size_t i;
    if(rust_format_bound(low, sizeof(low), plan->lower)
       || rust_format_bound(high, sizeof(high), plan->upper)) return -1;
    if(rust_write_method_doc(stream, "Decode a selector-directed CBOR SEQUENCE map.",
        "`input` supplies the map prefix; `limits` bounds resources.",
        "Returns the selected record and prefix consumption.",
        "Returns an error for missing, duplicate, unknown, or mismatched fields.",
        "`Type::decode_cbor(input, &Default::default())?;")) return -1;
    if(fprintf(stream, "    pub fn decode_cbor(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let map = ::asn1c_runtime::cbor::decode_map(input, limits)?;\n"
        "        let mut id = None;\n        let mut raw = None;\n"
        "        for entry in &map.value {\n            match entry.key {\n"
        "                b\"%s\" => {\n"
        "                    let decoded = ::asn1c_runtime::cbor::decode_integer_cbor(\n"
        "                        entry.value, %s, %s, limits)?;\n"
        "                    id = Some(::asn1c_runtime::cbor::complete_value(decoded, entry.value.len())?);\n"
        "                },\n                b\"%s\" => raw = Some(entry.value),\n"
        "                _ => {},\n"
        "            }\n        }\n"
        "        let id = id.ok_or(::asn1c_runtime::Error::InvalidEncoding {\n"
        "            reason: \"missing OPEN TYPE selector\" })?;\n"
        "        let raw = raw.ok_or(::asn1c_runtime::Error::InvalidEncoding {\n"
        "            reason: \"missing OPEN TYPE value\" })?;\n"
        "        let value = match id {\n",
        plan->selector->Identifier, low, high, plan->member->Identifier) < 0) return -1;
    for(i = 0; i < plan->rows; i++) {
        if(rust_format_bound(low, sizeof(low), plan->row[i].lower)
           || rust_format_bound(high, sizeof(high), plan->row[i].upper)) return -1;
        if(fprintf(stream, "            %" PRId64 " => {\n"
            "                let decoded = ::asn1c_runtime::cbor::decode_%s_cbor(raw, ",
            plan->row[i].key, plan->row[i].boolean ? "boolean" : "integer") < 0) return -1;
        if(plan->row[i].boolean) {
            if(fputs("limits)?;\n", stream) == EOF) return -1;
        } else if(fprintf(stream, "%s, %s, limits)?;\n", low, high) < 0) return -1;
        if(fprintf(stream, "                %s::Row%zu(\n"
            "                    ::asn1c_runtime::cbor::complete_value(decoded, raw.len())?)\n"
            "            },\n", choice, i + 1) < 0) return -1;
    }
    return fprintf(stream, "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unknown OPEN TYPE selector\" }),\n"
        "        };\n        let selected_id = id;\n"
        "        let selected_value = value;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self { %s: selected_id, %s: selected_value },\n"
        "            consumed_bits: map.consumed_bits, consumed_bytes: map.consumed_bytes })\n"
        "    }\n", selector, member) < 0 ? -1 : 0;
}

/* Emit a selector-driven UPER record from a validated IOC plan.
 * Inputs: stream receives Rust source; plan describes validated IOC rows.
 * Returns zero or -1 for write/allocation errors; no exceptions. Source:
 * X.691 open type framing. Version: 2026-10-30. Responsible: asn1c maintainers.
 * History: narrow selected OPEN TYPE. Example: emit a two-row record.
 */
static int
rust_write_open_module(FILE *stream, const rust_open_plan_t *plan, uint64_t codecs) {
    char *record = rust_identifier(plan->sequence->Identifier, 0);
    char *selector = rust_identifier(plan->selector->Identifier, 1);
    char *member = rust_identifier(plan->member->Identifier, 1);
    char *choice = rust_nested_type_name(record, plan->member);
    int ret = -1;
    if(!record || !selector || !member || !choice || !strcmp(selector, member)) goto done;
    if(rust_open_write_declarations(stream, plan, record, choice, selector, member)) goto done;
    if((codecs & RUST_CODEC_UPER)
       && (rust_open_write_encode(stream, plan, choice, selector, member, "uper")
           || rust_open_write_decode(stream, plan, choice, selector, member, "uper"))) goto done;
    if((codecs & RUST_CODEC_APER)
       && (rust_open_write_encode(stream, plan, choice, selector, member, "aper")
           || rust_open_write_decode(stream, plan, choice, selector, member, "aper"))) goto done;
    if((codecs & RUST_CODEC_OER)
       && (rust_open_write_oer_encode(stream, plan, choice, selector, member)
           || rust_open_write_oer_decode(stream, plan, choice, selector, member))) goto done;
    if((codecs & RUST_CODEC_CBOR)
       && (rust_open_write_cbor_encode(stream, plan, choice, selector, member)
           || rust_open_write_cbor_decode(stream, plan, choice, selector, member))) goto done;
    if(fputs("}\n", stream) == EOF) goto done;
    ret = 0;
done:
    free(record); free(selector); free(member); free(choice);
    return ret;
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
    if(expr->expr_type != ASN_CONSTR_SET
       && fputs("/// ASN.1 type generated from the fixed parser tree.\n", stream) == EOF) {
        free(name);
        return -1;
    }
    if(codecs == RUST_CODEC_XER) {
        ret = rust_write_xer_record(stream, name, expr);
    } else if(expr->expr_type == ASN_CONSTR_SET) {
        ret = rust_write_set(stream, name, expr, codecs);
    } else if(expr->expr_type == ASN_CONSTR_SEQUENCE) {
        ret = rust_write_all_sequences(stream, name, expr, 1, codecs);
    } else if(expr->expr_type == ASN_CONSTR_CHOICE) {
        ret = rust_write_cbor_choice(stream, name, expr);
    } else if(expr->expr_type == ASN_TYPE_ANY) {
        ret = rust_write_any(stream, name, codecs);
    } else if(expr->expr_type == ASN_BASIC_BOOLEAN) {
        ret = rust_write_boolean(stream, name, codecs);
    } else if(expr->expr_type == ASN_BASIC_NULL) {
        ret = rust_write_null(stream, name, codecs);
    } else if((expr->expr_type == ASN_BASIC_OCTET_STRING || expr->expr_type == ASN_BASIC_BIT_STRING)
              && rust_containing_node(expr->combined_constraints, 0)) {
        ret = rust_write_containing(stream, name, expr, rust_contained_primitive(module, expr), codecs);
    } else if((expr->expr_type == ASN_BASIC_OCTET_STRING
               || expr->expr_type == ASN_BASIC_BIT_STRING)
              && !expr->constraints && !expr->combined_constraints) {
        ret = rust_write_unconstrained_string(stream, name,
            expr->expr_type == ASN_BASIC_OCTET_STRING, codecs);
    } else if(expr->expr_type == ASN_BASIC_OCTET_STRING
              || expr->expr_type == ASN_BASIC_BIT_STRING) {
        ret = rust_write_string(stream, name, expr, codecs);
    } else if(expr->expr_type == ASN_BASIC_ENUMERATED) {
        ret = rust_write_enumerated(stream, name, expr, codecs);
    } else if(expr->expr_type == ASN_BASIC_INTEGER
              && !expr->constraints && !expr->combined_constraints) {
        ret = rust_write_big_integer(stream, name, codecs);
    } else {
        int64_t lower, upper;
        if(rust_integer_bounds(expr, &lower, &upper)) ret = -1;
        else ret = rust_write_integer(stream, name, lower, upper, codecs);
    }
    free(name);
    return ret || ferror(stream) ? -1 : 0;
}

/*
 * Emit the opaque ANY wrapper and selected codec methods.
 * Parameters: stream receives source; name is the Rust type identifier; codecs
 * selects the supported methods.
 * Returns zero on success or -1 on write error; no exceptions.
 * Source: Rust ANY runtimes. Version/date: 2026-10-30.
 * Responsible: asn1c maintainers. History: initial ANY support.
 * Example: rust_write_any(stream, "Value", RUST_CODEC_UPER).
 */
static int
rust_write_any(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream, "/// Opaque ASN.1 ANY octets.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// Opaque octet state variable.\n"
        "    pub ::std::vec::Vec<u8>\n);\n\nimpl %s {\n", name, name) < 0) return -1;
    if((codecs & RUST_CODEC_UPER)
       && rust_write_any_codec(stream, "uper", "uper_cursor::encode_any_uper(&self.0, limits)",
                               "uper_cursor::decode_any_uper(input, limits)")) return -1;
    /* Standalone APER starts aligned, so its ANY envelope is identical to UPER. */
    if((codecs & RUST_CODEC_APER)
       && rust_write_any_codec(stream, "aper", "uper_cursor::encode_any_uper(&self.0, limits)",
                               "uper_cursor::decode_any_uper(input, limits)")) return -1;
    if((codecs & RUST_CODEC_OER)
       && rust_write_any_codec(stream, "oer", "oer::encode_any_oer(&self.0, limits)",
                               "oer::decode_any_oer(input, limits)")) return -1;
    if((codecs & RUST_CODEC_CBOR)
       && rust_write_any_codec(stream, "cbor", "cbor::encode_any_cbor(&self.0, limits)",
                               "cbor::decode_any_cbor(input, limits)")) return -1;
    if((codecs & RUST_CODEC_JER)
       && rust_write_any_codec(stream, "jer", "jer::encode_octet_string_jer(&self.0, self.0.len(), limits)",
                               "jer::decode_bounded_octet_string_jer(input, 0, usize::MAX, limits)")) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one pair of codec methods for an opaque ANY wrapper.
 * Parameters: stream receives Rust; codec is the method suffix; encode and decode
 * are validated runtime call expressions. Returns zero or -1; no exceptions.
 * Source: Rust ANY codec emission. Version/date: 2026-10-30.
 * Responsible: asn1c maintainers. History: selectable opaque codecs.
 * Example: emit the UPER runtime pair.
 */
static int
rust_write_any_codec(FILE *stream, const char *codec, const char *encode, const char *decode) {
    if(rust_write_method_doc(stream, "Encode opaque ANY octets.",
        "`self` supplies octets; `limits` bounds resources.", "Returns the encoding.",
        "Returns a resource or allocation error.", "`value.encode_uper(&Default::default())?;")) return -1;
    if(fprintf(stream, "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::%s\n    }\n", codec, encode) < 0) return -1;
    if(rust_write_method_doc(stream, "Decode opaque ANY octets.",
        "`input` supplies bytes; `limits` bounds resources.", "Returns the value and consumed lengths.",
        "Returns an error for invalid input or resource exhaustion.",
        "`Type::decode_uper(input, &Default::default())?;")) return -1;
    return fprintf(stream, "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::%s?;\n"
        "        Ok(::asn1c_runtime::Decoded { value: Self(decoded.value),\n"
        "            consumed_bits: decoded.consumed_bits, consumed_bytes: decoded.consumed_bytes })\n"
        "    }\n", codec, decode) < 0 ? -1 : 0;
}

/* Emit a typed UPER wrapper for one validated primitive contents constraint.
 * Inputs: stream receives source, name is the Rust type, expr is the outer
 * string, inner is its resolved primitive. Returns zero or -1; no exceptions.
 * Source: Rust CONTAINING runtime. Version: 2026-10-30. Responsible: asn1c
 * maintainers. History: first typed primitive subset. Example: emit an integer.
 */
static int
rust_write_containing(FILE *stream, const char *name, asn1p_expr_t *expr, asn1p_expr_t *inner,
                      uint64_t codecs) {
    int is_boolean = inner && inner->expr_type == ASN_BASIC_BOOLEAN;
    int64_t lower = 0, upper = 1;
    char low[64], high[64];
    const char *type = is_boolean ? "bool" : "i64";
    const char *value = is_boolean ? "i64::from(self.0)" : "self.0";
    const char *decoded = is_boolean ? "decoded.value != 0" : "decoded.value";
    const char *octets = expr->expr_type == ASN_BASIC_OCTET_STRING ? "true" : "false";
    if(!inner || (!is_boolean && rust_integer_bounds(inner, &lower, &upper))
       || rust_format_bound(low, sizeof(low), lower) || rust_format_bound(high, sizeof(high), upper)) return -1;
    if(fprintf(stream, "/// Typed value of an ASN.1 CONTAINING string.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// Contained primitive state variable.\n    pub %s\n);\n\nimpl %s {\n",
        name, type, name) < 0) return -1;
    if((codecs & RUST_CODEC_UPER) && rust_write_method_doc(stream, "Encode this contained value with UPER.",
        "`self` supplies the primitive; `limits` bounds resources.", "Returns the outer encoding.",
        "Returns an error for invalid values or exhausted resources.", "`value.encode_uper(&Default::default())?;"))
        return -1;
    if((codecs & RUST_CODEC_UPER)
       && fprintf(stream, "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::uper_cursor::encode_containing_uper(%s, %s, %s, %s, limits)\n    }\n",
        value, low, high, octets) < 0) return -1;
    if((codecs & RUST_CODEC_UPER) && rust_write_method_doc(stream, "Decode a contained UPER value.",
        "`input` supplies the outer prefix; `limits` bounds resources.", "Returns the inner value and consumption.",
        "Returns an error for malformed contents or exhausted resources.",
        "`Type::decode_uper(input, &Default::default())?;"))
        return -1;
    if((codecs & RUST_CODEC_UPER) && fprintf(stream,
        "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::uper_cursor::decode_containing_uper(input, %s, %s, %s, limits)?;\n"
        "        Ok(::asn1c_runtime::Decoded { value: Self(%s),\n"
        "            consumed_bits: decoded.consumed_bits, consumed_bytes: decoded.consumed_bytes })\n"
        "    }\n", low, high, octets, decoded) < 0) return -1;
    if(codecs & RUST_CODEC_CBOR) {
        if(rust_write_method_doc(stream, "Encode the contained CBOR primitive in a CBOR byte string.",
            "`self` supplies the primitive; `limits` bounds resources.", "Returns the outer encoding.",
            "Returns an error for invalid values or exhausted resources.",
            "`value.encode_cbor(&Default::default())?;")) return -1;
        if(fputs("    pub fn encode_cbor(&self, limits: &::asn1c_runtime::Limits) ->\n"
                 "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n",
                 stream) == EOF) return -1;
        if(is_boolean) {
            if(fputs("        let inner = ::asn1c_runtime::cbor::encode_boolean_cbor(self.0, limits)?;\n",
                     stream) == EOF) return -1;
        } else if(fprintf(stream,
                         "        let inner = ::asn1c_runtime::cbor::encode_integer_cbor(self.0, %s, %s, limits)?;\n",
                         low, high) < 0) return -1;
        if(fprintf(stream, "        ::asn1c_runtime::cbor::encode_%s_cbor(&inner.bytes, %s0, usize::MAX, limits)\n"
                           "    }\n",
                   octets[0] == 't' ? "octet_string" : "bit_string",
                   octets[0] == 't' ? "" : "inner.bit_len, ") < 0) return -1;
        if(rust_write_method_doc(stream, "Decode one contained CBOR primitive from a CBOR byte string.",
            "`input` supplies the outer prefix; `limits` bounds resources.",
            "Returns the inner value and outer consumption.",
            "Returns an error for invalid outer bits or incomplete inner CBOR.",
            "`Type::decode_cbor(input, &Default::default())?;")) return -1;
        if(fprintf(stream, "    pub fn decode_cbor(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
                           "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
                           "        let outer = ::asn1c_runtime::cbor::decode_%s_cbor(\n"
                           "            input, 0, usize::MAX, limits)?;\n",
                   octets[0] == 't' ? "octet_string" : "bit_string") < 0) return -1;
        if(octets[0] != 't'
           && fputs("        if outer.value.bit_len() % 8 != 0 {\n"
                    "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
                    "                reason: \"contained CBOR is not octet aligned\" });\n"
                    "        }\n", stream) == EOF) return -1;
        if(fprintf(stream, "        let inner = outer.value%s;\n",
                   octets[0] == 't' ? "" : ".into_bytes()") < 0) return -1;
        if(is_boolean) {
            if(fputs("        let decoded = ::asn1c_runtime::cbor::decode_boolean_cbor(&inner, limits)?;\n",
                     stream) == EOF) return -1;
        } else if(fprintf(stream,
                         "        let decoded = ::asn1c_runtime::cbor::decode_integer_cbor(&inner, %s, %s, limits)?;\n",
                         low, high) < 0) return -1;
        if(fputs("        let value = ::asn1c_runtime::cbor::complete_value(decoded, inner.len())?;\n"
                 "        Ok(::asn1c_runtime::Decoded { value: Self(value),\n"
                 "            consumed_bits: outer.consumed_bits, consumed_bytes: outer.consumed_bytes })\n"
                 "    }\n", stream) == EOF) return -1;
    }
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit a nested ENUMERATED and helpers that share the enclosing UPER cursor.
 * Parameters: stream receives Rust, name identifies the type, and expr owns
 * validated root values. Returns zero on success, -1 on output failure; no
 * exceptions. Original source: standalone ENUMERATED UPER emitter.
 * Version/date: 0.7.0, 2026-10-30. Responsible: asn1c maintainers.
 * History: added inline SEQUENCE enum fields. Example: emit PacketStatus.
 */
static int
rust_write_inline_enum(FILE *stream, const char *name, asn1p_expr_t *expr,
                       uint64_t codecs) {
    asn1p_expr_t *item;
    size_t count = 0;
    TQ_FOR(item, &expr->members, next) count++;
    if(rust_write_enumerated(stream, name, expr, codecs & RUST_CODEC_UPER)) return -1;
    if(!(codecs & RUST_CODEC_UPER)) return 0;
    if(fprintf(stream, "impl %s {\n", name) < 0) return -1;
    if(rust_write_method_doc(stream, "Encode an enum in a shared UPER cursor.",
        "`self` supplies the value; `writer` is the enclosing cursor.",
        "Returns success after writing the index.", "Returns a cursor error.",
        "`value.encode_uper_fields(writer)?;")) return -1;
    if(fputs("    fn encode_uper_fields(self, writer: &mut ::asn1c_runtime::UperWriter) ->\n"
             "        ::core::result::Result<(), ::asn1c_runtime::Error> {\n"
             "        let index = match self {\n", stream) == EOF) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = variant ? fprintf(stream, "            Self::%s => %zu,\n",
                                    variant, rust_enumerated_rank(expr, item)) : -1;
        free(variant);
        if(ret < 0) return -1;
    }
    if(fprintf(stream, "        };\n        writer.write_integer(index, 0, %zu)\n    }\n", count - 1) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Decode an enum from a shared UPER cursor.",
        "`reader` is the enclosing cursor.", "Returns a validated enum variant.",
        "Returns an error for truncation or a spare index.",
        "`let value = Self::decode_uper_fields(reader)?;")) return -1;
    if(fprintf(stream, "    fn decode_uper_fields(reader: &mut ::asn1c_runtime::UperReader) ->\n"
               "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
               "        match reader.read_integer(0, %zu)? {\n", count - 1) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = variant ? fprintf(stream, "            %zu => Ok(Self::%s),\n",
                                    rust_enumerated_rank(expr, item), variant) : -1;
        free(variant);
        if(ret < 0) return -1;
    }
    return fputs("            _ => Err(::asn1c_runtime::Error::InvalidEncoding {\n"
                 "                reason: \"unused ENUMERATED root index\",\n"
                 "            }),\n        }\n    }\n}\n\n", stream) == EOF ? -1 : 0;
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
                    int top_level, uint64_t codecs) {
    asn1p_expr_t *member;
    int has_members = expr->members.tq_head != 0;
    if(fprintf(stream,
        "/// ASN.1 SEQUENCE record with direct inline fields.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s {\n", name) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_field(stream, name, member)) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(codecs & RUST_CODEC_UPER) {
    if(has_members) {
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
    }
    if(!top_level) {
        if((codecs & (RUST_CODEC_BER | RUST_CODEC_CER))
           && rust_write_sequence_ber_cer(stream, name, expr, 0, codecs)) return -1;
        if(fputs("}\n\n", stream) == EOF) return -1;
        return 0;
    }
    if(rust_write_method_doc(stream,
            "Encode the complete SEQUENCE with one shared UPER budget.",
            "`self` supplies the record; `limits` bounds the whole operation.",
            "Returns packed bytes and meaningful bit length.",
            "Returns an error for invalid fields or exhausted resources.",
            "`let encoded = value.encode_uper(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let %swriter = ::asn1c_runtime::UperWriter::new(limits)?;\n",
        has_members ? "mut " : "") < 0) return -1;
    if(has_members) {
        if(fputs("        self.encode_uper_fields(&mut writer)?;\n", stream) == EOF)
            return -1;
    } else if(fputs("        let _ = self;\n", stream) == EOF) return -1;
    if(fputs("        writer.finish()\n    }\n\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete SEQUENCE prefix with a shared UPER budget.",
            "`input` is the encoded prefix; `limits` bounds the whole operation.",
            "Returns validated fields and bit/byte prefix consumption.",
            "Returns an error for truncation, malformed fields, or exhausted resources.",
            "`let decoded = Type::decode_uper(input, &Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let %sreader = ::asn1c_runtime::UperReader::new(input, limits)?;\n",
        has_members ? "mut " : "") < 0) return -1;
    if(has_members) {
        if(fputs("        let value = Self::decode_uper_fields(&mut reader)?;\n", stream) == EOF)
            return -1;
    } else if(fputs("        let value = Self {};\n", stream) == EOF) return -1;
    if(fputs("        let consumed = reader.finish()?;\n"
             "        Ok(::asn1c_runtime::Decoded {\n"
             "            value,\n"
             "            consumed_bits: consumed.consumed_bits,\n"
             "            consumed_bytes: consumed.consumed_bytes,\n"
             "        })\n"
             "    }\n", stream) == EOF) return -1;
    }
    if((codecs & RUST_CODEC_CBOR) && rust_write_sequence_cbor(stream, expr)) return -1;
    if((codecs & (RUST_CODEC_BER | RUST_CODEC_CER))
       && rust_write_sequence_ber_cer(stream, name, expr, 1, codecs)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit DER/BER and CER methods for one validated direct-field SEQUENCE.
 * Parameters: stream receives Rust; expr owns untagged unique-tag fields;
 * codecs selects BER/DER and/or CER methods. Returns zero or -1. Errors: an
 * output failure is reported; generated methods return runtime errors.
 * Source: X.690 SEQUENCE framing and the shared-budget runtime API.
 * Version/date: 2026-10-31. Author: asn1c maintainers. History: second-wave
 * constructed codecs. Example: rust_write_sequence_ber_cer(out, name, expr, codecs).
 */
static int
rust_write_sequence_ber_cer(FILE *stream, const char *parent, asn1p_expr_t *expr,
                            int top_level, uint64_t codecs) {
    const char *writer_mut = expr->members.tq_head ? "mut " : "";
    int tagged_root = top_level && expr->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && expr->tag.tag_mode == TM_IMPLICIT;
    if(rust_write_nested_ber_cer_fields(stream, expr, parent)
       || rust_write_sequence_ber_cer_decode_fields(stream, parent, expr)) return -1;
    if(!top_level) return 0;
    if(rust_write_method_doc(stream, "Encode this SEQUENCE using the selected record rule.",
        "`self` supplies fields; `limits` bounds the complete operation.",
        "Returns one complete SEQUENCE TLV.",
        "Returns an error for invalid values or exhausted resources.",
        "`let encoded = value.encode_der(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    fn encode_record_with_rule(&self, rule: ::asn1c_runtime::ber::RecordEncoding,\n"
        "        context: &mut ::asn1c_runtime::ber::RecordContext) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let %swriter = ::asn1c_runtime::ber::SequenceWriter::new(rule, context)?;\n",
        writer_mut) < 0) return -1;
    if(!expr->members.tq_head
       && fputs("        let _ = self;\n", stream) == EOF) return -1;
    if(expr->members.tq_head
       && fputs("        self.encode_record_fields(&mut writer)?;\n", stream) == EOF)
        return -1;
    if(tagged_root) {
        if(fprintf(stream,
            "        writer.finish_tagged_root("
            "::asn1c_runtime::ber::Tag::context_specific(0x%04" PRIx32 "_%04" PRIx32
            "))\n    }\n\n",
            (uint32_t)expr->tag.tag_value >> 16,
            (uint32_t)expr->tag.tag_value & UINT32_C(0xffff)) < 0) return -1;
    } else if(fputs("        writer.finish()\n    }\n\n", stream) == EOF) {
        return -1;
    }
    if(codecs & RUST_CODEC_BER) {
        if(rust_write_method_doc(stream, "Encode this SEQUENCE using DER.",
            "`self` supplies fields; `limits` bounds the complete operation.",
            "Returns the complete DER SEQUENCE TLV.",
            "Returns an error for invalid values or exhausted resources.",
            "`let encoded = value.encode_der(&Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn encode_der(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let mut context = ::asn1c_runtime::ber::RecordContext::%s(limits);\n"
            "        self.encode_record_with_rule(\n"
            "            ::asn1c_runtime::ber::RecordEncoding::Der, &mut context)\n"
            "    }\n\n",
            rust_ber_cer_has_nested_sequence(expr) ? "new_nested" : "new") < 0) return -1;
        if(rust_write_sequence_ber_cer_decode_method(stream, expr, 0)) return -1;
    }
    if(codecs & RUST_CODEC_CER) {
        if(rust_write_method_doc(stream, "Encode this SEQUENCE using CER.",
            "`self` supplies fields; `limits` bounds the complete operation.",
            "Returns the complete CER SEQUENCE TLV.",
            "Returns an error for invalid values or exhausted resources.",
            "`let encoded = value.encode_cer(&Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn encode_cer(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let mut context = ::asn1c_runtime::ber::RecordContext::%s(limits);\n"
            "        self.encode_record_with_rule(\n"
            "            ::asn1c_runtime::ber::RecordEncoding::Cer, &mut context)\n"
            "    }\n\n",
            rust_ber_cer_has_nested_sequence(expr) ? "new_nested" : "new") < 0) return -1;
        if(rust_write_sequence_ber_cer_decode_method(stream, expr, 1)) return -1;
    }
    return 0;
}

/*
 * Emit a private SEQUENCE field encoder that borrows an existing writer.
 * Inputs: stream receives Rust; expr owns validated primitive child fields;
 * parent identifies nested type names. Returns zero or -1. Errors: output
 * failures are reported to the caller. Source: shared record context API.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested BER/CER.
 * Example: a parent's callback writes one inline child's fields here.
 */
static int
rust_write_nested_ber_cer_fields(FILE *stream, asn1p_expr_t *expr,
                                 const char *parent) {
    asn1p_expr_t *member;
    int uses_self = 0;
    if(!expr->members.tq_head) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type != ASN_CONSTR_SEQUENCE || member->members.tq_head
           || member->marker.flags == EM_OPTIONAL) uses_self = 1;
    }
    if(rust_write_method_doc(stream,
        "Append this SEQUENCE's fields to a caller-owned record writer.",
        "`self` supplies values; `writer` shares the parent's operation context.",
        "Returns success after all fields are appended.",
        "Returns an error for invalid values or exhausted resources.",
        "`self.encode_record_fields(child_writer)?;")) return -1;
    if(fputs(
        "    fn encode_record_fields(&self,\n"
        "        writer: &mut ::asn1c_runtime::ber::SequenceWriter<'_>) ->\n"
        "        ::core::result::Result<(), ::asn1c_runtime::Error> {\n",
        stream) == EOF) return -1;
    if(!uses_self && fputs("        let _ = self;\n", stream) == EOF) return -1;
    if(rust_write_ber_cer_tag_locals(stream, expr)) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_ber_cer_encode_field(stream, parent, member)) return -1;
    }
    return fputs("        Ok(())\n    }\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Sort validated SET fields by effective class and number.
 * Parameters: expr supplies fields; sorted/capacity hold pointers; count_out
 * receives the result length. Returns zero or -1. Source: X.690 SET order.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged SET.
 * Example: universal tag 1 sorts before context-specific tag 2.
 */
static int
rust_ber_cer_sort_set_fields(asn1p_expr_t *expr, asn1p_expr_t **sorted,
                             size_t capacity, size_t *count_out) {
    asn1p_expr_t *member;
    size_t count = 0;
    TQ_FOR(member, &expr->members, next) {
        size_t position = count;
        if(count >= capacity) return -1;
        while(position > 0
              && rust_ber_cer_tag_compare(sorted[position - 1], member) > 0) {
            sorted[position] = sorted[position - 1];
            position--;
        }
        sorted[position] = member;
        count++;
    }
    *count_out = count;
    return 0;
}

/*
 * Emit DER/CER methods for a validated direct-field SET.
 * Parameters: stream receives Rust; parent names inline enums; expr owns
 * unique-tag fields; codecs selects BER/DER and/or CER. Returns zero or -1.
 * Errors: output failure; generated methods return runtime errors.
 * Source: X.690 SET framing and the shared-budget runtime API.
 * Version/date: 2026-10-31. Author: asn1c maintainers. History: fourth wave.
 * Example: rust_write_set_ber_cer(out, name, expr, RUST_CODEC_BER).
 */
static int
rust_write_set_ber_cer(FILE *stream, const char *parent, asn1p_expr_t *expr,
                       uint64_t codecs) {
    asn1p_expr_t *sorted[6];
    size_t count;
    size_t i;
    asn1p_expr_t *member;
    int has_members = expr->members.tq_head != 0;
    int tagged_root = expr->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && expr->tag.tag_mode == TM_IMPLICIT;
    const char *context_constructor = rust_ber_cer_has_nested_sequence(expr)
                                    ? "new_nested" : "new";
    if(rust_ber_cer_sort_set_fields(expr, sorted,
                                    sizeof(sorted) / sizeof(sorted[0]), &count)) return -1;
    if(rust_write_method_doc(stream, "Encode this SET using the selected record rule.",
        "`self` supplies fields; `limits` bounds the complete operation.",
        "Returns one complete SET TLV.",
        "Returns an error for invalid values or exhausted resources.",
        "`let encoded = value.encode_der(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    fn encode_record_with_rule(&self, rule: ::asn1c_runtime::ber::RecordEncoding,\n"
        "        context: &mut ::asn1c_runtime::ber::RecordContext) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let %swriter = ::asn1c_runtime::ber::SetWriter::new(rule, context)?;\n",
        has_members ? "mut " : "") < 0) return -1;
    if(rust_write_ber_cer_tag_locals(stream, expr)) return -1;
    if(!has_members && fputs("        let _ = self;\n", stream) == EOF) return -1;
    for(i = 0; i < count; i++) {
        if(rust_write_sequence_ber_cer_encode_field(stream, parent, sorted[i]))
            return -1;
    }
    if(tagged_root) {
        if(fprintf(stream,
            "        writer.finish_tagged_root("
            "::asn1c_runtime::ber::Tag::context_specific(0x%04" PRIx32 "_%04" PRIx32
            "))\n    }\n\n",
            (uint32_t)expr->tag.tag_value >> 16,
            (uint32_t)expr->tag.tag_value & UINT32_C(0xffff)) < 0) return -1;
    } else if(fputs("        writer.finish()\n    }\n\n", stream) == EOF) {
        return -1;
    }
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_set_ber_cer_decode_helper(stream, parent, member)) return -1;
    }
    if(codecs & RUST_CODEC_BER) {
        if(rust_write_method_doc(stream, "Encode this SET using DER.",
            "`self` supplies fields; `limits` bounds the complete operation.",
            "Returns the complete DER SET TLV.",
            "Returns an error for invalid values or exhausted resources.",
            "`let encoded = value.encode_der(&Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn encode_der(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let mut context = ::asn1c_runtime::ber::RecordContext::%s(limits);\n"
            "        self.encode_record_with_rule(\n"
            "            ::asn1c_runtime::ber::RecordEncoding::Der, &mut context)\n"
            "    }\n\n", context_constructor) < 0) return -1;
        if(rust_write_set_ber_cer_decode_method(stream, expr, 0)) return -1;
    }
    if(codecs & RUST_CODEC_CER) {
        if(rust_write_method_doc(stream, "Encode this SET using CER.",
            "`self` supplies fields; `limits` bounds the complete operation.",
            "Returns the complete CER SET TLV.",
            "Returns an error for invalid values or exhausted resources.",
            "`let encoded = value.encode_cer(&Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn encode_cer(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let mut context = ::asn1c_runtime::ber::RecordContext::%s(limits);\n"
            "        self.encode_record_with_rule(\n"
            "            ::asn1c_runtime::ber::RecordEncoding::Cer, &mut context)\n"
            "    }\n\n", context_constructor) < 0) return -1;
        if(rust_write_set_ber_cer_decode_method(stream, expr, 1)) return -1;
    }
    return 0;
}

/*
 * Emit a small typed SET-field decoder so record dispatch stays concise.
 * Parameters: stream receives Rust; parent names inline enums; member is a
 * validated direct field. Returns zero or -1. Errors: source write failure.
 * Source: X.690 primitive field readers. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: fourth-wave SET generation.
 * Example: decode one BOOLEAN child after SetReader selects tag 1.
 */
static int
rust_write_set_ber_cer_decode_helper(FILE *stream, const char *parent,
                                     asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    char *nested_type = member->expr_type == ASN_BASIC_ENUMERATED
        || member->expr_type == ASN_CONSTR_SEQUENCE
        ? rust_nested_type_name(parent, member) : NULL;
    const char *type = member->expr_type == ASN_BASIC_BOOLEAN ? "bool"
        : member->expr_type == ASN_BASIC_NULL ? "()"
        : member->expr_type == ASN_BASIC_INTEGER ? "i64"
        : member->expr_type == ASN_BASIC_OCTET_STRING ? "::std::vec::Vec<u8>"
        : member->expr_type == ASN_BASIC_BIT_STRING
          && rust_fixed_size(member, &(size_t){0}) == 0 ? "::std::vec::Vec<u8>"
        : member->expr_type == ASN_BASIC_BIT_STRING ? "::asn1c_runtime::BitStringValue"
        : nested_type;
    int ret;
    if(!name || !type) {
        free(name);
        free(nested_type);
        return -1;
    }
    ret = fprintf(stream,
        "    fn __asn1c_decode_set_field_%s(\n"
        "        reader: &mut ::asn1c_runtime::ber::SetReader<'_, '_, '_>) ->\n"
        "        ::core::result::Result<%s, ::asn1c_runtime::Error> {\n",
        name, type);
    if(ret >= 0 && member->expr_type == ASN_BASIC_NULL) {
        ret = fputs("        reader.read_null()?;\n        Ok(())\n", stream) == EOF ? -1 : 0;
    } else if(ret >= 0) {
        if(rust_write_sequence_ber_cer_decode_value(stream, parent, member, "        "))
            ret = -1;
        else ret = fputs("        Ok(value)\n", stream) == EOF ? -1 : 0;
    }
    if(ret >= 0) ret = fputs("    }\n\n", stream) == EOF ? -1 : 0;
    free(name);
    free(nested_type);
    return ret < 0 ? -1 : 0;
}

/*
 * Emit the appropriate SET reader constructor and tag list.
 * Parameters: stream receives Rust; expr owns fields; tagged selects descriptor
 * dispatch; tagged_root selects the outer-tag reader. Returns zero or -1.
 * Source: X.690 SET fields and runtime API.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: tagged SET.
 * Example: build a descriptor-backed reader for context-specific fields.
 */
static int
rust_write_set_ber_cer_reader(FILE *stream, asn1p_expr_t *expr, int tagged,
                              int tagged_root) {
    asn1p_expr_t *member;
    if(tagged) {
        if(rust_write_ber_cer_field_descriptors(stream, expr, "            ")) return -1;
        if(tagged_root) {
            if(fprintf(stream,
                "            let mut reader = ::asn1c_runtime::ber::SetReader::"
                "new_tagged_root(\n"
                "                input, ::asn1c_runtime::ber::Tag::context_specific("
                "0x%04" PRIx32 "_%04" PRIx32 "),\n"
                "                &__asn1c_expected_fields, &mut context)?;\n",
                (uint32_t)expr->tag.tag_value >> 16,
                (uint32_t)expr->tag.tag_value & UINT32_C(0xffff)) < 0) return -1;
        } else if(fputs(
            "            let mut reader = ::asn1c_runtime::ber::SetReader::new_tagged(\n"
            "                input, &__asn1c_expected_fields, &mut context)?;\n",
            stream) == EOF) {
            return -1;
        }
        return 0;
    }
    if(fputs("            let mut reader = ::asn1c_runtime::ber::SetReader::new(\n"
             "                input, &[", stream) == EOF) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(fprintf(stream, "%s%llu", member == TQ_FIRST(&expr->members) ? "" : ", ",
                   (unsigned long long)rust_sequence_ber_cer_tag(member)) < 0) return -1;
    }
    return fputs("], &mut context)?;\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit empty slots used to collect unordered SET fields.
 * Parameters: stream receives Rust; expr owns validated fields. Returns zero
 * or -1. Source: X.690 unordered SET decode. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: fourth-wave SET generation.
 * Example: declare one `Option` slot for each effective tag.
 */
static int
rust_write_set_ber_cer_decode_slots(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        char *name = rust_identifier(member->Identifier, 1);
        int ret = name ? fprintf(stream, "            let mut __asn1c_%s = None;\n", name) : -1;
        free(name);
        if(ret < 0) return -1;
    }
    return 0;
}

/*
 * Emit one match arm that decodes a selected SET field.
 * Parameters: stream receives Rust; member is checked; tagged selects Tag API.
 * Returns zero or -1. Source: X.690 effective tag dispatch. Version/date:
 * 2026-11-01. Author: asn1c maintainers. History: unordered SET decoding.
 * Example: map a context-specific tag to its matching field slot.
 */
static int
rust_write_set_ber_cer_dispatch_arm(FILE *stream, asn1p_expr_t *member, int tagged) {
    char *name = rust_identifier(member->Identifier, 1);
    uint32_t tag_number;
    int tag_class;
    char formatted_number[16];
    const char *class_name;
    int result;
    if(!name || rust_ber_cer_member_tag(member, &tag_class, &tag_number)
       || rust_format_tag_number(formatted_number, sizeof(formatted_number), tag_number)) {
        free(name);
        return -1;
    }
    class_name = rust_ber_cer_tag_class(tag_class);
    if(!class_name) {
        free(name);
        return -1;
    }
    if(tagged)
        result = fprintf(stream,
            "                    (::asn1c_runtime::ber::TagClass::%s, %s) => {\n"
            "                        __asn1c_%s = Some(\n"
            "                            Self::__asn1c_decode_set_field_%s(\n"
            "                                &mut reader)?,\n"
            "                        );\n"
            "                    }\n", class_name, formatted_number, name, name);
    else
        result = fprintf(stream,
            "                    %s => {\n"
            "                        __asn1c_%s = Some(\n"
            "                            Self::__asn1c_decode_set_field_%s(\n"
            "                                &mut reader)?,\n"
            "                        );\n"
            "                    }\n", formatted_number, name, name);
    free(name);
    return result < 0 ? -1 : 0;
}

/*
 * Emit the loop that dispatches arbitrary BER SET component order.
 * Parameters: stream receives Rust; expr owns fields; tagged selects Tag API.
 * Returns zero or -1. Source: X.690 SET ordering rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged and universal SET decoding.
 * Example: accept any order while rejecting an unrecognized tag.
 */
static int
rust_write_set_ber_cer_dispatch(FILE *stream, asn1p_expr_t *expr, int tagged) {
    asn1p_expr_t *member;
    if(!expr->members.tq_head)
        return fprintf(stream,
        "            if reader.%s()?.is_some() {\n"
        "                return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                    reason: \"unexpected field in empty SET\",\n"
        "                });\n"
        "            }\n", tagged ? "next_tagged_field" : "next_field") < 0 ? -1 : 0;
    if(fprintf(stream,
        "            while let Some(__asn1c_tag) = reader.%s()? {\n"
        "                match %s {\n",
        tagged ? "next_tagged_field" : "next_field",
        tagged ? "(__asn1c_tag.class(), __asn1c_tag.number())" : "__asn1c_tag") < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_set_ber_cer_dispatch_arm(stream, member, tagged)) return -1;
    }
    return fputs(
        "                    _ => {\n"
        "                        return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                            reason: \"unknown SET field\",\n"
        "                        });\n"
        "                    }\n"
        "                }\n"
        "            }\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit the final SET struct and required-field checks from collected slots.
 * Parameters: stream receives Rust; expr owns validated field metadata.
 * Returns zero or -1. Source: ASN.1 required/OPTIONAL/DEFAULT semantics.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: SET support.
 * Example: convert a missing DEFAULT field into its literal value.
 */
static int
rust_write_set_ber_cer_construct_value(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(fputs("            let value = Self {\n", stream) == EOF) return -1;
    TQ_FOR(member, &expr->members, next) {
        char *name = rust_identifier(member->Identifier, 1);
        if(!name || fprintf(stream, "                %s: ", name) < 0) {
            free(name);
            return -1;
        }
        if(member->marker.flags == EM_OPTIONAL) {
            if(fprintf(stream, "__asn1c_%s,\n", name) < 0) {
                free(name);
                return -1;
            }
        } else if(member->marker.flags == EM_DEFAULT) {
            char literal[64];
            if(rust_sequence_default_literal(member, literal, sizeof(literal))
               || fprintf(stream, "__asn1c_%s.unwrap_or(%s),\n", name, literal) < 0) {
                free(name);
                return -1;
            }
        } else if(fprintf(stream,
            "__asn1c_%s.ok_or(::asn1c_runtime::Error::InvalidEncoding {\n"
            "                    reason: \"missing required SET field\",\n"
            "                })?,\n", name) < 0) {
            free(name);
            return -1;
        }
        free(name);
    }
    return fputs("            };\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one BER or strict CER decoder for a validated direct-field SET.
 * Parameters: stream receives Rust; parent names inline enums; expr owns
 * fields; cer selects canonical verification. Returns zero or -1.
 * Errors: output failure; generated methods reject malformed wire values.
 * Source: X.690 unordered SET fields and the record runtime. Version/date:
 * 2026-10-31. Author: asn1c maintainers. History: fourth wave.
 * Example: decode_cer rejects a reordered SET even when BER accepts it.
 */
static int
rust_write_set_ber_cer_decode_method(FILE *stream, asn1p_expr_t *expr, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    int tagged_root = expr->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && expr->tag.tag_mode == TM_IMPLICIT;
    int tagged = tagged_root || rust_ber_cer_has_tagged_members(expr);
    const char *context_constructor = rust_ber_cer_has_nested_sequence(expr)
                                    ? "new_nested" : "new";
    if(rust_write_method_doc(stream, cer
        ? "Strictly decode one CER SET prefix."
        : "Decode one BER SET prefix.",
        "`input` supplies the prefix; `limits` bounds the complete operation.",
        "Returns the validated record and consumed prefix lengths.",
        cer ? "Returns an error for malformed, noncanonical, or over-limit input."
            : "Returns an error for malformed, truncated, or over-limit input.",
        cer ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
            : "`let decoded = Type::decode_ber(input, &Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let mut context = ::asn1c_runtime::ber::RecordContext::%s(limits);\n"
        "        let (value, consumed) = {\n", suffix, context_constructor) < 0) return -1;
    if(rust_write_set_ber_cer_reader(stream, expr, tagged, tagged_root)
       || rust_write_set_ber_cer_decode_slots(stream, expr)
       || rust_write_set_ber_cer_dispatch(stream, expr, tagged)
       || fputs("            let consumed = reader.finish()?;\n", stream) == EOF
       || rust_write_set_ber_cer_construct_value(stream, expr)
       || fputs("            (value, consumed)\n        };\n", stream) == EOF) return -1;
    if(cer && fputs(
        "        let canonical = value.encode_record_with_rule(\n"
        "            ::asn1c_runtime::ber::RecordEncoding::Cer, &mut context)?;\n"
        "        context.verify_canonical(input, consumed.consumed_bytes,\n"
        "            &canonical.bytes)?;\n", stream) == EOF) return -1;
    return fputs(
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value,\n"
        "            consumed_bits: consumed.consumed_bits,\n"
        "            consumed_bytes: consumed.consumed_bytes,\n"
        "        })\n"
        "    }\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit the Rust data type and selected BER/CER methods for a flat SET.
 * Parameters: stream receives Rust; name is sanitized; expr owns fields;
 * codecs selects already-validated BER/CER methods. Returns zero or -1.
 * Errors: output failure; no runtime errors are thrown during generation.
 * Source: Rust record generator. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: fourth wave. Example: emit a six-tag SET.
 */
static int
rust_write_set(FILE *stream, const char *name, asn1p_expr_t *expr,
               uint64_t codecs) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE) {
            char *nested_name = rust_nested_type_name(name, member);
            int ret = nested_name
                ? rust_write_all_sequences(stream, nested_name, member, 0, codecs) : -1;
            free(nested_name);
            if(ret) return -1;
        } else if(member->expr_type == ASN_BASIC_ENUMERATED) {
            char *enum_name = rust_nested_type_name(name, member);
            int ret = enum_name ? 0 : -1;
            if(ret == 0 && strchr(enum_name, '_')
               && fputs("#[allow(non_camel_case_types)]\n", stream) == EOF) ret = -1;
            if(ret == 0) ret = rust_write_inline_enum(stream, enum_name, member, codecs);
            free(enum_name);
            if(ret) return -1;
        }
    }
    if(fprintf(stream,
        "/// ASN.1 SET record with direct inline fields.\n") < 0) return -1;
    if(strchr(name, '_') && fputs("#[allow(non_camel_case_types)]\n", stream) == EOF)
        return -1;
    if(fprintf(stream,
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s {\n", name) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_field(stream, name, member)) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(rust_write_set_ber_cer(stream, name, expr, codecs)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit a Rust match from each inline enum variant to its ASN.1 numeric value.
 * Parameters: stream receives Rust; parent/member identify the nested enum;
 * value is its Rust expression. Returns zero or -1 on allocation/output error.
 * Original source: X.680 enumeration numbers and X.690 INTEGER content.
 * Version/date: 2026-10-31. Author: asn1c maintainers.
 * History: third-wave BER/CER SEQUENCE support. Example: variant `active(3)`.
 */
static int
rust_write_sequence_ber_cer_enum_match(FILE *stream, const char *parent,
                                       asn1p_expr_t *member, const char *value) {
    asn1p_expr_t *item;
    char *type = rust_nested_type_name(parent, member);
    int tag_class;
    uint32_t tag_number;
    int tagged = !rust_ber_cer_member_tag(member, &tag_class, &tag_number)
              && tag_class == TC_CONTEXT_SPECIFIC;
    int explicit_tag = rust_ber_cer_member_explicit(member);
    (void)tag_number;
    if(!type || fprintf(stream, "            match %s {\n", value) < 0) {
        free(type);
        return -1;
    }
    TQ_FOR(item, &member->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = -1;
        if(variant && explicit_tag) {
            ret = fprintf(stream, "                %s::%s => {\n"
                "                    writer.write_enumerated_explicit(\n"
                "                        ", type, variant);
            if(ret >= 0) ret = rust_write_ber_cer_tag(stream, member);
            if(ret >= 0) ret = fprintf(stream, ",\n"
                "                        %lld,\n"
                "                    )?;\n"
                "                }\n", (long long)item->value->value.v_integer);
        } else if(variant && tagged) {
            ret = fprintf(stream, "                %s::%s => {\n"
                "                    writer.write_enumerated_tagged(\n"
                "                        ", type, variant);
            if(ret >= 0) ret = rust_write_ber_cer_tag(stream, member);
            if(ret >= 0) ret = fprintf(stream, ",\n"
                "                        %lld,\n"
                "                    )?;\n"
                "                }\n", (long long)item->value->value.v_integer);
        } else if(variant) {
            ret = fprintf(stream,
                "                %s::%s => { writer.write_enumerated(%lld)?; }\n",
                type, variant, (long long)item->value->value.v_integer);
        }
        free(variant);
        if(ret < 0) {
            free(type);
            return -1;
        }
    }
    free(type);
    return fputs("            }\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one value match from an ASN.1 ENUMERATED number to its Rust variant.
 * Parameters: stream receives Rust; parent/member identify the nested enum.
 * Returns zero or -1. Errors: output and allocation failure. Original source:
 * X.680 numeric enumeration values. Version/date: 2026-10-31. Responsible:
 * asn1c maintainers. History: third-wave BER/CER records. Example: map 20.
 */
static int
rust_write_sequence_ber_cer_enum_decode(FILE *stream, const char *parent,
                                        asn1p_expr_t *member) {
    asn1p_expr_t *item;
    char *type = rust_nested_type_name(parent, member);
    if(!type || fputs("match reader.read_enumerated()? {\n", stream) == EOF) {
        free(type);
        return -1;
    }
    TQ_FOR(item, &member->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = variant ? fprintf(stream, "                    %lld => %s::%s,\n",
            (long long)item->value->value.v_integer, type, variant) : -1;
        free(variant);
        if(ret < 0) {
            free(type);
            return -1;
        }
    }
    free(type);
    return fputs("                    _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
                 "                        reason: \"unknown ENUMERATED value\",\n"
                 "                    }),\n                }", stream) == EOF ? -1 : 0;
}

/*
 * Emit a BOOLEAN record-writer call for one effective tag.
 * Parameters: stream/value/tag describe generated Rust; flags select API.
 * Returns zero or -1. Source: X.690 BOOLEAN. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: implicit and explicit record fields.
 * Example: emit a context-specific BOOLEAN writer call.
 */
static int
rust_write_ber_cer_boolean(FILE *stream, const char *value,
                           const char *tag, int tagged, int explicit_tag) {
    if(explicit_tag)
        return fprintf(stream, "writer.write_boolean_explicit(%s, %s)?;\n",
                       tag, value) < 0 ? -1 : 0;
    if(tagged)
        return fprintf(stream, "writer.write_boolean_tagged(%s, %s)?;\n",
                       tag, value) < 0 ? -1 : 0;
    return fprintf(stream, "writer.write_boolean(%s)?;\n", value) < 0 ? -1 : 0;
}

/*
 * Emit a NULL record-writer call for one effective tag.
 * Parameters: stream/tag describe generated Rust; flags select API.
 * Returns zero or -1. Source: X.690 NULL. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: implicit and explicit record fields.
 * Example: emit a universal NULL writer call.
 */
static int
rust_write_ber_cer_null(FILE *stream, const char *tag, int tagged, int explicit_tag) {
    if(explicit_tag)
        return fprintf(stream, "writer.write_null_explicit(%s)?;\n", tag) < 0 ? -1 : 0;
    if(tagged)
        return fprintf(stream, "writer.write_null_tagged(%s)?;\n", tag) < 0 ? -1 : 0;
    return fputs("writer.write_null()?;\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit a bounded INTEGER record-writer call for one effective tag.
 * Parameters: stream/member/value/tag describe the field; flags select API.
 * Returns zero or -1. Source: X.690 INTEGER. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: implicit and explicit record fields.
 * Example: emit an INTEGER writer with the schema's inclusive bounds.
 */
static int
rust_write_ber_cer_integer(FILE *stream, asn1p_expr_t *member, const char *value,
                           const char *tag, int tagged, int explicit_tag) {
    int64_t lower, upper;
    char low[64], high[64];
    if(rust_integer_bounds(member, &lower, &upper)
       || rust_format_bound(low, sizeof(low), lower)
       || rust_format_bound(high, sizeof(high), upper)) return -1;
    if(explicit_tag)
        return fprintf(stream, "writer.write_integer_explicit(%s, %s, %s, %s)?;\n",
                       tag, value, low, high) < 0 ? -1 : 0;
    if(tagged)
        return fprintf(stream, "writer.write_integer_tagged(%s, %s, %s, %s)?;\n",
                       tag, value, low, high) < 0 ? -1 : 0;
    return fprintf(stream, "writer.write_integer(%s, %s, %s)?;\n",
                    value, low, high) < 0 ? -1 : 0;
}

/*
 * Emit a bounded OCTET STRING record-writer call for one effective tag.
 * Parameters: stream/member/value/tag describe the field; flags select API.
 * Returns zero or -1. Source: X.690 OCTET STRING. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: implicit and explicit record fields.
 * Example: emit a writer with the schema's inclusive SIZE bounds.
 */
static int
rust_write_ber_cer_octets(FILE *stream, asn1p_expr_t *member, const char *value,
                          const char *tag, int tagged, int explicit_tag) {
    size_t lower, upper;
    if(!rust_fixed_size(member, &lower)) upper = lower;
    else if(rust_bounded_size(member, &lower, &upper)) return -1;
    if(explicit_tag)
        return fprintf(stream,
            "writer.write_octet_string_explicit(%s, %s, %zu, %zu)?;\n",
            tag, value, lower, upper) < 0 ? -1 : 0;
    if(tagged)
        return fprintf(stream,
            "writer.write_octet_string_tagged(%s, %s, %zu, %zu)?;\n",
            tag, value, lower, upper) < 0 ? -1 : 0;
    return fprintf(stream, "writer.write_octet_string(%s, %zu, %zu)?;\n",
                   value, lower, upper) < 0 ? -1 : 0;
}

/*
 * Emit a bounded BIT STRING record-writer call for one effective tag.
 * Parameters: stream/member/value/tag describe the field; flags select API.
 * Returns zero or -1. Source: X.690 BIT STRING. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: implicit and explicit record fields.
 * Example: emit a fixed or bounded BIT STRING writer call.
 */
static int
rust_write_ber_cer_bits(FILE *stream, asn1p_expr_t *member, const char *value,
                        const char *tag, int tagged, int explicit_tag) {
    size_t lower, upper;
    int fixed = !rust_fixed_size(member, &lower);
    if(fixed) upper = lower;
    else if(rust_bounded_size(member, &lower, &upper)) return -1;
    if(fixed) {
        if(explicit_tag)
            return fprintf(stream,
                "writer.write_bit_string_explicit(%s, %s, %zu, %zu, %zu)?;\n",
                tag, value, lower, lower, upper) < 0 ? -1 : 0;
        if(tagged)
            return fprintf(stream,
                "writer.write_bit_string_tagged(%s, %s, %zu, %zu, %zu)?;\n",
                tag, value, lower, lower, upper) < 0 ? -1 : 0;
        return fprintf(stream, "writer.write_bit_string(%s, %zu, %zu, %zu)?;\n",
                       value, lower, lower, upper) < 0 ? -1 : 0;
    }
    if(explicit_tag)
        return fprintf(stream,
            "writer.write_bit_string_explicit(%s, %s.as_bytes(), %s.bit_len(), "
            "%zu, %zu)?;\n", tag, value, value, lower, upper) < 0 ? -1 : 0;
    if(tagged)
        return fprintf(stream,
            "writer.write_bit_string_tagged(%s, %s.as_bytes(), %s.bit_len(), "
            "%zu, %zu)?;\n", tag, value, value, lower, upper) < 0 ? -1 : 0;
    return fprintf(stream,
        "writer.write_bit_string(%s.as_bytes(), %s.bit_len(), %zu, %zu)?;\n",
        value, value, lower, upper) < 0 ? -1 : 0;
}

/*
 * Emit one BER/CER field write for a required or present field.
 * Parameters: stream receives Rust; parent/member/value identify the field.
 * Returns zero or -1. Source: X.690 field encodings. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: direct, implicit, and explicit fields.
 * Example: emit a bounded OCTET STRING writer call.
 */
static int
rust_write_sequence_ber_cer_encode_value(FILE *stream, const char *parent,
                                         asn1p_expr_t *member, const char *value) {
    int tag_class;
    uint32_t tag_number;
    int tagged = !rust_ber_cer_member_tag(member, &tag_class, &tag_number)
              && tag_class == TC_CONTEXT_SPECIFIC;
    int explicit_tag = rust_ber_cer_member_explicit(member);
    char tag_local[48];
    const char *tag_argument = "";
    if(tagged) {
        if(rust_ber_cer_tag_local(member, tag_local, sizeof(tag_local))) return -1;
        tag_argument = tag_local;
    }
    switch(member->expr_type) {
    case ASN_CONSTR_SEQUENCE: {
        char *nested_type = rust_nested_type_name(parent, member);
        const char *constructor = explicit_tag ? "new_explicit" : "new";
        const char *tag_expression = tagged ? tag_local
            : "::asn1c_runtime::ber::Tag::universal(16)";
        int ret;
        if(!nested_type) return -1;
        if(!member->members.tq_head) {
            ret = fprintf(stream,
                "        writer.write_nested_sequence(\n"
                "            ::asn1c_runtime::ber::RecordField::%s(\n"
                "                %s, ::asn1c_runtime::ber::FieldKind::Sequence)?,\n"
                "            |_child_writer| Ok(()))?;\n",
                constructor, tag_expression) < 0 ? -1 : 0;
        } else {
            ret = fprintf(stream,
                "        writer.write_nested_sequence(\n"
                "            ::asn1c_runtime::ber::RecordField::%s(\n"
                "                %s, ::asn1c_runtime::ber::FieldKind::Sequence)?,\n"
                "            |child_writer| %s.encode_record_fields(child_writer))?;\n",
                constructor, tag_expression, value) < 0 ? -1 : 0;
        }
        free(nested_type);
        return ret;
    }
    case ASN_BASIC_BOOLEAN:
        return rust_write_ber_cer_boolean(stream, value, tag_argument, tagged, explicit_tag);
    case ASN_BASIC_NULL:
        return rust_write_ber_cer_null(stream, tag_argument, tagged, explicit_tag);
    case ASN_BASIC_INTEGER:
        return rust_write_ber_cer_integer(stream, member, value, tag_argument,
                                          tagged, explicit_tag);
    case ASN_BASIC_ENUMERATED:
        return rust_write_sequence_ber_cer_enum_match(stream, parent, member, value);
    case ASN_BASIC_OCTET_STRING:
        return rust_write_ber_cer_octets(stream, member, value, tag_argument,
                                         tagged, explicit_tag);
    case ASN_BASIC_BIT_STRING:
        return rust_write_ber_cer_bits(stream, member, value, tag_argument,
                                       tagged, explicit_tag);
    default:
        return -1;
    }
}

/*
 * Emit one field's presence handling and primitive record encoding.
 * Parameters: stream receives Rust; parent/member identify the field; name is
 * sanitized. Returns zero or -1. Original source: X.690 SEQUENCE order.
 * Version/date: 2026-10-31. Responsible: asn1c maintainers. History: direct
 * and optional records. Example: omit an absent optional field.
 */
/*
 * Emit OPTIONAL presence handling for one record field.
 * Parameters: stream/parent/member/name identify the generated field.
 * Returns zero or -1. Source: ASN.1 OPTIONAL. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: direct, implicit, and explicit fields.
 * Example: an absent optional OCTET STRING emits no child.
 */
static int
rust_write_sequence_ber_cer_encode_optional(FILE *stream, const char *parent,
                                            asn1p_expr_t *member, const char *name) {
    char value[192];
    int ret;
    if(member->expr_type == ASN_BASIC_NULL) {
        if(fprintf(stream, "        if self.%s.is_some() {\n            ", name) < 0) return -1;
        ret = rust_write_sequence_ber_cer_encode_value(stream, parent, member, "()");
        if(ret < 0) return -1;
        return fputs("        }\n", stream) == EOF ? -1 : 0;
    }
    if(fprintf(stream, "        if let Some(value) = self.%s.as_ref() {\n            ", name) < 0)
        return -1;
    if(member->expr_type == ASN_BASIC_OCTET_STRING)
        strcpy(value, "value.as_slice()");
    else if(member->expr_type == ASN_BASIC_BIT_STRING)
        strcpy(value, "value");
    else if(member->expr_type == ASN_CONSTR_SEQUENCE)
        strcpy(value, "value");
    else
        strcpy(value, "*value");
    ret = rust_write_sequence_ber_cer_encode_value(stream, parent, member, value);
    if(ret < 0) return -1;
    return fputs("        }\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit default omission and encoding for one record field.
 * Parameters: stream/parent/member/name identify the generated field.
 * Returns zero or -1. Source: ASN.1 DEFAULT. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: BOOLEAN/INTEGER record defaults.
 * Example: emit a default FALSE BOOLEAN only when its value is true.
 */
static int
rust_write_sequence_ber_cer_encode_default(FILE *stream, const char *parent,
                                           asn1p_expr_t *member, const char *name) {
    char literal[64];
    char value[192];
    int written;
    int ret;
    if(rust_sequence_default_literal(member, literal, sizeof(literal))) return -1;
    written = snprintf(value, sizeof(value), "self.%s", name);
    if(written < 0 || (size_t)written >= sizeof(value)) return -1;
    if(member->expr_type == ASN_BASIC_BOOLEAN) {
        const char *condition = !strcmp(literal, "true") ? "!" : "";
        ret = fprintf(stream, "        if %sself.%s {\n            ", condition, name);
    } else {
        ret = fprintf(stream, "        if self.%s != %s {\n            ", name, literal);
    }
    if(ret < 0) return -1;
    ret = rust_write_sequence_ber_cer_encode_value(stream, parent, member, value);
    if(ret < 0) return -1;
    return fputs("        }\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one required record field without presence handling.
 * Parameters: stream/parent/member/name identify the generated field.
 * Returns zero or -1. Source: ASN.1 required components. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: direct, implicit, and explicit fields.
 * Example: borrow an OCTET STRING field for the writer.
 */
static int
rust_write_sequence_ber_cer_encode_required(FILE *stream, const char *parent,
                                            asn1p_expr_t *member, const char *name) {
    char value[192];
    int written;
    if(member->expr_type == ASN_BASIC_OCTET_STRING
       || (member->expr_type == ASN_BASIC_BIT_STRING
           && rust_fixed_size(member, &(size_t){0}) == 0))
        written = snprintf(value, sizeof(value), "&self.%s", name);
    else if(member->expr_type == ASN_BASIC_NULL)
        written = snprintf(value, sizeof(value), "()");
    else
        written = snprintf(value, sizeof(value), "self.%s", name);
    if(written < 0 || (size_t)written >= sizeof(value)) return -1;
    if(fputs("        ", stream) == EOF) return -1;
    return rust_write_sequence_ber_cer_encode_value(stream, parent, member, value);
}

/*
 * Emit one field's presence handling and primitive record encoding.
 * Parameters: stream receives Rust; parent/member identify the field.
 * Returns zero or -1. Source: X.690 SEQUENCE order. Version/date: 2026-10-31.
 * Author: asn1c maintainers. History: direct and implicit record fields.
 * Example: omit an absent OPTIONAL field before writing the next component.
 */
static int
rust_write_sequence_ber_cer_encode_field(FILE *stream, const char *parent,
                                         asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    int ret;
    if(!name) return -1;
    if(member->marker.flags == EM_OPTIONAL)
        ret = rust_write_sequence_ber_cer_encode_optional(stream, parent, member, name);
    else if(member->marker.flags == EM_DEFAULT)
        ret = rust_write_sequence_ber_cer_encode_default(stream, parent, member, name);
    else
        ret = rust_write_sequence_ber_cer_encode_required(stream, parent, member, name);
    free(name);
    return ret < 0 ? -1 : 0;
}

/*
 * Emit one BER/CER decode method with presence and DEFAULT tag handling.
 * Parameters: stream receives Rust; expr owns validated fields; cer selects
 * strict canonical verification. Returns zero or -1. Errors: output errors.
 * Source: X.690 ordered SEQUENCE fields and record runtime. Version/date:
 * 2026-10-31. Author: asn1c maintainers. History: generated record support.
 * Example: decode_ber accepts one prefix and reports consumed bytes.
 */
static int
rust_write_sequence_ber_cer_decode_method(FILE *stream, asn1p_expr_t *expr,
                                          int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *context_constructor = rust_ber_cer_has_nested_sequence(expr)
                                    ? "new_nested" : "new";
    int tagged_root = expr->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && expr->tag.tag_mode == TM_IMPLICIT;
    if(rust_write_method_doc(stream, cer
        ? "Strictly decode one CER SEQUENCE prefix."
        : "Decode one BER SEQUENCE prefix.",
        "`input` supplies the prefix; `limits` bounds the complete operation.",
        "Returns the validated record and consumed prefix lengths.",
        cer ? "Returns an error for malformed, noncanonical, or over-limit input."
            : "Returns an error for malformed, truncated, or over-limit input.",
        cer ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
            : "`let decoded = Type::decode_ber(input, &Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let mut context = ::asn1c_runtime::ber::RecordContext::%s(limits);\n"
        "        let (value, consumed) = {\n", suffix, context_constructor) < 0) return -1;
    if(rust_write_ber_cer_field_descriptors(stream, expr, "            ")) return -1;
    if(tagged_root) {
        if(fprintf(stream,
            "            let mut reader = ::asn1c_runtime::ber::SequenceReader::"
            "new_tagged_root(\n"
            "                input, ::asn1c_runtime::ber::Tag::context_specific("
            "0x%04" PRIx32 "_%04" PRIx32 "),\n"
            "                &__asn1c_expected_fields, &mut context)?;\n"
            "            let value = Self::decode_record_fields(&mut reader)?;\n"
            "            let consumed = reader.finish()?;\n"
            "            (value, consumed)\n"
            "        };\n", (uint32_t)expr->tag.tag_value >> 16,
            (uint32_t)expr->tag.tag_value & UINT32_C(0xffff)) < 0) return -1;
    } else if(fputs(
        "            let mut reader = ::asn1c_runtime::ber::SequenceReader::new_tagged(\n"
        "                input, &__asn1c_expected_fields, &mut context)?;\n"
        "            let value = Self::decode_record_fields(&mut reader)?;\n"
        "            let consumed = reader.finish()?;\n"
        "            (value, consumed)\n"
        "        };\n", stream) == EOF) {
        return -1;
    }
    if(cer) {
        if(fputs(
            "        let canonical = value.encode_record_with_rule(\n"
            "            ::asn1c_runtime::ber::RecordEncoding::Cer, &mut context)?;\n"
            "        context.verify_canonical(input, consumed.consumed_bytes,\n"
            "            &canonical.bytes)?;\n", stream) == EOF) return -1;
    }
    return fputs(
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value,\n"
        "            consumed_bits: consumed.consumed_bits,\n"
        "            consumed_bytes: consumed.consumed_bytes,\n"
        "        })\n"
        "    }\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit a private bounded-child field decoder with no fresh public context.
 * Inputs: stream receives Rust; parent names inline enums; expr owns validated
 * fields. Returns zero or -1. Errors: malformed fields flow from the runtime.
 * Source: shared nested record reader API. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: nested BER/CER. Example: decode child fields.
 */
static int
rust_write_sequence_ber_cer_decode_fields(FILE *stream, const char *parent,
                                          asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(rust_write_method_doc(stream,
        "Decode fields from a reader bounded by the parent record.",
        "`reader` shares the parent's input boundary and operation context.",
        "Returns validated fields after consuming the schema components.",
        "Returns an error for missing, duplicate, unknown, or malformed fields.",
        "`let child = Child::decode_record_fields(child_reader)?;")) return -1;
    if(fputs(
        "    fn decode_record_fields(\n"
        "        reader: &mut ::asn1c_runtime::ber::SequenceReader<'_, '_, '_>) ->\n"
        "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n", stream)
        == EOF) return -1;
    if(expr->members.tq_head
       && rust_write_ber_cer_reader_tag_locals(stream, expr)) return -1;
    if(fprintf(stream, "        let %s__asn1c_next_tag = reader.next_tagged_field()?;\n"
                "        let value = Self {\n",
               expr->members.tq_head ? "mut " : "") < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_ber_cer_decode_field(stream, parent, member, 1))
            return -1;
    }
    if(fputs(
        "        };\n"
        "        if __asn1c_next_tag.is_some() {\n"
        "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unexpected trailing SEQUENCE field\",\n"
        "            });\n"
        "        }\n"
        "        Ok(value)\n"
        "    }\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit a type-specific decode expression for a direct SEQUENCE field.
 * Parameters: stream receives Rust; parent identifies inline enums; member is
 * the field; indent is the generated line prefix. Returns zero or -1.
 * Errors: output failure; runtime validates malformed wire data. Source: X.690.
 * Version/date: 2026-10-31. Author: asn1c maintainers. History: third wave.
 * Example: decode bounded OCTET STRING into its value field.
 */
/*
 * Emit the bounded INTEGER read expression for a record field.
 * Parameters: stream/member/indent identify generated output and schema.
 * Returns zero or -1. Source: X.690 INTEGER. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: direct and implicit record fields.
 * Example: apply the ASN.1 inclusive range to a decoded INTEGER.
 */
static int
rust_write_ber_cer_decode_integer(FILE *stream, asn1p_expr_t *member,
                                 const char *indent) {
    int64_t lower, upper;
    char low[64], high[64];
    if(rust_integer_bounds(member, &lower, &upper)
       || rust_format_bound(low, sizeof(low), lower)
       || rust_format_bound(high, sizeof(high), upper)) return -1;
    return fprintf(stream, "%slet value = reader.read_integer(%s, %s)?;\n",
                   indent, low, high) < 0 ? -1 : 0;
}

/*
 * Emit the bounded OCTET STRING read expression for a record field.
 * Parameters: stream/member/indent identify generated output and schema.
 * Returns zero or -1. Source: X.690 OCTET STRING. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: direct and implicit record fields.
 * Example: apply inclusive SIZE bounds while decoding an OCTET STRING.
 */
static int
rust_write_ber_cer_decode_octets(FILE *stream, asn1p_expr_t *member,
                                 const char *indent) {
    size_t lower, upper;
    if(!rust_fixed_size(member, &lower)) upper = lower;
    else if(rust_bounded_size(member, &lower, &upper)) return -1;
    return fprintf(stream, "%slet value = reader.read_octet_string(%zu, %zu)?;\n",
                   indent, lower, upper) < 0 ? -1 : 0;
}

/*
 * Emit the bounded BIT STRING read and fixed-length validation.
 * Parameters: stream/member/indent identify generated output and schema.
 * Returns zero or -1. Source: X.690 BIT STRING. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: direct and implicit record fields.
 * Example: require the schema's exact bit count before moving its bytes.
 */
static int
rust_write_ber_cer_decode_bits(FILE *stream, asn1p_expr_t *member,
                               const char *indent) {
    size_t lower, upper;
    int fixed = !rust_fixed_size(member, &lower);
    if(fixed) upper = lower;
    else if(rust_bounded_size(member, &lower, &upper)) return -1;
    if(fprintf(stream, "%slet value = reader.read_bit_string(%zu, %zu)?;\n",
                indent, lower, upper) < 0) return -1;
    if(fixed && fprintf(stream,
        "%sif value.bit_len() != %zu {\n"
        "%s    return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "%s        reason: \"fixed BIT STRING length mismatch\",\n"
        "%s    });\n%s}\n%slet value = value.into_bytes();\n",
        indent, lower, indent, indent, indent, indent, indent) < 0) return -1;
    return 0;
}

/*
 * Emit a type-specific decode expression for a direct SEQUENCE field.
 * Parameters: stream receives Rust; parent identifies inline enums; member is
 * the field; indent is the generated line prefix. Returns zero or -1.
 * Errors: output failure; runtime validates malformed wire data. Source: X.690.
 * Version/date: 2026-10-31. Author: asn1c maintainers. History: record fields.
 * Example: decode bounded OCTET STRING into its value field.
 */
static int
rust_write_sequence_ber_cer_decode_value(FILE *stream, const char *parent,
                                         asn1p_expr_t *member, const char *indent) {
    switch(member->expr_type) {
    case ASN_CONSTR_SEQUENCE:
        return rust_write_nested_ber_cer_decode_value(stream, parent, member, indent);
    case ASN_BASIC_BOOLEAN:
        return fprintf(stream, "%slet value = reader.read_boolean()?;\n", indent) < 0
            ? -1 : 0;
    case ASN_BASIC_NULL:
        return fprintf(stream, "%sreader.read_null()?;\n", indent) < 0 ? -1 : 0;
    case ASN_BASIC_INTEGER:
        return rust_write_ber_cer_decode_integer(stream, member, indent);
    case ASN_BASIC_ENUMERATED:
        if(fprintf(stream, "%slet value = ", indent) < 0
           || rust_write_sequence_ber_cer_enum_decode(stream, parent, member)
           || fputs(";\n", stream) == EOF) return -1;
        return 0;
    case ASN_BASIC_OCTET_STRING:
        return rust_write_ber_cer_decode_octets(stream, member, indent);
    case ASN_BASIC_BIT_STRING:
        return rust_write_ber_cer_decode_bits(stream, member, indent);
    default:
        return -1;
    }
}

/*
 * Emit one child decoder call with descriptors for its direct components.
 * Inputs: stream/parent/member/indent identify generated Rust and the child
 * schema. Returns zero or -1. Errors: descriptor or output failures. Source:
 * shared bounded reader callback API. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: nested BER/CER. Example: decode Child.
 */
static int
rust_write_nested_ber_cer_decode_value(FILE *stream, const char *parent,
                                       asn1p_expr_t *member,
                                       const char *indent) {
    asn1p_expr_t *child;
    char *nested_type = rust_nested_type_name(parent, member);
    size_t indent_length = strlen(indent);
    char child_indent[32];
    int written;
    if(!nested_type || indent_length + 4 >= sizeof(child_indent)) {
        free(nested_type);
        return -1;
    }
    memcpy(child_indent, indent, indent_length);
    memcpy(child_indent + indent_length, "    ", 5);
    written = fprintf(stream, "%slet __asn1c_child_fields = [\n", indent);
    if(written < 0) {
        free(nested_type);
        return -1;
    }
    TQ_FOR(child, &member->members, next) {
        if(rust_write_ber_cer_field_descriptor(stream, child, child_indent)) {
            free(nested_type);
            return -1;
        }
    }
    written = fprintf(stream,
        "%s];\n%slet value = reader.read_nested_sequence(\n"
        "%s    &__asn1c_child_fields,\n"
        "%s    %s::decode_record_fields,\n"
        "%s)?;\n",
        indent, indent, indent, indent, nested_type, indent);
    free(nested_type);
    return written < 0 ? -1 : 0;
}

/*
 * Emit one field's tag dispatch, decoded value, and presence behavior.
 * Parameters: stream receives Rust; parent/member identify the field.
 * Returns zero or -1. Errors: output failure; runtime validates malformed
 * data. Original source: X.690 SEQUENCE component dispatch. Version/date:
 * 2026-10-31. Responsible: asn1c maintainers. History: direct-field records.
 * Example: an absent OPTIONAL OCTET STRING yields None.
 */
static int
rust_write_sequence_ber_cer_decode_field(FILE *stream, const char *parent,
                                         asn1p_expr_t *member, int tagged) {
    char *name = rust_identifier(member->Identifier, 1);
    char tag_local[48];
    char tag_value[64];
    int tag_class;
    uint32_t tag_number;
    const int optional = member->marker.flags == EM_OPTIONAL;
    const int is_default = member->marker.flags == EM_DEFAULT;
    int ret;
    if(!name) return -1;
    if(rust_ber_cer_member_tag(member, &tag_class, &tag_number)) {
        free(name);
        return -1;
    }
    if(tagged) {
        if(rust_ber_cer_tag_local(member, tag_local, sizeof(tag_local))) {
            free(name);
            return -1;
        }
        snprintf(tag_value, sizeof(tag_value), "Some(%s)", tag_local);
    } else {
        snprintf(tag_value, sizeof(tag_value), "Some(%u)", tag_number);
    }
    ret = fprintf(stream, "                %s: ", name);
    free(name);
    if(ret < 0) return -1;
    if(optional || is_default) {
        if(fprintf(stream, "if __asn1c_next_tag == %s {\n", tag_value) < 0) return -1;
        if(rust_write_sequence_ber_cer_decode_value(stream, parent, member,
                                                    "                    ")) return -1;
        if(fprintf(stream, "                    __asn1c_next_tag = reader.%s()?;\n",
                   tagged ? "next_tagged_field" : "next_field") < 0)
            return -1;
        if(optional) {
            ret = member->expr_type == ASN_BASIC_NULL
                ? fputs("                    Some(())\n                } else { None },\n", stream)
                : fputs("                    Some(value)\n                } else { None },\n", stream);
        } else {
            char literal[64];
            if(rust_sequence_default_literal(member, literal, sizeof(literal))) return -1;
            ret = fprintf(stream, "                    value\n                } else { %s },\n", literal);
        }
    } else {
        if(fprintf(stream,
            "{\n                    if __asn1c_next_tag != %s {\n"
            "                        return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
            "                            reason: \"missing required SEQUENCE field\",\n"
            "                        });\n                    }\n", tag_value) < 0) return -1;
        if(rust_write_sequence_ber_cer_decode_value(stream, parent, member,
                                                    "                    ")) return -1;
        if(fprintf(stream, "                    __asn1c_next_tag = reader.%s()?;\n",
                   tagged ? "next_tagged_field" : "next_field") < 0)
            return -1;
        ret = member->expr_type == ASN_BASIC_NULL
            ? fputs("                },\n", stream)
            : fputs("                    value\n                },\n", stream);
    }
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit one CBOR map entry from a validated direct SEQUENCE field.
 * Source: C SEQUENCE CBOR member-name mapping. Version/date: 2026-10-30.
 * Inputs: stream receives Rust; member supplies name, type and OPTIONAL flag.
 * Returns zero or -1 on output error. Errors: unsupported field shapes fail.
 * Author: asn1c maintainers. History: Rust constructed CBOR slice.
 * Example: an absent OPTIONAL BOOLEAN emits no map pair.
 */
static int
rust_write_sequence_cbor_encode_field(FILE *stream, asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    const char *value = member->marker.flags == EM_OPTIONAL ? "value" : NULL;
    char expression[256];
    int ret;
    if(!name) return -1;
    if(member->marker.flags == EM_OPTIONAL
       && fprintf(stream, "        if let Some(value) = &self.%s {\n", name) < 0) {
        free(name);
        return -1;
    }
    if(!value) {
        int written = snprintf(expression, sizeof(expression), "self.%s", name);
        if(written < 0 || (size_t)written >= sizeof(expression)) {
            free(name);
            return -1;
        }
        value = expression;
    }
    if(member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fprintf(stream, "            entries.push((\"%s\", ::asn1c_runtime::encode_boolean_cbor("
                      "%s%s, limits)?));\n", member->Identifier,
                      member->marker.flags == EM_OPTIONAL ? "*" : "", value);
    else if(member->expr_type == ASN_BASIC_NULL)
        ret = fprintf(stream, "            entries.push((\"%s\", "
                      "::asn1c_runtime::encode_null_cbor(limits)?));\n", member->Identifier);
    else if(member->expr_type == ASN_BASIC_INTEGER) {
        int64_t lower, upper;
        char low[64], high[64];
        if(rust_integer_bounds(member, &lower, &upper)
           || rust_format_bound(low, sizeof(low), lower)
           || rust_format_bound(high, sizeof(high), upper)) ret = -1;
        else ret = fprintf(stream, "            entries.push((\"%s\", "
                           "::asn1c_runtime::encode_integer_cbor(%s%s, %s, %s, limits)?));\n",
                           member->Identifier, member->marker.flags == EM_OPTIONAL ? "*" : "",
                           value, low, high);
    } else if(member->expr_type == ASN_TYPE_ANY)
        ret = fprintf(stream, "            entries.push((\"%s\", "
                      "::asn1c_runtime::cbor::encode_any_cbor(%s.as_slice(), limits)?));\n",
                      member->Identifier, value);
    else if(member->expr_type == ASN_BASIC_OCTET_STRING
            || member->expr_type == ASN_BASIC_BIT_STRING) {
        size_t lower, upper;
        int fixed = !rust_fixed_size(member, &lower);
        if(fixed) upper = lower;
        else if(rust_bounded_size(member, &lower, &upper)) {
            free(name);
            return -1;
        }
        if(member->expr_type == ASN_BASIC_OCTET_STRING)
            ret = fprintf(stream,
                "            entries.push((\"%s\", ::asn1c_runtime::cbor::"
                "encode_octet_string_cbor(%s.as_slice(), %zu, %zu, limits)?));\n",
                member->Identifier, value, lower, upper);
        else if(fixed)
            ret = fprintf(stream,
                "            entries.push((\"%s\", ::asn1c_runtime::cbor::"
                "encode_bit_string_cbor(%s.as_slice(), %zu, %zu, %zu, limits)?));\n",
                member->Identifier, value, lower, lower, upper);
        else ret = fprintf(stream,
                "            entries.push((\"%s\", ::asn1c_runtime::cbor::"
                "encode_bit_string_cbor(%s.as_bytes(), %s.bit_len(), %zu, %zu, limits)?));\n",
                member->Identifier, value, value, lower, upper);
    }
    else ret = -1;
    if(ret >= 0 && member->marker.flags == EM_OPTIONAL)
        ret = fputs("        }\n", stream) == EOF ? -1 : 0;
    free(name);
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit one CBOR map decode arm with full-value validation.
 * Source: C SEQUENCE CBOR text-key dispatch. Version/date: 2026-10-30.
 * Inputs: stream receives Rust; member supplies name and primitive codec.
 * Returns zero or -1 on output error. Errors: unsupported field shape fails.
 * Author: asn1c maintainers. History: Rust constructed CBOR slice.
 * Example: a duplicate key fails before overwriting the first value.
 */
static int
rust_write_sequence_cbor_decode_field(FILE *stream, asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    int ret;
    if(!name) return -1;
    ret = fprintf(stream, "                b\"%s\" => {\n", member->Identifier);
    if(ret >= 0 && member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fputs("                    let item = ::asn1c_runtime::decode_boolean_cbor(entry.value, limits)?;\n",
                    stream) == EOF ? -1 : 0;
    else if(ret >= 0 && member->expr_type == ASN_BASIC_NULL)
        ret = fputs("                    let item = ::asn1c_runtime::decode_null_cbor(entry.value, limits)?;\n",
                    stream) == EOF ? -1 : 0;
    else if(ret >= 0 && member->expr_type == ASN_BASIC_INTEGER) {
        int64_t lower, upper;
        char low[64], high[64];
        if(rust_integer_bounds(member, &lower, &upper)
           || rust_format_bound(low, sizeof(low), lower)
           || rust_format_bound(high, sizeof(high), upper)) ret = -1;
        else ret = fprintf(stream,
            "                    let item = ::asn1c_runtime::decode_integer_cbor("
            "entry.value, %s, %s, limits)?;\n", low, high);
    } else if(ret >= 0 && member->expr_type == ASN_TYPE_ANY)
        ret = fputs("                    let item = ::asn1c_runtime::cbor::decode_any_cbor(entry.value, limits)?;\n",
                    stream) == EOF ? -1 : 0;
    else if(ret >= 0 && (member->expr_type == ASN_BASIC_OCTET_STRING
                         || member->expr_type == ASN_BASIC_BIT_STRING)) {
        size_t lower, upper;
        if(!rust_fixed_size(member, &lower)) upper = lower;
        else if(rust_bounded_size(member, &lower, &upper)) ret = -1;
        if(ret >= 0) ret = fprintf(stream,
            "                    let item = ::asn1c_runtime::cbor::decode_%s_cbor("
            "entry.value, %zu, %zu, limits)?;\n",
            member->expr_type == ASN_BASIC_OCTET_STRING ? "octet_string" : "bit_string",
            lower, upper);
    }
    if(ret >= 0 && member->expr_type == ASN_BASIC_NULL)
        ret = fprintf(stream,
            "                    let _: () = ::asn1c_runtime::cbor::complete_value("
            "item, entry.value.len())?;\n"
            "                    __asn1c_%s = Some(());\n                }\n", name);
    else if(ret >= 0) ret = fprintf(stream,
        "                    __asn1c_%s = Some(::asn1c_runtime::cbor::complete_value("
        "item, entry.value.len())?%s);\n                }\n", name,
        member->expr_type == ASN_BASIC_BIT_STRING
          && !rust_fixed_size(member, &(size_t){0}) ? ".into_bytes()" : "");
    free(name);
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit CBOR map encoder and decoder methods for one flat SEQUENCE.
 * Source: repository C CBOR SEQUENCE mapping. Version/date: 2026-10-30.
 * Inputs: stream receives Rust; expr owns checked members. Returns zero or -1.
 * Errors: output failure or invalid default literal. Author: maintainers.
 * History: added direct primitive, OPTIONAL and ANY CBOR record support.
 * Example: encode a record as a definite map with declaration-order keys.
 */
static int
rust_write_sequence_cbor(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    size_t count = 0;
    TQ_FOR(member, &expr->members, next) count++;
    if(rust_write_method_doc(stream, "Encode this SEQUENCE as a CBOR text-key map.",
        "`self` supplies fields; `limits` bounds the whole map.",
        "Returns declaration-order map bytes.",
        "Returns an error for invalid fields, allocation, or resource exhaustion.",
        "`let bytes = value.encode_cbor(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_cbor(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let mut entries = ::std::vec::Vec::new();\n"
        "        entries.try_reserve_exact(%zu).map_err(|_| "
        "::asn1c_runtime::Error::AllocationFailed { requested_bytes: %zu })?;\n",
        count, count) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_cbor_encode_field(stream, member)) return -1;
    }
    if(fputs("        ::asn1c_runtime::cbor::encode_map(&entries, limits)\n    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream, "Decode one CBOR SEQUENCE map prefix.",
        "`input` supplies encoded bytes; `limits` bounds the complete map.",
        "Returns validated fields and prefix consumption.",
        "Returns an error for malformed, duplicate, or missing fields and resource exhaustion.",
        "`let value = Type::decode_cbor(input, &Default::default())?;")) return -1;
    if(fputs(
        "    pub fn decode_cbor(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::cbor::decode_map(input, limits)?;\n"
        "        let consumed_bits = decoded.consumed_bits;\n"
        "        let consumed_bytes = decoded.consumed_bytes;\n", stream) == EOF) return -1;
    TQ_FOR(member, &expr->members, next) {
        char *name = rust_identifier(member->Identifier, 1);
        const char *type = member->expr_type == ASN_BASIC_BOOLEAN ? "bool"
                           : member->expr_type == ASN_BASIC_NULL ? "()"
                           : member->expr_type == ASN_BASIC_INTEGER ? "i64"
                           : member->expr_type == ASN_BASIC_BIT_STRING
                             && rust_fixed_size(member, &(size_t){0})
                             ? "::asn1c_runtime::BitStringValue"
                           : "::std::vec::Vec<u8>";
        int ret = name ? fprintf(stream, "        let mut __asn1c_%s: Option<%s> = None;\n", name, type) : -1;
        free(name);
        if(ret < 0) return -1;
    }
    if(count) {
        if(fputs("        for entry in decoded.value {\n            match entry.key {\n", stream) == EOF) return -1;
        TQ_FOR(member, &expr->members, next) {
            if(rust_write_sequence_cbor_decode_field(stream, member)) return -1;
        }
        if(fputs("                _ => {}\n            }\n        }\n", stream) == EOF) return -1;
    } else if(fputs("        let _ = decoded.value;\n", stream) == EOF) return -1;
    if(fputs("        let value = Self {\n", stream) == EOF) return -1;
    TQ_FOR(member, &expr->members, next) {
        char *name = rust_identifier(member->Identifier, 1);
        int ret = -1;
        if(!name) return -1;
        if(member->marker.flags == EM_OPTIONAL)
            ret = fprintf(stream, "            %s: __asn1c_%s,\n", name, name);
        else if(member->marker.flags == EM_DEFAULT) {
            char literal[64];
            if(!rust_sequence_default_literal(member, literal, sizeof(literal)))
                ret = fprintf(stream, "            %s: __asn1c_%s.unwrap_or(%s),\n",
                              name, name, literal);
        } else ret = fprintf(stream,
            "            %s: __asn1c_%s.ok_or(::asn1c_runtime::Error::InvalidEncoding {\n"
            "                reason: \"missing required CBOR SEQUENCE field\",\n"
            "            })?,\n", name, name);
        free(name);
        if(ret < 0) return -1;
    }
    return fputs("        };\n        Ok(::asn1c_runtime::Decoded {\n"
                 "            value, consumed_bits, consumed_bytes,\n"
                 "        })\n    }\n", stream) == EOF ? -1 : 0;
}

/*
 * Purpose: emit one typed CHOICE alternative encoder arm.
 * Source: C one-pair CBOR CHOICE map. Version/date: 2026-10-30.
 * Inputs: stream receives Rust; item is one validated direct alternative.
 * Returns zero or -1 on output failure. Errors: unsupported item fails.
 * Author: maintainers. History: bounded CBOR CHOICE generation.
 * Example: a BOOLEAN choice maps to one named CBOR pair.
 */
static int
rust_write_cbor_choice_encode_arm(FILE *stream, asn1p_expr_t *item) {
    char *variant = rust_enum_variant(item->Identifier);
    int ret = -1;
    if(!variant) return -1;
    if(item->expr_type == ASN_BASIC_BOOLEAN)
        ret = fprintf(stream,
            "            Self::%s(value) => (\"%s\", "
            "::asn1c_runtime::encode_boolean_cbor(*value, limits)?),\n",
            variant, item->Identifier);
    else if(item->expr_type == ASN_BASIC_NULL)
        ret = fprintf(stream,
            "            Self::%s => (\"%s\", ::asn1c_runtime::encode_null_cbor(limits)?),\n",
            variant, item->Identifier);
    else if(item->expr_type == ASN_BASIC_INTEGER) {
        int64_t lower, upper;
        char low[64], high[64];
        if(!rust_integer_bounds(item, &lower, &upper)
           && !rust_format_bound(low, sizeof(low), lower)
           && !rust_format_bound(high, sizeof(high), upper))
            ret = fprintf(stream,
                "            Self::%s(value) => (\"%s\", "
                "::asn1c_runtime::encode_integer_cbor(*value, %s, %s, limits)?),\n",
                variant, item->Identifier, low, high);
    } else if(item->expr_type == ASN_TYPE_ANY)
        ret = fprintf(stream,
            "            Self::%s(value) => (\"%s\", "
            "::asn1c_runtime::cbor::encode_any_cbor(value, limits)?),\n",
            variant, item->Identifier);
    free(variant);
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit one typed CHOICE alternative decoder arm.
 * Source: C one-pair CBOR CHOICE map. Version/date: 2026-10-30.
 * Inputs: stream receives Rust; item is one validated direct alternative.
 * Returns zero or -1 on output failure. Errors: unsupported item fails.
 * Author: maintainers. History: bounded CBOR CHOICE generation.
 * Example: unknown names fail without selecting an alternative.
 */
static int
rust_write_cbor_choice_decode_arm(FILE *stream, asn1p_expr_t *item) {
    char *variant = rust_enum_variant(item->Identifier);
    int ret = -1;
    if(!variant) return -1;
    if(item->expr_type == ASN_BASIC_BOOLEAN)
        ret = fprintf(stream,
            "            b\"%s\" => Self::%s(::asn1c_runtime::cbor::complete_value(\n"
            "                ::asn1c_runtime::decode_boolean_cbor(entry.value, limits)?, "
            "entry.value.len())?),\n", item->Identifier, variant);
    else if(item->expr_type == ASN_BASIC_NULL)
        ret = fprintf(stream,
            "            b\"%s\" => {\n"
            "                let _: () = ::asn1c_runtime::cbor::complete_value(\n"
            "                    ::asn1c_runtime::decode_null_cbor(entry.value, limits)?, "
            "entry.value.len())?;\n"
            "                Self::%s\n            },\n", item->Identifier, variant);
    else if(item->expr_type == ASN_BASIC_INTEGER) {
        int64_t lower, upper;
        char low[64], high[64];
        if(!rust_integer_bounds(item, &lower, &upper)
           && !rust_format_bound(low, sizeof(low), lower)
           && !rust_format_bound(high, sizeof(high), upper))
            ret = fprintf(stream,
                "            b\"%s\" => Self::%s(::asn1c_runtime::cbor::complete_value(\n"
                "                ::asn1c_runtime::decode_integer_cbor("
                "entry.value, %s, %s, limits)?, entry.value.len())?),\n",
                item->Identifier, variant, low, high);
    } else if(item->expr_type == ASN_TYPE_ANY)
        ret = fprintf(stream,
            "            b\"%s\" => Self::%s(::asn1c_runtime::cbor::complete_value(\n"
            "                ::asn1c_runtime::cbor::decode_any_cbor(entry.value, limits)?, "
            "entry.value.len())?),\n", item->Identifier, variant);
    free(variant);
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit a typed direct-alternative CHOICE and its CBOR map methods.
 * Source: C CHOICE CBOR one-entry map. Version/date: 2026-10-30.
 * Inputs: stream receives Rust; name is type; expr owns checked alternatives.
 * Returns zero or -1 on output failure. Errors: unsupported item or write.
 * Author: maintainers. History: bounded CHOICE CBOR slice.
 * Example: `Choice::Flag(true)` emits `{ "flag": true }` in CBOR mapping.
 */
static int
rust_write_cbor_choice(FILE *stream, const char *name, asn1p_expr_t *expr) {
    asn1p_expr_t *item;
    if(fprintf(stream,
        "/// ASN.1 CHOICE with direct CBOR alternatives.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub enum %s {\n", name) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        const char *type = item->expr_type == ASN_BASIC_BOOLEAN ? "bool"
                           : item->expr_type == ASN_BASIC_INTEGER ? "i64"
                           : "::std::vec::Vec<u8>";
        int ret = variant ? (item->expr_type == ASN_BASIC_NULL
            ? fprintf(stream, "    /// ASN.1 %s alternative.\n    %s,\n", item->Identifier, variant)
            : fprintf(stream, "    /// ASN.1 %s alternative.\n    %s(%s),\n",
                      item->Identifier, variant, type)) : -1;
        free(variant);
        if(ret < 0) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(rust_write_method_doc(stream, "Encode this CHOICE as a one-pair CBOR map.",
        "`self` selects one alternative; `limits` bounds resources.",
        "Returns one named encoded alternative.",
        "Returns an error for invalid value, allocation, or exhausted limits.",
        "`let encoded = value.encode_cbor(&Default::default())?;")) return -1;
    if(fputs(
        "    pub fn encode_cbor(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let entry = match self {\n", stream) == EOF) return -1;
    TQ_FOR(item, &expr->members, next) {
        if(rust_write_cbor_choice_encode_arm(stream, item)) return -1;
    }
    if(fputs("        };\n        ::asn1c_runtime::cbor::encode_map(&[entry], limits)\n    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream, "Decode one CBOR CHOICE map prefix.",
        "`input` is one encoded prefix; `limits` bounds resources.",
        "Returns the selected value and prefix consumption.",
        "Returns an error for unknown/multiple alternatives, malformed values, or limits.",
        "`let decoded = Type::decode_cbor(input, &Default::default())?;")) return -1;
    if(fputs(
        "    pub fn decode_cbor(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::cbor::decode_map(input, limits)?;\n"
        "        if decoded.value.len() != 1 {\n"
        "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"CBOR CHOICE requires one map entry\",\n"
        "            });\n        }\n"
        "        let entry = &decoded.value[0];\n"
        "        let value = match entry.key {\n", stream) == EOF) return -1;
    TQ_FOR(item, &expr->members, next) {
        if(rust_write_cbor_choice_decode_arm(stream, item)) return -1;
    }
    return fputs(
        "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unknown CBOR CHOICE alternative\",\n"
        "            }),\n"
        "        };\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value, consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n    }\n}\n\n", stream) == EOF ? -1 : 0;
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
                         int top_level, uint64_t codecs) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        char *nested_name;
        if(member->expr_type != ASN_CONSTR_SEQUENCE
           && member->expr_type != ASN_BASIC_ENUMERATED) continue;
        nested_name = rust_nested_type_name(name, member);
        if(!nested_name) return -1;
        if((member->expr_type == ASN_CONSTR_SEQUENCE
            ? rust_write_all_sequences(stream, nested_name, member, 0, codecs)
            : rust_write_inline_enum(stream, nested_name, member, codecs))) {
            free(nested_name);
            return -1;
        }
        free(nested_name);
    }
    return rust_write_sequence(stream, name, expr, top_level, codecs);
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
    char *nested_type = (member->expr_type == ASN_CONSTR_SEQUENCE
                         || member->expr_type == ASN_BASIC_ENUMERATED)
        ? rust_nested_type_name(parent, member) : NULL;
    asn1p_expr_t *contained = rust_containing_node(member->combined_constraints, 0)
        ? rust_contained_primitive(member->module, member) : NULL;
    const char *type = contained ? (contained->expr_type == ASN_BASIC_BOOLEAN ? "bool" : "i64")
                       : nested_type ? nested_type
                       : member->expr_type == ASN_BASIC_BOOLEAN ? "bool"
                       : member->expr_type == ASN_BASIC_NULL ? "()"
                       : member->expr_type == ASN_BASIC_INTEGER ? "i64"
                       : member->expr_type == ASN_BASIC_BIT_STRING
                         && rust_fixed_size(member, &(size_t){0}) == 0
                         ? "::std::vec::Vec<u8>"
                       : member->expr_type == ASN_BASIC_BIT_STRING
                         ? "::asn1c_runtime::BitStringValue"
                       : "::std::vec::Vec<u8>";
    int ret = -1;
    if(name) {
        if((member->expr_type == ASN_CONSTR_SEQUENCE
            || member->expr_type == ASN_BASIC_ENUMERATED) && !nested_type) {
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
    if(member->expr_type == ASN_CONSTR_SEQUENCE && !member->members.tq_head) {
        ret = 0;
    } else if(member->expr_type == ASN_CONSTR_SEQUENCE
              || member->expr_type == ASN_BASIC_ENUMERATED) {
        if(member->marker.flags == EM_OPTIONAL) {
            ret = fprintf(stream,
                "        if let Some(value) = self.%s.as_ref() {\n"
                "            value.encode_uper_fields(writer)?;\n"
                "        }\n", name);
        } else {
            ret = fprintf(stream,
                "        self.%s.encode_uper_fields(writer)?;\n", name);
        }
    } else if(rust_containing_node(member->combined_constraints, 0)) {
        asn1p_expr_t *inner = rust_contained_primitive(member->module, member);
        int64_t lower = 0, upper = 1;
        char low[64], high[64];
        int is_boolean = inner && inner->expr_type == ASN_BASIC_BOOLEAN;
        if(inner && (is_boolean || !rust_integer_bounds(inner, &lower, &upper))
           && !rust_format_bound(low, sizeof(low), lower) && !rust_format_bound(high, sizeof(high), upper)) {
            const char *octets = member->expr_type == ASN_BASIC_OCTET_STRING ? "true" : "false";
            const char *cast = is_boolean ? "i64::from(" : "";
            const char *close = is_boolean ? ")" : "";
            if(member->marker.flags == EM_OPTIONAL)
                ret = fprintf(stream, "        if let Some(value) = self.%s.as_ref() {\n"
                    "            ::asn1c_runtime::uper_cursor::write_containing_uper(\n"
                    "                writer, %s*value%s, %s, %s, %s)?;\n"
                    "        }\n", name, cast, close, low, high, octets);
            else ret = fprintf(stream,
                "        ::asn1c_runtime::uper_cursor::write_containing_uper(writer, %sself.%s%s, %s, %s, %s)?;\n",
                cast, name, close, low, high, octets);
        }
    } else if(member->expr_type == ASN_TYPE_ANY) {
        ret = member->marker.flags == EM_OPTIONAL
            ? fprintf(stream, "        if let Some(value) = self.%s.as_ref() {\n"
                "            ::asn1c_runtime::uper_cursor::write_any_uper(writer, value)?;\n"
                "        }\n", name)
            : fprintf(stream, "        ::asn1c_runtime::uper_cursor::write_any_uper(writer, &self.%s)?;\n", name);
    } else if(member->marker.flags == EM_OPTIONAL) {
        ret = rust_write_sequence_encode_optional(stream, member, name);
    } else if(member->marker.flags == EM_DEFAULT) {
        ret = rust_write_sequence_encode_default(stream, member, name);
    } else if(member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fprintf(stream, "        writer.write_boolean(self.%s)?;\n", name);
    else if(member->expr_type == ASN_BASIC_NULL)
        ret = fputs("        writer.write_null()?;\n", stream);
    else if(member->expr_type == ASN_BASIC_OCTET_STRING
            || member->expr_type == ASN_BASIC_BIT_STRING)
        ret = rust_write_sequence_encode_string_field(stream, member, name);
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
 * Emit the fixed or bounded string cursor call for one required field.
 * Parameters: stream receives Rust; member supplies validated constraints;
 * name is the sanitized field name. Returns zero or -1; no exception.
 * Original source: Rust UPER SEQUENCE string generation. Version/date: 0.6.0,
 * 2026-10-30. Responsible party: asn1c maintainers. History: shared string
 * emitter. Example: rust_write_sequence_encode_string_field(out, field, "bits").
 */
static int
rust_write_sequence_encode_string_field(FILE *stream, asn1p_expr_t *member,
                                        const char *name) {
    size_t length, lower, upper;
    const int octets = member->expr_type == ASN_BASIC_OCTET_STRING;
    if(!rust_fixed_size(member, &length))
        return fprintf(stream, "        writer.write_%s(&self.%s, %zu)?;\n",
                       octets ? "octets" : "bit_string", name, length) < 0 ? -1 : 0;
    if(rust_bounded_size(member, &lower, &upper)) return -1;
    return fprintf(stream,
        "        writer.write_bounded_%s(&self.%s, %zu, %zu)?;\n",
        octets ? "octets" : "bit_string", name, lower, upper) < 0 ? -1 : 0;
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
    if(member->expr_type == ASN_BASIC_OCTET_STRING) {
        size_t length, lower, upper;
        if(!rust_fixed_size(member, &length))
            return fprintf(stream,
                "        if let Some(value) = self.%s.as_ref() {\n"
                "            writer.write_octets(value, %zu)?;\n"
                "        }\n", name, length) < 0 ? -1 : 0;
        if(rust_bounded_size(member, &lower, &upper)) return -1;
        return fprintf(stream,
            "        if let Some(value) = self.%s.as_ref() {\n"
            "            writer.write_bounded_octets(value, %zu, %zu)?;\n"
            "        }\n", name, lower, upper) < 0 ? -1 : 0;
    }
    {
        size_t length, lower, upper;
        if(!rust_fixed_size(member, &length))
            return fprintf(stream,
                "        if let Some(value) = self.%s.as_ref() {\n"
                "            writer.write_bit_string(value, %zu)?;\n"
                "        }\n", name, length) < 0 ? -1 : 0;
        if(rust_bounded_size(member, &lower, &upper)) return -1;
        return fprintf(stream,
            "        if let Some(value) = self.%s.as_ref() {\n"
            "            writer.write_bounded_bit_string(value, %zu, %zu)?;\n"
            "        }\n", name, lower, upper) < 0 ? -1 : 0;
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
    char *nested_type = (member->expr_type == ASN_CONSTR_SEQUENCE
                         || member->expr_type == ASN_BASIC_ENUMERATED)
        ? rust_nested_type_name(parent, member) : NULL;
    int ret = -1;
    if(!name || ((member->expr_type == ASN_CONSTR_SEQUENCE
                  || member->expr_type == ASN_BASIC_ENUMERATED) && !nested_type)) {
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
    if(member->expr_type == ASN_CONSTR_SEQUENCE && !member->members.tq_head) {
        if(member->marker.flags == EM_OPTIONAL) {
            ret = fprintf(stream,
                "if __asn1c_presence[%zu] { Some(%s {}) } else { None },\n",
                *presence_index, nested_type);
            (*presence_index)++;
        } else ret = fprintf(stream, "%s {},\n", nested_type);
        free(name);
        free(nested_type);
        return ret < 0 ? -1 : 0;
    }
    if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_BASIC_ENUMERATED) {
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
    if(rust_containing_node(member->combined_constraints, 0)) {
        asn1p_expr_t *inner = rust_contained_primitive(member->module, member);
        int64_t lower = 0, upper = 1;
        char low[64], high[64];
        int is_boolean = inner && inner->expr_type == ASN_BASIC_BOOLEAN;
        if(inner && (is_boolean || !rust_integer_bounds(inner, &lower, &upper))
           && !rust_format_bound(low, sizeof(low), lower) && !rust_format_bound(high, sizeof(high), upper))
            ret = fprintf(stream, "::asn1c_runtime::uper_cursor::read_containing_uper(reader, %s, %s, %s)?%s",
                low, high, member->expr_type == ASN_BASIC_OCTET_STRING ? "true" : "false",
                is_boolean ? " != 0" : "");
    } else if(member->expr_type == ASN_TYPE_ANY)
        ret = fputs("::asn1c_runtime::uper_cursor::read_any_uper(reader)?", stream);
    else if(member->expr_type == ASN_BASIC_BOOLEAN)
        ret = fputs("reader.read_boolean()?", stream);
    else if(member->expr_type == ASN_BASIC_OCTET_STRING
            || member->expr_type == ASN_BASIC_BIT_STRING)
        ret = rust_write_sequence_decode_string_field(stream, member);
    else {
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
 * Emit a fixed or bounded string cursor expression in one field initializer.
 * Parameters: stream receives Rust; member supplies type and size constraints.
 * Returns zero or -1; no exception. Original source: Rust UPER SEQUENCE string
 * decoding. Version/date: 0.6.0, 2026-10-30. Responsible party: asn1c
 * maintainers. History: shared OCTET/BIT STRING path. Example:
 * rust_write_sequence_decode_string_field(out, field).
 */
static int
rust_write_sequence_decode_string_field(FILE *stream, asn1p_expr_t *member) {
    size_t length, lower, upper;
    const int octets = member->expr_type == ASN_BASIC_OCTET_STRING;
    if(!rust_fixed_size(member, &length))
        return fprintf(stream, "reader.read_%s(%zu)?",
                       octets ? "octets" : "bit_string", length) < 0 ? -1 : 0;
    if(rust_bounded_size(member, &lower, &upper)) return -1;
    return fprintf(stream, "reader.read_bounded_%s(%zu, %zu)?",
                   octets ? "octets" : "bit_string", lower, upper) < 0 ? -1 : 0;
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
 * Emit selected JER methods for a fixed-size OCTET STRING or BIT STRING.
 * Parameters: stream receives Rust; length is the declared unit count;
 * octets selects OCTET STRING over BIT STRING.
 * Returns zero or -1 on output failure; it throws no exception.
 * Original source: OCTET_STRING/BIT_STRING JER helpers in the Rust runtime.
 * Version/date: 0.7.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: direct fixed-size string JER support. Example:
 * rust_write_string_jer(out, 3, 0).
 */
static int
rust_write_string_jer(FILE *stream, size_t length, int octets) {
    if(rust_write_method_doc(stream,
            octets ? "Encode this fixed-size OCTET STRING as JER hexadecimal."
                   : "Encode this fixed-size BIT STRING as JER hexadecimal.",
            "`self` is the validated value; `limits` bounds output and work.",
            "Returns compact uppercase hexadecimal JSON and complete counts.",
            "Returns an error for invalid content or exhausted resources.",
            "`let encoded = value.encode_jer(&Default::default())?;")) return -1;
    if(octets) {
        if(fprintf(stream,
            "    pub fn encode_jer(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        ::asn1c_runtime::encode_octet_string_jer(&self.0, %zu, limits)\n"
            "    }\n", length) < 0) return -1;
    } else if(fprintf(stream,
        "    pub fn encode_jer(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_bit_string_jer(&self.0, %zu, limits)\n"
        "    }\n", length) < 0) return -1;
    if(rust_write_method_doc(stream,
            octets ? "Decode one complete fixed-size OCTET STRING JER value."
                   : "Decode one complete fixed-size BIT STRING JER value.",
            "`input` is the entire JSON string; `limits` bounds input and work.",
            "Returns the validated value and full-input byte and bit counts.",
            "Returns an error for malformed hex, wrong size, trailing input, or limits.",
            "`let decoded = Type::decode_jer(input, &Default::default())?;")) return -1;
    if(octets) return fprintf(stream,
        "    pub fn decode_jer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_octet_string_jer(input, %zu, limits)?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(decoded.value),\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n"
        "    }\n", length) < 0 ? -1 : 0;
    return fprintf(stream,
        "    pub fn decode_jer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_bit_string_jer(input, %zu, limits)?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(decoded.value),\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n"
        "    }\n", length) < 0 ? -1 : 0;
}

/*
 * Purpose: emit direct fixed or bounded OCTET STRING CBOR methods.
 * Source: C OCTET_STRING CBOR byte-string mapping. Version: 2026-10-30.
 * Inputs: stream receives Rust; lower/upper are inclusive octet bounds.
 * Returns zero or -1 on output failure. Errors: no exception is thrown.
 * Author: asn1c maintainers. History: direct Rust string CBOR slice.
 * Example: one octet emits `41 XX`.
 */
static int
rust_write_octet_cbor(FILE *stream, size_t lower, size_t upper) {
    if(rust_write_method_doc(stream,
        "Encode this OCTET STRING as a CBOR byte string.",
        "`self` supplies octets; `limits` bounds resources.",
        "Returns definite byte-string encoding.",
        "Returns an error for invalid SIZE, allocation, or resource exhaustion.",
        "`let encoded = value.encode_cbor(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_cbor(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::cbor::encode_octet_string_cbor(&self.0, %zu, %zu, limits)\n"
        "    }\n", lower, upper) < 0) return -1;
    if(rust_write_method_doc(stream,
        "Decode one OCTET STRING CBOR prefix.",
        "`input` supplies bytes; `limits` bounds resources.",
        "Returns validated octets and consumed prefix lengths.",
        "Returns an error for malformed, truncated, out-of-range, or over-limit input.",
        "`let decoded = Type::decode_cbor(input, &Default::default())?;")) return -1;
    return fprintf(stream,
        "    pub fn decode_cbor(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::cbor::decode_octet_string_cbor(input, %zu, %zu, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n",
        lower, upper) < 0 ? -1 : 0;
}

/*
 * Purpose: emit direct fixed or bounded BIT STRING CBOR methods.
 * Source: C BIT_STRING CBOR unused-bit-octet mapping. Version: 2026-10-30.
 * Inputs: stream receives Rust; bounds count meaningful bits; bounded chooses
 * the validated BitStringValue representation. Returns zero or -1.
 * Errors: output failures are reported; no exception is thrown.
 * Author: maintainers. History: direct Rust string CBOR slice.
 * Example: one set bit emits `42 07 80`.
 */
static int
rust_write_bit_cbor(FILE *stream, size_t lower, size_t upper, int bounded) {
    char bit_text[32];
    int written = snprintf(bit_text, sizeof(bit_text), "%zu", lower);
    if(written < 0 || (size_t)written >= sizeof(bit_text)) return -1;
    if(rust_write_method_doc(stream,
        "Encode this BIT STRING with a CBOR unused-bit octet.",
        "`self` supplies packed bits; `limits` bounds resources.",
        "Returns definite byte-string encoding.",
        "Returns an error for invalid SIZE, padding, allocation, or limits.",
        "`let encoded = value.encode_cbor(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_cbor(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::cbor::encode_bit_string_cbor(\n"
        "            %s, %s, %zu, %zu, limits)\n    }\n",
        bounded ? "self.0.as_bytes()" : "&self.0",
        bounded ? "self.0.bit_len()" : bit_text, lower, upper) < 0) return -1;
    if(rust_write_method_doc(stream,
        "Decode one BIT STRING CBOR prefix.",
        "`input` supplies bytes; `limits` bounds resources.",
        "Returns validated packed bits and consumed prefix lengths.",
        "Returns an error for malformed, truncated, out-of-range, or over-limit input.",
        "`let decoded = Type::decode_cbor(input, &Default::default())?;")) return -1;
    return fprintf(stream,
        "    pub fn decode_cbor(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::cbor::decode_bit_string_cbor(input, %zu, %zu, limits)\n"
        "            .map(|decoded| decoded.map(%s))\n    }\n",
        lower, upper, bounded ? "Self" : "|value| Self(value.into_bytes())") < 0 ? -1 : 0;
}

/*
 * Emit a bounded OCTET STRING wrapper with selected UPER and JER methods.
 * Parameters: stream receives Rust; name is the generated type; lower and
 * upper are validated inclusive bounds; codecs selects emitted methods.
 * Returns zero or -1; it throws no exception. Original source: Rust bounded
 * UPER and JER APIs.
 * Version/date: 0.5.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: bounded octet slice. Example:
 * rust_write_bounded_octets(out, "Data", 1, 3, RUST_CODEC_JER).
 */
static int
rust_write_bounded_octets(FILE *stream, const char *name,
                          size_t lower, size_t upper, uint64_t codecs) {
    if(fprintf(stream,
        "/// Bounded nonextensible ASN.1 OCTET STRING payload.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// ASN.1 OCTET STRING payload state variable.\n"
        "    ::std::vec::Vec<u8>\n);\n\nimpl %s {\n", name, name) < 0)
        return -1;
    if(rust_write_method_doc(stream,
            "Construct an OCTET STRING within its declared size range.",
            "`value` contains the octets to validate.",
            "Returns the validated value.",
            "Returns an error when the octet count is outside the ASN.1 SIZE range.",
            "`let value = Type::new(vec![0xA5])?;")) return -1;
    if(fputs(
        "    pub fn new(value: ::std::vec::Vec<u8>) ->\n"
        "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n",
        stream) == EOF) return -1;
    if(lower == 0) {
        if(fprintf(stream, "        if value.len() > %zu {\n", upper) < 0) return -1;
    } else if(lower == 1) {
        if(fprintf(stream,
            "        if value.is_empty() || value.len() > %zu {\n", upper) < 0)
            return -1;
    } else if(fprintf(stream,
        "        if value.len() < %zu || value.len() > %zu {\n", lower, upper) < 0) {
        return -1;
    }
    if(fputs(
        "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"OCTET STRING length is outside its SIZE range\",\n"
        "            });\n        }\n        Ok(Self(value))\n    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream,
            "Return the OCTET STRING contents.",
            "`self` is a validated bounded OCTET STRING.",
            "Returns its octets without copying.",
            "This accessor cannot fail.",
            "`let bytes = value.as_bytes();")) return -1;
    if(fputs("    #[must_use]\n    pub fn as_bytes(&self) -> &[u8] { &self.0 }\n",
             stream) == EOF) return -1;
    if((codecs & RUST_CODEC_UPER)
       && rust_write_bounded_octets_uper(stream, lower, upper)) return -1;
    if((codecs & RUST_CODEC_JER)
       && rust_write_bounded_octets_jer(stream, lower, upper)) return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_string_ber_cer(stream, 1, 0, lower, upper, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_string_ber_cer(stream, 1, 0, lower, upper, 1)) return -1;
    if((codecs & RUST_CODEC_CBOR)
       && rust_write_octet_cbor(stream, lower, upper)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit UPER methods for one bounded OCTET STRING wrapper.
 * Parameters: stream receives Rust source; lower and upper are inclusive
 * declared bounds. Returns zero or -1; it throws no exception. Original
 * source: bounded Rust UPER cursor API. Version/date: 0.5.0, 2026-10-30.
 * Responsible party: asn1c
 * maintainers. History: extracted bounded octet emitter. Example:
 * rust_write_bounded_octets_uper(stream, 1, 7).
 */
static int
rust_write_bounded_octets_uper(FILE *stream, size_t lower, size_t upper) {
    if(rust_write_method_doc(stream,
            "Encode this bounded OCTET STRING with UPER.",
            "`self` is the value; `limits` bounds output and work.",
            "Returns packed bytes and meaningful bit length.",
            "Returns an error when a resource limit is exceeded.",
            "`let encoded = value.encode_uper(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let mut writer = ::asn1c_runtime::UperWriter::new(limits)?;\n"
        "        writer.write_bounded_octets(&self.0, %zu, %zu)?;\n"
        "        writer.finish()\n    }\n", lower, upper) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete bounded OCTET STRING UPER value.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the validated string and consumed prefix lengths.",
            "Returns an error for truncation, spare size codes, or exhausted resources.",
            "`let decoded = Type::decode_uper(input, &Default::default())?;")) return -1;
    return fprintf(stream,
        "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let mut reader = ::asn1c_runtime::UperReader::new(input, limits)?;\n"
        "        let value = reader.read_bounded_octets(%zu, %zu)?;\n"
        "        let consumed = reader.finish()?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(value),\n"
        "            consumed_bits: consumed.consumed_bits,\n"
        "            consumed_bytes: consumed.consumed_bytes,\n"
        "        })\n    }\n", lower, upper) < 0 ? -1 : 0;
}

/*
 * Emit strict complete-input JER methods for one bounded OCTET STRING.
 * Parameters: stream receives Rust source; lower and upper are inclusive
 * declared bounds. Returns zero or -1; it throws no exception. Original
 * source: bounded Rust JER runtime API. Version/date: 0.5.0, 2026-10-30.
 * Responsible party: asn1c
 * maintainers. History: extracted bounded octet emitter. Example:
 * rust_write_bounded_octets_jer(stream, 1, 7).
 */
static int
rust_write_bounded_octets_jer(FILE *stream, size_t lower, size_t upper) {
    if(rust_write_method_doc(stream,
            "Encode this bounded OCTET STRING as uppercase hexadecimal JER.",
            "`self` is validated; `limits` bounds output and work.",
            "Returns one quoted hexadecimal JSON string.",
            "Returns an error when a resource limit is exceeded.",
            "`let encoded = value.encode_jer(&Default::default())?;")) return -1;
    if(fputs(
        "    pub fn encode_jer(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_bounded_octet_string_jer(\n"
        "            &self.0, ", stream) == EOF
       || fprintf(stream, "%zu, %zu, limits)\n    }\n", lower, upper) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete bounded OCTET STRING JER value.",
            "`input` is the full JSON value; `limits` bounds input and work.",
            "Returns validated octets and full-input consumption.",
            "Returns an error for malformed JSON, hex, length, or limits.",
            "`let decoded = Type::decode_jer(input, &Default::default())?;")) return -1;
    if(fputs(
        "    pub fn decode_jer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_bounded_octet_string_jer(\n"
        "            input, ", stream) == EOF) return -1;
    return fprintf(stream,
        "%zu, %zu, limits)?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(decoded.value),\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n    }\n", lower, upper) < 0 ? -1 : 0;
}

/*
 * Emit a bounded-size BIT STRING wrapper with explicit meaningful bit length.
 * Parameters: stream receives Rust; name is the generated type; lower and
 * upper are validated inclusive bounds; codecs selects UPER and/or JER.
 * Returns zero or -1. Original source: X.691 and bounded BIT STRING JER.
 * Version/date: 0.7.0, 2026-10-30. Responsible party: asn1c maintainers.
 * History: bounded BIT STRING codec slice. Example:
 * rust_write_bounded_bits(out, "Bits", 1, 3, RUST_CODEC_JER).
 */
static int
rust_write_bounded_bits(FILE *stream, const char *name,
                        size_t lower, size_t upper, uint64_t codecs) {
    if(fprintf(stream,
        "/// Bounded nonextensible ASN.1 BIT STRING with its meaningful width.\n"
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// ASN.1 BIT STRING payload state variable.\n"
        "    ::asn1c_runtime::BitStringValue\n);\n\nimpl %s {\n",
        name, name) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Construct a BIT STRING within its declared size range.",
            "`value` carries packed octets and its exact meaningful bit length.",
            "Returns the validated value.",
            "Returns an error when its bit length is outside the ASN.1 SIZE range.",
            "`let bits = BitStringValue::new(vec![0xA0], 3)?;")) return -1;
    if(fputs(
        "    pub fn new(value: ::asn1c_runtime::BitStringValue) ->\n"
        "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n",
        stream) == EOF) return -1;
    if(lower == 0) {
        if(fprintf(stream, "        if value.bit_len() > %zu {\n", upper) < 0) return -1;
    } else if(fprintf(stream,
        "        if value.bit_len() < %zu || value.bit_len() > %zu {\n",
        lower, upper) < 0) return -1;
    if(fputs(
        "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"BIT STRING length is outside its SIZE range\",\n"
        "            });\n        }\n        Ok(Self(value))\n    }\n",
        stream) == EOF) return -1;
    if(rust_write_method_doc(stream,
            "Return the packed BIT STRING contents.",
            "`self` is a validated bounded BIT STRING.",
            "Returns its packed octets without copying.",
            "This accessor cannot fail.",
            "`let packed = bits.as_bytes();")) return -1;
    if(fputs(
        "    #[must_use]\n    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }\n",
        stream) == EOF) return -1;
    if(rust_write_method_doc(stream,
            "Return the exact number of meaningful BIT STRING bits.",
            "`self` is a validated bounded BIT STRING.",
            "Returns its logical bit length.",
            "This accessor cannot fail.",
            "`let width = bits.bit_len();")) return -1;
    if(fputs("    #[must_use]\n    pub const fn bit_len(&self) -> usize { self.0.bit_len() }\n",
             stream) == EOF) return -1;
    if(codecs & RUST_CODEC_UPER) {
    if(rust_write_method_doc(stream,
            "Encode this bounded BIT STRING with UPER.",
            "`self` is the value; `limits` bounds output and work.",
            "Returns packed bytes and meaningful bit length.",
            "Returns an error when a resource limit is exceeded.",
            "`let encoded = bits.encode_uper(&Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn encode_uper(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let mut writer = ::asn1c_runtime::UperWriter::new(limits)?;\n"
        "        writer.write_bounded_bit_string(&self.0, %zu, %zu)?;\n"
        "        writer.finish()\n    }\n", lower, upper) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Decode one complete bounded BIT STRING UPER value.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the validated bit string and consumed prefix lengths.",
            "Returns an error for truncation, spare size codes, or exhausted resources.",
            "`let decoded = Bits::decode_uper(input, &Default::default())?;")) return -1;
    if(fprintf(stream,
        "    pub fn decode_uper(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let mut reader = ::asn1c_runtime::UperReader::new(input, limits)?;\n"
        "        let value = reader.read_bounded_bit_string(%zu, %zu)?;\n"
        "        let consumed = reader.finish()?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(value),\n"
        "            consumed_bits: consumed.consumed_bits,\n"
        "            consumed_bytes: consumed.consumed_bytes,\n"
        "        })\n    }\n", lower, upper) < 0) return -1;
    }
    if(codecs & RUST_CODEC_JER) {
        if(rust_write_method_doc(stream,
                "Encode this bounded BIT STRING as a minified JER object.",
                "`self` is validated; `limits` bounds output and work.",
                "Returns uppercase hexadecimal plus the exact logical bit length.",
                "Returns an error for invalid content or exhausted resources.",
                "`let encoded = bits.encode_jer(&Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn encode_jer(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        ::asn1c_runtime::encode_bounded_bit_string_jer(\n"
            "            &self.0, %zu, %zu, limits)\n"
            "    }\n", lower, upper) < 0) return -1;
        if(rust_write_method_doc(stream,
                "Decode one complete bounded BIT STRING JER object.",
                "`input` is the full JSON value; `limits` bounds input and work.",
                "Returns validated packed bits and full-input consumption.",
                "Returns an error for malformed JSON, hex, length, padding, or limits.",
                "`let decoded = Bits::decode_jer(input, &Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn decode_jer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
            "        let decoded = ::asn1c_runtime::decode_bounded_bit_string_jer(\n"
            "            input, %zu, %zu, limits)?;\n"
            "        Ok(::asn1c_runtime::Decoded {\n"
            "            value: Self(decoded.value),\n"
            "            consumed_bits: decoded.consumed_bits,\n"
            "            consumed_bytes: decoded.consumed_bytes,\n"
            "        })\n    }\n", lower, upper) < 0) return -1;
    }
    if((codecs & RUST_CODEC_BER)
       && rust_write_string_ber_cer(stream, 0, 0, lower, upper, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_string_ber_cer(stream, 0, 0, lower, upper, 1)) return -1;
    if((codecs & RUST_CODEC_CBOR)
       && rust_write_bit_cbor(stream, lower, upper, 1)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
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
    size_t length, lower, upper;
    const int octets = expr->expr_type == ASN_BASIC_OCTET_STRING;
    if(rust_fixed_size(expr, &length)) {
        if(rust_bounded_size(expr, &lower, &upper)) return -1;
        return octets ? rust_write_bounded_octets(stream, name, lower, upper, codecs)
                      : rust_write_bounded_bits(stream, name, lower, upper, codecs);
    }
    if(fprintf(stream,
        "#[derive(Clone, Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n    /// ASN.1 string payload state variable.\n"
        "    ::std::vec::Vec<u8>\n);\n\nimpl %s {\n", name, name) < 0)
        return -1;
    if(rust_write_string_constructor(stream, length, octets)) return -1;
    if((codecs & RUST_CODEC_UPER)
       && rust_write_string_uper(stream, length, octets)) return -1;
    if((codecs & RUST_CODEC_JER)
       && rust_write_string_jer(stream, length, octets)) return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_string_ber_cer(stream, octets, 1, length, length, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_string_ber_cer(stream, octets, 1, length, length, 1)) return -1;
    if(codecs & RUST_CODEC_CBOR) {
        if(octets ? rust_write_octet_cbor(stream, length, length)
                  : rust_write_bit_cbor(stream, length, length, 0)) return -1;
    }
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one DER/BER or CER method pair for a size-constrained string.
 * Parameters: octets selects OCTET STRING; fixed selects byte-backed fixed
 * BIT STRING adaptation; lower and upper are inclusive schema bit/octet
 * bounds; cer selects CER over BER/DER. Returns zero or -1. Original source:
 * ASN.1 runtime root APIs. Version/date: 0.8.0, 2026-10-31. Responsible
 * party: asn1c maintainers. History: generated string BER/CER expansion.
 * Example: rust_write_string_ber_cer(out, 1, 0, 1, 8, 0).
 */
static int
rust_write_string_ber_cer(FILE *stream, int octets, int fixed,
                          size_t lower, size_t upper, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *encode_suffix = cer ? "cer" : "der";
    const char *encoder = octets ? "octet_string" : "bit_string";
    const char *method = cer ? "encode_cer" : "encode_der";
    const char *example = cer
        ? "`let encoded = value.encode_cer(&Default::default())?;"
        : "`let encoded = value.encode_der(&Default::default())?;";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";

    if(rust_write_method_doc(stream,
            octets ? "Encode this OCTET STRING using the selected canonical rules."
                   : "Encode this BIT STRING using the selected canonical rules.",
            "`self` is schema-validated; `limits` bounds output and work.",
            octets ? "Returns the complete canonical OCTET STRING TLV."
                   : "Returns the complete canonical BIT STRING TLV.",
            "Returns an error when a resource limit is exceeded.", example)) return -1;
    if(fprintf(stream,
        "    pub fn %s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n",
        method) < 0) return -1;
    if(!octets && fixed) {
        if(fprintf(stream,
            "        let value = ::asn1c_runtime::BitStringValue::from_bytes(\n"
            "            &self.0, %zu)?;\n"
            "        ::asn1c_runtime::encode_%s_%s(&value, limits)\n",
            lower, encoder, encode_suffix) < 0) return -1;
    } else if(fprintf(stream,
        "        ::asn1c_runtime::encode_%s_%s(&self.0, limits)\n",
        encoder, encode_suffix) < 0) return -1;
    if(fputs("    }\n", stream) == EOF) return -1;

    if(rust_write_method_doc(stream,
            octets ? "Decode one OCTET STRING TLV and report prefix consumption."
                   : "Decode one BIT STRING TLV and report prefix consumption.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns a schema-validated value and consumed prefix lengths.",
            "Returns an error for malformed input, invalid SIZE, or limits.",
            decode_example))
        return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_%s_%s(input, limits)?;\n",
        suffix, encoder, suffix) < 0) return -1;
    if(!octets && fixed) {
        if(fprintf(stream,
            "        if decoded.value.bit_len() != %zu {\n"
            "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
            "                reason: \"BIT STRING length is outside its SIZE range\",\n"
            "            });\n        }\n", lower) < 0) return -1;
        if(fputs(
            "        let value = Self::new(decoded.value.into_bytes())?;\n"
            "        Ok(::asn1c_runtime::Decoded {\n"
            "            value,\n"
            "            consumed_bits: decoded.consumed_bits,\n"
            "            consumed_bytes: decoded.consumed_bytes,\n"
            "        })\n    }\n", stream) == EOF) return -1;
    } else if(fputs(
        "        let value = Self::new(decoded.value)?;\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value,\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n    }\n", stream) == EOF) return -1;
    (void)upper;
    return 0;
}

/*
 * Emit a direct unconstrained string wrapper with ownership-taking storage.
 * Inputs: stream receives Rust, name is the public name, octets selects OCTET
 * STRING, and codecs is the validated BER/CER-only mask. Returns zero or -1.
 * Errors: generated codec methods propagate runtime validation and limit errors.
 * Original source: approved standalone BER/CER string API. Version/date:
 * 2026-11-01. Responsible party: asn1c maintainers. History: unbounded strings.
 * Example: rust_write_unconstrained_string(out, "Data", 1, RUST_CODEC_BER).
 */
static int
rust_write_unconstrained_string(FILE *stream, const char *name, int octets,
                                uint64_t codecs) {
    const char *kind = octets ? "OCTET STRING" : "BIT STRING";
    const char *storage = octets ? "::std::vec::Vec<u8>"
                                 : "::asn1c_runtime::BitStringValue";
    if(fprintf(stream,
        "/// Unconstrained ASN.1 %s with validated private storage.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Owned ASN.1 string payload state variable.\n"
        "    %s\n"
        ");\n\nimpl %s {\n", kind, name, storage, name) < 0) return -1;
    if(rust_write_method_doc(stream,
            octets ? "Take ownership of OCTET STRING contents."
                   : "Take ownership of a validated BIT STRING value.",
            octets ? "`value` is the owned octet vector."
                   : "`value` has exact bit length and zero padding from validated storage.",
            "Returns a wrapper without copying its payload.",
            "This constructor cannot fail.",
            octets ? "`let value = Type::new(vec![0xA5]);"
                   : "`let value = Type::new(BitStringValue::new(vec![0xA0], 3)?);"))
        return -1;
    if(octets) {
        if(fputs("    #[must_use]\n"
                 "    pub const fn new(value: ::std::vec::Vec<u8>) -> Self { Self(value) }\n",
                 stream) == EOF) return -1;
        if(rust_write_method_doc(stream, "Borrow the OCTET STRING contents.",
                "`self` is the value to inspect.", "Returns its octets without copying.",
                "This accessor cannot fail.", "`let bytes = value.as_bytes();"))
            return -1;
        if(fputs("    #[must_use]\n"
                 "    pub fn as_bytes(&self) -> &[u8] { &self.0 }\n", stream) == EOF)
            return -1;
    } else {
        if(fputs("    #[must_use]\n"
                 "    pub const fn new(value: ::asn1c_runtime::BitStringValue) -> Self {\n"
                 "        Self(value)\n    }\n", stream) == EOF) return -1;
        if(rust_write_method_doc(stream, "Borrow the validated BIT STRING value.",
                "`self` is the value to inspect.",
                "Returns packed bytes and the exact logical bit length.",
                "This accessor cannot fail.", "`let bits = value.as_bit_string();"))
            return -1;
        if(fputs("    #[must_use]\n"
                 "    pub const fn as_bit_string(&self) -> &::asn1c_runtime::BitStringValue {\n"
                 "        &self.0\n    }\n", stream) == EOF) return -1;
        if(rust_write_method_doc(stream, "Borrow the packed BIT STRING bytes.",
                "`self` is the value to inspect.", "Returns packed octets without copying.",
                "This accessor cannot fail.", "`let bytes = value.as_bytes();"))
            return -1;
        if(fputs("    #[must_use]\n"
                 "    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }\n",
                 stream) == EOF) return -1;
        if(rust_write_method_doc(stream, "Return the number of meaningful bits.",
                "`self` is the value to inspect.", "Returns the exact logical bit length.",
                "This accessor cannot fail.", "`let width = value.bit_len();")) return -1;
        if(fputs("    #[must_use]\n"
                 "    pub const fn bit_len(&self) -> usize { self.0.bit_len() }\n",
                 stream) == EOF) return -1;
    }
    if((codecs & RUST_CODEC_BER)
       && rust_write_unconstrained_string_ber_cer(stream, octets, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_unconstrained_string_ber_cer(stream, octets, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit one standalone DER/BER or CER codec pair for an unbounded string.
 * Inputs: stream receives Rust; octets selects OCTET STRING; cer selects CER.
 * Returns zero or -1 on write failure. Codec errors are returned to callers.
 * Original source: BER runtime standalone string APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: unconstrained string slice.
 * Example: rust_write_unconstrained_string_ber_cer(out, 0, 1).
 */
static int
rust_write_unconstrained_string_ber_cer(FILE *stream, int octets, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *encode_suffix = cer ? "cer" : "der";
    const char *encoder = octets ? "octet_string" : "bit_string";
    const char *description = cer ? "Encode this value using CER."
                                  : "Encode this value using DER.";
    const char *decode_description = cer
        ? "Strictly decode one CER string TLV and report prefix consumption."
        : "Decode one BER string TLV and report prefix consumption.";
    const char *decode_error = cer
        ? "Returns an error for malformed, noncanonical, or over-limit input."
        : "Returns an error for malformed or over-limit input.";
    const char *encode_example = cer
        ? "`let encoded = value.encode_cer(&Default::default())?;"
        : "`let encoded = value.encode_der(&Default::default())?;";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";

    if(rust_write_method_doc(stream, description,
            "`self` is the value; `limits` bounds output and work.",
            "Returns the complete canonical string TLV.",
            "Returns a runtime error if a configured limit is exceeded.", encode_example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_%s_%s(&self.0, limits)\n"
        "    }\n", encode_suffix, encoder, encode_suffix) < 0) return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is a prefix; `limits` bounds input, decoded storage, and work.",
            "Returns the value and exact consumed bit and byte counts.",
            decode_error, decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_%s_%s(input, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n",
        suffix, encoder, suffix) < 0) return -1;
    return 0;
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
    if((codecs & RUST_CODEC_BER)
       && rust_write_enumerated_ber_cer(stream, expr, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_enumerated_ber_cer(stream, expr, 1)) return -1;
    if(fputs("}\n\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit DER/BER or CER methods mapping enum variants to their ASN.1 values.
 * Parameters: stream receives Rust; expr supplies checked root values; cer
 * selects CER over DER/BER. Returns zero or -1. Original source: ASN.1
 * ENUMERATED value semantics and runtime root APIs. Version/date: 0.8.0,
 * 2026-10-31. Responsible party: asn1c maintainers. History: generated
 * enum BER/CER expansion. Example: rust_write_enumerated_ber_cer(out, e, 0).
 */
static int
rust_write_enumerated_ber_cer(FILE *stream, asn1p_expr_t *expr, int cer) {
    asn1p_expr_t *item;
    const char *encoding = cer ? "cer" : "der";
    const char *decoding = cer ? "cer" : "ber";
    const char *encode_method = cer ? "encode_cer" : "encode_der";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";

    if(rust_write_method_doc(stream,
            cer ? "Encode this ENUMERATED value using CER."
                : "Encode this ENUMERATED value using DER.",
            "`self` is a root variant; `limits` bounds output and work.",
            "Returns the canonical TLV for this ASN.1 numeric value.",
            "Returns an error when a resource limit is exceeded.",
            cer ? "`let encoded = value.encode_cer(&Default::default())?;"
                : "`let encoded = value.encode_der(&Default::default())?;"))
        return -1;
    if(fprintf(stream,
        "    pub fn %s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        let value = match self {\n", encode_method) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        char value[64];
        int invalid = !variant
            || rust_format_bound(value, sizeof(value),
                                 (int64_t)item->value->value.v_integer);
        int ret = invalid ? -1 : fprintf(stream,
            "            Self::%s => %s,\n", variant, value);
        free(variant);
        if(ret < 0) return -1;
    }
    if(fprintf(stream,
        "        };\n"
        "        ::asn1c_runtime::encode_enumerated_%s(value, limits)\n"
        "    }\n", encoding) < 0) return -1;

    if(rust_write_method_doc(stream,
            cer ? "Decode one CER ENUMERATED TLV and report prefix consumption."
                : "Decode one BER ENUMERATED TLV and report prefix consumption.",
            "`input` is the encoded prefix; `limits` bounds input and work.",
            "Returns the matching root variant and consumed prefix lengths.",
            "Returns an error for malformed input, unknown values, or limits.",
            decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_enumerated_%s(input, limits)?;\n"
        "        let value = match decoded.value {\n", decoding, decoding) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        char value[64];
        int invalid = !variant
            || rust_format_bound(value, sizeof(value),
                                 (int64_t)item->value->value.v_integer);
        int ret = invalid ? -1 : fprintf(stream,
            "            %s => Self::%s,\n", value, variant);
        free(variant);
        if(ret < 0) return -1;
    }
    if(fputs(
        "            _ => return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"unknown ENUMERATED value\",\n"
        "            }),\n"
        "        };\n"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value,\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n    }\n", stream) == EOF) return -1;
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
    if((codecs & RUST_CODEC_CBOR)
       && rust_write_per_oer(stream, "cbor", "boolean", NULL, NULL)) return -1;
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
    if((codecs & RUST_CODEC_CBOR)
       && rust_write_per_oer(stream, "cbor", "null", NULL, NULL)) return -1;
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
    if((codecs & RUST_CODEC_CBOR)
       && rust_write_per_oer(stream, "cbor", "integer", low, high)) return -1;
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
 * Emit an unconstrained signed INTEGER wrapper without exposing its storage.
 * Inputs: stream receives Rust, name is the public type, and codecs is the
 * validated BER/CER-only selection. Returns zero or -1 on output failure.
 * Errors: emitted methods return runtime validation, decode, and limit errors.
 * Source: new Rust BigInteger generator slice. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: initial unbounded INTEGER.
 * Example: rust_write_big_integer(stream, "Huge", RUST_CODEC_BER).
 */
static int
rust_write_big_integer(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream,
        "/// Unconstrained ASN.1 INTEGER with canonical signed-byte storage.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Private arbitrary-precision INTEGER state variable.\n"
        "    ::asn1c_runtime::BigInteger\n"
        ");\n\nimpl %s {\n", name, name) < 0) return -1;
    if(rust_write_method_doc(stream,
            "Construct an INTEGER from signed big-endian two's-complement bytes.",
            "`bytes` is nonempty signed input; `limits` bounds memory and work.",
            "Returns a value holding a normalized copy of the integer bytes.",
            "Returns an error for empty input, invalid representation, or limits.",
            "`let value = Type::try_from_signed_bytes(&[0x80], &limits)?;"))
        return -1;
    if(fputs("    pub fn try_from_signed_bytes(\n"
             "        bytes: &[u8], limits: &::asn1c_runtime::Limits\n"
             "    ) -> ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::BigInteger::try_from_signed_bytes(bytes, limits)\n"
             "            .map(Self)\n    }\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream, "Borrow the normalized signed INTEGER bytes.",
            "`self` is the value to inspect.",
            "Returns the minimal big-endian two's-complement byte representation.",
            "This accessor cannot fail.", "`let bytes = value.as_signed_bytes();"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub fn as_signed_bytes(&self) -> &[u8] {\n"
             "        self.0.as_signed_bytes()\n    }\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream, "Return the value when it fits in i64.",
            "`self` is the value to inspect.",
            "Returns `Some` for values in the signed 64-bit range, otherwise `None`.",
            "This accessor cannot fail.", "`let small = value.try_to_i64();"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub fn try_to_i64(&self) -> ::core::option::Option<i64> {\n"
             "        self.0.try_to_i64()\n    }\n", stream) == EOF) return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_big_integer_ber_cer(stream, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_big_integer_ber_cer(stream, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Emit one syntax-specific arbitrary-precision INTEGER method pair.
 * Inputs: stream receives source; cer selects CER instead of DER/BER.
 * Returns zero or -1 on output failure. Runtime errors carry malformed and
 * resource-limit failures. Source: new Rust BigInteger generator slice.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: split syntax methods for codec-selective generation.
 * Example: rust_write_big_integer_ber_cer(stream, 1) emits CER methods.
 */
static int
rust_write_big_integer_ber_cer(FILE *stream, int cer) {
    const char *lower = cer ? "cer" : "der";
    const char *decode = cer ? "cer" : "ber";
    const char *description = cer
        ? "Encode this value using CER."
        : "Encode this value using DER.";
    const char *return_text = cer
        ? "Returns the complete minimal signed INTEGER CER TLV."
        : "Returns the complete minimal signed INTEGER DER TLV.";
    const char *decode_description = cer
        ? "Strictly decode one CER INTEGER TLV and report prefix consumption."
        : "Decode one BER INTEGER TLV and report prefix consumption.";
    const char *decode_error = cer
        ? "Returns an error for truncated, noncanonical, malformed, or over-limit input."
        : "Returns an error for truncated, malformed, or over-limit input.";
    char example[96];
    int written;

    written = snprintf(example, sizeof(example),
                       "`let encoded = value.encode_%s(&Default::default())?;", lower);
    if(written < 0 || (size_t)written >= sizeof(example)) return -1;
    if(rust_write_method_doc(stream, description,
            "`self` is the value; `limits` bounds output and work.", return_text,
            "Returns a runtime error if a configured limit is exceeded.", example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_big_integer_%s(&self.0, limits)\n"
        "    }\n", lower, lower) < 0) return -1;
    written = snprintf(example, sizeof(example),
                       "`let decoded = Type::decode_%s(input, &Default::default())?;",
                       decode);
    if(written < 0 || (size_t)written >= sizeof(example)) return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is the encoded prefix; `limits` bounds decoding.",
            "Returns the value and consumed bit and byte counts.", decode_error,
            example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_big_integer_%s(input, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n", decode, decode) < 0)
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
           && strcmp(codec, "jer") && strcmp(codec, "cbor"))) return -1;
    label = !strcmp(codec, "aper") ? "APER"
          : !strcmp(codec, "oer") ? "OER" : !strcmp(codec, "cbor") ? "CBOR" : "JER";
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
        "runtime/LICENSE", "runtime/src/lib.rs", "runtime/src/big_integer.rs",
        "runtime/src/ber.rs",
        "runtime/src/cbor.rs", "runtime/src/jer.rs", "runtime/src/xer.rs",
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
