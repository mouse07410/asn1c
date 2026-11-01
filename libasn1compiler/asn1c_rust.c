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
static int rust_check_collection(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_oid_codecs(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_ia5_codecs(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_character_string(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static const char *rust_character_string_kind(const asn1p_expr_t *);
static int rust_check_utc_time(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_generalized_time(asn1p_module_t *, asn1p_expr_t *, uint64_t);
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
static int rust_check_ber_cer_choice(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_ber_cer_choice_root(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_ber_cer_choice_codecs(asn1p_module_t *, asn1p_expr_t *, uint64_t);
static int rust_check_ber_cer_choice_member(asn1p_module_t *, asn1p_expr_t *, unsigned *);
static int rust_check_ber_cer_choice_member_shape(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_ber_cer_choice_member_kind(asn1p_module_t *, asn1p_expr_t *, unsigned *);
static int rust_check_ber_cer_choice_integer(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_ber_cer_choice_name(asn1p_module_t *, asn1p_expr_t *, asn1p_expr_t *);
static int rust_check_inline_ber_cer_choice(asn1p_module_t *, asn1p_expr_t *,
                                           asn1p_expr_t *, int, uint64_t);
static int rust_inline_choice_shape_valid(asn1p_module_t *, asn1p_expr_t *);
static int rust_inline_choice_tagging_valid(asn1p_module_t *, asn1p_expr_t *);
static int rust_inline_choice_metadata_valid(asn1p_module_t *, asn1p_expr_t *);
static int rust_inline_choice_members_valid(asn1p_module_t *, asn1p_expr_t *);
static int rust_inline_choice_is_unique(asn1p_module_t *, asn1p_expr_t *,
                                        asn1p_expr_t *);
static int rust_check_inline_choice_collisions(asn1p_module_t *, asn1p_expr_t *,
                                               asn1p_expr_t *, int);
static int rust_check_sequence_tree(asn1p_module_t *, asn1p_expr_t *,
                                   asn1p_expr_t **, size_t, size_t *, size_t *, uint64_t);
static int rust_check_module_nested_names(asn1p_module_t *);
static int rust_collect_nested_names(asn1p_module_t *, asn1p_expr_t *,
                                     const char *, char **, size_t *, size_t);
static int rust_check_sequence_member(asn1p_module_t *, asn1p_expr_t *);
static int rust_sequence_member_shape_valid(const asn1p_expr_t *);
static int rust_ber_cer_member_tag(const asn1p_expr_t *, int *, uint32_t *);
static int rust_ber_cer_member_explicit(const asn1p_expr_t *);
static int rust_ber_cer_choice_has_tag(asn1p_expr_t *, uint32_t);
static uint32_t rust_ber_cer_choice_min_tag(asn1p_expr_t *);
static uint32_t rust_ber_cer_choice_arm_tag(asn1p_expr_t *);
static int rust_ber_cer_has_tagged_members(asn1p_expr_t *);
static int rust_ber_cer_has_nested_record(asn1p_expr_t *);
static int rust_ber_cer_has_named_sequence_member(asn1p_expr_t *);
static int rust_ber_cer_has_variable_content_member(asn1p_expr_t *);
static int rust_ber_cer_has_big_integer_member(asn1p_expr_t *);
static int rust_ber_cer_has_character_string_member(asn1p_expr_t *);
static int rust_ber_cer_field_kind_expression(const asn1p_expr_t *, char *, size_t);
static const char *rust_ber_cer_context_constructor(asn1p_expr_t *);
static int rust_check_ber_cer_ia5_record(asn1p_module_t *, asn1p_expr_t *,
                                         uint64_t);
static int rust_check_ber_cer_ia5_member(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_ber_cer_oid_record(asn1p_module_t *, asn1p_expr_t *,
                                         uint64_t);
static int rust_check_ber_cer_oid_member(asn1p_module_t *, asn1p_expr_t *);
static int rust_check_ber_cer_character_string_record(asn1p_module_t *,
                                                      asn1p_expr_t *, uint64_t);
static int rust_check_ber_cer_character_string_member(asn1p_module_t *,
                                                     asn1p_expr_t *);
static int rust_ber_cer_character_string_record_scan(asn1p_expr_t *, size_t *, int *);
static int rust_check_ber_cer_character_string_siblings(asn1p_module_t *,
                                                       asn1p_expr_t *);
static int rust_check_ber_cer_big_integer_record(asn1p_module_t *, asn1p_expr_t *,
                                                 uint64_t);
static int rust_check_ber_cer_big_integer_member(asn1p_module_t *, asn1p_expr_t *);
static int rust_ber_cer_is_unbounded_integer(const asn1p_expr_t *);
static size_t rust_ber_cer_big_integer_member_count(asn1p_expr_t *, int *, int *);
static int rust_check_ber_cer_big_integer_record_members(asn1p_module_t *,
                                                        asn1p_expr_t *);
static int rust_integer_single_range_supported(const asn1p_constraint_t *,
                                               unsigned, int *);
static asn1p_expr_t *rust_ber_cer_named_integer_target(const asn1p_expr_t *);
static asn1p_expr_t *rust_ber_cer_named_sequence_target(const asn1p_expr_t *);
static int rust_ber_cer_named_sequence_target_shape(asn1p_module_t *,
                                                    asn1p_expr_t *, const char *);
static int rust_check_ber_cer_named_integer_member(asn1p_module_t *,
                                                   asn1p_expr_t *);
static int rust_check_ber_cer_named_integer_record(asn1p_module_t *,
                                                    asn1p_expr_t *, uint64_t);
static int rust_check_ber_cer_named_sequence_member(asn1p_module_t *,
                                                    asn1p_expr_t *,
                                                    asn1p_expr_t *, size_t *);
static int rust_check_ber_cer_named_sequence_record(asn1p_module_t *,
                                                    asn1p_expr_t *, uint64_t);
static int rust_ber_cer_named_sequence_parent_scan(asn1p_expr_t *,
                                                   asn1p_expr_t **, size_t *, int *);
static int rust_ber_cer_named_sequence_parent_shape(asn1p_expr_t *,
                                                    asn1p_expr_t *, size_t,
                                                    int, uint64_t);
static asn1p_expr_t *rust_ber_cer_choice_member(asn1p_expr_t *, size_t *);
static int rust_ber_cer_has_empty_nested_record(asn1p_expr_t *);
static int rust_ber_cer_record_encode_uses_self(asn1p_expr_t *);
static const char *rust_ber_cer_optional_value_expression(asn1p_expr_t *);
static int rust_ber_cer_tag_compare(const asn1p_expr_t *, const asn1p_expr_t *);
static int rust_ber_cer_duplicate_tag(asn1p_expr_t *, asn1p_expr_t *);
static int rust_ber_cer_member_shape_valid(asn1p_expr_t *);
static int rust_check_ber_cer_member(asn1p_module_t *, asn1p_expr_t *,
                                    asn1p_expr_t *, int, size_t *, uint64_t);
static int rust_check_ber_cer_nested_record(asn1p_module_t *, asn1p_expr_t *,
                                            size_t *);
static int rust_ber_cer_nested_record_shape_valid(asn1p_expr_t *);
static int rust_ber_cer_sort_set_fields(asn1p_expr_t *, asn1p_expr_t **,
                                        size_t, size_t *);
static int rust_ber_cer_sort_set_fields_for_choice(asn1p_expr_t *, asn1p_expr_t *,
                                                    uint32_t, asn1p_expr_t **,
                                                    size_t, size_t *);
static int rust_ber_cer_set_choice_tag_compare(asn1p_expr_t *, asn1p_expr_t *,
                                                asn1p_expr_t *, uint32_t, int *);
static int rust_ber_cer_set_order_equal(asn1p_expr_t **, size_t,
                                        asn1p_expr_t **, size_t);
static int rust_write_set_ber_cer_choice_order(FILE *, const char *, asn1p_expr_t *);
static int rust_write_set_ber_cer_choice_der_group(
    FILE *, const char *, asn1p_expr_t *, const char *, int, size_t,
    asn1p_expr_t **, asn1p_expr_t **, size_t *, unsigned char *, size_t);
static int rust_write_set_ber_cer_choice_der_arms(FILE *, const char *,
                                                   asn1p_expr_t *,
                                                   const char *, int);
static int rust_write_set_ber_cer_choice_variant_order(FILE *, const char *,
                                                        asn1p_expr_t *, uint32_t,
                                                        const char *);
static int rust_write_set_ber_cer_encode_fields(
    FILE *, const char *, asn1p_expr_t *, asn1p_expr_t **, size_t,
    asn1p_expr_t *);
static int rust_write_set_ber_cer_dispatch_choice(FILE *, asn1p_expr_t *,
                                                   const char *);
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
static int rust_write_oid(FILE *, const char *, int, uint64_t);
static int rust_write_oid_ber_cer(FILE *, int, int);
static int rust_write_ia5_string(FILE *, const char *, uint64_t);
static int rust_write_ia5_string_ber_cer(FILE *, int);
static int rust_write_character_string(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_character_string_ber_cer(FILE *, const char *, int);
static int rust_write_utc_time(FILE *, const char *, uint64_t);
static int rust_write_utc_time_ber_cer(FILE *, int);
static int rust_write_generalized_time(FILE *, const char *, uint64_t);
static int rust_write_generalized_time_ber_cer(FILE *, int);
static int rust_write_collection(FILE *, const char *, asn1p_expr_t *, uint64_t);
static int rust_write_collection_codec(FILE *, const char *, const char *, const char *, int);
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
static int rust_write_set_ber_cer(FILE *, const char *, asn1p_expr_t *, int, uint64_t);
static int rust_write_set_ber_cer_decode_method(FILE *, const char *, asn1p_expr_t *, int);
static int rust_write_set_ber_cer_decode_helper(FILE *, const char *, asn1p_expr_t *);
static int rust_write_set(FILE *, const char *, asn1p_expr_t *, int, uint64_t);
static int rust_write_ber_cer_choice(FILE *, const char *, asn1p_expr_t *, uint64_t, int);
static int rust_write_choice_value_conversions(FILE *, asn1p_expr_t *);
static int rust_write_inline_choice_descriptor(FILE *, const char *, asn1p_expr_t *);
static int rust_write_choice_descriptors(FILE *, asn1p_expr_t *);
static int rust_write_choice_to_runtime(FILE *, asn1p_expr_t *);
static int rust_write_choice_from_runtime(FILE *, asn1p_expr_t *);
static int rust_write_choice_absent_arm(FILE *, const asn1p_expr_t *const [3]);
static int rust_write_sequence_ber_cer_encode_field(FILE *, const char *, asn1p_expr_t *);
static int rust_write_sequence_ber_cer_decode_field(FILE *, const char *, asn1p_expr_t *, int);
static int rust_write_sequence_ber_cer_choice_field(FILE *, const char *, asn1p_expr_t *,
                                                    int);
static int rust_write_inline_choice_tag_condition(FILE *, asn1p_expr_t *, int);
static int rust_write_sequence_ber_cer_decode_method(FILE *, const char *, asn1p_expr_t *, int);
static int rust_write_sequence_ber_cer_decode_fields(FILE *, const char *, asn1p_expr_t *);
static int rust_write_nested_ber_cer_fields(FILE *, asn1p_expr_t *, const char *, int);
static int rust_write_nested_ber_cer_decode_value(FILE *, const char *, asn1p_expr_t *,
                                                  const char *);
static int rust_write_set_ber_cer_decode_fields(FILE *, asn1p_expr_t *);
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
 * Validate one direct IA5String record member's approved untagged shape.
 * Parameters: module supplies diagnostics; member is the IA5String AST node.
 * Returns zero when valid or -1 with a source-located diagnostic. Errors:
 * constraints, aliases, tags, unsupported metadata, and DEFAULT are rejected.
 * Source: fixed ASN.1 AST and approved IA5 record gate.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: IA5 flat-record stage. Example: direct optional IA5String passes.
 */
static int
rust_check_ber_cer_ia5_member(asn1p_module_t *module, asn1p_expr_t *member) {
    int valid_shape;
    int natural_tag;
    int no_extensions;
    int supported_presence;
    if(!module || !member) return -1;
    valid_shape = rust_sequence_member_shape_valid(member);
    natural_tag = member->tag.tag_class == TC_NOCLASS
               && member->tag.tag_mode == TM_DEFAULT;
    no_extensions = !member->constraints && !member->combined_constraints
                 && !member->lhs_params && !member->rhs_pspecs
                 && !member->ioc_table && !member->members.tq_head
                 && member->encoding_control.encoding_type == EC_NONE;
    supported_presence = member->marker.flags == EM_NOMARK
                      || member->marker.flags == EM_OPTIONAL;
    if(valid_shape && natural_tag && no_extensions && supported_presence
       && !member->reference) return 0;
    rust_diagnostic(module, member,
        "record IA5String must be direct, unconstrained, natural-tagged, and required or OPTIONAL");
    return -1;
}

/*
 * Validate a flat BER/CER record that contains one natural IA5String field.
 * Parameters: module supplies diagnostics; expr owns the root; codecs is the
 * requested codec mask. Returns zero when no IA5 field exists or the one-field
 * gate passes, otherwise -1. Errors: tags, references, nesting, multiplicity,
 * and unsupported codecs fail before publication. Source: approved IA5 record
 * gate. Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: IA5 record stage. Example: one OPTIONAL field with scalar siblings.
 */
static int
rust_check_ber_cer_ia5_record(asn1p_module_t *module, asn1p_expr_t *expr,
                              uint64_t codecs) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    asn1p_expr_t *member;
    size_t ia5_count = 0;
    if(!module || !expr) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_STRING_IA5String && ++ia5_count > 1) {
            rust_diagnostic(module, member,
                            "BER/CER records support at most one direct IA5String field");
            return -1;
        }
    }
    if(!ia5_count) return 0;
    if(!(codecs & supported) || (codecs & ~supported)
       || expr->tag.tag_class != TC_NOCLASS || expr->tag.tag_mode != TM_DEFAULT) {
        rust_diagnostic(module, expr,
            "record IA5String requires an untagged root and BER/CER-only codecs");
        return -1;
    }
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_STRING_IA5String) {
            if(rust_check_ber_cer_ia5_member(module, member)) return -1;
        } else if(member->expr_type == ASN_CONSTR_SEQUENCE
                  || member->expr_type == ASN_CONSTR_SET
                  || member->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, member,
                            "record IA5String fields do not support nested record members");
            return -1;
        }
    }
    return 0;
}

/*
 * Validate one natural OID field with no constraints or type indirection.
 * Inputs: module supplies diagnostics; member is the resolved component.
 * Returns zero for a required/OPTIONAL direct OID field, otherwise -1.
 * Errors: tags, constraints, references, parameters, and DEFAULT are rejected.
 * Source: fixed ASN.1 AST and approved OID record gate. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: OID record field stage.
 * Example: direct OPTIONAL RELATIVE-OID passes.
 */
static int
rust_check_ber_cer_oid_member(asn1p_module_t *module, asn1p_expr_t *member) {
    int oid_type = member && (member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
                              || member->expr_type == ASN_BASIC_RELATIVE_OID);
    int natural_tag;
    int no_constraints;
    int no_indirection;
    int supported_presence;
    if(!module || !member || !oid_type) return -1;
    natural_tag = member->tag.tag_class == TC_NOCLASS
               && member->tag.tag_mode == TM_DEFAULT;
    no_constraints = !member->constraints && !member->combined_constraints;
    no_indirection = !member->reference && !member->lhs_params
                   && !member->rhs_pspecs && !member->ioc_table
                   && !member->members.tq_head
                   && member->encoding_control.encoding_type == EC_NONE;
    supported_presence = member->marker.flags == EM_NOMARK
                      || member->marker.flags == EM_OPTIONAL;
    if(rust_sequence_member_shape_valid(member) && natural_tag && no_constraints
       && no_indirection && supported_presence) return 0;
    rust_diagnostic(module, member,
        "record OID fields must be direct, unconstrained, natural-tagged, and required or OPTIONAL");
    return -1;
}

/*
 * Validate OID field count, incompatibilities, and record-level codec shape.
 * Parameters: module/expr identify the fixed root; codecs is its selection.
 * Returns zero when no OID exists or the narrow root gate passes, otherwise -1.
 * Errors: mixed IA5, duplicate OID kinds, tags, nesting, and other codecs fail.
 * Source: approved flat OID record gate. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: OBJECT IDENTIFIER record stage.
 * Example: one OID and one RELATIVE-OID fit beside scalar fields.
 */
static int
rust_check_ber_cer_oid_record(asn1p_module_t *module, asn1p_expr_t *expr,
                              uint64_t codecs) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    asn1p_expr_t *member;
    size_t oid_count = 0;
    size_t relative_count = 0;
    int has_ia5 = 0;
    if(!module || !expr) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER) oid_count++;
        if(member->expr_type == ASN_BASIC_RELATIVE_OID) relative_count++;
        if(member->expr_type == ASN_STRING_IA5String) has_ia5 = 1;
    }
    if(!oid_count && !relative_count) return 0;
    if(has_ia5 || oid_count > 1 || relative_count > 1) {
        rust_diagnostic(module, expr,
            "OID records allow at most one of each OID kind and exclude IA5String");
        return -1;
    }
    if(!(codecs & supported) || (codecs & ~supported)
       || expr->tag.tag_class != TC_NOCLASS || expr->tag.tag_mode != TM_DEFAULT) {
        rust_diagnostic(module, expr,
            "record OID fields require an untagged root and BER/CER-only codecs");
        return -1;
    }
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
           || member->expr_type == ASN_BASIC_RELATIVE_OID) {
            if(rust_check_ber_cer_oid_member(module, member)) return -1;
        } else if(member->expr_type == ASN_CONSTR_SEQUENCE
                  || member->expr_type == ASN_CONSTR_SET
                  || member->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, member,
                            "OID record fields do not support nested record members");
            return -1;
        }
    }
    return 0;
}

/*
 * Validate one direct restricted character-string record member.
 * Inputs: module supplies diagnostics; member is the fixed AST component.
 * Returns zero for a natural required/OPTIONAL member, otherwise -1.
 * Errors: constraints, tags, indirection, DEFAULT, and extensions fail closed.
 * Source: approved restricted-string record gate. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: typed record strings.
 * Example: a direct optional UTF8String passes.
 */
static int
rust_check_ber_cer_character_string_member(asn1p_module_t *module,
                                           asn1p_expr_t *member) {
    int supported_presence;
    if(!module || !member || !rust_character_string_kind(member)) return -1;
    supported_presence = member->marker.flags == EM_NOMARK
                      || member->marker.flags == EM_OPTIONAL;
    if(rust_sequence_member_shape_valid(member)
       && member->tag.tag_class == TC_NOCLASS
       && member->tag.tag_mode == TM_DEFAULT
       && !member->constraints && !member->combined_constraints
       && !member->reference && !member->members.tq_head
       && member->encoding_control.encoding_type == EC_NONE
       && supported_presence) return 0;
    rust_diagnostic(module, member,
        "restricted string record fields must be direct, natural, unconstrained, "
        "and required or OPTIONAL");
    return -1;
}

/*
 * Count supported strings and detect other variable/default record fields.
 * Inputs: expr owns flat members; count and excluded receive the results.
 * Returns zero or -1 for invalid helper arguments. Errors: none.
 * Source: approved restricted-string record gate. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: fail-closed field scan.
 * Example: UTF8String plus BOOLEAN returns count one and excluded zero.
 */
static int
rust_ber_cer_character_string_record_scan(asn1p_expr_t *expr, size_t *count,
                                          int *excluded) {
    asn1p_expr_t *member;
    if(!expr || !count || !excluded) return -1;
    *count = 0;
    *excluded = 0;
    TQ_FOR(member, &expr->members, next) {
        if(rust_character_string_kind(member)) (*count)++;
        if(member->expr_type == ASN_STRING_IA5String
           || member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
           || member->expr_type == ASN_BASIC_RELATIVE_OID
           || member->expr_type == ASN_BASIC_CHARACTER_STRING
           || (member->expr_type == ASN_BASIC_INTEGER && !member->constraints
               && !member->combined_constraints)
           || member->marker.flags == EM_DEFAULT) *excluded = 1;
    }
    return 0;
}

/*
 * Validate allowed scalar siblings after the string root gate passes.
 * Inputs: module supplies diagnostics; expr owns the record members.
 * Returns zero when no nested or CHOICE child is present, otherwise -1.
 * Errors: nested constructors and CHOICE receive a source diagnostic.
 * Source: approved flat restricted-string record subset.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: one variable field per record. Example: BOOLEAN remains eligible.
 */
static int
rust_check_ber_cer_character_string_siblings(asn1p_module_t *module,
                                             asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET
           || member->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, member,
                "restricted-string records do not support nested records or CHOICE");
            return -1;
        }
        if(rust_character_string_kind(member)
           && rust_check_ber_cer_character_string_member(module, member)) return -1;
    }
    return 0;
}

/*
 * Gate one non-IA5 restricted string in a flat BER/CER record.
 * Inputs: module/expr identify the fixed record; codecs is its selected mask.
 * Returns zero when absent or when the one-field shape passes, otherwise -1.
 * Errors: root tags, other variable fields, multiple strings, and codecs reject.
 * Source: approved restricted-string field design. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: flat typed-string records.
 * Example: one required UTF8String beside BOOLEAN passes.
 */
static int
rust_check_ber_cer_character_string_record(asn1p_module_t *module,
                                           asn1p_expr_t *expr, uint64_t codecs) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    size_t count;
    int excluded;
    if(!module || !expr
       || rust_ber_cer_character_string_record_scan(expr, &count, &excluded)) return -1;
    if(!count) return 0;
    if(count > 1 || excluded || !(codecs & supported) || (codecs & ~supported)
       || expr->tag.tag_class != TC_NOCLASS || expr->tag.tag_mode != TM_DEFAULT) {
        rust_diagnostic(module, expr,
            "restricted-string records require one untagged natural string, scalar "
            "siblings, and BER/CER-only codecs");
        return -1;
    }
    return rust_check_ber_cer_character_string_siblings(module, expr);
}

/*
 * Validate one unconstrained INTEGER record component.
 * Inputs: module supplies diagnostics; member is the resolved component.
 * Returns zero for a direct natural required/OPTIONAL field, otherwise -1.
 * Errors: tags, constraints, indirection, DEFAULT, and metadata fail closed.
 * Source: fixed ASN.1 AST and approved BigInteger record gate.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: arbitrary-precision INTEGER records. Example: OPTIONAL INTEGER.
 */
static int
rust_check_ber_cer_big_integer_member(asn1p_module_t *module,
                                     asn1p_expr_t *member) {
    int supported_presence;
    if(!module || !member || member->expr_type != ASN_BASIC_INTEGER) return -1;
    supported_presence = member->marker.flags == EM_NOMARK
                      || member->marker.flags == EM_OPTIONAL;
    if(rust_sequence_member_shape_valid(member)
       && member->tag.tag_class == TC_NOCLASS
       && member->tag.tag_mode == TM_DEFAULT
       && !member->constraints && !member->combined_constraints
       && !member->reference && !member->members.tq_head
       && member->encoding_control.encoding_type == EC_NONE
       && supported_presence) return 0;
    rust_diagnostic(module, member,
        "unconstrained INTEGER record fields must be direct, natural, and required or OPTIONAL");
    return -1;
}

/*
 * Identify an unconstrained direct INTEGER AST node.
 * Input: expr is one fixed type/member node. Returns one for unbounded INTEGER.
 * Errors: none. Source: ASN.1 fixed AST. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: BigInteger record gate.
 * Example: INTEGER (0..5) returns zero; INTEGER returns one.
 */
static int
rust_ber_cer_is_unbounded_integer(const asn1p_expr_t *expr) {
    return expr && expr->expr_type == ASN_BASIC_INTEGER
        && !expr->constraints && !expr->combined_constraints;
}

/*
 * Count unbounded INTEGER members and note excluded variable string families.
 * Inputs: expr is the flat record; has_ia5/has_oid receive family flags.
 * Returns the number of unconstrained INTEGER members. Errors: none.
 * Source: fixed ASN.1 AST. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: record eligibility scan.
 * Example: an INTEGER plus IA5String returns one and sets has_ia5.
 */
static size_t
rust_ber_cer_big_integer_member_count(asn1p_expr_t *expr, int *has_ia5,
                                     int *has_oid) {
    asn1p_expr_t *member;
    size_t count = 0;
    if(!expr || !has_ia5 || !has_oid) return 0;
    *has_ia5 = 0;
    *has_oid = 0;
    TQ_FOR(member, &expr->members, next) {
        if(rust_ber_cer_is_unbounded_integer(member)) count++;
        if(member->expr_type == ASN_STRING_IA5String) *has_ia5 = 1;
        if(member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
           || member->expr_type == ASN_BASIC_RELATIVE_OID) *has_oid = 1;
    }
    return count;
}

/*
 * Validate all fields once a record has passed its root-level BigInteger gate.
 * Inputs: module and expr identify the direct record AST.
 * Returns zero for valid direct fields, otherwise -1. Errors: nested fields or
 * malformed BigInteger members receive a source-located diagnostic.
 * Source: approved BigInteger record design. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: fail-closed member validation.
 * Example: a bounded INTEGER sibling remains eligible.
 */
static int
rust_check_ber_cer_big_integer_record_members(asn1p_module_t *module,
                                             asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        if(rust_ber_cer_is_unbounded_integer(member)
           && rust_check_ber_cer_big_integer_member(module, member)) return -1;
        if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET
           || member->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, member,
                            "BigInteger records do not support nested record members");
            return -1;
        }
    }
    return 0;
}

/*
 * Gate flat BER/CER records containing one unbounded signed INTEGER.
 * Parameters: module/expr identify the fixed record; codecs is selected.
 * Returns zero when absent or when the narrow record shape passes, else -1.
 * Errors: tags, constraints, aliases, nesting, OID/IA5, and other codecs fail.
 * Source: approved BigInteger record design. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: BigInteger record stage.
 * Example: one OPTIONAL INTEGER alongside BOOLEAN and OCTET STRING.
 */
static int
rust_check_ber_cer_big_integer_record(asn1p_module_t *module,
                                      asn1p_expr_t *expr, uint64_t codecs) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    size_t count;
    int has_ia5;
    int has_oid;
    if(!module || !expr) return -1;
    count = rust_ber_cer_big_integer_member_count(expr, &has_ia5, &has_oid);
    if(!count) return 0;
    if(count > 1 || has_ia5 || has_oid || !(codecs & supported)
       || (codecs & ~supported) || expr->tag.tag_class != TC_NOCLASS
       || expr->tag.tag_mode != TM_DEFAULT) {
        rust_diagnostic(module, expr,
            "BigInteger records require one untagged field and BER/CER-only codecs; "
            "IA5String and OID fields are excluded");
        return -1;
    }
    return rust_check_ber_cer_big_integer_record_members(module, expr);
}

/*
 * Validate the reference node before looking up its target.
 * Inputs: member is a fixed-tree field. Returns one for one simple local name.
 * Errors: malformed references and parameterized fields return zero.
 * Source: parser reference AST. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named INTEGER field gate.
 * Example: `n Small` passes this shape check.
 */
static int
rust_ber_cer_named_reference_shape(const asn1p_expr_t *member) {
    return member && member->meta_type == AMT_TYPEREF
        && member->expr_type == A1TC_REFERENCE && member->reference
        && member->reference->comp_count == 1
        && member->reference->components[0].name && !member->rhs_pspecs
        && !member->lhs_params && !member->ioc_table && !member->members.tq_head
        && member->encoding_control.encoding_type == EC_NONE;
}

/*
 * Check that a target is a direct, untagged bounded INTEGER assignment.
 * Inputs: module owns declarations; target/name identify the resolved symbol.
 * Returns one when direct and local, otherwise zero. Errors: unsupported metadata.
 * Source: fixed type assignment AST. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: bounded named INTEGER fields.
 * Example: direct `Small ::= INTEGER (0..5)` passes.
 */
static int
rust_ber_cer_named_integer_target_shape(asn1p_module_t *module,
                                        asn1p_expr_t *target,
                                        const char *name) {
    return module && target && target->module == module
        && target->meta_type == AMT_TYPE && target->expr_type == ASN_BASIC_INTEGER
        && target->Identifier && name && !strcmp(target->Identifier, name)
        && !target->reference && !target->lhs_params && !target->rhs_pspecs
        && !target->ioc_table && !target->members.tq_head
        && target->tag.tag_class == TC_NOCLASS && target->tag.tag_mode == TM_DEFAULT
        && target->marker.flags == EM_NOMARK
        && target->encoding_control.encoding_type == EC_NONE;
}

/*
 * Check for exactly one finite contiguous INTEGER constraint range.
 * Inputs: target is a direct INTEGER assignment. Returns one when its range
 * fits i64 and has one range leaf; otherwise zero. Errors: unsupported bounds.
 * Source: fixed constraint AST and Rust i64 wrapper. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named INTEGER range validation.
 * Example: `INTEGER (0..5)` passes; an interval union is rejected.
 */
static int
rust_ber_cer_named_integer_target_range(asn1p_expr_t *target) {
    int64_t lower, upper;
    int range_seen = 0;
    return target && target->combined_constraints
        && rust_integer_single_range_supported(target->combined_constraints, 0,
                                                &range_seen)
        && range_seen && !rust_integer_bounds(target, &lower, &upper);
}

/*
 * Confirm a resolved target is one of the module's direct assignments.
 * Inputs: module owns the assignment list; target is the resolved AST node.
 * Returns one when pointer identity is found, otherwise zero; no errors raised.
 * Source: fixed ASN.1 module tree. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: reject forks and foreign nodes.
 * Example: the module's `Small` pointer is found in its members list.
 */
static int
rust_ber_cer_named_target_is_local_assignment(asn1p_module_t *module,
                                              asn1p_expr_t *target) {
    asn1p_expr_t *assignment;
    TQ_FOR(assignment, &module->members, next) {
        if(assignment == target) return 1;
    }
    return 0;
}

/*
 * Resolve a fixed-tree field reference to its same-module INTEGER assignment.
 * Inputs: member is a type-reference field with retrieval metadata populated.
 * Returns a direct bounded target or NULL. Errors: unsupported shapes fail closed.
 * Source: fixed-tree reference metadata. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named INTEGER record gate.
 * Example: a field referencing local `Small ::= INTEGER (0..5)` resolves Small.
 */
static asn1p_expr_t *
rust_ber_cer_named_integer_target(const asn1p_expr_t *member) {
    asn1p_module_t *module;
    asn1p_expr_t *target;
    const char *name;
    if(!rust_ber_cer_named_reference_shape(member)) return NULL;
    module = member->module;
    target = member->reference->ref_expr;
    name = member->reference->components[0].name;
    if(!rust_ber_cer_named_integer_target_shape(module, target, name)
       || !rust_ber_cer_named_integer_target_range(target)
       || !rust_ber_cer_named_target_is_local_assignment(module, target)) return NULL;
    return target;
}

/*
 * Resolve one fixed-tree reference to a direct local named SEQUENCE.
 * Inputs: member is a simple type-reference field. Returns its target or NULL.
 * Errors: aliases, imports, tags, parameters, and malformed reference metadata
 * fail closed. Source: resolved ASN.1 assignment AST. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named child composition.
 * Example: a field referencing `Inner ::= SEQUENCE { ... }` resolves Inner.
 */
static asn1p_expr_t *
rust_ber_cer_named_sequence_target(const asn1p_expr_t *member) {
    asn1p_module_t *module;
    asn1p_expr_t *target;
    const char *name;
    if(!rust_ber_cer_named_reference_shape(member)) return NULL;
    module = member->module;
    target = member->reference->ref_expr;
    name = member->reference->components[0].name;
    if(!rust_ber_cer_named_sequence_target_shape(module, target, name)) return NULL;
    if(!rust_ber_cer_named_target_is_local_assignment(module, target)) return NULL;
    return target;
}

/*
 * Validate assignment metadata for a direct named SEQUENCE target.
 * Inputs: module owns target; name is the one resolved reference component.
 * Returns one for an untagged, unconstrained direct SEQUENCE assignment.
 * Errors: aliases, constraints, extensions, parameters, and encoding controls
 * return zero. Source: fixed ASN.1 type-assignment AST. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named child gate.
 * Example: direct `Inner ::= SEQUENCE { ... }` passes.
 */
static int
rust_ber_cer_named_sequence_target_shape(asn1p_module_t *module,
                                         asn1p_expr_t *target,
                                         const char *name) {
    return module && target && target->module == module
        && target->meta_type == AMT_TYPE && target->expr_type == ASN_CONSTR_SEQUENCE
        && target->Identifier && name && !strcmp(target->Identifier, name)
        && !target->reference && !target->constraints && !target->combined_constraints
        && !target->lhs_params && !target->rhs_pspecs && !target->ioc_table
        && target->marker.flags == EM_NOMARK
        && target->tag.tag_class == TC_NOCLASS && target->tag.tag_mode == TM_DEFAULT
        && target->encoding_control.encoding_type == EC_NONE;
}

/*
 * Validate one named child field and its direct child leaf record.
 * Inputs: module supplies diagnostics; owner/member identify parent and field;
 * work accumulates child leaf checks against the generated-record ceiling.
 * Returns zero or -1. Errors: recursive, constrained, tagged, or unsupported
 * children are diagnosed. Source: named SEQUENCE composition design.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: direct named child gate. Example: required `child Inner` is accepted.
 */
static int
rust_check_ber_cer_named_sequence_member(asn1p_module_t *module,
                                         asn1p_expr_t *owner,
                                         asn1p_expr_t *member, size_t *work) {
    asn1p_expr_t *target = rust_ber_cer_named_sequence_target(member);
    int tag_class;
    uint32_t tag_number;
    int supported_tag;
    int supported_presence;
    if(!module || !owner || !member || !work) return -1;
    supported_tag = !rust_ber_cer_member_tag(member, &tag_class, &tag_number);
    supported_presence = member->marker.flags == EM_NOMARK
                      || member->marker.flags == EM_OPTIONAL;
    if(!target || target == owner || member->module != module
       || member->constraints || member->combined_constraints
       || !supported_tag || !supported_presence
       || !rust_ber_cer_nested_record_shape_valid(target)) {
        rust_diagnostic(module, member,
            "named SEQUENCE fields need one direct same-module untagged child "
            "with supported member tags and required or OPTIONAL presence");
        return -1;
    }
    return rust_check_ber_cer_nested_record(module, target, work);
}

/*
 * Validate one named INTEGER reference and its supported member tags.
 * Inputs: module supplies diagnostics; member is the fixed record field.
 * Returns zero for a required/OPTIONAL natural or context-tagged field, else -1.
 * Errors: extra constraints, DEFAULT, imports, aliases, or bad tags reject.
 * Source: approved named INTEGER reference gate. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: bounded named fields.
 * Example: `[3] EXPLICIT Small OPTIONAL` passes for a valid local Small.
 */
static int
rust_check_ber_cer_named_integer_member(asn1p_module_t *module,
                                        asn1p_expr_t *member) {
    asn1p_expr_t *target;
    int supported_tag;
    int supported_presence;
    if(!module || !member) return -1;
    target = rust_ber_cer_named_integer_target(member);
    supported_tag = member->tag.tag_class == TC_NOCLASS
                 ? member->tag.tag_mode == TM_DEFAULT
                 : member->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && (member->tag.tag_mode == TM_IMPLICIT
                       || member->tag.tag_mode == TM_EXPLICIT)
                   && member->tag.tag_value >= 0
                   && member->tag.tag_value <= (asn1c_integer_t)UINT32_C(0x3fffffff);
    supported_presence = member->marker.flags == EM_NOMARK
                      || member->marker.flags == EM_OPTIONAL;
    if(target && member->module == module && !member->constraints
       && supported_tag && supported_presence) return 0;
    rust_diagnostic(module, member,
        "named INTEGER fields need one direct same-module bounded type reference "
        "without member constraints or DEFAULT");
    return -1;
}

/*
 * Identify a variable or constructed sibling outside this field gate.
 * Inputs: member is one record component. Returns one when excluded, else zero.
 * Errors: none. Source: approved named INTEGER record subset.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: keep this gate to scalar siblings. Example: OID returns one.
 */
static int
rust_ber_cer_named_integer_excluded_sibling(const asn1p_expr_t *member) {
    if(!member) return 1;
    if(rust_character_string_kind(member)) return 1;
    switch(member->expr_type) {
    case ASN_STRING_IA5String:
    case ASN_BASIC_OBJECT_IDENTIFIER:
    case ASN_BASIC_RELATIVE_OID:
    case ASN_BASIC_CHARACTER_STRING:
    case ASN_CONSTR_SEQUENCE:
    case ASN_CONSTR_SET:
    case ASN_CONSTR_CHOICE:
    case ASN_CONSTR_SEQUENCE_OF:
    case ASN_CONSTR_SET_OF:
        return 1;
    case ASN_BASIC_OCTET_STRING:
    case ASN_BASIC_BIT_STRING:
        return !member->constraints && !member->combined_constraints;
    case ASN_BASIC_INTEGER:
        return !member->constraints && !member->combined_constraints;
    default:
        return 0;
    }
}

/*
 * Count references and scan for excluded siblings in one root record.
 * Inputs: expr owns fields; references/excluded receive bounded scan results.
 * Returns zero or -1 for invalid output pointers; no exceptions.
 * Source: fixed record member list. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named field preflight.
 * Example: one `Small` reference plus BOOLEAN reports one and no exclusions.
 */
static int
rust_ber_cer_named_integer_record_scan(asn1p_expr_t *expr, size_t *references,
                                       int *excluded) {
    asn1p_expr_t *member;
    if(!expr || !references || !excluded) return -1;
    *references = 0;
    *excluded = 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == A1TC_REFERENCE) (*references)++;
        if(rust_ber_cer_named_integer_excluded_sibling(member)) *excluded = 1;
    }
    return 0;
}

/*
 * Validate root tags, reference count, sibling families, and codec selection.
 * Inputs: expr/root fields, references/excluded scan values, and codecs.
 * Returns one when the root gate shape is supported, otherwise zero.
 * Errors: none; caller emits the source-located diagnostic.
 * Source: approved named INTEGER record design. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: flat reference gate.
 * Example: BER/CER-only untagged root with one reference passes.
 */
static int
rust_ber_cer_named_integer_record_shape(const asn1p_expr_t *expr,
                                       uint64_t codecs, size_t references,
                                       int excluded) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    return expr && references == 1 && !excluded
        && (codecs & supported) && !(codecs & ~supported)
        && expr->tag.tag_class == TC_NOCLASS && expr->tag.tag_mode == TM_DEFAULT;
}

/*
 * Gate one named INTEGER field in an otherwise scalar flat record.
 * Inputs: module/expr identify the root; codecs is the selected codec mask.
 * Returns zero when absent or accepted, otherwise -1 with a diagnostic.
 * Errors: multiple references, variable/nested siblings, tags, or codecs reject.
 * Source: approved named INTEGER field design. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: same-module reference support.
 * Example: `Small` beside BOOLEAN and bounded OCTET STRING passes.
 */
static int
rust_check_ber_cer_named_integer_record(asn1p_module_t *module,
                                        asn1p_expr_t *expr, uint64_t codecs) {
    size_t references;
    int excluded;
    asn1p_expr_t *member;
    if(!module || !expr
       || rust_ber_cer_named_integer_record_scan(expr, &references, &excluded))
        return -1;
    if(!references) return 0;
    if(references == 1) {
        TQ_FOR(member, &expr->members, next) {
            if(member->expr_type == A1TC_REFERENCE && member->reference
               && member->reference->ref_expr
               && member->reference->ref_expr->expr_type == ASN_CONSTR_SEQUENCE)
                return 0;
        }
    }
    if(!rust_ber_cer_named_integer_record_shape(expr, codecs, references,
                                                excluded)) {
        rust_diagnostic(module, expr,
            "named INTEGER records require one untagged reference, scalar siblings, "
            "and BER/CER-only codecs");
        return -1;
    }
    return 0;
}

/*
 * Preflight one named SEQUENCE reference and its scalar parent siblings.
 * Inputs: module/expr identify the flat parent; codecs is its selected mask.
 * Returns zero when absent or structurally supported, otherwise -1.
 * Errors: multiple children, incompatible siblings, tags, roots, or codecs fail.
 * Source: named child composition design. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: single named child gate.
 * Example: one required `Inner` beside BOOLEAN passes for BER/CER-only.
 */
static int
rust_ber_cer_named_sequence_parent_scan(asn1p_expr_t *expr,
                                        asn1p_expr_t **child_out,
                                        size_t *references_out,
                                        int *excluded_out) {
    asn1p_expr_t *member;
    if(!expr || !child_out || !references_out || !excluded_out) return -1;
    *child_out = NULL;
    *references_out = 0;
    *excluded_out = 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == A1TC_REFERENCE) {
            (*references_out)++;
            *child_out = member;
        } else if(rust_ber_cer_named_integer_excluded_sibling(member)) {
            *excluded_out = 1;
        }
    }
    return 0;
}

/*
 * Validate a named-child parent root and its codec mask.
 * Inputs: expr is a flat parent; codecs is the requested selection.
 * Returns one for an untagged SEQUENCE/SET with BER/CER-only methods.
 * Errors: roots with constraints, tags, parameters, or controls return zero.
 * Source: named child composition gate. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: parent root validation.
 * Example: an untagged Packet SEQUENCE with BER/CER passes.
 */
static int
rust_ber_cer_named_sequence_parent_root_valid(asn1p_expr_t *expr,
                                              uint64_t codecs) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    return expr && (expr->expr_type == ASN_CONSTR_SEQUENCE
                    || expr->expr_type == ASN_CONSTR_SET)
        && (codecs & supported) && !(codecs & ~supported)
        && expr->tag.tag_class == TC_NOCLASS && expr->tag.tag_mode == TM_DEFAULT
        && !expr->constraints && !expr->combined_constraints && !expr->lhs_params
        && !expr->ioc_table && !expr->marker.flags && !expr->rhs_pspecs
        && expr->encoding_control.encoding_type == EC_NONE;
}

/*
 * Validate one named-child root candidate and its permitted direct siblings.
 * Inputs: expr/child identify the parent and child; references/excluded are scan results.
 * Returns one when one local named SEQUENCE and supported siblings are present.
 * Errors: unsupported child references, siblings, or root metadata return zero.
 * Source: named child composition gate. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: bounded parent structure.
 * Example: one `Inner` reference plus BOOLEAN returns one.
 */
static int
rust_ber_cer_named_sequence_parent_shape(asn1p_expr_t *expr,
                                         asn1p_expr_t *child,
                                         size_t references, int excluded,
                                         uint64_t codecs) {
    if(references != 1 || !child || excluded
       || !rust_ber_cer_named_sequence_target(child)) return 0;
    return rust_ber_cer_named_sequence_parent_root_valid(expr, codecs);
}

/*
 * Preflight one named SEQUENCE reference and its scalar parent siblings.
 * Inputs: module/expr identify the flat parent; codecs is its selected mask.
 * Returns zero when absent or structurally supported, otherwise -1.
 * Errors: multiple children, incompatible siblings, tags, roots, or codecs fail.
 * Source: named child composition design. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: single named child gate.
 * Example: one required `Inner` beside BOOLEAN passes for BER/CER-only.
 */
static int
rust_check_ber_cer_named_sequence_record(asn1p_module_t *module,
                                         asn1p_expr_t *expr, uint64_t codecs) {
    asn1p_expr_t *child;
    size_t references;
    int excluded;
    if(!module || !expr
       || rust_ber_cer_named_sequence_parent_scan(expr, &child, &references,
                                                  &excluded)) return -1;
    if(!references) return 0;
    if(references == 1 && child && child->reference && child->reference->ref_expr
       && child->reference->ref_expr->expr_type != ASN_CONSTR_SEQUENCE) return 0;
    if(!rust_ber_cer_named_sequence_parent_shape(expr, child, references,
                                                 excluded, codecs)) {
        rust_diagnostic(module, expr,
            "named SEQUENCE children require one untagged direct child, scalar "
            "siblings, and BER/CER-only codecs");
        return -1;
    }
    return 0;
}

/*
 * Validate module, type, constraint, and naming support before creating files.
 * Parameters: asn is the complete fixed tree; codecs is the requested mask.
 * Returns zero when at least one supported assignment exists, otherwise -1.
 * Errors: diagnostics retain ASN.1 source names and line numbers; no exception.
 * Source: new Rust backend. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: initial UPER type gate.
 * Example: rust_check_tree(fixed_tree).
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

/* Validate the codec mask for a direct unconstrained OID assignment.
 * Inputs: module and expr identify the type; codecs is the selected mask.
 * Returns zero for BER/CER-only selection, otherwise -1 with a diagnostic.
 * Errors: no exception. Original source: approved OID generator gate.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: direct OBJECT IDENTIFIER and RELATIVE-OID support.
 * Example: selecting BER and CER for an OBJECT IDENTIFIER is accepted.
 */
static int
rust_check_oid_codecs(asn1p_module_t *module, asn1p_expr_t *expr,
                      uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    const char *kind = expr->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
        ? "OBJECT IDENTIFIER" : "RELATIVE-OID";
    char diagnostic[128];
    int count;
    if(codecs && !(codecs & ~ber_cer)) return 0;
    count = snprintf(diagnostic, sizeof(diagnostic),
                     "unconstrained %s requires BER/CER-only codec selection", kind);
    if(count < 0 || (size_t)count >= sizeof(diagnostic)) return -1;
    rust_diagnostic(module, expr, diagnostic);
    return -1;
}

/* Validate BER/CER-only selection for one direct IA5String root.
 * Inputs: module and expr identify the fixed assignment; codecs is selected.
 * Returns zero for a nonempty BER/CER-only mask, otherwise -1 with a diagnostic.
 * Errors: no exception. Source: approved direct IA5String generator gate.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: raw-byte BER/DER with strict CER support.
 * Example: BER plus CER is accepted; BER plus UPER is refused.
 */
static int
rust_check_ia5_codecs(asn1p_module_t *module, asn1p_expr_t *expr,
                      uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    if(codecs && !(codecs & ~ber_cer)) return 0;
    rust_diagnostic(module, expr,
                    "unconstrained IA5String requires BER/CER-only codec selection");
    return -1;
}

/* Map one supported restricted-string AST type to its runtime kind.
 * Inputs: expr is a fixed parser-tree assignment. Returns a runtime enum
 * variant name, or NULL for every type outside the approved direct-string set.
 * Errors: none. Source: approved restricted-string BER/CER gate.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers. History: direct
 * restricted roots. Example: ASN_STRING_ISO646String maps to Iso646String.
 */
static const char *
rust_character_string_kind(const asn1p_expr_t *expr) {
    switch(expr->expr_type) {
    case ASN_STRING_ObjectDescriptor: return "ObjectDescriptor";
    case ASN_STRING_UTF8String: return "Utf8String";
    case ASN_STRING_NumericString: return "NumericString";
    case ASN_STRING_PrintableString: return "PrintableString";
    case ASN_STRING_TeletexString: return "TeletexString";
    case ASN_STRING_T61String: return "T61String";
    case ASN_STRING_VideotexString: return "VideotexString";
    case ASN_STRING_GraphicString: return "GraphicString";
    case ASN_STRING_VisibleString: return "VisibleString";
    case ASN_STRING_ISO646String: return "Iso646String";
    case ASN_STRING_GeneralString: return "GeneralString";
    case ASN_STRING_UniversalString: return "UniversalString";
    case ASN_STRING_BMPString: return "BmpString";
    default: return NULL;
    }
}

/* Return the ASN.1 spelling used in direct-string diagnostics.
 * Inputs: expr is a fixed parser-tree assignment. Returns a static string or
 * NULL for types outside the approved set. Errors: none. Source: ASN.1 lexer.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers. History: direct
 * restricted roots. Example: T61String is kept distinct from TeletexString.
 */
static const char *
rust_character_string_name(const asn1p_expr_t *expr) {
    switch(expr->expr_type) {
    case ASN_STRING_ObjectDescriptor: return "ObjectDescriptor";
    case ASN_STRING_UTF8String: return "UTF8String";
    case ASN_STRING_NumericString: return "NumericString";
    case ASN_STRING_PrintableString: return "PrintableString";
    case ASN_STRING_TeletexString: return "TeletexString";
    case ASN_STRING_T61String: return "T61String";
    case ASN_STRING_VideotexString: return "VideotexString";
    case ASN_STRING_GraphicString: return "GraphicString";
    case ASN_STRING_VisibleString: return "VisibleString";
    case ASN_STRING_ISO646String: return "ISO646String";
    case ASN_STRING_GeneralString: return "GeneralString";
    case ASN_STRING_UniversalString: return "UniversalString";
    case ASN_STRING_BMPString: return "BMPString";
    default: return NULL;
    }
}

/* Validate one direct restricted-string assignment and its codec selection.
 * Inputs: module/expr identify the assignment; codecs is its selected mask.
 * Returns zero when supported or -1 after a located diagnostic. Errors: none.
 * Source: approved restricted-string gate. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: direct roots. Example: UTF8String.
 */
static int
rust_check_character_string(asn1p_module_t *module, asn1p_expr_t *expr,
                            uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    const char *name = rust_character_string_name(expr);
    char diagnostic[160];
    int count;
    if(!name) return -1;
    if(expr->constraints || expr->combined_constraints || expr->reference
       || expr->rhs_pspecs || expr->marker.flags != EM_NOMARK
       || expr->lhs_params || expr->ioc_table || expr->members.tq_head) {
        count = snprintf(diagnostic, sizeof(diagnostic),
                         "%s requires a direct untagged unconstrained root", name);
        if(count < 0 || (size_t)count >= sizeof(diagnostic)) return -1;
        rust_diagnostic(module, expr, diagnostic);
        return -1;
    }
    if(codecs && !(codecs & ~ber_cer)) return 0;
    count = snprintf(diagnostic, sizeof(diagnostic),
                     "unconstrained %s requires BER/CER-only codec selection", name);
    if(count < 0 || (size_t)count >= sizeof(diagnostic)) return -1;
    rust_diagnostic(module, expr, diagnostic);
    return -1;
}

/* Validate one direct untagged UTCTime assignment and codec selection.
 * Inputs: module/expr identify the fixed parser-tree root; codecs is selected.
 * Returns zero for a supported raw root or -1 with a source diagnostic.
 * Errors: no exception. Source: approved UTCTime BER/CER gate.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers. History: direct
 * universal tag 23 support. Example: BER plus CER is accepted.
 */
static int
rust_check_utc_time(asn1p_module_t *module, asn1p_expr_t *expr,
                    uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    if(expr->constraints || expr->combined_constraints || expr->reference
       || expr->rhs_pspecs || expr->marker.flags != EM_NOMARK
       || expr->lhs_params || expr->ioc_table || expr->members.tq_head) {
        rust_diagnostic(module, expr,
                        "UTCTime requires a direct untagged unconstrained root");
        return -1;
    }
    if(codecs && !(codecs & ~ber_cer)) return 0;
    rust_diagnostic(module, expr,
                    "UTCTime requires BER/CER-only codec selection");
    return -1;
}

/* Validate a direct untagged GeneralizedTime root and its codec selection.
 * Inputs: module/expr identify the parser-tree root; codecs is the selection.
 * Returns zero when supported or -1 after a located diagnostic. Errors: none.
 * Source: approved GeneralizedTime BER/CER gate. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: direct universal tag 24.
 * Example: BER plus CER is accepted for an unconstrained root.
 */
static int
rust_check_generalized_time(asn1p_module_t *module, asn1p_expr_t *expr,
                            uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    if(expr->constraints || expr->combined_constraints || expr->reference
       || expr->rhs_pspecs || expr->marker.flags != EM_NOMARK
       || expr->lhs_params || expr->ioc_table || expr->members.tq_head) {
        rust_diagnostic(module, expr,
            "GeneralizedTime requires a direct untagged unconstrained root");
        return -1;
    }
    if(codecs && !(codecs & ~ber_cer)) return 0;
    rust_diagnostic(module, expr,
                    "GeneralizedTime requires BER/CER-only codec selection");
    return -1;
}

/* Validate one direct, untagged BER/CER collection with a supported leaf.
 * Inputs: module/expr identify the fixed root; codecs is the selected mask.
 * Returns zero when supported, otherwise -1 with a located diagnostic.
 * Errors: no exception. Source: approved collection BER/CER gate.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers. History: initial
 * SEQUENCE OF/SET OF slice. Example: `SEQUENCE OF BOOLEAN` passes.
 */
static int
rust_check_collection(asn1p_module_t *module, asn1p_expr_t *expr,
                      uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    asn1p_expr_t *element = TQ_FIRST(&expr->members);
    int64_t lower, upper;

    if(!codecs || (codecs & ~ber_cer)) goto unsupported_root;
    if(expr->constraints || expr->combined_constraints || expr->reference
       || expr->lhs_params || expr->rhs_pspecs || expr->ioc_table
       || expr->with_syntax || expr->marker.flags != EM_NOMARK
       || expr->marker.default_value || expr->unique
       || expr->tag.tag_class != TC_NOCLASS || expr->tag.tag_mode != TM_DEFAULT
       || !element
       || TQ_NEXT(element, next)) goto unsupported_root;
    if(element->reference || element->lhs_params || element->rhs_pspecs
       || element->ioc_table || element->with_syntax
       || element->marker.flags != EM_NOMARK || element->marker.default_value
       || element->tag.tag_class != TC_NOCLASS
       || element->tag.tag_mode != TM_DEFAULT || element->members.tq_head
       || element->unique) {
        rust_diagnostic(module, element,
                        "collection elements must be direct untagged primitive types");
        return -1;
    }
    if(element->expr_type == ASN_BASIC_BOOLEAN
       || element->expr_type == ASN_BASIC_NULL) {
        if(element->constraints || element->combined_constraints) {
            rust_diagnostic(module, element,
                            "BOOLEAN and NULL collection elements cannot have constraints");
            return -1;
        }
        return 0;
    }
    if(element->expr_type == ASN_BASIC_INTEGER && element->combined_constraints
       && rust_constraint_supported(element->combined_constraints, 0)
       && !rust_integer_bounds(element, &lower, &upper)) return 0;
    rust_diagnostic(module, element,
                    "collection element must be BOOLEAN, NULL, or bounded i64 INTEGER");
    return -1;

unsupported_root:
    rust_diagnostic(module, expr,
        "SEQUENCE OF/SET OF requires one untagged, unconstrained direct element and BER/CER-only codecs");
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
    if(expr->expr_type == ASN_CONSTR_SEQUENCE_OF
       || expr->expr_type == ASN_CONSTR_SET_OF)
        return rust_check_collection(module, expr, codecs);
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
        return codecs == RUST_CODEC_CBOR
            ? rust_check_cbor_choice(module, expr, codecs)
            : rust_check_ber_cer_choice(module, expr, codecs);
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
    if(expr->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
       || expr->expr_type == ASN_BASIC_RELATIVE_OID) {
        if(expr->constraints || expr->combined_constraints || expr->reference
           || expr->rhs_pspecs || expr->marker.flags != EM_NOMARK) {
            rust_diagnostic(module, expr,
                "OBJECT IDENTIFIER and RELATIVE-OID require direct unconstrained roots");
            return -1;
        }
        return rust_check_oid_codecs(module, expr, codecs);
    }
    if(expr->expr_type == ASN_STRING_IA5String) {
        if(expr->constraints || expr->combined_constraints || expr->reference
           || expr->rhs_pspecs || expr->marker.flags != EM_NOMARK) {
            rust_diagnostic(module, expr,
                "IA5String requires a direct untagged unconstrained root");
            return -1;
        }
        return rust_check_ia5_codecs(module, expr, codecs);
    }
    if(rust_character_string_kind(expr))
        return rust_check_character_string(module, expr, codecs);
    if(expr->expr_type == ASN_BASIC_UTCTime)
        return rust_check_utc_time(module, expr, codecs);
    if(expr->expr_type == ASN_BASIC_GeneralizedTime)
        return rust_check_generalized_time(module, expr, codecs);
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
    if(rust_check_ber_cer_ia5_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_character_string_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_big_integer_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_oid_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_named_integer_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_named_sequence_record(module, expr, codecs)) return -1;
    if(rust_check_sequence_tree(module, expr, stack, 0, &nodes, &work, codecs)) return -1;
    if((codecs & RUST_CODEC_UPER)
       && (codecs & (RUST_CODEC_BER | RUST_CODEC_CER))
       && rust_ber_cer_has_empty_nested_record(expr)) {
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
    if(rust_check_ber_cer_ia5_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_character_string_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_big_integer_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_oid_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_named_integer_record(module, expr, codecs)) return -1;
    if(rust_check_ber_cer_named_sequence_record(module, expr, codecs)) return -1;
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
        if(tagged_root && member->expr_type == ASN_CONSTR_SET) {
            rust_diagnostic(module, member,
                            "tagged BER/CER SET roots require direct primitive fields");
            return -1;
        }
        if(tagged_root && member->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, member,
                            "tagged BER/CER SET roots require direct primitive fields");
            return -1;
        }
        if((member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET
            || member->expr_type == ASN_CONSTR_CHOICE)
           && ++nodes > RUST_BER_CER_NODE_LIMIT) {
            rust_diagnostic(module, member, "BER/CER SET nesting exceeds the supported depth");
            return -1;
        }
        if(rust_check_ber_cer_member(module, expr, member, 1, &work, codecs)) return -1;
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
        if(tagged_root && member->expr_type == ASN_CONSTR_SET) {
            rust_diagnostic(module, member,
                            "tagged BER/CER SEQUENCE roots require direct primitive fields");
            return -1;
        }
        if(tagged_root && member->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, member,
                            "tagged BER/CER SEQUENCE roots require direct primitive fields");
            return -1;
        }
        if((member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET
            || member->expr_type == ASN_CONSTR_CHOICE)
           && ++nodes > RUST_BER_CER_NODE_LIMIT) {
            rust_diagnostic(module, member,
                            "BER/CER SEQUENCE nesting exceeds the supported depth");
            return -1;
        }
        if(rust_check_ber_cer_member(module, expr, member, 0, &work, codecs)) return -1;
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
                          asn1p_expr_t *member, int set, size_t *work,
                          uint64_t codecs) {
    if(member->expr_type == A1TC_REFERENCE) {
        if(rust_ber_cer_named_sequence_target(member)) {
            if(rust_check_ber_cer_named_sequence_member(module, expr, member, work)
               || (set && rust_check_sequence_name(module, expr, member))) return -1;
        } else if(rust_check_ber_cer_named_integer_member(module, member)
                  || (set && rust_check_sequence_name(module, expr, member))) {
            return -1;
        }
        if(rust_ber_cer_duplicate_tag(expr, member)) {
            rust_diagnostic(module, member,
                            "BER/CER record fields must have unique effective tags");
            return -1;
        }
        return 0;
    }
    if(member->expr_type == ASN_CONSTR_CHOICE) {
        if((set && rust_check_sequence_name(module, expr, member))
           || rust_check_inline_ber_cer_choice(module, expr, member, set, codecs))
            return -1;
        if(member->tag.tag_class == TC_CONTEXT_SPECIFIC
           && rust_ber_cer_duplicate_tag(expr, member)) {
            rust_diagnostic(module, member,
                            "BER/CER record fields must have unique effective tags");
            return -1;
        }
        return 0;
    }
    if(member->expr_type == ASN_STRING_IA5String) {
        if(rust_check_ber_cer_ia5_member(module, member)
           || (set && rust_check_sequence_name(module, expr, member))) return -1;
        if(rust_ber_cer_duplicate_tag(expr, member)) {
            rust_diagnostic(module, member,
                            "BER/CER record fields must have unique effective tags");
            return -1;
        }
        return 0;
    }
    if(rust_character_string_kind(member)) {
        if(rust_check_ber_cer_character_string_member(module, member)
           || (set && rust_check_sequence_name(module, expr, member))) return -1;
        if(rust_ber_cer_duplicate_tag(expr, member)) {
            rust_diagnostic(module, member,
                            "BER/CER record fields must have unique effective tags");
            return -1;
        }
        return 0;
    }
    if(member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
       || member->expr_type == ASN_BASIC_RELATIVE_OID) {
        if(rust_check_ber_cer_oid_member(module, member)
           || (set && rust_check_sequence_name(module, expr, member))) return -1;
        if(rust_ber_cer_duplicate_tag(expr, member)) {
            rust_diagnostic(module, member,
                            "BER/CER record fields must have unique effective tags");
            return -1;
        }
        return 0;
    }
    if(member->expr_type == ASN_BASIC_INTEGER && !member->constraints
       && !member->combined_constraints) {
        if(rust_check_ber_cer_big_integer_member(module, member)
           || (set && rust_check_sequence_name(module, expr, member))) return -1;
        if(rust_ber_cer_duplicate_tag(expr, member)) {
            rust_diagnostic(module, member,
                            "BER/CER record fields must have unique effective tags");
            return -1;
        }
        return 0;
    }
    if(!rust_ber_cer_member_shape_valid(member)
       || (set && rust_check_sequence_name(module, expr, member))) {
        rust_diagnostic(module, member,
                        "BER/CER record needs direct supported fields with universal or "
                        "resolved context-specific IMPLICIT or EXPLICIT tags and supported markers");
        return -1;
    }
    if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET) {
        if(member->expr_type == ASN_CONSTR_SET
           && (codecs & (RUST_CODEC_UPER | RUST_CODEC_CBOR))) {
            rust_diagnostic(module, member,
                            "inline SET children are supported only with BER/CER codecs");
            return -1;
        }
        if(member->marker.flags == EM_DEFAULT) {
            rust_diagnostic(module, member, "constructed DEFAULT fields are unsupported");
            return -1;
        }
        if(rust_check_ber_cer_nested_record(module, member, work)) return -1;
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
 * Validate one inline child record at the bounded BER/CER composition depth.
 * Inputs: module supplies diagnostics; record is one constructed component.
 * Returns zero for unique-tag primitive children or -1 for unsupported shapes.
 * Errors: references, extensions, DEFAULT, nested constructors, and field/work
 * excess fail closed. Source: approved inline record generator stage.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested BER/CER.
 * Example: a child SET with one bounded INTEGER is accepted.
 */
static int
rust_check_ber_cer_nested_record(asn1p_module_t *module,
                                 asn1p_expr_t *record, size_t *work) {
    asn1p_expr_t *member;
    size_t count = 0;
    if(!work) return -1;
    if(!rust_ber_cer_nested_record_shape_valid(record)) {
        rust_diagnostic(module, record,
                        "inline BER/CER child record has unsupported metadata");
        return -1;
    }
    if(record->expr_type == ASN_CONSTR_SET && !record->members.tq_head) {
        rust_diagnostic(module, record, "empty inline SET children are not C-compatible");
        return -1;
    }
    TQ_FOR(member, &record->members, next) {
        if(++count > RUST_BER_CER_FIELD_LIMIT
           || ++*work > RUST_BER_CER_WORK_LIMIT
           || member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET
           || member->marker.flags == EM_DEFAULT
           || !rust_ber_cer_member_shape_valid(member)
           || rust_check_sequence_name(module, record, member)
           || rust_check_sequence_member(module, member)
           || rust_ber_cer_duplicate_tag(record, member)) {
            rust_diagnostic(module, member,
                            "nested BER/CER record fields must be unique-tag required or "
                            "OPTIONAL primitive values");
            return -1;
        }
    }
    return 0;
}

/*
 * Validate structural properties of one inline nested SEQUENCE or SET.
 * Inputs: record is the parser node for the constructed child.
 * Returns one for inline record metadata without references or extensions;
 * an empty child is valid. Errors: malformed metadata returns zero. Source:
 * approved BER/CER slice.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested gate.
 * Example: an inline child without extensions passes this structural check.
 */
static int
rust_ber_cer_nested_record_shape_valid(asn1p_expr_t *record) {
    if(!record) return 0;
    return (record->expr_type == ASN_CONSTR_SEQUENCE || record->expr_type == ASN_CONSTR_SET)
        && !record->reference
        && !record->constraints
        && !record->combined_constraints
        && !record->lhs_params
        && !record->ioc_table
        && (record->marker.flags == EM_NOMARK || record->marker.flags == EM_OPTIONAL)
        && !record->rhs_pspecs
        && record->encoding_control.encoding_type == EC_NONE;
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
    if(rust_ber_cer_named_integer_target(member)) return 2;
    if(rust_ber_cer_named_sequence_target(member)) return 16;
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN: return 1;
    case ASN_BASIC_INTEGER: return 2;
    case ASN_BASIC_BIT_STRING: return 3;
    case ASN_BASIC_OCTET_STRING: return 4;
    case ASN_BASIC_NULL: return 5;
    case ASN_BASIC_OBJECT_IDENTIFIER: return 6;
    case ASN_BASIC_ENUMERATED: return 10;
    case ASN_BASIC_RELATIVE_OID: return 13;
    case ASN_STRING_IA5String: return 22;
    case ASN_STRING_ObjectDescriptor: return 7;
    case ASN_STRING_UTF8String: return 12;
    case ASN_STRING_NumericString: return 18;
    case ASN_STRING_PrintableString: return 19;
    case ASN_STRING_TeletexString:
    case ASN_STRING_T61String: return 20;
    case ASN_STRING_VideotexString: return 21;
    case ASN_STRING_GraphicString: return 25;
    case ASN_STRING_VisibleString:
    case ASN_STRING_ISO646String: return 26;
    case ASN_STRING_GeneralString: return 27;
    case ASN_STRING_UniversalString: return 28;
    case ASN_STRING_BMPString: return 30;
    case ASN_CONSTR_SEQUENCE: return 16;
    case ASN_CONSTR_SET: return 17;
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
    if(member->expr_type == ASN_CONSTR_CHOICE) {
        if(member->tag.tag_class != TC_CONTEXT_SPECIFIC
           || member->tag.tag_mode != TM_EXPLICIT || member->tag.tag_value < 0
           || member->tag.tag_value
              > (asn1c_integer_t)UINT32_C(0x3fffffff)) return -1;
        *class_out = TC_CONTEXT_SPECIFIC;
        *number_out = (uint32_t)member->tag.tag_value;
        return 0;
    }
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
 * Purpose: test whether a natural CHOICE contains one universal tag number.
 * Input: choice is validated; number is a supported intrinsic universal tag.
 * Returns one on a match, zero otherwise. Errors: none.
 * Source: intrinsic BOOLEAN/NULL/INTEGER tag mapping. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: logical CHOICE collisions.
 * Example: a natural BOOLEAN/NULL CHOICE contains tag 5.
 */
static int
rust_ber_cer_choice_has_tag(asn1p_expr_t *choice, uint32_t number) {
    asn1p_expr_t *alternative;
    TQ_FOR(alternative, &choice->members, next) {
        if(rust_ber_cer_choice_arm_tag(alternative) == number) return 1;
    }
    return 0;
}

/*
 * Map a prevalidated primitive CHOICE arm to its intrinsic universal tag.
 * Inputs: alternative is BOOLEAN, NULL, or bounded INTEGER after gate checks.
 * Returns its tag number. Errors: unsupported kinds return zero.
 * Source: X.680 primitive assignments. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET ordering.
 * Example: INTEGER maps to universal tag 2.
 */
static uint32_t
rust_ber_cer_choice_arm_tag(asn1p_expr_t *alternative) {
    if(!alternative) return 0;
    if(alternative->expr_type == ASN_BASIC_BOOLEAN) return 1;
    if(alternative->expr_type == ASN_BASIC_NULL) return 5;
    if(alternative->expr_type == ASN_BASIC_INTEGER) return 2;
    return 0;
}

/*
 * Return the minimum intrinsic tag number among validated CHOICE arms.
 * Inputs: choice contains one through three supported alternatives.
 * Returns the minimum tag, or zero if no valid arm is present.
 * Errors: none; schema validation owns malformed alternatives.
 * Source: X.690 CER SET ordering key. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE in SET.
 * Example: BOOLEAN/NULL/INTEGER has CER order key 1.
 */
static uint32_t
rust_ber_cer_choice_min_tag(asn1p_expr_t *choice) {
    asn1p_expr_t *alternative;
    uint32_t minimum = UINT32_MAX;
    if(!choice) return 0;
    TQ_FOR(alternative, &choice->members, next) {
        uint32_t number = rust_ber_cer_choice_arm_tag(alternative);
        if(number && number < minimum) minimum = number;
    }
    return minimum == UINT32_MAX ? 0 : minimum;
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
 * SEQUENCE or SET occurs, otherwise zero. Errors: none. Source: runtime context policy.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested records.
 * Example: an OPTIONAL child uses nested accounting even when absent.
 */
static int
rust_ber_cer_has_nested_record(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET
           || member->expr_type == ASN_CONSTR_CHOICE
           || rust_ber_cer_named_sequence_target(member)) return 1;
    }
    return 0;
}

/*
 * Detect a direct named SEQUENCE reference for descriptors and context mode.
 * Input: expr owns the record fields. Returns one when a resolved child exists.
 * Errors: none; unsupported references are rejected during preflight.
 * Source: named child resolver. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named child composition.
 * Example: a SET with `child Inner` returns one.
 */
static int
rust_ber_cer_has_named_sequence_member(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(rust_ber_cer_named_sequence_target(member)) return 1;
    }
    return 0;
}

/*
 * Detect a member requiring aggregate runtime storage tracking.
 * Input: expr owns one record's direct members. Returns one when present.
 * Errors: none. Source: approved IA5, OID, BigInteger, and restricted-string
 * record policies.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: variable-content record gates. Example: absent BigInteger still selects
 * aggregate accounting for the record operation, including optional strings.
 */
static int
rust_ber_cer_has_variable_content_member(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_STRING_IA5String
           || member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
           || member->expr_type == ASN_BASIC_RELATIVE_OID
           || rust_character_string_kind(member)
           || (member->expr_type == ASN_BASIC_INTEGER && !member->constraints
               && !member->combined_constraints)) return 1;
    }
    return 0;
}

/*
 * Detect an unbounded INTEGER requiring descriptor-based tag-2 dispatch.
 * Input: expr owns validated direct fields. Returns one when present.
 * Errors: none. Source: approved BigInteger record API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: tag-2 field disambiguation.
 * Example: one OPTIONAL unbounded INTEGER returns one.
 */
static int
rust_ber_cer_has_big_integer_member(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_BASIC_INTEGER && !member->constraints
           && !member->combined_constraints) return 1;
    }
    return 0;
}

/*
 * Detect a kind-bearing string field that needs descriptor-based SET dispatch.
 * Input: expr owns validated direct fields. Returns one when present.
 * Errors: none. Source: CharacterString record descriptor policy.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: preserve aliases with shared universal tags.
 * Example: a T61String field returns one.
 */
static int
rust_ber_cer_has_character_string_member(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if(rust_character_string_kind(member)) return 1;
    }
    return 0;
}

/*
 * Select the runtime budget mode required by a generated record operation.
 * Input: expr owns validated direct members. Returns a RecordContext method
 * name for new/nested/aggregate-scratch mode. Errors: none. Source: runtime
 * record context constructors. Version/date: 2026-11-01. Responsible party:
 * asn1c maintainers. History: nested and IA5 record support.
 * Example: an absent OPTIONAL OID selects `new_with_aggregate_scratch`.
 */
static const char *
rust_ber_cer_context_constructor(asn1p_expr_t *expr) {
    if(rust_ber_cer_has_nested_record(expr)) return "new_nested";
    if(rust_ber_cer_has_variable_content_member(expr))
        return "new_with_aggregate_scratch";
    return "new";
}

/*
 * Purpose: locate the one validated inline CHOICE and its logical field index.
 * Input: expr owns a record; index receives declaration position when present.
 * Returns the CHOICE member or NULL. Errors: none; preflight limits count to one.
 * Source: fixed record tree. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE generation.
 * Example: locate an OPTIONAL CHOICE at logical index one.
 */
static asn1p_expr_t *
rust_ber_cer_choice_member(asn1p_expr_t *expr, size_t *index) {
    asn1p_expr_t *member;
    size_t current = 0;
    if(!expr) return NULL;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_CHOICE) {
            if(index) *index = current;
            return member;
        }
        current++;
    }
    return NULL;
}

/*
 * Detect empty inline children whose UPER helper shape is not qualified.
 * Inputs: expr owns the root record's direct fields. Returns one on an empty
 * inline empty child record, otherwise zero. Errors: none. Source: Rust codec gate.
 * Version/date: 2026-11-01. Author: asn1c maintainers. History: nested records.
 * Example: an empty inline record is marked for codec-specific gate checks.
 */
static int
rust_ber_cer_has_empty_nested_record(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    if(!expr) return 0;
    TQ_FOR(member, &expr->members, next) {
        if((member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET)
           && !member->members.tq_head) return 1;
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
        if(prior->expr_type == ASN_CONSTR_CHOICE
           && prior->tag.tag_class == TC_NOCLASS) {
            if(member_class == TC_UNIVERSAL
               && rust_ber_cer_choice_has_tag(prior, member_number)) return 1;
            continue;
        }
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
    if(!member) return NULL;
    if(rust_ber_cer_named_integer_target(member)) return "Integer";
    if(rust_ber_cer_named_sequence_target(member)) return "Sequence";
    if(member->expr_type == ASN_BASIC_INTEGER && !member->constraints
       && !member->combined_constraints) return "BigInteger";
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN: return "Boolean";
    case ASN_BASIC_INTEGER: return "Integer";
    case ASN_BASIC_BIT_STRING: return "BitString";
    case ASN_BASIC_OCTET_STRING: return "OctetString";
    case ASN_BASIC_NULL: return "Null";
    case ASN_BASIC_ENUMERATED: return "Enumerated";
    case ASN_CONSTR_SEQUENCE: return "Sequence";
    case ASN_CONSTR_SET: return "Set";
    case ASN_STRING_IA5String: return "Ia5String";
    case ASN_BASIC_OBJECT_IDENTIFIER: return "ObjectIdentifier";
    case ASN_BASIC_RELATIVE_OID: return "RelativeOid";
    default: return NULL;
    }
}

/*
 * Format a field-kind expression while preserving restricted-string identity.
 * Inputs: member selects the descriptor; output/capacity receive Rust syntax.
 * Returns zero or -1 for unsupported kinds or insufficient output space.
 * Errors: none. Source: runtime FieldKind API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: built-in string aliases.
 * Example: T61String becomes CharacterString(T61String).
 */
static int
rust_ber_cer_field_kind_expression(const asn1p_expr_t *member, char *output,
                                   size_t capacity) {
    const char *character_kind = rust_character_string_kind(member);
    const char *field_kind = rust_ber_cer_field_kind(member);
    int written;
    if(!output || !capacity) return -1;
    if(character_kind) {
        written = snprintf(output, capacity,
            "CharacterString(::asn1c_runtime::CharacterStringKind::%s)",
            character_kind);
    } else if(field_kind) {
        written = snprintf(output, capacity, "%s", field_kind);
    } else {
        return -1;
    }
    return written < 0 || (size_t)written >= capacity ? -1 : 0;
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
        if(member->expr_type == ASN_CONSTR_CHOICE) continue;
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
        if(member->expr_type == ASN_CONSTR_CHOICE) continue;
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
    int has_descriptor = 0;
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type != ASN_CONSTR_CHOICE) has_descriptor = 1;
    }
    if(has_descriptor && fprintf(stream,
        "%suse ::asn1c_runtime::ber::{FieldKind, RecordField};\n", indent) < 0)
        return -1;
    TQ_FOR(member, &expr->members, next) {
        int class_code;
        uint32_t number;
        char local[48];
        char formatted_number[16];
        const char *class_name;
        if(member->expr_type == ASN_CONSTR_CHOICE) continue;
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
        if(member->expr_type == ASN_CONSTR_CHOICE) continue;
        char kind[112];
        const char *constructor = rust_ber_cer_member_explicit(member)
                                ? "new_explicit" : "new";
        char local[48];
        if(rust_ber_cer_field_kind_expression(member, kind, sizeof(kind))
           || rust_ber_cer_tag_local(member, local, sizeof(local))) return -1;
        if(rust_character_string_kind(member)) {
            if(fprintf(stream,
                "%s    RecordField::%s(\n"
                "%s        %s,\n"
                "%s        FieldKind::CharacterString(\n"
                "%s            ::asn1c_runtime::CharacterStringKind::%s,\n"
                "%s        ),\n"
                "%s    )?,\n",
                indent, constructor, indent, local, indent, indent,
                rust_character_string_kind(member), indent, indent) < 0) return -1;
        } else if(fprintf(stream,
            "%s    RecordField::%s(%s, FieldKind::%s)?,\n",
            indent, constructor, local, kind) < 0) {
            return -1;
        }
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
    char kind[112];
    const char *constructor = rust_ber_cer_member_explicit(member)
                            ? "new_explicit" : "new";
    if(rust_ber_cer_field_kind_expression(member, kind, sizeof(kind))
       || rust_ber_cer_member_tag(member, &class_code, &number)
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
 * Purpose: validate a direct primitive CHOICE for BER/CER generation.
 * Source: approved untagged X.690 CHOICE subset and fixed parser tree.
 * Version/date: 2026-11-01. Inputs: module supplies diagnostics; expr owns
 * alternatives; codecs is the selected mask. Returns zero or -1. Errors:
 * unsupported tags, members, bounds, codecs, or Rust-name collisions reject.
 * Responsible party: asn1c maintainers. History: initial BER/CER CHOICE slice.
 * Example: BOOLEAN, NULL, and bounded INTEGER alternatives pass this gate.
 */
static int
rust_check_ber_cer_choice(asn1p_module_t *module, asn1p_expr_t *expr,
                          uint64_t codecs) {
    const char *unsupported =
        "CHOICE requires direct untagged BOOLEAN, NULL, or bounded INTEGER alternatives";
    asn1p_expr_t *item;
    size_t count = 0;
    unsigned tags_seen = 0;

    if(rust_check_ber_cer_choice_codecs(module, expr, codecs)
       || rust_check_ber_cer_choice_root(module, expr)) return -1;
    TQ_FOR(item, &expr->members, next) {
        unsigned tag_bit;
        if(++count > 3) {
            rust_diagnostic(module, item, unsupported);
            return -1;
        }
        if(rust_check_ber_cer_choice_member(module, item, &tag_bit)
           || rust_check_ber_cer_choice_name(module, expr, item)) return -1;
        if(tags_seen & tag_bit) {
            rust_diagnostic(module, item, "CHOICE alternatives have duplicate intrinsic tags");
            return -1;
        }
        tags_seen |= tag_bit;
    }
    if(!count) {
        rust_diagnostic(module, expr, "CHOICE requires at least one primitive alternative");
        return -1;
    }
    return 0;
}

/*
 * Purpose: reject unsupported codec masks for direct primitive CHOICE.
 * Source: approved BER/CER-only CHOICE design. Version/date: 2026-11-01.
 * Inputs: module/expr identify the root; codecs is the selected mask.
 * Returns zero for a nonempty BER/CER subset, otherwise -1 with a diagnostic.
 * Errors: UPER, CBOR, and other mixed masks are rejected before publication.
 * Responsible party: asn1c maintainers. History: direct CHOICE gate.
 * Example: BER plus CER passes; BER plus UPER is rejected.
 */
static int
rust_check_ber_cer_choice_codecs(asn1p_module_t *module, asn1p_expr_t *expr,
                                 uint64_t codecs) {
    const uint64_t ber_cer = RUST_CODEC_BER | RUST_CODEC_CER;
    if(codecs && !(codecs & ~ber_cer)) return 0;
    rust_diagnostic(module, expr, "CHOICE requires BER/CER-only codec selection");
    return -1;
}

/*
 * Purpose: validate a direct untagged nonextensible CHOICE root.
 * Source: fixed parser tree for the approved primitive CHOICE gate.
 * Version/date: 2026-11-01. Inputs: module and expr identify the assignment.
 * Returns zero for a flat root, otherwise -1 with a source diagnostic.
 * Errors: tagged, constrained, parameterized, or marked roots are rejected.
 * Responsible party: asn1c maintainers. History: direct CHOICE gate.
 * Example: an untagged CHOICE with three primitive members passes.
 */
static int
rust_check_ber_cer_choice_root(asn1p_module_t *module, asn1p_expr_t *expr) {
    if(expr->constraints || expr->combined_constraints || expr->reference
       || expr->lhs_params || expr->rhs_pspecs || expr->ioc_table
       || expr->with_syntax || expr->marker.flags != EM_NOMARK
       || expr->marker.default_value || expr->unique
       || expr->tag.tag_class != TC_NOCLASS || expr->tag.tag_mode != TM_DEFAULT) {
        rust_diagnostic(module, expr,
                        "CHOICE requires an untagged direct root with no constraints");
        return -1;
    }
    return 0;
}

/*
 * Purpose: validate one direct BOOLEAN, NULL, or bounded INTEGER alternative.
 * Source: approved intrinsic-tag CHOICE contract and integer range helpers.
 * Version/date: 2026-11-01. Inputs: module/item identify the arm; tag_bit receives
 * its intrinsic-tag marker. Returns zero or -1 with a located diagnostic.
 * Errors: tags, references, defaults, extensions, and unsupported leaves reject.
 * Responsible party: asn1c maintainers. History: direct CHOICE gate.
 * Example: INTEGER (-2..5) receives the universal INTEGER marker.
 */
static int
rust_check_ber_cer_choice_member(asn1p_module_t *module, asn1p_expr_t *item,
                                 unsigned *tag_bit) {
    if(!tag_bit || rust_check_ber_cer_choice_member_shape(module, item)) return -1;
    return rust_check_ber_cer_choice_member_kind(module, item, tag_bit);
}

/*
 * Purpose: validate non-type structure for one direct CHOICE alternative.
 * Source: fixed parser tree and approved CHOICE exclusion list.
 * Version/date: 2026-11-01. Inputs: module/item identify the alternative.
 * Returns zero for an untagged required leaf or -1 with a located diagnostic.
 * Errors: references, tags, marker/default state, nested members, or malformed
 * member shapes reject. Responsible party: asn1c maintainers. History: CHOICE.
 * Example: an ordinary BOOLEAN arm passes; OPTIONAL arms are rejected.
 */
static int
rust_check_ber_cer_choice_member_shape(asn1p_module_t *module, asn1p_expr_t *item) {
    if(!rust_sequence_member_shape_valid(item) || item->reference
       || item->marker.flags != EM_NOMARK || item->marker.default_value
       || item->tag.tag_class != TC_NOCLASS || item->tag.tag_mode != TM_DEFAULT
       || item->with_syntax || item->unique || item->members.tq_head) {
        rust_diagnostic(module, item,
                        "CHOICE alternatives must be direct untagged primitive values");
        return -1;
    }
    return 0;
}

/*
 * Purpose: map one valid CHOICE leaf kind to its unique intrinsic tag marker.
 * Source: approved primitive CHOICE type set. Version/date: 2026-11-01.
 * Inputs: module/item identify the leaf; tag_bit receives its tag marker.
 * Returns zero or -1 with a source diagnostic. Errors: unsupported kinds and
 * constrained BOOLEAN/NULL leaves reject. Responsible party: asn1c maintainers.
 * History: initial direct CHOICE gate. Example: NULL maps to marker bit two.
 */
static int
rust_check_ber_cer_choice_member_kind(asn1p_module_t *module, asn1p_expr_t *item,
                                      unsigned *tag_bit) {
    switch(item->expr_type) {
    case ASN_BASIC_BOOLEAN:
        if(item->constraints || item->combined_constraints) {
            rust_diagnostic(module, item, "CHOICE BOOLEAN cannot have constraints");
            return -1;
        }
        *tag_bit = 1u;
        return 0;
    case ASN_BASIC_NULL:
        if(item->constraints || item->combined_constraints) {
            rust_diagnostic(module, item, "CHOICE NULL cannot have constraints");
            return -1;
        }
        *tag_bit = 2u;
        return 0;
    case ASN_BASIC_INTEGER:
        if(rust_check_ber_cer_choice_integer(module, item)) return -1;
        *tag_bit = 4u;
        return 0;
    default:
        rust_diagnostic(module, item,
                        "CHOICE supports only BOOLEAN, NULL, and bounded INTEGER");
        return -1;
    }
}

/*
 * Purpose: require a finite nonextensible i64 range on a CHOICE INTEGER arm.
 * Source: existing finite-integer constraint checker. Version/date: 2026-11-01.
 * Inputs: module/item identify the source arm. Returns zero or -1 with a
 * diagnostic. Errors: missing, union, extension, or out-of-range bounds reject.
 * Responsible party: asn1c maintainers. History: direct CHOICE gate.
 * Example: INTEGER (-2..5) passes; unconstrained INTEGER is rejected.
 */
static int
rust_check_ber_cer_choice_integer(asn1p_module_t *module, asn1p_expr_t *item) {
    int64_t lower, upper;
    if(item->combined_constraints
       && rust_constraint_supported(item->combined_constraints, 0)
       && !rust_integer_bounds(item, &lower, &upper)) return 0;
    rust_diagnostic(module, item,
                    "CHOICE INTEGER needs one finite nonextensible i64 range");
    return -1;
}

/*
 * Purpose: reject alternative names that collide after Rust variant conversion.
 * Source: generated Rust enum name sanitizer. Version/date: 2026-11-01.
 * Inputs: module supplies diagnostics; expr owns arms; item is the current arm.
 * Returns zero for a unique name or -1 after a source-located diagnostic.
 * Errors: invalid identifiers, allocation failures, and sanitized collisions reject.
 * Responsible party: asn1c maintainers. History: direct CHOICE gate.
 * Example: `a-2` and `a2` cannot both map to one enum variant.
 */
static int
rust_check_ber_cer_choice_name(asn1p_module_t *module, asn1p_expr_t *expr,
                               asn1p_expr_t *item) {
    asn1p_expr_t *prior;
    char *name;
    if(!rust_enum_name_safe(item->Identifier) || !(name = rust_enum_variant(item->Identifier))) {
        rust_diagnostic(module, item, "CHOICE alternative name cannot form a Rust variant");
        return -1;
    }
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
            rust_diagnostic(module, item,
                            "CHOICE alternative names collide after Rust sanitization");
            return -1;
        }
    }
    free(name);
    return 0;
}

/*
 * Purpose: validate one inline primitive CHOICE field under a record.
 * Inputs: module/parent/choice identify source; set selects the parent kind;
 * codecs is the selected mask. Returns zero or -1 with a located diagnostic.
 * Errors: unsupported wrappers, arms, codecs, and sibling collisions reject.
 * Source: approved one-inline-CHOICE gate. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline primitive CHOICE.
 * Example: an OPTIONAL natural CHOICE in a SET passes absent tag collisions.
 */
static int
rust_check_inline_ber_cer_choice(asn1p_module_t *module, asn1p_expr_t *parent,
                                 asn1p_expr_t *choice, int set, uint64_t codecs) {
    const uint64_t supported = RUST_CODEC_BER | RUST_CODEC_CER;
    if(codecs & ~supported) {
        rust_diagnostic(module, choice,
                        "inline CHOICE children require BER/CER-only selection");
        return -1;
    }
    if(rust_inline_choice_shape_valid(module, choice)
       || rust_inline_choice_is_unique(module, parent, choice)
       || rust_inline_choice_members_valid(module, choice)) return -1;
    if(choice->tag.tag_class == TC_NOCLASS
       && rust_check_inline_choice_collisions(module, parent, choice, set))
        return -1;
    return 0;
}

/*
 * Purpose: validate inline CHOICE root metadata and one supported tagging form.
 * Inputs: module/choice identify the fixed AST node under validation.
 * Returns zero or -1 with a source-located diagnostic. Errors: tags, aliases,
 * constraints, extensions, and defaults are rejected. Source: fixed ASN.1 AST.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: inline primitive CHOICE. Example: explicit SET CHOICE passes.
 */
static int
rust_inline_choice_shape_valid(asn1p_module_t *module, asn1p_expr_t *choice) {
    return rust_inline_choice_tagging_valid(module, choice)
        || rust_inline_choice_metadata_valid(module, choice) ? -1 : 0;
}

/*
 * Purpose: validate natural or context-specific EXPLICIT CHOICE tagging.
 * Inputs: module/choice identify source; parent-kind policy is checked later.
 * Returns zero or -1 with a diagnostic. Errors: IMPLICIT/classes/range reject.
 * Source: approved inline CHOICE tagging modes. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE gate.
 * Example: natural tagging is valid in a top-level SET.
 */
static int
rust_inline_choice_tagging_valid(asn1p_module_t *module, asn1p_expr_t *choice) {
    int natural = choice->tag.tag_class == TC_NOCLASS
               && choice->tag.tag_mode == TM_DEFAULT;
    int explicit_tag = choice->tag.tag_class == TC_CONTEXT_SPECIFIC
                    && choice->tag.tag_mode == TM_EXPLICIT
                    && choice->tag.tag_value >= 0
                    && choice->tag.tag_value
                       <= (asn1c_integer_t)UINT32_C(0x3fffffff);
    if(natural || explicit_tag) return 0;
    rust_diagnostic(module, choice,
                    "inline CHOICE needs natural tagging or one context-specific "
                    "EXPLICIT tag in SET/SEQUENCE");
    return -1;
}

/*
 * Purpose: reject aliases, constraints, extensions, and unsupported markers.
 * Inputs: module/choice identify the inline source node. Returns zero or -1.
 * Errors: references and malformed/fixed-tree metadata fail closed.
 * Source: approved inline CHOICE root shape. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE gate.
 * Example: an unconstrained inline CHOICE with OPTIONAL presence is valid.
 */
static int
rust_inline_choice_metadata_valid(asn1p_module_t *module, asn1p_expr_t *choice) {
    if(choice->expr_type == ASN_CONSTR_CHOICE && !choice->reference
       && !choice->constraints && !choice->combined_constraints && !choice->lhs_params
       && !choice->rhs_pspecs && !choice->ioc_table && !choice->with_syntax
       && !choice->unique && !choice->marker.default_value
       && (choice->marker.flags == EM_NOMARK
           || choice->marker.flags == EM_OPTIONAL)
       && choice->encoding_control.encoding_type == EC_NONE) return 0;
    rust_diagnostic(module, choice,
                    "inline CHOICE cannot be an alias, constrained, extended, or defaulted");
    return -1;
}

/*
 * Purpose: ensure a parent has exactly one inline CHOICE logical field.
 * Inputs: module/parent/choice identify the record and selected child.
 * Returns zero when unique or -1 with a diagnostic. Errors: second CHOICE fails.
 * Source: logical parent presence model. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE gate.
 * Example: one natural CHOICE is accepted among ordinary sibling fields.
 */
static int
rust_inline_choice_is_unique(asn1p_module_t *module, asn1p_expr_t *parent,
                              asn1p_expr_t *choice) {
    asn1p_expr_t *sibling;
    TQ_FOR(sibling, &parent->members, next) {
        if(sibling != choice && sibling->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, sibling,
                            "a record may contain only one inline CHOICE child");
            return -1;
        }
    }
    return 0;
}

/*
 * Purpose: validate each inline CHOICE arm and its generated Rust variant name.
 * Inputs: module/choice identify the source subtree. Returns zero or -1.
 * Errors: empty, excess, duplicate-tag, malformed, or colliding arms reject.
 * Source: approved primitive CHOICE arm set. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE gate.
 * Example: BOOLEAN and bounded INTEGER alternatives pass.
 */
static int
rust_inline_choice_members_valid(asn1p_module_t *module, asn1p_expr_t *choice) {
    asn1p_expr_t *item;
    size_t count = 0;
    unsigned tags_seen = 0;
    TQ_FOR(item, &choice->members, next) {
        unsigned tag_bit;
        if(++count > 3
           || rust_check_ber_cer_choice_member(module, item, &tag_bit)
           || rust_check_ber_cer_choice_name(module, choice, item)) return -1;
        if(tags_seen & tag_bit) {
            rust_diagnostic(module, item,
                            "inline CHOICE alternatives have duplicate intrinsic tags");
            return -1;
        }
        tags_seen |= tag_bit;
    }
    if(count) return 0;
    rust_diagnostic(module, choice, "inline CHOICE needs at least one primitive alternative");
    return -1;
}

/*
 * Purpose: reject multiple CHOICE children and natural-arm tag collisions.
 * Inputs: module/parent/choice identify the record and field; set is parent kind.
 * Returns zero or -1 with a source diagnostic. Errors: ambiguous tags reject.
 * Source: logical CHOICE field presence and X.690 component tags.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: inline CHOICE field gate. Example: BOOLEAN arm versus BOOLEAN sibling.
 */
static int
rust_check_inline_choice_collisions(asn1p_module_t *module, asn1p_expr_t *parent,
                                    asn1p_expr_t *choice, int set) {
    asn1p_expr_t *sibling;
    (void)set;
    TQ_FOR(sibling, &parent->members, next) {
        int sibling_class;
        uint32_t sibling_number;
        if(sibling == choice) continue;
        if(sibling->expr_type == ASN_CONSTR_CHOICE) {
            rust_diagnostic(module, sibling,
                            "a record may contain only one inline CHOICE child");
            return -1;
        }
        if(rust_ber_cer_member_tag(sibling, &sibling_class, &sibling_number)) {
            rust_diagnostic(module, sibling,
                            "inline CHOICE sibling has no supported effective tag");
            return -1;
        }
        if(sibling_class == TC_UNIVERSAL
           && rust_ber_cer_choice_has_tag(choice, sibling_number)) {
            rust_diagnostic(module, sibling,
                            "natural CHOICE arm collides with a sibling effective tag");
            return -1;
        }
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
        if(member->expr_type != ASN_CONSTR_SEQUENCE && member->expr_type != ASN_CONSTR_SET
           && member->expr_type != ASN_CONSTR_CHOICE
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
        if((member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET)
           && rust_collect_nested_names(module, member, name, names, name_count, depth + 1))
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
 * Check one member while accumulating bounded inline-record traversal work.
 * Inputs: module/parent/member identify source; stack/depth track recursion;
 * nodes/work/count carry limits; codecs controls the supported mask.
 * Returns zero or -1 with a diagnostic. Source: Rust fixed-tree preflight.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: inline BER/CER SET child gate. Example: validate one SET field.
 */
static int
rust_check_sequence_tree_member(asn1p_module_t *module, asn1p_expr_t *parent,
                                asn1p_expr_t *member, asn1p_expr_t **stack,
                                size_t depth, size_t *nodes, size_t *work,
                                size_t *count, uint64_t codecs) {
    if(++*count > RUST_SEQUENCE_FIELD_LIMIT || ++*work > RUST_SEQUENCE_WORK_LIMIT) {
        rust_diagnostic(module, member, "SEQUENCE aggregate field-work limit exceeded");
        return -1;
    }
    if(rust_check_sequence_name(module, parent, member)) return -1;
    if(member->expr_type == A1TC_REFERENCE) {
        if(depth != 0 || (codecs & ~(RUST_CODEC_BER | RUST_CODEC_CER))) {
            rust_diagnostic(module, member,
                "named record references are supported only in flat BER/CER records");
            return -1;
        }
        if(rust_ber_cer_named_sequence_target(member)) {
            if(++*nodes > RUST_SEQUENCE_NODE_LIMIT) {
                rust_diagnostic(module, member, "named child record node limit exceeded");
                return -1;
            }
            return rust_check_ber_cer_named_sequence_member(module, parent, member, work);
        }
        return rust_check_ber_cer_named_integer_member(module, member);
    }
    if(member->expr_type == ASN_CONSTR_CHOICE) {
        if(++*nodes > RUST_SEQUENCE_NODE_LIMIT) {
            rust_diagnostic(module, member, "nested record node limit exceeded");
            return -1;
        }
        return rust_check_inline_ber_cer_choice(module, parent, member, 0, codecs);
    }
    if(member->expr_type == ASN_CONSTR_SET) {
        if(!(codecs & (RUST_CODEC_BER | RUST_CODEC_CER))
           || (codecs & (RUST_CODEC_UPER | RUST_CODEC_CBOR))) {
            rust_diagnostic(module, member,
                            "inline SET children require BER/CER-only selection");
            return -1;
        }
        if(++*nodes > RUST_SEQUENCE_NODE_LIMIT) {
            rust_diagnostic(module, member, "nested record node limit exceeded");
            return -1;
        }
        return 0;
    }
    if(member->expr_type == ASN_CONSTR_SEQUENCE) {
        if(member->marker.flags == EM_DEFAULT) {
            rust_diagnostic(module, member, "constructed DEFAULT fields are unsupported");
            return -1;
        }
        if(!rust_sequence_member_shape_valid(member)) {
            rust_diagnostic(module, member, "nested SEQUENCE has an unsupported field shape");
            return -1;
        }
        return rust_check_sequence_tree(module, member, stack, depth + 1,
                                        nodes, work, codecs);
    }
    if(member->expr_type == ASN_STRING_IA5String) {
        if(depth != 0) {
            rust_diagnostic(module, member,
                            "IA5String fields are supported only at the record root");
            return -1;
        }
        return 0;
    }
    if(rust_character_string_kind(member)) {
        if(depth != 0) {
            rust_diagnostic(module, member,
                "restricted character-string fields are supported only at the record root");
            return -1;
        }
        return rust_check_ber_cer_character_string_member(module, member);
    }
    if(member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
       || member->expr_type == ASN_BASIC_RELATIVE_OID) {
        if(depth != 0) {
            rust_diagnostic(module, member,
                            "OID fields are supported only at the record root");
            return -1;
        }
        return rust_check_ber_cer_oid_member(module, member);
    }
    if(member->expr_type == ASN_BASIC_INTEGER && !member->constraints
       && !member->combined_constraints) {
        if(depth != 0) {
            rust_diagnostic(module, member,
                            "unconstrained INTEGER fields are supported only at the record root");
            return -1;
        }
        return rust_check_ber_cer_big_integer_member(module, member);
    }
    return rust_check_sequence_member(module, member);
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
                         size_t *work, uint64_t codecs) {
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
       || sequence->combined_constraints || sequence->lhs_params || sequence->ioc_table
       || (sequence->marker.flags != EM_NOMARK
           && sequence->marker.flags != EM_OPTIONAL)
       || sequence->rhs_pspecs
       || sequence->encoding_control.encoding_type != EC_NONE) {
        rust_diagnostic(module, sequence, "nested SEQUENCE has unsupported extensions or constraints");
        return -1;
    }
    stack[depth] = sequence;
    TQ_FOR(member, &sequence->members, next) {
        if(rust_check_sequence_tree_member(module, sequence, member, stack, depth,
                                           nodes, work, &count, codecs)) return -1;
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
 * Accept one contiguous INTEGER range and no union or singleton-value set.
 * Inputs: constraint is a fixed AST node; depth bounds recursion; seen tracks
 * the sole range leaf. Returns one for exactly one finite range, otherwise zero.
 * Errors: unsupported nodes and recursion excess return zero.
 * Source: ASN.1 INTEGER range AST. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: prevent widening named types.
 * Example: `INTEGER (0..5)` passes; `INTEGER (0..2 | 4..5)` fails.
 */
static int
rust_integer_single_range_supported(const asn1p_constraint_t *constraint,
                                    unsigned depth, int *seen) {
    unsigned index;
    if(!constraint || !seen || depth > RUST_CONSTRAINT_DEPTH_LIMIT) return 0;
    if(constraint->type == ACT_EL_RANGE) {
        if(*seen || !constraint->range_start || !constraint->range_stop
           || constraint->range_start->type != ATV_INTEGER
           || constraint->range_stop->type != ATV_INTEGER) return 0;
        *seen = 1;
        return 1;
    }
    if((constraint->type != ACT_CA_SET && constraint->type != ACT_CA_INT)
       || constraint->el_count != 1) return 0;
    for(index = 0; index < constraint->el_count; index++) {
        if(!rust_integer_single_range_supported(constraint->elements[index],
                                                depth + 1, seen)) return 0;
    }
    return 1;
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

/* Emit a typed owned wrapper for one validated direct collection root.
 * Inputs: stream receives Rust, name is the assignment name, expr is the root,
 * and codecs selects emitted methods. Returns zero or -1 on output failure.
 * Errors: emitted methods return malformed-input and limit errors.
 * Source: approved BER/CER collection runtime. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: initial OF collection support.
 * Example: rust_write_collection(out, "Flags", expr, RUST_CODEC_BER).
 */
static int
rust_write_collection(FILE *stream, const char *name, asn1p_expr_t *expr,
                      uint64_t codecs) {
    asn1p_expr_t *element = TQ_FIRST(&expr->members);
    const char *root = expr->expr_type == ASN_CONSTR_SET_OF ? "SetOf" : "SequenceOf";
    const char *variant;
    const char *rust_type;
    char descriptor[160];
    char lower[64], upper[64];
    int written;

    if(element->expr_type == ASN_BASIC_BOOLEAN) {
        variant = "Boolean";
        rust_type = "bool";
        strcpy(descriptor, "::asn1c_runtime::CollectionElementKind::Boolean");
    } else if(element->expr_type == ASN_BASIC_NULL) {
        variant = "Null";
        rust_type = "()";
        strcpy(descriptor, "::asn1c_runtime::CollectionElementKind::Null");
    } else {
        int64_t low, high;
        variant = "Integer";
        rust_type = "i64";
        if(rust_integer_bounds(element, &low, &high)
           || rust_format_bound(lower, sizeof(lower), low)
           || rust_format_bound(upper, sizeof(upper), high)) return -1;
        written = snprintf(descriptor, sizeof(descriptor),
            "::asn1c_runtime::CollectionElementKind::BoundedInteger { lower: %s, upper: %s }",
            lower, upper);
        if(written < 0 || (size_t)written >= sizeof(descriptor)) return -1;
    }
    if(fprintf(stream,
        "/// Owned values of an ASN.1 SEQUENCE OF or SET OF type.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Owned element vector state variable.\n"
        "    ::std::vec::Vec<%s>\n"
        ");\n\nimpl %s {\n", name, rust_type, name) < 0) return -1;
    if(rust_write_method_doc(stream, "Take ownership of the collection elements.",
            "`values` contains typed element values.",
            "Returns a wrapper that owns the supplied vector.",
            "This constructor cannot fail; codec methods enforce ASN.1 bounds.",
            "`let value = Type::new(vec![true, false]);")) return -1;
    if(fputs("    #[must_use]\n"
             "    pub const fn new(values: ::std::vec::Vec<", stream) == EOF
       || fputs(rust_type, stream) == EOF
       || fputs(">) -> Self { Self(values) }\n", stream) == EOF) return -1;
    if(rust_write_method_doc(stream, "Borrow the collection elements.",
            "`self` is the collection to inspect.",
            "Returns the ordered values without copying.",
            "This accessor cannot fail.", "`let values = value.as_slice();")) return -1;
    if(fprintf(stream,
        "    #[must_use]\n"
        "    pub fn as_slice(&self) -> &[%s] { &self.0 }\n", rust_type) < 0)
        return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_collection_codec(stream, root, descriptor, variant, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_collection_codec(stream, root, descriptor, variant, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit one DER/BER or CER codec pair for an owned collection wrapper.
 * Inputs: stream/name identify output; root/element describe runtime kinds;
 * variant selects matching decoded values; cer selects CER versus DER/BER.
 * Returns zero or -1. Emitted calls propagate runtime validation errors.
 * Source: approved collection runtime API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: generated OF codec methods.
 * Example: rust_write_collection_codec(out, "Flags", "SequenceOf", ...).
 */
static int
rust_write_collection_codec(FILE *stream, const char *root,
                            const char *descriptor, const char *variant, int cer) {
    const char *encode = cer ? "cer" : "der";
    const char *decode = cer ? "cer" : "ber";
    const char *input = !strcmp(variant, "Null") ? "self.0.len()" : "&self.0";
    const char *null_values = !strcmp(variant, "Null")
        ? "        let values = ::std::vec![(); values];\n" : "";
    const char *intro = cer ? "Strictly decode one CER collection prefix."
                            : "Decode one BER collection prefix.";
    const char *example = cer
        ? "`let decoded = Type::decode_cer(input, &limits)?;"
        : "`let decoded = Type::decode_ber(input, &limits)?;";
    char method_example[112];
    int written;

    written = snprintf(method_example, sizeof(method_example),
                       "`let encoded = value.encode_%s(&limits)?;", encode);
    if(written < 0 || (size_t)written >= sizeof(method_example)) return -1;
    if(rust_write_method_doc(stream, cer ? "Encode using canonical CER." :
                             "Encode using canonical DER.",
            "`self` supplies values; `limits` bounds output and cumulative work.",
            "Returns the complete encoded collection TLV.",
            "Returns an error for invalid values or exhausted limits.", method_example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_collection_%s(\n"
        "            ::asn1c_runtime::CollectionRootKind::%s,\n"
        "            %s,\n"
        "            ::asn1c_runtime::CollectionInput::%s(%s),\n"
        "            limits,\n"
        "        )\n    }\n", encode, encode, root, descriptor, variant, input) < 0)
        return -1;
    if(rust_write_method_doc(stream, intro,
            "`input` is a complete or suffixed BER/CER byte slice; `limits` bounds work.",
            "Returns decoded values and exact consumed prefix bits and bytes.",
            cer ? "Returns an error for malformed, noncanonical, or over-limit input."
                : "Returns an error for malformed or over-limit input.", example))
        return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        let decoded = ::asn1c_runtime::decode_collection_%s(\n"
        "            input,\n"
        "            ::asn1c_runtime::CollectionRootKind::%s,\n"
        "            %s,\n"
        "            limits,\n"
        "        )?;\n"
        "        let ::asn1c_runtime::CollectionValues::%s(values) = decoded.value else {\n"
        "            return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                reason: \"collection runtime returned an incompatible element kind\",\n"
        "            });\n"
        "        };\n"
        "%s"
        "        Ok(::asn1c_runtime::Decoded {\n"
        "            value: Self(values),\n"
        "            consumed_bits: decoded.consumed_bits,\n"
        "            consumed_bytes: decoded.consumed_bytes,\n"
        "        })\n    }\n", decode, decode, root, descriptor, variant,
        null_values) < 0) return -1;
    return 0;
}

/*
 * Emit one supported primitive wrapper, collection, or flat SEQUENCE.
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
    } else if(expr->expr_type == ASN_CONSTR_SEQUENCE_OF
              || expr->expr_type == ASN_CONSTR_SET_OF) {
        ret = rust_write_collection(stream, name, expr, codecs);
    } else if(expr->expr_type == ASN_CONSTR_SET) {
        ret = rust_write_set(stream, name, expr, 1, codecs);
    } else if(expr->expr_type == ASN_CONSTR_SEQUENCE) {
        ret = rust_write_all_sequences(stream, name, expr, 1, codecs);
    } else if(expr->expr_type == ASN_CONSTR_CHOICE) {
        ret = codecs == RUST_CODEC_CBOR
            ? rust_write_cbor_choice(stream, name, expr)
            : rust_write_ber_cer_choice(stream, name, expr, codecs, 1);
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
    } else if(expr->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
              || expr->expr_type == ASN_BASIC_RELATIVE_OID) {
        ret = rust_write_oid(stream, name,
            expr->expr_type == ASN_BASIC_RELATIVE_OID, codecs);
    } else if(expr->expr_type == ASN_STRING_IA5String) {
        ret = rust_write_ia5_string(stream, name, codecs);
    } else if(rust_character_string_kind(expr)) {
        ret = rust_write_character_string(stream, name, expr, codecs);
    } else if(expr->expr_type == ASN_BASIC_UTCTime) {
        ret = rust_write_utc_time(stream, name, codecs);
    } else if(expr->expr_type == ASN_BASIC_GeneralizedTime) {
        ret = rust_write_generalized_time(stream, name, codecs);
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
    const char *derive = rust_ber_cer_has_variable_content_member(expr)
                       ? "Debug, Eq, PartialEq" : "Clone, Debug, Eq, PartialEq";
    if(fprintf(stream,
        "/// ASN.1 SEQUENCE record with direct inline fields.\n"
        "#[derive(%s)]\n"
        "pub struct %s {\n", derive, name) < 0) return -1;
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
    if(rust_write_nested_ber_cer_fields(stream, expr, parent, 0)
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
            rust_ber_cer_context_constructor(expr)) < 0) return -1;
        if(rust_write_sequence_ber_cer_decode_method(stream, parent, expr, 0)) return -1;
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
            rust_ber_cer_context_constructor(expr)) < 0) return -1;
        if(rust_write_sequence_ber_cer_decode_method(stream, parent, expr, 1)) return -1;
    }
    return 0;
}

/*
 * Decide whether a record's BER/CER field emitter reads fields from self.
 * Inputs: expr is the validated record assignment.
 * Returns one when an emitted field accesses self; empty required named children do not.
 * Errors: none; this helper inspects the already-fixed tree only.
 * Source: generated callback usage. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: empty named child lint fix.
 * Example: a required empty target alone does not need to read self.
 */
static int
rust_ber_cer_record_encode_uses_self(asn1p_expr_t *expr) {
    asn1p_expr_t *member;
    TQ_FOR(member, &expr->members, next) {
        asn1p_expr_t *named = rust_ber_cer_named_sequence_target(member);
        int empty_named = named && !named->members.tq_head;
        if(!empty_named && (member->expr_type != ASN_CONSTR_SEQUENCE
           || member->members.tq_head || member->marker.flags == EM_OPTIONAL)) return 1;
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
                                 const char *parent, int set) {
    asn1p_expr_t *member;
    int uses_self = rust_ber_cer_record_encode_uses_self(expr);
    asn1p_expr_t *sorted[RUST_BER_CER_FIELD_LIMIT];
    size_t count = 0;
    size_t index;
    if(!expr->members.tq_head) return 0;
    if(rust_write_method_doc(stream,
        set ? "Append this SET's fields in effective-tag order to a caller-owned writer."
            : "Append this SEQUENCE's fields to a caller-owned record writer.",
        "`self` supplies values; `writer` shares the parent's operation context.",
        "Returns success after all fields are appended.",
        "Returns an error for invalid values or exhausted resources.",
        "`self.encode_record_fields(child_writer)?;")) return -1;
    if(set && rust_ber_cer_sort_set_fields(expr, sorted,
        sizeof(sorted) / sizeof(sorted[0]), &count)) return -1;
    if(fprintf(stream,
        "    fn encode_record_fields(&self,\n"
        "        writer: &mut ::asn1c_runtime::ber::%sWriter<'_>) ->\n"
        "        ::core::result::Result<(), ::asn1c_runtime::Error> {\n",
        set ? "Set" : "Sequence") < 0) return -1;
    if(!uses_self && fputs("        let _ = self;\n", stream) == EOF) return -1;
    if(rust_write_ber_cer_tag_locals(stream, expr)) return -1;
    if(set) {
        for(index = 0; index < count; index++)
            if(rust_write_sequence_ber_cer_encode_field(stream, parent, sorted[index])) return -1;
    } else {
        TQ_FOR(member, &expr->members, next) {
            if(rust_write_sequence_ber_cer_encode_field(stream, parent, member)) return -1;
        }
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
 * Sort SET fields using one natural CHOICE's rule-specific order key.
 * Inputs: expr is validated, choice is its natural CHOICE, and choice_tag is
 * the selected DER arm tag or CER minimum tag. Returns zero or -1.
 * Errors: unknown sibling tags or insufficient capacity fail closed.
 * Source: X.690 SET ordering. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE in SET.
 * Example: selected tag 5 places universal tag 4 before the CHOICE.
 */
static int
rust_ber_cer_sort_set_fields_for_choice(asn1p_expr_t *expr,
                                        asn1p_expr_t *choice,
                                        uint32_t choice_tag,
                                        asn1p_expr_t **sorted,
                                        size_t capacity,
                                        size_t *count_out) {
    asn1p_expr_t *member;
    size_t count = 0;
    TQ_FOR(member, &expr->members, next) {
        size_t position = count;
        int tag_class;
        uint32_t tag_number;
        if(count >= capacity) return -1;
        if(member == choice) {
            if(!choice_tag) return -1;
        } else if(rust_ber_cer_member_tag(member, &tag_class, &tag_number)) {
            return -1;
        }
        while(position > 0) {
            int comparison_valid;
            int comparison = rust_ber_cer_set_choice_tag_compare(
                sorted[position - 1], member, choice, choice_tag,
                &comparison_valid);
            if(!comparison_valid) return -1;
            if(comparison <= 0) break;
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
 * Compare fields with a synthetic universal tag for one natural CHOICE.
 * Inputs: left/right are checked fields; choice/choice_tag define its key.
 * Returns comparison and stores validity through valid_out; invalid tags fail.
 * Source: DER selected-tag and CER minimum-tag rules. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET emitter.
 * Example: compare a natural CHOICE tag 5 with OCTET STRING tag 4.
 */
static int
rust_ber_cer_set_choice_tag_compare(asn1p_expr_t *left,
                                    asn1p_expr_t *right,
                                    asn1p_expr_t *choice,
                                    uint32_t choice_tag,
                                    int *valid_out) {
    int left_class, right_class;
    uint32_t left_number, right_number;
    if(!valid_out) return 0;
    *valid_out = 0;
    if(left == choice) {
        left_class = TC_UNIVERSAL;
        left_number = choice_tag;
    } else if(rust_ber_cer_member_tag(left, &left_class, &left_number)) {
        return 0;
    }
    if(right == choice) {
        right_class = TC_UNIVERSAL;
        right_number = choice_tag;
    } else if(rust_ber_cer_member_tag(right, &right_class, &right_number)) {
        return 0;
    }
    *valid_out = 1;
    if(left_class != right_class) return left_class < right_class ? -1 : 1;
    if(left_number == right_number) return 0;
    return left_number < right_number ? -1 : 1;
}

/*
 * Compare two compile-time SET emission orders by member identity.
 * Inputs: arrays contain the sorted members and their lengths. Returns one
 * when both orders match, zero otherwise. Errors: none.
 * Source: fixed schema field sorting. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: selected CHOICE DER order.
 * Example: two selected tags before the same siblings share one match arm.
 */
static int
rust_ber_cer_set_order_equal(asn1p_expr_t **left, size_t left_count,
                             asn1p_expr_t **right, size_t right_count) {
    size_t index;
    if(left_count != right_count) return 0;
    for(index = 0; index < left_count; index++) {
        if(left[index] != right[index]) return 0;
    }
    return 1;
}

/*
 * Emit one branch's SET writes using the supplied natural-CHOICE ordering key.
 * Inputs: stream/parent/expr identify generated output; choice_tag is its key;
 * pattern is an optional match arm. Returns zero or -1.
 * Errors: allocation, sorting, and output failures abort generation.
 * Source: selected DER tag or minimum CER alternative tag. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET order.
 * Example: emit fields with the selected NULL tag as the CHOICE's key.
 */
static int
rust_write_set_ber_cer_choice_variant_order(FILE *stream, const char *parent,
                                             asn1p_expr_t *expr,
                                             uint32_t choice_tag,
                                             const char *pattern) {
    asn1p_expr_t *choice = rust_ber_cer_choice_member(expr, NULL);
    asn1p_expr_t *sorted[RUST_BER_CER_FIELD_LIMIT];
    size_t count;
    size_t index;
    if(!choice || rust_ber_cer_sort_set_fields_for_choice(expr, choice, choice_tag,
        sorted, sizeof(sorted) / sizeof(sorted[0]), &count)) return -1;
    if(pattern && fprintf(stream, "                    %s => {\n", pattern) < 0) return -1;
    for(index = 0; index < count; index++) {
        if(rust_write_sequence_ber_cer_encode_field(stream, parent, sorted[index]))
            return -1;
    }
    if(pattern && fputs("                    }\n", stream) == EOF) return -1;
    return 0;
}

/*
 * Emit one DER match arm for alternatives whose SET sort order is identical.
 * Parameters: stream/parent/expr identify output; choice_type names the enum;
 * optional controls Option wrapping; alternative_count bounds alternatives;
 * alternatives names arms; orders contains flattened sorted-field rows;
 * order_counts gives row lengths; emitted tracks completed arms; index selects
 * the group. Returns zero or -1. Errors: formatting or output failure.
 * Source: DER orders by selected alternative tag. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE in SET.
 * Example: selected BOOLEAN and INTEGER may share one precomputed field order.
 */
static int
rust_write_set_ber_cer_choice_der_group(FILE *stream, const char *parent,
                                        asn1p_expr_t *expr,
                                        const char *choice_type, int optional,
                                        size_t alternative_count,
                                        asn1p_expr_t **alternatives,
                                        asn1p_expr_t **orders,
                                        size_t *order_counts,
                                        unsigned char *emitted, size_t index) {
    char variants[1536] = {0};
    char pattern[2048];
    size_t variants_length = 0;
    size_t other;
    int written;
    if(emitted[index]) return 0;
    for(other = index; other < alternative_count; other++) {
        char *variant;
        char item_pattern[512];
        const char *suffix;
        if(emitted[other] || !rust_ber_cer_set_order_equal(
            &orders[index * RUST_BER_CER_FIELD_LIMIT], order_counts[index],
            &orders[other * RUST_BER_CER_FIELD_LIMIT], order_counts[other]))
            continue;
        variant = rust_enum_variant(alternatives[other]->Identifier);
        if(!variant) return -1;
        suffix = alternatives[other]->expr_type == ASN_BASIC_NULL ? "" : "(_)";
        written = snprintf(item_pattern, sizeof(item_pattern), "%s::%s%s",
            choice_type, variant, suffix);
        if(written >= 0 && (size_t)written < sizeof(item_pattern)) {
            int appended = snprintf(variants + variants_length,
                sizeof(variants) - variants_length, "%s%s",
                variants_length ? " | " : "", item_pattern);
            if(appended < 0
               || (size_t)appended >= sizeof(variants) - variants_length)
                written = -1;
            else variants_length += (size_t)appended;
        }
        free(variant);
        if(written < 0 || (size_t)written >= sizeof(item_pattern)) return -1;
        emitted[other] = 1;
    }
    if(optional && index == 0)
        written = snprintf(pattern, sizeof(pattern), "None | Some(%s)", variants);
    else if(optional)
        written = snprintf(pattern, sizeof(pattern), "Some(%s)", variants);
    else
        written = snprintf(pattern, sizeof(pattern), "%s", variants);
    if(written < 0 || (size_t)written >= sizeof(pattern)) return -1;
    return rust_write_set_ber_cer_choice_variant_order(stream, parent, expr,
        rust_ber_cer_choice_arm_tag(alternatives[index]), pattern);
}

/*
 * Emit all DER selected-tag groups for a natural CHOICE in SET.
 * Inputs: alternatives and flattened order rows are validated; emitted tracks
 * groups already written. Returns zero or -1. Errors: formatting/sort failure.
 * Source: X.690 DER SET order. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE SET.
 * Example: group arms whose selected tag yields the same sibling order.
 */
static int
rust_write_set_ber_cer_choice_der_arms(FILE *stream, const char *parent,
                                       asn1p_expr_t *expr,
                                       const char *choice_type, int optional) {
    asn1p_expr_t *choice = rust_ber_cer_choice_member(expr, NULL);
    asn1p_expr_t *alternatives[3] = {0};
    asn1p_expr_t *orders[3 * RUST_BER_CER_FIELD_LIMIT];
    size_t order_counts[3] = {0};
    size_t alternative_count = 0;
    unsigned char emitted[3] = {0};
    asn1p_expr_t *alternative;
    size_t index;
    if(!choice || !choice_type) return -1;
    TQ_FOR(alternative, &choice->members, next) {
        if(alternative_count >= 3) return -1;
        alternatives[alternative_count] = alternative;
        if(rust_ber_cer_sort_set_fields_for_choice(expr, choice,
            rust_ber_cer_choice_arm_tag(alternative),
            &orders[alternative_count * RUST_BER_CER_FIELD_LIMIT],
            RUST_BER_CER_FIELD_LIMIT, &order_counts[alternative_count])) return -1;
        alternative_count++;
    }
    for(index = 0; index < alternative_count; index++) {
        if(rust_write_set_ber_cer_choice_der_group(stream, parent, expr,
            choice_type, optional, alternative_count, alternatives, orders,
            order_counts, emitted, index)) return -1;
    }
    return 0;
}

/*
 * Emit a SET's fields under natural CHOICE-specific or ordinary tag sorting.
 * Inputs: sorted/count come from validated fields; choice may be natural.
 * Returns zero or -1. Errors: invalid choice order or source write failure.
 * Source: DER/CER SET ordering. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: selected CHOICE SET orders.
 * Example: emit DER's selected-arm order and CER's minimum-arm order.
 */
static int
rust_write_set_ber_cer_encode_fields(FILE *stream, const char *parent,
                                     asn1p_expr_t *expr,
                                     asn1p_expr_t **sorted, size_t count,
                                     asn1p_expr_t *choice) {
    size_t index;
    if(choice && choice->tag.tag_class == TC_NOCLASS)
        return rust_write_set_ber_cer_choice_order(stream, parent, expr);
    for(index = 0; index < count; index++) {
        if(rust_write_sequence_ber_cer_encode_field(stream, parent, sorted[index]))
            return -1;
    }
    return 0;
}

/*
 * Emit DER's selected-arm order and CER's minimum-arm order for a SET.
 * Inputs: stream receives Rust; parent/expr identify a validated SET with one
 * natural CHOICE. Returns zero or -1. Errors: invalid names/tags or output fail.
 * Source: X.690 SET ordering keys. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE in SET.
 * Example: NULL sorts after OCTET STRING in DER but before it in CER.
 */
static int
rust_write_set_ber_cer_choice_order(FILE *stream, const char *parent,
                                    asn1p_expr_t *expr) {
    asn1p_expr_t *choice = rust_ber_cer_choice_member(expr, NULL);
    char *field_name;
    char *choice_type;
    uint32_t minimum;
    int optional;
    int result = -1;
    if(!choice || !(field_name = rust_identifier(choice->Identifier, 1))) return -1;
    choice_type = rust_nested_type_name(parent, choice);
    minimum = rust_ber_cer_choice_min_tag(choice);
    optional = choice->marker.flags == EM_OPTIONAL;
    if(!choice_type || !minimum
       || fprintf(stream,
           "        match rule {\n"
           "            ::asn1c_runtime::ber::RecordEncoding::Der => {\n"
           "                match &self.%s {\n", field_name) < 0) goto cleanup;
    if(rust_write_set_ber_cer_choice_der_arms(stream, parent, expr, choice_type,
                                               optional)) goto cleanup;
    if(fputs(
        "                }\n"
        "            }\n"
        "            ::asn1c_runtime::ber::RecordEncoding::Cer => {\n", stream) == EOF
       || rust_write_set_ber_cer_choice_variant_order(stream, parent, expr,
                                                       minimum, NULL)
       || fputs(
        "            }\n"
        "        }\n", stream) == EOF) goto cleanup;
    result = 0;
cleanup:
    free(choice_type);
    free(field_name);
    return result;
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
                       int top_level, uint64_t codecs) {
    asn1p_expr_t *sorted[6];
    asn1p_expr_t *choice;
    size_t count;
    asn1p_expr_t *member;
    int has_members = expr->members.tq_head != 0;
    int tagged_root = expr->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && expr->tag.tag_mode == TM_IMPLICIT;
    choice = rust_ber_cer_choice_member(expr, NULL);
    const char *context_constructor = rust_ber_cer_context_constructor(expr);
    if(rust_ber_cer_sort_set_fields(expr, sorted,
                                    sizeof(sorted) / sizeof(sorted[0]), &count)) return -1;
    if(!top_level && rust_write_nested_ber_cer_fields(stream, expr, parent, 1)) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_set_ber_cer_decode_helper(stream, parent, member)) return -1;
    }
    if(!top_level) {
        if(rust_write_set_ber_cer_decode_fields(stream, expr)) return -1;
        return 0;
    }
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
    if(rust_write_set_ber_cer_encode_fields(stream, parent, expr, sorted, count,
                                             choice)) return -1;
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
        if(rust_write_set_ber_cer_decode_method(stream, parent, expr, 0)) return -1;
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
        if(rust_write_set_ber_cer_decode_method(stream, parent, expr, 1)) return -1;
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
/*
 * Purpose: select the runtime storage type for a supported primitive field.
 * Inputs: member is validated fixed-tree field metadata. Returns a static name.
 * Errors: this selector has no failure path; unsupported shapes use byte storage.
 * Source: Rust record value model. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: shared record type selection.
 * Example: bounded INTEGER maps to `i64` and unconstrained INTEGER to BigInteger.
 */
static const char *
rust_ber_cer_primitive_field_type(asn1p_expr_t *member) {
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN: return "bool";
    case ASN_BASIC_NULL: return "()";
    case ASN_BASIC_INTEGER:
        if(!member->constraints && !member->combined_constraints)
            return "::asn1c_runtime::BigInteger";
        return "i64";
    case ASN_BASIC_BIT_STRING:
        return rust_fixed_size(member, &(size_t){0}) == 0
            ? "::std::vec::Vec<u8>" : "::asn1c_runtime::BitStringValue";
    case ASN_STRING_IA5String: return "::asn1c_runtime::Ia5String";
    case ASN_BASIC_OBJECT_IDENTIFIER: return "::asn1c_runtime::ObjectIdentifier";
    case ASN_BASIC_RELATIVE_OID: return "::asn1c_runtime::RelativeOid";
    default:
        if(rust_character_string_kind(member)) return "::asn1c_runtime::CharacterString";
        return "::std::vec::Vec<u8>";
    }
}

/*
 * Purpose: choose the generated Rust storage type for one validated record field.
 * Inputs: parent names nested items; member is the fixed field; owned receives
 * an allocated named or nested type name when needed.
 * Returns a borrowed primitive type or the same allocated name in `*owned`.
 * Errors: unsupported nested names and allocation failures return NULL.
 * Source: validated ASN.1 field AST. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named reference field types.
 * Example: `Small` resolves to its generated newtype, while BOOLEAN is `bool`.
 */
static const char *
rust_ber_cer_record_field_type(const char *parent, asn1p_expr_t *member,
                               char **owned) {
    asn1p_expr_t *target = rust_ber_cer_named_integer_target(member);
    asn1p_expr_t *named_sequence = rust_ber_cer_named_sequence_target(member);
    asn1p_expr_t *contained;
    if(!owned) return NULL;
    *owned = NULL;
    if(target) *owned = rust_identifier(target->Identifier, 0);
    else if(named_sequence) *owned = rust_identifier(named_sequence->Identifier, 0);
    else if(member->expr_type == ASN_CONSTR_SEQUENCE
            || member->expr_type == ASN_CONSTR_SET
            || member->expr_type == ASN_CONSTR_CHOICE
            || member->expr_type == ASN_BASIC_ENUMERATED)
        *owned = rust_nested_type_name(parent, member);
    if(target || named_sequence || member->expr_type == ASN_CONSTR_SEQUENCE
       || member->expr_type == ASN_CONSTR_SET || member->expr_type == ASN_CONSTR_CHOICE
       || member->expr_type == ASN_BASIC_ENUMERATED) return *owned;
    contained = rust_containing_node(member->combined_constraints, 0)
        ? rust_contained_primitive(member->module, member) : NULL;
    if(rust_containing_node(member->combined_constraints, 0)) {
        if(!contained) return NULL;
        return contained->expr_type == ASN_BASIC_BOOLEAN ? "bool" : "i64";
    }
    return rust_ber_cer_primitive_field_type(member);
}

/*
 * Purpose: map a SET field to its return type and emit its shared-reader helper.
 * Inputs: stream receives code; parent names inline types; member is validated.
 * Returns zero on success or -1 for name/type/output failures.
 * Errors: runtime reads return their typed Error; no generated context is reset.
 * Source: BER/CER SetReader API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: tagged and named SET fields.
 * Example: decode a referenced `Small` through bounded `read_integer`.
 */
static int
rust_write_set_ber_cer_decode_helper(FILE *stream, const char *parent,
                                     asn1p_expr_t *member) {
    char *name = rust_identifier(member->Identifier, 1);
    char *owned_type = NULL;
    const char *type = rust_ber_cer_record_field_type(parent, member, &owned_type);
    int ret;
    if(!name || !type) {
        free(name);
        free(owned_type);
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
    free(owned_type);
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
rust_write_set_ber_cer_reader(FILE *stream, const char *parent,
                              asn1p_expr_t *expr, int tagged, int tagged_root) {
    asn1p_expr_t *member;
    size_t choice_index = 0;
    asn1p_expr_t *choice = rust_ber_cer_choice_member(expr, &choice_index);
    if(tagged) {
        if(rust_write_ber_cer_field_descriptors(stream, expr, "            ")) return -1;
        if(choice) {
            if(fputs("            let __asn1c_choice = ", stream) == EOF
               || rust_write_inline_choice_descriptor(stream, parent, choice)
               || fprintf(stream, ";\n"
                   "            let mut reader = ::asn1c_runtime::ber::SetReader::"
                   "new_tagged_with_choice(\n"
                   "                input, &__asn1c_expected_fields, __asn1c_choice, %zu, "
                   "&mut context)?;\n", choice_index) < 0) return -1;
        } else if(tagged_root) {
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
rust_write_set_ber_cer_dispatch_arm(FILE *stream, asn1p_expr_t *member, int tagged,
                                    const char *reader_arg) {
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
            "                                %s)?,\n"
            "                        );\n"
            "                    }\n", class_name, formatted_number, name, name,
            reader_arg);
    else
        result = fprintf(stream,
            "                    %s => {\n"
            "                        __asn1c_%s = Some(\n"
            "                            Self::__asn1c_decode_set_field_%s(\n"
            "                                %s)?,\n"
            "                        );\n"
            "                    }\n", formatted_number, name, name, reader_arg);
    free(name);
    return result < 0 ? -1 : 0;
}

/*
 * Emit one SET dispatch arm for every intrinsic tag of a natural CHOICE.
 * Inputs: stream receives Rust; choice and reader_arg identify the checked field.
 * Returns zero or -1. Errors: identifier allocation or output failures abort.
 * Source: logical CHOICE field dispatch. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: natural CHOICE in SET.
 * Example: BOOLEAN, NULL, and INTEGER tags all assign the same CHOICE slot.
 */
static int
rust_write_set_ber_cer_dispatch_choice(FILE *stream, asn1p_expr_t *choice,
                                       const char *reader_arg) {
    asn1p_expr_t *alternative;
    char *name = rust_identifier(choice->Identifier, 1);
    int first = 1;
    if(!name) return -1;
    if(fputs(
        "                    (\n"
        "                        ::asn1c_runtime::ber::TagClass::Universal,\n"
        "                        ", stream) == EOF) {
        free(name);
        return -1;
    }
    TQ_FOR(alternative, &choice->members, next) {
        uint32_t number = rust_ber_cer_choice_arm_tag(alternative);
        if(fprintf(stream, "%s%u", first ? "" : " | ", number) < 0) {
            free(name);
            return -1;
        }
        first = 0;
    }
    if(fprintf(stream,
        ",\n"
        "                    ) => {\n"
        "                        __asn1c_%s = Some(\n"
        "                            Self::__asn1c_decode_set_field_%s(\n"
        "                                %s)?);\n"
        "                    }\n", name, name, reader_arg) < 0) {
        free(name);
        return -1;
    }
    free(name);
    return 0;
}

/*
 * Emit the loop that dispatches arbitrary BER SET component order.
 * Parameters: stream receives Rust; expr owns fields; tagged selects Tag API.
 * Returns zero or -1. Source: X.690 SET ordering rules. Version/date: 2026-11-01.
 * Author: asn1c maintainers. History: tagged and universal SET decoding.
 * Example: accept any order while rejecting an unrecognized tag.
 */
static int
rust_write_set_ber_cer_dispatch(FILE *stream, asn1p_expr_t *expr, int tagged,
                                const char *reader_arg) {
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
        int natural_choice = member->expr_type == ASN_CONSTR_CHOICE
                          && member->tag.tag_class == TC_NOCLASS;
        if(natural_choice) {
            if(rust_write_set_ber_cer_dispatch_choice(stream, member, reader_arg))
                return -1;
        } else if(rust_write_set_ber_cer_dispatch_arm(stream, member, tagged, reader_arg)) {
            return -1;
        }
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
 * Emit the nested SET field decoder used inside a bounded parent reader.
 * Source: shared `SetReader::read_nested_set` callback API. Version/date:
 * 2026-11-01. Inputs: stream receives Rust; expr owns validated nonempty
 * child fields. Returns zero or -1.
 * Errors: output failure; the runtime reports malformed field errors.
 * Responsible party: asn1c maintainers. History: inline nested SET support.
 * Example: `Child::decode_record_fields(set_reader)` dispatches any BER order.
 */
static int
rust_write_set_ber_cer_decode_fields(FILE *stream, asn1p_expr_t *expr) {
    if(!expr->members.tq_head) return 0;
    if(rust_write_method_doc(stream,
        "Decode this SET's fields from a caller-bounded SET reader.",
        "`reader` shares the parent boundary and operation context.",
        "Returns all validated fields after unordered tag dispatch.",
        "Returns an error for missing, duplicate, unknown, or malformed fields.",
        "`let child = Child::decode_record_fields(child_reader)?;")) return -1;
    if(fputs(
        "    fn decode_record_fields(\n"
        "        reader: &mut ::asn1c_runtime::ber::SetReader<'_, '_, '_>) ->\n"
        "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n",
        stream) == EOF) return -1;
    if(rust_write_set_ber_cer_decode_slots(stream, expr)
       || rust_write_set_ber_cer_dispatch(stream, expr, 1, "reader")
       || rust_write_set_ber_cer_construct_value(stream, expr)
       || fputs("            Ok(value)\n        }\n\n", stream) == EOF) return -1;
    return 0;
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
rust_write_set_ber_cer_decode_method(FILE *stream, const char *parent,
                                     asn1p_expr_t *expr, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    int tagged_root = expr->tag.tag_class == TC_CONTEXT_SPECIFIC
                   && expr->tag.tag_mode == TM_IMPLICIT;
    int tagged = tagged_root || rust_ber_cer_has_tagged_members(expr)
              || rust_ber_cer_has_big_integer_member(expr)
              || rust_ber_cer_has_character_string_member(expr)
              || rust_ber_cer_has_named_sequence_member(expr)
              || rust_ber_cer_choice_member(expr, NULL) != NULL;
    const char *context_constructor = rust_ber_cer_context_constructor(expr);
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
    if(rust_write_set_ber_cer_reader(stream, parent, expr, tagged, tagged_root)
       || rust_write_set_ber_cer_decode_slots(stream, expr)
       || rust_write_set_ber_cer_dispatch(stream, expr, tagged, "&mut reader")
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
               int top_level, uint64_t codecs) {
    asn1p_expr_t *member;
    const char *derive = rust_ber_cer_has_variable_content_member(expr)
                       ? "Debug, Eq, PartialEq" : "Clone, Debug, Eq, PartialEq";
    TQ_FOR(member, &expr->members, next) {
        if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET) {
            char *nested_name = rust_nested_type_name(name, member);
            int ret = !nested_name ? -1 : member->expr_type == ASN_CONSTR_SEQUENCE
                ? rust_write_all_sequences(stream, nested_name, member, 0, codecs)
                : rust_write_set(stream, nested_name, member, 0, codecs);
            free(nested_name);
            if(ret) return -1;
        } else if(member->expr_type == ASN_CONSTR_CHOICE) {
            char *choice_name = rust_nested_type_name(name, member);
            int ret = choice_name
                ? rust_write_ber_cer_choice(stream, choice_name, member, codecs, 0) : -1;
            free(choice_name);
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
        "#[derive(%s)]\n"
        "pub struct %s {\n", derive, name) < 0) return -1;
    TQ_FOR(member, &expr->members, next) {
        if(rust_write_sequence_field(stream, name, member)) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0) return -1;
    if(rust_write_set_ber_cer(stream, name, expr, top_level, codecs)) return -1;
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
    asn1p_expr_t *bounds_type = rust_ber_cer_named_integer_target(member);
    int64_t lower, upper;
    char low[64], high[64];
    if(rust_integer_bounds(bounds_type ? bounds_type : member, &lower, &upper)
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
 * Purpose: emit one inline primitive CHOICE field write.
 * Inputs: stream receives Rust; parent/member select descriptors; value is borrowed.
 * Returns zero or -1 on generated-source write failure.
 * Errors: descriptor generation and output failures propagate as -1.
 * Source: shared runtime ChoiceField writer. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE record support.
 * Example: emit `writer.write_choice(descriptor, choice.runtime_value())?`.
 */
static int
rust_write_ber_cer_encode_choice(FILE *stream, const char *parent,
                                 asn1p_expr_t *member, const char *value) {
    if(fputs("writer.write_choice(\n            ", stream) == EOF
       || rust_write_inline_choice_descriptor(stream, parent, member)) return -1;
    return fprintf(stream, ",\n            (%s).runtime_value())?;\n", value) < 0 ? -1 : 0;
}

/*
 * Purpose: emit a nested SEQUENCE or SET writer callback using the parent context.
 * Inputs: stream/parent/member/value identify code and child; tag data selects framing.
 * Returns zero or -1. Errors: nested name, descriptor, or output failures.
 * Source: shared nested record writer API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: one inline record child.
 * Example: a context-specific EXPLICIT child gets one shared-context wrapper.
 */
static int
rust_write_ber_cer_encode_nested(FILE *stream, const char *parent,
                                 asn1p_expr_t *member, const char *value,
                                 const char *tag_local, int tagged,
                                 int explicit_tag) {
    asn1p_expr_t *named_sequence = rust_ber_cer_named_sequence_target(member);
    char *nested_type = named_sequence
        ? rust_identifier(named_sequence->Identifier, 0)
        : rust_nested_type_name(parent, member);
    int is_set = member->expr_type == ASN_CONSTR_SET;
    int empty_child = named_sequence ? !named_sequence->members.tq_head
                                     : !member->members.tq_head;
    const char *constructor = explicit_tag ? "new_explicit" : "new";
    const char *kind = is_set ? "Set" : "Sequence";
    const char *writer = is_set ? "set" : "sequence";
    const char *tag_expression = tagged ? tag_local
        : is_set ? "::asn1c_runtime::ber::Tag::universal(17)"
                 : "::asn1c_runtime::ber::Tag::universal(16)";
    int result;
    if(!nested_type) return -1;
    if(!is_set && empty_child) {
        result = fprintf(stream,
            "        writer.write_nested_sequence(\n"
            "            ::asn1c_runtime::ber::RecordField::%s(\n"
            "                %s, ::asn1c_runtime::ber::FieldKind::Sequence)?,\n"
            "            |_child_writer| Ok(()))?;\n", constructor, tag_expression);
    } else {
        result = fprintf(stream,
            "        writer.write_nested_%s(\n"
            "            ::asn1c_runtime::ber::RecordField::%s(\n"
            "                %s, ::asn1c_runtime::ber::FieldKind::%s)?,\n"
            "            |child_writer| %s.encode_record_fields(child_writer))?;\n",
            writer, constructor, tag_expression, kind, value);
    }
    free(nested_type);
    return result < 0 ? -1 : 0;
}

/*
 * Purpose: emit scalar BOOLEAN, NULL, INTEGER, or ENUMERATED field writes.
 * Inputs: stream/member/value and tag arguments define the validated scalar.
 * Returns zero or -1. Errors: unsupported scalar tags or output failures.
 * Source: X.690 primitive record APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: scalar BER/CER fields.
 * Example: write a bounded INTEGER with its target range and effective tag.
 */
static int
rust_write_ber_cer_encode_scalar(FILE *stream, const char *parent,
                                 asn1p_expr_t *member, const char *value,
                                 const char *tag, int tagged, int explicit_tag) {
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN:
        return rust_write_ber_cer_boolean(stream, value, tag, tagged, explicit_tag);
    case ASN_BASIC_NULL:
        return rust_write_ber_cer_null(stream, tag, tagged, explicit_tag);
    case ASN_BASIC_INTEGER:
        if(!member->constraints && !member->combined_constraints) {
            if(tagged || explicit_tag) return -1;
            return fprintf(stream, "writer.write_big_integer(%s)?;\n", value) < 0
                ? -1 : 0;
        }
        return rust_write_ber_cer_integer(stream, member, value, tag, tagged, explicit_tag);
    case ASN_BASIC_ENUMERATED:
        return rust_write_sequence_ber_cer_enum_match(stream, parent, member, value);
    default:
        return -1;
    }
}

/*
 * Purpose: emit owned or string-like BER/CER field writer expressions.
 * Inputs: stream/member/value and tag arguments select one validated field API.
 * Returns zero or -1. Errors: tagged unsupported ownership APIs fail closed.
 * Source: BER/CER owned runtime record methods. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: string and OID field methods.
 * Example: borrow a BitStringValue and write its exact bit length.
 */
static int
rust_write_ber_cer_encode_owned(FILE *stream, asn1p_expr_t *member,
                                const char *value, const char *tag,
                                int tagged, int explicit_tag) {
    const char *kind;
    if(tagged || explicit_tag) {
        if(member->expr_type == ASN_BASIC_OCTET_STRING)
            return rust_write_ber_cer_octets(stream, member, value, tag,
                                             tagged, explicit_tag);
        if(member->expr_type == ASN_BASIC_BIT_STRING)
            return rust_write_ber_cer_bits(stream, member, value, tag,
                                           tagged, explicit_tag);
        return -1;
    }
    switch(member->expr_type) {
    case ASN_BASIC_OCTET_STRING:
        return rust_write_ber_cer_octets(stream, member, value, tag, 0, 0);
    case ASN_BASIC_BIT_STRING:
        return rust_write_ber_cer_bits(stream, member, value, tag, 0, 0);
    case ASN_STRING_IA5String:
        return fprintf(stream, "writer.write_ia5_string(%s)?;\n", value) < 0 ? -1 : 0;
    case ASN_BASIC_OBJECT_IDENTIFIER:
        return fprintf(stream, "writer.write_object_identifier(%s)?;\n", value) < 0
            ? -1 : 0;
    case ASN_BASIC_RELATIVE_OID:
        return fprintf(stream, "writer.write_relative_oid(%s)?;\n", value) < 0
            ? -1 : 0;
    default:
        kind = rust_character_string_kind(member);
        if(!kind) return -1;
        return fprintf(stream,
            "writer.write_character_string(\n"
            "    ::asn1c_runtime::CharacterStringKind::%s, %s)?;\n",
            kind, value) < 0 ? -1 : 0;
    }
}

/*
 * Purpose: dispatch a required or present record field to its BER/CER writer.
 * Inputs: stream/parent/member/value identify generated code and fixed field.
 * Returns zero or -1. Errors: tag, descriptor, or output failures propagate.
 * Source: X.690 record codecs and shared-context runtime. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: direct and named field writes.
 * Example: emit a natural Small wrapper as a bounded INTEGER field.
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
    if(rust_ber_cer_named_integer_target(member))
        return rust_write_ber_cer_integer(stream, member, value, tag_argument,
                                          tagged, explicit_tag);
    if(rust_ber_cer_named_sequence_target(member))
        return rust_write_ber_cer_encode_nested(stream, parent, member, value,
                                                tag_local, tagged, explicit_tag);
    if(member->expr_type == ASN_CONSTR_CHOICE)
        return rust_write_ber_cer_encode_choice(stream, parent, member, value);
    if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET)
        return rust_write_ber_cer_encode_nested(stream, parent, member, value,
                                                tag_local, tagged, explicit_tag);
    if(member->expr_type == ASN_BASIC_BOOLEAN || member->expr_type == ASN_BASIC_NULL
       || member->expr_type == ASN_BASIC_INTEGER
       || member->expr_type == ASN_BASIC_ENUMERATED)
        return rust_write_ber_cer_encode_scalar(stream, parent, member, value,
                                                tag_argument, tagged, explicit_tag);
    return rust_write_ber_cer_encode_owned(stream, member, value,
                                           tag_argument, tagged, explicit_tag);
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
    asn1p_expr_t *named = rust_ber_cer_named_sequence_target(member);
    int ret;
    if(member->expr_type == ASN_BASIC_NULL || (named && !named->members.tq_head)) {
        if(fprintf(stream, "        if self.%s.is_some() {\n            ", name) < 0) return -1;
        ret = rust_write_sequence_ber_cer_encode_value(stream, parent, member, "()");
        if(ret < 0) return -1;
        return fputs("        }\n", stream) == EOF ? -1 : 0;
    }
    if(fprintf(stream, "        if let Some(value) = self.%s.as_ref() {\n            ", name) < 0)
        return -1;
    ret = rust_write_sequence_ber_cer_encode_value(
        stream, parent, member, rust_ber_cer_optional_value_expression(member));
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
 * Select the generated expression used for one present OPTIONAL field.
 * Inputs: member is the fixed field AST node.
 * Returns a static expression naming its borrowed or copied value.
 * Errors: none; unsupported forms are rejected before code generation.
 * Source: record field representation mapping. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: shared typed record writer.
 * Example: OCTET STRING uses `value.as_slice()` and BOOLEAN uses `*value`.
 */
static const char *
rust_ber_cer_optional_value_expression(asn1p_expr_t *member) {
    if(member->expr_type == ASN_BASIC_OCTET_STRING) return "value.as_slice()";
    if(rust_ber_cer_named_integer_target(member)) return "value.value()";
    if(member->expr_type == ASN_STRING_IA5String
       || member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
       || member->expr_type == ASN_BASIC_RELATIVE_OID
       || rust_character_string_kind(member)
       || (member->expr_type == ASN_BASIC_INTEGER && !member->constraints
           && !member->combined_constraints)) return "value";
    if(member->expr_type == ASN_BASIC_BIT_STRING) return "value";
    if(rust_ber_cer_named_sequence_target(member)
       || member->expr_type == ASN_CONSTR_SEQUENCE
       || member->expr_type == ASN_CONSTR_SET) return "value";
    if(member->expr_type == ASN_CONSTR_CHOICE) return "*value";
    return "*value";
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
    else if(rust_ber_cer_named_integer_target(member))
        written = snprintf(value, sizeof(value), "self.%s.value()", name);
    else if(member->expr_type == ASN_STRING_IA5String
            || member->expr_type == ASN_BASIC_OBJECT_IDENTIFIER
            || member->expr_type == ASN_BASIC_RELATIVE_OID
            || rust_character_string_kind(member)
            || (member->expr_type == ASN_BASIC_INTEGER && !member->constraints
                && !member->combined_constraints))
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
rust_write_sequence_ber_cer_decode_method(FILE *stream, const char *parent,
                                          asn1p_expr_t *expr, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    size_t choice_index = 0;
    asn1p_expr_t *choice = rust_ber_cer_choice_member(expr, &choice_index);
    const char *context_constructor = rust_ber_cer_context_constructor(expr);
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
    if(choice) {
        if(fputs("            let __asn1c_choice = ", stream) == EOF
           || rust_write_inline_choice_descriptor(stream, parent, choice)
           || fprintf(stream, ";\n"
               "            let mut reader = ::asn1c_runtime::ber::SequenceReader::"
               "new_tagged_with_choice(\n"
               "                input, &__asn1c_expected_fields, __asn1c_choice, %zu, "
               "&mut context)?;\n"
               "            let value = Self::decode_record_fields(&mut reader)?;\n"
               "            let consumed = reader.finish()?;\n"
               "            (value, consumed)\n"
               "        };\n", choice_index) < 0) return -1;
    } else if(tagged_root) {
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
        int ret = member->expr_type == ASN_CONSTR_CHOICE
            ? rust_write_sequence_ber_cer_choice_field(stream, parent, member, 1)
            : rust_write_sequence_ber_cer_decode_field(stream, parent, member, 1);
        if(ret) return -1;
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
    asn1p_expr_t *bounds_type = rust_ber_cer_named_integer_target(member);
    int64_t lower, upper;
    char low[64], high[64];
    if(rust_integer_bounds(bounds_type ? bounds_type : member, &lower, &upper)
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
 * Purpose: emit selected CHOICE decoding and convert to its generated enum.
 * Inputs: stream receives Rust; parent/member select enum and alternatives.
 * Returns zero or -1. Errors: nested name or output failures.
 * Source: shared ChoiceValue reader API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE record decode.
 * Example: map a selected runtime Integer arm to the nested enum.
 */
static int
rust_write_ber_cer_decode_choice(FILE *stream, const char *parent,
                                 asn1p_expr_t *member, const char *indent) {
    asn1p_expr_t *alternative;
    char *nested_type = rust_nested_type_name(parent, member);
    size_t count = 0;
    int written;
    TQ_FOR(alternative, &member->members, next) count++;
    if(!nested_type) return -1;
    written = fprintf(stream, "%slet value = %s::from_runtime_value(\n"
        "%s    reader.read_choice()?)%s;\n", indent, nested_type, indent,
        count == 3 ? "" : "?");
    free(nested_type);
    return written < 0 ? -1 : 0;
}

/*
 * Purpose: emit scalar BOOLEAN, NULL, INTEGER, or ENUMERATED reader calls.
 * Inputs: stream/member/parent/indent identify generated code and fixed field.
 * Returns zero or -1. Errors: output or bound formatting failures.
 * Source: X.690 primitive reader APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: scalar BER/CER record decode.
 * Example: apply the named INTEGER target's bounds before constructing its newtype.
 */
static int
rust_write_ber_cer_decode_scalar(FILE *stream, const char *parent,
                                 asn1p_expr_t *member, const char *indent) {
    switch(member->expr_type) {
    case ASN_BASIC_BOOLEAN:
        return fprintf(stream, "%slet value = reader.read_boolean()?;\n", indent) < 0
            ? -1 : 0;
    case ASN_BASIC_NULL:
        return fprintf(stream, "%sreader.read_null()?;\n", indent) < 0 ? -1 : 0;
    case ASN_BASIC_INTEGER:
        if(!member->constraints && !member->combined_constraints)
            return fprintf(stream, "%slet value = reader.read_big_integer()?;\n", indent) < 0
                ? -1 : 0;
        return rust_write_ber_cer_decode_integer(stream, member, indent);
    case ASN_BASIC_ENUMERATED:
        if(fprintf(stream, "%slet value = ", indent) < 0
           || rust_write_sequence_ber_cer_enum_decode(stream, parent, member)
           || fputs(";\n", stream) == EOF) return -1;
        return 0;
    default:
        return -1;
    }
}

/*
 * Purpose: emit reads for owned string, BIT STRING, IA5, and OID field values.
 * Inputs: stream/member/indent identify a validated variable or packed field.
 * Returns zero or -1. Errors: runtime validates content and field bounds.
 * Source: shared owned value reader APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: owned record field decode.
 * Example: read an OID through the parent's aggregate scratch context.
 */
static int
rust_write_ber_cer_decode_owned(FILE *stream, asn1p_expr_t *member,
                                const char *indent) {
    switch(member->expr_type) {
    case ASN_BASIC_OCTET_STRING:
        return rust_write_ber_cer_decode_octets(stream, member, indent);
    case ASN_BASIC_BIT_STRING:
        return rust_write_ber_cer_decode_bits(stream, member, indent);
    case ASN_STRING_IA5String:
        return fprintf(stream, "%slet value = reader.read_ia5_string()?;\n", indent) < 0
            ? -1 : 0;
    case ASN_BASIC_OBJECT_IDENTIFIER:
        return fprintf(stream, "%slet value = reader.read_object_identifier()?;\n",
                       indent) < 0 ? -1 : 0;
    case ASN_BASIC_RELATIVE_OID:
        return fprintf(stream, "%slet value = reader.read_relative_oid()?;\n",
                       indent) < 0 ? -1 : 0;
    default:
        return -1;
    }
}

/*
 * Purpose: emit named-newtype decode using the target's shared bounded INTEGER.
 * Inputs: stream/member/indent identify the field and generated destination.
 * Returns zero or -1. Errors: name allocation, range formatting, or output fail.
 * Source: fixed same-module INTEGER assignment. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: named INTEGER field decode.
 * Example: `read_integer(0, 5)` is wrapped with `Small::new`.
 */
static int
rust_write_ber_cer_decode_named_integer(FILE *stream, asn1p_expr_t *member,
                                        const char *indent) {
    asn1p_expr_t *target = rust_ber_cer_named_integer_target(member);
    char *named_type;
    int written;
    if(!target || rust_write_ber_cer_decode_integer(stream, member, indent)) return -1;
    named_type = rust_identifier(target->Identifier, 0);
    if(!named_type) return -1;
    written = fprintf(stream, "%slet value = %s::new(value)?;\n", indent, named_type);
    free(named_type);
    return written < 0 ? -1 : 0;
}

/*
 * Purpose: emit a type-specific decode expression for one record field.
 * Inputs: stream/parent/member/indent identify output and fixed field metadata.
 * Returns zero or -1. Errors: runtime reports malformed or over-limit input.
 * Source: X.690 and generated newtype APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: split field decoder dispatch.
 * Example: decode bounded `Small`, then validate its target range.
 */
static int
rust_write_sequence_ber_cer_decode_value(FILE *stream, const char *parent,
                                         asn1p_expr_t *member, const char *indent) {
    const char *character_kind = rust_character_string_kind(member);
    if(rust_ber_cer_named_integer_target(member))
        return rust_write_ber_cer_decode_named_integer(stream, member, indent);
    if(rust_ber_cer_named_sequence_target(member))
        return rust_write_nested_ber_cer_decode_value(stream, parent, member, indent);
    if(character_kind)
        return fprintf(stream,
            "%slet value = reader.read_character_string(\n"
            "%s    ::asn1c_runtime::CharacterStringKind::%s)?;\n",
            indent, indent, character_kind) < 0 ? -1 : 0;
    if(member->expr_type == ASN_CONSTR_CHOICE)
        return rust_write_ber_cer_decode_choice(stream, parent, member, indent);
    if(member->expr_type == ASN_CONSTR_SEQUENCE || member->expr_type == ASN_CONSTR_SET)
        return rust_write_nested_ber_cer_decode_value(stream, parent, member, indent);
    if(member->expr_type == ASN_BASIC_BOOLEAN || member->expr_type == ASN_BASIC_NULL
       || member->expr_type == ASN_BASIC_INTEGER
       || member->expr_type == ASN_BASIC_ENUMERATED)
        return rust_write_ber_cer_decode_scalar(stream, parent, member, indent);
    return rust_write_ber_cer_decode_owned(stream, member, indent);
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
    asn1p_expr_t *named_sequence = rust_ber_cer_named_sequence_target(member);
    asn1p_expr_t *child_record = named_sequence ? named_sequence : member;
    char *nested_type = named_sequence
        ? rust_identifier(named_sequence->Identifier, 0)
        : rust_nested_type_name(parent, member);
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
    TQ_FOR(child, &child_record->members, next) {
        if(rust_write_ber_cer_field_descriptor(stream, child, child_indent)) {
            free(nested_type);
            return -1;
        }
    }
    written = fprintf(stream,
        "%s];\n%slet value = reader.read_nested_%s(\n"
        "%s    &__asn1c_child_fields,\n"
        "%s    %s::decode_record_fields,\n"
        "%s)?;\n",
        indent, indent, member->expr_type == ASN_CONSTR_SET ? "set" : "sequence",
        indent, indent, nested_type, indent);
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
 * Purpose: emit a tag predicate for a natural or EXPLICIT CHOICE field.
 * Input: stream receives Rust; member is the validated CHOICE field.
 * Returns zero or -1. Errors: invalid fixed tags and output failures abort.
 * Source: intrinsic arm tags and the resolved EXPLICIT wrapper tag.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: inline CHOICE sequence dispatch. Example: match universal tag 5.
 */
static int
rust_write_inline_choice_tag_condition(FILE *stream, asn1p_expr_t *member, int mismatch) {
    asn1p_expr_t *alternative;
    int first = 1;
    if(member->tag.tag_class == TC_CONTEXT_SPECIFIC) {
        char number[16];
        if(rust_format_tag_number(number, sizeof(number),
                                  (uint32_t)member->tag.tag_value)) return -1;
        return fprintf(stream,
            "__asn1c_next_tag %s Some(::asn1c_runtime::ber::Tag::context_specific(%s))",
            mismatch ? "!=" : "==", number) < 0 ? -1 : 0;
    }
    TQ_FOR(alternative, &member->members, next) {
        uint32_t number = alternative->expr_type == ASN_BASIC_BOOLEAN ? 1
                        : alternative->expr_type == ASN_BASIC_NULL ? 5 : 2;
        if(fprintf(stream, "%s__asn1c_next_tag %s Some("
                    "::asn1c_runtime::ber::Tag::universal(%u))",
                   first ? "" : mismatch ? " && " : " || ",
                   mismatch ? "!=" : "==", number) < 0) return -1;
        first = 0;
    }
    return first ? -1 : 0;
}

/*
 * Purpose: emit one required or OPTIONAL CHOICE field in a SEQUENCE decoder.
 * Inputs: stream/parent/member identify output and the validated field.
 * Returns zero or -1. Errors: allocation and output failures abort generation.
 * Source: logical CHOICE presence over intrinsic X.690 alternative tags.
 * Version/date: 2026-11-01. Responsible party: asn1c maintainers.
 * History: inline CHOICE. Example: a selected arm consumes one logical slot.
 */
static int
rust_write_sequence_ber_cer_choice_field(FILE *stream, const char *parent,
                                         asn1p_expr_t *member, int tagged) {
    char *name = rust_identifier(member->Identifier, 1);
    char *nested_type = rust_nested_type_name(parent, member);
    asn1p_expr_t *alternative;
    size_t count = 0;
    int optional = member->marker.flags == EM_OPTIONAL;
    int ret;
    (void)tagged;
    TQ_FOR(alternative, &member->members, next) count++;
    if(!name || !nested_type) {
        free(name);
        free(nested_type);
        return -1;
    }
    ret = fprintf(stream, "                %s: ", name);
    if(ret >= 0 && optional) {
        ret = fputs("if ", stream) == EOF ? -1 : 0;
        if(ret >= 0) ret = rust_write_inline_choice_tag_condition(stream, member, 0);
        if(ret >= 0) ret = fputs(" {\n", stream) == EOF ? -1 : 0;
    }
    if(ret >= 0 && !optional) ret = fputs(" {\n"
        "                    if ", stream) == EOF ? -1 : 0;
    if(ret >= 0 && !optional)
        ret = rust_write_inline_choice_tag_condition(stream, member, 1);
    if(ret >= 0 && !optional) ret = fputs(" {\n"
        "                        return Err(::asn1c_runtime::Error::InvalidEncoding {\n"
        "                            reason: \"missing required SEQUENCE CHOICE\",\n"
        "                        });\n                    }\n", stream) == EOF ? -1 : 0;
    if(ret >= 0) ret = fprintf(stream,
        "                    let value = %s::from_runtime_value(\n"
        "                        reader.read_choice()?)%s;\n"
        "                    __asn1c_next_tag = reader.next_tagged_field()?;\n",
        nested_type, count == 3 ? "" : "?");
    if(ret >= 0) ret = optional
        ? fputs("                    Some(value)\n                } else { None },\n", stream)
        : fputs("                    value\n                },\n", stream);
    free(name);
    free(nested_type);
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
 * Purpose: emit owned enum conversions to the runtime's selected-value enum.
 * Source: approved direct BER/CER primitive CHOICE representation.
 * Version/date: 2026-11-01. Inputs: stream receives Rust; expr owns validated
 * alternatives. Returns zero or -1. Errors: output errors fail generation.
 * Responsible party: asn1c maintainers. History: initial BER/CER CHOICE slice.
 * Example: Choice::Flag(true) maps to ChoiceValue::Boolean(true).
 */
static int
rust_write_choice_value_conversions(FILE *stream, asn1p_expr_t *expr) {
    if(rust_write_choice_descriptors(stream, expr)
       || rust_write_choice_to_runtime(stream, expr)
       || rust_write_choice_from_runtime(stream, expr)) return -1;
    return 0;
}

/*
 * Purpose: emit a validated natural or EXPLICIT runtime CHOICE descriptor.
 * Inputs: stream receives Rust; parent and member identify the nested enum.
 * Returns zero or -1. Errors: invalid names/tags and output failures abort.
 * Source: shared-context runtime ChoiceField API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: inline CHOICE support.
 * Example: ChoiceField::explicit(tag, &Child::choice_alternatives()).
 */
static int
rust_write_inline_choice_descriptor(FILE *stream, const char *parent,
                                    asn1p_expr_t *member) {
    char *nested_type = rust_nested_type_name(parent, member);
    int explicit_tag = member->tag.tag_class == TC_CONTEXT_SPECIFIC;
    int ret;
    if(!nested_type) return -1;
    if(!explicit_tag) {
        ret = fprintf(stream,
            "::asn1c_runtime::ber::ChoiceField::natural(\n"
            "            &%s::choice_alternatives())?", nested_type);
        free(nested_type);
        return ret < 0 ? -1 : 0;
    }
    ret = fprintf(stream,
        "::asn1c_runtime::ber::ChoiceField::explicit(\n"
        "            ");
    if(ret >= 0) ret = rust_write_ber_cer_tag(stream, member);
    if(ret >= 0) ret = fprintf(stream,
        ",\n            &%s::choice_alternatives())?", nested_type);
    free(nested_type);
    return ret < 0 ? -1 : 0;
}

/*
 * Purpose: emit the allocation-free array of runtime tag and bound descriptors.
 * Source: approved runtime ChoiceAlternative API. Version/date: 2026-11-01.
 * Inputs: stream receives Rust source; expr owns validated alternatives.
 * Returns zero or -1. Errors: bound formatting and output failures abort emission.
 * Responsible party: asn1c maintainers. History: direct CHOICE generator.
 * Example: bounded INTEGER (-2..5) emits a BoundedInteger descriptor.
 */
static int
rust_write_choice_descriptors(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *item;
    size_t count = 0;
    TQ_FOR(item, &expr->members, next) count++;
    if(rust_write_method_doc(stream, "Build the runtime descriptors for this CHOICE.",
        "No inputs; descriptors preserve ASN.1 alternative order.",
        "Returns intrinsic tag kinds and integer bounds.",
        "No runtime error is possible for this validated fixed schema.",
        "`let alternatives = Self::choice_alternatives();")) return -1;
    if(fprintf(stream,
        "    const fn choice_alternatives() -> [::asn1c_runtime::ChoiceAlternative; %zu] {\n"
        "        [\n", count) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        if(item->expr_type == ASN_BASIC_BOOLEAN) {
            if(fputs("            ::asn1c_runtime::ChoiceAlternative::Boolean,\n", stream) == EOF)
                return -1;
        } else if(item->expr_type == ASN_BASIC_NULL) {
            if(fputs("            ::asn1c_runtime::ChoiceAlternative::Null,\n", stream) == EOF)
                return -1;
        } else {
            char lower[64], upper[64];
            int64_t lo, hi;
            if(rust_integer_bounds(item, &lo, &hi)
               || rust_format_bound(lower, sizeof(lower), lo)
               || rust_format_bound(upper, sizeof(upper), hi)) return -1;
            if(fprintf(stream,
                "            ::asn1c_runtime::ChoiceAlternative::BoundedInteger { "
                "lower: %s, upper: %s },\n", lower, upper) < 0) return -1;
        }
    }
    return fputs("        ]\n    }\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Purpose: emit conversion from each generated arm to the runtime value enum.
 * Source: approved runtime ChoiceValue API. Version/date: 2026-11-01.
 * Inputs: stream receives Rust source; expr owns validated alternatives.
 * Returns zero or -1. Errors: variant allocation or output failures abort.
 * Responsible party: asn1c maintainers. History: direct CHOICE generator.
 * Example: Self::Flag(value) maps to ChoiceValue::Boolean(*value).
 */
static int
rust_write_choice_to_runtime(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *item;
    if(rust_write_method_doc(stream, "Convert the selected arm to its runtime value.",
        "`self` identifies the selected enum alternative.",
        "Returns the corresponding runtime scalar value.",
        "No runtime error is possible for a generated enum value.",
        "`let selected = self.runtime_value();")) return -1;
    if(fputs(
        "    const fn runtime_value(self) -> ::asn1c_runtime::ChoiceValue {\n"
        "        match self {\n", stream) == EOF) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        int ret = !variant ? -1 : item->expr_type == ASN_BASIC_NULL
            ? fprintf(stream,
                "            Self::%s => ::asn1c_runtime::ChoiceValue::Null,\n", variant)
            : fprintf(stream,
                "            Self::%s(value) => ::asn1c_runtime::ChoiceValue::%s(value),\n",
                variant, item->expr_type == ASN_BASIC_BOOLEAN ? "Boolean" : "Integer");
        free(variant);
        if(ret < 0) return -1;
    }
    return fputs("        }\n    }\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Purpose: emit conversion from runtime scalar values to generated enum arms.
 * Source: approved runtime ChoiceValue API. Version/date: 2026-11-01.
 * Inputs: stream receives Rust source; expr owns validated alternatives.
 * Returns zero or -1. Errors: output failures abort emission; absent arms map to
 * InvalidEncoding. Responsible party: asn1c maintainers. History: direct CHOICE.
 * Example: ChoiceValue::Null maps to Self::Empty when that arm exists.
 */
static int
rust_write_choice_from_runtime(FILE *stream, asn1p_expr_t *expr) {
    asn1p_expr_t *item;
    const asn1p_expr_t *boolean_item = NULL, *null_item = NULL, *integer_item = NULL;
    const asn1p_expr_t *items[3];
    size_t selected_count;
    size_t index;
    TQ_FOR(item, &expr->members, next) {
        if(item->expr_type == ASN_BASIC_BOOLEAN) boolean_item = item;
        else if(item->expr_type == ASN_BASIC_NULL) null_item = item;
        else integer_item = item;
    }
    items[0] = boolean_item;
    items[1] = null_item;
    items[2] = integer_item;
    selected_count = (boolean_item != NULL) + (null_item != NULL) + (integer_item != NULL);
    if(rust_write_method_doc(stream, "Convert a runtime scalar to the generated enum.",
        "`value` is the decoded selected primitive.",
        "Returns the matching enum alternative.",
        "Returns an error if the runtime selected a tag absent from this schema.",
        "`let choice = Self::from_runtime_value(decoded.value);")) return -1;
    if(selected_count == 3) {
        if(fputs(
            "    const fn from_runtime_value(value: ::asn1c_runtime::ChoiceValue) -> Self {\n"
            "        match value {\n", stream) == EOF) return -1;
    } else if(fputs(
        "    const fn from_runtime_value(value: ::asn1c_runtime::ChoiceValue) ->\n"
        "        ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
        "        match value {\n", stream) == EOF) return -1;
    for(index = 0; index < 3; index++) {
        static const char *const pattern[3] = {
            "Boolean(value)", "Null", "Integer(value)"
        };
        const asn1p_expr_t *selected = items[index];
        if(selected) {
            char *variant = rust_enum_variant(selected->Identifier);
            int ret = !variant ? -1 : index == 1
                ? fprintf(stream,
                    selected_count == 3
                    ? "            ::asn1c_runtime::ChoiceValue::%s => Self::%s,\n"
                    : "            ::asn1c_runtime::ChoiceValue::%s => Ok(Self::%s),\n",
                    pattern[index], variant)
                : fprintf(stream, selected_count == 3
                    ? "            ::asn1c_runtime::ChoiceValue::%s => Self::%s(value),\n"
                    : "            ::asn1c_runtime::ChoiceValue::%s => Ok(Self::%s(value)),\n",
                    pattern[index], variant);
            free(variant);
            if(ret < 0) return -1;
        }
    }
    if(rust_write_choice_absent_arm(stream, items)) return -1;
    return fputs("        }\n    }\n\n", stream) == EOF ? -1 : 0;
}

/*
 * Purpose: emit one merged error arm for runtime alternatives absent from schema.
 * Source: runtime ChoiceValue enum and validated intrinsic CHOICE tags.
 * Version/date: 2026-11-01. Inputs: stream receives Rust; items map each tag to
 * the source alternative or NULL. Returns zero or -1. Errors: output failures.
 * Responsible party: asn1c maintainers. History: direct CHOICE emitter.
 * Example: absent NULL and INTEGER variants form one or-pattern error arm.
 */
static int
rust_write_choice_absent_arm(FILE *stream, const asn1p_expr_t *const items[3]) {
    static const char *const patterns[3] = {"Boolean(_)", "Null", "Integer(_)"};
    size_t index, missing = 0, emitted = 0;
    for(index = 0; index < 3; index++) missing += items[index] == NULL;
    if(!missing) return 0;
    if(fputs("            ::asn1c_runtime::ChoiceValue::", stream) == EOF) return -1;
    for(index = 0; index < 3; index++) {
        if(items[index]) continue;
        if(emitted && fputs(" | ::asn1c_runtime::ChoiceValue::", stream) == EOF) return -1;
        if(fputs(patterns[index], stream) == EOF) return -1;
        emitted++;
    }
    return fputs(
        " => Err(::asn1c_runtime::Error::InvalidEncoding { "
        "reason: \"runtime selected an absent CHOICE tag\" }),\n", stream) == EOF ? -1 : 0;
}

/*
 * Purpose: emit a typed untagged primitive CHOICE with BER/DER/CER methods.
 * Source: approved direct X.690 primitive CHOICE gate and runtime API.
 * Version/date: 2026-11-01. Inputs: stream receives Rust; name is the type;
 * expr owns validated alternatives; codecs selects emitted methods.
 * Returns zero or -1. Errors: allocation or output failures abort generation.
 * Responsible party: asn1c maintainers. History: initial BER/CER CHOICE slice.
 * Example: `Value::Count(3)` encodes as its INTEGER TLV with no outer wrapper.
 */
static int
rust_write_ber_cer_choice(FILE *stream, const char *name, asn1p_expr_t *expr,
                          uint64_t codecs, int top_level) {
    asn1p_expr_t *item;
    size_t alternative_count = 0;
    int full_choice;
    TQ_FOR(item, &expr->members, next) alternative_count++;
    full_choice = alternative_count == 3;
    if(fprintf(stream,
        "/// Selected primitive alternative of an untagged ASN.1 CHOICE.\n"
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n"
        "pub enum %s {\n", name) < 0) return -1;
    TQ_FOR(item, &expr->members, next) {
        char *variant = rust_enum_variant(item->Identifier);
        const char *type = item->expr_type == ASN_BASIC_BOOLEAN ? "bool"
                           : item->expr_type == ASN_BASIC_INTEGER ? "i64" : NULL;
        int ret = !variant ? -1 : type
            ? fprintf(stream,
                "    /// Selected ASN.1 %s alternative.\n    %s(%s),\n",
                item->Identifier, variant, type)
            : fprintf(stream,
                "    /// Selected ASN.1 %s alternative.\n    %s,\n",
                item->Identifier, variant);
        free(variant);
        if(ret < 0) return -1;
    }
    if(fprintf(stream, "}\n\nimpl %s {\n", name) < 0
       || rust_write_choice_value_conversions(stream, expr)) return -1;
    if(!top_level) return fputs("}\n\n", stream) == EOF ? -1 : 0;
    if(codecs & RUST_CODEC_BER) {
        if(rust_write_method_doc(stream, "Encode the selected alternative using DER.",
            "`self` selects the primitive; `limits` bounds the operation.",
            "Returns exactly the selected primitive TLV.",
            "Returns an error for invalid bounds or exhausted resources.",
        "`let encoded = value.encode_der(&Default::default())?;")) return -1;
        if(fputs(
            "    pub fn encode_der(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let alternatives = Self::choice_alternatives();\n"
            "        ::asn1c_runtime::encode_choice_der(\n"
            "            &alternatives, (*self).runtime_value(), limits)\n"
            "    }\n\n", stream) == EOF
           || rust_write_method_doc(stream, "Decode one BER CHOICE prefix.",
            "`input` is a complete or suffixed TLV; `limits` bounds the operation.",
            "Returns the selected enum value and exact prefix consumption.",
            "Returns an error for malformed, unknown, out-of-range, or over-limit input.",
            "`let decoded = Value::decode_ber(input, &Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn decode_ber(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
            "        let alternatives = Self::choice_alternatives();\n"
            "        let decoded = ::asn1c_runtime::decode_choice_ber(input, &alternatives, limits)?;\n"
            "        Ok(::asn1c_runtime::Decoded {\n"
            "            value: Self::from_runtime_value(decoded.value)%s,\n",
            full_choice ? "" : "?") < 0 || fputs(
            "            consumed_bits: decoded.consumed_bits,\n"
            "            consumed_bytes: decoded.consumed_bytes,\n"
            "        })\n    }\n\n", stream) == EOF) return -1;
    }
    if(codecs & RUST_CODEC_CER) {
        if(rust_write_method_doc(stream, "Encode the selected alternative using CER.",
            "`self` selects the primitive; `limits` bounds the operation.",
            "Returns exactly the selected canonical primitive TLV.",
            "Returns an error for invalid bounds or exhausted resources.",
            "`let encoded = value.encode_cer(&Default::default())?;")) return -1;
        if(fputs(
            "    pub fn encode_cer(&self, limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Encoded, ::asn1c_runtime::Error> {\n"
            "        let alternatives = Self::choice_alternatives();\n"
            "        ::asn1c_runtime::encode_choice_cer(\n"
            "            &alternatives, (*self).runtime_value(), limits)\n"
            "    }\n\n", stream) == EOF
           || rust_write_method_doc(stream, "Decode and strictly validate one CER CHOICE prefix.",
            "`input` is a complete or suffixed TLV; `limits` bounds all work.",
            "Returns the selected enum value and exact prefix consumption.",
            "Returns an error for malformed, noncanonical, out-of-range, or over-limit input.",
            "`let decoded = Value::decode_cer(input, &Default::default())?;")) return -1;
        if(fprintf(stream,
            "    pub fn decode_cer(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
            "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, ::asn1c_runtime::Error> {\n"
            "        let alternatives = Self::choice_alternatives();\n"
            "        let decoded = ::asn1c_runtime::decode_choice_cer(input, &alternatives, limits)?;\n"
            "        Ok(::asn1c_runtime::Decoded {\n"
            "            value: Self::from_runtime_value(decoded.value)%s,\n",
            full_choice ? "" : "?") < 0 || fputs(
            "            consumed_bits: decoded.consumed_bits,\n"
            "            consumed_bytes: decoded.consumed_bytes,\n"
            "        })\n    }\n\n", stream) == EOF) return -1;
    }
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
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
        if(member->expr_type != ASN_CONSTR_SEQUENCE && member->expr_type != ASN_CONSTR_SET
           && member->expr_type != ASN_CONSTR_CHOICE
           && member->expr_type != ASN_BASIC_ENUMERATED) continue;
        nested_name = rust_nested_type_name(name, member);
        if(!nested_name) return -1;
        if((member->expr_type == ASN_CONSTR_SEQUENCE
            ? rust_write_all_sequences(stream, nested_name, member, 0, codecs)
            : member->expr_type == ASN_CONSTR_SET
              ? rust_write_set(stream, nested_name, member, 0, codecs)
              : member->expr_type == ASN_CONSTR_CHOICE
                ? rust_write_ber_cer_choice(stream, nested_name, member, codecs, 0)
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
    char *owned_type = NULL;
    const char *type = rust_ber_cer_record_field_type(parent, member, &owned_type);
    int ret = -1;
    if(name && type) {
        ret = member->marker.flags == EM_OPTIONAL
            ? fprintf(stream,
                "    /// ASN.1 %s OPTIONAL field state variable.\n"
                "    pub %s: ::core::option::Option<%s>,\n",
                member->Identifier, name, type)
            : fprintf(stream,
                "    /// ASN.1 %s field state variable.\n    pub %s: %s,\n",
                member->Identifier, name, type);
    }
    free(name);
    free(owned_type);
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
 * Emit one unbounded OBJECT IDENTIFIER or RELATIVE-OID wrapper.
 * Inputs: stream receives Rust; name is the schema type; relative selects the
 * runtime value type; codecs is the validated BER/CER-only mask. Returns zero
 * or -1 on output failure. Methods propagate malformed-input and limit errors.
 * Source: approved standalone BER/CER OID APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: direct OID generator slice.
 * Example: rust_write_oid(out, "ObjectId", 0, RUST_CODEC_BER).
 */
static int
rust_write_oid(FILE *stream, const char *name, int relative, uint64_t codecs) {
    const char *kind = relative ? "RELATIVE-OID" : "OBJECT IDENTIFIER";
    const char *runtime_type = relative ? "RelativeOid" : "ObjectIdentifier";
    if(fprintf(stream,
        "/// Unconstrained ASN.1 %s with private canonical content.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Canonical base-128 content state variable.\n"
        "    ::asn1c_runtime::%s\n"
        ");\n\nimpl %s {\n", kind, name, runtime_type, name) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Construct from encoded subidentifier content.",
            "`content` contains base-128 groups; `limits` bounds input and work.",
            "Returns owned content with redundant leading groups normalized.",
            "Returns an error for empty, unterminated, or over-limit content.",
            "`let value = Type::try_from_content(&[0x2a, 0x03], &limits)?;"))
        return -1;
    if(fprintf(stream,
        "    pub fn try_from_content(\n"
        "        content: &[u8], limits: &::asn1c_runtime::Limits\n"
        "    ) -> ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::%s::try_from_content(content, limits).map(Self)\n"
        "    }\n", runtime_type) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Borrow the canonical encoded subidentifier content.",
            "`self` is the value to inspect.",
            "Returns canonical base-128 content without a universal tag.",
            "This accessor cannot fail.", "`let content = value.as_content();"))
        return -1;
    if(fprintf(stream,
        "    #[must_use]\n"
        "    pub fn as_content(&self) -> &[u8] { self.0.as_content() }\n") < 0)
        return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_oid_ber_cer(stream, relative, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_oid_ber_cer(stream, relative, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit one DER/BER or CER method pair for an OID wrapper.
 * Inputs: stream receives Rust; relative selects RELATIVE-OID; cer selects CER.
 * Returns zero or -1 on output failure. Runtime errors report invalid input.
 * Source: standalone BER runtime OID APIs. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: codec-selective OID output.
 * Example: rust_write_oid_ber_cer(stream, 1, 1) emits RELATIVE-OID CER methods.
 */
static int
rust_write_oid_ber_cer(FILE *stream, int relative, int cer) {
    const char *family = relative ? "relative_oid" : "object_identifier";
    const char *suffix = cer ? "cer" : "ber";
    const char *encode_suffix = cer ? "cer" : "der";
    const char *description = cer
        ? "Encode this value using canonical CER."
        : "Encode this value using DER.";
    const char *decode_description = cer
        ? "Strictly decode one CER OID TLV and report prefix consumption."
        : "Decode one BER OID TLV and report prefix consumption.";
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
            "`self` is validated; `limits` bounds output and work.",
            "Returns the complete canonical universal OID TLV.",
            "Returns a runtime error if a configured limit is exceeded.", encode_example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_%s_%s(&self.0, limits)\n"
        "    }\n", encode_suffix, family, encode_suffix) < 0)
        return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is a prefix; `limits` bounds input, decoded storage, and work.",
            "Returns the canonical value and exact consumed bit and byte counts.",
            decode_error, decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_%s_%s(input, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n",
        suffix, family, suffix) < 0)
        return -1;
    return 0;
}

/*
 * Emit one unbounded IA5String wrapper with private owned raw-byte storage.
 * Inputs: stream receives Rust, name is the schema type, and codecs is the
 * validated BER/CER-only mask. Returns zero or -1 on output failure.
 * Errors: generated methods propagate codec validation and limit errors.
 * Source: approved IA5String BER/CER API. Version/date: 2026-11-01.
 * Responsible party: asn1c maintainers. History: direct IA5String slice.
 * Example: rust_write_ia5_string(out, "Text", RUST_CODEC_CER).
 */
static int
rust_write_ia5_string(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream,
        "/// Unconstrained ASN.1 `IA5String` with private raw-byte storage.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Owned `IA5String` content state variable.\n"
        "    ::asn1c_runtime::Ia5String\n"
        ");\n\nimpl %s {\n", name, name) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Construct an owned `IA5String` from raw bytes.",
            "`bytes` is raw content; `limits` bounds input, storage, and work.",
            "Returns privately owned bytes without applying CER's 7-bit check.",
            "Returns an error if input or allocation exceeds configured limits.",
            "`let value = Type::try_from_bytes(&[0x80], &limits)?;"))
        return -1;
    if(fputs("    pub fn try_from_bytes(\n"
             "        bytes: &[u8], limits: &::asn1c_runtime::Limits\n"
             "    ) -> ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::Ia5String::try_from_bytes(bytes, limits)\n"
             "            .map(Self)\n    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream, "Borrow the stored `IA5String` content bytes.",
            "`self` is the value to inspect.",
            "Returns the original content bytes without copying.",
            "This accessor cannot fail.", "`let bytes = value.as_bytes();"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }\n",
             stream) == EOF)
        return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_ia5_string_ber_cer(stream, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_ia5_string_ber_cer(stream, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit one DER/BER or CER method pair for the IA5String wrapper.
 * Inputs: stream receives Rust; cer selects CER instead of DER/BER.
 * Returns zero or -1 on output failure. BER/DER preserve arbitrary octets;
 * CER methods apply the strict 7-bit IA5 constraint. Source: runtime IA5 APIs.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers.
 * History: codec-selective IA5 output. Example: rust_write_ia5_string_ber_cer(out, 1).
 */
static int
rust_write_ia5_string_ber_cer(FILE *stream, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *encode = cer ? "cer" : "der";
    const char *description = cer
        ? "Encode this value using strict IA5 CER rules."
        : "Encode this value using DER while preserving raw content bytes.";
    const char *decode_description = cer
        ? "Strictly decode one CER `IA5String` TLV and report prefix consumption."
        : "Decode one BER `IA5String` TLV and report prefix consumption.";
    const char *encode_result = cer
        ? "Returns an error if content contains a byte above 7f or exceeds limits."
        : "Returns an error if output or work exceeds configured limits.";
    const char *decode_result = cer
        ? "Returns an error for invalid IA5 bytes, noncanonical input, or limits."
        : "Returns an error for malformed input or exhausted limits.";
    const char *encode_example = cer
        ? "`let encoded = value.encode_cer(&Default::default())?;"
        : "`let encoded = value.encode_der(&Default::default())?;";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";

    if(rust_write_method_doc(stream, description,
            "`self` is the value; `limits` bounds output and work.",
            "Returns the complete universal tag 22 TLV.", encode_result, encode_example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_ia5_string_%s(&self.0, limits)\n"
        "    }\n", encode, encode) < 0)
        return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is a prefix; `limits` bounds input, decoded storage, and work.",
            "Returns the value and exact consumed byte and bit counts.",
            decode_result, decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_ia5_string_%s(input, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n",
        suffix, suffix) < 0)
        return -1;
    return 0;
}

/* Emit a private-byte wrapper for one fixed restricted ASN.1 string kind.
 * Inputs: stream receives Rust; name is the generated assignment; expr selects
 * the fixed runtime kind; codecs is a validated BER/CER mask. Returns zero or
 * -1 on output failure. Errors: runtime methods report malformed data/limits.
 * Source: approved CharacterString runtime API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: direct restricted-string roots.
 * Example: rust_write_character_string(out, "Text", utf8, RUST_CODEC_BER).
 */
static int
rust_write_character_string(FILE *stream, const char *name, asn1p_expr_t *expr,
                            uint64_t codecs) {
    const char *kind = rust_character_string_kind(expr);
    const char *asn_name = rust_character_string_name(expr);
    if(!kind || !asn_name) return -1;
    if(fprintf(stream,
        "/// Unconstrained ASN.1 `%s` with private raw-byte storage.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Owned character-string content state variable.\n"
        "    ::asn1c_runtime::CharacterString\n"
        ");\n\nimpl %s {\n", asn_name, name, name) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Construct an owned character string from raw bytes.",
            "`bytes` is raw content; `limits` bounds input, storage, and work.",
            "Returns privately owned bytes without applying CER validation.",
            "Returns an error if input or allocation exceeds configured limits.",
            "`let value = Type::try_from_bytes(&[0xff], &limits)?;"))
        return -1;
    if(fprintf(stream,
        "    pub fn try_from_bytes(\n"
        "        bytes: &[u8], limits: &::asn1c_runtime::Limits\n"
        "    ) -> ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::CharacterString::try_from_bytes(\n"
        "            ::asn1c_runtime::CharacterStringKind::%s, bytes, limits\n"
        "        ).map(Self)\n    }\n", kind) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Borrow the stored character-string bytes.",
            "`self` is the value to inspect.",
            "Returns the original content bytes without copying.",
            "This accessor cannot fail.", "`let bytes = value.as_bytes();"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }\n",
             stream) == EOF)
        return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_character_string_ber_cer(stream, kind, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_character_string_ber_cer(stream, kind, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit selected DER/BER and CER methods for a fixed character-string kind.
 * Inputs: stream receives Rust; kind is the runtime enum variant; cer selects
 * CER rather than BER/DER. Returns zero or -1 on output failure. Errors are
 * returned by runtime codecs. Source: CharacterString runtime API.
 * Version/date: 2026-11-01. Responsible: asn1c maintainers. History: direct
 * restricted roots. Example: rust_write_character_string_ber_cer(out, "Utf8String", 1).
 */
static int
rust_write_character_string_ber_cer(FILE *stream, const char *kind, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *encode = cer ? "cer" : "der";
    const char *description = cer
        ? "Encode this value using the selected character-string CER rules."
        : "Encode this value using DER while preserving raw content bytes.";
    const char *decode_description = cer
        ? "Strictly decode one CER string TLV and report prefix consumption."
        : "Decode one BER string TLV and report prefix consumption.";
    const char *encode_result = cer
        ? "Returns an error for invalid content, output limits, or work limits."
        : "Returns an error if output or work exceeds configured limits.";
    const char *decode_result = cer
        ? "Returns an error for invalid content, noncanonical input, or limits."
        : "Returns an error for malformed input or exhausted limits.";
    const char *encode_example = cer
        ? "`let encoded = value.encode_cer(&Default::default())?;"
        : "`let encoded = value.encode_der(&Default::default())?;";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";
    if(rust_write_method_doc(stream, description,
            "`self` is the value; `limits` bounds output and work.",
            "Returns the complete universal-tag TLV.", encode_result, encode_example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_character_string_%s(&self.0, limits)\n"
        "    }\n", encode, encode) < 0)
        return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is a prefix; `limits` bounds input, decoded storage, and work.",
            "Returns the value and exact consumed byte and bit counts.",
            decode_result, decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_character_string_%s(\n"
        "            input, ::asn1c_runtime::CharacterStringKind::%s, limits\n"
        "        ).map(|decoded| decoded.map(Self))\n    }\n",
        suffix, suffix, kind) < 0)
        return -1;
    return 0;
}

/* Emit a private raw-byte wrapper for one fixed ASN.1 UTCTime root.
 * Inputs: stream receives Rust; name is the generated assignment; codecs is
 * a validated BER/CER selection. Returns zero or -1 on write failure.
 * Errors: generated methods propagate validation and limit errors.
 * Source: approved UtcTime runtime API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: direct tag 23 root.
 * Example: rust_write_utc_time(stream, "Timestamp", RUST_CODEC_CER).
 */
static int
rust_write_utc_time(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream,
        "/// Direct ASN.1 `UTCTime` with private raw-byte storage.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Owned `UTCTime` content state variable.\n"
        "    ::asn1c_runtime::UtcTime\n"
        ");\n\nimpl %s {\n", name, name) < 0)
        return -1;
    if(rust_write_method_doc(stream, "Construct an owned `UTCTime` from raw bytes.",
            "`bytes` is raw content; `limits` bounds input, storage, and work.",
            "Returns privately owned content without validating time syntax.",
            "Returns an error if input or allocation exceeds configured limits.",
            "`let value = Type::try_from_bytes(b\"9912312359Z\", &limits)?;"))
        return -1;
    if(fputs("    pub fn try_from_bytes(\n"
             "        bytes: &[u8], limits: &::asn1c_runtime::Limits\n"
             "    ) -> ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::UtcTime::try_from_bytes(bytes, limits)\n"
             "            .map(Self)\n    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream, "Borrow the stored `UTCTime` content bytes.",
            "`self` is the value to inspect.",
            "Returns raw content without copying.", "This accessor cannot fail.",
            "`let bytes = value.as_bytes();"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }\n",
             stream) == EOF)
        return -1;
    if((codecs & RUST_CODEC_BER) && rust_write_utc_time_ber_cer(stream, 0)) return -1;
    if((codecs & RUST_CODEC_CER) && rust_write_utc_time_ber_cer(stream, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit the selected DER/BER or canonical CER method pair for UTCTime.
 * Inputs: stream receives Rust; cer selects CER instead of BER/DER.
 * Returns zero or -1 on output failure. Runtime failures remain typed errors.
 * Source: UtcTime runtime API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: codec-selective time output.
 * Example: rust_write_utc_time_ber_cer(stream, 1) emits strict CER methods.
 */
static int
rust_write_utc_time_ber_cer(FILE *stream, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *encode = cer ? "cer" : "der";
    const char *description = cer
        ? "Encode this value as normalized canonical CER `UTCTime`."
        : "Encode this value as raw DER `UTCTime` without syntax validation.";
    const char *decode_description = cer
        ? "Strictly decode one canonical CER `UTCTime` TLV and report prefix use."
        : "Decode one BER `UTCTime` TLV and report exact prefix consumption.";
    const char *encode_result = cer
        ? "Returns an error for invalid dates, zones, or limits."
        : "Returns an error if output or work exceeds configured limits.";
    const char *decode_result = cer
        ? "Returns an error for invalid/noncanonical time text or exhausted limits."
        : "Returns an error for malformed BER framing or exhausted limits.";
    const char *decode_value = cer
        ? "Returns normalized time content and exact consumed byte and bit counts."
        : "Returns raw time content and exact consumed byte and bit counts.";
    const char *encode_example = cer
        ? "`let encoded = value.encode_cer(&Default::default())?;"
        : "`let encoded = value.encode_der(&Default::default())?;";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";
    if(rust_write_method_doc(stream, description,
            "`self` is the time; `limits` bounds output and work.",
            "Returns a complete universal tag 23 TLV.", encode_result, encode_example))
        return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_utc_time_%s(&self.0, limits)\n"
        "    }\n", encode, encode) < 0)
        return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is a prefix; `limits` bounds input, retained bytes, and work.",
            decode_value,
            decode_result, decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_utc_time_%s(input, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n",
        suffix, suffix) < 0)
        return -1;
    return 0;
}

/* Emit a private raw-byte wrapper for one direct GeneralizedTime root.
 * Inputs: stream receives Rust; name is the assignment; codecs is validated.
 * Returns zero or -1 on write failure. Runtime errors remain typed errors.
 * Source: approved GeneralizedTime runtime API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: direct universal tag 24.
 * Example: rust_write_generalized_time(stream, "CreatedAt", RUST_CODEC_CER).
 */
static int
rust_write_generalized_time(FILE *stream, const char *name, uint64_t codecs) {
    if(fprintf(stream,
        "/// Direct ASN.1 `GeneralizedTime` with private raw-byte storage.\n"
        "#[derive(Debug, Eq, PartialEq)]\n"
        "pub struct %s(\n"
        "    /// Owned `GeneralizedTime` content state variable.\n"
        "    ::asn1c_runtime::GeneralizedTime\n"
        ");\n\nimpl %s {\n", name, name) < 0)
        return -1;
    if(rust_write_method_doc(stream,
            "Construct an owned `GeneralizedTime` from raw bytes.",
            "`bytes` is raw content; `limits` bounds input, storage, and work.",
            "Returns privately owned content without validating time syntax.",
            "Returns an error if input or allocation exceeds configured limits.",
            "`let value = Type::try_from_bytes(b\"20260101120000Z\", &limits)?;"))
        return -1;
    if(fputs("    pub fn try_from_bytes(\n"
             "        bytes: &[u8], limits: &::asn1c_runtime::Limits\n"
             "    ) -> ::core::result::Result<Self, ::asn1c_runtime::Error> {\n"
             "        ::asn1c_runtime::GeneralizedTime::try_from_bytes(bytes, limits)\n"
             "            .map(Self)\n    }\n", stream) == EOF)
        return -1;
    if(rust_write_method_doc(stream,
            "Borrow the stored `GeneralizedTime` content bytes.",
            "`self` is the value to inspect.",
            "Returns raw content without copying.", "This accessor cannot fail.",
            "`let bytes = value.as_bytes();"))
        return -1;
    if(fputs("    #[must_use]\n"
             "    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }\n",
             stream) == EOF)
        return -1;
    if((codecs & RUST_CODEC_BER)
       && rust_write_generalized_time_ber_cer(stream, 0)) return -1;
    if((codecs & RUST_CODEC_CER)
       && rust_write_generalized_time_ber_cer(stream, 1)) return -1;
    return fputs("}\n\n", stream) == EOF ? -1 : 0;
}

/* Emit the selected DER/BER or canonical CER methods for GeneralizedTime.
 * Inputs: stream receives Rust; cer selects CER instead of BER/DER.
 * Returns zero or -1 on write failure. Runtime failures remain typed errors.
 * Source: GeneralizedTime runtime API. Version/date: 2026-11-01.
 * Responsible: asn1c maintainers. History: codec-selective time output.
 * Example: rust_write_generalized_time_ber_cer(stream, 1) emits CER methods.
 */
static int
rust_write_generalized_time_ber_cer(FILE *stream, int cer) {
    const char *suffix = cer ? "cer" : "ber";
    const char *encode = cer ? "cer" : "der";
    const char *description = cer
        ? "Encode this value as canonical CER `GeneralizedTime`."
        : "Encode this value as canonical DER `GeneralizedTime`.";
    const char *decode_description = cer
        ? "Strictly decode one canonical CER `GeneralizedTime` TLV and prefix."
        : "Decode one BER `GeneralizedTime` TLV with exact prefix consumption.";
    const char *encode_result =
        "Returns an error for invalid/unsupported time text or exhausted limits.";
    const char *decode_result = cer
        ? "Returns an error for invalid/noncanonical time text or exhausted limits."
        : "Returns an error for malformed BER framing or exhausted limits.";
    const char *decode_value = cer
        ? "Returns normalized time content and exact consumed byte and bit counts."
        : "Returns raw time content and exact consumed byte and bit counts.";
    const char *encode_example = cer
        ? "`let encoded = value.encode_cer(&Default::default())?;"
        : "`let encoded = value.encode_der(&Default::default())?;";
    const char *decode_example = cer
        ? "`let decoded = Type::decode_cer(input, &Default::default())?;"
        : "`let decoded = Type::decode_ber(input, &Default::default())?;";
    if(rust_write_method_doc(stream, description,
            "`self` is the time; `limits` bounds output and work.",
            "Returns canonical primitive universal tag 24.", encode_result,
            encode_example)) return -1;
    if(fprintf(stream,
        "    pub fn encode_%s(&self, limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Encoded, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::encode_generalized_time_%s(&self.0, limits)\n"
        "    }\n", encode, encode) < 0)
        return -1;
    if(rust_write_method_doc(stream, decode_description,
            "`input` is a prefix; `limits` bounds input, retained bytes, and work.",
            decode_value, decode_result, decode_example)) return -1;
    if(fprintf(stream,
        "    pub fn decode_%s(input: &[u8], limits: &::asn1c_runtime::Limits) ->\n"
        "        ::core::result::Result<::asn1c_runtime::Decoded<Self>, "
        "::asn1c_runtime::Error> {\n"
        "        ::asn1c_runtime::decode_generalized_time_%s(input, limits)\n"
        "            .map(|decoded| decoded.map(Self))\n    }\n",
        suffix, suffix) < 0)
        return -1;
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
