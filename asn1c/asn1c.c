/*
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.
 * Copyright (c) 2022-2025 Mouse <mouse07410@hotmail.com> and contributors.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * This is the program that connects the libasn1* libraries together.
 * It uses them in turn to parse, fix and then compile or print the ASN.1 tree.
 */
#include "asn1_common.h"

#undef COPYRIGHT
#define COPYRIGHT "Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.\n\
Copyright (c) 2022-2026 Mouse <5923577+mouse07410@users.noreply.github.com> and contributors.\n"

#include <asn1parser.h>   /* Parse the ASN.1 file and build a tree */
#include <asn1fix.h>      /* Fix the ASN.1 tree */
#include <asn1print.h>    /* Print the ASN.1 tree */
#include <asn1compiler.h> /* Compile the ASN.1 tree */
#include <asn1fix_export.h>

#include <asn1c_compat.h> /* Portable basename(3) and dirname(3) */

#ifdef _WIN32
#include <io.h>
#include <direct.h>
#else
#include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>

/*
 * Parse a string as a decimal integer with validation.
 * Returns 1 on success, 0 on failure (non-integer, overflow, or trailing garbage).
 * If out_val is non-NULL, stores the parsed value on success.
 */
static int
is_integer(const char *str, long *out_val) {
    char *endptr;
    errno = 0; /* To distinguish success/failure after call */

    /* 10 is the base (decimal) */
    long val = strtol(str, &endptr, 10);

    /* Check for various possible errors */
    if (str == endptr) return 0; /* No digits found at all */
    if (errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) return 0; /* Overflow */
    if (errno != 0 && val == 0) return 0; /* Other conversion error */

    /* Check for trailing garbage (optional) */
    /* If you want to allow "123 ", you'd check if *endptr is whitespace */
    if (*endptr != '\0') return 0;

    if (out_val) *out_val = val;
    return 1; /* Success */
}

static void usage(const char *av0); /* Print the Usage screen and exit */
static int importStandardModules(asn1p_t *asn, const char *skeletons_dir);

/*
 * Parsed state for one asn1c command-line invocation.
 * Every member is a state variable owned by main() until cleanup.
 */
typedef struct asn1c_cli_options_s {
    enum asn1p_flags parser_flags; /* ASN.1 parser state variable. */
    enum asn1f_flags fixer_flags; /* Tree fixer state variable. */
    enum asn1c_flags compiler_flags; /* C compiler state variable. */
    enum asn1print_flags printer_flags; /* Printer state variable. */
    int print_out; /* Parse-and-print state variable. */
    int fix_n_print; /* Fix-before-print state variable. */
    int warnings_as_errors; /* Warning policy state variable. */
    int rust_target; /* Whole-target selection state variable. */
    int skeletons_explicit; /* -S provenance state variable. */
    int skeletons_owned; /* Cleanup ownership state variable. */
    int complex_threshold; /* C compiler threshold state variable. */
    uint64_t rust_codec_flags; /* Rust codec selection state variable. */
    const char *rust_incompatible_option; /* Incompatible option state variable. */
    char *skeletons_dir; /* Support directory state variable. */
    char *destdir; /* Output directory state variable. */
    char **debug_type_names; /* Debug-name list state variable. */
    size_t debug_type_names_count; /* Debug-name count state variable. */
    char rust_runtime_dir[PATH_MAX]; /* Resolved runtime path state variable. */
} asn1c_cli_options_t;

static void asn1c_cli_options_init(asn1c_cli_options_t *);
static int asn1c_extract_rust_switch(int *, char **, int *);
static int asn1c_short_option_takes_argument(char);
static int asn1c_parse_options(int *, char **, asn1c_cli_options_t *);
static int asn1c_handle_option(int, const char *, asn1c_cli_options_t *,
                               const char *);
static int asn1c_handle_basic_option(int, const char *, asn1c_cli_options_t *,
                                     const char *);
static int asn1c_handle_destination_option(const char *, asn1c_cli_options_t *);
static int asn1c_handle_skeleton_option(const char *, asn1c_cli_options_t *);
static int asn1c_handle_debug_option(const char *, asn1c_cli_options_t *);
static int asn1c_handle_tree_mode_option(int, asn1c_cli_options_t *);
static int asn1c_handle_f_option(const char *, asn1c_cli_options_t *);
static int asn1c_handle_codec_option(int, const char *, asn1c_cli_options_t *);
static int asn1c_handle_print_option(int, const char *, asn1c_cli_options_t *);
static int asn1c_handle_warning_option(const char *, asn1c_cli_options_t *);
static void asn1c_mark_rust_incompatible(asn1c_cli_options_t *, const char *);
static int asn1c_handle_simple_f_option(const char *, asn1c_cli_options_t *);
static int asn1c_parse_long_size(const char *, asn1c_cli_options_t *);
static int asn1c_parse_integer_native_type(const char *, asn1c_cli_options_t *);
static int asn1c_parse_complex_threshold(const char *, asn1c_cli_options_t *);
static int asn1c_validate_options(const asn1c_cli_options_t *);
static int asn1c_resolve_skeletons(asn1c_cli_options_t *, const char *);
static int asn1c_resolve_runtime(asn1c_cli_options_t *);
static int asn1c_runtime_layout_available(const char *);
static int asn1c_join_path(char *, size_t, const char *, const char *);
static int asn1c_parse_inputs(int, char **, enum asn1p_flags, asn1p_t **,
                              int *);
static void asn1c_cli_options_destroy(asn1c_cli_options_t *);
static int asn1c_import_and_fix_tree(asn1c_cli_options_t *, asn1p_t *, int *);
static int asn1c_run_pipeline(asn1c_cli_options_t *, int, int, char **,
                              asn1p_t *);

/*
 * Exit status (see asn1c(1), EXIT STATUS):
 *   0            Success. No FATAL diagnostic was reported.
 *   EX_USAGE     (64) Command line usage error.
 *   EX_DATAERR   (65) ASN.1 input error: a syntax error, or a FATAL
 *                     diagnostic during semantic processing.
 *   EX_NOINPUT   (66) An input file cannot be opened.
 *   EX_SOFTWARE  (70) Printing or code generation failed, or reported a
 *                     FATAL diagnostic. The output is incomplete.
 *   EX_OSFILE    (72) Skeleton files not found (with -Werror).
 *
 * A FATAL diagnostic always gives a non-zero exit status, also when the
 * library that reports it continues its work.
 */
static int fixer_fatal_count; /* FATAL diagnostics via fixer_error_logger */
static void fixer_error_logger(int _severity, const char *fmt, ...);

/*
 * Initialize C's historical defaults and the separate Rust codec selection.
 * Parameters: options is the command-line state to initialize. Returns no
 * value and raises no exception. Original source: asn1c CLI defaults.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: extended to isolate Rust from C defaults. Example: called once by
 * main() before parsing options.
 */
static void
asn1c_cli_options_init(asn1c_cli_options_t *options) {
    options->parser_flags = A1P_NOFLAGS;
    options->fixer_flags = A1F_NOFLAGS;
    options->compiler_flags =
        A1C_NO_C99 | A1C_GEN_BER | A1C_GEN_XER | A1C_GEN_OER | A1C_GEN_UPER
        | A1C_GEN_APER | A1C_GEN_PRINT | A1C_GEN_RFILL | A1C_GEN_EXAMPLE
        | A1C_GEN_JER | A1C_GEN_CBOR | A1C_GEN_CER;
    options->printer_flags = APF_NOFLAGS;
    options->print_out = 0;
    options->fix_n_print = 0;
    options->warnings_as_errors = 0;
    options->rust_target = 0;
    options->skeletons_explicit = 0;
    options->skeletons_owned = 0;
    options->complex_threshold = 4;
    options->rust_codec_flags = A1C_GEN_UPER | A1C_GEN_CER;
    options->rust_incompatible_option = NULL;
    options->skeletons_dir = NULL;
    options->destdir = NULL;
    options->debug_type_names = NULL;
    options->debug_type_names_count = 0;
    options->rust_runtime_dir[0] = '\0';
}

/*
 * Identify short options whose next character or argv item is their operand.
 * Parameters: option is one short-option letter. Returns nonzero for D,d,f,g,
 * n,p,S,W and zero otherwise. Original source: asn1c getopt option string.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: added so target extraction preserves option operands. Example:
 * `short_option_takes_argument('D')` is true.
 */
static int
asn1c_short_option_takes_argument(char option) {
    return strchr("DdfgnpSW", option) != NULL;
}

/*
 * Remove exact --rust options while preserving getopt's short-option operands.
 * Parameters: argc is the argument count; argv is compacted in place; selected
 * receives the target flag. Returns zero or -1; does not throw. Original source:
 * new asn1c CLI target selection. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: models clustered short options and `--`.
 * Example: `asn1c --rust schema.asn1` selects the Rust target.
 */
static int
asn1c_extract_rust_switch(int *argc, char **argv, int *selected) {
    int read_index, write_index = 1, end_options = 0;
    int found = 0;

    for(read_index = 1; read_index < *argc; read_index++) {
        const char *argument = argv[read_index];
        if(!end_options && !strcmp(argument, "--")) {
            end_options = 1;
            argv[write_index++] = argv[read_index];
            continue;
        }
        if(!end_options && !strcmp(argument, "--rust")) {
            if(found) {
                fprintf(stderr, "asn1c: --rust may be specified only once\n");
                return -1;
            }
            found = 1;
            *selected = 1;
            continue;
        }
        argv[write_index++] = argv[read_index];
        if(!end_options && argument[0] == '-' && argument[1]
           && argument[1] != '-') {
            const char *option = argument + 1;
            for(; *option; option++) {
                if(asn1c_short_option_takes_argument(*option)) {
                    if(!option[1] && read_index + 1 < *argc)
                        argv[write_index++] = argv[++read_index];
                    break;
                }
            }
        }
    }
    argv[write_index] = NULL;
    *argc = write_index;
    return 0;
}

/*
 * Convert one -gen-* or -no-gen-* argument to its compiler flag.
 * Parameters: name is the suffix without its CLI prefix. Returns the flag or
 * zero for an unknown name. Original source: asn1c encoding option table.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: added target-independent codec bookkeeping. Example:
 * `asn1c_codec_flag("UPER")` returns A1C_GEN_UPER.
 */
static uint64_t
asn1c_codec_flag(const char *name) {
    if(!strcmp(name, "BER")) return A1C_GEN_BER;
    if(!strcmp(name, "XER")) return A1C_GEN_XER;
    if(!strcmp(name, "JER")) return A1C_GEN_JER;
    if(!strcmp(name, "CBOR")) return A1C_GEN_CBOR;
    if(!strcmp(name, "CER")) return A1C_GEN_CER;
    if(!strcmp(name, "OER")) return A1C_GEN_OER;
    if(!strcmp(name, "UPER")) return A1C_GEN_UPER;
    if(!strcmp(name, "APER")) return A1C_GEN_APER;
    if(!strcmp(name, "print")) return A1C_GEN_PRINT;
    if(!strcmp(name, "random-fill")) return A1C_GEN_RFILL;
    if(!strcmp(name, "example")) return A1C_GEN_EXAMPLE;
    if(!strcmp(name, "autotools")) return A1C_GEN_AUTOTOOLS_EXAMPLE;
    return 0;
}

/*
 * Parse the full option vector after stripping the target-only long switch.
 * Parameters: argc is updated for the stripped switch; argv is the command
 * vector; options receives all parsed settings. Returns zero or -1; no
 * exception is raised. Original source: asn1c main option loop. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: split from
 * main to keep each callable unit bounded. Example: `parse_options(&argc, argv)`.
 */
static int
asn1c_parse_options(int *argc, char **argv, asn1c_cli_options_t *options) {
    int ch;
    if(asn1c_extract_rust_switch(argc, argv, &options->rust_target)) return -1;
    while((ch = getopt(*argc, argv, "D:d:EFf:g:hn:LPp:RS:vW:X")) != -1) {
        if(asn1c_handle_option(ch, optarg, options, argv[0])) return -1;
    }
    return 0;
}

/*
 * Dispatch one parsed option to its bounded option-family handler.
 * Parameters: ch and optarg identify the option; options stores results; av0
 * is the program name for usage. Returns zero or -1. Original source: asn1c
 * option switch. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: split for target-aware validation. Example:
 * `handle_option('g', "en-UPER", &options, argv[0])`.
 */
static int
asn1c_handle_option(int ch, const char *optarg, asn1c_cli_options_t *options,
                    const char *av0) {
    switch(ch) {
    case 'f': return asn1c_handle_f_option(optarg, options);
    case 'g':
    case 'n': return asn1c_handle_codec_option(ch, optarg, options);
    case 'p':
    case 'P': return asn1c_handle_print_option(ch, optarg, options);
    case 'W': return asn1c_handle_warning_option(optarg, options);
    default: return asn1c_handle_basic_option(ch, optarg, options, av0);
    }
}

/*
 * Apply an explicit codec toggle to C and Rust-specific option state.
 * Parameters: ch is 'g' or 'n'; optarg is the existing CLI spelling; options
 * stores updated masks. Returns zero or -1. Original source: asn1c codec
 * options. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: isolates Rust selections and maintains CER's BER
 * dependency. Example: `handle_codec_option('g', "en-CER", &options)`.
 */
static int
asn1c_handle_codec_option(int ch, const char *optarg,
                          asn1c_cli_options_t *options) {
    const char *prefix = ch == 'g' ? "en-" : "o-gen-";
    size_t prefix_length = strlen(prefix);
    uint64_t flag;
    if(strncmp(optarg, prefix, prefix_length)) goto invalid;
    if(ch == 'g' && !strcmp(optarg + prefix_length, "autotools"))
        goto invalid;
    flag = asn1c_codec_flag(optarg + prefix_length);
    if(!flag) goto invalid;
    if(ch == 'g') {
        options->compiler_flags |= (enum asn1c_flags)flag;
        if(flag == A1C_GEN_CER)
            options->compiler_flags |= A1C_GEN_BER;
        options->rust_codec_flags |= flag;
    } else {
        options->compiler_flags &= ~(enum asn1c_flags)flag;
        if(flag == A1C_GEN_BER)
            options->compiler_flags &= ~(enum asn1c_flags)A1C_GEN_CER;
        options->rust_codec_flags &= ~flag;
    }
    return 0;
invalid:
    fprintf(stderr, "-%c%s: Invalid argument\n", ch, optarg);
    return -1;
}

/*
 * Remember the first option that has no Rust-target meaning.
 * Parameters: options owns the diagnostic state; spelling identifies the
 * incompatible switch. Returns no value and raises no exception. Original
 * source: new asn1c target validation. Version/date: 0.1.0, 2026-10-11.
 * Responsible party: asn1c maintainers. History: added for pre-parse errors.
 * Example: `mark_rust_incompatible(&options, "-R")`.
 */
static void
asn1c_mark_rust_incompatible(asn1c_cli_options_t *options,
                             const char *spelling) {
    if(!options->rust_incompatible_option)
        options->rust_incompatible_option = spelling;
}

/*
 * Apply non-codec options that use the basic asn1c CLI switches.
 * Parameters: ch and optarg identify the option; options receives its value;
 * av0 is the executable name for usage. Returns zero or -1. Original source:
 * asn1c main option switch. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: extracted for smaller, target-aware parsing.
 * Example: `handle_basic_option('D', "generated", &options, argv[0])`.
 */
static int
asn1c_handle_basic_option(int ch, const char *optarg,
                          asn1c_cli_options_t *options, const char *av0) {
    switch(ch) {
    case 'D': return asn1c_handle_destination_option(optarg, options);
    case 'd': return asn1c_handle_debug_option(optarg, options);
    case 'E':
    case 'F':
    case 'X': return asn1c_handle_tree_mode_option(ch, options);
    case 'h':
        usage(av0);
    case 'R':
        options->compiler_flags |= A1C_OMIT_SUPPORT_CODE;
        asn1c_mark_rust_incompatible(options, "-R");
        return 0;
    case 'S': return asn1c_handle_skeleton_option(optarg, options);
    case 'v':
        fprintf(stderr, "ASN.1 Compiler, " VERSION " (" PACKAGE_BUGREPORT ")\n"
                        COPYRIGHT);
        exit(0);
    default:
        usage(av0);
    }
    return -1;
}

/*
 * Store an owned copy of the explicitly selected support directory.
 * Parameters: value is the -S operand; options owns the copied path.
 * Returns zero or -1. Original source: historical asn1c -S option.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: records explicit-path provenance for Rust runtime lookup. Example:
 * `-S /opt/share/asn1c` selects that support directory.
 */
static int
asn1c_handle_skeleton_option(const char *value,
                             asn1c_cli_options_t *options) {
    size_t length;
    char *directory;
    if(!value) return -1;
    length = strlen(value);
    if(length == SIZE_MAX) return -1;
    directory = malloc(length + 1);
    if(!directory) return -1;
    memcpy(directory, value, length + 1);
    if(options->skeletons_owned) free(options->skeletons_dir);
    options->skeletons_dir = directory;
    options->skeletons_owned = 1;
    options->skeletons_explicit = 1;
    return 0;
}

/*
 * Store the destination path using the C CLI's trailing-slash convention.
 * Parameters: value is the -D argument; options owns the allocated path.
 * Returns zero or -1; allocation errors are reported to the caller. Original
 * source: asn1c -D option. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: extracted for target handling. Example:
 * `-D generated` stores `generated/`.
 */
static int
asn1c_handle_destination_option(const char *value,
                                asn1c_cli_options_t *options) {
    size_t length;
    char *destination;
    if(!value) return -1;
    length = strlen(value);
    if(length == 0) {
        free(options->destdir);
        options->destdir = NULL;
        return 0;
    }
    if(length > SIZE_MAX - 2) return -1;
    destination = malloc(length + 2);
    if(!destination) return -1;
    memcpy(destination, value, length + 1);
    if(destination[length - 1] != '/') {
        destination[length] = '/';
        destination[length + 1] = '\0';
    }
    free(options->destdir);
    options->destdir = destination;
    return 0;
}

/*
 * Parse a debug option and retain target incompatibility when it is C-only.
 * Parameters: value is the -d argument; options stores debug state. Returns
 * zero or -1. Original source: asn1c -d option. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: extracted from
 * main. Example: `-debug-type-naming=Thing`.
 */
static int
asn1c_handle_debug_option(const char *value, asn1c_cli_options_t *options) {
    if(strncmp(value, "ebug-type-naming=", 17) == 0) {
        size_t count = options->debug_type_names_count;
        char **grown;
        size_t length = strlen(value + 17);
        char *name;
        if(count > SIZE_MAX / sizeof(*grown) - 2 || length == SIZE_MAX)
            return -1;
        name = malloc(length + 1);
        if(!name) return -1;
        memcpy(name, value + 17, length + 1);
        grown = realloc(options->debug_type_names,
                        (count + 2) * sizeof(*grown));
        if(!grown) {
            free(name);
            return -1;
        }
        options->debug_type_names = grown;
        options->debug_type_names[count] = name;
        options->debug_type_names[count + 1] = NULL;
        options->debug_type_names_count++;
        asn1c_mark_rust_incompatible(options, "-d debug-type-naming");
        return 0;
    }
    if(strcmp(value, "ebug-output-origin-lines") == 0) {
        options->compiler_flags |= A1C_DEBUG_OUTPUT_ORIGIN_LINES;
        asn1c_mark_rust_incompatible(options, "-d debug-output-origin-lines");
        return 0;
    }
    fprintf(stderr, "-d%s: Invalid argument\n", value);
    return -1;
}

/*
 * Record parse-tree display modes, which cannot be combined with --rust output.
 * Parameters: ch is E, F, or X; options stores the requested mode. Returns
 * zero. Original source: asn1c -E/-F/-X switch. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: extracted from
 * main. Example: `-X` requests parse, fix, and XML-DTD display.
 */
static int
asn1c_handle_tree_mode_option(int ch, asn1c_cli_options_t *options) {
    if(ch == 'E') {
        options->print_out = 1;
        asn1c_mark_rust_incompatible(options, "-E");
    } else if(ch == 'F') {
        options->fix_n_print = 1;
        asn1c_mark_rust_incompatible(options, "-F");
    } else {
        options->print_out = 1;
        options->fix_n_print = 1;
        options->printer_flags |= APF_PRINT_XML_DTD;
        asn1c_mark_rust_incompatible(options, "-X");
    }
    return 0;
}

/*
 * Handle one C compiler -f option that is represented by a direct flag change.
 * Parameters: name is the option suffix; options owns the compiler/fixer
 * settings. Returns 1 if handled, 0 if unknown. Original source: asn1c -f
 * switch. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: table-free split of legacy option parsing. Example:
 * `handle_simple_f_option("wide-types", &options)`.
 */
static int
asn1c_handle_simple_f_option(const char *name, asn1c_cli_options_t *options) {
    if(!strcmp(name, "all-defs-global"))
        options->compiler_flags |= A1C_ALL_DEFS_GLOBAL;
    else if(!strcmp(name, "bless-SIZE"))
        options->fixer_flags |= A1F_EXTENDED_SizeConstraint;
    else if(!strcmp(name, "compound-names")) {
        options->compiler_flags |= A1C_COMPOUND_NAMES;
        options->fixer_flags |= A1F_COMPOUND_NAMES;
    } else if(!strcmp(name, "indirect-choice"))
        options->compiler_flags |= A1C_INDIRECT_CHOICE;
    else if(!strcmp(name, "prefer-import-source"))
        options->fixer_flags |= A1F_PREFER_IMPORT_SOURCE;
    else if(!strcmp(name, "wide-types"))
        options->compiler_flags |= A1C_USE_WIDE_TYPES;
    else if(!strcmp(name, "line-refs"))
        options->compiler_flags |= A1C_LINE_REFS;
    else if(!strcmp(name, "no-constraints"))
        options->compiler_flags |= A1C_NO_CONSTRAINTS;
    else if(!strcmp(name, "no-include-deps"))
        options->compiler_flags |= A1C_NO_INCLUDE_DEPS;
    else if(!strcmp(name, "includes-quoted"))
        options->compiler_flags |= A1C_INCLUDES_QUOTED;
    else if(!strcmp(name, "unnamed-unions"))
        options->compiler_flags |= A1C_UNNAMED_UNIONS;
    else if(!strcmp(name, "link-skeletons"))
        options->compiler_flags |= A1C_LINK_SKELETONS;
    else if(!strcmp(name, "gen-only-pdu-deps"))
        options->compiler_flags |= A1C_GEN_ONLY_PDU_DEPS;
    else if(!strcmp(name, "list-deps"))
        options->compiler_flags |= A1C_LIST_DEPS;
    else
        return 0;
    asn1c_mark_rust_incompatible(options, "-f C-only option");
    return 1;
}

/*
 * Apply an option in the existing -f family or reject it before parsing.
 * Parameters: arg is the option suffix; options receives all related state.
 * Returns zero or -1. Original source: asn1c -f option switch. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: separated
 * codec-independent C options for --rust validation. Example:
 * `handle_f_option("complex-threshold=8", &options)`.
 */
static int
asn1c_handle_f_option(const char *arg, asn1c_cli_options_t *options) {
    int handled;
    if(!strncmp(arg, "complex-threshold=", 18))
        return asn1c_parse_complex_threshold(arg + 18, options);
    if(!strncmp(arg, "long-size=", 10))
        return asn1c_parse_long_size(arg + 10, options);
    if(!strncmp(arg, "integer-native-type=", 20))
        return asn1c_parse_integer_native_type(arg + 20, options);
    if(!strncmp(arg, "known-extern-type=", 18)) {
        int ret = asn1f_make_known_external_type(arg + 18);
        if(ret != 0 && errno != EEXIST) return -1;
        asn1c_mark_rust_incompatible(options, "-fknown-extern-type");
        return 0;
    }
    if(!strncmp(arg, "prefix=", 7)) {
        asn1c_prefix_set(arg + 7);
        asn1c_mark_rust_incompatible(options, "-fprefix");
        return 0;
    }
    if(!strcmp(arg, "native-types")) {
        fprintf(stderr, "-f%s: Deprecated option\n", arg);
        options->compiler_flags &= ~A1C_USE_WIDE_TYPES;
        asn1c_mark_rust_incompatible(options, "-fnative-types");
        return 0;
    }
    if(!strcmp(arg, "skeletons-copy")) {
        fprintf(stderr, "-f%s: Deprecated option\n", arg);
        options->compiler_flags &= ~A1C_LINK_SKELETONS;
        asn1c_mark_rust_incompatible(options, "-fskeletons-copy");
        return 0;
    }
    handled = asn1c_handle_simple_f_option(arg, options);
    if(handled) return 0;
    fprintf(stderr, "-f%s: Invalid argument\n", arg);
    return -1;
}

/*
 * Handle a -P or -p C printer/debug option.
 * Parameters: ch selects the option family; optarg is its suffix; options
 * receives the selected behavior. Returns zero or -1. Original source:
 * asn1c printer option switch. Version/date: 0.1.0, 2026-10-11. Responsible
 * party: asn1c maintainers. History: extracted to validate Rust target modes.
 * Example: `handle_print_option('p', "rint-lines", &options)`.
 */
static int
asn1c_handle_print_option(int ch, const char *optarg,
                          asn1c_cli_options_t *options) {
    if(ch == 'P') {
        options->compiler_flags |= A1C_PRINT_COMPILED;
        options->compiler_flags &= ~A1C_NO_C99;
        asn1c_mark_rust_incompatible(options, "-P");
        return 0;
    }
    if(!strncmp(optarg, "du=", 3)) {
        const char *name = optarg + 3;
        if(!strcmp(name, "all"))
            options->compiler_flags |= A1C_PDU_ALL;
        else if(!strcmp(name, "auto"))
            options->compiler_flags |= A1C_PDU_AUTO;
        else if(name[0] >= 'A' && name[0] <= 'Z') {
            asn1c__add_pdu_type(name);
            options->compiler_flags |= A1C_PDU_TYPE;
        } else {
            fprintf(stderr, "-pdu=%s: expected -pdu={all|auto|Type}\n", name);
            return -1;
        }
        asn1c_mark_rust_incompatible(options, "-pdu");
        return 0;
    }
    if(!strcmp(optarg, "rint-class-matrix"))
        options->printer_flags |= APF_PRINT_CLASS_MATRIX;
    else if(!strcmp(optarg, "rint-constraints"))
        options->printer_flags |= APF_PRINT_CONSTRAINTS;
    else if(!strcmp(optarg, "rint-lines"))
        options->printer_flags |= APF_LINE_COMMENTS;
    else {
        fprintf(stderr, "-p%s: Invalid argument\n", optarg);
        return -1;
    }
    asn1c_mark_rust_incompatible(options, "-p printer option");
    return 0;
}

/*
 * Parse warning and diagnostic options that do not generate C layout.
 * Parameters: optarg is the warning suffix; options receives the state.
 * Returns zero or -1. Original source: asn1c -W option switch. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: separated
 * compiler-only debugging from input diagnostics. Example: `-Werror`.
 */
static int
asn1c_handle_warning_option(const char *optarg,
                            asn1c_cli_options_t *options) {
    if(!strcmp(optarg, "error")) {
        options->warnings_as_errors = 1;
    } else if(!strcmp(optarg, "debug-lexer")) {
        options->parser_flags |= A1P_DEBUG_LEXER;
    } else if(!strcmp(optarg, "debug-parser")) {
        options->parser_flags |= A1P_DEBUG_PARSER;
    } else if(!strcmp(optarg, "debug-fixer")) {
        options->fixer_flags |= A1F_DEBUG;
    } else if(!strcmp(optarg, "debug-compiler")) {
        options->compiler_flags |= A1C_DEBUG;
        asn1c_mark_rust_incompatible(options, "-Wdebug-compiler");
    } else {
        fprintf(stderr, "-W%s: Invalid argument\n", optarg);
        return -1;
    }
    return 0;
}

/*
 * Parse and validate a requested C long width.
 * Parameters: value is the `-flong-size` suffix; options receives the global
 * C target setting. Returns zero or -1. Original source: asn1c -f parser.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: extracted from main. Example: `-flong-size=64`.
 */
static int
asn1c_parse_long_size(const char *value, asn1c_cli_options_t *options) {
    if(!strcmp(value, "32"))
        asn1c_target_long_size = ASN_TARGET_LONG_32;
    else if(!strcmp(value, "64"))
        asn1c_target_long_size = ASN_TARGET_LONG_64;
    else {
        fprintf(stderr, "-flong-size expects one of: 32, 64\n");
        return -1;
    }
    asn1c_mark_rust_incompatible(options, "-flong-size");
    return 0;
}

/*
 * Parse the C constrained-INTEGER native storage policy.
 * Parameters: value is the option suffix; options records Rust incompatibility.
 * Returns zero or -1. Original source: asn1c -finteger-native-type parser.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: extracted from main. Example: `-finteger-native-type=uint64`.
 */
static int
asn1c_parse_integer_native_type(const char *value,
                               asn1c_cli_options_t *options) {
    if(!strcmp(value, "auto") || !strcmp(value, "long")) {
        if(!strcmp(value, "long"))
            fprintf(stderr, "-finteger-native-type=long is deprecated\n");
        asn1c_integer_native_type = AINT_NATIVE_AUTO;
    } else if(!strcmp(value, "int32")) {
        asn1c_integer_native_type = AINT_NATIVE_INT32;
    } else if(!strcmp(value, "uint32")) {
        asn1c_integer_native_type = AINT_NATIVE_UINT32;
    } else if(!strcmp(value, "int64")) {
        asn1c_integer_native_type = AINT_NATIVE_INT64;
    } else if(!strcmp(value, "uint64")) {
        asn1c_integer_native_type = AINT_NATIVE_UINT64;
    } else {
        fprintf(stderr,
                "-finteger-native-type expects one of: "
                "int32, uint32, int64, uint64, auto\n");
        return -1;
    }
    asn1c_mark_rust_incompatible(options, "-finteger-native-type");
    return 0;
}

/*
 * Parse the positive C complex-structure indirection threshold.
 * Parameters: value is the decimal suffix; options receives the threshold.
 * Returns zero or -1. Original source: asn1c -f parser. Version/date: 0.1.0,
 * 2026-10-11. Responsible party: asn1c maintainers. History: extracted from
 * main. Example: `-fcomplex-threshold=8`.
 */
static int
asn1c_parse_complex_threshold(const char *value,
                              asn1c_cli_options_t *options) {
    long parsed;
    if(!is_integer(value, &parsed) || parsed <= 0 || parsed > 500) {
        fprintf(stderr, "-fcomplex-threshold: bad format or value too large\n");
        return -1;
    }
    options->complex_threshold = (int)parsed;
    asn1c_mark_rust_incompatible(options, "-fcomplex-threshold");
    return 0;
}

/*
 * Validate target-specific constraints before input files are parsed.
 * Parameters: options is the complete option state. Returns zero or -1; no
 * exception is raised. Original source: asn1c option validation. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: moved
 * target checks ahead of parsing/output. Example: `validate_options(&options)`.
 */
static int
asn1c_validate_options(const asn1c_cli_options_t *options) {
    const uint64_t rust_supported =
        (uint64_t)A1C_GEN_UPER | (uint64_t)A1C_GEN_BER
        | (uint64_t)A1C_GEN_CER | (uint64_t)A1C_GEN_APER
        | (uint64_t)A1C_GEN_OER | (uint64_t)A1C_GEN_JER | (uint64_t)A1C_GEN_CBOR
        | (uint64_t)A1C_GEN_XER;
    if(options->print_out) {
        if((options->printer_flags & APF_PRINT_CONSTRAINTS)
           && !options->fix_n_print) {
            fprintf(stderr,
                    "Error: -print-constraints argument requires -E -F\n");
            return -1;
        }
    } else {
        if(options->fix_n_print) {
            fprintf(stderr, "Error: -F requires -E\n");
            return -1;
        }
        if(options->printer_flags) {
            fprintf(stderr, "Error: -print-... arguments require -E\n");
            return -1;
        }
    }
    if(options->rust_target) {
        if(options->rust_incompatible_option) {
            fprintf(stderr, "Error: %s is incompatible with --rust\n",
                    options->rust_incompatible_option);
            return -1;
        }
        if(!options->rust_codec_flags
           || (options->rust_codec_flags & ~rust_supported)) {
            fprintf(stderr,
                    "Error: --rust supports UPER, APER, OER, BER, CER, JER, CBOR, and XER; select at least "
                    "one supported codec and no other codec\n");
            return -1;
        }
        return 0;
    }
    if((options->compiler_flags & A1C_NO_CONSTRAINTS)
       && (options->compiler_flags
           & (A1C_GEN_OER | A1C_GEN_UPER | A1C_GEN_APER))) {
        fprintf(stderr,
                "Error: -fno-constraints is incompatible with -gen-OER, "
                "-gen-UPER, or -gen-APER\n");
        return -1;
    }
    return 0;
}

/*
 * Join two filesystem path components with bounded output.
 * Parameters: output is the destination buffer; capacity is its size; left and
 * right are path components. Returns zero or -1. Original source: new asn1c
 * CLI path handling. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: added for portable runtime asset resolution.
 * Example: `join_path(buf, sizeof(buf), "share/asn1c", "runtime")`.
 */
static int
asn1c_join_path(char *output, size_t capacity, const char *left,
                const char *right) {
    size_t left_length;
    int written;
    if(!output || !capacity || !left || !right) return -1;
    left_length = strlen(left);
    written = snprintf(output, capacity, "%s%s%s", left,
                       left_length && left[left_length - 1] == '/' ? "" : "/",
                       right);
    return written < 0 || (size_t)written >= capacity ? -1 : 0;
}

/*
 * Select the source/install support directory using the C CLI's fallback.
 * Parameters: options stores the selected path; argv0 locates a source-tree
 * fallback. Returns zero or EX_OSFILE. Original source: asn1c skeleton search.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: extracted before --rust asset resolution. Example: `-S skeletons`.
 */
static int
asn1c_resolve_skeletons(asn1c_cli_options_t *options, const char *argv0) {
    struct stat status;
    if(!options->skeletons_dir) {
        if(stat(DATADIR, &status) == 0 && S_ISDIR(status.st_mode)) {
            options->skeletons_dir = DATADIR;
        } else {
            const char *directory = a1c_dirname(argv0);
            size_t length = strlen(directory);
            if(length > SIZE_MAX - sizeof("/../skeletons")) return EX_OSFILE;
            options->skeletons_dir = malloc(length + sizeof("/../skeletons"));
            if(!options->skeletons_dir) return EX_OSFILE;
            snprintf(options->skeletons_dir,
                     length + sizeof("/../skeletons"),
                     "%s/../skeletons", directory);
            options->skeletons_owned = 1;
        }
    }
    if(stat(options->skeletons_dir, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, "WARNING: skeletons directory is unavailable: %s\n",
                options->skeletons_dir);
        if(options->warnings_as_errors) return EX_OSFILE;
    }
    return 0;
}

/*
 * Verify every required runtime asset before parsing or creating output.
 * Parameters: path is a candidate crate directory. Returns true only when its
 * fixed runtime file set is present and regular. Original source: new asn1c
 * Rust CLI. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: added for early Rust target validation. Example:
 * `runtime_layout_available("share/asn1c/rust/asn1c-runtime")`.
 */
static int
asn1c_runtime_layout_available(const char *path) {
    static const char *const files[] = {
        "Cargo.toml", "README.md", "LICENSE", "src/lib.rs"
    };
    struct stat status;
    char asset[PATH_MAX];
    size_t i;
    if(lstat(path, &status) != 0 || !S_ISDIR(status.st_mode)) return 0;
    if(asn1c_join_path(asset, sizeof(asset), path, "src")
       || lstat(asset, &status) != 0 || !S_ISDIR(status.st_mode)) return 0;
    for(i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if(asn1c_join_path(asset, sizeof(asset), path, files[i])
           || lstat(asset, &status) != 0 || !S_ISREG(status.st_mode)) return 0;
    }
    return 1;
}

/*
 * Resolve the runtime beside the selected skeletons or in installed package data.
 * Parameters: options contains the skeleton path and writes the runtime path.
 * Returns zero or EX_OSFILE. Original source: new asn1c Rust CLI. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: supports
 * source and installed layouts. Example: `--rust -S /prefix/share/asn1c`.
 */
static int
asn1c_resolve_runtime(asn1c_cli_options_t *options) {
    char candidate[PATH_MAX];
    int resolved = 0;
    if(!options->skeletons_dir || !*options->skeletons_dir) {
        fprintf(stderr, "asn1c: Rust runtime lookup requires a nonempty -S path\n");
        return EX_OSFILE;
    }
    if(!asn1c_join_path(candidate, sizeof(candidate), options->skeletons_dir,
                        "rust/asn1c-runtime")
       && asn1c_runtime_layout_available(candidate)) resolved = 1;
    if(!resolved
       && !asn1c_join_path(candidate, sizeof(candidate), options->skeletons_dir,
                           "../rust/asn1c-runtime")
       && asn1c_runtime_layout_available(candidate)) resolved = 1;
    if(!resolved && !options->skeletons_explicit
       && !asn1c_join_path(candidate, sizeof(candidate), DATADIR,
                           "rust/asn1c-runtime")
       && asn1c_runtime_layout_available(candidate)) resolved = 1;
    if(!resolved) {
        fprintf(stderr,
                "asn1c: cannot find the Rust runtime beside skeletons or in "
                "installed package data\n");
        return EX_OSFILE;
    }
    strcpy(options->rust_runtime_dir, candidate);
    return 0;
}

/*
 * Parse all positional ASN.1 files and combine their modules into one tree.
 * Parameters: count and inputs describe the files; parser_flags configures the
 * parser; tree receives the result; exit_code receives a sysexits status.
 * Returns zero or -1. Original source: asn1c main input loop. Version/date:
 * 0.1.0, 2026-10-11. Responsible party: asn1c maintainers. History: extracted
 * to reduce main() complexity. Example: `parse_inputs(n, files, flags, &tree)`.
 */
static int
asn1c_parse_inputs(int count, char **inputs, enum asn1p_flags parser_flags,
                   asn1p_t **tree, int *exit_code) {
    int index;
    for(index = 0; index < count; index++) {
        asn1p_t *new_tree;
        errno = 0;
        new_tree = asn1p_parse_file(inputs[index], parser_flags);
        if(!new_tree) {
            int parse_errno = errno;
            fprintf(stderr, "Cannot parse \"%s\"\n", inputs[index]);
            *exit_code = (parse_errno == EINVAL || parse_errno == 0)
                             ? EX_DATAERR : EX_NOINPUT;
            return -1;
        }
        if(*tree) {
            asn1p_module_t *module;
            while((module = TQ_REMOVE(&(new_tree->modules), mod_next)))
                TQ_ADD(&((*tree)->modules), module, mod_next);
            asn1p_delete(new_tree);
        } else {
            *tree = new_tree;
        }
    }
    return 0;
}

/*
 * Release allocations owned by one parsed CLI invocation.
 * Parameters: options holds the state initialized by asn1c_cli_options_init.
 * Returns no value and raises no exception. Original source: new CLI ownership
 * cleanup. Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c
 * maintainers. History: added while splitting main(). Example:
 * `asn1c_cli_options_destroy(&options)` before process exit.
 */
static void
asn1c_cli_options_destroy(asn1c_cli_options_t *options) {
    size_t index;
    for(index = 0; index < options->debug_type_names_count; index++)
        free(options->debug_type_names[index]);
    free(options->debug_type_names);
    free(options->destdir);
    if(options->skeletons_owned) free(options->skeletons_dir);
}

/*
 * Import standard modules, bind module owners, and run the ASN.1 fixer.
 * Parameters: options contains fixer settings; asn is the parsed tree; result
 * receives EX_DATAERR for a nonfatal FATAL diagnostic allowed during -E -F.
 * Returns zero to continue or EX_DATAERR to stop. Original source: former main
 * tree-processing block. Version/date: 0.1.0, 2026-10-11. Responsible party:
 * asn1c maintainers. History: extracted to bound dispatch complexity. Example:
 * `asn1c_import_and_fix_tree(&options, tree, &result)`. Rust automatically
 * enables compound names in the fixer so distinct ASN.1 modules may define
 * the same symbol; generated Rust module paths preserve each assignment's
 * ownership. Module back-pointers are rebound after per-file trees merge.
 * The C-only `-fcompound-names` option remains incompatible with `--rust`,
 * and C invocations retain their selected fixer flags.
 */
static int
asn1c_import_and_fix_tree(asn1c_cli_options_t *options, asn1p_t *asn,
                          int *result) {
    asn1p_module_t *module;
    enum asn1f_flags fixer_flags = options->fixer_flags; /* Fixer policy state variable. */
    int fix_status;
    if(importStandardModules(asn, options->skeletons_dir)) {
        if(options->warnings_as_errors) return EX_DATAERR;
    } else {
        asn1f_use_standard_namespaces(asn);
    }
    /* Per-file parse trees were merged; restore owners before fixer lookups. */
    TQ_FOR(module, &asn->modules, mod_next) module->asn1p = asn;
    /* Rust module paths disambiguate names, so its fixer may accept duplicates. */
    if(options->rust_target) fixer_flags |= A1F_COMPOUND_NAMES;
    fix_status = asn1f_process(asn, fixer_flags, fixer_error_logger);
    if(fix_status == -1 || (fix_status == 1 && options->warnings_as_errors))
        return EX_DATAERR;
    if(fixer_fatal_count) {
        if(!(options->print_out && options->fix_n_print)) return EX_DATAERR;
        *result = EX_DATAERR;
    } else {
        *result = 0;
    }
    return 0;
}

/*
 * Run standard-module import, tree fixing, diagnostic handling, and codegen.
 * Parameters: options contains validated target settings; argc, optc, and argv
 * preserve the command-line context expected by the C backend; asn is the
 * parsed tree. Returns a sysexits status. Original source: former main pipeline.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: dispatches through the target-aware compiler API. Example:
 * `asn1c_run_pipeline(&options, argc, optind, argv, tree)`.
 */
static int
asn1c_run_pipeline(asn1c_cli_options_t *options, int argc, int optc,
                   char **argv, asn1p_t *asn) {
    int result;
    asn1c_target_options_t target_options;

    if(options->print_out && !options->fix_n_print)
        return asn1print(asn, options->printer_flags) ? EX_SOFTWARE : 0;
    if(asn1c_import_and_fix_tree(options, asn, &result)) return EX_DATAERR;
    if(options->print_out && options->fix_n_print) {
        if(asn1print(asn, options->printer_flags)) return EX_SOFTWARE;
        return result;
    }
    if(options->debug_type_names) {
        asn1c_debug_type_naming(asn, options->compiler_flags,
                                options->debug_type_names);
        return result;
    }
    target_options.target = options->rust_target ? ASN1C_TARGET_RUST
                                                 : ASN1C_TARGET_C;
    target_options.rust_runtime_dir = options->rust_target
                                          ? options->rust_runtime_dir : NULL;
    target_options.rust_codecs = options->rust_target
                                     ? options->rust_codec_flags : 0;
    if(asn1_compile_with_target(
           asn, options->skeletons_dir,
           options->destdir ? options->destdir : "", options->compiler_flags,
           argc, optc, argv, options->complex_threshold, &target_options))
        result = EX_SOFTWARE;
    if(fixer_fatal_count) result = EX_SOFTWARE;
    return result;
}


/*
 * Parse options, validate target compatibility, parse input, and dispatch.
 * Parameters: ac is the process argument count; av is its argument vector.
 * Returns zero or a sysexits status. Original source: historical asn1c main.
 * Version/date: 0.1.0, 2026-10-11. Responsible party: asn1c maintainers.
 * History: split into bounded option, input, and target-pipeline helpers.
 * Example: `asn1c --rust schema.asn1` generates a Rust project.
 */
int
main(int ac, char **av) {
    asn1c_cli_options_t options;
    asn1p_t *asn = NULL;
    int input_argc;
    int exit_code = 0;

    asn1c_cli_options_init(&options);
    if(asn1c_parse_options(&ac, av, &options)) {
        exit_code = EX_USAGE;
        goto cleanup;
    }
    if(asn1c_validate_options(&options)) {
        exit_code = EX_USAGE;
        goto cleanup;
    }
    input_argc = ac - optind;
    if(input_argc <= 0) {
        const char *program = a1c_basename(av[0], NULL);
        fprintf(stderr,
                "%s: No input files specified. Try '%s -h' for more "
                "information\n", program, program);
        exit_code = EX_USAGE;
        goto cleanup;
    }
    exit_code = asn1c_resolve_skeletons(&options, av[0]);
    if(exit_code) goto cleanup;
    if(options.rust_target) {
        exit_code = asn1c_resolve_runtime(&options);
        if(exit_code) goto cleanup;
    }
    if(asn1c_parse_inputs(input_argc, av + optind, options.parser_flags,
                          &asn, &exit_code))
        goto cleanup;
    exit_code = asn1c_run_pipeline(&options, ac, optind, av, asn);

cleanup:
    if(exit_code == 0 && fixer_fatal_count) exit_code = EX_SOFTWARE;
    asn1p_delete(asn);
    asn1p_lex_destroy();
    asn1c_cli_options_destroy(&options);
    return exit_code;
}

/*
 * Purpose: order standard module filenames independently of directory iteration.
 * Source: issue #592 PR #593 CI investigation. Version: 2026-10-30.
 * Inputs: left and right are pointers to filename pointers; return: qsort order.
 * Exceptions: none. Author/responsible party: asn1c maintainers.
 * History: keep the EXTERNAL module first to preserve generated symbol indexes.
 * Example: qsort(names, count, sizeof(*names), standard_module_name_compare).
 */
static int
standard_module_name_compare(const void *left, const void *right) {
    const char *a = *(const char *const *)left;
    const char *b = *(const char *const *)right;
    const char *first = "ASN1C-UsefulInformationObjectClasses.asn1";
    if(strcmp(a, first) == 0) return strcmp(b, first) == 0 ? 0 : -1;
    if(strcmp(b, first) == 0) return 1;
    return strcmp(a, b);
}

/*
 * Purpose: append an owned standard module filename to a growable list.
 * Source: issue #592 PR #593 CI investigation. Version: 2026-10-30.
 * Inputs: names, count, and capacity describe the list; filename is copied.
 * Return: zero on success, minus one on allocation or size overflow.
 * Exceptions: none. Author/responsible party: asn1c maintainers.
 * History: added deterministic directory enumeration. Example: append_standard_module_name(&names, &count, &cap, name).
 */
static int
append_standard_module_name(char ***names, size_t *count, size_t *capacity,
                            const char *filename) {
    size_t length = strlen(filename);
    char *copy;
    if(length == SIZE_MAX) return -1;
    if(*count == *capacity) {
        size_t next;
        char **grown;
        if(*capacity > SIZE_MAX / 2) return -1;
        next = *capacity ? *capacity * 2 : 8;
        if(next > SIZE_MAX / sizeof(*grown)) return -1;
        grown = realloc(*names, next * sizeof(*grown));
        if(!grown) return -1;
        *names = grown;
        *capacity = next;
    }
    copy = malloc(length + 1);
    if(!copy) return -1;
    memcpy(copy, filename, length + 1);
    (*names)[(*count)++] = copy;
    return 0;
}

/*
 * Purpose: parse and append one standard ASN.1 module to the compiler tree.
 * Source: former importStandardModules body. Version: 2026-10-30.
 * Inputs: asn is the destination tree; directory and filename identify the file.
 * Return: zero on success, minus one on parse, allocation, or size failure.
 * Exceptions: none. Author/responsible party: asn1c maintainers.
 * History: extracted to permit sorted imports. Example: import_standard_module_file(asn, dir, name).
 */
static int
import_standard_module_file(asn1p_t *asn, const char *directory,
                            const char *filename) {
    size_t dir_len = strlen(directory);
    size_t name_len = strlen(filename);
    size_t full_len;
    char *full_name;
    asn1p_t *new_asn;
    asn1p_module_t *mod;
    if(name_len > SIZE_MAX - 2 || dir_len > SIZE_MAX - name_len - 2) return -1;
    full_len = dir_len + name_len + 2;
    full_name = malloc(full_len);
    if(!full_name) return -1;
    snprintf(full_name, full_len, "%s/%s", directory, filename);
    new_asn = asn1p_parse_file(full_name, A1P_NOFLAGS);
    if(!new_asn) {
        fprintf(stderr, "WARNING: Cannot parse standard module \"%s\"\n", full_name);
        free(full_name);
        return -1;
    }
    free(full_name);
    while((mod = TQ_REMOVE(&(new_asn->modules), mod_next))) {
        mod->_tags |= MT_STANDARD_MODULE;
        TQ_ADD(&(asn->modules), mod, mod_next);
    }
    asn1p_delete(new_asn);
    asn1p_lex_destroy();
    return 0;
}

/*
 * Purpose: import standard ASN.1 modules in a stable order on every filesystem.
 * Source: original importStandardModules and issue #592 PR #593 CI findings.
 * Version: 2026-10-30. Author/responsible party: asn1c maintainers.
 * Inputs: asn is the destination tree; skeletons_dir contains standard-modules.
 * Return: zero on success, minus one on missing input, I/O, or allocation failure.
 * Exceptions: none. History: sort names before parsing. Example: importStandardModules(asn, dir).
 */
static int
importStandardModules(asn1p_t *asn, const char *skeletons_dir) {
    const char *suffix = "/standard-modules";
    size_t dir_len;
    char *target_dir;
    char **names = NULL;
    size_t count = 0;
    size_t capacity = 0;
    size_t i;
    int ret = 0;
#ifdef _WIN32
    intptr_t dir;
    struct _finddata_t c_file;
    char *pattern;
#else
    struct dirent *dp;
    DIR *dir;
#endif

    if(!asn || !skeletons_dir) return -1;
    dir_len = strlen(skeletons_dir);
    if(dir_len > SIZE_MAX - strlen(suffix) - 1) return -1;
    dir_len += strlen(suffix);
    target_dir = malloc(dir_len + 1);
    if(!target_dir) return -1;
    snprintf(target_dir, dir_len + 1, "%s%s", skeletons_dir, suffix);

#ifdef _WIN32
    if(dir_len > SIZE_MAX - sizeof("/*.asn1")) {
        free(target_dir);
        return -1;
    }
    pattern = malloc(dir_len + sizeof("/*.asn1"));
    if(!pattern) {
        free(target_dir);
        return -1;
    }
    snprintf(pattern, dir_len + sizeof("/*.asn1"), "%s/*.asn1", target_dir);
    dir = _findfirst(pattern, &c_file);
    free(pattern);
    if(dir == -1L) {
#else
    dir = opendir(target_dir);
    if(!dir) {
#endif
        fprintf(stderr, "WARNING: Cannot find standard modules in %s\n", target_dir);
        free(target_dir);
        return -1;
    }

    /* Copy names while iterating; the directory API's filename storage is temporary. */
#ifdef _WIN32
    do {
        const char *filename = c_file.name;
#else
    errno = 0;
    while((dp = readdir(dir))) {
        const char *filename = dp->d_name;
#endif
        size_t length = strlen(filename);
        if(length <= 5 || strcmp(filename + length - 5, ".asn1") != 0) continue;
        if(append_standard_module_name(&names, &count, &capacity, filename)) {
            fprintf(stderr, "WARNING: Cannot store standard module name %s\n", filename);
            ret = -1;
            break;
        }
#ifdef _WIN32
    } while(_findnext(dir, &c_file) == 0);
    _findclose(dir);
#else
        errno = 0;
    }
    if(ret == 0 && errno != 0) {
        fprintf(stderr, "WARNING: Cannot read standard modules in %s\n", target_dir);
        ret = -1;
    }
    closedir(dir);
#endif

    /* Parse in the fixture's stable order, then release all copied names. */
    if(ret == 0) {
        if(count > 1) qsort(names, count, sizeof(*names), standard_module_name_compare);
        for(i = 0; i < count; i++) {
            if(import_standard_module_file(asn, target_dir, names[i])) ret = -1;
        }
    }
    for(i = 0; i < count; i++) free(names[i]);
    free(names);
    free(target_dir);
    return ret;
}

/*
 * Same output as the default fixer logger. Counts FATAL diagnostics.
 */
static void
fixer_error_logger(int _severity, const char *fmt, ...) {
    va_list ap;
    const char *pfx = "";

    switch(_severity) {
    case -1: pfx = "DEBUG: "; break;
    case 0: pfx = "WARNING: "; break;
    case 1: pfx = "FATAL: "; fixer_fatal_count++; break;
    }

    fprintf(stderr, "%s", pfx);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/*
 * Print the usage screen and exit(EX_USAGE).
 */
static void __attribute__((noreturn))
usage(const char *av0) {
    /* clang-format off */
	fprintf(stderr,
"ASN.1 Compiler, " VERSION "\n" COPYRIGHT
"Usage: %s [options] file ...\n"
"Options:\n"
"  --rust                Generate Rust codecs for selected types and flat records\n"
"                        (UPER/CER default; opt-in BER/DER, APER, OER, JER, CBOR, XER)\n"
"  -E                    Run only the ASN.1 parser and print out the tree\n"
"  -F                    During -E operation, also perform tree fixing\n"
"\n"
"  -P                    Concatenate and print the compiled text\n"
"  -R                    Restrict output (tables only, no support code)\n"
"  -S <dir>              Directory with support (skeleton?) files\n"
"                        (Default is \"%s\")\n"
"  -D <dir>              Output directory (C default: current dir; Rust: asn1c-rust)\n"
"  -X                    Generate and print the XML DTD\n"
"\n"

"  -Werror               Treat warnings as errors; abort if any warning\n"
"  -Wdebug-lexer         Enable verbose debugging output from lexer\n"
"  -Wdebug-parser        Enable verbose debugging output from parser\n"
"  -Wdebug-fixer         --//-- semantics processor\n"
"  -Wdebug-compiler      --//-- compiler\n"
"\n"

"  -fbless-SIZE          Allow SIZE() constraint for INTEGER etc (non-std.)\n"
"  -fcomplex-threshold=<value>   Threshold value beyond which to use indirection\n"
"  -fcompound-names      Disambiguate C's struct NAME's inside top-level types\n"
"  -findirect-choice     Compile members of CHOICE as indirect pointers\n"
"  -fincludes-quoted     Generate #includes in \"double\" instead of <angle> quotes\n"
"  -fknown-extern-type=<name>    Pretend the specified type is known\n"
"  -fline-refs           Include ASN.1 module's line numbers in comments\n"
"  -fno-constraints      Do not generate the constraint checking code\n"
"  -fno-include-deps     Do not generate the courtesy #includes for dependencies\n"
"  -fprefer-import-source  Resolve only names listed in IMPORTS (no whole-module fallback)\n"
"  -funnamed-unions      Enable unnamed unions in structures\n"
"  -fwide-types          Use INTEGER_t instead of \"long\" by default, etc.\n"
"  -flong-size=<bits>    Target C long size for native INTEGER storage.\n"
"                        Values: 32, 64.  Default: auto portable 32-bit.\n"
"  -finteger-native-type=<mode>  Native C storage policy for constrained INTEGER\n"
"                        types.  Modes: auto, int32, uint32, int64, uint64.\n"
"                        Default: auto.  Values not fitting the policy are\n"
"                        generated as INTEGER_t.\n"
"  -fgen-only-pdu-deps   Generate code only for types that are dependencies of -pdu types\n"
"  -flist-deps           List PDU dependencies (requires -pdu option, no code generated)\n"
"  -fprefix=<prefix>     Add the specified prefix to generated types\n"
"\n"

"  -no-gen-BER           Do not generate the Basic Encoding Rules (BER, X.690) support code\n"
"  -gen-CER              Generate the Canonical Encoding Rules (CER, X.690) encoder; enables BER in C mode\n"
"  -no-gen-CER           Do not generate the Canonical Encoding Rules (CER, X.690) encoder\n"
"  -no-gen-XER           Do not generate the XML Encoding Rules (XER, X.693) support code\n"
"  -no-gen-JER           Do not generate the JSON Encoding Rules (JER, X.697) support code\n"
"  -no-gen-CBOR          Do not generate the Concise Binary Object Representation (CBOR, RFC 7049) support code\n"
"  -no-gen-OER           Do not generate the Octet Encoding Rules (OER, X.696) support code\n"
"  -no-gen-UPER          Do not generate the Unaligned Packed Encoding Rules (PER, X.691) support code\n"
"  -no-gen-APER          Do not generate the Aligned Packed Encoding Rules (PER, X.691) support code\n"
"  -no-gen-print         Do not generate the print code\n"
"  -no-gen-random-fill   Do not generate the random fill code\n"
"  -no-gen-example       Do not generate the ASN.1 format converter example\n"
"  -gen-autotools        Generate example top-level configure.ac and Makefile.am\n"
"  -pdu={all|auto|Type}  Generate PDU table (discover PDUs automatically)\n"
"\n"

"  -print-class-matrix   Print out the collected object class matrix (debug)\n"
"  -print-constraints    Explain subtype constraints (debug)\n"
"  -print-lines          Generate \"-- #line\" comments in -E output\n"
"\n"
"Exit status: 0 success; 64 usage error; 65 ASN.1 input error;\n"
"  66 input file cannot be opened; 70 printing or code generation failed\n"
"  or reported a FATAL diagnostic (incomplete output); 72 skeletons not found.\n"

	,
	a1c_basename(av0, NULL), DATADIR);
    /* clang-format on */
    exit(EX_USAGE);
}
