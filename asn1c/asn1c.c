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



int
main(int ac, char **av) {
    enum asn1p_flags asn1_parser_flags = A1P_NOFLAGS;
    enum asn1f_flags asn1_fixer_flags = A1F_NOFLAGS;
    enum asn1c_flags asn1_compiler_flags =
        A1C_NO_C99 | A1C_GEN_BER | A1C_GEN_XER | A1C_GEN_OER | A1C_GEN_UPER | A1C_GEN_APER | A1C_GEN_PRINT | A1C_GEN_RFILL | A1C_GEN_EXAMPLE | A1C_GEN_JER | A1C_GEN_CBOR;
    enum asn1print_flags asn1_printer_flags = APF_NOFLAGS;
    int print_arg__print_out = 0;   /* Don't compile, just print parsed */
    int print_arg__fix_n_print = 0; /* Fix and print */
    int warnings_as_errors = 0;     /* Treat warnings as errors */
    char *skeletons_dir = NULL;     /* Directory with supplementary stuff */
    char *destdir = NULL;           /* Destination for generated files */
    char **debug_type_names = 0;    /* Debug stuff */
    size_t debug_type_names_count = 0;
    asn1p_t *asn = 0;               /* An ASN.1 parsed tree */
    int ret;                        /* Return value from misc functions */
    int ch;                         /* Command line character */
    int i;                          /* Index in some loops */
    int exit_code = 0;              /* Exit code */
    int complex_threshold = 4;      /* Threshold for switching structures to ptrs */

    /*
     * Process command-line options.
     */
    while((ch = getopt(ac, av, "D:d:EFf:g:hn:LPp:RS:vW:X")) != -1) switch(ch) {
        case 'D':
            if(optarg && *optarg) {
                size_t optarg_len = strlen(optarg);
                free(destdir);
                destdir = calloc(1, optarg_len + 2); /* + "/\0" */
                assert(destdir);
                strcpy(destdir, optarg);
                if(destdir[optarg_len - 1] != '/') {
                    destdir[optarg_len] = '/';
                }
            } else {
                free(destdir);
                destdir = NULL;
            }
            break;
        case 'd':
            if(strncmp(optarg, "ebug-type-naming=", 17) == 0) {
                char **p = realloc(debug_type_names,
                                   (debug_type_names_count + 2) * sizeof(*p));
                assert(p);
                debug_type_names = p;
                debug_type_names[debug_type_names_count++] =
                    strdup(optarg + 17);
                debug_type_names[debug_type_names_count] = NULL;
                break;
            } else if(strcmp(optarg, "ebug-output-origin-lines") == 0) {
                asn1_compiler_flags |= A1C_DEBUG_OUTPUT_ORIGIN_LINES;
                break;
            }
            usage(av[0]);
        case 'E':
            print_arg__print_out = 1;
            break;
        case 'F':
            print_arg__fix_n_print = 1;
            break;
        case 'f':
            if(strcmp(optarg, "all-defs-global") == 0) {
                asn1_compiler_flags |= A1C_ALL_DEFS_GLOBAL;
            } else if(strcmp(optarg, "bless-SIZE") == 0) {
                asn1_fixer_flags |= A1F_EXTENDED_SizeConstraint;
            } else if(strcmp(optarg, "compound-names") == 0) {
                asn1_compiler_flags |= A1C_COMPOUND_NAMES;
                asn1_fixer_flags |= A1F_COMPOUND_NAMES;
            } else if(strcmp(optarg, "indirect-choice") == 0) {
                asn1_compiler_flags |= A1C_INDIRECT_CHOICE;
            } else if(strncmp(optarg, "known-extern-type=", 18) == 0) {
                char *known_type = optarg + 18;
                ret = asn1f_make_known_external_type(known_type);
                assert(ret == 0 || errno == EEXIST);
            } else if(strcmp(optarg, "allow-newer-modules") == 0) {
                asn1_fixer_flags |= A1F_ALLOW_NEWER_MODULES;
            } else if(strcmp(optarg, "prefer-import-source") == 0) {
                asn1_fixer_flags |= A1F_PREFER_IMPORT_SOURCE;
            } else if(strcmp(optarg, "native-types") == 0) {
                fprintf(stderr, "-f%s: Deprecated option\n", optarg);
                asn1_compiler_flags &= ~A1C_USE_WIDE_TYPES;
            } else if(strcmp(optarg, "wide-types") == 0) {
                asn1_compiler_flags |= A1C_USE_WIDE_TYPES;
            } else if(strncmp(optarg, "long-size=", 10) == 0) {
                char *mode = optarg + 10;
                if(strcmp(mode, "32") == 0) {
                    asn1c_target_long_size = ASN_TARGET_LONG_32;
                } else if(strcmp(mode, "64") == 0) {
                    asn1c_target_long_size = ASN_TARGET_LONG_64;
                } else {
                    fprintf(stderr, "-flong-size expects one of: 32, 64\n");
                    exit(EX_USAGE);
                }
            } else if(strcmp(optarg, "line-refs") == 0) {
                asn1_compiler_flags |= A1C_LINE_REFS;
            } else if(strcmp(optarg, "no-constraints") == 0) {
                asn1_compiler_flags |= A1C_NO_CONSTRAINTS;
            } else if(strcmp(optarg, "no-include-deps") == 0) {
                asn1_compiler_flags |= A1C_NO_INCLUDE_DEPS;
            } else if(strcmp(optarg, "includes-quoted") == 0) {
                asn1_compiler_flags |= A1C_INCLUDES_QUOTED;
            } else if(strcmp(optarg, "unnamed-unions") == 0) {
                asn1_compiler_flags |= A1C_UNNAMED_UNIONS;
            } else if(strcmp(optarg, "skeletons-copy") == 0) {
                fprintf(stderr, "-f%s: Deprecated option\n", optarg);
                asn1_compiler_flags &= ~A1C_LINK_SKELETONS;
            } else if(strcmp(optarg, "link-skeletons") == 0) {
                asn1_compiler_flags |= A1C_LINK_SKELETONS;
            } else if(strcmp(optarg, "gen-only-pdu-deps") == 0) {
                asn1_compiler_flags |= A1C_GEN_ONLY_PDU_DEPS;
            } else if(strcmp(optarg, "list-deps") == 0) {
                asn1_compiler_flags |= A1C_LIST_DEPS;
            } else if(strncmp(optarg, "integer-native-type=", 20) == 0) {
                char *mode = optarg + 20;
                if(strcmp(mode, "auto") == 0) {
                    asn1c_integer_native_type = AINT_NATIVE_AUTO;
                } else if(strcmp(mode, "int32") == 0) {
                    asn1c_integer_native_type = AINT_NATIVE_INT32;
                } else if(strcmp(mode, "uint32") == 0) {
                    asn1c_integer_native_type = AINT_NATIVE_UINT32;
                } else if(strcmp(mode, "int64") == 0) {
                    asn1c_integer_native_type = AINT_NATIVE_INT64;
                } else if(strcmp(mode, "uint64") == 0) {
                    asn1c_integer_native_type = AINT_NATIVE_UINT64;
                } else if(strcmp(mode, "long") == 0) {
                    /* Deprecated, ambiguous alias kept for compatibility. */
                    asn1c_integer_native_type = AINT_NATIVE_AUTO;
                } else {
                    fprintf(stderr,
                        "-finteger-native-type expects one of: "
                        "int32, uint32, int64, uint64, auto\n");
                    exit(EX_USAGE);
                }
            } else if(strncmp(optarg, "prefix=", 7) == 0) {
                char *prefix = optarg + 7;
                asn1c_prefix_set(prefix);
            } else if(strncmp(optarg, "complex-threshold=", 18) == 0) {
                char *threshold = optarg + 18;
                long thresh_val;
                if ((is_integer(threshold, &thresh_val) != 1)
                	|| (thresh_val > 500) /* let's not be stupid here */
                	|| (thresh_val <= 0)  /* again, stupidity not appreciated */
                	) {
                	fprintf(stderr, "-f%s: bad format or value too large\n", optarg);
	                exit(EX_USAGE);
	            }
                complex_threshold = (int)thresh_val;
            } else {
                fprintf(stderr, "-f%s: Invalid argument\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'g':
            if(strcmp(optarg, "en-BER") == 0) {
                asn1_compiler_flags |= A1C_GEN_BER;
            } else if(strcmp(optarg, "en-XER") == 0) {
                asn1_compiler_flags |= A1C_GEN_XER;
            } else if(strcmp(optarg, "en-JER") == 0) {
                asn1_compiler_flags |= A1C_GEN_JER;
            } else if(strcmp(optarg, "en-CBOR") == 0) {
                asn1_compiler_flags |= A1C_GEN_CBOR;
            } else if(strcmp(optarg, "en-OER") == 0) {
                asn1_compiler_flags |= A1C_GEN_OER;
            } else if(strcmp(optarg, "en-UPER") == 0) {
                asn1_compiler_flags |= A1C_GEN_UPER;
            } else if(strcmp(optarg, "en-APER") == 0) {
                asn1_compiler_flags |= A1C_GEN_APER;
            } else if(strcmp(optarg, "en-print") == 0) {
                asn1_compiler_flags |= A1C_GEN_PRINT;
            } else if(strcmp(optarg, "en-random-fill") == 0) {
                asn1_compiler_flags |= A1C_GEN_RFILL;
            } else if(strcmp(optarg, "en-example") == 0) {
                asn1_compiler_flags |= A1C_GEN_EXAMPLE;
            } else if(strcmp(optarg, "en-autotools") == 0) {
                asn1_compiler_flags |= A1C_GEN_AUTOTOOLS_EXAMPLE;
            } else {
                fprintf(stderr, "-g%s: Invalid argument\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'h':
            usage(av[0]);
        case 'n':
            if(strcmp(optarg, "o-gen-BER") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_BER;
            } else if(strcmp(optarg, "o-gen-XER") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_XER;
            } else if(strcmp(optarg, "o-gen-JER") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_JER;
            } else if(strcmp(optarg, "o-gen-CBOR") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_CBOR;
            } else if(strcmp(optarg, "o-gen-OER") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_OER;
            } else if(strcmp(optarg, "o-gen-UPER") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_UPER;
            } else if(strcmp(optarg, "o-gen-APER") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_APER;
            } else if(strcmp(optarg, "o-gen-print") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_PRINT;
            } else if(strcmp(optarg, "o-gen-random-fill") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_RFILL;
            } else if(strcmp(optarg, "o-gen-example") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_EXAMPLE;
            } else if(strcmp(optarg, "o-gen-autotools") == 0) {
                asn1_compiler_flags &= ~A1C_GEN_AUTOTOOLS_EXAMPLE;
            } else {
                fprintf(stderr, "-n%s: Invalid argument\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'P':
            asn1_compiler_flags |= A1C_PRINT_COMPILED;
            asn1_compiler_flags &= ~A1C_NO_C99;
            break;
        case 'p':
            if(strncmp(optarg, "du=", 3) == 0) {
                char *pduname = optarg + 3;
                if(strcmp(pduname, "all") == 0) {
                    asn1_compiler_flags |= A1C_PDU_ALL;
                } else if(strcmp(pduname, "auto") == 0) {
                    asn1_compiler_flags |= A1C_PDU_AUTO;
                } else if(pduname[0] >= 'A' && pduname[0] <= 'Z') {
                    asn1c__add_pdu_type(pduname);
                    asn1_compiler_flags |= A1C_PDU_TYPE;
                } else {
                    fprintf(stderr, "-pdu=%s: expected -pdu={all|auto|Type}\n",
                            pduname);
                    exit(EX_USAGE);
                }
            } else if(strcmp(optarg, "rint-class-matrix") == 0) {
                asn1_printer_flags |= APF_PRINT_CLASS_MATRIX;
            } else if(strcmp(optarg, "rint-constraints") == 0) {
                asn1_printer_flags |= APF_PRINT_CONSTRAINTS;
            } else if(strcmp(optarg, "rint-lines") == 0) {
                asn1_printer_flags |= APF_LINE_COMMENTS;
            } else {
                fprintf(stderr, "-p%s: Invalid argument\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'R':
            asn1_compiler_flags |= A1C_OMIT_SUPPORT_CODE;
            break;
        case 'S':
            skeletons_dir = optarg;
            break;
        case 'v':
            fprintf(stderr, "ASN.1 Compiler, " VERSION " (" PACKAGE_BUGREPORT ")\n" COPYRIGHT);
            exit(0);
            break;
        case 'W':
            if(strcmp(optarg, "error") == 0) {
                warnings_as_errors = 1;
                break;
            } else if(strcmp(optarg, "debug-lexer") == 0) {
                asn1_parser_flags |= A1P_DEBUG_LEXER;
                break;
            } else if(strcmp(optarg, "debug-parser") == 0) {
                asn1_parser_flags |= A1P_DEBUG_PARSER;
                break;
            } else if(strcmp(optarg, "debug-fixer") == 0) {
                asn1_fixer_flags |= A1F_DEBUG;
                break;
            } else if(strcmp(optarg, "debug-compiler") == 0) {
                asn1_compiler_flags |= A1C_DEBUG;
                break;
            } else {
                fprintf(stderr, "-W%s: Invalid argument\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'X':
            print_arg__print_out = 1;   /* Implicit -E */
            print_arg__fix_n_print = 1; /* Implicit -F */
            asn1_printer_flags |= APF_PRINT_XML_DTD;
            break;
        default:
            usage(av[0]);
        }

    /*
     * Validate the options combination.
     */
    if(print_arg__print_out) {
        if((asn1_printer_flags & APF_PRINT_CONSTRAINTS)
           && !print_arg__fix_n_print) {
            fprintf(stderr,
                    "Error: -print-constraints argument requires -E -F\n");
            exit(EX_USAGE);
        }
    } else {
        if(print_arg__fix_n_print) {
            fprintf(stderr, "Error: -F requires -E\n");
            exit(EX_USAGE);
        }
        if(asn1_printer_flags) {
            fprintf(stderr, "Error: -print-... arguments require -E\n");
            exit(EX_USAGE);
        }
    }

    /*
     * Ensure that there are some input files present.
     */
    if(ac > optind) {
        ac -= optind;
        av += optind;
    } else {
        const char *bin_name = a1c_basename(av[0], NULL);
        fprintf(stderr,
                "%s: No input files specified. "
                "Try '%s -h' for more information\n",
                bin_name, bin_name);
        exit(1);
    }

    /*
     * Make sure the skeleton directory is out there.
     */
    if(skeletons_dir == NULL) {
        struct stat sb;
        skeletons_dir = DATADIR;
        if(stat(skeletons_dir, &sb)) {
            /*
             * The default skeletons directory does not exist,
             * compute it from my file name:
             * ./asn1c/asn1c -> ./skeletons
             */
            const char *skel_dir;
            size_t len;

            skel_dir = a1c_dirname(av[-optind]);

            len = strlen(skel_dir) + sizeof("/../skeletons");
            skeletons_dir = malloc(len);
            assert(skeletons_dir);
            snprintf(skeletons_dir, len, "%s/../skeletons", skel_dir);
            if(stat(skeletons_dir, &sb)) {
                fprintf(stderr,
                        "WARNING: skeletons are neither in "
                        "\"%s\" nor in \"%s\"!\n",
                        DATADIR, skeletons_dir);
                if(warnings_as_errors) exit(EX_OSFILE);
            }
        }
    }

    /*
     * Iterate over input files and parse each.
     * All syntax trees from all files will be bundled together.
     */
    for(i = 0; i < ac; i++) {
        asn1p_t *new_asn;

        new_asn = asn1p_parse_file(av[i], asn1_parser_flags);
        if(new_asn == NULL) {
            fprintf(stderr, "Cannot parse \"%s\"\n", av[i]);
            exit_code = EX_DATAERR;
            goto cleanup;
        }

        /*
         * Bundle the parsed tree with existing one.
         */
        if(asn) {
            asn1p_module_t *mod;
            while((mod = TQ_REMOVE(&(new_asn->modules), mod_next)))
                TQ_ADD(&(asn->modules), mod, mod_next);
            asn1p_delete(new_asn);
        } else {
            asn = new_asn;
        }
    }

    /* These are mostly notes for the human readers */
    assert(asn);
    assert(skeletons_dir);

    /*
     * Dump the parsed ASN.1 tree if -E specified and -F is NOT given.
     */
    if(print_arg__print_out && !print_arg__fix_n_print) {
        if(asn1print(asn, asn1_printer_flags)) {
            exit_code = EX_SOFTWARE;
            goto cleanup;
        }
        return 0;
    }

    /*
     * Read in the files from skeletons/standard-modules
     */
    if(importStandardModules(asn, skeletons_dir)) {
        if(warnings_as_errors) {
            exit_code = EX_DATAERR;
            goto cleanup;
        }
    } else {
        asn1f_use_standard_namespaces(asn);
    }

    /*
     * Process the ASN.1 specification: perform semantic checks,
     * expand references, etc, etc.
     * This function will emit necessary warnings and error messages.
     */
    ret = asn1f_process(asn, asn1_fixer_flags,
                        NULL /* default fprintf(stderr) */);
    switch(ret) {
    case 0:
        break; /* All clear */
    case 1:
        if(!warnings_as_errors) {
            break;
        }
        /* Fall through */
    case -1:
        exit_code = EX_DATAERR; /* Fatal failure */
        goto cleanup;
    }

    /*
     * Dump the parsed ASN.1 tree if -E specified and -F is given.
     */
    if(print_arg__print_out && print_arg__fix_n_print) {
        if(asn1print(asn, asn1_printer_flags)) {
            exit_code = EX_SOFTWARE;
            goto cleanup;
        }
        return 0;
    }

    /*
     * -debug-type-naming=Type
     */
    if(debug_type_names) {
        asn1c_debug_type_naming(asn, asn1_compiler_flags, debug_type_names);
        return 0;
    }

    /*
     * Compile the ASN.1 tree into a set of source files
     * of another language.
     */
    if(asn1_compile(asn, skeletons_dir, destdir ? destdir : "",
                    asn1_compiler_flags, ac + optind, optind, av - optind,
                    complex_threshold)) {
        exit_code = EX_SOFTWARE;
    }

cleanup:
    asn1p_delete(asn);
    asn1p_lex_destroy();
    if (exit_code) exit(exit_code);

    return 0;
}

/*
 * Parse and import *.asn1 from skeletons/standard-modules
 */
static int
importStandardModules(asn1p_t *asn, const char *skeletons_dir) {
    asn1p_t *new_asn;
    asn1p_module_t *mod;
    const char *filename;
    char *fullname;
    char *target_dir;
    int target_dir_len;
    int len;
#ifdef _WIN32
    intptr_t dir;
    struct _finddata_t c_file;
    char *pattern;
#else
    struct dirent *dp;
    DIR *dir;
#endif
    int ret = 0;

    /* Notes for the human reader */
    assert(asn);
    assert(skeletons_dir);

    /*
     * Figure out the standard-modules directory.
     */
    target_dir_len = strlen(skeletons_dir) + sizeof("/standard-modules") - 1;
    target_dir = malloc(target_dir_len + 1);
    assert(target_dir);
    snprintf(target_dir, target_dir_len + 1, "%s/standard-modules",
             skeletons_dir);

#ifdef _WIN32
    len = target_dir_len + sizeof("/*.asn1");
    pattern = malloc(len);
    assert(pattern);
    snprintf(pattern, len, "%s/*.asn1", target_dir);
    dir = _findfirst(pattern, &c_file);
    if(dir == -1L) {
#else
    dir = opendir(target_dir);
    if(!dir) {
#endif
        fprintf(stderr, "WARNING: Cannot find standard modules in %s\n",
                target_dir);
        return -1;
    }

#ifdef _WIN32
    do {
        filename = c_file.name;
#else
    while((dp = readdir(dir))) {
        filename = dp->d_name;
#endif
        len = strlen(filename);
        if(len <= 5 || strcmp(filename + len - 5, ".asn1")) continue;
        len = target_dir_len + 1 + len + 1;
        fullname = malloc(len);
        if(!fullname) continue; /* Just skip it, no big deal */
        snprintf(fullname, len, "%s/%s", target_dir, filename);
        filename = fullname;

        new_asn = asn1p_parse_file(filename, A1P_NOFLAGS);
        if(new_asn == NULL) {
            fprintf(stderr, "WARNING: Cannot parse standard module \"%s\"\n",
                    filename);
            ret = -1;
            continue;
        }

        /* Import these modules and mark them as "standard" */
        while((mod = TQ_REMOVE(&(new_asn->modules), mod_next))) {
            mod->_tags |= MT_STANDARD_MODULE;
            TQ_ADD(&(asn->modules), mod, mod_next);
        }
        asn1p_delete(new_asn);
        asn1p_lex_destroy();

#ifdef _WIN32
    } while(_findnext(dir, &c_file) == 0);
    _findclose(dir);
#else
        free(fullname);
    } /* while(readdir()) */
    closedir(dir);
#endif

#ifdef _WIN32
    free(pattern);
#endif
    free(target_dir);

    return ret;
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
"  -E                    Run only the ASN.1 parser and print out the tree\n"
"  -F                    During -E operation, also perform tree fixing\n"
"\n"
"  -P                    Concatenate and print the compiled text\n"
"  -R                    Restrict output (tables only, no support code)\n"
"  -S <dir>              Directory with support (skeleton?) files\n"
"                        (Default is \"%s\")\n"
"  -D <dir>              Destination directory for generated files (default current dir)\n"
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
"  -fallow-newer-modules   Accept newer OID (last 2 arcs) or base+2 version arcs; fail if older\n"
"  -fline-refs           Include ASN.1 module's line numbers in comments\n"
"  -fno-constraints      Do not generate the constraint checking code\n"
"  -fno-include-deps     Do not generate the courtesy #includes for dependencies\n"
"  -fprefer-import-source  Require strict xp_members match for IMPORTS (fixes ambiguous same-name imports)\n"
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

	,
	a1c_basename(av0, NULL), DATADIR);
    /* clang-format on */
    exit(EX_USAGE);
}
