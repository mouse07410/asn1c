#!/usr/bin/env bash

set -x
set -e
set -o pipefail

top_builddir=${top_builddir:-../..}
top_srcdir=${top_srcdir:-../..}

# Resolve a source/build path from a generated test directory.
# Source: asn1c smoke harness; version 2026-11-02; maintainer: asn1c project.
# Input: $1 is an absolute or test-directory-relative path; output: resolved path.
# Errors: printf failures propagate. History: preserve absolute paths in VPATH builds.
# Example: path_from_testdir ../.. prints ../../..
path_from_testdir() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '../%s\n' "$1" ;;
    esac
}

ASN1C="$(path_from_testdir "${top_builddir}")/asn1c/asn1c"
SKELETONS_DIR="$(path_from_testdir "${top_srcdir}")/skeletons"

# Remove generated files from the current test directory.
# Source: asn1c smoke harness; version 2026-11-02; maintainer: asn1c project.
# Inputs: none; output: rm status; errors: filesystem removal errors propagate.
# History: shared cleanup for each generated variant. Example: cleanup
cleanup() {
    rm -rf *.[acho] Makefile.am.* *.mk *.txt *.asn
    rm -f converter-example
}

# Report the current schema and command after an error, then preserve its status.
# Source: asn1c smoke harness; version 2026-11-02; maintainer: asn1c project.
# Input: preceding command status and generated test.asn/status.txt; output: exits with that status.
# Errors: diagnostic file reads can fail without replacing the original status.
# History: trap preserves details for failed generated builds. Example: trap print_state ERR
print_state() {
    local err=$?
    set +x
    set +e
    trap "" EXIT ERR
    echo "Error $err while processing:"
    cat test.asn
    cat status.txt
    echo "FAILED"
    exit $err
}

# Generate and compile one ASN.1 type with the requested compiler flags.
# Source: asn1c smoke harness; version 2026-11-02; maintainer: asn1c project.
# Inputs: $1 is the ASN.1 type, $2 its compiler flags; output: command status.
# Errors: generation or build failure triggers the error trap.
# History: generated builds were limited to one job to reduce resource pressure.
# Example: verify INTEGER '-no-gen-XER'
verify() {
    local type="$1"
    local flags="$2"

    cleanup

    rm -rf "test-${type}"
    mkdir "test-${type}"
    cd "test-${type}"
    asncmd="${ASN1C} -fall-defs-global -Wdebug-compiler -flink-skeletons -S ${SKELETONS_DIR} $flags test.asn"

    {
    echo "$asncmd"
    echo "${MAKE:-make} -j1 -f converter-example.mk"
    } > status.txt

    echo "Module DEFINITIONS::=BEGIN T::=$type END" > test.asn
    $asncmd
    # Each test occupies one outer make job; avoid spawning a compiler swarm
    # when the caller runs the suite with an unbounded -j.
    CFLAGS=-O0 ${MAKE:-make} -j1 -f converter-example.mk | tail -10
    cd ..
}

# Build every codec-selection and native/wide variant of one type.
# Source: asn1c smoke harness; version 2026-11-02; maintainer: asn1c project.
# Input: $1 is an ASN.1 type; output: last build status.
# Errors: generation or build failure triggers the error trap.
# History: exercises individual disabled codecs and the all-disabled combination.
# Example: verify_type_with_variants INTEGER
verify_type_with_variants() {
    local type="$1"
    local flags native
    local all_disabled="-no-gen-UPER -no-gen-APER -no-gen-OER -no-gen-XER"
    all_disabled+=" -no-gen-JER -no-gen-BER -no-gen-print -no-gen-random-fill"

    for flags in "-no-gen-UPER" "-no-gen-APER" "-no-gen-OER" "-no-gen-XER" \
                 "-no-gen-JER" "-no-gen-BER" "-no-gen-print" "-no-gen-random-fill" \
                 "$all_disabled" ""; do
        for native in "" "-fwide-types"; do
            verify "$type" "$flags $native"
        done
    done
}

# Exercise the complete built-in set of basic ASN.1 types.
# Source: asn1c smoke harness; version 2026-11-02; maintainer: asn1c project.
# Inputs: none; output: last build status; errors: a failing variant triggers the trap.
# History: supports standalone execution without arguments.
# Example: verify_compile_and_link_variants
verify_compile_and_link_variants() {
    for type in INTEGER "INTEGER(0..1)" "ENUMERATED{foo}" NULL BOOLEAN \
                "BIT STRING" \
                "OBJECT IDENTIFIER" "RELATIVE-OID" \
                "SEQUENCE{f INTEGER}" \
                "CHOICE{f INTEGER}" \
                "OCTET STRING" IA5String "IA5String(SIZE(1))" UTF8String \
                REAL "SET OF INTEGER" "SEQUENCE OF INTEGER"; do
        verify_type_with_variants "$type"
    done
}

trap print_state EXIT ERR
if [ "x$*" = "x" ]; then
    verify_compile_and_link_variants
else
    for type in "$@"; do
        verify_type_with_variants "$type"
    done
fi
set +x
trap '' EXIT ERR

cleanup
echo "OK"
