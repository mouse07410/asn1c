#!/usr/bin/env bash
#
# Purpose: compile/run generated C XER regressions for GitHub issue #594.
# Original source: SET/SEQUENCE DEFAULT XER; fixture number 607.
# Version/date: 1.0, 2026-10-31.
# Inputs: configured asn1c, C compiler, make, and source/build root variables.
# Returns/errors: zero when native and wide generated projects pass.
# Responsible party: asn1c maintainers. History: added issue #594 XER coverage.
# Example: make check TESTS=check-issue-607.sh

set -euo pipefail

build_root=$(cd "${top_builddir:-../..}" && pwd)
source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-607.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM

asn1c="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
schema="$source_root/tests/tests-asn1c-smoke/data/issue-607-xer.asn1"
program="$source_root/tests/tests-asn1c-smoke/data/issue-607-xer.c"

# Purpose: generate, compile, and run one C storage mode for fixture 607.
# Original source: GitHub issue #594 generated-code regression.
# Version/date: 1.0, 2026-10-31.
# Parameters: mode is the output name; extra compiler flags select storage.
# Returns/errors: zero on successful generation, compilation, and assertions.
# Responsible party: asn1c maintainers. History: native and wide storage cases.
# Example: run_case wide -fwide-types.
run_case() {
    local mode=$1
    shift
    local generated="$test_directory/$mode"
    mkdir -p "$generated"
    if ! "$asn1c" -S "$skeletons" -D "$generated" -pdu=all "$@" \
        -no-gen-UPER -no-gen-APER -no-gen-OER -no-gen-CBOR \
        "$schema" > "$generated/asn1c.log" 2>&1; then
        cat "$generated/asn1c.log" >&2
        return 1
    fi
    if ! "${MAKE:-make}" -C "$generated" -f converter-example.mk \
        CC="${CC:-cc}" > "$generated/make.log" 2>&1; then
        cat "$generated/make.log" >&2
        return 1
    fi
    if ! "${CC:-cc}" -std=c99 -I"$generated" "$program" \
        "$generated/libasncodec.a" -lm -o "$generated/check-issue-607" \
        > "$generated/compile.log" 2>&1; then
        cat "$generated/compile.log" >&2
        return 1
    fi
    "$generated/check-issue-607"
}

run_case native
run_case wide -fwide-types

echo 'GitHub issue #594 (fixture 607) generated XER regression passed'
