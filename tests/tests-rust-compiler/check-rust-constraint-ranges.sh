#!/bin/sh

# Exercise constraint validation through actual Rust crate generation.
# Inputs: configured top_srcdir/top_builddir and the asn1c compiler binary.
# Returns: zero on success, 77 without Rust tools, and nonzero on failure.
# Errors: wrong diagnostics, crashes, hangs, or premature crate publication fail.
# Original source: new Rust backend constraint regression driver.
# Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
# History: covers issues #605 and #607 across parser and Rust backend paths.
# Example: make -C tests/tests-rust-compiler check TESTS=check-rust-constraint-ranges.sh.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)
test_srcdir="$top_srcdir/tests/tests-rust-compiler"
asn1c_bin="$top_builddir/asn1c/asn1c"
skeletons="$top_srcdir/skeletons"
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo "SKIP: Cargo and rustc are required for generated Rust range tests"
    exit 77
fi

if command -v timeout >/dev/null 2>&1; then
    timeout_cmd=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    timeout_cmd=gtimeout
else
    echo "FAIL: neither 'timeout' nor 'gtimeout' is available for this test"
    exit 1
fi

if [ ! -r "$top_builddir/config.h" ]; then
    echo "FAIL: cannot read configured feature header: $top_builddir/config.h"
    exit 1
fi

if grep -Eq '^#[[:space:]]*define[[:space:]]+HAVE_128_BIT_INT[[:space:]]+1' \
    "$top_builddir/config.h"; then
    asn_integer_min=-170141183460469231731687303715884105728
    asn_integer_max=170141183460469231731687303715884105727
    have_128_bit_int=1
else
    have_128_bit_int=0
fi

# Purpose: Write a one-type schema for a Rust CLI generation check.
# Original source: new issue #605/#607 Rust compiler regression harness.
# Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
# Inputs: $1 is a unique case name; $2 is its ASN.1 type expression.
# Returns: Writes a schema file under test_tmp; no value is returned.
# Errors: A failed write terminates the shell under set -e.
# History: Centralizes temporary schema construction for invalid and valid cases.
# Example: write_schema reversed 'INTEGER (5..1)'.
write_schema() {
    schema_name=$1
    type_expression=$2
    printf 'M DEFINITIONS ::= BEGIN\nT ::= %s\nEND\n' "$type_expression" \
        >"$test_tmp/$schema_name.asn1"
}

# Purpose: Generate a schema through --rust while bounding compiler execution.
# Original source: new issue #605/#607 Rust compiler regression harness.
# Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
# Inputs: $1 is a unique case name; $2 is an optional compiler flag.
# Returns: Sets result_status and records combined output in a per-case log.
# Errors: Caller interprets nonzero status, timeout, and signal termination.
# History: Ensures malformed schemas cannot hang the Rust compiler test suite.
# Example: run_generator reversed '' .
run_generator() {
    schema_name=$1
    extra_flag=$2
    result_status=0
    if [ -n "$extra_flag" ]; then
        "$timeout_cmd" 15 "$asn1c_bin" --rust "$extra_flag" -gen-UPER \
            -no-gen-CER -S "$skeletons" -D "$test_tmp/out-$schema_name" \
            "$test_tmp/$schema_name.asn1" >"$test_tmp/$schema_name.log" 2>&1 \
            || result_status=$?
    else
        "$timeout_cmd" 15 "$asn1c_bin" --rust -gen-UPER -no-gen-CER \
            -S "$skeletons" -D "$test_tmp/out-$schema_name" \
            "$test_tmp/$schema_name.asn1" >"$test_tmp/$schema_name.log" 2>&1 \
            || result_status=$?
    fi
}

# Purpose: Assert actual Rust generation rejects a reversed range safely.
# Original source: shared frontend's ASN1-0088 reversed-range regression.
# Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
# Inputs: $1 is a case name; $2 is its invalid ASN.1 type expression.
# Returns: Increments failures when exit status, diagnostic, or output is wrong.
# Errors: Reports the case failure and continues to exercise remaining cases.
# History: Adds Rust backend coverage of frontend failures previously tested in -E -F.
# Example: check_reversed size 'IA5String (SIZE (5..1))'.
check_reversed() {
    schema_name=$1
    type_expression=$2
    write_schema "$schema_name" "$type_expression"
    run_generator "$schema_name" ''

    if [ "$result_status" -eq 65 ] \
        && grep -Eq 'Constraint range .* is empty' "$test_tmp/$schema_name.log" \
        && [ ! -e "$test_tmp/out-$schema_name" ]; then
        echo "PASS: $schema_name rejected before Rust crate publication"
        return
    fi

    echo "FAIL: $schema_name expected exit 65, an empty-range diagnostic, and no crate"
    echo "Observed compiler status: $result_status"
    cat "$test_tmp/$schema_name.log"
    failures=$((failures + 1))
}

failures=0 # Failure count state variable retained across independent cases.

# Shared frontend protection must run under real Rust generation, including
# each reversed interval family and the union and extension construction paths.
check_reversed integer-reversed 'INTEGER (5..1)'
check_reversed integer-union 'INTEGER (0..10 | 5..1)'
check_reversed integer-extension 'INTEGER (0..10, ..., 9..6)'
check_reversed size-reversed 'IA5String (SIZE (5..1))'
check_reversed from-reversed 'IA5String (FROM ("Z".."A"))'
check_reversed real-reversed 'REAL (WITH COMPONENTS { mantissa (5..1) })'

# Purpose: Assert -fno-constraints is rejected as a C-only option for Rust.
# Original source: Rust CLI option contract.
# Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
# Inputs: Uses a valid schema to distinguish the option gate from schema errors.
# Returns: Increments failures unless exit 64 occurs without output publication.
# Errors: Reports compiler output and continues to the remaining boundary checks.
# History: Documents verified behavior for issue #605 compatibility coverage.
# Example: the Rust backend rejects -fno-constraints before parsing this schema.
check_no_constraints_gate() {
    write_schema no-constraints 'INTEGER (0..1)'
    result_status=0
    "$timeout_cmd" 15 "$asn1c_bin" --rust -fno-constraints -gen-UPER \
        -no-gen-CER -S "$skeletons" -D "$test_tmp/out-no-constraints" \
        "$test_tmp/no-constraints.asn1" >"$test_tmp/no-constraints.log" 2>&1 \
        || result_status=$?
    if [ "$result_status" -eq 64 ] \
        && grep -F 'C-only option is incompatible with --rust' \
            "$test_tmp/no-constraints.log" >/dev/null \
        && [ ! -e "$test_tmp/out-no-constraints" ]; then
        echo "PASS: Rust rejects the C-only -fno-constraints option"
        return
    fi

    echo "FAIL: -fno-constraints did not produce the expected Rust option error"
    echo "Observed compiler status: $result_status"
    cat "$test_tmp/no-constraints.log"
    failures=$((failures + 1))
}

check_no_constraints_gate

# Purpose: Assert a valid ASN.1 range is rejected cleanly by the Rust i64 gate.
# Original source: issue #607 configured-width endpoint regression.
# Version/date: 1, 2026-11-16. Responsible party: asn1c maintainers.
# Inputs: $1 is a case name; $2 is a valid finite INTEGER range expression.
# Returns: Increments failures unless Rust returns 70 with its i64 diagnostic.
# Errors: Reports abnormal, successful, or output-publishing rejection results.
# History: Distinguishes compiler-width support from Rust runtime representation.
# Example: check_rust_rejects_wide max "INTEGER (0..$asn_integer_max)".
check_rust_rejects_wide() {
    schema_name=$1
    type_expression=$2
    write_schema "$schema_name" "$type_expression"
    run_generator "$schema_name" ''

    if [ "$result_status" -eq 70 ] \
        && grep -F 'INTEGER needs one finite, nonextensible range fitting i64' \
            "$test_tmp/$schema_name.log" >/dev/null \
        && [ ! -e "$test_tmp/out-$schema_name" ]; then
        echo "PASS: Rust rejects unsupported wide range $schema_name before publication"
        return
    fi

    echo "FAIL: wide range $schema_name did not fail cleanly in the Rust i64 gate"
    echo "Observed compiler status: $result_status"
    cat "$test_tmp/$schema_name.log"
    failures=$((failures + 1))
}

# 128-bit source integers are valid for the shared compiler but exceed Rust's
# generated i64 representation. These cases also cover both native extrema.
if [ "$have_128_bit_int" -eq 1 ]; then
    check_rust_rejects_wide native-max "INTEGER (0..$asn_integer_max)"
    check_rust_rejects_wide native-min "INTEGER ($asn_integer_min..0)"
    check_rust_rejects_wide negative-to-max "INTEGER (-1..$asn_integer_max)"
    check_rust_rejects_wide i64-upper-neighbour \
        'INTEGER (9223372036854775808..9223372036854775809)'
    check_rust_rejects_wide i64-lower-neighbour \
        'INTEGER (-9223372036854775809..-9223372036854775808)'
else
    echo "NOTE: configured compiler lacks HAVE_128_BIT_INT; skipping wide-range backend checks"
fi

# Generate supported full i64 and narrow intervals with UPER and APER.
cat >"$test_tmp/signed64-boundaries.asn1" <<'EOF'
Signed64Boundaries DEFINITIONS ::= BEGIN
All ::= INTEGER (-9223372036854775808..9223372036854775807)
Small ::= INTEGER (-2..2)
END
EOF
if ! "$timeout_cmd" 15 "$asn1c_bin" --rust -gen-UPER -gen-APER -no-gen-CER \
    -S "$skeletons" -D "$test_tmp/signed64" \
    "$test_tmp/signed64-boundaries.asn1" >"$test_tmp/signed64.log" 2>&1; then
    echo "FAIL: valid signed64 boundary schema did not generate"
    cat "$test_tmp/signed64.log"
    exit 1
fi

mkdir "$test_tmp/signed64/tests"
cp "$test_srcdir/rust_constraint_ranges_conformance.rs" \
    "$test_tmp/signed64/tests/constraint_ranges.rs"

if ! (cargo test --offline --manifest-path "$test_tmp/signed64/Cargo.toml" \
    --all-targets --all-features \
    && cargo clippy --offline --manifest-path "$test_tmp/signed64/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic \
        -W clippy::nursery -D warnings) >"$test_tmp/signed64-rust.log" 2>&1; then
    cat "$test_tmp/signed64-rust.log"
    echo "FAIL: signed64 Rust boundary conformance or strict Clippy"
    exit 1
fi

echo "PASS: full signed64 and narrow interval UPER/APER boundaries"

if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures Rust constraint-range regression case(s) failed"
    exit 1
fi

echo "PASS: Rust backend constraint-range regressions"
