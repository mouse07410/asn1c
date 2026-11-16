#!/bin/sh

# Reversed constraint ranges (ASN1-0088), asn1c side.
#
# A value, SIZE or FROM constraint whose lower bound is greater than its
# upper bound is built by the fixer and then intersected with the parent
# type's range. The intersection asserts that both operands are non-empty,
# so a reversed range used to abort the process (SIGABRT, exit 134) instead
# of producing a diagnostic.
#
# Invariant: a reversed constraint range is reported as an error with a
# diagnostic and a non-zero exit, and never reaches the range-intersection
# machinery. The construction point in asn1constraint_compute_constraint_range()
# rejects it with "Constraint range ... is empty" and errno = EPERM, which
# surfaces as exit 65 (the same code as the equivalent empty-intersection
# diagnostic).
#
# Valid neighbouring forms must keep working, so the controls below cover
# equal bounds, single values, MIN..MAX, ordered SIZE and FROM ranges, and
# the multi-character FROM set. That last one is represented as a set of
# singleton elements whose parent edges are deliberately inverted
# (left = max, right = min), which is why the emptiness check is restricted
# to el_count == 0.
#
# An abort is the failure this test exists for, so a timeout (exit 124) or a
# death by signal (exit 128+) is reported separately from an ordinary error
# exit. `timeout` or `gtimeout` is required: skipping without it would hide
# the bug.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${ASN1C:-${top_builddir}/asn1c/asn1c}"

TIMEOUT_CMD=
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=gtimeout
else
    echo "FAIL: neither 'timeout' nor 'gtimeout' is available for this test"
    exit 1
fi

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

failures=0

# Purpose: Write the one-type ASN.1 schema used by a test case.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem; SCHEMA is the type expression.
# Returns: No value; writes NAME.asn1 beneath TMPDIR_TEST.
# Exceptions: A failed printf or write exits because the script uses set -e.
# Responsible party: asn1c test maintainers.
# History: Added with the reversed constraint range checks.
# Example: write_schema value-reversed 'INTEGER (5..1)'
# printf is used because FROM cases contain double quotes.
write_schema () {
    name=$1
    schema=$2

    printf 'M DEFINITIONS ::= BEGIN\nT ::= %s\nEND\n' "$schema" \
        > "$TMPDIR_TEST/$name.asn1"
}

# Purpose: Run asn1c on a generated schema with a ten-second time limit.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem for input and output files.
# Returns: No value; sets status to the selected timeout command's exit status.
# Exceptions: The caller handles non-zero status and timeout outcomes.
# Responsible party: asn1c test maintainers.
# History: Accepts either timeout or gtimeout for supported host platforms.
# Example: run_asn1c value-reversed
run_asn1c () {
    name=$1

    set +e
    "$TIMEOUT_CMD" 10 "$ASN1C" -E -F "$TMPDIR_TEST/$name.asn1" \
        >"$TMPDIR_TEST/$name.out" 2>"$TMPDIR_TEST/$name.err"
    status=$?
    set -e
}

# Purpose: Assert a reversed range fails with the expected diagnostic.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem; SCHEMA is the type expression.
# Returns: No value; increments failures when any assertion does not hold.
# Exceptions: Reports failure and continues with subsequent test cases.
# Responsible party: asn1c test maintainers.
# History: Checks exit 65, signal/timeout distinction, and empty range text.
# Example: check_invalid value-reversed 'INTEGER (5..1)'
check_invalid () {
    name=$1
    schema=$2

    write_schema "$name" "$schema"
    run_asn1c "$name"

    if [ "$status" -eq 124 ]; then
        echo "FAIL: $name ($schema): timed out after 10s (asn1c did not terminate)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif [ "$status" -ge 128 ]; then
        echo "FAIL: $name ($schema): died by signal (exit $status)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif [ "$status" -ne 65 ]; then
        echo "FAIL: $name ($schema): expected exit 65, got $status"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif ! grep -Eq 'Constraint range .* is empty' "$TMPDIR_TEST/$name.err"; then
        echo "FAIL: $name ($schema): missing 'Constraint range ... is empty'" \
             "diagnostic (exit $status)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    else
        echo "PASS: $name ($schema): exit 65 with the empty-range diagnostic"
    fi
}

# Purpose: Assert a valid neighboring range is accepted.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem; SCHEMA is the type expression.
# Returns: No value; increments failures when any assertion does not hold.
# Exceptions: Reports failure and continues with subsequent test cases.
# Responsible party: asn1c test maintainers.
# History: Keeps valid boundary forms covered with reversed range cases.
# Example: check_valid value-equal 'INTEGER (5..5)'
check_valid () {
    name=$1
    schema=$2

    write_schema "$name" "$schema"
    run_asn1c "$name"

    if [ "$status" -eq 124 ]; then
        echo "FAIL: $name ($schema): timed out after 10s (asn1c did not terminate)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif [ "$status" -ge 128 ]; then
        echo "FAIL: $name ($schema): died by signal (exit $status)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif [ "$status" -ne 0 ]; then
        echo "FAIL: $name ($schema): expected exit 0, got $status"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    else
        echo "PASS: $name ($schema)"
    fi
}

# Value and SIZE ranges whose lower bound exceeds the upper bound.
check_invalid value-reversed 'INTEGER (5..1)'
check_invalid value-zero-high 'INTEGER (1..0)'
check_invalid value-extensible 'INTEGER (5..1, ...)'

# A reversed interval nested inside a union or an extension addition list
# reaches the same construction point, so it must be rejected the same way.
check_invalid value-union 'INTEGER (0..10 | 5..1)'
check_invalid value-extension-add 'INTEGER (0..10, ..., 9..6)'

check_invalid size-reversed 'IA5String (SIZE (5..1))'
check_invalid size-zero-high 'IA5String (SIZE (1..0))'

# A single-character reversed FROM range: the alphabet becomes simple
# numeric edges (Z = 90, A = 65).
check_invalid from-reversed 'IA5String (FROM ("Z".."A"))'

# The same reversal inside a REAL WITH COMPONENTS clause reaches the inner
# range call; it must propagate the diagnostic instead of asserting.
check_invalid real-wcomps-reversed 'REAL (WITH COMPONENTS { mantissa (5..1) })'

# Controls: forms with non-reversed edges must keep working.
check_valid value-equal 'INTEGER (5..5)'
check_valid value-ordered 'INTEGER (0..1)'
check_valid value-min-max 'INTEGER (MIN..MAX)'
check_valid size-ordered 'IA5String (SIZE (1..5))'
check_valid from-ordered 'IA5String (FROM ("A".."Z"))'
check_valid from-multichar-set 'IA5String (FROM ("abc"))'
check_valid from-multichar-range 'IA5String (FROM ("AZ"))'

if [ "$failures" -ne 0 ]; then
    echo "$failures reversed-constraint-range check(s) failed"
    exit 1
fi

echo "PASS: reversed constraint ranges are diagnosed, ordered ranges accepted"
