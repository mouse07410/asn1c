#!/bin/sh

# Constraint ranges at the asn1c_integer_t limits (ASN1-0085), asn1c side.
#
# The fixer adjusts exclusive range endpoints by one. Its guards compared
# against INTMAX_MIN/INTMAX_MAX, the 63-bit limits, while asn1c_integer_t is
# __int128 in this build, so at the real limits the adjustment was performed
# anyway: ASN_INTEGER_MAX + 1 (or ASN_INTEGER_MIN - 1) is signed overflow. In
# a production build the wrapped endpoint corrupts the range and the fixer
# then spins allocating namespaces until memory runs out, so the visible
# symptom is a hang, not a diagnostic.
#
# Invariant: for every range whose endpoint is ASN_INTEGER_MIN or
# ASN_INTEGER_MAX, `asn1c -E -F` (parse + fix + print) terminates normally.
# The neighbouring values must keep working too. Endpoints are selected from
# the configured integer width, and signed 64-bit bounds are always covered.
#
# A hang is the failure this test exists for, so a timeout (exit 124) or a
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

if [ ! -r "$top_builddir/config.h" ]; then
    echo "FAIL: cannot read configured feature header: $top_builddir/config.h"
    exit 1
fi

if grep -Eq '^#[[:space:]]*define[[:space:]]+HAVE_128_BIT_INT[[:space:]]+1' \
    "$top_builddir/config.h"; then
    ASN_INTEGER_MIN=-170141183460469231731687303715884105728
    ASN_INTEGER_MAX=170141183460469231731687303715884105727
    ASN_INTEGER_MAX_MINUS_ONE=170141183460469231731687303715884105726
    WIDTH_CONTROL=85070591730234615865843651857942052864
else
    ASN_INTEGER_MIN=-9223372036854775808
    ASN_INTEGER_MAX=9223372036854775807
    ASN_INTEGER_MAX_MINUS_ONE=9223372036854775806
    WIDTH_CONTROL=4611686018427387904
fi

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

failures=0

# Purpose: Require an INTEGER range to parse and fix without timeout or error.
# Original source: Added for ASN1-0085 boundary regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem; RANGE is the INTEGER range text.
# Returns: No value; increments failures when the compiler fails or times out.
# Exceptions: Reports a failure and continues with later cases.
# Responsible party: asn1c test maintainers.
# History: Verifies configured-width endpoint arithmetic and controls.
# Example: check_range signed64-full '-9223372036854775808..9223372036854775807'
check_range () {
    name=$1
    range=$2

    cat > "$TMPDIR_TEST/$name.asn1" <<EOF
M DEFINITIONS ::= BEGIN
T ::= INTEGER ($range)
END
EOF

    set +e
    "$TIMEOUT_CMD" 10 "$ASN1C" -E -F "$TMPDIR_TEST/$name.asn1" \
        >"$TMPDIR_TEST/$name.out" 2>"$TMPDIR_TEST/$name.err"
    status=$?
    set -e

    if [ "$status" -eq 124 ]; then
        echo "FAIL: $name ($range): timed out after 10s (fixer did not terminate)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif [ "$status" -ge 128 ]; then
        echo "FAIL: $name ($range): died by signal (exit $status)"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    elif [ "$status" -ne 0 ]; then
        echo "FAIL: $name ($range): expected exit 0, got $status"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    else
        echo "PASS: $name ($range)"
    fi
}

# Configured ASN_INTEGER endpoints, plus a mixed signed range.
check_range max "0..$ASN_INTEGER_MAX"
check_range min "$ASN_INTEGER_MIN..0"
check_range neg1max "-1..$ASN_INTEGER_MAX"

# Keep signed 64-bit boundaries covered even in 128-bit builds.
check_range signed64-full '-9223372036854775808..9223372036854775807'

# Width-specific neighbouring values that must remain valid.
check_range width-control "0..$WIDTH_CONTROL"
check_range maxm1 "0..$ASN_INTEGER_MAX_MINUS_ONE"

if [ "$failures" -ne 0 ]; then
    echo "$failures constraint-boundary check(s) failed"
    exit 1
fi

echo "PASS: constraint ranges at the asn1c_integer_t limits are accepted"
