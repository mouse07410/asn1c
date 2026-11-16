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
# The neighbouring values must keep working too, so the controls below cover
# 2^126 and ASN_INTEGER_MAX - 1.
#
# A hang is the failure this test exists for, so a timeout (exit 124) or a
# death by signal (exit 128+) is reported separately from an ordinary error
# exit. `timeout` is required: skipping without it would hide the bug.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${ASN1C:-${top_builddir}/asn1c/asn1c}"

if ! command -v timeout >/dev/null 2>&1; then
    echo "FAIL: the 'timeout' command is required by this test but not found"
    exit 1
fi

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

failures=0

# check_range NAME RANGE
#
# Writes a one-type schema constrained to RANGE and requires `-E -F` to exit 0
# within the timeout.
check_range () {
    name=$1
    range=$2

    cat > "$TMPDIR_TEST/$name.asn1" <<EOF
M DEFINITIONS ::= BEGIN
T ::= INTEGER ($range)
END
EOF

    set +e
    timeout 10 "$ASN1C" -E -F "$TMPDIR_TEST/$name.asn1" \
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

# ASN_INTEGER_MAX, ASN_INTEGER_MIN, and the mixed range between them.
check_range max '0..170141183460469231731687303715884105727'
check_range min '-170141183460469231731687303715884105728..0'
check_range neg1max '-1..170141183460469231731687303715884105727'

# Controls: neighbours that already worked must keep working.
check_range 2p126 '0..85070591730234615865843651857942052864'
check_range maxm1 '0..170141183460469231731687303715884105726'

if [ "$failures" -ne 0 ]; then
    echo "$failures constraint-boundary check(s) failed"
    exit 1
fi

echo "PASS: constraint ranges at the asn1c_integer_t limits are accepted"
