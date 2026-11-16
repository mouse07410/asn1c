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
# A code generation case additionally pins the PER range width emitted for the
# full signed 64-bit range.
#
# A hang is the failure this test exists for, so a timeout (exit 124) or a
# death by signal (exit 128+) is reported separately from an ordinary error
# exit. The deadline uses a portable sleep/kill watchdog, so neither GNU
# timeout nor gtimeout has to be installed.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${ASN1C:-${top_builddir}/asn1c/asn1c}"

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

# The watchdog deadline is fixed unless the caller overrides it, as the
# reversed-range watchdog does; validate it before creating temp files.
deadline=${WATCHDOG_DEADLINE-10}
case "$deadline" in
    ''|*[!0-9]*|0|0*)
        echo "FAIL: WATCHDOG_DEADLINE must be a canonical decimal integer" \
             "from 1 through 3600" >&2
        exit 2
        ;;
esac
# Bound the length before the numeric test so an oversized value cannot make
# the shell arithmetic error out instead of rejecting it.
if [ "${#deadline}" -gt 4 ] || [ "$deadline" -gt 3600 ]; then
    echo "FAIL: WATCHDOG_DEADLINE must be a canonical decimal integer" \
         "from 1 through 3600" >&2
    exit 2
fi

TMPDIR_TEST=$(mktemp -d)
# State variables for exit/signal cleanup.
command_pid=
timer_pid=
cancel=
marker=

# Purpose: Stop the command and timer and remove temporary files on exit.
# Original source: Added with the boundary range checks.
# Version/date: 2, 2026-11-17.
# Inputs: None; uses the active PIDs and the cancel/marker paths.
# Returns: No value; waits for tracked children to exit.
# Exceptions: Cleanup commands may fail; failures are ignored.
# Responsible party: asn1c test maintainers.
# History: An interrupted run no longer leaves the compiler or timer behind.
cleanup () {
    trap - EXIT HUP INT TERM

    if [ -n "$timer_pid" ]; then
        if [ -n "$cancel" ]; then
            : > "$cancel" 2>/dev/null || :
        fi
        kill -TERM "$timer_pid" 2>/dev/null || :
        wait "$timer_pid" 2>/dev/null || :
        timer_pid=
    fi

    if [ -n "$command_pid" ]; then
        kill -TERM "$command_pid" 2>/dev/null || :
        sleep 2
        kill -KILL "$command_pid" 2>/dev/null || :
        wait "$command_pid" 2>/dev/null || :
        command_pid=
    fi

    rm -rf "$TMPDIR_TEST"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

failures=0

# Purpose: Run a command with a wall-clock limit without GNU timeout.
# Original source: Adapted from tests/tests-randomized/check-bundles.sh.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the case name for the marker; LIMIT is seconds; the rest is
#         the command and its arguments.
# Returns: the command's status, or 124 when the deadline expired.
# Exceptions: none; the timer exits by itself if it cannot be cancelled.
# Note: this script must not install HUP/INT/TERM traps before forking the
#       timer; a trap inherited by the subshell can swallow the cancel.
#       A deadline is authoritative: the timer writes the marker only while
#       the command is still alive, and re-checks the cancel file first.
# Responsible party: asn1c test maintainers.
# History: Replaces a hard dependency on timeout/gtimeout, absent on macOS.
# Example: run_bounded case 10 "$ASN1C" -E -F case.asn1
run_bounded () {
    name=$1
    limit=$2
    shift 2
    marker="$TMPDIR_TEST/$name.timeout"
    cancel="$TMPDIR_TEST/$name.cancel"

    rm -f "$marker" "$cancel"
    "$@" &
    command_pid=$!
    (
        trap - HUP INT TERM
        remaining=$limit
        while [ "$remaining" -gt 0 ]; do
            sleep 1
            # A cancel may arrive while the timer is starting up.
            [ ! -f "$cancel" ] || exit 0
            remaining=$((remaining - 1))
        done
        # The command may have finished just before the timer was cancelled.
        kill -0 "$command_pid" 2>/dev/null || exit 0
        [ ! -f "$cancel" ] || exit 0
        : > "$marker"
        kill -TERM "$command_pid" 2>/dev/null || :
        sleep 2
        # Do not KILL a PID that may already have been reaped and reused.
        [ ! -f "$cancel" ] || exit 0
        kill -KILL "$command_pid" 2>/dev/null || :
    ) &
    timer_pid=$!

    wait "$command_pid" && status=0 || status=$?
    # Tell the timer the command finished, then stop it.
    : > "$cancel"
    kill -TERM "$timer_pid" 2>/dev/null || :
    wait "$timer_pid" 2>/dev/null || :
    timer_pid=
    # The marker is written only while the command is still running past the
    # deadline, so a deadline is a failure whatever status the command then
    # reports (it may catch TERM and exit 0).
    if [ -f "$marker" ]; then
        rm -f "$marker"
        marker=
        cancel=
        command_pid=
        return 124
    fi
    marker=
    cancel=
    command_pid=
    return "$status"
}

# Purpose: Run asn1c with the configured deadline and bounded TERM grace.
# Original source: Added with the range regression checks.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the case name; the rest is passed to asn1c.
# Returns: No value; sets status to the compiler status, or 124 on deadline.
# Exceptions: The caller handles non-zero status and timeout outcomes.
# Responsible party: asn1c test maintainers.
# History: Uses POSIX sleep and kill rather than an external timeout utility.
# Example: run_asn1c full64 -D out full64.asn1
run_asn1c () {
    name=$1
    shift
    set +e
    run_bounded "$name" "$deadline" "$ASN1C" "$@" \
        >"$TMPDIR_TEST/$name.out" 2>"$TMPDIR_TEST/$name.err"
    status=$?
    set -e
}

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

    run_asn1c "$name" -E -F "$TMPDIR_TEST/$name.asn1"

    if [ "$status" -eq 124 ]; then
        echo "FAIL: $name ($range): timed out after ${deadline}s (fixer did not terminate)"
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

# Purpose: Require the PER constraint emitted for an INTEGER range to have the
# expected width.
# Original source: Added with the unsigned-span range width fix.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem; RANGE is the INTEGER range
#         text; BITS is the expected PER range width.
# Returns: No value; increments failures when generation or the check fails.
# Exceptions: Reports a failure and continues with later cases.
# Responsible party: asn1c test maintainers.
# History: Pins range_bits for a range that spans the whole intmax_t type.
# Example: check_codegen full64 '-9223372036854775808..9223372036854775807' 64
check_codegen () {
    name=$1
    range=$2
    bits=$3

    cat > "$TMPDIR_TEST/$name.asn1" <<EOF
M DEFINITIONS ::= BEGIN
T ::= INTEGER ($range)
END
EOF

    mkdir "$TMPDIR_TEST/$name-out"

    run_asn1c "$name" -D "$TMPDIR_TEST/$name-out" \
        "$TMPDIR_TEST/$name.asn1"

    if [ "$status" -eq 124 ]; then
        echo "FAIL: $name ($range): timed out after ${deadline}s (compiler did not terminate)"
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
        if line=$(grep -E "APC_CONSTRAINED,[[:space:]]*$bits," \
                       "$TMPDIR_TEST/$name-out/T.c"); then
            echo "PASS: $name ($range): $line"
        else
            echo "FAIL: $name ($range): no expected PER constraint" \
                 "(APC_CONSTRAINED, $bits) in T.c"
            failures=$((failures + 1))
        fi
    fi
}

# Purpose: Run the watchdog against a generated fake compiler and check status.
# Original source: Added with the boundary range checks.
# Version/date: 2, 2026-11-17.
# Inputs: LABEL names the case; BODY is the fake compiler script; EXPECT is
#         the expected run_asn1c status.
# Returns: No value; increments failures on a status mismatch.
# Exceptions: Reports a failure and continues.
# Responsible party: asn1c test maintainers.
# History: Keeps the deadline, TERM and KILL paths covered in-tree.
# Example: selftest_case hang 'exec sleep 30' 124
selftest_case () {
    label=$1
    body=$2
    expect=$3
    fake="$TMPDIR_TEST/fake-$label.sh"
    printf '#!/bin/sh\n%s\n' "$body" > "$fake"
    chmod +x "$fake"
    printf 'M DEFINITIONS ::= BEGIN\nT ::= INTEGER\nEND\n' \
        > "$TMPDIR_TEST/$label.asn1"
    saved_asn1c=$ASN1C
    saved_deadline=$deadline
    ASN1C=$fake
    deadline=1
    run_asn1c "$label" -E -F "$TMPDIR_TEST/$label.asn1"
    ASN1C=$saved_asn1c
    deadline=$saved_deadline
    if [ "$status" -eq "$expect" ]; then
        echo "PASS: watchdog $label: status $status"
    else
        echo "FAIL: watchdog $label: expected $expect, got $status"
        failures=$((failures + 1))
    fi
}

# A deadline that expires is always a timeout, whatever the compiler then does.
selftest_case prompt-exit 'exit 65' 65
selftest_case hang 'exec sleep 30' 124
selftest_case graceful-term-0 'trap "exit 0" TERM; while :; do sleep 1; done' 124
selftest_case ignore-term-kill 'trap "" TERM; while :; do sleep 1; done' 124

# Invalid deadline overrides must fail before any temp file is created.
for bad_deadline in 05 0 "" 3601 99999999999999999999; do
    set +e
    top_srcdir="$top_srcdir" top_builddir="$top_builddir" \
        WATCHDOG_DEADLINE="$bad_deadline" sh "$0" >/dev/null 2>&1
    deadline_status=$?
    set -e
    if [ "$deadline_status" -eq 2 ]; then
        echo "PASS: watchdog invalid-deadline [$bad_deadline]: status 2"
    else
        echo "FAIL: watchdog invalid-deadline [$bad_deadline]:" \
             "expected 2, got $deadline_status"
        failures=$((failures + 1))
    fi
done

# Configured ASN_INTEGER endpoints, plus a mixed signed range.
check_range max "0..$ASN_INTEGER_MAX"
check_range min "$ASN_INTEGER_MIN..0"
check_range neg1max "-1..$ASN_INTEGER_MAX"

# Keep signed 64-bit boundaries covered even in 128-bit builds.
check_range signed64-full '-9223372036854775808..9223372036854775807'

# Width-specific neighbouring values that must remain valid.
check_range width-control "0..$WIDTH_CONTROL"
check_range maxm1 "0..$ASN_INTEGER_MAX_MINUS_ONE"

# Full signed 64-bit range: valid on every build, 64 PER range bits.
check_codegen full64 '-9223372036854775808..9223372036854775807' 64

# The other power-of-two boundary: 0..INTMAX_MAX is 63 bits.
check_codegen max63 '0..9223372036854775807' 63

if [ "$failures" -ne 0 ]; then
    echo "$failures constraint-boundary check(s) failed"
    exit 1
fi

echo "PASS: constraint ranges at the asn1c_integer_t limits are accepted"
