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
# exit. A POSIX sleep/kill watchdog bounds the compiler run on every host.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${ASN1C:-${top_builddir}/asn1c/asn1c}"

TMPDIR_TEST=$(mktemp -d)
# These state variables hold direct child PIDs for exit/signal cleanup.
active_compiler_pid=
active_watchdog_pid=

# Purpose: Stop active test children and remove temporary files on exit.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: None; uses the active child PIDs and TMPDIR_TEST globals.
# Returns: No value; waits for tracked children to exit.
# Exceptions: Cleanup commands may fail; failures are ignored during cleanup.
# Responsible party: asn1c test maintainers.
# History: Ensures compiler and watchdog children do not outlive this script.
# Example: Called automatically by the EXIT and signal traps.
cleanup () {
    trap - EXIT HUP INT TERM

    if [ -n "$active_watchdog_pid" ]; then
        kill -TERM "$active_watchdog_pid" 2>/dev/null || :
        wait "$active_watchdog_pid" 2>/dev/null || :
        active_watchdog_pid=
    fi

    if [ -n "$active_compiler_pid" ]; then
        kill -TERM "$active_compiler_pid" 2>/dev/null || :
        sleep 2
        kill -KILL "$active_compiler_pid" 2>/dev/null || :
        wait "$active_compiler_pid" 2>/dev/null || :
        active_compiler_pid=
    fi

    rm -rf "$TMPDIR_TEST"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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

# Purpose: Sleep for a bounded watchdog interval and honor interruption.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: SECONDS is the requested delay; uses sleep_pid and interruption state.
# Returns: Zero when the interval completes; non-zero when interrupted.
# Exceptions: Sleep and kill failures are tolerated during process races.
# Responsible party: asn1c test maintainers.
# History: Saves the timer PID before acting on a deferred signal.
# Example: watchdog_sleep 10
watchdog_sleep () {
    seconds=$1
    sleep "$seconds" &
    sleep_pid=$!
    if [ -n "$watchdog_interrupted" ]; then
        kill "$sleep_pid" 2>/dev/null || :
    fi
    wait "$sleep_pid" 2>/dev/null || :
    # A trapped signal can interrupt wait before the killed sleep is reaped.
    if [ -n "$watchdog_interrupted" ]; then
        wait "$sleep_pid" 2>/dev/null || :
    fi
    sleep_pid=
    [ -z "$watchdog_interrupted" ]
}

# Purpose: Enforce the deadline and stop the compiler if it expires.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: Compiler PID and marker path.
# Returns: No value; creates the marker on timeout and signals the compiler.
# Exceptions: Sleep and kill failures are tolerated during process races.
# Responsible party: asn1c test maintainers.
# History: Cancels and reaps its timer on normal completion or interruption.
# Example: watchdog "$active_compiler_pid" "$timeout_marker" &
watchdog () {
    compiler_pid=$1
    marker=$2
    # The sleep PID is a state variable local to this watchdog subshell.
    sleep_pid=
    # This state variable defers timer cleanup until its launched PID is saved.
    watchdog_interrupted=
    trap 'watchdog_interrupted=1
          if [ -n "$sleep_pid" ]; then
              kill "$sleep_pid" 2>/dev/null || :
          fi' HUP INT TERM

    watchdog_sleep 10 || exit 0

    : > "$marker"
    kill -TERM "$compiler_pid" 2>/dev/null || exit 0
    watchdog_sleep 2 || exit 0
    kill -KILL "$compiler_pid" 2>/dev/null || :
}

# Purpose: Run asn1c with a ten-second deadline and bounded TERM grace.
# Original source: Added for ASN1-0088 reversed range regression coverage.
# Version/date: 1, 2026-11-16.
# Inputs: NAME is the temporary filename stem for input and output files.
# Returns: No value; sets status to compiler status or 124 on deadline.
# Exceptions: The caller handles non-zero status and timeout outcomes.
# Responsible party: asn1c test maintainers.
# History: Uses POSIX sleep and kill rather than an external timeout utility.
# Example: run_asn1c value-reversed
run_asn1c () {
    name=$1
    timeout_marker="$TMPDIR_TEST/$name.timeout"
    rm -f "$timeout_marker"

    # Defer signal exits until both child PIDs have been recorded for cleanup.
    # This state variable stores the signal's normal shell exit status.
    deferred_signal_status=
    trap 'deferred_signal_status=129' HUP
    trap 'deferred_signal_status=130' INT
    trap 'deferred_signal_status=143' TERM
    "$ASN1C" -E -F "$TMPDIR_TEST/$name.asn1" \
        >"$TMPDIR_TEST/$name.out" 2>"$TMPDIR_TEST/$name.err" &
    active_compiler_pid=$!
    watchdog "$active_compiler_pid" "$timeout_marker" &
    active_watchdog_pid=$!
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [ -n "$deferred_signal_status" ]; then
        exit "$deferred_signal_status"
    fi

    set +e
    wait "$active_compiler_pid"
    status=$?
    set -e

    # Cancel and reap the watchdog, including whichever sleep it owns.
    kill -TERM "$active_watchdog_pid" 2>/dev/null || :
    wait "$active_watchdog_pid" 2>/dev/null || :
    active_watchdog_pid=
    active_compiler_pid=
    if [ -f "$timeout_marker" ]; then
        status=124
    fi
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
