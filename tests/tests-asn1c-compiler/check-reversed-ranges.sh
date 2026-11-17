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
# exit. A POSIX sleep/kill watchdog bounds the compiler run on every host;
# it is cancelled through a cancel file as well as a signal, because a
# signal delivered while the timer is being forked can be lost.

set -eu

if [ "${WATCHDOG_DEADLINE+x}" = x ]; then
    deadline=$WATCHDOG_DEADLINE
else
    deadline=10
fi

case "$deadline" in
    ''|*[!0-9]*|0|0*)
        echo "ERROR: WATCHDOG_DEADLINE must be a canonical decimal integer from 1 to 3600" >&2
        exit 2
        ;;
esac

if [ "${#deadline}" -gt 4 ] || [ "$deadline" -gt 3600 ]; then
    echo "ERROR: WATCHDOG_DEADLINE must be a canonical decimal integer from 1 to 3600" >&2
    exit 2
fi

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${ASN1C:-${top_builddir}/asn1c/asn1c}"

TMPDIR_TEST=$(mktemp -d)
# These state variables hold direct child PIDs for exit/signal cleanup.
active_compiler_pid=
active_watchdog_pid=
active_cancel=

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

    if [ -n "$active_cancel" ]; then
        : > "$active_cancel"
    fi

    if [ -n "$active_watchdog_pid" ]; then
        kill -TERM "$active_watchdog_pid" 2>/dev/null || :
        wait "$active_watchdog_pid" 2>/dev/null || :
        active_watchdog_pid=
        active_cancel=
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

# Purpose: Sleep for a bounded interval, cancel file and interruption aware.
# Original source: Added with the reversed range checks.
# Version/date: 2, 2026-11-16.
# Inputs: SECONDS is the requested delay; uses cancel_file, sleep_pid and the
#         interruption state of the calling watchdog.
# Returns: Zero when the full interval passes; non-zero when cancelled.
# Exceptions: Sleep and kill failures are tolerated during process races.
# Responsible party: asn1c test maintainers.
# History: Polls a cancel file so a lost cancel signal costs at most a second.
# Example: watchdog_sleep 10
watchdog_sleep () {
    seconds=$1
    while [ "$seconds" -gt 0 ]; do
        sleep 1 &
        sleep_pid=$!
        if [ -n "$watchdog_interrupted" ] || [ -f "$cancel_file" ]; then
            kill "$sleep_pid" 2>/dev/null || :
        fi
        wait "$sleep_pid" 2>/dev/null || :
        # A trapped signal can interrupt wait before the killed sleep is reaped.
        if [ -n "$watchdog_interrupted" ] || [ -f "$cancel_file" ]; then
            wait "$sleep_pid" 2>/dev/null || :
            sleep_pid=
            return 1
        fi
        sleep_pid=
        seconds=$((seconds - 1))
    done
    return 0
}

# Purpose: Enforce the deadline and stop the compiler if it expires.
# Original source: Added with the reversed range checks.
# Version/date: 2, 2026-11-16.
# Inputs: Compiler PID, marker path and cancel file path.
# Returns: No value; creates the marker on timeout and signals the compiler.
# Exceptions: Sleep and kill failures are tolerated during process races.
# Responsible party: asn1c test maintainers.
# History: Polls the cancel file and checks the compiler is still alive.
# Example: watchdog "$active_compiler_pid" "$timeout_marker" "$cancel" &
watchdog () {
    compiler_pid=$1
    marker=$2
    cancel_file=$3
    # The sleep PID is a state variable local to this watchdog subshell.
    sleep_pid=
    # This state variable defers timer cleanup until its launched PID is saved.
    watchdog_interrupted=
    trap 'watchdog_interrupted=1
          if [ -n "$sleep_pid" ]; then
              kill "$sleep_pid" 2>/dev/null || :
          fi' HUP INT TERM

    watchdog_sleep "$deadline" || exit 0

    # The compiler may have exited while a cancel was being delivered.
    kill -0 "$compiler_pid" 2>/dev/null || exit 0
    [ ! -f "$cancel_file" ] || exit 0
    : > "$marker"
    kill -TERM "$compiler_pid" 2>/dev/null || exit 0
    # Cancel-aware grace: if the compiler died on TERM, the parent cancels
    # the watchdog here and the KILL is skipped; if it ignored TERM, the
    # parent is still waiting, the grace completes, and the KILL runs.
    watchdog_sleep 2 || exit 0
    kill -KILL "$compiler_pid" 2>/dev/null || :
}

# Purpose: Run asn1c with a ten-second deadline and bounded TERM grace.
# Original source: Added with the reversed range checks.
# Version/date: 2, 2026-11-16.
# Inputs: NAME is the temporary filename stem for input and output files.
# Returns: No value; sets status to compiler status or 124 on a real
#          deadline (marker present, whatever the wait status).
# Exceptions: The caller handles non-zero status and timeout outcomes.
# Responsible party: asn1c test maintainers.
# History: Cancels through a file as well as a signal; keeps a normal
#          exit status when the compiler won the race.
# Example: run_asn1c value-reversed
run_asn1c () {
    name=$1
    timeout_marker="$TMPDIR_TEST/$name.timeout"
    cancel_file="$TMPDIR_TEST/$name.cancel"
    rm -f "$timeout_marker" "$cancel_file"
    active_cancel=$cancel_file

    # Defer signal exits until both child PIDs have been recorded for cleanup.
    # This state variable stores the signal's normal shell exit status.
    deferred_signal_status=
    trap 'deferred_signal_status=129' HUP
    trap 'deferred_signal_status=130' INT
    trap 'deferred_signal_status=143' TERM
    "$ASN1C" -E -F "$TMPDIR_TEST/$name.asn1" \
        >"$TMPDIR_TEST/$name.out" 2>"$TMPDIR_TEST/$name.err" &
    active_compiler_pid=$!
    watchdog "$active_compiler_pid" "$timeout_marker" "$cancel_file" &
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

    # Cancel and reap the watchdog, including whichever sleep it owns. The
    # file is written first so a signal lost during the watchdog's fork
    # window is still observed by its one-second poll.
    : > "$cancel_file"
    kill -TERM "$active_watchdog_pid" 2>/dev/null || :
    wait "$active_watchdog_pid" 2>/dev/null || :
    active_watchdog_pid=
    active_compiler_pid=
    active_cancel=
    # The watchdog rechecks cancellation and compiler liveness before marking
    # a timeout. These separate checks are best effort, not atomic; the marker
    # is authoritative once present, even if the compiler then exits normally.
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
        echo "FAIL: $name ($schema): timed out after ${deadline}s (asn1c did not terminate)"
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
        echo "FAIL: $name ($schema): timed out after ${deadline}s (asn1c did not terminate)"
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

# Purpose: Check watchdog deadlines and cleanup with controlled fake compilers.
# Original source: Added with the reversed range checks.
# Version/date: 1, 2026-11-16.
# Inputs: LABEL names the case; BODY is the fake compiler script; EXPECT is
#         its expected asn1c status; TIMEOUT optionally sets its deadline.
# Returns: No value; increments failures when status or child cleanup differs.
# Exceptions: File and command errors may exit because the script uses set -e.
# Responsible party: asn1c test maintainers.
# History: Covers prompt exit, hanging compilers and graceful or ignored TERM.
# Example: selftest_case prompt-exit 'exit 65' 65 10
selftest_case () {
    label=$1
    body=$2
    expect=$3
    timeout=${4:-3}
    fake="$TMPDIR_TEST/fake-$label.sh"
    child_pid_file="$TMPDIR_TEST/$label.child-pid"
    printf '#!/bin/sh\n%s\n' "$body" > "$fake"
    chmod +x "$fake"
    write_schema "$label" 'INTEGER'
    saved_asn1c=$ASN1C saved_deadline=$deadline
    ASN1C=$fake deadline=$timeout
    SELFTEST_CHILD_PID_FILE=$child_pid_file
    export SELFTEST_CHILD_PID_FILE
    run_asn1c "$label"
    ASN1C=$saved_asn1c deadline=$saved_deadline
    unset SELFTEST_CHILD_PID_FILE
    if [ "$status" -eq "$expect" ]; then
        echo "PASS: watchdog $label: status $status"
    else
        echo "FAIL: watchdog $label: expected $expect, got $status"
        failures=$((failures + 1))
    fi

    case "$label" in
        graceful-term-*)
            if [ ! -s "$child_pid_file" ]; then
                echo "FAIL: watchdog $label: child PID was not recorded"
                failures=$((failures + 1))
            else
                IFS= read -r child_pid < "$child_pid_file"
                if kill -0 "$child_pid" 2>/dev/null; then
                    echo "FAIL: watchdog $label: child $child_pid survived compiler exit"
                    failures=$((failures + 1))
                else
                    echo "PASS: watchdog $label: child process was reaped"
                fi
            fi
            ;;
    esac
}

# Purpose: Check malformed WATCHDOG_DEADLINE values fail before test setup.
# Original source: Added with PR610 watchdog hardening.
# Version/date: 1, 2026-11-16.
# Inputs: LABEL names the case; VALUE is the malformed environment value.
# Returns: No value; increments failures unless exit 2 includes the validation.
# Exceptions: File and command errors may exit because the script uses set -e.
# Responsible party: asn1c test maintainers.
# History: Covers invalid syntax, noncanonical numbers and out-of-range values.
# Example: selftest_deadline_input leading-zero 01
selftest_deadline_input () {
    label=$1
    value=$2
    output="$TMPDIR_TEST/deadline-$label.out"
    error="$TMPDIR_TEST/deadline-$label.err"

    if WATCHDOG_DEADLINE=$value sh "$0" > "$output" 2> "$error"; then
        status=0
    else
        status=$?
    fi

    if [ "$status" -eq 2 ] && grep -Fq \
        'WATCHDOG_DEADLINE must be a canonical decimal integer from 1 to 3600' "$error"; then
        echo "PASS: watchdog deadline $label rejected"
    else
        echo "FAIL: watchdog deadline $label: expected exit 2 and validation message, got $status"
        cat "$error" >&2
        failures=$((failures + 1))
    fi
}

selftest_deadline_input alphabetic abc
selftest_deadline_input empty ''
selftest_deadline_input plus-sign +1
selftest_deadline_input whitespace ' 1'
selftest_deadline_input decimal 1.5
selftest_deadline_input negative -1
selftest_deadline_input zero 0
selftest_deadline_input leading-zero 01
selftest_deadline_input above-limit 3601
selftest_deadline_input oversized 9999999999999999999999999999999999999999

selftest_case prompt-exit 'exit 65' 65 10
selftest_case hang-term 'exec sleep 30' 124
# These variables expand in the generated compiler, not the test runner.
# shellcheck disable=SC2016
selftest_case graceful-term-65 \
    '# child_pid and term_pending are state variables for deferred TERM cleanup.
child_pid=
term_pending=
trap "term_pending=1
if [ -n \"\$child_pid\" ]; then
    kill \"\$child_pid\" 2>/dev/null || :
    wait \"\$child_pid\" 2>/dev/null || :
    exit 65
fi" TERM HUP INT
sleep 30 &
child_pid=$!
printf "%s\n" "$child_pid" > "$SELFTEST_CHILD_PID_FILE"
if [ -n "$term_pending" ]; then
    kill "$child_pid" 2>/dev/null || :
    wait "$child_pid" 2>/dev/null || :
    exit 65
fi
wait "$child_pid"' 124
# These variables expand in the generated compiler, not the test runner.
# shellcheck disable=SC2016
selftest_case graceful-term-0 \
    '# child_pid and term_pending are state variables for deferred TERM cleanup.
child_pid=
term_pending=
trap "term_pending=1
if [ -n \"\$child_pid\" ]; then
    kill \"\$child_pid\" 2>/dev/null || :
    wait \"\$child_pid\" 2>/dev/null || :
    exit 0
fi" TERM HUP INT
sleep 30 &
child_pid=$!
printf "%s\n" "$child_pid" > "$SELFTEST_CHILD_PID_FILE"
if [ -n "$term_pending" ]; then
    kill "$child_pid" 2>/dev/null || :
    wait "$child_pid" 2>/dev/null || :
    exit 0
fi
wait "$child_pid"' 124
selftest_case ignore-term-kill \
    'trap "" TERM; exec sleep 30' 124

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
