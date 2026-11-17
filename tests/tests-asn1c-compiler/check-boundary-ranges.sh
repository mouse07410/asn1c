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
# Example: cleanup runs automatically after the final test or a signal.
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

# Purpose: Sleep for a bounded interval while observing cancellation/signals.
# Original source: Adapted from tests/tests-asn1c-compiler/check-reversed-ranges.sh.
# Version/date: 1, 2026-11-17.
# Inputs: SECONDS is the requested delay; cancel_file, sleep_pid, and
#         watchdog_interrupted are local watchdog state.
# Returns: Zero when the interval ends; non-zero when cancellation is observed.
# Exceptions: Sleep and kill failures are tolerated during process races.
# Responsible party: asn1c test maintainers.
# History: Records and reaps each sleep child to prevent orphan sleeps.
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
        # Reap sleep if a trapped signal interrupted wait before it finished.
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

# Purpose: Enforce one command deadline and stop the command when it expires.
# Original source: Adapted from check-reversed-ranges.sh.
# Version/date: 2, 2026-11-17.
# Inputs: Command PID, seconds, marker path, and cancel file path.
# Returns: No value; marks a timeout and signals the command when overdue.
# Exceptions: Sleep and kill failures are tolerated during process races.
# Responsible party: asn1c test maintainers.
# History: Tracks and reaps its sleep child and observes cancel files.
# Example: watchdog "$command_pid" 10 "$marker" "$cancel" &
watchdog () {
    watched_pid=$1
    limit=$2
    timeout_marker=$3
    cancel_file=$4
    # The sleep PID is a state variable local to this watchdog process.
    sleep_pid=
    # This state variable defers sleep cleanup until its launched PID is saved.
    watchdog_interrupted=
    trap 'watchdog_interrupted=1
          if [ -n "$sleep_pid" ]; then
              kill "$sleep_pid" 2>/dev/null || :
          fi' HUP INT TERM

    watchdog_sleep "$limit" || exit 0

    # The command may have finished while cancellation was being delivered.
    kill -0 "$watched_pid" 2>/dev/null || exit 0
    [ ! -f "$cancel_file" ] || exit 0
    : > "$timeout_marker"
    kill -TERM "$watched_pid" 2>/dev/null || exit 0
    # A cancel during grace prevents a late KILL after a normal command exit.
    watchdog_sleep 2 || exit 0
    [ ! -f "$cancel_file" ] || exit 0
    # This PID check is best effort; exit and PID reuse cannot be checked
    # atomically with the subsequent signal.
    kill -0 "$watched_pid" 2>/dev/null || exit 0
    kill -KILL "$watched_pid" 2>/dev/null || :
}

# Purpose: Run a command with a wall-clock limit without GNU timeout.
# Original source: Adapted from tests/tests-randomized/check-bundles.sh and
#                  check-reversed-ranges.sh.
# Version/date: 2, 2026-11-17.
# Inputs: NAME is the marker stem; LIMIT is seconds; remaining arguments are
#         the command and its arguments.
# Returns: The command status, or 124 when the deadline marker was written.
# Exceptions: Signal exits are deferred until both direct child PIDs are saved.
# Note: Sleep and PID lifecycle checks are best effort; checking liveness and
#       signaling cannot be atomic, so PID reuse remains a narrow race.
# Responsible party: asn1c test maintainers.
# History: Defers signals until PID registration and tracks watchdog sleeps.
# Example: run_bounded case 10 "$ASN1C" -E -F case.asn1
run_bounded () {
    name=$1
    limit=$2
    shift 2
    marker="$TMPDIR_TEST/$name.timeout"
    cancel="$TMPDIR_TEST/$name.cancel"

    rm -f "$marker" "$cancel"
    # Defer signal exits until the compiler and watchdog PIDs are both saved.
    # This state variable records a signal received during child registration.
    deferred_signal_status=
    trap 'deferred_signal_status=129' HUP
    trap 'deferred_signal_status=130' INT
    trap 'deferred_signal_status=143' TERM
    "$@" &
    command_pid=$!
    watchdog "$command_pid" "$limit" "$marker" "$cancel" &
    timer_pid=$!
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [ -n "$deferred_signal_status" ]; then
        exit "$deferred_signal_status"
    fi

    if wait "$command_pid"; then
        status=0
    else
        status=$?
    fi
    # The cancel file covers a lost signal while the watchdog was starting.
    : > "$cancel"
    kill -TERM "$timer_pid" 2>/dev/null || :
    wait "$timer_pid" 2>/dev/null || :
    timer_pid=
    # Marker wins even if the command catches TERM and exits successfully.
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

# Purpose: Require PER range_bits and effective_bits emitted for an INTEGER.
# Original source: Added with the unsigned-span range width fix.
# Version/date: 2, 2026-11-17.
# Inputs: NAME is the temporary filename stem; RANGE is the INTEGER range
#         text; BITS is expected range_bits; EBITS is expected effective_bits.
# Returns: No value; increments failures when generation or the check fails.
# Exceptions: Reports a failure and continues with later cases.
# Responsible party: asn1c test maintainers.
# History: Pins both PER widths for boundary and finite ranges.
# Example: check_codegen full64 '-9223372036854775808..9223372036854775807' 64 -1
check_codegen () {
    name=$1
    range=$2
    bits=$3
    ebits=$4

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
        if line=$(grep -E "APC_CONSTRAINED,[[:space:]]*$bits,[[:space:]]*$ebits," \
                       "$TMPDIR_TEST/$name-out/T.c"); then
            echo "PASS: $name ($range): range_bits=$bits effective_bits=$ebits"
        else
            echo "FAIL: $name ($range): no expected PER constraint" \
                 "(APC_CONSTRAINED, $bits, $ebits) in T.c"
            failures=$((failures + 1))
        fi
    fi
}

# Purpose: Run a fake compiler and check watchdog status and child cleanup.
# Original source: Added with the boundary range checks.
# Version/date: 3, 2026-11-17.
# Inputs: LABEL names the case; BODY is the fake compiler script; EXPECT is
#         its expected status; TIMEOUT optionally overrides the deadline.
# Returns: No value; increments failures on status or child-reaping mismatch.
# Exceptions: Reports a failure and continues.
# Responsible party: asn1c test maintainers.
# History: Keeps prompt-exit, deadline, TERM and KILL paths covered in-tree.
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
    printf 'M DEFINITIONS ::= BEGIN\nT ::= INTEGER\nEND\n' \
        > "$TMPDIR_TEST/$label.asn1"
    saved_asn1c=$ASN1C saved_deadline=$deadline
    ASN1C=$fake deadline=$timeout
    SELFTEST_CHILD_PID_FILE=$child_pid_file
    export SELFTEST_CHILD_PID_FILE
    run_asn1c "$label" -E -F "$TMPDIR_TEST/$label.asn1"
    ASN1C=$saved_asn1c deadline=$saved_deadline
    unset SELFTEST_CHILD_PID_FILE
    if [ "$status" -eq "$expect" ]; then
        echo "PASS: watchdog $label: status $status"
    else
        echo "FAIL: watchdog $label: expected $expect, got $status"
        failures=$((failures + 1))
    fi

    case "$label" in
        graceful-term-*|ignore-term-kill)
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

# A deadline that expires is always a timeout, whatever the compiler then does.
selftest_case prompt-exit 'exit 65' 65 10
selftest_case hang 'exec sleep 30' 124
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
    'printf "%s\n" "$$" > "$SELFTEST_CHILD_PID_FILE"
trap "" TERM
exec sleep 30' 124

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

# Check both PER widths at the full signed and signed-maximum boundaries.
check_codegen full64 '-9223372036854775808..9223372036854775807' 64 -1

check_codegen max63 '0..9223372036854775807' 63 -1

# Finite value counts exercise fixed widths and the 16-bit alignment boundary.
check_codegen singleton '5..5' 0 0
check_codegen fixed16 '0..65535' 16 16
check_codegen variable17 '0..65536' 17 -1
check_codegen cross16 '65535..65536' 1 -1

if [ "$failures" -ne 0 ]; then
    echo "$failures constraint-boundary check(s) failed"
    exit 1
fi

echo "PASS: constraint ranges at the asn1c_integer_t limits are accepted"
