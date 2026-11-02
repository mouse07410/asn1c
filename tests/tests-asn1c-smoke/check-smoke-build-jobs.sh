#!/usr/bin/env bash

# Regression test for the serial generated-converter build in the smoke helper.
# Original source: added for this repository's smoke-test suite.
# Version: 2026-11-02.
# Inputs: none; uses temporary mock compiler and make executables.
# Output: exits zero when all 20 variants pass -j1 and make failures propagate.
# Errors: exits nonzero on an unexpected helper result, call count, or argument.
# Responsible party: asn1c maintainers.
# History: added to prevent generated smoke builds from amplifying resource use.
# Example: run from the smoke-test build directory with ./check-smoke-build-jobs.sh.

set -euo pipefail

# Resolve the helper before changing into the isolated temporary test directory.
script_dir=$(cd "$(dirname "$0")" && pwd)
smoke_helper="$script_dir/check-asn1c-smoke.sh"
tmp_parent=${TMPDIR:-/tmp}
tmp_dir=$(mktemp -d "${tmp_parent%/}/asn1c-smoke-build-jobs.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

# Keep helper cleanup and generated paths inside a private temporary directory.
mock_build="$tmp_dir/build"
mock_src="$tmp_dir/source"
mock_bin="$tmp_dir/bin"
work_dir="$tmp_dir/work"
make_log="$tmp_dir/make-invocations.log"
compiler_log="$tmp_dir/compiler-invocations.log"
mkdir -p "$mock_build/asn1c" "$mock_src/skeletons" "$mock_bin" "$work_dir"

# Record each compiler variant while succeeding so the helper reaches make.
cat > "$mock_build/asn1c/asn1c" <<'MOCK_COMPILER'
#!/usr/bin/env bash
set -euo pipefail
variant=""
for argument in "$@"; do
    case "$argument" in
        -no-gen-*|-fwide-types)
            if [ -n "$variant" ]; then
                variant="$variant $argument"
            else
                variant="$argument"
            fi
            ;;
    esac
done
printf '%s\n' "$variant" >> "$ASN1C_LOG"
exit 0
MOCK_COMPILER
chmod +x "$mock_build/asn1c/asn1c"

# The make stub records calls, rejects unbounded invocations, and can inject a
# controlled failure to verify that the helper's pipeline preserves the error.
cat > "$mock_bin/mock-make" <<'MOCK_MAKE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "$MAKE_LOG"

has_serial_jobs=no
for argument in "$@"; do
    if [ "$argument" = "-j1" ]; then
        has_serial_jobs=yes
    fi
done

if [ "$has_serial_jobs" != yes ]; then
    exit 91
fi

call_number=$(wc -l < "$MAKE_LOG")
if [ "$call_number" -eq "${MAKE_FAIL_AT:-0}" ]; then
    exit 23
fi
MOCK_MAKE
chmod +x "$mock_bin/mock-make"

# Run one type through ten flag sets and two native-type settings (20 builds).
# Use paths relative to the generated test directory so the helper's existing
# command construction also works when TMPDIR contains whitespace.
export MAKE="../../bin/mock-make"
export MAKE_LOG="$make_log"
export ASN1C_LOG="$compiler_log"
export MAKE_FAIL_AT=0
if (cd "$work_dir" && top_builddir=../build top_srcdir=../source \
        "$smoke_helper" INTEGER) > "$tmp_dir/success.log" 2>&1; then
    :
else
    cat "$tmp_dir/success.log"
    echo "smoke helper failed during the 20-variant serial-build check" >&2
    exit 1
fi

success_calls=$(wc -l < "$make_log")
if [ "$success_calls" -ne 20 ]; then
    echo "expected 20 generated make invocations, got $success_calls" >&2
    exit 1
fi

compiler_calls=$(wc -l < "$compiler_log")
if [ "$compiler_calls" -ne 20 ]; then
    echo "expected 20 compiler variants, got $compiler_calls" >&2
    exit 1
fi

# Require both native modes for each individual, combined, and empty flag set.
all_disabled="-no-gen-UPER -no-gen-APER -no-gen-OER -no-gen-XER"
all_disabled+=" -no-gen-JER -no-gen-BER -no-gen-print -no-gen-random-fill"
disabled_variants=(
    "-no-gen-UPER"
    "-no-gen-APER"
    "-no-gen-OER"
    "-no-gen-XER"
    "-no-gen-JER"
    "-no-gen-BER"
    "-no-gen-print"
    "-no-gen-random-fill"
    "$all_disabled"
    ""
)
for variant in "${disabled_variants[@]}"; do
    for native in "" "-fwide-types"; do
        expected_variant="$variant"
        if [ -n "$native" ]; then
            if [ -n "$expected_variant" ]; then
                expected_variant="$expected_variant $native"
            else
                expected_variant="$native"
            fi
        fi
        if ! grep -F -x -q -e "$expected_variant" "$compiler_log"; then
            echo "missing compiler variant: $expected_variant" >&2
            exit 1
        fi
    done
done

# The stub exits with status 23 on call seven; pipefail must make the helper fail.
: > "$make_log"
: > "$compiler_log"
export MAKE_FAIL_AT=7
failure_status=0
if (cd "$work_dir" && top_builddir=../build top_srcdir=../source \
        "$smoke_helper" INTEGER) > "$tmp_dir/failure.log" 2>&1; then
    cat "$tmp_dir/failure.log"
    echo "smoke helper masked the injected generated-make failure" >&2
    exit 1
else
    failure_status=$?
fi

if [ "$failure_status" -ne 23 ]; then
    cat "$tmp_dir/failure.log"
    echo "expected helper exit status 23, got $failure_status" >&2
    exit 1
fi

failure_calls=$(wc -l < "$make_log")
if [ "$failure_calls" -ne 7 ]; then
    echo "expected the injected failure on make call 7, got $failure_calls calls" >&2
    exit 1
fi

failure_compiler_calls=$(wc -l < "$compiler_log")
if [ "$failure_compiler_calls" -ne 7 ]; then
    echo "expected seven compiler variants before the failure, got " \
        "$failure_compiler_calls" >&2
    exit 1
fi

echo "OK: all 20 generated builds use -j1 and make failures propagate"
