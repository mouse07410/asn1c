#!/usr/bin/env bash
# Check strict/default generation and every codec policy boundary.
# Source: repository smoke harness; date: 2026-11-17; owner: asn1c maintainers.
# Inputs: top_srcdir/top_builddir, CC/MAKE/CFLAGS. Returns zero on success.
# Errors: any failed assertion or unexpected compiler status fails the test.
# History: --strict-mode regression driver. Example: make check TESTS=check-strict-mode.sh.
set -euo pipefail
source_root=$(cd "${top_srcdir:-../..}" && pwd)
build_root=$(cd "${top_builddir:-../..}" && pwd)
asn1c_bin="$build_root/asn1c/asn1c"
fixture="$source_root/tests/tests-asn1c-smoke/data/strict-mode"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-strict.XXXXXX")
trap 'status=$?; if ((status)); then tail -n 8 "$test_root"/*.log; fi;
    if [[ ${ASN1C_KEEP_STRICT_TEST_OUTPUT:-0} == 1 ]]; then echo "Retained $test_root";
    else rm -rf "$test_root"; fi' EXIT

# Both generation policies are compiled from separate copies of the runtime.
for policy in default strict; do
    extra=()
    if [[ $policy == strict ]]; then extra=(--strict-mode); fi
    mkdir "$test_root/$policy"
    "$asn1c_bin" "${extra[@]}" -S "$source_root/skeletons" \
        -D "$test_root/$policy" "$fixture.asn1" >"$test_root/$policy.log" 2>&1
    "${MAKE:-make}" -C "$test_root/$policy" -f converter-example.mk -j1 \
        CFLAGS="${CFLAGS:--O1 -g} -I." libasncodec.a >>"$test_root/$policy.log" 2>&1
    "${CC:-cc}" ${CFLAGS:--O1 -g} -I"$test_root/$policy" "$fixture.c" \
        "$test_root/$policy/libasncodec.a" -lm -o "$test_root/$policy/policy-test"
    "$test_root/$policy/policy-test"
done
