#!/usr/bin/env bash
# Verify standards-policy conflicts and exact long-option parsing.
# Source: CLI policy contract; date: 2026-11-17; owner: asn1c maintainers.
# Inputs: top_srcdir/top_builddir. Returns zero on success; errors abort.
# History: extracted fast CLI regressions. Example: bash check-strict-mode-cli.sh.
set -euo pipefail
source_root=$(cd "${top_srcdir:-../..}" && pwd)
build_root=$(cd "${top_builddir:-../..}" && pwd)
asn1c_bin="$build_root/asn1c/asn1c"
fixture="$source_root/tests/tests-asn1c-smoke/data/strict-mode"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-strict-cli.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

# Conflicts fail before publishing output, independently of argument ordering.
for target in '' --rust; do
    for conflict in -fno-constraints -fbless-SIZE -ftolerant-utc-time --strict-mode; do
        for order in before after; do
            args=(--strict-mode "$conflict")
            if [[ $order == after ]]; then args=("$conflict" --strict-mode); fi
            status=0
            "$asn1c_bin" $target "${args[@]}" -D "$test_root/invalid" "$fixture.asn1" \
                >"$test_root/invalid.log" 2>&1 || status=$?
            test "$status" = 64
            test ! -e "$test_root/invalid"
        done
    done
done

# Switch operands and -- retain their existing meaning; malformed spellings fail.
for option in --strict-mode=yes --strict-mode-no; do
    status=0
    "$asn1c_bin" "$option" "$fixture.asn1" >"$test_root/invalid.log" 2>&1 || status=$?
    test "$status" = 64
done
"$asn1c_bin" -E -- "$fixture.asn1" >"$test_root/printed.asn1"
"$asn1c_bin" -E --strict-mode "$fixture.asn1" >"$test_root/strict-printed.asn1"
cmp "$test_root/printed.asn1" "$test_root/strict-printed.asn1"

# Exact switch-looking operands are not consumed as standalone policy options.
"$asn1c_bin" -D --strict-mode --strict-mode -E "$fixture.asn1" >"$test_root/operand.asn1"
cmp "$test_root/printed.asn1" "$test_root/operand.asn1"
"$asn1c_bin" -ED --strict-mode --strict-mode "$fixture.asn1" >"$test_root/cluster.asn1"
cmp "$test_root/printed.asn1" "$test_root/cluster.asn1"
cp "$fixture.asn1" "$test_root/--strict-mode"
(cd "$test_root" && "$asn1c_bin" -E -- --strict-mode >end-options.asn1)

# Nonstandard SIZE applicability remains available only outside strict policy.
printf 'M DEFINITIONS ::= BEGIN T ::= INTEGER (SIZE(1..2)) END\n' >"$test_root/nonstandard.asn1"
"$asn1c_bin" -E -F -fbless-SIZE "$test_root/nonstandard.asn1" >"$test_root/blessed.asn1"
status=0
"$asn1c_bin" -E -F --strict-mode "$test_root/nonstandard.asn1" \
    >"$test_root/rejected.log" 2>&1 || status=$?
test "$status" = 65
