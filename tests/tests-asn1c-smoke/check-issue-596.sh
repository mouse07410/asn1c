#!/usr/bin/env bash
#
# Purpose: verify strict and tolerant UTCTime behavior in generated converters.
# Original source: issue #596 strict-default and compatibility requirements.
# Version/date: 1.0, 2026-11-12.
# Inputs: configured asn1c, source/build roots, CC, and MAKE environment values.
# Returns: zero when both generated runtime modes accept/reject expected BER.
# Errors: generation, compilation, macro, or decode mismatches exit nonzero.
# Responsible party: asn1c maintainers.
# History: added CLI, generated configuration, and BER decode coverage.
# Example: make check TESTS=check-issue-596.sh

set -euo pipefail

source_root=$(cd "${abs_top_srcdir:-${top_srcdir:?top_srcdir is required}}" && pwd)
build_root=$(cd "${abs_top_builddir:-${top_builddir:?top_builddir is required}}" && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-596.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

asn1c="$build_root/asn1c/asn1c"
skeletons="$source_root/skeletons"
schema="$test_root/UTCTime.asn1"

# Purpose: generate and compile one converter with the requested policy.
# Original source: issue #596 C runtime configuration and CLI option.
# Version/date: 1.0, 2026-11-12.
# Parameters: output directory name; optional compiler arguments.
# Returns: zero after generation, macro verification, and converter build.
# Errors: reports generation or build output before returning failure.
# Responsible party: asn1c maintainers. History: added strict/tolerant modes.
# Example: build_mode tolerant -ftolerant-utc-time.
build_mode() {
    local mode=$1
    shift
    local output="$test_root/$mode"
    mkdir -p "$output"
    if ! "$asn1c" -S "$skeletons" -D "$output" -pdu=UTValue \
        -no-gen-CER -no-gen-XER -no-gen-JER -no-gen-OER -no-gen-CBOR \
        -no-gen-UPER -no-gen-APER "$@" "$schema" \
        >"$output/generate.log" 2>&1; then
        cat "$output/generate.log" >&2
        return 1
    fi
    if [[ $mode == tolerant ]]; then
        grep -F '#define ASN_ENABLE_TOLERANT_UTCTIME 1' \
            "$output/asn_config.h" >/dev/null
    elif grep -F 'ASN_ENABLE_TOLERANT_UTCTIME' \
        "$output/asn_config.h" >/dev/null; then
        echo 'FAIL: strict output enables tolerant UTCTime parsing' >&2
        return 1
    fi
    if ! "${MAKE:-make}" -C "$output" -f converter-example.mk \
        CC="${CC:-cc}" >"$output/build.log" 2>&1; then
        cat "$output/build.log" >&2
        return 1
    fi
}

# Purpose: require a converter invocation to accept or reject one BER vector.
# Original source: issue #596 calendar and offset regression vectors.
# Version/date: 1.0, 2026-11-12.
# Parameters: mode, vector filename, expected status, and optional -c check.
# Returns: zero when converter exit status matches the expectation.
# Errors: emits a diagnostic and returns failure for a status mismatch.
# Responsible party: asn1c maintainers. History: checks decode and -c paths.
# Example: expect_decode strict invalid-feb31 fail -c.
expect_decode() {
    local mode=$1
    local vector=$2
    local expectation=$3
    local check_constraints=${4:-}
    local converter="$test_root/$mode/converter-example"
    local -a check_args=()
    if [[ $check_constraints == -c ]]; then
        check_args=(-c)
    fi
    if [[ $expectation == pass ]]; then
        if ! "$converter" -iber "${check_args[@]}" -onull "$vector" \
            >"$test_root/$mode/decode.log" 2>&1; then
            cat "$test_root/$mode/decode.log" >&2
            echo "FAIL: $mode unexpectedly rejected $vector" >&2
            return 1
        fi
    elif "$converter" -iber "${check_args[@]}" -onull "$vector" \
        >"$test_root/$mode/decode.log" 2>&1; then
        echo "FAIL: $mode unexpectedly accepted $vector" >&2
        return 1
    fi
}

cat >"$schema" <<'EOF'
UTCTimeModule DEFINITIONS ::= BEGIN
UTValue ::= UTCTime
END
EOF

# Each BER vector uses universal tag 23 and a single UTCTime value.
printf '\027\015000229120000Z' >"$test_root/leap-day.ber"
printf '\027\015040231120000Z' >"$test_root/february-31.ber"
printf '\027\017040229120000+00' >"$test_root/short-offset.ber"
printf '\027\015260231120000Z' >"$test_root/legacy-february-31.ber"
printf '\027\015261312120000Z' >"$test_root/legacy-month-13.ber"

build_mode strict
build_mode strict-no-constraints -fno-constraints
build_mode tolerant -ftolerant-utc-time

expect_decode strict "$test_root/leap-day.ber" pass
expect_decode strict "$test_root/february-31.ber" fail
expect_decode strict "$test_root/february-31.ber" fail -c
expect_decode strict "$test_root/short-offset.ber" fail
expect_decode strict "$test_root/short-offset.ber" fail -c
expect_decode strict "$test_root/legacy-february-31.ber" fail
expect_decode strict "$test_root/legacy-february-31.ber" fail -c
expect_decode strict "$test_root/legacy-month-13.ber" fail
expect_decode strict "$test_root/legacy-month-13.ber" fail -c

expect_decode strict-no-constraints "$test_root/leap-day.ber" pass
expect_decode strict-no-constraints "$test_root/february-31.ber" fail

expect_decode tolerant "$test_root/leap-day.ber" pass
expect_decode tolerant "$test_root/february-31.ber" pass
expect_decode tolerant "$test_root/short-offset.ber" pass

# Legacy text output demonstrates date normalization and bad month handling.
"$test_root/tolerant/converter-example" -iber -otext \
    "$test_root/legacy-february-31.ber" >"$test_root/tolerant/february-31.txt" 2>&1
grep -F '2026-03-03' "$test_root/tolerant/february-31.txt" >/dev/null
"$test_root/tolerant/converter-example" -iber -otext \
    "$test_root/legacy-month-13.ber" >"$test_root/tolerant/month-13.txt" 2>&1
grep -F '<bad-value>' "$test_root/tolerant/month-13.txt" >/dev/null

echo 'issue #596 strict and tolerant UTCTime converter checks passed'
