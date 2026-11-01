#!/usr/bin/env bash
# Verify one explicit context tag around inline ENUMERATED in SEQUENCE and SET.
# Source: X.690 explicit tagging and CER framing. Version/date: 2026-11-01.
# Inputs: configured asn1c build, source skeletons, and C compiler. Returns: zero
# for exact DER/CER vectors and BER/CER round-trips. History: generator regression.
# Example: make -C tests/tests-asn1c-smoke check TESTS=check-explicit-enum-tags.sh
set -euo pipefail

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_source_dir=$(cd "$(dirname "$0")" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-explicit-enum.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

"$test_build_root/asn1c/asn1c" -S "$test_source_root/skeletons" \
    -D "$test_directory" -fcompound-names -no-gen-UPER -no-gen-APER -no-gen-OER \
    -no-gen-JER -no-gen-CBOR "$test_source_dir/data/explicit-enum-tags.asn1"
"${MAKE:-make}" -C "$test_directory" -f converter-example.mk \
    CC="${CC:-cc}" >/dev/null
"${CC:-cc}" -I"$test_directory" -o "$test_directory/test" \
    "$test_source_dir/data/explicit-enum-tags.c" \
    "$test_directory/libasncodec.a" -lm
"$test_directory/test"
