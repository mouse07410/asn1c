#!/usr/bin/env bash
# Verify strict policy across Rust's supported codec/type combinations.
# Source: generated-Rust harness; version/date: 2026-11-17; owner: asn1c.
# Inputs: top_srcdir/top_builddir, Cargo/Rust tools. Returns 77 without tools,
# otherwise zero on success. Errors: compiler, codec, and lint failures abort.
# History: strict flag regression. Example: make check TESTS=check-rust-strict-mode.sh.
set -euo pipefail
source_root=$(cd "${top_srcdir:-../..}" && pwd)
build_root=$(cd "${top_builddir:-../..}" && pwd)
asn1c_bin="$build_root/asn1c/asn1c"
if ! command -v cargo >/dev/null || ! command -v rustc >/dev/null; then exit 77; fi
test_root=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-rust-strict.XXXXXX")
trap 'rm -rf "$test_root"' EXIT
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-1}
export CARGO_TARGET_DIR="$test_root/target"
cat >"$test_root/scalar.asn1" <<'SCHEMA'
StrictScalar DEFINITIONS ::= BEGIN
N ::= INTEGER (0..2)
Wide ::= INTEGER (0..3)
END
SCHEMA
cat >"$test_root/xer.asn1" <<'SCHEMA'
StrictXer DEFINITIONS ::= BEGIN
Record ::= SEQUENCE { n INTEGER (0..2) }
END
SCHEMA

# Validation is already mandatory in the supported Rust slice, so both profiles
# must satisfy the same contract. Strict mode forbids explicit tolerance flags.
for policy in default strict; do
    extra=()
    if [[ $policy == strict ]]; then extra=(--strict-mode); fi
    "$asn1c_bin" --rust "${extra[@]}" -S "$source_root/skeletons" \
        -gen-UPER -gen-APER -gen-OER -gen-BER -gen-CER -gen-JER -gen-CBOR \
        -D "$test_root/$policy" "$test_root/scalar.asn1"
    if [[ $policy == strict ]]; then
        grep -q 'features = \["strict-mode"\]' "$test_root/$policy/Cargo.toml"
    fi
    mkdir "$test_root/$policy/tests"
    cp "$source_root/tests/tests-rust-compiler/strict_mode_conformance.rs" "$test_root/$policy/tests/"
    cargo test --offline --manifest-path "$test_root/$policy/Cargo.toml"
    cargo clippy --offline --manifest-path "$test_root/$policy/Cargo.toml" --all-targets --all-features \
        -- -W clippy::pedantic -W clippy::nursery -D warnings

done
"$asn1c_bin" --strict-mode --rust -S "$source_root/skeletons" \
    -no-gen-UPER -no-gen-CER -gen-XER -D "$test_root/xer" "$test_root/xer.asn1"
mkdir "$test_root/xer/tests"
cp "$source_root/tests/tests-rust-compiler/strict_mode_xer.rs" "$test_root/xer/tests/"
cargo test --offline --manifest-path "$test_root/xer/Cargo.toml"
cargo clippy --offline --manifest-path "$test_root/xer/Cargo.toml" --all-targets --all-features \
    -- -W clippy::pedantic -W clippy::nursery -D warnings

# Strict mode must not publish an unsupported PER string crate.
printf 'M DEFINITIONS ::= BEGIN T ::= UTF8String (SIZE(0..32)) END\n' >"$test_root/nkm.asn1"
status=0
"$asn1c_bin" --rust --strict-mode -gen-APER -no-gen-CER \
    -S "$source_root/skeletons" -D "$test_root/rejected" "$test_root/nkm.asn1" \
    >"$test_root/rejected.log" 2>&1 || status=$?
test "$status" != 0
test ! -e "$test_root/rejected"
grep -q 'does not support' "$test_root/rejected.log"
