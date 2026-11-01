#!/bin/sh

# Qualify private BOOLEAN packing against every affected codec and generated C.
# Inputs: top_srcdir/top_builddir select source and configured build trees.
# Returns: zero for conformance, 77 without Rust tools, otherwise nonzero.
# Errors: generation, validation, strict lint, or C comparison failures fail.
# Source: Rust backend conformance drivers. Version/date: 2026-11-01.
# Responsible party: asn1c maintainers. History: approved bitset representation.
# Example: make -C tests/tests-rust-compiler check TESTS=check-rust-bitsets.sh.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)
test_srcdir="$top_srcdir/tests/tests-rust-compiler"
asn1c_bin="$top_builddir/asn1c/asn1c"
skeletons="$top_srcdir/skeletons"
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo "SKIP: Cargo and rustc are required for BOOLEAN bitset tests"
    exit 77
fi

# Run tests and the exact strict lint policy for one generated crate.
# Input $1 is its directory; no return value. Failed commands abort the driver.
# Source: alias driver. Version/date: 2026-11-01; asn1c maintainers.
# History: reusable generated-crate check. Example: check_crate "$test_tmp/auto".
check_crate() {
    if ! (cargo test --offline --manifest-path "$1/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$1/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
        >"$1/check.log" 2>&1; then
        cat "$1/check.log"
        exit 1
    fi
}

# Check required/default/optional BOOLEANs, SET, and named/imported children.
set -- "$test_srcdir/BoolStorage.asn1" "$test_srcdir/BoolImportBase.asn1" \
    "$test_srcdir/BoolImportClient.asn1"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$test_tmp/storage" "$@"
mkdir "$test_tmp/storage/tests"
cp "$test_srcdir/bool_bitset_conformance.rs" "$test_tmp/storage/tests/"
check_crate "$test_tmp/storage"

# Private storage must not expose a way to set spare bits from another crate.
printf '%s\n' 'use asn1c_generated::bool_storage::Bool4;' \
    '#[test] fn private_bits() { let value = Bool4::new([false;4], (2,None)); let _ = value.__0; }' \
    >"$test_tmp/storage/tests/private_bits.rs"
if cargo check --offline --tests --manifest-path "$test_tmp/storage/Cargo.toml" \
    >"$test_tmp/private.log" 2>&1; then
    echo "FAIL: packed BOOLEAN bytes were publicly accessible"
    exit 1
fi
grep -F 'E0616' "$test_tmp/private.log" >/dev/null
rm "$test_tmp/storage/tests/private_bits.rs"

# Independent codec selection and reverse module order must remain lint-clean.
for codec in BER CER; do
    "$asn1c_bin" --rust -no-gen-BER -no-gen-CER -no-gen-UPER "-gen-$codec" \
        -S "$skeletons" -D "$test_tmp/storage-$codec" \
        "$test_srcdir/BoolImportClient.asn1" "$test_srcdir/BoolImportBase.asn1" \
        "$test_srcdir/BoolStorage.asn1"
    check_crate "$test_tmp/storage-$codec"
done

# Mixed-codec methods share one representation without changing wire order.
"$asn1c_bin" --rust -gen-UPER -gen-CBOR -gen-BER -gen-CER -S "$skeletons" \
    -D "$test_tmp/auto" "$test_srcdir/BoolAuto.asn1"
mkdir "$test_tmp/auto/tests"
cp "$test_srcdir/bool_auto_conformance.rs" "$test_tmp/auto/tests/"
check_crate "$test_tmp/auto"

# XER uses Option<bool> for DEFAULT while packing only required booleans.
"$asn1c_bin" --rust -gen-XER -no-gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/xer" "$test_srcdir/BoolXer.asn1"
mkdir "$test_tmp/xer/tests"
cp "$test_srcdir/bool_xer_conformance.rs" "$test_tmp/xer/tests/"
check_crate "$test_tmp/xer"

# Exercise all bytes of the maximum admitted UPER BOOLEAN record.
"$asn1c_bin" --rust -gen-UPER -no-gen-CER -no-gen-BER -S "$skeletons" \
    -D "$test_tmp/wide" "$test_srcdir/Bool64.asn1"
mkdir "$test_tmp/wide/tests"
cp "$test_srcdir/bool_wide_conformance.rs" "$test_tmp/wide/tests/"
check_crate "$test_tmp/wide"

# DEFAULT-only and wide mixed/OPTIONAL records keep compact, bounded cursor methods.
for fixture in BoolDefaultsOnly WideMixed WideOptional; do
    "$asn1c_bin" --rust -gen-UPER -no-gen-CER -no-gen-BER -S "$skeletons" \
        -D "$test_tmp/$fixture" "$test_srcdir/$fixture.asn1"
    mkdir "$test_tmp/$fixture/tests"
    case "$fixture" in
        BoolDefaultsOnly) oracle=bool_defaults_conformance.rs ;;
        WideMixed) oracle=bool_wide_mixed_conformance.rs ;;
        WideOptional) oracle=bool_wide_optional_conformance.rs ;;
    esac
    cp "$test_srcdir/$oracle" "$test_tmp/$fixture/tests/"
    check_crate "$test_tmp/$fixture"
done

# Nonpacked owned buffers move through the two-argument constructor unchanged.
"$asn1c_bin" --rust -gen-UPER -gen-BER -gen-CER -S "$skeletons" \
    -D "$test_tmp/owned" "$test_srcdir/BoolOwned.asn1"
mkdir "$test_tmp/owned/tests"
cp "$test_srcdir/bool_owned_conformance.rs" "$test_tmp/owned/tests/"
check_crate "$test_tmp/owned"

# Opaque ANY dispatch must also work when neighboring BOOLEANs are packed.
"$asn1c_bin" --rust -gen-UPER -no-gen-CER -no-gen-BER -S "$skeletons" \
    -D "$test_tmp/any" "$test_srcdir/BoolAny.asn1"
mkdir "$test_tmp/any/tests"
cp "$test_srcdir/bool_any_conformance.rs" "$test_tmp/any/tests/"
check_crate "$test_tmp/any"

# Maximum admitted identifiers must fit generated source lines and strict lint.
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$test_tmp/long" "$test_srcdir/BoolLongName.asn1"
if grep -En '.{121}' "$test_tmp/long"/src/*.rs; then
    echo "FAIL: packed BOOLEAN output exceeded 120 columns"
    exit 1
fi
mkdir "$test_tmp/long/tests"
cp "$test_srcdir/bool_long_conformance.rs" "$test_tmp/long/tests/"
check_crate "$test_tmp/long"

# Reject the first excessive count and identifier before publishing any crate.
for fixture in Bool65 BoolLongName81; do
    "$asn1c_bin" -E "$test_srcdir/$fixture.asn1" >"$test_tmp/$fixture-parse.log" 2>&1
    rejected="$test_tmp/rejected-$fixture"
    status=0 # Rejection status state variable distinguishes a diagnostic from a crash.
    "$asn1c_bin" --rust -gen-UPER -no-gen-CER -no-gen-BER -S "$skeletons" \
        -D "$rejected" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture-reject.log" 2>&1 || status=$?
    if [ "$status" -eq 0 ] || [ "$status" -ge 128 ]; then
        echo "FAIL: excessive BOOLEAN schema succeeded or crashed: $fixture"
        exit 1
    fi
    test ! -e "$rejected"
done

# Compare canonical bytes and decode semantics with independently generated C.
bitset_c="$test_tmp/storage-c"
mkdir "$bitset_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$bitset_c" "$test_srcdir/BoolStorage.asn1" \
    "$test_srcdir/BoolImportBase.asn1" "$test_srcdir/BoolImportClient.asn1" \
    >"$test_tmp/c-generate.log" 2>&1
bitset_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' "$bitset_c/Makefile.am.libasncodec")
rm -f "$bitset_c/converter-example.c" "$bitset_c/pdu_collection.c"
if ! cc $bitset_cflags -I"$bitset_c" "$bitset_c"/*.c "$test_srcdir/c_boolean_storage.c" \
    -lm -o "$test_tmp/storage-c-check" >"$test_tmp/c-build.log" 2>&1; then
    cat "$test_tmp/c-build.log"
    exit 1
fi
"$test_tmp/storage-c-check"

# Probe sanitizer capability independently; a supported sanitizer failure is fatal.
if printf 'int main(void) { return 0; }\n' | \
    cc -x c - -fsanitize=address,undefined -o "$test_tmp/sanitizer-probe" \
    >"$test_tmp/sanitizer-probe.log" 2>&1 && \
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    "$test_tmp/sanitizer-probe" >>"$test_tmp/sanitizer-probe.log" 2>&1; then
    if ! cc $bitset_cflags -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
        -I"$bitset_c" "$bitset_c"/*.c "$test_srcdir/c_boolean_storage.c" -lm \
        -o "$test_tmp/storage-c-sanitize" >"$test_tmp/c-sanitize-build.log" 2>&1; then
        cat "$test_tmp/c-sanitize-build.log"
        exit 1
    fi
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$test_tmp/storage-c-sanitize"
else
    echo "NOTE: ASan/UBSan unavailable; normal C BOOLEAN checks passed"
fi

echo "PASS: private Rust BOOLEAN bitsets, strict Clippy, and C conformance"
