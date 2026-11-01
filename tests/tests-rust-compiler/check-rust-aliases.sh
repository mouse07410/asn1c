#!/bin/sh

# Qualify transparent local INTEGER aliases against Rust and generated C.
# Inputs: top_srcdir/top_builddir identify source and configured build trees.
# Returns: zero for passed conformance, 77 without Rust tools, otherwise nonzero.
# Errors: compiler, codec, lint, or publication failures fail the test.
# Original source: named INTEGER backend conformance driver.
# Version/date: 2026-11-01. Responsible party: asn1c maintainers.
# History: transparent bounded INTEGER alias gate.
# Example: make -C tests/tests-rust-compiler check TESTS=check-rust-aliases.sh.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)
test_srcdir="$top_srcdir/tests/tests-rust-compiler"
asn1c_bin="$top_builddir/asn1c/asn1c"
skeletons="$top_srcdir/skeletons"
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo "SKIP: Cargo and rustc are required for generated Rust alias tests"
    exit 77
fi

# Keep identical direct/alias parent schemas in separate generated Rust modules.
set -- "$test_srcdir/AliasIntegerRecord.asn1" \
    "$test_srcdir/AliasIntegerIdentity.asn1" \
    "$test_srcdir/AliasIntegerStandalone.asn1" \
    "$test_srcdir/NamedIntegerRecord.asn1" "$test_srcdir/NamedIntegerAlias.asn1"
alias_out="$test_tmp/aliases"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$alias_out" "$@"
mkdir "$alias_out/tests"
sed 's/asn1c_generated::named_integer_record::/asn1c_generated::alias_integer_record::/' \
    "$test_srcdir/named_integer_record_conformance.rs" \
    >"$alias_out/tests/alias_integer_record_conformance.rs"
cp "$test_srcdir/alias_integer_identity_conformance.rs" "$alias_out/tests/"
alias_source="$alias_out/src/alias_integer_record.rs"
for expected in 'pub type Small = Base;' 'pub value: Small' 'Small::new(value)?'; do
    if ! grep -F "$expected" "$alias_source" >/dev/null; then
        echo "FAIL: generated alias source omitted $expected"
        exit 1
    fi
done
if ! (cargo test --offline --manifest-path "$alias_out/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$alias_out/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/aliases.log" 2>&1; then
    cat "$test_tmp/aliases.log"
    echo "FAIL: Rust alias conformance or strict Clippy"
    exit 1
fi

# Each codec selection must compile without publishing the unselected methods.
for codec in BER CER; do
    selected="$test_tmp/aliases-$codec"
    if [ "$codec" = BER ]; then
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$selected" "$@"
        unwanted='encode_cer|decode_cer'
    else
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$selected" "$@"
        unwanted='encode_der|decode_ber'
    fi
    if ! cargo clippy --offline --manifest-path "$selected/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings \
        >"$test_tmp/aliases-$codec.log" 2>&1; then
        cat "$test_tmp/aliases-$codec.log"
        echo "FAIL: alias $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($unwanted)" "$selected"/src/*.rs >/dev/null; then
        echo "FAIL: alias $codec-only output retained an unselected method"
        exit 1
    fi
done

# A syntax error or crash cannot count as unsupported-schema validation.
for fixture in "$test_srcdir"/AliasIntegerNegative*.asn1; do
    name=$(basename "$fixture" .asn1)
    "$asn1c_bin" -E "$fixture" >"$test_tmp/parsed-$name.log" 2>&1
    status=0 # Command result state variable, retained across the rejection check.
    "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$test_tmp/rejected-$name" "$fixture" \
        >"$test_tmp/rejected-$name.log" 2>&1 || status=$?
    if [ "$status" -eq 0 ] || [ "$status" -ge 128 ]; then
        cat "$test_tmp/rejected-$name.log"
        echo "FAIL: unsupported alias $name succeeded or crashed (status $status)"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$name"
done

# Unused aliases need their own codec gate even without a parent record.
for codec in UPER APER OER CBOR JER XER; do
    for pairing in alone mixed; do
        if [ "$pairing" = mixed ]; then
            set -- -gen-BER -gen-CER
        else
            set -- -no-gen-BER -no-gen-CER
        fi
        rejected="$test_tmp/rejected-$codec-$pairing"
        status=0
        "$asn1c_bin" --rust -no-gen-UPER "$@" "-gen-$codec" -S "$skeletons" \
            -D "$rejected" "$test_srcdir/AliasIntegerStandalone.asn1" \
            >"$test_tmp/rejected-$codec-$pairing.log" 2>&1 || status=$?
        if [ "$status" -eq 0 ] || [ "$status" -ge 128 ]; then
            echo "FAIL: unsupported alias codec selection $codec-$pairing succeeded or crashed"
            exit 1
        fi
        test ! -e "$rejected"
    done
done

# The unchanged named-INTEGER C harness checks the same thirteen value pairs.
alias_c="$test_tmp/aliases-c"
mkdir "$alias_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$alias_c" "$test_srcdir/AliasIntegerRecord.asn1" \
    "$test_srcdir/AliasIntegerIdentity.asn1" >"$test_tmp/aliases-c-generate.log" 2>&1
alias_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' "$alias_c/Makefile.am.libasncodec")
rm -f "$alias_c/converter-example.c" "$alias_c/pdu_collection.c"

# Probe toolchain support separately so actual sanitized fixture failures fail.
sanitizers_available=0 # Sanitizer capability state variable for both C fixtures.
if printf 'int main(void) { return 0; }\n' | \
    cc -x c - -fsanitize=address,undefined -o "$test_tmp/sanitizer-probe" \
    >"$test_tmp/sanitizer-probe.log" 2>&1 && \
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    "$test_tmp/sanitizer-probe" >>"$test_tmp/sanitizer-probe.log" 2>&1; then
    sanitizers_available=1
else
    echo "NOTE: this toolchain cannot run ASan/UBSan; normal C alias checks still run"
fi
for fixture in c_named_integer_record c_alias_integer_identity; do
    if ! cc $alias_cflags -I"$alias_c" "$alias_c"/*.c "$test_srcdir/$fixture.c" \
        -lm -o "$test_tmp/$fixture" >"$test_tmp/$fixture-build.log" 2>&1; then
        cat "$test_tmp/$fixture-build.log"
        echo "FAIL: alias C fixture $fixture did not compile"
        exit 1
    fi
    "$test_tmp/$fixture"
    if [ "$sanitizers_available" -eq 0 ]; then
        continue
    fi
    if ! cc $alias_cflags -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
        -I"$alias_c" "$alias_c"/*.c "$test_srcdir/$fixture.c" -lm \
        -o "$test_tmp/$fixture-sanitize" >"$test_tmp/$fixture-sanitize-build.log" 2>&1; then
        cat "$test_tmp/$fixture-sanitize-build.log"
        echo "FAIL: sanitized alias C fixture $fixture did not compile"
        exit 1
    fi
    ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
        "$test_tmp/$fixture-sanitize"
done

echo "PASS: transparent Rust INTEGER aliases and C conformance"
