#!/bin/sh

# Run generated Rust conformance tests and live C comparison in isolated output.
# Original source: new asn1c Automake test. Version/date: 0.1.0, 2026-10-11.
# Responsible party: asn1c maintainers. History: initial Rust backend and CER slice.
# Example: make -C tests/tests-rust-compiler check.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)
test_srcdir="$top_srcdir/tests/tests-rust-compiler"
asn1c_bin="$top_builddir/asn1c/asn1c"
skeletons="$top_srcdir/skeletons"
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT HUP INT TERM

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    echo "SKIP: Cargo and rustc are required for generated Rust tests"
    exit 77
fi

if [ ! -x "$asn1c_bin" ]; then
    echo "FAIL: built compiler not found at $asn1c_bin"
    exit 1
fi

# Reject duplicate target selection and a Rust request with no codec selected.
if "$asn1c_bin" --rust --rust -S "$skeletons" \
    -D "$test_tmp/rejected-duplicate-rust" "$test_srcdir/FirstSlice.asn1" \
    >"$test_tmp/rejected-duplicate-rust.log" 2>&1; then
    echo "FAIL: compiler accepted duplicate --rust selectors"
    exit 1
fi
grep -F -- '--rust may be specified only once' \
    "$test_tmp/rejected-duplicate-rust.log" >/dev/null
test ! -e "$test_tmp/rejected-duplicate-rust"

if "$asn1c_bin" --rust -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-disabled-codecs" "$test_srcdir/FirstSlice.asn1" \
    >"$test_tmp/rejected-disabled-codecs.log" 2>&1; then
    echo "FAIL: compiler accepted --rust with all codecs disabled"
    exit 1
fi
grep -F 'select at least one supported codec' \
    "$test_tmp/rejected-disabled-codecs.log" >/dev/null
test ! -e "$test_tmp/rejected-disabled-codecs"

# Unsupported dynamic and contained types must fail before publishing a crate.
cat >"$test_tmp/Containing.asn1" <<'EOF'
Containing DEFINITIONS ::= BEGIN
Inner ::= INTEGER (0..2)
Outer ::= BIT STRING (CONTAINING Inner)
END
EOF
cat >"$test_tmp/Any.asn1" <<'EOF'
AnyModule DEFINITIONS ::= BEGIN
Value ::= ANY
Packet ::= SEQUENCE { flag BOOLEAN, payload ANY OPTIONAL }
Required ::= SEQUENCE { flag BOOLEAN, payload ANY }
END
EOF
cat >"$test_tmp/Open.asn1" <<'EOF'
OpenModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN
TESTCLASS ::= CLASS { &id INTEGER UNIQUE, &Extension }
    WITH SYNTAX { ID &id EXTENSION &Extension }
MyExtIEs TESTCLASS ::= { { ID 1 EXTENSION OCTET STRING (SIZE(3)) }, ... }
MyContainer ::= SEQUENCE {
    id TESTCLASS.&id({MyExtIEs}),
    extension TESTCLASS.&Extension({MyExtIEs}{@id})
}
END
EOF
for fixture in Open; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$rejected_out" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture" >&2
        exit 1
    fi
    grep -F 'Rust backend does not support' "$test_tmp/$fixture.log" >/dev/null
    test ! -e "$rejected_out"
done

# UPER CONTAINING supports direct local BOOLEAN and bounded INTEGER contents.
cat >"$test_tmp/ContainingSupported.asn1" <<'EOF'
Containing DEFINITIONS ::= BEGIN
Inner ::= INTEGER (0..2)
Bool ::= BOOLEAN
Oct ::= OCTET STRING (CONTAINING Inner)
Bits ::= BIT STRING (CONTAINING Inner)
BoolOct ::= OCTET STRING (CONTAINING Bool)
BoolBits ::= BIT STRING (CONTAINING BOOLEAN)
Packet ::= SEQUENCE { x BOOLEAN, i OCTET STRING (CONTAINING Inner) OPTIONAL, b BIT STRING (CONTAINING Bool) }
END
EOF
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/containing-rust" \
    "$test_tmp/ContainingSupported.asn1"
mkdir -p "$test_tmp/containing-rust/tests" "$test_tmp/containing-c"
cp "$test_srcdir/containing_conformance.rs" "$test_tmp/containing-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/containing-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/containing-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -no-gen-CER -S "$skeletons" -D "$test_tmp/containing-c" \
    "$test_tmp/ContainingSupported.asn1"
rm -f "$test_tmp/containing-c/converter-example.c" "$test_tmp/containing-c/pdu_collection.c"
cc -I"$test_tmp/containing-c" "$test_tmp/containing-c"/*.c "$test_srcdir/c_containing.c" \
    -lm -o "$test_tmp/c-containing"
"$test_tmp/c-containing"

# Reject unsupported contents shapes before publishing a Rust crate.
cat >"$test_tmp/ContainingSingleton.asn1" <<'EOF'
ContainingSingleton DEFINITIONS ::= BEGIN
Inner ::= INTEGER (1..1)
Outer ::= OCTET STRING (CONTAINING Inner)
END
EOF
cat >"$test_tmp/ContainingSized.asn1" <<'EOF'
ContainingSized DEFINITIONS ::= BEGIN
Inner ::= INTEGER (0..2)
Outer ::= OCTET STRING (SIZE(1)) (CONTAINING Inner)
END
EOF
for fixture in ContainingSingleton ContainingSized; do
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/rejected-$fixture" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture" >&2
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$fixture"
done
if "$asn1c_bin" --rust -gen-APER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-containing-aper" "$test_tmp/ContainingSupported.asn1" \
    >"$test_tmp/containing-aper.log" 2>&1; then
    echo "FAIL: Rust backend accepted unsupported APER CONTAINING" >&2
    exit 1
fi
test ! -e "$test_tmp/rejected-containing-aper"

# ANY preserves opaque bytes in a UPER envelope, including fragmented lengths.
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/any-rust" \
    "$test_tmp/Any.asn1"
mkdir -p "$test_tmp/any-rust/tests"
cp "$test_srcdir/any_conformance.rs" "$test_tmp/any-rust/tests/any_conformance.rs"
cargo test --offline --manifest-path "$test_tmp/any-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/any-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings

# Cross-check matching boundary vectors with generated C ANY codecs.
mkdir -p "$test_tmp/any-c"
"$asn1c_bin" -no-gen-CER -S "$skeletons" -D "$test_tmp/any-c" "$test_tmp/Any.asn1"
rm -f "$test_tmp/any-c/converter-example.c" "$test_tmp/any-c/pdu_collection.c"
cc -I"$test_tmp/any-c" "$test_tmp/any-c"/*.c "$test_srcdir/c_any.c" -lm -o "$test_tmp/c-any"
"$test_tmp/c-any"

# Standalone ANY supports APER, OER, and JER opaque framing as well.
cat >"$test_tmp/AnyAdditional.asn1" <<'EOF'
AnyModule DEFINITIONS ::= BEGIN
Value ::= ANY
END
EOF
"$asn1c_bin" --rust -gen-APER -gen-OER -gen-JER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$test_tmp/any-extra" "$test_tmp/AnyAdditional.asn1"
mkdir -p "$test_tmp/any-extra/tests" "$test_tmp/any-extra-c"
cp "$test_srcdir/any_additional.rs" "$test_tmp/any-extra/tests/"
cargo test --offline --manifest-path "$test_tmp/any-extra/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/any-extra/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-APER -gen-OER -gen-JER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/any-extra-c" "$test_tmp/AnyAdditional.asn1"
rm -f "$test_tmp/any-extra-c/converter-example.c" "$test_tmp/any-extra-c/pdu_collection.c"
cc -I"$test_tmp/any-extra-c" "$test_tmp/any-extra-c"/*.c "$test_srcdir/c_any_additional.c" \
    -lm -o "$test_tmp/c-any-additional"
"$test_tmp/c-any-additional"

# Nonextensible local IOC OPEN TYPE rows select bounded UPER primitives.
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/open-selected-rust" \
    "$test_srcdir/OpenSelected.asn1"
mkdir -p "$test_tmp/open-selected-rust/tests" "$test_tmp/open-selected-c"
cp "$test_srcdir/open_selected.rs" "$test_tmp/open-selected-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/open-selected-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/open-selected-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -no-gen-CER -S "$skeletons" -D "$test_tmp/open-selected-c" \
    "$test_srcdir/OpenSelected.asn1"
rm -f "$test_tmp/open-selected-c/converter-example.c" "$test_tmp/open-selected-c/pdu_collection.c"
cc -I"$test_tmp/open-selected-c" "$test_tmp/open-selected-c"/*.c "$test_srcdir/c_open_selected.c" \
    -lm -o "$test_tmp/c-open-selected"
"$test_tmp/c-open-selected"

# Extensible object sets and other codecs remain outside this slice.
sed 's/INTEGER (5..5) } }/INTEGER (5..5) }, ... }/' "$test_srcdir/OpenSelected.asn1" \
    >"$test_tmp/OpenExtensible.asn1"
if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/rejected-open-extensible" \
    "$test_tmp/OpenExtensible.asn1" >"$test_tmp/open-extensible.log" 2>&1; then
    echo "FAIL: Rust backend accepted extensible selected OPEN TYPE" >&2
    exit 1
fi
test ! -e "$test_tmp/rejected-open-extensible"
# APER/OER selected primitives have independently checked C wire vectors.
"$asn1c_bin" --rust -gen-APER -gen-OER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/open-selected-extra-rust" "$test_srcdir/OpenSelected.asn1"
mkdir -p "$test_tmp/open-selected-extra-rust/tests" "$test_tmp/open-selected-extra-c"
cp "$test_srcdir/open_selected_extra.rs" "$test_tmp/open-selected-extra-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/open-selected-extra-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/open-selected-extra-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-APER -gen-OER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/open-selected-extra-c" "$test_srcdir/OpenSelected.asn1"
rm -f "$test_tmp/open-selected-extra-c/converter-example.c" "$test_tmp/open-selected-extra-c/pdu_collection.c"
cc -I"$test_tmp/open-selected-extra-c" "$test_tmp/open-selected-extra-c"/*.c \
    "$test_srcdir/c_open_selected_extra.c" -lm -o "$test_tmp/c-open-selected-extra"
"$test_tmp/c-open-selected-extra"

# OER also supports multi-octet selector and selected INTEGER widths.
sed -e 's/INTEGER (0..255) UNIQUE/INTEGER (0..65535) UNIQUE/' \
    -e 's/INTEGER (0..2)/INTEGER (0..256)/' "$test_srcdir/OpenSelected.asn1" \
    >"$test_tmp/OpenOerWide.asn1"
"$asn1c_bin" --rust -gen-OER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/open-wide-rust" "$test_tmp/OpenOerWide.asn1"
mkdir -p "$test_tmp/open-wide-rust/tests" "$test_tmp/open-wide-c"
cp "$test_srcdir/open_selected_wide.rs" "$test_tmp/open-wide-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/open-wide-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/open-wide-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-OER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/open-wide-c" "$test_tmp/OpenOerWide.asn1"
rm -f "$test_tmp/open-wide-c/converter-example.c" "$test_tmp/open-wide-c/pdu_collection.c"
cc -I"$test_tmp/open-wide-c" "$test_tmp/open-wide-c"/*.c "$test_srcdir/c_open_selected_wide.c" \
    -lm -o "$test_tmp/c-open-selected-wide"
"$test_tmp/c-open-selected-wide"

# APER rejects bounds outside the proven aligned primitive subset.
sed 's/INTEGER (0..255) UNIQUE/INTEGER (0..256) UNIQUE/' "$test_srcdir/OpenSelected.asn1" \
    >"$test_tmp/OpenAperWideSelector.asn1"
sed 's/INTEGER (0..2)/INTEGER (0..256)/' "$test_srcdir/OpenSelected.asn1" \
    >"$test_tmp/OpenAperWideValue.asn1"
for fixture in OpenAperWideSelector OpenAperWideValue; do
    if "$asn1c_bin" --rust -gen-APER -no-gen-UPER -no-gen-CER -S "$skeletons" \
        -D "$test_tmp/rejected-$fixture" "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture" >&2
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$fixture"
done

# Reject unsupported relation shapes and selected types before publication.
sed 's/value CLASS1.\&Type({SET1}{@id})/value CLASS1.\&Type({SET1}{@id}) OPTIONAL/' \
    "$test_srcdir/OpenSelected.asn1" >"$test_tmp/OpenOptional.asn1"
sed 's/TYPE BOOLEAN/TYPE NULL/' "$test_srcdir/OpenSelected.asn1" >"$test_tmp/OpenNull.asn1"
sed 's/INTEGER (0..255) UNIQUE/INTEGER UNIQUE/' "$test_srcdir/OpenSelected.asn1" \
    >"$test_tmp/OpenUnbounded.asn1"
for fixture in OpenOptional OpenNull OpenUnbounded; do
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/rejected-$fixture" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture" >&2
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$fixture"
done

# An incomplete runtime beside explicit skeletons must fail before output.
missing_skeletons="$test_tmp/missing-runtime/skeletons"
missing_runtime="$missing_skeletons/rust/asn1c-runtime"
mkdir -p "$missing_runtime/src"
printf '%s\n' '[package]' >"$missing_runtime/Cargo.toml"
printf '%s\n' 'partial runtime fixture' >"$missing_runtime/README.md"
printf '%s\n' '// partial runtime fixture' >"$missing_runtime/src/lib.rs"
if "$asn1c_bin" --rust -S "$missing_skeletons" \
    -D "$test_tmp/rejected-missing-runtime" "$test_srcdir/FirstSlice.asn1" \
    >"$test_tmp/rejected-missing-runtime.log" 2>&1; then
    echo "FAIL: compiler accepted a runtime missing LICENSE"
    exit 1
fi
grep -F 'cannot find the Rust runtime' \
    "$test_tmp/rejected-missing-runtime.log" >/dev/null
test ! -e "$test_tmp/rejected-missing-runtime"

# Generate and compare twice before Cargo creates any build-owned files.
rust_out="$test_tmp/generated-rust"
"$asn1c_bin" --rust -S "$skeletons" -D "$rust_out" \
    "$test_srcdir/FirstSlice.asn1"
for generated in Cargo.toml src/lib.rs src/first_slice.rs runtime/Cargo.toml \
    runtime/LICENSE runtime/src/lib.rs runtime/src/big_integer.rs runtime/src/cbor.rs \
    runtime/src/jer.rs runtime/src/aper.rs \
    runtime/src/oer.rs \
    runtime/src/uper_cursor.rs; do
    if [ ! -f "$rust_out/$generated" ]; then
        echo "FAIL: generated Rust crate lacks $generated"
        exit 1
    fi
done
grep -F 'pub fn encode_cer' "$rust_out/src/first_slice.rs" >/dev/null
grep -F 'pub fn encode_uper' "$rust_out/src/first_slice.rs" >/dev/null
grep -F 'pub fn decode_cer' "$rust_out/src/first_slice.rs" >/dev/null
if grep -E 'pub fn (encode_der|decode_ber)' \
    "$rust_out/src/first_slice.rs" >/dev/null; then
    echo "FAIL: default Rust selection unexpectedly generated BER/DER methods"
    exit 1
fi
cp -R "$rust_out" "$test_tmp/first-generation"
"$asn1c_bin" --rust -S "$skeletons" -D "$rust_out" \
    "$test_srcdir/FirstSlice.asn1"
if ! diff -r "$rust_out" "$test_tmp/first-generation" >/dev/null; then
    echo "FAIL: Rust regeneration changed generated crate contents"
    exit 1
fi

# A user-owned sentinel must survive refusal of a nonempty destination.
mkdir "$test_tmp/protected-output"
printf '%s\n' 'user-owned sentinel' >"$test_tmp/expected-sentinel"
cp "$test_tmp/expected-sentinel" "$test_tmp/protected-output/README.txt"
if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/protected-output" \
    "$test_srcdir/FirstSlice.asn1" >"$test_tmp/protected.log" 2>&1; then
    echo "FAIL: generator accepted an unrelated file in its destination"
    exit 1
fi
cmp "$test_tmp/expected-sentinel" "$test_tmp/protected-output/README.txt"
if [ -e "$test_tmp/protected-output/Cargo.toml" ]; then
    echo "FAIL: refused generation wrote Cargo.toml over a protected destination"
    exit 1
fi

# A linked owned path is never followed or replaced during regeneration.
cp -R "$rust_out" "$test_tmp/symlink-output"
printf '%s\n' 'external symlink target' >"$test_tmp/external-sentinel"
cp "$test_tmp/external-sentinel" "$test_tmp/external-sentinel.expected"
rm "$test_tmp/symlink-output/src/lib.rs"
ln -s "$test_tmp/external-sentinel" "$test_tmp/symlink-output/src/lib.rs"
if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/symlink-output" \
    "$test_srcdir/FirstSlice.asn1" >"$test_tmp/symlink-output.log" 2>&1; then
    echo "FAIL: generator followed an interior symlink"
    exit 1
fi
test -L "$test_tmp/symlink-output/src/lib.rs"
if ! cmp "$test_tmp/external-sentinel.expected" "$test_tmp/external-sentinel"; then
    echo "FAIL: external symlink target changed"
    exit 1
fi

# A traversal manifest and an oversized manifest must leave prior files intact.
cp -R "$rust_out" "$test_tmp/traversal-output"
printf '%s\n' 'external traversal target' >"$test_tmp/outside"
printf '%s\n' '../outside' >"$test_tmp/traversal-output/.asn1c-rust-files"
if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/traversal-output" \
    "$test_srcdir/FirstSlice.asn1" >"$test_tmp/traversal-output.log" 2>&1; then
    echo "FAIL: generator accepted a traversal ownership manifest"
    exit 1
fi
grep -F '../outside' "$test_tmp/traversal-output/.asn1c-rust-files" >/dev/null
grep -F 'external traversal target' "$test_tmp/outside" >/dev/null
cmp "$rust_out/Cargo.toml" "$test_tmp/traversal-output/Cargo.toml"

cp -R "$rust_out" "$test_tmp/oversized-manifest-output"
awk 'BEGIN { for (i = 0; i < 100000; i++) print "src/lib.rs" }' \
    >"$test_tmp/oversized-manifest-output/.asn1c-rust-files"
if "$asn1c_bin" --rust -S "$skeletons" \
    -D "$test_tmp/oversized-manifest-output" "$test_srcdir/FirstSlice.asn1" \
    >"$test_tmp/oversized-manifest-output.log" 2>&1; then
    echo "FAIL: generator accepted an oversized ownership manifest"
    exit 1
fi
test "$(wc -l <"$test_tmp/oversized-manifest-output/.asn1c-rust-files")" -gt 4096
cmp "$rust_out/Cargo.toml" "$test_tmp/oversized-manifest-output/Cargo.toml"

# An explicit UPER selector is equivalent to Rust's default codec selection.
explicit_uper="$test_tmp/explicit-uper"
"$asn1c_bin" --rust -gen-UPER -S "$skeletons" -D "$explicit_uper" \
    "$test_srcdir/FirstSlice.asn1"
if [ ! -f "$explicit_uper/src/first_slice.rs" ]; then
    echo "FAIL: Rust backend rejected or omitted explicit UPER output"
    exit 1
fi
grep -F 'pub fn encode_uper' "$explicit_uper/src/first_slice.rs" >/dev/null
grep -F 'pub fn encode_cer' "$explicit_uper/src/first_slice.rs" >/dev/null

# CER-only selection emits CER encoders and decoders and omits every UPER method.
for selector in default explicit; do
    cer_out="$test_tmp/cer-only-$selector"
    if [ "$selector" = default ]; then
        "$asn1c_bin" --rust -no-gen-UPER -S "$skeletons" -D "$cer_out" \
            "$test_srcdir/FirstSlice.asn1"
    else
        "$asn1c_bin" --rust -gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$cer_out" "$test_srcdir/FirstSlice.asn1"
    fi
    generated_module="$cer_out/src/first_slice.rs"
    grep -F 'pub fn encode_cer' "$generated_module" >/dev/null
    if grep -E 'pub fn (encode|decode)_uper' "$generated_module" >/dev/null; then
        echo "FAIL: CER-only selection generated UPER methods"
        exit 1
    fi
    grep -F 'pub fn decode_cer' "$generated_module" >/dev/null
    if ! (cd "$cer_out" && \
        CARGO_TARGET_DIR="$test_tmp/cer-cargo-target-$selector" \
        cargo check --offline --manifest-path Cargo.toml) \
        >"$test_tmp/cer-cargo-check-$selector.log" 2>&1; then
        cat "$test_tmp/cer-cargo-check-$selector.log"
        echo "FAIL: generated CER-only Rust crate did not compile"
        exit 1
    fi
done

# Disabling BER removes its paired DER/BER methods and leaves CER selected.
cer_without_ber="$test_tmp/cer-without-ber"
"$asn1c_bin" --rust -no-gen-BER -no-gen-UPER -S "$skeletons" \
    -D "$cer_without_ber" "$test_srcdir/FirstSlice.asn1"
grep -F 'pub fn encode_cer' "$cer_without_ber/src/first_slice.rs" >/dev/null
if grep -E 'pub fn (encode_der|decode_ber)' \
    "$cer_without_ber/src/first_slice.rs" >/dev/null; then
    echo "FAIL: -no-gen-BER retained generated BER/DER methods"
    exit 1
fi
if grep -E 'pub fn (encode|decode)_uper' \
    "$cer_without_ber/src/first_slice.rs" >/dev/null; then
    echo "FAIL: disabled UPER remained in the generated codec mask"
    exit 1
fi

# BER-only selection emits the paired DER encoder and BER decoder per type.
ber_only="$test_tmp/ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$ber_only" "$test_srcdir/FirstSlice.asn1"
ber_module="$ber_only/src/first_slice.rs"
grep -F 'pub fn encode_der' "$ber_module" >/dev/null
grep -F 'pub fn decode_ber' "$ber_module" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|cer)' "$ber_module" >/dev/null; then
    echo "FAIL: BER-only selection generated UPER or CER methods"
    exit 1
fi
if ! (cd "$ber_only" && \
    CARGO_TARGET_DIR="$test_tmp/ber-only-cargo-target" \
    cargo check --offline --manifest-path Cargo.toml) \
    >"$test_tmp/ber-only-cargo-check.log" 2>&1; then
    cat "$test_tmp/ber-only-cargo-check.log"
    echo "FAIL: generated BER-only Rust crate did not compile"
    exit 1
fi

# CER-disabled Rust output keeps UPER methods and omits CER encoders.
uper_only="$test_tmp/uper-only"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$uper_only" \
    "$test_srcdir/FirstSlice.asn1"
grep -F 'pub fn encode_uper' "$uper_only/src/first_slice.rs" >/dev/null
if grep -F 'pub fn encode_cer' "$uper_only/src/first_slice.rs" >/dev/null; then
    echo "FAIL: -no-gen-CER retained generated CER methods"
    exit 1
fi
if grep -F 'pub fn decode_cer' "$uper_only/src/first_slice.rs" >/dev/null; then
    echo "FAIL: -no-gen-CER retained a generated CER decoder"
    exit 1
fi

# Flat SET and SEQUENCE basic XER encoders share formatting and defaults.
cat >"$test_tmp/XerSlice.asn1" <<'EOF'
XerSlice DEFINITIONS ::= BEGIN
S ::= SET { flag BOOLEAN DEFAULT TRUE, count INTEGER (0..5) DEFAULT 2,
            text IA5String OPTIONAL, ratio REAL DEFAULT 0.5 }
Q ::= SEQUENCE { flag BOOLEAN DEFAULT TRUE, count INTEGER (0..5) DEFAULT 2,
                 text IA5String OPTIONAL, ratio REAL DEFAULT 0.5 }
Empty ::= SEQUENCE { text IA5String OPTIONAL }
END
EOF
"$asn1c_bin" --rust -gen-XER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/xer-rust" "$test_tmp/XerSlice.asn1"
mkdir -p "$test_tmp/xer-rust/tests"
cp "$test_srcdir/xer_conformance.rs" "$test_tmp/xer-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/xer-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/xer-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings

# Compare both default and present REAL output against the C encoder.
mkdir -p "$test_tmp/xer-c"
"$asn1c_bin" -S "$skeletons" -D "$test_tmp/xer-c" "$test_tmp/XerSlice.asn1"
rm -f "$test_tmp/xer-c/converter-example.c" "$test_tmp/xer-c/pdu_collection.c"
cc -I"$test_tmp/xer-c" "$test_tmp/xer-c"/*.c "$test_srcdir/c_xer_record.c" \
    -lm -o "$test_tmp/c-xer-record"
"$test_tmp/c-xer-record"

# Automatic context tags put SET fields in declaration order, unlike the
# universal tag ordering of the untagged SET above.
sed 's/DEFINITIONS ::= BEGIN/DEFINITIONS AUTOMATIC TAGS ::= BEGIN/' \
    "$test_tmp/XerSlice.asn1" >"$test_tmp/XerAutomatic.asn1"
"$asn1c_bin" --rust -gen-XER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/xer-automatic" "$test_tmp/XerAutomatic.asn1"
mkdir -p "$test_tmp/xer-automatic/tests" "$test_tmp/xer-automatic-c"
cp "$test_srcdir/xer_conformance.rs" "$test_tmp/xer-automatic/tests/"
ASN1C_XER_AUTOMATIC=1 cargo test --offline --manifest-path "$test_tmp/xer-automatic/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/xer-automatic/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -no-gen-JER -S "$skeletons" -D "$test_tmp/xer-automatic-c" \
    "$test_tmp/XerAutomatic.asn1"
rm -f "$test_tmp/xer-automatic-c/converter-example.c" "$test_tmp/xer-automatic-c/pdu_collection.c"
cc -DXER_AUTOMATIC -I"$test_tmp/xer-automatic-c" "$test_tmp/xer-automatic-c"/*.c \
    "$test_srcdir/c_xer_record.c" -lm -o "$test_tmp/c-xer-automatic"
"$test_tmp/c-xer-automatic"

# REAL and mixed codec requests are rejected before publishing output.
cat >"$test_tmp/XerUnsupported.asn1" <<'EOF'
XerUnsupported DEFINITIONS ::= BEGIN
S ::= SET { ratio REAL DEFAULT 1.5 }
END
EOF
if "$asn1c_bin" --rust -gen-XER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-xer" "$test_tmp/XerUnsupported.asn1" \
    >"$test_tmp/rejected-xer.log" 2>&1; then
    echo "FAIL: Rust XER accepted unsupported REAL"
    exit 1
fi
grep -F 'unsupported flat XER record field or DEFAULT' \
    "$test_tmp/rejected-xer.log" >/dev/null
test ! -e "$test_tmp/rejected-xer"
cat >"$test_tmp/XerExplicit.asn1" <<'EOF'
XerExplicit DEFINITIONS AUTOMATIC TAGS ::= BEGIN
S ::= SET { flag [0] IMPLICIT BOOLEAN }
END
EOF
if "$asn1c_bin" --rust -gen-XER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-xer-explicit" "$test_tmp/XerExplicit.asn1" \
    >"$test_tmp/rejected-xer-explicit.log" 2>&1; then
    echo "FAIL: Rust XER accepted an explicitly tagged field"
    exit 1
fi
test ! -e "$test_tmp/rejected-xer-explicit"
if "$asn1c_bin" --rust -gen-XER -S "$skeletons" \
    -D "$test_tmp/rejected-xer-mixed" "$test_tmp/XerSlice.asn1" \
    >"$test_tmp/rejected-xer-mixed.log" 2>&1; then
    echo "FAIL: Rust XER accepted a mixed codec selection"
    exit 1
fi
test ! -e "$test_tmp/rejected-xer-mixed"

# CBOR directly encodes primitive values and opaque ANY octets.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-rust" "$test_srcdir/CborSlice.asn1"
mkdir -p "$test_tmp/cbor-rust/tests" "$test_tmp/cbor-c"
cp "$test_srcdir/cbor_conformance.rs" "$test_tmp/cbor-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-c" "$test_srcdir/CborSlice.asn1"
rm -f "$test_tmp/cbor-c/converter-example.c" "$test_tmp/cbor-c/pdu_collection.c"
cc -I"$test_tmp/cbor-c" "$test_tmp/cbor-c"/*.c "$test_srcdir/c_cbor.c" -lm -o "$test_tmp/c-cbor"
"$test_tmp/c-cbor"

# CBOR SEQUENCE maps cover direct primitives, OPTIONAL ANY, and DEFAULT fields.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-sequence-rust" "$test_srcdir/CborSequence.asn1"
mkdir -p "$test_tmp/cbor-sequence-rust/tests" "$test_tmp/cbor-sequence-c"
cp "$test_srcdir/cbor_sequence.rs" "$test_tmp/cbor-sequence-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-sequence-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-sequence-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-sequence-c" \
    "$test_srcdir/CborSequence.asn1"
rm -f "$test_tmp/cbor-sequence-c/converter-example.c" \
    "$test_tmp/cbor-sequence-c/pdu_collection.c"
cc -I"$test_tmp/cbor-sequence-c" "$test_tmp/cbor-sequence-c"/*.c \
    "$test_srcdir/c_cbor_sequence.c" -lm -o "$test_tmp/c-cbor-sequence"
"$test_tmp/c-cbor-sequence"

# Direct fixed and bounded CBOR strings preserve C's byte-string mapping.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-strings-rust" "$test_srcdir/CborStrings.asn1"
mkdir -p "$test_tmp/cbor-strings-rust/tests" "$test_tmp/cbor-strings-c"
cp "$test_srcdir/cbor_strings.rs" "$test_tmp/cbor-strings-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-strings-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-strings-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-strings-c" \
    "$test_srcdir/CborStrings.asn1"
rm -f "$test_tmp/cbor-strings-c/converter-example.c" \
    "$test_tmp/cbor-strings-c/pdu_collection.c"
cc -I"$test_tmp/cbor-strings-c" "$test_tmp/cbor-strings-c"/*.c \
    "$test_srcdir/c_cbor_strings.c" -lm -o "$test_tmp/c-cbor-strings"
"$test_tmp/c-cbor-strings"

# Flat CBOR SEQUENCE fields include direct fixed/bounded BIT/OCTET STRING.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-sequence-strings-rust" "$test_srcdir/CborSequenceStrings.asn1"
mkdir -p "$test_tmp/cbor-sequence-strings-rust/tests" "$test_tmp/cbor-sequence-strings-c"
cp "$test_srcdir/cbor_sequence_strings.rs" "$test_tmp/cbor-sequence-strings-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-sequence-strings-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-sequence-strings-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-sequence-strings-c" \
    "$test_srcdir/CborSequenceStrings.asn1"
rm -f "$test_tmp/cbor-sequence-strings-c/converter-example.c" \
    "$test_tmp/cbor-sequence-strings-c/pdu_collection.c"
cc -I"$test_tmp/cbor-sequence-strings-c" "$test_tmp/cbor-sequence-strings-c"/*.c \
    "$test_srcdir/c_cbor_sequence_strings.c" -lm -o "$test_tmp/c-cbor-sequence-strings"
"$test_tmp/c-cbor-sequence-strings"

# Direct CBOR CHOICE alternatives use the C one-entry text-key map.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-choice-rust" "$test_srcdir/CborChoice.asn1"
mkdir -p "$test_tmp/cbor-choice-rust/tests" "$test_tmp/cbor-choice-c"
cp "$test_srcdir/cbor_choice.rs" "$test_tmp/cbor-choice-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-choice-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-choice-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-choice-c" \
    "$test_srcdir/CborChoice.asn1"
rm -f "$test_tmp/cbor-choice-c/converter-example.c" \
    "$test_tmp/cbor-choice-c/pdu_collection.c"
cc -I"$test_tmp/cbor-choice-c" "$test_tmp/cbor-choice-c"/*.c \
    "$test_srcdir/c_cbor_choice.c" -lm -o "$test_tmp/c-cbor-choice"
"$test_tmp/c-cbor-choice"

# Direct primitive CHOICE uses a typed Rust enum and the selected primitive TLV.
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$test_tmp/primitive-choice-rust" "$test_srcdir/PrimitiveChoice.asn1"
mkdir -p "$test_tmp/primitive-choice-rust/tests" "$test_tmp/primitive-choice-c"
cp "$test_srcdir/choice_conformance.rs" "$test_tmp/primitive-choice-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/primitive-choice-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/primitive-choice-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$test_tmp/primitive-choice-c" "$test_srcdir/PrimitiveChoice.asn1"
rm -f "$test_tmp/primitive-choice-c/converter-example.c" \
    "$test_tmp/primitive-choice-c/pdu_collection.c"
cc -I"$test_tmp/primitive-choice-c" "$test_tmp/primitive-choice-c"/*.c \
    "$test_srcdir/c_primitive_choice.c" -lm -o "$test_tmp/c-primitive-choice"
"$test_tmp/c-primitive-choice"

# Single- and pair-alternative enums remain warning-free for codec-only output.
for fixture in ChoiceBooleanOnly ChoiceNullOnly ChoiceIntegerOnly ChoicePair; do
    for codec in BER CER; do
        choice_out="$test_tmp/choice-$fixture-$codec"
        if [ "$codec" = BER ]; then
            "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
                -D "$choice_out" "$test_srcdir/$fixture.asn1"
        else
            "$asn1c_bin" --rust -no-gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
                -D "$choice_out" "$test_srcdir/$fixture.asn1"
        fi
        cargo clippy --offline --manifest-path "$choice_out/Cargo.toml" \
            --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
    done
done

# Unsupported CHOICE shapes and mixed codecs fail before crate publication.
for fixture in ChoiceAlias ChoiceConstrainedBoolean ChoiceDefault ChoiceDuplicateTag \
    ChoiceExtension ChoiceIntegerExtension ChoiceIntegerUnion ChoiceMemberAlias \
    ChoiceNameCollision ChoiceNested ChoiceOptional ChoiceTaggedMember ChoiceTaggedRoot \
    ChoiceUnboundedInteger; do
    choice_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$choice_out" "$test_srcdir/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture CHOICE" >&2
        exit 1
    fi
    test ! -e "$choice_out"
done
choice_out="$test_tmp/rejected-ChoiceImport"
if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$choice_out" "$test_srcdir/ChoiceImport.asn1" \
    "$test_srcdir/ChoiceImportBase.asn1" >"$test_tmp/ChoiceImport.log" 2>&1; then
    echo "FAIL: Rust backend accepted imported CHOICE arm" >&2
    exit 1
fi
test ! -e "$choice_out"
for codec_mode in mixed uper; do
    choice_out="$test_tmp/rejected-choice-codecs-$codec_mode"
    if [ "$codec_mode" = mixed ]; then
        if "$asn1c_bin" --rust -gen-BER -gen-UPER -no-gen-CER -S "$skeletons" \
            -D "$choice_out" "$test_srcdir/PrimitiveChoice.asn1" \
            >"$test_tmp/choice-codecs.log" 2>&1; then
            echo "FAIL: Rust backend accepted mixed CHOICE codecs" >&2
            exit 1
        fi
    elif "$asn1c_bin" --rust -gen-UPER -no-gen-CER -S "$skeletons" \
        -D "$choice_out" "$test_srcdir/PrimitiveChoice.asn1" \
        >"$test_tmp/choice-codecs.log" 2>&1; then
        echo "FAIL: Rust backend accepted UPER-only CHOICE" >&2
        exit 1
    fi
    test ! -e "$choice_out"
done

# Typed local primitive CONTAINING uses inner CBOR bytes in an outer C-compatible string.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-containing-rust" "$test_srcdir/CborContaining.asn1"
mkdir -p "$test_tmp/cbor-containing-rust/tests" "$test_tmp/cbor-containing-c"
cp "$test_srcdir/cbor_containing.rs" "$test_tmp/cbor-containing-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-containing-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-containing-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-containing-c" \
    "$test_srcdir/CborContaining.asn1"
rm -f "$test_tmp/cbor-containing-c/converter-example.c" \
    "$test_tmp/cbor-containing-c/pdu_collection.c"
cc -I"$test_tmp/cbor-containing-c" "$test_tmp/cbor-containing-c"/*.c \
    "$test_srcdir/c_cbor_containing.c" -lm -o "$test_tmp/c-cbor-containing"
"$test_tmp/c-cbor-containing"

# The narrow IOC-selected OPEN TYPE uses direct selected CBOR map values.
"$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/cbor-open-rust" "$test_srcdir/OpenSelected.asn1"
mkdir -p "$test_tmp/cbor-open-rust/tests" "$test_tmp/cbor-open-c"
cp "$test_srcdir/cbor_open_selected.rs" "$test_tmp/cbor-open-rust/tests/"
cargo test --offline --manifest-path "$test_tmp/cbor-open-rust/Cargo.toml"
cargo clippy --offline --manifest-path "$test_tmp/cbor-open-rust/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings
"$asn1c_bin" -gen-CBOR -S "$skeletons" -D "$test_tmp/cbor-open-c" \
    "$test_srcdir/OpenSelected.asn1"
rm -f "$test_tmp/cbor-open-c/converter-example.c" "$test_tmp/cbor-open-c/pdu_collection.c"
cc -I"$test_tmp/cbor-open-c" "$test_tmp/cbor-open-c"/*.c \
    "$test_srcdir/c_cbor_open_selected.c" -lm -o "$test_tmp/c-cbor-open"
"$test_tmp/c-cbor-open"

# Nested records and SEQUENCE CONTAINING stay unsupported.
for fixture in "$test_srcdir/SequenceNested.asn1" \
    "$test_tmp/ContainingSupported.asn1"; do
    rejected_out="$test_tmp/rejected-cbor-$(basename "$fixture" .asn1)"
    if "$asn1c_bin" --rust -gen-CBOR -no-gen-UPER -no-gen-CER -S "$skeletons" \
        -D "$rejected_out" "$fixture" >"$test_tmp/rejected-cbor.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported CBOR $(basename "$fixture")" >&2
        exit 1
    fi
    test ! -e "$rejected_out"
done

# JER is an opt-in primitive codec; its generated methods build without PER or CER.
jer_out="$test_tmp/primitive-jer"
"$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$jer_out" "$test_srcdir/FirstSlice.asn1"
grep -F 'pub fn encode_jer' "$jer_out/src/first_slice.rs" >/dev/null
grep -F 'pub fn decode_jer' "$jer_out/src/first_slice.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|cer)' \
    "$jer_out/src/first_slice.rs" >/dev/null; then
    echo "FAIL: JER-only selection generated UPER or CER methods"
    exit 1
fi
mkdir "$jer_out/tests"
cp "$test_srcdir/jer_conformance.rs" "$jer_out/tests/jer_conformance.rs"
if ! (cd "$jer_out" && CARGO_TARGET_DIR="$test_tmp/target-jer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-jer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-jer.log" 2>&1; then
    cat "$test_tmp/check-jer.log"
    echo "FAIL: generated JER primitive vectors or strict Clippy"
    exit 1
fi
if "$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$test_tmp/rejected-jer-sequence" \
    "$test_srcdir/SequenceSlice.asn1" \
    >"$test_tmp/rejected-jer-sequence.log" 2>&1; then
    echo "FAIL: JER-only selection accepted a SEQUENCE without a JER codec"
    exit 1
fi
test ! -e "$test_tmp/rejected-jer-sequence"

# OCTET STRING JER supports the fixed-size direct subset; BIT STRING and other
# selected codecs remain rejected before the output crate is published.
if "$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$test_tmp/rejected-jer-bit-string" \
    "$test_srcdir/BitJERUnsupported.asn1" \
    >"$test_tmp/rejected-jer-bit-string.log" 2>&1; then
    echo "FAIL: JER-only Rust selection accepted BIT STRING"
    exit 1
fi
test ! -e "$test_tmp/rejected-jer-bit-string"
for unsupported in ExtensibleString VariableBitsExtensible VariableBitsUnion \
    VariableBitsOversize OversizeBits NamedBitString; do
    if "$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
        -S "$skeletons" -D "$test_tmp/rejected-jer-$unsupported" \
        "$test_srcdir/$unsupported.asn1" \
        >"$test_tmp/rejected-jer-$unsupported.log" 2>&1; then
        echo "FAIL: JER-only Rust selection accepted unsupported BIT STRING $unsupported"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-jer-$unsupported"
done
if "$asn1c_bin" --rust -gen-JER -gen-OER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$test_tmp/rejected-octet-jer-oer" \
    "$test_srcdir/OctetJER.asn1" >"$test_tmp/rejected-octet-jer-oer.log" 2>&1; then
    echo "FAIL: Rust accepted unsupported OCTET STRING JER/OER selection"
    exit 1
fi
test ! -e "$test_tmp/rejected-octet-jer-oer"
for unsupported in VariableUnion VariableOversize ExtensibleOctets; do
    if "$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
        -S "$skeletons" -D "$test_tmp/rejected-bounded-octet-jer-$unsupported" \
        "$test_srcdir/$unsupported.asn1" \
        >"$test_tmp/rejected-bounded-octet-jer-$unsupported.log" 2>&1; then
        echo "FAIL: JER-only Rust selection accepted unsupported OCTET STRING $unsupported"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-bounded-octet-jer-$unsupported"
done

octet_both_out="$test_tmp/octet-uper-jer"
"$asn1c_bin" --rust -gen-JER -no-gen-CER -S "$skeletons" \
    -D "$octet_both_out" "$test_srcdir/OctetJER.asn1"
grep -F 'pub fn encode_uper' "$octet_both_out/src/octet_jer.rs" >/dev/null
grep -F 'pub fn decode_uper' "$octet_both_out/src/octet_jer.rs" >/dev/null
grep -F 'pub fn encode_jer' "$octet_both_out/src/octet_jer.rs" >/dev/null
grep -F 'pub fn decode_jer' "$octet_both_out/src/octet_jer.rs" >/dev/null
if ! (cd "$octet_both_out" && CARGO_TARGET_DIR="$test_tmp/target-octet-both" \
    cargo check --offline --manifest-path Cargo.toml) \
    >"$test_tmp/check-octet-both.log" 2>&1; then
    cat "$test_tmp/check-octet-both.log"
    echo "FAIL: combined OCTET STRING UPER/JER crate did not compile"
    exit 1
fi

# Each newly available primitive family generates a standalone, offline crate.
for codec in APER OER; do
    codec_out="$test_tmp/primitive-$codec"
    "$asn1c_bin" --rust "-gen-$codec" -no-gen-UPER -no-gen-CER \
        -S "$skeletons" -D "$codec_out" "$test_srcdir/FirstSlice.asn1"
    codec_lower=$(printf '%s' "$codec" | tr '[:upper:]' '[:lower:]')
    grep -F "pub fn encode_$codec_lower" "$codec_out/src/first_slice.rs" >/dev/null
    grep -F "pub fn decode_$codec_lower" "$codec_out/src/first_slice.rs" >/dev/null
    if grep -E 'pub fn (encode|decode)_(uper|cer)' \
        "$codec_out/src/first_slice.rs" >/dev/null; then
        echo "FAIL: $codec-only selection generated UPER or CER methods"
        exit 1
    fi
    if ! (cd "$codec_out" && CARGO_TARGET_DIR="$test_tmp/target-$codec" \
        cargo check --offline --manifest-path Cargo.toml) \
        >"$test_tmp/check-$codec.log" 2>&1; then
        cat "$test_tmp/check-$codec.log"
        echo "FAIL: generated $codec-only Rust crate did not compile"
        exit 1
    fi
done

# The combined selection must expose both generated APIs and pass wire tests.
additional_out="$test_tmp/primitive-aper-oer"
"$asn1c_bin" --rust -gen-APER -gen-OER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$additional_out" "$test_srcdir/FirstSlice.asn1"
mkdir "$additional_out/tests"
cp "$test_srcdir/additional_codecs.rs" "$additional_out/tests/additional_codecs.rs"
if ! (cd "$additional_out" && CARGO_TARGET_DIR="$test_tmp/target-aper-oer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-aper-oer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-aper-oer.log" 2>&1; then
    cat "$test_tmp/check-aper-oer.log"
    echo "FAIL: generated APER/OER primitive vectors or strict Clippy"
    exit 1
fi

# Direct fixed strings and the unique-tag record now support the default mask.
string_default_out="$test_tmp/string-default"
"$asn1c_bin" --rust -S "$skeletons" -D "$string_default_out" \
    "$test_srcdir/StringSlice.asn1"
if ! (cd "$string_default_out" && \
    cargo check --offline --manifest-path Cargo.toml && \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/string-default-check.log" 2>&1; then
    cat "$test_tmp/string-default-check.log"
    echo "FAIL: generated default-mask string crate or strict Clippy"
    exit 1
fi
grep -F 'pub fn encode_cer' "$string_default_out/src/string_slice.rs" >/dev/null
for unsupported in ExtensibleString ExtensibleOctets VariableUnion VariableOversize \
    VariableBitsExtensible VariableBitsUnion VariableBitsOversize NamedBitString \
    OversizeOctets OversizeBits; do
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" \
        -D "$test_tmp/rejected-$unsupported" "$test_srcdir/$unsupported.asn1" \
        >"$test_tmp/rejected-$unsupported.log" 2>&1; then
        echo "FAIL: Rust accepted unsupported string form $unsupported"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$unsupported"
done
for codec_args in "-gen-OER -no-gen-CER"; do
    if "$asn1c_bin" --rust $codec_args -S "$skeletons" \
        -D "$test_tmp/rejected-variable-codecs" "$test_srcdir/VariableString.asn1" \
        >"$test_tmp/rejected-variable-codecs.log" 2>&1; then
        echo "FAIL: Rust accepted bounded OCTET STRING with unsupported codec selection"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-variable-codecs"
done
for codec_args in "-gen-OER -no-gen-CER"; do
    if "$asn1c_bin" --rust $codec_args -S "$skeletons" \
        -D "$test_tmp/rejected-variable-bit-codecs" \
        "$test_srcdir/VariableBitString.asn1" \
        >"$test_tmp/rejected-variable-bit-codecs.log" 2>&1; then
        echo "FAIL: Rust accepted bounded BIT STRING with non-UPER codecs"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-variable-bit-codecs"
done
boundary_out="$test_tmp/boundary-strings"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$boundary_out" \
    "$test_srcdir/BoundaryStrings.asn1"
mkdir "$boundary_out/tests"
cp "$test_srcdir/boundary_conformance.rs" "$boundary_out/tests/boundary_conformance.rs"
if ! (cd "$boundary_out" && CARGO_TARGET_DIR="$test_tmp/target-boundary" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-boundary" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-boundary.log" 2>&1; then
    cat "$test_tmp/check-boundary.log"
    echo "FAIL: maximum fixed-string boundary or strict Clippy"
    exit 1
fi
string_out="$test_tmp/string-uper"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$string_out" \
    "$test_srcdir/StringSlice.asn1"
mkdir "$string_out/tests"
cp "$test_srcdir/string_conformance.rs" "$string_out/tests/string_conformance.rs"
if ! (cd "$string_out" && CARGO_TARGET_DIR="$test_tmp/target-string" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-string" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-string.log" 2>&1; then
    cat "$test_tmp/check-string.log"
    echo "FAIL: generated fixed-size string tests or strict Clippy"
    exit 1
fi
# Compare fixed string and mixed-record vectors with separately generated C.
string_c_out="$test_tmp/string-c"
mkdir "$string_c_out"
"$asn1c_bin" -S "$skeletons" -gen-UPER -no-gen-XER -no-gen-JER \
    -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$string_c_out" "$test_srcdir/StringSlice.asn1" \
    >"$test_tmp/string-c-generate.log" 2>&1
string_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$string_c_out/Makefile.am.libasncodec")
if ! cc $string_cflags -I"$string_c_out" "$string_c_out"/*.c \
    "$test_srcdir/c_string.c" -lm -o "$test_tmp/c-string" \
    >"$test_tmp/c-string-compile.log" 2>&1; then
    cat "$test_tmp/c-string-compile.log"
    exit 1
fi
"$test_tmp/c-string"

# Bounded OCTET STRING UPER supports one contiguous nonextensible SIZE range.
variable_out="$test_tmp/variable-string-uper"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$variable_out" \
    "$test_srcdir/VariableString.asn1" "$test_srcdir/VariableSequence.asn1"
mkdir "$variable_out/tests"
cp "$test_srcdir/variable_string_conformance.rs" \
    "$variable_out/tests/variable_string_conformance.rs"
if ! (cd "$variable_out" && CARGO_TARGET_DIR="$test_tmp/target-variable-string" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-variable-string" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-variable-string.log" 2>&1; then
    cat "$test_tmp/check-variable-string.log"
    echo "FAIL: generated bounded OCTET STRING tests or strict Clippy"
    exit 1
fi
variable_c_out="$test_tmp/variable-string-c"
mkdir "$variable_c_out"
"$asn1c_bin" -S "$skeletons" -gen-UPER -no-gen-XER -no-gen-JER \
    -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$variable_c_out" "$test_srcdir/VariableString.asn1" \
    "$test_srcdir/VariableSequence.asn1" \
    >"$test_tmp/variable-string-c-generate.log" 2>&1
variable_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$variable_c_out/Makefile.am.libasncodec")
if ! cc $variable_cflags -I"$variable_c_out" "$variable_c_out"/*.c \
    "$test_srcdir/c_variable_string.c" -lm -o "$test_tmp/c-variable-string" \
    >"$test_tmp/c-variable-string-compile.log" 2>&1; then
    cat "$test_tmp/c-variable-string-compile.log"
    exit 1
fi
"$test_tmp/c-variable-string"

# Bounded BIT STRING UPER carries exact non-octet bit lengths in each value.
variable_bits_out="$test_tmp/variable-bit-string-uper"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$variable_bits_out" \
    "$test_srcdir/VariableBitString.asn1"
mkdir "$variable_bits_out/tests"
cp "$test_srcdir/variable_bit_string_conformance.rs" \
    "$variable_bits_out/tests/variable_bit_string_conformance.rs"
if ! (cd "$variable_bits_out" && CARGO_TARGET_DIR="$test_tmp/target-variable-bits" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-variable-bits" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-variable-bits.log" 2>&1; then
    cat "$test_tmp/check-variable-bits.log"
    echo "FAIL: generated bounded BIT STRING tests or strict Clippy"
    exit 1
fi
variable_bits_c_out="$test_tmp/variable-bit-string-c"
mkdir "$variable_bits_c_out"
"$asn1c_bin" -S "$skeletons" -gen-UPER -no-gen-XER -no-gen-JER \
    -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$variable_bits_c_out" \
    "$test_srcdir/VariableBitString.asn1" \
    >"$test_tmp/variable-bit-string-c-generate.log" 2>&1
variable_bits_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$variable_bits_c_out/Makefile.am.libasncodec")
if ! cc $variable_bits_cflags -I"$variable_bits_c_out" \
    "$variable_bits_c_out"/*.c "$test_srcdir/c_variable_bit_string.c" \
    -lm -o "$test_tmp/c-variable-bit-string" \
    >"$test_tmp/c-variable-bit-string-compile.log" 2>&1; then
    cat "$test_tmp/c-variable-bit-string-compile.log"
    exit 1
fi
"$test_tmp/c-variable-bit-string"

# Root ENUMERATED indexes follow numeric value order; extensions are gated.
if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-extensible-enum" "$test_srcdir/ExtensibleEnum.asn1" \
    >"$test_tmp/rejected-extensible-enum.log" 2>&1; then
    echo "FAIL: Rust accepted an extensible ENUMERATED"
    exit 1
fi
test ! -e "$test_tmp/rejected-extensible-enum"
enum_out="$test_tmp/enum-uper"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$enum_out" \
    "$test_srcdir/EnumSlice.asn1"
mkdir "$enum_out/tests"
cp "$test_srcdir/enum_conformance.rs" "$enum_out/tests/enum_conformance.rs"
if ! (cd "$enum_out" && CARGO_TARGET_DIR="$test_tmp/target-enum" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-enum" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-enum.log" 2>&1; then
    cat "$test_tmp/check-enum.log"
    echo "FAIL: generated ENUMERATED tests or strict Clippy"
    exit 1
fi

# ENUMERATED JER is opt-in and maps each root name to a complete JSON string.
enum_jer_out="$test_tmp/enum-jer"
"$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$enum_jer_out" "$test_srcdir/EnumSlice.asn1"
grep -F 'pub fn encode_jer' "$enum_jer_out/src/enum_slice.rs" >/dev/null
grep -F 'pub fn decode_jer' "$enum_jer_out/src/enum_slice.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|cer)' \
    "$enum_jer_out/src/enum_slice.rs" >/dev/null; then
    echo "FAIL: ENUMERATED JER-only selection generated UPER or CER methods"
    exit 1
fi
mkdir "$enum_jer_out/tests"
cp "$test_srcdir/enum_jer_conformance.rs" "$enum_jer_out/tests/enum_jer_conformance.rs"
if ! (cd "$enum_jer_out" && CARGO_TARGET_DIR="$test_tmp/target-enum-jer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-enum-jer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-enum-jer.log" 2>&1; then
    cat "$test_tmp/check-enum-jer.log"
    echo "FAIL: generated ENUMERATED JER tests or strict Clippy"
    exit 1
fi
enum_c_out="$test_tmp/enum-c"
mkdir "$enum_c_out"
"$asn1c_bin" -S "$skeletons" -gen-UPER -no-gen-XER -no-gen-JER \
    -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$enum_c_out" "$test_srcdir/EnumSlice.asn1" \
    >"$test_tmp/enum-c-generate.log" 2>&1
enum_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$enum_c_out/Makefile.am.libasncodec")
if ! cc $enum_cflags -I"$enum_c_out" "$enum_c_out"/*.c \
    "$test_srcdir/c_enum.c" -lm -o "$test_tmp/c-enum" \
    >"$test_tmp/c-enum-compile.log" 2>&1; then
    cat "$test_tmp/c-enum-compile.log"
    exit 1
fi
"$test_tmp/c-enum"

# This wider string SEQUENCE remains outside the current BER/CER record slice.
if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/rejected-sequence-default" \
    "$test_srcdir/SequenceSlice.asn1" >"$test_tmp/rejected-sequence-default.log" 2>&1; then
    echo "FAIL: default Rust codecs accepted an unsupported BER/CER SEQUENCE shape"
    exit 1
fi
test ! -e "$test_tmp/rejected-sequence-default"
if "$asn1c_bin" --rust -gen-OER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-sequence-oer" "$test_srcdir/SequenceSlice.asn1" \
    >"$test_tmp/rejected-sequence-oer.log" 2>&1; then
    echo "FAIL: Rust OER selection accepted a SEQUENCE without OER support"
    exit 1
fi
test ! -e "$test_tmp/rejected-sequence-oer"
sequence_out="$test_tmp/sequence-uper"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$sequence_out" \
    "$test_srcdir/SequenceSlice.asn1" "$test_srcdir/SequenceOptional.asn1" \
    "$test_srcdir/SequenceDefaults.asn1" "$test_srcdir/SequenceNested.asn1"
mkdir "$sequence_out/tests"
cp "$test_srcdir/sequence_conformance.rs" "$sequence_out/tests/sequence_conformance.rs"
cp "$test_srcdir/nested_conformance.rs" "$sequence_out/tests/nested_conformance.rs"
if ! (cd "$sequence_out" && CARGO_TARGET_DIR="$test_tmp/target-sequence" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-sequence" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-sequence.log" 2>&1; then
    cat "$test_tmp/check-sequence.log"
    echo "FAIL: generated UPER SEQUENCE or strict Clippy"
    exit 1
fi
# Compare the same complete vectors with separately generated C UPER code.
sequence_c_out="$test_tmp/sequence-c"
mkdir "$sequence_c_out"
"$asn1c_bin" -S "$skeletons" -gen-UPER -no-gen-XER -no-gen-JER \
    -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$sequence_c_out" "$test_srcdir/SequenceSlice.asn1" \
    "$test_srcdir/SequenceOptional.asn1" "$test_srcdir/SequenceDefaults.asn1" \
    "$test_srcdir/SequenceNested.asn1" \
    >"$test_tmp/sequence-c-generate.log" 2>&1
sequence_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$sequence_c_out/Makefile.am.libasncodec")
if ! cc $sequence_cflags -I"$sequence_c_out" "$sequence_c_out"/*.c \
    "$test_srcdir/c_sequence.c" -lm -o "$test_tmp/c-sequence" \
    >"$test_tmp/c-sequence-compile.log" 2>&1; then
    cat "$test_tmp/c-sequence-compile.log"
    exit 1
fi
"$test_tmp/c-sequence"
# Inline ENUMERATED fields use the same cursor and presence map as records.
enum_sequence_out="$test_tmp/sequence-enum"
"$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$enum_sequence_out" \
    "$test_srcdir/SequenceEnum.asn1"
mkdir "$enum_sequence_out/tests"
cp "$test_srcdir/sequence_enum_conformance.rs" "$enum_sequence_out/tests/"
(cd "$enum_sequence_out" && CARGO_TARGET_DIR="$test_tmp/target-sequence-enum" \
    cargo test --offline && cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings)
# Unsupported inline enum extensions and generated type collisions fail early.
cat >"$test_tmp/EnumExt.asn1" <<'EOF'
EnumExt DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { field ENUMERATED { one(1), ..., two(2) } OPTIONAL }
END
EOF
cat >"$test_tmp/EnumCollision.asn1" <<'EOF'
EnumCollision DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { field ENUMERATED { one(1) } OPTIONAL }
PacketField ::= BOOLEAN
END
EOF
for fixture in EnumExt EnumCollision; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$rejected_out" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture" >&2
        exit 1
    fi
    grep -F 'Rust backend does not support' "$test_tmp/$fixture.log" >/dev/null
    test ! -e "$rejected_out"
done
enum_sequence_c="$test_tmp/sequence-enum-c"
mkdir "$enum_sequence_c"
"$asn1c_bin" -S "$skeletons" -gen-UPER -no-gen-XER -no-gen-JER \
    -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -pdu=all -fgen-only-pdu-deps -no-gen-example \
    -D "$enum_sequence_c" "$test_srcdir/SequenceEnum.asn1" \
    >"$test_tmp/sequence-enum-c.log" 2>&1
enum_sequence_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$enum_sequence_c/Makefile.am.libasncodec")
cc $enum_sequence_cflags -I"$enum_sequence_c" "$enum_sequence_c"/*.c \
    "$test_srcdir/c_sequence_enum.c" -lm -o "$test_tmp/c-sequence-enum"
"$test_tmp/c-sequence-enum"
cat >"$test_tmp/SequenceTopTagged.asn1" <<'EOF'
SequenceTopTagged DEFINITIONS ::= BEGIN
TaggedPacket ::= [0] IMPLICIT BOOLEAN
END
EOF
for fixture in SequenceExtension; do
    rejected_out="$test_tmp/rejected-$fixture"
    fixture_path="$test_srcdir/$fixture.asn1"
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$rejected_out" \
        "$fixture_path" >"$test_tmp/rejected-$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture fields"
        exit 1
    fi
    grep -F 'SEQUENCE field' "$test_tmp/rejected-$fixture.log" >/dev/null
    test ! -e "$rejected_out"
done

# Nested constructed DEFAULTs and extensions remain outside the supported tree.
cat >"$test_tmp/NestedConstructedDefault.asn1" <<'EOF'
NestedConstructedDefault DEFINITIONS ::= BEGIN
Bad ::= SEQUENCE { inner SEQUENCE { flag BOOLEAN } DEFAULT {} }
END
EOF
cat >"$test_tmp/NestedExtension.asn1" <<'EOF'
NestedExtension DEFINITIONS ::= BEGIN
Bad ::= SEQUENCE { inner SEQUENCE { flag BOOLEAN, ... } }
END
EOF
for fixture in NestedConstructedDefault NestedExtension; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$rejected_out" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/rejected-$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done
if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-nested-name-collision" \
    "$test_srcdir/NestedNameCollision.asn1" \
    >"$test_tmp/rejected-nested-name-collision.log" 2>&1; then
    echo "FAIL: Rust backend accepted colliding nested type names"
    exit 1
fi
grep -F 'nested SEQUENCE type names collide' \
    "$test_tmp/rejected-nested-name-collision.log" >/dev/null
test ! -e "$test_tmp/rejected-nested-name-collision"

depth_body='flag BOOLEAN'
depth_level=0
while [ "$depth_level" -lt 17 ]; do
    depth_body="inner SEQUENCE { $depth_body }"
    depth_level=$((depth_level + 1))
done
{
    printf '%s\n' 'NestedDepth DEFINITIONS ::= BEGIN'
    printf 'Bad ::= SEQUENCE { %s }\n' "$depth_body"
    printf '%s\n' 'END'
} >"$test_tmp/NestedDepth.asn1"
if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-nested-depth" "$test_tmp/NestedDepth.asn1" \
    >"$test_tmp/rejected-nested-depth.log" 2>&1; then
    echo "FAIL: Rust backend accepted excessive nested SEQUENCE depth"
    exit 1
fi
test ! -e "$test_tmp/rejected-nested-depth"

# Direct AUTOMATIC TAGS on SEQUENCE members are ignored by PER. This tagged
# BOOLEAN remains outside the Rust subset and is rejected before publication.
if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-top-level-tag" "$test_tmp/SequenceTopTagged.asn1" \
    >"$test_tmp/rejected-top-level-tag.log" 2>&1; then
    echo "FAIL: Rust backend accepted a top-level tagged type"
    exit 1
fi
grep -F 'type tags are supported only on BER/CER-only flat SEQUENCE/SET roots' \
    "$test_tmp/rejected-top-level-tag.log" >/dev/null
test ! -e "$test_tmp/rejected-top-level-tag"

# Unsupported DEFAULT value types and out-of-range integer literals fail closed.
cat >"$test_tmp/SequenceDefaultBadType.asn1" <<'EOF'
SequenceDefaultBadType DEFINITIONS ::= BEGIN
BadType ::= SEQUENCE { value BOOLEAN DEFAULT 1 }
END
EOF
cat >"$test_tmp/SequenceDefaultOutOfRange.asn1" <<'EOF'
SequenceDefaultOutOfRange DEFINITIONS ::= BEGIN
OutOfRange ::= SEQUENCE { value INTEGER (0..3) DEFAULT 4 }
END
EOF
for fixture in SequenceDefaultBadType SequenceDefaultOutOfRange; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" \
        -D "$rejected_out" "$test_tmp/$fixture.asn1" \
        >"$test_tmp/rejected-$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted invalid $fixture"
        exit 1
    fi
    grep -F 'DEFAULT needs a literal BOOLEAN or in-range bounded INTEGER' \
        "$test_tmp/rejected-$fixture.log" >/dev/null
    test ! -e "$rejected_out"
done

# Unsupported C layout and inspection options must also reject before output.
for option in -fnative-types -fwide-types -E; do
    option_name=$(printf '%s' "$option" | tr -cd '[:alnum:]')
    rejected_out="$test_tmp/rejected-$option_name"
    if "$asn1c_bin" --rust "$option" -S "$skeletons" -D "$rejected_out" \
        "$test_srcdir/FirstSlice.asn1" >"$test_tmp/rejected-$option_name.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported option $option"
        exit 1
    fi
    if [ -e "$rejected_out" ]; then
        echo "FAIL: unsupported option $option created output before rejection"
        exit 1
    fi
done

# Unsupported ASN.1 types and ranges outside Rust i64 must fail before output.
if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$test_tmp/rejected-sequence" \
    "$test_srcdir/Unsupported.asn1" >"$test_tmp/rejected-sequence.log" 2>&1; then
    echo "FAIL: Rust backend accepted an unsupported SEQUENCE"
    exit 1
fi
grep -F 'SEQUENCE field needs a supported direct UPER primitive' \
    "$test_tmp/rejected-sequence.log" >/dev/null
if [ -e "$test_tmp/rejected-sequence" ]; then
    echo "FAIL: unsupported SEQUENCE created output before rejection"
    exit 1
fi

if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/rejected-bounds" \
    "$test_srcdir/InvalidBounds.asn1" >"$test_tmp/rejected-bounds.log" 2>&1; then
    echo "FAIL: Rust backend accepted INTEGER bounds outside i64"
    exit 1
fi
if [ -e "$test_tmp/rejected-bounds" ] || [ ! -s "$test_tmp/rejected-bounds.log" ]; then
    echo "FAIL: invalid INTEGER bounds created output before rejection"
    exit 1
fi

# Distinct ASN.1 module names that normalize to one Rust module must be rejected.
if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/rejected-name-collision" \
    "$test_srcdir/NameCollision.asn1" \
    >"$test_tmp/rejected-name-collision.log" 2>&1; then
    echo "FAIL: Rust backend accepted colliding normalized module names"
    exit 1
fi
grep -F 'module names collide after Rust sanitization' \
    "$test_tmp/rejected-name-collision.log" >/dev/null
if [ -e "$test_tmp/rejected-name-collision" ]; then
    echo "FAIL: colliding Rust module names created output before rejection"
    exit 1
fi

# Reject valid ASN.1 constructs outside this Rust slice before writing output.
for fixture in Alias Import TaggedBoolean ExtensibleInteger UnionInteger \
    NamedNumber EncodingControl; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -S "$skeletons" -D "$rejected_out" \
        "$test_srcdir/$fixture.asn1" >"$test_tmp/rejected-$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported fixture $fixture"
        exit 1
    fi
    if [ -e "$rejected_out" ] || [ ! -s "$test_tmp/rejected-$fixture.log" ]; then
        echo "FAIL: unsupported fixture $fixture wrote output or omitted diagnostics"
        exit 1
    fi
    case "$fixture" in
        Alias) expected='Rust backend does not support' ;;
        Import) expected='IMPORTS are not supported' ;;
        TaggedBoolean) expected='type tags are supported only on BER/CER-only flat SEQUENCE/SET roots' ;;
        ExtensibleInteger|UnionInteger)
            expected='INTEGER needs one finite, nonextensible range fitting i64' ;;
        NamedNumber) expected='Rust backend does not support' ;;
        EncodingControl) expected='encoding controls are not supported' ;;
    esac
    if ! grep -F "$expected" "$test_tmp/rejected-$fixture.log" >/dev/null; then
        echo "FAIL: unsupported fixture $fixture lacked its backend rejection reason"
        exit 1
    fi
done

# Runtime and Rust module names must not shadow generated dependency paths.
reserved_out="$test_tmp/reserved-module"
"$asn1c_bin" --rust -S "$skeletons" -D "$reserved_out" \
    "$test_srcdir/ReservedModule.asn1"
test -f "$reserved_out/src/asn1_lib.rs"
grep -F 'pub mod asn1_lib;' "$reserved_out/src/lib.rs" >/dev/null
test -f "$reserved_out/src/asn1_core.rs"
grep -F 'pub mod asn1_core;' "$reserved_out/src/lib.rs" >/dev/null
test -f "$reserved_out/src/asn1_asn1c_runtime.rs"
grep -F 'pub mod asn1_asn1c_runtime;' "$reserved_out/src/lib.rs" >/dev/null
if ! (cd "$reserved_out" && \
    CARGO_TARGET_DIR="$test_tmp/reserved-cargo-target" \
    cargo check --offline --manifest-path Cargo.toml) \
    >"$test_tmp/reserved-cargo-check.log" 2>&1; then
    cat "$test_tmp/reserved-cargo-check.log"
    echo "FAIL: reserved-module Rust crate did not pass offline cargo check"
    exit 1
fi

# Option-like tokens remain option operands and filenames in their positions.
operand_dir="$test_tmp/option-operands"
mkdir "$operand_dir"
mkdir "$operand_dir/--rust"
(
    cd "$operand_dir"
    "$asn1c_bin" -S "$skeletons" -D --rust "$test_srcdir/CParity.asn1" \
        >"$test_tmp/dash-dest.log" 2>&1
)
if [ ! -f "$operand_dir/--rust/Flag.c" ]; then
    cat "$test_tmp/dash-dest.log"
    echo "FAIL: -D did not preserve --rust as its directory operand"
    exit 1
fi
mkdir "$test_tmp/skeleton-operands"
ln -s "$skeletons" "$test_tmp/skeleton-operands/--rust"
mkdir "$test_tmp/skeleton-operands/from-option"
(
    cd "$test_tmp/skeleton-operands"
    "$asn1c_bin" -S --rust -D from-option \
        "$test_srcdir/CParity.asn1" >"$test_tmp/dash-skeleton.log" 2>&1
)
if [ ! -f "$test_tmp/skeleton-operands/from-option/Flag.c" ]; then
    cat "$test_tmp/dash-skeleton.log"
    echo "FAIL: -S did not preserve --rust as its directory operand"
    exit 1
fi

cp "$test_srcdir/FirstSlice.asn1" "$test_tmp/--rust"
mkdir "$test_tmp/filename-after-terminator"
(
    cd "$test_tmp"
    "$asn1c_bin" -S "$skeletons" -D filename-after-terminator -- --rust \
        >"$test_tmp/dash-filename.log" 2>&1
)
if [ ! -f "$test_tmp/filename-after-terminator/Flag.c" ]; then
    cat "$test_tmp/dash-filename.log"
    echo "FAIL: --rust after -- did not remain a C input filename"
    exit 1
fi
mkdir "$test_tmp/rust-filename-after-terminator"
(
    cd "$test_tmp"
    "$asn1c_bin" --rust -S "$skeletons" \
        -D rust-filename-after-terminator -- --rust
)
test -f "$test_tmp/rust-filename-after-terminator/src/first_slice.rs"

# Default C generation must still emit ordinary C files and no Cargo crate.
c_default="$test_tmp/default-c"
mkdir "$c_default"
if ! "$asn1c_bin" -S "$skeletons" -D "$c_default" \
    "$test_srcdir/CParity.asn1" >"$test_tmp/default-c.log" 2>&1; then
    cat "$test_tmp/default-c.log"
    exit 1
fi
for generated in Flag.c Flag.h Count.c Count.h; do
    if [ ! -f "$c_default/$generated" ]; then
        echo "FAIL: default C backend lacks $generated"
        exit 1
    fi
done
if [ -e "$c_default/Cargo.toml" ]; then
    echo "FAIL: default C backend unexpectedly emitted a Cargo crate"
    exit 1
fi

# In C mode CER depends on BER, and option order controls that shared backend.
c_cer_after_ber_off="$test_tmp/c-cer-after-ber-off"
mkdir "$c_cer_after_ber_off"
"$asn1c_bin" -no-gen-BER -gen-CER -S "$skeletons" \
    -D "$c_cer_after_ber_off" "$test_srcdir/CParity.asn1"
c_cer_after_ber_off_flags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$c_cer_after_ber_off/Makefile.am.libasncodec")
case "$c_cer_after_ber_off_flags" in
    *ASN_DISABLE_BER_SUPPORT*|*ASN_DISABLE_CER_SUPPORT*)
        echo "FAIL: -no-gen-BER -gen-CER did not restore the CER dependency"
        exit 1
        ;;
esac

c_ber_off_after_cer="$test_tmp/c-ber-off-after-cer"
mkdir "$c_ber_off_after_cer"
"$asn1c_bin" -gen-CER -no-gen-BER -S "$skeletons" \
    -D "$c_ber_off_after_cer" "$test_srcdir/CParity.asn1"
c_ber_off_after_cer_flags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$c_ber_off_after_cer/Makefile.am.libasncodec")
case "$c_ber_off_after_cer_flags" in
    *ASN_DISABLE_BER_SUPPORT*ASN_DISABLE_CER_SUPPORT*|\
    *ASN_DISABLE_CER_SUPPORT*ASN_DISABLE_BER_SUPPORT*) ;;
    *)
        echo "FAIL: -gen-CER -no-gen-BER retained the shared CER backend"
        exit 1
        ;;
esac

c_cer_off="$test_tmp/c-cer-off"
mkdir "$c_cer_off"
"$asn1c_bin" -no-gen-CER -S "$skeletons" -D "$c_cer_off" \
    "$test_srcdir/CParity.asn1"
c_cer_off_flags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$c_cer_off/Makefile.am.libasncodec")
case "$c_cer_off_flags" in
    *ASN_DISABLE_CER_SUPPORT*) ;;
    *)
        echo "FAIL: -no-gen-CER left the C CER encoder/decoder enabled"
        exit 1
        ;;
esac
case "$c_cer_off_flags" in
    *ASN_DISABLE_BER_SUPPORT*)
        echo "FAIL: -no-gen-CER disabled the independent BER decoder"
        exit 1
        ;;
esac

# Build the comparison project from its generated dependency closure, not the
# repository skeleton archive, so the test cannot link stale compiled objects.
c_out="$test_tmp/generated-c"
mkdir "$c_out"
if ! "$asn1c_bin" -S "$skeletons" -gen-UPER -gen-CER -gen-OER -gen-APER -no-gen-XER \
    -no-gen-CBOR -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$c_out" "$test_srcdir/CParity.asn1" \
    "$test_srcdir/OctetJER.asn1" "$test_srcdir/BerCerSlice.asn1" \
    >"$test_tmp/c-generate.log" 2>&1; then
    cat "$test_tmp/c-generate.log"
    exit 1
fi
if [ ! -f "$c_out/Makefile.am.libasncodec" ]; then
    echo "FAIL: generated C project lacks its library build settings"
    exit 1
fi
asn1c_module_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$c_out/Makefile.am.libasncodec")
# Split generated feature defines into arguments while preserving their values.
if ! cc $asn1c_module_cflags -I"$c_out" "$c_out"/*.c \
    "$test_srcdir/c_reference.c" -lm \
    -o "$test_tmp/c-reference" >"$test_tmp/c-compile.log" 2>&1; then
    cat "$test_tmp/c-compile.log"
    exit 1
fi
if ! cc $asn1c_module_cflags -I"$c_out" "$c_out"/*.c \
    "$test_srcdir/c_additional.c" -lm \
    -o "$test_tmp/c-additional" >"$test_tmp/c-additional-compile.log" 2>&1; then
    cat "$test_tmp/c-additional-compile.log"
    exit 1
fi
"$test_tmp/c-additional"
if ! cc $asn1c_module_cflags -I"$c_out" "$c_out"/*.c \
    "$test_srcdir/c_jer.c" -lm \
    -o "$test_tmp/c-jer" >"$test_tmp/c-jer-compile.log" 2>&1; then
    cat "$test_tmp/c-jer-compile.log"
    exit 1
fi
"$test_tmp/c-jer"

octet_jer_out="$test_tmp/octet-jer"
"$asn1c_bin" --rust -gen-JER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$octet_jer_out" "$test_srcdir/OctetJER.asn1"
grep -F 'pub fn encode_jer' "$octet_jer_out/src/octet_jer.rs" >/dev/null
grep -F 'pub fn decode_jer' "$octet_jer_out/src/octet_jer.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|cer)' \
    "$octet_jer_out/src/octet_jer.rs" >/dev/null; then
    echo "FAIL: OCTET STRING JER-only selection generated UPER or CER methods"
    exit 1
fi
mkdir "$octet_jer_out/tests" "$test_tmp/c-octet-jer-vectors" \
    "$test_tmp/rust-octet-jer-vectors"
cp "$test_srcdir/octet_jer_conformance.rs" \
    "$octet_jer_out/tests/octet_jer_conformance.rs"
cp "$test_srcdir/bit_jer_conformance.rs" \
    "$octet_jer_out/tests/bit_jer_conformance.rs"
"$test_tmp/c-jer" --write-dir "$test_tmp/c-octet-jer-vectors"
if ! (cd "$octet_jer_out" && \
    ASN1C_C_JER_VECTORS="$test_tmp/c-octet-jer-vectors" \
    ASN1C_RUST_JER_VECTORS="$test_tmp/rust-octet-jer-vectors" \
    ASN1C_C_BIT_JER_VECTORS="$test_tmp/c-octet-jer-vectors" \
    ASN1C_RUST_BIT_JER_VECTORS="$test_tmp/rust-octet-jer-vectors" \
    CARGO_TARGET_DIR="$test_tmp/target-octet-jer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-octet-jer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-octet-jer.log" 2>&1; then
    cat "$test_tmp/check-octet-jer.log"
    echo "FAIL: generated OCTET STRING JER tests or strict Clippy"
    exit 1
fi
"$test_tmp/c-jer" --decode-octet-dir "$test_tmp/rust-octet-jer-vectors"
"$test_tmp/c-jer" --decode-bit-dir "$test_tmp/rust-octet-jer-vectors"

# Exchange Rust JER primitive tokens with the independently built C decoder.
mkdir "$test_tmp/jer-vectors"
(cd "$jer_out" && ASN1C_RUST_JER_VECTORS="$test_tmp/jer-vectors" \
    CARGO_TARGET_DIR="$test_tmp/target-jer" \
    cargo test --offline --manifest-path Cargo.toml)
"$test_tmp/c-jer" --decode-dir "$test_tmp/jer-vectors"

# Both codecs exchange actual generated bytes through temporary wire fixtures.
mkdir "$test_tmp/c-vectors" "$test_tmp/rust-vectors"
"$test_tmp/c-reference" "$test_tmp/c-vectors"

# Keep Cargo's build artifacts outside both the repository and generated crate.
rust_ber_out="$test_tmp/generated-rust-ber"
"$asn1c_bin" --rust -gen-BER -S "$skeletons" -D "$rust_ber_out" \
    "$test_srcdir/FirstSlice.asn1"
mkdir "$rust_ber_out/tests"
cp "$test_srcdir/conformance.rs" "$rust_ber_out/tests/conformance.rs"
(cd "$rust_ber_out" && \
    ASN1C_C_VECTORS="$test_tmp/c-vectors" \
    ASN1C_RUST_VECTORS="$test_tmp/rust-vectors" \
    CARGO_TARGET_DIR="$test_tmp/cargo-target" \
    cargo test --offline --manifest-path Cargo.toml)
(cd "$rust_ber_out" && \
    CARGO_TARGET_DIR="$test_tmp/cargo-target" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings)
"$test_tmp/c-reference" --decode-dir "$test_tmp/rust-vectors"

# Exercise BER/DER/CER methods on direct enum and size-constrained strings.
ber_cer_out="$test_tmp/ber-cer-rust"
"$asn1c_bin" --rust -gen-BER -S "$skeletons" -D "$ber_cer_out" \
    "$test_srcdir/BerCerSlice.asn1"
mkdir -p "$ber_cer_out/tests"
cp "$test_srcdir/ber_cer_conformance.rs" "$ber_cer_out/tests/"
if ! cargo test --offline --manifest-path "$ber_cer_out/Cargo.toml" \
    >"$test_tmp/ber-cer-rust-test.log" 2>&1; then
    cat "$test_tmp/ber-cer-rust-test.log"
    echo "FAIL: generated Rust BER/DER/CER primitive conformance failed"
    exit 1
fi
if ! cargo clippy --offline --manifest-path "$ber_cer_out/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings \
    >"$test_tmp/ber-cer-rust-clippy.log" 2>&1; then
    cat "$test_tmp/ber-cer-rust-clippy.log"
    echo "FAIL: generated Rust BER/DER/CER output failed strict Clippy"
    exit 1
fi
grep -F 'pub fn encode_uper' "$ber_cer_out/src/ber_cer_slice.rs" >/dev/null
grep -F 'pub fn encode_der' "$ber_cer_out/src/ber_cer_slice.rs" >/dev/null
grep -F 'pub fn encode_cer' "$ber_cer_out/src/ber_cer_slice.rs" >/dev/null

# Each BER and CER selector can generate its own dependency-clean crate.
ber_only_strings="$test_tmp/ber-only-strings"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$ber_only_strings" "$test_srcdir/BerCerSlice.asn1"
if ! cargo check --offline --manifest-path "$ber_only_strings/Cargo.toml" \
    >"$test_tmp/ber-only-strings-check.log" 2>&1; then
    cat "$test_tmp/ber-only-strings-check.log"
    echo "FAIL: BER-only constrained string crate did not compile"
    exit 1
fi
grep -F 'pub fn decode_ber' "$ber_only_strings/src/ber_cer_slice.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|cer)' \
    "$ber_only_strings/src/ber_cer_slice.rs" >/dev/null; then
    echo "FAIL: BER-only constrained string output retained UPER or CER"
    exit 1
fi

cer_only_strings="$test_tmp/cer-only-strings"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$cer_only_strings" "$test_srcdir/BerCerSlice.asn1"
if ! cargo check --offline --manifest-path "$cer_only_strings/Cargo.toml" \
    >"$test_tmp/cer-only-strings-check.log" 2>&1; then
    cat "$test_tmp/cer-only-strings-check.log"
    echo "FAIL: CER-only constrained string crate did not compile"
    exit 1
fi
grep -F 'pub fn decode_cer' "$cer_only_strings/src/ber_cer_slice.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|der|ber)' \
    "$cer_only_strings/src/ber_cer_slice.rs" >/dev/null; then
    echo "FAIL: CER-only constrained string output retained UPER or BER/DER"
    exit 1
fi

# The C reference fixture independently encodes the same enum and string TLVs.
if ! cc $asn1c_module_cflags -I"$c_out" "$c_out"/*.c \
    "$test_srcdir/c_ber_cer.c" -lm -o "$test_tmp/c-ber-cer" \
    >"$test_tmp/c-ber-cer-compile.log" 2>&1; then
    cat "$test_tmp/c-ber-cer-compile.log"
    echo "FAIL: generated C BER/DER/CER reference did not compile"
    exit 1
fi
"$test_tmp/c-ber-cer"

# Flat, unique-tag direct SEQUENCE records compose UPER, DER/BER, and CER.
sequence_ber_cer_out="$test_tmp/sequence-ber-cer-rust"
"$asn1c_bin" --rust -gen-BER -S "$skeletons" -D "$sequence_ber_cer_out" \
    "$test_srcdir/SequenceBerCer.asn1"
mkdir "$sequence_ber_cer_out/tests"
cp "$test_srcdir/sequence_ber_cer_conformance.rs" "$sequence_ber_cer_out/tests/"
if ! (cd "$sequence_ber_cer_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-sequence-ber-cer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-sequence-ber-cer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-sequence-ber-cer.log" 2>&1; then
    cat "$test_tmp/check-sequence-ber-cer.log"
    echo "FAIL: generated mixed UPER/BER/CER SEQUENCE tests or strict Clippy"
    exit 1
fi
sequence_ber_cer_source="$sequence_ber_cer_out/src/sequence_ber_cer.rs"
for method in encode_uper encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$sequence_ber_cer_source" >/dev/null
done

# Check the selector-conditioned record emitters without the mixed defaults.
sequence_ber_only="$test_tmp/sequence-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$sequence_ber_only" "$test_srcdir/SequenceBerCer.asn1"
if ! (cargo check --offline --manifest-path "$sequence_ber_only/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$sequence_ber_only/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/sequence-ber-only-check.log" 2>&1; then
    cat "$test_tmp/sequence-ber-only-check.log"
    echo "FAIL: BER-only SEQUENCE crate did not compile"
    exit 1
fi
sequence_ber_only_source="$sequence_ber_only/src/sequence_ber_cer.rs"
grep -F 'pub fn encode_der' "$sequence_ber_only_source" >/dev/null
grep -F 'pub fn decode_ber' "$sequence_ber_only_source" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|cer)' \
    "$sequence_ber_only_source" >/dev/null; then
    echo "FAIL: BER-only SEQUENCE output retained UPER or CER"
    exit 1
fi

sequence_cer_only="$test_tmp/sequence-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$sequence_cer_only" "$test_srcdir/SequenceBerCer.asn1"
if ! (cargo check --offline --manifest-path "$sequence_cer_only/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$sequence_cer_only/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/sequence-cer-only-check.log" 2>&1; then
    cat "$test_tmp/sequence-cer-only-check.log"
    echo "FAIL: CER-only SEQUENCE crate did not compile"
    exit 1
fi
sequence_cer_only_source="$sequence_cer_only/src/sequence_ber_cer.rs"
grep -F 'pub fn encode_cer' "$sequence_cer_only_source" >/dev/null
grep -F 'pub fn decode_cer' "$sequence_cer_only_source" >/dev/null
if grep -E 'pub fn (encode|decode)_(uper|der|ber)' \
    "$sequence_cer_only_source" >/dev/null; then
    echo "FAIL: CER-only SEQUENCE output retained UPER or BER/DER"
    exit 1
fi

# Compare the same fixed DER/CER vectors with independently generated C code.
sequence_ber_cer_c_out="$test_tmp/sequence-ber-cer-c"
mkdir "$sequence_ber_cer_c_out"
"$asn1c_bin" -S "$skeletons" -gen-CER -no-gen-UPER -no-gen-XER \
    -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$sequence_ber_cer_c_out" \
    "$test_srcdir/SequenceBerCer.asn1" \
    >"$test_tmp/sequence-ber-cer-c-generate.log" 2>&1
sequence_ber_cer_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$sequence_ber_cer_c_out/Makefile.am.libasncodec")
rm -f "$sequence_ber_cer_c_out/converter-example.c" \
    "$sequence_ber_cer_c_out/pdu_collection.c"
if ! cc $sequence_ber_cer_cflags -I"$sequence_ber_cer_c_out" \
    "$sequence_ber_cer_c_out"/*.c "$test_srcdir/c_sequence_ber_cer.c" \
    -lm -o "$test_tmp/c-sequence-ber-cer" \
    >"$test_tmp/c-sequence-ber-cer-compile.log" 2>&1; then
    cat "$test_tmp/c-sequence-ber-cer-compile.log"
    echo "FAIL: generated C BER/CER SEQUENCE reference did not compile"
    exit 1
fi
"$test_tmp/c-sequence-ber-cer"

# Binary SET codecs are BER/CER-only; XER remains in its independent XER-only branch.
set_ber_cer_out="$test_tmp/set-ber-cer-rust"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -S "$skeletons" \
    -D "$set_ber_cer_out" "$test_srcdir/SetBerCer.asn1"
mkdir "$set_ber_cer_out/tests"
cp "$test_srcdir/set_ber_cer_conformance.rs" "$set_ber_cer_out/tests/"
if ! (cd "$set_ber_cer_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-set-ber-cer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-set-ber-cer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/check-set-ber-cer.log" 2>&1; then
    cat "$test_tmp/check-set-ber-cer.log"
    echo "FAIL: generated BER/CER SET tests or strict Clippy"
    exit 1
fi
set_ber_cer_source="$set_ber_cer_out/src/set_ber_cer.rs"
for method in encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$set_ber_cer_source" >/dev/null
done
grep -F 'pub struct SetEmptyRecord' "$set_ber_cer_source" >/dev/null

# Keep BER-only and CER-only SET output independently under strict linting.
set_ber_only="$test_tmp/set-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$set_ber_only" "$test_srcdir/SetBerCer.asn1"
if ! (cargo check --offline --manifest-path "$set_ber_only/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$set_ber_only/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/set-ber-only-check.log" 2>&1; then
    cat "$test_tmp/set-ber-only-check.log"
    echo "FAIL: BER-only SET crate did not compile under strict Clippy"
    exit 1
fi
grep -F 'pub fn decode_ber' "$set_ber_only/src/set_ber_cer.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_cer' "$set_ber_only/src/set_ber_cer.rs" >/dev/null; then
    echo "FAIL: BER-only SET output retained CER methods"
    exit 1
fi
set_cer_only="$test_tmp/set-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$set_cer_only" "$test_srcdir/SetBerCer.asn1"
if ! (cargo check --offline --manifest-path "$set_cer_only/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$set_cer_only/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/set-cer-only-check.log" 2>&1; then
    cat "$test_tmp/set-cer-only-check.log"
    echo "FAIL: CER-only SET crate did not compile under strict Clippy"
    exit 1
fi
grep -F 'pub fn decode_cer' "$set_cer_only/src/set_ber_cer.rs" >/dev/null
if grep -E 'pub fn (encode|decode)_(der|ber)' "$set_cer_only/src/set_ber_cer.rs" >/dev/null; then
    echo "FAIL: CER-only SET output retained DER/BER methods"
    exit 1
fi

# C's current empty SET output is not portable C; the C parity schema exercises
# required/default fields while the empty SET fixture remains Rust-generated.
set_ber_cer_c_out="$test_tmp/set-ber-cer-c"
mkdir "$set_ber_cer_c_out"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -fwide-types -pdu=all \
    -fgen-only-pdu-deps -no-gen-example -D "$set_ber_cer_c_out" \
    "$test_srcdir/SetBerCerC.asn1" >"$test_tmp/set-ber-cer-c-generate.log" 2>&1
set_ber_cer_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$set_ber_cer_c_out/Makefile.am.libasncodec")
rm -f "$set_ber_cer_c_out/converter-example.c" "$set_ber_cer_c_out/pdu_collection.c"
if ! cc $set_ber_cer_cflags -I"$set_ber_cer_c_out" \
    "$set_ber_cer_c_out"/*.c "$test_srcdir/c_set_ber_cer.c" \
    -lm -o "$test_tmp/c-set-ber-cer" >"$test_tmp/c-set-ber-cer-compile.log" 2>&1; then
    cat "$test_tmp/c-set-ber-cer-compile.log"
    echo "FAIL: generated C BER/CER SET reference did not compile"
    exit 1
fi
"$test_tmp/c-set-ber-cer"

# Resolved IMPLICIT member tags share the mixed SEQUENCE and BER/CER SET paths.
tagged_sequence_out="$test_tmp/tagged-sequence-rust"
"$asn1c_bin" --rust -gen-BER -S "$skeletons" -D "$tagged_sequence_out" \
    "$test_srcdir/TaggedSequence.asn1"
mkdir "$tagged_sequence_out/tests"
cp "$test_srcdir/tagged_sequence_conformance.rs" "$tagged_sequence_out/tests/"
if ! (cd "$tagged_sequence_out" && cargo test --offline --manifest-path Cargo.toml && \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-sequence-check.log" 2>&1; then
    cat "$test_tmp/tagged-sequence-check.log"
    echo "FAIL: tagged mixed-codec SEQUENCE tests or strict Clippy"
    exit 1
fi

for method in encode_der decode_ber encode_cer decode_cer encode_uper decode_uper; do
    grep -F "pub fn $method" "$tagged_sequence_out/src/tagged_sequence.rs" >/dev/null
done

# Selector-only builds exercise tagged code under each conditional codec branch.
tagged_sequence_ber="$test_tmp/tagged-sequence-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$tagged_sequence_ber" "$test_srcdir/TaggedSequence.asn1"
if ! (cargo check --offline --manifest-path "$tagged_sequence_ber/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_sequence_ber/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-sequence-ber-only.log" 2>&1; then
    cat "$test_tmp/tagged-sequence-ber-only.log"
    echo "FAIL: tagged BER-only SEQUENCE strict Clippy"
    exit 1
fi
tagged_sequence_cer="$test_tmp/tagged-sequence-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$tagged_sequence_cer" "$test_srcdir/TaggedSequence.asn1"
if ! (cargo check --offline --manifest-path "$tagged_sequence_cer/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_sequence_cer/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-sequence-cer-only.log" 2>&1; then
    cat "$test_tmp/tagged-sequence-cer-only.log"
    echo "FAIL: tagged CER-only SEQUENCE strict Clippy"
    exit 1
fi

# A single context-specific IMPLICIT tag may replace a flat SEQUENCE root.
tagged_root_out="$test_tmp/tagged-root-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$tagged_root_out" "$test_srcdir/TaggedRootSequence.asn1"
mkdir "$tagged_root_out/tests"
cp "$test_srcdir/tagged_root_conformance.rs" "$tagged_root_out/tests/"
if ! (cd "$tagged_root_out" && cargo test --offline --manifest-path Cargo.toml && \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-root-check.log" 2>&1; then
    cat "$test_tmp/tagged-root-check.log"
    echo "FAIL: tagged-root conformance or strict Clippy"
    exit 1
fi
for method in encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$tagged_root_out/src/tagged_root_sequence.rs" >/dev/null
done
if grep -E 'pub fn (encode|decode)_(uper|cbor|jer|xer|aper|oer)' \
    "$tagged_root_out/src/tagged_root_sequence.rs" >/dev/null; then
    echo "FAIL: tagged-root BER/CER output retained an unsupported codec"
    exit 1
fi

tagged_root_ber="$test_tmp/tagged-root-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$tagged_root_ber" "$test_srcdir/TaggedRootSequence.asn1"
if ! (cargo check --offline --manifest-path "$tagged_root_ber/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_root_ber/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-root-ber-only.log" 2>&1; then
    cat "$test_tmp/tagged-root-ber-only.log"
    echo "FAIL: tagged-root BER-only strict Clippy"
    exit 1
fi
tagged_root_cer="$test_tmp/tagged-root-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$tagged_root_cer" "$test_srcdir/TaggedRootSequence.asn1"
if ! (cargo check --offline --manifest-path "$tagged_root_cer/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_root_cer/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-root-cer-only.log" 2>&1; then
    cat "$test_tmp/tagged-root-cer-only.log"
    echo "FAIL: tagged-root CER-only strict Clippy"
    exit 1
fi

for root_fixture in TaggedRootExplicit.asn1 TaggedRootApplication.asn1 \
    TaggedRootNested.asn1 TaggedRootExtension.asn1 TaggedRootAlias.asn1 \
    TaggedRootStack.asn1; do
    rejected_out="$test_tmp/rejected-tagged-root-${root_fixture%.asn1}"
    if "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$root_fixture" \
        >"$test_tmp/rejected-tagged-root.log" 2>&1; then
        echo "FAIL: unsupported tagged-root shape $root_fixture was accepted"
        exit 1
    fi
    test ! -e "$rejected_out"
done

# Root tagging must not leak into the mixed UPER/BER/CER generator.
if "$asn1c_bin" --rust -gen-BER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-tagged-root-mixed" \
    "$test_srcdir/TaggedRootSequence.asn1" \
    >"$test_tmp/rejected-tagged-root-mixed.log" 2>&1; then
    echo "FAIL: tagged-root mixed codec selection was accepted"
    exit 1
fi
test ! -e "$test_tmp/rejected-tagged-root-mixed"

# The generated C implementation independently checks DER/CER and BER aliases.
tagged_root_c_out="$test_tmp/tagged-root-c"
mkdir "$tagged_root_c_out"
"$asn1c_bin" -fcompound-names -S "$skeletons" -D "$tagged_root_c_out" \
    "$test_srcdir/TaggedRootSequence.asn1" \
    >"$test_tmp/tagged-root-c-generate.log" 2>&1
rm -f "$tagged_root_c_out/converter-example.c" "$tagged_root_c_out/pdu_collection.c"
if ! cc -I"$tagged_root_c_out" "$tagged_root_c_out"/*.c \
    "$test_srcdir/c_tagged_root.c" -lm -o "$test_tmp/c-tagged-root" \
    >"$test_tmp/tagged-root-c-compile.log" 2>&1; then
    cat "$test_tmp/tagged-root-c-compile.log"
    echo "FAIL: generated C tagged-root reference did not compile"
    exit 1
fi
"$test_tmp/c-tagged-root"

# A context-specific IMPLICIT tag may replace a flat top-level SET root.
tagged_root_set_out="$test_tmp/tagged-root-set-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$tagged_root_set_out" "$test_srcdir/TaggedRootSet.asn1"
mkdir "$tagged_root_set_out/tests"
cp "$test_srcdir/tagged_root_set_conformance.rs" "$tagged_root_set_out/tests/"
if ! (cd "$tagged_root_set_out" && cargo test --offline --manifest-path Cargo.toml && \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-root-set-check.log" 2>&1; then
    cat "$test_tmp/tagged-root-set-check.log"
    echo "FAIL: tagged SET-root conformance or strict Clippy"
    exit 1
fi
for method in encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$tagged_root_set_out/src/tagged_root_set.rs" >/dev/null
done
if grep -E 'pub fn (encode|decode)_(uper|cbor|jer|xer|aper|oer)' \
    "$tagged_root_set_out/src/tagged_root_set.rs" >/dev/null; then
    echo "FAIL: tagged SET-root output retained an unsupported codec"
    exit 1
fi

tagged_root_set_ber="$test_tmp/tagged-root-set-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$tagged_root_set_ber" "$test_srcdir/TaggedRootSet.asn1"
if ! (cargo check --offline --manifest-path "$tagged_root_set_ber/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_root_set_ber/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-root-set-ber-only.log" 2>&1; then
    cat "$test_tmp/tagged-root-set-ber-only.log"
    echo "FAIL: tagged SET-root BER-only strict Clippy"
    exit 1
fi
tagged_root_set_cer="$test_tmp/tagged-root-set-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
    -D "$tagged_root_set_cer" "$test_srcdir/TaggedRootSet.asn1"
if ! (cargo check --offline --manifest-path "$tagged_root_set_cer/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_root_set_cer/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-root-set-cer-only.log" 2>&1; then
    cat "$test_tmp/tagged-root-set-cer-only.log"
    echo "FAIL: tagged SET-root CER-only strict Clippy"
    exit 1
fi

for root_set_fixture in TaggedRootSetExplicit.asn1 TaggedRootSetApplication.asn1 \
    TaggedRootSetNested.asn1 TaggedRootSetNestedSequence.asn1 \
    TaggedRootSetExtension.asn1 TaggedRootSetAlias.asn1 TaggedRootSetStack.asn1 \
    TaggedRootSetTooLarge.asn1; do
    rejected_out="$test_tmp/rejected-${root_set_fixture%.asn1}"
    if "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$root_set_fixture" \
        >"$test_tmp/rejected-tagged-root-set.log" 2>&1; then
        echo "FAIL: unsupported tagged SET-root shape $root_set_fixture was accepted"
        exit 1
    fi
    test ! -e "$rejected_out"
done
if "$asn1c_bin" --rust -gen-BER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-tagged-root-set-mixed" \
    "$test_srcdir/TaggedRootSet.asn1" >"$test_tmp/rejected-tagged-root-set-mixed.log" 2>&1; then
    echo "FAIL: tagged SET-root mixed codec selection was accepted"
    exit 1
fi
test ! -e "$test_tmp/rejected-tagged-root-set-mixed"

# C parity uses a separate schema because the C generator emits empty SET enums.
tagged_root_set_c_out="$test_tmp/tagged-root-set-c"
mkdir "$tagged_root_set_c_out"
"$asn1c_bin" -fcompound-names -S "$skeletons" -D "$tagged_root_set_c_out" \
    "$test_srcdir/TaggedRootSetC.asn1" \
    >"$test_tmp/tagged-root-set-c-generate.log" 2>&1
rm -f "$tagged_root_set_c_out/converter-example.c" "$tagged_root_set_c_out/pdu_collection.c"
if ! cc -I"$tagged_root_set_c_out" "$tagged_root_set_c_out"/*.c \
    "$test_srcdir/c_tagged_root_set.c" -lm -o "$test_tmp/c-tagged-root-set" \
    >"$test_tmp/tagged-root-set-c-compile.log" 2>&1; then
    cat "$test_tmp/tagged-root-set-c-compile.log"
    echo "FAIL: generated C tagged SET-root reference did not compile"
    exit 1
fi
"$test_tmp/c-tagged-root-set"

tagged_set_out="$test_tmp/tagged-set-rust"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -S "$skeletons" -D "$tagged_set_out" \
    "$test_srcdir/TaggedSet.asn1"
mkdir "$tagged_set_out/tests"
cp "$test_srcdir/tagged_set_conformance.rs" "$tagged_set_out/tests/"
if ! (cd "$tagged_set_out" && cargo test --offline --manifest-path Cargo.toml && \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-set-check.log" 2>&1; then
    cat "$test_tmp/tagged-set-check.log"
    echo "FAIL: tagged BER/CER SET tests or strict Clippy"
    exit 1
fi

tagged_set_ber="$test_tmp/tagged-set-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$tagged_set_ber" "$test_srcdir/TaggedSet.asn1"
if ! (cargo check --offline --manifest-path "$tagged_set_ber/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_set_ber/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-set-ber-only.log" 2>&1; then
    cat "$test_tmp/tagged-set-ber-only.log"
    echo "FAIL: tagged BER-only SET strict Clippy"
    exit 1
fi
tagged_set_cer="$test_tmp/tagged-set-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$tagged_set_cer" "$test_srcdir/TaggedSet.asn1"
if ! (cargo check --offline --manifest-path "$tagged_set_cer/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$tagged_set_cer/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/tagged-set-cer-only.log" 2>&1; then
    cat "$test_tmp/tagged-set-cer-only.log"
    echo "FAIL: tagged CER-only SET strict Clippy"
    exit 1
fi

# C provides independent DER/CER vectors and exercises alias/string behavior.
tagged_c_out="$test_tmp/tagged-records-c"
mkdir "$tagged_c_out"
"$asn1c_bin" -S "$skeletons" -D "$tagged_c_out" \
    "$test_srcdir/TaggedSequence.asn1" "$test_srcdir/TaggedSetC.asn1" \
    >"$test_tmp/tagged-records-c-generate.log" 2>&1
rm -f "$tagged_c_out/converter-example.c" "$tagged_c_out/pdu_collection.c"
if ! cc -I"$tagged_c_out" "$tagged_c_out"/*.c "$test_srcdir/c_tagged_sequence.c" \
    -lm -o "$test_tmp/c-tagged-sequence" \
    >"$test_tmp/tagged-records-c-compile.log" 2>&1; then
    cat "$test_tmp/tagged-records-c-compile.log"
    echo "FAIL: generated C tagged BER/CER reference did not compile"
    exit 1
fi
"$test_tmp/c-tagged-sequence"

# A resolved EXPLICIT wrapper is supported for each selected direct field kind.
explicit_sequence_out="$test_tmp/explicit-records-rust"
"$asn1c_bin" --rust -gen-BER -S "$skeletons" -D "$explicit_sequence_out" \
    "$test_srcdir/ExplicitRecords.asn1"
mkdir "$explicit_sequence_out/tests"
cp "$test_srcdir/explicit_sequence_conformance.rs" "$explicit_sequence_out/tests/"
if ! (cd "$explicit_sequence_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-explicit-sequence" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-explicit-sequence" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/explicit-sequence-check.log" 2>&1; then
    cat "$test_tmp/explicit-sequence-check.log"
    echo "FAIL: explicit mixed-codec SEQUENCE tests or strict Clippy"
    exit 1
fi
for method in encode_der decode_ber encode_cer decode_cer encode_uper decode_uper; do
    grep -F "pub fn $method" "$explicit_sequence_out/src/explicit_sequence.rs" >/dev/null
done

explicit_sequence_ber="$test_tmp/explicit-sequence-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$explicit_sequence_ber" "$test_srcdir/ExplicitRecords.asn1"
if ! (cargo check --offline --manifest-path "$explicit_sequence_ber/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$explicit_sequence_ber/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/explicit-sequence-ber-only.log" 2>&1; then
    cat "$test_tmp/explicit-sequence-ber-only.log"
    echo "FAIL: explicit BER-only SEQUENCE strict Clippy"
    exit 1
fi
explicit_sequence_cer="$test_tmp/explicit-sequence-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$explicit_sequence_cer" "$test_srcdir/ExplicitRecords.asn1"
if ! (cargo check --offline --manifest-path "$explicit_sequence_cer/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$explicit_sequence_cer/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/explicit-sequence-cer-only.log" 2>&1; then
    cat "$test_tmp/explicit-sequence-cer-only.log"
    echo "FAIL: explicit CER-only SEQUENCE strict Clippy"
    exit 1
fi

explicit_set_out="$test_tmp/explicit-records-set-rust"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -S "$skeletons" \
    -D "$explicit_set_out" "$test_srcdir/ExplicitSet.asn1"
mkdir "$explicit_set_out/tests"
cp "$test_srcdir/explicit_set_conformance.rs" "$explicit_set_out/tests/"
if ! (cd "$explicit_set_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-explicit-set" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-explicit-set" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/explicit-set-check.log" 2>&1; then
    cat "$test_tmp/explicit-set-check.log"
    echo "FAIL: explicit BER/CER SET tests or strict Clippy"
    exit 1
fi
explicit_set_ber="$test_tmp/explicit-set-ber-only"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$explicit_set_ber" "$test_srcdir/ExplicitSet.asn1"
if ! (cargo check --offline --manifest-path "$explicit_set_ber/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$explicit_set_ber/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/explicit-set-ber-only.log" 2>&1; then
    cat "$test_tmp/explicit-set-ber-only.log"
    echo "FAIL: explicit BER-only SET strict Clippy"
    exit 1
fi
explicit_set_cer="$test_tmp/explicit-set-cer-only"
"$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$explicit_set_cer" "$test_srcdir/ExplicitSet.asn1"
if ! (cargo check --offline --manifest-path "$explicit_set_cer/Cargo.toml" && \
    cargo clippy --offline --manifest-path "$explicit_set_cer/Cargo.toml" \
    --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/explicit-set-cer-only.log" 2>&1; then
    cat "$test_tmp/explicit-set-cer-only.log"
    echo "FAIL: explicit CER-only SET strict Clippy"
    exit 1
fi

# C independently encodes/decodes explicit scalar and constructed-string values.
explicit_c_out="$test_tmp/explicit-records-c"
mkdir "$explicit_c_out"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -fwide-types -pdu=all \
    -fgen-only-pdu-deps -no-gen-example -D "$explicit_c_out" \
    "$test_srcdir/ExplicitRecords.asn1" "$test_srcdir/ExplicitSet.asn1" \
    >"$test_tmp/explicit-records-c-generate.log" 2>&1
explicit_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$explicit_c_out/Makefile.am.libasncodec")
rm -f "$explicit_c_out/converter-example.c" "$explicit_c_out/pdu_collection.c"
if ! cc $explicit_cflags -I"$explicit_c_out" "$explicit_c_out"/*.c \
    "$test_srcdir/c_explicit_record.c" -lm -o "$test_tmp/c-explicit-record" \
    >"$test_tmp/c-explicit-record-compile.log" 2>&1; then
    cat "$test_tmp/c-explicit-record-compile.log"
    echo "FAIL: explicit generated C reference did not compile"
    exit 1
fi
"$test_tmp/c-explicit-record"
if cc $explicit_cflags -fsanitize=address -fno-omit-frame-pointer -g \
    -I"$explicit_c_out" "$explicit_c_out"/*.c "$test_srcdir/c_explicit_record.c" \
    -lm -o "$test_tmp/c-explicit-record-asan" \
    >"$test_tmp/c-explicit-record-asan-compile.log" 2>&1; then
    asan_status=0
    ASAN_OPTIONS=detect_leaks=1 "$test_tmp/c-explicit-record-asan" \
        >"$test_tmp/c-explicit-record-asan.log" 2>&1 || asan_status=$?
    if grep -Eq '^==[[:digit:]]+==AddressSanitizer: detect_leaks is not supported on this platform\.$' \
        "$test_tmp/c-explicit-record-asan.log" && \
        [ "$(wc -l <"$test_tmp/c-explicit-record-asan.log" | tr -d ' ')" -eq 1 ]; then
        if ! ASAN_OPTIONS=detect_leaks=0 "$test_tmp/c-explicit-record-asan" \
            >"$test_tmp/c-explicit-record-asan-fallback.log" 2>&1; then
            cat "$test_tmp/c-explicit-record-asan-fallback.log"
            echo "FAIL: explicit C fixture AddressSanitizer fallback run"
            exit 1
        fi
    elif [ "$asan_status" -ne 0 ]; then
        cat "$test_tmp/c-explicit-record-asan.log"
        echo "FAIL: explicit C fixture AddressSanitizer/LeakSanitizer run"
        exit 1
    fi
fi

# Verify one inline SEQUENCE child with mixed codec generation and shared context.
nested_ber_cer_out="$test_tmp/nested-ber-cer-rust"
"$asn1c_bin" --rust -gen-BER -S "$skeletons" -D "$nested_ber_cer_out" \
    "$test_srcdir/NestedBerCer.asn1"
mkdir "$nested_ber_cer_out/tests"
cp "$test_srcdir/nested_ber_cer_conformance.rs" "$nested_ber_cer_out/tests/"
if ! (cd "$nested_ber_cer_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-ber-cer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-ber-cer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/nested-ber-cer-check.log" 2>&1; then
    cat "$test_tmp/nested-ber-cer-check.log"
    echo "FAIL: nested mixed-codec SEQUENCE tests or strict Clippy"
    exit 1
fi
for method in encode_der decode_ber encode_cer decode_cer encode_uper decode_uper; do
    grep -F "pub fn $method" "$nested_ber_cer_out/src/nested_records.rs" >/dev/null
done
grep -F "RecordContext::new_nested(limits)" \
    "$nested_ber_cer_out/src/nested_records.rs" >/dev/null

# Empty children are checked in BER/CER-only output so UPER remains unaffected.
nested_empty_out="$test_tmp/nested-empty-ber-cer-rust"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -S "$skeletons" \
    -D "$nested_empty_out" "$test_srcdir/NestedEmptyBerCer.asn1"
mkdir "$nested_empty_out/tests"
cp "$test_srcdir/nested_empty_ber_cer_conformance.rs" "$nested_empty_out/tests/"
if ! (cd "$nested_empty_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-empty-ber-cer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-empty-ber-cer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/nested-empty-ber-cer-check.log" 2>&1; then
    cat "$test_tmp/nested-empty-ber-cer-check.log"
    echo "FAIL: empty nested BER/CER test or strict Clippy"
    exit 1
fi
grep -F "RecordContext::new_nested(limits)" \
    "$nested_empty_out/src/nested_empty_records.rs" >/dev/null
if "$asn1c_bin" --rust -gen-BER -S "$skeletons" \
    -D "$test_tmp/rejected-empty-child-mixed" \
    "$test_srcdir/NestedEmptyBerCer.asn1" \
    >"$test_tmp/empty-child-mixed.log" 2>&1; then
    echo "FAIL: empty nested child mixed UPER/BER/CER selection was accepted"
    exit 1
fi
test ! -e "$test_tmp/rejected-empty-child-mixed"

# BER/CER SET stays isolated from UPER while exercising the same child callback.
nested_set_out="$test_tmp/nested-set-ber-cer-rust"
"$asn1c_bin" --rust -gen-BER -no-gen-UPER -S "$skeletons" \
    -D "$nested_set_out" "$test_srcdir/NestedSetBerCer.asn1"
mkdir "$nested_set_out/tests"
cp "$test_srcdir/nested_set_ber_cer_conformance.rs" "$nested_set_out/tests/"
if ! (cd "$nested_set_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-set-ber-cer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-set-ber-cer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/nested-set-ber-cer-check.log" 2>&1; then
    cat "$test_tmp/nested-set-ber-cer-check.log"
    echo "FAIL: nested BER/CER SET tests or strict Clippy"
    exit 1
fi
grep -F "RecordContext::new_nested(limits)" \
    "$nested_set_out/src/nested_set_records.rs" >/dev/null

# Independently confirm the shared DER/CER vectors with generated C code.
nested_c_out="$test_tmp/nested-records-c"
mkdir "$nested_c_out"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -fwide-types -pdu=all \
    -fgen-only-pdu-deps -no-gen-example -D "$nested_c_out" \
    "$test_srcdir/NestedBerCer.asn1" "$test_srcdir/NestedSetBerCer.asn1" \
    "$test_srcdir/NestedEmptyBerCer.asn1" \
    >"$test_tmp/nested-records-c-generate.log" 2>&1
nested_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$nested_c_out/Makefile.am.libasncodec")
rm -f "$nested_c_out/converter-example.c" "$nested_c_out/pdu_collection.c"
if ! cc $nested_cflags -I"$nested_c_out" "$nested_c_out"/*.c \
    "$test_srcdir/c_nested_ber_cer.c" -lm -o "$test_tmp/c-nested-ber-cer" \
    >"$test_tmp/c-nested-ber-cer-compile.log" 2>&1; then
    cat "$test_tmp/c-nested-ber-cer-compile.log"
    echo "FAIL: generated C nested BER/CER reference did not compile"
    exit 1
fi
if ! "$test_tmp/c-nested-ber-cer"; then
    echo "FAIL: C nested DER/CER vectors did not match"
    exit 1
fi
if ! cc $nested_cflags -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$nested_c_out" "$nested_c_out"/*.c \
    "$test_srcdir/c_nested_ber_cer.c" -lm -o "$test_tmp/c-nested-ber-cer-sanitized" \
    >"$test_tmp/c-nested-ber-cer-sanitizer-build.log" 2>&1; then
    echo "SKIP: C compiler does not support AddressSanitizer and UndefinedBehaviorSanitizer"
else
    if [ "$(uname -s)" = Darwin ]; then
        ASAN_OPTIONS=detect_leaks=0 "$test_tmp/c-nested-ber-cer-sanitized"
    else
        "$test_tmp/c-nested-ber-cer-sanitized"
    fi
fi

# Verify one inline SET child under untagged SEQUENCE and SET roots.
nested_set_child_out="$test_tmp/nested-set-child-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$nested_set_child_out" "$test_srcdir/NestedSetChildren.asn1"
mkdir "$nested_set_child_out/tests"
cp "$test_srcdir/nested_set_children_conformance.rs" "$nested_set_child_out/tests/"
if ! (cd "$nested_set_child_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-set-child" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-nested-set-child" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/nested-set-child-check.log" 2>&1; then
    cat "$test_tmp/nested-set-child-check.log"
    echo "FAIL: nested SET child tests or strict Clippy"
    exit 1
fi
grep -F "RecordContext::new_nested(limits)" \
    "$nested_set_child_out/src/nested_set_children.rs" >/dev/null

# Compile and execute independent C DER/CER vectors for the same nested SETs.
nested_set_child_c_out="$test_tmp/nested-set-child-c"
mkdir "$nested_set_child_c_out"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -fwide-types -pdu=all \
    -fgen-only-pdu-deps -no-gen-example -D "$nested_set_child_c_out" \
    "$test_srcdir/NestedSetChildren.asn1" \
    >"$test_tmp/nested-set-child-c-generate.log" 2>&1
nested_set_child_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$nested_set_child_c_out/Makefile.am.libasncodec")
rm -f "$nested_set_child_c_out/converter-example.c" \
    "$nested_set_child_c_out/pdu_collection.c"
if ! cc $nested_set_child_cflags -I"$nested_set_child_c_out" \
    "$nested_set_child_c_out"/*.c "$test_srcdir/c_nested_set_child.c" \
    -lm -o "$test_tmp/c-nested-set-child" \
    >"$test_tmp/c-nested-set-child-compile.log" 2>&1; then
    cat "$test_tmp/c-nested-set-child-compile.log"
    echo "FAIL: generated C nested SET child reference did not compile"
    exit 1
fi
if ! "$test_tmp/c-nested-set-child"; then
    echo "FAIL: C nested SET child DER/CER or decode vectors did not match"
    exit 1
fi

# BER-only and CER-only nested SET selections also pass exact strict Clippy.
for codec in ber cer; do
    codec_out="$test_tmp/nested-set-child-$codec-only"
    if [ "$codec" = ber ]; then
        codec_flags="-gen-BER -no-gen-CER"
    else
        codec_flags="-gen-CER -no-gen-BER"
    fi
    # shellcheck disable=SC2086
    "$asn1c_bin" --rust $codec_flags -no-gen-UPER -no-gen-CBOR -no-gen-XER \
        -no-gen-JER -no-gen-APER -no-gen-OER -S "$skeletons" \
        -D "$codec_out" "$test_srcdir/NestedSetChildren.asn1"
    if ! (cd "$codec_out" && \
        CARGO_TARGET_DIR="$test_tmp/target-nested-set-child-$codec" \
        cargo clippy --offline --all-targets --all-features -- \
        -W clippy::pedantic -W clippy::nursery -D warnings) \
        >"$test_tmp/nested-set-child-$codec-only.log" 2>&1; then
        cat "$test_tmp/nested-set-child-$codec-only.log"
        echo "FAIL: nested SET child $codec-only strict Clippy"
        exit 1
    fi
done

# Excluded schemas and mixed selection must fail before output publication.
for rejected_schema in NestedSetEmpty NestedSetNested NestedSetMultiple \
    NestedSetDefault NestedSetExtension NestedSetAlias NestedSetLeafAlias \
    NestedSetTaggedRoot; do
    rejected_out="$test_tmp/rejected-$rejected_schema"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$rejected_schema.asn1" \
        >"$test_tmp/$rejected_schema.log" 2>&1; then
        echo "FAIL: unsupported nested SET schema $rejected_schema was accepted"
        exit 1
    fi
    test ! -e "$rejected_out"
done
mixed_nested_set_out="$test_tmp/rejected-nested-set-mixed-codecs"
if "$asn1c_bin" --rust -gen-BER -gen-CER -S "$skeletons" \
    -D "$mixed_nested_set_out" "$test_srcdir/NestedSetChildren.asn1" \
    >"$test_tmp/nested-set-mixed-codecs.log" 2>&1; then
    echo "FAIL: nested SET mixed UPER/BER/CER selection was accepted"
    exit 1
fi
test ! -e "$mixed_nested_set_out"
nested_set_import_out="$test_tmp/rejected-nested-set-import"
if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$nested_set_import_out" "$test_srcdir/NestedSetImportSource.asn1" \
    "$test_srcdir/NestedSetImport.asn1" \
    >"$test_tmp/nested-set-import.log" 2>&1; then
    echo "FAIL: nested SET with an imported leaf was accepted"
    exit 1
fi
test ! -e "$nested_set_import_out"

# Fail closed on SET shapes and codec combinations outside the current slice.
cat >"$test_tmp/SetApplication.asn1" <<'EOF'
SetApplication DEFINITIONS ::= BEGIN
Packet ::= SET { flag [APPLICATION 2] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SetPrivate.asn1" <<'EOF'
SetPrivate DEFINITIONS ::= BEGIN
Packet ::= SET { flag [PRIVATE 2] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SetUniversal.asn1" <<'EOF'
SetUniversal DEFINITIONS ::= BEGIN
Packet ::= SET { flag [UNIVERSAL 1] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SetRepeatedContextTag.asn1" <<'EOF'
SetRepeatedContextTag DEFINITIONS ::= BEGIN
Packet ::= SET { first [2] IMPLICIT BOOLEAN, second [2] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SetTooHighTag.asn1" <<'EOF'
SetTooHighTag DEFINITIONS ::= BEGIN
Packet ::= SET { flag [1073741824] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SetTaggedAny.asn1" <<'EOF'
SetTaggedAny DEFINITIONS ::= BEGIN
Packet ::= SET { value [5] EXPLICIT ANY }
END
EOF
cat >"$test_tmp/SetAlias.asn1" <<'EOF'
SetAlias DEFINITIONS ::= BEGIN
Flag ::= BOOLEAN
Packet ::= SET { flag Flag }
END
EOF
cat >"$test_tmp/SetNested.asn1" <<'EOF'
SetNested DEFINITIONS ::= BEGIN
Packet ::= SET { child SEQUENCE { nested SEQUENCE { flag BOOLEAN } } }
END
EOF
cat >"$test_tmp/SetRepeatedTag.asn1" <<'EOF'
SetRepeatedTag DEFINITIONS ::= BEGIN
Packet ::= SET { first OCTET STRING (SIZE(1)), second OCTET STRING (SIZE(2)) }
END
EOF
cat >"$test_tmp/SetNullDefault.asn1" <<'EOF'
SetNullDefault DEFINITIONS ::= BEGIN
Packet ::= SET { empty NULL DEFAULT NULL }
END
EOF
cat >"$test_tmp/SetEnumDefault.asn1" <<'EOF'
SetEnumDefault DEFINITIONS ::= BEGIN
Packet ::= SET { state ENUMERATED { idle(0), busy(1) } DEFAULT idle }
END
EOF
cat >"$test_tmp/SetStringDefault.asn1" <<'EOF'
SetStringDefault DEFINITIONS ::= BEGIN
Packet ::= SET { value OCTET STRING (SIZE(1..2)) DEFAULT '41'H }
END
EOF
cat >"$test_tmp/SetUnbounded.asn1" <<'EOF'
SetUnbounded DEFINITIONS ::= BEGIN
Packet ::= SET { value OCTET STRING }
END
EOF
cat >"$test_tmp/SetDisjointSize.asn1" <<'EOF'
SetDisjointSize DEFINITIONS ::= BEGIN
Packet ::= SET { value BIT STRING (SIZE(1..2 | 4..5)) }
END
EOF
cat >"$test_tmp/SetExtensibleSize.asn1" <<'EOF'
SetExtensibleSize DEFINITIONS ::= BEGIN
Packet ::= SET { value OCTET STRING (SIZE(1..3,...)) }
END
EOF
cat >"$test_tmp/SetContaining.asn1" <<'EOF'
SetContaining DEFINITIONS ::= BEGIN
Packet ::= SET { value OCTET STRING (CONTAINING INTEGER) }
END
EOF
cat >"$test_tmp/SetNamedBits.asn1" <<'EOF'
SetNamedBits DEFINITIONS ::= BEGIN
Packet ::= SET { value BIT STRING { red(0), blue(1) } (SIZE(1..2)) }
END
EOF
cat >"$test_tmp/SetExtensibleEnum.asn1" <<'EOF'
SetExtensibleEnum DEFINITIONS ::= BEGIN
Packet ::= SET { state ENUMERATED { idle(0), ..., busy(1) } }
END
EOF
cat >"$test_tmp/SetExtension.asn1" <<'EOF'
SetExtension DEFINITIONS ::= BEGIN
Packet ::= SET { flag BOOLEAN, ..., empty NULL }
END
EOF
for fixture in SetApplication SetPrivate SetUniversal \
    SetRepeatedContextTag SetTooHighTag SetTaggedAny SetAlias SetNested SetRepeatedTag \
    SetNullDefault SetEnumDefault SetStringDefault SetUnbounded SetDisjointSize \
    SetExtensibleSize SetContaining SetNamedBits SetExtensibleEnum SetExtension; do
    if "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER \
        -S "$skeletons" -D "$test_tmp/rejected-$fixture" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust BER backend accepted unsupported $fixture"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$fixture"
done

if "$asn1c_bin" --rust -gen-BER -S "$skeletons" \
    -D "$test_tmp/rejected-set-uper-mix" "$test_srcdir/SetBerCer.asn1" \
    >"$test_tmp/set-uper-mix.log" 2>&1; then
    echo "FAIL: BER SET backend accepted the default UPER codec mix"
    exit 1
fi
test ! -e "$test_tmp/rejected-set-uper-mix"
if "$asn1c_bin" --rust -gen-BER -gen-XER -no-gen-UPER -no-gen-CER \
    -S "$skeletons" -D "$test_tmp/rejected-set-xer-mix" "$test_srcdir/SetBerCer.asn1" \
    >"$test_tmp/set-xer-mix.log" 2>&1; then
    echo "FAIL: binary SET backend accepted a mixed XER codec mask"
    exit 1
fi
test ! -e "$test_tmp/rejected-set-xer-mix"

# Reject unsupported tag classes/modes, collisions, aliases, and shapes.
cat >"$test_tmp/SequenceBerCerApplication.asn1" <<'EOF'
SequenceBerCerApplication DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { flag [APPLICATION 2] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerPrivate.asn1" <<'EOF'
SequenceBerCerPrivate DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { flag [PRIVATE 2] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerRepeatedContext.asn1" <<'EOF'
SequenceBerCerRepeatedContext DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { first [2] IMPLICIT BOOLEAN, second [2] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerTooHighTag.asn1" <<'EOF'
SequenceBerCerTooHighTag DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { flag [1073741824] IMPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerTaggedAny.asn1" <<'EOF'
SequenceBerCerTaggedAny DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { value [5] EXPLICIT ANY }
END
EOF
cat >"$test_tmp/SequenceBerCerExplicitAlias.asn1" <<'EOF'
SequenceBerCerExplicitAlias DEFINITIONS ::= BEGIN
Flag ::= BOOLEAN
Packet ::= SEQUENCE { flag [0] EXPLICIT Flag }
END
EOF
cat >"$test_tmp/SequenceBerCerExplicitClass.asn1" <<'EOF'
SequenceBerCerExplicitClass DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { flag [APPLICATION 2] EXPLICIT BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerExplicitRoot.asn1" <<'EOF'
SequenceBerCerExplicitRoot DEFINITIONS ::= BEGIN
Packet ::= [0] EXPLICIT SEQUENCE { flag BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerDuplicate.asn1" <<'EOF'
SequenceBerCerDuplicate DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { first BOOLEAN, second BOOLEAN }
END
EOF
cat >"$test_tmp/SequenceBerCerNested.asn1" <<'EOF'
SequenceBerCerNested DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE {
    child SEQUENCE { nested SEQUENCE { number INTEGER (0..10) } }
}
END
EOF
cat >"$test_tmp/SequenceBerCerUnbounded.asn1" <<'EOF'
SequenceBerCerUnbounded DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { number INTEGER }
END
EOF
cat >"$test_tmp/SequenceBerCerNullDefault.asn1" <<'EOF'
SequenceBerCerNullDefault DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { empty NULL DEFAULT NULL }
END
EOF
cat >"$test_tmp/SequenceBerCerEnumDefault.asn1" <<'EOF'
SequenceBerCerEnumDefault DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { state ENUMERATED { idle(0), busy(1) } DEFAULT idle }
END
EOF
cat >"$test_tmp/SequenceBerCerOctetDefault.asn1" <<'EOF'
SequenceBerCerOctetDefault DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data OCTET STRING (SIZE(1..2)) DEFAULT 'AB'H }
END
EOF
cat >"$test_tmp/SequenceBerCerBitDefault.asn1" <<'EOF'
SequenceBerCerBitDefault DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data BIT STRING (SIZE(1..2)) DEFAULT '1'B }
END
EOF
cat >"$test_tmp/SequenceBerCerUnboundedString.asn1" <<'EOF'
SequenceBerCerUnboundedString DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data OCTET STRING }
END
EOF
cat >"$test_tmp/SequenceBerCerExtensibleString.asn1" <<'EOF'
SequenceBerCerExtensibleString DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data BIT STRING (SIZE(1..3,...)) }
END
EOF
cat >"$test_tmp/SequenceBerCerContaining.asn1" <<'EOF'
SequenceBerCerContaining DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data OCTET STRING (CONTAINING INTEGER) }
END
EOF
cat >"$test_tmp/SequenceBerCerNamedBits.asn1" <<'EOF'
SequenceBerCerNamedBits DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data BIT STRING { red(0), blue(1) } (SIZE(1..2)) }
END
EOF
cat >"$test_tmp/SequenceBerCerTooMany.asn1" <<'EOF'
SequenceBerCerTooMany DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE {
    a BOOLEAN, b INTEGER (0..1), c BIT STRING (SIZE(1)),
    d OCTET STRING (SIZE(1)), e NULL,
    f ENUMERATED { one(1) }, g BOOLEAN
}
END
EOF
cat >"$test_tmp/SequenceBerCerRepeatedOctets.asn1" <<'EOF'
SequenceBerCerRepeatedOctets DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { first OCTET STRING (SIZE(1)), second OCTET STRING (SIZE(2)) }
END
EOF
cat >"$test_tmp/SequenceBerCerDisjointSize.asn1" <<'EOF'
SequenceBerCerDisjointSize DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { data OCTET STRING (SIZE(1..2 | 4..5)) }
END
EOF
cat >"$test_tmp/SequenceBerCerExtensibleEnum.asn1" <<'EOF'
SequenceBerCerExtensibleEnum DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { state ENUMERATED { idle(0), ..., busy(1) } }
END
EOF
cat >"$test_tmp/SequenceBerCerNestedSet.asn1" <<'EOF'
SequenceBerCerNestedSet DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { child SEQUENCE { item SET { value INTEGER (0..10) } } }
END
EOF
cat >"$test_tmp/SequenceBerCerNestedChoice.asn1" <<'EOF'
SequenceBerCerNestedChoice DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { child SEQUENCE { item CHOICE { value INTEGER (0..10) } } }
END
EOF
cat >"$test_tmp/SequenceBerCerNestedOf.asn1" <<'EOF'
SequenceBerCerNestedOf DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { child SEQUENCE { items SEQUENCE OF INTEGER (0..10) } }
END
EOF
cat >"$test_tmp/SequenceBerCerNestedAny.asn1" <<'EOF'
SequenceBerCerNestedAny DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { child SEQUENCE { item ANY } }
END
EOF
cat >"$test_tmp/SequenceBerCerNestedDefault.asn1" <<'EOF'
SequenceBerCerNestedDefault DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { child SEQUENCE { value INTEGER (0..10) DEFAULT 0 } }
END
EOF
cat >"$test_tmp/SequenceBerCerConstructedDefault.asn1" <<'EOF'
SequenceBerCerConstructedDefault DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE {
    child SEQUENCE { value INTEGER (0..10) } DEFAULT { value 0 }
}
END
EOF
cat >"$test_tmp/SequenceBerCerNestedExtension.asn1" <<'EOF'
SequenceBerCerNestedExtension DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE { child SEQUENCE { value INTEGER (0..10), ..., extra BOOLEAN } }
END
EOF
cat >"$test_tmp/SequenceBerCerNestedReference.asn1" <<'EOF'
SequenceBerCerNestedReference DEFINITIONS ::= BEGIN
Child ::= SEQUENCE { value INTEGER (0..10) }
Packet ::= SEQUENCE { child Child }
END
EOF
cat >"$test_tmp/SequenceBerCerMultipleNested.asn1" <<'EOF'
SequenceBerCerMultipleNested DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE {
    first SEQUENCE { value INTEGER (0..10) },
    second SEQUENCE { value BOOLEAN }
}
END
EOF
cat >"$test_tmp/SequenceBerCerNestedCollision.asn1" <<'EOF'
SequenceBerCerNestedCollision DEFINITIONS ::= BEGIN
Packet ::= SEQUENCE {
    child SEQUENCE {
        first [2] IMPLICIT INTEGER (0..10),
        second [2] IMPLICIT BOOLEAN
    }
}
END
EOF
for fixture in SequenceBerCerApplication \
    SequenceBerCerPrivate SequenceBerCerRepeatedContext SequenceBerCerTooHighTag \
    SequenceBerCerTaggedAny SequenceBerCerExplicitAlias \
    SequenceBerCerExplicitClass SequenceBerCerExplicitRoot \
    SequenceBerCerDuplicate SequenceBerCerNested \
    SequenceBerCerUnbounded SequenceBerCerNullDefault \
    SequenceBerCerEnumDefault SequenceBerCerOctetDefault \
    SequenceBerCerBitDefault SequenceBerCerUnboundedString \
    SequenceBerCerExtensibleString SequenceBerCerContaining \
    SequenceBerCerNamedBits SequenceBerCerTooMany \
    SequenceBerCerRepeatedOctets SequenceBerCerDisjointSize \
    SequenceBerCerExtensibleEnum \
    SequenceBerCerNestedSet SequenceBerCerNestedChoice \
    SequenceBerCerNestedOf SequenceBerCerNestedAny \
    SequenceBerCerNestedDefault SequenceBerCerConstructedDefault \
    SequenceBerCerNestedExtension \
    SequenceBerCerNestedReference SequenceBerCerMultipleNested \
    SequenceBerCerNestedCollision; do
    if "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER \
        -S "$skeletons" -D "$test_tmp/rejected-$fixture" \
        "$test_tmp/$fixture.asn1" >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust BER backend accepted unsupported $fixture"
        exit 1
    fi
    test ! -e "$test_tmp/rejected-$fixture"
done

# Named BIT STRING roots require special trimming and remain outside this slice.
if "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-named-bits-ber" "$test_srcdir/NamedBitString.asn1" \
    >"$test_tmp/named-bits-ber.log" 2>&1; then
    echo "FAIL: Rust backend accepted named BIT STRING BER methods"
    exit 1
fi
test ! -e "$test_tmp/rejected-named-bits-ber"
if "$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$test_tmp/rejected-named-bits-cer" "$test_srcdir/NamedBitString.asn1" \
    >"$test_tmp/named-bits-cer.log" 2>&1; then
    echo "FAIL: Rust backend accepted named BIT STRING CER methods"
    exit 1
fi
test ! -e "$test_tmp/rejected-named-bits-cer"
if "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$test_tmp/rejected-extensible-enum-ber" "$test_srcdir/ExtensibleEnum.asn1" \
    >"$test_tmp/extensible-enum-ber.log" 2>&1; then
    echo "FAIL: Rust backend accepted extensible ENUMERATED BER methods"
    exit 1
fi
test ! -e "$test_tmp/rejected-extensible-enum-ber"
if "$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
    -D "$test_tmp/rejected-extensible-enum-cer" "$test_srcdir/ExtensibleEnum.asn1" \
    >"$test_tmp/extensible-enum-cer.log" 2>&1; then
    echo "FAIL: Rust backend accepted extensible ENUMERATED CER methods"
    exit 1
fi
test ! -e "$test_tmp/rejected-extensible-enum-cer"

# Unconstrained INTEGER uses the private arbitrary-precision BER/CER wrapper.
big_integer_mixed="$test_tmp/rejected-big-integer-default"
if "$asn1c_bin" --rust -S "$skeletons" -D "$big_integer_mixed" \
    "$test_srcdir/BigInteger.asn1" >"$test_tmp/big-integer-default.log" 2>&1; then
    echo "FAIL: default mixed codecs accepted unconstrained INTEGER"
    exit 1
fi
grep -F 'unconstrained INTEGER requires BER/CER-only codec selection' \
    "$test_tmp/big-integer-default.log" >/dev/null
test ! -e "$big_integer_mixed"

big_integer_mixed="$test_tmp/rejected-big-integer-uper"
if "$asn1c_bin" --rust -gen-BER -gen-UPER -no-gen-CER -S "$skeletons" \
    -D "$big_integer_mixed" "$test_srcdir/BigInteger.asn1" \
    >"$test_tmp/big-integer-uper.log" 2>&1; then
    echo "FAIL: BER/UPER mixed selection accepted unconstrained INTEGER"
    exit 1
fi
test ! -e "$big_integer_mixed"

for fixture in BigIntegerMinMax BigIntegerTagged BigIntegerField; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported BigInteger fixture $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

big_integer_out="$test_tmp/big-integer-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$big_integer_out" "$test_srcdir/BigInteger.asn1"
mkdir "$big_integer_out/tests"
cp "$test_srcdir/big_integer_conformance.rs" "$big_integer_out/tests/"
big_integer_source="$big_integer_out/src/big_integer.rs"
for method in try_from_signed_bytes as_signed_bytes try_to_i64 \
    encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$big_integer_source" >/dev/null
done
if grep -F '#[derive(Clone' "$big_integer_source" >/dev/null; then
    echo "FAIL: arbitrary-precision generated wrapper derives Clone"
    exit 1
fi
if ! (cd "$big_integer_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-big-integer" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-big-integer" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/big-integer-rust.log" 2>&1; then
    cat "$test_tmp/big-integer-rust.log"
    echo "FAIL: BigInteger conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        unwanted='encode_cer|decode_cer'
        codec_out="$test_tmp/big-integer-BER-only"
        "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER \
            -S "$skeletons" -D "$codec_out" "$test_srcdir/BigInteger.asn1"
    else
        unwanted='encode_der|decode_ber'
        codec_out="$test_tmp/big-integer-CER-only"
        "$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER \
            -S "$skeletons" -D "$codec_out" "$test_srcdir/BigInteger.asn1"
    fi
    if (cargo check --offline --manifest-path "$codec_out/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$codec_out/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
        >"$test_tmp/big-integer-$codec-only.log" 2>&1; then
        :
    else
        cat "$test_tmp/big-integer-$codec-only.log"
        echo "FAIL: BigInteger $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($unwanted)" "$codec_out/src/big_integer.rs" >/dev/null; then
        echo "FAIL: BigInteger $codec-only output includes the unselected codec"
        exit 1
    fi
done

# C wide INTEGER is the arbitrary-precision comparison target for this slice.
big_integer_c="$test_tmp/big-integer-c"
mkdir "$big_integer_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -fwide-types -pdu=all \
    -fgen-only-pdu-deps -no-gen-example -D "$big_integer_c" \
    "$test_srcdir/BigInteger.asn1" >"$test_tmp/big-integer-c-generate.log" 2>&1
big_integer_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$big_integer_c/Makefile.am.libasncodec")
rm -f "$big_integer_c/converter-example.c" "$big_integer_c/pdu_collection.c"
if ! cc $big_integer_cflags -I"$big_integer_c" "$big_integer_c"/*.c \
    "$test_srcdir/c_big_integer.c" -lm -o "$test_tmp/c-big-integer" \
    >"$test_tmp/big-integer-c-compile.log" 2>&1; then
    cat "$test_tmp/big-integer-c-compile.log"
    echo "FAIL: C wide INTEGER reference did not compile"
    exit 1
fi
if ! "$test_tmp/c-big-integer"; then
    echo "FAIL: C wide INTEGER DER/CER vectors or decode probes did not match"
    exit 1
fi

# Unconstrained strings are available only as direct BER/CER root values.
for fixture in UnconstrainedStringsNamedBits UnconstrainedStringsSize \
    UnconstrainedStringsTagged UnconstrainedStringsContaining \
    UnconstrainedStringsAlias UnconstrainedStringsField \
    UnconstrainedStringsImport; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported unconstrained string shape $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

unbounded_strings_mixed="$test_tmp/rejected-unconstrained-strings-mixed"
if "$asn1c_bin" --rust -S "$skeletons" -D "$unbounded_strings_mixed" \
    "$test_srcdir/UnconstrainedStrings.asn1" \
    >"$test_tmp/unconstrained-strings-mixed.log" 2>&1; then
    echo "FAIL: mixed default codecs accepted unbounded strings"
    exit 1
fi
test ! -e "$unbounded_strings_mixed"
unbounded_strings_uper="$test_tmp/rejected-unconstrained-strings-uper"
if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$unbounded_strings_uper" "$test_srcdir/UnconstrainedStrings.asn1" \
    >"$test_tmp/unconstrained-strings-uper.log" 2>&1; then
    echo "FAIL: UPER-only selection accepted unbounded strings"
    exit 1
fi
test ! -e "$unbounded_strings_uper"

unbounded_strings_out="$test_tmp/unconstrained-strings-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$unbounded_strings_out" "$test_srcdir/UnconstrainedStrings.asn1"
mkdir "$unbounded_strings_out/tests"
cp "$test_srcdir/unconstrained_strings_conformance.rs" \
    "$unbounded_strings_out/tests/"
unbounded_strings_source="$unbounded_strings_out/src/unconstrained_strings.rs"
for method in new as_bytes as_bit_string encode_der decode_ber encode_cer decode_cer; do
    if ! grep -Eq "pub (const )?fn $method" "$unbounded_strings_source"; then
        echo "FAIL: unconstrained string wrapper is missing $method"
        exit 1
    fi
done
if ! grep -Eq 'pub (const )?fn bit_len' "$unbounded_strings_source"; then
    echo "FAIL: unconstrained BIT STRING wrapper is missing bit_len"
    exit 1
fi
if grep -F '#[derive(Clone' "$unbounded_strings_source" >/dev/null; then
    echo "FAIL: unconstrained string wrappers derive Clone"
    exit 1
fi
if ! (cd "$unbounded_strings_out" && \
    CARGO_TARGET_DIR="$test_tmp/target-unconstrained-strings" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-unconstrained-strings" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/unconstrained-strings-rust.log" 2>&1; then
    cat "$test_tmp/unconstrained-strings-rust.log"
    echo "FAIL: unbounded string conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        unbounded_unwanted='encode_cer|decode_cer'
    else
        unbounded_unwanted='encode_der|decode_ber'
    fi
    unbounded_codec_out="$test_tmp/unconstrained-strings-$codec-only"
    if [ "$codec" = BER ]; then
        "$asn1c_bin" --rust -gen-BER -no-gen-UPER -no-gen-CER -S "$skeletons" \
            -D "$unbounded_codec_out" "$test_srcdir/UnconstrainedStrings.asn1"
    else
        "$asn1c_bin" --rust -gen-CER -no-gen-UPER -no-gen-BER -S "$skeletons" \
            -D "$unbounded_codec_out" "$test_srcdir/UnconstrainedStrings.asn1"
    fi
    if (cargo check --offline --manifest-path "$unbounded_codec_out/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$unbounded_codec_out/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -D warnings) \
        >"$test_tmp/unconstrained-strings-$codec-only.log" 2>&1; then
        :
    else
        cat "$test_tmp/unconstrained-strings-$codec-only.log"
        echo "FAIL: unbounded string $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($unbounded_unwanted)" \
        "$unbounded_codec_out/src/unconstrained_strings.rs" >/dev/null; then
        echo "FAIL: unbounded string $codec-only output has unselected methods"
        exit 1
    fi
done

# Generated C provides an independent BER/DER/CER reference for all boundaries.
unbounded_strings_c="$test_tmp/unconstrained-strings-c"
mkdir "$unbounded_strings_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$unbounded_strings_c" \
    "$test_srcdir/UnconstrainedStrings.asn1" \
    >"$test_tmp/unconstrained-strings-c-generate.log" 2>&1
unbounded_strings_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$unbounded_strings_c/Makefile.am.libasncodec")
rm -f "$unbounded_strings_c/converter-example.c" \
    "$unbounded_strings_c/pdu_collection.c"
if ! cc $unbounded_strings_cflags -I"$unbounded_strings_c" \
    "$unbounded_strings_c"/*.c "$test_srcdir/c_unconstrained_strings.c" \
    -lm -o "$test_tmp/c-unconstrained-strings" \
    >"$test_tmp/unconstrained-strings-c-compile.log" 2>&1; then
    cat "$test_tmp/unconstrained-strings-c-compile.log"
    echo "FAIL: C unbounded string reference did not compile"
    exit 1
fi
if ! "$test_tmp/c-unconstrained-strings"; then
    echo "FAIL: C unbounded string DER/CER vectors or decode probes did not match"
    exit 1
fi

# Direct OID values accept BER/CER only and keep canonical content private.
for fixture in OidValuesAlias OidValuesConstrained OidValuesField \
    OidValuesImport OidValuesTagged RelativeOidConstrained RelativeOidTagged; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported OID shape $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

oid_mixed="$test_tmp/rejected-oid-mixed"
if "$asn1c_bin" --rust -S "$skeletons" -D "$oid_mixed" \
    "$test_srcdir/OidValues.asn1" >"$test_tmp/oid-mixed.log" 2>&1; then
    echo "FAIL: mixed default codecs accepted direct OIDs"
    exit 1
fi
test ! -e "$oid_mixed"
oid_uper="$test_tmp/rejected-oid-uper"
if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$oid_uper" "$test_srcdir/OidValues.asn1" >"$test_tmp/oid-uper.log" 2>&1; then
    echo "FAIL: UPER-only selection accepted direct OIDs"
    exit 1
fi
test ! -e "$oid_uper"

oid_rust="$test_tmp/oid-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$oid_rust" "$test_srcdir/OidValues.asn1"
mkdir "$oid_rust/tests"
cp "$test_srcdir/oid_conformance.rs" "$oid_rust/tests/"
oid_source="$oid_rust/src/oid_values.rs"
for method in try_from_content as_content encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$oid_source" >/dev/null
done
if grep -F '#[derive(Clone' "$oid_source" >/dev/null; then
    echo "FAIL: OID wrappers derive infallible Clone"
    exit 1
fi
if ! (cd "$oid_rust" && \
    CARGO_TARGET_DIR="$test_tmp/target-oid" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-oid" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/oid-rust.log" 2>&1; then
    cat "$test_tmp/oid-rust.log"
    echo "FAIL: OID conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        oid_unwanted='encode_cer|decode_cer'
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/oid-$codec-only" "$test_srcdir/OidValues.asn1"
    else
        oid_unwanted='encode_der|decode_ber'
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/oid-$codec-only" "$test_srcdir/OidValues.asn1"
    fi
    oid_codec_out="$test_tmp/oid-$codec-only"
    if (cargo check --offline --manifest-path "$oid_codec_out/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$oid_codec_out/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic \
        -W clippy::nursery -D warnings) >"$test_tmp/oid-$codec-only.log" 2>&1; then
        :
    else
        cat "$test_tmp/oid-$codec-only.log"
        echo "FAIL: OID $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($oid_unwanted)" "$oid_codec_out/src/oid_values.rs" >/dev/null; then
        echo "FAIL: OID $codec-only output has unselected methods"
        exit 1
    fi
done

oid_c="$test_tmp/oid-c"
mkdir "$oid_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$oid_c" "$test_srcdir/OidValues.asn1" \
    >"$test_tmp/oid-c-generate.log" 2>&1
oid_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' "$oid_c/Makefile.am.libasncodec")
rm -f "$oid_c/converter-example.c" "$oid_c/pdu_collection.c"
if ! cc $oid_cflags -I"$oid_c" "$oid_c"/*.c "$test_srcdir/c_oid.c" \
    -lm -o "$test_tmp/c-oid" >"$test_tmp/oid-c-compile.log" 2>&1; then
    cat "$test_tmp/oid-c-compile.log"
    echo "FAIL: C OID differential fixture did not compile"
    exit 1
fi
if ! "$test_tmp/c-oid"; then
    echo "FAIL: C OID DER/CER vectors or BER compatibility probes failed"
    exit 1
fi

# Direct unconstrained IA5String keeps BER/DER raw-byte timing and strict CER.
for fixture in Ia5ValuesAlias Ia5ValuesConstrained Ia5ValuesField \
    Ia5ValuesImport Ia5ValuesTagged; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported IA5 shape $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

ia5_mixed="$test_tmp/rejected-ia5-mixed"
if "$asn1c_bin" --rust -S "$skeletons" -D "$ia5_mixed" \
    "$test_srcdir/Ia5Values.asn1" >"$test_tmp/ia5-mixed.log" 2>&1; then
    echo "FAIL: mixed default codecs accepted direct IA5String"
    exit 1
fi
test ! -e "$ia5_mixed"
ia5_uper="$test_tmp/rejected-ia5-uper"
if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$ia5_uper" "$test_srcdir/Ia5Values.asn1" \
    >"$test_tmp/ia5-uper.log" 2>&1; then
    echo "FAIL: UPER-only selection accepted direct IA5String"
    exit 1
fi
test ! -e "$ia5_uper"

ia5_rust="$test_tmp/ia5-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$ia5_rust" "$test_srcdir/Ia5Values.asn1"
mkdir "$ia5_rust/tests"
cp "$test_srcdir/ia5_conformance.rs" "$ia5_rust/tests/"
ia5_source="$ia5_rust/src/ia5_values.rs"
for method in try_from_bytes as_bytes encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$ia5_source" >/dev/null
done
if grep -F '#[derive(Clone' "$ia5_source" >/dev/null; then
    echo "FAIL: IA5 wrapper derives infallible Clone"
    exit 1
fi
if ! (cd "$ia5_rust" && \
    CARGO_TARGET_DIR="$test_tmp/target-ia5" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-ia5" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/ia5-rust.log" 2>&1; then
    cat "$test_tmp/ia5-rust.log"
    echo "FAIL: IA5 conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        ia5_unwanted='encode_cer|decode_cer'
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/ia5-$codec-only" "$test_srcdir/Ia5Values.asn1"
    else
        ia5_unwanted='encode_der|decode_ber'
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/ia5-$codec-only" "$test_srcdir/Ia5Values.asn1"
    fi
    ia5_codec_out="$test_tmp/ia5-$codec-only"
    if (cargo check --offline --manifest-path "$ia5_codec_out/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$ia5_codec_out/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic \
        -W clippy::nursery -D warnings) >"$test_tmp/ia5-$codec-only.log" 2>&1; then
        :
    else
        cat "$test_tmp/ia5-$codec-only.log"
        echo "FAIL: IA5 $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($ia5_unwanted)" "$ia5_codec_out/src/ia5_values.rs" >/dev/null; then
        echo "FAIL: IA5 $codec-only output has unselected methods"
        exit 1
    fi
done

ia5_c="$test_tmp/ia5-c"
mkdir "$ia5_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$ia5_c" "$test_srcdir/Ia5Values.asn1" \
    >"$test_tmp/ia5-c-generate.log" 2>&1
ia5_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' "$ia5_c/Makefile.am.libasncodec")
rm -f "$ia5_c/converter-example.c" "$ia5_c/pdu_collection.c"
if ! cc $ia5_cflags -I"$ia5_c" "$ia5_c"/*.c "$test_srcdir/c_ia5.c" \
    -lm -o "$test_tmp/c-ia5" >"$test_tmp/ia5-c-compile.log" 2>&1; then
    cat "$test_tmp/ia5-c-compile.log"
    echo "FAIL: C IA5 differential fixture did not compile"
    exit 1
fi
if ! "$test_tmp/c-ia5"; then
    echo "FAIL: C IA5 BER/DER/CER vectors or compatibility probes failed"
    exit 1
fi

# Direct restricted character strings keep type tags fixed and CER checks exact.
for fixture in RestrictedStringsAlias RestrictedStringsConstrained \
    RestrictedStringsField RestrictedStringsImport RestrictedStringsTagged \
    RestrictedStringsUnsupported; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported restricted-string shape $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

restricted_mixed="$test_tmp/rejected-restricted-mixed"
if "$asn1c_bin" --rust -S "$skeletons" -D "$restricted_mixed" \
    "$test_srcdir/RestrictedStrings.asn1" \
    >"$test_tmp/restricted-mixed.log" 2>&1; then
    echo "FAIL: mixed default codecs accepted restricted character strings"
    exit 1
fi
test ! -e "$restricted_mixed"
restricted_uper="$test_tmp/rejected-restricted-uper"
if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$restricted_uper" "$test_srcdir/RestrictedStrings.asn1" \
    >"$test_tmp/restricted-uper.log" 2>&1; then
    echo "FAIL: UPER-only selection accepted restricted character strings"
    exit 1
fi
test ! -e "$restricted_uper"

restricted_rust="$test_tmp/restricted-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$restricted_rust" "$test_srcdir/RestrictedStrings.asn1"
mkdir "$restricted_rust/tests"
cp "$test_srcdir/restricted_strings_conformance.rs" "$restricted_rust/tests/"
restricted_source="$restricted_rust/src/restricted_strings.rs"
for method in try_from_bytes as_bytes encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$restricted_source" >/dev/null
done
for kind in TeletexString T61String VisibleString Iso646String; do
    grep -F "CharacterStringKind::$kind" "$restricted_source" >/dev/null
done
if grep -F '#[derive(Clone' "$restricted_source" >/dev/null; then
    echo "FAIL: restricted-string wrappers derive infallible Clone"
    exit 1
fi
if ! (cd "$restricted_rust" && \
    CARGO_TARGET_DIR="$test_tmp/target-restricted" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-restricted" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/restricted-rust.log" 2>&1; then
    cat "$test_tmp/restricted-rust.log"
    echo "FAIL: restricted-string conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        restricted_unwanted='encode_cer|decode_cer'
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/restricted-$codec-only" "$test_srcdir/RestrictedStrings.asn1"
    else
        restricted_unwanted='encode_der|decode_ber'
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/restricted-$codec-only" "$test_srcdir/RestrictedStrings.asn1"
    fi
    restricted_codec_out="$test_tmp/restricted-$codec-only"
    if (cargo check --offline --manifest-path "$restricted_codec_out/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$restricted_codec_out/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic \
        -W clippy::nursery -D warnings) >"$test_tmp/restricted-$codec-only.log" 2>&1; then
        :
    else
        cat "$test_tmp/restricted-$codec-only.log"
        echo "FAIL: restricted-string $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($restricted_unwanted)" \
        "$restricted_codec_out/src/restricted_strings.rs" >/dev/null; then
        echo "FAIL: restricted-string $codec-only output has unselected methods"
        exit 1
    fi
done

restricted_c="$test_tmp/restricted-c"
mkdir "$restricted_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$restricted_c" "$test_srcdir/RestrictedStrings.asn1" \
    >"$test_tmp/restricted-c-generate.log" 2>&1
restricted_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$restricted_c/Makefile.am.libasncodec")
rm -f "$restricted_c/converter-example.c" "$restricted_c/pdu_collection.c"
if ! cc $restricted_cflags -I"$restricted_c" "$restricted_c"/*.c \
    "$test_srcdir/c_restricted_strings.c" -lm -o "$test_tmp/c-restricted" \
    >"$test_tmp/restricted-c-compile.log" 2>&1; then
    cat "$test_tmp/restricted-c-compile.log"
    echo "FAIL: C restricted-string differential fixture did not compile"
    exit 1
fi
if ! "$test_tmp/c-restricted"; then
    echo "FAIL: C restricted-string BER/DER/CER vectors failed"
    exit 1
fi

# Direct UTCTime preserves BER/DER content and normalizes only for CER.
for fixture in UtcTimeAlias UtcTimeConstrained UtcTimeField UtcTimeImport \
    UtcTimeTagged; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported UTCTime shape $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

utc_mixed="$test_tmp/rejected-utc-mixed"
if "$asn1c_bin" --rust -S "$skeletons" -D "$utc_mixed" \
    "$test_srcdir/UtcTimeValues.asn1" >"$test_tmp/utc-mixed.log" 2>&1; then
    echo "FAIL: mixed default codecs accepted direct UTCTime"
    exit 1
fi
test ! -e "$utc_mixed"
utc_uper="$test_tmp/rejected-utc-uper"
if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$utc_uper" "$test_srcdir/UtcTimeValues.asn1" \
    >"$test_tmp/utc-uper.log" 2>&1; then
    echo "FAIL: UPER-only selection accepted direct UTCTime"
    exit 1
fi
test ! -e "$utc_uper"

utc_rust="$test_tmp/utc-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$utc_rust" "$test_srcdir/UtcTimeValues.asn1"
mkdir "$utc_rust/tests"
cp "$test_srcdir/utc_time_conformance.rs" "$utc_rust/tests/"
utc_source="$utc_rust/src/utc_time_values.rs"
for method in try_from_bytes as_bytes encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$utc_source" >/dev/null
done
if grep -F '#[derive(Clone' "$utc_source" >/dev/null; then
    echo "FAIL: UtcTime wrapper derives infallible Clone"
    exit 1
fi
if ! (cd "$utc_rust" && \
    CARGO_TARGET_DIR="$test_tmp/target-utc" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-utc" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/utc-rust.log" 2>&1; then
    cat "$test_tmp/utc-rust.log"
    echo "FAIL: UTCTime conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        utc_unwanted='encode_cer|decode_cer'
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/utc-$codec-only" "$test_srcdir/UtcTimeValues.asn1"
    else
        utc_unwanted='encode_der|decode_ber'
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/utc-$codec-only" "$test_srcdir/UtcTimeValues.asn1"
    fi
    utc_codec_out="$test_tmp/utc-$codec-only"
    if (cargo check --offline --manifest-path "$utc_codec_out/Cargo.toml" && \
        cargo clippy --offline --manifest-path "$utc_codec_out/Cargo.toml" \
        --all-targets --all-features -- -W clippy::pedantic \
        -W clippy::nursery -D warnings) >"$test_tmp/utc-$codec-only.log" 2>&1; then
        :
    else
        cat "$test_tmp/utc-$codec-only.log"
        echo "FAIL: UTCTime $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($utc_unwanted)" \
        "$utc_codec_out/src/utc_time_values.rs" >/dev/null; then
        echo "FAIL: UTCTime $codec-only output has unselected methods"
        exit 1
    fi
done

utc_c="$test_tmp/utc-c"
mkdir "$utc_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$utc_c" "$test_srcdir/UtcTimeValues.asn1" \
    >"$test_tmp/utc-c-generate.log" 2>&1
utc_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' "$utc_c/Makefile.am.libasncodec")
rm -f "$utc_c/converter-example.c" "$utc_c/pdu_collection.c"
if ! cc $utc_cflags -I"$utc_c" "$utc_c"/*.c \
    "$test_srcdir/c_utc_time.c" -lm -o "$test_tmp/c-utc" \
    >"$test_tmp/utc-c-compile.log" 2>&1; then
    cat "$test_tmp/utc-c-compile.log"
    echo "FAIL: C UTCTime differential fixture did not compile"
    exit 1
fi
if ! "$test_tmp/c-utc"; then
    echo "FAIL: C UTCTime BER/DER/CER vectors failed"
    exit 1
fi

# Direct GeneralizedTime uses the C adapter's canonical zoned forms.
for fixture in GeneralizedTimeAlias GeneralizedTimeConstrained \
    GeneralizedTimeField GeneralizedTimeImport GeneralizedTimeTagged; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported GeneralizedTime shape $fixture"
        exit 1
    fi
    test ! -e "$rejected_out"
done

generalized_mixed="$test_tmp/rejected-generalized-mixed"
if "$asn1c_bin" --rust -S "$skeletons" -D "$generalized_mixed" \
    "$test_srcdir/GeneralizedTimeValues.asn1" \
    >"$test_tmp/generalized-mixed.log" 2>&1; then
    echo "FAIL: mixed default codecs accepted direct GeneralizedTime"
    exit 1
fi
test ! -e "$generalized_mixed"
generalized_uper="$test_tmp/rejected-generalized-uper"
if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
    -D "$generalized_uper" "$test_srcdir/GeneralizedTimeValues.asn1" \
    >"$test_tmp/generalized-uper.log" 2>&1; then
    echo "FAIL: UPER-only selection accepted direct GeneralizedTime"
    exit 1
fi
test ! -e "$generalized_uper"

generalized_rust="$test_tmp/generalized-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$generalized_rust" "$test_srcdir/GeneralizedTimeValues.asn1"
mkdir "$generalized_rust/tests"
cp "$test_srcdir/generalized_time_conformance.rs" "$generalized_rust/tests/"
generalized_source="$generalized_rust/src/generalized_time_values.rs"
for method in try_from_bytes as_bytes encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$generalized_source" >/dev/null
done
if grep -F '#[derive(Clone' "$generalized_source" >/dev/null; then
    echo "FAIL: GeneralizedTime wrapper derives infallible Clone"
    exit 1
fi
if ! (cd "$generalized_rust" && \
    CARGO_TARGET_DIR="$test_tmp/target-generalized" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-generalized" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/generalized-rust.log" 2>&1; then
    cat "$test_tmp/generalized-rust.log"
    echo "FAIL: GeneralizedTime conformance or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    if [ "$codec" = BER ]; then
        generalized_unwanted='encode_cer|decode_cer'
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/generalized-$codec-only" \
            "$test_srcdir/GeneralizedTimeValues.asn1"
    else
        generalized_unwanted='encode_der|decode_ber'
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$test_tmp/generalized-$codec-only" \
            "$test_srcdir/GeneralizedTimeValues.asn1"
    fi
    generalized_codec_out="$test_tmp/generalized-$codec-only"
    if ! (cd "$generalized_codec_out" && \
        cargo check --offline --manifest-path Cargo.toml && \
        cargo clippy --offline --all-targets --all-features -- \
        -W clippy::pedantic -W clippy::nursery -D warnings) \
        >"$test_tmp/generalized-$codec-only.log" 2>&1; then
        cat "$test_tmp/generalized-$codec-only.log"
        echo "FAIL: GeneralizedTime $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($generalized_unwanted)" \
        "$generalized_codec_out/src/generalized_time_values.rs" >/dev/null; then
        echo "FAIL: GeneralizedTime $codec-only output has unselected methods"
        exit 1
    fi
done

generalized_c="$test_tmp/generalized-c"
mkdir "$generalized_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$generalized_c" "$test_srcdir/GeneralizedTimeValues.asn1" \
    >"$test_tmp/generalized-c-generate.log" 2>&1
generalized_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' \
    "$generalized_c/Makefile.am.libasncodec")
rm -f "$generalized_c/converter-example.c" "$generalized_c/pdu_collection.c"
if ! cc $generalized_cflags -I"$generalized_c" "$generalized_c"/*.c \
    "$test_srcdir/c_generalized_time.c" -lm -o "$test_tmp/c-generalized" \
    >"$test_tmp/generalized-c-compile.log" 2>&1; then
    cat "$test_tmp/generalized-c-compile.log"
    echo "FAIL: C GeneralizedTime differential fixture did not compile"
    exit 1
fi
if ! "$test_tmp/c-generalized"; then
    echo "FAIL: C GeneralizedTime BER/DER/CER vectors failed"
    exit 1
fi

# Direct OF collections share the repeated-member runtime and its count budget.
of_rust="$test_tmp/of-collections-rust"
"$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
    -D "$of_rust" "$test_srcdir/OfCollections.asn1"
mkdir "$of_rust/tests"
cp "$test_srcdir/of_collections_conformance.rs" "$of_rust/tests/"
grep -F 'pub const fn new' "$of_rust/src/of_collections.rs" >/dev/null
for method in as_slice encode_der decode_ber encode_cer decode_cer; do
    grep -F "pub fn $method" "$of_rust/src/of_collections.rs" >/dev/null
done
if grep -F '#[derive(Clone' "$of_rust/src/of_collections.rs" >/dev/null; then
    echo "FAIL: collection wrappers derive infallible Clone"
    exit 1
fi
if ! (cd "$of_rust" && CARGO_TARGET_DIR="$test_tmp/target-of-collections" \
    cargo test --offline --manifest-path Cargo.toml && \
    CARGO_TARGET_DIR="$test_tmp/target-of-collections" \
    cargo clippy --offline --all-targets --all-features -- \
    -W clippy::pedantic -W clippy::nursery -D warnings) \
    >"$test_tmp/of-collections-rust.log" 2>&1; then
    cat "$test_tmp/of-collections-rust.log"
    echo "FAIL: collection vectors or strict Clippy"
    exit 1
fi

for codec in BER CER; do
    of_codec_out="$test_tmp/of-collections-$codec-only"
    if [ "$codec" = BER ]; then
        of_unwanted='encode_cer|decode_cer'
        "$asn1c_bin" --rust -gen-BER -no-gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$of_codec_out" "$test_srcdir/OfCollections.asn1"
    else
        of_unwanted='encode_der|decode_ber'
        "$asn1c_bin" --rust -gen-CER -no-gen-BER -no-gen-UPER -S "$skeletons" \
            -D "$of_codec_out" "$test_srcdir/OfCollections.asn1"
    fi
    if ! (cd "$of_codec_out" && cargo check --offline --manifest-path Cargo.toml && \
        cargo clippy --offline --all-targets --all-features -- \
        -W clippy::pedantic -W clippy::nursery -D warnings) \
        >"$test_tmp/of-collections-$codec-only.log" 2>&1; then
        cat "$test_tmp/of-collections-$codec-only.log"
        echo "FAIL: collection $codec-only strict Clippy"
        exit 1
    fi
    if grep -E "pub fn ($of_unwanted)" \
        "$of_codec_out/src/of_collections.rs" >/dev/null; then
        echo "FAIL: collection $codec-only crate has unselected methods"
        exit 1
    fi
done

for fixture in OfTaggedRoot OfSizedRoot OfTaggedElement OfAlias OfElementAlias \
    OfField OfNested OfConstrainedBoolean OfUnboundedInteger OfIntegerExtension \
    OfIntegerUnion \
    OfParameterized OfImport; do
    of_rejected="$test_tmp/rejected-$fixture"
    if [ "$fixture" = OfImport ]; then
        if "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
            -D "$of_rejected" "$test_srcdir/OfImportBase.asn1" \
            "$test_srcdir/OfImport.asn1" >"$test_tmp/rejected-$fixture.log" 2>&1; then
            echo "FAIL: Rust collection gate accepted unsupported $fixture"
            exit 1
        fi
    elif "$asn1c_bin" --rust -gen-BER -gen-CER -no-gen-UPER -S "$skeletons" \
        -D "$of_rejected" "$test_srcdir/$fixture.asn1" \
        >"$test_tmp/rejected-$fixture.log" 2>&1; then
        echo "FAIL: Rust collection gate accepted unsupported $fixture"
        exit 1
    fi
    test ! -e "$of_rejected"
done

for selection in mixed uper; do
    of_rejected="$test_tmp/rejected-of-codecs-$selection"
    if [ "$selection" = mixed ]; then
        if "$asn1c_bin" --rust -gen-BER -gen-CER -gen-UPER -S "$skeletons" \
            -D "$of_rejected" "$test_srcdir/OfCollections.asn1" \
            >"$test_tmp/rejected-of-codecs-$selection.log" 2>&1; then
            echo "FAIL: Rust collection gate accepted mixed codecs"
            exit 1
        fi
    else
        if "$asn1c_bin" --rust -gen-UPER -no-gen-BER -no-gen-CER -S "$skeletons" \
            -D "$of_rejected" "$test_srcdir/OfCollections.asn1" \
            >"$test_tmp/rejected-of-codecs-$selection.log" 2>&1; then
            echo "FAIL: Rust collection gate accepted UPER-only selection"
            exit 1
        fi
    fi
    test ! -e "$of_rejected"
done

of_c="$test_tmp/of-collections-c"
mkdir "$of_c"
"$asn1c_bin" -fcompound-names -S "$skeletons" -gen-CER -no-gen-UPER \
    -no-gen-XER -no-gen-JER -no-gen-CBOR -no-gen-OER -no-gen-APER \
    -no-gen-print -no-gen-random-fill -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$of_c" "$test_srcdir/OfCollections.asn1" \
    >"$test_tmp/of-collections-c-generate.log" 2>&1
of_cflags=$(sed -n 's/^ASN_MODULE_CFLAGS=//p' "$of_c/Makefile.am.libasncodec")
rm -f "$of_c/converter-example.c" "$of_c/pdu_collection.c"
if ! cc $of_cflags -I"$of_c" "$of_c"/*.c \
    "$test_srcdir/c_of_collections.c" -lm -o "$test_tmp/c-of-collections" \
    >"$test_tmp/of-collections-c-compile.log" 2>&1; then
    cat "$test_tmp/of-collections-c-compile.log"
    echo "FAIL: C collection differential fixture did not compile"
    exit 1
fi
if ! "$test_tmp/c-of-collections"; then
    echo "FAIL: C collection BER/DER/CER vectors failed"
    exit 1
fi

echo "PASS: generated Rust UPER/CER/BER-DER primitive slice"
