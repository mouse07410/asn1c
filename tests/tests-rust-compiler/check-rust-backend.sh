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
    runtime/LICENSE runtime/src/lib.rs runtime/src/aper.rs runtime/src/oer.rs \
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

# Unsupported codec requests must fail without publishing any Rust output.
for codec in XER JER CBOR; do
    rejected_out="$test_tmp/rejected-$codec"
    if "$asn1c_bin" --rust "-gen-$codec" -S "$skeletons" \
        -D "$rejected_out" "$test_srcdir/FirstSlice.asn1" \
        >"$test_tmp/rejected-$codec.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported -gen-$codec"
        exit 1
    fi
    if [ -e "$rejected_out" ]; then
        echo "FAIL: unsupported -gen-$codec created output before rejection"
        exit 1
    fi
done

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

# Flat required-field SEQUENCE is qualified only for an explicit UPER-only mask.
if "$asn1c_bin" --rust -S "$skeletons" -D "$test_tmp/rejected-sequence-default" \
    "$test_srcdir/SequenceSlice.asn1" >"$test_tmp/rejected-sequence-default.log" 2>&1; then
    echo "FAIL: default Rust codecs accepted a SEQUENCE without CER support"
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
    "$test_srcdir/SequenceSlice.asn1"
mkdir "$sequence_out/tests"
cp "$test_srcdir/sequence_conformance.rs" "$sequence_out/tests/sequence_conformance.rs"
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
for fixture in SequenceOptional SequenceNested SequenceExtension; do
    rejected_out="$test_tmp/rejected-$fixture"
    if "$asn1c_bin" --rust -no-gen-CER -S "$skeletons" -D "$rejected_out" \
        "$test_srcdir/$fixture.asn1" >"$test_tmp/rejected-$fixture.log" 2>&1; then
        echo "FAIL: Rust backend accepted unsupported $fixture fields"
        exit 1
    fi
    if [ "$fixture" = SequenceExtension ]; then
        grep -F 'SEQUENCE field needs BOOLEAN, NULL, or finite i64 INTEGER' \
            "$test_tmp/rejected-$fixture.log" >/dev/null
    else
        grep -F 'SEQUENCE field must be a required direct untagged primitive' \
            "$test_tmp/rejected-$fixture.log" >/dev/null
    fi
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
grep -F 'SEQUENCE field needs BOOLEAN, NULL, or finite i64 INTEGER' \
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
    UnconstrainedInteger NamedNumber EncodingControl; do
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
        TaggedBoolean) expected='explicit type tags are not supported' ;;
        ExtensibleInteger|UnionInteger|UnconstrainedInteger)
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
    -no-gen-JER -no-gen-CBOR -no-gen-print \
    -no-gen-random-fill -fwide-types -pdu=all -fgen-only-pdu-deps \
    -no-gen-example -D "$c_out" "$test_srcdir/CParity.asn1" \
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

echo "PASS: generated Rust UPER/CER/BER-DER primitive slice"
