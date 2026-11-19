#!/usr/bin/env sh
# Purpose: Exercise fixed-size named BIT STRINGs through generated BER and JER.
# Source: Issue #617. Version/date: 2026-11-19. Author: asn1c maintainers.
# Inputs: configured build/source roots, CC and MAKE. Returns: zero on success.
# Errors: nonzero on generation, build, or output mismatch. Throws: nothing.
# History: covers named SEQUENCE fields and a constrained alias in both modes.
# Example: make check TESTS=check-issue-617.sh
set -eu

test_build_root=$(cd "${top_builddir:-../..}" && pwd)
test_source_root=$(cd "${top_srcdir:-../..}" && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-issue-617.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM

# Generate both the reported schema and a subtype inheriting its NamedBitList.
cat > "$test_directory/schema.asn1" <<'ASN1'
M DEFINITIONS ::= BEGIN
E ::= BIT STRING {app(0), enrol(1)} (SIZE(8))
T ::= SEQUENCE { e E }
Named ::= BIT STRING {ready(0)}
Alias ::= Named (SIZE(8))
Member ::= SEQUENCE { e Named (SIZE(8)) }
Inline ::= SEQUENCE { e BIT STRING {ready(0)} (SIZE(8)) }
Empty ::= Named (SIZE(0))
Plain ::= BIT STRING (SIZE(8))
END
ASN1
# Check the compact example and a zero tail beyond the alias's declared width.
printf '\060\004\003\002\007\200' > "$test_directory/short.ber"
printf '\003\003\000\200\000' > "$test_directory/long.ber"
printf '\003\002\000\000' > "$test_directory/zeros.ber"
printf '\003\002\007\200' > "$test_directory/plain-short.ber"
for mode in default strict; do
    mkdir "$test_directory/$mode"
    converter="$test_directory/$mode/converter-example"
    set --
    if [ "$mode" = strict ]; then
        set -- --strict-mode
    fi
    "$test_build_root/asn1c/asn1c" "$@" -gen-JER -pdu=all \
        -no-gen-CER -no-gen-CBOR -no-gen-UPER -no-gen-APER \
        -no-gen-OER -no-gen-random-fill -S "$test_source_root/skeletons" \
        -D "$test_directory/$mode" "$test_directory/schema.asn1" >/dev/null
    "${MAKE:-make}" -C "$test_directory/$mode" -f converter-example.mk \
        CC="${CC:-cc}" >/dev/null

    # Convert the reported SEQUENCE and decode/re-encode the exact JER output.
    for pdu in T Member Inline; do
        "$converter" -p "$pdu" -iber -ojer "$test_directory/short.ber" > "$test_directory/short.jer"
        test "$(tr -d '[:space:]' < "$test_directory/short.jer")" = '{"e":"80"}'
    done
    "$converter" -p T -ijer -ojer "$test_directory/short.jer" > "$test_directory/round-trip.jer"
    cmp "$test_directory/short.jer" "$test_directory/round-trip.jer"

    # The alias inherits the NamedBitList and applies its own fixed SIZE.
    "$converter" -p Alias -iber -ojer "$test_directory/long.ber" > "$test_directory/long.jer"
    test "$(tr -d '[:space:]' < "$test_directory/long.jer")" = '"80"'

    # A named zero value fits SIZE(0); a short unnamed value cannot be padded.
    "$converter" -p Empty -iber -ojer "$test_directory/zeros.ber" > "$test_directory/empty.jer"
    test "$(tr -d '[:space:]' < "$test_directory/empty.jer")" = '""'
    if "$converter" -p Plain -iber -ojer "$test_directory/plain-short.ber" >/dev/null 2>&1; then
        echo "FAIL: $mode converter padded a short unnamed BIT STRING" >&2
        exit 1
    fi
done
