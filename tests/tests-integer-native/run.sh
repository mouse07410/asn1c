#!/bin/sh
#
# Standalone test runner for oversized INTEGER constraint support and the
# -finteger-native-type code-generation option.
#
# Usage:
#   ./run.sh [ASN1C_BINARY] [SKELETONS_DIR]
#
# Defaults assume an in-tree build:
#   ASN1C_BINARY  = ../../asn1c/asn1c
#   SKELETONS_DIR = ../../skeletons
#
set -e

here=$(cd "$(dirname "$0")" && pwd)
ASN1C="${1:-$here/../../asn1c/asn1c}"
SKELDIR="${2:-$here/../../skeletons}"
CC="${CC:-cc}"
ASN1="$here/oversized-integers.asn1"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "asn1c   : $ASN1C"
echo "skeleton: $SKELDIR"
echo

fail=0

# ---------------------------------------------------------------------------
# 1. Command-line option parsing
# ---------------------------------------------------------------------------
echo "== option parsing =="
for m in auto int32 uint32 int64 uint64; do
    if "$ASN1C" -finteger-native-type=$m -E "$ASN1" >/dev/null 2>&1; then
        echo "ok: accepts -finteger-native-type=$m"
    else
        echo "FAIL: rejected -finteger-native-type=$m"; fail=1
    fi
done
if "$ASN1C" -finteger-native-type=bogus -E "$ASN1" >/dev/null 2>&1; then
    echo "FAIL: accepted -finteger-native-type=bogus"; fail=1
else
    echo "ok: rejects -finteger-native-type=bogus"
fi
echo

# ---------------------------------------------------------------------------
# 2. Generated storage type per mode (the T1..T8 table)
# ---------------------------------------------------------------------------
echo "== generated storage types =="
check_storage() {  # $1=mode $2=type $3=expected
    d="$work/g_$1"; rm -rf "$d"; mkdir -p "$d"
    ( cd "$d" && "$ASN1C" -S "$SKELDIR" -gen-UPER -fwide-types \
        -finteger-native-type=$1 "$ASN1" >/dev/null 2>&1 )
    got=$(grep -hE "typedef.* $2_t" "$d/$2.h" | head -1 \
          | sed -E "s/typedef[[:space:]]+(.*)[[:space:]]+$2_t.*/\1/" \
          | tr '\t' ' ' | tr -s ' ' | sed -E 's/^ +| +$//g')
    if [ "$got" = "$3" ]; then echo "ok: $1 $2 = $got"
    else echo "FAIL: $1 $2 = '$got' (expected '$3')"; fail=1; fi
}
#            mode    type expected
# auto preserves the traditional storage decision (long / unsigned long /
# INTEGER_t); fixed-width types are only produced by the explicit modes.
check_storage auto   T1   "long"
check_storage auto   T2   "long"
check_storage auto   T3   "unsigned long"
check_storage auto   T4   "INTEGER_t"
check_storage auto   T5   "INTEGER_t"
check_storage auto   T7   "INTEGER_t"
check_storage int32  T1   "int32_t"
check_storage int32  T2   "int32_t"
check_storage int32  T3   "INTEGER_t"
check_storage int32  T4   "INTEGER_t"
check_storage int64  T4   "int64_t"
check_storage int64  T5   "INTEGER_t"
check_storage uint32 T2   "INTEGER_t"
check_storage uint32 T3   "uint32_t"
check_storage uint64 T2   "INTEGER_t"
check_storage uint64 T5   "uint64_t"
echo

# ---------------------------------------------------------------------------
# 3. Compiler-internal bigint unit test
# ---------------------------------------------------------------------------
echo "== bigint unit test =="
$CC -I"$here/../../libasn1compiler" "$here/test_bigint.c" \
    "$here/../../libasn1compiler/asn1c_bigint.c" -o "$work/test_bigint"
"$work/test_bigint" || fail=1
echo

# ---------------------------------------------------------------------------
# 4. Runtime helper tests (storage-agnostic): asn_cval_t + asn_ulong2INTEGER.
#    Generated with auto (default); test_cval only needs asn_constraint_value.h
#    and the INTEGER runtime.
# ---------------------------------------------------------------------------
echo "== runtime helper tests (asn_cval_t, asn_ulong2INTEGER) =="
gen="$work/gen"; rm -rf "$gen"; mkdir -p "$gen"
( cd "$gen" && "$ASN1C" -S "$SKELDIR" "$ASN1" >/dev/null 2>&1 )
cp "$here/test_cval.c" "$gen/"
( cd "$gen"
  for f in $(ls *.c | grep -vxE 'converter-example.c|test_cval.c'); do
      $CC -I. -c "$f" -o "${f%.c}.o" 2>/dev/null || echo "compile failed: $f"
  done
  $CC -I. test_cval.c *.o -o test_cval
)
"$gen/test_cval" || fail=1
echo

# ---------------------------------------------------------------------------
# 5. Fixed-width generated-code tests.  Generate the module under explicit
#    modes so the native storage type is deterministic, then exercise
#    encode/decode round-trips and constraint enforcement through the
#    width-aware NativeInteger codec.  Oversized types (T7/T8) stay INTEGER_t.
# ---------------------------------------------------------------------------
build_and_run() {  # $1=mode $2=test-source
    local mode="$1" src="$2" g="$work/gen_$mode"
    rm -rf "$g"; mkdir -p "$g"
    ( cd "$g" && "$ASN1C" -S "$SKELDIR" -finteger-native-type=$mode "$ASN1" >/dev/null 2>&1 )
    cp "$here/$src" "$g/"
    ( cd "$g"
      for f in $(ls *.c | grep -vxE "converter-example.c|$src"); do
          $CC -I. -c "$f" -o "${f%.c}.o" 2>/dev/null || echo "compile failed: $f"
      done
      $CC -I. "$src" *.o -lm -o test_prog
    )
    "$g/test_prog" || fail=1
}
echo "== fixed-width generated-code tests (uint64 mode) =="
build_and_run uint64 test_constraints.c
echo
echo "== fixed-width generated-code tests (int32 mode) =="
build_and_run int32 test_int32.c
echo

if [ "$fail" = 0 ]; then echo "=== ALL TESTS PASSED ==="; else echo "=== FAILURES ==="; fi
exit $fail
