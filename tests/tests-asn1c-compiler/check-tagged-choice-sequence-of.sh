#!/bin/sh

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${top_builddir}/asn1c/asn1c"
SKELETONS="${top_srcdir}/skeletons"
SCHEMA="${top_srcdir}/tests/tests-asn1c-compiler/566-sequence-of-tagged-choice-OK.asn1"

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

"$ASN1C" -S "$SKELETONS" -EF "$SCHEMA" >"$TMPDIR_TEST/fixed.asn"
grep -E '^List ::= SEQUENCE OF \[3\] IMPLICIT Tagged$' "$TMPDIR_TEST/fixed.asn" >/dev/null
grep -E '^SetList ::= SET OF \[5\] IMPLICIT Tagged$' "$TMPDIR_TEST/fixed.asn" >/dev/null
grep -E 'item[[:space:]]+\[3\] IMPLICIT Tagged' "$TMPDIR_TEST/fixed.asn" >/dev/null
grep -E '^BareList ::= SEQUENCE OF \[4\] EXPLICIT CHOICE' "$TMPDIR_TEST/fixed.asn" >/dev/null

(cd "$TMPDIR_TEST" && "$ASN1C" -S "$SKELETONS" -pdu=List "$SCHEMA") >/dev/null 2>&1
grep -F '/* IMPLICIT tag at current level */' "$TMPDIR_TEST/List.c" >/dev/null
if grep -F '/* EXPLICIT tag at current level */' "$TMPDIR_TEST/List.c" >/dev/null; then
    echo "FAIL: List element generated with an EXPLICIT tag"
    exit 1
fi
