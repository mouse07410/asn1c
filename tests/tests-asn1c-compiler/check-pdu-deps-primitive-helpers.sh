#!/bin/sh

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${top_builddir}/asn1c/asn1c"
SKELETONS="${top_srcdir}/skeletons"
SCHEMA="${top_srcdir}/tests/tests-asn1c-compiler/569-pdu-deps-primitive-helpers-OK.asn1"

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

(cd "$TMPDIR_TEST" && "$ASN1C" -S "$SKELETONS" -fcompound-names \
    -fgen-only-pdu-deps -pdu=Message "$SCHEMA") >/dev/null 2>&1

for f in asn_codecs_prim_ber.c asn_codecs_prim_jer.c asn_codecs_prim_xer.c; do
    if [ ! -f "$TMPDIR_TEST/$f" ]; then
        echo "FAIL: $f is missing with -fgen-only-pdu-deps"
        exit 1
    fi
done
