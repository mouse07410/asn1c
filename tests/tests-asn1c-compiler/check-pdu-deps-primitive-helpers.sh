#!/bin/sh

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${top_builddir}/asn1c/asn1c"
SKELETONS="${top_srcdir}/skeletons"

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

run_case() {
    name=$1
    type=$2
    native_types=$3
    shift 3
    case_dir="$TMPDIR_TEST/$name"
    mkdir "$case_dir"
    schema="$case_dir/input.asn1"

    cat >"$schema" <<EOF
PDUDepsPrimitive DEFINITIONS ::= BEGIN
PDU ::= $type
END
EOF

    if [ "$native_types" = yes ]; then
        (cd "$case_dir" && "$ASN1C" -S "$SKELETONS" -fcompound-names \
            -fnative-types -fgen-only-pdu-deps -pdu=PDU "$schema") >/dev/null 2>&1
    else
        (cd "$case_dir" && "$ASN1C" -S "$SKELETONS" -fcompound-names \
            -fgen-only-pdu-deps -pdu=PDU "$schema") >/dev/null 2>&1
    fi

    for f in "$@"; do
        if [ ! -f "$case_dir/$f" ]; then
            echo "FAIL: $f is missing for $name with -fgen-only-pdu-deps"
            exit 1
        fi
    done
}

run_case boolean BOOLEAN no asn_codecs_prim_xer.c asn_codecs_prim_jer.c
run_case integer INTEGER no asn_codecs_prim_ber.c asn_codecs_prim_xer.c asn_codecs_prim_jer.c
run_case null NULL no asn_codecs_prim_jer.c
run_case enumerated 'ENUMERATED { a(0) }' no asn_codecs_prim_jer.c
run_case object-identifier 'OBJECT IDENTIFIER' no asn_codecs_prim_ber.c asn_codecs_prim_xer.c asn_codecs_prim_jer.c
run_case real REAL no asn_codecs_prim_ber.c asn_codecs_prim_xer.c asn_codecs_prim_jer.c
run_case relative-oid 'RELATIVE-OID' no asn_codecs_prim_ber.c asn_codecs_prim_xer.c asn_codecs_prim_jer.c
run_case native-integer INTEGER yes asn_codecs_prim_xer.c
run_case native-real REAL yes asn_codecs_prim_ber.c
