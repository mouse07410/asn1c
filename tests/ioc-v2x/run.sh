#!/usr/bin/env bash
set -euo pipefail

d="$(cd "$(dirname "$0")" && pwd)"
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
cp -p "$d/C2X.asn" "$w/"
cp -p "$d/s4.xer" "$w/"
cd "$w"

# Support both direct execution and automake test execution
top_builddir="${abs_top_builddir:-${d}/../..}"
ASN1C_EXE="${top_builddir}/asn1c/asn1c"
#GEN_AUTOTOOLS="-gen-autotools"

echo "d=${d} w=${w} pwd=${PWD}"

${ASN1C_EXE} -fall-defs-global -fcompound-names -fincludes-quoted \
  -fline-refs -fwide-types \
  -pdu=EndApplicationMessage C2X.asn

CFLAGS="-g -DASN_EMIT_DEBUG" make -f converter-example.mk CC="${CC:-cc}" >/dev/null

./converter-example -p EndApplicationMessage -ixer s4.xer >/dev/null

if grep -R --fixed-strings '&asn_DEF_SEQUENCE_OF_t' . ; then
  echo "ERROR: placeholder *_t descriptor leaked into IOC rows" >&2; exit 1
fi
if grep -R --fixed-strings '&asn_DEF_SEQUENCE_OF,' . ; then
  echo "ERROR: bare &asn_DEF_SEQUENCE_OF leaked into IOC rows" >&2; exit 1
fi
if grep -R --fixed-strings '&asn_DEF_endApplication_Message_msg,' . ; then
  echo "ERROR: unsuffixed Open Type wrapper descriptor leaked" >&2; exit 1
fi
echo "OK"
