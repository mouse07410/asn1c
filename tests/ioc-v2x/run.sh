#!/usr/bin/env bash
set -euo pipefail

# For distcheck: srcdir points to source directory, current dir is build directory
# For normal check: srcdir=. and we're in the source directory
srcdir="${srcdir:-.}"
abs_top_builddir="${abs_top_builddir:-$(cd ../.. && pwd)}"
abs_top_srcdir="${abs_top_srcdir:-$(cd ../.. && pwd)}"

# Copy source files to current directory if not already present
if [ ! -f C2X.asn ]; then
  cp -p "${srcdir}/C2X.asn" .
fi
if [ ! -f s4.xer ]; then
  cp -p "${srcdir}/s4.xer" .
fi

ASN1C_EXE="${abs_top_builddir}/asn1c/asn1c"
SKELETONS_DIR="${abs_top_srcdir}/skeletons"

echo "srcdir=${srcdir} abs_top_builddir=${abs_top_builddir} abs_top_srcdir=${abs_top_srcdir} pwd=${PWD}"

${ASN1C_EXE} -S "${SKELETONS_DIR}" -fall-defs-global -fcompound-names -fincludes-quoted \
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
