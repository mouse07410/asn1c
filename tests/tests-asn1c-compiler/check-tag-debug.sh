#!/bin/sh

# -Wdebug-compiler must expose the tag-fetch trace, and only with the flag.
#
# asn1f_fetch_tags() used to build a zeroed temporary fixer context, so the
# DEBUG line naming the type being resolved never reached the compiler's
# logger. The flag must also stay output-neutral.

set -eu

# Automake exports top_srcdir/top_builddir to tests; accept absolute variants
# as well because this script is also useful when invoked directly.
src_root="${abs_top_srcdir:-${top_srcdir:?top_srcdir must name the source tree}}"
build_root="${abs_top_builddir:-${top_builddir:?top_builddir must name the build tree}}"
src_root=$(cd "$src_root" && pwd)
build_root=$(cd "$build_root" && pwd)
compiler="${build_root}/asn1c/asn1c"
skeletons="${src_root}/skeletons"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-tag-debug.XXXXXX")

cleanup() {
    rm -rf "$tmpdir"
}

trap cleanup EXIT HUP INT TERM

cat >"$tmpdir/tag.asn1" <<'EOF'
M DEFINITIONS ::= BEGIN
T ::= [2] INTEGER
END
EOF

# Generate both runs into the same relative directory so every path embedded
# in the output (headers, Makefiles) is identical; only the command line
# recorded in the file headers may mention -Wdebug-compiler.
cd "$tmpdir"
mkdir out

# -S avoids the VPATH skeletons warning, which would share stderr with the
# trace inspected below.
if ! "$compiler" -S "$skeletons" -D out -Wdebug-compiler \
    tag.asn1 >"$tmpdir/with.out" 2>"$tmpdir/with.err"; then
    cat "$tmpdir/with.err" >&2
    exit 1
fi
mv out with

mkdir out
if ! "$compiler" -S "$skeletons" -D out \
    tag.asn1 >"$tmpdir/without.out" 2>"$tmpdir/without.err"; then
    cat "$tmpdir/without.err" >&2
    exit 1
fi
mv out without

if ! grep -Fq 'Fetching tag from T' "$tmpdir/with.err"; then
    echo "FAIL: -Wdebug-compiler does not expose the tag-fetch trace" >&2
    cat "$tmpdir/with.err" >&2
    exit 1
fi
if grep -Fq 'Fetching tag from T' "$tmpdir/without.err"; then
    echo "FAIL: the tag-fetch trace appears without -Wdebug-compiler" >&2
    exit 1
fi
# The generated data must not depend on the flag. The only lines allowed to
# differ are the recorded invocation, which carries -Wdebug-compiler; check
# separately that it really is the recorded command line that changed.
if ! diff -r -I 'asn1c -S' with without >"$tmpdir/diff.log" 2>&1; then
    echo "FAIL: -Wdebug-compiler changes the generated output" >&2
    cat "$tmpdir/diff.log" >&2
    exit 1
fi
if ! grep -Fq 'asn1c -S' with/T.c \
    || ! grep -Fq ' -Wdebug-compiler' with/T.c; then
    echo "FAIL: the debug invocation is not recorded in the output" >&2
    exit 1
fi
if grep -Fq ' -Wdebug-compiler' without/T.c; then
    echo "FAIL: the plain invocation records the debug flag" >&2
    exit 1
fi

echo "PASS: tag-fetch trace is debug-gated and output-neutral"
