#!/bin/sh

# Regression test for generated equality constraints and Clang's
# -Wparentheses-equality diagnostic.

set -eu

# Automake exports top_srcdir/top_builddir to tests; accept absolute variants
# as well because this script is also useful when invoked directly.
src_root="${abs_top_srcdir:-${top_srcdir:?top_srcdir must name the source tree}}"
build_root="${abs_top_builddir:-${top_builddir:?top_builddir must name the build tree}}"
compiler="${build_root}/asn1c/asn1c"
schema="${src_root}/tests/tests-asn1c-compiler/test_simple_constraint.asn1"
skeletons="${src_root}/skeletons"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/asn1c-generated-warning.XXXXXX")

cleanup() {
    rm -rf "$tmpdir"
}

trap cleanup EXIT HUP INT TERM

# Generate a constrained OCTET STRING so the test exercises the compiler's
# generic constraint emitter, rather than a hand-written runtime skeleton.
if ! "$compiler" -S "$skeletons" -D "$tmpdir" \
    -no-gen-OER -no-gen-UPER -no-gen-APER -no-gen-JER "$schema" \
    >"$tmpdir/asn1c.log" 2>&1; then
    cat "$tmpdir/asn1c.log" >&2
    exit 1
fi

if grep -Fq 'if((size == 3UL))' "$tmpdir/TestMessage.c"; then
    echo "FAIL: generated equality constraint retains redundant parentheses" >&2
    exit 1
fi

# Compile the generated module with the diagnostic promoted to an error when
# Clang is in use; the textual assertion above keeps this test portable.
compiler_version=$(${CC:-cc} --version 2>/dev/null || true)
case "$compiler_version" in
    *[Cc]lang*)
        ${CC:-cc} -std=gnu18 -Werror=parentheses-equality \
            -I"$tmpdir" -c "$tmpdir/TestMessage.c" \
            -o "$tmpdir/TestMessage.o"
        ;;
esac

# Keep large tags in a temporary schema so this test needs no permanent
# fixture. Cover top-level tags and tags on both SEQUENCE and CHOICE members.
mkdir "$tmpdir/large-tags"
cat >"$tmpdir/large-tags.asn1" <<'EOF'
LargeTags DEFINITIONS ::= BEGIN
Root ::= [1073741823] INTEGER
SequenceType ::= SEQUENCE { sequenceMember [1073741823] INTEGER }
ChoiceType ::= CHOICE { choiceMember [1073741823] INTEGER }
END
EOF

if ! "$compiler" -S "$skeletons" -D "$tmpdir/large-tags" \
    -no-gen-OER -no-gen-UPER -no-gen-APER -no-gen-JER \
    "$tmpdir/large-tags.asn1" >"$tmpdir/large-tags.log" 2>&1; then
    cat "$tmpdir/large-tags.log" >&2
    echo "FAIL: compiler rejected the maximum C tag number" >&2
    exit 1
fi

# Check the emitted tag-number expressions independently of the host compiler.
# In particular, the suffix must be a lowercase u so shifting is unsigned.
for module in Root SequenceType ChoiceType; do
    if ! grep -Eq '\(1073741823u[[:space:]]*<<[[:space:]]*2\)' \
        "$tmpdir/large-tags/$module.c"; then
        echo "FAIL: $module does not emit the maximum tag as an unsigned expression" >&2
        exit 1
    fi
done

# Promote Clang's signed-shift diagnostic to an error for every generated
# module that exercises a maximum-size root or member tag.
case "$compiler_version" in
    *[Cc]lang*)
        for module in Root SequenceType ChoiceType; do
            ${CC:-cc} -std=gnu18 -Werror=shift-sign-overflow \
                -I"$tmpdir/large-tags" -c "$tmpdir/large-tags/$module.c" \
                -o "$tmpdir/large-tags/$module.o"
        done
        # Emulate a narrower unsigned int limit and verify the target guard.
        cat >"$tmpdir/large-tags/narrow-target.h" <<'EOF'
#include <asn_system.h>
#undef UINT_MAX
#define UINT_MAX 65535u
EOF
        if ${CC:-cc} -I"$tmpdir/large-tags" -include "$tmpdir/large-tags/narrow-target.h" \
            -fsyntax-only "$tmpdir/large-tags/Root.c" >"$tmpdir/narrow.log" 2>&1; then
            echo "FAIL: the generated tag compiles with a narrower target range" >&2
            exit 1
        fi
        grep -Fq 'ASN.1 tag number exceeds the C target tag number range' "$tmpdir/narrow.log"
        ;;
esac

# Each bad definition must exit with a range error and leave the output empty.
expect_tag_range_error() {
    case_dir="$tmpdir/$1"
    mkdir "$case_dir"
    cat >"$case_dir/input.asn1" <<EOF
OutOfRangeTag DEFINITIONS ::= BEGIN
$2
END
EOF
    if "$compiler" -S "$skeletons" -D "$case_dir" \
        -no-gen-OER -no-gen-UPER -no-gen-APER -no-gen-JER \
        "$case_dir/input.asn1" >"$case_dir/generate.log" 2>&1; then
        echo "FAIL: compiler accepted $1" >&2
        exit 1
    else
        status=$?
    fi
    if [ "$status" -ge 128 ] || ! grep -Fq 'outside the C tag number range' "$case_dir/generate.log"; then
        cat "$case_dir/generate.log" >&2
        echo "FAIL: compiler must reject $1 with a tag range diagnostic (status $status)" >&2
        exit 1
    fi
    if find "$case_dir" -type f -name '*.c' -print | grep -q .; then
        echo "FAIL: compiler emitted C source for $1" >&2
        exit 1
    fi
}

expect_tag_range_error out-of-range 'Invalid ::= [1073741824] INTEGER'
expect_tag_range_error reserved-member 'Invalid ::= SEQUENCE OF [PRIVATE 1073741823] IMPLICIT INTEGER'

echo "PASS: generated constraints and maximum tag values compile cleanly"
