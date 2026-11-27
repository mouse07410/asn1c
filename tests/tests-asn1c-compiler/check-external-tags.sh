#!/bin/sh

# Check that unknown external tags are preserved where the descriptor can
# delegate tag discovery and rejected where a container needs a concrete tag.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${top_builddir}/asn1c/asn1c"
SKELETONS="${top_srcdir}/skeletons"
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT HUP INT TERM

# Run an expected failure and require an ordinary nonzero exit plus a message.
# asn1c's documented exit statuses are below 128; signal-like shell statuses
# are rejected explicitly so a crash cannot satisfy a negative test.
expect_failure() {
    name="$1"
    definition="$2"
    diagnostic="$3"
    case_dir="$TMPDIR_TEST/$name"
    mkdir -p "$case_dir/out"
    cat >"$case_dir/input.asn1" <<EOF
M DEFINITIONS EXPLICIT TAGS ::= BEGIN
$definition
END
EOF

    set +e
    (cd "$case_dir" && "$ASN1C" -S "$SKELETONS" \
        -fknown-extern-type=KnownExt -no-gen-example -D out input.asn1) \
        >"$case_dir/stdout" 2>"$case_dir/stderr"
    status=$?
    set -e

    if [ "$status" -eq 0 ]; then
        echo "FAIL: $name unexpectedly succeeded" >&2
        cat "$case_dir/stderr" >&2
        exit 1
    fi
    if [ "$status" -ge 128 ]; then
        echo "FAIL: $name terminated with signal-like status $status" >&2
        cat "$case_dir/stderr" >&2
        exit 1
    fi
    if ! grep -F "$diagnostic" "$case_dir/stderr" >/dev/null; then
        echo "FAIL: $name did not report '$diagnostic'" >&2
        cat "$case_dir/stderr" >&2
        exit 1
    fi
    echo "PASS: $name exits with a diagnostic (status $status)"
}

# Untagged external members cannot participate in the generated tag dispatch.
expect_failure sequence-member \
    'T ::= SEQUENCE { ext KnownExt }' 'has no known outer tag'
expect_failure set-member \
    'T ::= SET { ext KnownExt }' 'has no known outer tag'
expect_failure choice-member \
    'T ::= CHOICE { ext KnownExt, ok INTEGER }' 'has no known outer tag'

# A root alias has no descriptor to delegate to; explicit aliases must retain
# the established fatal diagnostic and must not crash during code generation.
expect_failure untagged-alias \
    'T ::= KnownExt' 'cannot generate a descriptor'
expect_failure explicit-alias \
    'T ::= [0] EXPLICIT KnownExt' 'dangerously incompatible'
if ! grep -E '^FATAL: .*dangerously incompatible' \
    "$TMPDIR_TEST/explicit-alias/stderr" >/dev/null; then
    echo "FAIL: explicit external alias did not report the expected FATAL" >&2
    cat "$TMPDIR_TEST/explicit-alias/stderr" >&2
    exit 1
fi

# Static CHOICE collision checks cannot compare the external branch's tag.
warning_dir="$TMPDIR_TEST/external-choice-warning"
mkdir -p "$warning_dir"
cat >"$warning_dir/input.asn1" <<'EOF'
M DEFINITIONS EXPLICIT TAGS ::= BEGIN
T ::= CHOICE { ext KnownExt, value INTEGER }
END
EOF
if ! (cd "$warning_dir" && "$ASN1C" -S "$SKELETONS" \
    -fknown-extern-type=KnownExt -EF input.asn1) \
    >"$warning_dir/stdout" 2>"$warning_dir/stderr"; then
    echo "FAIL: external CHOICE fix should complete with a warning" >&2
    cat "$warning_dir/stderr" >&2
    exit 1
fi
if ! grep -F 'Cannot verify tag uniqueness for external component ext' \
    "$warning_dir/stderr" >/dev/null; then
    echo "FAIL: external CHOICE collision check omitted its warning" >&2
    cat "$warning_dir/stderr" >&2
    exit 1
fi
echo "PASS: external CHOICE collision check warns when tag is unknown"
set +e
(cd "$warning_dir" && "$ASN1C" -S "$SKELETONS" \
    -fknown-extern-type=KnownExt -Werror -EF input.asn1) \
    >"$warning_dir/werror.out" 2>"$warning_dir/werror.err"
status=$?
set -e
if [ "$status" -ne 65 ] || ! grep -Fq \
    'Cannot verify tag uniqueness for external component ext' "$warning_dir/werror.err"; then
    echo "FAIL: -Werror did not reject the external CHOICE warning (status $status)" >&2
    cat "$warning_dir/werror.err" >&2
    exit 1
fi
echo "PASS: -Werror rejects the external CHOICE warning"

# External elements in collections delegate their tag to the referenced
# descriptor. Explicit member tags remain represented in all container kinds.
tagged_dir="$TMPDIR_TEST/tagged"
mkdir -p "$tagged_dir/out"
cat >"$tagged_dir/input.asn1" <<'EOF'
M DEFINITIONS EXPLICIT TAGS ::= BEGIN
TaggedSequence ::= SEQUENCE { ext [0] EXPLICIT KnownExt }
TaggedSet ::= SET { ext [1] EXPLICIT KnownExt }
TaggedChoice ::= CHOICE { ext [2] EXPLICIT KnownExt, ok INTEGER }
SequenceOf ::= SEQUENCE OF KnownExt
SetOf ::= SET OF KnownExt
END
EOF
if ! (cd "$tagged_dir" && "$ASN1C" -S "$SKELETONS" \
    -fknown-extern-type=KnownExt -no-gen-example -D out input.asn1) \
    >"$tagged_dir/stdout" 2>"$tagged_dir/stderr"; then
    echo "FAIL: tagged external members should compile" >&2
    cat "$tagged_dir/stderr" >&2
    exit 1
fi

for type in TaggedSequence TaggedSet TaggedChoice; do
    if ! grep -F 'EXPLICIT tag at current level' \
        "$tagged_dir/out/$type.c" >/dev/null; then
        echo "FAIL: $type lost its declared EXPLICIT tag" >&2
        exit 1
    fi
done
for pair in 'TaggedSequence 0' 'TaggedSet 1' 'TaggedChoice 2'; do
    type=${pair% *}
    tag_number=${pair##* }
    if ! grep -F "(ASN_TAG_CLASS_CONTEXT | ($tag_number << 2))" \
        "$tagged_dir/out/$type.c" >/dev/null; then
        echo "FAIL: $type lost declared context tag $tag_number" >&2
        exit 1
    fi
done
for type in SequenceOf SetOf; do
    if ! grep -F -- '-1 /* Tag supplied by the external type descriptor */' \
        "$tagged_dir/out/$type.c" >/dev/null; then
        echo "FAIL: $type does not delegate the element tag to its descriptor" >&2
        exit 1
    fi
done
echo "PASS: explicit tags and external collection sentinels are generated"

# AUTOMATIC TAGS must continue to assign a usable outer tag to the member.
automatic_dir="$TMPDIR_TEST/automatic"
mkdir -p "$automatic_dir/out"
cat >"$automatic_dir/input.asn1" <<'EOF'
M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
AutoSequence ::= SEQUENCE { ext KnownExt }
AutoSet ::= SET { ext KnownExt }
AutoChoice ::= CHOICE { ext KnownExt, ok INTEGER }
END
EOF
if ! (cd "$automatic_dir" && "$ASN1C" -S "$SKELETONS" \
    -fknown-extern-type=KnownExt -no-gen-example -D out input.asn1) \
    >"$automatic_dir/stdout" 2>"$automatic_dir/stderr"; then
    echo "FAIL: automatic external member tags should compile" >&2
    cat "$automatic_dir/stderr" >&2
    exit 1
fi

for type in AutoSequence AutoSet AutoChoice; do
    if ! grep -F 'IMPLICIT tag at current level' \
        "$automatic_dir/out/$type.c" >/dev/null; then
        echo "FAIL: $type lost its AUTOMATIC tag" >&2
        exit 1
    fi
    if ! grep -F '(ASN_TAG_CLASS_CONTEXT | (0 << 2))' \
        "$automatic_dir/out/$type.c" >/dev/null; then
        echo "FAIL: $type lost its automatic context tag" >&2
        exit 1
    fi
done
echo "PASS: automatic tags on external members are generated"
