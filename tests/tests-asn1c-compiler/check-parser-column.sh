#!/bin/sh

# Parser errors name the offending token's source column (ASN1-0112).
#
# A syntax error must print file:line:column on stderr, with the 1-based
# start column of the token yyerror() runs on (the lookahead), and asn1c must
# still fail.  Tabs count as one character, and a token at the start of a
# line is column 1.

set -eu

top_srcdir=$(cd "${top_srcdir:-../..}" && pwd)
top_builddir=$(cd "${top_builddir:-../..}" && pwd)

ASN1C="${top_builddir}/asn1c/asn1c"
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

failures=0

# A comma after four spaces of indentation: four spaces, "A", space, "::=",
# space, so the offending token starts in column 11.
cat >"$TMPDIR_TEST/indented.asn1" <<'EOF'
ColTest DEFINITIONS ::= BEGIN
    A ::= , INTEGER
END
EOF

# The same error on a token that starts the line.
cat >"$TMPDIR_TEST/column1.asn1" <<'EOF'
ColTest DEFINITIONS ::= BEGIN
, INTEGER
END
EOF

# A tab counts as one column: tab, "A", space, "::=", space, comma.
printf 'ColTest DEFINITIONS ::= BEGIN\n\tA ::= , INTEGER\nEND\n' \
    >"$TMPDIR_TEST/tab.asn1"

# expect_column <name> <schema> <file:line:column>
expect_column() {
    name="$1"
    schema="$2"
    where="$3"

    set +e
    "$ASN1C" -E "$schema" >"$TMPDIR_TEST/$name.out" 2>"$TMPDIR_TEST/$name.err"
    status=$?
    set -e

    if [ "$status" -eq 0 ]; then
        echo "FAIL: $name: parser accepted a broken schema"
        failures=$((failures + 1))
        return 0
    fi
    if grep -F "$where" "$TMPDIR_TEST/$name.err" >/dev/null; then
        echo "PASS: $name: parser error reported at $where"
    else
        echo "FAIL: $name: parser error lacks $where"
        cat "$TMPDIR_TEST/$name.err" >&2
        failures=$((failures + 1))
    fi
}

expect_column indented "$TMPDIR_TEST/indented.asn1" "indented.asn1:2:11"
expect_column column1 "$TMPDIR_TEST/column1.asn1" "column1.asn1:2:1"
expect_column tab "$TMPDIR_TEST/tab.asn1" "tab.asn1:2:8"

if [ "$failures" -ne 0 ]; then
    echo "$failures parser column check(s) failed"
    exit 1
fi

echo "PASS: parser errors report the offending token's column"
