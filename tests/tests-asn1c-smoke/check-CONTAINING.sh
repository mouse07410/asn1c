#!/bin/sh

set -e

top_builddir=${top_builddir:-../..}
top_srcdir=${top_srcdir:-../..}

path_from_workdir() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '../%s\n' "$1" ;;
    esac
}

ASN1C="$(path_from_workdir "${top_builddir}")/asn1c/asn1c"
SKELETONS_DIR="$(path_from_workdir "${top_srcdir}")/skeletons"
WORKDIR="test-CONTAINING"

rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

# Inline contained types receive dedicated generated descriptors.
inline_index=0
for contained in 'INTEGER (0..2)' 'SEQUENCE { x BOOLEAN }'; do
    for outer in 'BIT STRING' 'OCTET STRING'; do
        inline_index=$((inline_index + 1))
        printf 'Repro DEFINITIONS ::= BEGIN\nOuter ::= %s (CONTAINING %s)\nEND\n' \
            "$outer" "$contained" > inline.asn
        mkdir "inline-${inline_index}" "inline-no-constraints-${inline_index}"
        "${ASN1C}" -S "${SKELETONS_DIR}" -no-gen-example \
            -D "inline-${inline_index}" inline.asn
        test -f "inline-${inline_index}/ASN1CContained1.c"
        "${ASN1C}" -fno-constraints -no-gen-OER -no-gen-UPER -no-gen-APER \
            -S "${SKELETONS_DIR}" -no-gen-example \
            -D "inline-no-constraints-${inline_index}" inline.asn
        test -f "inline-no-constraints-${inline_index}/ASN1CContained1.c"
    done
done

# Adding CONTAINING must not reprocess unrelated IOC specializations.
ioc_fixture="$(path_from_workdir "${top_srcdir}")/tests/tests-asn1c-compiler/170-private-ie-field-OK.asn1"
# A distcheck source tree is read-only; redirection gives the new fixture a
# writable mode even when the packaged source file cannot be modified.
cat "$ioc_fixture" > mixed-ioc.asn
cat >> mixed-ioc.asn <<'EOF'
Additional DEFINITIONS ::= BEGIN
Extra ::= OCTET STRING (CONTAINING INTEGER (0..2))
END
EOF
for input in "$ioc_fixture" mixed-ioc.asn; do
    output="ioc-$(basename "$input").out"
    "${ASN1C}" -S "${SKELETONS_DIR}" -no-gen-OER -no-gen-UPER \
        -no-gen-APER -no-gen-JER -P -fno-include-deps -findirect-choice \
        -fcompound-names "$input" > "$output"
    sed -n '/<<< FUNC-DECLS \[PrivateIE-Field\]/,/<<< INCLUDES \[PrivateIE-Container\]/p' \
        "$output" > "$output.section"
done
test -s ioc-mixed-ioc.asn.out.section
cmp "ioc-$(basename "$ioc_fixture").out.section" ioc-mixed-ioc.asn.out.section

# Traversal must not impose a new limit on schemas without CONTAINING.
deep_type='BOOLEAN'
deep_index=0
while [ "$deep_index" -lt 80 ]; do
    deep_type="SEQUENCE { x${deep_index} ${deep_type} }"
    deep_index=$((deep_index + 1))
done
printf 'Repro DEFINITIONS ::= BEGIN\nDeep ::= %s\nEND\n' "$deep_type" > deep.asn
mkdir deep-output
"${ASN1C}" -S "${SKELETONS_DIR}" -no-gen-example -D deep-output deep.asn
test -f deep-output/Deep.c

# Parameter actuals and formal references retain the contained type's scope.
cat > parameter-actual.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Wrapper{T} ::= SEQUENCE { value T }
Outer ::= Wrapper{OCTET STRING (CONTAINING INTEGER (0..2))}
END
EOF
cat > parameter-formal.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Wrapper{T} ::= OCTET STRING (CONTAINING SEQUENCE { x T })
Outer ::= Wrapper{INTEGER}
END
EOF
cat > parameter-nested.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Wrapper{T} ::= OCTET STRING (CONTAINING SEQUENCE {
    x OCTET STRING (CONTAINING SEQUENCE { y T })
})
Outer ::= Wrapper{INTEGER}
END
EOF
cat > parameter-cross.asn <<'EOF'
Library DEFINITIONS ::= BEGIN
EXPORTS Wrapper;
Wrapper{T} ::= OCTET STRING (CONTAINING SEQUENCE { x T })
END
Repro DEFINITIONS ::= BEGIN
IMPORTS Wrapper FROM Library;
A ::= INTEGER (0..2)
Outer ::= Wrapper{A}
END
EOF
cat > parameter-constraint.asn <<'EOF'
Library DEFINITIONS ::= BEGIN
EXPORTS Wrapper;
Wrapper{T} ::= OCTET STRING (CONTAINING SEQUENCE { x T })
END
Repro DEFINITIONS ::= BEGIN
IMPORTS Wrapper FROM Library;
Outer ::= OCTET STRING (CONTAINING Wrapper{INTEGER})
END
EOF
for case_name in actual formal nested cross constraint; do
    mkdir "parameter-${case_name}-output"
    "${ASN1C}" -S "${SKELETONS_DIR}" -no-gen-example \
        -pdu=Outer -fgen-only-pdu-deps \
        -D "parameter-${case_name}-output" "parameter-${case_name}.asn"
    test -f "parameter-${case_name}-output/ASN1CContained1.c"
    for source in "parameter-${case_name}-output"/ASN1CContained*.c \
                  "parameter-${case_name}-output"/Outer.c \
                  "parameter-${case_name}-output"/Wrapper.c \
                  "parameter-${case_name}-output"/A.c; do
        test -f "$source" || continue
        ${CC:-cc} -std=c99 -I "parameter-${case_name}-output" \
            -I "${SKELETONS_DIR}" -c "$source" -o "${source%.c}.o"
    done
done
test -f parameter-nested-output/ASN1CContained2.c
test -f parameter-cross-output/A.c
test -f parameter-constraint-output/ASN1CContained2.c
grep 'asn_check_octet_containing_constraint' parameter-constraint-output/Wrapper.c >/dev/null

cat > repro.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Inner ::= SEQUENCE { a BIT STRING (SIZE (16)), b INTEGER (0..255) }
Outer ::= SEQUENCE { c BIT STRING (CONTAINING Inner) }
END
EOF

"${ASN1C}" -S "${SKELETONS_DIR}" -fcompound-names -pdu=Outer \
    -fgen-only-pdu-deps \
    -no-gen-BER -no-gen-JER -no-gen-OER -no-gen-CBOR repro.asn
CFLAGS="${CFLAGS:-} -DJUNKTEST" ${MAKE:-make} -f converter-example.mk

./converter-example -R 64 -n 10 -ouper > random.uper
./converter-example -iuper -c -onull random.uper

printf '\010\251' > invalid.uper
if ./converter-example -iuper -c -onull invalid.uper; then
    echo "Invalid CONTAINING content passed the constraint check" >&2
    exit 1
fi

cd ..
rm -rf "${WORKDIR}"

# OCTET STRING content is a complete encoding, including zero PER padding.
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"
cat > repro.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Inner ::= INTEGER (0..2)
Outer ::= SEQUENCE { c OCTET STRING (CONTAINING Inner) }
END
EOF
"${ASN1C}" -S "${SKELETONS_DIR}" -fcompound-names -pdu=Outer \
    -fgen-only-pdu-deps \
    -no-gen-BER -no-gen-JER -no-gen-OER repro.asn
${MAKE:-make} -f converter-example.mk
printf '\001\200' > valid.uper
printf '\001\201' > bad-padding.uper
printf '\002\200\000' > trailing.uper
printf '\000' > empty.uper
printf '\001\300' > spare.uper
./converter-example -iuper -c -onull valid.uper
for input in bad-padding.uper trailing.uper empty.uper spare.uper; do
    if ./converter-example -iuper -c -onull "$input"; then
        echo "Invalid OCTET STRING CONTAINING content accepted: $input" >&2
        exit 1
    fi
done
./converter-example -iaper -c -onull valid.uper
for input in bad-padding.uper trailing.uper empty.uper spare.uper; do
    if ./converter-example -iaper -c -onull "$input"; then
        echo "Invalid APER OCTET STRING CONTAINING content accepted: $input" >&2
        exit 1
    fi
done
# CBOR carries the complete inner encoding as OCTET STRING bytes.
printf '\241\141\143\101\001' > valid.cbor
printf '\241\141\143\101\377' > invalid.cbor
./converter-example -icbor -c -onull valid.cbor
./converter-example -icbor -c -ocbor valid.cbor > roundtrip.cbor
cmp valid.cbor roundtrip.cbor
if ./converter-example -icbor -c -onull invalid.cbor; then
    echo "Invalid CBOR OCTET STRING CONTAINING content accepted" >&2
    exit 1
fi
cd ..
rm -rf "${WORKDIR}"

# BIT STRING CONTAINING carries complete CBOR octets after its unused-bit byte.
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"
cat > bit-cbor.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Inner ::= INTEGER (0..2)
Outer ::= BIT STRING (CONTAINING Inner)
END
EOF
"${ASN1C}" -S "${SKELETONS_DIR}" -fcompound-names -pdu=Outer \
    -fgen-only-pdu-deps -no-gen-BER -no-gen-JER -no-gen-OER bit-cbor.asn
${MAKE:-make} -f converter-example.mk
printf '\102\000\001' > valid.cbor
printf '\102\000\377' > invalid.cbor
printf '\102\001\000' > spare.cbor
./converter-example -icbor -c -onull valid.cbor
./converter-example -icbor -c -ocbor valid.cbor > roundtrip.cbor
cmp valid.cbor roundtrip.cbor
for input in invalid.cbor spare.cbor; do
    if ./converter-example -icbor -c -onull "$input"; then
        echo "Invalid CBOR BIT STRING CONTAINING content accepted: $input" >&2
        exit 1
    fi
done
cd ..
rm -rf "${WORKDIR}"

# A recursively contained type must fail safely on deeply nested input.
mkdir -p "${WORKDIR}"
cd "${WORKDIR}"
cat > recursive.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
C ::= OCTET STRING (CONTAINING C)
END
EOF
"${ASN1C}" -S "${SKELETONS_DIR}" -pdu=C \
    -no-gen-BER -no-gen-JER -no-gen-OER -no-gen-CBOR recursive.asn
${MAKE:-make} -f converter-example.mk
printf '\000' > nested.uper
length=1
while [ "$length" -le 80 ]; do
    printf "\\$(printf '%03o' "$length")" > nested-next.uper
    cat nested.uper >> nested-next.uper
    mv nested-next.uper nested.uper
    length=$((length + 1))
done
if ./converter-example -iuper -c -onull nested.uper; then
    echo "Recursive CONTAINING passed constraint checking" >&2
    exit 1
fi
cd ..
rm -rf "${WORKDIR}"
