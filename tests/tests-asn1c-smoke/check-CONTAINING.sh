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

# Inline contained types lack dedicated generated descriptors and must fail.
for contained in 'INTEGER (0..2)' 'SEQUENCE { x BOOLEAN }'; do
    for outer in 'BIT STRING' 'OCTET STRING'; do
        printf 'Repro DEFINITIONS ::= BEGIN\nOuter ::= %s (CONTAINING %s)\nEND\n' \
            "$outer" "$contained" > invalid-inline.asn
        if "${ASN1C}" -S "${SKELETONS_DIR}" invalid-inline.asn; then
            echo "Unsupported inline CONTAINING was accepted" >&2
            exit 1
        fi
        if "${ASN1C}" -fno-constraints -no-gen-OER -no-gen-UPER -no-gen-APER \
            -S "${SKELETONS_DIR}" invalid-inline.asn; then
            echo "Unsupported inline CONTAINING was accepted without constraints" >&2
            exit 1
        fi
    done
done

cat > repro.asn <<'EOF'
Repro DEFINITIONS ::= BEGIN
Inner ::= SEQUENCE { a BIT STRING (SIZE (16)), b INTEGER (0..255) }
Outer ::= SEQUENCE { c BIT STRING (CONTAINING Inner) }
END
EOF

"${ASN1C}" -S "${SKELETONS_DIR}" -fcompound-names -pdu=Outer \
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
    -no-gen-BER -no-gen-JER -no-gen-OER -no-gen-CBOR repro.asn
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
