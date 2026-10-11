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
