#!/usr/bin/env bash
set -euo pipefail

# Test for IEEE 1609.2 IOC SEQUENCE OF with parent field references
# This test verifies that the compiler can handle SEQUENCE OF members
# with IOC constraints that reference fields from the parent SEQUENCE

srcdir="${srcdir:-.}"
abs_top_builddir="${abs_top_builddir:-$(cd ../.. && pwd)}"
abs_top_srcdir="${abs_top_srcdir:-$(cd ../.. && pwd)}"

# Copy source file if not already present
if [ ! -f ieee1609-contributed-extension.asn1 ]; then
  cp -p "${srcdir}/ieee1609-contributed-extension.asn1" .
fi

ASN1C_EXE="${abs_top_builddir}/asn1c/asn1c"
SKELETONS_DIR="${abs_top_srcdir}/skeletons"

echo "Testing IEEE 1609.2 IOC SEQUENCE OF with parent field references..."

# Generate code - this should not crash
${ASN1C_EXE} -S "${SKELETONS_DIR}" -fcompound-names \
  -pdu=ContributedExtensionBlock ieee1609-contributed-extension.asn1

# Verify that ContributedExtensionBlock was generated
if [ ! -f ContributedExtensionBlock.h ]; then
  echo "ERROR: ContributedExtensionBlock.h was not generated" >&2
  exit 1
fi

if [ ! -f ContributedExtensionBlock.c ]; then
  echo "ERROR: ContributedExtensionBlock.c was not generated" >&2
  exit 1
fi

# Verify that the struct has correct structure (forward declaration of Member)
if ! grep -Eq "typedef struct ContributedExtensionBlock__extns__.*_Member" ContributedExtensionBlock.h; then
  echo "ERROR: Forward declaration of Member not found" >&2
  exit 1
fi

# Verify that extns uses the forward-declared Member type
if ! grep -Eq "A_SEQUENCE_OF\\(ContributedExtensionBlock__extns__.*_Member\\)" ContributedExtensionBlock.h; then
  echo "ERROR: SEQUENCE OF Member not found in extns" >&2
  exit 1
fi

# Verify that the offsetof uses the correct parent struct
if ! grep -q "offsetof(struct ContributedExtensionBlock, contributorId)" ContributedExtensionBlock.c; then
  echo "ERROR: offsetof should reference ContributedExtensionBlock, not extns" >&2
  exit 1
fi

# Try to compile the generated code
echo "Compiling generated code..."
CFLAGS="-I. -I${SKELETONS_DIR} -Werror -Wall -Wno-parentheses-equality"
if ! ${CC:-cc} $CFLAGS -c ContributedExtensionBlock.c -o ContributedExtensionBlock.o; then
  echo "ERROR: Generated code does not compile" >&2
  exit 1
fi

# Super-test to ensure everything here compiles and links
make ASN_MODULE_CFLAGS="-I. -I${SKELETONS_DIR} -Wno-parentheses-equality" -f converter-example.mk
echo ""

echo "OK: IEEE 1609.2 IOC test passed"
