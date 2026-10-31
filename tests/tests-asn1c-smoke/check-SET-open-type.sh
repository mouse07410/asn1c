#!/bin/sh
# Regression for generated IOC-selected SET roots and extension additions.
set -eu
top_builddir=${top_builddir:-../..}
top_srcdir=${top_srcdir:-../..}
path_from_testdir() {
    case "$1" in /*) printf '%s\n' "$1" ;; *) printf '../%s\n' "$1" ;; esac
}
ASN1C="$(path_from_testdir "${top_builddir}")/asn1c/asn1c"
SKELETONS_DIR="$(path_from_testdir "${top_srcdir}")/skeletons"
testdir="$(pwd)/test-SET-open-type"
trap 'rm -rf "${testdir}"' EXIT
rm -rf "${testdir}"
mkdir "${testdir}"
cd "${testdir}"
cat > input.asn <<'ASN'
TestModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN
TESTCLASS ::= CLASS { &id INTEGER UNIQUE, &Extension }
    WITH SYNTAX { ID &id EXTENSION &Extension }
MyExtIEs TESTCLASS ::= { { ID 1 EXTENSION INTEGER (0..255) }, ... }
RootContainer ::= SET {
    extension TESTCLASS.&Extension({MyExtIEs}{@id}),
    id TESTCLASS.&id({MyExtIEs})
}
InlineAny ::= SET { payload ANY }
ExtContainer ::= SET {
    fixed BOOLEAN,
    ...,
    extension TESTCLASS.&Extension({MyExtIEs}{@id}),
    id TESTCLASS.&id({MyExtIEs})
}
END
ASN
"${ASN1C}" -fcompound-names -flink-skeletons -gen-APER -gen-OER \
    -S "${SKELETONS_DIR}" input.asn
cat > test_program.c <<'C_EOF'
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "RootContainer.h"
#include "ExtContainer.h"
#include "InlineAny.h"
#include "aper_decoder.h"
#include "aper_encoder.h"
#include "oer_decoder.h"
#include "oer_encoder.h"

/*
 * Purpose: Round-trip a generated SET with an open root preceding its ID.
 * Source: IOC SET generator regression. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers APER and OER canonical order. Example: ID 1 selects 42.
 */
static void
check_root(void) {
    RootContainer_t value = {0}, *decoded = 0;
    uint8_t bytes[128];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    value.id = 1;
    value.extension.present = RootContainer__extension_PR_INTEGER_0_255_;
    value.extension.choice.INTEGER_0_255_ = 42;
    enc = aper_encode_to_buffer(&asn_DEF_RootContainer, 0, &value, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = aper_decode_complete(0, &asn_DEF_RootContainer, (void **)&decoded,
                               bytes, ((size_t)enc.encoded + 7) / 8);
    assert(dec.code == RC_OK && decoded->id == 1);
    assert(decoded->extension.present == RootContainer__extension_PR_INTEGER_0_255_);
    assert(decoded->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    enc = oer_encode_to_buffer(&asn_DEF_RootContainer, 0, &value, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = oer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, bytes, (size_t)enc.encoded);
    assert(dec.code == RC_OK && decoded->id == 1);
    assert(decoded->extension.present == RootContainer__extension_PR_INTEGER_0_255_);
    assert(decoded->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    /* The selected INTEGER occupies one byte; reject a second envelope byte. */
    assert(enc.encoded >= 3 && bytes[0] == 1);
    memmove(bytes + 3, bytes + 2, (size_t)enc.encoded - 2);
    bytes[0] = 2;
    bytes[2] = 0;
    dec = oer_decode(0, &asn_DEF_RootContainer, (void **)&decoded,
                     bytes, (size_t)enc.encoded + 1);
    assert(dec.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
}

/*
 * Purpose: Round-trip an open addition selected by a later ID addition.
 * Source: IOC SET generator regression. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers generated pointers and deferred selection. Example: ID 1 selects 42.
 */
static void
check_additions(void) {
    ExtContainer_t value = {0}, *decoded = 0;
    ExtContainer__extension extension = {0};
    long id = 1;
    uint8_t bytes[128];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    value.fixed = 1;
    value.id = &id;
    value.extension = &extension;
    extension.present = ExtContainer__extension_PR_INTEGER_0_255_;
    extension.choice.INTEGER_0_255_ = 42;
    enc = aper_encode_to_buffer(&asn_DEF_ExtContainer, 0, &value, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = aper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded,
                               bytes, ((size_t)enc.encoded + 7) / 8);
    assert(dec.code == RC_OK && decoded->id && *decoded->id == 1);
    assert(decoded->extension && decoded->extension->present == ExtContainer__extension_PR_INTEGER_0_255_);
    assert(decoded->extension->choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded);
    decoded = 0;
    enc = oer_encode_to_buffer(&asn_DEF_ExtContainer, 0, &value, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = oer_decode(0, &asn_DEF_ExtContainer, (void **)&decoded, bytes, (size_t)enc.encoded);
    assert(dec.code == RC_OK && decoded->id && *decoded->id == 1);
    assert(decoded->extension && decoded->extension->present == ExtContainer__extension_PR_INTEGER_0_255_);
    assert(decoded->extension->choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded);
}

/*
 * Purpose: Round-trip an inline ANY in a generated SET under APER and OER.
 * Source: ANY public signed-size layout. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers the smaller ANY storage layout in SET member validation.
 * Example: The payload 02 01 2a survives both byte-oriented codecs.
 */
static void
check_inline_any(void) {
    uint8_t payload[] = {2, 1, 42}, bytes[128];
    InlineAny_t value = {0}, *decoded = 0;
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    value.payload.buf = payload;
    value.payload.size = sizeof(payload);
    enc = aper_encode_to_buffer(&asn_DEF_InlineAny, 0, &value, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = aper_decode_complete(0, &asn_DEF_InlineAny, (void **)&decoded,
                               bytes, ((size_t)enc.encoded + 7) / 8);
    assert(dec.code == RC_OK && decoded->payload.size == sizeof(payload));
    assert(!memcmp(decoded->payload.buf, payload, sizeof(payload)));
    ASN_STRUCT_FREE(asn_DEF_InlineAny, decoded);
    decoded = 0;
    enc = oer_encode_to_buffer(&asn_DEF_InlineAny, 0, &value, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = oer_decode(0, &asn_DEF_InlineAny, (void **)&decoded, bytes, (size_t)enc.encoded);
    assert(dec.code == RC_OK && decoded->payload.size == sizeof(payload));
    assert(!memcmp(decoded->payload.buf, payload, sizeof(payload)));
    ASN_STRUCT_FREE(asn_DEF_InlineAny, decoded);
}

/* Execute both generated IOC layouts. */
int main(void) {
    check_root();
    check_additions();
    check_inline_any();
    return 0;
}
C_EOF
${MAKE:-make} -f converter-example.mk
${CC:-cc} -I. -o test_program test_program.c libasncodec.a -lm
./test_program
