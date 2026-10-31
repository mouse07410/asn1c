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
Payload ::= OCTET STRING (SIZE(2))
MyExtIEs TESTCLASS ::= { { ID 1 EXTENSION INTEGER (0..255) } |
                         { ID 2 EXTENSION Payload }, ... }
Reference ::= SEQUENCE {
    id TESTCLASS.&id({MyExtIEs}),
    extension TESTCLASS.&Extension({MyExtIEs}{@id})
}
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
#include "Reference.h"
#include "ExtContainer.h"
#include "InlineAny.h"
#include "aper_decoder.h"
#include "aper_encoder.h"
#include "oer_decoder.h"
#include "oer_encoder.h"
#include "jer_decoder.h"
#include "jer_encoder.h"

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

/* Bounded JER output storage for generated round-trip tests. */
typedef struct jer_test_output_s {
    char bytes[128]; /* Captured output. */
    size_t size;     /* Output length state variable. */
} jer_test_output_t;

/*
 * Purpose: Capture encoded JER without overflowing the test buffer.
 * Source: Encoder callback contract. Version: 2026-10-30.
 * Inputs: data/size are bytes; key is output state. Returns: zero or -1.
 * Errors: Oversized output fails. Author: maintainers.
 * History: Added for SET IOC interoperability tests. Example: Capture JSON.
 */
static int
jer_test_collect(const void *data, size_t size, void *key) {
    jer_test_output_t *out = key;
    if(size > sizeof(out->bytes) - out->size) return -1;
    memcpy(out->bytes + out->size, data, size);
    out->size += size;
    return 0;
}

/*
 * Purpose: Verify selected SET JER values, ordering, streaming and duplicates.
 * Source: SET IOC JER interoperability regression. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers two-pass SET JER selection without owned staging buffers.
 * Example: ID can precede or follow the encoded selected INTEGER.
 */
static void
check_jer(void) {
    static const char before[] = "{\"id\":1,\"extension\":42}";
    static const char after[] = "{\"extension\":42,\"id\":1}";
    static const char duplicate[] = "{\"id\":1,\"extension\":42,\"extension\":42}";
    static const char unknown[] = "{\"extension\":42,\"id\":3}";
    static const char octets[] = "{\"extension\":\"A1B2\",\"id\":2}";
    static const char ext_before[] = "{\"fixed\":true,\"id\":1,\"extension\":42}";
    static const char ext_after[] = "{\"fixed\":true,\"extension\":42,\"id\":1}";
    RootContainer_t value = {0}, *decoded = 0;
    Reference_t reference = {0};
    ExtContainer_t absent = {0}, *decoded_ext = 0;
    jer_test_output_t output = {{0}, 0};
    asn_dec_rval_t result;
    asn_enc_rval_t encoded;
    size_t i;
    value.id = 1;
    value.extension.present = RootContainer__extension_PR_INTEGER_0_255_;
    value.extension.choice.INTEGER_0_255_ = 42;
    reference.id = 1;
    reference.extension.present = Reference__extension_PR_INTEGER_0_255_;
    reference.extension.choice.INTEGER_0_255_ = 42;
    encoded = jer_encode(&asn_DEF_Reference, &reference, JER_F_MINIFIED, jer_test_collect, &output);
    assert(encoded.encoded > 0);
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, output.bytes, output.size);
    assert(result.code == RC_OK && decoded->id == 1 && decoded->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    output.size = 0;
    encoded = jer_encode(&asn_DEF_RootContainer, &value, JER_F_MINIFIED, jer_test_collect, &output);
    assert(encoded.encoded == (ssize_t)(sizeof(after) - 1));
    assert(output.size == sizeof(after) - 1 && !memcmp(output.bytes, after, output.size));
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, output.bytes, output.size);
    assert(result.code == RC_OK && decoded->id == 1 && decoded->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, before, sizeof(before) - 1);
    assert(result.code == RC_OK && decoded->id == 1 && decoded->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    for(i = 1; i < sizeof(after) - 1; i++) {
        result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, after, i);
        assert(result.code == RC_WMORE && result.consumed == 0 && !decoded);
    }
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, after, sizeof(after) - 1);
    assert(result.code == RC_OK && decoded->id == 1 && decoded->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, duplicate, sizeof(duplicate) - 1);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    decoded = 0;
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, unknown, sizeof(unknown) - 1);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    value.extension.present = RootContainer__extension_PR_asn1cUnknown;
    output.size = 0;
    encoded = jer_encode(&asn_DEF_RootContainer, &value, JER_F_MINIFIED, jer_test_collect, &output);
    assert(encoded.encoded == -1);
    decoded = 0;
    result = jer_decode(0, &asn_DEF_RootContainer, (void **)&decoded, octets, sizeof(octets) - 1);
    assert(result.code == RC_OK && decoded->id == 2);
    assert(decoded->extension.present == RootContainer__extension_PR_Payload);
    assert(decoded->extension.choice.Payload.size == 2);
    assert(decoded->extension.choice.Payload.buf[0] == 0xa1 && decoded->extension.choice.Payload.buf[1] == 0xb2);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded);
    result = jer_decode(0, &asn_DEF_ExtContainer, (void **)&decoded_ext,
                        ext_before, sizeof(ext_before) - 1);
    assert(result.code == RC_OK && decoded_ext->id && *decoded_ext->id == 1);
    assert(decoded_ext->extension && decoded_ext->extension->choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded_ext);
    decoded_ext = 0;
    result = jer_decode(0, &asn_DEF_ExtContainer, (void **)&decoded_ext,
                        ext_after, sizeof(ext_after) - 1);
    assert(result.code == RC_OK && decoded_ext->id && *decoded_ext->id == 1);
    assert(decoded_ext->extension && decoded_ext->extension->choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded_ext);
    absent.fixed = 1;
    output.size = 0;
    encoded = jer_encode(&asn_DEF_ExtContainer, &absent, JER_F_MINIFIED, jer_test_collect, &output);
    assert(encoded.encoded > 0);
}

/* Execute both generated IOC layouts. */
int main(void) {
    check_root();
    check_additions();
    check_inline_any();
    check_jer();
    return 0;
}
C_EOF
${MAKE:-make} -f converter-example.mk
${CC:-cc} -I. -o test_program test_program.c libasncodec.a -lm
./test_program
