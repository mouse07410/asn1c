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
RootReference ::= SEQUENCE {
    extension TESTCLASS.&Extension({MyExtIEs}{@id}),
    id TESTCLASS.&id({MyExtIEs})
}
ExtReference ::= SEQUENCE {
    fixed BOOLEAN,
    ...,
    extension TESTCLASS.&Extension({MyExtIEs}{@id}),
    id TESTCLASS.&id({MyExtIEs})
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
#include "RootReference.h"
#include "ExtReference.h"
#include "ExtContainer.h"
#include "InlineAny.h"
#include "aper_decoder.h"
#include "aper_encoder.h"
#include "uper_decoder.h"
#include "uper_encoder.h"
#include "uper_support.h"
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

/*
 * Purpose: Replace an eight-bit field at an arbitrary UPER bit offset.
 * Source: Test-only bit mutation. Version: 2026-10-30.
 * Inputs: bytes is mutable storage; offset locates the field; value is new data.
 * Returns: nothing. Errors: callers supply valid offsets. Author: maintainers.
 * History: Added for malformed nested-envelope regressions.
 * Example: Replacing an inner length with 127 makes its outer envelope too short.
 */
static void
uper_test_set_octet(uint8_t *bytes, size_t offset, unsigned value) {
    unsigned i;
    for(i = 0; i < 8; i++) {
        size_t bit = offset + i;
        uint8_t mask = (uint8_t)(0x80u >> (bit & 7));
        if(value & (0x80u >> i)) bytes[bit / 8] |= mask;
        else bytes[bit / 8] &= (uint8_t)~mask;
    }
}

/*
 * Purpose: Reject malformed nested addition lengths and unknown later IDs.
 * Source: X.691 extension framing. Version: 2026-10-30.
 * Inputs: bytes/count/bits hold a valid generated addition encoding.
 * Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers deferred buffers on malformed and unknown selections.
 * Example: Extra bytes inside a closed outer envelope must be rejected.
 */
static void
check_uper_bad_additions(const uint8_t *bytes, size_t count, size_t bits) {
    uint8_t malformed[256] = {0};
    asn_per_data_t cursor = {0};
    ExtContainer_t *decoded = 0;
    asn_dec_rval_t result;
    size_t outer_header, inner_header, outer_end, id_value, i;
    ssize_t length;
    int repeat;
    assert(count + 1 < sizeof(malformed));
    cursor.buffer = bytes;
    cursor.nbits = bits;
    assert(per_get_few_bits(&cursor, 1) == 1); /* Extension-present bit. */
    assert(per_get_few_bits(&cursor, 1) == 1); /* Fixed BOOLEAN root. */
    assert(uper_get_nslength(&cursor) == 2);
    assert(per_get_few_bits(&cursor, 2) == 3); /* Both additions present. */
    outer_header = cursor.moved;
    length = uper_get_length(&cursor, -1, 0, &repeat);
    assert(length == 2 && !repeat);
    inner_header = cursor.moved;
    outer_end = inner_header + (size_t)length * 8;
    assert(per_get_few_bits(&cursor, 8) == 1);
    assert(per_get_few_bits(&cursor, 8) == 42);
    assert(uper_get_length(&cursor, -1, 0, &repeat) == 2 && !repeat);
    assert(per_get_few_bits(&cursor, 8) == 1);
    id_value = cursor.moved;
    assert(per_get_few_bits(&cursor, 8) == 1);

    memcpy(malformed, bytes, count);
    uper_test_set_octet(malformed, inner_header, 127);
    result = uper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded, malformed, count);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded);
    decoded = 0;
    memcpy(malformed, bytes, count);
    uper_test_set_octet(malformed, id_value, 3);
    result = uper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded, malformed, count);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded);
    decoded = 0;
    memcpy(malformed, bytes, count);
    for(i = bits; i > outer_end; i--) {
        unsigned set = (malformed[(i - 1) / 8] >> (7 - ((i - 1) & 7))) & 1;
        size_t target = i + 7;
        uint8_t mask = (uint8_t)(0x80u >> (target & 7));
        if(set) malformed[target / 8] |= mask;
        else malformed[target / 8] &= (uint8_t)~mask;
    }
    uper_test_set_octet(malformed, outer_end, 0);
    uper_test_set_octet(malformed, outer_header, 3);
    result = uper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded,
                                  malformed, (bits + 15) / 8);
    assert(result.code == RC_FAIL);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded);
}

/*
 * Purpose: Round-trip generated UPER SET roots and extension additions.
 * Source: SET IOC interoperability regression. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers canonical root ordering and later extension selectors.
 * Example: An open INTEGER 42 is selected by a following ID of one.
 */
static void
check_uper(void) {
    RootContainer_t root = {0}, *decoded_root = 0;
    RootReference_t root_reference = {0};
    ExtContainer_t addition = {0}, *decoded_addition = 0;
    ExtReference_t addition_reference = {0};
    ExtContainer__extension extension = {0};
    ExtReference__extension extension_reference = {0};
    long id = 1;
    uint8_t bytes[128], reference_bytes[128];
    size_t count;
    asn_enc_rval_t enc, reference_enc;
    asn_dec_rval_t dec;
    root.id = 1;
    root.extension.present = RootContainer__extension_PR_INTEGER_0_255_;
    root.extension.choice.INTEGER_0_255_ = 42;
    enc = uper_encode_to_buffer(&asn_DEF_RootContainer, 0, &root, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    root_reference.id = 1;
    root_reference.extension.present = RootReference__extension_PR_INTEGER_0_255_;
    root_reference.extension.choice.INTEGER_0_255_ = 42;
    reference_enc = uper_encode_to_buffer(&asn_DEF_RootReference, 0, &root_reference,
                                          reference_bytes, sizeof(reference_bytes));
    assert(reference_enc.encoded == enc.encoded);
    count = ((size_t)enc.encoded + 7) / 8;
    assert(!memcmp(bytes, reference_bytes, count));
    dec = uper_decode_complete(0, &asn_DEF_RootContainer, (void **)&decoded_root, bytes, count);
    assert(dec.code == RC_OK && decoded_root->id == 1);
    assert(decoded_root->extension.present == RootContainer__extension_PR_INTEGER_0_255_);
    assert(decoded_root->extension.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded_root);
    decoded_root = 0;
    dec = uper_decode_complete(0, &asn_DEF_RootContainer, (void **)&decoded_root, bytes, count - 1);
    assert(dec.code == RC_WMORE);
    if(decoded_root) ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded_root);
    decoded_root = 0;
    assert(enc.encoded % 8 == 0 && bytes[count - 1] == 1);
    bytes[count - 1] = 3;
    dec = uper_decode_complete(0, &asn_DEF_RootContainer, (void **)&decoded_root, bytes, count);
    assert(dec.code == RC_FAIL);
    if(decoded_root) ASN_STRUCT_FREE(asn_DEF_RootContainer, decoded_root);
    root.id = 3;
    assert(uper_encode_to_buffer(&asn_DEF_RootContainer, 0, &root, bytes, sizeof(bytes)).encoded == -1);
    root.id = 1;
    root.extension.present = RootContainer__extension_PR_Payload;
    assert(uper_encode_to_buffer(&asn_DEF_RootContainer, 0, &root, bytes, sizeof(bytes)).encoded == -1);

    addition.fixed = 1;
    addition.id = &id;
    addition.extension = &extension;
    extension.present = ExtContainer__extension_PR_INTEGER_0_255_;
    extension.choice.INTEGER_0_255_ = 42;
    enc = uper_encode_to_buffer(&asn_DEF_ExtContainer, 0, &addition, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    addition_reference.fixed = 1;
    addition_reference.id = &id;
    addition_reference.extension = &extension_reference;
    extension_reference.present = ExtReference__extension_PR_INTEGER_0_255_;
    extension_reference.choice.INTEGER_0_255_ = 42;
    reference_enc = uper_encode_to_buffer(&asn_DEF_ExtReference, 0, &addition_reference,
                                          reference_bytes, sizeof(reference_bytes));
    assert(reference_enc.encoded == enc.encoded);
    count = ((size_t)enc.encoded + 7) / 8;
    assert(!memcmp(bytes, reference_bytes, count));
    check_uper_bad_additions(bytes, count, (size_t)enc.encoded);
    dec = uper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded_addition, bytes, count);
    assert(dec.code == RC_OK && decoded_addition->id && *decoded_addition->id == 1);
    assert(decoded_addition->extension && decoded_addition->extension->choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded_addition);
    decoded_addition = 0;
    {
        size_t prefix;
        for(prefix = 0; prefix < count; prefix++) {
            dec = uper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded_addition, bytes, prefix);
            assert(dec.code == RC_WMORE);
            if(decoded_addition) ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded_addition);
            decoded_addition = 0;
        }
    }
    addition.extension = 0;
    addition.id = 0;
    enc = uper_encode_to_buffer(&asn_DEF_ExtContainer, 0, &addition, bytes, sizeof(bytes));
    assert(enc.encoded > 0);
    dec = uper_decode_complete(0, &asn_DEF_ExtContainer, (void **)&decoded_addition,
                               bytes, ((size_t)enc.encoded + 7) / 8);
    assert(dec.code == RC_OK && !decoded_addition->id && !decoded_addition->extension);
    ASN_STRUCT_FREE(asn_DEF_ExtContainer, decoded_addition);
}

/* Execute both generated IOC layouts. */
int main(void) {
    check_root();
    check_additions();
    check_inline_any();
    check_jer();
    check_uper();
    return 0;
}
C_EOF
${MAKE:-make} -f converter-example.mk
${CC:-cc} -I. -o test_program test_program.c libasncodec.a -lm
./test_program
