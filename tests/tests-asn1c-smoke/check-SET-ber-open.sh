#!/bin/sh
# Generated SET BER/DER IOC-selected OPEN TYPE interoperability regression.
set -eu
top_builddir=${top_builddir:-../..}
top_srcdir=${top_srcdir:-../..}
path_from_testdir() {
    case "$1" in /*) printf '%s\n' "$1" ;; *) printf '../%s\n' "$1" ;; esac
}
ASN1C="$(path_from_testdir "${top_builddir}")/asn1c/asn1c"
SKELETONS_DIR="$(path_from_testdir "${top_srcdir}")/skeletons"
testdir="$(pwd)/test-SET-ber-open"
trap 'rm -rf "${testdir}"' EXIT
rm -rf "${testdir}"
mkdir "${testdir}"
cd "${testdir}"
cat > input.asn <<'ASN'
TestModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN
TESTCLASS ::= CLASS { &id INTEGER UNIQUE, &Value } WITH SYNTAX { ID &id VALUE &Value }
Payload ::= OCTET STRING (SIZE(2))
Values TESTCLASS ::= { { ID 1 VALUE INTEGER (0..255) } | { ID 2 VALUE Payload }, ... }
Reference ::= SEQUENCE { value TESTCLASS.&Value({Values}{@id}), id TESTCLASS.&id({Values}) }
Root ::= SET { value TESTCLASS.&Value({Values}{@id}), id TESTCLASS.&id({Values}) }
Extended ::= SET { fixed BOOLEAN, ..., value TESTCLASS.&Value({Values}{@id}), id TESTCLASS.&id({Values}) }
OptionalSet ::= SET { id TESTCLASS.&id({Values}), value TESTCLASS.&Value({Values}{@id}) OPTIONAL,
                      unrelated BOOLEAN OPTIONAL }
END
ASN
"${ASN1C}" -fcompound-names -flink-skeletons -S "${SKELETONS_DIR}" input.asn
cat > test_program.c <<'C_EOF'
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "Root.h"
#include "Reference.h"
#include "Extended.h"
#include "OptionalSet.h"
#include "ber_decoder.h"
#include "der_encoder.h"

/*
 * Purpose: Validate canonical DER, both BER field orders, and malformed input.
 * Source: SET OPEN TYPE generated interoperability. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Added for atomic two-pass BER selection.
 * Example: A selected INTEGER may precede its identifier on the wire.
 */
static void
check_root(void) {
    static const uint8_t canonical[] = {0x31, 8, 0xa0, 3, 2, 1, 42, 0x81, 1, 1};
    static const uint8_t reversed[] = {0x31, 8, 0x81, 1, 1, 0xa0, 3, 2, 1, 42};
    static const uint8_t indefinite[] = {0x31, 0x80, 0x81, 1, 1, 0xa0, 3, 2, 1, 42, 0, 0};
    static const uint8_t duplicate[] = {0x31, 11, 0xa0, 3, 2, 1, 42, 0x81, 1, 1, 0x81, 1, 1};
    static const uint8_t malformed[] = {0x31, 8, 0xa0, 5, 2, 1, 42, 0x81, 1, 1};
    static const uint8_t wrong_tag[] = {0x31, 8, 0xa0, 3, 4, 1, 42, 0x81, 1, 1};
    static const uint8_t unknown[] = {0x31, 8, 0xa0, 3, 2, 1, 42, 0x81, 1, 3};
    Root_t value = {0}, *decoded = 0, *preallocated;
    Reference_t reference = {0};
    uint8_t output[64], reference_output[64];
    asn_enc_rval_t enc, ref;
    asn_dec_rval_t dec;
    size_t i;
    value.id = 1;
    value.value.present = Root__value_PR_INTEGER_0_255_;
    value.value.choice.INTEGER_0_255_ = 42;
    enc = der_encode_to_buffer(&asn_DEF_Root, &value, output, sizeof(output));
    assert(enc.encoded == sizeof(canonical) && !memcmp(output, canonical, sizeof(canonical)));
    reference.id = 1;
    reference.value.present = Reference__value_PR_INTEGER_0_255_;
    reference.value.choice.INTEGER_0_255_ = 42;
    ref = der_encode_to_buffer(&asn_DEF_Reference, &reference, reference_output, sizeof(reference_output));
    assert(ref.encoded == enc.encoded && !memcmp(output + 1, reference_output + 1, sizeof(canonical) - 1));
    for(i = 0; i < sizeof(canonical); i++) {
        dec = ber_decode(0, &asn_DEF_Root, (void **)&decoded, canonical, i);
        assert(dec.code == RC_WMORE && dec.consumed == 0 && !decoded);
    }
    preallocated = calloc(1, sizeof(*preallocated));
    assert(preallocated);
    decoded = preallocated;
    dec = ber_decode(0, &asn_DEF_Root, (void **)&decoded, canonical, sizeof(canonical));
    assert(dec.code == RC_OK && decoded == preallocated && decoded->id == 1);
    assert(decoded->value.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_Root, decoded);
    decoded = 0;
    dec = ber_decode(0, &asn_DEF_Root, (void **)&decoded, reversed, sizeof(reversed));
    assert(dec.code == RC_OK && decoded->id == 1 && decoded->value.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_Root, decoded);
    decoded = 0;
    dec = ber_decode(0, &asn_DEF_Root, (void **)&decoded, indefinite, sizeof(indefinite));
    assert(dec.code == RC_OK && decoded->id == 1 && decoded->value.choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_Root, decoded);
    decoded = 0;
#define CHECK_FAILURE(input) do { \
    dec = ber_decode(0, &asn_DEF_Root, (void **)&decoded, input, sizeof(input)); \
    assert(dec.code == RC_FAIL); \
    if(decoded) ASN_STRUCT_FREE(asn_DEF_Root, decoded); \
    decoded = 0; \
} while(0)
    CHECK_FAILURE(duplicate);
    CHECK_FAILURE(malformed);
    CHECK_FAILURE(wrong_tag);
    CHECK_FAILURE(unknown);
#undef CHECK_FAILURE
    value.value.present = Root__value_PR_Payload;
    assert(der_encode_to_buffer(&asn_DEF_Root, &value, output, sizeof(output)).encoded == -1);
}

/*
 * Purpose: Reject ambiguous metadata and preserve absent optional open values.
 * Source: SET tag routing and selector safety. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers unsupported untagged/overlapping tags and omitted siblings.
 * Example: A present open value with an absent unrelated sibling fails closed.
 */
static void
check_metadata_and_optional(void) {
    static const uint8_t missing_sibling[] = {0x31, 8, 0x80, 1, 1, 0xa1, 3, 2, 1, 42};
    Root_t value = {0}, *decoded = 0;
    OptionalSet_t optional = {0}, *decoded_optional = 0;
    OptionalSet__value selected = {0};
    asn_TYPE_descriptor_t bad = asn_DEF_Root;
    asn_SET_specifics_t specifics = *(const asn_SET_specifics_t *)bad.specifics;
    asn_TYPE_member_t members[2];
    asn_TYPE_tag2member_t map[2];
    uint8_t output[64];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    memcpy(members, bad.elements, sizeof(members));
    memcpy(map, specifics.tag2el, sizeof(map));
    bad.elements = members;
    bad.specifics = &specifics;
    specifics.tag2el = map;
    value.id = 1;
    value.value.present = Root__value_PR_INTEGER_0_255_;
    value.value.choice.INTEGER_0_255_ = 42;
    members[0].tag = (ber_tlv_tag_t)-1;
    assert(der_encode_to_buffer(&bad, &value, output, sizeof(output)).encoded == -1);
    dec = ber_decode(0, &bad, (void **)&decoded, output, 0);
    assert(dec.code == RC_FAIL && !decoded);
    members[0].tag = asn_DEF_Root.elements[0].tag;
    map[1].el_tag = map[0].el_tag;
    assert(der_encode_to_buffer(&bad, &value, output, sizeof(output)).encoded == -1);
    dec = ber_decode(0, &bad, (void **)&decoded, output, 0);
    assert(dec.code == RC_FAIL && !decoded);
    map[1] = ((const asn_SET_specifics_t *)asn_DEF_Root.specifics)->tag2el[1];
    members[1].flags |= ATF_OPEN_TYPE;
    members[1].type_selector = members[0].type_selector;
    dec = ber_decode(0, &bad, (void **)&decoded, output, 0);
    assert(dec.code == RC_FAIL && !decoded);

    optional.id = 1;
    enc = der_encode_to_buffer(&asn_DEF_OptionalSet, &optional, output, sizeof(output));
    assert(enc.encoded > 0);
    dec = ber_decode(0, &asn_DEF_OptionalSet, (void **)&decoded_optional, output, (size_t)enc.encoded);
    assert(dec.code == RC_OK && !decoded_optional->value && !decoded_optional->unrelated);
    ASN_STRUCT_FREE(asn_DEF_OptionalSet, decoded_optional);
    decoded_optional = 0;
    dec = ber_decode(0, &asn_DEF_OptionalSet, (void **)&decoded_optional,
                     missing_sibling, sizeof(missing_sibling));
    assert(dec.code == RC_FAIL);
    ASN_STRUCT_FREE(asn_DEF_OptionalSet, decoded_optional);
    selected.present = OptionalSet__value_PR_INTEGER_0_255_;
    selected.choice.INTEGER_0_255_ = 42;
    optional.value = &selected;
    assert(der_encode_to_buffer(&asn_DEF_OptionalSet, &optional, output, sizeof(output)).encoded == -1);
}

/*
 * Purpose: Round-trip pointer-backed generated extension open members.
 * Source: SET BER extension metadata. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Errors: assertions abort. Author: maintainers.
 * History: Covers selector-after ordering and preallocated empty targets.
 * Example: Extension ID one selects the INTEGER value 42.
 */
static void
check_extension(void) {
    Extended_t value = {0}, *decoded;
    Extended__value selected = {0};
    long id = 1;
    uint8_t output[64];
    asn_enc_rval_t enc;
    asn_dec_rval_t dec;
    value.fixed = 1;
    value.id = &id;
    value.value = &selected;
    selected.present = Extended__value_PR_INTEGER_0_255_;
    selected.choice.INTEGER_0_255_ = 42;
    enc = der_encode_to_buffer(&asn_DEF_Extended, &value, output, sizeof(output));
    assert(enc.encoded > 0);
    decoded = calloc(1, sizeof(*decoded));
    assert(decoded);
    dec = ber_decode(0, &asn_DEF_Extended, (void **)&decoded, output, (size_t)enc.encoded);
    assert(dec.code == RC_OK && decoded->id && *decoded->id == 1);
    assert(decoded->value && decoded->value->choice.INTEGER_0_255_ == 42);
    ASN_STRUCT_FREE(asn_DEF_Extended, decoded);
    /* Existing selected storage must never be overwritten or leaked. */
    decoded = calloc(1, sizeof(*decoded));
    assert(decoded);
    decoded->value = calloc(1, sizeof(*decoded->value));
    assert(decoded->value);
    decoded->value->present = Extended__value_PR_INTEGER_0_255_;
    dec = ber_decode(0, &asn_DEF_Extended, (void **)&decoded, output, (size_t)enc.encoded);
    assert(dec.code == RC_FAIL && decoded->value);
    ASN_STRUCT_FREE(asn_DEF_Extended, decoded);
}

/* Run generated root, malformed metadata, and extension regressions. */
int main(void) {
    check_root();
    check_metadata_and_optional();
    check_extension();
    return 0;
}
C_EOF
${MAKE:-make} -f converter-example.mk
${CC:-cc} -I. -o test_program test_program.c libasncodec.a -lm
./test_program
