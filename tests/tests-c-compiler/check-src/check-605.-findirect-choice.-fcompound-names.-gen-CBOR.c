/*
 * Verify CBOR SEQUENCE maps, OPTIONAL, ANY, and IOC-selected OPEN TYPE.
 * Source: the 605 generated fixture and repository CBOR map mapping.
 * Version: 2026-10-30. Author: asn1c maintainers.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ContentWrapper.h"
#include "DefaultRecord.h"
#include "OpaqueRecord.h"
#include "PersonInfo.h"
#include <cbor_decoder.h>
#include <cbor_encoder.h>
#include <cbor_support.h>
#include <OBJECT_IDENTIFIER.h>
#include <OCTET_STRING.h>

/* Bounded CBOR bytes retained by the test callback. */
typedef struct cbor_output_s {
    uint8_t bytes[4096]; /* Encoded output bytes. */
    size_t used;          /* Number of initialized bytes; state variable. */
} cbor_output_t;

/*
 * Purpose: append encoded bytes without truncation.
 * Source: asn_app_consume_bytes_f. Version: 2026-10-30.
 * Inputs: data/size are the encoded fragment, key is cbor_output_t.
 * Returns: zero on success or -1 on capacity failure. Exceptions: none.
 * Author: maintainers. History: added bounded CBOR output.
 * Example: cbor_encode(..., append_bytes, &output).
 */
static int
append_bytes(const void *data, size_t size, void *key) {
    cbor_output_t *output = key;
    if(!output || (!data && size) || output->used > sizeof(output->bytes)
       || size > sizeof(output->bytes) - output->used) return -1;
    if(size) memcpy(output->bytes + output->used, data, size);
    output->used += size;
    return 0;
}

/*
 * Purpose: initialize a selected PersonInfo with optional email.
 * Source: generated IOC fixture. Version: 2026-10-30.
 * Inputs: value receives the object; email_present chooses OPTIONAL presence.
 * Returns: nothing. Exceptions: assertions stop on allocation failure.
 * Author: maintainers. History: added CBOR selected-arm regression.
 * Example: fill_wrapper(&value, 0) omits email.
 */
static void
fill_wrapper(ContentWrapper_t *value, int email_present) {
    const asn_oid_arc_t arcs[] = {1, 2, 3, 4, 1};
    PersonInfo_t *person;
    memset(value, 0, sizeof(*value));
    assert(OBJECT_IDENTIFIER_set_arcs(&value->contentType, arcs,
                                      sizeof(arcs) / sizeof(arcs[0])) == 0);
    person = calloc(1, sizeof(*person));
    assert(person);
    assert(OCTET_STRING_fromString(&person->name, "Alice") == 0);
    person->age = 42;
    if(email_present) {
        person->email = calloc(1, sizeof(*person->email));
        assert(person->email);
        assert(OCTET_STRING_fromString(person->email, "alice@example.test") == 0);
    }
    value->content.present = ContentWrapper__content_PR_PersonInfo;
    value->content.choice.PersonInfo = person;
}

/*
 * Purpose: measure an encoded CBOR key and value pair.
 * Source: cbor_skip_item_with_ctx. Version: 2026-10-30.
 * Inputs: bytes/size bound input and offset starts at the key.
 * Returns: total pair length. Exceptions: assertions stop on bad fixture data.
 * Author: maintainers. History: added wire-order inversion.
 * Example: pair_size(output.bytes, output.used, 1) measures map pair one.
 */
static size_t
pair_size(const uint8_t *bytes, size_t size, size_t offset) {
    ssize_t key, value;
    assert(offset < size);
    key = cbor_skip_item_with_ctx(0, bytes + offset, size - offset);
    assert(key > 0 && (size_t)key < size - offset);
    value = cbor_skip_item_with_ctx(0, bytes + offset + (size_t)key,
                                    size - offset - (size_t)key);
    assert(value > 0 && (size_t)value <= size - offset - (size_t)key);
    return (size_t)key + (size_t)value;
}

/*
 * Purpose: verify one decoded selected PersonInfo value.
 * Source: generated 605 ASN.1 fixture. Version: 2026-10-30.
 * Inputs: value is decoded, email_present is expected OPTIONAL presence.
 * Returns: nothing. Exceptions: assertions stop on mismatch.
 * Author: maintainers. History: added CBOR round-trip verification.
 * Example: check_wrapper(decoded, 1) requires an email.
 */
static void
check_wrapper(const ContentWrapper_t *value, int email_present) {
    assert(value);
    assert(value->content.present == ContentWrapper__content_PR_PersonInfo);
    assert(value->content.choice.PersonInfo);
    assert(value->content.choice.PersonInfo->age == 42);
    assert((value->content.choice.PersonInfo->email != NULL) == email_present);
}

/*
 * Purpose: verify selector-after-open order, malformed maps, and preservation.
 * Source: CBOR map mapping and generated 605 IOC fixture. Version: 2026-10-30.
 * Inputs: email_present chooses the nested OPTIONAL field.
 * Returns: nothing. Exceptions: assertions stop on regression.
 * Author: maintainers. History: added transactional decode tests.
 * Example: check_open_case(0) tests absent nested email.
 */
static void
check_open_case(int email_present) {
    ContentWrapper_t source;
    ContentWrapper_t *decoded = NULL, *preallocated;
    cbor_output_t output = {{0}, 0};
    uint8_t changed[4096];
    asn_dec_rval_t result;
    size_t first, second, cut;
    ssize_t key_size;
    fill_wrapper(&source, email_present);
    assert(cbor_encode(&asn_DEF_ContentWrapper, &source, append_bytes, &output).encoded >= 0);
    assert(output.used > 3 && output.bytes[0] == 0xa2);
    first = pair_size(output.bytes, output.used, 1);
    second = pair_size(output.bytes, output.used, 1 + first);
    assert(first + second + 1 == output.used);
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         output.bytes, output.used);
    assert(result.code == RC_OK && result.consumed == output.used);
    check_wrapper(decoded, email_present);
    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);

    /* Swap complete entries so the open value precedes its selector. */
    changed[0] = 0xa2;
    memcpy(changed + 1, output.bytes + 1 + first, second);
    memcpy(changed + 1 + second, output.bytes + 1, first);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used);
    assert(result.code == RC_OK && result.consumed == output.used);
    check_wrapper(decoded, email_present);
    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);

    /* Every proper prefix, duplicate and missing mandatory member fails. */
    for(cut = 0; cut < output.used; cut++) {
        decoded = NULL;
        result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                             output.bytes, cut);
        assert(result.code != RC_OK);
        ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);
    }
    changed[0] = 0xa1;
    memcpy(changed + 1, output.bytes + 1, first);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded, changed, 1 + first);
    assert(result.code != RC_OK);
    assert(decoded == NULL);
    changed[0] = 0xa3;
    memcpy(changed + 1, output.bytes + 1, first + second);
    memcpy(changed + 1 + first + second, output.bytes + 1, first);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used + first);
    assert(result.code != RC_OK && decoded == NULL);

    /* An existing value remains intact after a later duplicate is found. */
    preallocated = calloc(1, sizeof(*preallocated));
    assert(preallocated);
    fill_wrapper(preallocated, email_present);
    decoded = preallocated;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used + first);
    assert(result.code != RC_OK && decoded == preallocated);
    check_wrapper(preallocated, email_present);
    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, preallocated);

    /* Duplicate unknown keys also fail even when both required keys exist. */
    assert(output.used + 6 <= sizeof(changed));
    changed[0] = 0xa4;
    memcpy(changed + 1, output.bytes + 1, first + second);
    memcpy(changed + output.used, "\x61x\xf5\x61x\xf4", 6);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used + 6);
    assert(result.code != RC_OK && decoded == NULL);

    /* A single unknown key is skipped; invalid UTF-8 keys are rejected. */
    changed[0] = 0xa3;
    memcpy(changed + 1, output.bytes + 1, first + second);
    memcpy(changed + output.used, "\x61x\xf5", 3);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used + 3);
    assert(result.code == RC_OK && decoded);
    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);
    changed[output.used + 1] = 0xff;
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used + 3);
    assert(result.code != RC_OK && decoded == NULL);

    /* A syntactically valid but unknown OID cannot choose a selected arm. */
    memcpy(changed, output.bytes, output.used);
    changed[first] ^= 0x01;
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used);
    assert(result.code != RC_OK && decoded == NULL);

    /* A selected child must consume its entire encoded map value. */
    memcpy(changed, output.bytes, output.used);
    key_size = cbor_skip_item_with_ctx(0, changed + 1 + first, second);
    assert(key_size > 0 && (size_t)key_size < second);
    changed[1 + first + (size_t)key_size] = 0xa0;
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                         changed, output.used);
    assert(result.code != RC_OK && decoded == NULL);
    ASN_STRUCT_RESET(asn_DEF_ContentWrapper, &source);
}

/*
 * Purpose: verify direct ANY and OPTIONAL in ordinary CBOR SEQUENCE maps.
 * Source: generated 605 OpaqueRecord fixture. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Exceptions: assertions stop on mismatch.
 * Author: maintainers. History: added opaque byte-string map regression.
 * Example: check_opaque_case() tests both absent and present raw values.
 */
static void
check_opaque_case(void) {
    OpaqueRecord_t source = {0}, *decoded = NULL;
    cbor_output_t output = {{0}, 0};
    const uint8_t encoded_any[] = {0x05, 0x00};
    asn_dec_rval_t result;
    asn_TYPE_descriptor_t malformed;
    asn_TYPE_member_t members[2];
    source.enabled = 1;
    assert(cbor_encode(&asn_DEF_OpaqueRecord, &source, append_bytes, &output).encoded >= 0);
    assert(output.bytes[0] == 0xa1);
    result = cbor_decode(0, &asn_DEF_OpaqueRecord, (void **)&decoded,
                         output.bytes, output.used);
    assert(result.code == RC_OK && decoded && decoded->enabled && !decoded->raw);
    ASN_STRUCT_FREE(asn_DEF_OpaqueRecord, decoded);
    source.raw = calloc(1, sizeof(*source.raw));
    assert(source.raw);
    source.raw->buf = malloc(sizeof(encoded_any));
    assert(source.raw->buf);
    memcpy(source.raw->buf, encoded_any, sizeof(encoded_any));
    source.raw->size = sizeof(encoded_any);
    output.used = 0;
    assert(cbor_encode(&asn_DEF_OpaqueRecord, &source, append_bytes, &output).encoded >= 0);
    assert(output.bytes[0] == 0xa2);
    decoded = NULL;
    result = cbor_decode(0, &asn_DEF_OpaqueRecord, (void **)&decoded,
                         output.bytes, output.used);
    assert(result.code == RC_OK && decoded && decoded->raw);
    assert(decoded->raw->size == sizeof(encoded_any));
    assert(!memcmp(decoded->raw->buf, encoded_any, sizeof(encoded_any)));
    ASN_STRUCT_FREE(asn_DEF_OpaqueRecord, decoded);

    /* Invalid storage offsets fail before output or decode allocation. */
    malformed = asn_DEF_OpaqueRecord;
    memcpy(members, malformed.elements, sizeof(members));
    members[0].memb_offset = sizeof(source) - 1;
    malformed.elements = members;
    output.used = 0;
    assert(cbor_encode(&malformed, &source, append_bytes, &output).encoded < 0);
    assert(output.used == 0);
    decoded = NULL;
    result = cbor_decode(0, &malformed, (void **)&decoded, "\xa0", 1);
    assert(result.code != RC_OK && decoded == NULL);

    /* Invalid descriptor text cannot become a CBOR map key. */
    memcpy(members, asn_DEF_OpaqueRecord.elements, sizeof(members));
    members[0].name = "\xc0\x80";
    output.used = 0;
    assert(cbor_encode(&malformed, &source, append_bytes, &output).encoded < 0);
    assert(output.used == 0);
    result = cbor_decode(0, &malformed, (void **)&decoded, "\xa0", 1);
    assert(result.code != RC_OK && decoded == NULL);
    ASN_STRUCT_RESET(asn_DEF_OpaqueRecord, &source);
}

/*
 * Purpose: fuzz both generated CBOR SEQUENCE decoder shapes.
 * Source: libFuzzer input contract and 605 fixture. Version: 2026-10-30.
 * Inputs: data/size are arbitrary bytes. Returns: zero after freeing results.
 * Errors: malformed data is expected and must not crash or leak.
 * Author: maintainers. History: added CBOR map decoder fuzz entry.
 * Example: a fuzzer mutates map heads, keys and selected child values.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ContentWrapper_t *wrapper = NULL;
    OpaqueRecord_t *record = NULL;
    DefaultRecord_t *default_record = NULL;
    if(!data && size) return 0;
    cbor_decode(0, &asn_DEF_ContentWrapper, (void **)&wrapper, data, size);
    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, wrapper);
    cbor_decode(0, &asn_DEF_OpaqueRecord, (void **)&record, data, size);
    ASN_STRUCT_FREE(asn_DEF_OpaqueRecord, record);
    cbor_decode(0, &asn_DEF_DefaultRecord, (void **)&default_record, data, size);
    ASN_STRUCT_FREE(asn_DEF_DefaultRecord, default_record);
    return 0;
}

/*
 * Purpose: verify omitted DEFAULT fields are restored during CBOR decode.
 * Source: generated 605 DEFAULT setter. Version: 2026-10-30.
 * Inputs: none. Returns: nothing. Exceptions: assertions on mismatch.
 * Author: maintainers. History: added DEFAULT map regression.
 * Example: an empty map creates enabled=TRUE.
 */
static void
check_default_case(void) {
    static const uint8_t empty_map[] = {0xa0};
    DefaultRecord_t source = {0};
    DefaultRecord_t *decoded = NULL;
    cbor_output_t output = {{0}, 0};
    asn_dec_rval_t result;
    assert(cbor_encode(&asn_DEF_DefaultRecord, &source, append_bytes, &output).encoded >= 0);
    assert(output.used == sizeof(empty_map) && output.bytes[0] == empty_map[0]);
    result = cbor_decode(0, &asn_DEF_DefaultRecord, (void **)&decoded,
                         output.bytes, output.used);
    assert(result.code == RC_OK && result.consumed == sizeof(empty_map));
    assert(decoded && decoded->enabled && *decoded->enabled == 1 && !decoded->raw);
    ASN_STRUCT_FREE(asn_DEF_DefaultRecord, decoded);
}

/*
 * Purpose: execute generated CBOR SEQUENCE regressions.
 * Source: 605 fixture tests. Version: 2026-10-30.
 * Inputs: none. Returns: zero on success. Exceptions: assertions on failure.
 * Author: maintainers. History: added C CBOR map coverage.
 * Example: ./check-program.
 */
int
main(void) {
    check_open_case(0);
    check_open_case(1);
    check_opaque_case();
    check_default_case();
    return 0;
}
