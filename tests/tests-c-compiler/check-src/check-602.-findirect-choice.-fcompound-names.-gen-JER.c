/*
 * Check IOC-selected JER OPEN TYPE values with OPTIONAL contained members.
 * Original source: check-173 IOC regression and JER OPEN TYPE runtime.
 * Version: 2026-10-30. Author: asn1c maintainers.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ContentWrapper.h"
#include "PersonInfo.h"
#include <jer_decoder.h>
#include <jer_encoder.h>
#include <OBJECT_IDENTIFIER.h>
#include <OCTET_STRING.h>

/* The output buffer owns one complete encoded JSON value. */
typedef struct jer_output_s {
    uint8_t bytes[4096]; /* Bounded encoded JSON bytes. */
    size_t used;          /* Number of initialized bytes; state variable. */
} jer_output_t;

/*
 * Append bytes to the bounded output buffer without truncation.
 * Original source: JER encoder callback contract. Version: 2026-10-30.
 * Parameters: buffer is source data; size is its length; key is jer_output_t.
 * Returns zero on success and minus one if input or capacity is invalid.
 * Exceptions: None. Author: asn1c maintainers. History: initial JER test.
 * Example: jer_encode(..., append_output, &output).
 */
static int
append_output(const void *buffer, size_t size, void *key) {
    jer_output_t *output = key;
    if(!output || (!buffer && size)) return -1;
    if(output->used > sizeof(output->bytes)
       || size > sizeof(output->bytes) - output->used) {
        return -1;
    }
    if(size) memcpy(output->bytes + output->used, buffer, size);
    output->used += size;
    return 0;
}

/*
 * Construct a valid IOC selector and its selected PersonInfo value.
 * Original source: check-173 IOC fixture. Version: 2026-10-30.
 * Parameters: wrapper receives an initialized value; email_present chooses
 * whether the contained OPTIONAL member is present.
 * Returns nothing. Exceptions: Assertions terminate on allocation failure.
 * Author: asn1c maintainers. History: initial JER test.
 * Example: fill_wrapper(&source, 1).
 */
static void
fill_wrapper(ContentWrapper_t *wrapper, int email_present) {
    const asn_oid_arc_t arcs[] = {1, 2, 3, 4, 1};
    PersonInfo_t *person;
    memset(wrapper, 0, sizeof(*wrapper));
    assert(OBJECT_IDENTIFIER_set_arcs(&wrapper->contentType, arcs,
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
    wrapper->content.present = ContentWrapper__content_PR_PersonInfo;
    wrapper->content.choice.PersonInfo = person;
}

/*
 * Verify a selected OPEN TYPE round trip and all truncated input prefixes.
 * Original source: check-173 and OPEN_TYPE_jer_get(). Version: 2026-10-30.
 * Parameters: email_present chooses whether the nested OPTIONAL is present.
 * Returns nothing. Exceptions: Assertions terminate on codec regression.
 * Author: asn1c maintainers. History: initial JER test.
 * Example: check_case(0) verifies the absent OPTIONAL path.
 */
static void
check_case(int email_present) {
    ContentWrapper_t source;
    ContentWrapper_t *decoded = NULL;
    jer_output_t output = {{0}, 0};
    asn_enc_rval_t encoded;
    asn_dec_rval_t result;
    size_t cut;

    fill_wrapper(&source, email_present);
    encoded = jer_encode(&asn_DEF_ContentWrapper, &source, JER_F_MINIFIED,
                         append_output, &output);
    assert(encoded.encoded >= 0);
    assert(output.used > 0 && output.used < sizeof(output.bytes));
    result = jer_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                        output.bytes, output.used);
    assert(result.code == RC_OK);
    assert(decoded && decoded->content.present == ContentWrapper__content_PR_PersonInfo);
    assert(decoded->content.choice.PersonInfo);
    assert(decoded->content.choice.PersonInfo->age == 42);
    assert((decoded->content.choice.PersonInfo->email != NULL) == email_present);

    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);

    /* A proper prefix cannot contain the closing wrapper delimiter. */
    for(cut = 0; cut < output.used; cut++) {
        decoded = NULL;
        result = jer_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                            output.bytes, cut);
        assert(result.code != RC_OK);
        ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);
    }

    /* Corrupt a nested integer after the selected arm has been allocated. */
    for(cut = 0; cut + sizeof("\"age\":42") - 1 <= output.used; cut++) {
        if(memcmp(output.bytes + cut, "\"age\":42", sizeof("\"age\":42") - 1) == 0) {
            size_t digit = cut + sizeof("\"age\":") - 1;
            output.bytes[digit] = 'x';
            decoded = NULL;
            result = jer_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                                output.bytes, output.used);
            assert(result.code != RC_OK);
            ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);
            output.bytes[digit] = '4';
            break;
        }
    }
    assert(cut + sizeof("\"age\":42") - 1 <= output.used);

    /* Unknown JSON escapes must fail inside the selected UTF8String. */
    for(cut = 0; cut + sizeof("Alice") - 1 <= output.used; cut++) {
        if(memcmp(output.bytes + cut, "Alice", sizeof("Alice") - 1) == 0) {
            output.bytes[cut] = '\\';
            decoded = NULL;
            result = jer_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                                output.bytes, output.used);
            assert(result.code != RC_OK);
            ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);
            output.bytes[cut] = 'A';
            break;
        }
    }
    assert(cut + sizeof("Alice") - 1 <= output.used);

    /* A malformed final wrapper delimiter must also release its content. */
    assert(output.bytes[output.used - 1] == '}');
    output.bytes[output.used - 1] = ']';
    decoded = NULL;
    result = jer_decode(0, &asn_DEF_ContentWrapper, (void **)&decoded,
                        output.bytes, output.used);
    assert(result.code != RC_OK);
    ASN_STRUCT_FREE(asn_DEF_ContentWrapper, decoded);
    ASN_STRUCT_RESET(asn_DEF_ContentWrapper, &source);
}

/*
 * Exercise present and absent OPTIONAL values inside a selected OPEN TYPE.
 * Original source: check-173 regression. Version: 2026-10-30.
 * Parameters: None. Returns zero when assertions pass.
 * Exceptions: Assertions terminate on codec regression.
 * Author: asn1c maintainers. History: initial JER test.
 * Example: ./check-program.
 */
int
main(void) {
    check_case(0);
    check_case(1);
    return 0;
}
