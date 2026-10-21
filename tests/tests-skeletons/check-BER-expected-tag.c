/*
 * BER constructed-string expected-tag regression (ASN1-0017).
 *
 * The descriptor of a type such as `Label2 ::= [1] Label` (with
 * `Label ::= [9] EXPLICIT UTF8String`) carries two different tag arrays:
 *
 *   tags     = [1], [UTF8String]              (effective tag chain)
 *   all_tags = [1], [9], [UTF8String]         (containment map)
 *
 * The constructed-string BER decoder must expect the *effective* tag at each
 * nesting level.  Selecting from `all_tags` makes it expect the superseded
 * `[9]` wrapper tag and reject a valid `[1] [UTF8String]` value (check-33).
 */
#include <stdio.h>
#include <string.h>

#include <asn_application.h>
#include <UTF8String.h>

static int failures; /* Count of failed checks across the whole run. */

/*
 * Record a failed check with its label.
 * Original source: New ASN1-0017 skeleton regression test.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: ok is the check result; label names the check.
 * Returns: No value; increments the global failure count when ok is zero.
 * Errors: None. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added for ASN1-0017.
 * Example: check(rv.code == RC_OK, "effective tag accepted").
 */
static void
check(int ok, const char *label) {
    if(!ok) {
        fprintf(stderr, "FAIL: %s\n", label);
        failures++;
    }
}

/*
 * Decode one BER TLV with tag_mode 0 against a custom descriptor.
 * Original source: New ASN1-0017 skeleton regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td describes the type; bytes/size is the input; value receives
 *   the decoded string (freed by the caller).
 * Returns: The decoder result.
 * Errors: None. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added for ASN1-0017.
 * Example: rv = decode(&td, bytes, size, &value).
 */
static asn_dec_rval_t
decode(const asn_TYPE_descriptor_t *td, const void *bytes, size_t size,
       UTF8String_t **value) {
    void *decoded = NULL;
    asn_dec_rval_t rv = td->op->ber_decoder(NULL, td, &decoded, bytes, size, 0);

    *value = (UTF8String_t *)decoded;
    return rv;
}

/*
 * Release a decoded value.
 * Original source: New ASN1-0017 skeleton regression test.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td owns the value; value may be NULL.
 * Returns: No value.
 * Errors: None. C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added for ASN1-0017.
 * Example: free_value(&td, value).
 */
static void
free_value(const asn_TYPE_descriptor_t *td, UTF8String_t *value) {
    if(value) td->op->free_struct(td, value, ASFM_FREE_EVERYTHING);
}

/*
 * Decode one BER TLV and require the exact expected string payload.
 * Original source: New ASN1-0017 skeleton regression helper.
 * Version/date: 1.0, 2026-10-21.
 * Parameters: td describes the type; bytes/size is the input; expected is the
 *   NUL-terminated payload; label names the check.
 * Returns: No value.
 * Errors: Mismatches are recorded through check(). C has no exceptions.
 * Responsible party: asn1c maintainers. History: Added for ASN1-0017.
 * Example: check_text(&td, bytes, size, "AB", "chunked value decodes").
 */
static void
check_text(const asn_TYPE_descriptor_t *td, const void *bytes, size_t size,
           const char *expected, const char *label) {
    UTF8String_t *value = NULL;
    size_t expected_size = strlen(expected);
    asn_dec_rval_t rv = decode(td, bytes, size, &value);

    check(rv.code == RC_OK && rv.consumed == size && value != NULL
          && value->size == expected_size
          && !memcmp(value->buf, expected, expected_size), label);
    free_value(td, value);
}

int
main(void) {
    static const ber_tlv_tag_t effective_tags[] = {
        ASN_TAG_CLASS_CONTEXT | (1 << 2),      /* [1] */
        ASN_TAG_CLASS_UNIVERSAL | (12 << 2)    /* UTF8String */
    };
    static const ber_tlv_tag_t containment_tags[] = {
        ASN_TAG_CLASS_CONTEXT | (1 << 2),      /* [1] */
        ASN_TAG_CLASS_CONTEXT | (9 << 2),      /* [9] superseded wrapper */
        ASN_TAG_CLASS_UNIVERSAL | (12 << 2)    /* UTF8String */
    };
    /* [1] { UTF8String "TestLabel2" } */
    static const uint8_t valid_value[] = {
        0xa1, 0x0c, 0x0c, 0x0a,
        'T', 'e', 's', 't', 'L', 'a', 'b', 'e', 'l', '2'
    };
    /* [1] { [9] { UTF8String "A" } }: valid ASN.1, superseded [9] tag. */
    static const uint8_t superseded_value[] = {
        0xa1, 0x05, 0xa9, 0x03, 0x0c, 0x01, 'A'
    };
    /* [1] { constructed UTF8String with chunks "A", "B" }. */
    static const uint8_t chunked_value[] = {
        0xa1, 0x08, 0x2c, 0x06, 0x0c, 0x01, 'A', 0x0c, 0x01, 'B'
    };
    asn_TYPE_descriptor_t td = asn_DEF_UTF8String;
    UTF8String_t *value = NULL;
    asn_dec_rval_t rv;

    td.tags = effective_tags;
    td.tags_count = sizeof(effective_tags) / sizeof(effective_tags[0]);
    td.all_tags = containment_tags;
    td.all_tags_count = sizeof(containment_tags) / sizeof(containment_tags[0]);

    /* tags_count != all_tags_count: the effective chain must win. */
    check_text(&td, valid_value, sizeof(valid_value), "TestLabel2",
               "effective [1] [UTF8String] chain decodes");

    /* Chunk tags are matched at the level below the effective UTF8String tag. */
    check_text(&td, chunked_value, sizeof(chunked_value), "AB",
               "constructed chunks under effective chain decode");

    /* The superseded [9] tag is in all_tags, but not in the effective chain. */
    rv = decode(&td, superseded_value, sizeof(superseded_value), &value);
    check(rv.code != RC_OK, "superseded [9] tag is not accepted");
    free_value(&td, value);

    if(failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
