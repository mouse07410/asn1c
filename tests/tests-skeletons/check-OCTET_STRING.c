#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <OCTET_STRING.h>
#include <BIT_STRING.h>

enum encoding_type { HEX, BINARY, UTF8, BASE64 };
enum encoding_rules { XER, JER };

#define check_xer(t, tag, buf, verify)  check_impl(__LINE__, XER, t, tag,  buf, verify, 0)
#define check_xer_bin(t, tag, buf, verify, verify_len)  check_impl(__LINE__, XER, t, tag,  buf, verify, verify_len)
#define check_jer(t, buf, verify)       check_impl(__LINE__, JER, t, NULL, buf, verify, 0)

/*
 * Purpose: decode one XER or JER input and compare it with the expected bytes.
 * Original source: asn1c OCTET STRING skeleton tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: lineno is the caller line; rules and type select the decoder;
 *   tagname names an XER tag; xmlbuf is the input; verify and verify_len give
 *   expected bytes, or a null verify requests rejection.
 * Returns: none.
 * Exceptions: none; assertion failures terminate the test process.
 * Responsible party: asn1c maintainers.
 * History: existing decoder regression helper, documented with the new tests.
 * Example: check_xer(HEX, NULL, "<OCTET_STRING>41</OCTET_STRING>", "A").
 */
static void
check_impl(int lineno, enum encoding_rules rules, enum encoding_type type,
           char *tagname, char *xmlbuf, char *verify, size_t verify_len) {
	size_t xmllen = strlen(xmlbuf);
	size_t verlen = verify_len ? verify_len : (verify ? strlen(verify) : 0);
	asn_TYPE_descriptor_t *td = &asn_DEF_OCTET_STRING;
	OCTET_STRING_t *st = 0;
	OCTET_STRING_t **stp = &st;
	asn_dec_rval_t rc;
    switch(rules) {
    case XER:
        ;
        xer_type_decoder_f *xer_decoder = 0;

        switch(type) {
        case HEX:
            xer_decoder = OCTET_STRING_decode_xer_hex;
            break;
        case BINARY:
            td = &asn_DEF_BIT_STRING;
            xer_decoder = OCTET_STRING_decode_xer_binary;
            break;
        case UTF8:
            xer_decoder = OCTET_STRING_decode_xer_utf8;
            break;
        case BASE64:
            xer_decoder = OCTET_STRING_decode_xer_base64;
            break;
        }

        rc = xer_decoder(0, td, (void **)stp, tagname, xmlbuf, xmllen);
        break;
    case JER:
        ;
        jer_type_decoder_f *jer_decoder = 0;

        switch(type) {
        case HEX:
            jer_decoder = OCTET_STRING_decode_jer_hex;
            break;
        case UTF8:
            jer_decoder = OCTET_STRING_decode_jer_utf8;
            break;
        default:
            /* Not supported */
            assert(0);
        }

        rc = jer_decoder(0, td, NULL, (void **)stp, xmlbuf, xmllen);
        break;
    }
	printf("%03d: [%s] => [%.*s]:%zu vs [%s]:%zu, code %d\n",
		lineno, xmlbuf,
		st && st->buf ? (int)st->size : 0,
		st && st->buf ? (const char *)st->buf : "",
		st ? st->size : 0, verify ? verify : "", verlen, rc.code);

	if(verify) {
		assert(rc.code == RC_OK);
		assert(st);
		assert(st->buf);
		assert(st->size == verlen);
		assert(!memcmp(st->buf, verify, verlen));
	} else {
		assert(rc.code != RC_OK);
	}

	ASN_STRUCT_FREE(*td, st);
}

/* state variable: shared output buffer for the small XER encoder fixtures. */
static char buf[1024]; /* state variable: encoded bytes accumulated by write_buf. */

/*
 * Purpose: append encoded bytes to the shared XER test buffer.
 * Original source: asn1c OCTET STRING skeleton tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: buffer and size describe bytes to append; key points to the offset.
 * Returns: zero after appending.
 * Exceptions: none; an oversized append fails through assert.
 * Responsible party: asn1c maintainers.
 * History: existing encoder callback, documented with the new tests.
 * Example: OCTET_STRING_encode_xer(..., write_buf, &offset).
 */
static int
write_buf(const void *buffer, size_t size, void *key) {
	size_t *off = key;
	assert(*off + size < sizeof(buf));
	memcpy(buf + *off, buffer, size);
	*off += size;
	return 0;
}

/*
 * Purpose: encode a text string as XER and compare its exact textual form.
 * Original source: asn1c OCTET STRING skeleton tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: orig is the input string; encoded is the expected XER text.
 * Returns: none.
 * Exceptions: none; assertion failures terminate the test process.
 * Responsible party: asn1c maintainers.
 * History: existing encoder regression helper, documented with the new tests.
 * Example: encode("hello", "hello").
 */
static void
encode(char *orig, char *encoded) {
	OCTET_STRING_t os;
	size_t written = 0;
	asn_enc_rval_t er;

	memset(&os, 0, sizeof(os));

	OCTET_STRING_fromString(&os, orig);

	er = OCTET_STRING_encode_xer_utf8(&asn_DEF_OCTET_STRING, &os,
			0, 0, write_buf, &written);
	assert(er.encoded >= 0);
	buf[er.encoded] = '\0';
	printf("Orig: [%s], encoded: [%s], check [%s]\n",
		orig, buf, encoded);
	assert(strcmp(buf, encoded) == 0);
	ASN_STRUCT_RESET(asn_DEF_OCTET_STRING, &os);
}

/*
 * Purpose: assert that two OCTET STRING structures compare with the expected sign.
 * Original source: asn1c skeleton regression tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: line identifies the calling test; left and right are nullable values;
 *   expected is -1, 0, or 1 for the required comparison sign.
 * Returns: none.
 * Exceptions: none; an unexpected comparison aborts through assert.
 * Responsible party: asn1c maintainers.
 * History: added for the zero-length OCTET STRING comparison regression.
 * Example: check_octet_compare(__LINE__, &empty, &value, -1).
 */
static void
check_octet_compare(int line, const OCTET_STRING_t *left,
                    const OCTET_STRING_t *right, int expected) {
    int actual = OCTET_STRING_compare(&asn_DEF_OCTET_STRING, left, right);

    if((actual < 0) != (expected < 0)
       || (actual > 0) != (expected > 0)) {
        fprintf(stderr, "%03d: OCTET_STRING_compare returned %d, expected sign %d\n",
                line, actual, expected);
        assert(0);
    }
}

/*
 * Purpose: cover valid empty, ordinary, absent, and malformed OCTET STRING comparisons.
 * Original source: asn1c skeleton regression tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: none; test values use local storage for their backing bytes.
 * Returns: none.
 * Exceptions: none; an incorrect comparison aborts through check_octet_compare.
 * Responsible party: asn1c maintainers.
 * History: added for the randomized explicit-string UBSan failure.
 * Example: called by main before the text decoder tests.
 */
static void
test_octet_string_compare(void) {
    uint8_t empty_storage = 0;
    uint8_t abc_bytes[] = {'a', 'b', 'c'};
    uint8_t ab_bytes[] = {'a', 'b'};
    uint8_t abd_bytes[] = {'a', 'b', 'd'};
    OCTET_STRING_t null_empty = {0};
    OCTET_STRING_t allocated_empty = {0};
    OCTET_STRING_t abc = {0};
    OCTET_STRING_t ab = {0};
    OCTET_STRING_t abd = {0};
    OCTET_STRING_t malformed_one = {0};
    OCTET_STRING_t malformed_two = {0};

    allocated_empty.buf = &empty_storage;
    abc.buf = abc_bytes;
    abc.size = sizeof(abc_bytes);
    ab.buf = ab_bytes;
    ab.size = sizeof(ab_bytes);
    abd.buf = abd_bytes;
    abd.size = sizeof(abd_bytes);
    malformed_one.size = 1;
    malformed_two.size = 2;

    /* Every pair of null-backed and allocated zero-length values is equal. */
    check_octet_compare(__LINE__, &null_empty, &null_empty, 0);
    check_octet_compare(__LINE__, &null_empty, &allocated_empty, 0);
    check_octet_compare(__LINE__, &allocated_empty, &null_empty, 0);
    check_octet_compare(__LINE__, &allocated_empty, &allocated_empty, 0);

    /* Preserve ordering for absent structures and both empty representations. */
    check_octet_compare(__LINE__, NULL, NULL, 0);
    check_octet_compare(__LINE__, NULL, &null_empty, -1);
    check_octet_compare(__LINE__, &null_empty, NULL, 1);
    check_octet_compare(__LINE__, &null_empty, &abc, -1);
    check_octet_compare(__LINE__, &abc, &null_empty, 1);
    check_octet_compare(__LINE__, &allocated_empty, &abc, -1);
    check_octet_compare(__LINE__, &abc, &allocated_empty, 1);

    /* Check equal prefixes, differing bytes, and the reverse comparisons. */
    check_octet_compare(__LINE__, &ab, &abc, -1);
    check_octet_compare(__LINE__, &abc, &ab, 1);
    check_octet_compare(__LINE__, &abc, &abd, -1);
    check_octet_compare(__LINE__, &abd, &abc, 1);
    check_octet_compare(__LINE__, &abc, &abc, 0);

    /* Malformed positive-size null buffers sort after valid values by size. */
    check_octet_compare(__LINE__, &null_empty, &malformed_one, -1);
    check_octet_compare(__LINE__, &malformed_one, &abc, 1);
    check_octet_compare(__LINE__, &abc, &malformed_one, -1);
    check_octet_compare(__LINE__, &malformed_one, &malformed_two, -1);
    check_octet_compare(__LINE__, &malformed_two, &malformed_one, 1);
    check_octet_compare(__LINE__, &malformed_one, &malformed_one, 0);
    check_octet_compare(__LINE__, &null_empty, &malformed_two, -1);
}

/*
 * Purpose: verify safe copies of empty values and rejection of malformed sources.
 * Original source: asn1c skeleton regression tests.
 * Version/date: 1.0, 2026-10-21.
 * Inputs: none; test values use local storage for source bytes.
 * Returns: none.
 * Exceptions: none; an incorrect result aborts through assert.
 * Responsible party: asn1c maintainers.
 * History: added for null-backed empty values and allocation-length overflow.
 * Example: called by main before the text decoder tests.
 */
static void
test_octet_string_copy(void) {
    uint8_t empty_storage = 0;
    uint8_t overflow_storage = 0;
    OCTET_STRING_t null_empty = {0};
    OCTET_STRING_t allocated_empty = {0};
    OCTET_STRING_t malformed = {0};
    OCTET_STRING_t overflow = {0};
    OCTET_STRING_t destination = {0};
    asn_OCTET_STRING_specifics_t small_specifics = {0};
    asn_TYPE_descriptor_t small_descriptor = asn_DEF_OCTET_STRING;
    OCTET_STRING_t *copy = NULL;
    uint8_t *original_destination_buffer;
    void *destination_pointer;
    int result;

    allocated_empty.buf = &empty_storage;
    malformed.size = 1;
    overflow.buf = &overflow_storage;
    overflow.size = SIZE_MAX;

    /* A null-backed empty source creates an owned, NUL-terminated copy. */
    result = OCTET_STRING_copy(&asn_DEF_OCTET_STRING, (void **)&copy,
                               &null_empty);
    assert(result == 0);
    assert(copy && copy->size == 0 && copy->buf && copy->buf[0] == '\0');
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, copy);
    copy = NULL;

    /* An allocated empty source replaces existing destination contents safely. */
    result = OCTET_STRING_fromBuf(&destination, "old", 3);
    assert(result == 0);
    destination_pointer = &destination;
    result = OCTET_STRING_copy(&asn_DEF_OCTET_STRING, &destination_pointer,
                              &allocated_empty);
    assert(result == 0);
    assert(destination_pointer == &destination);
    assert(destination.size == 0 && destination.buf && destination.buf[0] == '\0');

    /* Invalid sources fail before changing an existing destination. */
    result = OCTET_STRING_fromBuf(&destination, "keep", 4);
    assert(result == 0);
    original_destination_buffer = destination.buf;
    destination_pointer = &destination;
    result = OCTET_STRING_copy(&asn_DEF_OCTET_STRING, &destination_pointer,
                              &malformed);
    assert(result == -1);
    assert(destination_pointer == &destination);
    assert(destination.buf == original_destination_buffer);
    assert(destination.size == 4);
    assert(memcmp(destination.buf, "keep", 4) == 0);

    /* SIZE_MAX uses a non-null dummy buffer to test overflow before any read. */
    result = OCTET_STRING_copy(&asn_DEF_OCTET_STRING, &destination_pointer,
                              &overflow);
    assert(result == -1);
    assert(destination_pointer == &destination);
    assert(destination.buf == original_destination_buffer);
    assert(destination.size == 4);
    assert(memcmp(destination.buf, "keep", 4) == 0);

    /* A too-small descriptor must be rejected before allocating a structure. */
    small_specifics.struct_size = 1;
    small_specifics.subvariant = ASN_OSUBV_STR;
    small_descriptor.specifics = &small_specifics;
    result = OCTET_STRING_copy(&small_descriptor, (void **)&copy, &null_empty);
    assert(result == -1);
    assert(copy == NULL);
    result = OCTET_STRING_copy(&small_descriptor, &destination_pointer,
                              &null_empty);
    assert(result == -1);
    assert(destination_pointer == &destination);
    assert(destination.buf == original_destination_buffer);
    assert(destination.size == 4);
    assert(memcmp(destination.buf, "keep", 4) == 0);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &destination);
}

/*
 * Purpose: verify a BER BIT STRING at every two-feed boundary and byte by byte.
 * Original source: issue #602 regression tests, written for asn1c.
 * Version/date: 1.0, 2026-11-13.
 * Inputs: wire/size identify the encoding; valid selects acceptance; expected,
 *   expected_size and unused describe the decoded value for valid inputs.
 * Returns: none. Exceptions: assertion failure terminates the test.
 * Responsible party: asn1c maintainers.
 * History: covers overwritten fragment padding and incremental parser state.
 * Example: check_bit_ber(wire, sizeof(wire), 0, NULL, 0, 0).
 */
static void
check_bit_ber(const uint8_t *wire, size_t size, int valid,
              const uint8_t *expected, size_t expected_size, int unused) {
    size_t split;

    /* Include a whole-buffer decode and every possible partial header/payload. */
    for(split = 0; split <= size; split++) {
        BIT_STRING_t *value = NULL; /* state variable: incrementally decoded value. */
        asn_dec_rval_t rv;
        size_t consumed; /* state variable: bytes committed by the decoder. */

        rv = ber_decode(NULL, &asn_DEF_BIT_STRING, (void **)&value, wire, split);
        assert(rv.consumed <= split);
        consumed = rv.consumed;
        if(rv.code == RC_WMORE) {
            rv = ber_decode(NULL, &asn_DEF_BIT_STRING, (void **)&value,
                            wire + consumed, size - consumed);
            assert(rv.consumed <= size - consumed);
            consumed += rv.consumed;
        }
        assert(rv.code == (valid ? RC_OK : RC_FAIL));
        if(valid) {
            assert(consumed == size);
            assert(value && value->size == expected_size);
            assert(value->bits_unused == unused);
            if(expected_size) assert(memcmp(value->buf, expected, expected_size) == 0);
        }
        ASN_STRUCT_FREE(asn_DEF_BIT_STRING, value);
    }

    /* Retain unconsumed header bytes while exposing just one new byte per call. */
    {
        BIT_STRING_t *value = NULL; /* state variable: bytewise decoded value. */
        size_t available; /* state variable: exposed prefix length. */
        size_t consumed = 0; /* state variable: committed prefix length. */
        asn_dec_rval_t rv = { RC_WMORE, 0 };

        for(available = 1; available <= size && rv.code == RC_WMORE; available++) {
            rv = ber_decode(NULL, &asn_DEF_BIT_STRING, (void **)&value,
                            wire + consumed, available - consumed);
            assert(rv.consumed <= available - consumed);
            consumed += rv.consumed;
        }
        assert(rv.code == (valid ? RC_OK : RC_FAIL));
        if(valid) {
            assert(consumed == size);
            assert(value && value->size == expected_size);
            assert(value->bits_unused == unused);
            if(expected_size) assert(memcmp(value->buf, expected, expected_size) == 0);
        }
        ASN_STRUCT_FREE(asn_DEF_BIT_STRING, value);
    }
}

/*
 * Purpose: exercise X.690 8.6.4 fragment padding rules and malformed counts.
 * Original source: issue #602 example and locally derived boundary vectors.
 * Version/date: 1.0, 2026-11-13.
 * Inputs: none. Returns: none. Exceptions: assertion failure terminates tests.
 * Responsible party: asn1c maintainers.
 * History: adds definite/indefinite, nested, empty and exhaustive count cases.
 * Example: called once by main before the existing string codec checks.
 */
static void
check_bit_ber_fragments(void) {
    uint8_t pair[] = {0x23, 8, 3, 2, 0, 0x80, 3, 2, 0, 0xfe};
    uint8_t only[] = {0x23, 4, 3, 2, 0, 0xff};
    uint8_t expected[] = {0x80, 0xfe};
    unsigned count;

#define BIT_BER_BAD(bytes) \
    check_bit_ber((const uint8_t *)(bytes), sizeof(bytes) - 1, 0, NULL, 0, 0)
#define BIT_BER_GOOD(bytes, data, unused) \
    check_bit_ber((const uint8_t *)(bytes), sizeof(bytes) - 1, 1, \
                  (const uint8_t *)(data), sizeof(data) - 1, unused)

    /* The reported loss also occurs across indefinite and nested boundaries. */
    BIT_BER_BAD("\x23\x08\x03\x02\x01\x80\x03\x02\x00\xff");
    BIT_BER_BAD("\x23\x80\x03\x02\x01\x80\x03\x02\x00\xff\x00\x00");
    BIT_BER_BAD("\x23\x0a\x23\x04\x03\x02\x01\x80\x03\x02\x00\xff");
    BIT_BER_BAD("\x23\x80\x23\x80\x03\x02\x01\x80\x00\x00"
                "\x03\x02\x00\xff\x00\x00");
    BIT_BER_BAD("\x23\x07\x03\x02\x01\x80\x03\x01\x00");
    BIT_BER_BAD("\x23\x06\x03\x02\x01\x80\x23\x00");

    /* Each primitive fragment needs its own valid unused-bit count octet. */
    BIT_BER_BAD("\x23\x02\x03\x00");
    BIT_BER_BAD("\x23\x06\x03\x00\x03\x02\x00\xff");
    BIT_BER_BAD("\x23\x03\x03\x01\x01");
    BIT_BER_BAD("\x23\x07\x03\x01\x01\x03\x02\x00\xff");

    /* Empty strings and a padded final leaf remain valid, including nested EOCs. */
    BIT_BER_GOOD("\x23\x00", "", 0);
    BIT_BER_GOOD("\x23\x80\x00\x00", "", 0);
    BIT_BER_GOOD("\x23\x03\x03\x01\x00", "", 0);
    BIT_BER_GOOD("\x23\x07\x03\x01\x00\x03\x02\x01\x80", "\x80", 1);
    BIT_BER_GOOD("\x23\x06\x23\x04\x03\x02\x01\x80", "\x80", 1);
    BIT_BER_GOOD("\x23\x80\x23\x80\x03\x02\x01\x80\x00\x00\x00\x00", "\x80", 1);
    BIT_BER_GOOD("\x03\x02\x01\x80", "\x80", 1);

    /* Exhaustively mutate counts: only zero is allowed before a later fragment. */
    for(count = 0; count <= 255; count++) {
        uint8_t last = (uint8_t)(0xff << (count & 7));
        pair[4] = (uint8_t)count;
        only[4] = (uint8_t)count;
        check_bit_ber(pair, sizeof(pair), count == 0, expected, sizeof(expected), 0);
        check_bit_ber(only, sizeof(only), count <= 7, &last, 1, (int)count);
    }
#undef BIT_BER_BAD
#undef BIT_BER_GOOD
}

/*
 * Purpose: run direct OCTET STRING safety tests and text codec regressions.
 * Original source: asn1c OCTET STRING skeleton tests.
 * Version/date: 1.2, 2026-11-13.
 * Inputs: none.
 * Returns: zero when all assertions pass.
 * Exceptions: none; assertion failures terminate the test process.
 * Responsible party: asn1c maintainers.
 * History: adds BER BIT STRING fragment checks before existing string tests.
 * Example: invoked by the check-OCTET_STRING test executable.
 */
int
main() {
    check_bit_ber_fragments();
	test_octet_string_compare();
	test_octet_string_copy();

	check_xer(HEX, 0, "<OCTET_STRING>41424</OCTET_STRING>",
		"AB@");

	check_xer(HEX, 0, "<!--comment--><OCTET_STRING>\n"
		"<!--comment-->41424</OCTET_STRING>",
		"AB@");

	check_xer(HEX, 0, "<OCTET_STRING blah blah> 4 1 4 2 4 5 44 </OCTET_STRING>",
		"ABED");

	/* Some hard cases */
	check_xer(HEX, "z", "<z><!-- < -->40</z>", "@");
	check_xer(HEX, "z", "<z><!-- <-->40</z>", "@");
	check_xer(HEX, "z", "<z><!-- -->>40</z>", 0);
	check_xer(HEX, "z", "<z><!-- <some <sometag>-->40</z>", "@");
	check_xer(HEX, "z", "<z><!-- <some <sometag-->>40</z>", 0);

	check_xer(HEX, "z", "ignored<z>40</z>stuff", "@");

	check_xer(HEX, "tag", "<tag>4</tag>", "@");
	check_xer(HEX, "a-z", "<a-z>7 375 73 6c6 9<!--/-->6 b</a-z>", "suslik");

	/* This one has a comment in a not-yet-supported place */ 
	/* check(HEX, "a-z", "<a-z>73 75 73 6c 6<!--/-->9 6b</a-z>",
		"suslik"); */

	check_xer(BINARY, "tag", "<tag/>", "");
	check_xer(BINARY, "tag", "<tag>blah</tag>", 0);
	check_xer(BINARY, "tag", "<tag>01000001</tag>", "A");
	check_xer(BINARY, "tag", "<tag>01000<!--blah--> 00 101 00001</tag>", "AB");

	check_xer(UTF8, 0, "<OCTET_STRING>one, two, three</OCTET_STRING>",
		"one, two, three");

	check_xer(UTF8, "z", "<z></z>", "");
	check_xer(UTF8, "z", "<z z z>&lt;&amp;&gt;</z z z>", "<&>");
	check_xer(UTF8, "z", "<z z z>a&lt;b&amp;c&gt;d</z z z>", "a<b&c>d");
	check_xer(UTF8, "z", "<z z z>a&lt</z z z>", "a&lt");
	check_xer(UTF8, "z", "<z z z>a&sdfsdfsdf;b</z z z>", "a&sdfsdfsdf;b");
	check_xer(UTF8, "z", "<z z z>a&#x20;b</z z z>", "a b");
	check_xer(UTF8, "z", "<z z z>a&#32;b</z z z>", "a b");
	check_xer(UTF8, "z", "<z>a&#x20here</z>", "a here");
	check_xer(UTF8, "z", "<z>a&#32323;b</z>", "a\347\271\203b");
	check_xer(UTF8, "z", "<z>a&#x4fc4;|</z>", "a\xe4\xbf\x84|");
    /* Last unicode point */
	check_xer(UTF8, "z", "<z>a&#x10ffff;|</z>", "a\xf4\x8f\xbf\xbf|");
	check_xer(UTF8, "z", "<z>a&#1114111;|</z>", "a\xf4\x8f\xbf\xbf|");
    /* Invalid or unsafe numeric character references */
	check_xer(UTF8, "z", "<z>a&#x110000;|</z>", 0);
	check_xer(UTF8, "z", "<z>a&#1114112;|</z>", 0);
	check_xer(UTF8, "z", "<z>a&#3000000000;b</z>", 0);
	check_xer(UTF8, "z", "<z>a&#5000000000;b</z>", 0);
	check_xer(UTF8, "z", "<z>a&#300</z>", "a&#300");
	check_xer(UTF8, "z", "<z>a&#-300;</z>", 0);
	check_xer_bin(UTF8, "z", "<z>a&#0;b</z>", "a\0b", 3);
	check_xer_bin(UTF8, "z", "<z>a&#x0;b</z>", "a\0b", 3);
	check_xer(UTF8, "z", "<z>a&#;b</z>", 0);
	check_xer(UTF8, "z", "<z>a&#x;b</z>", 0);
	check_xer(UTF8, "z", "<z>a<ff/>b</z>", "a\014b");
	check_xer(UTF8, "z", "<z>a<soh/>b</z>", "a\001b");
	check_xer(UTF8, "z", "<z>a<bel/></z>", "a\007");

	encode("", "");
	encode("a", "a");
	encode("a\nb", "a\nb");
	encode("a\bc", "a<bs/>c");
	encode("ab\01c\ndef\r\n", "ab<soh/>c\ndef\r\n");

	check_jer(HEX, "\"\"", "");
	check_jer(HEX, "\"", 0);
	check_jer(HEX, "", 0);
	check_jer(HEX, "\"6869\"", "hi");
	//check_jer(HEX, "\"68 69\"", 0); /* we want to allow space */
    check_jer(HEX, "\"68 69\"", "hi");

	check_jer(UTF8, "\"\"", "");
	check_jer(UTF8, "\"", 0);
	check_jer(UTF8, "", 0);
	check_jer(UTF8, "\"hi\"", "hi");
	check_jer(UTF8, "\"h i\"", "h i");

	/* Base64 XER tests */
	check_xer(BASE64, "tag", "<tag>SGVsbG8sIFdvcmxkIQ==</tag>", "Hello, World!");
	check_xer_bin(BASE64, "z", "<z>AAECA//+/Q==</z>", "\x00\x01\x02\x03\xff\xfe\xfd", 7);
	check_xer(BASE64, "tag", "<tag></tag>", "");
	check_xer(BASE64, "tag", "<tag>QQ==</tag>", "A");
	check_xer(BASE64, "tag", "<tag>QUI=</tag>", "AB");
	check_xer(BASE64, "tag", "<tag>QUJD</tag>", "ABC");
	/* Base64 with whitespace */
	check_xer(BASE64, "tag", "<tag>SGVs bG8s\nIFdv cmxk IQ==</tag>", "Hello, World!");
	/* Invalid Base64 - should fail */
	check_xer(BASE64, "tag", "<tag>SGVs!bG8</tag>", 0);

	return 0;
}
