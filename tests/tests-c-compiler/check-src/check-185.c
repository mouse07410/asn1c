#undef	NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#include <Message.h>
#include <NestedPayload.h>
#include <NestedSet.h>
#include <PayloadChoice.h>
#include <PayloadSeqOf.h>
#include <PayloadSetOf.h>
#include <jer_decoder.h>
#include <jer_encoder.h>

static char jer_buf[4096];
static size_t jer_len;

static int
buf_writer(const void *buffer, size_t size, void *app_key) {
	(void)app_key;
	assert(jer_len + size < sizeof(jer_buf));
	memcpy(jer_buf + jer_len, buffer, size);
	jer_len += size;
	jer_buf[jer_len] = '\0';
	return 0;
}

static void
assert_contains(const char *haystack, const char *needle) {
	assert(strstr(haystack, needle) != NULL);
}

static void
assert_not_contains(const char *haystack, const char *needle) {
	assert(strstr(haystack, needle) == NULL);
}

static OCTET_STRING_t *
make_octets(const char *text) {
	OCTET_STRING_t *st = calloc(1, sizeof(*st));

	assert(st != 0);
	assert(OCTET_STRING_fromBuf(st, text, strlen(text)) == 0);
	return st;
}

static void
check_bytes(const OCTET_STRING_t *st, const char *expected) {
	size_t expected_len = strlen(expected);

	assert(st->size == expected_len);
	assert(memcmp(st->buf, expected, expected_len) == 0);
}

static int
set_contains(PayloadSetOf_t *set, const char *expected) {
	int i;

	for(i = 0; i < set->list.count; i++) {
		OCTET_STRING_t *st = set->list.array[i];
		if(st->size == (int)strlen(expected)
		&& memcmp(st->buf, expected, strlen(expected)) == 0)
			return 1;
	}

	return 0;
}

static void
fill_message(Message_t *msg) {
	memset(msg, 0, sizeof(*msg));
	msg->count = 7;

	assert(OCTET_STRING_fromBuf(&msg->payload, "Hello", 5) == 0);
	assert(OCTET_STRING_fromBuf(&msg->named, "World", 5) == 0);
	assert(OCTET_STRING_fromBuf(&msg->prefixed, "Prefix", 6) == 0);

	msg->nested = calloc(1, sizeof(*msg->nested));
	assert(msg->nested != 0);
	assert(OCTET_STRING_fromBuf(&msg->nested->embedded, "Nest", 4) == 0);

	msg->nestedSet = calloc(1, sizeof(*msg->nestedSet));
	assert(msg->nestedSet != 0);
	assert(OCTET_STRING_fromBuf(&msg->nestedSet->setEmbedded, "Set", 3) == 0);

	msg->choice = calloc(1, sizeof(*msg->choice));
	assert(msg->choice != 0);
	msg->choice->present = PayloadChoice_PR_chosen;
	assert(OCTET_STRING_fromBuf(&msg->choice->choice.chosen, "Choice", 6) == 0);

	msg->seqOf = calloc(1, sizeof(*msg->seqOf));
	assert(msg->seqOf != 0);
	assert(ASN_SEQUENCE_ADD(&msg->seqOf->list, make_octets("One")) == 0);
	assert(ASN_SEQUENCE_ADD(&msg->seqOf->list, make_octets("Two")) == 0);

	msg->setOf = calloc(1, sizeof(*msg->setOf));
	assert(msg->setOf != 0);
	assert(ASN_SET_ADD(&msg->setOf->list, make_octets("Red")) == 0);
	assert(ASN_SET_ADD(&msg->setOf->list, make_octets("Blue")) == 0);
}

static void
check_jer_output(const char *jer) {
	assert_contains(jer, "\"SGVsbG8=\"");
	assert_contains(jer, "\"V29ybGQ=\"");
	assert_contains(jer, "\"UHJlZml4\"");
	assert_contains(jer, "\"TmVzdA==\"");
	assert_contains(jer, "\"U2V0\"");
	assert_contains(jer, "\"Q2hvaWNl\"");
	assert_contains(jer, "\"T25l\"");
	assert_contains(jer, "\"VHdv\"");
	assert_contains(jer, "\"UmVk\"");
	assert_contains(jer, "\"Qmx1ZQ==\"");

	assert_not_contains(jer, "48656C6C6F");
	assert_not_contains(jer, "576F726C64");
	assert_not_contains(jer, "507265666978");
	assert_not_contains(jer, "4E657374");
	assert_not_contains(jer, "536574");
	assert_not_contains(jer, "43686F696365");
	assert_not_contains(jer, "4F6E65");
	assert_not_contains(jer, "54776F");
	assert_not_contains(jer, "526564");
	assert_not_contains(jer, "426C7565");
}

static void
check_decoded_message(Message_t *msg) {
	assert(msg != 0);

	check_bytes(&msg->payload, "Hello");
	check_bytes(&msg->named, "World");
	check_bytes(&msg->prefixed, "Prefix");
	assert(msg->nested != 0);
	check_bytes(&msg->nested->embedded, "Nest");
	assert(msg->nestedSet != 0);
	check_bytes(&msg->nestedSet->setEmbedded, "Set");
	assert(msg->choice != 0);
	assert(msg->choice->present == PayloadChoice_PR_chosen);
	check_bytes(&msg->choice->choice.chosen, "Choice");
	assert(msg->seqOf != 0);
	assert(msg->seqOf->list.count == 2);
	check_bytes(msg->seqOf->list.array[0], "One");
	check_bytes(msg->seqOf->list.array[1], "Two");
	assert(msg->setOf != 0);
	assert(msg->setOf->list.count == 2);
	assert(set_contains(msg->setOf, "Red"));
	assert(set_contains(msg->setOf, "Blue"));
	assert(msg->count == 7);
}

static void
encode_decode_message(void) {
	Message_t src;
	Message_t *decoded = 0;
	asn_dec_rval_t dr;
	asn_enc_rval_t er;

	fill_message(&src);

	jer_len = 0;
	er = jer_encode(&asn_DEF_Message, &src, JER_F, buf_writer, 0);
	assert(er.encoded > 0);
	assert(jer_len > 0);
	check_jer_output(jer_buf);

	dr = jer_decode(0, &asn_DEF_Message, (void **)&decoded,
	                jer_buf, jer_len);
	assert(dr.code == RC_OK);
	check_decoded_message(decoded);

	jer_len = 0;
	er = jer_encode(&asn_DEF_Message, decoded, JER_F, buf_writer, 0);
	assert(er.encoded > 0);
	check_jer_output(jer_buf);

	ASN_STRUCT_RESET(asn_DEF_Message, &src);
	ASN_STRUCT_FREE(asn_DEF_Message, decoded);
}

int
main(int ac, char **av) {
	(void)ac;
	(void)av;

	encode_decode_message();

	return 0;
}
