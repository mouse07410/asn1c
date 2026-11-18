/*
 * Regression test for APER decoding of CHOICE types.
 *
 * Three decoder paths must reject malformed input without calling a NULL
 * function pointer:
 *
 *  - an extensible CHOICE with no extension additions must reject the
 *    extension bit instead of reusing it as a member index;
 *  - a selected member whose type has no APER decoder must fail cleanly;
 *  - the open-type helper must fail cleanly for a type without an APER
 *    decoder.
 *
 * A CHOICE with an actual extension addition is checked as well: selecting
 * one must still encode and decode through the open type path.
 */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <asn_application.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <aper_opentype.h>
#include <constr_CHOICE.h>
#include <INTEGER.h>
#include <NULL.h>
#include <per_support.h>

/* Local generated-type stand-in, for issue #615 (2026-11-18). */
typedef struct TestChoice {
    enum {
        TestChoice_PR_NOTHING,
        TestChoice_PR_a,
        TestChoice_PR_b,
        TestChoice_PR_c
    } present; /* Selected alternative; state variable. */
    /* Storage for the selected alternative. */
    union TestChoice_u {
        NULL_t a; /* Root NULL alternative. */
        INTEGER_t b; /* Root INTEGER alternative. */
        INTEGER_t c; /* Extension INTEGER alternative. */
    } choice; /* Alternative values. */
    asn_struct_ctx_t _asn_ctx; /* Decoder state variable. */
} TestChoice_t;

/*
 * A type with a usable free method but no APER decoder. The CHOICE decoder
 * and the open-type helper must reject it instead of calling a NULL codec.
 */
/* No-op free callback. Source: issue #615 regression, Javier and asn1c
 * maintainers, 2026-11-18. Inputs: td descriptor, sptr value, method free
 * mode. Returns nothing; raises no exceptions. Example: ASN_STRUCT_FREE
 * invokes this callback for the local no-codec type. */
static void
null_codec_free(const asn_TYPE_descriptor_t *td, void *sptr,
                enum asn_struct_free_method method) {
    (void)td;
    (void)sptr;
    (void)method;
}

static asn_TYPE_operation_t null_codec_ops = {
    .free_struct = null_codec_free,
};

static asn_TYPE_descriptor_t null_codec_td = {
    .name = "NoCodec",
    .xml_tag = "NoCodec",
    .op = &null_codec_ops,
};

/* CHOICE { a NULL, b INTEGER, ... } -- extensible, no extension additions. */
static asn_TYPE_member_t base_members[] = {
    {
        .flags = 0,
        .name = "a",
        .type = &asn_DEF_NULL,
        .memb_offset = offsetof(TestChoice_t, choice.a),
    },
    {
        .flags = 0,
        .name = "b",
        .type = &asn_DEF_INTEGER,
        .memb_offset = offsetof(TestChoice_t, choice.b),
    },
};

static const asn_TYPE_tag2member_t base_tag2el[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (5 << 2)), 0, 0, 0 },  /* a NULL */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 },  /* b INTEGER */
};

static asn_per_constraints_t base_constraints = {
    { APC_CONSTRAINED | APC_EXTENSIBLE, 1, 1, 0, 1 },  /* (0..1,...) */
    { APC_UNCONSTRAINED, -1, -1, 0, 0 },
    0, 0  /* No PER value map */
};

static asn_CHOICE_specifics_t base_specs = {
    .struct_size = sizeof(TestChoice_t),
    .ctx_offset = offsetof(TestChoice_t, _asn_ctx),
    .pres_offset = offsetof(TestChoice_t, present),
    .pres_size = sizeof(((TestChoice_t *)0)->present),
    .tag2el = base_tag2el,
    .tag2el_count = 2,  /* == ext_start: no extension additions */
    .to_canonical_order = NULL,
    .from_canonical_order = NULL,
    .ext_start = 2
};

static asn_TYPE_descriptor_t base_td = {
    .name = "TestChoice",
    .xml_tag = "TestChoice",
    .op = &asn_OP_CHOICE,
    .elements = base_members,
    .elements_count = 2,
    .specifics = &base_specs,
    .encoding_constraints = { .per_constraints = &base_constraints },
};

/* CHOICE { a NULL, b INTEGER, ..., c INTEGER } -- with an extension addition. */
static asn_TYPE_member_t ext_members[] = {
    {
        .flags = 0,
        .name = "a",
        .type = &asn_DEF_NULL,
        .memb_offset = offsetof(TestChoice_t, choice.a),
    },
    {
        .flags = 0,
        .name = "b",
        .type = &asn_DEF_INTEGER,
        .memb_offset = offsetof(TestChoice_t, choice.b),
    },
    {
        .flags = 0,
        .name = "c",
        .type = &asn_DEF_INTEGER,
        .memb_offset = offsetof(TestChoice_t, choice.c),
    },
};

static const asn_TYPE_tag2member_t ext_tag2el[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (5 << 2)), 0, 0, 0 },  /* a NULL */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 },  /* b INTEGER */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, 0, 0 },  /* c INTEGER */
};

static asn_CHOICE_specifics_t ext_specs = {
    .struct_size = sizeof(TestChoice_t),
    .ctx_offset = offsetof(TestChoice_t, _asn_ctx),
    .pres_offset = offsetof(TestChoice_t, present),
    .pres_size = sizeof(((TestChoice_t *)0)->present),
    .tag2el = ext_tag2el,
    .tag2el_count = 3,
    .to_canonical_order = NULL,
    .from_canonical_order = NULL,
    .ext_start = 2
};

static asn_TYPE_descriptor_t ext_td = {
    .name = "TestChoiceExt",
    .xml_tag = "TestChoiceExt",
    .op = &asn_OP_CHOICE,
    .elements = ext_members,
    .elements_count = 3,
    .specifics = &ext_specs,
    .encoding_constraints = { .per_constraints = &base_constraints },
};

/*
 * CHOICE { a NULL, b NoCodec } -- not extensible, and the selected member
 * has no APER decoder.
 */
static asn_TYPE_member_t nodec_members[] = {
    {
        .flags = 0,
        .name = "a",
        .type = &asn_DEF_NULL,
        .memb_offset = offsetof(TestChoice_t, choice.a),
    },
    {
        .flags = 0,
        .name = "b",
        .type = &null_codec_td,
        .memb_offset = offsetof(TestChoice_t, choice.b),
    },
};

static const asn_TYPE_tag2member_t nodec_tag2el[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (5 << 2)), 0, 0, 0 },  /* a NULL */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 },  /* b NoCodec */
};

static asn_per_constraints_t nodec_constraints = {
    { APC_CONSTRAINED, 1, 1, 0, 1 },  /* (0..1) */
    { APC_UNCONSTRAINED, -1, -1, 0, 0 },
    0, 0
};

static asn_CHOICE_specifics_t nodec_specs = {
    .struct_size = sizeof(TestChoice_t),
    .ctx_offset = offsetof(TestChoice_t, _asn_ctx),
    .pres_offset = offsetof(TestChoice_t, present),
    .pres_size = sizeof(((TestChoice_t *)0)->present),
    .tag2el = nodec_tag2el,
    .tag2el_count = 2,
    .to_canonical_order = NULL,
    .from_canonical_order = NULL,
    .ext_start = -1
};

static asn_TYPE_descriptor_t nodec_td = {
    .name = "TestChoiceNoCodec",
    .xml_tag = "TestChoiceNoCodec",
    .op = &asn_OP_CHOICE,
    .elements = nodec_members,
    .elements_count = 2,
    .specifics = &nodec_specs,
    .encoding_constraints = { .per_constraints = &nodec_constraints },
};

/* Decode a complete value. Source: issue #615 regression, Javier and asn1c
 * maintainers, 2026-11-18. Inputs: td descriptor, buf and size input, st
 * output. Returns decoder status; raises no exceptions. Example:
 * decode(&base_td, a_null, sizeof(a_null), &st). */
static asn_dec_rval_t
decode(asn_TYPE_descriptor_t *td, const void *buf, size_t size,
       TestChoice_t **st) {
    *st = NULL;
    return aper_decode_complete(NULL, td, (void **)st, buf, size);
}

/* Check rejection and free the partial value. Source: issue #615 regression,
 * Javier and asn1c maintainers, 2026-11-18. Inputs: td descriptor, buf and
 * size input, what label. Returns nothing; assert aborts on failure. Example:
 * check_rejected(&base_td, data, size, "invalid"). */
static void
check_rejected(asn_TYPE_descriptor_t *td, const void *buf, size_t size,
               const char *what) {
    TestChoice_t *st = NULL;
    asn_dec_rval_t rv = decode(td, buf, size, &st);

    fprintf(stderr, "%s => code %d, consumed %zu\n", what, (int)rv.code,
            rv.consumed);
    assert(rv.code == RC_FAIL);
    ASN_STRUCT_FREE(*td, st);
}

/* Exercise the decoder. Source: issue #615 regression, Javier and asn1c
 * maintainers, 2026-11-18; extended for index bounds that day. Inputs: none.
 * Returns zero; assert aborts on failure. Example: run the test executable. */
int
main(void) {
    static const unsigned char ext_bit_only[] = { 0x80 };
    /* Extension bit followed by a well-formed open type encoding member b. */
    static const unsigned char ext_plus_open[] = { 0x80, 0x02, 0x01, 0x05 };
    /* Large-form extension indices, aligned after the first two bits. */
    static const unsigned char large_index[] = { 0xc0, 0x03, 0xff, 0xff, 0xff };
    static const unsigned char four_octet_index[] = { 0xc0, 0x04, 0x7f, 0xff, 0xff, 0xff };
    static const unsigned char nodec_index[] = { 0x80 };
    static const unsigned char open_type[] = { 0x01, 0x05 };
    static const unsigned char a_null[] = { 0x00 };           /* a: index 0 */
    static const unsigned char b_int[] = { 0x40, 0x01, 0x05 }; /* b: 5 */
    TestChoice_t *st = NULL;
    asn_dec_rval_t rv;
    asn_enc_rval_t erv;
    unsigned char buf[64];
    size_t size;
    long value;

    /* A selected root member without an APER decoder must fail cleanly. */
    check_rejected(&nodec_td, nodec_index, sizeof(nodec_index),
                   "APER root member without an APER decoder");
    /* A failed selection must remain safe to free with missing metadata. */
    nodec_members[1].type = NULL;
    check_rejected(&nodec_td, nodec_index, sizeof(nodec_index),
                   "APER root member without a descriptor");
    nodec_members[1].type = &null_codec_td;
    null_codec_td.op = NULL;
    check_rejected(&nodec_td, nodec_index, sizeof(nodec_index),
                   "APER root member without operations");
    null_codec_td.op = &null_codec_ops;

    /* The open-type helper must fail cleanly for a type without a decoder. */
    {
        /* Length 1, content 0x05: well-formed open type. */
        asn_per_data_t pd;
        void *sptr = NULL;

        memset(&pd, 0, sizeof(pd));
        pd.buffer = open_type;
        pd.nbits = sizeof(open_type) * 8;
        rv = aper_open_type_get(NULL, &null_codec_td, NULL, &sptr, &pd);
        fprintf(stderr, "open type with no APER decoder => code %d, "
                "consumed %zu\n", (int)rv.code, rv.consumed);
        assert(rv.code == RC_FAIL);
        rv = aper_open_type_get(NULL, NULL, NULL, &sptr, &pd);
        assert(rv.code == RC_FAIL);
        rv = aper_open_type_get(NULL, &asn_DEF_NULL, NULL, &sptr, NULL);
        assert(rv.code == RC_FAIL);
    }

    /*
     * An extensible CHOICE with no extension additions must reject the
     * extension bit instead of treating it as member index 1.
     */
    check_rejected(&base_td, ext_bit_only, sizeof(ext_bit_only),
                   "APER extension bit with no extension additions");

    /*
     * The same bit with a valid open-type payload used to decode root member
     * b, accepting a value that this CHOICE cannot encode.
     */
    check_rejected(&base_td, ext_plus_open, sizeof(ext_plus_open),
                   "APER extension bit with a valid open-type payload");

    /* The extension index must be bounded before adding the root size. */
    check_rejected(&ext_td, large_index, sizeof(large_index),
                   "APER large extension index");
    rv = decode(&ext_td, large_index, sizeof(large_index) - 1, &st);
    assert(rv.code == RC_WMORE);
    ASN_STRUCT_FREE(ext_td, st);
    /* The current bit reader cannot return a 32-bit index. */
    rv = decode(&ext_td, four_octet_index, sizeof(four_octet_index), &st);
    assert(rv.code == RC_WMORE);
    ASN_STRUCT_FREE(ext_td, st);

    /* Valid root alternatives still decode. */
    rv = decode(&base_td, a_null, sizeof(a_null), &st);
    assert(rv.code == RC_OK);
    assert(st->present == TestChoice_PR_a);
    ASN_STRUCT_FREE(base_td, st);

    rv = decode(&base_td, b_int, sizeof(b_int), &st);
    assert(rv.code == RC_OK);
    assert(st->present == TestChoice_PR_b);
    assert(asn_INTEGER2long(&st->choice.b, &value) == 0);
    assert(value == 5);
    ASN_STRUCT_FREE(base_td, st);

    /* A valid extension addition must still work through the open type. */
    memset(buf, 0, sizeof(buf));
    {
        TestChoice_t enc;
        memset(&enc, 0, sizeof(enc));
        enc.present = TestChoice_PR_c;
        assert(asn_long2INTEGER(&enc.choice.c, 7) == 0);

        erv = aper_encode_to_buffer(&ext_td, NULL, &enc, buf, sizeof(buf));
        assert(erv.encoded > 0);
        size = ((size_t)erv.encoded + 7) / 8;
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &enc.choice.c);
    }

    st = NULL;
    rv = decode(&ext_td, buf, size, &st);
    assert(rv.code == RC_OK);
    assert(st->present == TestChoice_PR_c);
    assert(asn_INTEGER2long(&st->choice.c, &value) == 0);
    assert(value == 7);
    ASN_STRUCT_FREE(ext_td, st);

    return 0;
}
