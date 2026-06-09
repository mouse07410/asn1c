/* X.691 constrained-length determinant test for APER INTEGER */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <INTEGER.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <aper_support.c>
#include <aper_support.h>
#include <per_support.c>
#include <per_support.h>

static int
FailOut(const void *data, size_t size, void *op_key) {
    (void)data;
    (void)size;
    (void)op_key;
    assert(!"UNREACHABLE");
    return 0;
}

struct test_case {
    uint64_t value;
    const uint8_t *expected;
    size_t expected_len;
};

struct test_case_signed {
    long value;
    const uint8_t *expected;
    size_t expected_len;
};

static void
check_x691_constrained_range(const char *label, int lineno,
                             const asn_per_constraints_t *cts,
                             const struct test_case *tc) {
    INTEGER_t st;
    INTEGER_t *decoded_st = 0;
    struct asn_INTEGER_specifics_s specs;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    size_t encoded_len;

    memset(&st, 0, sizeof(st));
    memset(&specs, 0, sizeof(specs));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));

    asn_uint642INTEGER(&st, tc->value);

    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = FailOut;

    specs.field_width = sizeof(uint64_t);
    specs.field_unsigned = 1;
    asn_DEF_INTEGER.specifics = &specs;

    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, cts, &st, &po);
    assert(enc_rval.encoded >= 0);

    encoded_len = (size_t)(po.buffer - po.tmpspace) + ((po.nboff + 7) / 8);

    printf("%s:%d value=%" ASN_PRIu64 " expected_len=%zu got_len=%zu\n", label,
           lineno, tc->value, tc->expected_len, encoded_len);

    assert(encoded_len == tc->expected_len);
    assert(memcmp(po.tmpspace, tc->expected, tc->expected_len) == 0);

    pd.buffer = po.tmpspace;
    pd.nboff = 0;
    pd.nbits = 8 * encoded_len;
    pd.moved = 0;

    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, cts,
                                   (void **)&decoded_st, &pd);
    assert(dec_rval.code == RC_OK);

    {
        uint64_t decoded_value = 0;
        asn_INTEGER2uint64(decoded_st, &decoded_value);
        assert(decoded_value == tc->value);
    }

    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    ASN_STRUCT_FREE(asn_DEF_INTEGER, decoded_st);
}

static void
check_x691_constrained_range_signed(const char *label, int lineno,
                                    const asn_per_constraints_t *cts,
                                    const struct test_case_signed *tc) {
    INTEGER_t st;
    INTEGER_t *decoded_st = 0;
    struct asn_INTEGER_specifics_s specs;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    size_t encoded_len;

    memset(&st, 0, sizeof(st));
    memset(&specs, 0, sizeof(specs));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));

    asn_imax2INTEGER(&st, tc->value);

    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = FailOut;

    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;
    asn_DEF_INTEGER.specifics = &specs;

    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, cts, &st, &po);
    assert(enc_rval.encoded >= 0);

    encoded_len = (size_t)(po.buffer - po.tmpspace) + ((po.nboff + 7) / 8);

    printf("%s:%d value=%ld expected_len=%zu got_len=%zu\n", label, lineno,
           tc->value, tc->expected_len, encoded_len);

    assert(encoded_len == tc->expected_len);
    assert(memcmp(po.tmpspace, tc->expected, tc->expected_len) == 0);

    pd.buffer = po.tmpspace;
    pd.nboff = 0;
    pd.nbits = 8 * encoded_len;
    pd.moved = 0;

    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, cts,
                                   (void **)&decoded_st, &pd);
    assert(dec_rval.code == RC_OK);

    {
        intmax_t decoded_value = 0;
        asn_INTEGER2imax(decoded_st, &decoded_value);
        assert(decoded_value == tc->value);
    }

    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    ASN_STRUCT_FREE(asn_DEF_INTEGER, decoded_st);
}

static void
test_range_bits_36(void) {
    static const uint8_t exp_0[] = {0x01, 0x00};
    static const uint8_t exp_1[] = {0x01, 0x01};
    static const uint8_t exp_255[] = {0x01, 0xFF};
    static const uint8_t exp_256[] = {0x02, 0x01, 0x00};
    static const uint8_t exp_65535[] = {0x02, 0xFF, 0xFF};
    static const uint8_t exp_65536[] = {0x03, 0x01, 0x00, 0x00};
    static const uint8_t exp_max[] = {0x05, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF};

    static const struct test_case cases[] = {
        {0, exp_0, sizeof(exp_0)},
        {1, exp_1, sizeof(exp_1)},
        {255, exp_255, sizeof(exp_255)},
        {256, exp_256, sizeof(exp_256)},
        {65535, exp_65535, sizeof(exp_65535)},
        {65536, exp_65536, sizeof(exp_65536)},
        {UINT64_C(68719476735), exp_max, sizeof(exp_max)},
    };

    asn_per_constraints_t cts;
    size_t i;

    memset(&cts, 0, sizeof(cts));
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 36;
    cts.value.effective_bits = 36;
    cts.value.lower_bound = 0;
    cts.value.upper_bound = UINT64_C(68719476735);

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_x691_constrained_range("range36", __LINE__, &cts, &cases[i]);
    }
}

/*
 * range_bits=17: smallest value that enters the >16 code path.
 * INTEGER (0..131071), max_range_bytes=3.
 */
static void
test_range_bits_17(void) {
    static const uint8_t exp_0[] = {0x01, 0x00};
    static const uint8_t exp_1[] = {0x01, 0x01};
    static const uint8_t exp_255[] = {0x01, 0xFF};
    static const uint8_t exp_256[] = {0x02, 0x01, 0x00};
    static const uint8_t exp_65535[] = {0x02, 0xFF, 0xFF};
    /* 131071 = 0x01FFFF, 3 value bytes */
    static const uint8_t exp_max[] = {0x03, 0x01, 0xFF, 0xFF};

    static const struct test_case cases[] = {
        {0, exp_0, sizeof(exp_0)},
        {1, exp_1, sizeof(exp_1)},
        {255, exp_255, sizeof(exp_255)},
        {256, exp_256, sizeof(exp_256)},
        {65535, exp_65535, sizeof(exp_65535)},
        {131071, exp_max, sizeof(exp_max)},
    };

    asn_per_constraints_t cts;
    size_t i;

    memset(&cts, 0, sizeof(cts));
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 17;
    cts.value.effective_bits = 17;
    cts.value.lower_bound = 0;
    cts.value.upper_bound = 131071;

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_x691_constrained_range("range17", __LINE__, &cts, &cases[i]);
    }
}

/*
 * Non-zero lower_bound: INTEGER (1000..100000).
 * range = 99001, range_bits=17, max_range_bytes=3.
 * Encoded offset = value - 1000.
 */
static void
test_range_bits_17_offset(void) {
    /* offset 0 */
    static const uint8_t exp_lo[] = {0x01, 0x00};
    /* offset 1 */
    static const uint8_t exp_lo1[] = {0x01, 0x01};
    /* offset 255 */
    static const uint8_t exp_255[] = {0x01, 0xFF};
    /* offset 256: 2 value bytes */
    static const uint8_t exp_256[] = {0x02, 0x01, 0x00};
    /* offset 99000 = 0x0182B8: 3 value bytes */
    static const uint8_t exp_hi[] = {0x03, 0x01, 0x82, 0xB8};

    static const struct test_case cases[] = {
        {1000, exp_lo, sizeof(exp_lo)},   {1001, exp_lo1, sizeof(exp_lo1)},
        {1255, exp_255, sizeof(exp_255)}, {1256, exp_256, sizeof(exp_256)},
        {100000, exp_hi, sizeof(exp_hi)},
    };

    asn_per_constraints_t cts;
    size_t i;

    memset(&cts, 0, sizeof(cts));
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 17;
    cts.value.effective_bits = 17;
    cts.value.lower_bound = 1000;
    cts.value.upper_bound = 100000;

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_x691_constrained_range("offset17", __LINE__, &cts, &cases[i]);
    }
}

/*
 * Signed with negative lower_bound: INTEGER (-50000..50000).
 * range = 100001, range_bits=17, max_range_bytes=3.
 * Encoded offset = value - (-50000) = value + 50000.
 */
static void
test_range_bits_17_signed(void) {
    /* offset 0 */
    static const uint8_t exp_lo[] = {0x01, 0x00};
    /* offset 1 */
    static const uint8_t exp_lo1[] = {0x01, 0x01};
    /* offset 50000 = 0xC350: 2 value bytes */
    static const uint8_t exp_mid[] = {0x02, 0xC3, 0x50};
    /* offset 100000 = 0x0186A0: 3 value bytes */
    static const uint8_t exp_hi[] = {0x03, 0x01, 0x86, 0xA0};

    static const struct test_case_signed cases[] = {
        {-50000, exp_lo, sizeof(exp_lo)},
        {-49999, exp_lo1, sizeof(exp_lo1)},
        {0, exp_mid, sizeof(exp_mid)},
        {50000, exp_hi, sizeof(exp_hi)},
    };

    asn_per_constraints_t cts;
    size_t i;

    memset(&cts, 0, sizeof(cts));
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 17;
    cts.value.effective_bits = 17;
    cts.value.lower_bound = -50000;
    cts.value.upper_bound = 50000;

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check_x691_constrained_range_signed("signed17", __LINE__, &cts,
                                            &cases[i]);
    }
}

int
main(void) {
    test_range_bits_17();
    test_range_bits_17_offset();
    test_range_bits_17_signed();
    test_range_bits_36();
    return 0;
}
