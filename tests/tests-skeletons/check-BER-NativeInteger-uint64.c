/*
 * Verify NativeInteger_encode_der produces X.690-conformant BER for
 * unsigned long values > INT64_MAX (requires a 0x00 pad byte).
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <INTEGER.h>
#include <NativeInteger.h>

static int failures = 0;

static const asn_INTEGER_specifics_t specs_unsigned = {
    0, 0, 0, 0, 0,
    sizeof(unsigned long), /* field_width */
    1                      /* field_unsigned */
};

static const asn_INTEGER_specifics_t specs_signed = {
    0, 0, 0, 0, 0,
    sizeof(long), /* field_width */
    0             /* field_unsigned (signed) */
};

static asn_TYPE_descriptor_t td_unsigned;
static asn_TYPE_descriptor_t td_signed;

/* Universal tag 2 (INTEGER), primitive. */
static const ber_tlv_tag_t integer_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};

/* Collect encoded bytes. */
static uint8_t enc_buf[32];
static size_t enc_len;

static int
collect(const void *data, size_t size, void *key) {
    (void)key;
    memcpy(enc_buf + enc_len, data, size);
    enc_len += size;
    return 0;
}

static void
check_encode(const char *name, const asn_TYPE_descriptor_t *td,
             unsigned long value, const uint8_t *expected,
             size_t expected_len) {
    enc_len = 0;
    asn_enc_rval_t r = NativeInteger_encode_der(td, &value, 0, 0, collect, 0);
    if(r.encoded < 0 || enc_len != expected_len
       || memcmp(enc_buf, expected, expected_len) != 0) {
        printf("FAIL  %s: got %zu bytes", name, enc_len);
        for(size_t i = 0; i < enc_len; i++)
            printf(" %02x", enc_buf[i]);
        printf(", expected %zu bytes", expected_len);
        for(size_t i = 0; i < expected_len; i++)
            printf(" %02x", expected[i]);
        printf("\n");
        failures++;
    } else {
        printf("pass  %s\n", name);
    }
}

static void
check_roundtrip(const char *name, const asn_TYPE_descriptor_t *td,
                unsigned long value) {
    enc_len = 0;
    NativeInteger_encode_der(td, &value, 0, 0, collect, 0);

    unsigned long decoded = 0;
    void *ptr = &decoded;
    asn_dec_rval_t dr =
        NativeInteger_decode_ber(0, td, &ptr, enc_buf, enc_len, 0);
    if(dr.code != RC_OK || decoded != value) {
        printf("FAIL  %s roundtrip: encoded value %lu decoded as %lu\n", name,
               value, decoded);
        failures++;
    } else {
        printf("pass  %s roundtrip\n", name);
    }
}

int
main(void) {
    /* Initialise minimal type descriptors. */
    memset(&td_unsigned, 0, sizeof(td_unsigned));
    td_unsigned.name = "UnsignedInteger";
    td_unsigned.xml_tag = "UnsignedInteger";
    td_unsigned.op = &asn_OP_NativeInteger;
    td_unsigned.specifics = &specs_unsigned;
    td_unsigned.tags = integer_tags;
    td_unsigned.tags_count = 1;
    td_unsigned.all_tags = integer_tags;
    td_unsigned.all_tags_count = 1;

    memset(&td_signed, 0, sizeof(td_signed));
    td_signed.name = "SignedInteger";
    td_signed.xml_tag = "SignedInteger";
    td_signed.op = &asn_OP_NativeInteger;
    td_signed.specifics = &specs_signed;
    td_signed.tags = integer_tags;
    td_signed.tags_count = 1;
    td_signed.all_tags = integer_tags;
    td_signed.all_tags_count = 1;

    printf("--- unsigned encoding ---\n");
    /* 0: 02 01 00 */
    check_encode("unsigned 0", &td_unsigned, 0UL,
                 (uint8_t[]){0x02, 0x01, 0x00}, 3);
    /* 1: 02 01 01 */
    check_encode("unsigned 1", &td_unsigned, 1UL,
                 (uint8_t[]){0x02, 0x01, 0x01}, 3);

#if ULONG_MAX == UINT64_MAX
    /* INT64_MAX: 02 08 7f ff ff ff ff ff ff ff */
    check_encode("unsigned INT64_MAX", &td_unsigned, (unsigned long)INT64_MAX,
                 (uint8_t[]){0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff},
                 10);
    /* INT64_MAX+1: 02 09 00 80 00 00 00 00 00 00 00 */
    check_encode("unsigned INT64_MAX+1", &td_unsigned,
                 (unsigned long)INT64_MAX + 1UL,
                 (uint8_t[]){0x02, 0x09, 0x00, 0x80, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00},
                 11);
    /* UINT64_MAX: 02 09 00 ff ff ff ff ff ff ff ff */
    check_encode("unsigned UINT64_MAX", &td_unsigned, UINT64_MAX,
                 (uint8_t[]){0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff},
                 11);
#else
    printf("skip  64-bit unsigned vectors (sizeof(unsigned long)=%zu)\n",
           sizeof(unsigned long));
#endif

    printf("--- signed encoding (regression) ---\n");
    /* -1: 02 01 ff */
    check_encode("signed -1", &td_signed, (unsigned long)-1L,
                 (uint8_t[]){0x02, 0x01, 0xff}, 3);
    /* -128: 02 01 80 */
    check_encode("signed -128", &td_signed, (unsigned long)-128L,
                 (uint8_t[]){0x02, 0x01, 0x80}, 3);

#if LONG_MIN == INT64_MIN && LONG_MAX == INT64_MAX
    /* INT64_MIN: 02 08 80 00 00 00 00 00 00 00 */
    check_encode("signed INT64_MIN", &td_signed, (unsigned long)INT64_MIN,
                 (uint8_t[]){0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00},
                 10);
#endif

    printf("--- round-trips ---\n");
    check_roundtrip("unsigned 0", &td_unsigned, 0UL);
    check_roundtrip("unsigned 1", &td_unsigned, 1UL);
#if ULONG_MAX == UINT64_MAX
    check_roundtrip("unsigned INT64_MAX", &td_unsigned, (unsigned long)INT64_MAX);
    check_roundtrip("unsigned INT64_MAX+1", &td_unsigned,
                    (unsigned long)INT64_MAX + 1UL);
    check_roundtrip("unsigned UINT64_MAX", &td_unsigned, UINT64_MAX);
#endif

    printf("\n%s\n", failures ? "FAILED" : "All tests passed.");
    return failures ? 1 : 0;
}
