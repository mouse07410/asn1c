#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <V.h>

static int
decode_code(const uint8_t *buf, size_t size) {
    V_t *v = 0;
    asn_dec_rval_t rv = ber_decode(0, &asn_DEF_V, (void **)&v, buf, size);
    ASN_STRUCT_FREE(asn_DEF_V, v);
    return rv.code;
}

#define CHECK(code, ...)                          \
    do {                                          \
        static const uint8_t b[] = {__VA_ARGS__}; \
        assert(decode_code(b, sizeof(b)) == code); \
    } while(0)

int
main(void) {
    /* a, then [1] again */
    CHECK(RC_FAIL, 0x30, 0x06, 0x81, 0x01, 0x00, 0x81, 0x01, 0x00);
    /* a, [1] again, unknown [5] */
    CHECK(RC_FAIL, 0x30, 0x09, 0x81, 0x01, 0x00, 0x81, 0x01, 0x00, 0x85, 0x01,
          0x00);
    /* indefinite length */
    CHECK(RC_FAIL, 0x30, 0x80, 0x81, 0x01, 0x00, 0x81, 0x01, 0x00, 0x00, 0x00);
    /* a, b */
    CHECK(RC_OK, 0x30, 0x06, 0x81, 0x01, 0x00, 0x84, 0x01, 0x00);
    /* a, unknown [5], later additions reusing [1] and [4] */
    CHECK(RC_OK, 0x30, 0x0c, 0x81, 0x01, 0x00, 0x85, 0x01, 0x00, 0x81, 0x01,
          0x00, 0x84, 0x01, 0x00);
    /* only unknown [5] */
    CHECK(RC_OK, 0x30, 0x03, 0x85, 0x01, 0x00);
    return 0;
}
