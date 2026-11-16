#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
/* Boundary checks must execute even when the surrounding build defines NDEBUG. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>

#include "asn1p_integer.h"

static void check(int lineno, asn1c_integer_t value, const char *expected);
static void check_string(int lineno, asn1c_integer_t value,
                         const char *expected);

struct {
    uint8_t *buf; size_t size;
} ff = {
    (uint8_t *)"sdf", 3
};

/*
 * Purpose: check decimal parsing at signed compiler-integer boundaries.
 * Original source: PR #598 regression coverage written for asn1c.
 * Version/date: 1.0, 2026-11-13.
 * Inputs: none. Returns: the maximum supported integer for existing byte tests.
 * Exceptions: assertion failure terminates the test.
 * Responsible party: asn1c maintainers.
 * History: uses decimal reference values without signed sign-bit shifts.
 * Example: main uses the returned maximum for INTEGER byte encoding checks.
 */
static asn1c_integer_t
check_parse_limits(void) {
    const char *maximum;
    const char *minimum;
    const char *above;
    const char *below;
    asn1c_integer_t value; /* state variable: parsed boundary value. */
    asn1c_integer_t max_value; /* state variable: supported maximum. */

    /* Reference decimal boundaries independently exercise both supported widths. */
    if(sizeof(asn1c_integer_t) == 16) {
        maximum = "170141183460469231731687303715884105727";
        minimum = "-170141183460469231731687303715884105728";
        above = "170141183460469231731687303715884105728";
        below = "-170141183460469231731687303715884105729";
    } else {
        assert(sizeof(asn1c_integer_t) == 8);
        maximum = "9223372036854775807";
        minimum = "-9223372036854775808";
        above = "9223372036854775808";
        below = "-9223372036854775809";
    }

    /* Valid extremes parse exactly; decimal overflows must be rejected. */
    assert(asn1p_atoi(maximum, &max_value) == 0);
    assert(strcmp(asn1p_itoa(max_value), maximum) == 0);
    assert(asn1p_atoi(minimum, &value) == 0);
    assert(value == -max_value - 1);
    assert(asn1p_atoi(above, &value) == -1);
    assert(asn1p_atoi(below, &value) == -1);
    assert(asn1p_atoi("0", &value) == 0 && value == 0);
    assert(asn1p_atoi("12x", &value) == -1);
    return max_value;
}

/*
 * Purpose: check unsigned bit-length helpers at their boundaries.
 * Original source: mr-j0nes, PR #612, with expanded boundary coverage.
 * Version/date: 1.1, 2026-11-17.
 * Inputs: none. Returns: no value.
 * Exceptions: assertion failure terminates the test.
 * Responsible party: asn1c maintainers.
 * History: checks every unsigned power-of-two boundary and signed small range.
 * Example: main() calls this after the parse-limit checks.
 */
static void
check_bit_lengths(void) {
    size_t bit; /* state variable: current unsigned bit boundary. */
    int left; /* state variable: lower endpoint under exhaustive test. */
    int right; /* state variable: upper endpoint under exhaustive test. */

    /* Check zero and both sides of every unsigned power-of-two boundary. */
    assert(asn1p_unsigned_bit_length(0) == 0);
    for(bit = 1; bit <= ASN_INTEGER_BITS; bit++) {
        asn1c_uinteger_t power = (asn1c_uinteger_t)1 << (bit - 1);
        assert(asn1p_unsigned_bit_length(power - 1) == bit - 1);
        assert(asn1p_unsigned_bit_length(power) == bit);
    }
    assert(asn1p_unsigned_bit_length(~(asn1c_uinteger_t)0)
           == ASN_INTEGER_BITS);

    /* Exhaust ordered and reversed intervals in a signed range small enough
     * that the independent count calculation cannot overflow. */
    for(left = -32; left <= 32; left++) {
        for(right = -32; right <= 32; right++) {
            int width = 0; /* state variable: independently calculated width. */
            int capacity = 1; /* state variable: representable value count. */
            int count = right >= left ? right - left + 1 : 0;

            while(capacity < count) {
                width++;
                capacity *= 2;
            }
            assert(asn1p_range_bit_length(left, right) == (size_t)width);
        }
    }

    /* Verify the full signed span and familiar power-of-two range widths. */
    assert(asn1p_range_bit_length(5, 5) == 0);
    assert(asn1p_range_bit_length(0, 1) == 1);
    assert(asn1p_range_bit_length(0, 2) == 2);
    assert(asn1p_range_bit_length(0, 3) == 2);
    assert(asn1p_range_bit_length(0, 255) == 8);
    assert(asn1p_range_bit_length(0, 256) == 9);
    assert(asn1p_range_bit_length(-128, 127) == 8);
    assert(asn1p_range_bit_length(0, ASN_INTEGER_MAX) == ASN_INTEGER_BITS - 1);
    assert(asn1p_range_bit_length(ASN_INTEGER_MIN, 0) == ASN_INTEGER_BITS);
    assert(asn1p_range_bit_length(ASN_INTEGER_MIN, ASN_INTEGER_MAX)
           == ASN_INTEGER_BITS);
}

/*
 * Purpose: check exact decimal formatting of both formatters.
 * Original source: mr-j0nes, ASN1-0087.
 * Version/date: 1.0, 2026-11-17.
 * Inputs: none. Returns: no value.
 * Exceptions: assertion failure terminates the test.
 * Responsible party: asn1c maintainers.
 * History: split from main() to keep the function size bounded.
 * Example: main() calls this after the bit-length checks.
 */
static void
check_itoa_formatting(void) {
/* asn1p_itoa() and asn1p_itoa_s(): exact decimal formatting. */
check_string(__LINE__, 0, "0");
check_string(__LINE__, 1, "1");
check_string(__LINE__, -1, "-1");

/* Nine-digit chunk boundaries. */
check_string(__LINE__, 999999999, "999999999");
check_string(__LINE__, 1000000000, "1000000000");
check_string(__LINE__, 1000000001, "1000000001");
check_string(__LINE__, -999999999, "-999999999");
check_string(__LINE__, -1000000000, "-1000000000");
check_string(__LINE__, -1000000001, "-1000000001");

/* Fast-path boundaries; the expected text follows sizeof(long). */
switch(sizeof(long)) {
case 8:
    check_string(__LINE__, LONG_MIN, "-9223372036854775808");
    check_string(__LINE__, LONG_MAX, "9223372036854775807");
    break;
case 4:
    check_string(__LINE__, LONG_MIN, "-2147483648");
    check_string(__LINE__, LONG_MAX, "2147483647");
    break;
default:
    assert(!"Unreachable");
}

/* intmax_t is 64-bit on every supported platform. */
check_string(__LINE__, INTMAX_MIN, "-9223372036854775808");
check_string(__LINE__, INTMAX_MAX, "9223372036854775807");

/*
 * ASN_INTEGER_MIN/MAX and their neighbours.  The values come from the
 * macros, never from a literal, so this also compiles on the narrower
 * integer builds.
 */
switch(sizeof(asn1c_integer_t)) {
case 16:
    check_string(__LINE__, ASN_INTEGER_MIN + 1,
                 "-170141183460469231731687303715884105727");
    check_string(__LINE__, ASN_INTEGER_MAX - 1,
                 "170141183460469231731687303715884105726");
    check_string(__LINE__, ASN_INTEGER_MIN,
                 "-170141183460469231731687303715884105728");
    check_string(__LINE__, ASN_INTEGER_MAX,
                 "170141183460469231731687303715884105727");
    break;
case 8:
    check_string(__LINE__, ASN_INTEGER_MIN + 1, "-9223372036854775807");
    check_string(__LINE__, ASN_INTEGER_MAX - 1, "9223372036854775806");
    check_string(__LINE__, ASN_INTEGER_MIN, "-9223372036854775808");
    check_string(__LINE__, ASN_INTEGER_MAX, "9223372036854775807");
    break;
case 4:
    check_string(__LINE__, ASN_INTEGER_MIN + 1, "-2147483647");
    check_string(__LINE__, ASN_INTEGER_MAX - 1, "2147483646");
    check_string(__LINE__, ASN_INTEGER_MIN, "-2147483648");
    check_string(__LINE__, ASN_INTEGER_MAX, "2147483647");
    break;
default:
    assert(!"Unreachable");
}
}

/*
 * Purpose: run parser boundary and INTEGER representation regressions.
 * Original source: existing asn1c integer tests; PR #598 boundary extension.
 * Version/date: 1.1, 2026-11-13.
 * Inputs: none. Returns: zero on success. Exceptions: failed assertions abort.
 * Responsible party: asn1c maintainers. History: eliminates test sign-bit shifts.
 * Example: invoked by make check in libasn1parser.
 */
int main() {
    asn1c_integer_t maximum = check_parse_limits();

    check(__LINE__, 0, "{ (uint8_t *)\"\\x00\\0\", 1 }");
    check(__LINE__, 1, "{ (uint8_t *)\"\\x01\\0\", 1 }");
    check(__LINE__, 127, "{ (uint8_t *)\"\\x7f\\0\", 1 }");
    check(__LINE__, 128, "{ (uint8_t *)\"\\x00\\x80\\0\", 2 }");
    check(__LINE__, 129, "{ (uint8_t *)\"\\x00\\x81\\0\", 2 }");

    check(__LINE__, -1, "{ (uint8_t *)\"\\xff\\0\", 1 }");
    check(__LINE__, -2, "{ (uint8_t *)\"\\xfe\\0\", 1 }");
    check(__LINE__, -127, "{ (uint8_t *)\"\\x81\\0\", 1 }");
    check(__LINE__, -128, "{ (uint8_t *)\"\\x80\\0\", 1 }");
    check(__LINE__, -129, "{ (uint8_t *)\"\\xff\\x7f\\0\", 2 }");
    check(__LINE__, -254, "{ (uint8_t *)\"\\xff\\x02\\0\", 2 }");
    check(__LINE__, -255, "{ (uint8_t *)\"\\xff\\x01\\0\", 2 }");
    check(__LINE__, -256, "{ (uint8_t *)\"\\xff\\x00\\0\", 2 }");
    check(__LINE__, -257, "{ (uint8_t *)\"\\xfe\\xff\\0\", 2 }");

    check(__LINE__, ~(asn1c_integer_t)0, "{ (uint8_t *)\"\\xff\\0\", 1 }");

    switch(sizeof(asn1c_integer_t)) {
    case 4:
        check(__LINE__,
              maximum,
              "{ (uint8_t *)\""
              "\\x7f\\xff\\xff\\xff"
              "\\0\", 4 }");
        break;
    case 8:
        check(__LINE__,
              maximum,
              "{ (uint8_t *)\""
              "\\x7f\\xff\\xff\\xff\\xff\\xff\\xff\\xff"
              "\\0\", 8 }");
        break;
    case 16:
        check(__LINE__,
              maximum,
              "{ (uint8_t *)\""
              "\\x7f\\xff\\xff\\xff\\xff\\xff\\xff\\xff"
              "\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff"
              "\\0\", 16 }");

        break;
    default:
        assert(!"Unreachable");
    }

    check_bit_lengths();

    check_itoa_formatting();

    return 0;
}

static void check(int lineno, asn1c_integer_t value, const char *expected) {
    abuf *ab;
    ab = asn1p_integer_as_INTEGER(value);
    assert(ab);
    if(strcmp(ab->buffer, expected)) {
        fprintf(stderr, "%02d: %s -> [%s], expected [%s]\n", lineno,
                asn1p_itoa(value), ab->buffer, expected);
        assert(strcmp(ab->buffer, expected) == 0);
    }
    printf("%02d: %s -> %s\n", lineno, asn1p_itoa(value), ab->buffer);
    abuf_free(ab);
}

/*
 * Check both formatters, the returned length, and the buffer-size contract:
 * the result must be NUL-terminated, so size == strlen(expected) has no room
 * for the NUL and must fail, while size == strlen(expected) + 1 must fit.
 */
static void check_string(int lineno, asn1c_integer_t value,
                         const char *expected) {
    char buf[128] = "";
    const char *s = asn1p_itoa(value);
    size_t len = strlen(expected);
    int ret;

    if(!s || strcmp(s, expected) != 0) {
        fprintf(stderr, "%02d: asn1p_itoa() -> [%s], expected [%s]\n",
                lineno, s ? s : "(null)", expected);
        assert(!"asn1p_itoa() returned the wrong string");
    }

    ret = asn1p_itoa_s(buf, sizeof(buf), value);
    if(ret != (int)len || strlen(buf) != len || strcmp(buf, expected) != 0) {
        fprintf(stderr,
                "%02d: asn1p_itoa_s() -> ret=%d strlen=%zu [%s], "
                "expected ret=%d strlen=%zu [%s]\n",
                lineno, ret, strlen(buf), buf, (int)len, len, expected);
        assert(!"asn1p_itoa_s() returned the wrong string or length");
    }

    ret = asn1p_itoa_s(buf, len, value);
    if(ret != -1) {
        fprintf(stderr,
                "%02d: asn1p_itoa_s(buf, %zu) -> %d, expected -1 "
                "(no room for the NUL)\n",
                lineno, len, ret);
        assert(!"asn1p_itoa_s() accepted a buffer without room for the NUL");
    }

    ret = asn1p_itoa_s(buf, len + 1, value);
    if(ret != (int)len || strlen(buf) != len || strcmp(buf, expected) != 0) {
        fprintf(stderr,
                "%02d: asn1p_itoa_s(buf, %zu) -> ret=%d strlen=%zu [%s], "
                "expected ret=%d strlen=%zu [%s]\n",
                lineno, len + 1, ret, strlen(buf), buf, (int)len, len,
                expected);
        assert(!"asn1p_itoa_s() failed on an exactly fitting buffer");
    }
}
