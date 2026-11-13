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
