#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>

#include "asn1p_integer.h"

/*
 * Parse the number in the given string until the given *end position,
 * returning the position after the last parsed character back using the
 * same (*end) pointer.
 * WARNING: This behavior is different from the standard strtol/strtoimax(3).
 */
enum strtox_result_e {
    STRTOX_ERROR_RANGE = -3, /* Input outside of supported numeric range */
    STRTOX_ERROR_INVAL = -2, /* Invalid data encountered (e.g., "+-") */
    STRTOX_EXPECT_MORE = -1, /* More data expected (e.g. "+") */
    STRTOX_OK = 0,           /* Conversion succeeded, number ends at (*end) */
    STRTOX_EXTRA_DATA =
        1 /* Conversion succeeded, but the string has extra stuff */
};

static enum strtox_result_e
strtoaint_lim(const char *str, const char **end, asn1c_integer_t *intp) {
	const asn1c_integer_t upper_boundary = ASN_INTEGER_MAX / 10;
	int last_digit_max = ASN_INTEGER_MAX % 10;
	int sign = 1;
	asn1c_integer_t value;

	if(str >= *end) return STRTOX_ERROR_INVAL;

	switch(*str) {
	case '-':
		last_digit_max++;
		sign = -1;
		/* FALL THROUGH */
	case '+':
		str++;
		if(str >= *end) {
			*end = str;
			return STRTOX_EXPECT_MORE;
		}
	}

	for(value = 0; str < (*end); str++) {
		switch(*str) {
		case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
		case 0x35: case 0x36: case 0x37: case 0x38: case 0x39: {
			int d = *str - '0';
			if(value < upper_boundary) {
				value = value * 10 + d;
			} else if(value == upper_boundary) {
				if(d <= last_digit_max) {
					if(sign > 0) {
						value = value * 10 + d;
					} else {
						sign = 1;
						value = -value * 10 - d;
					}
				} else {
					*end = str;
					return STRTOX_ERROR_RANGE;
				}
			} else {
				*end = str;
				return STRTOX_ERROR_RANGE;
			}
		    }
		    continue;
		default:
		    *end = str;
		    *intp = sign * value;
		    return STRTOX_EXTRA_DATA;
		}
	}

	*end = str;
	*intp = sign * value;
	return STRTOX_OK;
}

/*
 * Purpose: return the binary width needed to encode values from zero through
 * value, inclusive. This is ceil(log2(value + 1)); zero needs no bits.
 * Original source: mr-j0nes, PR #612.
 * Version/date: 1.0, 2026-11-17.
 * Inputs: value, the largest unsigned value in the encoded range.
 * Returns: the number of bits needed to encode that range.
 * Exceptions: none.
 * Responsible party: mr-j0nes (original implementation); asn1c maintainers.
 * History: helper added for PER integer range width calculation.
 * Example: asn1p_unsigned_bit_length(3) returns 2 for values 0 through 3.
 */
size_t
asn1p_unsigned_bit_length(asn1c_uinteger_t value) {
	size_t bits = 0; /* state variable: accumulated binary width. */
	/* Consume one unsigned bit per iteration; no signed arithmetic is used. */
	while(value) {
		bits++;
		value >>= 1;
	}
	return bits;
}

/*
 * Purpose: return the minimum bit width for the inclusive signed range.
 * The width is ceil(log2(count)), where count is right - left + 1; a
 * singleton range therefore needs zero bits.
 * Original source: mr-j0nes, PR #612.
 * Version/date: 1.0, 2026-11-17.
 * Inputs: left, the lower signed endpoint; right, the upper signed endpoint.
 * Returns: the minimum width, or zero when right is less than left.
 * Exceptions: none.
 * Responsible party: mr-j0nes (original implementation); asn1c maintainers.
 * History: uses unsigned span subtraction to cover the full signed domain
 * without overflowing signed arithmetic.
 * Example: asn1p_range_bit_length(-128, 127) returns 8.
 */
size_t
asn1p_range_bit_length(asn1c_integer_t left, asn1c_integer_t right) {
	if(right < left)
		return 0;
	return asn1p_unsigned_bit_length((asn1c_uinteger_t)right
					 - (asn1c_uinteger_t)left);
}

int
asn1p_atoi(const char *ptr, asn1c_integer_t *value) {
    const char *end = ptr + strlen(ptr);
    if(strtoaint_lim(ptr, &end, value) == STRTOX_OK) {
        return 0;
    } else {
        return -1;
    }
}

const char *asn1p_itoa(asn1c_integer_t v) {
    static char static_buf[128];
    int ret = asn1p_itoa_s(static_buf, sizeof(static_buf), v);
    if(ret > 0) {
        assert((size_t)ret < sizeof(static_buf));
        return static_buf;
    } else {
        return NULL;
    }
}

/*
 * Purpose: format a signed ASN.1 integer as a NUL-terminated decimal string.
 * Original source: asn1c; unsigned minimum fix by mr-j0nes, PR #614.
 * Version/date: 1.1, 2026-11-18.
 * Inputs: buf is the destination; size is its capacity; v is the value.
 * Returns: decimal string length excluding NUL, or -1 if it does not fit.
 * Exceptions: none.
 * Responsible party: asn1c maintainers.
 * History: use unsigned magnitude to format the minimum without overflow.
 * Example: asn1p_itoa_s(buf, sizeof(buf), -1) writes "-1" and returns 2.
 */
int asn1p_itoa_s(char *buf, size_t size, asn1c_integer_t v) {
    char tmp_buf[128];
    asn1c_uinteger_t mag;
    int sign;

    /* A nonzero capacity must refer to writable storage. */
    if(!buf) return -1;

    if(v >= LONG_MIN && v < LONG_MAX) {
        int ret = snprintf(buf, size, "%ld", (long)v);
        if(ret < 0 || (size_t)ret >= size) {
            return -1;
        }
        return ret;
    }

    /*
     * Compute |v| in unsigned arithmetic.  Negating ASN_INTEGER_MIN in
     * asn1c_integer_t would overflow; the unsigned conversion is defined
     * modulo 2^N and yields 2^(N-1) for the minimum.
     */
    sign = (v < 0);
    mag = sign ? (asn1c_uinteger_t)0 - (asn1c_uinteger_t)v
               : (asn1c_uinteger_t)v;

    assert(mag > 1000000000UL);

    {
        char restbuf[10] = "000000000";
        unsigned long rest = (unsigned long)(mag % 1000000000UL);
        const char *reststr = asn1p_itoa((long)rest);
        size_t restlen = strlen(reststr);
        /* mag <= 2^(N-1), so the quotient fits the signed type. */
        asn1c_integer_t head = (asn1c_integer_t)(mag / 1000000000UL);
        const char *headstr;
        int ret;

        assert(restlen <= 9);
        memcpy(restbuf + (9 - restlen), reststr, restlen);

        headstr = asn1p_itoa(head);
        assert(headstr);
        ret = snprintf(tmp_buf, sizeof(tmp_buf), "%s%s%s",
                       sign ? "-" : "", headstr, restbuf);
        if(ret < 0 || (size_t)ret >= size) {
            assert(ret > 0 && (size_t)ret < sizeof(tmp_buf));
            return -1;
        }
        memcpy(buf, tmp_buf, ret);
        buf[ret] = '\0';
        return ret;
    }
}

abuf *
asn1p_integer_as_INTEGER(asn1c_integer_t value) {
    abuf *ab = abuf_new();
    uint8_t buf[sizeof(value) + 1];
    uint8_t *bp = buf;

    do {
        *bp++ = value;
        value >>= 8;
    } while(!((value == 0 && !(bp[-1] & 0x80))
              || (value == -1 && (bp[-1] & 0x80))));

    abuf_printf(ab, "{ (uint8_t *)\"");

    for(const uint8_t *p = bp-1; p >= buf; p--) {
        abuf_printf(ab, "\\x%02x", *p);
    }

    abuf_printf(ab, "\\0\", %zu }", bp - buf);

    return ab;
}
