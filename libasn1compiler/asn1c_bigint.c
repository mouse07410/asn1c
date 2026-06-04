/*
 * Arbitrary-precision integer support for the asn1c code generator.
 * See asn1c_bigint.h for the contract.  Dependency-free; uses only malloc.
 */
#include "asn1c_bigint.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

/* ===== magnitude helpers (big-endian, no leading zero octets) ===== */

/* Trim leading zero octets in-place; canonical zero is size 0. */
static void
mag_trim(uint8_t *mag, size_t *size) {
    size_t i = 0;
    while(i < *size && mag[i] == 0)
        i++;
    if(i) {
        memmove(mag, mag + i, *size - i);
        *size -= i;
    }
}

/* Compare two big-endian trimmed magnitudes. */
static int
mag_cmp(const uint8_t *a, size_t as, const uint8_t *b, size_t bs) {
    if(as != bs)
        return as < bs ? -1 : 1;
    return memcmp(a, b, as);   /* big-endian, equal length */
}

/* ===== public API ===== */

void
asn1c_bigint_free(asn1c_bigint_t *v) {
    if(!v) return;
    if(v->mag) free(v->mag);
    v->mag = NULL;
    v->mag_size = 0;
    v->negative = 0;
}

int
asn1c_bigint_from_decimal(const char *text, asn1c_bigint_t *out) {
    const char *p;
    int negative = 0;
    /* little-endian working magnitude during multiply-add */
    uint8_t *le = NULL;
    size_t le_len = 0, le_cap = 0;
    size_t i;
    int saw_digit = 0;

    if(!text || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    p = text;
    while(*p && isspace((unsigned char)*p)) p++;
    if(*p == '+' || *p == '-') {
        negative = (*p == '-');
        p++;
    }

    for(; *p && !isspace((unsigned char)*p); p++) {
        int d;
        unsigned carry;
        if(*p < '0' || *p > '9') {
            free(le);
            return -1;
        }
        d = *p - '0';
        saw_digit = 1;
        /* le = le * 10 + d */
        carry = (unsigned)d;
        for(i = 0; i < le_len; i++) {
            unsigned v = (unsigned)le[i] * 10u + carry;
            le[i] = (uint8_t)(v & 0xff);
            carry = v >> 8;
        }
        while(carry) {
            if(le_len == le_cap) {
                size_t ncap = le_cap ? le_cap * 2 : 8;
                uint8_t *nle = (uint8_t *)realloc(le, ncap);
                if(!nle) { free(le); return -1; }
                le = nle;
                le_cap = ncap;
            }
            le[le_len++] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
    }
    /* allow trailing whitespace only */
    while(*p && isspace((unsigned char)*p)) p++;
    if(*p != '\0' || !saw_digit) {
        free(le);
        return -1;
    }

    /* Convert little-endian working buffer to big-endian trimmed magnitude */
    if(le_len == 0) {
        /* value is zero */
        free(le);
        out->negative = 0;
        out->mag = NULL;
        out->mag_size = 0;
        return 0;
    } else {
        uint8_t *be = (uint8_t *)malloc(le_len);
        if(!be) { free(le); return -1; }
        for(i = 0; i < le_len; i++)
            be[i] = le[le_len - 1 - i];
        free(le);
        out->mag = be;
        out->mag_size = le_len;
        mag_trim(out->mag, &out->mag_size);
        out->negative = (out->mag_size == 0) ? 0 : negative;
        return 0;
    }
}

int
asn1c_bigint_cmp(const asn1c_bigint_t *a, const asn1c_bigint_t *b) {
    int a_zero = (a->mag_size == 0);
    int b_zero = (b->mag_size == 0);
    int an = a_zero ? 0 : a->negative;
    int bn = b_zero ? 0 : b->negative;
    int m;

    if(an != bn)
        return an ? -1 : 1;   /* negative < non-negative */

    m = mag_cmp(a->mag, a->mag_size, b->mag, b->mag_size);
    return an ? -m : m;       /* for negatives, larger magnitude is smaller */
}

int
asn1c_bigint_fits_uintmax(const asn1c_bigint_t *v, uintmax_t *out) {
    uintmax_t acc = 0;
    size_t i;
    if(v->negative && v->mag_size)
        return 0;
    if(v->mag_size > sizeof(uintmax_t))
        return 0;
    for(i = 0; i < v->mag_size; i++)
        acc = (acc << 8) | v->mag[i];
    if(out) *out = acc;
    return 1;
}

int
asn1c_bigint_fits_intmax(const asn1c_bigint_t *v, intmax_t *out) {
    uintmax_t acc = 0;
    size_t i;
    if(v->mag_size > sizeof(uintmax_t))
        return 0;
    for(i = 0; i < v->mag_size; i++)
        acc = (acc << 8) | v->mag[i];

    if(!v->negative) {
        if(acc > (uintmax_t)INTMAX_MAX)
            return 0;
        if(out) *out = (intmax_t)acc;
        return 1;
    } else {
        /* |INTMAX_MIN| == INTMAX_MAX + 1 */
        uintmax_t lim = (uintmax_t)INTMAX_MAX + 1;
        if(acc > lim)
            return 0;
        if(out) {
            if(acc == lim)
                *out = INTMAX_MIN;
            else
                *out = -(intmax_t)acc;
        }
        return 1;
    }
}

int
asn1c_bigint_fits_uint64(const asn1c_bigint_t *v, uint64_t *out) {
    uint64_t acc = 0;
    size_t i;
    if(v->negative && v->mag_size)
        return 0;
    if(v->mag_size > 8)
        return 0;
    for(i = 0; i < v->mag_size; i++)
        acc = (acc << 8) | v->mag[i];
    if(out) *out = acc;
    return 1;
}

int
asn1c_bigint_fits_int64(const asn1c_bigint_t *v, int64_t *out) {
    uint64_t acc = 0;
    size_t i;
    if(v->mag_size > 8)
        return 0;
    for(i = 0; i < v->mag_size; i++)
        acc = (acc << 8) | v->mag[i];

    if(!v->negative) {
        if(acc > (uint64_t)INT64_MAX)
            return 0;
        if(out) *out = (int64_t)acc;
        return 1;
    } else {
        uint64_t lim = (uint64_t)INT64_MAX + 1;
        if(acc > lim)
            return 0;
        if(out) {
            if(acc == lim)
                *out = INT64_MIN;
            else
                *out = -(int64_t)acc;
        }
        return 1;
    }
}

int
asn1c_bigint_to_integer_content_octets(const asn1c_bigint_t *v,
                                       uint8_t **buf, size_t *size) {
    uint8_t *work;
    size_t len, start;

    if(!buf || !size)
        return -1;

    /* zero -> single 0x00 octet */
    if(v->mag_size == 0) {
        work = (uint8_t *)malloc(1);
        if(!work) return -1;
        work[0] = 0x00;
        *buf = work;
        *size = 1;
        return 0;
    }

    /* Build a sign-extended buffer with one guard octet at the front. */
    len = v->mag_size + 1;
    work = (uint8_t *)malloc(len);
    if(!work) return -1;
    work[0] = 0x00;
    memcpy(work + 1, v->mag, v->mag_size);

    if(v->negative) {
        /* two's complement over the whole buffer: invert then add one */
        size_t i;
        unsigned carry = 1;
        for(i = len; i-- > 0; ) {
            unsigned t = (unsigned)(uint8_t)~work[i] + carry;
            work[i] = (uint8_t)(t & 0xff);
            carry = t >> 8;
        }
    }

    /* Canonicalize: strip redundant leading sign octets. */
    start = 0;
    if(v->negative) {
        while(len - start > 1
              && work[start] == 0xFF
              && (work[start + 1] & 0x80))
            start++;
    } else {
        while(len - start > 1
              && work[start] == 0x00
              && !(work[start + 1] & 0x80))
            start++;
    }

    *size = len - start;
    if(start) {
        uint8_t *out = (uint8_t *)malloc(*size);
        if(!out) { free(work); return -1; }
        memcpy(out, work + start, *size);
        free(work);
        *buf = out;
    } else {
        *buf = work;
    }
    return 0;
}

/* ===== range arithmetic ===== */

/* result = a + b for big-endian trimmed magnitudes; caller frees *r. */
static int
mag_add(const uint8_t *a, size_t as, const uint8_t *b, size_t bs,
        uint8_t **r, size_t *rs) {
    size_t n = (as > bs ? as : bs) + 1;
    uint8_t *out = (uint8_t *)calloc(n, 1);
    size_t i;
    unsigned carry = 0;
    if(!out) return -1;
    for(i = 0; i < n; i++) {
        unsigned av = (i < as) ? a[as - 1 - i] : 0;
        unsigned bv = (i < bs) ? b[bs - 1 - i] : 0;
        unsigned s = av + bv + carry;
        out[n - 1 - i] = (uint8_t)(s & 0xff);
        carry = s >> 8;
    }
    mag_trim(out, &n);
    *r = out;
    *rs = n;
    return 0;
}

/* result = a - b for a >= b (big-endian trimmed magnitudes); caller frees. */
static int
mag_sub(const uint8_t *a, size_t as, const uint8_t *b, size_t bs,
        uint8_t **r, size_t *rs) {
    uint8_t *out = (uint8_t *)calloc(as ? as : 1, 1);
    size_t i;
    int borrow = 0;
    if(!out) return -1;
    for(i = 0; i < as; i++) {
        int av = a[as - 1 - i];
        int bv = (i < bs) ? b[bs - 1 - i] : 0;
        int s = av - bv - borrow;
        if(s < 0) { s += 256; borrow = 1; } else borrow = 0;
        out[as - 1 - i] = (uint8_t)s;
    }
    *rs = as ? as : 1;
    mag_trim(out, rs);
    *r = out;
    return 0;
}

int
asn1c_bigint_subtract_range_plus_one(const asn1c_bigint_t *lb,
                                     const asn1c_bigint_t *ub,
                                     asn1c_bigint_t *range) {
    uint8_t *diff = NULL, *res = NULL;
    size_t diff_s = 0, res_s = 0;
    static const uint8_t one[1] = { 1 };
    int ln, un;

    if(!lb || !ub || !range)
        return -1;
    if(asn1c_bigint_cmp(lb, ub) > 0)
        return -1;          /* lb must be <= ub */

    memset(range, 0, sizeof(*range));

    ln = (lb->mag_size == 0) ? 0 : lb->negative;
    un = (ub->mag_size == 0) ? 0 : ub->negative;

    /* Compute |ub - lb| (always >= 0 since ub >= lb). */
    if(ln == un) {
        /* same sign: subtract magnitudes (order depends on sign) */
        if(!un) {
            /* both >= 0, ub.mag >= lb.mag */
            if(mag_sub(ub->mag, ub->mag_size, lb->mag, lb->mag_size,
                       &diff, &diff_s)) return -1;
        } else {
            /* both < 0, |lb| >= |ub| */
            if(mag_sub(lb->mag, lb->mag_size, ub->mag, ub->mag_size,
                       &diff, &diff_s)) return -1;
        }
    } else {
        /* ub >= 0 and lb < 0: difference is sum of magnitudes */
        if(mag_add(ub->mag, ub->mag_size, lb->mag, lb->mag_size,
                   &diff, &diff_s)) return -1;
    }

    /* range = diff + 1 */
    if(mag_add(diff, diff_s, one, 1, &res, &res_s)) {
        free(diff);
        return -1;
    }
    free(diff);

    range->negative = 0;
    range->mag = res;
    range->mag_size = res_s;
    return 0;
}
