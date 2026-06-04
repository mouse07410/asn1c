/*-
 * Runtime helpers for asn_cval_t constraint bounds.  See asn_constraint_value.h.
 */
#include <asn_internal.h>
#include <asn_constraint_value.h>
#include <errno.h>

/* ===== canonical two's-complement content-octet comparison ===== */

/* A bound's content octets are negative iff the top bit of the first octet
 * is set (and there is at least one octet). */
static int
acv_bytes_negative(const uint8_t *buf, size_t size) {
    return (size > 0) && (buf[0] & 0x80);
}

/*
 * Defensive canonicalization: return a pointer/length pair stripped of
 * redundant leading sign octets.  Operates on the caller's buffer (no copy).
 */
static void
acv_bytes_canonical(const uint8_t *buf, size_t size,
                    const uint8_t **out_buf, size_t *out_size) {
    if(size == 0) {
        *out_buf = buf;
        *out_size = 0;
        return;
    }
    if(buf[0] & 0x80) {
        /* negative: drop leading 0xFF while next octet keeps the sign bit */
        while(size > 1 && buf[0] == 0xFF && (buf[1] & 0x80)) {
            buf++;
            size--;
        }
    } else {
        /* non-negative: drop leading 0x00 while next octet lacks the sign bit */
        while(size > 1 && buf[0] == 0x00 && !(buf[1] & 0x80)) {
            buf++;
            size--;
        }
    }
    *out_buf = buf;
    *out_size = size;
}

/* Compare two canonical INTEGER content-octet arrays as signed integers. */
static int
acv_cmp_bytes(const uint8_t *ab, size_t as, const uint8_t *bb, size_t bs) {
    int an, bn;
    acv_bytes_canonical(ab, as, &ab, &as);
    acv_bytes_canonical(bb, bs, &bb, &bs);
    an = acv_bytes_negative(ab, as);
    bn = acv_bytes_negative(bb, bs);
    if(an != bn)
        return an ? -1 : 1;     /* negative < non-negative */
    if(!an) {
        /* both non-negative: longer canonical form is larger */
        if(as != bs) return as < bs ? -1 : 1;
        return memcmp(ab, bb, as);
    } else {
        /* both negative: longer canonical form is more negative (smaller) */
        if(as != bs) return as < bs ? 1 : -1;
        /* same width two's complement: unsigned order == signed order */
        return memcmp(ab, bb, as);
    }
}

/* Materialize a scalar as canonical content octets into an INTEGER_t. */
static int
acv_sint_to_INTEGER(intmax_t v, INTEGER_t *tmp) {
    memset(tmp, 0, sizeof(*tmp));
    return asn_imax2INTEGER(tmp, v);
}
static int
acv_uint_to_INTEGER(uintmax_t v, INTEGER_t *tmp) {
    memset(tmp, 0, sizeof(*tmp));
    return asn_umax2INTEGER(tmp, v);
}

/* Compare a materialized scalar (as INTEGER_t bytes) against cval bytes. */
static int
acv_cmp_scalarbytes_vs_cvalbytes(const INTEGER_t *s, const asn_cval_t *b) {
    return acv_cmp_bytes(s->buf, s->size, b->value.b.buf, b->value.b.size);
}

/* ===== scalar vs cval ===== */

int
asn_cval_cmp_uint(uintmax_t a, const asn_cval_t *b) {
    switch(b->kind) {
    case ACV_UINT:
        if(a < b->value.u) return -1;
        if(a > b->value.u) return 1;
        return 0;
    case ACV_SINT:
        if(b->value.s < 0) return 1;                  /* a >= 0 > b */
        if(a < (uintmax_t)b->value.s) return -1;
        if(a > (uintmax_t)b->value.s) return 1;
        return 0;
    case ACV_INTEGER_BYTES: {
        INTEGER_t tmp;
        int r;
        if(acv_uint_to_INTEGER(a, &tmp) != 0) return 0;
        r = acv_cmp_scalarbytes_vs_cvalbytes(&tmp, b);
        if(tmp.buf) FREEMEM(tmp.buf);
        return r;
    }
    case ACV_ABSENT:
    default:
        return 0;
    }
}

int
asn_cval_cmp_sint(intmax_t a, const asn_cval_t *b) {
    switch(b->kind) {
    case ACV_SINT:
        if(a < b->value.s) return -1;
        if(a > b->value.s) return 1;
        return 0;
    case ACV_UINT:
        if(a < 0) return -1;                          /* a < 0 <= b */
        if((uintmax_t)a < b->value.u) return -1;
        if((uintmax_t)a > b->value.u) return 1;
        return 0;
    case ACV_INTEGER_BYTES: {
        INTEGER_t tmp;
        int r;
        if(acv_sint_to_INTEGER(a, &tmp) != 0) return 0;
        r = acv_cmp_scalarbytes_vs_cvalbytes(&tmp, b);
        if(tmp.buf) FREEMEM(tmp.buf);
        return r;
    }
    case ACV_ABSENT:
    default:
        return 0;
    }
}

/* Convert a cval scalar into canonical content octets in *tmp. */
static int
acv_to_INTEGER(const asn_cval_t *v, INTEGER_t *tmp, int *materialized) {
    *materialized = 0;
    switch(v->kind) {
    case ACV_SINT:
        if(acv_sint_to_INTEGER(v->value.s, tmp) != 0) return -1;
        *materialized = 1;
        return 0;
    case ACV_UINT:
        if(acv_uint_to_INTEGER(v->value.u, tmp) != 0) return -1;
        *materialized = 1;
        return 0;
    case ACV_INTEGER_BYTES:
        /* alias the static bytes; do not free */
        tmp->buf = (uint8_t *)v->value.b.buf;
        tmp->size = v->value.b.size;
        return 0;
    case ACV_ABSENT:
    default:
        return -1;
    }
}

int
asn_cval_cmp(const asn_cval_t *a, const asn_cval_t *b) {
    /* Fast scalar paths */
    if(a->kind == ACV_SINT) return asn_cval_cmp_sint(a->value.s, b);
    if(a->kind == ACV_UINT) return asn_cval_cmp_uint(a->value.u, b);
    if(a->kind == ACV_INTEGER_BYTES) {
        INTEGER_t tb;
        int mat = 0, r;
        if(b->kind == ACV_INTEGER_BYTES)
            return acv_cmp_bytes(a->value.b.buf, a->value.b.size,
                                 b->value.b.buf, b->value.b.size);
        if(acv_to_INTEGER(b, &tb, &mat) != 0) return 0;
        r = acv_cmp_bytes(a->value.b.buf, a->value.b.size, tb.buf, tb.size);
        if(mat && tb.buf) FREEMEM(tb.buf);
        return r;
    }
    return 0;
}

/* ===== INTEGER_t vs cval ===== */

int
asn_INTEGER_cmp_cval(const INTEGER_t *a, const asn_cval_t *b,
                     int a_is_unsigned) {
    /* Try the scalar fast paths first. */
    if(a_is_unsigned) {
        uintmax_t uv;
        if(asn_INTEGER2umax(a, &uv) == 0)
            return asn_cval_cmp_uint(uv, b);
    } else {
        intmax_t sv;
        if(asn_INTEGER2imax(a, &sv) == 0)
            return asn_cval_cmp_sint(sv, b);
    }
    /* Value does not fit a native scalar: compare canonical octets. */
    {
        INTEGER_t tb;
        int mat = 0, r;
        if(b->kind == ACV_INTEGER_BYTES) {
            return acv_cmp_bytes(a->buf, a->size,
                                 b->value.b.buf, b->value.b.size);
        }
        if(acv_to_INTEGER(b, &tb, &mat) != 0) return 0;
        r = acv_cmp_bytes(a->buf, a->size, tb.buf, tb.size);
        if(mat && tb.buf) FREEMEM(tb.buf);
        return r;
    }
}

/* ===== range checks ===== */

int
asn_check_integer_range_sint(intmax_t value,
                             const asn_cval_t *lb, const asn_cval_t *ub) {
    if(lb && lb->kind != ACV_ABSENT && asn_cval_cmp_sint(value, lb) < 0)
        return -1;
    if(ub && ub->kind != ACV_ABSENT && asn_cval_cmp_sint(value, ub) > 0)
        return -1;
    return 0;
}

int
asn_check_integer_range_uint(uintmax_t value,
                             const asn_cval_t *lb, const asn_cval_t *ub) {
    if(lb && lb->kind != ACV_ABSENT && asn_cval_cmp_uint(value, lb) < 0)
        return -1;
    if(ub && ub->kind != ACV_ABSENT && asn_cval_cmp_uint(value, ub) > 0)
        return -1;
    return 0;
}

int
asn_check_INTEGER_range(const INTEGER_t *value,
                        const asn_cval_t *lb, const asn_cval_t *ub,
                        int value_is_unsigned) {
    if(lb && lb->kind != ACV_ABSENT
       && asn_INTEGER_cmp_cval(value, lb, value_is_unsigned) < 0)
        return -1;
    if(ub && ub->kind != ACV_ABSENT
       && asn_INTEGER_cmp_cval(value, ub, value_is_unsigned) > 0)
        return -1;
    return 0;
}

/* ===== v2 range arithmetic ===== */

/* Extract a scalar bound as a uintmax_t offset from 0; returns 0 on success.
 * For ACV_INTEGER_BYTES (beyond uintmax) returns -1 (caller treats as big). */
static int
acv_as_imax(const asn_cval_t *v, intmax_t *out) {
    switch(v->kind) {
    case ACV_SINT: *out = v->value.s; return 0;
    case ACV_UINT:
        if(v->value.u > (uintmax_t)INTMAX_MAX) return -1;
        *out = (intmax_t)v->value.u; return 0;
    default: return -1;
    }
}

int
asn_cval_compute_range(const asn_cval_t *lb, const asn_cval_t *ub,
                       asn_range_info_t *out) {
    intmax_t l, u;
    uintmax_t range_minus_1;
    int bits;

    if(!out) return -1;
    out->kind = ASN_RANGE_UNCONSTRAINED;
    out->u64_range = 0;
    out->range_bits = -1;
    out->effective_bits = -1;

    if(!lb || !ub || lb->kind == ACV_ABSENT || ub->kind == ACV_ABSENT)
        return -1;   /* open range: unconstrained for this helper */

    /* Big bounds are out of scope for the native fast path. */
    if(lb->kind == ACV_INTEGER_BYTES || ub->kind == ACV_INTEGER_BYTES) {
        out->kind = ASN_RANGE_BIG;
        return -1;
    }

    /*
     * Compute (ub - lb) as an unsigned magnitude without overflow.  Both
     * bounds fit intmax_t here (UINT bounds above INTMAX_MAX are rare for
     * native ranges; if encountered, fall back to big).
     */
    if(ub->kind == ACV_UINT && lb->kind == ACV_UINT) {
        if(ub->value.u < lb->value.u) return -1;
        range_minus_1 = ub->value.u - lb->value.u;
    } else if(acv_as_imax(lb, &l) == 0 && acv_as_imax(ub, &u) == 0) {
        if(u < l) return -1;
        /* u - l fits uintmax_t even across the sign boundary */
        range_minus_1 = (uintmax_t)u - (uintmax_t)l;
    } else {
        out->kind = ASN_RANGE_BIG;
        return -1;
    }

    /* range = range_minus_1 + 1; guard the all-ones case. */
    if(range_minus_1 == UINTMAX_MAX) {
        out->kind = ASN_RANGE_BIG;   /* range == 2^64, not representable in u64 */
        return -1;
    }
    out->u64_range = (uint64_t)(range_minus_1 + 1);
    out->kind = ASN_RANGE_NATIVE_U64;

    /* bits = ceil(log2(range)) computed from range_minus_1 */
    bits = 0;
    {
        uintmax_t v = range_minus_1;   /* values 0..range-1 need this many bits */
        while(v) { bits++; v >>= 1; }
    }
    out->range_bits = bits;
    out->effective_bits = bits;
    return 0;
}
