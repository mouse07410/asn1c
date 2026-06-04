/*-
 * Tagged constraint-value representation for ASN.1 INTEGER bounds.
 *
 * ASN.1 INTEGER constraint bounds may exceed the range of any signed scalar
 * (consider 18446744073709551615 == UINT64_MAX, or values beyond 2^64).
 * Storing a bound only as a signed long/intmax_t loses the distinction
 * between UINT64_MAX and -1.  This type carries each bound together with the
 * domain it must be interpreted in:
 *
 *   ACV_ABSENT        - open/unconstrained side (MIN or MAX).
 *   ACV_SINT          - fits intmax_t, interpreted as signed.
 *   ACV_UINT          - non-negative, fits uintmax_t (may exceed INTMAX_MAX).
 *   ACV_INTEGER_BYTES - exceeds native scalars; stored as canonical ASN.1
 *                       INTEGER two's-complement content octets.
 *
 * Generated constraint descriptors use static storage of this type; no heap
 * allocation is required for the bounds themselves.  Runtime helpers may
 * materialize a temporary INTEGER_t only when a comparison needs it.
 */
#ifndef ASN_CONSTRAINT_VALUE_H
#define ASN_CONSTRAINT_VALUE_H

#include <INTEGER.h>    /* INTEGER_t and conversion helpers */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum asn_cval_kind_e {
    ACV_ABSENT = 0,
    ACV_SINT,
    ACV_UINT,
    ACV_INTEGER_BYTES
} asn_cval_kind_e;

typedef struct asn_cval_bytes_s {
    const uint8_t *buf;     /* canonical INTEGER content octets */
    size_t size;
} asn_cval_bytes_t;

typedef struct asn_cval_s {
    asn_cval_kind_e kind;
    union {
        intmax_t s;
        uintmax_t u;
        asn_cval_bytes_t b;
    } value;
} asn_cval_t;

/*
 * Three-way comparisons.  Return convention:
 *   <0 : left  < right
 *    0 : left == right
 *   >0 : left  > right
 * ACV_ABSENT must not be passed to these comparison helpers; the range-check
 * helpers below handle absent (open) bounds.
 */
int asn_cval_cmp(const asn_cval_t *a, const asn_cval_t *b);
int asn_cval_cmp_sint(intmax_t a, const asn_cval_t *b);
int asn_cval_cmp_uint(uintmax_t a, const asn_cval_t *b);

/*
 * Compare an INTEGER_t against a constraint value.  a_is_unsigned indicates
 * that the INTEGER_t encodes a non-negative value whose magnitude may exceed
 * INTMAX_MAX (e.g. a uint64_t-backed field round-tripped through INTEGER_t).
 */
int asn_INTEGER_cmp_cval(const INTEGER_t *a, const asn_cval_t *b,
                         int a_is_unsigned);

/*
 * Range membership checks.  An ACV_ABSENT bound denotes an open side.
 * Return 0 if value is within [lb, ub], non-zero (-1) if out of range.
 */
int asn_check_integer_range_sint(intmax_t value,
                                 const asn_cval_t *lb, const asn_cval_t *ub);
int asn_check_integer_range_uint(uintmax_t value,
                                 const asn_cval_t *lb, const asn_cval_t *ub);
int asn_check_INTEGER_range(const INTEGER_t *value,
                            const asn_cval_t *lb, const asn_cval_t *ub,
                            int value_is_unsigned);

/* ===================================================================
 * v2 integer constraint descriptor (additive; ABI-compatible).
 *
 * The legacy asn_per_constraint_t stores bounds as intmax_t, which cannot
 * represent UINT64_MAX (it aliases to -1) or values beyond 64 bits.  This
 * substructure carries bounds as asn_cval_t so PER/OER descriptors can
 * describe unsigned-native and oversized ranges without wraparound.  It is
 * defined here as shared infrastructure; encode/decode paths may adopt it
 * incrementally alongside the existing asn_per_constraint_t.
 * =================================================================== */
typedef struct asn_integer_constraint_s {
    asn_cval_t lower_bound;
    asn_cval_t upper_bound;
    int range_bits;             /* ceil(log2(range)); -1 if not applicable */
    int effective_bits;         /* effective per-element bits; -1 if N/A */
    unsigned range_is_native:1; /* range fits uint64_t */
    unsigned range_is_big:1;    /* range exceeds uint64_t */
} asn_integer_constraint_t;

typedef enum asn_range_kind_e {
    ASN_RANGE_UNCONSTRAINED,
    ASN_RANGE_NATIVE_U64,
    ASN_RANGE_BIG
} asn_range_kind_e;

typedef struct asn_range_info_s {
    asn_range_kind_e kind;
    uint64_t u64_range;         /* valid when kind == ASN_RANGE_NATIVE_U64 */
    int range_bits;
    int effective_bits;
} asn_range_info_t;

/*
 * Compute range = (upper_bound - lower_bound) + 1 and the number of bits
 * required to encode it, without overflow, for scalar bounds.  This is the
 * safe PER/OER range arithmetic for the common (native) case: it succeeds
 * (returns 0) when both bounds are concrete and the resulting range fits
 * uint64_t, filling *out; otherwise it reports ASN_RANGE_BIG / returns -1.
 */
int asn_cval_compute_range(const asn_cval_t *lb, const asn_cval_t *ub,
                           asn_range_info_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ASN_CONSTRAINT_VALUE_H */
