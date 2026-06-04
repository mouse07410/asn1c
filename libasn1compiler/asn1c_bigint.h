/*
 * Arbitrary-precision (big-endian magnitude) integer support for the
 * asn1c code generator.
 *
 * This is a small, dependency-free helper used to represent ASN.1 INTEGER
 * literals and constraint bounds whose magnitude may exceed the native
 * scalar types (long / intmax_t / uintmax_t) of the host or target.  It is
 * deliberately minimal: just enough to parse decimal literals, classify
 * whether they fit common native widths, render canonical two's-complement
 * INTEGER content octets, and compare/subtract bounds for range arithmetic.
 *
 * No heavyweight dependency (e.g. GMP) is introduced.
 */
#ifndef ASN1C_BIGINT_H
#define ASN1C_BIGINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A signed arbitrary precision integer, stored as a sign flag plus a
 * big-endian magnitude with no leading zero octets (the canonical form for
 * zero is negative==0 and mag_size==0).
 */
typedef struct asn1c_bigint_s {
    int negative;       /* 1 if the value is strictly negative */
    uint8_t *mag;       /* big-endian magnitude, no leading zeroes; may be NULL when mag_size==0 */
    size_t mag_size;    /* number of significant magnitude octets */
} asn1c_bigint_t;

/* Release memory held by *v and reset it to the canonical zero. */
void asn1c_bigint_free(asn1c_bigint_t *v);

/*
 * Parse a base-10 ASCII integer literal (optionally prefixed with '+' or
 * '-') into *out.  Leading/trailing ASCII whitespace is tolerated.
 * Returns 0 on success, -1 on malformed input or allocation failure.
 * On success the caller owns *out and must release it with
 * asn1c_bigint_free().
 */
int asn1c_bigint_from_decimal(const char *text, asn1c_bigint_t *out);

/* Comparison: returns <0, 0, >0 for a<b, a==b, a>b. */
int asn1c_bigint_cmp(const asn1c_bigint_t *a, const asn1c_bigint_t *b);

/*
 * Fit tests.  Each returns 1 and (when out != NULL) stores the value if it
 * fits the target type, otherwise returns 0.
 */
int asn1c_bigint_fits_intmax(const asn1c_bigint_t *v, intmax_t *out);
int asn1c_bigint_fits_uintmax(const asn1c_bigint_t *v, uintmax_t *out);
int asn1c_bigint_fits_int64(const asn1c_bigint_t *v, int64_t *out);
int asn1c_bigint_fits_uint64(const asn1c_bigint_t *v, uint64_t *out);

/*
 * Render canonical ASN.1 INTEGER content octets (big-endian two's
 * complement, minimal length) into a freshly malloc'd buffer.
 *   - zero            -> single octet 0x00
 *   - positive values -> magnitude, with a leading 0x00 prepended when the
 *                        top bit of the first octet would otherwise be set;
 *   - negative values -> minimal two's-complement representation.
 * Returns 0 on success (caller frees *buf), -1 on allocation failure.
 */
int asn1c_bigint_to_integer_content_octets(const asn1c_bigint_t *v,
                                           uint8_t **buf, size_t *size);

/*
 * Compute range = (ub - lb) + 1 for lb <= ub.  Used by PER/OER range
 * arithmetic.  Returns 0 on success (caller frees *range via
 * asn1c_bigint_free), -1 if lb > ub or on allocation failure.
 */
int asn1c_bigint_subtract_range_plus_one(const asn1c_bigint_t *lb,
                                         const asn1c_bigint_t *ub,
                                         asn1c_bigint_t *range);

#ifdef __cplusplus
}
#endif

#endif /* ASN1C_BIGINT_H */
