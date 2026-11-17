#ifndef	ASN1P_INTEGER_H
#define	ASN1P_INTEGER_H

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif	/* HAVE_CONFIG_H */

#include <asn1_buffer.h>

#ifdef	HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif	/* HAVE_SYS_TYPES_H */
#ifdef	HAVE_INTTYPES_H
#include <inttypes.h>		/* POSIX 1003.1-2001, C99 */
#else	/* HAVE_INTTYPES_H */
#ifdef	HAVE_STDINT_H
#include <stdint.h>		/* SUSv2+ */
#endif	/* HAVE_STDINT_H */
#endif	/* HAVE_INTTYPES_H */

/*
 * Basic integer type used in numerous places.
 * ASN.1 does not define any limits on this number, so it must be sufficiently
 * large to accommodate typical inputs. It does not have to be a dynamically
 * allocated type with potentially unlimited width: consider the width of
 * an integer defined here as one of the "compiler limitations".
 * NOTE: this is NOT a type for ASN.1 "INTEGER" type representation, this
 * type is used by the compiler itself to handle large integer values
 * specified inside ASN.1 grammar.
 */
#ifdef  HAVE_128_BIT_INT
typedef	__int128 asn1c_integer_t;
#else
typedef	intmax_t asn1c_integer_t;
#endif

/*
 * Limits of asn1c_integer_t. Code that adjusts a range endpoint by one must
 * compare against these, not against INTMAX_MIN/INTMAX_MAX: the two agree only
 * in an intmax_t build, and in the 128-bit build the INTMAX_* guards let the
 * increment of ASN_INTEGER_MAX (or the decrement of ASN_INTEGER_MIN) through,
 * which is signed overflow.
 */
#define ASN_INTEGER_BITS (8 * sizeof(asn1c_integer_t))
/*
 * The largest value of the signed type, built without shifting into the
 * sign bit: shifting a signed 1 by (bits - 1) places is undefined because
 * the result, 2^(bits-1), is not representable. Shifting by (bits - 2)
 * keeps every intermediate value representable, and doubling into the last
 * step stays within the type.
 */
#define ASN_INTEGER_MAX \
    ((((asn1c_integer_t)1 << (ASN_INTEGER_BITS - 2)) - 1) * 2 + 1)
#define ASN_INTEGER_MIN (-(ASN_INTEGER_MAX)-1)

/* Unsigned counterpart of asn1c_integer_t, for span arithmetic. */
#ifdef HAVE_128_BIT_INT
typedef unsigned __int128 asn1c_uinteger_t;
#else
typedef uintmax_t asn1c_uinteger_t;
#endif

/* Bits needed for values [0, value], equal to ceil(log2(value + 1)). */
size_t asn1p_unsigned_bit_length(asn1c_uinteger_t value);
/* Bits needed for [left, right]: ceil(log2(count)); 0 for empty/reversed. */
size_t asn1p_range_bit_length(asn1c_integer_t left, asn1c_integer_t right);

int asn1p_atoi(const char *ptr, asn1c_integer_t *r_value);
const char *asn1p_itoa(asn1c_integer_t value);   /* Ptr to a static buf */
/*
 * Return values:
 * -1: The value did not fit in the buffer.
 * >0: The length in bytes of the stringified numeric value.
 */
int asn1p_itoa_s(char *buf, size_t size,
                 asn1c_integer_t value); /* Return -1 on error, or length. */

/*
 * Convert asn1c_integer_t into INTEGER_t structure.
 */
abuf *asn1p_integer_as_INTEGER(asn1c_integer_t value);

#endif	/* ASN1P_INTEGER_H */
