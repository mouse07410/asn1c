/*
 * Unsigned INTEGER_t: identical to INTEGER_t but asn_DEF_UInteger carries
 * field_unsigned=1 in its specifics.  Used for INTEGER (low..high) where
 * low >= 0 and high > INT64_MAX (value fits in uint64_t but not int64_t).
 */
#ifndef _UINTEGER_H_
#define _UINTEGER_H_

#include <INTEGER.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef INTEGER_t UInteger_t;

extern asn_TYPE_descriptor_t asn_DEF_UInteger;

#ifdef __cplusplus
}
#endif

#endif  /* _UINTEGER_H_ */
