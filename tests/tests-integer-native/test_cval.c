/*
 * Unit tests for the asn_cval_t runtime helpers (skeletons/asn_constraint_value.c)
 * and the asn_ulong2INTEGER() unsigned-conversion fix.
 *
 * Compiled against a generated output directory (see run.sh), which contains
 * asn_constraint_value.{c,h} and INTEGER.c.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include "asn_constraint_value.h"

static int fails = 0;
#define CK(name, cond) do { \
    if(!(cond)) { printf("FAIL: %s\n", name); fails++; } \
    else printf("ok: %s\n", name); } while(0)

static const uint8_t U64MAX[] = {0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
static const uint8_t TWO64[]  = {0x01,0,0,0,0,0,0,0,0};

int main(void) {
    /* asn_ulong2INTEGER must keep ULONG_MAX positive (not -1). */
    { INTEGER_t st; uintmax_t out=0; intmax_t sv;
      memset(&st,0,sizeof st);
      CK("ulong2INTEGER ok", asn_ulong2INTEGER(&st, ULONG_MAX)==0);
      CK("ulong2INTEGER->umax", asn_INTEGER2umax(&st,&out)==0 && out==(uintmax_t)ULONG_MAX);
      CK("ULONG_MAX not signed -1", !(asn_INTEGER2imax(&st,&sv)==0 && sv==-1));
      free(st.buf); }

    asn_cval_t ub_u64 = { ACV_UINT, { .u = (uintmax_t)18446744073709551615ULL } };
    asn_cval_t lb0    = { ACV_UINT, { .u = 0 } };
    asn_cval_t neg1   = { ACV_SINT, { .s = -1 } };
    asn_cval_t ub_big = { ACV_INTEGER_BYTES, { .b = { TWO64, sizeof TWO64 } } };
    asn_cval_t absent = { ACV_ABSENT, { .s = 0 } };

    CK("UINT64_MAX==UINT64_MAX", asn_cval_cmp_uint(18446744073709551615ULL,&ub_u64)==0);
    CK("0<UINT64_MAX", asn_cval_cmp_uint(0,&ub_u64)<0);
    CK("0>(sint)-1", asn_cval_cmp_uint(0,&neg1)>0);
    CK("UINT64_MAX vs -1 distinguished", asn_cval_cmp(&ub_u64,&neg1)>0);
    CK("in-range 0", asn_check_integer_range_uint(0,&lb0,&ub_u64)==0);
    CK("in-range MAX", asn_check_integer_range_uint(18446744073709551615ULL,&lb0,&ub_u64)==0);
    CK("in-range mid", asn_check_integer_range_uint(9223372036854775808ULL,&lb0,&ub_u64)==0);
    CK("UINT64_MAX < 2^64(bytes)", asn_cval_cmp_uint(18446744073709551615ULL,&ub_big)<0);
    CK("range 0..2^64 accepts UINT64_MAX", asn_check_integer_range_uint(18446744073709551615ULL,&lb0,&ub_big)==0);

    { INTEGER_t v; asn_cval_t ub_u64bytes = { ACV_INTEGER_BYTES, { .b = { U64MAX, sizeof U64MAX } } };
      memset(&v,0,sizeof v); asn_umax2INTEGER(&v,18446744073709551615ULL);
      CK("INTEGER UINT64_MAX == bytes UINT64_MAX", asn_INTEGER_cmp_cval(&v,&ub_u64bytes,1)==0);
      CK("INTEGER UINT64_MAX < bytes 2^64", asn_INTEGER_cmp_cval(&v,&ub_big,1)<0);
      free(v.buf); }

    CK("absent lower ok", asn_check_integer_range_uint(0,&absent,&ub_u64)==0);

    /* v2 range arithmetic */
    { asn_cval_t lb={ACV_UINT,{.u=18446744073709551610ULL}}, ub={ACV_UINT,{.u=18446744073709551615ULL}};
      asn_range_info_t ri;
      CK("range T6: 6/3bits", asn_cval_compute_range(&lb,&ub,&ri)==0 && ri.u64_range==6 && ri.range_bits==3); }
    { asn_cval_t lb={ACV_UINT,{.u=0}}, ub={ACV_UINT,{.u=255}}; asn_range_info_t ri;
      CK("range 0..255: 256/8bits", asn_cval_compute_range(&lb,&ub,&ri)==0 && ri.u64_range==256 && ri.range_bits==8); }
    { asn_cval_t lb={ACV_UINT,{.u=0}}, ub={ACV_INTEGER_BYTES,{.b={TWO64,sizeof TWO64}}}; asn_range_info_t ri;
      CK("range big -> BIG", asn_cval_compute_range(&lb,&ub,&ri)==-1 && ri.kind==ASN_RANGE_BIG); }

    printf(fails ? "\n%d FAILURES\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
