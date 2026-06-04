/*
 * Unit tests for the compiler-internal arbitrary-precision integer helpers
 * (libasn1compiler/asn1c_bigint.c).  Compile standalone:
 *
 *   cc -I../../libasn1compiler test_bigint.c ../../libasn1compiler/asn1c_bigint.c -o test_bigint
 *   ./test_bigint
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "asn1c_bigint.h"

static int fails = 0;
#define CK(name, cond) do { \
    if(!(cond)) { printf("FAIL: %s\n", name); fails++; } \
    else printf("ok: %s\n", name); } while(0)

static void
octets_eq(const char *name, const char *dec, const uint8_t *exp, size_t n) {
    asn1c_bigint_t b;
    uint8_t *buf;
    size_t sz, i;
    int ok;
    if(asn1c_bigint_from_decimal(dec, &b)) { printf("FAIL parse %s\n", name); fails++; return; }
    if(asn1c_bigint_to_integer_content_octets(&b, &buf, &sz)) { printf("FAIL oct %s\n", name); fails++; asn1c_bigint_free(&b); return; }
    ok = (sz == n && memcmp(buf, exp, n) == 0);
    if(!ok) { printf("FAIL: %s octets got [", name); for(i=0;i<sz;i++) printf("%02x ", buf[i]); printf("]\n"); fails++; }
    else printf("ok: %s octets\n", name);
    free(buf);
    asn1c_bigint_free(&b);
}

int main(void) {
    asn1c_bigint_t b;
    uintmax_t um; intmax_t im; uint64_t u64; int64_t i64;

    octets_eq("zero", "0", (uint8_t[]){0x00}, 1);
    octets_eq("127", "127", (uint8_t[]){0x7f}, 1);
    octets_eq("128", "128", (uint8_t[]){0x00,0x80}, 2);
    octets_eq("255", "255", (uint8_t[]){0x00,0xff}, 2);
    octets_eq("256", "256", (uint8_t[]){0x01,0x00}, 2);
    octets_eq("neg1", "-1", (uint8_t[]){0xff}, 1);
    octets_eq("neg128", "-128", (uint8_t[]){0x80}, 1);
    octets_eq("neg129", "-129", (uint8_t[]){0xff,0x7f}, 2);
    octets_eq("neg256", "-256", (uint8_t[]){0xff,0x00}, 2);
    octets_eq("uint64max", "18446744073709551615",
              (uint8_t[]){0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, 9);
    octets_eq("two64", "18446744073709551616",
              (uint8_t[]){0x01,0,0,0,0,0,0,0,0}, 9);

    asn1c_bigint_from_decimal("18446744073709551615", &b);
    CK("u64max fits_uint64", asn1c_bigint_fits_uint64(&b,&u64) && u64==UINT64_MAX);
    CK("u64max !fits_int64", !asn1c_bigint_fits_int64(&b,&i64));
    CK("u64max fits_uintmax", asn1c_bigint_fits_uintmax(&b,&um) && um==UINT64_MAX);
    CK("u64max !fits_intmax", !asn1c_bigint_fits_intmax(&b,&im));
    asn1c_bigint_free(&b);

    asn1c_bigint_from_decimal("18446744073709551616", &b);
    CK("2^64 !fits_uint64", !asn1c_bigint_fits_uint64(&b,&u64));
    asn1c_bigint_free(&b);

    asn1c_bigint_from_decimal("-9223372036854775808", &b);
    CK("int64min fits_int64", asn1c_bigint_fits_int64(&b,&i64) && i64==INT64_MIN);
    asn1c_bigint_free(&b);

    { asn1c_bigint_t a,c; asn1c_bigint_from_decimal("-1",&a); asn1c_bigint_from_decimal("1",&c);
      CK("cmp -1<1", asn1c_bigint_cmp(&a,&c)<0); asn1c_bigint_free(&a); asn1c_bigint_free(&c); }
    { asn1c_bigint_t a,c; asn1c_bigint_from_decimal("18446744073709551615",&a);
      asn1c_bigint_from_decimal("18446744073709551610",&c);
      CK("cmp big>big", asn1c_bigint_cmp(&a,&c)>0); asn1c_bigint_free(&a); asn1c_bigint_free(&c); }

    { asn1c_bigint_t lb,ub,r;
      asn1c_bigint_from_decimal("18446744073709551610",&lb);
      asn1c_bigint_from_decimal("18446744073709551615",&ub);
      CK("range ok", asn1c_bigint_subtract_range_plus_one(&lb,&ub,&r)==0);
      CK("range==6", asn1c_bigint_fits_uint64(&r,&u64) && u64==6);
      asn1c_bigint_free(&lb); asn1c_bigint_free(&ub); asn1c_bigint_free(&r); }
    { asn1c_bigint_t lb,ub,r;
      asn1c_bigint_from_decimal("-18446744073709551616",&lb);
      asn1c_bigint_from_decimal("18446744073709551616",&ub);
      asn1c_bigint_subtract_range_plus_one(&lb,&ub,&r);
      /* 36893488147419103233 == 0x02 00..00 01 (9 octets) */
      { uint8_t exp[]={0x02,0,0,0,0,0,0,0,0x01}; uint8_t *buf; size_t sz;
        asn1c_bigint_to_integer_content_octets(&r,&buf,&sz);
        CK("range neg..pos", sz==9 && memcmp(buf,exp,9)==0); free(buf); }
      asn1c_bigint_free(&lb); asn1c_bigint_free(&ub); asn1c_bigint_free(&r); }

    CK("reject empty", asn1c_bigint_from_decimal("",&b)!=0);
    CK("reject 12a", asn1c_bigint_from_decimal("12a",&b)!=0);

    printf(fails ? "\n%d FAILURES\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
