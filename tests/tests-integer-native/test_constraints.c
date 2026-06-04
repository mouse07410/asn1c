/*
 * Fixed-width round-trip and constraint-enforcement tests, compiled against
 * the oversized-integers module generated with -finteger-native-type=uint64.
 *
 * Under uint64 mode the storage types are:
 *   T1 (0..255)            uint64_t
 *   T3 (0..2^32-1)         uint64_t
 *   T4 (0..2^63-1)         uint64_t
 *   T5 (0..2^64-1)         uint64_t
 *   T6 (2^64-6..2^64-1)    uint64_t
 *   T7 (0..2^64)           INTEGER_t   (exceeds uint64 -> arbitrary precision)
 *   T8 (-2^64..2^64)       INTEGER_t
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "T1.h"
#include "T4.h"
#include "T5.h"
#include "T6.h"
#include "T7.h"
#include "T8.h"

static int fails = 0;
#define CK(name, cond) do { \
    if(!(cond)) { printf("FAIL: %s\n", name); fails++; } \
    else printf("ok: %s\n", name); } while(0)

static int co(const asn_TYPE_descriptor_t *td, const void *s) {
    char eb[256]; size_t el = sizeof eb;
    return asn_check_constraints(td, s, eb, &el) == 0;
}

/* BER + UPER round-trip through a uint64_t-backed native member. */
static int rt_u64(const asn_TYPE_descriptor_t *td, uint64_t v) {
    uint64_t in = v; void *o = 0; uint8_t b[64];
    asn_enc_rval_t er = der_encode_to_buffer(td, &in, b, sizeof b);
    if(er.encoded < 0) return 1;
    asn_dec_rval_t dr = ber_decode(0, td, &o, b, er.encoded);
    int ok = (dr.code == RC_OK && o && *(uint64_t *)o == v);
    if(o) ASN_STRUCT_FREE(*td, o);
    if(!ok) return 2;
    o = 0; er = uper_encode_to_buffer(td, 0, &in, b, sizeof b);
    if(er.encoded < 0) return 3;
    dr = uper_decode_complete(0, td, &o, b, (er.encoded + 7) / 8);
    ok = (dr.code == RC_OK && o && *(uint64_t *)o == v);
    if(o) ASN_STRUCT_FREE(*td, o);
    return ok ? 0 : 4;
}

int main(void) {
    /* T5 = INTEGER (0..UINT64_MAX), uint64_t */
    CK("T5 UPER+BER 0", rt_u64(&asn_DEF_T5, 0) == 0);
    CK("T5 UPER+BER UINT64_MAX", rt_u64(&asn_DEF_T5, 18446744073709551615ULL) == 0);
    CK("T5 UPER+BER 2^63", rt_u64(&asn_DEF_T5, 9223372036854775808ULL) == 0);
    { uint64_t v = 18446744073709551615ULL; CK("T5 MAX in-range", co(&asn_DEF_T5, &v)); }

    /* T6 = INTEGER (2^64-6 .. 2^64-1), uint64_t */
    CK("T6 UPER+BER lb", rt_u64(&asn_DEF_T6, 18446744073709551610ULL) == 0);
    CK("T6 UPER+BER ub", rt_u64(&asn_DEF_T6, 18446744073709551615ULL) == 0);
    { uint64_t v = 18446744073709551609ULL; CK("T6 below-lb rejected", !co(&asn_DEF_T6, &v)); }
    { uint64_t v = 0; CK("T6 zero rejected", !co(&asn_DEF_T6, &v)); }

    /* T1 = INTEGER (0..255), uint64_t */
    CK("T1 UPER+BER 255", rt_u64(&asn_DEF_T1, 255) == 0);
    { uint64_t v = 256; CK("T1 256 rejected", !co(&asn_DEF_T1, &v)); }

    /* T4 = INTEGER (0..2^63-1), uint64_t */
    CK("T4 UPER+BER INT64_MAX", rt_u64(&asn_DEF_T4, 9223372036854775807ULL) == 0);

    /* T7 = INTEGER (0..2^64), INTEGER_t (oversized upper bound) */
    { INTEGER_t s; memset(&s, 0, sizeof s); asn_umax2INTEGER(&s, 18446744073709551615ULL);
      CK("T7 UINT64_MAX in-range", co(&asn_DEF_T7, &s)); free(s.buf); }
    { INTEGER_t s; uint8_t b[] = {0x01,0,0,0,0,0,0,0,0x01}; memset(&s,0,sizeof s);
      s.buf = malloc(9); memcpy(s.buf, b, 9); s.size = 9;
      CK("T7 2^64+1 rejected", !co(&asn_DEF_T7, &s)); free(s.buf); }
    { INTEGER_t s; memset(&s, 0, sizeof s); asn_imax2INTEGER(&s, -1);
      CK("T7 -1 rejected", !co(&asn_DEF_T7, &s)); free(s.buf); }

    /* T8 = INTEGER (-2^64..2^64), INTEGER_t */
    { INTEGER_t s; memset(&s, 0, sizeof s); asn_imax2INTEGER(&s, 0);
      CK("T8 0 in-range", co(&asn_DEF_T8, &s)); free(s.buf); }
    { INTEGER_t s; uint8_t b[] = {0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}; memset(&s,0,sizeof s);
      s.buf = malloc(9); memcpy(s.buf, b, 9); s.size = 9;
      CK("T8 -2^64-1 rejected", !co(&asn_DEF_T8, &s)); free(s.buf); }

    printf(fails ? "\n%d FAILURES\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
