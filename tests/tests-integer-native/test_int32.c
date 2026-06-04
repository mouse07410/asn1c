/*
 * Fixed-width round-trip and constraint-enforcement tests for int32_t native
 * storage, compiled against the oversized-integers module generated with
 * -finteger-native-type=int32.
 *
 * Under int32 mode:  T1 (0..255) and T2 (-2^31..2^31-1) are int32_t;
 * wider/unsigned-overflowing types fall back to INTEGER_t.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "T1.h"
#include "T2.h"

static int fails = 0;
#define CK(name, cond) do { \
    if(!(cond)) { printf("FAIL: %s\n", name); fails++; } \
    else printf("ok: %s\n", name); } while(0)

static int co(const asn_TYPE_descriptor_t *td, const void *s) {
    char eb[256]; size_t el = sizeof eb;
    return asn_check_constraints(td, s, eb, &el) == 0;
}

/* BER + UPER round-trip through an int32_t-backed native member. */
static int rt_i32(const asn_TYPE_descriptor_t *td, int32_t v) {
    int32_t in = v; void *o = 0; uint8_t b[64];
    asn_enc_rval_t er = der_encode_to_buffer(td, &in, b, sizeof b);
    if(er.encoded < 0) return 1;
    asn_dec_rval_t dr = ber_decode(0, td, &o, b, er.encoded);
    int ok = (dr.code == RC_OK && o && *(int32_t *)o == v);
    if(o) ASN_STRUCT_FREE(*td, o);
    if(!ok) return 2;
    o = 0; er = uper_encode_to_buffer(td, 0, &in, b, sizeof b);
    if(er.encoded < 0) return 3;
    dr = uper_decode_complete(0, td, &o, b, (er.encoded + 7) / 8);
    ok = (dr.code == RC_OK && o && *(int32_t *)o == v);
    if(o) ASN_STRUCT_FREE(*td, o);
    return ok ? 0 : 4;
}

int main(void) {
    /* T1 = INTEGER (0..255), int32_t */
    CK("T1 int32 round-trip 0",   rt_i32(&asn_DEF_T1, 0)   == 0);
    CK("T1 int32 round-trip 255", rt_i32(&asn_DEF_T1, 255) == 0);
    { int32_t v = 256; CK("T1 256 rejected", !co(&asn_DEF_T1, &v)); }
    { int32_t v = -1;  CK("T1 -1 rejected",  !co(&asn_DEF_T1, &v)); }

    /* T2 = INTEGER (-2^31..2^31-1), int32_t */
    CK("T2 int32 round-trip INT32_MAX", rt_i32(&asn_DEF_T2, 2147483647) == 0);
    CK("T2 int32 round-trip INT32_MIN", rt_i32(&asn_DEF_T2, (-2147483647 - 1)) == 0);
    CK("T2 int32 round-trip 0",         rt_i32(&asn_DEF_T2, 0) == 0);

    printf(fails ? "\n%d FAILURES\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
