/*
 * BER round-trip for SeqOfU64Max (SEQUENCE OF INTEGER (0..18446744073709551615)).
 * FL_FITS_UNSIGN extended to ULONG_MAX: elements stored as native unsigned long.
 */
#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <SeqOfU64Max.h>

/* DER encoding of SeqOfU64Max containing { 0, UINT64_MAX }:
 * UINT64_MAX = 18446744073709551615 = 0xFFFFFFFFFFFFFFFF
 * DER INTEGER UINT64_MAX: 0x02 0x09 0x00 0xFF*8 (needs 0x00 pad for sign)
 */
static uint8_t der_input[] = {
    0x30, 0x0e,                                                 /* SEQUENCE OF, length 14 */
    0x02, 0x01, 0x00,                                           /* INTEGER 0 */
    0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff  /* INTEGER UINT64_MAX */
};

static uint8_t enc_buf[64];
static size_t  enc_pos;

static int
enc_cb(const void *buf, size_t size, void *key) {
    (void)key;
    assert(enc_pos + size <= sizeof(enc_buf));
    memcpy(enc_buf + enc_pos, buf, size);
    enc_pos += size;
    return 0;
}

int
main(int ac, char **av) {
    SeqOfU64Max_t *seq = NULL;
    asn_dec_rval_t drv;
    asn_enc_rval_t erv;

    (void)ac; (void)av;

    drv = ber_decode(0, &asn_DEF_SeqOfU64Max, (void **)&seq,
                     der_input, sizeof(der_input));
    assert(drv.code == RC_OK);
    assert(drv.consumed == sizeof(der_input));

    assert(seq->list.count == 2);
    assert(*(unsigned long *)seq->list.array[0] == 0UL);
    assert(*(unsigned long *)seq->list.array[1] == UINT64_MAX);

    enc_pos = 0;
    erv = der_encode(&asn_DEF_SeqOfU64Max, seq, enc_cb, NULL);
    assert(erv.encoded == (ssize_t)sizeof(der_input));
    assert(memcmp(enc_buf, der_input, sizeof(der_input)) == 0);

    ASN_STRUCT_FREE(asn_DEF_SeqOfU64Max, seq);
    printf("check-206: SeqOfU64Max BER round-trip OK\n");
    return 0;
}
