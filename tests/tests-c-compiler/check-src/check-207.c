/*
 * BER round-trip for SetOfUInt32 (SET OF INTEGER (0..4294967295)).
 * SET OF uses tag 0x31; elements stored as native unsigned long.
 */
#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <SetOfUInt32.h>

/* DER encoding of SetOfUInt32 containing { 0, 4294967295 } */
static uint8_t der_input[] = {
    0x31, 0x0a,                               /* SET OF, length 10 */
    0x02, 0x01, 0x00,                         /* INTEGER 0 */
    0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff  /* INTEGER 4294967295 */
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
    SetOfUInt32_t *seq = NULL;
    asn_dec_rval_t drv;
    asn_enc_rval_t erv;

    (void)ac; (void)av;

    drv = ber_decode(0, &asn_DEF_SetOfUInt32, (void **)&seq,
                     der_input, sizeof(der_input));
    assert(drv.code == RC_OK);
    assert(drv.consumed == sizeof(der_input));

    assert(seq->list.count == 2);
    assert(*(unsigned long *)seq->list.array[0] == 0UL);
    assert(*(unsigned long *)seq->list.array[1] == 4294967295UL);

    enc_pos = 0;
    erv = der_encode(&asn_DEF_SetOfUInt32, seq, enc_cb, NULL);
    assert(erv.encoded == (ssize_t)sizeof(der_input));
    assert(memcmp(enc_buf, der_input, sizeof(der_input)) == 0);

    ASN_STRUCT_FREE(asn_DEF_SetOfUInt32, seq);
    printf("check-207: SetOfUInt32 BER round-trip OK\n");
    return 0;
}
