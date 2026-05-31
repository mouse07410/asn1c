/*
 * BER round-trip for SeqOf34 (SEQUENCE OF INTEGER (3..4)).
 * Elements stored as native long.
 */
#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <SeqOf34.h>

/* DER encoding of SeqOf34 containing { 3, 4 } */
static uint8_t der_input[] = {
    0x30, 0x06,             /* SEQUENCE OF, length 6 */
    0x02, 0x01, 0x03,       /* INTEGER 3 */
    0x02, 0x01, 0x04        /* INTEGER 4 */
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
    SeqOf34_t *seq = NULL;
    asn_dec_rval_t drv;
    asn_enc_rval_t erv;

    (void)ac; (void)av;

    drv = ber_decode(0, &asn_DEF_SeqOf34, (void **)&seq,
                     der_input, sizeof(der_input));
    assert(drv.code == RC_OK);
    assert(drv.consumed == sizeof(der_input));

    assert(seq->list.count == 2);
    assert(*(long *)seq->list.array[0] == 3L);
    assert(*(long *)seq->list.array[1] == 4L);

    enc_pos = 0;
    erv = der_encode(&asn_DEF_SeqOf34, seq, enc_cb, NULL);
    assert(erv.encoded == (ssize_t)sizeof(der_input));
    assert(memcmp(enc_buf, der_input, sizeof(der_input)) == 0);

    ASN_STRUCT_FREE(asn_DEF_SeqOf34, seq);
    printf("check-205: SeqOf34 BER round-trip OK\n");
    return 0;
}
