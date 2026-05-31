/*
 * UPER round-trip for SeqOf34 (SEQUENCE OF INTEGER (3..4)).
 * Elements stored as native long; PER range [3..4] = 1 bit per element.
 */
#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <SeqOf34.h>

/* UPER encoding of SeqOf34 containing { 3, 4 }:
 * 0x02  -- 2 elements
 * 0x40  -- element 3: (3-3)=0 -> bit 0; element 4: (4-3)=1 -> bit 1
 *          (bits: 01xxxxxx = 0x40)
 */
static uint8_t uper_expected[] = { 0x02, 0x40 };

int
main(int ac, char **av) {
    SeqOf34_t enc_seq;
    SeqOf34_t *dec_seq = NULL;
    asn_enc_rval_t erv;
    asn_dec_rval_t drv;
    uint8_t enc_buf[sizeof(uper_expected)];

    (void)ac; (void)av;

    long *v3 = malloc(sizeof(long));
    long *v4 = malloc(sizeof(long));
    assert(v3 && v4);
    *v3 = 3;
    *v4 = 4;

    memset(&enc_seq, 0, sizeof(enc_seq));
    ASN_SEQUENCE_ADD(&enc_seq.list, v3);
    ASN_SEQUENCE_ADD(&enc_seq.list, v4);

    erv = uper_encode_to_buffer(&asn_DEF_SeqOf34, 0, &enc_seq,
                                enc_buf, sizeof(enc_buf));
    /* 8 bits (count=2) + 1 bit (value 3) + 1 bit (value 4) = 10 bits */
    assert(erv.encoded == 10);
    assert(memcmp(enc_buf, uper_expected, sizeof(uper_expected)) == 0);

    drv = uper_decode(0, &asn_DEF_SeqOf34, (void **)&dec_seq,
                      enc_buf, sizeof(enc_buf), 0, 0);
    assert(drv.code == RC_OK);
    assert(dec_seq->list.count == 2);
    assert(*(long *)dec_seq->list.array[0] == 3L);
    assert(*(long *)dec_seq->list.array[1] == 4L);

    ASN_STRUCT_RESET(asn_DEF_SeqOf34, &enc_seq);
    ASN_STRUCT_FREE(asn_DEF_SeqOf34, dec_seq);
    printf("check-205.-gen-UPER: SeqOf34 UPER round-trip OK\n");
    return 0;
}
