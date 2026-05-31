/*
 * UPER round-trip for SeqOfUInt32 (SEQUENCE OF INTEGER (0..4294967295)).
 * Elements stored as native unsigned long.
 */
#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <SeqOfUInt32.h>

/* UPER encoding of SeqOfUInt32 containing { 0, 4294967295 }:
 * 0x02               -- 2 elements (length determinant)
 * 0x00 0x00 0x00 0x00 -- element 0  (32 bits)
 * 0xFF 0xFF 0xFF 0xFF  -- element 4294967295 (32 bits)
 */
static uint8_t uper_expected[] = {
    0x02,
    0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF
};

int
main(int ac, char **av) {
    SeqOfUInt32_t enc_seq;
    SeqOfUInt32_t *dec_seq = NULL;
    asn_enc_rval_t erv;
    asn_dec_rval_t drv;
    uint8_t enc_buf[sizeof(uper_expected)];

    (void)ac; (void)av;

    /* build list with heap-allocated elements */
    unsigned long *v0 = malloc(sizeof(unsigned long));
    unsigned long *v1 = malloc(sizeof(unsigned long));
    assert(v0 && v1);
    *v0 = 0;
    *v1 = 4294967295UL;

    memset(&enc_seq, 0, sizeof(enc_seq));
    ASN_SEQUENCE_ADD(&enc_seq.list, v0);
    ASN_SEQUENCE_ADD(&enc_seq.list, v1);

    erv = uper_encode_to_buffer(&asn_DEF_SeqOfUInt32, 0, &enc_seq,
                                enc_buf, sizeof(enc_buf));
    assert(erv.encoded == (ssize_t)(sizeof(uper_expected) * 8));
    assert(memcmp(enc_buf, uper_expected, sizeof(uper_expected)) == 0);

    drv = uper_decode(0, &asn_DEF_SeqOfUInt32, (void **)&dec_seq,
                      enc_buf, sizeof(enc_buf), 0, 0);
    assert(drv.code == RC_OK);
    assert(dec_seq->list.count == 2);
    assert(*(unsigned long *)dec_seq->list.array[0] == 0UL);
    assert(*(unsigned long *)dec_seq->list.array[1] == 4294967295UL);

    ASN_STRUCT_RESET(asn_DEF_SeqOfUInt32, &enc_seq);
    ASN_STRUCT_FREE(asn_DEF_SeqOfUInt32, dec_seq);
    printf("check-204.-gen-UPER: SeqOfUInt32 UPER round-trip OK\n");
    return 0;
}
