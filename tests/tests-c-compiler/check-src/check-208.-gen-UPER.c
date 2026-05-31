/*
 * BER + UPER round-trip for SeqOfPill (SEQUENCE OF ENUMERATED { bluepill, redpill }).
 * NativeEnumerated stores elements as long; PER range [0..1] = 1 bit per element.
 */
#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <SeqOfPill.h>

/* DER encoding of SeqOfPill containing { bluepill(0), redpill(1) } */
static uint8_t der_input[] = {
    0x30, 0x06,             /* SEQUENCE OF, length 6 */
    0x0a, 0x01, 0x00,       /* ENUMERATED bluepill(0) */
    0x0a, 0x01, 0x01        /* ENUMERATED redpill(1) */
};

/* UPER encoding of SeqOfPill containing { bluepill, redpill }:
 * 0x02  -- 2 elements
 * 0x40  -- bluepill=0 -> bit 0; redpill=1 -> bit 1 (01xxxxxx = 0x40)
 */
static uint8_t uper_expected[] = { 0x02, 0x40 };

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
    SeqOfPill_t *seq = NULL;
    SeqOfPill_t enc_seq;
    SeqOfPill_t *dec_seq = NULL;
    asn_dec_rval_t drv;
    asn_enc_rval_t erv;
    uint8_t uper_buf[sizeof(uper_expected)];

    (void)ac; (void)av;

    /* BER round-trip */
    drv = ber_decode(0, &asn_DEF_SeqOfPill, (void **)&seq,
                     der_input, sizeof(der_input));
    assert(drv.code == RC_OK);
    assert(drv.consumed == sizeof(der_input));
    assert(seq->list.count == 2);
    assert(*(long *)seq->list.array[0] == Member_bluepill);
    assert(*(long *)seq->list.array[1] == Member_redpill);

    enc_pos = 0;
    erv = der_encode(&asn_DEF_SeqOfPill, seq, enc_cb, NULL);
    assert(erv.encoded == (ssize_t)sizeof(der_input));
    assert(memcmp(enc_buf, der_input, sizeof(der_input)) == 0);
    ASN_STRUCT_FREE(asn_DEF_SeqOfPill, seq);

    /* UPER round-trip */
    long *v0 = malloc(sizeof(long));
    long *v1 = malloc(sizeof(long));
    assert(v0 && v1);
    *v0 = Member_bluepill;
    *v1 = Member_redpill;

    memset(&enc_seq, 0, sizeof(enc_seq));
    ASN_SEQUENCE_ADD(&enc_seq.list, v0);
    ASN_SEQUENCE_ADD(&enc_seq.list, v1);

    erv = uper_encode_to_buffer(&asn_DEF_SeqOfPill, 0, &enc_seq,
                                uper_buf, sizeof(uper_buf));
    /* 8 bits (count=2) + 1 bit (bluepill) + 1 bit (redpill) = 10 bits */
    assert(erv.encoded == 10);
    assert(memcmp(uper_buf, uper_expected, sizeof(uper_expected)) == 0);

    drv = uper_decode(0, &asn_DEF_SeqOfPill, (void **)&dec_seq,
                      uper_buf, sizeof(uper_buf), 0, 0);
    assert(drv.code == RC_OK);
    assert(dec_seq->list.count == 2);
    assert(*(long *)dec_seq->list.array[0] == Member_bluepill);
    assert(*(long *)dec_seq->list.array[1] == Member_redpill);

    ASN_STRUCT_RESET(asn_DEF_SeqOfPill, &enc_seq);
    ASN_STRUCT_FREE(asn_DEF_SeqOfPill, dec_seq);
    printf("check-208.-gen-UPER: SeqOfPill BER+UPER round-trip OK\n");
    return 0;
}
