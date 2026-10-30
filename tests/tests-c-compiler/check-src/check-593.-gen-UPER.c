/*
 * Purpose: verify that an extension CHOICE tag cannot reorder SET roots.
 * Source: X.691 (02/2021) SET canonical root order and generated CXER map.
 * Version/date: 2026-10-30. Responsible party: asn1c maintainers.
 * History: regression for using the full tag map in SET UPER ordering.
 */
#undef NDEBUG
#include <assert.h>
#include <string.h>
#include <S.h>
#include <CH.h>

/*
 * Purpose: check canonical wire order, decode, truncation, and map validation.
 * Original source: new regression based on X.691 SET ordering.
 * Version/date: 2026-10-30. Inputs: none. Returns: success via assertions.
 * Exceptions: assertion failure on regression. Author: asn1c maintainers.
 * History: first version. Example: run as check-593.-gen-UPER.c.
 */
static void
check_root_order(void) {
    static const unsigned char expected[] = {0x05, 0x40};
    unsigned char encoded[8] = {0};
    asn_SET_specifics_t *specs = (asn_SET_specifics_t *)asn_DEF_S.specifics;
    const asn_TYPE_tag2member_t *saved_map = specs->tag2el_cxer;
    S_t src;
    CH_t choice;
    S_t *decoded = 0;
    asn_enc_rval_t er;
    asn_dec_rval_t dr;

    /* The extension [1] tag is below n [2], but root [3] is above it. */
    memset(&src, 0, sizeof(src));
    memset(&choice, 0, sizeof(choice));
    src.n = 5;
    src.c = &choice;
    choice.present = CH_PR_root;
    choice.choice.root = 1;
    er = uper_encode_to_buffer(&asn_DEF_S, 0, &src, encoded, sizeof(encoded));
    assert(er.encoded == 10);
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);

    /* The same order must decode, while a truncated value needs more bits. */
    dr = uper_decode(0, &asn_DEF_S, (void **)&decoded, expected,
                     sizeof(expected), 0, 0);
    assert(dr.code == RC_OK && decoded->n == 5);
    assert(decoded->c && decoded->c->present == CH_PR_root);
    assert(decoded->c->choice.root == 1);
    ASN_STRUCT_FREE(asn_DEF_S, decoded);
    decoded = 0;
    dr = uper_decode(0, &asn_DEF_S, (void **)&decoded, expected, 1, 0, 0);
    assert(dr.code != RC_OK);
    if(decoded) ASN_STRUCT_FREE(asn_DEF_S, decoded);

    /* A malformed canonical map must fail cleanly before member access. */
    specs->tag2el_cxer = 0;
    er = uper_encode_to_buffer(&asn_DEF_S, 0, &src, encoded, sizeof(encoded));
    assert(er.encoded == -1);
    specs->tag2el_cxer = saved_map;
}

/*
 * Purpose: run the SET UPER canonical-order regression.
 * Original source: new test entry point. Version/date: 2026-10-30.
 * Inputs: argc and argv are unused. Returns: zero on success.
 * Exceptions: assertion failure on regression. Author: asn1c maintainers.
 * History: first version. Example: ./check-program.
 */
int
main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    check_root_order();
    return 0;
}
