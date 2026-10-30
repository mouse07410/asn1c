/*
 * Check generated C APER/OER primitive wire forms against the Rust vectors.
 * Original source: asn1c C comparison fixture. Version/date: 2026-10-30.
 * Responsible party: asn1c maintainers. History: APER/OER Rust slice.
 * Example: compile beside CParity generated sources and run with no arguments.
 */
#include <asn_application.h>
#include <aper_decoder.h>
#include <aper_encoder.h>
#include <oer_decoder.h>
#include <oer_encoder.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Flag.h>
#include <Empty.h>
#include <Count.h>
#include <Singleton.h>
#include <SignBounds.h>

/*
 * One C-derived wire check; the byte arrays match independent Rust tests.
 * Each member describes one generated descriptor, source value, and expected
 * wire form. There are no mutable state variables in this structure.
 */
typedef struct primitive_case_s {
    const asn_TYPE_descriptor_t *type; /* Generated ASN.1 descriptor. */
    const void *value;                /* C value passed to both encoders. */
    const unsigned char *aper;        /* Expected complete APER bytes. */
    size_t aper_len;                  /* Expected APER byte count. */
    const unsigned char *oer;         /* Expected OER bytes. */
    size_t oer_len;                   /* Expected OER byte count. */
    const char *name;                 /* Diagnostic case name. */
} primitive_case_t;

/*
 * Encode one primitive with generated C APER/OER code and check its bytes.
 * Parameters: item supplies descriptor, value, golden bytes, and case name.
 * Returns zero for both matches or one for encoder/length/content failure.
 * Exceptions: none; C allocation failure becomes an error return.
 * Original source: C generated-code comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: initial
 * APER/OER Rust parity check. Example: check_case(&cases[0]).
 */
static int
check_case(const primitive_case_t *item) {
    void *aper = NULL;
    unsigned char oer[16] = {0};
    ssize_t aper_len;
    asn_enc_rval_t oer_result;
    int failed;

    if(!item || !item->type || !item->value || !item->name
       || !item->aper || !item->oer) return 1;
    aper_len = aper_encode_to_new_buffer(item->type, NULL, item->value, &aper);
    oer_result = oer_encode_to_buffer(item->type, NULL, item->value,
                                      oer, sizeof(oer));
    failed = aper_len < 0 || oer_result.encoded < 0
             || (size_t)aper_len != item->aper_len
             || (size_t)oer_result.encoded != item->oer_len;
    if(!failed) {
        failed = memcmp(aper, item->aper, item->aper_len) != 0
                 || memcmp(oer, item->oer, item->oer_len) != 0;
    }
    free(aper);
    if(failed) fprintf(stderr, "C APER/OER vector mismatch: %s\n", item->name);
    return failed;
}

/*
 * Run C-produced primitive vectors also asserted by Rust integration tests.
 * Parameters: argc is argument count; argv is the unused argument array.
 * Returns zero for all matches, one for unexpected arguments or any mismatch.
 * Exceptions: none. Original source: asn1c comparison fixture. Version/date:
 * 2026-10-30. Responsible party: asn1c maintainers. History: initial
 * APER/OER parity vectors. Example: ./c-additional.
 */
int
main(int argc, char **argv) {
    Flag_t flag = 1;
    Empty_t empty = 0;
    Count_t count = 10;
    Singleton_t singleton = 5;
    SignBounds_t sign = 128;
    const unsigned char aper_flag[] = {0x80};
    const unsigned char oer_flag[] = {0xff};
    const unsigned char aper_empty[] = {0x00};
    const unsigned char oer_empty[] = {0x00};
    const unsigned char aper_count[] = {0xa0};
    const unsigned char oer_count[] = {0x0a};
    const unsigned char aper_singleton[] = {0x00};
    const unsigned char oer_singleton[] = {0x05};
    const unsigned char aper_sign[] = {0x01, 0x01};
    const unsigned char oer_sign[] = {0x00, 0x80};
    const primitive_case_t cases[] = {
        {&asn_DEF_Flag, &flag, aper_flag, 1, oer_flag, 1, "BOOLEAN TRUE"},
        {&asn_DEF_Empty, &empty, aper_empty, 1, oer_empty, 0, "NULL"},
        {&asn_DEF_Count, &count, aper_count, 1, oer_count, 1, "Count(10)"},
        {&asn_DEF_Singleton, &singleton, aper_singleton, 1,
         oer_singleton, 1, "Singleton(5)"},
        {&asn_DEF_SignBounds, &sign, aper_sign, 2, oer_sign, 2,
         "SignBounds(128)"}
    };
    size_t i;
    int failed = 0;
    (void)argv;
    if(argc != 1) return 1;

    /* Check each generated C encoder against the separately asserted bytes. */
    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        failed |= check_case(&cases[i]);
    }
    return failed;
}
