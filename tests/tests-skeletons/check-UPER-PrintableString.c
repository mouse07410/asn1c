#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <PrintableString.h>
#include <uper_decoder.h>
#include <uper_encoder.h>

/*
 * Encode and decode a PrintableString via UPER, verify round-trip.
 * This exercises the full 7-bit encoding path, including characters
 * whose alphabet positions are above 15 (e.g. lowercase letters),
 * which would have been silently truncated before the fix.
 */
static void
check_round_trip_OK(const char *str) {
    uint8_t uper_output_buffer[256];
    PrintableString_t *st_in = NULL;
    PrintableString_t *st_out = NULL;
    size_t len = strlen(str);

    st_in = OCTET_STRING_new_fromBuf(&asn_DEF_PrintableString, str, len);
    assert(st_in);
    assert(st_in->size == len);

    /* Verify the string is a valid PrintableString */
    int ct = asn_check_constraints(&asn_DEF_PrintableString, st_in, NULL, NULL);
    assert(ct == 0);

    asn_enc_rval_t enc =
        uper_encode_to_buffer(&asn_DEF_PrintableString, NULL, st_in,
                              uper_output_buffer, sizeof(uper_output_buffer));
    assert(enc.encoded > 0);

    asn_dec_rval_t dec =
        uper_decode(NULL, &asn_DEF_PrintableString, (void **)&st_out,
                    uper_output_buffer, (enc.encoded + 7) / 8, 0, 0);
    assert(dec.consumed == (size_t)enc.encoded);
    assert(st_out != NULL);

    int ct_out = asn_check_constraints(&asn_DEF_PrintableString, st_out, NULL, NULL);
    assert(ct_out == 0);

    assert(st_out->size == len);
    assert(memcmp(st_out->buf, str, len) == 0);

    fprintf(stderr, "OK: round-trip for \"%s\"\n", str);

    ASN_STRUCT_FREE(asn_DEF_PrintableString, st_in);
    ASN_STRUCT_FREE(asn_DEF_PrintableString, st_out);
}

/*
 * Verify that a string with characters outside the PrintableString alphabet
 * is rejected by the constraint check.
 */
static void
check_constraint_failed(const char *str, size_t len) {
    PrintableString_t *st_in = NULL;
    char error_buf[128];
    size_t error_buf_len = sizeof(error_buf);

    st_in = OCTET_STRING_new_fromBuf(&asn_DEF_PrintableString, str, len);
    assert(st_in);

    int ct = asn_check_constraints(&asn_DEF_PrintableString, st_in,
                                   error_buf, &error_buf_len);
    assert(ct != 0);
    fprintf(stderr, "Correctly rejected invalid PrintableString: %s\n",
            error_buf);

    ASN_STRUCT_FREE(asn_DEF_PrintableString, st_in);
}

int
main(void) {
    /* Basic digits and letters already within the old 4-bit range (positions 0-15) */
    check_round_trip_OK("Hello");
    check_round_trip_OK("0123456789");

    /* Lowercase letters: positions 49-74 in the PrintableString alphabet,
     * well above 15.  These triggered the pre-fix truncation bug where the
     * high bits were silently dropped, corrupting the decoded string. */
    check_round_trip_OK("abcdefghijklmnopqrstuvwxyz");
    check_round_trip_OK("hello world");
    check_round_trip_OK("abc xyz");

    /* Mix of upper- and lowercase with punctuation */
    check_round_trip_OK("Hello World");
    check_round_trip_OK("Test 123 abc");

    /* Characters not in the PrintableString alphabet must be rejected */
    check_constraint_failed("\x01", 1);    /* control character (0x01) */
    check_constraint_failed("@", 1);       /* '@' not in alphabet */
    check_constraint_failed("{", 1);       /* '{' not in alphabet */

    return 0;
}
