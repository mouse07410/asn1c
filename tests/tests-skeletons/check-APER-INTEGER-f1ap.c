/* Test APER INTEGER encoding for F1AP use case (issue report) */

#include <stdio.h>
#include <assert.h>

#include <INTEGER.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <per_support.c>
#include <per_support.h>
#include <aper_support.c>
#include <aper_support.h>

static void
print_bytes(const char *label, const uint8_t *data, size_t len) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("(%zu bytes)\n", len);
}

static void
check_f1ap_id_encoding(int lineno, unsigned long value, 
                       const uint8_t *expected, size_t expected_len) {
    INTEGER_t st;
    INTEGER_t *reconstructed_st = NULL;
    struct asn_INTEGER_specifics_s specs;
    struct asn_per_constraints_s cts;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    
    printf("%d: Testing F1AP ID value %lu\n", lineno, value);
    
    memset(&st, 0, sizeof(st));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));
    
    /* GNB-CU-UE-F1AP-ID ::= INTEGER (0..4294967295) */
    /* Range = 4294967296, range_bits = 32 */
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 32;
    cts.value.effective_bits = 32;
    cts.value.lower_bound = 0;
    cts.value.upper_bound = 4294967295UL;
    
    /* Convert value to INTEGER (unsigned) */
    asn_ulong2INTEGER(&st, value);
    
    /* Setup output */
    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = (asn_app_consume_bytes_f *)0;
    
    /* Setup specs for unsigned */
    specs.field_width = sizeof(unsigned long);
    specs.field_unsigned = 1;
    asn_DEF_INTEGER.specifics = &specs;
    
    /* Encode */
    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, &cts, &st, &po);
    assert(enc_rval.encoded >= 0);
    
    /* Get encoded bytes */
    size_t actual_len = (po.buffer - po.tmpspace) + ((po.nboff + 7) / 8);
    uint8_t *actual = po.tmpspace;
    
    /* Print results */
    print_bytes("Expected", expected, expected_len);
    print_bytes("Actual  ", actual, actual_len);
    
    /* Verify encoding matches expected */
    if (actual_len != expected_len) {
        printf("  ERROR: Length mismatch (expected %zu, got %zu)\n", 
               expected_len, actual_len);
        assert(actual_len == expected_len);
    }
    
    if (memcmp(actual, expected, expected_len) != 0) {
        printf("  ERROR: Bytes don't match\n");
        assert(0 && "Encoding mismatch");
    }
    
    printf("  PASS: Encoding matches expected\n");
    
    /* Now decode it back */
    pd.buffer = actual;
    pd.nboff = 0;
    pd.nbits = 8 * actual_len;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, 
                                   (void **)&reconstructed_st, &pd);
    assert(dec_rval.code == RC_OK);
    
    /* Verify decoded value */
    unsigned long decoded_value = 0;
    asn_INTEGER2ulong(reconstructed_st, &decoded_value);
    
    if (decoded_value != value) {
        printf("  ERROR: Decoded value %lu != original %lu\n", 
               decoded_value, value);
        assert(decoded_value == value);
    }
    
    printf("  PASS: Decoded value %lu matches original\n", decoded_value);
    
    /* Cleanup */
    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
    printf("\n");
}

int main() {
    printf("=== F1AP INTEGER (0..4294967295) APER Encoding Test ===\n\n");
    
    /* Test case 1 from issue: value 32 (0x20) */
    /* Expected: 01 20 (APER length determinant, then value byte) */
    uint8_t expected_32[] = {0x01, 0x20};
    check_f1ap_id_encoding(__LINE__, 32, expected_32, sizeof(expected_32));
    
    /* Test case 2 from issue: value 1 (0x01) */
    /* Expected: 01 01 (APER length determinant, then value byte) */
    uint8_t expected_1[] = {0x01, 0x01};
    check_f1ap_id_encoding(__LINE__, 1, expected_1, sizeof(expected_1));
    
    /* Additional test cases */
    
    /* Value 0: Expected 01 00 (APER length determinant, then value 0x00) */
    uint8_t expected_0[] = {0x01, 0x00};
    check_f1ap_id_encoding(__LINE__, 0, expected_0, sizeof(expected_0));
    
    /* Value 255 (0xFF): Expected 01 FF (APER length determinant, then value 0xFF) */
    uint8_t expected_255[] = {0x01, 0xFF};
    check_f1ap_id_encoding(__LINE__, 255, expected_255, sizeof(expected_255));
    
    /* Value 256 (0x0100): Expected 02 01 00 */
    uint8_t expected_256[] = {0x02, 0x01, 0x00};
    check_f1ap_id_encoding(__LINE__, 256, expected_256, sizeof(expected_256));
    
    /* Value 65535 (0xFFFF): Expected 02 FF FF */
    uint8_t expected_65535[] = {0x02, 0xFF, 0xFF};
    check_f1ap_id_encoding(__LINE__, 65535, expected_65535, sizeof(expected_65535));
    
    /* Value 65536 (0x010000): Expected 03 01 00 00 */
    uint8_t expected_65536[] = {0x03, 0x01, 0x00, 0x00};
    check_f1ap_id_encoding(__LINE__, 65536, expected_65536, sizeof(expected_65536));
    
    /* Value 16777215 (0xFFFFFF): Expected 03 FF FF FF */
    uint8_t expected_16777215[] = {0x03, 0xFF, 0xFF, 0xFF};
    check_f1ap_id_encoding(__LINE__, 16777215, expected_16777215, sizeof(expected_16777215));
    
    /* Max value 4294967295 (0xFFFFFFFF): Expected 04 FF FF FF FF */
    uint8_t expected_max[] = {0x04, 0xFF, 0xFF, 0xFF, 0xFF};
    check_f1ap_id_encoding(__LINE__, 4294967295UL, expected_max, sizeof(expected_max));
    
    printf("=== All F1AP tests passed! ===\n");
    return 0;
}
