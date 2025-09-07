#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <OCTET_STRING.h>

/* Test for large OCTET_STRING JER decoding - addresses issue #242 */

static void test_large_jer_hex(void) {
    printf("Testing large OCTET_STRING JER hex decoding...\n");
    
    /* Test the specific size that was failing: 3988 octets = 7976 hex chars */
    int test_size = 3988;
    size_t hex_len = test_size * 2;
    char *hex_json = malloc(hex_len + 3); /* hex + quotes + null */
    assert(hex_json);
    
    /* Create hex string: "414141...4141" (all 'A' bytes) */
    hex_json[0] = '"';
    for (size_t i = 0; i < hex_len; i++) {
        hex_json[1 + i] = (i % 2 == 0) ? '4' : '1';
    }
    hex_json[hex_len + 1] = '"';
    hex_json[hex_len + 2] = '\0';
    
    /* Decode using JER hex decoder */
    OCTET_STRING_t *st = NULL;
    asn_dec_rval_t rval = OCTET_STRING_decode_jer_hex(
        NULL, &asn_DEF_OCTET_STRING, NULL, 
        (void**)&st, hex_json, strlen(hex_json));
    
    /* Verify successful decoding */
    printf("  Size %d octets: ", test_size);
    assert(rval.code == RC_OK);
    assert(st != NULL);
    assert(st->size == test_size);
    assert(st->buf != NULL);
    assert(st->buf[0] == 0x41);  /* First byte should be 'A' */
    assert(st->buf[test_size-1] == 0x41);  /* Last byte should be 'A' */
    printf("SUCCESS\n");
    
    /* Cleanup */
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, st);
    free(hex_json);
}

static void test_boundary_sizes(void) {
    printf("Testing boundary sizes around 4KB...\n");
    
    int test_sizes[] = {3985, 3986, 3987, 3988, 3989, 3990, 4000};
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    for (int i = 0; i < num_tests; i++) {
        int test_size = test_sizes[i];
        size_t hex_len = test_size * 2;
        char *hex_json = malloc(hex_len + 3);
        assert(hex_json);
        
        /* Create simple hex pattern */
        hex_json[0] = '"';
        for (size_t j = 0; j < hex_len; j++) {
            hex_json[1 + j] = (j % 2 == 0) ? '4' : '2';  /* 0x42 = 'B' */
        }
        hex_json[hex_len + 1] = '"';
        hex_json[hex_len + 2] = '\0';
        
        /* Test decoding */
        OCTET_STRING_t *st = NULL;
        asn_dec_rval_t rval = OCTET_STRING_decode_jer_hex(
            NULL, &asn_DEF_OCTET_STRING, NULL, 
            (void**)&st, hex_json, strlen(hex_json));
        
        printf("  Size %d: ", test_size);
        assert(rval.code == RC_OK);
        assert(st != NULL);
        assert(st->size == test_size);
        assert(st->buf[0] == 0x42);  /* Should be 'B' */
        printf("OK\n");
        
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, st);
        free(hex_json);
    }
}

int main() {
    printf("Large OCTET_STRING JER decoding test (issue #242 fix)\n");
    printf("=====================================================\n");
    
    test_large_jer_hex();
    test_boundary_sizes();
    
    printf("\nAll tests passed! Large OCTET_STRING JER decoding is working correctly.\n");
    return 0;
}