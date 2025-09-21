#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

#include <OCTET_STRING.h>
#include <OCTET_STRING.c>
#include <OCTET_STRING_aper.c>
#include <BIT_STRING.h>
#include <per_support.c>
#include <aper_support.c>
#include <aper_decoder.c>
#include <asn_bit_data.c>
#include <OCTET_STRING_print.c>
#include <constraints.c>

/*
 * Test to verify fix for RC_WMORE issue where consumed=0
 * which could lead to infinite loops in calling code.
 *
 * Issue: When APER decoding OCTET_STRING fails due to insufficient data,
 * it should report the number of bits consumed to prevent infinite retry loops.
 */

static void test_rc_wmore_consumption_tracking() {
    OCTET_STRING_t *os = NULL;
    asn_dec_rval_t rval;
    
    printf("Testing RC_WMORE consumption tracking fix...\n");
    
    /*
     * Test case 1: Truncated data after successful length decode
     * This should return RC_WMORE with consumed > 0
     */
    printf("\nTest 1: Truncated OCTET_STRING data\n");
    uint8_t truncated_data[] = {
        0x0A,  // Length = 10 bytes
        0x41, 0x42, 0x43, 0x44, 0x45  // Only 5 bytes provided
    };
    
    rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void**)&os,
                               truncated_data, sizeof(truncated_data));
    
    printf("  Input: Length=10, but only 5 data bytes provided\n");
    printf("  Result: code=%d (%s), consumed=%zu bits\n", 
           rval.code, 
           rval.code == RC_OK ? "RC_OK" : rval.code == RC_WMORE ? "RC_WMORE" : "RC_FAIL",
           rval.consumed);
    
    assert(rval.code == RC_WMORE);
    assert(rval.consumed > 0); // This is the key fix - should not be 0
    printf("  ✓ RC_WMORE with consumed=%zu > 0 (progress tracked correctly)\n", rval.consumed);
    
    if (os) {
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, os);
        os = NULL;
    }
    
    /*
     * Test case 2: Valid complete OCTET_STRING should still work
     */
    printf("\nTest 2: Valid complete OCTET_STRING\n");
    uint8_t valid_data[] = {
        0x05,  // Length = 5 bytes
        0x48, 0x65, 0x6C, 0x6C, 0x6F  // "Hello"
    };
    
    rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void**)&os,
                               valid_data, sizeof(valid_data));
    
    printf("  Input: Length=5, with 5 data bytes\n");
    printf("  Result: code=%d, consumed=%zu bits\n", rval.code, rval.consumed);
    
    assert(rval.code == RC_OK);
    assert(rval.consumed > 0);
    assert(os != NULL);
    assert(os->size == 5);
    assert(memcmp(os->buf, "Hello", 5) == 0);
    printf("  ✓ Successful decode: '%.*s'\n", (int)os->size, os->buf);
    
    ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, os);
    os = NULL;
    
    /*
     * Test case 3: Empty buffer (should return RC_WMORE with consumed=0,
     * which is acceptable since no progress can be made)
     */
    printf("\nTest 3: Empty buffer\n");
    uint8_t empty_buffer[] = {};
    
    rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void**)&os,
                               empty_buffer, 0);
    
    printf("  Input: Empty buffer\n");
    printf("  Result: code=%d, consumed=%zu bits\n", rval.code, rval.consumed);
    
    assert(rval.code == RC_WMORE);
    // consumed=0 is acceptable here since no bits can be read
    printf("  ✓ RC_WMORE with consumed=%zu (acceptable for empty buffer)\n", rval.consumed);
    
    /*
     * Test case 4: Insufficient data for length field itself
     */
    printf("\nTest 4: Partial length field\n");
    
    // For lengths >= 128, APER uses multi-byte encoding
    // We'll simulate a truncated length field
    uint8_t partial_length[] = {
        0x82  // Indicates 2-byte length follows, but no second byte
    };
    
    rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void**)&os,
                               partial_length, sizeof(partial_length));
    
    printf("  Input: Partial length field (missing second byte)\n");
    printf("  Result: code=%d, consumed=%zu bits\n", rval.code, rval.consumed);
    
    // This should return RC_WMORE and may have consumed some bits
    assert(rval.code == RC_WMORE);
    printf("  ✓ RC_WMORE with consumed=%zu\n", rval.consumed);
    
    if (os) {
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, os);
        os = NULL;
    }
}

int main() {
    test_rc_wmore_consumption_tracking();
    printf("\n✓ All RC_WMORE consumption tracking tests passed!\n");
    return 0;
}