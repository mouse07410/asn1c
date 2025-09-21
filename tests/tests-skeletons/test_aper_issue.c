#include <stdio.h>
#include <assert.h>
#include <OCTET_STRING.h>
#include <aper_decoder.h>

static void test_rc_wmore_issue() {
    OCTET_STRING_t *os = NULL;
    asn_dec_rval_t rval;
    
    printf("Testing RC_WMORE issue...\n");
    
    // Test case that might trigger RC_WMORE with consumed=0
    uint8_t test_data[] = {0x00}; // Single byte
    
    rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void**)&os, test_data, sizeof(test_data));
    
    printf("Decode result: code=%d, consumed=%zu\n", rval.code, rval.consumed);
    
    if (rval.code == RC_WMORE && rval.consumed == 0) {
        printf("Found the RC_WMORE issue!\n");
    }
    
    if (os) {
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, os);
    }
}

int main() {
    test_rc_wmore_issue();
    return 0;
}
