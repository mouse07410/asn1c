#include <stdio.h>
#include <assert.h>
#include <OCTET_STRING.h>
#include <OCTET_STRING.c>
#include <OCTET_STRING_aper.c>
#include <per_support.c>
#include <aper_support.c>
#include <aper_decoder.c>
#include <asn_bit_data.c>
#include <OCTET_STRING_print.c>
#include <constraints.c>

// Simulate a calling loop that would retry decoding
void simulate_caller_retry_loop() {
    OCTET_STRING_t *os = NULL;
    asn_dec_rval_t rval;
    int retry_count = 0;
    const int MAX_RETRIES = 10;
    
    // Data that causes the issue: length indicates 8 bytes but only 3 are provided
    uint8_t problematic_data[] = {
        0x08,  // Length = 8 bytes  
        0x41, 0x42, 0x43  // Only 3 bytes: "ABC"
    };
    
    printf("Simulating caller retry loop with problematic data...\n");
    printf("Data: Length=8 bytes, but only 3 data bytes provided\n");
    
    while (retry_count < MAX_RETRIES) {
        retry_count++;
        
        rval = aper_decode_complete(NULL, &asn_DEF_OCTET_STRING, (void**)&os,
                                   problematic_data, sizeof(problematic_data));
        
        printf("Attempt %d: code=%d (%s), consumed=%zu bits\n", 
               retry_count,
               rval.code,
               rval.code == RC_OK ? "RC_OK" : rval.code == RC_WMORE ? "RC_WMORE" : "RC_FAIL",
               rval.consumed);
        
        if (rval.code == RC_OK) {
            printf("✓ Successfully decoded!\n");
            break;
        } else if (rval.code == RC_WMORE) {
            if (rval.consumed == 0) {
                printf("✗ RC_WMORE with consumed=0 - would cause infinite loop!\n");
                printf("✗ This is the bug we fixed!\n");
                break;
            } else {
                printf("✓ RC_WMORE with consumed=%zu > 0 - progress tracked, safe to retry\n", rval.consumed);
                printf("   (But we won't actually retry since data is insufficient)\n");
                break;
            }
        } else {
            printf("✗ Failed with RC_FAIL\n");
            break;
        }
        
        if (os) {
            ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, os);
            os = NULL;
        }
    }
    
    if (retry_count >= MAX_RETRIES) {
        printf("✗ Hit maximum retry limit - would have been infinite loop!\n");
    }
    
    if (os) {
        ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, os);
    }
}

int main() {
    simulate_caller_retry_loop();
    return 0;
}
