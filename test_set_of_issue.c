#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Simulate an APER SET OF decoding test
// We'll create a minimal test to understand the issue

#include "constr_SET_OF_aper.c"
#include "aper_support.c" 
#include "aper_decoder.c"
#include "per_decoder.c"
#include "per_support.c"

// We need to create a minimal test case for SET OF AliasAddress decoding
// Let's focus specifically on the issue mentioned in the problem statement

void test_set_of_aper_decoding() {
    printf("Testing SET OF APER decoding issue...\n");
    
    // Create a simple test case that should trigger the issue
    // Based on the debug output: "destinationAddress SET OF AliasAddress decoded 0"
    // This suggests that the length is decoded as 0 initially, then something fails
    
    // A minimal APER encoded SET OF with one element might look like:
    // Length encoding + element data
    
    uint8_t test_data[] = {
        0x01,  // Length = 1 (one element in the SET OF)
        0x80   // Simple element (e.g., dialedDigits choice with minimal data)
    };
    
    printf("Test data: ");
    for (int i = 0; i < sizeof(test_data); i++) {
        printf("%02x ", test_data[i]);
    }
    printf("\n");
    
    // For now, just print that we'd need to set up the full decoding infrastructure
    printf("This would require setting up a full ASN.1 type descriptor and decoder context.\n");
    printf("The actual issue is likely in the aper_get_length() function or bit handling.\n");
}

int main() {
    test_set_of_aper_decoding();
    return 0;
}