#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Include the generated H.323 headers
#include "AliasAddress.h"
#include "aper_decoder.h"
#include "asn_SET_OF.h"

// Define a SET OF AliasAddress type for testing
typedef struct SEQUENCE_OF_AliasAddress {
    A_SET_OF(AliasAddress_t) list;
} SEQUENCE_OF_AliasAddress_t;

// Test function to create a minimal SET OF AliasAddress test case
void test_set_of_alias_address_aper() {
    printf("Testing minimal SET OF AliasAddress APER decoding...\n");
    
    // Create some test data for a SET OF with one simple AliasAddress
    // AliasAddress is a CHOICE, so we need to encode a choice variant
    
    // For APER, a minimal SET OF AliasAddress with one dialedDigits element might be:
    // - Length = 1 (1 element) 
    // - Choice: dialedDigits (tag 0)
    // - String: "123"
    
    // APER encoding would be something like:
    uint8_t test_data1[] = {
        0x01,  // Length of SET OF = 1 element
        0x80,  // dialedDigits choice (tag 0), length follows
        0x03,  // Length of string = 3
        '1', '2', '3'  // String content "123"
    };
    
    printf("Test case 1 - Simple SET OF with dialedDigits:\n");
    printf("Data: ");
    for (int i = 0; i < sizeof(test_data1); i++) {
        printf("%02x ", test_data1[i]);
    }
    printf("\n");
    
    // Test case 2: Empty SET OF
    uint8_t test_data2[] = {
        0x00   // Length of SET OF = 0 elements
    };
    
    printf("Test case 2 - Empty SET OF:\n");
    printf("Data: ");
    for (int i = 0; i < sizeof(test_data2); i++) {
        printf("%02x ", test_data2[i]);
    }
    printf("\n");
    
    // Test case 3: SET OF with multiple elements
    uint8_t test_data3[] = {
        0x02,  // Length of SET OF = 2 elements
        0x80,  // First element: dialedDigits choice
        0x01,  // Length = 1
        '1',   // Content "1"
        0x80,  // Second element: dialedDigits choice  
        0x01,  // Length = 1
        '2'    // Content "2"
    };
    
    printf("Test case 3 - SET OF with 2 elements:\n");
    printf("Data: ");
    for (int i = 0; i < sizeof(test_data3); i++) {
        printf("%02x ", test_data3[i]);
    }
    printf("\n");
    
    printf("\nNote: This is a conceptual test. To properly test decoding,\n");
    printf("we would need the full ASN.1 type descriptor for SET OF AliasAddress.\n");
    printf("The actual fix should be tested with the H.225 context.\n");
}

int main() {
    printf("SET OF AliasAddress APER Decoding Test\n");
    printf("=====================================\n\n");
    
    test_set_of_alias_address_aper();
    
    printf("\n=== Testing our fix in aper_get_length ===\n");
    printf("The fix was to conditionally apply alignment in aper_get_length().\n");
    printf("Before: Always called aper_get_align() before reading length\n");
    printf("After: Only align when ebits >= 0 or for unconstrained lengths\n");
    
    return 0;
}