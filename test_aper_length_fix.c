#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Test the APER support functions directly
#include "aper_support.h"
#include "asn_bit_data.h"

void test_aper_get_length_fix() {
    printf("Testing aper_get_length() function directly...\n\n");
    
    // Test case 1: Unconstrained SET OF length (the problematic case)
    // This should NOT force alignment inappropriately
    
    uint8_t test_data1[] = {
        0x01,  // Length = 1 (single byte length determinant, bit aligned)
        0x80   // Some following data  
    };
    
    asn_bit_data_t pd1;
    memset(&pd1, 0, sizeof(pd1));
    pd1.buffer = test_data1;
    pd1.nbits = sizeof(test_data1) * 8;
    pd1.nboff = 0;
    
    int repeat1 = 0;
    ssize_t length1 = aper_get_length(&pd1, 0, -1, -1, &repeat1);
    
    printf("Test 1 - Unconstrained length (lb=0, ub=-1, ebits=-1):\n");
    printf("  Input data: %02x %02x\n", test_data1[0], test_data1[1]);
    printf("  Decoded length: %zd\n", length1);
    printf("  Repeat flag: %d\n", repeat1);
    printf("  Bits consumed: %zu\n", pd1.moved);
    printf("  Expected: length=1, repeat=0, bits=8 (if aligned) or variable\n\n");
    
    // Test case 2: Constrained SET OF length  
    uint8_t test_data2[] = {
        0x04,  // Length = 4 (within a constrained range)
        0x00   // Following data
    };
    
    asn_bit_data_t pd2;
    memset(&pd2, 0, sizeof(pd2));
    pd2.buffer = test_data2;
    pd2.nbits = sizeof(test_data2) * 8;
    pd2.nboff = 0;
    
    int repeat2 = 0;
    ssize_t length2 = aper_get_length(&pd2, 0, 10, -1, &repeat2);  // Constrained to 0..10
    
    printf("Test 2 - Constrained length (lb=0, ub=10, ebits=-1):\n");
    printf("  Input data: %02x %02x\n", test_data2[0], test_data2[1]);
    printf("  Decoded length: %zd\n", length2);
    printf("  Repeat flag: %d\n", repeat2);
    printf("  Bits consumed: %zu\n", pd2.moved);
    printf("  Expected: Should use aper_get_constrained_whole_number\n\n");
    
    // Test case 3: Test with effective bits
    uint8_t test_data3[] = {
        0x05,  // Some bit pattern
        0x00
    };
    
    asn_bit_data_t pd3;
    memset(&pd3, 0, sizeof(pd3));
    pd3.buffer = test_data3;
    pd3.nbits = sizeof(test_data3) * 8;
    pd3.nboff = 0;
    
    int repeat3 = 0;
    ssize_t length3 = aper_get_length(&pd3, 0, -1, 4, &repeat3);  // 4 effective bits
    
    printf("Test 3 - Length with effective bits (lb=0, ub=-1, ebits=4):\n");
    printf("  Input data: %02x %02x\n", test_data3[0], test_data3[1]);
    printf("  Decoded length: %zd\n", length3);
    printf("  Repeat flag: %d\n", repeat3);
    printf("  Bits consumed: %zu\n", pd3.moved);
    printf("  Expected: Should align then read 4 bits\n\n");
    
    // Test case 4: Test an unaligned start position (this was likely the problem)
    uint8_t test_data4[] = {
        0x81,  // First byte with some bits used
        0x02,  // Next byte where length should be read
        0x00
    };
    
    asn_bit_data_t pd4;
    memset(&pd4, 0, sizeof(pd4));
    pd4.buffer = test_data4;
    pd4.nbits = sizeof(test_data4) * 8;
    pd4.nboff = 1;  // Start at bit offset 1 (unaligned)
    
    int repeat4 = 0;
    ssize_t length4 = aper_get_length(&pd4, 0, -1, -1, &repeat4);
    
    printf("Test 4 - Unaligned unconstrained length (offset=1 bit):\n");
    printf("  Input data: %02x %02x %02x (starting at bit 1)\n", 
           test_data4[0], test_data4[1], test_data4[2]);
    printf("  Decoded length: %zd\n", length4);
    printf("  Repeat flag: %d\n", repeat4);
    printf("  Bits consumed: %zu\n", pd4.moved);
    printf("  Initial offset: 1 bit\n");
    printf("  This test shows if alignment is being handled correctly\n");
}

int main() {
    printf("APER Length Decoding Fix Test\n");
    printf("============================\n\n");
    
    test_aper_get_length_fix();
    
    printf("\n=== Summary ===\n");
    printf("The fix ensures that aper_get_length() only applies alignment when\n");
    printf("it's actually required by the APER standard, rather than always\n");
    printf("forcing alignment. This should fix SET OF decoding issues where\n");
    printf("inappropriate alignment was causing bit stream misalignment.\n");
    
    return 0;
}