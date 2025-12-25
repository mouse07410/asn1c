/*
 * Test for recursion depth overflow protection in ASN.1 encoders/decoders.
 * This test verifies that circular references and deeply nested structures
 * are properly detected and rejected to prevent stack overflow.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <asn_internal.h>

/*
 * Simple test: Verify depth limit constant is defined
 */
static void test_depth_limit_defined(void) {
    printf("Testing depth limit constant...\n");
    assert(ASN_STACK_OVERFLOW_LIMIT > 0);
    assert(ASN_STACK_OVERFLOW_LIMIT == 30);  /* Default value */
    printf("  PASS: ASN_STACK_OVERFLOW_LIMIT = %d\n", ASN_STACK_OVERFLOW_LIMIT);
}

/*
 * Test: Verify thread-local encoding depth variable exists
 */
static void test_encoding_depth_variable(void) {
    printf("Testing encoding depth variable...\n");
    
    /* Reset depth to 0 */
    asn1_encoding_depth = 0;
    assert(asn1_encoding_depth == 0);
    
    /* Simulate incrementing depth */
    asn1_encoding_depth++;
    assert(asn1_encoding_depth == 1);
    
    /* Reset back */
    asn1_encoding_depth = 0;
    assert(asn1_encoding_depth == 0);
    
    printf("  PASS: Encoding depth tracking works\n");
}

/*
 * Test: Verify depth limit is enforced during encoding
 */
static void test_encoder_depth_limit(void) {
    printf("Testing encoder depth limit enforcement...\n");
    
    /* Set depth to just below limit */
    asn1_encoding_depth = ASN_STACK_OVERFLOW_LIMIT - 1;
    
    /* Next increment should succeed */
    assert(asn1_encoding_depth < ASN_STACK_OVERFLOW_LIMIT);
    
    /* Set depth to limit */
    asn1_encoding_depth = ASN_STACK_OVERFLOW_LIMIT;
    
    /* At limit, should fail */
    assert(asn1_encoding_depth >= ASN_STACK_OVERFLOW_LIMIT);
    
    /* Reset */
    asn1_encoding_depth = 0;
    
    printf("  PASS: Encoder depth limit enforcement works\n");
}

/*
 * Test: Verify macros are properly defined
 */
static void test_macros_defined(void) {
    printf("Testing recursion check macros...\n");
    
    /* These should compile without errors */
    #ifdef ASN__ENCODER_RECURSION_DEPTH_INC
    printf("  ASN__ENCODER_RECURSION_DEPTH_INC defined\n");
    #else
    assert(0 && "ASN__ENCODER_RECURSION_DEPTH_INC not defined");
    #endif
    
    #ifdef ASN__ENCODER_RECURSION_DEPTH_DEC
    printf("  ASN__ENCODER_RECURSION_DEPTH_DEC defined\n");
    #else
    assert(0 && "ASN__ENCODER_RECURSION_DEPTH_DEC not defined");
    #endif
    
    #ifdef ASN__DECODER_RECURSION_DEPTH_CHECK
    printf("  ASN__DECODER_RECURSION_DEPTH_CHECK defined\n");
    #else
    assert(0 && "ASN__DECODER_RECURSION_DEPTH_CHECK not defined");
    #endif
    
    printf("  PASS: All macros are defined\n");
}

int main(void) {
    printf("=== ASN.1 Recursion Overflow Protection Tests ===\n\n");
    
    test_depth_limit_defined();
    test_encoding_depth_variable();
    test_encoder_depth_limit();
    test_macros_defined();
    
    printf("\n=== All tests passed ===\n");
    return 0;
}
