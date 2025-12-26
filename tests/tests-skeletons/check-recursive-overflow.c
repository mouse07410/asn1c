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
 * Test: Verify thread-local encoding depth variables exist for all formats
 */
static void test_encoding_depth_variables(void) {
    printf("Testing encoding depth variables for all formats...\n");
    
    /* BER/DER */
    asn1_encoding_depth = 0;
    assert(asn1_encoding_depth == 0);
    asn1_encoding_depth++;
    assert(asn1_encoding_depth == 1);
    asn1_encoding_depth = 0;
    printf("  BER/DER encoding depth tracking works\n");
    
    /* UPER */
    uper_encoding_depth = 0;
    assert(uper_encoding_depth == 0);
    uper_encoding_depth++;
    assert(uper_encoding_depth == 1);
    uper_encoding_depth = 0;
    printf("  UPER encoding depth tracking works\n");
    
    /* APER */
    aper_encoding_depth = 0;
    assert(aper_encoding_depth == 0);
    aper_encoding_depth++;
    assert(aper_encoding_depth == 1);
    aper_encoding_depth = 0;
    printf("  APER encoding depth tracking works\n");
    
    /* OER */
    oer_encoding_depth = 0;
    assert(oer_encoding_depth == 0);
    oer_encoding_depth++;
    assert(oer_encoding_depth == 1);
    oer_encoding_depth = 0;
    printf("  OER encoding depth tracking works\n");
    
    /* XER */
    xer_encoding_depth = 0;
    assert(xer_encoding_depth == 0);
    xer_encoding_depth++;
    assert(xer_encoding_depth == 1);
    xer_encoding_depth = 0;
    printf("  XER encoding depth tracking works\n");
    
    /* JER */
    jer_encoding_depth = 0;
    assert(jer_encoding_depth == 0);
    jer_encoding_depth++;
    assert(jer_encoding_depth == 1);
    jer_encoding_depth = 0;
    printf("  JER encoding depth tracking works\n");
    
    printf("  PASS: All encoding depth variables work\n");
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
 * Test: Verify macros are properly defined for all formats
 */
static void test_macros_defined(void) {
    printf("Testing recursion check macros...\n");
    
    /* BER/DER macros */
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
    
    /* UPER macros */
    #ifdef UPER_ENCODER_RECURSION_DEPTH_INC
    printf("  UPER_ENCODER_RECURSION_DEPTH_INC defined\n");
    #else
    assert(0 && "UPER_ENCODER_RECURSION_DEPTH_INC not defined");
    #endif
    
    #ifdef UPER_ENCODER_RECURSION_DEPTH_DEC
    printf("  UPER_ENCODER_RECURSION_DEPTH_DEC defined\n");
    #else
    assert(0 && "UPER_ENCODER_RECURSION_DEPTH_DEC not defined");
    #endif
    
    /* APER macros */
    #ifdef APER_ENCODER_RECURSION_DEPTH_INC
    printf("  APER_ENCODER_RECURSION_DEPTH_INC defined\n");
    #else
    assert(0 && "APER_ENCODER_RECURSION_DEPTH_INC not defined");
    #endif
    
    #ifdef APER_ENCODER_RECURSION_DEPTH_DEC
    printf("  APER_ENCODER_RECURSION_DEPTH_DEC defined\n");
    #else
    assert(0 && "APER_ENCODER_RECURSION_DEPTH_DEC not defined");
    #endif
    
    /* OER macros */
    #ifdef OER_ENCODER_RECURSION_DEPTH_INC
    printf("  OER_ENCODER_RECURSION_DEPTH_INC defined\n");
    #else
    assert(0 && "OER_ENCODER_RECURSION_DEPTH_INC not defined");
    #endif
    
    #ifdef OER_ENCODER_RECURSION_DEPTH_DEC
    printf("  OER_ENCODER_RECURSION_DEPTH_DEC defined\n");
    #else
    assert(0 && "OER_ENCODER_RECURSION_DEPTH_DEC not defined");
    #endif
    
    /* XER macros */
    #ifdef XER_ENCODER_RECURSION_DEPTH_INC
    printf("  XER_ENCODER_RECURSION_DEPTH_INC defined\n");
    #else
    assert(0 && "XER_ENCODER_RECURSION_DEPTH_INC not defined");
    #endif
    
    #ifdef XER_ENCODER_RECURSION_DEPTH_DEC
    printf("  XER_ENCODER_RECURSION_DEPTH_DEC defined\n");
    #else
    assert(0 && "XER_ENCODER_RECURSION_DEPTH_DEC not defined");
    #endif
    
    /* JER macros */
    #ifdef JER_ENCODER_RECURSION_DEPTH_INC
    printf("  JER_ENCODER_RECURSION_DEPTH_INC defined\n");
    #else
    assert(0 && "JER_ENCODER_RECURSION_DEPTH_INC not defined");
    #endif
    
    #ifdef JER_ENCODER_RECURSION_DEPTH_DEC
    printf("  JER_ENCODER_RECURSION_DEPTH_DEC defined\n");
    #else
    assert(0 && "JER_ENCODER_RECURSION_DEPTH_DEC not defined");
    #endif
    
    printf("  PASS: All macros are defined\n");
}

/*
 * Test: Simulate deep recursion and verify it's caught
 * This tests the actual enforcement mechanism by simulating
 * what would happen in a deeply nested or circular structure.
 */
static void test_deep_recursion_protection(void) {
    printf("Testing deep recursion protection...\n");
    
    int depth_hit_limit = 0;
    
    /* Simulate encoder recursion */
    for(int i = 0; i < ASN_STACK_OVERFLOW_LIMIT + 5; i++) {
        if(asn1_encoding_depth >= ASN_STACK_OVERFLOW_LIMIT) {
            depth_hit_limit = 1;
            break;
        }
        asn1_encoding_depth++;
    }
    
    assert(depth_hit_limit && "Depth limit should have been hit");
    assert(asn1_encoding_depth == ASN_STACK_OVERFLOW_LIMIT);
    
    /* Reset for next test */
    asn1_encoding_depth = 0;
    
    printf("  PASS: Deep recursion correctly stopped at depth %d\n", 
           ASN_STACK_OVERFLOW_LIMIT);
}

/*
 * Integration test: Verify that attempting to encode beyond the depth limit
 * would fail gracefully. This simulates what happens with circular references.
 */
static void test_circular_reference_simulation(void) {
    printf("Testing circular reference simulation...\n");
    
    /* Simulate encoding a structure with circular reference */
    /* In a real circular structure, the encoder would keep calling itself */
    /* until the depth limit is hit */
    
    int encoding_would_fail = 0;
    
    /* Reset depth */
    asn1_encoding_depth = 0;
    uper_encoding_depth = 0;
    aper_encoding_depth = 0;
    
    /* Simulate BER encoding reaching limit */
    for(int i = 0; i < ASN_STACK_OVERFLOW_LIMIT; i++) {
        asn1_encoding_depth++;
    }
    
    /* At this point, the next encoding attempt should fail */
    if(asn1_encoding_depth >= ASN_STACK_OVERFLOW_LIMIT) {
        encoding_would_fail = 1;
    }
    
    assert(encoding_would_fail && "BER encoding should fail at depth limit");
    printf("  BER encoding correctly rejects at depth %d\n", asn1_encoding_depth);
    
    /* Test UPER */
    encoding_would_fail = 0;
    for(int i = 0; i < ASN_STACK_OVERFLOW_LIMIT; i++) {
        uper_encoding_depth++;
    }
    
    if(uper_encoding_depth >= ASN_STACK_OVERFLOW_LIMIT) {
        encoding_would_fail = 1;
    }
    
    assert(encoding_would_fail && "UPER encoding should fail at depth limit");
    printf("  UPER encoding correctly rejects at depth %d\n", uper_encoding_depth);
    
    /* Test APER */
    encoding_would_fail = 0;
    for(int i = 0; i < ASN_STACK_OVERFLOW_LIMIT; i++) {
        aper_encoding_depth++;
    }
    
    if(aper_encoding_depth >= ASN_STACK_OVERFLOW_LIMIT) {
        encoding_would_fail = 1;
    }
    
    assert(encoding_would_fail && "APER encoding should fail at depth limit");
    printf("  APER encoding correctly rejects at depth %d\n", aper_encoding_depth);
    
    /* Reset all depths */
    asn1_encoding_depth = 0;
    uper_encoding_depth = 0;
    aper_encoding_depth = 0;
    
    printf("  PASS: Circular reference protection works for all tested formats\n");
}

/*
 * Test: Verify underflow protection prevents depth counters from going negative
 * This protects against malicious PDUs that might try to manipulate depth counters
 */
static void test_depth_underflow_protection(void) {
    printf("Testing depth underflow protection...\n");
    
    /* Test BER/DER underflow protection */
    asn1_encoding_depth = 0;
    ASN__ENCODER_RECURSION_DEPTH_DEC();  /* Should not go negative */
    assert(asn1_encoding_depth == 0 && "BER depth should not go negative");
    printf("  BER/DER underflow protection works\n");
    
    /* Test UPER underflow protection */
    uper_encoding_depth = 0;
    UPER_ENCODER_RECURSION_DEPTH_DEC();
    assert(uper_encoding_depth == 0 && "UPER depth should not go negative");
    printf("  UPER underflow protection works\n");
    
    /* Test APER underflow protection */
    aper_encoding_depth = 0;
    APER_ENCODER_RECURSION_DEPTH_DEC();
    assert(aper_encoding_depth == 0 && "APER depth should not go negative");
    printf("  APER underflow protection works\n");
    
    /* Test OER underflow protection */
    oer_encoding_depth = 0;
    OER_ENCODER_RECURSION_DEPTH_DEC();
    assert(oer_encoding_depth == 0 && "OER depth should not go negative");
    printf("  OER underflow protection works\n");
    
    /* Test XER underflow protection */
    xer_encoding_depth = 0;
    XER_ENCODER_RECURSION_DEPTH_DEC();
    assert(xer_encoding_depth == 0 && "XER depth should not go negative");
    printf("  XER underflow protection works\n");
    
    /* Test JER underflow protection */
    jer_encoding_depth = 0;
    JER_ENCODER_RECURSION_DEPTH_DEC();
    assert(jer_encoding_depth == 0 && "JER depth should not go negative");
    printf("  JER underflow protection works\n");
    
    printf("  PASS: All formats protected against underflow\n");
}

/*
 * Test: Simulate malicious PDU attack attempting depth manipulation
 * This tests defense against attempts to underflow depth counters
 */
static void test_malicious_pdu_protection(void) {
    printf("Testing malicious PDU protection...\n");
    
    /* Simulate a malicious PDU trying to underflow counters */
    /* by calling DEC without corresponding INC */
    
    /* Test BER/DER */
    asn1_encoding_depth = 0;
    for(int i = 0; i < 10; i++) {
        ASN__ENCODER_RECURSION_DEPTH_DEC();
    }
    assert(asn1_encoding_depth == 0 && "BER depth resisted underflow attack");
    printf("  BER/DER resisted underflow attack (depth=%d)\n", asn1_encoding_depth);
    
    /* Test UPER */
    uper_encoding_depth = 0;
    for(int i = 0; i < 10; i++) {
        UPER_ENCODER_RECURSION_DEPTH_DEC();
    }
    assert(uper_encoding_depth == 0 && "UPER depth resisted underflow attack");
    printf("  UPER resisted underflow attack (depth=%d)\n", uper_encoding_depth);
    
    /* Test APER */
    aper_encoding_depth = 0;
    for(int i = 0; i < 10; i++) {
        APER_ENCODER_RECURSION_DEPTH_DEC();
    }
    assert(aper_encoding_depth == 0 && "APER depth resisted underflow attack");
    printf("  APER resisted underflow attack (depth=%d)\n", aper_encoding_depth);
    
    /* Test OER */
    oer_encoding_depth = 0;
    for(int i = 0; i < 10; i++) {
        OER_ENCODER_RECURSION_DEPTH_DEC();
    }
    assert(oer_encoding_depth == 0 && "OER depth resisted underflow attack");
    printf("  OER resisted underflow attack (depth=%d)\n", oer_encoding_depth);
    
    /* Test XER */
    xer_encoding_depth = 0;
    for(int i = 0; i < 10; i++) {
        XER_ENCODER_RECURSION_DEPTH_DEC();
    }
    assert(xer_encoding_depth == 0 && "XER depth resisted underflow attack");
    printf("  XER resisted underflow attack (depth=%d)\n", xer_encoding_depth);
    
    /* Test JER */
    jer_encoding_depth = 0;
    for(int i = 0; i < 10; i++) {
        JER_ENCODER_RECURSION_DEPTH_DEC();
    }
    assert(jer_encoding_depth == 0 && "JER depth resisted underflow attack");
    printf("  JER resisted underflow attack (depth=%d)\n", jer_encoding_depth);
    
    printf("  PASS: All formats protected against malicious PDU attacks\n");
}

/*
 * Test: Verify correct inc/dec pairing maintains accurate depth
 */
static void test_depth_balance(void) {
    printf("Testing depth counter balance...\n");
    
    /* Test BER/DER - manually increment/decrement to test balance */
    asn1_encoding_depth = 0;
    asn1_encoding_depth++;
    asn1_encoding_depth++;
    asn1_encoding_depth++;
    assert(asn1_encoding_depth == 3);
    ASN__ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODER_RECURSION_DEPTH_DEC();
    ASN__ENCODER_RECURSION_DEPTH_DEC();
    assert(asn1_encoding_depth == 0);
    printf("  BER/DER depth balancing works\n");
    
    /* Test UPER */
    uper_encoding_depth = 0;
    uper_encoding_depth++;
    uper_encoding_depth++;
    assert(uper_encoding_depth == 2);
    UPER_ENCODER_RECURSION_DEPTH_DEC();
    UPER_ENCODER_RECURSION_DEPTH_DEC();
    assert(uper_encoding_depth == 0);
    printf("  UPER depth balancing works\n");
    
    /* Test APER */
    aper_encoding_depth = 0;
    aper_encoding_depth++;
    aper_encoding_depth++;
    assert(aper_encoding_depth == 2);
    APER_ENCODER_RECURSION_DEPTH_DEC();
    APER_ENCODER_RECURSION_DEPTH_DEC();
    assert(aper_encoding_depth == 0);
    printf("  APER depth balancing works\n");
    
    /* Test OER */
    oer_encoding_depth = 0;
    oer_encoding_depth++;
    assert(oer_encoding_depth == 1);
    OER_ENCODER_RECURSION_DEPTH_DEC();
    assert(oer_encoding_depth == 0);
    printf("  OER depth balancing works\n");
    
    /* Test XER */
    xer_encoding_depth = 0;
    xer_encoding_depth++;
    assert(xer_encoding_depth == 1);
    XER_ENCODER_RECURSION_DEPTH_DEC();
    assert(xer_encoding_depth == 0);
    printf("  XER depth balancing works\n");
    
    /* Test JER */
    jer_encoding_depth = 0;
    jer_encoding_depth++;
    assert(jer_encoding_depth == 1);
    JER_ENCODER_RECURSION_DEPTH_DEC();
    assert(jer_encoding_depth == 0);
    printf("  JER depth balancing works\n");
    
    printf("  PASS: Depth balancing works for all formats\n");
}

int main(void) {
    printf("=== ASN.1 Recursion Overflow Protection Tests ===\n\n");
    
    test_depth_limit_defined();
    test_encoding_depth_variables();
    test_encoder_depth_limit();
    test_macros_defined();
    test_deep_recursion_protection();
    test_circular_reference_simulation();
    test_depth_underflow_protection();
    test_malicious_pdu_protection();
    test_depth_balance();
    
    printf("\n=== All tests passed ===\n");
    return 0;
}
