#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skeletons/INTEGER.h"
#include "skeletons/uper_decoder.h"
#include "skeletons/asn_codecs.h"
#include "skeletons/asn_internal.h"

static void test_canonical_integer_decoding(void) {
    INTEGER_t *integer = NULL;
    asn_dec_rval_t rval;
    asn_codec_ctx_t ctx_basic = {0};
    asn_codec_ctx_t ctx_canonical = {0};
    
    /* Test data: non-minimal integer encoding (leading zero in positive number) */
    /* Length=2, followed by 0x00 0x42 (should be just 0x42) */
    uint8_t non_minimal_data[] = {0x02, 0x00, 0x42};
    
    ctx_basic.max_stack_size = ASN__DEFAULT_STACK_MAX;
    ctx_basic.uper_canonical = 0;
    
    ctx_canonical.max_stack_size = ASN__DEFAULT_STACK_MAX;
    ctx_canonical.uper_canonical = 1;
    
    printf("Testing non-minimal integer encoding...\n");
    
    /* Test 1: Basic UPER should accept non-minimal encoding */
    integer = NULL;
    rval = uper_decode(&ctx_basic, &asn_DEF_INTEGER, (void **)&integer,
                       non_minimal_data, sizeof(non_minimal_data), 0, 0);
    
    if(rval.code == RC_OK) {
        printf("✓ Basic UPER accepted non-minimal encoding (as expected)\n");
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
    } else {
        printf("✗ Basic UPER unexpectedly rejected non-minimal encoding\n");
    }
    
    /* Test 2: Canonical UPER should reject non-minimal encoding */
    integer = NULL;
    rval = uper_decode(&ctx_canonical, &asn_DEF_INTEGER, (void **)&integer,
                       non_minimal_data, sizeof(non_minimal_data), 0, 0);
    
    if(rval.code != RC_OK) {
        printf("✓ Canonical UPER rejected non-minimal encoding (as expected)\n");
    } else {
        printf("✗ Canonical UPER unexpectedly accepted non-minimal encoding\n");
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
    }
    
    /* Test 3: Test minimal encoding (should be accepted by both) */
    uint8_t minimal_data[] = {0x01, 0x42};
    
    integer = NULL;
    rval = uper_decode(&ctx_basic, &asn_DEF_INTEGER, (void **)&integer,
                       minimal_data, sizeof(minimal_data), 0, 0);
    
    if(rval.code == RC_OK) {
        printf("✓ Basic UPER accepted minimal encoding\n");
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
    } else {
        printf("✗ Basic UPER rejected minimal encoding\n");
    }
    
    integer = NULL;
    rval = uper_decode(&ctx_canonical, &asn_DEF_INTEGER, (void **)&integer,
                       minimal_data, sizeof(minimal_data), 0, 0);
    
    if(rval.code == RC_OK) {
        printf("✓ Canonical UPER accepted minimal encoding\n");
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
    } else {
        printf("✗ Canonical UPER rejected minimal encoding\n");
    }
}

static void test_canonical_functions(void) {
    INTEGER_t *integer = NULL;
    asn_dec_rval_t rval;
    
    /* Test the new canonical functions */
    uint8_t non_minimal_data[] = {0x02, 0x00, 0x42};
    
    printf("\nTesting canonical convenience functions...\n");
    
    /* Test canonical complete function */
    integer = NULL;
    rval = uper_decode_complete_canonical(NULL, &asn_DEF_INTEGER, (void **)&integer,
                                         non_minimal_data, sizeof(non_minimal_data));
    
    if(rval.code != RC_OK) {
        printf("✓ uper_decode_complete_canonical rejected non-minimal encoding\n");
    } else {
        printf("✗ uper_decode_complete_canonical accepted non-minimal encoding\n");
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
    }
    
    /* Test canonical function */
    integer = NULL;
    rval = uper_decode_canonical(NULL, &asn_DEF_INTEGER, (void **)&integer,
                                non_minimal_data, sizeof(non_minimal_data), 0, 0);
    
    if(rval.code != RC_OK) {
        printf("✓ uper_decode_canonical rejected non-minimal encoding\n");
    } else {
        printf("✗ uper_decode_canonical accepted non-minimal encoding\n");
        ASN_STRUCT_FREE(asn_DEF_INTEGER, integer);
    }
}

int main(void) {
    printf("Testing Canonical UPER Decoder\n");
    printf("===============================\n\n");
    
    test_canonical_integer_decoding();
    test_canonical_functions();
    
    printf("\nTest completed.\n");
    return 0;
}