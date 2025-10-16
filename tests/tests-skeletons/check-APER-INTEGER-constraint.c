/* Test for APER INTEGER constraint validation during decoding */

#include <stdio.h>
#include <assert.h>

#include <INTEGER.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <per_support.c>
#include <per_support.h>
#include <aper_support.c>
#include <aper_support.h>

static void
test_decode_out_of_bounds_small_range() {
    INTEGER_t *st = NULL;
    asn_per_data_t pd;
    asn_dec_rval_t dec_rval;
    struct asn_per_constraints_s cts;
    struct asn_INTEGER_specifics_s specs;
    
    printf("Test 1: INTEGER (1..100) with out-of-bounds encoded value\n");
    
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));
    
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 7;  // 100 values (0..99 offset) requires 7 bits
    cts.value.effective_bits = 7;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 100;
    
    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;
    
    asn_DEF_INTEGER.specifics = &specs;
    
    /* 
     * Input: 0xfe = 11111110 in binary
     * With 7 bits: 1111110 = 126 (decimal)
     * After adding lower_bound (1): 126 + 1 = 127
     * This is out of range [1..100], so decoding should fail
     */
    uint8_t input_data[] = { 0xfe };
    
    pd.buffer = input_data;
    pd.nboff = 0;
    pd.nbits = 8;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, (void **)&st, &pd);
    
    if (dec_rval.code == RC_OK) {
        long value = 0;
        asn_INTEGER2long(st, &value);
        printf("  ERROR: Decoded out-of-bounds value %ld (should have failed)\n", value);
        assert(!"Decoding should have failed for out-of-bounds value");
    } else {
        printf("  PASS: Decoding correctly failed for out-of-bounds value\n");
    }
    
    if(st) ASN_STRUCT_FREE(asn_DEF_INTEGER, st);
}

static void
test_decode_in_bounds_small_range() {
    INTEGER_t *st = NULL;
    asn_per_data_t pd;
    asn_dec_rval_t dec_rval;
    struct asn_per_constraints_s cts;
    struct asn_INTEGER_specifics_s specs;
    
    printf("Test 2: INTEGER (1..100) with in-bounds encoded value\n");
    
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));
    
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 7;  // 100 values requires 7 bits
    cts.value.effective_bits = 7;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 100;
    
    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;
    
    asn_DEF_INTEGER.specifics = &specs;
    
    /* 
     * Input: 0x62 = 01100010 in binary
     * With 7 bits: 1100010 = 98 (decimal offset from 0)
     * After adding lower_bound (1): 98 + 1 = 99
     * This is within range [1..100], so decoding should succeed
     */
    uint8_t input_data[] = { 0x62 };
    
    pd.buffer = input_data;
    pd.nboff = 0;
    pd.nbits = 8;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, (void **)&st, &pd);
    
    if (dec_rval.code != RC_OK) {
        printf("  ERROR: Decoding failed for in-bounds value (code=%d)\n", dec_rval.code);
        assert(!"Decoding should have succeeded for in-bounds value");
    } else {
        long value = 0;
        asn_INTEGER2long(st, &value);
        printf("  PASS: Decoded value %ld (within bounds [1..100])\n", value);
        assert(value >= 1 && value <= 100);
    }
    
    if(st) ASN_STRUCT_FREE(asn_DEF_INTEGER, st);
}

static void
test_decode_out_of_bounds_large_range() {
    INTEGER_t st;
    INTEGER_t *reconstructed_st = NULL;
    struct asn_INTEGER_specifics_s specs;
    struct asn_per_constraints_s cts;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    
    printf("Test 3: INTEGER (1..1000000) encode/decode with manually corrupted value\n");
    
    memset(&st, 0, sizeof(st));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));
    
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 20;  // 1000000 values requires 20 bits
    cts.value.effective_bits = 20;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 1000000;
    
    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;
    
    asn_DEF_INTEGER.specifics = &specs;
    
    /* Encode a valid value first */
    long test_value = 500000;
    asn_long2INTEGER(&st, test_value);
    
    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = (asn_app_consume_bytes_f *)0;  /* Will fail if overflow */
    
    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, &cts, &st, &po);
    assert(enc_rval.encoded >= 0);
    
    /* Now manually corrupt the encoded data to create an out-of-bounds value
     * For range_bits=20, the format is: length_bits + aligned_bytes
     * We'll modify the bytes to create a value > 999999 (max offset from 1) */
    size_t encoded_bytes = (po.buffer - po.tmpspace) + ((po.nboff + 7) / 8);
    if (encoded_bytes >= 3) {
        /* Corrupt the value bytes to be 0xFFFFFF which >> 999999 */
        po.tmpspace[encoded_bytes - 3] = 0xFF;
        po.tmpspace[encoded_bytes - 2] = 0xFF;
        po.tmpspace[encoded_bytes - 1] = 0xFF;
    }
    
    /* Try to decode the corrupted data */
    pd.buffer = po.tmpspace;
    pd.nboff = 0;
    pd.nbits = 8 * encoded_bytes;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, (void **)&reconstructed_st, &pd);
    
    if (dec_rval.code == RC_OK) {
        long value = 0;
        asn_INTEGER2long(reconstructed_st, &value);
        printf("  ERROR: Decoded out-of-bounds value %ld (should have failed)\n", value);
        assert(!"Decoding should have failed for out-of-bounds value");
    } else {
        printf("  PASS: Decoding correctly failed for corrupted out-of-bounds value\n");
    }
    
    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    if(reconstructed_st) ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
}

static void
test_decode_in_bounds_large_range() {
    INTEGER_t st;
    INTEGER_t *reconstructed_st = NULL;
    struct asn_INTEGER_specifics_s specs;
    struct asn_per_constraints_s cts;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    
    printf("Test 4: INTEGER (1..1000000) with in-bounds encoded value\n");
    
    memset(&st, 0, sizeof(st));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));
    
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 20;  // 1000000 values requires 20 bits
    cts.value.effective_bits = 20;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 1000000;
    
    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;
    
    asn_DEF_INTEGER.specifics = &specs;
    
    /* Test encoding and decoding a valid value near upper bound */
    long test_value = 1000000;  // Max value
    asn_long2INTEGER(&st, test_value);
    
    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = (asn_app_consume_bytes_f *)0;
    
    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, &cts, &st, &po);
    if (enc_rval.encoded < 0) {
        printf("  ERROR: Encoding failed\n");
        assert(!"Encoding should have succeeded");
    }
    
    /* Decode it back */
    size_t encoded_bytes = (po.buffer - po.tmpspace) + ((po.nboff + 7) / 8);
    pd.buffer = po.tmpspace;
    pd.nboff = 0;
    pd.nbits = 8 * encoded_bytes;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, (void **)&reconstructed_st, &pd);
    
    if (dec_rval.code != RC_OK) {
        printf("  ERROR: Decoding failed for in-bounds value (code=%d)\n", dec_rval.code);
        assert(!"Decoding should have succeeded for in-bounds value");
    } else {
        long value = 0;
        asn_INTEGER2long(reconstructed_st, &value);
        printf("  PASS: Decoded value %ld (within bounds [1..1000000])\n", value);
        assert(value >= 1 && value <= 1000000);
        assert(value == test_value);
    }
    
    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    if(reconstructed_st) ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
}

static void
test_decode_boundary_values() {
    INTEGER_t *st = NULL;
    asn_per_data_t pd;
    asn_dec_rval_t dec_rval;
    struct asn_per_constraints_s cts;
    struct asn_INTEGER_specifics_s specs;
    
    printf("Test 5: INTEGER (1..100) boundary values\n");
    
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));
    
    cts.value.flags = APC_CONSTRAINED;
    cts.value.range_bits = 7;
    cts.value.effective_bits = 7;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 100;
    
    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;
    
    asn_DEF_INTEGER.specifics = &specs;
    
    /* Test lower boundary: offset 0 -> value 1 */
    uint8_t input_lower[] = { 0x00 };
    pd.buffer = input_lower;
    pd.nboff = 0;
    pd.nbits = 8;
    pd.moved = 0;
    
    st = NULL;
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, (void **)&st, &pd);
    if (dec_rval.code == RC_OK) {
        long value = 0;
        asn_INTEGER2long(st, &value);
        printf("  PASS: Lower boundary value %ld decoded successfully\n", value);
        assert(value == 1);
    } else {
        printf("  ERROR: Failed to decode lower boundary\n");
        assert(!"Should decode lower boundary");
    }
    if(st) ASN_STRUCT_FREE(asn_DEF_INTEGER, st);
    
    /* Test upper boundary: offset 99 -> value 100 */
    uint8_t input_upper[] = { 0xc6 };  /* 11000110, first 7 bits = 1100011 = 99 */
    pd.buffer = input_upper;
    pd.nboff = 0;
    pd.nbits = 8;
    pd.moved = 0;
    
    st = NULL;
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts, (void **)&st, &pd);
    if (dec_rval.code == RC_OK) {
        long value = 0;
        asn_INTEGER2long(st, &value);
        printf("  PASS: Upper boundary value %ld decoded successfully\n", value);
        assert(value == 100);
    } else {
        printf("  ERROR: Failed to decode upper boundary\n");
        assert(!"Should decode upper boundary");
    }
    if(st) ASN_STRUCT_FREE(asn_DEF_INTEGER, st);
}

int main() {
    test_decode_in_bounds_small_range();
    printf("\n");
    test_decode_out_of_bounds_small_range();
    printf("\n");
    test_decode_in_bounds_large_range();
    printf("\n");
    test_decode_out_of_bounds_large_range();
    printf("\n");
    test_decode_boundary_values();
    printf("\n");
    
    printf("All tests passed!\n");
    return 0;
}
