/* Test for APER INTEGER extensible constraint in extension */

#include <stdio.h>
#include <assert.h>

#include <INTEGER.h>
#include <INTEGER.c>
#include <INTEGER_aper.c>
#include <per_support.c>
#include <per_support.h>

static int FailOut(const void *data, size_t size, void *op_key) {
    (void)data;
    (void)size;
    (void)op_key;
    assert(!"UNREACHABLE");
    return 0;
}

static void normalize(asn_per_outp_t *po) {
    if(po->nboff >= 8) {
        po->buffer += (po->nboff >> 3);
        po->nbits  -= (po->nboff & ~0x07);
        po->nboff  &= 0x07;
    }
}

static void
test_extensible_constraint_in_extension() {
    INTEGER_t st;
    INTEGER_t *reconstructed_st = 0;
    struct asn_INTEGER_specifics_s specs;
    struct asn_per_constraints_s cts;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    
    printf("Testing extensible constraint in extension...\n");

    memset(&st, 0, sizeof(st));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));

    // Set up extensible constraint like ExpectedActivityPeriod ::= INTEGER (1..181, ...)
    cts.value.flags = APC_CONSTRAINED | APC_EXTENSIBLE;
    cts.value.range_bits = 8;
    cts.value.effective_bits = 8;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 181;

    // Test encoding a value outside the root range (in extension)
    long test_value = 255;  // Outside 1..181 range
    asn_long2INTEGER(&st, test_value);

    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = FailOut;

    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;

    asn_DEF_INTEGER.specifics = &specs;
    
    // Encode the value
    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, &cts, &st, &po);
    if (enc_rval.encoded == -1) {
        printf("Encoding failed\n");
        return;
    }
    
    printf("Encoded successfully\n");
    
    normalize(&po);

    // Decode the value back
    pd.buffer = po.tmpspace;
    pd.nboff = 0;
    pd.nbits = 8 * (po.buffer - po.tmpspace) + po.nboff;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts,
                                   (void **)&reconstructed_st, &pd);
    
    if (dec_rval.code != RC_OK) {
        printf("Decoding failed: %d\n", dec_rval.code);
        return;
    }

    long reconstructed_value = 0;
    asn_INTEGER2long(reconstructed_st, &reconstructed_value);
    
    printf("Original value: %ld\n", test_value);
    printf("Reconstructed value: %ld\n", reconstructed_value);
    
    // The values should match
    if (reconstructed_value == test_value) {
        printf("SUCCESS: Values match\n");
    } else {
        printf("FAILURE: Values don't match\n");
    }

    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
}

static void
test_extensible_constraint_in_root() {
    INTEGER_t st;
    INTEGER_t *reconstructed_st = 0;
    struct asn_INTEGER_specifics_s specs;
    struct asn_per_constraints_s cts;
    asn_enc_rval_t enc_rval;
    asn_dec_rval_t dec_rval;
    asn_per_outp_t po;
    asn_per_data_t pd;
    
    printf("Testing extensible constraint in root range...\n");

    memset(&st, 0, sizeof(st));
    memset(&po, 0, sizeof(po));
    memset(&pd, 0, sizeof(pd));
    memset(&cts, 0, sizeof(cts));
    memset(&specs, 0, sizeof(specs));

    // Set up extensible constraint like ExpectedActivityPeriod ::= INTEGER (1..181, ...)
    cts.value.flags = APC_CONSTRAINED | APC_EXTENSIBLE;
    cts.value.range_bits = 8;
    cts.value.effective_bits = 8;
    cts.value.lower_bound = 1;
    cts.value.upper_bound = 181;

    // Test encoding a value inside the root range
    long test_value = 100;  // Inside 1..181 range
    asn_long2INTEGER(&st, test_value);

    po.buffer = po.tmpspace;
    po.nboff = 0;
    po.nbits = 8 * sizeof(po.tmpspace);
    po.output = FailOut;

    specs.field_width = sizeof(long);
    specs.field_unsigned = 0;

    asn_DEF_INTEGER.specifics = &specs;
    
    // Encode the value
    enc_rval = INTEGER_encode_aper(&asn_DEF_INTEGER, &cts, &st, &po);
    if (enc_rval.encoded == -1) {
        printf("Encoding failed\n");
        return;
    }
    
    printf("Encoded successfully\n");
    
    normalize(&po);

    // Decode the value back
    pd.buffer = po.tmpspace;
    pd.nboff = 0;
    pd.nbits = 8 * (po.buffer - po.tmpspace) + po.nboff;
    pd.moved = 0;
    
    dec_rval = INTEGER_decode_aper(0, &asn_DEF_INTEGER, &cts,
                                   (void **)&reconstructed_st, &pd);
    
    if (dec_rval.code != RC_OK) {
        printf("Decoding failed: %d\n", dec_rval.code);
        return;
    }

    long reconstructed_value = 0;
    asn_INTEGER2long(reconstructed_st, &reconstructed_value);
    
    printf("Original value: %ld\n", test_value);
    printf("Reconstructed value: %ld\n", reconstructed_value);
    
    // The values should match
    if (reconstructed_value == test_value) {
        printf("SUCCESS: Values match\n");
    } else {
        printf("FAILURE: Values don't match\n");
    }

    ASN_STRUCT_RESET(asn_DEF_INTEGER, &st);
    ASN_STRUCT_FREE(asn_DEF_INTEGER, reconstructed_st);
}

int main() {
    test_extensible_constraint_in_root();
    printf("\n");
    test_extensible_constraint_in_extension();
    return 0;
}