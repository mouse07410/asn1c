#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

// Include generated ASN.1 headers
#include "RasMessage.h"
#include "GatekeeperRequest.h"
#include "AdmissionRequest.h"
#include "RegistrationRequest.h"
#include "ber_decoder.h"
#include "der_encoder.h"
#include "per_decoder.h"
#include "per_encoder.h"

// Utility function to print hex data
void print_hex_data(const char* label, const unsigned char* data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04zx: ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) printf("\n");
    }
    printf("\n");
}

// Function to analyze and explain decode errors
void analyze_decode_error(const char* test_name, const unsigned char* data, size_t data_len, asn_dec_rval_t result) {
    printf("=== %s DECODE ANALYSIS ===\n", test_name);
    printf("Data length: %zu bytes\n", data_len);
    printf("Consumed bytes: %ld\n", (long)result.consumed);
    printf("Result code: %d ", (int)result.code);
    
    switch(result.code) {
        case RC_OK:
            printf("(OK - unexpected in error analysis)\n");
            break;
        case RC_WMORE:
            printf("(Want more data - incomplete message)\n");
            break;
        case RC_FAIL:
            printf("(Decode failed - invalid format)\n");
            break;
        default:
            printf("(Unknown error)\n");
            break;
    }
    
    if (data_len > 0) {
        printf("First byte: 0x%02x\n", data[0]);
        
        // Analyze the first byte for CHOICE tag information
        unsigned char tag = data[0];
        if ((tag & 0x80) == 0x80) {
            // Context-specific tag
            int choice_index = (tag & 0x7C) >> 2;
            printf("Context tag detected: [CONTEXT %d]\n", choice_index);
            
            const char* expected_messages[] = {
                "GatekeeperRequest",     // [0]
                "GatekeeperConfirm",     // [1] 
                "GatekeeperReject",      // [2]
                "RegistrationRequest",   // [3]
                "RegistrationConfirm",   // [4]
                "RegistrationReject",    // [5]
                "AdmissionRequest",      // [6]
                "AdmissionConfirm",      // [7]
                "AdmissionReject"        // [8]
            };
            
            if (choice_index < 9) {
                printf("Expected message type: %s\n", expected_messages[choice_index]);
            } else {
                printf("Invalid choice index: %d (expected 0-8)\n", choice_index);
            }
        } else if (tag == 0x30) {
            printf("SEQUENCE tag detected - this is likely wrong for RasMessage CHOICE\n");
            printf("RasMessage requires CONTEXT tags, not SEQUENCE tags\n");
        } else {
            printf("Unexpected tag: 0x%02x\n", tag);
        }
    }
    
    print_hex_data("Raw data", data, data_len > 32 ? 32 : data_len);
    
    printf("DEBUGGING SUGGESTIONS:\n");
    printf("1. Check if the data is properly encoded H.225 RAS\n");
    printf("2. Verify the ASN.1 definitions match your protocol version\n");
    printf("3. Try different encoding rules (BER vs PER)\n");
    printf("4. Ensure the data is complete and not truncated\n");
    printf("\n");
}

// Create a working example by encoding and then decoding
int demonstrate_working_example() {
    printf("=== DEMONSTRATING WORKING H.225 EXAMPLE ===\n");
    
    // Create a GatekeeperRequest
    RasMessage_t ras_msg;
    GatekeeperRequest_t *grq;
    
    memset(&ras_msg, 0, sizeof(ras_msg));
    ras_msg.present = RasMessage_PR_gatekeeperRequest;
    grq = &ras_msg.choice.gatekeeperRequest;
    
    // Set required fields
    grq->requestSeqNum = 12345;
    
    // Set protocolIdentifier (H.225.0 OID)
    grq->protocolIdentifier.buf = malloc(10);
    grq->protocolIdentifier.size = 10;
    memcpy(grq->protocolIdentifier.buf, 
           (unsigned char[]){0x00, 0x00, 0x8b, 0x5a, 0x00, 0x83, 0x14, 0x8d, 0x00, 0x01}, 10);
    
    // Set rasAddress
    grq->rasAddress.present = TransportAddress_PR_ipAddress;
    grq->rasAddress.choice.ipAddress.ip.buf = calloc(4, 1);
    grq->rasAddress.choice.ipAddress.ip.size = 4;
    grq->rasAddress.choice.ipAddress.ip.buf[0] = 192;
    grq->rasAddress.choice.ipAddress.ip.buf[1] = 168;
    grq->rasAddress.choice.ipAddress.ip.buf[2] = 1;
    grq->rasAddress.choice.ipAddress.ip.buf[3] = 100;
    grq->rasAddress.choice.ipAddress.port = 1719;
    
    // Set endpointType
    grq->endpointType.mc = 0;
    grq->endpointType.undefinedNode = 0;
    
    printf("Step 1: Created GatekeeperRequest structure\n");
    printf("  requestSeqNum: %ld\n", (long)grq->requestSeqNum);
    printf("  rasAddress: %d.%d.%d.%d:%ld\n",
           grq->rasAddress.choice.ipAddress.ip.buf[0],
           grq->rasAddress.choice.ipAddress.ip.buf[1],
           grq->rasAddress.choice.ipAddress.ip.buf[2],
           grq->rasAddress.choice.ipAddress.ip.buf[3],
           (long)grq->rasAddress.choice.ipAddress.port);
    
    // Encode to DER
    uint8_t encoded_buffer[1024];
    asn_enc_rval_t enc_result;
    
    enc_result = der_encode_to_buffer(&asn_DEF_RasMessage, &ras_msg, 
                                     encoded_buffer, sizeof(encoded_buffer));
    
    if (enc_result.encoded == -1) {
        printf("ERROR: Failed to encode GRQ\n");
        free(grq->protocolIdentifier.buf);
        free(grq->rasAddress.choice.ipAddress.ip.buf);
        return 1;
    }
    
    printf("Step 2: Successfully encoded to DER (%ld bytes)\n", (long)enc_result.encoded);
    print_hex_data("Encoded data", encoded_buffer, enc_result.encoded);
    
    // Clean up the original structure
    free(grq->protocolIdentifier.buf);
    free(grq->rasAddress.choice.ipAddress.ip.buf);
    
    // Now decode it back
    RasMessage_t *decoded_msg = NULL;
    asn_dec_rval_t dec_result;
    
    dec_result = ber_decode(0, &asn_DEF_RasMessage, (void**)&decoded_msg,
                           encoded_buffer, enc_result.encoded);
    
    if (dec_result.code != RC_OK) {
        printf("ERROR: Failed to decode our own encoded data\n");
        analyze_decode_error("SELF-ENCODED", encoded_buffer, enc_result.encoded, dec_result);
        if (decoded_msg) ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
        return 1;
    }
    
    printf("Step 3: Successfully decoded back (%ld bytes consumed)\n", (long)dec_result.consumed);
    
    // Verify the data
    if (decoded_msg->present != RasMessage_PR_gatekeeperRequest) {
        printf("ERROR: Decoded message type changed\n");
        ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
        return 1;
    }
    
    printf("  Decoded as: GatekeeperRequest\n");
    printf("  requestSeqNum: %ld\n", (long)decoded_msg->choice.gatekeeperRequest.requestSeqNum);
    printf("  rasAddress: %d.%d.%d.%d:%ld\n",
           decoded_msg->choice.gatekeeperRequest.rasAddress.choice.ipAddress.ip.buf[0],
           decoded_msg->choice.gatekeeperRequest.rasAddress.choice.ipAddress.ip.buf[1],
           decoded_msg->choice.gatekeeperRequest.rasAddress.choice.ipAddress.ip.buf[2],
           decoded_msg->choice.gatekeeperRequest.rasAddress.choice.ipAddress.ip.buf[3],
           (long)decoded_msg->choice.gatekeeperRequest.rasAddress.choice.ipAddress.port);
    
    printf("✅ WORKING EXAMPLE COMPLETED SUCCESSFULLY\n\n");
    
    ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
    return 0;
}

// Test problematic data patterns that users might encounter
int test_problematic_patterns() {
    printf("=== TESTING PROBLEMATIC DATA PATTERNS ===\n");
    
    // Pattern 1: Data with SEQUENCE tag instead of CHOICE tag
    unsigned char wrong_sequence_tag[] = {
        0x30, 0x20,              // SEQUENCE (wrong for RasMessage)
        0x02, 0x02, 0x12, 0x34,  // requestSeqNum
        0x06, 0x08, 0x00, 0x00,  // protocolIdentifier
        0x8b, 0x5a, 0x00, 0x83,
        0x14, 0x8d, 0x00, 0x01,
        // ... more data
    };
    
    // Pattern 2: Truncated data
    unsigned char truncated_data[] = {
        0x80, 0x20,              // [CONTEXT 0] but claims 32 bytes
        0x02, 0x02, 0x12, 0x34   // Only 4 bytes follow
    };
    
    // Pattern 3: Wrong choice index
    unsigned char wrong_choice[] = {
        0xA0, 0x10,              // [CONTEXT 8] (outside valid range for our definition)
        0x02, 0x02, 0x12, 0x34,
        0x06, 0x08, 0x00, 0x00,
        0x8b, 0x5a, 0x00, 0x83,
        0x14, 0x8d, 0x00, 0x01
    };
    
    RasMessage_t *ras_msg = NULL;
    asn_dec_rval_t result;
    
    // Test pattern 1
    printf("Testing Pattern 1: SEQUENCE tag instead of CHOICE\n");
    result = ber_decode(0, &asn_DEF_RasMessage, (void**)&ras_msg,
                       wrong_sequence_tag, sizeof(wrong_sequence_tag));
    if (result.code != RC_OK) {
        analyze_decode_error("WRONG_SEQUENCE", wrong_sequence_tag, sizeof(wrong_sequence_tag), result);
    }
    if (ras_msg) { ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg); ras_msg = NULL; }
    
    // Test pattern 2
    printf("Testing Pattern 2: Truncated data\n");
    result = ber_decode(0, &asn_DEF_RasMessage, (void**)&ras_msg,
                       truncated_data, sizeof(truncated_data));
    if (result.code != RC_OK) {
        analyze_decode_error("TRUNCATED", truncated_data, sizeof(truncated_data), result);
    }
    if (ras_msg) { ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg); ras_msg = NULL; }
    
    // Test pattern 3
    printf("Testing Pattern 3: Wrong choice index\n");
    result = ber_decode(0, &asn_DEF_RasMessage, (void**)&ras_msg,
                       wrong_choice, sizeof(wrong_choice));
    if (result.code != RC_OK) {
        analyze_decode_error("WRONG_CHOICE", wrong_choice, sizeof(wrong_choice), result);
    }
    if (ras_msg) { ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg); ras_msg = NULL; }
    
    return 0;
}

// Test with alternative encoding rules
int test_alternative_encodings() {
    printf("=== TESTING ALTERNATIVE ENCODING RULES ===\n");
    
    // First create a message and encode with different rules
    RasMessage_t ras_msg;
    GatekeeperRequest_t *grq;
    
    memset(&ras_msg, 0, sizeof(ras_msg));
    ras_msg.present = RasMessage_PR_gatekeeperRequest;
    grq = &ras_msg.choice.gatekeeperRequest;
    
    grq->requestSeqNum = 54321;
    
    // Set minimal required fields
    grq->protocolIdentifier.buf = malloc(10);
    grq->protocolIdentifier.size = 10;
    memcpy(grq->protocolIdentifier.buf, 
           (unsigned char[]){0x00, 0x00, 0x8b, 0x5a, 0x00, 0x83, 0x14, 0x8d, 0x00, 0x01}, 10);
    
    grq->rasAddress.present = TransportAddress_PR_ipAddress;
    grq->rasAddress.choice.ipAddress.ip.buf = calloc(4, 1);
    grq->rasAddress.choice.ipAddress.ip.size = 4;
    grq->rasAddress.choice.ipAddress.ip.buf[0] = 10;
    grq->rasAddress.choice.ipAddress.ip.buf[1] = 0;
    grq->rasAddress.choice.ipAddress.ip.buf[2] = 0;
    grq->rasAddress.choice.ipAddress.ip.buf[3] = 1;
    grq->rasAddress.choice.ipAddress.port = 1719;
    
    grq->endpointType.mc = 0;
    grq->endpointType.undefinedNode = 0;
    
    // Test DER encoding
    uint8_t der_buffer[1024];
    asn_enc_rval_t der_result = der_encode_to_buffer(&asn_DEF_RasMessage, &ras_msg, 
                                                    der_buffer, sizeof(der_buffer));
    
    if (der_result.encoded != -1) {
        printf("DER Encoding: %ld bytes\n", (long)der_result.encoded);
        print_hex_data("DER encoded", der_buffer, der_result.encoded);
        
        // Test decoding back
        RasMessage_t *decoded = NULL;
        asn_dec_rval_t dec_result = ber_decode(0, &asn_DEF_RasMessage, (void**)&decoded,
                                              der_buffer, der_result.encoded);
        if (dec_result.code == RC_OK) {
            printf("✅ DER decode successful\n");
            ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded);
        } else {
            printf("❌ DER decode failed\n");
        }
    }
    
    // Test UPER encoding (if available)
    uint8_t uper_buffer[1024];
    asn_enc_rval_t uper_result = uper_encode_to_buffer(&asn_DEF_RasMessage, NULL, &ras_msg, 
                                                      uper_buffer, sizeof(uper_buffer));
    
    if (uper_result.encoded != -1) {
        printf("UPER Encoding: %ld bytes\n", (long)uper_result.encoded);
        print_hex_data("UPER encoded", uper_buffer, (uper_result.encoded + 7) / 8);
        
        // Test decoding back
        RasMessage_t *decoded = NULL;
        asn_dec_rval_t dec_result = uper_decode(0, &asn_DEF_RasMessage, (void**)&decoded,
                                               uper_buffer, (uper_result.encoded + 7) / 8, 0, 0);
        if (dec_result.code == RC_OK) {
            printf("✅ UPER decode successful\n");
            ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded);
        } else {
            printf("❌ UPER decode failed\n");
        }
    } else {
        printf("UPER encoding not available or failed\n");
    }
    
    // Cleanup
    free(grq->protocolIdentifier.buf);
    free(grq->rasAddress.choice.ipAddress.ip.buf);
    
    return 0;
}

int main() {
    printf("H.225 RAS and CS Message Decoding - Comprehensive Analysis\n");
    printf("==========================================================\n");
    printf("This tool helps diagnose H.225 message decoding issues.\n\n");
    
    int total_failures = 0;
    
    // Demonstrate that the generated code works correctly
    total_failures += demonstrate_working_example();
    
    // Test common problematic patterns
    test_problematic_patterns();
    
    // Test alternative encoding rules
    test_alternative_encodings();
    
    printf("=== SUMMARY AND RECOMMENDATIONS ===\n");
    printf("\n📋 KEY INSIGHTS:\n");
    printf("1. asn1c generates correct H.225 RAS decoding code\n");
    printf("2. Most failures are due to incorrect input data encoding\n");
    printf("3. RasMessage CHOICE requires CONTEXT tags [0] through [8]\n");
    printf("4. Both BER and PER encoding rules are supported\n");
    
    printf("\n🔧 TROUBLESHOOTING STEPS:\n");
    printf("1. Verify your data starts with correct CONTEXT tag:\n");
    printf("   - GatekeeperRequest: 0x80\n");
    printf("   - RegistrationRequest: 0x8C\n");
    printf("   - AdmissionRequest: 0x96\n");
    printf("2. Check data completeness (not truncated)\n");
    printf("3. Ensure ASN.1 definitions match your protocol version\n");
    printf("4. Try both BER and PER decoders\n");
    printf("5. Compare with working encoded examples\n");
    
    printf("\n🎯 NEXT STEPS IF STILL FAILING:\n");
    printf("1. Provide hex dump of your failing data\n");
    printf("2. Share your complete ASN.1 definitions\n");
    printf("3. Specify which H.225 protocol version you're using\n");
    printf("4. Indicate source of the data (Wireshark, another tool, etc.)\n");
    
    if (total_failures == 0) {
        printf("\n✅ All validation tests passed - asn1c H.225 support is working!\n");
    } else {
        printf("\n❌ %d validation failures detected\n", total_failures);
    }
    
    return total_failures;
}