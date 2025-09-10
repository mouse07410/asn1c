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

// Corrected test data with proper CHOICE tags
// GatekeeperRequest should use [CONTEXT 0] = 0x80

static unsigned char sample_grq_data[] = {
    // RasMessage CHOICE with gatekeeperRequest [0] IMPLICIT
    0x80, 0x2F,              // [CONTEXT 0] IMPLICIT, length 47
    0x02, 0x02, 0x12, 0x34,  // requestSeqNum: 4660
    0x06, 0x08, 0x00, 0x00,  // protocolIdentifier (H.225.0 OID)
    0x8b, 0x5a, 0x00, 0x83,
    0x14, 0x8d, 0x00, 0x01,
    0x80, 0x06,              // rasAddress (ipAddress)
    0x04, 0x04, 0xc0, 0xa8,  // IP: 192.168.1.100
    0x01, 0x64, 0x02, 0x02, 0x06, 0xb7,  // Port: 1719
    0x81, 0x08,              // endpointType
    0x86, 0x01, 0x01,        // terminal = true
    0x87, 0x01, 0x00,        // mc = false
    0x88, 0x01, 0x00         // undefinedNode = false
};

// RegistrationRequest should use [CONTEXT 3] = 0x8C
static unsigned char sample_rrq_data[] = {
    // RasMessage CHOICE with registrationRequest [3] IMPLICIT
    0x8C, 0x45,              // [CONTEXT 3] IMPLICIT, length 69
    0x02, 0x02, 0x9a, 0xbc,  // requestSeqNum: 39612
    0x06, 0x08, 0x00, 0x00,  // protocolIdentifier (H.225.0 OID)
    0x8b, 0x5a, 0x00, 0x83,
    0x14, 0x8d, 0x00, 0x01,
    0x01, 0x01, 0x01,        // discoveryComplete: true
    0x30, 0x08,              // callSignalAddress (SEQUENCE OF)
    0x80, 0x06,              // ipAddress
    0x04, 0x04, 0xc0, 0xa8,  // IP: 192.168.1.10
    0x01, 0x0a, 0x02, 0x02, 0x13, 0xc4,  // Port: 5060
    0x30, 0x08,              // rasAddress (SEQUENCE OF)
    0x80, 0x06,              // ipAddress
    0x04, 0x04, 0xc0, 0xa8,  // IP: 192.168.1.10  
    0x01, 0x0a, 0x02, 0x02, 0x13, 0xc5,  // Port: 5061
    0x30, 0x06,              // endpointType
    0x86, 0x01, 0x01,        // terminal: true
    0x87, 0x01, 0x00,        // mc: false
    0x88, 0x01, 0x00         // undefinedNode: false
};

// AdmissionRequest should use [CONTEXT 6] = 0x96
static unsigned char sample_arq_data[] = {
    // RasMessage CHOICE with admissionRequest [6] IMPLICIT
    0x96, 0x50,              // [CONTEXT 6] IMPLICIT, length 80
    0x02, 0x02, 0x56, 0x78,  // requestSeqNum: 22136
    0x80, 0x01, 0x00,        // callType: pointToPoint
    0x01, 0x10,              // endpointIdentifier "EP001" (simplified encoding)
    0x00, 0x45, 0x00, 0x50,  // "EP001" in UTF-16
    0x00, 0x30, 0x00, 0x30,
    0x00, 0x31, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x02, 0x04, 0x00, 0x01, 0x86, 0xa0,  // bandWidth: 100000
    0x02, 0x02, 0x12, 0x34,  // callReferenceValue: 4660
    0x04, 0x10,              // conferenceID (16 bytes)
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef,
    0x01, 0x01, 0x01,        // activeMC: true
    0x01, 0x01, 0x00,        // answerCall: false
    0x01, 0x01, 0x01,        // canMapAlias: true
    0x30, 0x12,              // callIdentifier
    0x04, 0x10,              // GUID (16 bytes)
    0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10,
    0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};

// Function to print decode error details
void print_decode_error(const char* test_name, asn_dec_rval_t result) {
    printf("=== %s DECODE FAILED ===\n", test_name);
    printf("Decode result code: %d\n", (int)result.code);
    printf("Consumed bytes: %ld\n", (long)result.consumed);
    
    switch(result.code) {
        case RC_OK:
            printf("Status: OK (unexpected)\n");
            break;
        case RC_WMORE:
            printf("Status: Want more data\n");
            break;
        case RC_FAIL:
            printf("Status: Decode failed\n");
            break;
        default:
            printf("Status: Unknown error code\n");
            break;
    }
    printf("\n");
}

// Test function for basic GRQ decoding
int test_grq_decode() {
    printf("Testing GatekeeperRequest decoding...\n");
    
    RasMessage_t *ras_msg = NULL;
    asn_dec_rval_t result;
    
    // Test with corrected GRQ data
    result = ber_decode(0, &asn_DEF_RasMessage, (void**)&ras_msg, 
                       sample_grq_data, sizeof(sample_grq_data));
    
    if (result.code != RC_OK) {
        print_decode_error("GRQ", result);
        if (ras_msg) ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
        return 1;
    }
    
    printf("GRQ decode SUCCESS: consumed %ld bytes\n", (long)result.consumed);
    
    // Verify it's a GatekeeperRequest
    if (ras_msg->present != RasMessage_PR_gatekeeperRequest) {
        printf("ERROR: Expected GatekeeperRequest, got choice %d\n", ras_msg->present);
        ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
        return 1;
    }
    
    printf("Successfully decoded as GatekeeperRequest\n");
    printf("Request Seq Num: %ld\n", (long)ras_msg->choice.gatekeeperRequest.requestSeqNum);
    
    ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
    return 0;
}

// Test function for RRQ decoding
int test_rrq_decode() {
    printf("\nTesting RegistrationRequest decoding...\n");
    
    RasMessage_t *ras_msg = NULL;
    asn_dec_rval_t result;
    
    result = ber_decode(0, &asn_DEF_RasMessage, (void**)&ras_msg,
                       sample_rrq_data, sizeof(sample_rrq_data));
    
    if (result.code != RC_OK) {
        print_decode_error("RRQ", result);
        if (ras_msg) ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
        return 1;
    }
    
    printf("RRQ decode SUCCESS: consumed %ld bytes\n", (long)result.consumed);
    
    // Verify it's a RegistrationRequest
    if (ras_msg->present != RasMessage_PR_registrationRequest) {
        printf("ERROR: Expected RegistrationRequest, got choice %d\n", ras_msg->present);
        ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
        return 1;
    }
    
    printf("Successfully decoded as RegistrationRequest\n");
    printf("Request Seq Num: %ld\n", (long)ras_msg->choice.registrationRequest.requestSeqNum);
    
    ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
    return 0;
}

// Test function for ARQ decoding
int test_arq_decode() {
    printf("\nTesting AdmissionRequest decoding...\n");
    
    RasMessage_t *ras_msg = NULL;
    asn_dec_rval_t result;
    
    result = ber_decode(0, &asn_DEF_RasMessage, (void**)&ras_msg,
                       sample_arq_data, sizeof(sample_arq_data));
    
    if (result.code != RC_OK) {
        print_decode_error("ARQ", result);
        if (ras_msg) ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
        return 1;
    }
    
    printf("ARQ decode SUCCESS: consumed %ld bytes\n", (long)result.consumed);
    
    // Verify it's an AdmissionRequest
    if (ras_msg->present != RasMessage_PR_admissionRequest) {
        printf("ERROR: Expected AdmissionRequest, got choice %d\n", ras_msg->present);
        ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
        return 1;
    }
    
    printf("Successfully decoded as AdmissionRequest\n");
    printf("Request Seq Num: %ld\n", (long)ras_msg->choice.admissionRequest.requestSeqNum);
    
    ASN_STRUCT_FREE(asn_DEF_RasMessage, ras_msg);
    return 0;
}

// Simplified encode/decode round-trip test
int test_encode_decode_roundtrip() {
    printf("\nTesting encode/decode round-trip...\n");
    
    // Create a simple GatekeeperRequest using the structure directly
    RasMessage_t ras_msg;
    GatekeeperRequest_t *grq;
    
    memset(&ras_msg, 0, sizeof(ras_msg));
    ras_msg.present = RasMessage_PR_gatekeeperRequest;
    grq = &ras_msg.choice.gatekeeperRequest;
    
    // Set required fields
    grq->requestSeqNum = 12345;
    
    // Set protocolIdentifier to a simple OID
    grq->protocolIdentifier.buf = malloc(10);
    grq->protocolIdentifier.size = 10;
    memcpy(grq->protocolIdentifier.buf, 
           (unsigned char[]){0x00, 0x00, 0x8b, 0x5a, 0x00, 0x83, 0x14, 0x8d, 0x00, 0x01}, 10);
    
    // Set rasAddress to a simple IP address
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
    
    // Encode to DER
    asn_enc_rval_t enc_result;
    uint8_t *encoded_buffer = NULL;
    size_t encoded_size = 0;
    
    // Allocate a reasonable buffer size
    encoded_size = 1024;  // Should be enough for our simple message
    encoded_buffer = malloc(encoded_size);
    
    enc_result = der_encode_to_buffer(&asn_DEF_RasMessage, &ras_msg, 
                                     encoded_buffer, encoded_size);
    
    if (enc_result.encoded == -1) {
        printf("ERROR: Failed to encode GRQ: %s\n", 
               enc_result.failed_type ? enc_result.failed_type->name : "unknown");
        free(grq->protocolIdentifier.buf);
        free(grq->rasAddress.choice.ipAddress.ip.buf);
        free(encoded_buffer);
        return 1;
    }
    
    printf("Encoded GRQ: %ld bytes\n", (long)enc_result.encoded);
    
    // Now decode it back
    RasMessage_t *decoded_msg = NULL;
    asn_dec_rval_t dec_result;
    
    dec_result = ber_decode(0, &asn_DEF_RasMessage, (void**)&decoded_msg,
                           encoded_buffer, enc_result.encoded);
    
    free(encoded_buffer);
    free(grq->protocolIdentifier.buf);
    free(grq->rasAddress.choice.ipAddress.ip.buf);
    
    if (dec_result.code != RC_OK) {
        printf("ERROR: Failed to decode our own encoded data\n");
        print_decode_error("ROUNDTRIP", dec_result);
        if (decoded_msg) ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
        return 1;
    }
    
    printf("Round-trip SUCCESS: %ld bytes consumed\n", (long)dec_result.consumed);
    
    // Verify the data
    if (decoded_msg->present != RasMessage_PR_gatekeeperRequest) {
        printf("ERROR: Round-trip changed message type\n");
        ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
        return 1;
    }
    
    if (decoded_msg->choice.gatekeeperRequest.requestSeqNum != 12345) {
        printf("ERROR: Round-trip changed requestSeqNum\n");
        ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
        return 1;
    }
    
    printf("Round-trip data verification PASSED\n");
    ASN_STRUCT_FREE(asn_DEF_RasMessage, decoded_msg);
    return 0;
}

int main() {
    printf("H.225 RAS Message Decoding Test (Fixed)\n");
    printf("=======================================\n");
    printf("This test demonstrates the fix for H.225 RAS message decoding issues.\n\n");
    
    int test_failures = 0;
    
    // Run individual tests
    test_failures += test_grq_decode();
    test_failures += test_rrq_decode();
    test_failures += test_arq_decode();
    test_failures += test_encode_decode_roundtrip();
    
    printf("\n=== TEST SUMMARY ===\n");
    if (test_failures == 0) {
        printf("All tests PASSED\n");
        printf("H.225 RAS decoding is working correctly!\n");
        printf("\nThe issue was in the test data encoding.\n");
        printf("CHOICE types in ASN.1 require proper context tags.\n");
    } else {
        printf("Some tests FAILED (%d failures)\n", test_failures);
        printf("Further investigation needed.\n");
    }
    
    return test_failures;
}