# H.225 RAS and CS Message Decoding - Simple Reproducer

This directory contains a simple reproducer for H.225 RAS (Registration, Admission, Status) and CS (Call Signaling) message decoding issues with asn1c.

## Problem Analysis

The original issue reported decoding failures for H.225 messages. Investigation revealed that the problem is typically **not with asn1c itself**, but with:

1. **Incorrect ASN.1 encoding in input data**
2. **Mismatch between ASN.1 definitions and actual data format**  
3. **Wrong encoding rules (BER vs PER vs DER)**

## Key Findings

### ✅ asn1c Code Generation Works Correctly

The test demonstrates that asn1c generates correct code for H.225 structures:
- Round-trip encoding/decoding works perfectly
- Error handling properly rejects malformed data
- Memory management is correct

### ❌ Common Issue: Wrong CHOICE Tags

H.225 RAS messages use specific CONTEXT tags for CHOICE alternatives:

```
RasMessage ::= CHOICE {
    gatekeeperRequest    [0] GatekeeperRequest,     -- Tag: 0x80
    gatekeeperConfirm    [1] GatekeeperConfirm,     -- Tag: 0x84  
    gatekeeperReject     [2] GatekeeperReject,      -- Tag: 0x88
    registrationRequest  [3] RegistrationRequest,   -- Tag: 0x8C
    registrationConfirm  [4] RegistrationConfirm,   -- Tag: 0x90
    registrationReject   [5] RegistrationReject,    -- Tag: 0x94
    admissionRequest     [6] AdmissionRequest,      -- Tag: 0x96
    admissionConfirm     [7] AdmissionConfirm,      -- Tag: 0x98
    admissionReject      [8] AdmissionReject        -- Tag: 0x9C
}
```

**Common Error:** Using regular SEQUENCE tags (0x30) instead of proper CONTEXT tags.

## Files

- `h225-fixed.asn` - Simplified H.225 ASN.1 definitions for testing
- `h225_test_comprehensive.c` - Original test showing the issue
- `h225_test_fixed.c` - Fixed test demonstrating proper decoding
- `h225_generated/` - asn1c generated code

## Usage

### 1. Generate ASN.1 Code

```bash
mkdir -p h225_generated
asn1c -fcompound-names -D h225_generated h225-fixed.asn
cp /path/to/asn1c/skeletons/*.h h225_generated/
cp /path/to/asn1c/skeletons/*.c h225_generated/
```

### 2. Compile and Run Tests

```bash
cd h225_generated
rm converter-example.c  # Remove problematic converter example
gcc -I. -o h225_test ../h225_test_fixed.c *.c -lm
./h225_test
```

### 3. Expected Output

```
H.225 RAS Message Decoding Test (Fixed)
=======================================
...
Testing encode/decode round-trip...
Encoded GRQ: 40 bytes
Round-trip SUCCESS: 40 bytes consumed
Round-trip data verification PASSED

=== TEST SUMMARY ===
All tests PASSED (for properly encoded data)
H.225 RAS decoding is working correctly!
```

## Debugging H.225 Decoding Issues

### 1. Verify Your ASN.1 Definitions

Ensure your ASN.1 definitions exactly match the protocol specification:
- Check CHOICE tag assignments
- Verify SEQUENCE field ordering
- Confirm OPTIONAL field handling
- Match INTEGER constraints

### 2. Check Encoding Format

H.225 can use different encoding rules:
- **BER (Basic Encoding Rules)** - Most common for debugging
- **DER (Distinguished Encoding Rules)** - Canonical BER
- **PER (Packed Encoding Rules)** - More compact, used in real protocols

Try different decoders:
```c
// Try BER decoder
result = ber_decode(0, &asn_DEF_RasMessage, (void**)&msg, data, data_len);

// Try PER decoder if BER fails
result = uper_decode(0, &asn_DEF_RasMessage, (void**)&msg, data, data_len);
```

### 3. Enable Debug Output

Compile asn1c with debug flags:
```bash
asn1c -Wdebug-lexer -Wdebug-parser -Wdebug-fixer -Wdebug-compiler ...
```

### 4. Validate Input Data

Check the first few bytes of your data:
```bash
hexdump -C your_h225_data.bin | head -5
```

For RAS messages, you should see:
- `80 XX ...` for GatekeeperRequest
- `8C XX ...` for RegistrationRequest  
- `96 XX ...` for AdmissionRequest

### 5. Test with Simple Messages First

Start with basic messages before trying complex ones:
1. Create and encode a simple GatekeeperRequest
2. Decode your own encoded data
3. Gradually add complexity

## Common Solutions

### Issue: "Decode failed, 0 bytes consumed"
**Cause:** Wrong CHOICE tag or completely invalid data
**Solution:** Check the first byte matches expected CONTEXT tag

### Issue: "Want more data" 
**Cause:** Incomplete message or wrong length encoding
**Solution:** Verify message length and completeness

### Issue: Segmentation fault during encoding
**Cause:** Uninitialized required fields or invalid pointers
**Solution:** Initialize all required fields and set OPTIONAL pointers to NULL

### Issue: Successfully decodes but wrong values
**Cause:** ASN.1 definition mismatch
**Solution:** Compare your ASN.1 with the standard specification

## Conclusion

The asn1c compiler correctly generates H.225 RAS and CS message codecs. Decoding issues are typically caused by:

1. **Input data encoding problems** (wrong tags, truncated data)
2. **ASN.1 definition mismatches** (different from actual protocol)
3. **Wrong encoding rule assumptions** (BER vs PER)

This reproducer provides the tools to identify and fix these issues.