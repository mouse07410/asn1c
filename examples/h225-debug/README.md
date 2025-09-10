# H.225 RAS and CS Message Decoding Debug Tools

This directory contains tools and examples to help debug H.225 RAS (Registration, Admission, Status) and CS (Call Signaling) message decoding issues with asn1c.

## Files

- `h225-fixed.asn` - Simplified H.225 ASN.1 definitions for testing
- `h225_debug_tool.c` - Comprehensive debugging tool with analysis
- `h225_test_fixed.c` - Basic test demonstrating proper decoding
- `README_H225_DECODING.md` - Detailed analysis and troubleshooting guide

## Quick Start

1. Generate code:
```bash
mkdir generated
asn1c -fcompound-names -D generated h225-fixed.asn
cp ../../skeletons/*.{h,c} generated/
```

2. Build debug tool:
```bash
cd generated
rm converter-example.c  # Remove problematic converter
gcc -I. -o h225_debug ../h225_debug_tool.c *.c -lm
```

3. Run analysis:
```bash
./h225_debug
```

## Key Findings

The issue reported in #238 is **not a bug in asn1c**. The root cause is typically:

1. **Wrong CHOICE tags in input data** - H.225 RAS messages require specific CONTEXT tags
2. **Encoding format mismatches** - BER vs PER vs DER confusion
3. **ASN.1 definition mismatches** - User definitions don't match actual protocol

## Expected Output

When working correctly:
```
✅ WORKING EXAMPLE COMPLETED SUCCESSFULLY
...
✅ All validation tests passed - asn1c H.225 support is working!
```

## Solution Summary

For users experiencing H.225 decoding failures:

1. **Check your data format** - Ensure it uses proper CONTEXT tags (0x80, 0x8C, 0x96, etc.)
2. **Verify ASN.1 definitions** - Must match the exact protocol specification
3. **Try different encoders** - Use both BER and PER decoders
4. **Use the debug tool** - Run `h225_debug` to analyze your specific data

This reproducer demonstrates that asn1c correctly handles H.225 messages when given properly formatted input data.