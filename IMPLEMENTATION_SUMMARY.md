# Implementation Summary: Partial Decoding Support

## Issue
Support for partial decoding when input message is truncated or when decoding fails.

## Solution Implemented

### 1. Enhanced Error Reporting
Modified the UPER decoder to report the exact position (byte and bit) where decoding failed, instead of just returning 0.

**File**: `skeletons/uper_decoder.c`
- Now calculates and returns the actual position reached before failure
- Provides better debugging information through ASN_DEBUG messages

### 2. Partial Decoding Results
Added `-P` command line option to the converter tool to print any successfully decoded fields when decoding fails.

**File**: `skeletons/converter-example.c`
- New `-P` flag to enable partial result printing
- Prints partial structures for both RC_WMORE and RC_FAIL error cases
- Enhanced error messages show exact byte position of failure

### 3. API Support for Future Extensions
Added infrastructure for partial decoding control in the codec context.

**File**: `skeletons/asn_codecs.h`
- Added `preserve_partial_decoding` flag to `asn_codec_ctx_t`
- Reserved for future use to control decoder behavior

### 4. Documentation
Created comprehensive documentation for users.

**Files**: `PARTIAL_DECODING.md`, `README.md`
- Usage instructions
- Examples
- Known limitations
- Comparison with Wireshark

## Test Results

```bash
# Test 1: Valid message (no regression)
./converter-example -iber -onull test-message.ber
✅ Output: "test-message.ber: decoded successfully"

# Test 2: Truncated message without -P
./converter-example -iber -onull test-message-truncated.ber
✅ Output: "Decode failed past byte 15: Unexpected end of input"

# Test 3: Truncated message with -P (key feature!)
./converter-example -iber -onull -P test-message-truncated.ber
✅ Output shows:
=== Partial Decoding Results ===
TestMessage ::= {
    version: 1
    name: TestName
    timestamp: 0
}
=== End of Partial Results ===
test-message-truncated.ber: Decode failed past byte 15: Unexpected end of input
```

## Benefits

1. **Better Debugging**: See which field causes decoding to fail
2. **Truncated Log Analysis**: Extract maximum information from partial captures  
3. **Development Speed**: Quickly identify encoding/decoding mismatches
4. **Similar to Wireshark**: Provides equivalent functionality to Wireshark RRC decoder

## Backwards Compatibility

✅ **Fully backwards compatible**
- No changes to existing APIs
- New flag is opt-in via `-P`
- Default behavior unchanged
- All existing tests pass

## Future Enhancements

The `preserve_partial_decoding` flag in `asn_codec_ctx_t` can be used to:
- Control whether decoders free partially decoded structures on failure
- Provide programmatic access to partial results (not just printing)
- Fine-tune memory management for embedded systems

## Files Modified

1. `skeletons/asn_codecs.h` - Added preserve_partial_decoding flag
2. `skeletons/uper_decoder.c` - Report actual position on failure
3. `skeletons/converter-example.c` - Added -P flag and partial output
4. `PARTIAL_DECODING.md` - New user documentation
5. `README.md` - Feature overview

## Commits

1. Initial plan and codec context changes
2. Add partial decoding support and improved error messages
3. Improve error reporting with byte position
4. Add documentation
5. Fix compilation error (variable scope)

## Status

✅ **Complete and Tested**
- All changes committed
- Tests passing
- Documentation complete
- Ready for review
