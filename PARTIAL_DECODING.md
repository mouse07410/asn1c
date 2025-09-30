# Partial Decoding Support

## Overview

This document describes the partial decoding feature that helps debug truncated or malformed ASN.1 messages.

## Problem Statement

When ASN.1 UPER/BER decoding fails, users previously received minimal error information:
- Generic error messages like "Decode failed past byte 0: Input processing error"
- No visibility into which field caused the failure
- No access to successfully decoded portions of the message

This made debugging difficult, especially when working with:
- Truncated log messages (e.g., only first 100 bytes captured)
- Corrupted message data
- Protocol implementation issues

## Solution

The implementation provides two key improvements:

### 1. Enhanced Error Messages

The decoder now reports the exact position where decoding failed:
```
test-message.uper: Decode failed at byte 12, bit 3: Input processing error
```

For PER/UPER encodings, both byte and bit positions are reported since PER is a bit-oriented encoding.

### 2. Partial Decoding Results

The converter tool (`converter-example`) now supports a `-P` flag that prints any successfully decoded fields when decoding fails.

## Usage

### Command Line Option

Add the `-P` flag when using the converter tool:

```bash
./converter-example -iber -P input-file.ber
```

### Example Output

When decoding a truncated message with `-P`:

```
=== Partial Decoding Results ===
TestMessage ::= {
    version: 1
    name: TestName
    timestamp: 0
    data: 
    flags: <absent>
}
=== End of Partial Results ===

test-message.ber: Decode failed past byte 15: Unexpected end of input
```

This shows:
- Fields that were successfully decoded (version, name)
- Fields that were partially decoded (timestamp showing default value)
- Fields that were not reached (data, flags)

## Technical Details

### Code Changes

1. **asn_codecs.h**: Added `preserve_partial_decoding` flag to `asn_codec_ctx_t`
2. **uper_decoder.c**: Modified to report exact bit position on failure
3. **converter-example.c**: Added `-P` option and partial structure printing

### How It Works

1. When decoding fails, the decoder tracks how many bits/bytes were successfully consumed
2. The partially decoded structure remains allocated in memory (not freed immediately)
3. If `-P` flag is set, the structure is printed to stderr before cleanup
4. Error message includes precise failure location

### Limitations

- Partial results are only available when the decoder has allocated and partially populated the structure
- Very early failures (e.g., in the first few bytes) may not have any partial structure to show
- This is expected behavior - if the structure allocation fails, there's nothing to print
- BER/DER encodings generally provide better partial results than PER/UPER for truncated messages

## Comparison with Wireshark

Similar to Wireshark's RRC decoder which prints all decoded fields followed by:
```
[Expert Info (Error/Malformed): Malformed Packet (Exception occurred)]
```

This implementation provides equivalent functionality for command-line ASN.1 decoding.

## Use Cases

1. **Debugging Protocol Issues**: See which field causes decoding to fail
2. **Analyzing Truncated Logs**: Extract maximum information from partial captures
3. **Development**: Quickly identify encoding/decoding mismatches
4. **Diagnostics**: Understand message structure even when complete message isn't available

## See Also

- `asn1c -h` for compiler options
- `converter-example -h` for runtime options
- `doc/asn1c-usage.pdf` for comprehensive documentation
