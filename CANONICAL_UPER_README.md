# Canonical UPER Decoder Implementation

This implementation adds canonical UPER (Unaligned Packed Encoding Rules) validation to asn1c, addressing the issue described in #243.

## Summary of Changes

### 1. Added canonical validation flags
- Extended `asn_codec_ctx_t` in `asn_codecs.h` with `uper_canonical` flag
- Added `enum uper_decoder_flags_e` in `uper_decoder.h`
- Created convenience functions `uper_decode_canonical()` and `uper_decode_complete_canonical()`

### 2. Implemented canonical validation for INTEGER
- Added minimal octet encoding validation in `INTEGER_uper.c`
- Validates X.691 11.3.6 compliance: rejects leading zeros in positive numbers and leading ones in negative numbers when not minimal
- Only applies to unconstrained integers as required by the standard

### 3. Implemented canonical validation for SEQUENCE
- Added extension group validation in `constr_SEQUENCE_uper.c`
- Validates X.691 19.9 compliance: rejects extension bit set to 1 when all components are missing
- Added default value validation for X.691 19.5 compliance: rejects encoded default values for simple types

## Usage

### Basic UPER (default, backward compatible)
```c
asn_dec_rval_t rval = uper_decode(NULL, &asn_DEF_MyType, &ptr, buffer, size, 0, 0);
```

### Canonical UPER (strict validation)
```c
// Using context flag
asn_codec_ctx_t ctx = {0};
ctx.uper_canonical = 1;
asn_dec_rval_t rval = uper_decode(&ctx, &asn_DEF_MyType, &ptr, buffer, size, 0, 0);

// Using convenience function
asn_dec_rval_t rval = uper_decode_canonical(NULL, &asn_DEF_MyType, &ptr, buffer, size, 0, 0);
```

## Validation Rules Implemented

1. **X.691 11.3.6** - Minimal octet encoding for unconstrained integers
2. **X.691 19.5** - DEFAULT value encoding prohibition for simple types  
3. **X.691 19.9** - Extension addition group encoding rules

## Backward Compatibility

All existing code continues to work unchanged. The new canonical validation is opt-in through:
- Setting `ctx.uper_canonical = 1` in the codec context
- Using the new `*_canonical()` convenience functions

## Testing

The implementation has been verified to:
- Pass all existing UPER integer tests
- Reject non-canonical encodings when canonical mode is enabled
- Accept the same non-canonical encodings when in basic mode (backward compatibility)

This addresses the core issue where asn1c was accepting non-canonical UPER encodings that should be rejected according to X.691 standards.