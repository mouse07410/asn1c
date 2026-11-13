//! Bounded CBOR codecs for direct primitives and opaque ANY.
//! Source: C CBOR skeletons. Version: 2026-10-30. Responsible: asn1c maintainers.
use crate::{
    allocate_zeroed, check_input_limit, check_work_limit, require_bytes, validate_integer,
    BitStringValue, Decoded, Encoded, Error, Limits,
};
use std::collections::HashSet;

/// Borrowed key and complete encoded value from a definite CBOR map.
///
/// The key is the raw text-string payload. The value includes its CBOR head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapEntry<'a> {
    /// Raw bytes of one text-string map key.
    pub key: &'a [u8],
    /// Complete encoded CBOR item associated with the key.
    pub value: &'a [u8],
}

/// Encode a shortest-form CBOR head. Inputs: major type and argument. Returns
/// fixed storage and used length; no errors. Source: `cbor_encode_head`.
/// Version: 2026-10-30. Responsible: asn1c maintainers. History: primitive CBOR.
/// Example: `head(0, 24)` returns a two-octet header.
fn head(major: u8, argument: u64) -> ([u8; 9], usize) {
    let mut bytes = [0; 9];
    let prefix = major << 5;
    if argument < 24 {
        bytes[0] = prefix | argument.to_be_bytes()[7];
        return (bytes, 1);
    }
    let width = if u8::try_from(argument).is_ok() {
        1
    } else if u16::try_from(argument).is_ok() {
        2
    } else if u32::try_from(argument).is_ok() {
        4
    } else {
        8
    };
    bytes[0] = prefix
        | match width {
            1 => 24,
            2 => 25,
            4 => 26,
            _ => 27,
        };
    bytes[1..=width].copy_from_slice(&argument.to_be_bytes()[8 - width..]);
    (bytes, width + 1)
}

/// Parse a definite CBOR head. Input: byte prefix. Returns major type, argument
/// and head length. Errors: truncation or reserved/indefinite head. Source:
/// `cbor_decode_head`. Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: primitive CBOR. Example: `[0x18, 24]` gives argument 24.
fn parse_head(input: &[u8]) -> Result<(u8, u64, usize), Error> {
    require_bytes(input, 1)?;
    let first = input[0];
    let info = first & 31;
    if info < 24 {
        return Ok((first >> 5, u64::from(info), 1));
    }
    let width = match info {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => {
            return Err(Error::InvalidEncoding {
                reason: "invalid CBOR head",
            })
        }
    };
    require_bytes(input, width + 1)?;
    let mut raw = [0; 8];
    raw[8 - width..].copy_from_slice(&input[1..=width]);
    let argument = u64::from_be_bytes(raw);
    if first >> 5 == 7 && info == 24 && argument < 32 {
        return Err(Error::InvalidEncoding {
            reason: "invalid CBOR simple value",
        });
    }
    Ok((first >> 5, argument, width + 1))
}

/// Convert a CBOR bignum magnitude into the bounded signed INTEGER domain.
/// Input: payload and tag 2 or 3. Returns the signed value. Errors: magnitude
/// exceeds `i64`. Source: RFC 8949 bignum tags. Version: 2026-11-12.
/// Responsible: asn1c maintainers. History: bounded CBOR bignum support.
/// Example: tag 3 with an empty payload yields -1.
fn decode_bignum_payload(payload: &[u8], tag: u64) -> Result<i64, Error> {
    let first_significant = payload.iter().position(|byte| *byte != 0);
    let magnitude_bytes = first_significant.map_or(&[][..], |start| &payload[start..]);
    if magnitude_bytes.len() > 8 {
        return Err(Error::InvalidEncoding {
            reason: "CBOR bignum exceeds i64",
        });
    }
    let mut raw = [0; 8];
    raw[8 - magnitude_bytes.len()..].copy_from_slice(magnitude_bytes);
    let magnitude = u64::from_be_bytes(raw);
    let magnitude = i64::try_from(magnitude).map_err(|_| Error::InvalidEncoding {
        reason: "CBOR bignum exceeds i64",
    })?;
    if tag == 2 {
        Ok(magnitude)
    } else {
        Ok(-1 - magnitude)
    }
}

#[cfg(test)]
mod integer_tests {
    use super::{decode_integer_cbor, decode_map};
    use crate::{Error, Limits, Resource};

    /// Check bignum values at signed boundaries and through leading tags.
    /// Source: RFC 8949 tags 2 and 3. Version: 2026-11-12.
    /// Inputs: none. Returns: unit. Errors: assertion panic on failure.
    /// Responsible: asn1c maintainers. History: bounded CBOR bignum regression.
    /// Example: `cargo test --manifest-path rust/asn1c-runtime/Cargo.toml bignum_values`.
    #[test]
    fn bignum_values() {
        let limits = Limits::default();
        let cases: &[(&[u8], i64, usize)] = &[
            (&[0xc2, 0x40], 0, 2),
            (&[0xc3, 0x40], -1, 2),
            (&[0xc2, 0x42, 0x00, 0x2a], 42, 4),
            (&[0xc0, 0xc2, 0x42, 0x00, 0x2a, 0x01], 42, 5),
            (
                &[0xc2, 0x48, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                i64::MAX,
                10,
            ),
            (
                &[0xc3, 0x48, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                i64::MIN,
                10,
            ),
            (&[0xc2, 0x58, 0x01, 0x42], 66, 4),
        ];
        for (wire, expected, consumed) in cases {
            let decoded = decode_integer_cbor(wire, i64::MIN, i64::MAX, &limits).unwrap();
            assert_eq!(decoded.value, *expected, "{wire:?}");
            assert_eq!(decoded.consumed_bytes, *consumed, "{wire:?}");
            assert_eq!(decoded.consumed_bits, consumed * 8, "{wire:?}");
        }
        assert_eq!(
            decode_integer_cbor(&[0xc0, 0x01], 1, 1, &limits)
                .unwrap()
                .value,
            1
        );
    }

    /// Reject malformed bignum types, inconsistent tags, truncation, and overflow.
    /// Source: RFC 8949 tag 2 and 3 structure. Version: 2026-11-12.
    /// Inputs: none. Returns: unit. Errors: assertion panic on failure.
    /// Responsible: asn1c maintainers. History: malformed bignum regression.
    /// Example: `cargo test --manifest-path rust/asn1c-runtime/Cargo.toml bad_bignums`.
    #[test]
    fn bad_bignums() {
        let limits = Limits::default();
        for wire in [
            &[][..],
            &[0xc2][..],
            &[0xc2, 0x01][..],
            &[0xc3, 0x61, b'x'][..],
            &[0x41, 0x01][..],
            &[0xc2, 0xc0, 0x40][..],
            &[0xc2, 0xc3, 0x40][..],
            &[0x5f, 0xff][..],
            &[0xc2, 0x42, 0x01][..],
            &[0xc2, 0x48, 0x80, 0, 0, 0, 0, 0, 0, 0][..],
            &[0xc3, 0x48, 0x80, 0, 0, 0, 0, 0, 0, 0][..],
            &[0xc2, 0x49, 0x01, 0, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            assert!(
                decode_integer_cbor(wire, i64::MIN, i64::MAX, &limits).is_err(),
                "{wire:?}"
            );
        }
        assert!(decode_integer_cbor(&[0xc2, 0x41, 0x2a], 0, 41, &limits).is_err());
        assert!(decode_integer_cbor(&[0xc3, 0x41, 0x2a], -42, -1, &limits).is_err());
        assert!(matches!(
            decode_integer_cbor(
                &[0xc2, 0x43, 1, 2, 3],
                i64::MIN,
                i64::MAX,
                &Limits {
                    max_work_bits: 32,
                    ..limits
                }
            ),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        assert!(decode_integer_cbor(
            &[0xc2, 0x40, 0],
            0,
            0,
            &Limits {
                max_input_bytes: 2,
                ..limits
            }
        )
        .is_err());
    }

    /// Reject RFC-reserved AI=24 values and keep valid simple and float values skippable.
    /// Source: RFC 8949 simple-value encoding. Version: 2026-11-12.
    /// Inputs: none. Returns: unit. Errors: assertion panic on failure.
    /// Responsible: asn1c maintainers. History: malformed-simple regression.
    /// Example: `cargo test --manifest-path rust/asn1c-runtime/Cargo.toml simple_values`.
    #[test]
    fn simple_values() {
        let limits = Limits::default();
        for argument in 0..=31 {
            let wire = [0xa1, 0x61, b'x', 0xf8, argument];
            assert!(decode_map(&wire, &limits).is_err(), "{wire:?}");
        }
        for argument in [32, 255] {
            let wire = [0xa1, 0x61, b'x', 0xf8, argument];
            assert!(decode_map(&wire, &limits).is_ok(), "{wire:?}");
        }
        for wire in [
            &[0xa1, 0x61, b'x', 0xf9, 0x7c, 0x00][..],
            &[0xa1, 0x61, b'x', 0xfa, 0x7f, 0xc0, 0, 0][..],
            &[0xa1, 0x61, b'x', 0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0][..],
        ] {
            assert!(decode_map(wire, &limits).is_ok(), "{wire:?}");
        }
    }
}

/// Find an item after leading semantic tags. Inputs: input prefix and limits.
/// Returns item offset. Errors: truncation, malformed heads, or work limits.
/// Source: `cbor_skip_tags`. Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: prefix decoding. Example: `[0xc0, 0xf5]` yields offset one.
fn item_offset(input: &[u8], limits: &Limits) -> Result<usize, Error> {
    check_input_limit(input, limits)?;
    let mut offset = 0_usize;
    loop {
        let (major, _, count) = parse_head(&input[offset..])?;
        let next = offset.checked_add(count).ok_or(Error::SizeOverflow)?;
        check_work_limit(next.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
        if major != 6 {
            return Ok(offset);
        }
        offset = next;
    }
}

/// Encode a head and optional payload. Inputs: major, argument, payload and
/// limits. Returns encoding. Errors: size, resource or allocation failure.
/// Source: C CBOR encoder. Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: primitive CBOR. Example: empty byte string yields `[0x40]`.
fn encode_head_payload(
    major: u8,
    argument: u64,
    payload: &[u8],
    limits: &Limits,
) -> Result<Encoded, Error> {
    let (header, count) = head(major, argument);
    let length = count
        .checked_add(payload.len())
        .ok_or(Error::SizeOverflow)?;
    let bits = length.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bits, limits)?;
    let mut bytes = allocate_zeroed(length, limits)?;
    bytes[..count].copy_from_slice(&header[..count]);
    bytes[count..].copy_from_slice(payload);
    Ok(Encoded {
        bytes,
        bit_len: bits,
    })
}

/// Encode BOOLEAN as CBOR. Inputs: value and resource limits. Returns encoding.
///
/// Errors: resource or allocation errors. Source: `BOOLEAN_encode_cbor`.
/// Version: 2026-10-30. Responsible: asn1c maintainers. History: CBOR slice.
/// Example: TRUE emits `[0xf5]`.
///
/// # Errors
/// Returns a resource or allocation error.
pub fn encode_boolean_cbor(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    encode_head_payload(7, if value { 21 } else { 20 }, &[], limits)
}

/// Decode a tagged or untagged CBOR BOOLEAN prefix. Inputs: bytes and limits.
///
/// Returns value and consumption. Source: `BOOLEAN_decode_cbor`; version
/// 2026-10-30. Responsible: asn1c maintainers. History: CBOR slice.
/// Example: `[0xf5]` yields TRUE.
///
/// # Errors
/// Returns malformed, truncated, or resource-limit errors.
pub fn decode_boolean_cbor(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    let offset = item_offset(input, limits)?;
    let value = match input[offset] {
        0xf4 => false,
        0xf5 => true,
        _ => {
            return Err(Error::InvalidEncoding {
                reason: "invalid CBOR BOOLEAN",
            })
        }
    };
    let bytes = offset.checked_add(1).ok_or(Error::SizeOverflow)?;
    Ok(Decoded {
        value,
        consumed_bits: bytes.checked_mul(8).ok_or(Error::SizeOverflow)?,
        consumed_bytes: bytes,
    })
}

/// Encode NULL as CBOR. Input: limits. Returns encoding. Source:
///
/// `NULL_encode_cbor`. Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: CBOR slice. Example: emits `[0xf6]`.
///
/// # Errors
/// Returns a resource or allocation error.
pub fn encode_null_cbor(limits: &Limits) -> Result<Encoded, Error> {
    encode_head_payload(7, 22, &[], limits)
}

/// Decode a tagged or untagged CBOR NULL prefix. Inputs: bytes and limits.
///
/// Returns unit and consumption. Source: `NULL_decode_cbor`. Version:
/// 2026-10-30. Responsible: asn1c maintainers. History: CBOR slice.
/// Example: `[0xf6]` yields unit.
///
/// # Errors
/// Returns malformed, truncated, or resource-limit errors.
pub fn decode_null_cbor(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    let offset = item_offset(input, limits)?;
    if input[offset] != 0xf6 {
        return Err(Error::InvalidEncoding {
            reason: "invalid CBOR NULL",
        });
    }
    let bytes = offset.checked_add(1).ok_or(Error::SizeOverflow)?;
    Ok(Decoded {
        value: (),
        consumed_bits: bytes.checked_mul(8).ok_or(Error::SizeOverflow)?,
        consumed_bytes: bytes,
    })
}

/// Encode a bounded INTEGER in CBOR. Inputs: value, inclusive bounds and limits.
///
/// Returns shortest encoding. Source: `NativeInteger_encode_cbor`. Version:
/// 2026-10-30. Responsible: asn1c maintainers. History: bounded INTEGER.
/// Example: -1 emits `[0x20]`.
///
/// # Errors
/// Returns invalid bounds/value, resource, or allocation errors.
pub fn encode_integer_cbor(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;
    let (major, argument) = if value < 0 {
        (1, value.unsigned_abs() - 1)
    } else {
        (0, u64::try_from(value).map_err(|_| Error::SizeOverflow)?)
    };
    encode_head_payload(major, argument, &[], limits)
}

/// Decode a tagged or untagged bounded INTEGER prefix. Inputs: bytes, inclusive
///
/// bounds and limits. Returns value and consumption. Source: `NativeInteger_decode_cbor`.
/// Version: 2026-10-30. Responsible: asn1c maintainers. History: bounded INTEGER.
/// Example: `[0x20]` yields -1.
///
/// # Errors
/// Returns malformed, out-of-range, truncated, or resource-limit errors.
pub fn decode_integer_cbor(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    check_input_limit(input, limits)?;
    let mut offset = 0_usize;
    let mut bignum_tag = None;
    loop {
        let (major, argument, count) = parse_head(&input[offset..])?;
        let next = offset.checked_add(count).ok_or(Error::SizeOverflow)?;
        check_work_limit(next.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
        if major != 6 {
            break;
        }
        if argument == 2 || argument == 3 {
            if bignum_tag.is_some() {
                return Err(Error::InvalidEncoding {
                    reason: "nested CBOR bignum tag",
                });
            }
            bignum_tag = Some(argument);
        } else if bignum_tag.is_some() {
            return Err(Error::InvalidEncoding {
                reason: "CBOR bignum tag must directly enclose a byte string",
            });
        }
        offset = next;
    }
    let (major, argument, count) = parse_head(&input[offset..])?;
    let (value, bytes) = if let Some(tag) = bignum_tag {
        if major != 2 {
            return Err(Error::InvalidEncoding {
                reason: "CBOR bignum tag must enclose a byte string",
            });
        }
        let length = usize::try_from(argument).map_err(|_| Error::SizeOverflow)?;
        let start = offset.checked_add(count).ok_or(Error::SizeOverflow)?;
        let end = start.checked_add(length).ok_or(Error::SizeOverflow)?;
        require_bytes(input, end)?;
        check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
        (decode_bignum_payload(&input[start..end], tag)?, end)
    } else {
        let integer = i64::try_from(argument).map_err(|_| Error::InvalidEncoding {
            reason: "CBOR INTEGER exceeds i64",
        })?;
        let value = match major {
            0 => integer,
            1 => -1 - integer,
            _ => {
                return Err(Error::InvalidEncoding {
                    reason: "invalid CBOR INTEGER",
                })
            }
        };
        (value, offset.checked_add(count).ok_or(Error::SizeOverflow)?)
    };
    validate_integer(value, lower, upper)?;
    Ok(Decoded {
        value,
        consumed_bits: bytes.checked_mul(8).ok_or(Error::SizeOverflow)?,
        consumed_bytes: bytes,
    })
}

/// Encode opaque ANY as a CBOR byte string. Inputs: octets and limits. Returns
///
/// encoding. Source: `ANY_encode_cbor`. Version: 2026-10-30. Responsible:
/// asn1c maintainers. History: opaque ANY. Example: empty bytes emit `[0x40]`.
///
/// # Errors
/// Returns size, resource, or allocation errors.
pub fn encode_any_cbor(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    if value.len() > i32::MAX as usize {
        return Err(Error::InvalidEncoding {
            reason: "CBOR ANY exceeds C size limit",
        });
    }
    encode_head_payload(
        2,
        u64::try_from(value.len()).map_err(|_| Error::SizeOverflow)?,
        value,
        limits,
    )
}

/// Decode a tagged definite CBOR byte string as opaque ANY. Inputs: prefix and
///
/// limits. Returns octets and consumption. Source: `ANY_decode_cbor`. Version:
/// 2026-10-30. Responsible: asn1c maintainers. History: opaque ANY.
/// Example: `[0x41, 0xa5]` yields `[0xa5]`.
///
/// # Errors
/// Returns malformed, truncated, size, resource or allocation errors.
pub fn decode_any_cbor(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    let offset = item_offset(input, limits)?;
    let (major, length, count) = parse_head(&input[offset..])?;
    if major != 2 {
        return Err(Error::InvalidEncoding {
            reason: "invalid CBOR byte string",
        });
    }
    let length = usize::try_from(length).map_err(|_| Error::SizeOverflow)?;
    if length > i32::MAX as usize {
        return Err(Error::InvalidEncoding {
            reason: "CBOR ANY exceeds C size limit",
        });
    }
    let start = offset.checked_add(count).ok_or(Error::SizeOverflow)?;
    let end = start.checked_add(length).ok_or(Error::SizeOverflow)?;
    require_bytes(input, end)?;
    let bits = end.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bits, limits)?;
    let mut value = allocate_zeroed(length, limits)?;
    value.copy_from_slice(&input[start..end]);
    Ok(Decoded {
        value,
        consumed_bits: bits,
        consumed_bytes: end,
    })
}

/// Validate one direct string's inclusive ASN.1 SIZE range.
/// Inputs: actual size, lower and upper bounds. Returns unit on success.
/// Errors: malformed bounds or out-of-range values. Source: Rust bounded
/// string runtimes. Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: CBOR string support. Example: `check_size(2, 1, 3)?`.
const fn check_size(actual: usize, lower: usize, upper: usize) -> Result<(), Error> {
    if lower > upper || actual < lower || actual > upper {
        return Err(Error::InvalidEncoding {
            reason: "CBOR string length is outside its SIZE range",
        });
    }
    Ok(())
}

/// Encode a bounded OCTET STRING as a definite CBOR byte string.
///
/// Inputs: octets, inclusive SIZE bounds and limits. Returns encoded bytes.
/// Source: `OCTET_STRING_encode_cbor`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: direct string CBOR slice.
/// Example: `[0xa5]` emits `[0x41, 0xa5]`.
///
/// # Errors
/// Returns an error for invalid SIZE, allocation or resource exhaustion.
pub fn encode_octet_string_cbor(
    value: &[u8],
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    check_size(value.len(), lower, upper)?;
    encode_any_cbor(value, limits)
}

/// Decode a bounded OCTET STRING from one definite CBOR byte-string prefix.
///
/// Inputs: bytes, inclusive SIZE bounds and limits. Returns octets and prefix
/// consumption. Source: `OCTET_STRING_decode_cbor`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: direct string CBOR slice.
/// Example: `[0x41, 0xa5]` yields `[0xa5]`.
///
/// # Errors
/// Returns an error for malformed or truncated input, SIZE, or resource limits.
pub fn decode_octet_string_cbor(
    input: &[u8],
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Decoded<Vec<u8>>, Error> {
    let decoded = decode_any_cbor(input, limits)?;
    check_size(decoded.value.len(), lower, upper)?;
    Ok(decoded)
}

/// Encode a bounded packed BIT STRING with an unused-bit count byte.
///
/// Inputs: packed octets, exact bit length, inclusive SIZE bounds and limits.
/// Returns definite CBOR byte-string encoding. Source: `BIT_STRING_encode_cbor`.
/// Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: direct bit-string CBOR slice. Example: one set bit emits `42 07 80`.
///
/// # Errors
/// Returns an error for invalid length or padding, overflow, allocation or limits.
pub fn encode_bit_string_cbor(
    value: &[u8],
    bit_len: usize,
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    check_size(bit_len, lower, upper)?;
    let storage = bit_len.checked_add(7).ok_or(Error::SizeOverflow)? / 8;
    let unused = (8 - bit_len % 8) % 8;
    if storage != value.len()
        || (unused != 0
            && value
                .last()
                .is_some_and(|byte| byte & ((1_u8 << unused) - 1) != 0))
    {
        return Err(Error::InvalidEncoding {
            reason: "invalid CBOR BIT STRING storage or padding",
        });
    }
    let payload_len = value.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    let mut payload = allocate_zeroed(payload_len, limits)?;
    payload[0] = u8::try_from(unused).map_err(|_| Error::SizeOverflow)?;
    payload[1..].copy_from_slice(value);
    encode_head_payload(
        2,
        u64::try_from(payload_len).map_err(|_| Error::SizeOverflow)?,
        &payload,
        limits,
    )
}

/// Decode a bounded packed BIT STRING with exact bit count and zero padding.
///
/// Inputs: bytes, inclusive SIZE bounds and limits. Returns validated packed
/// bits and prefix consumption. Source: `BIT_STRING_decode_cbor`.
/// Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: direct bit-string CBOR slice. Example: `42 07 80` yields one bit.
///
/// # Errors
/// Returns an error for malformed or truncated input, SIZE, padding or limits.
pub fn decode_bit_string_cbor(
    input: &[u8],
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Decoded<BitStringValue>, Error> {
    let decoded = decode_any_cbor(input, limits)?;
    if decoded.value.is_empty() {
        return Err(Error::InvalidEncoding {
            reason: "CBOR BIT STRING lacks unused-bit count",
        });
    }
    let mut payload = decoded.value;
    let unused = usize::from(payload.remove(0));
    if unused > 7 {
        return Err(Error::InvalidEncoding {
            reason: "invalid CBOR BIT STRING unused-bit count",
        });
    }
    let bit_len = payload
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(unused))
        .ok_or(Error::InvalidEncoding {
            reason: "invalid CBOR BIT STRING bit length",
        })?;
    check_size(bit_len, lower, upper)?;
    Ok(Decoded {
        value: BitStringValue::new(payload, bit_len)?,
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Skip one definite CBOR item, including nested arrays, maps, and tags.
/// Inputs are the whole remaining slice, resource limits, and recursion depth.
/// Returns the item length. Errors: malformed input, truncation, depth, or limits.
/// Source: `cbor_skip_item_with_ctx`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: constructed CBOR map support.
/// Example: a two-element array consumes its head and both children.
fn skip_item(input: &[u8], limits: &Limits, depth: usize) -> Result<usize, Error> {
    if depth > 64 {
        return Err(Error::InvalidEncoding {
            reason: "CBOR nesting depth exceeded",
        });
    }
    require_bytes(input, 1)?;
    let major = input[0] >> 5;
    if input[0] & 31 == 31 && (2..=5).contains(&major) {
        return skip_indefinite(input, major, limits, depth);
    }
    let (major, argument, header) = parse_head(input)?;
    let mut end = header;
    match major {
        0 | 1 | 7 => {}
        2 | 3 => {
            let length = usize::try_from(argument).map_err(|_| Error::SizeOverflow)?;
            end = end.checked_add(length).ok_or(Error::SizeOverflow)?;
            require_bytes(input, end)?;
            check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
            if major == 3 && std::str::from_utf8(&input[header..end]).is_err() {
                return Err(Error::InvalidEncoding {
                    reason: "CBOR text value is not UTF-8",
                });
            }
        }
        4 | 5 => {
            let count = if major == 5 {
                argument.checked_mul(2).ok_or(Error::SizeOverflow)?
            } else {
                argument
            };
            if count > u64::try_from(input.len()).map_err(|_| Error::SizeOverflow)? {
                return Err(Error::NeedMoreBytes {
                    required_bytes: usize::try_from(count).unwrap_or(usize::MAX),
                    available_bytes: input.len(),
                });
            }
            for _ in 0..count {
                let child = skip_item(&input[end..], limits, depth + 1)?;
                end = end.checked_add(child).ok_or(Error::SizeOverflow)?;
            }
        }
        6 => {
            let child = skip_item(&input[end..], limits, depth + 1)?;
            end = end.checked_add(child).ok_or(Error::SizeOverflow)?;
        }
        _ => unreachable!(),
    }
    check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
    Ok(end)
}

/// Skip one indefinite CBOR string, array, or map.
/// Inputs: item bytes, major type, limits, and current depth. Returns item
/// length. Errors: malformed chunks, truncation, depth, or resource limits.
/// Source: RFC 8949 section 3.2. Version: 2026-11-12.
/// Responsible: asn1c maintainers. History: indefinite map-value support.
/// Example: `[0x5f, 0x41, 0xa5, 0xff]` consumes four bytes.
fn skip_indefinite(input: &[u8], major: u8, limits: &Limits, depth: usize) -> Result<usize, Error> {
    if major == 2 || major == 3 {
        return skip_indefinite_string(input, major, limits);
    }
    let mut end = 1_usize;
    let mut map_key_expected = true;
    loop {
        require_bytes(input, end.checked_add(1).ok_or(Error::SizeOverflow)?)?;
        if input[end] == 0xff {
            if major == 5 && !map_key_expected {
                return Err(Error::InvalidEncoding {
                    reason: "indefinite CBOR map has an unmatched key",
                });
            }
            end += 1;
            check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
            return Ok(end);
        }
        let child_length = skip_item(&input[end..], limits, depth + 1)?;
        end = end.checked_add(child_length).ok_or(Error::SizeOverflow)?;
        if major == 5 {
            map_key_expected = !map_key_expected;
        }
        check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
    }
}

/// Skip one indefinite CBOR byte or text string and validate each text chunk.
/// Inputs: item bytes, major type, and limits. Returns item length. Errors:
/// wrong chunk type, nested chunks, invalid UTF-8, truncation, or resource limit.
/// Source: RFC 8949 section 3.2. Version: 2026-11-12.
/// Responsible: asn1c maintainers. History: indefinite string support.
/// Example: `[0x7f, 0x61, b'a', 0x60, 0xff]` consumes five bytes.
fn skip_indefinite_string(input: &[u8], major: u8, limits: &Limits) -> Result<usize, Error> {
    let mut end = 1_usize;
    loop {
        require_bytes(input, end.checked_add(1).ok_or(Error::SizeOverflow)?)?;
        if input[end] == 0xff {
            end += 1;
            check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
            return Ok(end);
        }
        let (chunk_major, length, header) = parse_head(&input[end..])?;
        if chunk_major != major {
            return Err(Error::InvalidEncoding {
                reason: "invalid indefinite CBOR string chunk",
            });
        }
        let length = usize::try_from(length).map_err(|_| Error::SizeOverflow)?;
        let start = end.checked_add(header).ok_or(Error::SizeOverflow)?;
        let chunk_end = start.checked_add(length).ok_or(Error::SizeOverflow)?;
        require_bytes(input, chunk_end)?;
        check_work_limit(chunk_end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
        if major == 3 && std::str::from_utf8(&input[start..chunk_end]).is_err() {
            return Err(Error::InvalidEncoding {
                reason: "CBOR text value is not UTF-8",
            });
        }
        end = chunk_end;
        check_work_limit(end.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
    }
}

/// Encode a definite CBOR text-key map in entry order.
///
/// Each value must be one complete octet-aligned CBOR item. Keys are unique.
/// Source: C `SEQUENCE_encode_cbor`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: generated SEQUENCE CBOR support.
/// Example: `encode_map(&[("flag", encoded)], &Limits::default())?`.
///
/// # Errors
/// Returns an error for duplicate keys, malformed values, size overflow,
/// exhausted resources, or failed allocation.
pub fn encode_map(entries: &[(&str, Encoded)], limits: &Limits) -> Result<Encoded, Error> {
    let (map_head, map_head_len) = head(
        5,
        u64::try_from(entries.len()).map_err(|_| Error::SizeOverflow)?,
    );
    let mut length = map_head_len;
    let mut keys = HashSet::new();
    keys.try_reserve(entries.len())
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: entries.len(),
        })?;
    for (key, value) in entries {
        if !keys.insert(*key)
            || value.bytes.is_empty()
            || skip_item(&value.bytes, limits, 0)? != value.bytes.len()
        {
            return Err(Error::InvalidEncoding {
                reason: "duplicate CBOR key or invalid map value",
            });
        }
        if value.bit_len
            != value
                .bytes
                .len()
                .checked_mul(8)
                .ok_or(Error::SizeOverflow)?
        {
            return Err(Error::InvalidEncoding {
                reason: "CBOR map value is not octet aligned",
            });
        }
        let (_, key_head_len) = head(
            3,
            u64::try_from(key.len()).map_err(|_| Error::SizeOverflow)?,
        );
        length = length
            .checked_add(key_head_len)
            .and_then(|sum| sum.checked_add(key.len()))
            .and_then(|sum| sum.checked_add(value.bytes.len()))
            .ok_or(Error::SizeOverflow)?;
    }
    let bits = length.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bits, limits)?;
    let mut bytes = allocate_zeroed(length, limits)?;
    bytes[..map_head_len].copy_from_slice(&map_head[..map_head_len]);
    let mut offset = map_head_len;
    for (key, value) in entries {
        let (key_head, key_head_len) = head(
            3,
            u64::try_from(key.len()).map_err(|_| Error::SizeOverflow)?,
        );
        bytes[offset..offset + key_head_len].copy_from_slice(&key_head[..key_head_len]);
        offset += key_head_len;
        bytes[offset..offset + key.len()].copy_from_slice(key.as_bytes());
        offset += key.len();
        bytes[offset..offset + value.bytes.len()].copy_from_slice(&value.bytes);
        offset += value.bytes.len();
    }
    Ok(Encoded {
        bytes,
        bit_len: bits,
    })
}

/// Decode a definite CBOR text-key map into borrowed complete value items.
///
/// Leading semantic tags and nonminimal definite heads are accepted. Duplicate
/// keys, indefinite lengths, and malformed or incomplete values are rejected.
/// Source: C `SEQUENCE_decode_cbor` and `cbor_skip_item_with_ctx`.
/// Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: generated SEQUENCE CBOR support.
/// Example: `decode_map(&[0xa1, 0x61, b'x', 0xf5], &Limits::default())?`.
///
/// # Errors
/// Returns an error for malformed input, duplicate keys, excessive nesting,
/// exhausted resources, or failed allocation.
pub fn decode_map<'a>(
    input: &'a [u8],
    limits: &Limits,
) -> Result<Decoded<Vec<MapEntry<'a>>>, Error> {
    let offset = item_offset(input, limits)?;
    let (major, count, header) = parse_head(&input[offset..])?;
    if major != 5 {
        return Err(Error::InvalidEncoding {
            reason: "CBOR SEQUENCE is not a map",
        });
    }
    let count = usize::try_from(count).map_err(|_| Error::SizeOverflow)?;
    if count > input.len() / 2 {
        return Err(Error::NeedMoreBytes {
            required_bytes: count.checked_mul(2).ok_or(Error::SizeOverflow)?,
            available_bytes: input.len(),
        });
    }
    let mut entries = Vec::new();
    entries
        .try_reserve(count)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: count,
        })?;
    let mut keys = HashSet::new();
    keys.try_reserve(count)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: count,
        })?;
    let mut end = offset.checked_add(header).ok_or(Error::SizeOverflow)?;
    for _ in 0..count {
        let (key_major, key_length, key_header) = parse_head(&input[end..])?;
        if key_major != 3 {
            return Err(Error::InvalidEncoding {
                reason: "CBOR map key is not text",
            });
        }
        let key_length = usize::try_from(key_length).map_err(|_| Error::SizeOverflow)?;
        let key_start = end.checked_add(key_header).ok_or(Error::SizeOverflow)?;
        let key_end = key_start
            .checked_add(key_length)
            .ok_or(Error::SizeOverflow)?;
        require_bytes(input, key_end)?;
        let key = &input[key_start..key_end];
        std::str::from_utf8(key).map_err(|_| Error::InvalidEncoding {
            reason: "CBOR text key is not UTF-8",
        })?;
        if !keys.insert(key) {
            return Err(Error::InvalidEncoding {
                reason: "duplicate CBOR map key",
            });
        }
        let value_length = skip_item(&input[key_end..], limits, 0)?;
        end = key_end
            .checked_add(value_length)
            .ok_or(Error::SizeOverflow)?;
        entries.push(MapEntry {
            key,
            value: &input[key_end..end],
        });
    }
    let bits = end.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bits, limits)?;
    Ok(Decoded {
        value: entries,
        consumed_bits: bits,
        consumed_bytes: end,
    })
}

/// Require a field decoder to consume its complete CBOR map value.
///
/// Inputs: decoded prefix and exact entry span. Returns its validated value.
/// Errors: trailing data. Source: C member CBOR dispatch. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: flat SEQUENCE field validation.
/// Example: `complete_value(decode_boolean_cbor(bytes, limits)?, bytes.len())?`.
///
/// # Errors
/// Returns `InvalidEncoding` when the decoded prefix is shorter than the entry.
pub fn complete_value<T>(decoded: Decoded<T>, exact_bytes: usize) -> Result<T, Error> {
    if decoded.consumed_bytes != exact_bytes {
        return Err(Error::InvalidEncoding {
            reason: "trailing CBOR map field data",
        });
    }
    Ok(decoded.value)
}

#[cfg(test)]
mod map_tests {
    use super::{decode_map, encode_boolean_cbor, encode_map};
    use crate::{Encoded, Error, Limits};

    /// Check map ordering, tags, nonminimal heads, and borrowed entry spans.
    /// Source: C SEQUENCE CBOR mapping. Version: 2026-10-30.
    /// Inputs: none. Returns: unit. Errors: assertion panic on failure.
    /// Responsible: asn1c maintainers. History: CBOR map regression.
    /// Example: `cargo test map_round_trip`.
    #[test]
    fn map_round_trip() {
        let limits = Limits::default();
        let flag = encode_boolean_cbor(true, &limits).unwrap();
        let encoded = encode_map(&[("flag", flag)], &limits).unwrap();
        assert_eq!(encoded.bytes, [0xa1, 0x64, b'f', b'l', b'a', b'g', 0xf5]);
        let tagged = [0xc0, 0xb8, 1, 0x78, 4, b'f', b'l', b'a', b'g', 0xf5, 0xff];
        let decoded = decode_map(&tagged, &limits).unwrap();
        assert_eq!(decoded.consumed_bytes, tagged.len() - 1);
        assert_eq!(decoded.value[0].key, b"flag");
        assert_eq!(decoded.value[0].value, [0xf5]);
    }

    /// Reject duplicate keys, bad nested items, and budget excess.
    /// Source: C CBOR map decoder. Version: 2026-10-30.
    /// Inputs: none. Returns: unit. Errors: assertion panic on failure.
    /// Responsible: asn1c maintainers. History: malformed-map regression.
    /// Example: `cargo test bad_maps`.
    #[test]
    fn bad_maps() {
        let limits = Limits::default();
        for wire in [
            &[][..],
            &[0xbf][..],
            &[0xa1, 0x01, 0xf5][..],
            &[0xa1, 0x61, b'x'][..],
            &[0xa1, 0x61, b'x', 0x9f][..],
            &[0xa1, 0x61, 0xff, 0xf5][..],
            &[0xa1, 0x61, b'x', 0x81, 0x61, 0xff][..],
            &[0xa2, 0x61, b'x', 0xf5, 0x61, b'x', 0xf4][..],
            &[0xa1, 0x61, b'x', 0x81][..],
        ] {
            assert!(decode_map(wire, &limits).is_err(), "{wire:?}");
        }
        let tiny = Limits {
            max_work_bits: 8,
            ..limits
        };
        assert!(decode_map(&[0xa0], &tiny).is_ok());
        assert!(decode_map(&[0xa1, 0x61, b'x', 0xf5], &tiny).is_err());
        let value = encode_boolean_cbor(true, &limits).unwrap();
        assert!(matches!(
            encode_map(&[("x", value.clone()), ("x", value)], &limits),
            Err(Error::InvalidEncoding { .. })
        ));
    }

    /// Skip valid indefinite values and reject malformed chunks and map pairs.
    /// Source: RFC 8949 section 3.2. Version: 2026-11-12.
    /// Inputs: none. Returns: unit. Errors: assertion panic on failure.
    /// Responsible: asn1c maintainers. History: indefinite map-value regression.
    /// Example: `cargo test --manifest-path rust/asn1c-runtime/Cargo.toml indefinite_values`.
    #[test]
    fn indefinite_values() {
        let limits = Limits::default();
        let valid_items: &[&[u8]] = &[
            &[0x9f, 0xf5, 0xff],
            &[0xbf, 0x61, b'a', 0xf5, 0xff],
            &[0x5f, 0x41, 0xa5, 0x40, 0xff],
            &[0x7f, 0x61, b'a', 0x60, 0xff],
            &[0x9f, 0x9f, 0xf4, 0xff, 0xff],
        ];
        for item in valid_items {
            let mut wire = vec![0xa1, 0x61, b'x'];
            wire.extend_from_slice(item);
            let decoded = decode_map(&wire, &limits).unwrap();
            assert_eq!(decoded.value[0].value, *item);
            let encoded = Encoded {
                bytes: item.to_vec(),
                bit_len: item.len() * 8,
            };
            assert!(encode_map(&[("x", encoded)], &limits).is_ok(), "{item:?}");
        }

        let invalid_items: &[&[u8]] = &[
            &[0x9f, 0x01],
            &[0xbf, 0x61, b'a', 0xff],
            &[0x5f, 0x61, b'a', 0xff],
            &[0x5f, 0x5f, 0xff, 0xff],
            &[0x7f, 0x61, 0xff, 0xff],
            &[0x7f, 0x7f, 0xff, 0xff],
            &[0xbf, 0x61, b'a', 0xf5],
        ];
        for item in invalid_items {
            let mut wire = vec![0xa1, 0x61, b'x'];
            wire.extend_from_slice(item);
            assert!(decode_map(&wire, &limits).is_err(), "{item:?}");
            let encoded = Encoded {
                bytes: item.to_vec(),
                bit_len: item.len() * 8,
            };
            assert!(encode_map(&[("x", encoded)], &limits).is_err(), "{item:?}");
        }
    }
}

#[cfg(test)]
mod string_tests {
    use super::{
        decode_bit_string_cbor, decode_octet_string_cbor, encode_bit_string_cbor,
        encode_octet_string_cbor,
    };
    use crate::Limits;

    /// Compare direct string encodings with C's byte-string mapping.
    /// Source: C BIT/OCTET STRING CBOR codecs. Version: 2026-10-30.
    /// Inputs: none. Returns: unit. Errors: assertion panic.
    /// Responsible: maintainers. History: CBOR string support.
    /// Example: `cargo test string_vectors`.
    #[test]
    fn string_vectors() {
        let limits = Limits::default();
        assert_eq!(
            encode_octet_string_cbor(&[0xa5, 0x5a], 2, 2, &limits)
                .unwrap()
                .bytes,
            [0x42, 0xa5, 0x5a]
        );
        assert_eq!(
            decode_octet_string_cbor(&[0xc0, 0x58, 2, 0xa5, 0x5a], 2, 2, &limits)
                .unwrap()
                .value,
            [0xa5, 0x5a]
        );
        assert_eq!(
            encode_bit_string_cbor(&[0xa0], 3, 3, 3, &limits)
                .unwrap()
                .bytes,
            [0x42, 5, 0xa0]
        );
        let bits = decode_bit_string_cbor(&[0xc0, 0x42, 5, 0xa0], 3, 3, &limits).unwrap();
        assert_eq!(bits.value.bit_len(), 3);
        assert_eq!(bits.value.as_bytes(), [0xa0]);
        assert_eq!(bits.consumed_bytes, 4);
        assert_eq!(
            encode_bit_string_cbor(&[], 0, 0, 9, &limits).unwrap().bytes,
            [0x41, 0]
        );
    }

    /// Reject malformed lengths, padding, indefinite input and limits.
    /// Source: C BIT/OCTET STRING CBOR validation. Version: 2026-10-30.
    /// Inputs: none. Returns: unit. Errors: assertion panic.
    /// Responsible: maintainers. History: CBOR string hardening.
    /// Example: `cargo test malformed_strings`.
    #[test]
    fn malformed_strings() {
        let limits = Limits::default();
        assert!(encode_octet_string_cbor(&[], 1, 2, &limits).is_err());
        assert!(decode_octet_string_cbor(&[0x5f], 0, 3, &limits).is_err());
        assert!(decode_octet_string_cbor(&[0x41], 0, 3, &limits).is_err());
        assert!(encode_bit_string_cbor(&[0xa1], 3, 3, 3, &limits).is_err());
        for wire in [
            &[0x40][..],
            &[0x41, 8][..],
            &[0x41, 1][..],
            &[0x42, 7, 0x81][..],
            &[0x5f][..],
        ] {
            assert!(decode_bit_string_cbor(wire, 0, 9, &limits).is_err());
        }
        let tiny = Limits {
            max_output_bytes: 1,
            ..limits
        };
        assert!(encode_bit_string_cbor(&[0x80], 1, 1, 1, &tiny).is_err());
    }
}
