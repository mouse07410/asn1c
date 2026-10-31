//! Bounded CBOR codecs for direct primitives and opaque ANY.
//! Source: C CBOR skeletons. Version: 2026-10-30. Responsible: asn1c maintainers.
use crate::{
    allocate_zeroed, check_input_limit, check_work_limit, require_bytes, validate_integer, Decoded,
    Encoded, Error, Limits,
};

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
    Ok((first >> 5, u64::from_be_bytes(raw), width + 1))
}

/// Find an item after leading semantic tags. Inputs: input prefix and limits.
/// Returns item offset. Errors: truncation, malformed tags, or work limits.
/// Source: `cbor_skip_tags`. Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: prefix decoding. Example: `[0xc0, 0xf5]` yields offset one.
fn item_offset(input: &[u8], limits: &Limits, reject_bignum: bool) -> Result<usize, Error> {
    check_input_limit(input, limits)?;
    let mut offset = 0_usize;
    loop {
        let (major, argument, count) = parse_head(&input[offset..])?;
        let next = offset.checked_add(count).ok_or(Error::SizeOverflow)?;
        check_work_limit(next.checked_mul(8).ok_or(Error::SizeOverflow)?, limits)?;
        if major != 6 {
            return Ok(offset);
        }
        if reject_bignum && (argument == 2 || argument == 3) {
            return Err(Error::InvalidEncoding {
                reason: "CBOR bignum tags are unsupported",
            });
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
    let offset = item_offset(input, limits, false)?;
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
    let offset = item_offset(input, limits, false)?;
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
    let offset = item_offset(input, limits, true)?;
    let (major, argument, count) = parse_head(&input[offset..])?;
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
    validate_integer(value, lower, upper)?;
    let bytes = offset.checked_add(count).ok_or(Error::SizeOverflow)?;
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
    let offset = item_offset(input, limits, false)?;
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
