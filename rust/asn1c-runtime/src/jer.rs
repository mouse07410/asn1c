//! Safe, bounded primitive codecs for the compact JSON Encoding Rules (JER).
//!
//! This module encodes BOOLEAN, NULL, finite bounded signed `i64` INTEGER,
//! direct ENUMERATED values, fixed-size OCTET STRING and BIT STRING values,
//! and bounded BIT STRING objects as compact C-compatible JSON tokens. Decoders
//! accept one complete primitive with
//! optional JSON whitespace (space, tab, LF, or CR)
//! around it. They reject any non-whitespace suffix and consume the complete
//! supplied input, including surrounding whitespace. This is a complete-input
//! API; it does not provide incremental or streaming token decoding.
//!
//! Specification: ITU-T X.697 (02/2021),
//! <https://www.itu.int/rec/T-REC-X.697-202102-I/en>. C implementation
//! references: `skeletons/BOOLEAN_jer.c`, `NULL_jer.c`, `NativeInteger_jer.c`,
//! `INTEGER_jer.c`, `ENUMERATED_jer.c`, `OCTET_STRING_jer.c`, and
//! `BIT_STRING_jer.c`. The INTEGER
//! lexical tests reflect vectors in
//! `tests/tests-skeletons/check-INTEGER.c`. Version/date: 2026-10-30.
//! Responsible party: asn1c maintainers. History: initial bounded JER
//! primitive slice. Example: `encode_boolean_jer(true, &Limits::default())?`
//! produces the four bytes `true`.

use super::{
    allocate_zeroed, check_input_limit, check_work_limit, validate_integer, BitStringValue,
    Decoded, Encoded, Error, Limits,
};

/// Maximum number of root alternatives accepted by the generated ENUMERATED JER API.
const MAX_JER_ENUMERATED_VARIANTS: usize = 64;

/// Encode a BOOLEAN as the compact JSON literal `true` or `false`.
///
/// # Parameters
/// `value` is the ASN.1 BOOLEAN; `limits` bounds output bytes and work.
///
/// # Returns
/// The canonical ASCII JSON token and its bit length.
///
/// # Errors
/// Returns an output limit, work limit, allocation, or size error. It raises no
/// exception.
///
/// # Source, version, history, and example
/// Original source: `BOOLEAN_encode_jer` in `skeletons/BOOLEAN_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: `encode_boolean_jer(true, limits)`.
pub fn encode_boolean_jer(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    encode_token(if value { b"true" } else { b"false" }, limits)
}

/// Decode one complete JSON BOOLEAN primitive, allowing JSON whitespace around it.
///
/// # Parameters
/// `input` is the entire primitive input; `limits` bounds its byte size and
/// cumulative work across every supplied byte.
///
/// # Returns
/// The BOOLEAN value and consumption of the full input, including whitespace.
///
/// # Errors
/// Returns truncation, malformed input, invalid UTF-8, or input/work limit
/// errors. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `BOOLEAN_decode_jer` in `skeletons/BOOLEAN_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: `decode_boolean_jer(b" true ", limits)`.
pub fn decode_boolean_jer(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    let (token, consumed_bits) = complete_token(input, limits)?;
    let value = match token {
        b"true" => true,
        b"false" => false,
        _ if is_keyword_prefix(token, b"true") && token_can_continue(input) => {
            return Err(Error::NeedMoreBytes {
                required_bytes: keyword_required_bytes(input.len(), token.len(), 4)?,
                available_bytes: input.len(),
            });
        }
        _ if is_keyword_prefix(token, b"false") && token_can_continue(input) => {
            return Err(Error::NeedMoreBytes {
                required_bytes: keyword_required_bytes(input.len(), token.len(), 5)?,
                available_bytes: input.len(),
            });
        }
        _ => {
            return Err(Error::InvalidEncoding {
                reason: "expected one complete JSON BOOLEAN literal",
            });
        }
    };

    Ok(decoded_complete(value, input.len(), consumed_bits))
}

/// Encode an ASN.1 NULL as the compact JSON literal `null`.
///
/// # Parameters
/// `limits` bounds output bytes and work.
///
/// # Returns
/// The four ASCII bytes `null` and their bit length.
///
/// # Errors
/// Returns an output limit, work limit, allocation, or size error. It raises no
/// exception.
///
/// # Source, version, history, and example
/// Original source: `NULL_encode_jer` in `skeletons/NULL_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: `encode_null_jer(limits)`.
pub fn encode_null_jer(limits: &Limits) -> Result<Encoded, Error> {
    encode_token(b"null", limits)
}

/// Decode one complete JSON NULL primitive, allowing JSON whitespace around it.
///
/// # Parameters
/// `input` is the entire primitive input; `limits` bounds its byte size and
/// cumulative work across every supplied byte.
///
/// # Returns
/// Unit value and consumption of the full input, including whitespace.
///
/// # Errors
/// Returns truncation, malformed input, invalid UTF-8, or input/work limit
/// errors. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `NULL_decode_jer` in `skeletons/NULL_jer.c`; unlike the C
/// callback, this requires all four literal bytes and rejects trailing data.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: `decode_null_jer(b"null", limits)`.
pub fn decode_null_jer(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    let (token, consumed_bits) = complete_token(input, limits)?;
    if token != b"null" {
        if is_keyword_prefix(token, b"null") && token_can_continue(input) {
            return Err(Error::NeedMoreBytes {
                required_bytes: keyword_required_bytes(input.len(), token.len(), 4)?,
                available_bytes: input.len(),
            });
        }
        return Err(Error::InvalidEncoding {
            reason: "expected one complete JSON NULL literal",
        });
    }

    Ok(decoded_complete((), input.len(), consumed_bits))
}

/// Encode a finite bounded signed INTEGER using minimal decimal notation.
///
/// # Parameters
/// `value` is the INTEGER; `lower` and `upper` are inclusive bounds; `limits`
/// bounds output bytes and work.
///
/// # Returns
/// The minimal signed base-10 token, without a plus sign or leading zeroes.
///
/// # Errors
/// Returns invalid bounds, an out-of-range value, a limit, allocation, or size
/// error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `NativeInteger_encode_jer` and `INTEGER_encode_jer` in
/// `skeletons/NativeInteger_jer.c` and `skeletons/INTEGER_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: `encode_integer_jer(-3, -8, 8, limits)`.
pub fn encode_integer_jer(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;
    let mut buffer = [0_u8; 20];
    let start = format_integer(value, &mut buffer)?;
    encode_token(&buffer[start..], limits)
}

/// Decode one complete bounded signed INTEGER JSON primitive.
///
/// # Parameters
/// `input` is the entire primitive input; `lower` and `upper` are inclusive
/// bounds; `limits` bounds its byte size and cumulative work.
///
/// # Returns
/// The signed value and consumption of the full input, including whitespace.
///
/// # Errors
/// Returns invalid bounds, truncation, malformed or overflowing input, a range
/// violation, invalid UTF-8, or a resource limit error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `INTEGER_decode_jer` in `skeletons/INTEGER_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: `decode_integer_jer(b"-3", -8, 8, limits)`.
pub fn decode_integer_jer(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }

    let (token, consumed_bits) = complete_token(input, limits)?;
    let value = match parse_integer(token) {
        Err(Error::NeedMoreBytes { .. }) if token_can_continue(input) => {
            return Err(Error::NeedMoreBytes {
                required_bytes: input.len().checked_add(1).ok_or(Error::SizeOverflow)?,
                available_bytes: input.len(),
            });
        }
        Err(Error::NeedMoreBytes { .. }) => return Err(invalid_integer()),
        other => other?,
    };
    validate_integer(value, lower, upper)?;
    Ok(decoded_complete(value, input.len(), consumed_bits))
}

/// Encode one ENUMERATED root name as a compact JSON string.
///
/// # Parameters
/// index selects a name in declaration order; names contains one to 64 unique
/// valid root identifiers; limits bounds output and mapping validation.
///
/// # Returns
/// A quoted JSON string such as "red" and its complete-octet bit length.
///
/// # Errors
/// Returns an invalid mapping, an out-of-range index, a resource limit,
/// allocation, or size error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `ENUMERATED_encode_jer` in `skeletons/ENUMERATED_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial bounded ENUMERATED JER slice. Example: index 1 emits the quoted
/// JSON string `"red"`.
pub fn encode_enumerated_jer(
    index: usize,
    names: &[&str],
    limits: &Limits,
) -> Result<Encoded, Error> {
    if names.is_empty() || names.len() > MAX_JER_ENUMERATED_VARIANTS {
        return Err(invalid_enumerated_mapping());
    }
    let name = names
        .get(index)
        .copied()
        .ok_or_else(invalid_enumerated_mapping)?;
    let table_bytes = names.iter().try_fold(0_usize, |total, name| {
        total.checked_add(name.len()).ok_or(Error::SizeOverflow)
    })?;
    let output_len = name.len().checked_add(2).ok_or(Error::SizeOverflow)?;
    let bit_len = output_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let validation_bytes = table_bytes
        .checked_mul(names.len() + 1)
        .ok_or(Error::SizeOverflow)?;
    let validation_bits = validation_bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let total_work = bit_len
        .checked_add(validation_bits)
        .ok_or(Error::SizeOverflow)?;
    check_work_limit(total_work, limits)?;

    // Reject malformed or ambiguous root-name tables before selecting a name.
    for (name_index, candidate) in names.iter().enumerate() {
        if !is_enumerated_name(candidate)
            || names[..name_index]
                .iter()
                .any(|previous| previous == candidate)
        {
            return Err(invalid_enumerated_mapping());
        }
    }
    let mut bytes = allocate_zeroed(output_len, limits)?;
    bytes[0] = b'"';
    bytes[1..output_len - 1].copy_from_slice(name.as_bytes());
    bytes[output_len - 1] = b'"';
    Ok(Encoded { bytes, bit_len })
}

/// Decode one complete JSON string naming an ENUMERATED root alternative.
///
/// The accepted spelling is the exact C-compatible token "name" with
/// optional JSON whitespace around it. JSON escapes are not accepted because
/// ASN.1 identifiers cannot contain characters requiring JSON escaping and
/// the C JER decoder compares the identifier spelling directly.
///
/// # Parameters
/// input is the complete primitive input; names contains one to 64 unique root
/// identifiers in declaration order; limits bounds input and lookup work.
///
/// # Returns
/// The selected declaration-order index and consumption of the complete input.
///
/// # Errors
/// Returns invalid mapping, truncation, malformed or unknown names, invalid
/// UTF-8, or a resource limit error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `ENUMERATED_decode_jer` in `skeletons/ENUMERATED_jer.c`;
/// this API additionally rejects trailing input. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial bounded
/// ENUMERATED JER slice. Example: decode a complete quoted red token.
pub fn decode_enumerated_jer(
    input: &[u8],
    names: &[&str],
    limits: &Limits,
) -> Result<Decoded<usize>, Error> {
    if names.is_empty() || names.len() > MAX_JER_ENUMERATED_VARIANTS {
        return Err(invalid_enumerated_mapping());
    }
    let (token, consumed_bits) = complete_token(input, limits)?;
    let token_len = token.len();
    let table_bytes = names.iter().try_fold(0_usize, |total, name| {
        total.checked_add(name.len()).ok_or(Error::SizeOverflow)
    })?;
    let scan_bytes = table_bytes
        .checked_add(token_len)
        .and_then(|bytes| bytes.checked_mul(names.len() + 1))
        .ok_or(Error::SizeOverflow)?;
    let scan_bits = scan_bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let total_work = consumed_bits
        .checked_add(scan_bits)
        .ok_or(Error::SizeOverflow)?;
    check_work_limit(total_work, limits)?;

    // Validate the supplied root-name table before comparing any token.
    for (index, name) in names.iter().enumerate() {
        if !is_enumerated_name(name) || names[..index].iter().any(|previous| previous == name) {
            return Err(invalid_enumerated_mapping());
        }
    }

    let Some(name_bytes) = token
        .strip_prefix(b"\"")
        .and_then(|bytes| bytes.strip_suffix(b"\""))
    else {
        return Err(invalid_enumerated_token());
    };
    let index = names
        .iter()
        .position(|name| name.as_bytes() == name_bytes)
        .ok_or_else(invalid_enumerated_token)?;
    Ok(decoded_complete(index, input.len(), consumed_bits))
}

/// Encode a fixed-size OCTET STRING as a quoted uppercase hexadecimal JSON string.
///
/// # Parameters
/// `value` is the complete OCTET STRING value; `declared_size` is its ASN.1
/// fixed `SIZE`; `limits` bounds the encoded output and byte-processing work.
///
/// # Returns
/// A token such as `"00AF"` and its complete-octet bit length. Empty input
/// encodes as `""`.
///
/// # Errors
/// Returns `InvalidEncoding` when the value length differs from `declared_size`,
/// or a checked-size, output/work-limit, or allocation error. It raises no
/// exception.
///
/// # Source, version, history, and example
/// Original source: `OCTET_STRING_encode_jer` in `skeletons/OCTET_STRING_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added as fixed-size OCTET STRING JER runtime support. Example:
/// `encode_octet_string_jer(&[0xAF], 1, limits)` emits `"AF"`.
pub fn encode_octet_string_jer(
    value: &[u8],
    declared_size: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    if value.len() != declared_size {
        return Err(invalid_octet_string_size());
    }

    // Include both quotes and two hexadecimal digits per value octet.
    let body_len = value.len().checked_mul(2).ok_or(Error::SizeOverflow)?;
    let output_len = body_len.checked_add(2).ok_or(Error::SizeOverflow)?;
    let bit_len = output_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;
    let mut bytes = allocate_zeroed(output_len, limits)?;
    bytes[0] = b'"';
    for (index, octet) in value.iter().enumerate() {
        let offset = index.checked_mul(2).ok_or(Error::SizeOverflow)?;
        bytes[offset + 1] = b"0123456789ABCDEF"[usize::from(octet >> 4)];
        bytes[offset + 2] = b"0123456789ABCDEF"[usize::from(octet & 0x0f)];
    }
    bytes[output_len - 1] = b'"';
    Ok(Encoded { bytes, bit_len })
}

/// Decode one complete quoted hexadecimal OCTET STRING JSON token.
///
/// Lowercase and uppercase hexadecimal digits are accepted. The decoded byte
/// count must exactly match `declared_size`; only JSON's four ASCII whitespace
/// bytes may surround the quoted token.
///
/// # Parameters
/// `input` is the entire primitive input; `declared_size` is its ASN.1 fixed
/// `SIZE`; `limits` bounds input, decoded output, and processing work.
///
/// # Returns
/// The decoded octets and consumption of the complete input, including
/// surrounding whitespace.
///
/// # Errors
/// Returns truncation for empty input, `InvalidEncoding` for malformed UTF-8,
/// quotes, digits, odd digit counts, wrong lengths, or trailing tokens, and a
/// checked-size, resource-limit, or allocation error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `OCTET_STRING_decode_jer_hex` in
/// `skeletons/OCTET_STRING_jer.c`; this API additionally requires one complete
/// token and the caller's fixed size. Version/date: 2026-10-30. Responsible
/// party: asn1c maintainers. History: added as fixed-size OCTET STRING JER
/// runtime support. Example: `decode_octet_string_jer(b"\"00af\"", 2, limits)`.
pub fn decode_octet_string_jer(
    input: &[u8],
    declared_size: usize,
    limits: &Limits,
) -> Result<Decoded<Vec<u8>>, Error> {
    let (token, consumed_bits) = complete_token(input, limits)?;
    let Some(body) = token
        .strip_prefix(b"\"")
        .and_then(|bytes| bytes.strip_suffix(b"\""))
    else {
        return Err(invalid_octet_string_token());
    };
    let output = decode_octet_string_body(body, Some(declared_size), consumed_bits, limits)?;
    Ok(decoded_complete(output, input.len(), consumed_bits))
}

/// Encode a bounded OCTET STRING as the C-compatible quoted hexadecimal form.
///
/// # Parameters
/// `value` contains the octets; `lower` and `upper` are inclusive ASN.1 SIZE
/// bounds; `limits` bounds encoded output and byte-processing work.
///
/// # Returns
/// Uppercase hexadecimal digits in one quoted JSON string.
///
/// # Errors
/// Returns `InvalidEncoding` for invalid bounds or an out-of-range length, and
/// resource, overflow, or allocation errors. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `OCTET_STRING_encode_jer` in `skeletons/OCTET_STRING_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added direct bounded OCTET STRING JER. Example: `[0xAF]` encodes as `"AF"`.
pub fn encode_bounded_octet_string_jer(
    value: &[u8],
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_octet_string_bounds(value.len(), lower, upper)?;
    encode_octet_string_jer(value, value.len(), limits)
}

/// Decode one complete bounded OCTET STRING JER hexadecimal string.
///
/// # Parameters
/// `input` is the entire JSON value; `lower` and `upper` are inclusive ASN.1
/// SIZE bounds; `limits` bounds input, decoded output, and processing work.
///
/// # Returns
/// The decoded octets and consumption of the complete input, including JSON
/// whitespace surrounding the string.
///
/// # Errors
/// Returns an error for malformed JSON/hex, an invalid range or length,
/// trailing input, or exhausted resources. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `OCTET_STRING_decode_jer_hex` in
/// `skeletons/OCTET_STRING_jer.c`; this API additionally requires one complete
/// token. Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added direct bounded OCTET STRING JER. Example: decode `"00af"`
/// with bounds `1..=3`.
pub fn decode_bounded_octet_string_jer(
    input: &[u8],
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Decoded<Vec<u8>>, Error> {
    let (token, consumed_bits) = complete_token(input, limits)?;
    let Some(body) = token
        .strip_prefix(b"\"")
        .and_then(|bytes| bytes.strip_suffix(b"\""))
    else {
        return Err(invalid_octet_string_token());
    };
    if body.len() & 1 != 0 {
        return Err(invalid_octet_string_token());
    }
    let octet_len = body.len() / 2;
    validate_octet_string_bounds(octet_len, lower, upper)?;
    let output = decode_octet_string_body(body, Some(octet_len), consumed_bits, limits)?;
    Ok(decoded_complete(output, input.len(), consumed_bits))
}

/// Decode and validate a hexadecimal OCTET STRING body before allocating output.
///
/// # Parameters and returns
/// `body` is the string content; `expected_size` optionally constrains decoded
/// octets; `prior_work` is complete-input scan work; `limits` bounds all work.
/// Returns the decoded bytes.
///
/// # Errors
/// Returns malformed-hex, size, resource-limit, overflow, or allocation errors.
/// It raises no exception.
///
/// # Source, version, history, and example
/// Original source: hexadecimal conversion in `OCTET_STRING_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// shared fixed and bounded OCTET STRING JER validation. Example: decodes
/// `b"A8"` as one octet.
fn decode_octet_string_body(
    body: &[u8],
    expected_size: Option<usize>,
    prior_work: usize,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    if body.len() & 1 != 0 {
        return Err(invalid_octet_string_token());
    }
    let output_len = body.len() / 2;
    if expected_size.is_some_and(|expected| expected != output_len) {
        return Err(invalid_octet_string_size());
    }
    let hex_work = body.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    let total_work = prior_work
        .checked_add(hex_work)
        .ok_or(Error::SizeOverflow)?;
    check_work_limit(total_work, limits)?;

    // Check every digit before reserving the decoded value's output buffer.
    for pair_start in (0..body.len()).step_by(2) {
        if hex_nibble(body[pair_start]).is_none() || hex_nibble(body[pair_start + 1]).is_none() {
            return Err(invalid_octet_string_token());
        }
    }
    let mut output = allocate_zeroed(output_len, limits)?;
    for (index, decoded_octet) in output.iter_mut().enumerate() {
        let offset = index.checked_mul(2).ok_or(Error::SizeOverflow)?;
        let high = hex_nibble(body[offset]).ok_or_else(invalid_octet_string_token)?;
        let low = hex_nibble(body[offset + 1]).ok_or_else(invalid_octet_string_token)?;
        *decoded_octet = (high << 4) | low;
    }
    Ok(output)
}

/// Validate inclusive OCTET STRING bounds and one actual length.
///
/// # Parameters and returns
/// `length` is the actual octet count; `lower` and `upper` are inclusive
/// declared bounds. Returns success when the ordered range contains length.
///
/// # Errors
/// Returns `InvalidEncoding` for reversed bounds or an out-of-range length.
/// It raises no exception.
///
/// # Source, version, history, and example
/// Original source: direct bounded Rust OCTET STRING JER validation.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added bounded JER bounds checks. Example: validates length two in `1..=3`.
fn validate_octet_string_bounds(length: usize, lower: usize, upper: usize) -> Result<(), Error> {
    if lower > upper {
        return Err(Error::InvalidEncoding {
            reason: "OCTET STRING SIZE bounds are invalid",
        });
    }
    if !(lower..=upper).contains(&length) {
        return Err(invalid_octet_string_size());
    }
    Ok(())
}

/// Encode a fixed-size BIT STRING as the C-compatible quoted hexadecimal form.
///
/// # Parameters
/// `value` is the packed value with zero unused low bits; `declared_bit_len`
/// is the fixed ASN.1 SIZE; `limits` bounds output and work.
///
/// # Returns
/// Uppercase hexadecimal octets in one JSON string, including packed padding.
///
/// # Errors
/// Returns an error for a wrong storage length, nonzero padding, or resource
/// limits. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `BIT_STRING_encode_jer` in `skeletons/BIT_STRING_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added direct fixed BIT STRING JER. Example: a three-bit `0xA0` value emits
/// the JSON token `"A0"`.
pub fn encode_bit_string_jer(
    value: &[u8],
    declared_bit_len: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_jer_bit_string(value, declared_bit_len)?;
    encode_bit_string_token(value, declared_bit_len, None, limits)
}

/// Decode one complete fixed-size BIT STRING JER hexadecimal token.
///
/// # Parameters
/// `input` is the entire JSON string; `declared_bit_len` is the fixed ASN.1
/// SIZE; `limits` bounds input, output, and processing work.
///
/// # Returns
/// The validated packed value and full-input consumption, including whitespace.
///
/// # Errors
/// Returns an error for malformed JSON/hex, wrong size, nonzero unused bits,
/// trailing input, or resource limits. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: `BIT_STRING_decode_jer` in `skeletons/BIT_STRING_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added direct fixed BIT STRING JER. Example: decode `b"\"A0\""` at SIZE(3).
pub fn decode_bit_string_jer(
    input: &[u8],
    declared_bit_len: usize,
    limits: &Limits,
) -> Result<Decoded<Vec<u8>>, Error> {
    let (token, consumed_bits) = complete_token(input, limits)?;
    let Some(body) = token
        .strip_prefix(b"\"")
        .and_then(|bytes| bytes.strip_suffix(b"\""))
    else {
        return Err(invalid_bit_string_token());
    };
    let expected_bytes = bit_string_octet_len(declared_bit_len)?;
    let output = decode_hex_body(body, Some(expected_bytes), consumed_bits, limits)?;
    validate_jer_bit_string(&output, declared_bit_len)?;
    Ok(decoded_complete(output, input.len(), consumed_bits))
}

/// Encode a bounded BIT STRING as the C-compatible minified JER object.
///
/// # Parameters
/// `value` carries packed bytes and its exact bit length; `lower` and `upper`
/// are inclusive ASN.1 SIZE bounds; `limits` bounds output and work.
///
/// # Returns
/// A token shaped as `{"value":"A8","length":5}` with uppercase hex.
///
/// # Errors
/// Returns an error for invalid bounds, length, padding, or resource limits.
/// It raises no exception.
///
/// # Source, version, history, and example
/// Original source: variable-size `BIT_STRING_encode_jer` in
/// `skeletons/BIT_STRING_jer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: added bounded BIT STRING JER. Example: a
/// five-bit `0xA8` value emits `{"value":"A8","length":5}`.
pub fn encode_bounded_bit_string_jer(
    value: &BitStringValue,
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_bit_string_bounds(value.bit_len(), lower, upper)?;
    validate_jer_bit_string(value.as_bytes(), value.bit_len())?;
    encode_bit_string_token(
        value.as_bytes(),
        value.bit_len(),
        Some(value.bit_len()),
        limits,
    )
}

/// Decode one complete bounded BIT STRING JER object.
///
/// # Parameters
/// `input` is the entire JSON object; `lower` and `upper` are inclusive ASN.1
/// SIZE bounds; `limits` bounds input, output, and processing work.
///
/// # Returns
/// The validated packed value, exact bit length, and full-input consumption.
///
/// # Errors
/// Returns malformed JSON/hex, invalid bounds or length, nonzero padding,
/// trailing input, or resource-limit errors. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: variable-size `BIT_STRING_decode_jer` in
/// `skeletons/BIT_STRING_jer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: added bounded BIT STRING JER. Example: decode
/// `b"{\"value\":\"A8\",\"length\":5}"` for SIZE(1..7).
pub fn decode_bounded_bit_string_jer(
    input: &[u8],
    lower: usize,
    upper: usize,
    limits: &Limits,
) -> Result<Decoded<BitStringValue>, Error> {
    let (token, consumed_bits) = complete_token(input, limits)?;
    let (body, bit_len) = parse_bounded_bit_string_object(token)?;
    validate_bit_string_bounds(bit_len, lower, upper)?;
    let expected_bytes = bit_string_octet_len(bit_len)?;
    let output = decode_hex_body(body, Some(expected_bytes), consumed_bits, limits)?;
    validate_jer_bit_string(&output, bit_len)?;
    let value = BitStringValue::new(output, bit_len)?;
    Ok(decoded_complete(value, input.len(), consumed_bits))
}

/// Build one fixed-string or bounded-object JER token from validated packed bits.
///
/// # Parameters
/// `value` is the packed content; `bit_len` is meaningful bits; `include_length`
/// selects C's variable-size object shape; `limits` bounds output and work.
///
/// # Returns
/// The uppercase hexadecimal token with complete-octet bit length.
///
/// # Errors
/// Returns checked-size, resource-limit, allocation, or storage validation
/// errors. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: fixed and variable `BIT_STRING_encode_jer` output shapes.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// shared JER encoder. Example: encode a zero-padded three-bit value.
fn encode_bit_string_token(
    value: &[u8],
    bit_len: usize,
    include_length: Option<usize>,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_jer_bit_string(value, bit_len)?;
    let hex_len = value.len().checked_mul(2).ok_or(Error::SizeOverflow)?;
    let mut length_digits = [0_u8; 20];
    let digit_start = format_usize(include_length.unwrap_or(0), &mut length_digits);
    let (prefix_len, suffix_len) = if include_length.is_some() {
        (
            10_usize,
            12_usize
                .checked_add(length_digits.len() - digit_start)
                .ok_or(Error::SizeOverflow)?,
        )
    } else {
        (1, 1)
    };
    let output_len = prefix_len
        .checked_add(hex_len)
        .and_then(|len| len.checked_add(suffix_len))
        .ok_or(Error::SizeOverflow)?;
    let work_bits = output_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(work_bits, limits)?;
    let mut output = allocate_zeroed(output_len, limits)?;
    if include_length.is_some() {
        output[..prefix_len].copy_from_slice(b"{\"value\":\"");
    } else {
        output[0] = b'"';
    }
    for (index, octet) in value.iter().enumerate() {
        let offset = prefix_len
            .checked_add(index.checked_mul(2).ok_or(Error::SizeOverflow)?)
            .ok_or(Error::SizeOverflow)?;
        output[offset] = b"0123456789ABCDEF"[usize::from(octet >> 4)];
        output[offset + 1] = b"0123456789ABCDEF"[usize::from(octet & 0x0f)];
    }
    let mut suffix = prefix_len.checked_add(hex_len).ok_or(Error::SizeOverflow)?;
    output[suffix] = b'"';
    if include_length.is_some() {
        suffix += 1;
        output[suffix..suffix + 10].copy_from_slice(b",\"length\":");
        suffix += 10;
        let digits = &length_digits[digit_start..];
        output[suffix..suffix + digits.len()].copy_from_slice(digits);
        suffix += digits.len();
        output[suffix] = b'}';
    }
    Ok(Encoded {
        bytes: output,
        bit_len: work_bits,
    })
}

/// Validate storage length and zero unused low bits for a logical BIT STRING.
///
/// # Parameters and returns
/// `value` is packed content and `bit_len` is its meaningful width. Returns
/// success only for the exact storage length and canonical zero padding.
///
/// # Errors
/// Returns `InvalidEncoding` for an inconsistent value; raises no exception.
///
/// # Source, version, history, and example
/// Original source: BIT STRING representation requirements in
/// `skeletons/BIT_STRING_jer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: added BIT STRING JER validation. Example:
/// validates `[0xA0]` at width three.
fn validate_jer_bit_string(value: &[u8], bit_len: usize) -> Result<(), Error> {
    if value.len() != bit_string_octet_len(bit_len)? {
        return Err(invalid_bit_string_size());
    }
    let remainder = bit_len % 8;
    if remainder != 0
        && value
            .last()
            .is_some_and(|byte| byte & (0xff >> remainder) != 0)
    {
        return Err(invalid_bit_string_padding());
    }
    Ok(())
}

/// Compute the canonical packed-octet count for a meaningful BIT STRING width.
///
/// # Parameters and returns
/// `bit_len` is the number of meaningful bits. Returns `ceil(bit_len / 8)`.
///
/// # Errors
/// Returns `SizeOverflow` if rounding the width exceeds `usize`.
///
/// # Source, version, history, and example
/// Original source: packed ASN.1 BIT STRING storage. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added JER storage checks.
/// Example: `bit_string_octet_len(9)` returns two.
fn bit_string_octet_len(bit_len: usize) -> Result<usize, Error> {
    bit_len
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(Error::SizeOverflow)
}

/// Check inclusive bounds for a bounded BIT STRING JER operation.
///
/// # Parameters and returns
/// `bit_len` is the actual width; `lower` and `upper` are inclusive bounds.
/// Returns success when the bounds are ordered and contain the width.
///
/// # Errors
/// Returns `InvalidEncoding` for reversed bounds or an out-of-range length.
/// It raises no exception.
///
/// # Source, version, history, and example
/// Original source: constrained BIT STRING validation. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: bounded JER.
/// Example: validates bit length five in SIZE(1..7).
fn validate_bit_string_bounds(bit_len: usize, lower: usize, upper: usize) -> Result<(), Error> {
    if lower > upper {
        return Err(Error::InvalidEncoding {
            reason: "BIT STRING SIZE bounds are invalid",
        });
    }
    if !(lower..=upper).contains(&bit_len) {
        return Err(invalid_bit_string_size());
    }
    Ok(())
}

/// Parse the exact ordered `value` and `length` members of a bounded JER object.
///
/// # Parameters and returns
/// `token` is the trimmed JSON object. Returns the quoted hex body and logical
/// bit length for the C-compatible member order.
///
/// # Errors
/// Returns `InvalidEncoding` for missing, reordered, malformed, or extra data.
/// It raises no exception.
///
/// # Source, version, history, and example
/// Original source: key order in `BIT_STRING_decode_jer`. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: bounded JER.
/// Example: parses `{"value":"A8","length":5}`.
fn parse_bounded_bit_string_object(token: &[u8]) -> Result<(&[u8], usize), Error> {
    let mut offset = 0;
    take_json_literal(token, &mut offset, b"{")?;
    take_json_literal(token, &mut offset, b"\"value\"")?;
    take_json_literal(token, &mut offset, b":")?;
    take_json_literal(token, &mut offset, b"\"")?;
    let body_start = offset;
    let body_len = token[offset..]
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or_else(invalid_bit_string_token)?;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(Error::SizeOverflow)?;
    let body = &token[body_start..body_end];
    offset = body_end.checked_add(1).ok_or(Error::SizeOverflow)?;
    take_json_literal(token, &mut offset, b",")?;
    take_json_literal(token, &mut offset, b"\"length\"")?;
    take_json_literal(token, &mut offset, b":")?;
    skip_json_whitespace(token, &mut offset);
    let digits_start = offset;
    while token.get(offset).is_some_and(u8::is_ascii_digit) {
        offset += 1;
    }
    let digits = token
        .get(digits_start..offset)
        .filter(|digits| !digits.is_empty())
        .ok_or_else(invalid_bit_string_token)?;
    if digits.len() > 1 && digits[0] == b'0' {
        return Err(invalid_bit_string_token());
    }
    let bit_len = std::str::from_utf8(digits)
        .map_err(|_| invalid_bit_string_token())?
        .parse::<usize>()
        .map_err(|_| invalid_bit_string_token())?;
    take_json_literal(token, &mut offset, b"}")?;
    if offset != token.len() {
        return Err(invalid_bit_string_token());
    }
    Ok((body, bit_len))
}

/// Consume one expected JSON punctuation or quoted key after JSON whitespace.
///
/// # Parameters and returns
/// `input` is the bounded token, `offset` is updated past `expected`, and
/// `expected` is a literal byte string. Returns success on exact match.
///
/// # Errors
/// Returns `InvalidEncoding` on truncation or mismatch; raises no exception.
///
/// # Source, version, history, and example
/// Original source: structural checks in `BIT_STRING_decode_jer`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: bounded JER parser. Example: consume `:` after a key.
fn take_json_literal(input: &[u8], offset: &mut usize, expected: &[u8]) -> Result<(), Error> {
    skip_json_whitespace(input, offset);
    let end = offset
        .checked_add(expected.len())
        .ok_or(Error::SizeOverflow)?;
    if input.get(*offset..end) != Some(expected) {
        return Err(invalid_bit_string_token());
    }
    *offset = end;
    Ok(())
}

/// Skip the four JSON whitespace bytes without advancing beyond the input.
///
/// # Parameters and returns
/// `input` is the token and `offset` is updated past spaces, tabs, CR, and LF.
/// This helper returns no value and cannot fail.
///
/// # Errors
/// None; it raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: JSON whitespace accepted by `BIT_STRING__jer_skip_whitespace`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: bounded JER parser. Example: skip whitespace before a colon.
fn skip_json_whitespace(input: &[u8], offset: &mut usize) {
    while input
        .get(*offset)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
    {
        *offset += 1;
    }
}

/// Decode and validate an even-length hexadecimal body before allocating output.
///
/// # Parameters and returns
/// `body` is the quoted token content; `expected_len` optionally specifies
/// decoded octets; `prior_work` is input-scan work; `limits` bounds all work.
/// Returns decoded bytes.
///
/// # Errors
/// Returns malformed-hex, size, resource-limit, or allocation errors.
/// It raises no exception.
///
/// # Source, version, history, and example
/// Original source: hex conversion in `BIT_STRING_decode_jer` and the fixed
/// OCTET STRING JER helper. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: shared BIT STRING JER parser. Example: decodes
/// `b"A8"` as one octet.
fn decode_hex_body(
    body: &[u8],
    expected_len: Option<usize>,
    prior_work: usize,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    if body.len() & 1 != 0 {
        return Err(invalid_bit_string_token());
    }
    let output_len = body.len() / 2;
    if expected_len.is_some_and(|expected| expected != output_len) {
        return Err(invalid_bit_string_size());
    }
    let hex_work = body.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    let total_work = prior_work
        .checked_add(hex_work)
        .ok_or(Error::SizeOverflow)?;
    check_work_limit(total_work, limits)?;
    for pair_start in (0..body.len()).step_by(2) {
        if hex_nibble(body[pair_start]).is_none() || hex_nibble(body[pair_start + 1]).is_none() {
            return Err(invalid_bit_string_token());
        }
    }
    let mut output = allocate_zeroed(output_len, limits)?;
    for (index, octet) in output.iter_mut().enumerate() {
        let offset = index.checked_mul(2).ok_or(Error::SizeOverflow)?;
        let high = hex_nibble(body[offset]).ok_or_else(invalid_bit_string_token)?;
        let low = hex_nibble(body[offset + 1]).ok_or_else(invalid_bit_string_token)?;
        *octet = (high << 4) | low;
    }
    Ok(output)
}

/// Format one `usize` as decimal text in caller-provided storage.
///
/// # Parameters and returns
/// `value` is a nonnegative integer and `buffer` holds at least 20 bytes.
/// Returns the first occupied index; the number is `buffer[start..]`.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: minimal length field in C JER BIT STRING output.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: bounded JER output. Example: formats zero as `b"0"`.
const fn format_usize(value: usize, buffer: &mut [u8; 20]) -> usize {
    let mut cursor = buffer.len();
    let mut remaining = value;
    loop {
        cursor -= 1;
        buffer[cursor] = b"0123456789"[remaining % 10];
        remaining /= 10;
        if remaining == 0 {
            return cursor;
        }
    }
}

/// Return the static error for a malformed BIT STRING JER token.
///
/// # Parameters and returns
/// No parameters. Returns a stable `InvalidEncoding` error.
///
/// # Errors
/// Constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: strict complete-input BIT STRING JER validation.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added BIT STRING JER. Example: reports malformed hex.
const fn invalid_bit_string_token() -> Error {
    Error::InvalidEncoding {
        reason: "expected one complete BIT STRING JER value",
    }
}

/// Return the static error for inconsistent BIT STRING size or logical length.
///
/// # Parameters and returns
/// No parameters. Returns a stable `InvalidEncoding` error.
///
/// # Errors
/// Constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: BIT STRING SIZE validation in the generated Rust wrapper.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added BIT STRING JER. Example: reports a fixed-width mismatch.
const fn invalid_bit_string_size() -> Error {
    Error::InvalidEncoding {
        reason: "BIT STRING length does not match declared SIZE",
    }
}

/// Return the static error for nonzero unused low bits in packed BIT STRING data.
///
/// # Parameters and returns
/// No parameters. Returns a stable `InvalidEncoding` error.
///
/// # Errors
/// Constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: canonical BIT STRING storage and UPER cursor validation.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added BIT STRING JER. Example: rejects `0xA1` for a three-bit value.
const fn invalid_bit_string_padding() -> Error {
    Error::InvalidEncoding {
        reason: "nonzero unused BIT STRING bits",
    }
}

/// Convert one ASCII hexadecimal digit to its four-bit numeric value.
///
/// # Parameters and returns
/// `digit` is one candidate ASCII byte. Returns its nibble for `0`-`9`,
/// `A`-`F`, or `a`-`f`; otherwise returns `None`.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: hexadecimal digit mapping in `OCTET_STRING_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added with fixed-size OCTET STRING JER support. Example: `hex_nibble(b'F')`
/// returns `Some(15)`.
const fn hex_nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Construct the static error for an OCTET STRING size mismatch.
///
/// # Parameters and returns
/// No parameters. Returns an `InvalidEncoding` error for a nonmatching fixed
/// `SIZE` value.
///
/// # Errors
/// This helper constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: fixed-size validation for the generated Rust JER API.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added with fixed-size OCTET STRING JER support. Example:
/// `Err(invalid_octet_string_size())` reports a size mismatch.
const fn invalid_octet_string_size() -> Error {
    Error::InvalidEncoding {
        reason: "OCTET STRING length does not match declared SIZE",
    }
}

/// Construct the static error for a malformed OCTET STRING JSON token.
///
/// # Parameters and returns
/// No parameters. Returns an `InvalidEncoding` error for an invalid quoted
/// hexadecimal string.
///
/// # Errors
/// This helper constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: strict complete-input validation for the generated Rust JER
/// API. Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added with fixed-size OCTET STRING JER support. Example:
/// `Err(invalid_octet_string_token())` reports malformed hex.
const fn invalid_octet_string_token() -> Error {
    Error::InvalidEncoding {
        reason: "expected one complete quoted hexadecimal OCTET STRING",
    }
}

/// Check that a root identifier is safe as a literal JSON string body.
///
/// # Parameters and returns
/// name is the candidate ASN.1 identifier. Returns true for ASCII ASN.1
/// identifier characters that need no JSON escaping.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: ASN.1 identifier lexical restrictions and JER string
/// mapping. Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added with ENUMERATED JER support. Example:
/// `is_enumerated_name("sELF")` returns true.
fn is_enumerated_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        if byte == b'-' {
            if previous_hyphen {
                return false;
            }
            previous_hyphen = true;
        } else if byte.is_ascii_alphanumeric() {
            previous_hyphen = false;
        } else {
            return false;
        }
    }
    !previous_hyphen
}

/// Create the static error for an invalid ENUMERATED root-name table.
///
/// # Parameters and returns
/// No parameters. Returns an `InvalidEncoding` error for a malformed mapping.
///
/// # Errors
/// This helper constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: new bounded ENUMERATED JER helper. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: added with
/// ENUMERATED JER support. Example: return `Err(invalid_enumerated_mapping())`.
const fn invalid_enumerated_mapping() -> Error {
    Error::InvalidEncoding {
        reason: "ENUMERATED JER root-name mapping is invalid",
    }
}

/// Create the static error for a malformed or unknown ENUMERATED JSON string.
///
/// # Parameters and returns
/// No parameters. Returns an `InvalidEncoding` error for an invalid token.
///
/// # Errors
/// This helper constructs an error and cannot itself fail or raise an exception.
///
/// # Source, version, history, and example
/// Original source: new strict complete-input JER helper. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: added with
/// ENUMERATED JER support. Example: return `Err(invalid_enumerated_token())`.
const fn invalid_enumerated_token() -> Error {
    Error::InvalidEncoding {
        reason: "expected one complete known ENUMERATED JSON string",
    }
}

/// Allocate and populate an encoded ASCII JSON token under output/work limits.
///
/// # Parameters and returns
/// `token` is a static or stack-backed ASCII token; `limits` bounds resources.
/// Returns the token and its total number of wire bits.
///
/// # Errors
/// Returns a checked-size, work/output-limit, or allocation error. It raises no
/// exception.
///
/// # Source, version, history, and example
/// Original source: new bounded JER helper. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial JER primitive slice.
/// Example: `encode_token(b"null", limits)`.
fn encode_token(token: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    let bit_len = token.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;
    let mut bytes = allocate_zeroed(token.len(), limits)?;
    bytes.copy_from_slice(token);
    Ok(Encoded { bytes, bit_len })
}

/// Validate and trim one complete UTF-8 input while charging all supplied bytes.
///
/// # Parameters and returns
/// `input` is the entire caller buffer; `limits` sets input and work ceilings.
/// Returns the token slice without JSON whitespace and full-input bit count.
///
/// # Errors
/// Returns input/work limits, size overflow, invalid UTF-8, or empty-input
/// truncation. It raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new complete-input JER helper. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial JER primitive slice.
/// Example: `complete_token(b" null ", limits)` returns `null` and 48 bits.
fn complete_token<'a>(input: &'a [u8], limits: &Limits) -> Result<(&'a [u8], usize), Error> {
    check_input_limit(input, limits)?;
    let consumed_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(consumed_bits, limits)?;
    std::str::from_utf8(input).map_err(|_| Error::InvalidEncoding {
        reason: "JER input is not valid UTF-8",
    })?;

    let (start, end) = trim_json_whitespace(input);
    if start == end {
        return Err(Error::NeedMoreBytes {
            required_bytes: input.len().checked_add(1).ok_or(Error::SizeOverflow)?,
            available_bytes: input.len(),
        });
    }
    Ok((&input[start..end], consumed_bits))
}

/// Find the non-whitespace span using exactly the four JSON whitespace bytes.
///
/// # Parameters and returns
/// `input` is a valid byte slice. Returns half-open start and end offsets.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: JSON whitespace grammar (RFC 8259, section 2). Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
/// primitive slice. Example: `trim_json_whitespace(b"\ttrue ")` returns `(1, 5)`.
const fn trim_json_whitespace(input: &[u8]) -> (usize, usize) {
    let mut start = 0;
    let mut end = input.len();

    // Strip only JSON's permitted whitespace bytes; Unicode whitespace is not JSON whitespace.
    while start < end && is_json_whitespace(input[start]) {
        start += 1;
    }
    while end > start && is_json_whitespace(input[end - 1]) {
        end -= 1;
    }
    (start, end)
}

/// Return whether one byte is a JSON whitespace character.
///
/// # Parameters and returns
/// `byte` is the candidate input byte. Returns true for space, tab, LF, or CR.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: JSON whitespace grammar (RFC 8259, section 2). Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
/// primitive slice. Example: `is_json_whitespace(b' ')` is true.
const fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

/// Check whether a nonempty byte slice is a strict prefix of a keyword.
///
/// # Parameters and returns
/// `token` is the candidate token and `keyword` is its complete literal.
/// Returns true only when all token bytes match an initial keyword segment.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new JER keyword validation helper. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial JER primitive slice.
/// Example: `is_keyword_prefix(b"tru", b"true")` is true.
fn is_keyword_prefix(token: &[u8], keyword: &[u8]) -> bool {
    !token.is_empty() && token.len() < keyword.len() && keyword.starts_with(token)
}

/// Report whether a partial token could continue at the end of the input.
///
/// # Parameters and returns
/// `input` is the complete supplied buffer. Returns false when its last byte
/// is JSON whitespace, which already ended any preceding token.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: JSON token boundary rule. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: distinguish truncation from
/// a terminated incomplete token. Example: `token_can_continue(b"tru")` is true.
fn token_can_continue(input: &[u8]) -> bool {
    input.last().is_some_and(|byte| !is_json_whitespace(*byte))
}

/// Compute the full input length needed to complete a trimmed keyword prefix.
///
/// # Parameters and returns
/// `input_bytes` includes surrounding whitespace; `token_bytes` is the prefix
/// length; `keyword_bytes` is the complete keyword length. Returns the minimum
/// input byte count after inserting missing keyword bytes before trailing space.
///
/// # Errors
/// Returns `SizeOverflow` if adding the missing bytes overflows `usize`. It
/// raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new complete-input JER helper. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added for precise truncation
/// reports. Example: `keyword_required_bytes(3, 1, 4)` returns `6`.
fn keyword_required_bytes(
    input_bytes: usize,
    token_bytes: usize,
    keyword_bytes: usize,
) -> Result<usize, Error> {
    let missing = keyword_bytes
        .checked_sub(token_bytes)
        .ok_or(Error::SizeOverflow)?;
    input_bytes.checked_add(missing).ok_or(Error::SizeOverflow)
}

/// Parse the JSON integer grammar into an `i64` using checked arithmetic.
///
/// # Parameters and returns
/// `token` is the non-whitespace token. Returns its signed value when it uses
/// minimal integer syntax and fits the runtime's `i64` representation.
///
/// # Errors
/// Returns truncation for an empty token or lone minus, and `InvalidEncoding`
/// for invalid syntax or overflow. It raises no exception or allocates memory.
///
/// # Source, version, history, and example
/// Original source: JSON number grammar (RFC 8259, section 6) and
/// `INTEGER__jer_body_decode` in `skeletons/INTEGER_jer.c`. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
/// primitive slice. Example: `parse_integer(b"-12")` returns `-12`.
fn parse_integer(token: &[u8]) -> Result<i64, Error> {
    if token.is_empty() {
        return Err(Error::NeedMoreBytes {
            required_bytes: 1,
            available_bytes: 0,
        });
    }

    let negative = token[0] == b'-';
    let digits = if negative { &token[1..] } else { token };
    if digits.is_empty() {
        return Err(Error::NeedMoreBytes {
            required_bytes: token.len().checked_add(1).ok_or(Error::SizeOverflow)?,
            available_bytes: token.len(),
        });
    }
    validate_integer_digits(digits)?;

    let maximum = if negative {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    let magnitude = parse_magnitude(digits, maximum)?;
    if negative && magnitude == maximum {
        return Ok(i64::MIN);
    }
    let positive = i64::try_from(magnitude).map_err(|_| invalid_integer())?;
    if negative {
        positive.checked_neg().ok_or_else(invalid_integer)
    } else {
        Ok(positive)
    }
}

/// Validate minimal JSON integer digit syntax after an optional minus sign.
///
/// # Parameters and returns
/// `digits` is the digit portion. Returns `Ok(())` for `0` or a nonzero digit
/// followed by decimal digits.
///
/// # Errors
/// Returns `InvalidEncoding` for leading zeroes or non-digit syntax. It raises
/// no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: JSON integer grammar (RFC 8259, section 6). Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial JER
/// primitive slice. Example: `validate_integer_digits(b"120")?`.
fn validate_integer_digits(digits: &[u8]) -> Result<(), Error> {
    if digits[0] == b'0' {
        if digits.len() == 1 {
            return Ok(());
        }
        return Err(invalid_integer());
    }
    if !(b'1'..=b'9').contains(&digits[0]) {
        return Err(invalid_integer());
    }
    if digits.iter().any(|digit| !digit.is_ascii_digit()) {
        return Err(invalid_integer());
    }
    Ok(())
}

/// Accumulate decimal digits without exceeding the sign-specific `i64` magnitude.
///
/// # Parameters and returns
/// `digits` contains validated decimal digits; `maximum` is the allowed
/// magnitude. Returns the accumulated unsigned value.
///
/// # Errors
/// Returns `InvalidEncoding` when checked arithmetic overflows or exceeds the
/// allowed magnitude. It raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new checked JER integer parser. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial JER primitive slice.
/// Example: `parse_magnitude(b"12", 99)` returns `12`.
fn parse_magnitude(digits: &[u8], maximum: u64) -> Result<u64, Error> {
    let mut magnitude = 0_u64;
    for digit in digits {
        let numeric = u64::from(*digit - b'0');
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(numeric))
            .filter(|value| *value <= maximum)
            .ok_or_else(invalid_integer)?;
    }
    Ok(magnitude)
}

/// Format an `i64` into a caller-provided 20-byte decimal scratch buffer.
///
/// # Parameters and returns
/// `value` is the signed value; `buffer` receives the minimal decimal token.
/// Returns the first occupied buffer index.
///
/// # Errors
/// Returns `SizeOverflow` if an impossible scratch-buffer index underflows. It
/// raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new bounded JER integer formatter, matching the decimal
/// output of `NativeInteger_encode_jer` in `skeletons/NativeInteger_jer.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial JER primitive slice. Example: formatting `-12` writes `-12`.
fn format_integer(value: i64, buffer: &mut [u8; 20]) -> Result<usize, Error> {
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut cursor = buffer.len();

    // Emit digits backward so the minimum signed value needs no signed absolute-value operation.
    loop {
        let digit = (magnitude % 10) as u8;
        cursor = cursor.checked_sub(1).ok_or(Error::SizeOverflow)?;
        buffer[cursor] = b'0' + digit;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if negative {
        cursor = cursor.checked_sub(1).ok_or(Error::SizeOverflow)?;
        buffer[cursor] = b'-';
    }
    Ok(cursor)
}

/// Build a complete-input decode result with checked bit accounting supplied by the caller.
///
/// # Parameters and returns
/// `value` is the decoded primitive; `input_bytes` is the whole accepted slice;
/// `consumed_bits` is its checked full-input bit count. Returns a `Decoded`.
///
/// # Errors
/// This helper cannot fail, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new complete-input JER helper. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial JER primitive slice.
/// Example: `decoded_complete(true, 4, 32)` records a complete token.
const fn decoded_complete<T>(value: T, input_bytes: usize, consumed_bits: usize) -> Decoded<T> {
    Decoded {
        value,
        consumed_bits,
        consumed_bytes: input_bytes,
    }
}

/// Construct the shared malformed INTEGER syntax or overflow error.
///
/// # Parameters and returns
/// No parameters. Returns a static `InvalidEncoding` error.
///
/// # Errors
/// This helper constructs an error, raises no exception, and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new JER parser helper. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial JER primitive slice.
/// Example: `invalid_integer()` reports malformed JSON INTEGER syntax.
const fn invalid_integer() -> Error {
    Error::InvalidEncoding {
        reason: "expected a minimal finite JSON INTEGER within the i64 range",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Resource;

    /// Return default test limits for one primitive operation.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the runtime's finite defaults.
    ///
    /// # Errors
    /// This helper cannot fail and raises no exception.
    ///
    /// # Source, version, history, and example
    /// Original source: runtime test helper. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: added with JER tests.
    /// Example: `let limits = limits();`.
    fn limits() -> Limits {
        Limits::default()
    }

    /// Verify canonical BOOLEAN and NULL encoding and complete decoding.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: JER regression tests. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial test suite.
    /// Example: run with `cargo test`.
    #[test]
    fn boolean_and_null_tokens_round_trip() {
        assert_eq!(encode_boolean_jer(true, &limits()).unwrap().bytes, b"true");
        assert_eq!(
            encode_boolean_jer(false, &limits()).unwrap().bytes,
            b"false"
        );
        assert_eq!(encode_null_jer(&limits()).unwrap().bytes, b"null");

        let true_value = decode_boolean_jer(b"\ttrue \r\n", &limits()).unwrap();
        assert!(true_value.value);
        assert_eq!(true_value.consumed_bytes, 8);
        assert_eq!(true_value.consumed_bits, 64);
        assert!(!decode_boolean_jer(b"false", &limits()).unwrap().value);

        let null_value = decode_null_jer(b" \nnull\t", &limits()).unwrap();
        assert_eq!(null_value.value, ());
        assert_eq!(null_value.consumed_bytes, 7);
        assert_eq!(null_value.consumed_bits, 56);
    }

    /// Verify uppercase encoding, lowercase decoding, empty values, and every octet.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: fixed-size OCTET STRING JER regression tests.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added with OCTET STRING JER support. Example: run with
    /// `cargo test`.
    #[test]
    fn octet_string_tokens_encode_uppercase_and_round_trip_all_octets() {
        let all_octets: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = encode_octet_string_jer(&all_octets, 256, &limits()).unwrap();
        assert_eq!(encoded.bytes.len(), 514);
        assert_eq!(&encoded.bytes[..5], b"\"0001");
        assert_eq!(&encoded.bytes[encoded.bytes.len() - 5..], b"FEFF\"");
        assert_eq!(encoded.bit_len, encoded.bytes.len() * 8);
        assert!(encoded.bytes.iter().all(u8::is_ascii));

        let decoded = decode_octet_string_jer(&encoded.bytes, 256, &limits()).unwrap();
        assert_eq!(decoded.value, all_octets);
        assert_eq!(decoded.consumed_bytes, encoded.bytes.len());
        assert_eq!(decoded.consumed_bits, encoded.bit_len);

        let lowercase = decode_octet_string_jer(b" \t\"00af\"\r\n", 2, &limits()).unwrap();
        assert_eq!(lowercase.value, [0x00, 0xaf]);
        assert_eq!(lowercase.consumed_bytes, 10);
        assert_eq!(lowercase.consumed_bits, 80);

        let empty = encode_octet_string_jer(&[], 0, &limits()).unwrap();
        assert_eq!(empty.bytes, b"\"\"");
        assert_eq!(
            decode_octet_string_jer(b"\"\"", 0, &limits())
                .unwrap()
                .value,
            []
        );
    }

    /// Verify malformed OCTET STRING JSON forms and fixed-size mismatches are rejected.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: strict OCTET STRING JER regression tests.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added with OCTET STRING JER support. Example: run with
    /// `cargo test`.
    #[test]
    fn octet_string_decoder_rejects_malformed_tokens_and_sizes() {
        let invalid = [
            b"".as_slice(),
            b"\"",
            b"00\"",
            b"\"00",
            b"\"0\"",
            b"\"0G\"",
            b"\"GG\"",
            b"\"00\"x",
            b"\"00\" \"01\"",
            b"\"\\u0030\\u0030\"",
            b"\"00\"\0",
            b"\"\xff\"",
        ];
        for input in invalid {
            assert!(
                decode_octet_string_jer(input, 1, &limits()).is_err(),
                "accepted {input:?}"
            );
        }
        assert!(matches!(
            decode_octet_string_jer(b"\"00\"", 0, &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_octet_string_jer(b"\"\"", 1, &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            encode_octet_string_jer(&[0], 0, &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
    }

    /// Verify every token byte mutation to a non-hex character is rejected.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: deterministic malformed-input mutation regression test.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added with OCTET STRING JER support. Example: run with
    /// `cargo test`.
    #[test]
    fn octet_string_decoder_rejects_deterministic_malformed_mutations() {
        let valid = b"\"0123456789ABCDEF\"";
        for index in 1..valid.len() - 1 {
            let mut mutated = valid.to_vec();
            mutated[index] = b'G';
            assert!(
                matches!(
                    decode_octet_string_jer(&mutated, 8, &limits()),
                    Err(Error::InvalidEncoding { .. })
                ),
                "accepted mutation at byte {index}"
            );
        }
    }

    /// Verify OCTET STRING operations report input, output, and work limit errors.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: bounded OCTET STRING JER regression tests.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added with OCTET STRING JER support. Example: run with
    /// `cargo test`.
    #[test]
    fn octet_string_operations_enforce_resource_limits() {
        let encoded = b"\"00\"";
        let input_limited = Limits {
            max_input_bytes: 3,
            ..limits()
        };
        assert!(matches!(
            decode_octet_string_jer(encoded, 1, &input_limited),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));

        let output_limited = Limits {
            max_output_bytes: 0,
            ..limits()
        };
        assert!(matches!(
            encode_octet_string_jer(&[0], 1, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert!(matches!(
            decode_octet_string_jer(encoded, 1, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));

        let encode_work_limited = Limits {
            max_work_bits: 31,
            ..limits()
        };
        assert!(matches!(
            encode_octet_string_jer(&[0], 1, &encode_work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        let decode_work_limited = Limits {
            max_work_bits: 47,
            ..limits()
        };
        assert!(matches!(
            decode_octet_string_jer(encoded, 1, &decode_work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }

    /// Verify bounded OCTET STRING JER emits quoted hex and requires full input.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a valid round trip or expected rejection fails.
    ///
    /// # Source, version, history, and example
    /// Original source: variable OCTET STRING JER in
    /// `skeletons/OCTET_STRING_jer.c`. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: bounded OCTET JER.
    /// Example: `[0x00, 0xAF]` encodes as `"00AF"` in SIZE(1..3).
    #[test]
    fn bounded_octet_string_jer_round_trips_complete_hex_tokens() {
        let value = [0x00, 0xaf, 0xff];
        let encoded = encode_bounded_octet_string_jer(&value, 1, 7, &limits()).unwrap();
        assert_eq!(encoded.bytes, b"\"00AFFF\"");
        assert_eq!(encoded.bit_len, 64);

        let decoded =
            decode_bounded_octet_string_jer(b" \t\"00aFfF\"\r\n", 1, 7, &limits()).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bytes, 12);
        assert_eq!(decoded.consumed_bits, 96);
        for input in [
            b"\"\"".as_slice(),
            b"\"00AFFF\"x",
            b"\"00AFFFx\"",
            b"\"00AFFFG1\"",
            b"\"0000000000000000\"",
            b"[\"00AFFF\"]",
        ] {
            assert!(decode_bounded_octet_string_jer(input, 1, 7, &limits()).is_err());
        }
        assert!(encode_bounded_octet_string_jer(&[], 1, 7, &limits()).is_err());
        assert!(encode_bounded_octet_string_jer(&[0; 8], 1, 7, &limits()).is_err());
        assert_eq!(
            decode_bounded_octet_string_jer(b"\"\"", 0, 0, &limits())
                .unwrap()
                .value,
            Vec::<u8>::new()
        );
        assert!(decode_bounded_octet_string_jer(b"\"00\"", 2, 1, &limits()).is_err());
    }

    /// Verify bounded OCTET STRING JER honors all configured resource ceilings.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a configured input, output, or work cap is not enforced.
    ///
    /// # Source, version, history, and example
    /// Original source: bounded OCTET STRING JER resource accounting.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: bounded OCTET JER. Example: an output cap rejects `"00"`.
    #[test]
    fn bounded_octet_string_jer_enforces_resource_limits() {
        let value = [0x00];
        let encoded = b"\"00\"";
        let output_limited = Limits {
            max_output_bytes: 0,
            ..limits()
        };
        assert!(matches!(
            encode_bounded_octet_string_jer(&value, 1, 3, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert!(matches!(
            decode_bounded_octet_string_jer(encoded, 1, 3, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));

        let input_limited = Limits {
            max_input_bytes: 3,
            ..limits()
        };
        assert!(matches!(
            decode_bounded_octet_string_jer(encoded, 1, 3, &input_limited),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));

        let work_limited = Limits {
            max_work_bits: 31,
            ..limits()
        };
        assert!(matches!(
            encode_bounded_octet_string_jer(&value, 1, 3, &work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        let decode_work_limited = Limits {
            max_work_bits: 47,
            ..limits()
        };
        assert!(matches!(
            decode_bounded_octet_string_jer(encoded, 1, 3, &decode_work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }

    /// Verify minimal integer encoding and signed `i64` boundary round trips.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: JER regression tests. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial test suite.
    /// Example: run with `cargo test`.
    #[test]
    fn integer_tokens_are_minimal_and_cover_i64_boundaries() {
        let samples = [
            (i64::MIN, b"-9223372036854775808".as_slice()),
            (-1, b"-1".as_slice()),
            (0, b"0".as_slice()),
            (1, b"1".as_slice()),
            (i64::MAX, b"9223372036854775807".as_slice()),
        ];
        for (value, token) in samples {
            let encoded = encode_integer_jer(value, i64::MIN, i64::MAX, &limits()).unwrap();
            assert_eq!(encoded.bytes, token);
            assert_eq!(encoded.bit_len, token.len() * 8);
            let decoded = decode_integer_jer(token, i64::MIN, i64::MAX, &limits()).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bytes, token.len());
        }
        assert_eq!(
            decode_integer_jer(b"-0", -1, 1, &limits()).unwrap().value,
            0
        );
    }

    /// Verify whitespace grammar and strict complete-input keyword handling.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: JER regression tests. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial test suite.
    /// Example: run with `cargo test`.
    #[test]
    fn keywords_accept_only_json_whitespace_and_one_full_literal() {
        for input in [b"true".as_slice(), b" true", b"true\t", b"\r\ntrue "] {
            assert!(decode_boolean_jer(input, &limits()).unwrap().value);
        }
        for input in [b"null".as_slice(), b" null", b"null\t", b"\r\nnull "] {
            assert_eq!(decode_null_jer(input, &limits()).unwrap().value, ());
        }
        for input in [
            b"true false".as_slice(),
            b"truex",
            b"True",
            "false\u{00a0}".as_bytes(),
        ] {
            assert!(decode_boolean_jer(input, &limits()).is_err());
        }
        for input in [b"n".as_slice(), b"nul", b"nullx", b"NULL", b"null null"] {
            assert!(decode_null_jer(input, &limits()).is_err());
        }
    }

    /// Verify strict minimal JSON integer syntax and malformed token rejection.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: JER regression tests. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial test suite.
    /// Example: run with `cargo test`.
    #[test]
    fn integer_decoder_rejects_non_json_and_nonminimal_numbers() {
        for token in [
            b"+1".as_slice(),
            b"01",
            b"00",
            b"-01",
            b"1.0",
            b"1e3",
            b"1E3",
            b"--1",
            b"1x",
            b"[1]",
        ] {
            assert!(
                decode_integer_jer(token, i64::MIN, i64::MAX, &limits()).is_err(),
                "{token:?}"
            );
        }
        for token in [b"9223372036854775808".as_slice(), b"-9223372036854775809"] {
            assert!(decode_integer_jer(token, i64::MIN, i64::MAX, &limits()).is_err());
        }
        assert_eq!(
            decode_integer_jer(b" 12 \n", 0, 20, &limits())
                .unwrap()
                .value,
            12
        );
    }

    /// Verify malformed UTF-8, invalid bytes, and incomplete primitive prefixes.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: JER regression tests. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial test suite.
    /// Example: run with `cargo test`.
    #[test]
    fn invalid_utf8_bytes_and_truncated_tokens_are_rejected() {
        assert!(decode_boolean_jer(&[0xff], &limits()).is_err());
        assert!(decode_null_jer(b"nul\xff", &limits()).is_err());
        assert!(decode_integer_jer(b"1\0", i64::MIN, i64::MAX, &limits()).is_err());
        for input in [b"".as_slice(), b" ", b"t", b"tru", b"fals"] {
            assert!(decode_boolean_jer(input, &limits()).is_err());
        }
        for input in [b"".as_slice(), b" ", b"nu", b"nul"] {
            assert!(decode_null_jer(input, &limits()).is_err());
        }
        for input in [b"".as_slice(), b" ", b"-"] {
            assert!(decode_integer_jer(input, i64::MIN, i64::MAX, &limits()).is_err());
        }
        assert!(matches!(
            decode_boolean_jer(b"tru ", &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_null_jer(b"nul\t", &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_integer_jer(b"- ", i64::MIN, i64::MAX, &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_boolean_jer(b"tru", &limits()),
            Err(Error::NeedMoreBytes { .. })
        ));
    }

    /// Exercise every one-byte token against all primitive decoders.
    ///
    /// # Parameters and returns
    /// No parameters or return value; all 256 inputs must return a bounded
    /// result without a panic or out-of-bounds read.
    ///
    /// # Errors and panics
    /// Panics only if an assertion about a decoder result fails.
    ///
    /// # Source, version, history, and example
    /// Original source: deterministic malformed-input fuzz regression.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added with the JER primitive slice. Example: run `cargo test`.
    #[test]
    fn single_byte_mutations_remain_bounded() {
        for byte in u8::MIN..=u8::MAX {
            let input = [byte];
            assert!(decode_boolean_jer(&input, &limits()).is_err());
            assert!(decode_null_jer(&input, &limits()).is_err());
            let result = decode_integer_jer(&input, i64::MIN, i64::MAX, &limits());
            assert_eq!(result.is_ok(), byte.is_ascii_digit());
        }
    }

    /// Verify bounds validation and input, output, and cumulative work limits.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only when a test assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: JER resource regression tests. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial test suite.
    /// Example: run with `cargo test`.
    #[test]
    fn constraints_and_resource_budgets_are_enforced() {
        assert!(matches!(
            encode_integer_jer(1, 2, 1, &limits()),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            encode_integer_jer(3, 0, 2, &limits()),
            Err(Error::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            decode_integer_jer(b"3", 0, 2, &limits()),
            Err(Error::ValueOutOfRange { .. })
        ));

        let input_limited = Limits {
            max_input_bytes: 3,
            ..limits()
        };
        assert!(matches!(
            decode_null_jer(b"null", &input_limited),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        let work_limited = Limits {
            max_work_bits: 31,
            ..limits()
        };
        assert!(matches!(
            decode_null_jer(b"null", &work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        let output_limited = Limits {
            max_output_bytes: 3,
            ..limits()
        };
        assert!(matches!(
            encode_boolean_jer(true, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        let encode_work_limited = Limits {
            max_work_bits: 31,
            ..limits()
        };
        assert!(matches!(
            encode_null_jer(&encode_work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }

    /// Verify ENUMERATED names use compact C-compatible JSON string tokens.
    ///
    /// # Parameters and returns
    /// No parameters or return value; checks declaration-order mapping and
    /// complete-input consumption.
    ///
    /// # Errors and panics
    /// Panics only when an assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: ENUMERATED JER mapping in `skeletons/ENUMERATED_jer.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added with bounded ENUMERATED JER support. Example: run cargo test.
    #[test]
    fn enumerated_names_encode_and_decode() {
        let names = ["blue", "red", "sELF"];
        let encoded = encode_enumerated_jer(1, &names, &limits()).unwrap();
        assert_eq!(encoded.bytes, b"\"red\"");
        assert_eq!(encoded.bit_len, 40);

        let decoded = decode_enumerated_jer(b" \n\"sELF\"\t", &names, &limits()).unwrap();
        assert_eq!(decoded.value, 2);
        assert_eq!(decoded.consumed_bytes, 9);
        assert_eq!(decoded.consumed_bits, 72);
    }

    /// Reject malformed ENUMERATED strings, duplicate tables, and exhausted budgets.
    ///
    /// # Parameters and returns
    /// No parameters or return value; exercises hostile complete-input cases.
    ///
    /// # Errors and panics
    /// Panics only when an invalid token is unexpectedly accepted.
    ///
    /// # Source, version, history, and example
    /// Original source: strict complete-input JER requirements. Version/date:
    /// 2026-10-30. Responsible party: asn1c maintainers. History: added with
    /// ENUMERATED JER support. Example: run cargo test.
    #[test]
    fn enumerated_rejects_invalid_tokens_mappings_and_limits() {
        let names = ["blue", "red"];
        for token in [
            b"".as_slice(),
            b"\"red",
            b"red\"",
            b"\"unknown\"",
            b"\"red\"x",
            b"\"red\" \"blue\"",
            b"\"r\\u0065d\"",
            b"\"\xff\"",
        ] {
            assert!(
                decode_enumerated_jer(token, &names, &limits()).is_err(),
                "accepted {token:?}"
            );
        }
        assert!(encode_enumerated_jer(2, &names, &limits()).is_err());
        assert!(encode_enumerated_jer(0, &["bad\"name"], &limits()).is_err());
        assert!(encode_enumerated_jer(0, &["red-"], &limits()).is_err());
        assert!(encode_enumerated_jer(0, &["red--blue"], &limits()).is_err());
        assert!(encode_enumerated_jer(0, &["blue", "bad\"name"], &limits()).is_err());
        assert!(encode_enumerated_jer(0, &["red", "red"], &limits()).is_err());
        assert!(decode_enumerated_jer(b"\"red\"", &["red", "red"], &limits()).is_err());
        let too_many_names = vec!["red"; MAX_JER_ENUMERATED_VARIANTS + 1];
        assert!(encode_enumerated_jer(0, &too_many_names, &limits()).is_err());
        assert!(decode_enumerated_jer(b"\"red\"", &too_many_names, &limits()).is_err());

        let input_limited = Limits {
            max_input_bytes: 4,
            ..limits()
        };
        assert!(matches!(
            decode_enumerated_jer(b"\"red\"", &names, &input_limited),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        let work_limited = Limits {
            max_work_bits: 327,
            ..limits()
        };
        assert!(matches!(
            decode_enumerated_jer(b"\"red\"", &names, &work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        let output_limited = Limits {
            max_output_bytes: 4,
            ..limits()
        };
        assert!(matches!(
            encode_enumerated_jer(1, &names, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        let encode_work_limited = Limits {
            max_work_bits: 215,
            ..limits()
        };
        assert!(matches!(
            encode_enumerated_jer(0, &names, &encode_work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }

    /// Verify fixed BIT STRING hexadecimal tokens preserve exact logical width.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only if a regression assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: fixed-size `BIT_STRING_encode_jer` representation.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added BIT STRING JER tests. Example: a three-bit value uses
    /// one packed byte and emits `"A0"`.
    #[test]
    fn fixed_bit_string_jer_round_trips_canonical_hex() {
        let encoded = encode_bit_string_jer(&[0xa0], 3, &limits()).unwrap();
        assert_eq!(encoded.bytes, b"\"A0\"");
        assert_eq!(encoded.bit_len, 32);
        let decoded = decode_bit_string_jer(b" \t\"a0\"\r\n", 3, &limits()).unwrap();
        assert_eq!(decoded.value, [0xa0]);
        assert_eq!(decoded.consumed_bytes, 8);
        assert_eq!(decoded.consumed_bits, 64);
        assert_eq!(
            encode_bit_string_jer(&[], 0, &limits()).unwrap().bytes,
            b"\"\""
        );
    }

    /// Reject malformed fixed BIT STRING tokens and noncanonical padding.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only if a malformed-input regression assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: strict validation around `BIT_STRING_decode_jer`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added BIT STRING JER tests. Example: reject `"A1"` at width 3.
    #[test]
    fn fixed_bit_string_jer_rejects_bad_hex_size_padding_and_suffixes() {
        for input in [b"\"A\"".as_slice(), b"\"GG\"", b"\"A0\"false", b"\"0000\""] {
            assert!(decode_bit_string_jer(input, 3, &limits()).is_err());
        }
        assert!(decode_bit_string_jer(b"\"A1\"", 3, &limits()).is_err());
        assert!(encode_bit_string_jer(&[0xa1], 3, &limits()).is_err());
        assert!(encode_bit_string_jer(&[], 1, &limits()).is_err());
    }

    /// Verify bounded BIT STRING values use the C variable-size JSON shape.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only if a generated token or round-trip assertion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: variable-size `BIT_STRING_encode_jer` representation.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added bounded BIT STRING JER tests. Example: width five `A8`
    /// encodes as `{"value":"A8","length":5}`.
    #[test]
    fn bounded_bit_string_jer_uses_value_then_length_object() {
        let value = BitStringValue::new(vec![0xa8], 5).unwrap();
        let encoded = encode_bounded_bit_string_jer(&value, 1, 7, &limits()).unwrap();
        assert_eq!(encoded.bytes, b"{\"value\":\"A8\",\"length\":5}");
        assert_eq!(encoded.bit_len, encoded.bytes.len() * 8);
        let decoded = decode_bounded_bit_string_jer(
            b" { \"value\" : \"a8\" , \"length\" : 5 } ",
            1,
            7,
            &limits(),
        )
        .unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bytes, 35);
        assert_eq!(decoded.consumed_bits, 35 * 8);
    }

    /// Reject bounded BIT STRING objects with invalid syntax, widths, or padding.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only if an invalid bounded object is accepted.
    ///
    /// # Source, version, history, and example
    /// Original source: size and packed-data validation for variable BIT STRING.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added bounded BIT STRING JER tests. Example: `length:5` with
    /// an empty payload is rejected.
    #[test]
    fn bounded_bit_string_jer_rejects_invalid_objects() {
        for input in [
            b"{}".as_slice(),
            b"{\"length\":5,\"value\":\"A8\"}",
            b"{\"value\":\"A8\",\"length\":0}",
            b"{\"value\":\"A8\",\"length\":8}",
            b"{\"value\":\"A1\",\"length\":5}",
            b"{\"value\":\"A8\",\"length\":05}",
            b"{\"value\":\"A8\",\"length\":5} false",
        ] {
            assert!(decode_bounded_bit_string_jer(input, 1, 7, &limits()).is_err());
        }
        let value = BitStringValue::new(vec![0xa8], 5).unwrap();
        assert!(encode_bounded_bit_string_jer(&value, 6, 7, &limits()).is_err());
        assert!(encode_bounded_bit_string_jer(&value, 7, 1, &limits()).is_err());
    }

    /// Ensure fixed and bounded BIT STRING JER obey input, output, and work caps.
    ///
    /// # Parameters and returns
    /// No parameters or return value.
    ///
    /// # Errors
    /// Panics only if a resource ceiling is not enforced.
    ///
    /// # Source, version, history, and example
    /// Original source: bounded JER runtime resource accounting.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added BIT STRING JER limit coverage. Example: a three-byte
    /// output limit rejects the four-byte fixed token `"A0"`.
    #[test]
    fn bit_string_jer_enforces_resource_limits() {
        let output_limited = Limits {
            max_output_bytes: 3,
            ..limits()
        };
        assert!(matches!(
            encode_bit_string_jer(&[0xa0], 3, &output_limited),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        let input_limited = Limits {
            max_input_bytes: 3,
            ..limits()
        };
        assert!(matches!(
            decode_bit_string_jer(b"\"A0\"", 3, &input_limited),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        let work_limited = Limits {
            max_work_bits: 31,
            ..limits()
        };
        assert!(matches!(
            encode_bit_string_jer(&[0xa0], 3, &work_limited),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }
}
