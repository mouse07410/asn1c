//! Safe, bounded primitive codecs for the compact JSON Encoding Rules (JER).
//!
//! This module encodes BOOLEAN, NULL, and finite bounded signed `i64` INTEGER
//! values as compact C-compatible JSON primitive tokens. Decoders accept one
//! complete primitive with optional JSON whitespace (space, tab, LF, or CR)
//! around it. They reject any non-whitespace suffix and consume the complete
//! supplied input, including surrounding whitespace. This is a complete-input
//! API; it does not provide incremental or streaming token decoding.
//!
//! Specification: ITU-T X.697 (02/2021),
//! <https://www.itu.int/rec/T-REC-X.697-202102-I/en>. C implementation
//! references: `skeletons/BOOLEAN_jer.c`, `NULL_jer.c`, `NativeInteger_jer.c`,
//! and `INTEGER_jer.c`. The INTEGER lexical tests also reflect vectors in
//! `tests/tests-skeletons/check-INTEGER.c`. Version/date: 2026-10-30.
//! Responsible party: asn1c maintainers. History: initial bounded JER
//! primitive slice. Example: `encode_boolean_jer(true, &Limits::default())?`
//! produces the four bytes `true`.

use super::{
    allocate_zeroed, check_input_limit, check_work_limit, validate_integer, Decoded, Encoded,
    Error, Limits,
};

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
}
