//! Bounded primitive codecs for Octet Encoding Rules (OER).
//!
//! This module implements OER BOOLEAN and NULL, plus signed `i64` INTEGER
//! values with finite inclusive bounds. It does not implement complete OER or
//! canonical validation for every possible wire form. Encoders emit the
//! canonical BOOLEAN truth octet and fixed-width constrained INTEGER forms;
//! BOOLEAN decoding accepts any nonzero truth octet as required by basic OER.
//!
//! INTEGER widths follow ITU-T X.696 (02/2021), clauses 10.2–10.4: bounds
//! determine whether the value uses a fixed unsigned or signed 1, 2, 4, or
//! 8-octet word. The numeric value itself is encoded, without subtracting the
//! lower bound. Singleton INTEGER ranges therefore still use one octet.
//!
//! Decoders consume one value prefix and leave any suffix untouched. Each
//! operation checks the supplied input size, output size, and meaningful
//! octet work against the caller's [`Limits`].
//!
//! Original source: X.696 OER rules and the primitive implementations in
//! `skeletons/BOOLEAN_oer.c`, `skeletons/NULL_oer.c`, and
//! `skeletons/INTEGER_oer.c`. Version/date: Rust OER primitive slice,
//! 2026-10-30. Responsible party: asn1c maintainers. History: added after the
//! UPER and BER-family primitive slices. Example: `encode_integer_oer(7, 0,
//! 255, &Limits::default())?` produces `[7]`.

use super::{
    allocate_zeroed, check_input_limit, check_work_limit, require_bytes, validate_integer, Decoded,
    Encoded, Error, Limits,
};

/// Encode an OER BOOLEAN using canonical primitive output.
///
/// # Parameters
/// `value` is the ASN.1 BOOLEAN; `limits` bounds output bytes and wire work.
///
/// # Returns
/// One octet: `00` for FALSE or canonical `FF` for TRUE, with eight work bits.
///
/// # Errors
/// Returns an output-size, work-limit, or allocation error. It raises no
/// exception.
///
/// # Source, version, history, and example
/// Original source: X.696 clauses 9 and 31.3; `BOOLEAN_encode_oer` in
/// `skeletons/BOOLEAN_oer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial OER primitive slice. Example:
/// `encode_boolean_oer(true, &Limits::default())?` returns `[0xFF]`.
pub fn encode_boolean_oer(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    check_work_limit(8, limits)?;
    let mut bytes = allocate_zeroed(1, limits)?;

    // X.696 canonical output uses FF for TRUE and zero for FALSE.
    bytes[0] = if value { u8::MAX } else { 0 };
    Ok(Encoded { bytes, bit_len: 8 })
}

/// Decode one OER BOOLEAN prefix.
///
/// # Parameters
/// `input` is the available input prefix and may contain a suffix; `limits`
/// bounds the full slice and one octet of decoder work.
///
/// # Returns
/// The BOOLEAN value and consumption of exactly one octet. Every nonzero
/// octet represents TRUE, including noncanonical values other than `FF`.
///
/// # Errors
/// Returns `NeedMoreBytes`, an input/work limit error, or a size error. It
/// raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.696 clause 9 and `BOOLEAN_decode_oer` in
/// `skeletons/BOOLEAN_oer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial OER primitive slice. Example:
/// `decode_boolean_oer(&[1], &Limits::default())?` returns TRUE.
pub fn decode_boolean_oer(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, 1)?;
    check_work_limit(8, limits)?;

    // Basic OER permits any nonzero truth octet; the encoder emits canonical FF.
    Ok(Decoded {
        value: input[0] != 0,
        consumed_bits: 8,
        consumed_bytes: 1,
    })
}

/// Encode an OER NULL value.
///
/// # Parameters
/// `limits` bounds the empty output and the zero-octet work performed.
///
/// # Returns
/// An empty byte vector with `bit_len == 0`, as NULL has no OER contents.
///
/// # Errors
/// Returns an output-size or work-limit error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: OER NULL encoding has zero contents in
/// `skeletons/NULL_oer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial OER primitive slice. Example:
/// `encode_null_oer(&Limits::default())?` returns an empty encoding.
pub fn encode_null_oer(limits: &Limits) -> Result<Encoded, Error> {
    check_work_limit(0, limits)?;
    let bytes = allocate_zeroed(0, limits)?;
    Ok(Encoded { bytes, bit_len: 0 })
}

/// Decode an OER NULL prefix.
///
/// # Parameters
/// `input` is the available input prefix and may contain a suffix; `limits`
/// bounds the full supplied slice. NULL consumes no bytes.
///
/// # Returns
/// Unit value with zero bits and zero bytes consumed, even when input is empty.
///
/// # Errors
/// Returns an input-size limit error. The operation performs zero wire work
/// and raises no exception.
///
/// # Source, version, history, and example
/// Original source: `NULL_decode_oer` in `skeletons/NULL_oer.c`. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial OER
/// primitive slice. Example: `decode_null_oer(&[], &Limits::default())?`.
pub fn decode_null_oer(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    check_input_limit(input, limits)?;
    check_work_limit(0, limits)?;
    Ok(Decoded {
        value: (),
        consumed_bits: 0,
        consumed_bytes: 0,
    })
}

/// Encode a bounded signed INTEGER using its X.696 fixed-width OER form.
///
/// # Parameters
/// `value` is the integer; `lower` and `upper` are inclusive effective bounds;
/// `limits` bounds output bytes and wire work.
///
/// # Returns
/// The value in the smallest X.696 fixed word of 1, 2, 4, or 8 octets that
/// contains the entire declared range. The lower bound is not subtracted.
///
/// # Errors
/// Returns invalid bounds, an out-of-range value, an output/work limit error,
/// or allocation error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.696 clauses 10.2–10.4 and `INTEGER_encode_oer` in
/// `skeletons/INTEGER_oer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial bounded OER slice. Example:
/// `encode_integer_oer(-1, -128, 127, limits)?` returns `[0xFF]`.
pub fn encode_integer_oer(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;
    let (width, _) = integer_width(lower, upper)?;
    let bit_len = width.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;
    let mut bytes = allocate_zeroed(width, limits)?;

    // Copy the low fixed-width octets after range-based width selection.
    let encoded = value.to_be_bytes();
    bytes.copy_from_slice(&encoded[8 - width..]);

    Ok(Encoded { bytes, bit_len })
}

/// Decode one bounded signed INTEGER OER prefix into an `i64`.
///
/// # Parameters
/// `input` is the available input prefix and may contain a suffix; `lower` and
/// `upper` are inclusive effective bounds; `limits` bounds the full input and
/// the fixed-width value work.
///
/// # Returns
/// The decoded integer and consumption of exactly the bound-selected 1, 2, 4,
/// or 8 octets. Trailing bytes remain unconsumed.
///
/// # Errors
/// Returns invalid bounds, truncation, malformed/out-of-range value, input or
/// work-limit, or size errors. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.696 clauses 10.2–10.4 and `INTEGER_decode_oer` in
/// `skeletons/INTEGER_oer.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial bounded OER slice. Example:
/// `decode_integer_oer(&[0xFF], -128, 127, limits)?` returns `-1`.
pub fn decode_integer_oer(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    let (width, unsigned) = integer_width(lower, upper)?;
    check_input_limit(input, limits)?;
    require_bytes(input, width)?;
    let bit_len = width.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;

    // Decode as an unsigned fixed word for nonnegative ranges, otherwise sign-extend.
    let contents = &input[..width];
    let value = if unsigned {
        let mut octets = [0; 8];
        octets[8 - width..].copy_from_slice(contents);
        let unsigned_value = u64::from_be_bytes(octets);
        i64::try_from(unsigned_value).map_err(|_| Error::InvalidEncoding {
            reason: "OER unsigned INTEGER is outside the 64-bit runtime range",
        })?
    } else {
        let sign = if contents[0] & 0x80 != 0 { 0xff } else { 0 };
        let mut octets = [sign; 8];
        octets[8 - width..].copy_from_slice(contents);
        i64::from_be_bytes(octets)
    };
    validate_integer(value, lower, upper)?;

    Ok(Decoded {
        value,
        consumed_bits: bit_len,
        consumed_bytes: width,
    })
}

/// Select the fixed INTEGER word required by X.696 for finite `i64` bounds.
///
/// # Parameters and returns
/// `lower` and `upper` are inclusive bounds. Returns the octet width and
/// whether the wire word is unsigned.
///
/// # Errors
/// Returns `InvalidBounds`; it raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: X.696 clauses 10.2–10.4. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial bounded OER slice.
/// Example: `integer_width(0, 256)?` returns `(2, true)`.
fn integer_width(lower: i64, upper: i64) -> Result<(usize, bool), Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }

    // X.696 chooses unsigned words when the effective lower bound is nonnegative.
    if lower >= 0 {
        let width = if upper <= i64::from(u8::MAX) {
            1
        } else if upper <= i64::from(u16::MAX) {
            2
        } else if upper <= i64::from(u32::MAX) {
            4
        } else {
            8
        };
        return Ok((width, true));
    }

    // Negative lower bounds select the smallest signed word containing both ends.
    let width = if lower >= i64::from(i8::MIN) && upper <= i64::from(i8::MAX) {
        1
    } else if lower >= i64::from(i16::MIN) && upper <= i64::from(i16::MAX) {
        2
    } else if lower >= i64::from(i32::MIN) && upper <= i64::from(i32::MAX) {
        4
    } else {
        8
    };
    Ok((width, false))
}

/// Encode opaque ANY octets with an OER length determinant.
///
/// # Parameters and returns
/// `value` supplies octets and `limits` bounds resources. Returns the encoding.
///
/// # Errors
/// Returns size, resource, or allocation errors.
///
/// # Source, version, history, and example
/// Source: `ANY_encode_oer` and `oer_serialize_length`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: opaque OER ANY support.
/// Example: `encode_any_oer(&[0xa5], &Limits::default())?`.
pub fn encode_any_oer(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    let length = value.len();
    let octets = length.to_be_bytes();
    let first = octets
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(octets.len() - 1);
    let count = octets.len() - first;
    let header = if length < 128 { 1 } else { count + 1 };
    let total = header.checked_add(length).ok_or(Error::SizeOverflow)?;
    let bits = total.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bits, limits)?;
    let mut bytes = allocate_zeroed(total, limits)?;
    if length < 128 {
        bytes[0] = u8::try_from(length).map_err(|_| Error::SizeOverflow)?;
    } else {
        bytes[0] = 0x80 | u8::try_from(count).map_err(|_| Error::SizeOverflow)?;
        bytes[1..header].copy_from_slice(&octets[first..]);
    }
    bytes[header..].copy_from_slice(value);
    Ok(Encoded {
        bytes,
        bit_len: bits,
    })
}

/// Decode an OER length-delimited opaque ANY prefix.
///
/// # Parameters and returns
/// `input` supplies the prefix; `limits` bounds resources. Returns octets and
/// consumed lengths. Basic OER permits nonminimal length representations.
///
/// # Errors
/// Returns truncation, arithmetic, allocation, or resource errors.
///
/// # Source, version, history, and example
/// Source: `ANY_decode_oer` and `oer_fetch_length`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: opaque OER ANY support.
/// Example: `decode_any_oer(&[1, 0xa5], &Limits::default())?`.
pub fn decode_any_oer(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, 1)?;
    let first = input[0];
    let count = if first & 0x80 == 0 {
        0
    } else {
        usize::from(first & 0x7f)
    };
    let header = count + 1;
    require_bytes(input, header)?;
    let mut length = if count == 0 && first & 0x80 == 0 {
        usize::from(first)
    } else {
        0
    };
    for byte in &input[1..header] {
        length = length
            .checked_mul(256)
            .and_then(|n| n.checked_add(usize::from(*byte)))
            .ok_or(Error::SizeOverflow)?;
    }
    let total = header.checked_add(length).ok_or(Error::SizeOverflow)?;
    require_bytes(input, total)?;
    let bits = total.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bits, limits)?;
    let mut value = allocate_zeroed(length, limits)?;
    value.copy_from_slice(&input[header..total]);
    Ok(Decoded {
        value,
        consumed_bits: bits,
        consumed_bytes: total,
    })
}

/// Encode a selected primitive and selector in a complete OER record.
///
/// # Parameters and returns
/// `selector` and `selector_bounds` describe the INTEGER selector. `value`,
/// `value_bounds` and `boolean` describe the selected primitive. `limits`
/// bounds the entire operation. Returns the record encoding.
///
/// # Errors
/// Returns invalid values, bounds, exhausted resources, allocation or size errors.
///
/// # Source, version, history, and example
/// Source: C OER SEQUENCE and OPEN TYPE codecs. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: selected primitive OPEN TYPE.
/// Example: `encode_open_record_oer(1, (0, 255), 1, (0, 1), true, limits)?`.
pub fn encode_open_record_oer(
    selector: i64,
    selector_bounds: (i64, i64),
    value: i64,
    value_bounds: (i64, i64),
    boolean: bool,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let id = encode_integer_oer(selector, selector_bounds.0, selector_bounds.1, limits)?;
    let inner = if boolean {
        validate_integer(value, 0, 1)?;
        encode_boolean_oer(value != 0, limits)?
    } else {
        encode_integer_oer(value, value_bounds.0, value_bounds.1, limits)?
    };
    let envelope = encode_any_oer(&inner.bytes, limits)?;
    let length = id
        .bytes
        .len()
        .checked_add(envelope.bytes.len())
        .ok_or(Error::SizeOverflow)?;
    let bits = length.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(
        bits.checked_add(inner.bit_len).ok_or(Error::SizeOverflow)?,
        limits,
    )?;
    let mut bytes = allocate_zeroed(length, limits)?;
    bytes[..id.bytes.len()].copy_from_slice(&id.bytes);
    bytes[id.bytes.len()..].copy_from_slice(&envelope.bytes);
    Ok(Encoded {
        bytes,
        bit_len: bits,
    })
}

/// Decode one selected primitive OER envelope after a decoded selector.
///
/// # Parameters and returns
/// `input` is the complete record prefix; `offset` is the selector byte width;
/// `bounds` and `boolean` describe the selected primitive. `limits` bounds
/// input, output, and cumulative work. Returns value and full-prefix lengths.
///
/// # Errors
/// Returns malformed, truncated, invalid-value, resource or allocation errors.
///
/// # Source, version, history, and example
/// Source: C OER SEQUENCE and OPEN TYPE codecs. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: selected primitive OPEN TYPE.
/// Example: `decode_open_payload_oer(input, 1, (0, 1), true, limits)?`.
pub fn decode_open_payload_oer(
    input: &[u8],
    offset: usize,
    bounds: (i64, i64),
    boolean: bool,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, offset)?;
    let envelope = decode_any_oer(&input[offset..], limits)?;
    let inner = if boolean {
        let decoded = decode_boolean_oer(&envelope.value, limits)?;
        Decoded {
            value: i64::from(decoded.value),
            consumed_bits: decoded.consumed_bits,
            consumed_bytes: decoded.consumed_bytes,
        }
    } else {
        decode_integer_oer(&envelope.value, bounds.0, bounds.1, limits)?
    };
    if inner.consumed_bytes != envelope.value.len() {
        return Err(Error::InvalidEncoding {
            reason: "OPEN TYPE envelope has trailing octets",
        });
    }
    let total = offset
        .checked_add(envelope.consumed_bytes)
        .ok_or(Error::SizeOverflow)?;
    let bits = total.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(
        bits.checked_add(inner.consumed_bits)
            .ok_or(Error::SizeOverflow)?,
        limits,
    )?;
    Ok(Decoded {
        value: inner.value,
        consumed_bits: bits,
        consumed_bytes: total,
    })
}

#[cfg(test)]
mod tests {
    //! Regression coverage for bounded OER primitive boundaries and limits.

    use super::{
        decode_boolean_oer, decode_integer_oer, decode_null_oer, encode_boolean_oer,
        encode_integer_oer, encode_null_oer,
    };
    use crate::{Error, Limits, Resource};

    /// Return standard default resource ceilings for one test operation.
    ///
    /// Original source: OER runtime tests. Version/date: 2026-10-30.
    /// Parameters: none. Returns: default limits. Errors: none. Responsible
    /// party: asn1c maintainers. History: initial OER primitive tests. Example:
    /// `let limits = limits();`.
    fn limits() -> Limits {
        Limits::default()
    }

    /// Test canonical BOOLEAN output and permissive OER truth decoding.
    ///
    /// Original source: X.696 clause 9 and C OER BOOLEAN skeleton. Version/date:
    /// 2026-10-30. Parameters: none. Returns: no value; assertions fail on a
    /// mismatch. Errors: test panic on failure. Responsible party: asn1c
    /// maintainers. History: initial OER primitive tests. Example: TRUE encodes
    /// as `[0xFF]`, while `[1]` decodes as TRUE.
    #[test]
    fn boolean_canonical_output_and_basic_truth_values() {
        let false_value = encode_boolean_oer(false, &limits()).expect("encode FALSE");
        let true_value = encode_boolean_oer(true, &limits()).expect("encode TRUE");
        assert_eq!(false_value.bytes, [0x00]);
        assert_eq!(true_value.bytes, [0xff]);
        assert_eq!(false_value.bit_len, 8);
        assert!(!decode_boolean_oer(&[0], &limits()).unwrap().value);
        assert!(decode_boolean_oer(&[1], &limits()).unwrap().value);
        assert!(decode_boolean_oer(&[0x7f], &limits()).unwrap().value);
        assert_eq!(
            decode_boolean_oer(&[0, 0xaa], &limits())
                .unwrap()
                .consumed_bytes,
            1
        );
    }

    /// Test BOOLEAN truncation and exact resource-budget boundaries.
    ///
    /// Original source: OER primitive budget contract. Version/date: 2026-10-30.
    /// Parameters: none. Returns: no value; assertions fail on a mismatch.
    /// Errors: test panic on failure. Responsible party: asn1c maintainers.
    /// History: initial OER primitive tests. Example: an empty input requests
    /// one byte, while a seven-bit work budget rejects one BOOLEAN octet.
    #[test]
    fn boolean_truncation_and_limits() {
        assert!(matches!(
            decode_boolean_oer(&[], &limits()),
            Err(Error::NeedMoreBytes {
                required_bytes: 1,
                ..
            })
        ));

        // Configure each ceiling immediately below the one-octet operation.
        let mut tight = limits();
        tight.max_input_bytes = 0;
        assert!(matches!(
            decode_boolean_oer(&[0], &tight),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        tight.max_input_bytes = 1;
        tight.max_work_bits = 7;
        assert!(matches!(
            decode_boolean_oer(&[0], &tight),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        tight.max_work_bits = 8;
        tight.max_output_bytes = 0;
        assert!(matches!(
            encode_boolean_oer(true, &tight),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
    }

    /// Test zero-width NULL encoding and prefix behavior.
    ///
    /// Original source: OER NULL skeleton. Version/date: 2026-10-30.
    /// Parameters: none. Returns: no value; assertions fail on a mismatch.
    /// Errors: test panic on failure. Responsible party: asn1c maintainers.
    /// History: initial OER primitive tests. Example: empty input decodes NULL
    /// and reports zero bytes consumed.
    #[test]
    fn null_is_empty_and_consumes_no_input() {
        let encoded = encode_null_oer(&limits()).expect("encode NULL");
        assert_eq!(encoded.bytes, Vec::<u8>::new());
        assert_eq!(encoded.bit_len, 0);
        let decoded = decode_null_oer(&[0xaa], &limits()).expect("decode NULL");
        assert_eq!(decoded.consumed_bits, 0);
        assert_eq!(decoded.consumed_bytes, 0);

        let mut zero_limits = limits();
        zero_limits.max_output_bytes = 0;
        zero_limits.max_work_bits = 0;
        encode_null_oer(&zero_limits).expect("zero-width NULL fits zero budgets");
        zero_limits.max_input_bytes = 0;
        decode_null_oer(&[], &zero_limits).expect("empty input fits zero budget");
    }

    /// Test the X.696 unsigned and signed INTEGER width transitions.
    ///
    /// Original source: X.696 clauses 10.3 and 10.4. Version/date: 2026-10-30.
    /// Parameters: none. Returns: no value; assertions fail on a mismatch.
    /// Errors: test panic on failure. Responsible party: asn1c maintainers.
    /// History: initial OER primitive tests. Example: the range `0..=256` uses
    /// two octets, and the range `-128..=127` uses one.
    #[test]
    fn integer_width_boundaries_follow_oer_ranges() {
        let limits = limits();
        let vectors = [
            (0, 0, 255, vec![0x00]),
            (255, 0, 255, vec![0xff]),
            (256, 0, 256, vec![0x01, 0x00]),
            (65_535, 0, 65_535, vec![0xff, 0xff]),
            (65_536, 0, 65_536, vec![0, 1, 0, 0]),
            (-128, -128, 127, vec![0x80]),
            (127, -128, 127, vec![0x7f]),
            (128, -128, 128, vec![0x00, 0x80]),
            (-32_769, -32_769, 0, vec![0xff, 0xff, 0x7f, 0xff]),
            (
                i64::MIN,
                i64::MIN,
                i64::MAX,
                i64::MIN.to_be_bytes().to_vec(),
            ),
            (i64::MAX, 0, i64::MAX, i64::MAX.to_be_bytes().to_vec()),
        ];

        for (value, lower, upper, expected) in vectors {
            // Verify both prescribed octets and the inverse signed value.
            let encoded =
                encode_integer_oer(value, lower, upper, &limits).expect("encode bounded INTEGER");
            assert_eq!(encoded.bytes, expected);
            assert_eq!(encoded.bit_len, encoded.bytes.len() * 8);
            assert_eq!(
                decode_integer_oer(&encoded.bytes, lower, upper, &limits)
                    .expect("decode bounded INTEGER")
                    .value,
                value
            );
        }
    }

    /// Test INTEGER singleton ranges, validation, truncation, and limits.
    ///
    /// Original source: X.696 INTEGER rules and OER runtime limits.
    /// Version/date: 2026-10-30. Parameters: none. Returns: no value; assertions
    /// fail on a mismatch. Errors: test panic on failure. Responsible party:
    /// asn1c maintainers. History: initial OER primitive tests. Example: a
    /// singleton value of 5 still encodes as one octet `[5]`.
    #[test]
    fn integer_singleton_errors_and_limits() {
        let encoded = encode_integer_oer(5, 5, 5, &limits()).expect("singleton");
        assert_eq!(encoded.bytes, [5]);
        assert_eq!(decode_integer_oer(&[5], 5, 5, &limits()).unwrap().value, 5);
        assert!(matches!(
            encode_integer_oer(6, 5, 5, &limits()),
            Err(Error::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            encode_integer_oer(0, 1, 0, &limits()),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            decode_integer_oer(&[], -1, 1, &limits()),
            Err(Error::NeedMoreBytes {
                required_bytes: 1,
                ..
            })
        ));

        // Exact resource boundaries accept the encoded width and reject one less.
        let mut tight = limits();
        tight.max_output_bytes = 1;
        tight.max_work_bits = 8;
        encode_integer_oer(-1, -128, 127, &tight).expect("one-byte output budget");
        tight.max_output_bytes = 0;
        assert!(matches!(
            encode_integer_oer(-1, -128, 127, &tight),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        tight.max_input_bytes = 1;
        tight.max_output_bytes = 1;
        tight.max_work_bits = 7;
        assert!(matches!(
            decode_integer_oer(&[0], -128, 127, &tight),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }

    /// Test INTEGER prefix consumption, sign extension, and out-of-range input.
    ///
    /// Original source: X.696 INTEGER rules. Version/date: 2026-10-30.
    /// Parameters: none. Returns: no value; assertions fail on a mismatch.
    /// Errors: test panic on failure. Responsible party: asn1c maintainers.
    /// History: initial OER primitive tests. Example: `FF FF` sign-extends to
    /// `-1` under bounds `-32768..=32767`.
    #[test]
    fn integer_decoder_consumes_prefix_and_checks_bounds() {
        let decoded = decode_integer_oer(&[0xff, 0xff, 0x55], -32_768, 32_767, &limits())
            .expect("decode signed prefix");
        assert_eq!(decoded.value, -1);
        assert_eq!(decoded.consumed_bytes, 2);
        assert_eq!(decoded.consumed_bits, 16);
        assert!(matches!(
            decode_integer_oer(&[10], 0, 9, &limits()),
            Err(Error::ValueOutOfRange { value: 10, .. })
        ));
        assert!(matches!(
            decode_integer_oer(&[0xff; 8], 0, i64::MAX, &limits()),
            Err(Error::InvalidEncoding { .. })
        ));
    }
}
