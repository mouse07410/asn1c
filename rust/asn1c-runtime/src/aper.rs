//! Safe, bounded APER primitives for BOOLEAN, NULL, and bounded signed INTEGER.
//!
//! Every operation treats its input or output prefix as beginning at an octet
//! boundary. INTEGER constraints are inclusive `i64` bounds; unconstrained and
//! semi-constrained INTEGER encodings are outside this module's API. Complete
//! zero-width values use one zero filler octet while reporting zero wire bits.
//!
//! Copyright (c) 2003-2017 Lev Walkin and contributors; 2022-2026 Mouse and
//! contributors. Redistribution and use are permitted under the BSD 2-Clause
//! terms in the accompanying `LICENSE`. The software is provided "as is";
//! see `LICENSE` for the complete disclaimer.

use crate::{
    check_input_limit, check_work_limit, integer_shape, read_bits, validate_integer, write_bits,
    Decoded, Encoded, Error, Limits, Resource,
};

/// Encode one APER BOOLEAN bit.
///
/// # Parameters
/// `value` is the ASN.1 boolean; `limits` bounds output bytes and work bits.
///
/// # Returns
/// One byte containing the value in its most significant bit and `bit_len` 1.
///
/// # Errors
/// Returns a typed limit or allocation error. It raises no exception.
///
/// # Source, history, and example
/// Original source: `BOOLEAN_encode_aper` in `skeletons/BOOLEAN_aper.c`.
/// Version/date: Rust APER slice, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial bounded APER runtime. Example:
/// `encode_boolean_aper(true, &Limits::default())?`.
pub fn encode_boolean_aper(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    check_work_limit(1, limits)?;
    let mut bytes = allocate_zeroed(1, limits)?;
    write_bits(&mut bytes, u64::from(value), 1)?;
    Ok(Encoded { bytes, bit_len: 1 })
}

/// Decode a one-bit APER BOOLEAN prefix.
///
/// # Parameters
/// `input` is the encoded prefix; `limits` bounds the whole slice and work.
///
/// # Returns
/// The boolean value, one meaningful bit consumed, and one byte occupied.
///
/// # Errors
/// Returns truncation, input-limit, or work-limit errors. It raises no
/// exception. Trailing bits in the final byte are ignored.
///
/// # Source, history, and example
/// Original source: `BOOLEAN_decode_aper` in `skeletons/BOOLEAN_aper.c`.
/// Version/date: Rust APER slice, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial bounded APER runtime. Example:
/// `decode_boolean_aper(&[0x80], &Limits::default())?`.
pub fn decode_boolean_aper(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    check_input_limit(input, limits)?;
    check_work_limit(1, limits)?;
    require_bits(input, 1)?;
    Ok(Decoded {
        value: read_bits(input, 1)? != 0,
        consumed_bits: 1,
        consumed_bytes: 1,
    })
}

/// Encode an APER NULL complete value, which has no bits in X.691.
///
/// # Parameters
/// `limits` bounds the complete-value output buffer and zero bits of work.
///
/// # Returns
/// One zero filler byte with `bit_len == 0`, matching the top-level complete
/// encoder contract for a zero-width value.
///
/// # Errors
/// Returns an output-limit or allocation error. It raises no exception.
///
/// # Source, history, and example
/// Original source: `NULL_encode_aper` in `skeletons/NULL_aper.c`, X.691 §18.
/// Version/date: Rust APER slice, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial bounded APER runtime. Example:
/// `encode_null_aper(&Limits::default())?`.
pub fn encode_null_aper(limits: &Limits) -> Result<Encoded, Error> {
    check_work_limit(0, limits)?;
    let bytes = allocate_zeroed(1, limits)?;
    Ok(Encoded { bytes, bit_len: 0 })
}

/// Decode an APER NULL complete-value prefix, which consumes no bits.
///
/// # Parameters
/// `input` is the available prefix; `limits` bounds its whole size.
///
/// # Returns
/// Unit value with zero meaningful bits and one complete-value byte consumed.
///
/// # Errors
/// Returns truncation, malformed filler, input-limit, or work-limit errors. It
/// raises no exception.
///
/// # Source, history, and example
/// Original source: `NULL_decode_aper` in `skeletons/NULL_aper.c`, X.691 §18.
/// Version/date: Rust APER slice, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial bounded APER runtime. Example:
/// `decode_null_aper(&[0], &Limits::default())?`.
pub fn decode_null_aper(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    check_input_limit(input, limits)?;
    check_work_limit(0, limits)?;
    let filler = input.first().ok_or(Error::NeedMoreBytes {
        required_bytes: 1,
        available_bytes: input.len(),
    })?;
    if *filler != 0 {
        return Err(Error::InvalidEncoding {
            reason: "nonzero complete-encoding filler for a zero-width value",
        });
    }
    Ok(Decoded {
        value: (),
        consumed_bits: 0,
        consumed_bytes: 1,
    })
}

/// Encode a bounded signed INTEGER as an APER prefix.
///
/// # Parameters
/// `value` is the INTEGER; `lower` and `upper` are inclusive bounds; `limits`
/// bounds output bytes and wire bits. The prefix starts on an octet boundary.
///
/// # Returns
/// The X.691 aligned constrained-whole-number representation. Singleton
/// ranges produce a zero filler byte with `bit_len == 0`; wide ranges include
/// determinant alignment filler bits in `bit_len`.
///
/// # Errors
/// Returns constraint, limit, length, or allocation errors. It raises no
/// exception. Unconstrained and semi-constrained INTEGER forms are unsupported.
///
/// # Source, history, and example
/// Original source: constrained path in `skeletons/INTEGER_aper.c` and
/// `aper_put_constrained_whole_number` in `skeletons/aper_support.c`.
/// Version/date: Rust APER slice, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial bounded APER runtime. Example:
/// `encode_integer_aper(-1, -2, 2, &Limits::default())?`.
pub fn encode_integer_aper(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;
    let (span, range_bits) = integer_shape(lower, upper)?;
    let offset =
        u64::try_from(i128::from(value) - i128::from(lower)).map_err(|_| Error::SizeOverflow)?;
    let (bit_len, field_bits, payload_bytes) = integer_layout(span, range_bits, offset)?;
    let byte_len = aper_byte_len(bit_len)?;
    check_work_limit(bit_len, limits)?;
    let mut bytes = allocate_zeroed(byte_len, limits)?;

    // Small ranges use a bit field; medium ranges align and use fixed octets.
    if range_bits <= 16 {
        if field_bits != 0 {
            write_bits(&mut bytes, offset, field_bits)?;
        }
    } else {
        write_wide_offset(&mut bytes, range_bits, field_bits, offset, payload_bytes)?;
    }
    Ok(Encoded { bytes, bit_len })
}

/// Decode a bounded signed INTEGER APER prefix.
///
/// # Parameters
/// `input` is the prefix; `lower` and `upper` are inclusive bounds; `limits`
/// bounds the entire input and consumed wire-bit work. The complete-value
/// prefix starts at an octet boundary.
///
/// # Returns
/// The decoded INTEGER and its consumed bit and byte prefix lengths.
///
/// # Errors
/// Returns invalid bounds, truncation, spare-code, limit, or size errors. It
/// raises no exception. Unconstrained and semi-constrained forms are unsupported.
///
/// # Source, history, and example
/// Original source: constrained path in `skeletons/INTEGER_aper.c` and
/// `aper_get_constrained_whole_number` in `skeletons/aper_support.c`.
/// Version/date: Rust APER slice, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial bounded APER runtime. Example:
/// `decode_integer_aper(input, -2, 2, &Limits::default())?`.
pub fn decode_integer_aper(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    let (span, range_bits) = integer_shape(lower, upper)?;
    check_input_limit(input, limits)?;
    if span == 0 {
        check_work_limit(0, limits)?;
        let filler = input.first().ok_or(Error::NeedMoreBytes {
            required_bytes: 1,
            available_bytes: input.len(),
        })?;
        if *filler != 0 {
            return Err(Error::InvalidEncoding {
                reason: "nonzero complete-encoding filler for a singleton INTEGER",
            });
        }
        return Ok(Decoded {
            value: lower,
            consumed_bits: 0,
            consumed_bytes: 1,
        });
    }

    // Fixed-width fields are direct except for their X.691 octet alignment.
    let (offset, consumed_bits) = if range_bits <= 16 {
        let field_bits = fixed_field_bits(span, range_bits);
        check_work_limit(field_bits, limits)?;
        require_bits(input, field_bits)?;
        (read_bits_at(input, 0, field_bits)?, field_bits)
    } else {
        decode_wide_offset(input, range_bits, limits)?
    };

    if u128::from(offset) > span {
        return Err(Error::InvalidEncoding {
            reason: "spare aligned constrained INTEGER code",
        });
    }
    let value = i128::from(lower) + i128::from(offset);
    let value = i64::try_from(value).map_err(|_| Error::InvalidEncoding {
        reason: "aligned constrained INTEGER result is outside i64",
    })?;
    Ok(Decoded {
        value,
        consumed_bits,
        consumed_bytes: aper_byte_len(consumed_bits)?,
    })
}

/// Allocate an output vector after enforcing its configured byte ceiling.
///
/// # Parameters and returns
/// `byte_len` is the exact output size; `limits` supplies the byte ceiling.
/// Returns a zero-filled buffer of that size.
///
/// # Errors
/// Returns `LimitExceeded` or `AllocationFailed`; it raises no exception.
///
/// # Source, history, and example
/// Original source: APER-local wrapper around the Rust runtime allocator.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `allocate_zeroed(1, limits)?`.
fn allocate_zeroed(byte_len: usize, limits: &Limits) -> Result<Vec<u8>, Error> {
    if byte_len > limits.max_output_bytes {
        return Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            limit: limits.max_output_bytes,
            requested: byte_len,
        });
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_len)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: byte_len,
        })?;
    bytes.resize(byte_len, 0);
    Ok(bytes)
}

/// Return the fixed APER field width for a bounded range.
///
/// # Parameters and returns
/// `span` is the inclusive maximum offset; `range_bits` is its bit width.
/// Returns a zero width for singleton, the offset width through span 254, an
/// octet at span 255, or two octets through span 65535.
///
/// # Errors
/// This helper cannot fail and raises no exception.
///
/// # Source, history, and example
/// Original source: thresholds in `aper_get_constrained_whole_number` and
/// `aper_put_constrained_whole_number` in `skeletons/aper_support.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `fixed_field_bits(255, 8)` returns 8.
const fn fixed_field_bits(span: u128, range_bits: usize) -> usize {
    match span {
        0 => 0,
        1..=254 => range_bits,
        255 => 8,
        _ => 16,
    }
}

/// Derive an APER INTEGER field and its complete prefix width.
///
/// # Parameters and returns
/// `span` and `range_bits` describe the constrained offset range; `offset` is
/// the checked value offset. Returns total encoded bits, determinant width, and
/// the minimal unsigned payload octet count.
///
/// # Errors
/// Returns `SizeOverflow` if a checked bit count cannot fit `usize`.
///
/// # Source, history, and example
/// Original source: constrained integer framing in `skeletons/INTEGER_aper.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example: a 17-bit range
/// uses a 2-bit length determinant followed by aligned offset octets.
fn integer_layout(
    span: u128,
    range_bits: usize,
    offset: u64,
) -> Result<(usize, usize, usize), Error> {
    if span == 0 {
        return Ok((0, 0, 0));
    }
    if range_bits <= 16 {
        let field_bits = fixed_field_bits(span, range_bits);
        return Ok((field_bits, field_bits, 0));
    }
    let max_bytes = range_bits.checked_add(7).ok_or(Error::SizeOverflow)? / 8;
    let determinant_bits = ceil_log2(max_bytes);
    let payload_bytes = minimal_unsigned_bytes(offset);
    if payload_bytes > max_bytes {
        return Err(Error::InvalidEncoding {
            reason: "constrained INTEGER offset needs too many octets",
        });
    }
    let aligned_payload_bit = align_to_octet(determinant_bits)?;
    let payload_bits = payload_bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let bit_len = aligned_payload_bit
        .checked_add(payload_bits)
        .ok_or(Error::SizeOverflow)?;
    Ok((bit_len, determinant_bits, payload_bytes))
}

/// Write a wide-range length field and its aligned unsigned offset octets.
///
/// # Parameters and returns
/// `output` is the zero-filled destination; `range_bits` sets the maximum
/// payload length; `determinant_bits` is the length field width; `offset` is
/// the checked value offset; `payload_bytes` is its minimal octet count.
/// Returns `Ok(())` after writing both fields.
///
/// # Errors
/// Returns `SizeOverflow` or `InvalidEncoding` for inconsistent internal
/// dimensions. It raises no exception and allocates no additional storage.
///
/// # Source, history, and example
/// Original source: `aper_integer_put_wide` in `skeletons/INTEGER_aper.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example: offset `0x1234`
/// is emitted as bytes `12 34` after determinant and alignment.
fn write_wide_offset(
    output: &mut [u8],
    range_bits: usize,
    determinant_bits: usize,
    offset: u64,
    payload_bytes: usize,
) -> Result<(), Error> {
    let max_bytes = range_bits.checked_add(7).ok_or(Error::SizeOverflow)? / 8;
    if payload_bytes == 0 || payload_bytes > max_bytes {
        return Err(Error::InvalidEncoding {
            reason: "invalid constrained INTEGER payload length",
        });
    }
    let length_code = u64::try_from(payload_bytes - 1).map_err(|_| Error::SizeOverflow)?;
    write_bits_at(output, 0, length_code, determinant_bits)?;
    let payload_start = align_to_octet(determinant_bits)?;
    let mut remaining = offset;
    for index in 0..payload_bytes {
        let shift = (payload_bytes - index - 1)
            .checked_mul(8)
            .ok_or(Error::SizeOverflow)?;
        let octet = u8::try_from((remaining >> shift) & 0xff).map_err(|_| Error::SizeOverflow)?;
        let position = payload_start
            .checked_add(index.checked_mul(8).ok_or(Error::SizeOverflow)?)
            .ok_or(Error::SizeOverflow)?;
        write_bits_at(output, position, u64::from(octet), 8)?;
        remaining &= !(u64::from(octet) << shift);
    }
    if remaining != 0 {
        return Err(Error::InvalidEncoding {
            reason: "constrained INTEGER payload did not contain the full offset",
        });
    }
    Ok(())
}

/// Read a wide-range constrained offset and validate its determinant.
///
/// # Parameters and returns
/// `input` is the encoded prefix; `range_bits` describes the maximum offset;
/// `limits` bounds input size and consumed work. Returns the unsigned offset.
///
/// # Errors
/// Returns truncation, invalid-length, limit, or size errors. It raises no
/// exception. Spare offset values are checked by the caller.
///
/// # Source, history, and example
/// Original source: `aper_integer_get_wide` in `skeletons/INTEGER_aper.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example: reads a bounded
/// length determinant and then its aligned payload.
fn decode_wide_offset(
    input: &[u8],
    range_bits: usize,
    limits: &Limits,
) -> Result<(u64, usize), Error> {
    let max_bytes = range_bits.checked_add(7).ok_or(Error::SizeOverflow)? / 8;
    let determinant_bits = ceil_log2(max_bytes);
    let determinant_end = determinant_bits;
    check_work_limit(align_to_octet(determinant_end)?, limits)?;
    require_bits(input, determinant_bits)?;
    let encoded_length = read_bits_at(input, 0, determinant_bits)?;
    let payload_bytes = usize::try_from(encoded_length)
        .map_err(|_| Error::SizeOverflow)?
        .checked_add(1)
        .ok_or(Error::SizeOverflow)?;
    if payload_bytes > max_bytes || payload_bytes > 8 {
        return Err(Error::InvalidEncoding {
            reason: "constrained INTEGER length determinant exceeds its range",
        });
    }

    // The payload starts at the next octet boundary after the determinant.
    let payload_start = align_to_octet(determinant_end)?;
    let payload_bits = payload_bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let required_bits = payload_start
        .checked_add(payload_bits)
        .ok_or(Error::SizeOverflow)?;
    check_work_limit(required_bits, limits)?;
    require_bits(input, required_bits)?;
    let mut offset = 0_u64; // state variable: accumulates the big-endian offset.
    for index in 0..payload_bytes {
        let position = payload_start
            .checked_add(index.checked_mul(8).ok_or(Error::SizeOverflow)?)
            .ok_or(Error::SizeOverflow)?;
        let octet = read_bits_at(input, position, 8)?;
        offset = (offset << 8) | octet;
    }
    Ok((offset, required_bits))
}

/// Return the minimum number of octets in an unsigned offset, including zero.
///
/// # Parameters and returns
/// `value` is the nonnegative offset. Returns a number from one through eight.
///
/// # Errors
/// This helper cannot fail and raises no exception.
///
/// # Source, history, and example
/// Original source: `aper_integer_put_wide` in `skeletons/INTEGER_aper.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `minimal_unsigned_bytes(0)` returns 1.
fn minimal_unsigned_bytes(value: u64) -> usize {
    let significant_bits = u64::BITS as usize - value.leading_zeros() as usize;
    significant_bits.max(1).div_ceil(8)
}

/// Convert APER wire-bit length to the number of occupied bytes.
///
/// # Parameters and returns
/// `bit_len` is the complete APER prefix width. Returns its ceiling byte count;
/// zero bits occupy one complete-value filler byte.
///
/// # Errors
/// Returns `SizeOverflow` if rounding cannot fit `usize`.
///
/// # Source, history, and example
/// Original source: aligned PER prefix accounting in `skeletons/aper_support.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `aper_byte_len(9)` returns 2.
fn aper_byte_len(bit_len: usize) -> Result<usize, Error> {
    if bit_len == 0 {
        return Ok(1);
    }
    bit_len
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(Error::SizeOverflow)
}

/// Return the smallest bit width whose field can represent `value` choices.
///
/// # Parameters and returns
/// `value` is a positive choice count. Returns zero for one, otherwise the
/// ceiling of base-two logarithm.
///
/// # Errors
/// This helper cannot fail and raises no exception.
///
/// # Source, history, and example
/// Original source: `aper_log2_ceil_size` in `skeletons/INTEGER_aper.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `ceil_log2(5)` returns 3.
const fn ceil_log2(value: usize) -> usize {
    value.saturating_sub(1).bit_width() as usize
}

/// Round a bit position up to its next octet boundary.
///
/// # Parameters and returns
/// `bit_position` is a bit count. Returns the same position when aligned or
/// the next multiple of eight otherwise.
///
/// # Errors
/// Returns `SizeOverflow` if rounding cannot fit `usize`.
///
/// # Source, history, and example
/// Original source: `aper_put_align` in `skeletons/aper_support.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `align_to_octet(3)` returns 8.
fn align_to_octet(bit_position: usize) -> Result<usize, Error> {
    bit_position
        .checked_add(7)
        .map(|rounded| rounded & !7)
        .ok_or(Error::SizeOverflow)
}

/// Read at most 64 bits beginning at an arbitrary checked bit offset.
///
/// # Parameters and returns
/// `input` supplies the bits; `start_bit` is their first bit; `bit_len` is the
/// width. Returns a right-aligned unsigned value.
///
/// # Errors
/// Returns truncation, invalid-width, or size errors. It raises no exception.
///
/// # Source, history, and example
/// Original source: bit extraction in `skeletons/asn_bit_data.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `read_bits_at(&[0x80], 0, 1)` returns 1.
fn read_bits_at(input: &[u8], start_bit: usize, bit_len: usize) -> Result<u64, Error> {
    if bit_len > u64::BITS as usize {
        return Err(Error::InvalidEncoding {
            reason: "bit width exceeds the integer accumulator",
        });
    }
    let end_bit = start_bit.checked_add(bit_len).ok_or(Error::SizeOverflow)?;
    require_bits(input, end_bit)?;
    let mut value = 0_u64; // state variable: accumulates selected bits in wire order.
    for position in start_bit..end_bit {
        let byte = *input.get(position / 8).ok_or(Error::SizeOverflow)?;
        let shift = 7 - (position % 8);
        value = (value << 1) | u64::from((byte >> shift) & 1);
    }
    Ok(value)
}

/// Write at most 64 bits beginning at an arbitrary checked bit offset.
///
/// # Parameters and returns
/// `output` is a zero-filled destination; `start_bit` is the first output bit;
/// `value` contains the source bits; `bit_len` is the field width. Returns
/// `Ok(())` after writing most-significant bit first.
///
/// # Errors
/// Returns invalid-width or size errors. It raises no exception and allocates
/// no memory.
///
/// # Source, history, and example
/// Original source: bit insertion in `skeletons/asn_bit_outp.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `write_bits_at(&mut [0], 0, 1, 1)` writes `0x80`.
fn write_bits_at(
    output: &mut [u8],
    start_bit: usize,
    value: u64,
    bit_len: usize,
) -> Result<(), Error> {
    if bit_len > u64::BITS as usize {
        return Err(Error::InvalidEncoding {
            reason: "bit width exceeds the integer accumulator",
        });
    }
    let end_bit = start_bit.checked_add(bit_len).ok_or(Error::SizeOverflow)?;
    if end_bit > output.len().checked_mul(8).ok_or(Error::SizeOverflow)? {
        return Err(Error::InvalidEncoding {
            reason: "output buffer is too small for the bit field",
        });
    }
    for index in 0..bit_len {
        let source_shift = bit_len - index - 1;
        let bit = ((value >> source_shift) & 1) as u8;
        let position = start_bit + index;
        let target = output.get_mut(position / 8).ok_or(Error::SizeOverflow)?;
        *target |= bit << (7 - (position % 8));
    }
    Ok(())
}

/// Require the given number of meaningful input bits.
///
/// # Parameters and returns
/// `input` is the available slice; `required_bits` is the prefix width.
/// Returns `Ok(())` when enough bits are present.
///
/// # Errors
/// Returns `NeedMoreBits` or `SizeOverflow`; it raises no exception.
///
/// # Source, history, and example
/// Original source: input bit bounds in `skeletons/aper_support.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// introduced with the bounded APER primitive slice. Example:
/// `require_bits(&[0], 1)?`.
fn require_bits(input: &[u8], required_bits: usize) -> Result<(), Error> {
    let available_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    if available_bits < required_bits {
        return Err(Error::NeedMoreBits {
            required_bits,
            available_bits,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_boolean_aper, decode_integer_aper, decode_null_aper, encode_boolean_aper,
        encode_integer_aper, encode_null_aper,
    };
    use crate::{Error, Limits, Resource};

    /// Verify APER BOOLEAN bit order and prefix behavior.
    ///
    /// Original source: `BOOLEAN_aper.c`. Version/date: 2026-10-30.
    /// Inputs: false and true values. Returns: no value; assertions validate
    /// output and consumed prefix. Errors: none expected. Responsible party:
    /// asn1c maintainers. History: initial APER regression tests. Example:
    /// true encodes in the high bit as `0x80`.
    #[test]
    fn boolean_round_trips() {
        for value in [false, true] {
            let encoded = encode_boolean_aper(value, &Limits::default()).expect("encode BOOLEAN");
            assert_eq!(encoded.bytes, [if value { 0x80 } else { 0x00 }]);
            assert_eq!(encoded.bit_len, 1);
            let decoded =
                decode_boolean_aper(&encoded.bytes, &Limits::default()).expect("decode BOOLEAN");
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bits, 1);
        }
    }

    /// Verify APER NULL complete-value filler and zero-bit consumption.
    ///
    /// Original source: `NULL_aper.c`, X.691 §18. Version/date: 2026-10-30.
    /// Inputs: zero filler, empty input, and nonzero filler. Returns: no value;
    /// assertions validate complete-value framing and zero-bit consumption.
    /// Errors: the empty and nonzero inputs produce expected errors.
    /// Responsible party: asn1c maintainers. History: initial APER regression
    /// tests. Example: `[0]` decodes as NULL with one byte consumed.
    #[test]
    fn null_has_zero_width() {
        let encoded = encode_null_aper(&Limits::default()).expect("encode NULL");
        assert_eq!(encoded.bytes, [0]);
        assert_eq!(encoded.bit_len, 0);
        let decoded = decode_null_aper(&[0], &Limits::default()).expect("decode NULL");
        assert_eq!(decoded.value, ());
        assert_eq!(decoded.consumed_bits, 0);
        assert_eq!(decoded.consumed_bytes, 1);
        assert!(matches!(
            decode_null_aper(&[], &Limits::default()),
            Err(Error::NeedMoreBytes { .. })
        ));
        assert!(matches!(
            decode_null_aper(&[1], &Limits::default()),
            Err(Error::InvalidEncoding { .. })
        ));
    }

    /// Verify constrained INTEGER range thresholds and signed endpoints.
    ///
    /// Original source: `INTEGER_aper.c` and `aper_support.c`.
    /// Version/date: 2026-10-30. Inputs: singleton, 255/256/257/65536/65537
    /// cardinalities, and the full i64 domain. Returns: no value; assertions
    /// verify wire lengths and round trips. Errors: none expected. Responsible
    /// party: asn1c maintainers. History: initial APER regression tests.
    /// Example: the full i64 range remains supported without signed overflow.
    #[test]
    fn integer_thresholds_round_trip() {
        let cases = [
            (7, 7, 7, 0),
            (253, 0, 254, 8),
            (255, 0, 255, 8),
            (256, 0, 256, 16),
            (65_535, 0, 65_535, 16),
            (65_536, 0, 65_536, 32),
            (65_537, 0, 65_537, 32),
            (i64::MIN, i64::MIN, i64::MAX, 16),
            (i64::MAX, i64::MIN, i64::MAX, 72),
        ];
        for (value, lower, upper, expected_bits) in cases {
            let encoded = encode_integer_aper(value, lower, upper, &Limits::default())
                .expect("encode INTEGER");
            assert_eq!(encoded.bit_len, expected_bits);
            if lower == upper {
                assert_eq!(encoded.bytes, [0]);
            }
            let decoded = decode_integer_aper(&encoded.bytes, lower, upper, &Limits::default())
                .expect("decode INTEGER");
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bits, expected_bits);
            assert_eq!(decoded.consumed_bytes, encoded.bytes.len());
        }
    }

    /// Check exact APER octets around aligned range-size transitions.
    ///
    /// Original source: `aper_put_constrained_whole_number` in
    /// `skeletons/aper_support.c` and wide-offset logic in `INTEGER_aper.c`.
    /// Version/date: 2026-10-30. Inputs: final values in ranges of 255, 256,
    /// 257, 65536, and 65537 values. Returns: no value; assertions check exact
    /// bytes and bit lengths. Errors: none expected. Responsible party: asn1c
    /// maintainers. History: initial APER wire-vector tests. Example: a 257
    /// choice range switches to the aligned 16-bit case.
    #[test]
    fn integer_aligned_wire_vectors() {
        let cases: &[(i64, i64, &[u8])] = &[
            (254, 254, &[0xfe]),
            (255, 255, &[0xff]),
            (256, 256, &[0x01, 0x00]),
            (65_535, 65_535, &[0xff, 0xff]),
            (65_536, 65_536, &[0x80, 0x01, 0x00, 0x00]),
        ];
        for &(value, upper, expected) in cases {
            let encoded = encode_integer_aper(value, 0, upper, &Limits::default())
                .expect("encode APER wire vector");
            assert_eq!(encoded.bytes, expected);
        }
        let singleton =
            encode_integer_aper(3, 3, 3, &Limits::default()).expect("encode APER singleton");
        assert_eq!(singleton.bytes, [0]);
    }

    /// Verify malformed wide determinants, spare values, truncation, and limits.
    ///
    /// Original source: constrained INTEGER checks in `INTEGER_aper.c`.
    /// Version/date: 2026-10-30. Inputs: malformed encodings, short slices,
    /// and restrictive limits. Returns: no value; assertions verify typed
    /// errors. Errors: expected validation failures. Responsible party: asn1c
    /// maintainers. History: initial APER negative tests. Example: determinant
    /// 3 is rejected when only 3 payload octets are allowed (codes 0..2).
    #[test]
    fn rejects_invalid_input_and_limits() {
        assert!(matches!(
            decode_integer_aper(&[], 0, 255, &Limits::default()),
            Err(Error::NeedMoreBits { .. })
        ));
        assert!(matches!(
            decode_integer_aper(&[0xff], 0, 2, &Limits::default()),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_integer_aper(&[0xc0, 0, 0, 0], 0, 65_536, &Limits::default()),
            Err(Error::InvalidEncoding { .. })
        ));
        let tight = Limits {
            max_input_bytes: 0,
            ..Limits::default()
        };
        assert!(matches!(
            decode_boolean_aper(&[0], &tight),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        let tight = Limits {
            max_output_bytes: 0,
            ..Limits::default()
        };
        assert!(matches!(
            encode_boolean_aper(false, &tight),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert!(matches!(
            encode_integer_aper(
                0,
                0,
                1,
                &Limits {
                    max_work_bits: 0,
                    ..Limits::default()
                }
            ),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        assert!(matches!(
            encode_integer_aper(2, 0, 1, &Limits::default()),
            Err(Error::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            decode_integer_aper(&[], 2, 1, &Limits::default()),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            decode_integer_aper(&[], 3, 3, &Limits::default()),
            Err(Error::NeedMoreBytes { .. })
        ));
        assert!(matches!(
            decode_integer_aper(&[1], 3, 3, &Limits::default()),
            Err(Error::InvalidEncoding { .. })
        ));
    }
}
