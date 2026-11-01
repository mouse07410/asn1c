//! Safe, bounded primitive codecs for generated ASN.1 Rust code.
//!
//! In addition to a limited PER/OER/CER/DER/BER codec slice, this crate covers
//! BOOLEAN, NULL, bounded signed INTEGER, direct ENUMERATED, fixed and
//! bounded-size UPER strings, fixed or bounded JER strings, and direct CBOR
//! primitives and opaque ANY values.
//! It uses only the Rust standard library and applies caller-configurable input,
//! output, and work limits before reading bits or allocating output storage.
//!
//! Copyright (c) 2003-2017 Lev Walkin and contributors; 2022-2026 Mouse and
//! contributors. Redistribution and use are permitted under the BSD 2-Clause
//! terms in the accompanying `LICENSE`. The software is provided "as is";
//! see `LICENSE` for the complete disclaimer.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

/// Primitive Aligned Packed Encoding Rules (APER) codecs.
pub mod aper;
/// Checked BER parsing and DER/CER string and ENUMERATED codecs.
pub mod ber;
/// Bounded primitive and opaque CBOR codecs.
pub mod cbor;
/// Bounded primitive JSON Encoding Rules (JER) codecs.
pub mod jer;
/// Primitive Octet Encoding Rules (OER) codecs.
pub mod oer;
/// Composable UPER bit cursors with operation-wide resource accounting.
pub mod uper_cursor;
/// Bounded basic XER output for flat generated records.
pub mod xer;

pub use aper::{
    decode_boolean_aper, decode_integer_aper, decode_null_aper, encode_boolean_aper,
    encode_integer_aper, encode_null_aper,
};
pub use ber::{
    decode_bit_string_ber, decode_bit_string_cer, decode_enumerated_ber, decode_enumerated_cer,
    decode_octet_string_ber, decode_octet_string_cer, encode_bit_string_cer, encode_bit_string_der,
    encode_enumerated_cer, encode_enumerated_der, encode_octet_string_cer, encode_octet_string_der,
    FieldKind, RecordContext, RecordEncoding, RecordField, SequenceReader, SequenceWriter,
    SetReader, SetWriter, Tag, TagClass, MAX_TAG_NUMBER,
};
pub use cbor::{
    decode_boolean_cbor, decode_integer_cbor, decode_null_cbor, encode_boolean_cbor,
    encode_integer_cbor, encode_null_cbor,
};
pub use jer::{
    decode_bit_string_jer, decode_boolean_jer, decode_bounded_bit_string_jer,
    decode_bounded_octet_string_jer, decode_enumerated_jer, decode_integer_jer, decode_null_jer,
    decode_octet_string_jer, encode_bit_string_jer, encode_boolean_jer,
    encode_bounded_bit_string_jer, encode_bounded_octet_string_jer, encode_enumerated_jer,
    encode_integer_jer, encode_null_jer, encode_octet_string_jer,
};
pub use oer::{
    decode_boolean_oer, decode_integer_oer, decode_null_oer, encode_boolean_oer,
    encode_integer_oer, encode_null_oer,
};
pub use uper_cursor::{BitStringValue, UperReader, UperWriter};

/// Default maximum number of input bytes accepted by one operation (1 MiB).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Default maximum number of output bytes produced by one operation (1 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Default maximum number of wire bits processed by one operation (8 `MiBits`).
pub const DEFAULT_MAX_WORK_BITS: usize = 8 * 1024 * 1024;

/// Resource ceilings applied by each primitive operation.
///
/// The byte limits apply to the complete provided input slice and the complete
/// encoded output buffer. `max_work_bits` bounds primitive wire bits. For a
/// composed UPER value, it bounds cumulative wire bits plus eight work units
/// per field, including zero-width fields. These finite defaults are
/// configurable by each caller. APER and OER use the same ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of the entire input slice accepted by a decode operation.
    pub max_input_bytes: usize,
    /// Maximum size of an encoded output buffer, including padding bytes.
    pub max_output_bytes: usize,
    /// Maximum primitive wire bits or composed UPER field work units.
    pub max_work_bits: usize,
}

/// Resource whose configured ceiling was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Supplied input bytes exceeded `Limits::max_input_bytes`.
    InputBytes,
    /// Encoded output bytes exceeded `Limits::max_output_bytes`.
    OutputBytes,
    /// Codec work bits exceeded `Limits::max_work_bits`.
    WorkBits,
}

/// A bounded encoding and the number of meaningful bits it contains.
///
/// For UPER and APER, `bit_len` counts meaningful bits; APER includes required
/// internal alignment. OER, CER, and DER count all bits in their octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// Encoded bytes, including codec-specific complete-value framing.
    pub bytes: Vec<u8>,
    /// Meaningful PER bits or total octet-aligned OER/CER/DER wire bits.
    pub bit_len: usize,
}

/// A decoded value and its prefix consumption in bits and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<T> {
    /// Decoded ASN.1 value.
    pub value: T,
    /// Number of meaningful bits consumed from the input prefix.
    pub consumed_bits: usize,
    /// Number of whole bytes occupied by the consumed prefix.
    pub consumed_bytes: usize,
}

impl<T> Decoded<T> {
    /// Transform the decoded value while preserving its input consumption.
    ///
    /// # Parameters
    /// `self` is the decoded result; `transform` maps its value to a new type.
    ///
    /// # Returns
    /// A result containing the transformed value and unchanged consumption.
    ///
    /// # Errors and panics
    /// This method returns no error. A panic from `transform` is propagated.
    ///
    /// # Source, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
    /// 2026-10-11. Responsible party: asn1c maintainers. History: introduced
    /// with the initial runtime slice. Example: `decoded.map(|value| !value)`.
    pub fn map<U, F>(self, transform: F) -> Decoded<U>
    where
        F: FnOnce(T) -> U,
    {
        Decoded {
            value: transform(self.value),
            consumed_bits: self.consumed_bits,
            consumed_bytes: self.consumed_bytes,
        }
    }
}

/// Error returned for invalid constraints, malformed input, or exhausted limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The lower constraint bound is greater than the upper bound.
    InvalidBounds {
        /// Inclusive lower bound supplied by the caller.
        lower: i64,
        /// Inclusive upper bound supplied by the caller.
        upper: i64,
    },
    /// A value does not fit its inclusive constraint range.
    ValueOutOfRange {
        /// Value supplied to the encoder or validator.
        value: i64,
        /// Inclusive lower bound supplied by the caller.
        lower: i64,
        /// Inclusive upper bound supplied by the caller.
        upper: i64,
    },
    /// The input ended before the requested number of bits was available.
    NeedMoreBits {
        /// Minimum meaningful bits required to decode the value.
        required_bits: usize,
        /// Bits available in the supplied input slice.
        available_bits: usize,
    },
    /// The input ended before a complete zero-width encoding byte was available.
    NeedMoreBytes {
        /// Minimum whole bytes required to decode the value.
        required_bytes: usize,
        /// Whole bytes available in the supplied input slice.
        available_bytes: usize,
    },
    /// Input bits are not a valid encoding of the selected constrained type.
    InvalidEncoding {
        /// Static explanation of the malformed encoding.
        reason: &'static str,
    },
    /// The requested input, output, or work exceeds the configured limit.
    LimitExceeded {
        /// Resource for which the configured ceiling was exceeded.
        resource: Resource,
        /// Configured resource ceiling.
        limit: usize,
        /// Requested resource amount.
        requested: usize,
    },
    /// A checked length or bit-count calculation overflowed `usize`.
    SizeOverflow,
    /// Fallible output-buffer reservation failed.
    AllocationFailed {
        /// Number of output bytes requested from the allocator.
        requested_bytes: usize,
    },
}

impl Default for Limits {
    /// Return the runtime's finite per-operation resource limits.
    ///
    /// # Parameters and returns
    /// No parameters. Returns limits for 1 MiB input, 1 MiB output, and 8 `MiBits`
    /// of work.
    ///
    /// # Errors
    /// This method cannot fail and raises no exception.
    ///
    /// # Source, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
    /// 2026-10-11. Responsible party: asn1c maintainers. History: introduced
    /// with the initial runtime slice. Example: `let limits = Limits::default();`.
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_work_bits: DEFAULT_MAX_WORK_BITS,
        }
    }
}

impl fmt::Display for Error {
    /// Write a human-readable description of this error.
    ///
    /// # Parameters and returns
    /// `self` is the error and `formatter` is the destination. Returns the
    /// formatter's result.
    ///
    /// # Errors
    /// Returns the formatter's error if writing fails; raises no exception.
    ///
    /// # Source, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
    /// 2026-10-11. Responsible party: asn1c maintainers. History: introduced
    /// with the initial runtime slice. Example: `format!("{error}")`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBounds { lower, upper } => {
                write!(formatter, "invalid INTEGER bounds {lower}..={upper}")
            }
            Self::ValueOutOfRange {
                value,
                lower,
                upper,
            } => write!(formatter, "INTEGER {value} is outside {lower}..={upper}"),
            Self::NeedMoreBits {
                required_bits,
                available_bits,
            } => write!(
                formatter,
                "need {required_bits} bits, only {available_bits} are available"
            ),
            Self::NeedMoreBytes {
                required_bytes,
                available_bytes,
            } => write!(
                formatter,
                "need {required_bytes} bytes, only {available_bytes} are available"
            ),
            Self::InvalidEncoding { reason } => {
                write!(formatter, "invalid ASN.1 encoding: {reason}")
            }
            Self::LimitExceeded {
                resource,
                limit,
                requested,
            } => write!(
                formatter,
                "{resource:?} limit {limit} exceeded by request for {requested}"
            ),
            Self::SizeOverflow => formatter.write_str("size calculation overflowed"),
            Self::AllocationFailed { requested_bytes } => {
                write!(
                    formatter,
                    "could not reserve {requested_bytes} output bytes"
                )
            }
        }
    }
}

/// Mark runtime errors as standard library errors.
///
/// # Parameters and returns
/// No parameters or return value.
///
/// # Errors
/// This marker implementation cannot fail and raises no exception.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime API. Version/date: 0.1.0,
/// 2026-10-11. Responsible party: asn1c maintainers. History: introduced with
/// the initial runtime slice. Example: `fn report(e: &dyn std::error::Error)`.
impl std::error::Error for Error {}

/// Encode one UPER BOOLEAN bit.
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
/// Original source: `BOOLEAN_encode_uper` in `skeletons/BOOLEAN_uper.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial constrained-UPER runtime. Example:
/// `encode_boolean(true, &Limits::default())?`.
pub fn encode_boolean(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    let bit_len = 1;
    let byte_len = encoded_byte_len(bit_len)?;
    check_work_limit(bit_len, limits)?;

    // Reserve only after both configured output and allocator bounds are checked.
    let mut bytes = allocate_zeroed(byte_len, limits)?;
    write_bits(&mut bytes, u64::from(value), bit_len)?;

    Ok(Encoded { bytes, bit_len })
}

/// Decode a one-bit UPER BOOLEAN prefix.
///
/// # Parameters
/// `input` is the encoded prefix; `limits` bounds the full input slice and work.
///
/// # Returns
/// The boolean value, one meaningful bit consumed, and one byte consumed.
///
/// # Errors
/// Returns `NeedMoreBits`, a configured limit error, or a length-overflow error.
/// It raises no exception. The seven low padding bits are deliberately ignored.
///
/// # Source, history, and example
/// Original source: `BOOLEAN_decode_uper` in `skeletons/BOOLEAN_uper.c` and
/// complete-input behavior in `skeletons/uper_decoder.c`. Version/date:
/// Rust port slice, 2026-10-11. Responsible party: asn1c maintainers. History:
/// initial constrained-UPER runtime. Example: `decode_boolean(&[0x80], limits)`.
pub fn decode_boolean(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    check_input_limit(input, limits)?;
    require_bits(input, 1)?;
    check_work_limit(1, limits)?;

    // Only the first meaningful bit is read; C-compatible padding is ignored.
    let value = read_bits(input, 1)? != 0;
    Ok(Decoded {
        value,
        consumed_bits: 1,
        consumed_bytes: 1,
    })
}

/// Encode a UPER NULL complete encoding.
///
/// # Parameters
/// `limits` bounds the one-byte complete encoding and bit-work budget.
///
/// # Returns
/// A single zero byte with `bit_len == 0`, matching complete UPER behavior.
///
/// # Errors
/// Returns a configured output-limit or allocation error. It raises no exception.
///
/// # Source, history, and example
/// Original source: `NULL_encode_uper` and `uper_encode_to_new_buffer` in
/// `skeletons/NULL_uper.c` and `skeletons/uper_encoder.c`. Version/date:
/// Rust port slice, 2026-10-11. Responsible party: asn1c maintainers. History:
/// initial constrained-UPER runtime. Example: `encode_null(limits)`.
pub fn encode_null(limits: &Limits) -> Result<Encoded, Error> {
    check_work_limit(0, limits)?;
    let bytes = allocate_zeroed(1, limits)?;
    Ok(Encoded { bytes, bit_len: 0 })
}

/// Decode a complete zero-width UPER NULL prefix.
///
/// # Parameters
/// `input` is the complete-value prefix; `limits` bounds the full slice.
///
/// # Returns
/// Unit value, zero meaningful bits consumed, and one complete-encoding byte.
///
/// # Errors
/// Returns `NeedMoreBytes`, `InvalidEncoding`, a limit error, or `SizeOverflow`.
/// It raises no exception. A nonzero zero-width byte is malformed.
///
/// # Source, history, and example
/// Original source: `NULL_decode_uper` and `uper_decode_complete` in
/// `skeletons/NULL_uper.c` and `skeletons/uper_decoder.c`. Version/date:
/// Rust port slice, 2026-10-11. Responsible party: asn1c maintainers. History:
/// initial constrained-UPER runtime. Example: `decode_null(&[0], limits)`.
pub fn decode_null(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, 1)?;
    check_work_limit(0, limits)?;
    if input[0] != 0 {
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

/// Validate an INTEGER against inclusive signed bounds.
///
/// # Parameters
/// `value` is the value to check; `lower` and `upper` are inclusive bounds.
///
/// # Returns
/// `Ok(())` if bounds are ordered and contain `value`.
///
/// # Errors
/// Returns `InvalidBounds` or `ValueOutOfRange`; it raises no exception.
///
/// # Source, history, and example
/// Original source: bounded-value checks in `skeletons/INTEGER_uper.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial constrained-UPER runtime. Example:
/// `validate_integer(4, 0, 10)?`.
pub const fn validate_integer(value: i64, lower: i64, upper: i64) -> Result<(), Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }
    if value < lower || value > upper {
        return Err(Error::ValueOutOfRange {
            value,
            lower,
            upper,
        });
    }
    Ok(())
}

/// Encode a constrained signed INTEGER as a UPER bit prefix.
///
/// # Parameters
/// `value` is the INTEGER; `lower` and `upper` are inclusive bounds; `limits`
/// bounds output bytes and meaningful work bits.
///
/// # Returns
/// The offset from `lower` in the minimum fixed bit width. Singleton ranges use
/// a complete zero-width encoding represented by one zero byte.
///
/// # Errors
/// Returns constraint, limit, length, or allocation errors. It raises no
/// exception. Arithmetic uses widened checked representations.
///
/// # Source, history, and example
/// Original source: constrained path in `INTEGER_encode_uper` in
/// `skeletons/INTEGER_uper.c`. Version/date: Rust port slice, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial constrained-UPER
/// runtime. Example: `encode_integer(-1, -2, 2, limits)`.
pub fn encode_integer(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;
    let (_, bit_len) = integer_shape(lower, upper)?;

    // Widen before subtracting so the full signed range remains representable.
    let offset = i128::from(value) - i128::from(lower);
    let offset = u64::try_from(offset).map_err(|_| Error::SizeOverflow)?;
    let byte_len = encoded_byte_len(bit_len)?;
    check_work_limit(bit_len, limits)?;

    // The range shape proves that this fixed-width offset fits in the output.
    let mut bytes = allocate_zeroed(byte_len, limits)?;
    write_bits(&mut bytes, offset, bit_len)?;
    Ok(Encoded { bytes, bit_len })
}

/// Encode one BOOLEAN as a complete CER TLV.
///
/// # Parameters
/// `value` is the ASN.1 boolean; `limits` bounds output bytes and wire-bit work.
///
/// # Returns
/// The minimal BOOLEAN TLV (`01 01 00` or `01 01 FF`) with total wire bits.
///
/// # Errors
/// Returns a configured limit, checked-size, or allocation error. It raises no
/// exception and allocates only after both resource limits have been checked.
///
/// # Source, version, history, and example
/// Original source: CER primitive encoding contract in X.690 and the asn1c
/// BER primitive encoder. Version/date: Rust CER slice, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial CER encoder slice.
/// Example: `encode_boolean_cer(true, &Limits::default())?`.
pub fn encode_boolean_cer(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    let contents = [if value { 0xff } else { 0x00 }];
    encode_cer_tlv(0x01, &contents, limits)
}

/// Encode one NULL as its complete CER TLV.
///
/// # Parameters
/// `limits` bounds output bytes and total wire-bit work.
///
/// # Returns
/// The canonical NULL TLV `05 00` with `bit_len` equal to 16.
///
/// # Errors
/// Returns a configured limit, checked-size, or allocation error. It raises no
/// exception and allocates only after both resource limits have been checked.
///
/// # Source, version, history, and example
/// Original source: CER primitive encoding contract in X.690 and the asn1c
/// BER primitive encoder. Version/date: Rust CER slice, 2026-10-11.
/// Responsible party: asn1c maintainers. History: initial CER encoder slice.
/// Example: `encode_null_cer(&Limits::default())?`.
pub fn encode_null_cer(limits: &Limits) -> Result<Encoded, Error> {
    encode_cer_tlv(0x05, &[], limits)
}

/// Encode a bounded signed INTEGER as a minimal CER TLV.
///
/// # Parameters
/// `value` is the signed value; `lower` and `upper` are inclusive ASN.1 bounds;
/// `limits` bounds output bytes and total wire-bit work.
///
/// # Returns
/// The INTEGER tag, minimal short-form length, and shortest signed two's-
/// complement content, with `bit_len` equal to the complete TLV size in bits.
///
/// # Errors
/// Returns `InvalidBounds`, `ValueOutOfRange`, a configured limit, checked-size,
/// or allocation error. It raises no exception and allocates after validation.
///
/// # Source, version, history, and example
/// Original source: CER INTEGER rules in X.690 and the asn1c BER integer
/// encoder. Version/date: Rust CER slice, 2026-10-11. Responsible party:
/// asn1c maintainers. History: initial i64 CER encoder slice. Example:
/// `encode_integer_cer(-129, i64::MIN, i64::MAX, &Limits::default())?`.
pub fn encode_integer_cer(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    validate_integer(value, lower, upper)?;

    // Retain only the shortest signed two's-complement representation.
    let full = value.to_be_bytes();
    // state variable: marks the first byte of the minimal signed representation.
    let mut first = 0;
    while first + 1 < full.len() {
        let current = full[first];
        let next = full[first + 1];
        if (current == 0x00 && next & 0x80 == 0) || (current == 0xff && next & 0x80 != 0) {
            first += 1;
        } else {
            break;
        }
    }

    encode_cer_tlv(0x02, &full[first..], limits)
}

/// Assemble a short-form CER TLV and enforce output and work ceilings.
///
/// # Parameters
/// `tag` is the one-octet identifier; `contents` is the primitive payload;
/// `limits` supplies maximum output bytes and wire work bits.
///
/// # Returns
/// A complete TLV with a short-form definite length and total bits in `bit_len`.
///
/// # Errors
/// Returns `InvalidEncoding` for content requiring a different length form,
/// `SizeOverflow`, `LimitExceeded`, or `AllocationFailed`. It raises no
/// exception; length and work arithmetic is checked before allocation.
///
/// # Source, version, history, and example
/// Original source: new safe Rust helper for CER primitive encoders.
/// Version/date: Rust CER slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial CER encoder slice. Example:
/// `encode_cer_tlv(0x05, &[], limits)` returns `[05 00]`.
fn encode_cer_tlv(tag: u8, contents: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    if contents.len() > 127 {
        return Err(Error::InvalidEncoding {
            reason: "CER primitive content requires a longer length form",
        });
    }

    // Compute and charge the complete octet-aligned TLV before allocation.
    let byte_len = contents.len().checked_add(2).ok_or(Error::SizeOverflow)?;
    let bit_len = byte_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;
    let mut bytes = allocate_zeroed(byte_len, limits)?;
    bytes[0] = tag;
    bytes[1] = u8::try_from(contents.len()).map_err(|_| Error::SizeOverflow)?;
    bytes[2..].copy_from_slice(contents);

    Ok(Encoded { bytes, bit_len })
}

/// Strictly decode one CER BOOLEAN TLV prefix.
///
/// # Parameters
/// `input` holds the encoding, which may be followed by unrelated bytes;
/// `limits` bounds the complete input slice and the TLV wire-bit work.
///
/// # Returns
/// The boolean value with `consumed_bytes == 3` and `consumed_bits == 24`.
/// Trailing bytes after the TLV are left unconsumed, matching C `cer_decode`.
///
/// # Errors
/// Returns `NeedMoreBytes` for truncation, `InvalidEncoding` for a wrong tag,
/// non-short or wrong length, or a content octet other than `00`/`FF` (BER
/// accepts any nonzero octet, CER does not), or a configured limit error. It
/// raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: X.690 clauses 8.2 and 11.1 and the asn1c strict C
/// `cer_decode`. Version/date: Rust CER decoder slice, 2026-10-11. Responsible
/// party: asn1c maintainers. History: initial CER decoder slice. Example:
/// `decode_boolean_cer(&[0x01, 0x01, 0xff], &Limits::default())?`.
pub fn decode_boolean_cer(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    let (contents, decoded) = decode_cer_tlv(0x01, input, limits)?;
    let value = match contents {
        [0x00] => false,
        [0xff] => true,
        [_] => {
            return Err(Error::InvalidEncoding {
                reason: "CER BOOLEAN TRUE must use content octet FF",
            })
        }
        _ => {
            return Err(Error::InvalidEncoding {
                reason: "CER BOOLEAN content must be exactly one octet",
            })
        }
    };
    Ok(decoded.map(|()| value))
}

/// Strictly decode one CER NULL TLV prefix.
///
/// # Parameters
/// `input` holds the encoding, which may be followed by unrelated bytes;
/// `limits` bounds the complete input slice and the TLV wire-bit work.
///
/// # Returns
/// The unit value with `consumed_bytes == 2` and `consumed_bits == 16`.
///
/// # Errors
/// Returns `NeedMoreBytes`, `InvalidEncoding` for a wrong tag or any length
/// other than short-form zero, or a configured limit error. It raises no
/// exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: X.690 clause 8.8 and the asn1c strict C `cer_decode`.
/// Version/date: Rust CER decoder slice, 2026-10-11. Responsible party:
/// asn1c maintainers. History: initial CER decoder slice. Example:
/// `decode_null_cer(&[0x05, 0x00], &Limits::default())?`.
pub fn decode_null_cer(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    let (contents, decoded) = decode_cer_tlv(0x05, input, limits)?;
    if !contents.is_empty() {
        return Err(Error::InvalidEncoding {
            reason: "CER NULL content must be empty",
        });
    }
    Ok(decoded)
}

/// Strictly decode one bounded CER INTEGER TLV prefix.
///
/// # Parameters
/// `input` holds the encoding, which may be followed by unrelated bytes;
/// `lower` and `upper` are inclusive ASN.1 bounds; `limits` bounds the complete
/// input slice and the TLV wire-bit work.
///
/// # Returns
/// The signed value and its whole-TLV consumption in bytes and bits.
///
/// # Errors
/// Returns `InvalidBounds`; `NeedMoreBytes` for truncation; `InvalidEncoding`
/// for a wrong tag, non-short length, empty content, more than eight content
/// octets, or a redundant leading `00`/`FF` octet; `ValueOutOfRange`; or a
/// configured limit error. It raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: X.690 clause 8.3 and the asn1c strict C `cer_decode`.
/// Version/date: Rust CER decoder slice, 2026-10-11. Responsible party:
/// asn1c maintainers. History: initial i64 CER decoder slice. Example:
/// `decode_integer_cer(&[0x02, 0x02, 0x00, 0x80], 0, 255, &Limits::default())?`.
pub fn decode_integer_cer(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }
    let (contents, decoded) = decode_cer_tlv(0x02, input, limits)?;
    if contents.is_empty() {
        return Err(Error::InvalidEncoding {
            reason: "CER INTEGER content must not be empty",
        });
    }
    if contents.len() > 8 {
        return Err(Error::InvalidEncoding {
            reason: "CER INTEGER content exceeds the 64-bit runtime range",
        });
    }
    if contents.len() > 1
        && ((contents[0] == 0x00 && contents[1] & 0x80 == 0)
            || (contents[0] == 0xff && contents[1] & 0x80 != 0))
    {
        return Err(Error::InvalidEncoding {
            reason: "CER INTEGER content has a redundant leading octet",
        });
    }

    // Sign-extend the minimal two's-complement content into an i64.
    let sign_octet = if contents[0] & 0x80 != 0 { 0xff } else { 0x00 };
    let mut sign_extended_bytes = [sign_octet; 8];
    sign_extended_bytes[8 - contents.len()..].copy_from_slice(contents);
    let value = i64::from_be_bytes(sign_extended_bytes);
    validate_integer(value, lower, upper)?;
    Ok(decoded.map(|()| value))
}

/// Encode a BOOLEAN as its canonical DER primitive TLV.
///
/// # Parameters
/// `value` is the ASN.1 BOOLEAN; `limits` bounds output bytes and wire work.
///
/// # Returns
/// The canonical DER BOOLEAN TLV, identical to this runtime's CER primitive
/// encoding: `01 01 00` for FALSE or `01 01 FF` for TRUE.
///
/// # Errors
/// Returns a configured limit or allocation error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.690 DER BOOLEAN rules and `encode_boolean_cer`.
/// Version/date: Rust DER API, 2026-10-30. Responsible party: asn1c
/// maintainers. History: added with BER prefix decoding. Example:
/// `encode_boolean_der(true, &Limits::default())?`.
pub fn encode_boolean_der(value: bool, limits: &Limits) -> Result<Encoded, Error> {
    encode_boolean_cer(value, limits)
}

/// Encode a NULL as its canonical DER primitive TLV.
///
/// # Parameters
/// `limits` bounds output bytes and total wire-bit work.
///
/// # Returns
/// The canonical DER NULL TLV `05 00`, identical to CER primitive output.
///
/// # Errors
/// Returns a configured limit or allocation error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.690 DER NULL rules and `encode_null_cer`.
/// Version/date: Rust DER API, 2026-10-30. Responsible party: asn1c
/// maintainers. History: added with BER prefix decoding. Example:
/// `encode_null_der(&Limits::default())?`.
pub fn encode_null_der(limits: &Limits) -> Result<Encoded, Error> {
    encode_null_cer(limits)
}

/// Encode a bounded signed INTEGER as its canonical DER primitive TLV.
///
/// # Parameters
/// `value` is the INTEGER; `lower` and `upper` are inclusive ASN.1 bounds;
/// `limits` bounds output bytes and total wire-bit work.
///
/// # Returns
/// A minimal two's-complement DER INTEGER TLV, identical to CER output for
/// this primitive and bounded i64 value.
///
/// # Errors
/// Returns invalid bounds, an out-of-range value, a configured limit, or an
/// allocation error. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.690 DER INTEGER rules and `encode_integer_cer`.
/// Version/date: Rust DER API, 2026-10-30. Responsible party: asn1c
/// maintainers. History: added with BER prefix decoding. Example:
/// `encode_integer_der(-129, i64::MIN, i64::MAX, &Limits::default())?`.
pub fn encode_integer_der(
    value: i64,
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Encoded, Error> {
    encode_integer_cer(value, lower, upper, limits)
}

/// Decode one BER BOOLEAN primitive TLV prefix.
///
/// # Parameters
/// `input` is the complete available prefix and may contain a trailing suffix;
/// `limits` bounds the entire input slice and this TLV's wire-bit work.
///
/// # Returns
/// The boolean value and TLV prefix consumption. BER TRUE accepts any
/// nonzero content octet; this API deliberately requires exactly one content
/// octet for BOOLEAN.
///
/// # Errors
/// Returns truncation, malformed tag/length/content, resource-limit, or size
/// errors. Primitive indefinite lengths are rejected. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.690 BER BOOLEAN rules and the asn1c BER decoder.
/// Version/date: Rust BER API, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial BER primitive prefix decoder. Example:
/// `decode_boolean_ber(&[1, 1, 1], &Limits::default())?` is TRUE.
pub fn decode_boolean_ber(input: &[u8], limits: &Limits) -> Result<Decoded<bool>, Error> {
    let (contents, decoded) = decode_ber_tlv(0x01, input, limits)?;
    if contents.len() != 1 {
        return Err(Error::InvalidEncoding {
            reason: "BER BOOLEAN content must be exactly one octet",
        });
    }
    Ok(decoded.map(|()| contents[0] != 0))
}

/// Decode one BER NULL primitive TLV prefix.
///
/// # Parameters
/// `input` is the available prefix and may contain trailing bytes; `limits`
/// bounds the entire input slice and the TLV's wire-bit work.
///
/// # Returns
/// Unit value and the whole BER TLV's prefix consumption.
///
/// # Errors
/// Returns truncation, malformed tag/length/content, resource-limit, or size
/// errors. Primitive indefinite lengths are rejected. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.690 BER NULL rules and the asn1c BER decoder.
/// Version/date: Rust BER API, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial BER primitive prefix decoder. Example:
/// `decode_null_ber(&[5, 0], &Limits::default())?`.
pub fn decode_null_ber(input: &[u8], limits: &Limits) -> Result<Decoded<()>, Error> {
    let (contents, decoded) = decode_ber_tlv(0x05, input, limits)?;
    if !contents.is_empty() {
        return Err(Error::InvalidEncoding {
            reason: "BER NULL content must be empty",
        });
    }
    Ok(decoded)
}

/// Decode one bounded BER INTEGER primitive TLV prefix into an i64.
///
/// # Parameters
/// `input` is the available prefix and may contain trailing bytes; `lower` and
/// `upper` are inclusive ASN.1 bounds; `limits` bounds input and TLV work.
///
/// # Returns
/// The decoded signed value and whole-TLV prefix consumption. Redundant sign
/// extension octets are accepted as a C-compatibility extension when they
/// represent a value in the i64 range; X.690 requires minimal INTEGER contents.
///
/// # Errors
/// Returns invalid bounds, truncation, malformed tag/length/content, an
/// out-of-range value, a resource-limit, or size error. Primitive indefinite
/// lengths are rejected. It raises no exception.
///
/// # Source, version, history, and example
/// Original source: X.690 BER INTEGER rules and the asn1c BER decoder.
/// Version/date: Rust BER API, 2026-10-30. Responsible party: asn1c
/// maintainers. History: initial BER primitive prefix decoder. Example:
/// `decode_integer_ber(&[2, 1, 0xff], -1, 1, &Limits::default())?`.
pub fn decode_integer_ber(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }
    let (contents, decoded) = decode_ber_tlv(0x02, input, limits)?;
    if contents.is_empty() {
        return Err(Error::InvalidEncoding {
            reason: "BER INTEGER content must not be empty",
        });
    }

    // Remove only sign octets whose removal preserves the encoded value.
    let mut significant = contents;
    while significant.len() > 8 {
        let first = significant[0];
        let next = significant[1];
        let redundant_positive = first == 0x00 && next & 0x80 == 0;
        let redundant_negative = first == 0xff && next & 0x80 != 0;
        if !redundant_positive && !redundant_negative {
            return Err(Error::InvalidEncoding {
                reason: "BER INTEGER value is outside the 64-bit runtime range",
            });
        }
        significant = &significant[1..];
    }

    // Sign extension preserves two's-complement interpretation up to i64 width.
    let sign_octet = if significant[0] & 0x80 != 0 {
        0xff
    } else {
        0x00
    };
    let mut sign_extended_bytes = [sign_octet; 8];
    sign_extended_bytes[8 - significant.len()..].copy_from_slice(significant);
    let value = i64::from_be_bytes(sign_extended_bytes);
    validate_integer(value, lower, upper)?;
    Ok(decoded.map(|()| value))
}

/// Parse one BER primitive TLV prefix with checked definite-length handling.
///
/// # Parameters
/// `tag` is the expected one-octet primitive identifier; `input` is the
/// available input prefix; `limits` supplies byte and work ceilings.
///
/// # Returns
/// A borrowed content slice and decoded TLV consumption, leaving any suffix
/// unconsumed. Short and long definite lengths are accepted.
///
/// # Errors
/// Returns truncation, wrong-tag/indefinite-length errors, configured limits,
/// or checked-size errors. It raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new checked helper for the Rust BER primitive API.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added with BER prefix decoding. Example: `decode_ber_tlv(5, &[5, 0], limits)`.
fn decode_ber_tlv<'a>(
    tag: u8,
    input: &'a [u8],
    limits: &Limits,
) -> Result<(&'a [u8], Decoded<()>), Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, 2)?;
    if input[0] != tag {
        return Err(Error::InvalidEncoding {
            reason: "BER identifier octet does not match the expected primitive type",
        });
    }

    let first_length = input[1];
    if first_length == 0xff {
        return Err(Error::InvalidEncoding {
            reason: "BER length octet FF is reserved",
        });
    }
    let (header_len, content_len) = if first_length & 0x80 == 0 {
        (2, usize::from(first_length))
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 {
            return Err(Error::InvalidEncoding {
                reason: "BER primitive length must be definite",
            });
        }
        let header_len = 2_usize.checked_add(count).ok_or(Error::SizeOverflow)?;
        require_bytes(input, header_len)?;

        // Accumulate all length octets with overflow checks; leading zeroes are safe.
        let mut content_len = 0_usize;
        for octet in &input[2..header_len] {
            content_len = content_len
                .checked_mul(256)
                .and_then(|length| length.checked_add(usize::from(*octet)))
                .ok_or(Error::SizeOverflow)?;
        }
        (header_len, content_len)
    };

    // Charge the declared complete TLV before checking its content availability.
    let total_len = header_len
        .checked_add(content_len)
        .ok_or(Error::SizeOverflow)?;
    let work_bits = total_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(work_bits, limits)?;
    require_bytes(input, total_len)?;
    Ok((
        &input[header_len..total_len],
        Decoded {
            value: (),
            consumed_bits: work_bits,
            consumed_bytes: total_len,
        },
    ))
}

/// Split one short-form primitive CER TLV prefix and charge its resources.
///
/// # Parameters
/// `tag` is the expected one-octet identifier; `input` is the encoded prefix;
/// `limits` supplies the input-slice and work-bit ceilings.
///
/// # Returns
/// The content octets and a unit `Decoded` describing the TLV consumption.
///
/// # Errors
/// Returns `LimitExceeded`, `NeedMoreBytes`, `InvalidEncoding` for a wrong tag
/// or a long-form/indefinite length (never minimal for these primitives), or
/// `SizeOverflow`. It raises no exception and allocates no memory.
///
/// # Source, version, history, and example
/// Original source: new safe Rust helper mirroring `encode_cer_tlv`.
/// Version/date: Rust CER decoder slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial CER decoder slice. Example:
/// `decode_cer_tlv(0x05, &[0x05, 0x00], limits)` returns empty contents.
fn decode_cer_tlv<'a>(
    tag: u8,
    input: &'a [u8],
    limits: &Limits,
) -> Result<(&'a [u8], Decoded<()>), Error> {
    check_input_limit(input, limits)?;
    require_bytes(input, 2)?;
    if input[0] != tag {
        return Err(Error::InvalidEncoding {
            reason: "CER identifier octet does not match the expected type",
        });
    }
    if input[1] & 0x80 != 0 {
        return Err(Error::InvalidEncoding {
            reason: "CER primitive length must use the minimal short form",
        });
    }

    let byte_len = usize::from(input[1])
        .checked_add(2)
        .ok_or(Error::SizeOverflow)?;
    require_bytes(input, byte_len)?;
    let bit_len = byte_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check_work_limit(bit_len, limits)?;
    Ok((
        &input[2..byte_len],
        Decoded {
            value: (),
            consumed_bits: bit_len,
            consumed_bytes: byte_len,
        },
    ))
}

/// Decode a constrained signed INTEGER prefix from UPER.
///
/// # Parameters
/// `input` is the encoded prefix; `lower` and `upper` are inclusive bounds;
/// `limits` bounds the entire slice and meaningful work bits.
///
/// # Returns
/// The decoded INTEGER plus the meaningful bit and byte prefix consumption.
///
/// # Errors
/// Returns invalid bounds, truncation, malformed encodings or spare codes,
/// limit errors, or checked-size errors. It raises no exception; a zero-width
/// value requires a zero complete byte.
///
/// # Source, history, and example
/// Original source: constrained path in `INTEGER_decode_uper` and complete
/// handling in `skeletons/uper_decoder.c`. Version/date: Rust port slice,
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial
/// constrained-UPER runtime. Example: `decode_integer(input, -2, 2, limits)`.
pub fn decode_integer(
    input: &[u8],
    lower: i64,
    upper: i64,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    let (span, bit_len) = integer_shape(lower, upper)?;
    check_input_limit(input, limits)?;

    // C's complete decoder uses one zero byte for a value with no content bits.
    if bit_len == 0 {
        require_bytes(input, 1)?;
        check_work_limit(0, limits)?;
        if input[0] != 0 {
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

    require_bits(input, bit_len)?;
    check_work_limit(bit_len, limits)?;
    let offset = u128::from(read_bits(input, bit_len)?);
    if offset > span {
        return Err(Error::InvalidEncoding {
            reason: "spare constrained INTEGER code",
        });
    }

    // The range check above makes this widened sum fall within the i64 bounds.
    let decoded = i128::from(lower) + i128::try_from(offset).map_err(|_| Error::SizeOverflow)?;
    let value = i64::try_from(decoded).map_err(|_| Error::InvalidEncoding {
        reason: "constrained INTEGER result is outside i64",
    })?;
    Ok(Decoded {
        value,
        consumed_bits: bit_len,
        consumed_bytes: encoded_byte_len(bit_len)?,
    })
}

/// Compute the offset span and minimum fixed UPER bit width for signed bounds.
///
/// # Parameters and returns
/// `lower` and `upper` are inclusive signed bounds. Returns the nonnegative
/// widened span and the number of bits needed to represent every offset.
///
/// # Errors
/// Returns `InvalidBounds`; it raises no exception and cannot overflow `i128`.
///
/// # Source, history, and example
/// Original source: the range-width concept in `skeletons/INTEGER_uper.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: introduced to safely cover all i64 bounds. Example:
/// `integer_shape(i64::MIN, i64::MAX)?` returns span `u64::MAX`, width 64.
fn integer_shape(lower: i64, upper: i64) -> Result<(u128, usize), Error> {
    if lower > upper {
        return Err(Error::InvalidBounds { lower, upper });
    }

    // i128 subtraction safely represents the complete i64 signed span.
    let span = (i128::from(upper) - i128::from(lower)).cast_unsigned();
    let bit_len = if span == 0 {
        0
    } else {
        span.bit_width() as usize
    };
    Ok((span, bit_len))
}

/// Check the complete supplied slice against the configured input ceiling.
///
/// # Parameters and returns
/// `input` is the whole caller-provided slice; `limits` supplies its byte cap.
/// Returns `Ok(())` when the slice fits.
///
/// # Errors
/// Returns `LimitExceeded`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime budget helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `check_input_limit(&[0x80], limits)?`.
const fn check_input_limit(input: &[u8], limits: &Limits) -> Result<(), Error> {
    enforce_limit(Resource::InputBytes, input.len(), limits.max_input_bytes)
}

/// Check the meaningful-bit budget for one primitive operation.
///
/// # Parameters and returns
/// `work_bits` is the planned meaningful work; `limits` supplies its ceiling.
/// Returns `Ok(())` when the planned work fits.
///
/// # Errors
/// Returns `LimitExceeded`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime budget helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `check_work_limit(1, limits)?`.
const fn check_work_limit(work_bits: usize, limits: &Limits) -> Result<(), Error> {
    enforce_limit(Resource::WorkBits, work_bits, limits.max_work_bits)
}

/// Return an error if a requested resource exceeds its configured ceiling.
///
/// # Parameters and returns
/// `resource` identifies the budget; `requested` is the amount used; `limit`
/// is the permitted maximum. Returns `Ok(())` if `requested <= limit`.
///
/// # Errors
/// Returns `LimitExceeded`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: new asn1c Rust runtime budget helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `enforce_limit(Resource::WorkBits, 1, 8)?`.
const fn enforce_limit(resource: Resource, requested: usize, limit: usize) -> Result<(), Error> {
    if requested > limit {
        return Err(Error::LimitExceeded {
            resource,
            limit,
            requested,
        });
    }
    Ok(())
}

/// Require enough whole input bytes for a zero-width complete encoding.
///
/// # Parameters and returns
/// `input` is the available slice; `required_bytes` is the required prefix.
/// Returns `Ok(())` when that prefix exists.
///
/// # Errors
/// Returns `NeedMoreBytes`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: complete-value behavior in `skeletons/uper_decoder.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial runtime slice. Example: `require_bytes(input, 1)?`.
const fn require_bytes(input: &[u8], required_bytes: usize) -> Result<(), Error> {
    if input.len() < required_bytes {
        return Err(Error::NeedMoreBytes {
            required_bytes,
            available_bytes: input.len(),
        });
    }
    Ok(())
}

/// Require a meaningful number of bits in the supplied input prefix.
///
/// # Parameters and returns
/// `input` is the available slice; `required_bits` is the prefix width.
/// Returns `Ok(())` when enough bits are present.
///
/// # Errors
/// Returns `NeedMoreBits` or `SizeOverflow`; it raises no exception.
///
/// # Source, history, and example
/// Original source: bit-availability checks in `skeletons/uper_decoder.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial runtime slice. Example: `require_bits(input, 1)?`.
fn require_bits(input: &[u8], required_bits: usize) -> Result<(), Error> {
    // Check before multiplication so even extreme caller slices cannot wrap.
    let available_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    if available_bits < required_bits {
        return Err(Error::NeedMoreBits {
            required_bits,
            available_bits,
        });
    }
    Ok(())
}

/// Compute the whole-byte buffer size for a meaningful bit count.
///
/// # Parameters and returns
/// `bit_len` is the number of meaningful bits. Returns the padded byte count,
/// using one byte for a complete zero-width encoding.
///
/// # Errors
/// Returns `SizeOverflow`; it raises no exception and allocates no memory.
///
/// # Source, history, and example
/// Original source: `uper_encode_to_new_buffer` in `skeletons/uper_encoder.c`.
/// Version/date: Rust port slice, 2026-10-11. Responsible party: asn1c
/// maintainers. History: initial runtime slice. Example: `encoded_byte_len(1)?`.
fn encoded_byte_len(bit_len: usize) -> Result<usize, Error> {
    if bit_len == 0 {
        return Ok(1);
    }
    bit_len
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(Error::SizeOverflow)
}

/// Allocate a zero-filled output buffer after checking limits fallibly.
///
/// # Parameters and returns
/// `byte_len` is the requested complete output size; `limits` supplies its cap.
/// Returns a zero-initialized vector of that size.
///
/// # Errors
/// Returns `LimitExceeded` or `AllocationFailed`; it raises no exception.
///
/// # Source, history, and example
/// Original source: new safe Rust runtime allocation helper. Version/date:
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `allocate_zeroed(1, limits)?`.
fn allocate_zeroed(byte_len: usize, limits: &Limits) -> Result<Vec<u8>, Error> {
    enforce_limit(Resource::OutputBytes, byte_len, limits.max_output_bytes)?;
    let mut bytes = Vec::new();

    // Reserve fallibly before resizing the buffer to prevent implicit growth.
    bytes
        .try_reserve_exact(byte_len)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: byte_len,
        })?;
    bytes.resize(byte_len, 0);
    Ok(bytes)
}

/// Read up to 64 bits from the most significant end of a byte slice.
///
/// # Parameters and returns
/// `input` is the bit source; `bit_len` is the number of leading bits to read.
/// Returns those bits as a right-aligned `u64`.
///
/// # Errors
/// Returns `InvalidEncoding`, `NeedMoreBits`, or `SizeOverflow`; it raises no
/// exception and performs no allocation.
///
/// # Source, history, and example
/// Original source: bit helpers in `skeletons/asn_bit_data.c` and constrained
/// helpers in `skeletons/uper_support.c`. Version/date: Rust port slice,
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `read_bits(&[0x80], 1)?` returns `1`.
fn read_bits(input: &[u8], bit_len: usize) -> Result<u64, Error> {
    if bit_len > u64::BITS as usize {
        return Err(Error::InvalidEncoding {
            reason: "bit width exceeds the integer accumulator",
        });
    }
    require_bits(input, bit_len)?;

    // state variable: accumulates bits in wire order without unchecked indexing.
    let mut value = 0_u64;
    for position in 0..bit_len {
        let byte = *input.get(position / 8).ok_or(Error::SizeOverflow)?;
        let shift = 7 - (position % 8);
        value = (value << 1) | u64::from((byte >> shift) & 1);
    }
    Ok(value)
}

/// Write up to 64 bits from a right-aligned value into a zero-filled output.
///
/// # Parameters and returns
/// `output` is the destination; `value` contains the bits; `bit_len` is their
/// width. Returns `Ok(())` after writing bits in most-significant-first order.
///
/// # Errors
/// Returns `InvalidEncoding` or `SizeOverflow` for an invalid internal shape.
/// It raises no exception and performs no allocation.
///
/// # Source, history, and example
/// Original source: bit helpers in `skeletons/asn_bit_data.c` and constrained
/// helpers in `skeletons/uper_support.c`. Version/date: Rust port slice,
/// 2026-10-11. Responsible party: asn1c maintainers. History: initial runtime
/// slice. Example: `write_bits(&mut [0], 1, 1)` writes `0x80`.
fn write_bits(output: &mut [u8], value: u64, bit_len: usize) -> Result<(), Error> {
    if bit_len > u64::BITS as usize || output.len() < encoded_byte_len(bit_len)? {
        return Err(Error::InvalidEncoding {
            reason: "output buffer is too small for the bit width",
        });
    }

    // Leave the final byte's unused low bits zero as required by the encoding.
    for position in 0..bit_len {
        let source_shift = bit_len - position - 1;
        let bit = (value >> source_shift) & 1;
        if bit != 0 {
            let target = output.get_mut(position / 8).ok_or(Error::SizeOverflow)?;
            *target |= 1 << (7 - (position % 8));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test BOOLEAN wire values, prefix consumption, and permissive padding.
    ///
    /// Original source: UPER BOOLEAN contract in the C skeleton. Version/date:
    /// 2026-10-11. Inputs: true/false bytes and padding variants. Returns: no
    /// value; assertions fail on mismatch. Errors: none expected. Responsible
    /// party: asn1c maintainers. History: initial Rust runtime tests.
    /// Example: verifies true encodes as the leading bit `0x80`.
    #[test]
    fn boolean_vectors_and_padding() {
        let limits = Limits::default();
        let encoded = encode_boolean(true, &limits).expect("encode true");
        assert_eq!(encoded.bytes, [0x80]);
        assert_eq!(encoded.bit_len, 1);

        // Padding is ignored, but the first meaningful bit determines truth.
        for (byte, expected) in [(0x80, true), (0xff, true), (0x7f, false)] {
            let decoded = decode_boolean(&[byte], &limits).expect("decode boolean");
            assert_eq!(decoded.value, expected);
            assert_eq!(decoded.consumed_bits, 1);
            assert_eq!(decoded.consumed_bytes, 1);
        }
        assert_eq!(encode_boolean(false, &limits).unwrap().bytes, [0]);
    }

    /// Test BOOLEAN and NULL truncation and resource-budget boundaries.
    ///
    /// Original source: complete UPER decoding contract in the C skeleton.
    /// Version/date: 2026-10-11. Inputs: empty slices and zero limits. Returns:
    /// no value; assertions fail on mismatch. Errors: expected typed errors.
    /// Responsible party: asn1c maintainers. History: initial runtime tests.
    /// Example: empty BOOLEAN input must request one more bit.
    #[test]
    fn truncation_and_zero_budgets() {
        let defaults = Limits::default();
        assert!(matches!(
            decode_boolean(&[], &defaults),
            Err(Error::NeedMoreBits {
                required_bits: 1,
                available_bits: 0
            })
        ));
        assert!(matches!(
            decode_integer(&[], 0, 5, &defaults),
            Err(Error::NeedMoreBits {
                required_bits: 3,
                available_bits: 0
            })
        ));
        assert!(matches!(
            decode_null(&[], &defaults),
            Err(Error::NeedMoreBytes {
                required_bytes: 1,
                available_bytes: 0
            })
        ));

        // Empty work budgets reject BOOLEAN work but still permit zero-width NULL.
        let zero_work = Limits {
            max_work_bits: 0,
            ..defaults
        };
        assert!(matches!(
            encode_boolean(true, &zero_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        assert_eq!(encode_null(&zero_work).unwrap().bytes, [0]);
    }

    /// Test the zero-width complete encoding shared by NULL and singleton INTEGER.
    ///
    /// Original source: `uper_decode_complete` and NULL UPER operations in C.
    /// Version/date: 2026-10-11. Inputs: zero, nonzero, and empty bytes. Returns:
    /// no value; assertions fail on mismatch. Errors: malformed filler and
    /// truncation are expected. Responsible party: asn1c maintainers. History:
    /// initial runtime tests. Example: NULL encodes as `[0]`, with zero bits.
    #[test]
    fn null_and_singleton_zero_width_rules() {
        let limits = Limits::default();
        let null = encode_null(&limits).unwrap();
        assert_eq!(null.bytes, [0]);
        assert_eq!(null.bit_len, 0);
        let decoded_null = decode_null(&[0, 0xaa], &limits).unwrap();
        assert_eq!(decoded_null.value, ());
        assert_eq!(decoded_null.consumed_bits, 0);
        assert_eq!(decoded_null.consumed_bytes, 1);
        assert!(matches!(
            decode_null(&[1], &limits),
            Err(Error::InvalidEncoding { .. })
        ));

        // Singleton INTEGER also consumes the complete zero filler byte.
        let singleton = encode_integer(9, 9, 9, &limits).unwrap();
        assert_eq!(singleton.bytes, [0]);
        assert_eq!(singleton.bit_len, 0);
        assert_eq!(decode_integer(&[0], 9, 9, &limits).unwrap().value, 9);
        assert!(matches!(
            decode_integer(&[0x80], 9, 9, &limits),
            Err(Error::InvalidEncoding { .. })
        ));
    }

    /// Test signed constrained INTEGER offsets and the complete i64 range.
    ///
    /// Original source: bounded INTEGER path in `INTEGER_uper.c`. Version/date:
    /// 2026-10-11. Inputs: signed subrange and `i64::MIN..=i64::MAX`. Returns:
    /// no value; assertions fail on mismatch. Errors: none expected. Responsible
    /// party: asn1c maintainers. History: initial runtime tests. Example: full
    /// i64 bounds require exactly 64 meaningful bits without signed overflow.
    #[test]
    fn integer_signed_range_and_full_i64_span() {
        let limits = Limits::default();
        for value in -2..=2 {
            let encoded = encode_integer(value, -2, 2, &limits).unwrap();
            assert_eq!(encoded.bit_len, 3);
            let expected_index = usize::try_from(value + 2).expect("small nonnegative offset");
            let expected = [0x00, 0x20, 0x40, 0x60, 0x80][expected_index];
            assert_eq!(encoded.bytes, [expected]);
            let mut with_suffix = encoded.bytes.clone();
            with_suffix.push(0xaa);
            let consumed = decode_integer(&with_suffix, -2, 2, &limits).unwrap();
            assert_eq!(
                (
                    consumed.value,
                    consumed.consumed_bits,
                    consumed.consumed_bytes
                ),
                (value, 3, 1)
            );
        }

        // Widened span math preserves both endpoints of the entire i64 domain.
        for value in [i64::MIN, -1, 0, i64::MAX] {
            let encoded = encode_integer(value, i64::MIN, i64::MAX, &limits).unwrap();
            assert_eq!(encoded.bit_len, 64);
            assert_eq!(encoded.bytes.len(), 8);
            if value == i64::MIN {
                assert_eq!(encoded.bytes, [0; 8]);
            } else if value == i64::MAX {
                assert_eq!(encoded.bytes, [0xff; 8]);
            }
            assert_eq!(
                decode_integer(&encoded.bytes, i64::MIN, i64::MAX, &limits)
                    .unwrap()
                    .value,
                value
            );
        }
    }

    /// Test invalid ranges, spare constrained codes, and truncated integers.
    ///
    /// Original source: constrained whole-number checks in the C skeleton.
    /// Version/date: 2026-10-11. Inputs: inverted bounds, spare codes, and short
    /// bit prefixes. Returns: no value; assertions fail on mismatch. Errors:
    /// expected typed errors. Responsible party: asn1c maintainers. History:
    /// initial runtime tests. Example: range 0..=5 has invalid three-bit codes 6-7.
    #[test]
    fn malformed_and_spare_integer_codes() {
        let limits = Limits::default();
        assert!(matches!(
            validate_integer(0, 1, 0),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            encode_integer(6, 0, 5, &limits),
            Err(Error::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            decode_integer(&[0xc0], 0, 5, &limits),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_integer(&[0xff], 0, 511, &limits),
            Err(Error::NeedMoreBits {
                required_bits: 9,
                available_bits: 8
            })
        ));
    }

    /// Exhaust all first-byte patterns for a constrained three-bit INTEGER.
    ///
    /// Original source: deterministic malformed-input campaign for this runtime.
    /// Version/date: 2026-10-11. Inputs: all 256 byte values. Returns: no value;
    /// assertions fail on mismatch. Errors: codes above the range must be
    /// rejected. Responsible party: asn1c maintainers. History: initial tests.
    /// Example: low padding variations preserve the same decoded integer.
    #[test]
    fn integer_byte_pattern_mutation_loop() {
        let limits = Limits::default();
        for byte in 0_u8..=u8::MAX {
            let code = i64::from(byte >> 5);
            let result = decode_integer(&[byte], 0, 5, &limits);
            if code <= 5 {
                let decoded = result.expect("in-range constrained code");
                assert_eq!(decoded.value, code);
                assert_eq!(decoded.consumed_bits, 3);
            } else {
                assert!(matches!(result, Err(Error::InvalidEncoding { .. })));
            }
        }
    }

    /// Test decoded mapping and input, output, and work budget enforcement.
    ///
    /// Original source: new runtime result/budget contract. Version/date:
    /// 2026-10-11. Inputs: constrained BOOLEAN and INTEGER operations with small
    /// limits. Returns: no value; assertions fail on mismatch. Errors: budget
    /// errors are expected. Responsible party: asn1c maintainers. History:
    /// initial runtime tests. Example: map preserves the original bit counts.
    #[test]
    fn limits_and_mapped_consumption() {
        let defaults = Limits::default();
        let decoded = decode_boolean(&[0x80], &defaults).unwrap();
        let mapped = decoded.map(|value| if value { 7 } else { -7 });
        assert_eq!(mapped.value, 7);
        assert_eq!(mapped.consumed_bits, 1);
        assert_eq!(mapped.consumed_bytes, 1);

        // Independent caps fail before bit processing or allocation.
        let no_input = Limits {
            max_input_bytes: 0,
            ..defaults
        };
        let no_output = Limits {
            max_output_bytes: 0,
            ..defaults
        };
        let too_little_work = Limits {
            max_work_bits: 2,
            ..defaults
        };
        let exact_limits = Limits {
            max_input_bytes: 1,
            max_output_bytes: 1,
            max_work_bits: 3,
        };
        assert!(decode_boolean(&[0x80], &exact_limits).is_ok());
        assert!(encode_boolean(true, &exact_limits).is_ok());
        assert!(encode_integer(1, 0, 7, &exact_limits).is_ok());
        assert!(encode_null(&exact_limits).is_ok());
        assert!(matches!(
            decode_boolean(&[0x80], &no_input),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        assert!(matches!(
            encode_null(&no_output),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert!(matches!(
            encode_integer(1, 0, 7, &too_little_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
        assert!(validate_integer(5, 0, 5).is_ok());
        assert!(matches!(
            validate_integer(6, 0, 5),
            Err(Error::ValueOutOfRange { .. })
        ));
    }

    /// Test canonical CER BOOLEAN and NULL encodings and their wire-bit counts.
    ///
    /// Original source: X.690 CER primitive encoding rules. Version/date:
    /// 2026-10-11. Inputs: both BOOLEAN values and NULL. Returns: no value;
    /// assertions fail on mismatch. Errors: none expected. Responsible party:
    /// asn1c maintainers. History: added with the CER primitive slice.
    /// Example: TRUE must encode with content octet `FF`.
    #[test]
    fn cer_boolean_and_null_vectors() {
        let limits = Limits::default();
        let true_value = encode_boolean_cer(true, &limits).unwrap();
        assert_eq!(true_value.bytes, [0x01, 0x01, 0xff]);
        assert_eq!(true_value.bit_len, 24);
        let false_value = encode_boolean_cer(false, &limits).unwrap();
        assert_eq!(false_value.bytes, [0x01, 0x01, 0x00]);
        assert_eq!(false_value.bit_len, 24);
        let null_value = encode_null_cer(&limits).unwrap();
        assert_eq!(null_value.bytes, [0x05, 0x00]);
        assert_eq!(null_value.bit_len, 16);
    }

    /// Test minimal CER INTEGER content at sign-boundary and i64 endpoints.
    ///
    /// Original source: X.690 CER INTEGER encoding rules. Version/date:
    /// 2026-10-11. Inputs: 0, signed-byte boundaries, and both i64 endpoints.
    /// Returns: no value; assertions fail on mismatch. Errors: none expected.
    /// Responsible party: asn1c maintainers. History: added with CER support.
    /// Example: 128 requires a leading zero content octet.
    #[test]
    fn cer_integer_minimal_signed_vectors() {
        let limits = Limits::default();
        let vectors: &[(i64, &[u8])] = &[
            (0, &[0x02, 0x01, 0x00]),
            (127, &[0x02, 0x01, 0x7f]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (-128, &[0x02, 0x01, 0x80]),
            (-129, &[0x02, 0x02, 0xff, 0x7f]),
            (-1, &[0x02, 0x01, 0xff]),
            (i64::MIN, &[0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            (
                i64::MAX,
                &[0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        // Every fixture also checks that complete wire octets determine bit_len.
        for (value, expected) in vectors {
            let encoded = encode_integer_cer(*value, i64::MIN, i64::MAX, &limits)
                .expect("encode CER INTEGER");
            assert_eq!(encoded.bytes, *expected, "value {value}");
            assert_eq!(encoded.bit_len, expected.len() * 8, "value {value}");
        }
    }

    /// Test CER INTEGER bounds and exact output/work ceilings.
    ///
    /// Original source: runtime constraint checks and CER resource contract.
    /// Version/date: 2026-10-11. Inputs: invalid bounds, out-of-range values,
    /// and exact or insufficient limits. Returns: no value; assertions fail on
    /// mismatch. Errors: typed constraint and resource errors are expected.
    /// Responsible party: asn1c maintainers. History: added with CER support.
    /// Example: a three-byte BOOLEAN succeeds with 24 work bits.
    #[test]
    fn cer_validation_and_resource_limits() {
        let limits = Limits {
            max_input_bytes: 0,
            max_output_bytes: 3,
            max_work_bits: 32,
        };
        assert_eq!(encode_boolean_cer(true, &limits).unwrap().bit_len, 24);
        assert!(matches!(
            encode_null_cer(&limits),
            Ok(Encoded { bit_len: 16, .. })
        ));
        assert!(matches!(
            encode_integer_cer(128, i64::MIN, i64::MAX, &limits),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                limit: 3,
                requested: 4,
            })
        ));
        assert!(matches!(
            encode_integer_cer(2, 3, 1, &limits),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            encode_integer_cer(6, 0, 5, &limits),
            Err(Error::ValueOutOfRange { .. })
        ));

        // Charge work for the complete TLV, including tag and length octets.
        let too_little_work = Limits {
            max_work_bits: 23,
            ..limits
        };
        assert!(matches!(
            encode_boolean_cer(true, &too_little_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 24,
                ..
            })
        ));
        let too_little_integer_work = Limits {
            max_output_bytes: 4,
            max_work_bits: 31,
            ..limits
        };
        assert!(matches!(
            encode_integer_cer(128, i64::MIN, i64::MAX, &too_little_integer_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 32,
                ..
            })
        ));
        let no_null_output = Limits {
            max_output_bytes: 1,
            ..limits
        };
        assert!(matches!(
            encode_null_cer(&no_null_output),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                requested: 2,
                ..
            })
        ));
    }

    /// Test strict CER decoding of BOOLEAN, NULL, and INTEGER prefixes.
    ///
    /// Original source: X.690 CER rules and the strict C `cer_decode`.
    /// Version/date: 2026-10-11. Inputs: canonical TLVs, trailing bytes, and
    /// noncanonical, truncated, mistagged, and out-of-range encodings. Returns:
    /// no value; assertions fail on mismatch. Errors: typed errors expected for
    /// rejected inputs. Responsible party: asn1c maintainers. History: added
    /// with the CER decoder slice. Example: `01 01 01` is rejected.
    #[test]
    fn cer_strict_decode_vectors() {
        let limits = Limits::default();
        let t = decode_boolean_cer(&[0x01, 0x01, 0xff, 0x99], &limits).unwrap();
        assert_eq!((t.value, t.consumed_bytes, t.consumed_bits), (true, 3, 24));
        assert!(
            !decode_boolean_cer(&[0x01, 0x01, 0x00], &limits)
                .unwrap()
                .value
        );
        for bad in [
            &[0x01, 0x01, 0x01][..],
            &[0x01, 0x81, 0x01, 0xff],
            &[0x01, 0x02, 0xff, 0xff],
            &[0x01, 0x00],
            &[0x02, 0x01, 0xff],
            &[0x01, 0x80, 0xff, 0x00, 0x00],
        ] {
            assert!(
                matches!(
                    decode_boolean_cer(bad, &limits),
                    Err(Error::InvalidEncoding { .. })
                ),
                "{bad:02x?}"
            );
        }
        assert!(matches!(
            decode_boolean_cer(&[0x01, 0x01], &limits),
            Err(Error::NeedMoreBytes {
                required_bytes: 3,
                available_bytes: 2
            })
        ));
        assert!(matches!(
            decode_boolean_cer(&[0x01], &limits),
            Err(Error::NeedMoreBytes { .. })
        ));

        let n = decode_null_cer(&[0x05, 0x00, 0x05], &limits).unwrap();
        assert_eq!((n.consumed_bytes, n.consumed_bits), (2, 16));
        assert!(matches!(
            decode_null_cer(&[0x05, 0x01, 0x00], &limits),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_null_cer(&[0x05, 0x81, 0x00], &limits),
            Err(Error::InvalidEncoding { .. })
        ));

        // Every canonical encoder output must round-trip through the decoder.
        for value in [0, 1, 127, 128, -128, -129, -1, 255, 256, i64::MIN, i64::MAX] {
            let encoded = encode_integer_cer(value, i64::MIN, i64::MAX, &limits).unwrap();
            let decoded = decode_integer_cer(&encoded.bytes, i64::MIN, i64::MAX, &limits).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bytes, encoded.bytes.len());
            assert_eq!(decoded.consumed_bits, encoded.bit_len);
        }
        for bad in [
            &[0x02, 0x02, 0x00, 0x7f][..],
            &[0x02, 0x02, 0xff, 0x80],
            &[0x02, 0x00],
            &[0x02, 0x81, 0x01, 0x00],
            &[0x02, 0x09, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0],
            &[0x0a, 0x01, 0x00],
        ] {
            assert!(
                matches!(
                    decode_integer_cer(bad, i64::MIN, i64::MAX, &limits),
                    Err(Error::InvalidEncoding { .. })
                ),
                "{bad:02x?}"
            );
        }
        assert!(matches!(
            decode_integer_cer(&[0x02, 0x02, 0x00, 0x80], 0, 127, &limits),
            Err(Error::ValueOutOfRange { value: 128, .. })
        ));
        assert!(matches!(
            decode_integer_cer(&[0x02, 0x01, 0x00], 3, 1, &limits),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            decode_integer_cer(&[0x02, 0x02, 0x00], 0, 255, &limits),
            Err(Error::NeedMoreBytes { .. })
        ));
    }

    /// Test CER decoder input-slice and work ceilings at their exact edges.
    ///
    /// Original source: runtime resource contract. Version/date: 2026-10-11.
    /// Inputs: exact and insufficient limits. Returns: no value; assertions
    /// fail on mismatch. Errors: `LimitExceeded` expected below the edge.
    /// Responsible party: asn1c maintainers. History: added with the CER
    /// decoder slice. Example: a BOOLEAN needs 24 work bits.
    #[test]
    fn cer_decode_resource_limits() {
        let exact = Limits {
            max_input_bytes: 3,
            max_output_bytes: 0,
            max_work_bits: 24,
        };
        assert!(
            decode_boolean_cer(&[0x01, 0x01, 0xff], &exact)
                .unwrap()
                .value
        );
        assert!(matches!(
            decode_boolean_cer(&[0x01, 0x01, 0xff, 0x00], &exact),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                requested: 4,
                ..
            })
        ));
        let low_work = Limits {
            max_work_bits: 23,
            ..exact
        };
        assert!(matches!(
            decode_boolean_cer(&[0x01, 0x01, 0xff], &low_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 24,
                ..
            })
        ));
    }

    /// Test DER encoders produce the canonical existing CER primitive bytes.
    ///
    /// Original source: X.690 DER primitive rules. Version/date: 2026-10-30.
    /// Inputs: BOOLEAN values, NULL, signed INTEGER boundaries and limits.
    /// Returns: no value; assertions fail on mismatches. Errors: none expected.
    /// Responsible party: asn1c maintainers. History: added with BER support.
    /// Example: DER TRUE is encoded with the canonical `FF` content octet.
    #[test]
    fn der_encoders_are_canonical() {
        let limits = Limits::default();
        assert_eq!(
            encode_boolean_der(true, &limits).unwrap().bytes,
            [1, 1, 0xff]
        );
        assert_eq!(encode_boolean_der(false, &limits).unwrap().bytes, [1, 1, 0]);
        assert_eq!(encode_null_der(&limits).unwrap().bytes, [5, 0]);
        for value in [i64::MIN, -129, -1, 0, 127, 128, i64::MAX] {
            assert_eq!(
                encode_integer_der(value, i64::MIN, i64::MAX, &limits).unwrap(),
                encode_integer_cer(value, i64::MIN, i64::MAX, &limits).unwrap()
            );
        }
        assert!(matches!(
            encode_integer_der(4, 0, 3, &limits),
            Err(Error::ValueOutOfRange { .. })
        ));
    }

    /// Test BER prefix decoding of primitive values and permissive encodings.
    ///
    /// Original source: X.690 BER primitive rules. Version/date: 2026-10-30.
    /// Inputs: short/long definite lengths, nonzero BOOLEAN, trailing bytes,
    /// and redundant INTEGER sign octets. Returns: no value; assertions fail
    /// on mismatch. Errors: none expected. Responsible party: maintainers.
    /// History: added with BER support. Example: BER TRUE may use content `01`.
    #[test]
    fn ber_prefix_decode_accepts_definite_lengths_and_redundancy() {
        let limits = Limits::default();
        let boolean = decode_boolean_ber(&[1, 0x81, 1, 0x01, 0xaa], &limits).unwrap();
        assert_eq!(
            (boolean.value, boolean.consumed_bytes, boolean.consumed_bits),
            (true, 4, 32)
        );
        assert!(!decode_boolean_ber(&[1, 1, 0], &limits).unwrap().value);

        let null = decode_null_ber(&[5, 0x81, 0, 0xaa], &limits).unwrap();
        assert_eq!((null.consumed_bytes, null.consumed_bits), (3, 24));

        // Long redundant prefixes remain valid if the represented i64 fits.
        let positive = [2, 9, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let negative = [2, 9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            decode_integer_ber(&positive, i64::MIN, i64::MAX, &limits)
                .unwrap()
                .value,
            1
        );
        assert_eq!(
            decode_integer_ber(&negative, i64::MIN, i64::MAX, &limits)
                .unwrap()
                .value,
            -1
        );
        for value in [i64::MIN, -129, -128, -1, 0, 127, 128, i64::MAX] {
            let der = encode_integer_der(value, i64::MIN, i64::MAX, &limits).unwrap();
            assert_eq!(
                decode_integer_ber(&der.bytes, i64::MIN, i64::MAX, &limits)
                    .unwrap()
                    .value,
                value
            );
        }
    }

    /// Test BER tag, definite-length, content, range, and truncation failures.
    ///
    /// Original source: X.690 BER primitive rules and runtime length checks.
    /// Version/date: 2026-10-30. Inputs: invalid, indefinite, oversized,
    /// and truncated TLVs. Returns: no value; assertions fail on mismatch.
    /// Errors: typed errors are expected for malformed inputs. Responsible
    /// party: asn1c maintainers. History: added with BER support. Example:
    /// an indefinite primitive length is rejected.
    #[test]
    fn ber_malformed_and_truncated_inputs_are_rejected() {
        let limits = Limits::default();
        for malformed in [
            &[1, 0x80, 0][..],
            &[1, 0xff][..],
            &[1, 0][..],
            &[1, 2, 1, 1][..],
            &[0x21, 1, 0xff][..],
        ] {
            assert!(matches!(
                decode_boolean_ber(malformed, &limits),
                Err(Error::InvalidEncoding { .. })
            ));
        }
        assert!(matches!(
            decode_boolean_ber(&[1], &limits),
            Err(Error::NeedMoreBytes { .. })
        ));
        assert!(matches!(
            decode_boolean_ber(&[1, 0x81], &limits),
            Err(Error::NeedMoreBytes { .. })
        ));
        assert!(matches!(
            decode_null_ber(&[5, 1, 0], &limits),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_integer_ber(&[2, 0], i64::MIN, i64::MAX, &limits),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            decode_integer_ber(&[2, 1, 0], 1, 0, &limits),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            decode_integer_ber(&[2, 1, 0x80], 0, 127, &limits),
            Err(Error::ValueOutOfRange { .. })
        ));
        assert!(matches!(
            decode_integer_ber(
                &[2, 9, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
                i64::MIN,
                i64::MAX,
                &limits
            ),
            Err(Error::InvalidEncoding { .. })
        ));

        let truncated_large = [2, 0x82, 1, 0];
        assert!(matches!(
            decode_integer_ber(&truncated_large, i64::MIN, i64::MAX, &limits),
            Err(Error::NeedMoreBytes {
                required_bytes: 260,
                available_bytes: 4
            })
        ));
        let mut large_content = vec![2, 0x82, 1, 0];
        large_content.resize(260, 0);
        assert!(matches!(
            decode_integer_ber(&large_content, i64::MIN, i64::MAX, &limits),
            Ok(Decoded {
                value: 0,
                consumed_bytes: 260,
                consumed_bits: 2080,
                ..
            })
        ));
        large_content[4] = 0x80;
        assert!(matches!(
            decode_integer_ber(&large_content, i64::MIN, i64::MAX, &limits),
            Err(Error::InvalidEncoding { .. })
        ));

        let overflowing_length = [2, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            decode_integer_ber(&overflowing_length, i64::MIN, i64::MAX, &limits),
            Err(Error::SizeOverflow)
        ));

        // Sweep every one-octet length determinant through the bounded parser.
        // The supplied content stays short, so most values should report an
        // ordinary typed error without reading past the available input.
        for length in u8::MIN..=u8::MAX {
            assert!(std::panic::catch_unwind(|| {
                let _ = decode_integer_ber(&[2, length, 0], i64::MIN, i64::MAX, &limits);
            })
            .is_ok());
        }
    }

    /// Test BER input/work limits and checked handling of declared lengths.
    ///
    /// Original source: runtime resource contract. Version/date: 2026-10-30.
    /// Inputs: exact and insufficient limits plus a large declared length.
    /// Returns: no value; assertions fail on mismatch. Errors: limit errors
    /// are expected. Responsible party: asn1c maintainers. History: BER tests.
    /// Example: suffix bytes count toward the configured input cap.
    #[test]
    fn ber_decode_resource_limits() {
        let exact = Limits {
            max_input_bytes: 3,
            max_output_bytes: 0,
            max_work_bits: 24,
        };
        assert!(decode_null_ber(&[5, 0, 0], &exact).is_ok());
        let no_suffix = Limits {
            max_input_bytes: 2,
            ..exact
        };
        assert!(matches!(
            decode_null_ber(&[5, 0, 0], &no_suffix),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                ..
            })
        ));
        let low_work = Limits {
            max_work_bits: 15,
            ..exact
        };
        assert!(matches!(
            decode_null_ber(&[5, 0], &low_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 16,
                ..
            })
        ));
        let declared_large = [5, 0x84, 0, 0x10, 0, 0];
        assert!(matches!(
            decode_null_ber(&declared_large, &Limits::default()),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 8_388_656,
                ..
            })
        ));
    }
}
