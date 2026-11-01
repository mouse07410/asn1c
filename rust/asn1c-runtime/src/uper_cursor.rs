//! Stateful bit cursors for composing one bounded UPER value.
//!
//! `UperWriter` and `UperReader` append or consume primitive BOOLEAN, NULL,
//! finite bounded signed INTEGER, fixed and bounded-size OCTET STRING, and
//! fixed and bounded-size BIT STRING fields in one continuous bit stream.
//! The configured input ceiling applies once to the complete supplied slice;
//! output bytes and work are accumulated over every field in the operation.
//! A complete zero-width value is represented by one zero filler byte at
//! `finish`, while field methods themselves never add alignment or filler.
//!
//! Original source: the X.691 UPER bit-stream conventions and asn1c's
//! `skeletons/uper_encoder.c`, `skeletons/uper_decoder.c`, and primitive
//! UPER skeletons. Version/date: Rust cursor slice, 2026-10-30. Responsible
//! party: asn1c maintainers. History: initial composable UPER runtime API.
//! Example: create a writer, call its field methods, then call `finish`.

use crate::{
    check_input_limit, check_work_limit, integer_shape, validate_integer, Decoded, Encoded, Error,
    Limits, Resource,
};

const FIELD_WORK_OVERHEAD: usize = 8;

/// Packed BIT STRING octets together with their exact meaningful bit count.
///
/// Unlike a byte vector alone, this value preserves a non-octet-aligned
/// ASN.1 bit length. The final octet's unused low bits are always zero.
///
/// # Source, version, history, and example
/// Original source: X.691 BIT STRING value representation.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added for bounded-size BIT STRING UPER. Example:
/// `BitStringValue::new(vec![0xA0], 3)?`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitStringValue {
    /// Packed value octets; this is a state variable.
    bytes: Vec<u8>,
    /// Number of meaningful bits; this is a state variable.
    bit_len: usize,
}

impl BitStringValue {
    /// Create a packed BIT STRING after validating its length and unused bits.
    ///
    /// # Parameters
    /// `bytes` stores bits most-significant first; `bit_len` gives the exact
    /// number of meaningful bits represented by those bytes.
    ///
    /// # Returns
    /// A value with exactly `ceil(bit_len / 8)` bytes and zero unused low bits.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for a byte-count mismatch or nonzero padding,
    /// or `SizeOverflow` when storage-size arithmetic cannot be represented.
    ///
    /// # Source, version, history, and example
    /// Original source: canonical packed BIT STRING representation.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added for bounded-size BIT STRING UPER. Example:
    /// `BitStringValue::new(vec![0xA0], 3)?`.
    pub fn new(bytes: Vec<u8>, bit_len: usize) -> Result<Self, Error> {
        if bytes.len() != bit_storage_len(bit_len)? {
            return Err(Error::InvalidEncoding {
                reason: "BIT STRING storage length does not match its bit length",
            });
        }
        if let Some(unused_mask) = unused_low_bit_mask(bit_len) {
            let last = bytes.last().copied().ok_or(Error::SizeOverflow)?;
            if last & unused_mask != 0 {
                return Err(Error::InvalidEncoding {
                    reason: "BIT STRING has nonzero unused trailing bits",
                });
            }
        }
        Ok(Self { bytes, bit_len })
    }

    /// Copy a borrowed packed BIT STRING with fallible allocation.
    ///
    /// # Parameters and returns
    /// `bytes` contains packed bits; `bit_len` is their exact meaningful width.
    /// Returns an owned, validated BIT STRING value.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for an inconsistent length or padding,
    /// `SizeOverflow` for unrepresentable storage, or `AllocationFailed` if
    /// storage cannot be reserved. It does not panic on malformed input.
    ///
    /// # Source, version, history, and example
    /// Original source: the validated `BitStringValue::new` representation.
    /// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
    /// History: added a fallible adapter for generated fixed-size BER codecs.
    /// Example: `BitStringValue::from_bytes(&[0xa0], 3)?`.
    pub fn from_bytes(bytes: &[u8], bit_len: usize) -> Result<Self, Error> {
        if bytes.len() != bit_storage_len(bit_len)? {
            return Err(Error::InvalidEncoding {
                reason: "BIT STRING storage length does not match its bit length",
            });
        }
        if let Some(unused_mask) = unused_low_bit_mask(bit_len) {
            let last = bytes.last().copied().ok_or(Error::SizeOverflow)?;
            if last & unused_mask != 0 {
                return Err(Error::InvalidEncoding {
                    reason: "BIT STRING has nonzero unused trailing bits",
                });
            }
        }

        // Validate the borrowed representation before requesting owned storage.
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: bytes.len(),
            })?;
        owned.extend_from_slice(bytes);
        Self::new(owned, bit_len)
    }

    /// Return the packed BIT STRING contents without copying.
    ///
    /// # Parameters and returns
    /// `self` is the validated bit string. Returns its packed octets.
    ///
    /// # Errors
    /// This accessor cannot fail.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: added for variable bits.
    /// Example: `let packed = bits.as_bytes();`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the retained capacity of the packed BIT STRING storage.
    ///
    /// # Parameters and returns
    /// `self` is the validated value. Returns the owned Vec capacity without
    /// exposing or copying its storage.
    ///
    /// # Errors
    /// This accessor cannot fail.
    ///
    /// # Source, version, history, and example
    /// Original source: bounded runtime scratch accounting. Version/date:
    /// 2026-11-01. Responsible party: asn1c maintainers. History: nested BER
    /// record budgeting. Example: `let cap = bits.storage_capacity();`.
    #[must_use]
    pub(crate) const fn storage_capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Consume the validated BIT STRING and return its packed octets.
    /// Inputs: `self` is the owned value. Returns its bytes without allocation.
    /// Errors: none. Source: packed BIT STRING representation.
    /// Version: 2026-10-30. Responsible: asn1c maintainers.
    /// History: fixed-size CBOR decoding. Example: `let bytes = bits.into_bytes();`.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the exact number of meaningful bits.
    ///
    /// # Parameters and returns
    /// `self` is the validated bit string. Returns its logical bit length.
    ///
    /// # Errors
    /// This accessor cannot fail.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c Rust runtime API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: added for variable bits.
    /// Example: `let width = bits.bit_len();`.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bit_len
    }
}

/// Incrementally compose a single UPER value from primitive fields.
///
/// Bits are written most-significant first and fields are packed directly
/// together. `finish` adds one zero filler byte only if the entire value has
/// zero meaningful bits.
///
/// # Source, version, history, and example
/// Original source: X.691 unaligned PER and `uper_encode_to_new_buffer` in
/// `skeletons/uper_encoder.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial composable cursor API. Example:
/// `let mut writer = UperWriter::new(&Limits::default())?;`.
pub struct UperWriter {
    /// Encoded-byte state variable; length is the ceiling of `bit_len / 8`.
    bytes: Vec<u8>,
    /// Meaningful bits written so far; this is a state variable.
    bit_len: usize,
    /// Cumulative meaningful-bit and per-field work; this is a state variable.
    work_used: usize,
    /// Resource limits for this complete value.
    limits: Limits,
}

impl UperWriter {
    /// Create an empty writer using operation-wide resource limits.
    ///
    /// # Parameters
    /// `limits` sets the maximum complete output size and cumulative work.
    ///
    /// # Returns
    /// A writer with no fields, bits, or allocated output bytes.
    ///
    /// # Errors
    /// This constructor currently cannot fail and raises no exception.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `let writer = UperWriter::new(&Limits::default())?;`.
    pub const fn new(limits: &Limits) -> Result<Self, Error> {
        Ok(Self {
            bytes: Vec::new(),
            bit_len: 0,
            work_used: 0,
            limits: *limits,
        })
    }

    /// Append one BOOLEAN bit to the current bit stream.
    ///
    /// # Parameters
    /// `value` is the ASN.1 BOOLEAN value to encode.
    ///
    /// # Returns
    /// `Ok(())` after adding one meaningful bit.
    ///
    /// # Errors
    /// Returns a cumulative work/output limit, size, or allocation error.
    ///
    /// # Source, version, history, and example
    /// Original source: `BOOLEAN_encode_uper` in `skeletons/BOOLEAN_uper.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example:
    /// `writer.write_boolean(true)?;`.
    pub fn write_boolean(&mut self, value: bool) -> Result<(), Error> {
        let work = self.next_work(1)?;
        let next_bits = self.next_bit_len(1)?;
        self.prepare_output(next_bits)?;
        write_bits_at(&mut self.bytes, self.bit_len, u64::from(value), 1)?;
        self.bit_len = next_bits;
        self.work_used = work;
        Ok(())
    }

    /// Append a zero-width NULL field without inserting alignment bits.
    ///
    /// # Parameters
    /// No value parameter is needed because ASN.1 NULL has one value.
    ///
    /// # Returns
    /// `Ok(())` after accounting for one field and consuming no wire bits.
    ///
    /// # Errors
    /// Returns a cumulative work limit or size error.
    ///
    /// # Source, version, history, and example
    /// Original source: `NULL_encode_uper` in `skeletons/NULL_uper.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example: `writer.write_null()?;`.
    pub fn write_null(&mut self) -> Result<(), Error> {
        self.append_zero_width_field()
    }

    /// Append one finite bounded signed INTEGER as a fixed-width UPER offset.
    ///
    /// # Parameters
    /// `value` is the value to encode; `lower` and `upper` are inclusive bounds.
    ///
    /// # Returns
    /// `Ok(())` after writing the minimum fixed-width offset from `lower`.
    ///
    /// # Errors
    /// Returns invalid bounds, out-of-range, cumulative limit, size, or
    /// allocation errors. Unconstrained and semi-constrained forms are absent.
    ///
    /// # Source, version, history, and example
    /// Original source: constrained `INTEGER_encode_uper` in
    /// `skeletons/INTEGER_uper.c`. Version/date: 2026-10-30. Responsible party:
    /// asn1c maintainers. History: initial cursor implementation. Example:
    /// `writer.write_integer(-1, -2, 2)?;`.
    pub fn write_integer(&mut self, value: i64, lower: i64, upper: i64) -> Result<(), Error> {
        validate_integer(value, lower, upper)?;
        let (span, field_bits) = integer_shape(lower, upper)?;
        let offset = u64::try_from(i128::from(value) - i128::from(lower))
            .map_err(|_| Error::SizeOverflow)?;
        if u128::from(offset) > span {
            return Err(Error::ValueOutOfRange {
                value,
                lower,
                upper,
            });
        }

        let work = self.next_work(field_bits)?;
        let next_bits = self.next_bit_len(field_bits)?;
        self.prepare_output(next_bits)?;
        write_bits_at(&mut self.bytes, self.bit_len, offset, field_bits)?;
        self.bit_len = next_bits;
        self.work_used = work;
        Ok(())
    }

    /// Append a fixed-size OCTET STRING without aligning the shared bit stream.
    ///
    /// # Parameters
    /// `value` supplies the octets; `expected_len` is the exact ASN.1 size.
    ///
    /// # Returns
    /// `Ok(())` after appending all octet bits in most-significant-first order.
    ///
    /// # Errors
    /// Returns an exact-length validation, cumulative work/output limit,
    /// checked-size, or allocation error. On error, cursor bit and work state
    /// are unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 fixed-size OCTET STRING UPER encoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added to the composable cursor API. Example:
    /// `writer.write_octets(&[0xA5], 1)?;`.
    pub fn write_octets(&mut self, value: &[u8], expected_len: usize) -> Result<(), Error> {
        let field_bits = expected_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
        if value.len() != expected_len {
            return Err(Error::InvalidEncoding {
                reason: "OCTET STRING length does not match its fixed size",
            });
        }
        let work = self.next_work(field_bits)?;
        let next_bits = self.next_bit_len(field_bits)?;
        self.prepare_output(next_bits)?;
        write_slice_bits_at(&mut self.bytes, self.bit_len, value, field_bits)?;
        self.bit_len = next_bits;
        self.work_used = work;
        Ok(())
    }

    /// Append a bounded-size OCTET STRING without aligning the shared bit stream.
    ///
    /// # Parameters
    /// `value` supplies the octets; `lower` and `upper` are inclusive size bounds.
    /// The supported bounds satisfy `0 <= lower < upper < 65536`.
    ///
    /// # Returns
    /// `Ok(())` after writing the constrained length offset and octet payload.
    ///
    /// # Errors
    /// Returns invalid bounds, out-of-range length, cumulative work/output
    /// limit, checked-size, or allocation errors. Validation and limit errors
    /// leave cursor, work, and output state unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 bounded OCTET STRING UPER encoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added for variable-size bounded strings. Example:
    /// `writer.write_bounded_octets(&[0xA5], 1, 3)?;`.
    pub fn write_bounded_octets(
        &mut self,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        let (span, length_bits) = bounded_string_shape(lower, upper)?;
        if value.len() < lower || value.len() > upper {
            return Err(Error::InvalidEncoding {
                reason: "OCTET STRING length is outside its constrained size",
            });
        }
        let length_offset = value.len().checked_sub(lower).ok_or(Error::SizeOverflow)?;
        if u128::try_from(length_offset).map_err(|_| Error::SizeOverflow)? > span {
            return Err(Error::SizeOverflow);
        }
        let payload_bits = value.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
        let field_bits = length_bits
            .checked_add(payload_bits)
            .ok_or(Error::SizeOverflow)?;
        let work = self.next_work(field_bits)?;
        let next_bits = self.next_bit_len(field_bits)?;
        let payload_start = self
            .bit_len
            .checked_add(length_bits)
            .ok_or(Error::SizeOverflow)?;
        let length_offset = u64::try_from(length_offset).map_err(|_| Error::SizeOverflow)?;

        // The calculated endpoints and lengths make both bit-copy operations
        // fit the output prepared below; they cannot fail for valid internals.
        self.prepare_output(next_bits)?;
        write_bits_at(&mut self.bytes, self.bit_len, length_offset, length_bits)?;
        write_slice_bits_at(&mut self.bytes, payload_start, value, payload_bits)?;
        self.bit_len = next_bits;
        self.work_used = work;
        Ok(())
    }

    /// Append a fixed-size BIT STRING without aligning the shared bit stream.
    ///
    /// # Parameters
    /// `value` stores the bits most-significant first; `bit_len` is the exact
    /// number of meaningful bits. Unused low bits in the final octet must be
    /// zero.
    ///
    /// # Returns
    /// `Ok(())` after appending exactly `bit_len` bits.
    ///
    /// # Errors
    /// Returns an exact-storage-length or unused-bit validation, cumulative
    /// work/output limit, checked-size, or allocation error. On error, cursor
    /// bit and work state are unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 fixed-size BIT STRING UPER encoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added to the composable cursor API. Example:
    /// `writer.write_bit_string(&[0xA0], 3)?;`.
    pub fn write_bit_string(&mut self, value: &[u8], bit_len: usize) -> Result<(), Error> {
        let expected_bytes = bit_storage_len(bit_len)?;
        if value.len() != expected_bytes {
            return Err(Error::InvalidEncoding {
                reason: "BIT STRING storage length does not match its bit length",
            });
        }
        if let Some(unused_mask) = unused_low_bit_mask(bit_len) {
            let last = value.last().copied().ok_or(Error::SizeOverflow)?;
            if last & unused_mask != 0 {
                return Err(Error::InvalidEncoding {
                    reason: "BIT STRING has nonzero unused trailing bits",
                });
            }
        }

        let work = self.next_work(bit_len)?;
        let next_bits = self.next_bit_len(bit_len)?;
        self.prepare_output(next_bits)?;
        write_slice_bits_at(&mut self.bytes, self.bit_len, value, bit_len)?;
        self.bit_len = next_bits;
        self.work_used = work;
        Ok(())
    }

    /// Append a bounded-size BIT STRING without aligning the shared bit stream.
    ///
    /// # Parameters
    /// `value` carries packed octets and an exact bit length; `lower` and
    /// `upper` are inclusive bounds satisfying `0 <= lower < upper < 65536`.
    ///
    /// # Returns
    /// `Ok(())` after writing the constrained bit length and its payload bits.
    ///
    /// # Errors
    /// Returns invalid bounds, out-of-range length, cumulative work/output
    /// limit, checked-size, or allocation errors. Validation and limit failures
    /// leave cursor, work, and output state unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 bounded BIT STRING UPER encoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added for variable-size bounded bit strings. Example:
    /// `writer.write_bounded_bit_string(&bits, 1, 3)?;`.
    pub fn write_bounded_bit_string(
        &mut self,
        value: &BitStringValue,
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        let (span, length_bits) = bounded_string_shape(lower, upper)?;
        if value.bit_len < lower || value.bit_len > upper {
            return Err(Error::InvalidEncoding {
                reason: "BIT STRING length is outside its constrained size",
            });
        }
        let length_offset = value
            .bit_len
            .checked_sub(lower)
            .ok_or(Error::SizeOverflow)?;
        if u128::try_from(length_offset).map_err(|_| Error::SizeOverflow)? > span {
            return Err(Error::SizeOverflow);
        }
        let field_bits = length_bits
            .checked_add(value.bit_len)
            .ok_or(Error::SizeOverflow)?;
        let work = self.next_work(field_bits)?;
        let next_bits = self.next_bit_len(field_bits)?;
        let payload_start = self
            .bit_len
            .checked_add(length_bits)
            .ok_or(Error::SizeOverflow)?;
        let length_offset = u64::try_from(length_offset).map_err(|_| Error::SizeOverflow)?;

        // Checked endpoint arithmetic guarantees both writes fit after reserve.
        self.prepare_output(next_bits)?;
        write_bits_at(&mut self.bytes, self.bit_len, length_offset, length_bits)?;
        write_slice_bits_at(&mut self.bytes, payload_start, &value.bytes, value.bit_len)?;
        self.bit_len = next_bits;
        self.work_used = work;
        Ok(())
    }

    /// Finish the complete value, adding a zero filler byte when it has no bits.
    ///
    /// # Parameters
    /// `self` is consumed so the returned encoding owns the completed bytes.
    ///
    /// # Returns
    /// The complete encoding and its meaningful bit count.
    ///
    /// # Errors
    /// Returns an output limit, size, or allocation error if completion fails.
    ///
    /// # Source, version, history, and example
    /// Original source: complete-value framing in `skeletons/uper_encoder.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example: `let encoded = writer.finish()?;`.
    pub fn finish(mut self) -> Result<Encoded, Error> {
        if self.bit_len == 0 {
            check_output_limit(1, &self.limits)?;
            self.bytes
                .try_reserve_exact(1)
                .map_err(|_| Error::AllocationFailed { requested_bytes: 1 })?;
            self.bytes.resize(1, 0);
        }
        Ok(Encoded {
            bytes: self.bytes,
            bit_len: self.bit_len,
        })
    }

    /// Calculate and validate the next cumulative work amount.
    ///
    /// # Parameters and returns
    /// `field_bits` is the field's meaningful wire width. Returns the next
    /// cumulative work amount after its fixed overhead.
    ///
    /// # Errors
    /// Returns `SizeOverflow` or `LimitExceeded`; it performs no mutation.
    ///
    /// # Source, version, history, and example
    /// Original source: operation-wide UPER resource accounting. Version/date:
    /// 2026-10-30. Responsible party: asn1c maintainers. History: initial
    /// cursor implementation. Example: `self.next_work(1)?`.
    fn next_work(&self, field_bits: usize) -> Result<usize, Error> {
        let field_work = field_bits
            .checked_add(FIELD_WORK_OVERHEAD)
            .ok_or(Error::SizeOverflow)?;
        let next_work = self
            .work_used
            .checked_add(field_work)
            .ok_or(Error::SizeOverflow)?;
        check_work_limit(next_work, &self.limits)?;
        Ok(next_work)
    }

    /// Calculate the next cumulative meaningful bit length.
    ///
    /// # Parameters and returns
    /// `field_bits` is the appended width. Returns the new total bit length.
    ///
    /// # Errors
    /// Returns `SizeOverflow` if the total cannot fit `usize`.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `self.next_bit_len(1)?`.
    fn next_bit_len(&self, field_bits: usize) -> Result<usize, Error> {
        self.bit_len
            .checked_add(field_bits)
            .ok_or(Error::SizeOverflow)
    }

    /// Reserve and zero any additional bytes required by a planned bit length.
    ///
    /// # Parameters and returns
    /// `bit_len` is the planned total. Zero bits require no byte until finish.
    /// Returns `Ok(())` after enforcing the complete-output byte ceiling.
    ///
    /// # Errors
    /// Returns an output limit, size, or fallible-allocation error.
    ///
    /// # Source, version, history, and example
    /// Original source: bounded output-buffer handling in the asn1c runtime.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example: `self.prepare_output(1)?`.
    fn prepare_output(&mut self, bit_len: usize) -> Result<(), Error> {
        let required_bytes = if bit_len == 0 {
            0
        } else {
            encoded_byte_len(bit_len)?
        };
        check_output_limit(required_bytes, &self.limits)?;

        // Reserve before resizing so a failed allocation never triggers a panic.
        let additional = if required_bytes > self.bytes.len() {
            required_bytes - self.bytes.len()
        } else {
            0
        };
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: required_bytes,
            })?;
        if self.bytes.len() < required_bytes {
            self.bytes.resize(required_bytes, 0);
        }
        Ok(())
    }

    /// Account for a zero-width field without adding bits or bytes.
    ///
    /// # Parameters and returns
    /// No parameters. Returns `Ok(())` after work-limit validation.
    ///
    /// # Errors
    /// Returns a cumulative work limit or size error.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `self.append_zero_width_field()?`.
    fn append_zero_width_field(&mut self) -> Result<(), Error> {
        let work = self.next_work(0)?;
        self.work_used = work;
        Ok(())
    }
}

/// Incrementally decode primitive fields from one complete UPER input slice.
///
/// The input limit is checked once by `new` against the full slice. Field reads
/// then advance a shared bit cursor and cumulative work counter. Trailing bits
/// in the last occupied byte are left untouched.
///
/// # Source, version, history, and example
/// Original source: X.691 UPER and `uper_decode_complete` in
/// `skeletons/uper_decoder.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial composable cursor API. Example:
/// `let mut reader = UperReader::new(&[0x80], &Limits::default())?;`.
pub struct UperReader<'a> {
    /// The complete caller-supplied input; this reference is never reallocated.
    input: &'a [u8],
    /// Available input bit count checked once during construction.
    available_bits: usize,
    /// Number of meaningful bits consumed so far; this is a state variable.
    bit_offset: usize,
    /// Cumulative meaningful-bit and per-field work; this is a state variable.
    work_used: usize,
    /// Resource limits for this complete value.
    limits: Limits,
}

impl<'a> UperReader<'a> {
    /// Create a reader and validate the size of the entire supplied input.
    ///
    /// # Parameters
    /// `input` is the complete available value slice; `limits` bounds its size
    /// and cumulative decoding work.
    ///
    /// # Returns
    /// A reader positioned at bit zero with no work yet charged.
    ///
    /// # Errors
    /// Returns an input-limit or checked bit-length overflow error.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `let reader = UperReader::new(input, &Limits::default())?;`.
    pub fn new(input: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        check_input_limit(input, limits)?;
        let available_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
        Ok(Self {
            input,
            available_bits,
            bit_offset: 0,
            work_used: 0,
            limits: *limits,
        })
    }

    /// Read and consume one BOOLEAN bit.
    ///
    /// # Parameters
    /// No parameters; the next meaningful bit is interpreted as BOOLEAN.
    ///
    /// # Returns
    /// `true` for a one bit and `false` for a zero bit.
    ///
    /// # Errors
    /// Returns truncation, cumulative work-limit, or checked-size errors.
    ///
    /// # Source, version, history, and example
    /// Original source: `BOOLEAN_decode_uper` in `skeletons/BOOLEAN_uper.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example: `reader.read_boolean()?`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        let value = self.read_field_bits(1)? != 0;
        Ok(value)
    }

    /// Read a zero-width NULL field without advancing the bit cursor.
    ///
    /// # Parameters
    /// No parameters; ASN.1 NULL has one value and no UPER contents.
    ///
    /// # Returns
    /// `Ok(())` after accounting for one field.
    ///
    /// # Errors
    /// Returns a cumulative work-limit or size error.
    ///
    /// # Source, version, history, and example
    /// Original source: `NULL_decode_uper` in `skeletons/NULL_uper.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example: `reader.read_null()?;`.
    pub fn read_null(&mut self) -> Result<(), Error> {
        self.charge_zero_width_field()
    }

    /// Read one finite bounded signed INTEGER from the shared bit stream.
    ///
    /// # Parameters
    /// `lower` and `upper` are inclusive signed bounds for the constrained value.
    ///
    /// # Returns
    /// The decoded value represented by the next fixed-width offset.
    ///
    /// # Errors
    /// Returns invalid bounds, truncation, spare-code, cumulative limit, or
    /// checked-size errors. Unconstrained forms are unsupported.
    ///
    /// # Source, version, history, and example
    /// Original source: constrained `INTEGER_decode_uper` in
    /// `skeletons/INTEGER_uper.c`. Version/date: 2026-10-30. Responsible party:
    /// asn1c maintainers. History: initial cursor implementation. Example:
    /// `reader.read_integer(-2, 2)?`.
    pub fn read_integer(&mut self, lower: i64, upper: i64) -> Result<i64, Error> {
        let (span, field_bits) = integer_shape(lower, upper)?;
        let work = self.next_work(field_bits)?;
        let offset = self.peek_field_bits(field_bits)?;
        if u128::from(offset) > span {
            return Err(Error::InvalidEncoding {
                reason: "spare constrained INTEGER code",
            });
        }

        let value = i128::from(lower) + i128::from(offset);
        let value = i64::try_from(value).map_err(|_| Error::InvalidEncoding {
            reason: "constrained INTEGER result is outside i64",
        })?;
        self.commit_field(field_bits, work)?;
        Ok(value)
    }

    /// Read a fixed-size OCTET STRING from the shared bit stream.
    ///
    /// # Parameters
    /// `expected_len` is the exact number of octets to consume.
    ///
    /// # Returns
    /// A newly allocated vector containing the decoded octets.
    ///
    /// # Errors
    /// Returns truncation, cumulative work-limit, checked-size, or fallible
    /// allocation errors. On error, cursor bit and work state are unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 fixed-size OCTET STRING UPER decoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added to the composable cursor API. Example:
    /// `let octets = reader.read_octets(1)?;`.
    pub fn read_octets(&mut self, expected_len: usize) -> Result<Vec<u8>, Error> {
        let field_bits = expected_len.checked_mul(8).ok_or(Error::SizeOverflow)?;
        let work = self.next_work(field_bits)?;
        self.ensure_available(field_bits)?;
        let mut value = allocate_zeroed_bytes(expected_len)?;
        read_slice_bits_at(self.input, self.bit_offset, &mut value, field_bits)?;
        self.commit_field(field_bits, work)?;
        Ok(value)
    }

    /// Read a bounded-size OCTET STRING from the shared bit stream.
    ///
    /// # Parameters
    /// `lower` and `upper` are inclusive size bounds satisfying
    /// `0 <= lower < upper < 65536`.
    ///
    /// # Returns
    /// A newly allocated vector containing the decoded octets.
    ///
    /// # Errors
    /// Returns invalid bounds, a spare length code, truncation, cumulative
    /// work-limit, checked-size, or fallible allocation errors. On error,
    /// reader cursor and work state are unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 bounded OCTET STRING UPER decoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added for variable-size bounded strings. Example:
    /// `let value = reader.read_bounded_octets(1, 3)?;`.
    pub fn read_bounded_octets(&mut self, lower: usize, upper: usize) -> Result<Vec<u8>, Error> {
        let (span, length_bits) = bounded_string_shape(lower, upper)?;
        let length_offset = self.peek_field_bits(length_bits)?;
        if u128::from(length_offset) > span {
            return Err(Error::InvalidEncoding {
                reason: "spare constrained OCTET STRING length code",
            });
        }
        let length = lower
            .checked_add(usize::try_from(length_offset).map_err(|_| Error::SizeOverflow)?)
            .ok_or(Error::SizeOverflow)?;
        let payload_bits = length.checked_mul(8).ok_or(Error::SizeOverflow)?;
        let field_bits = length_bits
            .checked_add(payload_bits)
            .ok_or(Error::SizeOverflow)?;
        let work = self.next_work(field_bits)?;
        self.ensure_available(field_bits)?;
        let mut value = allocate_zeroed_bytes(length)?;
        let payload_start = self
            .bit_offset
            .checked_add(length_bits)
            .ok_or(Error::SizeOverflow)?;
        read_slice_bits_at(self.input, payload_start, &mut value, payload_bits)?;
        self.commit_field(field_bits, work)?;
        Ok(value)
    }

    /// Read a fixed-size BIT STRING from the shared bit stream.
    ///
    /// # Parameters
    /// `bit_len` is the exact number of meaningful bits to consume.
    ///
    /// # Returns
    /// A newly allocated, most-significant-first byte vector. Unused low bits
    /// in its final octet are zero.
    ///
    /// # Errors
    /// Returns truncation, cumulative work-limit, checked-size, or fallible
    /// allocation errors. On error, cursor bit and work state are unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 fixed-size BIT STRING UPER decoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added to the composable cursor API. Example:
    /// `let bits = reader.read_bit_string(3)?;`.
    pub fn read_bit_string(&mut self, bit_len: usize) -> Result<Vec<u8>, Error> {
        let output_len = bit_storage_len(bit_len)?;
        let work = self.next_work(bit_len)?;
        self.ensure_available(bit_len)?;
        let mut value = allocate_zeroed_bytes(output_len)?;
        read_slice_bits_at(self.input, self.bit_offset, &mut value, bit_len)?;
        self.commit_field(bit_len, work)?;
        Ok(value)
    }

    /// Read a bounded-size BIT STRING from the shared bit stream.
    ///
    /// # Parameters
    /// `lower` and `upper` are inclusive size bounds satisfying
    /// `0 <= lower < upper < 65536`.
    ///
    /// # Returns
    /// A validated packed value that preserves its exact meaningful bit count.
    ///
    /// # Errors
    /// Returns invalid bounds, a spare length code, truncation, cumulative
    /// work-limit, checked-size, or allocation errors. On error, reader cursor
    /// and work state are unchanged.
    ///
    /// # Source, version, history, and example
    /// Original source: X.691 bounded BIT STRING UPER decoding.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: added for variable-size bounded bit strings. Example:
    /// `let bits = reader.read_bounded_bit_string(1, 3)?;`.
    pub fn read_bounded_bit_string(
        &mut self,
        lower: usize,
        upper: usize,
    ) -> Result<BitStringValue, Error> {
        let (span, length_bits) = bounded_string_shape(lower, upper)?;
        let length_offset = self.peek_field_bits(length_bits)?;
        if u128::from(length_offset) > span {
            return Err(Error::InvalidEncoding {
                reason: "spare constrained BIT STRING length code",
            });
        }
        let bit_len = lower
            .checked_add(usize::try_from(length_offset).map_err(|_| Error::SizeOverflow)?)
            .ok_or(Error::SizeOverflow)?;
        let field_bits = length_bits
            .checked_add(bit_len)
            .ok_or(Error::SizeOverflow)?;
        let work = self.next_work(field_bits)?;
        self.ensure_available(field_bits)?;
        let output_len = bit_storage_len(bit_len)?;
        let mut bytes = allocate_zeroed_bytes(output_len)?;
        let payload_start = self
            .bit_offset
            .checked_add(length_bits)
            .ok_or(Error::SizeOverflow)?;
        read_slice_bits_at(self.input, payload_start, &mut bytes, bit_len)?;
        self.commit_field(field_bits, work)?;
        // Zeroed storage plus copying only meaningful bits preserves canonical padding.
        Ok(BitStringValue { bytes, bit_len })
    }

    /// Finish decoding and report the consumed prefix.
    ///
    /// # Parameters
    /// `self` is consumed because no more fields can be read after completion.
    ///
    /// # Returns
    /// Unit plus the meaningful bit and whole-byte prefix lengths. For a
    /// zero-width value, one zero filler byte is required and reported.
    ///
    /// # Errors
    /// Returns missing-byte or malformed-filler errors for a zero-width value.
    ///
    /// # Source, version, history, and example
    /// Original source: complete-value behavior in `skeletons/uper_decoder.c`.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: initial cursor implementation. Example: `reader.finish()?`.
    pub fn finish(self) -> Result<Decoded<()>, Error> {
        if self.bit_offset == 0 {
            let filler = self.input.first().ok_or(Error::NeedMoreBytes {
                required_bytes: 1,
                available_bytes: self.input.len(),
            })?;
            if *filler != 0 {
                return Err(Error::InvalidEncoding {
                    reason: "nonzero complete-encoding filler for a zero-width value",
                });
            }
            return Ok(Decoded {
                value: (),
                consumed_bits: 0,
                consumed_bytes: 1,
            });
        }

        Ok(Decoded {
            value: (),
            consumed_bits: self.bit_offset,
            consumed_bytes: encoded_byte_len(self.bit_offset)?,
        })
    }

    /// Read a field's bits and immediately commit its cursor and work state.
    ///
    /// # Parameters and returns
    /// `field_bits` is the requested width. Returns its right-aligned value.
    ///
    /// # Errors
    /// Returns truncation, cumulative work-limit, or checked-size errors.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `self.read_field_bits(1)?`.
    fn read_field_bits(&mut self, field_bits: usize) -> Result<u64, Error> {
        let work = self.next_work(field_bits)?;
        let value = self.peek_field_bits(field_bits)?;
        self.commit_field(field_bits, work)?;
        Ok(value)
    }

    /// Read field bits without mutating state, after checking work and input.
    ///
    /// # Parameters and returns
    /// `field_bits` is the field width. Returns a right-aligned `u64`.
    ///
    /// # Errors
    /// Returns work-limit, truncation, width, or checked-size errors.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `self.peek_field_bits(2)?`.
    fn peek_field_bits(&self, field_bits: usize) -> Result<u64, Error> {
        if field_bits > u64::BITS as usize {
            return Err(Error::InvalidEncoding {
                reason: "UPER field width exceeds the integer accumulator",
            });
        }
        let end = self
            .bit_offset
            .checked_add(field_bits)
            .ok_or(Error::SizeOverflow)?;
        if end > self.available_bits {
            return Err(Error::NeedMoreBits {
                required_bits: end,
                available_bits: self.available_bits,
            });
        }

        // state variable: accumulate the requested wire-order bits without indexing panics.
        let mut value = 0_u64;
        for relative in 0..field_bits {
            let absolute = self
                .bit_offset
                .checked_add(relative)
                .ok_or(Error::SizeOverflow)?;
            let byte = *self.input.get(absolute / 8).ok_or(Error::SizeOverflow)?;
            let shift = 7 - (absolute % 8);
            value = (value << 1) | u64::from((byte >> shift) & 1);
        }
        Ok(value)
    }

    /// Validate that a complete arbitrary-width field is available.
    ///
    /// # Parameters and returns
    /// `field_bits` is the requested width. Returns `Ok(())` if its endpoint
    /// fits in the complete input slice.
    ///
    /// # Errors
    /// Returns `NeedMoreBits` or `SizeOverflow`; it does not mutate reader state.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: added for string fields.
    /// Example: `self.ensure_available(8)?`.
    fn ensure_available(&self, field_bits: usize) -> Result<(), Error> {
        let end = self
            .bit_offset
            .checked_add(field_bits)
            .ok_or(Error::SizeOverflow)?;
        if end > self.available_bits {
            return Err(Error::NeedMoreBits {
                required_bits: end,
                available_bits: self.available_bits,
            });
        }
        Ok(())
    }

    /// Commit a previously validated field width and its work charge.
    ///
    /// # Parameters and returns
    /// `field_bits` is the number of consumed bits; `work` is the checked next
    /// cumulative work count. Returns `Ok(())` after updating reader state.
    ///
    /// # Errors
    /// Returns `SizeOverflow` if the cursor arithmetic is inconsistent.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `self.commit_field(1, next_work)?`.
    fn commit_field(&mut self, field_bits: usize, work: usize) -> Result<(), Error> {
        self.bit_offset = self
            .bit_offset
            .checked_add(field_bits)
            .ok_or(Error::SizeOverflow)?;
        self.work_used = work;
        Ok(())
    }

    /// Calculate and validate a field's next cumulative work charge.
    ///
    /// # Parameters and returns
    /// `field_bits` is the meaningful wire width. Returns cumulative work
    /// including the fixed eight-unit per-field overhead.
    ///
    /// # Errors
    /// Returns `SizeOverflow` or a work `LimitExceeded` error.
    ///
    /// # Source, version, history, and example
    /// Original source: operation-wide UPER resource accounting. Version/date:
    /// 2026-10-30. Responsible party: asn1c maintainers. History: initial
    /// cursor implementation. Example: `self.next_work(1)?`.
    fn next_work(&self, field_bits: usize) -> Result<usize, Error> {
        let field_work = field_bits
            .checked_add(FIELD_WORK_OVERHEAD)
            .ok_or(Error::SizeOverflow)?;
        let next_work = self
            .work_used
            .checked_add(field_work)
            .ok_or(Error::SizeOverflow)?;
        check_work_limit(next_work, &self.limits)?;
        Ok(next_work)
    }

    /// Charge a zero-width field while leaving the bit cursor unchanged.
    ///
    /// # Parameters and returns
    /// No parameters. Returns `Ok(())` after its work budget is checked.
    ///
    /// # Errors
    /// Returns a cumulative work limit or size error.
    ///
    /// # Source, version, history, and example
    /// Original source: new asn1c UPER cursor API. Version/date: 2026-10-30.
    /// Responsible party: asn1c maintainers. History: initial implementation.
    /// Example: `self.charge_zero_width_field()?`.
    fn charge_zero_width_field(&mut self) -> Result<(), Error> {
        let work = self.next_work(0)?;
        self.work_used = work;
        Ok(())
    }
}

/// Write a field into an already sized output buffer at an absolute bit offset.
///
/// # Parameters and returns
/// `output` is the zero-filled destination; `start` is its bit position;
/// `value` is right-aligned; `width` is the field's meaningful width.
/// Returns `Ok(())` after writing bits most-significant first.
///
/// # Errors
/// Returns `InvalidEncoding` for a width above 64 and `SizeOverflow` for an
/// inconsistent destination or position. It allocates no memory.
///
/// # Source, version, history, and example
/// Original source: bit helpers in `skeletons/asn_bit_data.c` and
/// `skeletons/uper_support.c`. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: initial cursor implementation. Example:
/// `write_bits_at(&mut [0], 0, 1, 1)?` writes `0x80`.
fn write_bits_at(output: &mut [u8], start: usize, value: u64, width: usize) -> Result<(), Error> {
    if width > u64::BITS as usize {
        return Err(Error::InvalidEncoding {
            reason: "UPER field width exceeds the integer accumulator",
        });
    }
    let end = start.checked_add(width).ok_or(Error::SizeOverflow)?;
    let capacity = output.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    if end > capacity {
        return Err(Error::InvalidEncoding {
            reason: "output buffer is too small for the bit field",
        });
    }

    // Copy the field into the existing zeroed buffer without disturbing earlier bits.
    for relative in 0..width {
        let source_shift = width - relative - 1;
        if ((value >> source_shift) & 1) != 0 {
            let absolute = start.checked_add(relative).ok_or(Error::SizeOverflow)?;
            let target = output.get_mut(absolute / 8).ok_or(Error::SizeOverflow)?;
            *target |= 1 << (7 - (absolute % 8));
        }
    }
    Ok(())
}

/// Write arbitrary-width source bits into an already sized output buffer.
///
/// # Parameters and returns
/// `output` is the destination; `start` is its bit offset; `input` stores
/// most-significant-first bits; `bit_len` is their meaningful count. Returns
/// `Ok(())` after copying exactly that many bits.
///
/// # Errors
/// Returns `SizeOverflow` for unrepresentable sizes or `InvalidEncoding` for
/// inconsistent internal buffer lengths. No allocation occurs.
///
/// # Source, version, history, and example
/// Original source: X.691 UPER bit-string packing. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added for cursor strings.
/// Example: `write_slice_bits_at(output, 3, &[0xA0], 3)?`.
fn write_slice_bits_at(
    output: &mut [u8],
    start: usize,
    input: &[u8],
    bit_len: usize,
) -> Result<(), Error> {
    let end = start.checked_add(bit_len).ok_or(Error::SizeOverflow)?;
    let output_bits = output.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    let input_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    if end > output_bits || bit_len > input_bits {
        return Err(Error::InvalidEncoding {
            reason: "bit-slice buffer is too small for the requested field",
        });
    }

    // Copy source bits individually to preserve existing bits around an
    // unaligned destination range in the continuous output stream.
    for relative in 0..bit_len {
        let source = *input.get(relative / 8).ok_or(Error::SizeOverflow)?;
        let source_bit = (source >> (7 - (relative % 8))) & 1;
        if source_bit != 0 {
            let absolute = start.checked_add(relative).ok_or(Error::SizeOverflow)?;
            let target = output.get_mut(absolute / 8).ok_or(Error::SizeOverflow)?;
            *target |= 1 << (7 - (absolute % 8));
        }
    }
    Ok(())
}

/// Copy arbitrary-width input bits into a zeroed output buffer.
///
/// # Parameters and returns
/// `input` is the complete source; `start` is its bit offset; `output` is the
/// destination; `bit_len` is the meaningful count. Returns `Ok(())` after
/// copying exactly that many bits.
///
/// # Errors
/// Returns `SizeOverflow` for unrepresentable sizes or `InvalidEncoding` for
/// inconsistent internal buffer lengths. No allocation occurs.
///
/// # Source, version, history, and example
/// Original source: X.691 UPER bit-string unpacking. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added for cursor strings.
/// Example: `read_slice_bits_at(input, 3, output, 3)?`.
fn read_slice_bits_at(
    input: &[u8],
    start: usize,
    output: &mut [u8],
    bit_len: usize,
) -> Result<(), Error> {
    let end = start.checked_add(bit_len).ok_or(Error::SizeOverflow)?;
    let input_bits = input.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    let output_bits = output.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    if end > input_bits || bit_len > output_bits {
        return Err(Error::InvalidEncoding {
            reason: "bit-slice buffer is too small for the requested field",
        });
    }

    // Set only one bits; the caller zero-initializes the destination so unused
    // trailing output bits remain canonical zeros.
    for relative in 0..bit_len {
        let absolute = start.checked_add(relative).ok_or(Error::SizeOverflow)?;
        let source = *input.get(absolute / 8).ok_or(Error::SizeOverflow)?;
        if ((source >> (7 - (absolute % 8))) & 1) != 0 {
            let target = output.get_mut(relative / 8).ok_or(Error::SizeOverflow)?;
            *target |= 1 << (7 - (relative % 8));
        }
    }
    Ok(())
}

/// Validate a bounded string range and calculate its constrained length width.
///
/// # Parameters and returns
/// `lower` and `upper` are inclusive size bounds. Returns the offset span and
/// `ceil(log2(span + 1))` bits needed to represent every permitted size.
///
/// # Errors
/// Returns `InvalidEncoding` unless `0 <= lower < upper < 65536`.
///
/// # Source, version, history, and example
/// Original source: X.691 constrained length determinant rules.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added for bounded string cursor methods.
/// Example: `bounded_string_shape(1, 3)?` returns `(2, 2)`.
fn bounded_string_shape(lower: usize, upper: usize) -> Result<(u128, usize), Error> {
    if lower >= upper || upper >= 65_536 {
        return Err(Error::InvalidEncoding {
            reason: "unsupported bounded string size range",
        });
    }
    let span = upper.checked_sub(lower).ok_or(Error::SizeOverflow)?;
    let cardinality = span.checked_add(1).ok_or(Error::SizeOverflow)?;
    let maximum_offset = cardinality.checked_sub(1).ok_or(Error::SizeOverflow)?;
    let width = usize::BITS
        .checked_sub(maximum_offset.leading_zeros())
        .ok_or(Error::SizeOverflow)?;
    let width = usize::try_from(width).map_err(|_| Error::SizeOverflow)?;
    Ok((
        u128::try_from(span).map_err(|_| Error::SizeOverflow)?,
        width,
    ))
}

/// Allocate and zero an output vector without allowing allocation panics.
///
/// # Parameters and returns
/// `byte_len` is the caller-validated output size. Returns a zero-filled vector.
///
/// # Errors
/// Returns `AllocationFailed` if the requested allocation cannot be reserved.
///
/// # Source, version, history, and example
/// Original source: bounded allocation policy in the asn1c runtime.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: added for arbitrary-width cursor reads. Example:
/// `let bytes = allocate_zeroed_bytes(2)?;`.
fn allocate_zeroed_bytes(byte_len: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_len)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: byte_len,
        })?;
    bytes.resize(byte_len, 0);
    Ok(bytes)
}

/// Return the storage-byte count for a meaningful BIT STRING width.
///
/// # Parameters and returns
/// `bit_len` is the number of meaningful bits. Returns zero for zero bits and
/// the ceiling byte count otherwise.
///
/// # Errors
/// Returns `SizeOverflow` if rounding cannot be represented.
///
/// # Source, version, history, and example
/// Original source: X.691 BIT STRING storage sizing. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: added for cursor strings.
/// Example: `bit_storage_len(9)?` returns two.
fn bit_storage_len(bit_len: usize) -> Result<usize, Error> {
    if bit_len == 0 {
        return Ok(0);
    }
    bit_len
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(Error::SizeOverflow)
}

/// Return the mask covering unused low-order bits in a partial final octet.
///
/// # Parameters and returns
/// `bit_len` is the meaningful BIT STRING width. Returns `None` when aligned,
/// or a mask whose set bits must be zero in the final source octet.
///
/// # Errors
/// This helper is total and raises no error.
///
/// # Source, version, history, and example
/// Original source: X.691 BIT STRING padding validation. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: added for
/// cursor strings. Example: `unused_low_bit_mask(3) == Some(0x1f)`.
const fn unused_low_bit_mask(bit_len: usize) -> Option<u8> {
    let used_in_last = bit_len % 8;
    if used_in_last == 0 {
        None
    } else {
        Some((1_u8 << (8 - used_in_last)) - 1)
    }
}

/// Check a complete output byte count against the writer's configured ceiling.
///
/// # Parameters and returns
/// `byte_len` is the required complete output size; `limits` supplies its cap.
/// Returns `Ok(())` when the requested size is permitted.
///
/// # Errors
/// Returns `LimitExceeded`; it performs no allocation.
///
/// # Source, version, history, and example
/// Original source: bounded output checks in the asn1c runtime. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial
/// implementation. Example: `check_output_limit(1, limits)?`.
const fn check_output_limit(byte_len: usize, limits: &Limits) -> Result<(), Error> {
    if byte_len > limits.max_output_bytes {
        return Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            limit: limits.max_output_bytes,
            requested: byte_len,
        });
    }
    Ok(())
}

/// Return occupied complete-value bytes for a meaningful bit count.
///
/// # Parameters and returns
/// `bit_len` is the meaningful wire width. Returns one for zero bits and the
/// ceiling byte count otherwise.
///
/// # Errors
/// Returns `SizeOverflow` if rounding the width would overflow `usize`.
///
/// # Source, version, history, and example
/// Original source: `uper_encode_to_new_buffer` in `skeletons/uper_encoder.c`.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// initial implementation. Example: `encoded_byte_len(9)?` returns two.
fn encoded_byte_len(bit_len: usize) -> Result<usize, Error> {
    if bit_len == 0 {
        return Ok(1);
    }
    bit_len
        .checked_add(7)
        .map(|rounded| rounded / 8)
        .ok_or(Error::SizeOverflow)
}

/// Encode opaque ANY octets with the UPER length envelope.
///
/// # Parameters and returns
/// `value` supplies octets; `limits` bounds resources. Returns the encoding.
///
/// # Errors
/// Returns resource, allocation, or arithmetic errors.
///
/// # Source, version, history, and example
/// Source: `skeletons/ANY_uper.c`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: initial ANY framing.
/// Example: `encode_any_uper(&[], &Limits::default())?`.
pub fn encode_any_uper(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    let mut writer = UperWriter::new(limits)?;
    write_any_uper(&mut writer, value)?;
    writer.finish()
}

/// Append opaque ANY octets to a shared UPER cursor.
///
/// # Parameters and returns
/// `writer` is the cursor; `value` supplies octets. Returns success on completion.
///
/// # Errors
/// Returns resource, allocation, or arithmetic errors; the cursor may be partially advanced.
///
/// # Source, version, history, and example
/// Source: `skeletons/ANY_uper.c`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: composable ANY framing.
/// Example: `write_any_uper(&mut writer, &[])?`.
pub fn write_any_uper(writer: &mut UperWriter, value: &[u8]) -> Result<(), Error> {
    let mut rest = value;
    loop {
        let length = rest.len();
        let fragment = if length < 128 {
            writer.write_integer(
                i64::try_from(length).map_err(|_| Error::SizeOverflow)?,
                0,
                255,
            )?;
            length
        } else if length < 16384 {
            let header = 0x8000 | length;
            writer.write_integer(
                i64::try_from(header).map_err(|_| Error::SizeOverflow)?,
                0,
                65535,
            )?;
            length
        } else {
            let units = (length / 16384).min(4);
            writer.write_integer(
                i64::try_from(0xc0 | units).map_err(|_| Error::SizeOverflow)?,
                0,
                255,
            )?;
            units * 16384
        };
        writer.write_octets(&rest[..fragment], fragment)?;
        rest = &rest[fragment..];
        if length < 16384 {
            break;
        }
    }
    Ok(())
}

/// Decode an opaque ANY value from a UPER prefix.
///
/// # Parameters and returns
/// `input` supplies the encoded prefix; `limits` bounds resources. Returns
/// the octets and consumed prefix lengths.
///
/// # Errors
/// Returns an error for truncation, invalid lengths, exhausted resources,
/// allocation failure, or arithmetic overflow.
///
/// # Source, version, history, and example
/// Source: `skeletons/ANY_uper.c`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: initial ANY framing.
/// Example: `decode_any_uper(&[0], &Limits::default())?`.
pub fn decode_any_uper(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    let mut reader = UperReader::new(input, limits)?;
    let value = read_any_uper(&mut reader)?;
    let consumed = reader.finish()?;
    Ok(Decoded {
        value,
        consumed_bits: consumed.consumed_bits,
        consumed_bytes: consumed.consumed_bytes,
    })
}

/// Read opaque ANY octets from a shared UPER cursor.
///
/// # Parameters and returns
/// `reader` supplies the cursor. Returns the decoded opaque octets.
///
/// # Errors
/// Returns an error for malformed or truncated input, limits, or allocation failure;
/// the cursor may be partially advanced.
///
/// # Source, version, history, and example
/// Source: `skeletons/ANY_uper.c`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: composable ANY framing.
/// Example: `read_any_uper(&mut reader)?`.
pub fn read_any_uper(reader: &mut UperReader<'_>) -> Result<Vec<u8>, Error> {
    let mut value = Vec::new();
    loop {
        let first =
            usize::try_from(reader.read_integer(0, 255)?).map_err(|_| Error::SizeOverflow)?;
        let (length, fragmented) = if first < 128 {
            (first, false)
        } else if first < 192 {
            let second =
                usize::try_from(reader.read_integer(0, 255)?).map_err(|_| Error::SizeOverflow)?;
            (((first & 0x3f) << 8) | second, false)
        } else {
            let units = first & 0x3f;
            if !(1..=4).contains(&units) {
                return Err(Error::InvalidEncoding {
                    reason: "invalid UPER fragment length",
                });
            }
            (units * 16384, true)
        };
        let fragment = reader.read_octets(length)?;
        let new_len = value.len().checked_add(length).ok_or(Error::SizeOverflow)?;
        value
            .try_reserve(length)
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: new_len,
            })?;
        value.extend_from_slice(&fragment);
        if !fragmented {
            break;
        }
    }
    Ok(value)
}

/// Encode a bounded primitive inside an unconstrained UPER string.
///
/// # Parameters and returns
/// `value` and inclusive `lower`/`upper` describe the inner integer;
/// `octets` selects OCTET STRING (otherwise BIT STRING); `limits` bounds work.
/// Returns the outer encoding with a short length determinant.
///
/// # Errors
/// Returns invalid bounds, out-of-range values, resource or allocation errors.
///
/// # Source, version, history, and example
/// Source: X.691 contents constraints and string length encoding.
/// Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: bounded primitive CONTAINING support. Example: encode value 2 in 0..2.
pub fn encode_containing_uper(
    value: i64,
    lower: i64,
    upper: i64,
    octets: bool,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let mut writer = UperWriter::new(limits)?;
    write_containing_uper(&mut writer, value, lower, upper, octets)?;
    writer.finish()
}

/// Append a primitive CONTAINING value to a shared UPER cursor.
///
/// # Parameters and returns
/// `writer` is the cursor; `value`, `lower`, and `upper` describe the inner
/// integer; `octets` selects OCTET STRING. Returns success when appended.
///
/// # Errors
/// Returns invalid bounds or value, resource, or allocation errors. The cursor
/// may be partially advanced on failure.
///
/// # Source, version, history, and example
/// Source: X.691 contents constraints. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: composed UPER values.
/// Example: `write_containing_uper(&mut writer, 1, 0, 2, true)?`.
pub fn write_containing_uper(
    writer: &mut UperWriter,
    value: i64,
    lower: i64,
    upper: i64,
    octets: bool,
) -> Result<(), Error> {
    let (_, width) = integer_shape(lower, upper)?;
    if width == 0 {
        return Err(Error::InvalidEncoding {
            reason: "zero-width contained value",
        });
    }
    let length = if octets { width.div_ceil(8) } else { width };
    writer.write_integer(
        i64::try_from(length).map_err(|_| Error::SizeOverflow)?,
        0,
        255,
    )?;
    writer.write_integer(value, lower, upper)?;
    if octets && width % 8 != 0 {
        let padding = 8 - width % 8;
        writer.write_integer(0, 0, (1_i64 << padding) - 1)?;
    }
    Ok(())
}

/// Decode a bounded primitive contained in an unconstrained UPER string.
///
/// # Parameters and returns
/// `input` supplies the outer prefix; `lower`/`upper` constrain the inner value;
/// `octets` selects OCTET STRING and `limits` bounds work. Returns the inner
/// value and outer prefix consumption.
///
/// # Errors
/// Rejects truncation, incorrect outer length, spare inner values, nonzero
/// octet padding, invalid bounds, and resource or allocation errors.
///
/// # Source, version, history, and example
/// Source: X.691 contents constraints and string length encoding.
/// Version: 2026-10-30. Responsible: asn1c maintainers.
/// History: bounded primitive CONTAINING support. Example: decode the value 2.
pub fn decode_containing_uper(
    input: &[u8],
    lower: i64,
    upper: i64,
    octets: bool,
    limits: &Limits,
) -> Result<Decoded<i64>, Error> {
    let mut reader = UperReader::new(input, limits)?;
    let value = read_containing_uper(&mut reader, lower, upper, octets)?;
    let consumed = reader.finish()?;
    Ok(Decoded {
        value,
        consumed_bits: consumed.consumed_bits,
        consumed_bytes: consumed.consumed_bytes,
    })
}

/// Read a primitive CONTAINING value from a shared UPER cursor.
///
/// # Parameters and returns
/// `reader` supplies the cursor; `lower` and `upper` constrain the inner value;
/// `octets` selects OCTET STRING. Returns the validated inner integer.
///
/// # Errors
/// Returns malformed input, bounds, allocation, or resource errors. The cursor
/// may be partially advanced on failure.
///
/// # Source, version, history, and example
/// Source: X.691 contents constraints. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: composed UPER values.
/// Example: `read_containing_uper(&mut reader, 0, 2, true)?`.
pub fn read_containing_uper(
    reader: &mut UperReader<'_>,
    lower: i64,
    upper: i64,
    octets: bool,
) -> Result<i64, Error> {
    let (_, width) = integer_shape(lower, upper)?;
    if width == 0 {
        return Err(Error::InvalidEncoding {
            reason: "zero-width contained value",
        });
    }
    let expected = if octets { width.div_ceil(8) } else { width };
    let first = usize::try_from(reader.read_integer(0, 255)?).map_err(|_| Error::SizeOverflow)?;
    let length = if first < 128 {
        first
    } else if first < 192 {
        let second =
            usize::try_from(reader.read_integer(0, 255)?).map_err(|_| Error::SizeOverflow)?;
        ((first & 0x3f) << 8) | second
    } else {
        return Err(Error::InvalidEncoding {
            reason: "invalid contained length",
        });
    };
    if length != expected {
        return Err(Error::InvalidEncoding {
            reason: "invalid contained length",
        });
    }
    let value = reader.read_integer(lower, upper)?;
    if octets && width % 8 != 0 {
        let padding = 8 - width % 8;
        if reader.read_integer(0, (1_i64 << padding) - 1)? != 0 {
            return Err(Error::InvalidEncoding {
                reason: "nonzero contained padding",
            });
        }
    }
    Ok(value)
}

/// Write a selected primitive in a UPER open-type octet envelope.
///
/// # Parameters and returns
/// `writer` supplies the shared cursor; `value`, `lower`, and `upper` describe
/// the selected INTEGER or BOOLEAN (0..1). Returns success on completion.
///
/// # Errors
/// Returns invalid bounds or values and resource errors. The cursor may be
/// partially advanced on failure.
///
/// # Source, version, history, and example
/// Source: `skeletons/uper_opentype.c`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: selected primitive OPEN TYPE.
/// Example: `write_open_primitive_uper(writer, 1, 0, 2)?`.
pub fn write_open_primitive_uper(
    writer: &mut UperWriter,
    value: i64,
    lower: i64,
    upper: i64,
) -> Result<(), Error> {
    let (_, width) = integer_shape(lower, upper)?;
    if width != 0 {
        return write_containing_uper(writer, value, lower, upper, true);
    }
    writer.write_integer(value, lower, upper)?;
    writer.write_integer(1, 0, 255)?;
    writer.write_integer(0, 0, 255)
}

/// Read a selected primitive from a UPER open-type octet envelope.
///
/// # Parameters and returns
/// `reader` supplies the shared cursor; `lower` and `upper` constrain the
/// selected value. Returns the validated INTEGER or BOOLEAN as an integer.
///
/// # Errors
/// Returns malformed envelope, invalid value, bounds, or resource errors.
/// The cursor may be partially advanced on failure.
///
/// # Source, version, history, and example
/// Source: `skeletons/uper_opentype.c`. Version: 2026-10-30.
/// Responsible: asn1c maintainers. History: selected primitive OPEN TYPE.
/// Example: `read_open_primitive_uper(reader, 0, 2)?`.
pub fn read_open_primitive_uper(
    reader: &mut UperReader<'_>,
    lower: i64,
    upper: i64,
) -> Result<i64, Error> {
    let (_, width) = integer_shape(lower, upper)?;
    if width != 0 {
        return read_containing_uper(reader, lower, upper, true);
    }
    let first = reader.read_integer(0, 255)?;
    let length = if first == 0x80 {
        reader.read_integer(0, 255)?
    } else {
        first
    };
    if length != 1 {
        return Err(Error::InvalidEncoding {
            reason: "invalid zero-width open type",
        });
    }
    let filler = reader.read_integer(0, 255)?;
    if filler != 0 {
        return Err(Error::InvalidEncoding {
            reason: "invalid zero-width open type",
        });
    }
    reader.read_integer(lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check the fallible borrowed BIT STRING adapter against valid and invalid storage.
    ///
    /// Inputs: packed octets and exact or inconsistent bit widths. Returns no
    /// value; assertions check ownership and validation errors. Errors:
    /// malformed values must return an error without a panic. Original source:
    /// `BitStringValue` storage invariants. Version/date: 2026-10-31.
    /// Responsible party: asn1c maintainers. History: generated BER adapter.
    /// Example: three meaningful bits occupy one octet with zero padding.
    #[test]
    fn borrowed_bit_string_adapter_validates_before_copy() {
        let original = [0xa0];
        let value = BitStringValue::from_bytes(&original, 3).expect("valid bits");
        assert_eq!(value.as_bytes(), original);
        assert_eq!(value.bit_len(), 3);
        assert!(BitStringValue::from_bytes(&original, 9).is_err());
        assert!(BitStringValue::from_bytes(&[0xa1], 3).is_err());
        assert!(BitStringValue::from_bytes(&[], usize::MAX).is_err());
    }

    /// Verify that fields share octets and do not receive per-field padding.
    ///
    /// Original source: composable UPER cursor contract. Version/date:
    /// 2026-10-30. Inputs: mixed BOOLEAN, NULL, and bounded INTEGER fields.
    /// Returns: no value; assertions verify packed bytes and cursor counts.
    /// Errors: none expected. Responsible party: asn1c maintainers.
    /// History: initial cursor regression suite. Example: four mixed bits become `C0`.
    #[test]
    fn packs_mixed_fields_without_alignment() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer.write_boolean(true).expect("boolean");
        writer.write_null().expect("null");
        writer.write_integer(2, 0, 2).expect("integer");
        writer.write_boolean(false).expect("boolean");
        let encoded = writer.finish().expect("finish");
        assert_eq!(encoded.bytes, [0xC0]);
        assert_eq!(encoded.bit_len, 4);

        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        assert!(reader.read_boolean().expect("boolean"));
        reader.read_null().expect("null");
        assert_eq!(reader.read_integer(0, 2).expect("integer"), 2);
        assert!(!reader.read_boolean().expect("boolean"));
        let decoded = reader.finish().expect("finish");
        assert_eq!(decoded.consumed_bits, 4);
        assert_eq!(decoded.consumed_bytes, 1);
    }

    /// Verify zero-width complete framing and strict zero filler validation.
    ///
    /// Original source: complete UPER zero-width behavior. Version/date:
    /// 2026-10-30. Inputs: empty/all-zero writer states and malformed filler.
    /// Returns: no value; assertions inspect exact filler behavior. Errors:
    /// malformed filler and missing byte are expected. Responsible party:
    /// asn1c maintainers. History: initial cursor regression suite.
    /// Example: NULL alone finishes as `[0]` with zero meaningful bits.
    #[test]
    fn zero_width_value_uses_one_checked_filler_byte() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer.write_null().expect("null");
        writer.write_integer(-3, -3, -3).expect("singleton integer");
        let encoded = writer.finish().expect("finish");
        assert_eq!(encoded.bytes, [0]);
        assert_eq!(encoded.bit_len, 0);

        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        reader.read_null().expect("null");
        assert_eq!(reader.read_integer(-3, -3).expect("integer"), -3);
        assert_eq!(reader.finish().expect("finish").consumed_bytes, 1);

        let reader = UperReader::new(&[1], &limits).expect("reader");
        assert!(matches!(
            reader.finish(),
            Err(Error::InvalidEncoding { .. })
        ));
        let reader = UperReader::new(&[], &limits).expect("reader");
        assert!(matches!(reader.finish(), Err(Error::NeedMoreBytes { .. })));
    }

    /// Verify exact cumulative work and output byte ceilings across fields.
    ///
    /// Original source: cursor operation-wide limit contract. Version/date:
    /// 2026-10-30. Inputs: exact and one-under budgets. Returns: no value;
    /// assertions validate the boundary and typed errors. Errors: one work and
    /// one output limit are expected. Responsible party: asn1c maintainers.
    /// History: initial cursor regression suite. Example: a BOOLEAN costs 9.
    #[test]
    fn enforces_exact_cumulative_budgets() {
        let exact = Limits {
            max_input_bytes: 1,
            max_output_bytes: 1,
            max_work_bits: 18,
        };
        let mut writer = UperWriter::new(&exact).expect("writer");
        writer.write_boolean(true).expect("first field");
        writer.write_boolean(false).expect("second field");
        assert_eq!(writer.finish().expect("finish").bytes, [0x80]);

        let tight_work = Limits {
            max_work_bits: 17,
            ..exact
        };
        let mut writer = UperWriter::new(&tight_work).expect("writer");
        writer.write_boolean(true).expect("first field");
        assert!(matches!(
            writer.write_boolean(false),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 18,
                ..
            })
        ));

        let tight_output = Limits {
            max_output_bytes: 1,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&tight_output).expect("writer");
        for _ in 0..8 {
            writer.write_boolean(false).expect("first octet");
        }
        assert!(matches!(
            writer.write_boolean(true),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                requested: 2,
                ..
            })
        ));
    }

    /// Verify singleton, ordinary, and full-width signed INTEGER round trips.
    ///
    /// Original source: constrained UPER INTEGER contract. Version/date:
    /// 2026-10-30. Inputs: singleton and full i64 ranges. Returns: no value;
    /// assertions compare decoded values. Errors: none expected. Responsible
    /// party: asn1c maintainers. History: initial cursor regression suite.
    /// Example: the full i64 range occupies 64 bits.
    #[test]
    fn supports_bounded_integer_shapes() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer
            .write_integer(i64::MIN, i64::MIN, i64::MAX)
            .expect("integer");
        writer.write_integer(5, 5, 5).expect("singleton");
        let encoded = writer.finish().expect("finish");
        assert_eq!(encoded.bit_len, 64);

        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        assert_eq!(
            reader.read_integer(i64::MIN, i64::MAX).expect("integer"),
            i64::MIN
        );
        assert_eq!(reader.read_integer(5, 5).expect("singleton"), 5);
        assert_eq!(reader.finish().expect("finish").consumed_bits, 64);
    }

    /// Verify invalid bounds, out-of-range values, spare codes, and truncation.
    ///
    /// Original source: bounded constrained INTEGER validation. Version/date:
    /// 2026-10-30. Inputs: invalid constraints and malformed bit prefixes.
    /// Returns: no value; assertions check typed failures. Errors: all tested
    /// failures are expected. Responsible party: asn1c maintainers. History:
    /// initial cursor regression suite. Example: `11` is spare for range 0..=2.
    #[test]
    fn rejects_invalid_or_incomplete_fields() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        assert!(matches!(
            writer.write_integer(2, 3, 1),
            Err(Error::InvalidBounds { .. })
        ));
        assert!(matches!(
            writer.write_integer(3, 0, 2),
            Err(Error::ValueOutOfRange { .. })
        ));

        let mut spare = UperReader::new(&[0xC0], &limits).expect("reader");
        assert!(matches!(
            spare.read_integer(0, 2),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(spare.read_boolean().expect("state unchanged"));
        assert_eq!(spare.read_integer(0, 2).expect("remaining bits"), 2);

        let mut truncated = UperReader::new(&[], &limits).expect("reader");
        assert!(matches!(
            truncated.read_boolean(),
            Err(Error::NeedMoreBits { .. })
        ));
    }

    /// Ensure repeated zero-width fields cannot bypass the work ceiling.
    ///
    /// Original source: cumulative per-operation work contract. Version/date:
    /// 2026-10-30. Inputs: many NULL field attempts under a finite limit.
    /// Returns: no value; assertions verify the first over-budget field fails.
    /// Errors: one work-limit error is expected. Responsible party: asn1c
    /// maintainers. History: initial cursor regression suite. Example: each
    /// zero-width field still incurs eight work units.
    #[test]
    fn many_zero_width_fields_are_bounded() {
        let limits = Limits {
            max_work_bits: 8 * 100,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&limits).expect("writer");
        for _ in 0..100 {
            writer.write_null().expect("within budget");
        }
        assert!(matches!(
            writer.write_null(),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 808,
                ..
            })
        ));

        let mut reader = UperReader::new(&[0], &limits).expect("reader");
        for _ in 0..100 {
            reader.read_null().expect("within budget");
        }
        assert!(matches!(
            reader.read_null(),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 808,
                ..
            })
        ));
    }

    /// Verify complete input byte limits are checked at construction time.
    ///
    /// Original source: cursor input-budget contract. Version/date:
    /// 2026-10-30. Inputs: a two-byte slice under a one-byte ceiling. Returns:
    /// no value; assertions inspect the resource and requested size. Errors:
    /// input-limit failure is expected. Responsible party: asn1c maintainers.
    /// History: initial cursor regression suite. Example: suffix bytes count.
    #[test]
    fn input_limit_applies_to_the_entire_slice_once() {
        let limits = Limits {
            max_input_bytes: 1,
            ..Limits::default()
        };
        assert!(matches!(
            UperReader::new(&[0x80, 0], &limits),
            Err(Error::LimitExceeded {
                resource: Resource::InputBytes,
                requested: 2,
                ..
            })
        ));
    }

    /// Verify checked bit-length rounding rejects arithmetic overflow.
    ///
    /// Original source: bounded bit-length arithmetic. Version/date:
    /// 2026-10-30. Inputs: the largest representable `usize`. Returns: no
    /// value; assertion checks `SizeOverflow`. Errors: overflow is expected.
    /// Responsible party: asn1c maintainers. History: initial cursor suite.
    /// Example: a maximum bit count cannot be rounded to bytes safely.
    #[test]
    fn rejects_bit_count_rounding_overflow() {
        assert!(matches!(
            encoded_byte_len(usize::MAX),
            Err(Error::SizeOverflow)
        ));
    }

    /// Verify fixed-size strings share cross-byte positions with other fields.
    ///
    /// Original source: composable X.691 UPER string contract. Version/date:
    /// 2026-10-30. Inputs: one BOOLEAN, two octets, and five string bits.
    /// Returns: no value; assertions check packed bytes and decoded fields.
    /// Errors: none expected. Responsible party: asn1c maintainers.
    /// History: added with fixed-size cursor strings. Example: 22 bits pack
    /// into `[0xD2, 0x9E, 0x58]` without field alignment.
    #[test]
    fn packs_fixed_strings_across_byte_boundaries() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer.write_boolean(true).expect("boolean");
        writer.write_octets(&[0xA5, 0x3C], 2).expect("octets");
        writer.write_bit_string(&[0xB0], 5).expect("bits");
        let encoded = writer.finish().expect("finish");
        assert_eq!(encoded.bytes, [0xD2, 0x9E, 0x58]);
        assert_eq!(encoded.bit_len, 22);

        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        assert!(reader.read_boolean().expect("boolean"));
        assert_eq!(reader.read_octets(2).expect("octets"), [0xA5, 0x3C]);
        assert_eq!(reader.read_bit_string(5).expect("bits"), [0xB0]);
        let decoded = reader.finish().expect("finish");
        assert_eq!(decoded.consumed_bits, 22);
        assert_eq!(decoded.consumed_bytes, 3);
    }

    /// Verify empty fixed-size strings consume work but no wire bits.
    ///
    /// Original source: cursor zero-width field contract. Version/date:
    /// 2026-10-30. Inputs: empty OCTET STRING and BIT STRING fields.
    /// Returns: no value; assertions inspect filler and state accounting.
    /// Errors: none expected. Responsible party: asn1c maintainers.
    /// History: added with fixed-size cursor strings. Example: each empty
    /// field costs eight work units and the complete value has one filler byte.
    #[test]
    fn accepts_zero_length_strings() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer.write_octets(&[], 0).expect("empty octets");
        writer.write_bit_string(&[], 0).expect("empty bits");
        assert_eq!(writer.work_used, 16);
        let encoded = writer.finish().expect("finish");
        assert_eq!(encoded.bytes, [0]);
        assert_eq!(encoded.bit_len, 0);

        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        assert_eq!(reader.read_octets(0).expect("empty octets"), []);
        assert_eq!(reader.read_bit_string(0).expect("empty bits"), []);
        assert_eq!(reader.work_used, 16);
        assert_eq!(reader.finish().expect("finish").consumed_bits, 0);
    }

    /// Verify malformed string inputs leave writer cursor and work state intact.
    ///
    /// Original source: fixed-size ASN.1 string validation. Version/date:
    /// 2026-10-30. Inputs: wrong OCTET STRING size, wrong BIT STRING storage,
    /// and nonzero unused trailing bits. Returns: no value; assertions inspect
    /// state and a subsequent valid encoding. Errors: validation errors are
    /// expected. Responsible party: asn1c maintainers. History: added with
    /// fixed-size cursor strings. Example: a 3-bit value must have five low
    /// zero bits in its final octet.
    #[test]
    fn rejects_malformed_writer_strings_without_state_changes() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        assert!(matches!(
            writer.write_octets(&[0xAA], 2),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            writer.write_bit_string(&[], 3),
            Err(Error::InvalidEncoding { .. })
        ));
        assert!(matches!(
            writer.write_bit_string(&[0xA1], 3),
            Err(Error::InvalidEncoding { .. })
        ));
        assert_eq!(writer.bit_len, 0);
        assert_eq!(writer.work_used, 0);

        writer.write_bit_string(&[0xA0], 3).expect("valid bits");
        let encoded = writer.finish().expect("finish");
        assert_eq!(encoded.bytes, [0xA0]);
        assert_eq!(encoded.bit_len, 3);
    }

    /// Verify truncated reads do not advance either reader state variable.
    ///
    /// Original source: fixed-size UPER string decoding. Version/date:
    /// 2026-10-30. Inputs: one byte consumed partly, then an overlong octet
    /// request. Returns: no value; assertions validate retry and final offset.
    /// Errors: one `NeedMoreBits` is expected. Responsible party: asn1c
    /// maintainers. History: added with fixed-size cursor strings. Example:
    /// seven remaining bits can still be read after the failed octet request.
    #[test]
    fn truncated_string_read_preserves_reader_state() {
        let limits = Limits::default();
        let mut reader = UperReader::new(&[0xA0], &limits).expect("reader");
        assert!(reader.read_boolean().expect("boolean"));
        let prior_work = reader.work_used;
        assert!(matches!(
            reader.read_octets(1),
            Err(Error::NeedMoreBits {
                required_bits: 9,
                available_bits: 8
            })
        ));
        assert_eq!(reader.bit_offset, 1);
        assert_eq!(reader.work_used, prior_work);
        assert_eq!(reader.read_bit_string(7).expect("remaining bits"), [0x40]);
        assert_eq!(reader.finish().expect("finish").consumed_bits, 8);
    }

    /// Verify string fields charge payload bits plus eight units per field.
    ///
    /// Original source: cursor operation-wide work and output ceilings.
    /// Version/date: 2026-10-30. Inputs: exact and under-budget bit strings,
    /// plus a cross-byte output attempt. Returns: no value; assertions inspect
    /// typed errors and unchanged state. Errors: work/output limits expected.
    /// Responsible party: asn1c maintainers. History: added with fixed-size
    /// cursor strings. Example: a five-bit field costs thirteen work units.
    #[test]
    fn string_fields_enforce_work_and_output_budgets() {
        let exact_work = Limits {
            max_work_bits: 13,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&exact_work).expect("writer");
        writer
            .write_bit_string(&[0xA0], 5)
            .expect("exact work budget");
        assert_eq!(writer.work_used, 13);

        let tight_work = Limits {
            max_work_bits: 12,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&tight_work).expect("writer");
        assert!(matches!(
            writer.write_bit_string(&[0xA0], 5),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 13,
                ..
            })
        ));
        assert_eq!(writer.bit_len, 0);
        assert_eq!(writer.work_used, 0);

        let tight_output = Limits {
            max_output_bytes: 1,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&tight_output).expect("writer");
        writer.write_boolean(true).expect("first bit");
        assert!(matches!(
            writer.write_octets(&[0xFF], 1),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                requested: 2,
                ..
            })
        ));
        assert_eq!(writer.bit_len, 1);
        assert_eq!(writer.work_used, 9);

        let tight_reader = Limits {
            max_work_bits: 12,
            ..Limits::default()
        };
        let mut reader = UperReader::new(&[0xA0], &tight_reader).expect("reader");
        assert!(matches!(
            reader.read_bit_string(5),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                requested: 13,
                ..
            })
        ));
        assert_eq!(reader.bit_offset, 0);
        assert_eq!(reader.work_used, 0);
    }

    /// Verify string width arithmetic rejects unrepresentable values.
    ///
    /// Original source: checked cursor size arithmetic. Version/date:
    /// 2026-10-30. Inputs: maximum `usize` bit and octet lengths.
    /// Returns: no value; assertions inspect `SizeOverflow`. Errors: overflow
    /// is expected. Responsible party: asn1c maintainers. History: added with
    /// fixed-size cursor strings. Example: `bit_storage_len(usize::MAX)` fails.
    #[test]
    fn rejects_string_size_overflow() {
        assert!(matches!(
            bit_storage_len(usize::MAX),
            Err(Error::SizeOverflow)
        ));
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        assert!(matches!(
            writer.write_octets(&[], usize::MAX),
            Err(Error::SizeOverflow)
        ));
        let mut reader = UperReader::new(&[], &limits).expect("reader");
        assert!(matches!(
            reader.read_octets(usize::MAX),
            Err(Error::SizeOverflow)
        ));
        assert_eq!(writer.bit_len, 0);
        assert_eq!(reader.bit_offset, 0);
    }

    /// Check the UPER reference vectors for SIZE(1..3) OCTET STRING values.
    ///
    /// Original source: X.691 constrained length determinant rules.
    /// Version/date: 2026-10-30. Inputs: A5 and A5 5A. Returns no value;
    /// assertions verify packed wire bytes, bit counts, and decode results.
    /// Errors: test setup failures panic through `expect`. Responsible party:
    /// asn1c maintainers. History: bounded octet cursor conformance.
    /// Example: A5 encodes as `29 40` over ten meaningful bits.
    #[test]
    fn bounded_octets_match_constrained_length_vectors() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer
            .write_bounded_octets(&[0xA5], 1, 3)
            .expect("one octet");
        let one = writer.finish().expect("encoding");
        assert_eq!(one.bytes, [0x29, 0x40]);
        assert_eq!(one.bit_len, 10);
        let mut reader = UperReader::new(&one.bytes, &limits).expect("reader");
        assert_eq!(reader.read_bounded_octets(1, 3).expect("decode"), [0xA5]);

        let mut writer = UperWriter::new(&limits).expect("writer");
        writer
            .write_bounded_octets(&[0xA5, 0x5A], 1, 3)
            .expect("two octets");
        let two = writer.finish().expect("encoding");
        assert_eq!(two.bytes, [0x69, 0x56, 0x80]);
        assert_eq!(two.bit_len, 18);
        let mut reader = UperReader::new(&two.bytes, &limits).expect("reader");
        assert_eq!(
            reader.read_bounded_octets(1, 3).expect("decode"),
            [0xA5, 0x5A]
        );
    }

    /// Check malformed bounded OCTET STRING input leaves cursor state intact.
    ///
    /// Original source: X.691 constrained length determinant validation.
    /// Version/date: 2026-10-30. Inputs: invalid bounds, spare length code,
    /// and truncated payload. Returns no value; assertions inspect errors and
    /// unchanged state variables. Errors: malformed inputs are expected.
    /// Responsible party: asn1c maintainers. History: bounded octet regression.
    /// Example: code `11` is spare when the size range is 1..3.
    #[test]
    fn bounded_octets_reject_malformed_values_atomically() {
        let limits = Limits::default();
        let mut writer = UperWriter::new(&limits).expect("writer");
        assert!(writer.write_bounded_octets(&[], 1, 3).is_err());
        assert!(writer.write_bounded_octets(&[0], 1, 65_536).is_err());
        assert_eq!(writer.bit_len, 0);
        assert_eq!(writer.work_used, 0);

        let mut spare = UperReader::new(&[0xC0, 0x00], &limits).expect("reader");
        assert!(spare.read_bounded_octets(1, 3).is_err());
        assert_eq!(spare.bit_offset, 0);
        assert_eq!(spare.work_used, 0);

        let mut truncated = UperReader::new(&[0x29], &limits).expect("reader");
        assert!(truncated.read_bounded_octets(1, 3).is_err());
        assert_eq!(truncated.bit_offset, 0);
        assert_eq!(truncated.work_used, 0);
    }

    /// Check bounded OCTET STRING output and work limits before state changes.
    ///
    /// Original source: operation-wide UPER resource accounting.
    /// Version/date: 2026-10-30. Inputs: SIZE(1..3), one octet, and ceilings
    /// below required output/work. Returns no value; assertions inspect errors.
    /// Errors: configured limit failures are expected. Responsible party:
    /// asn1c maintainers. History: bounded-octet limit regression.
    /// Example: one octet plus its 2-bit length costs 18 work units.
    #[test]
    fn bounded_octets_enforce_operation_limits() {
        let work_limited = Limits {
            max_work_bits: 17,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&work_limited).expect("writer");
        assert!(writer.write_bounded_octets(&[0xA5], 1, 3).is_err());
        assert_eq!(writer.bit_len, 0);
        assert_eq!(writer.work_used, 0);
        let mut reader = UperReader::new(&[0x29, 0x40], &work_limited).expect("reader");
        assert!(reader.read_bounded_octets(1, 3).is_err());
        assert_eq!(reader.bit_offset, 0);
        assert_eq!(reader.work_used, 0);

        let output_limited = Limits {
            max_output_bytes: 1,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&output_limited).expect("writer");
        assert!(writer.write_bounded_octets(&[0xA5], 1, 3).is_err());
        assert_eq!(writer.bit_len, 0);

        let input_limited = Limits {
            max_input_bytes: 1,
            ..Limits::default()
        };
        assert!(UperReader::new(&[0x29, 0x40], &input_limited).is_err());
    }

    /// Exercise deterministic one-bit mutations of complete bounded vectors.
    ///
    /// Original source: bounded OCTET STRING malformed-input audit.
    /// Version/date: 2026-10-30. Inputs: every meaningful bit flipped in the
    /// one- and two-octet SIZE(1..3) golden vectors. Returns no value; successful
    /// decodes must remain within bounds. Errors: mutations may be rejected.
    /// Responsible party: asn1c maintainers. History: deterministic fuzz-like
    /// bounded-size test. Example: mutate each bit in `29 40`.
    #[test]
    fn bounded_octet_single_bit_mutations_stay_bounded() {
        for (wire, bit_len) in [(&[0x29, 0x40][..], 10), (&[0x69, 0x56, 0x80][..], 18)] {
            for bit in 0..bit_len {
                let mut mutated = wire.to_vec();
                mutated[bit / 8] ^= 1 << (7 - (bit % 8));
                let mut reader = UperReader::new(&mutated, &Limits::default()).expect("reader");
                if let Ok(value) = reader.read_bounded_octets(1, 3) {
                    assert!((1..=3).contains(&value.len()));
                }
            }
        }
    }

    /// Verify bounded BIT STRING values retain non-octet bit lengths on wire.
    ///
    /// Original source: X.691 constrained BIT STRING length and payload rules.
    /// Version/date: 2026-10-30. Inputs: one- and three-bit SIZE(1..3) values
    /// plus a three-bit SIZE(2..4) value. Returns no value; assertions inspect
    /// bytes, bit counts, and decoded values. Errors: setup failures use `expect`.
    /// Responsible party: asn1c maintainers. History: bounded-bit cursor vectors.
    /// Example: 3 bits `101` encode as `A8` over five meaningful bits.
    #[test]
    fn bounded_bit_strings_match_constrained_length_vectors() {
        let limits = Limits::default();
        let one_bit = BitStringValue::new(vec![0x80], 1).expect("one bit");
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer
            .write_bounded_bit_string(&one_bit, 1, 3)
            .expect("encode one bit");
        let encoded = writer.finish().expect("encoding");
        assert_eq!(encoded.bytes, [0x20]);
        assert_eq!(encoded.bit_len, 3);
        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        assert_eq!(
            reader.read_bounded_bit_string(1, 3).expect("decode"),
            one_bit
        );

        let three_bits = BitStringValue::new(vec![0xA0], 3).expect("three bits");
        let mut writer = UperWriter::new(&limits).expect("writer");
        writer
            .write_bounded_bit_string(&three_bits, 1, 3)
            .expect("encode three bits");
        let encoded = writer.finish().expect("encoding");
        assert_eq!(encoded.bytes, [0xA8]);
        assert_eq!(encoded.bit_len, 5);
        let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
        assert_eq!(
            reader.read_bounded_bit_string(1, 3).expect("decode"),
            three_bits
        );
    }

    /// Verify bounded BIT STRING rejects malformed lengths and input atomically.
    ///
    /// Original source: X.691 constrained length validation.
    /// Version/date: 2026-10-30. Inputs: spare code, truncated payload,
    /// malformed value storage, and invalid bounds. Returns no value;
    /// assertions inspect errors and unchanged cursor/work state.
    /// Errors: all malformed inputs are expected. Responsible party: asn1c
    /// maintainers. History: bounded-bit rejection coverage. Example: `11` is
    /// spare for SIZE(1..3).
    #[test]
    fn bounded_bit_strings_reject_malformed_values_atomically() {
        assert!(BitStringValue::new(vec![0xA1], 3).is_err());
        assert!(BitStringValue::new(vec![0x80], 9).is_err());
        assert!(BitStringValue::new(vec![], usize::MAX).is_err());
        let empty = BitStringValue::new(vec![], 0).expect("empty");
        let mut writer = UperWriter::new(&Limits::default()).expect("writer");
        assert!(writer.write_bounded_bit_string(&empty, 1, 3).is_err());
        assert!(writer.write_bounded_bit_string(&empty, 1, 65_536).is_err());
        assert_eq!(writer.bit_len, 0);
        assert_eq!(writer.work_used, 0);

        let mut spare = UperReader::new(&[0xC0], &Limits::default()).expect("reader");
        assert!(spare.read_bounded_bit_string(1, 3).is_err());
        assert_eq!(spare.bit_offset, 0);
        assert_eq!(spare.work_used, 0);

        let mut truncated = UperReader::new(&[0x2B], &Limits::default()).expect("reader");
        for _ in 0..4 {
            truncated.read_boolean().expect("prefix boolean");
        }
        let prior_work = truncated.work_used;
        assert!(truncated.read_bounded_bit_string(1, 3).is_err());
        assert_eq!(truncated.bit_offset, 4);
        assert_eq!(truncated.work_used, prior_work);
    }

    /// Verify bounded BIT STRING operations enforce work and input ceilings.
    ///
    /// Original source: operation-wide UPER resource accounting.
    /// Version/date: 2026-10-30. Inputs: a three-bit value plus tight work and
    /// input budgets. Returns no value; assertions inspect resource errors and
    /// unchanged state. Errors: configured limits are expected. Responsible
    /// party: asn1c maintainers. History: bounded-bit limit coverage.
    /// Example: a five-bit field including its length costs thirteen units.
    #[test]
    fn bounded_bit_strings_enforce_operation_limits() {
        let value = BitStringValue::new(vec![0xA0], 3).expect("three bits");
        let work_limited = Limits {
            max_work_bits: 12,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&work_limited).expect("writer");
        assert!(writer.write_bounded_bit_string(&value, 1, 3).is_err());
        assert_eq!(writer.bit_len, 0);
        let mut reader = UperReader::new(&[0xA8], &work_limited).expect("reader");
        assert!(reader.read_bounded_bit_string(1, 3).is_err());
        assert_eq!(reader.bit_offset, 0);

        let output_limited = Limits {
            max_output_bytes: 0,
            ..Limits::default()
        };
        let mut writer = UperWriter::new(&output_limited).expect("writer");
        assert!(writer.write_bounded_bit_string(&value, 1, 3).is_err());
        assert_eq!(writer.bit_len, 0);

        let input_limited = Limits {
            max_input_bytes: 0,
            ..Limits::default()
        };
        assert!(UperReader::new(&[0xA8], &input_limited).is_err());
    }

    /// Exercise deterministic one-bit mutations of bounded BIT STRING vectors.
    ///
    /// Original source: bounded BIT STRING malformed-input audit.
    /// Version/date: 2026-10-30. Inputs: every meaningful bit flipped in two
    /// SIZE(1..3) golden encodings. Returns no value; accepted values must stay
    /// inside the declared bit range. Errors: mutations may be rejected.
    /// Responsible party: asn1c maintainers. History: deterministic fuzz-like
    /// bounded-bit test. Example: mutate each bit in `A8`.
    #[test]
    fn bounded_bit_single_bit_mutations_stay_bounded() {
        for (wire, wire_bits) in [(&[0x20][..], 3), (&[0xA8][..], 5)] {
            for bit in 0..wire_bits {
                let mut mutated = wire.to_vec();
                mutated[bit / 8] ^= 1 << (7 - (bit % 8));
                let mut reader = UperReader::new(&mutated, &Limits::default()).expect("reader");
                if let Ok(value) = reader.read_bounded_bit_string(1, 3) {
                    assert!((1..=3).contains(&value.bit_len()));
                    assert_eq!(
                        BitStringValue::new(value.as_bytes().to_vec(), value.bit_len()),
                        Ok(value)
                    );
                }
            }
        }
    }

    /// Exhaust every one-octet pattern at every short BIT STRING width.
    ///
    /// Parameters: none. Returns: no value; assertions check validation and
    /// round trips. Errors: nonzero unused bits must be rejected. Original
    /// source: deterministic mutation coverage for unaligned X.691 bit copy.
    /// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
    /// History: fixed string cursor fuzz-style regression. Example: all 256
    /// byte patterns are tried at each width from one through eight bits.
    #[test]
    fn exhaustive_short_bit_string_patterns() {
        let limits = Limits::default();
        for width in 1..=8 {
            let unused_mask = if width == 8 {
                0
            } else {
                (1_u8 << (8 - width)) - 1
            };
            for raw in u8::MIN..=u8::MAX {
                let mut writer = UperWriter::new(&limits).expect("writer");
                writer.write_boolean(true).expect("prefix");
                let result = writer.write_bit_string(&[raw], width);
                if raw & unused_mask != 0 {
                    assert!(matches!(result, Err(Error::InvalidEncoding { .. })));
                    continue;
                }
                result.expect("valid bits");
                writer.write_boolean(false).expect("suffix");
                let encoded = writer.finish().expect("complete value");
                let mut reader = UperReader::new(&encoded.bytes, &limits).expect("reader");
                assert!(reader.read_boolean().expect("prefix"));
                assert_eq!(reader.read_bit_string(width).expect("bits"), [raw]);
                assert!(!reader.read_boolean().expect("suffix"));
                assert_eq!(reader.finish().expect("complete").consumed_bits, width + 2);
            }
        }
    }
}
