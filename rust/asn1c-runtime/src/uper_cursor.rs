//! Stateful bit cursors for composing one bounded UPER value.
//!
//! `UperWriter` and `UperReader` append or consume primitive BOOLEAN, NULL,
//! and finite bounded signed INTEGER fields in one continuous bit stream.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
