//! Checked BER parsing and DER/CER codecs for ENUMERATED and string primitives.
//!
//! Original source: X.690 BER/DER/CER rules and asn1c runtime behavior.
//! Version/date: first expansion, 2026-10-31. Responsible party: asn1c
//! maintainers. Example: `decode_octet_string_ber(input, &Limits::default())?`.

use crate::{BitStringValue, Decoded, Encoded, Error, Limits, Resource};

/// Maximum constructed-TLV nesting accepted by this parser.
/// Initial fixed cap aligned with the C codec's `ASN_STACK_OVERFLOW_LIMIT` (30).
const MAX_DEPTH: usize = 30;
/// Maximum CER content octets in a primitive string value or fragment.
const CER_FRAGMENT_MAX: usize = 1000;
const TAG_BIT_STRING: u64 = 3;
const TAG_OCTET_STRING: u64 = 4;
const TAG_ENUMERATED: u64 = 10;
const TAG_SEQUENCE: u64 = 16;
const TAG_BOOLEAN: u64 = 1;
const TAG_INTEGER: u64 = 2;
const TAG_NULL: u64 = 5;
const MAX_SEQUENCE_FIELDS: usize = 6;

/// Canonical encoding rule used for one generated record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordEncoding {
    /// Encode the outer SEQUENCE with a minimal definite length.
    Der,
    /// Encode the outer SEQUENCE with indefinite length and EOC.
    Cer,
}

/// Shared resource accounting for one generated BER/DER/CER record operation.
///
/// A context is created once for an encode or decode operation and may be
/// reused for strict CER re-encoding and comparison. On decode, `max_output_bytes`
/// also caps aggregate retained OCTET/BIT STRING payload storage.
pub struct RecordContext {
    /// Copied caller ceilings for this complete operation.
    limits: Limits,
    /// Cumulative work; this is a state variable.
    work_used: usize,
    /// Retained decoded string storage; this is a state variable.
    retained_bytes: usize,
}

/// One field header and content span in a flat SEQUENCE.
#[derive(Clone, Copy)]
struct FieldSpan {
    /// Universal tag number of the current field.
    tag: u64,
    /// First identifier byte in caller input.
    tlv_start: usize,
    /// Exclusive encoded field end in caller input.
    tlv_end: usize,
    /// Whether the field uses constructed encoding.
    constructed: bool,
    /// First content byte in caller input.
    content_start: usize,
    /// Exclusive content end in caller input.
    content_end: usize,
}

/// Encode direct fields into one bounded SEQUENCE operation.
pub struct SequenceWriter<'context> {
    /// Encoding form selected for the outer record.
    rule: RecordEncoding,
    /// Shared operation limits and work budget.
    context: &'context mut RecordContext,
    /// Complete output buffer with outer header placeholder; state variable.
    bytes: Vec<u8>,
    /// Bit mask of emitted universal tags; state variable.
    seen_mask: u8,
}

/// Read fields from one BER SEQUENCE prefix under a shared operation budget.
pub struct SequenceReader<'input, 'tags, 'context> {
    /// Complete caller input, including any suffix; state variable.
    input: &'input [u8],
    /// Schema field tags in declaration order.
    expected_tags: &'tags [u64],
    /// Shared operation limits and work budget.
    context: &'context mut RecordContext,
    /// Definite outer content end, or input end for indefinite form.
    content_bound: usize,
    /// Whether the outer SEQUENCE uses indefinite length.
    indefinite: bool,
    /// Next child candidate offset; state variable.
    cursor: usize,
    /// Expected tag index of the last child; state variable.
    last_tag_index: Option<usize>,
    /// Current child span awaiting a typed reader; state variable.
    current: Option<FieldSpan>,
    /// Exact consumed end once the outer boundary has been reached; state variable.
    consumed_end: Option<usize>,
}

impl RecordContext {
    /// Create one operation context with a copy of the caller's ceilings.
    ///
    /// # Parameters and returns
    /// `limits` supplies whole-input, complete-output, and cumulative-work
    /// maxima. Returns an unused context ready for one record operation.
    ///
    /// # Errors
    /// This constructor cannot fail and raises no exception.
    ///
    /// # Source, version, history, example
    /// Source: bounded record-operation policy. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `let mut context = RecordContext::new(&limits);`.
    #[must_use]
    pub const fn new(limits: &Limits) -> Self {
        Self {
            limits: *limits,
            work_used: 0,
            retained_bytes: 0,
        }
    }

    /// Compare a strict CER prefix with its canonical re-encoding.
    ///
    /// # Parameters
    /// `input` is the complete available slice; `consumed` is the decoded
    /// record prefix size; `canonical` is its CER encoding. Parsing and
    /// encoding must already have charged this same context.
    ///
    /// # Returns
    /// `Ok(())` when exactly the consumed prefix matches canonical bytes.
    ///
    /// # Errors
    /// Returns `InvalidEncoding`, checked-size, or work-limit errors.
    /// It raises no exception.
    ///
    /// # Source, version, history, example
    /// Source: X.690 strict CER via decode/re-encode comparison.
    /// Version: 2026-10-31. Responsible: asn1c maintainers.
    /// History: shared-budget record decoding. Example: `context.verify_canonical(input, n, bytes)?`.
    pub fn verify_canonical(
        &mut self,
        input: &[u8],
        consumed: usize,
        canonical: &[u8],
    ) -> Result<(), Error> {
        ensure_canonical(
            input,
            consumed,
            canonical,
            &mut self.work_used,
            &self.limits,
        )
    }

    /// Charge newly visited wire octets against this operation.
    ///
    /// # Parameters and returns
    /// `bytes` is work not charged by another pass; returns success if the
    /// cumulative work stays within this context's ceiling.
    ///
    /// # Errors
    /// Returns `SizeOverflow` or a work `LimitExceeded` error.
    ///
    /// # Source, version, history, example
    /// Source: runtime cumulative work budget. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: record contexts.
    /// Example: `context.charge(1)?` charges one octet of work.
    fn charge(&mut self, bytes: usize) -> Result<(), Error> {
        charge_work(&mut self.work_used, bytes, &self.limits)
    }

    /// Return output limits remaining for one retained-string decode operation.
    ///
    /// # Parameters and returns
    /// Returns a copy with the retained-storage ceiling; work is charged
    /// directly to this context during parsing.
    ///
    /// # Errors
    /// Returns `SizeOverflow` if the retained counter is inconsistent.
    ///
    /// # Source, version, history, example
    /// Source: bounded sequence scratch policy. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: shared string fields.
    /// Example: `let remaining = context.remaining_decode_limits()?`.
    fn remaining_decode_limits(&self) -> Result<Limits, Error> {
        let mut remaining = self.limits;
        remaining.max_output_bytes = self
            .limits
            .max_output_bytes
            .checked_sub(self.retained_bytes)
            .ok_or(Error::SizeOverflow)?;
        Ok(remaining)
    }

    /// Retain decoded field bytes after a decoder has checked the remaining cap.
    ///
    /// # Parameters and returns
    /// `bytes` is the field's owned payload length; returns success when the
    /// cumulative retained storage stays within `max_output_bytes`.
    ///
    /// # Errors
    /// Returns checked-size or output-limit errors.
    ///
    /// # Source, version, history, example
    /// Source: sequence decoded-storage policy. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: bounded string fields.
    /// Example: `context.retain_decoded(owned.len())?`.
    fn retain_decoded(&mut self, bytes: usize) -> Result<(), Error> {
        let total = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or(Error::SizeOverflow)?;
        check(Resource::OutputBytes, total, self.limits.max_output_bytes)?;
        self.retained_bytes = total;
        Ok(())
    }

    /// Check projected complete record output before growing the buffer.
    ///
    /// # Parameters and returns
    /// `bytes` is the projected encoded record size; returns success if allowed.
    ///
    /// # Errors
    /// Returns output `LimitExceeded`; it raises no exception.
    ///
    /// # Source, version, history, example
    /// Source: bounded record output policy. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: record contexts.
    /// Example: `context.check_output(next_size)?`.
    const fn check_output(&self, bytes: usize) -> Result<(), Error> {
        check(Resource::OutputBytes, bytes, self.limits.max_output_bytes)
    }
}

impl SequenceWriter<'_> {
    /// Begin one SEQUENCE encoder using the shared operation context.
    ///
    /// # Parameters
    /// `rule` selects DER definite or CER indefinite outer framing; `context`
    /// owns the cumulative work ceiling and complete output limit.
    ///
    /// # Returns
    /// A writer ready to receive its declaration-order primitive fields or strings.
    ///
    /// # Errors
    /// Returns output-limit, work-limit, or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SEQUENCE framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `SequenceWriter::new(RecordEncoding::Der, &mut context)?`.
    pub fn new(
        rule: RecordEncoding,
        context: &mut RecordContext,
    ) -> Result<SequenceWriter<'_>, Error> {
        let minimum_size = if rule == RecordEncoding::Cer { 4 } else { 2 };
        context.check_output(minimum_size)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(2)
            .map_err(|_| Error::AllocationFailed { requested_bytes: 2 })?;
        bytes.extend_from_slice(&[0x30, if rule == RecordEncoding::Cer { 0x80 } else { 0 }]);
        if rule == RecordEncoding::Cer {
            context.charge(2)?;
        } else {
            context.charge(1)?;
        }
        Ok(SequenceWriter {
            rule,
            context,
            bytes,
            seen_mask: 0,
        })
    }

    /// Append one canonical BOOLEAN field with its universal tag.
    ///
    /// # Parameters and returns
    /// `value` is the ASN.1 BOOLEAN; returns success after appending its TLV.
    ///
    /// # Errors
    /// Returns duplicate-field, output/work-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 DER/CER BOOLEAN content. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `writer.write_boolean(true)?`.
    pub fn write_boolean(&mut self, value: bool) -> Result<(), Error> {
        let content = [if value { 0xff } else { 0 }];
        self.write_field(TAG_BOOLEAN, &content, 0x01)
    }

    /// Append one empty NULL field with its universal tag.
    ///
    /// # Parameters and returns
    /// No value parameter is needed; returns success after appending `05 00`.
    ///
    /// # Errors
    /// Returns duplicate-field, output/work-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 NULL content. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `writer.write_null()?`.
    pub fn write_null(&mut self) -> Result<(), Error> {
        self.write_field(TAG_NULL, &[], 0x10)
    }

    /// Append one minimally encoded bounded signed INTEGER field.
    ///
    /// # Parameters
    /// `value` is the signed value; `lower` and `upper` are inclusive schema
    /// bounds. The writer's context covers encoding and the complete record.
    ///
    /// # Returns
    /// `Ok(())` after appending a shortest two's-complement INTEGER TLV.
    ///
    /// # Errors
    /// Returns invalid bounds, out-of-range, duplicate-field, resource, size,
    /// or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 INTEGER content rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `writer.write_integer(-2, -4, 4)?`.
    pub fn write_integer(&mut self, value: i64, lower: i64, upper: i64) -> Result<(), Error> {
        crate::validate_integer(value, lower, upper)?;
        let full = value.to_be_bytes();
        let first = minimal_signed_start(full);
        self.write_field(TAG_INTEGER, &full[first..], 0x02)
    }

    /// Append one minimally encoded numeric ENUMERATED field.
    ///
    /// # Parameters and returns
    /// `value` is the generated variant's signed numeric representation.
    /// Returns success after writing a shortest universal tag 10 TLV.
    ///
    /// # Errors
    /// Returns duplicate-field, output/work-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 ENUMERATED content. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct record fields.
    /// Example: `writer.write_enumerated(-1)?`.
    pub fn write_enumerated(&mut self, value: i64) -> Result<(), Error> {
        let full = value.to_be_bytes();
        let first = minimal_signed_start(full);
        self.write_field(TAG_ENUMERATED, &full[first..], 0x20)
    }

    /// Append one bounded OCTET STRING using the selected record rule.
    ///
    /// # Parameters
    /// `value` is the payload; `lower` and `upper` are inclusive SIZE bounds.
    /// CER fragments values above 1000 content octets.
    ///
    /// # Returns
    /// `Ok(())` after appending the canonical child TLV or fragment sequence.
    ///
    /// # Errors
    /// Returns invalid bounds/SIZE, duplicate-field, resource, size, or
    /// allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 OCTET STRING DER/CER rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct record string fields.
    /// Example: `writer.write_octet_string(b"abc", 1, 8)?`.
    pub fn write_octet_string(
        &mut self,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        validate_size(value.len(), lower, upper)?;
        let field_size = octet_field_size(value.len(), self.rule)?;
        self.prepare_field(field_size, 0x08)?;
        match (self.rule, value.len() > CER_FRAGMENT_MAX) {
            (RecordEncoding::Cer, true) => {
                push(&mut self.bytes, &[0x24, 0x80], &self.context.limits)?;
                for fragment in value.chunks(CER_FRAGMENT_MAX) {
                    push_primitive(
                        &mut self.bytes,
                        TAG_OCTET_STRING,
                        fragment,
                        &self.context.limits,
                    )?;
                }
                push(&mut self.bytes, &[0, 0], &self.context.limits)?;
            }
            _ => push_primitive(
                &mut self.bytes,
                TAG_OCTET_STRING,
                value,
                &self.context.limits,
            )?,
        }
        self.seen_mask |= 0x08;
        Ok(())
    }

    /// Append one bounded BIT STRING using the selected record rule.
    ///
    /// # Parameters
    /// `bytes` stores packed bits; `bit_len` gives their meaningful width;
    /// `lower_bits` and `upper_bits` are inclusive SIZE bounds. CER fragments
    /// content above 1000 octets including each unused-count octet.
    ///
    /// # Returns
    /// `Ok(())` after appending the canonical child TLV or fragment sequence.
    ///
    /// # Errors
    /// Returns malformed storage/padding, invalid bounds/SIZE, duplicate-field,
    /// resource, size, or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BIT STRING DER/CER rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct record string fields.
    /// Example: `writer.write_bit_string(&[0xa0], 3, 1, 8)?`.
    pub fn write_bit_string(
        &mut self,
        bytes: &[u8],
        bit_len: usize,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<(), Error> {
        validate_packed_bits(bytes, bit_len)?;
        validate_size(bit_len, lower_bits, upper_bits)?;
        let unused = unused_bits(bit_len);
        let field_size = bit_field_size(bytes.len(), self.rule)?;
        self.prepare_field(field_size, 0x04)?;
        let content_len = bytes.len().checked_add(1).ok_or(Error::SizeOverflow)?;
        if self.rule == RecordEncoding::Cer && content_len > CER_FRAGMENT_MAX {
            push(&mut self.bytes, &[0x23, 0x80], &self.context.limits)?;
            let fragment_count = bytes.len().div_ceil(CER_FRAGMENT_MAX - 1);
            for (index, fragment) in bytes.chunks(CER_FRAGMENT_MAX - 1).enumerate() {
                let fragment_unused = if index + 1 == fragment_count {
                    unused
                } else {
                    0
                };
                push_bit_fragment(
                    &mut self.bytes,
                    fragment,
                    fragment_unused,
                    &self.context.limits,
                )?;
            }
            push(&mut self.bytes, &[0, 0], &self.context.limits)?;
        } else {
            push_bit_fragment(&mut self.bytes, bytes, unused, &self.context.limits)?;
        }
        self.seen_mask |= 0x04;
        Ok(())
    }

    /// Finalize the complete record and release the shared context borrow.
    ///
    /// # Parameters and returns
    /// `self` owns the accumulated fields. Returns complete DER/CER bytes and
    /// their octet-aligned wire-bit count.
    ///
    /// # Errors
    /// Returns output/work-limit, size, or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 definite DER and indefinite CER SEQUENCE framing.
    /// Version: 2026-10-31. Responsible: asn1c maintainers.
    /// History: flat record runtime API. Example: `writer.finish()?`.
    pub fn finish(mut self) -> Result<Encoded, Error> {
        match self.rule {
            RecordEncoding::Der => {
                let content_len = self.bytes.len().checked_sub(2).ok_or(Error::SizeOverflow)?;
                let length_len = length_size(content_len);
                let total_len = 1_usize
                    .checked_add(length_len)
                    .and_then(|n| n.checked_add(content_len))
                    .ok_or(Error::SizeOverflow)?;
                self.context.check_output(total_len)?;
                self.context.charge(length_len)?;
                if content_len >= 128 {
                    self.context.charge(content_len)?;
                }
                patch_der_length(&mut self.bytes, content_len)?;
            }
            RecordEncoding::Cer => {
                let total_len = self.bytes.len().checked_add(2).ok_or(Error::SizeOverflow)?;
                self.context.check_output(total_len)?;
                self.context.charge(2)?;
                push(&mut self.bytes, &[0, 0], &self.context.limits)?;
            }
        }
        finish(self.bytes, &self.context.limits)
    }

    /// Append a typed field after checking uniqueness and cumulative budgets.
    ///
    /// # Parameters
    /// `tag` is one supported universal field tag; `content` is its payload;
    /// `mask` identifies it in the duplicate-detection state.
    ///
    /// # Returns
    /// `Ok(())` after writing identifier, shortest length, and content.
    ///
    /// # Errors
    /// Returns duplicate-tag, output/work-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: shared bounded TLV writer. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: used by the public typed field methods.
    fn write_field(&mut self, tag: u64, content: &[u8], mask: u8) -> Result<(), Error> {
        let field_size = 1_usize
            .checked_add(length_size(content.len()))
            .and_then(|n| n.checked_add(content.len()))
            .ok_or(Error::SizeOverflow)?;
        self.prepare_field(field_size, mask)?;
        push_primitive(&mut self.bytes, tag, content, &self.context.limits)?;
        self.seen_mask |= mask;
        Ok(())
    }

    /// Check uniqueness, complete output, and work before a field is appended.
    ///
    /// # Parameters and returns
    /// `field_size` is the complete child TLV size; `mask` is its unique-tag
    /// bit. Returns the mask after checks.
    ///
    /// # Errors
    /// Returns duplicate-tag, size, output-limit, or work-limit errors.
    ///
    /// # Source, version, history, example
    /// Source: shared bounded TLV writer. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct string support.
    /// Example: called by each typed `write_*` method.
    fn prepare_field(&mut self, field_size: usize, mask: u8) -> Result<(), Error> {
        if self.seen_mask & mask != 0 {
            return Err(invalid(
                "flat SEQUENCE writer received a duplicate universal tag",
            ));
        }
        let content_size = self.bytes.len().checked_sub(2).ok_or(Error::SizeOverflow)?;
        let next_content = content_size
            .checked_add(field_size)
            .ok_or(Error::SizeOverflow)?;
        self.context
            .check_output(record_size(self.rule, next_content)?)?;
        let work_bytes = field_size.checked_add(1).ok_or(Error::SizeOverflow)?;
        self.context.charge(work_bytes)?;
        Ok(())
    }
}

impl<'input, 'tags, 'context> SequenceReader<'input, 'tags, 'context> {
    /// Start decoding one BER SEQUENCE prefix against declaration-order tags.
    ///
    /// # Parameters
    /// `input` is the full available slice; `expected_tags` lists up to six
    /// unique BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, or ENUMERATED
    /// universal tags in schema order; `context` supplies shared budgets.
    ///
    /// # Returns
    /// A cursor accepting definite or indefinite BER outer lengths.
    ///
    /// # Errors
    /// Returns input-limit, truncation, wrong-tag/form, duplicate-descriptor,
    /// depth, size, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER SEQUENCE framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `SequenceReader::new(input, &[1, 4, 10], &mut context)?`.
    pub fn new(
        input: &'input [u8],
        expected_tags: &'tags [u64],
        context: &'context mut RecordContext,
    ) -> Result<Self, Error> {
        check(
            Resource::InputBytes,
            input.len(),
            context.limits.max_input_bytes,
        )?;
        if expected_tags.len() > MAX_SEQUENCE_FIELDS {
            return Err(invalid("record reader supports at most six direct fields"));
        }
        for (index, tag) in expected_tags.iter().enumerate() {
            context.charge(1)?;
            if !matches!(
                *tag,
                TAG_BOOLEAN
                    | TAG_INTEGER
                    | TAG_BIT_STRING
                    | TAG_OCTET_STRING
                    | TAG_NULL
                    | TAG_ENUMERATED
            ) {
                return Err(invalid(
                    "SEQUENCE descriptor contains an unsupported field tag",
                ));
            }
            for previous in &expected_tags[..index] {
                context.charge(1)?;
                if previous == tag {
                    return Err(invalid("SEQUENCE descriptor tags must be unique"));
                }
            }
        }
        let work = &mut context.work_used;
        let header = parse_header(input, 0, input.len(), work, true, &context.limits)?;
        if header.class != 0 || header.tag != TAG_SEQUENCE || !header.constructed {
            return Err(invalid(
                "BER record is not a constructed universal SEQUENCE",
            ));
        }
        let length_octets = header.content - header.identifier_len;
        context.charge(length_octets)?;
        let (content_bound, indefinite) = if let Some(length) = header.length {
            let end = header
                .content
                .checked_add(length)
                .ok_or(Error::SizeOverflow)?;
            require(input, header.content, length, input.len())?;
            (end, false)
        } else {
            (input.len(), true)
        };
        Ok(Self {
            input,
            expected_tags,
            context,
            content_bound,
            indefinite,
            cursor: header.content,
            last_tag_index: None,
            current: None,
            consumed_end: None,
        })
    }

    /// Advance to the next field, returning its universal tag number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns `Some(tag)` for a field or `None` after the
    /// definite body or matching outer EOC has been consumed.
    ///
    /// # Errors
    /// Returns malformed child framing, unknown/duplicate/out-of-order tags,
    /// truncation, size, depth, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: BER SEQUENCE field traversal. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `while let Some(tag) = reader.next_field()? { ... }`.
    pub fn next_field(&mut self) -> Result<Option<u64>, Error> {
        if self.current.is_some() {
            return Err(invalid("SEQUENCE field must be decoded before advancing"));
        }
        if self.consumed_end.is_some() {
            return Ok(None);
        }
        if self.indefinite && is_eoc(self.input, self.cursor, self.input.len()) {
            self.context.charge(2)?;
            self.cursor = self.cursor.checked_add(2).ok_or(Error::SizeOverflow)?;
            self.consumed_end = Some(self.cursor);
            return Ok(None);
        }
        if !self.indefinite && self.cursor == self.content_bound {
            self.consumed_end = Some(self.cursor);
            return Ok(None);
        }
        let header = parse_header(
            self.input,
            self.cursor,
            self.content_bound,
            &mut self.context.work_used,
            true,
            &self.context.limits,
        )?;
        if header.class != 0 || header.tag == 0 {
            return Err(invalid(
                "SEQUENCE child tag is not a supported universal field",
            ));
        }
        let mut matching_index = None;
        for (index, tag) in self.expected_tags.iter().enumerate() {
            self.context.charge(1)?;
            if *tag == header.tag {
                matching_index = Some(index);
                break;
            }
        }
        let Some(index) = matching_index else {
            return Err(invalid("SEQUENCE contains an unknown field tag"));
        };
        if self
            .last_tag_index
            .is_some_and(|previous| index <= previous)
        {
            return Err(invalid(
                "SEQUENCE fields are duplicated or out of declaration order",
            ));
        }
        self.context.charge(1)?;
        let start = self.cursor;
        let end = scan(
            self.input,
            start,
            self.content_bound,
            1,
            &mut self.context.work_used,
            false,
            &self.context.limits,
        )?;
        let content_end = header
            .length
            .and_then(|length| header.content.checked_add(length))
            .unwrap_or_else(|| end.saturating_sub(2));
        self.current = Some(FieldSpan {
            tag: header.tag,
            tlv_start: start,
            tlv_end: end,
            constructed: header.constructed,
            content_start: header.content,
            content_end,
        });
        self.last_tag_index = Some(index);
        self.cursor = end;
        Ok(Some(header.tag))
    }

    /// Decode the current primitive BOOLEAN field and consume it.
    ///
    /// # Parameters and returns
    /// No parameters. Returns false for zero content and true for nonzero.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for a wrong/constructed tag or non-one-octet
    /// content, or a work-limit error. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER BOOLEAN. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `let enabled = reader.read_boolean()?;`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        let field = self.current_field(TAG_BOOLEAN)?;
        if field.constructed || field.content_end - field.content_start != 1 {
            return Err(invalid("BER BOOLEAN field must contain exactly one octet"));
        }
        self.context.charge(1)?;
        let value = self.input[field.content_start] != 0;
        self.current = None;
        Ok(value)
    }

    /// Decode the current primitive NULL field and consume it.
    ///
    /// # Parameters and returns
    /// No parameters. Returns unit for an empty NULL content.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for a wrong/constructed tag or nonempty
    /// content, or a work-limit error. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER NULL. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `reader.read_null()?;`.
    pub fn read_null(&mut self) -> Result<(), Error> {
        let field = self.current_field(TAG_NULL)?;
        if field.constructed || field.content_start != field.content_end {
            return Err(invalid("BER NULL field content must be empty"));
        }
        self.context.charge(1)?;
        self.current = None;
        Ok(())
    }

    /// Decode the current signed INTEGER field and validate its bounds.
    ///
    /// # Parameters
    /// `lower` and `upper` are the inclusive bounds declared for this field.
    ///
    /// # Returns
    /// The decoded signed integer.
    ///
    /// # Errors
    /// Returns invalid bounds, malformed/out-of-range content, field mismatch,
    /// value-out-of-range, or work-limit errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER INTEGER rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `reader.read_integer(0, 255)?`.
    pub fn read_integer(&mut self, lower: i64, upper: i64) -> Result<i64, Error> {
        crate::validate_integer(lower, lower, upper)?;
        let field = self.current_field(TAG_INTEGER)?;
        if field.constructed {
            return Err(invalid("BER INTEGER field must use primitive form"));
        }
        let contents = &self.input[field.content_start..field.content_end];
        self.context.charge(contents.len())?;
        let value = signed_value(contents)?;
        crate::validate_integer(value, lower, upper)?;
        self.current = None;
        Ok(value)
    }

    /// Decode the current primitive numeric ENUMERATED field.
    ///
    /// # Parameters and returns
    /// No parameters. Returns its signed i64 representation; generated code
    /// maps that number to a declared variant.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for a constructed, empty, or out-of-range
    /// value and work-limit errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER ENUMERATED rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct record fields.
    /// Example: `let variant_number = reader.read_enumerated()?`.
    pub fn read_enumerated(&mut self) -> Result<i64, Error> {
        let field = self.current_field(TAG_ENUMERATED)?;
        if field.constructed {
            return Err(invalid("BER ENUMERATED field must use primitive form"));
        }
        let content = &self.input[field.content_start..field.content_end];
        self.context.charge(content.len())?;
        let value = signed_value(content)?;
        self.current = None;
        Ok(value)
    }

    /// Decode and flatten the current bounded BER OCTET STRING field.
    ///
    /// # Parameters
    /// `lower` and `upper` are inclusive SIZE bounds. The current field may be
    /// primitive or constructed with definite/indefinite fragments.
    ///
    /// # Returns
    /// Owned concatenated payload bytes.
    ///
    /// # Errors
    /// Returns malformed BER, invalid SIZE, storage/output/work limits, or
    /// allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER OCTET STRING. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct record strings.
    /// Example: `let bytes = reader.read_octet_string(1, 32)?`.
    pub fn read_octet_string(&mut self, lower: usize, upper: usize) -> Result<Vec<u8>, Error> {
        validate_size_bounds(lower, upper)?;
        let field = self.current_field(TAG_OCTET_STRING)?;
        let encoded = &self.input[field.tlv_start..field.tlv_end];
        let limits = self.context.remaining_decode_limits()?;
        let decoded =
            decode_octet_ber_with_work(encoded, &limits, &mut self.context.work_used, Some(upper))?;
        if decoded.consumed_bytes != encoded.len() {
            return Err(invalid("OCTET STRING field has trailing encoded data"));
        }
        validate_size(decoded.value.len(), lower, upper)?;
        self.context.retain_decoded(decoded.value.len())?;
        self.current = None;
        Ok(decoded.value)
    }

    /// Decode and flatten the current bounded BER BIT STRING field.
    ///
    /// # Parameters
    /// `lower_bits` and `upper_bits` are inclusive SIZE bounds. The current
    /// field may be primitive or constructed with definite/indefinite fragments.
    ///
    /// # Returns
    /// A validated packed bit value with its exact meaningful bit length.
    ///
    /// # Errors
    /// Returns malformed BER, invalid SIZE, storage/output/work limits, or
    /// allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER BIT STRING. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct record strings.
    /// Example: `let bits = reader.read_bit_string(1, 32)?`.
    pub fn read_bit_string(
        &mut self,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<BitStringValue, Error> {
        validate_size_bounds(lower_bits, upper_bits)?;
        let field = self.current_field(TAG_BIT_STRING)?;
        let encoded = &self.input[field.tlv_start..field.tlv_end];
        let limits = self.context.remaining_decode_limits()?;
        let payload_cap = packed_storage_len(upper_bits);
        let decoded = decode_bit_ber_with_work(
            encoded,
            &limits,
            &mut self.context.work_used,
            Some(payload_cap),
        )?;
        if decoded.consumed_bytes != encoded.len() {
            return Err(invalid("BIT STRING field has trailing encoded data"));
        }
        validate_size(decoded.value.bit_len(), lower_bits, upper_bits)?;
        self.context
            .retain_decoded(decoded.value.as_bytes().len())?;
        self.current = None;
        Ok(decoded.value)
    }

    /// Finish traversal and return the exact SEQUENCE prefix consumption.
    ///
    /// # Parameters and returns
    /// Consumes `self`; returns unit with whole-prefix byte and bit counts.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` if a field or outer terminator remains unread.
    /// It also returns size overflow. No panic.
    ///
    /// # Source, version, history, example
    /// Source: BER prefix-decoder contract. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: `let span = reader.finish()?;`.
    pub fn finish(self) -> Result<Decoded<()>, Error> {
        if self.current.is_some() {
            return Err(invalid("SEQUENCE has a field that was not decoded"));
        }
        let end = self
            .consumed_end
            .ok_or_else(|| invalid("SEQUENCE reader did not reach its outer boundary"))?;
        let bits = end.checked_mul(8).ok_or(Error::SizeOverflow)?;
        Ok(Decoded {
            value: (),
            consumed_bits: bits,
            consumed_bytes: end,
        })
    }

    /// Return the current field only when it has the requested primitive tag.
    ///
    /// # Parameters and returns
    /// `tag` is the expected universal number. Returns the current field span.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when no field is pending or the tag differs.
    ///
    /// # Source, version, history, example
    /// Source: typed BER field dispatch. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: called by each typed `read_*` method.
    const fn current_field(&self, tag: u64) -> Result<FieldSpan, Error> {
        match &self.current {
            Some(field) if field.tag == tag => Ok(*field),
            Some(_) => Err(invalid("SEQUENCE field reader does not match current tag")),
            None => Err(invalid("SEQUENCE has no current field")),
        }
    }
}

/// Parsed BER identifier and length metadata.
struct Header {
    /// Identifier class, with zero for universal.
    class: u8,
    /// Constructed bit from the identifier.
    constructed: bool,
    /// Numeric tag, including high-tag form.
    tag: u64,
    /// Number of identifier octets as received, including permissive BER form.
    identifier_len: usize,
    /// First content octet.
    content: usize,
    /// Definite content length; `None` denotes constructed indefinite form.
    length: Option<usize>,
}

/// State used to validate unused bits across BIT STRING leaves.
struct BitState {
    /// Unused bits in the most recently appended fragment; state variable.
    unused: u8,
    /// Count of primitive leaves; state variable.
    fragments: usize,
}

/// Accumulated BIT STRING payload and final-fragment metadata.
struct BitAccumulator {
    /// Packed payload bytes collected so far; this is a state variable.
    bytes: Vec<u8>,
    /// Fragment padding/count metadata; this is a state variable.
    state: BitState,
}

/// Shared limits, work counter, and schema payload ceiling during flattening.
struct FlattenBudget<'limits, 'work> {
    /// Remaining global output and work ceilings.
    limits: &'limits Limits,
    /// Cumulative parser work; this is a state variable.
    work: &'work mut usize,
    /// Optional SIZE upper bound checked before payload appends.
    max_payload: Option<usize>,
}

/// Decode one BER ENUMERATED prefix to a signed numeric value.
///
/// # Parameters
/// `input` is an available prefix, possibly followed by unrelated bytes;
/// `limits` caps the entire input and consumed wire work.
///
/// # Returns
/// The signed numeric value and complete TLV prefix consumption.
///
/// # Errors
/// Returns truncation, malformed encoding, range, or limit errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 ENUMERATED/INTEGER rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first BER expansion.
/// Example: `decode_enumerated_ber(&[10, 1, 1], limits)?`.
pub fn decode_enumerated_ber(input: &[u8], limits: &Limits) -> Result<Decoded<i64>, Error> {
    let (header, end, bits, _) = parse_root(input, TAG_ENUMERATED, false, limits)?;
    let content_end = content_end(&header)?;
    let value = signed_value(&input[header.content..content_end])?;
    Ok(Decoded {
        value,
        consumed_bits: bits,
        consumed_bytes: end,
    })
}

/// Encode a numeric ENUMERATED value using canonical DER.
///
/// # Parameters
/// `value` is the mapped number; `limits` caps output bytes and wire work.
///
/// # Returns
/// A minimal universal tag 10 TLV.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER ENUMERATED rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first DER expansion.
/// Example: `encode_enumerated_der(1, limits)?`.
pub fn encode_enumerated_der(value: i64, limits: &Limits) -> Result<Encoded, Error> {
    encode_signed(TAG_ENUMERATED, value, limits)
}

/// Encode a numeric ENUMERATED value using canonical CER.
///
/// # Parameters
/// `value` is the mapped number; `limits` caps output bytes and wire work.
///
/// # Returns
/// A minimal universal tag 10 TLV.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER ENUMERATED rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first CER expansion.
/// Example: `encode_enumerated_cer(1, limits)?`.
pub fn encode_enumerated_cer(value: i64, limits: &Limits) -> Result<Encoded, Error> {
    encode_signed(TAG_ENUMERATED, value, limits)
}

/// Strictly decode a canonical CER ENUMERATED prefix.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, output, and work.
///
/// # Returns
/// The signed value and complete canonical TLV consumption.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` when canonical re-encoding differs.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical form. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first strict CER decoder.
/// Example: `decode_enumerated_cer(&[10, 1, 1], limits)?`.
pub fn decode_enumerated_cer(input: &[u8], limits: &Limits) -> Result<Decoded<i64>, Error> {
    let decoded = decode_enumerated_ber(input, limits)?;
    let phase_limits = limits_after_work(decoded.consumed_bits, limits)?;
    let canonical = encode_enumerated_cer(decoded.value, &phase_limits)?;
    let mut work = decoded.consumed_bits;
    charge_work(&mut work, canonical.bytes.len(), limits)?;
    ensure_canonical(
        input,
        decoded.consumed_bytes,
        &canonical.bytes,
        &mut work,
        limits,
    )?;
    Ok(decoded)
}

/// Encode OCTET STRING as a canonical DER primitive TLV.
///
/// # Parameters
/// `value` is the payload; `limits` caps output bytes and wire work.
///
/// # Returns
/// A complete universal tag 4 TLV with minimal definite length.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER OCTET STRING rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first DER string API.
/// Example: `encode_octet_string_der(b"abc", limits)?`.
pub fn encode_octet_string_der(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    write_primitive(TAG_OCTET_STRING, value, limits)
}

/// Encode OCTET STRING using canonical CER fragmentation above 1000 octets.
///
/// # Parameters
/// `value` is the payload; `limits` caps output bytes and wire work.
///
/// # Returns
/// A primitive TLV through 1000 octets, otherwise indefinite constructed form.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER OCTET STRING fragmentation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first CER string API.
/// Example: `encode_octet_string_cer(b"abc", limits)?`.
pub fn encode_octet_string_cer(value: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    check(Resource::OutputBytes, value.len(), limits.max_output_bytes)?;
    if value.len() <= CER_FRAGMENT_MAX {
        return write_primitive(TAG_OCTET_STRING, value, limits);
    }
    let count = value.len().div_ceil(CER_FRAGMENT_MAX);
    let size = fragmented_size(value.len(), count, false)?;
    let mut out = new_output(size, limits)?;
    push(&mut out, &[0x24, 0x80], limits)?;
    for fragment in value.chunks(CER_FRAGMENT_MAX) {
        push_primitive(&mut out, TAG_OCTET_STRING, fragment, limits)?;
    }
    push(&mut out, &[0, 0], limits)?;
    finish(out, limits)
}

/// Decode one BER OCTET STRING prefix, flattening primitive/constructed leaves.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps full input, decoded storage,
/// and consumed wire work.
///
/// # Returns
/// Concatenated payload bytes with complete TLV prefix consumption.
///
/// # Errors
/// Returns malformed nesting, tag, EOC, length, depth, size, allocation, or
/// configured-limit errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 BER constructed strings. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first BER string API.
/// Example: `decode_octet_string_ber(&[4, 1, b'x'], limits)?`.
pub fn decode_octet_string_ber(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    Ok(decode_octet_ber_work(input, limits)?.0)
}

/// Decode OCTET STRING and return its actual parser work for strict CER.
///
/// # Parameters and returns
/// `input` is the available prefix; `limits` caps input, payload and traversal.
/// Returns decoded value plus cumulative parser work bits.
///
/// # Errors
/// Returns malformed BER, resource, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: BER OCTET STRING decoding. Version: 2026-10-31.
/// Responsible: maintainers. History: work accounting. Example: strict CER.
fn decode_octet_ber_work(
    input: &[u8],
    limits: &Limits,
) -> Result<(Decoded<Vec<u8>>, usize), Error> {
    decode_octet_ber_work_bounded(input, limits, None)
}

/// Decode OCTET STRING under an optional schema payload ceiling.
///
/// # Parameters and returns
/// `input` is one TLV; `limits` supplies remaining shared ceilings;
/// `max_payload` is an optional SIZE upper bound checked before each append.
/// Returns the decoded value and work spent in bits.
///
/// # Errors
/// Returns malformed BER, SIZE, work/output, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: bounded BER record string fields. Version: 2026-10-31.
/// Responsible: maintainers. History: shared record contexts.
/// Example: used by `SequenceReader::read_octet_string`.
fn decode_octet_ber_work_bounded(
    input: &[u8],
    limits: &Limits,
    max_payload: Option<usize>,
) -> Result<(Decoded<Vec<u8>>, usize), Error> {
    let mut work = 0;
    let decoded = decode_octet_ber_with_work(input, limits, &mut work, max_payload)?;
    Ok((decoded, work))
}

/// Decode and flatten OCTET STRING while charging a caller-owned work counter.
///
/// # Parameters and returns
/// `input` is one TLV; `limits` supplies current ceilings; `work` is shared
/// cumulative work; `max_payload` is an optional schema size cap. Returns the
/// decoded value and consumed prefix.
///
/// # Errors
/// Returns malformed BER, SIZE, work/output, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: bounded BER record string fields. Version: 2026-10-31.
/// Responsible: maintainers. History: direct cumulative work mutation.
/// Example: called by `SequenceReader::read_octet_string`.
fn decode_octet_ber_with_work(
    input: &[u8],
    limits: &Limits,
    work: &mut usize,
    max_payload: Option<usize>,
) -> Result<Decoded<Vec<u8>>, Error> {
    let (header, end, bits) = parse_root_with_work(input, TAG_OCTET_STRING, true, limits, work)?;
    let mut value = Vec::new();
    {
        let mut budget = FlattenBudget {
            limits,
            work,
            max_payload,
        };
        flatten_octets(input, &header, end, 0, &mut value, &mut budget)?;
    }
    Ok(Decoded {
        value,
        consumed_bits: bits,
        consumed_bytes: end,
    })
}

/// Strictly decode one canonical CER OCTET STRING prefix.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, output, and wire work.
///
/// # Returns
/// Concatenated payload and canonical TLV prefix consumption.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` if re-encoding differs.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical form. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first strict CER string decoder.
/// Example: `decode_octet_string_cer(&[4, 1, b'x'], limits)?`.
pub fn decode_octet_string_cer(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    let (decoded, mut work) = decode_octet_ber_work(input, limits)?;
    let phase_limits = limits_after_work(work, limits)?;
    let canonical = encode_octet_string_cer(&decoded.value, &phase_limits)?;
    charge_work(&mut work, canonical.bytes.len(), limits)?;
    ensure_canonical(
        input,
        decoded.consumed_bytes,
        &canonical.bytes,
        &mut work,
        limits,
    )?;
    Ok(decoded)
}

/// Encode a validated BIT STRING as a canonical DER primitive TLV.
///
/// # Parameters
/// `value` is the packed bit value; `limits` caps output and wire work.
///
/// # Returns
/// A universal tag 3 TLV with an initial unused-bit count octet.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER BIT STRING rules. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first DER string API.
/// Example: `encode_bit_string_der(&bits, limits)?`.
pub fn encode_bit_string_der(value: &BitStringValue, limits: &Limits) -> Result<Encoded, Error> {
    write_bit_fragment(value.as_bytes(), unused_bits(value.bit_len()), limits)
}

/// Encode BIT STRING using CER fragmentation when content exceeds 1000 octets.
///
/// # Parameters
/// `value` is the packed bit value; `limits` caps output and wire work.
///
/// # Returns
/// A primitive through 1000 content octets, otherwise constructed fragments
/// of at most 1000 content octets including each unused-count octet.
///
/// # Errors
/// Returns size, limit, or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 CER BIT STRING fragmentation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first CER string API.
/// Example: `encode_bit_string_cer(&bits, limits)?`.
pub fn encode_bit_string_cer(value: &BitStringValue, limits: &Limits) -> Result<Encoded, Error> {
    let bytes = value.as_bytes();
    check(Resource::OutputBytes, bytes.len(), limits.max_output_bytes)?;
    let unused = unused_bits(value.bit_len());
    let content_len = bytes.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    if content_len <= CER_FRAGMENT_MAX {
        return write_bit_fragment(bytes, unused, limits);
    }
    let fragment_payload = CER_FRAGMENT_MAX - 1;
    let count = bytes.len().div_ceil(fragment_payload);
    let size = fragmented_size(bytes.len(), count, true)?;
    let mut out = new_output(size, limits)?;
    push(&mut out, &[0x23, 0x80], limits)?;
    for (index, fragment) in bytes.chunks(fragment_payload).enumerate() {
        let fragment_unused = if index + 1 == count { unused } else { 0 };
        push_bit_fragment(&mut out, fragment, fragment_unused, limits)?;
    }
    push(&mut out, &[0, 0], limits)?;
    finish(out, limits)
}

/// Decode a BER BIT STRING prefix and concatenate constructed fragments.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, decoded storage, and
/// consumed wire work.
///
/// # Returns
/// The packed bit value and complete TLV prefix consumption.
///
/// # Errors
/// Returns malformed nesting, tag, EOC, padding, depth, size, allocation, or
/// configured-limit errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 BER BIT STRING fragments. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first BER string API.
/// Example: `decode_bit_string_ber(&[3, 2, 0, 0xa0], limits)?`.
pub fn decode_bit_string_ber(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<BitStringValue>, Error> {
    Ok(decode_bit_ber_work(input, limits)?.0)
}

/// Decode BIT STRING and return actual parser work for strict CER.
///
/// # Parameters and returns
/// `input` is available prefix; `limits` caps input, payload and traversal.
/// Returns decoded value plus cumulative parser work bits.
///
/// # Errors
/// Returns malformed BER, resource, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: BER BIT STRING decoding. Version: 2026-10-31.
/// Responsible: maintainers. History: work accounting. Example: strict CER.
fn decode_bit_ber_work(
    input: &[u8],
    limits: &Limits,
) -> Result<(Decoded<BitStringValue>, usize), Error> {
    decode_bit_ber_work_bounded(input, limits, None)
}

/// Decode BIT STRING under an optional schema payload ceiling.
///
/// # Parameters and returns
/// `input` is one TLV; `limits` supplies remaining shared ceilings;
/// `max_payload` caps accumulated packed bytes before each append. Returns the
/// validated value and parser work in bits.
///
/// # Errors
/// Returns malformed BER, SIZE, work/output, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: bounded BER record string fields. Version: 2026-10-31.
/// Responsible: maintainers. History: shared record contexts.
/// Example: used by `SequenceReader::read_bit_string`.
fn decode_bit_ber_work_bounded(
    input: &[u8],
    limits: &Limits,
    max_payload: Option<usize>,
) -> Result<(Decoded<BitStringValue>, usize), Error> {
    let mut work = 0;
    let decoded = decode_bit_ber_with_work(input, limits, &mut work, max_payload)?;
    Ok((decoded, work))
}

/// Decode and flatten BIT STRING while charging a caller-owned work counter.
///
/// # Parameters and returns
/// `input` is one TLV; `limits` supplies current ceilings; `work` is shared
/// cumulative work; `max_payload` is an optional schema storage cap. Returns
/// the validated value and consumed prefix.
///
/// # Errors
/// Returns malformed BER, SIZE, work/output, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: bounded BER record string fields. Version: 2026-10-31.
/// Responsible: maintainers. History: direct cumulative work mutation.
/// Example: called by `SequenceReader::read_bit_string`.
fn decode_bit_ber_with_work(
    input: &[u8],
    limits: &Limits,
    work: &mut usize,
    max_payload: Option<usize>,
) -> Result<Decoded<BitStringValue>, Error> {
    let (header, end, bits) = parse_root_with_work(input, TAG_BIT_STRING, true, limits, work)?;
    let mut value = BitAccumulator {
        bytes: Vec::new(),
        state: BitState {
            unused: 0,
            fragments: 0,
        },
    };
    {
        let mut budget = FlattenBudget {
            limits,
            work,
            max_payload,
        };
        flatten_bits(input, &header, end, 0, &mut value, &mut budget)?;
    }
    let bit_len = value
        .bytes
        .len()
        .checked_mul(8)
        .and_then(|n| n.checked_sub(usize::from(value.state.unused)))
        .ok_or(Error::SizeOverflow)?;
    let value = BitStringValue::new(value.bytes, bit_len)?;
    Ok(Decoded {
        value,
        consumed_bits: bits,
        consumed_bytes: end,
    })
}

/// Strictly decode one canonical CER BIT STRING prefix.
///
/// # Parameters
/// `input` is an available prefix; `limits` caps input, output, and wire work.
///
/// # Returns
/// The packed bit value and canonical TLV prefix consumption.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` if re-encoding differs.
///
/// # Source, version, history, example
/// Source: X.690 CER canonical form. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: first strict CER string decoder.
/// Example: `decode_bit_string_cer(&[3, 2, 0, 0xa0], limits)?`.
pub fn decode_bit_string_cer(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<BitStringValue>, Error> {
    let (decoded, mut work) = decode_bit_ber_work(input, limits)?;
    let phase_limits = limits_after_work(work, limits)?;
    let canonical = encode_bit_string_cer(&decoded.value, &phase_limits)?;
    charge_work(&mut work, canonical.bytes.len(), limits)?;
    ensure_canonical(
        input,
        decoded.consumed_bytes,
        &canonical.bytes,
        &mut work,
        limits,
    )?;
    Ok(decoded)
}

/// Parse the expected root universal tag and charge its full TLV work.
///
/// # Parameters and returns
/// `input` is the full prefix; `tag` is expected universal tag; `constructed`
/// permits constructed form; `limits` supplies budgets. Returns header, end,
/// and wire bits.
///
/// # Errors
/// Returns malformed TLV, truncation, work, input-limit, or size errors.
///
/// # Source, version, history, example
/// Source: checked BER framing. Version: 2026-10-31. Responsible: maintainers.
/// History: initial parser. Example: used by each BER primitive decoder.
fn parse_root(
    input: &[u8],
    tag: u64,
    constructed: bool,
    limits: &Limits,
) -> Result<(Header, usize, usize, usize), Error> {
    let mut work = 0;
    let (header, end, bits) = parse_root_with_work(input, tag, constructed, limits, &mut work)?;
    Ok((header, end, bits, work))
}

/// Parse a BER root while charging directly to the caller's work counter.
///
/// # Parameters and returns
/// `input`, `tag`, `constructed`, and `limits` define the accepted root;
/// `work` is the cumulative counter shared with its enclosing operation.
/// Returns header, consumed bytes, and wire bits.
///
/// # Errors
/// Returns malformed TLV, truncation, work, input-limit, or size errors.
///
/// # Source, version, history, example
/// Source: checked BER framing. Version: 2026-10-31. Responsible: maintainers.
/// History: shared record decoder accounting. Example: BER record string read.
fn parse_root_with_work(
    input: &[u8],
    tag: u64,
    constructed: bool,
    limits: &Limits,
    work: &mut usize,
) -> Result<(Header, usize, usize), Error> {
    check(Resource::InputBytes, input.len(), limits.max_input_bytes)?;
    let header = parse_header(input, 0, input.len(), work, true, limits)?;
    if header.class != 0 || header.tag != tag {
        return Err(invalid(
            "BER identifier does not match expected universal tag",
        ));
    }
    if header.constructed && !constructed {
        return Err(invalid(
            "BER constructed form is not valid for this primitive",
        ));
    }
    let end = scan(input, 0, input.len(), 0, work, false, limits)?;
    let bits = end.checked_mul(8).ok_or(Error::SizeOverflow)?;
    Ok((header, end, bits))
}

/// Parse identifier and length while respecting the parent boundary.
///
/// # Parameters and returns
/// `input` is the complete slice; `start` is the identifier position;
/// `bound` is its parent's exclusive end; `work`, `meter`, and `limits` enforce
/// incremental parser budgets. Returns checked metadata.
///
/// # Errors
/// Returns truncation, malformed high tag/length, parent-boundary, or overflow.
///
/// # Source, version, history, example
/// Source: X.690 BER identifier/length forms. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: `parse_header(..)`.
fn parse_header(
    input: &[u8],
    start: usize,
    bound: usize,
    work: &mut usize,
    meter: bool,
    limits: &Limits,
) -> Result<Header, Error> {
    require(input, start, 1, bound)?;
    if meter {
        charge_work(work, 1, limits)?;
    }
    let first = input[start];
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let short = u64::from(first & 0x1f);
    let mut cursor = start + 1;
    let tag = if short == 0x1f {
        let mut value = 0_u64;
        loop {
            require(input, cursor, 1, bound)?;
            if meter {
                charge_work(work, 1, limits)?;
            }
            let byte = input[cursor];
            cursor += 1;
            value = value
                .checked_mul(128)
                .and_then(|n| n.checked_add(u64::from(byte & 0x7f)))
                .ok_or(Error::SizeOverflow)?;
            if byte & 0x80 == 0 {
                break;
            }
        }
        value
    } else {
        short
    };
    let identifier_len = cursor - start;
    require(input, cursor, 1, bound)?;
    let length_byte = input[cursor];
    cursor += 1;
    let length = if length_byte == 0x80 {
        if !constructed {
            return Err(invalid("primitive BER value has indefinite length"));
        }
        None
    } else if length_byte & 0x80 == 0 {
        Some(usize::from(length_byte))
    } else {
        if length_byte == 0xff {
            return Err(invalid("BER length FF is reserved"));
        }
        let count = usize::from(length_byte & 0x7f);
        require(input, cursor, count, bound)?;
        let mut size = 0_usize;
        for byte in &input[cursor..cursor + count] {
            size = size
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or(Error::SizeOverflow)?;
        }
        cursor += count;
        Some(size)
    };
    Ok(Header {
        class,
        constructed,
        tag,
        identifier_len,
        content: cursor,
        length,
    })
}

/// Scan one TLV and recursively validate all constructed children and EOCs.
///
/// # Parameters and returns
/// `input` is the whole slice; `start` locates this element; `bound` is its
/// parent limit; `depth` is current nesting; `work` and `limits` charge parsing;
/// `meter` controls whether identifier work was charged by the caller.
/// Returns exclusive end index.
///
/// # Errors
/// Returns malformed child/EOC, truncation, depth, or checked-size errors.
///
/// # Source, version, history, example
/// Source: BER constructed values and EOC rules. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: called by root.
fn scan(
    input: &[u8],
    start: usize,
    bound: usize,
    depth: usize,
    work: &mut usize,
    meter: bool,
    limits: &Limits,
) -> Result<usize, Error> {
    let header = parse_header(input, start, bound, work, meter, limits)?;
    let length_octets = header.content - start - header.identifier_len;
    charge_work(work, length_octets, limits)?;
    if header.class == 0 && header.tag == 0 {
        return Err(invalid("BER EOC is outside an indefinite value"));
    }
    let Some(length) = header.length else {
        if depth >= MAX_DEPTH {
            return Err(invalid("BER nesting exceeds depth limit"));
        }
        let mut cursor = header.content;
        loop {
            require(input, cursor, 1, bound)?;
            if input[cursor] == 0 {
                require(input, cursor, 2, bound)?;
                if input[cursor + 1] == 0 {
                    charge_work(work, 2, limits)?;
                    return cursor.checked_add(2).ok_or(Error::SizeOverflow);
                }
            }
            cursor = scan(input, cursor, bound, depth + 1, work, true, limits)?;
        }
    };
    let end = header
        .content
        .checked_add(length)
        .ok_or(Error::SizeOverflow)?;
    require(input, header.content, length, bound)?;
    if !header.constructed {
        charge_work(work, length, limits)?;
        return Ok(end);
    }
    if depth >= MAX_DEPTH {
        return Err(invalid("BER nesting exceeds depth limit"));
    }
    let mut cursor = header.content;
    while cursor < end {
        cursor = scan(input, cursor, end, depth + 1, work, true, limits)?;
    }
    if cursor != end {
        return Err(invalid("BER child crosses parent boundary"));
    }
    Ok(end)
}

/// Flatten primitive OCTET STRING leaves from a structurally validated TLV.
///
/// # Parameters and returns
/// `input`, `head`, and `end` identify the TLV; `depth` bounds recursion;
/// `out` accumulates payload; `budget` carries storage and work ceilings.
/// Returns success.
///
/// # Errors
/// Returns child-tag, depth, output-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: BER constructed OCTET STRING. Version: 2026-10-31.
/// Responsible: maintainers. History: initial string decoder. Example: root use.
fn flatten_octets(
    input: &[u8],
    head: &Header,
    end: usize,
    depth: usize,
    out: &mut Vec<u8>,
    budget: &mut FlattenBudget<'_, '_>,
) -> Result<(), Error> {
    if !head.constructed {
        let stop = content_end(head)?;
        charge_work(budget.work, stop - head.content, budget.limits)?;
        append_payload(
            out,
            &input[head.content..stop],
            budget.max_payload,
            budget.limits,
        )?;
        return Ok(());
    }
    if depth >= MAX_DEPTH {
        return Err(invalid("BER string nesting exceeds depth limit"));
    }
    let bound = head
        .length
        .map_or_else(|| end.saturating_sub(2), |n| head.content + n);
    let mut cursor = head.content;
    while cursor < bound {
        if is_eoc(input, cursor, end) {
            break;
        }
        let child = parse_header(input, cursor, bound, budget.work, true, budget.limits)?;
        if child.class != 0 || child.tag != TAG_OCTET_STRING {
            return Err(invalid("constructed OCTET STRING contains another tag"));
        }
        let child_end = scan(
            input,
            cursor,
            bound,
            depth + 1,
            budget.work,
            false,
            budget.limits,
        )?;
        flatten_octets(input, &child, child_end, depth + 1, out, budget)?;
        cursor = child_end;
    }
    Ok(())
}

/// Flatten primitive BIT STRING leaves while enforcing non-final padding rules.
///
/// # Parameters and returns
/// `input`, `head`, and `end` locate the TLV; `depth` bounds recursion;
/// `value` accumulates payload and fragment state; `budget` carries limits.
/// Returns success.
///
/// # Errors
/// Returns malformed tags or unused counts, depth, limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BER BIT STRING fragments. Version: 2026-10-31.
/// Responsible: maintainers. History: initial string decoder. Example: root use.
fn flatten_bits(
    input: &[u8],
    head: &Header,
    end: usize,
    depth: usize,
    value: &mut BitAccumulator,
    budget: &mut FlattenBudget<'_, '_>,
) -> Result<(), Error> {
    if !head.constructed {
        let stop = content_end(head)?;
        let content = &input[head.content..stop];
        if content.is_empty() {
            return Err(invalid("BIT STRING lacks unused-bit count"));
        }
        let unused = content[0];
        let payload = &content[1..];
        validate_bits(payload, unused)?;
        if value.state.fragments > 0 && value.state.unused != 0 {
            return Err(invalid("non-final BIT STRING fragment has unused bits"));
        }
        let offset = value.bytes.len();
        charge_work(budget.work, payload.len(), budget.limits)?;
        append_payload(&mut value.bytes, payload, budget.max_payload, budget.limits)?;
        if unused > 0 && !payload.is_empty() {
            charge_work(budget.work, 1, budget.limits)?;
        }
        normalize_padding_at(&mut value.bytes, offset, payload.len(), unused);
        value.state.fragments = value
            .state
            .fragments
            .checked_add(1)
            .ok_or(Error::SizeOverflow)?;
        value.state.unused = unused;
        return Ok(());
    }
    if depth >= MAX_DEPTH {
        return Err(invalid("BER BIT STRING nesting exceeds depth limit"));
    }
    let bound = head
        .length
        .map_or_else(|| end.saturating_sub(2), |n| head.content + n);
    let mut cursor = head.content;
    while cursor < bound {
        if is_eoc(input, cursor, end) {
            break;
        }
        let child = parse_header(input, cursor, bound, budget.work, true, budget.limits)?;
        if child.class != 0 || child.tag != TAG_BIT_STRING {
            return Err(invalid("constructed BIT STRING contains another tag"));
        }
        let child_end = scan(
            input,
            cursor,
            bound,
            depth + 1,
            budget.work,
            false,
            budget.limits,
        )?;
        flatten_bits(input, &child, child_end, depth + 1, value, budget)?;
        cursor = child_end;
    }
    Ok(())
}

/// Detect the only valid EOC encoding at a known input position.
///
/// # Parameters and returns
/// `input` is the full slice; `offset` is candidate position; `end` is TLV end.
/// Returns true for two zero octets in range.
///
/// # Errors
/// Cannot fail or raise.
///
/// # Source, version, history, example
/// Source: X.690 BER EOC. Version: 2026-10-31. Responsible: maintainers.
/// History: initial parser. Example: called while flattening indefinite values.
fn is_eoc(input: &[u8], offset: usize, end: usize) -> bool {
    offset
        .checked_add(1)
        .is_some_and(|next| next < end && input[offset] == 0 && input[next] == 0)
}

/// Convert minimal or redundantly sign-extended BER contents to an i64.
///
/// # Parameters and returns
/// `bytes` are signed two's-complement content octets; returns represented i64.
///
/// # Errors
/// Returns `InvalidEncoding` for empty or out-of-range content. No panic.
///
/// # Source, version, history, example
/// Source: X.690 signed integer content. Version: 2026-10-31.
/// Responsible: maintainers. History: direct ENUMERATED support.
/// Example: `signed_value(&[0xff])? == -1`.
fn signed_value(bytes: &[u8]) -> Result<i64, Error> {
    if bytes.is_empty() {
        return Err(invalid("ENUMERATED content is empty"));
    }
    let mut significant = bytes;
    while significant.len() > 8 {
        let first = significant[0];
        let next = significant[1];
        if !((first == 0 && next & 0x80 == 0) || (first == 0xff && next & 0x80 != 0)) {
            return Err(invalid("ENUMERATED value exceeds i64 range"));
        }
        significant = &significant[1..];
    }
    let sign = if significant[0] & 0x80 != 0 { 0xff } else { 0 };
    let mut full = [sign; 8];
    full[8 - significant.len()..].copy_from_slice(significant);
    Ok(i64::from_be_bytes(full))
}

/// Find the first byte of the minimal signed representation of an i64.
///
/// # Parameters and returns
/// `bytes` is the complete eight-octet big-endian two's-complement form.
/// Returns its first nonredundant byte index.
///
/// # Errors
/// Cannot fail because an i64 always has at least one content octet.
///
/// # Source, version, history, example
/// Source: X.690 minimal signed INTEGER content. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: shared primitive/record output.
/// Example: `minimal_signed_start(128_i64.to_be_bytes())`.
const fn minimal_signed_start(bytes: [u8; 8]) -> usize {
    let mut first = 0;
    while first < 7 {
        let current = bytes[first];
        let next = bytes[first + 1];
        if (current == 0 && next & 0x80 == 0) || (current == 0xff && next & 0x80 != 0) {
            first += 1;
        } else {
            break;
        }
    }
    first
}

/// Compute the complete outer SEQUENCE size for one body length.
///
/// # Parameters and returns
/// `rule` chooses DER or CER; `content_len` is the encoded child-TLV byte count.
/// Returns total output bytes including canonical outer framing.
///
/// # Errors
/// Returns `SizeOverflow` when the complete size cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 constructed value framing. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: shared record writer.
/// Example: `record_size(RecordEncoding::Der, 0)? == 2`.
fn record_size(rule: RecordEncoding, content_len: usize) -> Result<usize, Error> {
    match rule {
        RecordEncoding::Der => 1_usize
            .checked_add(length_size(content_len))
            .and_then(|size| size.checked_add(content_len))
            .ok_or(Error::SizeOverflow),
        RecordEncoding::Cer => 4_usize.checked_add(content_len).ok_or(Error::SizeOverflow),
    }
}

/// Validate inclusive ASN.1 SIZE bounds independently of a field's value.
///
/// # Parameters and returns
/// `lower` and `upper` are inclusive bounds. Returns success when ordered.
///
/// # Errors
/// Returns `InvalidEncoding` when the lower bound exceeds the upper bound.
///
/// # Source, version, history, example
/// Source: generated finite string SIZE constraints. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: bounded record fields.
/// Example: `validate_size_bounds(0, 64)?`.
const fn validate_size_bounds(lower: usize, upper: usize) -> Result<(), Error> {
    if lower > upper {
        return Err(invalid("string SIZE lower bound exceeds upper bound"));
    }
    Ok(())
}

/// Validate one actual length against inclusive ASN.1 SIZE bounds.
///
/// # Parameters and returns
/// `size` is the measured octet or bit count; `lower`/`upper` are inclusive.
/// Returns success when the measured length is in range.
///
/// # Errors
/// Returns `InvalidEncoding` for an invalid range or out-of-range value.
///
/// # Source, version, history, example
/// Source: generated finite string SIZE constraints. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: bounded record fields.
/// Example: `validate_size(payload.len(), 1, 64)?`.
fn validate_size(size: usize, lower: usize, upper: usize) -> Result<(), Error> {
    validate_size_bounds(lower, upper)?;
    if size < lower || size > upper {
        return Err(invalid("string length is outside its SIZE bounds"));
    }
    Ok(())
}

/// Compute packed storage bytes for a logical BIT STRING width without overflow.
///
/// # Parameters and returns
/// `bit_len` is the meaningful bit count. Returns its ceiling byte count.
///
/// # Errors
/// This total helper cannot fail.
///
/// # Source, version, history, example
/// Source: ASN.1 packed BIT STRING representation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: borrowed record writer.
/// Example: `packed_storage_len(9) == 2`.
const fn packed_storage_len(bit_len: usize) -> usize {
    if bit_len.is_multiple_of(8) {
        bit_len / 8
    } else {
        bit_len / 8 + 1
    }
}

/// Validate borrowed packed BIT STRING storage without allocating a wrapper.
///
/// # Parameters and returns
/// `bytes` contains MSB-first payload; `bit_len` is the exact meaningful width.
/// Returns success for exact storage and zero padding.
///
/// # Errors
/// Returns `InvalidEncoding` for a byte-count mismatch or nonzero unused bits.
///
/// # Source, version, history, example
/// Source: `BitStringValue` storage invariant. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: avoid fixed-value copies.
/// Example: `validate_packed_bits(&[0xa0], 3)?`.
fn validate_packed_bits(bytes: &[u8], bit_len: usize) -> Result<(), Error> {
    if bytes.len() != packed_storage_len(bit_len) {
        return Err(invalid("BIT STRING storage does not match its bit length"));
    }
    let unused = unused_bits(bit_len);
    if unused > 0 {
        let mask = (1_u8 << unused) - 1;
        if bytes.last().is_some_and(|last| last & mask != 0) {
            return Err(invalid("BIT STRING has nonzero unused trailing bits"));
        }
    }
    Ok(())
}

/// Compute one primitive universal child TLV size for a content length.
///
/// # Parameters and returns
/// `content_len` is the encoded content size. Returns tag, length, and content
/// octets using shortest definite length form.
///
/// # Errors
/// Returns `SizeOverflow` on checked arithmetic failure.
///
/// # Source, version, history, example
/// Source: X.690 primitive TLV lengths. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: bounded record strings.
/// Example: `primitive_field_size(3)? == 5`.
fn primitive_field_size(content_len: usize) -> Result<usize, Error> {
    1_usize
        .checked_add(length_size(content_len))
        .and_then(|n| n.checked_add(content_len))
        .ok_or(Error::SizeOverflow)
}

/// Compute exact OCTET STRING child size before any fragment loop.
///
/// # Parameters and returns
/// `payload_len` is the value size; `rule` selects DER or CER. Returns complete
/// primitive or constructed child TLV size in O(1).
///
/// # Errors
/// Returns `SizeOverflow` on checked arithmetic failure.
///
/// # Source, version, history, example
/// Source: X.690 CER OCTET STRING fragmentation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: bounded record strings.
/// Example: `octet_field_size(1001, RecordEncoding::Cer)?`.
fn octet_field_size(payload_len: usize, rule: RecordEncoding) -> Result<usize, Error> {
    if rule == RecordEncoding::Cer && payload_len > CER_FRAGMENT_MAX {
        fragmented_size(payload_len, payload_len.div_ceil(CER_FRAGMENT_MAX), false)
    } else {
        primitive_field_size(payload_len)
    }
}

/// Compute exact BIT STRING child size before any fragment loop.
///
/// # Parameters and returns
/// `payload_len` is packed byte count; `rule` selects DER or CER. Returns the
/// complete child size in O(1), counting each unused-count octet.
///
/// # Errors
/// Returns `SizeOverflow` on checked arithmetic failure.
///
/// # Source, version, history, example
/// Source: X.690 CER BIT STRING fragmentation. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: bounded record strings.
/// Example: `bit_field_size(1000, RecordEncoding::Cer)?`.
fn bit_field_size(payload_len: usize, rule: RecordEncoding) -> Result<usize, Error> {
    let content_len = payload_len.checked_add(1).ok_or(Error::SizeOverflow)?;
    if rule == RecordEncoding::Cer && content_len > CER_FRAGMENT_MAX {
        fragmented_size(
            payload_len,
            payload_len.div_ceil(CER_FRAGMENT_MAX - 1),
            true,
        )
    } else {
        primitive_field_size(content_len)
    }
}

/// Patch a DER SEQUENCE's placeholder length to its shortest definite form.
///
/// # Parameters and returns
/// `output` begins with tag and one placeholder length octet; `content_len`
/// gives body bytes. Returns success after inserting any additional length
/// octets and shifting the body in-place.
///
/// # Errors
/// Returns checked-size or allocation errors. No panic.
///
/// # Source, version, history, example
/// Source: X.690 DER definite length. Version: 2026-10-31.
/// Responsible: asn1c maintainers. History: flat record writer.
/// Example: called by `SequenceWriter::finish`.
fn patch_der_length(output: &mut Vec<u8>, content_len: usize) -> Result<(), Error> {
    if content_len < 128 {
        output[1] = u8::try_from(content_len).map_err(|_| Error::SizeOverflow)?;
        return Ok(());
    }
    let length_bytes = content_len.to_be_bytes();
    let first = length_bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::SizeOverflow)?;
    let count = length_bytes.len() - first;
    let extra = count;
    let old_len = output.len();
    let new_len = old_len.checked_add(extra).ok_or(Error::SizeOverflow)?;
    output
        .try_reserve(extra)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: new_len,
        })?;
    output.resize(new_len, 0);
    output.copy_within(2..old_len, 2 + extra);
    output[1] = 0x80 | u8::try_from(count).map_err(|_| Error::SizeOverflow)?;
    output[2..2 + count].copy_from_slice(&length_bytes[first..]);
    Ok(())
}

/// Encode a signed value as minimal canonical universal TLV.
///
/// # Parameters and returns
/// `tag` selects the universal tag; `value` is signed; `limits` bounds output.
/// Returns the complete DER/CER encoding.
///
/// # Errors
/// Returns invalid-size, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 canonical signed integer content. Version: 2026-10-31.
/// Responsible: maintainers. History: shared ENUMERATED encoder.
/// Example: `encode_signed(TAG_ENUMERATED, 4, limits)?`.
fn encode_signed(tag: u64, value: i64, limits: &Limits) -> Result<Encoded, Error> {
    let bytes = value.to_be_bytes();
    let first = minimal_signed_start(bytes);
    write_primitive(tag, &bytes[first..], limits)
}

/// Write a canonical primitive universal TLV.
///
/// # Parameters and returns
/// `tag` is a universal number; `contents` is payload; `limits` sets ceilings.
/// Returns a complete minimal definite-length TLV.
///
/// # Errors
/// Returns checked-size, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 DER/CER identifier and length rules. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: used by DER API.
fn write_primitive(tag: u64, contents: &[u8], limits: &Limits) -> Result<Encoded, Error> {
    let size = identifier_size(tag)?
        .checked_add(length_size(contents.len()))
        .and_then(|n| n.checked_add(contents.len()))
        .ok_or(Error::SizeOverflow)?;
    let mut out = new_output(size, limits)?;
    push_identifier(&mut out, false, tag, limits)?;
    push_length(&mut out, contents.len(), limits)?;
    push(&mut out, contents, limits)?;
    finish(out, limits)
}

/// Write a primitive BIT STRING TLV with its leading unused-bit count.
///
/// # Parameters and returns
/// `payload` holds packed bits; `unused` is 0..=7; `limits` caps output.
/// Returns one complete primitive TLV.
///
/// # Errors
/// Returns invalid padding, size, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING encoding. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: DER API calls it.
fn write_bit_fragment(payload: &[u8], unused: u8, limits: &Limits) -> Result<Encoded, Error> {
    validate_bits(payload, unused)?;
    let content_len = payload.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    let size = 1_usize
        .checked_add(length_size(content_len))
        .and_then(|n| n.checked_add(content_len))
        .ok_or(Error::SizeOverflow)?;
    let mut out = new_output(size, limits)?;
    push_bit_fragment(&mut out, payload, unused, limits)?;
    finish(out, limits)
}

/// Append one primitive BIT STRING fragment to an output buffer.
///
/// # Parameters and returns
/// `out` receives bytes; `payload` is packed data; `unused` is its count;
/// `limits` caps complete output. Returns success.
///
/// # Errors
/// Returns invalid padding, limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING fragment content. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: CER API calls it.
fn push_bit_fragment(
    out: &mut Vec<u8>,
    payload: &[u8],
    unused: u8,
    limits: &Limits,
) -> Result<(), Error> {
    validate_bits(payload, unused)?;
    let size = payload.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    push_identifier(out, false, TAG_BIT_STRING, limits)?;
    push_length(out, size, limits)?;
    push(out, &[unused], limits)?;
    push(out, payload, limits)
}

/// Append one primitive string fragment with a definite length.
///
/// # Parameters and returns
/// `out` is the output; `tag` is its universal number; `fragment` is payload;
/// `limits` caps output. Returns success.
///
/// # Errors
/// Returns limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 primitive string TLVs. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: CER OCTET API.
fn push_primitive(
    out: &mut Vec<u8>,
    tag: u64,
    fragment: &[u8],
    limits: &Limits,
) -> Result<(), Error> {
    push_identifier(out, false, tag, limits)?;
    push_length(out, fragment.len(), limits)?;
    push(out, fragment, limits)
}

/// Compute exact encoded size for the CER constructed string framing.
///
/// # Parameters and returns
/// `payload_len` is data octets; `fragments` is leaf count; `bits` adds one
/// count octet per BIT fragment. Returns exact total output bytes.
///
/// # Errors
/// Returns `SizeOverflow` on arithmetic overflow.
///
/// # Source, version, history, example
/// Source: X.690 CER fragment form. Version: 2026-10-31.
/// Responsible: maintainers. History: initial writer. Example: CER encoders.
fn fragmented_size(payload_len: usize, fragments: usize, bits: bool) -> Result<usize, Error> {
    if fragments == 0 {
        return Err(Error::SizeOverflow);
    }
    let capacity = if bits {
        CER_FRAGMENT_MAX - 1
    } else {
        CER_FRAGMENT_MAX
    };
    let full_payload = capacity
        .checked_mul(fragments - 1)
        .ok_or(Error::SizeOverflow)?;
    if full_payload >= payload_len {
        return Err(Error::SizeOverflow);
    }
    let last_payload = payload_len - full_payload;
    let full_content = capacity
        .checked_add(usize::from(bits))
        .ok_or(Error::SizeOverflow)?;
    let last_content = last_payload
        .checked_add(usize::from(bits))
        .ok_or(Error::SizeOverflow)?;
    let full_size = (fragments - 1)
        .checked_mul(1 + length_size(full_content) + full_content)
        .ok_or(Error::SizeOverflow)?;
    4_usize
        .checked_add(full_size)
        .and_then(|n| n.checked_add(1 + length_size(last_content) + last_content))
        .ok_or(Error::SizeOverflow)
}

/// Append shortest universal identifier, including high-tag form.
///
/// # Parameters and returns
/// `out` receives bytes; `constructed` selects form; `tag` is numeric tag;
/// `limits` caps output. Returns success.
///
/// # Errors
/// Returns size, output-limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 identifier encoding. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: tag 4.
fn push_identifier(
    out: &mut Vec<u8>,
    constructed: bool,
    tag: u64,
    limits: &Limits,
) -> Result<(), Error> {
    let form = if constructed { 0x20 } else { 0 };
    if tag < 31 {
        return push(
            out,
            &[form | u8::try_from(tag).map_err(|_| Error::SizeOverflow)?],
            limits,
        );
    }
    push(out, &[form | 0x1f], limits)?;
    let mut groups = [0_u8; 10];
    let mut n = 0;
    let mut value = tag;
    loop {
        groups[n] = (value & 0x7f) as u8;
        n += 1;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    for index in (0..n).rev() {
        let more = if index > 0 { 0x80 } else { 0 };
        push(out, &[groups[index] | more], limits)?;
    }
    Ok(())
}

/// Append a shortest definite length field.
///
/// # Parameters and returns
/// `out` receives length octets; `length` is content size; `limits` caps output.
/// Returns success.
///
/// # Errors
/// Returns output-limit or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BER definite lengths. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: length 128.
fn push_length(out: &mut Vec<u8>, length: usize, limits: &Limits) -> Result<(), Error> {
    if length < 128 {
        return push(
            out,
            &[u8::try_from(length).map_err(|_| Error::SizeOverflow)?],
            limits,
        );
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::SizeOverflow)?;
    let count = bytes.len() - first;
    push(
        out,
        &[0x80 | u8::try_from(count).map_err(|_| Error::SizeOverflow)?],
        limits,
    )?;
    push(out, &bytes[first..], limits)
}

/// Append bytes after checking output budget and reserving fallibly.
///
/// # Parameters and returns
/// `out` is the growing vector; `bytes` is appended; `limits` caps total output.
/// Returns success.
///
/// # Errors
/// Returns `LimitExceeded`, `SizeOverflow`, or `AllocationFailed`.
///
/// # Source, version, history, example
/// Source: bounded Rust output safety. Version: 2026-10-31.
/// Responsible: maintainers. History: first writer. Example: all append paths.
fn push(out: &mut Vec<u8>, bytes: &[u8], limits: &Limits) -> Result<(), Error> {
    let next = out
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, next, limits.max_output_bytes)?;
    out.try_reserve(bytes.len())
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: next,
        })?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Allocate a checked output vector with capacity for one complete encoding.
///
/// # Parameters and returns
/// `size` is expected output bytes; `limits` supplies output/work ceilings.
/// Returns a fallibly reserved vector.
///
/// # Errors
/// Returns configured limit, arithmetic, or allocation errors.
///
/// # Source, version, history, example
/// Source: bounded Rust output safety. Version: 2026-10-31.
/// Responsible: maintainers. History: first writer. Example: primitive writer.
fn new_output(size: usize, limits: &Limits) -> Result<Vec<u8>, Error> {
    check(Resource::OutputBytes, size, limits.max_output_bytes)?;
    let work = size.checked_mul(8).ok_or(Error::SizeOverflow)?;
    check(Resource::WorkBits, work, limits.max_work_bits)?;
    let mut out = Vec::new();
    out.try_reserve_exact(size)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: size,
        })?;
    Ok(out)
}

/// Finalize output and derive its octet-aligned bit length.
///
/// # Parameters and returns
/// `bytes` is complete TLV; `limits` supplies final ceilings. Returns `Encoded`.
///
/// # Errors
/// Returns size or resource-limit errors.
///
/// # Source, version, history, example
/// Source: runtime `Encoded` contract. Version: 2026-10-31.
/// Responsible: maintainers. History: first writer. Example: output helpers.
fn finish(bytes: Vec<u8>, limits: &Limits) -> Result<Encoded, Error> {
    let bits = bytes.len().checked_mul(8).ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, bytes.len(), limits.max_output_bytes)?;
    check(Resource::WorkBits, bits, limits.max_work_bits)?;
    Ok(Encoded {
        bytes,
        bit_len: bits,
    })
}

/// Return shortest identifier length for a universal tag number.
///
/// # Parameters and returns
/// `tag` is the number; returns 1 for low tags and shortest high-tag length.
///
/// # Errors
/// Returns overflow if calculation cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 high-tag form. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: tag 3 is 1.
fn identifier_size(tag: u64) -> Result<usize, Error> {
    if tag < 31 {
        return Ok(1);
    }
    let bits = 64_usize
        .checked_sub(tag.leading_zeros() as usize)
        .ok_or(Error::SizeOverflow)?;
    1_usize
        .checked_add(bits.div_ceil(7))
        .ok_or(Error::SizeOverflow)
}

/// Return shortest definite length-field byte count.
///
/// # Parameters and returns
/// `length` is content size; returns one byte for short form or count plus data.
///
/// # Errors
/// Cannot fail.
///
/// # Source, version, history, example
/// Source: X.690 length forms. Version: 2026-10-31.
/// Responsible: maintainers. History: canonical writer. Example: 128 maps to 2.
const fn length_size(length: usize) -> usize {
    if length < 128 {
        return 1;
    }
    let bits = length.bit_width();
    1 + bits.div_ceil(8) as usize
}

/// Validate BIT STRING unused count and low padding bits.
///
/// # Parameters and returns
/// `payload` is packed octets and `unused` is the count. Returns success.
///
/// # Errors
/// Returns `InvalidEncoding` for count/padding violations.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING unused-count rules. Version: 2026-10-31.
/// Responsible: maintainers. History: first string API. Example: empty/partial.
const fn validate_bits(payload: &[u8], unused: u8) -> Result<(), Error> {
    if unused > 7 || (payload.is_empty() && unused != 0) {
        return Err(invalid("BIT STRING unused-bit count is invalid"));
    }
    Ok(())
}

/// Compute final octet unused bits from a validated logical bit count.
///
/// # Parameters and returns
/// `bit_len` is meaningful bits; returns an integer from 0 to 7.
///
/// # Errors
/// Cannot fail.
///
/// # Source, version, history, example
/// Source: packed ASN.1 BIT STRING. Version: 2026-10-31.
/// Responsible: maintainers. History: first encoder. Example: length 3 gives 5.
const fn unused_bits(bit_len: usize) -> u8 {
    match bit_len % 8 {
        0 => 0,
        1 => 7,
        2 => 6,
        3 => 5,
        4 => 4,
        5 => 3,
        6 => 2,
        _ => 1,
    }
}

/// Return the checked exclusive end of a definite value's content.
///
/// # Parameters and returns
/// `head` is parsed TLV metadata; returns content offset plus length.
///
/// # Errors
/// Returns malformed indefinite content or checked-size error.
///
/// # Source, version, history, example
/// Source: checked BER parsing. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: primitive decode.
fn content_end(head: &Header) -> Result<usize, Error> {
    head.length
        .and_then(|n| head.content.checked_add(n))
        .ok_or_else(|| invalid("primitive content requires definite length"))
}

/// Append decoded semantic bytes within output and allocation ceilings.
///
/// # Parameters and returns
/// `out` is payload storage; `payload` is a source slice; `limits` caps bytes.
/// Returns success.
///
/// # Errors
/// Returns configured limit, overflow, or allocation error.
///
/// # Source, version, history, example
/// Source: bounded Rust decode allocation. Version: 2026-10-31.
/// Responsible: maintainers. History: first string API. Example: flattening.
fn append_payload(
    out: &mut Vec<u8>,
    payload: &[u8],
    max_payload: Option<usize>,
    limits: &Limits,
) -> Result<(), Error> {
    let next = out
        .len()
        .checked_add(payload.len())
        .ok_or(Error::SizeOverflow)?;
    if max_payload.is_some_and(|maximum| next > maximum) {
        return Err(invalid("BER string exceeds its declared SIZE upper bound"));
    }
    check(Resource::OutputBytes, next, limits.max_output_bytes)?;
    out.try_reserve(payload.len())
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: next,
        })?;
    out.extend_from_slice(payload);
    Ok(())
}

/// Ensure strict CER input matches the re-encoded canonical prefix.
///
/// # Parameters and returns
/// `input` is available data, `used` is decoded TLV size, and `canonical` is
/// output; `work` accumulates operation bits; `limits` supplies its ceiling.
/// Returns success for exact byte equality.
///
/// # Errors
/// Returns `InvalidEncoding` on mismatch.
///
/// # Source, version, history, example
/// Source: CER canonicality by BER decode/re-encode. Version: 2026-10-31.
/// Responsible: maintainers. History: first strict decoder. Example: CER APIs.
fn ensure_canonical(
    input: &[u8],
    used: usize,
    canonical: &[u8],
    work: &mut usize,
    limits: &Limits,
) -> Result<(), Error> {
    charge_work(work, used.max(canonical.len()), limits)?;
    if input.get(..used) != Some(canonical) {
        return Err(invalid("CER differs from canonical re-encoding"));
    }
    Ok(())
}

/// Require a bounded byte range to be present in input and its parent.
///
/// # Parameters and returns
/// `input` is the full slice; `start`, `size` describe range; `bound` caps it.
/// Returns success when available.
///
/// # Errors
/// Returns `NeedMoreBytes`, `InvalidEncoding`, or `SizeOverflow`.
///
/// # Source, version, history, example
/// Source: BER parser safe slicing. Version: 2026-10-31.
/// Responsible: maintainers. History: initial parser. Example: parse header.
fn require(input: &[u8], start: usize, size: usize, bound: usize) -> Result<(), Error> {
    let end = start.checked_add(size).ok_or(Error::SizeOverflow)?;
    if end > bound {
        if end > input.len() {
            return Err(Error::NeedMoreBytes {
                required_bytes: end,
                available_bytes: input.len(),
            });
        }
        return Err(invalid("BER child crosses parent boundary"));
    }
    if end > input.len() {
        return Err(Error::NeedMoreBytes {
            required_bytes: end,
            available_bytes: input.len(),
        });
    }
    Ok(())
}

/// Check a requested resource against its configured ceiling.
///
/// # Parameters and returns
/// `resource` names the budget; `used` is requested amount; `limit` is maximum.
/// Returns success when usage fits.
///
/// # Errors
/// Returns `LimitExceeded` when requested amount is greater than limit.
///
/// # Source, version, history, example
/// Source: runtime resource contract. Version: 2026-10-31.
/// Responsible: maintainers. History: first BER API. Example: work check.
const fn check(resource: Resource, used: usize, limit: usize) -> Result<(), Error> {
    if used > limit {
        return Err(Error::LimitExceeded {
            resource,
            limit,
            requested: used,
        });
    }
    Ok(())
}

/// Construct an invalid-encoding error with a static reason.
///
/// # Parameters and returns
/// `reason` explains malformed data; returns the typed error.
///
/// # Errors
/// Cannot fail.
///
/// # Source, version, history, example
/// Source: runtime error contract. Version: 2026-10-31.
/// Responsible: maintainers. History: first BER API. Example: `invalid("bad")`.
const fn invalid(reason: &'static str) -> Error {
    Error::InvalidEncoding { reason }
}

/// Clear unused low bits in one just-appended BIT STRING fragment.
///
/// # Parameters and returns
/// `bytes` is output; `offset` and `len` identify its fragment; `unused` is
/// padding count. Mutates its final fragment byte when applicable.
///
/// # Errors
/// Cannot fail; caller supplies a range created by a successful append.
///
/// # Source, version, history, example
/// Source: C BER compatibility in `OCTET_STRING_ber.c`. Version: 2026-10-31.
/// Responsible: maintainers. History: C parity. Example: called by flattener.
const fn normalize_padding_at(bytes: &mut [u8], offset: usize, len: usize, unused: u8) {
    if unused > 0 && len > 0 {
        let index = offset + len - 1;
        bytes[index] &= !((1_u8 << unused) - 1);
    }
}

/// Charge BER parser work as header, payload, or EOC octets are visited.
///
/// # Parameters and returns
/// `work` accumulates bits; `bytes` is newly examined octets; `limits` caps work.
/// Returns success if the cumulative request is permitted.
///
/// # Errors
/// Returns `SizeOverflow` or work `LimitExceeded`.
///
/// # Source, version, history, example
/// Source: runtime work budget. Version: 2026-10-31. Responsible: maintainers.
/// History: incremental BER parser checks. Example: called during scanning.
fn charge_work(work: &mut usize, bytes: usize, limits: &Limits) -> Result<(), Error> {
    let add = bytes.checked_mul(8).ok_or(Error::SizeOverflow)?;
    let total = work.checked_add(add).ok_or(Error::SizeOverflow)?;
    check(Resource::WorkBits, total, limits.max_work_bits)?;
    *work = total;
    Ok(())
}

/// Check strict CER parse and canonical re-encoding work cumulatively.
///
/// # Parameters and returns
/// `used` is parser work; `limits` supplies the common ceiling. Returns a copy
/// with only the unspent work budget available to canonical re-encoding.
///
/// # Errors
/// Returns `SizeOverflow` or work `LimitExceeded`.
///
/// # Source, version, history, example
/// Source: bounded strict CER operation policy. Version: 2026-10-31.
/// Responsible: maintainers. History: cumulative strict check. Example: CER APIs.
const fn limits_after_work(used: usize, limits: &Limits) -> Result<Limits, Error> {
    if used > limits.max_work_bits {
        return Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            limit: limits.max_work_bits,
            requested: used,
        });
    }
    let mut remaining = *limits;
    remaining.max_work_bits -= used;
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cover signed values, redundant BER sign octets, and CER rejection.
    /// Source: X.690 ENUMERATED; version: 2026-10-31; inputs: i64 edges.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn enumerated_round_trip_and_canonical_rejection() {
        let limits = Limits::default();
        for n in [i64::MIN, -129, -1, 0, 127, 128, i64::MAX] {
            let der = encode_enumerated_der(n, &limits).unwrap();
            assert_eq!(der, encode_enumerated_cer(n, &limits).unwrap());
            assert_eq!(decode_enumerated_ber(&der.bytes, &limits).unwrap().value, n);
            assert_eq!(decode_enumerated_cer(&der.bytes, &limits).unwrap().value, n);
        }
        assert_eq!(
            decode_enumerated_ber(&[10, 2, 0, 1], &limits)
                .unwrap()
                .value,
            1
        );
        assert!(decode_enumerated_cer(&[10, 2, 0, 1], &limits).is_err());
        assert!(decode_enumerated_ber(&[10, 0x80, 0, 0], &limits).is_err());
        assert!(decode_enumerated_ber(&[10, 0xff], &limits).is_err());
        assert!(decode_enumerated_ber(&[10, 9, 1, 2], &limits).is_err());
    }

    /// Cover constructed strings, EOC nesting, high tags, and malformed lengths.
    /// Source: X.690 BER strings; version: 2026-10-31; inputs: definite/indefinite.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn octet_ber_constructed_and_checked_tlv_forms() {
        let limits = Limits::default();
        let inputs: &[&[u8]] = &[
            &[4, 3, b'a', b'b', b'c'],
            &[0x24, 6, 4, 1, b'a', 4, 1, b'b'],
            &[0x24, 0x80, 4, 1, b'a', 4, 1, b'b', 0, 0],
            &[0x24, 0x80, 0, 0],
        ];
        let expected: &[&[u8]] = &[b"abc", b"ab", b"ab", b""];
        for (input, value) in inputs.iter().zip(expected) {
            assert_eq!(
                decode_octet_string_ber(input, &limits).unwrap().value,
                *value
            );
        }
        assert_eq!(
            decode_octet_string_ber(&[0x24, 0x80, 0, 0], &limits)
                .unwrap()
                .consumed_bytes,
            4
        );
        // BER accepts high-tag encodings of low tags; canonical CER rejects them.
        assert_eq!(
            decode_octet_string_ber(&[0x1f, 0x80, 4, 1, 0xaa], &limits)
                .unwrap()
                .value,
            [0xaa]
        );
        assert!(decode_octet_string_cer(&[0x1f, 4, 1, 0xaa], &limits).is_err());
        assert!(decode_octet_string_ber(&[0x24, 0x80, 4, 1, b'x'], &limits).is_err());
        assert!(decode_octet_string_ber(&[4, 0x80, 0, 0], &limits).is_err());
        assert!(decode_octet_string_ber(&[4, 0xff], &limits).is_err());
        assert!(decode_octet_string_ber(&[4, 0x82, 0, 4, 1], &limits).is_err());
        assert!(decode_octet_string_ber(&[0x24, 2, 0, 0], &limits).is_err());
        assert!(decode_octet_string_ber(&[0x1f, 0x81], &limits).is_err());
        let mut overflow_tag = vec![0x1f];
        overflow_tag.extend([0xff; 10]);
        overflow_tag.push(0);
        assert!(decode_octet_string_ber(&overflow_tag, &limits).is_err());
        let mut overflow_length = vec![4, 0x89];
        overflow_length.extend([0xff; 9]);
        assert!(decode_octet_string_ber(&overflow_length, &limits).is_err());
        assert_eq!(
            decode_octet_string_ber(&[4, 0x82, 0, 1, 0xaa], &limits)
                .unwrap()
                .value,
            [0xaa]
        );
    }

    /// Check CER primitive boundaries, fragmentation, and strict canonicality.
    /// Source: X.690 CER strings; version: 2026-10-31; inputs: 1000/1001 edges.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first CER expansion. Example: run via `cargo test`.
    #[test]
    fn octet_cer_fragmentation_and_strict_decode() {
        let limits = Limits::default();
        for size in [0, 127, 128, 999, 1000, 1001, 2001] {
            let value = vec![0x5a; size];
            let encoded = encode_octet_string_cer(&value, &limits).unwrap();
            assert_eq!(
                decode_octet_string_cer(&encoded.bytes, &limits)
                    .unwrap()
                    .value,
                value
            );
        }
        assert_eq!(
            encode_octet_string_cer(&vec![0; 1000], &limits)
                .unwrap()
                .bytes[0],
            4
        );
        assert_eq!(
            encode_octet_string_cer(&vec![0; 1001], &limits)
                .unwrap()
                .bytes[0],
            0x24
        );
        assert!(decode_octet_string_cer(&[4, 0x81, 1, 0x5a], &limits).is_err());
        assert!(decode_octet_string_cer(&[0x24, 0x80, 4, 1, 0x5a, 0, 0], &limits).is_err());
        assert!(decode_octet_string_cer(&[0x24, 0x80, 0, 0], &limits).is_err());
    }

    /// Check BIT STRING padding normalization, fragment rules, and CER forms.
    /// Source: X.690 BIT STRING; version: 2026-10-31; inputs: empty/partial/large.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn bit_string_ber_and_cer_canonicality() {
        let limits = Limits::default();
        let permissive = decode_bit_string_ber(&[3, 2, 3, 0xa7], &limits).unwrap();
        assert_eq!(permissive.value.as_bytes(), &[0xa0]);
        assert_eq!(permissive.value.bit_len(), 5);
        assert!(decode_bit_string_cer(&[3, 2, 3, 0xa7], &limits).is_err());
        for (bytes, bits) in [(vec![], 0), (vec![0xa0], 3), (vec![0xff; 1000], 8000)] {
            let value = BitStringValue::new(bytes, bits).unwrap();
            let der = encode_bit_string_der(&value, &limits).unwrap();
            assert_eq!(
                decode_bit_string_ber(&der.bytes, &limits).unwrap().value,
                value
            );
            let cer = encode_bit_string_cer(&value, &limits).unwrap();
            assert_eq!(
                decode_bit_string_cer(&cer.bytes, &limits).unwrap().value,
                value
            );
        }
        let fragmented = BitStringValue::new(vec![0xa0; 1000], 7995).unwrap();
        let cer = encode_bit_string_cer(&fragmented, &limits).unwrap();
        assert_eq!(cer.bytes[0], 0x23);
        assert_eq!(
            decode_bit_string_cer(&cer.bytes, &limits).unwrap().value,
            fragmented
        );
        assert!(decode_bit_string_ber(&[3, 1, 1], &limits).is_err());
        assert!(decode_bit_string_ber(&[3, 2, 8, 0], &limits).is_err());
        assert!(decode_bit_string_ber(&[0x23, 6, 3, 2, 1, 0x80, 3, 0], &limits).is_err());
    }

    /// Ensure parser depth and operation budgets reject work incrementally.
    /// Source: BER safety limits; version: 2026-10-31; inputs: nested TLVs.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER expansion. Example: run via `cargo test`.
    #[test]
    fn depth_and_resource_limits() {
        let limits = Limits::default();
        let mut nested = vec![0x24, 0x80];
        for _ in 0..=MAX_DEPTH {
            nested.extend_from_slice(&[0x24, 0x80]);
        }
        nested.extend_from_slice(&[4, 0, 0, 0]);
        assert!(decode_octet_string_ber(&nested, &limits).is_err());
        let no_work = Limits {
            max_work_bits: 0,
            ..limits
        };
        assert!(decode_octet_string_ber(&[0x24, 0x80, 4, 1, 1, 0, 0], &no_work).is_err());
        let mut long_identifier = vec![0x1f];
        long_identifier.extend(std::iter::repeat_n(0x80, 4096));
        long_identifier.extend_from_slice(&[4, 0]);
        assert!(decode_octet_string_ber(&long_identifier, &no_work).is_err());
        let tiny_input = Limits {
            max_input_bytes: 2,
            ..limits
        };
        assert!(decode_octet_string_ber(&[4, 1, 0], &tiny_input).is_err());
        let tiny_output = Limits {
            max_output_bytes: 0,
            ..limits
        };
        assert!(encode_octet_string_cer(&vec![0; 100_000], &tiny_output).is_err());
        let strict_work = Limits {
            max_work_bits: 79,
            ..limits
        };
        assert!(decode_octet_string_cer(&[4, 1, 7], &strict_work).is_err());
        let exact_strict_work = Limits {
            max_work_bits: 80,
            ..limits
        };
        assert_eq!(
            decode_octet_string_cer(&[4, 1, 7], &exact_strict_work)
                .unwrap()
                .value,
            [7]
        );
    }

    /// Mutate valid BER vectors and ensure malformed inputs never panic.
    /// Source: BER parser hardening cases; version: 2026-10-31; inputs: all
    /// one-byte substitutions in primitive and constructed OCTET/BIT TLVs.
    /// Returns: assertions; errors: panic if a decoder unwinds; responsible:
    /// asn1c maintainers. History: first BER expansion. Example: cargo test.
    #[test]
    fn single_byte_mutations_do_not_panic() {
        let limits = Limits::default();
        let vectors: &[&[u8]] = &[
            &[4, 3, 0x11, 0x22, 0x33],
            &[0x24, 0x80, 4, 1, 0xaa, 4, 1, 0xbb, 0, 0],
            &[3, 2, 3, 0xa0],
            &[0x23, 0x80, 3, 2, 0, 0xaa, 0, 0],
        ];
        for vector in vectors {
            for index in 0..vector.len() {
                for octet in 0..=u8::MAX {
                    let mut mutated = vector.to_vec();
                    mutated[index] = octet;
                    assert!(std::panic::catch_unwind(|| {
                        let _ = decode_octet_string_ber(&mutated, &limits);
                        let _ = decode_bit_string_ber(&mutated, &limits);
                    })
                    .is_ok());
                }
            }
        }
    }

    /// Round-trip direct fields through DER, CER, and BER prefix readers.
    /// Source: X.690 record framing; version: 2026-10-31; inputs: BOOLEAN,
    /// NULL, and constrained INTEGER. Returns: assertions; errors: assertion
    /// failures; responsible: maintainers. History: flat record support.
    /// Example: run via `cargo test`.
    #[test]
    fn flat_sequence_writer_reader_round_trip() {
        let limits = Limits::default();
        let mut der_context = RecordContext::new(&limits);
        let mut der = SequenceWriter::new(RecordEncoding::Der, &mut der_context).unwrap();
        der.write_boolean(true).unwrap();
        der.write_null().unwrap();
        der.write_integer(-129, -200, 200).unwrap();
        let der = der.finish().unwrap();
        assert_eq!(der.bytes, [0x30, 9, 1, 1, 0xff, 5, 0, 2, 2, 0xff, 0x7f]);

        let tags = [TAG_BOOLEAN, TAG_NULL, TAG_INTEGER];
        let mut ber_context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&der.bytes, &tags, &mut ber_context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BOOLEAN));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_field().unwrap(), Some(TAG_NULL));
        reader.read_null().unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_INTEGER));
        assert_eq!(reader.read_integer(-200, 200).unwrap(), -129);
        assert_eq!(reader.next_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, der.bytes.len());

        let mut cer_context = RecordContext::new(&limits);
        let mut cer = SequenceWriter::new(RecordEncoding::Cer, &mut cer_context).unwrap();
        cer.write_boolean(true).unwrap();
        cer.write_null().unwrap();
        cer.write_integer(-129, -200, 200).unwrap();
        let cer = cer.finish().unwrap();
        assert_eq!(&cer.bytes[..2], &[0x30, 0x80]);
        assert_eq!(&cer.bytes[cer.bytes.len() - 2..], &[0, 0]);

        let mut strict_context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&cer.bytes, &tags, &mut strict_context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BOOLEAN));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_field().unwrap(), Some(TAG_NULL));
        reader.read_null().unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_INTEGER));
        assert_eq!(reader.read_integer(-200, 200).unwrap(), -129);
        assert_eq!(reader.next_field().unwrap(), None);
        let prefix = reader.finish().unwrap();
        let mut canonical = SequenceWriter::new(RecordEncoding::Cer, &mut strict_context).unwrap();
        canonical.write_boolean(true).unwrap();
        canonical.write_null().unwrap();
        canonical.write_integer(-129, -200, 200).unwrap();
        let canonical = canonical.finish().unwrap();
        strict_context
            .verify_canonical(&cer.bytes, prefix.consumed_bytes, &canonical.bytes)
            .unwrap();
    }

    /// Preserve empty-record framing and exact prefix consumption.
    /// Source: X.690 empty SEQUENCE forms; version: 2026-10-31; inputs: empty
    /// DER/CER plus suffixes. Returns: assertions; errors: assertion failures.
    /// Responsible: asn1c maintainers. History: flat record support.
    /// Example: run via `cargo test`.
    #[test]
    fn empty_sequence_and_suffix_consumption() {
        let limits = Limits::default();
        let mut context = RecordContext::new(&limits);
        let der = SequenceWriter::new(RecordEncoding::Der, &mut context)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(der.bytes, [0x30, 0]);
        let mut context = RecordContext::new(&limits);
        let cer = SequenceWriter::new(RecordEncoding::Cer, &mut context)
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(cer.bytes, [0x30, 0x80, 0, 0]);

        for bytes in [
            [0x30, 0, 0xaa].as_slice(),
            [0x30, 0x80, 0, 0, 0xaa].as_slice(),
        ] {
            let mut context = RecordContext::new(&limits);
            let mut reader = SequenceReader::new(bytes, &[], &mut context).unwrap();
            assert_eq!(reader.next_field().unwrap(), None);
            let prefix = reader.finish().unwrap();
            assert_eq!(prefix.consumed_bytes, bytes.len() - 1);
        }
    }

    /// Reject invalid descriptors, duplicate/out-of-order fields, and truncation.
    /// Source: C nonextensible SEQUENCE behavior; version: 2026-10-31; inputs:
    /// malformed descriptors and BER child/body boundaries. Returns: assertions.
    /// Errors: assertion failures; responsible: maintainers. History: record API.
    /// Example: run via `cargo test`.
    #[test]
    fn sequence_rejects_ambiguous_and_malformed_fields() {
        let limits = Limits::default();
        let too_many_tags = [1, 2, 3, 4, 5, 10, 16];
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new(&[0x30, 0], &too_many_tags, &mut context).is_err());
        let unsupported_tag = [6];
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new(&[0x30, 0], &unsupported_tag, &mut context).is_err());
        let duplicate_tags = [1, 1];
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new(&[0x30, 0], &duplicate_tags, &mut context).is_err());

        let out_of_order = [0x30, 6, 2, 1, 1, 1, 1, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&out_of_order, &[1, 2], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_INTEGER));
        assert_eq!(reader.read_integer(0, 10).unwrap(), 1);
        assert!(reader.next_field().is_err());

        let duplicate_field = [0x30, 6, 1, 1, 0, 1, 1, 0xff];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&duplicate_field, &[1, 2], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BOOLEAN));
        assert!(!reader.read_boolean().unwrap());
        assert!(reader.next_field().is_err());

        let unknown = [0x30, 3, 3, 1, 0];
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new(&unknown, &[1, 2], &mut context)
            .unwrap()
            .next_field()
            .is_err());
        let child_crosses = [0x30, 2, 1, 2, 0];
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new(&child_crosses, &[1], &mut context)
            .unwrap()
            .next_field()
            .is_err());
        let no_eoc = [0x30, 0x80, 1, 1, 0xff];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&no_eoc, &[1], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BOOLEAN));
        reader.read_boolean().unwrap();
        assert!(reader.next_field().is_err());
    }

    /// Check cumulative record work and complete output ceilings at boundaries.
    /// Source: runtime resource policy; version: 2026-10-31; inputs: empty and
    /// one-field records. Returns: assertions; errors: assertion failures.
    /// Responsible: asn1c maintainers. History: shared record budgets.
    /// Example: run via `cargo test`.
    #[test]
    fn sequence_context_enforces_work_and_output_limits() {
        let limits = Limits {
            max_work_bits: 15,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        assert!(writer.finish().is_err());

        let limits = Limits {
            max_output_bytes: 3,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        assert!(SequenceWriter::new(RecordEncoding::Cer, &mut context).is_err());

        let limits = Limits {
            max_input_bytes: 2,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new(&[0x30, 0, 0], &[], &mut context).is_err());
    }

    /// Apply one aggregate budget to CER parsing, re-encoding, and comparison.
    /// Source: shared record-operation accounting; version: 2026-10-31; input:
    /// one canonical BOOLEAN record. Returns: boundary assertions. Errors:
    /// failed assertions; responsible: maintainers. History: record hardening.
    /// Example: run with `cargo test`.
    #[test]
    fn strict_cer_sequence_uses_one_cumulative_budget() {
        let canonical = [0x30, 0x80, 0x01, 0x01, 0xff, 0, 0];
        let tags = [TAG_BOOLEAN];
        let limits = Limits {
            max_work_bits: 208,
            max_output_bytes: canonical.len(),
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&canonical, &tags, &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BOOLEAN));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_boolean(true).unwrap();
        let encoded = writer.finish().unwrap();
        context
            .verify_canonical(&canonical, consumed.consumed_bytes, &encoded.bytes)
            .unwrap();

        let limits = Limits {
            max_work_bits: 207,
            ..limits
        };
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&canonical, &tags, &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BOOLEAN));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_boolean(true).unwrap();
        let encoded = writer.finish().unwrap();
        assert!(context
            .verify_canonical(&canonical, consumed.consumed_bytes, &encoded.bytes)
            .is_err());

        let too_small_output = Limits {
            max_output_bytes: canonical.len() - 1,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&too_small_output);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        assert!(writer.write_boolean(true).is_err());
    }

    /// Encode large DER fields across short/long length and shift boundaries.
    /// Source: X.690 DER length rules; version: 2026-10-31; values: 127/128
    /// payload octets. Returns: exact framing assertions. Errors: assertions.
    /// Responsible: maintainers. History: bounded record strings. Example: test.
    #[test]
    fn sequence_der_octets_cover_127_128_and_charge_body_shift() {
        for (length, expected_outer, expected_field) in [
            (127, [0x30, 0x81, 0x81], &[0x04, 0x7f][..]),
            (128, [0x30, 0x81, 0x83], &[0x04, 0x81, 0x80][..]),
        ] {
            let payload = vec![0x5a; length];
            let limits = Limits::default();
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
            writer.write_octet_string(&payload, length, length).unwrap();
            let encoded = writer.finish().unwrap();
            assert_eq!(&encoded.bytes[..3], &expected_outer);
            assert_eq!(&encoded.bytes[3..3 + expected_field.len()], expected_field);
            assert_eq!(
                encoded.bytes.len(),
                expected_outer.len() + expected_field.len() + length
            );

            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new(&encoded.bytes, &[TAG_OCTET_STRING], &mut context).unwrap();
            assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
            assert_eq!(reader.read_octet_string(length, length).unwrap(), payload);
            assert_eq!(reader.next_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
        }

        let payload = vec![0x7f; 127];
        let limits = Limits {
            max_work_bits: 2096,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_octet_string(&payload, 127, 127).unwrap();
        assert_eq!(writer.finish().unwrap().bytes.len(), 132);

        let limits = Limits {
            max_work_bits: 2095,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_octet_string(&payload, 127, 127).unwrap();
        assert!(writer.finish().is_err());
    }

    /// Check canonical CER OCTET and BIT STRING fragmentation boundaries.
    /// Source: X.690 CER string rules; version: 2026-10-31; values: OCTET 1000/
    /// 1001, BIT 999/1000 payload octets. Returns: framing and round-trip checks.
    /// Errors: failed assertions; responsible: maintainers. History: records.
    /// Example: run using `cargo test`.
    #[test]
    fn sequence_cer_octet_and_bit_fragment_boundaries() {
        for (length, first_tag) in [(1000, 0x04), (1001, 0x24)] {
            let payload = vec![0x6b; length];
            let limits = Limits::default();
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
            writer.write_octet_string(&payload, length, length).unwrap();
            let encoded = writer.finish().unwrap();
            assert_eq!(&encoded.bytes[..2], &[0x30, 0x80]);
            assert_eq!(encoded.bytes[2], first_tag);
            if length == 1001 {
                assert_eq!(encoded.bytes[3], 0x80);
            }
            assert_eq!(&encoded.bytes[encoded.bytes.len() - 2..], &[0, 0]);

            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new(&encoded.bytes, &[TAG_OCTET_STRING], &mut context).unwrap();
            assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
            assert_eq!(reader.read_octet_string(length, length).unwrap(), payload);
            assert_eq!(reader.next_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
        }

        for (payload_len, first_tag) in [(999, 0x03), (1000, 0x23)] {
            let payload = vec![0xa5; payload_len];
            let bit_len = payload_len * 8;
            let limits = Limits::default();
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
            writer
                .write_bit_string(&payload, bit_len, bit_len, bit_len)
                .unwrap();
            let encoded = writer.finish().unwrap();
            assert_eq!(encoded.bytes[2], first_tag);
            if payload_len == 1000 {
                assert_eq!(encoded.bytes[3], 0x80);
            }

            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new(&encoded.bytes, &[TAG_BIT_STRING], &mut context).unwrap();
            assert_eq!(reader.next_field().unwrap(), Some(TAG_BIT_STRING));
            let decoded = reader.read_bit_string(bit_len, bit_len).unwrap();
            assert_eq!(decoded.as_bytes(), payload);
            assert_eq!(decoded.bit_len(), bit_len);
            assert_eq!(reader.next_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
        }
    }

    /// Decode constructed BER strings and enforce aggregate retained storage.
    /// Source: X.690 BER constructed strings; version: 2026-10-31; vectors:
    /// definite/indefinite fragments and two fields. Returns: assertions.
    /// Errors: malformed or over-budget inputs return errors. Responsible:
    /// maintainers. History: sequence string budgets. Example: cargo test.
    #[test]
    fn sequence_flattens_constructed_strings_and_caps_retained_storage() {
        let octets = [0x30, 0x0a, 0x24, 0x80, 0x04, 1, b'a', 0x04, 1, b'b', 0, 0];
        let mut context = RecordContext::new(&Limits::default());
        let mut reader = SequenceReader::new(&octets, &[TAG_OCTET_STRING], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
        assert_eq!(reader.read_octet_string(2, 2).unwrap(), b"ab");
        assert_eq!(reader.next_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, octets.len());

        let nested = [
            0x30, 0x0c, 0x24, 0x0a, 0x04, 1, b'a', 0x24, 0x80, 0x04, 1, b'b', 0, 0,
        ];
        let mut context = RecordContext::new(&Limits::default());
        let mut reader = SequenceReader::new(&nested, &[TAG_OCTET_STRING], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
        assert_eq!(reader.read_octet_string(2, 2).unwrap(), b"ab");
        assert_eq!(reader.next_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, nested.len());

        let bits = [
            0x30, 0x0c, 0x23, 0x80, 0x03, 2, 0, 0xaa, 0x03, 2, 3, 0xa7, 0, 0,
        ];
        let mut context = RecordContext::new(&Limits::default());
        let mut reader = SequenceReader::new(&bits, &[TAG_BIT_STRING], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BIT_STRING));
        let decoded = reader.read_bit_string(13, 13).unwrap();
        assert_eq!(decoded.as_bytes(), [0xaa, 0xa0]);
        assert_eq!(reader.next_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, bits.len());

        let many = [0x30, 0x0c, 0x04, 5, 1, 2, 3, 4, 5, 0x03, 3, 0, 0x11, 0x22];
        let limits = Limits {
            max_output_bytes: 6,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SequenceReader::new(&many, &[TAG_OCTET_STRING, TAG_BIT_STRING], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
        assert_eq!(reader.read_octet_string(5, 5).unwrap(), [1, 2, 3, 4, 5]);
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BIT_STRING));
        let before_failed_append = reader.context.work_used;
        assert!(matches!(
            reader.read_bit_string(16, 16),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert!(reader.context.work_used > before_failed_append);
    }

    /// Keep failed string-decoder work charged when callers retry a field.
    /// Source: shared BER operation budget; version: 2026-10-31; input: an
    /// OCTET STRING whose first requested SIZE upper bound is too small.
    /// Returns: counter assertions. Errors: assertion failures. Responsible:
    /// maintainers. History: failed-pass accounting. Example: cargo test.
    #[test]
    fn sequence_failed_string_decode_keeps_work_charged() {
        let input = [0x30, 5, 0x04, 3, 0x11, 0x22, 0x33];
        let mut context = RecordContext::new(&Limits::default());
        let mut reader = SequenceReader::new(&input, &[TAG_OCTET_STRING], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
        let before = reader.context.work_used;
        assert!(reader.read_octet_string(0, 2).is_err());
        let after_failure = reader.context.work_used;
        assert!(after_failure > before);
        assert_eq!(reader.read_octet_string(3, 3).unwrap(), [0x11, 0x22, 0x33]);
        assert!(reader.context.work_used > after_failure);
    }

    /// Reject noncanonical BER padding when a record is decoded as strict CER.
    /// Source: X.690 BIT STRING canonical content; version: 2026-10-31; vector
    /// has nonzero low padding bits. Returns: canonical comparison failure.
    /// Errors: assertion failures. Responsible: maintainers. History: records.
    /// Example: run using `cargo test`.
    #[test]
    fn sequence_strict_cer_rejects_noncanonical_bit_padding() {
        let input = [0x30, 0x80, 0x03, 0x02, 0x05, 0xa7, 0, 0];
        let limits = Limits::default();
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(&input, &[TAG_BIT_STRING], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_BIT_STRING));
        let value = reader.read_bit_string(3, 3).unwrap();
        assert_eq!(value.as_bytes(), [0xa0]);
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer
            .write_bit_string(value.as_bytes(), value.bit_len(), 3, 3)
            .unwrap();
        let canonical = writer.finish().unwrap();
        assert!(context
            .verify_canonical(&input, consumed.consumed_bytes, &canonical.bytes)
            .is_err());
    }

    /// Share strict CER work across ENUMERATED and constructed string fields.
    /// Source: X.690 CER canonical comparison; version: 2026-10-31; input is a
    /// BER-valid noncanonical OCTET fragmentation. Returns: strict rejection.
    /// Errors: assertion failure; responsible: maintainers. History: records.
    /// Example: run using `cargo test`.
    #[test]
    fn sequence_enumerated_round_trip_and_strict_string_fragment_check() {
        let limits = Limits::default();
        let payload = vec![0x55; 1001];
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_enumerated(-129).unwrap();
        writer
            .write_octet_string(&payload, payload.len(), payload.len())
            .unwrap();
        let canonical = writer.finish().unwrap();
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(
            &canonical.bytes,
            &[TAG_ENUMERATED, TAG_OCTET_STRING],
            &mut context,
        )
        .unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_ENUMERATED));
        assert_eq!(reader.read_enumerated().unwrap(), -129);
        assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
        assert_eq!(
            reader
                .read_octet_string(payload.len(), payload.len())
                .unwrap(),
            payload
        );
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        context
            .verify_canonical(&canonical.bytes, consumed.consumed_bytes, &canonical.bytes)
            .unwrap();

        let mut noncanonical = vec![0x30, 0x80, 0x0a, 2, 0xff, 0x7f, 0x24, 0x80];
        noncanonical.extend_from_slice(&[0x04, 0x82, 0x03, 0xe7]);
        noncanonical.extend_from_slice(&vec![0x55; 999]);
        noncanonical.extend_from_slice(&[0x04, 2, 0x55, 0x55, 0, 0, 0, 0]);
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new(
            &noncanonical,
            &[TAG_ENUMERATED, TAG_OCTET_STRING],
            &mut context,
        )
        .unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(TAG_ENUMERATED));
        assert_eq!(reader.read_enumerated().unwrap(), -129);
        assert_eq!(reader.next_field().unwrap(), Some(TAG_OCTET_STRING));
        let decoded = reader
            .read_octet_string(payload.len(), payload.len())
            .unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_enumerated(-129).unwrap();
        writer
            .write_octet_string(&decoded, decoded.len(), decoded.len())
            .unwrap();
        let reencoded = writer.finish().unwrap();
        assert!(context
            .verify_canonical(&noncanonical, consumed.consumed_bytes, &reencoded.bytes)
            .is_err());
    }
}
