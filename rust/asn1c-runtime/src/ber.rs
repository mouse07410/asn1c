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
const TAG_SET: u64 = 17;
const MAX_SEQUENCE_FIELDS: usize = 6;
/// Largest BER tag number representable by the C runtime's packed tag value.
pub const MAX_TAG_NUMBER: u32 = 0x3fff_ffff;

/// BER identifier class, ordered by its two wire bits.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TagClass {
    /// Universal ASN.1 type tag.
    Universal = 0,
    /// Application-wide tag class.
    Application = 1,
    /// Context-specific tag class.
    ContextSpecific = 2,
    /// Private tag class.
    Private = 3,
}

impl TagClass {
    /// Decode the two class bits from a BER identifier.
    ///
    /// # Parameters and returns
    /// `bits` is the two-bit class value. Returns the matching class.
    ///
    /// # Errors
    /// This total helper cannot fail because its input is masked to two bits.
    ///
    /// # Source, version, history, example
    /// Source: X.690 identifier class bits. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `TagClass::from_bits(2) == TagClass::ContextSpecific`.
    const fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

/// Identifier class and numeric tag, without the constructed bit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Tag {
    /// The BER identifier class.
    class: TagClass,
    /// Numeric tag number, bounded to the C runtime's representable range.
    number: u32,
}

impl Tag {
    /// Construct a checked identifier class and number pair.
    ///
    /// # Parameters and returns
    /// `class` selects class bits; `number` is the numeric tag. Returns the
    /// tag when it fits the C runtime's packed representation.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when `number` exceeds `MAX_TAG_NUMBER`.
    ///
    /// # Source, version, history, example
    /// Source: C `ber_tlv_tag_t` range. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `Tag::new(TagClass::ContextSpecific, 31)?`.
    pub fn new(class: TagClass, number: u32) -> Result<Self, Error> {
        let tag = Self { class, number };
        tag.validate()?;
        Ok(tag)
    }

    /// Construct a universal tag for a static descriptor.
    ///
    /// Runtime record operations revalidate this value.
    ///
    /// # Parameters and returns
    /// `number` is the universal tag number. Returns its descriptor.
    ///
    /// # Errors
    /// This const helper cannot fail; runtime APIs reject out-of-range values.
    ///
    /// # Source, version, history, example
    /// Source: X.690 universal tags. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged descriptors.
    /// Example: `Tag::universal(4)`.
    #[must_use]
    pub const fn universal(number: u32) -> Self {
        Self {
            class: TagClass::Universal,
            number,
        }
    }

    /// Construct a context-specific tag for a static descriptor.
    ///
    /// Runtime record operations revalidate this value.
    ///
    /// # Parameters and returns
    /// `number` is the context-specific tag number. Returns its descriptor.
    ///
    /// # Errors
    /// This const helper cannot fail; runtime APIs reject out-of-range values.
    ///
    /// # Source, version, history, example
    /// Source: X.690 context-specific tags. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged descriptors.
    /// Example: `Tag::context_specific(31)`.
    #[must_use]
    pub const fn context_specific(number: u32) -> Self {
        Self {
            class: TagClass::ContextSpecific,
            number,
        }
    }

    /// Return this tag's identifier class.
    ///
    /// # Parameters and returns
    /// No parameters. Returns its class.
    ///
    /// # Errors
    /// This total accessor cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: BER tag descriptor API. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `tag.class() == TagClass::Universal`.
    #[must_use]
    pub const fn class(self) -> TagClass {
        self.class
    }

    /// Return this tag's numeric identifier number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the numeric tag number.
    ///
    /// # Errors
    /// This total accessor cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: BER tag descriptor API. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `tag.number() == 31`.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.number
    }

    /// Check this descriptor against the C runtime's packed tag range.
    ///
    /// # Parameters and returns
    /// No parameters. Returns success if the tag number fits.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when the tag number exceeds the cap.
    ///
    /// # Source, version, history, example
    /// Source: C `ber_tlv_tag_t` range. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: checked tag descriptors.
    /// Example: called by constructors and every tagged operation.
    const fn validate(self) -> Result<(), Error> {
        if self.number > MAX_TAG_NUMBER {
            return Err(Error::InvalidEncoding {
                reason: "BER tag number exceeds the C runtime limit",
            });
        }
        Ok(())
    }
}

/// Semantic ASN.1 primitive kind carried separately from an effective tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldKind {
    /// BOOLEAN field content.
    Boolean,
    /// Signed bounded INTEGER field content.
    Integer,
    /// Packed BIT STRING field content.
    BitString,
    /// OCTET STRING field content.
    OctetString,
    /// Empty NULL field content.
    Null,
    /// Signed numeric ENUMERATED field content.
    Enumerated,
}

impl FieldKind {
    /// Return the intrinsic universal tag number for this primitive kind.
    ///
    /// # Parameters and returns
    /// No parameters. Returns its universal tag number.
    ///
    /// # Errors
    /// This total helper cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: X.690 universal primitive tags. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `FieldKind::Boolean.universal_tag() == 1`.
    const fn universal_tag(self) -> u64 {
        match self {
            Self::Boolean => TAG_BOOLEAN,
            Self::Integer => TAG_INTEGER,
            Self::BitString => TAG_BIT_STRING,
            Self::OctetString => TAG_OCTET_STRING,
            Self::Null => TAG_NULL,
            Self::Enumerated => TAG_ENUMERATED,
        }
    }
}

/// Effective identifier and semantic type for one direct record member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordField {
    /// Effective BER identifier, including an IMPLICIT replacement tag.
    tag: Tag,
    /// ASN.1 primitive kind whose content rules remain in effect.
    kind: FieldKind,
}

impl RecordField {
    /// Construct a checked record field descriptor.
    ///
    /// # Parameters and returns
    /// `tag` is the effective identifier; `kind` selects the underlying ASN.1
    /// primitive semantics. Returns a validated descriptor.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for an out-of-range tag or a mismatched
    /// intrinsic universal tag.
    ///
    /// # Source, version, history, example
    /// Source: X.690 IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `RecordField::new(Tag::context_specific(3), FieldKind::Boolean)?`.
    pub fn new(tag: Tag, kind: FieldKind) -> Result<Self, Error> {
        validate_field_descriptor(tag, kind)?;
        Ok(Self { tag, kind })
    }

    /// Return this member's effective BER identifier.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the stored tag.
    ///
    /// # Errors
    /// This total accessor cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: BER record descriptor API. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `field.tag().class()`.
    #[must_use]
    pub const fn tag(self) -> Tag {
        self.tag
    }

    /// Return this member's ASN.1 primitive kind.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the stored field kind.
    ///
    /// # Errors
    /// This total accessor cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: BER record descriptor API. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `field.kind() == FieldKind::Boolean`.
    #[must_use]
    pub const fn kind(self) -> FieldKind {
        self.kind
    }
}

/// Validate the effective tag against its ASN.1 primitive kind.
///
/// # Parameters and returns
/// `tag` is the encoded identifier and `kind` supplies its content semantics.
/// Returns success for bounded tags and matching universal identifiers.
///
/// # Errors
/// Returns `InvalidEncoding` when a tag exceeds the C limit or a universal tag
/// does not identify the supplied primitive kind.
///
/// # Source, version, history, example
/// Source: X.690 IMPLICIT tag replacement. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged record support.
/// Example: called by `RecordField::new` and all tagged writers.
fn validate_field_descriptor(tag: Tag, kind: FieldKind) -> Result<(), Error> {
    tag.validate()?;
    if tag.class == TagClass::Universal && u64::from(tag.number) != kind.universal_tag() {
        return Err(invalid(
            "universal field tag does not match its primitive kind",
        ));
    }
    Ok(())
}

/// Map one supported universal tag to its semantic primitive kind.
///
/// # Parameters and returns
/// `tag` is a numeric universal tag. Returns its field kind when supported.
///
/// # Errors
/// This lookup cannot fail; unsupported tags return `None`.
///
/// # Source, version, history, example
/// Source: runtime's flat primitive field set. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged reader compatibility.
/// Example: `field_kind_for_universal(1) == Some(FieldKind::Boolean)`.
const fn field_kind_for_universal(tag: u64) -> Option<FieldKind> {
    match tag {
        TAG_BOOLEAN => Some(FieldKind::Boolean),
        TAG_INTEGER => Some(FieldKind::Integer),
        TAG_BIT_STRING => Some(FieldKind::BitString),
        TAG_OCTET_STRING => Some(FieldKind::OctetString),
        TAG_NULL => Some(FieldKind::Null),
        TAG_ENUMERATED => Some(FieldKind::Enumerated),
        _ => None,
    }
}

/// Canonical encoding rule used for one generated record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordEncoding {
    /// Encode the outer SEQUENCE or SET with a minimal definite length.
    Der,
    /// Encode the outer SEQUENCE or SET with indefinite length and EOC.
    Cer,
}

/// Component ordering and outer tag for one flat record container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordKind {
    /// Preserve schema declaration order for SEQUENCE components.
    Sequence,
    /// Accept arbitrary decode order and emit SET components by class/number.
    Set,
}

impl RecordKind {
    /// Return the universal constructed tag number for this container.
    ///
    /// # Parameters and returns
    /// No parameters. Returns 16 for SEQUENCE or 17 for SET.
    ///
    /// # Errors
    /// This total helper cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: X.690 universal constructed tags. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET support.
    /// Example: `RecordKind::Set.universal_tag() == TAG_SET`.
    const fn universal_tag(self) -> u64 {
        match self {
            Self::Sequence => TAG_SEQUENCE,
            Self::Set => TAG_SET,
        }
    }

    /// Return the first encoded identifier octet for this container.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the constructed universal tag octet.
    ///
    /// # Errors
    /// This total helper cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: X.690 universal constructed tags. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET support.
    /// Example: `RecordKind::Sequence.identifier() == 0x30`.
    const fn identifier(self) -> u8 {
        match self {
            Self::Sequence => 0x30,
            Self::Set => 0x31,
        }
    }
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
    /// Effective identifier of the current field.
    tag: Tag,
    /// Primitive semantics taken from its descriptor.
    kind: FieldKind,
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
    /// Container tag and component ordering rule.
    kind: RecordKind,
    /// Shared operation limits and work budget.
    context: &'context mut RecordContext,
    /// Complete output buffer with outer header placeholder; state variable.
    bytes: Vec<u8>,
    /// Tags already emitted; this is a state variable.
    seen_tags: [Option<Tag>; MAX_SEQUENCE_FIELDS],
    /// Number of used slots in `seen_tags`; this is a state variable.
    field_count: usize,
    /// Last tag for canonical SET component order; state variable.
    last_tag: Option<Tag>,
}

/// Encode flat SET fields under one bounded BER/DER/CER record context.
pub struct SetWriter<'context> {
    /// Shared typed-field encoder configured for SET tag order.
    inner: SequenceWriter<'context>,
}

/// Read fields from one BER SEQUENCE prefix under a shared operation budget.
pub struct SequenceReader<'input, 'tags, 'context> {
    /// Complete caller input, including any suffix; state variable.
    input: &'input [u8],
    /// Schema field tags in declaration order.
    expected_tags: &'tags [u64],
    /// Optional effective tags and semantic kinds for tagged schemas.
    tagged_fields: Option<&'tags [RecordField]>,
    /// Container tag and BER component ordering rule.
    kind: RecordKind,
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
    /// Schema indices already observed; state variable.
    seen_mask: u8,
    /// Current child span awaiting a typed reader; state variable.
    current: Option<FieldSpan>,
    /// Exact consumed end once the outer boundary has been reached; state variable.
    consumed_end: Option<usize>,
}

/// Read flat SET fields in any BER order under one bounded record context.
pub struct SetReader<'input, 'tags, 'context> {
    /// Shared typed-field reader configured for unordered SET components.
    inner: SequenceReader<'input, 'tags, 'context>,
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
        Self::new_with_kind(rule, context, RecordKind::Sequence)
    }

    /// Begin a record writer for one container kind.
    ///
    /// # Parameters and returns
    /// `rule` selects DER/CER; `context` owns shared budgets; `kind` selects
    /// SEQUENCE declaration order or canonical SET tag order.
    /// Returns a writer with the matching universal constructed identifier.
    ///
    /// # Errors
    /// Returns output-limit, work-limit, or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 flat record framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: common SET implementation.
    /// Example: called by `SequenceWriter::new` and `SetWriter::new`.
    fn new_with_kind(
        rule: RecordEncoding,
        context: &mut RecordContext,
        kind: RecordKind,
    ) -> Result<SequenceWriter<'_>, Error> {
        let minimum_size = if rule == RecordEncoding::Cer { 4 } else { 2 };
        context.check_output(minimum_size)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(2)
            .map_err(|_| Error::AllocationFailed { requested_bytes: 2 })?;
        bytes.extend_from_slice(&[
            kind.identifier(),
            if rule == RecordEncoding::Cer { 0x80 } else { 0 },
        ]);
        if rule == RecordEncoding::Cer {
            context.charge(2)?;
        } else {
            context.charge(1)?;
        }
        Ok(SequenceWriter {
            rule,
            kind,
            context,
            bytes,
            seen_tags: [None; MAX_SEQUENCE_FIELDS],
            field_count: 0,
            last_tag: None,
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
        self.write_boolean_tagged(Tag::universal(1), value)
    }

    /// Append BOOLEAN content under a checked effective tag.
    ///
    /// # Parameters and returns
    /// `tag` is the effective identifier; `value` is the ASN.1 BOOLEAN.
    /// Returns success after the complete TLV is appended.
    ///
    /// # Errors
    /// Returns invalid universal tag/kind, duplicate/order, resource, size,
    /// or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BOOLEAN and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `writer.write_boolean_tagged(Tag::context_specific(2), true)?`.
    pub fn write_boolean_tagged(&mut self, tag: Tag, value: bool) -> Result<(), Error> {
        let content = [if value { 0xff } else { 0 }];
        self.write_field(tag, FieldKind::Boolean, &content)
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
        self.write_null_tagged(Tag::universal(5))
    }

    /// Append empty NULL content under a checked effective tag.
    ///
    /// # Parameters and returns
    /// `tag` is the effective identifier. Returns success after an empty TLV.
    ///
    /// # Errors
    /// Returns invalid universal tag/kind, duplicate/order, resource, size,
    /// or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 NULL and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `writer.write_null_tagged(Tag::context_specific(5))?`.
    pub fn write_null_tagged(&mut self, tag: Tag) -> Result<(), Error> {
        self.write_field(tag, FieldKind::Null, &[])
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
        self.write_integer_tagged(Tag::universal(2), value, lower, upper)
    }

    /// Append bounded INTEGER content under a checked effective tag.
    ///
    /// # Parameters
    /// `tag` is the effective identifier; `value` is signed; `lower` and
    /// `upper` are inclusive schema bounds.
    ///
    /// # Returns
    /// `Ok(())` after appending shortest two's-complement content.
    ///
    /// # Errors
    /// Returns invalid bounds/value, tag/kind mismatch, resource, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 INTEGER and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `writer.write_integer_tagged(Tag::context_specific(7), 3, 0, 8)?`.
    pub fn write_integer_tagged(
        &mut self,
        tag: Tag,
        value: i64,
        lower: i64,
        upper: i64,
    ) -> Result<(), Error> {
        crate::validate_integer(value, lower, upper)?;
        let full = value.to_be_bytes();
        let first = minimal_signed_start(full);
        self.write_field(tag, FieldKind::Integer, &full[first..])
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
        self.write_enumerated_tagged(Tag::universal(10), value)
    }

    /// Append numeric ENUMERATED content under a checked effective tag.
    ///
    /// # Parameters and returns
    /// `tag` is the effective identifier; `value` is the generated variant's
    /// signed numeric representation. Returns success after the TLV is written.
    ///
    /// # Errors
    /// Returns tag/kind mismatch, duplicate/order, work/output, size, or
    /// allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 ENUMERATED and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `writer.write_enumerated_tagged(Tag::context_specific(10), 1)?`.
    pub fn write_enumerated_tagged(&mut self, tag: Tag, value: i64) -> Result<(), Error> {
        let full = value.to_be_bytes();
        let first = minimal_signed_start(full);
        self.write_field(tag, FieldKind::Enumerated, &full[first..])
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
        self.write_octet_string_tagged(Tag::universal(4), value, lower, upper)
    }

    /// Append a bounded OCTET STRING under a checked effective tag.
    ///
    /// # Parameters
    /// `tag` is the effective identifier; `value` is payload; `lower` and
    /// `upper` are inclusive SIZE bounds. CER fragments above 1000 content
    /// octets; fragment tags remain universal OCTET STRING.
    ///
    /// # Returns
    /// `Ok(())` after the canonical child TLV is appended.
    ///
    /// # Errors
    /// Returns invalid SIZE/tag, duplicate/order, resource, size, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 OCTET STRING and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `writer.write_octet_string_tagged(tag, b"abc", 1, 8)?`.
    pub fn write_octet_string_tagged(
        &mut self,
        tag: Tag,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        validate_size(value.len(), lower, upper)?;
        validate_field_descriptor(tag, FieldKind::OctetString)?;
        let field_size = octet_field_size(value.len(), self.rule, tag)?;
        self.prepare_field(tag, field_size)?;
        match (self.rule, value.len() > CER_FRAGMENT_MAX) {
            (RecordEncoding::Cer, true) => {
                push_indefinite_header(&mut self.bytes, tag, &self.context.limits)?;
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
            _ => push_primitive_tagged(&mut self.bytes, tag, value, &self.context.limits)?,
        }
        self.remember_tag(tag)?;
        self.last_tag = Some(tag);
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
        self.write_bit_string_tagged(Tag::universal(3), bytes, bit_len, lower_bits, upper_bits)
    }

    /// Append a bounded BIT STRING under a checked effective tag.
    ///
    /// # Parameters
    /// `tag` is the effective identifier; `bytes` are packed bits; `bit_len` is
    /// exact width; `lower_bits` and `upper_bits` are inclusive SIZE bounds.
    /// CER fragments retain universal BIT STRING tags.
    ///
    /// # Returns
    /// `Ok(())` after the canonical child TLV is appended.
    ///
    /// # Errors
    /// Returns malformed bits, invalid SIZE/tag, duplicate/order, resource, or
    /// allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BIT STRING and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `writer.write_bit_string_tagged(tag, &[0x80], 1, 1, 8)?`.
    pub fn write_bit_string_tagged(
        &mut self,
        tag: Tag,
        bytes: &[u8],
        bit_len: usize,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<(), Error> {
        validate_packed_bits(bytes, bit_len)?;
        validate_size(bit_len, lower_bits, upper_bits)?;
        validate_field_descriptor(tag, FieldKind::BitString)?;
        let unused = unused_bits(bit_len);
        let field_size = bit_field_size(bytes.len(), self.rule, tag)?;
        self.prepare_field(tag, field_size)?;
        let content_len = bytes.len().checked_add(1).ok_or(Error::SizeOverflow)?;
        if self.rule == RecordEncoding::Cer && content_len > CER_FRAGMENT_MAX {
            push_indefinite_header(&mut self.bytes, tag, &self.context.limits)?;
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
            push_bit_fragment_tagged(&mut self.bytes, tag, bytes, unused, &self.context.limits)?;
        }
        self.remember_tag(tag)?;
        self.last_tag = Some(tag);
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

    /// Append typed content after checking its effective tag and budgets.
    ///
    /// # Parameters and returns
    /// `tag` is the effective class/number; `kind` describes content semantics;
    /// `content` is the already encoded primitive payload. Returns success after
    /// identifier, shortest length, and content are appended.
    ///
    /// # Errors
    /// Returns tag/kind mismatch, duplicate/order, resource, size, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: shared bounded TLV writer. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record runtime API.
    /// Example: used by the public typed field methods.
    fn write_field(&mut self, tag: Tag, kind: FieldKind, content: &[u8]) -> Result<(), Error> {
        validate_field_descriptor(tag, kind)?;
        let field_size = tagged_primitive_field_size(tag, content.len())?;
        self.prepare_field(tag, field_size)?;
        push_primitive_tagged(&mut self.bytes, tag, content, &self.context.limits)?;
        self.remember_tag(tag)?;
        self.last_tag = Some(tag);
        Ok(())
    }

    /// Remember one successfully emitted field identifier.
    ///
    /// # Parameters and returns
    /// `tag` is the identifier just appended. Returns success after recording it.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` if the record field cap is already reached.
    ///
    /// # Source, version, history, example
    /// Source: flat record supported-field cap. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: called after every successful field append.
    fn remember_tag(&mut self, tag: Tag) -> Result<(), Error> {
        let slot = self
            .seen_tags
            .get_mut(self.field_count)
            .ok_or_else(|| invalid("record writer supports at most six fields"))?;
        *slot = Some(tag);
        self.field_count += 1;
        Ok(())
    }

    /// Check uniqueness, complete output, and work before a field is appended.
    ///
    /// # Parameters and returns
    /// `tag` identifies the field; `field_size` is its complete child TLV size.
    /// SET writers also check increasing class/number order.
    /// Returns success after validation and budget charging.
    ///
    /// # Errors
    /// Returns duplicate-tag, size, output-limit, or work-limit errors.
    ///
    /// # Source, version, history, example
    /// Source: shared bounded TLV writer. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: direct string support.
    /// Example: called by each typed `write_*` method.
    fn prepare_field(&mut self, tag: Tag, field_size: usize) -> Result<(), Error> {
        tag.validate()?;
        if self.field_count >= MAX_SEQUENCE_FIELDS {
            return Err(invalid("record writer supports at most six fields"));
        }
        if self.seen_tags[..self.field_count].contains(&Some(tag)) {
            return Err(invalid("record writer received a duplicate effective tag"));
        }
        if self.kind == RecordKind::Set && self.last_tag.is_some_and(|last| tag <= last) {
            return Err(invalid(
                "SET writer fields must use increasing class and tag order",
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

impl<'context> SetWriter<'context> {
    /// Begin one SET encoder using shared operation limits.
    ///
    /// # Parameters and returns
    /// `rule` selects DER definite or CER indefinite framing; `context` owns
    /// complete output and cumulative work ceilings. Returns a tag-sorted SET
    /// writer.
    ///
    /// # Errors
    /// Returns output-limit, work-limit, or allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `SetWriter::new(RecordEncoding::Der, &mut context)?`.
    pub fn new(rule: RecordEncoding, context: &'context mut RecordContext) -> Result<Self, Error> {
        Ok(Self {
            inner: SequenceWriter::new_with_kind(rule, context, RecordKind::Set)?,
        })
    }

    /// Append one BOOLEAN member in increasing universal-tag order.
    ///
    /// # Parameters and returns
    /// `value` is the ASN.1 BOOLEAN. Returns success after encoding tag 1.
    ///
    /// # Errors
    /// Returns duplicate/order, work/output-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and BOOLEAN rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET fields.
    /// Example: `writer.write_boolean(true)?`.
    pub fn write_boolean(&mut self, value: bool) -> Result<(), Error> {
        self.inner.write_boolean(value)
    }

    /// Append one NULL member in increasing universal-tag order.
    ///
    /// # Parameters and returns
    /// No value is needed; returns success after encoding tag 5.
    ///
    /// # Errors
    /// Returns duplicate/order, work/output-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and NULL rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET fields.
    /// Example: `writer.write_null()?`.
    pub fn write_null(&mut self) -> Result<(), Error> {
        self.inner.write_null()
    }

    /// Append one bounded INTEGER member in increasing tag order.
    ///
    /// # Parameters
    /// `value` is signed; `lower` and `upper` are inclusive schema bounds.
    ///
    /// # Returns
    /// `Ok(())` after encoding the minimal integer under tag 2.
    ///
    /// # Errors
    /// Returns invalid bounds/value, duplicate/order, resource, size, or
    /// allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and INTEGER rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET fields.
    /// Example: `writer.write_integer(-1, -3, 3)?`.
    pub fn write_integer(&mut self, value: i64, lower: i64, upper: i64) -> Result<(), Error> {
        self.inner.write_integer(value, lower, upper)
    }

    /// Append one numeric ENUMERATED member in increasing tag order.
    ///
    /// # Parameters and returns
    /// `value` is the generated variant's numeric representation. Returns
    /// success after encoding tag 10.
    ///
    /// # Errors
    /// Returns duplicate/order, work/output-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and ENUMERATED rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET fields.
    /// Example: `writer.write_enumerated(1)?`.
    pub fn write_enumerated(&mut self, value: i64) -> Result<(), Error> {
        self.inner.write_enumerated(value)
    }

    /// Append one bounded OCTET STRING member in increasing tag order.
    ///
    /// # Parameters and returns
    /// `value` is payload bytes; `lower` and `upper` are inclusive SIZE bounds.
    /// Returns success after DER/CER canonical child encoding.
    ///
    /// # Errors
    /// Returns invalid SIZE, duplicate/order, resource, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and OCTET STRING rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET fields.
    /// Example: `writer.write_octet_string(b"x", 1, 4)?`.
    pub fn write_octet_string(
        &mut self,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        self.inner.write_octet_string(value, lower, upper)
    }

    /// Append one bounded BIT STRING member in increasing tag order.
    ///
    /// # Parameters
    /// `bytes` are packed bits; `bit_len` is exact width; `lower_bits` and
    /// `upper_bits` are inclusive SIZE bounds.
    ///
    /// # Returns
    /// `Ok(())` after DER/CER canonical child encoding.
    ///
    /// # Errors
    /// Returns malformed bits, invalid SIZE, duplicate/order, resource, or
    /// allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and BIT STRING rules. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET fields.
    /// Example: `writer.write_bit_string(&[0x80], 1, 1, 1)?`.
    pub fn write_bit_string(
        &mut self,
        bytes: &[u8],
        bit_len: usize,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<(), Error> {
        self.inner
            .write_bit_string(bytes, bit_len, lower_bits, upper_bits)
    }

    /// Append BOOLEAN content under an effective SET tag.
    ///
    /// # Parameters and returns
    /// `tag` is the identifier; `value` is the ASN.1 BOOLEAN. Returns success.
    ///
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and BOOLEAN rules. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET fields.
    /// Example: `writer.write_boolean_tagged(tag, true)?`.
    pub fn write_boolean_tagged(&mut self, tag: Tag, value: bool) -> Result<(), Error> {
        self.inner.write_boolean_tagged(tag, value)
    }

    /// Append empty NULL content under an effective SET tag.
    ///
    /// # Parameters and returns
    /// `tag` is the identifier. Returns success after writing its empty TLV.
    ///
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and NULL rules. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET fields.
    /// Example: `writer.write_null_tagged(tag)?`.
    pub fn write_null_tagged(&mut self, tag: Tag) -> Result<(), Error> {
        self.inner.write_null_tagged(tag)
    }

    /// Append bounded INTEGER content under an effective SET tag.
    ///
    /// # Parameters
    /// `tag` is the identifier; `value` is signed; `lower` and `upper` are bounds.
    ///
    /// # Returns
    /// Success after writing the minimal signed representation.
    ///
    /// # Errors
    /// Returns invalid bounds/tag/value, duplicate/order, resource, or allocation.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and INTEGER rules. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET fields.
    /// Example: `writer.write_integer_tagged(tag, 3, 0, 8)?`.
    pub fn write_integer_tagged(
        &mut self,
        tag: Tag,
        value: i64,
        lower: i64,
        upper: i64,
    ) -> Result<(), Error> {
        self.inner.write_integer_tagged(tag, value, lower, upper)
    }

    /// Append numeric ENUMERATED content under an effective SET tag.
    ///
    /// # Parameters and returns
    /// `tag` is the identifier; `value` is the signed variant number.
    /// Returns success after writing the minimal representation.
    ///
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and ENUMERATED rules. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET fields.
    /// Example: `writer.write_enumerated_tagged(tag, 1)?`.
    pub fn write_enumerated_tagged(&mut self, tag: Tag, value: i64) -> Result<(), Error> {
        self.inner.write_enumerated_tagged(tag, value)
    }

    /// Append bounded OCTET STRING content under an effective SET tag.
    ///
    /// # Parameters
    /// `tag` is the identifier; `value` is payload and `lower`/`upper` are SIZE.
    ///
    /// # Returns
    /// Success after DER/CER child encoding.
    ///
    /// # Errors
    /// Returns invalid size/tag, duplicate/order, resource, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and OCTET STRING rules. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET fields.
    /// Example: `writer.write_octet_string_tagged(tag, b"x", 1, 4)?`.
    pub fn write_octet_string_tagged(
        &mut self,
        tag: Tag,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        self.inner
            .write_octet_string_tagged(tag, value, lower, upper)
    }

    /// Append bounded BIT STRING content under an effective SET tag.
    ///
    /// # Parameters
    /// `tag` is the identifier; `bytes` are packed bits and `bit_len` is width;
    /// `lower_bits` and `upper_bits` are SIZE bounds.
    ///
    /// # Returns
    /// Success after DER/CER child encoding.
    ///
    /// # Errors
    /// Returns invalid bits/size/tag, duplicate/order, resource, or allocation.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and BIT STRING rules. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET fields.
    /// Example: `writer.write_bit_string_tagged(tag, &[0x80], 1, 1, 8)?`.
    pub fn write_bit_string_tagged(
        &mut self,
        tag: Tag,
        bytes: &[u8],
        bit_len: usize,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<(), Error> {
        self.inner
            .write_bit_string_tagged(tag, bytes, bit_len, lower_bits, upper_bits)
    }

    /// Finalize the SET and release its shared context borrow.
    ///
    /// # Parameters and returns
    /// Consumes the writer. Returns complete DER/CER bytes and bit length.
    ///
    /// # Errors
    /// Returns output/work-limit, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 DER/CER SET framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `let encoded = writer.finish()?`.
    pub fn finish(self) -> Result<Encoded, Error> {
        self.inner.finish()
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
        Self::new_with_kind(input, expected_tags, None, context, RecordKind::Sequence)
    }

    /// Start decoding a BER SEQUENCE with effective tags and separate kinds.
    ///
    /// # Parameters
    /// `input` is the available prefix; `fields` lists up to six unique
    /// effective tag/kind descriptors in declaration order; `context` supplies
    /// the shared resource budgets.
    ///
    /// # Returns
    /// A cursor accepting definite or indefinite BER framing.
    ///
    /// # Errors
    /// Returns malformed descriptors, framing, tag, work, input, or size errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER and IMPLICIT tags. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `SequenceReader::new_tagged(input, &fields, &mut context)?`.
    pub fn new_tagged(
        input: &'input [u8],
        fields: &'tags [RecordField],
        context: &'context mut RecordContext,
    ) -> Result<Self, Error> {
        Self::new_with_kind(input, &[], Some(fields), context, RecordKind::Sequence)
    }

    /// Construct a record reader for SEQUENCE or SET framing.
    ///
    /// # Parameters and returns
    /// `input` is the full available slice; `expected_tags` lists supported
    /// unique universal fields; `context` provides shared budgets; `kind`
    /// selects the outer tag and component ordering behavior. Returns a cursor.
    ///
    /// # Errors
    /// Returns input-limit, truncation, wrong-tag/form, duplicate-descriptor,
    /// depth, size, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER record framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: common SET parser.
    /// Example: called by `SequenceReader::new` and `SetReader::new`.
    fn new_with_kind(
        input: &'input [u8],
        expected_tags: &'tags [u64],
        tagged_fields: Option<&'tags [RecordField]>,
        context: &'context mut RecordContext,
        kind: RecordKind,
    ) -> Result<Self, Error> {
        check(
            Resource::InputBytes,
            input.len(),
            context.limits.max_input_bytes,
        )?;
        let field_len = tagged_fields.map_or(expected_tags.len(), <[RecordField]>::len);
        if field_len > MAX_SEQUENCE_FIELDS {
            return Err(invalid("record reader supports at most six direct fields"));
        }
        if let Some(fields) = tagged_fields {
            for (index, field) in fields.iter().enumerate() {
                context.charge(1)?;
                validate_field_descriptor(field.tag, field.kind)?;
                for previous in &fields[..index] {
                    context.charge(1)?;
                    if previous.tag == field.tag {
                        return Err(invalid("record descriptor tags must be unique"));
                    }
                }
            }
        } else {
            for (index, tag) in expected_tags.iter().enumerate() {
                context.charge(1)?;
                if field_kind_for_universal(*tag).is_none() {
                    return Err(invalid(
                        "record descriptor has an unsupported universal tag",
                    ));
                }
                for previous in &expected_tags[..index] {
                    context.charge(1)?;
                    if previous == tag {
                        return Err(invalid("record descriptor tags must be unique"));
                    }
                }
            }
        }
        let work = &mut context.work_used;
        let header = parse_header(input, 0, input.len(), work, true, &context.limits)?;
        if header.class != 0 || header.tag != kind.universal_tag() || !header.constructed {
            return Err(invalid(
                "BER record has the wrong constructed universal tag",
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
            tagged_fields,
            kind,
            context,
            content_bound,
            indefinite,
            cursor: header.content,
            last_tag_index: None,
            seen_mask: 0,
            current: None,
            consumed_end: None,
        })
    }

    /// Advance to the next field and return its numeric tag number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the effective tag number or `None` at the body
    /// boundary. Use `next_tagged_field` when the class is also required.
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
        if self.tagged_fields.is_some() {
            return Err(invalid(
                "tagged record traversal requires next_tagged_field",
            ));
        }
        Ok(self.next_tagged_field()?.map(|tag| u64::from(tag.number)))
    }

    /// Advance to the next field and return its effective class and number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns a tag for one member or `None` after the definite
    /// boundary or matching EOC is consumed.
    ///
    /// # Errors
    /// Returns malformed child framing, unknown/duplicate/out-of-order tags,
    /// truncation, size, depth, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: BER SEQUENCE field traversal. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `while let Some(tag) = reader.next_tagged_field()? { ... }`.
    pub fn next_tagged_field(&mut self) -> Result<Option<Tag>, Error> {
        if self.current.is_some() {
            return Err(invalid("record field must be decoded before advancing"));
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
        if header.class == 0 && header.tag == 0 {
            return Err(invalid("BER EOC is not a record field"));
        }
        let effective_tag = Tag {
            class: TagClass::from_bits(header.class),
            number: u32::try_from(header.tag).map_err(|_| Error::SizeOverflow)?,
        };
        let mut matching_index = None;
        let mut field_kind = None;
        if let Some(fields) = self.tagged_fields {
            for (index, field) in fields.iter().enumerate() {
                self.context.charge(1)?;
                if field.tag == effective_tag {
                    matching_index = Some(index);
                    field_kind = Some(field.kind);
                    break;
                }
            }
        } else {
            if effective_tag.class != TagClass::Universal {
                return Err(invalid("record contains an unknown effective tag"));
            }
            for (index, tag) in self.expected_tags.iter().enumerate() {
                self.context.charge(1)?;
                if *tag == u64::from(effective_tag.number) {
                    matching_index = Some(index);
                    field_kind = field_kind_for_universal(*tag);
                    break;
                }
            }
        }
        let Some(index) = matching_index else {
            return Err(invalid("record contains an unknown field tag"));
        };
        let field_mask = 1_u8 << index;
        if self.seen_mask & field_mask != 0 {
            return Err(invalid("record contains a duplicate field tag"));
        }
        if self.kind == RecordKind::Sequence
            && self
                .last_tag_index
                .is_some_and(|previous| index <= previous)
        {
            return Err(invalid("SEQUENCE fields are out of declaration order"));
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
            tag: effective_tag,
            kind: field_kind.ok_or_else(|| invalid("record descriptor has no field kind"))?,
            tlv_start: start,
            tlv_end: end,
            constructed: header.constructed,
            content_start: header.content,
            content_end,
        });
        self.last_tag_index = Some(index);
        self.seen_mask |= field_mask;
        self.cursor = end;
        Ok(Some(effective_tag))
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
        let field = self.current_field(FieldKind::Boolean)?;
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
        let field = self.current_field(FieldKind::Null)?;
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
        let field = self.current_field(FieldKind::Integer)?;
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
        let field = self.current_field(FieldKind::Enumerated)?;
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
        let field = self.current_field(FieldKind::OctetString)?;
        let encoded = &self.input[field.tlv_start..field.tlv_end];
        let limits = self.context.remaining_decode_limits()?;
        let decoded = decode_octet_ber_with_tag_work(
            encoded,
            field.tag,
            &limits,
            &mut self.context.work_used,
            Some(upper),
        )?;
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
        let field = self.current_field(FieldKind::BitString)?;
        let encoded = &self.input[field.tlv_start..field.tlv_end];
        let limits = self.context.remaining_decode_limits()?;
        let payload_cap = packed_storage_len(upper_bits);
        let decoded = decode_bit_ber_with_tag_work(
            encoded,
            field.tag,
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
    /// `kind` is the expected primitive semantics. Returns the current span.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when no field is pending or the tag differs.
    ///
    /// # Source, version, history, example
    /// Source: typed BER field dispatch. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat record runtime API.
    /// Example: called by each typed `read_*` method.
    fn current_field(&self, kind: FieldKind) -> Result<FieldSpan, Error> {
        match &self.current {
            Some(field) if field.kind == kind => Ok(*field),
            Some(_) => Err(invalid("record field reader does not match current kind")),
            None => Err(invalid("SEQUENCE has no current field")),
        }
    }
}

impl<'input, 'tags, 'context> SetReader<'input, 'tags, 'context> {
    /// Start decoding one BER SET prefix against its supported field tags.
    ///
    /// # Parameters
    /// `input` is the full available slice; `expected_tags` lists up to six
    /// unique supported universal tags in any schema order; `context` supplies
    /// the shared input, output, retained-storage, and work budgets.
    ///
    /// # Returns
    /// A cursor accepting definite or indefinite BER SET framing and arbitrary
    /// member order.
    ///
    /// # Errors
    /// Returns input-limit, truncation, wrong-tag/form, duplicate-descriptor,
    /// depth, size, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER SET framing. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `SetReader::new(input, &[1, 4, 10], &mut context)?`.
    pub fn new(
        input: &'input [u8],
        expected_tags: &'tags [u64],
        context: &'context mut RecordContext,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: SequenceReader::new_with_kind(
                input,
                expected_tags,
                None,
                context,
                RecordKind::Set,
            )?,
        })
    }

    /// Start decoding a BER SET with effective tags and separate field kinds.
    ///
    /// # Parameters
    /// `input` is the available prefix; `fields` lists up to six unique tag/kind
    /// descriptors; `context` supplies shared limits.
    ///
    /// # Returns
    /// A cursor accepting arbitrary BER member order.
    ///
    /// # Errors
    /// Returns malformed descriptors, framing, tag, work, input, or size errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER SET and IMPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `SetReader::new_tagged(input, &fields, &mut context)?`.
    pub fn new_tagged(
        input: &'input [u8],
        fields: &'tags [RecordField],
        context: &'context mut RecordContext,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: SequenceReader::new_with_kind(
                input,
                &[],
                Some(fields),
                context,
                RecordKind::Set,
            )?,
        })
    }

    /// Advance to the next SET member, returning its universal tag number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns `Some(tag)` for a member or `None` at the outer
    /// definite boundary or matching EOC.
    ///
    /// # Errors
    /// Returns malformed framing, unknown/duplicate tags, truncation, size,
    /// depth, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: BER SET field traversal. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `while let Some(tag) = reader.next_field()? { ... }`.
    pub fn next_field(&mut self) -> Result<Option<u64>, Error> {
        self.inner.next_field()
    }

    /// Advance to the next SET member and return its class and number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the effective tag or `None` at the outer boundary.
    ///
    /// # Errors
    /// Returns malformed framing, unknown/duplicate tags, truncation, size,
    /// depth, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: BER SET traversal. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged record support.
    /// Example: `while let Some(tag) = reader.next_tagged_field()? { ... }`.
    pub fn next_tagged_field(&mut self) -> Result<Option<Tag>, Error> {
        self.inner.next_tagged_field()
    }

    /// Decode the current BOOLEAN SET member and consume it.
    ///
    /// # Parameters and returns
    /// No parameters. Returns false for zero content and true for nonzero.
    ///
    /// # Errors
    /// Returns malformed/form mismatch or work-limit errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER BOOLEAN. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `let enabled = reader.read_boolean()?`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        self.inner.read_boolean()
    }

    /// Decode the current empty NULL SET member and consume it.
    ///
    /// # Parameters and returns
    /// No parameters. Returns unit after validating empty content.
    ///
    /// # Errors
    /// Returns malformed/form mismatch or work-limit errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER NULL. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `reader.read_null()?`.
    pub fn read_null(&mut self) -> Result<(), Error> {
        self.inner.read_null()
    }

    /// Decode the current bounded INTEGER SET member and consume it.
    ///
    /// # Parameters
    /// `lower` and `upper` are the inclusive schema bounds.
    ///
    /// # Returns
    /// The decoded signed integer.
    ///
    /// # Errors
    /// Returns invalid bounds, malformed content, value-out-of-range, or work
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER INTEGER. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `reader.read_integer(-4, 4)?`.
    pub fn read_integer(&mut self, lower: i64, upper: i64) -> Result<i64, Error> {
        self.inner.read_integer(lower, upper)
    }

    /// Decode the current numeric ENUMERATED SET member and consume it.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the signed number mapped to a generated variant.
    ///
    /// # Errors
    /// Returns malformed/form mismatch or work-limit errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER ENUMERATED. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `let number = reader.read_enumerated()?`.
    pub fn read_enumerated(&mut self) -> Result<i64, Error> {
        self.inner.read_enumerated()
    }

    /// Decode and flatten the current bounded OCTET STRING SET member.
    ///
    /// # Parameters
    /// `lower` and `upper` are inclusive SIZE bounds.
    ///
    /// # Returns
    /// Owned concatenated payload bytes.
    ///
    /// # Errors
    /// Returns malformed BER, invalid SIZE, cumulative storage, or work errors.
    /// No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER OCTET STRING. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `let bytes = reader.read_octet_string(1, 8)?`.
    pub fn read_octet_string(&mut self, lower: usize, upper: usize) -> Result<Vec<u8>, Error> {
        self.inner.read_octet_string(lower, upper)
    }

    /// Decode and flatten the current bounded BIT STRING SET member.
    ///
    /// # Parameters
    /// `lower_bits` and `upper_bits` are inclusive logical SIZE bounds.
    ///
    /// # Returns
    /// Packed bytes and their exact meaningful bit count.
    ///
    /// # Errors
    /// Returns malformed BER, invalid SIZE, cumulative storage, or work errors.
    /// No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER BIT STRING. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `let bits = reader.read_bit_string(1, 64)?`.
    pub fn read_bit_string(
        &mut self,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<BitStringValue, Error> {
        self.inner.read_bit_string(lower_bits, upper_bits)
    }

    /// Finish traversal and return the exact SET prefix consumption.
    ///
    /// # Parameters and returns
    /// Consumes the reader. Returns unit with whole-prefix byte and bit counts.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` if a member or outer EOC remains unread, or
    /// size overflow. No panic.
    ///
    /// # Source, version, history, example
    /// Source: BER prefix-decoder contract. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: flat SET runtime API.
    /// Example: `let span = reader.finish()?`.
    pub fn finish(self) -> Result<Decoded<()>, Error> {
        self.inner.finish()
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
    decode_octet_ber_with_tag_work(input, Tag::universal(4), limits, work, max_payload)
}

/// Decode and flatten OCTET STRING under a caller-selected effective tag.
///
/// # Parameters and returns
/// `input` is one TLV; `tag` is its effective root identifier; `limits` and
/// `work` share operation ceilings; `max_payload` bounds flattened storage.
/// Returns decoded bytes and exact prefix consumption.
///
/// # Errors
/// Returns malformed root/fragments, tag, storage/work, allocation, or size errors.
///
/// # Source, version, history, example
/// Source: X.690 BER strings with IMPLICIT tags. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged record string readers.
/// Example: called with `FieldSpan::tag` by `read_octet_string`.
fn decode_octet_ber_with_tag_work(
    input: &[u8],
    tag: Tag,
    limits: &Limits,
    work: &mut usize,
    max_payload: Option<usize>,
) -> Result<Decoded<Vec<u8>>, Error> {
    let (header, end, bits) = parse_root_tag_with_work(input, tag, true, limits, work)?;
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
    decode_bit_ber_with_tag_work(input, Tag::universal(3), limits, work, max_payload)
}

/// Decode and flatten BIT STRING under a caller-selected effective tag.
///
/// # Parameters and returns
/// `input` is one TLV; `tag` is its effective root identifier; `limits` and
/// `work` share operation ceilings; `max_payload` bounds flattened storage.
/// Returns packed bits and exact prefix consumption.
///
/// # Errors
/// Returns malformed root/fragments, tag, padding, storage/work, or size errors.
///
/// # Source, version, history, example
/// Source: X.690 BER strings with IMPLICIT tags. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged record string readers.
/// Example: called with `FieldSpan::tag` by `read_bit_string`.
fn decode_bit_ber_with_tag_work(
    input: &[u8],
    tag: Tag,
    limits: &Limits,
    work: &mut usize,
    max_payload: Option<usize>,
) -> Result<Decoded<BitStringValue>, Error> {
    let (header, end, bits) = parse_root_tag_with_work(input, tag, true, limits, work)?;
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
    let number = u32::try_from(tag).map_err(|_| Error::SizeOverflow)?;
    parse_root_tag_with_work(
        input,
        Tag::new(TagClass::Universal, number)?,
        constructed,
        limits,
        work,
    )
}

/// Parse a BER root against an effective class/number identifier.
///
/// # Parameters and returns
/// `input` is available data; `tag` is the full expected identifier;
/// `constructed` allows constructed form; `limits` and `work` bound the parse.
/// Returns checked header, consumed prefix and wire bits.
///
/// # Errors
/// Returns malformed/mismatched TLV, truncation, input/work, or size errors.
///
/// # Source, version, history, example
/// Source: X.690 BER root parsing. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: implicit record roots.
/// Example: called by tagged OCTET/BIT STRING readers.
fn parse_root_tag_with_work(
    input: &[u8],
    tag: Tag,
    constructed: bool,
    limits: &Limits,
    work: &mut usize,
) -> Result<(Header, usize, usize), Error> {
    tag.validate()?;
    check(Resource::InputBytes, input.len(), limits.max_input_bytes)?;
    let header = parse_header(input, 0, input.len(), work, true, limits)?;
    if TagClass::from_bits(header.class) != tag.class || header.tag != u64::from(tag.number) {
        return Err(invalid(
            "BER identifier does not match the expected effective tag",
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
        let mut value = 0_u32;
        loop {
            require(input, cursor, 1, bound)?;
            if meter {
                charge_work(work, 1, limits)?;
            }
            let byte = input[cursor];
            cursor += 1;
            value = value
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(byte & 0x7f)))
                .ok_or(Error::SizeOverflow)?;
            if byte & 0x80 == 0 {
                break;
            }
            if value > MAX_TAG_NUMBER >> 7 {
                return Err(Error::SizeOverflow);
            }
        }
        if value > MAX_TAG_NUMBER {
            return Err(Error::SizeOverflow);
        }
        u64::from(value)
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
fn octet_field_size(payload_len: usize, rule: RecordEncoding, tag: Tag) -> Result<usize, Error> {
    if rule == RecordEncoding::Cer && payload_len > CER_FRAGMENT_MAX {
        fragmented_size_tagged(
            payload_len,
            payload_len.div_ceil(CER_FRAGMENT_MAX),
            false,
            tag,
        )
    } else {
        tagged_primitive_field_size(tag, payload_len)
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
fn bit_field_size(payload_len: usize, rule: RecordEncoding, tag: Tag) -> Result<usize, Error> {
    let content_len = payload_len.checked_add(1).ok_or(Error::SizeOverflow)?;
    if rule == RecordEncoding::Cer && content_len > CER_FRAGMENT_MAX {
        fragmented_size_tagged(
            payload_len,
            payload_len.div_ceil(CER_FRAGMENT_MAX - 1),
            true,
            tag,
        )
    } else {
        tagged_primitive_field_size(tag, content_len)
    }
}

/// Compute a tagged primitive TLV's exact encoded byte count.
///
/// # Parameters and returns
/// `tag` is its class/number; `content_len` is content bytes. Returns full TLV size.
///
/// # Errors
/// Returns `SizeOverflow` for arithmetic overflow or invalid tag values.
///
/// # Source, version, history, example
/// Source: X.690 minimal identifier and length forms. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged writers.
/// Example: `tagged_primitive_field_size(tag, 1)?`.
fn tagged_primitive_field_size(tag: Tag, content_len: usize) -> Result<usize, Error> {
    if tag.class == TagClass::Universal && tag.number < 31 {
        return primitive_field_size(content_len);
    }
    tag_identifier_size(tag)?
        .checked_add(length_size(content_len))
        .and_then(|n| n.checked_add(content_len))
        .ok_or(Error::SizeOverflow)
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
    push_bit_fragment_tagged(out, Tag::universal(3), payload, unused, limits)
}

/// Append primitive BIT STRING content under one effective identifier.
///
/// # Parameters and returns
/// `tag` is the root identifier; `payload` and `unused` describe bit content;
/// `limits` caps output. Returns success.
///
/// # Errors
/// Returns invalid padding, tag, output-limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING IMPLICIT tagging. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged string fields.
/// Example: used for a short implicitly tagged BIT STRING.
fn push_bit_fragment_tagged(
    out: &mut Vec<u8>,
    tag: Tag,
    payload: &[u8],
    unused: u8,
    limits: &Limits,
) -> Result<(), Error> {
    validate_bits(payload, unused)?;
    let size = payload.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    push_identifier_tagged(out, false, tag, limits)?;
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

/// Append a primitive definite TLV with a checked effective identifier.
///
/// # Parameters and returns
/// `tag` is the class/number identifier; `fragment` is encoded content; limits
/// cap output. Returns success.
///
/// # Errors
/// Returns invalid tag, output-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 primitive TLV encoding. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged record fields.
/// Example: writes an implicitly tagged BOOLEAN/INTEGER/string root.
fn push_primitive_tagged(
    out: &mut Vec<u8>,
    tag: Tag,
    fragment: &[u8],
    limits: &Limits,
) -> Result<(), Error> {
    push_identifier_tagged(out, false, tag, limits)?;
    push_length(out, fragment.len(), limits)?;
    push(out, fragment, limits)
}

/// Append a constructed identifier and indefinite-length marker.
///
/// # Parameters and returns
/// `out` receives the root header; `tag` is its effective identifier; `limits`
/// caps output. Returns success.
///
/// # Errors
/// Returns invalid tag, output-limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 CER indefinite constructed values. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: implicit string fragmentation.
/// Example: used before universal string fragments.
fn push_indefinite_header(out: &mut Vec<u8>, tag: Tag, limits: &Limits) -> Result<(), Error> {
    push_identifier_tagged(out, true, tag, limits)?;
    push(out, &[0x80], limits)
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
    let tag = if bits {
        Tag::universal(3)
    } else {
        Tag::universal(4)
    };
    fragmented_size_tagged(payload_len, fragments, bits, tag)
}

/// Compute CER fragmented size with a possibly implicit root identifier.
///
/// # Parameters and returns
/// `payload_len` is data octets; `fragments` is leaf count; `bits` adds one
/// count octet per BIT fragment; `tag` is the outer effective identifier.
/// Returns the exact total encoding size.
///
/// # Errors
/// Returns invalid tag or `SizeOverflow` on checked arithmetic failure.
///
/// # Source, version, history, example
/// Source: X.690 CER constructed string framing. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: IMPLICIT string roots.
/// Example: `fragmented_size_tagged(n, count, false, tag)?`.
fn fragmented_size_tagged(
    payload_len: usize,
    fragments: usize,
    bits: bool,
    tag: Tag,
) -> Result<usize, Error> {
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
    tag_identifier_size(tag)?
        .checked_add(3)
        .and_then(|n| n.checked_add(full_size))
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
    let number = u32::try_from(tag).map_err(|_| Error::SizeOverflow)?;
    let tag = Tag::new(TagClass::Universal, number)?;
    push_identifier_tagged(out, constructed, tag, limits)
}

/// Return the minimal identifier width for a checked tag.
///
/// # Parameters and returns
/// `tag` is a class and numeric tag. Returns one octet for low form and one
/// plus the needed base-128 group count for high form.
///
/// # Errors
/// Returns `InvalidEncoding` for a number outside the C tag range.
///
/// # Source, version, history, example
/// Source: X.690 identifier width. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: tagged record support.
/// Example: `tag_identifier_size(Tag::context_specific(31))? == 2`.
fn tag_identifier_size(tag: Tag) -> Result<usize, Error> {
    tag.validate()?;
    if tag.number < 31 {
        return Ok(1);
    }
    let mut groups = 1_usize;
    let mut value = tag.number >> 7;
    while value != 0 {
        groups = groups.checked_add(1).ok_or(Error::SizeOverflow)?;
        value >>= 7;
    }
    groups.checked_add(1).ok_or(Error::SizeOverflow)
}

/// Append a shortest class-aware identifier, including high-tag form.
///
/// # Parameters and returns
/// `out` receives bytes; `constructed` selects form; `tag` carries class and
/// number; `limits` caps output. Returns success.
///
/// # Errors
/// Returns invalid tag, output-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 identifier encoding. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: class-aware tags.
/// Example: emits canonical high-tag identifier groups.
fn push_identifier_tagged(
    out: &mut Vec<u8>,
    constructed: bool,
    tag: Tag,
    limits: &Limits,
) -> Result<(), Error> {
    tag.validate()?;
    let form = u8::from(constructed) << 5;
    let class = (tag.class as u8) << 6;
    if tag.number < 31 {
        let number = u8::try_from(tag.number).map_err(|_| Error::SizeOverflow)?;
        return push(out, &[class | form | number], limits);
    }
    push(out, &[class | form | 0x1f], limits)?;
    let mut groups = [0_u8; 5];
    let mut count = 0_usize;
    let mut number = tag.number;
    loop {
        groups[count] = (number & 0x7f) as u8;
        count += 1;
        number >>= 7;
        if number == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        let continuation = if index > 0 { 0x80 } else { 0 };
        push(out, &[groups[index] | continuation], limits)?;
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

    /// Advance a lexicographic permutation for exhaustive SET member-order tests.
    /// Source: test-only permutation algorithm; version: 2026-10-31.
    /// Inputs: a nonempty ascending suffix; returns whether it advanced.
    /// Errors: none; responsible: runtime maintainers; history: flat SET tests.
    /// Example: repeatedly call with `[0, 1, 2]` to visit all six permutations.
    fn next_permutation(values: &mut [usize]) -> bool {
        let Some(pivot) = (0..values.len().saturating_sub(1))
            .rev()
            .find(|index| values[*index] < values[*index + 1])
        else {
            return false;
        };
        let successor = (pivot + 1..values.len())
            .rev()
            .find(|index| values[pivot] < values[*index]);
        let Some(successor) = successor else {
            return false;
        };
        values.swap(pivot, successor);
        values[pivot + 1..].reverse();
        true
    }

    /// Check BER accepts every order and canonical SET output sorts by tag.
    /// Source: X.690 SET component rules; version: 2026-10-31; inputs: 720 orders.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER SET wave. Example: run via `cargo test`.
    #[test]
    fn set_reader_accepts_all_member_orders_and_writer_sorts() {
        let limits = Limits::default();
        let fields: [&[u8]; 6] = [
            &[0x01, 0x01, 0xff],
            &[0x02, 0x01, 0x07],
            &[0x03, 0x02, 0x00, 0x80],
            &[0x04, 0x01, 0xaa],
            &[0x05, 0x00],
            &[0x0a, 0x01, 0x02],
        ];
        let expected_tags = [
            TAG_ENUMERATED,
            TAG_OCTET_STRING,
            TAG_INTEGER,
            TAG_NULL,
            TAG_BIT_STRING,
            TAG_BOOLEAN,
        ];
        let mut permutation = [0, 1, 2, 3, 4, 5];
        loop {
            let mut input = vec![0x31, 18];
            for index in permutation {
                input.extend_from_slice(fields[index]);
            }
            input.extend_from_slice(&[0xde, 0xad]);

            let mut context = RecordContext::new(&limits);
            let mut reader = SetReader::new(&input, &expected_tags, &mut context).unwrap();
            while let Some(tag) = reader.next_field().unwrap() {
                match tag {
                    TAG_BOOLEAN => assert!(reader.read_boolean().unwrap()),
                    TAG_INTEGER => assert_eq!(reader.read_integer(-8, 8).unwrap(), 7),
                    TAG_BIT_STRING => {
                        let value = reader.read_bit_string(8, 8).unwrap();
                        assert_eq!(value.as_bytes(), &[0x80]);
                    }
                    TAG_OCTET_STRING => {
                        assert_eq!(reader.read_octet_string(1, 1).unwrap(), [0xaa]);
                    }
                    TAG_NULL => reader.read_null().unwrap(),
                    TAG_ENUMERATED => assert_eq!(reader.read_enumerated().unwrap(), 2),
                    _ => panic!("unsupported tag from validated SET reader"),
                }
            }
            let consumed = reader.finish().unwrap();
            assert_eq!(consumed.consumed_bytes, 20);
            assert_eq!(consumed.consumed_bits, 160);

            let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
            writer.write_boolean(true).unwrap();
            writer.write_integer(7, -8, 8).unwrap();
            writer.write_bit_string(&[0x80], 8, 8, 8).unwrap();
            writer.write_octet_string(&[0xaa], 1, 1).unwrap();
            writer.write_null().unwrap();
            writer.write_enumerated(2).unwrap();
            let mut canonical = vec![0x31, 18];
            for field in fields {
                canonical.extend_from_slice(field);
            }
            assert_eq!(writer.finish().unwrap().bytes, canonical);

            if !next_permutation(&mut permutation) {
                break;
            }
        }
    }

    /// Cover empty SET framing, canonical tag order, and writer order checks.
    /// Source: X.690 DER/CER SET; version: 2026-10-31; inputs: empty and fields.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER SET wave. Example: run via `cargo test`.
    #[test]
    fn set_writer_supports_empty_and_rejects_noncanonical_order() {
        let limits = Limits::default();
        for (rule, expected) in [
            (RecordEncoding::Der, vec![0x31, 0]),
            (RecordEncoding::Cer, vec![0x31, 0x80, 0, 0]),
        ] {
            let mut context = RecordContext::new(&limits);
            let encoded = SetWriter::new(rule, &mut context)
                .unwrap()
                .finish()
                .unwrap();
            assert_eq!(encoded.bytes, expected);

            let mut reader = SetReader::new(&expected, &[], &mut context).unwrap();
            assert_eq!(reader.next_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, expected.len());
        }

        let nonminimal_outer = [0x3f, 0x11, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new(&nonminimal_outer, &[], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), None);
        assert_eq!(
            reader.finish().unwrap().consumed_bytes,
            nonminimal_outer.len()
        );

        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer(1, 0, 2).unwrap();
        assert!(writer.write_boolean(false).is_err());
        assert!(writer.write_integer(2, 0, 2).is_err());
    }

    /// Decode a test SET by dispatching every returned universal tag.
    /// Source: test-only BER SET helper; version: 2026-10-31.
    /// Inputs: one SET prefix and its unique supported descriptor tags.
    /// Returns: exact prefix consumption; errors: malformed field or limits.
    /// Responsible: runtime maintainers; history: SET malformed-input tests.
    /// Example: `consume_set(&[0x31, 0], &[])?`.
    fn consume_set(input: &[u8], tags: &[u64]) -> Result<Decoded<()>, Error> {
        let mut context = RecordContext::new(&Limits::default());
        let mut reader = SetReader::new(input, tags, &mut context)?;
        while let Some(tag) = reader.next_field()? {
            match tag {
                TAG_BOOLEAN => {
                    let _ = reader.read_boolean()?;
                }
                TAG_INTEGER => {
                    let _ = reader.read_integer(i64::MIN, i64::MAX)?;
                }
                TAG_BIT_STRING => {
                    let _ = reader.read_bit_string(0, usize::MAX)?;
                }
                TAG_OCTET_STRING => {
                    let _ = reader.read_octet_string(0, usize::MAX)?;
                }
                TAG_NULL => reader.read_null()?,
                TAG_ENUMERATED => {
                    let _ = reader.read_enumerated()?;
                }
                _ => return Err(invalid("test SET reader returned an unknown field")),
            }
        }
        reader.finish()
    }

    /// Check SET malformed members, framing, descriptors, and shared budgets.
    /// Source: X.690 BER SET; version: 2026-10-31; inputs: hostile TLVs/limits.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER SET wave. Example: run via `cargo test`.
    #[test]
    fn set_reader_rejects_malformed_members_and_limits() {
        let limits = Limits::default();
        let malformed: &[&[u8]] = &[
            &[0x30, 0],
            &[0x31, 1, 0],
            &[0x31, 2, 1, 2],
            &[0x31, 4, 1, 1, 0xff, 0x05],
            &[0x31, 6, 1, 1, 0, 1, 1, 0],
            &[0x31, 2, 6, 0],
            &[0x31, 0x80],
            &[0x31, 0x80, 0, 1, 0xff, 0, 0],
            &[0x31, 0x80, 1, 1, 0xff],
            &[0x31, 5, 0x24, 0x80, 4, 1, 0xaa],
        ];
        for input in malformed {
            assert!(
                consume_set(input, &[1, 2, 3, 4, 5, 10]).is_err(),
                "accepted {input:02x?}"
            );
        }

        let too_many_tags = [1, 2, 3, 4, 5, 10, 1];
        let mut context = RecordContext::new(&limits);
        assert!(SetReader::new(&[0x31, 0], &too_many_tags, &mut context).is_err());

        let mut zero_work = limits;
        zero_work.max_work_bits = 0;
        let mut context = RecordContext::new(&zero_work);
        assert!(SetReader::new(&[0x31, 0], &[], &mut context).is_err());

        let mut storage_limited = limits;
        storage_limited.max_output_bytes = 2;
        let string_set = [0x31, 8, 4, 2, 0xaa, 0xbb, 3, 2, 0, 0x80];
        let mut context = RecordContext::new(&storage_limited);
        let mut reader = SetReader::new(&string_set, &[4, 3], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(4));
        assert_eq!(reader.read_octet_string(0, 2).unwrap(), [0xaa, 0xbb]);
        assert_eq!(reader.next_field().unwrap(), Some(3));
        assert!(reader.read_bit_string(0, 8).is_err());

        let mut small_output = limits;
        small_output.max_output_bytes = 3;
        let mut context = RecordContext::new(&small_output);
        assert!(SetWriter::new(RecordEncoding::Cer, &mut context).is_err());
    }

    /// Require canonical CER SET order by re-encoding with the same context.
    /// Source: X.690 CER SET sorting; version: 2026-10-31; inputs: tag permutations.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: first BER SET wave. Example: run via `cargo test`.
    #[test]
    fn strict_cer_set_rejects_unsorted_order_and_shares_work() {
        let limits = Limits::default();
        let mut encode_context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Cer, &mut encode_context).unwrap();
        writer.write_boolean(true).unwrap();
        writer.write_integer(7, 0, 8).unwrap();
        let canonical = writer.finish().unwrap();

        let mut canonical_context = RecordContext::new(&limits);
        let mut reader = SetReader::new(&canonical.bytes, &[1, 2], &mut canonical_context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(1));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_field().unwrap(), Some(2));
        assert_eq!(reader.read_integer(0, 8).unwrap(), 7);
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SetWriter::new(RecordEncoding::Cer, &mut canonical_context).unwrap();
        writer.write_boolean(true).unwrap();
        writer.write_integer(7, 0, 8).unwrap();
        let reencoded = writer.finish().unwrap();
        canonical_context
            .verify_canonical(&canonical.bytes, consumed.consumed_bytes, &reencoded.bytes)
            .unwrap();

        let noncanonical = [0x31, 0x80, 0x02, 0x01, 0x07, 0x01, 0x01, 0xff, 0, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new(&noncanonical, &[1, 2], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), Some(2));
        assert_eq!(reader.read_integer(0, 8).unwrap(), 7);
        assert_eq!(reader.next_field().unwrap(), Some(1));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();

        let mut writer = SetWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_boolean(true).unwrap();
        writer.write_integer(7, 0, 8).unwrap();
        let canonical = writer.finish().unwrap();
        assert!(context
            .verify_canonical(&noncanonical, consumed.consumed_bytes, &canonical.bytes)
            .is_err());

        let mut tight = limits;
        tight.max_work_bits = 70;
        let mut context = RecordContext::new(&tight);
        let mut reader = SetReader::new(&[0x31, 0x80, 0, 0], &[], &mut context).unwrap();
        assert_eq!(reader.next_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let writer = SetWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        let canonical = writer.finish().unwrap();
        assert!(context
            .verify_canonical(
                &[0x31, 0x80, 0, 0],
                consumed.consumed_bytes,
                &canonical.bytes
            )
            .is_err());
    }

    /// Round-trip tagged SEQUENCE and SET fields from all four BER classes.
    /// Source: X.690 identifier classes; version: 2026-11-01; inputs: four classes.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: implicit tagging wave. Example: run via `cargo test`.
    #[test]
    fn tagged_records_preserve_class_kind_and_set_order() {
        let limits = Limits::default();
        let universal = Tag::new(TagClass::Universal, 1).unwrap();
        let application = Tag::new(TagClass::Application, 30).unwrap();
        let context_specific = Tag::new(TagClass::ContextSpecific, 31).unwrap();
        let private = Tag::new(TagClass::Private, 128).unwrap();
        let fields = [
            RecordField::new(universal, FieldKind::Boolean).unwrap(),
            RecordField::new(application, FieldKind::Integer).unwrap(),
            RecordField::new(context_specific, FieldKind::OctetString).unwrap(),
            RecordField::new(private, FieldKind::Enumerated).unwrap(),
        ];

        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_tagged(universal, true).unwrap();
        writer.write_integer_tagged(application, 1, 0, 3).unwrap();
        writer
            .write_octet_string_tagged(context_specific, b"x", 1, 1)
            .unwrap();
        writer.write_enumerated_tagged(private, 2).unwrap();
        let encoded = writer.finish().unwrap();
        assert_eq!(
            encoded.bytes,
            [0x30, 15, 0x01, 1, 0xff, 0x5e, 1, 1, 0x9f, 0x1f, 1, b'x', 0xdf, 0x81, 0, 1, 2,]
        );

        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
        assert!(reader.next_field().is_err());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(universal));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(application));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 1);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(context_specific));
        assert_eq!(reader.read_octet_string(1, 1).unwrap(), [b'x']);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(private));
        assert_eq!(reader.read_enumerated().unwrap(), 2);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());

        let set_fields = [
            RecordField::new(Tag::new(TagClass::Private, 0).unwrap(), FieldKind::Null).unwrap(),
            RecordField::new(context_specific, FieldKind::OctetString).unwrap(),
            RecordField::new(application, FieldKind::Integer).unwrap(),
            RecordField::new(universal, FieldKind::Boolean).unwrap(),
        ];
        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_tagged(universal, false).unwrap();
        writer.write_integer_tagged(application, 1, 0, 3).unwrap();
        writer
            .write_octet_string_tagged(context_specific, b"x", 1, 1)
            .unwrap();
        writer
            .write_null_tagged(Tag::new(TagClass::Private, 0).unwrap())
            .unwrap();
        let canonical = writer.finish().unwrap();
        assert_eq!(
            canonical.bytes,
            [0x31, 12, 0x01, 1, 0, 0x5e, 1, 1, 0x9f, 0x1f, 1, b'x', 0xc0, 0]
        );

        let reversed = [
            0x31, 12, 0xc0, 0, 0x9f, 0x1f, 1, b'x', 0x5e, 1, 1, 0x01, 1, 0,
        ];
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new_tagged(&reversed, &set_fields, &mut context).unwrap();
        assert_eq!(
            reader.next_tagged_field().unwrap(),
            Some(Tag::new(TagClass::Private, 0).unwrap())
        );
        reader.read_null().unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(context_specific));
        assert_eq!(reader.read_octet_string(1, 1).unwrap(), [b'x']);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(application));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 1);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(universal));
        assert!(!reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();

        let mut context = RecordContext::new(&limits);
        let mut unordered = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        unordered
            .write_integer_tagged(application, 1, 0, 3)
            .unwrap();
        assert!(unordered.write_boolean_tagged(universal, true).is_err());
    }

    /// Round-trip same-kind fields under distinct effective tags and reject duplicates.
    /// Source: tagged record API regression; version: 2026-11-01; inputs: two BOOLEAN fields.
    /// Returns: assertions; errors: assertion failures; responsible: runtime maintainers.
    /// History: verifies tag-based field tracking. Example: run via `cargo test`.
    #[test]
    fn tagged_records_allow_same_kind_and_reject_duplicate_effective_tags() {
        let limits = Limits::default();
        let first = Tag::context_specific(2);
        let second = Tag::context_specific(3);
        let fields = [
            RecordField::new(first, FieldKind::Boolean).unwrap(),
            RecordField::new(second, FieldKind::Boolean).unwrap(),
        ];

        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_tagged(first, true).unwrap();
        writer.write_boolean_tagged(second, false).unwrap();
        let encoded_sequence = writer.finish().unwrap();
        assert_eq!(encoded_sequence.bytes, [0x30, 6, 0x82, 1, 0xff, 0x83, 1, 0]);

        let mut context = RecordContext::new(&limits);
        let mut reader =
            SequenceReader::new_tagged(&encoded_sequence.bytes, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(first));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(second));
        assert!(!reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();

        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_tagged(first, true).unwrap();
        writer.write_boolean_tagged(second, false).unwrap();
        let encoded_set = writer.finish().unwrap();
        assert_eq!(encoded_set.bytes, [0x31, 6, 0x82, 1, 0xff, 0x83, 1, 0]);

        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new_tagged(&encoded_set.bytes, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(first));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(second));
        assert!(!reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();

        let duplicate_fields = [fields[0], fields[0]];
        let mut context = RecordContext::new(&limits);
        assert!(SequenceReader::new_tagged(
            &encoded_sequence.bytes,
            &duplicate_fields,
            &mut context
        )
        .is_err());
        let mut context = RecordContext::new(&limits);
        assert!(
            SetReader::new_tagged(&encoded_set.bytes, &duplicate_fields, &mut context).is_err()
        );

        let duplicate_sequence = [0x30, 6, 0x82, 1, 0xff, 0x82, 1, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SequenceReader::new_tagged(&duplicate_sequence, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(first));
        assert!(reader.read_boolean().unwrap());
        assert!(reader.next_tagged_field().is_err());

        let duplicate_set = [0x31, 6, 0x82, 1, 0xff, 0x82, 1, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new_tagged(&duplicate_set, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(first));
        assert!(reader.read_boolean().unwrap());
        assert!(reader.next_tagged_field().is_err());

        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_tagged(first, true).unwrap();
        assert!(writer.write_boolean_tagged(first, false).is_err());
        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_tagged(first, true).unwrap();
        assert!(writer.write_boolean_tagged(first, false).is_err());
    }

    /// Cover C-compatible high-tag boundaries, aliases, truncation, and work.
    /// Source: C `ber_fetch_tag`; version: 2026-11-01; inputs: 30/31/127/128/max.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: class-aware BER parser. Example: run via `cargo test`.
    #[test]
    fn tagged_identifiers_match_c_range_and_ber_permissiveness() {
        let limits = Limits::default();
        let vectors: &[(u32, &[u8])] = &[
            (30, &[0x30, 3, 0x9e, 1, 0xff]),
            (31, &[0x30, 4, 0x9f, 0x1f, 1, 0xff]),
            (127, &[0x30, 4, 0x9f, 0x7f, 1, 0xff]),
            (128, &[0x30, 5, 0x9f, 0x81, 0, 1, 0xff]),
            (
                MAX_TAG_NUMBER,
                &[0x30, 8, 0x9f, 0x83, 0xff, 0xff, 0xff, 0x7f, 1, 0xff],
            ),
        ];
        for (number, expected) in vectors {
            let tag = Tag::new(TagClass::ContextSpecific, *number).unwrap();
            let field = RecordField::new(tag, FieldKind::Boolean).unwrap();
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
            writer.write_boolean_tagged(tag, true).unwrap();
            let encoded = writer.finish().unwrap();
            assert_eq!(encoded.bytes, *expected);

            let mut context = RecordContext::new(&limits);
            let fields = [field];
            let mut reader =
                SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
            assert!(reader.read_boolean().unwrap());
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            reader.finish().unwrap();
        }
        assert!(Tag::new(TagClass::ContextSpecific, MAX_TAG_NUMBER + 1).is_err());
        assert!(RecordField::new(Tag::universal(1), FieldKind::Integer).is_err());

        let overflow = [0x30, 8, 0x9f, 0x84, 0x80, 0x80, 0x80, 0, 1, 0xff];
        let tag31 = Tag::context_specific(31);
        let field = RecordField::new(tag31, FieldKind::Boolean).unwrap();
        let mut context = RecordContext::new(&limits);
        let fields = [field];
        let mut reader = SequenceReader::new_tagged(&overflow, &fields, &mut context).unwrap();
        assert!(reader.next_tagged_field().is_err());

        let truncated = [0x30, 3, 0x9f, 0x81, 0x80];
        let mut context = RecordContext::new(&limits);
        let fields = [field];
        let mut reader = SequenceReader::new_tagged(&truncated, &fields, &mut context).unwrap();
        assert!(reader.next_tagged_field().is_err());

        let mut long_alias = vec![0x30, 44, 0x9f];
        long_alias.extend([0x80; 40]);
        long_alias.extend([0x1f, 1, 0xff]);
        let mut context = RecordContext::new(&limits);
        let fields = [field];
        let mut reader = SequenceReader::new_tagged(&long_alias, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag31));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_boolean_tagged(tag31, true).unwrap();
        let canonical = writer.finish().unwrap();
        assert!(context
            .verify_canonical(&long_alias, consumed.consumed_bytes, &canonical.bytes)
            .is_err());

        let mut constrained = limits;
        constrained.max_work_bits = 80;
        let mut context = RecordContext::new(&constrained);
        let fields = [field];
        let mut reader = SequenceReader::new_tagged(&long_alias, &fields, &mut context).unwrap();
        assert!(reader.next_tagged_field().is_err());
    }

    /// Check tagged string short/fragment forms and universal nested fragments.
    /// Source: X.690 CER strings; version: 2026-11-01; inputs: 1000/1001 octets.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: implicit string root support. Example: run via `cargo test`.
    #[test]
    fn tagged_strings_replace_only_the_outer_identifier() {
        let limits = Limits::default();
        let octet_tag = Tag::context_specific(31);
        let octet_field = RecordField::new(octet_tag, FieldKind::OctetString).unwrap();
        for (size, prefix) in [
            (1000, &[0x9f, 0x1f, 0x82, 0x03, 0xe8][..]),
            (1001, &[0xbf, 0x1f, 0x80, 0x04, 0x82, 0x03, 0xe8][..]),
        ] {
            let value = vec![0x5a; size];
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
            writer
                .write_octet_string_tagged(octet_tag, &value, size, size)
                .unwrap();
            let encoded = writer.finish().unwrap();
            assert_eq!(&encoded.bytes[2..2 + prefix.len()], prefix);
            if size == 1001 {
                assert_eq!(encoded.bytes[9], 0x5a);
            }

            let mut context = RecordContext::new(&limits);
            let fields = [octet_field];
            let mut reader =
                SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(octet_tag));
            assert_eq!(reader.read_octet_string(size, size).unwrap(), value);
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            reader.finish().unwrap();
        }

        let bit_tag = Tag::new(TagClass::Application, 128).unwrap();
        let bit_field = RecordField::new(bit_tag, FieldKind::BitString).unwrap();
        for (size, constructed) in [(999, false), (1000, true)] {
            let bytes = vec![0xff; size];
            let bit_len = size * 8;
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
            writer
                .write_bit_string_tagged(bit_tag, &bytes, bit_len, bit_len, bit_len)
                .unwrap();
            let encoded = writer.finish().unwrap();
            if constructed {
                assert_eq!(&encoded.bytes[2..6], &[0x7f, 0x81, 0, 0x80]);
                assert_eq!(&encoded.bytes[6..11], &[0x03, 0x82, 0x03, 0xe8, 0]);
            } else {
                assert_eq!(&encoded.bytes[2..9], &[0x5f, 0x81, 0, 0x82, 0x03, 0xe8, 0]);
            }
            let mut context = RecordContext::new(&limits);
            let fields = [bit_field];
            let mut reader =
                SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(bit_tag));
            let decoded = reader.read_bit_string(bit_len, bit_len).unwrap();
            assert_eq!(decoded.as_bytes(), bytes);
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            reader.finish().unwrap();
        }

        let nested_octets = [
            0x30, 0x80, 0xbf, 0x1f, 0x80, 0x24, 0x80, 0x04, 1, b'a', 0, 0, 0, 0, 0, 0,
        ];
        let mut context = RecordContext::new(&limits);
        let fields = [octet_field];
        let mut reader = SequenceReader::new_tagged(&nested_octets, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(octet_tag));
        assert_eq!(reader.read_octet_string(1, 1).unwrap(), [b'a']);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, nested_octets.len());

        let bit_tag = Tag::context_specific(31);
        let bit_field = RecordField::new(bit_tag, FieldKind::BitString).unwrap();
        let nested_bits = [
            0x30, 0x80, 0xbf, 0x1f, 0x80, 0x23, 0x80, 0x03, 2, 5, 0xa0, 0, 0, 0, 0, 0, 0,
        ];
        let mut context = RecordContext::new(&limits);
        let fields = [bit_field];
        let mut reader = SequenceReader::new_tagged(&nested_bits, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(bit_tag));
        let decoded = reader.read_bit_string(3, 3).unwrap();
        assert_eq!(decoded.as_bytes(), &[0xa0]);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();
    }

    /// Decode, re-encode, and compare a two-field tagged CER SET.
    /// Source: tagged CER budget test helper; version: 2026-11-01.
    /// Inputs: canonical CER SET and work ceiling. Returns cumulative work used.
    /// Errors: malformed input, canonical mismatch, or exceeded budgets.
    /// Responsible: runtime maintainers; history: shared tagged budget tests.
    /// Example: `tagged_set_cer_work(input, ceiling)?`.
    fn tagged_set_cer_work(input: &[u8], max_work_bits: usize) -> Result<usize, Error> {
        let limits = Limits {
            max_work_bits,
            ..Limits::default()
        };
        let boolean_tag = Tag::context_specific(31);
        let octet_tag = Tag::context_specific(32);
        let fields = [
            RecordField::new(boolean_tag, FieldKind::Boolean)?,
            RecordField::new(octet_tag, FieldKind::OctetString)?,
        ];
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new_tagged(input, &fields, &mut context)?;
        let mut boolean = false;
        let mut octets = Vec::new();
        while let Some(tag) = reader.next_tagged_field()? {
            match tag {
                tag if tag == boolean_tag => boolean = reader.read_boolean()?,
                tag if tag == octet_tag => octets = reader.read_octet_string(1, 1)?,
                _ => return Err(invalid("tagged SET budget helper found unknown field")),
            }
        }
        let consumed = reader.finish()?;
        let mut writer = SetWriter::new(RecordEncoding::Cer, &mut context)?;
        writer.write_boolean_tagged(boolean_tag, boolean)?;
        writer.write_octet_string_tagged(octet_tag, &octets, 1, 1)?;
        let canonical = writer.finish()?;
        context.verify_canonical(input, consumed.consumed_bytes, &canonical.bytes)?;
        Ok(context.work_used)
    }

    /// Check tagged SET retained storage and exact cumulative strict CER work.
    /// Source: operation-wide record budgets; version: 2026-11-01; inputs: 2 fields.
    /// Returns: assertions; errors: assertion failures; responsible: maintainers.
    /// History: tagged record budget tests. Example: run via `cargo test`.
    #[test]
    fn tagged_record_budgets_cover_fields_reencode_and_compare() {
        let retained = [0x31, 10, 0x9f, 0x1f, 2, 0xaa, 0xbb, 0x9f, 0x20, 2, 0, 0x80];
        let fields = [
            RecordField::new(Tag::context_specific(31), FieldKind::OctetString).unwrap(),
            RecordField::new(Tag::context_specific(32), FieldKind::BitString).unwrap(),
        ];
        let limits = Limits {
            max_output_bytes: 2,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new_tagged(&retained, &fields, &mut context).unwrap();
        assert_eq!(
            reader.next_tagged_field().unwrap(),
            Some(Tag::context_specific(31))
        );
        assert_eq!(reader.read_octet_string(2, 2).unwrap(), [0xaa, 0xbb]);
        assert_eq!(
            reader.next_tagged_field().unwrap(),
            Some(Tag::context_specific(32))
        );
        assert!(reader.read_bit_string(8, 8).is_err());

        let canonical = [0x31, 0x80, 0x9f, 0x1f, 1, 0xff, 0x9f, 0x20, 1, b'x', 0, 0];
        let required = tagged_set_cer_work(&canonical, usize::MAX).unwrap();
        assert_eq!(tagged_set_cer_work(&canonical, required).unwrap(), required);
        assert!(tagged_set_cer_work(&canonical, required - 1).is_err());
    }
}
