//! Checked BER parsing and DER/CER codecs for OIDs, ENUMERATED, and strings.
//!
//! Original source: X.690 BER/DER/CER rules and asn1c runtime behavior.
//! Version/date: first expansion, 2026-10-31. Responsible party: asn1c
//! maintainers. Example: `decode_octet_string_ber(input, &Limits::default())?`.

use crate::{BitStringValue, Decoded, Encoded, Error, Limits, Resource};

/// Maximum constructed-TLV nesting accepted by this parser.
/// Initial fixed cap aligned with the C codec's `ASN_STACK_OVERFLOW_LIMIT` (30).
const MAX_DEPTH: usize = 30;
/// Maximum simultaneous parent and child record buffer capacity.
const MAX_RECORD_SCRATCH_BYTES: usize = 128 * 1024 * 1024;
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
const TAG_OBJECT_IDENTIFIER: u32 = 6;
const TAG_RELATIVE_OID: u32 = 13;
const UTC_WINDOW_MINUTES: i64 = 36_525 * 1_440;
/// Maximum simultaneous retained and canonical character-string buffer capacity.
const MAX_CHARACTER_STRING_SCRATCH_BYTES: usize = 128 * 1024 * 1024;
/// Maximum simultaneous retained and canonical OID codec buffer capacity.
const MAX_OID_SCRATCH_BYTES: usize = 128 * 1024 * 1024;
const MAX_SEQUENCE_FIELDS: usize = 6;
/// Largest BER tag number representable by the C runtime's packed tag value.
pub const MAX_TAG_NUMBER: u32 = 0x3fff_ffff;

/// Direct untagged ASN.1 character-string root supported by the BER/CER runtime.
///
/// `TeletexString`/`T61String` share universal tag 20; `VisibleString`/
/// `ISO646String` share tag 26. Values preserve their selected type identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CharacterStringKind {
    /// `ObjectDescriptor`, universal tag 7; arbitrary bytes under C behavior.
    ObjectDescriptor,
    /// `UTF8String`, universal tag 12; validates C's minimal 1-6 byte forms in CER.
    Utf8String,
    /// `NumericString`, universal tag 18.
    NumericString,
    /// `PrintableString`, universal tag 19.
    PrintableString,
    /// `TeletexString`, universal tag 20; arbitrary bytes under C behavior.
    TeletexString,
    /// `T61String` alias, universal tag 20.
    T61String,
    /// `VideotexString`, universal tag 21; arbitrary bytes under C behavior.
    VideotexString,
    /// `IA5String`, universal tag 22.
    Ia5String,
    /// `GraphicString`, universal tag 25; arbitrary bytes under C behavior.
    GraphicString,
    /// `VisibleString`, universal tag 26.
    VisibleString,
    /// `ISO646String` alias, universal tag 26.
    Iso646String,
    /// `GeneralString`, universal tag 27; arbitrary bytes under C behavior.
    GeneralString,
    /// `UniversalString`, universal tag 28; content length must be divisible by four.
    UniversalString,
    /// `BMPString`, universal tag 30; content length must be divisible by two.
    BmpString,
}

impl CharacterStringKind {
    /// Return the selected type's intrinsic universal tag number.
    ///
    /// # Parameters and returns
    /// No parameters. Returns one supported tag number from the enum variant.
    ///
    /// # Errors
    /// This mapping cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 universal character-string tags. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct character-string gate.
    /// Example: `CharacterStringKind::Utf8String.tag_number() == 12`.
    #[must_use]
    pub const fn tag_number(self) -> u32 {
        match self {
            Self::ObjectDescriptor => 7,
            Self::Utf8String => 12,
            Self::NumericString => 18,
            Self::PrintableString => 19,
            Self::TeletexString | Self::T61String => 20,
            Self::VideotexString => 21,
            Self::Ia5String => 22,
            Self::GraphicString => 25,
            Self::VisibleString | Self::Iso646String => 26,
            Self::GeneralString => 27,
            Self::UniversalString => 28,
            Self::BmpString => 30,
        }
    }
}

/// Owned raw octets for a direct ASN.1 character-string value.
///
/// BER decoding and DER encoding preserve bytes. CER applies the C descriptor's
/// content check for the stored `kind`; the type has no infallible `Clone`.
#[derive(Debug, Eq, PartialEq)]
pub struct CharacterString {
    /// Selected ASN.1 string type used for tag and CER checks; state variable.
    kind: CharacterStringKind,
    /// Owned raw content octets; state variable.
    bytes: Vec<u8>,
}

impl CharacterString {
    /// Copy raw bytes into a typed string value without applying CER validation.
    ///
    /// # Parameters and returns
    /// `kind` fixes the intrinsic type; `bytes` is raw content; `limits` caps
    /// input, retained output, and copy work. Returns an owned value.
    ///
    /// # Errors
    /// Returns resource, checked-size, or fallible allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: C BER/DER callback timing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: `CharacterString::try_from_bytes(kind, b"abc", limits)?`.
    pub fn try_from_bytes(
        kind: CharacterStringKind,
        bytes: &[u8],
        limits: &Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            kind,
            bytes: copy_character_string_bytes(bytes, limits)?,
        })
    }

    /// Return the selected kind.
    ///
    /// # Parameters and returns
    /// No parameters. Returns the Copy enum selected at construction.
    ///
    /// # Errors
    /// This accessor cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: direct character-string API. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: `value.kind() == CharacterStringKind::Ia5String`.
    #[must_use]
    pub const fn kind(&self) -> CharacterStringKind {
        self.kind
    }

    /// Borrow the raw content bytes without applying a character constraint.
    ///
    /// # Parameters and returns
    /// No parameters. Returns stored content bytes.
    ///
    /// # Errors
    /// This accessor cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: direct character-string API. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: `value.as_bytes() == b"abc"`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Canonical encoded content octets for an ASN.1 OBJECT IDENTIFIER.
///
/// Each base-128 subidentifier is minimally encoded. The first subidentifier
/// combines the first two arcs; this type intentionally exposes encoded content
/// rather than a machine-sized numeric arc representation.
#[derive(Debug, Eq, PartialEq)]
pub struct ObjectIdentifier {
    /// Canonical nonempty base-128 OBJECT IDENTIFIER content; state variable.
    content: Vec<u8>,
}

impl ObjectIdentifier {
    /// Create an OID from encoded content, removing redundant leading `0x80` groups.
    ///
    /// # Parameters and returns
    /// `content` is the OID's encoded subidentifier content; `limits` caps input,
    /// retained output, and work. Returns canonical content.
    ///
    /// # Errors
    /// Returns invalid encoding for empty or unterminated content, resource
    /// limit errors, checked-size errors, or fallible allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 8.19. Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: direct OID runtime gate. Example: `ObjectIdentifier::try_from_content(&[42], limits)?`.
    pub fn try_from_content(content: &[u8], limits: &Limits) -> Result<Self, Error> {
        Ok(Self {
            content: normalize_oid_content(content, limits)?,
        })
    }

    /// Borrow the canonical encoded OID content octets.
    ///
    /// # Parameters and returns
    /// No parameters. Returns nonempty, minimal base-128 subidentifier content.
    ///
    /// # Errors
    /// This accessor cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 8.19 content form. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID runtime gate.
    /// Example: `oid.as_content() == [42]`.
    #[must_use]
    pub fn as_content(&self) -> &[u8] {
        &self.content
    }
}

/// Canonical encoded content octets for an ASN.1 RELATIVE-OID.
///
/// Every arc is a minimally encoded base-128 subidentifier. The value keeps
/// raw content octets so arc size is not limited by a machine integer.
#[derive(Debug, Eq, PartialEq)]
pub struct RelativeOid {
    /// Canonical nonempty base-128 RELATIVE-OID content; state variable.
    content: Vec<u8>,
}

impl RelativeOid {
    /// Create a RELATIVE-OID from content, removing redundant leading `0x80` groups.
    ///
    /// # Parameters and returns
    /// `content` is encoded base-128 arc content; `limits` caps input, retained
    /// output, and work. Returns canonical content.
    ///
    /// # Errors
    /// Returns invalid encoding for empty or unterminated content, resource
    /// limit errors, checked-size errors, or fallible allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 8.20. Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: direct OID runtime gate. Example: `RelativeOid::try_from_content(&[42], limits)?`.
    pub fn try_from_content(content: &[u8], limits: &Limits) -> Result<Self, Error> {
        Ok(Self {
            content: normalize_oid_content(content, limits)?,
        })
    }

    /// Borrow the canonical encoded RELATIVE-OID content octets.
    ///
    /// # Parameters and returns
    /// No parameters. Returns nonempty, minimal base-128 arc content.
    ///
    /// # Errors
    /// This accessor cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 8.20 content form. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID runtime gate.
    /// Example: `oid.as_content() == [42]`.
    #[must_use]
    pub fn as_content(&self) -> &[u8] {
        &self.content
    }
}

/// Raw octets for a direct ASN.1 `IA5String` value.
///
/// BER decoding and DER encoding preserve every octet. CER operations apply
/// the 7-bit IA5 constraint, matching the C runtime's codec timing.
#[derive(Debug, Eq, PartialEq)]
pub struct Ia5String {
    /// Owned raw value octets; state variable.
    bytes: Vec<u8>,
}

impl Ia5String {
    /// Copy raw `IA5String` bytes without applying the CER-only repertoire check.
    ///
    /// # Parameters and returns
    /// `bytes` is the raw content; `limits` caps input, retained output, and
    /// copy work. Returns an owned value without cloning.
    ///
    /// # Errors
    /// Returns input/output/work/scratch limits, checked-size errors, or an
    /// allocation error. No panic.
    ///
    /// # Source, version, history, example
    /// Source: C `IA5String` BER/DER codec timing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: `Ia5String::try_from_bytes(&[0x41], limits)?`.
    pub fn try_from_bytes(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        Ok(Self {
            bytes: copy_character_string_bytes(bytes, limits)?,
        })
    }

    /// Borrow the raw `IA5String` content bytes.
    ///
    /// # Parameters and returns
    /// No parameters. Returns stored bytes without applying a repertoire check.
    ///
    /// # Errors
    /// This accessor cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: C `IA5String` BER/DER codec timing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: `value.as_bytes() == [0x41]`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Raw octets for a direct ASN.1 `UTCTime` value.
///
/// BER decoding and DER encoding preserve bytes. CER validates and normalizes
/// the time text. The value has no infallible `Clone` implementation.
#[derive(Debug, Eq, PartialEq)]
pub struct UtcTime {
    /// Owned raw time-content octets; state variable.
    bytes: Vec<u8>,
}

impl UtcTime {
    /// Copy raw `UTCTime` content without applying the CER syntax check.
    ///
    /// # Parameters and returns
    /// `bytes` is raw content; `limits` caps input, retained output, and copy
    /// work. Returns an owned value without cloning.
    ///
    /// # Errors
    /// Returns input/output/work/scratch limits, checked-size errors, or a
    /// fallible allocation error.
    ///
    /// # Source, version, history, example
    /// Source: C `UTCTime` BER/DER codec timing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: `UtcTime::try_from_bytes(b"991231235959Z", limits)?`.
    pub fn try_from_bytes(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        Ok(Self {
            bytes: copy_character_string_bytes(bytes, limits)?,
        })
    }

    /// Borrow the raw `UTCTime` content bytes.
    ///
    /// # Parameters and returns
    /// No parameters. Returns stored bytes without applying a syntax check.
    ///
    /// # Errors
    /// This accessor cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: C `UTCTime` BER/DER codec timing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: `value.as_bytes() == b"991231235959Z"`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

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
    /// Inline constructed SEQUENCE record content.
    Sequence,
}

/// Wire tagging mode stored in a checked record descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaggingMode {
    /// The effective identifier replaces the intrinsic universal identifier.
    Implicit,
    /// The effective constructed identifier wraps one intrinsic universal TLV.
    Explicit,
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
            Self::Sequence => TAG_SEQUENCE,
        }
    }
}

/// Effective identifier and semantic type for one direct record member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordField {
    /// Effective BER identifier used as an IMPLICIT replacement or EXPLICIT wrapper.
    tag: Tag,
    /// ASN.1 primitive kind whose content rules remain in effect.
    kind: FieldKind,
    /// Whether `tag` replaces or wraps the intrinsic universal identifier.
    tagging: TaggingMode,
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
        validate_field_mode(tag, kind, TaggingMode::Implicit)?;
        Ok(Self {
            tag,
            kind,
            tagging: TaggingMode::Implicit,
        })
    }

    /// Construct a checked context-specific EXPLICIT field descriptor.
    ///
    /// The effective tag wraps exactly one TLV with the primitive kind's
    /// intrinsic universal tag. Runtime readers validate the complete wrapper.
    ///
    /// # Parameters and returns
    /// `tag` is the context-specific wrapper identifier; `kind` selects the
    /// inner universal value. Returns a validated explicit descriptor.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` unless `tag` is a bounded context-specific tag.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `RecordField::new_explicit(Tag::context_specific(2), FieldKind::Boolean)?`.
    pub fn new_explicit(tag: Tag, kind: FieldKind) -> Result<Self, Error> {
        validate_field_mode(tag, kind, TaggingMode::Explicit)?;
        Ok(Self {
            tag,
            kind,
            tagging: TaggingMode::Explicit,
        })
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

/// Validate one field descriptor's effective tag and tagging mode.
///
/// # Parameters and returns
/// `tag` is the effective identifier, `kind` is its ASN.1 value kind, and
/// `mode` says whether the tag replaces or wraps the intrinsic identifier.
/// Returns success for a supported descriptor.
///
/// # Errors
/// Returns `InvalidEncoding` for an out-of-range tag, a mismatched universal
/// implicit tag, or an explicit tag outside the context-specific class.
///
/// # Source, version, history, example
/// Source: X.690 implicit/explicit tagging. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit record support.
/// Example: called by both `RecordField` constructors and writers.
fn validate_field_mode(tag: Tag, kind: FieldKind, mode: TaggingMode) -> Result<(), Error> {
    match mode {
        TaggingMode::Implicit => validate_field_descriptor(tag, kind),
        TaggingMode::Explicit => {
            tag.validate()?;
            if tag.class != TagClass::ContextSpecific {
                return Err(invalid("EXPLICIT record tags must be context-specific"));
            }
            Ok(())
        }
    }
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
        TAG_SEQUENCE => Some(FieldKind::Sequence),
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
/// also caps cumulative OCTET/BIT STRING payload allocation charges. Nested
/// callback failures roll back traversal but keep work and allocation charges.
pub struct RecordContext {
    /// Copied caller ceilings for this complete operation.
    limits: Limits,
    /// Cumulative work; this is a state variable.
    work_used: usize,
    /// Cumulative decoded string payload bytes charged to this operation; state variable.
    retained_bytes: usize,
    /// Cumulative decoded string Vec capacity charged to this operation; state variable.
    retained_capacity: usize,
    /// Active nested record and explicit-wrapper depth; state variable.
    depth: usize,
    /// Active nested child records; this stage permits one; state variable.
    nested_record_depth: usize,
    /// Whether the caller opted into nested aggregate scratch accounting.
    nested_accounting: bool,
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
    /// First byte of the outer parent field, including an EXPLICIT wrapper.
    field_start: usize,
    /// Effective mode used by the parent field descriptor.
    tagging: TaggingMode,
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
    /// Parent buffer capacity retained while this nested writer is active.
    parent_capacity: Option<usize>,
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
    /// Schema index of the pending child; state variable.
    current_index: Option<usize>,
    /// SEQUENCE index before the pending child; rollback snapshot state variable.
    current_previous_index: Option<usize>,
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
        Self::with_nested_accounting(limits, false)
    }

    /// Create one operation context with nested-record scratch accounting.
    ///
    /// Generated types containing an inline SEQUENCE use this at the public
    /// operation boundary, even when the child is OPTIONAL and absent.
    ///
    /// # Parameters and returns
    /// `limits` supplies whole-input, complete-output, and cumulative-work
    /// maxima. Returns a context enforcing aggregate nested scratch bounds.
    ///
    /// # Errors
    /// This constructor cannot fail and raises no exception.
    ///
    /// # Source, version, history, example
    /// Source: compatible nested record policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: inline SEQUENCE support.
    /// Example: `let mut context = RecordContext::new_nested(&limits);`.
    #[must_use]
    pub const fn new_nested(limits: &Limits) -> Self {
        Self::with_nested_accounting(limits, true)
    }

    /// Initialize the shared record counters while preserving the public Limits API.
    ///
    /// # Parameters and returns
    /// `limits` supplies existing ceilings; `nested` enables aggregate scratch
    /// accounting. Returns an unused operation context.
    ///
    /// # Errors
    /// This helper cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: bounded record-operation policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested context opt-in.
    /// Example: called by `new` and `new_nested`.
    const fn with_nested_accounting(limits: &Limits, nested: bool) -> Self {
        Self {
            limits: *limits,
            work_used: 0,
            retained_bytes: 0,
            retained_capacity: 0,
            depth: 0,
            nested_record_depth: 0,
            nested_accounting: nested,
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

    /// Reserve one or more bounded nested record layers.
    ///
    /// # Parameters and returns
    /// `layers` counts nested SEQUENCE and EXPLICIT wrapper levels. Returns
    /// success when the cumulative depth remains within `MAX_DEPTH`.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when the finite nesting ceiling is exceeded.
    ///
    /// # Source, version, history, example
    /// Source: bounded record traversal policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested record support.
    /// Example: nested callbacks reserve one layer plus any wrapper.
    fn enter_nested(&mut self, layers: usize) -> Result<(), Error> {
        if !self.nested_accounting {
            return Err(invalid("nested records require RecordContext::new_nested"));
        }
        if self.nested_record_depth != 0 {
            return Err(invalid("nested records support one inline child level"));
        }
        let next_depth = self.depth.checked_add(layers).ok_or(Error::SizeOverflow)?;
        if next_depth > MAX_DEPTH {
            return Err(invalid("record nesting exceeds depth limit"));
        }
        self.depth = next_depth;
        self.nested_record_depth += 1;
        Ok(())
    }

    /// Release the nesting layers reserved by one completed callback.
    ///
    /// # Parameters and returns
    /// `layers` is the count previously accepted by `enter_nested`. Returns
    /// nothing; inconsistent release leaves the state at zero.
    ///
    /// # Errors
    /// This cleanup helper cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: bounded record traversal policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested record support.
    /// Example: called after every nested callback result.
    const fn leave_nested(&mut self, layers: usize) {
        self.depth = self.depth.saturating_sub(layers);
        self.nested_record_depth = self.nested_record_depth.saturating_sub(1);
    }

    /// Return output limits remaining for one decoded-string allocation.
    ///
    /// # Parameters and returns
    /// Returns a copy with remaining cumulative payload and scratch ceilings;
    /// work is charged directly to this context during parsing.
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
        if self.nested_accounting {
            let scratch_remaining = MAX_RECORD_SCRATCH_BYTES
                .checked_sub(self.retained_capacity)
                .ok_or(Error::SizeOverflow)?;
            remaining.max_output_bytes = remaining.max_output_bytes.min(scratch_remaining);
        }
        Ok(remaining)
    }

    /// Charge decoded field allocation after a decoder checks the remaining cap.
    ///
    /// # Parameters and returns
    /// `bytes` is the field payload length; `capacity` is its Vec capacity.
    /// Charges remain cumulative even when a callback fails or the value drops.
    ///
    /// # Errors
    /// Returns checked-size or output-limit errors. Nested decodes also enforce
    /// the fixed scratch cap against cumulative capacity charges.
    ///
    /// # Source, version, history, example
    /// Source: sequence decoded-storage policy. Version: 2026-10-31.
    /// Responsible: asn1c maintainers. History: bounded string fields.
    /// Example: `context.retain_decoded(owned.len(), owned.capacity())?`.
    fn retain_decoded(&mut self, bytes: usize, capacity: usize) -> Result<(), Error> {
        let total = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or(Error::SizeOverflow)?;
        check(Resource::OutputBytes, total, self.limits.max_output_bytes)?;
        let total_capacity = self
            .retained_capacity
            .checked_add(capacity)
            .ok_or(Error::SizeOverflow)?;
        if self.nested_accounting {
            check_scratch_total(total_capacity, MAX_RECORD_SCRATCH_BYTES)?;
        }
        self.retained_bytes = total;
        self.retained_capacity = total_capacity;
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
        if context.nested_accounting {
            check_scratch_total(
                context
                    .retained_capacity
                    .checked_add(2)
                    .ok_or(Error::SizeOverflow)?,
                MAX_RECORD_SCRATCH_BYTES,
            )?;
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(2)
            .map_err(|_| Error::AllocationFailed { requested_bytes: 2 })?;
        if context.nested_accounting {
            check_scratch_total(
                context
                    .retained_capacity
                    .checked_add(bytes.capacity())
                    .ok_or(Error::SizeOverflow)?,
                MAX_RECORD_SCRATCH_BYTES,
            )?;
        }
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
            parent_capacity: None,
        })
    }

    /// Begin a nested child encoder while the parent buffer remains allocated.
    ///
    /// # Parameters and returns
    /// `rule` and `context` are inherited from the parent; `parent_capacity` is
    /// its retained `Vec` capacity. Returns a child with combined scratch checks.
    ///
    /// # Errors
    /// Returns output/scratch-limit, work-limit, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: shared nested record operation context. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: inline SEQUENCE support.
    /// Example: called only from `write_nested_sequence`.
    fn new_nested_writer(
        rule: RecordEncoding,
        context: &mut RecordContext,
        parent_capacity: usize,
    ) -> Result<SequenceWriter<'_>, Error> {
        check_combined_capacities(parent_capacity, 2, context.retained_capacity)?;
        let mut writer = Self::new_with_kind(rule, context, RecordKind::Sequence)?;
        writer.parent_capacity = Some(parent_capacity);
        writer.check_actual_nested_storage()?;
        Ok(writer)
    }

    /// Check projected child length against combined retained parent capacity.
    ///
    /// # Parameters and returns
    /// `child_len` is the projected complete child record size. Returns success
    /// when parent capacity plus child size fits both internal ceilings.
    ///
    /// # Errors
    /// Returns `LimitExceeded(OutputBytes)` or `SizeOverflow`.
    ///
    /// # Source, version, history, example
    /// Source: aggregate nested scratch policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: inline SEQUENCE support.
    /// Example: used before growing a nested child buffer.
    fn check_nested_storage(&self, child_len: usize) -> Result<(), Error> {
        if !self.context.nested_accounting {
            return Ok(());
        }
        let total = self
            .parent_capacity
            .unwrap_or(0)
            .checked_add(child_len)
            .and_then(|size| size.checked_add(self.context.retained_capacity))
            .ok_or(Error::SizeOverflow)?;
        check_scratch_total(total, MAX_RECORD_SCRATCH_BYTES)
    }

    /// Check actual Vec capacities after an allocator reservation.
    ///
    /// # Parameters and returns
    /// No parameters. Returns success if retained parent and child capacities
    /// fit the internal scratch and caller output ceilings.
    ///
    /// # Errors
    /// Returns `LimitExceeded(OutputBytes)` or `SizeOverflow`.
    ///
    /// # Source, version, history, example
    /// Source: aggregate nested scratch policy. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: inline SEQUENCE support.
    /// Example: called immediately after child Vec growth.
    fn check_actual_nested_storage(&self) -> Result<(), Error> {
        self.check_nested_storage(self.bytes.capacity())
    }

    /// Encode one inline child record in this parent's operation and buffer.
    ///
    /// # Parameters
    /// `field` supplies its natural, IMPLICIT, or EXPLICIT child tag;
    /// `encode` writes the child's direct primitive members.
    ///
    /// # Returns
    /// `Ok(())` after one complete child TLV has been committed to the parent.
    ///
    /// # Errors
    /// Returns descriptor, callback, resource, work, size, or allocation errors.
    /// The parent field list and bytes remain unchanged on failure.
    ///
    /// # Source, version, history, example
    /// Source: X.690 nested SEQUENCE framing. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: callback-based record stage.
    /// Example: `writer.write_nested_sequence(field, |child| child.write_integer(1, 0, 2))?`.
    pub fn write_nested_sequence<F>(&mut self, field: RecordField, encode: F) -> Result<(), Error>
    where
        F: FnOnce(&mut SequenceWriter<'_>) -> Result<(), Error>,
    {
        if field.kind != FieldKind::Sequence {
            return Err(invalid("nested record descriptor must have SEQUENCE kind"));
        }
        validate_field_mode(field.tag, field.kind, field.tagging)?;
        let layers = 1 + usize::from(field.tagging == TaggingMode::Explicit);
        self.context.enter_nested(layers)?;
        let parent_capacity = self.bytes.capacity();
        let result = self.write_nested_sequence_inner(field, encode, parent_capacity);
        self.context.leave_nested(layers);
        result
    }

    /// Build a child value, apply its tag mode, then append it transactionally.
    ///
    /// # Parameters and returns
    /// `field` and `encode` have the public callback method's meanings;
    /// `parent_capacity` is retained during child allocation. Returns success.
    ///
    /// # Errors
    /// Returns validation, callback, resource, size, or allocation errors.
    /// Parent bytes and field metadata change only after all checks pass.
    ///
    /// # Source, version, history, example
    /// Source: shared bounded record writer. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: inline SEQUENCE support.
    /// Example: called by `write_nested_sequence`.
    fn write_nested_sequence_inner<F>(
        &mut self,
        field: RecordField,
        encode: F,
        parent_capacity: usize,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut SequenceWriter<'_>) -> Result<(), Error>,
    {
        let mut child = Self::new_nested_writer(self.rule, self.context, parent_capacity)?;
        encode(&mut child)?;
        let mut encoded = child.finish()?;
        apply_nested_tagging(
            &mut encoded.bytes,
            field,
            self.rule,
            parent_capacity,
            self.context.retained_capacity,
            &self.context.limits,
        )?;
        self.prepare_field(field.tag, encoded.bytes.len())?;
        let requested_len = self
            .bytes
            .len()
            .checked_add(encoded.bytes.len())
            .ok_or(Error::SizeOverflow)?;
        let projected_parent_capacity = self.bytes.capacity().max(requested_len);
        check_combined_capacities(
            projected_parent_capacity,
            encoded.bytes.capacity(),
            self.context.retained_capacity,
        )?;
        self.bytes
            .try_reserve_exact(encoded.bytes.len())
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: requested_len,
            })?;
        check_combined_capacities(
            self.bytes.capacity(),
            encoded.bytes.capacity(),
            self.context.retained_capacity,
        )?;
        self.bytes.extend_from_slice(&encoded.bytes);
        self.remember_tag(field.tag)?;
        self.last_tag = Some(field.tag);
        Ok(())
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

    /// Append BOOLEAN inside one context-specific EXPLICIT wrapper.
    ///
    /// # Parameters and returns
    /// `tag` is the context-specific wrapper; `value` is the BOOLEAN value.
    /// Returns success after the wrapper and intrinsic universal child are added.
    ///
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT BOOLEAN. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `writer.write_boolean_explicit(Tag::context_specific(2), true)?`.
    pub fn write_boolean_explicit(&mut self, tag: Tag, value: bool) -> Result<(), Error> {
        let content = [if value { 0xff } else { 0 }];
        self.write_explicit_primitive(tag, FieldKind::Boolean, &content)
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

    /// Append NULL inside one context-specific EXPLICIT wrapper.
    ///
    /// # Parameters and returns
    /// `tag` is the context-specific wrapper. Returns success after the empty
    /// universal NULL child and wrapper are added.
    ///
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT NULL. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `writer.write_null_explicit(Tag::context_specific(5))?`.
    pub fn write_null_explicit(&mut self, tag: Tag) -> Result<(), Error> {
        self.write_explicit_primitive(tag, FieldKind::Null, &[])
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

    /// Append bounded INTEGER inside one context-specific EXPLICIT wrapper.
    ///
    /// # Parameters
    /// `tag` is the wrapper; `value` is signed; `lower` and `upper` are
    /// inclusive schema bounds.
    ///
    /// # Returns
    /// `Ok(())` after the minimal universal INTEGER and wrapper are appended.
    ///
    /// # Errors
    /// Returns invalid bounds/value/tag, duplicate/order, resource, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT INTEGER. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `writer.write_integer_explicit(tag, 3, 0, 8)?`.
    pub fn write_integer_explicit(
        &mut self,
        tag: Tag,
        value: i64,
        lower: i64,
        upper: i64,
    ) -> Result<(), Error> {
        crate::validate_integer(value, lower, upper)?;
        let full = value.to_be_bytes();
        let first = minimal_signed_start(full);
        self.write_explicit_primitive(tag, FieldKind::Integer, &full[first..])
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

    /// Append ENUMERATED inside one context-specific EXPLICIT wrapper.
    ///
    /// # Parameters and returns
    /// `tag` is the wrapper; `value` is the generated variant's signed number.
    /// Returns success after the universal child and wrapper are added.
    ///
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT ENUMERATED. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `writer.write_enumerated_explicit(tag, 1)?`.
    pub fn write_enumerated_explicit(&mut self, tag: Tag, value: i64) -> Result<(), Error> {
        let full = value.to_be_bytes();
        let first = minimal_signed_start(full);
        self.write_explicit_primitive(tag, FieldKind::Enumerated, &full[first..])
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

    /// Append OCTET STRING inside one context-specific EXPLICIT wrapper.
    ///
    /// # Parameters
    /// `tag` is the wrapper; `value` is payload; `lower` and `upper` are
    /// inclusive SIZE bounds.
    ///
    /// # Returns
    /// `Ok(())` after the wrapper contains one canonical universal OCTET STRING.
    ///
    /// # Errors
    /// Returns invalid SIZE/tag, duplicate/order, resource, size, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT OCTET STRING. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `writer.write_octet_string_explicit(tag, b"x", 1, 8)?`.
    pub fn write_octet_string_explicit(
        &mut self,
        tag: Tag,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        validate_size(value.len(), lower, upper)?;
        validate_field_mode(tag, FieldKind::OctetString, TaggingMode::Explicit)?;
        let inner_size = octet_field_size(value.len(), self.rule, Tag::universal(4))?;
        self.prepare_explicit_field(tag, inner_size)?;
        self.push_explicit_header(tag, inner_size)?;
        append_octet_value(&mut self.bytes, self.rule, value, &self.context.limits)?;
        self.finish_explicit_field(tag)
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

    /// Append BIT STRING inside one context-specific EXPLICIT wrapper.
    ///
    /// # Parameters
    /// `tag` is the wrapper; `bytes` are packed bits; `bit_len` is exact width;
    /// `lower_bits` and `upper_bits` are inclusive SIZE bounds.
    ///
    /// # Returns
    /// `Ok(())` after one canonical universal BIT STRING is wrapped.
    ///
    /// # Errors
    /// Returns malformed bits, invalid SIZE/tag, duplicate/order, resource, or
    /// allocation errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT BIT STRING. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: `writer.write_bit_string_explicit(tag, &[0x80], 1, 1, 8)?`.
    pub fn write_bit_string_explicit(
        &mut self,
        tag: Tag,
        bytes: &[u8],
        bit_len: usize,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<(), Error> {
        validate_packed_bits(bytes, bit_len)?;
        validate_size(bit_len, lower_bits, upper_bits)?;
        validate_field_mode(tag, FieldKind::BitString, TaggingMode::Explicit)?;
        let inner_size = bit_field_size(bytes.len(), self.rule, Tag::universal(3))?;
        self.prepare_explicit_field(tag, inner_size)?;
        self.push_explicit_header(tag, inner_size)?;
        append_bit_value(
            &mut self.bytes,
            self.rule,
            bytes,
            unused_bits(bit_len),
            &self.context.limits,
        )?;
        self.finish_explicit_field(tag)
    }

    /// Append one scalar universal TLV inside an EXPLICIT record wrapper.
    ///
    /// # Parameters and returns
    /// `tag` is the context-specific wrapper, `kind` defines the intrinsic
    /// universal child, and `content` is its primitive payload. Returns success.
    ///
    /// # Errors
    /// Returns tag, duplicate/order, output/work, size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT primitive encoding. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: used by BOOLEAN, NULL, INTEGER, and ENUMERATED writers.
    fn write_explicit_primitive(
        &mut self,
        tag: Tag,
        kind: FieldKind,
        content: &[u8],
    ) -> Result<(), Error> {
        validate_field_mode(tag, kind, TaggingMode::Explicit)?;
        let inner_tag = intrinsic_tag(kind);
        let inner_size = tagged_primitive_field_size(inner_tag, content.len())?;
        self.prepare_explicit_field(tag, inner_size)?;
        self.push_explicit_header(tag, inner_size)?;
        push_primitive_tagged(&mut self.bytes, inner_tag, content, &self.context.limits)?;
        self.finish_explicit_field(tag)
    }

    /// Check field uniqueness and complete explicit-wrapper resource bounds.
    ///
    /// # Parameters and returns
    /// `tag` is the effective wrapper; `inner_size` is its complete child TLV.
    /// Returns success after checking and charging the complete field.
    ///
    /// # Errors
    /// Returns duplicate/order, size, output-limit, work-limit, or tag errors.
    ///
    /// # Source, version, history, example
    /// Source: bounded explicit record writing. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: called before each explicit field append.
    fn prepare_explicit_field(&mut self, tag: Tag, inner_size: usize) -> Result<(), Error> {
        validate_field_mode(tag, FieldKind::Null, TaggingMode::Explicit)?;
        let field_size = explicit_wrapper_size(self.rule, tag, inner_size)?;
        self.prepare_field(tag, field_size)
    }

    /// Append the explicit constructed wrapper header for the active rule.
    ///
    /// # Parameters and returns
    /// `tag` is the effective identifier; `inner_size` is the single child's
    /// complete encoded size. Returns success after the header is appended.
    ///
    /// # Errors
    /// Returns size, output-limit, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: DER/CER explicit wrappers. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: called after `prepare_explicit_field`.
    fn push_explicit_header(&mut self, tag: Tag, inner_size: usize) -> Result<(), Error> {
        match self.rule {
            RecordEncoding::Der => {
                push_identifier_tagged(&mut self.bytes, true, tag, &self.context.limits)?;
                push_length(&mut self.bytes, inner_size, &self.context.limits)
            }
            RecordEncoding::Cer => {
                push_indefinite_header(&mut self.bytes, tag, &self.context.limits)
            }
        }
    }

    /// Append the CER terminator and record one completed explicit field.
    ///
    /// # Parameters and returns
    /// `tag` identifies the field just emitted. Returns success after recording it.
    ///
    /// # Errors
    /// Returns output-limit, allocation, or field-cap errors.
    ///
    /// # Source, version, history, example
    /// Source: CER EOC and record writer state. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit record support.
    /// Example: called after the child TLV has been appended.
    fn finish_explicit_field(&mut self, tag: Tag) -> Result<(), Error> {
        if self.rule == RecordEncoding::Cer {
            push(&mut self.bytes, &[0, 0], &self.context.limits)?;
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
    pub fn finish(self) -> Result<Encoded, Error> {
        self.finish_with_root_tag(None)
    }

    /// Finalize the record with one context-specific IMPLICIT root tag.
    ///
    /// # Parameters and returns
    /// `self` owns the fields; `tag` is the constructed context-specific
    /// replacement for the universal SEQUENCE identifier. Returns complete
    /// DER/CER bytes and their octet-aligned wire-bit count.
    ///
    /// # Errors
    /// Returns invalid-tag, output/work-limit, checked-size, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 IMPLICIT constructed tagging and BER tag range.
    /// Version: 2026-11-01. Responsible: asn1c maintainers.
    /// History: flat context-specific root support.
    /// Example: `writer.finish_tagged_root(Tag::context_specific(3))?`.
    pub fn finish_tagged_root(self, tag: Tag) -> Result<Encoded, Error> {
        validate_implicit_root_tag(tag)?;
        self.finish_with_root_tag(Some(tag))
    }

    /// Finalize framing and optionally replace the universal root identifier.
    ///
    /// # Parameters and returns
    /// `root_tag` is either absent for the unchanged universal output or the
    /// validated context-specific IMPLICIT replacement. Returns `Encoded`.
    ///
    /// # Errors
    /// Returns output/work-limit, checked-size, or allocation errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 DER/CER record framing. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: shared record finalizer.
    /// Example: called by `finish` and `finish_tagged_root`.
    fn finish_with_root_tag(mut self, root_tag: Option<Tag>) -> Result<Encoded, Error> {
        let mut root_identifier = [0_u8; 6];
        let identifier_len = if let Some(tag) = root_tag {
            encode_identifier_bytes(tag, true, &mut root_identifier)?
        } else {
            1
        };
        match self.rule {
            RecordEncoding::Der => {
                let content_len = self.bytes.len().checked_sub(2).ok_or(Error::SizeOverflow)?;
                let length_len = length_size(content_len);
                let natural_len = 1_usize
                    .checked_add(length_len)
                    .and_then(|n| n.checked_add(content_len))
                    .ok_or(Error::SizeOverflow)?;
                let total_len = natural_len
                    .checked_add(identifier_len - 1)
                    .ok_or(Error::SizeOverflow)?;
                self.context.check_output(total_len)?;
                self.check_nested_storage(total_len)?;
                self.context.charge(length_len)?;
                if content_len >= 128 {
                    self.context.charge(content_len)?;
                }
                patch_der_length(&mut self.bytes, content_len)?;
            }
            RecordEncoding::Cer => {
                let content_len = self.bytes.len().checked_sub(2).ok_or(Error::SizeOverflow)?;
                let total_len = identifier_len
                    .checked_add(1)
                    .and_then(|length| length.checked_add(content_len))
                    .and_then(|length| length.checked_add(2))
                    .ok_or(Error::SizeOverflow)?;
                self.context.check_output(total_len)?;
                self.check_nested_storage(total_len)?;
                self.context.charge(2)?;
                push(&mut self.bytes, &[0, 0], &self.context.limits)?;
            }
        }
        if root_tag.is_some() {
            retag_root_record(
                &mut self.bytes,
                &root_identifier[..identifier_len],
                self.context,
                self.parent_capacity.unwrap_or(0),
            )?;
        }
        self.check_actual_nested_storage()?;
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
        self.check_actual_nested_storage()?;
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
        let total_size = record_size(self.rule, next_content)?;
        self.context.check_output(total_size)?;
        self.check_nested_storage(total_size)?;
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

    /// Append an inline SEQUENCE SET member with its declared effective tag.
    ///
    /// # Parameters
    /// `field` describes the nested SEQUENCE tag; `encode` writes its children.
    ///
    /// # Returns
    /// `Ok(())` after the complete member is appended in SET tag order.
    ///
    /// # Errors
    /// Returns descriptor, callback, order, resource, size, or allocation errors.
    /// Parent SET bytes and field state remain unchanged on failure.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET and constructed components. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested record support.
    /// Example: `writer.write_nested_sequence(field, |child| encode_child(child))?`.
    pub fn write_nested_sequence<F>(&mut self, field: RecordField, encode: F) -> Result<(), Error>
    where
        F: FnOnce(&mut SequenceWriter<'_>) -> Result<(), Error>,
    {
        self.inner.write_nested_sequence(field, encode)
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

    /// Append BOOLEAN inside a context-specific EXPLICIT SET member.
    ///
    /// # Parameters and returns
    /// `tag` is the wrapper; `value` is BOOLEAN. Returns success after the child.
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, size, or allocation errors.
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT SET member. Version: 2026-11-01.
    /// Responsible: maintainers. History: explicit SET API. Example: tagged BOOLEAN.
    pub fn write_boolean_explicit(&mut self, tag: Tag, value: bool) -> Result<(), Error> {
        self.inner.write_boolean_explicit(tag, value)
    }

    /// Append NULL inside a context-specific EXPLICIT SET member.
    ///
    /// # Parameters and returns
    /// `tag` is the wrapper. Returns success after the empty child.
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, size, or allocation errors.
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT SET member. Version: 2026-11-01.
    /// Responsible: maintainers. History: explicit SET API. Example: tagged NULL.
    pub fn write_null_explicit(&mut self, tag: Tag) -> Result<(), Error> {
        self.inner.write_null_explicit(tag)
    }

    /// Append bounded INTEGER inside a context-specific EXPLICIT SET member.
    ///
    /// # Parameters and returns
    /// `tag` is the wrapper; `value` is signed; `lower` and `upper` are bounds.
    /// Returns success after the minimal INTEGER child.
    /// # Errors
    /// Returns invalid bounds/value/tag, duplicate/order, resource, or allocation.
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT SET member. Version: 2026-11-01.
    /// Responsible: maintainers. History: explicit SET API. Example: tagged INTEGER.
    pub fn write_integer_explicit(
        &mut self,
        tag: Tag,
        value: i64,
        lower: i64,
        upper: i64,
    ) -> Result<(), Error> {
        self.inner.write_integer_explicit(tag, value, lower, upper)
    }

    /// Append ENUMERATED inside a context-specific EXPLICIT SET member.
    ///
    /// # Parameters and returns
    /// `tag` is the wrapper; `value` is the signed variant number. Returns success.
    /// # Errors
    /// Returns invalid tag, duplicate/order, resource, size, or allocation errors.
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT SET member. Version: 2026-11-01.
    /// Responsible: maintainers. History: explicit SET API. Example: tagged enum.
    pub fn write_enumerated_explicit(&mut self, tag: Tag, value: i64) -> Result<(), Error> {
        self.inner.write_enumerated_explicit(tag, value)
    }

    /// Append OCTET STRING inside a context-specific EXPLICIT SET member.
    ///
    /// # Parameters and returns
    /// `tag` is the wrapper; `value` is payload; `lower` and `upper` are SIZE.
    /// Returns success after canonical DER/CER child encoding.
    /// # Errors
    /// Returns invalid SIZE/tag, duplicate/order, resource, size, or allocation.
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT SET member. Version: 2026-11-01.
    /// Responsible: maintainers. History: explicit SET API. Example: tagged octets.
    pub fn write_octet_string_explicit(
        &mut self,
        tag: Tag,
        value: &[u8],
        lower: usize,
        upper: usize,
    ) -> Result<(), Error> {
        self.inner
            .write_octet_string_explicit(tag, value, lower, upper)
    }

    /// Append BIT STRING inside a context-specific EXPLICIT SET member.
    ///
    /// # Parameters and returns
    /// `tag` is wrapper; `bytes` and `bit_len` describe packed bits; SIZE bounds
    /// are inclusive. Returns success after canonical child encoding.
    /// # Errors
    /// Returns malformed bits, invalid SIZE/tag, duplicate/order, resource, or
    /// allocation errors.
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT SET member. Version: 2026-11-01.
    /// Responsible: maintainers. History: explicit SET API. Example: tagged bits.
    pub fn write_bit_string_explicit(
        &mut self,
        tag: Tag,
        bytes: &[u8],
        bit_len: usize,
        lower_bits: usize,
        upper_bits: usize,
    ) -> Result<(), Error> {
        self.inner
            .write_bit_string_explicit(tag, bytes, bit_len, lower_bits, upper_bits)
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

    /// Finalize the SET with a context-specific IMPLICIT root tag.
    ///
    /// # Parameters and returns
    /// `self` owns the tag-sorted members; `tag` replaces the universal SET
    /// identifier. Returns complete DER/CER bytes and their bit length.
    ///
    /// # Errors
    /// Returns invalid-tag, output/work-limit, checked-size, or allocation
    /// errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 IMPLICIT SET tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET root support.
    /// Example: `writer.finish_tagged_root(Tag::context_specific(3))?`.
    pub fn finish_tagged_root(self, tag: Tag) -> Result<Encoded, Error> {
        self.inner.finish_tagged_root(tag)
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

    /// Start decoding a context-specific IMPLICIT SEQUENCE root.
    ///
    /// # Parameters
    /// `input` is the full available slice; `tag` is the constructed
    /// context-specific replacement identifier; `fields` lists the direct
    /// members; `context` supplies shared operation budgets.
    ///
    /// # Returns
    /// A cursor over the root record. `finish()` reports the exact consumed
    /// prefix, leaving any following bytes unconsumed.
    ///
    /// # Errors
    /// Returns invalid tag or descriptor, input-limit, truncation, framing,
    /// size, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 IMPLICIT constructed tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: flat tagged-root support.
    /// Example: `SequenceReader::new_tagged_root(input, tag, &fields, &mut context)?`.
    pub fn new_tagged_root(
        input: &'input [u8],
        tag: Tag,
        fields: &'tags [RecordField],
        context: &'context mut RecordContext,
    ) -> Result<Self, Error> {
        validate_implicit_root_tag(tag)?;
        Self::new_with_outer_tag(input, &[], Some(fields), context, RecordKind::Sequence, tag)
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
        Self::new_with_outer_tag(
            input,
            expected_tags,
            tagged_fields,
            context,
            kind,
            Tag::universal(u32::try_from(kind.universal_tag()).map_err(|_| Error::SizeOverflow)?),
        )
    }

    /// Construct a nested SEQUENCE reader with its caller's effective root tag.
    ///
    /// # Parameters and returns
    /// `input` is exactly one bounded child TLV; `fields` lists its direct
    /// members; `context` is shared with the parent; `outer_tag` is either the
    /// natural universal tag or an IMPLICIT replacement. Returns a cursor.
    ///
    /// # Errors
    /// Returns the same bounded framing and descriptor errors as the public
    /// constructors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 nested record boundaries. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested record support.
    /// Example: called by `read_nested_sequence` with its checked field span.
    fn new_nested(
        input: &'input [u8],
        fields: &'tags [RecordField],
        context: &'context mut RecordContext,
        outer_tag: Tag,
    ) -> Result<Self, Error> {
        Self::new_with_outer_tag(
            input,
            &[],
            Some(fields),
            context,
            RecordKind::Sequence,
            outer_tag,
        )
    }

    /// Parse a record whose outer tag is supplied by a schema descriptor.
    ///
    /// # Parameters and returns
    /// `input`, descriptor slices, `context`, and `kind` have the same roles as
    /// `new_with_kind`; `outer_tag` supplies its effective constructed tag.
    /// Returns a reader over the verified record body.
    ///
    /// # Errors
    /// Returns input-limit, descriptor, framing, tag/form, size, and work errors.
    ///
    /// # Source, version, history, example
    /// Source: X.690 implicit SEQUENCE tags. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested record support.
    /// Example: called by existing and nested reader constructors.
    fn new_with_outer_tag(
        input: &'input [u8],
        expected_tags: &'tags [u64],
        tagged_fields: Option<&'tags [RecordField]>,
        context: &'context mut RecordContext,
        kind: RecordKind,
        outer_tag: Tag,
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
                validate_field_mode(field.tag, field.kind, field.tagging)?;
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
        if header.class != outer_tag.class as u8
            || header.tag != u64::from(outer_tag.number)
            || !header.constructed
        {
            return Err(invalid("BER record has the wrong constructed outer tag"));
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
            current_index: None,
            current_previous_index: None,
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
        if self.indefinite && is_eoc(self.input, self.cursor, self.content_bound) {
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
        let (index, kind, field_tagging) = self.field_descriptor(effective_tag)?;
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
        let (mut field, end) = match field_tagging {
            TaggingMode::Implicit => {
                let end = scan(
                    self.input,
                    start,
                    self.content_bound,
                    2,
                    &mut self.context.work_used,
                    false,
                    &self.context.limits,
                )?;
                (field_span(header, start, end, effective_tag, kind)?, end)
            }
            TaggingMode::Explicit => scan_explicit_member(
                self.input,
                start,
                self.content_bound,
                header,
                kind,
                &mut self.context.work_used,
                &self.context.limits,
            )?,
        };
        field.field_start = start;
        field.tagging = field_tagging;
        self.current_previous_index = self.last_tag_index;
        self.current_index = Some(index);
        self.current = Some(field);
        self.last_tag_index = Some(index);
        self.seen_mask |= field_mask;
        self.cursor = end;
        Ok(Some(effective_tag))
    }

    /// Decode the current inline SEQUENCE with this operation's shared context.
    ///
    /// # Parameters
    /// `child_fields` lists the child's direct field descriptors; `decode`
    /// consumes them through a bounded child reader and returns the child value.
    ///
    /// # Returns
    /// The callback's value after runtime verification of the exact child span.
    ///
    /// # Errors
    /// Returns wrong field kind, malformed/trailing child data, callback,
    /// resource, depth, size, or work errors. Parent traversal rolls back on
    /// every error, while work and decoded-allocation charges remain cumulative.
    /// Callback side effects and captured values are outside this rollback.
    ///
    /// # Source, version, history, example
    /// Source: X.690 nested SEQUENCE decoding. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: callback-based record stage.
    /// Example: `reader.read_nested_sequence(&fields, |child| decode_child(child))?`.
    pub fn read_nested_sequence<T, F>(
        &mut self,
        child_fields: &[RecordField],
        decode: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&mut SequenceReader<'_, '_, '_>) -> Result<T, Error>,
    {
        let pending = self.current;
        let result = (|| {
            let field = self.current_field(FieldKind::Sequence)?;
            if !field.constructed {
                return Err(invalid("nested SEQUENCE field must use constructed form"));
            }
            let child_input = self
                .input
                .get(field.tlv_start..field.tlv_end)
                .ok_or_else(|| invalid("nested SEQUENCE span is outside parent input"))?;
            let root_tag = field.tag;
            let layers = 1 + usize::from(field.tagging == TaggingMode::Explicit);
            self.context.enter_nested(layers)?;
            let child_result = {
                let context = &mut *self.context;
                SequenceReader::new_nested(child_input, child_fields, context, root_tag).and_then(
                    |mut child| {
                        let value = decode(&mut child)?;
                        let completed = child.finish()?;
                        if completed.consumed_bytes != child_input.len() {
                            return Err(invalid("nested SEQUENCE has trailing encoded data"));
                        }
                        Ok(value)
                    },
                )
            };
            self.context.leave_nested(layers);
            child_result
        })();
        match result {
            Ok(value) => {
                self.current = None;
                self.current_index = None;
                self.current_previous_index = None;
                Ok(value)
            }
            Err(error) => {
                if let Some(field) = pending {
                    self.rollback_nested_field(field);
                }
                Err(error)
            }
        }
    }

    /// Restore parent traversal to the first byte of a failed nested field.
    ///
    /// # Parameters and returns
    /// `field` is the pending child span and carries its pre-wrapper start.
    /// Returns nothing after restoring parent traversal state. Work and
    /// decoded-allocation charges remain cumulative.
    ///
    /// # Errors
    /// This bounded state restoration cannot fail or panic.
    ///
    /// # Source, version, history, example
    /// Source: nested decode traversal contract. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: callback-based record stage.
    /// Example: called when the nested callback or child finalization fails.
    const fn rollback_nested_field(&mut self, field: FieldSpan) {
        if let Some(index) = self.current_index.take() {
            self.seen_mask &= !(1_u8 << index);
        }
        self.cursor = field.field_start;
        self.last_tag_index = self.current_previous_index.take();
        self.current = None;
        self.consumed_end = None;
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
        self.context
            .retain_decoded(decoded.value.len(), decoded.value.capacity())?;
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
        self.context.retain_decoded(
            decoded.value.as_bytes().len(),
            decoded.value.storage_capacity(),
        )?;
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

    /// Resolve one effective wire tag against the bounded field descriptor list.
    ///
    /// # Parameters and returns
    /// `tag` is the parsed class and number. Returns its schema index, primitive
    /// kind, and implicit/explicit mode after charging each descriptor check.
    ///
    /// # Errors
    /// Returns unknown-tag or cumulative-work errors.
    ///
    /// # Source, version, history, example
    /// Source: bounded BER record dispatch. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: explicit field mode.
    /// Example: called by `next_tagged_field`.
    fn field_descriptor(&mut self, tag: Tag) -> Result<(usize, FieldKind, TaggingMode), Error> {
        if let Some(fields) = self.tagged_fields {
            for (index, field) in fields.iter().enumerate() {
                self.context.charge(1)?;
                if field.tag == tag {
                    return Ok((index, field.kind, field.tagging));
                }
            }
        } else {
            if tag.class != TagClass::Universal {
                return Err(invalid("record contains an unknown effective tag"));
            }
            for (index, expected) in self.expected_tags.iter().enumerate() {
                self.context.charge(1)?;
                if *expected == u64::from(tag.number) {
                    let kind = field_kind_for_universal(*expected)
                        .ok_or_else(|| invalid("record descriptor has no field kind"))?;
                    return Ok((index, kind, TaggingMode::Implicit));
                }
            }
        }
        Err(invalid("record contains an unknown field tag"))
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

    /// Start decoding a context-specific IMPLICIT SET root.
    ///
    /// # Parameters
    /// `input` is the full available slice; `tag` is the constructed
    /// context-specific replacement identifier; `fields` lists direct members;
    /// `context` supplies shared input, output, retained-storage, and work limits.
    ///
    /// # Returns
    /// A cursor over the SET. `finish()` reports its exact prefix while members
    /// may appear in any BER order.
    ///
    /// # Errors
    /// Returns invalid tag or descriptor, input-limit, truncation, framing,
    /// size, or work errors. No panic.
    ///
    /// # Source, version, history, example
    /// Source: X.690 IMPLICIT constructed SET tagging. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: tagged SET root support.
    /// Example: `SetReader::new_tagged_root(input, tag, &fields, &mut context)?`.
    pub fn new_tagged_root(
        input: &'input [u8],
        tag: Tag,
        fields: &'tags [RecordField],
        context: &'context mut RecordContext,
    ) -> Result<Self, Error> {
        validate_implicit_root_tag(tag)?;
        Ok(Self {
            inner: SequenceReader::new_with_outer_tag(
                input,
                &[],
                Some(fields),
                context,
                RecordKind::Set,
                tag,
            )?,
        })
    }

    /// Decode the current inline SEQUENCE SET member in a bounded callback.
    ///
    /// # Parameters
    /// `child_fields` describes direct child members; `decode` consumes them
    /// through a child reader sharing this SET operation context.
    ///
    /// # Returns
    /// The callback's value after exact child boundary and EOC validation.
    ///
    /// # Errors
    /// Returns field, callback, malformed child, resource, depth, size, or work
    /// errors. Parent SET traversal rolls back on failure.
    ///
    /// # Source, version, history, example
    /// Source: X.690 nested SET component decoding. Version: 2026-11-01.
    /// Responsible: asn1c maintainers. History: nested record support.
    /// Example: `reader.read_nested_sequence(&fields, |child| decode_child(child))?`.
    pub fn read_nested_sequence<T, F>(
        &mut self,
        child_fields: &[RecordField],
        decode: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&mut SequenceReader<'_, '_, '_>) -> Result<T, Error>,
    {
        self.inner.read_nested_sequence(child_fields, decode)
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
#[derive(Clone, Copy)]
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

/// Encode an OBJECT IDENTIFIER as canonical DER.
///
/// # Parameters and returns
/// `value` contains canonical encoded content; `limits` caps output, scratch,
/// and work. Returns one primitive definite-length TLV.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 8.19. Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct OID runtime gate. Example: `encode_object_identifier_der(&oid, limits)?`.
pub fn encode_object_identifier_der(
    value: &ObjectIdentifier,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let mut work = 0;
    encode_oid_content(
        &value.content,
        value.content.capacity(),
        TAG_OBJECT_IDENTIFIER,
        limits,
        &mut work,
    )
}

/// Encode an OBJECT IDENTIFIER as canonical CER.
///
/// # Parameters and returns
/// `value` contains canonical encoded content; `limits` caps output, scratch,
/// and work. Returns one primitive definite-length TLV.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 8.19. Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct OID runtime gate. Example: `encode_object_identifier_cer(&oid, limits)?`.
pub fn encode_object_identifier_cer(
    value: &ObjectIdentifier,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let mut work = 0;
    encode_oid_content(
        &value.content,
        value.content.capacity(),
        TAG_OBJECT_IDENTIFIER,
        limits,
        &mut work,
    )
}

/// Decode and normalize one BER OBJECT IDENTIFIER prefix.
///
/// # Parameters and returns
/// `input` may include a suffix; `limits` caps the full input, retained value,
/// scratch, and cumulative work. Returns canonical content and exact prefix size.
///
/// # Errors
/// Returns malformed/truncated BER, empty or unterminated content, limit,
/// checked-size, or allocation errors. Empty content is deliberately rejected.
///
/// # Source, version, history, example
/// Source: X.690 8.19 and C BER aliases. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: `decode_object_identifier_ber(input, limits)?`.
pub fn decode_object_identifier_ber(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<ObjectIdentifier>, Error> {
    let decoded = decode_oid_content(input, TAG_OBJECT_IDENTIFIER, limits, false)?;
    Ok(Decoded {
        value: ObjectIdentifier {
            content: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Strictly decode one canonical CER OBJECT IDENTIFIER prefix.
///
/// # Parameters and returns
/// `input` may include a suffix; `limits` caps input and retained/output scratch,
/// plus one cumulative parse, normalization, re-encode, and compare budget.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` if the consumed prefix is not
/// canonical CER; empty and unterminated content are rejected.
///
/// # Source, version, history, example
/// Source: X.690 8.19 strict CER comparison. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: `decode_object_identifier_cer(input, limits)?`.
pub fn decode_object_identifier_cer(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<ObjectIdentifier>, Error> {
    let decoded = decode_oid_content(input, TAG_OBJECT_IDENTIFIER, limits, true)?;
    Ok(Decoded {
        value: ObjectIdentifier {
            content: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Encode a RELATIVE-OID as canonical DER.
///
/// # Parameters and returns
/// `value` contains canonical encoded content; `limits` caps output, scratch,
/// and work. Returns one primitive definite-length TLV.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 8.20. Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct OID runtime gate. Example: `encode_relative_oid_der(&oid, limits)?`.
pub fn encode_relative_oid_der(value: &RelativeOid, limits: &Limits) -> Result<Encoded, Error> {
    let mut work = 0;
    encode_oid_content(
        &value.content,
        value.content.capacity(),
        TAG_RELATIVE_OID,
        limits,
        &mut work,
    )
}

/// Encode a RELATIVE-OID as canonical CER.
///
/// # Parameters and returns
/// `value` contains canonical encoded content; `limits` caps output, scratch,
/// and work. Returns one primitive definite-length TLV.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 8.20. Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct OID runtime gate. Example: `encode_relative_oid_cer(&oid, limits)?`.
pub fn encode_relative_oid_cer(value: &RelativeOid, limits: &Limits) -> Result<Encoded, Error> {
    let mut work = 0;
    encode_oid_content(
        &value.content,
        value.content.capacity(),
        TAG_RELATIVE_OID,
        limits,
        &mut work,
    )
}

/// Decode and normalize one BER RELATIVE-OID prefix.
///
/// # Parameters and returns
/// `input` may include a suffix; `limits` caps full input, retained value,
/// scratch, and cumulative work. Returns canonical content and exact prefix size.
///
/// # Errors
/// Returns malformed/truncated BER, empty or unterminated content, limit,
/// checked-size, or allocation errors. Empty content is deliberately rejected.
///
/// # Source, version, history, example
/// Source: X.690 8.20 and C BER aliases. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: `decode_relative_oid_ber(input, limits)?`.
pub fn decode_relative_oid_ber(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<RelativeOid>, Error> {
    let decoded = decode_oid_content(input, TAG_RELATIVE_OID, limits, false)?;
    Ok(Decoded {
        value: RelativeOid {
            content: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Strictly decode one canonical CER RELATIVE-OID prefix.
///
/// # Parameters and returns
/// `input` may include a suffix; `limits` caps input and retained/output scratch,
/// plus one cumulative parse, normalization, re-encode, and compare budget.
///
/// # Errors
/// Returns BER errors or `InvalidEncoding` if the consumed prefix is not
/// canonical CER; empty and unterminated content are rejected.
///
/// # Source, version, history, example
/// Source: X.690 8.20 strict CER comparison. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: `decode_relative_oid_cer(input, limits)?`.
pub fn decode_relative_oid_cer(
    input: &[u8],
    limits: &Limits,
) -> Result<Decoded<RelativeOid>, Error> {
    let decoded = decode_oid_content(input, TAG_RELATIVE_OID, limits, true)?;
    Ok(Decoded {
        value: RelativeOid {
            content: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Encode raw `IA5String` bytes as a primitive DER TLV.
///
/// # Parameters and returns
/// `value` contains raw bytes; `limits` caps complete output, work, and scratch.
/// Returns tag 22 with a shortest definite length. The bytes are not validated.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C `IA5String` DER callback. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: `encode_ia5_string_der(&value, limits)?`.
pub fn encode_ia5_string_der(value: &Ia5String, limits: &Limits) -> Result<Encoded, Error> {
    encode_ia5_der(&value.bytes, value.bytes.capacity(), limits)
}

/// Encode `IA5String` as canonical CER after validating all content octets.
///
/// # Parameters and returns
/// `value` contains raw bytes; `limits` caps complete output, work, and scratch.
/// Returns tag 22 primitive through 1000 content octets, otherwise tag 22 with
/// universal tag-4 fragments.
///
/// # Errors
/// Returns invalid encoding for octets above `0x7f`, resource limits, checked
/// size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: C `IA5String` CER constraint timing. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: `encode_ia5_string_cer(&value, limits)?`.
pub fn encode_ia5_string_cer(value: &Ia5String, limits: &Limits) -> Result<Encoded, Error> {
    let mut work = 0;
    validate_ia5_content(&value.bytes, limits, &mut work)?;
    let encoded_len = ia5_cer_encoded_len(value.bytes.len())?;
    check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        value
            .bytes
            .capacity()
            .checked_add(encoded_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    charge_work(&mut work, encoded_len, limits)?;
    encode_ia5_cer_precharged(&value.bytes, value.bytes.capacity(), limits)
}

/// Decode one BER `IA5String` prefix while preserving all content octets.
///
/// # Parameters and returns
/// `input` may have a suffix; `limits` caps the entire slice, retained bytes,
/// and traversal work. Returns raw value bytes and exact TLV prefix consumption.
///
/// # Errors
/// Returns malformed/truncated BER, tag/fragment/EOC, resource, size, or
/// allocation errors. The IA5 repertoire is deliberately not checked.
///
/// # Source, version, history, example
/// Source: C `IA5String` BER callback. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: `decode_ia5_string_ber(input, limits)?`.
pub fn decode_ia5_string_ber(input: &[u8], limits: &Limits) -> Result<Decoded<Ia5String>, Error> {
    let decoded = decode_ia5_ber_bytes(input, limits, &mut 0)?;
    Ok(Decoded {
        value: Ia5String {
            bytes: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Strictly decode one canonical CER `IA5String` prefix.
///
/// # Parameters and returns
/// `input` may have a suffix; `limits` caps whole input, retained/output
/// scratch, and cumulative parse/validation/re-encode/compare work.
/// Returns the validated bytes and exact prefix consumption.
///
/// # Errors
/// Returns BER, IA5 repertoire, canonicality, resource, checked-size, or
/// allocation errors. Empty `IA5String` content is valid.
///
/// # Source, version, history, example
/// Source: X.690 CER and C IA5 constraint timing. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: `decode_ia5_string_cer(input, limits)?`.
pub fn decode_ia5_string_cer(input: &[u8], limits: &Limits) -> Result<Decoded<Ia5String>, Error> {
    let decoded = decode_ia5_cer_bytes(input, limits)?;
    Ok(Decoded {
        value: Ia5String {
            bytes: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Encode a typed restricted character string as canonical DER.
///
/// # Parameters and returns
/// `value` fixes the string kind and raw bytes; `limits` caps output/work/scratch.
/// Returns a primitive TLV using the kind's universal tag.
///
/// # Errors
/// Returns output, work, scratch, size, or allocation errors. CER constraints
/// are intentionally not checked by DER encoding.
///
/// # Source, version, history, example
/// Source: C DER callbacks. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: `encode_character_string_der(&value, limits)?`.
pub fn encode_character_string_der(
    value: &CharacterString,
    limits: &Limits,
) -> Result<Encoded, Error> {
    encode_character_string_der_bytes(value.kind, &value.bytes, value.bytes.capacity(), limits)
}

/// Encode a typed restricted character string as canonical CER.
///
/// # Parameters and returns
/// `value` fixes the string kind and raw bytes; `limits` caps output/work/scratch.
/// Returns a primitive TLV through 1000 content octets or tag-4 fragmentation.
///
/// # Errors
/// Returns invalid C repertoire/alignment, output/work/scratch, size, or
/// allocation errors.
///
/// # Source, version, history, example
/// Source: C CER constraints and X.690 string forms. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: `encode_character_string_cer(&value, limits)?`.
pub fn encode_character_string_cer(
    value: &CharacterString,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let mut work = 0;
    validate_character_string_content(value.kind, &value.bytes, limits, &mut work)?;
    let encoded_len = character_string_cer_encoded_len(value.kind, value.bytes.len())?;
    check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        value
            .bytes
            .capacity()
            .checked_add(encoded_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    charge_work(&mut work, encoded_len, limits)?;
    encode_character_string_cer_precharged(value.kind, &value.bytes, value.bytes.capacity(), limits)
}

/// Decode one BER character-string prefix using the requested intrinsic tag.
///
/// # Parameters and returns
/// `input` may have a suffix; `kind` selects the expected universal tag;
/// `limits` caps the whole input, retained bytes, and work. Returns raw bytes
/// and exact prefix consumption without applying the CER content check.
///
/// # Errors
/// Returns malformed BER, wrong tags/fragments, resource, size, or allocation
/// errors.
///
/// # Source, version, history, example
/// Source: C OCTET STRING-based string callbacks. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: `decode_character_string_ber(input, kind, limits)?`.
pub fn decode_character_string_ber(
    input: &[u8],
    kind: CharacterStringKind,
    limits: &Limits,
) -> Result<Decoded<CharacterString>, Error> {
    let mut work = 0;
    let decoded = decode_character_string_ber_bytes(input, kind, limits, &mut work)?;
    Ok(Decoded {
        value: CharacterString {
            kind,
            bytes: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Strictly decode one canonical CER character-string prefix.
///
/// # Parameters and returns
/// `input` may have a suffix; `kind` selects the expected universal tag;
/// `limits` caps whole input, retained/output scratch, and cumulative work.
/// Returns validated raw bytes and exact prefix consumption.
///
/// # Errors
/// Returns malformed BER, invalid C-compatible content, noncanonical CER,
/// resource, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C CER constraints and X.690 canonical forms. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: `decode_character_string_cer(input, kind, limits)?`.
pub fn decode_character_string_cer(
    input: &[u8],
    kind: CharacterStringKind,
    limits: &Limits,
) -> Result<Decoded<CharacterString>, Error> {
    let decoded = decode_character_string_cer_bytes(input, kind, limits)?;
    Ok(Decoded {
        value: CharacterString {
            kind,
            bytes: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Encode raw `UTCTime` content as DER without checking its syntax.
///
/// # Parameters and returns
/// `value` holds raw time bytes; `limits` caps output, work, and simultaneous
/// retained/output scratch. Returns a primitive universal tag 23 TLV.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: C `UTCTime_encode_der`. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: `encode_utc_time_der(&value, limits)?`.
pub fn encode_utc_time_der(value: &UtcTime, limits: &Limits) -> Result<Encoded, Error> {
    let mut work = 0;
    let output_len = single_identifier_tlv_len(value.bytes.len())?;
    charge_work(&mut work, output_len, limits)?;
    encode_utc_time_der_bytes(&value.bytes, value.bytes.capacity(), limits)
}

/// Encode `UTCTime` as CER after validating and converting it to UTC.
///
/// # Parameters and returns
/// `value` holds raw time bytes; `limits` caps output, work, and simultaneous
/// retained/output scratch. Returns canonical `YYMMDDhhmmssZ` under tag 23.
///
/// # Errors
/// Returns invalid syntax/calendar/zone, out-of-window normalization, resource,
/// checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C CER `UTCTime` normalization, with checked Gregorian arithmetic.
/// Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct `UTCTime` gate. Example: `encode_utc_time_cer(&value, limits)?`.
pub fn encode_utc_time_cer(value: &UtcTime, limits: &Limits) -> Result<Encoded, Error> {
    let mut work = 0;
    let canonical = normalize_utc_time_content(&value.bytes, limits, &mut work)?;
    let output_len = single_identifier_tlv_len(canonical.len())?;
    check(Resource::OutputBytes, output_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        value
            .bytes
            .capacity()
            .checked_add(output_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    charge_work(&mut work, output_len, limits)?;
    encode_utc_time_der_bytes(&canonical, value.bytes.capacity(), limits)
}

/// Decode one BER `UTCTime` prefix and preserve its raw content bytes.
///
/// # Parameters and returns
/// `input` is the full available slice and may have a suffix; `limits` caps
/// input, retained value, and work. Returns raw content and exact prefix use.
/// Primitive and nested constructed tag-23 values with tag-4 fragments are
/// accepted.
///
/// # Errors
/// Returns malformed framing/fragment, tag, resource, size, or allocation errors.
/// No time syntax check is applied.
///
/// # Source, version, history, example
/// Source: C `UTCTime_decode_ber` via `OCTET_STRING_decode_ber`.
/// Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct `UTCTime` gate. Example: `decode_utc_time_ber(input, limits)?`.
pub fn decode_utc_time_ber(input: &[u8], limits: &Limits) -> Result<Decoded<UtcTime>, Error> {
    let mut work = 0;
    let decoded = decode_utc_time_ber_bytes(input, limits, &mut work)?;
    Ok(Decoded {
        value: UtcTime {
            bytes: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Strictly decode one canonical CER `UTCTime` prefix.
///
/// # Parameters and returns
/// `input` is the full available slice and may have a suffix; `limits` caps
/// input, retained/output scratch, and cumulative work. Returns canonical raw
/// content and exact prefix consumption.
///
/// # Errors
/// Returns BER framing, time syntax/calendar/zone, canonicality, resource,
/// checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: strict C CER re-encoding plus X.690 `UTCTime` rules.
/// Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct `UTCTime` gate. Example: `decode_utc_time_cer(input, limits)?`.
pub fn decode_utc_time_cer(input: &[u8], limits: &Limits) -> Result<Decoded<UtcTime>, Error> {
    let decoded = decode_utc_time_cer_bytes(input, limits)?;
    Ok(Decoded {
        value: UtcTime {
            bytes: decoded.value,
        },
        consumed_bits: decoded.consumed_bits,
        consumed_bytes: decoded.consumed_bytes,
    })
}

/// Encode raw IA5 content as DER under its simultaneous value/output budget.
///
/// # Parameters and returns
/// `bytes` is unvalidated content; `retained_capacity` is its live allocation;
/// `limits` sets output/work ceilings. Returns primitive tag 22.
///
/// # Errors
/// Returns resource, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C `IA5String` DER callback. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: called by `encode_ia5_string_der`.
fn encode_ia5_der(
    bytes: &[u8],
    retained_capacity: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    encode_character_string_der_bytes(
        CharacterStringKind::Ia5String,
        bytes,
        retained_capacity,
        limits,
    )
}

/// Encode one raw string payload as a DER primitive under a shared scratch cap.
///
/// # Parameters and returns
/// `kind` selects the universal tag; `bytes` is raw content;
/// `retained_capacity` is a live value allocation; `limits` caps output/work.
/// Returns the complete primitive TLV.
///
/// # Errors
/// Returns resource, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C DER string callbacks. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: shared IA5/restricted-string core.
/// Example: called by public character-string and IA5 DER methods.
fn encode_character_string_der_bytes(
    kind: CharacterStringKind,
    bytes: &[u8],
    retained_capacity: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let encoded_len = single_identifier_tlv_len(bytes.len())?;
    check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        retained_capacity
            .checked_add(encoded_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    let mut work = 0;
    charge_work(&mut work, encoded_len, limits)?;
    let encoded = write_primitive(u64::from(kind.tag_number()), bytes, limits)?;
    check_character_string_scratch(
        retained_capacity
            .checked_add(encoded.bytes.capacity())
            .ok_or(Error::SizeOverflow)?,
    )?;
    Ok(encoded)
}

/// Build canonical CER IA5 output after its validation and work are charged.
///
/// # Parameters and returns
/// `bytes` is validated 7-bit content; `retained_capacity` is the live value
/// capacity; `limits` sets output/work ceilings. Returns a complete TLV.
///
/// # Errors
/// Returns resource, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 CER string forms. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: called after `validate_ia5_content`.
fn encode_ia5_cer_precharged(
    bytes: &[u8],
    retained_capacity: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    encode_character_string_cer_precharged(
        CharacterStringKind::Ia5String,
        bytes,
        retained_capacity,
        limits,
    )
}

/// Write canonical CER string bytes after content validation and work precharge.
///
/// # Parameters and returns
/// `kind` selects the outer tag; `bytes` is validated content;
/// `retained_capacity` is a live value buffer; `limits` caps output/scratch.
/// Returns canonical primitive or constructed CER.
///
/// # Errors
/// Returns resource, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 CER string forms. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: shared IA5/restricted-string core.
/// Example: called after `validate_character_string_content`.
fn encode_character_string_cer_precharged(
    kind: CharacterStringKind,
    bytes: &[u8],
    retained_capacity: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let encoded_len = character_string_cer_encoded_len(kind, bytes.len())?;
    check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        retained_capacity
            .checked_add(encoded_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    let mut output = new_output(encoded_len, limits)?;
    if bytes.len() <= CER_FRAGMENT_MAX {
        push_identifier(&mut output, false, u64::from(kind.tag_number()), limits)?;
        push_length(&mut output, bytes.len(), limits)?;
        push(&mut output, bytes, limits)?;
    } else {
        push_indefinite_header(&mut output, Tag::universal(kind.tag_number()), limits)?;
        for fragment in bytes.chunks(CER_FRAGMENT_MAX) {
            push_primitive(&mut output, TAG_OCTET_STRING, fragment, limits)?;
        }
        push(&mut output, &[0, 0], limits)?;
    }
    if output.len() != encoded_len {
        return Err(Error::SizeOverflow);
    }
    check_character_string_scratch(
        retained_capacity
            .checked_add(output.capacity())
            .ok_or(Error::SizeOverflow)?,
    )?;
    finish(output, limits)
}

/// Return exact CER size using tag 22 outside and tag 4 inside fragments.
///
/// # Parameters and returns
/// `content_len` is reassembled IA5 content bytes. Returns primitive or
/// constructed complete-TLV size.
///
/// # Errors
/// Returns `SizeOverflow` on checked arithmetic failure.
///
/// # Source, version, history, example
/// Source: X.690 9.2 and CER fragment-tag correction. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: 1001 content bytes select constructed output.
fn ia5_cer_encoded_len(content_len: usize) -> Result<usize, Error> {
    character_string_cer_encoded_len(CharacterStringKind::Ia5String, content_len)
}

/// Return exact CER size for a kind's outer tag and universal tag-4 fragments.
///
/// # Parameters and returns
/// `kind` selects the universal outer tag; `content_len` is reassembled bytes.
/// Returns primitive or constructed complete-TLV size.
///
/// # Errors
/// Returns `SizeOverflow` when checked size arithmetic fails.
///
/// # Source, version, history, example
/// Source: C CER fragmentation and X.690 9.2. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: shared string CER sizing.
/// Example: content above 1000 selects constructed output.
fn character_string_cer_encoded_len(
    kind: CharacterStringKind,
    content_len: usize,
) -> Result<usize, Error> {
    if content_len <= CER_FRAGMENT_MAX {
        return single_identifier_tlv_len(content_len);
    }
    let count = content_len.div_ceil(CER_FRAGMENT_MAX);
    fragmented_size_tagged(content_len, count, false, Tag::universal(kind.tag_number()))
}

/// Decode one BER `IA5String` and preserve its raw bytes.
///
/// # Parameters and returns
/// `input` is the whole supplied slice; `limits` caps input and output;
/// `work` shares parser and flattening work. Returns the consumed TLV prefix.
///
/// # Errors
/// Returns BER framing, tag/fragment, output/work, size, or allocation errors.
/// Does not apply the IA5 repertoire constraint.
///
/// # Source, version, history, example
/// Source: C `IA5String` BER callback. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: called by both public IA5 decoders.
fn decode_ia5_ber_bytes(
    input: &[u8],
    limits: &Limits,
    work: &mut usize,
) -> Result<Decoded<Vec<u8>>, Error> {
    decode_character_string_ber_bytes(input, CharacterStringKind::Ia5String, limits, work)
}

/// Strictly decode and canonicalize one CER `IA5String` under one budget.
///
/// # Parameters and returns
/// `input` is the full slice; `limits` caps input/output/work/scratch. Returns
/// validated content and exact consumed prefix.
///
/// # Errors
/// Returns BER, repertoire, canonicality, limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 strict CER and IA5 validation. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: called by `decode_ia5_string_cer`.
fn decode_ia5_cer_bytes(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    decode_character_string_cer_bytes(input, CharacterStringKind::Ia5String, limits)
}

/// Decode and re-encode one strict CER prefix under a shared work/scratch budget.
///
/// # Parameters and returns
/// `input` is the complete supplied slice; `kind` selects tag/check semantics;
/// `limits` caps input/output/work/scratch. Returns raw bytes and prefix use.
///
/// # Errors
/// Returns BER framing, content constraint, canonicality, resource, size, or
/// allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 strict CER and C descriptor constraints. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: shared IA5/restricted-string core.
/// Example: called by generic and IA5 CER decoders.
fn decode_character_string_cer_bytes(
    input: &[u8],
    kind: CharacterStringKind,
    limits: &Limits,
) -> Result<Decoded<Vec<u8>>, Error> {
    let mut work = 0;
    let decoded = decode_character_string_ber_bytes(input, kind, limits, &mut work)?;
    validate_character_string_content(kind, &decoded.value, limits, &mut work)?;
    let encoded_len = character_string_cer_encoded_len(kind, decoded.value.len())?;
    check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        decoded
            .value
            .capacity()
            .checked_add(encoded_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    let compare_len = decoded.consumed_bytes.max(encoded_len);
    let future_work = encoded_len
        .checked_add(compare_len)
        .ok_or(Error::SizeOverflow)?;
    charge_work(&mut work, future_work, limits)?;
    let canonical = encode_character_string_cer_precharged(
        kind,
        &decoded.value,
        decoded.value.capacity(),
        limits,
    )?;
    if input.get(..decoded.consumed_bytes) != Some(canonical.bytes.as_slice()) {
        let reason = if kind == CharacterStringKind::Ia5String {
            "CER IA5String differs from canonical re-encoding"
        } else {
            "CER character string differs from canonical re-encoding"
        };
        return Err(invalid(reason));
    }
    Ok(decoded)
}

/// Decode one BER character-string and bound its retained value capacity.
///
/// # Parameters and returns
/// `input` is the whole slice; `kind` selects the outer tag; `limits` caps
/// input/output; `work` shares parser and flattening work. Returns exact prefix.
///
/// # Errors
/// Returns malformed BER, tag/fragment, output/work, scratch, or allocation errors.
///
/// # Source, version, history, example
/// Source: C OCTET STRING-based BER callbacks. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: shared string BER core.
/// Example: called by public generic and IA5 BER decoders.
fn decode_character_string_ber_bytes(
    input: &[u8],
    kind: CharacterStringKind,
    limits: &Limits,
    work: &mut usize,
) -> Result<Decoded<Vec<u8>>, Error> {
    let decode_limits = character_string_decode_limits(limits);
    let decoded = decode_octet_ber_with_tag_work(
        input,
        Tag::universal(kind.tag_number()),
        &decode_limits,
        work,
        None,
    )?;
    check_character_string_scratch(decoded.value.capacity())?;
    Ok(decoded)
}

/// Parsed `UTCTime` fields and their numeric-zone adjustment.
#[derive(Clone, Copy)]
struct UtcTimeFields {
    /// Full Gregorian year selected by the 50-year pivot; state variable.
    year: u32,
    /// One-based Gregorian month; state variable.
    month: u32,
    /// One-based day of month; state variable.
    day: u32,
    /// Hour from 0 through 23; state variable.
    hour: u32,
    /// Minute from 0 through 59; state variable.
    minute: u32,
    /// Second from 0 through 59, defaulting to zero; state variable.
    second: u32,
    /// Numeric offset sign, or zero for `Z`; state variable.
    offset_sign: i64,
    /// Absolute numeric-zone offset in minutes; state variable.
    offset_minutes: i64,
}

/// Decode one BER `UTCTime` prefix using shared OCTET STRING framing.
///
/// # Parameters and returns
/// `input` is the complete supplied slice; `limits` caps input and retained
/// bytes; `work` shares parser and fragment-copy work. Returns raw content and
/// exact prefix consumption.
///
/// # Errors
/// Returns malformed BER, tag/fragment, output/work/scratch, size, or allocation
/// errors. Time syntax is intentionally not checked here.
///
/// # Source, version, history, example
/// Source: C `UTCTime_decode_ber` and shared OCTET STRING runtime.
/// Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct `UTCTime` gate. Example: called by `decode_utc_time_ber`.
fn decode_utc_time_ber_bytes(
    input: &[u8],
    limits: &Limits,
    work: &mut usize,
) -> Result<Decoded<Vec<u8>>, Error> {
    let decode_limits = character_string_decode_limits(limits);
    let decoded =
        decode_octet_ber_with_tag_work(input, Tag::universal(23), &decode_limits, work, None)?;
    check_character_string_scratch(decoded.value.capacity())?;
    Ok(decoded)
}

/// Re-encode a strict CER `UTCTime` prefix and compare only its consumed bytes.
///
/// # Parameters and returns
/// `input` may have a suffix; `limits` caps all resources. Returns the decoded
/// normalized bytes and exact prefix consumption.
///
/// # Errors
/// Returns BER/time/canonicality, resource, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: strict CER prefix re-encoding. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: called by `decode_utc_time_cer`.
fn decode_utc_time_cer_bytes(input: &[u8], limits: &Limits) -> Result<Decoded<Vec<u8>>, Error> {
    let mut work = 0;
    let decoded = decode_utc_time_ber_bytes(input, limits, &mut work)?;
    let canonical = normalize_utc_time_content(&decoded.value, limits, &mut work)?;
    let output_len = single_identifier_tlv_len(canonical.len())?;
    check(Resource::OutputBytes, output_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        decoded
            .value
            .capacity()
            .checked_add(output_len)
            .ok_or(Error::SizeOverflow)?,
    )?;

    // Precharge full canonical output and comparison before allocating it.
    let compare_len = decoded.consumed_bytes.max(output_len);
    charge_work(
        &mut work,
        output_len
            .checked_add(compare_len)
            .ok_or(Error::SizeOverflow)?,
        limits,
    )?;
    let canonical_tlv = encode_utc_time_der_bytes(&canonical, decoded.value.capacity(), limits)?;
    if input.get(..decoded.consumed_bytes) != Some(canonical_tlv.bytes.as_slice()) {
        return Err(invalid("CER UTCTime differs from canonical re-encoding"));
    }
    Ok(decoded)
}

/// Encode a primitive universal tag-23 TLV and include the retained value in scratch checks.
///
/// # Parameters and returns
/// `bytes` is raw content; `retained_capacity` is live value capacity; `limits`
/// caps output/work/scratch. Returns a complete DER TLV.
///
/// # Errors
/// Returns output/work/scratch, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C `UTCTime_encode_der`. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: called by DER and canonical CER encoders.
fn encode_utc_time_der_bytes(
    bytes: &[u8],
    retained_capacity: usize,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let encoded_len = single_identifier_tlv_len(bytes.len())?;
    check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    check_character_string_scratch(
        retained_capacity
            .checked_add(encoded_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    let encoded = write_primitive(23, bytes, limits)?;
    check_character_string_scratch(
        retained_capacity
            .checked_add(encoded.bytes.capacity())
            .ok_or(Error::SizeOverflow)?,
    )?;
    Ok(encoded)
}

/// Validate and normalize `UTCTime` bytes to `YYMMDDhhmmssZ`.
///
/// # Parameters and returns
/// `bytes` is the entire content; `limits` caps parsing work; `work` is the
/// cumulative operation counter. Returns exactly 13 canonical content octets.
///
/// # Errors
/// Returns malformed syntax/calendar/zone, unsupported normalized year,
/// work-limit, or checked-size errors.
///
/// # Source, version, history, example
/// Source: C CER `UTCTime` adapter with checked Gregorian arithmetic.
/// Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct `UTCTime` gate. Example: normalizes `9912312359Z`.
fn normalize_utc_time_content(
    bytes: &[u8],
    limits: &Limits,
    work: &mut usize,
) -> Result<[u8; 13], Error> {
    charge_work(work, bytes.len(), limits)?;
    let fields = parse_utc_time_fields(bytes)?;
    validate_utc_time_fields(&fields)?;
    let utc = normalize_utc_time_fields(fields)?;
    render_utc_time(&utc)
}

/// Parse the supported `UTCTime` lengths, decimal fields, and zone suffix.
///
/// # Parameters and returns
/// `bytes` is raw `UTCTime` content. Returns fields with the C 1950 pivot.
///
/// # Errors
/// Returns `InvalidEncoding` for unsupported length, nondecimal fields, or
/// malformed zone syntax.
///
/// # Source, version, history, example
/// Source: C CER `UTCTime` parser. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: called by `normalize_utc_time_content`.
fn parse_utc_time_fields(bytes: &[u8]) -> Result<UtcTimeFields, Error> {
    let (digit_len, has_seconds) = match bytes.len() {
        11 | 15 => (10, false),
        13 | 17 => (12, true),
        _ => return Err(invalid("UTCTime content has an unsupported length")),
    };

    // Parse six fixed-width decimal components, defaulting absent seconds to zero.
    let short_year = parse_utc_pair(bytes, 0)?;
    let year = if short_year >= 50 {
        1900 + short_year
    } else {
        2000 + short_year
    };
    let month = parse_utc_pair(bytes, 2)?;
    let day = parse_utc_pair(bytes, 4)?;
    let hour = parse_utc_pair(bytes, 6)?;
    let minute = parse_utc_pair(bytes, 8)?;
    let second = if has_seconds {
        parse_utc_pair(bytes, 10)?
    } else {
        0
    };

    // Parse either the canonical Z suffix or a signed four-digit offset.
    let (offset_sign, offset_minutes) = if digit_len < bytes.len() - 1 {
        let sign = match bytes.get(digit_len) {
            Some(b'+') => 1_i64,
            Some(b'-') => -1_i64,
            _ => return Err(invalid("UTCTime numeric zone has an invalid sign")),
        };
        let offset_hour = i64::from(parse_utc_pair(bytes, digit_len + 1)?);
        let offset_minute = i64::from(parse_utc_pair(bytes, digit_len + 3)?);
        if offset_hour > 23 || offset_minute > 59 {
            return Err(invalid("UTCTime numeric zone is out of range"));
        }
        (sign, offset_hour * 60 + offset_minute)
    } else if bytes.get(digit_len) == Some(&b'Z') {
        (0, 0)
    } else {
        return Err(invalid("UTCTime Z suffix is missing"));
    };

    Ok(UtcTimeFields {
        year,
        month,
        day,
        hour,
        minute,
        second,
        offset_sign,
        offset_minutes,
    })
}

/// Parse two bounded ASCII decimal digits as an unsigned value.
///
/// # Parameters and returns
/// `bytes` is content and `offset` is the first digit index. Returns its value.
///
/// # Errors
/// Returns `InvalidEncoding` when the pair is truncated or nondecimal.
///
/// # Source, version, history, example
/// Source: C CER `UTCTime` decimal-field parser. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: parses a month from bytes 2 and 3.
fn parse_utc_pair(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(2).ok_or(Error::SizeOverflow)?;
    let pair = bytes
        .get(offset..end)
        .ok_or_else(|| invalid("UTCTime decimal field is truncated"))?;
    let first = pair[0];
    let second = pair[1];
    if !first.is_ascii_digit() || !second.is_ascii_digit() {
        return Err(invalid("UTCTime decimal field contains a non-digit"));
    }
    Ok(u32::from(first - b'0') * 10 + u32::from(second - b'0'))
}

/// Validate local `UTCTime` date and clock fields before zone adjustment.
///
/// # Parameters and returns
/// `fields` contains parsed calendar values. Returns success for a valid date.
///
/// # Errors
/// Returns `InvalidEncoding` for an invalid Gregorian date or clock component.
///
/// # Source, version, history, example
/// Source: C CER `UTCTime` calendar checks. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: called before numeric-zone conversion.
fn validate_utc_time_fields(fields: &UtcTimeFields) -> Result<(), Error> {
    if !(1..=12).contains(&fields.month)
        || fields.hour > 23
        || fields.minute > 59
        || fields.second > 59
    {
        return Err(invalid(
            "UTCTime calendar or clock component is out of range",
        ));
    }
    let days = utc_month_days(fields.year, fields.month)?;
    if fields.day == 0 || fields.day > days {
        return Err(invalid("UTCTime day is invalid for its month"));
    }
    Ok(())
}

/// Return the day count for a validated month, including Gregorian leap day.
///
/// # Parameters and returns
/// `year` and `month` select the Gregorian month. Returns its number of days.
///
/// # Errors
/// Returns `InvalidEncoding` if the month is outside 1 through 12.
///
/// # Source, version, history, example
/// Source: proleptic Gregorian calendar arithmetic. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: February 2000 has 29 days.
const fn utc_month_days(year: u32, month: u32) -> Result<u32, Error> {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if utc_is_leap_year(year) => 29,
        2 => 28,
        _ => return Err(invalid("UTCTime month is out of range")),
    };
    Ok(days)
}

/// Test the proleptic Gregorian leap-year rule.
///
/// # Parameters and returns
/// `year` is a full Gregorian year. Returns whether February has 29 days.
///
/// # Errors
/// This bounded arithmetic helper cannot fail.
///
/// # Source, version, history, example
/// Source: Gregorian leap-year rule. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: `utc_is_leap_year(2000)` is true.
const fn utc_is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Convert local `UTCTime` fields to a UTC date within the supported pivot window.
///
/// # Parameters and returns
/// `fields` contains validated local date, clock, and numeric zone. Returns UTC
/// fields with zero zone metadata.
///
/// # Errors
/// Returns `InvalidEncoding` when conversion leaves years 1950 through 2049,
/// or `SizeOverflow` if checked arithmetic fails.
///
/// # Source, version, history, example
/// Source: C CER UTC conversion, using checked Gregorian arithmetic.
/// Version: 2026-11-01. Responsible: runtime maintainers.
/// History: direct `UTCTime` gate. Example: converts `+0100` by subtracting an hour.
fn normalize_utc_time_fields(fields: UtcTimeFields) -> Result<UtcTimeFields, Error> {
    let mut days = 0_i64;
    let mut year = 1950_u32;
    let mut month = 1_u32;

    // Count full years and prior months from the fixed 1950 epoch.
    while year < fields.year {
        days = days
            .checked_add(if utc_is_leap_year(year) { 366 } else { 365 })
            .ok_or(Error::SizeOverflow)?;
        year = year.checked_add(1).ok_or(Error::SizeOverflow)?;
    }
    while month < fields.month {
        days = days
            .checked_add(i64::from(utc_month_days(fields.year, month)?))
            .ok_or(Error::SizeOverflow)?;
        month = month.checked_add(1).ok_or(Error::SizeOverflow)?;
    }
    days = days
        .checked_add(i64::from(fields.day - 1))
        .ok_or(Error::SizeOverflow)?;

    // Apply the signed numeric zone offset in minutes without time_t conversion.
    let local_minutes = days
        .checked_mul(1440)
        .and_then(|n| n.checked_add(i64::from(fields.hour) * 60))
        .and_then(|n| n.checked_add(i64::from(fields.minute)))
        .ok_or(Error::SizeOverflow)?;
    let offset = fields
        .offset_sign
        .checked_mul(fields.offset_minutes)
        .ok_or(Error::SizeOverflow)?;
    let utc_minutes = local_minutes
        .checked_sub(offset)
        .ok_or(Error::SizeOverflow)?;
    if !(0..UTC_WINDOW_MINUTES).contains(&utc_minutes) {
        return Err(invalid(
            "UTCTime zone conversion leaves years 1950 through 2049",
        ));
    }

    // Convert epoch minutes back into a date while preserving seconds.
    let mut day_index = utc_minutes / 1440;
    year = 1950;
    while day_index >= i64::from(if utc_is_leap_year(year) { 366_u32 } else { 365 }) {
        day_index -= i64::from(if utc_is_leap_year(year) { 366_u32 } else { 365 });
        year = year.checked_add(1).ok_or(Error::SizeOverflow)?;
    }
    month = 1;
    while day_index >= i64::from(utc_month_days(year, month)?) {
        day_index -= i64::from(utc_month_days(year, month)?);
        month = month.checked_add(1).ok_or(Error::SizeOverflow)?;
    }
    let minute_of_day = utc_minutes % 1440;
    Ok(UtcTimeFields {
        year,
        month,
        day: u32::try_from(day_index + 1).map_err(|_| Error::SizeOverflow)?,
        hour: u32::try_from(minute_of_day / 60).map_err(|_| Error::SizeOverflow)?,
        minute: u32::try_from(minute_of_day % 60).map_err(|_| Error::SizeOverflow)?,
        second: fields.second,
        offset_sign: 0,
        offset_minutes: 0,
    })
}

/// Render a normalized UTC date as thirteen ASCII content octets.
///
/// # Parameters and returns
/// `fields` contains normalized year, month, day, and clock values. Returns
/// `YYMMDDhhmmssZ`.
///
/// # Errors
/// Returns `SizeOverflow` if a checked field conversion fails.
///
/// # Source, version, history, example
/// Source: C CER `UTCTime` canonical renderer. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct `UTCTime` gate.
/// Example: renders a date as a fixed 13-byte stack value.
fn render_utc_time(fields: &UtcTimeFields) -> Result<[u8; 13], Error> {
    let components = [
        fields.year % 100,
        fields.month,
        fields.day,
        fields.hour,
        fields.minute,
        fields.second,
    ];
    let mut output = [0_u8; 13];
    for (index, component) in components.into_iter().enumerate() {
        let tens = u8::try_from(component / 10).map_err(|_| Error::SizeOverflow)?;
        let units = u8::try_from(component % 10).map_err(|_| Error::SizeOverflow)?;
        output[index * 2] = b'0' + tens;
        output[index * 2 + 1] = b'0' + units;
    }
    output[12] = b'Z';
    Ok(output)
}

/// Check the full 7-bit IA5 repertoire and meter its byte scan.
///
/// # Parameters and returns
/// `bytes` is raw content; `limits` caps work; `work` shares operation bits.
/// Returns success when every octet is at most `0x7f`.
///
/// # Errors
/// Returns a work limit or `InvalidEncoding` for a high-bit octet.
///
/// # Source, version, history, example
/// Source: X.680 IA5 repertoire and C IA5 constraint. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: CER operations validate before output/publication.
fn validate_ia5_content(bytes: &[u8], limits: &Limits, work: &mut usize) -> Result<(), Error> {
    validate_character_string_content(CharacterStringKind::Ia5String, bytes, limits, work)
}

/// Apply the selected C descriptor's CER content check and meter the scan.
///
/// # Parameters and returns
/// `kind` selects the C-compatible repertoire/alignment rule; `bytes` is fully
/// reassembled content; `limits` caps work; `work` shares the operation budget.
/// Returns success when the selected type's check accepts the content.
///
/// # Errors
/// Returns `WorkBits` when scanning exceeds the ceiling or `InvalidEncoding`
/// when the content violates the selected C rule.
///
/// # Source, version, history, example
/// Source: C skeleton descriptor constraints. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: called before CER encode and after BER reassembly.
fn validate_character_string_content(
    kind: CharacterStringKind,
    bytes: &[u8],
    limits: &Limits,
    work: &mut usize,
) -> Result<(), Error> {
    charge_work(work, bytes.len(), limits)?;
    let valid = match kind {
        CharacterStringKind::NumericString => bytes
            .iter()
            .all(|byte| *byte == b' ' || byte.is_ascii_digit()),
        CharacterStringKind::PrintableString => bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    *byte,
                    b' ' | b'\''
                        | b'('
                        | b')'
                        | b'+'
                        | b','
                        | b'-'
                        | b'.'
                        | b'/'
                        | b':'
                        | b'='
                        | b'?'
                )
        }),
        CharacterStringKind::VisibleString | CharacterStringKind::Iso646String => {
            bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
        }
        CharacterStringKind::Ia5String => bytes.iter().all(|byte| *byte <= 0x7f),
        CharacterStringKind::Utf8String => is_c_compatible_utf8(bytes),
        CharacterStringKind::BmpString => bytes.len().is_multiple_of(2),
        CharacterStringKind::UniversalString => bytes.len().is_multiple_of(4),
        CharacterStringKind::ObjectDescriptor
        | CharacterStringKind::TeletexString
        | CharacterStringKind::T61String
        | CharacterStringKind::VideotexString
        | CharacterStringKind::GraphicString
        | CharacterStringKind::GeneralString => true,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(character_string_constraint_reason(kind)))
    }
}

/// Return the static diagnostic for one failed C-compatible string check.
///
/// # Parameters and returns
/// `kind` identifies the already-failed validator. Returns a static message.
///
/// # Errors
/// This lookup cannot fail or panic.
///
/// # Source, version, history, example
/// Source: C descriptor constraint classes. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: passed to `InvalidEncoding` after validator failure.
const fn character_string_constraint_reason(kind: CharacterStringKind) -> &'static str {
    match kind {
        CharacterStringKind::NumericString => {
            "NumericString contains a byte outside space and digits"
        }
        CharacterStringKind::PrintableString => {
            "PrintableString contains a byte outside its alphabet"
        }
        CharacterStringKind::VisibleString | CharacterStringKind::Iso646String => {
            "VisibleString contains a byte outside 0x20..=0x7e"
        }
        CharacterStringKind::Ia5String => "IA5String content contains an octet above 0x7f",
        CharacterStringKind::Utf8String => "UTF8String is not a minimal C-compatible sequence",
        CharacterStringKind::BmpString => "BMPString content length is not divisible by two",
        CharacterStringKind::UniversalString => {
            "UniversalString content length is not divisible by four"
        }
        CharacterStringKind::ObjectDescriptor
        | CharacterStringKind::TeletexString
        | CharacterStringKind::T61String
        | CharacterStringKind::VideotexString
        | CharacterStringKind::GraphicString
        | CharacterStringKind::GeneralString => "character string constraint failed",
    }
}

/// Match the C runtime's minimal one-to-six-octet `UTF8String` validator.
///
/// # Parameters and returns
/// `bytes` is the complete reassembled value. Returns false for invalid starts,
/// incomplete sequences, bad continuations, and overlong encodings.
///
/// # Errors
/// Does not allocate or panic; malformed bytes return false.
///
/// # Source, version, history, example
/// Source: `UTF8String__process` in the C skeleton. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: C compatibility gate.
/// Example: accepts minimal legacy 5-byte `[0xf8, 0x88, 0x80, 0x80, 0x80]`.
fn is_c_compatible_utf8(bytes: &[u8]) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let first = bytes[cursor];
        let width = match first {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            0xf8..=0xfb => 5,
            0xfc..=0xfd => 6,
            _ => return false,
        };
        if width > bytes.len() - cursor {
            return false;
        }
        let mut value = u32::from(first & (0xff >> width));
        for octet in &bytes[cursor + 1..cursor + width] {
            if !(0x80..=0xbf).contains(octet) {
                return false;
            }
            value = (value << 6) | u32::from(octet & 0x3f);
        }
        let minimum = match width {
            1 => 0,
            2 => 0x80,
            3 => 0x800,
            4 => 0x1_0000,
            5 => 0x20_0000,
            6 => 0x400_0000,
            _ => return false,
        };
        if value < minimum {
            return false;
        }
        cursor += width;
    }
    true
}

/// Cap IA5 retained bytes while preserving caller input and work limits.
///
/// # Parameters and returns
/// `limits` supplies all ceilings; returns a copy capped to the IA5 scratch
/// maximum for decoded output.
///
/// # Errors
/// This helper cannot fail.
///
/// # Source, version, history, example
/// Source: bounded scalar scratch policy. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct IA5 gate.
/// Example: passed to the shared OCTET flattener.
fn character_string_decode_limits(limits: &Limits) -> Limits {
    let mut decoded_limits = *limits;
    decoded_limits.max_output_bytes = decoded_limits
        .max_output_bytes
        .min(MAX_CHARACTER_STRING_SCRATCH_BYTES);
    decoded_limits
}

/// Bound simultaneous retained and canonical character-string buffers.
///
/// # Parameters and returns
/// `bytes` is the checked sum of live allocation capacities. Returns success
/// when it does not exceed the fixed string scratch cap.
///
/// # Errors
/// Returns `LimitExceeded(OutputBytes)` when the cap is exceeded.
///
/// # Source, version, history, example
/// Source: scalar codec scratch policy. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: restricted-string runtime gate.
/// Example: checks retained value plus canonical output.
const fn check_character_string_scratch(bytes: usize) -> Result<(), Error> {
    check(
        Resource::OutputBytes,
        bytes,
        MAX_CHARACTER_STRING_SCRATCH_BYTES,
    )
}

/// Fallibly copy unvalidated character-string bytes under scalar limits.
///
/// # Parameters and returns
/// `bytes` is raw input; `limits` caps input, retained output, and copy work.
/// Returns an owned buffer after checking its actual reserved capacity.
///
/// # Errors
/// Returns input/output/work/scratch, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: C BER/DER string values and scalar scratch policy. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: shared IA5/restricted-string core.
/// Example: used by `CharacterString` and `Ia5String` constructors.
fn copy_character_string_bytes(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    check(Resource::InputBytes, bytes.len(), limits.max_input_bytes)?;
    check(Resource::OutputBytes, bytes.len(), limits.max_output_bytes)?;
    check_character_string_scratch(bytes.len())?;
    let mut work = 0;
    charge_work(&mut work, bytes.len(), limits)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: bytes.len(),
        })?;
    check_character_string_scratch(owned.capacity())?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

/// Normalize one encoded OID content value under constructor limits.
///
/// # Parameters and returns
/// `content` is encoded base-128 content; `limits` bounds input, retained
/// storage, and work. Returns canonical nonempty content bytes.
///
/// # Errors
/// Returns invalid empty/unterminated content, resource, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 base-128 subidentifier form. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: called by both public OID constructors.
fn normalize_oid_content(content: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    check(Resource::InputBytes, content.len(), limits.max_input_bytes)?;
    let mut work = 0;
    let normalized_len = scan_oid_content(content, limits, &mut work)?;
    check(
        Resource::OutputBytes,
        normalized_len,
        limits.max_output_bytes,
    )?;
    check_oid_scratch(normalized_len)?;
    charge_work(&mut work, content.len(), limits)?;
    copy_oid_content(content, normalized_len, 0, limits)
}

/// Validate base-128 arc boundaries and count canonical content bytes.
///
/// # Parameters and returns
/// `content` is the encoded value; `limits` bounds parsing; `work` is shared.
/// Returns normalized byte length after removing leading `0x80` groups.
///
/// # Errors
/// Returns empty/unterminated content, size overflow, or input/work limits.
///
/// # Source, version, history, example
/// Source: X.690 8.19 and 8.20. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: used before reserving retained content.
fn scan_oid_content(content: &[u8], limits: &Limits, work: &mut usize) -> Result<usize, Error> {
    if content.is_empty() {
        return Err(invalid("OID content must not be empty"));
    }
    if content.last().is_some_and(|octet| octet & 0x80 != 0) {
        return Err(invalid(
            "OID content ends with an unterminated base-128 arc",
        ));
    }
    charge_work(work, content.len(), limits)?;
    let mut normalized_len = 0_usize;
    let mut at_arc_start = true;
    for octet in content {
        if at_arc_start && *octet == 0x80 {
            continue;
        }
        normalized_len = normalized_len.checked_add(1).ok_or(Error::SizeOverflow)?;
        at_arc_start = octet & 0x80 == 0;
    }
    if !at_arc_start {
        return Err(invalid(
            "OID content ends with an unterminated base-128 arc",
        ));
    }
    if normalized_len == 0 {
        return Err(invalid("OID content has no terminated base-128 arc"));
    }
    Ok(normalized_len)
}

/// Copy canonical OID bytes into a fallibly reserved retained buffer.
///
/// # Parameters and returns
/// `content` is validated BER content; `normalized_len` is its canonical size;
/// `additional_scratch` reserves room for a simultaneously live output buffer;
/// the caller charges the full source traversal before allocation. Returns bytes.
///
/// # Errors
/// Returns output/scratch limits, size overflow, or allocation errors.
///
/// # Source, version, history, example
/// Source: bounded OID normalization. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: called after scan and work preflight.
fn copy_oid_content(
    content: &[u8],
    normalized_len: usize,
    additional_scratch: usize,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    check(
        Resource::OutputBytes,
        normalized_len,
        limits.max_output_bytes,
    )?;
    let projected = normalized_len
        .checked_add(additional_scratch)
        .ok_or(Error::SizeOverflow)?;
    check_oid_scratch(projected)?;
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(normalized_len)
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: normalized_len,
        })?;
    let mut at_arc_start = true;
    for octet in content {
        if at_arc_start && *octet == 0x80 {
            continue;
        }
        normalized.push(*octet);
        at_arc_start = octet & 0x80 == 0;
    }
    if normalized.len() != normalized_len {
        return Err(Error::SizeOverflow);
    }
    check_oid_scratch(
        normalized
            .capacity()
            .checked_add(additional_scratch)
            .ok_or(Error::SizeOverflow)?,
    )?;
    Ok(normalized)
}

/// Encode canonical OID content with one primitive universal identifier.
///
/// # Parameters and returns
/// `content` is canonical; `retained_capacity` is a simultaneously live value
/// allocation; `tag` selects 6 or 13; `limits` caps output/work/scratch;
/// `work` shares cumulative bits with a strict BER/CER decode operation.
/// Returns a complete shortest definite-length TLV after charging this pass.
///
/// # Errors
/// Returns output/work/scratch limits, checked-size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 OBJECT IDENTIFIER and RELATIVE-OID forms. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: called by both OID encoders and strict CER validation.
fn encode_oid_content(
    content: &[u8],
    retained_capacity: usize,
    tag: u32,
    limits: &Limits,
    work: &mut usize,
) -> Result<Encoded, Error> {
    let total_len = single_identifier_tlv_len(content.len())?;
    check(Resource::OutputBytes, total_len, limits.max_output_bytes)?;
    check_oid_scratch(
        retained_capacity
            .checked_add(total_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    charge_work(work, total_len, limits)?;
    let mut output = new_output(total_len, limits)?;
    output.push(u8::try_from(tag).map_err(|_| Error::SizeOverflow)?);
    let mut encoded_length = [0_u8; std::mem::size_of::<usize>() + 1];
    let length_len = encode_length_bytes(content.len(), &mut encoded_length)?;
    output.extend_from_slice(&encoded_length[..length_len]);
    output.extend_from_slice(content);
    if output.len() != total_len {
        return Err(Error::SizeOverflow);
    }
    check_oid_scratch(
        retained_capacity
            .checked_add(output.capacity())
            .ok_or(Error::SizeOverflow)?,
    )?;
    finish(output, limits)
}

/// Build canonical OID output after a strict decoder has precharged its work.
///
/// # Parameters and returns
/// `content` is canonical; `retained_capacity` is live retained capacity;
/// `tag` is 6 or 13; `limits` bounds resources. Returns the complete TLV.
///
/// # Errors
/// Returns output/scratch limits, checked-size errors, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 OID canonical encoding. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: strict CER OID comparison.
/// Example: called after the decoder precharges all remaining phases.
fn encode_oid_content_precharged(
    content: &[u8],
    retained_capacity: usize,
    tag: u32,
    limits: &Limits,
) -> Result<Encoded, Error> {
    let total_len = single_identifier_tlv_len(content.len())?;
    check(Resource::OutputBytes, total_len, limits.max_output_bytes)?;
    check_oid_scratch(
        retained_capacity
            .checked_add(total_len)
            .ok_or(Error::SizeOverflow)?,
    )?;
    let mut output = new_output(total_len, limits)?;
    output.push(u8::try_from(tag).map_err(|_| Error::SizeOverflow)?);
    let mut encoded_length = [0_u8; std::mem::size_of::<usize>() + 1];
    let length_len = encode_length_bytes(content.len(), &mut encoded_length)?;
    output.extend_from_slice(&encoded_length[..length_len]);
    output.extend_from_slice(content);
    if output.len() != total_len {
        return Err(Error::SizeOverflow);
    }
    check_oid_scratch(
        retained_capacity
            .checked_add(output.capacity())
            .ok_or(Error::SizeOverflow)?,
    )?;
    finish(output, limits)
}

/// Decode, normalize, and optionally canonically re-encode one OID prefix.
///
/// # Parameters and returns
/// `input` is the full available slice; `tag` is 6 or 13; `limits` supplies
/// operation budgets; `strict_cer` enables canonical comparison. Returns
/// normalized content and exact prefix consumption.
///
/// # Errors
/// Returns malformed BER, empty/unterminated content, canonical mismatch,
/// limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BER/CER OID rules. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: called by the four standalone OID decoders.
fn decode_oid_content(
    input: &[u8],
    tag: u32,
    limits: &Limits,
    strict_cer: bool,
) -> Result<Decoded<Vec<u8>>, Error> {
    let mut work = 0;
    let (header, consumed_bytes, consumed_bits) =
        parse_root_tag_with_work(input, Tag::universal(tag), false, limits, &mut work)?;
    let content_len = header
        .length
        .ok_or_else(|| invalid("primitive OID length must be definite"))?;
    let content_end = header
        .content
        .checked_add(content_len)
        .ok_or(Error::SizeOverflow)?;
    if content_end != consumed_bytes {
        return Err(invalid("OID content length does not match primitive TLV"));
    }
    let content = input
        .get(header.content..content_end)
        .ok_or(Error::NeedMoreBytes {
            required_bytes: content_end,
            available_bytes: input.len(),
        })?;
    let normalized_len = scan_oid_content(content, limits, &mut work)?;
    check(
        Resource::OutputBytes,
        normalized_len,
        limits.max_output_bytes,
    )?;
    let encoded_len = single_identifier_tlv_len(normalized_len)?;
    let extra_scratch = if strict_cer { encoded_len } else { 0 };
    if strict_cer {
        check(Resource::OutputBytes, encoded_len, limits.max_output_bytes)?;
    }
    check_oid_scratch(
        normalized_len
            .checked_add(extra_scratch)
            .ok_or(Error::SizeOverflow)?,
    )?;
    let comparison_len = if strict_cer {
        consumed_bytes.max(encoded_len)
    } else {
        0
    };
    let future_work = content
        .len()
        .checked_add(if strict_cer { encoded_len } else { 0 })
        .and_then(|bytes| bytes.checked_add(comparison_len))
        .ok_or(Error::SizeOverflow)?;
    charge_work(&mut work, future_work, limits)?;
    let normalized = copy_oid_content(content, normalized_len, extra_scratch, limits)?;

    if strict_cer {
        let canonical =
            encode_oid_content_precharged(&normalized, normalized.capacity(), tag, limits)?;
        if input.get(..consumed_bytes) != Some(canonical.bytes.as_slice()) {
            return Err(invalid("CER OID differs from canonical re-encoding"));
        }
    }
    Ok(Decoded {
        value: normalized,
        consumed_bits,
        consumed_bytes,
    })
}

/// Calculate the shortest one-octet-identifier primitive TLV size.
///
/// # Parameters and returns
/// `content_len` is primitive content. Returns identifier, length, and content
/// octets combined for a tag number below 31.
///
/// # Errors
/// Returns `SizeOverflow` when a complete TLV size cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 definite-length encoding. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID and IA5 gates.
/// Example: short content adds two framing octets.
fn single_identifier_tlv_len(content_len: usize) -> Result<usize, Error> {
    1_usize
        .checked_add(length_size(content_len))
        .and_then(|size| size.checked_add(content_len))
        .ok_or(Error::SizeOverflow)
}

/// Bound simultaneous retained and canonical OID buffers by the fixed scratch cap.
///
/// # Parameters and returns
/// `bytes` is the checked sum of live OID buffer capacities. Returns success
/// when within the fixed codec ceiling.
///
/// # Errors
/// Returns `LimitExceeded(OutputBytes)` when the OID scratch cap is exceeded.
///
/// # Source, version, history, example
/// Source: `BigInteger` scalar scratch policy. Version: 2026-11-01.
/// Responsible: runtime maintainers. History: direct OID runtime gate.
/// Example: checks retained content plus canonical output.
const fn check_oid_scratch(bytes: usize) -> Result<(), Error> {
    check(Resource::OutputBytes, bytes, MAX_OID_SCRATCH_BYTES)
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

/// Build the typed span of one already scanned primitive or constructed TLV.
///
/// # Parameters and returns
/// `header` describes the root, `start` and `end` bound its full TLV, `tag` is
/// its effective identifier, and `kind` selects content semantics. Returns a
/// span with exact content boundaries.
///
/// # Errors
/// Returns `SizeOverflow` for an impossible end calculation or malformed
/// indefinite span.
///
/// # Source, version, history, example
/// Source: shared record field spans. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit record support.
/// Example: used for direct and wrapped fields.
fn field_span(
    header: Header,
    start: usize,
    end: usize,
    tag: Tag,
    kind: FieldKind,
) -> Result<FieldSpan, Error> {
    if kind == FieldKind::Sequence && !header.constructed {
        return Err(invalid("BER SEQUENCE field must use constructed form"));
    }
    let content_end = match header.length {
        Some(length) => header
            .content
            .checked_add(length)
            .ok_or(Error::SizeOverflow)?,
        None => end.checked_sub(2).ok_or(Error::SizeOverflow)?,
    };
    Ok(FieldSpan {
        tag,
        kind,
        tlv_start: start,
        tlv_end: end,
        field_start: start,
        tagging: TaggingMode::Implicit,
        constructed: header.constructed,
        content_start: header.content,
        content_end,
    })
}

/// Scan one EXPLICIT wrapper and require exactly one intrinsic child TLV.
///
/// # Parameters and returns
/// `input`, `start`, and `bound` identify the containing bytes; `outer` is the
/// already parsed wrapper; `kind` specifies its universal child; `work` and
/// `limits` are the shared operation budget. Returns the child span and wrapper
/// end offset.
///
/// # Errors
/// Returns malformed wrapper form, child tag, EOC, parent-boundary, depth,
/// work, or size errors.
///
/// # Source, version, history, example
/// Source: X.690 EXPLICIT BER values. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit record support.
/// Example: called by tagged SEQUENCE and SET field traversal.
fn scan_explicit_member(
    input: &[u8],
    start: usize,
    bound: usize,
    outer: Header,
    kind: FieldKind,
    work: &mut usize,
    limits: &Limits,
) -> Result<(FieldSpan, usize), Error> {
    if !outer.constructed {
        return Err(invalid("EXPLICIT record wrapper must be constructed"));
    }
    let length_octets = outer.content - start - outer.identifier_len;
    charge_work(work, length_octets, limits)?;
    let definite_end = if let Some(length) = outer.length {
        let end = outer
            .content
            .checked_add(length)
            .ok_or(Error::SizeOverflow)?;
        require(input, outer.content, length, bound)?;
        Some(end)
    } else {
        None
    };
    let child_bound = definite_end.unwrap_or(bound);
    let child_start = outer.content;
    let child = parse_header(input, child_start, child_bound, work, true, limits)?;
    let expected_tag = intrinsic_tag(kind);
    if child.class != TagClass::Universal as u8 || child.tag != u64::from(expected_tag.number) {
        return Err(invalid(
            "EXPLICIT wrapper child has the wrong universal tag",
        ));
    }
    if kind == FieldKind::Sequence && !child.constructed {
        return Err(invalid("EXPLICIT SEQUENCE child must use constructed form"));
    }
    if !matches!(
        kind,
        FieldKind::BitString | FieldKind::OctetString | FieldKind::Sequence
    ) && child.constructed
    {
        return Err(invalid("EXPLICIT scalar child must use primitive form"));
    }
    let child_end = scan(input, child_start, child_bound, 3, work, false, limits)?;
    let wrapper_end = match definite_end {
        Some(end) if child_end == end => end,
        Some(_) => return Err(invalid("EXPLICIT wrapper must contain exactly one child")),
        None => {
            if !is_eoc(input, child_end, bound) {
                return Err(invalid("EXPLICIT wrapper must contain one child and EOC"));
            }
            charge_work(work, 2, limits)?;
            child_end.checked_add(2).ok_or(Error::SizeOverflow)?
        }
    };
    let field = field_span(child, child_start, child_end, expected_tag, kind)?;
    Ok((field, wrapper_end))
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

/// Return the intrinsic universal identifier for a record field kind.
///
/// # Parameters and returns
/// `kind` selects the ASN.1 primitive. Returns its universal identifier.
///
/// # Errors
/// This total mapping cannot fail.
///
/// # Source, version, history, example
/// Source: X.690 primitive tag assignments. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit record support.
/// Example: `intrinsic_tag(FieldKind::Boolean) == Tag::universal(1)`.
const fn intrinsic_tag(kind: FieldKind) -> Tag {
    match kind {
        FieldKind::Boolean => Tag::universal(1),
        FieldKind::Integer => Tag::universal(2),
        FieldKind::BitString => Tag::universal(3),
        FieldKind::OctetString => Tag::universal(4),
        FieldKind::Null => Tag::universal(5),
        FieldKind::Enumerated => Tag::universal(10),
        FieldKind::Sequence => Tag::universal(16),
    }
}

/// Compute one complete DER or CER explicit wrapper size in constant time.
///
/// # Parameters and returns
/// `rule` selects definite DER or indefinite CER; `tag` is the wrapper;
/// `inner_size` is its sole encoded child. Returns the wrapper TLV byte count.
///
/// # Errors
/// Returns `SizeOverflow` when checked size arithmetic fails.
///
/// # Source, version, history, example
/// Source: X.690 explicit constructed wrappers. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit record support.
/// Example: `explicit_wrapper_size(RecordEncoding::Der, tag, child_len)?`.
fn explicit_wrapper_size(
    rule: RecordEncoding,
    tag: Tag,
    inner_size: usize,
) -> Result<usize, Error> {
    let identifier_len = tag_identifier_size(tag)?;
    match rule {
        RecordEncoding::Der => identifier_len
            .checked_add(length_size(inner_size))
            .and_then(|n| n.checked_add(inner_size))
            .ok_or(Error::SizeOverflow),
        RecordEncoding::Cer => identifier_len
            .checked_add(3)
            .and_then(|n| n.checked_add(inner_size))
            .ok_or(Error::SizeOverflow),
    }
}

/// Apply a nested SEQUENCE field's natural, IMPLICIT, or EXPLICIT tag in place.
///
/// # Parameters and returns
/// `bytes` is one complete canonical child SEQUENCE; `field` supplies its tag
/// mode; `rule` selects DER/CER; `parent_capacity` remains live alongside it;
/// `limits` supplies output bounds. Returns success after in-place wrapping.
///
/// # Errors
/// Returns invalid descriptor, output/scratch-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 constructed tagging. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: inline SEQUENCE support.
/// Example: called before a complete child is appended to its parent.
fn apply_nested_tagging(
    bytes: &mut Vec<u8>,
    field: RecordField,
    rule: RecordEncoding,
    parent_capacity: usize,
    retained_capacity: usize,
    limits: &Limits,
) -> Result<(), Error> {
    validate_field_mode(field.tag, FieldKind::Sequence, field.tagging)?;
    if field.tagging == TaggingMode::Implicit {
        retag_nested_record(bytes, field.tag, parent_capacity, retained_capacity, limits)?;
    } else {
        wrap_nested_record(
            bytes,
            field.tag,
            rule,
            parent_capacity,
            retained_capacity,
            limits,
        )?;
    }
    Ok(())
}

/// Validate a context-specific tag used to replace a constructed record root.
///
/// # Parameters and returns
/// `tag` is the requested IMPLICIT root tag. Returns success when its class and
/// numeric range are supported by the C-compatible BER runtime.
///
/// # Errors
/// Returns `InvalidEncoding` for a non-context-specific or out-of-range tag.
///
/// # Source, version, history, example
/// Source: X.690 identifier classes and C `ber_tlv_tag_t` range.
/// Version: 2026-11-01. Responsible: asn1c maintainers.
/// History: flat tagged-root support. Example: called before root parsing or encoding.
fn validate_implicit_root_tag(tag: Tag) -> Result<(), Error> {
    tag.validate()?;
    if tag.class != TagClass::ContextSpecific {
        return Err(invalid(
            "IMPLICIT constructed root tag must be context-specific",
        ));
    }
    Ok(())
}

/// Replace a completed root identifier and meter the bytes moved in place.
///
/// # Parameters and returns
/// `bytes` is a complete record TLV; `identifier` is its shortest constructed
/// replacement; `context` supplies shared work and output ceilings;
/// `parent_capacity` is retained parent storage. Returns success after retagging.
///
/// # Errors
/// Returns checked-size, output/scratch/work-limit, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 IMPLICIT constructed tag replacement.
/// Version: 2026-11-01. Responsible: asn1c maintainers.
/// History: root tag support. Example: called by `finish_tagged_root`.
fn retag_root_record(
    bytes: &mut Vec<u8>,
    identifier: &[u8],
    context: &mut RecordContext,
    parent_capacity: usize,
) -> Result<(), Error> {
    let old_len = bytes.len();
    let suffix_len = old_len.checked_sub(1).ok_or(Error::SizeOverflow)?;
    let new_len = suffix_len
        .checked_add(identifier.len())
        .ok_or(Error::SizeOverflow)?;
    context.check_output(new_len)?;
    if context.nested_accounting {
        check_combined_capacities(parent_capacity, new_len, context.retained_capacity)?;
    }
    let shifted_work = if identifier.len() > 1 {
        suffix_len
            .checked_add(identifier.len() - 1)
            .ok_or(Error::SizeOverflow)?
    } else {
        0
    };
    context.charge(shifted_work)?;
    if new_len > old_len {
        bytes
            .try_reserve_exact(new_len - old_len)
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: new_len,
            })?;
    }
    if context.nested_accounting {
        check_combined_capacities(parent_capacity, bytes.capacity(), context.retained_capacity)?;
    }
    if identifier.len() == 1 {
        bytes[0] = identifier[0];
    } else {
        bytes.resize(new_len, 0);
        bytes.copy_within(1..old_len, identifier.len());
        bytes[..identifier.len()].copy_from_slice(identifier);
    }
    Ok(())
}

/// Replace a child's universal SEQUENCE identifier without reallocating scratch.
///
/// # Parameters and returns
/// `bytes` holds the complete child; `tag` is its effective IMPLICIT tag;
/// `parent_capacity` is retained parent storage; `limits` applies the cap.
/// Returns success after replacing the first identifier.
///
/// # Errors
/// Returns checked-size, output/scratch-limit, invalid-tag, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 IMPLICIT constructed tag replacement. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: inline SEQUENCE support.
/// Example: called for natural and IMPLICIT child fields.
fn retag_nested_record(
    bytes: &mut Vec<u8>,
    tag: Tag,
    parent_capacity: usize,
    retained_capacity: usize,
    limits: &Limits,
) -> Result<(), Error> {
    let mut identifier = [0_u8; 6];
    let identifier_len = encode_identifier_bytes(tag, true, &mut identifier)?;
    let old_len = bytes.len();
    let new_len = old_len
        .checked_sub(1)
        .and_then(|length| length.checked_add(identifier_len))
        .ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, new_len, limits.max_output_bytes)?;
    check_combined_capacities(parent_capacity, new_len, retained_capacity)?;
    if new_len > old_len {
        bytes
            .try_reserve_exact(new_len - old_len)
            .map_err(|_| Error::AllocationFailed {
                requested_bytes: new_len,
            })?;
    }
    check_combined_capacities(parent_capacity, bytes.capacity(), retained_capacity)?;
    if identifier_len > 1 {
        bytes.resize(new_len, 0);
        bytes.copy_within(1..old_len, identifier_len);
    } else if new_len < old_len {
        bytes.copy_within(1..old_len, 1);
        bytes.truncate(new_len);
    }
    bytes[..identifier_len].copy_from_slice(&identifier[..identifier_len]);
    Ok(())
}

/// Wrap one complete child SEQUENCE with a constructed EXPLICIT identifier.
///
/// # Parameters and returns
/// `bytes` is the child TLV; `tag` is its wrapper; `rule` selects definite DER
/// or indefinite CER; `parent_capacity` and `limits` bound combined storage.
/// Returns success after shifting the child behind one wrapper header.
///
/// # Errors
/// Returns checked-size, output/scratch-limit, invalid-tag, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 EXPLICIT constructed tags. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: inline SEQUENCE support.
/// Example: called for EXPLICIT child fields before parent append.
fn wrap_nested_record(
    bytes: &mut Vec<u8>,
    tag: Tag,
    rule: RecordEncoding,
    parent_capacity: usize,
    retained_capacity: usize,
    limits: &Limits,
) -> Result<(), Error> {
    let mut identifier = [0_u8; 6];
    let identifier_len = encode_identifier_bytes(tag, true, &mut identifier)?;
    let child_len = bytes.len();
    let mut length_bytes = [0_u8; std::mem::size_of::<usize>() + 1];
    let length_len = match rule {
        RecordEncoding::Der => encode_length_bytes(child_len, &mut length_bytes)?,
        RecordEncoding::Cer => 1,
    };
    let header_len = identifier_len
        .checked_add(length_len)
        .ok_or(Error::SizeOverflow)?;
    let suffix_len = if rule == RecordEncoding::Cer { 2 } else { 0 };
    let total_len = header_len
        .checked_add(child_len)
        .and_then(|length| length.checked_add(suffix_len))
        .ok_or(Error::SizeOverflow)?;
    check(Resource::OutputBytes, total_len, limits.max_output_bytes)?;
    check_combined_capacities(parent_capacity, total_len, retained_capacity)?;
    bytes
        .try_reserve_exact(total_len.saturating_sub(child_len))
        .map_err(|_| Error::AllocationFailed {
            requested_bytes: total_len,
        })?;
    check_combined_capacities(parent_capacity, bytes.capacity(), retained_capacity)?;
    bytes.resize(total_len, 0);
    bytes.copy_within(0..child_len, header_len);
    bytes[..identifier_len].copy_from_slice(&identifier[..identifier_len]);
    if rule == RecordEncoding::Der {
        bytes[identifier_len..header_len].copy_from_slice(&length_bytes[..length_len]);
    } else {
        bytes[identifier_len] = 0x80;
        bytes[total_len - 2..].copy_from_slice(&[0, 0]);
    }
    Ok(())
}

/// Encode a checked class/number identifier into a fixed stack buffer.
///
/// # Parameters and returns
/// `tag` supplies the class and number; `constructed` selects the form bit;
/// `output` has capacity for the bounded C tag representation. Returns bytes used.
///
/// # Errors
/// Returns `InvalidEncoding` when the tag exceeds the runtime's C-compatible range.
///
/// # Source, version, history, example
/// Source: X.690 identifier encoding. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: nested wrapper encoder.
/// Example: called by `retag_nested_record` and `wrap_nested_record`.
fn encode_identifier_bytes(
    tag: Tag,
    constructed: bool,
    output: &mut [u8; 6],
) -> Result<usize, Error> {
    tag.validate()?;
    let class_and_form = ((tag.class as u8) << 6) | (u8::from(constructed) << 5);
    if tag.number < 31 {
        output[0] = class_and_form | u8::try_from(tag.number).map_err(|_| Error::SizeOverflow)?;
        return Ok(1);
    }
    output[0] = class_and_form | 0x1f;
    let mut groups = [0_u8; 5];
    let mut count = 0_usize;
    let mut number = tag.number;
    loop {
        groups[count] = u8::try_from(number & 0x7f).map_err(|_| Error::SizeOverflow)?;
        count += 1;
        number >>= 7;
        if number == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        let continuation = if index == 0 { 0 } else { 0x80 };
        output[count - index] = groups[index] | continuation;
    }
    Ok(count + 1)
}

/// Encode the shortest definite length into a fixed stack buffer.
///
/// # Parameters and returns
/// `length` is the content byte count; `output` holds its length octets.
/// Returns the number of encoded octets.
///
/// # Errors
/// Returns `SizeOverflow` if the encoded width cannot be represented.
///
/// # Source, version, history, example
/// Source: X.690 definite lengths. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: nested explicit wrappers.
/// Example: called when writing a DER EXPLICIT child header.
fn encode_length_bytes(
    length: usize,
    output: &mut [u8; std::mem::size_of::<usize>() + 1],
) -> Result<usize, Error> {
    if length < 128 {
        output[0] = u8::try_from(length).map_err(|_| Error::SizeOverflow)?;
        return Ok(1);
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::SizeOverflow)?;
    let count = bytes.len() - first;
    output[0] = 0x80 | u8::try_from(count).map_err(|_| Error::SizeOverflow)?;
    output[1..=count].copy_from_slice(&bytes[first..]);
    Ok(count + 1)
}

/// Bound cumulative decode charges and simultaneous record buffers by the scratch cap.
///
/// # Parameters and returns
/// `parent_capacity` and `child_capacity` are live Vec capacities;
/// `retained_capacity` is the cumulative decoded-allocation charge. Returns
/// success when their checked sum fits the fixed internal cap.
///
/// # Errors
/// Returns checked-size or output-limit errors.
///
/// # Source, version, history, example
/// Source: nested operation scratch policy. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: inline SEQUENCE support.
/// Example: called before and after every nested buffer reservation.
fn check_combined_capacities(
    parent_capacity: usize,
    child_capacity: usize,
    retained_capacity: usize,
) -> Result<(), Error> {
    let total = parent_capacity
        .checked_add(child_capacity)
        .and_then(|size| size.checked_add(retained_capacity))
        .ok_or(Error::SizeOverflow)?;
    check_scratch_total(total, MAX_RECORD_SCRATCH_BYTES)
}

/// Check aggregate scratch accounting against a supplied ceiling.
///
/// # Parameters and returns
/// `total` is the checked aggregate scratch amount; `ceiling` bounds it. Returns
/// success when live writer capacities plus cumulative decode charges fit.
///
/// # Errors
/// Returns `LimitExceeded(OutputBytes)` when the aggregate exceeds the ceiling.
///
/// # Source, version, history, example
/// Source: bounded nested scratch accounting. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: nested callback resource gate.
/// Example: `check_scratch_total(10, 10)?` accepts the exact boundary.
const fn check_scratch_total(total: usize, ceiling: usize) -> Result<(), Error> {
    check(Resource::OutputBytes, total, ceiling)
}

/// Append one canonical OCTET STRING child under its intrinsic universal tag.
///
/// # Parameters and returns
/// `out` is the shared record buffer; `rule` selects DER/CER; `value` is the
/// payload; `limits` caps buffer growth. Returns success after one child TLV.
///
/// # Errors
/// Returns output-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 OCTET STRING DER/CER forms. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit inner strings.
/// Example: called by the explicit OCTET STRING writer.
fn append_octet_value(
    out: &mut Vec<u8>,
    rule: RecordEncoding,
    value: &[u8],
    limits: &Limits,
) -> Result<(), Error> {
    if rule == RecordEncoding::Cer && value.len() > CER_FRAGMENT_MAX {
        push_indefinite_header(out, Tag::universal(4), limits)?;
        for fragment in value.chunks(CER_FRAGMENT_MAX) {
            push_primitive_tagged(out, Tag::universal(4), fragment, limits)?;
        }
        push(out, &[0, 0], limits)
    } else {
        push_primitive_tagged(out, Tag::universal(4), value, limits)
    }
}

/// Append one canonical BIT STRING child under its intrinsic universal tag.
///
/// # Parameters and returns
/// `out` is the shared record buffer; `rule` selects DER/CER; `bytes` is the
/// packed payload; `unused` is its trailing padding count; `limits` caps growth.
/// Returns success after one child TLV.
///
/// # Errors
/// Returns invalid padding, output-limit, size, or allocation errors.
///
/// # Source, version, history, example
/// Source: X.690 BIT STRING DER/CER forms. Version: 2026-11-01.
/// Responsible: asn1c maintainers. History: explicit inner strings.
/// Example: called by the explicit BIT STRING writer.
fn append_bit_value(
    out: &mut Vec<u8>,
    rule: RecordEncoding,
    bytes: &[u8],
    unused: u8,
    limits: &Limits,
) -> Result<(), Error> {
    let content_len = bytes.len().checked_add(1).ok_or(Error::SizeOverflow)?;
    if rule == RecordEncoding::Cer && content_len > CER_FRAGMENT_MAX {
        push_indefinite_header(out, Tag::universal(3), limits)?;
        let fragment_count = bytes.len().div_ceil(CER_FRAGMENT_MAX - 1);
        for (index, fragment) in bytes.chunks(CER_FRAGMENT_MAX - 1).enumerate() {
            let fragment_unused = if index + 1 == fragment_count {
                unused
            } else {
                0
            };
            push_bit_fragment(out, fragment, fragment_unused, limits)?;
        }
        push(out, &[0, 0], limits)
    } else {
        push_bit_fragment_tagged(out, Tag::universal(3), bytes, unused, limits)
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
    out.try_reserve_exact(payload.len())
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

    /// Accept empty constructed BER strings and nested definite/indefinite forms.
    /// Source: X.690 BER constructed BIT/OCTET STRING values.
    /// Version: 2026-11-01. Inputs: empty and mixed nested length forms.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn direct_ber_strings_accept_empty_and_nested_constructed_forms() {
        let limits = Limits::default();
        for input in [&[0x24, 0][..], &[0x24, 0x80, 0, 0][..]] {
            let decoded = decode_octet_string_ber(input, &limits).unwrap();
            assert_eq!(decoded.value, []);
            assert_eq!(decoded.consumed_bytes, input.len());
            assert!(decode_octet_string_cer(input, &limits).is_err());
        }
        for input in [&[0x23, 0][..], &[0x23, 0x80, 0, 0][..]] {
            let decoded = decode_bit_string_ber(input, &limits).unwrap();
            assert_eq!(decoded.value.as_bytes(), []);
            assert_eq!(decoded.value.bit_len(), 0);
            assert_eq!(decoded.consumed_bytes, input.len());
            assert!(decode_bit_string_cer(input, &limits).is_err());
        }

        let octet_vectors: [&[u8]; 2] = [
            &[0x24, 0x80, 0x24, 6, 4, 1, b'a', 4, 1, b'b', 0, 0],
            &[0x24, 10, 0x24, 0x80, 4, 1, b'a', 4, 1, b'b', 0, 0],
        ];
        for input in octet_vectors {
            let decoded = decode_octet_string_ber(input, &limits).unwrap();
            assert_eq!(decoded.value, b"ab");
            assert_eq!(decoded.consumed_bytes, input.len());
        }

        let bit_vectors: [&[u8]; 2] = [
            &[0x23, 0x80, 0x23, 8, 3, 2, 0, 0x80, 3, 2, 0, 0x40, 0, 0],
            &[0x23, 12, 0x23, 0x80, 3, 2, 0, 0x80, 3, 2, 0, 0x40, 0, 0],
        ];
        for input in bit_vectors {
            let decoded = decode_bit_string_ber(input, &limits).unwrap();
            assert_eq!(decoded.value.as_bytes(), [0x80, 0x40]);
            assert_eq!(decoded.value.bit_len(), 16);
            assert_eq!(decoded.consumed_bytes, input.len());
        }
    }

    /// Preserve the deliberate rejection of C-accepted non-final BIT padding.
    /// Source: C BER compatibility probe and X.690 8.6.4 fragment rules.
    /// Version: 2026-11-01. Input: non-final fragment with three unused bits.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn bit_ber_rejects_nonfinal_unused_bits_accepted_by_c() {
        let limits = Limits::default();
        let c_accepted_nonfinal_padding = [
            0x23, 0x80, 0x03, 0x02, 0x03, 0xa0, 0x03, 0x02, 0x00, 0xaa, 0, 0,
        ];
        assert!(decode_bit_string_ber(&c_accepted_nonfinal_padding, &limits).is_err());
        assert!(decode_bit_string_cer(&c_accepted_nonfinal_padding, &limits).is_err());
    }

    /// Check canonical OCTET/BIT CER primitive and fragmentation boundaries.
    /// Source: C CER boundary vectors and X.690 string content limits.
    /// Version: 2026-11-01. Inputs: content lengths 999, 1000, and 1001.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn direct_cer_strings_cover_all_1000_octet_boundaries() {
        let limits = Limits::default();
        for size in [999, 1000] {
            let payload = vec![0x5a; size];
            let encoded = encode_octet_string_cer(&payload, &limits).unwrap();
            assert_eq!(
                &encoded.bytes[..5],
                &[
                    4,
                    0x82,
                    u8::try_from(size >> 8).unwrap(),
                    u8::try_from(size & 0xff).unwrap(),
                    0x5a,
                ]
            );
            assert_eq!(
                decode_octet_string_cer(&encoded.bytes, &limits)
                    .unwrap()
                    .value,
                payload
            );
        }
        let payload = vec![0x5a; 1001];
        let encoded = encode_octet_string_cer(&payload, &limits).unwrap();
        assert_eq!(&encoded.bytes[..7], &[0x24, 0x80, 4, 0x82, 3, 0xe8, 0x5a]);
        assert_eq!(&encoded.bytes[1006..], &[4, 1, 0x5a, 0, 0]);
        assert_eq!(
            decode_octet_string_cer(&encoded.bytes, &limits)
                .unwrap()
                .value,
            payload
        );
        let multi_fragment = vec![0x5a; 2001];
        let encoded = encode_octet_string_cer(&multi_fragment, &limits).unwrap();
        assert_eq!(encoded.bytes.len(), 2015);
        assert_eq!(&encoded.bytes[..6], &[0x24, 0x80, 4, 0x82, 3, 0xe8]);
        assert_eq!(&encoded.bytes[2010..], &[4, 1, 0x5a, 0, 0]);
        assert_eq!(
            decode_octet_string_cer(&encoded.bytes, &limits)
                .unwrap()
                .value,
            multi_fragment
        );

        for (data_len, expected_tag) in [(998, 3), (999, 3)] {
            let bits = BitStringValue::new(vec![0x5a; data_len], data_len * 8).unwrap();
            let encoded = encode_bit_string_cer(&bits, &limits).unwrap();
            assert_eq!(encoded.bytes[0], expected_tag);
            assert_eq!(encoded.bytes[1], 0x82);
            let content_len = data_len + 1;
            assert_eq!(
                encoded.bytes[2..4],
                [0x03, u8::try_from(content_len & 0xff).unwrap()]
            );
            assert_eq!(
                decode_bit_string_cer(&encoded.bytes, &limits)
                    .unwrap()
                    .value,
                bits
            );
        }
        let mut data = vec![0x5a; 999];
        data.push(0xa0);
        let bits = BitStringValue::new(data, 7999).unwrap();
        let encoded = encode_bit_string_cer(&bits, &limits).unwrap();
        assert_eq!(&encoded.bytes[..6], &[0x23, 0x80, 3, 0x82, 3, 0xe8]);
        assert_eq!(&encoded.bytes[1006..], &[3, 2, 1, 0xa0, 0, 0]);
        assert_eq!(
            decode_bit_string_cer(&encoded.bytes, &limits)
                .unwrap()
                .value,
            bits
        );
        let mut multi_fragment_data = vec![0x5a; 2000];
        multi_fragment_data.push(0x58);
        let multi_fragment_bits = BitStringValue::new(multi_fragment_data, 16_005).unwrap();
        let encoded = encode_bit_string_cer(&multi_fragment_bits, &limits).unwrap();
        assert_eq!(encoded.bytes.len(), 2018);
        assert_eq!(&encoded.bytes[2010..], &[3, 4, 3, 0x5a, 0x5a, 0x58, 0, 0]);
        assert_eq!(
            decode_bit_string_cer(&encoded.bytes, &limits)
                .unwrap()
                .value,
            multi_fragment_bits
        );
    }

    /// Reject malformed EOCs, fragment tags, and truncated definite lengths.
    /// Source: X.690 BER constructed-string boundary and fragment rules.
    /// Version: 2026-11-01. Inputs: malformed OCTET and BIT STRING TLVs.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn direct_ber_strings_reject_malformed_eoc_fragments_and_lengths() {
        let limits = Limits::default();
        let malformed_octets: &[&[u8]] = &[
            &[0x24, 0x80, 4, 1, b'x'],
            &[0x24, 2, 0, 0],
            &[0x24, 0x80, 0, 1],
            &[0x24, 0x80, 5, 0, 0, 0],
            &[4, 0x82, 0, 4, 1],
        ];
        for input in malformed_octets {
            assert!(decode_octet_string_ber(input, &limits).is_err());
            assert!(decode_octet_string_cer(input, &limits).is_err());
        }

        let malformed_bits: &[&[u8]] = &[
            &[0x23, 0x80, 3, 2, 0, 0x80],
            &[0x23, 2, 0, 0],
            &[0x23, 0x80, 4, 2, 0, 0x80, 0, 0],
            &[3, 0x82, 0, 4, 0],
        ];
        for input in malformed_bits {
            assert!(decode_bit_string_ber(input, &limits).is_err());
            assert!(decode_bit_string_cer(input, &limits).is_err());
        }
    }

    /// Enforce exact input, retained-output, complete-output, and work boundaries.
    /// Source: runtime BER/DER resource contract for standalone string codecs.
    /// Version: 2026-11-01. Inputs: primitive OCTET/BIT values and tight limits.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn direct_string_codecs_check_exact_resource_limits() {
        let defaults = Limits::default();
        let octet_input = [4, 1, 0x5a];
        let octet_work = decode_octet_ber_work(&octet_input, &defaults).unwrap().1;
        let exact_octet_decode = Limits {
            max_input_bytes: 3,
            max_output_bytes: 1,
            max_work_bits: octet_work,
        };
        assert_eq!(
            decode_octet_string_ber(&octet_input, &exact_octet_decode)
                .unwrap()
                .value,
            [0x5a]
        );
        let exact_octet_encode = Limits {
            max_input_bytes: 3,
            max_output_bytes: 3,
            max_work_bits: 24,
        };
        assert_eq!(
            encode_octet_string_der(&[0x5a], &exact_octet_encode)
                .unwrap()
                .bytes,
            octet_input
        );
        for tight in [
            Limits {
                max_input_bytes: 2,
                ..exact_octet_decode
            },
            Limits {
                max_output_bytes: 0,
                ..exact_octet_decode
            },
            Limits {
                max_work_bits: octet_work - 1,
                ..exact_octet_decode
            },
        ] {
            assert!(decode_octet_string_ber(&octet_input, &tight).is_err());
        }
        assert!(encode_octet_string_der(
            &[0x5a],
            &Limits {
                max_output_bytes: 2,
                ..exact_octet_encode
            }
        )
        .is_err());
        assert!(encode_octet_string_der(
            &[0x5a],
            &Limits {
                max_work_bits: 23,
                ..exact_octet_encode
            }
        )
        .is_err());
        let suffix_input = [4, 1, 0x5a, 0xff];
        assert!(decode_octet_string_ber(
            &suffix_input,
            &Limits {
                max_input_bytes: 3,
                ..defaults
            }
        )
        .is_err());
    }

    /// Enforce exact retained-output and work boundaries for BIT STRING codecs.
    /// Source: runtime BER/DER resource contract for standalone string codecs.
    /// Version: 2026-11-01. Inputs: primitive BIT STRING values and tight limits.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn direct_bit_codecs_check_exact_resource_limits() {
        let defaults = Limits::default();
        let bit_value = BitStringValue::new(vec![0x80], 8).unwrap();
        let bit_der = [3, 2, 0, 0x80];
        let bit_work = decode_bit_ber_work(&bit_der, &defaults).unwrap().1;
        let exact_bit = Limits {
            max_input_bytes: bit_der.len(),
            max_output_bytes: 1,
            max_work_bits: bit_work,
        };
        assert_eq!(
            decode_bit_string_ber(&bit_der, &exact_bit).unwrap().value,
            bit_value
        );
        assert_eq!(
            encode_bit_string_der(
                &bit_value,
                &Limits {
                    max_output_bytes: 4,
                    ..defaults
                }
            )
            .unwrap()
            .bytes,
            bit_der
        );
        assert!(decode_bit_string_ber(
            &bit_der,
            &Limits {
                max_work_bits: bit_work - 1,
                ..exact_bit
            }
        )
        .is_err());
        assert!(decode_bit_string_ber(
            &bit_der,
            &Limits {
                max_output_bytes: 0,
                ..exact_bit
            }
        )
        .is_err());
    }

    /// Verify strict CER BIT STRING shares one work ceiling across parse and re-encode.
    /// Source: runtime strict CER cumulative work policy. Version: 2026-11-01.
    /// Inputs: canonical fragmented BIT STRING; returns assertions.
    /// Errors: assertion failures. Responsible: runtime maintainers.
    /// History: direct-string runtime gate. Example: run with `cargo test`.
    #[test]
    fn direct_bit_cer_work_limit_covers_parse_reencode_and_compare() {
        let defaults = Limits::default();
        let value = BitStringValue::new(vec![0x5a; 1000], 8000).unwrap();
        let canonical = encode_bit_string_cer(&value, &defaults).unwrap();
        let (parsed, parse_work) = decode_bit_ber_work(&canonical.bytes, &defaults).unwrap();
        assert_eq!(parsed.value, value);

        // Encoding and byte-for-byte comparison each charge the canonical TLV size.
        let canonical_work = canonical.bytes.len().checked_mul(16).unwrap();
        let exact_work = parse_work.checked_add(canonical_work).unwrap();
        let exact_limits = Limits {
            max_work_bits: exact_work,
            ..defaults
        };
        assert_eq!(
            decode_bit_string_cer(&canonical.bytes, &exact_limits)
                .unwrap()
                .value,
            value
        );
        let below_limits = Limits {
            max_work_bits: exact_work - 1,
            ..defaults
        };
        assert!(decode_bit_string_cer(&canonical.bytes, &below_limits).is_err());
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

    /// Decode constructed BER strings and enforce cumulative allocation charges.
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

    /// Decode, re-encode, and compare one explicit CER BOOLEAN record.
    ///
    /// # Parameters and returns
    /// `input` is a complete record prefix; `max_work_bits` is the shared
    /// operation ceiling. Returns cumulative work after canonical comparison.
    ///
    /// # Errors
    /// Returns malformed input, budget, or canonical mismatch errors.
    ///
    /// # Source, version, history, example
    /// Source: explicit CER work tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit wrapper coverage.
    /// Example: `explicit_boolean_cer_work(input, ceiling)?`.
    fn explicit_boolean_cer_work(input: &[u8], max_work_bits: usize) -> Result<usize, Error> {
        let limits = Limits {
            max_work_bits,
            ..Limits::default()
        };
        let tag = Tag::context_specific(0);
        let fields = [RecordField::new_explicit(tag, FieldKind::Boolean)?];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(input, &fields, &mut context)?;
        if reader.next_tagged_field()? != Some(tag) {
            return Err(invalid("explicit CER BOOLEAN is missing"));
        }
        let value = reader.read_boolean()?;
        if reader.next_tagged_field()?.is_some() {
            return Err(invalid("explicit CER BOOLEAN record has an extra field"));
        }
        let consumed = reader.finish()?;
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context)?;
        writer.write_boolean_explicit(tag, value)?;
        let canonical = writer.finish()?;
        context.verify_canonical(input, consumed.consumed_bytes, &canonical.bytes)?;
        Ok(context.work_used)
    }

    /// Decode and canonically re-encode a fragmented explicit CER OCTET STRING.
    ///
    /// # Parameters and returns
    /// `input` is a complete record prefix; `max_work_bits` is the shared
    /// operation ceiling. Returns cumulative work after canonical comparison.
    ///
    /// # Errors
    /// Returns malformed input, SIZE, budget, or canonical mismatch errors.
    ///
    /// # Source, version, history, example
    /// Source: explicit CER string work tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit wrapper coverage.
    /// Example: `explicit_octet_cer_work(input, ceiling)?`.
    fn explicit_octet_cer_work(input: &[u8], max_work_bits: usize) -> Result<usize, Error> {
        let limits = Limits {
            max_work_bits,
            ..Limits::default()
        };
        let tag = Tag::context_specific(0);
        let fields = [RecordField::new_explicit(tag, FieldKind::OctetString)?];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(input, &fields, &mut context)?;
        if reader.next_tagged_field()? != Some(tag) {
            return Err(invalid("explicit CER OCTET STRING is missing"));
        }
        let value = reader.read_octet_string(1001, 1001)?;
        if reader.next_tagged_field()?.is_some() {
            return Err(invalid("explicit CER OCTET STRING has an extra field"));
        }
        let consumed = reader.finish()?;
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context)?;
        writer.write_octet_string_explicit(tag, &value, 1001, 1001)?;
        let canonical = writer.finish()?;
        context.verify_canonical(input, consumed.consumed_bytes, &canonical.bytes)?;
        Ok(context.work_used)
    }

    /// Decode, re-encode, and compare one fragmented explicit CER BIT STRING.
    ///
    /// # Parameters and returns
    /// `input` is a complete record prefix; `max_work_bits` is the shared
    /// operation ceiling. Returns cumulative work after canonical comparison.
    ///
    /// # Errors
    /// Returns malformed input, SIZE, budget, or canonical mismatch errors.
    ///
    /// # Source, version, history, example
    /// Source: explicit CER bit work tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit wrapper coverage.
    /// Example: `explicit_bit_cer_work(input, ceiling)?`.
    fn explicit_bit_cer_work(input: &[u8], max_work_bits: usize) -> Result<usize, Error> {
        let limits = Limits {
            max_work_bits,
            ..Limits::default()
        };
        let tag = Tag::context_specific(1);
        let fields = [RecordField::new_explicit(tag, FieldKind::BitString)?];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(input, &fields, &mut context)?;
        if reader.next_tagged_field()? != Some(tag) {
            return Err(invalid("explicit CER BIT STRING is missing"));
        }
        let value = reader.read_bit_string(8000, 8000)?;
        if reader.next_tagged_field()?.is_some() {
            return Err(invalid("explicit CER BIT STRING has an extra field"));
        }
        let consumed = reader.finish()?;
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context)?;
        writer.write_bit_string_explicit(tag, value.as_bytes(), value.bit_len(), 8000, 8000)?;
        let canonical = writer.finish()?;
        context.verify_canonical(input, consumed.consumed_bytes, &canonical.bytes)?;
        Ok(context.work_used)
    }

    /// Build nested indefinite OCTET STRINGs under one explicit wrapper.
    ///
    /// # Parameters and returns
    /// `levels` is the number of constructed universal string nodes. Returns a
    /// complete indefinite SEQUENCE prefix with matching EOCs.
    ///
    /// # Errors
    /// This test-only builder uses bounded small inputs and cannot fail.
    ///
    /// # Source, version, history, example
    /// Source: explicit BER depth tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit nesting coverage.
    /// Example: `nested_explicit_octets(2)`.
    fn nested_explicit_octets(levels: usize) -> Vec<u8> {
        let mut input = vec![0x30, 0x80, 0xa0, 0x80];
        for _ in 0..levels {
            input.extend_from_slice(&[0x24, 0x80]);
        }
        input.extend_from_slice(&[4, 0]);
        for _ in 0..levels + 2 {
            input.extend_from_slice(&[0, 0]);
        }
        input
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

    /// Round-trip all six explicit primitive kinds with DER and CER wrappers.
    ///
    /// # Parameters and returns
    /// No parameters. Asserts canonical wrapper vectors and decoded values.
    ///
    /// # Errors
    /// Panics on encoding, decoding, or vector mismatch.
    ///
    /// # Source, version, history, example
    /// Source: X.690 EXPLICIT record encoding. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit wrapper tests.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_record_fields_round_trip_der_and_cer() {
        let limits = Limits::default();
        let tags = [
            Tag::context_specific(0),
            Tag::context_specific(1),
            Tag::context_specific(2),
            Tag::context_specific(3),
            Tag::context_specific(4),
            Tag::context_specific(5),
        ];
        let fields = [
            RecordField::new_explicit(tags[0], FieldKind::Boolean).unwrap(),
            RecordField::new_explicit(tags[1], FieldKind::Integer).unwrap(),
            RecordField::new_explicit(tags[2], FieldKind::BitString).unwrap(),
            RecordField::new_explicit(tags[3], FieldKind::OctetString).unwrap(),
            RecordField::new_explicit(tags[4], FieldKind::Null).unwrap(),
            RecordField::new_explicit(tags[5], FieldKind::Enumerated).unwrap(),
        ];
        let der = [
            0x30, 0x1f, 0xa0, 3, 1, 1, 0xff, 0xa1, 3, 2, 1, 3, 0xa2, 4, 3, 2, 7, 0x80, 0xa3, 4, 4,
            2, b'x', b'y', 0xa4, 2, 5, 0, 0xa5, 3, 10, 1, 2,
        ];
        let cer = [
            0x30, 0x80, 0xa0, 0x80, 1, 1, 0xff, 0, 0, 0xa1, 0x80, 2, 1, 3, 0, 0, 0xa2, 0x80, 3, 2,
            7, 0x80, 0, 0, 0xa3, 0x80, 4, 2, b'x', b'y', 0, 0, 0xa4, 0x80, 5, 0, 0, 0, 0xa5, 0x80,
            10, 1, 2, 0, 0, 0, 0,
        ];

        for (rule, expected) in [
            (RecordEncoding::Der, der.as_slice()),
            (RecordEncoding::Cer, cer.as_slice()),
        ] {
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(rule, &mut context).unwrap();
            writer.write_boolean_explicit(tags[0], true).unwrap();
            writer.write_integer_explicit(tags[1], 3, 0, 3).unwrap();
            writer
                .write_bit_string_explicit(tags[2], &[0x80], 1, 1, 1)
                .unwrap();
            writer
                .write_octet_string_explicit(tags[3], b"xy", 2, 2)
                .unwrap();
            writer.write_null_explicit(tags[4]).unwrap();
            writer.write_enumerated_explicit(tags[5], 2).unwrap();
            let encoded = writer.finish().unwrap();
            assert_eq!(encoded.bytes, expected);

            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
            for tag in tags {
                assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
                match tag.number() {
                    0 => assert!(reader.read_boolean().unwrap()),
                    1 => assert_eq!(reader.read_integer(0, 3).unwrap(), 3),
                    2 => assert_eq!(reader.read_bit_string(1, 1).unwrap().as_bytes(), &[0x80]),
                    3 => assert_eq!(reader.read_octet_string(2, 2).unwrap(), b"xy"),
                    4 => reader.read_null().unwrap(),
                    5 => assert_eq!(reader.read_enumerated().unwrap(), 2),
                    _ => panic!("unexpected test tag"),
                }
            }
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            let consumed = reader.finish().unwrap();
            let mut writer = SequenceWriter::new(rule, &mut context).unwrap();
            writer.write_boolean_explicit(tags[0], true).unwrap();
            writer.write_integer_explicit(tags[1], 3, 0, 3).unwrap();
            writer
                .write_bit_string_explicit(tags[2], &[0x80], 1, 1, 1)
                .unwrap();
            writer
                .write_octet_string_explicit(tags[3], b"xy", 2, 2)
                .unwrap();
            writer.write_null_explicit(tags[4]).unwrap();
            writer.write_enumerated_explicit(tags[5], 2).unwrap();
            let canonical = writer.finish().unwrap();
            context
                .verify_canonical(&encoded.bytes, consumed.consumed_bytes, &canonical.bytes)
                .unwrap();
        }
    }

    /// Sort explicit SET writes and accept valid BER members in reverse order.
    ///
    /// # Parameters and returns
    /// No parameters. Asserts canonical writer order and unordered reader dispatch.
    ///
    /// # Errors
    /// Panics on an unexpected encoding or decoded value.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET ordering and EXPLICIT wrappers. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit SET coverage.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_set_sorts_writes_and_reads_any_ber_member_order() {
        let first = Tag::context_specific(0);
        let second = Tag::context_specific(1);
        let fields = [
            RecordField::new_explicit(first, FieldKind::Boolean).unwrap(),
            RecordField::new_explicit(second, FieldKind::Boolean).unwrap(),
        ];
        let limits = Limits::default();
        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_explicit(second, false).unwrap();
        assert!(writer.write_boolean_explicit(first, true).is_err());

        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_explicit(first, true).unwrap();
        writer.write_boolean_explicit(second, false).unwrap();
        let encoded = writer.finish().unwrap();
        assert_eq!(
            encoded.bytes,
            [0x31, 10, 0xa0, 3, 1, 1, 0xff, 0xa1, 3, 1, 1, 0]
        );

        let reversed = [0x31, 10, 0xa1, 3, 1, 1, 0, 0xa0, 3, 1, 1, 0xff];
        let mut context = RecordContext::new(&limits);
        let mut reader = SetReader::new_tagged(&reversed, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(second));
        assert!(!reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(first));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, reversed.len());
    }

    /// Accept permissive high-tag BER explicit aliases and emit minimal forms.
    ///
    /// # Parameters and returns
    /// No parameters. Checks high-tag construction and canonical CER comparison.
    ///
    /// # Errors
    /// Panics on an unexpected parsing or encoding result.
    ///
    /// # Source, version, history, example
    /// Source: X.690 high-tag identifiers. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit high-tag coverage.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_high_tags_accept_ber_aliases_and_canonicalize() {
        let tag = Tag::context_specific(128);
        let fields = [RecordField::new_explicit(tag, FieldKind::Boolean).unwrap()];
        let limits = Limits::default();
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_boolean_explicit(tag, true).unwrap();
        let encoded = writer.finish().unwrap();
        assert_eq!(encoded.bytes, [0x30, 7, 0xbf, 0x81, 0, 3, 1, 1, 0xff]);

        let alias = [0x30, 8, 0xbf, 0x80, 0x81, 0, 3, 1, 1, 0xff];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&alias, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_boolean_explicit(tag, true).unwrap();
        let canonical = writer.finish().unwrap();
        assert!(context
            .verify_canonical(&alias, consumed.consumed_bytes, &canonical.bytes)
            .is_err());
    }

    /// Accept valid explicit BER wrapper boundaries and reject malformed ones.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises definite/indefinite wrappers and malformed children.
    ///
    /// # Errors
    /// Panics on an unexpected parser result.
    ///
    /// # Source, version, history, example
    /// Source: X.690 explicit BER framing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit parser tests.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_reader_checks_child_count_tags_eoc_and_bounds() {
        let tag = Tag::context_specific(0);
        let fields = [RecordField::new_explicit(tag, FieldKind::Boolean).unwrap()];
        let limits = Limits::default();
        let definite = [0x30, 5, 0xa0, 3, 1, 1, 0xff];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&definite, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, definite.len());

        let indefinite = [0x30, 0x80, 0xa0, 0x80, 1, 1, 0xff, 0, 0, 0, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&indefinite, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, indefinite.len());

        let malformed: [&[u8]; 7] = [
            &[0x30, 3, 0x80, 1, 0xff],
            &[0x30, 2, 0xa0, 0],
            &[0x30, 5, 0xa0, 3, 2, 1, 1],
            &[0x30, 7, 0xa0, 5, 1, 1, 0xff, 5, 0],
            &[0x30, 5, 0xa0, 3, 1, 2, 0xff],
            &[0x30, 7, 0xa0, 5, 0x21, 3, 1, 1, 0xff],
            &[0x30, 0x80, 0xa0, 0x80, 1, 1, 0xff, 5, 0, 0, 0, 0, 0],
        ];
        for input in malformed {
            let mut context = RecordContext::new(&limits);
            let mut reader = SequenceReader::new_tagged(input, &fields, &mut context).unwrap();
            assert!(reader.next_tagged_field().is_err(), "input={input:x?}");
        }

        let missing_record_eoc = [0x30, 0x80, 0xa0, 0x80, 1, 1, 0xff, 0, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SequenceReader::new_tagged(&missing_record_eoc, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert!(reader.read_boolean().unwrap());
        assert!(reader.next_tagged_field().is_err());
        assert!(RecordField::new_explicit(
            Tag::new(TagClass::Private, 1).unwrap(),
            FieldKind::Boolean
        )
        .is_err());
    }

    /// Verify explicit strings preserve universal fragments and share budgets.
    ///
    /// # Parameters and returns
    /// No parameters. Covers nested BER, CER fragment boundaries, storage, and work.
    ///
    /// # Errors
    /// Panics on an unexpected parser result.
    ///
    /// # Source, version, history, example
    /// Source: X.690 explicit CER string wrappers. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit string tests.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_string_wrappers_flatten_fragments_and_charge_shared_work() {
        let limits = Limits::default();
        let tag = Tag::context_specific(0);
        let fields = [RecordField::new_explicit(tag, FieldKind::OctetString).unwrap()];
        let nested = [
            0x30, 0x80, 0xa0, 0x80, 0x24, 0x80, 4, 1, b'x', 0, 0, 0, 0, 0, 0,
        ];
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&nested, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert_eq!(reader.read_octet_string(1, 1).unwrap(), b"x");
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();

        let payload = vec![b'x'; 1001];
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer
            .write_octet_string_explicit(tag, &payload, 1001, 1001)
            .unwrap();
        let encoded_octets = writer.finish().unwrap();
        assert_eq!(&encoded_octets.bytes[4..6], &[0x24, 0x80]);
        assert_eq!(encoded_octets.bytes[6], 4);
        assert_eq!(encoded_octets.bytes[1010], 4);
        assert_eq!(&encoded_octets.bytes[1013..1019], &[0, 0, 0, 0, 0, 0]);
        let required = explicit_octet_cer_work(&encoded_octets.bytes, usize::MAX).unwrap();
        assert_eq!(
            explicit_octet_cer_work(&encoded_octets.bytes, required).unwrap(),
            required
        );
        assert!(explicit_octet_cer_work(&encoded_octets.bytes, required - 1).is_err());

        let bit_tag = Tag::context_specific(1);
        let bit_fields = [RecordField::new_explicit(bit_tag, FieldKind::BitString).unwrap()];
        let bit_payload = vec![0xff; 1000];
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer
            .write_bit_string_explicit(bit_tag, &bit_payload, 8000, 8000, 8000)
            .unwrap();
        let encoded_bits = writer.finish().unwrap();
        assert_eq!(&encoded_bits.bytes[4..6], &[0x23, 0x80]);
        assert_eq!(&encoded_bits.bytes[6..11], &[3, 0x82, 3, 0xe8, 0]);
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SequenceReader::new_tagged(&encoded_bits.bytes, &bit_fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(bit_tag));
        assert_eq!(
            reader.read_bit_string(8000, 8000).unwrap().as_bytes(),
            bit_payload
        );
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();
        let required = explicit_bit_cer_work(&encoded_bits.bytes, usize::MAX).unwrap();
        assert_eq!(
            explicit_bit_cer_work(&encoded_bits.bytes, required).unwrap(),
            required
        );
        assert!(explicit_bit_cer_work(&encoded_bits.bytes, required - 1).is_err());

        let stored = [
            0x30, 12, 0xa0, 4, 4, 2, 0xaa, 0xbb, 0xa1, 4, 4, 2, 0xcc, 0xdd,
        ];
        let two_fields = [
            fields[0],
            RecordField::new_explicit(Tag::context_specific(1), FieldKind::OctetString).unwrap(),
        ];
        let storage_limits = Limits {
            max_output_bytes: 2,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&storage_limits);
        let mut reader = SequenceReader::new_tagged(&stored, &two_fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert_eq!(reader.read_octet_string(2, 2).unwrap(), [0xaa, 0xbb]);
        assert_eq!(
            reader.next_tagged_field().unwrap(),
            Some(Tag::context_specific(1))
        );
        assert!(reader.read_octet_string(2, 2).is_err());
    }

    /// Verify the explicit wrapper contributes one level to the BER depth cap.
    ///
    /// # Parameters and returns
    /// No parameters. Accepts the highest supported constructed depth and rejects
    /// one additional nested constructed child.
    ///
    /// # Errors
    /// Panics on an unexpected depth result.
    ///
    /// # Source, version, history, example
    /// Source: fixed BER nesting cap. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit depth tests.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_wrapper_nesting_respects_fixed_depth_cap() {
        let tag = Tag::context_specific(0);
        let fields = [RecordField::new_explicit(tag, FieldKind::OctetString).unwrap()];
        let limits = Limits::default();
        let accepted = nested_explicit_octets(MAX_DEPTH - 3);
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&accepted, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert_eq!(reader.read_octet_string(0, 0).unwrap(), []);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();

        let too_deep = nested_explicit_octets(MAX_DEPTH - 2);
        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&too_deep, &fields, &mut context).unwrap();
        assert!(reader.next_tagged_field().is_err());
    }

    /// Cover DER length transitions inside an explicit string wrapper.
    ///
    /// # Parameters and returns
    /// No parameters. Checks long-form child, wrapper, and record lengths.
    ///
    /// # Errors
    /// Panics on a noncanonical or malformed encoding.
    ///
    /// # Source, version, history, example
    /// Source: X.690 DER length forms. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit length boundaries.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_der_wrapper_checks_long_form_lengths_and_canonicality() {
        let tag = Tag::context_specific(0);
        let fields = [RecordField::new_explicit(tag, FieldKind::OctetString).unwrap()];
        let value = vec![0x5a; 126];
        let limits = Limits::default();
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer
            .write_octet_string_explicit(tag, &value, 126, 126)
            .unwrap();
        let encoded = writer.finish().unwrap();
        assert_eq!(
            &encoded.bytes[..8],
            &[0x30, 0x81, 0x83, 0xa0, 0x81, 0x80, 4, 126]
        );

        let mut context = RecordContext::new(&limits);
        let mut reader = SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(tag));
        assert_eq!(reader.read_octet_string(126, 126).unwrap(), value);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer
            .write_octet_string_explicit(tag, &[0x5a; 126], 126, 126)
            .unwrap();
        let canonical = writer.finish().unwrap();
        context
            .verify_canonical(&encoded.bytes, consumed.consumed_bytes, &canonical.bytes)
            .unwrap();
    }

    /// Check explicit CER work and output limits at exact boundaries.
    ///
    /// # Parameters and returns
    /// No parameters. Asserts exact work and pre-allocation output checks.
    ///
    /// # Errors
    /// Panics on an unexpected limit result.
    ///
    /// # Source, version, history, example
    /// Source: explicit operation budget tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: explicit wrapper budgets.
    /// Example: run via `cargo test`.
    #[test]
    fn explicit_cer_scalar_work_and_output_limits_are_cumulative() {
        let tag = Tag::context_specific(0);
        let canonical = [0x30, 0x80, 0xa0, 0x80, 1, 1, 0xff, 0, 0, 0, 0];
        let required = explicit_boolean_cer_work(&canonical, usize::MAX).unwrap();
        assert_eq!(
            explicit_boolean_cer_work(&canonical, required).unwrap(),
            required
        );
        assert!(explicit_boolean_cer_work(&canonical, required - 1).is_err());

        let limits = Limits {
            max_output_bytes: 10,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        assert!(writer.write_boolean_explicit(tag, true).is_err());
        let limits = Limits {
            max_output_bytes: 11,
            ..Limits::default()
        };
        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_boolean_explicit(tag, true).unwrap();
        assert_eq!(writer.finish().unwrap().bytes, canonical);

        let der = [0x30, 5, 0xa0, 3, 1, 1, 0xff];
        assert!(explicit_boolean_cer_work(&der, usize::MAX).is_err());
    }

    /// Match natural, IMPLICIT, and EXPLICIT nested child vectors for DER/CER.
    ///
    /// # Parameters and returns
    /// No parameters. Verifies six supplied X.690 nested record vectors and decode.
    ///
    /// # Errors
    /// Panics on encoding, decoding, or expected-vector mismatches.
    ///
    /// # Source, version, history, example
    /// Source: C fixture vectors supplied for inline SEQUENCE stage.
    /// Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: nested record acceptance tests. Example: run via `cargo test`.
    #[test]
    fn nested_sequence_tag_modes_match_der_cer_vectors() {
        let modes = [
            (
                RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap(),
                &[0x30, 0x0b, 2, 1, 1, 0x30, 3, 2, 1, 2, 1, 1, 0xff][..],
                &[
                    0x30, 0x80, 2, 1, 1, 0x30, 0x80, 2, 1, 2, 0, 0, 1, 1, 0xff, 0, 0,
                ][..],
            ),
            (
                RecordField::new(Tag::context_specific(3), FieldKind::Sequence).unwrap(),
                &[0x30, 0x0b, 2, 1, 1, 0xa3, 3, 2, 1, 2, 1, 1, 0xff][..],
                &[
                    0x30, 0x80, 2, 1, 1, 0xa3, 0x80, 2, 1, 2, 0, 0, 1, 1, 0xff, 0, 0,
                ][..],
            ),
            (
                RecordField::new_explicit(Tag::context_specific(3), FieldKind::Sequence).unwrap(),
                &[0x30, 0x0d, 2, 1, 1, 0xa3, 5, 0x30, 3, 2, 1, 2, 1, 1, 0xff][..],
                &[
                    0x30, 0x80, 2, 1, 1, 0xa3, 0x80, 0x30, 0x80, 2, 1, 2, 0, 0, 0, 0, 1, 1, 0xff,
                    0, 0,
                ][..],
            ),
            (
                RecordField::new(Tag::context_specific(31), FieldKind::Sequence).unwrap(),
                &[0x30, 0x0c, 2, 1, 1, 0xbf, 0x1f, 3, 2, 1, 2, 1, 1, 0xff][..],
                &[
                    0x30, 0x80, 2, 1, 1, 0xbf, 0x1f, 0x80, 2, 1, 2, 0, 0, 1, 1, 0xff, 0, 0,
                ][..],
            ),
        ];
        let child_fields = [RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap()];
        let limits = Limits::default();

        for (field, der_expected, cer_expected) in modes {
            for (rule, expected) in [
                (RecordEncoding::Der, der_expected),
                (RecordEncoding::Cer, cer_expected),
            ] {
                let mut context = RecordContext::new_nested(&limits);
                let mut writer = SequenceWriter::new(rule, &mut context).unwrap();
                writer.write_integer(1, 0, 3).unwrap();
                writer
                    .write_nested_sequence(field, |child| child.write_integer(2, 0, 3))
                    .unwrap();
                writer.write_boolean(true).unwrap();
                let encoded = writer.finish().unwrap();
                assert_eq!(encoded.bytes, expected);

                let fields = [
                    RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap(),
                    field,
                    RecordField::new(Tag::universal(1), FieldKind::Boolean).unwrap(),
                ];
                let mut context = RecordContext::new_nested(&limits);
                let mut reader =
                    SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
                assert_eq!(reader.next_tagged_field().unwrap(), Some(Tag::universal(2)));
                assert_eq!(reader.read_integer(0, 3).unwrap(), 1);
                assert_eq!(reader.next_tagged_field().unwrap(), Some(field.tag()));
                let child_value = reader
                    .read_nested_sequence(&child_fields, |child| {
                        assert_eq!(child.next_tagged_field()?, Some(Tag::universal(2)));
                        let value = child.read_integer(0, 3)?;
                        if child.next_tagged_field()?.is_some() {
                            return Err(invalid("nested fixture child has an extra field"));
                        }
                        Ok(value)
                    })
                    .unwrap();
                assert_eq!(child_value, 2);
                assert_eq!(reader.next_tagged_field().unwrap(), Some(Tag::universal(1)));
                assert!(reader.read_boolean().unwrap());
                assert_eq!(reader.next_tagged_field().unwrap(), None);
                assert_eq!(reader.finish().unwrap().consumed_bytes, expected.len());
            }
        }
    }

    /// Accept independently definite/indefinite BER wrappers within their spans.
    ///
    /// # Parameters and returns
    /// No parameters. Reads mixed parent, EXPLICIT wrapper, and child lengths.
    ///
    /// # Errors
    /// Panics if a valid BER value is rejected or a missing boundary is accepted.
    ///
    /// # Source, version, history, example
    /// Source: X.690 constructed BER framing decision. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: mixed wrapper tests.
    /// Example: run via `cargo test`.
    #[test]
    fn nested_sequence_accepts_mixed_ber_lengths_and_checks_eocs() {
        let wrapper =
            RecordField::new_explicit(Tag::context_specific(3), FieldKind::Sequence).unwrap();
        let fields = [
            RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap(),
            wrapper,
            RecordField::new(Tag::universal(1), FieldKind::Boolean).unwrap(),
        ];
        let child_fields = [RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap()];
        let mixed = [
            0x30, 0x80, 2, 1, 1, 0xa3, 7, 0x30, 0x80, 2, 1, 2, 0, 0, 1, 1, 0xff, 0, 0,
        ];
        let limits = Limits::default();
        let mut context = RecordContext::new_nested(&limits);
        let mut reader = SequenceReader::new_tagged(&mixed, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(Tag::universal(2)));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 1);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(wrapper.tag()));
        assert_eq!(
            reader
                .read_nested_sequence(&child_fields, |child| {
                    assert_eq!(child.next_tagged_field()?, Some(Tag::universal(2)));
                    let value = child.read_integer(0, 3)?;
                    assert_eq!(child.next_tagged_field()?, None);
                    Ok(value)
                })
                .unwrap(),
            2
        );
        assert_eq!(reader.next_tagged_field().unwrap(), Some(Tag::universal(1)));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        assert_eq!(consumed.consumed_bytes, mixed.len());
        let mut canonical_writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        canonical_writer.write_integer(1, 0, 3).unwrap();
        canonical_writer
            .write_nested_sequence(wrapper, |child| child.write_integer(2, 0, 3))
            .unwrap();
        canonical_writer.write_boolean(true).unwrap();
        let canonical = canonical_writer.finish().unwrap();
        assert!(context
            .verify_canonical(&mixed, consumed.consumed_bytes, &canonical.bytes)
            .is_err());

        // A child indefinite EOC cannot consume the enclosing parent's missing EOC.
        let missing_parent_eoc = [0x30, 0x80, 0x30, 0x80, 2, 1, 2, 0, 0];
        let natural_fields = [RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap()];
        let mut context = RecordContext::new_nested(&limits);
        let mut reader =
            SequenceReader::new_tagged(&missing_parent_eoc, &natural_fields, &mut context).unwrap();
        assert_eq!(
            reader.next_tagged_field().unwrap(),
            Some(natural_fields[0].tag())
        );
        let nested_fields = [RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap()];
        reader
            .read_nested_sequence(&nested_fields, |child| {
                assert_eq!(child.next_tagged_field()?, Some(Tag::universal(2)));
                child.read_integer(0, 3)?;
                assert_eq!(child.next_tagged_field()?, None);
                Ok(())
            })
            .unwrap();
        assert!(reader.next_tagged_field().is_err());

        // An EXPLICIT wrapper must contain exactly one complete child TLV.
        let extra_child = [0x30, 9, 0xa3, 7, 0x30, 3, 2, 1, 2, 5, 0];
        let mut context = RecordContext::new_nested(&limits);
        let extra_fields = [wrapper];
        let mut reader =
            SequenceReader::new_tagged(&extra_child, &extra_fields, &mut context).unwrap();
        assert!(reader.next_tagged_field().is_err());
    }

    /// Verify nested read rollback and the shared one-child work/output budget.
    ///
    /// # Parameters and returns
    /// No parameters. Confirms the same parent field can be retried after a
    /// callback error and checks nested depth plus output/work failures.
    ///
    /// # Errors
    /// Panics on unexpected rollback, resource, or callback behavior.
    ///
    /// # Source, version, history, example
    /// Source: nested operation transaction/resource contract.
    /// Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: nested callback tests. Example: run via `cargo test`.
    #[test]
    fn nested_sequence_rolls_back_and_bounds_resources() {
        let nested = RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap();
        let child_fields = [RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap()];
        let fields = [nested];
        let limits = Limits::default();
        let mut context = RecordContext::new_nested(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer
            .write_nested_sequence(nested, |child| {
                assert!(child
                    .write_nested_sequence(nested, |grandchild| {
                        grandchild.write_integer(3, 0, 3)
                    })
                    .is_err());
                child.write_integer(2, 0, 3)
            })
            .unwrap();
        let encoded = writer.finish().unwrap();

        let mut context = RecordContext::new_nested(&limits);
        let mut reader = SequenceReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(nested.tag()));
        assert!(reader
            .read_nested_sequence(&child_fields, |_| {
                Err::<(), Error>(invalid("injected failure"))
            })
            .is_err());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(nested.tag()));
        assert_eq!(
            reader
                .read_nested_sequence(&child_fields, |child| {
                    assert_eq!(child.next_tagged_field()?, Some(Tag::universal(2)));
                    let value = child.read_integer(0, 3)?;
                    assert_eq!(child.next_tagged_field()?, None);
                    Ok(value)
                })
                .unwrap(),
            2
        );
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        reader.finish().unwrap();

        let tiny_work = Limits {
            max_work_bits: 15,
            ..Limits::default()
        };
        let mut context = RecordContext::new_nested(&tiny_work);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        assert!(writer
            .write_nested_sequence(nested, |child| child.write_integer(2, 0, 3))
            .is_err());
        assert_eq!(writer.bytes, [0x30, 0]);

        let tight_output = Limits {
            max_output_bytes: 6,
            ..Limits::default()
        };
        let mut context = RecordContext::new_nested(&tight_output);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        assert!(writer
            .write_nested_sequence(nested, |child| child.write_integer(2, 0, 3))
            .is_err());
        assert_eq!(writer.bytes, [0x30, 0]);

        let mut flat_context = RecordContext::new(&limits);
        let mut flat_writer = SequenceWriter::new(RecordEncoding::Der, &mut flat_context).unwrap();
        assert!(flat_writer
            .write_nested_sequence(nested, |child| child.write_integer(2, 0, 3))
            .is_err());
        assert_eq!(flat_writer.bytes, [0x30, 0]);
    }

    /// Keep decoded-allocation charges after a failed callback and retry.
    ///
    /// # Parameters and returns
    /// No parameters. Captures a successfully decoded string, returns an error,
    /// then verifies the same field cannot use its already charged scratch twice.
    ///
    /// # Errors
    /// Panics if traversal or cumulative scratch accounting is not preserved.
    ///
    /// # Source, version, history, example
    /// Source: nested callback resource contract. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: monotonic allocation charges.
    /// Example: run via `cargo test`.
    #[test]
    fn failed_nested_callback_keeps_string_allocation_charge() {
        let nested = RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap();
        let octets = RecordField::new(Tag::universal(4), FieldKind::OctetString).unwrap();
        let fields = [nested];
        let child_fields = [octets];
        let input = [0x30, 6, 0x30, 4, 4, 2, b'a', b'b'];
        let limits = Limits::default();
        let mut context = RecordContext::new_nested(&limits);
        context.retained_capacity = MAX_RECORD_SCRATCH_BYTES - 3;
        let mut reader = SequenceReader::new_tagged(&input, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(nested.tag()));

        let mut escaped = None;
        assert!(reader
            .read_nested_sequence(&child_fields, |child| {
                assert_eq!(child.next_tagged_field()?, Some(octets.tag()));
                escaped = Some(child.read_octet_string(2, 2)?);
                Err::<(), Error>(invalid("injected callback failure"))
            })
            .is_err());
        assert_eq!(escaped.as_deref(), Some(&b"ab"[..]));
        assert!(reader.context.retained_capacity > MAX_RECORD_SCRATCH_BYTES - 3);

        // Logical traversal rolls back, but retry cannot reclaim the charged allocation.
        assert_eq!(reader.next_tagged_field().unwrap(), Some(nested.tag()));
        assert!(matches!(
            reader.read_nested_sequence(&child_fields, |child| {
                assert_eq!(child.next_tagged_field()?, Some(octets.tag()));
                child.read_octet_string(2, 2).map(|_| ())
            }),
            Err(Error::LimitExceeded {
                resource: Resource::OutputBytes,
                ..
            })
        ));
        assert_eq!(reader.next_tagged_field().unwrap(), Some(nested.tag()));
    }

    /// Measure and enforce the simultaneous parent/child capacity boundary.
    ///
    /// # Parameters and returns
    /// No parameters. Derives the current Vec capacity sum, accepts that limit,
    /// and rejects one byte less before parent logical commit.
    ///
    /// # Errors
    /// Panics on an unexpected capacity-boundary or transaction result.
    ///
    /// # Source, version, history, example
    /// Source: nested scratch allocation policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: nested resource tests.
    /// Example: run via `cargo test`.
    #[test]
    fn nested_sequence_checks_aggregate_capacity_before_parent_commit() {
        check_scratch_total(10, 10).unwrap();
        assert!(check_scratch_total(11, 10).is_err());
        check_combined_capacities(MAX_RECORD_SCRATCH_BYTES - 3, 2, 1).unwrap();
        assert!(check_combined_capacities(MAX_RECORD_SCRATCH_BYTES - 2, 2, 1).is_err());

        let nested = RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap();
        let expected = [0x30, 5, 0x30, 3, 2, 1, 2];
        let exact_limits = Limits {
            max_output_bytes: expected.len(),
            ..Limits::default()
        };
        let mut context = RecordContext::new_nested(&exact_limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer
            .write_nested_sequence(nested, |child| child.write_integer(2, 0, 3))
            .unwrap();
        assert_eq!(writer.finish().unwrap().bytes, expected);

        let below_limits = Limits {
            max_output_bytes: expected.len() - 1,
            ..Limits::default()
        };
        let mut context = RecordContext::new_nested(&below_limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        assert!(writer
            .write_nested_sequence(nested, |child| child.write_integer(2, 0, 3))
            .is_err());
        assert_eq!(writer.bytes, [0x30, 0]);
    }

    /// Keep a decoded CER string allocation charged during nested re-encoding.
    ///
    /// # Parameters and returns
    /// No parameters. Decodes a nested OCTET STRING, re-encodes through the same
    /// nested context, and checks strict canonical equality.
    ///
    /// # Errors
    /// Panics on retained-capacity or canonical output mismatches.
    ///
    /// # Source, version, history, example
    /// Source: X.690 nested CER and shared operation accounting.
    /// Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: retained-capacity overlap tests. Example: run via `cargo test`.
    #[test]
    fn nested_cer_retained_capacity_is_live_during_reencoding() {
        let nested = RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap();
        let parent_fields = [nested];
        let child_fields = [RecordField::new(Tag::universal(4), FieldKind::OctetString).unwrap()];
        let input = [0x30, 0x80, 0x30, 0x80, 4, 3, b'a', b'b', b'c', 0, 0, 0, 0];
        let limits = Limits::default();
        let mut context = RecordContext::new_nested(&limits);
        let mut reader = SequenceReader::new_tagged(&input, &parent_fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(nested.tag()));
        let value = reader
            .read_nested_sequence(&child_fields, |child| {
                assert_eq!(child.next_tagged_field()?, Some(Tag::universal(4)));
                let value = child.read_octet_string(3, 3)?;
                assert_eq!(child.next_tagged_field()?, None);
                Ok(value)
            })
            .unwrap();
        assert_eq!(value, b"abc");
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap();
        assert!(context.retained_capacity >= value.capacity());

        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer
            .write_nested_sequence(nested, |child| child.write_octet_string(&value, 3, 3))
            .unwrap();
        let canonical = writer.finish().unwrap();
        context
            .verify_canonical(&input, consumed.consumed_bytes, &canonical.bytes)
            .unwrap();
        assert_eq!(canonical.bytes, input);
    }

    /// Apply opt-in scratch accounting before and after nested child work.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises near-cap retained allocation charges, decode prelimits,
    /// root fields surrounding a child, and unchanged flat-context semantics.
    ///
    /// # Errors
    /// Panics on an unexpected scratch-limit or compatibility result.
    ///
    /// # Source, version, history, example
    /// Source: operation-wide nested scratch policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: nested budget regression.
    /// Example: run via `cargo test`.
    #[test]
    fn nested_context_caps_retained_and_parent_storage() {
        let nested = RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap();
        let limits = Limits::default();
        let mut before = RecordContext::new_nested(&limits);
        before.retained_capacity = MAX_RECORD_SCRATCH_BYTES - 3;
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut before).unwrap();
        assert!(writer.write_boolean(true).is_err());
        assert_eq!(writer.bytes, [0x30, 0]);

        let mut child_context = RecordContext::new_nested(&limits);
        child_context.retained_capacity = MAX_RECORD_SCRATCH_BYTES - 3;
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut child_context).unwrap();
        assert!(writer
            .write_nested_sequence(nested, |child| child.write_integer(2, 0, 3))
            .is_err());
        assert_eq!(writer.bytes, [0x30, 0]);

        let mut nested_context = RecordContext::new_nested(&limits);
        nested_context.retained_capacity = MAX_RECORD_SCRATCH_BYTES - 10;
        assert_eq!(
            nested_context
                .remaining_decode_limits()
                .unwrap()
                .max_output_bytes,
            10
        );
        nested_context.retain_decoded(1, 10).unwrap();
        assert!(nested_context.retain_decoded(1, 1).is_err());
        assert_eq!(nested_context.retained_bytes, 1);

        let flat_limits = Limits {
            max_output_bytes: usize::MAX,
            ..Limits::default()
        };
        let mut flat_context = RecordContext::new(&flat_limits);
        flat_context
            .retain_decoded(1, MAX_RECORD_SCRATCH_BYTES + 1)
            .unwrap();
        assert!(SequenceWriter::new(RecordEncoding::Der, &mut flat_context).is_ok());
    }

    /// Exercise nested DER/CER decoders with every truncation and byte mutation.
    ///
    /// # Parameters and returns
    /// No parameters. Every strict prefix must fail; each one-byte XOR mutation
    /// is parsed to either a bounded value or a typed error without panicking.
    ///
    /// # Errors
    /// Panics on a valid truncation, invalid full vector, or runtime panic.
    ///
    /// # Source, version, history, example
    /// Source: deterministic malformed nested-input mutation coverage.
    /// Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: fuzz-like nested BER tests. Example: run via `cargo test`.
    #[test]
    fn nested_vectors_reject_truncations_and_bound_mutations() {
        let nested = RecordField::new(Tag::universal(16), FieldKind::Sequence).unwrap();
        let parent_fields = [
            RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap(),
            nested,
            RecordField::new(Tag::universal(1), FieldKind::Boolean).unwrap(),
        ];
        let child_fields = [RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap()];
        let vectors: &[&[u8]] = &[
            &[0x30, 0x0b, 2, 1, 1, 0x30, 3, 2, 1, 2, 1, 1, 0xff],
            &[
                0x30, 0x80, 2, 1, 1, 0x30, 0x80, 2, 1, 2, 0, 0, 1, 1, 0xff, 0, 0,
            ],
        ];
        let limits = Limits::default();
        let decode = |input: &[u8]| -> Result<(), Error> {
            let mut context = RecordContext::new_nested(&limits);
            let mut reader = SequenceReader::new_tagged(input, &parent_fields, &mut context)?;
            while let Some(tag) = reader.next_tagged_field()? {
                match tag {
                    Tag {
                        class: TagClass::Universal,
                        number: 2,
                    } => {
                        reader.read_integer(0, 3)?;
                    }
                    tag if tag == nested.tag() => {
                        reader.read_nested_sequence(&child_fields, |child| {
                            if child.next_tagged_field()?.is_none() {
                                return Err(invalid("mutated child has no member"));
                            }
                            child.read_integer(0, 3)?;
                            if child.next_tagged_field()?.is_some() {
                                return Err(invalid("mutated child has an extra member"));
                            }
                            Ok(())
                        })?;
                    }
                    Tag {
                        class: TagClass::Universal,
                        number: 1,
                    } => {
                        reader.read_boolean()?;
                    }
                    _ => return Err(invalid("mutated parent has an unknown field")),
                }
            }
            reader.finish()?;
            Ok(())
        };

        for vector in vectors {
            for end in 0..vector.len() {
                assert!(decode(&vector[..end]).is_err());
            }
            assert!(decode(vector).is_ok());
            for index in 0..vector.len() {
                let mut mutated = vector.to_vec();
                mutated[index] ^= 1;
                let _ = decode(&mutated);
            }
        }
    }

    /// Ensure nested SET components use their outer effective tag for ordering.
    ///
    /// # Parameters and returns
    /// No parameters. Verifies sorted SET bytes and decoded member selection.
    ///
    /// # Errors
    /// Panics on an unexpected canonical vector, ordering result, or decode.
    ///
    /// # Source, version, history, example
    /// Source: X.690 SET component ordering and supplied C fixture.
    /// Version: 2026-11-01. Responsible: runtime maintainers.
    /// History: nested SET tests. Example: run via `cargo test`.
    #[test]
    fn nested_set_orders_by_outer_effective_tag() {
        let integer = RecordField::new(Tag::context_specific(0), FieldKind::Integer).unwrap();
        let boolean = RecordField::new(Tag::context_specific(1), FieldKind::Boolean).unwrap();
        let child =
            RecordField::new_explicit(Tag::context_specific(3), FieldKind::Sequence).unwrap();
        let child_fields = [RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap()];
        let limits = Limits::default();
        let mut context = RecordContext::new_nested(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer_tagged(integer.tag(), 1, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean.tag(), true).unwrap();
        writer
            .write_nested_sequence(child, |nested| nested.write_integer(2, 0, 3))
            .unwrap();
        let encoded = writer.finish().unwrap();
        assert_eq!(
            encoded.bytes,
            [0x31, 0x0d, 0x80, 1, 1, 0x81, 1, 0xff, 0xa3, 5, 0x30, 3, 2, 1, 2]
        );

        let fields = [integer, child, boolean];
        let mut context = RecordContext::new_nested(&limits);
        let mut reader = SetReader::new_tagged(&encoded.bytes, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(integer.tag()));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 1);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(boolean.tag()));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(child.tag()));
        assert_eq!(
            reader
                .read_nested_sequence(&child_fields, |nested| {
                    assert_eq!(nested.next_tagged_field()?, Some(Tag::universal(2)));
                    let value = nested.read_integer(0, 3)?;
                    assert_eq!(nested.next_tagged_field()?, None);
                    Ok(value)
                })
                .unwrap(),
            2
        );
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
    }

    /// Check the C fixture bytes and same-context CER canonical re-encoding.
    /// Source: C RI [3] IMPLICIT SEQUENCE { x INTEGER }, x = 2.
    /// Version: 2026-11-01. Inputs: DER and CER root values. Returns: assertions.
    /// Errors: assertion failures. Responsible: runtime maintainers.
    /// History: tagged-root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_root_matches_c_der_and_cer_fixture() {
        let limits = Limits::default();
        let root_tag = Tag::context_specific(3);
        let integer = RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap();
        let fields = [integer];

        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        let der = writer.finish_tagged_root(root_tag).unwrap();
        assert_eq!(der.bytes, [0xa3, 3, 2, 1, 2]);

        let mut context = RecordContext::new(&limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        let cer = writer.finish_tagged_root(root_tag).unwrap();
        assert_eq!(cer.bytes, [0xa3, 0x80, 2, 1, 2, 0, 0]);

        let mut input_with_suffix = cer.bytes.clone();
        input_with_suffix.extend_from_slice(&[5, 0]);
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SequenceReader::new_tagged_root(&input_with_suffix, root_tag, &fields, &mut context)
                .unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(integer.tag()));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap().consumed_bytes;
        assert_eq!(consumed, cer.bytes.len());

        let mut writer = SequenceWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        let canonical = writer.finish_tagged_root(root_tag).unwrap();
        context
            .verify_canonical(&input_with_suffix, consumed, &canonical.bytes)
            .unwrap();
    }

    /// Cover canonical high tags, BER-compatible aliases, and invalid root tags.
    /// Source: X.690 high-tag identifier forms and C-compatible parser range.
    /// Version: 2026-11-01. Inputs: boundary tags and malformed identifiers.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged-root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_root_high_tags_aliases_and_validation() {
        let limits = Limits::default();
        let integer = RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap();
        let fields = [integer];
        for number in [30, 31, 127, MAX_TAG_NUMBER] {
            let tag = Tag::context_specific(number);
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
            writer.write_integer(2, 0, 3).unwrap();
            let encoded = writer.finish_tagged_root(tag).unwrap();
            let mut identifier = [0_u8; 6];
            let identifier_len = encode_identifier_bytes(tag, true, &mut identifier).unwrap();
            assert_eq!(
                &encoded.bytes[..identifier_len],
                &identifier[..identifier_len]
            );

            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new_tagged_root(&encoded.bytes, tag, &fields, &mut context)
                    .unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(integer.tag()));
            assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
        }

        for alias in [
            [0xbf, 0x1e, 3, 2, 1, 2, 0, 0],
            [0xbf, 0x80, 0x1f, 3, 2, 1, 2, 0],
        ] {
            let (tag, input) = if alias[1] == 0x1e {
                (Tag::context_specific(30), &alias[..6])
            } else {
                (Tag::context_specific(31), &alias[..7])
            };
            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new_tagged_root(input, tag, &fields, &mut context).unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(integer.tag()));
            assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, input.len());
        }

        let wrong_classes = [
            Tag::universal(3),
            Tag {
                class: TagClass::Application,
                number: 3,
            },
            Tag {
                class: TagClass::Private,
                number: 3,
            },
            Tag {
                class: TagClass::ContextSpecific,
                number: MAX_TAG_NUMBER + 1,
            },
        ];
        for tag in wrong_classes {
            let mut context = RecordContext::new(&limits);
            assert!(SequenceReader::new_tagged_root(&[], tag, &fields, &mut context).is_err());
            let mut context = RecordContext::new(&limits);
            let writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
            assert!(writer.finish_tagged_root(tag).is_err());
        }
        assert!(Tag::new(TagClass::ContextSpecific, MAX_TAG_NUMBER + 1).is_err());
    }

    /// Reject malformed framing while preserving exact prefix and whole-input limits.
    /// Source: X.690 constructed roots, truncation, and EOC rules.
    /// Version: 2026-11-01. Inputs: truncated, primitive, overflowing, and bad-EOC TLVs.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged-root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_root_rejects_malformed_framing_and_keeps_prefix_bounds() {
        let limits = Limits::default();
        let root_tag = Tag::context_specific(3);
        let integer = RecordField::new(Tag::universal(2), FieldKind::Integer).unwrap();
        let fields = [integer];
        let valid = [0xa3, 3, 2, 1, 2];
        let decode = |input: &[u8]| -> Result<(i64, usize), Error> {
            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new_tagged_root(input, root_tag, &fields, &mut context)?;
            if reader.next_tagged_field()? != Some(integer.tag()) {
                return Err(invalid("tagged-root fixture is missing its INTEGER"));
            }
            let value = reader.read_integer(0, 3)?;
            if reader.next_tagged_field()?.is_some() {
                return Err(invalid("tagged-root fixture has an extra field"));
            }
            let consumed = reader.finish()?.consumed_bytes;
            Ok((value, consumed))
        };

        for end in 0..valid.len() {
            assert!(decode(&valid[..end]).is_err());
        }
        assert_eq!(decode(&valid).unwrap(), (2, valid.len()));
        let mut suffixed = valid.to_vec();
        suffixed.extend_from_slice(&[5, 0]);
        assert_eq!(decode(&suffixed).unwrap(), (2, valid.len()));
        assert!(decode(&[0x83, 3, 2, 1, 2]).is_err());
        assert!(decode(&[0xa3, 5, 0, 0, 2, 1, 2]).is_err());
        assert!(decode(&[0xbf, 0x84, 0x80, 0x80, 0x80, 0, 3, 2, 1, 2]).is_err());
        assert!(decode(&[0xa3, 0x80, 2, 1, 2]).is_err());

        let tight_input = Limits {
            max_input_bytes: valid.len(),
            ..limits
        };
        assert!(decode(&valid).is_ok());
        let mut context = RecordContext::new(&tight_input);
        let reader = SequenceReader::new_tagged_root(&suffixed, root_tag, &fields, &mut context);
        assert!(reader.is_err());

        for index in 0..valid.len() {
            for bit in 0..8 {
                let mut changed = valid;
                changed[index] ^= 1 << bit;
                let _ = decode(&changed);
            }
        }
    }

    /// Enforce tagged-root output and shifted-work limits at exact boundaries.
    /// Source: runtime complete-output and cumulative-work policy.
    /// Version: 2026-11-01. Inputs: low/high-tag DER records and tight limits.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged-root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_root_checks_final_output_and_shift_work() {
        let base_limits = Limits::default();
        let root_tag = Tag::context_specific(31);
        let output = |max_output_bytes| Limits {
            max_output_bytes,
            ..base_limits
        };

        let mut context = RecordContext::new(&output(6));
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        let encoded = writer.finish_tagged_root(root_tag).unwrap();
        assert_eq!(encoded.bytes, [0xbf, 0x1f, 3, 2, 1, 2]);

        let mut context = RecordContext::new(&output(5));
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        assert!(writer.finish_tagged_root(root_tag).is_err());

        let mut measured = RecordContext::new(&base_limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut measured).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        writer.finish_tagged_root(root_tag).unwrap();
        let exact_work_bits = measured.work_used;
        let exact_limits = Limits {
            max_work_bits: exact_work_bits,
            ..base_limits
        };
        let mut exact = RecordContext::new(&exact_limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut exact).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        assert!(writer.finish_tagged_root(root_tag).is_ok());

        let below_limits = Limits {
            max_work_bits: exact_work_bits - 1,
            ..base_limits
        };
        let mut below = RecordContext::new(&below_limits);
        let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut below).unwrap();
        writer.write_integer(2, 0, 3).unwrap();
        assert!(writer.finish_tagged_root(root_tag).is_err());
    }

    /// Exercise outer DER length encoding at the 127/128 content boundary.
    /// Source: X.690 shortest definite lengths and high-tag identifiers.
    /// Version: 2026-11-01. Inputs: OCTET STRING content lengths around 127.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged-root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_root_shifts_der_length_transition() {
        let limits = Limits::default();
        let root_tag = Tag::context_specific(31);
        let octets = RecordField::new(Tag::universal(4), FieldKind::OctetString).unwrap();
        let fields = [octets];
        for payload_len in [125, 126] {
            let payload = vec![0x5a; payload_len];
            let mut context = RecordContext::new(&limits);
            let mut writer = SequenceWriter::new(RecordEncoding::Der, &mut context).unwrap();
            writer
                .write_octet_string(&payload, payload_len, payload_len)
                .unwrap();
            let encoded = writer.finish_tagged_root(root_tag).unwrap();
            assert_eq!(&encoded.bytes[..2], &[0xbf, 0x1f]);
            if payload_len == 125 {
                assert_eq!(encoded.bytes[2], 127);
            } else {
                assert_eq!(&encoded.bytes[2..4], &[0x81, 0x80]);
            }

            let mut context = RecordContext::new(&limits);
            let mut reader =
                SequenceReader::new_tagged_root(&encoded.bytes, root_tag, &fields, &mut context)
                    .unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(octets.tag()));
            assert_eq!(
                reader.read_octet_string(payload_len, payload_len).unwrap(),
                payload
            );
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
        }
    }

    /// Match the C DER/CER SET fixture and decode members in reverse BER order.
    /// Source: C [3] IMPLICIT SET { [0] INTEGER 2, [1] BOOLEAN TRUE }.
    /// Version: 2026-11-01. Inputs: DER, CER, and reversed BER member order.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged SET root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_set_root_matches_c_vectors_and_accepts_unordered_ber() {
        let limits = Limits::default();
        let root_tag = Tag::context_specific(3);
        let integer_tag = Tag::context_specific(0);
        let boolean_tag = Tag::context_specific(1);
        let fields = [
            RecordField::new(integer_tag, FieldKind::Integer).unwrap(),
            RecordField::new(boolean_tag, FieldKind::Boolean).unwrap(),
        ];

        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        let der = writer.finish_tagged_root(root_tag).unwrap();
        assert_eq!(der.bytes, [0xa3, 6, 0x80, 1, 2, 0x81, 1, 0xff]);

        let mut context = RecordContext::new(&limits);
        let mut writer = SetWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        let cer = writer.finish_tagged_root(root_tag).unwrap();
        assert_eq!(cer.bytes, [0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0]);

        let reversed = [0xa3, 6, 0x81, 1, 0xff, 0x80, 1, 2];
        let mut suffixed = reversed.to_vec();
        suffixed.extend_from_slice(&[5, 0]);
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SetReader::new_tagged_root(&suffixed, root_tag, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(boolean_tag));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(integer_tag));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, reversed.len());

        let only_integer = [0xa3, 3, 0x80, 1, 2];
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SetReader::new_tagged_root(&only_integer, root_tag, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(integer_tag));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, only_integer.len());

        for (rule, encoded) in [
            (RecordEncoding::Der, &[0xa3, 0][..]),
            (RecordEncoding::Cer, &[0xa3, 0x80, 0, 0][..]),
        ] {
            let mut context = RecordContext::new(&limits);
            let writer = SetWriter::new(rule, &mut context).unwrap();
            assert_eq!(writer.finish_tagged_root(root_tag).unwrap().bytes, encoded);
            let mut context = RecordContext::new(&limits);
            let mut reader =
                SetReader::new_tagged_root(encoded, root_tag, &fields, &mut context).unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.len());
        }
    }

    /// Reject reversed SET order in CER using one cumulative operation context.
    /// Source: X.690 CER SET canonical ordering and shared budget contract.
    /// Version: 2026-11-01. Inputs: reversed CER members. Returns: assertions.
    /// Errors: assertion failures. Responsible: maintainers.
    /// History: tagged SET root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_set_root_strict_cer_reencoding_checks_sorted_order() {
        let limits = Limits::default();
        let root_tag = Tag::context_specific(3);
        let integer_tag = Tag::context_specific(0);
        let boolean_tag = Tag::context_specific(1);
        let fields = [
            RecordField::new(integer_tag, FieldKind::Integer).unwrap(),
            RecordField::new(boolean_tag, FieldKind::Boolean).unwrap(),
        ];
        let reversed = [0xa3, 0x80, 0x81, 1, 0xff, 0x80, 1, 2, 0, 0];
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SetReader::new_tagged_root(&reversed, root_tag, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(boolean_tag));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), Some(integer_tag));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        let consumed = reader.finish().unwrap().consumed_bytes;

        let mut writer = SetWriter::new(RecordEncoding::Cer, &mut context).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        let canonical = writer.finish_tagged_root(root_tag).unwrap();
        assert_eq!(
            canonical.bytes,
            [0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff, 0, 0]
        );
        assert!(context
            .verify_canonical(&reversed, consumed, &canonical.bytes)
            .is_err());
    }

    /// Check canonical high tags, BER aliases, and rejected root tag classes.
    /// Source: X.690 high tags and C-compatible parser range.
    /// Version: 2026-11-01. Inputs: boundary tags, aliases, invalid descriptors.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged SET root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_set_root_high_tags_aliases_and_validation() {
        let limits = Limits::default();
        let integer_tag = Tag::context_specific(0);
        let boolean_tag = Tag::context_specific(1);
        let fields = [
            RecordField::new(integer_tag, FieldKind::Integer).unwrap(),
            RecordField::new(boolean_tag, FieldKind::Boolean).unwrap(),
        ];
        for number in [30, 31, 127, MAX_TAG_NUMBER] {
            let tag = Tag::context_specific(number);
            let mut context = RecordContext::new(&limits);
            let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
            writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
            let encoded = writer.finish_tagged_root(tag).unwrap();
            let mut identifier = [0_u8; 6];
            let identifier_len = encode_identifier_bytes(tag, true, &mut identifier).unwrap();
            assert_eq!(
                &encoded.bytes[..identifier_len],
                &identifier[..identifier_len]
            );
            let mut context = RecordContext::new(&limits);
            let mut reader =
                SetReader::new_tagged_root(&encoded.bytes, tag, &fields, &mut context).unwrap();
            assert_eq!(reader.next_tagged_field().unwrap(), Some(integer_tag));
            assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
            assert_eq!(reader.next_tagged_field().unwrap(), None);
            assert_eq!(reader.finish().unwrap().consumed_bytes, encoded.bytes.len());
        }

        let alias = [0xbf, 0x80, 0x1f, 6, 0x80, 1, 2, 0x81, 1, 0xff];
        let alias_tag = Tag::context_specific(31);
        let mut context = RecordContext::new(&limits);
        let mut reader =
            SetReader::new_tagged_root(&alias, alias_tag, &fields, &mut context).unwrap();
        assert_eq!(reader.next_tagged_field().unwrap(), Some(integer_tag));
        assert_eq!(reader.read_integer(0, 3).unwrap(), 2);
        assert_eq!(reader.next_tagged_field().unwrap(), Some(boolean_tag));
        assert!(reader.read_boolean().unwrap());
        assert_eq!(reader.next_tagged_field().unwrap(), None);
        assert_eq!(reader.finish().unwrap().consumed_bytes, alias.len());

        let invalid_tags = [
            Tag::universal(3),
            Tag {
                class: TagClass::Application,
                number: 3,
            },
            Tag {
                class: TagClass::Private,
                number: 3,
            },
            Tag {
                class: TagClass::ContextSpecific,
                number: MAX_TAG_NUMBER + 1,
            },
        ];
        for tag in invalid_tags {
            let mut context = RecordContext::new(&limits);
            assert!(SetReader::new_tagged_root(&[], tag, &fields, &mut context).is_err());
            let mut context = RecordContext::new(&limits);
            let writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
            assert!(writer.finish_tagged_root(tag).is_err());
        }
    }

    /// Reject malformed SET root framing and bounded mutations.
    /// Source: X.690 constructed SET framing and EOC rules.
    /// Version: 2026-11-01. Inputs: truncations, EOC misuse, and mutations.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged SET root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_set_root_rejects_malformed_framing_and_checks_resources() {
        let limits = Limits::default();
        let root_tag = Tag::context_specific(3);
        let integer_tag = Tag::context_specific(0);
        let boolean_tag = Tag::context_specific(1);
        let fields = [
            RecordField::new(integer_tag, FieldKind::Integer).unwrap(),
            RecordField::new(boolean_tag, FieldKind::Boolean).unwrap(),
        ];
        let reversed = [0xa3, 6, 0x81, 1, 0xff, 0x80, 1, 2];
        let decode = |input: &[u8]| -> Result<usize, Error> {
            let mut context = RecordContext::new(&limits);
            let mut reader = SetReader::new_tagged_root(input, root_tag, &fields, &mut context)?;
            while let Some(tag) = reader.next_tagged_field()? {
                match tag {
                    tag if tag == boolean_tag => {
                        reader.read_boolean()?;
                    }
                    tag if tag == integer_tag => {
                        reader.read_integer(0, 3)?;
                    }
                    _ => return Err(invalid("tagged SET contains an unknown member")),
                }
            }
            Ok(reader.finish()?.consumed_bytes)
        };
        for end in 0..reversed.len() {
            assert!(decode(&reversed[..end]).is_err());
        }
        assert_eq!(decode(&reversed).unwrap(), reversed.len());
        let mut suffixed = reversed.to_vec();
        suffixed.extend_from_slice(&[5, 0]);
        let tight_input = Limits {
            max_input_bytes: reversed.len(),
            ..limits
        };
        let mut context = RecordContext::new(&tight_input);
        assert!(SetReader::new_tagged_root(&suffixed, root_tag, &fields, &mut context).is_err());
        assert!(decode(&[0x83, 6, 0x80, 1, 2, 0x81, 1, 0xff]).is_err());
        assert!(decode(&[0xa3, 8, 0, 0, 0x80, 1, 2, 0x81, 1, 0xff]).is_err());
        assert!(decode(&[0xa3, 0x80, 0x80, 1, 2, 0x81, 1, 0xff]).is_err());
        assert!(decode(&[0xbf, 0x84, 0x80, 0x80, 0x80, 0, 6, 0x80, 1, 2, 0x81, 1, 0xff]).is_err());
        for index in 0..reversed.len() {
            for bit in 0..8 {
                let mut changed = reversed;
                changed[index] ^= 1 << bit;
                let _ = decode(&changed);
            }
        }
    }

    /// Enforce tagged SET output and shifted-work budgets at exact boundaries.
    /// Source: runtime complete-output and cumulative-work policy.
    /// Version: 2026-11-01. Inputs: high-tag SET and tight limits.
    /// Returns: assertions. Errors: assertion failures. Responsible: maintainers.
    /// History: tagged SET root regression. Example: run via `cargo test`.
    #[test]
    fn tagged_set_root_checks_output_and_work_limits() {
        let limits = Limits::default();
        let integer_tag = Tag::context_specific(0);
        let boolean_tag = Tag::context_specific(1);
        let high_tag = Tag::context_specific(31);
        let exact_output = Limits {
            max_output_bytes: 9,
            ..limits
        };
        let mut context = RecordContext::new(&exact_output);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        assert_eq!(writer.finish_tagged_root(high_tag).unwrap().bytes.len(), 9);

        let below_output = Limits {
            max_output_bytes: 8,
            ..limits
        };
        let mut context = RecordContext::new(&below_output);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut context).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        assert!(writer.finish_tagged_root(high_tag).is_err());

        let measured_limits = Limits::default();
        let mut measured = RecordContext::new(&measured_limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut measured).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        writer.finish_tagged_root(high_tag).unwrap();
        let exact_work = measured.work_used;
        let exact_limits = Limits {
            max_work_bits: exact_work,
            ..measured_limits
        };
        let mut exact = RecordContext::new(&exact_limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut exact).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        assert!(writer.finish_tagged_root(high_tag).is_ok());
        let below_limits = Limits {
            max_work_bits: exact_work - 1,
            ..measured_limits
        };
        let mut below = RecordContext::new(&below_limits);
        let mut writer = SetWriter::new(RecordEncoding::Der, &mut below).unwrap();
        writer.write_integer_tagged(integer_tag, 2, 0, 3).unwrap();
        writer.write_boolean_tagged(boolean_tag, true).unwrap();
        assert!(writer.finish_tagged_root(high_tag).is_err());
    }

    /// Normalize independent base-128 arcs and reject empty or dangling content.
    ///
    /// # Parameters and returns
    /// No parameters. Checks both public constructors and retained canonical bytes.
    ///
    /// # Errors
    /// Panics on an unexpected normalization or validation result.
    ///
    /// # Source, version, history, example
    /// Source: X.690 OID content rules. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_constructors_normalize_arcs_and_reject_dangling_content() {
        let limits = Limits::default();
        let oid = ObjectIdentifier::try_from_content(&[0x80, 0x80, 42, 0x80, 1], &limits).unwrap();
        assert_eq!(oid.as_content(), [42, 1]);
        let relative = RelativeOid::try_from_content(&[0x80, 0x80, 0, 0x81, 0], &limits).unwrap();
        assert_eq!(relative.as_content(), [0, 0x81, 0]);

        for invalid_content in [&[][..], &[0x80][..], &[1, 0x80][..], &[0, 0x80, 0x80][..]] {
            assert!(ObjectIdentifier::try_from_content(invalid_content, &limits).is_err());
            assert!(RelativeOid::try_from_content(invalid_content, &limits).is_err());
        }

        let exact_multi_group = Limits {
            max_input_bytes: 3,
            max_output_bytes: 1,
            max_work_bits: 48,
        };
        assert!(ObjectIdentifier::try_from_content(&[0x80, 0x80, 42], &exact_multi_group).is_ok());
        assert!(ObjectIdentifier::try_from_content(
            &[0x80, 0x80, 42],
            &Limits {
                max_work_bits: 47,
                ..exact_multi_group
            }
        )
        .is_err());
    }

    /// Round-trip low, combined-first-arc, and wider-than-u64 OID content.
    ///
    /// # Parameters and returns
    /// No parameters. Checks DER/CER outputs and BER/CER prefix consumption.
    ///
    /// # Errors
    /// Panics on codec or byte-vector mismatches.
    ///
    /// # Source, version, history, example
    /// Source: X.690 OBJECT IDENTIFIER and RELATIVE-OID. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_der_cer_round_trip_large_base128_subidentifiers() {
        let limits = Limits::default();
        let mut huge_arc = vec![0x81; 20];
        huge_arc.push(0);
        let oid_values: &[&[u8]] = &[&[0, 0], &[39], &[40], &[0x81, 0], &huge_arc];
        for content in oid_values {
            let value = ObjectIdentifier::try_from_content(content, &limits).unwrap();
            let der = encode_object_identifier_der(&value, &limits).unwrap();
            let cer = encode_object_identifier_cer(&value, &limits).unwrap();
            assert_eq!(der.bytes, cer.bytes);
            assert_eq!(
                decode_object_identifier_ber(&der.bytes, &limits)
                    .unwrap()
                    .value,
                value
            );
            assert_eq!(
                decode_object_identifier_cer(&cer.bytes, &limits)
                    .unwrap()
                    .value,
                value
            );
        }

        let relative_values: &[&[u8]] = &[&[0], &[0x81, 0], &huge_arc];
        for content in relative_values {
            let value = RelativeOid::try_from_content(content, &limits).unwrap();
            let der = encode_relative_oid_der(&value, &limits).unwrap();
            let cer = encode_relative_oid_cer(&value, &limits).unwrap();
            assert_eq!(der.bytes, cer.bytes);
            assert_eq!(
                decode_relative_oid_ber(&der.bytes, &limits).unwrap().value,
                value
            );
            assert_eq!(
                decode_relative_oid_cer(&cer.bytes, &limits).unwrap().value,
                value
            );
        }
    }

    /// Accept C-compatible BER tag/content aliases and reject them in strict CER.
    ///
    /// # Parameters and returns
    /// No parameters. Checks high-tag aliases, arc normalization, and suffixes.
    ///
    /// # Errors
    /// Panics on unexpected BER acceptance or CER canonicality results.
    ///
    /// # Source, version, history, example
    /// Source: X.690 identifiers and base-128 arcs. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_ber_accepts_high_tag_and_arc_aliases_but_cer_rejects() {
        let limits = Limits::default();
        let aliases: &[&[u8]] = &[
            &[0x1f, 6, 1, 42],
            &[6, 3, 0x80, 0x80, 42],
            &[0x1f, 0x80, 6, 3, 0x80, 0x80, 42],
        ];
        for alias in aliases {
            let decoded = decode_object_identifier_ber(alias, &limits).unwrap();
            assert_eq!(decoded.value.as_content(), [42]);
            assert_eq!(decoded.consumed_bytes, alias.len());
            assert!(decode_object_identifier_cer(alias, &limits).is_err());
        }
        let relative_alias = [0x1f, 0x0d, 3, 0x80, 0x80, 42];
        let decoded = decode_relative_oid_ber(&relative_alias, &limits).unwrap();
        assert_eq!(decoded.value.as_content(), [42]);
        assert!(decode_relative_oid_cer(&relative_alias, &limits).is_err());

        let canonical_with_suffix = [6, 1, 42, 0xff];
        let decoded = decode_object_identifier_cer(&canonical_with_suffix, &limits).unwrap();
        assert_eq!(decoded.value.as_content(), [42]);
        assert_eq!(decoded.consumed_bytes, 3);
    }

    /// Keep OID CER primitive at short, long-form, and 1001-byte content sizes.
    ///
    /// # Parameters and returns
    /// No parameters. Checks C vectors at 127, 128, and 1001 content octets.
    ///
    /// # Errors
    /// Panics on output, length, primitive-form, or strict-decode mismatches.
    ///
    /// # Source, version, history, example
    /// Source: X.690 OID CER forms and C probes. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_cer_length_boundaries_remain_primitive() {
        let limits = Limits::default();
        for content_len in [127, 128, 1001] {
            let content = vec![0; content_len];
            let oid = ObjectIdentifier::try_from_content(&content, &limits).unwrap();
            let relative = RelativeOid::try_from_content(&content, &limits).unwrap();
            let oid_encoding = encode_object_identifier_cer(&oid, &limits).unwrap();
            let relative_encoding = encode_relative_oid_cer(&relative, &limits).unwrap();
            assert_oid_cer_length_vector(
                TAG_OBJECT_IDENTIFIER,
                content_len,
                &oid_encoding,
                decode_object_identifier_cer(&oid_encoding.bytes, &limits).is_ok(),
            );
            assert_oid_cer_length_vector(
                TAG_RELATIVE_OID,
                content_len,
                &relative_encoding,
                decode_relative_oid_cer(&relative_encoding.bytes, &limits).is_ok(),
            );
        }
    }

    /// Check one primitive OID CER TLV's shortest length boundary.
    ///
    /// # Parameters and returns
    /// `tag`, `content_len`, and `encoded` identify the TLV; `decoded` reports
    /// strict decoder success. Returns by assertion.
    ///
    /// # Errors
    /// Panics when output length/header or strict decoding is incorrect.
    ///
    /// # Source, version, history, example
    /// Source: X.690 OID CER lengths. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: called for both universal OID tags.
    fn assert_oid_cer_length_vector(
        tag: u32,
        content_len: usize,
        encoded: &Encoded,
        decoded: bool,
    ) {
        let expected_len = match content_len {
            127 => 129,
            128 => 131,
            _ => 1005,
        };
        assert_eq!(encoded.bytes.len(), expected_len);
        assert_eq!(encoded.bytes[0], u8::try_from(tag).unwrap());
        assert!(decoded);
        match content_len {
            127 => assert_eq!(&encoded.bytes[..2], &[u8::try_from(tag).unwrap(), 0x7f]),
            128 => assert_eq!(
                &encoded.bytes[..3],
                &[u8::try_from(tag).unwrap(), 0x81, 0x80]
            ),
            _ => assert_eq!(
                &encoded.bytes[..4],
                &[u8::try_from(tag).unwrap(), 0x82, 3, 0xe9]
            ),
        }
    }

    /// Reject empty, dangling, malformed-length, constructed, and wrong-tag OIDs.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises both OID types with malformed BER root forms.
    ///
    /// # Errors
    /// Panics if malformed input is accepted.
    ///
    /// # Source, version, history, example
    /// Source: X.690 primitive OID rules. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_decoders_reject_empty_dangling_and_malformed_roots() {
        let limits = Limits::default();
        let invalid_values: &[&[u8]] = &[
            &[0, 0],
            &[0x26, 0],
            &[0x2d, 0],
            &[6, 0x80, 0, 0],
            &[6, 0],
            &[6, 1, 0x80],
            &[6, 2, 1, 0x80],
            &[6, 3, 0, 0x80, 0x80],
            &[6, 0x82, 0],
            &[6, 0x82, 0, 2, 1],
            &[6, 0xff],
            &[0x1f, 0x86],
        ];
        for input in invalid_values {
            assert!(decode_object_identifier_ber(input, &limits).is_err());
            assert!(decode_object_identifier_cer(input, &limits).is_err());
            assert!(decode_relative_oid_ber(input, &limits).is_err());
            assert!(decode_relative_oid_cer(input, &limits).is_err());
        }
        for invalid_content in [&[][..], &[1, 0x80][..], &[0, 0x80, 0x80][..]] {
            let mut oid = vec![6, u8::try_from(invalid_content.len()).unwrap()];
            oid.extend_from_slice(invalid_content);
            let mut relative = vec![13, u8::try_from(invalid_content.len()).unwrap()];
            relative.extend_from_slice(invalid_content);
            assert!(decode_object_identifier_ber(&oid, &limits).is_err());
            assert!(decode_object_identifier_cer(&oid, &limits).is_err());
            assert!(decode_relative_oid_ber(&relative, &limits).is_err());
            assert!(decode_relative_oid_cer(&relative, &limits).is_err());
        }
        let mut tag_overflow = vec![0x1f];
        tag_overflow.extend([0xff; 5]);
        tag_overflow.extend([0x7f, 1, 42]);
        assert!(decode_object_identifier_ber(&tag_overflow, &limits).is_err());
        let mut length_overflow = vec![6, 0x89];
        length_overflow.extend([0xff; 9]);
        assert!(decode_object_identifier_ber(&length_overflow, &limits).is_err());
    }

    /// Check OID constructor and encoder input/output/work ceilings exactly.
    ///
    /// # Parameters and returns
    /// No parameters. Checks exact limits and one-unit-below rejection.
    ///
    /// # Errors
    /// Panics on unexpected boundary behavior.
    ///
    /// # Source, version, history, example
    /// Source: runtime OID scalar resource policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_constructors_and_encoders_check_exact_limits() {
        let exact = Limits {
            max_input_bytes: 2,
            max_output_bytes: 1,
            max_work_bits: 32,
        };
        let oid = ObjectIdentifier::try_from_content(&[0x80, 42], &exact).unwrap();
        assert_eq!(oid.as_content(), [42]);
        for too_small in [
            Limits {
                max_input_bytes: 1,
                ..exact
            },
            Limits {
                max_output_bytes: 0,
                ..exact
            },
            Limits {
                max_work_bits: 31,
                ..exact
            },
        ] {
            assert!(ObjectIdentifier::try_from_content(&[0x80, 42], &too_small).is_err());
        }

        let exact_encode = Limits {
            max_input_bytes: 1,
            max_output_bytes: 3,
            max_work_bits: 24,
        };
        assert_eq!(
            encode_object_identifier_der(&oid, &exact_encode)
                .unwrap()
                .bytes,
            [6, 1, 42]
        );
        assert!(encode_object_identifier_der(
            &oid,
            &Limits {
                max_output_bytes: 2,
                ..exact_encode
            }
        )
        .is_err());
        assert!(encode_object_identifier_der(
            &oid,
            &Limits {
                max_work_bits: 23,
                ..exact_encode
            }
        )
        .is_err());
        assert!(check_oid_scratch(MAX_OID_SCRATCH_BYTES).is_ok());
        assert!(check_oid_scratch(MAX_OID_SCRATCH_BYTES + 1).is_err());
        assert!(encode_oid_content_precharged(
            &[0],
            MAX_OID_SCRATCH_BYTES - 2,
            TAG_OBJECT_IDENTIFIER,
            &Limits::default()
        )
        .is_err());
        assert!(copy_oid_content(&[0], 1, MAX_OID_SCRATCH_BYTES, &Limits::default()).is_err());
    }

    /// Check decoder whole-slice input, retained output, and exact work limits.
    ///
    /// # Parameters and returns
    /// No parameters. Checks BER OID and RELATIVE-OID limits at exact boundaries.
    ///
    /// # Errors
    /// Panics on unexpected resource-limit results.
    ///
    /// # Source, version, history, example
    /// Source: runtime prefix decoder resource contract. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_ber_decoders_check_whole_input_retained_output_and_work() {
        let input = [6, 1, 42, 0xff];
        let exact_work = minimum_oid_work(&input, |bytes, budget| {
            decode_object_identifier_ber(bytes, budget).map(|_| ())
        });
        let exact_limits = Limits {
            max_input_bytes: input.len(),
            max_output_bytes: 1,
            max_work_bits: exact_work,
        };
        let decoded = decode_object_identifier_ber(&input, &exact_limits).unwrap();
        assert_eq!(decoded.value.as_content(), [42]);
        assert_eq!(decoded.consumed_bytes, 3);
        assert!(decode_object_identifier_ber(
            &input,
            &Limits {
                max_input_bytes: input.len() - 1,
                ..exact_limits
            }
        )
        .is_err());
        assert!(decode_object_identifier_ber(
            &input,
            &Limits {
                max_output_bytes: 0,
                ..exact_limits
            }
        )
        .is_err());
        assert!(decode_object_identifier_ber(
            &input,
            &Limits {
                max_work_bits: exact_work - 1,
                ..exact_limits
            }
        )
        .is_err());

        let relative = [13, 1, 42];
        assert_eq!(
            decode_relative_oid_ber(&relative, &exact_limits)
                .unwrap()
                .value
                .as_content(),
            [42]
        );
    }

    /// Find the minimum work ceiling at which one valid OID decode passes.
    ///
    /// # Parameters and returns
    /// `input` is canonical; `decode` is one strict OID decoder. Returns its
    /// exact cumulative work threshold by binary search.
    ///
    /// # Errors
    /// Panics if the canonical input fails at the default work ceiling.
    ///
    /// # Source, version, history, example
    /// Source: scalar codec work budget. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: called by the exact-work test below.
    fn minimum_oid_work<F>(input: &[u8], decode: F) -> usize
    where
        F: Fn(&[u8], &Limits) -> Result<(), Error>,
    {
        let default_limit = Limits::default().max_work_bits;
        let mut low = 0_usize;
        let mut high = default_limit;
        assert!(decode(input, &Limits::default()).is_ok());
        while low < high {
            let middle = low + (high - low) / 2;
            let limits = Limits {
                max_work_bits: middle,
                ..Limits::default()
            };
            if decode(input, &limits).is_ok() {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    /// Verify strict CER OID work includes parse, scan, copy, output, and compare.
    ///
    /// # Parameters and returns
    /// No parameters. Checks exact and one-bit-below work for OID and RELATIVE-OID.
    ///
    /// # Errors
    /// Panics on unexpected work accounting or canonicality behavior.
    ///
    /// # Source, version, history, example
    /// Source: cumulative scalar CER work contract. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_strict_cer_uses_one_cumulative_work_budget() {
        let limits = Limits::default();
        let oid = encode_object_identifier_cer(
            &ObjectIdentifier::try_from_content(&[0x81, 0], &limits).unwrap(),
            &limits,
        )
        .unwrap();
        let relative = encode_relative_oid_cer(
            &RelativeOid::try_from_content(&[0x81, 0], &limits).unwrap(),
            &limits,
        )
        .unwrap();
        let oid_work = minimum_oid_work(&oid.bytes, |input, budget| {
            decode_object_identifier_cer(input, budget).map(|_| ())
        });
        let relative_work = minimum_oid_work(&relative.bytes, |input, budget| {
            decode_relative_oid_cer(input, budget).map(|_| ())
        });
        assert_eq!(oid_work, 128);
        assert_eq!(relative_work, 128);
        let exact_oid = Limits {
            max_work_bits: oid_work,
            ..limits
        };
        let below_oid = Limits {
            max_work_bits: oid_work - 1,
            ..limits
        };
        assert!(decode_object_identifier_cer(&oid.bytes, &exact_oid).is_ok());
        assert!(decode_object_identifier_cer(&oid.bytes, &below_oid).is_err());

        let exact_relative = Limits {
            max_work_bits: relative_work,
            ..limits
        };
        let below_relative = Limits {
            max_work_bits: relative_work - 1,
            ..limits
        };
        assert!(decode_relative_oid_cer(&relative.bytes, &exact_relative).is_ok());
        assert!(decode_relative_oid_cer(&relative.bytes, &below_relative).is_err());
    }

    /// Mutate OID tag, length, and content bytes without allowing decoder panics.
    ///
    /// # Parameters and returns
    /// No parameters. Tries all byte substitutions and every proper prefix.
    ///
    /// # Errors
    /// Panics only if a decoder unwinds on mutated untrusted input.
    ///
    /// # Source, version, history, example
    /// Source: BER parser mutation hardening. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct OID gate.
    /// Example: run with `cargo test`.
    #[test]
    fn oid_single_byte_mutations_and_truncations_do_not_panic() {
        let limits = Limits::default();
        let vectors: &[&[u8]] = &[
            &[6, 3, 0x2a, 0x86, 0x48],
            &[13, 2, 0x81, 0],
            &[0x1f, 0x80, 6, 3, 0x80, 0x80, 42],
        ];
        for vector in vectors {
            for end in 0..vector.len() {
                let truncated = &vector[..end];
                let _ = decode_object_identifier_ber(truncated, &limits);
                let _ = decode_object_identifier_cer(truncated, &limits);
                let _ = decode_relative_oid_ber(truncated, &limits);
                let _ = decode_relative_oid_cer(truncated, &limits);
            }
            for index in 0..vector.len() {
                for replacement in 0_u8..=u8::MAX {
                    let mut mutated = vector.to_vec();
                    mutated[index] = replacement;
                    let _ = decode_object_identifier_ber(&mutated, &limits);
                    let _ = decode_object_identifier_cer(&mutated, &limits);
                    let _ = decode_relative_oid_ber(&mutated, &limits);
                    let _ = decode_relative_oid_cer(&mutated, &limits);
                }
            }
        }
    }

    /// Preserve raw bytes in BER/DER and apply the repertoire rule only in CER.
    ///
    /// # Parameters and returns
    /// No parameters. Checks constructor and codec policy with valid/invalid IA5.
    ///
    /// # Errors
    /// Panics on unexpected codec values or policy acceptance.
    ///
    /// # Source, version, history, example
    /// Source: C IA5 callback behavior. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_raw_ber_der_and_cer_constraint_timing() {
        let limits = Limits::default();
        let raw = Ia5String::try_from_bytes(&[0, 0x1b, 0x7f, 0x80, 0xff], &limits).unwrap();
        assert_eq!(raw.as_bytes(), [0, 0x1b, 0x7f, 0x80, 0xff]);
        assert_eq!(
            encode_ia5_string_der(&raw, &limits).unwrap().bytes,
            [0x16, 5, 0, 0x1b, 0x7f, 0x80, 0xff]
        );
        assert!(encode_ia5_string_cer(&raw, &limits).is_err());

        let decoded = decode_ia5_string_ber(&[0x16, 1, 0x80], &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), [0x80]);
        assert_eq!(decoded.consumed_bytes, 3);
        assert!(decode_ia5_string_cer(&[0x16, 1, 0x80], &limits).is_err());

        let valid = Ia5String::try_from_bytes(&[0, 0x1b, 0x7f], &limits).unwrap();
        assert_eq!(
            encode_ia5_string_cer(&valid, &limits).unwrap().bytes,
            [0x16, 3, 0, 0x1b, 0x7f]
        );
        assert_eq!(
            decode_ia5_string_cer(&[0x16, 3, 0, 0x1b, 0x7f], &limits)
                .unwrap()
                .value
                .as_bytes(),
            [0, 0x1b, 0x7f]
        );
    }

    /// Accept BER constructed IA5 content only through universal OCTET fragments.
    ///
    /// # Parameters and returns
    /// No parameters. Covers definite, nested-indefinite, empty, and suffix cases.
    ///
    /// # Errors
    /// Panics on incorrect bytes, consumption, or canonicality decisions.
    ///
    /// # Source, version, history, example
    /// Source: X.690 constructed strings and C probe. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_ber_constructed_fragments_and_prefix_consumption() {
        let limits = Limits::default();
        let definite = [0x36, 5, 4, 1, b'A', 4, 0];
        let decoded = decode_ia5_string_ber(&definite, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"A");
        assert_eq!(decoded.consumed_bytes, definite.len());

        let nested = [0x36, 0x80, 4, 1, b'A', 0x24, 0x80, 4, 1, b'B', 0, 0, 0, 0];
        let decoded = decode_ia5_string_ber(&nested, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"AB");
        assert_eq!(decoded.consumed_bytes, nested.len());
        assert!(decode_ia5_string_cer(&nested, &limits).is_err());

        let constructed_empty = [0x36, 0x80, 0, 0];
        let decoded = decode_ia5_string_ber(&constructed_empty, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), []);
        assert_eq!(decoded.consumed_bytes, constructed_empty.len());
        assert!(decode_ia5_string_cer(&constructed_empty, &limits).is_err());
        assert!(decode_ia5_string_cer(&[0x16, 0], &limits).is_ok());

        let with_suffix = [0x36, 0x80, 4, 1, b'Z', 0, 0, 0xff];
        let decoded = decode_ia5_string_ber(&with_suffix, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"Z");
        assert_eq!(decoded.consumed_bytes, 7);
    }

    /// Reject malformed IA5 framing, wrong fragment tags, and misplaced EOC.
    ///
    /// # Parameters and returns
    /// No parameters. Sends malformed and truncated root/child forms to BER.
    ///
    /// # Errors
    /// Panics if any malformed input is accepted.
    ///
    /// # Source, version, history, example
    /// Source: X.690 BER TLV rules. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_ber_rejects_malformed_roots_and_children() {
        let limits = Limits::default();
        let malformed: &[&[u8]] = &[
            &[],
            &[0x16],
            &[0x16, 0x80, 0, 0],
            &[0x16, 1],
            &[0x16, 2, b'A'],
            &[0x36, 0x80, 4, 1, b'A'],
            &[0x36, 0x80, 0, 1],
            &[0x36, 1, 4],
            &[0x36, 0x80, 0x16, 1, b'A', 0, 0],
            &[0x36, 0x80, 0x0c, 1, b'A', 0, 0],
            &[0x36, 0x80, 4, 0x80, 0, 0, 0, 0],
            &[0x17, 0],
            &[0x1f, 0x81],
        ];
        for input in malformed {
            assert!(decode_ia5_string_ber(input, &limits).is_err(), "{input:?}");
        }
    }

    /// Accept C-compatible BER low-tag aliases while requiring canonical CER.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises root and universal OCTET fragment aliases.
    ///
    /// # Errors
    /// Panics on alias rejection in BER or alias acceptance in strict CER.
    ///
    /// # Source, version, history, example
    /// Source: C BER alias probes. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_ber_aliases_are_normalized_by_cer_validation() {
        let limits = Limits::default();
        let root_alias = [0x1f, 0x16, 1, b'A'];
        let decoded = decode_ia5_string_ber(&root_alias, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"A");
        assert_eq!(decoded.consumed_bytes, root_alias.len());
        assert!(decode_ia5_string_cer(&root_alias, &limits).is_err());

        let child_alias = [0x36, 0x80, 0x1f, 4, 1, b'A', 0, 0];
        assert_eq!(
            decode_ia5_string_ber(&child_alias, &limits)
                .unwrap()
                .value
                .as_bytes(),
            b"A"
        );
        assert!(decode_ia5_string_cer(&child_alias, &limits).is_err());

        let high_bit_child = [0x36, 0x80, 4, 1, 0x80, 0, 0];
        assert_eq!(
            decode_ia5_string_ber(&high_bit_child, &limits)
                .unwrap()
                .value
                .as_bytes(),
            [0x80]
        );
        assert!(decode_ia5_string_cer(&high_bit_child, &limits).is_err());
    }

    /// Check primitive length transitions and CER fragmentation boundaries.
    ///
    /// # Parameters and returns
    /// No parameters. Validates 127/128 and 1000/1001/2001-byte content forms.
    ///
    /// # Errors
    /// Panics on mismatched expected lengths, headers, fragments, or round trips.
    ///
    /// # Source, version, history, example
    /// Source: X.690 CER plus C probes. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_cer_short_long_and_fragment_boundaries() {
        let limits = Limits::default();
        let cases = [
            (0, 2),
            (127, 129),
            (128, 131),
            (999, 1003),
            (1000, 1004),
            (1001, 1011),
            (2001, 2015),
        ];
        for (size, expected_len) in cases {
            let value = Ia5String::try_from_bytes(&vec![0x7f; size], &limits).unwrap();
            let encoded = encode_ia5_string_cer(&value, &limits).unwrap();
            assert_eq!(encoded.bytes.len(), expected_len);
            assert_eq!(encoded.bit_len, expected_len * 8);
            let decoded = decode_ia5_string_cer(&encoded.bytes, &limits).unwrap();
            assert_eq!(decoded.value.as_bytes(), value.as_bytes());
            assert_eq!(decoded.consumed_bytes, expected_len);
        }

        let value_127 = Ia5String::try_from_bytes(&[0x41; 127], &limits).unwrap();
        assert_eq!(
            &encode_ia5_string_cer(&value_127, &limits).unwrap().bytes[..2],
            &[0x16, 127]
        );
        let value_128 = Ia5String::try_from_bytes(&[0x41; 128], &limits).unwrap();
        assert_eq!(
            &encode_ia5_string_cer(&value_128, &limits).unwrap().bytes[..3],
            &[0x16, 0x81, 0x80]
        );

        let value_1001 = Ia5String::try_from_bytes(&vec![0x7f; 1001], &limits).unwrap();
        let encoded = encode_ia5_string_cer(&value_1001, &limits).unwrap();
        assert_eq!(&encoded.bytes[..6], &[0x36, 0x80, 4, 0x82, 3, 0xe8]);
        assert_eq!(
            &encoded.bytes[encoded.bytes.len() - 5..],
            &[4, 1, 0x7f, 0, 0]
        );
    }

    /// Enforce exact constructor, DER, and CER encoder resource limits.
    ///
    /// # Parameters and returns
    /// No parameters. Checks input, output, and work ceilings at exact boundaries.
    ///
    /// # Errors
    /// Panics on resource acceptance below the documented measured threshold.
    ///
    /// # Source, version, history, example
    /// Source: runtime IA5 resource policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_constructor_and_encoder_limits_are_exact() {
        let exact = Limits {
            max_input_bytes: 2,
            max_output_bytes: 2,
            max_work_bits: 16,
        };
        assert_eq!(
            Ia5String::try_from_bytes(&[0, 0x7f], &exact)
                .unwrap()
                .as_bytes(),
            [0, 0x7f]
        );
        assert!(Ia5String::try_from_bytes(
            &[0, 0x7f],
            &Limits {
                max_input_bytes: 1,
                ..exact
            }
        )
        .is_err());
        assert!(Ia5String::try_from_bytes(
            &[0, 0x7f],
            &Limits {
                max_output_bytes: 1,
                ..exact
            }
        )
        .is_err());
        assert!(Ia5String::try_from_bytes(
            &[0, 0x7f],
            &Limits {
                max_work_bits: 15,
                ..exact
            }
        )
        .is_err());

        let value = Ia5String::try_from_bytes(&[0, 0x7f], &Limits::default()).unwrap();
        let der_exact = Limits {
            max_output_bytes: 4,
            max_work_bits: 32,
            ..Limits::default()
        };
        assert_eq!(
            encode_ia5_string_der(&value, &der_exact).unwrap().bytes,
            [0x16, 2, 0, 0x7f]
        );
        assert!(encode_ia5_string_der(
            &value,
            &Limits {
                max_output_bytes: 3,
                ..der_exact
            }
        )
        .is_err());
        assert!(encode_ia5_string_der(
            &value,
            &Limits {
                max_work_bits: 31,
                ..der_exact
            }
        )
        .is_err());

        let cer_exact = Limits {
            max_output_bytes: 4,
            max_work_bits: 48,
            ..Limits::default()
        };
        assert!(encode_ia5_string_cer(&value, &cer_exact).is_ok());
        assert!(encode_ia5_string_cer(
            &value,
            &Limits {
                max_work_bits: 47,
                ..cer_exact
            }
        )
        .is_err());

        assert!(check_character_string_scratch(MAX_CHARACTER_STRING_SCRATCH_BYTES).is_ok());
        assert!(check_character_string_scratch(MAX_CHARACTER_STRING_SCRATCH_BYTES + 1).is_err());
    }

    /// Check retained-plus-output scratch boundaries without large allocations.
    ///
    /// # Parameters and returns
    /// No parameters. Uses a one-byte value and synthetic retained capacities.
    ///
    /// # Errors
    /// Panics if exact scratch capacity fails or one byte above the cap passes.
    ///
    /// # Source, version, history, example
    /// Source: IA5 scalar scratch policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_encoders_preflight_combined_scratch_capacity() {
        let limits = Limits {
            max_output_bytes: 3,
            ..Limits::default()
        };
        let exact_retained = MAX_CHARACTER_STRING_SCRATCH_BYTES - 3;
        let over_retained = exact_retained + 1;

        assert_eq!(
            encode_ia5_der(&[0], exact_retained, &limits).unwrap().bytes,
            [0x16, 1, 0]
        );
        assert!(encode_ia5_der(&[0], over_retained, &limits).is_err());
        assert_eq!(
            encode_ia5_cer_precharged(&[0], exact_retained, &limits)
                .unwrap()
                .bytes,
            [0x16, 1, 0]
        );
        assert!(encode_ia5_cer_precharged(&[0], over_retained, &limits).is_err());
    }

    /// Enforce BER and strict-CER decoder limits, including cumulative work.
    ///
    /// # Parameters and returns
    /// No parameters. Checks exact and one-below decode resource boundaries.
    ///
    /// # Errors
    /// Panics on unexpected resource acceptance or work accounting.
    ///
    /// # Source, version, history, example
    /// Source: runtime IA5 resource policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_decoder_limits_and_strict_work_are_exact() {
        let ber_with_suffix = [0x16, 2, 0, 0x7f, 0xff];
        let ber_work = minimum_ia5_ber_work(&ber_with_suffix);
        let ber_exact = Limits {
            max_input_bytes: ber_with_suffix.len(),
            max_output_bytes: 2,
            max_work_bits: ber_work,
        };
        let decoded = decode_ia5_string_ber(&ber_with_suffix, &ber_exact).unwrap();
        assert_eq!(decoded.value.as_bytes(), [0, 0x7f]);
        assert_eq!(decoded.consumed_bytes, 4);
        assert!(decode_ia5_string_ber(
            &ber_with_suffix,
            &Limits {
                max_input_bytes: ber_with_suffix.len() - 1,
                ..ber_exact
            }
        )
        .is_err());
        assert!(decode_ia5_string_ber(
            &ber_with_suffix,
            &Limits {
                max_output_bytes: 1,
                ..ber_exact
            }
        )
        .is_err());
        assert!(decode_ia5_string_ber(
            &ber_with_suffix,
            &Limits {
                max_work_bits: ber_work - 1,
                ..ber_exact
            }
        )
        .is_err());

        let canonical = [0x16, 1, b'A'];
        let minimum = minimum_ia5_cer_work(&canonical);
        assert_eq!(minimum, 88);
        let exact_cer = Limits {
            max_work_bits: minimum,
            ..Limits::default()
        };
        let below_cer = Limits {
            max_work_bits: minimum - 1,
            ..Limits::default()
        };
        assert!(decode_ia5_string_cer(&canonical, &exact_cer).is_ok());
        assert!(decode_ia5_string_cer(&canonical, &below_cer).is_err());
        assert!(decode_ia5_string_cer(
            &canonical,
            &Limits {
                max_output_bytes: 2,
                ..Limits::default()
            }
        )
        .is_err());
        let strict_with_suffix = [0x16, 1, b'A', 0xff];
        let strict_prefix = decode_ia5_string_cer(&strict_with_suffix, &Limits::default()).unwrap();
        assert_eq!(strict_prefix.consumed_bytes, 3);

        let malformed_high_tag = [0x1f, 0x81, 0x80, 0x16, 1, 0x41];
        let low_work = Limits {
            max_work_bits: 8,
            ..Limits::default()
        };
        assert!(matches!(
            decode_ia5_string_ber(&malformed_high_tag, &low_work),
            Err(Error::LimitExceeded {
                resource: Resource::WorkBits,
                ..
            })
        ));
    }

    /// Find the minimum cumulative work ceiling for strict IA5 CER decoding.
    ///
    /// # Parameters and returns
    /// `input` is canonical CER; returns the least passing work limit.
    ///
    /// # Errors
    /// Panics if default limits reject canonical test input.
    ///
    /// # Source, version, history, example
    /// Source: scalar codec resource tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: called by `ia5_decoder_limits_and_strict_work_are_exact`.
    fn minimum_ia5_cer_work(input: &[u8]) -> usize {
        let decode = |limits: &Limits| decode_ia5_string_cer(input, limits).map(|_| ());
        let mut low = 0;
        let mut high = Limits::default().max_work_bits;
        assert!(decode(&Limits::default()).is_ok());
        while low < high {
            let middle = low + (high - low) / 2;
            let limits = Limits {
                max_work_bits: middle,
                ..Limits::default()
            };
            if decode(&limits).is_ok() {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    /// Find the minimum BER work ceiling for one IA5 prefix decode.
    ///
    /// # Parameters and returns
    /// `input` is a valid BER prefix; returns the least passing work limit.
    ///
    /// # Errors
    /// Panics if default limits reject canonical test input.
    ///
    /// # Source, version, history, example
    /// Source: scalar codec resource tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: called by `ia5_decoder_limits_and_strict_work_are_exact`.
    fn minimum_ia5_ber_work(input: &[u8]) -> usize {
        let decode = |limits: &Limits| decode_ia5_string_ber(input, limits).map(|_| ());
        let mut low = 0;
        let mut high = Limits::default().max_work_bits;
        assert!(decode(&Limits::default()).is_ok());
        while low < high {
            let middle = low + (high - low) / 2;
            let limits = Limits {
                max_work_bits: middle,
                ..Limits::default()
            };
            if decode(&limits).is_ok() {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    /// Exercise malformed and mutated IA5 BER/CER inputs without decoder panics.
    ///
    /// # Parameters and returns
    /// No parameters. Tries all proper prefixes and single-byte substitutions.
    ///
    /// # Errors
    /// Panics only if an untrusted input mutation unwinds from a decoder.
    ///
    /// # Source, version, history, example
    /// Source: BER parser mutation hardening. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct IA5 gate.
    /// Example: run with `cargo test`.
    #[test]
    fn ia5_single_byte_mutations_and_truncations_do_not_panic() {
        let limits = Limits::default();
        let vectors: &[&[u8]] = &[
            &[0x16, 3, 0, 0x1b, 0x7f],
            &[0x36, 0x80, 4, 1, b'A', 0, 0],
            &[0x1f, 0x16, 1, b'A'],
        ];
        for vector in vectors {
            for end in 0..vector.len() {
                let truncated = &vector[..end];
                let _ = decode_ia5_string_ber(truncated, &limits);
                let _ = decode_ia5_string_cer(truncated, &limits);
            }
            for index in 0..vector.len() {
                for replacement in 0_u8..=u8::MAX {
                    let mut mutated = vector.to_vec();
                    mutated[index] = replacement;
                    let _ = decode_ia5_string_ber(&mutated, &limits);
                    let _ = decode_ia5_string_cer(&mutated, &limits);
                }
            }
        }
    }

    /// Check universal tag mappings, aliases, raw BER/DER, and empty CER values.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises every supported kind and shared-tag alias.
    ///
    /// # Errors
    /// Panics on wrong tag selection, lost raw bytes, or malformed empty output.
    ///
    /// # Source, version, history, example
    /// Source: X.690 universal tags and C descriptors. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_kinds_preserve_raw_values_and_empty_forms() {
        let cases: &[(CharacterStringKind, u8)] = &[
            (CharacterStringKind::ObjectDescriptor, 7),
            (CharacterStringKind::Utf8String, 12),
            (CharacterStringKind::NumericString, 18),
            (CharacterStringKind::PrintableString, 19),
            (CharacterStringKind::TeletexString, 20),
            (CharacterStringKind::T61String, 20),
            (CharacterStringKind::VideotexString, 21),
            (CharacterStringKind::Ia5String, 22),
            (CharacterStringKind::GraphicString, 25),
            (CharacterStringKind::VisibleString, 26),
            (CharacterStringKind::Iso646String, 26),
            (CharacterStringKind::GeneralString, 27),
            (CharacterStringKind::UniversalString, 28),
            (CharacterStringKind::BmpString, 30),
        ];
        let limits = Limits::default();
        for (kind, tag) in cases {
            assert_eq!(kind.tag_number(), u32::from(*tag));
            let value = CharacterString::try_from_bytes(*kind, &[0xff], &limits).unwrap();
            assert_eq!(value.kind(), *kind);
            assert_eq!(value.as_bytes(), [0xff]);
            let der = encode_character_string_der(&value, &limits).unwrap();
            assert_eq!(der.bytes, [*tag, 1, 0xff]);
            let decoded = decode_character_string_ber(&der.bytes, *kind, &limits).unwrap();
            assert_eq!(decoded.value.kind(), *kind);
            assert_eq!(decoded.value.as_bytes(), [0xff]);

            let empty = CharacterString::try_from_bytes(*kind, &[], &limits).unwrap();
            let cer = encode_character_string_cer(&empty, &limits).unwrap();
            assert_eq!(cer.bytes, [*tag, 0]);
            assert_eq!(
                decode_character_string_cer(&cer.bytes, *kind, &limits)
                    .unwrap()
                    .value
                    .as_bytes(),
                []
            );
        }
    }

    /// Keep generic IA5 codecs byte-for-byte aligned with the source-compatible API.
    ///
    /// # Parameters and returns
    /// No parameters. Compares values, encodings, decodings, and prefix use.
    ///
    /// # Errors
    /// Panics if either IA5 API changes observable encoding or decode behavior.
    ///
    /// # Source, version, history, example
    /// Source: approved IA5 compatibility surface. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: shared string core regression.
    /// Example: run with `cargo test`.
    #[test]
    fn generic_ia5_kind_matches_existing_ia5_api() {
        let limits = Limits::default();
        let bytes = [0, 0x1b, 0x7f];
        let legacy = Ia5String::try_from_bytes(&bytes, &limits).unwrap();
        let generic =
            CharacterString::try_from_bytes(CharacterStringKind::Ia5String, &bytes, &limits)
                .unwrap();
        let der_from_ia5 = encode_ia5_string_der(&legacy, &limits).unwrap();
        let der_from_kind = encode_character_string_der(&generic, &limits).unwrap();
        let cer_from_ia5 = encode_ia5_string_cer(&legacy, &limits).unwrap();
        let cer_from_kind = encode_character_string_cer(&generic, &limits).unwrap();
        assert_eq!(der_from_kind.bytes, der_from_ia5.bytes);
        assert_eq!(cer_from_kind.bytes, cer_from_ia5.bytes);

        let raw_ia5 = decode_ia5_string_ber(&der_from_kind.bytes, &limits).unwrap();
        let raw_generic = decode_character_string_ber(
            &der_from_ia5.bytes,
            CharacterStringKind::Ia5String,
            &limits,
        )
        .unwrap();
        assert_eq!(raw_ia5.value.as_bytes(), raw_generic.value.as_bytes());
        assert_eq!(raw_ia5.consumed_bytes, raw_generic.consumed_bytes);

        let strict_ia5 = decode_ia5_string_cer(&cer_from_kind.bytes, &limits).unwrap();
        let strict_generic = decode_character_string_cer(
            &cer_from_ia5.bytes,
            CharacterStringKind::Ia5String,
            &limits,
        )
        .unwrap();
        assert_eq!(strict_ia5.value.as_bytes(), strict_generic.value.as_bytes());
        assert_eq!(strict_ia5.consumed_bytes, strict_generic.consumed_bytes);
    }

    /// Match C CER validators for alphabets, alignment, and unvalidated kinds.
    ///
    /// # Parameters and returns
    /// No parameters. Tests valid and invalid content for each validator class.
    ///
    /// # Errors
    /// Panics on C-compatible accepted values being rejected or invalid values passing.
    ///
    /// # Source, version, history, example
    /// Source: C skeleton descriptor constraints. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_cer_validators_match_c_descriptor_rules() {
        let limits = Limits::default();
        let printable =
            b" '()+,-./:=?0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let accepted: &[(CharacterStringKind, &[u8])] = &[
            (CharacterStringKind::ObjectDescriptor, &[0xff, 0x80]),
            (CharacterStringKind::TeletexString, &[0xff, 0x80]),
            (CharacterStringKind::T61String, &[0xff, 0x80]),
            (CharacterStringKind::VideotexString, &[0xff, 0x80]),
            (CharacterStringKind::GraphicString, &[0xff, 0x80]),
            (CharacterStringKind::GeneralString, &[0xff, 0x80]),
            (CharacterStringKind::NumericString, b" 0123456789"),
            (CharacterStringKind::PrintableString, printable),
            (CharacterStringKind::VisibleString, &[0x20, 0x7e]),
            (CharacterStringKind::Iso646String, &[0x20, 0x7e]),
            (CharacterStringKind::Ia5String, &[0, 0x1b, 0x7f]),
            (CharacterStringKind::BmpString, &[0xd8, 0]),
            (
                CharacterStringKind::UniversalString,
                &[0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (kind, bytes) in accepted {
            let value = CharacterString::try_from_bytes(*kind, bytes, &limits).unwrap();
            let encoded = encode_character_string_cer(&value, &limits).unwrap();
            assert_eq!(
                decode_character_string_cer(&encoded.bytes, *kind, &limits)
                    .unwrap()
                    .value
                    .as_bytes(),
                *bytes
            );
        }

        let rejected: &[(CharacterStringKind, &[u8])] = &[
            (CharacterStringKind::NumericString, b"A"),
            (CharacterStringKind::PrintableString, b"*"),
            (CharacterStringKind::VisibleString, &[0x1f]),
            (CharacterStringKind::Iso646String, &[0x7f]),
            (CharacterStringKind::Ia5String, &[0x80]),
            (CharacterStringKind::BmpString, &[0]),
            (CharacterStringKind::UniversalString, &[0, 0, 0]),
            (CharacterStringKind::Utf8String, &[0xff]),
        ];
        for (kind, bytes) in rejected {
            let value = CharacterString::try_from_bytes(*kind, bytes, &limits).unwrap();
            assert!(encode_character_string_der(&value, &limits).is_ok());
            assert!(encode_character_string_cer(&value, &limits).is_err());
            let der = encode_character_string_der(&value, &limits).unwrap();
            assert!(decode_character_string_ber(&der.bytes, *kind, &limits).is_ok());
            assert!(decode_character_string_cer(&der.bytes, *kind, &limits).is_err());
        }
    }

    /// Preserve C's minimal legacy `UTF8String` forms rather than Rust UTF-8 rules.
    ///
    /// # Parameters and returns
    /// No parameters. Covers ASCII, surrogate/out-of-range, 5/6-byte, and invalid forms.
    ///
    /// # Errors
    /// Panics if C-compatible UTF8 inputs are rejected or malformed inputs pass.
    ///
    /// # Source, version, history, example
    /// Source: C `UTF8String__process`. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_utf8_validator_matches_legacy_c_behavior() {
        let limits = Limits::default();
        let accepted: &[&[u8]] = &[
            b"hello",
            &[0xed, 0xa0, 0x80],
            &[0xf4, 0x90, 0x80, 0x80],
            &[0xf8, 0x88, 0x80, 0x80, 0x80],
            &[0xfc, 0x84, 0x80, 0x80, 0x80, 0x80],
            &[0xfd, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf],
        ];
        for bytes in accepted {
            let value =
                CharacterString::try_from_bytes(CharacterStringKind::Utf8String, bytes, &limits)
                    .unwrap();
            let encoded = encode_character_string_cer(&value, &limits).unwrap();
            assert_eq!(
                decode_character_string_cer(
                    &encoded.bytes,
                    CharacterStringKind::Utf8String,
                    &limits
                )
                .unwrap()
                .value
                .as_bytes(),
                *bytes
            );
        }

        let rejected: &[&[u8]] = &[
            &[0x80],
            &[0xfe],
            &[0xff],
            &[0xc0, 0x80],
            &[0xe2, 0x28, 0xa1],
            &[0xf0, 0x90, 0x80],
        ];
        for bytes in rejected {
            let value =
                CharacterString::try_from_bytes(CharacterStringKind::Utf8String, bytes, &limits)
                    .unwrap();
            assert!(encode_character_string_cer(&value, &limits).is_err());
        }
    }

    /// Reassemble BER before UTF8 validation and split CER content bytewise.
    ///
    /// # Parameters and returns
    /// No parameters. Tests nested tag-4 BER and a UTF8 sequence split at byte 1000.
    ///
    /// # Errors
    /// Panics if reassembly, prefix consumption, or strict CER comparison differs.
    ///
    /// # Source, version, history, example
    /// Source: X.690 string components and C CER byte chunking. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_constructed_ber_and_utf8_cer_fragmentation() {
        let limits = Limits::default();
        let nested = [
            0x2c, 0x80, 4, 1, 0xc2, 0x24, 0x80, 4, 1, 0xa2, 0, 0, 0, 0, 0xff,
        ];
        let decoded =
            decode_character_string_ber(&nested, CharacterStringKind::Utf8String, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), [0xc2, 0xa2]);
        assert_eq!(decoded.consumed_bytes, 14);
        assert!(
            decode_character_string_cer(&nested, CharacterStringKind::Utf8String, &limits).is_err()
        );

        let nested_definite = [0x32, 0x80, 4, 1, b'1', 0x24, 3, 4, 1, b'2', 0, 0];
        let decoded = decode_character_string_ber(
            &nested_definite,
            CharacterStringKind::NumericString,
            &limits,
        )
        .unwrap();
        assert_eq!(decoded.value.as_bytes(), b"12");
        assert_eq!(decoded.consumed_bytes, nested_definite.len());

        let mut split_value = vec![b'a'; 999];
        split_value.extend([0xc2, 0xa2]);
        let value =
            CharacterString::try_from_bytes(CharacterStringKind::Utf8String, &split_value, &limits)
                .unwrap();
        let encoded = encode_character_string_cer(&value, &limits).unwrap();
        assert_eq!(&encoded.bytes[..6], &[0x2c, 0x80, 4, 0x82, 3, 0xe8]);
        assert_eq!(
            &encoded.bytes[encoded.bytes.len() - 5..],
            &[4, 1, 0xa2, 0, 0]
        );
        assert_eq!(
            decode_character_string_cer(&encoded.bytes, CharacterStringKind::Utf8String, &limits)
                .unwrap()
                .value
                .as_bytes(),
            split_value
        );
    }

    /// Check generic CER length transitions, fragments, aliases, and malformed BER.
    ///
    /// # Parameters and returns
    /// No parameters. Tests 127/128 and 1000/1001/2001-byte `ObjectDescriptor` values.
    ///
    /// # Errors
    /// Panics on wrong boundaries, prefix consumption, alias, or malformed acceptance.
    ///
    /// # Source, version, history, example
    /// Source: C CER probes and X.690 framing. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_cer_boundaries_and_ber_aliases() {
        let limits = Limits::default();
        let cases = [
            (127, 129),
            (128, 131),
            (999, 1003),
            (1000, 1004),
            (1001, 1011),
            (2001, 2015),
        ];
        for (size, encoded_len) in cases {
            let value = CharacterString::try_from_bytes(
                CharacterStringKind::ObjectDescriptor,
                &vec![0xa5; size],
                &limits,
            )
            .unwrap();
            let encoded = encode_character_string_cer(&value, &limits).unwrap();
            assert_eq!(encoded.bytes.len(), encoded_len);
            let decoded = decode_character_string_cer(
                &encoded.bytes,
                CharacterStringKind::ObjectDescriptor,
                &limits,
            )
            .unwrap();
            assert_eq!(decoded.value.as_bytes(), value.as_bytes());
            assert_eq!(decoded.consumed_bytes, encoded_len);
        }
        let value_127 = CharacterString::try_from_bytes(
            CharacterStringKind::ObjectDescriptor,
            &[0x41; 127],
            &limits,
        )
        .unwrap();
        assert_eq!(
            &encode_character_string_cer(&value_127, &limits)
                .unwrap()
                .bytes[..2],
            &[7, 127]
        );
        let value_128 = CharacterString::try_from_bytes(
            CharacterStringKind::ObjectDescriptor,
            &[0x41; 128],
            &limits,
        )
        .unwrap();
        assert_eq!(
            &encode_character_string_cer(&value_128, &limits)
                .unwrap()
                .bytes[..3],
            &[7, 0x81, 0x80]
        );

        let alias = [0x1f, 18, 1, b'1', 0xff];
        let decoded =
            decode_character_string_ber(&alias, CharacterStringKind::NumericString, &limits)
                .unwrap();
        assert_eq!(decoded.value.as_bytes(), b"1");
        assert_eq!(decoded.consumed_bytes, 4);
        assert!(
            decode_character_string_cer(&alias, CharacterStringKind::NumericString, &limits)
                .is_err()
        );

        let wrong_fragment = [0x32, 0x80, 0x12, 1, b'1', 0, 0];
        let missing_eoc = [0x32, 0x80, 4, 1, b'1'];
        let malformed: &[&[u8]] = &[
            &wrong_fragment,
            &missing_eoc,
            &[0x13, 0],
            &[0x12, 0x80, 0, 0],
            &[0x12, 2, b'1'],
            &[0x32, 0x80, 0, 1],
        ];
        for input in malformed {
            assert!(decode_character_string_ber(
                input,
                CharacterStringKind::NumericString,
                &limits
            )
            .is_err());
        }
    }

    /// Enforce generic constructor, BER, DER, and strict CER resource ceilings.
    ///
    /// # Parameters and returns
    /// No parameters. Checks input/output/work exactness and shared CER accounting.
    ///
    /// # Errors
    /// Panics on incorrect consumption, work, or limit handling.
    ///
    /// # Source, version, history, example
    /// Source: runtime character-string resource policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_resource_limits_and_strict_work_are_exact() {
        let kind = CharacterStringKind::ObjectDescriptor;
        let exact = Limits {
            max_input_bytes: 1,
            max_output_bytes: 1,
            max_work_bits: 8,
        };
        let value = CharacterString::try_from_bytes(kind, b"A", &exact).unwrap();
        assert_eq!(value.as_bytes(), b"A");
        assert!(CharacterString::try_from_bytes(
            kind,
            b"A",
            &Limits {
                max_input_bytes: 0,
                ..exact
            }
        )
        .is_err());
        assert!(CharacterString::try_from_bytes(
            kind,
            b"A",
            &Limits {
                max_output_bytes: 0,
                ..exact
            }
        )
        .is_err());
        assert!(CharacterString::try_from_bytes(
            kind,
            b"A",
            &Limits {
                max_work_bits: 7,
                ..exact
            }
        )
        .is_err());

        let default = Limits::default();
        let value = CharacterString::try_from_bytes(kind, b"A", &default).unwrap();
        let der_exact = Limits {
            max_output_bytes: 3,
            max_work_bits: 24,
            ..default
        };
        assert!(encode_character_string_der(&value, &der_exact).is_ok());
        assert!(encode_character_string_der(
            &value,
            &Limits {
                max_output_bytes: 2,
                ..der_exact
            }
        )
        .is_err());
        assert!(encode_character_string_der(
            &value,
            &Limits {
                max_work_bits: 23,
                ..der_exact
            }
        )
        .is_err());

        let encoded = [7, 1, b'A'];
        let work_bits = minimum_character_string_cer_work(&encoded, kind);
        assert_eq!(work_bits, 88);
        assert!(decode_character_string_cer(
            &encoded,
            kind,
            &Limits {
                max_work_bits: work_bits,
                ..default
            }
        )
        .is_ok());
        assert!(decode_character_string_cer(
            &encoded,
            kind,
            &Limits {
                max_work_bits: work_bits - 1,
                ..default
            }
        )
        .is_err());
    }

    /// Check generic CER encoding's complete-output and validation work ceilings.
    ///
    /// # Parameters and returns
    /// No parameters. Encodes one valid `ObjectDescriptor` at exact and lower limits.
    ///
    /// # Errors
    /// Panics if exact output/work fails or a one-below ceiling passes.
    ///
    /// # Source, version, history, example
    /// Source: runtime character-string limits. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_cer_encoder_checks_exact_resources() {
        let kind = CharacterStringKind::ObjectDescriptor;
        let value = CharacterString::try_from_bytes(kind, b"A", &Limits::default()).unwrap();
        let exact = Limits {
            max_output_bytes: 3,
            max_work_bits: 32,
            ..Limits::default()
        };
        assert_eq!(
            encode_character_string_cer(&value, &exact).unwrap().bytes,
            [7, 1, b'A']
        );
        assert!(encode_character_string_cer(
            &value,
            &Limits {
                max_output_bytes: 2,
                ..exact
            }
        )
        .is_err());
        assert!(encode_character_string_cer(
            &value,
            &Limits {
                max_work_bits: 31,
                ..exact
            }
        )
        .is_err());
    }

    /// Apply whole-slice input limits while returning generic BER prefixes.
    ///
    /// # Parameters and returns
    /// No parameters. The decoded TLV is followed by a suffix byte.
    ///
    /// # Errors
    /// Panics if the full input slice is not charged or prefix consumption changes.
    ///
    /// # Source, version, history, example
    /// Source: runtime decoder limits. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_ber_prefix_checks_whole_input_limit() {
        let kind = CharacterStringKind::ObjectDescriptor;
        let input = [7, 1, b'A', 0xff];
        let default = Limits::default();
        let exact = Limits {
            max_input_bytes: input.len(),
            max_output_bytes: 1,
            ..default
        };
        let decoded = decode_character_string_ber(&input, kind, &exact).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"A");
        assert_eq!(decoded.consumed_bytes, 3);
        assert!(decode_character_string_ber(
            &input,
            kind,
            &Limits {
                max_input_bytes: input.len() - 1,
                ..exact
            }
        )
        .is_err());
        let strict_limits = Limits {
            max_input_bytes: input.len(),
            ..default
        };
        let strict = decode_character_string_cer(&input, kind, &strict_limits).unwrap();
        assert_eq!(strict.consumed_bytes, 3);
        assert!(decode_character_string_cer(
            &input,
            kind,
            &Limits {
                max_input_bytes: input.len() - 1,
                ..strict_limits
            }
        )
        .is_err());
    }

    /// Check generic retained-plus-canonical scratch preflight at both boundaries.
    ///
    /// # Parameters and returns
    /// No parameters. Uses a tiny payload with synthetic live retained capacity.
    ///
    /// # Errors
    /// Panics if exact capacity fails or one byte over the fixed cap passes.
    ///
    /// # Source, version, history, example
    /// Source: character-string scratch policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_encoder_scratch_preflight_is_exact() {
        let kind = CharacterStringKind::ObjectDescriptor;
        let limits = Limits {
            max_output_bytes: 3,
            ..Limits::default()
        };
        let exact_capacity = MAX_CHARACTER_STRING_SCRATCH_BYTES - 3;
        let above_capacity = exact_capacity + 1;
        assert_eq!(
            encode_character_string_der_bytes(kind, &[0xa5], exact_capacity, &limits)
                .unwrap()
                .bytes,
            [7, 1, 0xa5]
        );
        assert!(encode_character_string_der_bytes(kind, &[0xa5], above_capacity, &limits).is_err());
        assert_eq!(
            encode_character_string_cer_precharged(kind, &[0xa5], exact_capacity, &limits)
                .unwrap()
                .bytes,
            [7, 1, 0xa5]
        );
        assert!(
            encode_character_string_cer_precharged(kind, &[0xa5], above_capacity, &limits).is_err()
        );
    }

    /// Find the exact cumulative strict CER work threshold for one kind.
    ///
    /// # Parameters and returns
    /// `input` is canonical CER; `kind` selects the tag and validator. Returns
    /// the least passing work limit.
    ///
    /// # Errors
    /// Panics if default limits reject canonical test input.
    ///
    /// # Source, version, history, example
    /// Source: scalar codec resource tests. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: called by `character_string_resource_limits_and_strict_work_are_exact`.
    fn minimum_character_string_cer_work(input: &[u8], kind: CharacterStringKind) -> usize {
        let decode = |limits: &Limits| decode_character_string_cer(input, kind, limits).map(|_| ());
        let mut low = 0;
        let mut high = Limits::default().max_work_bits;
        assert!(decode(&Limits::default()).is_ok());
        while low < high {
            let middle = low + (high - low) / 2;
            let limits = Limits {
                max_work_bits: middle,
                ..Limits::default()
            };
            if decode(&limits).is_ok() {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        low
    }

    /// Mutate generic string tags, lengths, content, and prefixes without panics.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises every selected kind with one-byte mutations.
    ///
    /// # Errors
    /// Panics only if a decoder unwinds on mutated untrusted input.
    ///
    /// # Source, version, history, example
    /// Source: BER parser mutation hardening. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: restricted-string runtime gate.
    /// Example: run with `cargo test`.
    #[test]
    fn character_string_mutations_and_truncations_do_not_panic() {
        let kinds = [
            CharacterStringKind::ObjectDescriptor,
            CharacterStringKind::Utf8String,
            CharacterStringKind::NumericString,
            CharacterStringKind::PrintableString,
            CharacterStringKind::TeletexString,
            CharacterStringKind::T61String,
            CharacterStringKind::VideotexString,
            CharacterStringKind::Ia5String,
            CharacterStringKind::GraphicString,
            CharacterStringKind::VisibleString,
            CharacterStringKind::Iso646String,
            CharacterStringKind::GeneralString,
            CharacterStringKind::UniversalString,
            CharacterStringKind::BmpString,
        ];
        let limits = Limits::default();
        for kind in kinds {
            let value = CharacterString::try_from_bytes(kind, b"A", &limits).unwrap();
            let wire = encode_character_string_der(&value, &limits).unwrap().bytes;
            for end in 0..wire.len() {
                let truncated = &wire[..end];
                let _ = decode_character_string_ber(truncated, kind, &limits);
                let _ = decode_character_string_cer(truncated, kind, &limits);
            }
            for index in 0..wire.len() {
                for replacement in 0_u8..=u8::MAX {
                    let mut mutated = wire.clone();
                    mutated[index] = replacement;
                    let _ = decode_character_string_ber(&mutated, kind, &limits);
                    let _ = decode_character_string_cer(&mutated, kind, &limits);
                }
            }
        }
    }

    /// Verify BER raw preservation, universal tag-4 fragments, and DER passthrough.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises primitive aliases, constructed values, and suffix use.
    ///
    /// # Errors
    /// Panics if valid BER is rejected or raw bytes change unexpectedly.
    ///
    /// # Source, version, history, example
    /// Source: C `UTCTime` OCTET STRING adapter. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: run with `cargo test`.
    #[test]
    fn utc_time_ber_and_der_preserve_raw_bytes_and_constructed_fragments() {
        let limits = Limits::default();

        // Raw invalid time bytes remain valid BER/DER content by C callback timing.
        let raw = decode_utc_time_ber(&[0x17, 1, 0xff, 0x55], &limits).unwrap();
        assert_eq!(raw.value.as_bytes(), [0xff]);
        assert_eq!(raw.consumed_bytes, 3);
        assert_eq!(
            encode_utc_time_der(&raw.value, &limits).unwrap().bytes,
            [0x17, 1, 0xff]
        );

        // Nested constructed tag-23 uses universal OCTET STRING tag-4 leaves.
        let nested = [
            0x37, 0x80, 0x24, 0x80, 0x04, 2, b'9', b'9', 0, 0, 0x04, 3, b'1', b'2', b'3', 0, 0,
            0x55,
        ];
        let decoded = decode_utc_time_ber(&nested, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"99123");
        assert_eq!(decoded.consumed_bytes, nested.len() - 1);
        assert_eq!(decoded.consumed_bits, (nested.len() - 1) * 8);
        assert_eq!(
            encode_utc_time_der(&decoded.value, &limits).unwrap().bytes,
            [0x17, 5, b'9', b'9', b'1', b'2', b'3']
        );

        // BER accepts empty constructed content and nonminimal high-tag aliases.
        let empty = decode_utc_time_ber(&[0x37, 0x80, 0, 0], &limits).unwrap();
        assert_eq!(empty.value.as_bytes(), []);
        assert_eq!(
            decode_utc_time_ber(&[0x1f, 0x17, 1, 0xff], &limits)
                .unwrap()
                .value
                .as_bytes(),
            [0xff]
        );
        let child_alias = [0x37, 0x80, 0x1f, 4, 1, b'A', 0, 0];
        assert_eq!(
            decode_utc_time_ber(&child_alias, &limits)
                .unwrap()
                .value
                .as_bytes(),
            b"A"
        );
    }

    /// Cover UTC normalization, the 1950 pivot, zone arithmetic, and the epoch sentinel.
    ///
    /// # Parameters and returns
    /// No parameters. Encodes valid input forms and checks canonical CER content.
    ///
    /// # Errors
    /// Panics if an accepted time fails or canonical bytes differ.
    ///
    /// # Source, version, history, example
    /// Source: approved C CER `UTCTime` contract. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: run with `cargo test`.
    #[test]
    fn utc_time_cer_normalizes_forms_and_epoch_boundary() {
        let limits = Limits::default();
        let cases: [(&[u8], &[u8]); 11] = [
            (b"9912312359Z", b"991231235900Z"),
            (b"5001010000Z", b"500101000000Z"),
            (b"4912312359Z", b"491231235900Z"),
            (b"0002291200Z", b"000229120000Z"),
            (b"0001010000+0100", b"991231230000Z"),
            (b"991231235959-0100", b"000101005959Z"),
            (b"700101005959+0100", b"691231235959Z"),
            (b"691231235959Z", b"691231235959Z"),
            (b"991231235959+2359", b"991231000059Z"),
            (b"4912312359+2359", b"491231000000Z"),
            (b"5001010000-2359", b"500101235900Z"),
        ];
        for (input, expected) in cases {
            let value = UtcTime::try_from_bytes(input, &limits).unwrap();
            let encoded = encode_utc_time_cer(&value, &limits).unwrap();
            assert_eq!(&encoded.bytes[..2], &[0x17, 13]);
            assert_eq!(&encoded.bytes[2..], expected);
            let decoded = decode_utc_time_cer(&encoded.bytes, &limits).unwrap();
            assert_eq!(decoded.value.as_bytes(), expected);
        }
    }

    /// Reject malformed `UTCTime` syntax, invalid dates, and unsupported UTC years.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises all accepted lexical shapes and calendar edges.
    ///
    /// # Errors
    /// Panics if malformed CER content is accepted.
    ///
    /// # Source, version, history, example
    /// Source: C CER `UTCTime` parser. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: run with `cargo test`.
    #[test]
    fn utc_time_cer_rejects_bad_fields_and_zone_window() {
        let limits = Limits::default();
        let invalid_values: [&[u8]; 15] = [
            b"",
            b"9912312359",
            b"9912312359X",
            b"9913312359Z",
            b"9902291200Z",
            b"9912312359Zjunk",
            b"9912312359+0000Z",
            b"9912312460Z",
            b"991231235960Z",
            b"9912312359+2400",
            b"9912312359+0060",
            b"9912312359-010",
            b"9912312359+01000",
            b"5001010000+0001",
            b"4912312359-0001",
        ];
        for bytes in invalid_values {
            let value = UtcTime::try_from_bytes(bytes, &limits).unwrap();
            assert!(encode_utc_time_cer(&value, &limits).is_err(), "{bytes:?}");
        }
    }

    /// Enforce strict canonical CER and exact prefix consumption.
    ///
    /// # Parameters and returns
    /// No parameters. Tests a canonical prefix, suffix, aliases, and constructed form.
    ///
    /// # Errors
    /// Panics if noncanonical encodings are accepted or canonical input is rejected.
    ///
    /// # Source, version, history, example
    /// Source: strict C CER re-encode comparison. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: run with `cargo test`.
    #[test]
    fn utc_time_strict_cer_requires_canonical_prefix() {
        let limits = Limits::default();
        let canonical = [
            0x17, 13, b'6', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5', b'9', b'Z',
        ];
        let mut with_suffix = canonical.to_vec();
        with_suffix.push(0x55);
        let decoded = decode_utc_time_cer(&with_suffix, &limits).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"691231235959Z");
        assert_eq!(decoded.consumed_bytes, canonical.len());
        assert_eq!(decoded.consumed_bits, canonical.len() * 8);

        let aliases: [&[u8]; 5] = [
            &[
                0x17, 11, b'6', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'Z',
            ],
            &[
                0x17, 15, b'6', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'+', b'0',
                b'0', b'0', b'0',
            ],
            &[
                0x1f, 23, 13, b'6', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5',
                b'9', b'Z',
            ],
            &[
                0x37, 0x80, 4, 13, b'6', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9',
                b'5', b'9', b'Z', 0, 0,
            ],
            &[0x37, 0x80, 0, 0],
        ];
        for input in aliases {
            assert!(decode_utc_time_cer(input, &limits).is_err());
        }
    }

    /// Check exact input, output, scratch, and cumulative work ceilings.
    ///
    /// # Parameters and returns
    /// No parameters. Tests constructor, DER, CER, BER, and strict CER boundaries.
    ///
    /// # Errors
    /// Panics if an operation crosses its configured resource boundary.
    ///
    /// # Source, version, history, example
    /// Source: shared scalar resource policy. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: run with `cargo test`.
    #[test]
    fn utc_time_resource_limits_are_exact() {
        let raw = b"691231235959Z";
        let constructor_limits = Limits {
            max_input_bytes: raw.len(),
            max_output_bytes: raw.len(),
            max_work_bits: raw.len() * 8,
        };
        let value = UtcTime::try_from_bytes(raw, &constructor_limits).unwrap();
        assert!(UtcTime::try_from_bytes(
            raw,
            &Limits {
                max_work_bits: raw.len() * 8 - 1,
                ..constructor_limits
            }
        )
        .is_err());

        let der_limits = Limits {
            max_input_bytes: raw.len(),
            max_output_bytes: 15,
            max_work_bits: 15 * 8,
        };
        assert!(encode_utc_time_der(&value, &der_limits).is_ok());
        assert!(encode_utc_time_der(
            &value,
            &Limits {
                max_work_bits: 15 * 8 - 1,
                ..der_limits
            }
        )
        .is_err());

        let cer_limits = Limits {
            max_input_bytes: raw.len(),
            max_output_bytes: 15,
            max_work_bits: (raw.len() + 15) * 8,
        };
        assert!(encode_utc_time_cer(&value, &cer_limits).is_ok());
        assert!(encode_utc_time_cer(
            &value,
            &Limits {
                max_work_bits: (raw.len() + 15) * 8 - 1,
                ..cer_limits
            }
        )
        .is_err());

        let wire = [0x17, 1, 0xff];
        let ber_limits = Limits {
            max_input_bytes: wire.len(),
            max_output_bytes: 1,
            max_work_bits: 4 * 8,
        };
        assert!(decode_utc_time_ber(&wire, &ber_limits).is_ok());
        assert!(decode_utc_time_ber(
            &wire,
            &Limits {
                max_work_bits: 4 * 8 - 1,
                ..ber_limits
            }
        )
        .is_err());

        let canonical = encode_utc_time_cer(&value, &Limits::default()).unwrap();
        let strict_limits = Limits {
            max_input_bytes: canonical.bytes.len(),
            max_output_bytes: canonical.bytes.len(),
            max_work_bits: 568,
        };
        assert!(decode_utc_time_cer(&canonical.bytes, &strict_limits).is_ok());
        assert!(decode_utc_time_cer(
            &canonical.bytes,
            &Limits {
                max_work_bits: 567,
                ..strict_limits
            }
        )
        .is_err());
        assert!(encode_utc_time_der_bytes(
            b"A",
            MAX_CHARACTER_STRING_SCRATCH_BYTES - 3,
            &Limits::default()
        )
        .is_ok());
        assert!(encode_utc_time_der_bytes(
            b"A",
            MAX_CHARACTER_STRING_SCRATCH_BYTES - 2,
            &Limits::default()
        )
        .is_err());
    }

    /// Mutate `UTCTime` BER headers and truncate valid DER without panicking.
    ///
    /// # Parameters and returns
    /// No parameters. Exercises every byte mutation and every strict prefix.
    ///
    /// # Errors
    /// Panics only if a decoder unwinds on mutated untrusted input.
    ///
    /// # Source, version, history, example
    /// Source: BER parser mutation hardening. Version: 2026-11-01.
    /// Responsible: runtime maintainers. History: direct `UTCTime` gate.
    /// Example: run with `cargo test`.
    #[test]
    fn utc_time_mutations_and_truncations_do_not_panic() {
        let limits = Limits::default();
        let value = UtcTime::try_from_bytes(b"991231235959Z", &limits).unwrap();
        let wire = encode_utc_time_der(&value, &limits).unwrap().bytes;
        for end in 0..wire.len() {
            let prefix = &wire[..end];
            let _ = decode_utc_time_ber(prefix, &limits);
            let _ = decode_utc_time_cer(prefix, &limits);
        }
        for index in 0..wire.len() {
            for byte in 0_u8..=u8::MAX {
                let mut mutated = wire.clone();
                mutated[index] = byte;
                let _ = decode_utc_time_ber(&mutated, &limits);
                let _ = decode_utc_time_cer(&mutated, &limits);
            }
        }
        for malformed in [
            &[0x37, 0x80, 0, 1, 0][..],
            &[0x37, 0x80, 0x17, 0, 0, 0][..],
            &[0x37, 0x80, 0x04, 1, b'A'][..],
            &[0x17, 0x80][..],
        ] {
            assert!(decode_utc_time_ber(malformed, &limits).is_err());
        }
    }
}
