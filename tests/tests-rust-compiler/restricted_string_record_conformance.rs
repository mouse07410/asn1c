//! BER/DER/CER conformance for restricted character strings in flat records.

use asn1c_generated::restricted_string_record::*;
use asn1c_runtime::{CharacterString, CharacterStringKind, Limits};

/// Append the shortest definite length for the bounded conformance vectors.
/// Inputs: `out` receives length octets; `length` is content length.
/// Returns no value. Errors are impossible because all vectors fit `u16`.
/// Source: X.690 definite-length form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record string vectors.
/// Example: length 1001 appends `82 03 e9`.
fn append_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(u8::try_from(length).unwrap());
    } else if length < 256 {
        out.extend_from_slice(&[0x81, u8::try_from(length).unwrap()]);
    } else {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }
}

/// Build a primitive TLV with a one-octet tag.
/// Inputs: `tag` is the identifier; `content` is the raw value.
/// Returns the complete TLV. Errors are impossible for bounded test vectors.
/// Source: X.690. Version/date: 2026-11-01. Responsible party: maintainers.
/// History: live C/Rust parity. Example: `primitive(1, &[255])` is `01 01 ff`.
fn primitive(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    append_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Wrap a body in a definite-length one-octet-tag TLV.
/// Inputs: `tag` is the identifier; `body` is the encoded body.
/// Returns one complete TLV. Errors are impossible for these vectors.
/// Source: X.690. Version/date: 2026-11-01. Responsible party: maintainers.
/// History: record framing. Example: an empty SEQUENCE is `[0x30, 0]`.
fn definite(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    append_length(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// Build the canonical primitive or fragmented CER string encoding.
/// Inputs: `tag` is the string tag; `content` is reassembled content.
/// Returns one canonical string TLV. Errors are impossible for test vectors.
/// Source: X.690 CER string rules. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: 1000-octet cutover.
/// Example: 1001 octets use indefinite tag-4 fragments and an EOC.
fn cer_string(tag: u8, content: &[u8]) -> Vec<u8> {
    if content.len() <= 1000 {
        return primitive(tag, content);
    }
    let mut out = vec![tag | 0x20, 0x80];
    for chunk in content.chunks(1000) {
        out.extend_from_slice(&primitive(0x04, chunk));
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Build the expected canonical SEQUENCE with a leading string and BOOLEAN.
/// Inputs: `tag` identifies the string; `content` is its value; `cer` selects
/// indefinite CER framing. Returns the complete encoded record.
/// Source: restricted-string record vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: C differential tests.
/// Example: `UTF8String` `A` and TRUE encode as `30 06 0c 01 41 01 01 ff`.
fn sequence_vector(tag: u8, content: &[u8], cer: bool) -> Vec<u8> {
    let string = if cer {
        cer_string(tag, content)
    } else {
        primitive(tag, content)
    };
    let mut body = string;
    body.extend_from_slice(&[0x01, 0x01, 0xff]);
    if cer {
        let mut out = vec![0x30, 0x80];
        out.extend_from_slice(&body);
        out.extend_from_slice(&[0, 0]);
        out
    } else {
        definite(0x30, &body)
    }
}

/// Build canonical SET bytes with BOOLEAN tag 1 and an optional string field.
/// Inputs: `tag` identifies the string; `present` controls inclusion; `cer`
/// selects indefinite root framing. Returns the complete SET TLV.
/// Source: X.690 SET ordering. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: optional record fields.
/// Example: absent `PrintableString` emits only BOOLEAN TRUE.
fn set_vector(tag: u8, content: &[u8], present: bool, cer: bool) -> Vec<u8> {
    let mut body = vec![0x01, 0x01, 0xff];
    if present {
        let string = if cer {
            cer_string(tag, content)
        } else {
            primitive(tag, content)
        };
        body.extend_from_slice(&string);
    }
    if cer {
        let mut out = vec![0x31, 0x80];
        out.extend_from_slice(&body);
        out.extend_from_slice(&[0, 0]);
        out
    } else {
        definite(0x31, &body)
    }
}

/// Check exact bytes, value identity, and consumed-prefix results for a record.
/// Inputs: record type, kind, tag, and content are supplied by the macro call.
/// Returns no value. Errors are codec or assertion failures.
/// Source: C differential vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: all-kind record coverage.
/// Example: `check_sequence!(SequenceUtf8, Utf8String, 12, b"A")`.
macro_rules! check_sequence {
    ($record:ident, $kind:ident, $tag:expr, $content:expr) => {{
        let limits = Limits::default();
        let content: &[u8] = $content;
        let value =
            CharacterString::try_from_bytes(CharacterStringKind::$kind, content, &limits).unwrap();
        let record = $record { value, flag: true };
        let der = sequence_vector($tag, content, false);
        let cer = sequence_vector($tag, content, true);
        assert_eq!(record.value.kind(), CharacterStringKind::$kind);
        assert_eq!(record.value.as_bytes(), content);
        assert_eq!(record.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(record.encode_cer(&limits).unwrap().bytes, cer);
        let mut der_prefix = der.clone();
        der_prefix.push(0x55);
        let decoded = <$record>::decode_ber(&der_prefix, &limits).unwrap();
        assert_eq!(decoded.value.value.as_bytes(), content);
        assert_eq!(decoded.value.value.kind(), CharacterStringKind::$kind);
        assert_eq!(decoded.consumed_bytes, der.len());
        assert_eq!(decoded.consumed_bits, der.len() * 8);
        let mut cer_prefix = cer.clone();
        cer_prefix.push(0x55);
        let decoded = <$record>::decode_cer(&cer_prefix, &limits).unwrap();
        assert_eq!(decoded.value.value.as_bytes(), content);
        assert_eq!(decoded.value.value.kind(), CharacterStringKind::$kind);
        assert_eq!(decoded.consumed_bytes, cer.len());
        assert_eq!(decoded.consumed_bits, cer.len() * 8);
    }};
}

/// Exercise every fixed AST kind and preserve the two shared-tag identities.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: restricted-string record acceptance matrix. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: initial flat-record gate.
/// Example: T61 and Teletex share tag 20 but retain different kinds.
#[test]
fn every_restricted_kind_round_trips_through_sequence_records() {
    check_sequence!(SequenceObjectDescriptor, ObjectDescriptor, 7, &[0xff]);
    check_sequence!(SequenceUtf8, Utf8String, 12, b"A");
    check_sequence!(SequenceNumeric, NumericString, 18, b" 19");
    check_sequence!(SequencePrintable, PrintableString, 19, b"Az09 '()+,-./:=?");
    check_sequence!(SequenceTeletex, TeletexString, 20, &[0xff]);
    check_sequence!(SequenceT61, T61String, 20, &[0xfe]);
    check_sequence!(SequenceVideotex, VideotexString, 21, &[0x80]);
    check_sequence!(SequenceGraphic, GraphicString, 25, &[0x81]);
    check_sequence!(SequenceVisible, VisibleString, 26, b" ~");
    check_sequence!(SequenceISO646, Iso646String, 26, b" ~");
    check_sequence!(SequenceGeneral, GeneralString, 27, &[0xff]);
    check_sequence!(SequenceUniversal, UniversalString, 28, &[0, 0, 0, 65]);
    check_sequence!(SequenceBMP, BmpString, 30, &[0, 65]);
}

/// Check required-field omission/presence behavior for an OPTIONAL SEQUENCE field.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: C/Rust optional field semantics. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record optionality coverage.
/// Example: absent `UTF8String` leaves the required BOOLEAN as the only field.
#[test]
fn optional_sequence_string_supports_absence_and_presence() {
    let limits = Limits::default();
    let absent = SequenceUtf8Optional {
        value: None,
        flag: true,
    };
    assert_eq!(
        absent.encode_der(&limits).unwrap().bytes,
        [0x30, 3, 1, 1, 0xff]
    );
    assert_eq!(
        absent.encode_cer(&limits).unwrap().bytes,
        [0x30, 0x80, 1, 1, 0xff, 0, 0]
    );
    let decoded = SequenceUtf8Optional::decode_ber(&[0x30, 3, 1, 1, 0xff, 0x55], &limits).unwrap();
    assert_eq!(decoded.value.value, None);
    assert_eq!(decoded.consumed_bytes, 5);
    let value =
        CharacterString::try_from_bytes(CharacterStringKind::Utf8String, b"A", &limits).unwrap();
    let present = SequenceUtf8Optional {
        value: Some(value),
        flag: true,
    };
    let der = sequence_vector(12, b"A", false);
    let cer = sequence_vector(12, b"A", true);
    assert_eq!(present.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(present.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(
        SequenceUtf8Optional::decode_cer(&cer, &limits)
            .unwrap()
            .value
            .value
            .unwrap()
            .as_bytes(),
        b"A"
    );
}

/// Confirm a restricted string composes with bounded explicit/implicit siblings.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: existing bounded string-field record codecs. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: scalar sibling compatibility.
/// Example: explicit OCTET and implicit BIT fields retain their effective tags.
#[test]
fn bounded_tagged_octet_and_bit_siblings_share_record_limits() {
    let limits = Limits::default();
    let value =
        CharacterString::try_from_bytes(CharacterStringKind::Utf8String, b"A", &limits).unwrap();
    let record = SequenceUtf8BoundedSiblings {
        value,
        payload: vec![0xaa],
        bits: asn1c_runtime::BitStringValue::new(vec![0xa0], 5).unwrap(),
        flag: true,
    };
    let body = [
        0x0c, 1, b'A', 0xa0, 3, 0x04, 1, 0xaa, 0x81, 2, 3, 0xa0, 1, 1, 0xff,
    ];
    let der = definite(0x30, &body);
    let cer_body = [
        0x0c, 1, b'A', 0xa0, 0x80, 0x04, 1, 0xaa, 0, 0, 0x81, 2, 3, 0xa0, 1, 1, 0xff,
    ];
    let mut cer = vec![0x30, 0x80];
    cer.extend_from_slice(&cer_body);
    cer.extend_from_slice(&[0, 0]);
    assert_eq!(record.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(record.encode_cer(&limits).unwrap().bytes, cer);
    let decoded = SequenceUtf8BoundedSiblings::decode_ber(&der, &limits).unwrap();
    assert_eq!(decoded.value.value.as_bytes(), b"A");
    assert_eq!(decoded.value.payload, [0xaa]);
    assert_eq!(decoded.value.bits, record.bits);
    assert_eq!(decoded.consumed_bytes, der.len());
    let decoded = SequenceUtf8BoundedSiblings::decode_cer(&cer, &limits).unwrap();
    assert_eq!(decoded.value.payload, [0xaa]);
    assert_eq!(decoded.value.bits, record.bits);
    assert_eq!(decoded.consumed_bytes, cer.len());
    let tight_output = Limits {
        max_output_bytes: der.len() - 1,
        ..Limits::default()
    };
    assert!(record.encode_der(&tight_output).is_err());
    let tight_input = Limits {
        max_input_bytes: der.len() - 1,
        ..Limits::default()
    };
    assert!(SequenceUtf8BoundedSiblings::decode_ber(&der, &tight_input).is_err());
}

/// Test outer-record CER fragmentation and aligned code-unit boundaries.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live C record vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: CER field cutover coverage.
/// Example: 1001 UTF8 octets encode as a constructed string inside CER SEQUENCE.
#[test]
fn sequence_record_cer_boundaries_match_per_kind() {
    let limits = Limits::default();
    for length in [0, 127, 128, 999, 1000, 1001, 2001] {
        let content = vec![b'A'; length];
        let value =
            CharacterString::try_from_bytes(CharacterStringKind::Utf8String, &content, &limits)
                .unwrap();
        let record = SequenceUtf8 { value, flag: true };
        let der = sequence_vector(12, &content, false);
        let cer = sequence_vector(12, &content, true);
        assert_eq!(record.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(record.encode_cer(&limits).unwrap().bytes, cer);
        let decoded = SequenceUtf8::decode_cer(&cer, &limits).unwrap();
        assert_eq!(decoded.value.value.as_bytes(), content);
        assert_eq!(decoded.consumed_bytes, cer.len());
    }
    for (kind, unit, lengths) in [
        (
            CharacterStringKind::BmpString,
            &[0, 65][..],
            &[998, 1000, 1002, 2000][..],
        ),
        (
            CharacterStringKind::UniversalString,
            &[0, 0, 0, 65][..],
            &[996, 1000, 1004, 2000][..],
        ),
    ] {
        for length in lengths {
            let content: Vec<u8> = unit.iter().copied().cycle().take(*length).collect();
            let value = CharacterString::try_from_bytes(kind, &content, &limits).unwrap();
            let (der, cer) = match kind {
                CharacterStringKind::BmpString => {
                    let record = SequenceBMP { value, flag: true };
                    (
                        record.encode_der(&limits).unwrap().bytes,
                        record.encode_cer(&limits).unwrap().bytes,
                    )
                }
                CharacterStringKind::UniversalString => {
                    let record = SequenceUniversal { value, flag: true };
                    (
                        record.encode_der(&limits).unwrap().bytes,
                        record.encode_cer(&limits).unwrap().bytes,
                    )
                }
                _ => unreachable!(),
            };
            assert_eq!(
                der,
                sequence_vector(u8::try_from(kind.tag_number()).unwrap(), &content, false)
            );
            assert_eq!(
                cer,
                sequence_vector(u8::try_from(kind.tag_number()).unwrap(), &content, true)
            );
        }
    }
}

/// Verify aliases remain distinct and SET presence/order uses natural tags.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: C optional-SET vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: kind-aware descriptors.
/// Example: omitted T61 yields only BOOLEAN in the SET.
#[test]
fn optional_set_fields_preserve_alias_identity_and_presence() {
    let limits = Limits::default();
    for (content, expected_kind) in [
        (b"A".as_slice(), CharacterStringKind::PrintableString),
        (b"A".as_slice(), CharacterStringKind::T61String),
        (b"A".as_slice(), CharacterStringKind::Iso646String),
    ] {
        let actual = match expected_kind {
            CharacterStringKind::PrintableString => {
                let value =
                    CharacterString::try_from_bytes(expected_kind, content, &limits).unwrap();
                let record = SetPrintableOptional {
                    value: Some(value),
                    flag: true,
                };
                (
                    record.encode_der(&limits).unwrap().bytes,
                    record.encode_cer(&limits).unwrap().bytes,
                )
            }
            CharacterStringKind::T61String => {
                let value =
                    CharacterString::try_from_bytes(expected_kind, content, &limits).unwrap();
                let record = SetT61Optional {
                    value: Some(value),
                    flag: true,
                };
                (
                    record.encode_der(&limits).unwrap().bytes,
                    record.encode_cer(&limits).unwrap().bytes,
                )
            }
            CharacterStringKind::Iso646String => {
                let value =
                    CharacterString::try_from_bytes(expected_kind, content, &limits).unwrap();
                let record = SetISO646Optional {
                    value: Some(value),
                    flag: true,
                };
                (
                    record.encode_der(&limits).unwrap().bytes,
                    record.encode_cer(&limits).unwrap().bytes,
                )
            }
            _ => unreachable!(),
        };
        let tag = u8::try_from(expected_kind.tag_number()).unwrap();
        assert_eq!(actual.0, set_vector(tag, content, true, false));
        assert_eq!(actual.1, set_vector(tag, content, true, true));
        let mut reversed = vec![0x31, 0x06];
        reversed.extend_from_slice(&primitive(tag, content));
        reversed.extend_from_slice(&[0x01, 0x01, 0xff]);
        let canonical_cer = set_vector(tag, content, true, true);
        match expected_kind {
            CharacterStringKind::PrintableString => {
                let ber = SetPrintableOptional::decode_ber(&reversed, &limits).unwrap();
                let cer = SetPrintableOptional::decode_cer(&canonical_cer, &limits).unwrap();
                assert_eq!(ber.value.value.unwrap().kind(), expected_kind);
                assert_eq!(cer.value.value.unwrap().kind(), expected_kind);
            }
            CharacterStringKind::T61String => {
                let ber = SetT61Optional::decode_ber(&reversed, &limits).unwrap();
                let cer = SetT61Optional::decode_cer(&canonical_cer, &limits).unwrap();
                assert_eq!(ber.value.value.unwrap().kind(), expected_kind);
                assert_eq!(cer.value.value.unwrap().kind(), expected_kind);
            }
            CharacterStringKind::Iso646String => {
                let ber = SetISO646Optional::decode_ber(&reversed, &limits).unwrap();
                let cer = SetISO646Optional::decode_cer(&canonical_cer, &limits).unwrap();
                assert_eq!(ber.value.value.unwrap().kind(), expected_kind);
                assert_eq!(cer.value.value.unwrap().kind(), expected_kind);
            }
            _ => unreachable!(),
        }
    }
    let absent = SetPrintableOptional {
        value: None,
        flag: true,
    };
    assert_eq!(
        absent.encode_der(&limits).unwrap().bytes,
        [0x31, 3, 1, 1, 0xff]
    );
    assert_eq!(
        absent.encode_cer(&limits).unwrap().bytes,
        [0x31, 0x80, 1, 1, 0xff, 0, 0]
    );
    let reversed_ber = [0x31, 0x06, 0x13, 0x01, b'A', 0x01, 0x01, 0xff];
    let decoded = SetPrintableOptional::decode_ber(&reversed_ber, &limits).unwrap();
    assert_eq!(decoded.value.value.unwrap().as_bytes(), b"A");
    assert!(SetPrintableOptional::decode_cer(&reversed_ber, &limits).is_err());
    let canonical_cer = set_vector(19, b"A", true, true);
    let mut suffix = canonical_cer.clone();
    suffix.push(0x55);
    let decoded = SetPrintableOptional::decode_cer(&suffix, &limits).unwrap();
    assert_eq!(decoded.value.value.unwrap().as_bytes(), b"A");
    assert_eq!(decoded.consumed_bytes, canonical_cer.len());
    assert_eq!(decoded.consumed_bits, canonical_cer.len() * 8);
    let absent_cer = absent.encode_cer(&limits).unwrap().bytes;
    let decoded = SetPrintableOptional::decode_cer(&absent_cer, &limits).unwrap();
    assert_eq!(decoded.value.value, None);
}

/// Cover constructed BER, malformed fragments, and whole-input limits.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: X.690 fragment rules and runtime limit contract. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: malformed record vectors.
/// Example: constructed UTF8 fragments reassemble before kind validation.
#[test]
fn constructed_ber_prefix_malformed_inputs_and_limits() {
    let limits = Limits::default();
    let constructed = [
        0x30, 0x80, 0x2c, 0x80, 0x04, 1, b'A', 0x04, 1, b'B', 0, 0, 1, 1, 0xff, 0, 0, 0x55,
    ];
    let decoded = SequenceUtf8::decode_ber(&constructed, &limits).unwrap();
    assert_eq!(decoded.value.value.as_bytes(), b"AB");
    assert_eq!(decoded.consumed_bytes, constructed.len() - 1);
    assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
    for end in 0..constructed.len() - 2 {
        assert!(SequenceUtf8::decode_ber(&constructed[..end], &limits).is_err());
    }
    for wire in [
        &[
            0x30, 0x80, 0x2c, 0x80, 0x0c, 1, b'A', 0, 0, 1, 1, 0xff, 0, 0,
        ][..],
        &[
            0x30, 0x80, 0x2c, 0x80, 0x04, 2, b'A', 0, 0, 1, 1, 0xff, 0, 0,
        ][..],
        &[0x30, 0x80, 0x2c, 0x80, 0x04, 1, b'A', 0, 1, 1, 0xff, 0, 0][..],
    ] {
        assert!(SequenceUtf8::decode_ber(wire, &limits).is_err());
    }
    let small_input = Limits {
        max_input_bytes: 4,
        ..Limits::default()
    };
    assert!(SequenceUtf8::decode_ber(&constructed, &small_input).is_err());
    let value =
        CharacterString::try_from_bytes(CharacterStringKind::Utf8String, &[b'A'; 64], &limits)
            .unwrap();
    let record = SequenceUtf8 { value, flag: true };
    let small_output = Limits {
        max_output_bytes: 8,
        ..Limits::default()
    };
    assert!(record.encode_der(&small_output).is_err());
}

/// Confirm kind-specific CER validation follows raw DER preservation.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: C descriptor constraints and generic runtime policy.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: field-level repertoire and alignment checks.
/// Example: invalid UTF8 can be DER-encoded but is rejected by CER.
#[test]
fn invalid_cer_field_content_is_rejected_without_affecting_der() {
    let limits = Limits::default();
    let invalid_cases = [
        (CharacterStringKind::Utf8String, vec![0xff]),
        (CharacterStringKind::NumericString, vec![b'@']),
        (CharacterStringKind::PrintableString, vec![b'@']),
        (CharacterStringKind::VisibleString, vec![0x1f]),
        (CharacterStringKind::BmpString, vec![0]),
        (CharacterStringKind::UniversalString, vec![0, 0, 0]),
    ];
    for (kind, content) in invalid_cases {
        let value = CharacterString::try_from_bytes(kind, &content, &limits).unwrap();
        match kind {
            CharacterStringKind::Utf8String => {
                let record = SequenceUtf8 { value, flag: true };
                assert!(record.encode_der(&limits).is_ok());
                assert!(record.encode_cer(&limits).is_err());
            }
            CharacterStringKind::NumericString => {
                let record = SequenceNumeric { value, flag: true };
                assert!(record.encode_der(&limits).is_ok());
                assert!(record.encode_cer(&limits).is_err());
            }
            CharacterStringKind::PrintableString => {
                let record = SequencePrintable { value, flag: true };
                assert!(record.encode_der(&limits).is_ok());
                assert!(record.encode_cer(&limits).is_err());
            }
            CharacterStringKind::VisibleString => {
                let record = SequenceVisible { value, flag: true };
                assert!(record.encode_der(&limits).is_ok());
                assert!(record.encode_cer(&limits).is_err());
            }
            CharacterStringKind::BmpString => {
                let record = SequenceBMP { value, flag: true };
                assert!(record.encode_der(&limits).is_ok());
                assert!(record.encode_cer(&limits).is_err());
            }
            CharacterStringKind::UniversalString => {
                let record = SequenceUniversal { value, flag: true };
                assert!(record.encode_der(&limits).is_ok());
                assert!(record.encode_cer(&limits).is_err());
            }
            _ => unreachable!(),
        }
    }
}

/// Ensure CER validation runs on the reassembled UTF8 field and C-compatible form.
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: C descriptor vectors and approved UTF8 policy. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: cross-fragment validation.
/// Example: a minimal five-byte sequence split at byte 1000 remains accepted.
#[test]
fn utf8_cer_validates_reassembled_content() {
    let limits = Limits::default();
    let mut content = vec![b'A'; 999];
    content.extend_from_slice(&[0xf8, 0x88, 0x80, 0x80, 0x80]);
    let value = CharacterString::try_from_bytes(CharacterStringKind::Utf8String, &content, &limits)
        .unwrap();
    let record = SequenceUtf8 { value, flag: true };
    let cer = record.encode_cer(&limits).unwrap().bytes;
    let decoded = SequenceUtf8::decode_cer(&cer, &limits).unwrap();
    assert_eq!(decoded.value.value.as_bytes(), content);
    let invalid =
        CharacterString::try_from_bytes(CharacterStringKind::Utf8String, &[0xff], &limits).unwrap();
    let invalid_record = SequenceUtf8 {
        value: invalid,
        flag: true,
    };
    assert!(invalid_record.encode_der(&limits).is_ok());
    assert!(invalid_record.encode_cer(&limits).is_err());
}
