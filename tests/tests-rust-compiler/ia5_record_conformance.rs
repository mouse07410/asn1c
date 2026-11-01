//! BER/DER/CER conformance for direct `IA5String` fields in flat records.

use asn1c_generated::ia5_record::{Sequence, Set};
use asn1c_runtime::{Ia5String, Limits};

/// Append the shortest definite-length form to a test vector.
///
/// Parameters: `output` receives octets; `length` is the content size.
/// Returns no value. Errors are impossible for these bounded test vectors.
/// Source: X.690 definite length form. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 record vectors.
/// Example: length 1001 appends `82 03 e9`.
fn append_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(u8::try_from(length).unwrap());
    } else if length < 256 {
        output.extend_from_slice(&[0x81, u8::try_from(length).unwrap()]);
    } else {
        output.push(0x82);
        output.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }
}

/// Build one definite TLV with a one-octet identifier.
///
/// Parameters: `tag` is the identifier; `content` supplies the payload.
/// Returns a complete TLV. Errors are impossible for the fixed vector sizes.
/// Source: X.690 TLV framing. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record-level parity.
/// Example: tag 22 and `A` produce `16 01 41`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Build a canonical `IA5String` value for CER record vectors.
///
/// Parameters: `content` is raw IA5 data. Returns the primitive form through
/// 1000 octets and constructed tag-4 fragments above it. Errors are none.
/// Source: X.690 CER string fragmentation. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 record boundaries.
/// Example: 1001 octets use tag 36 with fragment lengths 1000 and 1.
fn cer_ia5(content: &[u8]) -> Vec<u8> {
    if content.len() <= 1000 {
        return tlv(0x16, content);
    }
    let mut output = vec![0x36, 0x80];
    for fragment in content.chunks(1000) {
        output.extend_from_slice(&tlv(0x04, fragment));
    }
    output.extend_from_slice(&[0, 0]);
    output
}

/// Build a Sequence vector with fixed scalar siblings and optional IA5 data.
///
/// Parameters: `text` is optional IA5 content; `cer` selects root framing.
/// Returns a complete Sequence TLV. Errors are impossible for fixed fields.
/// Source: `Ia5Record.asn1` and C probe vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 flat-record parity.
/// Example: absent `text` omits tag 22 while retaining the other fields.
fn sequence_wire(text: Option<&[u8]>, cer: bool) -> Vec<u8> {
    let mut body = tlv(0x01, &[0xff]);
    if let Some(content) = text {
        let encoded = if cer {
            cer_ia5(content)
        } else {
            tlv(0x16, content)
        };
        body.extend_from_slice(&encoded);
    }
    body.extend_from_slice(&tlv(0x02, &[2]));
    body.extend_from_slice(&tlv(0x04, &[0xaa]));
    if cer {
        let mut output = vec![0x30, 0x80];
        output.extend_from_slice(&body);
        output.extend_from_slice(&[0, 0]);
        output
    } else {
        tlv(0x30, &body)
    }
}

/// Construct one generated Sequence value without cloning owned IA5 storage.
///
/// Parameters: `text` supplies optional content. Returns populated scalar
/// siblings and an owned wrapper. Errors from the test constructor are panics.
/// Source: generated `Sequence` public fields. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 optional path.
/// Example: `sequence(Some(b"A"))` creates one OPTIONAL string.
fn sequence(text: Option<&[u8]>) -> Sequence {
    let limits = Limits::default();
    Sequence {
        before: true,
        text: text.map(|content| Ia5String::try_from_bytes(content, &limits).unwrap()),
        count: 2,
        bytes: vec![0xaa],
    }
}

/// Compare record DER/CER bytes and decoded values for all string boundaries.
///
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: C IA5 record vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record boundary matrix.
/// Example: the 1001-octet CER string uses constructed OCTET STRING fragments.
#[test]
fn sequence_der_cer_and_decoding_match_ia5_boundaries() {
    let limits = Limits::default();
    for length in [0, 1, 127, 128, 999, 1000, 1001, 2001] {
        let content = vec![b'A'; length];
        let value = sequence(Some(&content));
        let der = sequence_wire(Some(&content), false);
        let cer = sequence_wire(Some(&content), true);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        let decoded = Sequence::decode_ber(&der, &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bytes, der.len());
        assert_eq!(decoded.consumed_bits, der.len() * 8);
        let decoded = Sequence::decode_ber(&cer, &limits).unwrap();
        assert_eq!(decoded.value, value);
        let decoded = Sequence::decode_cer(&cer, &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bytes, cer.len());
        assert_eq!(decoded.consumed_bits, cer.len() * 8);
    }
}

/// Check absent OPTIONAL storage and SET order/prefix behavior.
///
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: C vectors for `Sequence` and `Set`. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: aggregate-mode constructor.
/// Example: absent IA5 still uses the aggregate-scratch record context.
#[test]
fn optional_absence_and_set_member_order_are_preserved() {
    let limits = Limits::default();
    let absent = sequence(None);
    let der = sequence_wire(None, false);
    let cer = sequence_wire(None, true);
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(Sequence::decode_ber(&der, &limits).unwrap().value, absent);
    assert_eq!(Sequence::decode_cer(&cer, &limits).unwrap().value, absent);

    let set = Set {
        text: Ia5String::try_from_bytes(b"A", &limits).unwrap(),
        flag: true,
    };
    let set_der = [0x31, 0x06, 0x16, 0x01, b'A', 0x84, 0x01, 0xff];
    let set_cer = [0x31, 0x80, 0x16, 0x01, b'A', 0x84, 0x01, 0xff, 0, 0];
    assert_eq!(set.encode_der(&limits).unwrap().bytes, set_der);
    assert_eq!(set.encode_cer(&limits).unwrap().bytes, set_cer);
    assert_eq!(Set::decode_ber(&set_der, &limits).unwrap().value, set);
    assert_eq!(Set::decode_cer(&set_cer, &limits).unwrap().value, set);
    let mut suffix = set_cer.to_vec();
    suffix.push(0xaa);
    let decoded = Set::decode_cer(&suffix, &limits).unwrap();
    assert_eq!(decoded.value, set);
    assert_eq!(decoded.consumed_bytes, set_cer.len());
    assert_eq!(decoded.consumed_bits, set_cer.len() * 8);

    let reversed = [0x31, 0x80, 0x84, 0x01, 0xff, 0x16, 0x01, b'A', 0, 0];
    assert_eq!(Set::decode_ber(&reversed, &limits).unwrap().value, set);
    assert!(Set::decode_cer(&reversed, &limits).is_err());
}

/// Decode constructed BER IA5 fragments and reject malformed child tags.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: X.690 constructed string forms and live C probes.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: IA5 record hostile-input coverage. Example: OCTET fragments flatten.
#[test]
fn constructed_ber_fragments_and_invalid_children_are_checked() {
    let limits = Limits::default();
    let mut body = tlv(0x01, &[0xff]);
    body.extend_from_slice(&[
        0x36, 0x80, 0x04, 0x01, b'A', 0x24, 0x80, 0x04, 0x01, b'B', 0, 0, 0, 0,
    ]);
    body.extend_from_slice(&tlv(0x02, &[2]));
    body.extend_from_slice(&tlv(0x04, &[0xaa]));
    let mut wire = vec![0x30, 0x80];
    wire.extend_from_slice(&body);
    wire.extend_from_slice(&[0, 0]);
    let decoded = Sequence::decode_ber(&wire, &limits).unwrap();
    assert_eq!(decoded.value, sequence(Some(b"AB")));
    assert_eq!(decoded.consumed_bytes, wire.len());
    assert!(Sequence::decode_cer(&wire, &limits).is_err());

    let mut empty_body = tlv(0x01, &[0xff]);
    empty_body.extend_from_slice(&[0x36, 0x80, 0, 0]);
    empty_body.extend_from_slice(&tlv(0x02, &[2]));
    empty_body.extend_from_slice(&tlv(0x04, &[0xaa]));
    let mut empty = vec![0x30, 0x80];
    empty.extend_from_slice(&empty_body);
    empty.extend_from_slice(&[0, 0]);
    let decoded = Sequence::decode_ber(&empty, &limits).unwrap();
    assert_eq!(decoded.value, sequence(Some(b"")));
    assert!(Sequence::decode_cer(&empty, &limits).is_err());

    let mut wrong_body = tlv(0x01, &[0xff]);
    wrong_body.extend_from_slice(&[0x36, 0x80, 0x16, 0x01, b'A', 0, 0]);
    wrong_body.extend_from_slice(&tlv(0x02, &[2]));
    wrong_body.extend_from_slice(&tlv(0x04, &[0xaa]));
    let mut wrong = vec![0x30, 0x80];
    wrong.extend_from_slice(&wrong_body);
    wrong.extend_from_slice(&[0, 0]);
    assert!(Sequence::decode_ber(&wrong, &limits).is_err());
}

/// Preserve raw BER/DER bytes and exercise malformed, prefix, and limit paths.
///
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: direct IA5 and record runtime contracts. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: IA5 record validation.
/// Example: BER preserves byte 80; strict CER rejects its value and encoding.
#[test]
fn invalid_repertoire_truncation_and_resource_limits_fail_safely() {
    let limits = Limits::default();
    let high = sequence(Some(&[0x80]));
    assert_eq!(
        high.encode_der(&limits).unwrap().bytes,
        sequence_wire(Some(&[0x80]), false)
    );
    assert!(high.encode_cer(&limits).is_err());
    let der = sequence_wire(Some(&[0x80]), false);
    let decoded = Sequence::decode_ber(&der, &limits).unwrap();
    assert_eq!(decoded.value.text.as_ref().unwrap().as_bytes(), [0x80]);
    assert!(Sequence::decode_cer(&der, &limits).is_err());

    let canonical = sequence_wire(Some(b"A"), true);
    for end in 0..canonical.len() {
        assert!(Sequence::decode_ber(&canonical[..end], &limits).is_err());
        assert!(Sequence::decode_cer(&canonical[..end], &limits).is_err());
    }
    for malformed in [
        &[0x30, 0x80, 0, 0][..],
        &[0x30, 0x06, 0x01, 0x01, 0xff, 0x16, 0x01, b'A'][..],
        &[0x30, 0x80, 0x01, 0x01, 0xff, 0x16, 0x80, 0, 0][..],
    ] {
        assert!(Sequence::decode_ber(malformed, &limits).is_err());
        assert!(Sequence::decode_cer(malformed, &limits).is_err());
    }
    let small_input = Limits {
        max_input_bytes: canonical.len() - 1,
        ..limits
    };
    assert!(Sequence::decode_ber(&canonical, &small_input).is_err());
    let small_output = Limits {
        max_output_bytes: 3,
        ..limits
    };
    assert!(sequence(Some(b"A")).encode_cer(&small_output).is_err());
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(Sequence::decode_ber(&canonical, &no_work).is_err());
}
