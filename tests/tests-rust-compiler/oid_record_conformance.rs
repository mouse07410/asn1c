//! BER/DER/CER tests for direct OBJECT IDENTIFIER and RELATIVE-OID record fields.

use asn1c_generated::oid_record::{Sequence, Set, SetOptional};
use asn1c_runtime::{Limits, ObjectIdentifier, RelativeOid};

/// Append a shortest definite length to a test vector.
///
/// Inputs: `output` receives encoded octets; `length` is the content size.
/// Returns no value. Errors are impossible for bounded fixture lengths.
/// Source: X.690 definite lengths. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID record vectors.
/// Example: length 128 appends `81 80`.
fn append_length(output: &mut Vec<u8>, length: usize) {
    if length < 128 {
        output.push(u8::try_from(length).unwrap());
    } else if length < 256 {
        output.extend_from_slice(&[0x81, u8::try_from(length).unwrap()]);
    } else {
        output.extend_from_slice(&[
            0x82,
            u8::try_from(length >> 8).unwrap(),
            u8::try_from(length & 0xff).unwrap(),
        ]);
    }
}

/// Build one definite TLV with a one-octet universal identifier.
///
/// Inputs: `tag` is universal; `content` supplies payload bytes.
/// Returns the complete TLV. Errors are impossible for bounded fixtures.
/// Source: X.690 TLV framing. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID record parity.
/// Example: tag 6 and `[2b, 03]` produce `06 02 2b 03`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Create a Sequence value with optional OID fields and fixed siblings.
///
/// Inputs: optional content slices are canonical base-128 subidentifier bytes.
/// Returns owned values. Errors from test constructors are assertion panics.
/// Source: generated `Sequence` struct. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID field vectors.
/// Example: `sequence(Some(&[0x2b]), None)` leaves RELATIVE-OID absent.
fn sequence(oid: Option<&[u8]>, relative: Option<&[u8]>) -> Sequence {
    let limits = Limits::default();
    Sequence {
        before: true,
        oid: oid.map(|content| ObjectIdentifier::try_from_content(content, &limits).unwrap()),
        count: 2,
        relative: relative.map(|content| RelativeOid::try_from_content(content, &limits).unwrap()),
        bytes: vec![0xaa],
    }
}

/// Build canonical Sequence DER or CER bytes for optional OID content.
///
/// Inputs: optional `oid` and `relative` content plus CER root selection.
/// Returns a complete root TLV. Errors are impossible for bounded values.
/// Source: `OidRecord.asn1` and C vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: record canonical bytes.
/// Example: CER uses an indefinite outer SEQUENCE and retains primitive OIDs.
fn sequence_wire(oid: Option<&[u8]>, relative: Option<&[u8]>, cer: bool) -> Vec<u8> {
    let mut body = tlv(0x01, &[0xff]);
    if let Some(content) = oid {
        body.extend_from_slice(&tlv(0x06, content));
    }
    body.extend_from_slice(&tlv(0x02, &[2]));
    if let Some(content) = relative {
        body.extend_from_slice(&tlv(0x0d, content));
    }
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

/// Create a required-field Set and its canonical encoded bytes.
///
/// Inputs: OID contents are canonical; `cer` selects indefinite SET framing.
/// Returns the value and expected wire bytes. Errors are constructor panics.
/// Source: generated `Set` and C probes. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: SET OID tag-order vectors.
/// Example: universal tags 6 and 13 precede context-specific tag 4.
fn set_value(oid: &[u8], relative: &[u8]) -> (Set, Vec<u8>, Vec<u8>) {
    let limits = Limits::default();
    let value = Set {
        oid: ObjectIdentifier::try_from_content(oid, &limits).unwrap(),
        relative: RelativeOid::try_from_content(relative, &limits).unwrap(),
        flag: true,
    };
    let mut body = tlv(0x06, oid);
    body.extend_from_slice(&tlv(0x0d, relative));
    body.extend_from_slice(&tlv(0x84, &[0xff]));
    let der = tlv(0x31, &body);
    let mut cer = vec![0x31, 0x80];
    cer.extend_from_slice(&body);
    cer.extend_from_slice(&[0, 0]);
    (value, der, cer)
}

/// Build an optional OID Set value and its DER or CER prefix.
///
/// Inputs: optional OID content and CER root selection. Returns value and wire.
/// Errors are limited to invalid test constructors. Source: `OidRecord` schema.
/// Version/date: 2026-11-01. Responsible: asn1c maintainers.
/// History: optional SET OID presence. Example: no OID fields leaves only tag 4.
fn optional_set_value(oid: Option<&[u8]>, relative: Option<&[u8]>) -> SetOptional {
    let limits = Limits::default();
    SetOptional {
        oid: oid.map(|content| ObjectIdentifier::try_from_content(content, &limits).unwrap()),
        relative: relative.map(|content| RelativeOid::try_from_content(content, &limits).unwrap()),
        flag: true,
    }
}

/// Build canonical optional SET DER or CER bytes in effective-tag order.
///
/// Inputs: optional OID content and CER selection. Returns one complete SET TLV.
/// Errors are impossible for bounded fixture inputs. Source: X.690 SET order.
/// Version/date: 2026-11-01. Responsible: asn1c maintainers.
/// History: optional OID SET. Example: OID tag 6 precedes context tag 4.
fn optional_set_wire(oid: Option<&[u8]>, relative: Option<&[u8]>, cer: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(content) = oid {
        body.extend_from_slice(&tlv(0x06, content));
    }
    if let Some(content) = relative {
        body.extend_from_slice(&tlv(0x0d, content));
    }
    body.extend_from_slice(&tlv(0x84, &[0xff]));
    if cer {
        let mut output = vec![0x31, 0x80];
        output.extend_from_slice(&body);
        output.extend_from_slice(&[0, 0]);
        output
    } else {
        tlv(0x31, &body)
    }
}

/// Compare generated Sequence DER/CER output and decode across OID boundaries.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live C record vectors and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID record boundaries.
/// Example: 1001 content octets remain primitive in CER.
#[test]
fn sequence_der_cer_and_decode_match_oid_boundaries() {
    let limits = Limits::default();
    let huge_arc = [
        0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
    ];
    for content in [vec![0], vec![0x2b, 0x03], huge_arc.to_vec()] {
        let relative = [0x81, 0];
        let value = sequence(Some(&content), Some(&relative));
        let der = sequence_wire(Some(&content), Some(&relative), false);
        let cer = sequence_wire(Some(&content), Some(&relative), true);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        assert_eq!(Sequence::decode_ber(&der, &limits).unwrap().value, value);
        assert_eq!(Sequence::decode_ber(&cer, &limits).unwrap().value, value);
        let decoded = Sequence::decode_cer(&cer, &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bytes, cer.len());
        assert_eq!(decoded.consumed_bits, cer.len() * 8);
    }
    for length in [127, 128, 1001] {
        let content = vec![0; length];
        let value = sequence(Some(&content), Some(&content));
        let der = sequence_wire(Some(&content), Some(&content), false);
        let cer = sequence_wire(Some(&content), Some(&content), true);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        assert_eq!(Sequence::decode_cer(&cer, &limits).unwrap().value, value);
    }
}

/// Check optional omission, SET tag order, BER dispatch, and strict CER prefix.
///
/// Inputs: none. Returns no value. Errors are codec or assertion failures.
/// Source: live C vectors and generated record API. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID record presence/order.
/// Example: an absent OPTIONAL OID still uses aggregate-scratch context.
#[test]
fn optional_absence_and_set_tag_order_are_preserved() {
    let limits = Limits::default();
    let absent = sequence(None, None);
    let der = sequence_wire(None, None, false);
    let cer = sequence_wire(None, None, true);
    assert_eq!(absent.encode_der(&limits).unwrap().bytes, der);
    assert_eq!(absent.encode_cer(&limits).unwrap().bytes, cer);
    assert_eq!(Sequence::decode_ber(&der, &limits).unwrap().value, absent);
    assert_eq!(Sequence::decode_cer(&cer, &limits).unwrap().value, absent);

    let optional_oid = [0x2b, 0x03];
    let optional_relative = [0x81, 0];
    for (oid, relative) in [
        (Some(&optional_oid[..]), None),
        (None, Some(&optional_relative[..])),
    ] {
        let value = sequence(oid, relative);
        let der = sequence_wire(oid, relative, false);
        let cer = sequence_wire(oid, relative, true);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        assert_eq!(Sequence::decode_ber(&der, &limits).unwrap().value, value);
        assert_eq!(Sequence::decode_cer(&cer, &limits).unwrap().value, value);
    }
    for (oid, relative) in [
        (None, None),
        (Some(&optional_oid[..]), None),
        (None, Some(&optional_relative[..])),
        (Some(&optional_oid[..]), Some(&optional_relative[..])),
    ] {
        let value = optional_set_value(oid, relative);
        let der = optional_set_wire(oid, relative, false);
        let cer = optional_set_wire(oid, relative, true);
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        assert_eq!(SetOptional::decode_ber(&der, &limits).unwrap().value, value);
        assert_eq!(SetOptional::decode_cer(&cer, &limits).unwrap().value, value);
    }
    let reversed_optional = [
        0x31, 0x80, 0x84, 1, 0xff, 0x0d, 2, 0x81, 0, 0x06, 2, 0x2b, 3, 0, 0,
    ];
    let both_present = optional_set_value(Some(&optional_oid), Some(&optional_relative));
    assert_eq!(
        SetOptional::decode_ber(&reversed_optional, &limits)
            .unwrap()
            .value,
        both_present
    );
    assert!(SetOptional::decode_cer(&reversed_optional, &limits).is_err());

    let oid = [0x2b, 0x03];
    let relative = [0x81, 0];
    let (value, set_der, set_cer) = set_value(&oid, &relative);
    assert_eq!(value.encode_der(&limits).unwrap().bytes, set_der);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, set_cer);
    assert_eq!(Set::decode_ber(&set_der, &limits).unwrap().value, value);
    let mut suffix = set_cer.clone();
    suffix.push(0xaa);
    let decoded = Set::decode_cer(&suffix, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, set_cer.len());
    assert_eq!(decoded.consumed_bits, set_cer.len() * 8);
    let reversed = [
        0x31, 0x80, 0x84, 1, 0xff, 0x0d, 2, 0x81, 0, 0x06, 2, 0x2b, 3, 0, 0,
    ];
    assert_eq!(Set::decode_ber(&reversed, &limits).unwrap().value, value);
    assert!(Set::decode_cer(&reversed, &limits).is_err());
    assert!(Set::decode_cer(&set_der, &limits).is_err());
}

/// Normalize BER base-128 aliases and reject malformed OID fields.
///
/// Inputs: none. Returns no value. Errors are assertions on malformed wire.
/// Source: C OID decoder probes and runtime OID rules. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: BER alias handling.
/// Example: redundant `80 2b` BER content normalizes to `2b` and CER rejects it.
#[test]
fn ber_oid_aliases_normalize_and_invalid_content_fails() {
    let limits = Limits::default();
    let alias = sequence_wire(Some(&[0x80, 0x2b]), Some(&[0x81, 0]), true);
    let decoded = Sequence::decode_ber(&alias, &limits).unwrap();
    assert_eq!(decoded.value.oid.unwrap().as_content(), [0x2b]);
    assert!(Sequence::decode_cer(&alias, &limits).is_err());
    let relative_alias = sequence_wire(None, Some(&[0x80, 0]), true);
    let decoded = Sequence::decode_ber(&relative_alias, &limits).unwrap();
    assert_eq!(decoded.value.relative.unwrap().as_content(), [0]);
    assert!(Sequence::decode_cer(&relative_alias, &limits).is_err());
    for malformed in [
        &[
            0x30, 0x0b, 0x01, 1, 0xff, 0x06, 0, 0x02, 1, 2, 0x04, 1, 0xaa,
        ][..],
        &[
            0x30, 0x0c, 0x01, 1, 0xff, 0x02, 1, 2, 0x0d, 1, 0x80, 0x04, 1, 0xaa,
        ][..],
    ] {
        assert!(Sequence::decode_ber(malformed, &limits).is_err());
        assert!(Sequence::decode_cer(malformed, &limits).is_err());
    }
}

/// Exercise record truncation and input, output, and work budgets.
///
/// Inputs: none. Returns no value. Errors are expected malformed/limit failures.
/// Source: record runtime limits. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: hostile OID field inputs.
/// Example: a limit below the complete CER prefix rejects its decode.
#[test]
fn truncation_and_resource_limits_fail_safely() {
    let limits = Limits::default();
    let content = [0x2b, 0x03];
    let wire = sequence_wire(Some(&content), Some(&[0x81, 0]), true);
    for end in 0..wire.len() {
        assert!(Sequence::decode_ber(&wire[..end], &limits).is_err());
        assert!(Sequence::decode_cer(&wire[..end], &limits).is_err());
    }
    for index in 0..wire.len() {
        let mut mutated = wire.clone();
        mutated[index] ^= 0x80;
        if let Ok(decoded) = Sequence::decode_ber(&mutated, &limits) {
            assert!(decoded.consumed_bytes <= mutated.len());
        }
        if let Ok(decoded) = Sequence::decode_cer(&mutated, &limits) {
            assert!(decoded.consumed_bytes <= mutated.len());
        }
    }
    let low_input = Limits {
        max_input_bytes: wire.len() - 1,
        ..limits
    };
    assert!(Sequence::decode_ber(&wire, &low_input).is_err());
    let value = sequence(Some(&content), Some(&[0x81, 0]));
    let low_output = Limits {
        max_output_bytes: 4,
        ..limits
    };
    assert!(value.encode_cer(&low_output).is_err());
    let no_work = Limits {
        max_work_bits: 0,
        ..limits
    };
    assert!(Sequence::decode_ber(&wire, &no_work).is_err());
}
