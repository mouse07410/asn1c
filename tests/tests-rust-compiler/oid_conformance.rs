//! Generated BER/DER/CER conformance tests for OBJECT IDENTIFIER values.

use asn1c_generated::oid_values::{OidValue, RelativeValue};
use asn1c_runtime::Limits;

/// Append the shortest definite length representation used by these vectors.
///
/// Parameters: `output` receives the length; `length` is content size. Returns
/// no value. Errors are impossible for this test's bounded vector sizes.
/// Source: X.690 length encoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID wire vectors.
/// Example: content length 128 becomes `81 80`.
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

/// Build a primitive universal OID TLV.
///
/// Parameters: `tag` selects OBJECT IDENTIFIER or RELATIVE-OID; `content` is
/// canonical base-128 content. Returns the full TLV. Errors are impossible.
/// Source: X.690 primitive encoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: C/Rust differential vectors.
/// Example: tag six and content zero produce `06 01 00`.
fn oid_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    append_length(&mut output, content.len());
    output.extend_from_slice(content);
    output
}

/// Build content vectors covering first arcs, large arcs, and length forms.
///
/// Parameters: none. Returns canonical base-128 encoded content values.
/// Errors are impossible; allocation failure aborts the test process.
/// Source: X.690 OID content rules. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: interoperability boundaries.
/// Example: the large arc exceeds `u64` without numeric conversion.
fn canonical_contents() -> Vec<Vec<u8>> {
    let mut large_arc = vec![0x81];
    large_arc.extend_from_slice(&[0x80; 9]);
    large_arc.push(0);
    vec![
        vec![0x00],
        vec![0x4f, 0x7f],
        vec![0x88, 0x37, 0x81, 0x00],
        large_arc,
        vec![0x00; 127],
        vec![0x00; 128],
        vec![0x00; 1001],
    ]
}

/// Compare one OBJECT IDENTIFIER's canonical encode/decode and prefix counts.
///
/// Parameters: `content` is canonical encoded content; `limits` bounds codecs.
/// Returns no value. Errors are assertion failures from codec mismatches.
/// Source: generated runtime API and C fixed vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID bidirectional tests.
/// Example: test the combined first subidentifier for arcs `2.999`.
fn check_oid_case(content: &[u8], limits: &Limits) {
    let value = OidValue::try_from_content(content, limits).unwrap();
    let expected = oid_tlv(0x06, content);
    assert_eq!(value.as_content(), content);
    assert_eq!(value.encode_der(limits).unwrap().bytes, expected);
    assert_eq!(value.encode_cer(limits).unwrap().bytes, expected);
    let mut prefix = expected.clone();
    prefix.push(0xff);
    let ber = OidValue::decode_ber(&prefix, limits).unwrap();
    assert_eq!(ber.value.as_content(), content);
    assert_eq!(ber.consumed_bytes, expected.len());
    assert_eq!(ber.consumed_bits, expected.len() * 8);
    let cer = OidValue::decode_cer(&prefix, limits).unwrap();
    assert_eq!(cer.value.as_content(), content);
    assert_eq!(cer.consumed_bytes, expected.len());
    assert_eq!(cer.consumed_bits, expected.len() * 8);
}

/// Compare one RELATIVE-OID's canonical encode/decode and prefix counts.
///
/// Parameters: `content` is canonical encoded arc content; `limits` bounds use.
/// Returns no value. Errors are assertion failures from codec mismatches.
/// Source: generated runtime API and C fixed vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: relative OID tests.
/// Example: test arcs 127 and 128 without numeric-width assumptions.
fn check_relative_case(content: &[u8], limits: &Limits) {
    let value = RelativeValue::try_from_content(content, limits).unwrap();
    let expected = oid_tlv(0x0d, content);
    assert_eq!(value.as_content(), content);
    assert_eq!(value.encode_der(limits).unwrap().bytes, expected);
    assert_eq!(value.encode_cer(limits).unwrap().bytes, expected);
    let mut prefix = expected.clone();
    prefix.push(0xff);
    let ber = RelativeValue::decode_ber(&prefix, limits).unwrap();
    assert_eq!(ber.value.as_content(), content);
    assert_eq!(ber.consumed_bytes, expected.len());
    assert_eq!(ber.consumed_bits, expected.len() * 8);
    let cer = RelativeValue::decode_cer(&prefix, limits).unwrap();
    assert_eq!(cer.value.as_content(), content);
    assert_eq!(cer.consumed_bytes, expected.len());
    assert_eq!(cer.consumed_bits, expected.len() * 8);
}

/// Compare canonical OID values including 127/128/1001 content-length cases.
///
/// Parameters: none. Returns no value. Errors are codec or assertion failures.
/// Source: C wide OID probes and X.690. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: direct OID C differential.
/// Example: 1001 content octets remain one primitive CER value.
#[test]
fn canonical_oid_values_match_der_cer_and_ber() {
    let limits = Limits::default();
    let oid_contents = canonical_contents();
    let relative_contents = vec![
        vec![0x00],
        vec![0x7f, 0x81, 0x00],
        vec![0x81, 0x80, 0x01],
        vec![0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
        vec![0x00; 127],
        vec![0x00; 128],
        vec![0x00; 1001],
    ];
    for content in oid_contents {
        check_oid_case(&content, &limits);
    }
    for content in relative_contents {
        check_relative_case(&content, &limits);
    }
}

/// Normalize redundant groups and accept BER identifier aliases only.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: X.690 base-128 subidentifiers and BER identifiers. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers.
/// History: strict CER canonicality coverage. Example: `80 00` normalizes to `00`.
#[test]
fn ber_normalizes_aliases_and_strict_cer_rejects_them() {
    let limits = Limits::default();
    let content = [0x00, 0x80, 0x01, 0x80, 0x80, 0x00];
    let normalized = [0x00, 0x01, 0x00];
    assert_eq!(
        OidValue::try_from_content(&content, &limits)
            .unwrap()
            .as_content(),
        normalized
    );
    assert_eq!(
        RelativeValue::try_from_content(&content, &limits)
            .unwrap()
            .as_content(),
        normalized
    );
    for (wire, expected, oid) in [
        (vec![0x06, 0x02, 0x80, 0x00], vec![0x00], true),
        (vec![0x0d, 0x02, 0x80, 0x00], vec![0x00], false),
        (vec![0x1f, 0x06, 0x01, 0x00], vec![0x00], true),
        (vec![0x1f, 0x0d, 0x01, 0x00], vec![0x00], false),
    ] {
        if oid {
            let decoded = OidValue::decode_ber(&wire, &limits).unwrap();
            assert_eq!(decoded.value.as_content(), expected);
            assert_eq!(decoded.consumed_bytes, wire.len());
            assert!(OidValue::decode_cer(&wire, &limits).is_err());
        } else {
            let decoded = RelativeValue::decode_ber(&wire, &limits).unwrap();
            assert_eq!(decoded.value.as_content(), expected);
            assert_eq!(decoded.consumed_bytes, wire.len());
            assert!(RelativeValue::decode_cer(&wire, &limits).is_err());
        }
    }
}

/// Reject invalid content and malformed/truncated primitive identifier forms.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: X.690 OID validity and hostile-input cases. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: malformed OID coverage.
/// Example: an unterminated continuation group is invalid.
#[test]
fn malformed_oid_content_lengths_and_constructed_forms_fail() {
    let limits = Limits::default();
    for invalid in [
        &[][..],
        &[0x80][..],
        &[0x80, 0x80][..],
        &[0x01, 0x80][..],
        &[0x00, 0x80, 0x80][..],
    ] {
        assert!(OidValue::try_from_content(invalid, &limits).is_err());
        assert!(RelativeValue::try_from_content(invalid, &limits).is_err());
    }
    let malformed_oid: &[&[u8]] = &[
        &[0x06, 0x00],
        &[0x06, 0x01, 0x80],
        &[0x06, 0x02, 0x01, 0x80],
        &[0x06, 0x03, 0x00, 0x80, 0x80],
        &[0x06, 0x81],
        &[0x06, 0x80, 0, 0],
        &[0x26, 0x01, 0x00],
    ];
    for wire in malformed_oid {
        assert!(OidValue::decode_ber(wire, &limits).is_err());
        assert!(OidValue::decode_cer(wire, &limits).is_err());
    }
    let malformed_relative: &[&[u8]] = &[
        &[0x0d, 0x00],
        &[0x0d, 0x01, 0x80],
        &[0x0d, 0x02, 0x01, 0x80],
        &[0x0d, 0x03, 0x00, 0x80, 0x80],
        &[0x0d, 0x81],
        &[0x0d, 0x80, 0, 0],
        &[0x2d, 0x01, 0x00],
    ];
    for wire in malformed_relative {
        assert!(RelativeValue::decode_ber(wire, &limits).is_err());
        assert!(RelativeValue::decode_cer(wire, &limits).is_err());
    }
}

/// Check truncation, mutations, prefix bounds, and configured resource limits.
///
/// Parameters: none. Returns no value. Errors are assertion failures.
/// Source: BER parser robustness requirements. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: OID limits and mutations.
/// Example: every proper prefix of a 1001-octet OID is rejected.
#[test]
fn oid_prefix_mutation_and_resource_bounds_are_checked() {
    let limits = Limits::default();
    let exact_constructor = Limits {
        max_input_bytes: 2,
        max_output_bytes: 1,
        max_work_bits: 32,
    };
    let normalized_oid = OidValue::try_from_content(&[0x80, 42], &exact_constructor).unwrap();
    let normalized_relative =
        RelativeValue::try_from_content(&[0x80, 42], &exact_constructor).unwrap();
    assert_eq!(normalized_oid.as_content(), [42]);
    assert_eq!(normalized_relative.as_content(), [42]);
    let exact_encode = Limits {
        max_input_bytes: 1,
        max_output_bytes: 3,
        ..limits
    };
    assert_eq!(normalized_oid.encode_der(&exact_encode).unwrap().bytes, [6, 1, 42]);
    assert!(normalized_oid
        .encode_der(&Limits {
            max_output_bytes: 2,
            ..exact_encode
        })
        .is_err());
    let exact_decode = Limits {
        max_input_bytes: 4,
        max_output_bytes: 1,
        ..limits
    };
    let decoded = OidValue::decode_ber(&[6, 1, 42, 0xff], &exact_decode).unwrap();
    assert_eq!(decoded.value.as_content(), [42]);
    assert_eq!(decoded.consumed_bytes, 3);
    assert!(OidValue::decode_ber(
        &[6, 1, 42, 0xff],
        &Limits {
            max_input_bytes: 3,
            ..exact_decode
        }
    )
    .is_err());
    assert!(OidValue::decode_ber(
        &[6, 1, 42, 0xff],
        &Limits {
            max_output_bytes: 0,
            ..exact_decode
        }
    )
    .is_err());

    let content = vec![0x00; 1001];
    let value = OidValue::try_from_content(&content, &limits).unwrap();
    let wire = value.encode_cer(&limits).unwrap().bytes;
    for end in 0..wire.len() {
        assert!(OidValue::decode_ber(&wire[..end], &limits).is_err());
        assert!(OidValue::decode_cer(&wire[..end], &limits).is_err());
    }
    for index in 0..wire.len() {
        let mut changed = wire.clone();
        changed[index] ^= 0x80;
        if let Ok(decoded) = OidValue::decode_ber(&changed, &limits) {
            assert!(decoded.consumed_bytes <= changed.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }
    }
    let input_limited = Limits { max_input_bytes: 3, ..limits };
    let output_limited = Limits { max_output_bytes: 3, ..limits };
    let no_work = Limits { max_work_bits: 0, ..limits };
    assert!(OidValue::decode_ber(&wire, &input_limited).is_err());
    assert!(value.encode_der(&output_limited).is_err());
    assert!(OidValue::try_from_content(&content, &no_work).is_err());
}
