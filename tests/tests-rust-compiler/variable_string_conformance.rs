//! Generated UPER tests for bounded-size OCTET STRING values.

use asn1c_generated::variable_sequence::Packet;
use asn1c_generated::variable_string::Data;
use asn1c_runtime::{Error, Limits, Resource};

/// Verify bounded standalone octet strings against fixed UPER vectors.
///
/// Original source: X.691 constrained OCTET STRING UPER rules.
/// Version/date: 2026-10-30. Inputs: one- and two-octet SIZE(1..3) values.
/// Returns no value; assertions check wire bytes, bit lengths, and round trips.
/// Errors: invalid sizes and truncation return typed errors. Responsible party:
/// asn1c maintainers. History: variable-size bounded OCTET STRING coverage.
/// Example: A5 encodes as `29 40` over ten meaningful bits.
#[test]
fn standalone_bounded_octets_match_golden_vectors() {
    let limits = Limits::default();
    let one = Data::new(vec![0xa5]).unwrap();
    let encoded_one = one.encode_uper(&limits).unwrap();
    assert_eq!(encoded_one.bytes, [0x29, 0x40]);
    assert_eq!(encoded_one.bit_len, 10);
    assert_eq!(Data::decode_uper(&encoded_one.bytes, &limits).unwrap().value, one);

    let two = Data::new(vec![0xa5, 0x5a]).unwrap();
    let encoded_two = two.encode_uper(&limits).unwrap();
    assert_eq!(encoded_two.bytes, [0x69, 0x56, 0x80]);
    assert_eq!(encoded_two.bit_len, 18);
    assert_eq!(Data::decode_uper(&encoded_two.bytes, &limits).unwrap().value, two);
    assert!(matches!(Data::new(vec![]), Err(Error::InvalidEncoding { .. })));
    assert!(matches!(Data::new(vec![0; 4]), Err(Error::InvalidEncoding { .. })));
}

/// Verify invalid lengths, spare codes, and truncation are rejected.
///
/// Original source: X.691 constrained whole-number size validation.
/// Version/date: 2026-10-30. Inputs: malformed SIZE(1..3) encodings.
/// Returns no value; assertions verify typed errors and no unsafe acceptance.
/// Errors: malformed inputs are expected. Responsible party: asn1c maintainers.
/// History: variable-size malformed-input tests. Example: `11` is spare for 1..3.
#[test]
fn bounded_octets_reject_malformed_encodings() {
    let limits = Limits::default();
    assert!(matches!(Data::decode_uper(&[0xc0, 0], &limits),
        Err(Error::InvalidEncoding { .. })));
    assert!(matches!(Data::decode_uper(&[0x29], &limits),
        Err(Error::NeedMoreBits { .. })));
    assert!(matches!(Data::decode_uper(&[], &limits),
        Err(Error::NeedMoreBits { .. })));
}

/// Verify required and OPTIONAL bounded octets share the record cursor.
///
/// Original source: X.691 UPER SEQUENCE presence and field ordering.
/// Version/date: 2026-10-30. Inputs: a BOOLEAN, OPTIONAL SIZE(1..3), and
/// required SIZE(2..4). Returns no value; assertions check the shared vector.
/// Errors: setup failures panic through `unwrap`. Responsible party: asn1c
/// maintainers. History: variable OCTET STRING SEQUENCE field coverage.
/// Example: the present OPTIONAL record encodes as `DA 55 A6 AA EF 30`.
#[test]
fn sequence_bounded_octets_match_shared_cursor_vector() {
    let limits = Limits::default();
    let present = Packet {
        flag: true,
        maybe: Some(vec![0xa5, 0x5a]),
        tail: vec![0xaa, 0xbb, 0xcc],
    };
    let encoded = present.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xda, 0x55, 0xa6, 0xaa, 0xef, 0x30]);
    assert_eq!(encoded.bit_len, 46);
    assert_eq!(Packet::decode_uper(&encoded.bytes, &limits).unwrap().value, present);

    let absent = Packet {
        flag: false,
        maybe: None,
        tail: vec![0x11, 0x22],
    };
    let encoded = absent.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0x01, 0x12, 0x20]);
    assert_eq!(encoded.bit_len, 20);
    assert_eq!(Packet::decode_uper(&encoded.bytes, &limits).unwrap().value, absent);
}

/// Verify bounded octet methods apply shared work and byte ceilings.
///
/// Original source: operation-wide UPER resource accounting.
/// Version/date: 2026-10-30. Inputs: one-octet SIZE(1..3) value and narrow
/// work/output ceilings. Returns no value; assertions inspect resource errors.
/// Errors: limit failures are expected. Responsible party: asn1c maintainers.
/// History: generated bounded-string resource tests. Example: 18 work units.
#[test]
fn bounded_octets_obey_resource_limits() {
    let value = Data::new(vec![0xa5]).unwrap();
    let work_limited = Limits {
        max_work_bits: 17,
        ..Limits::default()
    };
    assert!(matches!(value.encode_uper(&work_limited),
        Err(Error::LimitExceeded { resource: Resource::WorkBits, .. })));

    let output_limited = Limits {
        max_output_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(value.encode_uper(&output_limited),
        Err(Error::LimitExceeded { resource: Resource::OutputBytes, .. })));
}
