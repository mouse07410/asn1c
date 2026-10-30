//! Generated UPER tests for bounded-size, non-octet-aligned BIT STRING values.

use asn1c_generated::variable_bit_string::{Bits, Packet};
use asn1c_runtime::{BitStringValue, Error, Limits, Resource};

/// Verify standalone bounded BIT STRING values match fixed UPER vectors.
///
/// Original source: X.691 constrained BIT STRING UPER rules.
/// Version/date: 2026-10-30. Inputs: one- and three-bit SIZE(1..3) values.
/// Returns no value; assertions check wire bytes, bit counts, and round trips.
/// Errors: invalid packed storage and truncation return typed errors.
/// Responsible party: asn1c maintainers. History: bounded-bit UPER coverage.
/// Example: 3 bits `101` encode as `A8` over five meaningful bits.
#[test]
fn standalone_bounded_bits_match_golden_vectors() {
    let limits = Limits::default();
    let one = Bits::new(BitStringValue::new(vec![0x80], 1).unwrap()).unwrap();
    let encoded = one.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0x20]);
    assert_eq!(encoded.bit_len, 3);
    assert_eq!(Bits::decode_uper(&encoded.bytes, &limits).unwrap().value, one);

    let three = Bits::new(BitStringValue::new(vec![0xA0], 3).unwrap()).unwrap();
    let encoded = three.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xA8]);
    assert_eq!(encoded.bit_len, 5);
    let decoded = Bits::decode_uper(&encoded.bytes, &limits).unwrap();
    assert_eq!(decoded.value, three);
    assert_eq!(decoded.value.bit_len(), 3);
    assert_eq!(decoded.value.as_bytes(), [0xA0]);
}

/// Verify bounded required and OPTIONAL BIT STRING fields share one cursor.
///
/// Original source: X.691 UPER SEQUENCE presence and field ordering.
/// Version/date: 2026-10-30. Inputs: BOOLEAN, optional SIZE(1..3), and
/// required SIZE(2..4) values. Returns no value; assertions check shared vectors.
/// Errors: setup failures panic through `unwrap`. Responsible party: asn1c
/// maintainers. History: variable BIT STRING SEQUENCE coverage.
/// Example: the present record encodes as `D9 C0` over eleven bits.
#[test]
fn sequence_bounded_bits_match_shared_cursor_vectors() {
    let limits = Limits::default();
    let present = Packet {
        prefix: true,
        maybe: Some(BitStringValue::new(vec![0x80], 2).unwrap()),
        tail: BitStringValue::new(vec![0xC0], 3).unwrap(),
    };
    let encoded = present.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xD9, 0xC0]);
    assert_eq!(encoded.bit_len, 11);
    assert_eq!(Packet::decode_uper(&encoded.bytes, &limits).unwrap().value, present);

    let absent = Packet {
        prefix: false,
        maybe: None,
        tail: BitStringValue::new(vec![0x40], 2).unwrap(),
    };
    let encoded = absent.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0x04]);
    assert_eq!(encoded.bit_len, 6);
    assert_eq!(Packet::decode_uper(&encoded.bytes, &limits).unwrap().value, absent);
}

/// Verify malformed bounded BIT STRING lengths, padding, and spare codes fail.
///
/// Original source: X.691 constrained length and BIT STRING padding validation.
/// Version/date: 2026-10-30. Inputs: wrong storage, nonzero padding, spare
/// length code, and truncated payload. Returns no value; assertions inspect
/// typed errors. Errors: malformed values are expected. Responsible party:
/// asn1c maintainers. History: bounded-bit hostile-input checks.
/// Example: length code `11` is spare for SIZE(1..3).
#[test]
fn bounded_bits_reject_malformed_values() {
    let limits = Limits::default();
    assert!(matches!(BitStringValue::new(vec![], 1), Err(Error::InvalidEncoding { .. })));
    assert!(matches!(BitStringValue::new(vec![0xA1], 3), Err(Error::InvalidEncoding { .. })));
    assert!(matches!(Bits::decode_uper(&[0xC0], &limits),
        Err(Error::InvalidEncoding { .. })));
    assert!(matches!(Bits::decode_uper(&[], &limits),
        Err(Error::NeedMoreBits { .. })));
}

/// Verify bounded BIT STRING constructors enforce work and output limits.
///
/// Original source: operation-wide UPER resource accounting.
/// Version/date: 2026-10-30. Inputs: three-bit SIZE(1..3) value and narrow
/// work/output budgets. Returns no value; assertions inspect resource errors.
/// Errors: configured limits are expected. Responsible party: asn1c maintainers.
/// History: generated bounded-bit resource coverage. Example: thirteen work units.
#[test]
fn bounded_bits_obey_resource_limits() {
    let bits = Bits::new(BitStringValue::new(vec![0xA0], 3).unwrap()).unwrap();
    let work_limited = Limits {
        max_work_bits: 12,
        ..Limits::default()
    };
    assert!(matches!(bits.encode_uper(&work_limited),
        Err(Error::LimitExceeded { resource: Resource::WorkBits, .. })));
    let output_limited = Limits {
        max_output_bytes: 0,
        ..Limits::default()
    };
    assert!(matches!(bits.encode_uper(&output_limited),
        Err(Error::LimitExceeded { resource: Resource::OutputBytes, .. })));
}
