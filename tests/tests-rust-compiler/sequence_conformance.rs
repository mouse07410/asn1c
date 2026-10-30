//! Generated UPER SEQUENCE regression tests for a shared operation budget.

use asn1c_generated::sequence_slice::{AllZero, CrossByte, Packet, WideRecord};
use asn1c_runtime::{Error, Limits, Resource};

/// Verify non-octet field packing and prefix consumption in one SEQUENCE.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: malformed wire input returns a typed error; test failures panic.
/// Original source: UPER field-order rules and independent bit vector.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: first generated constructed UPER slice. Example: five field bits
/// `1 101 0` produce the complete byte `D0`.
#[test]
fn packet_packs_fields_without_individual_padding() {
    let limits = Limits::default();
    let packet = Packet {
        first: true,
        empty: (),
        count: 5,
        fixed: 7,
        last: false,
    };
    let encoded = packet.encode_uper(&limits).expect("encode packet");
    assert_eq!(encoded.bytes, [0xd0]);
    assert_eq!(encoded.bit_len, 5);

    let decoded = Packet::decode_uper(&[0xd0, 0xaa], &limits).expect("decode packet prefix");
    assert_eq!(decoded.value, packet);
    assert_eq!(decoded.consumed_bits, 5);
    assert_eq!(decoded.consumed_bytes, 1);
    assert!(matches!(
        Packet::decode_uper(&[], &limits),
        Err(Error::NeedMoreBits { .. })
    ));
    assert!(matches!(
        Packet::decode_uper(&[0xe0], &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Verify zero-width fields use only the complete-value filler at the end.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: malformed filler returns an error; test failures panic.
/// Original source: UPER complete-value zero-width convention.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: first generated constructed UPER slice. Example: two zero-width
/// fields still produce just one zero filler byte.
#[test]
fn all_zero_fields_share_one_complete_value_filler() {
    let limits = Limits::default();
    let value = AllZero {
        empty: (),
        fixed: 7,
    };
    let encoded = value
        .encode_uper(&limits)
        .expect("encode zero-width packet");
    assert_eq!(encoded.bytes, [0]);
    assert_eq!(encoded.bit_len, 0);
    let decoded = AllZero::decode_uper(&encoded.bytes, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bytes, 1);
    assert_eq!(decoded.consumed_bits, 0);
    assert!(matches!(
        AllZero::decode_uper(&[], &limits),
        Err(Error::NeedMoreBytes { .. })
    ));
    assert!(matches!(
        AllZero::decode_uper(&[1], &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}

/// Verify byte and work ceilings apply to the whole constructed value.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: over-limit calls return typed errors; test failures panic.
/// Original source: Rust operation-wide budget contract. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: first
/// generated constructed UPER budget tests. Example: five fields consume
/// five wire bits plus 40 component-work units.
#[test]
fn packet_budget_is_cumulative_across_fields() {
    let packet = Packet {
        first: true,
        empty: (),
        count: 5,
        fixed: 7,
        last: false,
    };
    let exact = Limits {
        max_work_bits: 45,
        ..Limits::default()
    };
    packet.encode_uper(&exact).expect("exact work budget");
    Packet::decode_uper(&[0xd0], &exact).expect("exact decode budget");

    let less_work = Limits {
        max_work_bits: 44,
        ..exact
    };
    assert!(matches!(
        packet.encode_uper(&less_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));
    assert!(matches!(
        Packet::decode_uper(&[0xd0], &less_work),
        Err(Error::LimitExceeded {
            resource: Resource::WorkBits,
            ..
        })
    ));

    let no_output = Limits {
        max_output_bytes: 0,
        ..exact
    };
    assert!(matches!(
        packet.encode_uper(&no_output),
        Err(Error::LimitExceeded {
            resource: Resource::OutputBytes,
            ..
        })
    ));
    let one_input_byte = Limits {
        max_input_bytes: 1,
        ..exact
    };
    assert!(matches!(
        Packet::decode_uper(&[0xd0, 0xaa], &one_input_byte),
        Err(Error::LimitExceeded {
            resource: Resource::InputBytes,
            ..
        })
    ));
}

/// Verify a primitive field continues through an octet boundary.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: truncation produces a typed error; test failures panic.
/// Original source: UPER continuous bit-field ordering. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: generated
/// cross-byte SEQUENCE regression. Example: `1 10101011 0` becomes `D5 80`.
#[test]
fn cross_byte_fields_are_continuous() {
    let limits = Limits::default();
    let value = CrossByte {
        first: true,
        octet: 0xab,
        last: false,
    };
    let encoded = value.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xd5, 0x80]);
    assert_eq!(encoded.bit_len, 10);
    let decoded = CrossByte::decode_uper(&encoded.bytes, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bits, 10);
    assert_eq!(decoded.consumed_bytes, 2);
    assert!(matches!(
        CrossByte::decode_uper(&[0xd5], &limits),
        Err(Error::NeedMoreBits { .. })
    ));
}

/// Verify the full signed `i64` range does not overflow cursor offsets.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: test failures panic; the valid endpoints must encode and decode.
/// Original source: constrained UPER integer offset rule. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: generated
/// wide-field regression. Example: MIN offset is eight zero bytes.
#[test]
fn wide_record_covers_signed_endpoints() {
    let limits = Limits::default();
    for (number, byte) in [(i64::MIN, 0x00), (i64::MAX, 0xff)] {
        let value = WideRecord {
            wide: number,
            tail: true,
        };
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes[..8], [byte; 8]);
        assert_eq!(encoded.bytes[8], 0x80);
        assert_eq!(encoded.bit_len, 65);
        assert_eq!(
            WideRecord::decode_uper(&encoded.bytes, &limits)
                .unwrap()
                .value,
            value
        );
    }
}
