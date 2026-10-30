//! Generated UPER SEQUENCE regression tests for a shared operation budget.

use asn1c_generated::sequence_optional::{
    BitmapAcrossOctets, OptionalBoolean, OptionalPacket, ZeroOptional,
};
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

/// Verify optional payload bits follow the complete declaration-order bitmap.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: malformed input returns typed errors; test failures panic.
/// Original source: X.691 OPTIONAL preamble and independent bit vectors.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: optional flat SEQUENCE regression. Example: all present is `FD 4B 40`.
#[test]
fn optional_fields_pack_presence_before_payloads() {
    let limits = Limits::default();
    let absent = OptionalPacket {
        first: true,
        nothing: None,
        number: None,
        octet: None,
        bits: None,
    };
    let absent_encoded = absent.encode_uper(&limits).unwrap();
    assert_eq!(absent_encoded.bytes, [0x08]);
    assert_eq!(absent_encoded.bit_len, 5);
    assert_eq!(OptionalPacket::decode_uper(&absent_encoded.bytes, &limits)
        .unwrap().value, absent);

    let present = OptionalPacket {
        first: true,
        nothing: Some(()),
        number: Some(2),
        octet: Some(vec![0xa5]),
        bits: Some(vec![0xa0]),
    };
    let encoded = present.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xfd, 0x4b, 0x40]);
    assert_eq!(encoded.bit_len, 18);
    assert_eq!(OptionalPacket::decode_uper(&encoded.bytes, &limits)
        .unwrap().value, present);
}

/// Verify that a nine-bit OPTIONAL preamble crosses an octet boundary.
///
/// Parameters: none. Returns: no value; assertions verify byte and bit counts.
/// Errors: malformed or truncated inputs return typed errors; test failures
/// panic. Original source: ITU-T X.691 section 19.2 presence bitmap ordering.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers. History:
/// added a cross-octet presence regression. Example: first and ninth fields
/// present produce the preamble bits `100000001`.
#[test]
fn optional_presence_bitmap_crosses_octets() {
    let limits = Limits::default();
    let value = BitmapAcrossOctets {
        o1: Some(true), r1: 0,
        o2: None, r2: 0,
        o3: None, r3: 0,
        o4: None, r4: 0,
        o5: None, r5: 0,
        o6: None, r6: 0,
        o7: None, r7: 0,
        o8: None, r8: 0,
        o9: Some(false), r9: 0,
    };
    let encoded = value.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0x80, 0xc0, 0x00]);
    assert_eq!(encoded.bit_len, 20);
    let decoded = BitmapAcrossOctets::decode_uper(&encoded.bytes, &limits).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!(decoded.consumed_bits, 20);
    assert_eq!(decoded.consumed_bytes, 3);
    assert!(matches!(
        BitmapAcrossOctets::decode_uper(&encoded.bytes[..1], &limits),
        Err(Error::NeedMoreBits { .. })
    ));
}

/// Check OPTIONAL BOOLEAN absent, false, and true states independently.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: none are expected for complete valid encodings.
/// Original source: X.691 OPTIONAL preamble and UPER BOOLEAN coding.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: optional BOOLEAN regression. Example: present true is `11`.
#[test]
fn optional_boolean_distinguishes_presence_from_false() {
    let limits = Limits::default();
    for (maybe, expected, bit_len) in [
        (None, 0x00, 1),
        (Some(false), 0x80, 2),
        (Some(true), 0xc0, 2),
    ] {
        let value = OptionalBoolean { maybe };
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, [expected]);
        assert_eq!(encoded.bit_len, bit_len);
        assert_eq!(OptionalBoolean::decode_uper(&encoded.bytes, &limits)
            .unwrap().value, value);
    }
}

/// Check presence-only fields for NULL, singleton, and empty fixed strings.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: malformed filler returns a typed error.
/// Original source: X.691 OPTIONAL and zero-width primitive rules.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: zero-width optional regression. Example: all present is `F0`.
#[test]
fn optional_zero_width_values_distinguish_absence() {
    let limits = Limits::default();
    let absent = ZeroOptional {
        nothing: None,
        single: None,
        emptyoctets: None,
        emptybits: None,
    };
    let absent_encoded = absent.encode_uper(&limits).unwrap();
    assert_eq!(absent_encoded.bytes, [0x00]);
    assert_eq!(absent_encoded.bit_len, 4);
    assert_eq!(ZeroOptional::decode_uper(&absent_encoded.bytes, &limits)
        .unwrap().value, absent);

    let present = ZeroOptional {
        nothing: Some(()),
        single: Some(7),
        emptyoctets: Some(Vec::new()),
        emptybits: Some(Vec::new()),
    };
    let encoded = present.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xf0]);
    assert_eq!(encoded.bit_len, 4);
    assert_eq!(ZeroOptional::decode_uper(&encoded.bytes, &limits)
        .unwrap().value, present);
}

/// Reject truncated presence/payload bits and preserve prefix consumption.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: truncation returns typed errors; suffix data remains unconsumed.
/// Original source: UPER cursor truncation and prefix-decoding rules.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: OPTIONAL hostile-input regression. Example: empty input truncates
/// the BOOLEAN presence bit.
#[test]
fn optional_decode_rejects_truncation_and_bad_padding() {
    let limits = Limits::default();
    assert!(matches!(
        OptionalBoolean::decode_uper(&[], &limits),
        Err(Error::NeedMoreBits { .. })
    ));
    assert!(matches!(
        OptionalPacket::decode_uper(&[0xf8], &limits),
        Err(Error::NeedMoreBits { .. })
    ));
    let decoded = ZeroOptional::decode_uper(&[0x01], &limits).unwrap();
    assert_eq!(decoded.consumed_bits, 4);
}

/// Check presence and field work against exact cumulative input/output limits.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: exceeded limits return typed errors.
/// Original source: generated UPER operation-wide resource contract.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: OPTIONAL budget regression. Example: absent fields use 45 work units.
#[test]
fn optional_fields_share_operation_limits() {
    let absent = OptionalPacket {
        first: true,
        nothing: None,
        number: None,
        octet: None,
        bits: None,
    };
    let exact = Limits {
        max_work_bits: 45,
        ..Limits::default()
    };
    let encoded = absent.encode_uper(&exact).unwrap();
    OptionalPacket::decode_uper(&encoded.bytes, &exact).unwrap();
    let short_work = Limits { max_work_bits: 44, ..exact };
    assert!(matches!(absent.encode_uper(&short_work), Err(Error::LimitExceeded {
        resource: Resource::WorkBits, ..
    })));
    assert!(matches!(OptionalPacket::decode_uper(&encoded.bytes, &short_work),
        Err(Error::LimitExceeded { resource: Resource::WorkBits, .. })));
    let no_output = Limits { max_output_bytes: 0, ..exact };
    assert!(matches!(absent.encode_uper(&no_output), Err(Error::LimitExceeded {
        resource: Resource::OutputBytes, ..
    })));
    let no_input = Limits { max_input_bytes: 0, ..exact };
    assert!(matches!(OptionalPacket::decode_uper(&encoded.bytes, &no_input),
        Err(Error::LimitExceeded { resource: Resource::InputBytes, .. })));
}

/// Reject invalid values and lengths in present fields.
///
/// Parameters: none. Returns: no value; assertions fail on mismatch.
/// Errors: invalid constrained values and fixed string lengths return errors.
/// Original source: UPER cursor field validation contract.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: OPTIONAL value validation regression. Example: number 4 exceeds 3.
#[test]
fn optional_fields_validate_present_values() {
    let limits = Limits::default();
    let invalid_integer = OptionalPacket {
        first: false,
        nothing: None,
        number: Some(4),
        octet: None,
        bits: None,
    };
    assert!(matches!(invalid_integer.encode_uper(&limits),
        Err(Error::ValueOutOfRange { .. })));
    let invalid_octet = OptionalPacket { octet: Some(Vec::new()), ..invalid_integer };
    assert!(invalid_octet.encode_uper(&limits).is_err());
}
