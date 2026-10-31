//! Opaque ANY UPER length and malformed-input regression tests.
use asn1c_generated::any_module::{Packet, Required, Value};
use asn1c_runtime::Limits;

/// Exercise short, two-octet, and fragmented length determinants.
/// Source: X.691 and C ANY UPER framing; version 2026-10-30.
/// Inputs: none. Returns: nothing. Panics on failed assertions.
/// Responsible: asn1c maintainers. History: initial ANY tests.
/// Example: run with `cargo test`.
#[test]
fn lengths_and_roundtrip() {
    let limits = Limits::default();
    for length in [0, 1, 127, 128, 16383, 16384, 65536, 65537] {
        let value = Value(vec![0xa5; length]);
        let encoded = value.encode_uper(&limits).unwrap();
        let decoded = Value::decode_uper(&encoded.bytes, &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bits, encoded.bit_len);
        let expected = match length {
            0 => 0,
            1 => 1,
            127 => 127,
            128 | 16383 => 0x80,
            _ => 0xc0,
        };
        assert_eq!(
            encoded.bytes[0] & if length >= 128 { 0xc0 } else { 0xff },
            expected
        );
        if length < 16384 {
            let header = usize::from(length >= 128) + 1;
            assert!(encoded.bytes[header..].iter().all(|byte| *byte == 0xa5));
            if length >= 128 {
                assert_eq!(usize::from(encoded.bytes[1]), length & 255);
            }
        } else if length == 16384 {
            assert_eq!(encoded.bytes[0], 0xc1);
            assert!(encoded.bytes[1..=length].iter().all(|byte| *byte == 0xa5));
            assert_eq!(encoded.bytes[length + 1], 0);
        }
    }
}

/// Reject invalid fragment headers, truncation, and operation limits.
/// Source: malformed ANY framing; version 2026-10-30. Inputs: none.
/// Returns: nothing. Panics on failed assertions. Responsible: asn1c maintainers.
/// History: initial validation. Example: run with `cargo test`.
#[test]
fn rejects_invalid_input_and_limits() {
    let limits = Limits::default();
    for bytes in [
        &[][..],
        &[0x80][..],
        &[0xc0][..],
        &[0xc5][..],
        &[1][..],
        &[0xc1, 0][..],
    ] {
        assert!(Value::decode_uper(bytes, &limits).is_err());
    }
    let small = Limits {
        max_output_bytes: 1,
        ..limits
    };
    assert!(Value(vec![1]).encode_uper(&small).is_err());
    let small = Limits {
        max_input_bytes: 1,
        ..limits
    };
    assert!(Value::decode_uper(&[1, 1], &small).is_err());
}

/// Exercise an OPTIONAL ANY envelope across an unaligned SEQUENCE cursor.
/// Source: X.691 field packing. Version: 2026-10-30. Inputs: none.
/// Returns: nothing. Panics on assertion failure. Responsible: asn1c maintainers.
/// History: composable ANY fields. Example: run with `cargo test`.
#[test]
fn optional_any_field() {
    let limits = Limits::default();
    let packet = Packet {
        flag: true,
        payload: Some(vec![0xa5]),
    };
    let encoded = packet.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xc0, 0x69, 0x40]);
    assert_eq!(encoded.bit_len, 18);
    assert_eq!(
        Packet::decode_uper(&encoded.bytes, &limits).unwrap().value,
        packet
    );
    let absent = Packet {
        flag: true,
        payload: None,
    };
    assert_eq!(absent.encode_uper(&limits).unwrap().bytes, [0x40]);
    assert_eq!(Packet::decode_uper(&[0x40], &limits).unwrap().value, absent);
    assert!(Packet::decode_uper(&[0xc0, 0x40], &limits).is_err());
    let required = Required {
        flag: true,
        payload: vec![0xa5],
    };
    let encoded = required.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bit_len, 17);
    assert_eq!(
        Required::decode_uper(&encoded.bytes, &limits)
            .unwrap()
            .value,
        required
    );
}
