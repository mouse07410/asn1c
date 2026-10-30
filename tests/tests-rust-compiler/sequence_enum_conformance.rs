//! Inline ENUMERATED OPTIONAL record interoperability and malformed inputs.
use asn1c_generated::sequence_enum::{Packet, PacketMaybe, PacketSingle};
use asn1c_runtime::Limits;

/// Check presence bits, numeric ordering, singleton framing, and invalid input.
/// Source: X.691 and the C-generated fixture. Version: 2026-10-30.
/// Inputs: fixed records and encoded bytes. Returns: nothing; assertions panic
/// on failure. Responsible party: asn1c maintainers. History: inline enums.
/// Example: a present high value encodes as 0xe0.
#[test]
fn inline_enums() {
    let limits = Limits::default();
    for (maybe, expected, bits) in [
        (None, 0x40, 2),
        (Some(PacketMaybe::Low), 0xc0, 4),
        (Some(PacketMaybe::Middle), 0xd0, 4),
        (Some(PacketMaybe::High), 0xe0, 4),
    ] {
        let packet = Packet { enabled: true, maybe, single: PacketSingle::Only };
        let encoded = packet.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, [expected]);
        assert_eq!(encoded.bit_len, bits);
        assert_eq!(Packet::decode_uper(&encoded.bytes, &limits).unwrap().value, packet);
    }
    assert!(Packet::decode_uper(&[], &limits).is_err());
    assert!(Packet::decode_uper(&[0xf0], &limits).is_err());
}

/// Check resource limits apply to the enclosing record and enum cursor.
/// Source: UPER shared resource contract. Version: 2026-10-30.
/// Inputs: one present value and restrictive limits. Returns: nothing;
/// assertions panic on failure. Responsible party: asn1c maintainers.
/// History: inline enum budget regression. Example: zero work is rejected.
#[test]
fn inline_enum_limits() {
    let packet = Packet { enabled: true, maybe: Some(PacketMaybe::High), single: PacketSingle::Only };
    let limits = Limits::default();
    let encoded = packet.encode_uper(&limits).unwrap();
    let no_work = Limits { max_work_bits: 0, ..limits };
    assert!(packet.encode_uper(&no_work).is_err());
    assert!(Packet::decode_uper(&encoded.bytes, &no_work).is_err());
    assert!(packet.encode_uper(&Limits { max_output_bytes: 0, ..limits }).is_err());
    assert!(Packet::decode_uper(&encoded.bytes, &Limits { max_input_bytes: 0, ..limits }).is_err());
}
