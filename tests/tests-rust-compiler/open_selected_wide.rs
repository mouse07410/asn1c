//! OER selected OPEN TYPE with multi-octet selector and selected integer.
use asn1c_generated::open_module::{Packet, PacketValue};
use asn1c_runtime::Limits;

/// Verify a two-octet selector and selected value against generated C.
/// Source: C OER codecs. Version: 2026-10-30. Inputs: none; returns nothing.
/// Panics on failure. Responsible: asn1c maintainers. History: wide OER parity.
/// Example: run with `cargo test`.
#[test]
fn wide_oer() {
    let limits = Limits::default();
    let packet = Packet {
        id: 2,
        value: PacketValue::Row2(256),
    };
    let wire = [0, 2, 2, 1, 0];
    assert_eq!(packet.encode_oer(&limits).unwrap().bytes, wire);
    assert_eq!(Packet::decode_oer(&wire, &limits).unwrap().value, packet);
    assert!(Packet::decode_oer(&[0, 2, 1, 0], &limits).is_err());
    assert!(Packet::decode_oer(&[0, 2, 2, 1], &limits).is_err());
}
