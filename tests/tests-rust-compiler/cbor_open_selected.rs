//! Selected OPEN TYPE CBOR map vectors and selector validation.
use asn1c_generated::open_module::{Packet, PacketValue};
use asn1c_runtime::Limits;

/// Check selected rows, reordered keys, malformed selectors and values.
/// Source: C CBOR SEQUENCE and OPEN TYPE mapping. Version: 2026-10-30.
/// Inputs: none. Returns: none. Errors: assertion panic. Responsible: maintainers.
/// History: Rust selected OPEN TYPE CBOR. Example: `cargo test`.
#[test]
fn vectors_and_validation() {
    let limits = Limits::default();
    let yes = Packet { id: 1, value: PacketValue::Row1(true) };
    let two = Packet { id: 2, value: PacketValue::Row2(2) };
    let singleton = Packet { id: 3, value: PacketValue::Row3(5) };
    let yes_wire = [0xa2, 0x62, b'i', b'd', 1, 0x65, b'v', b'a', b'l', b'u', b'e', 0xf5];
    let two_wire = [0xa2, 0x62, b'i', b'd', 2, 0x65, b'v', b'a', b'l', b'u', b'e', 2];
    let singleton_wire = [0xa2, 0x62, b'i', b'd', 3, 0x65, b'v', b'a', b'l', b'u', b'e', 5];
    assert_eq!(yes.encode_cbor(&limits).unwrap().bytes, yes_wire);
    assert_eq!(two.encode_cbor(&limits).unwrap().bytes, two_wire);
    assert_eq!(singleton.encode_cbor(&limits).unwrap().bytes, singleton_wire);
    assert_eq!(Packet::decode_cbor(&yes_wire, &limits).unwrap().value, yes);
    assert_eq!(Packet::decode_cbor(&two_wire, &limits).unwrap().value, two);
    assert_eq!(Packet::decode_cbor(&singleton_wire, &limits).unwrap().value, singleton);
    let reversed = [0xa2, 0x65, b'v', b'a', b'l', b'u', b'e', 0xf5, 0x62, b'i', b'd', 1];
    assert_eq!(Packet::decode_cbor(&reversed, &limits).unwrap().value, yes);
    let unknown = [0xa3, 0x61, b'x', 0xf6, 0x62, b'i', b'd', 1,
                   0x65, b'v', b'a', b'l', b'u', b'e', 0xf5];
    assert_eq!(Packet::decode_cbor(&unknown, &limits).unwrap().value, yes);
    assert!(Packet { id: 2, value: PacketValue::Row1(true) }.encode_cbor(&limits).is_err());
    assert!(Packet { id: 2, value: PacketValue::Row2(3) }.encode_cbor(&limits).is_err());
    for wire in [
        &[][..], &[0xa0][..], &[0xa1, 0x62, b'i', b'd', 1][..],
        &[0xa1, 0x65, b'v', b'a', b'l', b'u', b'e', 0xf5][..],
        &[0xa2, 0x62, b'i', b'd', 4, 0x65, b'v', b'a', b'l', b'u', b'e', 1][..],
        &[0xa2, 0x62, b'i', b'd', 2, 0x65, b'v', b'a', b'l', b'u', b'e', 3][..],
        &[0xa2, 0x62, b'i', b'd', 1, 0x65, b'v', b'a', b'l', b'u', b'e', 1][..],
        &[0xa2, 0x62, b'i', b'd', 1, 0x62, b'i', b'd', 1][..],
        &[0xa4, 0x61, b'x', 0xf6, 0x61, b'x', 0xf6, 0x62, b'i', b'd', 1,
          0x65, b'v', b'a', b'l', b'u', b'e', 0xf5][..],
    ] {
        assert!(Packet::decode_cbor(wire, &limits).is_err());
    }
}
