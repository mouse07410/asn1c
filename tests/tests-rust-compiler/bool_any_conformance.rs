//! Packing BOOLEAN fields preserves opaque ANY framing and ownership.

use asn1c_generated::bool_any::Packet;
use asn1c_runtime::Limits;

/// Exercise every packed pattern with absent, empty, and nonempty opaque payloads.
/// Inputs: none. Returns: none. Errors: ownership, framing, or decoding mismatch fails.
/// Source: `BoolAny` and existing opaque ANY contracts. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: emitter dispatch regression.
/// Example: `Packet::new([true; 4], (Some(vec![0xaa]),))`.
#[test]
fn packed_boolean_siblings_preserve_optional_any() {
    let limits = Limits::default();
    for pattern in 0_u8..16 {
        let flags = std::array::from_fn(|index| pattern & (1 << index) != 0);
        for payload in [None, Some(Vec::new()), Some(vec![0xde, 0xad])] {
            let value = Packet::new(flags, (payload,));
            let encoded = value.encode_uper(&limits).unwrap();
            let decoded = Packet::decode_uper(&encoded.bytes, &limits).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bits, encoded.bit_len);
            assert_eq!(value.get_fourth(), flags[3]);
        }
    }
    let absent = Packet::new([true, false, true, false], (None,));
    let empty = Packet::new([true, false, true, false], (Some(Vec::new()),));
    let absent_wire = absent.encode_uper(&limits).unwrap();
    assert_eq!(absent_wire.bytes, [0x50]);
    assert_eq!(absent_wire.bit_len, 5);
    let empty_wire = empty.encode_uper(&limits).unwrap();
    assert_eq!(empty_wire.bytes, [0xd0, 0]);
    assert_eq!(empty_wire.bit_len, 13);
    for end in 0..empty_wire.bytes.len() {
        assert!(Packet::decode_uper(&empty_wire.bytes[..end], &limits).is_err());
    }
}
