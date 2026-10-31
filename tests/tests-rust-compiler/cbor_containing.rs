//! Typed CONTAINING CBOR vectors and malformed inner values.
use asn1c_generated::cbor_containing::{Bits, BoolBits, BoolOct, Oct};
use asn1c_runtime::Limits;

/// Check C-compatible byte strings and reject incomplete or non-octet inner CBOR.
/// Source: C CBOR string mapping. Version: 2026-10-30. Responsible: maintainers.
/// Inputs: none. Returns: none. Errors: assertion panic. Example: `cargo test`.
#[test]
fn vectors_and_validation() {
    let limits = Limits::default();
    assert_eq!(Oct(2).encode_cbor(&limits).unwrap().bytes, [0x41, 0x02]);
    assert_eq!(Bits(2).encode_cbor(&limits).unwrap().bytes, [0x42, 0, 0x02]);
    assert_eq!(BoolOct(true).encode_cbor(&limits).unwrap().bytes, [0x41, 0xf5]);
    assert_eq!(BoolBits(true).encode_cbor(&limits).unwrap().bytes, [0x42, 0, 0xf5]);
    assert_eq!(Oct::decode_cbor(&[0x41, 0x02], &limits).unwrap().value, Oct(2));
    assert_eq!(Bits::decode_cbor(&[0x42, 0, 0x02], &limits).unwrap().value, Bits(2));
    assert_eq!(BoolOct::decode_cbor(&[0x41, 0xf5], &limits).unwrap().value, BoolOct(true));
    assert_eq!(BoolBits::decode_cbor(&[0x42, 0, 0xf5], &limits).unwrap().value, BoolBits(true));
    for input in [
        &[][..], &[0x40], &[0x41, 0x03], &[0x41, 0xf5],
        &[0x42, 0x02, 0x02], &[0x42, 0x00, 0x02],
    ] {
        assert!(Oct::decode_cbor(input, &limits).is_err());
    }
    for input in [
        &[][..], &[0x40], &[0x41, 0x02], &[0x42, 1, 0x02],
        &[0x43, 0, 0x02, 0x00],
    ] {
        assert!(Bits::decode_cbor(input, &limits).is_err());
    }
    assert!(Oct(3).encode_cbor(&limits).is_err());
    let small = Limits { max_output_bytes: 1, ..limits };
    assert!(Oct(2).encode_cbor(&small).is_err());
    let small = Limits { max_input_bytes: 1, ..limits };
    assert!(Oct::decode_cbor(&[0x41, 0x02], &small).is_err());
}
