//! CBOR SEQUENCE fields with direct fixed and bounded strings.
use asn1c_generated::cbor_sequence_strings::Record;
use asn1c_runtime::{BitStringValue, Limits};

/// Compare Rust and generated C CBOR map bytes for string fields.
/// Source: C SEQUENCE and BIT/OCTET CBOR codecs. Version: 2026-10-30.
/// Inputs: none. Returns: unit. Errors: assertion panic.
/// Responsible: asn1c maintainers. History: flat string-field support.
/// Example: `cargo test vector`.
#[test]
fn vector() {
    let limits = Limits::default();
    let value = Record {
        bits: BitStringValue::new(vec![0x80, 0], 9).unwrap(),
        octets: vec![0xa5, 0x5a],
        maybe_bits: Some(vec![0xa0]),
        maybe_octets: Some(vec![]),
    };
    let expected = [
        0xa4, 0x64, b'b', b'i', b't', b's', 0x43, 7, 0x80, 0, 0x66, b'o', b'c', b't', b'e',
        b't', b's', 0x42, 0xa5, 0x5a, 0x69, b'm', b'a', b'y', b'b', b'e', b'B', b'i', b't',
        b's', 0x42, 5, 0xa0, 0x6b, b'm', b'a', b'y', b'b', b'e', b'O', b'c', b't', b'e', b't',
        b's', 0x40,
    ];
    assert_eq!(value.encode_cbor(&limits).unwrap().bytes, expected);
    assert_eq!(Record::decode_cbor(&expected, &limits).unwrap().value, value);
}

/// Reject malformed sizes and padding; accept omitted OPTIONAL strings.
/// Source: C SEQUENCE and string CBOR validation. Version: 2026-10-30.
/// Inputs: none. Returns: unit. Errors: assertion panic.
/// Responsible: maintainers. History: malformed string-field regression.
/// Example: `cargo test missing_and_malformed`.
#[test]
fn missing_and_malformed() {
    let limits = Limits::default();
    let wire = [
        0xa2, 0x66, b'o', b'c', b't', b'e', b't', b's', 0x42, 0xa5, 0x5a, 0x64, b'b', b'i',
        b't', b's', 0x42, 5, 0xa0,
    ];
    let decoded = Record::decode_cbor(&wire, &limits).unwrap().value;
    assert_eq!(decoded.bits.bit_len(), 3);
    assert!(decoded.maybe_bits.is_none());
    assert!(decoded.maybe_octets.is_none());
    let mut wrong_size = wire;
    wrong_size[8] = 0x41;
    assert!(Record::decode_cbor(&wrong_size, &limits).is_err());
    let mut bad_padding = wire;
    bad_padding[18] = 0xa1;
    assert!(Record::decode_cbor(&bad_padding, &limits).is_err());
    let missing = [0xa1, 0x64, b'b', b'i', b't', b's', 0x42, 5, 0xa0];
    assert!(Record::decode_cbor(&missing, &limits).is_err());
    let invalid_key = [0xa1, 0x61, 0xff, 0xf5];
    assert!(Record::decode_cbor(&invalid_key, &limits).is_err());
}
