//! Direct CBOR OCTET STRING and BIT STRING C wire parity tests.
use asn1c_generated::cbor_strings::{BoundedBits, BoundedOctets, FixedBits, FixedOctets};
use asn1c_runtime::{BitStringValue, Limits};

/// Compare fixed and bounded string encodings with generated C vectors.
/// Source: C BIT/OCTET STRING CBOR codecs. Version: 2026-10-30.
/// Inputs: none. Returns: unit. Errors: assertion panic.
/// Responsible: asn1c maintainers. History: direct CBOR string support.
/// Example: `cargo test vectors`.
#[test]
fn vectors() {
    let limits = Limits::default();
    let octets = FixedOctets::new(vec![0xa5, 0x5a]).unwrap();
    assert_eq!(octets.encode_cbor(&limits).unwrap().bytes, [0x42, 0xa5, 0x5a]);
    assert_eq!(
        FixedOctets::decode_cbor(&[0x42, 0xa5, 0x5a], &limits)
            .unwrap()
            .value,
        octets
    );
    let empty = BoundedOctets::new(vec![]).unwrap();
    assert_eq!(empty.encode_cbor(&limits).unwrap().bytes, [0x40]);
    assert_eq!(
        BoundedOctets::decode_cbor(&[0xc0, 0x58, 0], &limits)
            .unwrap()
            .value,
        empty
    );
    let fixed = FixedBits::new(vec![0xa0]).unwrap();
    assert_eq!(fixed.encode_cbor(&limits).unwrap().bytes, [0x42, 5, 0xa0]);
    assert_eq!(
        FixedBits::decode_cbor(&[0x42, 5, 0xa0], &limits)
            .unwrap()
            .value,
        fixed
    );
    let bounded = BoundedBits::new(BitStringValue::new(vec![0x80, 0], 9).unwrap()).unwrap();
    assert_eq!(bounded.encode_cbor(&limits).unwrap().bytes, [0x43, 7, 0x80, 0]);
    assert_eq!(
        BoundedBits::decode_cbor(&[0xc0, 0x43, 7, 0x80, 0], &limits)
            .unwrap()
            .value,
        bounded
    );
    let zero = BoundedBits::new(BitStringValue::new(vec![], 0).unwrap()).unwrap();
    assert_eq!(zero.encode_cbor(&limits).unwrap().bytes, [0x41, 0]);
}

/// Check wrong SIZE, padding, malformed heads and limits are rejected.
/// Source: C BIT/OCTET STRING CBOR validation. Version: 2026-10-30.
/// Inputs: none. Returns: unit. Errors: assertion panic.
/// Responsible: asn1c maintainers. History: malformed-input regression.
/// Example: `cargo test rejects_bad_strings`.
#[test]
fn rejects_bad_strings() {
    let limits = Limits::default();
    assert!(FixedOctets::new(vec![0]).is_err());
    assert!(FixedOctets::decode_cbor(&[0x41, 0], &limits).is_err());
    assert!(BoundedOctets::decode_cbor(&[0x5f], &limits).is_err());
    assert!(FixedBits::new(vec![0xa1]).is_err());
    assert!(FixedBits::decode_cbor(&[0x42, 5, 0xa1], &limits).is_err());
    assert!(BoundedBits::decode_cbor(&[0x40], &limits).is_err());
    assert!(BoundedBits::decode_cbor(&[0x41, 8], &limits).is_err());
    let tiny = Limits {
        max_output_bytes: 1,
        ..limits
    };
    assert!(FixedBits::new(vec![0xa0])
        .unwrap()
        .encode_cbor(&tiny)
        .is_err());
}
