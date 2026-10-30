//! Generated fixed-size UPER OCTET STRING and BIT STRING regression tests.

use asn1c_generated::string_slice::{
    EmptyBits, EmptyOctets, MixedStringRecord, OneOctet, ThreeBits,
};
use asn1c_runtime::{Error, Limits, Resource};

/// Check standalone octet and bit values, padding, and prefix consumption.
///
/// Parameters: none. Returns: no value; assertions verify exact wire values.
/// Errors: malformed constructors and truncated input return typed errors.
/// Original source: fixed-size X.691 string rules. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: fixed string UPER slice.
/// Example: the three bits `101` occupy the high part of byte `A0`.
#[test]
fn standalone_strings_validate_and_round_trip() {
    let limits = Limits::default();
    let octets = OneOctet::new(vec![0xa5]).unwrap();
    let encoded = octets.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xa5]);
    assert_eq!(encoded.bit_len, 8);
    let decoded = OneOctet::decode_uper(&[0xa5, 0xff], &limits).unwrap();
    assert_eq!(decoded.value, octets);
    assert_eq!((decoded.consumed_bits, decoded.consumed_bytes), (8, 1));

    let bits = ThreeBits::new(vec![0xa0]).unwrap();
    let encoded = bits.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0xa0]);
    assert_eq!(encoded.bit_len, 3);
    assert_eq!(ThreeBits::decode_uper(&[0xbf], &limits).unwrap().value, bits);
    assert!(matches!(OneOctet::new(vec![]), Err(Error::InvalidEncoding { .. })));
    assert!(matches!(ThreeBits::new(vec![0xa1]), Err(Error::InvalidEncoding { .. })));
    assert!(matches!(ThreeBits::decode_uper(&[], &limits), Err(Error::NeedMoreBits { .. })));
}

/// Check zero-width strings use the complete-value filler once.
///
/// Parameters: none. Returns: no value; assertions inspect byte and bit counts.
/// Errors: malformed filler and missing input are rejected. Original source:
/// X.691 complete UPER framing. Version/date: 2026-10-30. Responsible party:
/// asn1c maintainers. History: fixed string UPER slice. Example: SIZE(0)
/// encodes as one zero filler octet with zero meaningful bits.
#[test]
fn empty_strings_use_complete_filler() {
    let limits = Limits::default();
    let octets = EmptyOctets::new(vec![]).unwrap();
    let bits = EmptyBits::new(vec![]).unwrap();
    for encoded in [octets.encode_uper(&limits).unwrap(), bits.encode_uper(&limits).unwrap()] {
        assert_eq!(encoded.bytes, [0]);
        assert_eq!(encoded.bit_len, 0);
    }
    assert_eq!(EmptyOctets::decode_uper(&[0], &limits).unwrap().value, octets);
    assert_eq!(EmptyBits::decode_uper(&[0], &limits).unwrap().value, bits);
    assert!(matches!(EmptyBits::decode_uper(&[], &limits), Err(Error::NeedMoreBytes { .. })));
    assert!(matches!(EmptyOctets::decode_uper(&[1], &limits), Err(Error::InvalidEncoding { .. })));
}

/// Check string fields share one continuous bit cursor with surrounding types.
///
/// Parameters: none. Returns: no value; assertions compare a manual vector.
/// Errors: malformed field lengths, pad bits, truncation, and budget exhaustion
/// are expected. Original source: X.691 unaligned field order. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: fixed string
/// SEQUENCE slice. Example: `1 A5 5A 10101 10` packs as `D2 AD 56`.
#[test]
fn mixed_sequence_packs_and_checks_complete_budget() {
    let value = MixedStringRecord {
        prefix: true,
        octets: vec![0xa5, 0x5a],
        bits: vec![0xa8],
        suffix: 2,
    };
    let exact = Limits {
        max_input_bytes: 3,
        max_output_bytes: 3,
        max_work_bits: 56,
    };
    let encoded = value.encode_uper(&exact).unwrap();
    assert_eq!(encoded.bytes, [0xd2, 0xad, 0x56]);
    assert_eq!(encoded.bit_len, 24);
    let decoded = MixedStringRecord::decode_uper(&encoded.bytes, &exact).unwrap();
    assert_eq!(decoded.value, value);
    assert_eq!((decoded.consumed_bits, decoded.consumed_bytes), (24, 3));

    let less_work = Limits { max_work_bits: 55, ..exact };
    assert!(matches!(value.encode_uper(&less_work), Err(Error::LimitExceeded {
        resource: Resource::WorkBits, ..
    })));
    assert!(matches!(MixedStringRecord::decode_uper(&encoded.bytes, &less_work),
        Err(Error::LimitExceeded { resource: Resource::WorkBits, .. })));
    assert!(matches!(MixedStringRecord::decode_uper(&encoded.bytes[..2], &exact),
        Err(Error::NeedMoreBits { .. })));
    let malformed = MixedStringRecord { bits: vec![0xa9], ..value.clone() };
    assert!(matches!(malformed.encode_uper(&exact), Err(Error::InvalidEncoding { .. })));
    let malformed = MixedStringRecord { octets: vec![0xa5], ..value };
    assert!(matches!(malformed.encode_uper(&exact), Err(Error::InvalidEncoding { .. })));
}
