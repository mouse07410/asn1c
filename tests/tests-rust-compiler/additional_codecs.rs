//! Generated wrapper checks for the bounded primitive APER and OER slices.
//!
//! These vectors exercise the generated API as well as the vendored runtime.
//! They cover only direct BOOLEAN, NULL, and finite `i64` INTEGER assignments.

use asn1c_generated::first_slice::{Count, Empty, Flag, SignBounds, Singleton};
use asn1c_runtime::{Error, Limits};

/// Check the generated APER wrappers against independent primitive vectors.
///
/// Parameters: none. Returns: no value; assertions fail the test on mismatch.
/// Errors: a runtime error or failed assertion panics in this test.
/// Original source: X.691 aligned PER primitive rules. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: initial APER
/// generated integration. Example: TRUE occupies one meaningful bit.
#[test]
fn generated_aper_primitive_vectors_and_invalid_offsets() {
    let limits = Limits::default();
    let flag = Flag::new(true).encode_aper(&limits).expect("encode APER BOOLEAN");
    assert_eq!(flag.bytes, [0x80]);
    assert_eq!(flag.bit_len, 1);
    assert!(Flag::decode_aper(&flag.bytes, &limits).unwrap().value.value());

    let null = Empty.encode_aper(&limits).expect("encode APER NULL");
    assert_eq!(null.bytes, [0]);
    assert_eq!(null.bit_len, 0);
    let decoded_null = Empty::decode_aper(&null.bytes, &limits).unwrap();
    assert_eq!(decoded_null.consumed_bits, 0);
    assert_eq!(decoded_null.consumed_bytes, 1);
    assert!(matches!(Empty::decode_aper(&[], &limits), Err(Error::NeedMoreBytes { .. })));
    assert!(matches!(Empty::decode_aper(&[1], &limits), Err(Error::InvalidEncoding { .. })));

    let count = Count::new(10).unwrap().encode_aper(&limits).unwrap();
    assert_eq!(count.bytes, [0xa0]);
    assert_eq!(count.bit_len, 5);
    assert_eq!(Count::decode_aper(&count.bytes, &limits).unwrap().value.value(), 10);
    assert!(matches!(
        Count::decode_aper(&[0xf8], &limits),
        Err(Error::InvalidEncoding { .. })
    ));

    let signed = SignBounds::new(128).unwrap().encode_aper(&limits).unwrap();
    assert_eq!(signed.bytes, [0x01, 0x01]);
    assert_eq!(SignBounds::decode_aper(&signed.bytes, &limits).unwrap().value.value(), 128);
    let singleton = Singleton::new(5).unwrap().encode_aper(&limits).unwrap();
    assert_eq!(singleton.bytes, [0]);
    assert_eq!(singleton.bit_len, 0);
    assert_eq!(Singleton::decode_aper(&[0], &limits).unwrap().value.value(), 5);
}

/// Check generated OER wrappers, prefix accounting, and malformed input.
///
/// Parameters: none. Returns: no value; assertions fail the test on mismatch.
/// Errors: a runtime error or failed assertion panics in this test.
/// Original source: X.696 primitive rules. Version/date: 2026-10-30.
/// Responsible party: asn1c maintainers. History: initial OER generated
/// integration. Example: `Count(10)` encodes as the signed octet `0A`.
#[test]
fn generated_oer_primitive_vectors_and_prefixes() {
    let limits = Limits::default();
    let flag = Flag::new(true).encode_oer(&limits).unwrap();
    assert_eq!(flag.bytes, [0xff]);
    assert_eq!(flag.bit_len, 8);
    assert!(Flag::decode_oer(&[1, 0xaa], &limits).unwrap().value.value());

    let null = Empty.encode_oer(&limits).unwrap();
    assert_eq!(null.bytes, []);
    assert_eq!(Empty::decode_oer(&[], &limits).unwrap().consumed_bytes, 0);

    let count = Count::new(10).unwrap().encode_oer(&limits).unwrap();
    assert_eq!(count.bytes, [0x0a]);
    assert_eq!(Count::decode_oer(&[0x0a, 0xaa], &limits).unwrap().consumed_bytes, 1);
    assert_eq!(Singleton::new(5).unwrap().encode_oer(&limits).unwrap().bytes, [5]);
    assert!(matches!(
        Count::decode_oer(&[0x7f], &limits),
        Err(Error::ValueOutOfRange { .. })
    ));
}
