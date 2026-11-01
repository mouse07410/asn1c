//! Generated BER/DER/CER conformance tests for unconstrained INTEGER.

use asn1c_generated::big_integer::Huge;
use asn1c_runtime::{Error, Limits};

/// Compare the supported small and machine-boundary values to exact TLVs.
///
/// Parameters: none. Returns: no value; assertions compare DER and CER vectors.
/// Errors: encoding and decoding errors cause an assertion failure.
/// Original source: X.690 INTEGER vectors. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: `BigInteger` generator slice.
/// Example: 128 encodes as `02 02 00 80`.
#[test]
fn integer_boundaries_match_exact_der_and_cer() {
    let limits = Limits::default();
    let vectors: &[(&[u8], &[u8])] = &[
        (&[0x00], &[0x02, 0x01, 0x00]),
        (&[0x01], &[0x02, 0x01, 0x01]),
        (&[0xff], &[0x02, 0x01, 0xff]),
        (&[0xff, 0x7f], &[0x02, 0x02, 0xff, 0x7f]),
        (&[0x80], &[0x02, 0x01, 0x80]),
        (&[0x7f], &[0x02, 0x01, 0x7f]),
        (&[0x00, 0x80], &[0x02, 0x02, 0x00, 0x80]),
        (&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
         &[0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        (&[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
         &[0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (&[0x01, 0, 0, 0, 0, 0, 0, 0, 0],
         &[0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
        (&[0xfe, 0, 0, 0, 0, 0, 0, 0, 0],
         &[0x02, 0x09, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];

    // Each fixed DER vector also applies to CER for primitive INTEGER TLVs.
    for (signed_bytes, expected) in vectors {
        let value = Huge::try_from_signed_bytes(signed_bytes, &limits).unwrap();
        assert_eq!(value.encode_der(&limits).unwrap().bytes, *expected);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, *expected);
        assert_eq!(value.as_signed_bytes(), *signed_bytes);
        let mut prefixed = expected.to_vec();
        prefixed.push(0xff);
        let ber = Huge::decode_ber(&prefixed, &limits).unwrap();
        let cer = Huge::decode_cer(&prefixed, &limits).unwrap();
        for decoded in [ber, cer] {
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.consumed_bytes, expected.len());
            assert_eq!(decoded.consumed_bits, expected.len() * 8);
        }
    }
}

/// Verify a content length above 127 uses the correct DER/CER length form.
///
/// Parameters: none. Returns: no value; assertions compare the complete TLV.
/// Errors: encoding failures cause an assertion failure.
/// Original source: X.690 long-form length encoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: arbitrary length coverage.
/// Example: a 129-octet INTEGER body begins `02 81 81`.
#[test]
fn integer_content_longer_than_128_octets_encodes_exactly() {
    let limits = Limits::default();
    let mut signed_bytes = vec![0; 129];
    signed_bytes[0] = 1;
    let value = Huge::try_from_signed_bytes(&signed_bytes, &limits).unwrap();
    let mut expected = vec![0x02, 0x81, 0x81];
    expected.extend_from_slice(&signed_bytes);

    assert_eq!(value.encode_der(&limits).unwrap().bytes, expected);
    assert_eq!(value.encode_cer(&limits).unwrap().bytes, expected);
    assert_eq!(value.as_signed_bytes(), signed_bytes);
    let decoded = Huge::decode_ber(&expected, &limits).unwrap();
    let strict = Huge::decode_cer(&expected, &limits).unwrap();
    for value in [decoded, strict] {
        assert_eq!(value.value.as_signed_bytes(), signed_bytes);
        assert_eq!(value.consumed_bytes, expected.len());
        assert_eq!(value.consumed_bits, expected.len() * 8);
    }
}

/// Check exact i64 conversion edges without narrowing arbitrary values.
///
/// Parameters: none. Returns: no value; assertions compare optional conversions.
/// Errors: construction failures cause an assertion failure.
/// Original source: signed `i64` boundaries. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: conversion accessor coverage.
/// Example: the positive value `2^64` returns `None`.
#[test]
fn optional_i64_conversion_handles_both_signed_boundaries() {
    let limits = Limits::default();
    let maximum = Huge::try_from_signed_bytes(
        &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &limits,
    )
    .unwrap();
    let minimum = Huge::try_from_signed_bytes(
        &[0x80, 0, 0, 0, 0, 0, 0, 0],
        &limits,
    )
    .unwrap();
    let above = Huge::try_from_signed_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0], &limits)
        .unwrap();
    let below = Huge::try_from_signed_bytes(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 0], &limits)
        .unwrap();

    assert_eq!(maximum.try_to_i64(), Some(i64::MAX));
    assert_eq!(minimum.try_to_i64(), Some(i64::MIN));
    assert_eq!(above.try_to_i64(), None);
    assert_eq!(below.try_to_i64(), None);
}

/// Check BER/CER decoding, prefix lengths, strictness, and redundant signs.
///
/// Parameters: none. Returns: no value; assertions check decoded values.
/// Errors: malformed or noncanonical encodings must produce runtime errors.
/// Original source: BER/CER INTEGER decoding. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: prefix and strictness tests.
/// Example: BER accepts `02 02 00 01`; strict CER rejects it.
#[test]
fn decoding_reports_exact_prefix_and_enforces_cer_canonicality() {
    let limits = Limits::default();
    let canonical = [0x02, 0x02, 0x00, 0x80, 0xff];
    let decoded = Huge::decode_ber(&canonical, &limits).unwrap();
    assert_eq!(decoded.value.as_signed_bytes(), [0x00, 0x80]);
    assert_eq!((decoded.consumed_bytes, decoded.consumed_bits), (4, 32));
    assert_eq!(decoded.value.encode_der(&limits).unwrap().bytes, &canonical[..4]);
    let strict = Huge::decode_cer(&canonical, &limits).unwrap();
    assert_eq!(strict.value.as_signed_bytes(), [0x00, 0x80]);
    assert_eq!((strict.consumed_bytes, strict.consumed_bits), (4, 32));

    for redundant in [&[0x02, 0x02, 0x00, 0x01][..], &[0x02, 0x02, 0xff, 0xff][..]] {
        let decoded = Huge::decode_ber(redundant, &limits).unwrap();
        assert_eq!(decoded.consumed_bytes, redundant.len());
        assert_eq!(decoded.consumed_bits, redundant.len() * 8);
        assert!(Huge::decode_cer(redundant, &limits).is_err());
    }
    let high_tag_alias = [0x1f, 0x02, 0x01, 0x01];
    let alias = Huge::decode_ber(&high_tag_alias, &limits).unwrap();
    assert_eq!(alias.value.try_to_i64(), Some(1));
    assert_eq!((alias.consumed_bytes, alias.consumed_bits), (4, 32));
    assert!(Huge::decode_cer(&high_tag_alias, &limits).is_err());
    assert!(Huge::decode_ber(&[0x02, 0x00], &limits).is_err());
    assert!(Huge::decode_cer(&[0x02, 0x00], &limits).is_err());
}

/// Exercise malformed, truncated, limited, and mutated byte inputs safely.
///
/// Parameters: none. Returns: no value; assertions require checked outcomes.
/// Errors: malformed inputs and exhausted limits must return errors.
/// Original source: X.690 malformed-input boundary tests. Version/date:
/// 2026-11-01. Responsible party: asn1c maintainers. History: hostile input.
/// Example: a truncated length octet is rejected without panicking.
#[test]
fn malformed_inputs_and_resource_limits_are_checked() {
    let limits = Limits::default();
    for input in [
        &[][..],
        &[0x03, 0x01, 0x00][..],
        &[0x22, 0x01, 0x01][..],
        &[0x82, 0x01, 0x01][..],
        &[0x02, 0x80, 0x00, 0x00][..],
        &[0x02, 0x02, 0x01][..],
        &[0x02, 0x82, 0x01][..],
    ] {
        assert!(Huge::decode_ber(input, &limits).is_err());
        assert!(Huge::decode_cer(input, &limits).is_err());
    }

    let value = Huge::try_from_signed_bytes(&[0x01, 0, 0, 0], &limits).unwrap();
    let small_input = Limits { max_input_bytes: 3, ..limits };
    let small_output = Limits { max_output_bytes: 4, ..limits };
    let no_work = Limits { max_work_bits: 0, ..limits };
    assert!(Huge::decode_ber(&[0x02, 0x02, 0x01, 0x00], &small_input).is_err());
    assert!(value.encode_der(&small_output).is_err());
    assert!(value.encode_cer(&no_work).is_err());

    // Mutate each byte and try every truncation; accepted prefixes stay bounded.
    let wire = [0x02, 0x04, 0x01, 0, 0, 0];
    for index in 0..wire.len() {
        let mut mutated = wire;
        mutated[index] ^= 0x80;
        if let Ok(decoded) = Huge::decode_ber(&mutated, &limits) {
            assert!(decoded.consumed_bytes <= mutated.len());
            assert_eq!(decoded.consumed_bits, decoded.consumed_bytes * 8);
        }
        assert!(Huge::decode_ber(&wire[..index], &limits).is_err());
    }
}

/// Confirm byte constructors own and normalize their input and reject empty.
///
/// Parameters: none. Returns: no value; assertions inspect accessor bytes.
/// Errors: empty representations are rejected with `InvalidEncoding`.
/// Original source: runtime `BigInteger` constructor. Version/date: 2026-11-01.
/// Responsible party: asn1c maintainers. History: mutation isolation test.
/// Example: redundant `00 01` normalizes to `01`.
#[test]
fn constructor_copies_and_normalizes_signed_bytes() {
    let limits = Limits::default();
    let mut source = [0x00, 0x01];
    let value = Huge::try_from_signed_bytes(&source, &limits).unwrap();
    source[1] = 0xff;
    assert_eq!(source, [0x00, 0xff]);
    assert_eq!(value.as_signed_bytes(), [0x01]);
    assert_eq!(value.try_to_i64(), Some(1));
    assert!(matches!(
        Huge::try_from_signed_bytes(&[], &limits),
        Err(Error::InvalidEncoding { .. })
    ));
}
