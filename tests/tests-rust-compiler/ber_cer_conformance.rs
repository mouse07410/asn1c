//! Generated BER/DER/CER tests for ENUMERATED and size-constrained strings.

use asn1c_generated::ber_cer_slice::{Bits, Color, FixedBits, FixedOctets, Octets};
use asn1c_runtime::{BitStringValue, Error, Limits};

/// Check declared ENUMERATED numeric values in DER, BER, and CER.
///
/// Parameters: none. Returns: no value; assertions compare fixed wire vectors.
/// Errors: unknown values and malformed TLVs must return typed errors.
/// Original source: ASN.1 ENUMERATED roots and X.690 TLV encoding.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: generated BER/CER method coverage. Example: minimum(-3) is `0a 01 fd`.
#[test]
fn enumerated_uses_declared_signed_values() {
    let limits = Limits::default();
    // Map each Rust variant to its declared signed INTEGER value in both rules.
    for (value, der, cer) in [
        (
            Color::Minimum,
            &[0x0a, 0x01, 0xfd][..],
            &[0x0a, 0x01, 0xfd][..],
        ),
        (
            Color::Zero,
            &[0x0a, 0x01, 0x00][..],
            &[0x0a, 0x01, 0x00][..],
        ),
        (
            Color::Maximum,
            &[0x0a, 0x01, 0x07][..],
            &[0x0a, 0x01, 0x07][..],
        ),
        (
            Color::Wideminimum,
            &[0x0a, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0][..],
            &[0x0a, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0][..],
        ),
        (
            Color::Widemaximum,
            &[0x0a, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            &[0x0a, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        ),
    ] {
        assert_eq!(value.encode_der(&limits).unwrap().bytes, der);
        assert_eq!(value.encode_cer(&limits).unwrap().bytes, cer);
        assert_eq!(Color::decode_ber(der, &limits).unwrap().value, value);
        assert_eq!(Color::decode_cer(cer, &limits).unwrap().value, value);
    }
    // Reject a numeric value that the runtime can parse but the ASN.1 root omits.
    assert!(matches!(
        Color::decode_ber(&[0x0a, 0x01, 0x01], &limits),
        Err(Error::InvalidEncoding { .. })
    ));
    assert!(Color::decode_cer(&[0x0a, 0x01, 0x01], &limits).is_err());
    // The generated decode method forwards input ceilings to the BER runtime.
    let short_input = Limits {
        max_input_bytes: 2,
        ..limits
    };
    assert!(Color::decode_ber(&[0x0a, 0x01, 0xfd], &short_input).is_err());
}

/// Check bounded and fixed OCTET STRING APIs enforce the ASN.1 SIZE.
///
/// Parameters: none. Returns: no value; assertions compare BER/DER/CER bytes.
/// Errors: out-of-range constructor and decoded lengths return typed errors.
/// Original source: X.690 OCTET STRING encoding and declared SIZE constraints.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: first generated string BER/CER tests. Example: `[a5]` is `04 01 a5`.
#[test]
fn octet_strings_enforce_declared_sizes() {
    let limits = Limits::default();
    let octets = Octets::new(vec![0xa5, 0x5a]).unwrap();
    let expected = [0x04, 0x02, 0xa5, 0x5a];
    // Both canonical encoders preserve valid contents and enforce output limits.
    assert_eq!(octets.encode_der(&limits).unwrap().bytes, expected);
    assert_eq!(octets.encode_cer(&limits).unwrap().bytes, expected);
    let short_output = Limits {
        max_output_bytes: 3,
        ..limits
    };
    assert!(octets.encode_der(&short_output).is_err());
    let input = [0x04, 0x02, 0xa5, 0x5a, 0xff];
    let decoded = Octets::decode_ber(&input, &limits).unwrap();
    assert_eq!(decoded.value.as_bytes(), [0xa5, 0x5a]);
    assert_eq!((decoded.consumed_bits, decoded.consumed_bytes), (32, 4));
    // BER prefix decoding rejects values outside the bounded and fixed SIZE.
    assert!(Octets::decode_ber(&[0x04, 0x00], &limits).is_err());
    assert!(Octets::decode_ber(&[0x04, 0x05, 1, 2, 3, 4, 5], &limits).is_err());
    assert!(Octets::new(vec![]).is_err());
    assert!(Octets::new(vec![0; 5]).is_err());

    let fixed = FixedOctets::new(vec![0xa5, 0x5a]).unwrap();
    assert_eq!(fixed.encode_der(&limits).unwrap().bytes, expected);
    assert_eq!(fixed.encode_cer(&limits).unwrap().bytes, expected);
    assert!(FixedOctets::decode_cer(&[0x04, 0x01, 0xa5], &limits).is_err());
}

/// Check BIT STRING logical widths, including same-storage wrong-width input.
///
/// Parameters: none. Returns: no value; assertions compare wire vectors.
/// Errors: declared SIZE violations and invalid packed bits return typed errors.
/// Original source: X.690 BIT STRING unused-bit encoding and ASN.1 SIZE.
/// Version/date: 2026-10-31. Responsible party: asn1c maintainers.
/// History: fixed-width decode regression for matching storage but wrong width.
/// Example: 3 meaningful bits `a0` encode as `03 02 05 a0`.
#[test]
fn bit_strings_enforce_exact_logical_sizes() {
    let limits = Limits::default();
    let bits = Bits::new(BitStringValue::new(vec![0xa0], 3).unwrap()).unwrap();
    let expected = [0x03, 0x02, 0x05, 0xa0];
    // The logical bit width, unused-bit count, and BER prefix are all preserved.
    assert_eq!(bits.encode_der(&limits).unwrap().bytes, expected);
    assert_eq!(bits.encode_cer(&limits).unwrap().bytes, expected);
    let decoded = Bits::decode_cer(&[0x03, 0x02, 0x05, 0xa0, 0xff], &limits).unwrap();
    assert_eq!(decoded.value.bit_len(), 3);
    assert_eq!((decoded.consumed_bits, decoded.consumed_bytes), (32, 4));
    assert!(Bits::decode_ber(&[0x03, 0x02, 0x07, 0x80], &limits).is_err());
    assert!(Bits::new(BitStringValue::new(vec![0x80], 2).unwrap()).is_err());

    // Fixed decoding must reject four bits even though one packed byte fits SIZE(3).
    let fixed = FixedBits::new(vec![0xa0]).unwrap();
    assert_eq!(fixed.encode_der(&limits).unwrap().bytes, expected);
    assert_eq!(fixed.encode_cer(&limits).unwrap().bytes, expected);
    assert!(FixedBits::decode_ber(&[0x03, 0x02, 0x04, 0xa0], &limits).is_err());
    assert!(FixedBits::decode_cer(&[0x03, 0x02, 0x05, 0xa0, 0x00], &limits).is_ok());
}
