//! Generated nonextensible UPER ENUMERATED regression tests.

use asn1c_generated::enum_slice::{Color, Keyword, Only, Three};
use asn1c_runtime::{Error, Limits, Resource};

/// Check numeric value order defines UPER root indexes, not declaration order.
///
/// Parameters: none. Returns: no value; assertions compare fixed vectors.
/// Errors: spare indexes and truncation return typed errors. Original source:
/// X.691 root ENUMERATED indexing and C value2enum order. Version/date:
/// 2026-10-30. Responsible party: asn1c maintainers. History: first enum
/// slice. Example: `blue(20)` gets index 2 despite being declared first.
#[test]
fn numeric_order_and_spare_index() {
    let limits = Limits::default();
    for (value, wire) in [
        (Color::Blue, 0x80),
        (Color::Red, 0x00),
        (Color::Green, 0x40),
    ] {
        let encoded = value.encode_uper(&limits).unwrap();
        assert_eq!(encoded.bytes, [wire]);
        assert_eq!(encoded.bit_len, 2);
        let decoded = Color::decode_uper(&[wire, 0xff], &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!((decoded.consumed_bits, decoded.consumed_bytes), (2, 1));
    }
    assert!(matches!(Color::decode_uper(&[0xc0], &limits),
        Err(Error::InvalidEncoding { .. })));
    assert!(matches!(Color::decode_uper(&[], &limits), Err(Error::NeedMoreBits { .. })));
}

/// Check singleton framing, signed numeric values, and exact work bounds.
///
/// Parameters: none. Returns: no value; assertions verify UPER behavior.
/// Errors: invalid filler and resource exhaustion return typed errors.
/// Original source: complete UPER framing and constrained root index.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: first enum slice. Example: a singleton uses zero wire bits.
#[test]
fn singleton_and_budgets() {
    let limits = Limits::default();
    let encoded = Only::Sole.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0]);
    assert_eq!(encoded.bit_len, 0);
    assert_eq!(Only::decode_uper(&[0], &limits).unwrap().value, Only::Sole);
    assert!(matches!(Only::decode_uper(&[1], &limits), Err(Error::InvalidEncoding { .. })));

    let encoded = Three::Third.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0x80]);
    assert_eq!(Three::decode_uper(&encoded.bytes, &limits).unwrap().value, Three::Third);
    let exact = Limits { max_work_bits: 10, ..limits };
    Color::Green.encode_uper(&exact).unwrap();
    let too_small = Limits { max_work_bits: 9, ..limits };
    assert!(matches!(Color::Green.encode_uper(&too_small),
        Err(Error::LimitExceeded { resource: Resource::WorkBits, .. })));
}

/// Check a mixed-case ASN.1 item cannot become Rust's reserved `Self` name.
///
/// Parameters: none. Returns: no value; assertion verifies generated API.
/// Errors: no error expected. Original source: Rust identifier rules.
/// Version/date: 2026-10-30. Responsible party: asn1c maintainers.
/// History: review regression for enum variant normalization.
/// Example: ASN.1 `sELF` becomes Rust `Asn1Self`.
#[test]
fn keyword_after_case_normalization_is_safe() {
    let limits = Limits::default();
    let encoded = Keyword::Asn1Self.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0]);
    assert_eq!(encoded.bit_len, 1);
    assert_eq!(Keyword::decode_uper(&[0], &limits).unwrap().value, Keyword::Asn1Self);
}
