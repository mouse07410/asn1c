use asn1c_generated::wide_optional::Flags;
use asn1c_runtime::Limits;

/// Preserve the transparent constructor tuple and all-absent OPTIONAL map.
///
/// Inputs: four required values and sixty absent OPTIONAL fields. Returns no
/// value; bytes, bit length, and decode equality are asserted. Errors: any
/// codec mismatch fails. Source: `WideOptional` schema and X.691 ordering.
/// Version/date: 2026-11-01. Responsible party: asn1c maintainers.
/// History: oversized OPTIONAL tuple regression. Example: call `new` with the
/// original tuple shape even though generated Rust uses a private type alias.
#[test]
fn wide_optional_tuple_remains_transparent_and_roundtrips() {
    let mut value = Flags::new(
        [true, false, true, false],
        (
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None,
        ),
    );
    let limits = Limits::default();
    let encoded = value.encode_uper(&limits).unwrap();
    assert_eq!(encoded.bytes, [0, 0, 0, 0, 0, 0, 0, 0x0a]);
    assert_eq!(encoded.bit_len, 64);
    assert_eq!(
        Flags::decode_uper(&encoded.bytes, &limits).unwrap().value,
        value
    );
    // Boundary setters check the tuple materializer beyond its first array slot.
    value.set_bit4(Some(false));
    value.set_bit63(Some(true));
    let present = value.encode_uper(&limits).unwrap();
    assert_eq!(present.bit_len, 66);
    assert_eq!(present.bytes, [0x80, 0, 0, 0, 0, 0, 0, 0x1a, 0x40]);
    let decoded = Flags::decode_uper(&present.bytes, &limits).unwrap().value;
    assert_eq!(decoded, value);
    assert_eq!(decoded.get_bit4(), Some(false));
    assert_eq!(decoded.get_bit63(), Some(true));
}
