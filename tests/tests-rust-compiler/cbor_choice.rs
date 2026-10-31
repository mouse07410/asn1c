//! Direct-alternative CBOR CHOICE one-entry map conformance.
use asn1c_generated::cbor_choice::Value;
use asn1c_runtime::Limits;

/// Compare each generated choice with the C one-entry map vector.
/// Source: C CHOICE CBOR codec. Version: 2026-10-30. Inputs: none.
/// Returns: unit. Errors: assertion panic. Responsible: asn1c maintainers.
/// History: bounded CHOICE slice. Example: `cargo test variants`.
#[test]
fn variants() {
    let limits = Limits::default();
    for (value, wire) in [
        (
            Value::Flag(true),
            vec![0xa1, 0x64, b'f', b'l', b'a', b'g', 0xf5],
        ),
        (
            Value::Empty,
            vec![0xa1, 0x65, b'e', b'm', b'p', b't', b'y', 0xf6],
        ),
        (
            Value::Count(-2),
            vec![0xa1, 0x65, b'c', b'o', b'u', b'n', b't', 0x21],
        ),
        (
            Value::Data(vec![0, 0xa5]),
            vec![0xa1, 0x64, b'd', b'a', b't', b'a', 0x42, 0, 0xa5],
        ),
    ] {
        assert_eq!(value.encode_cbor(&limits).unwrap().bytes, wire);
        let decoded = Value::decode_cbor(&wire, &limits).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.consumed_bytes, wire.len());
    }
    assert_eq!(
        Value::decode_cbor(&[0xc0, 0xb8, 1, 0x64, b'f', b'l', b'a', b'g', 0xf5], &limits)
            .unwrap()
            .value,
        Value::Flag(true)
    );
}

/// Reject empty/multi-entry maps, duplicates, unknown names and bad values.
/// Source: C CHOICE CBOR decoder. Version: 2026-10-30. Inputs: none.
/// Returns: unit. Errors: assertion panic. Responsible: asn1c maintainers.
/// History: malformed-choice regression. Example: `cargo test malformed`.
#[test]
fn malformed() {
    let limits = Limits::default();
    for wire in [
        &[][..],
        &[0xa0][..],
        &[0xa1, 0x64, b'j', b'u', b'n', b'k', 0xf5][..],
        &[0xa1, 0x64, b'f', b'l', b'a', b'g', 0xf6][..],
        &[0xa1, 0x65, b'c', b'o', b'u', b'n', b't', 0x06][..],
        &[0xa1, 0x64, b'd', b'a', b't', b'a', 0x5f][..],
        &[0xa2, 0x64, b'f', b'l', b'a', b'g', 0xf5, 0x65, b'e', b'm', b'p', b't', b'y', 0xf6][..],
        &[0xa2, 0x64, b'f', b'l', b'a', b'g', 0xf5, 0x64, b'f', b'l', b'a', b'g', 0xf4][..],
        &[0xa1, 0x61, 0xff, 0xf5][..],
    ] {
        assert!(Value::decode_cbor(wire, &limits).is_err(), "{wire:?}");
    }
    assert!(Value::Count(6).encode_cbor(&limits).is_err());
    let tiny = Limits {
        max_output_bytes: 1,
        ..limits
    };
    assert!(Value::Flag(true).encode_cbor(&tiny).is_err());
}
