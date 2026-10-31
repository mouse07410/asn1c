//! Direct CBOR primitive and opaque ANY conformance and malformed inputs.
use asn1c_generated::cbor::{Count, Empty, Flag, Value};
use asn1c_runtime::Limits;

/// Compare primitive CBOR boundary and ANY vectors with generated C.
/// Source: C CBOR codecs. Version: 2026-10-30. Inputs: none; returns nothing.
/// Panics on failure. Responsible: asn1c maintainers. History: CBOR slice.
/// Example: run with `cargo test`.
#[test]
fn vectors() {
    let limits = Limits::default();
    assert_eq!(Flag::new(true).encode_cbor(&limits).unwrap().bytes, [0xf5]);
    assert!(!Flag::decode_cbor(&[0xc0, 0xf4, 0xff], &limits)
        .unwrap()
        .value
        .value());
    assert_eq!(Empty.encode_cbor(&limits).unwrap().bytes, [0xf6]);
    assert_eq!(
        Empty::decode_cbor(&[0xf6], &limits).unwrap().consumed_bytes,
        1
    );
    for (value, wire) in [
        (0, vec![0]),
        (23, vec![23]),
        (24, vec![0x18, 24]),
        (-1, vec![0x20]),
        (-24, vec![0x37]),
        (-25, vec![0x38, 24]),
        (
            i64::MAX,
            vec![0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
        (
            i64::MIN,
            vec![0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ] {
        assert_eq!(
            Count::new(value)
                .unwrap()
                .encode_cbor(&limits)
                .unwrap()
                .bytes,
            wire
        );
        assert_eq!(
            Count::decode_cbor(&wire, &limits).unwrap().value.value(),
            value
        );
    }
    assert_eq!(
        Count::decode_cbor(&[0xc0, 0x18, 0x01], &limits)
            .unwrap()
            .value
            .value(),
        1
    );
    for length in [0, 23, 24, 255, 256] {
        let value = Value(vec![0xa5; length]);
        let encoded = value.encode_cbor(&limits).unwrap();
        assert_eq!(
            Value::decode_cbor(&encoded.bytes, &limits).unwrap().value,
            value
        );
        if length == 24 {
            assert_eq!(&encoded.bytes[..2], &[0x58, 24]);
        }
        if length == 256 {
            assert_eq!(&encoded.bytes[..3], &[0x59, 1, 0]);
        }
    }
    let any = Value(vec![0, 0xa5]);
    assert_eq!(any.encode_cbor(&limits).unwrap().bytes, [0x42, 0, 0xa5]);
    assert_eq!(
        Value::decode_cbor(&[0xc0, 0x58, 2, 0, 0xa5, 9], &limits)
            .unwrap()
            .value,
        any
    );
}

/// Reject malformed heads, invalid major types, truncation and resource limits.
/// Source: C CBOR head rules. Version: 2026-10-30. Inputs: none; returns nothing.
/// Panics on failure. Responsible: asn1c maintainers. History: CBOR hardening.
/// Example: run with `cargo test`.
#[test]
fn invalid_and_limits() {
    let limits = Limits::default();
    for input in [
        &[][..],
        &[0xc0][..],
        &[0xf6][..],
        &[0xf8, 21][..],
        &[0xff][..],
    ] {
        assert!(Flag::decode_cbor(input, &limits).is_err());
    }
    for input in [
        &[][..],
        &[0x18][..],
        &[0x1c][..],
        &[0x1f][..],
        &[0xc2, 0][..],
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
    ] {
        assert!(Count::decode_cbor(input, &limits).is_err());
    }
    for input in [
        &[][..],
        &[0x5f][..],
        &[0x41][..],
        &[0x61, 1][..],
        &[0x5a, 0x80, 0, 0, 0][..],
    ] {
        assert!(Value::decode_cbor(input, &limits).is_err());
    }
    assert!(Empty::decode_cbor(&[0xf4], &limits).is_err());
    let small = Limits {
        max_input_bytes: 1,
        max_output_bytes: 1,
        max_work_bits: 8,
    };
    assert!(Value(vec![1]).encode_cbor(&small).is_err());
    assert!(Value::decode_cbor(&[0x41, 1], &small).is_err());
    assert!(Flag::decode_cbor(&[0xc0, 0xf5], &small).is_err());
    let work = Limits {
        max_work_bits: 8,
        ..limits
    };
    assert!(Flag::decode_cbor(&[0xc0, 0xf5], &work).is_err());
    assert!(Value(vec![0xa5]).encode_cbor(&work).is_err());
    for byte in 0_u8..=255 {
        let _ = Flag::decode_cbor(&[byte], &limits);
        let _ = Empty::decode_cbor(&[byte], &limits);
        let _ = Count::decode_cbor(&[byte], &limits);
        let _ = Value::decode_cbor(&[byte], &limits);
    }
}
