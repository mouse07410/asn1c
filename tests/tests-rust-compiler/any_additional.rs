//! C-compatible standalone opaque ANY APER, OER, and JER tests.
use asn1c_generated::any_module::Value;
use asn1c_runtime::Limits;

/// Verify framing at short, long, and fragmented length boundaries.
/// Source: C ANY codecs. Version: 2026-10-30. Inputs: none. Returns: nothing.
/// Panics on assertion failure. Responsible: asn1c maintainers.
/// History: extra opaque ANY codecs. Example: run with `cargo test`.
#[test]
fn additional_codecs() {
    let limits = Limits::default();
    for length in [0, 1, 127, 128, 256, 16384] {
        let value = Value(vec![0xa5; length]);
        let aper = value.encode_aper(&limits).unwrap();
        assert_eq!(
            Value::decode_aper(&aper.bytes, &limits).unwrap().value,
            value
        );
        let oer = value.encode_oer(&limits).unwrap();
        assert_eq!(Value::decode_oer(&oer.bytes, &limits).unwrap().value, value);
        let expected = match length {
            0 => vec![0],
            1 => vec![1],
            127 => vec![127],
            128 => vec![0x81, 0x80],
            256 => vec![0x82, 1, 0],
            _ => vec![0x82, 0x40, 0],
        };
        assert!(oer.bytes.starts_with(&expected));
        assert!(oer.bytes[expected.len()..].iter().all(|byte| *byte == 0xa5));
        let jer = value.encode_jer(&limits).unwrap();
        assert_eq!(Value::decode_jer(&jer.bytes, &limits).unwrap().value, value);
    }
    assert_eq!(
        Value(vec![0xa5]).encode_aper(&limits).unwrap().bytes,
        [1, 0xa5]
    );
    assert_eq!(
        Value(vec![0xa5]).encode_jer(&limits).unwrap().bytes,
        b"\"A5\""
    );
}

/// Reject malformed, truncated, and resource-exhausting inputs.
/// Source: codec framing. Version: 2026-10-30. Inputs: none. Returns: nothing.
/// Panics on assertion failure. Responsible: asn1c maintainers.
/// History: extra opaque ANY codecs. Example: run with `cargo test`.
#[test]
fn invalid_inputs() {
    let limits = Limits::default();
    for input in [
        &[][..],
        &[0x81][..],
        &[2, 0][..],
        &[0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0][..],
    ] {
        assert!(Value::decode_oer(input, &limits).is_err());
    }
    for input in [&[][..], &[0xc0][..], &[1][..], &[0x80][..]] {
        assert!(Value::decode_aper(input, &limits).is_err());
    }
    for input in [&[][..], b"\"0\"", b"\"GG\"", b"\"00\" x"] {
        assert!(Value::decode_jer(input, &limits).is_err());
    }
    let small = Limits {
        max_output_bytes: 1,
        ..limits
    };
    let value = Value(vec![0xa5]);
    assert!(value.encode_aper(&small).is_err());
    assert!(value.encode_oer(&small).is_err());
    assert!(value.encode_jer(&small).is_err());
    let low_work = Limits {
        max_work_bits: 7,
        ..limits
    };
    assert!(value.encode_aper(&low_work).is_err());
    assert!(value.encode_oer(&low_work).is_err());
    assert!(value.encode_jer(&low_work).is_err());
    assert!(Value::decode_aper(&[1, 0xa5], &low_work).is_err());
    assert!(Value::decode_oer(&[1, 0xa5], &low_work).is_err());
    assert!(Value::decode_jer(b"\"A5\"", &low_work).is_err());
    let low_input = Limits {
        max_input_bytes: 1,
        ..limits
    };
    assert!(Value::decode_aper(&[1, 0xa5], &low_input).is_err());
    assert!(Value::decode_oer(&[1, 0xa5], &low_input).is_err());
    assert!(Value::decode_jer(b"\"A5\"", &low_input).is_err());
}
